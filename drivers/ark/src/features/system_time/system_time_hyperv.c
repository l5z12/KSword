/*++

Module Name:

    system_time_hyperv.c

Abstract:

    Achieve global system clock rate adjustment by combining the Hyper-V user-shared QPC page with existing HAL hooks.

Third-Party Notice:

    The license and archival notes for the referenced mechanism are located at:
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_hyperv.h"

#include <intrin.h>

/*
 * MmMapIoSpace must not be used to create an alias for ordinary RAM. Keep the
 * experimental Hyper-V reference-page strategy fail-closed until it can use a
 * documented writable mapping contract without risking an uncorrectable MCE.
 */
#define KSW_SYSTEM_TIME_HYPERV_DIRECT_PAGE_MAPPING_ENABLED 0

/* SystemHypervisorSharedPageInformation is numbered 197 in the current Windows ABI. */
#define KSW_SYSTEM_TIME_HYPERV_SHARED_PAGE_INFORMATION 197UL

/* KUSER_SHARED_DATA provides both the QPC fast-path flag and the final global bias. */
#define KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE 0xFFFFF78000000000ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET        0x3C6ULL
#define KSW_SYSTEM_TIME_QPC_BIAS_OFFSET          0x3B8ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_ENABLED_BIT   0x01U
#define KSW_SYSTEM_TIME_QPC_HYPERV_PAGE_BIT      0x02U

/* The Hyper-V shared page structure matches the three fields used by the native ntdll fast path. */
typedef struct KswSystemTimeHypervSharedData
{
    volatile LONG64 timeUpdateLock;
    volatile LONG64 qpcMultiplier;
    volatile LONG64 qpcBias;
} KswSystemTimeHypervSharedData;

/* System info responses return only the user virtual addresses of shared pages mapped read-only in each process. */
typedef struct KswSystemTimeHypervPageInformation
{
    PVOID hypervisorSharedUserVa;
} KswSystemTimeHypervPageInformation;

/* Dynamically resolve ZwQuerySystemInformation to avoid dependency on enumeration declarations not exposed in the WDK. */
typedef NTSTATUS
(NTAPI* KswZwQuerySystemInformationRoutine)(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

/* A stable snapshot corresponds to the ntdll rule of 'sequence numbers remaining equal before and after reading'. */
typedef struct KswSystemTimeHypervSnapshot
{
    ULONGLONG timeUpdateLock;
    ULONGLONG multiplier;
    ULONGLONG bias;
} KswSystemTimeHypervSnapshot;

/* The mapping object binds the user address, the full-page kernel mapping, and the field address into a single release unit. */
typedef struct KswSystemTimeHypervMapping
{
    PVOID mappedPage;
    volatile KswSystemTimeHypervSharedData* sharedData;
    PVOID sharedUserVa;
} KswSystemTimeHypervMapping;

/* Module state is protected by a spin lock to ensure safe cross-execution between control threads and maintenance DPCs. */
typedef struct KswSystemTimeHypervState
{
    KSPIN_LOCK lock;
    KswSystemTimeHypervMapping mapping;
    KswSystemTimeHypervSnapshot original;
    KswSystemTimeHypervSnapshot activeValue;
    ULONG command;
    ULONG factor;
    BOOLEAN initialized;
    BOOLEAN prepared;
    BOOLEAN active;
    BOOLEAN reserved;
} KswSystemTimeHypervState;

static KswSystemTimeHypervState gKswordArkSystemTimeHypervState;

#if defined(_M_AMD64) || defined(_M_X64)
#pragma intrinsic(__cpuid)
#pragma intrinsic(__rdtsc)
#pragma intrinsic(__umulh)
#endif

/* Identify Microsoft Hv and Hv#1 interfaces; reject treating other hypervisors as Hyper-V. */
static
BOOLEAN
kswordArkSystemTimeHypervIsMicrosoftHypervisor(
    VOID
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    int registers[4] = { 0, 0, 0, 0 };

    __cpuid(registers, 1);
    if ((((ULONG)registers[2]) & 0x80000000UL) == 0UL) {
        return FALSE;
    }

    __cpuid(registers, (int)0x40000000UL);
    if ((ULONG)registers[0] < 0x40000001UL ||
        (ULONG)registers[1] != 0x7263694DUL ||
        (ULONG)registers[2] != 0x666F736FUL ||
        (ULONG)registers[3] != 0x76482074UL) {
        return FALSE;
    }

    __cpuid(registers, (int)0x40000001UL);
    return (ULONG)registers[0] == 0x31237648UL;
#else
    return FALSE;
#endif
}

/* Dynamically retrieve the system information query entry point; if the entry point is missing, handle it as platform unsupported. */
static
KswZwQuerySystemInformationRoutine
kswordArkSystemTimeHypervResolveQueryRoutine(
    VOID
    )
{
    UNICODE_STRING routineName = { 0 };

    RtlInitUnicodeString(
        &routineName,
        L"ZwQuerySystemInformation");
    return (KswZwQuerySystemInformationRoutine)
        MmGetSystemRoutineAddress(&routineName);
}

/* Obtain a stable combination of lock, multiplier, and offset in the order of ntdll reads. */
static
NTSTATUS
kswordArkSystemTimeHypervReadSnapshot(
    _In_ volatile KswSystemTimeHypervSharedData* sharedData,
    _Out_ KswSystemTimeHypervSnapshot* snapshot
    )
{
    ULONG retryIndex = 0UL;

    if (sharedData == NULL || snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (retryIndex = 0UL; retryIndex < 16UL; ++retryIndex) {
        const ULONGLONG kFirstLock = (ULONGLONG)
            InterlockedCompareExchange64(
                &sharedData->timeUpdateLock,
                0LL,
                0LL);
        ULONGLONG multiplier = 0ULL;
        ULONGLONG bias = 0ULL;
        ULONGLONG secondLock = 0ULL;

        if ((ULONG)kFirstLock == 0UL) {
            continue;
        }

        multiplier = (ULONGLONG)
            InterlockedCompareExchange64(
                &sharedData->qpcMultiplier,
                0LL,
                0LL);
        bias = (ULONGLONG)
            InterlockedCompareExchange64(
                &sharedData->qpcBias,
                0LL,
                0LL);
        KeMemoryBarrier();
        secondLock = (ULONGLONG)
            InterlockedCompareExchange64(
                &sharedData->timeUpdateLock,
                0LL,
                0LL);
        if (kFirstLock == secondLock && multiplier != 0ULL) {
            snapshot->timeUpdateLock = kFirstLock;
            snapshot->multiplier = multiplier;
            snapshot->bias = bias;
            return STATUS_SUCCESS;
        }
    }

    RtlZeroMemory(snapshot, sizeof(*snapshot));
    return STATUS_RETRY;
}

/* Compare multiplier and bias ownership; a sequence number change alone is not considered a third-party conflict. */
static
BOOLEAN
kswordArkSystemTimeHypervSameClockValue(
    _In_ const KswSystemTimeHypervSnapshot* left,
    _In_ const KswSystemTimeHypervSnapshot* right
    )
{
    return left != NULL &&
        right != NULL &&
        left->multiplier == right->multiplier &&
        left->bias == right->bias;
}

/* Validate that the user address lies within a single x64 user page to prevent cross-page physical mapping miswrites. */
static
BOOLEAN
kswordArkSystemTimeHypervValidateUserAddress(
    _In_ PVOID userVa
    )
{
    const ULONGLONG kAddress = (ULONGLONG)(ULONG_PTR)userVa;
    const ULONGLONG kPageOffset =
        kAddress & ((ULONGLONG)PAGE_SIZE - 1ULL);

    return userVa != NULL &&
        kAddress <= 0x00007FFFFFFFFFFFULL &&
        kPageOffset <= (ULONGLONG)PAGE_SIZE -
            sizeof(KswSystemTimeHypervSharedData) &&
        (kAddress & (sizeof(LONG64) - 1ULL)) == 0ULL;
}

/* Query the shared page, verify the fast-path bit, and establish a full-page writable physical mapping with matching cache attributes. */
static
NTSTATUS
kswordArkSystemTimeHypervOpenMapping(
    _Out_ KswSystemTimeHypervMapping* mapping,
    _Out_ KswSystemTimeHypervSnapshot* snapshot
    )
{
#if !KSW_SYSTEM_TIME_HYPERV_DIRECT_PAGE_MAPPING_ENABLED
    if (mapping == NULL || snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(mapping, sizeof(*mapping));
    RtlZeroMemory(snapshot, sizeof(*snapshot));
    return STATUS_NOT_SUPPORTED;
#elif defined(_M_AMD64) || defined(_M_X64)
    KSW_ZW_QUERY_SYSTEM_INFORMATION_ROUTINE queryRoutine = NULL;
    KSW_SYSTEM_TIME_HYPERV_PAGE_INFORMATION pageInformation = { 0 };
    PHYSICAL_ADDRESS targetPhysical = { 0 };
    PHYSICAL_ADDRESS pagePhysical = { 0 };
    SIZE_T pageOffset = 0U;
    ULONG returnedLength = 0UL;
    volatile UCHAR* bypassByte = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (Mapping == NULL || Snapshot == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Mapping, sizeof(*Mapping));
    RtlZeroMemory(Snapshot, sizeof(*Snapshot));

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!KswordARKSystemTimeHypervIsMicrosoftHypervisor()) {
        return STATUS_NOT_SUPPORTED;
    }

    queryRoutine = KswordARKSystemTimeHypervResolveQueryRoutine();
    if (queryRoutine == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    status = queryRoutine(
        KSW_SYSTEM_TIME_HYPERV_SHARED_PAGE_INFORMATION,
        &pageInformation,
        sizeof(pageInformation),
        &returnedLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (returnedLength != 0UL &&
        returnedLength < sizeof(pageInformation)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (!KswordARKSystemTimeHypervValidateUserAddress(
            pageInformation.HypervisorSharedUserVa) ||
        !MmIsAddressValid(
            pageInformation.HypervisorSharedUserVa)) {
        return STATUS_DEVICE_NOT_READY;
    }

    bypassByte = (volatile UCHAR*)(ULONG_PTR)(
        KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
        KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET);
    if (!MmIsAddressValid((PVOID)bypassByte) ||
        ((*bypassByte &
            (KSW_SYSTEM_TIME_QPC_BYPASS_ENABLED_BIT |
             KSW_SYSTEM_TIME_QPC_HYPERV_PAGE_BIT)) !=
            (KSW_SYSTEM_TIME_QPC_BYPASS_ENABLED_BIT |
             KSW_SYSTEM_TIME_QPC_HYPERV_PAGE_BIT))) {
        return STATUS_DEVICE_NOT_READY;
    }

    targetPhysical = MmGetPhysicalAddress(
        pageInformation.HypervisorSharedUserVa);
    pageOffset = (SIZE_T)(
        (ULONGLONG)targetPhysical.QuadPart &
        ((ULONGLONG)PAGE_SIZE - 1ULL));
    pagePhysical.QuadPart =
        targetPhysical.QuadPart - (LONGLONG)pageOffset;
    Mapping->MappedPage = MmMapIoSpace(
        pagePhysical,
        PAGE_SIZE,
        MmCached);
    if (Mapping->MappedPage == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mapping->SharedData =
        (volatile KSW_SYSTEM_TIME_HYPERV_SHARED_DATA*)(
            (UCHAR*)Mapping->MappedPage + pageOffset);
    Mapping->SharedUserVa =
        pageInformation.HypervisorSharedUserVa;
    status = KswordARKSystemTimeHypervReadSnapshot(
        Mapping->SharedData,
        Snapshot);
    if (!NT_SUCCESS(status)) {
        MmUnmapIoSpace(Mapping->MappedPage, PAGE_SIZE);
        RtlZeroMemory(Mapping, sizeof(*Mapping));
        return status;
    }
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Mapping);
    UNREFERENCED_PARAMETER(Snapshot);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* Unmap temporary or persistent physical mappings and clear all addresses prone to misuse. */
static
VOID
kswordArkSystemTimeHypervCloseMapping(
    _Inout_ KswSystemTimeHypervMapping* mapping
    )
{
    if (mapping == NULL) {
        return;
    }
    if (mapping->mappedPage != NULL) {
        MmUnmapIoSpace(mapping->mappedPage, PAGE_SIZE);
    }
    RtlZeroMemory(mapping, sizeof(*mapping));
}

/* Compute the target multiplier N or 1/N from the raw Hyper-V multiplier based on the protocol command. */
static
NTSTATUS
kswordArkSystemTimeHypervComputeMultiplier(
    _In_ ULONGLONG originalMultiplier,
    _In_ ULONG command,
    _In_ ULONG factor,
    _Out_ ULONGLONG* multiplier
    )
{
    if (multiplier == NULL || originalMultiplier == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP) {
        if (factor == 0UL ||
            originalMultiplier > MAXULONGLONG / factor) {
            return STATUS_INTEGER_OVERFLOW;
        }
        *multiplier = originalMultiplier * factor;
    } else if (command ==
        KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN) {
        if (factor == 0UL) {
            return STATUS_INVALID_PARAMETER;
        }
        *multiplier = originalMultiplier / factor;
    } else if (command ==
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET) {
        *multiplier = originalMultiplier;
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    return *multiplier == 0ULL
        ? STATUS_INTEGER_OVERFLOW
        : STATUS_SUCCESS;
}

/* Reads the KUSER_SHARED_DATA QPC bias that will eventually be added by ntdll to the Hyper-V result. */
static
NTSTATUS
kswordArkSystemTimeHypervReadGlobalQpcBias(
    _Out_ ULONGLONG* bias
    )
{
    volatile ULONGLONG* qpcBias =
        (volatile ULONGLONG*)(ULONG_PTR)(
            KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
            KSW_SYSTEM_TIME_QPC_BIAS_OFFSET);

    if (bias == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!MmIsAddressValid((PVOID)qpcBias)) {
        return STATUS_ACCESS_VIOLATION;
    }

    __try {
        *bias = *qpcBias;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *bias = 0ULL;
        return GetExceptionCode();
    }
    return STATUS_SUCCESS;
}

/* Validate the shared page formula against the unclaimed kernel QPC with a 10ms tolerance; reject invalid layouts. */
static
NTSTATUS
kswordArkSystemTimeHypervValidateClockFormula(
    _In_ const KswSystemTimeHypervSnapshot* snapshot
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    LARGE_INTEGER frequency = { 0 };
    LARGE_INTEGER kernelCounter = { 0 };
    ULONGLONG globalBias = 0ULL;
    ULONGLONG tsc = 0ULL;
    ULONGLONG sharedCounter = 0ULL;
    ULONGLONG difference = 0ULL;
    ULONGLONG tolerance = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (snapshot == NULL || snapshot->multiplier == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkSystemTimeHypervReadGlobalQpcBias(
        &globalBias);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    tsc = __rdtsc();
    sharedCounter =
        __umulh(tsc, snapshot->multiplier) +
        snapshot->bias +
        globalBias;
    kernelCounter = KeQueryPerformanceCounter(&frequency);
    if (kernelCounter.QuadPart <= 0LL ||
        frequency.QuadPart <= 0LL) {
        return STATUS_DATA_ERROR;
    }

    difference = sharedCounter >=
        (ULONGLONG)kernelCounter.QuadPart
        ? sharedCounter - (ULONGLONG)kernelCounter.QuadPart
        : (ULONGLONG)kernelCounter.QuadPart - sharedCounter;
    tolerance = (ULONGLONG)frequency.QuadPart / 100ULL;
    if (tolerance < 1000ULL) {
        tolerance = 1000ULL;
    }
    return difference <= tolerance
        ? STATUS_SUCCESS
        : STATUS_DATA_ERROR;
#else
    UNREFERENCED_PARAMETER(Snapshot);
    return STATUS_NOT_SUPPORTED;
#endif
}
/*
 * Atomically zero the sequence number first to let ntdll temporarily fall back to system calls, then publish the multiplier and offset.
 * On publish failure, restore to the values observed when entering the function to avoid leaving partially written shared pages.
 */
static
NTSTATUS
kswordArkSystemTimeHypervWriteSnapshot(
    _In_ volatile KswSystemTimeHypervSharedData* sharedData,
    _In_ const KswSystemTimeHypervSnapshot* expected,
    _In_ ULONGLONG multiplier,
    _In_ ULONGLONG bias,
    _Out_ KswSystemTimeHypervSnapshot* published
    )
{
    KswSystemTimeHypervSnapshot observed = { 0 };
    ULONGLONG publishLock = 0ULL;
    LONG64 observedLock = 0LL;
    BOOLEAN ownsUpdate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (sharedData == NULL || expected == NULL ||
        published == NULL || multiplier == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(published, sizeof(*published));

    publishLock = expected->timeUpdateLock + 1ULL;
    if ((ULONG)publishLock == 0UL) {
        ++publishLock;
    }
    observedLock = InterlockedCompareExchange64(
        &sharedData->timeUpdateLock,
        0LL,
        (LONG64)expected->timeUpdateLock);
    if ((ULONGLONG)observedLock != expected->timeUpdateLock) {
        return STATUS_CONFLICTING_ADDRESSES;
    }
    ownsUpdate = TRUE;

    __try {
        KeMemoryBarrier();
        (void)InterlockedExchange64(
            &sharedData->qpcMultiplier,
            (LONG64)multiplier);
        (void)InterlockedExchange64(
            &sharedData->qpcBias,
            (LONG64)bias);
        KeMemoryBarrier();
        (void)InterlockedExchange64(
            &sharedData->timeUpdateLock,
            (LONG64)publishLock);
        ownsUpdate = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (ownsUpdate) {
        (void)InterlockedExchange64(
            &sharedData->qpcMultiplier,
            (LONG64)expected->multiplier);
        (void)InterlockedExchange64(
            &sharedData->qpcBias,
            (LONG64)expected->bias);
        KeMemoryBarrier();
        (void)InterlockedExchange64(
            &sharedData->timeUpdateLock,
            (LONG64)publishLock);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * First record all committed ownership values; even if a subsequent stable read encounters a transient sequence conflict,
     * the caller can use this to perform a safe rollback restoring only the "last published value for this feature".
     */
    published->timeUpdateLock = publishLock;
    published->multiplier = multiplier;
    published->bias = bias;
    status = kswordArkSystemTimeHypervReadSnapshot(
        sharedData,
        &observed);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (observed.multiplier != multiplier ||
        observed.bias != bias) {
        return STATUS_DATA_ERROR;
    }
    *published = observed;
    return STATUS_SUCCESS;
}

/*
 * Use the already-acquired KeQueryPerformanceCounter as the continuous target and resolve the shared page offset.
 * Aligns with the kernel virtual QPC because it computes high64(TSC * multiplier) + pageBias + globalBias.
 */
static
NTSTATUS
kswordArkSystemTimeHypervUpdateLocked(
    _In_ ULONG command,
    _In_ ULONG factor,
    _In_ BOOLEAN allowOriginalValue
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    KswSystemTimeHypervSnapshot current = { 0 };
    KswSystemTimeHypervSnapshot published = { 0 };
    LARGE_INTEGER targetCounter = { 0 };
    ULONGLONG globalBias = 0ULL;
    ULONGLONG multiplier = 0ULL;
    ULONGLONG tsc = 0ULL;
    ULONGLONG pageBias = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (!gKswordArkSystemTimeHypervState.prepared ||
        gKswordArkSystemTimeHypervState.mapping.sharedData == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = kswordArkSystemTimeHypervReadSnapshot(
        gKswordArkSystemTimeHypervState.mapping.sharedData,
        &current);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (gKswordArkSystemTimeHypervState.active) {
        const BOOLEAN kIsActiveValue =
            kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.activeValue);
        const BOOLEAN kIsOriginalValue =
            kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.original);

        if (!kIsActiveValue &&
            !(allowOriginalValue && kIsOriginalValue)) {
            return STATUS_CONFLICTING_ADDRESSES;
        }
    } else if (!kswordArkSystemTimeHypervSameClockValue(
            &current,
            &gKswordArkSystemTimeHypervState.original)) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    status = kswordArkSystemTimeHypervComputeMultiplier(
        gKswordArkSystemTimeHypervState.original.multiplier,
        command,
        factor,
        &multiplier);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkSystemTimeHypervReadGlobalQpcBias(
        &globalBias);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    tsc = __rdtsc();
    targetCounter = KeQueryPerformanceCounter(NULL);
    if (targetCounter.QuadPart <= 0LL) {
        return STATUS_DATA_ERROR;
    }
    pageBias =
        (ULONGLONG)targetCounter.QuadPart -
        globalBias -
        __umulh(tsc, multiplier);
    status = kswordArkSystemTimeHypervWriteSnapshot(
        gKswordArkSystemTimeHypervState.mapping.sharedData,
        &current,
        multiplier,
        pageBias,
        &published);
    if (!NT_SUCCESS(status)) {
        if (published.timeUpdateLock != 0ULL &&
            published.multiplier == multiplier &&
            published.bias == pageBias) {
            gKswordArkSystemTimeHypervState.activeValue = published;
        }
        return status;
    }

    gKswordArkSystemTimeHypervState.activeValue = published;
    gKswordArkSystemTimeHypervState.command = command;
    gKswordArkSystemTimeHypervState.factor = factor;
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Command);
    UNREFERENCED_PARAMETER(Factor);
    UNREFERENCED_PARAMETER(AllowOriginalValue);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
kswordArkSystemTimeHypervInitialize(
    VOID
    )
{
    RtlZeroMemory(
        &gKswordArkSystemTimeHypervState,
        sizeof(gKswordArkSystemTimeHypervState));
    KeInitializeSpinLock(
        &gKswordArkSystemTimeHypervState.lock);
    gKswordArkSystemTimeHypervState.command =
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
    gKswordArkSystemTimeHypervState.factor = 1UL;
    gKswordArkSystemTimeHypervState.initialized = TRUE;
}

NTSTATUS
kswordArkSystemTimeHypervQuery(
    _Out_ KswordArkSystemTimeHypervDiagnostics* diagnostics
    )
{
    KswSystemTimeHypervMapping temporaryMapping = { 0 };
    KswSystemTimeHypervSnapshot temporarySnapshot = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    if (diagnostics == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(diagnostics, sizeof(*diagnostics));
    if (kswordArkSystemTimeHypervIsMicrosoftHypervisor()) {
        diagnostics->stateFlags |=
            KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_PRESENT;
    } else {
        return STATUS_NOT_SUPPORTED;
    }

    KeAcquireSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        &oldIrql);
    if (gKswordArkSystemTimeHypervState.prepared) {
        diagnostics->stateFlags |=
            KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE;
        if (gKswordArkSystemTimeHypervState.active) {
            diagnostics->stateFlags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_ACTIVE;
        }
        diagnostics->sharedUserVa =
            gKswordArkSystemTimeHypervState.mapping.sharedUserVa;
        diagnostics->originalMultiplier =
            gKswordArkSystemTimeHypervState.original.multiplier;
        diagnostics->originalBias =
            gKswordArkSystemTimeHypervState.original.bias;
        status = kswordArkSystemTimeHypervReadSnapshot(
            gKswordArkSystemTimeHypervState.mapping.sharedData,
            &temporarySnapshot);
        KeReleaseSpinLock(
            &gKswordArkSystemTimeHypervState.lock,
            oldIrql);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        diagnostics->timeUpdateLock =
            temporarySnapshot.timeUpdateLock;
        diagnostics->currentMultiplier =
            temporarySnapshot.multiplier;
        diagnostics->currentBias = temporarySnapshot.bias;
        return STATUS_SUCCESS;
    }
    KeReleaseSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        oldIrql);

    status = kswordArkSystemTimeHypervOpenMapping(
        &temporaryMapping,
        &temporarySnapshot);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    diagnostics->stateFlags |=
        KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE;
    diagnostics->sharedUserVa =
        temporaryMapping.sharedUserVa;
    diagnostics->timeUpdateLock =
        temporarySnapshot.timeUpdateLock;
    diagnostics->originalMultiplier =
        temporarySnapshot.multiplier;
    diagnostics->originalBias = temporarySnapshot.bias;
    diagnostics->currentMultiplier =
        temporarySnapshot.multiplier;
    diagnostics->currentBias = temporarySnapshot.bias;
    kswordArkSystemTimeHypervCloseMapping(
        &temporaryMapping);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkSystemTimeHypervPrepare(
    VOID
    )
{
    KswSystemTimeHypervMapping mapping = { 0 };
    KswSystemTimeHypervSnapshot snapshot = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    status = kswordArkSystemTimeHypervOpenMapping(
        &mapping,
        &snapshot);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkSystemTimeHypervValidateClockFormula(
        &snapshot);
    if (!NT_SUCCESS(status)) {
        kswordArkSystemTimeHypervCloseMapping(&mapping);
        return status;
    }

    KeAcquireSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        &oldIrql);
    if (!gKswordArkSystemTimeHypervState.initialized ||
        gKswordArkSystemTimeHypervState.prepared) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        gKswordArkSystemTimeHypervState.mapping = mapping;
        gKswordArkSystemTimeHypervState.original = snapshot;
        gKswordArkSystemTimeHypervState.activeValue = snapshot;
        gKswordArkSystemTimeHypervState.prepared = TRUE;
        gKswordArkSystemTimeHypervState.active = FALSE;
        RtlZeroMemory(&mapping, sizeof(mapping));
    }
    KeReleaseSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        oldIrql);

    kswordArkSystemTimeHypervCloseMapping(&mapping);
    return status;
}

NTSTATUS
kswordArkSystemTimeHypervActivate(
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        &oldIrql);
    if (!gKswordArkSystemTimeHypervState.prepared ||
        gKswordArkSystemTimeHypervState.active) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        status = kswordArkSystemTimeHypervUpdateLocked(
            command,
            factor,
            FALSE);
        if (NT_SUCCESS(status)) {
            gKswordArkSystemTimeHypervState.active = TRUE;
        }
    }
    KeReleaseSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        oldIrql);
    return status;
}

NTSTATUS
kswordArkSystemTimeHypervReconfigure(
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        &oldIrql);
    if (!gKswordArkSystemTimeHypervState.active) {
        status = STATUS_DEVICE_NOT_READY;
    } else {
        status = kswordArkSystemTimeHypervUpdateLocked(
            command,
            factor,
            FALSE);
    }
    KeReleaseSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        oldIrql);
    return status;
}

NTSTATUS
kswordArkSystemTimeHypervMaintain(
    VOID
    )
{
    KswSystemTimeHypervSnapshot current = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        &oldIrql);
    if (!gKswordArkSystemTimeHypervState.active) {
        status = STATUS_DEVICE_NOT_READY;
    } else {
        status = kswordArkSystemTimeHypervReadSnapshot(
            gKswordArkSystemTimeHypervState.mapping.sharedData,
            &current);
        if (NT_SUCCESS(status) &&
            kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.activeValue)) {
            gKswordArkSystemTimeHypervState.activeValue.timeUpdateLock =
                current.timeUpdateLock;
        } else if (NT_SUCCESS(status) &&
            kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.original)) {
            status = kswordArkSystemTimeHypervUpdateLocked(
                gKswordArkSystemTimeHypervState.command,
                gKswordArkSystemTimeHypervState.factor,
                TRUE);
        } else if (NT_SUCCESS(status)) {
            status = STATUS_CONFLICTING_ADDRESSES;
        }
    }
    KeReleaseSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        oldIrql);
    return status;
}

NTSTATUS
kswordArkSystemTimeHypervRestore(
    VOID
    )
{
    KswSystemTimeHypervMapping mapping = { 0 };
    KswSystemTimeHypervSnapshot current = { 0 };
    KswSystemTimeHypervSnapshot published = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        &oldIrql);
    if (gKswordArkSystemTimeHypervState.prepared) {
        status = kswordArkSystemTimeHypervReadSnapshot(
            gKswordArkSystemTimeHypervState.mapping.sharedData,
            &current);
        if (NT_SUCCESS(status) &&
            kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.activeValue) &&
            !kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.original)) {
            status = kswordArkSystemTimeHypervWriteSnapshot(
                gKswordArkSystemTimeHypervState.mapping.sharedData,
                &current,
                gKswordArkSystemTimeHypervState.original.multiplier,
                gKswordArkSystemTimeHypervState.original.bias,
                &published);
        } else if (NT_SUCCESS(status) &&
            !kswordArkSystemTimeHypervSameClockValue(
                &current,
                &gKswordArkSystemTimeHypervState.original)) {
            status = STATUS_CONFLICTING_ADDRESSES;
        }

        mapping = gKswordArkSystemTimeHypervState.mapping;
        RtlZeroMemory(
            &gKswordArkSystemTimeHypervState.mapping,
            sizeof(gKswordArkSystemTimeHypervState.mapping));
        RtlZeroMemory(
            &gKswordArkSystemTimeHypervState.original,
            sizeof(gKswordArkSystemTimeHypervState.original));
        RtlZeroMemory(
            &gKswordArkSystemTimeHypervState.activeValue,
            sizeof(gKswordArkSystemTimeHypervState.activeValue));
        gKswordArkSystemTimeHypervState.command =
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        gKswordArkSystemTimeHypervState.factor = 1UL;
        gKswordArkSystemTimeHypervState.prepared = FALSE;
        gKswordArkSystemTimeHypervState.active = FALSE;
    }
    KeReleaseSpinLock(
        &gKswordArkSystemTimeHypervState.lock,
        oldIrql);

    kswordArkSystemTimeHypervCloseMapping(&mapping);
    return status;
}
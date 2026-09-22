/*++

Module Name:

    system_time_runtime.c

Abstract:

    Implements system-wide acceleration, deceleration, and recoverable takeover using a continuous virtual performance counter.

Third-Party Notice:

    The license and archival notes for the referenced mechanism are located at:
    third_party/SystemWideTransmission/LICENSE.txt
    third_party/SystemWideTransmission/NOTICE.md

Environment:

    Kernel-mode Driver Framework.

--*/

#include "system_time_internal.h"
#include "ark/ark_push_lock.h"
#include "system_time_counter.h"
#include "system_time_hyperv.h"

/* The HAL counter callback on current x64 Windows takes no parameters and returns a 64-bit count. */
typedef LONGLONG
(*KswSystemTimeCounterRoutine)(
    VOID
    );

/* The QPC bypass bit is located in the long-term compatibility field of KUSER_SHARED_DATA. */
#define KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE 0xFFFFF78000000000ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET        0x3C6ULL
#define KSW_SYSTEM_TIME_QPC_BYPASS_BIT           0x01U
#define KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK    0xFEU
#define KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT       0x00010000L

/* Periodic maintenance is only re-acquired when the slot is restored to the original function by the system, without overwriting unknown third-party handlers. */
#define KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS 1000L
#define KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT      100UL
#define KSW_SYSTEM_TIME_DRAIN_DELAY_100NS      (-10000LL)

/* Global state is protected by the control lock; fields marked volatile are also read by DPCs or hooks. */
typedef struct KswordArkSystemTimeState
{
    EX_PUSH_LOCK controlLock;
    KTIMER maintenanceTimer;
    KDPC maintenanceDpc;
    KswordArkSystemTimeResolution resolution;
    PVOID originalPrimary;
    PVOID originalSecondary;
    volatile LONG initialized;
    volatile LONG active;
    volatile LONG conflictDetected;
    volatile LONG generation;
    volatile LONG runtimeStatus;
    volatile LONG lastStatus;
    ULONG lastCommand;
    ULONG factor;
    ULONG resolutionMode;
    ULONG backend;
    BOOLEAN resolved;
    BOOLEAN originalQpcBypassBit;
    BOOLEAN originalInternalBypassBit;
    BOOLEAN patchBitsCaptured;
    BOOLEAN qpcBypassPatched;
} KswordArkSystemTimeState;

static KswordArkSystemTimeState gKswordArkSystemTimeState;

/* Counter slots and the original function must reside in the currently valid kernel address space. */
static
BOOLEAN
kswordArkSystemTimeIsKernelAddressValid(
    _In_opt_ const VOID* address
    )
{
    return address != NULL &&
        (ULONG_PTR)address >= (ULONG_PTR)MmSystemRangeStart &&
        MmIsAddressValid((PVOID)address);
}

/* Both the first and last bytes spanned by the pointer slot must be resident before atomic read/write operations are permitted. */
static
BOOLEAN
kswordArkSystemTimeIsSlotAddressValid(
    _In_opt_ volatile PVOID* slot
    )
{
    const UCHAR* first = (const UCHAR*)slot;

    return kswordArkSystemTimeIsKernelAddressValid(first) &&
        kswordArkSystemTimeIsKernelAddressValid(
            first + sizeof(PVOID) - 1U);
}

/* Returns the read-only kernel mapping of the QPC bypass byte in KUSER_SHARED_DATA. */
static
volatile UCHAR*
kswordArkSystemTimeQpcBypassByte(
    VOID
    )
{
    return (volatile UCHAR*)(ULONG_PTR)(
        KSW_SYSTEM_TIME_SHARED_DATA_KERNEL_BASE +
        KSW_SYSTEM_TIME_QPC_BYPASS_OFFSET);
}

/*
 * The kernel virtual mapping of KUSER_SHARED_DATA is read-only on newer systems; MmIsAddressValid only confirms
 * page existence, not write permission. This implementation retains the original physical page mapping principle
 * but establishes a short-term, cache-coherent writable mapping for the entire page. Before unmapping, it
 * validates the target bit to avoid direct writes to 0xFFFFF780... which would trigger a 0x50 exception.
 */
static
NTSTATUS
kswordArkSystemTimeWriteQpcBypassBit(
    _In_ BOOLEAN enabled,
    _Out_opt_ BOOLEAN* previousEnabled
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    volatile UCHAR* qpcBypass =
        kswordArkSystemTimeQpcBypassByte();
    PHYSICAL_ADDRESS targetPhysical = { 0 };
    PHYSICAL_ADDRESS pagePhysical = { 0 };
    SIZE_T pageOffset = 0U;
    PVOID mappedPage = NULL;
    volatile UCHAR* mappedByte = NULL;
    UCHAR oldByte = 0U;
    UCHAR newByte = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (previousEnabled != NULL) {
        *previousEnabled = FALSE;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!MmIsAddressValid((PVOID)qpcBypass)) {
        return STATUS_ACCESS_VIOLATION;
    }

    targetPhysical = MmGetPhysicalAddress((PVOID)qpcBypass);
    pageOffset = (SIZE_T)(
        (ULONGLONG)targetPhysical.QuadPart &
        ((ULONGLONG)PAGE_SIZE - 1ULL));
    pagePhysical.QuadPart =
        targetPhysical.QuadPart - (LONGLONG)pageOffset;
    mappedPage = MmMapIoSpace(
        pagePhysical,
        PAGE_SIZE,
        MmCached);
    if (mappedPage == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mappedByte = (volatile UCHAR*)(
        (UCHAR*)mappedPage + pageOffset);
    __try {
        oldByte = *mappedByte;
        newByte = enabled
            ? (UCHAR)(oldByte |
                KSW_SYSTEM_TIME_QPC_BYPASS_BIT)
            : (UCHAR)(oldByte &
                KSW_SYSTEM_TIME_QPC_BYPASS_CLEAR_MASK);
        *mappedByte = newByte;
        KeMemoryBarrier();
        if (((*mappedByte &
                KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0U) !=
            (enabled != FALSE)) {
            *mappedByte = oldByte;
            KeMemoryBarrier();
            status = STATUS_DATA_ERROR;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    MmUnmapIoSpace(mappedPage, PAGE_SIZE);
    if (NT_SUCCESS(status) && previousEnabled != NULL) {
        *previousEnabled =
            (oldByte & KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0U;
    }
    return status;
#else
    UNREFERENCED_PARAMETER(Enabled);
    UNREFERENCED_PARAMETER(PreviousEnabled);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* Read a function pointer slot; SEH prevents system crashes caused by exception resolution states. */
static
BOOLEAN
kswordArkSystemTimeReadSlot(
    _In_ volatile PVOID* slot,
    _Out_ PVOID* value
    )
{
    if (value == NULL ||
        !kswordArkSystemTimeIsSlotAddressValid(slot)) {
        return FALSE;
    }

    __try {
        *value = *(PVOID volatile*)slot;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *value = NULL;
        return FALSE;
    }
    return TRUE;
}

/* Install this feature hook only if the slot still points to the expected original function; an unknown pointer is treated as a conflict. */
static
BOOLEAN
kswordArkSystemTimePatchSlot(
    _In_ volatile PVOID* slot,
    _In_ PVOID expectedOriginal
    )
{
    PVOID observed = NULL;

    if (!kswordArkSystemTimeIsSlotAddressValid(slot) ||
        !kswordArkSystemTimeIsKernelAddressValid(expectedOriginal)) {
        return FALSE;
    }

    __try {
        observed = InterlockedCompareExchangePointer(
            (PVOID volatile*)slot,
            kswordArkSystemTimeCounterHookAddress(),
            expectedOriginal);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return observed == expectedOriginal ||
        observed == kswordArkSystemTimeCounterHookAddress();
}

/* Only restore slots still held by this feature to avoid overwriting third-party hooks installed later. */
static
BOOLEAN
kswordArkSystemTimeRestoreSlot(
    _In_ volatile PVOID* slot,
    _In_ PVOID original
    )
{
    PVOID observed = NULL;

    if (!kswordArkSystemTimeIsSlotAddressValid(slot) ||
        !kswordArkSystemTimeIsKernelAddressValid(original)) {
        return FALSE;
    }

    __try {
        observed = InterlockedCompareExchangePointer(
            (PVOID volatile*)slot,
            original,
            kswordArkSystemTimeCounterHookAddress());
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
    return observed == kswordArkSystemTimeCounterHookAddress() ||
        observed == original;
}

/* Save bypass snapshots according to the backend; the Hyper-V path only disables internal HAL bypasses. */
static
NTSTATUS
kswordArkSystemTimeConfigureBypassesLocked(
    _In_ BOOLEAN disableUserQpcBypass
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    volatile UCHAR* qpcBypass =
        kswordArkSystemTimeQpcBypassByte();
    BOOLEAN oldQpcBypassBit = FALSE;
    LONG oldInternalFlags = 0L;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS rollbackStatus = STATUS_SUCCESS;

    if (gKswordArkSystemTimeState.resolution.internalFlags == NULL ||
        !MmIsAddressValid((PVOID)qpcBypass)) {
        return STATUS_ACCESS_VIOLATION;
    }

    if (disableUserQpcBypass) {
        status = kswordArkSystemTimeWriteQpcBypassBit(
            FALSE,
            &oldQpcBypassBit);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    } else {
        __try {
            oldQpcBypassBit =
                ((*qpcBypass & KSW_SYSTEM_TIME_QPC_BYPASS_BIT) != 0U);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
        if (!oldQpcBypassBit) {
            return STATUS_DEVICE_NOT_READY;
        }
    }

    __try {
        oldInternalFlags = InterlockedAnd(
            gKswordArkSystemTimeState.resolution.internalFlags,
            ~KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (disableUserQpcBypass) {
            rollbackStatus = kswordArkSystemTimeWriteQpcBypassBit(
                oldQpcBypassBit,
                NULL);
            if (!NT_SUCCESS(rollbackStatus)) {
                InterlockedExchange(
                    &gKswordArkSystemTimeState.conflictDetected,
                    1L);
                return rollbackStatus;
            }
        }
        return status;
    }

    gKswordArkSystemTimeState.originalQpcBypassBit =
        oldQpcBypassBit;
    gKswordArkSystemTimeState.originalInternalBypassBit =
        (oldInternalFlags &
            KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT) != 0;
    gKswordArkSystemTimeState.patchBitsCaptured = TRUE;
    gKswordArkSystemTimeState.qpcBypassPatched =
        disableUserQpcBypass;
    KeMemoryBarrier();
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(DisableUserQpcBypass);
    return STATUS_NOT_SUPPORTED;
#endif
}

/* Restore actual modified bypass bits from the pre-activation snapshot without rewriting other system flags. */
static
NTSTATUS
kswordArkSystemTimeRestoreBypasses(
    VOID
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    NTSTATUS qpcStatus = STATUS_SUCCESS;
    NTSTATUS internalStatus = STATUS_SUCCESS;

    if (!gKswordArkSystemTimeState.patchBitsCaptured) {
        return STATUS_SUCCESS;
    }

    if (gKswordArkSystemTimeState.qpcBypassPatched) {
        qpcStatus = kswordArkSystemTimeWriteQpcBypassBit(
            gKswordArkSystemTimeState.originalQpcBypassBit,
            NULL);
    }
    __try {
        if (gKswordArkSystemTimeState.originalInternalBypassBit) {
            (void)InterlockedOr(
                gKswordArkSystemTimeState.resolution.internalFlags,
                KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
        } else {
            (void)InterlockedAnd(
                gKswordArkSystemTimeState.resolution.internalFlags,
                ~KSW_SYSTEM_TIME_INTERNAL_BYPASS_BIT);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        internalStatus = GetExceptionCode();
    }

    if (!NT_SUCCESS(qpcStatus) ||
        !NT_SUCCESS(internalStatus)) {
        InterlockedExchange(
            &gKswordArkSystemTimeState.conflictDetected,
            1L);
        return !NT_SUCCESS(qpcStatus)
            ? qpcStatus
            : internalStatus;
    }
    gKswordArkSystemTimeState.patchBitsCaptured = FALSE;
    gKswordArkSystemTimeState.qpcBypassPatched = FALSE;
    return STATUS_SUCCESS;
#else
    /* Non-x64 paths do not capture or modify bypass bits; restore remains idempotent and successful. */
    return STATUS_SUCCESS;
#endif
}

/* Resolve and cache the two current build counter slots; retain queryable status code on failure. */
static
NTSTATUS
kswordArkSystemTimeResolveLocked(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (gKswordArkSystemTimeState.resolved) {
        return STATUS_SUCCESS;
    }

    status = kswordArkSystemTimeResolve(
        gKswordArkSystemTimeState.resolutionMode,
        &gKswordArkSystemTimeState.resolution);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &gKswordArkSystemTimeState.runtimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_RESOLVE_FAILED);
        InterlockedExchange(
            &gKswordArkSystemTimeState.lastStatus,
            status);
        return status;
    }

    gKswordArkSystemTimeState.resolved = TRUE;
    InterlockedExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &gKswordArkSystemTimeState.lastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/*
 * Must be in an unclaimed state before switching the resolution scheme.
 * Clear old resolution and bypass snapshots to ensure the next enablement re-locates and re-forensics based on the new scheme.
 */
static
NTSTATUS
kswordArkSystemTimeSelectResolutionModeLocked(
    _In_ ULONG resolutionMode
    )
{
    if (resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT &&
        resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED) {
        return STATUS_INVALID_PARAMETER;
    }

    if (resolutionMode ==
        gKswordArkSystemTimeState.resolutionMode) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.active,
            0L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }

    RtlZeroMemory(
        &gKswordArkSystemTimeState.resolution,
        sizeof(gKswordArkSystemTimeState.resolution));
    gKswordArkSystemTimeState.originalPrimary = NULL;
    gKswordArkSystemTimeState.originalSecondary = NULL;
    gKswordArkSystemTimeState.resolutionMode = resolutionMode;
    gKswordArkSystemTimeState.resolved = FALSE;
    gKswordArkSystemTimeState.patchBitsCaptured = FALSE;
    return STATUS_SUCCESS;
}

/* The backend can only switch when not taken over, preventing a mixed state of half shared pages and half compatible bypass. */
static
NTSTATUS
kswordArkSystemTimeSelectBackendLocked(
    _In_ ULONG backend
    )
{
    if (backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC &&
        backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT) {
        return STATUS_INVALID_PARAMETER;
    }
    if (backend == gKswordArkSystemTimeState.backend) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.active,
            0L,
            0L) != 0L) {
        return STATUS_DEVICE_BUSY;
    }

    gKswordArkSystemTimeState.backend = backend;
    return STATUS_SUCCESS;
}

/* Read the current functions from both slots and establish them as a recoverable baseline before activation. */
static
NTSTATUS
kswordArkSystemTimeCaptureOriginalsLocked(
    VOID
    )
{
    PVOID primary = NULL;
    PVOID secondary = NULL;

    if (!kswordArkSystemTimeReadSlot(
            gKswordArkSystemTimeState.resolution.primarySlot,
            &primary) ||
        !kswordArkSystemTimeReadSlot(
            gKswordArkSystemTimeState.resolution.secondarySlot,
            &secondary) ||
        !kswordArkSystemTimeIsKernelAddressValid(primary) ||
        !kswordArkSystemTimeIsKernelAddressValid(secondary) ||
        primary == kswordArkSystemTimeCounterHookAddress() ||
        secondary == kswordArkSystemTimeCounterHookAddress()) {
        return STATUS_CONFLICTING_ADDRESSES;
    }

    gKswordArkSystemTimeState.originalPrimary = primary;
    gKswordArkSystemTimeState.originalSecondary = secondary;
    return STATUS_SUCCESS;
}

/* Constructs the current state flags; the caller holds the control lock or is in the single-threaded initialization phase. */
static
ULONG
kswordArkSystemTimeStateFlagsLocked(
    VOID
    )
{
    KswordArkSystemTimeHypervDiagnostics hyperv = { 0 };
    ULONG flags = 0UL;
    PVOID primary = NULL;
    PVOID secondary = NULL;

    (void)kswordArkSystemTimeHypervQuery(&hyperv);
    flags |= hyperv.stateFlags;
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.initialized,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_INITIALIZED;
    }
    if (gKswordArkSystemTimeState.resolved) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED;
    }
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.active,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE;
        if (gKswordArkSystemTimeState.lastCommand ==
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP) {
            flags |= KSWORD_ARK_SYSTEM_TIME_STATE_SPEED_UP;
        } else if (gKswordArkSystemTimeState.lastCommand ==
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN) {
            flags |= KSWORD_ARK_SYSTEM_TIME_STATE_SLOW_DOWN;
        }

        if (kswordArkSystemTimeReadSlot(
            gKswordArkSystemTimeState.resolution.primarySlot,
            &primary) &&
            primary ==
                kswordArkSystemTimeCounterHookAddress()) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_PRIMARY_HOOKED;
        }
        if (kswordArkSystemTimeReadSlot(
            gKswordArkSystemTimeState.resolution.secondarySlot,
            &secondary) &&
            secondary ==
                kswordArkSystemTimeCounterHookAddress()) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_SECONDARY_HOOKED;
        }
        if (gKswordArkSystemTimeState.qpcBypassPatched) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_QPC_BYPASS_DISABLED;
        }
        if (gKswordArkSystemTimeState.patchBitsCaptured) {
            flags |=
                KSWORD_ARK_SYSTEM_TIME_STATE_INTERNAL_FLAG_PATCHED;
        }
    }
    if (gKswordArkSystemTimeState.resolution.usesHandlerTable) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_HANDLER_TABLE;
    }
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.conflictDetected,
            0L,
            0L) != 0L) {
        flags |= KSWORD_ARK_SYSTEM_TIME_STATE_CONFLICT;
    }
    return flags;
}

/* Write the current state to the fixed query response; the caller must hold the control lock. */
static
VOID
kswordArkSystemTimeFillQueryLocked(
    _Out_ KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE* response
    )
{
    KswordArkSystemTimeHypervDiagnostics hyperv = { 0 };
    LARGE_INTEGER counter = { 0 };

    (void)kswordArkSystemTimeHypervQuery(&hyperv);
    RtlZeroMemory(response, sizeof(*response));
    response->version =
        KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->status = (ULONG)InterlockedCompareExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        0L,
        0L);
    response->stateFlags =
        kswordArkSystemTimeStateFlagsLocked();
    response->generation = (ULONG)InterlockedCompareExchange(
        &gKswordArkSystemTimeState.generation,
        0L,
        0L);
    response->command =
        gKswordArkSystemTimeState.lastCommand;
    response->factor =
        gKswordArkSystemTimeState.factor;
    response->osBuildNumber =
        gKswordArkSystemTimeState.resolution.osBuildNumber;
    response->lastStatus = InterlockedCompareExchange(
        &gKswordArkSystemTimeState.lastStatus,
        0L,
        0L);
    response->resolutionMode =
        gKswordArkSystemTimeState.resolutionMode;
    response->backend =
        gKswordArkSystemTimeState.backend;

    counter = KeQueryPerformanceCounter(NULL);
    response->counterValue =
        (ULONGLONG)counter.QuadPart;
    response->counterSourceAddress =
        (ULONGLONG)(ULONG_PTR)
            gKswordArkSystemTimeState.resolution.counterDescriptor;
    response->primarySlotAddress =
        (ULONGLONG)(ULONG_PTR)
            gKswordArkSystemTimeState.resolution.primarySlot;
    response->secondarySlotAddress =
        (ULONGLONG)(ULONG_PTR)
            gKswordArkSystemTimeState.resolution.secondarySlot;
    response->hypervisorSharedPageAddress =
        (ULONGLONG)(ULONG_PTR)hyperv.sharedUserVa;
    response->hypervisorTimeUpdateLock =
        hyperv.timeUpdateLock;
    response->hypervisorOriginalMultiplier =
        hyperv.originalMultiplier;
    response->hypervisorOriginalBias =
        hyperv.originalBias;
    response->hypervisorCurrentMultiplier =
        hyperv.currentMultiplier;
    response->hypervisorCurrentBias =
        hyperv.currentBias;
}

/*
 * Stop maintenance and restore the takeover state.
 * The driver image can only be safely unloaded after waiting for in-flight hooks to exit.
 */
static
NTSTATUS
kswordArkSystemTimeDeactivateLocked(
    VOID
    )
{
    BOOLEAN primaryRestored = TRUE;
    BOOLEAN secondaryRestored = TRUE;
    NTSTATUS hypervStatus = STATUS_SUCCESS;
    NTSTATUS bypassStatus = STATUS_SUCCESS;
    ULONG retryIndex = 0UL;
    LARGE_INTEGER delay = { 0 };

    InterlockedExchange(
        &gKswordArkSystemTimeState.active,
        0L);
    (void)KeCancelTimer(
        &gKswordArkSystemTimeState.maintenanceTimer);
    KeFlushQueuedDpcs();

    if (gKswordArkSystemTimeState.backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        hypervStatus = kswordArkSystemTimeHypervRestore();
    }
    if (gKswordArkSystemTimeState.originalPrimary != NULL) {
        primaryRestored = kswordArkSystemTimeRestoreSlot(
            gKswordArkSystemTimeState.resolution.primarySlot,
            gKswordArkSystemTimeState.originalPrimary);
    }
    if (gKswordArkSystemTimeState.originalSecondary != NULL) {
        secondaryRestored = kswordArkSystemTimeRestoreSlot(
            gKswordArkSystemTimeState.resolution.secondarySlot,
            gKswordArkSystemTimeState.originalSecondary);
    }

    bypassStatus = kswordArkSystemTimeRestoreBypasses();
    KeMemoryBarrier();
    delay.QuadPart =
        KSW_SYSTEM_TIME_DRAIN_DELAY_100NS;
    for (retryIndex = 0UL;
         retryIndex < KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT;
         ++retryIndex) {
        if (kswordArkSystemTimeCounterInFlight() == 0L) {
            break;
        }
        (void)KeDelayExecutionThread(
            KernelMode,
            FALSE,
            &delay);
    }

    gKswordArkSystemTimeState.lastCommand =
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
    gKswordArkSystemTimeState.factor = 1UL;
    kswordArkSystemTimeCounterReset();

    if (!primaryRestored ||
        !secondaryRestored ||
        !NT_SUCCESS(hypervStatus) ||
        !NT_SUCCESS(bypassStatus) ||
        retryIndex == KSW_SYSTEM_TIME_DRAIN_RETRY_COUNT) {
        const NTSTATUS kFailureStatus =
            !NT_SUCCESS(hypervStatus)
            ? hypervStatus
            : !NT_SUCCESS(bypassStatus)
                ? bypassStatus
                : STATUS_CONFLICTING_ADDRESSES;

        InterlockedExchange(
            &gKswordArkSystemTimeState.conflictDetected,
            1L);
        InterlockedExchange(
            &gKswordArkSystemTimeState.runtimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &gKswordArkSystemTimeState.lastStatus,
            kFailureStatus);
        return kFailureStatus;
    }

    InterlockedExchange(
        &gKswordArkSystemTimeState.conflictDetected,
        0L);
    InterlockedExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &gKswordArkSystemTimeState.lastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/* Convert Hyper-V detection failure into a stable UI state, rather than disguising different failures as 'not present'. */
static
ULONG
kswordArkSystemTimeHypervFailureStatus(
    _In_ NTSTATUS status,
    _In_ BOOLEAN duringWrite
    )
{
    if (status == STATUS_NOT_SUPPORTED) {
        return KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT;
    }
    if (status == STATUS_DEVICE_NOT_READY ||
        status == STATUS_PROCEDURE_NOT_FOUND) {
        return KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE;
    }
    if (status == STATUS_CONFLICTING_ADDRESSES ||
        status == STATUS_DATA_ERROR ||
        status == STATUS_RETRY) {
        return KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_VALIDATION_FAILED;
    }
    return duringWrite
        ? KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_WRITE_FAILED
        : KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE;
}

/* Install kernel counter slots and configure the user-mode QPC path according to the selected backend. */
static
NTSTATUS
kswordArkSystemTimeActivateLocked(
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    KswSystemTimeCounterRoutine originalCounter = NULL;
    LONGLONG initialCounter = 0LL;
    LARGE_INTEGER dueTime = { 0 };
    BOOLEAN hypervPrepared = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    status = kswordArkSystemTimeResolveLocked();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkSystemTimeCaptureOriginalsLocked();
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &gKswordArkSystemTimeState.runtimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &gKswordArkSystemTimeState.lastStatus,
            status);
        return status;
    }

    if (gKswordArkSystemTimeState.backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        status = kswordArkSystemTimeHypervPrepare();
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(
                &gKswordArkSystemTimeState.runtimeStatus,
                (LONG)kswordArkSystemTimeHypervFailureStatus(
                    status,
                    FALSE));
            InterlockedExchange(
                &gKswordArkSystemTimeState.lastStatus,
                status);
            if (status == STATUS_CONFLICTING_ADDRESSES ||
                status == STATUS_DATA_ERROR) {
                InterlockedExchange(
                    &gKswordArkSystemTimeState.conflictDetected,
                    1L);
            }
            return status;
        }
        hypervPrepared = TRUE;
    }

    originalCounter =
        (KswSystemTimeCounterRoutine)
            gKswordArkSystemTimeState.originalPrimary;
    initialCounter = originalCounter();
    kswordArkSystemTimeCounterActivate(
        gKswordArkSystemTimeState.originalPrimary,
        initialCounter,
        command,
        factor);
    gKswordArkSystemTimeState.lastCommand = command;
    gKswordArkSystemTimeState.factor = factor;
    InterlockedExchange(
        &gKswordArkSystemTimeState.conflictDetected,
        0L);

    status = kswordArkSystemTimeConfigureBypassesLocked(
        gKswordArkSystemTimeState.backend ==
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT);
    if (!NT_SUCCESS(status)) {
        kswordArkSystemTimeCounterReset();
        if (hypervPrepared) {
            (void)kswordArkSystemTimeHypervRestore();
        }
        gKswordArkSystemTimeState.lastCommand =
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        gKswordArkSystemTimeState.factor = 1UL;
        InterlockedExchange(
            &gKswordArkSystemTimeState.runtimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_PATCH_FAILED);
        InterlockedExchange(
            &gKswordArkSystemTimeState.lastStatus,
            status);
        return status;
    }

    if (!kswordArkSystemTimePatchSlot(
            gKswordArkSystemTimeState.resolution.primarySlot,
            gKswordArkSystemTimeState.originalPrimary)) {
        (void)kswordArkSystemTimeRestoreBypasses();
        status = STATUS_CONFLICTING_ADDRESSES;
    } else if (!kswordArkSystemTimePatchSlot(
            gKswordArkSystemTimeState.resolution.secondarySlot,
            gKswordArkSystemTimeState.originalSecondary)) {
        (void)kswordArkSystemTimeRestoreSlot(
            gKswordArkSystemTimeState.resolution.primarySlot,
            gKswordArkSystemTimeState.originalPrimary);
        (void)kswordArkSystemTimeRestoreBypasses();
        status = STATUS_CONFLICTING_ADDRESSES;
    }

    if (!NT_SUCCESS(status)) {
        if (hypervPrepared) {
            (void)kswordArkSystemTimeHypervRestore();
        }
        kswordArkSystemTimeCounterReset();
        gKswordArkSystemTimeState.lastCommand =
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        gKswordArkSystemTimeState.factor = 1UL;
        InterlockedExchange(
            &gKswordArkSystemTimeState.conflictDetected,
            1L);
        InterlockedExchange(
            &gKswordArkSystemTimeState.runtimeStatus,
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
        InterlockedExchange(
            &gKswordArkSystemTimeState.lastStatus,
            status);
        return status;
    }

    if (gKswordArkSystemTimeState.backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        status = kswordArkSystemTimeHypervActivate(
            command,
            factor);
        if (!NT_SUCCESS(status)) {
            (void)kswordArkSystemTimeRestoreSlot(
                gKswordArkSystemTimeState.resolution.primarySlot,
                gKswordArkSystemTimeState.originalPrimary);
            (void)kswordArkSystemTimeRestoreSlot(
                gKswordArkSystemTimeState.resolution.secondarySlot,
                gKswordArkSystemTimeState.originalSecondary);
            (void)kswordArkSystemTimeRestoreBypasses();
            (void)kswordArkSystemTimeHypervRestore();
            kswordArkSystemTimeCounterReset();
            gKswordArkSystemTimeState.lastCommand =
                KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
            gKswordArkSystemTimeState.factor = 1UL;
            InterlockedExchange(
                &gKswordArkSystemTimeState.runtimeStatus,
                (LONG)kswordArkSystemTimeHypervFailureStatus(
                    status,
                    TRUE));
            InterlockedExchange(
                &gKswordArkSystemTimeState.lastStatus,
                status);
            if (status == STATUS_CONFLICTING_ADDRESSES ||
                status == STATUS_DATA_ERROR) {
                InterlockedExchange(
                    &gKswordArkSystemTimeState.conflictDetected,
                    1L);
            }
            return status;
        }
    }

    InterlockedExchange(
        &gKswordArkSystemTimeState.active,
        1L);
    dueTime.QuadPart =
        -((LONGLONG)KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS *
            10000LL);
    (void)KeSetTimerEx(
        &gKswordArkSystemTimeState.maintenanceTimer,
        dueTime,
        KSW_SYSTEM_TIME_MAINTENANCE_PERIOD_MS,
        &gKswordArkSystemTimeState.maintenanceDpc);
    InterlockedExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &gKswordArkSystemTimeState.lastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/* In the active state, first settle the kernel counter, then continuously update the Hyper-V shared page with the same target. */
static
NTSTATUS
kswordArkSystemTimeReconfigureLocked(
    _In_ ULONG command,
    _In_ ULONG factor
    )
{
    const ULONG kOldCommand =
        gKswordArkSystemTimeState.lastCommand;
    const ULONG kOldFactor =
        gKswordArkSystemTimeState.factor;
    NTSTATUS hypervRollbackStatus = STATUS_SUCCESS;
    NTSTATUS counterRollbackStatus = STATUS_SUCCESS;
    NTSTATUS status =
        kswordArkSystemTimeCounterReconfigure(
            command,
            factor);

    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (gKswordArkSystemTimeState.backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        status = kswordArkSystemTimeHypervReconfigure(
            command,
            factor);
        if (!NT_SUCCESS(status)) {
            /*
             * The shared page may have already been committed, with only a stable read-back failure. First, roll back the shared
             * page to the old multiplier using the current kernel virtual count as a continuous anchor, then roll back to the kernel
             * multiplier; any rollback failure stops takeover to avoid divergence between user-mode and kernel-mode timing paths.
             */
            hypervRollbackStatus =
                kswordArkSystemTimeHypervReconfigure(
                    kOldCommand,
                    kOldFactor);
            counterRollbackStatus =
                kswordArkSystemTimeCounterReconfigure(
                    kOldCommand,
                    kOldFactor);
            if (!NT_SUCCESS(hypervRollbackStatus) ||
                !NT_SUCCESS(counterRollbackStatus)) {
                (void)kswordArkSystemTimeDeactivateLocked();
            }
            InterlockedExchange(
                &gKswordArkSystemTimeState.runtimeStatus,
                (LONG)kswordArkSystemTimeHypervFailureStatus(
                    status,
                    TRUE));
            InterlockedExchange(
                &gKswordArkSystemTimeState.lastStatus,
                status);
            if (status == STATUS_CONFLICTING_ADDRESSES ||
                status == STATUS_DATA_ERROR) {
                InterlockedExchange(
                    &gKswordArkSystemTimeState.conflictDetected,
                    1L);
            }
            return status;
        }
    }

    gKswordArkSystemTimeState.lastCommand = command;
    gKswordArkSystemTimeState.factor = factor;
    InterlockedExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &gKswordArkSystemTimeState.lastStatus,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

/*
 * The maintenance DPC accepts only two states: 'still the original function' or 'still this hook'.
 * Hyper-V pages accept only original snapshots or snapshots from this feature; unknown writes trigger a failure shutdown.
 */
static
VOID
kswordArkSystemTimeMaintenanceDpc(
    _In_ PKDPC dpc,
    _In_opt_ PVOID deferredContext,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2
    )
{
    BOOLEAN primaryOk = TRUE;
    BOOLEAN secondaryOk = TRUE;
    NTSTATUS hypervStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(deferredContext);
    UNREFERENCED_PARAMETER(systemArgument1);
    UNREFERENCED_PARAMETER(systemArgument2);

    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.active,
            0L,
            0L) == 0L) {
        return;
    }

    primaryOk = kswordArkSystemTimePatchSlot(
        gKswordArkSystemTimeState.resolution.primarySlot,
        gKswordArkSystemTimeState.originalPrimary);
    secondaryOk = kswordArkSystemTimePatchSlot(
        gKswordArkSystemTimeState.resolution.secondarySlot,
        gKswordArkSystemTimeState.originalSecondary);
    if (primaryOk && secondaryOk &&
        gKswordArkSystemTimeState.backend ==
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        hypervStatus = kswordArkSystemTimeHypervMaintain();
        if (hypervStatus == STATUS_RETRY ||
            hypervStatus == STATUS_DEVICE_BUSY) {
            return;
        }
    }
    if (primaryOk && secondaryOk &&
        NT_SUCCESS(hypervStatus)) {
        return;
    }

    InterlockedExchange(
        &gKswordArkSystemTimeState.active,
        0L);
    (void)kswordArkSystemTimeRestoreSlot(
        gKswordArkSystemTimeState.resolution.primarySlot,
        gKswordArkSystemTimeState.originalPrimary);
    (void)kswordArkSystemTimeRestoreSlot(
        gKswordArkSystemTimeState.resolution.secondarySlot,
        gKswordArkSystemTimeState.originalSecondary);
    if (gKswordArkSystemTimeState.backend ==
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC) {
        (void)kswordArkSystemTimeHypervRestore();
    }
    (void)kswordArkSystemTimeRestoreBypasses();
    kswordArkSystemTimeCounterReset();
    InterlockedExchange(
        &gKswordArkSystemTimeState.conflictDetected,
        1L);
    InterlockedExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT);
    InterlockedExchange(
        &gKswordArkSystemTimeState.lastStatus,
        NT_SUCCESS(hypervStatus)
            ? STATUS_CONFLICTING_ADDRESSES
            : hypervStatus);
    (void)InterlockedIncrement(
        &gKswordArkSystemTimeState.generation);
}

/* During driver load, only initialize state and DPC; actual kernel takeover must still be explicitly triggered by the UI. */
VOID
kswordArkSystemTimeInitialize(
    VOID
    )
{
    RtlZeroMemory(
        &gKswordArkSystemTimeState,
        sizeof(gKswordArkSystemTimeState));
    kswordArkSystemTimeCounterInitialize();
    kswordArkSystemTimeHypervInitialize();
    ExInitializePushLock(
        &gKswordArkSystemTimeState.controlLock);
    KeInitializeTimerEx(
        &gKswordArkSystemTimeState.maintenanceTimer,
        SynchronizationTimer);
    KeInitializeDpc(
        &gKswordArkSystemTimeState.maintenanceDpc,
        kswordArkSystemTimeMaintenanceDpc,
        NULL);
    gKswordArkSystemTimeState.lastCommand =
        KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
    gKswordArkSystemTimeState.factor = 1UL;
    gKswordArkSystemTimeState.resolutionMode =
        KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT;
    gKswordArkSystemTimeState.backend =
        KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC;
    InterlockedExchange(
        &gKswordArkSystemTimeState.generation,
        1L);
    InterlockedExchange(
        &gKswordArkSystemTimeState.runtimeStatus,
        KSWORD_ARK_SYSTEM_TIME_STATUS_OK);
    InterlockedExchange(
        &gKswordArkSystemTimeState.lastStatus,
        STATUS_SUCCESS);
    InterlockedExchange(
        &gKswordArkSystemTimeState.initialized,
        1L);
}

/* The unload path unconditionally cancels the DPC and performs full recovery and in-flight draining while active. */
VOID
kswordArkSystemTimeUninitialize(
    VOID
    )
{
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.initialized,
            0L,
            0L) == 0L) {
        return;
    }

    kswordArkAcquirePushLockExclusive(
        &gKswordArkSystemTimeState.controlLock);
    (void)kswordArkSystemTimeDeactivateLocked();
    InterlockedExchange(
        &gKswordArkSystemTimeState.initialized,
        0L);
    kswordArkReleasePushLockExclusive(
        &gKswordArkSystemTimeState.controlLock);
}

/* The query attempts to read-only parse the current build but installs no hooks or modifies bypass bits. */
NTSTATUS
kswordArkSystemTimeQuery(
    _Out_ KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE* response
    )
{
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &gKswordArkSystemTimeState.initialized,
            0L,
            0L) == 0L) {
        return STATUS_DEVICE_NOT_READY;
    }

    kswordArkAcquirePushLockExclusive(
        &gKswordArkSystemTimeState.controlLock);
    if (!gKswordArkSystemTimeState.resolved) {
        (void)kswordArkSystemTimeResolveLocked();
    }
    kswordArkSystemTimeFillQueryLocked(response);
    kswordArkReleasePushLockExclusive(
        &gKswordArkSystemTimeState.controlLock);
    return STATUS_SUCCESS;
}

/*
 * Validate protocol, confirm token, rate, and generation at the control entry point before executing the action.
 * RESET is an idempotent recovery command, unaffected by expiration generation or acknowledgment tokens; when takeover
 * occurs, switch to continuous 1x without directly reverting the leading virtual counter to the smaller original counter.
 */
NTSTATUS
kswordArkSystemTimeControl(
    _In_ const KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST* request,
    _Out_ KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE* response
    )
{
    ULONG oldFlags = 0UL;
    ULONG oldGeneration = 0UL;
    NTSTATUS actionStatus = STATUS_SUCCESS;

    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version =
        KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
    response->size = sizeof(*response);

    if (request->version !=
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
         request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP &&
         request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN)) {
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        (request->factor <
            KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR ||
         request->factor >
            KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR)) {
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        (request->resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT &&
         request->resolutionMode !=
            KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED)) {
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        request->backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC &&
        request->backend !=
            KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT) {
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        ((request->flags &
            KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
         request->confirmationToken !=
            KSWORD_ARK_SYSTEM_TIME_CONFIRMATION_TOKEN)) {
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED;
        response->lastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        return STATUS_SUCCESS;
    }

    kswordArkAcquirePushLockExclusive(
        &gKswordArkSystemTimeState.controlLock);
    oldFlags = kswordArkSystemTimeStateFlagsLocked();
    oldGeneration = (ULONG)InterlockedCompareExchange(
        &gKswordArkSystemTimeState.generation,
        0L,
        0L);

    if (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        InterlockedCompareExchange(
            &gKswordArkSystemTimeState.conflictDetected,
            0L,
            0L) != 0L) {
        actionStatus = STATUS_CONFLICTING_ADDRESSES;
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT;
    } else if (request->command !=
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET &&
        request->expectedGeneration != 0UL &&
        request->expectedGeneration != oldGeneration) {
        actionStatus = STATUS_REVISION_MISMATCH;
        response->status =
            KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION;
    } else if (request->command ==
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET) {
        if (InterlockedCompareExchange(
                &gKswordArkSystemTimeState.active,
                0L,
                0L) != 0L) {
            /*
             * After acceleration, the virtual counter may lead the original QPC. Directly restoring the function slot will cause the system counter to jump backward.
             * Keep the hook and atomically switch to 1x so that existing offsets remain unchanged while subsequent increments resume normal speed.
             */
            actionStatus =
                kswordArkSystemTimeReconfigureLocked(
                    KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
                    1UL);
        } else {
            actionStatus =
                kswordArkSystemTimeDeactivateLocked();
        }
        response->status = NT_SUCCESS(actionStatus)
            ? KSWORD_ARK_SYSTEM_TIME_STATUS_OK
            : KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT;
    } else {
        /*
         * Allows switching schemes and forces re-parsing when inactive.
         * When active, only the same scheme can continue to adjust the multiplier.
         */
        actionStatus =
            kswordArkSystemTimeSelectResolutionModeLocked(
                request->resolutionMode);
        if (NT_SUCCESS(actionStatus)) {
            actionStatus = kswordArkSystemTimeSelectBackendLocked(
                request->backend);
        }
        if (!NT_SUCCESS(actionStatus)) {
            response->status =
                KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST;
        } else if (InterlockedCompareExchange(
                &gKswordArkSystemTimeState.active,
                0L,
                0L) != 0L) {
            actionStatus =
                kswordArkSystemTimeReconfigureLocked(
                    request->command,
                    request->factor);
            response->status = NT_SUCCESS(actionStatus)
                ? KSWORD_ARK_SYSTEM_TIME_STATUS_OK
                : (ULONG)InterlockedCompareExchange(
                    &gKswordArkSystemTimeState.runtimeStatus,
                    0L,
                    0L);
        } else {
            actionStatus =
                kswordArkSystemTimeActivateLocked(
                    request->command,
                    request->factor);
            response->status = NT_SUCCESS(actionStatus)
                ? KSWORD_ARK_SYSTEM_TIME_STATUS_OK
                : (ULONG)InterlockedCompareExchange(
                    &gKswordArkSystemTimeState.runtimeStatus,
                    0L,
                    0L);
        }
    }

    if (NT_SUCCESS(actionStatus) &&
        response->status ==
            KSWORD_ARK_SYSTEM_TIME_STATUS_OK) {
        (void)InterlockedIncrement(
            &gKswordArkSystemTimeState.generation);
    }

    response->oldStateFlags = oldFlags;
    response->newStateFlags =
        kswordArkSystemTimeStateFlagsLocked();
    response->oldGeneration = oldGeneration;
    response->newGeneration =
        (ULONG)InterlockedCompareExchange(
            &gKswordArkSystemTimeState.generation,
            0L,
            0L);
    response->command =
        gKswordArkSystemTimeState.lastCommand;
    response->factor =
        gKswordArkSystemTimeState.factor;
    response->osBuildNumber =
        gKswordArkSystemTimeState.resolution.osBuildNumber;
    response->lastStatus = actionStatus;
    response->resolutionMode =
        gKswordArkSystemTimeState.resolutionMode;
    response->backend =
        gKswordArkSystemTimeState.backend;
    response->counterValue =
        (ULONGLONG)KeQueryPerformanceCounter(NULL).QuadPart;
    kswordArkReleasePushLockExclusive(
        &gKswordArkSystemTimeState.controlLock);
    return STATUS_SUCCESS;
}

/*++

Module Name:

    page_fault_manager.c

Abstract:

    Per-processor shadow-IDT lifecycle and nonpaged vector-14 dispatcher.

Environment:

    Installation runs at PASSIVE_LEVEL.  The dispatcher runs on the exception
    path without allocation, pageable access, blocking locks, or formatted I/O.

--*/

#include "page_fault_manager.h"
#include "rxpf_diagnostics.h"
#include "src/platform/pool_compat.h"

#define KSW_RXPF_IDT_TAG 'iPxR'
#define KSW_RXPF_IDT_VECTOR_COUNT 256UL
#define KSW_RXPF_IDT_ENTRY_BYTES 16UL
#define KSW_RXPF_PAGE_FAULT_VECTOR 14UL

#pragma pack(push, 1)
typedef struct KswRxpfIdtr
{
    USHORT limit;
    ULONG64 base;
} KswRxpfIdtr, *PkswRxpfIdtr;

typedef struct KswRxpfIdtEntry
{
    USHORT offsetLow;
    USHORT selector;
    UCHAR ist;
    UCHAR typeAttributes;
    USHORT offsetMiddle;
    ULONG offsetHigh;
    ULONG reserved;
} KswRxpfIdtEntry, *PkswRxpfIdtEntry;
#pragma pack(pop)

typedef struct KswRxpfCpuIdtState
{
    KswRxpfIdtr originalIdtr;
    KswRxpfIdtr shadowIdtr;
    KswRxpfIdtEntry originalPageFaultEntry;
    PVOID originalPageFaultHandler;
    PVOID shadowTable;
    PROCESSOR_NUMBER processorNumber;
    ULONG processorIndex;
    volatile LONG active;
    volatile LONG installed;
    volatile LONG handlerDepth;
    volatile LONG lastStatus;
} KswRxpfCpuIdtState, *PkswRxpfCpuIdtState;

typedef struct KswRxpfPageFaultState
{
    PkswRxpfPageTable pageTable;
    PkswRxpfCpuIdtState cpus;
    ULONG cpuCapacity;
    volatile LONG cpuCount;
    PVOID processorChangeHandle;
    PVOID emergencyOriginalHandler;
    EX_PUSH_LOCK controlLock;
    volatile LONG initialized;
    volatile LONG installing;
    volatile LONG installed;
    volatile LONG lastStatus;
} KswRxpfPageFaultState;

static KswRxpfPageFaultState gKswRxpfPageFault;

C_ASSERT(sizeof(KswRxpfIdtr) == 10U);
C_ASSERT(sizeof(KswRxpfIdtEntry) == 16U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, r15) == 0U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, r11) == 32U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, rax) == 112U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, errorCode) == 120U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, rip) == 128U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, cs) == 136U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, rflags) == 144U);
C_ASSERT(FIELD_OFFSET(KswRxpfTrapFrame, hardwareRsp) == 152U);
C_ASSERT(sizeof(KswRxpfTrapFrame) == 168U);

static ULONGLONG
kswRxpfIdtHandlerAddress(
    _In_ const KswRxpfIdtEntry* entry
    )
{
    ULONGLONG address = 0ULL;

    /* Combine the architectural offset fragments without unaligned loads. */
    address = (ULONGLONG)entry->offsetLow;
    address |= ((ULONGLONG)entry->offsetMiddle) << 16;
    address |= ((ULONGLONG)entry->offsetHigh) << 32;
    return address;
}

static VOID
kswRxpfIdtSetHandlerAddress(
    _Inout_ KswRxpfIdtEntry* entry,
    _In_ ULONGLONG handlerAddress
    )
{
    ULONGLONG address = handlerAddress;

    /* Change only the three handler-offset fields in the copied descriptor. */
    entry->offsetLow = (USHORT)(address & 0xFFFFULL);
    entry->offsetMiddle = (USHORT)((address >> 16) & 0xFFFFULL);
    entry->offsetHigh = (ULONG)(address >> 32);
}

static BOOLEAN
kswRxpfCanonicalKernelAddress(
    _In_ ULONGLONG address
    )
{
    /* All installed handler targets must be canonical kernel addresses. */
    return (address >> 48) == 0xFFFFULL &&
        address >= (ULONGLONG)(ULONG_PTR)MmSystemRangeStart;
}

static VOID
kswRxpfProcessorChangeCallback(
    _In_ PVOID callbackContext,
    _In_ PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT changeContext,
    _Inout_ PNTSTATUS operationStatus
    )
{
    UNREFERENCED_PARAMETER(callbackContext);

    /* Deny dynamic processor addition while capture/install/restore is active. */
    if (changeContext != NULL && operationStatus != NULL &&
        changeContext->State == KeProcessorAddStartNotify &&
        (InterlockedCompareExchange(
            &gKswRxpfPageFault.installing,
            1,
            1) != 0 ||
         InterlockedCompareExchange(
            &gKswRxpfPageFault.installed,
            1,
            1) != 0)) {
        *operationStatus = STATUS_DEVICE_BUSY;
    }
}

static VOID
kswRxpfFreeShadowTables(
    VOID
    )
{
    ULONG index = 0UL;

    /* Rows are unreachable from vector 14 before this control-path cleanup. */
    for (index = 0UL; index < gKswRxpfPageFault.cpuCapacity; ++index) {
        PkswRxpfCpuIdtState cpu = &gKswRxpfPageFault.cpus[index];
        PVOID shadow = cpu->shadowTable;

        RtlZeroMemory(cpu, sizeof(*cpu));
        if (shadow != NULL) {
            ExFreePoolWithTag(shadow, KSW_RXPF_IDT_TAG);
        }
    }
    InterlockedExchange(&gKswRxpfPageFault.cpuCount, 0);
    gKswRxpfPageFault.emergencyOriginalHandler = NULL;
}

static NTSTATUS
kswRxpfCaptureShadowTables(
    VOID
    )
{
    ULONG activeCount =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    ULONG globalIndex = 0UL;

    /* The preallocated row array must cover the complete stable topology. */
    if (activeCount == 0UL ||
        activeCount > gKswRxpfPageFault.cpuCapacity) {
        return STATUS_NOT_SUPPORTED;
    }
    kswRxpfFreeShadowTables();

    /* Capture and copy each processor's own IDT while pinned to that CPU. */
    for (globalIndex = 0UL; globalIndex < activeCount; ++globalIndex) {
        PROCESSOR_NUMBER processor;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        KswRxpfIdtr idtr;
        PkswRxpfCpuIdtState cpu =
            &gKswRxpfPageFault.cpus[globalIndex];
        SIZE_T tableBytes = 0U;
        PkswRxpfIdtEntry shadowEntries = NULL;
        KswRxpfIdtEntry pageFaultEntry;
        ULONGLONG originalHandler = 0ULL;
        NTSTATUS status = STATUS_SUCCESS;

        RtlZeroMemory(&processor, sizeof(processor));
        status = KeGetProcessorNumberFromIndex(globalIndex, &processor);
        if (!NT_SUCCESS(status) ||
            processor.Number >= sizeof(KAFFINITY) * 8UL) {
            kswRxpfFreeShadowTables();
            return STATUS_NOT_SUPPORTED;
        }
        cpu->shadowTable = kswordArkAllocateNonPagedPool(
            KSW_RXPF_IDT_VECTOR_COUNT * KSW_RXPF_IDT_ENTRY_BYTES,
            KSW_RXPF_IDT_TAG);
        if (cpu->shadowTable == NULL) {
            kswRxpfFreeShadowTables();
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(
            cpu->shadowTable,
            KSW_RXPF_IDT_VECTOR_COUNT * KSW_RXPF_IDT_ENTRY_BYTES);

        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processor.Group;
        targetAffinity.Mask = ((KAFFINITY)1) << processor.Number;
        KeSetSystemGroupAffinityThread(
            &targetAffinity,
            &previousAffinity);
        RtlZeroMemory(&idtr, sizeof(idtr));
        __sidt(&idtr);
        tableBytes = (SIZE_T)idtr.limit + 1U;
        if (idtr.base == 0ULL ||
            tableBytes < (KSW_RXPF_PAGE_FAULT_VECTOR + 1UL) *
                KSW_RXPF_IDT_ENTRY_BYTES ||
            tableBytes > KSW_RXPF_IDT_VECTOR_COUNT *
                KSW_RXPF_IDT_ENTRY_BYTES) {
            KeRevertToUserGroupAffinityThread(&previousAffinity);
            kswRxpfFreeShadowTables();
            return STATUS_NOT_SUPPORTED;
        }
        __try {
            RtlCopyMemory(
                cpu->shadowTable,
                (const VOID*)(ULONG_PTR)idtr.base,
                tableBytes);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
        }
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        if (!NT_SUCCESS(status)) {
            kswRxpfFreeShadowTables();
            return status;
        }

        shadowEntries =
            (PkswRxpfIdtEntry)cpu->shadowTable;
        RtlCopyMemory(
            &pageFaultEntry,
            &shadowEntries[KSW_RXPF_PAGE_FAULT_VECTOR],
            sizeof(pageFaultEntry));
        originalHandler = kswRxpfIdtHandlerAddress(&pageFaultEntry);

        /* IF must stay masked until the handler joins its lifecycle read side. */
        if ((pageFaultEntry.typeAttributes & 0x80U) == 0U ||
            (pageFaultEntry.typeAttributes & 0x0FU) != 0x0EU ||
            (pageFaultEntry.ist & 0x07U) != 0U ||
            pageFaultEntry.selector == 0U ||
            pageFaultEntry.reserved != 0UL ||
            !kswRxpfCanonicalKernelAddress(originalHandler)) {
            kswRxpfFreeShadowTables();
            return STATUS_NOT_SUPPORTED;
        }

        /* Preserve every gate attribute and replace only the handler offset. */
        kswRxpfIdtSetHandlerAddress(
            &shadowEntries[KSW_RXPF_PAGE_FAULT_VECTOR],
            (ULONGLONG)(ULONG_PTR)KswRxpfPageFaultStub);
        cpu->originalIdtr = idtr;
        cpu->shadowIdtr.limit = idtr.limit;
        cpu->shadowIdtr.base =
            (ULONG64)(ULONG_PTR)cpu->shadowTable;
        cpu->originalPageFaultEntry = pageFaultEntry;
        cpu->originalPageFaultHandler =
            (PVOID)(ULONG_PTR)originalHandler;
        cpu->processorNumber = processor;
        cpu->processorIndex = globalIndex;
        cpu->lastStatus = STATUS_SUCCESS;
        KeMemoryBarrier();
        InterlockedExchange(&cpu->active, 1);
        if (gKswRxpfPageFault.emergencyOriginalHandler == NULL) {
            gKswRxpfPageFault.emergencyOriginalHandler =
                cpu->originalPageFaultHandler;
        }
    }

    /* Reject a topology change that raced the capture window. */
    if (KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != activeCount) {
        kswRxpfFreeShadowTables();
        return STATUS_RETRY;
    }
    InterlockedExchange(
        &gKswRxpfPageFault.cpuCount,
        (LONG)activeCount);
    return STATUS_SUCCESS;
}

static ULONG_PTR
kswRxpfInstallIpi(
    _In_ ULONG_PTR context
    )
{
    ULONG processorIndex = KeGetCurrentProcessorIndex();
    KswRxpfIdtr currentIdtr;
    KswRxpfIdtr verifyIdtr;
    PkswRxpfCpuIdtState cpu = NULL;

    UNREFERENCED_PARAMETER(context);
    if (processorIndex >= gKswRxpfPageFault.cpuCapacity) {
        return 0ULL;
    }
    cpu = &gKswRxpfPageFault.cpus[processorIndex];
    if (InterlockedCompareExchange(&cpu->active, 1, 1) == 0) {
        cpu->lastStatus = STATUS_NOT_FOUND;
        return 0ULL;
    }

    /* Refuse to replace an IDTR that changed after the per-CPU capture. */
    RtlZeroMemory(&currentIdtr, sizeof(currentIdtr));
    __sidt(&currentIdtr);
    if (currentIdtr.base != cpu->originalIdtr.base ||
        currentIdtr.limit != cpu->originalIdtr.limit) {
        cpu->lastStatus = STATUS_REVISION_MISMATCH;
        return 0ULL;
    }
    __lidt(&cpu->shadowIdtr);
    KeMemoryBarrier();
    InterlockedExchange(&cpu->installed, 1);
    RtlZeroMemory(&verifyIdtr, sizeof(verifyIdtr));
    __sidt(&verifyIdtr);
    if (verifyIdtr.base != cpu->shadowIdtr.base ||
        verifyIdtr.limit != cpu->shadowIdtr.limit) {
        /* Conservatively retain Installed so rollback restores this CPU. */
        cpu->lastStatus = STATUS_UNSUCCESSFUL;
        return 0ULL;
    }
    cpu->lastStatus = STATUS_SUCCESS;
    return 1ULL;
}

static ULONG_PTR
kswRxpfRestoreIpi(
    _In_ ULONG_PTR context
    )
{
    ULONG processorIndex = KeGetCurrentProcessorIndex();
    KswRxpfIdtr verifyIdtr;
    PkswRxpfCpuIdtState cpu = NULL;

    UNREFERENCED_PARAMETER(context);
    if (processorIndex >= gKswRxpfPageFault.cpuCapacity) {
        return 0ULL;
    }
    cpu = &gKswRxpfPageFault.cpus[processorIndex];
    if (InterlockedCompareExchange(&cpu->active, 1, 1) == 0) {
        return 1ULL;
    }
    if (InterlockedCompareExchange(&cpu->installed, 1, 1) == 0) {
        cpu->lastStatus = STATUS_SUCCESS;
        return 1ULL;
    }

    /* Installed rows must return to the exact IDTR captured on that CPU. */
    __lidt(&cpu->originalIdtr);
    RtlZeroMemory(&verifyIdtr, sizeof(verifyIdtr));
    __sidt(&verifyIdtr);
    if (verifyIdtr.base != cpu->originalIdtr.base ||
        verifyIdtr.limit != cpu->originalIdtr.limit) {
        cpu->lastStatus = STATUS_UNSUCCESSFUL;
        return 0ULL;
    }
    KeMemoryBarrier();
    InterlockedExchange(&cpu->installed, 0);
    cpu->lastStatus = STATUS_SUCCESS;
    return 1ULL;
}

static NTSTATUS
kswRxpfVerifyAllRowsRestored(
    VOID
    )
{
    LONG cpuCount = InterlockedCompareExchange(
        &gKswRxpfPageFault.cpuCount,
        0,
        0);
    LONG index = 0;

    /* Every active row must report a verified restore before storage is freed. */
    for (index = 0; index < cpuCount; ++index) {
        PkswRxpfCpuIdtState cpu = &gKswRxpfPageFault.cpus[index];

        if (InterlockedCompareExchange(&cpu->active, 1, 1) != 0 &&
            (InterlockedCompareExchange(&cpu->installed, 1, 1) != 0 ||
             cpu->lastStatus != STATUS_SUCCESS)) {
            return cpu->lastStatus != STATUS_SUCCESS
                ? cpu->lastStatus
                : STATUS_UNSUCCESSFUL;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfPageFaultManagerInitialize(
    _In_ PkswRxpfPageTable pageTable,
    _In_ ULONG maximumProcessorCount
    )
{
    SIZE_T allocationBytes = 0U;
    PkswRxpfCpuIdtState cpus = NULL;

    /* Allocate all topology rows before any IDT installation can begin. */
    if (pageTable == NULL || maximumProcessorCount == 0UL ||
        maximumProcessorCount > MAXULONG_PTR /
            sizeof(KswRxpfCpuIdtState)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &gKswRxpfPageFault.initialized,
            1,
            1) != 0) {
        return STATUS_SUCCESS;
    }
    allocationBytes =
        (SIZE_T)maximumProcessorCount * sizeof(KswRxpfCpuIdtState);
    cpus = (PkswRxpfCpuIdtState)kswordArkAllocateNonPagedPool(
        allocationBytes,
        KSW_RXPF_IDT_TAG);
    if (cpus == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(cpus, allocationBytes);
    RtlZeroMemory(&gKswRxpfPageFault, sizeof(gKswRxpfPageFault));
    gKswRxpfPageFault.pageTable = pageTable;
    gKswRxpfPageFault.cpus = cpus;
    gKswRxpfPageFault.cpuCapacity = maximumProcessorCount;
    ExInitializePushLock(&gKswRxpfPageFault.controlLock);
    gKswRxpfPageFault.processorChangeHandle =
        KeRegisterProcessorChangeCallback(
            kswRxpfProcessorChangeCallback,
            NULL,
            0UL);
    if (gKswRxpfPageFault.processorChangeHandle == NULL) {
        ExFreePoolWithTag(cpus, KSW_RXPF_IDT_TAG);
        RtlZeroMemory(&gKswRxpfPageFault, sizeof(gKswRxpfPageFault));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeMemoryBarrier();
    InterlockedExchange(&gKswRxpfPageFault.initialized, 1);
    return STATUS_SUCCESS;
}

VOID
kswRxpfPageFaultManagerUninitialize(
    VOID
    )
{
    PkswRxpfCpuIdtState cpus = gKswRxpfPageFault.cpus;
    PVOID callbackHandle =
        gKswRxpfPageFault.processorChangeHandle;
    LARGE_INTEGER retryDelay;

    /* Restore all CPUs before removing the topology callback and allocations. */
    retryDelay.QuadPart = -100000LL;
    while (!NT_SUCCESS(kswRxpfPageFaultRestore())) {
        /* A failed restore keeps every exception-visible allocation alive. */
        (void)KeDelayExecutionThread(KernelMode, FALSE, &retryDelay);
    }
    while (!NT_SUCCESS(kswRxpfDiagnosticsWaitForHandlers(5000UL))) {
        /* The manager owns exception-visible storage until every reader exits. */
    }
    if (callbackHandle != NULL) {
        KeDeregisterProcessorChangeCallback(callbackHandle);
    }
    kswRxpfFreeShadowTables();
    InterlockedExchange(&gKswRxpfPageFault.initialized, 0);
    KeMemoryBarrier();
    RtlZeroMemory(&gKswRxpfPageFault, sizeof(gKswRxpfPageFault));
    if (cpus != NULL) {
        ExFreePoolWithTag(cpus, KSW_RXPF_IDT_TAG);
    }
}

NTSTATUS
kswRxpfPageFaultInstall(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS rollbackStatus = STATUS_SUCCESS;
    LONG cpuCount = 0;
    LONG index = 0;

    /* Serialize capture/install/rollback against user control requests. */
    if (InterlockedCompareExchange(
            &gKswRxpfPageFault.initialized,
            1,
            1) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gKswRxpfPageFault.controlLock);
    if (InterlockedCompareExchange(
            &gKswRxpfPageFault.installed,
            1,
            1) != 0) {
        status = gKswRxpfPageFault.lastStatus;
        ExReleasePushLockExclusive(&gKswRxpfPageFault.controlLock);
        KeLeaveCriticalRegion();
        return NT_SUCCESS(status)
            ? STATUS_SUCCESS
            : status;
    }
    InterlockedExchange(&gKswRxpfPageFault.installing, 1);
    status = kswRxpfCaptureShadowTables();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    /* The IPI callback performs only SIDT/LIDT and fixed-row stores. */
    (void)KeIpiGenericCall(kswRxpfInstallIpi, 0ULL);
    cpuCount = InterlockedCompareExchange(
        &gKswRxpfPageFault.cpuCount,
        0,
        0);
    for (index = 0; index < cpuCount; ++index) {
        PkswRxpfCpuIdtState cpu = &gKswRxpfPageFault.cpus[index];

        if (InterlockedCompareExchange(&cpu->installed, 1, 1) == 0 ||
            cpu->lastStatus != STATUS_SUCCESS) {
            status = cpu->lastStatus != STATUS_SUCCESS
                ? cpu->lastStatus
                : STATUS_UNSUCCESSFUL;
            break;
        }
    }
    if (!NT_SUCCESS(status)) {
        /* Roll back every CPU that accepted the shadow before reporting failure. */
        (void)KeIpiGenericCall(kswRxpfRestoreIpi, 0ULL);
        rollbackStatus = kswRxpfVerifyAllRowsRestored();
        if (NT_SUCCESS(rollbackStatus)) {
            rollbackStatus =
                kswRxpfDiagnosticsWaitForHandlers(5000UL);
        }
        if (NT_SUCCESS(rollbackStatus)) {
            kswRxpfFreeShadowTables();
        } else {
            /* Keep restore callable and storage resident after partial rollback. */
            InterlockedExchange(&gKswRxpfPageFault.installed, 1);
            status = rollbackStatus;
        }
        goto Exit;
    }
    KeMemoryBarrier();
    InterlockedExchange(&gKswRxpfPageFault.installed, 1);

Exit:
    gKswRxpfPageFault.lastStatus = status;
    InterlockedExchange(&gKswRxpfPageFault.installing, 0);
    ExReleasePushLockExclusive(&gKswRxpfPageFault.controlLock);
    KeLeaveCriticalRegion();
    return status;
}

NTSTATUS
kswRxpfPageFaultRestore(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Idempotent restore is safe during DriverEntry rollback and final unload. */
    if (InterlockedCompareExchange(
            &gKswRxpfPageFault.initialized,
            1,
            1) == 0) {
        return STATUS_SUCCESS;
    }
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gKswRxpfPageFault.controlLock);
    if (InterlockedCompareExchange(
            &gKswRxpfPageFault.installed,
            1,
            1) == 0) {
        ExReleasePushLockExclusive(&gKswRxpfPageFault.controlLock);
        KeLeaveCriticalRegion();
        return STATUS_SUCCESS;
    }
    InterlockedExchange(&gKswRxpfPageFault.installing, 1);

    /* Every hooked CPU restores its original complete IDTR at IPI_LEVEL. */
    (void)KeIpiGenericCall(kswRxpfRestoreIpi, 0ULL);
    status = kswRxpfVerifyAllRowsRestored();
    if (NT_SUCCESS(status)) {
        status = kswRxpfDiagnosticsWaitForHandlers(5000UL);
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&gKswRxpfPageFault.installed, 0);
            kswRxpfFreeShadowTables();
        }
    }
    /* Failure intentionally leaves Installed set and all storage resident. */
    gKswRxpfPageFault.lastStatus = status;
    InterlockedExchange(&gKswRxpfPageFault.installing, 0);
    ExReleasePushLockExclusive(&gKswRxpfPageFault.controlLock);
    KeLeaveCriticalRegion();
    return status;
}

BOOLEAN
kswRxpfPageFaultIsInstalled(
    VOID
    )
{
    /* Return the atomic shadow-IDT publication state. */
    return InterlockedCompareExchange(
        &gKswRxpfPageFault.installed,
        1,
        1) != 0;
}

ULONG
kswRxpfPageFaultProcessorCount(
    VOID
    )
{
    /* Return the active topology captured for the current installation. */
    return (ULONG)InterlockedCompareExchange(
        &gKswRxpfPageFault.cpuCount,
        0,
        0);
}

static BOOLEAN
kswRxpfExecuteFaultClass(
    _In_ const KswRxpfTrapFrame* frame,
    _In_ ULONGLONG cr2
    )
{
    ULONGLONG error = frame->errorCode;

    /* Require P=1, W=0, U=0, RSVD=0, I/D=1 and no later extension bits. */
    return (frame->cs & 3ULL) == 0ULL &&
        cr2 == frame->rip &&
        (error & 0x01ULL) != 0ULL &&
        (error & 0x02ULL) == 0ULL &&
        (error & 0x04ULL) == 0ULL &&
        (error & 0x08ULL) == 0ULL &&
        (error & 0x10ULL) != 0ULL &&
        (error & ~0x1FULL) == 0ULL;
}

static BOOLEAN
kswRxpfResumeStackValid(
    _In_ ULONGLONG resumeRsp,
    _In_ ULONGLONG stackLow,
    _In_ ULONGLONG stackHigh
    )
{
    ULONGLONG frameBase = resumeRsp - 24ULL;

    /* Assembly writes a three-qword same-CPL IRET frame below logical RSP. */
    if (frameBase > resumeRsp || frameBase < stackLow ||
        resumeRsp > stackHigh || resumeRsp - frameBase != 24ULL) {
        return FALSE;
    }
    return MmIsAddressValid((PVOID)(ULONG_PTR)frameBase) &&
        MmIsAddressValid((PVOID)(ULONG_PTR)(resumeRsp - 1ULL));
}

ULONGLONG
NTAPI
KswRxpfPageFaultDispatch(
    _Inout_ PkswRxpfTrapFrame frame,
    _Out_ PVOID* transferTargetOut,
    _Out_ ULONGLONG* resumeRspOut,
    _Out_ PkswRxpfTrapFrame resumeFrameOut
    )
{
    ULONG processorIndex = KeGetCurrentProcessorIndex();
    PkswRxpfCpuIdtState cpu = NULL;
    PVOID originalHandler = gKswRxpfPageFault.emergencyOriginalHandler;
    ULONGLONG cr2 = __readcr2();
    ULONGLONG pageBase = cr2 & ~(PAGE_SIZE - 1ULL);
    PkswRxpfPageRecord record = NULL;
    KswRxpfEmulationContext emulation;
    KswRxpfTrapFrame originalFrame;
    ULONG frameBytes = FIELD_OFFSET(KswRxpfTrapFrame, hardwareRsp);
    ULONG availableBytes = 0UL;
    ULONGLONG stackLow = 0ULL;
    ULONGLONG stackHigh = 0ULL;
    ULONGLONG entryRsp = 0ULL;
    PHYSICAL_ADDRESS physicalAddress;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    ULONGLONG action = KSW_RXPF_DISPATCH_CHAIN;
    BOOLEAN enteredReadSide = FALSE;
    BOOLEAN enteredDepth = FALSE;
    BOOLEAN recordReferenced = FALSE;

    /*
     * The accepted interrupt gate keeps IPIs masked until this C entry. Join
     * the global read side before touching manager or page-table storage.
     */
    kswRxpfDiagnosticsEnterHandler();
    enteredReadSide = TRUE;

    /* Always return a chain target, including recursion and shutdown paths. */
    if (processorIndex < gKswRxpfPageFault.cpuCapacity) {
        cpu = &gKswRxpfPageFault.cpus[processorIndex];
        if (cpu->originalPageFaultHandler != NULL) {
            originalHandler = cpu->originalPageFaultHandler;
        }
    }
    *transferTargetOut = originalHandler;
    *resumeRspOut = 0ULL;
    RtlZeroMemory(resumeFrameOut, sizeof(*resumeFrameOut));
    kswRxpfDiagnosticsCountTotalFault();
    if (frame == NULL || originalHandler == NULL || cpu == NULL ||
        InterlockedCompareExchange(&cpu->active, 1, 1) == 0) {
        status = STATUS_DEVICE_NOT_READY;
        goto Exit;
    }

    /* Per-CPU depth catches faults anywhere in the custom dispatch chain. */
    if (InterlockedIncrement(&cpu->handlerDepth) != 1) {
        kswRxpfDiagnosticsCountRecursiveFault();
        InterlockedDecrement(&cpu->handlerDepth);
        goto Exit;
    }
    enteredDepth = TRUE;

    /* Reject user, write, not-present, reserved-bit, and non-fetch faults. */
    if (!kswRxpfExecuteFaultClass(frame, cr2) ||
        KeGetCurrentIrql() > APC_LEVEL) {
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }
    record = kswRxpfPageTableLookupFault(
        gKswRxpfPageFault.pageTable,
        pageBase);
    if (record == NULL ||
        frame->rip < (ULONGLONG)record->pageBase ||
        frame->rip >= (ULONGLONG)record->pageBase + PAGE_SIZE) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    InterlockedIncrement(&record->referenceCount);
    recordReferenced = TRUE;
    KeMemoryBarrier();

    /* Snapshot state before any managed-failure branch needs diagnostics. */
    RtlZeroMemory(&originalFrame, sizeof(originalFrame));
    RtlCopyMemory(&originalFrame, frame, frameBytes);
    RtlZeroMemory(resumeFrameOut, sizeof(*resumeFrameOut));
    RtlCopyMemory(resumeFrameOut, &originalFrame, frameBytes);
    RtlZeroMemory(&emulation, sizeof(emulation));

    /* Revalidate the locked physical page identity before reading its alias. */
    physicalAddress = MmGetPhysicalAddress(
        (PVOID)(ULONG_PTR)record->pageBase);
    if (((ULONGLONG)physicalAddress.QuadPart >> PAGE_SHIFT) != record->pfn ||
        record->writableAlias == 0ULL) {
        status = STATUS_REVISION_MISMATCH;
        record->lastFailureReason =
            KSWORD_ARK_RXPF_EMULATION_INVALID_ADDRESS;
        goto ManagedFailure;
    }
    kswRxpfDiagnosticsCountManagedFault();
    InterlockedIncrement64(&record->faultCount);

    emulation.frame = resumeFrameOut;
    IoGetStackLimits(
        (PULONG_PTR)&stackLow,
        (PULONG_PTR)&stackHigh);
    emulation.stackLow = stackLow;
    emulation.stackHigh = stackHigh;
    entryRsp = (ULONGLONG)(ULONG_PTR)&frame->hardwareRsp;
    emulation.logicalRsp = entryRsp;
    availableBytes = (ULONG)min(
        (ULONGLONG)KSW_RXPF_X64_MAX_INSTRUCTION_BYTES,
        ((ULONGLONG)record->pageBase + PAGE_SIZE) - frame->rip);
    emulation.availableBytes = availableBytes;

    /* Read only from the locked writable alias and never cross the page. */
    __try {
        RtlCopyMemory(
            emulation.instruction,
            (const UCHAR*)(ULONG_PTR)record->writableAlias +
                (frame->rip - (ULONGLONG)record->pageBase),
            availableBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        RtlCopyMemory(frame, &originalFrame, frameBytes);
        record->lastFailureReason =
            KSWORD_ARK_RXPF_EMULATION_INVALID_ADDRESS;
        goto ManagedFailure;
    }

    /* Emulate one complete whitelisted instruction or preserve the fault. */
    status = kswRxpfX64EmulateOne(&emulation);
    if (!NT_SUCCESS(status) ||
        entryRsp < 8ULL ||
        emulation.logicalRsp < entryRsp - 8ULL ||
        !kswRxpfResumeStackValid(
            emulation.logicalRsp,
            stackLow,
            stackHigh)) {
        if (NT_SUCCESS(status)) {
            status = STATUS_STACK_OVERFLOW;
            emulation.emulationResult =
                KSWORD_ARK_RXPF_EMULATION_STACK_RANGE;
        }
        RtlCopyMemory(frame, &originalFrame, frameBytes);
        record->lastFailureReason = emulation.emulationResult;
        goto ManagedFailure;
    }

    /* Publish the modified context and same-CPL resume RSP to the assembly stub. */
    *resumeRspOut = emulation.logicalRsp;
    InterlockedIncrement64(&record->emulatedCount);
    record->lastStatus = STATUS_SUCCESS;
    record->lastFailureReason = KSWORD_ARK_RXPF_EMULATION_SUCCESS;
    kswRxpfDiagnosticsCountEmulatedInstruction();
    kswRxpfDiagnosticsRecord(
        processorIndex,
        cr2,
        originalFrame.rip,
        originalFrame.errorCode,
        (ULONGLONG)record->recordId,
        emulation.decodedInstruction,
        KSWORD_ARK_RXPF_EMULATION_SUCCESS,
        resumeFrameOut->rip,
        STATUS_SUCCESS);
    action = KSW_RXPF_DISPATCH_HANDLED;
    goto Exit;

ManagedFailure:
    /* Unsupported instructions remain visible to the original Windows #PF. */
    record->lastStatus = status;
    InterlockedIncrement64(&record->unsupportedCount);
    kswRxpfDiagnosticsCountUnsupportedInstruction();
    kswRxpfDiagnosticsRecord(
        processorIndex,
        cr2,
        originalFrame.rip,
        originalFrame.errorCode,
        (ULONGLONG)record->recordId,
        emulation.decodedInstruction,
        record->lastFailureReason,
        originalFrame.rip,
        status);

Exit:
    if (action == KSW_RXPF_DISPATCH_CHAIN) {
        kswRxpfDiagnosticsCountChainedFault();
    }
    if (recordReferenced) {
        InterlockedDecrement(&record->referenceCount);
    }
    if (enteredDepth) {
        InterlockedDecrement(&cpu->handlerDepth);
    }
    if (enteredReadSide) {
        kswRxpfDiagnosticsLeaveHandler();
    }
    return action;
}

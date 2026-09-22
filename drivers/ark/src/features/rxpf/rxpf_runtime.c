/*++

Module Name:

    rxpf_runtime.c

Abstract:

    Control-path coordinator for the experimental RX/NX page-fault emulator.

Environment:

    Kernel mode, PASSIVE_LEVEL control path.  The vector-14 path is implemented
    by page_fault_manager.c and never enters this module.

--*/

#include "rxpf_runtime.h"

#include "image_protection_manager.h"
#include "page_fault_manager.h"
#include "page_state_table.h"
#include "rxpf_diagnostics.h"
#include "rxpf_self_test.h"
#include "x64_instruction_emulator.h"

typedef struct KswRxpfRuntimeState
{
    KswRxpfPageTable pageTable;
    PDRIVER_OBJECT driverObject;
    ULONG maximumProcessorCount;
    volatile LONG initialized;
    volatile LONG accepting;
    volatile LONG generation;
    volatile LONG allocatedSelfTestPassed;
    volatile LONG lastStatus;
} KswRxpfRuntimeState;

static KswRxpfRuntimeState gKswRxpfRuntime;

static const UCHAR kGKswRxpfSelfTestCode[] = {
    0x48U, 0xC7U, 0xC0U, 0x78U, 0x56U, 0x34U, 0x12U,
    0x48U, 0x83U, 0xC0U, 0x01U,
    0xC3U
};

static NTSTATUS
kswRxpfValidateHeader(
    _In_ const KSWORD_ARK_RXPF_REQUEST_HEADER* header,
    _In_ ULONG expectedSize,
    _In_ ULONG allowedFlags
    )
{
    /* Every request is exact-version, exact-size and explicitly confirmed. */
    if (header == NULL ||
        header->version != KSWORD_ARK_RXPF_PROTOCOL_VERSION ||
        header->size != expectedSize ||
        header->confirmationToken != KSWORD_ARK_RXPF_CONFIRMATION_TOKEN ||
        (header->flags & KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED) == 0UL ||
        (header->flags & ~allowedFlags) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

static VOID
kswRxpfFillPageResponse(
    _In_opt_ const KswRxpfPageRecord* record,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    /* The caller holds the writer lock while copying mutable record fields. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    if (record == NULL) {
        return;
    }
    response->state = (ULONG)record->state;
    response->targetKind = record->targetKind;
    response->flags = record->flags;
    response->generation = record->generation;
    response->referenceCount = (ULONG)record->referenceCount;
    response->emulationEnabled = (ULONG)record->emulationEnabled;
    response->recordId = (ULONGLONG)record->recordId;
    response->pageBase = (ULONGLONG)record->pageBase;
    response->writableAlias = record->writableAlias;
    response->pfn = record->pfn;
    response->ownerImageBase = record->ownerImageBase;
    response->faultCount = (ULONGLONG)record->faultCount;
    response->emulatedCount = (ULONGLONG)record->emulatedCount;
    response->unsupportedCount = (ULONGLONG)record->unsupportedCount;
    response->lastStatus = record->lastStatus;
    response->lastFailureReason = record->lastFailureReason;
    response->originalProtection = record->originalProtection;
    response->currentProtection = record->currentProtection;
    response->writableAliasProtection =
        record->writableAliasProtection;
    response->lastWriteOffset = record->lastWriteOffset;
    response->lastWriteLength = record->lastWriteLength;
    RtlCopyMemory(
        response->lastWriteBytes,
        record->lastWriteBytes,
        sizeof(response->lastWriteBytes));
}

static BOOLEAN
kswRxpfRuntimeReady(
    VOID
    )
{
    /* Accepting is cleared before unload begins and is never re-enabled. */
    return InterlockedCompareExchange(
        &gKswRxpfRuntime.initialized,
        1,
        1) != 0 &&
        InterlockedCompareExchange(
            &gKswRxpfRuntime.accepting,
            1,
            1) != 0;
}

static VOID
kswRxpfSetLastStatus(
    _In_ NTSTATUS status
    )
{
    /* Keep runtime and exported diagnostic status consistent. */
    InterlockedExchange(&gKswRxpfRuntime.lastStatus, status);
    kswRxpfDiagnosticsSetLastStatus(status);
}

NTSTATUS
kswRxpfRuntimeInitialize(
    _In_ PDRIVER_OBJECT driverObject
    )
{
    ULONG maximumProcessorCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Initialization is idempotent for DriverEntry rollback paths. */
    if (driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &gKswRxpfRuntime.initialized,
            1,
            1) != 0) {
        return STATUS_SUCCESS;
    }
    maximumProcessorCount =
        KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (maximumProcessorCount == 0UL) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Allocate every exception-path structure before publishing the runtime. */
    RtlZeroMemory(&gKswRxpfRuntime, sizeof(gKswRxpfRuntime));
    gKswRxpfRuntime.driverObject = driverObject;
    gKswRxpfRuntime.maximumProcessorCount = maximumProcessorCount;
    kswRxpfPageTableInitialize(&gKswRxpfRuntime.pageTable);

    status = kswRxpfDiagnosticsInitialize(maximumProcessorCount);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = kswRxpfPageFaultManagerInitialize(
        &gKswRxpfRuntime.pageTable,
        maximumProcessorCount);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = kswRxpfImageProtectionInitialize(driverObject);
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }
    status = kswRxpfX64RunUnitTests();
    if (!NT_SUCCESS(status)) {
        goto Exit;
    }

    /* Unsupported nt builds still initialize, but all internal calls fail closed. */
    InterlockedExchange(&gKswRxpfRuntime.accepting, 1);
    InterlockedExchange(&gKswRxpfRuntime.initialized, 1);
    kswRxpfSetLastStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;

Exit:
    /* Reverse partially completed initialization without exposing IOCTL state. */
    kswRxpfImageProtectionUninitialize();
    kswRxpfPageFaultManagerUninitialize();
    kswRxpfDiagnosticsUninitialize();
    RtlZeroMemory(&gKswRxpfRuntime, sizeof(gKswRxpfRuntime));
    return status;
}

VOID
kswRxpfRuntimeUninitialize(
    VOID
    )
{
    ULONG index = 0UL;
    LARGE_INTEGER retryDelay;

    /* Idempotent teardown is used by both unload and DriverEntry rollback. */
    if (InterlockedCompareExchange(
            &gKswRxpfRuntime.initialized,
            1,
            1) == 0) {
        return;
    }

    /* Stop new control requests, then unpublish all records from vector 14. */
    InterlockedExchange(&gKswRxpfRuntime.accepting, 0);
    kswRxpfPageTableStopAccepting(&gKswRxpfRuntime.pageTable);
    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    for (index = 0UL; index < KSW_RXPF_PAGE_TABLE_CAPACITY; ++index) {
        PkswRxpfPageRecord record =
            &gKswRxpfRuntime.pageTable.slots[index];

        if ((ULONGLONG)record->pageBase > KSW_RXPF_PAGE_TOMBSTONE &&
            record->state != KSWORD_ARK_RXPF_PAGE_STATE_TERMINATING) {
            kswRxpfPageTableBeginRemoveLocked(
                &gKswRxpfRuntime.pageTable,
                record);
        }
    }
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);

    /* Restore every processor's original IDTR before releasing any code/data. */
    retryDelay.QuadPart = -100000LL;
    while (!NT_SUCCESS(kswRxpfPageFaultRestore())) {
        /* Prefer a blocked unload over freeing code still reachable by vector 14. */
        (void)KeDelayExecutionThread(KernelMode, FALSE, &retryDelay);
    }
    while (!NT_SUCCESS(kswRxpfDiagnosticsWaitForHandlers(5000UL))) {
        /* Unload cannot safely continue while a processor still reads a record. */
    }

    /* With vector 14 restored and all read-side users gone, resources are private. */
    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    for (index = 0UL; index < KSW_RXPF_PAGE_TABLE_CAPACITY; ++index) {
        PkswRxpfPageRecord record =
            &gKswRxpfRuntime.pageTable.slots[index];

        if ((ULONGLONG)record->pageBase > KSW_RXPF_PAGE_TOMBSTONE) {
            kswRxpfImageProtectionReleaseRecord(record);
            kswRxpfPageTableClearRemovedLocked(
                &gKswRxpfRuntime.pageTable,
                record);
        }
    }
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);

    kswRxpfPageFaultManagerUninitialize();
    kswRxpfDiagnosticsUninitialize();
    kswRxpfImageProtectionUninitialize();
    InterlockedExchange(&gKswRxpfRuntime.initialized, 0);
    KeMemoryBarrier();
    RtlZeroMemory(&gKswRxpfRuntime, sizeof(gKswRxpfRuntime));
}

NTSTATUS
kswRxpfRuntimeQuerySupport(
    _Out_ KSWORD_ARK_RXPF_QUERY_SUPPORT_RESPONSE* response
    )
{
    /* Support discovery itself never attempts an internal function call. */
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    kswRxpfImageProtectionQuerySupport(response);
    response->processorCount =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (kswRxpfPageFaultIsInstalled()) {
        response->supportFlags |= KSWORD_ARK_RXPF_SUPPORT_IDT_INSTALLED;
    }
    if (InterlockedCompareExchange(
            &gKswRxpfRuntime.allocatedSelfTestPassed,
            1,
            1) != 0) {
        response->supportFlags |=
            KSWORD_ARK_RXPF_SUPPORT_ALLOCATED_TEST_PASSED;
    }
    if (InterlockedCompareExchange(
            &gKswRxpfRuntime.initialized,
            1,
            1) == 0) {
        response->supportFlags &= ~KSWORD_ARK_RXPF_SUPPORT_INITIALIZED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfRuntimeRegisterPage(
    _In_ const KSWORD_ARK_RXPF_REGISTER_PAGE_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    KswRxpfPageRecord source;
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Registration allocates/locks resources only on the serialized control path. */
    if (request == NULL || response == NULL || request->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED |
            KSWORD_ARK_RXPF_FLAG_CAPTURE_BACKUP);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }
    if (request->targetKind != KSWORD_ARK_RXPF_TARGET_ALLOCATED_TEST &&
        InterlockedCompareExchange(
            &gKswRxpfRuntime.allocatedSelfTestPassed,
            1,
            1) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    status = kswRxpfImageProtectionCreateRecord(
        request->targetKind,
        request->targetAddress,
        request->header.flags & KSWORD_ARK_RXPF_FLAG_CAPTURE_BACKUP,
        &source);
    if (!NT_SUCCESS(status)) {
        kswRxpfSetLastStatus(status);
        return status;
    }

    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    status = kswRxpfPageTableInsertLocked(
        &gKswRxpfRuntime.pageTable,
        &source,
        &record);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&gKswRxpfRuntime.generation);
        kswRxpfFillPageResponse(record, response);
    }
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    if (!NT_SUCCESS(status)) {
        kswRxpfImageProtectionReleaseRecord(&source);
    }
    kswRxpfSetLastStatus(status);
    return status;
}

NTSTATUS
kswRxpfRuntimeChangePage(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Permission transition is single-shot and protected by the writer lock. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }
    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    record = kswRxpfPageTableFindByIdLocked(
        &gKswRxpfRuntime.pageTable,
        request->recordId);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
    } else {
        status = kswRxpfImageProtectionChangeToRwNx(record);
        record->lastStatus = status;
        if (NT_SUCCESS(status)) {
            InterlockedIncrement(&gKswRxpfRuntime.generation);
        }
    }
    kswRxpfFillPageResponse(record, response);
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    kswRxpfSetLastStatus(status);
    return status;
}

NTSTATUS
kswRxpfRuntimeQueryPage(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Query uses the same lock as writers to return a coherent record snapshot. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }
    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    record = kswRxpfPageTableFindByIdLocked(
        &gKswRxpfRuntime.pageTable,
        request->recordId);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
    }
    kswRxpfFillPageResponse(record, response);
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    return status;
}

NTSTATUS
kswRxpfRuntimeWritePage(
    _In_ const KSWORD_ARK_RXPF_WRITE_PAGE_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Instruction bytes cannot change while any CPU may emulate the page. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }
    if (request->length == 0UL ||
        request->length > KSWORD_ARK_RXPF_MAX_WRITE_BYTES ||
        (ULONGLONG)request->offset + request->length > PAGE_SIZE ||
        (ULONGLONG)request->offset + request->length < request->offset) {
        return STATUS_INVALID_PARAMETER;
    }

    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    record = kswRxpfPageTableFindByIdLocked(
        &gKswRxpfRuntime.pageTable,
        request->recordId);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
    } else if (InterlockedCompareExchange(
            &record->emulationEnabled,
            0,
            0) != 0) {
        status = STATUS_DEVICE_BUSY;
    } else {
        status = kswRxpfImageProtectionWrite(
            record,
            request->offset,
            request->bytes,
            request->length);
        if (NT_SUCCESS(status)) {
            InterlockedIncrement(&gKswRxpfRuntime.generation);
        }
    }
    if (record != NULL) {
        record->lastStatus = status;
    }
    kswRxpfFillPageResponse(record, response);
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    kswRxpfSetLastStatus(status);
    return status;
}

NTSTATUS
kswRxpfRuntimeSetEmulation(
    _In_ const KSWORD_ARK_RXPF_SET_EMULATION_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN restoreIdt = FALSE;

    /* Enabling is published only after every online CPU has installed its IDT. */
    if (request == NULL || response == NULL || request->enable > 1UL ||
        request->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }

    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    record = kswRxpfPageTableFindByIdLocked(
        &gKswRxpfRuntime.pageTable,
        request->recordId);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }
    if (record->state != KSWORD_ARK_RXPF_PAGE_STATE_RW_NX) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Exit;
    }
    if (request->enable != 0UL) {
        status = kswRxpfPageFaultInstall();
        if (NT_SUCCESS(status) &&
            InterlockedExchange(&record->emulationEnabled, 1) == 0) {
            InterlockedIncrement(
                &gKswRxpfRuntime.pageTable.enabledCount);
            InterlockedIncrement(&gKswRxpfRuntime.generation);
        }
    } else if (InterlockedExchange(&record->emulationEnabled, 0) != 0) {
        LONG enabledCount = InterlockedDecrement(
            &gKswRxpfRuntime.pageTable.enabledCount);

        KeMemoryBarrier();
        InterlockedIncrement(&gKswRxpfRuntime.generation);
        restoreIdt = enabledCount == 0;
        status = kswRxpfDiagnosticsWaitForHandlers(5000UL);
        record->lastStatus = status;
    }

Exit:
    if (record != NULL) {
        record->lastStatus = status;
    }
    kswRxpfFillPageResponse(record, response);
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    if (restoreIdt) {
        NTSTATUS restoreStatus = kswRxpfPageFaultRestore();

        if (NT_SUCCESS(status) && !NT_SUCCESS(restoreStatus)) {
            status = restoreStatus;
        }
        response->lastStatus = status;
    }
    kswRxpfSetLastStatus(status);
    return status;
}

NTSTATUS
kswRxpfRuntimeQueryStats(
    _Out_ KSWORD_ARK_RXPF_STATS_RESPONSE* response
    )
{
    /* Aggregate counters are atomic and require no state-table lock. */
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    kswRxpfDiagnosticsQueryStats(
        (ULONG)InterlockedCompareExchange(
            &gKswRxpfRuntime.generation,
            0,
            0),
        (ULONG)InterlockedCompareExchange(
            &gKswRxpfRuntime.pageTable.registeredCount,
            0,
            0),
        (ULONG)InterlockedCompareExchange(
            &gKswRxpfRuntime.pageTable.enabledCount,
            0,
            0),
        kswRxpfPageFaultIsInstalled() ? 1UL : 0UL,
        kswRxpfPageFaultProcessorCount(),
        response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfRuntimeDrainEvents(
    _In_ const KSWORD_ARK_RXPF_DRAIN_EVENTS_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_DRAIN_EVENTS_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Ring export occurs only on the ordinary IOCTL path. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) ||
        request->maxRows > KSWORD_ARK_RXPF_MAX_EVENT_ROWS) {
        return STATUS_INVALID_PARAMETER;
    }
    kswRxpfDiagnosticsDrain(request, response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfRuntimeUnregisterPage(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_PAGE_RESPONSE* response
    )
{
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN restoreIdt = FALSE;

    /* Mark terminating first; only a completed read-side grace period permits free. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        return NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
    }

    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    record = kswRxpfPageTableFindByIdLocked(
        &gKswRxpfRuntime.pageTable,
        request->recordId);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
    } else {
        kswRxpfFillPageResponse(record, response);
        kswRxpfPageTableBeginRemoveLocked(
            &gKswRxpfRuntime.pageTable,
            record);
        restoreIdt = InterlockedCompareExchange(
            &gKswRxpfRuntime.pageTable.enabledCount,
            0,
            0) == 0;
    }
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (restoreIdt) {
        status = kswRxpfPageFaultRestore();
    }
    if (NT_SUCCESS(status)) {
        status = kswRxpfDiagnosticsWaitForHandlers(5000UL);
    }
    if (!NT_SUCCESS(status)) {
        kswRxpfSetLastStatus(status);
        return status;
    }

    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    kswRxpfImageProtectionReleaseRecord(record);
    kswRxpfPageTableClearRemovedLocked(
        &gKswRxpfRuntime.pageTable,
        record);
    InterlockedIncrement(&gKswRxpfRuntime.generation);
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    kswRxpfSetLastStatus(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

NTSTATUS
kswRxpfRuntimeRunSelfTest(
    _In_ const KSWORD_ARK_RXPF_RECORD_REQUEST* request,
    _Out_ KSWORD_ARK_RXPF_SELF_TEST_RESPONSE* response
    )
{
    PkswRxpfPageRecord record = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN enabledHere = FALSE;
    BOOLEAN restoreIdt = FALSE;
    ULONGLONG faultsBefore = 0ULL;
    ULONGLONG faultsAfter = 0ULL;
    ULONGLONG returnedValue = 0ULL;
    ULONG workerCount = 0UL;

    /* The live test is limited to either driver-owned, one-page code target. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_RXPF_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->expectedValue = KSW_RXPF_SELF_TEST_EXPECTED_VALUE;
    status = kswRxpfValidateHeader(
        &request->header,
        sizeof(*request),
        KSWORD_ARK_RXPF_FLAG_UI_CONFIRMED);
    if (!NT_SUCCESS(status) || !kswRxpfRuntimeReady()) {
        status = NT_SUCCESS(status) ? STATUS_DELETE_PENDING : status;
        goto Complete;
    }

    kswRxpfPageTableAcquireExclusive(&gKswRxpfRuntime.pageTable);
    record = kswRxpfPageTableFindByIdLocked(
        &gKswRxpfRuntime.pageTable,
        request->recordId);
    if (record == NULL) {
        status = STATUS_NOT_FOUND;
        goto Unlock;
    }
    response->recordId = (ULONGLONG)record->recordId;
    if ((record->targetKind != KSWORD_ARK_RXPF_TARGET_ALLOCATED_TEST &&
         record->targetKind != KSWORD_ARK_RXPF_TARGET_SELF_IMAGE_TEST) ||
        record->state != KSWORD_ARK_RXPF_PAGE_STATE_RW_NX ||
        record->writableAlias == 0ULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Unlock;
    }
    if (InterlockedCompareExchange(
            &record->emulationEnabled,
            0,
            0) != 0) {
        status = STATUS_DEVICE_BUSY;
        goto Unlock;
    }

    status = kswRxpfImageProtectionWrite(
        record,
        0UL,
        kGKswRxpfSelfTestCode,
        sizeof(kGKswRxpfSelfTestCode));
    if (!NT_SUCCESS(status)) {
        goto Unlock;
    }
    status = kswRxpfPageFaultInstall();
    if (!NT_SUCCESS(status)) {
        goto Unlock;
    }
    InterlockedExchange(&record->emulationEnabled, 1);
    InterlockedIncrement(&gKswRxpfRuntime.pageTable.enabledCount);
    enabledHere = TRUE;
    KeMemoryBarrier();
    faultsBefore = (ULONGLONG)InterlockedCompareExchange64(
        &record->faultCount,
        0,
        0);

    /* Exercise the lock-free read side once on every active processor. */
    status = kswRxpfRunConcurrentExecutionTest(
        (PVOID)(ULONG_PTR)record->pageBase,
        KSW_RXPF_SELF_TEST_EXPECTED_VALUE,
        &returnedValue,
        &workerCount);
    faultsAfter = (ULONGLONG)InterlockedCompareExchange64(
        &record->faultCount,
        0,
        0);
    if (enabledHere) {
        InterlockedExchange(&record->emulationEnabled, 0);
        restoreIdt = InterlockedDecrement(
            &gKswRxpfRuntime.pageTable.enabledCount) == 0;
        KeMemoryBarrier();
    }
    if (NT_SUCCESS(status) &&
        (returnedValue != KSW_RXPF_SELF_TEST_EXPECTED_VALUE ||
         workerCount == 0UL ||
         faultsAfter - faultsBefore !=
            (ULONGLONG)workerCount * 3ULL)) {
        status = STATUS_DATA_ERROR;
    }
    record->lastStatus = status;
    response->returnedValue = returnedValue;
    response->faultsObserved = faultsAfter - faultsBefore;
    response->instructionCount = workerCount * 3UL;
    response->result = NT_SUCCESS(status)
        ? KSWORD_ARK_RXPF_EMULATION_SUCCESS
        : record->lastFailureReason;

Unlock:
    kswRxpfPageTableReleaseExclusive(&gKswRxpfRuntime.pageTable);
    if (restoreIdt) {
        NTSTATUS restoreStatus = kswRxpfPageFaultRestore();

        if (NT_SUCCESS(status) && !NT_SUCCESS(restoreStatus)) {
            status = restoreStatus;
        }
    }

    if (NT_SUCCESS(status)) {
        InterlockedExchange(&gKswRxpfRuntime.allocatedSelfTestPassed, 1);
    }
Complete:
    response->lastStatus = status;
    kswRxpfSetLastStatus(status);
    return status;
}

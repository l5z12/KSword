/*++

Module Name:

    debug_output_capture.c

Abstract:

    Captures kernel debug-print callbacks into a fixed nonpaged ring buffer.

Environment:

    Kernel-mode Driver Framework.  The callback may run at IRQL <= DIRQL.

--*/

#include "ark/ark_driver.h"

// DbgSetDebugPrintCallback allows only one static callback, so save the current control device context.
static PdeviceContext volatile gKswordArkDebugOutputContext = NULL;

// Static zero-initialization means the push lock is not held; all start/stop transactions and unload deregistrations are serialized by this global lock.
static EX_PUSH_LOCK gKswordArkDebugOutputControlLock;

// Atomically read the current callback context to avoid data races between normal pointer reads and the start/stop paths.
static PdeviceContext kswordArkDebugOutputReadContext(VOID)
{
    return (PdeviceContext)InterlockedCompareExchangePointer(
        (PVOID volatile*)&gKswordArkDebugOutputContext,
        NULL,
        NULL);
}

// The callback path cannot allocate memory, wait on locks, or write debug logs, as this would cause recursion or high IRQL faults.
static VOID kswordArkDebugPrintCallback(
    _In_ PSTRING output,
    _In_ ULONG componentId,
    _In_ ULONG level)
{
    PdeviceContext context;
    KswordArkDebugOutputSlot* slot;
    ULONGLONG latestSequence;
    ULONGLONG sequence;
    ULONG slotIndex;
    USHORT copyLength;

    // Read the global context first; when stopping capture, clear the enabled flag first, then unregister the callback.
    context = kswordArkDebugOutputReadContext();
    if (context == NULL ||
        InterlockedCompareExchange(&context->debugOutputCaptureEnabled, 0, 0) == 0 ||
        output == NULL ||
        output->Buffer == NULL) {
        return;
    }

    // Callbacks may execute at DIRQL; only try-lock is performed. In case of concurrent writes, drops are preferred over waiting.
    if (InterlockedCompareExchange(&context->debugOutputWriterLock, 1, 0) != 0) {
        InterlockedIncrement64(&context->debugOutputDroppedCount);
        return;
    }

    // Each record uses a monotonic sequence number to locate the ring buffer slot; sequence number zero is reserved for "no records yet".
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &context->debugOutputLatestSequence,
        0,
        0);
    sequence = latestSequence + 1;
    slotIndex = (ULONG)((sequence - 1) % KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY);
    slot = &context->debugOutputSlots[slotIndex];

    // A negative commit sequence indicates the slot is being written to; the reader accepts only consistent positive sequences from two consecutive reads.
    InterlockedExchange64(&slot->commitSequence, -((LONG64)sequence));
    RtlZeroMemory(&slot->record, sizeof(slot->record));
    slot->record.sequence = sequence;
    slot->record.interruptTime100ns = KeQueryInterruptTime();
    slot->record.componentId = componentId;
    slot->record.level = level;

    // DbgPrintEx: Each output line is limited to 512 bytes; a trailing NUL is reserved for safe user-mode parsing.
    copyLength = output->Length;
    if (copyLength >= KSWORD_ARK_DEBUG_OUTPUT_TEXT_BYTES) {
        copyLength = KSWORD_ARK_DEBUG_OUTPUT_TEXT_BYTES - 1;
        slot->record.flags |= KSWORD_ARK_DEBUG_OUTPUT_RECORD_FLAG_TEXT_TRUNCATED;
    }
    if (copyLength != 0) {
        RtlCopyMemory(slot->record.text, output->Buffer, copyLength);
    }
    slot->record.text[copyLength] = '\0';
    slot->record.textLengthBytes = copyLength;

    // Publish the complete record first, then publish the commit sequence and latest sequence to ensure the reader never sees a partial record.
    KeMemoryBarrier();
    InterlockedExchange64(&slot->commitSequence, (LONG64)sequence);
    InterlockedExchange64(&context->debugOutputLatestSequence, (LONG64)sequence);
    InterlockedExchange(&context->debugOutputWriterLock, 0);
}

// Reset the ring buffer only if the callback is unregistered or has not yet been registered.
static VOID kswordArkDebugOutputReset(_Inout_ PdeviceContext context)
{
    InterlockedExchange(&context->debugOutputWriterLock, 0);
    InterlockedExchange64(&context->debugOutputLatestSequence, 0);
    InterlockedExchange64(&context->debugOutputDroppedCount, 0);
    RtlZeroMemory(context->debugOutputSlots, sizeof(context->debugOutputSlots));
}

// Convert the current registered, captured, and discarded states into a shared protocol response.
static VOID kswordArkDebugOutputFillControlResponse(
    _In_ PdeviceContext context,
    _Out_ KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE* response)
{
    PdeviceContext activeContext;
    ULONGLONG latestSequence;

    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    activeContext = kswordArkDebugOutputReadContext();
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &context->debugOutputLatestSequence,
        0,
        0);

    if (activeContext == context) {
        response->runtimeFlags |= KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_REGISTERED;
    }
    if (InterlockedCompareExchange(&context->debugOutputCaptureEnabled, 0, 0) != 0) {
        response->runtimeFlags |= KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_CAPTURING;
    }
    response->droppedCount = (ULONGLONG)InterlockedCompareExchange64(
        &context->debugOutputDroppedCount,
        0,
        0);
    if (response->droppedCount != 0) {
        response->runtimeFlags |= KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_DROPPED;
    }
    response->latestSequence = latestSequence;
    response->ringCapacity = KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY;
    response->queuedCount = (ULONG)min(
        latestSequence,
        (ULONGLONG)KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY);
    response->registrationStatus = context->debugOutputRegistrationStatus;
    response->lastStatus = context->debugOutputLastStatus;
}

// initialize the control device context; do not register callbacks here, only register them when the user explicitly starts capturing.
NTSTATUS kswordArkDebugOutputInitialize(_In_ WDFDEVICE device)
{
    PdeviceContext context;

    if (device == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    context = DeviceGetContext(device);
    context->debugOutputCaptureEnabled = 0;
    context->debugOutputWriterLock = 0;
    context->debugOutputLatestSequence = 0;
    context->debugOutputDroppedCount = 0;
    context->debugOutputRegistrationStatus = STATUS_NOT_SUPPORTED;
    context->debugOutputLastStatus = STATUS_SUCCESS;
    RtlZeroMemory(context->debugOutputSlots, sizeof(context->debugOutputSlots));
    return STATUS_SUCCESS;
}

// Executes start, stop, or query operations and always returns diagnostic runtime status.
NTSTATUS kswordArkDebugOutputControl(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE* response)
{
    PdeviceContext context;
    PdeviceContext activeContext;
    NTSTATUS status;

    if (device == NULL || request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->version != KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION ||
        request->size < sizeof(*request)) {
        /*
         * The METHOD_BUFFERED adapter reports the fixed response size even for
         * control failures, so initialize every returned field rather than
         * exposing stale request bytes to the user-mode diagnostic parser.
         */
        RtlZeroMemory(response, sizeof(*response));
        response->version = KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->registrationStatus = STATUS_REVISION_MISMATCH;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_REVISION_MISMATCH;
    }

    context = DeviceGetContext(device);
    status = STATUS_SUCCESS;

    /*
     * The default WDF queue uses Parallel scheduling. START/STOP involves more than a single atomic flag change; it includes
     * ring reset, global context publication, and system callback registration or deregistration. These must be executed as an
     * indivisible transaction. The callback hot path does not acquire this lock, so DIRQL capture behavior remains unchanged.
     */
    kswordArkAcquirePushLockExclusive(&gKswordArkDebugOutputControlLock);
    switch (request->action) {
    case KSWORD_ARK_DEBUG_OUTPUT_ACTION_START:
        activeContext = kswordArkDebugOutputReadContext();
        if (activeContext == context &&
            InterlockedCompareExchange(&context->debugOutputCaptureEnabled, 0, 0) != 0) {
            status = STATUS_SUCCESS;
            break;
        }
        if (activeContext != NULL) {
            status = STATUS_DEVICE_BUSY;
            break;
        }

        // Clear previous session data before releasing the context to ensure the new session starts from sequence number one.
        kswordArkDebugOutputReset(context);
        InterlockedExchange(&context->debugOutputCaptureEnabled, 1);
        activeContext = (PdeviceContext)InterlockedCompareExchangePointer(
            (PVOID volatile*)&gKswordArkDebugOutputContext,
            context,
            NULL);
        if (activeContext != NULL) {
            InterlockedExchange(&context->debugOutputCaptureEnabled, 0);
            status = STATUS_DEVICE_BUSY;
            break;
        }

        // Capture messages entering the kernel debug pipeline using WDK-supported callback interfaces without modifying global filters.
        status = DbgSetDebugPrintCallback(kswordArkDebugPrintCallback, TRUE);
        context->debugOutputRegistrationStatus = status;
        if (!NT_SUCCESS(status)) {
            InterlockedExchange(&context->debugOutputCaptureEnabled, 0);
            InterlockedCompareExchangePointer(
                (PVOID volatile*)&gKswordArkDebugOutputContext,
                NULL,
                context);
        }
        break;

    case KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP:
        activeContext = kswordArkDebugOutputReadContext();
        if (activeContext == context) {
            // First disable callback writes, then unregister the callback from the kernel to prevent new records from appearing in the stop window.
            InterlockedExchange(&context->debugOutputCaptureEnabled, 0);
            status = DbgSetDebugPrintCallback(kswordArkDebugPrintCallback, FALSE);
            context->debugOutputRegistrationStatus = status;
            if (NT_SUCCESS(status)) {
                InterlockedCompareExchangePointer(
                    (PVOID volatile*)&gKswordArkDebugOutputContext,
                    NULL,
                    context);
            }
        } else {
            InterlockedExchange(&context->debugOutputCaptureEnabled, 0);
            status = STATUS_SUCCESS;
        }
        break;

    case KSWORD_ARK_DEBUG_OUTPUT_ACTION_QUERY:
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    context->debugOutputLastStatus = status;
    kswordArkDebugOutputFillControlResponse(context, response);
    kswordArkReleasePushLockExclusive(&gKswordArkDebugOutputControlLock);
    return status;
}

// Read stable snapshots incrementally by sequence number; ring buffer overwrites and concurrent modifications are explicitly reported via flags and counters.
NTSTATUS kswordArkDebugOutputDrain(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
{
    PdeviceContext context;
    KswordArkDebugOutputSlot* slot;
    const size_t kResponseHeaderSize = FIELD_OFFSET(KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE, records);
    ULONGLONG latestSequence;
    ULONGLONG earliestSequence;
    ULONGLONG afterSequence;
    ULONGLONG nextSequence;
    ULONGLONG sequence;
    ULONG outputCapacity;
    ULONG requestedCount;
    ULONG recordCount;
    LONG64 commitBefore;
    LONG64 commitAfter;

    if (device == NULL || request == NULL || response == NULL || bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    if (request->version != KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION ||
        request->size < sizeof(*request)) {
        return STATUS_REVISION_MISMATCH;
    }
    if (outputBufferLength < kResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    context = DeviceGetContext(device);
    outputCapacity = (ULONG)((outputBufferLength - kResponseHeaderSize) /
        sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD));
    requestedCount = request->maxRecords;
    if (requestedCount == 0) {
        requestedCount = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS;
    }
    requestedCount = min(requestedCount, KSWORD_ARK_DEBUG_OUTPUT_MAX_DRAIN_RECORDS);
    requestedCount = min(requestedCount, outputCapacity);

    RtlZeroMemory(response, kResponseHeaderSize +
        ((size_t)requestedCount * sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD)));
    response->version = KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION;
    response->size = (ULONG)kResponseHeaderSize;
    response->entrySize = sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD);
    response->ringCapacity = KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY;
    if (kswordArkDebugOutputReadContext() == context) {
        response->runtimeFlags |= KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_REGISTERED;
    }
    if (InterlockedCompareExchange(&context->debugOutputCaptureEnabled, 0, 0) != 0) {
        response->runtimeFlags |= KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_CAPTURING;
    }
    response->droppedCount = (ULONGLONG)InterlockedCompareExchange64(
        &context->debugOutputDroppedCount,
        0,
        0);
    if (response->droppedCount != 0) {
        response->runtimeFlags |= KSWORD_ARK_DEBUG_OUTPUT_RUNTIME_DROPPED;
    }

    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &context->debugOutputLatestSequence,
        0,
        0);
    response->latestSequence = latestSequence;
    earliestSequence = latestSequence > KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY
        ? latestSequence - KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY + 1
        : (latestSequence == 0 ? 0 : 1);
    response->firstAvailableSequence = earliestSequence;

    afterSequence = request->afterSequence;
    if (afterSequence > latestSequence) {
        // After driver restart or new session, the old cursor may exceed the current sequence number; treat as reading from the beginning.
        afterSequence = 0;
        response->responseFlags |= KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_OVERFLOW;
    }
    nextSequence = afterSequence;
    if (earliestSequence != 0 && afterSequence + 1 < earliestSequence) {
        response->lostBeforeFirst = earliestSequence - (afterSequence + 1);
        response->responseFlags |= KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_OVERFLOW;
        nextSequence = earliestSequence - 1;
    }

    recordCount = 0;
    sequence = nextSequence + 1;
    while (sequence != 0 && sequence <= latestSequence && recordCount < requestedCount) {
        slot = &context->debugOutputSlots[(sequence - 1) % KSWORD_ARK_DEBUG_OUTPUT_RING_CAPACITY];
        commitBefore = InterlockedCompareExchange64(&slot->commitSequence, 0, 0);
        if (commitBefore == (LONG64)sequence) {
            RtlCopyMemory(
                &response->records[recordCount],
                &slot->record,
                sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD));
            KeMemoryBarrier();
            commitAfter = InterlockedCompareExchange64(&slot->commitSequence, 0, 0);
            if (commitAfter == commitBefore &&
                response->records[recordCount].sequence == sequence) {
                recordCount++;
            } else {
                RtlZeroMemory(
                    &response->records[recordCount],
                    sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD));
                response->responseFlags |= KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_SNAPSHOT_RACE;
            }
        } else {
            response->responseFlags |= KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_SNAPSHOT_RACE;
        }
        nextSequence = sequence;
        sequence++;
    }

    response->returnedCount = recordCount;
    response->nextSequence = nextSequence;
    if (nextSequence < latestSequence) {
        response->responseFlags |= KSWORD_ARK_DEBUG_OUTPUT_DRAIN_FLAG_MORE_AVAILABLE;
    }
    response->size = (ULONG)(kResponseHeaderSize +
        ((size_t)recordCount * sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD)));
    *bytesReturned = response->size;
    return STATUS_SUCCESS;
}

// Unregister callbacks before driver unloading; this step must be completed first to avoid the kernel retaining function pointers to unloaded code.
VOID kswordArkDebugOutputUninitialize(VOID)
{
    PdeviceContext context;
    NTSTATUS status;

    // Share the lock used by concurrent IOCTL START/STOP operations to prevent interleaving unload-time unregistration with control transactions.
    kswordArkAcquirePushLockExclusive(&gKswordArkDebugOutputControlLock);
    context = kswordArkDebugOutputReadContext();
    if (context == NULL) {
        kswordArkReleasePushLockExclusive(&gKswordArkDebugOutputControlLock);
        return;
    }

    InterlockedExchange(&context->debugOutputCaptureEnabled, 0);
    status = DbgSetDebugPrintCallback(kswordArkDebugPrintCallback, FALSE);
    context->debugOutputRegistrationStatus = status;
    context->debugOutputLastStatus = status;
    if (NT_SUCCESS(status)) {
        InterlockedCompareExchangePointer(
            (PVOID volatile*)&gKswordArkDebugOutputContext,
            NULL,
            context);
    }
    kswordArkReleasePushLockExclusive(&gKswordArkDebugOutputControlLock);
}

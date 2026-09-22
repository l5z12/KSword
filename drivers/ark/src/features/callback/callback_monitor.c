/*++

Module Name:

    callback_monitor.c

Abstract:

    Non-blocking structured telemetry ring for kernel callback events.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "../file_monitor/file_monitor_internal.h"

C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST) == 24U);
C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE) == 56U);
C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT) == 1264U);
C_ASSERT(sizeof(KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST) == 24U);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records) == 72U);

#define KSWORD_ARK_CALLBACK_MONITOR_CONTROL_SPIN_LIMIT 65536UL

static BOOLEAN
kswordArkCallbackMonitorTryAcquireWriterLockBounded(
    _Inout_ KswordArkCallbackRuntime* runtime
    )
{
    ULONG spinIndex = 0UL;

    // The control IOCTL allows waiting for short records being submitted, but must be bounded to avoid indefinite CPU occupation on a single core or due to priority inversion.
    for (spinIndex = 0UL;
         spinIndex < KSWORD_ARK_CALLBACK_MONITOR_CONTROL_SPIN_LIMIT;
         ++spinIndex) {
        if (InterlockedCompareExchange(&runtime->monitorWriterLock, 1L, 0L) == 0L) {
            return TRUE;
        }
        YieldProcessor();
    }
    return FALSE;
}

static ULONG
kswordArkCallbackMonitorRegisteredMask(
    _In_ const KswordArkCallbackRuntime* runtime
    )
{
    ULONG categoryMask = 0UL;

    // Each bit reflects whether the corresponding system callback was actually registered successfully.
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_PROCESS) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_THREAD) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_IMAGE) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_OBJECT) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
    }
    if ((runtime->registeredCallbacksMask & KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER) != 0UL) {
        categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
    }
    return categoryMask;
}

static VOID
kswordArkCallbackMonitorCopyUnicode(
    _In_opt_ PCUNICODE_STRING source,
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_ ULONG presentFlag,
    _In_ ULONG truncatedFlag,
    _Inout_ ULONG* eventFlags
    )
{
    ULONG sourceChars = 0UL;
    ULONG copyChars = 0UL;

    // The output buffer remains NUL-terminated regardless of success or failure.
    if (destination == NULL || destinationChars == 0UL || eventFlags == NULL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    // UNICODE_STRING length is in bytes, while Protocol Buffer length is in WCHARs.
    sourceChars = (ULONG)(source->Length / sizeof(WCHAR));
    copyChars = min(sourceChars, destinationChars - 1UL);
    if (copyChars != 0UL) {
        RtlCopyMemory(destination, source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    }
    destination[copyChars] = L'\0';
    *eventFlags |= presentFlag;
    if (copyChars < sourceChars) {
        *eventFlags |= truncatedFlag;
    }
}

static VOID
kswordArkCallbackMonitorFillStatus(
    _In_ KswordArkCallbackRuntime* runtime,
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* response
    )
{
    ULONG categoryMask = 0UL;
    ULONGLONG latestSequence = 0ULL;
    ULONGLONG droppedCount = 0ULL;

    // Fixed header fields allow R3 to safely determine the response version during future protocol extensions.
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->ringCapacity = KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY;
    response->registeredCategoryMask = kswordArkCallbackMonitorRegisteredMask(runtime);

    // Atomically read the hot path status to avoid querying IOCTLs for any locks that would block callbacks.
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->monitorCategoryMask, 0L, 0L);
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->monitorLatestSequence,
        0LL,
        0LL);
    droppedCount = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->monitorDroppedCount,
        0LL,
        0LL);
    response->categoryMask = categoryMask;
    response->latestSequence = latestSequence;
    response->droppedCount = droppedCount;
    response->queuedCount = (ULONG)min(
        latestSequence,
        (ULONGLONG)KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY);
    response->lastStatus = runtime->monitorLastStatus;
    response->minifilterStartStatus = runtime->miniFilterStartStatus;
    if (categoryMask != 0UL) {
        response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING;
    }
    if (droppedCount != 0ULL) {
        response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_DROPPED;
    }
    if (InterlockedCompareExchange(&runtime->stopping, 0L, 0L) != 0L) {
        response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_STOPPING;
    }
}

BOOLEAN
kswordArkCallbackMonitorIsEnabled(
    _In_ ULONG category
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    ULONG categoryMask = 0UL;

    // Unpublished or unloading runtimes are not allowed to generate new telemetry records.
    if (runtime == NULL || InterlockedCompareExchange(&runtime->stopping, 0L, 0L) != 0L) {
        return FALSE;
    }
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->monitorCategoryMask, 0L, 0L);
    return ((categoryMask & category) != 0UL) ? TRUE : FALSE;
}

VOID
kswordArkCallbackMonitorPublish(
    _In_ const KswordArkCallbackMonitorEventInput* eventInput
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KswordArkCallbackMonitorSlot* slot = NULL;
    KSWORD_ARK_CALLBACK_MONITOR_EVENT* eventRecord = NULL;
    ULONGLONG latestSequence = 0ULL;
    ULONGLONG sequence = 0ULL;
    ULONG categoryMask = 0UL;
    ULONG slotIndex = 0UL;

    // Reject closing the category in a lock-free manner first to avoid entering try-lock and string copying.
    if (runtime == NULL || eventInput == NULL) {
        return;
    }
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->monitorCategoryMask, 0L, 0L);
    if ((categoryMask & eventInput->category) == 0UL ||
        InterlockedCompareExchange(&runtime->stopping, 0L, 0L) != 0L) {
        return;
    }

    // System callbacks cannot wait; on concurrent publish contention, only increment the dropped count.
    if (InterlockedCompareExchange(&runtime->monitorWriterLock, 1L, 0L) != 0L) {
        (VOID)InterlockedIncrement64(&runtime->monitorDroppedCount);
        return;
    }

    // After acquiring the write lock, re-check the control flag to prevent submitting new records when STOP and callbacks run in parallel.
    categoryMask = (ULONG)InterlockedCompareExchange(&runtime->monitorCategoryMask, 0L, 0L);
    if ((categoryMask & eventInput->category) == 0UL ||
        InterlockedCompareExchange(&runtime->stopping, 0L, 0L) != 0L) {
        (VOID)InterlockedExchange(&runtime->monitorWriterLock, 0L);
        return;
    }

    // Monotonic sequence 0 is reserved for the empty ring; slots are stably mapped by sequence.
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->monitorLatestSequence,
        0LL,
        0LL);
    sequence = latestSequence + 1ULL;
    slotIndex = (ULONG)((sequence - 1ULL) % KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY);
    slot = &runtime->monitorSlots[slotIndex];
    eventRecord = &slot->event;

    // A negative commit sequence indicates the slot is being updated; the reader will not copy a half-written event.
    (VOID)InterlockedExchange64(&slot->commitSequence, -((LONG64)sequence));
    RtlZeroMemory(eventRecord, sizeof(*eventRecord));
    eventRecord->version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    eventRecord->size = sizeof(*eventRecord);
    eventRecord->sequence = sequence;
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&eventRecord->timeUtc100ns);
    eventRecord->category = eventInput->category;
    eventRecord->operation = eventInput->operation;
    eventRecord->flags = eventInput->flags;
    eventRecord->resultStatus = eventInput->resultStatus;
    eventRecord->originatingProcessId = eventInput->originatingProcessId;
    eventRecord->originatingThreadId = eventInput->originatingThreadId;
    eventRecord->targetProcessId = eventInput->targetProcessId;
    eventRecord->targetThreadId = eventInput->targetThreadId;
    eventRecord->parentProcessId = eventInput->parentProcessId;
    eventRecord->sessionId = eventInput->sessionId;
    eventRecord->originalAccess = eventInput->originalAccess;
    eventRecord->desiredAccess = eventInput->desiredAccess;
    eventRecord->objectType = eventInput->objectType;
    eventRecord->detailCode = eventInput->detailCode;
    eventRecord->address = eventInput->address;
    eventRecord->regionSize = eventInput->regionSize;
    if (eventRecord->originatingProcessId <= 4UL) {
        eventRecord->flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_SYSTEM_PROCESS;
    }
    kswordArkCallbackMonitorCopyUnicode(
        eventInput->processName,
        eventRecord->processName,
        RTL_NUMBER_OF(eventRecord->processName),
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_PRESENT,
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_TRUNCATED,
        &eventRecord->flags);
    kswordArkCallbackMonitorCopyUnicode(
        eventInput->path,
        eventRecord->path,
        RTL_NUMBER_OF(eventRecord->path),
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_PRESENT,
        KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PATH_TRUNCATED,
        &eventRecord->flags);

    // Publish the complete record first, then publish the slot commit sequence and the ring's latest sequence.
    KeMemoryBarrier();
    (VOID)InterlockedExchange64(&slot->commitSequence, (LONG64)sequence);
    (VOID)InterlockedExchange64(&runtime->monitorLatestSequence, (LONG64)sequence);
    (VOID)InterlockedExchange(&runtime->monitorWriterLock, 0L);
}

NTSTATUS
kswordArkCallbackMonitorControl(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST* request,
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* response
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    ULONG requestedMask = 0UL;
    LONG previousMask = 0L;
    BOOLEAN writerLockHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    // All control responses return the full status to facilitate R3 interpretation of failure reasons.
    if (runtime == NULL || request == NULL || response == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (request->version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
        request->size < sizeof(*request)) {
        runtime->monitorLastStatus = STATUS_REVISION_MISMATCH;
        kswordArkCallbackMonitorFillStatus(runtime, response);
        return STATUS_REVISION_MISMATCH;
    }

    // START accepts only the six category bits declared in the shared protocol.
    if (request->action == KSWORD_ARK_CALLBACK_MONITOR_ACTION_START) {
        requestedMask = request->categoryMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL;
        if (requestedMask == 0UL) {
            status = STATUS_INVALID_PARAMETER;
        }
        if (NT_SUCCESS(status) &&
            (requestedMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER) != 0UL) {
            status = kswordArkFileMonitorEnsureFilteringStarted();
        }
        if (NT_SUCCESS(status)) {
            // Control threads can wait for a short single-writer critical section; system callbacks only perform try-lock.
            writerLockHeld = kswordArkCallbackMonitorTryAcquireWriterLockBounded(runtime);
            if (!writerLockHeld) {
                status = STATUS_DEVICE_BUSY;
            }
            else {
                previousMask = InterlockedCompareExchange(&runtime->monitorCategoryMask, 0L, 0L);
                if (previousMask == 0L) {
                    // The entire large ring can be safely reset only when no callbacks are writable.
                    RtlZeroMemory(runtime->monitorSlots, sizeof(runtime->monitorSlots));
                    (VOID)InterlockedExchange64(&runtime->monitorLatestSequence, 0LL);
                    (VOID)InterlockedExchange64(&runtime->monitorDroppedCount, 0LL);
                }
                (VOID)InterlockedExchange(&runtime->monitorCategoryMask, (LONG)requestedMask);
            }
        }
    }
    else if (request->action == KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP) {
        // Synchronize with callbacks already in the commit critical section; no trailing records will occur after STOP returns.
        writerLockHeld = kswordArkCallbackMonitorTryAcquireWriterLockBounded(runtime);
        if (!writerLockHeld) {
            status = STATUS_DEVICE_BUSY;
        }
        else {
            (VOID)InterlockedExchange(&runtime->monitorCategoryMask, 0L);
            status = STATUS_SUCCESS;
        }
    }
    else {
        status = STATUS_INVALID_PARAMETER;
    }

    if (writerLockHeld) {
        (VOID)InterlockedExchange(&runtime->monitorWriterLock, 0L);
    }
    runtime->monitorLastStatus = status;
    kswordArkCallbackMonitorFillStatus(runtime, response);
    return status;
}

NTSTATUS
kswordArkCallbackMonitorQuery(
    _Out_ KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* response
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();

    // The query is a read-only snapshot; it does not alter category or cursor state.
    if (runtime == NULL || response == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    kswordArkCallbackMonitorFillStatus(runtime, response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackMonitorRead(
    _In_ const KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KswordArkCallbackMonitorSlot* slot = NULL;
    const size_t kResponseHeaderSize = FIELD_OFFSET(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records);
    ULONGLONG latestSequence = 0ULL;
    ULONGLONG earliestSequence = 0ULL;
    ULONGLONG afterSequence = 0ULL;
    ULONGLONG nextSequence = 0ULL;
    ULONGLONG sequence = 0ULL;
    ULONG outputCapacity = 0UL;
    ULONG requestedCount = 0UL;
    ULONG recordCount = 0UL;
    LONG64 commitBefore = 0LL;
    LONG64 commitAfter = 0LL;

    // First validate the fixed protocol header and variable-length output boundary.
    if (runtime == NULL || request == NULL || response == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (request->version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
        request->size < sizeof(*request)) {
        return STATUS_REVISION_MISMATCH;
    }
    if (outputBufferLength < kResponseHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Trim the record count for this call based on the caller's buffer, protocol defaults, and hard limits.
    outputCapacity = (ULONG)((outputBufferLength - kResponseHeaderSize) /
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
    requestedCount = request->maxRecords;
    if (requestedCount == 0UL) {
        requestedCount = KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS;
    }
    requestedCount = min(requestedCount, KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
    requestedCount = min(requestedCount, outputCapacity);

    // Zero only the actual writable length to prevent large output buffers from carrying stale kernel data.
    RtlZeroMemory(
        response,
        kResponseHeaderSize + ((SIZE_T)requestedCount * sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT)));
    response->version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    response->size = (ULONG)kResponseHeaderSize;
    response->entrySize = sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT);
    response->ringCapacity = KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY;
    response->categoryMask = (ULONG)InterlockedCompareExchange(
        &runtime->monitorCategoryMask,
        0L,
        0L);
    if (response->categoryMask != 0UL) {
        response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING;
    }
    response->droppedCount = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->monitorDroppedCount,
        0LL,
        0LL);
    if (response->droppedCount != 0ULL) {
        response->runtimeFlags |= KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_DROPPED;
    }

    // Capture the latest and earliest sequence numbers; callers behind the first sequence reconcile precisely using lostBeforeFirst.
    latestSequence = (ULONGLONG)InterlockedCompareExchange64(
        &runtime->monitorLatestSequence,
        0LL,
        0LL);
    earliestSequence = latestSequence > KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY
        ? latestSequence - KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY + 1ULL
        : (latestSequence == 0ULL ? 0ULL : 1ULL);
    response->latestSequence = latestSequence;
    response->firstAvailableSequence = earliestSequence;
    afterSequence = request->afterSequence;
    if (afterSequence > latestSequence) {
        afterSequence = 0ULL;
        response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_OVERFLOW;
    }
    nextSequence = afterSequence;
    if (earliestSequence != 0ULL && afterSequence + 1ULL < earliestSequence) {
        response->lostBeforeFirst = earliestSequence - (afterSequence + 1ULL);
        response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_OVERFLOW;
        nextSequence = earliestSequence - 1ULL;
    }

    // Verify the commit sequence number before and after copying each slot; preserve the cursor to handle race conditions, retrying or reconciling on the next read.
    sequence = nextSequence + 1ULL;
    while (sequence != 0ULL && sequence <= latestSequence && recordCount < requestedCount) {
        slot = &runtime->monitorSlots[(sequence - 1ULL) % KSWORD_ARK_CALLBACK_MONITOR_RING_CAPACITY];
        commitBefore = InterlockedCompareExchange64(&slot->commitSequence, 0LL, 0LL);
        if (commitBefore == (LONG64)sequence) {
            RtlCopyMemory(
                &response->records[recordCount],
                &slot->event,
                sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
            KeMemoryBarrier();
            commitAfter = InterlockedCompareExchange64(&slot->commitSequence, 0LL, 0LL);
            if (commitAfter == commitBefore && response->records[recordCount].sequence == sequence) {
                ++recordCount;
            }
            else {
                RtlZeroMemory(
                    &response->records[recordCount],
                    sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
                response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE;
                break;
            }
        }
        else {
            response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE;
            break;
        }
        nextSequence = sequence;
        ++sequence;
    }

    // The final length includes only successfully validated records.
    response->returnedCount = recordCount;
    response->nextSequence = nextSequence;
    if (nextSequence < latestSequence) {
        response->responseFlags |= KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_MORE_AVAILABLE;
    }
    response->size = (ULONG)(kResponseHeaderSize +
        ((SIZE_T)recordCount * sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT)));
    *bytesWrittenOut = response->size;
    return STATUS_SUCCESS;
}

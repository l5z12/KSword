/*++

Module Name:

    callback_waiter.c

Abstract:

    WAIT/ANSWER/CANCEL model and pending-decision context management.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_push_lock.h"

static VOID
kswordArkPendingDecisionReference(
    _In_ KswordArkPendingDecision* pendingDecision
    )
{
    if (pendingDecision != NULL) {
        (VOID)InterlockedIncrement(&pendingDecision->refCount);
    }
}

static VOID
kswordArkPendingDecisionRelease(
    _In_opt_ KswordArkPendingDecision* pendingDecision
    )
{
    if (pendingDecision == NULL) {
        return;
    }

    if (InterlockedDecrement(&pendingDecision->refCount) == 0) {
        ExFreePoolWithTag(pendingDecision, KSWORD_ARK_CALLBACK_TAG_PENDING);
    }
}

static KswordArkPendingDecision*
kswordArkFindPendingDecisionByGuidLocked(
    _In_ KswordArkCallbackRuntime* runtime,
    _In_ const KSWORD_ARK_GUID128* eventGuid
    )
{
    PLIST_ENTRY currentEntry = NULL;

    if (runtime == NULL || eventGuid == NULL) {
        return NULL;
    }

    currentEntry = runtime->pendingDecisionList.Flink;
    while (currentEntry != &runtime->pendingDecisionList) {
        KswordArkPendingDecision* currentDecision =
            CONTAINING_RECORD(currentEntry, KswordArkPendingDecision, link);
        if (kswordArkGuidEquals(&currentDecision->eventGuid, eventGuid)) {
            return currentDecision;
        }
        currentEntry = currentEntry->Flink;
    }

    return NULL;
}

static BOOLEAN
kswordArkInsertPendingDecision(
    _In_ KswordArkCallbackRuntime* runtime,
    _In_ KswordArkPendingDecision* pendingDecision
    )
{
    BOOLEAN inserted = FALSE;

    if (runtime == NULL || pendingDecision == NULL) {
        return FALSE;
    }

    kswordArkAcquirePushLockExclusive(&runtime->pendingLock);
    // Do not publish new wait items once unloading has started to avoid leaving wake-up-unreachable waiters after the unload callback.
    if (InterlockedCompareExchange(&runtime->stopping, 0L, 0L) == 0L) {
        InsertTailList(&runtime->pendingDecisionList, &pendingDecision->link);
        kswordArkPendingDecisionReference(pendingDecision); // list reference
        (VOID)InterlockedIncrement(&runtime->pendingDecisionCount);
        inserted = TRUE;
    }
    kswordArkReleasePushLockExclusive(&runtime->pendingLock);
    return inserted;
}

static VOID
kswordArkRemovePendingDecision(
    _In_ KswordArkCallbackRuntime* runtime,
    _In_ KswordArkPendingDecision* pendingDecision
    )
{
    BOOLEAN removed = FALSE;

    kswordArkAcquirePushLockExclusive(&runtime->pendingLock);
    if (pendingDecision->link.Flink != NULL && pendingDecision->link.Blink != NULL) {
        RemoveEntryList(&pendingDecision->link);
        // Links are cleared only while holding PendingLock; the cancellation path uses this to identify unlinked items.
        pendingDecision->link.Flink = NULL;
        pendingDecision->link.Blink = NULL;
        (VOID)InterlockedDecrement(&runtime->pendingDecisionCount);
        removed = TRUE;
    }
    kswordArkReleasePushLockExclusive(&runtime->pendingLock);

    if (removed) {
        kswordArkPendingDecisionRelease(pendingDecision); // drop list reference
    }
}

static VOID
kswordArkBuildEventPacket(
    _In_ const KswordArkPendingDecision* pendingDecision,
    _Out_ KSWORD_ARK_CALLBACK_EVENT_PACKET* packetOut
    )
{
    if (pendingDecision == NULL || packetOut == NULL) {
        return;
    }

    RtlZeroMemory(packetOut, sizeof(*packetOut));
    packetOut->size = sizeof(*packetOut);
    packetOut->version = KSWORD_ARK_CALLBACK_PROTOCOL_VERSION;
    packetOut->eventGuid = pendingDecision->eventGuid;
    packetOut->callbackType = pendingDecision->callbackType;
    packetOut->operationType = pendingDecision->operationType;
    packetOut->action = pendingDecision->match.action;
    packetOut->matchMode = pendingDecision->match.matchMode;
    packetOut->defaultDecision = pendingDecision->defaultDecision;
    packetOut->timeoutMs = pendingDecision->timeoutMs;
    packetOut->groupId = pendingDecision->match.groupId;
    packetOut->ruleId = pendingDecision->match.ruleId;
    packetOut->groupPriority = pendingDecision->match.groupPriority;
    packetOut->rulePriority = pendingDecision->match.rulePriority;
    packetOut->originatingPid = pendingDecision->originatingPid;
    packetOut->originatingTid = pendingDecision->originatingTid;
    packetOut->sessionId = pendingDecision->sessionId;
    packetOut->pathUnavailable = pendingDecision->pathUnavailable;
    packetOut->createdAtUtc100ns = (ULONG64)pendingDecision->createdAtUtc100ns.QuadPart;
    packetOut->deadlineUtc100ns = (ULONG64)pendingDecision->deadlineUtc100ns.QuadPart;

    kswordArkCopyWideStringToFixedBuffer(
        pendingDecision->initiatorPath,
        packetOut->initiatorPath,
        RTL_NUMBER_OF(packetOut->initiatorPath));
    kswordArkCopyWideStringToFixedBuffer(
        pendingDecision->targetPath,
        packetOut->targetPath,
        RTL_NUMBER_OF(packetOut->targetPath));
    kswordArkCopyWideStringToFixedBuffer(
        pendingDecision->match.ruleInitiatorPattern,
        packetOut->ruleInitiatorPattern,
        RTL_NUMBER_OF(packetOut->ruleInitiatorPattern));
    kswordArkCopyWideStringToFixedBuffer(
        pendingDecision->match.ruleTargetPattern,
        packetOut->ruleTargetPattern,
        RTL_NUMBER_OF(packetOut->ruleTargetPattern));
    kswordArkCopyWideStringToFixedBuffer(
        pendingDecision->match.groupName,
        packetOut->groupName,
        RTL_NUMBER_OF(packetOut->groupName));
    kswordArkCopyWideStringToFixedBuffer(
        pendingDecision->match.ruleName,
        packetOut->ruleName,
        RTL_NUMBER_OF(packetOut->ruleName));
}

static NTSTATUS
kswordArkDispatchEventToWaitingRequest(
    _In_ KswordArkCallbackRuntime* runtime,
    _In_ const KswordArkPendingDecision* pendingDecision
    )
{
    WDFREQUEST waitRequest = WDF_NO_HANDLE;
    KSWORD_ARK_CALLBACK_EVENT_PACKET eventPacket;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID outputBuffer = NULL;
    size_t outputLength = 0;

    if (runtime == NULL || runtime->waitQueue == WDF_NO_HANDLE || pendingDecision == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = WdfIoQueueRetrieveNextRequest(runtime->waitQueue, &waitRequest);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        waitRequest,
        sizeof(KSWORD_ARK_CALLBACK_EVENT_PACKET),
        &outputBuffer,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        WdfRequestCompleteWithInformation(waitRequest, status, 0U);
        return status;
    }

    kswordArkBuildEventPacket(pendingDecision, &eventPacket);
    RtlCopyMemory(outputBuffer, &eventPacket, sizeof(eventPacket));
    WdfRequestCompleteWithInformation(waitRequest, STATUS_SUCCESS, sizeof(eventPacket));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackWaiterInitialize(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || runtime->device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    queueConfig.PowerManaged = WdfFalse;

    WDF_OBJECT_ATTRIBUTES_INIT(&queueAttributes);
    queueAttributes.ParentObject = runtime->device;

    status = WdfIoQueueCreate(
        runtime->device,
        &queueConfig,
        &queueAttributes,
        &runtime->waitQueue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
kswordArkCallbackWaiterUninitialize(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    if (runtime == NULL) {
        return;
    }

    // Cannot cancel items via the global runtime because unloading revokes the global publication before destroying this queue.
    (VOID)kswordArkCallbackCancelAllPendingForRuntime(runtime);
    if (runtime->waitQueue != WDF_NO_HANDLE) {
        WdfIoQueuePurgeSynchronously(runtime->waitQueue);
        WdfObjectDelete(runtime->waitQueue);
        runtime->waitQueue = WDF_NO_HANDLE;
    }
}

NTSTATUS
kswordArkCallbackIoctlWaitEventInternal(
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (runtime == NULL || runtime->waitQueue == WDF_NO_HANDLE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = WdfRequestForwardToIoQueue(request, runtime->waitQueue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    return STATUS_PENDING;
}

NTSTATUS
kswordArkCallbackIoctlAnswerEventInternal(
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* completeBytesOut
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KSWORD_ARK_CALLBACK_ANSWER_REQUEST* answerRequest = NULL;
    size_t answerLength = 0;
    KswordArkPendingDecision* matchedDecision = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (completeBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *completeBytesOut = 0U;

    if (runtime == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST),
        (PVOID*)&answerRequest,
        &answerLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (inputBufferLength < sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST) ||
        answerRequest->size < sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST) ||
        answerRequest->version != KSWORD_ARK_CALLBACK_PROTOCOL_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    if (answerRequest->decision != KSWORD_ARK_DECISION_ALLOW &&
        answerRequest->decision != KSWORD_ARK_DECISION_DENY) {
        return STATUS_INVALID_PARAMETER;
    }

    // Responses, timeouts, and cancellations all arbitrate FinalDecision under the same lock, preventing timeouts from overwriting accepted responses.
    kswordArkAcquirePushLockExclusive(&runtime->pendingLock);
    matchedDecision = kswordArkFindPendingDecisionByGuidLocked(runtime, &answerRequest->eventGuid);
    if (matchedDecision == NULL) {
        kswordArkReleasePushLockExclusive(&runtime->pendingLock);
        return STATUS_NOT_FOUND;
    }

    if (InterlockedCompareExchange(&matchedDecision->answered, 0L, 0L) != 0L) {
        kswordArkReleasePushLockExclusive(&runtime->pendingLock);
        return STATUS_ALREADY_COMMITTED;
    }

    matchedDecision->finalDecision = answerRequest->decision;
    (VOID)InterlockedExchange(&matchedDecision->answered, 1L);
    // The responder thread holds a temporary reference outside the lock before signaling to prevent the concurrent timeout path from releasing the object.
    kswordArkPendingDecisionReference(matchedDecision);
    kswordArkReleasePushLockExclusive(&runtime->pendingLock);
    KeSetEvent(&matchedDecision->decisionEvent, IO_NO_INCREMENT, FALSE);
    *completeBytesOut = sizeof(KSWORD_ARK_CALLBACK_ANSWER_REQUEST);
    kswordArkPendingDecisionRelease(matchedDecision);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackCancelAllPendingForRuntime(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    if (runtime == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    for (;;) {
        KswordArkPendingDecision* pendingDecision = NULL;

        kswordArkAcquirePushLockExclusive(&runtime->pendingLock);
        if (!IsListEmpty(&runtime->pendingDecisionList)) {
            PLIST_ENTRY entry = RemoveHeadList(&runtime->pendingDecisionList);

            pendingDecision = CONTAINING_RECORD(entry, KswordArkPendingDecision, link);
            // Unlink from the protected original list first; never temporarily suspend the node to an unprotected local list.
            pendingDecision->link.Flink = NULL;
            pendingDecision->link.Blink = NULL;
            (VOID)InterlockedDecrement(&runtime->pendingDecisionCount);
            if (InterlockedCompareExchange(&pendingDecision->answered, 0L, 0L) == 0L) {
                pendingDecision->finalDecision = pendingDecision->defaultDecision;
                (VOID)InterlockedExchange(&pendingDecision->answered, 1L);
            }
        }
        kswordArkReleasePushLockExclusive(&runtime->pendingLock);

        if (pendingDecision == NULL) {
            break;
        }

        // Unconditionally set the event to cover the narrow window where the reply thread has submitted but not yet signaled.
        KeSetEvent(&pendingDecision->decisionEvent, IO_NO_INCREMENT, FALSE);
        kswordArkPendingDecisionRelease(pendingDecision); // drop list reference
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkCallbackCancelAllPendingInternal(
    VOID
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();

    return kswordArkCallbackCancelAllPendingForRuntime(runtime);
}

NTSTATUS
kswordArkCallbackAskUserDecision(
    _In_ const KswordArkCallbackEventInput* eventInput,
    _Out_ ULONG* decisionOut
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    KswordArkPendingDecision* pendingDecision = NULL;
    NTSTATUS dispatchStatus = STATUS_SUCCESS;
    NTSTATUS waitStatus = STATUS_SUCCESS;
    LARGE_INTEGER timeoutInterval = { 0 };
    ULONGLONG timeout100ns = 0;
    ULONG waitTimeoutMs = 0;

    if (decisionOut == NULL || eventInput == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *decisionOut = KSWORD_ARK_DECISION_ALLOW;

    if (runtime == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // A degraded startup may leave the AskUser queue empty; in this case, Ask rules must fall
    // back to their default decision rather than passing an uninitialized verdict to the caller.
    if (runtime->waitQueue == WDF_NO_HANDLE) {
        *decisionOut = eventInput->match.askDefaultDecision;
        if (*decisionOut != KSWORD_ARK_DECISION_DENY) {
            *decisionOut = KSWORD_ARK_DECISION_ALLOW;
        }
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (InterlockedCompareExchange(&runtime->stopping, 0L, 0L) != 0L) {
        // Callbacks during unloading must immediately adopt the rule's default value and cannot create wait items that block the unloading flow.
        *decisionOut = eventInput->match.askDefaultDecision;
        if (*decisionOut != KSWORD_ARK_DECISION_DENY) {
            *decisionOut = KSWORD_ARK_DECISION_ALLOW;
        }
        return STATUS_DEVICE_NOT_READY;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        *decisionOut = eventInput->match.askDefaultDecision;
        if (*decisionOut != KSWORD_ARK_DECISION_DENY) {
            *decisionOut = KSWORD_ARK_DECISION_ALLOW;
        }
        return STATUS_UNSUCCESSFUL;
    }

    pendingDecision = (KswordArkPendingDecision*)kswordArkAllocateNonPaged(
        sizeof(KswordArkPendingDecision),
        KSWORD_ARK_CALLBACK_TAG_PENDING);
    if (pendingDecision == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(pendingDecision, sizeof(*pendingDecision));

    pendingDecision->refCount = 1;
    pendingDecision->answered = 0;
    kswordArkGuidGenerate(&pendingDecision->eventGuid);
    KeInitializeEvent(&pendingDecision->decisionEvent, NotificationEvent, FALSE);

    pendingDecision->callbackType = eventInput->callbackType;
    pendingDecision->operationType = eventInput->operationType;
    pendingDecision->originatingPid = eventInput->originatingPid;
    pendingDecision->originatingTid = eventInput->originatingTid;
    pendingDecision->sessionId = eventInput->sessionId;
    pendingDecision->pathUnavailable = eventInput->pathUnavailable;
    pendingDecision->match = eventInput->match;
    pendingDecision->timeoutMs = eventInput->match.askTimeoutMs;
    if (pendingDecision->timeoutMs == 0U) {
        pendingDecision->timeoutMs = 5000U;
    }
    pendingDecision->defaultDecision = eventInput->match.askDefaultDecision;
    if (pendingDecision->defaultDecision != KSWORD_ARK_DECISION_ALLOW &&
        pendingDecision->defaultDecision != KSWORD_ARK_DECISION_DENY) {
        pendingDecision->defaultDecision = KSWORD_ARK_DECISION_ALLOW;
    }
    pendingDecision->finalDecision = pendingDecision->defaultDecision;
    kswordArkGetSystemTimeUtc100ns(&pendingDecision->createdAtUtc100ns);
    pendingDecision->deadlineUtc100ns.QuadPart =
        pendingDecision->createdAtUtc100ns.QuadPart + ((LONGLONG)pendingDecision->timeoutMs * 10000LL);

    kswordArkCopyUnicodeToFixedBuffer(
        &eventInput->initiatorPath,
        pendingDecision->initiatorPath,
        RTL_NUMBER_OF(pendingDecision->initiatorPath));
    kswordArkCopyUnicodeToFixedBuffer(
        &eventInput->targetPath,
        pendingDecision->targetPath,
        RTL_NUMBER_OF(pendingDecision->targetPath));

    if (!kswordArkInsertPendingDecision(runtime, pendingDecision)) {
        // The stopped state may be established only after pre-checks; on insertion failure, retain the rule's default decision and release the owner reference.
        *decisionOut = pendingDecision->defaultDecision;
        kswordArkPendingDecisionRelease(pendingDecision); // owner release
        return STATUS_DEVICE_NOT_READY;
    }
    dispatchStatus = kswordArkDispatchEventToWaitingRequest(runtime, pendingDecision);
    if (!NT_SUCCESS(dispatchStatus)) {
        kswordArkRemovePendingDecision(runtime, pendingDecision);
        *decisionOut = pendingDecision->defaultDecision;
        kswordArkPendingDecisionRelease(pendingDecision); // owner release
        kswordArkCallbackLogFormat(
            "Warn",
            "AskUser fallback default: no waiting receiver, callback=%lu, op=0x%08lX, groupId=%lu, ruleId=%lu.",
            (unsigned long)eventInput->callbackType,
            (unsigned long)eventInput->operationType,
            (unsigned long)eventInput->match.groupId,
            (unsigned long)eventInput->match.ruleId);
        return STATUS_NOT_FOUND;
    }

    waitTimeoutMs = pendingDecision->timeoutMs;
    if (waitTimeoutMs > 600000UL) {
        waitTimeoutMs = 600000UL;
    }
    timeout100ns = (ULONGLONG)waitTimeoutMs * 10000ULL;
    if (timeout100ns > (ULONGLONG)MAXLONGLONG) {
        timeout100ns = (ULONGLONG)MAXLONGLONG;
    }
    timeoutInterval.QuadPart = -(LONGLONG)timeout100ns;

    waitStatus = KeWaitForSingleObject(
        &pendingDecision->decisionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    if (waitStatus == STATUS_TIMEOUT) {
        BOOLEAN timeoutApplied = FALSE;

        // Shares PendingLock with Answer and Cancel to ensure the final decision and its state are not subject to race writes.
        kswordArkAcquirePushLockExclusive(&runtime->pendingLock);
        if (InterlockedCompareExchange(&pendingDecision->answered, 0L, 0L) == 0L) {
            pendingDecision->finalDecision = pendingDecision->defaultDecision;
            (VOID)InterlockedExchange(&pendingDecision->answered, 1L);
            timeoutApplied = TRUE;
        }
        *decisionOut = pendingDecision->finalDecision;
        kswordArkReleasePushLockExclusive(&runtime->pendingLock);

        if (timeoutApplied) {
            kswordArkCallbackLogFormat(
                "Warn",
                "AskUser timeout default applied, callback=%lu, op=0x%08lX, groupId=%lu, ruleId=%lu.",
                (unsigned long)eventInput->callbackType,
                (unsigned long)eventInput->operationType,
                (unsigned long)eventInput->match.groupId,
                (unsigned long)eventInput->match.ruleId);
        }
    }
    else {
        // After the event wakes, read the result while still holding the lock to synchronize with writes in the reply, cancel, and timeout paths.
        kswordArkAcquirePushLockShared(&runtime->pendingLock);
        *decisionOut = pendingDecision->finalDecision;
        kswordArkReleasePushLockShared(&runtime->pendingLock);
    }

    kswordArkRemovePendingDecision(runtime, pendingDecision);
    kswordArkPendingDecisionRelease(pendingDecision); // owner release
    return STATUS_SUCCESS;
}

ULONG
kswordArkCallbackGetWaitingRequestCount(
    VOID
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    ULONG queueRequests = 0U;

    if (runtime == NULL || runtime->waitQueue == WDF_NO_HANDLE) {
        return 0U;
    }

    (VOID)WdfIoQueueGetState(runtime->waitQueue, &queueRequests, NULL);
    return queueRequests;
}

ULONG
kswordArkCallbackGetPendingDecisionCount(
    VOID
    )
{
    KswordArkCallbackRuntime* runtime = kswordArkCallbackGetRuntime();
    if (runtime == NULL) {
        return 0U;
    }

    return (ULONG)InterlockedCompareExchange(&runtime->pendingDecisionCount, 0L, 0L);
}

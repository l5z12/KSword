/*++

Module Name:

    thread_callback.c

Abstract:

    Thread create callback registration and log-only dispatch.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

VOID
kswordArkThreadCreateNotify(
    _In_ HANDLE processId,
    _In_ HANDLE threadId,
    _In_ BOOLEAN create
    )
{
    KswordArkCallbackMatchResult matchResult;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    PEPROCESS targetProcess = NULL;
    ULONG targetSessionId = 0UL;
    ULONG operationType = create ? KSWORD_ARK_THREAD_OP_CREATE : KSWORD_ARK_THREAD_OP_EXIT;
    NTSTATUS matchStatus = STATUS_SUCCESS;

    (VOID)kswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        NULL);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    if (NT_SUCCESS(PsLookupProcessByProcessId(processId, &targetProcess))) {
        (VOID)kswordArkResolveProcessImagePath(
            targetProcess,
            targetPathBuffer,
            RTL_NUMBER_OF(targetPathBuffer),
            NULL);
        targetSessionId = kswordArkGetProcessSessionIdSafe(targetProcess);
        ObDereferenceObject(targetProcess);
    }

    if (targetPathBuffer[0] == L'\0') {
        (VOID)RtlStringCbPrintfW(
            targetPathBuffer,
            sizeof(targetPathBuffer),
            L"PID=%lu,TID=%lu",
            (unsigned long)HandleToULong(processId),
            (unsigned long)HandleToULong(threadId));
    }
    RtlInitUnicodeString(&targetPath, targetPathBuffer);

    // Thread telemetry is published before rule matching to ensure complete monitoring even without rule configurations.
    if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD)) {
        KswordArkCallbackMonitorEventInput monitorInput;
        RtlZeroMemory(&monitorInput, sizeof(monitorInput));
        monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
        monitorInput.operation = operationType;
        monitorInput.originatingProcessId = HandleToULong(PsGetCurrentProcessId());
        monitorInput.originatingThreadId = HandleToULong(PsGetCurrentThreadId());
        monitorInput.targetProcessId = HandleToULong(processId);
        monitorInput.targetThreadId = HandleToULong(threadId);
        monitorInput.sessionId = targetSessionId;
        monitorInput.processName = &initiatorPath;
        monitorInput.path = &targetPath;
        kswordArkCallbackMonitorPublish(&monitorInput);
    }

    matchStatus = kswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_THREAD_CREATE,
        operationType,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(matchStatus) || !matchResult.matched) {
        return;
    }

    kswordArkCallbackLogFormat(
        "Info",
        "Thread callback log rule hit, processId=%lu, threadId=%lu, create=%lu, groupId=%lu, ruleId=%lu.",
        (unsigned long)HandleToULong(processId),
        (unsigned long)HandleToULong(threadId),
        (unsigned long)(create ? 1UL : 0UL),
        (unsigned long)matchResult.groupId,
        (unsigned long)matchResult.ruleId);
}

NTSTATUS
kswordArkThreadCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    status = PsSetCreateThreadNotifyRoutine(kswordArkThreadCreateNotify);
    if (NT_SUCCESS(status)) {
        // The global runtime is not yet published during registration; logs must explicitly use the runtime version.
        kswordArkCallbackLogFrameForRuntime(runtime, "Info", "Thread create callback registered.");
    }
    return status;
}

VOID
kswordArkThreadCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(runtime);

    status = PsRemoveCreateThreadNotifyRoutine(kswordArkThreadCreateNotify);
    if (NT_SUCCESS(status)) {
        kswordArkCallbackLogFrame("Info", "Thread create callback unregistered.");
    }
}

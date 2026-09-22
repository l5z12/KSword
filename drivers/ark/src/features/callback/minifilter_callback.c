/*++

Module Name:

    minifilter_callback.c

Abstract:

    Callback-rule enforcement for the shared KswordARK file-system minifilter.

Environment:

    Kernel-mode minifilter

--*/

#include "callback_internal.h"
#include "ark/ark_file_monitor.h"
#include "../file_monitor/file_monitor_internal.h"

static BOOLEAN
kswordArkMinifilterBuildTargetPath(
    _In_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Out_writes_(targetChars) PWCHAR targetBuffer,
    _In_ USHORT targetChars
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PFLT_FILE_NAME_INFORMATION nameInformation = NULL;
    UNICODE_STRING fallbackName;

    if (targetBuffer == NULL || targetChars == 0U) {
        return FALSE;
    }

    targetBuffer[0] = L'\0';
    RtlZeroMemory(&fallbackName, sizeof(fallbackName));

    status = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInformation);
    if (NT_SUCCESS(status) && nameInformation != NULL) {
        (VOID)FltParseFileNameInformation(nameInformation);
        kswordArkCopyUnicodeToFixedBuffer(&nameInformation->Name, targetBuffer, targetChars);
        FltReleaseFileNameInformation(nameInformation);
        return (targetBuffer[0] != L'\0') ? TRUE : FALSE;
    }

    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }

    if (fltObjects != NULL &&
        fltObjects->FileObject != NULL &&
        fltObjects->FileObject->FileName.Buffer != NULL &&
        fltObjects->FileObject->FileName.Length != 0U) {
        fallbackName = fltObjects->FileObject->FileName;
        kswordArkCopyUnicodeToFixedBuffer(&fallbackName, targetBuffer, targetChars);
    }

    return (targetBuffer[0] != L'\0') ? TRUE : FALSE;
}

static ULONG
kswordArkMinifilterGetRequestorProcessId(
    _In_ PFLT_CALLBACK_DATA data
    )
{
    if (data == NULL) {
        return 0UL;
    }

    return (ULONG)(ULONG_PTR)FltGetRequestorProcessId(data);
}

FLT_PREOP_CALLBACK_STATUS
kswordArkMinifilterApplyRule(
    _In_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ ULONG operationType
    )
{
    KswordArkCallbackMatchResult matchResult;
    KswordArkCallbackEventInput eventInput;
    UNICODE_STRING initiatorPath;
    UNICODE_STRING targetPath;
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    BOOLEAN initiatorPathUnavailable = TRUE;
    BOOLEAN targetPathAvailable = FALSE;
    ULONG decision = KSWORD_ARK_DECISION_ALLOW;
    ULONG requestorProcessId = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&matchResult, sizeof(matchResult));
    RtlZeroMemory(&eventInput, sizeof(eventInput));
    RtlZeroMemory(&initiatorPath, sizeof(initiatorPath));
    RtlZeroMemory(&targetPath, sizeof(targetPath));

    if (data == NULL || operationType == 0UL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestorProcessId = kswordArkMinifilterGetRequestorProcessId(data);

    (VOID)kswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        &initiatorPathUnavailable);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    targetPathAvailable = kswordArkMinifilterBuildTargetPath(
        data,
        fltObjects,
        targetPathBuffer,
        RTL_NUMBER_OF(targetPathBuffer));
    RtlInitUnicodeString(&targetPath, targetPathBuffer);

    status = kswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_MINIFILTER,
        operationType,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(status) || !matchResult.matched) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
        kswordArkCallbackLogFormat(
            "Info",
            "Minifilter callback log rule hit, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)requestorProcessId,
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_DENY) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0U;
        kswordArkCallbackLogFormat(
            "Warn",
            "Minifilter callback denied, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)requestorProcessId,
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return FLT_PREOP_COMPLETE;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_ALLOW) {
        kswordArkCallbackLogFormat(
            "Info",
            "Minifilter callback allow rule hit, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)requestorProcessId,
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (matchResult.action != KSWORD_ARK_RULE_ACTION_ASK_USER) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        decision = matchResult.askDefaultDecision;
    }
    else {
        eventInput.callbackType = KSWORD_ARK_CALLBACK_TYPE_MINIFILTER;
        eventInput.operationType = operationType;
        eventInput.originatingPid = requestorProcessId;
        eventInput.originatingTid = HandleToULong(PsGetCurrentThreadId());
        eventInput.sessionId = kswordArkGetProcessSessionIdSafe(PsGetCurrentProcess());
        eventInput.pathUnavailable = (!targetPathAvailable || initiatorPathUnavailable) ? 1UL : 0UL;
        eventInput.initiatorPath = initiatorPath;
        eventInput.targetPath = targetPath;
        eventInput.match = matchResult;
        decision = matchResult.askDefaultDecision;
        status = kswordArkCallbackAskUserDecision(&eventInput, &decision);
        if (!NT_SUCCESS(status)) {
            kswordArkCallbackLogFormat(
                "Warn",
                "Minifilter ask-user fallback used, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu, status=0x%08X.",
                (unsigned long)operationType,
                (unsigned long)requestorProcessId,
                (unsigned long)matchResult.groupId,
                (unsigned long)matchResult.ruleId,
                (unsigned int)status);
        }
    }

    if (decision == KSWORD_ARK_DECISION_DENY) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED;
        data->IoStatus.Information = 0U;
        kswordArkCallbackLogFormat(
            "Warn",
            "Minifilter ask-user decision DENY, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)requestorProcessId,
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return FLT_PREOP_COMPLETE;
    }

    kswordArkCallbackLogFormat(
        "Info",
        "Minifilter ask-user decision ALLOW, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
        (unsigned long)operationType,
        (unsigned long)requestorProcessId,
        (unsigned long)matchResult.groupId,
        (unsigned long)matchResult.ruleId);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

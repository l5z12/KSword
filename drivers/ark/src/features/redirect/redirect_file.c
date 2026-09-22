/*++

Module Name:

    redirect_file.c

Abstract:

    File-system create redirection helper for the shared minifilter runtime.

Environment:

    Kernel-mode minifilter

--*/

#include "redirect_internal.h"
#include "ark/ark_push_lock.h"

NTSTATUS
kswordArkRedirectTryRewriteFileCreate(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Out_ BOOLEAN* redirectedOut
    )
/*++

Routine Description:

    In IRP_MJ_CREATE pre-operation, attempt to replace FileObject->FileName. Note:
    This implementation uses only FltMgr/IO manager public fields; after matching a rule, it replaces the current
    create name with the target NT path and calls FltSetCallbackDataDirty to notify FltMgr to reprocess the parameters.

Arguments:

    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    RedirectedOut - Returns TRUE if the current create path has been rewritten.

Return Value:

    STATUS_SUCCESS indicates the check is complete; a failure status indicates a rule was matched but the rewrite failed.

--*/
{
    KswordArkRedirectRuntime* runtime = kswordArkRedirectGetRuntime();
    KSWORD_ARK_REDIRECT_RULE matchedRule;
    UNICODE_STRING sourceName;
    UNICODE_STRING targetName;
    ULONG processId = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (redirectedOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *redirectedOut = FALSE;

    if (data == NULL || fltObjects == NULL || fltObjects->FileObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (data->Iopb == NULL || data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return STATUS_SUCCESS;
    }
    if ((runtime->runtimeFlags & KSWORD_ARK_REDIRECT_RUNTIME_FILE_ACTIVE) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (fltObjects->FileObject->FileName.Buffer == NULL ||
        fltObjects->FileObject->FileName.Length == 0U) {
        return STATUS_SUCCESS;
    }

    sourceName = fltObjects->FileObject->FileName;
    processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(data);

    kswordArkAcquirePushLockShared(&runtime->lock);
    status = kswordArkRedirectFindMatchLocked(
        runtime,
        KSWORD_ARK_REDIRECT_TYPE_FILE,
        processId,
        &sourceName,
        &matchedRule);
    kswordArkReleasePushLockShared(&runtime->lock);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&targetName, matchedRule.targetPath);
    if (targetName.Buffer == NULL || targetName.Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }

    status = IoReplaceFileObjectName(
        fltObjects->FileObject,
        targetName.Buffer,
        targetName.Length);
    if (!NT_SUCCESS(status)) {
        kswordArkRedirectLogFormat(
            "Warn",
            "File redirect failed, pid=%lu, ruleId=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned long)matchedRule.ruleId,
            (unsigned int)status);
        return status;
    }

    FltSetCallbackDataDirty(data);
    InterlockedIncrement64(&runtime->fileRedirectHits);
    *redirectedOut = TRUE;

    kswordArkRedirectLogFormat(
        "Info",
        "File redirect applied, pid=%lu, ruleId=%lu.",
        (unsigned long)processId,
        (unsigned long)matchedRule.ruleId);
    return STATUS_SUCCESS;
}

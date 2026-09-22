/*++

Module Name:

    process_callback.c

Abstract:

    Process create callback registration and dispatch.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_bugcheck.h"
#include "ark/ark_process_protect.h"

NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS process
    );

VOID
kswordArkProcessCreateNotifyEx(
    _Inout_ PEPROCESS process,
    _In_ HANDLE processId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO createInfo
    )
{
    KswordArkCallbackMatchResult matchResult;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    BOOLEAN initiatorPathUnavailable = TRUE;
    ULONG operationType = KSWORD_ARK_PROCESS_OP_CREATE;
    NTSTATUS matchStatus = STATUS_SUCCESS;

    kswordArkBugcheckTrackProcess(process, processId, createInfo);

    if (createInfo == NULL) {
        KswordArkCallbackMonitorEventInput monitorInput;
        PCHAR shortImageName = NULL;

        // Exit notifications read only the fixed short name within EPROCESS to avoid new pool allocations for telemetry.
        if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)) {
            shortImageName = PsGetProcessImageFileName(process);
            if (shortImageName != NULL && shortImageName[0] != '\0') {
                (VOID)RtlStringCbPrintfW(
                    targetPathBuffer,
                    sizeof(targetPathBuffer),
                    L"%S",
                    shortImageName);
            }
            RtlInitUnicodeString(&targetPath, targetPathBuffer);
            RtlZeroMemory(&monitorInput, sizeof(monitorInput));
            monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
            monitorInput.operation = KSWORD_ARK_CALLBACK_MONITOR_PROCESS_OP_EXIT;
            monitorInput.originatingProcessId = HandleToULong(PsGetCurrentProcessId());
            monitorInput.originatingThreadId = HandleToULong(PsGetCurrentThreadId());
            monitorInput.targetProcessId = HandleToULong(processId);
            monitorInput.sessionId = kswordArkGetProcessSessionIdSafe(process);
            monitorInput.processName = &targetPath;
            monitorInput.path = &targetPath;
            kswordArkCallbackMonitorPublish(&monitorInput);
        }
        // Exit notification: Remove the process from the PP self-healing ledger to prevent dead PIDs from occupying slots.
        kswordArkProcessProtectNotifyProcessExit(HandleToULong(processId));
        return;
    }

    // The kernel PP layer executes before general rules: this is the only opportunity to re-apply protection to a target process after
    // a restart, before it begins execution. It does not modify CreationStatus and thus does not affect subsequent DENY decisions.
    kswordArkProcessProtectNotifyProcessCreate(
        process,
        HandleToULong(processId),
        createInfo->ImageFileName);

    (VOID)kswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        &initiatorPathUnavailable);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    if (createInfo->ImageFileName != NULL &&
        createInfo->ImageFileName->Buffer != NULL &&
        createInfo->ImageFileName->Length > 0U) {
        targetPath = *createInfo->ImageFileName;
    }
    else {
        RtlInitUnicodeString(&targetPath, targetPathBuffer);
    }

    // Telemetry and rule evaluation are independent; process creation events must still be published even when no rules match.
    if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)) {
        KswordArkCallbackMonitorEventInput monitorInput;
        RtlZeroMemory(&monitorInput, sizeof(monitorInput));
        monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
        monitorInput.operation = operationType;
        monitorInput.originatingProcessId = HandleToULong(createInfo->CreatingThreadId.UniqueProcess);
        monitorInput.originatingThreadId = HandleToULong(createInfo->CreatingThreadId.UniqueThread);
        monitorInput.targetProcessId = HandleToULong(processId);
        monitorInput.parentProcessId = HandleToULong(createInfo->ParentProcessId);
        monitorInput.sessionId = kswordArkGetProcessSessionIdSafe(process);
        monitorInput.processName = &initiatorPath;
        monitorInput.path = &targetPath;
        kswordArkCallbackMonitorPublish(&monitorInput);
    }

    matchStatus = kswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_PROCESS_CREATE,
        operationType,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(matchStatus) || !matchResult.matched) {
        return;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
        kswordArkCallbackLogFormat(
            "Info",
            "Process callback log rule hit, creatorPid=%lu, targetPid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)HandleToULong(processId),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_DENY) {
        createInfo->CreationStatus = STATUS_ACCESS_DENIED;
        kswordArkCallbackLogFormat(
            "Warn",
            "Process creation denied, creatorPid=%lu, targetPid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)HandleToULong(processId),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_ALLOW) {
        kswordArkCallbackLogFormat(
            "Info",
            "Process callback allow rule hit, creatorPid=%lu, targetPid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)HandleToULong(processId),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
    }
}

NTSTATUS
kswordArkProcessCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    status = PsSetCreateProcessNotifyRoutineEx(kswordArkProcessCreateNotifyEx, FALSE);
    if (NT_SUCCESS(status)) {
        // The global runtime is not yet published during registration; logs must explicitly use the runtime version.
        kswordArkCallbackLogFrameForRuntime(runtime, "Info", "Process create callback registered.");
    }
    return status;
}

VOID
kswordArkProcessCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(runtime);

    status = PsSetCreateProcessNotifyRoutineEx(kswordArkProcessCreateNotifyEx, TRUE);
    if (NT_SUCCESS(status)) {
        kswordArkCallbackLogFrame("Info", "Process create callback unregistered.");
    }
}

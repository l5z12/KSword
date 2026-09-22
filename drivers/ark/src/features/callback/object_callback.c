/*++

Module Name:

    object_callback.c

Abstract:

    Object manager callback registration (Process/Thread handle operations only).

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"
#include "ark/ark_process_protect.h"

static const WCHAR kGKswordArkObAltitude[] = L"385201.5142";

NTSYSAPI
PEPROCESS
NTAPI
PsGetThreadProcess(
    _In_ PETHREAD thread
    );

#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#endif
#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD 0x0002
#endif
#ifndef PROCESS_SET_QUOTA
#define PROCESS_SET_QUOTA 0x0100
#endif
#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
#ifndef PROCESS_SUSPEND_RESUME
#define PROCESS_SUSPEND_RESUME 0x0800
#endif
#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE 0x0001
#endif
#ifndef THREAD_SUSPEND_RESUME
#define THREAD_SUSPEND_RESUME 0x0002
#endif
#ifndef THREAD_SET_CONTEXT
#define THREAD_SET_CONTEXT 0x0010
#endif
#ifndef THREAD_SET_INFORMATION
#define THREAD_SET_INFORMATION 0x0020
#endif
#ifndef THREAD_SET_LIMITED_INFORMATION
#define THREAD_SET_LIMITED_INFORMATION 0x0400
#endif
#ifndef THREAD_DIRECT_IMPERSONATION
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif

static ACCESS_MASK
kswordArkObjectBuildStripMask(
    _In_ POBJECT_TYPE objectType
    )
{
    if (objectType == *PsProcessType) {
        return (ACCESS_MASK)(
            PROCESS_TERMINATE |
            PROCESS_CREATE_THREAD |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_DUP_HANDLE |
            PROCESS_SET_INFORMATION |
            PROCESS_SET_QUOTA |
            PROCESS_SUSPEND_RESUME |
            WRITE_DAC |
            WRITE_OWNER);
    }

    if (objectType == *PsThreadType) {
        return (ACCESS_MASK)(
            THREAD_TERMINATE |
            THREAD_SUSPEND_RESUME |
            THREAD_SET_CONTEXT |
            THREAD_SET_INFORMATION |
            THREAD_SET_LIMITED_INFORMATION |
            THREAD_DIRECT_IMPERSONATION |
            WRITE_DAC |
            WRITE_OWNER);
    }

    return 0U;
}

OB_PREOP_CALLBACK_STATUS
kswordArkObjectPreOperation(
    _In_ PVOID registrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION operationInformation
    )
{
    KswordArkCallbackRuntime* runtime = (KswordArkCallbackRuntime*)registrationContext;
    KswordArkCallbackMatchResult matchResult;
    ULONG operationType = 0U;
    ULONG callbackOperationMask = 0U;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    ACCESS_MASK* desiredAccessPointer = NULL;
    ACCESS_MASK originalDesiredAccess = 0U;
    ACCESS_MASK accessBeforeRuleStrip = 0U;
    ACCESS_MASK stripMask = 0U;
    ACCESS_MASK strippedAccess = 0U;
    PEPROCESS targetProcess = NULL;
    BOOLEAN targetIsThreadObject = FALSE;
    ULONG targetProcessId = 0UL;
    ULONG targetThreadId = 0UL;
    NTSTATUS matchStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(runtime);

    if (operationInformation == NULL ||
        operationInformation->KernelHandle ||
        operationInformation->ObjectType == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->ObjectType != *PsProcessType &&
        operationInformation->ObjectType != *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        operationType = KSWORD_ARK_OBJECT_OP_HANDLE_CREATE;
        desiredAccessPointer = &operationInformation->Parameters->CreateHandleInformation.DesiredAccess;
    }
    else if (operationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        operationType = KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE;
        desiredAccessPointer = &operationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
    }
    else {
        return OB_PREOP_SUCCESS;
    }

    if (operationInformation->ObjectType == *PsProcessType) {
        callbackOperationMask = operationType | KSWORD_ARK_OBJECT_OP_TYPE_PROCESS;
        targetProcess = (PEPROCESS)operationInformation->Object;
    }
    else {
        callbackOperationMask = operationType | KSWORD_ARK_OBJECT_OP_TYPE_THREAD;
        targetIsThreadObject = TRUE;
        targetProcess = PsGetThreadProcess((PETHREAD)operationInformation->Object);
        targetThreadId = HandleToULong(PsGetThreadId((PETHREAD)operationInformation->Object));
    }

    if (targetProcess != NULL) {
        targetProcessId = HandleToULong(PsGetProcessId(targetProcess));
    }

    // Save the system's original requested permissions to display both the original and the permissions processed by the process protection layer later.
    if (desiredAccessPointer != NULL) {
        originalDesiredAccess = *desiredAccessPointer;
    }

    if (targetProcess != NULL) {
        (VOID)kswordArkResolveProcessImagePath(
            targetProcess,
            targetPathBuffer,
            RTL_NUMBER_OF(targetPathBuffer),
            NULL);
    }

    (VOID)kswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        NULL);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    // Process protection executes before general callback rules: it has its own rule table and trust whitelist;
    // the permission bits removed by both are unioned. Reuse the already-resolved image path here to avoid
    // redundant SeLocateProcessImageName calls on the hot handle path. Placeholder strings are written only after
    // protection checks, ensuring protection rules see the real path or an empty string, not diagnostic text.
    (VOID)kswordArkProcessProtectFilterHandleOperation(
        targetIsThreadObject,
        targetProcess,
        targetPathBuffer,
        initiatorPathBuffer,
        desiredAccessPointer);

    if (targetPathBuffer[0] == L'\0') {
        (VOID)RtlStringCbPrintfW(
            targetPathBuffer,
            sizeof(targetPathBuffer),
            L"ObjectType=%s,Operation=0x%08lX",
            (operationInformation->ObjectType == *PsProcessType) ? L"Process" : L"Thread",
            (unsigned long)operationType);
    }
    RtlInitUnicodeString(&targetPath, targetPathBuffer);

    matchStatus = kswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_OBJECT,
        callbackOperationMask,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (NT_SUCCESS(matchStatus) && matchResult.matched) {
        if (matchResult.action == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
            kswordArkCallbackLogFormat(
                "Info",
                "Object callback log rule hit, objectType=%lu, operation=0x%08lX, groupId=%lu, ruleId=%lu.",
                (unsigned long)((operationInformation->ObjectType == *PsProcessType) ? 1UL : 2UL),
                (unsigned long)callbackOperationMask,
                (unsigned long)matchResult.groupId,
                (unsigned long)matchResult.ruleId);
        }
        else if (matchResult.action == KSWORD_ARK_RULE_ACTION_STRIP_ACCESS &&
                 desiredAccessPointer != NULL) {
            stripMask = kswordArkObjectBuildStripMask(operationInformation->ObjectType);
            accessBeforeRuleStrip = *desiredAccessPointer;
            strippedAccess = accessBeforeRuleStrip & (~stripMask);
            *desiredAccessPointer = strippedAccess;

            kswordArkCallbackLogFormat(
                "Warn",
                "Object access stripped, objectType=%lu, op=0x%08lX, desired=0x%08lX->0x%08lX, groupId=%lu, ruleId=%lu.",
                (unsigned long)((operationInformation->ObjectType == *PsProcessType) ? 1UL : 2UL),
                (unsigned long)callbackOperationMask,
                (unsigned long)accessBeforeRuleStrip,
                (unsigned long)strippedAccess,
                (unsigned long)matchResult.groupId,
                (unsigned long)matchResult.ruleId);
        }
    }

    // Publish only after all protection layers and general rules are processed; DesiredAccess is then the final access mask actually adopted by the object manager.
    if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT)) {
        KswordArkCallbackMonitorEventInput monitorInput;
        RtlZeroMemory(&monitorInput, sizeof(monitorInput));
        monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
        monitorInput.operation = callbackOperationMask;
        monitorInput.flags = KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_ACCESS_PRESENT;
        if (targetIsThreadObject) {
            monitorInput.flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_OBJECT_THREAD;
        }
        monitorInput.originatingProcessId = HandleToULong(PsGetCurrentProcessId());
        monitorInput.originatingThreadId = HandleToULong(PsGetCurrentThreadId());
        monitorInput.targetProcessId = targetProcessId;
        monitorInput.targetThreadId = targetThreadId;
        monitorInput.sessionId = kswordArkGetProcessSessionIdSafe(PsGetCurrentProcess());
        monitorInput.originalAccess = (ULONG)originalDesiredAccess;
        monitorInput.desiredAccess = desiredAccessPointer != NULL ? (ULONG)(*desiredAccessPointer) : 0UL;
        monitorInput.objectType = targetIsThreadObject ? 2UL : 1UL;
        monitorInput.processName = &initiatorPath;
        monitorInput.path = &targetPath;
        kswordArkCallbackMonitorPublish(&monitorInput);
    }
    return OB_PREOP_SUCCESS;
}

NTSTATUS
kswordArkObjectCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration[2];
    UNICODE_STRING altitudeText;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&callbackRegistration, sizeof(callbackRegistration));
    RtlZeroMemory(operationRegistration, sizeof(operationRegistration));
    RtlInitUnicodeString(&altitudeText, kGKswordArkObAltitude);

    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = kswordArkObjectPreOperation;
    operationRegistration[0].PostOperation = NULL;

    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations =
        OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = kswordArkObjectPreOperation;
    operationRegistration[1].PostOperation = NULL;

    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = RTL_NUMBER_OF(operationRegistration);
    callbackRegistration.RegistrationContext = runtime;
    callbackRegistration.Altitude = altitudeText;
    callbackRegistration.OperationRegistration = operationRegistration;

    status = ObRegisterCallbacks(&callbackRegistration, &runtime->obRegistrationHandle);
    // Process protection relies entirely on this handle callback: the registration result must be written back; otherwise,
    // R3 cannot distinguish between "no protection rules configured" and "handle callback failed to attach on this machine."
    kswordArkProcessProtectNoteObjectCallbackState(NT_SUCCESS(status) ? TRUE : FALSE, status);
    if (NT_SUCCESS(status)) {
        // The global runtime is not yet published during registration; logs must explicitly use the runtime version.
        kswordArkCallbackLogFrameForRuntime(
            runtime,
            "Info",
            "Object callbacks registered for Process/Thread.");
    }
    return status;
}

VOID
kswordArkObjectCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    if (runtime == NULL) {
        return;
    }

    if (runtime->obRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(runtime->obRegistrationHandle);
        runtime->obRegistrationHandle = NULL;
        kswordArkProcessProtectNoteObjectCallbackState(FALSE, STATUS_NOT_SUPPORTED);
        kswordArkCallbackLogFrame("Info", "Object callbacks unregistered.");
    }
}

/*++

Module Name:

    registry_callback.c

Abstract:

    Registry pre-operation callback registration and enforcement.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_internal.h"

static const WCHAR kGKswordArkRegistryAltitude[] = L"385201.5141";

static BOOLEAN
kswordArkResolveRegistryOperation(
    _In_ REG_NOTIFY_CLASS notifyClass,
    _In_ PVOID operationInfo,
    _Out_ ULONG* operationTypeOut,
    _Outptr_result_maybenull_ PVOID* keyObjectOut,
    _Outptr_result_maybenull_ PCUNICODE_STRING* completeNameOut,
    _Outptr_result_maybenull_ PCUNICODE_STRING* valueNameOut
    )
{
    if (operationTypeOut == NULL || keyObjectOut == NULL ||
        completeNameOut == NULL || valueNameOut == NULL || operationInfo == NULL) {
        return FALSE;
    }

    *operationTypeOut = 0U;
    *keyObjectOut = NULL;
    *completeNameOut = NULL;
    *valueNameOut = NULL;

    switch (notifyClass) {
    case RegNtPreCreateKeyEx:
    {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_CREATE_KEY;
        *completeNameOut = info->CompleteName;
        return TRUE;
    }
    case RegNtPreOpenKeyEx:
    {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_OPEN_KEY;
        *completeNameOut = info->CompleteName;
        return TRUE;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_DELETE_KEY;
        *keyObjectOut = info->Object;
        return TRUE;
    }
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_SET_VALUE;
        *keyObjectOut = info->Object;
        *valueNameOut = info->ValueName;
        return TRUE;
    }
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_DELETE_VALUE;
        *keyObjectOut = info->Object;
        *valueNameOut = info->ValueName;
        return TRUE;
    }
    case RegNtPreRenameKey:
    {
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_RENAME_KEY;
        *keyObjectOut = info->Object;
        *valueNameOut = info->NewName;
        return TRUE;
    }
    case RegNtPreSetInformationKey:
    {
        PREG_SET_INFORMATION_KEY_INFORMATION info = (PREG_SET_INFORMATION_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_SET_INFO;
        *keyObjectOut = info->Object;
        return TRUE;
    }
    case RegNtPreQueryValueKey:
    {
        PREG_QUERY_VALUE_KEY_INFORMATION info = (PREG_QUERY_VALUE_KEY_INFORMATION)operationInfo;
        *operationTypeOut = KSWORD_ARK_REG_OP_QUERY_VALUE;
        *keyObjectOut = info->Object;
        *valueNameOut = info->ValueName;
        return TRUE;
    }
    default:
        return FALSE;
    }
}

static VOID
kswordArkBuildRegistryTargetPath(
    _In_ KswordArkCallbackRuntime* runtime,
    _In_ ULONG operationType,
    _In_opt_ PVOID keyObject,
    _In_opt_ PCUNICODE_STRING completeName,
    _In_opt_ PCUNICODE_STRING valueName,
    _Out_writes_(targetChars) PWCHAR targetBuffer,
    _In_ USHORT targetChars
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PCUNICODE_STRING keyPath = NULL;
    WCHAR keyPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    WCHAR suffixBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_PATTERN_CHARS] = { 0 };

    if (targetBuffer == NULL || targetChars == 0U) {
        return;
    }
    targetBuffer[0] = L'\0';

    if (completeName != NULL && completeName->Buffer != NULL && completeName->Length > 0U) {
        kswordArkCopyUnicodeToFixedBuffer(completeName, targetBuffer, targetChars);
        return;
    }

    if (runtime != NULL && runtime->registryCookie.QuadPart != 0LL && keyObject != NULL) {
        status = CmCallbackGetKeyObjectIDEx(
            &runtime->registryCookie,
            keyObject,
            NULL,
            &keyPath,
            0U);
        if (NT_SUCCESS(status) && keyPath != NULL && keyPath->Buffer != NULL && keyPath->Length > 0U) {
            kswordArkCopyUnicodeToFixedBuffer(keyPath, keyPathBuffer, RTL_NUMBER_OF(keyPathBuffer));
            CmCallbackReleaseKeyObjectIDEx(keyPath);
        }
    }

    if (keyPathBuffer[0] != L'\0' && valueName != NULL && valueName->Buffer != NULL && valueName->Length > 0U) {
        kswordArkCopyUnicodeToFixedBuffer(valueName, suffixBuffer, RTL_NUMBER_OF(suffixBuffer));
        (VOID)RtlStringCbPrintfW(
            targetBuffer,
            targetChars * sizeof(WCHAR),
            L"%ws\\%ws",
            keyPathBuffer,
            suffixBuffer);
        return;
    }

    if (keyPathBuffer[0] != L'\0') {
        kswordArkCopyWideStringToFixedBuffer(keyPathBuffer, targetBuffer, targetChars);
        return;
    }

    (VOID)RtlStringCbPrintfW(
        targetBuffer,
        targetChars * sizeof(WCHAR),
        L"RegistryOperation=0x%08lX",
        (unsigned long)operationType);
}

NTSTATUS
kswordArkRegistryCallback(
    _In_opt_ PVOID callbackContext,
    _In_opt_ PVOID argument1,
    _In_opt_ PVOID argument2
    )
{
    KswordArkCallbackRuntime* runtime = (KswordArkCallbackRuntime*)callbackContext;
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    KswordArkCallbackMatchResult matchResult;
    KswordArkCallbackEventInput eventInput;
    ULONG decision = KSWORD_ARK_DECISION_ALLOW;
    ULONG operationType = 0U;
    PVOID keyObject = NULL;
    PCUNICODE_STRING completeName = NULL;
    PCUNICODE_STRING valueName = NULL;
    UNICODE_STRING initiatorPath = { 0 };
    UNICODE_STRING targetPath = { 0 };
    WCHAR initiatorPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_INITIATOR_CHARS] = { 0 };
    WCHAR targetPathBuffer[KSWORD_ARK_CALLBACK_EVENT_MAX_TARGET_CHARS] = { 0 };
    BOOLEAN initiatorPathUnavailable = TRUE;
    NTSTATUS matchStatus = STATUS_SUCCESS;
    NTSTATUS askStatus = STATUS_SUCCESS;

    if (runtime == NULL || argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    if (!kswordArkResolveRegistryOperation(
        notifyClass,
        argument2,
        &operationType,
        &keyObject,
        &completeName,
        &valueName)) {
        return STATUS_SUCCESS;
    }

    (VOID)kswordArkResolveProcessImagePath(
        PsGetCurrentProcess(),
        initiatorPathBuffer,
        RTL_NUMBER_OF(initiatorPathBuffer),
        &initiatorPathUnavailable);
    RtlInitUnicodeString(&initiatorPath, initiatorPathBuffer);

    kswordArkBuildRegistryTargetPath(
        runtime,
        operationType,
        keyObject,
        completeName,
        valueName,
        targetPathBuffer,
        RTL_NUMBER_OF(targetPathBuffer));
    RtlInitUnicodeString(&targetPath, targetPathBuffer);

    // Registry telemetry records only pre-operation context; rule results are still handled by the existing chain.
    if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY)) {
        KswordArkCallbackMonitorEventInput monitorInput;
        RtlZeroMemory(&monitorInput, sizeof(monitorInput));
        monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
        monitorInput.operation = operationType;
        monitorInput.originatingProcessId = HandleToULong(PsGetCurrentProcessId());
        monitorInput.originatingThreadId = HandleToULong(PsGetCurrentThreadId());
        monitorInput.sessionId = kswordArkGetProcessSessionIdSafe(PsGetCurrentProcess());
        monitorInput.processName = &initiatorPath;
        monitorInput.path = &targetPath;
        kswordArkCallbackMonitorPublish(&monitorInput);
    }

    matchStatus = kswordArkCallbackMatchRule(
        KSWORD_ARK_CALLBACK_TYPE_REGISTRY,
        operationType,
        &initiatorPath,
        &targetPath,
        &matchResult);
    if (!NT_SUCCESS(matchStatus) || !matchResult.matched) {
        return STATUS_SUCCESS;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_LOG_ONLY) {
        kswordArkCallbackLogFormat(
            "Info",
            "Registry callback log rule hit, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return STATUS_SUCCESS;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_DENY) {
        kswordArkCallbackLogFormat(
            "Warn",
            "Registry callback denied, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return STATUS_ACCESS_DENIED;
    }

    if (matchResult.action == KSWORD_ARK_RULE_ACTION_ALLOW) {
        kswordArkCallbackLogFormat(
            "Info",
            "Registry callback allow rule hit, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return STATUS_SUCCESS;
    }

    if (matchResult.action != KSWORD_ARK_RULE_ACTION_ASK_USER) {
        return STATUS_SUCCESS;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return (matchResult.askDefaultDecision == KSWORD_ARK_DECISION_DENY)
            ? STATUS_ACCESS_DENIED
            : STATUS_SUCCESS;
    }

    RtlZeroMemory(&eventInput, sizeof(eventInput));
    eventInput.callbackType = KSWORD_ARK_CALLBACK_TYPE_REGISTRY;
    eventInput.operationType = operationType;
    eventInput.originatingPid = HandleToULong(PsGetCurrentProcessId());
    eventInput.originatingTid = HandleToULong(PsGetCurrentThreadId());
    eventInput.sessionId = kswordArkGetProcessSessionIdSafe(PsGetCurrentProcess());
    eventInput.pathUnavailable = initiatorPathUnavailable ? 1UL : 0UL;
    eventInput.initiatorPath = initiatorPath;
    eventInput.targetPath = targetPath;
    eventInput.match = matchResult;

    decision = matchResult.askDefaultDecision;
    askStatus = kswordArkCallbackAskUserDecision(&eventInput, &decision);
    if (!NT_SUCCESS(askStatus)) {
        kswordArkCallbackLogFormat(
            "Warn",
            "Registry ask-user fallback used, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu, status=0x%08X.",
            (unsigned long)operationType,
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId,
            (unsigned int)askStatus);
    }

    if (decision == KSWORD_ARK_DECISION_DENY) {
        kswordArkCallbackLogFormat(
            "Warn",
            "Registry ask-user decision DENY, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
            (unsigned long)operationType,
            (unsigned long)HandleToULong(PsGetCurrentProcessId()),
            (unsigned long)matchResult.groupId,
            (unsigned long)matchResult.ruleId);
        return STATUS_ACCESS_DENIED;
    }

    kswordArkCallbackLogFormat(
        "Info",
        "Registry ask-user decision ALLOW, op=0x%08lX, pid=%lu, groupId=%lu, ruleId=%lu.",
        (unsigned long)operationType,
        (unsigned long)HandleToULong(PsGetCurrentProcessId()),
        (unsigned long)matchResult.groupId,
        (unsigned long)matchResult.ruleId);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkRegistryCallbackRegister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    UNICODE_STRING altitudeText;
    NTSTATUS status = STATUS_SUCCESS;
    WDFDRIVER driverHandle = WDF_NO_HANDLE;
    PDRIVER_OBJECT driverObject = NULL;

    if (runtime == NULL || runtime->device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    driverHandle = WdfDeviceGetDriver(runtime->device);
    if (driverHandle == WDF_NO_HANDLE) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    driverObject = WdfDriverWdmGetDriverObject(driverHandle);
    if (driverObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlInitUnicodeString(&altitudeText, kGKswordArkRegistryAltitude);
    runtime->registryCookie.QuadPart = 0LL;
    status = CmRegisterCallbackEx(
        kswordArkRegistryCallback,
        &altitudeText,
        driverObject,
        runtime,
        &runtime->registryCookie,
        NULL);
    if (NT_SUCCESS(status)) {
        // The global runtime is not yet published during registration; logs must explicitly use the runtime version.
        kswordArkCallbackLogFrameForRuntime(runtime, "Info", "Registry callback registered.");
    }
    return status;
}

VOID
kswordArkRegistryCallbackUnregister(
    _In_ KswordArkCallbackRuntime* runtime
    )
{
    if (runtime == NULL) {
        return;
    }

    if (runtime->registryCookie.QuadPart != 0LL) {
        (VOID)CmUnRegisterCallback(runtime->registryCookie);
        runtime->registryCookie.QuadPart = 0LL;
        kswordArkCallbackLogFrame("Info", "Registry callback unregistered.");
    }
}

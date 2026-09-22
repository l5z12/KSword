/*++

Module Name:

    redirect_registry.c

Abstract:

    Registry create/open redirection callback for KswordARK.

Environment:

    Kernel-mode Configuration Manager callback

--*/

#include "redirect_internal.h"
#include "ark/ark_push_lock.h"

static const WCHAR kGKswordArkRedirectRegistryAltitude[] = L"385201.6141";

typedef struct KswordArkRegCreateOpenView
{
    PUNICODE_STRING completeName;
    ACCESS_MASK desiredAccess;
} KswordArkRegCreateOpenView;

static BOOLEAN
kswordArkRedirectRegistryGetCreateOpenView(
    _In_ REG_NOTIFY_CLASS notifyClass,
    _In_ PVOID operationInfo,
    _Out_ KswordArkRegCreateOpenView* viewOut
    )
/*++

Routine Description:

    normalize create/open registry callback parameters into a unified view. Note: Currently only handles
    public RegNtPreCreateKeyEx and RegNtPreOpenKeyEx; other operations do not participate in path replacement.

Arguments:

    NotifyClass - Configuration Manager notification type.
    OperationInfo - Corresponding notification structure.
    ViewOut - Returned unified view.

Return Value:

    TRUE indicates redirection is attempted; FALSE indicates the notification is ignored.

--*/
{
    if (operationInfo == NULL || viewOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(viewOut, sizeof(*viewOut));

    if (notifyClass == RegNtPreCreateKeyEx) {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)operationInfo;
        viewOut->completeName = info->CompleteName;
        viewOut->desiredAccess = info->DesiredAccess;
        return TRUE;
    }
    if (notifyClass == RegNtPreOpenKeyEx) {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)operationInfo;
        viewOut->completeName = info->CompleteName;
        viewOut->desiredAccess = info->DesiredAccess;
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS
kswordArkRedirectRegistryOpenTarget(
    _In_ const KSWORD_ARK_REDIRECT_RULE* rule,
    _In_ ACCESS_MASK desiredAccess,
    _Out_ HANDLE* keyHandleOut
    )
/*++

Routine Description:

    Open the redirection target key. Note: Cm callbacks require the callback to return success and set ResultObject for
    the open to land on the replacement key; therefore, use OBJ_KERNEL_HANDLE for controlled opening of the target path.

Arguments:

    Rule - The matched registry redirection rule.
    DesiredAccess - The original request's desired access mask.
    KeyHandleOut: Returns the target key handle; the caller is responsible for calling ZwClose.

Return Value:

    ZwOpenKey returns a status or parameter error.

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING targetPath;

    if (rule == NULL || keyHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *keyHandleOut = NULL;

    RtlInitUnicodeString(&targetPath, rule->targetPath);
    if (targetPath.Buffer == NULL || targetPath.Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    if (desiredAccess == 0UL) {
        desiredAccess = KEY_READ;
    }
    return ZwOpenKey(
        keyHandleOut,
        desiredAccess,
        &objectAttributes);
}

NTSTATUS
kswordArkRedirectRegistryCallback(
    _In_opt_ PVOID callbackContext,
    _In_opt_ PVOID argument1,
    _In_opt_ PVOID argument2
    )
/*++

Routine Description:

    Handle registry create/open redirection. Note: Only open the target key and populate ResultObject
    when a rule matches, then return STATUS_CALLBACK_BYPASS to let the Configuration Manager use the
    substitute object; if no rule matches or the operation fails, leave the original request unchanged.

Arguments:

    CallbackContext - Redirect runtime.
    Argument1 - REG_NOTIFY_CLASS。
    Argument2 - Specific operation structure.

Return Value:

    STATUS_CALLBACK_BYPASS indicates the target has been replaced; otherwise return STATUS_SUCCESS.

--*/
{
    KswordArkRedirectRuntime* runtime = (KswordArkRedirectRuntime*)callbackContext;
    REG_NOTIFY_CLASS notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)argument1;
    KswordArkRegCreateOpenView view;
    KSWORD_ARK_REDIRECT_RULE matchedRule;
    HANDLE targetHandle = NULL;
    PVOID targetObject = NULL;
    ULONG processId = HandleToULong(PsGetCurrentProcessId());
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || argument2 == NULL) {
        return STATUS_SUCCESS;
    }
    if ((runtime->runtimeFlags & KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_ACTIVE) == 0UL) {
        return STATUS_SUCCESS;
    }
    if (!kswordArkRedirectRegistryGetCreateOpenView(notifyClass, argument2, &view)) {
        return STATUS_SUCCESS;
    }
    if (view.completeName == NULL || view.completeName->Buffer == NULL || view.completeName->Length == 0U) {
        return STATUS_SUCCESS;
    }

    kswordArkAcquirePushLockShared(&runtime->lock);
    status = kswordArkRedirectFindMatchLocked(
        runtime,
        KSWORD_ARK_REDIRECT_TYPE_REGISTRY,
        processId,
        view.completeName,
        &matchedRule);
    kswordArkReleasePushLockShared(&runtime->lock);
    if (!NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }

    status = kswordArkRedirectRegistryOpenTarget(
        &matchedRule,
        view.desiredAccess,
        &targetHandle);
    if (!NT_SUCCESS(status)) {
        kswordArkRedirectLogFormat(
            "Warn",
            "Registry redirect open-target failed, pid=%lu, ruleId=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned long)matchedRule.ruleId,
            (unsigned int)status);
        return STATUS_SUCCESS;
    }

    status = ObReferenceObjectByHandle(
        targetHandle,
        0,
        *CmKeyObjectType,
        KernelMode,
        &targetObject,
        NULL);
    ZwClose(targetHandle);
    if (!NT_SUCCESS(status) || targetObject == NULL) {
        kswordArkRedirectLogFormat(
            "Warn",
            "Registry redirect reference-target failed, pid=%lu, ruleId=%lu, status=0x%08X.",
            (unsigned long)processId,
            (unsigned long)matchedRule.ruleId,
            (unsigned int)status);
        return STATUS_SUCCESS;
    }

    if (notifyClass == RegNtPreCreateKeyEx) {
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)argument2;
        if (info->ResultObject != NULL) {
            *info->ResultObject = targetObject;
        }
        info->GrantedAccess = view.desiredAccess;
        if (info->Disposition != NULL) {
            *info->Disposition = REG_OPENED_EXISTING_KEY;
        }
    }
    else {
        PREG_OPEN_KEY_INFORMATION info = (PREG_OPEN_KEY_INFORMATION)argument2;
        if (info->ResultObject != NULL) {
            *info->ResultObject = targetObject;
        }
        info->GrantedAccess = view.desiredAccess;
    }

    InterlockedIncrement64(&runtime->registryRedirectHits);
    kswordArkRedirectLogFormat(
        "Info",
        "Registry redirect applied, pid=%lu, ruleId=%lu.",
        (unsigned long)processId,
        (unsigned long)matchedRule.ruleId);
    return STATUS_CALLBACK_BYPASS;
}

NTSTATUS
kswordArkRedirectRegistryRegister(
    _In_ KswordArkRedirectRuntime* runtime,
    _In_ PDRIVER_OBJECT driverObject
    )
/*++

Routine Description:

    Register an independent registry redirection callback. Note: This callback uses a different altitude than the
    custom callback rule module to avoid conflicts when both sessions attempt to modify the same callback file.

Arguments:

    Runtime - Redirect runtime.
    DriverObject.

Return Value:

    Return status from CmRegisterCallbackEx.

--*/
{
    UNICODE_STRING altitudeText;
    NTSTATUS status = STATUS_SUCCESS;

    if (runtime == NULL || driverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&altitudeText, kGKswordArkRedirectRegistryAltitude);
    runtime->registryCookie.QuadPart = 0LL;
    status = CmRegisterCallbackEx(
        kswordArkRedirectRegistryCallback,
        &altitudeText,
        driverObject,
        runtime,
        &runtime->registryCookie,
        NULL);
    return status;
}

VOID
kswordArkRedirectRegistryUnregister(
    _In_ KswordArkRedirectRuntime* runtime
    )
/*++

Routine Description:

    Unregister the registry redirection callback. Note: Call CmUnRegisterCallback only when
    Cookie is non-zero, and clear the REGISTRY_HOOKED flag to ensure unloading idempotency.

Arguments:

    Runtime - Redirect runtime.

Return Value:

    None. This function has no return value.

--*/
{
    if (runtime == NULL) {
        return;
    }

    if (runtime->registryCookie.QuadPart != 0LL) {
        (VOID)CmUnRegisterCallback(runtime->registryCookie);
        runtime->registryCookie.QuadPart = 0LL;
    }
    runtime->runtimeFlags &= ~KSWORD_ARK_REDIRECT_RUNTIME_REGISTRY_HOOKED;
}

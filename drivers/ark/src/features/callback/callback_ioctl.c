/*++

Module Name:

    callback_ioctl.c

Abstract:

    IOCTL handlers for KswordARK callback interception operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkCallbackIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one callback-handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
kswordArkCallbackIoctlSetRulesHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_CALLBACK_RULES by delegating blob validation and
    activation to the existing callback rule module.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Rule blob length supplied by user mode.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives callback module completion bytes.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlSetRules.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_CALLBACK_SET_RULES;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkCallbackIoctlLog(device, "Warn", "Callback rules denied by safety policy, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkCallbackIoctlSetRules(request, inputBufferLength, bytesReturned);
    if (NT_SUCCESS(status)) {
        (void)kswordArkDriverEnqueueLogFrame(device, "Info", "Callback rules applied.");
    }
    else {
        kswordArkCallbackIoctlLog(device, "Error", "Callback rules apply failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
kswordArkCallbackIoctlSetMinifilterBypassPidsHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_MINIFILTER_BYPASS_PIDS. This mutates callback
    behavior because allowlisted PIDs bypass minifilter rules, redirect and file
    monitor capture, so it reuses the callback-set safety policy gate.

Arguments:

    Device - WDF device used for safety evaluation and audit logging.
    Request - Current IOCTL request.
    InputBufferLength - Whitelist request packet length.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives callback module completion bytes.

Return Value:

    NTSTATUS from safety evaluation or kswordArkCallbackIoctlSetMinifilterBypassPids.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_CALLBACK_SET_RULES;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkCallbackIoctlLog(device, "Warn", "Minifilter bypass PID update denied by safety policy, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkCallbackIoctlSetMinifilterBypassPids(
        request,
        inputBufferLength,
        bytesReturned);
    if (NT_SUCCESS(status)) {
        (void)kswordArkDriverEnqueueLogFrame(device, "Info", "Minifilter bypass PID whitelist applied.");
    }
    else {
        kswordArkCallbackIoctlLog(device, "Warn", "Minifilter bypass PID update failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
kswordArkCallbackIoctlQueryMinifilterBypassPidsHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_MINIFILTER_BYPASS_PIDS. The operation is
    read-only and returns the current fixed-size whitelist response packet.

Arguments:

    Device - WDF device used for diagnostic logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; unused for this IOCTL.
    OutputBufferLength - Whitelist response buffer length.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlQueryMinifilterBypassPids.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(inputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkCallbackIoctlQueryMinifilterBypassPids(
        request,
        outputBufferLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Minifilter bypass PID query failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
kswordArkCallbackIoctlGetRuntimeStateHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_GET_CALLBACK_RUNTIME_STATE by forwarding the output
    request to the callback runtime module.

Arguments:

    Device - WDF device, currently unused by this pass-through handler.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; unused for this IOCTL.
    OutputBufferLength - Runtime state output buffer length.
    BytesReturned - Receives sizeof(runtime-state) on success.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlGetRuntimeState.

--*/
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    return kswordArkCallbackIoctlGetRuntimeState(request, outputBufferLength, bytesReturned);
}

NTSTATUS
kswordArkCallbackIoctlWaitEventHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_WAIT_CALLBACK_EVENT. STATUS_PENDING is intentionally
    returned to dispatch so the request is not completed twice.

Arguments:

    Device - WDF device, currently unused by this pass-through handler.
    Request - Current IOCTL request.
    InputBufferLength - Wait request length, validated by callback module.
    OutputBufferLength - Event packet output buffer length.
    BytesReturned - Receives bytes when completed synchronously.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlWaitEvent, including STATUS_PENDING.

--*/
{
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    return kswordArkCallbackIoctlWaitEvent(request, outputBufferLength, bytesReturned);
}

NTSTATUS
kswordArkCallbackIoctlAnswerEventHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ANSWER_CALLBACK_EVENT by forwarding the answer packet
    to the pending-decision runtime.

Arguments:

    Device - WDF device used for failure logging.
    Request - Current IOCTL request.
    InputBufferLength - Answer request length.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives callback module completion bytes.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlAnswerEvent.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkCallbackIoctlAnswerEvent(request, inputBufferLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Callback answer failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}
NTSTATUS
kswordArkCallbackIoctlCancelAllPendingHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_CANCEL_ALL_PENDING_DECISIONS. No input or output
    buffer is required; the callback runtime owns the cancellation logic.

Arguments:

    Device - WDF device used for failure logging.
    Request - Current IOCTL request, intentionally unused.
    InputBufferLength - Caller input length, intentionally unused.
    OutputBufferLength - Caller output length, intentionally unused.
    BytesReturned - Receives callback module completion bytes.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlCancelAllPending.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(request);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_CALLBACK_CANCEL_PENDING;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkCallbackIoctlLog(device, "Warn", "Cancel-all pending decisions denied by safety policy, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkCallbackIoctlCancelAllPending(bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Cancel-all pending decisions failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
kswordArkCallbackIoctlRemoveExternalCallbackHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK. The handler keeps the
    explicit FILE_WRITE_ACCESS validation before calling the remove feature.

Arguments:

    Device - WDF device used for audit logging.
    Request - Current IOCTL request.
    InputBufferLength - Remove request length.
    OutputBufferLength - Remove response buffer length.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from access validation or kswordArkCallbackIoctlRemoveExternalCallback.

--*/
{
    NTSTATUS status;

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_CALLBACK_REMOVE_EXTERNAL;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkCallbackIoctlLog(device, "Warn", "Remove external callback denied by safety policy, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Remove external callback denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkCallbackIoctlRemoveExternalCallback(request, inputBufferLength, outputBufferLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Remove external callback failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
kswordArkCallbackIoctlRemoveExternalCallbackExHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX. The EX protocol carries
    enumeration identity, trust flags and the requested remove behavior. This
    dispatch layer still enforces the same write-access and safety-policy gates
    as the legacy mutating remove IOCTL.

Arguments:

    Device - WDF device used for audit logging.
    Request - Current IOCTL request.
    InputBufferLength - EX remove request length.
    OutputBufferLength - EX remove response buffer length.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from access validation or kswordArkCallbackIoctlRemoveExternalCallbackEx.

--*/
{
    NTSTATUS status;

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_CALLBACK_REMOVE_EXTERNAL;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkCallbackIoctlLog(device, "Warn", "Remove external callback EX denied by safety policy, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Remove external callback EX denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkCallbackIoctlRemoveExternalCallbackEx(request, inputBufferLength, outputBufferLength, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(device, "Warn", "Remove external callback EX failed, status=0x%08X.", (unsigned int)status);
    }
    return status;
}

NTSTATUS
kswordArkCallbackIoctlEnumCallbacksHandler(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_CALLBACKS. The operation is read-only and keeps
    all business traversal inside the callback feature module.

Arguments:

    Device - WDF device used for diagnostic logging.
    Request - Current IOCTL request.
    InputBufferLength - Enumeration request length.
    OutputBufferLength - Enumeration response buffer length.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from kswordArkCallbackIoctlEnumCallbacks.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkCallbackIoctlEnumCallbacks(
        request,
        inputBufferLength,
        outputBufferLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkCallbackIoctlLog(
            device,
            "Warn",
            "Callback enumeration failed, status=0x%08X.",
            (unsigned int)status);
    }
    return status;
}

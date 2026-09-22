/*++

Module Name:

    process_ioctl.c

Abstract:

    IOCTL handlers for KswordARK process operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#ifndef STATUS_PROCESS_IS_TERMINATING
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xC000010AL)
#endif

#define KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY))

/* Note: Older termination requests contain only PID and exitStatus; the new driver continues to accept this fixed prefix. */
#define KSWORD_ARK_TERMINATE_REQUEST_V1_SIZE \
    FIELD_OFFSET(KSWORD_ARK_TERMINATE_PROCESS_REQUEST, expectedCreateTime100ns)

/* Note: For legacy special flag requests, copy up to flags; for new fields, copy selectively based on actual input length. */
#define KSWORD_ARK_PROCESS_SPECIAL_REQUEST_V1_SIZE \
    FIELD_OFFSET(KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST, expectedCreateTime100ns)

#define KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_INJECT_PROCESS_REQUEST, payload)

#define KSWORD_ARK_PROCESS_INJECT_IOCTL_POOL_TAG 'jIsK'

static VOID
kswordArkProcessIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one process-handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string such as Info/Warn/Error.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are intentionally ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(
        logMessage,
        sizeof(logMessage),
        formatText,
        arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
kswordArkProcessIoctlTerminate(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_TERMINATE_PROCESS. The handler validates the fixed
    request and forwards process termination to the existing process feature.

Arguments:

    Device - WDF device used for logging and feature context.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length; used by WDF retrieval.
    OutputBufferLength - Caller-supplied output length; unused for this IOCTL.
    BytesReturned - Receives sizeof(request) on success and zero on failure.

Return Value:

    NTSTATUS from validation or kswordArkDriverTerminateProcessByPid.

--*/
{
    KSWORD_ARK_TERMINATE_PROCESS_REQUEST* terminateRequest = NULL;
    KSWORD_ARK_TERMINATE_PROCESS_REQUEST terminateRequestValue;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_TERMINATE_REQUEST_V1_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 terminate ioctl: input buffer invalid, status=0x%08X", (unsigned int)status);
        return status;
    }

    terminateRequest = (KSWORD_ARK_TERMINATE_PROCESS_REQUEST*)inputBuffer;
    /* Note: Zero out first, then copy according to the actual length; the old request naturally gets expectedCreateTime100ns=0. */
    RtlZeroMemory(&terminateRequestValue, sizeof(terminateRequestValue));
    RtlCopyMemory(
        &terminateRequestValue,
        terminateRequest,
        min(actualInputLength, sizeof(terminateRequestValue)));
    status = kswordArkValidateUserPid((ULONG)terminateRequestValue.processId);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 terminate ioctl: pid=%lu rejected.", (unsigned long)terminateRequestValue.processId);
        return status;
    }
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_TERMINATE;
        safetyContext.targetProcessId = (ULONG)terminateRequestValue.processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkProcessIoctlLog(device, "Warn", "R0 terminate denied by safety policy: pid=%lu, status=0x%08X.", (unsigned long)terminateRequestValue.processId, (unsigned int)status);
            return status;
        }
    }

    kswordArkProcessIoctlLog(
        device,
        "Info",
        "R0 terminate ioctl: pid=%lu, exit=0x%08X, expectedCreate=%I64u.",
        (unsigned long)terminateRequestValue.processId,
        (unsigned int)terminateRequestValue.exitStatus,
        terminateRequestValue.expectedCreateTime100ns);
    status = kswordArkDriverTerminateProcessByPid(
        device,
        (ULONG)terminateRequestValue.processId,
        (NTSTATUS)terminateRequestValue.exitStatus,
        terminateRequestValue.expectedCreateTime100ns);
    if (NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Info", "R0 terminate success: pid=%lu.", (unsigned long)terminateRequestValue.processId);
        *bytesReturned = actualInputLength;
    }
    else if (status == STATUS_PROCESS_IS_TERMINATING) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 terminate pending: pid=%lu, status=0x%08X (still terminating).", (unsigned long)terminateRequestValue.processId, (unsigned int)status);
    }
    else {
        kswordArkProcessIoctlLog(device, "Error", "R0 terminate failed: pid=%lu, status=0x%08X.", (unsigned long)terminateRequestValue.processId, (unsigned int)status);
    }

    return status;
}

NTSTATUS
kswordArkProcessIoctlSuspend(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SUSPEND_PROCESS with the same request and completion
    semantics as the previous dispatch switch case.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; used by WDF retrieval.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives sizeof(request) on success and zero on failure.

Return Value:

    NTSTATUS from validation or kswordArkDriverSuspendProcessByPid.

--*/
{
    KSWORD_ARK_SUSPEND_PROCESS_REQUEST* suspendRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(KSWORD_ARK_SUSPEND_PROCESS_REQUEST), &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 suspend ioctl: input buffer invalid, status=0x%08X", (unsigned int)status);
        return status;
    }

    suspendRequest = (KSWORD_ARK_SUSPEND_PROCESS_REQUEST*)inputBuffer;
    status = kswordArkValidateUserPid((ULONG)suspendRequest->processId);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 suspend ioctl: pid=%lu rejected.", (unsigned long)suspendRequest->processId);
        return status;
    }
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND;
        safetyContext.targetProcessId = (ULONG)suspendRequest->processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkProcessIoctlLog(device, "Warn", "R0 suspend denied by safety policy: pid=%lu, status=0x%08X.", (unsigned long)suspendRequest->processId, (unsigned int)status);
            return status;
        }
    }

    kswordArkProcessIoctlLog(device, "Info", "R0 suspend ioctl: pid=%lu.", (unsigned long)suspendRequest->processId);
    status = kswordArkDriverSuspendProcessByPid((ULONG)suspendRequest->processId);
    if (NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Info", "R0 suspend success: pid=%lu.", (unsigned long)suspendRequest->processId);
        *bytesReturned = sizeof(KSWORD_ARK_SUSPEND_PROCESS_REQUEST);
    }
    else {
        kswordArkProcessIoctlLog(device, "Error", "R0 suspend failed: pid=%lu, status=0x%08X.", (unsigned long)suspendRequest->processId, (unsigned int)status);
    }

    return status;
}

NTSTATUS
kswordArkProcessIoctlResume(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_RESUME_PROCESS.
    Note: Symmetric line-by-line with the suspend handler. The security policy deliberately reuses
    KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND instead of adding a new operation code: resume is the inverse of
    suspend; if it can be suspended, it must be resumable. Giving it a separate switch that can be turned off
    independently would create a state where processes can be suspended but not resumed, requiring a reboot to exit.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; used by WDF retrieval.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives sizeof(request) on success and zero on failure.

Return Value:

    NTSTATUS from validation or kswordArkDriverResumeProcessByPid.

--*/
{
    KSWORD_ARK_RESUME_PROCESS_REQUEST* resumeRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(KSWORD_ARK_RESUME_PROCESS_REQUEST), &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 resume ioctl: input buffer invalid, status=0x%08X", (unsigned int)status);
        return status;
    }

    resumeRequest = (KSWORD_ARK_RESUME_PROCESS_REQUEST*)inputBuffer;
    status = kswordArkValidateUserPid((ULONG)resumeRequest->processId);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 resume ioctl: pid=%lu rejected.", (unsigned long)resumeRequest->processId);
        return status;
    }
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SUSPEND;
        safetyContext.targetProcessId = (ULONG)resumeRequest->processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkProcessIoctlLog(device, "Warn", "R0 resume denied by safety policy: pid=%lu, status=0x%08X.", (unsigned long)resumeRequest->processId, (unsigned int)status);
            return status;
        }
    }

    kswordArkProcessIoctlLog(device, "Info", "R0 resume ioctl: pid=%lu.", (unsigned long)resumeRequest->processId);
    status = kswordArkDriverResumeProcessByPid((ULONG)resumeRequest->processId);
    if (NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Info", "R0 resume success: pid=%lu.", (unsigned long)resumeRequest->processId);
        *bytesReturned = sizeof(KSWORD_ARK_RESUME_PROCESS_REQUEST);
    }
    else {
        kswordArkProcessIoctlLog(device, "Error", "R0 resume failed: pid=%lu, status=0x%08X.", (unsigned long)resumeRequest->processId, (unsigned int)status);
    }

    return status;
}

NTSTATUS
kswordArkProcessIoctlSetPplLevel(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_PPL_LEVEL by forwarding the requested protection
    byte to the process feature after basic PID validation.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; used by WDF retrieval.
    OutputBufferLength - Caller output length; unused for this IOCTL.
    BytesReturned - Receives sizeof(request) on success and zero on failure.

Return Value:

    NTSTATUS from validation or kswordArkDriverSetProcessPplLevelByPid.

--*/
{
    KSWORD_ARK_SET_PPL_LEVEL_REQUEST* setPplRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(KSWORD_ARK_SET_PPL_LEVEL_REQUEST), &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 set PPL ioctl: input buffer invalid, status=0x%08X", (unsigned int)status);
        return status;
    }

    setPplRequest = (KSWORD_ARK_SET_PPL_LEVEL_REQUEST*)inputBuffer;
    status = kswordArkValidateUserPid((ULONG)setPplRequest->processId);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 set PPL ioctl: pid=%lu rejected.", (unsigned long)setPplRequest->processId);
        return status;
    }
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
        safetyContext.targetProcessId = (ULONG)setPplRequest->processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkProcessIoctlLog(device, "Warn", "R0 set PPL denied by safety policy: pid=%lu, status=0x%08X.", (unsigned long)setPplRequest->processId, (unsigned int)status);
            return status;
        }
    }

    kswordArkProcessIoctlLog(device, "Info", "R0 set PPL ioctl: pid=%lu, level=0x%02X.", (unsigned long)setPplRequest->processId, (unsigned int)setPplRequest->protectionLevel);
    status = kswordArkDriverSetProcessPplLevelByPid((ULONG)setPplRequest->processId, (UCHAR)setPplRequest->protectionLevel);
    if (NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Info", "R0 set PPL success: pid=%lu, level=0x%02X.", (unsigned long)setPplRequest->processId, (unsigned int)setPplRequest->protectionLevel);
        *bytesReturned = sizeof(KSWORD_ARK_SET_PPL_LEVEL_REQUEST);
    }
    else {
        kswordArkProcessIoctlLog(device, "Error", "R0 set PPL failed: pid=%lu, level=0x%02X, status=0x%08X.", (unsigned long)setPplRequest->processId, (unsigned int)setPplRequest->protectionLevel, (unsigned int)status);
    }

    return status;
}

NTSTATUS
kswordArkProcessIoctlSetIntegrity(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY. Note: the handler is responsible
    only for access validation, fixed packet parsing, and safety policy; the backend
    first sets TokenIntegrityLevel via Zw* token APIs. If the API is rejected, perform
    a fallback by overwriting the Token SID in place after validating DynData/PDB.

Arguments:

    Device - WDF device used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length; validated through WDF helper.
    OutputBufferLength - Output length; validated through WDF helper.
    BytesReturned - Receives sizeof(response) when output is available.

Return Value:

    STATUS_SUCCESS once the response packet is valid. Per-target operation
    status is reported in response->status/lastStatus.

--*/
{
    KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST* integrityRequest = NULL;
    KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST integrityRequestSnapshot;
    KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE* integrityResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 process-integrity denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process-integrity ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED can expose the same system buffer for input and output.
     * Snapshot the request before the response buffer is zeroed; otherwise
     * clearing the response aliases and erases processId/integrityRid.
     */
    integrityRequest = (KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST*)inputBuffer;
    RtlCopyMemory(&integrityRequestSnapshot, integrityRequest, sizeof(integrityRequestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process-integrity ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    integrityResponse = (KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE*)outputBuffer;
    RtlZeroMemory(integrityResponse, sizeof(*integrityResponse));
    integrityResponse->size = sizeof(*integrityResponse);
    integrityResponse->version = KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION;
    integrityResponse->processId = integrityRequestSnapshot.processId;
    integrityResponse->integrityRid = integrityRequestSnapshot.integrityRid;
    integrityResponse->status = KSWORD_ARK_PROCESS_INTEGRITY_STATUS_FAILED;
    integrityResponse->lastStatus = STATUS_INVALID_PARAMETER;
    *bytesReturned = sizeof(*integrityResponse);

    if (integrityRequestSnapshot.size != sizeof(integrityRequestSnapshot) ||
        integrityRequestSnapshot.version != KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION) {
        kswordArkProcessIoctlLog(
            device,
            "Warn",
            "R0 process-integrity ioctl: protocol rejected, size=%lu, version=%lu.",
            (unsigned long)integrityRequestSnapshot.size,
            (unsigned long)integrityRequestSnapshot.version);
        return STATUS_SUCCESS;
    }

    status = kswordArkValidateUserPid((ULONG)integrityRequestSnapshot.processId);
    if (!NT_SUCCESS(status)) {
        integrityResponse->lastStatus = status;
        kswordArkProcessIoctlLog(device, "Warn", "R0 process-integrity ioctl: pid=%lu rejected.", (unsigned long)integrityRequestSnapshot.processId);
        return STATUS_SUCCESS;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
        safetyContext.targetProcessId = (ULONG)integrityRequestSnapshot.processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            integrityResponse->lastStatus = status;
            kswordArkProcessIoctlLog(device, "Warn", "R0 process-integrity denied by safety policy: pid=%lu, status=0x%08X.", (unsigned long)integrityRequestSnapshot.processId, (unsigned int)status);
            return STATUS_SUCCESS;
        }
    }

    operationStatus = kswordArkDriverSetProcessIntegrityByPid(
        (ULONG)integrityRequestSnapshot.processId,
        (ULONG)integrityRequestSnapshot.integrityRid);
    integrityResponse->lastStatus = operationStatus;
    integrityResponse->status = NT_SUCCESS(operationStatus)
        ? KSWORD_ARK_PROCESS_INTEGRITY_STATUS_APPLIED
        : KSWORD_ARK_PROCESS_INTEGRITY_STATUS_FAILED;

    {
        CHAR diagnosticText[512] = { 0 };
        if (NT_SUCCESS(kswordArkDriverDescribeLastProcessIntegrityAttempt(
            diagnosticText,
            sizeof(diagnosticText)))) {
            kswordArkProcessIoctlLog(
                device,
                NT_SUCCESS(operationStatus) ? "Info" : "Warn",
                "R0 process-integrity detail: %s",
                diagnosticText);
        }
    }

    if (NT_SUCCESS(operationStatus)) {
        kswordArkProcessIoctlLog(
            device,
            "Info",
            "R0 process-integrity success: pid=%lu, rid=0x%08lX.",
            (unsigned long)integrityRequestSnapshot.processId,
            (unsigned long)integrityRequestSnapshot.integrityRid);
    }
    else {
        kswordArkProcessIoctlLog(
            device,
            "Error",
            "R0 process-integrity failed: pid=%lu, rid=0x%08lX, status=0x%08X.",
            (unsigned long)integrityRequestSnapshot.processId,
            (unsigned long)integrityRequestSnapshot.integrityRid,
            (unsigned int)operationStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkProcessIoctlTokenPrivileges(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle bounded process-token privilege query and adjustment requests. The
    handler owns protocol/access/safety validation while the feature backend
    owns all process and token operations.

Arguments:

    Device - WDF device used for logging and mutation safety evaluation.
    Request - Current METHOD_BUFFERED request.
    InputBufferLength - Caller input length, validated by the WDF helper.
    OutputBufferLength - Caller output length, validated by the WDF helper.
    BytesReturned - Receives the fixed response size after protocol validation.

Return Value:

    Buffer/protocol validation status. A valid response returns STATUS_SUCCESS
    and carries per-operation status in response->status/lastStatus.

--*/
{
    KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST* tokenRequest = NULL;
    KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE* tokenResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG processId = 0UL;
    ULONG operation = 0UL;
    ULONG flags = 0UL;
    ULONG entryCount = 0UL;
    ULONG entryIndex = 0UL;
    ULONG appliedCount = 0UL;
    ULONG failedIndex = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE;
    ULONG64 expectedCreateTime100ns = 0ULL;
    ULONG64 processCreateTime100ns = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(
            device,
            "Warn",
            "R0 process-token privilege denied: write access required, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(
            device,
            "Error",
            "R0 process-token privilege input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(
            device,
            "Error",
            "R0 process-token privilege output invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    tokenRequest = (KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST*)inputBuffer;
    if (tokenRequest->size != sizeof(*tokenRequest) ||
        tokenRequest->version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
        (tokenRequest->operation != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY &&
         tokenRequest->operation != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST) ||
        tokenRequest->entryCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
        (tokenRequest->flags & ~(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED |
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_ALLOW_REMOVE)) != 0UL) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 process-token privilege protocol rejected.");
        return STATUS_INVALID_PARAMETER;
    }

    processId = tokenRequest->processId;
    operation = tokenRequest->operation;
    flags = tokenRequest->flags;
    entryCount = tokenRequest->entryCount;
    expectedCreateTime100ns = tokenRequest->expectedCreateTime100ns;

    status = kswordArkValidateUserPid(processId);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(
            device,
            "Warn",
            "R0 process-token privilege pid rejected: pid=%lu.",
            (unsigned long)processId);
        return status;
    }

    if (operation == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY && entryCount != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (operation == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST) {
        if (entryCount == 0UL || expectedCreateTime100ns == 0ULL ||
            (flags & KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED) == 0UL ||
            tokenRequest->confirmationToken != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_CONFIRMATION_TOKEN) {
            return STATUS_ACCESS_DENIED;
        }
        for (entryIndex = 0UL; entryIndex < entryCount; ++entryIndex) {
            const ULONG kRequestedAction = tokenRequest->entries[entryIndex].action;
            if (kRequestedAction != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE &&
                kRequestedAction != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE &&
                kRequestedAction != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE) {
                return STATUS_INVALID_PARAMETER;
            }
            if (kRequestedAction == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE &&
                (flags & KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_ALLOW_REMOVE) == 0UL) {
                return STATUS_ACCESS_DENIED;
            }
        }

        {
            KswordArkSafetyContext safetyContext;
            RtlZeroMemory(&safetyContext, sizeof(safetyContext));
            safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
            safetyContext.targetProcessId = processId;
            safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
            status = kswordArkSafetyEvaluate(device, &safetyContext);
            if (!NT_SUCCESS(status)) {
                kswordArkProcessIoctlLog(
                    device,
                    "Warn",
                    "R0 process-token privilege adjustment denied by safety policy: pid=%lu, status=0x%08X.",
                    (unsigned long)processId,
                    (unsigned int)status);
                return status;
            }
        }

        operationStatus = kswordArkDriverAdjustProcessTokenPrivileges(
            processId,
            expectedCreateTime100ns,
            tokenRequest->entries,
            entryCount,
            &appliedCount,
            &failedIndex,
            &processCreateTime100ns);
    }

    tokenResponse = (KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE*)outputBuffer;
    RtlZeroMemory(tokenResponse, sizeof(*tokenResponse));
    tokenResponse->size = sizeof(*tokenResponse);
    tokenResponse->version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
    tokenResponse->operation = operation;
    tokenResponse->processId = processId;
    tokenResponse->failedIndex = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE;
    *bytesReturned = sizeof(*tokenResponse);

    if (operation == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY) {
        operationStatus = kswordArkDriverQueryProcessTokenPrivileges(
            processId,
            expectedCreateTime100ns,
            tokenResponse);
        tokenResponse->status = operationStatus == STATUS_SUCCESS
            ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
            : (operationStatus == STATUS_BUFFER_OVERFLOW
                ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL
                : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED);
    }
    else {
        tokenResponse->requestedCount = entryCount;
        tokenResponse->appliedCount = appliedCount;
        tokenResponse->failedIndex = failedIndex;
        tokenResponse->processCreateTime100ns = processCreateTime100ns;
        tokenResponse->status = operationStatus == STATUS_SUCCESS && appliedCount == entryCount
            ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
            : (appliedCount != 0UL
                ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL
                : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED);
    }
    tokenResponse->lastStatus = operationStatus;

    kswordArkProcessIoctlLog(
        device,
        tokenResponse->status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ? "Info" : "Warn",
        "R0 process-token privilege completed: operation=%lu, pid=%lu, rows=%lu, applied=%lu, status=0x%08X.",
        (unsigned long)operation,
        (unsigned long)processId,
        (unsigned long)tokenResponse->entryCount,
        (unsigned long)tokenResponse->appliedCount,
        (unsigned int)operationStatus);
    return STATUS_SUCCESS;
}
NTSTATUS
kswordArkProcessIoctlEnumProcess(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_PROCESS. Optional input keeps the old default
    scan-CID-table behavior; output parsing and feature call remain unchanged.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Supplied input bytes; shorter input selects defaults.
    OutputBufferLength - Supplied output bytes; checked by WDF output retrieval.
    BytesReturned - Receives the feature-written response byte count.

Return Value:

    NTSTATUS from buffer retrieval or kswordArkDriverEnumerateProcesses.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_PROCESS_REQUEST requestSnapshot = { 0 };
    KSWORD_ARK_ENUM_PROCESS_REQUEST defaultRequest = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_ENUM_PROCESS_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 enum-process ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        /* Preserve METHOD_BUFFERED input before output retrieval exposes the shared buffer. */
        RtlCopyMemory(
            &requestSnapshot,
            inputBuffer,
            sizeof(requestSnapshot));
        enumRequest = &requestSnapshot;
    }
    else {
        enumRequest = &defaultRequest;
        enumRequest->flags = KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE;
        enumRequest->startPid = 0UL;
        enumRequest->endPid = 0UL;
        enumRequest->reserved = 0UL;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(request, KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE, &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 enum-process ioctl: output buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateProcesses(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 enum-process failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_ENUM_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_PROCESS_RESPONSE* responseHeader = (KSWORD_ARK_ENUM_PROCESS_RESPONSE*)outputBuffer;
        kswordArkProcessIoctlLog(
            device,
            "Info",
            "R0 enum-process success: total=%lu, returned=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            *bytesReturned);
    }
    else {
        kswordArkProcessIoctlLog(device, "Warn", "R0 enum-process success: outBytes=%Iu (header partial).", *bytesReturned);
    }

    return status;
}

NTSTATUS
kswordArkProcessIoctlSetVisibility(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY. Note: This IOCTL performs recoverable unlink/relink
    of ActiveProcessLinks managed by Ksword; the handler is responsible for write access, safety
    policy, and fixed packet validation; the backend does not accept kernel addresses passed from R3.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must include the fixed request.
    OutputBufferLength: Output length; must accommodate the fixed response.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST* visibilityRequest = NULL;
    KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE* visibilityResponse = NULL;
    KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST visibilityRequestValue;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG visibilityStatus = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
    ULONG hiddenCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 process visibility denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process visibility ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process visibility ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    visibilityRequest = (KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST*)inputBuffer;
    RtlZeroMemory(&visibilityRequestValue, sizeof(visibilityRequestValue));
    RtlCopyMemory(&visibilityRequestValue, visibilityRequest, sizeof(visibilityRequestValue));
    visibilityResponse = (KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE*)outputBuffer;
    RtlZeroMemory(visibilityResponse, sizeof(*visibilityResponse));
    visibilityResponse->version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
    visibilityResponse->processId = visibilityRequestValue.processId;

    if (visibilityRequestValue.action == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE) {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.targetProcessId = (ULONG)visibilityRequestValue.processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            visibilityResponse->status = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
            visibilityResponse->hiddenCount = 0UL;
            visibilityResponse->lastStatus = status;
            *bytesReturned = sizeof(*visibilityResponse);
            kswordArkProcessIoctlLog(
                device,
                "Warn",
                "R0 process visibility denied by safety policy: pid=%lu, action=%lu, status=0x%08X.",
                (unsigned long)visibilityRequestValue.processId,
                (unsigned long)visibilityRequestValue.action,
                (unsigned int)status);
            return status;
        }
    }

    status = kswordArkDriverSetProcessVisibility(
        (ULONG)visibilityRequestValue.processId,
        (ULONG)visibilityRequestValue.action,
        (ULONG)visibilityRequestValue.flags,
        &visibilityStatus,
        &hiddenCount);

    visibilityResponse->status = visibilityStatus;
    visibilityResponse->hiddenCount = hiddenCount;
    visibilityResponse->lastStatus = status;
    *bytesReturned = sizeof(*visibilityResponse);

    if (NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(
            device,
            "Info",
            "R0 process visibility updated: pid=%lu, action=%lu, flags=0x%08lX, status=%lu, hiddenCount=%lu.",
            (unsigned long)visibilityRequestValue.processId,
            (unsigned long)visibilityRequestValue.action,
            (unsigned long)visibilityRequestValue.flags,
            (unsigned long)visibilityStatus,
            (unsigned long)hiddenCount);
    }
    else {
        kswordArkProcessIoctlLog(
            device,
            "Error",
            "R0 process visibility failed: pid=%lu, action=%lu, flags=0x%08lX, status=0x%08X.",
            (unsigned long)visibilityRequestValue.processId,
            (unsigned long)visibilityRequestValue.action,
            (unsigned long)visibilityRequestValue.flags,
            (unsigned int)status);
    }

    return status;
}

NTSTATUS
kswordArkProcessIoctlSetSpecialFlags(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS. Note: The handler is
    responsible for write access, security policy, and fixed packet validation;
    specific BreakOnTermination/APC writes are completed in process_flags.c.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must include the fixed request.
    OutputBufferLength: Output length; must accommodate the fixed response.
    BytesReturned - Returns the number of response bytes.

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST* specialRequest = NULL;
    KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE* specialResponse = NULL;
    KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST specialRequestValue;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG operationStatus = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNKNOWN;
    ULONG appliedFlags = 0UL;
    ULONG touchedThreadCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 process-special denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_PROCESS_SPECIAL_REQUEST_V1_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process-special ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process-special ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    specialRequest = (KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST*)inputBuffer;
    RtlZeroMemory(&specialRequestValue, sizeof(specialRequestValue));
    RtlCopyMemory(
        &specialRequestValue,
        specialRequest,
        min(actualInputLength, sizeof(specialRequestValue)));
    specialResponse = (KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE*)outputBuffer;
    RtlZeroMemory(specialResponse, sizeof(*specialResponse));
    specialResponse->version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
    specialResponse->processId = specialRequestValue.processId;
    specialResponse->action = specialRequestValue.action;

    status = kswordArkValidateUserPid((ULONG)specialRequestValue.processId);
    if (NT_SUCCESS(status)) {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
        safetyContext.targetProcessId = (ULONG)specialRequestValue.processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
    }

    if (NT_SUCCESS(status)) {
        status = kswordArkDriverSetProcessSpecialFlags(
            (ULONG)specialRequestValue.processId,
            (ULONG)specialRequestValue.action,
            (ULONG)specialRequestValue.flags,
            specialRequestValue.expectedCreateTime100ns,
            &operationStatus,
            &appliedFlags,
            &touchedThreadCount);
    }
    else {
        operationStatus = KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED;
    }

    specialResponse->status = operationStatus;
    specialResponse->appliedFlags = appliedFlags;
    specialResponse->touchedThreadCount = touchedThreadCount;
    specialResponse->lastStatus = status;
    *bytesReturned = sizeof(*specialResponse);

    kswordArkProcessIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Error",
        "R0 process-special result: pid=%lu, action=%lu, status=%lu, touched=%lu, nt=0x%08X.",
        (unsigned long)specialRequestValue.processId,
        (unsigned long)specialRequestValue.action,
        (unsigned long)operationStatus,
        (unsigned long)touchedThreadCount,
        (unsigned int)status);
    return status;
}

NTSTATUS
kswordArkProcessIoctlDkomProcess(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_DKOM_PROCESS. Note: Currently, only the high-risk action of deleting the
    EPROCESS corresponding to the target PID from PspCidTable is provided; addresses are resolved by R0.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must include the fixed request.
    OutputBufferLength: Output length; must accommodate the fixed response.
    BytesReturned - Returns the number of response bytes.

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_DKOM_PROCESS_REQUEST* dkomRequest = NULL;
    KSWORD_ARK_DKOM_PROCESS_RESPONSE* dkomResponse = NULL;
    KSWORD_ARK_DKOM_PROCESS_REQUEST dkomRequestValue;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG operationStatus = KSWORD_ARK_PROCESS_DKOM_STATUS_UNKNOWN;
    ULONG removedEntries = 0UL;
    ULONG64 pspCidTableAddress = 0ULL;
    ULONG64 processObjectAddress = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 process-dkom denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_DKOM_PROCESS_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process-dkom ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_DKOM_PROCESS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 process-dkom ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    dkomRequest = (KSWORD_ARK_DKOM_PROCESS_REQUEST*)inputBuffer;
    RtlZeroMemory(&dkomRequestValue, sizeof(dkomRequestValue));
    RtlCopyMemory(&dkomRequestValue, dkomRequest, sizeof(dkomRequestValue));
    dkomResponse = (KSWORD_ARK_DKOM_PROCESS_RESPONSE*)outputBuffer;
    RtlZeroMemory(dkomResponse, sizeof(*dkomResponse));
    dkomResponse->version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
    dkomResponse->processId = dkomRequestValue.processId;
    dkomResponse->action = dkomRequestValue.action;

    status = kswordArkValidateUserPid((ULONG)dkomRequestValue.processId);
    if (NT_SUCCESS(status)) {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.targetProcessId = (ULONG)dkomRequestValue.processId;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
    }

    if (NT_SUCCESS(status)) {
        status = kswordArkDriverDkomProcess(
            (ULONG)dkomRequestValue.processId,
            (ULONG)dkomRequestValue.action,
            (ULONG)dkomRequestValue.flags,
            &operationStatus,
            &removedEntries,
            &pspCidTableAddress,
            &processObjectAddress);
    }
    else {
        operationStatus = KSWORD_ARK_PROCESS_DKOM_STATUS_OPERATION_FAILED;
    }

    dkomResponse->status = operationStatus;
    dkomResponse->removedEntries = removedEntries;
    dkomResponse->lastStatus = status;
    dkomResponse->pspCidTableAddress = pspCidTableAddress;
    dkomResponse->processObjectAddress = processObjectAddress;
    *bytesReturned = sizeof(*dkomResponse);

    kswordArkProcessIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Error",
        "R0 process-dkom result: pid=%lu, action=%lu, status=%lu, removed=%lu, cid=0x%I64X, nt=0x%08X.",
        (unsigned long)dkomRequestValue.processId,
        (unsigned long)dkomRequestValue.action,
        (unsigned long)operationStatus,
        (unsigned long)removedEntries,
        pspCidTableAddress,
        (unsigned int)status);
    return status;
}

NTSTATUS
kswordArkProcessIoctlInjectProcess(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_INJECT_PROCESS. The METHOD_BUFFERED input carries a
    variable-length DLL path or shellcode blob, so the handler copies it before
    retrieving the output buffer.

Arguments:

    Device - WDF device used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length supplied by WDF; validation uses the
        retrieved buffer length.
    OutputBufferLength - Output length supplied by WDF; validation uses the
        retrieved buffer length.
    BytesReturned - Receives sizeof(KSWORD_ARK_INJECT_PROCESS_RESPONSE) when a
        semantic response is produced.

Return Value:

    STATUS_SUCCESS when the response contains the semantic injection status, or
    validation/safety NTSTATUS when the request cannot be executed.

--*/
{
    KSWORD_ARK_INJECT_PROCESS_REQUEST* injectRequest = NULL;
    KSWORD_ARK_INJECT_PROCESS_REQUEST* injectRequestCopy = NULL;
    KSWORD_ARK_INJECT_PROCESS_RESPONSE* injectResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    size_t bytesWritten = 0U;
    const ULONG kAllowedFlags =
        KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED |
        KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 inject denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 inject ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    injectRequest = (KSWORD_ARK_INJECT_PROCESS_REQUEST*)inputBuffer;
    if (injectRequest->version != KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION ||
        (injectRequest->flags & ~kAllowedFlags) != 0UL ||
        (injectRequest->injectType != KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH &&
            injectRequest->injectType != KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE) ||
        injectRequest->payloadBytes == 0UL ||
        injectRequest->payloadBytes > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES ||
        (SIZE_T)injectRequest->payloadBytes > (MAXSIZE_T - KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE)) {
        kswordArkProcessIoctlLog(
            device,
            "Warn",
            "R0 inject ioctl: request rejected, pid=%lu, type=%lu, flags=0x%08X, bytes=%lu.",
            (unsigned long)injectRequest->processId,
            (unsigned long)injectRequest->injectType,
            (unsigned int)injectRequest->flags,
            (unsigned long)injectRequest->payloadBytes);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkValidateUserPid((ULONG)injectRequest->processId);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Warn", "R0 inject ioctl: pid rejected, pid=%lu.", (unsigned long)injectRequest->processId);
        return status;
    }

    requiredInputLength =
        KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE +
        (SIZE_T)injectRequest->payloadBytes;
    if (actualInputLength < requiredInputLength) {
        kswordArkProcessIoctlLog(
            device,
            "Warn",
            "R0 inject ioctl: input truncated, actual=%Iu, required=%Iu.",
            actualInputLength,
            requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    injectRequestCopy = (KSWORD_ARK_INJECT_PROCESS_REQUEST*)kswordArkAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_PROCESS_INJECT_IOCTL_POOL_TAG);
    if (injectRequestCopy == NULL) {
        kswordArkProcessIoctlLog(device, "Error", "R0 inject ioctl: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(injectRequestCopy, injectRequest, requiredInputLength);
    injectRequest = injectRequestCopy;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_INJECT_PROCESS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(device, "Error", "R0 inject ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(injectRequestCopy, KSWORD_ARK_PROCESS_INJECT_IOCTL_POOL_TAG);
        return status;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_INJECT;
        safetyContext.targetProcessId = (ULONG)injectRequest->processId;
        safetyContext.contextFlags =
            ((injectRequest->flags & KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED) != 0UL) ?
            KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED :
            0UL;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkProcessIoctlLog(
                device,
                "Warn",
                "R0 inject denied by safety policy: pid=%lu, type=%lu, status=0x%08X.",
                (unsigned long)injectRequest->processId,
                (unsigned long)injectRequest->injectType,
                (unsigned int)status);
            ExFreePoolWithTag(injectRequestCopy, KSWORD_ARK_PROCESS_INJECT_IOCTL_POOL_TAG);
            return status;
        }
    }

    injectResponse = (KSWORD_ARK_INJECT_PROCESS_RESPONSE*)outputBuffer;
    status = kswordArkDriverInjectProcess(
        injectResponse,
        actualOutputLength,
        injectRequest,
        requiredInputLength,
        &bytesWritten);
    *bytesReturned = bytesWritten;
    if (!NT_SUCCESS(status)) {
        kswordArkProcessIoctlLog(
            device,
            "Error",
            "R0 inject backend failed: pid=%lu, type=%lu, status=0x%08X.",
            (unsigned long)injectRequest->processId,
            (unsigned long)injectRequest->injectType,
            (unsigned int)status);
        ExFreePoolWithTag(injectRequestCopy, KSWORD_ARK_PROCESS_INJECT_IOCTL_POOL_TAG);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_INJECT_PROCESS_RESPONSE)) {
        kswordArkProcessIoctlLog(
            device,
            injectResponse->status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED ? "Info" : "Error",
            "R0 inject result: pid=%lu, type=%lu, status=%lu, written=%lu, remote=0x%I64X, nt=0x%08X.",
            (unsigned long)injectResponse->processId,
            (unsigned long)injectResponse->injectType,
            (unsigned long)injectResponse->status,
            (unsigned long)injectResponse->bytesWritten,
            injectResponse->remoteBaseAddress,
            (unsigned int)injectResponse->lastStatus);
    }

    ExFreePoolWithTag(injectRequestCopy, KSWORD_ARK_PROCESS_INJECT_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}

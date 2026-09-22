/*++

Module Name:

    security_audit_ioctl.c

Abstract:

    IOCTL handlers for read-only security posture audit queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "security_audit_internal.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordSecurityAuditIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Emit compact security-audit IOCTL logs without returning paths or private data.

Arguments:

    Device - WDF device used by the log channel.
    levelText - Text log level.
    FormatText - printf-style format string.
    ... - Format arguments.

Return Value:

    None. The routine only attempts best-effort log enqueue.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
kswordArkSecurityAuditIoctlQuerySecurityStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_SECURITY_STATUS. The handler accepts an optional
    versioned request and delegates all posture collection to security_audit_query.c.

Arguments:

    Device - WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length.
    OutputBufferLength - Caller-supplied output length.
    BytesReturned - Receives the completed byte count.

Return Value:

    NTSTATUS from validation or query backend.

--*/
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN inputPresent = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &inputPresent);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditIoctlLog(device, "Error", "security-status input invalid: 0x%08X.", (unsigned int)status);
        return status;
    }
    if (inputPresent) {
        const KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST* queryRequest = (const KSWORD_ARK_QUERY_SECURITY_STATUS_REQUEST*)inputBuffer;
        if (queryRequest->size < sizeof(*queryRequest) || queryRequest->version > KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION || queryRequest->flags != 0UL) {
            return STATUS_INVALID_PARAMETER;
        }
        UNREFERENCED_PARAMETER(actualInputLength);
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditIoctlLog(device, "Error", "security-status output invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkSecurityAuditQuerySecurityStatus(outputBuffer, actualOutputLength, bytesReturned);
    kswordSecurityAuditIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "security-status completed: status=0x%08X bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkSecurityAuditIoctlQueryDriverTrustView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW. The handler validates only
    row bounds and flags; loaded-module and signing-cache work stays in the feature backend.

Arguments:

    Device - WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length.
    OutputBufferLength - Caller-supplied output length.
    BytesReturned - Receives the completed byte count.

Return Value:

    NTSTATUS from validation or query backend.

--*/
{
    const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST* queryRequest = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN inputPresent = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &inputPresent);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditIoctlLog(device, "Error", "driver-trust-view input invalid: 0x%08X.", (unsigned int)status);
        return status;
    }
    if (inputPresent) {
        queryRequest = (const KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_REQUEST*)inputBuffer;
        if (queryRequest->size < sizeof(*queryRequest) || queryRequest->version > KSWORD_ARK_SECURITY_AUDIT_PROTOCOL_VERSION) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((queryRequest->flags & ~KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_INCLUDE_SIGNING_LEVEL) != 0UL) {
            return STATUS_INVALID_PARAMETER;
        }
        UNREFERENCED_PARAMETER(actualInputLength);
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        FIELD_OFFSET(KSWORD_ARK_QUERY_DRIVER_TRUST_VIEW_RESPONSE, entries),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditIoctlLog(device, "Error", "driver-trust-view output invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkSecurityAuditQueryDriverTrustView(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    kswordSecurityAuditIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "driver-trust-view completed: status=0x%08X bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkSecurityAuditIoctlQueryHyperVSummary(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_HYPERV_SUMMARY by retrieving the fixed output buffer.

Arguments:

    Device - WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length.
    OutputBufferLength - Caller-supplied output length.
    BytesReturned - Receives the completed byte count.

Return Value:

    NTSTATUS from validation or query backend.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditIoctlLog(device, "Error", "hyperv-summary output invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkSecurityAuditQueryHyperVSummary(outputBuffer, actualOutputLength, bytesReturned);
    kswordSecurityAuditIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "hyperv-summary completed: status=0x%08X bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

NTSTATUS
kswordArkSecurityAuditIoctlQueryAppControlStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_APP_CONTROL_STATUS by retrieving the fixed output buffer.

Arguments:

    Device - WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Caller-supplied input length.
    OutputBufferLength - Caller-supplied output length.
    BytesReturned - Receives the completed byte count.

Return Value:

    NTSTATUS from validation or query backend.

--*/
{
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordSecurityAuditIoctlLog(device, "Error", "app-control-status output invalid: 0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkSecurityAuditQueryAppControlStatus(outputBuffer, actualOutputLength, bytesReturned);
    kswordSecurityAuditIoctlLog(device, NT_SUCCESS(status) ? "Info" : "Error", "app-control-status completed: status=0x%08X bytes=%Iu.", (unsigned int)status, *bytesReturned);
    return status;
}

/*++

Module Name:

    preflight_ioctl.c

Abstract:

    IOCTL handler for Phase-16 release preflight diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkPreflightIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output: preflight query log. Note: Pre-release diagnostic logs record only
    summary status and counts; detailed check text is carried in the response packet.

Arguments:

    Device - The WDF device object.
    levelText - Log level.
    FormatText - printf-style format string.
    ... - Format arguments.

Return Value:

    None. This function has no return value.

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
kswordArkPreflightIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PREFLIGHT. Note: Input is optional; output returns
    entries up to capacity. R3 can resize based on totalCheckCount and retry.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned: Number of bytes written.

Return Value:

    NTSTATUS from validation or preflight backend.

--*/
{
    KSWORD_ARK_QUERY_PREFLIGHT_REQUEST* preflightRequest = NULL;
    KSWORD_ARK_QUERY_PREFLIGHT_REQUEST defaultRequest = { 0 };
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_PREFLIGHT_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_QUERY_PREFLIGHT_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkPreflightIoctlLog(device, "Error", "R0 preflight: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (hasInput) {
        /*
         * METHOD_BUFFERED shares one SystemBuffer for input and output. The backend
         * calls RtlZeroMemory on the output before reading flags to select checks.
         * Without an input snapshot, it would interpret response-header bytes as flags.
         */
        RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
        preflightRequest = &requestSnapshot;
        if (preflightRequest->size < sizeof(KSWORD_ARK_QUERY_PREFLIGHT_REQUEST) ||
            preflightRequest->version != KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION ||
            (preflightRequest->flags & ~KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_ALL) != 0UL) {
            kswordArkPreflightIoctlLog(device, "Warn", "R0 preflight: request rejected, flags=0x%08X.", (unsigned int)preflightRequest->flags);
            return STATUS_INVALID_PARAMETER;
        }
    }
    else {
        preflightRequest = &defaultRequest;
        preflightRequest->size = sizeof(defaultRequest);
        preflightRequest->version = KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION;
        preflightRequest->flags = KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_EXTERNAL_GATES;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE) - sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkPreflightIoctlLog(device, "Error", "R0 preflight: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkPreflightQuery(
        outputBuffer,
        actualOutputLength,
        preflightRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkPreflightIoctlLog(device, "Error", "R0 preflight query failed, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE) - sizeof(KSWORD_ARK_PREFLIGHT_CHECK_ENTRY)) {
        KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE* response =
            (KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE*)outputBuffer;
        kswordArkPreflightIoctlLog(
            device,
            response->overallStatus <= KSWORD_ARK_PREFLIGHT_STATUS_WARN ? "Info" : "Warn",
            "R0 preflight complete: overall=%lu, checks=%lu/%lu.",
            (unsigned long)response->overallStatus,
            (unsigned long)response->returnedCheckCount,
            (unsigned long)response->totalCheckCount);
    }

    return STATUS_SUCCESS;
}

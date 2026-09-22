/*++

Module Name:

    handle_ioctl.c

Abstract:

    IOCTL handlers for KswordARK handle-table inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE) - sizeof(KSWORD_ARK_HANDLE_ENTRY))

static VOID
kswordArkHandleIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format one handle IOCTL diagnostic line. Note: Log failures do not affect user requests;
    here we retain only sufficient context for troubleshooting capability and buffer issues.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI template.
    ... - Template arguments.

Return Value:

    None.

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
kswordArkHandleIoctlEnumProcessHandles(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES. Note: The request packet must provide the PID; the output
    packet may be truncated. R3 determines if a larger buffer is needed based on totalCount/returnedCount.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length.
    OutputBufferLength - Caller output length.
    BytesReturned - Receives response bytes written by the feature.

Return Value:

    NTSTATUS from validation or handle-table enumeration.

--*/
{
    KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST requestSnapshot = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkHandleIoctlLog(device, "Error", "R0 enum-handle ioctl: input buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /* Preserve METHOD_BUFFERED input before the backend clears the shared response buffer. */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    enumRequest = &requestSnapshot;
    if (enumRequest->processId == 0UL) {
        kswordArkHandleIoctlLog(device, "Warn", "R0 enum-handle ioctl: missing pid.");
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkHandleIoctlLog(device, "Error", "R0 enum-handle ioctl: output buffer invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateProcessHandles(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        if (!KSWORD_ARK_ENUM_HANDLE_STATUS_IS_EXPECTED_CHURN(enumRequest->flags, status)) {
            kswordArkHandleIoctlLog(
                device,
                "Error",
                "R0 enum-handle failed: pid=%lu, status=0x%08X, outBytes=%Iu.",
                (unsigned long)enumRequest->processId,
                (unsigned int)status,
                *bytesReturned);
        }
        return status;
    }

    if ((enumRequest->flags & KSWORD_ARK_ENUM_HANDLE_FLAG_QUIET_LOG) == 0UL &&
        *bytesReturned >= KSWORD_ARK_HANDLE_ENUM_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE* responseHeader = (KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*)outputBuffer;
        kswordArkHandleIoctlLog(
            device,
            "Info",
            "R0 enum-handle success: pid=%lu, total=%lu, returned=%lu, status=%lu, outBytes=%Iu.",
            (unsigned long)responseHeader->processId,
            (unsigned long)responseHeader->totalCount,
            (unsigned long)responseHeader->returnedCount,
            (unsigned long)responseHeader->overallStatus,
            *bytesReturned);
    }

    return status;
}

NTSTATUS
kswordArkHandleIoctlQueryHandleObject(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT. Note: This path accepts only PID and handle value,
    not object address, to prevent exposing addresses that could become operational credentials.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length.
    OutputBufferLength - Caller output length.
    BytesReturned - Receives fixed response length.

Return Value:

    NTSTATUS from validation or object query helper.

--*/
{
    KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST requestSnapshot = { 0 };
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkHandleIoctlLog(device, "Error", "R0 query-handle-object ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /* Preserve METHOD_BUFFERED input before the backend clears the shared response buffer. */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkHandleIoctlLog(device, "Error", "R0 query-handle-object ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryHandleObject(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkHandleIoctlLog(device, "Error", "R0 query-handle-object failed: pid=%lu, handle=0x%I64X, status=0x%08X.", (unsigned long)queryRequest->processId, queryRequest->handleValue, (unsigned int)status);
        return status;
    }

    if ((queryRequest->flags & KSWORD_ARK_QUERY_OBJECT_FLAG_QUIET_LOG) == 0UL &&
        *bytesReturned >= sizeof(KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE)) {
        KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response = (KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE*)outputBuffer;
        kswordArkHandleIoctlLog(
            device,
            "Info",
            "R0 query-handle-object success: pid=%lu, handle=0x%I64X, queryStatus=%lu, proxyStatus=%lu.",
            (unsigned long)response->processId,
            response->handleValue,
            (unsigned long)response->queryStatus,
            (unsigned long)response->proxyStatus);
    }

    return STATUS_SUCCESS;
}

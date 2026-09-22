/*++

Module Name:

    wsl_silo_ioctl.c

Abstract:

    IOCTL handler for Phase-13 WSL/Pico and Silo diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkWslSiloIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output WSL/Silo query logs. Note: Logs only record PID/TID and status, not internal pointers
    or Linux process details, to avoid leaking excessive kernel diagnostic information.

Arguments:

    Device - The WDF device object.
    levelText - Log level.
    FormatText - printf-style format string.
    ... - Format arguments.

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
kswordArkWslSiloIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_WSL_SILO. Note: The request packet is mandatory; when flags
    is 0, query all basic information; actual field reading is performed by wsl_silo_query.c.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length.
    BytesReturned - Length of data received.

Return Value:

    NTSTATUS from validation or backend.

--*/
{
    KSWORD_ARK_QUERY_WSL_SILO_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_WSL_SILO_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const ULONG kAllowedFlags = KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_WSL_SILO_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkWslSiloIoctlLog(device, "Error", "R0 query-wsl-silo: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The backend must zero the output before
     * reading processId/threadId; otherwise, without a snapshot, it will query an incorrect process or thread.
     */
    queryRequest = (KSWORD_ARK_QUERY_WSL_SILO_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if ((queryRequest->flags & ~kAllowedFlags) != 0UL) {
        kswordArkWslSiloIoctlLog(device, "Warn", "R0 query-wsl-silo: flags rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_WSL_SILO_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkWslSiloIoctlLog(device, "Error", "R0 query-wsl-silo: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryWslSilo(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkWslSiloIoctlLog(device, "Error", "R0 query-wsl-silo failed: pid=%lu, tid=%lu, status=0x%08X.", (unsigned long)queryRequest->processId, (unsigned long)queryRequest->threadId, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_WSL_SILO_RESPONSE)) {
        KSWORD_ARK_QUERY_WSL_SILO_RESPONSE* response = (KSWORD_ARK_QUERY_WSL_SILO_RESPONSE*)outputBuffer;
        kswordArkWslSiloIoctlLog(
            device,
            "Info",
            "R0 query-wsl-silo success: pid=%lu, tid=%lu, status=%lu, fields=0x%08X.",
            (unsigned long)response->processId,
            (unsigned long)response->threadId,
            (unsigned long)response->queryStatus,
            (unsigned int)response->fieldFlags);
    }

    return STATUS_SUCCESS;
}

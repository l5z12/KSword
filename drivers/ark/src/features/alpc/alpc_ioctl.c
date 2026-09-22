/*++

Module Name:

    alpc_ioctl.c

Abstract:

    IOCTL handler for KswordARK ALPC inspection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkAlpcIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and write ALPC IOCTL diagnostic logs. Note: Log failures do not affect the
    main IOCTL path; only retain troubleshooting key fields like pid/handle/status.

Arguments:

    Device - The WDF device object.
    levelText - Log level text.
    FormatText: printf-style format string.
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
kswordArkAlpcIoctlQueryAlpcPort(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_ALPC_PORT. Note: The handler only performs
    WDF buffer validation and logging; actual PID+Handle object reference
    resolution and ALPC field reading occur at the feature query layer.

Arguments:

    Device - The WDF device object.
    Request - current WDF request.
    InputBufferLength: input buffer length.
    OutputBufferLength - Output buffer length.
    BytesReturned - number of bytes returned.

Return Value:

    NTSTATUS indicates the result of WDF buffer validation or query execution.

--*/
{
    KSWORD_ARK_QUERY_ALPC_PORT_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_ALPC_PORT_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_QUERY_ALPC_PORT_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkAlpcIoctlLog(device, "Error", "R0 query-alpc ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED uses the same SystemBuffer for input and output; the backend clears the output before
     * reading processId/handleValue. Without taking a snapshot, it would query a handle from an incorrect process.
     */
    queryRequest = (KSWORD_ARK_QUERY_ALPC_PORT_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkAlpcIoctlLog(device, "Error", "R0 query-alpc ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryAlpcPort(outputBuffer, actualOutputLength, queryRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkAlpcIoctlLog(
            device,
            "Error",
            "R0 query-alpc failed: pid=%lu, handle=0x%I64X, status=0x%08X.",
            (unsigned long)queryRequest->processId,
            queryRequest->handleValue,
            (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE)) {
        KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE* response = (KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE*)outputBuffer;
        kswordArkAlpcIoctlLog(
            device,
            "Info",
            "R0 query-alpc success: pid=%lu, handle=0x%I64X, queryStatus=%lu, fieldFlags=0x%08lX.",
            (unsigned long)response->processId,
            response->handleValue,
            (unsigned long)response->queryStatus,
            (unsigned long)response->fieldFlags);
    }

    return STATUS_SUCCESS;
}

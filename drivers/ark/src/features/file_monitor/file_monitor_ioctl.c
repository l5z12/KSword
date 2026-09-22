/*++

Module Name:

    file_monitor_ioctl.c

Abstract:

    IOCTL handlers for Phase-12 file-system monitor runtime.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) - sizeof(KSWORD_ARK_FILE_MONITOR_EVENT))

static VOID
kswordArkFileMonitorIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Output file monitor IOCTL log. Note: Log records only control status and event count,
    not detailed paths, to prevent log channel congestion from high-frequency events.

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
kswordArkFileMonitorIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle file monitoring Start/Stop/Clear control. Note: Start accepts operationMask and processId;
    Stop stops collection only without unregistering the filter; Clear empties the ring buffer.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length.
    OutputBufferLength - Output length, unused.
    BytesReturned - number of bytes written; control IOCTLs always return 0.

Return Value:

    NTSTATUS from validation or runtime control.

--*/
{
    KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST* controlRequest = NULL;
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileMonitorIoctlLog(device, "Error", "R0 file-monitor control: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    controlRequest = (KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST*)inputBuffer;
    if ((controlRequest->operationMask & ~KSWORD_ARK_FILE_MONITOR_OPERATION_ALL) != 0UL) {
        kswordArkFileMonitorIoctlLog(device, "Warn", "R0 file-monitor control: operation mask rejected, mask=0x%08X.", (unsigned int)controlRequest->operationMask);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkFileMonitorControl(controlRequest);
    kswordArkFileMonitorIoctlLog(
        device,
        NT_SUCCESS(status) ? "Info" : "Warn",
        "R0 file-monitor control: action=%lu, mask=0x%08X, pid=%lu, status=0x%08X.",
        (unsigned long)controlRequest->action,
        (unsigned int)controlRequest->operationMask,
        (unsigned long)controlRequest->processId,
        (unsigned int)status);
    return status;
}

NTSTATUS
kswordArkFileMonitorIoctlDrain(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle file monitoring event drain. Note: Input packet is optional; output packet returns events
    by capacity, consumed upon retrieval; R3 displays a dropped packet warning based on droppedCount.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Input length; use defaults if less than the request packet size.
    OutputBufferLength - Output length.
    BytesReturned - number of bytes in the response.

Return Value:

    NTSTATUS from buffer retrieval or drain backend.

--*/
{
    KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST* drainRequest = NULL;
    KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST defaultRequest = { 0 };
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
        sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkFileMonitorIoctlLog(device, "Error", "R0 file-monitor drain: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    drainRequest = hasInput ? (KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST*)inputBuffer : &defaultRequest;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileMonitorIoctlLog(device, "Error", "R0 file-monitor drain: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkFileMonitorDrain(
        outputBuffer,
        actualOutputLength,
        drainRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkFileMonitorIoctlLog(device, "Error", "R0 file-monitor drain failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE* response = (KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE*)outputBuffer;
        kswordArkFileMonitorIoctlLog(
            device,
            "Info",
            "R0 file-monitor drain: returned=%lu, queuedBefore=%lu, dropped=%lu.",
            (unsigned long)response->returnedCount,
            (unsigned long)response->totalQueuedBeforeDrain,
            (unsigned long)response->droppedCount);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileMonitorIoctlQueryStatus(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Query file monitor runtime status. Note: Used by R3 to display minifilter
    registration/startup status, ring buffer queue depth, and dropped count.

Arguments:

    Device - The WDF device object.
    Request - Current IOCTL request.
    InputBufferLength - Unused.
    OutputBufferLength - Output length.
    BytesReturned - Length of response received.

Return Value:

    NTSTATUS from output retrieval or status backend.

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
        sizeof(KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileMonitorIoctlLog(device, "Error", "R0 file-monitor status: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkFileMonitorQueryStatus(
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (NT_SUCCESS(status) && *bytesReturned >= sizeof(KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE)) {
        KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE* response = (KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE*)outputBuffer;
        kswordArkFileMonitorIoctlLog(
            device,
            "Info",
            "R0 file-monitor status: flags=0x%08X, queued=%lu, dropped=%lu.",
            (unsigned int)response->runtimeFlags,
            (unsigned long)response->queuedCount,
            (unsigned long)response->droppedCount);
    }

    return status;
}

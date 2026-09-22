/*++

Module Name:

    callback_monitor_ioctl.c

Abstract:

    WDF IOCTL adapters for the callback telemetry monitor.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

NTSTATUS
kswordArkCallbackMonitorIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST* input = NULL;
    KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST requestSnapshot;
    KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* output = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Device is used only to unify the handler signature; business state belongs to the callback runtime.
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    // METHOD_BUFFERED shares system buffers for input/output; save the request before writing the response.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    requestSnapshot = *input;
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // Business layer validates version, category, and Minifilter startup status.
    status = kswordArkCallbackMonitorControl(&requestSnapshot, output);
    *bytesReturned = sizeof(*output);
    return status;
}

NTSTATUS
kswordArkCallbackMonitorIoctlQuery(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE* output = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // Query has no input buffer and does not depend on WDFDEVICE.
    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // Status response has a fixed size; return the complete data upon successful read.
    status = kswordArkCallbackMonitorQuery(output);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(*output);
    }
    return status;
}

NTSTATUS
kswordArkCallbackMonitorIoctlRead(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST* input = NULL;
    KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST requestSnapshot;
    KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE* output = NULL;
    const size_t kResponseHeaderSize = FIELD_OFFSET(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records);
    NTSTATUS status = STATUS_SUCCESS;

    // Device is only used to unify the handler signature; reads directly access the callback runtime.
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    // Retrieve the shared METHOD_BUFFERED output region after saving the cursor.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    requestSnapshot = *input;
    status = WdfRequestRetrieveOutputBuffer(
        request,
        kResponseHeaderSize,
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < kResponseHeaderSize) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // The high-frequency polling path does not write logs to avoid creating an event and notification storm.
    return kswordArkCallbackMonitorRead(
        &requestSnapshot,
        output,
        outputBufferLength,
        bytesReturned);
}

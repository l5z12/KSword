/*++

Module Name:

    debug_output_ioctl.c

Abstract:

    IOCTL adapters for kernel debug-output capture control and draining.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

// Handle capture start/stop and status queries; both requests and responses are carried in METHOD_BUFFERED system buffers.
NTSTATUS kswordArkDebugOutputIoctlControl(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
{
    KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST* input;
    KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST requestSnapshot;
    KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE* output;
    NTSTATUS status;

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    // Retrieve the buffer based on the fixed header size of the shared protocol first to prevent short requests from reaching the business layer.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    // METHOD_BUFFERED input and output share the same system buffer; the full request must be saved before writing the response.
    requestSnapshot = *input;
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // The business layer validates the protocol version and returns the current registration and discard status.
    status = kswordArkDebugOutputControl(device, &requestSnapshot, output);
    *bytesReturned = sizeof(*output);
    return status;
}

// Batch read the kernel circular buffer by cursor; the actual returned length is precisely calculated by the business layer.
NTSTATUS kswordArkDebugOutputIoctlDrain(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
{
    KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST* input;
    KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST requestSnapshot;
    KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE* output;
    const size_t kResponseHeaderSize = FIELD_OFFSET(KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE, records);
    NTSTATUS status;

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    // Input: Contains at least the version, size, cursor, and the expected count for this request.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    // Drain clears the variable-length output buffer, so input fields like afterSequence/maxRecords must be copied first.
    requestSnapshot = *input;
    status = WdfRequestRetrieveOutputBuffer(
        request,
        kResponseHeaderSize,
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < kResponseHeaderSize) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // High-frequency polling does not output any debug logs here to avoid capturing itself and forming a feedback loop.
    return kswordArkDebugOutputDrain(
        device,
        &requestSnapshot,
        output,
        outputBufferLength,
        bytesReturned);
}

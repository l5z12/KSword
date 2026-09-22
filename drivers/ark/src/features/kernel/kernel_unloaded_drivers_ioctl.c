/*++

Module Name:

    kernel_unloaded_drivers_ioctl.c

Abstract:

    WDF adapter for the read-only unloaded-driver source query.

--*/

#include "kernel_unloaded_drivers.h"

NTSTATUS
kswordArkKernelIoctlQueryUnloadedDrivers(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    // This IOCTL has no device-level state and does not request write access.
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));

    // The fixed request header must be fully present.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength <
            sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST) ||
        actualInputLength <
            sizeof(KSWORD_ARK_QUERY_UNLOADED_DRIVERS_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }

    // METHOD_BUFFERED input/output may alias the same system buffer; since the backend clears the output region first,
    // the complete request must be saved before reading/writing the output to prevent size/source from being overwritten.
    RtlCopyMemory(
        &requestCopy,
        inputBuffer,
        sizeof(requestCopy));

    // Variable-length output must at least accommodate the response header; the backend calculates row capacity based on the actual length.
    status = WdfRequestRetrieveOutputBuffer(
        request,
        KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength <
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE ||
        actualOutputLength <
            KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE_HEADER_SIZE) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    return kswordArkQueryUnloadedDrivers(
        &requestCopy,
        (KSWORD_ARK_QUERY_UNLOADED_DRIVERS_RESPONSE*)outputBuffer,
        actualOutputLength,
        bytesReturned);
}

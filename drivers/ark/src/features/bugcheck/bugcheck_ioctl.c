/*++

Module Name:

    bugcheck_ioctl.c

Abstract:

    Silent optional BGRA32 bitmap upload for the VMware bugcheck panel.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_panel.h"

NTSTATUS
kswordArkBugcheckIoctlConfigureDiagnostics(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE* output = NULL;
    NTSTATUS status;

    // The controller saved the device object in DriverEntry; the handler explicitly marks this parameter as unused in business logic decisions.
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    // Requests and responses are fixed-length METHOD_BUFFERED packets; insufficient length results in an immediate failure returned by the unified dispatch layer.
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || outputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // On function-level failure, write the response status; the IOCTL itself completes successfully, allowing R3 to obtain a precise summary of the preparation phase.
    status = kswordArkBugcheckControlConfigure(input, output);
    if (NT_SUCCESS(status)) {
        *bytesReturned = sizeof(*output);
    }
    return status;
}

NTSTATUS
kswordArkBugcheckIoctlSetBitmap(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    return STATUS_NOT_SUPPORTED;
#else
    KSWORD_ARK_BUGCHECK_BITMAP_HEADER* header;
    ULONGLONG expectedStride;
    ULONGLONG expectedBytes;
    size_t requiredBytes;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_BUGCHECK_BITMAP_HEADER),
        (PVOID*)&header,
        NULL);
    if (!NT_SUCCESS(status) || inputBufferLength < sizeof(*header)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    expectedStride = (ULONGLONG)header->width * 4ULL;
    expectedBytes = expectedStride * (ULONGLONG)header->height;
    if (header->version != KSWORD_ARK_BUGCHECK_BITMAP_PROTOCOL_VERSION ||
        header->size != sizeof(*header) ||
        header->magic != KSWORD_ARK_BUGCHECK_BITMAP_MAGIC ||
        header->format != KSWORD_ARK_BUGCHECK_BITMAP_FORMAT_BGRA32 ||
        header->flags != 0 || header->reserved0 != 0 || header->reserved1 != 0 ||
        header->width == 0 || header->height == 0 ||
        header->width > KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH ||
        header->height > KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT ||
        expectedStride != header->stride ||
        expectedBytes == 0 ||
        expectedBytes > KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES ||
        expectedBytes != header->dataLength) {
        return STATUS_INVALID_PARAMETER;
    }

    requiredBytes = sizeof(*header) + (size_t)header->dataLength;
    if (requiredBytes < sizeof(*header) || inputBufferLength < requiredBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // The legacy VMware uploader remains protocol-compatible while that
    // backend is screened from the active physical-machine drawing path.
    if (!gKswordArkBugcheckState.svga.mapped) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(
            &gKswordArkBugcheckState.bitmap.uploading,
            1,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    // Make the crash path fall back to the built-in text while the single
    // backing buffer is changing. Metadata becomes visible before Valid=1.
    InterlockedExchange(&gKswordArkBugcheckState.bitmap.valid, 0);
    KeMemoryBarrier();
    RtlCopyMemory(
        gKswordArkBugcheckBitmapPixels,
        ((PUCHAR)header) + sizeof(*header),
        header->dataLength);
    gKswordArkBugcheckState.bitmap.width = header->width;
    gKswordArkBugcheckState.bitmap.height = header->height;
    gKswordArkBugcheckState.bitmap.stride = header->stride;
    gKswordArkBugcheckState.bitmap.dataLength = header->dataLength;
    gKswordArkBugcheckState.bitmap.brandColorRgb =
        header->brandColorRgb & 0x00FFFFFFUL;
    if (gKswordArkBugcheckState.bitmap.brandColorRgb == 0) {
        gKswordArkBugcheckState.bitmap.brandColorRgb = 0x0078D4UL;
    }
    KeMemoryBarrier();
    InterlockedExchange(&gKswordArkBugcheckState.bitmap.valid, 1);
    InterlockedExchange(&gKswordArkBugcheckState.bitmap.uploading, 0);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS
kswordArkBugcheckIoctlSetVerdictResources(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    return STATUS_NOT_SUPPORTED;
#else
    PVOID packet;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(outputBufferLength);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (inputBufferLength <
            sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER) ||
        inputBufferLength > MAXULONG) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    packet = NULL;
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER),
        &packet,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return kswordArkBugcheckPanelInstallVerdictResources(
        packet,
        (ULONG)inputBufferLength);
#endif
}

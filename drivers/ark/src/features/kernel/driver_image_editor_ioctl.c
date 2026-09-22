/*++

Module Name:

    driver_image_editor_ioctl.c

Abstract:

    IOCTL boundary for unrestricted DriverObject image-field and loaded-module
    list transactions.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control path.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

// Note: Write an audit frame for every query, modification, restoration, or abandonment; logs only generate alerts without altering the target policy.
static VOID
kswordArkDriverImageLogResult(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DRIVER_IMAGE_RESPONSE* response
    )
{
    CHAR message[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (response == NULL) {
        return;
    }
    status = RtlStringCbPrintfA(
        message,
        sizeof(message),
        "R0 driver-image: action=%lu status=0x%08X object=0x%I64X "
        "start=0x%I64X size=0x%I64X section=0x%I64X "
        "kldrBase=0x%I64X kldrSize=0x%I64X loader=0x%I64X "
        "link=0x%I64X generation=%lu managed=0x%02X owned=0x%02X "
        "conflict=0x%02X flags=0x%08X loaderStatus=0x%08X.",
        (unsigned long)response->action,
        (unsigned int)response->lastStatus,
        response->driverObjectAddress,
        response->currentValues.driverStart,
        response->currentValues.driverSize,
        response->currentValues.driverSection,
        response->currentValues.kldrDllBase,
        response->currentValues.kldrSizeOfImage,
        response->loaderEntryAddress,
        response->loaderLinkAddress,
        (unsigned long)response->generation,
        (unsigned int)response->managedFieldMask,
        (unsigned int)response->ownedFieldMask,
        (unsigned int)response->conflictFieldMask,
        (unsigned int)response->responseFlags,
        (unsigned int)response->loaderStatus);
    if (NT_SUCCESS(status)) {
        (VOID)kswordArkDriverEnqueueLogFrame(
            device,
            NT_SUCCESS((NTSTATUS)response->lastStatus) ? "Warn" : "Error",
            message);
    }
}

// Note: For METHOD_BUFFERED, first copy an input snapshot to the boundary, then write a fixed-size response to avoid aliasing within the same buffer.
NTSTATUS
kswordArkKernelIoctlControlDriverImage(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_DRIVER_IMAGE_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_DRIVER_IMAGE_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_DRIVER_IMAGE_REQUEST requestSnapshot;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    // Note: FILE_WRITE_ACCESS is still validated within WDF request boundaries; reject modification protocols initiated by read-only device handles.
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        (PVOID*)&inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*outputBuffer),
        (PVOID*)&outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlZeroMemory(outputBuffer, sizeof(*outputBuffer));
    *bytesReturned = sizeof(*outputBuffer);

    // Note: Business status is always encapsulated in the response; if the IOCTL transfer succeeds, R3 is allowed to read the complete conflict diagnosis.
    status = kswordArkDriverControlImage(
        &requestSnapshot,
        outputBuffer);
    kswordArkDriverImageLogResult(device, outputBuffer);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}

/*++

Module Name:

    driver_dispatch_editor_ioctl.c

Abstract:

    IOCTL boundary for the generic DriverObject MajorFunction editor.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>

static VOID
kswordArkDriverDispatchLogResult(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* response
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
        "R0 driver-dispatch: action=%lu major=0x%02lX status=0x%08X "
        "driver=0x%I64X current=0x%I64X original=0x%I64X applied=0x%I64X "
        "requested=0x%I64X generation=%lu flags=0x%08X.",
        (unsigned long)response->action,
        (unsigned long)response->majorFunction,
        (unsigned int)response->lastStatus,
        response->driverObjectAddress,
        response->currentDispatchAddress,
        response->originalDispatchAddress,
        response->appliedDispatchAddress,
        response->requestedDispatchAddress,
        (unsigned long)response->generation,
        (unsigned int)response->responseFlags);
    if (NT_SUCCESS(status)) {
        (VOID)kswordArkDriverEnqueueLogFrame(
            device,
            NT_SUCCESS((NTSTATUS)response->lastStatus) ? "Warn" : "Error",
            message);
    }
}

NTSTATUS
kswordArkKernelIoctlControlDriverDispatch(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_DRIVER_DISPATCH_REQUEST* inputBuffer = NULL;
    KSWORD_ARK_DRIVER_DISPATCH_RESPONSE* outputBuffer = NULL;
    KSWORD_ARK_DRIVER_DISPATCH_REQUEST requestSnapshot;
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
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));
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

    status = kswordArkDriverControlDispatch(&requestSnapshot, outputBuffer);
    kswordArkDriverDispatchLogResult(device, outputBuffer);
    UNREFERENCED_PARAMETER(status);
    return STATUS_SUCCESS;
}

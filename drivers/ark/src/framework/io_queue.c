/*++

Module Name:

    io_queue.c

Abstract:

    This file contains queue setup plus read/stop callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkWindowBandIoctl.h"
#include "io_queue.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, kswordArkDriverQueueInitialize)
#endif

NTSTATUS
kswordArkDriverQueueInitialize(
    _In_ WDFDEVICE device,
    _In_ BOOLEAN powerManaged
    )
/*++

Routine Description:

     Configure the default queue and callbacks.

Arguments:

    Device - Handle to a framework device object.
    PowerManaged - TRUE only for the compatibility PnP device. Control devices
        never participate in power management, so their default queue must be
        created with PowerManaged explicitly cleared instead of WdfUseDefault.

Return Value:

    NTSTATUS

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    PAGED_CODE();

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
        );

    // Explicitly hardcode the power management attribute to exclude resolution differences of WdfUseDefault across different KMDF versions.
    queueConfig.PowerManaged = powerManaged ? WdfTrue : WdfFalse;
    queueConfig.EvtIoDeviceControl = kswordArkDriverEvtIoDeviceControl;
    queueConfig.EvtIoRead = kswordArkDriverEvtIoRead;
    // EvtIoStop is only meaningful on the power management queue; the device queue must remain empty.
    queueConfig.EvtIoStop = powerManaged ? kswordArkDriverEvtIoStop : NULL;

    status = WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
        );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
kswordArkDriverEvtIoInCallerContext(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request
    )
{
    WDF_REQUEST_PARAMETERS parameters;
    NTSTATUS status = STATUS_SUCCESS;

    WDF_REQUEST_PARAMETERS_INIT(&parameters);
    WdfRequestGetParameters(request, &parameters);
    if (parameters.Type == WdfRequestTypeDeviceControl &&
        (parameters.Parameters.DeviceIoControl.IoControlCode == IOCTL_KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY ||
         parameters.Parameters.DeviceIoControl.IoControlCode == IOCTL_KSWORD_ARK_WINDOW_BAND)) {
        kswordArkDriverDispatchDeviceControl(
            device,
            WDF_NO_HANDLE,
            request,
            parameters.Parameters.DeviceIoControl.OutputBufferLength,
            parameters.Parameters.DeviceIoControl.InputBufferLength,
            parameters.Parameters.DeviceIoControl.IoControlCode);
        return;
    }

    status = WdfDeviceEnqueueRequest(device, request);
    if (!NT_SUCCESS(status)) {
        TraceEvents(
            TRACE_LEVEL_ERROR,
            TRACE_QUEUE,
            "WdfDeviceEnqueueRequest failed %!STATUS!",
            status);
        WdfRequestComplete(request, status);
    }
}


VOID
kswordArkDriverEvtIoRead(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t length
    )
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_READ request.

Arguments:

    Queue - Handle to the queue object.
    Request - Handle to a framework request object.
    Length - Requested output length in bytes.

Return Value:

    VOID

--*/
{
    WDFDEVICE device = WdfIoQueueGetDevice(queue);
    PVOID outputBuffer = NULL;
    size_t outputBufferLength = 0;
    size_t bytesWritten = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(length);

    status = WdfRequestRetrieveOutputBuffer(
        request,
        1,
        &outputBuffer,
        &outputBufferLength);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfRequestRetrieveOutputBuffer failed %!STATUS!", status);
        WdfRequestCompleteWithInformation(request, status, 0);
        return;
    }

    status = kswordArkDriverReadNextLogLine(
        device,
        outputBuffer,
        outputBufferLength,
        &bytesWritten);
    WdfRequestCompleteWithInformation(request, status, bytesWritten);
}

VOID
kswordArkDriverEvtIoStop(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ ULONG actionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves D0.

Arguments:

    Queue - Handle to the queue object.
    Request - Handle to a framework request object.
    ActionFlags - Bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS values.

Return Value:

    VOID

--*/
{
    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d",
        queue,
        request,
        actionFlags);

    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(request);
    UNREFERENCED_PARAMETER(actionFlags);
}

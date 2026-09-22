#pragma once

#include <wdf.h>

EXTERN_C_START

// This is the context that can be placed per queue
// and would contain per queue information.
typedef struct QueueContext {

    ULONG privateDeviceData;  // just a placeholder

} QueueContext, *PqueueContext;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QueueContext, QueueGetContext)

NTSTATUS
kswordArkDriverQueueInitialize(
    _In_ WDFDEVICE device,
    _In_ BOOLEAN powerManaged
    );

VOID
kswordArkDriverDispatchDeviceControl(
    _In_ WDFDEVICE device,
    _In_opt_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _In_ size_t inputBufferLength,
    _In_ ULONG ioControlCode
    );

// Events from the IoQueue object
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL kswordArkDriverEvtIoDeviceControl;
EVT_WDF_IO_IN_CALLER_CONTEXT kswordArkDriverEvtIoInCallerContext;
EVT_WDF_IO_QUEUE_IO_READ kswordArkDriverEvtIoRead;
EVT_WDF_IO_QUEUE_IO_STOP kswordArkDriverEvtIoStop;

EXTERN_C_END

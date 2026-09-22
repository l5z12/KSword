/*++

Module Name:

    ioctl_dispatch.c

Abstract:

    Thin IOCTL dispatch for the default queue. Business behavior is implemented
    in feature-owned handler files registered through ioctl_registry.c.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ioctl_registry.h"
#include "ioctl_dispatch.tmh"

#include <ntstrsafe.h>
#include <stdarg.h>

static VOID
kswordArkDispatchLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one dispatch-level log line. Feature-specific details are
    logged in each handler; dispatch logs routing and unsupported-control cases.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored so completion still occurs.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

VOID
kswordArkDriverDispatchDeviceControl(
    _In_ WDFDEVICE device,
    _In_opt_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _In_ size_t inputBufferLength,
    _In_ ULONG ioControlCode
    )
/*++

Routine Description:

    Route IRP_MJ_DEVICE_CONTROL requests to a registered feature handler. The
    dispatch layer owns lookup, completion, and common tracing only.

Arguments:

    Queue - Handle to the queue object.
    Request - Handle to a framework request object.
    OutputBufferLength - Size of output buffer in bytes.
    InputBufferLength - Size of input buffer in bytes.
    IoControlCode - I/O control code.

Return Value:

    None. The request is completed unless a handler returns STATUS_PENDING.

--*/
{
    const KswordArkIoctlEntry* ioctlEntry = NULL;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    size_t completeBytes = 0;

    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p OutputBufferLength %d InputBufferLength %d IoControlCode %d",
        queue,
        request,
        (int)outputBufferLength,
        (int)inputBufferLength,
        ioControlCode);

    ioctlEntry = kswordArkLookupIoctlEntry(ioControlCode);
    if (ioctlEntry == NULL || ioctlEntry->handler == NULL) {
        kswordArkDispatchLog(device, "Warn", "Unsupported ioctl=0x%08X.", (unsigned int)ioControlCode);
        WdfRequestCompleteWithInformation(request, status, completeBytes);
        return;
    }

    if (!kswordArkCapabilityIsIoctlAllowed(ioctlEntry->requiredCapability, &status)) {
        kswordArkDispatchLog(
            device,
            "Warn",
            "IOCTL denied by capability gate: name=%s, code=0x%08X, required=0x%I64X, status=0x%08X.",
            ioctlEntry->name != NULL ? ioctlEntry->name : "<unnamed>",
            (unsigned int)ioctlEntry->ioControlCode,
            ioctlEntry->requiredCapability,
            (unsigned int)status);
        kswordArkCapabilityRecordLastError(status, "ioctl_dispatch", "IOCTL denied by DynData capability gate.");
        WdfRequestCompleteWithInformation(request, status, completeBytes);
        return;
    }

    status = ioctlEntry->handler(device, request, inputBufferLength, outputBufferLength, &completeBytes);
    if ((ioctlEntry->flags & KSWORD_ARK_IOCTL_FLAG_QUIET_COMPLETION) == 0UL &&
        !((ioctlEntry->flags & KSWORD_ARK_IOCTL_FLAG_QUIET_SUCCESS) != 0UL &&
        (NT_SUCCESS(status) || status == STATUS_PENDING)) &&
        !((ioctlEntry->flags & KSWORD_ARK_IOCTL_FLAG_QUIET_INVALID_CID) != 0UL &&
        status == STATUS_INVALID_CID)) {
        kswordArkDispatchLog(
            device,
            NT_SUCCESS(status) || status == STATUS_PENDING ? "Info" : "Warn",
            "IOCTL complete: name=%s, code=0x%08X, status=0x%08X, in=%Iu, out=%Iu, bytes=%Iu.",
            ioctlEntry->name != NULL ? ioctlEntry->name : "<unnamed>",
            (unsigned int)ioctlEntry->ioControlCode,
            (unsigned int)status,
            inputBufferLength,
            outputBufferLength,
            completeBytes);
    }

    if (status != STATUS_PENDING) {
        WdfRequestCompleteWithInformation(request, status, completeBytes);
    }
}

VOID
kswordArkDriverEvtIoDeviceControl(
    _In_ WDFQUEUE queue,
    _In_ WDFREQUEST request,
    _In_ size_t outputBufferLength,
    _In_ size_t inputBufferLength,
    _In_ ULONG ioControlCode
    )
{
    kswordArkDriverDispatchDeviceControl(
        WdfIoQueueGetDevice(queue),
        queue,
        request,
        outputBufferLength,
        inputBufferLength,
        ioControlCode);
}

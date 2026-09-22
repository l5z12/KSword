/*++

Module Name:

    log_channel.c

Abstract:

    This file contains log ring buffer helper functions.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "log_channel.tmh"

#include <ntstrsafe.h>

#include "KswordArkLogProtocol.h"

// Increment ring index and wrap around at queue capacity.
static ULONG
kswordArkDriverAdvanceRingIndex(
    _In_ ULONG currentIndex
    )
{
    return (currentIndex + 1U) % KSWORD_ARK_LOG_RING_CAPACITY;
}

NTSTATUS
kswordArkDriverInitializeLogChannel(
    _In_ WDFDEVICE device
    )
{
    PdeviceContext deviceContext = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    WDF_OBJECT_ATTRIBUTES spinLockAttributes;

    if (device == WDF_NO_HANDLE) {
        return STATUS_INVALID_PARAMETER;
    }

    deviceContext = DeviceGetContext(device);
    if (deviceContext == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (deviceContext->logQueueLock != WDF_NO_HANDLE) {
        return STATUS_SUCCESS;
    }

    WDF_OBJECT_ATTRIBUTES_INIT(&spinLockAttributes);
    spinLockAttributes.ParentObject = device;
    status = WdfSpinLockCreate(&spinLockAttributes, &deviceContext->logQueueLock);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "WdfSpinLockCreate failed %!STATUS!", status);
        return status;
    }

    deviceContext->logQueueHeadIndex = 0U;
    deviceContext->logQueueTailIndex = 0U;
    deviceContext->logQueueCount = 0U;
    RtlZeroMemory(deviceContext->logEntryLength, sizeof(deviceContext->logEntryLength));
    RtlZeroMemory(deviceContext->logEntryText, sizeof(deviceContext->logEntryText));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnqueueLogLine(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR formattedLogLine
    )
{
    PdeviceContext deviceContext = NULL;
    size_t lineLengthBytes = 0;
    ULONG slotIndex = 0;

    if (device == WDF_NO_HANDLE || formattedLogLine == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    deviceContext = DeviceGetContext(device);
    if (deviceContext == NULL || deviceContext->logQueueLock == WDF_NO_HANDLE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!NT_SUCCESS(RtlStringCbLengthA(
        formattedLogLine,
        KSWORD_ARK_LOG_ENTRY_MAX_BYTES,
        &lineLengthBytes))) {
        lineLengthBytes = KSWORD_ARK_LOG_ENTRY_MAX_BYTES - 1U;
    }

    WdfSpinLockAcquire(deviceContext->logQueueLock);

    slotIndex = deviceContext->logQueueTailIndex;
    RtlZeroMemory(deviceContext->logEntryText[slotIndex], KSWORD_ARK_LOG_ENTRY_MAX_BYTES);
    if (lineLengthBytes > 0U) {
        RtlCopyMemory(deviceContext->logEntryText[slotIndex], formattedLogLine, lineLengthBytes);
    }
    deviceContext->logEntryText[slotIndex][lineLengthBytes] = '\0';
    deviceContext->logEntryLength[slotIndex] = (ULONG)lineLengthBytes;

    if (deviceContext->logQueueCount == KSWORD_ARK_LOG_RING_CAPACITY) {
        deviceContext->logQueueHeadIndex =
            kswordArkDriverAdvanceRingIndex(deviceContext->logQueueHeadIndex);
    }
    else {
        deviceContext->logQueueCount += 1U;
    }

    deviceContext->logQueueTailIndex =
        kswordArkDriverAdvanceRingIndex(deviceContext->logQueueTailIndex);

    WdfSpinLockRelease(deviceContext->logQueueLock);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnqueueLogFrame(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    )
{
    CHAR frameBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    PCSTR safeLevelText = (levelText != NULL) ? levelText : "Info";
    PCSTR safeMessageText = (messageText != NULL) ? messageText : "";
    NTSTATUS status = STATUS_SUCCESS;

    status = RtlStringCbPrintfA(
        frameBuffer,
        sizeof(frameBuffer),
        "[%s]%s%s",
        safeLevelText,
        safeMessageText,
        KSWORD_ARK_LOG_END_MARKER);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE, "RtlStringCbPrintfA failed %!STATUS!", status);
        return status;
    }

    return kswordArkDriverEnqueueLogLine(device, frameBuffer);
}

NTSTATUS
kswordArkDriverReadNextLogLine(
    _In_ WDFDEVICE device,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
{
    PdeviceContext deviceContext = NULL;
    ULONG slotIndex = 0;
    ULONG lineLength = 0;

    if (bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (device == WDF_NO_HANDLE || outputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    deviceContext = DeviceGetContext(device);
    if (deviceContext == NULL || deviceContext->logQueueLock == WDF_NO_HANDLE) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    WdfSpinLockAcquire(deviceContext->logQueueLock);

    if (deviceContext->logQueueCount == 0U) {
        WdfSpinLockRelease(deviceContext->logQueueLock);
        return STATUS_NO_MORE_ENTRIES;
    }

    slotIndex = deviceContext->logQueueHeadIndex;
    lineLength = deviceContext->logEntryLength[slotIndex];
    if (outputBufferLength < lineLength) {
        WdfSpinLockRelease(deviceContext->logQueueLock);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (lineLength > 0U) {
        RtlCopyMemory(outputBuffer, deviceContext->logEntryText[slotIndex], lineLength);
    }
    *bytesWrittenOut = lineLength;

    deviceContext->logEntryLength[slotIndex] = 0U;
    deviceContext->logEntryText[slotIndex][0] = '\0';
    deviceContext->logQueueHeadIndex =
        kswordArkDriverAdvanceRingIndex(deviceContext->logQueueHeadIndex);
    deviceContext->logQueueCount -= 1U;

    WdfSpinLockRelease(deviceContext->logQueueLock);
    return STATUS_SUCCESS;
}

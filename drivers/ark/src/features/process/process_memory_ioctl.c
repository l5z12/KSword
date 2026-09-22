/*++

Module Name:

    process_memory_ioctl.c

Abstract:

    IOCTL handlers for Phase-11 read-only process memory operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#define KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data)
#define KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data)
#define KSWORD_ARK_MEMORY_IOCTL_POOL_TAG 'iMsK'

static VOID
kswordArkMemoryIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Write Phase-11 memory IOCTL diagnostic log. Note: Only PID, address, status, and byte count
    are recorded; the read data is excluded to prevent leaking the target process's content.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level text.
    FormatText: printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. Log failure does not affect IOCTL completion.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
kswordArkMemoryIoctlQueryVirtualMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY. Note: The handler is only
    responsible for WDF buffer acquisition and validating PID, flags, and base
    address; the actual ZwQueryVirtualMemory query is performed by process_memory.c.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const ULONG kAllowedFlags = KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 query-vm ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED uses the same SystemBuffer for input and output; the backend clears the output before reading
     * processId/baseAddress. Without a snapshot, it would enumerate error intervals from incorrect processes.
     */
    queryRequest = (KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if ((queryRequest->flags & ~kAllowedFlags) != 0UL) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 query-vm ioctl: flags rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    status = kswordArkValidateUserPid(queryRequest->processId);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 query-vm ioctl: pid rejected, pid=%lu.", (unsigned long)queryRequest->processId);
        return status;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 query-vm ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryVirtualMemory(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 query-vm failed: pid=%lu, address=0x%I64X, status=0x%08X.", (unsigned long)queryRequest->processId, queryRequest->baseAddress, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE* response = (KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        kswordArkMemoryIoctlLog(
            device,
            "Info",
            "R0 query-vm success: pid=%lu, address=0x%I64X, status=%lu, fields=0x%08X.",
            (unsigned long)response->processId,
            response->requestedBaseAddress,
            (unsigned long)response->queryStatus,
            (unsigned int)response->fieldFlags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlReadVirtualMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY. Note: The first version is read-only; it does not support write,
    allocation, or protection modification. Read failures are reported to R3 via response->readStatus/copyStatus.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST* readRequest = NULL;
    KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST readRequestValue;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 read-vm ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    readRequest = (KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST*)inputBuffer;
    RtlZeroMemory(&readRequestValue, sizeof(readRequestValue));
    RtlCopyMemory(&readRequestValue, readRequest, sizeof(readRequestValue));

    if ((readRequestValue.flags & ~(
        KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE |
        KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS)) != 0UL) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 read-vm ioctl: flags rejected, flags=0x%08X.", (unsigned int)readRequestValue.flags);
        return STATUS_INVALID_PARAMETER;
    }
    if ((readRequestValue.flags & KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS) == 0UL) {
        status = kswordArkValidateUserPid(readRequestValue.processId);
        if (!NT_SUCCESS(status)) {
            kswordArkMemoryIoctlLog(device, "Warn", "R0 read-vm ioctl: pid rejected, pid=%lu.", (unsigned long)readRequestValue.processId);
            return status;
        }
    }
    if (readRequestValue.bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 read-vm ioctl: size rejected, pid=%lu, bytes=%lu.", (unsigned long)readRequestValue.processId, (unsigned long)readRequestValue.bytesToRead);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 read-vm ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverReadVirtualMemory(
        outputBuffer,
        actualOutputLength,
        &readRequestValue,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 read-vm failed: pid=%lu, address=0x%I64X, bytes=%lu, status=0x%08X.", (unsigned long)readRequestValue.processId, readRequestValue.baseAddress, (unsigned long)readRequestValue.bytesToRead, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE* response = (KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        kswordArkMemoryIoctlLog(
            device,
            "Info",
            "R0 read-vm success: pid=%lu, address=0x%I64X, status=%lu, requested=%lu, read=%lu.",
            (unsigned long)response->processId,
            response->requestedBaseAddress,
            (unsigned long)response->readStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesRead);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlWriteVirtualMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY. Note: This handler accepts only R3-confirmed differential
    block write requests and completes access permission, length, and policy checks before entering the feature.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation, safety policy or feature backend.

--*/
{
    KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* writeRequest = NULL;
    KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* writeRequestCopy = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    const ULONG kAllowedFlags =
        KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE |
        KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS;
    BOOLEAN writeKernelAddress = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm ioctl denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 write-vm ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    writeRequest = (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*)inputBuffer;
    if ((writeRequest->flags & ~kAllowedFlags) != 0UL) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm ioctl: flags rejected, flags=0x%08X.", (unsigned int)writeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    writeKernelAddress =
        ((writeRequest->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS) != 0UL) ? TRUE : FALSE;
    if (!writeKernelAddress) {
        status = kswordArkValidateUserPid(writeRequest->processId);
        if (!NT_SUCCESS(status)) {
            kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm ioctl: pid rejected, pid=%lu.", (unsigned long)writeRequest->processId);
            return status;
        }
    }
    if (writeRequest->bytesToWrite == 0UL ||
        writeRequest->bytesToWrite > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm ioctl: size rejected, pid=%lu, bytes=%lu.", (unsigned long)writeRequest->processId, (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    if ((SIZE_T)writeRequest->bytesToWrite >
        (MAXSIZE_T - KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE)) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm ioctl: size overflow rejected, bytes=%lu.", (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    requiredInputLength =
        KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE +
        (SIZE_T)writeRequest->bytesToWrite;
    if (actualInputLength < requiredInputLength) {
        kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm ioctl: input truncated, actual=%Iu, required=%Iu.", actualInputLength, requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * METHOD_BUFFERED may alias the input and output system buffers.  Copy the
     * variable-length write request before retrieving/clearing the output
     * buffer, otherwise RtlZeroMemory(outputBuffer) can erase request->data.
     */
    writeRequestCopy = (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*)kswordArkAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
    if (writeRequestCopy == NULL) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 write-vm ioctl: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writeRequestCopy, writeRequest, requiredInputLength);
    writeRequest = writeRequestCopy;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 write-vm ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
        return status;
    }

    if ((writeRequest->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE) == 0UL) {
        KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        RtlZeroMemory(outputBuffer, actualOutputLength);
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->processId = writeKernelAddress ? 0UL : writeRequest->processId;
        response->fieldFlags =
            (writeKernelAddress
                ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
                : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE) |
            KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED;
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED;
        response->lookupStatus = STATUS_SUCCESS;
        response->copyStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->source = writeKernelAddress
            ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
            : KSWORD_ARK_MEMORY_SOURCE_R0_MM_WRITE_VIRTUAL_MEMORY;
        response->requestedBaseAddress = writeRequest->baseAddress;
        response->requestedBytes = writeRequest->bytesToWrite;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_WRITE_MAX_BYTES;
        *bytesReturned = sizeof(*response);
        kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm requires force confirmation: pid=%lu, flags=0x%08X, address=0x%I64X, bytes=%lu.", (unsigned long)writeRequest->processId, (unsigned int)writeRequest->flags, writeRequest->baseAddress, (unsigned long)writeRequest->bytesToWrite);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
        return STATUS_SUCCESS;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.targetProcessId = writeKernelAddress ? 0UL : writeRequest->processId;
        safetyContext.contextFlags =
            ((writeRequest->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE) != 0UL) ?
            KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED :
            0UL;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkMemoryIoctlLog(device, "Warn", "R0 write-vm denied by safety policy: pid=%lu, address=0x%I64X, bytes=%lu, status=0x%08X.", (unsigned long)writeRequest->processId, writeRequest->baseAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
            ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
            return status;
        }
    }

    status = kswordArkDriverWriteVirtualMemory(
        outputBuffer,
        actualOutputLength,
        writeRequest,
        actualInputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryIoctlLog(device, "Error", "R0 write-vm failed: pid=%lu, address=0x%I64X, bytes=%lu, status=0x%08X.", (unsigned long)writeRequest->processId, writeRequest->baseAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        kswordArkMemoryIoctlLog(
            device,
            "Info",
            "R0 write-vm success: pid=%lu, address=0x%I64X, status=%lu, requested=%lu, written=%lu.",
            (unsigned long)response->processId,
            response->requestedBaseAddress,
            (unsigned long)response->writeStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesWritten);
    }

    ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}

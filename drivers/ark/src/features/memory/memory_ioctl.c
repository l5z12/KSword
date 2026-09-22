/*++

Module Name:

    memory_ioctl.c

Abstract:

    IOCTL handlers for physical memory and page-table inspection operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_memory_evidence.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// Physical write requests include a trailing data[] array, which doesn't fit on the stack; use a pool copy instead. The tag matches other IOCTL copies.
#define KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG 'pMsK'

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

// The physical read response header does not include the trailing data[1]; the handler only requires R3 to provide at least the header space.
#define KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE) - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)0)->data))

// The physical write request header does not include the trailing data[1]; the handler uses it to calculate the full input length.
#define KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST) - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)0)->data))

// The kernel executable page scan response header does not include trailing entries[1].
#define KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY))

// Kernel executable scan v1 request prefix, allowing legacy R3 callers to pass only flags, maxEntries, start, and end.
#define KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE \
    FIELD_OFFSET(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST, maxBytes)

// The kernel memory evidence scan response header does not include trailing rows[1].
#define KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))

static VOID
kswordArkMemoryToolIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Diagnostic log for IOCTLs that write to physical memory/PTE. Note: The log records only the address, length,
    status, and PID, not the physical memory content, to avoid writing sensitive bytes into the ring buffer.

Arguments:

    Device - WDF device object used for dispatching logs.
    levelText - Log level text.
    FormatText: printf-style ANSI format string.
    ... - Format arguments.

Return Value:

    None. Log failure does not affect IOCTL request completion.

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
kswordArkMemoryIoctlReadPhysicalMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY. Note: the handler is responsible for WDF buffer retrieval,
    initial flags/length screening, and read access validation; actual MmCopyMemory reading occurs in the backend.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or kswordArkDriverReadPhysicalMemory.

--*/
{
    KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST* readRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST),
        (PVOID*)&readRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 read-physical ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED uses the same SystemBuffer for input and output; the backend first clears the
     * output buffer with RtlZeroMemory, then reads physicalAddress/bytesToRead. Without a snapshot, the
     * response header bytes would be misinterpreted as the physical address and length for MmCopyMemory.
     */
    RtlCopyMemory(&requestSnapshot, readRequest, sizeof(requestSnapshot));
    readRequest = &requestSnapshot;

    if (readRequest->flags != 0UL ||
        readRequest->reserved != 0UL ||
        readRequest->reserved2 != 0UL) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 read-physical ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)readRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (readRequest->bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 read-physical ioctl: size rejected, pa=0x%I64X, bytes=%lu.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 read-physical ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverReadPhysicalMemory(
        outputBuffer,
        actualOutputLength,
        readRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 read-physical failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        kswordArkMemoryToolIoctlLog(
            device,
            "Info",
            "R0 read-physical response: pa=0x%I64X, status=%lu, requested=%lu, read=%lu.",
            response->requestedPhysicalAddress,
            (unsigned long)response->readStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesRead);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlScanKernelExecutableMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY. Note: The handler performs only METHOD_BUFFERED
    buffer retrieval, initial filtering of flags/range, and logging; the actual scanning is a read-only backend
    that does not write PTEs, does not modify CR0, and does not guarantee full kernel address space coverage.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength - input length; if omitted, use the default conservative full-module scan.
    OutputBufferLength - Output length; WDF re-confirmation.
    BytesReturned - number of bytes in the response.

Return Value:

    NTSTATUS from buffer validation or kswordArkDriverScanKernelExecutableMemory.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* scanRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST defaultRequest;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST scanRequestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&scanRequestCopy, sizeof(scanRequestCopy));
    defaultRequest.flags = KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE,
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 scan-kernel-exec ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }
    if (hasInput &&
        actualInputLength > KSWORD_ARK_KERNEL_EXEC_SCAN_REQUEST_V1_SIZE &&
        actualInputLength < sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST)) {
        kswordArkMemoryToolIoctlLog(
            device,
            "Warn",
            "R0 scan-kernel-exec ioctl: partial v2 input rejected, actual=%Iu.",
            actualInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    if (hasInput) {
        size_t bytesToCopy = actualInputLength;
        if (bytesToCopy > sizeof(scanRequestCopy)) {
            bytesToCopy = sizeof(scanRequestCopy);
        }
        RtlCopyMemory(&scanRequestCopy, inputBuffer, bytesToCopy);
    }
    scanRequest = hasInput ? &scanRequestCopy : &defaultRequest;
    if ((scanRequest->flags & ~KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL) != 0UL ||
        scanRequest->reserved0 != 0UL ||
        (scanRequest->startAddress != 0ULL &&
            scanRequest->endAddress != 0ULL &&
            scanRequest->endAddress <= scanRequest->startAddress) ||
        scanRequest->maxBytes > KSWORD_ARK_KERNEL_EXEC_SCAN_HARD_MAX_BYTES ||
        scanRequest->hashBytes > KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX) {
        kswordArkMemoryToolIoctlLog(
            device,
            "Warn",
            "R0 scan-kernel-exec ioctl: flags/range/budget rejected, flags=0x%08X, start=0x%I64X, end=0x%I64X.",
            (unsigned int)scanRequest->flags,
            scanRequest->startAddress,
            scanRequest->endAddress);
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Note: This IOCTL uses METHOD_BUFFERED, so input and output may share the same SystemBuffer. The
     * backend clears the response buffer, so the request must be copied before retrieving the output buffer.
     */
    if (!hasInput) {
        RtlCopyMemory(&scanRequestCopy, scanRequest, sizeof(scanRequestCopy));
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 scan-kernel-exec ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverScanKernelExecutableMemory(
        outputBuffer,
        actualOutputLength,
        &scanRequestCopy,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 scan-kernel-exec failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE* response =
            (KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*)outputBuffer;
        kswordArkMemoryToolIoctlLog(
            device,
            "Info",
            "R0 scan-kernel-exec response: status=%lu, total=%lu, returned=%lu, modules=%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount,
            (unsigned long)response->moduleCount,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlWritePhysicalMemory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY. Note: Writing to physical memory requires FILE_WRITE_ACCESS,
    FORCE confirmation, and safety policy approval; the backend then performs the mapped write.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation, safety policy or kswordArkDriverWritePhysicalMemory.

--*/
{
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* writeRequest = NULL;
    // writeRequestCopy is a complete pool copy of the request header plus trailing data[], with variable length so it cannot be placed on the stack.
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* writeRequestCopy = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    const ULONG kAllowedFlags =
        KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED |
        KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE,
        (PVOID*)&writeRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 write-physical ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if ((writeRequest->flags & ~kAllowedFlags) != 0UL ||
        writeRequest->reserved != 0UL ||
        writeRequest->reserved2 != 0UL) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)writeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (writeRequest->bytesToWrite == 0UL ||
        writeRequest->bytesToWrite > KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical ioctl: size rejected, pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }
    if ((SIZE_T)writeRequest->bytesToWrite >
        (MAXSIZE_T - KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE)) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical ioctl: size overflow rejected, bytes=%lu.", (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }

    requiredInputLength =
        KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE +
        (SIZE_T)writeRequest->bytesToWrite;
    if (actualInputLength < requiredInputLength) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical ioctl: input truncated, actual=%Iu, required=%Iu.", actualInputLength, requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * METHOD_BUFFERED input and output share the same SystemBuffer. The backend first zero-fills
     * the output buffer via RtlZeroMemory, then reads physicalAddress/bytesToWrite and
     * Copy Request->data into the mapped page; failing to copy first treats response header
     * bytes as a physical address, writing response content into incorrect physical memory.
     */
    writeRequestCopy = (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)kswordArkAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
    if (writeRequestCopy == NULL) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 write-physical ioctl: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writeRequestCopy, writeRequest, requiredInputLength);
    writeRequest = writeRequestCopy;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 write-physical ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return status;
    }

    if ((writeRequest->flags & KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE) == 0UL) {
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        RtlZeroMemory(outputBuffer, actualOutputLength);
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        response->fieldFlags =
            KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT |
            KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED;
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED;
        response->mapStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->copyStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->source = KSWORD_ARK_MEMORY_SOURCE_R0_MM_MAP_PHYSICAL_MEMORY;
        response->requestedBytes = writeRequest->bytesToWrite;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES;
        response->requestedPhysicalAddress = writeRequest->physicalAddress;
        *bytesReturned = sizeof(*response);
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical requires force confirmation: pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return STATUS_SUCCESS;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.targetProcessId = 0UL;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkMemoryToolIoctlLog(device, "Warn", "R0 write-physical denied by safety policy: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
            ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
            return status;
        }
    }

    // The backend only sees the pool copy; length must be updated to the copy's length, not the SystemBuffer length.
    status = kswordArkDriverWritePhysicalMemory(
        outputBuffer,
        actualOutputLength,
        writeRequest,
        requiredInputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 write-physical failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE)) {
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response =
            (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
        kswordArkMemoryToolIoctlLog(
            device,
            "Info",
            "R0 write-physical response: pa=0x%I64X, status=%lu, requested=%lu, written=%lu.",
            response->requestedPhysicalAddress,
            (unsigned long)response->writeStatus,
            (unsigned long)response->requestedBytes,
            (unsigned long)response->bytesWritten);
    }

    ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_MEMORY_TOOL_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlScanKernelMemoryEvidence(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle unregistered IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE. Note: Session 6 is unified in
    ioctl_registry.c; the current handler only performs METHOD_BUFFERED input copy, initial screening of
    flags/range/cost limits, PASSIVE_LEVEL constraints, and logging. The backend performs read-only collection
    of PTE, BigPool, and module section samples; it does not write PTEs, modify CR0, or write to kernel memory.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; if omitted, use the default read-only full-source scan request.
    OutputBufferLength - Output length; WDF re-confirmation.
    BytesReturned - number of bytes in the response.

Return Value:

    NTSTATUS from buffer validation or kswordArkDriverScanKernelMemoryEvidence.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* evidenceRequest = NULL;
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST defaultRequest;
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    const ULONG kAllowedFlags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 memory-evidence ioctl rejected: non-passive IRQL.");
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&defaultRequest, sizeof(defaultRequest));
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    defaultRequest.flags =
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    defaultRequest.maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS;
    defaultRequest.maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES;
    defaultRequest.maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS;
    defaultRequest.sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES;

    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 memory-evidence ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    evidenceRequest = hasInput ?
        (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST*)inputBuffer :
        &defaultRequest;
    if ((evidenceRequest->flags & ~kAllowedFlags) != 0UL ||
        evidenceRequest->reserved0 != 0UL ||
        evidenceRequest->reserved1 != 0UL ||
        (evidenceRequest->startAddress != 0ULL &&
            evidenceRequest->endAddress != 0ULL &&
            evidenceRequest->endAddress <= evidenceRequest->startAddress) ||
        (evidenceRequest->maxRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) ||
        (evidenceRequest->maxBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES) ||
        (evidenceRequest->maxBigPoolRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS) ||
        (evidenceRequest->sampleBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_SAMPLE_BYTES) ||
        ((evidenceRequest->flags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL &&
            (evidenceRequest->startAddress == 0ULL ||
                evidenceRequest->endAddress == 0ULL ||
                evidenceRequest->endAddress <= evidenceRequest->startAddress))) {
        kswordArkMemoryToolIoctlLog(
            device,
            "Warn",
            "R0 memory-evidence ioctl rejected: flags=0x%08X, start=0x%I64X, end=0x%I64X.",
            (unsigned int)evidenceRequest->flags,
            evidenceRequest->startAddress,
            evidenceRequest->endAddress);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&requestCopy, evidenceRequest, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 memory-evidence ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverScanKernelMemoryEvidence(
        outputBuffer,
        actualOutputLength,
        &requestCopy,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 memory-evidence failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *bytesReturned);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* response =
            (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*)outputBuffer;
        kswordArkMemoryToolIoctlLog(
            device,
            "Info",
            "R0 memory-evidence response: status=%lu, total=%lu, returned=%lu, modules=%lu, bigpool=%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->totalRows,
            (unsigned long)response->returnedRows,
            (unsigned long)response->moduleCount,
            (unsigned long)response->bigPoolRowsSeen,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlTranslateVirtualAddress(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS. Note: The handler performs only buffering
    and flags validation; actual CR3/page table read-only traversal is performed by the backend.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or kswordArkDriverTranslateVirtualAddress.

--*/
{
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST* translateRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST),
        (PVOID*)&translateRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 translate-va ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input and output share the same SystemBuffer; the backend clears the output before
     * reading processId/virtualAddress. Without a snapshot, an incorrect address will be translated.
     */
    RtlCopyMemory(&requestSnapshot, translateRequest, sizeof(requestSnapshot));
    translateRequest = &requestSnapshot;

    if (translateRequest->flags != 0UL || translateRequest->reserved != 0UL) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 translate-va ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)translateRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 translate-va ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverTranslateVirtualAddress(
        outputBuffer,
        actualOutputLength,
        translateRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 translate-va failed: pid=%lu, va=0x%I64X, status=0x%08X.", (unsigned long)translateRequest->processId, translateRequest->virtualAddress, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE)) {
        KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE* response =
            (KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE*)outputBuffer;
        kswordArkMemoryToolIoctlLog(
            device,
            "Info",
            "R0 translate-va response: pid=%lu, va=0x%I64X, resolved=%lu, status=%lu, pa=0x%I64X.",
            (unsigned long)response->info.processId,
            response->info.virtualAddress,
            (unsigned long)response->info.resolved,
            (unsigned long)response->info.queryStatus,
            response->info.physicalAddress);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlQueryPageTableEntry(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY. Note: Returns raw PML4E/PDPTE/PDE/PTE values, flags,
    index, page size, and huge page type. Write capability for page tables is not provided by default.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or kswordArkDriverQueryPageTableEntry.

--*/
{
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST* queryRequest = NULL;
    // requestSnapshot: Saves the complete request before zeroing the shared SystemBuffer in the backend.
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST requestSnapshot;
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
        sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 query-pte ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * For METHOD_BUFFERED, input and output share the same SystemBuffer. The backend must zero the output before
     * reading processId/virtualAddress; otherwise, without a snapshot, it will read incorrect page table entries.
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if (queryRequest->flags != 0UL || queryRequest->reserved != 0UL) {
        kswordArkMemoryToolIoctlLog(device, "Warn", "R0 query-pte ioctl: flags/reserved rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 query-pte ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryPageTableEntry(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMemoryToolIoctlLog(device, "Error", "R0 query-pte failed: pid=%lu, va=0x%I64X, status=0x%08X.", (unsigned long)queryRequest->processId, queryRequest->virtualAddress, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE)) {
        KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE* response =
            (KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE*)outputBuffer;
        kswordArkMemoryToolIoctlLog(
            device,
            "Info",
            "R0 query-pte response: pid=%lu, va=0x%I64X, resolved=%lu, status=%lu, pageSize=%lu.",
            (unsigned long)response->info.processId,
            response->info.virtualAddress,
            (unsigned long)response->info.resolved,
            (unsigned long)response->info.queryStatus,
            (unsigned long)response->info.pageSize);
    }

    return STATUS_SUCCESS;
}

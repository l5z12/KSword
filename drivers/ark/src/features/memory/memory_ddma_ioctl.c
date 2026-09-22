/*++

Module Name:

    memory_ddma_ioctl.c

Abstract:

    IOCTL handlers for the DDMA (Disk Direct Memory Access) backend.

    These handlers only manage WDF buffer acquisition, request snapshots, initial flag/length filtering, and
    write access validation; the actual disk DMA logic resides entirely in the backend of memory_ddma.c.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_ddma.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// DDMA write requests include a trailing data[] array with variable length, which cannot fit in a stack snapshot; use a pool copy instead.
#define KSWORD_ARK_DDMA_IOCTL_POOL_TAG 'iDsK'

// The header length must use the same criterion as memory_ddma.c: FIELD_OFFSET, not "sizeof(struct) -
// sizeof(trailing member)". The two differ by alignment padding at the end of the structure; mixing them causes R3
// parsing to misalign the entire block. See the note above the similarly named macro in memory_ddma.c for details.
#define KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE, entries)

#define KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE, data)

#define KSWORD_ARK_DDMA_WRITE_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST, data)

static VOID
kswordArkDdmaIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Write DDMA IOCTL diagnostic log. Note: The log records only disk serial number, physical
    address, temporary LBA, length, and status; it does not record memory content read or written.

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
kswordArkMemoryIoctlDdmaQueryCapability(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY. Note: Capability probing issues real ATA read commands to the disk, so it
    requires write access just like read/write operations. The probing itself only reads sectors and does not require write access.
    FORCE。

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation or kswordArkDriverDdmaQueryCapability.

--*/
{
    KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST* queryRequest = NULL;
    // requestSnapshot: Save the complete request before the backend clears the shared SystemBuffer.
    KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST requestSnapshot;
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

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma query denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST),
        (PVOID*)&queryRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma query: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED uses the same SystemBuffer for input and output; the backend first clears the output buffer
     * with RtlZeroMemory, then reads flags/scratchLba. Without a snapshot, the response header bytes would be
     * misinterpreted as the scratch LBA for ATA commands, potentially writing to completely unrelated disk sectors.
     */
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));
    queryRequest = &requestSnapshot;

    if ((queryRequest->flags & ~KSWORD_ARK_DDMA_QUERY_FLAG_ALLOWED) != 0UL ||
        queryRequest->reserved0 != 0UL ||
        queryRequest->reserved1 != 0UL) {

        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma query: flags/reserved rejected, flags=0x%08X.", (unsigned int)queryRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma query: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverDdmaQueryCapability(
        outputBuffer,
        actualOutputLength,
        queryRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma query failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_DDMA_QUERY_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE* response =
            (KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE*)outputBuffer;
        kswordArkDdmaIoctlLog(
            device,
            "Info",
            "R0 ddma query response: status=%lu, disks=%lu, ready=%lu, caps=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->returnedDisks,
            (unsigned long)response->readyDisks,
            (unsigned int)response->capabilityFlags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlDdmaReadPhysical(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handling IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL. Note: DDMA reads temporarily occupy disk sectors, constituting
    a destructive path; therefore, write access is required and must be evaluated by the safety policy.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation, safety policy or kswordArkDriverDdmaReadPhysical.

--*/
{
    KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST* readRequest = NULL;
    KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST requestSnapshot;
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

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma read denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST),
        (PVOID*)&readRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma read: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    // Similar to the query case: the backend first clears the shared SystemBuffer, so the request must be snapshot first.
    RtlCopyMemory(&requestSnapshot, readRequest, sizeof(requestSnapshot));
    readRequest = &requestSnapshot;

    if ((readRequest->flags & ~KSWORD_ARK_DDMA_READ_FLAG_ALLOWED) != 0UL ||
        readRequest->reserved0 != 0UL) {

        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma read: flags/reserved rejected, flags=0x%08X.", (unsigned int)readRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (readRequest->bytesToRead == 0UL ||
        readRequest->bytesToRead > KSWORD_ARK_DDMA_READ_MAX_BYTES) {

        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma read: size rejected, pa=0x%I64X, bytes=%lu.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma read: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    {
        // DDMA read requires writing to a disk buffer sector once; evaluate it as a memory write operation, not a memory read operation.
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.targetProcessId = 0UL;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma read denied by safety policy: pa=0x%I64X, status=0x%08X.", readRequest->physicalAddress, (unsigned int)status);
            return status;
        }
    }

    status = kswordArkDriverDdmaReadPhysical(
        outputBuffer,
        actualOutputLength,
        readRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma read failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", readRequest->physicalAddress, (unsigned long)readRequest->bytesToRead, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_DDMA_READ_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE* response =
            (KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE*)outputBuffer;
        kswordArkDdmaIoctlLog(
            device,
            "Info",
            "R0 ddma read response: pa=0x%I64X, lba=0x%I64X, disk=%lu, status=%lu, read=%lu, fields=0x%08X.",
            response->requestedPhysicalAddress,
            response->scratchLba,
            (unsigned long)response->diskIndex,
            (unsigned long)response->readStatus,
            (unsigned long)response->bytesRead,
            (unsigned int)response->fieldFlags);

        // Failure to restore the scratch sector is the most critical state and must be logged at the Error level.
        if ((response->fieldFlags & KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED) == 0UL &&
            response->backupStatus != STATUS_NOT_SUPPORTED) {

            kswordArkDdmaIoctlLog(
                device,
                "Error",
                "R0 ddma read: scratch sectors NOT restored, lba=0x%I64X, restoreStatus=0x%08X.",
                response->scratchLba,
                (unsigned int)response->restoreStatus);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMemoryIoctlDdmaWritePhysical(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handling IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL. Note: This is the most destructive path
    in this module, involving writes to both physical memory and disk temporary sectors. It
    requires triple authorization: write access, the FORCE flag, and safety policy approval.

Arguments:

    Device - WDF device object, used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength: input length; re-validated by WDF under METHOD_BUFFERED.
    OutputBufferLength - output length; under METHOD_BUFFERED, WDF performs validation again.
    BytesReturned - number of bytes written.

Return Value:

    NTSTATUS from validation, safety policy or kswordArkDriverDdmaWritePhysical.

--*/
{
    KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST* writeRequest = NULL;
    // Write request headers with trailing data[] have variable lengths and cannot fit on the stack; use a pool copy.
    KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST* writeRequestCopy = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma write denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_DDMA_WRITE_REQUEST_HEADER_SIZE,
        (PVOID*)&writeRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma write: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    if ((writeRequest->flags & ~KSWORD_ARK_DDMA_WRITE_FLAG_ALLOWED) != 0UL ||
        writeRequest->reserved0 != 0UL) {

        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma write: flags/reserved rejected, flags=0x%08X.", (unsigned int)writeRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (writeRequest->bytesToWrite == 0UL ||
        writeRequest->bytesToWrite > KSWORD_ARK_DDMA_WRITE_MAX_BYTES) {

        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma write: size rejected, pa=0x%I64X, bytes=%lu.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite);
        return STATUS_INVALID_PARAMETER;
    }

    requiredInputLength =
        KSWORD_ARK_DDMA_WRITE_REQUEST_HEADER_SIZE + (size_t)writeRequest->bytesToWrite;
    if (actualInputLength < requiredInputLength) {
        kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma write: input truncated, actual=%Iu, required=%Iu.", actualInputLength, requiredInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * METHOD_BUFFERED uses SystemBuffer for both input and output. The backend first clears the output, then reads
     * physicalAddress/scratchLba and sends Request->data to DMA. Failing to copy first means using the response header
     * bytes as addresses and data, causing the DMA to write response content directly into incorrect physical memory.
     */
    writeRequestCopy = (KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST*)kswordArkAllocateNonPagedPool(
        requiredInputLength,
        KSWORD_ARK_DDMA_IOCTL_POOL_TAG);
    if (writeRequestCopy == NULL) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma write: input copy allocation failed, bytes=%Iu.", requiredInputLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(writeRequestCopy, writeRequest, requiredInputLength);
    writeRequest = writeRequestCopy;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma write: output invalid, status=0x%08X.", (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_DDMA_IOCTL_POOL_TAG);
        return status;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_MEMORY_WRITE;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.targetProcessId = 0UL;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkDdmaIoctlLog(device, "Warn", "R0 ddma write denied by safety policy: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
            ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_DDMA_IOCTL_POOL_TAG);
            return status;
        }
    }

    // The backend only sees the pool copy; length must be updated to the copy's length, not the SystemBuffer length.
    status = kswordArkDriverDdmaWritePhysical(
        outputBuffer,
        actualOutputLength,
        writeRequest,
        requiredInputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkDdmaIoctlLog(device, "Error", "R0 ddma write failed: pa=0x%I64X, bytes=%lu, status=0x%08X.", writeRequest->physicalAddress, (unsigned long)writeRequest->bytesToWrite, (unsigned int)status);
        ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_DDMA_IOCTL_POOL_TAG);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE)) {
        KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE* response =
            (KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE*)outputBuffer;
        kswordArkDdmaIoctlLog(
            device,
            "Warn",
            "R0 ddma write response: pa=0x%I64X, lba=0x%I64X, disk=%lu, status=%lu, written=%lu, fields=0x%08X.",
            response->requestedPhysicalAddress,
            response->scratchLba,
            (unsigned long)response->diskIndex,
            (unsigned long)response->writeStatus,
            (unsigned long)response->bytesWritten,
            (unsigned int)response->fieldFlags);

        if ((response->fieldFlags & KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED) == 0UL &&
            response->backupStatus != STATUS_NOT_SUPPORTED) {

            kswordArkDdmaIoctlLog(
                device,
                "Error",
                "R0 ddma write: scratch sectors NOT restored, lba=0x%I64X, restoreStatus=0x%08X.",
                response->scratchLba,
                (unsigned int)response->restoreStatus);
        }
    }

    ExFreePoolWithTag(writeRequestCopy, KSWORD_ARK_DDMA_IOCTL_POOL_TAG);
    return STATUS_SUCCESS;
}

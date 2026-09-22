/*++

Module Name:

    process_memory.c

Abstract:

    Phase-11 read-only process virtual memory helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID object,
    _In_ ULONG handleAttributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_opt_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Out_ PHANDLE handle
    );

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS fromProcess,
    _In_reads_bytes_(bufferSize) PVOID fromAddress,
    _In_ PEPROCESS toProcess,
    _Out_writes_bytes_(bufferSize) PVOID toAddress,
    _In_ SIZE_T bufferSize,
    _In_ KPROCESSOR_MODE previousMode,
    _Out_ PSIZE_T numberOfBytesCopied
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryVirtualMemory(
    _In_ HANDLE processHandle,
    _In_opt_ PVOID baseAddress,
    _In_ ULONG memoryInformationClass,
    _Out_writes_bytes_(memoryInformationLength) PVOID memoryInformation,
    _In_ SIZE_T memoryInformationLength,
    _Out_opt_ PSIZE_T returnLength
    );

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE (0x0020)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION (0x0008)
#endif

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#ifndef STATUS_DATA_ERROR
#define STATUS_DATA_ERROR ((NTSTATUS)0xC000003EL)
#endif

#define KSWORD_ARK_MEMORY_BASIC_INFORMATION_CLASS 0UL
#define KSWORD_ARK_MEMORY_MAPPED_FILENAME_INFORMATION_CLASS 2UL
#define KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data)
#define KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data)

/*
 * KswordARKMemoryRwCanary
 * Inputs:
 * - No input; this is a dedicated exported writable test cell.
 * Processing:
 * - Kernel-memory read/write UI can target this address to verify the R0
 *   kernel VA read/write path without modifying real kernel state.
 * Return behavior:
 * - No function return; callers read/write its bytes through the normal memory
 *   IOCTL path.  The value is intentionally volatile and exported so it is kept
 *   in the image and can be located by RVA from the PE export table.
 */
__declspec(dllexport) volatile ULONGLONG kswordArkMemoryRwCanary =
    0x1122334455667788ULL;

typedef struct KswordArkMemoryBasicInformation
{
    PVOID baseAddress;
    PVOID allocationBase;
    ULONG allocationProtect;
    SIZE_T regionSize;
    ULONG state;
    ULONG protect;
    ULONG type;
} KswordArkMemoryBasicInformation;

typedef struct KswordArkMemoryMappedFileNameBuffer
{
    UNICODE_STRING name;
    WCHAR buffer[KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS];
} KswordArkMemoryMappedFileNameBuffer;

static BOOLEAN
kswordArkMemoryIsUserAddressRange(
    _In_ ULONG64 baseAddress,
    _In_ SIZE_T length
    )
/*++

Routine Description:

    Check if the read range is entirely within user address space. Note: Phase-11 v1 handles only process user
    virtual memory; the read-only path must not allow reading kernel addresses or forming wrap-around ranges.

Arguments:

    BaseAddress - Requested starting address.
    Length - Requested length, which may be zero.

Return Value:

    TRUE indicates the range can be passed to MmCopyVirtualMemory; FALSE indicates it should be rejected.

--*/
{
    ULONG64 endAddress = 0ULL;
    ULONG64 highestUserAddress = (ULONG64)(ULONG_PTR)MmHighestUserAddress;

    if (length == 0U) {
        return TRUE;
    }

    endAddress = baseAddress + (ULONG64)length - 1ULL;
    if (endAddress < baseAddress) {
        return FALSE;
    }

    return endAddress <= highestUserAddress;
}

static BOOLEAN
kswordArkMemoryIsKernelAddressRange(
    _In_ ULONG64 baseAddress,
    _In_ SIZE_T length
    )
/*++

Routine Description:

    Validate a kernel virtual-address read range without touching memory.
    Note: This check only validates the high half and wraparound, not page presence. Actual
    access is performed by MmCopyMemory to prevent bugchecks caused by invalid addresses.

Arguments:

    BaseAddress - Requested kernel virtual address.
    Length - Requested byte count.

Return Value:

    TRUE if the range is syntactically a kernel VA range.

--*/
{
    ULONG64 endAddress = 0ULL;
    ULONG64 highestUserAddress = (ULONG64)(ULONG_PTR)MmHighestUserAddress;

    if (length == 0U) {
        return TRUE;
    }

    endAddress = baseAddress + (ULONG64)length - 1ULL;
    if (endAddress < baseAddress) {
        return FALSE;
    }

    return baseAddress > highestUserAddress;
}

static NTSTATUS
kswordArkMemoryCopyKernelVirtualMemory(
    _In_ ULONG64 sourceAddress,
    _Out_writes_bytes_(bytesToRead) UCHAR* destination,
    _In_ SIZE_T bytesToRead,
    _Out_ SIZE_T* bytesCopiedOut
    )
/*++

Routine Description:

    Copy kernel virtual memory into a caller-owned response buffer. Note:
    Read kernel addresses using MmCopyMemory in virtual mode; the function is read-only and does not modify target memory.

Arguments:

    SourceAddress - Kernel virtual source address.
    Destination - Output buffer.
    BytesToRead - Bytes requested.
    BytesCopiedOut - Receives bytes copied by MmCopyMemory.

Return Value:

    STATUS_SUCCESS or the MmCopyMemory/exception status.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (destination == NULL || bytesCopiedOut == NULL || bytesToRead == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesCopiedOut = 0U;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)sourceAddress;
    __try {
        status = MmCopyMemory(
            destination,
            copyAddress,
            bytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copiedBytes = 0U;
    }

    *bytesCopiedOut = copiedBytes;
    return status;
}

static NTSTATUS
kswordArkMemoryWriteKernelVirtualMemory(
    _In_ ULONG64 destinationAddress,
    _In_reads_bytes_(bytesToWrite) const UCHAR* source,
    _In_ SIZE_T bytesToWrite,
    _Out_ SIZE_T* bytesWrittenOut
    )
/*++

Routine Description:

    Write bytes into kernel virtual memory under SEH protection. Note: This path
    is used only when R3 explicitly passes KERNEL_ADDRESS + FORCE; the function
    does not modify page protections, so the target page must already be writable.

Arguments:

    DestinationAddress - Kernel virtual destination address.
    Source - Caller-provided bytes from METHOD_BUFFERED input.
    BytesToWrite - Number of bytes to write.
    BytesWrittenOut - Receives bytes copied before failure.

Return Value:

    STATUS_SUCCESS when all bytes were written; otherwise an exception/status code.

--*/
{
    SIZE_T writeOffset = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (source == NULL || bytesWrittenOut == NULL || bytesToWrite == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    while (writeOffset < bytesToWrite) {
        volatile UCHAR* destinationByte =
            (volatile UCHAR*)(ULONG_PTR)(destinationAddress + (ULONG64)writeOffset);
        UCHAR verifyByte = 0U;

        /*
         * Use volatile byte stores and immediate read-back verification.  A
         * plain RtlCopyMemory can report no exception even when the caller later
         * observes unchanged data through a different path; verification makes
         * the IOCTL result reflect the actual persisted byte value.
         */
        __try {
            *destinationByte = source[writeOffset];
            KeMemoryBarrier();
            verifyByte = *destinationByte;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            break;
        }

        if (verifyByte != source[writeOffset]) {
            status = STATUS_DATA_ERROR;
            break;
        }

        writeOffset += 1U;
    }

    *bytesWrittenOut = writeOffset;
    return (writeOffset == bytesToWrite) ? STATUS_SUCCESS : status;
}

static NTSTATUS
kswordArkMemoryOpenProcessForQuery(
    _In_ ULONG processId,
    _In_ ACCESS_MASK desiredAccess,
    _Out_ HANDLE* processHandleOut,
    _Outptr_ PEPROCESS* processObjectOut
    )
/*++

Routine Description:

    Open the target process with read-only access to query required permissions while retaining the PEPROCESS reference.
    Note: First obtain the object via PID, then create a handle for the same object in KernelMode using ObOpenObjectByPointer
    to avoid the scenario where the PID exits and is reused, causing the query to target a different process.

Arguments:

    ProcessId - target PID.
    DesiredAccess: Required permissions for ZwQueryVirtualMemory/MmCopyVirtualMemory.
    ProcessHandleOut - Receives a kernel handle; the caller must call ZwClose.
    ProcessObjectOut - receives an EPROCESS reference; the caller must call ObDereferenceObject.

Return Value:

    STATUS_SUCCESS or a failure status from the underlying open/reference operation.

--*/
{
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (processHandleOut == NULL || processObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *processHandleOut = NULL;
    *processObjectOut = NULL;

    status = PsLookupProcessByProcessId(ULongToHandle(processId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * Bind the returned handle to the referenced process object. Reopening by
     * numeric PID after PsLookupProcessByProcessId can select a recycled PID.
     */
    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        desiredAccess,
        *PsProcessType,
        KernelMode,
        &processHandle);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    *processHandleOut = processHandle;
    *processObjectOut = processObject;
    return STATUS_SUCCESS;
}

static VOID
kswordArkMemoryCopyUnicodeStringToFixedBuffer(
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _In_opt_ const UNICODE_STRING* source,
    _Out_ ULONG* charsCopiedOut,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Safely copy UNICODE_STRING into the protocol's fixed-width character array. Note: The protocol array always
    retains a trailing null, allowing R3 to construct std::wstring/QString directly from length or the trailing null.

Arguments:

    Destination - Fixed target array.
    DestinationChars: Capacity of the target WCHAR array.
    Source: source UNICODE_STRING, which may be null.
    CharsCopiedOut - Number of characters copied, excluding trailing zeros.
    TruncatedOut - Indicates whether the receive was truncated.

Return Value:

    None.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG charsToCopy = 0UL;

    if (charsCopiedOut != NULL) {
        *charsCopiedOut = 0UL;
    }
    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    RtlZeroMemory(destination, (SIZE_T)destinationChars * sizeof(WCHAR));
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    sourceChars = (ULONG)(source->Length / sizeof(WCHAR));
    charsToCopy = sourceChars;
    if (charsToCopy >= destinationChars) {
        charsToCopy = destinationChars - 1UL;
        if (truncatedOut != NULL) {
            *truncatedOut = TRUE;
        }
    }

    if (charsToCopy > 0UL) {
        RtlCopyMemory(
            destination,
            source->Buffer,
            (SIZE_T)charsToCopy * sizeof(WCHAR));
    }
    if (charsCopiedOut != NULL) {
        *charsCopiedOut = charsToCopy;
    }
}

NTSTATUS
kswordArkDriverQueryVirtualMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query the virtual memory region containing a specific address in the target process. Note: This function
    only calls ZwQueryVirtualMemory; it does not read page contents or modify the target process. MappedFilename
    is an optional diagnostic field; failure does not result in loss of basic region information.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Length of the response buffer.
    Request - The request packet, containing PID, address, and flags.
    BytesWrittenOut - Receives the fixed response length.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; specific query results are written to response->queryStatus.

--*/
{
    KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE* response = NULL;
    KswordArkMemoryBasicInformation basicInformation;
    KswordArkMemoryMappedFileNameBuffer mappedNameBuffer;
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    SIZE_T returnedBytes = 0U;
    ULONG requestFlags = 0UL;
    BOOLEAN nameTruncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->processId == 0UL || request->processId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkMemoryIsUserAddressRange(request->baseAddress, 1U)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&basicInformation, sizeof(basicInformation));
    RtlZeroMemory(&mappedNameBuffer, sizeof(mappedNameBuffer));

    response = (KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = request->processId;
    response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE;
    response->openStatus = STATUS_SUCCESS;
    response->basicStatus = STATUS_NOT_SUPPORTED;
    response->mappedFileNameStatus = STATUS_NOT_SUPPORTED;
    response->source = KSWORD_ARK_MEMORY_SOURCE_R0_ZW_QUERY_VIRTUAL_MEMORY;
    response->requestedBaseAddress = request->baseAddress;
    response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE;

    requestFlags = request->flags;
    if (requestFlags == 0UL) {
        requestFlags = KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_ALL;
    }

    status = kswordArkMemoryOpenProcessForQuery(
        request->processId,
        PROCESS_QUERY_INFORMATION,
        &processHandle,
        &processObject);
    response->openStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_PROCESS_OPEN_FAILED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = ZwQueryVirtualMemory(
        processHandle,
        (PVOID)(ULONG_PTR)request->baseAddress,
        KSWORD_ARK_MEMORY_BASIC_INFORMATION_CLASS,
        &basicInformation,
        sizeof(basicInformation),
        &returnedBytes);
    response->basicStatus = status;
    if (NT_SUCCESS(status)) {
        response->baseAddress = (ULONG64)(ULONG_PTR)basicInformation.baseAddress;
        response->allocationBase = (ULONG64)(ULONG_PTR)basicInformation.allocationBase;
        response->allocationProtect = basicInformation.allocationProtect;
        response->regionSize = (ULONG64)basicInformation.regionSize;
        response->state = basicInformation.state;
        response->protect = basicInformation.protect;
        response->type = basicInformation.type;
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT;
    }
    else {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_QUERY_FAILED;
        goto Exit;
    }

    if ((requestFlags & KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME) != 0UL) {
        mappedNameBuffer.name.Buffer = mappedNameBuffer.buffer;
        mappedNameBuffer.name.Length = 0U;
        mappedNameBuffer.name.MaximumLength = (USHORT)sizeof(mappedNameBuffer.buffer);

        returnedBytes = 0U;
        status = ZwQueryVirtualMemory(
            processHandle,
            (PVOID)(ULONG_PTR)request->baseAddress,
            KSWORD_ARK_MEMORY_MAPPED_FILENAME_INFORMATION_CLASS,
            &mappedNameBuffer,
            sizeof(mappedNameBuffer),
            &returnedBytes);
        response->mappedFileNameStatus = status;
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
            kswordArkMemoryCopyUnicodeStringToFixedBuffer(
                response->mappedFileName,
                KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS,
                &mappedNameBuffer.name,
                &response->mappedFileNameLengthChars,
                &nameTruncated);
            if (response->mappedFileNameLengthChars > 0UL) {
                response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_MAPPED_FILE_NAME_PRESENT;
            }
            if (nameTruncated || status == STATUS_BUFFER_OVERFLOW) {
                response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_MAPPED_FILE_NAME_TRUNCATED;
            }
        }
        else {
            response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_NAME_FAILED;
        }
    }

Exit:
    if (processHandle != NULL) {
        ZwClose(processHandle);
        processHandle = NULL;
    }
    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }

    if (response->queryStatus == KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_OK;
    }
    else if ((response->fieldFlags & KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT) != 0UL &&
        response->queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_OK) {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_PARTIAL;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverReadVirtualMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Copy a memory segment from the target process's user address space into the response
    packet. Note: The first version was read-only using MmCopyVirtualMemory. Any failure writes
    to the response status; R3 displays the NTSTATUS within the view without popup spam.

Arguments:

    OutputBuffer - Response buffer, with data immediately following the header.
    OutputBufferLength - Length of the response buffer.
    Request - The request packet, containing PID, start address, and read length.
    BytesWrittenOut - Actual number of response bytes received.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; read failure details are written to response->readStatus.

--*/
{
    KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE* response = NULL;
    PEPROCESS processObject = NULL;
    SIZE_T bytesCopied = 0U;
    SIZE_T bytesAvailable = 0U;
    SIZE_T bytesToRead = 0U;
    BOOLEAN zeroFillUnreadable = FALSE;
    BOOLEAN readKernelAddress = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    readKernelAddress =
        ((request->flags & KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS) != 0UL) ? TRUE : FALSE;

    if (!readKernelAddress && (request->processId == 0UL || request->processId <= 4UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToRead == 0U) {
        RtlZeroMemory(outputBuffer, outputBufferLength);
        response = (KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->headerSize = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        response->processId = readKernelAddress ? 0UL : request->processId;
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        response->lookupStatus = STATUS_SUCCESS;
        response->copyStatus = STATUS_SUCCESS;
        response->source = readKernelAddress
            ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
            : KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_VIRTUAL_MEMORY;
        response->requestedBaseAddress = request->baseAddress;
        response->requestedBytes = 0UL;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
        response->fieldFlags |= readKernelAddress
            ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
            : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE;
        *bytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    if (readKernelAddress) {
        if (!kswordArkMemoryIsKernelAddressRange(request->baseAddress, (SIZE_T)request->bytesToRead)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (!kswordArkMemoryIsUserAddressRange(request->baseAddress, (SIZE_T)request->bytesToRead)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);

    response = (KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->headerSize = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
    response->processId = readKernelAddress ? 0UL : request->processId;
    response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE;
    response->lookupStatus = STATUS_SUCCESS;
    response->copyStatus = STATUS_NOT_SUPPORTED;
    response->source = readKernelAddress
        ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
        : KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_VIRTUAL_MEMORY;
    response->requestedBaseAddress = request->baseAddress;
    response->requestedBytes = request->bytesToRead;
    response->maxBytesPerRequest = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
    response->fieldFlags |= readKernelAddress
        ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
        : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE;
    zeroFillUnreadable =
        ((request->flags & KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE) != 0UL) ? TRUE : FALSE;

    bytesAvailable = outputBufferLength - KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
    bytesToRead = (SIZE_T)request->bytesToRead;
    if (bytesToRead > bytesAvailable) {
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_BUFFER_TOO_SMALL;
        *bytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (readKernelAddress) {
        SIZE_T copyOffset = 0U;
        SIZE_T readableBytes = 0U;
        NTSTATUS firstCopyFailure = STATUS_SUCCESS;
        BOOLEAN anyCopyFailure = FALSE;

        while (copyOffset < bytesToRead) {
            SIZE_T chunkBytes = bytesToRead - copyOffset;
            SIZE_T chunkCopied = 0U;
            NTSTATUS chunkStatus = STATUS_SUCCESS;

            if (chunkBytes > PAGE_SIZE) {
                chunkBytes = PAGE_SIZE;
            }

            chunkStatus = kswordArkMemoryCopyKernelVirtualMemory(
                request->baseAddress + (ULONG64)copyOffset,
                response->data + copyOffset,
                chunkBytes,
                &chunkCopied);
            readableBytes += chunkCopied;
            if (!NT_SUCCESS(chunkStatus) || chunkCopied != chunkBytes) {
                anyCopyFailure = TRUE;
                if (NT_SUCCESS(firstCopyFailure) && !NT_SUCCESS(chunkStatus)) {
                    firstCopyFailure = chunkStatus;
                }
            }
            copyOffset += chunkBytes;
        }

        if (anyCopyFailure && NT_SUCCESS(firstCopyFailure)) {
            firstCopyFailure = STATUS_PARTIAL_COPY;
        }
        response->copyStatus = anyCopyFailure ? firstCopyFailure : STATUS_SUCCESS;
        response->bytesRead = zeroFillUnreadable
            ? request->bytesToRead
            : (ULONG)readableBytes;
        bytesCopied = zeroFillUnreadable ? bytesToRead : readableBytes;

        if (bytesCopied > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT;
        }
        if (!anyCopyFailure && readableBytes == bytesToRead) {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        }
        else if (readableBytes > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
            if (zeroFillUnreadable) {
                response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
            }
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;
        }
        else {
            if (zeroFillUnreadable) {
                response->fieldFlags |=
                    KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT |
                    KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY |
                    KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
                bytesCopied = bytesToRead;
                response->bytesRead = request->bytesToRead;
                response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED;
            }
            else {
                response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED;
            }
        }

        *bytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE + bytesCopied;
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    response->lookupStatus = status;
    if (!NT_SUCCESS(status)) {
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED;
        *bytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (zeroFillUnreadable) {
        SIZE_T copyOffset = 0U;
        SIZE_T readableBytes = 0U;
        NTSTATUS firstCopyFailure = STATUS_SUCCESS;
        BOOLEAN anyCopyFailure = FALSE;

        while (copyOffset < bytesToRead) {
            SIZE_T chunkBytes = bytesToRead - copyOffset;
            SIZE_T chunkCopied = 0U;
            NTSTATUS chunkStatus = STATUS_SUCCESS;

            if (chunkBytes > PAGE_SIZE) {
                chunkBytes = PAGE_SIZE;
            }

            chunkStatus = MmCopyVirtualMemory(
                processObject,
                (PVOID)(ULONG_PTR)(request->baseAddress + (ULONG64)copyOffset),
                PsGetCurrentProcess(),
                response->data + copyOffset,
                chunkBytes,
                KernelMode,
                &chunkCopied);
            readableBytes += chunkCopied;
            if (!NT_SUCCESS(chunkStatus) || chunkCopied != chunkBytes) {
                anyCopyFailure = TRUE;
                if (NT_SUCCESS(firstCopyFailure) && !NT_SUCCESS(chunkStatus)) {
                    firstCopyFailure = chunkStatus;
                }
            }
            copyOffset += chunkBytes;
        }

        status = anyCopyFailure ? firstCopyFailure : STATUS_SUCCESS;
        response->copyStatus = status;
        response->bytesRead = request->bytesToRead;
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT;
        bytesCopied = bytesToRead;

        if (!anyCopyFailure && readableBytes == bytesToRead) {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        }
        else {
            response->fieldFlags |=
                KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY |
                KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
            response->readStatus = (readableBytes > 0U) ?
                KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY :
                KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED;
        }
    }
    else {
        status = MmCopyVirtualMemory(
            processObject,
            (PVOID)(ULONG_PTR)request->baseAddress,
            PsGetCurrentProcess(),
            response->data,
            bytesToRead,
            KernelMode,
            &bytesCopied);
        response->copyStatus = status;
        response->bytesRead = (ULONG)bytesCopied;
        if (bytesCopied > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT;
        }

        if (NT_SUCCESS(status) && bytesCopied == bytesToRead) {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        }
        else if (bytesCopied > 0U || status == STATUS_PARTIAL_COPY) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;
        }
        else {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED;
        }
    }

    ObDereferenceObject(processObject);
    processObject = NULL;

    *bytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE + bytesCopied;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverWriteVirtualMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* request,
    _In_ size_t requestBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Write difference blocks submitted by R3 to the target process's user address space. Note: The caller transmits only
    continuous change blocks already compared with the backup; R0 will still re-validate PID, range, length, and input buffer.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Length of the response buffer.
    Request - METHOD_BUFFERED input request; the header is immediately followed by the bytes to be written.
    RequestBufferLength - Actual input buffer length returned by WDF.
    BytesWrittenOut - Receives the fixed response length.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; write failure details are written to response->writeStatus.

--*/
{
    KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE* response = NULL;
    PEPROCESS processObject = NULL;
    SIZE_T bytesCopied = 0U;
    SIZE_T bytesToWrite = 0U;
    SIZE_T requiredInputBytes = 0U;
    BOOLEAN writeKernelAddress = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (requestBufferLength < KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    writeKernelAddress =
        ((request->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS) != 0UL) ? TRUE : FALSE;

    if (!writeKernelAddress && (request->processId == 0UL || request->processId <= 4UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToWrite == 0UL ||
        request->bytesToWrite > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    bytesToWrite = (SIZE_T)request->bytesToWrite;
    if (bytesToWrite > (MAXSIZE_T - KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE)) {
        return STATUS_INVALID_PARAMETER;
    }
    requiredInputBytes = KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE + bytesToWrite;
    if (requestBufferLength < requiredInputBytes) {
        return STATUS_INVALID_PARAMETER;
    }
    if (writeKernelAddress) {
        if (!kswordArkMemoryIsKernelAddressRange(request->baseAddress, bytesToWrite)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (!kswordArkMemoryIsUserAddressRange(request->baseAddress, bytesToWrite)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = writeKernelAddress ? 0UL : request->processId;
    response->fieldFlags =
        (writeKernelAddress
            ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
            : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE) |
        KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT;
    response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_UNAVAILABLE;
    response->lookupStatus = STATUS_SUCCESS;
    response->copyStatus = STATUS_NOT_SUPPORTED;
    response->source = writeKernelAddress
        ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
        : KSWORD_ARK_MEMORY_SOURCE_R0_MM_WRITE_VIRTUAL_MEMORY;
    response->requestedBaseAddress = request->baseAddress;
    response->requestedBytes = request->bytesToWrite;
    response->maxBytesPerRequest = KSWORD_ARK_MEMORY_WRITE_MAX_BYTES;

    if ((request->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_USED;
    }

    if (writeKernelAddress) {
        status = kswordArkMemoryWriteKernelVirtualMemory(
            request->baseAddress,
            request->data,
            bytesToWrite,
            &bytesCopied);
        response->copyStatus = status;
        response->bytesWritten = (ULONG)bytesCopied;

        if (NT_SUCCESS(status) && bytesCopied == bytesToWrite) {
            response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_OK;
        }
        else if (bytesCopied > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
            response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY;
        }
        else {
            response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_COPY_FAILED;
        }

        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    response->lookupStatus = status;
    if (!NT_SUCCESS(status)) {
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_PROCESS_LOOKUP_FAILED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)request->data,
        processObject,
        (PVOID)(ULONG_PTR)request->baseAddress,
        bytesToWrite,
        KernelMode,
        &bytesCopied);
    response->copyStatus = status;
    response->bytesWritten = (ULONG)bytesCopied;

    if (NT_SUCCESS(status) && bytesCopied == bytesToWrite) {
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_OK;
    }
    else if (bytesCopied > 0U || status == STATUS_PARTIAL_COPY) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY;
    }
    else {
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_COPY_FAILED;
    }

    ObDereferenceObject(processObject);
    processObject = NULL;

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

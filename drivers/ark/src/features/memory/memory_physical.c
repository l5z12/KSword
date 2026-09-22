/*++

Module Name:

    memory_physical.c

Abstract:

    R0 physical memory read/write helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

/* The physical read response header does not include the trailing data[1]; the caller interprets the return length as header + bytesRead. */
#define KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE) - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)0)->data))

/* The physical write request header does not include the trailing data[1], used to verify if METHOD_BUFFERED input is complete. */
#define KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE \
    (sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST) - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)0)->data))

// x64 page table formats currently support up to 52 physical address bits; higher bits are conservatively rejected to avoid LARGE_INTEGER sign extension risks.
#define KSWORD_ARK_PHYSICAL_ADDRESS_MAX 0x000FFFFFFFFFFFFFULL

static BOOLEAN
kswordArkPhysicalIsRangeValid(
    _In_ ULONG64 physicalAddress,
    _In_ SIZE_T length
    )
/*++

Routine Description:

    Validate whether the physical address range is acceptable by this module. Note: The function performs only generic arithmetic protection, including
    zero-length checks, 52-bit upper bound checks, and endAddress wraparound detection; it does not verify whether the specific machine has that page installed.

Arguments:

    PhysicalAddress - Starting physical address.
    Length - Requested length, which may be zero.

Return Value:

    TRUE indicates the range is not overflowed and is within the conservative physical address limit; FALSE indicates it should be rejected.

--*/
{
    ULONG64 endAddress = 0ULL;

    if (physicalAddress > KSWORD_ARK_PHYSICAL_ADDRESS_MAX) {
        return FALSE;
    }
    if (length == 0U) {
        return TRUE;
    }
    if ((ULONG64)length > (KSWORD_ARK_PHYSICAL_ADDRESS_MAX - physicalAddress + 1ULL)) {
        return FALSE;
    }

    endAddress = physicalAddress + (ULONG64)length - 1ULL;
    if (endAddress < physicalAddress) {
        return FALSE;
    }

    return endAddress <= KSWORD_ARK_PHYSICAL_ADDRESS_MAX;
}

static VOID
kswordArkPhysicalInitReadResponse(
    _Out_ KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE* response,
    _In_ const KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST* request
    )
/*++

Routine Description:

    initialize physical memory read response header. Note: All status fields are initially set to unavailable or unsupported;
    subsequent read paths update only the fields actually completed to avoid leaving uninitialized data in failure branches.

Arguments:

    Response - Output response header.
    Request - Input read request.

Return Value:

    None. The function only writes to the response structure provided by the caller.

--*/
{
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->headerSize = KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE;
    response->fieldFlags = 0UL;
    response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_UNAVAILABLE;
    response->copyStatus = STATUS_NOT_SUPPORTED;
    response->source = KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_PHYSICAL_MEMORY;
    response->requestedBytes = request->bytesToRead;
    response->bytesRead = 0UL;
    response->maxBytesPerRequest = KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES;
    response->requestedPhysicalAddress = request->physicalAddress;
}

static VOID
kswordArkPhysicalInitWriteResponse(
    _Out_ KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response,
    _In_ const KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* request
    )
/*++

Routine Description:

    initialize the physical memory write response header. Note: The write path is high-risk; do not assume by default that
    the memory is already mapped or copied. The caller can inspect mapStatus/copyStatus to identify the failure location.

Arguments:

    Response - Output response header.
    Request - Input write request.

Return Value:

    None. The function does not return a status.

--*/
{
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->fieldFlags = KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT;
    response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_UNAVAILABLE;
    response->mapStatus = STATUS_NOT_SUPPORTED;
    response->copyStatus = STATUS_NOT_SUPPORTED;
    response->source = KSWORD_ARK_MEMORY_SOURCE_R0_MM_MAP_PHYSICAL_MEMORY;
    response->requestedBytes = request->bytesToWrite;
    response->bytesWritten = 0UL;
    response->maxBytesPerRequest = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES;
    response->requestedPhysicalAddress = request->physicalAddress;
}

NTSTATUS
kswordArkDriverReadPhysicalMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Safely read a segment of physical memory. Note: The function prioritizes the physical copy path of MmCopyMemory without
    establishing a persistent mapping; the read length is constrained by the protocol limit, and all address calculations
    include overflow checks. Requires PASSIVE_LEVEL to avoid triggering potentially blocking kernel paths at high IRQLs.

Arguments:

    OutputBuffer: Response buffer, with read data immediately following the header.
    OutputBufferLength - Total length of the response buffer.
    Request - Read request, containing physical address and length.
    BytesWrittenOut - Actual number of bytes written in the response.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; read details are written to response->readStatus/copyStatus.

--*/
{
    KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE* response = NULL;
    MM_COPY_ADDRESS copyAddress;
    SIZE_T bytesAvailable = 0U;
    SIZE_T bytesCopied = 0U;
    SIZE_T bytesToRead = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->flags != 0UL || request->reserved != 0UL || request->reserved2 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
    kswordArkPhysicalInitReadResponse(response, request);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_IRQL_REJECTED;
        response->copyStatus = STATUS_INVALID_DEVICE_STATE;
        *bytesWrittenOut = KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    bytesToRead = (SIZE_T)request->bytesToRead;
    if (!kswordArkPhysicalIsRangeValid(request->physicalAddress, bytesToRead)) {
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_RANGE_REJECTED;
        response->copyStatus = STATUS_INVALID_PARAMETER;
        *bytesWrittenOut = KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (bytesToRead == 0U) {
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_OK;
        response->copyStatus = STATUS_SUCCESS;
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT;
        *bytesWrittenOut = KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    bytesAvailable = outputBufferLength - KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE;
    if (bytesToRead > bytesAvailable) {
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_BUFFER_TOO_SMALL;
        response->copyStatus = STATUS_BUFFER_TOO_SMALL;
        *bytesWrittenOut = KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)request->physicalAddress;

    __try {
        status = MmCopyMemory(
            response->data,
            copyAddress,
            bytesToRead,
            MM_COPY_MEMORY_PHYSICAL,
            &bytesCopied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        bytesCopied = 0U;
    }

    response->copyStatus = status;
    response->bytesRead = (ULONG)bytesCopied;
    if (bytesCopied > 0U) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT;
    }

    if (NT_SUCCESS(status) && bytesCopied == bytesToRead) {
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_OK;
    }
    else if (bytesCopied > 0U || status == STATUS_PARTIAL_COPY) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_PARTIAL;
    }
    else {
        response->readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_COPY_FAILED;
    }

    *bytesWrittenOut = KSWORD_ARK_PHYSICAL_READ_RESPONSE_HEADER_SIZE + bytesCopied;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverWritePhysicalMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* request,
    _In_ size_t requestBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Controlled write to a segment of physical memory. Note: The function requires the FORCE flag, enforces
    length limits, validates METHOD_BUFFERED input integrity, and manages temporary mappings in pairs
    using MmMapIoSpaceEx/MmUnmapIoSpace. It does not modify PTEs/PDEs and does not bypass PatchGuard.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Total length of the response buffer.
    Request - Write request, with bytes to write immediately following the header.
    RequestBufferLength - Actual length of the input buffer.
    BytesWrittenOut - Fixed number of response bytes received.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; write details are written to response->writeStatus.

--*/
{
    KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE* response = NULL;
    PHYSICAL_ADDRESS physicalAddress;
    PVOID mappedAddress = NULL;
    PVOID writeAddress = NULL;
    ULONG64 pageOffset = 0ULL;
    SIZE_T mappedLength = 0U;
    SIZE_T bytesToWrite = 0U;
    SIZE_T requiredInputBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (requestBufferLength < KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->reserved != 0UL || request->reserved2 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((request->flags &
        ~(KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED | KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->bytesToWrite == 0UL ||
        request->bytesToWrite > KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    bytesToWrite = (SIZE_T)request->bytesToWrite;
    if (bytesToWrite > (MAXSIZE_T - KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE)) {
        return STATUS_INVALID_PARAMETER;
    }
    requiredInputBytes = KSWORD_ARK_PHYSICAL_WRITE_REQUEST_HEADER_SIZE + bytesToWrite;
    if (requestBufferLength < requiredInputBytes) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE*)outputBuffer;
    kswordArkPhysicalInitWriteResponse(response, request);

    if ((request->flags & KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE) == 0UL) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_REQUIRED;
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED;
        response->mapStatus = STATUS_REQUEST_NOT_ACCEPTED;
        response->copyStatus = STATUS_REQUEST_NOT_ACCEPTED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_USED;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_IRQL_REJECTED;
        response->mapStatus = STATUS_INVALID_DEVICE_STATE;
        response->copyStatus = STATUS_INVALID_DEVICE_STATE;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    if (!kswordArkPhysicalIsRangeValid(request->physicalAddress, bytesToWrite)) {
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_RANGE_REJECTED;
        response->mapStatus = STATUS_INVALID_PARAMETER;
        response->copyStatus = STATUS_INVALID_PARAMETER;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    pageOffset = request->physicalAddress & ((ULONG64)PAGE_SIZE - 1ULL);
    if ((ULONG64)bytesToWrite > ((ULONG64)MAXSIZE_T - pageOffset)) {
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_RANGE_REJECTED;
        response->mapStatus = STATUS_INTEGER_OVERFLOW;
        response->copyStatus = STATUS_INTEGER_OVERFLOW;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    mappedLength = (SIZE_T)(pageOffset + (ULONG64)bytesToWrite);

    RtlZeroMemory(&physicalAddress, sizeof(physicalAddress));
    physicalAddress.QuadPart =
        (LONGLONG)(request->physicalAddress & ~((ULONG64)PAGE_SIZE - 1ULL));

    mappedAddress = MmMapIoSpaceEx(
        physicalAddress,
        mappedLength,
        PAGE_READWRITE | PAGE_NOCACHE);
    if (mappedAddress == NULL) {
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_MAP_FAILED;
        response->mapStatus = STATUS_INSUFFICIENT_RESOURCES;
        response->copyStatus = STATUS_INSUFFICIENT_RESOURCES;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    response->mapStatus = STATUS_SUCCESS;
    writeAddress = (PVOID)((PUCHAR)mappedAddress + pageOffset);

    __try {
        RtlCopyMemory(writeAddress, request->data, bytesToWrite);
        response->bytesWritten = request->bytesToWrite;
        response->copyStatus = STATUS_SUCCESS;
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT;
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_OK;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        response->bytesWritten = 0UL;
        response->copyStatus = status;
        response->writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_COPY_FAILED;
    }

    MmUnmapIoSpace(mappedAddress, mappedLength);
    mappedAddress = NULL;

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

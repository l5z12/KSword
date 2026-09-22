/*++

Module Name:

    memory_physical_layout.c

Abstract:

    Read-only physical memory layout snapshot for HardwareDock. The query
    exposes aggregate geometry only: count, span, gap estimate and extrema.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

typedef struct KswPhysicalMemoryRange
{
    PHYSICAL_ADDRESS baseAddress;
    PHYSICAL_ADDRESS numberOfBytes;
} KswPhysicalMemoryRange, *PkswPhysicalMemoryRange;

NTSTATUS
kswordArkDriverQueryPhysicalMemoryLayout(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Build a read-only summary of the system physical memory map using
    MmGetPhysicalMemoryRanges.

Arguments:

    OutputBuffer - Caller-supplied response buffer.
    OutputBufferLength - Output buffer size in bytes.
    BytesWrittenOut - Receives sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE).

Return Value:

    STATUS_SUCCESS on success; STATUS_BUFFER_TOO_SMALL or STATUS_INVALID_PARAMETER
    for malformed caller buffers.

--*/
{
    KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE* response = NULL;
    PkswPhysicalMemoryRange ranges = NULL;
    ULONGLONG totalBytes = 0ULL;
    ULONGLONG highestAddress = 0ULL;
    ULONGLONG largestRange = 0ULL;
    ULONGLONG smallestRange = 0ULL;
    ULONGLONG firstBase = 0ULL;
    ULONGLONG lastEnd = 0ULL;
    ULONGLONG estimatedGap = 0ULL;
    ULONG rangeCount = 0UL;
    ULONG zeroLengthCount = 0UL;
    BOOLEAN haveRange = FALSE;

    if (bytesWrittenOut == NULL || outputBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    response = (KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_PHYSICAL_MEMORY_LAYOUT_PROTOCOL_VERSION;
    response->lastStatus = STATUS_SUCCESS;

    ranges = (PkswPhysicalMemoryRange)MmGetPhysicalMemoryRanges();
    if (ranges == NULL) {
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (PkswPhysicalMemoryRange range = ranges; range->numberOfBytes.QuadPart != 0; ++range) {
        const ULONGLONG kBase = (ULONGLONG)range->baseAddress.QuadPart;
        const ULONGLONG kBytes = (ULONGLONG)range->numberOfBytes.QuadPart;
        const ULONGLONG kEnd = kBytes > 0ULL ? (kBase + kBytes - 1ULL) : kBase;

        ++rangeCount;
        if (kBytes == 0ULL) {
            ++zeroLengthCount;
            continue;
        }

        if (!haveRange) {
            firstBase = kBase;
            smallestRange = kBytes;
            haveRange = TRUE;
        }
        else {
            if (kBase > lastEnd + 1ULL) {
                estimatedGap += kBase - (lastEnd + 1ULL);
            }
            if (kBytes < smallestRange) {
                smallestRange = kBytes;
            }
        }

        totalBytes += kBytes;
        if (kBytes > largestRange) {
            largestRange = kBytes;
        }
        if (kEnd > highestAddress) {
            highestAddress = kEnd;
        }
        lastEnd = kEnd;
    }

    ExFreePool(ranges);

    response->fieldFlags = haveRange ? KSWORD_ARK_PHYSICAL_MEMORY_LAYOUT_FIELD_RANGES_PRESENT : 0UL;
    response->rangeCount = rangeCount;
    response->zeroLengthRangeCount = zeroLengthCount;
    response->truncated = 0UL;
    response->totalPhysicalBytes = totalBytes;
    response->highestPhysicalAddress = highestAddress;
    response->largestRangeBytes = largestRange;
    response->smallestRangeBytes = smallestRange;
    response->firstBaseAddress = firstBase;
    response->lastEndAddress = lastEnd;
    response->estimatedAddressSpaceGapBytes = estimatedGap;

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

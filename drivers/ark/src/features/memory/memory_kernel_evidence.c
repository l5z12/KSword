/*++

Module Name:

    memory_kernel_evidence.c

Abstract:

    Read-only kernel memory evidence collector for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_memory_evidence.h"
#include "memory_evidence_enrichment.h"
#include "memory_kernel_exec_scan_internal.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSW_MEMORY_EVIDENCE_TAG 'eKsK'
#define KSW_MEMORY_EVIDENCE_SYSTEM_BIG_POOL_INFORMATION_CLASS 0x42UL
#define KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

typedef struct KswMemoryEvidenceBigpoolEntry
{
    union
    {
        PVOID virtualAddress;
        ULONG_PTR nonPaged;
    } address;
    SIZE_T sizeInBytes;
    union
    {
        UCHAR tagChars[4];
        ULONG tagUlong;
    } tag;
} KswMemoryEvidenceBigpoolEntry, *PkswMemoryEvidenceBigpoolEntry;

typedef struct KswMemoryEvidenceBigpoolInformation
{
    ULONG count;
    KswMemoryEvidenceBigpoolEntry allocatedInfo[1];
} KswMemoryEvidenceBigpoolInformation, *PkswMemoryEvidenceBigpoolInformation;

typedef struct KswMemoryEvidenceLimits
{
    ULONG effectiveFlags;
    ULONG maxRows;
    ULONG maxBigPoolRows;
    ULONG sampleBytes;
    ULONG64 maxBytes;
} KswMemoryEvidenceLimits;

typedef struct KswMemoryEvidenceState
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* response;
    ULONG rowCapacity;
    ULONG returnedRows;
    ULONG64 bytesScanned;
    BOOLEAN truncated;
    BOOLEAN budgetExhausted;
} KswMemoryEvidenceState;

static BOOLEAN
kswordArkMemoryEvidenceRangeIntersects(
    _In_ ULONG64 rangeStart,
    _In_ ULONG64 rangeEnd,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* request
    )
/*++

Routine Description:

    Test whether a half-open candidate range intersects the optional request range.

Arguments:

    RangeStart - Candidate range start address.
    RangeEnd - Candidate range end address.
    Request - Evidence request containing startAddress/endAddress filters.

Return Value:

    TRUE when the candidate must be considered; FALSE when it can be skipped.

--*/
{
    ULONG64 filterEnd = 0ULL;

    if (request == NULL || rangeEnd <= rangeStart) {
        return FALSE;
    }
    if (request->startAddress == 0ULL && request->endAddress == 0ULL) {
        return TRUE;
    }

    filterEnd = (request->endAddress == 0ULL) ? MAXULONGLONG : request->endAddress;
    if (rangeEnd <= request->startAddress || rangeStart >= filterEnd) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
kswordArkMemoryEvidenceValidateRequest(
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* request,
    _Out_ KswMemoryEvidenceLimits* limitsOut
    )
/*++

Routine Description:

    Validate evidence scan flags, reserved fields, range bounds, and cost limits.

Arguments:

    Request - User-mode request copied from METHOD_BUFFERED input.
    LimitsOut - Receives effective bounded flags and scan limits.

Return Value:

    STATUS_SUCCESS when valid; STATUS_INVALID_PARAMETER for unknown flags, bad
    reserved fields, reversed ranges, missing non-module range, or excessive caps.

--*/
{
    KswMemoryEvidenceLimits limits;

    if (request == NULL || limitsOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&limits, sizeof(limits));

    if (request->reserved0 != 0UL || request->reserved1 != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.effectiveFlags = request->flags;
    if (limits.effectiveFlags == 0UL) {
        limits.effectiveFlags =
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES |
            KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
    }
    if ((limits.effectiveFlags & ~KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->startAddress != 0ULL &&
        request->endAddress != 0ULL &&
        request->endAddress <= request->startAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((limits.effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL &&
        (request->startAddress == 0ULL || request->endAddress == 0ULL || request->endAddress <= request->startAddress)) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.maxRows = request->maxRows;
    if (limits.maxRows == 0UL) {
        limits.maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS;
    }
    if (limits.maxRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.maxBigPoolRows = request->maxBigPoolRows;
    if (limits.maxBigPoolRows == 0UL) {
        limits.maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS;
    }
    if (limits.maxBigPoolRows > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.sampleBytes = request->sampleBytes;
    if (limits.sampleBytes == 0UL) {
        limits.sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES;
    }
    if (limits.sampleBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_SAMPLE_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    limits.maxBytes = request->maxBytes;
    if (limits.maxBytes == 0ULL) {
        limits.maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES;
    }
    if (limits.maxBytes > KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    *limitsOut = limits;
    return STATUS_SUCCESS;
}

static VOID
kswordArkMemoryEvidenceInitRow(
    _Out_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* row,
    _In_ ULONG evidenceKind,
    _In_ ULONG64 virtualAddress,
    _In_ ULONG64 regionSize,
    _In_ ULONG pageSize
    )
/*++

Routine Description:

    initialize one evidence row with protocol defaults.

Arguments:

    Row - Row to initialize.
    EvidenceKind - Source/classification kind for the row.
    VirtualAddress - Region start address.
    RegionSize - Region size in bytes.
    PageSize - Observed page size, or PAGE_SIZE when unknown.

Return Value:

    None. The function writes only Row.

--*/
{
    if (row == NULL) {
        return;
    }

    RtlZeroMemory(row, sizeof(*row));
    row->rowSize = sizeof(*row);
    row->evidenceKind = evidenceKind;
    row->virtualAddress = virtualAddress;
    row->regionSize = regionSize;
    row->pageSize = pageSize;
    row->ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN;
    row->confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    row->backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_UNKNOWN;
    row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_UNAVAILABLE;
    row->lastStatus = STATUS_SUCCESS;
    row->hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE;
}

static VOID
kswordArkMemoryEvidenceCopyWideLiteral(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
/*++

Routine Description:

    Copy a literal wide string into a bounded protocol field.

Arguments:

    Destination - Destination WCHAR buffer.
    DestinationChars - Destination capacity in WCHARs.
    Source - Optional source string.

Return Value:

    None. Destination is NUL-terminated when capacity is nonzero.

--*/
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source != NULL) {
        (VOID)RtlStringCchCopyW(destination, destinationChars, source);
    }
}

static VOID
kswordArkMemoryEvidenceCopyAnsiToWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_reads_bytes_(sourceBytes) const UCHAR* source,
    _In_ ULONG sourceBytes
    )
/*++

Routine Description:

    Copy bounded ANSI module text into a WCHAR protocol field.

Arguments:

    Destination - Destination WCHAR buffer.
    DestinationChars - Destination capacity in WCHARs.
    Source - Bounded ANSI source bytes.
    SourceBytes - Source byte limit.

Return Value:

    None. Bytes are widened directly for display-only owner names.

--*/
{
    ULONG index = 0UL;

    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index + 1UL < destinationChars && index < sourceBytes; ++index) {
        if (source[index] == '\0') {
            break;
        }
        destination[index] = (WCHAR)source[index];
    }
    destination[index] = L'\0';
}

static VOID
kswordArkMemoryEvidenceCopySectionName(
    _Out_writes_bytes_(destinationBytes) UCHAR* destination,
    _In_ ULONG destinationBytes,
    _In_reads_bytes_(sourceBytes) const UCHAR* source,
    _In_ ULONG sourceBytes
    )
/*++

Routine Description:

    Copy an 8-byte PE section name into a row field.

Arguments:

    Destination - Destination byte array.
    DestinationBytes - Destination byte capacity.
    Source - Source bytes.
    SourceBytes - Source byte count.

Return Value:

    None. Destination is zero-filled before copying.

--*/
{
    ULONG index = 0UL;

    if (destination == NULL || destinationBytes == 0UL) {
        return;
    }
    RtlZeroMemory(destination, destinationBytes);
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index < destinationBytes && index < sourceBytes; ++index) {
        destination[index] = source[index];
        if (source[index] == '\0') {
            break;
        }
    }
}

static CHAR
kswordArkMemoryEvidenceLowerAnsi(
    _In_ CHAR character
    )
/*++

Routine Description:

    Lowercase an ASCII byte for pool-tag heuristics.

Arguments:

    Character - Input byte.

Return Value:

    Lowercase ASCII byte or the original byte.

--*/
{
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character + ('a' - 'A'));
    }
    return character;
}

static BOOLEAN
kswordArkMemoryEvidenceTagContains3(
    _In_reads_bytes_(4) const UCHAR tagChars[4],
    _In_ CHAR a,
    _In_ CHAR b,
    _In_ CHAR c
    )
/*++

Routine Description:

    Check whether a four-byte tag contains a case-insensitive three-byte token.

Arguments:

    TagChars - BigPool tag bytes.
    A - First token byte.
    B - Second token byte.
    C - Third token byte.

Return Value:

    TRUE when the token appears at tag offset 0 or 1; otherwise FALSE.

--*/
{
    ULONG index = 0UL;

    if (tagChars == NULL) {
        return FALSE;
    }
    for (index = 0UL; index <= 1UL; ++index) {
        if (kswordArkMemoryEvidenceLowerAnsi((CHAR)tagChars[index]) == kswordArkMemoryEvidenceLowerAnsi(a) &&
            kswordArkMemoryEvidenceLowerAnsi((CHAR)tagChars[index + 1UL]) == kswordArkMemoryEvidenceLowerAnsi(b) &&
            kswordArkMemoryEvidenceLowerAnsi((CHAR)tagChars[index + 2UL]) == kswordArkMemoryEvidenceLowerAnsi(c)) {
            return TRUE;
        }
    }
    return FALSE;
}

static ULONG64
kswordArkMemoryEvidenceFnv1a64(
    _In_reads_bytes_(bytesToHash) const UCHAR* bytes,
    _In_ ULONG bytesToHash
    )
/*++

Routine Description:

    Compute an FNV-1a 64-bit hash over an already-local memory sample.

Arguments:

    Bytes - Sample bytes.
    BytesToHash - Sample length.

Return Value:

    Hash value, or zero when no bytes are supplied.

--*/
{
    ULONG index = 0UL;
    ULONG64 hash = 1469598103934665603ULL;

    if (bytes == NULL || bytesToHash == 0UL) {
        return 0ULL;
    }
    for (index = 0UL; index < bytesToHash; ++index) {
        hash ^= (ULONG64)bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static BOOLEAN
kswordArkMemoryEvidenceReadVirtualSafe(
    _In_ ULONG64 virtualAddress,
    _Out_writes_bytes_(bytesToRead) VOID* destination,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Copy kernel virtual memory into local storage with MmCopyMemory and SEH.

Arguments:

    VirtualAddress - Source virtual address.
    Destination - Destination buffer.
    BytesToRead - Bytes to copy.

Return Value:

    TRUE on an exact copy; FALSE on exception, failing status, or short copy.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (virtualAddress == 0ULL || destination == NULL || bytesToRead == 0U) {
        return FALSE;
    }
    RtlZeroMemory(destination, bytesToRead);

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)virtualAddress;
    __try {
        status = MmCopyMemory(
            destination,
            copyAddress,
            bytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }

    if (!NT_SUCCESS(status) || copiedBytes != bytesToRead) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }
    return TRUE;
}

static VOID
kswordArkMemoryEvidencePermissionFromPage(
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo,
    _Out_ ULONG* permissionFlagsOut,
    _Out_ ULONG* riskFlagsOut,
    _Out_ ULONG* confidenceOut
    )
/*++

Routine Description:

    Convert page-table effective flags to evidence permission/risk/confidence fields.

Arguments:

    PageInfo - Read-only page-table query result.
    PermissionFlagsOut - Receives P/R/W/X/NX/Large/Global/User bits.
    RiskFlagsOut - Receives page-level RWX and LargeExecutable risks.
    ConfidenceOut - Receives confidence score for the observation.

Return Value:

    None. Outputs are zeroed when input is invalid.

--*/
{
    ULONG permissionFlags = 0UL;
    ULONG riskFlags = 0UL;
    ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;

    if (permissionFlagsOut != NULL) {
        *permissionFlagsOut = 0UL;
    }
    if (riskFlagsOut != NULL) {
        *riskFlagsOut = 0UL;
    }
    if (confidenceOut != NULL) {
        *confidenceOut = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    }
    if (pageInfo == NULL) {
        return;
    }

    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT |
            KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_READ;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX;
    }
    else if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE) != 0UL ||
        pageInfo->largePageType != KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_LARGE;
        riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_LARGE_EXECUTABLE;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_GLOBAL;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL) {
        permissionFlags |= KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_USER;
    }
    if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL &&
        (permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) != 0UL) {
        riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX;
    }

    if (pageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK && pageInfo->resolved != 0UL) {
        confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_HIGH;
    }
    else if (pageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT) {
        confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_LOW;
    }
    else {
        confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_MEDIUM;
    }

    if (permissionFlagsOut != NULL) {
        *permissionFlagsOut = permissionFlags;
    }
    if (riskFlagsOut != NULL) {
        *riskFlagsOut = riskFlags;
    }
    if (confidenceOut != NULL) {
        *confidenceOut = confidence;
    }
}

static BOOLEAN
kswordArkMemoryEvidenceSectionIsTextLike(
    _In_ const IMAGE_SECTION_HEADER* sectionHeader
    )
/*++

Routine Description:

    Classify a PE section as text/code-like.

Arguments:

    SectionHeader - Section header copied from kernel image memory.

Return Value:

    TRUE for IMAGE_SCN_CNT_CODE or .text-like names; otherwise FALSE.

--*/
{
    if (sectionHeader == NULL) {
        return FALSE;
    }
    if ((sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) != 0UL) {
        return TRUE;
    }
    return sectionHeader->Name[0] == '.' &&
        (sectionHeader->Name[1] == 't' || sectionHeader->Name[1] == 'T') &&
        (sectionHeader->Name[2] == 'e' || sectionHeader->Name[2] == 'E') &&
        (sectionHeader->Name[3] == 'x' || sectionHeader->Name[3] == 'X') &&
        (sectionHeader->Name[4] == 't' || sectionHeader->Name[4] == 'T');
}

static BOOLEAN
kswordArkMemoryEvidenceReadSections(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Out_writes_(KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS) IMAGE_SECTION_HEADER* sectionHeaders,
    _Out_ ULONG* sectionCountOut
    )
/*++

Routine Description:

    Copy a module PE section table into local storage using safe image reads.

Arguments:

    ModuleEntry - Loaded kernel module snapshot row.
    SectionHeaders - Caller-provided fixed section header array.
    SectionCountOut - Receives section count used by the scanner.

Return Value:

    TRUE when PE headers are readable and section count is within the hard cap.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionTableRva = 0UL;
    ULONG sectionCount = 0UL;
    ULONG sectionIndex = 0UL;

    if (moduleEntry == NULL || sectionHeaders == NULL || sectionCountOut == NULL) {
        return FALSE;
    }
    *sectionCountOut = 0UL;
    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    RtlZeroMemory(sectionHeaders, sizeof(IMAGE_SECTION_HEADER) * KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS);

    if (!kswordArkHookReadImageBytes(moduleEntry, 0UL, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0) {
        return FALSE;
    }
    if (!kswordArkHookReadImageNtHeaders(moduleEntry, &ntHeaders)) {
        return FALSE;
    }
    if (ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS) {
        return FALSE;
    }
    if ((ULONG)dosHeader.e_lfanew > MAXULONG - (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) ||
        (ULONG)dosHeader.e_lfanew + (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) >
            MAXULONG - (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader) {
        return FALSE;
    }

    sectionTableRva =
        (ULONG)dosHeader.e_lfanew +
        (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader;
    sectionCount = (ULONG)ntHeaders.FileHeader.NumberOfSections;

    for (sectionIndex = 0UL; sectionIndex < sectionCount; ++sectionIndex) {
        ULONG sectionRva = 0UL;
        if (!kswordArkHookAddRvaOffset(
            sectionTableRva,
            sectionIndex,
            (ULONG)sizeof(IMAGE_SECTION_HEADER),
            &sectionRva)) {
            break;
        }
        (VOID)kswordArkHookReadImageBytes(
            moduleEntry,
            sectionRva,
            &sectionHeaders[sectionIndex],
            sizeof(sectionHeaders[sectionIndex]));
    }

    *sectionCountOut = sectionCount;
    return TRUE;
}

static BOOLEAN
kswordArkMemoryEvidenceClassifyPageSection(
    _In_reads_(sectionCount) const IMAGE_SECTION_HEADER* sectionHeaders,
    _In_ ULONG sectionCount,
    _In_ ULONG64 moduleBase,
    _In_ ULONG moduleSize,
    _In_ ULONG64 pageAddress,
    _In_ ULONG pageSize,
    _Out_ BOOLEAN* isTextLikeOut,
    _Out_ BOOLEAN* isWritableOut,
    _Out_ ULONG* sectionRvaOut,
    _Out_ ULONG* sectionSizeOut,
    _Out_writes_bytes_(KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES) UCHAR* sectionNameOut
    )
/*++

Routine Description:

    Find sections overlapping a page and derive text/writable metadata.

Arguments:

    SectionHeaders - Local section header array.
    SectionCount - Number of entries.
    ModuleBase - Loaded image base.
    ModuleSize - Loaded image size.
    PageAddress - Page or large-page base address.
    PageSize - Page size from page-table walk.
    IsTextLikeOut - TRUE only when all overlapping sections are text-like.
    IsWritableOut - TRUE when any overlapping section is writable.
    SectionRvaOut - First overlapping section RVA.
    SectionSizeOut - First overlapping section size.
    SectionNameOut - First overlapping section name.

Return Value:

    TRUE when at least one valid section overlaps; otherwise FALSE.

--*/
{
    ULONG sectionIndex = 0UL;
    ULONG64 pageEnd = 0ULL;
    ULONG64 moduleEnd = 0ULL;
    BOOLEAN sawSection = FALSE;
    BOOLEAN sawText = FALSE;
    BOOLEAN sawNonText = FALSE;
    BOOLEAN sawWritable = FALSE;

    if (isTextLikeOut != NULL) {
        *isTextLikeOut = FALSE;
    }
    if (isWritableOut != NULL) {
        *isWritableOut = FALSE;
    }
    if (sectionRvaOut != NULL) {
        *sectionRvaOut = 0UL;
    }
    if (sectionSizeOut != NULL) {
        *sectionSizeOut = 0UL;
    }
    if (sectionNameOut != NULL) {
        RtlZeroMemory(sectionNameOut, KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES);
    }

    if (sectionHeaders == NULL || sectionCount == 0UL || moduleSize == 0UL || pageSize == 0UL) {
        return FALSE;
    }
    if ((ULONG64)moduleSize > MAXULONGLONG - moduleBase) {
        return FALSE;
    }
    moduleEnd = moduleBase + (ULONG64)moduleSize;
    pageEnd = ((ULONG64)pageSize > MAXULONGLONG - pageAddress) ? MAXULONGLONG : pageAddress + (ULONG64)pageSize;

    for (sectionIndex = 0UL; sectionIndex < sectionCount; ++sectionIndex) {
        const IMAGE_SECTION_HEADER* sectionHeader = &sectionHeaders[sectionIndex];
        ULONG sectionSize = sectionHeader->Misc.VirtualSize;
        ULONG64 sectionStart = 0ULL;
        ULONG64 sectionEnd = 0ULL;

        if (sectionSize == 0UL) {
            sectionSize = sectionHeader->SizeOfRawData;
        }
        if (sectionSize == 0UL || sectionHeader->VirtualAddress >= moduleSize) {
            continue;
        }
        if ((ULONG64)sectionHeader->VirtualAddress > MAXULONGLONG - moduleBase) {
            continue;
        }

        sectionStart = moduleBase + (ULONG64)sectionHeader->VirtualAddress;
        sectionEnd = ((ULONG64)sectionSize > MAXULONGLONG - sectionStart) ? moduleEnd : sectionStart + (ULONG64)sectionSize;
        if (sectionEnd > moduleEnd || sectionEnd < sectionStart) {
            sectionEnd = moduleEnd;
        }
        if (pageEnd <= sectionStart || pageAddress >= sectionEnd) {
            continue;
        }

        sawSection = TRUE;
        if (kswordArkMemoryEvidenceSectionIsTextLike(sectionHeader)) {
            sawText = TRUE;
        }
        else {
            sawNonText = TRUE;
        }
        if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0UL) {
            sawWritable = TRUE;
        }
        if (sectionRvaOut != NULL && *sectionRvaOut == 0UL) {
            *sectionRvaOut = sectionHeader->VirtualAddress;
        }
        if (sectionSizeOut != NULL && *sectionSizeOut == 0UL) {
            *sectionSizeOut = sectionSize;
        }
        if (sectionNameOut != NULL && sectionNameOut[0] == '\0') {
            kswordArkMemoryEvidenceCopySectionName(
                sectionNameOut,
                KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES,
                sectionHeader->Name,
                KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES);
        }
    }

    if (isTextLikeOut != NULL) {
        *isTextLikeOut = (sawText && !sawNonText) ? TRUE : FALSE;
    }
    if (isWritableOut != NULL) {
        *isWritableOut = sawWritable;
    }
    return sawSection;
}

static BOOLEAN
kswordArkMemoryEvidenceConsumeBudget(
    _Inout_ KswMemoryEvidenceState* state,
    _In_ ULONG64 bytes
    )
/*++

Routine Description:

    Account scan cost against maxBytes before probing another page/range.

Arguments:

    State - Mutable evidence scan state.
    Bytes - Bytes represented by the next probe.

Return Value:

    TRUE when scanning may proceed; FALSE when the budget is exhausted.

--*/
{
    if (state == NULL || state->response == NULL) {
        return FALSE;
    }
    if (state->bytesScanned >= state->response->maxBytes ||
        bytes > state->response->maxBytes - state->bytesScanned) {
        state->budgetExhausted = TRUE;
        state->truncated = TRUE;
        state->bytesScanned = state->response->maxBytes;
        return FALSE;
    }
    state->bytesScanned += bytes;
    return TRUE;
}

static VOID
kswordArkMemoryEvidenceAppendRow(
    _Inout_ KswMemoryEvidenceState* state,
    _In_ const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* row
    )
/*++

Routine Description:

    Append a row if row capacity remains while always counting totalRows.

Arguments:

    State - Mutable evidence scan state.
    Row - Candidate row.

Return Value:

    None. The function updates response counts and truncation state.

--*/
{
    if (state == NULL || state->response == NULL || row == NULL) {
        return;
    }

    state->response->totalRows += 1UL;
    if (state->returnedRows >= state->rowCapacity) {
        state->truncated = TRUE;
        return;
    }

    RtlCopyMemory(&state->response->rows[state->returnedRows], row, sizeof(*row));
    ++state->returnedRows;
    state->response->returnedRows = state->returnedRows;
}

static VOID
kswordArkMemoryEvidenceFillSample(
    _Inout_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* row,
    _In_ ULONG64 virtualAddress,
    _In_ ULONG sampleBytes
    )
/*++

Routine Description:

    Read a bounded memory sample and calculate its FNV-1a hash.

Arguments:

    Row - Row receiving sample metadata.
    VirtualAddress - Source memory address.
    SampleBytes - Requested sample length.

Return Value:

    None. Failed reads leave sampleSize zero and hashAlgorithm NONE.

--*/
{
    ULONG sampleLength = sampleBytes;

    if (row == NULL || sampleLength == 0UL) {
        return;
    }
    if (sampleLength > KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES) {
        sampleLength = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES;
    }
    if (!kswordArkMemoryEvidenceReadVirtualSafe(virtualAddress, row->sample, sampleLength)) {
        row->sampleSize = 0UL;
        row->hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE;
        row->contentHash = 0ULL;
        return;
    }

    row->sampleSize = sampleLength;
    row->hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_FNV1A64;
    row->contentHash = kswordArkMemoryEvidenceFnv1a64(row->sample, sampleLength);
}

static VOID
kswordArkMemoryEvidenceFillModuleRow(
    _Out_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* row,
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo,
    _In_ ULONG64 pageAddress,
    _In_ BOOLEAN isTextLike,
    _In_ BOOLEAN isWritableSection,
    _In_ ULONG sectionRva,
    _In_ ULONG sectionSize,
    _In_reads_bytes_(KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES) const UCHAR* sectionName,
    _In_ ULONG sampleBytes
    )
/*++

Routine Description:

    Build one loaded-module executable/text evidence row.

Arguments:

    Row - Output row.
    ModuleEntry - Loaded module snapshot entry.
    PageInfo - Read-only page-table result.
    PageAddress - Page or large-page base address.
    IsTextLike - TRUE when PE section metadata is text/code-like.
    IsWritableSection - TRUE when PE section metadata is writable.
    SectionRva - First overlapping section RVA.
    SectionSize - First overlapping section size.
    SectionName - First overlapping section name.
    SampleBytes - Number of bytes to sample from memory.

Return Value:

    None. The function writes only Row.

--*/
{
    ULONG permissionFlags = 0UL;
    ULONG riskFlags = 0UL;
    ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    ULONG pageSize = (pageInfo != NULL && pageInfo->pageSize != 0UL) ? pageInfo->pageSize : PAGE_SIZE;

    kswordArkMemoryEvidenceInitRow(
        row,
        isTextLike ? KSWORD_ARK_MEMORY_EVIDENCE_KIND_TEXT_SECTION_MEMORY : KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE,
        pageAddress,
        (ULONG64)pageSize,
        pageSize);
    if (row == NULL || moduleEntry == NULL || pageInfo == NULL) {
        return;
    }

    kswordArkMemoryEvidencePermissionFromPage(pageInfo, &permissionFlags, &riskFlags, &confidence);
    row->permissionFlags = permissionFlags;
    row->ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE;
    row->riskFlags = riskFlags;
    row->confidence = confidence;
    row->backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_LOADED_MODULE;
    row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_NOT_APPLICABLE;
    row->moduleBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
    row->moduleSize = moduleEntry->imageSize;
    row->ownerAddress = row->moduleBase;
    if (moduleEntry->section != NULL) {
        row->sectionObjectAddress = (ULONG64)(ULONG_PTR)moduleEntry->section;
        row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_SECTION_OBJECT_PRESENT;
        row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_SECTION_PRESENT;
    }
    row->lastStatus = pageInfo->walkStatus;
    row->sectionRva = sectionRva;
    row->sectionSize = sectionSize;
    kswordArkMemoryEvidenceCopySectionName(
        row->sectionName,
        KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES,
        sectionName,
        KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES);
    kswordArkMemoryEvidenceCopyAnsiToWide(
        row->ownerName,
        KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS,
        moduleEntry->fullPathName,
        (ULONG)sizeof(moduleEntry->fullPathName));

    if (!isTextLike) {
        row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_MODULE_NON_TEXT_EXECUTABLE;
    }
    if (isWritableSection && (row->permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
        row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_RWX;
    }

    kswordArkMemoryEvidenceFillSample(row, pageAddress, sampleBytes);
    (VOID)RtlStringCchPrintfW(
        row->detail,
        KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS,
        L"module section text=%lu writableSection=%lu sectionRva=0x%lX sectionSize=0x%lX",
        isTextLike ? 1UL : 0UL,
        isWritableSection ? 1UL : 0UL,
        sectionRva,
        sectionSize);
}

static NTSTATUS
kswordArkMemoryEvidenceScanModule(
    _Inout_ KswMemoryEvidenceState* state,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* request,
    _In_ const KswMemoryEvidenceLimits* limits,
    _In_ const KswHookSystemModuleEntry* moduleEntry
    )
/*++

Routine Description:

    Scan one loaded module for executable text and non-text pages.

Arguments:

    State - Mutable response state.
    Request - Original request with range filter.
    Limits - Effective scan limits.
    ModuleEntry - Loaded module snapshot entry.

Return Value:

    STATUS_SUCCESS when processed or skipped; first page-query failure otherwise.

--*/
{
    IMAGE_SECTION_HEADER sectionHeaders[KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS];
    ULONG sectionCount = 0UL;
    ULONG64 moduleBase = 0ULL;
    ULONG64 moduleEnd = 0ULL;
    ULONG64 pageAddress = 0ULL;
    BOOLEAN includeLoaded = FALSE;
    BOOLEAN includeTextSamples = FALSE;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (state == NULL || request == NULL || limits == NULL || moduleEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    includeLoaded = (limits->effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE) != 0UL;
    includeTextSamples = (limits->effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES) != 0UL;
    if (!includeLoaded && !includeTextSamples) {
        return STATUS_SUCCESS;
    }
    if (!kswordArkKernelExecSafeModuleRange(moduleEntry, &moduleBase, &moduleEnd)) {
        return STATUS_SUCCESS;
    }
    if (!kswordArkMemoryEvidenceRangeIntersects(moduleBase, moduleEnd, request)) {
        return STATUS_SUCCESS;
    }
    if (!kswordArkMemoryEvidenceReadSections(moduleEntry, sectionHeaders, &sectionCount)) {
        return STATUS_SUCCESS;
    }

    pageAddress = kswordArkKernelExecAlignDown(moduleBase, PAGE_SIZE);
    if (request->startAddress != 0ULL && pageAddress < request->startAddress) {
        pageAddress = kswordArkKernelExecAlignDown(request->startAddress, PAGE_SIZE);
    }
    if (pageAddress < moduleBase) {
        pageAddress = moduleBase;
    }

    while (pageAddress < moduleEnd) {
        KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
        KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW row;
        UCHAR sectionName[KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES];
        ULONG sectionRva = 0UL;
        ULONG sectionSize = 0UL;
        ULONG pageSize = PAGE_SIZE;
        ULONG64 nextAddress = 0ULL;
        BOOLEAN isTextLike = FALSE;
        BOOLEAN isWritableSection = FALSE;
        NTSTATUS status = STATUS_SUCCESS;

        if (request->endAddress != 0ULL && pageAddress >= request->endAddress) {
            break;
        }
        if (!kswordArkMemoryEvidenceConsumeBudget(state, PAGE_SIZE)) {
            break;
        }

        RtlZeroMemory(&pageInfo, sizeof(pageInfo));
        status = kswordArkKernelExecQueryPage(pageAddress, &pageInfo);
        if (!NT_SUCCESS(status)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
            pageAddress += PAGE_SIZE;
            continue;
        }
        if (pageInfo.queryStatus != KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK ||
            pageInfo.resolved == 0UL ||
            (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) == 0UL) {
            pageAddress += PAGE_SIZE;
            continue;
        }

        pageSize = (pageInfo.pageSize != 0UL) ? pageInfo.pageSize : PAGE_SIZE;
        if (pageSize > PAGE_SIZE &&
            !kswordArkMemoryEvidenceConsumeBudget(state, (ULONG64)pageSize - (ULONG64)PAGE_SIZE)) {
            break;
        }
        nextAddress = pageAddress + (ULONG64)pageSize;
        if (nextAddress <= pageAddress) {
            break;
        }
        if ((pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
            pageAddress = nextAddress;
            continue;
        }

        RtlZeroMemory(sectionName, sizeof(sectionName));
        if (!kswordArkMemoryEvidenceClassifyPageSection(
            sectionHeaders,
            sectionCount,
            moduleBase,
            moduleEntry->imageSize,
            pageAddress,
            pageSize,
            &isTextLike,
            &isWritableSection,
            &sectionRva,
            &sectionSize,
            sectionName)) {
            pageAddress = nextAddress;
            continue;
        }
        if (isTextLike && !includeTextSamples && !includeLoaded) {
            pageAddress = nextAddress;
            continue;
        }
        if (!isTextLike && !includeLoaded) {
            pageAddress = nextAddress;
            continue;
        }

        kswordArkMemoryEvidenceFillModuleRow(
            &row,
            moduleEntry,
            &pageInfo,
            pageAddress,
            isTextLike,
            isWritableSection,
            sectionRva,
            sectionSize,
            sectionName,
            limits->sampleBytes);
        kswordArkMemoryEvidenceAppendRow(state, &row);
        if (state->truncated) {
            break;
        }
        pageAddress = nextAddress;
    }

    return firstFailure;
}

static NTSTATUS
kswordArkMemoryEvidenceScanModules(
    _Inout_ KswMemoryEvidenceState* state,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* request,
    _In_ const KswMemoryEvidenceLimits* limits,
    _Inout_opt_ KswHookSystemModuleInformation** moduleInfoOut
    )
/*++

Routine Description:

    Query SystemModuleInformation and scan loaded module executable evidence.

Arguments:

    State - Mutable response state.
    Request - Original request.
    Limits - Effective scan limits.
    ModuleInfoOut - Optional snapshot returned to the caller for reuse.

Return Value:

    STATUS_SUCCESS or the first snapshot/page-query failure status.

--*/
{
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG moduleIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (state == NULL || state->response == NULL || request == NULL || limits == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (moduleInfoOut != NULL) {
        *moduleInfoOut = NULL;
    }

    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    state->response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        return status;
    }
    state->response->moduleCount = moduleInfo->numberOfModules;

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        status = kswordArkMemoryEvidenceScanModule(state, request, limits, &moduleInfo->modules[moduleIndex]);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
        if (state->truncated || state->budgetExhausted) {
            break;
        }
    }

    if (moduleInfoOut != NULL) {
        *moduleInfoOut = moduleInfo;
    }
    else {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    return firstFailure;
}

static BOOLEAN
kswordArkMemoryEvidenceCanMergeNonModule(
    _In_ const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* left,
    _In_ const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* right
    )
/*++

Routine Description:

    Decide whether two non-module executable rows are contiguous and compatible.

Arguments:

    Left - Current aggregate row.
    Right - New candidate row.

Return Value:

    TRUE when Right can extend Left; otherwise FALSE.

--*/
{
    ULONG64 leftEnd = 0ULL;

    if (left == NULL || right == NULL || left->pageSize == 0UL) {
        return FALSE;
    }
    if (left->ownerKind != right->ownerKind ||
        left->permissionFlags != right->permissionFlags ||
        left->pageSize != right->pageSize ||
        left->riskFlags != right->riskFlags ||
        left->rowFlags != right->rowFlags ||
        left->backingKind != right->backingKind ||
        left->sectionHintStatus != right->sectionHintStatus) {
        return FALSE;
    }
    if (left->regionSize > MAXULONGLONG - left->virtualAddress) {
        return FALSE;
    }
    leftEnd = left->virtualAddress + left->regionSize;
    return right->virtualAddress == leftEnd;
}

static VOID
kswordArkMemoryEvidenceFillNonModuleRow(
    _Out_ KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW* row,
    _In_ ULONG64 pageAddress,
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo,
    _In_ ULONG sampleBytes
    )
/*++

Routine Description:

    Build one executable page row for an address outside loaded module ranges.

Arguments:

    Row - Output evidence row.
    PageAddress - Page or large-page base address.
    PageInfo - Read-only page-table query result.
    SampleBytes - Number of bytes to sample.

Return Value:

    None. The function writes only Row.

--*/
{
    ULONG permissionFlags = 0UL;
    ULONG riskFlags = 0UL;
    ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_UNKNOWN;
    ULONG pageSize = (pageInfo != NULL && pageInfo->pageSize != 0UL) ? pageInfo->pageSize : PAGE_SIZE;

    kswordArkMemoryEvidenceInitRow(
        row,
        KSWORD_ARK_MEMORY_EVIDENCE_KIND_EXECUTABLE_RANGE,
        pageAddress,
        (ULONG64)pageSize,
        pageSize);
    if (row == NULL || pageInfo == NULL) {
        return;
    }

    kswordArkMemoryEvidencePermissionFromPage(pageInfo, &permissionFlags, &riskFlags, &confidence);
    row->permissionFlags = permissionFlags;
    row->ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NONMODULE;
    row->backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_PRIVATE;
    row->rowFlags = KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_NONMODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_SECTION_HINT_UNAVAILABLE;
    row->riskFlags = riskFlags |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_RISK_OWNER_MISSING;
    if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_WRITE) != 0UL &&
        (permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
        row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_RWX_PRIVATE;
    }
    else if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
        row->rowFlags |= KSWORD_ARK_MEMORY_EVIDENCE_ROW_FLAG_RX_PRIVATE;
        row->riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_RX_PRIVATE;
    }
    row->sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_UNAVAILABLE;
    row->confidence = confidence;
    row->lastStatus = pageInfo->walkStatus;
    kswordArkMemoryEvidenceCopyWideLiteral(row->ownerName, KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS, L"NonModule");
    kswordArkMemoryEvidenceFillSample(row, pageAddress, sampleBytes);
    kswordArkMemoryEvidenceApplyImageLikeHint(row);
    (VOID)RtlStringCchCopyW(
        row->detail,
        KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS,
        L"bounded range executable private/non-module page; section hint unavailable");
}

static NTSTATUS
kswordArkMemoryEvidenceScanNonModuleRange(
    _Inout_ KswMemoryEvidenceState* state,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* request,
    _In_ const KswMemoryEvidenceLimits* limits,
    _In_ const KswHookSystemModuleInformation* moduleInfo
    )
/*++

Routine Description:

    Scan a caller-bounded range for executable pages outside loaded modules.

Arguments:

    State - Mutable response state.
    Request - Request with required startAddress/endAddress bounds.
    Limits - Effective scan limits.
    ModuleInfo - Reused loaded module snapshot.

Return Value:

    STATUS_SUCCESS or first page-query failure status.

--*/
{
    ULONG64 pageAddress = 0ULL;
    KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW aggregate;
    BOOLEAN haveAggregate = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (state == NULL || state->response == NULL || request == NULL || limits == NULL || moduleInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((limits->effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) == 0UL) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&aggregate, sizeof(aggregate));
    pageAddress = kswordArkKernelExecAlignDown(request->startAddress, PAGE_SIZE);
    while (pageAddress < request->endAddress) {
        KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
        KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW row;
        ULONG pageSize = PAGE_SIZE;
        ULONG64 nextAddress = 0ULL;

        if (kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)pageAddress) != NULL) {
            pageAddress += PAGE_SIZE;
            continue;
        }
        if (!kswordArkMemoryEvidenceConsumeBudget(state, PAGE_SIZE)) {
            break;
        }

        RtlZeroMemory(&pageInfo, sizeof(pageInfo));
        status = kswordArkKernelExecQueryPage(pageAddress, &pageInfo);
        if (!NT_SUCCESS(status)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = status;
            }
            pageAddress += PAGE_SIZE;
            continue;
        }
        if (pageInfo.queryStatus != KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK ||
            pageInfo.resolved == 0UL ||
            (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) == 0UL ||
            (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
            pageAddress += PAGE_SIZE;
            continue;
        }

        pageSize = (pageInfo.pageSize != 0UL) ? pageInfo.pageSize : PAGE_SIZE;
        if (pageSize > PAGE_SIZE &&
            !kswordArkMemoryEvidenceConsumeBudget(state, (ULONG64)pageSize - (ULONG64)PAGE_SIZE)) {
            break;
        }
        nextAddress = pageAddress + (ULONG64)pageSize;
        if (nextAddress <= pageAddress) {
            break;
        }
        kswordArkMemoryEvidenceFillNonModuleRow(&row, pageAddress, &pageInfo, limits->sampleBytes);

        if (haveAggregate && kswordArkMemoryEvidenceCanMergeNonModule(&aggregate, &row)) {
            aggregate.regionSize += row.regionSize;
            aggregate.contentHash ^= row.contentHash;
        }
        else {
            if (haveAggregate) {
                kswordArkMemoryEvidenceAppendRow(state, &aggregate);
                if (state->truncated) {
                    break;
                }
            }
            aggregate = row;
            haveAggregate = TRUE;
        }
        pageAddress = nextAddress;
    }

    if (haveAggregate && !state->truncated) {
        kswordArkMemoryEvidenceAppendRow(state, &aggregate);
    }
    return firstFailure;
}

static VOID
kswordArkMemoryEvidenceFillTagWide(
    _In_reads_bytes_(4) const UCHAR tagChars[4],
    _Out_writes_(5) WCHAR tagText[5]
    )
/*++

Routine Description:

    Convert a four-byte BigPool tag into printable WCHAR text.

Arguments:

    TagChars - Raw BigPool tag bytes.
    TagText - Five-WCHAR destination including terminator.

Return Value:

    None. NUL bytes are displayed as spaces.

--*/
{
    ULONG index = 0UL;

    if (tagText == NULL) {
        return;
    }
    for (index = 0UL; index < 4UL; ++index) {
        UCHAR ch = (tagChars != NULL) ? tagChars[index] : ' ';
        tagText[index] = (WCHAR)(ch == 0U ? ' ' : ch);
    }
    tagText[4] = L'\0';
}

static NTSTATUS
kswordArkMemoryEvidenceScanBigPool(
    _Inout_ KswMemoryEvidenceState* state,
    _In_ const KswMemoryEvidenceLimits* limits
    )
/*++

Routine Description:

    Query SystemBigPoolInformation and emit bounded BigPool evidence rows.

Arguments:

    State - Mutable response state.
    Limits - Effective BigPool and scan-cost limits.

Return Value:

    STATUS_SUCCESS or ZwQuerySystemInformation/allocation failure status.

--*/
{
    PVOID buffer = NULL;
    ULONG bufferBytes = 0UL;
    ULONG rowIndex = 0UL;
    ULONG count = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (state == NULL || state->response == NULL || limits == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((limits->effectiveFlags & (KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL)) == 0UL) {
        return STATUS_SUCCESS;
    }

    status = ZwQuerySystemInformation(
        KSW_MEMORY_EVIDENCE_SYSTEM_BIG_POOL_INFORMATION_CLASS,
        NULL,
        0UL,
        &bufferBytes);
    if (bufferBytes == 0UL) {
        state->response->lastStatus = NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
        return state->response->lastStatus;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    buffer = ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_MEMORY_EVIDENCE_TAG);
#pragma warning(pop)
    if (buffer == NULL) {
        state->response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        KSW_MEMORY_EVIDENCE_SYSTEM_BIG_POOL_INFORMATION_CLASS,
        buffer,
        bufferBytes,
        &bufferBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, KSW_MEMORY_EVIDENCE_TAG);
        state->response->lastStatus = status;
        return status;
    }

    count = ((KswMemoryEvidenceBigpoolInformation*)buffer)->count;
    for (rowIndex = 0UL; rowIndex < count; ++rowIndex) {
        KswMemoryEvidenceBigpoolEntry* entry = NULL;
        KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW row;
        KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
        WCHAR tagText[5];
        ULONG permissionFlags = 0UL;
        ULONG pageRiskFlags = 0UL;
        ULONG confidence = KSWORD_ARK_MEMORY_EVIDENCE_CONFIDENCE_LOW;
        ULONG bigPoolFlags = 0UL;
        ULONG ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL;
        ULONG riskFlags = 0UL;
        ULONG64 rawAddress = 0ULL;
        ULONG64 address = 0ULL;
        ULONG64 size = 0ULL;
        BOOLEAN isExecutable = FALSE;
        BOOLEAN isSuspicious = FALSE;

        if (rowIndex >= limits->maxBigPoolRows) {
            state->truncated = TRUE;
            state->response->responseFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_BIGPOOL_TRUNCATED;
            break;
        }
        entry = &((KswMemoryEvidenceBigpoolInformation*)buffer)->allocatedInfo[rowIndex];
        state->response->bigPoolRowsSeen += 1UL;

        rawAddress = (ULONG64)entry->address.nonPaged;
        address = rawAddress & ~(ULONG64)1ULL;
        size = (ULONG64)entry->sizeInBytes;
        if ((rawAddress & 1ULL) != 0ULL) {
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED;
        }
        if (address == 0ULL || size == 0ULL) {
            continue;
        }

        if (kswordArkMemoryEvidenceTagContains3(entry->tag.tagChars, 'P', 'T', 'E')) {
            ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE;
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_TAG_SYSTEM_PTE_LIKE;
        }
        if (kswordArkMemoryEvidenceTagContains3(entry->tag.tagChars, 'M', 'D', 'L')) {
            ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE;
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_TAG_MDL_LIKE;
        }

        if (!kswordArkMemoryEvidenceConsumeBudget(state, PAGE_SIZE)) {
            break;
        }
        RtlZeroMemory(&pageInfo, sizeof(pageInfo));
        status = kswordArkKernelExecQueryPage(kswordArkKernelExecAlignDown(address, PAGE_SIZE), &pageInfo);
        if (NT_SUCCESS(status) && pageInfo.queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK) {
            kswordArkMemoryEvidencePermissionFromPage(&pageInfo, &permissionFlags, &pageRiskFlags, &confidence);
            if ((permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE) != 0UL) {
                isExecutable = TRUE;
                bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_EXECUTABLE;
            }
        }

        isSuspicious = ((bigPoolFlags & KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED) != 0UL &&
            (ownerKind == KSWORD_ARK_MEMORY_EVIDENCE_OWNER_SYSTEM_PTE ||
                ownerKind == KSWORD_ARK_MEMORY_EVIDENCE_OWNER_MDL_LIKE));
        if (isSuspicious) {
            bigPoolFlags |= KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_EXECUTABLE_SUSPECTED;
        }
        if (isExecutable || isSuspicious) {
            riskFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL;
        }
        riskFlags |= pageRiskFlags;

        if ((limits->effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL) == 0UL &&
            (limits->effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL) != 0UL &&
            !isExecutable && !isSuspicious) {
            continue;
        }

        kswordArkMemoryEvidenceInitRow(
            &row,
            KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL,
            address,
            size,
            (pageInfo.pageSize != 0UL) ? pageInfo.pageSize : PAGE_SIZE);
        row.permissionFlags = permissionFlags;
        row.ownerKind = ownerKind;
        row.riskFlags = riskFlags;
        row.confidence = confidence;
        row.backingKind = KSWORD_ARK_MEMORY_EVIDENCE_BACKING_BIGPOOL;
        row.sectionHintStatus = KSWORD_ARK_MEMORY_EVIDENCE_SECTION_HINT_NOT_APPLICABLE;
        row.ownerAddress = address;
        row.lastStatus = NT_SUCCESS(status) ? pageInfo.walkStatus : status;
        row.bigPoolTag = entry->tag.tagUlong;
        row.bigPoolFlags = bigPoolFlags;
        kswordArkMemoryEvidenceCopyWideLiteral(row.ownerName, KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS, L"BigPool");
        kswordArkMemoryEvidenceFillSample(&row, address, limits->sampleBytes);
        kswordArkMemoryEvidenceApplyImageLikeHint(&row);
        kswordArkMemoryEvidenceFillTagWide(entry->tag.tagChars, tagText);
        (VOID)RtlStringCchPrintfW(
            row.detail,
            KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS,
            L"tag=%ws nonPaged=%lu executable=%lu suspected=%lu size=0x%I64X",
            tagText,
            (bigPoolFlags & KSWORD_ARK_MEMORY_EVIDENCE_BIGPOOL_FLAG_NON_PAGED) ? 1UL : 0UL,
            isExecutable ? 1UL : 0UL,
            isSuspicious ? 1UL : 0UL,
            size);

        kswordArkMemoryEvidenceAppendRow(state, &row);
        if (state->truncated || state->budgetExhausted) {
            break;
        }
    }

    ExFreePoolWithTag(buffer, KSW_MEMORY_EVIDENCE_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverScanKernelMemoryEvidence(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Collect read-only kernel memory evidence rows for executable pages, BigPool,
    page-table permissions, and text-section memory samples. The routine rejects
    non-PASSIVE_LEVEL callers and never writes kernel memory, PTEs, or CR0.WP.

Arguments:

    OutputBuffer - METHOD_BUFFERED response buffer.
    OutputBufferLength - Response buffer length.
    Request - Evidence scan request with flags and cost limits.
    BytesWrittenOut - Receives response byte count.

Return Value:

    STATUS_SUCCESS when a response header is valid; response->status/lastStatus
    describe scan completeness. Parameter/buffer errors are returned directly.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE* response = NULL;
    KswMemoryEvidenceLimits limits;
    KswMemoryEvidenceState state;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    size_t rowCapacitySize = 0U;
    ULONG rowCapacity = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstPartialStatus = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;

    if (outputBufferLength < KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    rowCapacitySize = (outputBufferLength - KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
    rowCapacity = (rowCapacitySize > (size_t)KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS) ?
        KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS :
        (ULONG)rowCapacitySize;
    RtlZeroMemory(&limits, sizeof(limits));
    status = kswordArkMemoryEvidenceValidateRequest(request, &limits);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (limits.maxRows > rowCapacity) {
        limits.maxRows = rowCapacity;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE;
    response->sourceFlags = limits.effectiveFlags;
    response->rowSize = sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
    response->maxRows = limits.maxRows;
    response->maxBytes = limits.maxBytes;
    response->lastStatus = STATUS_SUCCESS;

    RtlZeroMemory(&state, sizeof(state));
    state.response = response;
    state.rowCapacity = limits.maxRows;

    if ((limits.effectiveFlags & (
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES |
        KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_TEXT_SECTION_SAMPLES)) != 0UL) {
        status = kswordArkMemoryEvidenceScanModules(&state, request, &limits, &moduleInfo);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = status;
        }
    }

    if (!state.budgetExhausted &&
        !state.truncated &&
        moduleInfo != NULL &&
        (limits.effectiveFlags & KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_NONMODULE_EXECUTABLE_RANGES) != 0UL) {
        status = kswordArkMemoryEvidenceScanNonModuleRange(&state, request, &limits, moduleInfo);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = status;
        }
    }

    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        moduleInfo = NULL;
    }

    if (!state.budgetExhausted && !state.truncated) {
        status = kswordArkMemoryEvidenceScanBigPool(&state, &limits);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = status;
        }
    }

    response->returnedRows = state.returnedRows;
    response->bytesScanned = state.bytesScanned;
    if (state.truncated) {
        response->responseFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_TRUNCATED;
    }
    if (state.budgetExhausted) {
        response->responseFlags |= KSWORD_ARK_MEMORY_EVIDENCE_RESPONSE_FLAG_BUDGET_EXHAUSTED;
    }

    if (state.truncated || state.budgetExhausted || !NT_SUCCESS(firstPartialStatus)) {
        response->status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL;
        response->lastStatus = state.truncated ? STATUS_BUFFER_TOO_SMALL : firstPartialStatus;
    }
    else {
        response->status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
    }

    *bytesWrittenOut = KSW_MEMORY_EVIDENCE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedRows * sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW));
    return STATUS_SUCCESS;
}

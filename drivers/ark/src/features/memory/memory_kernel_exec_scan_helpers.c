/*++

Module Name:

    memory_kernel_exec_scan_helpers.c

Abstract:

    Helper routines for conservative kernel executable page scanning.

Environment:

    Kernel-mode Driver Framework

--*/

#include "memory_kernel_exec_scan_internal.h"

ULONG64
kswordArkKernelExecAlignDown(
    _In_ ULONG64 value,
    _In_ ULONG64 alignment
    )
/*++

Routine Description:

    Align the address downward using the actual pageSize for page-table scans. This
    function only computes power-of-2 alignment; it does not access the target address.

Arguments:

    Value - Input address.
    Alignment is the alignment granularity and must be a power of 2; invalid inputs degrade to the original value.

Return Value:

    Returns the aligned address; the function does not return an error status.

--*/
{
    if (alignment == 0ULL || (alignment & (alignment - 1ULL)) != 0ULL) {
        return value;
    }
    return value & ~(alignment - 1ULL);
}

BOOLEAN
kswordArkKernelExecRangeIntersectsRequest(
    _In_ ULONG64 rangeStart,
    _In_ ULONG64 rangeEnd,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request
    )
/*++

Routine Description:

    Check if the half-open interval intersects with the request address filter. Note: startAddress/endAddress
    both being 0 means no filtering; endAddress being 0 means from startAddress to the highest address.

Arguments:

    RangeStart - Start address of the candidate half-open interval.
    RangeEnd - End address of the candidate half-open interval.
    Request - Snapshot of this scan request.

Return Value:

    TRUE indicates the candidate interval requires scanning or returning; FALSE indicates it can be skipped.

--*/
{
    ULONG64 filterEnd = 0ULL;

    if (request == NULL) {
        return FALSE;
    }
    if (rangeEnd <= rangeStart) {
        return FALSE;
    }
    if (request->startAddress == 0ULL && request->endAddress == 0ULL) {
        return TRUE;
    }

    filterEnd = (request->endAddress == 0ULL) ? MAXULONGLONG : request->endAddress;
    if (rangeEnd <= request->startAddress) {
        return FALSE;
    }
    if (rangeStart >= filterEnd) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkKernelExecSectionIsTextLike(
    _In_ const IMAGE_SECTION_HEADER* sectionHeader
    )
/*++

Routine Description:

    Determine whether a PE section should be classified as module code/text. Note:
    Prefer IMAGE_SCN_CNT_CODE while maintaining compatibility with common .text
    names; other executable sections are classified as module non-text executable.

Arguments:

    SectionHeader: A section header safely copied to the local stack.

Return Value:

    TRUE indicates a text/code class section; FALSE indicates a non-text class section.

--*/
{
    if (sectionHeader == NULL) {
        return FALSE;
    }
    if ((sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) != 0UL) {
        return TRUE;
    }
    if (sectionHeader->Name[0] == '.' &&
        (sectionHeader->Name[1] == 't' || sectionHeader->Name[1] == 'T') &&
        (sectionHeader->Name[2] == 'e' || sectionHeader->Name[2] == 'E') &&
        (sectionHeader->Name[3] == 'x' || sectionHeader->Name[3] == 'X') &&
        (sectionHeader->Name[4] == 't' || sectionHeader->Name[4] == 'T')) {
        return TRUE;
    }
    return FALSE;
}

static ULONG64
kswordArkKernelExecFnv1a64(
    _In_reads_bytes_(bytesToHash) const UCHAR* bytes,
    _In_ ULONG bytesToHash
    )
/*++

Routine Description:

    Compute the FNV-1a 64-bit hash of the first byte sample of the executable. Note: The caller has already copied
    kernel bytes to a local buffer; this function does not access the target address nor return the original bytes.

Arguments:

    Bytes - Local sample buffer.
    BytesToHash - Sample length.

Return Value:

    Hash value; returns 0 if input is null.

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

BOOLEAN
kswordArkKernelExecSafeModuleRange(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Out_ ULONG64* moduleBaseOut,
    _Out_ ULONG64* moduleEndOut
    )
/*++

Routine Description:

    Safely compute the semi-open address range of a module image. Note: Although SystemModuleInformation comes
    from the kernel, we must prevent base + size wraparound from affecting address filtering and section trimming.

Arguments:

    ModuleEntry - Loaded module entry.
    ModuleBaseOut: Returns the module base address.
    ModuleEndOut: Returns the module end address.

Return Value:

    TRUE indicates a valid interval; FALSE indicates the entry lacks a base address/size or an integer overflow occurred.

--*/
{
    ULONG64 moduleBase = 0ULL;

    if (moduleEntry == NULL || moduleBaseOut == NULL || moduleEndOut == NULL) {
        return FALSE;
    }
    *moduleBaseOut = 0ULL;
    *moduleEndOut = 0ULL;
    if (moduleEntry->imageBase == NULL || moduleEntry->imageSize == 0UL) {
        return FALSE;
    }

    moduleBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
    if ((ULONG64)moduleEntry->imageSize > (MAXULONGLONG - moduleBase)) {
        return FALSE;
    }

    *moduleBaseOut = moduleBase;
    *moduleEndOut = moduleBase + (ULONG64)moduleEntry->imageSize;
    return TRUE;
}

static BOOLEAN
kswordArkKernelExecCanMergeEntry(
    _In_ const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* left,
    _In_ const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* right,
    _Out_opt_ BOOLEAN* overlapOut
    )
/*++

Routine Description:

    Check if two scan results belong to the same continuous interval. Note: Only merge adjacent pages sharing the
    same module, page size, permissions, and risk classification; return overlap on large page duplicate hits.

Arguments:

    Left - Aggregated previous result.
    Right - new candidate result.
    OverlapOut - Optional output; TRUE indicates Right falls within Left's coverage range.

Return Value:

    TRUE indicates entries can be merged into one; FALSE indicates a new entry should be created or duplicates skipped.

--*/
{
    ULONG64 leftBytes = 0ULL;
    ULONG64 leftEnd = 0ULL;

    if (overlapOut != NULL) {
        *overlapOut = FALSE;
    }
    if (left == NULL || right == NULL || left->pageSize == 0UL) {
        return FALSE;
    }
    if (left->moduleBase != right->moduleBase ||
        left->moduleSize != right->moduleSize ||
        left->pageSize != right->pageSize ||
        left->sectionOwnerBase != right->sectionOwnerBase ||
        left->sectionRva != right->sectionRva ||
        left->sectionSize != right->sectionSize ||
        left->unknownExecutable != right->unknownExecutable) {
        return FALSE;
    }

    leftBytes = (ULONG64)left->pageCount * (ULONG64)left->pageSize;
    if (leftBytes > (MAXULONGLONG - left->virtualAddress)) {
        return FALSE;
    }
    leftEnd = left->virtualAddress + leftBytes;

    if (right->virtualAddress < leftEnd) {
        if (overlapOut != NULL) {
            *overlapOut = TRUE;
        }
        return FALSE;
    }
    if (left->effectiveFlags != right->effectiveFlags ||
        left->protection != right->protection ||
        left->riskFlags != right->riskFlags ||
        left->ownerKind != right->ownerKind ||
        left->hashAlgorithm != right->hashAlgorithm ||
        left->hashStatus != right->hashStatus ||
        left->firstBytesHashed != right->firstBytesHashed ||
        RtlCompareMemory(
            left->sectionName,
            right->sectionName,
            KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES) !=
            KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES) {
        return FALSE;
    }
    return right->virtualAddress == leftEnd;
}

static VOID
kswordArkKernelExecMakeEntryMoreConservative(
    _Inout_ KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* target,
    _In_ const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* source
    )
/*++

Routine Description:

    Guide existing scan rows toward more conservative classifications. Note: When the same page is observed repeatedly across
    multiple sections, a higher-risk classification from a later observation should override a lower-risk label from an earlier one.

Arguments:

    Target - Currently scanned row that has been written.
    Source - newly observed higher-risk candidate.

Return Value:

    None. The function only updates Target.

--*/
{
    if (target == NULL || source == NULL) {
        return;
    }

    target->effectiveFlags |= source->effectiveFlags;
    target->protection |= source->protection;
    target->riskFlags |= source->riskFlags;
    if (source->ownerKind > target->ownerKind) {
        target->ownerKind = source->ownerKind;
    }
    if (target->hashStatus != KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_READ_FAILED &&
        source->hashStatus == KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_READ_FAILED) {
        target->hashStatus = source->hashStatus;
        target->riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_FIRST_BYTES_UNREADABLE;
    }
}

VOID
kswordArkKernelExecAddEntry(
    _Inout_ KswKernelExecScanState* state,
    _In_ const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* candidate
    )
/*++

Routine Description:

    Aggregate a candidate executable page into the response. Note: totalCount tracks the number of rows after
    aggregation; if the output buffer is insufficient, continue maintaining totalCount without writing out of bounds.

Arguments:

    State: Scan state containing response header, capacity, and previous aggregation result.
    Candidate: New page or large page candidate.

Return Value:

    None. The function only updates State/Response.

--*/
{
    BOOLEAN overlap = FALSE;

    if (state == NULL || state->response == NULL || candidate == NULL || candidate->pageCount == 0UL) {
        return;
    }

    if (state->haveLastAggregate) {
        if (kswordArkKernelExecCanMergeEntry(&state->lastAggregate, candidate, &overlap)) {
            state->lastAggregate.pageCount += candidate->pageCount;
            state->lastAggregate.regionSize += candidate->regionSize;
            kswordArkKernelExecMakeEntryMoreConservative(&state->lastAggregate, candidate);
            if (!state->truncated && state->response->returnedCount > 0UL) {
                state->response->entries[state->response->returnedCount - 1UL].pageCount =
                    state->lastAggregate.pageCount;
                state->response->entries[state->response->returnedCount - 1UL].regionSize =
                    state->lastAggregate.regionSize;
                kswordArkKernelExecMakeEntryMoreConservative(
                    &state->response->entries[state->response->returnedCount - 1UL],
                    candidate);
            }
            return;
        }
        if (overlap) {
            kswordArkKernelExecMakeEntryMoreConservative(&state->lastAggregate, candidate);
            if (!state->truncated && state->response->returnedCount > 0UL) {
                kswordArkKernelExecMakeEntryMoreConservative(
                    &state->response->entries[state->response->returnedCount - 1UL],
                    candidate);
            }
            return;
        }
    }

    RtlCopyMemory(&state->lastAggregate, candidate, sizeof(state->lastAggregate));
    state->haveLastAggregate = TRUE;
    state->response->totalCount += 1UL;
    if (state->response->returnedCount < state->entryCapacity) {
        RtlCopyMemory(
            &state->response->entries[state->response->returnedCount],
            candidate,
            sizeof(*candidate));
        state->response->returnedCount += 1UL;
    }
    else {
        state->truncated = TRUE;
    }
}

NTSTATUS
kswordArkKernelExecQueryPage(
    _In_ ULONG64 virtualAddress,
    _Out_ KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* infoOut
    )
/*++

Routine Description:

    Query page table information for a kernel virtual address. Note: Reuse the existing
    kswordArkDriverQueryPageTableEntry backend to maintain consistent Present/NX/Writable parsing semantics with
    the single-address page table IOCTL; this function reads page tables only and does not modify PTEs/PDEs.

Arguments:

    VirtualAddress: The kernel virtual address to be queried.
    InfoOut: Receives the page table parsing result.

Return Value:

    STATUS_SUCCESS indicates InfoOut is initialized; parse failure details are in InfoOut->queryStatus.

--*/
{
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST request;
    KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE response;
    size_t bytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (infoOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(infoOut, sizeof(*infoOut));
    RtlZeroMemory(&request, sizeof(request));
    RtlZeroMemory(&response, sizeof(response));

    request.processId = 0UL;
    request.virtualAddress = virtualAddress;
    status = kswordArkDriverQueryPageTableEntry(
        &response,
        sizeof(response),
        &request,
        &bytesWritten);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (bytesWritten < sizeof(response)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(infoOut, &response.info, sizeof(*infoOut));
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkKernelExecPageQueryFailureStatus(
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo
    )
/*++

Routine Description:

    Convert page table query protocol status to a recordable NTSTATUS. Note: The page table backend typically returns
    STATUS_SUCCESS and places details in queryStatus/walkStatus; the scanning layer must pass severe states such as unsupported
    operations, read failures, or invalid addresses to lastStatus to avoid false positives indicating a complete conservative scan.

Arguments:

    PageInfo - Single page page table query result.

Return Value:

    Returns an NTSTATUS usable for response->lastStatus; returns STATUS_UNSUCCESSFUL if granularity is not possible.

--*/
{
    if (pageInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(pageInfo->walkStatus) &&
        pageInfo->walkStatus != STATUS_NO_MEMORY) {
        return pageInfo->walkStatus;
    }
    if (pageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_PROCESS_LOOKUP_FAILED) {
        return NT_SUCCESS(pageInfo->lookupStatus) ? STATUS_NOT_FOUND : pageInfo->lookupStatus;
    }
    if (pageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_INVALID_ADDRESS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (pageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_SUPPORTED) {
        return STATUS_NOT_SUPPORTED;
    }
    if (pageInfo->queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_IRQL_REJECTED) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    return STATUS_UNSUCCESSFUL;
}

BOOLEAN
kswordArkKernelExecShouldReturnCandidate(
    _In_ ULONG requestFlags,
    _In_ ULONG ownerKind,
    _In_ ULONG riskFlags
    )
/*++

Routine Description:

    Determine whether candidate rows should be returned based on request flags. Note: When flags are 0, it is equivalent to
    INCLUDE_ALL. Writable executable regions, even if from a text section, can still be matched by the corresponding risk filter.

Arguments:

    RequestFlags - Request flags.
    OwnerKind - Candidate ownerKind.
    RiskFlags - candidate riskFlags.

Return Value:

    TRUE indicates this candidate should be included in the response; FALSE indicates it should be skipped.

--*/
{
    ULONG effectiveFlags = requestFlags;

    if (effectiveFlags == 0UL) {
        effectiveFlags = KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL;
    }
    if ((effectiveFlags & KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_WRITABLE_EXECUTABLE) != 0UL &&
        (riskFlags & KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE) != 0UL) {
        return TRUE;
    }
    if ((effectiveFlags & KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_MODULE_TEXT) != 0UL &&
        ownerKind == KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT) {
        return TRUE;
    }
    if ((effectiveFlags & KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_MODULE_NON_TEXT) != 0UL &&
        ownerKind == KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT) {
        return TRUE;
    }
    if ((effectiveFlags & KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_UNKNOWN_EXECUTABLE) != 0UL &&
        (riskFlags & KSWORD_ARK_KERNEL_EXEC_RISK_UNKNOWN_EXECUTABLE) != 0UL) {
        return TRUE;
    }
    return FALSE;
}

ULONG
kswordArkKernelExecProtectionFromPage(
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo
    )
/*++

Routine Description:

    Convert page table effectiveFlags into a memory protection summary. Note: This summary is used solely
    for R3 display of P/R/W/X/NX/large/global/user states and does not drive any write or repair actions.

Arguments:

    PageInfo - Page table read-only query result.

Return Value:

    KSWORD_ARK_MEMORY_PROTECTION_* bitmap; returns 0 if input is invalid.

--*/
{
    ULONG protection = 0UL;

    if (pageInfo == NULL) {
        return 0UL;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_PRESENT |
            KSWORD_ARK_MEMORY_PROTECTION_READ;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_WRITE;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_NX;
    }
    else if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_EXECUTE;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_GLOBAL;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_USER;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE) != 0UL ||
        pageInfo->largePageType != KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE) {
        protection |= KSWORD_ARK_MEMORY_PROTECTION_LARGE;
    }
    return protection;
}

BOOLEAN
kswordArkKernelExecReadFirstBytesHash(
    _In_ ULONG64 virtualAddress,
    _In_ ULONG bytesToHash,
    _Out_ ULONG64* hashOut,
    _Out_ ULONG* bytesHashedOut
    )
/*++

Routine Description:

    Copy the first bytes of the executable to a read-only buffer and compute its hash. Note: The function uses MmCopyMemory with virtual
    addresses and SEH protection; it returns only the hash and length, not the original bytes, and does not modify the target page.

Arguments:

    VirtualAddress - The kernel virtual address to be read.
    BytesToHash - Requested hash length; caller has already normalized to a hard upper limit.
    HashOut - Receives the FNV-1a 64-bit hash.
    BytesHashedOut - Receives the actual number of hashed bytes.

Return Value:

    TRUE indicates a complete read and hash were performed; FALSE indicates a read failure or invalid parameters.

--*/
{
    UCHAR localBytes[KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX];
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    ULONG hashLength = bytesToHash;
    NTSTATUS status = STATUS_SUCCESS;

    if (hashOut != NULL) {
        *hashOut = 0ULL;
    }
    if (bytesHashedOut != NULL) {
        *bytesHashedOut = 0UL;
    }
    if (virtualAddress == 0ULL ||
        hashOut == NULL ||
        bytesHashedOut == NULL ||
        hashLength == 0UL) {
        return FALSE;
    }
    if (hashLength > KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX) {
        hashLength = KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX;
    }

    RtlZeroMemory(localBytes, sizeof(localBytes));
    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)virtualAddress;
    __try {
        status = MmCopyMemory(
            localBytes,
            copyAddress,
            (SIZE_T)hashLength,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copiedBytes = 0U;
    }

    if (!NT_SUCCESS(status) || copiedBytes != (SIZE_T)hashLength) {
        RtlZeroMemory(localBytes, sizeof(localBytes));
        return FALSE;
    }

    *hashOut = kswordArkKernelExecFnv1a64(localBytes, hashLength);
    *bytesHashedOut = hashLength;
    RtlZeroMemory(localBytes, sizeof(localBytes));
    return TRUE;
}

VOID
kswordArkKernelExecFillCandidate(
    _In_ ULONG64 pageAddress,
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo,
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_reads_bytes_(modulePathBytes) const UCHAR* modulePath,
    _In_ ULONG modulePathBytes,
    _In_ const KswKernelExecSectionOwner* sectionOwner,
    _In_ ULONG hashBytes,
    _Out_ KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* candidate
    )
/*++

Routine Description:

    Construct a kernel executable page response row. Note: ownerKind and riskFlags are determined jointly by
    PE section attribution, page table effectiveFlags, and the first-byte hash status; the module path is
    sourced from SystemModuleInformation; the function reads memory only and does not return raw sample bytes.

Arguments:

    PageAddress - Starting virtual address of a page or large page.
    PageInfo - Page table query result.
    ModuleEntry - Associated loaded module.
    modulePath: Module path ANSI interval.
    ModulePathBytes - Maximum number of bytes for the module path.
    SectionOwner - Attribution information for the current page section.
    HashBytes: Length of the first-byte hash; 0 indicates no calculation.
    Candidate - Output response row.

Return Value:

    None. The function only writes to Candidate.

--*/
{
    ULONG ownerKind = KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT;
    ULONG riskFlags = KSWORD_ARK_KERNEL_EXEC_RISK_NONE;
    ULONG pageSize = PAGE_SIZE;

    if (candidate == NULL || pageInfo == NULL || moduleEntry == NULL) {
        return;
    }

    RtlZeroMemory(candidate, sizeof(*candidate));
    pageSize = (pageInfo->pageSize != 0UL) ? pageInfo->pageSize : PAGE_SIZE;
    candidate->virtualAddress = pageAddress;
    candidate->regionSize = (ULONG64)pageSize;
    candidate->pageCount = 1UL;
    candidate->pageSize = pageSize;
    candidate->effectiveFlags = pageInfo->effectiveFlags;
    candidate->protection = kswordArkKernelExecProtectionFromPage(pageInfo);
    candidate->moduleBase = (ULONG64)(ULONG_PTR)moduleEntry->imageBase;
    candidate->moduleSize = moduleEntry->imageSize;
    candidate->hashAlgorithm = KSWORD_ARK_KERNEL_EXEC_HASH_NONE;
    candidate->hashStatus = KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_UNAVAILABLE;

    if (sectionOwner == NULL || !sectionOwner->found) {
        ownerKind = KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_UNKNOWN_SECTION;
        riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_UNKNOWN_EXECUTABLE;
        candidate->unknownExecutable = 1UL;
    }
    else if (!sectionOwner->isTextLike) {
        ownerKind = KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_NON_TEXT;
        riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE;
    }
    if (sectionOwner != NULL && sectionOwner->isWritable) {
        riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE;
    }
    if ((pageInfo->effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        ownerKind = KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE;
        riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE;
    }
    if (pageInfo->largePageType != KSWORD_ARK_PAGE_TABLE_LARGE_PAGE_NONE) {
        riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE;
    }

    if (sectionOwner != NULL) {
        candidate->sectionOwnerBase = candidate->moduleBase;
        candidate->sectionRva = sectionOwner->sectionRva;
        candidate->sectionSize = sectionOwner->sectionSize;
        RtlCopyMemory(
            candidate->sectionName,
            sectionOwner->sectionName,
            KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES);
    }
    if (hashBytes != 0UL) {
        ULONG bytesHashed = 0UL;
        ULONG64 contentHash = 0ULL;

        if (kswordArkKernelExecReadFirstBytesHash(
            pageAddress,
            hashBytes,
            &contentHash,
            &bytesHashed)) {
            candidate->hashAlgorithm = KSWORD_ARK_KERNEL_EXEC_HASH_FNV1A64;
            candidate->hashStatus = KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_OK;
            candidate->firstBytesHashed = bytesHashed;
            candidate->contentHash = contentHash;
        }
        else {
            candidate->hashStatus = KSWORD_ARK_KERNEL_EXEC_HASH_STATUS_READ_FAILED;
            riskFlags |= KSWORD_ARK_KERNEL_EXEC_RISK_FIRST_BYTES_UNREADABLE;
        }
    }

    candidate->ownerKind = ownerKind;
    candidate->riskFlags = riskFlags;
    kswordArkHookCopyBoundedAnsiToWide(
        modulePath,
        modulePathBytes,
        candidate->modulePath,
        KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS);
}

VOID
kswordArkKernelExecClassifyPageBySections(
    _In_reads_(sectionCount) const IMAGE_SECTION_HEADER* sectionHeaders,
    _In_ ULONG sectionCount,
    _In_ ULONG64 moduleBase,
    _In_ ULONG moduleSize,
    _In_ ULONG64 pageAddress,
    _In_ ULONG pageSize,
    _Out_ KswKernelExecSectionOwner* sectionOwnerOut
    )
/*++

Routine Description:

    Classify a module page by PE section metadata. Scan range covers the full module image;
    sections are used only to mark executable pages as text / non-text / writable; pages in
    headers/gaps that do not match any section are conservatively classified as non-text.

Arguments:

    SectionHeaders: locally copied array of section headers.
    SectionCount: number of section headers.
    ModuleBase: Module load base address.
    ModuleSize: Module image size.
    PageAddress - Current page start address.
    PageSize: current page size, from page table parsing or default 4KB.
    SectionOwnerOut - Returns section hit, text/writable status, and attribution of the first section.

Return Value:

    None. The function only writes the output boolean.

--*/
{
    ULONG sectionIndex = 0UL;
    ULONG64 moduleEnd = moduleBase + (ULONG64)moduleSize;
    ULONG64 pageEnd = 0ULL;
    BOOLEAN hasTextSection = FALSE;
    BOOLEAN hasNonTextSection = FALSE;
    BOOLEAN hasWritableSection = FALSE;
    BOOLEAN hasAnySection = FALSE;

    if (sectionOwnerOut != NULL) {
        RtlZeroMemory(sectionOwnerOut, sizeof(*sectionOwnerOut));
    }
    if (sectionOwnerOut == NULL ||
        sectionHeaders == NULL ||
        sectionCount == 0UL ||
        moduleSize == 0UL ||
        pageSize == 0UL) {
        return;
    }
    if ((ULONG64)pageSize > (MAXULONGLONG - pageAddress)) {
        pageEnd = MAXULONGLONG;
    }
    else {
        pageEnd = pageAddress + (ULONG64)pageSize;
    }

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
        if ((ULONG64)sectionHeader->VirtualAddress > (MAXULONGLONG - moduleBase)) {
            continue;
        }

        sectionStart = moduleBase + (ULONG64)sectionHeader->VirtualAddress;
        if ((ULONG64)sectionSize > (MAXULONGLONG - sectionStart)) {
            sectionEnd = moduleEnd;
        }
        else {
            sectionEnd = sectionStart + (ULONG64)sectionSize;
        }
        if (sectionEnd > moduleEnd || sectionEnd < sectionStart) {
            sectionEnd = moduleEnd;
        }
        if (pageEnd <= sectionStart || pageAddress >= sectionEnd) {
            continue;
        }

        hasAnySection = TRUE;
        if (kswordArkKernelExecSectionIsTextLike(sectionHeader)) {
            hasTextSection = TRUE;
        }
        else {
            hasNonTextSection = TRUE;
        }
        if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0UL) {
            hasWritableSection = TRUE;
        }
        if (sectionOwnerOut->sectionRva == 0UL &&
            sectionOwnerOut->sectionSize == 0UL) {
            sectionOwnerOut->sectionRva = sectionHeader->VirtualAddress;
            sectionOwnerOut->sectionSize = sectionSize;
            RtlCopyMemory(
                sectionOwnerOut->sectionName,
                sectionHeader->Name,
                KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES);
        }
    }

    sectionOwnerOut->found = hasAnySection;
    sectionOwnerOut->isTextLike = (hasTextSection && !hasNonTextSection) ? TRUE : FALSE;
    sectionOwnerOut->isWritable = hasWritableSection;
}

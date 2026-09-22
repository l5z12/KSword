/*++

Module Name:

    memory_kernel_exec_scan.c

Abstract:

    Conservative read-only kernel executable page scanner for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "memory_kernel_exec_scan_internal.h"

static NTSTATUS
kswordArkKernelExecScanOnePage(
    _Inout_ KswKernelExecScanState* state,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request,
    _In_ ULONG64 pageAddress,
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_reads_(sectionCount) const IMAGE_SECTION_HEADER* sectionHeaders,
    _In_ ULONG sectionCount,
    _In_reads_bytes_(modulePathBytes) const UCHAR* modulePath,
    _In_ ULONG modulePathBytes,
    _Out_ ULONG64* nextAddressOut
    )
/*++

Routine Description:

    Scan a page or large-page address. Query the page table first; treat it as executable only when Present
    is set and NX is clear. Advance by the actual pageSize to avoid duplicate rows within a large page.
    Additionally, pages belonging to code sections that are either non-executable or writable are considered protection anomalies.
    These are returned together when the INCLUDE_SECTION_ANOMALY flag is requested, rather than being directly discarded by NX checks.

Arguments:

    State - Scan state.
    Request - Snapshot request.
    PageAddress - Current page-aligned address.
    ModuleEntry - Belonging module.
    SectionHeaders: locally copied array of section headers.
    SectionCount: number of section headers.
    modulePath - module path.
    ModulePathBytes: Maximum length of the module path.
    NextAddressOut - Returns the address for the next scan.

Return Value:

    STATUS_SUCCESS indicates this page is processed successfully; non-success indicates a page table backend exception.

--*/
{
    KSWORD_ARK_PAGE_TABLE_ENTRY_INFO pageInfo;
    KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY candidate;
    KswKernelExecSectionOwner sectionOwner;
    ULONG pageSize = PAGE_SIZE;
    ULONG64 pageBase = pageAddress;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG anomalyRisk = KSWORD_ARK_KERNEL_EXEC_RISK_NONE;
    BOOLEAN pageIsExecutable = FALSE;
    BOOLEAN pageIsWritable = FALSE;

    if (state == NULL || request == NULL || moduleEntry == NULL || nextAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (pageAddress > (MAXULONGLONG - (ULONG64)PAGE_SIZE)) {
        *nextAddressOut = MAXULONGLONG;
    }
    else {
        *nextAddressOut = pageAddress + (ULONG64)PAGE_SIZE;
    }
    if (state->bytesScanned >= state->maxBytes ||
        (ULONG64)PAGE_SIZE > (state->maxBytes - state->bytesScanned)) {
        state->budgetExhausted = TRUE;
        state->truncated = TRUE;
        state->bytesScanned = state->maxBytes;
        return STATUS_SUCCESS;
    }
    state->bytesScanned += (ULONG64)PAGE_SIZE;

    status = kswordArkKernelExecQueryPage(pageAddress, &pageInfo);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (pageInfo.pageSize != 0UL) {
        pageSize = pageInfo.pageSize;
        pageBase = kswordArkKernelExecAlignDown(pageAddress, (ULONG64)pageSize);
        if (pageBase <= pageAddress &&
            (ULONG64)pageSize <= (MAXULONGLONG - pageBase)) {
            *nextAddressOut = pageBase + (ULONG64)pageSize;
        }
        if (pageSize > PAGE_SIZE) {
            ULONG64 extraBytes = (ULONG64)pageSize - (ULONG64)PAGE_SIZE;
            if (extraBytes > (state->maxBytes - state->bytesScanned)) {
                state->budgetExhausted = TRUE;
                state->truncated = TRUE;
                state->bytesScanned = state->maxBytes;
                return STATUS_SUCCESS;
            }
            state->bytesScanned += extraBytes;
        }
    }

    if (pageInfo.queryStatus != KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK) {
        if (pageInfo.queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_NOT_PRESENT) {
            return STATUS_SUCCESS;
        }
        return kswordArkKernelExecPageQueryFailureStatus(&pageInfo);
    }
    if (pageInfo.resolved == 0UL ||
        (pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT) == 0UL) {
        return STATUS_UNSUCCESSFUL;
    }
    // Section classification must be completed before NX check: Once a code section page is changed to
    // RW, the page table carries NX; checking only executable pages would miss this state entirely.
    RtlZeroMemory(&sectionOwner, sizeof(sectionOwner));
    kswordArkKernelExecClassifyPageBySections(
        sectionHeaders,
        sectionCount,
        (ULONG64)(ULONG_PTR)moduleEntry->imageBase,
        moduleEntry->imageSize,
        pageBase,
        pageSize,
        &sectionOwner);

    pageIsExecutable =
        ((pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) == 0UL) ? TRUE : FALSE;
    pageIsWritable =
        ((pageInfo.effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) ? TRUE : FALSE;

    // The normal state of a code section page is read-only executable; non-executable or writable states are anomalies.
    if (sectionOwner.found && sectionOwner.isTextLike) {
        if (!pageIsExecutable) {
            anomalyRisk |= KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_NOT_EXECUTABLE;
        }
        if (pageIsWritable) {
            anomalyRisk |= KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_WRITABLE;
        }
    }

    // Non-executable pages are processed only if flagged as a code section anomaly and the caller explicitly requests it.
    if (!pageIsExecutable) {
        if (anomalyRisk == 0UL ||
            (request->flags & KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_SECTION_ANOMALY) == 0UL) {
            return STATUS_SUCCESS;
        }
    }

    kswordArkKernelExecFillCandidate(
        pageBase,
        &pageInfo,
        moduleEntry,
        modulePath,
        modulePathBytes,
        &sectionOwner,
        request->hashBytes,
        &candidate);

    // FillCandidate assumes the input is an executable page, so it directly flags "writable" as W+X. When the page already has NX,
    // this conclusion is invalid; remove it first and merge the code section exception bit to avoid contradictory conclusions.
    if (!pageIsExecutable) {
        candidate.riskFlags &= ~KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE;
        if (candidate.ownerKind == KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_WRITABLE_EXECUTABLE) {
            candidate.ownerKind = KSWORD_ARK_KERNEL_EXEC_OWNER_MODULE_TEXT;
        }
    }

    // The anomaly bit is merged after FillCandidate to avoid affecting the original ownerKind classification logic.
    candidate.riskFlags |= anomalyRisk;

    // Once a code section anomaly is detected, return immediately without being affected by include classification filtering.
    if (anomalyRisk == 0UL &&
        !kswordArkKernelExecShouldReturnCandidate(
            request->flags,
            candidate.ownerKind,
            candidate.riskFlags)) {
        return STATUS_SUCCESS;
    }

    kswordArkKernelExecAddEntry(state, &candidate);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkKernelExecScanModulePages(
    _Inout_ KswKernelExecScanState* state,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request,
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_reads_(sectionCount) const IMAGE_SECTION_HEADER* sectionHeaders,
    _In_ ULONG sectionCount,
    _In_reads_bytes_(modulePathBytes) const UCHAR* modulePath,
    _In_ ULONG modulePathBytes
    )
/*++

Routine Description:

    Scan pages within a module image range. Note: This is v1's conservative boundary; do not scan the entire
    kernel address space, only iterate through imageBase..imageEnd of modules loaded in SystemModuleInformation.
    section headers are used only for text/non-text/writable classification.

Arguments:

    State - Scan state.
    Request - Snapshot request.
    ModuleEntry - Currently loaded module.
    SectionHeaders: locally copied array of section headers.
    SectionCount: number of section headers.
    modulePath - module path.
    ModulePathBytes - Maximum number of bytes for the module path.

Return Value:

    STATUS_SUCCESS or page table query exception status.

--*/
{
    ULONG64 moduleBase = 0ULL;
    ULONG64 moduleEnd = 0ULL;
    ULONG64 scanAddress = 0ULL;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (state == NULL || request == NULL || moduleEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkKernelExecSafeModuleRange(moduleEntry, &moduleBase, &moduleEnd)) {
        return STATUS_SUCCESS;
    }

    scanAddress = kswordArkKernelExecAlignDown(moduleBase, (ULONG64)PAGE_SIZE);
    if (scanAddress < moduleBase) {
        scanAddress = moduleBase;
    }
    if (request->startAddress != 0ULL && scanAddress < request->startAddress) {
        scanAddress = kswordArkKernelExecAlignDown(request->startAddress, (ULONG64)PAGE_SIZE);
        if (scanAddress < moduleBase) {
            scanAddress = moduleBase;
        }
    }

    while (scanAddress < moduleEnd) {
        ULONG64 nextAddress = 0ULL;
        ULONG64 probeEnd = 0ULL;
        NTSTATUS status = STATUS_SUCCESS;

        if (request->endAddress != 0ULL && scanAddress >= request->endAddress) {
            break;
        }
        if (scanAddress > (MAXULONGLONG - (ULONG64)PAGE_SIZE)) {
            probeEnd = MAXULONGLONG;
        }
        else {
            /*
             * Note: The filter check uses a 4KB probe window as the minimum unit. If the request's startAddress falls in
             * the middle of a page, scanAddress..scanAddress+1 will not intersect, causing the page to be incorrectly
             * skipped; the actual large page boundaries will be advanced via NextAddressOut after the page table query.
             */
            probeEnd = scanAddress + (ULONG64)PAGE_SIZE;
        }
        if (!kswordArkKernelExecRangeIntersectsRequest(scanAddress, probeEnd, request)) {
            break;
        }

        status = kswordArkKernelExecScanOnePage(
            state,
            request,
            scanAddress,
            moduleEntry,
            sectionHeaders,
            sectionCount,
            modulePath,
            modulePathBytes,
            &nextAddress);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
        if (nextAddress <= scanAddress) {
            if (scanAddress > (MAXULONGLONG - (ULONG64)PAGE_SIZE)) {
                break;
            }
            nextAddress = scanAddress + (ULONG64)PAGE_SIZE;
        }
        scanAddress = nextAddress;
    }

    return firstFailure;
}

static NTSTATUS
kswordArkKernelExecScanModule(
    _Inout_ KswKernelExecScanState* state,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request,
    _In_ const KswHookSystemModuleEntry* moduleEntry
    )
/*++

Routine Description:

    Scan the image pages of a loaded kernel module. Note: PE headers and section headers are copied to local storage
    via the safe read helper hook_scan_support before parsing. This function does not rely on the PE section execute
    bit as the final authority; the final executable determination comes from the read-only page table analysis.
    Present/NX。

Arguments:

    State - Scan state.
    Request - Snapshot request.
    ModuleEntry - SystemModuleInformation module entry.

Return Value:

    STATUS_SUCCESS indicates module processing is complete; on parse failure, return the corresponding status for partial marking.

--*/
{
    IMAGE_SECTION_HEADER sectionHeaders[KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS];
    IMAGE_NT_HEADERS ntHeaders;
    const UCHAR* modulePathText = NULL;
    ULONG modulePathBytes = 0UL;
    ULONG sectionTableRva = 0UL;
    ULONG sectionCount = 0UL;
    ULONG sectionIndex = 0UL;
    ULONG64 moduleBase = 0ULL;
    ULONG64 moduleEnd = 0ULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    RtlZeroMemory(sectionHeaders, sizeof(sectionHeaders));
    if (state == NULL || request == NULL || moduleEntry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkKernelExecSafeModuleRange(moduleEntry, &moduleBase, &moduleEnd)) {
        return STATUS_SUCCESS;
    }
    if (!kswordArkKernelExecRangeIntersectsRequest(
        moduleBase,
        moduleEnd,
        request)) {
        return STATUS_SUCCESS;
    }

    modulePathText = moduleEntry->fullPathName;
    modulePathBytes = (ULONG)sizeof(moduleEntry->fullPathName);
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    if (!kswordArkHookReadImageNtHeaders(moduleEntry, &ntHeaders)) {
        firstFailure = STATUS_INVALID_IMAGE_FORMAT;
    }
    else if (ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS ||
        (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) >
            (MAXULONG - (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader)) {
        firstFailure = STATUS_INVALID_IMAGE_FORMAT;
    }
    else {
        /*
         * Note: Section table is located at PE header start RVA + OptionalHeader field offset
         * + SizeOfOptionalHeader. Do not derive RVA from the local ntHeaders copy address.
         */
        IMAGE_DOS_HEADER dosHeader;
        ULONG peHeaderRva = 0UL;

        RtlZeroMemory(&dosHeader, sizeof(dosHeader));
        if (!kswordArkHookReadImageBytes(moduleEntry, 0UL, &dosHeader, sizeof(dosHeader)) ||
            dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
            dosHeader.e_lfanew <= 0) {
            firstFailure = STATUS_INVALID_IMAGE_FORMAT;
        }
        else {
            peHeaderRva = (ULONG)dosHeader.e_lfanew;
            if (peHeaderRva > (MAXULONG - (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader)) ||
                peHeaderRva + (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) >
                    (MAXULONG - (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader)) {
                firstFailure = STATUS_INVALID_IMAGE_FORMAT;
            }
            else {
                sectionTableRva =
                    peHeaderRva +
                    (ULONG)FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                    (ULONG)ntHeaders.FileHeader.SizeOfOptionalHeader;
                sectionCount = (ULONG)ntHeaders.FileHeader.NumberOfSections;
            }
        }
    }

    for (sectionIndex = 0UL; sectionIndex < sectionCount; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG sectionRva = 0UL;

        if (!kswordArkHookAddRvaOffset(
            sectionTableRva,
            sectionIndex,
            (ULONG)sizeof(IMAGE_SECTION_HEADER),
            &sectionRva)) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = STATUS_INTEGER_OVERFLOW;
            }
            break;
        }
        RtlZeroMemory(&sectionHeader, sizeof(sectionHeader));
        if (!kswordArkHookReadImageBytes(
            moduleEntry,
            sectionRva,
            &sectionHeader,
            sizeof(sectionHeader))) {
            if (NT_SUCCESS(firstFailure)) {
                firstFailure = STATUS_ACCESS_VIOLATION;
            }
            continue;
        }

        RtlCopyMemory(&sectionHeaders[sectionIndex], &sectionHeader, sizeof(sectionHeaders[sectionIndex]));
    }

    status = kswordArkKernelExecScanModulePages(
        state,
        request,
        moduleEntry,
        sectionHeaders,
        sectionCount,
        modulePathText,
        modulePathBytes);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) {
        firstFailure = status;
    }

    return firstFailure;
}

static BOOLEAN
kswordArkKernelExecValidateRequest(
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request
    )
/*++

Routine Description:

    Validate scan request. Unknown flags, reverse address ranges, and obviously meaningless maxEntries will
    be rejected by the handler/backend; maxEntries of 0 indicates limiting only by output buffer capacity.

Arguments:

    Request - Request structure.

Return Value:

    TRUE indicates the request is acceptable; FALSE indicates STATUS_INVALID_PARAMETER should be returned.

--*/
{
    if (request == NULL) {
        return FALSE;
    }
    if ((request->flags & ~KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL) != 0UL) {
        return FALSE;
    }
    if (request->reserved0 != 0UL) {
        return FALSE;
    }
    if (request->startAddress != 0ULL &&
        request->endAddress != 0ULL &&
        request->endAddress <= request->startAddress) {
        return FALSE;
    }
    if (request->maxBytes > KSWORD_ARK_KERNEL_EXEC_SCAN_HARD_MAX_BYTES) {
        return FALSE;
    }
    if (request->hashBytes > KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_HARD_MAX) {
        return FALSE;
    }
    return TRUE;
}

NTSTATUS
kswordArkDriverScanKernelExecutableMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Conservatively scan executable pages within kernel module images. Note: v1 only iterates over loaded kernel
    module image ranges returned by SystemModuleInformation, reusing page table read-only queries to determine
    Present/NX/Writable status; PE sections are used solely for text/non-text/writable classification. It does
    not scan the entire kernel address space, does not write PTEs, and does not modify CR0.

Arguments:

    OutputBuffer - Response buffer, with entries immediately following the header.
    OutputBufferLength - Total length of the response buffer.
    Request - Scan request, containing flags/maxEntries/start/end.
    BytesWrittenOut - Returns the actual number of response bytes.

Return Value:

    STATUS_SUCCESS indicates that the response packet is valid; integrity is indicated by response->status/lastStatus.

--*/
{
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE* response = NULL;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST effectiveRequest;
    KswKernelExecScanState state;
    ULONG moduleInfoBytes = 0UL;
    ULONG moduleIndex = 0UL;
    ULONG entryCapacity = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS firstPartialStatus = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (!kswordArkKernelExecValidateRequest(request)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&effectiveRequest, sizeof(effectiveRequest));
    RtlCopyMemory(&effectiveRequest, request, sizeof(effectiveRequest));
    if (effectiveRequest.flags == 0UL) {
        effectiveRequest.flags = KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL;
    }
    if (effectiveRequest.maxBytes == 0ULL) {
        effectiveRequest.maxBytes = KSWORD_ARK_KERNEL_EXEC_SCAN_DEFAULT_MAX_BYTES;
    }
    if (effectiveRequest.hashBytes == 0UL) {
        effectiveRequest.hashBytes = KSWORD_ARK_KERNEL_EXEC_FIRST_BYTES_DEFAULT;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_UNAVAILABLE;
    response->sourceFlags = effectiveRequest.flags;
    response->entrySize = sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY);
    response->maxEntries = effectiveRequest.maxEntries;
    response->maxBytes = effectiveRequest.maxBytes;
    response->lastStatus = STATUS_SUCCESS;

    entryCapacity = (ULONG)((outputBufferLength - KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY));
    if (effectiveRequest.maxEntries != 0UL && entryCapacity > effectiveRequest.maxEntries) {
        entryCapacity = effectiveRequest.maxEntries;
    }
    if (response->maxEntries == 0UL) {
        response->maxEntries = entryCapacity;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_IRQL_REJECTED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        *bytesWrittenOut = KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    // Note: moduleInfoBytes satisfies only the snapshot helper's output contract; the scanning logic uses the entry count.
    status = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = status;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_QUERY_FAILED;
        *bytesWrittenOut = KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    response->moduleCount = moduleInfo->numberOfModules;

    RtlZeroMemory(&state, sizeof(state));
    state.response = response;
    state.entryCapacity = entryCapacity;
    state.maxBytes = effectiveRequest.maxBytes;

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        NTSTATUS moduleStatus = STATUS_SUCCESS;

        moduleStatus = kswordArkKernelExecScanModule(
            &state,
            &effectiveRequest,
            &moduleInfo->modules[moduleIndex]);
        if (!NT_SUCCESS(moduleStatus) && NT_SUCCESS(firstPartialStatus)) {
            firstPartialStatus = moduleStatus;
        }
        if (state.budgetExhausted) {
            break;
        }
    }

    response->bytesScanned = state.bytesScanned;
    if (state.truncated) {
        response->responseFlags |= KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_FLAG_TRUNCATED;
    }
    if (state.budgetExhausted) {
        response->responseFlags |= KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_FLAG_BUDGET_EXHAUSTED;
    }

    if (state.truncated || state.budgetExhausted || !NT_SUCCESS(firstPartialStatus)) {
        response->status = KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_PARTIAL_CONSERVATIVE;
        response->lastStatus = (state.truncated || state.budgetExhausted) ?
            STATUS_BUFFER_TOO_SMALL :
            firstPartialStatus;
    }
    else {
        response->status = KSWORD_ARK_KERNEL_EXEC_SCAN_STATUS_CONSERVATIVE;
        response->lastStatus = STATUS_SUCCESS;
    }

    *bytesWrittenOut = KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY));

    ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    return STATUS_SUCCESS;
}

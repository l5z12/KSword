#pragma once

#include "ark/ark_driver.h"
#include "../kernel/hook_scan_support.h"

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONG64)~0ULL)
#endif

// The response header does not include trailing entries[1], used for METHOD_BUFFERED output length validation.
#define KSWORD_ARK_KERNEL_EXEC_SCAN_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY))

// Note: Section headers are used only for classification, not to determine if a page is executable. A fixed upper bound prevents stack buffer
// overflow from anomalous PE headers; when exceeded, continue with a conservative scan without section headers within the module range.
#define KSWORD_ARK_KERNEL_EXEC_MAX_SECTION_HEADERS 96UL

typedef struct KswKernelExecScanState
{
    // Response: Output response header; the function writes result rows only within the entries capacity.
    KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE* response;
    // EntryCapacity: The number of entries that OutputBufferLength can hold, already truncated by maxEntries.
    ULONG entryCapacity;
    // Truncated: TRUE indicates totalCount > returnedCount; response status should be partial.
    BOOLEAN truncated;
    // HaveLastAggregate/LastAggregate: Store the previous aggregate row to facilitate consecutive page merging.
    BOOLEAN haveLastAggregate;
    KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY lastAggregate;
    // BytesScanned: Cumulative page scan budget; returns partial only when MaxBytes is reached, without further probing.
    ULONG64 bytesScanned;
    // MaxBytes: Maximum number of bytes that can be scanned for this request; 0 is normalized to the default value in the backend.
    ULONG64 maxBytes;
    // BudgetExhausted: TRUE indicates the scan budget is exhausted; the response must be marked as partial.
    BOOLEAN budgetExhausted;
} KswKernelExecScanState;

typedef struct KswKernelExecSectionOwner
{
    // Found: TRUE indicates at least one valid PE section was hit in the current page.
    BOOLEAN found;
    // IsTextLike: TRUE indicates that all overlapping sections are text/code-like.
    BOOLEAN isTextLike;
    // IsWritable: TRUE indicates that any overlapping section is declared writable.
    BOOLEAN isWritable;
    // SectionRva/SectionSize: RVA and size of the first overlapping section, used solely for attribution display.
    ULONG sectionRva;
    ULONG sectionSize;
    // SectionName: The 8-byte PE section name of the first overlapping section.
    UCHAR sectionName[KSWORD_ARK_KERNEL_EXEC_SECTION_NAME_BYTES];
} KswKernelExecSectionOwner;

ULONG64
kswordArkKernelExecAlignDown(
    _In_ ULONG64 value,
    _In_ ULONG64 alignment
    );

BOOLEAN
kswordArkKernelExecRangeIntersectsRequest(
    _In_ ULONG64 rangeStart,
    _In_ ULONG64 rangeEnd,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request
    );

BOOLEAN
kswordArkKernelExecSafeModuleRange(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Out_ ULONG64* moduleBaseOut,
    _Out_ ULONG64* moduleEndOut
    );

VOID
kswordArkKernelExecAddEntry(
    _Inout_ KswKernelExecScanState* state,
    _In_ const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY* candidate
    );

NTSTATUS
kswordArkKernelExecQueryPage(
    _In_ ULONG64 virtualAddress,
    _Out_ KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* infoOut
    );

NTSTATUS
kswordArkKernelExecPageQueryFailureStatus(
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo
    );

BOOLEAN
kswordArkKernelExecShouldReturnCandidate(
    _In_ ULONG requestFlags,
    _In_ ULONG ownerKind,
    _In_ ULONG riskFlags
    );

ULONG
kswordArkKernelExecProtectionFromPage(
    _In_ const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO* pageInfo
    );

BOOLEAN
kswordArkKernelExecReadFirstBytesHash(
    _In_ ULONG64 virtualAddress,
    _In_ ULONG bytesToHash,
    _Out_ ULONG64* hashOut,
    _Out_ ULONG* bytesHashedOut
    );

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
    );

VOID
kswordArkKernelExecClassifyPageBySections(
    _In_reads_(sectionCount) const IMAGE_SECTION_HEADER* sectionHeaders,
    _In_ ULONG sectionCount,
    _In_ ULONG64 moduleBase,
    _In_ ULONG moduleSize,
    _In_ ULONG64 pageAddress,
    _In_ ULONG pageSize,
    _Out_ KswKernelExecSectionOwner* sectionOwnerOut
    );

#pragma once

#include "KswordArkSafetyIoctl.h"

// ============================================================
// KswordArkInjectionScanIoctl.h
// Purpose:
// - Define the R0 scan backend protocol for injection trace detection (issue #196);
// - Two read-only capabilities: process VAD enumeration and scanning of process user-mode executable PTE ranges.
// - Both are **independent views**, used to cross-verify with R3's
//   VirtualQueryEx/QueryWorkingSetEx; they are not the same data retrieved via different paths.
//
// Why are these two required instead of reusing existing IOCTLs?
//   * IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY uses ZwQueryVirtualMemory, which is the **same
//     source** as R3's VirtualQueryEx; cross-checking it is equivalent to comparing it with itself.
//     VAD enumeration directly reads the balanced tree of EPROCESS.VadRoot, which is the second source.
//   IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY parses only one VA at a time. Iterating through every
//     VA to find pages marked 'executable' by the page table (as PteMalfind does) is infeasible.
//
// Hard boundary (defined in the protocol to prevent implementers or callers from forgetting later):
//   * Read-only. This file provides no entry points to write VADs, write PTEs, or modify protections.
//   * Internal structures must be validated against the target build: VadRoot offset comes from DynData; unverified versions
//     must return DYNDATA_MISSING and set profileVerified to 0. **Do not** use offsets from similar versions to continue reading.
//   * The target address space changes during scanning. The protocol does not provide a 'consistent snapshot', only cursor-based
//     rescan and inconsistency counts; callers must treat this as a cross-timepoint observation, not an atomic snapshot.
//   * Kernel collection relies on kernel trust. An adversary with kernel capabilities can modify the metadata read here.
//     This protocol does not guarantee 'undetectable if a driver is present'.
// ============================================================

#define KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_ENUMERATE_PROCESS_VAD 0x912UL
#define KSWORD_ARK_IOCTL_FUNCTION_SCAN_PROCESS_EXECUTABLE_PTE 0x913UL

// FILE_WRITE_ACCESS aligns with memory-related IOCTLs: these two
// expose internal kernel structures and cannot use FILE_ANY_ACCESS.
#define IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUMERATE_PROCESS_VAD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SCAN_PROCESS_EXECUTABLE_PTE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// ---------------------------------------------------------------------------
// Generic status
// ---------------------------------------------------------------------------
#define KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE           0UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_OK                    1UL
// PARTIAL: The request range was traversed, but some nodes/entries could not be read during the process.
#define KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL               2UL
// TRUNCATED: Hit entry or budget limit, **did not** complete the requested range. Must be separated from PARTIAL:
// The former indicates 'range exhausted but with gaps', while the latter means 'range not fully traversed'. Mixing them may mislead the caller into thinking the entire range was covered.
#define KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED             3UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_DYNDATA_MISSING       4UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED 5UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_EXITING       6UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED           7UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_BUFFER_TOO_SMALL      8UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_IRQL_REJECTED         9UL
#define KSWORD_ARK_INJECTION_SCAN_STATUS_INVALID_RANGE         10UL

// Response field availability.
#define KSWORD_ARK_INJECTION_FIELD_ENTRIES_PRESENT     0x00000001UL
#define KSWORD_ARK_INJECTION_FIELD_CURSOR_PRESENT      0x00000002UL
#define KSWORD_ARK_INJECTION_FIELD_ROOT_PRESENT        0x00000004UL
#define KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED    0x00000008UL
#define KSWORD_ARK_INJECTION_FIELD_INCONSISTENT_WALK   0x00000010UL
#define KSWORD_ARK_INJECTION_FIELD_CR3_PRESENT         0x00000020UL
// This traversal completes the entire tree (no range filtering, no cursor, no truncation),
// so visitedCount / parentMismatchNodes / vadHintVisited can be compared against vadCount.
// **If this bit is absent, those fields must not participate in any judgment** — visitedCount is naturally small during partial traversal.
#define KSWORD_ARK_INJECTION_FIELD_INTEGRITY_VALID     0x00000040UL
// The offset for EPROCESS.VadCount is available and has been read.
#define KSWORD_ARK_INJECTION_FIELD_VAD_COUNT_PRESENT   0x00000080UL
// EPROCESS.VadHint offset is available and has been read.
#define KSWORD_ARK_INJECTION_FIELD_VAD_HINT_PRESENT    0x00000100UL

// ---------------------------------------------------------------------------
// VAD enumeration
// ---------------------------------------------------------------------------
#define KSWORD_ARK_INJECTION_VAD_LIMIT_DEFAULT 2048UL
#define KSWORD_ARK_INJECTION_VAD_LIMIT_MAX     16384UL
// Maximum depth of the balanced tree. Real VAD tree depth is far smaller; setting a hard limit ensures the explicit stack
// for in-order traversal has a fixed size and prevents malformed/rewritten trees from causing traversal to go out of bounds.
#define KSWORD_ARK_INJECTION_VAD_MAX_DEPTH     64UL

// entryFlags
#define KSWORD_ARK_INJECTION_VAD_FLAG_PRIVATE_MEMORY 0x00000001UL
#define KSWORD_ARK_INJECTION_VAD_FLAG_HAS_SUBSECTION 0x00000002UL
#define KSWORD_ARK_INJECTION_VAD_FLAG_LONG_VAD       0x00000004UL
#define KSWORD_ARK_INJECTION_VAD_FLAG_NODE_UNREADABLE 0x00000008UL
#define KSWORD_ARK_INJECTION_VAD_FLAG_RANGE_MALFORMED 0x00000010UL
// protection / vadType / PRIVATE_MEMORY are decoded from LongFlags based on an **assumed** bitfield layout.
// DynData only validates the offset of EPROCESS.VadRoot, not the bit positions of MMVAD_FLAGS. Therefore, these three fields are for display purposes
// only and **must not** be used to perform 'contradiction' checks against R3 protection attributes. If the bit layout is guessed incorrectly, this
// results in a massive false contradiction. The original vadFlagsRaw is always returned alongside to facilitate post-event verification.
#define KSWORD_ARK_INJECTION_VAD_FLAG_FLAGS_LAYOUT_ASSUMED 0x00000020UL

// MMVAD_FLAGS.VadType (unpublished in winnt, stable across
// versions). Use UNKNOWN if parsing fails; do not guess.
#define KSWORD_ARK_INJECTION_VAD_TYPE_UNKNOWN 0xFFFFFFFFUL

typedef struct _KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long maxEntries;
    unsigned long reserved0;
    unsigned long long startAddress;   // 0 indicates starting from the user-space origin.
    unsigned long long endAddress;     // 0 means the end of user space.
    // Resume cursor: nextCursorVpn from the previous response. 0 starts from the beginning.
    unsigned long long cursorVpn;
    unsigned long long reserved1;
} KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST;

// A single VAD record. **Deliberately excludes the filename**: retrieving the filename from a VAD requires
// Three untrusted dereferences (Subsection -> ControlArea -> FilePointer) pose a risk far exceeding the benefit. The path
// dimension is already provided by R3's GetMappedFileNameW; cross-verification requires only the range and protection attributes.
// subsection being non-0 only indicates "this is a mapping supported by a section", which is sufficient for classification.
// **It is a Subsection pointer, not a ControlArea.** The two differ by one level of indirection
// (_SUBSECTION.ControlArea is at offset 0); the measured address difference is 0x80 = sizeof(_CONTROL_AREA).
// The actual ControlArea is provided by IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES. Previously this was named
// controlArea; anyone using it to cross-check against ControlArea addresses elsewhere would be misled.
typedef struct _KSWORD_ARK_PROCESS_VAD_ENTRY
{
    unsigned long long startVa;
    unsigned long long endVaExclusive;
    unsigned long long vadNodeAddress;
    unsigned long long subsection;       // 0 = Private memory or unreadable
    unsigned long long firstPrototypePte; // Diagnosis only
    unsigned long vadFlagsRaw;           // Original value of MmvadShort.LongFlags
    unsigned long protection;            // MMVAD_FLAGS.Protection (MM_ encoding)
    unsigned long vadType;               // MMVAD_FLAGS.VadType
    unsigned long entryFlags;
} KSWORD_ARK_PROCESS_VAD_ENTRY;

typedef struct _KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long status;
    long lastStatus;
    unsigned long entrySize;
    unsigned long returnedCount;
    // The actual number of nodes visited in this traversal (including those filtered out by range). It is separated
    // from returnedCount; otherwise, "filtered out many" and "traversed very few" would look identical in accounting.
    unsigned long visitedCount;
    unsigned long unreadableNodeCount;
    // Whether the EPROCESS.VadRoot offset in DynData has been verified for the current build.
    // If 0, the result cannot be used for "missing field inference"; the caller must degrade.
    unsigned long profileVerified;
    unsigned long vadRootOffset;
    unsigned long long vadRootAddress;
    unsigned long long nextCursorVpn;    // 0 = Completed

    // --- Tree structure integrity (broken link check) ---------------------------------------------
    // These items only make sense when **fully traversing the entire tree**: with range filtering, with
    // cursors, or when hitting the entry limit, visitedCount should not equal VadCount. Therefore, they
    // are gated by KSWORD_ARK_INJECTION_FIELD_INTEGRITY_VALID; the caller must check that bit first.
    unsigned long long vadHintAddress;   // Value of EPROCESS.VadHint; 0 means the offset is unavailable.
    // EPROCESS.VadCount is maintained by the kernel. Unlinking usually does not decrement
    // it, so visitedCount < vadCount directly indicates nodes missing from the tree.
    unsigned long vadCount;
    // Count of nodes with inconsistent parent pointers: the node pointed to by ParentValue & ~3 has
    // neither its left nor right child pointing back to this node. A clean unlink (redirecting the
    // parent's child pointer to this node's subtree) leaves no such trace, but a brute-force rewrite does.
    unsigned long parentMismatchNodes;
    // The node pointed to by EPROCESS.VadHint was visited during this traversal. VadHint is the kernel's "most
    // recently used VAD" cache; if it points to a node not found in the tree, the tree has been modified.
    unsigned long vadHintVisited;
    unsigned long integrityReserved;

    KSWORD_ARK_PROCESS_VAD_ENTRY entries[1];
} KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE;

#define KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY))

// ---------------------------------------------------------------------------
// User-mode executable PTE scan.
// ---------------------------------------------------------------------------
// Default entry limit based on empirical measurement, not arbitrary: On 2026-09-12 at Win11 22621.4317, explorer.exe's
// entire user address space produced 7266 segments (443 table reads, 22779 executable 4 KiB pages), and lsass produced 1044
// segments. 4096 was the previous default, causing explorer to truncate mid-process. 16384 provides a 2x safety margin.
#define KSWORD_ARK_INJECTION_PTE_LIMIT_DEFAULT 16384UL
#define KSWORD_ARK_INJECTION_PTE_LIMIT_MAX     32768UL
// Read table budget: maximum number of page table pages to read per request. Each page in a 4-level page table is 4 KiB.
// The default value is set to cover all mapped regions of a typical process; exceeding this triggers TRUNCATED + cursor rescan.
#define KSWORD_ARK_INJECTION_PTE_TABLE_READS_DEFAULT 8192UL
#define KSWORD_ARK_INJECTION_PTE_TABLE_READS_MAX     262144UL

// flags
// By default, only report leaf entries marked 'executable' in the page table. When set, also report
// non-executable mapped leaves — extremely high volume, for diagnostics only; do not enable in regular scans.
#define KSWORD_ARK_INJECTION_PTE_FLAG_INCLUDE_NON_EXECUTABLE 0x00000001UL
// By default, skip supervisor pages (which should not exist in user address space). If set, report them together.
#define KSWORD_ARK_INJECTION_PTE_FLAG_INCLUDE_SUPERVISOR 0x00000002UL

// entryFlags
#define KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE 0x00000001UL
#define KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_WRITABLE   0x00000002UL
#define KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_USER       0x00000004UL
#define KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_LARGE_PAGE 0x00000008UL

typedef struct _KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long maxEntries;
    unsigned long maxTableReads;
    unsigned long long startAddress;
    unsigned long long endAddress;      // 0 indicates ending at the user-space destination.
    unsigned long long cursorAddress;   // Continuation cursor; 0 means start at startAddress.
    unsigned long long reserved0;
} KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST;

// A contiguous sequence of leaf pages with identical attributes. Returned by "segment" rather than "page": a 2 MiB executable private
// allocation consists of 512 4 KiB leaves; returning them page-by-page would overflow the buffer without providing additional information.
typedef struct _KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY
{
    unsigned long long startVa;
    unsigned long long byteLength;
    unsigned long long firstPhysicalAddress;
    unsigned long long firstEntryValue;   // The original value of the first leaf item in this segment.
    unsigned long pageSize;
    unsigned long pageCount;
    unsigned long effectiveFlags;         // KSWORD_ARK_PAGE_TABLE_FLAG_* (after hierarchical merging)
    unsigned long entryFlags;             // KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_*
} KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY;

typedef struct _KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long status;
    long lastStatus;
    unsigned long entrySize;
    unsigned long returnedCount;
    unsigned long tableReads;          // Actual number of table pages read.
    unsigned long failedTableReads;    // Number of pages failed to read; >0 indicates PARTIAL.
    unsigned long executablePageCount; // Total matching executable leaf pages, counted in 4 KiB units.
    unsigned long reserved0;
    unsigned long long scannedBegin;   // Actual range scanned
    unsigned long long scannedEnd;
    unsigned long long nextCursorAddress;  // 0 = Completed
    unsigned long long cr3PhysicalAddress;
    KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY entries[1];
} KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE;

#define KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE) - \
     sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY))

// ---------------------------------------------------------------------------
// Image section object reference pages (issue #196 §5.3).
// ---------------------------------------------------------------------------
// Obtain the **second source** for what this image 'should be': not the file on disk, but the section object
// held by the memory manager itself. The chain is VAD → Subsection → ControlArea → Segment → PrototypePte[].
//
// It acquires two additional capabilities compared to 'and disk files'.
//   * A reference still exists when the disk file is locked, unreadable, or has been replaced.
//   * Even if an attacker modifies the disk file to match memory, detection still works: the section object
//     retains the content from when the mapping was created, which is unaffected by disk file changes.
//
// Deliberately do not decode software PTEs. Prototype PTEs come in multiple forms: valid (hardware format),
// transition, in pagefile, or demand-zero. Only the valid form has an **architecture-defined** bit layout
// (bit 0 = Present, bits 12..51 = PFN); the encoding for transition/pagefile is Windows-internal and
// version-dependent. This is precisely the boundary drawn by kLimitKernelVadFlagsUnverified.
// Therefore, this interface retrieves the PFN only for valid prototype PTEs and reads the physical page; all
// others are reported as 'unable to retrieve reference' and recorded by the upper layer as coverage gaps. **Never
// bring the page into memory** — doing so would alter the target state and cause a deadlock at this IRQL.
#define KSWORD_ARK_IOCTL_FUNCTION_READ_IMAGE_SECTION_PAGES 0x914UL

#define IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_READ_IMAGE_SECTION_PAGES, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// Maximum number of pages to parse per request. With byte granularity, each page is 4 KiB; 64 pages =
// 256 KiB, which exceeds the comfort zone of METHOD_BUFFERED, so only metadata is provided by default.
#define KSWORD_ARK_INJECTION_SECTION_PAGES_DEFAULT 512UL
#define KSWORD_ARK_INJECTION_SECTION_PAGES_MAX     4096UL
// Upper limit when page bytes are included, treated as a separate case: METHOD_BUFFERED buffers must be allocated in a single allocation.
#define KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX 64UL

// flags
// After setting, each entry is followed by 4096 bytes of clean page content (valid only for valid prototype PTEs).
// If not set, only metadata is returned; entries contain no bytes.
#define KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES 0x00000001UL

// Entry flag: The prototype PTE for this page is in
// valid hardware format, so physicalAddress is usable.
#define KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_VALID        0x00000001UL
// The prototype PTE was read but is not in a valid state (transition / page file / zero page).
// **Not an error**: it means 'this page is not currently in memory; this interface is designed not to bring it in'.
#define KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_NOT_RESIDENT 0x00000002UL
// Prototype PTE itself was not read (e.g., paged pool swapped out).
#define KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_PTE_UNREADABLE 0x00000004UL
// Bytes for this page are returned with the entry.
#define KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_BYTES_PRESENT 0x00000008UL

typedef struct _KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long flags;
    unsigned long long rangeStart;   // VA in the target process, page-aligned.
    unsigned long long rangeEnd;     // Excludes
    unsigned long maxPages;
    unsigned long reserved0;
    unsigned long long cursorVa;     // 0 = Start from beginning.
} KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST;

typedef struct _KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY
{
    unsigned long long va;                 // Virtual address in the target process.
    unsigned long long prototypePteAddress;// The prototype PTE's own kernel address.
    unsigned long long prototypePteValue;  // Original value, undecoded
    unsigned long long physicalAddress;    // Valid only when VALID.
    unsigned long entryFlags;
    unsigned long reserved0;
} KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY;

typedef struct _KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long status;
    long lastStatus;
    unsigned long entrySize;
    unsigned long returnedCount;
    unsigned long validPageCount;       // Retrieve the reference page count.
    unsigned long notResidentPageCount; // Prototype PTE is not in valid state.
    unsigned long unreadablePteCount;   // Prototype PTE itself is unreadable
    unsigned long bytesPerPage;         // 4096 if bytes are specified; otherwise 0.
    unsigned long long controlArea;     // ControlArea resolved in this pass.
    unsigned long long segment;         // Segment resolved in this pass.
    unsigned long long prototypePteArray; // Segment.PrototypePte
    unsigned long long nextCursorVa;    // 0 means the scan is complete.
    // Offset of the byte area from the start of the response; nonzero when INCLUDE_BYTES is set.
    //
    // * **This field must be provided directly by the response; the caller must not calculate it.** The byte area follows the
    // **capacity** of the entries, where capacity is constrained by both the buffer size and the maxPages value in the request.
    // The caller only knows the former; recalculating the offset will point to the wrong page.
    unsigned long long byteAreaOffset;
    KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY entries[1];
    // Byte region: validPageCount × bytesPerPage, ordered consistently
    // with the sequence of BYTES_PRESENT bits set in the entries.
} KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE;

#define KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE) - \
     sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY))

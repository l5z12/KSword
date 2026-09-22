/*++

Module Name:

    injection_pte_scan.c

Abstract:

    Read-only page-table range scan that reports user-space executable leaves.

    This is the **third view** for injection trace detection (beyond R3 VirtualQuery / R0 VAD). It answers only one question:
    **which user pages the processor will actually execute as code**. VAD and VirtualQueryEx provide "protection attributes
    recorded by the memory manager," whereas the actual ability to execute is determined by the NX bit in the page tables.
    When the two differ, the hardware side is the source of truth.
    PteMalfind, proposed at DFRWS 2019, targets this discrepancy.

    Intentionally omitted actions:
      * Do not draw conclusions without checking the Dirty bit. Dirty means 'written since last cleared', not a historical log;
        treating it as 'this page was modified' is wrong. The original item value is returned as-is; inspect it yourself if needed.
      * Do not modify any page table entries. This module has no write path.
      * Does not lock the address space. The target may change during scanning; the protocol uses a cursor
        for rescan + inconsistency count to express this, avoiding the pretense of an atomic snapshot.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL only.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_injection_scan.h"

#if defined(_M_AMD64) || defined(_M_X64)
#include <intrin.h>
#endif

/*
 * These routines are declared in ntifs.h, not ntddk.h; this driver does not include ntifs.h.
 * Note: ApcState uses a PVOID plus a fixed-size byte array, for the same reason as memory_pagetable.c:
 * Definition of KAPC_STATE is also in ntifs.h.
 */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

// Shared x64 paging constants with memory_pagetable.c. Redefining them risks silent drift
// between the two, so we only reference the existing KSWORD_ARK_PAGE_TABLE_* flags from the
// protocol header. The physical address mask is declared once here per Intel SDM definition.
#define KSW_INJ_PTE_PRESENT_BIT   0x0000000000000001ULL
#define KSW_INJ_PTE_WRITE_BIT     0x0000000000000002ULL
#define KSW_INJ_PTE_USER_BIT      0x0000000000000004ULL
#define KSW_INJ_PTE_LARGE_BIT     0x0000000000000080ULL
#define KSW_INJ_PTE_NX_BIT        0x8000000000000000ULL
#define KSW_INJ_PTE_ADDR_4KB_MASK 0x000FFFFFFFFFF000ULL
#define KSW_INJ_PTE_ADDR_2MB_MASK 0x000FFFFFFFE00000ULL
#define KSW_INJ_PTE_ADDR_1GB_MASK 0x000FFFFFC0000000ULL

#define KSW_INJ_ENTRIES_PER_TABLE 512U
#define KSW_INJ_TABLE_BYTES       4096U
// CR4.LA57: Under 5-level paging, this 4-level traversal is incorrect. Must reject rather than
// forcibly follow the 4-level path—the walker in memory_pagetable.c follows the same rule.
#define KSW_INJ_CR4_LA57_BIT      (1ULL << 12)

EXTERN_C ULONG64 kswordArkInjectionUserAddressLimit(VOID);

typedef struct KswInjPteTable
{
    ULONG64 entries[KSW_INJ_ENTRIES_PER_TABLE];
} KswInjPteTable;

typedef struct KswInjPteScanState
{
    KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE* response;
    size_t entryCapacity;
    ULONG maxTableReads;
    ULONG64 rangeEnd;
    BOOLEAN includeNonExecutable;
    BOOLEAN includeSupervisor;
    BOOLEAN truncated;

    // Segments currently being accumulated. A PageCount of 0 indicates no accumulation is in progress.
    ULONG64 runStartVa;
    ULONG64 runNextVa;
    ULONG64 runFirstPhysical;
    ULONG64 runFirstValue;
    ULONG runPageSize;
    ULONG runPageCount;
    ULONG runEffectiveFlags;
    ULONG runEntryFlags;
} KswInjPteScanState;

static NTSTATUS
kswordArkInjectionReadPhysicalTable(
    _In_ ULONG64 physicalAddress,
    _Out_ KswInjPteTable* table
    )
/*++

Routine Description:

    Read an entire page table page at once. Note: Reading 8 bytes per entry requires 512 MmCopyMemory calls, whereas a single range
    scan would involve millions of calls; reading the whole page reduces this to one call. Page table pages are always 4 KiB aligned.

Return Value:

    STATUS_SUCCESS indicates a complete read of 4096 bytes.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (table == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(table, sizeof(*table));

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)physicalAddress;

    __try {
        status = MmCopyMemory(
            table,
            copyAddress,
            KSW_INJ_TABLE_BYTES,
            MM_COPY_MEMORY_PHYSICAL,
            &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0U;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (copied != KSW_INJ_TABLE_BYTES) {
        return STATUS_PARTIAL_COPY;
    }
    return STATUS_SUCCESS;
}

static ULONG
kswordArkInjectionMergeFlags(
    _In_ ULONG64 pml4e,
    _In_ ULONG64 pdpte,
    _In_ ULONG64 pde,
    _In_ ULONG64 leaf,
    _In_ BOOLEAN leafIsPte
    )
/*++

Routine Description:

    Merge entries at each level to obtain effective permissions. Note: In x64 paging, write and user permissions are ANDed
    across levels, while NX is ORed. Checking only leaf entries would incorrectly report a non-writable page range as writable.

--*/
{
    ULONG flags = 0UL;
    // Note: For large pages, the leaf is the PDE/PDPTE itself. The caller has already passed it to both
    // Pde and Leaf; performing the AND operation again yields no change, so no branching is needed here.
    ULONG64 writable = pml4e & pdpte & pde & leaf & KSW_INJ_PTE_WRITE_BIT;
    ULONG64 user = pml4e & pdpte & pde & leaf & KSW_INJ_PTE_USER_BIT;
    ULONG64 nx = (pml4e | pdpte | pde | leaf) & KSW_INJ_PTE_NX_BIT;

    flags |= KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT;
    if (writable != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE;
    }
    if (user != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_USER;
    }
    if (nx != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    }
    if ((leaf & KSW_INJ_PTE_LARGE_BIT) != 0ULL && !leafIsPte) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE;
    }
    if ((leaf & 0x20ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED;
    }
    if ((leaf & 0x40ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY;
    }
    return flags;
}

static VOID
kswordArkInjectionFlushRun(
    _Inout_ KswInjPteScanState* state
    )
/*++

Routine Description:

    Write the currently accumulated segment into the response. Note: On buffer full,
    set Truncated instead of discarding, allowing the caller to resume scanning.

--*/
{
    KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY* entry = NULL;

    if (state->runPageCount == 0UL) {
        return;
    }
    if ((size_t)state->response->returnedCount >= state->entryCapacity) {
        state->truncated = TRUE;
        state->response->nextCursorAddress = state->runStartVa;
        state->response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CURSOR_PRESENT;
        state->runPageCount = 0UL;
        return;
    }

    entry = &state->response->entries[state->response->returnedCount];
    entry->startVa = state->runStartVa;
    entry->byteLength = state->runNextVa - state->runStartVa;
    entry->firstPhysicalAddress = state->runFirstPhysical;
    entry->firstEntryValue = state->runFirstValue;
    entry->pageSize = state->runPageSize;
    entry->pageCount = state->runPageCount;
    entry->effectiveFlags = state->runEffectiveFlags;
    entry->entryFlags = state->runEntryFlags;
    ++state->response->returnedCount;
    state->response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ENTRIES_PRESENT;
    state->runPageCount = 0UL;
}

static VOID
kswordArkInjectionAppendLeaf(
    _Inout_ KswInjPteScanState* state,
    _In_ ULONG64 virtualAddress,
    _In_ ULONG64 physicalAddress,
    _In_ ULONG64 entryValue,
    _In_ ULONG pageSize,
    _In_ ULONG effectiveFlags
    )
{
    ULONG entryFlags = 0UL;
    const ULONG64 kPageBytes = (ULONG64)pageSize;

    if ((effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) == 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE;
    }
    if ((effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_WRITABLE;
    }
    if ((effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_USER;
    }
    if ((effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE) != 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_LARGE_PAGE;
    }

    if ((entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE) != 0UL) {
        state->response->executablePageCount +=
            (ULONG)(kPageBytes / KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB);
    }

    // Segment merge condition: contiguous addresses, identical page size, and exactly matching effective permissions.
    if (state->runPageCount != 0UL &&
        state->runNextVa == virtualAddress &&
        state->runPageSize == pageSize &&
        state->runEffectiveFlags == effectiveFlags) {
        state->runNextVa += kPageBytes;
        ++state->runPageCount;
        return;
    }

    kswordArkInjectionFlushRun(state);
    if (state->truncated) {
        return;
    }
    state->runStartVa = virtualAddress;
    state->runNextVa = virtualAddress + kPageBytes;
    state->runFirstPhysical = physicalAddress;
    state->runFirstValue = entryValue;
    state->runPageSize = pageSize;
    state->runPageCount = 1UL;
    state->runEffectiveFlags = effectiveFlags;
    state->runEntryFlags = entryFlags;
}

static BOOLEAN
kswordArkInjectionLeafWanted(
    _In_ const KswInjPteScanState* state,
    _In_ ULONG effectiveFlags
    )
{
    const BOOLEAN kExecutable = ((effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) == 0UL);
    const BOOLEAN kUser = ((effectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL);

    if (!kUser && !state->includeSupervisor) {
        return FALSE;
    }
    if (!kExecutable && !state->includeNonExecutable) {
        return FALSE;
    }
    return TRUE;
}

NTSTATUS
kswordArkDriverScanProcessExecutablePte(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Perform a range scan on the target process's page tables to report user-mode executable leaf pages.

Return Value:

    STATUS_SUCCESS indicates that the IOCTL has produced a readable response (failure details are written in response->status).

--*/
{
    KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE* response = NULL;
    KswInjPteScanState state;
    KswInjPteTable* pml4 = NULL;
    KswInjPteTable* pdpt = NULL;
    KswInjPteTable* pd = NULL;
    KswInjPteTable* pt = NULL;
    PEPROCESS processObject = NULL;
    DECLSPEC_ALIGN(16) UCHAR apcState[128];
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 cr3 = 0ULL;
    ULONG64 rangeStart = 0ULL;
    ULONG64 rangeEnd = 0ULL;
    ULONG64 scanFrom = 0ULL;
    ULONG maxEntries = 0UL;
    ULONG maxTableReads = 0UL;
    ULONG pml4Index = 0UL;

    if (bytesWrittenOut == NULL || outputBuffer == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY);
    response->processId = request->processId;
    response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_IRQL_REJECTED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    if (request->processId == 0UL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    rangeStart = request->startAddress & ~((ULONG64)PAGE_SIZE - 1ULL);
    rangeEnd = (request->endAddress == 0ULL)
        ? (kswordArkInjectionUserAddressLimit() + 1ULL)
        : request->endAddress;
    if (rangeEnd > kswordArkInjectionUserAddressLimit() + 1ULL) {
        rangeEnd = kswordArkInjectionUserAddressLimit() + 1ULL;
    }
    scanFrom = (request->cursorAddress != 0ULL) ? request->cursorAddress : rangeStart;
    scanFrom &= ~((ULONG64)PAGE_SIZE - 1ULL);
    if (scanFrom < rangeStart) {
        scanFrom = rangeStart;
    }
    if (rangeEnd <= scanFrom) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_INVALID_RANGE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    maxEntries = request->maxEntries;
    if (maxEntries == 0UL) {
        maxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_DEFAULT;
    }
    if (maxEntries > KSWORD_ARK_INJECTION_PTE_LIMIT_MAX) {
        maxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_MAX;
    }
    maxTableReads = request->maxTableReads;
    if (maxTableReads == 0UL) {
        maxTableReads = KSWORD_ARK_INJECTION_PTE_TABLE_READS_DEFAULT;
    }
    if (maxTableReads > KSWORD_ARK_INJECTION_PTE_TABLE_READS_MAX) {
        maxTableReads = KSWORD_ARK_INJECTION_PTE_TABLE_READS_MAX;
    }

    RtlZeroMemory(&state, sizeof(state));
    state.response = response;
    state.entryCapacity =
        (outputBufferLength - KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY);
    if (state.entryCapacity > (size_t)maxEntries) {
        state.entryCapacity = (size_t)maxEntries;
    }
    if (state.entryCapacity == 0U) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_BUFFER_TOO_SMALL;
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        return STATUS_SUCCESS;
    }
    state.maxTableReads = maxTableReads;
    state.rangeEnd = rangeEnd;
    state.includeNonExecutable =
        (request->flags & KSWORD_ARK_INJECTION_PTE_FLAG_INCLUDE_NON_EXECUTABLE) != 0UL;
    state.includeSupervisor =
        (request->flags & KSWORD_ARK_INJECTION_PTE_FLAG_INCLUDE_SUPERVISOR) != 0UL;

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    /*
     * Reserve one page per table (four tables total, 16 KiB). Placing this on the
     * stack would consume most of the kernel stack, so use non-paged pool instead.
     */
    pml4 = (KswInjPteTable*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(KswInjPteTable) * 4U, 'jnIK');
    if (pml4 == NULL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }
    pdpt = pml4 + 1;
    pd = pml4 + 2;
    pt = pml4 + 3;

    // With five-level paging, this four-level walk would resolve every address incorrectly. Reject it instead of forcing a fallback.
    if ((__readcr4() & KSW_INJ_CR4_LA57_BIT) != 0ULL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        ExFreePool(pml4);
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }

    /*
     * Attach to the target process only to read CR3. Windows does not expose a stable offset for
     * EPROCESS.DirectoryTableBase, so version-specific offsets are not hardcoded. Page tables are read by physical
     * address and do not depend on the current address space; therefore, detach immediately after reading CR3.
     */
    __try {
        RtlZeroMemory(apcState, sizeof(apcState));
        KeStackAttachProcess((PVOID)processObject, apcState);
        attached = TRUE;
        cr3 = __readcr3() & KSW_INJ_PTE_ADDR_4KB_MASK;
        KeUnstackDetachProcess(apcState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (attached) {
            KeUnstackDetachProcess(apcState);
            attached = FALSE;
        }
        cr3 = 0ULL;
    }

    if (cr3 == 0ULL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = STATUS_NOT_FOUND;
        ExFreePool(pml4);
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }
    response->cr3PhysicalAddress = cr3;
    response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CR3_PRESENT;
    response->scannedBegin = scanFrom;

    status = kswordArkInjectionReadPhysicalTable(cr3, pml4);
    ++response->tableReads;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = status;
        ExFreePool(pml4);
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }

    /*
     * Traverse top-down, descending only into present subtrees. Entirely non-existent address spaces incur zero table
     * reads, as the vast majority of user space is empty; querying page-by-page would be impossible to complete.
     */
    for (pml4Index = (ULONG)((scanFrom >> 39) & 0x1FFULL);
         pml4Index < KSW_INJ_ENTRIES_PER_TABLE && !state.truncated;
         ++pml4Index) {
        const ULONG64 kPml4e = pml4->entries[pml4Index];
        ULONG64 pml4Base = ((ULONG64)pml4Index) << 39;
        ULONG pdptIndex = 0UL;

        if (pml4Base >= rangeEnd) {
            break;
        }
        if ((kPml4e & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
            continue;
        }
        if (response->tableReads >= state.maxTableReads) {
            state.truncated = TRUE;
            response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED;
            response->nextCursorAddress = pml4Base;
            break;
        }
        status = kswordArkInjectionReadPhysicalTable(kPml4e & KSW_INJ_PTE_ADDR_4KB_MASK, pdpt);
        ++response->tableReads;
        if (!NT_SUCCESS(status)) {
            ++response->failedTableReads;
            continue;
        }

        /*
         * The inner loop always starts from 0, skipping ahead with the "continue if the entire segment is before the cursor" check below. Calculating
         * the start index via arithmetic is prone to off-by-one errors at cross-level boundaries, whereas performing hundreds of integer comparisons
         * is negligible in cost. The expensive operation is the table read, which is already blocked by the present bit and range checks.
         */
        for (pdptIndex = 0UL;
             pdptIndex < KSW_INJ_ENTRIES_PER_TABLE && !state.truncated;
             ++pdptIndex) {
            const ULONG64 kPdpte = pdpt->entries[pdptIndex];
            const ULONG64 kPdptBase = pml4Base | (((ULONG64)pdptIndex) << 30);
            ULONG pdIndex = 0UL;

            if (kPdptBase >= rangeEnd) {
                break;
            }
            if (kPdptBase + (1ULL << 30) <= scanFrom) {
                continue;
            }
            if ((kPdpte & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
                continue;
            }
            if ((kPdpte & KSW_INJ_PTE_LARGE_BIT) != 0ULL) {
                const ULONG kFlags = kswordArkInjectionMergeFlags(kPml4e, kPdpte, kPdpte, kPdpte, FALSE);
                if (kswordArkInjectionLeafWanted(&state, kFlags) && kPdptBase >= scanFrom) {
                    kswordArkInjectionAppendLeaf(
                        &state,
                        kPdptBase,
                        kPdpte & KSW_INJ_PTE_ADDR_1GB_MASK,
                        kPdpte,
                        KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_1GB,
                        kFlags);
                }
                continue;
            }
            if (response->tableReads >= state.maxTableReads) {
                state.truncated = TRUE;
                response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED;
                response->nextCursorAddress = kPdptBase;
                break;
            }
            status = kswordArkInjectionReadPhysicalTable(kPdpte & KSW_INJ_PTE_ADDR_4KB_MASK, pd);
            ++response->tableReads;
            if (!NT_SUCCESS(status)) {
                ++response->failedTableReads;
                continue;
            }

            for (pdIndex = 0UL;
                 pdIndex < KSW_INJ_ENTRIES_PER_TABLE && !state.truncated;
                 ++pdIndex) {
                const ULONG64 kPde = pd->entries[pdIndex];
                const ULONG64 kPdBase = kPdptBase | (((ULONG64)pdIndex) << 21);
                ULONG ptIndex = 0UL;

                if (kPdBase >= rangeEnd) {
                    break;
                }
                if (kPdBase + (1ULL << 21) <= scanFrom) {
                    continue;
                }
                if ((kPde & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
                    continue;
                }
                if ((kPde & KSW_INJ_PTE_LARGE_BIT) != 0ULL) {
                    const ULONG kFlags = kswordArkInjectionMergeFlags(kPml4e, kPdpte, kPde, kPde, FALSE);
                    if (kswordArkInjectionLeafWanted(&state, kFlags) && kPdBase >= scanFrom) {
                        kswordArkInjectionAppendLeaf(
                            &state,
                            kPdBase,
                            kPde & KSW_INJ_PTE_ADDR_2MB_MASK,
                            kPde,
                            KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_2MB,
                            kFlags);
                    }
                    continue;
                }
                if (response->tableReads >= state.maxTableReads) {
                    state.truncated = TRUE;
                    response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED;
                    response->nextCursorAddress = kPdBase;
                    break;
                }
                status = kswordArkInjectionReadPhysicalTable(kPde & KSW_INJ_PTE_ADDR_4KB_MASK, pt);
                ++response->tableReads;
                if (!NT_SUCCESS(status)) {
                    ++response->failedTableReads;
                    continue;
                }

                for (ptIndex = 0UL;
                     ptIndex < KSW_INJ_ENTRIES_PER_TABLE && !state.truncated;
                     ++ptIndex) {
                    const ULONG64 kPte = pt->entries[ptIndex];
                    const ULONG64 kPageVa = kPdBase | (((ULONG64)ptIndex) << 12);
                    ULONG flags = 0UL;

                    if (kPageVa >= rangeEnd) {
                        break;
                    }
                    if (kPageVa < scanFrom) {
                        continue;
                    }
                    if ((kPte & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
                        continue;
                    }
                    flags = kswordArkInjectionMergeFlags(kPml4e, kPdpte, kPde, kPte, TRUE);
                    if (!kswordArkInjectionLeafWanted(&state, flags)) {
                        continue;
                    }
                    kswordArkInjectionAppendLeaf(
                        &state,
                        kPageVa,
                        kPte & KSW_INJ_PTE_ADDR_4KB_MASK,
                        kPte,
                        KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB,
                        flags);
                }
            }
        }
    }

    if (!state.truncated) {
        kswordArkInjectionFlushRun(&state);
    }
    response->scannedEnd = state.truncated
        ? response->nextCursorAddress
        : rangeEnd;

    if (state.truncated) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED;
    } else if (response->failedTableReads != 0UL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL;
    } else {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_OK;
    }

    *bytesWrittenOut =
        KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
         sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY));
    response->size = (ULONG)*bytesWrittenOut;

    ExFreePool(pml4);
    ObDereferenceObject(processObject);
    return STATUS_SUCCESS;
}

/*++

Module Name:

    hvm_ept_local.c

Abstract:

    Implements per-processor private EPT hierarchies.

    Both flip mechanisms in this driver write one EPT leaf and let the guest
    retire a single instruction.  With one shared hierarchy that write is
    visible to every other processor for the whole window, which is why both
    features refuse any topology but a single processor.

    A private hierarchy removes that window by construction rather than by
    timing: each processor walks its own copy of the tables on the path to a
    flippable leaf, and everything else stays shared.  A private path is its
    shared counterpart with only the addresses replaced, so the two are
    provably identical in every other bit.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL except for Translate.

--*/

#include "hvm_ept_local.h"

#include "driver/KswordArkHvmControls.h"

#if defined(_M_AMD64)

#include "../../platform/pool_compat.h"

/* Tag the single per-processor block backing every private table. */
#define KSW_HVM_EPT_LOCAL_POOL_TAG 'LvHK'

/* Carve one per-processor block into pages without a second allocator. */
typedef struct KswHvmLocalPageCursor
{
    /* Retain the block start so pages can be handed out in order. */
    PUCHAR block;
    /* Retain how many pages the block holds. */
    ULONG total;
    /* Retain how many pages have been handed out. */
    ULONG used;
} KswHvmLocalPageCursor;

/*
 * Hand out one zero-initialized page from the block.
 *
 * A nonpaged allocation of a whole number of pages is page aligned, so each
 * page handed out here is exactly one physical page and its address can be
 * published into a parent entry on its own.  The pages need not be
 * physically contiguous with each other - nothing in the hierarchy assumes
 * that - which is what lets one allocation replace one per table.
 */
static PVOID
kswordArkHvmEptLocalTakePage(
    _Inout_ KswHvmLocalPageCursor* cursor,
    _Out_ PHYSICAL_ADDRESS* physicalAddress
    )
{
    PVOID page = NULL;

    /* Report exhaustion rather than running past the block. */
    physicalAddress->QuadPart = 0LL;
    if (cursor->used >= cursor->total) {
        /* Return no page for an exhausted block. */
        return NULL;
    }
    page = cursor->block + ((SIZE_T)cursor->used * (SIZE_T)PAGE_SIZE);
    cursor->used += 1UL;
    *physicalAddress = MmGetPhysicalAddress(page);
    /* Refuse a page whose physical address could not be resolved. */
    if (physicalAddress->QuadPart == 0LL) {
        /* Return no page rather than publishing address zero. */
        return NULL;
    }
    /* Return the page for the caller to fill. */
    return page;
}

/* Find the forked table that mirrors one shared table, or NULL. */
static KswHvmEptLocalTable*
kswordArkHvmEptLocalFindTable(
    _In_ const KswHvmEptLocal* local,
    _In_ const VOID* sharedVirtual,
    _In_ ULONG level
    )
{
    ULONG index = 0UL;

    /* Scan the bounded fork ledger for an exact match. */
    for (index = 0UL; index < local->tableCount; ++index) {
        /* Compare both the source table and its level. */
        if (local->tables[index].sharedVirtual == sharedVirtual &&
            local->tables[index].level == level) {
            /* Return the existing fork, cast away const for the caller. */
            return (KswHvmEptLocalTable*)&local->tables[index];
        }
    }
    /* Report that this table is still shared. */
    return NULL;
}

/* Copy one shared table into a fresh private page and record the fork. */
static NTSTATUS
kswordArkHvmEptLocalForkTable(
    _Inout_ KswHvmEptLocal* local,
    _Inout_ KswHvmLocalPageCursor* cursor,
    _In_ PVOID sharedVirtual,
    _In_ ULONG level,
    _Outptr_ KswHvmEptLocalTable** table
    )
{
    PHYSICAL_ADDRESS physicalAddress = { 0 };
    KswHvmEptLocalTable* record = NULL;
    PVOID page = NULL;

    /* Refuse a fork the bounded ledger cannot record. */
    if (local->tableCount >= KSW_HVM_MAX_LOCAL_TABLES) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    page = kswordArkHvmEptLocalTakePage(cursor, &physicalAddress);
    /* Refuse when the pre-computed page budget turned out to be short. */
    if (page == NULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * Copy the shared table wholesale.  Everything below this table stays
     * shared until something forks it too, so the private path starts out
     * indistinguishable from the shared one.
     */
    RtlCopyMemory(page, sharedVirtual, (SIZE_T)PAGE_SIZE);
    record = &local->tables[local->tableCount];
    record->sharedVirtual = sharedVirtual;
    record->privateVirtual = page;
    record->privatePhysical = physicalAddress;
    record->level = level;
    record->reserved0 = 0UL;
    local->tableCount += 1UL;
    *table = record;
    /* Complete the fork successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptLocalCollectLeaves(
    _In_ const KswHvmRuntime* runtime,
    _Out_writes_to_(capacity, *count) ULONGLONG* bases,
    _In_ ULONG capacity,
    _Out_ ULONG* count
    )
{
    ULONG index = 0UL;
    ULONG scan = 0UL;
    ULONG total = 0UL;

    /* Reject an incomplete caller contract before reading any table. */
    if (runtime == NULL || bases == NULL || count == NULL || capacity == 0UL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *count = 0UL;
    /*
     * Views own their leaf exclusively and flip it on every access-type
     * mismatch, so every installed view contributes a base.
     */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        ULONGLONG base = 0ULL;
        BOOLEAN duplicate = FALSE;

        /* Skip slots that hold no view. */
        if (!runtime->eptViews[index].active) {
            /* Continue to the next bounded record. */
            continue;
        }
        base = KswordArkHvmEptLeafBase(
            runtime->eptViews[index].physicalAddress);
        /* Skip a base another view already contributed. */
        for (scan = 0UL; scan < total; ++scan) {
            if (bases[scan] == base) {
                /* Record the duplicate and stop scanning. */
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate) {
            /* Continue to the next bounded record. */
            continue;
        }
        /* Refuse a set larger than one private hierarchy may mirror. */
        if (total >= capacity) {
            /* Return the exact bounded-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        bases[total] = base;
        total += 1UL;
    }
    /*
     * Allow-once rules temporarily widen a leaf, so every page they cover
     * contributes its containing leaf.  Rules that only deny access never
     * flip anything and are deliberately not collected.
     */
    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_EPT_RULES; ++index) {
        ULONGLONG cursor = 0ULL;
        ULONGLONG end = 0ULL;

        /* Skip inactive rules and rules that never grant. */
        if (!runtime->eptRules[index].active ||
            (runtime->eptRules[index].flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) == 0UL) {
            /* Continue to the next bounded record. */
            continue;
        }
        cursor = KswordArkHvmEptLeafBase(
            runtime->eptRules[index].physicalAddress);
        end = runtime->eptRules[index].physicalAddress +
            ((ULONGLONG)runtime->eptRules[index].pageCount *
                KSW_HVM_PAGE_BYTES);
        while (cursor < end) {
            BOOLEAN duplicate = FALSE;

            /* Skip a base already contributed by a view or another rule. */
            for (scan = 0UL; scan < total; ++scan) {
                if (bases[scan] == cursor) {
                    /* Record the duplicate and stop scanning. */
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                /* Refuse a set larger than one hierarchy may mirror. */
                if (total >= capacity) {
                    /* Return the exact bounded-resource failure. */
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                bases[total] = cursor;
                total += 1UL;
            }
            /* Advance to the next whole two-MiB leaf. */
            cursor += KSW_HVM_LARGE_PAGE_BYTES;
        }
    }
    *count = total;
    /* Complete the collection successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptLocalCheckAdmission(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG byteCount
    )
{
    ULONGLONG bases[KSW_HVM_MAX_LOCAL_LEAVES] = { 0 };
    ULONGLONG cursor = 0ULL;
    ULONGLONG end = 0ULL;
    ULONG count = 0UL;
    ULONG scan = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before reading any table. */
    if (runtime == NULL || byteCount == 0ULL ||
        physicalAddress > (MAXULONGLONG - byteCount)) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* No mirroring means no limit; this is the feature-off answer. */
    if (!runtime->localEptArmed) {
        /* Complete without consulting any bound. */
        return STATUS_SUCCESS;
    }
    /* Start from what the currently installed rules and views already cost. */
    status = kswordArkHvmEptLocalCollectLeaves(
        runtime,
        bases,
        KSW_HVM_MAX_LOCAL_LEAVES,
        &count);
    if (!NT_SUCCESS(status)) {
        /* Return the exact collection failure. */
        return status;
    }
    /* Add every leaf the prospective range would contribute. */
    cursor = KswordArkHvmEptLeafBase(physicalAddress);
    end = physicalAddress + byteCount;
    while (cursor < end) {
        BOOLEAN duplicate = FALSE;

        for (scan = 0UL; scan < count; ++scan) {
            if (bases[scan] == cursor) {
                /* An already-counted leaf costs nothing more. */
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            /* Refuse here, where the caller still knows what it asked for. */
            if (count >= KSW_HVM_MAX_LOCAL_LEAVES) {
                /* Return the exact bounded-resource failure. */
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            bases[count] = cursor;
            count += 1UL;
        }
        /* Advance to the next whole two-MiB leaf. */
        cursor += KSW_HVM_LARGE_PAGE_BYTES;
    }
    /*
     * Also check the aggregate page budget, using the worst-case shape where
     * every leaf needs its own parents.  Refusing a set the exact build would
     * have accepted is the safe direction to be wrong in.
     */
    if (!KswordArkHvmEptLocalFitsBudget(
            KswordArkHvmEptLocalPageCost(
                runtime->processorCount,
                count,
                count,
                count),
            KSW_HVM_MAX_LOCAL_EPT_PAGES)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Complete the admission check successfully. */
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmEptLocalRelease(
    _Inout_ KswHvmEptLocal* local
    )
{
    /* Tolerate a zeroed record so every failure path can call this. */
    if (local == NULL) {
        /* Return without touching an absent record. */
        return;
    }
    /*
     * One allocation backs the root and every forked table, so one free
     * releases all of them.  ExFreePool is legal at DISPATCH_LEVEL, which
     * matters because this runs from the resident teardown path that a power
     * callback can reach.
     */
    if (local->pageBlock != NULL) {
        ExFreePool(local->pageBlock);
    }
    RtlZeroMemory(local, sizeof(*local));
}

NTSTATUS
kswordArkHvmEptLocalBuild(
    _Inout_ KswHvmRuntime* runtime,
    _In_reads_(count) const ULONGLONG* bases,
    _In_ ULONG count,
    _Out_ KswHvmEptLocal* local
    )
{
    KswHvmLocalPageCursor cursor = { 0 };
    PHYSICAL_ADDRESS rootPhysical = { 0 };
    ULONGLONG pageCost = 0ULL;
    ULONG distinctPml4 = 0UL;
    ULONG distinctGib = 0UL;
    ULONG index = 0UL;
    ULONG scan = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before allocating anything. */
    if (runtime == NULL || bases == NULL || local == NULL ||
        count == 0UL || count > KSW_HVM_MAX_LOCAL_LEAVES ||
        runtime->eptPml4 == NULL || runtime->eptPointer == 0ULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(local, sizeof(*local));
    /*
     * Count the distinct parents before allocating, so the page budget is
     * exact rather than worst-case.  Two leaves in the same GiB window share
     * both a PDPT and a page directory.
     */
    for (index = 0UL; index < count; ++index) {
        BOOLEAN seenPml4 = FALSE;
        BOOLEAN seenGib = FALSE;

        for (scan = 0UL; scan < index; ++scan) {
            if (KswordArkHvmEptPml4Index(bases[scan]) ==
                KswordArkHvmEptPml4Index(bases[index])) {
                /* Record that this PML4 slot already has a fork. */
                seenPml4 = TRUE;
                if (KswordArkHvmEptPdptIndex(bases[scan]) ==
                    KswordArkHvmEptPdptIndex(bases[index])) {
                    /* Record that this GiB window already has a fork. */
                    seenGib = TRUE;
                }
            }
        }
        if (!seenPml4) {
            distinctPml4 += 1UL;
        }
        if (!seenGib) {
            distinctGib += 1UL;
        }
    }
    /* Refuse before allocating when the whole set cannot fit the budget. */
    pageCost = KswordArkHvmEptLocalPageCost(
        runtime->processorCount,
        distinctPml4,
        distinctGib,
        count);
    if (!KswordArkHvmEptLocalFitsBudget(
            pageCost,
            KSW_HVM_MAX_LOCAL_EPT_PAGES)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* This record needs only its own share of that budget. */
    cursor.total = 1UL + distinctPml4 + distinctGib + count;
    if (cursor.total > (KSW_HVM_MAX_LOCAL_TABLES + 1UL)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /*
     * One allocation for the whole processor.  A per-table allocator would
     * make a fragmented machine fail a start half-way through, and would put
     * MmFreeContiguousMemory - which requires PASSIVE_LEVEL - on a teardown
     * path a power callback can reach.
     */
    cursor.block = (PUCHAR)kswordArkAllocateNonPagedPool(
        (SIZE_T)cursor.total * (SIZE_T)PAGE_SIZE,
        KSW_HVM_EPT_LOCAL_POOL_TAG);
    if (cursor.block == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(cursor.block, (SIZE_T)cursor.total * (SIZE_T)PAGE_SIZE);
    local->pageBlock = cursor.block;
    local->pageCount = cursor.total;
    /* Take the root first so every rebase below has somewhere to publish. */
    local->pml4Virtual = kswordArkHvmEptLocalTakePage(
        &cursor,
        &rootPhysical);
    if (local->pml4Virtual == NULL) {
        /* Release everything this record took before returning. */
        kswordArkHvmEptLocalRelease(local);
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(
        local->pml4Virtual,
        runtime->eptPml4,
        (SIZE_T)PAGE_SIZE);
    local->pml4Physical = rootPhysical;
    /*
     * Derive the private pointer from the shared one rather than composing it
     * from constants.  Composing would give the memory type, the walk length
     * and the accessed/dirty bit a second source of truth; derived this way
     * the private pointer is accepted by VM entry exactly when the shared one
     * is, and an INVEPT descriptor built from it matches the VMCS field.
     */
    local->eptPointer = KswordArkHvmEptRebaseEntry(
        runtime->eptPointer,
        (ULONGLONG)rootPhysical.QuadPart);
    /* Fork parent before child so no private entry ever points at nothing. */
    for (index = 0UL; index < count; ++index) {
        const ULONG kPml4Index = KswordArkHvmEptPml4Index(bases[index]);
        const ULONG kPdptIndex = KswordArkHvmEptPdptIndex(bases[index]);
        const ULONG kPdIndex = KswordArkHvmEptPdIndex(bases[index]);
        KswHvmEptLocalTable* pdptRecord = NULL;
        KswHvmEptLocalTable* pdRecord = NULL;
        KswHvmEptLocalTable* ptRecord = NULL;
        KswHvmEptSplit* split = NULL;
        ULONGLONG* privateTable = NULL;
        ULONG splitScan = 0UL;

        /* Refuse a base whose shared hierarchy was never populated. */
        if (kPml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
            kPdptIndex >= 512UL ||
            runtime->eptPdpt[kPml4Index] == NULL ||
            runtime->eptPd[kPml4Index][kPdptIndex] == NULL) {
            /* Release everything and refuse the whole set. */
            kswordArkHvmEptLocalRelease(local);
            /* Return the exact hierarchy-contract failure. */
            return STATUS_INVALID_PARAMETER;
        }
        /*
         * Require a live split.  Splitting here would allocate from the
         * shared ledger while this routine owns a private block, and both
         * producers already split eagerly when the rule or view was added -
         * so a missing split means the caller changed the tables underneath
         * us, which must fail rather than be repaired.
         */
        for (splitScan = 0UL;
             splitScan < KSW_HVM_MAX_EPT_SPLITS;
             ++splitScan) {
            if (runtime->eptSplits[splitScan].active &&
                runtime->eptSplits[splitScan].physicalBase == bases[index]) {
                /* Bind the split whose page table will be mirrored. */
                split = &runtime->eptSplits[splitScan];
                break;
            }
        }
        if (split == NULL || split->pageTable == NULL) {
            /* Release everything and refuse the whole set. */
            kswordArkHvmEptLocalRelease(local);
            /* Return the exact missing-split failure. */
            return STATUS_NOT_FOUND;
        }
        /* Ensure this PML4 slot has a private page-directory-pointer table. */
        pdptRecord = kswordArkHvmEptLocalFindTable(
            local,
            runtime->eptPdpt[kPml4Index],
            KSW_HVM_LOCAL_LEVEL_PDPT);
        if (pdptRecord == NULL) {
            status = kswordArkHvmEptLocalForkTable(
                local,
                &cursor,
                runtime->eptPdpt[kPml4Index],
                KSW_HVM_LOCAL_LEVEL_PDPT,
                &pdptRecord);
            if (!NT_SUCCESS(status)) {
                /* Release everything and refuse the whole set. */
                kswordArkHvmEptLocalRelease(local);
                /* Return the exact fork failure. */
                return status;
            }
            /* Point the private root at the private PDPT. */
            ((ULONGLONG*)local->pml4Virtual)[kPml4Index] =
                KswordArkHvmEptRebaseEntry(
                    ((const ULONGLONG*)runtime->eptPml4)[kPml4Index],
                    (ULONGLONG)pdptRecord->privatePhysical.QuadPart);
        }
        /* Ensure this GiB window has a private page directory. */
        pdRecord = kswordArkHvmEptLocalFindTable(
            local,
            runtime->eptPd[kPml4Index][kPdptIndex],
            KSW_HVM_LOCAL_LEVEL_PD);
        if (pdRecord == NULL) {
            status = kswordArkHvmEptLocalForkTable(
                local,
                &cursor,
                runtime->eptPd[kPml4Index][kPdptIndex],
                KSW_HVM_LOCAL_LEVEL_PD,
                &pdRecord);
            if (!NT_SUCCESS(status)) {
                /* Release everything and refuse the whole set. */
                kswordArkHvmEptLocalRelease(local);
                /* Return the exact fork failure. */
                return status;
            }
            /* Point the private PDPT at the private page directory. */
            privateTable = (ULONGLONG*)pdptRecord->privateVirtual;
            privateTable[kPdptIndex] = KswordArkHvmEptRebaseEntry(
                ((const ULONGLONG*)runtime->eptPdpt[kPml4Index])[kPdptIndex],
                (ULONGLONG)pdRecord->privatePhysical.QuadPart);
        }
        /* Mirror the split page table that actually gets flipped. */
        ptRecord = kswordArkHvmEptLocalFindTable(
            local,
            split->pageTable,
            KSW_HVM_LOCAL_LEVEL_PT);
        if (ptRecord == NULL) {
            status = kswordArkHvmEptLocalForkTable(
                local,
                &cursor,
                split->pageTable,
                KSW_HVM_LOCAL_LEVEL_PT,
                &ptRecord);
            if (!NT_SUCCESS(status)) {
                /* Release everything and refuse the whole set. */
                kswordArkHvmEptLocalRelease(local);
                /* Return the exact fork failure. */
                return status;
            }
            /* Point the private page directory at the private leaf table. */
            privateTable = (ULONGLONG*)pdRecord->privateVirtual;
            privateTable[kPdIndex] = KswordArkHvmEptRebaseEntry(
                ((const ULONGLONG*)
                    runtime->eptPd[kPml4Index][kPdptIndex])[kPdIndex],
                (ULONGLONG)ptRecord->privatePhysical.QuadPart);
        }
    }
    /* Publish the record only after every table is in place. */
    KeMemoryBarrier();
    local->active = TRUE;
    /* Complete the build successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptLocalVerify(
    _In_ const KswHvmRuntime* runtime,
    _In_reads_(processorCount) const KswHvmEptLocal* localArray,
    _In_ ULONG processorCount,
    _In_reads_(count) const ULONGLONG* bases,
    _In_ ULONG count
    )
{
    ULONG processor = 0UL;
    ULONG peer = 0UL;
    ULONG index = 0UL;

    /* Reject an incomplete caller contract before any walk. */
    if (runtime == NULL || localArray == NULL || bases == NULL ||
        processorCount == 0UL || count == 0UL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    for (processor = 0UL; processor < processorCount; ++processor) {
        const KswHvmEptLocal* local = &localArray[processor];

        /* Every processor must actually own a built hierarchy. */
        if (!local->active ||
            local->pml4Virtual == NULL ||
            local->eptPointer == 0ULL) {
            /* Return the exact verification failure. */
            return STATUS_UNSUCCESSFUL;
        }
        /*
         * Compare the root address, not the whole pointer.
         *
         * What makes single-context INVEPT on one processor leave the others
         * alone is that their cached translations are tagged by the root
         * address.  Two pointers differing only in a control bit would tag
         * identically, so comparing whole pointers would accept exactly the
         * arrangement this check exists to reject.
         */
        if ((local->eptPointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) ==
            (runtime->eptPointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK)) {
            /* Return the exact verification failure. */
            return STATUS_UNSUCCESSFUL;
        }
        for (peer = 0UL; peer < processor; ++peer) {
            if ((local->eptPointer & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) ==
                (localArray[peer].eptPointer &
                    KSWORD_ARK_HVM_EPT_PHYSICAL_MASK)) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
        }
        /*
         * Walk each base from this private root downward and check the
         * postcondition, rather than replaying how the build got there.  A
         * mistake shared by build and check would survive a replay.
         */
        for (index = 0UL; index < count; ++index) {
            const ULONG kPml4Index = KswordArkHvmEptPml4Index(bases[index]);
            const ULONG kPdptIndex = KswordArkHvmEptPdptIndex(bases[index]);
            const ULONG kPdIndex = KswordArkHvmEptPdIndex(bases[index]);
            const KswHvmEptLocalTable* record = NULL;
            const ULONGLONG* table = NULL;
            ULONGLONG entry = 0ULL;
            ULONG scan = 0UL;
            ULONG slot = 0UL;

            /* Resolve the private PDPT the private root names. */
            entry = ((const ULONGLONG*)local->pml4Virtual)[kPml4Index];
            record = NULL;
            for (scan = 0UL; scan < local->tableCount; ++scan) {
                if ((ULONGLONG)local->tables[scan].privatePhysical.QuadPart ==
                        (entry & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) &&
                    local->tables[scan].level == KSW_HVM_LOCAL_LEVEL_PDPT) {
                    /* Bind the private table this entry actually names. */
                    record = &local->tables[scan];
                    break;
                }
            }
            if (record == NULL) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
            /* Resolve the private page directory that PDPT names. */
            table = (const ULONGLONG*)record->privateVirtual;
            entry = table[kPdptIndex];
            record = NULL;
            for (scan = 0UL; scan < local->tableCount; ++scan) {
                if ((ULONGLONG)local->tables[scan].privatePhysical.QuadPart ==
                        (entry & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) &&
                    local->tables[scan].level == KSW_HVM_LOCAL_LEVEL_PD) {
                    /* Bind the private table this entry actually names. */
                    record = &local->tables[scan];
                    break;
                }
            }
            if (record == NULL) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
            /* Resolve the private leaf table that page directory names. */
            table = (const ULONGLONG*)record->privateVirtual;
            entry = table[kPdIndex];
            record = NULL;
            for (scan = 0UL; scan < local->tableCount; ++scan) {
                if ((ULONGLONG)local->tables[scan].privatePhysical.QuadPart ==
                        (entry & KSWORD_ARK_HVM_EPT_PHYSICAL_MASK) &&
                    local->tables[scan].level == KSW_HVM_LOCAL_LEVEL_PT) {
                    /* Bind the private table this entry actually names. */
                    record = &local->tables[scan];
                    break;
                }
            }
            if (record == NULL) {
                /* Return the exact verification failure. */
                return STATUS_UNSUCCESSFUL;
            }
            /*
             * The private leaf table must still agree with the shared one,
             * entry for entry.  Any divergence at arm time means the copy
             * raced a mutation, and the whole arm has to fail.
             */
            for (slot = 0UL;
                 slot < (PAGE_SIZE / sizeof(ULONGLONG));
                 ++slot) {
                if (((const ULONGLONG*)record->privateVirtual)[slot] !=
                    ((const ULONGLONG*)record->sharedVirtual)[slot]) {
                    /* Return the exact verification failure. */
                    return STATUS_UNSUCCESSFUL;
                }
            }
        }
    }
    /* Complete verification successfully. */
    return STATUS_SUCCESS;
}

volatile ULONGLONG*
kswordArkHvmEptLocalTranslate(
    _In_opt_ const KswHvmEptLocal* local,
    _In_opt_ volatile ULONGLONG* sharedEntry
    )
{
    ULONGLONG tableBase = 0ULL;
    ULONGLONG offset = 0ULL;
    ULONG index = 0UL;

    /*
     * The feature-off case.  Returning NULL here is what makes the two arm
     * sites collapse to exactly the code they run today: they keep the
     * shared pointer they already hold.
     */
    if (local == NULL || sharedEntry == NULL || !local->active) {
        /* Report that no translation applies. */
        return NULL;
    }
    tableBase = KswordArkHvmEptEntryTableBase((ULONGLONG)(ULONG_PTR)sharedEntry);
    offset = KswordArkHvmEptEntryByteOffset((ULONGLONG)(ULONG_PTR)sharedEntry);
    /* Find the private mirror of the table this entry lives in. */
    for (index = 0UL; index < local->tableCount; ++index) {
        /* Only leaf tables are ever flipped, so only they are translated. */
        if (local->tables[index].level == KSW_HVM_LOCAL_LEVEL_PT &&
            (ULONGLONG)(ULONG_PTR)local->tables[index].sharedVirtual ==
                tableBase) {
            /* Return the same slot inside this processor's own copy. */
            return (volatile ULONGLONG*)(
                (PUCHAR)local->tables[index].privateVirtual +
                (SIZE_T)offset);
        }
    }
    /*
     * A flippable leaf that has no mirror is a build error, and the caller
     * must fail closed rather than write the shared table it was trying to
     * avoid.
     */
    return NULL;
}

#endif /* defined(_M_AMD64) */

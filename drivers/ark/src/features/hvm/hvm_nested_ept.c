/*++

Module Name:

    hvm_nested_ept.c

Abstract:

    Implements shadow-EPT composition for L2 execution.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_nested_ept.h"
#include "hvm_ept.h"
#include "hvm_ept_switch.h"
#include "hvm_resident.h"

#if defined(_M_AMD64)

#include "../../platform/pool_compat.h"

/* Tag the single per-processor block backing every shadow table. */
#define KSW_HVM_NEPT_POOL_TAG 'NvHK'

/* Name the read, write and execute permission bits of an EPT entry. */
#define KSW_HVM_NEPT_READ 0x1ULL
#define KSW_HVM_NEPT_WRITE 0x2ULL
#define KSW_HVM_NEPT_EXECUTE 0x4ULL
#define KSW_HVM_NEPT_PERMISSIONS \
    (KSW_HVM_NEPT_READ | KSW_HVM_NEPT_WRITE | KSW_HVM_NEPT_EXECUTE)
/* Name the bit that makes an interior entry a leaf. */
#define KSW_HVM_NEPT_LARGE 0x80ULL
/* Name the frame field of an EPT entry. */
#define KSW_HVM_NEPT_FRAME_MASK 0x000FFFFFFFFFF000ULL
/* Name write-back in the memory-type field of a leaf. */
#define KSW_HVM_NEPT_MEMORY_TYPE_WB 0x30ULL
/* Name the four-level page-walk length an EPT pointer encodes. */
#define KSW_HVM_NEPT_EPTP_WALK_4 0x18ULL
/* Name the EPT-pointer bit that asks the processor to maintain A/D flags. */
#define KSW_HVM_NEPT_EPTP_ENABLE_AD (1ULL << 6)
/* Name the two leaf bits the processor maintains: accessed (8), dirty (9). */
#define KSW_HVM_NEPT_AD_BITS ((1ULL << 8) | (1ULL << 9))

/* Find the override that owns this guest-physical address, or NULL. */
static KswHvmNestedPage* kswordArkHvmNestedPageForAddress(
    KswHvmRuntime* runtime, KswHvmShadowEptState* shadow,
    ULONGLONG guestPhysical)
{
    KswHvmNestedPage* page = (KswHvmNestedPage*)InterlockedCompareExchangePointer(
        (PVOID volatile*)&runtime->nestedPage, NULL, NULL);
    /* A revoked lease composes nothing, whatever it still owns. */
    if (page == NULL || ReadAcquire(&runtime->nestedPageRevocationReason) != 0L ||
        page->ept12Pointer != shadow->l1EptPointer) {
        return NULL;
    }
    /*
     * Ask the plan, not the base address.
     *
     * A 4-KiB plan answers exactly what the previous equality test answered, so
     * the single-page path is unchanged; a larger plan owns every page of its
     * region. Comparing against GuestPhysicalPage here instead would silently
     * restrict a published 2-MiB region to its first page, leaving 511 pages
     * composed from the source while every counter reported a live override.
     */
    return kswordHvmLeafPlanContains(&page->plan, guestPhysical) ? page : NULL;
}

static ULONGLONG kswordArkHvmNestedPageLeaf(
    KswHvmRuntime* runtime, KswHvmShadowEptState* shadow,
    ULONGLONG guestPhysical, ULONGLONG originalLeaf, BOOLEAN count)
{
    KswHvmNestedPage* page =
        kswordArkHvmNestedPageForAddress(runtime, shadow, guestPhysical);
    ULONGLONG index;

    if (page == NULL) { return originalLeaf; }
    /* The replacement is ordinary RAM. Preserve both levels' permissions. */
    if ((originalLeaf & 0x38ULL) != KSW_HVM_NEPT_MEMORY_TYPE_WB) { return originalLeaf; }
    if (count) {
        (void)InterlockedCompareExchange64(&page->originalPhysicalPage,
            (LONG64)(originalLeaf & KSW_HVM_NEPT_FRAME_MASK), 0LL);
        (void)InterlockedIncrement64(&page->composedCount);
    }
    /* Backing is contiguous, so the page's offset in the region is its offset
       in the backing. For a 4-KiB plan the index is always zero. */
    index = (guestPhysical - page->plan.guestBase) >> KSW_PLAN_SHIFT_4K;
    return (originalLeaf & ~KSW_HVM_NEPT_FRAME_MASK) |
        kswordHvmLeafPlanPageFrame(&page->plan, index);
}

/*
 * Answer whether this address should be published as a leaf above the PT level,
 * and with which frame.
 *
 * Returning the granularity rather than a boolean keeps one decision in one
 * place: the fill path stops its descent at whatever level this names, and a
 * plan that names 4 KiB produces the ordinary path with no special case.
 */
static ULONG kswordArkHvmNestedPageLargeLeaf(
    KswHvmRuntime* runtime, KswHvmShadowEptState* shadow,
    ULONGLONG guestPhysical, ULONGLONG composedLeaf, ULONGLONG* largeLeaf)
{
    KswHvmNestedPage* page =
        kswordArkHvmNestedPageForAddress(runtime, shadow, guestPhysical);

    *largeLeaf = 0ULL;
    /* No override, or one published at ordinary granularity. */
    if (page == NULL || page->plan.leafShift <= KSW_PLAN_SHIFT_4K) {
        return KSW_PLAN_SHIFT_4K;
    }
    /* Only write-back RAM is replaced, exactly as at 4 KiB. */
    if ((composedLeaf & 0x38ULL) != KSW_HVM_NEPT_MEMORY_TYPE_WB) {
        return KSW_PLAN_SHIFT_4K;
    }
    /*
     * Carry the region base and set the leaf bit.
     *
     * The frame is the region base and not the faulting page's frame: hardware
     * supplies the offset from the address it is translating, so a leaf naming
     * an offset frame would serve the whole region shifted by that offset.
     * Permissions and memory type come from the composed 4-KiB leaf, which is
     * sound only because the plan already refused any region whose source leaf
     * is finer than the leaf being installed - so these bits describe every
     * page beneath it, not merely the one that faulted.
     */
    *largeLeaf = (composedLeaf & ~KSW_HVM_NEPT_FRAME_MASK) |
        kswordHvmLeafPlanLeafFrame(&page->plan) | KSW_HVM_NEPT_LARGE;
    return page->plan.leafShift;
}

/*
 * Answer whether this processor can maintain EPT accessed/dirty flags.
 *
 * Asked of the capability MSR rather than assumed from the fact that L1 asked:
 * L1 reads the same MSR, but it reads it through us, and nothing guarantees
 * the two views agree on a machine where an outer hypervisor filters it.
 * Setting EPTP bit 6 on a processor that cannot honour it fails VM entry with
 * an error L1 has no way to act on.
 */
static BOOLEAN
kswordArkHvmNestedEptProcessorSupportsAccessedDirty(
    VOID
    )
{
    /* IA32_VMX_EPT_VPID_CAP bit 21 reports EPT A/D support. */
    const ULONGLONG kCapability = __readmsr(0x48CUL);

    /* Report exactly what the processor claims. */
    return ((kCapability & (1ULL << 21)) != 0ULL) ? TRUE : FALSE;
}
/* Name write-back in the memory-type field of an EPT pointer. */
#define KSW_HVM_NEPT_EPTP_MEMORY_TYPE_WB 0x6ULL

/* Hand out one zero-initialized page from the processor's block. */
static PVOID
kswordArkHvmNestedEptTakePage(
    _Inout_ KswHvmShadowEptState* shadow,
    _Out_ ULONGLONG* physicalAddress
    )
{
    PVOID page = NULL;
    PHYSICAL_ADDRESS physical = { 0 };

    *physicalAddress = 0ULL;
    /* Report exhaustion rather than running past the block. */
    if (shadow->pageBlock == NULL ||
        shadow->pageUsed >= shadow->pageTotal) {
        /* Return no page for an exhausted block. */
        return NULL;
    }
    page = (PVOID)((PUCHAR)shadow->pageBlock +
        ((SIZE_T)shadow->pageUsed * (SIZE_T)PAGE_SIZE));
    RtlZeroMemory(page, PAGE_SIZE);
    physical = MmGetPhysicalAddress(page);
    *physicalAddress = (ULONGLONG)physical.QuadPart;
    shadow->pagePhysical[shadow->pageUsed] =
        (ULONGLONG)physical.QuadPart & KSW_HVM_NEPT_FRAME_MASK;
    shadow->pageUsed += 1UL;
    /* Return one page whose physical identity is already resolved. */
    return page;
}

/*
 * Navigate one interior entry back to the table it names.
 *
 * Only pages this record handed out are accepted.  A frame we never issued
 * means the entry was not written by us - either an invariant is broken or
 * something outside edited the hierarchy - and the honest response is to stop
 * rather than follow a pointer into memory of unknown ownership.
 */
static volatile ULONGLONG*
kswordArkHvmNestedEptPageVirtual(
    _In_ const KswHvmShadowEptState* shadow,
    _In_ ULONGLONG entry
    )
{
    const ULONGLONG kFrame = entry & KSW_HVM_NEPT_FRAME_MASK;
    ULONG index = 0UL;

    for (index = 0UL; index < shadow->pageUsed; ++index) {
        if (shadow->pagePhysical[index] == kFrame) {
            /* Return the table this record issued for that frame. */
            return (volatile ULONGLONG*)((PUCHAR)shadow->pageBlock +
                ((SIZE_T)index * (SIZE_T)PAGE_SIZE));
        }
    }
    /* Return nothing for a frame this record never issued. */
    return NULL;
}

VOID
kswordArkHvmNestedEptInitialize(
    _Out_ KswHvmShadowEptState* shadow,
    _In_ ULONGLONG l0EptPointer
    )
{
    /* Ignore a missing record rather than fault on initialization. */
    if (shadow == NULL) {
        /* Return without touching absent state. */
        return;
    }
    RtlZeroMemory(shadow, sizeof(*shadow));
    shadow->l0EptPointer = l0EptPointer;
    shadow->lastStatus = STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmNestedEptPrepare(
    _Inout_ KswHvmShadowEptState* shadow
    )
{
    ULONGLONG rootPhysical = 0ULL;
    /* Preserve the ledger allocation result for a complete rollback. */
    NTSTATUS adStatus = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before reserving anything. */
    if (shadow == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Keep an existing reservation rather than leaking a second one. */
    if (shadow->pageBlock != NULL) {
        /* Return the already-complete reservation. */
        return STATUS_SUCCESS;
    }
    /*
     * One allocation for the whole processor, from the pool rather than
     * contiguous memory.  Releasing happens on the residency teardown path,
     * which a power callback can reach and where PASSIVE_LEVEL is not
     * guaranteed - the same constraint that already shapes the private EPT
     * hierarchies and the host stacks.
     */
    shadow->pageBlock = kswordArkAllocateNonPagedPool(
        (SIZE_T)KSW_HVM_NEPT_TABLE_PAGES * (SIZE_T)PAGE_SIZE,
        KSW_HVM_NEPT_POOL_TAG);
    /* Leave composition unavailable when the reservation fails. */
    if (shadow->pageBlock == NULL) {
        shadow->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        shadow->pageBlock,
        (SIZE_T)KSW_HVM_NEPT_TABLE_PAGES * (SIZE_T)PAGE_SIZE);
    shadow->pageTotal = KSW_HVM_NEPT_TABLE_PAGES;
    shadow->pageUsed = 0UL;
    /*
     * Room for a copy of every EPT12 table page the hierarchy depends on.
     *
     * A second allocation rather than a bigger first one: this block is read
     * and compared, never handed out as a table, and keeping the two apart
     * means a bug in one cannot hand the processor a page from the other.
     * Failure is not fatal - it costs the right to keep the shadow across an
     * invalidation, which is exactly what the code did before this existed.
     */
    shadow->trackedCopyBlock = kswordArkAllocateNonPagedPool(
        (SIZE_T)KSW_HVM_NEPT_TRACKED_PAGES * (SIZE_T)PAGE_SIZE,
        KSW_HVM_NEPT_POOL_TAG);
    if (shadow->trackedCopyBlock != NULL) {
        RtlZeroMemory(
            shadow->trackedCopyBlock,
            (SIZE_T)KSW_HVM_NEPT_TRACKED_PAGES * (SIZE_T)PAGE_SIZE);
    }
    shadow->trackedCount = 0UL;
    shadow->trackedOverflowCount = 0UL;
    /* Every composed leaf must have a lossless A/D ledger reservation. */
    adStatus = kswordArkHvmNestedAdPrepare(shadow);
    /* Unwind all partial reservations on a ledger allocation failure. */
    if (!NT_SUCCESS(adStatus)) {
        /* Release the table and snapshot blocks as well. */
        kswordArkHvmNestedEptRelease(shadow);
        /* Preserve the original error after cleanup. */
        shadow->lastStatus = adStatus;
        /* Refuse incomplete preparation. */
        return adStatus;
    }
    /* Take the root first so every fill below has somewhere to publish. */
    shadow->rootVirtual = kswordArkHvmNestedEptTakePage(
        shadow,
        &rootPhysical);
    if (shadow->rootVirtual == NULL) {
        /* Release snapshots and the ledger too if root reservation failed. */
        kswordArkHvmNestedEptRelease(shadow);
        shadow->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    shadow->rootPhysical = rootPhysical;
    /*
     * The composed pointer names our root, never L1's.
     *
     * Walk length and memory type come from what the processor supports, not
     * from what L1 asked for: L1's EPT12 is data we interpret, and copying its
     * pointer format would let a malformed one reach the hardware EPTP.
     */
    shadow->composedEptPointer =
        (rootPhysical & KSW_HVM_NEPT_FRAME_MASK) |
        KSW_HVM_NEPT_EPTP_WALK_4 |
        KSW_HVM_NEPT_EPTP_MEMORY_TYPE_WB;
    shadow->lastStatus = STATUS_SUCCESS;
    /* Return a complete reservation. */
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmNestedEptRelease(
    _Inout_ KswHvmShadowEptState* shadow
    )
{
    /* Ignore a record whose reservation never completed. */
    if (shadow == NULL) {
        /* Return without touching an absent reservation. */
        return;
    }
    /* Release even a partially prepared hierarchy. */
    if (shadow->pageBlock != NULL) {
        /* No CPU can still execute this block on the release path. */
        ExFreePool(shadow->pageBlock);
        /* Make repeated cleanup harmless. */
        shadow->pageBlock = NULL;
    }
    /* The ledger is owned by this active CPU reservation. */
    kswordArkHvmNestedAdRelease(shadow);
    if (shadow->trackedCopyBlock != NULL) {
        ExFreePool(shadow->trackedCopyBlock);
        shadow->trackedCopyBlock = NULL;
    }
    shadow->trackedCount = 0UL;
    shadow->trackedOverflowCount = 0UL;
    shadow->pageTotal = 0UL;
    shadow->pageUsed = 0UL;
    shadow->rootVirtual = NULL;
    shadow->rootPhysical = 0ULL;
    shadow->composedEptPointer = 0ULL;
    shadow->active = FALSE;
}

VOID
kswordArkHvmNestedEptInvalidate(
    _Inout_ KswHvmShadowEptState* shadow
    )
{
    /* Ignore a record with nothing composed. */
    if (shadow == NULL || shadow->rootVirtual == NULL) {
        /* Return without dropping absent mappings. */
        return;
    }
    /*
     * Drop everything rather than the one entry L1 named.
     *
     * Precise invalidation needs a reverse map from L1 physical back to every
     * L2 page that composed through it, and nothing here maintains one.
     * Dropping the whole hierarchy costs refills; dropping the wrong subset
     * costs an L2 running on a translation L1 already retired, with no symptom
     * until the memory underneath it is reused.  Coarse and certain beats
     * precise and unproven.
     */
    RtlZeroMemory(shadow->rootVirtual, PAGE_SIZE);
    shadow->pageUsed = 1UL;
    /*
     * The copies describe a hierarchy that no longer exists.
     *
     * What gets composed next may walk a different set of EPT12 pages, and
     * comparing the next invalidation against copies taken for the old one
     * would vouch for pages the new mappings never read.  Forgetting them
     * costs one snapshot per table page on the way back up.
     */
    shadow->trackedCount = 0UL;
    shadow->trackedOverflowCount = 0UL;
    /*
     * The A/D records describe leaves that no longer exist.
     *
     * Keeping them would have the next propagation read bits out of table
     * pages that have since been handed to a different guest-physical address,
     * and write them into EPT12 entries for pages L2 never touched.  The
     * caller is expected to have propagated before invalidating; anything not
     * folded by then is lost, which is the same thing INVEPT means for the
     * translations themselves.
     */
    shadow->adRecordCount = 0UL;
    /*
     * Zeroing the tables is not the whole job.
     *
     * The processor caches translations derived from them, and those survive
     * an edit to the memory they came from - that is what INVEPT exists for.
     * Dropping the tables without invalidating leaves L2 running on exactly
     * the mappings this call was made to retire, and the tables now say
     * nothing, so nothing later will contradict the stale entry either.
     */
    if (shadow->composedEptPointer != 0ULL) {
        if (kswordArkHvmAsmInveptSingle(shadow->composedEptPointer) != 0U) {
            shadow->faulted = TRUE;
            shadow->lastStatus = STATUS_UNSUCCESSFUL;
        }
    }
    shadow->invalidationGeneration = shadow->generation;
    shadow->generation += 1UL;
    /* A wrapped epoch must not alias an entry from the first generation. */
    if (shadow->generation == 0UL && shadow->adEntries != NULL) {
        /* No leaf survives the invalidation that precedes this reset. */
        RtlZeroMemory(shadow->adEntries,
            (SIZE_T)KSW_HVM_NEPT_AD_RECORDS * sizeof(*shadow->adEntries));
    }
}

NTSTATUS
kswordArkHvmNestedEptSetL1Pointer(
    _Inout_ KswHvmShadowEptState* shadow,
    _In_ ULONGLONG l1EptPointer
    )
{
    /* Reject an incomplete caller contract before recording anything. */
    if (shadow == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    if (shadow->faulted) { return shadow->lastStatus; }
    /* Refuse to arm composition without a reserved hierarchy. */
    if (shadow->rootVirtual == NULL) {
        shadow->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Return the exact unavailable-reservation failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Reject an EPT pointer whose frame the architecture cannot encode. */
    if ((l1EptPointer & KSW_HVM_NEPT_FRAME_MASK) == 0ULL) {
        shadow->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the exact encoding failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Accessed/dirty is maintained and folded back, not refused.
     *
     * L1 asking for A/D is L1 saying it intends to read those bits back out of
     * its own EPT12 - that is the only thing they are for, and every use of
     * them (live migration, snapshots, copy-on-write) decides which pages to
     * copy from exactly that readback.
     *
     * L2 runs on the composed hierarchy, so the processor sets A/D in *our*
     * shadow leaves.  Leaving it there means L1 reads its own tables back,
     * finds every bit clear, and skips exactly the pages its guest modified -
     * silently, with nothing anywhere reporting it.  So the bits are folded
     * into EPT12 when L2 stops, using the leaf addresses recorded during
     * composition.
     *
     * Two things still have to be true, and both are checked rather than
     * assumed: the processor must be able to maintain the bits at all, and the
     * record table must not overflow.  Either failing turns the feature off
     * and refuses the entry, because half-propagated A/D is worse than none.
     */
    if ((l1EptPointer & KSW_HVM_NEPT_EPTP_ENABLE_AD) != 0ULL) {
        shadow->l1RequestedAccessedDirty = TRUE;
        if (!kswordArkHvmNestedEptProcessorSupportsAccessedDirty()) {
            shadow->accessedDirtyActive = FALSE;
            shadow->lastStatus = STATUS_NOT_SUPPORTED;
            /* Return the exact unsupported-control failure. */
            return STATUS_NOT_SUPPORTED;
        }
        shadow->accessedDirtyActive = TRUE;
    } else {
        shadow->l1RequestedAccessedDirty = FALSE;
        shadow->accessedDirtyActive = FALSE;
    }
    /* Drop every mapping composed against a different EPT12. */
    if (shadow->l1EptPointer != l1EptPointer) {
        kswordArkHvmNestedEptInvalidate(shadow);
        if (shadow->faulted) { return shadow->lastStatus; }
        shadow->outerViewIndex = 0UL;
        KswordArkHvmEptSwProgressReset(&shadow->outerViewProgress);
        shadow->l1EptPointer = l1EptPointer;
    }
    /*
     * Put A/D into the pointer the processor actually loads.
     *
     * The composed pointer is built once at reservation time, before anything
     * knows what L1 will ask for, so this bit can only be decided here.  It is
     * assigned in both directions: a stale set bit from a previous L1 would
     * have the processor maintaining bits nobody is folding back.
     */
    if (shadow->accessedDirtyActive) {
        shadow->composedEptPointer |= KSW_HVM_NEPT_EPTP_ENABLE_AD;
    } else {
        shadow->composedEptPointer &= ~KSW_HVM_NEPT_EPTP_ENABLE_AD;
    }
    shadow->l1PointerValid = TRUE;
    shadow->active = TRUE;
    shadow->lastStatus = STATUS_SUCCESS;
    /* Return the armed composition. */
    return STATUS_SUCCESS;
}

/*
 * Take a private copy of one EPT12 table page, once.
 *
 * Called from the walk, so it runs in VMX root and must map through the
 * per-processor window like everything else here.  A frame already tracked is
 * left alone: the copy has to be of what the hierarchy was *composed from*,
 * and re-snapshotting on a later walk would quietly absorb an edit L1 made in
 * between - which is exactly the edit this exists to catch.
 */
static VOID
kswordArkHvmNestedEptTrackTablePage(
    _Inout_ KswHvmShadowEptState* shadow,
    _Inout_ KswHvmPhysWindow* window,
    _In_ ULONGLONG tableFrame,
    _In_ ULONG level
    )
{
    volatile VOID* mapped = NULL;
    ULONG index = 0UL;

    if (shadow->trackedCopyBlock == NULL || tableFrame == 0ULL) {
        /* Report nothing; the invalidation path treats absent as unknown. */
        return;
    }
    for (index = 0UL; index < shadow->trackedCount; ++index) {
        if (shadow->trackedFrame[index] == tableFrame) {
            /* Aliased table levels cannot share a safe A/D interpretation. */
            if (shadow->trackedLevel[index] != (UCHAR)level) {
                /* Force the conservative invalidation path for this hierarchy. */
                shadow->trackedOverflowCount += 1UL;
            }
            /* Return; the copy that matters is the first one. */
            return;
        }
    }
    if (shadow->trackedCount >= KSW_HVM_NEPT_TRACKED_PAGES) {
        shadow->trackedOverflowCount += 1UL;
        /* Return; the count is what forfeits the right to keep the shadow. */
        return;
    }
    if (kswordArkHvmPhysWindowMap(
            window,
            tableFrame,
            PAGE_SIZE,
            &mapped) != KSW_HVM_PHYS_WINDOW_OK ||
        mapped == NULL) {
        shadow->trackedOverflowCount += 1UL;
        /* Return; an untaken copy is counted the same as no room for one. */
        return;
    }
    RtlCopyMemory(
        (UCHAR*)shadow->trackedCopyBlock +
            ((SIZE_T)shadow->trackedCount * (SIZE_T)PAGE_SIZE),
        (const VOID*)mapped,
        PAGE_SIZE);
    kswordArkHvmPhysWindowUnmap(window);
    shadow->trackedFrame[shadow->trackedCount] = tableFrame;
    /* Keep the architectural level with the exact table snapshot. */
    shadow->trackedLevel[shadow->trackedCount] = (UCHAR)level;
    shadow->trackedCount += 1UL;
}

BOOLEAN
kswordArkHvmNestedEptInvalidateChecked(
    _Inout_ KswHvmShadowEptState* shadow,
    _Inout_ KswHvmPhysWindow* window
    )
{
    ULONG index = 0UL;

    if (shadow == NULL || window == NULL ||
        shadow->rootVirtual == NULL) {
        /* Report that nothing was kept, because nothing was composed. */
        return FALSE;
    }
    /*
     * A hierarchy we could not fully snapshot has to be dropped.
     *
     * Overflow means at least one table page the mappings depend on has no
     * copy, so "unchanged" cannot be established for it.  Keeping the shadow
     * on the strength of the pages we did copy would be asserting something
     * about the ones we did not.
     */
    if (shadow->trackedCopyBlock == NULL ||
        shadow->trackedCount == 0UL ||
        shadow->trackedOverflowCount != 0UL) {
        kswordArkHvmNestedEptInvalidate(shadow);
        shadow->invalidateDroppedCount += 1UL;
        /* Report the drop. */
        return FALSE;
    }
    for (index = 0UL; index < shadow->trackedCount; ++index) {
        volatile VOID* mapped = NULL;
        BOOLEAN same = FALSE;

        if (kswordArkHvmPhysWindowMap(
                window,
                shadow->trackedFrame[index],
                PAGE_SIZE,
                &mapped) != KSW_HVM_PHYS_WINDOW_OK ||
            mapped == NULL) {
            /* A page we cannot re-read is a page we cannot vouch for. */
            kswordArkHvmNestedEptInvalidate(shadow);
            shadow->invalidateDroppedCount += 1UL;
            /* Report the drop. */
            return FALSE;
        }
        /* Hardware A/D sets alone do not change a translation or its rights. */
        same = kswordArkHvmNestedAdCompare(shadow, index,
            (const volatile ULONGLONG*)mapped);
        kswordArkHvmPhysWindowUnmap(window);
        if (!same) {
            kswordArkHvmNestedEptInvalidate(shadow);
            shadow->invalidateDroppedCount += 1UL;
            /* Report the drop; L1 really did edit its tables. */
            return FALSE;
        }
    }
    /*
     * Every mapping field is unchanged, so the composed mappings still say
     * exactly what EPT12 says.  What remains is the processor's own caches,
     * which is the part INVEPT genuinely always means.
     */
    if (shadow->composedEptPointer != 0ULL) {
        if (kswordArkHvmAsmInveptSingle(shadow->composedEptPointer) != 0U) {
            shadow->faulted = TRUE;
            shadow->lastStatus = STATUS_UNSUCCESSFUL;
        }
    }
    shadow->invalidationGeneration = shadow->generation;
    shadow->invalidateKeptCount += 1UL;
    /* Report that the hierarchy was kept. */
    return TRUE;
}

/*
 * Walk EPT12 for one L2 guest physical address.
 *
 * Every level is read through the window because EPT12's tables live at L1
 * physical addresses, which under our identity EPT01 are host physical
 * addresses - readable only through a mapping we create.
 */
static BOOLEAN
kswordArkHvmNestedEptWalkL1(
    _Inout_ KswHvmShadowEptState* shadow,
    _Inout_ KswHvmPhysWindow* window,
    _In_ ULONGLONG guestPhysicalAddress,
    _Out_ ULONGLONG* l1Physical,
    _Out_ ULONGLONG* permissionsArg,
    _Out_opt_ ULONGLONG* l1EntryAddress
    )
{
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG kShifts[4] = { 39UL, 30UL, 21UL, 12UL };
    ULONGLONG table = shadow->l1EptPointer & KSW_HVM_NEPT_FRAME_MASK;
    ULONGLONG permissions = KSW_HVM_NEPT_PERMISSIONS;
    ULONG level = 0UL;

    *l1Physical = 0ULL;
    *permissionsArg = 0ULL;
    if (l1EntryAddress != NULL) { *l1EntryAddress = 0ULL; }
    for (level = 0UL; level < 4UL; ++level) {
        const ULONGLONG kIndex =
            (guestPhysicalAddress >> kShifts[level]) & 0x1FFULL;
        const ULONGLONG kEntryAddress = table + (kIndex << 3);
        ULONGLONG entry = 0ULL;

        /*
         * Copy this table page before reading anything out of it.
         *
         * Before, not after: the copy has to be of the bytes the mapping is
         * about to be composed from, so that a later comparison answers "is
         * the hierarchy still what L1's tables say" rather than "did anything
         * change since some arbitrary moment".
         */
        kswordArkHvmNestedEptTrackTablePage(shadow, window, table, level);
        if (!NT_SUCCESS(kswordArkHvmPhysWindowReadQword(
                window,
                kEntryAddress,
                &entry))) {
            shadow->lastDenySite = 6UL;
            shadow->lastStatus = STATUS_INVALID_ADDRESS;
            /* This is our read failure, not a missing EPT12 mapping. */
            return FALSE;
        }
        /*
         * Remember where the entry that decides this page lives.
         *
         * Only meaningful at the last level, and only known here - after the
         * walk returns, `table` is gone and recovering this address would mean
         * walking EPT12 again, from a VM exit, for every page.
         */
        if (l1EntryAddress != NULL) { *l1EntryAddress = kEntryAddress; }
        /*
         * Accumulate permissions down the walk, never widen them.
         *
         * An interior entry that denies write denies it for everything
         * beneath, so the effective permission is the intersection - taking
         * only the leaf's bits would grant access L1 revoked one level up.
         */
        permissions &= entry;
        /* A wholly unreadable entry terminates the walk with no mapping. */
        if ((entry & KSW_HVM_NEPT_PERMISSIONS) == 0ULL) {
            /*
             * Keep which level stopped and what it read.
             *
             * "The walk found nothing" is not actionable on its own: stopping
             * at the PML4 means L1 has not built this half of the address
             * space at all, stopping at the PT means one page is absent, and
             * an entry that is nonzero but permissionless means L1 deliberately
             * revoked it.  Those are three different defects and one count.
             */
            shadow->lastDenySite = 1UL;
            shadow->lastDenyLevel = level;
            shadow->lastDenyEntry = entry;
            shadow->lastDenyGuestPhysical = guestPhysicalAddress;
            /* Report that EPT12 maps nothing here. */
            return FALSE;
        }
        /* Resolve large leaves at the levels that may terminate a walk. */
        if ((level >= 1UL && level <= 2UL &&
                (entry & KSW_HVM_NEPT_LARGE) != 0ULL) ||
            level == 3UL) {
            const ULONGLONG kOffsetMask =
                (level == 3UL)
                    ? (PAGE_SIZE - 1ULL)
                    : ((1ULL << kShifts[level]) - 1ULL);

            *l1Physical =
                ((entry & KSW_HVM_NEPT_FRAME_MASK) & ~kOffsetMask) |
                (guestPhysicalAddress & kOffsetMask);
            /* Retain EPT12's cache type and ignore-PAT policy as well as RWX. */
            *permissionsArg = (permissions & KSW_HVM_NEPT_PERMISSIONS) |
                (entry & 0x78ULL);
            /* Report a complete EPT12 translation. */
            return TRUE;
        }
        table = entry & KSW_HVM_NEPT_FRAME_MASK;
    }
    /* Report that the walk ran out of levels without a leaf. */
    return FALSE;
}


/* Resolve the selected KSword backing page without assuming identity. */
static BOOLEAN
kswordArkHvmNestedEptReadOuter(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KswHvmShadowEptState* shadow,
    _In_ ULONGLONG l1Physical,
    _Out_ ULONGLONG* leaf,
    _Out_ ULONG* shift
    )
{
    const KswHvmEptswHierarchy* selected = NULL;

    if (!kswordArkHvmEptReadLeaf(runtime, l1Physical, leaf, shift)) {
        return FALSE;
    }
    if (shadow->outerViewIndex == 0UL) { return TRUE; }
    if (!runtime->eptSwitch.active ||
        shadow->outerViewIndex > runtime->eptSwitch.leafCapacity ||
        shadow->outerViewIndex > KSWORD_ARK_HVM_MAX_VIEWS) {
        return FALSE;
    }
    selected = &runtime->eptSwitch.hierarchies[shadow->outerViewIndex - 1UL];
    if (!selected->active) { return FALSE; }
    if (selected->leafPhysical == (l1Physical & KSW_HVM_NEPT_FRAME_MASK)) {
        *leaf = selected->secondaryEntry;
        *shift = 12UL;
    }
    return TRUE;
}

/* Reuse the existing view planner; only this processor's shadow is rebuilt. */
static NTSTATUS
kswordArkHvmNestedEptSwitchOuter(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmShadowEptState* shadow,
    _Inout_ KswHvmPhysWindow* window,
    _In_ ULONGLONG l1Physical,
    _In_ ULONGLONG guestPhysical,
    _In_ ULONGLONG guestRip,
    _In_ ULONG access
    )
{
    ULONG index = 0UL;

    for (index = 0UL; index < KSWORD_ARK_HVM_MAX_VIEWS; ++index) {
        KswHvmEptViewSlot* view = &runtime->eptViews[index];
        ULONG next = 0UL;
        ULONGLONG outerEptp = 0ULL;
        NTSTATUS status;

        if (!view->active ||
            view->physicalAddress != (l1Physical & KSW_HVM_NEPT_FRAME_MASK)) {
            continue;
        }
        /* A nested view requires the backend that does not depend on MTF. */
        if (view->eptSwitchIndex == 0UL) { return STATUS_NOT_SUPPORTED; }
        status = kswordArkHvmEptSwitchPlanViolation(
            runtime, &shadow->outerViewProgress, shadow->outerViewIndex,
            view->eptSwitchIndex - 1UL, access, view->kind,
            guestRip, guestPhysical, &next, &outerEptp);
        if (!NT_SUCCESS(status)) { return status; }
        /* Fold before retiring the mappings. Aliases all change together. */
        (void)kswordArkHvmNestedEptPropagateAccessedDirty(shadow, window);
        kswordArkHvmNestedEptInvalidate(shadow);
        if (shadow->faulted) { return shadow->lastStatus; }
        shadow->outerViewIndex = next;
        InterlockedIncrement64(&view->flipCount);
        /* outerEptp is a planner identity, never a vmcs02 EPT pointer. */
        return STATUS_SUCCESS;
    }
    return STATUS_ACCESS_DENIED;
}

ULONG
kswordArkHvmNestedEptFill(
    _Inout_ struct KswHvmRuntime* runtime,
    _Inout_ KswHvmShadowEptState* shadow,
    _Inout_ KswHvmPhysWindow* window,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access,
    _In_ ULONGLONG guestRip
    )
{
    /* Index shifts for PML4, PDPT, PD and PT in walk order. */
    static const ULONG kShifts[4] = { 39UL, 30UL, 21UL, 12UL };
    ULONGLONG l1Physical = 0ULL;
    ULONGLONG permissions = 0ULL;
    /* Where EPT12's own leaf for this page lives, for folding A/D back. */
    ULONGLONG l1EntryAddress = 0ULL;
    volatile ULONGLONG* table = NULL;
    ULONGLONG hostLeaf = 0ULL;
    ULONGLONG composedLeaf = 0ULL;
    ULONG hostShift = 0UL;
    ULONG composition = 0UL;
    BOOLEAN switched = FALSE;
    ULONG level = 0UL;
    /* Level whose entry holds the leaf: 3 for an ordinary page, higher for a
       large one. Set once the override's granularity is known. */
    ULONG leafTerminationLevel = 3UL;

    /* Refuse composition without an armed hierarchy or a usable window. */
    if (runtime == NULL || shadow == NULL || window == NULL ||
        shadow->faulted ||
        !shadow->active || shadow->rootVirtual == NULL) {
        /* Report that this violation is not ours to satisfy. */
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    shadow->lastStatus = STATUS_SUCCESS;
    shadow->lastDenySite = 0UL;
    if (access == 0UL || (access & ~7UL) != 0UL) {
        shadow->lastStatus = STATUS_INVALID_PARAMETER;
        return KSW_HVM_NEPT_FILL_FAILED;
    }
retryTranslation:
    /* Recheck before filling as a local L2 exit need not revisit its entry builder. */
    if (!kswordArkHvmNestedPageValidateTranslation(runtime, window, shadow->l1EptPointer)) {
        /* A revoked lease must not preserve this CPU's already composed override. */
        kswordArkHvmNestedEptInvalidate(shadow);
        /* Retain backing and propagate an actual local invalidation failure. */
        if (shadow->faulted) { return KSW_HVM_NEPT_FILL_FAILED; }
    }
    /* Translate through L1's own hierarchy first. */
    if (!kswordArkHvmNestedEptWalkL1(
            shadow,
            window,
            guestPhysicalAddress,
            &l1Physical,
            &permissions,
            &l1EntryAddress)) {
        shadow->denyCount += 1UL;
        return shadow->lastDenySite == 1UL
            ? KSW_HVM_NEPT_FILL_L1_DENIED : KSW_HVM_NEPT_FILL_FAILED;
    }
    /*
     * Refuse when EPT12 grants less than the access needs.
     *
     * This is the violation L1 installed its EPT to receive, so it must reach
     * L1 rather than be satisfied here.  Composing a leaf that permits it
     * would silently defeat whatever L1 was protecting.
     */
    if ((access & KSW_HVM_NEPT_PERMISSIONS) != 0UL &&
        ((ULONGLONG)access & permissions) !=
            ((ULONGLONG)access & KSW_HVM_NEPT_PERMISSIONS)) {
        shadow->denyCount += 1UL;
        shadow->lastDenySite = 2UL;
        shadow->lastDenyAccess = access;
        shadow->lastDenyPermissions = permissions;
        shadow->lastDenyGuestPhysical = guestPhysicalAddress;
        /* Report the violation as L1's to handle. */
        return KSW_HVM_NEPT_FILL_L1_DENIED;
    }
    if (!kswordArkHvmNestedEptReadOuter(
            runtime, shadow, l1Physical, &hostLeaf, &hostShift)) {
        shadow->lastDenySite = 3UL;
        shadow->lastStatus = STATUS_INVALID_ADDRESS;
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    composition = KswordArkHvmNestedEptComposeLeaf(
        l1Physical, permissions, hostLeaf, hostShift, access, &composedLeaf);
    if (composition == KSWORD_ARK_HVM_NEPT_COMPOSE_OUTER_DENIED && !switched) {
        shadow->lastStatus = kswordArkHvmNestedEptSwitchOuter(
            runtime, shadow, window, l1Physical, guestPhysicalAddress,
            guestRip, access);
        if (NT_SUCCESS(shadow->lastStatus)) {
            switched = TRUE;
            /* Invalidation retired EPT12 snapshots too; take them again. */
            goto retryTranslation;
        }
    }
    if (composition != KSWORD_ARK_HVM_NEPT_COMPOSE_OK) {
        shadow->denyCount += 1UL;
        shadow->lastDenySite = 3UL;
        shadow->lastDenyAccess = access;
        shadow->lastDenyPermissions = permissions & hostLeaf & 7ULL;
        shadow->lastDenyGuestPhysical = guestPhysicalAddress;
        shadow->lastDenyEntry = hostLeaf;
        if (NT_SUCCESS(shadow->lastStatus)) {
            shadow->lastStatus = STATUS_NOT_SUPPORTED;
        }
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    composedLeaf = kswordArkHvmNestedPageLeaf(
        runtime, shadow, guestPhysicalAddress, composedLeaf, TRUE);
    /*
     * Decide the granularity before descending, because it decides how far.
     *
     * A 2-MiB leaf lives in the PD and a 1-GiB leaf in the PDPT, so the walk
     * that builds interior tables has to stop one or two levels earlier. The
     * shifts array is indexed by level, so the level that terminates the walk is
     * the index whose shift equals the plan's granularity.
     */
    {
        ULONGLONG largeLeaf = 0ULL;
        const ULONG kLeafShift = kswordArkHvmNestedPageLargeLeaf(
            runtime, shadow, guestPhysicalAddress, composedLeaf, &largeLeaf);

        if (kLeafShift > KSW_PLAN_SHIFT_4K) {
            /* PDPT for 1 GiB, PD for 2 MiB; both are inside the interior walk. */
            const ULONG kLeafLevel = (kLeafShift == KSW_PLAN_SHIFT_1G) ? 1UL : 2UL;

            composedLeaf = largeLeaf;
            leafTerminationLevel = kLeafLevel;
        }
    }
    /* Build the shadow path down to the leaf's own level. */
    table = (volatile ULONGLONG*)shadow->rootVirtual;
    for (level = 0UL; level < leafTerminationLevel; ++level) {
        const ULONGLONG kIndex =
            (guestPhysicalAddress >> kShifts[level]) & 0x1FFULL;
        ULONGLONG entry = table[kIndex];

        if ((entry & KSW_HVM_NEPT_PERMISSIONS) == 0ULL) {
            ULONGLONG childPhysical = 0ULL;
            PVOID child = kswordArkHvmNestedEptTakePage(
                shadow,
                &childPhysical);

            /* Report exhaustion as a refusal, never as a crash. */
            if (child == NULL) {
                shadow->exhaustionCount += 1UL;
                shadow->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
                shadow->lastDenySite = 4UL;
                shadow->lastDenyLevel = level;
                shadow->lastDenyGuestPhysical = guestPhysicalAddress;
                /* Report that no mapping could be composed. */
                return KSW_HVM_NEPT_FILL_FAILED;
            }
            /*
             * Interior entries carry full permissions.
             *
             * The leaf is where the intersection is expressed; narrowing an
             * interior entry would apply it to every page under that entry,
             * including ones composed later from different EPT12 leaves.
             */
            entry = (childPhysical & KSW_HVM_NEPT_FRAME_MASK) |
                KSW_HVM_NEPT_PERMISSIONS;
            table[kIndex] = entry;
        }
        table = kswordArkHvmNestedEptPageVirtual(shadow, entry);
        /* Refuse when an interior entry names a page we did not hand out. */
        if (table == NULL) {
            shadow->lastStatus = STATUS_DATA_ERROR;
            shadow->lastDenySite = 5UL;
            shadow->lastDenyLevel = level;
            shadow->lastDenyEntry = entry;
            shadow->lastDenyGuestPhysical = guestPhysicalAddress;
            /* Report that the hierarchy could not be navigated. */
            return KSW_HVM_NEPT_FILL_FAILED;
        }
    }
    {
        const ULONGLONG kLeaf = composedLeaf;
        /* Index at the level the walk stopped on, not always the PT. */
        const ULONGLONG kLeafIndex =
            (guestPhysicalAddress >> kShifts[leafTerminationLevel]) & 0x1FFULL;

        /*
         * Writing a leaf here may replace an interior entry that still names a
         * table page filled by earlier 4-KiB faults in the same region. Those
         * pages are not returned to the block: the block is reclaimed whole on
         * release, and returning one would require proving no processor still
         * holds a cached translation through it. Leaking a table page until
         * release is bounded; freeing one early is not.
         */
        table[kLeafIndex] = kLeaf;
        /*
         * Read the assignment back.  One load, and it separates "we composed
         * the wrong mapping" from "we composed the right one somewhere else" -
         * two failures that look identical from every counter downstream.
         */
        if (table[kLeafIndex] != kLeaf) {
            shadow->leafWriteMismatchCount += 1UL;
        }
    }
    /*
     * Every so often, re-ask EPT12 about a mapping composed earlier.
     *
     * The address verified is the one held back from the previous sample, not
     * this one: a leaf checked against the walk that just produced it proves
     * only that the assignment worked, which the read-back above already says.
     * What matters is whether a mapping that has been in use still agrees with
     * L1's tables.  See the field comment for why this is the one failure that
     * leaves no exit behind.
     */
    /*
     * Ride the same sampling tick for the region recheck.
     *
     * One EPT12 walk per 4096 fills, against a lease that is otherwise rechecked
     * only where it was captured. Sharing the tick keeps the exit path's cost
     * unchanged in shape: it was already doing a walk here every 4096 fills.
     */
    if ((shadow->fillCount & 0xFFFUL) == 0UL) {
        kswordArkHvmNestedPageSampleRegion(runtime, window);
    }
    if ((shadow->fillCount & 0xFFFUL) == 0UL) {
        const ULONGLONG kPending = shadow->verifyPendingGuestPhysical;

        if (kPending != 0ULL &&
            shadow->verifyPendingGeneration != shadow->generation) {
            /*
             * The hierarchy was dropped and rebuilt since this address was
             * held back, so the leaf now present was composed from a different
             * EPT12.  Comparing it proves nothing either way.
             */
            shadow->verifySkippedGenerationCount += 1UL;
        } else if (kPending != 0ULL) {
            volatile ULONGLONG* verifyTable =
                (volatile ULONGLONG*)shadow->rootVirtual;
            ULONG verifyLevel = 0UL;
            /* Set when the walk ends on a large leaf above the PT level. */
            BOOLEAN verifyLarge = FALSE;

            shadow->verifySampleCount += 1UL;
            for (verifyLevel = 0UL; verifyLevel < 3UL; ++verifyLevel) {
                const ULONGLONG kEntry =
                    verifyTable[(kPending >> kShifts[verifyLevel]) & 0x1FFULL];

                if ((kEntry & KSW_HVM_NEPT_PERMISSIONS) == 0ULL) {
                    verifyTable = NULL;
                    break;
                }
                /*
                 * A large leaf terminates this walk; it is not an interior
                 * entry and its frame is replacement backing, not a table page
                 * we handed out. Resolving it as a table returns NULL and would
                 * be charged as "the hierarchy could not be navigated" - a
                 * correct mapping counted as an unexplained failure, on every
                 * sample, for as long as the region stays published.
                 */
                if (verifyLevel >= 1UL &&
                    (kEntry & KSW_HVM_NEPT_LARGE) != 0ULL) {
                    verifyLarge = TRUE;
                    break;
                }
                verifyTable =
                    kswordArkHvmNestedEptPageVirtual(shadow, kEntry);
                if (verifyTable == NULL) { break; }
            }
            if (verifyTable == NULL) {
                /* Dropped by an invalidation: correct, not a mismatch. */
                shadow->verifyUnresolvedCount += 1UL;
            } else {
                ULONGLONG freshPhysical = 0ULL;
                ULONGLONG freshPermissions = 0ULL;
                /* The leaf lives at whichever level terminated the walk. */
                const ULONGLONG kShadowLeaf = verifyTable[
                    (kPending >> kShifts[verifyLarge ? verifyLevel : 3UL]) & 0x1FFULL];

                if (!kswordArkHvmNestedEptWalkL1(
                        shadow,
                        window,
                        kPending,
                        &freshPhysical,
                        &freshPermissions,
                        NULL)) {
                    shadow->verifyUnresolvedCount += 1UL;
                } else if (!kswordArkHvmNestedEptReadOuter(
                               runtime, shadow, freshPhysical, &hostLeaf, &hostShift)) {
                    shadow->verifyUnresolvedCount += 1UL;
                } else {
                    const ULONGLONG kComposed = hostLeaf |
                        (freshPhysical & ((1ULL << hostShift) - 1ULL) &
                         KSW_HVM_NEPT_FRAME_MASK);
                    ULONGLONG expectedLarge = 0ULL;
                    /*
                     * Expect what the fill path would install today, at the same
                     * granularity. A large leaf carries the region base while the
                     * per-page frame carries an offset, so comparing a published
                     * 2-MiB leaf against the 4-KiB answer would report a mismatch
                     * on every sample of a region that is in fact correct.
                     */
                    const ULONG kExpectedShift = kswordArkHvmNestedPageLargeLeaf(
                        runtime, shadow, kPending, kComposed, &expectedLarge);
                    const ULONGLONG kExpectedFrame =
                        (kExpectedShift > KSW_PLAN_SHIFT_4K)
                            ? (expectedLarge & KSW_HVM_NEPT_FRAME_MASK)
                            : (kswordArkHvmNestedPageLeaf(runtime, shadow, kPending,
                                   kComposed, FALSE) & KSW_HVM_NEPT_FRAME_MASK);

                    if ((kShadowLeaf & KSW_HVM_NEPT_FRAME_MASK) != kExpectedFrame) {
                        /*
                         * Recorded only on a mismatch.  Recording every sample
                         * overwrites the one case worth looking at with the
                         * ordinary one that follows it - measured: the counter
                         * said three mismatches while the retained scene showed a
                         * matching pair.
                         */
                        shadow->verifyLastGuestPhysical = kPending;
                        shadow->verifyLastShadowFrame =
                            kShadowLeaf & KSW_HVM_NEPT_FRAME_MASK;
                        shadow->verifyLastL1Frame =
                            (hostLeaf & KSW_HVM_NEPT_FRAME_MASK) |
                            (freshPhysical & ((1ULL << hostShift) - 1ULL) &
                             KSW_HVM_NEPT_FRAME_MASK);
                        shadow->verifyMismatchCount += 1UL;
                    }
                }
            }
        }
        shadow->verifyPendingGuestPhysical =
            guestPhysicalAddress & KSW_HVM_NEPT_FRAME_MASK;
        shadow->verifyPendingGeneration = shadow->generation;
    }
    /* Retain every source until its writable A/D state has been published. */
    if (shadow->accessedDirtyActive && !kswordArkHvmNestedAdRecord(shadow,
            &table[(guestPhysicalAddress >> kShifts[3]) & 0x1FFULL], l1EntryAddress)) {
        /* An untracked translation must never run with advertised A/D support. */
        shadow->faulted = TRUE;
        /* Return a local resource failure rather than a fictitious L1 fault. */
        shadow->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        /* Stop L2 before using the untracked leaf. */
        return KSW_HVM_NEPT_FILL_FAILED;
    }
    shadow->fillCount += 1UL;
    shadow->lastStatus = STATUS_SUCCESS;
    /* Report that the faulting access may now be retried. */
    return KSW_HVM_NEPT_FILL_RESOLVED;
}

#else

VOID KswordARKHvmNestedPageResetLocked(KSW_HVM_RUNTIME* Runtime)
{
    UNREFERENCED_PARAMETER(Runtime);
}

NTSTATUS KswordARKHvmNestedPageControl(
    const KSWORD_ARK_HVM_NESTED_PAGE_REQUEST* Request,
    KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE* Response)
{
    UNREFERENCED_PARAMETER(Request);
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_NESTED_PAGE_VERSION;
    Response->size = sizeof(*Response);
    Response->status = 1UL;
    Response->lastStatus = (ULONG)STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmNestedEptInitialize(
    _Out_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L0EptPointer
    )
{
    UNREFERENCED_PARAMETER(L0EptPointer);
    /* Zero the record so no caller reads uninitialized shadow state. */
    if (Shadow != NULL) {
        RtlZeroMemory(Shadow, sizeof(*Shadow));
    }
}

NTSTATUS
KswordARKHvmNestedEptPrepare(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    UNREFERENCED_PARAMETER(Shadow);
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

VOID
KswordARKHvmNestedEptRelease(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    UNREFERENCED_PARAMETER(Shadow);
}

NTSTATUS
KswordARKHvmNestedEptSetL1Pointer(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _In_ ULONGLONG L1EptPointer
    )
{
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(L1EptPointer);
    /* Return the explicit unsupported-architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

VOID
KswordARKHvmNestedEptInvalidate(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow
    )
{
    UNREFERENCED_PARAMETER(Shadow);
}

BOOLEAN
KswordARKHvmNestedEptInvalidateChecked(
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window
    )
{
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(Window);
    /* Report the explicit unsupported-architecture boundary as "not kept". */
    return FALSE;
}

ULONG
KswordARKHvmNestedEptFill(
    _Inout_ struct _KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_SHADOW_EPT_STATE* Shadow,
    _Inout_ KSW_HVM_PHYS_WINDOW* Window,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ ULONGLONG GuestRip
    )
{
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Shadow);
    UNREFERENCED_PARAMETER(Window);
    UNREFERENCED_PARAMETER(GuestPhysicalAddress);
    UNREFERENCED_PARAMETER(Access);
    UNREFERENCED_PARAMETER(GuestRip);
    /* Report that no mapping could be composed. */
    return KSW_HVM_NEPT_FILL_FAILED;
}

#endif

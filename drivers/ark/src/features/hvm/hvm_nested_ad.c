/* Lossless per-CPU EPT A/D propagation with no allocation in a VM exit. */
#include "hvm_nested_ept.h"
#include "hvm_nested_ad_compare.h"
#include "../../platform/pool_compat.h"

/* Keep allocation accounting separate from the page-table pool tag. */
#define KSW_HVM_AD_TAG 'AdHK'
/* Architectural A/D bits in an EPT entry. */
#define KSW_HVM_AD_BITS 0x300ULL

NTSTATUS kswordArkHvmNestedAdPrepare(KswHvmShadowEptState* shadow)
{
    /* Allocate entries and a dense pending-index array in one owned block. */
    const SIZE_T kEntries = (SIZE_T)KSW_HVM_NEPT_AD_RECORDS * sizeof(*shadow->adEntries);
    /* Reserve enough pending indices for every possible shadow leaf. */
    const SIZE_T kBytes = kEntries + (SIZE_T)KSW_HVM_NEPT_AD_RECORDS * sizeof(ULONG);
    /* Preserve an existing reservation. */
    if (shadow->adEntries != NULL) { return STATUS_SUCCESS; }
    /* Only called while preparing resources, before any VMX-root entry. */
    shadow->adEntries = (KswHvmNeptAdEntry*)kswordArkAllocateNonPagedPool(kBytes, KSW_HVM_AD_TAG);
    /* Refuse advertising A/D without its backing ledger. */
    if (shadow->adEntries == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Every slot begins absent and belongs to generation zero. */
    RtlZeroMemory(shadow->adEntries, kBytes);
    /* ULONG indices follow the naturally aligned entry array. */
    shadow->adPendingSlots = (ULONG*)((UCHAR*)shadow->adEntries + kEntries);
    /* No shadow leaf has been composed yet. */
    shadow->adRecordCount = 0UL;
    /* Report a complete reservation. */
    return STATUS_SUCCESS;
}

VOID kswordArkHvmNestedAdRelease(KswHvmShadowEptState* shadow)
{
    /* Cleanup is also valid after a partial preparation failure. */
    if (shadow->adEntries != NULL) {
        /* All CPUs have stopped using this owned allocation. */
        ExFreePool(shadow->adEntries);
        /* Do not retain a dangling allocation pointer. */
        shadow->adEntries = NULL;
    }
    /* The pending array is an interior pointer into the same allocation. */
    shadow->adPendingSlots = NULL;
    /* No pending indices remain valid after release. */
    shadow->adRecordCount = 0UL;
}

BOOLEAN kswordArkHvmNestedAdRecord(KswHvmShadowEptState* shadow,
    volatile ULONGLONG* leaf, ULONGLONG l1EntryAddress)
{
    /* All leaf pointers must refer into this CPU's reserved table block. */
    const ULONG_PTR kOffset = (ULONG_PTR)leaf - (ULONG_PTR)shadow->pageBlock;
    /* Division is exact after the alignment check below. */
    const SIZE_T kSlot = kOffset / sizeof(ULONGLONG);
    /* Select a slot only after validating its allocation and address. */
    KswHvmNeptAdEntry* entry = NULL;
    /* Reject invalid addresses rather than silently losing dirty tracking. */
    if (shadow->adEntries == NULL || (kOffset & 7UL) != 0UL ||
        kSlot >= KSW_HVM_NEPT_AD_RECORDS || (l1EntryAddress & 7ULL) != 0ULL ||
        l1EntryAddress == 0ULL) {
        /* Make every contract failure observable. */
        shadow->adOverflowCount += 1UL;
        /* The caller must refuse entry with an untracked leaf. */
        return FALSE;
    }
    /* A leaf index directly selects its source metadata. */
    entry = &shadow->adEntries[kSlot];
    /* A new generation or a completed leaf needs one pending index. */
    if (entry->generation != shadow->generation || entry->pending == 0U) {
        /* One index per leaf makes overflow impossible without a defect. */
        if (shadow->adRecordCount >= KSW_HVM_NEPT_AD_RECORDS) {
            /* Count rather than discard an older pending dirty observation. */
            shadow->adOverflowCount += 1UL;
            /* Refuse the new mapping. */
            return FALSE;
        }
        /* Append this unique shadow-leaf slot. */
        shadow->adPendingSlots[shadow->adRecordCount++] = (ULONG)kSlot;
    }
    /* Bind the slot to its current hierarchy generation. */
    entry->generation = shadow->generation;
    /* Retain only an L1 physical address, never a temporary window mapping. */
    entry->l1EntryAddress = l1EntryAddress;
    /* A refilled leaf starts a fresh hardware observation. */
    entry->publishedBits = 0U;
    /* The slot must remain until future writes can no longer add a bit. */
    entry->pending = 1U;
    /* Report that every future dirty bit has a destination. */
    return TRUE;
}

/* Update only our own A/D changes in the snapshot, preserving mapping edits. */
static VOID kswordHvmAdUpdateCopy(KswHvmShadowEptState* shadow,
    ULONGLONG address, ULONGLONG bits)
{
    /* Find the snapshot of the source table, never a shadow table. */
    ULONG index = 0UL;
    /* Bound the search by the pages actually recorded. */
    for (index = 0UL; index < shadow->trackedCount; ++index) {
        /* A source entry belongs to exactly one physical table page. */
        if (shadow->trackedFrame[index] == (address & ~0xFFFULL)) {
            /* Compute the aligned entry in our private snapshot. */
            ULONGLONG* copy = (ULONGLONG*)((UCHAR*)shadow->trackedCopyBlock +
                (SIZE_T)index * PAGE_SIZE + (SIZE_T)(address & 0xFFFULL));
            /* Preserve all original address and permission fields. */
            *copy |= bits;
            /* Do not accidentally absorb an unrelated L1 table edit. */
            return;
        }
    }
}

ULONG kswordArkHvmNestedEptPropagateAccessedDirty(
    KswHvmShadowEptState* shadow, KswHvmPhysWindow* window)
{
    /* Walk only entries with a bit still capable of changing. */
    ULONG pending = 0UL;
    /* Count physical source entries actually changed by this call. */
    ULONG updated = 0UL;
    /* Nothing needs propagation when A/D is not in use. */
    if (shadow == NULL || window == NULL || !shadow->accessedDirtyActive ||
        shadow->adEntries == NULL || shadow->pageBlock == NULL) { return 0UL; }
    /* A dense pending list avoids an O(all reserved entries) scan. */
    while (pending < shadow->adRecordCount) {
        /* Every index was range-checked by the record publisher. */
        const ULONG kSlot = shadow->adPendingSlots[pending];
        /* Read the hardware-maintained leaf directly, without four page walks. */
        const ULONGLONG kLeaf = ((volatile ULONGLONG*)shadow->pageBlock)[kSlot];
        /* Source metadata remains valid for this shadow generation. */
        KswHvmNeptAdEntry* entry = &shadow->adEntries[kSlot];
        /* Only two hardware bits can be published. */
        const ULONGLONG kBits = kLeaf & KSW_HVM_AD_BITS;
        /* Skip physical mappings when no newly set bit exists. */
        if ((kBits & ~((ULONGLONG)entry->publishedBits << 8)) != 0ULL) {
            /* A temporary mapping never survives this propagation call. */
            volatile VOID* mapped = NULL;
            /* An inaccessible source retains its pending record for retry. */
            if (kswordArkHvmPhysWindowMap(window, entry->l1EntryAddress,
                    sizeof(ULONGLONG), &mapped) == KSW_HVM_PHYS_WINDOW_OK && mapped != NULL) {
                /* Atomic OR cannot lose another CPU's mapping or A/D update. */
                const ULONGLONG kPrior = (ULONGLONG)InterlockedOr64(
                    (volatile LONG64*)mapped, (LONG64)kBits);
                /* Restore the physical window before touching other mappings. */
                kswordArkHvmPhysWindowUnmap(window);
                /* Count real source-bit changes, not already-published bits. */
                if ((kPrior & kBits) != kBits) { updated += 1UL; }
                /* Remember the set bits so L1 clearing them remains detectable. */
                kswordHvmAdUpdateCopy(shadow, entry->l1EntryAddress, kBits);
                /* This shadow leaf no longer needs another OR of those bits. */
                entry->publishedBits |= (UCHAR)(kBits >> 8);
            }
        }
        /* A read-only leaf cannot later become dirty without another refill. */
        if (entry->publishedBits == 3U ||
            (entry->publishedBits == 1U && (kLeaf & 2ULL) == 0ULL)) {
            /* Mark completion before compacting its index out of the list. */
            entry->pending = 0U;
            /* Remove in O(1), retaining the last pending entry for this index. */
            shadow->adRecordCount -= 1UL;
            /* The replacement index is processed on the next loop iteration. */
            shadow->adPendingSlots[pending] = shadow->adPendingSlots[shadow->adRecordCount];
        } else {
            /* Writable A-only leaves remain observable for a future write. */
            pending += 1UL;
        }
    }
    /* Keep a cumulative count for runtime evidence. */
    shadow->adPropagatedCount += updated;
    /* Report real source updates to the caller. */
    return updated;
}

BOOLEAN kswordArkHvmNestedAdCompare(KswHvmShadowEptState* shadow,
    ULONG trackedIndex, const volatile ULONGLONG* current)
{
    /* Point at the exact snapshot that produced the cached mappings. */
    ULONGLONG* copy = (ULONGLONG*)((UCHAR*)shadow->trackedCopyBlock +
        (SIZE_T)trackedIndex * PAGE_SIZE);
    /* Inspect every entry in the tracked table. */
    ULONG index = 0UL;
    /* Entry loads are aligned and naturally atomic on the supported x64 host. */
    for (index = 0UL; index < 512UL; ++index) {
        /* Read once so comparison and snapshot advancement use the same value. */
        const ULONGLONG kNow = current[index];
        /* Any changed mapping, reserved bit, or A/D clear requires a rebuild. */
        if (!kswordHvmEptEntryKeepsTranslation(copy[index], kNow,
                shadow->trackedLevel[trackedIndex], shadow->l1RequestedAccessedDirty)) {
            /* The caller immediately discards this whole snapshot generation. */
            return FALSE;
        }
        /* Accept only monotonic A/D progress; later clears must be observable. */
        copy[index] = kNow;
    }
    /* No translation or observation epoch changed in this table. */
    return TRUE;
}

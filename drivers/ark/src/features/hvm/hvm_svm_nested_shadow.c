/* Preallocated AMD NPT02 construction; all paths are bounded and nonblocking. */
#include "hvm_svm_nested_shadow.h"

/* Clear one owned hardware page without calling an allocator or memory manager. */
static void kswNshadowClear(KswSvmU64* words)
{
    /* Every page contains exactly 512 architectural entries. */
    unsigned int slot;
    /* The owning CPU is outside its nested guest during every update. */
    for (slot = 0; slot < 512U; ++slot) { words[slot] = 0; }
}

/* Locate child pages through the allocation ledger, never by mapping guest pointers. */
static unsigned int kswNshadowFind(const KswNshadow* shadow, KswSvmU64 physical)
{
    /* Search has an explicit maximum of 256 prepared pages. */
    unsigned int page;
    /* Root is never a valid child of another table. */
    for (page = 1; page < shadow->used; ++page) {
        /* Hardware addresses were validated at prepare time. */
        if (shadow->pages[page].physical == physical) { return page; }
    }
    /* An entry outside the owned ledger indicates corruption. */
    return shadow->capacity;
}

/* Validate the entire pool before clearing or publishing any page. */
unsigned int kswSvmNestedShadowInitialize(KswNshadow* shadow,
    KswNshadowPage* pages, unsigned int count, unsigned int physicalBits)
{
    /* Bound physical addresses before any shifts or parent publication. */
    KswSvmU64 mask = kswNptAddressMask(physicalBits);
    /* Duplicate mappings would make per-level ownership ambiguous. */
    unsigned int page, previous;
    /* Only an empty software owner may acquire a pool. */
    if (!shadow || shadow->pages || !pages || !mask || !count || count > KSW_NSHADOW_MAX_PAGES) {
        /* Reject without altering caller-owned state. */
        return KSW_NSHADOW_INVALID;
    }
    /* Verify all resource descriptors before the first page write. */
    for (page = 0; page < count; ++page) {
        /* Zero physical frame is refused for the host-owned table pool. */
        if (!pages[page].words || ((size_t)pages[page].words & 4095U) ||
            !pages[page].physical || (pages[page].physical & ~mask)) { return KSW_NSHADOW_INVALID; }
        /* Distinct virtual mappings of one physical page are not distinct resources. */
        for (previous = 0; previous < page; ++previous) {
            /* Check both identities to avoid accidentally aliasing live tables. */
            if (pages[page].physical == pages[previous].physical ||
                pages[page].words == pages[previous].words) { return KSW_NSHADOW_INVALID; }
        }
    }
    /* Publish the verified ledger while no CPU can execute this root. */
    shadow->pages = pages;
    /* Preserve the hard preparation budget. */
    shadow->capacity = count;
    /* Initially only the empty root belongs to the hardware tree. */
    shadow->used = 1;
    /* Bind the first translation resolution to epoch one. */
    shadow->epoch = 1;
    /* Preserve the exact PA mask used for every later entry. */
    shadow->addressMask = mask;
    /* First use must not inherit translations from an earlier ASID owner. */
    shadow->flushPending = 1;
    /* No guest entry may observe allocator residue. */
    kswNshadowClear(pages[0].words);
    /* Unused child pages are cleared just before they are linked. */
    return KSW_NSHADOW_OK;
}

/* Reset is a software invalidation only; it is not a substitute for TLB_CONTROL. */
unsigned int kswSvmNestedShadowReset(KswNshadow* shadow)
{
    /* Epoch wrap cannot make an ancient candidate look current. */
    if (!shadow || !shadow->pages || !shadow->used || shadow->epoch == ~0ULL) { return KSW_NSHADOW_INVALID; }
    /* Clearing the root disconnects every old child before the pool is reused. */
    kswNshadowClear(shadow->pages[0].words);
    /* Future child allocations clear their pages again before publication. */
    shadow->used = 1;
    /* Invalidate all previously resolved candidates. */
    ++shadow->epoch;
    /* The owner must issue a real hardware flush before using this root again. */
    shadow->flushPending = 1;
    /* Resource ownership remains unchanged. */
    return KSW_NSHADOW_OK;
}

/* Install one 4-KiB leaf, splitting large source mappings in the resolver. */
unsigned int kswSvmNestedShadowInstall(KswNshadow* shadow, const KswNmmuResult* result)
{
    /* Retain at most the four indices needed by this bounded walk. */
    unsigned int indices[4];
    /* Track existing parent pages before making any edits. */
    unsigned int page = 0, level, missing = 3;
    /* Allowed leaf bits: frame, P/RW/US, cache, A/D and NX; no Intel EPT attributes. */
    KswSvmU64 allowed;
    /* Refuse malformed owners before indexing their resource ledger. */
    if (!shadow || !result || !shadow->pages || !shadow->used ||
        shadow->used > shadow->capacity || shadow->capacity > KSW_NSHADOW_MAX_PAGES) { return KSW_NSHADOW_INVALID; }
    /* Zero/default result buffers are never valid mappings. */
    if (result->status != KSW_NNPT_OK || !result->leaf || !result->inner.complete || !result->outer.complete) {
        /* The caller must resolve and commit both source paths first. */
        return KSW_NSHADOW_INVALID;
    }
    /* Reject stale translations even if their physical frames happen to match. */
    if (result->epoch != shadow->epoch) { return KSW_NSHADOW_STALE; }
    /* Keep the candidate bound to both committed source translations. */
    if (result->gpa != result->inner.inputAddress || result->inner.address != result->outer.inputAddress ||
        (result->leaf & shadow->addressMask) != (result->outer.address & shadow->addressMask) ||
        (result->leaf & 7ULL & ~(result->inner.permissions & result->outer.permissions)) ||
        ((result->inner.permissions | result->outer.permissions) & KSW_NNPT_NX & ~result->leaf)) {
        /* Refuse mixed evidence even when its epoch is numerically current. */
        return KSW_NSHADOW_INVALID;
    }
    /* Allow bit 7 as 4-KiB PAT, not as a large-page flag. */
    allowed = shadow->addressMask | 0xffULL | KSW_NNPT_NX;
    /* Physical/GPA width, user permission and committed A bit are required. */
    if ((result->leaf & ~allowed) || (result->gpa & ~(shadow->addressMask | 4095ULL)) ||
        (result->leaf & 0x25ULL) != 0x25ULL ||
        ((result->leaf & 2ULL) && !(result->leaf & 0x40ULL))) { return KSW_NSHADOW_INVALID; }
    /* Compute each index from the original L2 GPA, never from the final host PA. */
    for (level = 0; level < 4; ++level) { indices[level] = (unsigned int)((result->gpa >> (39U - 9U * level)) & 511ULL); }
    /* Inspect existing tables without mutating on budget/corruption failure. */
    for (level = 0; level < 3; ++level) {
        /* Read a host-owned parent entry, not a guest-controlled table. */
        KswSvmU64 entry = shadow->pages[page].words[indices[level]];
        /* A zero slot needs a new suffix of intermediate tables. */
        if (!entry) { missing = level; break; }
        /* Only exact permissive nonleaf entries, plus hardware A, are owned here. */
        if ((entry & ~shadow->addressMask & ~0x20ULL) != 7ULL) { return KSW_NSHADOW_INVALID; }
        /* A hardware pointer must resolve through our prepared ownership ledger. */
        {
            /* Parents are allocated before children, so a backward edge is corruption. */
            unsigned int child = kswNshadowFind(shadow, entry & shadow->addressMask);
            /* This also rejects cycles and a table pointing at itself. */
            if (child <= page || child == shadow->capacity) { return KSW_NSHADOW_INVALID; }
            /* Follow only a forward edge in the allocation ledger. */
            page = child;
        }
        /* Never follow a forged pointer outside the pool. */
        if (page == shadow->capacity) { return KSW_NSHADOW_INVALID; }
    }
    /* Refuse before clearing/linking anything when the entire suffix cannot fit. */
    if (3U - missing > shadow->capacity - shadow->used) { return KSW_NSHADOW_FULL; }
    /* Add at most three pages, all of which were preallocated and validated. */
    for (level = missing; level < 3; ++level) {
        /* Acquire the next unused page from the local ledger. */
        unsigned int child = shadow->used++;
        /* Eliminate stale leaf entries before making this page reachable. */
        kswNshadowClear(shadow->pages[child].words);
        /* The owner is outside VMRUN; publication completes before the next entry. */
        shadow->pages[page].words[indices[level]] = shadow->pages[child].physical | 7ULL;
        /* Continue down the newly constructed suffix. */
        page = child;
    }
    /* Commit a fully resolved leaf only after all parents are present. */
    shadow->pages[page].words[indices[3]] = result->leaf;
    /* All installs, including permission reductions/replacements, require a flush. */
    shadow->flushPending = 1;
    /* No source A/D work or memory allocation remains in this installation. */
    return KSW_NSHADOW_OK;
}

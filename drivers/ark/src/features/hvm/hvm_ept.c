/*++

Module Name:

    hvm_ept.c

Abstract:

    Implements bounded EPT large-leaf splitting, permission rules, and
    monitor-trap restoration without allocation in the VM-exit path.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_ept.h"
#include "hvm_resident.h"
/* The first-access watch does not include diagnostic aspects; it shares the same implementation as offline tests. */
#include "../../../../../shared/driver/KswordArkHvmWatch.h"

/*
 * The bit layout must be bitwise consistent with the shared header; otherwise, offline tests validate a different arithmetic.
 *
 * Pin to compile time rather than relying on convention: these two sets of constants belong to three header files (protocol, driver internals,
 * shared pure modules). If either side changes a bit, no compile error occurs; instead, tests and the kernel will calculate independently.
 */
C_ASSERT(KSW_HVM_WATCH_ACCESS_READ == KSWORD_ARK_HVM_EPT_ACCESS_READ);
C_ASSERT(KSW_HVM_WATCH_ACCESS_WRITE == KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
C_ASSERT(KSW_HVM_WATCH_ACCESS_EXECUTE == KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
C_ASSERT(KSW_HVM_WATCH_LEAF_READ == KSW_EPT_READ);
C_ASSERT(KSW_HVM_WATCH_LEAF_WRITE == KSW_EPT_WRITE);
C_ASSERT(KSW_HVM_WATCH_LEAF_EXECUTE == KSW_EPT_EXECUTE);
C_ASSERT(KSW_HVM_WATCH_STATE_ARMED == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
C_ASSERT(KSW_HVM_WATCH_STATE_TRIGGERED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED);
C_ASSERT(KSW_HVM_WATCH_STATE_DISARMED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED);
C_ASSERT(KSW_HVM_WATCH_STATE_INVALIDATED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED);
C_ASSERT(KSW_HVM_WATCH_STATE_FAULTED ==
    KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED);

/* Return the active split that owns one two-MiB physical range. */
static KswHvmEptSplit*
kswordArkHvmEptFindSplit(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalBase
    )
{
    ULONG index = 0UL;

    /* Search the bounded split ledger without allocation. */
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_SPLITS;
         ++index) {
        /* Match only active records with the exact aligned base. */
        if (runtime->eptSplits[index].active &&
            runtime->eptSplits[index].physicalBase ==
                physicalBase) {
            /* Return the exact active split record. */
            return &runtime->eptSplits[index];
        }
    }
    /* Report that no existing four-KiB table owns the range. */
    return NULL;
}

/* Allocate one free split-ledger slot. */
static KswHvmEptSplit*
kswordArkHvmEptFindFreeSplit(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Search the bounded split ledger for one inactive record. */
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_SPLITS;
         ++index) {
        /* Return the first inactive split record. */
        if (!runtime->eptSplits[index].active) {
            /* Return the reusable zeroed split record. */
            return &runtime->eptSplits[index];
        }
    }
    /* Report split-ledger exhaustion explicitly. */
    return NULL;
}

/* Resolve the parent PDE for one guest physical address. */
static volatile ULONGLONG*
kswordArkHvmEptFindParentEntry(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress
    )
{
    ULONG pml4Index = 0UL;
    ULONG pdptIndex = 0UL;
    ULONG pdIndex = 0UL;
    ULONGLONG* pd = NULL;

    /* Reject physical addresses outside the explicit EPT mapping window. */
    if (physicalAddress >= KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Report the address as unmapped. */
        return NULL;
    }
    /* Decode the EPT PML4 index from the guest physical address. */
    pml4Index =
        (ULONG)((physicalAddress >> 39) & 0x1FFULL);
    /* Decode the EPT PDPT index from the guest physical address. */
    pdptIndex =
        (ULONG)((physicalAddress >> 30) & 0x1FFULL);
    /* Decode the EPT page-directory index from the guest physical address. */
    pdIndex =
        (ULONG)((physicalAddress >> 21) & 0x1FFULL);
    /* Reject sparse hierarchy holes before dereferencing a page directory. */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        runtime->eptPd[pml4Index][pdptIndex] == NULL) {
        /* Report the address as unmapped. */
        return NULL;
    }
    /* Select the writable page-directory virtual address. */
    pd = (ULONGLONG*)runtime->eptPd[pml4Index][pdptIndex];
    /* Return the exact writable parent PDE. */
    return &pd[pdIndex];
}

/* Split one two-MiB EPT identity leaf into 512 four-KiB entries. */
NTSTATUS
kswordArkHvmEptEnsureSplitLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _Outptr_ KswHvmEptSplit** splitArg
    )
{
    ULONGLONG physicalBase =
        physicalAddress &
        ~(KSW_HVM_LARGE_PAGE_BYTES - 1ULL);
    volatile ULONGLONG* parentEntry = NULL;
    KswHvmEptSplit* split = NULL;
    PHYSICAL_ADDRESS pageTablePhysical = { 0 };
    ULONGLONG originalEntry = 0ULL;
    ULONGLONG leafFlags = 0ULL;
    ULONG pageIndex = 0UL;

    /* Reject a missing output before changing EPT state. */
    if (splitArg == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reuse an existing split for the same two-MiB range. */
    split = kswordArkHvmEptFindSplit(
        runtime,
        physicalBase);
    /* Return the existing split without rewriting its page table. */
    if (split != NULL) {
        /* Publish the exact reusable split. */
        *splitArg = split;
        /* Complete the idempotent split request. */
        return STATUS_SUCCESS;
    }
    /* Resolve the sparse parent PDE that currently owns the range. */
    parentEntry = kswordArkHvmEptFindParentEntry(
        runtime,
        physicalBase);
    /* Reject holes and non-large parent entries explicitly. */
    if (parentEntry == NULL ||
        ((*parentEntry) & KSW_EPT_LARGE_PAGE) == 0ULL) {
        /* Report that the baseline identity leaf is unavailable. */
        return STATUS_NOT_FOUND;
    }
    /* Reserve one bounded split-ledger record before allocating a page. */
    split = kswordArkHvmEptFindFreeSplit(runtime);
    /* Report bounded split capacity exhaustion. */
    if (split == NULL) {
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Preserve the original parent identity leaf before replacement. */
    originalEntry = *parentEntry;
    /*
     * Preserve permissions and memory type while dropping the large marker.
     * Suppress-#VE has to be carried across explicitly: this mask is what the
     * split leaves inherit, and a leaf that loses the bit silently becomes
     * convertible the moment #VE is ever enabled.
     */
    leafFlags = originalEntry &
        (KSW_EPT_READ |
         KSW_EPT_WRITE |
         KSW_EPT_EXECUTE |
         KSW_EPT_SUPPRESS_VE |
         (7ULL << KSW_EPT_MEMORY_TYPE_SHIFT));
    /* Guarantee the bit even if the parent leaf somehow lacked it. */
    leafFlags |= KSW_EPT_SUPPRESS_VE;
    /* Allocate one zeroed page table through the shared cleanup ledger. */
    split->pageTable = kswordArkHvmAllocateEptPageLocked(
        runtime,
        &pageTablePhysical);
    /* Report allocation failure without publishing a partial parent entry. */
    if (split->pageTable == NULL) {
        /* Clear the reusable ledger record. */
        RtlZeroMemory(split, sizeof(*split));
        /* Return the exact resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Populate every four-KiB identity leaf before switching the parent PDE. */
    for (pageIndex = 0UL; pageIndex < 512UL; ++pageIndex) {
        /* Encode one physical page and the inherited permissions and type. */
        ((ULONGLONG*)split->pageTable)[pageIndex] =
            (physicalBase +
                ((ULONGLONG)pageIndex * KSW_HVM_PAGE_BYTES)) |
            leafFlags;
    }
    /* Preserve all split metadata before the parent entry becomes visible. */
    split->physicalBase = physicalBase;
    /* Preserve the page-table physical address for protocol cleanup. */
    split->pageTablePhysical = pageTablePhysical;
    /* Preserve the writable parent entry for reset. */
    split->parentEntry = parentEntry;
    /* Preserve the original large leaf for reset. */
    split->originalEntry = originalEntry;
    /* Order the fully initialized page table before replacing its parent. */
    KeMemoryBarrier();
    /* Point the parent PDE at the new four-KiB page table. */
    *parentEntry =
        (pageTablePhysical.QuadPart &
            KSW_EPT_PHYSICAL_MASK) |
        KSW_EPT_READ |
        KSW_EPT_WRITE |
        KSW_EPT_EXECUTE;
    /* Publish the completed split record after the parent transition. */
    split->active = TRUE;
    /* Publish the exact active split to the caller. */
    *splitArg = split;
    /* Complete the split operation successfully. */
    return STATUS_SUCCESS;
}

/* Return the writable four-KiB EPT entry for one split physical page. */
volatile ULONGLONG*
kswordArkHvmEptFindLeafEntry(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress
    )
{
    ULONGLONG physicalBase =
        physicalAddress &
        ~(KSW_HVM_LARGE_PAGE_BYTES - 1ULL);
    ULONG pageIndex = (ULONG)(
        (physicalAddress - physicalBase) >>
        12);
    KswHvmEptSplit* split =
        kswordArkHvmEptFindSplit(
            runtime,
            physicalBase);

    /* Report an unsplit or unavailable page explicitly. */
    if (split == NULL ||
        split->pageTable == NULL) {
        /* Return no writable four-KiB entry. */
        return NULL;
    }
    /* Return the exact writable four-KiB identity leaf. */
    return &((ULONGLONG*)split->pageTable)[pageIndex];
}


BOOLEAN
kswordArkHvmEptReadLeaf(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _Out_ ULONGLONG* leaf,
    _Out_ ULONG* leafShift
    )
{
    volatile ULONGLONG* entry = NULL;

    if (leaf == NULL || leafShift == NULL) { return FALSE; }
    *leaf = 0ULL;
    *leafShift = 0UL;
    if (runtime == NULL ||
        physicalAddress >= runtime->highestMappedPhysicalAddress) {
        return FALSE;
    }
    entry = kswordArkHvmEptFindParentEntry(runtime, physicalAddress);
    if (entry == NULL) { return FALSE; }
    if ((*entry & KSW_EPT_LARGE_PAGE) != 0ULL) {
        *leaf = *entry;
        *leafShift = 21UL;
        return TRUE;
    }
    entry = kswordArkHvmEptFindLeafEntry(runtime, physicalAddress);
    if (entry == NULL) { return FALSE; }
    *leaf = *entry;
    *leafShift = 12UL;
    return TRUE;
}

/* Apply every active overlapping rule to one four-KiB EPT entry. */
static VOID
kswordArkHvmEptRecomputePageLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress
    )
{
    volatile ULONGLONG* entry =
        kswordArkHvmEptFindLeafEntry(
            runtime,
            physicalAddress);
    ULONGLONG value = 0ULL;
    ULONG ruleIndex = 0UL;

    /* Ignore pages whose split failed before recomputation. */
    if (entry == NULL) {
        /* Return without dereferencing an unavailable leaf. */
        return;
    }
    /* Restore baseline R/W/X before applying all active overlapping rules. */
    value = *entry |
        KSW_EPT_READ |
        KSW_EPT_WRITE |
        KSW_EPT_EXECUTE;
    /* Apply each bounded active rule that contains the physical page. */
    for (ruleIndex = 0UL;
         ruleIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++ruleIndex) {
        const KswHvmEptRuleSlot* rule =
            &runtime->eptRules[ruleIndex];
        ULONGLONG ruleBytes = 0ULL;
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rule records. */
        if (!rule->active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Convert the validated page count to bytes. */
        ruleBytes = rule->pageCount * KSW_HVM_PAGE_BYTES;
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->physicalAddress + ruleBytes;
        /* Skip rules that do not contain the target page. */
        if (physicalAddress < rule->physicalAddress ||
            physicalAddress >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Remove read permission requested by the overlapping rule. */
        if ((rule->deniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
            /* Clear the EPT read permission. */
            value &= ~KSW_EPT_READ;
        }
        /* Remove write permission requested by the overlapping rule. */
        if ((rule->deniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
            /* Clear the EPT write permission. */
            value &= ~KSW_EPT_WRITE;
        }
        /* Remove execute permission requested by the overlapping rule. */
        if ((rule->deniedAccess &
                KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
            /* Clear the EPT execute permission. */
            value &= ~KSW_EPT_EXECUTE;
        }
    }
    /* Publish the recomputed permission value atomically on x64. */
    *entry = value;
}

/*
 * Compute what one page's leaf value becomes once a given rule stops denying.
 *
 * Deliberately not "read DeniedAccess after the winner cleared it": the
 * processor that loses the atomic transition can reach this point before the
 * winner's store is visible to it, and a recompute that still sees the denial
 * would restore the restricted value, resume, fault again, and keep doing that
 * until the store lands.  Excluding the rule by identity removes the ordering
 * question entirely - every processor computes the same final value no matter
 * when it arrives.
 *
 * VM-exit safe: it reads only the rule table and the split ledger, both of
 * which residency freezes, and it takes no lock.
 */
static ULONGLONG
kswordArkHvmEptComputeLeafExcluding(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG currentValue,
    _In_ const KswHvmEptRuleSlot* excluded
    )
{
    ULONGLONG value = KswordArkHvmWatchRestoreLeaf(currentValue);
    ULONG ruleIndex = 0UL;

    /* Apply each bounded active rule that still contains the physical page. */
    for (ruleIndex = 0UL;
         ruleIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++ruleIndex) {
        const KswHvmEptRuleSlot* rule =
            &runtime->eptRules[ruleIndex];
        ULONGLONG ruleBytes = 0ULL;
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rule records. */
        if (!rule->active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Skip the rule whose denial this computation is removing. */
        if (rule == excluded) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Convert the validated page count to bytes. */
        ruleBytes = rule->pageCount * KSW_HVM_PAGE_BYTES;
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->physicalAddress + ruleBytes;
        /* Skip rules that do not contain the target page. */
        if (physicalAddress < rule->physicalAddress ||
            physicalAddress >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Remove exactly the permissions this overlapping rule denies. */
        value = KswordArkHvmWatchApplyDenial(
            value,
            rule->deniedAccess);
    }
    /* Return the permission value the page settles on. */
    return value;
}

/* Recompute every page in one validated rule range. */
static VOID
kswordArkHvmEptRecomputeRangeLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG pageCount
    )
{
    ULONGLONG pageIndex = 0ULL;

    /* Recompute each bounded four-KiB page exactly once. */
    for (pageIndex = 0ULL;
         pageIndex < pageCount;
         ++pageIndex) {
        /* Recompute all overlapping rule permissions for one page. */
        kswordArkHvmEptRecomputePageLocked(
            runtime,
            physicalAddress +
                (pageIndex * KSW_HVM_PAGE_BYTES));
    }
}

/* Validate one physical rule range without truncation. */
static BOOLEAN
kswordArkHvmEptValidateRuleRange(
    _In_ ULONGLONG physicalAddress,
    _In_ ULONGLONG pageCount
    )
{
    ULONGLONG byteCount = 0ULL;

    /* Require a nonempty page-aligned physical range. */
    if (pageCount == 0ULL ||
        (physicalAddress &
            (KSW_HVM_PAGE_BYTES - 1ULL)) != 0ULL) {
        /* Reject a malformed rule range. */
        return FALSE;
    }
    /* Reject multiplication overflow before converting pages to bytes. */
    if (pageCount >
        (MAXULONGLONG / KSW_HVM_PAGE_BYTES)) {
        /* Reject the overflowing rule range. */
        return FALSE;
    }
    /* Convert the validated page count to bytes. */
    byteCount = pageCount * KSW_HVM_PAGE_BYTES;
    /* Reject address addition overflow and the explicit mapping boundary. */
    if (physicalAddress > MAXULONGLONG - byteCount ||
        physicalAddress + byteCount >
            KSW_HVM_MAX_MAPPED_PHYSICAL) {
        /* Reject the out-of-window rule range. */
        return FALSE;
    }
    /* Accept the fully representable physical page range. */
    return TRUE;
}

VOID
kswordArkHvmEptResetLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Reject a missing runtime during defensive teardown. */
    if (runtime == NULL) {
        /* Return without dereferencing an invalid runtime. */
        return;
    }
    /* Restore every replaced two-MiB parent entry. */
    for (index = 0UL;
         index < KSW_HVM_MAX_EPT_SPLITS;
         ++index) {
        KswHvmEptSplit* split =
            &runtime->eptSplits[index];

        /* Skip inactive split records. */
        if (!split->active ||
            split->parentEntry == NULL) {
            /* Continue to the next bounded split record. */
            continue;
        }
        /* Restore the exact baseline two-MiB identity leaf. */
        *split->parentEntry = split->originalEntry;
    }
    /* Clear every protocol-visible EPT rule. */
    RtlZeroMemory(
        runtime->eptRules,
        sizeof(runtime->eptRules));
    /* Clear every split ledger record after parent restoration. */
    RtlZeroMemory(
        runtime->eptSplits,
        sizeof(runtime->eptSplits));
    /* Publish zero active EPT rules. */
    runtime->eptRuleCount = 0UL;
    /* Clear protocol-visible EPT-rule activity. */
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE);
}

/* Publish one watch slot as a protocol row. */
static VOID
kswordArkHvmEptFillWatchRow(
    _In_ const KswHvmEptRuleSlot* slot,
    _Out_ KSWORD_ARK_HVM_EPT_WATCH_ROW* row
    )
{
    /* initialize the complete row before publishing any field. */
    RtlZeroMemory(row, sizeof(*row));
    /* Publish the watch identity, which is the rule identity. */
    row->watchId = slot->ruleId;
    /* Publish the lifecycle state read once, not re-read per field. */
    row->state = (ULONG)InterlockedCompareExchange(
        (volatile LONG*)&slot->watchState,
        0L,
        0L);
    /* Publish the requested and normalized access masks side by side. */
    row->requestedAccess = slot->watchRequestedAccess;
    row->effectiveAccess = slot->watchEffectiveAccess;
    row->addressKind = slot->watchAddressKind;
    row->hitCount = slot->watchHitCount;
    row->lastHitSequence = slot->watchLastHitSequence;
    row->lastHitStatus = slot->watchLastHitStatus;
    row->armedGeneration = slot->watchArmedGeneration;
    /* Publish the requested target next to the page actually watched. */
    row->requestedAddress = slot->watchRequestedAddress;
    row->requestedLength = slot->watchRequestedLength;
    row->physicalPage = slot->physicalAddress;
    row->pageCount = slot->pageCount;
    /* Publish the recorded hit scene. */
    row->lastHitRip = slot->watchLastHitRip;
    row->lastHitGuestLinearAddress = slot->watchLastHitGuestLinearAddress;
    row->lastHitGuestPhysicalAddress = slot->watchLastHitGuestPhysicalAddress;
    row->lastHitCr3 = slot->watchLastHitCr3;
    row->lastHitRsp = slot->watchLastHitRsp;
    row->lastHitTimestamp = slot->watchLastHitTimestamp;
    row->lastHitProcessorGroup = slot->watchLastHitProcessorGroup;
    row->lastHitProcessorNumber = slot->watchLastHitProcessorNumber;
    row->lastHitGuestLinearValid = slot->watchLastHitGuestLinearValid;
    row->lastHitRangeMatch = slot->watchLastHitRangeMatch;
}

/*
 * Report whether any other EPT mechanism already owns one physical page.
 *
 * Refusing instead of merging is deliberate.  A view and a watch want opposite
 * values in the same leaf: the view keeps a restricted primary value in place
 * permanently, while the watch restores full permissions the first time it is
 * hit.  Whichever writes last wins, and it wins silently - the other feature
 * simply stops working with nothing anywhere reporting why.  One page, one
 * owner, and the conflict named in the response.
 */
static BOOLEAN
kswordArkHvmEptPageHasOwner(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalPage,
    _In_opt_ const KswHvmEptRuleSlot* ignoredRule,
    _Out_ ULONG* ownerId,
    _Out_ ULONG* ownerKind
    )
{
    ULONG index = 0UL;

    /* Publish no owner before the bounded scans. */
    *ownerId = 0UL;
    *ownerKind = KSWORD_ARK_HVM_WATCH_CONFLICT_NONE;
    /* Scan every installed split view. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_VIEWS;
         ++index) {
        const KswHvmEptViewSlot* view =
            &runtime->eptViews[index];

        /* Skip inactive or nonoverlapping views. */
        if (!view->active ||
            view->physicalAddress != physicalPage) {
            /* Continue to the next bounded view record. */
            continue;
        }
        /* Publish the conflicting view identity. */
        *ownerId = view->viewId;
        *ownerKind = KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW;
        /* Report that the page already has an owner. */
        return TRUE;
    }
    /* Scan every active rule, including other watches. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        const KswHvmEptRuleSlot* rule =
            &runtime->eptRules[index];
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive slots and the caller's own record. */
        if (!rule->active ||
            rule == ignoredRule) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->physicalAddress +
            (rule->pageCount * KSW_HVM_PAGE_BYTES);
        /* Skip rules that do not contain the page. */
        if (physicalPage < rule->physicalAddress ||
            physicalPage >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Publish the conflicting rule identity and its kind. */
        *ownerId = rule->ruleId;
        *ownerKind = (rule->flags &
            KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL
            ? KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH
            : KSWORD_ARK_HVM_WATCH_CONFLICT_RULE;
        /* Report that the page already has an owner. */
        return TRUE;
    }
    /* Report a page with exactly one prospective owner. */
    return FALSE;
}

/* Find one active watch by identifier. */
static KswHvmEptRuleSlot*
kswordArkHvmEptFindWatch(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG watchId
    )
{
    ULONG index = 0UL;

    /* Scan every bounded rule record for one active watch. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        KswHvmEptRuleSlot* rule =
            &runtime->eptRules[index];

        /* Select the active watch whose identifier matches exactly. */
        if (rule->active &&
            (rule->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL &&
            rule->ruleId == watchId) {
            /* Return the selected watch record. */
            return rule;
        }
    }
    /* Report that no active watch carries that identifier. */
    return NULL;
}

VOID
kswordArkHvmEptInvalidateWatchesLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Reject a missing runtime during defensive teardown. */
    if (runtime == NULL) {
        /* Return without dereferencing an invalid runtime. */
        return;
    }
    /* Retire every armed watch that this residency will stop observing. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        KswHvmEptRuleSlot* rule =
            &runtime->eptRules[index];

        /* Skip inactive slots and every non-watch rule. */
        if (!rule->active ||
            (rule->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) == 0UL) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /*
         * Only ARMED watches change.  A DISARMED one already produced its
         * evidence and that evidence stays true regardless of what residency
         * does next; overwriting it would erase a real observation.
         */
        if (InterlockedCompareExchange(
                &rule->watchState,
                (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED,
                (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED) !=
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Stop denying: the page must not stay restricted with nobody looking. */
        rule->deniedAccess = 0UL;
        /* Restore the page against every rule that still denies it. */
        kswordArkHvmEptRecomputeRangeLocked(
            runtime,
            rule->physicalAddress,
            rule->pageCount);
    }
}

NTSTATUS
kswordArkHvmEptRuleControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG slotIndex = 0UL;
    KswHvmEptRuleSlot* slot = NULL;
    ULONG assignedRuleId = 0UL;
    ULONG effectiveDeniedAccess = 0UL;

    /* Validate the fixed pointers before initializing the response. */
    if (runtime == NULL ||
        request == NULL ||
        response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the complete protocol response. */
    RtlZeroMemory(response, sizeof(*response));
    /* Publish the response protocol version. */
    response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    response->size = sizeof(*response);
    /* Publish the current EPT implementation maturity. */
    response->implementation = runtime->eptImplementation;
    /* Require prepared EPT state for every rule operation. */
    if ((runtime->stateFlags &
            KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        /* Publish the stable not-prepared protocol status. */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED;
        /* Publish the authoritative NTSTATUS. */
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Return a query snapshot without mutating EPT state. */
    if (request->operation == KSWORD_ARK_HVM_EPT_RULE_QUERY) {
        /* Search one exact requested rule identifier when provided. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            /* Skip inactive or nonmatching rule records. */
            if (!runtime->eptRules[slotIndex].active ||
                (request->ruleId != 0UL &&
                 runtime->eptRules[slotIndex].ruleId !=
                    request->ruleId)) {
                /* Continue to the next bounded rule record. */
                continue;
            }
            /* Select the first exact or first active rule. */
            slot = &runtime->eptRules[slotIndex];
            /* Stop after one protocol-visible rule snapshot. */
            break;
        }
        /* Publish not-found only for a requested exact identifier. */
        if (slot == NULL &&
            request->ruleId != 0UL) {
            /* Publish the stable not-found protocol status. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND;
            /* Publish the authoritative NTSTATUS. */
            response->lastStatus = STATUS_NOT_FOUND;
        } else {
            /* Publish a successful query snapshot. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
            /* Publish the optional selected rule fields. */
            if (slot != NULL) {
                /* Publish the selected stable rule identifier. */
                response->ruleId = slot->ruleId;
                /* Publish the selected denied-access mask. */
                response->deniedAccess = slot->deniedAccess;
                /* Publish the selected rule behavior flags. */
                response->flags = slot->flags;
                /* Publish the selected first physical page. */
                response->physicalAddress =
                    slot->physicalAddress;
                /* Publish the selected page count. */
                response->pageCount = slot->pageCount;
            }
            /* Publish the successful query NTSTATUS. */
            response->lastStatus = STATUS_SUCCESS;
        }
        /* Publish the complete current rule count. */
        response->ruleCount = runtime->eptRuleCount;
        /* Publish the current lifecycle generation. */
        response->generation = runtime->generation;
        /* Return the protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Return the whole watch table without mutating EPT state. */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        ULONG returned = 0UL;
        ULONG total = 0UL;

        /* Publish every active watch up to the bounded row capacity. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            const KswHvmEptRuleSlot* rule =
                &runtime->eptRules[slotIndex];

            /* Skip inactive slots and every non-watch rule. */
            if (!rule->active ||
                (rule->flags &
                    KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) == 0UL) {
                /* Continue to the next bounded rule record. */
                continue;
            }
            /* Count every watch, including ones past the row capacity. */
            total += 1UL;
            /* Publish only as many rows as the fixed response can carry. */
            if (returned < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS) {
                /* Publish one complete watch snapshot. */
                kswordArkHvmEptFillWatchRow(
                    rule,
                    &response->watchRows[returned]);
                /* Advance the bounded published row count. */
                returned += 1UL;
            }
        }
        /* Publish the published and total counts separately. */
        response->returnedWatchRows = returned;
        response->watchRowCount = total;
        /* Publish the successful snapshot status. */
        response->status = KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
        response->lastStatus = STATUS_SUCCESS;
        /* Publish the complete current rule count. */
        response->ruleCount = runtime->eptRuleCount;
        /* Publish the current lifecycle generation. */
        response->generation = runtime->generation;
        /* Return the protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Require typed UI confirmation for every EPT mutation. */
    if ((request->flags &
            KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED) == 0UL ||
        request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN) {
        /* Publish the stable confirmation-required protocol status. */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED;
        /* Publish the authoritative access failure. */
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Require a matching generation for every mutating EPT operation. */
    if (request->expectedGeneration != 0UL &&
        request->expectedGeneration != runtime->generation) {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
        /* Publish the authoritative compare-before failure. */
        response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Re-arm one watch that already fired, keeping its identity and history. */
    if (request->operation == KSWORD_ARK_HVM_EPT_RULE_REARM) {
        ULONG conflictOwnerId = 0UL;
        ULONG conflictOwnerKind = 0UL;

        /* Locate the exact active watch. */
        slot = kswordArkHvmEptFindWatch(
            runtime,
            request->ruleId);
        /* Report a missing watch explicitly. */
        if (slot == NULL) {
            /* Publish the stable not-found protocol status. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND;
            /* Publish the authoritative NTSTATUS. */
            response->lastStatus = STATUS_NOT_FOUND;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /*
         * Re-arming, like arming, happens while residency is stopped: the
         * caller never reaches here otherwise, because the rule table is
         * frozen for the whole of residency.
         */
        /* Refuse to re-arm onto a page another mechanism has since claimed. */
        if (kswordArkHvmEptPageHasOwner(
                runtime,
                slot->physicalAddress,
                slot,
                &conflictOwnerId,
                &conflictOwnerKind)) {
            /* Publish the stable leaf-conflict protocol status. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT;
            /* Publish which mechanism owns the page instead. */
            response->conflictOwnerId = conflictOwnerId;
            response->conflictOwnerKind = conflictOwnerKind;
            /* Publish the authoritative conflict failure. */
            response->lastStatus = STATUS_SHARING_VIOLATION;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /* Restore the normalized tripwire mask this watch was installed with. */
        slot->deniedAccess = slot->watchEffectiveAccess;
        /* Advance the lifecycle generation before binding the watch to it. */
        runtime->generation += 1UL;
        /* Bind this armed round to the generation that will observe it. */
        slot->watchArmedGeneration = runtime->generation;
        /* Order every field before the state becomes observable to VMX root. */
        KeMemoryBarrier();
        /* Publish the armed lifecycle state. */
        InterlockedExchange(
            &slot->watchState,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
        /* Apply the restored denial to every covered page. */
        kswordArkHvmEptRecomputeRangeLocked(
            runtime,
            slot->physicalAddress,
            slot->pageCount);
        /* Invalidate resident EPT translations on every active processor. */
        status = kswordArkHvmResidentInvalidateEpt(
            runtime->eptPointer);
        /* Publish success or an explicit partial invalidation result. */
        response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_EPT_RULE_STATUS_OK
            : KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        /* Publish the re-armed watch identity and its complete snapshot. */
        response->ruleId = slot->ruleId;
        response->deniedAccess = slot->deniedAccess;
        response->flags = slot->flags;
        response->physicalAddress = slot->physicalAddress;
        response->pageCount = slot->pageCount;
        response->ruleCount = runtime->eptRuleCount;
        response->generation = runtime->generation;
        response->lastStatus = status;
        kswordArkHvmEptFillWatchRow(slot, &response->watch);
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Clear every rule and restore baseline permissions. */
    if (request->operation == KSWORD_ARK_HVM_EPT_RULE_CLEAR) {
        /* Restore split leaves and clear all rule records. */
        kswordArkHvmEptResetLocked(runtime);
        /* Advance the lifecycle generation after the mutation. */
        runtime->generation += 1UL;
        /* Invalidate resident EPT translations on every active processor. */
        status = kswordArkHvmResidentInvalidateEpt(
            runtime->eptPointer);
        /* Publish success or an explicit partial invalidation result. */
        response->status = NT_SUCCESS(status)
            ? KSWORD_ARK_HVM_EPT_RULE_STATUS_OK
            : KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        /* Publish the authoritative invalidation status. */
        response->lastStatus = status;
        /* Publish the advanced generation. */
        response->generation = runtime->generation;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Locate one exact active rule for removal. */
    if (request->operation == KSWORD_ARK_HVM_EPT_RULE_REMOVE) {
        ULONGLONG removedAddress = 0ULL;
        ULONGLONG removedPageCount = 0ULL;

        /* Search the bounded rule table for the exact identifier. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            /* Select only the exact active rule identifier. */
            if (runtime->eptRules[slotIndex].active &&
                runtime->eptRules[slotIndex].ruleId ==
                    request->ruleId) {
                /* Preserve the selected slot for removal. */
                slot = &runtime->eptRules[slotIndex];
                /* Stop after the exact stable rule match. */
                break;
            }
        }
        /* Return an explicit not-found result for stale identifiers. */
        if (slot == NULL) {
            /* Publish the stable not-found protocol status. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND;
            /* Publish the authoritative NTSTATUS. */
            response->lastStatus = STATUS_NOT_FOUND;
            /* Publish the unchanged rule count. */
            response->ruleCount = runtime->eptRuleCount;
            /* Publish the unchanged generation. */
            response->generation = runtime->generation;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /* Preserve the removed range before clearing the slot. */
        removedAddress = slot->physicalAddress;
        /* Preserve the removed page count before clearing the slot. */
        removedPageCount = slot->pageCount;
        /* Clear the exact selected rule record. */
        RtlZeroMemory(slot, sizeof(*slot));
        /* Decrement the active rule count without underflow. */
        if (runtime->eptRuleCount != 0UL) {
            /* Publish one fewer active EPT rule. */
            runtime->eptRuleCount -= 1UL;
        }
        /* Recompute pages against every remaining overlapping rule. */
        kswordArkHvmEptRecomputeRangeLocked(
            runtime,
            removedAddress,
            removedPageCount);
        /* Clear rule-active state after the final rule is removed. */
        if (runtime->eptRuleCount == 0UL) {
            /* Clear protocol-visible EPT-rule activity. */
            kswordArkHvmStateClear(
                runtime,
                KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE);
        }
    /* Validate and add one new physical-page rule. */
    } else if (request->operation == KSWORD_ARK_HVM_EPT_RULE_ADD) {
        ULONGLONG pageIndex = 0ULL;

        /* Require one valid permission bit and no unknown access bits. */
        if ((request->deniedAccess &
                (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                 KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
                 KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) == 0UL ||
            (request->deniedAccess &
                ~(KSWORD_ARK_HVM_EPT_ACCESS_READ |
                  KSWORD_ARK_HVM_EPT_ACCESS_WRITE |
                  KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) != 0UL ||
            !kswordArkHvmEptValidateRuleRange(
                request->physicalAddress,
                request->pageCount)) {
            /* Publish the stable invalid-request protocol status. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
            /* Publish the authoritative parameter failure. */
            response->lastStatus = STATUS_INVALID_PARAMETER;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /*
         * Traditional EPT never permits W=1 with R=0.  READ removal therefore
         * also removes WRITE.  When execute-only EPT is unavailable, remove
         * EXECUTE as well rather than publishing an illegal R=0/W=0/X=1 leaf.
         */
        /*
         * Normalization lives in the shared pure header so the offline suite
         * proves the same code the exit path runs.  Getting it wrong has no
         * diagnostic surface in either direction: too little and the leaf is
         * architecturally illegal (one anonymous exit reason 49), too much and
         * the watch silently covers more than the user asked for.
         */
        effectiveDeniedAccess = KswordArkHvmWatchNormalizeAccess(
            request->deniedAccess,
            (runtime->vmxEptVpidCapabilities &
                KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL);
        /* Validate everything that is specific to a first-touch watch. */
        if ((request->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            ULONG conflictOwnerId = 0UL;
            ULONG conflictOwnerKind = 0UL;

            /*
             * A watch covers exactly one page.
             *
             * Not a limitation being papered over: the hit path restores
             * permissions from VMX root, and that work has to stay bounded by
             * a constant rather than by whatever range a caller asked for.
             * One page is also the honest unit - EPT permissions are page
             * granular, so a multi-page watch would be several independent
             * watches wearing one identifier, with one shared hit count that
             * could not say which page was touched.
             */
            if (request->pageCount != 1ULL ||
                (request->flags &
                    (KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE |
                     KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE)) != 0UL) {
                /* Publish the stable invalid-request protocol status. */
                response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
                /* Publish the authoritative parameter failure. */
                response->lastStatus = STATUS_INVALID_PARAMETER;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
            /*
             * A watch is armed while residency is STOPPED, exactly like every
             * other EPT rule, and takes effect when residency starts.
             *
             * An earlier version refused a watch unless residency was already
             * running, reasoning that a tripwire nothing can trip is worse than
             * a refusal.  That reasoning produced a rule that could never be
             * installed at all: kswordArkHvmEptRuleControl deliberately freezes
             * the whole rule table while resident, because VM exits scan it
             * without taking the PASSIVE_LEVEL lock.  The two conditions were
             * mutually exclusive.
             *
             * The honest fix is not to weaken that freeze - it is a real
             * safety invariant - but to drop the extra gate and let the state
             * be visible instead: an armed watch with residency stopped reads
             * as exactly that, and the callers say so.
             */
            /* Refuse a page another EPT mechanism already owns. */
            if (kswordArkHvmEptPageHasOwner(
                    runtime,
                    request->physicalAddress,
                    NULL,
                    &conflictOwnerId,
                    &conflictOwnerKind)) {
                /* Publish the stable leaf-conflict protocol status. */
                response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT;
                /* Publish which mechanism owns the page instead. */
                response->conflictOwnerId = conflictOwnerId;
                response->conflictOwnerKind = conflictOwnerKind;
                /* Publish the authoritative conflict failure. */
                response->lastStatus = STATUS_SHARING_VIOLATION;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        }
        /* Reserve one free bounded rule slot. */
        for (slotIndex = 0UL;
             slotIndex < KSWORD_ARK_HVM_MAX_EPT_RULES;
             ++slotIndex) {
            /* Select the first inactive rule record. */
            if (!runtime->eptRules[slotIndex].active) {
                /* Preserve the reusable rule slot. */
                slot = &runtime->eptRules[slotIndex];
                /* Stop after selecting one bounded free slot. */
                break;
            }
        }
        /* Report fixed rule-table exhaustion explicitly. */
        if (slot == NULL) {
            /* Publish the stable table-full protocol status. */
            response->status =
                KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL;
            /* Publish the authoritative resource failure. */
            response->lastStatus =
                STATUS_INSUFFICIENT_RESOURCES;
            /* Return a protocol-level result successfully. */
            return STATUS_SUCCESS;
        }
        /*
         * An allow-once rule the private hierarchies could not mirror must be
         * refused here rather than at start.  Rules that only deny access
         * never flip a leaf, so they are exempt and this check skips them.
         */
        if ((request->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) != 0UL) {
            /*
             * Refuse a one-instruction grant this machine cannot serve.
             *
             * The runtime gate (the allAllowOnce branch further down) already
             * requires either a private hierarchy or exactly one processor,
             * and fails closed otherwise.  That gate is correct but it fires
             * too late: the rule installs, reports success, and only on some
             * later hit does the machine leave VMX - and since fail-closed
             * became a whole-machine stop, it takes every processor with it.
             * Nothing connects the install the user did to the moment
             * virtualization silently went away.
             *
             * Mirroring the runtime condition here, not a weaker proxy: the
             * latch is what admission below already consults, and a rule
             * added while stopped has no per-VCPU record to ask instead.
             * ENFORCE never reaches this branch - it is rejected earlier as
             * UNIMPLEMENTED, and storing it drops ALLOW_ONCE anyway.
             */
            if (runtime->processorCount != 1UL &&
                !runtime->localEptArmed) {
                /* Publish the stable machine-capability refusal. */
                response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE;
                /* Publish the authoritative capability failure. */
                response->lastStatus = STATUS_NOT_SUPPORTED;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
            status = kswordArkHvmEptLocalCheckAdmission(
                runtime,
                request->physicalAddress,
                (ULONGLONG)request->pageCount * KSW_HVM_PAGE_BYTES);
            if (!NT_SUCCESS(status)) {
                /* Publish the stable table-full protocol status. */
                response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL;
                /* Publish the authoritative admission failure. */
                response->lastStatus = status;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        }
        /* Pre-split every covered two-MiB leaf before publishing the rule. */
        for (pageIndex = 0ULL;
             pageIndex < request->pageCount;
             ++pageIndex) {
            KswHvmEptSplit* split = NULL;

            /* Ensure one writable four-KiB page table covers this page. */
            status = kswordArkHvmEptEnsureSplitLocked(
                runtime,
                request->physicalAddress +
                    (pageIndex * KSW_HVM_PAGE_BYTES),
                &split);
            /* Stop before rule publication when any split fails. */
            if (!NT_SUCCESS(status)) {
                /* Publish the stable split-failed protocol status. */
                response->status =
                    KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED;
                /* Publish the authoritative split failure. */
                response->lastStatus = status;
                /* Return a protocol-level result successfully. */
                return STATUS_SUCCESS;
            }
        }
        /* Allocate a nonzero identifier from generation and slot position. */
        assignedRuleId =
            ((runtime->generation & 0x00FFFFFFUL) << 8) |
            (slotIndex + 1UL);
        /* Replace an impossible wrapped zero identifier with the slot index. */
        if (assignedRuleId == 0UL) {
            /* Publish a stable nonzero identifier. */
            assignedRuleId = slotIndex + 1UL;
        }
        /* Publish the stable rule identifier. */
        slot->ruleId = assignedRuleId;
        /* Publish the denied-access mask. */
        slot->deniedAccess = effectiveDeniedAccess;
        /* Preserve only defined behavior flags. */
        slot->flags = request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE);
        /* initialize the complete watch record for every rule. */
        slot->watchState = (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_NONE;
        slot->watchRequestedAccess = 0UL;
        slot->watchEffectiveAccess = 0UL;
        slot->watchAddressKind = 0UL;
        slot->watchHitCount = 0UL;
        slot->watchLastHitStatus = KSWORD_ARK_HVM_EPT_WATCH_HIT_NONE;
        slot->watchArmedGeneration = 0UL;
        slot->watchRequestedAddress = 0ULL;
        slot->watchRequestedLength = 0ULL;
        slot->watchLastHitSequence = 0ULL;
        slot->watchLastHitRip = 0ULL;
        slot->watchLastHitGuestLinearAddress = 0ULL;
        slot->watchLastHitGuestPhysicalAddress = 0ULL;
        slot->watchLastHitCr3 = 0ULL;
        slot->watchLastHitRsp = 0ULL;
        slot->watchLastHitTimestamp = 0ULL;
        slot->watchLastHitProcessorGroup = 0U;
        slot->watchLastHitProcessorNumber = 0U;
        slot->watchLastHitGuestLinearValid = 0U;
        slot->watchLastHitRangeMatch = 0UL;
        /* Populate the watch record only for a first-touch watch. */
        if ((slot->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            /*
             * Keep the user's request next to the mask actually installed.
             * They differ whenever architectural normalization widened the
             * request - and a UI that shows only one of them either rewrites
             * what the user asked for or understates what is being watched.
             */
            slot->watchRequestedAccess = request->deniedAccess;
            slot->watchEffectiveAccess = effectiveDeniedAccess;
            slot->watchAddressKind = request->addressKind;
            /*
             * Default the requested range to the whole page when the caller
             * gave none, so range matching reports MATCH rather than a
             * silent miss for a caller that watched a page on purpose.
             */
            slot->watchRequestedAddress =
                request->requestedLength != 0ULL
                    ? request->requestedAddress
                    : request->physicalAddress;
            slot->watchRequestedLength =
                request->requestedLength != 0ULL
                    ? request->requestedLength
                    : KSW_HVM_PAGE_BYTES;
            /* Bind this armed round to the generation advanced below. */
            slot->watchArmedGeneration = runtime->generation + 1UL;
            /* Publish the armed lifecycle state. */
            slot->watchState =
                (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED;
        }
        /*
         * Durable denial and a one-instruction grant are opposite outcomes for
         * the same access.  Let denial win rather than storing a rule whose
         * behavior would depend on aggregation order.
         */
        if ((slot->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE) != 0UL) {
            /* Drop the contradictory temporary grant. */
            slot->flags &= ~KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE;
        }
        /* Publish the first page-aligned physical address. */
        slot->physicalAddress = request->physicalAddress;
        /* Publish the complete validated page count. */
        slot->pageCount = request->pageCount;
        /* Order every rule field before publishing the active marker. */
        KeMemoryBarrier();
        /* Publish the complete active rule. */
        slot->active = TRUE;
        /* Publish one additional active EPT rule. */
        runtime->eptRuleCount += 1UL;
        /* Recompute every covered page against all active rules. */
        kswordArkHvmEptRecomputeRangeLocked(
            runtime,
            request->physicalAddress,
            request->pageCount);
        /* Publish protocol-visible EPT-rule activity. */
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE);
    } else {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST;
        /* Publish the authoritative parameter failure. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Advance the lifecycle generation after an add or removal mutation. */
    runtime->generation += 1UL;
    /* Invalidate resident EPT translations on every active processor. */
    status = kswordArkHvmResidentInvalidateEpt(
        runtime->eptPointer);
    /* Publish success or an explicit partial invalidation result. */
    response->status = NT_SUCCESS(status)
        ? KSWORD_ARK_HVM_EPT_RULE_STATUS_OK
        : KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
    /* Publish the affected or removed rule identifier. */
    response->ruleId = assignedRuleId != 0UL
        ? assignedRuleId
        : request->ruleId;
    /* Publish the effective, architecturally legal permission-removal mask. */
    if (assignedRuleId != 0UL) {
        /* Return the normalized mask applied to the new rule. */
        response->deniedAccess = effectiveDeniedAccess;
        /* Return the complete watch snapshot the caller will display. */
        if (slot != NULL &&
            (slot->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            /* Publish one armed watch row. */
            kswordArkHvmEptFillWatchRow(slot, &response->watch);
        }
    }
    /* Publish the current active rule count. */
    response->ruleCount = runtime->eptRuleCount;
    /* Publish the advanced lifecycle generation. */
    response->generation = runtime->generation;
    /* Publish the authoritative invalidation status. */
    response->lastStatus = status;
    /* Return the protocol-level result successfully. */
    return STATUS_SUCCESS;
}

BOOLEAN
kswordArkHvmEptRestoreTransient(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptTransient* transient
    )
{
    /* Reject a malformed recovery record without discarding its evidence. */
    if (runtime == NULL ||
        transient == NULL) {
        /* Report that no safe restoration was proven. */
        return FALSE;
    }
    /* Treat an unarmed record as already restored. */
    if (!transient->armed) {
        /* Complete the idempotent restoration successfully. */
        return TRUE;
    }
    /* Preserve an armed malformed record for fail-closed devirtualization. */
    if (transient->entry == NULL ||
        runtime->eptPointer == 0ULL) {
        /* Report that the pending grant cannot be safely restored. */
        return FALSE;
    }
    /* Restore the exact restricted four-KiB entry first. */
    *transient->entry = transient->restrictedValue;
    /* Order the restoration before invalidating the current EPT context. */
    KeMemoryBarrier();
    /*
     * Invalidate the hierarchy the grant was actually made in.  Single-context
     * INVEPT is scoped by the pointer it names, so naming the shared one here
     * would leave a private processor holding the widened translation.
     */
    if (kswordArkHvmAsmInveptSingle(
            transient->eptPointer != 0ULL
                ? transient->eptPointer
                : runtime->eptPointer) != 0U) {
        /* Keep Armed and every recovery field for VMXOFF fail-closed cleanup. */
        return FALSE;
    }
    /* Clear the complete recovery record only after successful INVEPT. */
    transient->armed = FALSE;
    transient->reserved0[0] = 0U;
    transient->reserved0[1] = 0U;
    transient->reserved0[2] = 0U;
    transient->ruleId = 0UL;
    transient->entry = NULL;
    transient->restrictedValue = 0ULL;
    transient->eptPointer = 0ULL;
    /* Report a fully restored and invalidated EPT context. */
    return TRUE;
}

BOOLEAN
kswordArkHvmEptHandleViolation(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONGLONG guestLinearAddress,
    _In_ ULONG access,
    _In_ BOOLEAN guestLinearAddressValid,
    _In_opt_ const KswHvmEptLocal* local,
    _Out_ KswHvmEptTransient* transient,
    _Out_ ULONG* ruleId,
    _Out_ ULONG* disposition,
    _Out_ KswHvmEptWatchHit* watchHit
    )
{
    ULONGLONG physicalPage =
        guestPhysicalAddress &
        ~(KSW_HVM_PAGE_BYTES - 1ULL);
    ULONG index = 0UL;
    ULONG selectedRuleId = 0UL;
    BOOLEAN matched = FALSE;
    BOOLEAN allAllowOnce = TRUE;
    BOOLEAN enforceMatched = FALSE;
    /* Set by any non-watch rule, so a watch never shares a disposition. */
    BOOLEAN otherMatched = FALSE;
    KswHvmEptRuleSlot* watchSlot = NULL;
    volatile ULONGLONG* entry = NULL;
    ULONGLONG grantedValue = 0ULL;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (runtime == NULL ||
        transient == NULL ||
        ruleId == NULL ||
        disposition == NULL ||
        watchHit == NULL) {
        /* Report an unhandled fatal EPT violation. */
        return FALSE;
    }
    /* Publish the fail-closed disposition before any rule is examined. */
    *disposition = KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE;
    /* Publish no new rule match before the bounded rule scan. */
    *ruleId = 0UL;
    /* Publish an empty watch result before any rule is examined. */
    watchHit->firstHit = FALSE;
    watchHit->rangeMatch = FALSE;
    watchHit->reserved0[0] = 0U;
    watchHit->reserved0[1] = 0U;
    watchHit->watchId = 0UL;
    /*
     * A second violation before MTF must restore the first grant and then
     * devirtualize.  Never overwrite the only recovery record.
     */
    if (transient->armed) {
        /* Preserve the first rule as the authoritative failure evidence. */
        *ruleId = transient->ruleId;
        /* Attempt restoration; failure intentionally leaves the record armed. */
        (void)kswordArkHvmEptRestoreTransient(
            runtime,
            transient);
        /* Force fail-closed devirtualization after any overlapping transient. */
        return FALSE;
    }
    /* Clear stale unarmed fields without calling vectorized runtime helpers. */
    transient->reserved0[0] = 0U;
    transient->reserved0[1] = 0U;
    transient->reserved0[2] = 0U;
    transient->ruleId = 0UL;
    transient->entry = NULL;
    transient->restrictedValue = 0ULL;
    transient->eptPointer = 0ULL;
    /* Aggregate every active rule that covers this page and access type. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_EPT_RULES;
         ++index) {
        KswHvmEptRuleSlot* rule =
            &runtime->eptRules[index];
        ULONGLONG ruleBytes = 0ULL;
        ULONGLONG ruleEnd = 0ULL;

        /* Skip inactive rules. */
        if (!rule->active) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Skip rules that did not remove the attempted access type. */
        if ((rule->deniedAccess & access) == 0UL) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Convert the validated page count to bytes. */
        ruleBytes = rule->pageCount * KSW_HVM_PAGE_BYTES;
        /* Compute the validated exclusive rule end. */
        ruleEnd = rule->physicalAddress + ruleBytes;
        /* Skip rules that do not contain the faulting page. */
        if (physicalPage < rule->physicalAddress ||
            physicalPage >= ruleEnd) {
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Preserve the first matching identifier for allow-once telemetry. */
        if (!matched) {
            /* Select the first complete overlapping rule. */
            selectedRuleId = rule->ruleId;
        }
        /* Publish that at least one rule covers this exact attempted access. */
        matched = TRUE;
        /*
         * A watch resolves on its own, after the scan, and never mixes with
         * the other three dispositions: installation already refuses a watch
         * on a page any of them owns, so seeing both here would mean the
         * table is inconsistent - and then the conservative outcome wins.
         */
        if ((rule->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE) != 0UL) {
            /* Preserve the first watch as the authoritative hit owner. */
            if (watchSlot == NULL) {
                /* Select the watch this violation belongs to. */
                watchSlot = rule;
            }
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Publish that a non-watch rule also covers this access. */
        otherMatched = TRUE;
        /*
         * A durable denial neither grants a temporary permission nor tears
         * down residency, so it is tracked separately from the tripwire and
         * allow-once dispositions and resolved after the whole scan.
         */
        if ((rule->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE) != 0UL) {
            /* Preserve the first denying rule as authoritative evidence. */
            if (!enforceMatched) {
                /* Select the rule that will produce the injected fault. */
                selectedRuleId = rule->ruleId;
            }
            /* Publish that at least one rule denies this access durably. */
            enforceMatched = TRUE;
            /* Continue to the next bounded rule record. */
            continue;
        }
        /* Any strict tripwire dominates every overlapping allow-once rule. */
        if ((rule->flags &
                KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE) == 0UL) {
            /* Preserve the first strict rule as authoritative evidence. */
            if (allAllowOnce) {
                /* Select the rule that requires immediate devirtualization. */
                selectedRuleId = rule->ruleId;
            }
            /* Prevent any temporary grant for the aggregate rule set. */
            allAllowOnce = FALSE;
        }
    }
    /*
     * First-touch watch.
     *
     * Resolved before every other disposition and only when no other rule
     * covers the same access, because a watch means "let it through and tell
     * me who did it" while the others mean "stop", "deny" or "step".  Mixing
     * them would silently turn one into the other.
     */
    if (watchSlot != NULL &&
        !otherMatched) {
        LONG previousState = 0L;
        KSW_HVM_WATCH_HIT_PLAN plan = { 0 };
        volatile ULONGLONG* watchEntry = NULL;
        ULONGLONG restoredValue = 0ULL;
        ULONGLONG invalidatePointer = 0ULL;

        /* Publish the watch identity as the authoritative rule evidence. */
        selectedRuleId = watchSlot->ruleId;
        *ruleId = selectedRuleId;
        watchHit->watchId = selectedRuleId;
        /*
         * Decide the single owner of this first touch.
         *
         * Every processor that faults on the page still has to repair its own
         * view below - only the one that wins here records evidence and moves
         * the lifecycle.  Losers that merely resumed would fault again on the
         * same instruction until the winner's store reached them.
         */
        previousState = InterlockedCompareExchange(
            &watchSlot->watchState,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED,
            (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED);
        /*
         * The decision itself lives in the shared pure header, exhaustively
         * tested offline.  Both ways of getting it wrong are silent: two
         * processors each believing they are the first touch produces two
         * contradictory "first" records, and a loser that resumes without
         * repairing its own view re-faults on the same instruction until the
         * winner's store reaches it - a livelock with no error code at all.
         */
        plan = KswordArkHvmWatchPlanHit((ULONG)previousState);
        /* Refuse to continue from a lifecycle state this path cannot explain. */
        if (!plan.Accepted) {
            /* Report that the dispatcher must leave EPT enforcement. */
            return FALSE;
        }
        /* Record which processor owns the one logical first touch. */
        watchHit->firstHit = plan.OwnsFirstHit != 0U;
        /* Stop denying before anything recomputes the page from the table. */
        if (watchHit->firstHit) {
            /*
             * Clearing the mask is the representation of "disarmed": both the
             * scan above and the recompute below read it, so one store retires
             * the tripwire everywhere without a second state to keep in sync.
             */
            watchSlot->deniedAccess = 0UL;
            /* Order the retirement before any permission is restored. */
            KeMemoryBarrier();
        }
        /* Resolve the preallocated writable four-KiB leaf for this page. */
        watchEntry = kswordArkHvmEptFindLeafEntry(
            runtime,
            physicalPage);
        /* Fail closed when split metadata is unexpectedly unavailable. */
        if (watchEntry == NULL) {
            /* Report that the resident dispatcher must devirtualize. */
            return FALSE;
        }
        /* Compute the value the page settles on once this watch stops denying. */
        restoredValue = kswordArkHvmEptComputeLeafExcluding(
            runtime,
            physicalPage,
            *watchEntry,
            watchSlot);
        /*
         * Publish into the shared table first so that a later passive-level
         * recompute agrees with what the processors are already using.
         */
        *watchEntry = restoredValue;
        /* Repair this processor's own mirror when it runs a private hierarchy. */
        if (local != NULL) {
            volatile ULONGLONG* localEntry =
                kswordArkHvmEptLocalTranslate(local, watchEntry);

            /* Fail closed rather than leave this processor still denied. */
            if (localEntry == NULL) {
                /* Report that the resident dispatcher must devirtualize. */
                return FALSE;
            }
            /* Restore the permission in the hierarchy this processor walks. */
            *localEntry = restoredValue;
            /* Name the private hierarchy for the invalidation below. */
            invalidatePointer = local->eptPointer;
        }
        /* Order the restoration before invalidating any translation. */
        KeMemoryBarrier();
        /* Discard translations built from the restricted leaf. */
        if (kswordArkHvmAsmInveptSingle(
                invalidatePointer != 0ULL
                    ? invalidatePointer
                    : runtime->eptPointer) != 0U) {
            /* Report that the resident dispatcher must devirtualize. */
            return FALSE;
        }
        /* Record the hit scene on the owning processor only. */
        if (watchHit->firstHit) {
            /*
             * Range match is an attribution refinement, never a filter: the
             * hit is reported either way, because the hardware watched the
             * whole page and saying otherwise would misdescribe what happened.
             */
            watchHit->rangeMatch = KswordArkHvmWatchRangeMatch(
                guestLinearAddressValid ? 1 : 0,
                guestLinearAddress,
                watchSlot->watchRequestedAddress,
                watchSlot->watchRequestedLength) != 0;
            /* Preserve the scene the dispatcher will publish as evidence. */
            watchSlot->watchLastHitGuestPhysicalAddress = guestPhysicalAddress;
            watchSlot->watchLastHitGuestLinearAddress = guestLinearAddress;
            watchSlot->watchLastHitGuestLinearValid =
                guestLinearAddressValid ? 1U : 0U;
            watchSlot->watchLastHitRangeMatch =
                watchHit->rangeMatch ? 1UL : 0UL;
            watchSlot->watchHitCount += 1UL;
            /*
             * Assume the evidence was lost until the ring says otherwise.
             *
             * The publish happens in the dispatcher, after this function
             * returns, and it can fail.  Starting from "lost" means a failed
             * publish needs no extra bookkeeping to be reported honestly,
             * while starting from "published" would quietly claim evidence
             * that does not exist.
             */
            watchSlot->watchLastHitStatus =
                KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST;
            /* Order every recorded field before the terminal state. */
            KeMemoryBarrier();
            /* Publish the terminal lifecycle state for this armed round. */
            InterlockedExchange(
                &watchSlot->watchState,
                (LONG)KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED);
        }
        /* Request the resume that re-executes the original instruction. */
        *disposition = KSW_HVM_EPT_DISPOSITION_WATCH_ONCE;
        /* Report a completely resolved violation with residency intact. */
        return TRUE;
    }
    /*
     * A watch that reached here shares its page with another rule, which
     * installation is supposed to make impossible.  Deny the one-instruction
     * grant so the aggregate falls through to fail-closed devirtualization
     * rather than resolving as whichever rule happened to be scanned first.
     */
    if (watchSlot != NULL) {
        /* Prevent any temporary grant for an inconsistent rule set. */
        allAllowOnce = FALSE;
    }
    /*
     * A durable denial outranks an overlapping allow-once grant: permitting
     * the access even once would defeat the rule that exists to refuse it.
     * A strict tripwire still dominates, because tearing down residency is
     * the most conservative outcome available.
     */
    if (enforceMatched && allAllowOnce) {
        /* Publish the aggregate rule identity before the disposition. */
        *ruleId = selectedRuleId;
        /*
         * Denial is expressed as a page fault, and a page fault without a
         * meaningful CR2 would send the guest handler to an arbitrary
         * address.  Without a reported guest-linear address, fall back to the
         * tripwire behavior rather than inventing one.
         */
        if (!guestLinearAddressValid) {
            /* Report that the dispatcher must leave EPT enforcement. */
            return FALSE;
        }
        /* Request the injected fault that expresses durable denial. */
        *disposition = KSW_HVM_EPT_DISPOSITION_INJECT_FAULT;
        /* Report a completely resolved violation. */
        return TRUE;
    }
    /* Publish the aggregate rule identity before choosing a disposition. */
    *ruleId = selectedRuleId;
    /* Unruled accesses and any strict overlapping rule devirtualize. */
    if (!matched ||
        !allAllowOnce) {
        /* Report that the resident dispatcher must leave EPT enforcement. */
        return FALSE;
    }
    /*
     * ALLOW_ONCE edits an EPT leaf.  On a SHARED hierarchy that is safe only
     * with exactly one resident VCPU, because every other one would see the
     * widened permission for the whole window.  With a private hierarchy the
     * leaf is this processor's alone, so the topology requirement drops out -
     * but the capability requirement below never does.
     */
    if ((local == NULL &&
            (runtime->processorCount != 1UL ||
             InterlockedCompareExchange(
                 &runtime->residentProcessorCount,
                 0L,
                 0L) != 1L)) ||
        (runtime->featureFlags &
            (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) !=
            (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
             KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) {
        /* Reject a shared-leaf permission window that another VCPU could use. */
        return FALSE;
    }
    /* Resolve the preallocated writable four-KiB leaf after aggregation. */
    entry = kswordArkHvmEptFindLeafEntry(
        runtime,
        physicalPage);
    /* Fail closed when split metadata is unexpectedly unavailable. */
    if (entry == NULL) {
        /* Report that the resident dispatcher must devirtualize. */
        return FALSE;
    }
    /*
     * Redirect the write to this processor's own copy of the leaf.  A leaf
     * that is flippable but has no mirror is a build error, and writing the
     * shared table instead would silently reintroduce exactly the hazard the
     * private hierarchy exists to remove - so it fails closed.
     */
    if (local != NULL) {
        entry = kswordArkHvmEptLocalTranslate(local, entry);
        if (entry == NULL) {
            /* Report that the resident dispatcher must devirtualize. */
            return FALSE;
        }
    }
    /* Preserve every recovery field before changing the leaf. */
    transient->restrictedValue = *entry;
    transient->entry = entry;
    transient->ruleId = selectedRuleId;
    /* Record which hierarchy must be invalidated when this grant ends. */
    transient->eptPointer = local != NULL ? local->eptPointer : 0ULL;
    /* Publish the armed recovery record before granting any permission. */
    KeMemoryBarrier();
    transient->armed = TRUE;
    /* Compute a temporary value that grants only the attempted permissions. */
    grantedValue = transient->restrictedValue;
    /* Temporarily grant attempted read permission. */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
        /* Add EPT read permission for one instruction. */
        grantedValue |= KSW_EPT_READ;
    }
    /* Temporarily grant attempted write permission. */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        /* EPT never permits W=1 with R=0, so grant the legal R/W pair. */
        grantedValue |= KSW_EPT_READ | KSW_EPT_WRITE;
    }
    /* Temporarily grant attempted execute permission. */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
        /* Add EPT execute permission for one instruction. */
        grantedValue |= KSW_EPT_EXECUTE;
        /* Add READ when the processor cannot encode execute-only EPT leaves. */
        if ((runtime->vmxEptVpidCapabilities &
                KSW_EPT_CAP_EXECUTE_ONLY) == 0ULL) {
            /* Preserve an architecturally legal temporary execute leaf. */
            grantedValue |= KSW_EPT_READ;
        }
    }
    /* Publish the complete temporary permission value. */
    *entry = grantedValue;
    /* Order the permission grant before current-context invalidation. */
    KeMemoryBarrier();
    /* Invalidate the hierarchy the grant was made in, before VMRESUME. */
    if (kswordArkHvmAsmInveptSingle(
            transient->eptPointer != 0ULL
                ? transient->eptPointer
                : runtime->eptPointer) != 0U) {
        /* Restore and invalidate; retain Armed if the restoration also fails. */
        (void)kswordArkHvmEptRestoreTransient(
            runtime,
            transient);
        /* Require immediate fail-closed devirtualization. */
        return FALSE;
    }
    /* Request the monitor-trap step that restores the temporary grant. */
    *disposition = KSW_HVM_EPT_DISPOSITION_ALLOW_ONCE;
    /* Report a handled, single-VCPU allow-once EPT violation. */
    return TRUE;
}

BOOLEAN
kswordArkHvmEptHandleMonitorTrap(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptTransient* transient
    )
{
    /* Restore and invalidate before monitor-trap can be disabled. */
    return kswordArkHvmEptRestoreTransient(
        runtime,
        transient);
}

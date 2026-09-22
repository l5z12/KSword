/*
 * hvm_ept_switch.c
 *
 * "Switch EPTP" separates the **side-effecting** half of the view backend: page pool, ledger, and release.
 *
 * Pure arithmetic resides in shared/driver/KswordArkHvmEptSwitch.h, shared with host unit tests. This file
 * deliberately avoids recalculating any bitfields; if it did, the two arithmetic implementations would
 * drift apart. Such errors have no diagnostic surface: uncleared leaf reserved bits manifest only as exit
 * reason 49, and an index off-by-one causes a page to permanently stay shadowed while all self-tests pass.
 */

#include "hvm_ept_switch.h"

#include "driver/KswordArkHvmEptSwitch.h"

#include "../../platform/pool_compat.h"

#define KSW_HVM_EPTSW_POOL_TAG 'SvHK'

/*
 * Page pool upper limit.
 *
 * In shared base mode, the total overhead is **independent** of the number of processors: 32 leaves × 4 pages = 128 pages = 512 KiB,
 * regardless of whether the machine has 1 core or 256 cores. This upper limit includes a 2x margin purely to cause small machines to
 * hit the wall if someone changes the base count to be billed per core, rather than waiting until large machines to reject startup.
 */
#define KSW_HVM_EPTSW_MAX_PAGES 256ULL

/*
 * Each installed view occupies exactly one hierarchy index, so these two limits **must be equal**.
 *
 * If they are unequal, neither direction provides diagnostic coverage: a larger view table implies views that fit but
 * cannot be switched, leaving a page unprotected while self-checks pass; a larger hierarchy table implies wasted pages.
 *
 * KSW_HVM_MAX_LOCAL_LEAVES (8) from hvm_ept_local.h is **not** involved in this minimum calculation:
 * That is the per-processor private budget; the two mechanisms are mutually exclusive at the protocol layer and never coexist.
 */
C_ASSERT(KSWORD_ARK_HVM_EPTSW_MAX_LEAVES == KSWORD_ARK_HVM_MAX_VIEWS);
/*
 * hvm_internal.h writes the path page count as a literal to avoid pulling in the entire arithmetic header into every TU.
 * This is the sole link between the literal and the shared header; changes
 * on either side will break the build rather than silently diverging.
 */
C_ASSERT(KSW_HVM_EPTSW_PATH_PAGES == KSWORD_ARK_HVM_EPTSW_PATH_PAGES);
/* The ledger array must accommodate the base plus one set per leaf. */
C_ASSERT(RTL_NUMBER_OF(((KswHvmEptsw*)0)->hierarchies) ==
         KSWORD_ARK_HVM_EPTSW_MAX_LEAVES);
/* The flat EPTP table must be exactly `base + one set per leaf`; the switch planner validates this length. */
C_ASSERT(RTL_NUMBER_OF(((KswHvmEptsw*)0)->eptp) ==
         KSWORD_ARK_HVM_EPTSW_MAX_LEAVES + 1UL);

/*
 * Shared arithmetic header naming convention requires the integrator to provide five mirror assertions (KswordArkHvmEptSwitch.h:1371).
 *
 * The two sets of constants have the same values today, but they **come from different headers and are maintained for different
 * reasons**. If one side changes without the other following suit, the switcher will use a "read" criterion to service a write,
 * or use CLOAK permissions to service a HOOK page — selecting the wrong layer. This has no symptoms: the view remains, the
 * driver keeps running, and self-checks pass, but the protected page returns incorrect content for a specific class of accesses.
 */
C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_READ ==
         KSWORD_ARK_HVM_EPT_ACCESS_READ);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_WRITE ==
         KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_ACCESS_EXECUTE ==
         KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_CLOAK ==
         KSWORD_ARK_HVM_VIEW_KIND_CLOAK);
C_ASSERT(KSWORD_ARK_HVM_EPTSW_KIND_HOOK ==
         KSWORD_ARK_HVM_VIEW_KIND_HOOK);

/*
 * Native physical address width.
 *
 * A well-formedness check uses it to compute the valid mask for page frames. Follow the same reading logic and boundary conditions as in
 * hvm_ept_builder.c:222-232 without establishing a separate set. If the two locations diverge on "how many bits constitute validity," the
 * result is that on some machines, the constructed hierarchy may consider itself valid while the processor flags it as misconfigured.
 * Return 0 if the value cannot be read; the caller should reject it rather than proceeding with a guessed width.
 */
static ULONG
kswordArkHvmEptSwitchPhysicalAddressBits(VOID)
{
    int cpuInfo[4] = { 0 };
    ULONG bits = 0UL;

    __cpuid(cpuInfo, (int)0x80000000UL);
    /* Refuse when the extended leaf carrying the width does not exist. */
    if ((ULONG)cpuInfo[0] < 0x80000008UL) {
        /* Return zero so the caller refuses rather than guesses. */
        return 0UL;
    }
    __cpuid(cpuInfo, (int)0x80000008UL);
    bits = (ULONG)cpuInfo[0] & 0xFFUL;
    /* Refuse a width no real processor reports. */
    if (bits < 32UL || bits > 52UL) {
        /* Return zero so the caller refuses rather than guesses. */
        return 0UL;
    }
    return bits;
}

/*
 * Get the level-th page of record i.
 *
 * Fixed slices instead of cursors: a view can be unloaded in any order; releasing under a cursor either
 * leaks those four pages or fragments the pool. Slices enable precise release and free reuse, at the
 * cost of pre-allocating the pool once — which is 512 KiB and independent of the processor count.
 */
static PVOID
kswordArkHvmEptSwitchPage(
    _In_ const KswHvmEptsw* state,
    _In_ ULONG record,
    _In_ ULONG level,
    _Out_ PHYSICAL_ADDRESS* physicalAddress
    )
{
    ULONG page = 0UL;
    PVOID virtualAddress = NULL;

    physicalAddress->QuadPart = 0LL;
    /* Refuse an index the pool cannot back rather than running past it. */
    if (state->pageBlock == NULL ||
        record >= state->leafCapacity ||
        level >= KSW_HVM_EPTSW_PATH_PAGES) {
        /* Return no page for an inadmissible request. */
        return NULL;
    }
    page = (record * KSW_HVM_EPTSW_PATH_PAGES) + level;
    if (page >= state->pageCount) {
        /* Return no page rather than running past the block. */
        return NULL;
    }
    virtualAddress = state->pageBlock + ((SIZE_T)page * (SIZE_T)PAGE_SIZE);
    *physicalAddress = MmGetPhysicalAddress(virtualAddress);
    /* Refuse a page whose physical address could not be resolved. */
    if (physicalAddress->QuadPart == 0LL) {
        /* Return no page rather than publishing address zero. */
        return NULL;
    }
    /* Return the page for the caller to fill. */
    return virtualAddress;
}

NTSTATUS
kswordArkHvmEptSwitchBuildLeaf(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG leafPhysical,
    _In_ ULONGLONG primaryEntry,
    _In_ ULONGLONG secondaryEntry,
    _In_ const volatile ULONGLONG* sharedPageTable,
    _Out_ ULONG* hierarchyIndex
    )
{
    KswHvmEptsw* state = NULL;
    KswHvmEptswHierarchy* record = NULL;
    PHYSICAL_ADDRESS physical[KSW_HVM_EPTSW_PATH_PAGES];
    PVOID level[KSW_HVM_EPTSW_PATH_PAGES];
    ULONGLONG* table = NULL;
    const ULONGLONG* sharedPml4 = NULL;
    const ULONGLONG* sharedPdpt = NULL;
    const ULONGLONG* sharedPd = NULL;
    ULONG pml4Index = 0UL;
    ULONG pdptIndex = 0UL;
    ULONG pdIndex = 0UL;
    ULONG ptIndex = 0UL;
    ULONG slot = 0UL;
    ULONG walk = 0UL;
    ULONG physicalBits = 0UL;

    /* Reject an incomplete caller contract before touching the pool. */
    if (runtime == NULL ||
        hierarchyIndex == NULL ||
        sharedPageTable == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *hierarchyIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    state = &runtime->eptSwitch;
    /* Only a reserved pool has anything to build into. */
    if (!state->active || state->pageBlock == NULL) {
        /* Return the exact state-contract failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    RtlZeroMemory(physical, sizeof(physical));
    RtlZeroMemory(level, sizeof(level));
    pml4Index = KswordArkHvmEptSwPml4Index(leafPhysical);
    pdptIndex = KswordArkHvmEptSwPdptIndex(leafPhysical);
    pdIndex = KswordArkHvmEptSwPdIndex(leafPhysical);
    ptIndex = KswordArkHvmEptSwPtIndex(leafPhysical);
    /*
     * Refuse a target the base hierarchy never populated.  Building a path
     * onto absent tables would produce a hierarchy that walks into zero
     * entries - an EPT misconfiguration whose exit tells you a bit is wrong
     * without telling you which.
     */
    if (pml4Index >= KSW_HVM_MAX_PML4_ENTRIES ||
        pdptIndex >= 512UL ||
        runtime->eptPml4 == NULL ||
        runtime->eptPdpt[pml4Index] == NULL ||
        runtime->eptPd[pml4Index][pdptIndex] == NULL) {
        /* Return the exact hierarchy-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Take the first free record; its pages are implied by its index. */
    for (slot = 0UL; slot < state->leafCapacity; ++slot) {
        if (!state->hierarchies[slot].active) {
            record = &state->hierarchies[slot];
            break;
        }
    }
    /* Report bounded capacity exhaustion. */
    if (record == NULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Resolve every page of this record's slice before writing any of them. */
    for (walk = 0UL; walk < KSW_HVM_EPTSW_PATH_PAGES; ++walk) {
        level[walk] = kswordArkHvmEptSwitchPage(
            state,
            slot,
            walk,
            &physical[walk]);
        if (level[walk] == NULL) {
            /* Return the exact bounded-resource failure. */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    sharedPml4 = (const ULONGLONG*)runtime->eptPml4;
    sharedPdpt = (const ULONGLONG*)runtime->eptPdpt[pml4Index];
    sharedPd = (const ULONGLONG*)runtime->eptPd[pml4Index][pdptIndex];
    /*
     * Copy each table wholesale, then repoint only the one entry on the path.
     * Everything the copies do not name stays shared with the base, which is
     * what keeps the cost four pages instead of a second full hierarchy - and
     * what makes "only this leaf differs" true by construction rather than by
     * an invariant somebody has to maintain.
     */
    RtlCopyMemory(level[0], sharedPml4, (SIZE_T)PAGE_SIZE);
    RtlCopyMemory(level[1], sharedPdpt, (SIZE_T)PAGE_SIZE);
    RtlCopyMemory(level[2], sharedPd, (SIZE_T)PAGE_SIZE);
    RtlCopyMemory(level[3], (const void*)sharedPageTable, (SIZE_T)PAGE_SIZE);
    /* Write the leaf first so no parent ever points at an unfinished table. */
    table = (ULONGLONG*)level[3];
    table[ptIndex] = secondaryEntry;
    /* Repoint the copied parents child-first, for the same reason. */
    table = (ULONGLONG*)level[2];
    table[pdIndex] = KswordArkHvmEptRebaseEntry(
        sharedPd[pdIndex],
        (ULONGLONG)physical[3].QuadPart);
    table = (ULONGLONG*)level[1];
    table[pdptIndex] = KswordArkHvmEptRebaseEntry(
        sharedPdpt[pdptIndex],
        (ULONGLONG)physical[2].QuadPart);
    table = (ULONGLONG*)level[0];
    table[pml4Index] = KswordArkHvmEptRebaseEntry(
        sharedPml4[pml4Index],
        (ULONGLONG)physical[1].QuadPart);
    /*
     * Derive the pointer from the base rather than composing it.  Composing
     * would give the memory type, the walk length and the accessed/dirty bit
     * a second source of truth; derived this way it is accepted by VM entry
     * exactly when the base pointer is, and an INVEPT descriptor built from
     * it matches the field the processor was loaded with.
     */
    record->eptPointer = KswordArkHvmEptSwRebaseEptp(
        runtime->eptPointer,
        (ULONGLONG)physical[0].QuadPart);
    /* Refuse a pointer the architecture would reject at VM entry. */
    physicalBits = kswordArkHvmEptSwitchPhysicalAddressBits();
    if (physicalBits == 0UL ||
        KswordArkHvmEptSwEptpIsWellFormed(
            record->eptPointer,
            runtime->vmxEptVpidCapabilities,
            physicalBits) != KSWORD_ARK_HVM_EPTSW_EPTP_OK) {
        RtlZeroMemory(record, sizeof(*record));
        /* Return the exact encoding failure. */
        return STATUS_INVALID_PARAMETER;
    }
    record->leafPhysical = leafPhysical;
    record->primaryEntry = primaryEntry;
    record->secondaryEntry = secondaryEntry;
    for (walk = 0UL; walk < KSW_HVM_EPTSW_PATH_PAGES; ++walk) {
        record->level[walk] = level[walk];
    }
    /* Publish into the flat ledger the switch planner indexes. */
    state->eptp[slot + 1UL] = record->eptPointer;
    /* Published last, for the same reason as the pool's own Active flag. */
    record->active = TRUE;
    state->builtCount += 1UL;
    /* Array index k-1 is hierarchy index k; index 0 is the base. */
    *hierarchyIndex = slot + 1UL;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEptSwitchVerifyLeaf(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONG hierarchyIndex
    )
{
    const KswHvmEptsw* state = NULL;
    const KswHvmEptswHierarchy* record = NULL;
    const ULONGLONG* table = NULL;
    ULONG slot = 0UL;
    ULONG physicalBits = 0UL;

    /* Reject an incomplete caller contract. */
    if (runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    state = &runtime->eptSwitch;
    /* The base is not a built hierarchy and has nothing to verify. */
    if (KswordArkHvmEptSwIndexIsBase(hierarchyIndex) ||
        hierarchyIndex > state->leafCapacity) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    slot = hierarchyIndex - 1UL;
    record = &state->hierarchies[slot];
    if (!record->active) {
        /* Return the exact state-contract failure. */
        return STATUS_NOT_FOUND;
    }
    /*
     * Walk the built hierarchy the way the processor would and require the
     * target leaf to read back as the secondary value.
     *
     * This is not a tautology: the write above went through level[3], while
     * this walk starts at level[0] and follows the rebased parent entries.
     * An index computed one level off, or a parent rebased to the wrong page,
     * produces a walk that lands somewhere else - and that failure has no
     * other symptom, because the hierarchy is still structurally valid and
     * the processor would happily use it.
     */
    /*
     * A **different** return code at each step.
     *
     * When five checks share a single code path, a single failure only reports 'verification failed' without pinpointing the cause, requiring either
     * added logging or a debugger to locate it. This path is only executed on physical hardware and only at the moment the view is installed.
     * These codes are used purely for discrimination here; their meaning is defined by this comment and should not be interpreted by their literal semantics.
     */
    /*
     * Use the mask to extract the address; **do not** use KswordArkHvmEptTablePointer — that is a **constructor**
     * (building a non-leaf entry from a physical address with 'Address | RWX'), not an extractor.
     * Use it as an extractor: the left side of the comparison always includes the extra RWX bits, so this condition never holds. The symptom
     * is that all constructed hierarchies fail validation, even though the construction itself is correct. This bug has occurred before.
     */
    table = (const ULONGLONG*)record->level[0];
    if ((table[KswordArkHvmEptSwPml4Index(record->leafPhysical)] &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) !=
        ((ULONGLONG)MmGetPhysicalAddress(record->level[1]).QuadPart &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) {
        /* PML4 entry does not point to a copy of the PDPT for this record. */
        return STATUS_INVALID_ADDRESS;
    }
    table = (const ULONGLONG*)record->level[1];
    if ((table[KswordArkHvmEptSwPdptIndex(record->leafPhysical)] &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) !=
        ((ULONGLONG)MmGetPhysicalAddress(record->level[2]).QuadPart &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) {
        /* PDPT entry does not point to the PD copy of this record. */
        return STATUS_INVALID_ADDRESS_COMPONENT;
    }
    table = (const ULONGLONG*)record->level[2];
    if ((table[KswordArkHvmEptSwPdIndex(record->leafPhysical)] &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK) !=
        ((ULONGLONG)MmGetPhysicalAddress(record->level[3]).QuadPart &
            KSWORD_ARK_HVM_EPTSW_PHYSICAL_MASK)) {
        /* PD entry does not point to a copy of this record's PT. */
        return STATUS_INVALID_ADDRESS_WILDCARD;
    }
    table = (const ULONGLONG*)record->level[3];
    if (table[KswordArkHvmEptSwPtIndex(record->leafPhysical)] !=
        record->secondaryEntry) {
        /* The leaf entry is not the written secondary value. */
        return STATUS_DATA_ERROR;
    }
    /*
     * Refuse a leaf the architecture would reject as a misconfiguration.
     *
     * Not a large page: this backend only ever relaxes a four-KiB leaf, which
     * is why the caller had to split the covering two-MiB entry first.
     * Execute-only support is passed from the measured capability rather than
     * assumed - it is the whole premise of the backend, and a leaf that drops
     * READ without it is exactly the encoding the processor refuses.
     */
    physicalBits = kswordArkHvmEptSwitchPhysicalAddressBits();
    if (physicalBits == 0UL ||
        KswordArkHvmEptSwLeafIsWellFormed(
            record->secondaryEntry,
            0,
            physicalBits,
            (runtime->vmxEptVpidCapabilities &
                KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL ? 1 : 0) !=
            KSWORD_ARK_HVM_EPTSW_LEAF_OK) {
        /* Return the exact encoding failure. */
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmEptSwitchReleaseLeaf(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG hierarchyIndex
    )
{
    KswHvmEptsw* state = NULL;
    KswHvmEptswHierarchy* record = NULL;

    /* Tolerate a missing runtime so every failure path can call this. */
    if (runtime == NULL) {
        /* Return without touching anything. */
        return;
    }
    state = &runtime->eptSwitch;
    /* Ignore the base and any index the ledger cannot name. */
    if (KswordArkHvmEptSwIndexIsBase(hierarchyIndex) ||
        hierarchyIndex > state->leafCapacity) {
        /* Return without touching anything. */
        return;
    }
    record = &state->hierarchies[hierarchyIndex - 1UL];
    if (!record->active) {
        /* Return without double-counting a record already released. */
        return;
    }
    /*
     * The pages stay in the pool - this record owns a fixed slice of it - so
     * only the ledger is cleared.  Zeroed rather than flag-cleared: a stale
     * EptPointer would name a hierarchy nobody maintains any more, and the
     * one thing that must never happen is loading it.
     */
    RtlZeroMemory(record, sizeof(*record));
    /*
     * Clear the ledger slot in the same breath.  A pointer left here would
     * name a hierarchy whose record is gone, and the one thing that must
     * never happen is the processor being loaded with it.
     */
    state->eptp[hierarchyIndex] = 0ULL;
    if (state->builtCount != 0UL) {
        state->builtCount -= 1UL;
    }
}

NTSTATUS
kswordArkHvmEptSwitchPlanViolation(
    _In_ const KswHvmRuntime* runtime,
    _Inout_ KSWORD_ARK_HVM_EPTSW_PROGRESS* progress,
    _In_ ULONG activeIndex,
    _In_ ULONG leafSlot,
    _In_ ULONG access,
    _In_ ULONG kind,
    _In_ ULONGLONG guestRip,
    _In_ ULONGLONG guestPhysical,
    _Out_ ULONG* nextIndex,
    _Out_ ULONGLONG* targetEptp
    )
{
    const KswHvmEptsw* state = NULL;
    KSWORD_ARK_HVM_EPTSW_TRANSITION transition;
    int executeOnly = 0;

    /* Reject an incomplete caller contract before deciding anything. */
    if (runtime == NULL ||
        progress == NULL ||
        nextIndex == NULL ||
        targetEptp == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *nextIndex = KSWORD_ARK_HVM_EPTSW_INDEX_BASE;
    *targetEptp = 0ULL;
    state = &runtime->eptSwitch;
    /* Only a reserved runtime has a ledger to plan against. */
    if (!state->active) {
        /* Return the exact state-contract failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    RtlZeroMemory(&transition, sizeof(transition));
    executeOnly =
        (runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL
            ? 1
            : 0;
    /*
     * Decide and resolve in one shared-header call.  Nothing here re-derives
     * a permission or an index: the whole point of that header is that this
     * arithmetic has exactly one implementation, shared with the offline
     * tests, because every way of getting it wrong is symptomless at run time.
     */
    if (KswordArkHvmEptSwPlanSwitch(
            state->eptp,
            state->hierarchyCount,
            activeIndex,
            leafSlot,
            state->leafCapacity,
            access,
            kind,
            executeOnly,
            &transition) != KSWORD_ARK_HVM_EPTSW_OUTCOME_SWITCH) {
        /*
         * Refused.  Every refusal reason names a case that would otherwise be
         * a silent hang or a silent leak, so the caller must fail closed -
         * the same path a failed leaf flip takes today - rather than switch
         * anyway and hope the next exit resolves it.
         */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * Forward progress is a **precondition of the write**, stated as such by
     * the planner's contract.  It cannot be folded into the planner: that is
     * a pure function seeing one violation, and the combination that hangs -
     * an instruction whose fetch needs one leaf's secondary value while its
     * operand needs another's - has two halves that are each perfectly
     * serviceable.  The planner would return SWITCH forever while RIP never
     * advances, and the machine would stop with no bugcheck, no event and no
     * log.
     */
    if (!KswordArkHvmEptSwProgressAdmit(
            progress,
            guestRip,
            guestPhysical,
            transition.NextIndex)) {
        /* Return the exact non-progress failure. */
        return STATUS_POSSIBLE_DEADLOCK;
    }
    *nextIndex = transition.NextIndex;
    *targetEptp = transition.TargetEptp;
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmEptSwitchRelease(
    _Inout_ KswHvmRuntime* runtime
    )
{
    KswHvmEptsw* state = NULL;

    /* Tolerate a missing runtime so teardown paths need no extra guard. */
    if (runtime == NULL) {
        /* Return without touching anything. */
        return;
    }
    state = &runtime->eptSwitch;
    /*
     * One allocation backs every hierarchy, so one free releases all of them.
     * ExFreePool is legal at DISPATCH_LEVEL, which matters because this runs
     * from a teardown path a power callback can reach.
     */
    if (state->pageBlock != NULL) {
        ExFreePool(state->pageBlock);
    }
    /*
     * Zero the whole record rather than clearing selected members.  A stale
     * EptPointer left behind here would be loaded by a later residency and
     * would name freed memory - a fault with no error path, because the
     * processor takes it during VM entry.
     */
    RtlZeroMemory(state, sizeof(*state));
}

NTSTATUS
kswordArkHvmEptSwitchReserve(
    _Inout_ KswHvmRuntime* runtime
    )
{
    KswHvmEptsw* state = NULL;
    ULONG leafCapacity = 0UL;
    ULONG hierarchyCount = 0UL;
    ULONG baseCount = 0UL;
    ULONGLONG pageCost = 0ULL;

    /* Reject an incomplete caller contract before allocating anything. */
    if (runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    state = &runtime->eptSwitch;
    /*
     * Refuse a second reservation rather than leaking the first.  The caller
     * is prepare, which already refuses to run while RESOURCES_READY is set,
     * so reaching here twice means an ordering bug worth surfacing.
     */
    if (state->active) {
        /* Return the exact state-contract failure. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Only an armed runtime has anything to reserve. */
    if (!runtime->eptpSwitchArmed) {
        /* Return the exact state-contract failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * The base hierarchy must exist first: every secondary hierarchy is a
     * copy of one path through it, and its pointer is derived from the base
     * pointer rather than composed from constants.
     */
    if (runtime->eptPointer == 0ULL || runtime->eptPml4 == NULL) {
        /* Return the exact state-contract failure. */
        return STATUS_DEVICE_NOT_READY;
    }
    leafCapacity = KSWORD_ARK_HVM_EPTSW_MAX_LEAVES;
    /*
     * Shared base, so exactly one - and therefore the whole cost is
     * independent of the processor count.  Passed explicitly rather than
     * hard-coded to 1 so the composed case has one place to change if the
     * mutual exclusion with per-processor EPT is ever lifted.
     */
    baseCount = KswordArkHvmEptSwBaseCount(
        0,
        runtime->processorCount);
    hierarchyCount = KswordArkHvmEptSwHierarchyCount(leafCapacity);
    pageCost = KswordArkHvmEptSwSecondaryPageCost(
        baseCount,
        leafCapacity);
    /*
     * Both helpers report an inadmissible request as zero, which is why they
     * are checked before the budget rather than folded into it: zero fits any
     * budget, so a folded check would accept exactly the cases meant to be
     * refused.
     */
    if (hierarchyCount == 0UL || pageCost == 0ULL) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordArkHvmEptSwFitsBudget(
            pageCost,
            KSW_HVM_EPTSW_MAX_PAGES)) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Refuse a cost that cannot be expressed in the cursor's width. */
    if (pageCost > (ULONGLONG)MAXULONG) {
        /* Return the exact bounded-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* One allocation for every hierarchy, for the reason in the header. */
    state->pageBlock = (PUCHAR)kswordArkAllocateNonPagedPool(
        (SIZE_T)pageCost * (SIZE_T)PAGE_SIZE,
        KSW_HVM_EPTSW_POOL_TAG);
    if (state->pageBlock == NULL) {
        /* Return the exact nonpaged-resource failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(
        state->pageBlock,
        (SIZE_T)pageCost * (SIZE_T)PAGE_SIZE);
    state->pageCount = (ULONG)pageCost;
    state->reserved2 = 0UL;
    state->leafCapacity = leafCapacity;
    state->hierarchyCount = hierarchyCount;
    state->builtCount = 0UL;
    /*
     * Slot 0 is the base, and it is the pointer the processor is already
     * running on.  Published here rather than at the first switch so the
     * ledger is complete the moment it exists: a planner that finds slot 0
     * empty would have to invent a "return to base" target, and inventing it
     * is exactly how the base and the VMCS come to disagree.
     */
    state->eptp[KSWORD_ARK_HVM_EPTSW_INDEX_BASE] = runtime->eptPointer;
    /*
     * Published last.  Every reader treats Active as "the page pool exists
     * and the ledger is consistent", so setting it before the fields above
     * would let a concurrent teardown free a block the ledger still counts.
     */
    state->active = TRUE;
    return STATUS_SUCCESS;
}

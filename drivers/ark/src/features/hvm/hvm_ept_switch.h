/*
 * hvm_ept_switch.h
 *
 * Driver-side entry point for the 'EPTP switch' decoupled view backend.
 *
 * Pure arithmetic, bit layout, and the switch state machine reside in shared/driver/KswordArkHvmEptSwitch.h, where
 * the kernel and host unit tests share the same implementation. This module contains only the side-effecting half:
 * page pool, hierarchical construction, EPTP ledger, and release. The state structure KswHvmEptsw is defined in
 * hvm_internal.h, grouped with other runtime-embedded records (view slots, MSR policy slots).
 *
 * The relationship with hvm_ept_local is **mutually exclusive**, not additive. Both address the issue of "ensuring a flipped leaf is
 * not visible to other processors," but use opposite approaches: the private layer restricts **writes** to the leaf to a single
 * processor, whereas this backend does not write to the leaf at runtime at all. Instead, it swaps the EPT_POINTER in the current
 * processor's VMCS to point to a complete hierarchy with different content, differing only in a single leaf. The protocol layer
 * rejects simultaneous requests for both (in hvm_runtime.c) before any allocation, so this module can assume LocalEptArmed is false.
 *
 * The **sole reason** this backend exists is capability, not performance: the write-leaf + monitor-trap
 * approach requires the Monitor Trap Flag, which nested Hyper-V does not expose to the guest; this
 * approach requires execute-only EPT leaves, which have been verified as available on the same machine.
 */

#pragma once

#include "hvm_internal.h"

/* The type of the forward-looking ledger appears in the interface below and must be the one **actually** defined in the shared header. */
#include "driver/KswordArkHvmEptSwitch.h"

EXTERN_C_START

/*
 * Reserve the page pool and establish the ledger, **without constructing any sub-layers**.
 *
 * Called after the base EPT is built in PREPARE, and only when EptpSwitchArmed is true.
 * Reject the reservation before allocating a single page if the budget is insufficient;
 * failing mid-allocation would leave a fragmented machine stuck in an undefined startup state.
 */
NTSTATUS
kswordArkHvmEptSwitchReserve(
    _Inout_ KswHvmRuntime* runtime
    );

/*
 * Constructs a set of sub-levels for a single leaf and returns its level index (1..LeafCapacity, 0 is the base).
 *
 * Copy the four tables from root to leaf, modify only the item on the path to point to the copy, and write the leaf itself as a secondary value.
 * Everything not explicitly named in the copy remains shared with the base. This is why the 'only this leaf
 * differs' property holds constructively, and why the overhead is only four pages instead of a full hierarchy.
 *
 * SharedPageTable is the 4KiB page table in the base that covers this leaf (from EPT split). The caller must ensure
 * the split exists first: performing a split here would allocate pages from the shared ledger while holding the pool.
 */
NTSTATUS
kswordArkHvmEptSwitchBuildLeaf(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG leafPhysical,
    _In_ ULONGLONG primaryEntry,
    _In_ ULONGLONG secondaryEntry,
    _In_ const volatile ULONGLONG* sharedPageTable,
    _Out_ ULONG* hierarchyIndex
    );

/*
 * Verify a constructed hierarchy by traversing the processor table.
 *
 * **Not a tautology**: the write path uses level[3], while the verification traverses down from level[0] along the modified
 * parent. An off-by-one index error or a parent redirected to the wrong page will cause this traversal to land elsewhere. Such
 * errors have **no other symptoms**: the hierarchy remains structurally valid, and the processor will use it without issue.
 */
NTSTATUS
kswordArkHvmEptSwitchVerifyLeaf(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONG hierarchyIndex
    );

/*
 * Calculate which hierarchy level to switch to for this EPT violation and record this transition in the processor's progress log.
 *
 * Return: If STATUS_SUCCESS, *TargetEptp is the value to write into VMCS.
 * Return: Any failure must follow the fail-closed path (same as today's
 * 'flip-fail' path); do not switch over and wait for the next exit to resolve it:
 *
 *   STATUS_NOT_SUPPORTED —— The planner rejects. Each rejection reason corresponds
 *                                to an input that would otherwise cause a silent deadlock or silent leak.
 *   STATUS_POSSIBLE_DEADLOCK — This switch yields no forward progress. Typical cause: an instruction's
 *                                fetch and its operands require values from two different view pages; since both halves can be
 *                                serviced, the system enters an infinite switch loop while the RIP remains stationary.
 *
 * This function only performs decision-making and accounting; it **does not touch VMCS nor issue INVEPT**.
 */
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
    );

/* Release a set of sub-level ledgers. Pages remain in the pool (records own fixed slices); can be called repeatedly. */
VOID
kswordArkHvmEptSwitchReleaseLeaf(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG hierarchyIndex
    );

/*
 * Release the page pool and reset the ledger to a committed state. This function is safe to call multiple times
 * and tolerates a NULL Runtime, ensuring that no extra guards are needed for every failure or teardown path.
 */
VOID
kswordArkHvmEptSwitchRelease(
    _Inout_ KswHvmRuntime* runtime
    );

EXTERN_C_END

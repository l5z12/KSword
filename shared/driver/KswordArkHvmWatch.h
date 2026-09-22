/*
 * KswordArkHvmWatch.h
 *
 * The first access to EPT WATCH_ONCE covers the few cases where miscalculations do not raise errors
 * but silently produce incorrect results. The inclusion criteria match KswordArkHvmEptSwitch.h: pure
 * input-to-output operations with no side effects, where errors are difficult to detect immediately.
 *
 * ------------------------------------------------------------------
 * What is this mechanism?
 * ------------------------------------------------------------------
 *
 * Remove a specific permission from the target page. On the next access causing a VM-exit, record the context, then permanently
 * restore the permission, invalidate the translation, and VMRESUME without advancing RIP—re-executing the original instruction
 * to completion normally, allowing the resident process to continue. This is equivalent to 'ALLOW_ONCE' minus the step of
 * revoking the permission, so Monitor Trap Flag (MTF) is unnecessary, enabling operation on nested targets without MTF support.
 *
 * ------------------------------------------------------------------
 * Why these matters must be proven on the build machine
 * ------------------------------------------------------------------
 *
 * None of the three error types have a diagnostic interface:
 *
 *   - **Incorrect permission normalization**: On the EPT architecture, there are no leaf entries that are 'writable
 *     but not readable', nor can every processor encode 'execute-only'. Writing the user-requested mask directly into a
 *     leaf entry produces an invalid leaf, manifesting as an EPT misconfiguration exit (exit reason 49) on a subsequent
 *     access. This exit only indicates that one bit is incorrect, not which bit. If normalization is over-applied, the
 *     situation is worse: the monitored scope silently becomes larger than the user expects, with no warning.
 *
 *   - **Incorrect decision for multi-core first-hit**: When two processors simultaneously hit the same page
 *     and both believe they are the first, the user sees two contradictory "first access" events. If the losing
 *     party simply performs a VMRESUME without fixing its own view, it will repeat the violation indefinitely
 *     until the fix propagates to it—a livelock with no error code. Neither outcome produces any output.
 *
 *   - **Range calculation error**: EPT monitors entire pages, while users often care about only a few bytes within a page.
 *     The consequence of a check failure isn't a crash, but a conclusion that looks perfectly correct but may be entirely
 *     irrelevant: "Your target was accessed." Such errors only mislead the debugging direction, preventing discovery.
 *
 * This header is shared between C and C++: the VM-exit path in the driver and the offline test link on
 * the build machine use the same implementation, so tests prove the exact code running in the kernel.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Bitwise identical to KSWORD_ARK_HVM_EPT_ACCESS_* in KswordArkHvmIoctl.h. */
#define KSW_HVM_WATCH_ACCESS_READ    0x00000001UL
#define KSW_HVM_WATCH_ACCESS_WRITE   0x00000002UL
#define KSW_HVM_WATCH_ACCESS_EXECUTE 0x00000004UL

/* Bitwise identical to KSW_EPT_* in hvm_internal.h. */
#define KSW_HVM_WATCH_LEAF_READ    0x1ULL
#define KSW_HVM_WATCH_LEAF_WRITE   0x2ULL
#define KSW_HVM_WATCH_LEAF_EXECUTE 0x4ULL

/* Values match exactly with KSWORD_ARK_HVM_EPT_WATCH_STATE_* in KswordArkHvmIoctl.h. */
#define KSW_HVM_WATCH_STATE_NONE        0UL
#define KSW_HVM_WATCH_STATE_ARMED       1UL
#define KSW_HVM_WATCH_STATE_TRIGGERED   2UL
#define KSW_HVM_WATCH_STATE_DISARMED    3UL
#define KSW_HVM_WATCH_STATE_INVALIDATED 4UL
#define KSW_HVM_WATCH_STATE_FAULTED     5UL

/*
 * Hit handling plan for a single match.
 *
 * The three bits answer three independent questions, not a single 'success/failure' outcome:
 *
 *   Accepted: Whether this state can continue along the hit path. If
 *                not, the caller must fail-closed rather than guessing a disposition.
 *   OwnsFirstHit: Is this processor the sole first-hit owner? Only it
 *                records evidence, advances the lifecycle, and publishes events.
 *   MustRepair: Whether to restore this page's permissions and invalidate our own context.
 *
 * The key point is that MustRepair and OwnsFirstHit are not the same thing: a processor that loses the atomic
 * conversion must also repair its own view. If only the winner repairs, the loser will repeatedly collide
 * with the same instruction before the winner's write propagates to it—a livelock that prints nothing.
 */
typedef struct _KSW_HVM_WATCH_HIT_PLAN
{
    unsigned char Accepted;
    unsigned char OwnsFirstHit;
    unsigned char MustRepair;
    unsigned char Reserved;
} KSW_HVM_WATCH_HIT_PLAN;

/*
 * normalize the user-requested access mask into an architecture-valid EPT deny mask.
 *
 * Two hard constraints:
 *   1. Traditional EPT does not allow W=1 with R=0. Therefore, removing read access requires removing
 *      write access as well — otherwise, the remaining leaf entry would be R=0/W=1, which is illegal.
 *   2. Execute-only leaf entries are not supported on all processors. If unsupported, read must
 *      be removed along with execute; otherwise, the remaining state (R=0/W=0/X=1) is also illegal.
 *
 * The return value is necessarily a superset of the input: normalization only expands the monitoring
 * scope, never shrinks it. The caller must retain both the request value and the return value; displaying
 * only one would either alter the user's request or falsely claim finer monitoring than actually provided.
 */
static __inline unsigned long
KswordArkHvmWatchNormalizeAccess(
    unsigned long RequestedAccess,
    int ExecuteOnlySupported
    )
{
    unsigned long effective = RequestedAccess &
        (KSW_HVM_WATCH_ACCESS_READ |
         KSW_HVM_WATCH_ACCESS_WRITE |
         KSW_HVM_WATCH_ACCESS_EXECUTE);

    /* Return as-is when no valid bits exist; validity is rejected by the caller in an earlier step. */
    if (effective == 0UL) {
        return 0UL;
    }
    if ((effective & KSW_HVM_WATCH_ACCESS_READ) != 0UL) {
        /* Prevent the architecturally invalid 'writable but not readable' state. */
        effective |= KSW_HVM_WATCH_ACCESS_WRITE;
        if (!ExecuteOnlySupported) {
            /* This processor cannot encode execute-only leaf entries; it must degrade to marking the entire page inaccessible. */
            effective |= KSW_HVM_WATCH_ACCESS_EXECUTE;
        }
    }
    return effective;
}

/*
 * Remove permission bits from the leaf item using a denial mask.
 *
 * Only clears bits, never sets them: this function expresses 'removal'; any 'accidental
 * bit-setting' would silently allow an access that should have been blocked.
 */
static __inline unsigned long long
KswordArkHvmWatchApplyDenial(
    unsigned long long Leaf,
    unsigned long DeniedAccess
    )
{
    unsigned long long value = Leaf;

    if ((DeniedAccess & KSW_HVM_WATCH_ACCESS_READ) != 0UL) {
        value &= ~KSW_HVM_WATCH_LEAF_READ;
    }
    if ((DeniedAccess & KSW_HVM_WATCH_ACCESS_WRITE) != 0UL) {
        value &= ~KSW_HVM_WATCH_LEAF_WRITE;
    }
    if ((DeniedAccess & KSW_HVM_WATCH_ACCESS_EXECUTE) != 0UL) {
        value &= ~KSW_HVM_WATCH_LEAF_EXECUTE;
    }
    return value;
}

/*
 * Restore a leaf entry to a baseline with 'no rejections'.
 *
 * Only modify the R/W/X bits; preserve all other bits (page frame, memory type, large page
 * bit, suppress-#VE) as-is. Changing the memory type during permission restoration causes
 * an EPT misconfiguration, and the resulting exit does not indicate which bit is incorrect.
 */
static __inline unsigned long long
KswordArkHvmWatchRestoreLeaf(
    unsigned long long Leaf
    )
{
    return Leaf |
        KSW_HVM_WATCH_LEAF_READ |
        KSW_HVM_WATCH_LEAF_WRITE |
        KSW_HVM_WATCH_LEAF_EXECUTE;
}

/*
 * Decide who bears this hit.
 *
 * PreviousState is the value read before the atomic transition from ARMED to TRIGGERED:
 *
 *   ARMED: This processor won; it is the sole first-hit owner.
 *   TRIGGERED: Another processor is handling the same first hit; this core only fixes its own view.
 *   DISARMED: The first trigger has been handled; this core hit an old translation that hasn't expired yet; fix only.
 *   Remaining hit-path states that cannot be explained (never armed, invalidated, or installation
 *                failed) must not be assigned a specific handling policy; instead, they are handled via fail-closed.
 */
static __inline KSW_HVM_WATCH_HIT_PLAN
KswordArkHvmWatchPlanHit(
    unsigned long PreviousState
    )
{
    KSW_HVM_WATCH_HIT_PLAN plan;

    plan.Accepted = 0U;
    plan.OwnsFirstHit = 0U;
    plan.MustRepair = 0U;
    plan.Reserved = 0U;
    if (PreviousState == KSW_HVM_WATCH_STATE_ARMED) {
        plan.Accepted = 1U;
        plan.OwnsFirstHit = 1U;
        plan.MustRepair = 1U;
        return plan;
    }
    if (PreviousState == KSW_HVM_WATCH_STATE_TRIGGERED ||
        PreviousState == KSW_HVM_WATCH_STATE_DISARMED) {
        /*
         * The loser must also be repaired. Otherwise, if only VMRESUME occurs, it will repeatedly trigger violations until the
         * winner's recovery propagates to it, resulting in a livelock with no error code, no logs, and no self-termination.
         */
        plan.Accepted = 1U;
        plan.MustRepair = 1U;
        return plan;
    }
    return plan;
}

/*
 * Check if a hit falls within the specific byte range of actual user interest.
 *
 * This is a refinement of attribution, not filtering: regardless of whether the match falls within the range, a hit must
 * be reported. Hardware monitors entire pages; describing it otherwise would be describing an event that did not occur.
 *
 * When GlaValid is false, always return 0. The caller must represent this state as
 * "unable to determine" rather than "out of range": the processor not reporting a
 * linear address is a different fact from reporting an address out of range.
 */
static __inline int
KswordArkHvmWatchRangeMatch(
    int GlaValid,
    unsigned long long GuestLinearAddress,
    unsigned long long RequestedAddress,
    unsigned long long RequestedLength
    )
{
    if (!GlaValid ||
        RequestedLength == 0ULL) {
        return 0;
    }
    /*
     * Reject intervals that would wrap around instead of allowing them to match half the address space.
     *
     * The criterion is written as (length - 1) > (~0 - base) rather than base > ~0 - length: the latter would cause
     * Reject intervals that **exactly reach the end of the address space** as well (when
     * base=0xFF..F8 and length=8, end overflows to 0), even though that is a completely valid
     * interval. Treating a valid interval as "out of range" is precisely the type of error this
     * feature must never produce. Since length is non-zero, subtracting one will not underflow.
     */
    if (RequestedLength - 1ULL > ~0ULL - RequestedAddress) {
        return 0;
    }
    /*
     * Use subtraction for comparison instead of calculating 'end' first: the interval is proven not to wrap,
     * and subtraction never overflows for any input, ensuring the last cell correctly falls within the range.
     */
    if (GuestLinearAddress < RequestedAddress) {
        return 0;
    }
    return (GuestLinearAddress - RequestedAddress) < RequestedLength ? 1 : 0;
}

#ifdef __cplusplus
}
#endif

// Offline test for the first access watch (EPT WATCH_ONCE, shared/driver/KswordArkHvmWatch.h).
//
// The four items under test share a common trait: **calculation errors do not trigger exceptions**.
//
//   * If permission normalization is too low, the leaf architecture becomes invalid, manifesting as an anonymous
//     exit reason 49; if too high, the monitored scope silently exceeds user expectations with no warning.
//   * Incorrect multi-core first-touch resolution may result in two contradictory 'first access' events,
//     or cause the competing processor to enter a livelock without an error code that never terminates.
//   * Manually modifying bits other than R/W/X in the leaf results in exactly one exit reason 49.
//   * Range calculation error: instead of a crash, it yields a conclusion that reads
//     perfectly correct but is actually completely irrelevant: "Your target was accessed".
//
// Thus, they can only be verified on the build machine. The assertion principle is consistent with HvmEptSwitchTests.cpp:
//   * Expected values are hardcoded via manual calculation, never reverse-calculated from the function under test;
//   * The state machine performs exhaustive checks; states that should not be accepted must be explicitly rejected.
//   * Test both sides of the boundary; testing only one side is equivalent to not testing at all.

#include "TestSupport.h"

#include "../../../shared/driver/KswordArkHvmWatch.h"

#include <cstdint>

namespace {

// A typical 4 KiB identity leaf: Frame 0x12345000, RWX (0x7), WB (6<<3 = 0x30),
// suppress-#VE (bit 63). Low byte = 0x7 | 0x30 = 0x37.
constexpr std::uint64_t kLeafRwx = 0x8000000012345037ULL;
// Remove the R/W/X bits from the same leaf: 0x37 & ~0x7 = 0x30.
constexpr std::uint64_t kLeafNoAccess = 0x8000000012345030ULL;

// ---------------------------------------------------------------------------
// Permission normalization
// ---------------------------------------------------------------------------
void testNormalizeAccess(ksword_tests::Suite& suite) {
    // Write and execute do not trigger any side effects: each is a valid independent denial.
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_WRITE, 1) ==
            KSW_HVM_WATCH_ACCESS_WRITE,
        L"watch normalize: write alone stays write (execute-only supported)");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_WRITE, 0) ==
            KSW_HVM_WATCH_ACCESS_WRITE,
        L"watch normalize: write alone stays write (no execute-only)");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_EXECUTE, 1) ==
            KSW_HVM_WATCH_ACCESS_EXECUTE,
        L"watch normalize: execute alone stays execute (execute-only supported)");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_EXECUTE, 0) ==
            KSW_HVM_WATCH_ACCESS_EXECUTE,
        L"watch normalize: execute alone stays execute (no execute-only)");
    // Write + Execute also does not trigger side effects: the remaining leaf is R=1/W=0/X=0, which is valid.
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(
            KSW_HVM_WATCH_ACCESS_WRITE | KSW_HVM_WATCH_ACCESS_EXECUTE, 0) ==
            (KSW_HVM_WATCH_ACCESS_WRITE | KSW_HVM_WATCH_ACCESS_EXECUTE),
        L"watch normalize: write+execute needs no widening");

    // Read implies write: EPT does not support W=1/R=0.
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_READ, 1) ==
            (KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_WRITE),
        L"watch normalize: read widens to read+write with execute-only");
    // When execute-only capability is absent, read access must include execute; otherwise, R=0/W=0/X=1 remains invalid.
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(KSW_HVM_WATCH_ACCESS_READ, 0) ==
            (KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_WRITE |
             KSW_HVM_WATCH_ACCESS_EXECUTE),
        L"watch normalize: read widens to all three without execute-only");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(
            KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_EXECUTE, 1) ==
            (KSW_HVM_WATCH_ACCESS_READ | KSW_HVM_WATCH_ACCESS_WRITE |
             KSW_HVM_WATCH_ACCESS_EXECUTE),
        L"watch normalize: read+execute widens to all three");

    // Normalization can only expand, never shrink: intersect with input per combination.
    for (unsigned long requested = 1UL; requested <= 7UL; ++requested) {
        for (int executeOnly = 0; executeOnly <= 1; ++executeOnly) {
            const unsigned long kEffective =
                KswordArkHvmWatchNormalizeAccess(requested, executeOnly);
            suite.expect(
                (kEffective & requested) == requested,
                L"watch normalize: result is a superset of the request");
            suite.expect(
                (kEffective & ~7UL) == 0UL,
                L"watch normalize: result carries no bit outside r/w/x");
            // Normalization is idempotent: re-normalizing cannot increase it further.
            suite.expect(
                KswordArkHvmWatchNormalizeAccess(kEffective, executeOnly) ==
                    kEffective,
                L"watch normalize: idempotent");
            // The result must be a valid remaining permission combination. Removing all RWX permissions is
            //legal (indicating the entire page is inaccessible); the only illegal case is R=0 while W=1.
            const bool kReadDenied =
                (kEffective & KSW_HVM_WATCH_ACCESS_READ) != 0UL;
            const bool kWriteDenied =
                (kEffective & KSW_HVM_WATCH_ACCESS_WRITE) != 0UL;
            suite.expect(
                !kReadDenied || kWriteDenied,
                L"watch normalize: denying read always denies write");
            const bool kExecuteDenied =
                (kEffective & KSW_HVM_WATCH_ACCESS_EXECUTE) != 0UL;
            suite.expect(
                executeOnly != 0 || !kReadDenied || kExecuteDenied,
                L"watch normalize: without execute-only, denying read denies execute");
        }
    }

    // Undefined bits are always discarded and never passed down as a fourth permission.
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(0xFFFFFFF8UL, 1) == 0UL,
        L"watch normalize: unknown bits alone normalize to zero");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(
            0xFFFFFFF0UL | KSW_HVM_WATCH_ACCESS_WRITE, 1) ==
            KSW_HVM_WATCH_ACCESS_WRITE,
        L"watch normalize: unknown bits are dropped, known bits survive");
    suite.expect(
        KswordArkHvmWatchNormalizeAccess(0UL, 1) == 0UL,
        L"watch normalize: empty request stays empty");
}

// ---------------------------------------------------------------------------
// Leaf arithmetic
// ---------------------------------------------------------------------------
void testLeafArithmetic(ksword_tests::Suite& suite) {
    // Removing write clears only bit 1: 0x37 & ~0x2 = 0x35.
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, KSW_HVM_WATCH_ACCESS_WRITE) ==
            0x8000000012345035ULL,
        L"watch leaf: denying write clears bit 1 only");
    // Removing execute clears only bit 2: 0x37 & ~0x4 = 0x33.
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, KSW_HVM_WATCH_ACCESS_EXECUTE) ==
            0x8000000012345033ULL,
        L"watch leaf: denying execute clears bit 2 only");
    // Remove read-only bit 0: 0x37 & ~0x1 = 0x36. Normalization of responsibility does not lie with this function;
    // it simply expresses "remove according to mask," so a single read denial is **intentionally** allowed here.
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, KSW_HVM_WATCH_ACCESS_READ) ==
            0x8000000012345036ULL,
        L"watch leaf: denying read clears bit 0 only");
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, 7UL) == kLeafNoAccess,
        L"watch leaf: denying all three clears exactly r/w/x");
    // Empty mask changes nothing.
    suite.expect(
        KswordArkHvmWatchApplyDenial(kLeafRwx, 0UL) == kLeafRwx,
        L"watch leaf: an empty denial changes nothing");
    // The page frame, memory type, large page bit, and suppress-#VE bit must not be modified.
    suite.expect(
        (KswordArkHvmWatchApplyDenial(kLeafRwx, 7UL) & ~7ULL) ==
            (kLeafRwx & ~7ULL),
        L"watch leaf: denial never touches a bit outside r/w/x");

    // Restore sets only the three bits; others remain unchanged.
    suite.expect(
        KswordArkHvmWatchRestoreLeaf(kLeafNoAccess) == kLeafRwx,
        L"watch leaf: restore adds exactly r/w/x back");
    suite.expect(
        KswordArkHvmWatchRestoreLeaf(kLeafRwx) == kLeafRwx,
        L"watch leaf: restoring an unrestricted leaf is idempotent");
    suite.expect(
        (KswordArkHvmWatchRestoreLeaf(kLeafNoAccess) & ~7ULL) ==
            (kLeafNoAccess & ~7ULL),
        L"watch leaf: restore never touches a bit outside r/w/x");
    // Restoring a zero-filled leaf (unmapped slot) yields only 0x7; no page frames are created out of thin air.
    suite.expect(
        KswordArkHvmWatchRestoreLeaf(0ULL) == 7ULL,
        L"watch leaf: restoring an empty entry yields exactly r/w/x");

    // Removing and restoring must return to the original value: this property ensures the original access completes in the hit path.
    for (unsigned long denied = 0UL; denied <= 7UL; ++denied) {
        suite.expect(
            KswordArkHvmWatchRestoreLeaf(
                KswordArkHvmWatchApplyDenial(kLeafRwx, denied)) == kLeafRwx,
            L"watch leaf: deny then restore round-trips to the original leaf");
    }
}

// ---------------------------------------------------------------------------
// Multi-core first-hit resolution: Exhaust all six states.
// ---------------------------------------------------------------------------
void testPlanHit(ksword_tests::Suite& suite) {
    // ARMED: The sole winner. Records evidence and updates the view.
    const KSW_HVM_WATCH_HIT_PLAN kArmed =
        KswordArkHvmWatchPlanHit(KSW_HVM_WATCH_STATE_ARMED);
    suite.expect(kArmed.Accepted == 1U,
        L"watch plan: armed is accepted");
    suite.expect(kArmed.OwnsFirstHit == 1U,
        L"watch plan: armed owns the first hit");
    suite.expect(kArmed.MustRepair == 1U,
        L"watch plan: armed repairs its own view");

    // TRIGGERED: Loser. The view **must** be updated, but a second "first time" record is strictly forbidden.
    const KSW_HVM_WATCH_HIT_PLAN kTriggered =
        KswordArkHvmWatchPlanHit(KSW_HVM_WATCH_STATE_TRIGGERED);
    suite.expect(kTriggered.Accepted == 1U,
        L"watch plan: triggered is accepted");
    suite.expect(kTriggered.OwnsFirstHit == 0U,
        L"watch plan: triggered never owns a second first hit");
    suite.expect(kTriggered.MustRepair == 1U,
        L"watch plan: triggered still repairs its own view");

    // DISARMED: The first hit has already been processed; this core's collision involves an old translation that hasn't expired. Only repair.
    const KSW_HVM_WATCH_HIT_PLAN kDisarmed =
        KswordArkHvmWatchPlanHit(KSW_HVM_WATCH_STATE_DISARMED);
    suite.expect(kDisarmed.Accepted == 1U,
        L"watch plan: disarmed is accepted");
    suite.expect(kDisarmed.OwnsFirstHit == 0U,
        L"watch plan: disarmed owns no first hit");
    suite.expect(kDisarmed.MustRepair == 1U,
        L"watch plan: disarmed still repairs its own view");

    // Three unexplainable states must be explicitly rejected and handed to fail-closed, rather than guessing a disposition.
    const unsigned long kRejected[] = {
        KSW_HVM_WATCH_STATE_NONE,
        KSW_HVM_WATCH_STATE_INVALIDATED,
        KSW_HVM_WATCH_STATE_FAULTED,
    };
    for (const unsigned long kState : kRejected) {
        const KSW_HVM_WATCH_HIT_PLAN kPlan =
            KswordArkHvmWatchPlanHit(kState);
        suite.expect(kPlan.Accepted == 0U,
            L"watch plan: an unexplainable state is refused");
        suite.expect(kPlan.OwnsFirstHit == 0U,
            L"watch plan: a refused state owns no first hit");
        suite.expect(kPlan.MustRepair == 0U,
            L"watch plan: a refused state repairs nothing");
    }
    // Values outside the protocol are rejected rather than falling into a branch.
    for (unsigned long state = 6UL; state <= 12UL; ++state) {
        suite.expect(
            KswordArkHvmWatchPlanHit(state).Accepted == 0U,
            L"watch plan: an out-of-protocol state is refused");
    }
    suite.expect(
        KswordArkHvmWatchPlanHit(0xFFFFFFFFUL).Accepted == 0U,
        L"watch plan: the maximum state value is refused");

    // Global invariant: If accepted, the view must be updated; if not accepted, do nothing.
    // This is the direct criterion for a livelock—the previous implementation was 'only the winner repairs'.
    for (unsigned long state = 0UL; state <= 8UL; ++state) {
        const KSW_HVM_WATCH_HIT_PLAN kPlan =
            KswordArkHvmWatchPlanHit(state);
        suite.expect(
            kPlan.Accepted == kPlan.MustRepair,
            L"watch plan: every accepted hit repairs, every refused one does not");
        suite.expect(
            kPlan.OwnsFirstHit == 0U || kPlan.Accepted == 1U,
            L"watch plan: ownership implies acceptance");
    }
}

// ---------------------------------------------------------------------------
// Range check
// ---------------------------------------------------------------------------
void testRangeMatch(ksword_tests::Suite& suite) {
    constexpr std::uint64_t kBase = 0xFFFFF80112345678ULL;
    constexpr std::uint64_t kLength = 8ULL;

    // The range is half-open: the first byte is included, the next byte after the last is excluded. Test both boundaries.
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kBase, kBase, kLength) == 1,
        L"watch range: the first byte matches");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kBase + 7ULL, kBase, kLength) == 1,
        L"watch range: the last byte matches");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kBase + 8ULL, kBase, kLength) == 0,
        L"watch range: one past the end does not match");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kBase - 1ULL, kBase, kLength) == 0,
        L"watch range: one before the start does not match");

    // It never matches when there is no valid linear address—the caller must display this
    // state as "unable to determine" rather than "not in range". These are distinct facts.
    suite.expect(
        KswordArkHvmWatchRangeMatch(0, kBase, kBase, kLength) == 0,
        L"watch range: an invalid GLA never matches");
    suite.expect(
        KswordArkHvmWatchRangeMatch(0, kBase + 4ULL, kBase, kLength) == 0,
        L"watch range: an invalid GLA never matches even inside the range");

    // Zero-length requests match nothing: without a request range, there is no concept of 'falling within' it.
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kBase, kBase, 0ULL) == 0,
        L"watch range: a zero-length request matches nothing");

    // A wrapping range must be rejected, not matched against half the address space.
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, 0ULL, 0xFFFFFFFFFFFFFFF8ULL, 16ULL) == 0,
        L"watch range: a wrapping range matches nothing at the wrap point");
    suite.expect(
        KswordArkHvmWatchRangeMatch(
            1, 0xFFFFFFFFFFFFFFFCULL, 0xFFFFFFFFFFFFFFF8ULL, 16ULL) == 0,
        L"watch range: a wrapping range is refused outright");
    // The interval that just reaches the end of the address space without wrapping remains valid.
    suite.expect(
        KswordArkHvmWatchRangeMatch(
            1, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFF8ULL, 8ULL) == 1,
        L"watch range: a range ending exactly at the top still matches");

    // Whole-page request: any offset within the page counts as a match; offsets outside do not.
    constexpr std::uint64_t kPage = 0xFFFFF80112345000ULL;
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kPage, kPage, 4096ULL) == 1,
        L"watch range: page start matches a whole-page request");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kPage + 4095ULL, kPage, 4096ULL) == 1,
        L"watch range: page end matches a whole-page request");
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kPage + 4096ULL, kPage, 4096ULL) == 0,
        L"watch range: the next page does not match a whole-page request");

    // Within the same page but outside the requested range — this is precisely the state that must be displayed separately from "hit":
    // Hardware monitors whole pages, so events are reported, but they are not attributed to the specific bytes requested by the user.
    suite.expect(
        KswordArkHvmWatchRangeMatch(1, kPage + 0x100ULL, kBase, kLength) == 0,
        L"watch range: same page but outside the requested bytes does not match");
}

} // namespace

int runHvmWatchTests() {
    ksword_tests::Suite suite(L"HVM watch");
    testNormalizeAccess(suite);
    testLeafArithmetic(suite);
    testPlanHit(suite);
    testRangeMatch(suite);
    suite.report();
    return suite.failures();
}

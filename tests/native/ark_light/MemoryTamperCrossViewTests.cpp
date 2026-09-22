// Offline tests for the Memory Tamper Cross View (shared/evidence/MemoryTamperCrossView.h).
//
// This layer belongs to the category where **a wrong judgment does not raise an error but quietly reports 'clean'**: its output is
// treated as the answer to 'has this memory been covertly modified', and a false Consistent result appears identical to a
// successful concealment in the UI. Therefore, the judgment matrix must be exhaustively verified, especially the three hard rules:
//
//   T-01 read failure, channel unavailable, or not covered are not equivalent to 'not tampered'.
//   T-02: One-time inconsistencies do not escalate to conclusions (memory may be legitimately written at any time).
//   T-03: Bytes that cannot be read are not padded with 00 for comparison.
//
// Additionally, this unit test verifies the **order of checks**: The typical signature of SLAT hiding is consistency between the CPU side and the disk reference, with
// modifications visible only on the DMA side. If the check for "memory differs from reference" is performed first, the case where the CPU side matches the reference
// will be incorrectly judged as "consistent"—effectively being deceived by the hidden changes. An incorrect order will not cause any compilation or runtime errors.

#include "TestSupport.h"

#include "../../../shared/evidence/MemoryTamperCrossView.h"

#include <cstdint>
#include <vector>

namespace {

using ksword::evidence::analyzeTamperRounds;
using ksword::evidence::groupOf;
using ksword::evidence::TamperPathGroup;
using ksword::evidence::TamperReadPath;
using ksword::evidence::TamperRound;
using ksword::evidence::TamperSampleStatus;
using ksword::evidence::TamperVerdict;
using ksword::evidence::TamperViewSample;

// Use three distinct byte sequences; exclude all-zero and all-FF patterns because they can easily hide errors in these comparisons.
const std::vector<std::uint8_t> kClean{0x48, 0x89, 0x5C, 0x24, 0x08, 0x57};
const std::vector<std::uint8_t> kPatched{0xE9, 0x11, 0x22, 0x33, 0x44, 0x57};
const std::vector<std::uint8_t> kOther{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

TamperViewSample readSample(const TamperReadPath path, const std::vector<std::uint8_t>& bytes) {
    TamperViewSample sample;
    sample.path = path;
    sample.status = TamperSampleStatus::kRead;
    sample.bytes = bytes;
    return sample;
}

TamperViewSample failedSample(const TamperReadPath path, const TamperSampleStatus status) {
    TamperViewSample sample;
    sample.path = path;
    sample.status = status;
    return sample;
}

// repeatRound: Repeats the same round content n times to construct a continuous divergence where every round is identical.
std::vector<TamperRound> repeatRound(const TamperRound& round, const int times) {
    return std::vector<TamperRound>(static_cast<std::size_t>(times), round);
}

// ------------------------------------------------------------
// 1. Grouping: If grouping is incorrect, all subsequent checks fail silently without error reporting.
// ------------------------------------------------------------
void testPathGrouping(ksword_tests::Suite& suite) {
    suite.expect(groupOf(TamperReadPath::kUserModeVirtual) == TamperPathGroup::kCpuMediated,
        L"tamper: R3 read is CPU-mediated");
    suite.expect(groupOf(TamperReadPath::kKernelVirtual) == TamperPathGroup::kCpuMediated,
        L"tamper: R0 virtual read is CPU-mediated");
    // This case is most easily misclassified as DMA: reading by physical address is still CPU memory
    // access and can still be deceived by SLAT. Misclassifying it would make EPT hiding undetectable.
    suite.expect(groupOf(TamperReadPath::kKernelPhysical) == TamperPathGroup::kCpuMediated,
        L"tamper: R0 physical read is still CPU-mediated, not DMA");
    // HVM is more prone to misinterpretation: its interface is named "ring -1 memory access", which sounds like it belongs to VMX root.
    // The implementation (hvm_memory.c) runs in a driver context at PASSIVE_LEVEL without entering VMX root, yet still consumes
    // SLAT. Assigning it to the DMA group would create an extra, invalid piece of evidence stating 'CPU view is redirected' without
    // triggering any errors. Its independence stems from a different reason: it does not call documented memory manager routines.
    suite.expect(groupOf(TamperReadPath::kHvmPrivateWindow) == TamperPathGroup::kCpuMediated,
        L"tamper: the HVM private window is CPU-mediated despite its ring -1 name");
    suite.expect(groupOf(TamperReadPath::kDmaPhysical) == TamperPathGroup::kDmaMediated,
        L"tamper: DDMA read is the only DMA-mediated path");
    suite.expect(groupOf(TamperReadPath::kImageSectionClean) == TamperPathGroup::kStaticReference,
        L"tamper: the section object's clean pages are a static reference");
    suite.expect(groupOf(TamperReadPath::kOnDiskImage) == TamperPathGroup::kStaticReference,
        L"tamper: the on-disk image is a static reference");
}

// ------------------------------------------------------------
// II. T-01: Failure to read is not 'clean'.
// ------------------------------------------------------------
void testFailuresAreNeverClean(ksword_tests::Suite& suite) {
    suite.expect(analyzeTamperRounds({}).verdict == TamperVerdict::kInconclusive,
        L"tamper: no rounds at all is inconclusive, never consistent");

    // Only one path read successfully: no basis for comparison.
    TamperRound singleView;
    singleView.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    singleView.views.push_back(failedSample(TamperReadPath::kDmaPhysical, TamperSampleStatus::kUnavailable));
    singleView.views.push_back(failedSample(TamperReadPath::kOnDiskImage, TamperSampleStatus::kOutOfCoverage));
    const auto kSingleFinding = analyzeTamperRounds(repeatRound(singleView, 3));
    suite.expect(kSingleFinding.verdict == TamperVerdict::kInconclusive,
        L"tamper: one readable path across every round is inconclusive");
    suite.expect(kSingleFinding.comparableRoundCount == 0,
        L"tamper: a round with one readable path counts as zero comparable rounds");
    suite.expect(!kSingleFinding.inconclusiveReason.empty(),
        L"tamper: an inconclusive verdict always states which condition blocked it");

    // The four non-Read states must not be treated as comparable data.
    for (const TamperSampleStatus kStatus : {
             TamperSampleStatus::kNotAttempted,
             TamperSampleStatus::kUnavailable,
             TamperSampleStatus::kFailed,
             TamperSampleStatus::kOutOfCoverage}) {
        TamperRound round;
        round.views.push_back(failedSample(TamperReadPath::kKernelVirtual, kStatus));
        round.views.push_back(failedSample(TamperReadPath::kDmaPhysical, kStatus));
        const auto kFinding = analyzeTamperRounds(repeatRound(round, 3));
        suite.expect(kFinding.verdict == TamperVerdict::kInconclusive,
            L"tamper: non-Read statuses never become comparable data");
    }

    // The most critical point: when DMA is unavailable, consistency between the two CPU paths is **insufficient** to prove the
    // absence of SLAT hiding, as both paths can be deceived by the same hidden entity. Here, 'Consistent' only describes that the
    // compared paths match; therefore, the conclusion text must explicitly indicate the absence of DMA, conveyed by lastRoundStatus.
    TamperRound noDma;
    noDma.views.push_back(readSample(TamperReadPath::kUserModeVirtual, kClean));
    noDma.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    noDma.views.push_back(failedSample(TamperReadPath::kDmaPhysical, TamperSampleStatus::kUnavailable));
    const auto kNoDmaFinding = analyzeTamperRounds(repeatRound(noDma, 3));
    suite.expect(kNoDmaFinding.verdict == TamperVerdict::kConsistent,
        L"tamper: two agreeing CPU paths are reported consistent");
    suite.expect(kNoDmaFinding.lastRoundStatus.size() == 3,
        L"tamper: every configured path is carried in lastRoundStatus, including the missing one");
    bool dmaStatusVisible = false;
    for (const TamperViewSample& sample : kNoDmaFinding.lastRoundStatus) {
        if (sample.path == TamperReadPath::kDmaPhysical
            && sample.status == TamperSampleStatus::kUnavailable) {
            dmaStatusVisible = true;
        }
    }
    suite.expect(dmaStatusVisible,
        L"tamper: the DMA path's unavailability stays visible next to a consistent verdict");
}

// ------------------------------------------------------------
// 3. T-02: A transient inconsistency does not become a verdict.
// ------------------------------------------------------------
void testTransientDisagreementIsNotAVerdict(ksword_tests::Suite& suite) {
    TamperRound agreeing;
    agreeing.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    agreeing.views.push_back(readSample(TamperReadPath::kDmaPhysical, kClean));

    TamperRound disagreeing;
    disagreeing.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    disagreeing.views.push_back(readSample(TamperReadPath::kDmaPhysical, kPatched));

    // Only one of the three rounds is inconsistent: indistinguishable from 'exactly one normal write occurred within the sampling window'.
    const std::vector<TamperRound> kMixed{agreeing, disagreeing, agreeing};
    const auto kMixedFinding = analyzeTamperRounds(kMixed);
    suite.expect(kMixedFinding.verdict == TamperVerdict::kInconclusive,
        L"tamper: a disagreement seen in only some rounds does not become a verdict");
    suite.expect(!kMixedFinding.inconclusiveReason.empty(),
        L"tamper: the transient case explains itself rather than looking clean");
    // But it must **appear in the list**: if it's not visible in the UI, the user will think nothing happened in this round.
    suite.expect(kMixedFinding.disagreements.size() == 1,
        L"tamper: a transient disagreement is still listed as an observation");
    suite.expect(kMixedFinding.disagreements.front().comparableRounds == 3
        && kMixedFinding.disagreements.front().disagreeingRounds == 1,
        L"tamper: the listing records how many rounds disagreed out of how many comparable");

    // Only escalate to a conclusion if there is disagreement in every round.
    const auto kPersistentFinding = analyzeTamperRounds(repeatRound(disagreeing, 3));
    suite.expect(kPersistentFinding.verdict == TamperVerdict::kCpuViewRedirected,
        L"tamper: a disagreement present in every round becomes a verdict");

    // Invalid with a single round: one round cannot distinguish tampering from a race condition, even if that round is inconsistent.
    const auto kSingleRoundFinding = analyzeTamperRounds(repeatRound(disagreeing, 1));
    suite.expect(kSingleRoundFinding.verdict == TamperVerdict::kInconclusive,
        L"tamper: a single round is never enough to separate tampering from a write race");
}

// ------------------------------------------------------------
// IV. Determination order: SLAT hiding must precede 'memory differs from reference'.
// ------------------------------------------------------------
void testRedirectionOutranksReferenceDiff(ksword_tests::Suite& suite) {
    // The shape the tamperer wants: what the CPU reads is exactly the original bytes on disk, while the DMA side sees the truth.
    TamperRound hidden;
    hidden.views.push_back(readSample(TamperReadPath::kUserModeVirtual, kClean));
    hidden.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    hidden.views.push_back(readSample(TamperReadPath::kDmaPhysical, kPatched));
    hidden.views.push_back(readSample(TamperReadPath::kOnDiskImage, kClean));

    const auto kHiddenFinding = analyzeTamperRounds(repeatRound(hidden, 3));
    suite.expect(kHiddenFinding.verdict == TamperVerdict::kCpuViewRedirected,
        L"tamper: CPU-vs-DMA disagreement outranks every other pattern");
    suite.expect(kHiddenFinding.cpuMatchesStaticReference,
        L"tamper: the finding records that the CPU side matched the clean reference");

    // Plain patch: All live paths see the modification, differing only from the static reference.
    // This is what 'LiveDiffersFromReference' means; it does not imply someone is hiding something.
    TamperRound plainPatch;
    plainPatch.views.push_back(readSample(TamperReadPath::kKernelVirtual, kPatched));
    plainPatch.views.push_back(readSample(TamperReadPath::kDmaPhysical, kPatched));
    plainPatch.views.push_back(readSample(TamperReadPath::kOnDiskImage, kClean));
    const auto kPlainFinding = analyzeTamperRounds(repeatRound(plainPatch, 3));
    suite.expect(kPlainFinding.verdict == TamperVerdict::kLiveDiffersFromReference,
        L"tamper: a patch every live path can see is not a redirection");

    // The two shapes must yield different verdicts: collapsing them means being unable to distinguish between 'modified' and 'modified and hidden'.
    suite.expect(kHiddenFinding.verdict != kPlainFinding.verdict,
        L"tamper: hidden and plain patches never collapse into the same verdict");
}

// ------------------------------------------------------------
// 5. User-mode view divergence.
// ------------------------------------------------------------
void testUserModeHookPattern(ksword_tests::Suite& suite) {
    TamperRound hooked;
    hooked.views.push_back(readSample(TamperReadPath::kUserModeVirtual, kClean));
    hooked.views.push_back(readSample(TamperReadPath::kKernelVirtual, kPatched));
    hooked.views.push_back(readSample(TamperReadPath::kDmaPhysical, kPatched));

    const auto kFinding = analyzeTamperRounds(repeatRound(hooked, 3));
    // R0 and DMA agree, so this is not a redirection; the discrepancy exists only in the R3 path.
    suite.expect(kFinding.verdict == TamperVerdict::kUserModeViewDiffers,
        L"tamper: R3 disagreeing while R0 and DMA agree is a user-mode hook, not a redirection");

    // Reverse case: R3 and R0 are consistent but DMA differs; this is still redirection.
    // Do not downgrade to a user-mode hook just because "R3 is also involved."
    TamperRound redirected;
    redirected.views.push_back(readSample(TamperReadPath::kUserModeVirtual, kClean));
    redirected.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    redirected.views.push_back(readSample(TamperReadPath::kDmaPhysical, kPatched));
    suite.expect(analyzeTamperRounds(repeatRound(redirected, 3)).verdict
            == TamperVerdict::kCpuViewRedirected,
        L"tamper: R3 agreeing with R0 does not downgrade a CPU-vs-DMA disagreement");
}

// ------------------------------------------------------------
// VI. T-03 and the boundaries of the comparison itself.
// ------------------------------------------------------------
void testComparisonEdges(ksword_tests::Suite& suite) {
    // Length mismatch: the difference in the shorter segment must be counted as a discrepancy; do not compare only the common prefix and report 'match'.
    TamperRound shortRead;
    shortRead.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    shortRead.views.push_back(readSample(
        TamperReadPath::kDmaPhysical,
        std::vector<std::uint8_t>(kClean.begin(), kClean.begin() + 3)));
    const auto kShortFinding = analyzeTamperRounds(repeatRound(shortRead, 3));
    suite.expect(kShortFinding.verdict == TamperVerdict::kCpuViewRedirected,
        L"tamper: a path that read fewer bytes counts as disagreeing, not as agreeing");
    suite.expect(!kShortFinding.disagreements.empty()
        && kShortFinding.disagreements.front().differingByteCount == 3,
        L"tamper: the length gap is counted into the differing byte count");

    // The offset of the first difference must be precise: the UI relies on it for positioning, and users will look at the wrong place if an error occurs.
    TamperRound offsetRound;
    std::vector<std::uint8_t> tweaked = kClean;
    tweaked[4] = 0x90;
    offsetRound.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    offsetRound.views.push_back(readSample(TamperReadPath::kDmaPhysical, tweaked));
    const auto kOffsetFinding = analyzeTamperRounds(repeatRound(offsetRound, 2));
    suite.expect(!kOffsetFinding.disagreements.empty(),
        L"tamper: a single differing byte is still reported");
    suite.expect(kOffsetFinding.disagreements.front().firstDifferingOffset == 4,
        L"tamper: the first differing offset is exact");
    suite.expect(kOffsetFinding.disagreements.front().differingByteCount == 1,
        L"tamper: a single differing byte counts as exactly one");
    suite.expect(kOffsetFinding.disagreements.front().leftByte == kClean[4]
        && kOffsetFinding.disagreements.front().rightByte == 0x90,
        L"tamper: both sides' bytes at the first difference are carried out");

    // Fully consistent multi-round: Conclusion is Consistent, and the discrepancy list is empty.
    TamperRound clean;
    clean.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    clean.views.push_back(readSample(TamperReadPath::kDmaPhysical, kClean));
    clean.views.push_back(readSample(TamperReadPath::kOnDiskImage, kClean));
    const auto kCleanFinding = analyzeTamperRounds(repeatRound(clean, 3));
    suite.expect(kCleanFinding.verdict == TamperVerdict::kConsistent,
        L"tamper: every path agreeing every round is consistent");
    suite.expect(kCleanFinding.disagreements.empty(),
        L"tamper: a consistent verdict lists no disagreements");
    suite.expect(kCleanFinding.comparableRoundCount == 3,
        L"tamper: every round with two readable paths counts as comparable");

    // The two CPU paths must remain distinct and lack DMA/reference; if they do, classify as 'Unclassified' and do not report a match.
    TamperRound cpuOnly;
    cpuOnly.views.push_back(readSample(TamperReadPath::kKernelVirtual, kClean));
    cpuOnly.views.push_back(readSample(TamperReadPath::kKernelPhysical, kOther));
    const auto kCpuOnlyFinding = analyzeTamperRounds(repeatRound(cpuOnly, 3));
    suite.expect(kCpuOnlyFinding.verdict == TamperVerdict::kUnexplainedDisagreement,
        L"tamper: two CPU paths persistently disagreeing is reported, not swallowed");
}

}  // namespace

int runMemoryTamperCrossViewTests() {
    ksword_tests::Suite suite(L"T memory tamper cross-view");
    testPathGrouping(suite);
    testFailuresAreNeverClean(suite);
    testTransientDisagreementIsNotAVerdict(suite);
    testRedirectionOutranksReferenceDiff(suite);
    testUserModeHookPattern(suite);
    testComparisonEdges(suite);
    suite.report();
    return suite.failures();
}

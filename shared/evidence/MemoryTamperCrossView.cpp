#include "MemoryTamperCrossView.h"

#include <algorithm>
#include <map>
#include <utility>

namespace ksword::evidence {

const char* tamperReadPathName(const TamperReadPath path) noexcept {
    switch (path) {
        case TamperReadPath::kUserModeVirtual: return "R3 用户态读";
        case TamperReadPath::kKernelVirtual: return "R0 虚拟地址读";
        case TamperReadPath::kKernelPhysical: return "R0 物理地址读";
        case TamperReadPath::kHvmPrivateWindow: return "HVM 私有页表窗口";
        case TamperReadPath::kDmaPhysical: return "DDMA 物理读";
        case TamperReadPath::kImageSectionClean: return "节对象干净页";
        case TamperReadPath::kOnDiskImage: return "磁盘映像";
    }
    return "未知路径";
}

TamperPathGroup groupOf(const TamperReadPath path) noexcept {
    switch (path) {
        case TamperReadPath::kUserModeVirtual:
        case TamperReadPath::kKernelVirtual:
        case TamperReadPath::kKernelPhysical:
        case TamperReadPath::kHvmPrivateWindow:
            return TamperPathGroup::kCpuMediated;
        case TamperReadPath::kDmaPhysical:
            return TamperPathGroup::kDmaMediated;
        case TamperReadPath::kImageSectionClean:
        case TamperReadPath::kOnDiskImage:
            return TamperPathGroup::kStaticReference;
    }
    return TamperPathGroup::kCpuMediated;
}

const char* tamperSampleStatusName(const TamperSampleStatus status) noexcept {
    switch (status) {
        case TamperSampleStatus::kNotAttempted: return "未采集";
        case TamperSampleStatus::kUnavailable: return "通道不可用";
        case TamperSampleStatus::kFailed: return "读取失败";
        case TamperSampleStatus::kOutOfCoverage: return "不覆盖该范围";
        case TamperSampleStatus::kRead: return "已读到";
    }
    return "未知状态";
}

const char* tamperVerdictName(const TamperVerdict verdict) noexcept {
    switch (verdict) {
        case TamperVerdict::kInconclusive: return "无法判定";
        case TamperVerdict::kConsistent: return "各视图一致";
        case TamperVerdict::kCpuViewRedirected: return "CPU 视图被重定向";
        case TamperVerdict::kUserModeViewDiffers: return "用户态视图不同";
        case TamperVerdict::kLiveDiffersFromReference: return "内存与静态参考不同";
        case TamperVerdict::kUnexplainedDisagreement: return "存在未归类的分歧";
    }
    return "未知结论";
}

namespace {

// PathPair: A pair of paths sorted by enum value to ensure (a,b) and (b,a) map to the same key.
using PathPair = std::pair<TamperReadPath, TamperReadPath>;

PathPair makePair(const TamperReadPath left, const TamperReadPath right) {
    return (static_cast<int>(left) <= static_cast<int>(right))
        ? PathPair{left, right}
        : PathPair{right, left};
}

// PairTally: Cumulative count for a pair of paths across rounds.
struct PairTally final {
    int comparableRounds = 0;
    int disagreeingRounds = 0;
    bool firstDifferenceRecorded = false;
    std::size_t firstDifferingOffset = 0;
    std::size_t differingByteCount = 0;
    std::uint8_t leftByte = 0;
    std::uint8_t rightByte = 0;
};

// compareBytes: compares byte-by-byte, returns the count of differing bytes, and outputs the first differing location.
//
// When lengths differ, compare only the common prefix and count the length difference as a discrepancy: a path
// reading fewer bytes is a divergence, just like 'reading different bytes,' and should not be silently ignored.
std::size_t compareBytes(
    const std::vector<std::uint8_t>& left,
    const std::vector<std::uint8_t>& right,
    std::size_t& firstDifferingOffsetOut,
    std::uint8_t& leftByteOut,
    std::uint8_t& rightByteOut) {
    const std::size_t kCommonLength = (std::min)(left.size(), right.size());
    std::size_t differingCount = 0;
    bool firstRecorded = false;
    for (std::size_t index = 0; index < kCommonLength; ++index) {
        if (left[index] == right[index]) {
            continue;
        }
        ++differingCount;
        if (!firstRecorded) {
            firstRecorded = true;
            firstDifferingOffsetOut = index;
            leftByteOut = left[index];
            rightByteOut = right[index];
        }
    }
    const std::size_t kLengthGap =
        (left.size() > right.size()) ? (left.size() - right.size())
                                     : (right.size() - left.size());
    if (kLengthGap != 0 && !firstRecorded) {
        firstDifferingOffsetOut = kCommonLength;
        leftByteOut = 0;
        rightByteOut = 0;
    }
    return differingCount + kLengthGap;
}

// readableSamplesOf: Retrieve all observations with status == Read in a round.
std::vector<const TamperViewSample*> readableSamplesOf(const TamperRound& round) {
    std::vector<const TamperViewSample*> readable;
    readable.reserve(round.views.size());
    for (const TamperViewSample& sample : round.views) {
        if (sample.status == TamperSampleStatus::kRead) {
            readable.push_back(&sample);
        }
    }
    return readable;
}

// persistentDisagreementBetween：
// - Check if a specific path pair is inconsistent in **every round** (T-02).
// - Only holds when this pair has at least two comparable rounds: one round cannot distinguish tampering from races within the sampling window.
bool persistentDisagreementBetween(const PairTally& tally) {
    return tally.comparableRounds >= 2
        && tally.disagreeingRounds == tally.comparableRounds;
}

// anyPersistentDisagreementAcross：
// - Find persistent disagreements between the two groups.
bool anyPersistentDisagreementAcross(
    const std::map<PathPair, PairTally>& tallies,
    const TamperPathGroup leftGroup,
    const TamperPathGroup rightGroup) {
    for (const auto& [pair, tally] : tallies) {
        const TamperPathGroup kGroupA = groupOf(pair.first);
        const TamperPathGroup kGroupB = groupOf(pair.second);
        const bool kSpansGroups =
            (kGroupA == leftGroup && kGroupB == rightGroup)
            || (kGroupA == rightGroup && kGroupB == leftGroup);
        if (kSpansGroups && persistentDisagreementBetween(tally)) {
            return true;
        }
    }
    return false;
}

// agreementAcross：
// - There exists a pair between the two groups that is comparable and never diverges.
bool agreementAcross(
    const std::map<PathPair, PairTally>& tallies,
    const TamperPathGroup leftGroup,
    const TamperPathGroup rightGroup) {
    for (const auto& [pair, tally] : tallies) {
        const TamperPathGroup kGroupA = groupOf(pair.first);
        const TamperPathGroup kGroupB = groupOf(pair.second);
        const bool kSpansGroups =
            (kGroupA == leftGroup && kGroupB == rightGroup)
            || (kGroupA == rightGroup && kGroupB == leftGroup);
        if (kSpansGroups && tally.comparableRounds > 0 && tally.disagreeingRounds == 0) {
            return true;
        }
    }
    return false;
}

}  // namespace

TamperFinding analyzeTamperRounds(const std::vector<TamperRound>& rounds) {
    TamperFinding finding;
    if (!rounds.empty()) {
        finding.lastRoundStatus = rounds.back().views;
    }

    if (rounds.empty()) {
        finding.inconclusiveReason = "没有任何采样轮次。";
        return finding;
    }

    // Accumulate per round and per pair.
    std::map<PathPair, PairTally> tallies;
    for (const TamperRound& round : rounds) {
        const std::vector<const TamperViewSample*> kReadable = readableSamplesOf(round);
        if (kReadable.size() >= 2) {
            ++finding.comparableRoundCount;
        }
        for (std::size_t leftIndex = 0; leftIndex < kReadable.size(); ++leftIndex) {
            for (std::size_t rightIndex = leftIndex + 1; rightIndex < kReadable.size();
                 ++rightIndex) {
                const TamperViewSample& leftSample = *kReadable[leftIndex];
                const TamperViewSample& rightSample = *kReadable[rightIndex];
                // A path appearing twice in a single round is a caller error. Skip it rather than comparing it to
                // itself to produce 'consistency', which would artificially inflate the number of comparable rounds.
                if (leftSample.path == rightSample.path) {
                    continue;
                }
                PairTally& tally = tallies[makePair(leftSample.path, rightSample.path)];
                ++tally.comparableRounds;

                std::size_t firstOffset = 0;
                std::uint8_t leftByte = 0;
                std::uint8_t rightByte = 0;
                const std::size_t kDifferingCount = compareBytes(
                    leftSample.bytes, rightSample.bytes, firstOffset, leftByte, rightByte);
                if (kDifferingCount == 0) {
                    continue;
                }
                ++tally.disagreeingRounds;
                if (!tally.firstDifferenceRecorded) {
                    tally.firstDifferenceRecorded = true;
                    tally.firstDifferingOffset = firstOffset;
                    tally.differingByteCount = kDifferingCount;
                    tally.leftByte = leftByte;
                    tally.rightByte = rightByte;
                }
            }
        }
    }

    // T-01: If fewer than two comparable paths exist, the result must be "inconclusive".
    if (finding.comparableRoundCount == 0) {
        finding.inconclusiveReason =
            "没有任何一轮同时读到两条以上路径，无法互比。读失败不等于没有篡改。";
        return finding;
    }

    // Export persistent disagreements into a list, and also record those that occurred but were not persistent—they represent a
    // typical race condition shape. These must be visible in the UI; otherwise, users might assume nothing happened in this round.
    for (const auto& [pair, tally] : tallies) {
        if (tally.disagreeingRounds == 0) {
            continue;
        }
        TamperDisagreement disagreement;
        disagreement.left = pair.first;
        disagreement.right = pair.second;
        disagreement.firstDifferingOffset = tally.firstDifferingOffset;
        disagreement.differingByteCount = tally.differingByteCount;
        disagreement.leftByte = tally.leftByte;
        disagreement.rightByte = tally.rightByte;
        disagreement.comparableRounds = tally.comparableRounds;
        disagreement.disagreeingRounds = tally.disagreeingRounds;
        finding.disagreements.push_back(disagreement);
    }

    // The criterion for redirection is not "there exists at least one CPU↔DMA disagreement," but rather "**no** CPU path is
    // consistent with DMA." These are not equivalent; the distinction matches the shape of a user-mode hook: R3 is hooked and
    // reads clean bytes, while R0 and DMA both read the actual patch. In this scenario, R3↔DMA shows persistent disagreement,
    // but R0↔DMA is consistent, indicating that the CPU→memory path itself is healthy and the issue lies at the R3 layer.
    // Treating "any pair of disagreements" as a match would falsely flag this as SLAT redirection,
    // diverting the investigation from user-mode hooks to the hypervisor. Conversely, as long as
    // at least one CPU path aligns with the DMA path, there is no overall redirection.
    const bool kCpuVsDma =
        anyPersistentDisagreementAcross(
            tallies, TamperPathGroup::kCpuMediated, TamperPathGroup::kDmaMediated)
        && !agreementAcross(
            tallies, TamperPathGroup::kCpuMediated, TamperPathGroup::kDmaMediated);
    const bool kLiveVsReference =
        anyPersistentDisagreementAcross(
            tallies, TamperPathGroup::kCpuMediated, TamperPathGroup::kStaticReference)
        || anyPersistentDisagreementAcross(
            tallies, TamperPathGroup::kDmaMediated, TamperPathGroup::kStaticReference);

    // The order of judgment is itself a criterion: the discrepancy between CPU and DMA must be prioritized over 'memory differs from reference'.
    // The typical shape of SLAT hiding is exactly that the CPU side matches the reference perfectly (the hider shows you the
    // original bytes), while only the DMA side sees the real modifications. If you first check 'memory differs from reference',
    // this case will be judged as 'consistent' because the CPU side matches the reference, thus being deceived by the hider.
    if (kCpuVsDma) {
        finding.verdict = TamperVerdict::kCpuViewRedirected;
        finding.cpuMatchesStaticReference = agreementAcross(
            tallies, TamperPathGroup::kCpuMediated, TamperPathGroup::kStaticReference);
        return finding;
    }

    // Persistent divergence between R3 and R0: both traverse the CPU, but the difference lies in the user-mode segment.
    const auto kUserVsKernelVirtual = tallies.find(
        makePair(TamperReadPath::kUserModeVirtual, TamperReadPath::kKernelVirtual));
    const auto kUserVsKernelPhysical = tallies.find(
        makePair(TamperReadPath::kUserModeVirtual, TamperReadPath::kKernelPhysical));
    const bool kUserModeDiffers =
        (kUserVsKernelVirtual != tallies.end()
         && persistentDisagreementBetween(kUserVsKernelVirtual->second))
        || (kUserVsKernelPhysical != tallies.end()
            && persistentDisagreementBetween(kUserVsKernelPhysical->second));
    if (kUserModeDiffers) {
        finding.verdict = TamperVerdict::kUserModeViewDiffers;
        return finding;
    }

    if (kLiveVsReference) {
        finding.verdict = TamperVerdict::kLiveDiffersFromReference;
        return finding;
    }

    // There are still persistent disagreements not falling into any of the above patterns (e.g., persistent differences between two CPU paths).
    for (const auto& [pair, tally] : tallies) {
        (void)pair;
        if (persistentDisagreementBetween(tally)) {
            finding.verdict = TamperVerdict::kUnexplainedDisagreement;
            return finding;
        }
    }

    // Discrepancies appear but not in every round: per T-02, do not escalate to a conclusion, but also do not
    // report "consistency"—it could equally be a successful tampering that is only visible in a subset of rounds.
    if (!finding.disagreements.empty()) {
        finding.verdict = TamperVerdict::kInconclusive;
        finding.inconclusiveReason =
            "存在分歧但并非每一轮都出现，无法与采样窗口内的正常写入区分，请增加轮次重试。";
        return finding;
    }

    finding.verdict = TamperVerdict::kConsistent;
    return finding;
}

}  // namespace ksword::evidence

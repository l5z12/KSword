#include "EvidenceEnvelope.h"

#include <algorithm>
#include <limits>

namespace ksword::evidence {

const char* collectionStatusName(CollectionStatus status) noexcept {
    switch (status) {
    case CollectionStatus::kNotCollected: return "NotCollected";
    case CollectionStatus::kSuccess:      return "Success";
    case CollectionStatus::kPartial:      return "Partial";
    case CollectionStatus::kUnsupported:  return "Unsupported";
    case CollectionStatus::kAccessDenied: return "AccessDenied";
    case CollectionStatus::kTimeout:      return "Timeout";
    case CollectionStatus::kError:        return "Error";
    }
    return "NotCollected";
}

bool statusCarriesObservation(CollectionStatus status) noexcept {
    return status == CollectionStatus::kSuccess || status == CollectionStatus::kPartial;
}

CollectionOutcome CollectionOutcome::success() noexcept {
    CollectionOutcome outcome;
    outcome.status = CollectionStatus::kSuccess;
    return outcome;
}

CollectionOutcome CollectionOutcome::notCollected() noexcept {
    CollectionOutcome outcome;
    outcome.status = CollectionStatus::kNotCollected;
    return outcome;
}

CollectionOutcome CollectionOutcome::failure(CollectionStatus status,
                                             std::string domain,
                                             std::uint64_t code,
                                             std::string message) {
    CollectionOutcome outcome;
    outcome.status = status;
    outcome.nativeCodeDomain = std::move(domain);
    outcome.nativeCode = OptionalU64::of(code);
    outcome.message = std::move(message);
    return outcome;
}

const char* analysisConclusionName(AnalysisConclusion conclusion) noexcept {
    switch (conclusion) {
    case AnalysisConclusion::kNoEvidence:           return "NoEvidence";
    case AnalysisConclusion::kNoDifferenceObserved: return "NoDifferenceObserved";
    case AnalysisConclusion::kDifferenceObserved:   return "DifferenceObserved";
    case AnalysisConclusion::kIndeterminate:        return "Indeterminate";
    }
    return "NoEvidence";
}

namespace {

// Accounting counters are u64 and originate from different collectors; addition must saturate, never wrap around to a smaller 'completed count'.
std::uint64_t saturatingAdd(std::uint64_t a, std::uint64_t b) noexcept {
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint64_t>::max)();
    return (a > kMax - b) ? kMax : (a + b);
}

// Range validity check: all four endpoints must be present simultaneously.
// When only begin is filled without end, the end boundary cannot be validated. The previous implementation would read the
// .value of two unset OptionalU64 fields (both 0), making "0 < 0" always false, so the end boundary was never checked (F-06).
bool rangeStated(const CoverageAccount& coverage) noexcept {
    return coverage.requestedBegin.present && coverage.requestedEnd.present &&
           coverage.processedBegin.present && coverage.processedEnd.present;
}

bool anyRangeEndpoint(const CoverageAccount& coverage) noexcept {
    return coverage.requestedBegin.present || coverage.requestedEnd.present ||
           coverage.processedBegin.present || coverage.processedEnd.present;
}

} // namespace

bool CoverageAccount::fullyCovered() const noexcept {
    // Disqualifying conditions: If any is true, coverage cannot be complete.
    // countsIncomplete is also included: when a count source is unknown, a 0 in failed/skipped means 'not counted'
    // rather than 'did not occur'; treating this as full coverage would be passing off unknown as complete.
    if (limitHit || cancelled || countsIncomplete ||
        failed != 0U || skipped != 0U || truncated != 0U) {
        return false;
    }

    // Positive evidence (a): Range scope. All four endpoints must be present, and the processed range must fully cover the requested range.
    bool rangeComplete = false;
    if (rangeStated(*this)) {
        if (processedBegin.value > requestedBegin.value || processedEnd.value < requestedEnd.value) {
            return false;
        }
        rangeComplete = true;
    } else if (anyRangeEndpoint(*this)) {
        // Endpoint incomplete: boundaries unclear; prefer marking as incomplete.
        return false;
    }

    // Positive evidence (b): Quantity scope. If a total is claimed, it must be fully processed.
    bool countComplete = false;
    if (totalKnown.present) {
        if (succeeded < totalKnown.value) {
            return false;
        }
        countComplete = true;
    }

    // F-06: If neither of the two positive evidences exists (e.g., a default-constructed empty account), it represents "unknown coverage,"
    // not a "100% complete scan." Any collector that forgets to populate an account should not be granted a complete coverage status.
    return rangeComplete || countComplete;
}

std::string CoverageAccount::describeRemaining() const {
    // F-06: Stop reason takes precedence. Cancellation is not a 'hit limit'; the two must not be conflated in reports.
    if (cancelled) {
        return std::string("cancelled");
    }
    if (limitHit) {
        return std::string("limit-hit:") +
               (limit.present ? formatU64(limit.value, U64Format::kDecimal) : std::string("unknown"));
    }
    if (countsIncomplete) {
        // At least one count source is unknown: the number is only a lower bound. It must never fall
        // through to the 'remaining:N' branch below to report a seemingly precise remaining amount.
        return std::string("counts-incomplete");
    }
    if (truncated != 0U) {
        // The counts might mathematically balance out, but truncation means we haven't seen everything;
        // this must be reported first, otherwise it contradicts what `fullyCovered()` states.
        return std::string("truncated:") + formatU64(truncated, U64Format::kDecimal);
    }
    if (totalKnown.present) {
        const std::uint64_t kDone =
            saturatingAdd(saturatingAdd(succeeded, failed), saturatingAdd(skipped, truncated));
        if (kDone < totalKnown.value) {
            return std::string("remaining:") + formatU64(totalKnown.value - kDone, U64Format::kDecimal);
        }
        if (failed != 0U || skipped != 0U) {
            // The counts match but there are failures/skips: remaining amount is 0 does not equal having seen everything.
            return std::string("incomplete:failed=") + formatU64(failed, U64Format::kDecimal) +
                   ",skipped=" + formatU64(skipped, U64Format::kDecimal);
        }
        return std::string("remaining:0");
    }
    if (rangeStated(*this)) {
        const std::uint64_t kHead = processedBegin.value > requestedBegin.value
                                       ? processedBegin.value - requestedBegin.value
                                       : 0ULL;
        const std::uint64_t kTail = requestedEnd.value > processedEnd.value
                                       ? requestedEnd.value - processedEnd.value
                                       : 0ULL;
        return std::string("remaining-range:") + formatU64(saturatingAdd(kHead, kTail), U64Format::kDecimal);
    }
    if (requestedEnd.present && processedEnd.present && requestedEnd.value > processedEnd.value) {
        return std::string("remaining-range:") +
               formatU64(requestedEnd.value - processedEnd.value, U64Format::kDecimal);
    }
    // F-06: If the total is unknown, explicitly state unknown; do not use the returned count to impersonate the total.
    return std::string("remaining:unknown");
}

const char* sourceOriginName(SourceOrigin origin) noexcept {
    switch (origin) {
    case SourceOrigin::kUnknown:       return "Unknown";
    case SourceOrigin::kLiveKernel:    return "LiveKernel";
    case SourceOrigin::kLiveUserMode:  return "LiveUserMode";
    case SourceOrigin::kExternalFile:  return "ExternalFile";
    case SourceOrigin::kOfflineSample: return "OfflineSample";
    }
    return "Unknown";
}

const char* captureModeName(CaptureMode mode) noexcept {
    switch (mode) {
    case CaptureMode::kUnknown:   return "Unknown";
    case CaptureMode::kSnapshot:  return "Snapshot";
    case CaptureMode::kStreaming: return "Streaming";
    case CaptureMode::kReplay:    return "Replay";
    }
    return "Unknown";
}

bool monotonicComparable(const CaptureWindow& a, const CaptureWindow& b) noexcept {
    if (a.bootId.empty() || b.bootId.empty()) {
        return false;
    }
    if (a.bootId != b.bootId) {
        return false;
    }
    return a.machineId == b.machineId;
}

bool monotonicDeltaNanos(const CaptureWindow& window,
                         std::uint64_t earlierTicks,
                         std::uint64_t laterTicks,
                         std::int64_t& outNanos) noexcept {
    if (window.bootId.empty() || !window.monotonicFrequency.present) {
        return false;
    }
    const std::uint64_t kFrequency = window.monotonicFrequency.value;
    if (kFrequency == 0U) {
        return false;
    }
    const bool kForward = laterTicks >= earlierTicks;
    const std::uint64_t kDelta = kForward ? (laterTicks - earlierTicks) : (earlierTicks - laterTicks);

    // delta / freq converts seconds to nanoseconds; performs integer division first then multiplies the remainder to avoid overflow from delta * 1e9.
    constexpr std::uint64_t kNanosPerSecond = 1000000000ULL;
    const std::uint64_t kWhole = kDelta / kFrequency;
    const std::uint64_t kRemainder = kDelta % kFrequency;
    constexpr std::uint64_t kMax = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
    if (kWhole > kMax / kNanosPerSecond) {
        return false;
    }
    const std::uint64_t kNanos = kWhole * kNanosPerSecond + (kRemainder * kNanosPerSecond) / kFrequency;
    if (kNanos > kMax) {
        return false;
    }
    outNanos = kForward ? static_cast<std::int64_t>(kNanos) : -static_cast<std::int64_t>(kNanos);
    return true;
}

AnalysisConclusion EvidenceEnvelope::deriveConclusion(bool differenceFound) const noexcept {
    if (!statusCarriesObservation(outcome.status)) {
        // Collection failed / not collected / unsupported: No evidence, not 'normal'.
        return AnalysisConclusion::kNoEvidence;
    }
    if (differenceFound) {
        return AnalysisConclusion::kDifferenceObserved;
    }
    if (outcome.status == CollectionStatus::kPartial || !coverage.fullyCovered()) {
        // When coverage is insufficient, "no difference observed" cannot be upgraded to "no difference found."
        return AnalysisConclusion::kIndeterminate;
    }
    return AnalysisConclusion::kNoDifferenceObserved;
}

std::size_t TrustStatement::originViewCount(SourceOrigin origin) const noexcept {
    switch (origin) {
    case SourceOrigin::kUnknown:       return unknownOriginViewCount;
    case SourceOrigin::kLiveKernel:    return liveKernelViewCount;
    case SourceOrigin::kLiveUserMode:  return liveUserModeViewCount;
    case SourceOrigin::kExternalFile:  return externalFileViewCount;
    case SourceOrigin::kOfflineSample: return offlineSampleViewCount;
    }
    return 0U;
}

TrustStatement buildTrustStatement(const std::vector<EvidenceEnvelope>& envelopes) {
    TrustStatement statement;
    statement.viewCount = envelopes.size();

    std::vector<std::string> groups;
    groups.reserve(envelopes.size());
    bool sawAny = false;
    bool allLiveKernel = true;

    for (const EvidenceEnvelope& envelope : envelopes) {
        // F-11: Count by source category; the conclusion 'half comes from offline samples' must be visible.
        switch (envelope.source.origin) {
        case SourceOrigin::kUnknown:       ++statement.unknownOriginViewCount; break;
        case SourceOrigin::kLiveKernel:    ++statement.liveKernelViewCount; break;
        case SourceOrigin::kLiveUserMode:  ++statement.liveUserModeViewCount; break;
        case SourceOrigin::kExternalFile:  ++statement.externalFileViewCount; break;
        case SourceOrigin::kOfflineSample: ++statement.offlineSampleViewCount; break;
        }
        // X-01: Multiple views from the same sourceGroup count as a single independent source.
        const std::string& group =
            envelope.source.sourceGroup.empty() ? envelope.source.collectorId : envelope.source.sourceGroup;
        if (std::find(groups.begin(), groups.end(), group) == groups.end()) {
            groups.push_back(group);
        }
        sawAny = true;
        if (envelope.source.origin != SourceOrigin::kLiveKernel) {
            allLiveKernel = false;
        }
        // Partial itself indicates the requested scope is not fully covered, even if the ledger fields are not yet filled.
        if (envelope.outcome.status == CollectionStatus::kPartial ||
            !statusCarriesObservation(envelope.outcome.status) ||
            !envelope.coverage.fullyCovered()) {
            statement.anyIncompleteCoverage = true;
        }
    }

    statement.independentSourceGroupCount = groups.size();
    statement.allFromSameLiveKernel = sawAny && allLiveKernel;
    statement.distinctOriginCount =
        (statement.unknownOriginViewCount != 0U ? 1U : 0U) +
        (statement.liveKernelViewCount != 0U ? 1U : 0U) +
        (statement.liveUserModeViewCount != 0U ? 1U : 0U) +
        (statement.externalFileViewCount != 0U ? 1U : 0U) +
        (statement.offlineSampleViewCount != 0U ? 1U : 0U);

    // F-11: Conclusions are always expressed as limitations, not guarantees.
    if (statement.allFromSameLiveKernel) {
        statement.limitationKeys.emplace_back("trust.limitation.sameLiveKernel");
    }
    if (statement.independentSourceGroupCount <= 1U && statement.viewCount > 1U) {
        statement.limitationKeys.emplace_back("trust.limitation.singleSourceGroup");
    }
    // F-11: External files and offline samples do not describe the "currently running kernel". When mixed into conclusions, they
    // must be explicitly declared separately; otherwise, readers may mistake a semi-offline assessment for an on-site judgment.
    if (statement.externalFileViewCount != 0U) {
        statement.limitationKeys.emplace_back("trust.limitation.externalFile");
    }
    if (statement.offlineSampleViewCount != 0U) {
        statement.limitationKeys.emplace_back("trust.limitation.offlineSample");
    }
    if (statement.anyIncompleteCoverage) {
        statement.limitationKeys.emplace_back("trust.limitation.incompleteCoverage");
    }
    statement.limitationKeys.emplace_back("trust.limitation.noAbsenceProof");
    return statement;
}

} // namespace ksword::evidence

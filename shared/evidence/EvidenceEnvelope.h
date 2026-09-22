#pragma once

// Evidence envelope — F-04 source and timestamp, F-05 separation of availability and conclusion, F-06 accounting for incomplete collection,
// F-11: Source trust boundary.
//
// This layer describes only the act of collection itself, not the collected objects. Every module
// (I/X/M/T/N/S/D/C/G) includes an envelope with its results; UI, export, and reporting use this
// to distinguish between 'collection failure', 'analysis inconclusive', and 'correct empty set'.

#include "LosslessValue.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// F-05: Collection status. It is separate from the analysis conclusion; neither field can be inferred from the other.
// ---------------------------------------------------------------------------
enum class CollectionStatus {
    kNotCollected,  // Not collected at all
    kSuccess,       // Completed and covering the requested range (which may be a correct empty set).
    kPartial,       // Executed but did not cover the full request scope.
    kUnsupported,   // Current driver/OS/hardware does not support this capability.
    kAccessDenied,  // Access denied
    kTimeout,       // Timeout
    kError,         // Other failures
};

const char* collectionStatusName(CollectionStatus status) noexcept;

// Only Success/Partial states carry real observations; 'empty' in other states does not mean 'non-existent'.
bool statusCarriesObservation(CollectionStatus status) noexcept;

// F-05: On failure, preserve the original error code and description; do not pad with default 0, empty string, or "success".
struct CollectionOutcome final {
    CollectionStatus status = CollectionStatus::kNotCollected;
    OptionalU64 nativeCode;  // Original NTSTATUS / Win32 / HRESULT value; unset if unknown.
    std::string nativeCodeDomain;  // "NTSTATUS" / "WIN32" / "HRESULT" / ""
    std::string message;           // Original text from the source, not an explanation we generated.

    static CollectionOutcome success() noexcept;
    static CollectionOutcome notCollected() noexcept;
    static CollectionOutcome failure(CollectionStatus status,
                                     std::string domain,
                                     std::uint64_t code,
                                     std::string message);
};

// ---------------------------------------------------------------------------
// F-05: Analysis conclusion. "Normal" cannot be generated when there is no evidence.
// ---------------------------------------------------------------------------
enum class AnalysisConclusion {
    kNoEvidence,             // No observations available — not "normal".
    kNoDifferenceObserved,   // Sufficient coverage observed with no contradictions — not "system secure"
    kDifferenceObserved,     // Difference observed
    kIndeterminate,          // Observed but insufficient to determine
};

const char* analysisConclusionName(AnalysisConclusion conclusion) noexcept;

// ---------------------------------------------------------------------------
// F-06: Incomplete collection account.
// ---------------------------------------------------------------------------
struct CoverageAccount final {
    OptionalU64 requestedBegin;  // Requested range (address/sequence/time; units defined by the caller).
    OptionalU64 requestedEnd;
    OptionalU64 processedBegin;  // Actual range processed
    OptionalU64 processedEnd;

    std::uint64_t succeeded = 0;
    std::uint64_t failed = 0;
    std::uint64_t skipped = 0;
    std::uint64_t truncated = 0;

    bool limitHit = false;          // Stop early due to limit hit
    OptionalU64 limit;              // Effective upper limit
    // F-06: User-initiated cancellation and 'limit hit' are distinct stop reasons and must not share limitHit;
    // otherwise, a single cancellation would be recorded as 'hitting an unknown limit', losing the 'reason' dimension.
    bool cancelled = false;
    // F-06: The four counters above are raw u64 values without an "unknown" state. Some sources report only totals without
    // details (e.g., ETW provides only a total for EventsLost). In such cases, summing unknown items as 0 into failed/skipped
    // effectively writes "zero items lost" instead of "unknown how many were lost". Setting this flag indicates **at least
    // one counting source is unknown**; the numbers in the ledger are merely a lower bound, not the full picture.
    bool countsIncomplete = false;
    OptionalU64 totalKnown;         // Total object count. 'Unknown' means unset; do not substitute with the number of already returned items.

    // F-06: Full coverage requires **positive evidence**; empty accounts are not full coverage.
    // Decision: First check for negative conditions (hit upper limit, cancelled, failure, skip,
    // or truncation), then require at least one of the following two positive evidences to hold:
    //   (a) Scope criteria: All four endpoints (requested/processed) must be present **simultaneously**, and the processed range
    //       must fully cover the requested range. Missing any endpoint makes boundary validation impossible, so it doesn't count.
    //   (b) Quantity semantics: totalKnown is declared, and succeeded is already not less than it.
    // Both are missing (i.e., "nothing filled in") → return false: unknown coverage ≠ complete coverage.
    // Invariant: When fullyCovered() is true, describeRemaining() never returns "remaining:unknown".
    bool fullyCovered() const noexcept;

    // Remaining amount description for UI/reports; returns a clear "unknown" text key instead of 0 when undeterminable.
    // F-06 requires "remaining range and reason to be visible", so the stop reason (cancelled
    // / limit-hit / truncated) takes precedence over pure quantity descriptions in output.
    std::string describeRemaining() const;
};

// ---------------------------------------------------------------------------
// F-11: Source trust boundary.
// ---------------------------------------------------------------------------
enum class SourceOrigin {
    kUnknown,
    kLiveKernel,    // Same running Windows kernel instance.
    kLiveUserMode,  // R3 interface on the same machine
    kExternalFile,  // External files on disk (images, policies, configurations)
    kOfflineSample, // Saved session/snapshot/dump
};

const char* sourceOriginName(SourceOrigin origin) noexcept;

// F-04 + X-01: collector identity. sourceGroup represents the "underlying evidence source"; two layers of wrapping
// for the same collector must share the same sourceGroup, otherwise they are treated as two independent sources.
struct SourceRef final {
    std::string collectorId;              // Stable identifier, e.g., "r0.process.enum"
    std::uint32_t collectorVersion = 0;   // The parsing/protocol version of this collector
    std::string sourceGroup;              // Independent source group key
    SourceOrigin origin = SourceOrigin::kUnknown;
    std::string dependsOn;                // Dependency chain description, e.g., "ArkDriverClient/IOCTL 0x..."
};

enum class CaptureMode {
    kUnknown,
    kSnapshot,   // One-time snapshot
    kStreaming,  // Continuous collection
    kReplay,     // Replay from saved data
};

const char* captureModeName(CaptureMode mode) noexcept;

// F-04: UTC and monotonic clocks are used separately. Direct comparison of monotonic values across boot cycles is prohibited.
struct CaptureWindow final {
    OptionalU64 startUtc100ns;
    OptionalU64 endUtc100ns;
    OptionalU64 startMonotonic;   // QPC ticks, comparable only within the same bootId.
    OptionalU64 endMonotonic;
    OptionalU64 monotonicFrequency;

    std::string machineId;
    std::string bootId;    // Boot cycle identifier; do not subtract monotonic values with different bootId values.
    std::string sessionId; // Current collection session
    CaptureMode mode = CaptureMode::kUnknown;
};

// F-04: Two monotonic timestamps can only be subtracted if they are within the same boot cycle.
bool monotonicComparable(const CaptureWindow& a, const CaptureWindow& b) noexcept;

// Returns false if incomparable (different boot / missing frequency / missing value); out is not modified.
bool monotonicDeltaNanos(const CaptureWindow& window,
                         std::uint64_t earlierTicks,
                         std::uint64_t laterTicks,
                         std::int64_t& outNanos) noexcept;

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------
struct EvidenceEnvelope final {
    SourceRef source;
    CaptureWindow window;
    CollectionOutcome outcome;
    CoverageAccount coverage;
    std::string evidenceId;  // Stable ID for this batch of results, used for navigation and report references (F-12).

    // F-05 core constraint: Without observations, do not conclude that "no differences were found".
    // differenceFound is only accepted when statusCarriesObservation is true.
    AnalysisConclusion deriveConclusion(bool differenceFound) const noexcept;
};

// F-11: Consistency across multiple views only indicates that no contradictions were found in those views. This function produces structured facts
// covering coverage and trust statements for the caller to render; it never produces conclusions like "system is secure" or "no rootkit exists."
struct TrustStatement final {
    std::size_t viewCount = 0;
    std::size_t independentSourceGroupCount = 0;
    bool allFromSameLiveKernel = false;
    bool anyIncompleteCoverage = false;

    // F-11 requires distinguishing between three sources: 'same running Windows kernel', 'external files', and 'offline samples'.
    // The single `allFromSameLiveKernel` flag only indicates whether everything originates from the local kernel. When
    // false, no field specifies the origin of the remainder, so counts are performed per category based on `SourceOrigin`.
    std::size_t unknownOriginViewCount = 0;
    std::size_t liveKernelViewCount = 0;
    std::size_t liveUserModeViewCount = 0;
    std::size_t externalFileViewCount = 0;
    std::size_t offlineSampleViewCount = 0;
    std::size_t distinctOriginCount = 0;   // Count of source categories involved in this conclusion

    std::vector<std::string> limitationKeys;  // i18n key; UI handles translation

    // Convenient read: count occurrences of a source type. Used by UI to render "how much of this conclusion comes from offline samples".
    std::size_t originViewCount(SourceOrigin origin) const noexcept;
};

TrustStatement buildTrustStatement(const std::vector<EvidenceEnvelope>& envelopes);

} // namespace ksword::evidence

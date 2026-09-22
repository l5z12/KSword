#pragma once

// X module: cross-view difference explanation and verification.
//
// Input consists of multiple sampling rounds, each containing observations from several views. Output is not "equal/unequal" but rather:
//   * The hit status of each object in each view, and whether that view was qualified to perform "missing item" inference at that time;
//   * Resampling history after the first missing item, distinguishing transient differences, persistent differences, objects that have ended, and items that cannot be re-verified;
//   * View count and **independent source group count** are tracked separately; two layers of wrapping from the same collector do not count as two sources.
//
// Three hard rules that span the entire module:
//   * X-06: View timeout/rejection/truncation/unsupported/complete absence does not confirm "the view does not exist".
//     The census, re-examination, and conclusion stages must all be handled as 'unable to determine';
//     it is strictly forbidden to benignly convert them to 'object ended' or 'no differences found'.
//   * X-01: Trustworthiness can only be upheld by independent sources that are genuinely present in every round. The view set takes the union of all
//     rounds (absent rounds explicitly produce NotCollected), and the source group count takes the minimum of the independent group counts per round.
//   * X-04: Loading a module, DriverObject, DeviceObject, and disk service configuration are four distinct entities; a one-to-one correspondence is not
//     required. Inference for missing items is performed only between views of the same category; cross-category interactions record only cardinality facts.
//
// This layer does not recognize rootkits nor produce malicious verdicts; it only provides facts traceable to source records.

#include "EvidenceEnvelope.h"
#include "ObjectIdentity.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

// The presence of an object in a view.
enum class ObjectPresence {
    kPresent,               // This view lists this object.
    kAbsentInUsableView,    // The view is valid, self-consistent, and covers the target range, yet this object is absent.
    kUnknownViewFailed,     // View failure/timeout/access denied/entire round absent — not 'confirmed non-existent'.
    kUnknownOutOfCoverage,  // View succeeded but was truncated, did not cover the target range, or the account balance is insufficient to prove completeness.
    kNotComparableCategory, // X-04: This view enumerates a different class of entities; missing items are structurally valid.
};

const char* objectPresenceName(ObjectPresence presence) noexcept;

// X-04: Entity categories enumerated by the view. Missing item inference only holds within the same category.
// Unspecified is comparable with Unspecified (callers in a single entity domain need not worry about the category).
enum class ViewEntityCategory {
    kUnspecified,
    kProcessList,        // Process list
    kThreadList,         // Thread list
    kLoadedModuleList,   // Loaded module list (PsLoadedModuleList / module enumeration)
    kDriverObjectTable,  // DriverObject under the \Driver directory
    kDeviceObjectTree,   // Device object tree
    kServiceConfig,      // Service configuration on disk (registry), unrelated to 'loaded' state.
};

const char* viewEntityCategoryName(ViewEntityCategory category) noexcept;

// X-06: Only views that are successful, cover the target scope, and **positively prove integrity** can be used for absence inference.
// Note: A CoverageAccount with all default fields causes fullyCovered() to return true, which only indicates "no failure was recorded,"
// not "the enumeration was truly complete." Therefore, an additional requirement is imposed for the account to provide positive evidence:
//   (a) totalKnown is declared and succeeded has reached it; or (b) all four
//   endpoints (requested/processed) exist, and processed covers requested.
// If both are missing, no account is filled = cannot be used as 'confirmation of absence'.
bool viewUsableForAbsence(const EvidenceEnvelope& envelope, bool coversTargetScope) noexcept;

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// A view record. Fill identity based on kind (choose one of three); rawRecordId points back to the original row for X-07 unwind.
struct ViewRecord final {
    ObjectKind kind = ObjectKind::kUnknown;
    ProcessInstanceId process;
    ThreadInstanceId thread;
    DriverInstanceId driver;
    std::string rawRecordId;

    // Cross-session primary key. Empty when identity is insufficient; in this case, the object can only enter candidate state (see candidateKey).
    std::string identityKey() const;

    // X-02: Weak identity deduplication key. **Valid only within this analysis session**, constructed from reusable identifiers like PID/TID/name/path.
    // It is absolutely not a cross-session primary key, nor should it be used to determine "this is definitely the same object." Its sole purpose is to
    // ensure a weak identity object appears exactly once in the report, rather than being dropped or duplicated by record count.
    std::string candidateKey() const;

    IdentityStrength strength() const noexcept;
    std::string displayText() const;
};

struct ViewSnapshot final {
    std::string viewId;
    EvidenceEnvelope envelope;
    // X-04: The entity category enumerated by this view. Default Unspecified indicates 'in the same domain as other views with unspecified categories'.
    ViewEntityCategory category = ViewEntityCategory::kUnspecified;
    // Whether this view claims to cover the target scope for the current comparison (e.g., 'all processes').
    bool coversTargetScope = true;
    std::vector<ViewRecord> records;
};

struct SampleRound final {
    std::uint64_t sampleId = 0;
    OptionalU64 sampleUtc100ns;
    std::vector<ViewSnapshot> views;
};

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------
enum class DiscrepancyState {
    kNoDiscrepancy,   // Observed in every available view.
    kPendingRecheck,  // First missing item; resampling rounds are insufficient.
    kTransient,       // Appeared in subsequent samples — a sampling time difference, not hidden.
    kPersistent,      // The required number of review rounds has been reached, and the item is consistently missing in available views.
    kObjectEnded,     // Note: The object ended before review (the witness view has all items available this round and no longer lists it).
    kUnverifiable,    // Not enough views in the review round qualified for missing item inference.
    kCandidateOnly,   // X-02: Insufficient identity; retain only the candidate relationship and prohibit participation in any diff upgrades.
};

const char* discrepancyStateName(DiscrepancyState state) noexcept;

// F-05: State and conclusion are two independent axes, but they must not contradict each other (e.g., Persistent+NoEvidence,
// ObjectEnded+NoDifferenceObserved). analyzeCrossView performs this validation at the end and provides a fallback.
bool stateConclusionConsistent(DiscrepancyState state, AnalysisConclusion conclusion) noexcept;

struct ViewHit final {
    std::string viewId;
    std::string sourceGroup;   // Independent source group for this view in this round; empty (unknown for this round) if absent for the entire round.
    ObjectPresence presence = ObjectPresence::kUnknownViewFailed;
    std::string rawRecordId;   // Refers to the source record when Present.
    CollectionStatus viewStatus = CollectionStatus::kNotCollected;
    ViewEntityCategory category = ViewEntityCategory::kUnspecified;
};

// X-04: Cross-category "missing items" are structural phenomena, not differences. This section only states cardinality facts; for example,
// "present in the module list but absent in the DriverObject view" is an independent observation and does not constitute a difference by default.
struct CategoryObservation final {
    ViewEntityCategory category = ViewEntityCategory::kUnspecified;
    std::size_t viewsInCategory = 0;        // Number of views in this category (including absences in this round).
    std::size_t viewsListing = 0;           // Lists the number of views for this object.
    std::size_t usableViewsNotListing = 0;  // Number of available views that do not list this object.
    bool comparable = false;                // Whether this category participates in the object's absence inference.
};

struct RecheckEntry final {
    std::uint64_t sampleId = 0;
    OptionalU64 sampleUtc100ns;
    OptionalU64 intervalFromFirst100ns;  // Interval from the first observation; unset if no timestamp or clock rollback occurs.
    bool clockWentBackwards = false;     // X-05: Current UTC is earlier than the first round; interval unavailable (NTP correction).
    std::size_t presentViews = 0;
    std::size_t usableAbsentViews = 0;
    std::size_t unusableViews = 0;
    std::size_t crossCategoryViews = 0;  // X-04: Different entity categories do not participate in missing-item inference.
    // X-07: Each iteration expands per-view hits and original record IDs, rather than retaining only three counters.
    std::vector<ViewHit> hits;
};

// X-02: **Candidate relationship** between weak identity records and strong identity objects.
//
// Why it's needed: Weak records (e.g., a process whose creation time is unavailable in a view) previously
// resulted in isolated CandidateOnly findings, making it unclear in reports that "it might be the confirmed
// object." However, it must never be merged in—that is exactly the false merge prohibited by X-02.
//
// Only Match* paths using ObjectIdentity are taken; the result is **never Confirmed**: weak identities are by definition insufficient
// for confirmation, and the unified identity threshold will downgrade them to Candidate. NoMatch pairs are not recorded.
struct CandidateLink final {
    std::string strongIdentityKey;  // Strong identity object corresponding to the candidate.
    MatchResult match = MatchResult::kCandidate;
    std::string basis;              // Basis description: which fields match and which are missing.
};

struct CrossViewFinding final {
    ObjectKind kind = ObjectKind::kUnknown;
    // Empty indicates insufficient identity (X-02); in this case, candidateKey is non-empty and state is always CandidateOnly.
    std::string identityKey;
    // Weak identity deduplication key; empty when identityKey is non-null. It is not a primary key, used only for reporting deduplication and localization.
    std::string candidateKey;
    IdentityStrength strength = IdentityStrength::kUnusable;
    std::string displayText;

    DiscrepancyState state = DiscrepancyState::kNoDiscrepancy;
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;

    std::vector<ViewHit> latestHits;             // X-07: Hit status per view in the last round.
    std::vector<RecheckEntry> recheckHistory;    // X-07: Recheck history (including per-round hits).
    std::vector<CategoryObservation> latestCategories;  // X-04: Category cardinality of the last round

    // X-02: When this is a weak record, list the strong identity objects it may correspond to (never Confirmed).
    // On strong identity objects, list weak records pointing to them; direction is distinguished by whether identityKey is null.
    std::vector<CandidateLink> candidateLinks;

    // X-07: Trace back from the conclusion to the source record that first reported the object.
    std::string firstSeenViewId;
    std::string firstSeenRawRecordId;
    std::size_t firstSeenRoundIndex = 0;

    // X-01: viewCount is the size of the union of view IDs across all rounds, always equal to latestHits.size();
    // independentSourceGroupCount is the **minimum number of independent source groups per round**
    // — sources that appear only in round 1 and then disappear cannot sustain credibility.
    std::size_t viewCount = 0;
    std::size_t independentSourceGroupCount = 0;
    std::size_t latestRoundViewCount = 0;  // Number of views actually present in the last round.
};

struct CrossViewReport final {
    std::vector<CrossViewFinding> findings;
    TrustStatement trust;
    std::size_t roundCount = 0;
    // X-01: Provide the three metrics separately to avoid using the "best round" to falsely inflate the credibility of the entire sampling period.
    std::size_t viewCount = 0;             // Union of all round view IDs.
    std::size_t latestRoundViewCount = 0;  // Actual attendance in the last round.
    std::size_t minRoundViewCount = 0;     // Minimum actual round count.
    std::size_t independentSourceGroupCount = 0;  // Minimum independent group count across rounds.
    // Number of records with insufficient identity that can only retain candidate relationships (X-02/X-03: avoid false merges).
    std::size_t weakIdentityRecords = 0;
    // Number of unique objects after deduplication by weak identity; each object generates a CandidateOnly finding.
    std::size_t weakIdentityObjects = 0;
    // X-02: Total number of candidate edges established between 'weak records' and 'strong objects' (counted once per pair).
    std::size_t candidateLinkCount = 0;
    // Internal consistency self-check (see SelfCheck in .cpp): Always true on the normal path. If false, the counting
    // scope does not match the hits, so the UI must downgrade the entire report display instead of accepting it as-is.
    bool selfCheckPassed = true;
};

struct CrossViewOptions final {
    // X-05: Attempt recheck in at least two subsequent samples by default.
    std::size_t requiredRecheckRounds = 2;
};

CrossViewReport analyzeCrossView(const std::vector<SampleRound>& rounds,
                                 const CrossViewOptions& options = CrossViewOptions{});

} // namespace ksword::evidence

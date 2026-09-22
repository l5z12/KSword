#pragma once

// T module: Unified timeline and investigation session (analysis layer).
//
// This layer performs no data collection. ETW, Callback Monitor, and File Monitor remain the existing collectors.
// This file provides only nine criteria: session state, event envelope, time semantics, process ownership,
// lost accounts, filter separation, boundedness and retention, save and restore, and relationship edges. This
// enables the same set of criteria to be used by both offline sample drivers and real-time collection drivers.
//
// Hard rule spanning the entire module:
//   * T-01: **"Pause Display" and "Stop Collection" are distinct actions**. Pausing only freezes the UI; the background continues logging and persisting data.
//     No new events may be recorded after stopping. Any transfer must explicitly state whether the background is still recording.
//   * T-02: Unknown event versions **must not** be mapped to old structures. Unknown events should be saved as
//     unparseable records, preserving original fields and payloads, while the parsing version is logged separately.
//   * T-04: No strict total order across sources. Sort keys are deterministic and interpretable, but "determinism" comes from
//     tiebreak rules, not the illusion of "precisely comparable timestamps"; indistinguishable adjacent orders must be flagged.
//     Subtracting two timestamps always follows the signed path; unsigned wraparound would report a 1ms callback as an astronomical number.
//   * T-05: When a process start event is missing, create a temporary entity with "incomplete identity"; **never** silently assign
//     it to the current process with the same PID. PID reuse and "late events after the target has ended" must be distinguishable.
//   * T-06: Count six categories of losses separately without duplication; a count of 0 must have a named
//     statistical source. If the source only provides total time, do not fabricate precise loss time intervals.
//   * T-12: Relationship is not causality. Causal wording is only allowed on SourceProvidedLink.
//
// This layer produces no malicious verdicts and contains no fields like malicious/threat/suspicious/riskScore.

#include "EvidenceEnvelope.h"
#include "EvidenceJson.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ksword::evidence {

// ===========================================================================
// T-01: Session lifecycle
// ===========================================================================

// Five states. DisplayPaused and Stopped are distinct states. Previous implementations merged them into a single button
// and returned directly in ETW callbacks (pause = silently drop events). This enforces separation at the type level.
enum class SessionState {
    kNew,           // Newly created but not started; range and upper bound are modifiable.
    kCollecting,    // Background recording + UI refresh
    kDisplayPaused, // UI frozen, **background recording continues**
    kStopped,       // Collection stopped; no new events recorded, ready for save.
    kSaved,         // Persisted to disk; read-only
};

const char* sessionStateName(SessionState state) noexcept;

// T-01: Do not record new events after stopping. Only these two states accept new events.
bool sessionAcceptsNewEvents(SessionState state) noexcept;

// T-01: Whether the UI refreshes with events. DisplayPaused is false, but this does not affect the line above.
bool sessionUpdatesDisplay(SessionState state) noexcept;

enum class SessionAction {
    kStart,           // Start collection
    kPauseDisplay,    // Pause display (continue in background)
    kResumeDisplay,   // Resume display
    kStopCollection,  // Stop collection
    kSave,            // Save
    kReset,           // Create new (discard current session content, return to New).
};

const char* sessionActionName(SessionAction action) noexcept;

// Transition criteria: when allowed=false, nextState remains current, and backgroundRecording /
// displayUpdating still describe the **current** state—illegal actions do not change any facts.
struct SessionTransition final {
    bool allowed = false;
    SessionState nextState = SessionState::kNew;
    bool backgroundRecording = false;  // Whether background recording continues after transfer.
    bool displayUpdating = false;      // Whether the UI follows incoming events after the transition.
    // Explanation key for buffering/persistence while paused (T-01 requires the pause-time policy to be visible).
    std::string bufferingNoticeKey;
    std::string rejectionKey;  // i18n reason key when allowed=false; empty when transfer is valid.
};

SessionTransition evaluateSessionTransition(SessionState current, SessionAction action);

// ===========================================================================
// T-02: Event envelope and parsing results
// ===========================================================================

// The six required categories for the first round. Other is used for events outside the declared scope; it is not a synonym for 'unresolvable'.
enum class TimelineEventCategory {
    kProcess,
    kThread,
    kImage,
    kFile,
    kRegistry,
    kNetwork,
    kOther,
};

const char* timelineEventCategoryName(TimelineEventCategory category) noexcept;

// T-02: Three-state parse result. Default is UnparsedUnknownSchema. Forgetting to run the parser should not yield a 'parsed'
// state; this is the flaw in the existing implementation (where the fallback branch also sets decodedReady to true).
enum class EventParseOutcome {
    kParsed,                // Parser matching exact (provider, eventId, version).
    kUnparsedUnknownSchema, // No parser exists for this version; save as an unparsed record without applying the old structure.
    kMalformed,             // Payload itself is malformed or truncated, lacking even original fields.
};

const char* eventParseOutcomeName(EventParseOutcome outcome) noexcept;

// Raw fields: name -> original text. Unparsed records retain this for export and subsequent replay.
using RawFieldList = std::vector<std::pair<std::string, std::string>>;

// Time resolution. Used to convert the 'indistinguishable window' during cross-source comparison, not for display formatting.
enum class TimeResolution {
    kUnknown,
    kSecond,
    kMillisecond,
    kMicrosecond,
    kHundredNanosecond,
};

const char* timeResolutionName(TimeResolution resolution) noexcept;

// The indistinguishable span corresponding to the precision (in 100ns units). Returns 0 for Unknown; the caller uses this to determine 'cannot be defined'.
std::uint64_t resolutionSpan100ns(TimeResolution resolution) noexcept;

// ===========================================================================
// T-04: Time semantics
//
// Clock calibration is an optional, independent fact; never overwrite source time in-place: preserve
// source time as-is, record calibration offset separately, and treat 'effective time' as a derived value.
// ===========================================================================

struct EventTimeStamp final {
    OptionalU64 sourceTime100ns;   // Original time provided by the source; no path may modify it.
    OptionalU64 receiveTime100ns;  // R3: Receive (enqueue) timestamp
    TimeResolution sourceResolution = TimeResolution::kUnknown;

    // Calibration: record if available for later display; sourceTime100ns always retains its original value.
    bool calibrationAvailable = false;
    std::int64_t calibrationOffset100ns = 0;
    std::string calibrationId;  // Calibration source identifier; this ID changes when calibration changes.

    std::string bootId;             // Boot cycle. Do not subtract time values with different bootId values.
    OptionalU64 sourceMonotonic;    // QPC count, comparable only within the same bootId.

    bool lateArrival = false;    // Late arrival (received out of chronological order)
    bool orderUncertain = false; // Its order relative to adjacent events cannot be distinguished at this precision.

    // Effective time = source time (with cumulative correction if calibration exists, saturating without wraparound); if source time is missing, it degrades to receive time.
    // The second return value indicates which metric was used; the UI must display it.
    OptionalU64 effectiveTime100ns() const noexcept;
    bool effectiveFromReceiveTime() const noexcept;
};

// Comparison result for two timestamps. Never use unsigned subtraction: Module X
// previously failed due to wraparound (a 1ms rollback was reported as 5.8e13 years).
enum class TimeComparison {
    kComparable,             // Order determination
    kComparableButUncertain, // If the difference is within the timestamp precision, including identical timestamps, the order cannot be distinguished.
    kIncomparableCrossBoot,  // Time values are incomparable across boot cycles.
    kIncomparableUnknownTime,// No available time on either side
    kIncomparableMagnitude,  // Difference exceeds int64 range; prefer incomparable over wraparound.
};

const char* timeComparisonName(TimeComparison comparison) noexcept;

struct TimeComparisonResult final {
    TimeComparison kind = TimeComparison::kIncomparableUnknownTime;
    std::int64_t delta100ns = 0;  // later - earlier; valid only for Comparable*.
    bool regression = false;      // later time is earlier than earlier (out of order or clock rollback).
    bool calibrationChanged = false;  // Different calibrationId values on the two sides require a note qualifying the ordering.

    bool comparable() const noexcept {
        return kind == TimeComparison::kComparable || kind == TimeComparison::kComparableButUncertain;
    }
};

// earlier / later are merely parameter names and do not presuppose order; regression indicates the actual order is reversed relative to the parameter order.
TimeComparisonResult compareEventTimes(const EventTimeStamp& earlier,
                                       const EventTimeStamp& later) noexcept;

// Cross-source sort key. Deterministic = all fields participate in comparison with a final unique tiebreak; Interpretable
// = explanationKey explains why this entry is sorted here. **Does not claim strict total ordering across CPUs/sources**:
// for two entries with the same explanationKey of "tie-broken-by-arrival", their true relative order is unknown.
struct TimelineSortKey final {
    std::uint32_t bootEpochRank = 0;    // Order of first appearance of bootId; grouped by bootId across boots.
    bool timeKnown = false;             // Whether valid time is available.
    std::uint64_t effectiveTime100ns = 0;
    std::uint64_t arrivalSequence = 0;  // R3 receive sequence number, deterministic tiebreak.
    std::string sourceGroup;            // Source group, stable tiebreak.
    std::string recordId;               // Final unique tiebreaker.
    std::string explanationKey;         // Explanation of the sort key for this entry (i18n key).
};

// Strict weak ordering. Unknown timestamps are placed after known ones (rather than being treated as 0 and sorted to the front).
bool sortKeyLess(const TimelineSortKey& a, const TimelineSortKey& b) noexcept;

// ===========================================================================
// T-05 process ownership
// ===========================================================================

enum class AttributionKind {
    kBoundToInstance,   // Within the lifetime window of a known instance.
    kProvisional,       // Missing start event or falling outside all known windows — establishes an incomplete provisional identity entity.
    kAfterInstanceExit, // Known that the instance with the same PID has exited, and no new instance has overwritten it after the event time.
    kAmbiguous,         // Multiple windows with the same PID overlap at this timestamp; do not guess.
    kUnknownProcess,    // No PID available.
};

const char* attributionKindName(AttributionKind kind) noexcept;

// Provisional entity. identityComplete is always false until confirmProvisional() completes the evidence.
struct ProvisionalProcessEntity final {
    std::string provisionalId;   // Stable temporary ID used for export and subsequent association.
    std::string bootId;
    OptionalU64 pid;
    OptionalU64 firstSeenTime100ns;
    OptionalU64 lastSeenTime100ns;
    std::uint64_t eventCount = 0;
    AttributionKind originKind = AttributionKind::kProvisional;  // Reason at establishment

    bool identityComplete = false;
    std::string resolvedInstanceKey;  // The crossSessionKey associated with the instance after resolution.
    std::string resolutionNoteKey;    // Association process note (i18n key), for tracking.
};

struct AttributionDecision final {
    AttributionKind kind = AttributionKind::kUnknownProcess;
    ProcessInstanceId instance;  // Only meaningful when BoundToInstance is set.
    std::string provisionalId;   // Relevant in Provisional, AfterInstanceExit, or Ambiguous states.
    IdentityStrength identityStrength = IdentityStrength::kUnusable;
    // Unified threshold for ObjectIdentity: if identity is insufficient, the strongest result is Candidate.
    MatchResult identityMatch = MatchResult::kCandidate;
    std::string reasonKey;
};

// Process instance ledger. Only records "seen start/end" events without any live context access.
class ProcessInstanceLedger final {
public:
    // Observe process start event. Identity must include at least bootId+pid; otherwise, registration is rejected and false is returned.
    bool observeStart(const ProcessInstanceId& identity, std::uint64_t startTime100ns);

    // Note: Process exit event observed. Returns false if no matching instance is found (do not fabricate 'exited' instances).
    //
    // T-05: When identity includes createTime100ns, it **must** exactly match the createTime in the instance record.
    // createTime is the field that distinguishes PID-reused instances. Selecting candidates solely by bootId/pid/"latest start time" would
    // incorrectly attribute A's late exit event to B (A's window would appear infinitely extended, while B is deemed ended), causing
    // subsequent events to be misattributed back and forth between A and B. Reject mismatches and let the caller record an unmatched exit.
    bool observeExit(const ProcessInstanceId& identity, std::uint64_t exitTime100ns);

    // Without createTime, candidates must be selected by 'latest start time and not yet ended', which is a weak
    // match. The count is exposed separately to allow the UI/report to indicate 'these exit times are guesses'.
    std::size_t weakExitMatchCount() const noexcept { return weakExitMatchCount_; }

    // Attribution decision. **Will not** send events falling outside the window to the current process with the same PID.
    AttributionDecision attribute(const std::string& bootId,
                                  const OptionalU64& pid,
                                  const EventTimeStamp& time);

    // Later, the start evidence was added: attaching the temporary entity to the real instance and leaving a traceable note.
    bool confirmProvisional(const std::string& provisionalId,
                            const ProcessInstanceId& identity,
                            std::string noteKey);

    const std::vector<ProvisionalProcessEntity>& provisionals() const noexcept {
        return provisionals_;
    }
    const ProvisionalProcessEntity* findProvisional(const std::string& provisionalId) const noexcept;

    std::size_t instanceCount() const noexcept { return instances_.size(); }

private:
    struct InstanceRecord final {
        ProcessInstanceId identity;
        std::uint64_t startTime100ns = 0;
        bool exitKnown = false;
        std::uint64_t exitTime100ns = 0;
    };

    ProvisionalProcessEntity& touchProvisional(const std::string& bootId,
                                               const OptionalU64& pid,
                                               const OptionalU64& time,
                                               AttributionKind originKind);

    std::vector<InstanceRecord> instances_;
    std::vector<ProvisionalProcessEntity> provisionals_;
    // Temporary entity ID -> index. IDs are length-prefixed encoded, so ID equality <=> (bootId, pid, originKind) equality.
    std::unordered_map<std::string, std::size_t> provisionalIndex_;
    std::size_t weakExitMatchCount_ = 0;
};

// T-05: The provisional entity ID is uniquely determined by (bootId, pid, originKind). **Do not** simply concatenate them: an empty
// bootId degrades to "boot-unknown", which would collide with an actual boot cycle named "boot-unknown"; similarly, a bootId containing
// ":pid=" would also cause collisions. Therefore, each segment includes a length prefix, ensuring the encoding is injective.
std::string makeProvisionalEntityId(const std::string& bootId,
                                    const OptionalU64& pid,
                                    AttributionKind originKind);

// ===========================================================================
// T-06: Loss ledger
// ===========================================================================

enum class LossCategory {
    kSourceDrop,       // Drops reported by the source (ETW session / provider).
    kRingOverwrite,    // Driver ring buffer overwrite / cursor lagging behind.
    kQueueDiscard,     // R3 queue discard
    kParseFailure,     // Parse failure
    kFilteredOut,      // Filtered out by collection (never entered the session, unrelated to display filtering)
    kRetentionEvicted, // Retention policy eviction
};

inline constexpr std::size_t kLossCategoryCount = 6U;
const char* lossCategoryName(LossCategory category) noexcept;
LossCategory lossCategoryAt(std::size_t index) noexcept;

// A counter for a class of lost events. An unset count means "unknown", which is distinct from 0; a count of 0 must also include a source.
struct LossCounter final {
    OptionalU64 count;
    std::string statisticSource;      // "etw.EventsLost" / "ring.OverwriteCount" / "local.parser" …
    bool sourceIsAuthoritative = false;  // true = Source is authoritative; local increment is prohibited.
    bool intervalSupported = false;   // Whether the source truly provides a lost time interval.
    OptionalU64 intervalBegin100ns;
    OptionalU64 intervalEnd100ns;
};

// Accounting rule (T-06 "No duplicate counting"):
//   * declareSource() assigns a unique statistical source for a category. Reset before changing the source.
//   * Categories with an authoritative source (sourceIsAuthoritative=true) can only call setAbsolute(), not addObserved().
//     Locally incremented categories can only use addObserved(), not setAbsolute(). Mixing both paths causes double counting.
//   * setInterval() is only valid if the source declares intervalSupported; otherwise, it is rejected—do not fabricate intervals.
class LossLedger final {
public:
    bool declareSource(LossCategory category,
                       std::string statisticSource,
                       bool sourceIsAuthoritative,
                       bool intervalSupported);

    bool setAbsolute(LossCategory category, std::uint64_t count);
    bool addObserved(LossCategory category, std::uint64_t delta);
    bool setInterval(LossCategory category, std::uint64_t begin100ns, std::uint64_t end100ns);

    const LossCounter& counter(LossCategory category) const noexcept;
    LossCounter& mutableCounter(LossCategory category) noexcept;

    bool anyUnknown() const noexcept;   // Any category lacks a named source or count.
    // Return unset if any category is unknown: adding unknown as 0 would present a partial trace as complete.
    OptionalU64 totalLost() const noexcept;

    // Explanation keys for UI/reports. Even without losses, it provides a positive explanation stating that all six categories have named sources.
    std::vector<std::string> limitationKeys() const;

private:
    LossCounter counters_[kLossCategoryCount];
};

// ===========================================================================
// T-03: Filter separation
// ===========================================================================

enum class FilterStage {
    kCollection,  // Collection filtering: if a match occurs, do not enter the session and count it as FilteredOut.
    kDisplay,     // Display filtering: modifies only the visible set, leaving session content unchanged.
};

const char* filterStageName(FilterStage stage) noexcept;

// Minimal rule set: an empty list means no restriction on this dimension. The production side can extend it, but the criteria remain unchanged.
struct EventFilter final {
    bool active = false;
    std::string ruleId;
    std::vector<std::uint64_t> allowedPids;
    std::vector<TimelineEventCategory> allowedCategories;
    std::vector<std::string> allowedProviderIds;
};

struct TimelineEvent;  // Forward declaration

bool filterAdmits(const EventFilter& filter, const TimelineEvent& event) noexcept;

enum class ExportScope {
    kVisibleOnly,  // Export only the results filtered by current visibility.
    kFullSession,  // Exports all events retained in the session (display filtering does not apply).
};

const char* exportScopeName(ExportScope scope) noexcept;

struct ExportPlan final {
    ExportScope scope = ExportScope::kVisibleOnly;
    std::uint64_t exportedEventCount = 0;
    std::uint64_t retainedEventCount = 0;       // Actual number of entries retained in the session
    std::uint64_t hiddenByDisplayFilter = 0;    // Hidden by display filter but still present in the session.
    std::uint64_t excludedByCollectionFilter = 0;  // Excluded by collection filter; never entered the session.
    bool representsRetainedSession = false;     // Whether all events retained by the session are covered.
    // Whether the session itself represents complete system activity. Requires positive evidence:
    //   * At least one collector capability must be declared, and every declared collector must be Success.
    //   * No collection filtering, no loss/eviction, and no timeout.
    //   Accounting did not fail
    //   * If the session is restored from a file, that file must be structurally complete (status == Ok) and contain no events that cannot be restored.
    // If any required item is missing, the result is false. A session where a collector was declared but never executed is definitely not a complete collection.
    bool retainedSessionIsCompleteCapture = false;
    // Count of collectors that are declared but not in Success state (only valid if count is 0 and capabilities are non-empty).
    std::uint64_t unavailableCollectorCount = 0;
    // T-10: Count of events present in the file but unrecoverable (uncommitted tail + excess portion declared by the trailer).
    std::uint64_t unrecoverableFileEventCount = 0;
    std::vector<std::string> noticeKeys;        // Notice keys that must be exported.
};

// ===========================================================================
// T-08 Bounded and retention policies
// ===========================================================================

enum class RetentionPolicy {
    kStopOnLimit,  // Stop recording new events upon reaching the limit.
    kEvictOldest,  // Evict the oldest upon reaching the limit.
};

const char* retentionPolicyName(RetentionPolicy policy) noexcept;

struct BoundsPolicy final {
    OptionalU64 maxEventsInMemory;
    OptionalU64 maxArchiveBytes;
    OptionalU64 approximateBytesPerEvent;  // Converts disk limit to count; if unknown, no conversion is performed.
    RetentionPolicy policy = RetentionPolicy::kStopOnLimit;
    // T-08: Upper bound and limit behavior must be presented **before collection**. If not declared, collection is not allowed to start.
    bool declaredBeforeCollection = false;
};

enum class BoundsState {
    kWithinLimits,
    kMemoryLimitReached,
    kArchiveLimitReached,
};

const char* boundsStateName(BoundsState state) noexcept;

struct IngestResult final {
    bool accepted = false;         // Whether the event enters the session.
    bool evictedOldest = false;    // Whether the oldest entry was evicted to make room.
    bool countedAsLoss = false;    // Whether an entry has already been recorded in the account.
    LossCategory lossCategory = LossCategory::kQueueDiscard;
    BoundsState bounds = BoundsState::kWithinLimits;
    std::string reasonKey;
    std::uint64_t assignedSequence = 0;  // Receive sequence number upon acceptance.
};

// ===========================================================================
// T-02: Event entity
// ===========================================================================

struct TimelineEvent final {
    std::string recordId;      // Stable ID within the session.
    std::string providerId;    // provider name or GUID text
    std::string sourceGroup;   // Independent source group (multiple layers of wrapping from the same collector share this).
    std::uint32_t eventId = 0;
    std::uint32_t eventVersion = 0;
    std::uint32_t opcode = 0;
    std::uint32_t task = 0;
    TimelineEventCategory category = TimelineEventCategory::kOther;

    EventParseOutcome parseOutcome = EventParseOutcome::kUnparsedUnknownSchema;
    std::string parserId;              // The parser actually in use; null if not parsed.
    std::uint32_t parserVersion = 0;   // Unparsed value is 0 — do not use any other version number.
    std::string parseReasonKey;

    RawFieldList rawFields;      // Raw fields; unresolved records are also retained.
    std::string rawPayloadHex;   // Raw payload as hexadecimal text for subsequent re-parsing.

    EventTimeStamp time;

    // Attribution result. Binds events to a process instance; when evidence is missing, it uses provisionalId rather than 'the current process with the same PID'.
    AttributionKind attribution = AttributionKind::kUnknownProcess;
    std::string processInstanceKey;  // crossSessionKey: Null when identity is insufficient.
    std::string provisionalProcessId;
    OptionalU64 pid;
    OptionalU64 tid;

    std::uint64_t arrivalSequence = 0;  // Assigned by the session during ingest.

    // Correlation fields provided directly by the source (e.g., ETW ActivityId / CorrelationId).
    // Only these can support SourceProvidedLink edges, thereby enabling causal phrasing.
    std::string sourceLinkId;
    std::string sourceLinkField;
};

// ---------------------------------------------------------------------------
// T-02 parsing: Unknown versions do not use old structures.
// ---------------------------------------------------------------------------

struct EventSchema final {
    std::string providerId;
    std::uint32_t eventId = 0;
    std::uint32_t version = 0;
    std::string parserId;
    std::uint32_t parserVersion = 0;
    TimelineEventCategory category = TimelineEventCategory::kOther;
    std::vector<std::string> requiredFields;
};

class EventSchemaRegistry final {
public:
    void add(EventSchema schema);

    // Exact match on (provider, eventId, version). **No** path for 'nearest downgrade to a lower version'.
    const EventSchema* findExact(const std::string& providerId,
                                 std::uint32_t eventId,
                                 std::uint32_t version) const noexcept;

    // Used solely to distinguish 'unknown provider/eventId' from 'known event with unknown
    // version' to make reasonKey more precise; it never participates in parser selection.
    bool knowsProviderEvent(const std::string& providerId, std::uint32_t eventId) const noexcept;

    std::size_t size() const noexcept { return schemas_.size(); }

private:
    std::vector<EventSchema> schemas_;
};

struct EventParseRequest final {
    std::string providerId;
    std::uint32_t eventId = 0;
    std::uint32_t version = 0;
    RawFieldList rawFields;
    std::string rawPayloadHex;
    bool payloadTruncated = false;  // Payload known to be incomplete on the collection side.
};

struct EventParseReport final {
    EventParseOutcome outcome = EventParseOutcome::kUnparsedUnknownSchema;
    std::string parserId;
    std::uint32_t parserVersion = 0;
    std::string reasonKey;
    std::vector<std::string> missingRequiredFields;
    TimelineEventCategory category = TimelineEventCategory::kOther;
};

EventParseReport parseEventPayload(const EventSchemaRegistry& registry,
                                   const EventParseRequest& request);

// Apply the parsing conclusion to the event. If parsing failed, keep parserVersion as 0 and retain rawFields unchanged.
void applyParseReport(TimelineEvent& event, const EventParseReport& report);

// ===========================================================================
// T-12 relationship edge (no causal impersonation)
// ===========================================================================

enum class TimelineEdgeKind {
    kSameProcess,        // Same process instance
    kParentChild,        // Parent-child process (from the parent instance field of process creation events)
    kTemporalNeighbor,   // Temporal neighbors — merely "occurring adjacent to each other".
    kSourceProvidedLink, // Directly provided source association (ActivityId / CorrelationId).
};

const char* timelineEdgeKindName(TimelineEdgeKind kind) noexcept;

// Only SourceProvidedLink permits causal wording. The API contains, and will never contain, a 'causes' field.
bool edgeKindAllowsCausalWording(TimelineEdgeKind kind) noexcept;

struct TimelineEdge final {
    TimelineEdgeKind kind = TimelineEdgeKind::kTemporalNeighbor;
    std::string fromRecordId;
    std::string toRecordId;
    std::string basisKey;         // Edge construction basis (i18n key); visible when clicked in the UI.
    std::string basisDetail;      // Specific value of the basis, e.g., instance key or ActivityId.
    OptionalU64 temporalGap100ns; // Time difference when TemporalNeighbor.
    bool orderUncertain = false;  // The order of the two endpoints cannot be distinguished at this precision.
};

struct EdgeBuildOptions final {
    // If not set, no TemporalNeighbor edge is created; 'adjacency' must be explicitly requested by the caller.
    OptionalU64 temporalNeighborWindow100ns;
    bool includeSameProcess = true;
    bool includeParentChild = true;
    bool includeSourceProvidedLink = true;
};

// Parent-child relationship source: The (child, parent) instance keys provided by the source in the process creation event.
struct ParentChildFact final {
    std::string recordId;          // Event carrying this fact
    std::string childInstanceKey;
    std::string parentInstanceKey;
};

std::vector<TimelineEdge> buildEdges(const std::vector<TimelineEvent>& events,
                                     const std::vector<ParentChildFact>& parentFacts,
                                     const EdgeBuildOptions& options);

// ===========================================================================
// T-10: Load result (the session must carry it itself, so it is declared before the session).
// ===========================================================================

enum class SessionLoadStatus {
    kOk,                     // Header, all batches, and trailer are present and self-consistent.
    kEmpty,                  // Empty input
    kMissingHeader,          // The first line is not a valid header.
    kVersionTooNew,          // formatVersion is higher than this version — do not guess or modify the file.
    kIncompleteTail,         // Submitted batch is recoverable; tail is incomplete (missing trailer / partial line).
    kCorrupt,                // Structural corruption or checksum mismatch occurred mid-stream; previous batches remain intact.
    kTrailerMismatch,        // Note: trailer declared count does not match actual recovery count.
};

const char* sessionLoadStatusName(SessionLoadStatus status) noexcept;

// T-10: The loading conclusion must be attached to the session itself, not just to a one-time SessionLoadResult.
// Otherwise, after handing over result.session, downstream components (export plan, envelope, UI) would see
// a clean session, and the 'trailer mismatch' issue would vanish completely after just two lines of code.
struct SessionLoadIntegrity final {
    bool restoredFromFile = false;
    SessionLoadStatus status = SessionLoadStatus::kOk;
    std::string diagnosticKey;
    // Count of events present in the file but unrecoverable: uncommitted tail + trailer declared excess over actual.
    // This is **not** one of the six T-06 collection loss categories (which refer to the collection period), but rather the T-10 "missing
    // marker for the uncommitted portion." Therefore, it is tracked separately with its own statistical source and must never be merged
    // into LossLedger::totalLost(). Mixing these two metrics would make it impossible to determine "how much was lost in this collection."
    std::uint64_t unrecoverableEventCount = 0;
    std::string unrecoverableStatisticSource;  // e.g., "local.session-file.uncommitted"

    bool representsCompleteFile() const noexcept { return status == SessionLoadStatus::kOk; }
};

// ===========================================================================
// Session
// ===========================================================================

struct CollectorCapability final {
    std::string collectorId;
    std::uint32_t collectorVersion = 0;
    std::string sourceGroup;
    SourceOrigin origin = SourceOrigin::kUnknown;
    std::vector<TimelineEventCategory> declaredCategories;
    // Whether this collector is actually available under this profile; if unavailable, a reason must be provided (do not leave blank when marked as available).
    CollectionOutcome availability;
};

struct SessionManifest final {
    std::string sessionId;
    std::string machineId;
    std::string bootId;
    std::string displayName;
    CaptureWindow window;
    std::vector<CollectorCapability> capabilities;
    // Query range (time/sequence), used for comparison after restart.
    OptionalU64 queryRangeBegin100ns;
    OptionalU64 queryRangeEnd100ns;
};

// Note: Event storage. Using deque instead of vector:
//   * T-08 EvictOldest must be O(1) per eviction. vector::erase(begin()) shifts the entire retained window
//     (measured: ~186 evictions/sec at 100k limit, 54x slower than the 10k/sec requirement in Section 7 L2);
//   * Uses page allocation; expansion does not require moving the entire block, nor does it need a single contiguous memory region.
//   * Element references remain valid when elements are added or removed at either end; pointers returned by visibleEvents() do not become invalid due to subsequent ingest operations.
using TimelineEventStore = std::deque<TimelineEvent>;

class TimelineSession final {
public:
    TimelineSession();
    TimelineSession(SessionManifest manifest, BoundsPolicy bounds);

    SessionState state() const noexcept { return state_; }
    const SessionManifest& manifest() const noexcept { return manifest_; }
    const BoundsPolicy& bounds() const noexcept { return bounds_; }
    void setManifest(SessionManifest manifest) { manifest_ = std::move(manifest); }

    // Execute state transition. Start requires additional conditions (T-08):
    //   1. The upper limit is declared before collection;
    //   2. The declared disk limit is **executable** — providing maxArchiveBytes without a
    //      non-zero approximateBytesPerEvent gives users a limit that will never take effect;
    //   3. There must be at least one upper bound that can be truly converted into a count; otherwise, the criterion 'memory has an upper limit' is empty.
    SessionTransition apply(SessionAction action);

    void setCollectionFilter(EventFilter filter) { collectionFilter_ = std::move(filter); }
    void setDisplayFilter(EventFilter filter) { displayFilter_ = std::move(filter); }
    const EventFilter& collectionFilter() const noexcept { return collectionFilter_; }
    const EventFilter& displayFilter() const noexcept { return displayFilter_; }

    // Ingestion entry point: status check -> recordId validation -> ingestion filtering -> bounded retention -> timestamping -> session assignment.
    // Display filtering does not participate in any judgment here (T-03).
    //
    // Reject if recordId is null or duplicates an existing event: recordId serves as the final tiebreaker for
    // sorting, the join key for relationship edges, and the export primary key; duplicates would cause these three to
    // point to different records. The rejected entry is logged as discarded on the R3 side, not silently swallowed.
    IngestResult ingest(TimelineEvent event);

    const TimelineEventStore& events() const noexcept { return events_; }
    std::vector<const TimelineEvent*> visibleEvents() const;

    LossLedger& loss() noexcept { return loss_; }
    const LossLedger& loss() const noexcept { return loss_; }
    ProcessInstanceLedger& processes() noexcept { return processes_; }
    const ProcessInstanceLedger& processes() const noexcept { return processes_; }

    // T-04: Deterministic and explainable sort keys, returned sorted by sortKeyLess.
    std::vector<TimelineSortKey> sortedOrder() const;

    // T-03: Export plan. VisibleOnly must include a note stating 'hidden events exist'.
    ExportPlan buildExportPlan(ExportScope scope) const;

    BoundsState boundsState() const noexcept { return boundsState_; }
    std::uint64_t nextSequence() const noexcept { return nextSequence_; }

    std::uint64_t collectionFilteredOutCount() const noexcept { return filteredOutCount_; }

    // T-06: True when local increments fail to be accounted for (e.g., source overridden by an authoritative external standard). When true, this class's count is
    // marked as "unknown", and totalLost() is unset—preferring to declare the entire ledger's total as undeterminable rather than silently dropping a single entry.
    bool lossAccountingFailed() const noexcept { return lossAccountingFailed_; }

    // T-10: Whether this session was recovered from a file and whether that file is complete.
    const SessionLoadIntegrity& loadIntegrity() const noexcept { return loadIntegrity_; }
    std::uint64_t unrecoverableFileEventCount() const noexcept {
        return loadIntegrity_.unrecoverableEventCount;
    }

    // Restore path only: directly append events from the committed batch, bypassing filtering and limits.
    // The sole reason for this path is T-10: upon restart, we must reproduce "what was
    // recorded at that time," not re-filter history using today's filters and limits.
    // Return false if recordId is null or duplicate: The file structure is corrupted; the caller must check for Corrupt.
    bool appendRestoredEvent(TimelineEvent event);
    void setStateForRestore(SessionState state) noexcept { state_ = state; }
    void setBoundsForRestore(BoundsPolicy bounds) { bounds_ = std::move(bounds); }
    void setStatsForRestore(std::uint64_t filteredOutCount, BoundsState bounds) noexcept;
    void setLoadIntegrityForRestore(SessionLoadIntegrity integrity) {
        loadIntegrity_ = std::move(integrity);
    }

private:
    struct BootEpoch final {
        std::string bootId;
        bool maxTimeKnown = false;
        std::uint64_t maxEffectiveTime100ns = 0U;
    };

    std::uint32_t registerBoot(const std::string& bootId);
    std::uint32_t bootRankOf(const std::string& bootId) const noexcept;
    // T-06: The four loss categories generated by the session itself must declare their sources via the session. Previously, callers had to run
    // declareSource() first; forgetting to do so caused addObserved() to return false for all entries, leaving lost counts unaccounted for.
    void declareLocalLossSources();
    // Returns whether this entry was truly recorded in the ledger. Failure to record is a hard error: the counter for
    // this category is set to unknown, lossAccountingFailed_ is set, ensuring this entry never disappears silently.
    bool recordLocalLoss(LossCategory category, std::uint64_t delta);

    SessionManifest manifest_;
    BoundsPolicy bounds_;
    SessionState state_ = SessionState::kNew;
    EventFilter collectionFilter_;
    EventFilter displayFilter_;
    TimelineEventStore events_;
    std::unordered_set<std::string> recordIds_;  // Retain recordId values within the window for O(1) duplicate detection.
    std::vector<BootEpoch> bootEpochs_;
    LossLedger loss_;
    ProcessInstanceLedger processes_;
    SessionLoadIntegrity loadIntegrity_;
    BoundsState boundsState_ = BoundsState::kWithinLimits;
    std::uint64_t nextSequence_ = 1U;
    std::uint64_t filteredOutCount_ = 0U;
    bool lossAccountingFailed_ = false;
};

// ===========================================================================
// T-09 / T-10 Save and restore
// ===========================================================================

// Line-delimited format: Line 1 is the header, followed by one line per committed batch, and a final line for the trailer.
// It is not a single JSON document: if killed mid-write, a single document would fail full parsing, making it impossible
// to meet the T-10 requirement that 'submitted batches remain recoverable while the uncommitted tail is marked missing'.
inline constexpr std::uint32_t kTimelineFormatVersion = 1U;
inline constexpr const char* kTimelineFormatKind = "ksword.timeline.session";

struct SessionBatch final {
    std::uint64_t batchIndex = 0;
    bool committed = false;
    std::vector<TimelineEvent> events;
};

// T-08: Stream output. Each line is passed to the sink as it is generated; peak memory usage is 'one batch' rather than 'the entire file'.
// For a session with 200,000 entries and 512B payloads, the old serializeSession would first allocate a 360 MiB block in memory
// std::string; this path is not taken. batchSize=0 is treated as 1 batch.
void serializeSessionTo(const TimelineSession& session,
                        std::size_t batchSize,
                        const std::function<void(std::string_view)>& sink);

// Serialize the entire session to a string. For small sessions and testing only; use serializeSessionTo for large sessions.
std::string serializeSession(const TimelineSession& session, std::size_t batchSize);

// Serialize only the header line (for reuse in the incremental write path).
std::string serializeSessionHeaderLine(const TimelineSession& session);
std::string serializeBatchLine(const SessionBatch& batch);
std::string serializeTrailerLine(const TimelineSession& session, std::uint64_t committedBatchCount);

struct SessionLoadResult final {
    SessionLoadStatus status = SessionLoadStatus::kEmpty;
    TimelineSession session;
    std::uint32_t fileFormatVersion = 0;
    std::uint64_t committedBatchCount = 0;
    std::uint64_t recoveredEventCount = 0;
    std::uint64_t uncommittedEventCount = 0;  // Count of entries in the uncommitted batch, marked as missing.
    bool trailerPresent = false;              // Whether a trailer line has been read.
    std::uint64_t declaredEventCount = 0;     // Count declared by the trailer; valid when trailerPresent.
    // Events present in the file but unrecoverable: uncommitted tail plus the excess count
    // declared by the trailer. Equal to result.session.unrecoverableFileEventCount().
    std::uint64_t unrecoverableEventCount = 0;
    std::size_t failedLineIndex = 0;          // Line number with issues (0-based); meaningless when status is Ok.
    JsonParseStatus jsonStatus = JsonParseStatus::kOk;
    std::string diagnosticKey;

    // T-09: Offline reopening only guarantees committed batches; this explicitly states "not a complete session."
    bool representsCompleteFile() const noexcept { return status == SessionLoadStatus::kOk; }
};

// Read-only parsing. No branches write back or repair source files.
//
// Structural criterion (T-10 "Submitted data must be recoverable or explicitly diagnosable"): The trailer must be the last line.
// Any non-empty line after the trailer (a second trailer, an old trailer left in the middle due to an interrupted rewrite, or an
// appended batch) is marked Corrupt; otherwise, a structurally corrupted file would be read back as a "clean, complete session."
SessionLoadResult loadSession(std::string_view text);

// For export/reporting: consolidate collector availability, load integrity, missing accounts, and coverage status into a single envelope.
//
// Degradation order (first-come, first-served, and always moving toward 'more uncertain'):
//   New                                   -> NotCollected
//   No collector capabilities declared -> Partial (without knowing what to collect, completeness is unknown).
//   A declared collector is not Success -> Partial; propagate that collector's
//                                            nativeCodeDomain / nativeCode / message into outcome.
//   Session recovered from an incomplete file / unrecoverable events -> Partial.
//   Local accounting failed / unknown accounting entries -> Partial.
//   Loss, limits reached, or collection filters applied -> Partial.
//   Otherwise -> Success.
EvidenceEnvelope buildSessionEnvelope(const TimelineSession& session);

} // namespace ksword::evidence

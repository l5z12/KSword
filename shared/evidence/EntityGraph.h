#pragma once

// G module: Entity relationships and cross-page investigation.
//
// This layer contains only the relationship model and unwind strategy, with no UI, layout, or rendering concepts. Its responsibility is:
//   * G-01: Every edge carries type, direction, time validity interval, evidence reference, and determinism. The six semantic categories
//     remain distinct and never collapse into a single "related" edge; relationships lacking evidence must not be displayed as certain.
//   * G-02 node identity derives from the instance identity of ObjectIdentity. Objects created in different boot cycles, at different
//     PID creation times, or with address reuse are distinct nodes; historical edges do not automatically apply to current objects.
//   * G-03: The three minimal viable investigation chains explicitly mark missing data as "missing" rather than skipping those steps.
//   * G-04 initially provides only the target plus one hop; default is 200 nodes and 500 edges. More must be explicitly requested by the caller.
//     Distinguish the count loaded this time from the total count; report unknown when the total is unavailable.
//   * G-05: Missing owner, unloaded, source not collected, and actual inconsistency are four independent
//     cases. There is no rule of "no edge implies malicious," nor any malicious/risk scoring field.
//   * G-06: The graph, list, details, and export references share the same set of entity IDs and evidence IDs. Offline expansion
//     uses only saved data; encountering an unsaved neighbor results in 'unsaved' status rather than initiating a query.
//   * G-08: The graph represents the evidence view, not analytical truth. Inferences can be expanded to rules and sources. The model contains
//     no fields like layout/size/color that carry undefined risk semantics, and conclusions remain consistent regardless of input order.
//
// Three hard rules that span the entire module:
//   * Absence is absence. Not collected, unsupported, rejected, timeout, and correct empty set are five
//     distinct states; always preserve the original error code, never collapse into 'missing this link'.
//   * Default is not complete. A default-constructed GraphEdge is of Unknown type, Unknown
//     certainty, and Unknown direction, and is directly rejected by addEdge; a default-constructed
//     EntityGraph has an envelope of NotCollected, and summarizeGraph can only return NoEvidence.
//   * The criteria do not exceed privileges. This layer does not recognize rootkits, does not assign scores, and
//     does not produce "malicious/suspicious" labels; it only provides facts traceable back to the source record.

#include "EvidenceEnvelope.h"
#include "EvidenceJson.h"
#include "LiveNavigation.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"
#include "ScanBudget.h"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// G-01: Edge semantics
// ---------------------------------------------------------------------------

// EdgeKind is a **relationship type**, not a "correlation degree". Each kind has independent semantics and independent evidence requirements.
// Deliberately omitting catch-all values like Related or Associated here: uncertain
// relationships must fall into CandidateOwner (ownership in doubt) or TemporalNeighbor
// (temporal proximity only). Neither expresses causality, and neither can be elevated to Owns.
enum class EdgeKind {
    kUnknown,           // Unspecified — addEdge rejects it; not allowed into the graph.
    kOwns,              // Lifecycle ownership: Process→Thread / Process→Handle / Process→Connection.
    kLoads,             // Load image: Process or kernel → Loaded module.
    kMaps,              // Address space mapping: Process -> Mapped file or region
    kOpens,             // Handle → the target object it opens.
    kCandidateOwner,    // Ownership is at the candidate evidence level only; semantically it can never be Confirmed.
    kTemporalNeighbor,  // Temporal neighbor. No direction, does not express causality (explicitly prohibited in the 'not included' specification).
    kDeviceOf,          // DeviceObject → its owning DriverObject
    kImageOf,           // DriverObject -> Image file on disk
    kServiceOf,         // Disk image → verifiable service configuration
    kTimelineEntry,     // System object → one evidence record on the timeline.
};

const char* edgeKindName(EdgeKind kind) noexcept;

// CandidateOwner is defined as 'insufficient evidence to confirm ownership', so its certainty upper bound is Candidate.
bool edgeKindAllowsConfirmed(EdgeKind kind) noexcept;

// TemporalNeighbor is symmetric: A occurring near B is equivalent to B occurring near
// A. Assigning it a direction incorrectly treats temporal proximity as causality.
bool edgeKindIsSymmetric(EdgeKind kind) noexcept;

enum class EdgeDirection {
    kUnknown,    // Direction unknown — addEdge rejects it; it must not be used as FromTo.
    kFromTo,     // Note: 'from' is the subject, 'to' is the object.
    kSymmetric,  // Undirected
};

const char* edgeDirectionName(EdgeDirection direction) noexcept;

// G-01: Relationships lacking evidence must not be displayed as certain. Unknown is the default value, meaning "not even a candidate".
enum class EdgeCertainty {
    kUnknown,
    kCandidate,
    kConfirmed,
};

const char* edgeCertaintyName(EdgeCertainty certainty) noexcept;

struct GraphEdge final {
    std::string edgeId;          // If left empty, deriveEdgeId deterministically generates it.
    EdgeKind kind = EdgeKind::kUnknown;
    EdgeDirection direction = EdgeDirection::kUnknown;
    std::string fromNodeId;
    std::string toNodeId;

    // Valid time interval (UTC 100ns). If both ends are unset, it means 'validity unknown', not 'always valid'.
    OptionalU64 validFrom100ns;
    OptionalU64 validTo100ns;

    // G-01 / G-08: Evidence references and inference rules. Certainty must not be Confirmed when evidenceRefs is empty.
    std::vector<std::string> evidenceRefs;
    EdgeCertainty certainty = EdgeCertainty::kUnknown;
    std::string ruleId;              // Rule ID that generated this edge; expandable in the UI.
    std::string ruleDescriptionKey;  // i18n key for rule description
    std::string sourceGroup;         // The independent source group this edge originates from.
};

// Deterministically generated edge IDs: type + endpoints + validity interval + rule. The same relationship across different time intervals constitutes
// two distinct edges, so the interval participates in the ID; this ensures the same set of IDs is obtained regardless of import order (G-08).
std::string deriveEdgeId(const GraphEdge& edge);

// Edge temporal validity. Unknown is neither 'invalid' nor 'valid'.
enum class TemporalValidity {
    kUnknown,
    kValid,
    kNotValid,
    // The interval itself is invalid (validFrom > validTo). This is neither "invalid at this moment" nor "unknown moment":
    // Merging it into NotValid makes a bad-interval edge permanently invisible under
    // any time-filter, with no way to say "invisible because the interval is reversed."
    // ScanBudget's AddressRange::reversed is the same thing in another place.
    kIntervalInvalid,
};

const char* temporalValidityName(TemporalValidity validity) noexcept;

TemporalValidity edgeValidAt(const GraphEdge& edge, const OptionalU64& utc100ns) noexcept;

// G-01: filter by kind/certainty. An empty vector means no filtering on that dimension.
struct EdgeFilter final {
    std::vector<EdgeKind> kinds;
    std::vector<EdgeCertainty> certainties;

    // Time filtering: if atUtc100ns is not set, do not filter by time.
    OptionalU64 atUtc100ns;
    // Edges with unknown validity are retained by default — "unknown" is not equivalent to "invalid" (same principle as G-05).
    // Exclude only when explicitly requested by the caller, and this must be stated in the exported constraints.
    bool excludeUnknownValidity = false;
};

bool edgeMatchesFilter(const GraphEdge& edge, const EdgeFilter& filter) noexcept;

// ---------------------------------------------------------------------------
// G-02: Node identity
// ---------------------------------------------------------------------------

// ObjectKind describes system objects. Timeline entries and evidence records are not system objects; forcing them into ObjectKind
// would cause 'processes' and 'log entries' to share the same matching rules. Therefore, an orthogonal category dimension is added.
enum class NodeCategory {
    kSystemObject,
    kTimelineEntry,
    kEvidenceRecord,
};

const char* nodeCategoryName(NodeCategory category) noexcept;

// Node lifecycle. Unknown is the default value — 'not knowing if it still exists' is not the same as 'it still exists'.
enum class NodeLifecycle {
    kUnknown,
    kObserved,  // Note: It was indeed observed at the collection moment.
    kEnded,     // Exited / unloaded / connection closed.
};

const char* nodeLifecycleName(NodeLifecycle lifecycle) noexcept;

// NodeIdentity directly holds the six instance identities from ObjectIdentity.h, selecting one based on kind.
// Devices and Services lack a lifecycle identity structure in F-03, so they must use (bootId, name); consequently,
// their strength is always Weak—this must be explicitly stated and cannot be treated as reliable like processes.
struct NodeIdentity final {
    NodeCategory category = NodeCategory::kSystemObject;
    ObjectKind kind = ObjectKind::kUnknown;

    ProcessInstanceId process;
    ThreadInstanceId thread;
    DriverInstanceId driver;  // Shared by Driver and Module
    FileIdentity file;
    HandleIdentity handle;
    ConnectionIdentity connection;

    std::string bootId;      // Device / Service / Non-system object.
    std::string name;        // Device / Service name, or record ID.
    // instanceTag: Instance discriminator tag provided by the caller (e.g., "Nth observation" or collection session ID).
    // G-02: Addresses are reused, and names are recycled. When identity is **not strong enough**, two observations of the same name and
    // address must be distinguished by this tag; otherwise, two distinct objects would be merged into a single node. When identity is strong
    // enough (crossSessionKey is accessible), it is excluded from the primary key to prevent splitting a single object into two nodes.
    std::string instanceTag;

    IdentityStrength strength() const noexcept;

    // Cross-session primary key. Returns an empty string if identity is insufficient (following the F-03 convention).
    std::string crossSessionKey() const;

    // Unique key within the graph. Strong identity uses crossSessionKey; weak identity encodes all available
    // fields plus instanceTag — better to split one object into two nodes than to merge two objects into one.
    std::string nodeKey() const;

    // Used for navigation and evidence references. Jumping is disallowed when navigable() is false (F-12 identity threshold).
    ObjectRef makeRef(const std::string& evidenceId, const std::string& displayText) const;
};

// Dispatch to the corresponding Match* based on kind. If kind or category differs, return
// NoMatch. Device/Service lack lifecycle identity, so the strongest match possible is Candidate.
//
// For the Device / Service / Record branch, there is an additional threshold: if either side has `strength() == Unusable`, or
// if the three fields `(bootId, name, instanceTag)` are all empty on either side, the result is NoMatch. MatchResult has no
// "insufficient information" state; a Candidate is treated by the caller as a "weak match" for identity gating. Interpreting
// "nothing filled in" as "could be the same" is exactly what G-02 aims to prevent: merging two distinct objects into one.
MatchResult matchNodeIdentity(const NodeIdentity& a, const NodeIdentity& b) noexcept;

struct GraphNode final {
    // If left empty, it is generated by NodeIdentity::nodeKey(). If the caller provides one, use the caller's
    // (session replay must be able to restore the saved ID exactly as-is; G-06 requires cross-view ID consistency).
    std::string nodeId;
    NodeIdentity identity;
    std::string displayText;
    std::string evidenceId;      // Envelope that generated this node; null = original evidence inaccessible
    NodeLifecycle lifecycle = NodeLifecycle::kUnknown;

    // G-05: The relationship type that "should" connect this node to its owner. Filling this distinguishes between "source not collected"
    // and "collected but no owner exists"; if not filled, it is treated as "source not collected" (defaulting to a non-benign conclusion).
    EdgeKind ownerRelation = EdgeKind::kUnknown;
    ObjectKind ownerKind = ObjectKind::kUnknown;

    // G-05 Class 4: Actual inconsistencies observed by other modules (e.g., X's cross-view).
    // Only transport facts and evidence IDs; do not perform any risk assessment.
    bool inconsistencyObserved = false;
    std::vector<std::string> inconsistencyEvidenceIds;

    // The collection result for this node itself. Retains the original error code on failure.
    CollectionOutcome outcome;

    bool objectNavigable() const noexcept;   // Whether the identity is sufficient to navigate object pages.
    bool evidenceOpenable() const noexcept;  // Whether the original evidence can be opened.
};

enum class NodeAdmission {
    kAcceptedNew,
    kAcceptedMerged,                   // Same nodeId appears again; evidence is merged.
    kAcceptedMergedLifecycleConflict,  // During merge, lifecycle conflict on both sides; downgrade to Unknown.
    kRejectedNoIdentity,               // Unable to even construct a unique key within the graph.
    // G-02: Two conflicting identities appear on the same `nodeId` (`matchNodeIdentity` returns `NoMatch` and the `nodeKey` on both
    // sides differs). Merging would collapse the two objects into one, while silently discarding would prevent the second
    // observation from being recorded—both are forbidden. Therefore, this is rejected, and the caller is made aware of the conflict.
    kRejectedIdentityConflict,
};

const char* nodeAdmissionName(NodeAdmission admission) noexcept;
bool nodeAdmissionAccepted(NodeAdmission admission) noexcept;

enum class EdgeAdmission {
    kAccepted,
    kDemotedMissingEvidence,        // G-01: evidenceRefs is empty; Confirmed downgraded to Candidate.
    kDemotedCandidateOwnerKind,     // candidate-owner cannot be determined under these semantics.
    kDemotedTemporalDirectionDropped,  // Temporal proximity was given a direction, but the direction was dropped.
    kRejectedUnknownKind,
    kRejectedUnknownDirection,
    kRejectedMissingEndpoint,
    kRejectedDuplicateId,
    kRejectedInvalidInterval,       // validFrom > validTo: The interval is inherently invalid.
};

const char* edgeAdmissionName(EdgeAdmission admission) noexcept;
bool edgeAdmissionAccepted(EdgeAdmission admission) noexcept;

// Normalization of an edge before it enters the graph. Return value indicates what was changed; out is the edge that will actually be stored.
// Exposed separately to allow callers to verify criteria without building the graph (G-08 inference can be expanded).
EdgeAdmission normalizeEdge(const GraphEdge& input, GraphEdge& out);

// ---------------------------------------------------------------------------
// G-03 / G-05: Relationship coverage declaration.
// ---------------------------------------------------------------------------

// "No data on this hop" and "not collected on this hop" must be distinct. The graph does not know which collections the caller
// has run; the caller must explicitly declare them. No declaration = NotCollected (the default is never "collected but empty").
struct RelationCoverage final {
    CollectionOutcome outcome;   // Default: NotCollected
    CoverageAccount coverage;    // F-06 Account; an empty account does not represent full coverage.
    std::string evidenceId;
};

// A declared coverage entry. This declaration must be transportable verbatim for export and session replay (G-06).
struct RelationCoverageEntry final {
    EdgeKind kind = EdgeKind::kUnknown;
    ObjectKind targetKind = ObjectKind::kUnknown;
    RelationCoverage coverage;
};

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

// G-06: Offline expansion policy. In offline sessions, allowLiveQueries is always false;
// encountering unsaved neighbors requires only bookkeeping, never silently initiating live queries.
struct OfflineExpansionPolicy final {
    bool allowLiveQueries = false;
    DataOrigin origin = DataOrigin::kSession;
};

// Unsaved neighbor: an edge points to a node not currently in the dataset. This indicates 'not saved', not 'non-existent'.
struct UnsavedNeighbor final {
    std::string edgeId;
    std::string missingNodeId;
    EdgeKind relation = EdgeKind::kUnknown;
};

class EntityGraph final {
public:
    EntityGraph() = default;

    NodeAdmission addNode(GraphNode node);
    EdgeAdmission addEdge(const GraphEdge& edge);

    const GraphNode* findNode(const std::string& nodeId) const noexcept;
    const GraphEdge* findEdge(const std::string& edgeId) const noexcept;

    // Internal index. All expansions and link traversals go through it to avoid any O(n^2) scans (G-04).
    bool nodeIndexOf(const std::string& nodeId, std::size_t& out) const noexcept;
    const std::vector<GraphNode>& nodes() const noexcept { return nodes_; }
    const std::vector<GraphEdge>& edges() const noexcept { return edges_; }
    std::size_t nodeCount() const noexcept { return nodes_.size(); }
    std::size_t edgeCount() const noexcept { return edges_.size(); }

    // Indices of edges connected to a node, sorted in ascending order by edgeId. The order is independent of insertion order (G-08).
    const std::vector<std::size_t>& incidentEdges(std::size_t nodeIndex) const;

    // G-05: EdgeKind::Unknown is not a relationship but represents "not filled." Allowing it into the coverage table would
    // issue a "this hop is fully verified" proof to every node lacking an ownerRelation annotation; therefore, reject it
    // and return false. ObjectKind::Unknown is a valid target category (timeline records do not have an ObjectKind).
    bool declareRelationCoverage(EdgeKind kind, ObjectKind targetKind, RelationCoverage coverage);
    // Returns the default value NotCollected if not declared.
    RelationCoverage relationCoverage(EdgeKind kind, ObjectKind targetKind) const;
    // All declared coverages, sorted ascending by (kind, targetKind). For export and replay.
    std::vector<RelationCoverageEntry> declaredRelationCoverages() const;

    // Observations blocked by RejectedIdentityConflict during graph construction. Deliberately excluded from GraphConclusion
    // and exports: it records the **input stream** (which observation arrived first), not the data itself. Since "who was
    // rejected" varies with arrival order, including it in conclusions would violate G-08's order independence.
    std::uint64_t identityConflictCount() const noexcept { return identityConflicts_; }

    void setEnvelope(EvidenceEnvelope envelope) { envelope_ = std::move(envelope); }
    const EvidenceEnvelope& envelope() const noexcept { return envelope_; }

    void setOfflinePolicy(OfflineExpansionPolicy policy) noexcept { policy_ = policy; }
    const OfflineExpansionPolicy& offlinePolicy() const noexcept { return policy_; }

private:
    void attachEdgeToNode(const std::string& nodeId, std::size_t edgeIndex);

    std::vector<GraphNode> nodes_;
    std::vector<GraphEdge> edges_;
    std::unordered_map<std::string, std::size_t> nodeIndex_;
    std::unordered_map<std::string, std::size_t> edgeIndex_;
    // Edges pointing to nodes not yet in the graph (unsaved neighbors). Nodes are automatically added to the adjacency list once the graph is complete.
    std::unordered_map<std::string, std::vector<std::size_t>> pending_;
    // Sort adjacency lists lazily on the first query and reuse the result. Graph construction
    // is O(E) and traversal is O(V+E), avoiding O(n^2) linear searches by nodeId (G-04).
    // The two mutable members serve only this lazy sort; this class does not guarantee thread safety.
    mutable std::vector<std::vector<std::size_t>> adjacency_;
    mutable std::vector<char> adjacencySorted_;
    std::map<std::pair<EdgeKind, ObjectKind>, RelationCoverage> coverage_;
    EvidenceEnvelope envelope_;
    OfflineExpansionPolicy policy_;
    std::uint64_t identityConflicts_ = 0;
};

// ---------------------------------------------------------------------------
// G-04: Bounded unwind
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t kDefaultMaxNodes = 200;
inline constexpr std::uint64_t kDefaultMaxEdges = 500;
inline constexpr std::uint64_t kDefaultMaxHops = 1;

struct ExpansionLimits final {
    std::uint64_t maxNodes = kDefaultMaxNodes;
    std::uint64_t maxEdges = kDefaultMaxEdges;
    std::uint64_t maxHops = kDefaultMaxHops;
};

struct ExpansionRequest final {
    std::vector<std::string> rootNodeIds;
    ExpansionLimits limits;
    EdgeFilter filter;
    // G-04: Anything beyond the default limit must be explicitly requested by the caller. Without this
    // flag, limits/hops exceeding the default are clamped to the default value and noted in the result.
    bool continueRequestedByUser = false;
};

struct ExpansionResult final {
    std::vector<std::string> nodeIds;  // Sorted by nodeId in ascending order; independent of input order.
    std::vector<std::string> edgeIds;  // In ascending order by edgeId

    // G-04: The count must not imply that everything is loaded. loaded* represents what was actually loaded this time; totalKnown is only valid when...
    // The value is set only when **traversal truly reaches the end**, which requires simultaneously satisfying: no upper limit hit, no
    // unsaved neighbors, and the loaded count equals all nodes and edges saved in the graph. Missing the last condition results in 'claiming
    // the total is known after traversing only one connected component'—another way of using loadedNodes to impersonate the total.
    std::uint64_t loadedNodes = 0;
    std::uint64_t loadedEdges = 0;
    bool moreAvailable = false;
    OptionalU64 totalKnownNodes;
    OptionalU64 totalKnownEdges;

    bool nodeLimitHit = false;
    bool edgeLimitHit = false;
    bool hopLimitHit = false;
    bool limitsClampedToDefault = false;  // Exceeded the default upper limit but did not explicitly request to continue.
    bool hopsClampedToDefault = false;

    // Number of edges excluded by filter conditions. This is a user choice, not a coverage gap, so it is not included in coverage.
    std::uint64_t filteredEdgeCount = 0;

    // G-06: Unsaved neighbors. Under the offline policy, this must be "accounting" rather than "querying".
    std::vector<UnsavedNeighbor> unsavedNeighbors;
    // Number of times a live query was initiated during this expansion. Since expandGraph has no live query exit
    // points, it will always remain at the default 0. Do not write 0 again at the end of the function; otherwise,
    // this field will be constantly 0, making any assertions based on it trivially true and effectively unverified.
    std::uint64_t liveQueriesIssued = 0;

    CoverageAccount coverage;
    std::vector<std::string> limitationKeys;  // Sorted and deduplicated i18n keys.
};

ExpansionResult expandGraph(const EntityGraph& graph, const ExpansionRequest& request);

// ---------------------------------------------------------------------------
// G-02: Locate historical edge to live.
// ---------------------------------------------------------------------------

enum class EndpointRole {
    kFrom,
    kTo,
};

const char* endpointRoleName(EndpointRole role) noexcept;

struct HistoricalEdgeLiveRequest final {
    std::string edgeId;
    EndpointRole endpoint = EndpointRole::kTo;
    LiveResolution live;               // Candidates found by the caller during live resolution (possibly with found=false).
    NavigationPage page = NavigationPage::kUnknown;
    bool targetPageAvailable = false;
    bool objectPresentInPage = false;
    bool evidencePresentInSession = false;
};

struct HistoricalEdgeLiveResult final {
    bool edgeFound = false;
    bool nodeFound = false;
    bool liveResolverSupported = false;  // Currently, only processes have live resolution contracts.
    ObjectKind kind = ObjectKind::kUnknown;
    std::string savedNodeId;
    // Non-null only if identity is Allowed. When identity mismatches, **never** fill in the new object's ID (Core G-02).
    std::string liveNodeId;
    LiveNavigationDecision identityDecision = LiveNavigationDecision::kRejectIdentityUnverifiable;
    bool navigationAttempted = false;
    NavigationOutcome navigation = NavigationOutcome::kIdentityUnusable;
    std::string reasonKey;
};

// Historical edges must not automatically resolve to current objects: first perform identity validation via resolveProcessNavigation;
// only proceed to decideNavigation if allowed. Otherwise, do not initiate navigation and do not provide a context ID.
HistoricalEdgeLiveResult resolveHistoricalEdgeToLive(const EntityGraph& graph,
                                                     const HistoricalEdgeLiveRequest& request);

// ---------------------------------------------------------------------------
// G-03: Minimum viable investigation chain
// ---------------------------------------------------------------------------

enum class ChainKind {
    kProcessSubjects,       // Process → Thread / Module / Handle
    kDeviceToService,       // Device → DriverObject → Driver image → Service
    kConnectionToTimeline,  // Connection → Process instance → Timeline
};

const char* chainKindName(ChainKind kind) noexcept;

// Availability of each link. The five "missing" states are not equivalent; preserve the original collection results for each.
enum class StepAvailability {
    kPresent,                   // This link has an object.
    kMissingNoData,             // Source successful and account positive proof covers the full scope; this link genuinely does not exist.
    kMissingCoverageIncomplete, // Coverage is partial; absence cannot be confirmed.
    kMissingNotCollected,       // Not collected
    kMissingUnsupported,
    kMissingAccessDenied,
    kMissingCollectionFailed,   // Timeout or other error; the original code is in outcome.
    kMissingIdentityUnusable,   // A record exists, but its identity cannot establish a definite hop.
    // The preceding link is missing, leaving no starting point for this lookup. This differs
    // from an uncollected source: collection may be complete but lack a starting point.
    // Collapsing this into MissingNotCollected would misrepresent the collection ledger.
    kMissingPreviousStepMissing,
};

const char* stepAvailabilityName(StepAvailability availability) noexcept;
bool stepIsMissing(StepAvailability availability) noexcept;

struct ChainStep final {
    std::size_t index = 0;
    std::string labelKey;                       // i18n key; UI handles translation
    NodeCategory expectedCategory = NodeCategory::kSystemObject;
    ObjectKind expectedKind = ObjectKind::kUnknown;
    EdgeKind relationFromPrevious = EdgeKind::kUnknown;
    StepAvailability availability = StepAvailability::kMissingNotCollected;
    CollectionOutcome outcome;                  // Preserve original error code
    std::string evidenceId;

    std::vector<std::string> nodeIds;           // Sorted by nodeId in ascending order.
    std::vector<std::string> edgeIds;           // In ascending order by edgeId
    EdgeCertainty weakestEdgeCertainty = EdgeCertainty::kUnknown;
    bool truncated = false;                     // Hit maxNodesPerStep.
    std::uint64_t matchCount = 0;

    // There are two distinct answers to 'can this step jump to the object page', so they must be provided separately: 'any' means 'at least one
    // can', while 'every' means 'every listed one can'. The UI uses 'any' to decide whether to show the button, and 'every' to determine if the
    // entire step is navigable. If the previous step is missing, both are false—a jump from a non-existent starting point is not permitted.
    bool anyObjectNavigable = false;
    bool everyObjectNavigable = false;
    // G-03 condition: 'source details openable at every step', so this bit has 'every' semantics: if any node in this ring
    // cannot open the original evidence, the result is false. Using 'any' would incorrectly mark a 3-of-1 ring as satisfied.
    bool evidenceOpenable = false;
};

struct ChainOptions final {
    std::uint64_t maxNodesPerStep = 50;
    EdgeFilter filter;
};

struct InvestigationChain final {
    ChainKind kind = ChainKind::kProcessSubjects;
    std::string rootNodeId;
    bool rootFound = false;
    std::vector<ChainStep> steps;

    std::size_t missingStepCount() const noexcept;
    // The chain is considered complete only if all steps are Present. A default-constructed chain is never 'complete'.
    bool complete() const noexcept;
    // Every step can open source details (G-03 pass condition: "Cannot just draw nodes without navigation.").
    bool everyPresentStepOpensSource() const noexcept;
};

InvestigationChain buildChain(const EntityGraph& graph,
                              ChainKind kind,
                              const std::string& rootNodeId,
                              const ChainOptions& options);

// ---------------------------------------------------------------------------
// G-05: Isolated and unknown do not equal anomalies.
// ---------------------------------------------------------------------------

// The four cases are separated. The default value is deliberately SourceNotCollected rather than
// NotIsolated—a report with nothing filled in must not be interpreted as 'this node relationship is normal'.
//
// Naming deliberately avoids 'cause': this describes the **observed data state** (presence/absence of edges,
// whether sources were collected, whether objects exist), not a causal or property judgment on any behavior.
// None of the four values express risk, and no rule infers 'anomaly' from 'isolated' (G-05 via condition).
enum class IsolationState {
    kNotIsolated,
    kOwnerMissing,           // Source fully collected and object exists, but the owner edge is missing.
    kObjectUnloaded,         // Object unloaded / no longer active; no current relationships is normal.
    kSourceNotCollected,     // Source of relationship not collected / unsupported / rejected / failed / incomplete
    kObservedInconsistency,  // Actual inconsistencies observed by other modules.
};

const char* isolationStateName(IsolationState state) noexcept;

struct IsolationReport final {
    std::string nodeId;
    bool nodeFound = false;
    bool isolated = false;
    IsolationState state = IsolationState::kSourceNotCollected;
    std::uint64_t edgeCountAfterFilter = 0;
    std::uint64_t edgeCountBeforeFilter = 0;

    CollectionOutcome ownerLookupOutcome;   // ownerLookupOutcome: Original collection result from the owner.
    std::string evidenceId;
    // G-05: Isolated nodes can still view raw evidence. When this bit is true, the UI must offer 'Open Raw Evidence'.
    bool rawEvidenceAvailable = false;
    // If false, it indicates 'no raw evidence exists'; the UI must display this message instead of merely graying out a button.
    std::string rawEvidenceMissingKey;
    std::vector<std::string> inconsistencyEvidenceIds;
    std::string explanationKey;
};

IsolationReport classifyIsolation(const EntityGraph& graph,
                                  const std::string& nodeId,
                                  const EdgeFilter& filter);

// ---------------------------------------------------------------------------
// G-06 / G-08: Lists, details, exports, and conclusions.
// ---------------------------------------------------------------------------

// Sort key for list view. Sorting affects only the display order, not any conclusions (G-08).
enum class EntityListOrder {
    kByNodeId,
    kByDisplayText,
    kByKind,
    kByEdgeCountDescending,
};

const char* entityListOrderName(EntityListOrder order) noexcept;

struct EntityListRow final {
    std::string nodeId;       // Uses the same ID (G-06) as the graph, details, and export.
    NodeCategory category = NodeCategory::kSystemObject;
    ObjectKind kind = ObjectKind::kUnknown;
    std::string displayText;
    std::string evidenceId;
    IdentityStrength strength = IdentityStrength::kUnusable;
    NodeLifecycle lifecycle = NodeLifecycle::kUnknown;
    std::uint64_t edgeCount = 0;
    bool objectNavigable = false;
    bool evidenceOpenable = false;
};

// IDs in expansion.nodeIds that point to non-existent nodes in the graph are skipped (this occurs when the view and graph are out of sync).
// Write the count of skipped entries to outMissingNodeCount; never drop silently. If the row count does not match
// loadedNodes, the caller must be able to explain the discrepancy (G-04: counts must not imply all nodes were loaded).
std::vector<EntityListRow> buildEntityList(const EntityGraph& graph,
                                           const ExpansionResult& expansion,
                                           const EdgeFilter& filter,
                                           EntityListOrder order,
                                           std::uint64_t* outMissingNodeCount = nullptr);

// Inference note for an edge. G-08: "All expandable inference rules and sources."
struct EdgeInferenceNote final {
    std::string edgeId;
    EdgeKind kind = EdgeKind::kUnknown;
    EdgeCertainty certainty = EdgeCertainty::kUnknown;
    std::string ruleId;
    std::string ruleDescriptionKey;
    std::vector<std::string> evidenceRefs;  // Sorted.
    // Reason this is not Confirmed. Empty when already Confirmed.
    std::string notConfirmedReasonKey;
};

EdgeInferenceNote describeEdgeInference(const GraphEdge& edge);

struct NodeDetail final {
    std::string nodeId;
    bool nodeFound = false;
    NodeCategory category = NodeCategory::kSystemObject;
    ObjectKind kind = ObjectKind::kUnknown;
    std::string displayText;
    std::string evidenceId;
    IdentityStrength strength = IdentityStrength::kUnusable;
    NodeLifecycle lifecycle = NodeLifecycle::kUnknown;
    std::vector<std::string> incomingEdgeIds;  // Sorted
    std::vector<std::string> outgoingEdgeIds;
    std::vector<std::string> symmetricEdgeIds;
    std::vector<EdgeInferenceNote> inferences;
    IsolationReport isolation;
};

NodeDetail buildNodeDetail(const EntityGraph& graph,
                           const std::string& nodeId,
                           const EdgeFilter& filter);

// G-08: Layer conclusion. All fields are derived from evidence and accounts, with no risk/malicious dimensions.
// For the same data, changing the input order or sorting method must result in this structure being identical field-by-field.
struct GraphConclusion final {
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;

    std::uint64_t nodeCount = 0;
    std::uint64_t edgeCountAfterFilter = 0;
    std::uint64_t edgeCountBeforeFilter = 0;

    std::uint64_t confirmedEdgeCount = 0;
    std::uint64_t candidateEdgeCount = 0;
    std::uint64_t unknownCertaintyEdgeCount = 0;

    std::uint64_t isolatedNodeCount = 0;
    std::uint64_t ownerMissingCount = 0;
    std::uint64_t unloadedCount = 0;
    std::uint64_t sourceNotCollectedCount = 0;
    std::uint64_t inconsistencyCount = 0;

    std::uint64_t unusableIdentityNodeCount = 0;
    std::uint64_t nodesWithoutEvidenceCount = 0;

    CoverageAccount coverage;
    std::vector<std::string> limitationKeys;  // Sorted and deduplicated

    friend bool operator==(const GraphConclusion& a, const GraphConclusion& b);
    friend bool operator!=(const GraphConclusion& a, const GraphConclusion& b) { return !(a == b); }
};

GraphConclusion summarizeGraph(const EntityGraph& graph, const EdgeFilter& filter);

// Export: nodes are sorted by nodeId and edges by edgeId, so output is independent of insertion order (G-08).
// All 64-bit values use the text form of LosslessValue; no floating-point (F-08).
//
// G-06: The exporter must be able to reconstruct the same graph, so it carries more than just "what is visible on screen":
//   * Each node writes a complete ObjectIdentity payload (instance identity per kind) along with ownerRelation and
//     ownerKind. Without them, identity strength, cross-session primary keys, navigability, and isolation criteria
//     degrade in reopened sessions, making structural compliance with "identity and relationship consistency" impossible.
//   * Graph-level output of envelope, declared relationship coverage, and offline policies — without them, the
//     conclusion would drop from NoDifferenceObserved to NoEvidence, and the link would become missing instead of Present.
// Identity payloads write only the portion required for that kind: nodeKey, crossSessionKey, strength, and
// matchNodeIdentity are all dispatched by kind; bytes in other slots have no meaning within this module.
JsonValue exportGraph(const EntityGraph& graph,
                      const ExpansionResult& expansion,
                      const EdgeFilter& filter);

// Imported accounts. Parsing failures do not throw exceptions nor treat a 'partial graph' as success: every rejected record is counted.
struct GraphImport final {
    bool schemaRecognised = false;   // Import is only possible if the schema is recognized.
    EntityGraph graph;

    std::uint64_t nodesAccepted = 0;
    std::uint64_t nodesRejected = 0;
    std::uint64_t edgesAccepted = 0;
    std::uint64_t edgesRejected = 0;
    std::uint64_t coverageAccepted = 0;
    std::uint64_t coverageRejected = 0;

    std::vector<std::string> limitationKeys;  // Sorted and deduplicated
};

// Inverse of exportGraph. Import uses only what is written in the document; any missing fields retain their default values
// (default does not equal complete: missing envelope means NotCollected, missing coverage declaration means not collected).
GraphImport importGraph(const JsonValue& document);

// Exports the schema identifier used. Starting from v2, nodes carry full identity payloads, and the graph includes an envelope and override declarations.
inline constexpr const char* kEntityGraphSchema = "ksword.entityGraph.v2";

} // namespace ksword::evidence

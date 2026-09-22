#include "EntityGraph.h"

#include <algorithm>
#include <utility>

namespace ksword::evidence {
namespace {

// The primary key separator follows the convention in ObjectIdentity.cpp: these two bytes
// do not appear in paths, GUIDs, or numbers, ensuring 'a|b' and 'a' + '|b' do not collide.
constexpr char kFieldSep = '\x1F';
constexpr char kGroupSep = '\x1E';

void appendField(std::string& key, const std::string& value) {
    key.push_back(kFieldSep);
    key.append(value);
}

void appendField(std::string& key, const OptionalU64& value, U64Format format) {
    key.push_back(kFieldSep);
    if (value.present) {
        key.append(formatU64(value.value, format));
    }
}

void appendField(std::string& key, std::uint64_t value) {
    key.push_back(kFieldSep);
    key.append(formatU64(value, U64Format::kDecimal));
}

void sortUnique(std::vector<std::string>& values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
}

void mergeSortedUnique(std::vector<std::string>& target, const std::vector<std::string>& extra) {
    target.insert(target.end(), extra.begin(), extra.end());
    sortUnique(target);
}

// Weak identity field dump. Prefer splitting the same object into two nodes rather
// than merging two objects (G-02: address reuse and name reuse must be separated).
void appendProcessFields(std::string& key, const ProcessInstanceId& id) {
    appendField(key, id.bootId);
    appendField(key, id.pid, U64Format::kDecimal);
    appendField(key, id.createTime100ns, U64Format::kDecimal);
    appendField(key, id.eprocessAddress, U64Format::kHexAddress);
    appendField(key, id.imageName);
}

void appendWeakFields(std::string& key, const NodeIdentity& id) {
    switch (id.kind) {
    case ObjectKind::kProcess:
        appendProcessFields(key, id.process);
        break;
    case ObjectKind::kThread:
        appendProcessFields(key, id.thread.process);
        appendField(key, id.thread.tid, U64Format::kDecimal);
        appendField(key, id.thread.createTime100ns, U64Format::kDecimal);
        appendField(key, id.thread.ethreadAddress, U64Format::kHexAddress);
        break;
    case ObjectKind::kDriver:
    case ObjectKind::kModule:
        appendField(key, id.driver.bootId);
        appendField(key, id.driver.imagePath);
        appendField(key, id.driver.imageBase, U64Format::kHexAddress);
        appendField(key, id.driver.imageSize, U64Format::kDecimal);
        appendField(key, id.driver.timeDateStamp, U64Format::kDecimal);
        appendField(key, id.driver.checksum, U64Format::kDecimal);
        appendField(key, id.driver.pdbSignature);
        appendField(key, id.driver.loadOrderIndex, U64Format::kDecimal);
        break;
    case ObjectKind::kFile:
        appendField(key, id.file.path);
        appendField(key, id.file.volumeSerial, U64Format::kDecimal);
        appendField(key, id.file.fileId);
        appendField(key, id.file.sizeBytes, U64Format::kDecimal);
        appendField(key, id.file.lastWriteUtc100ns, U64Format::kDecimal);
        appendField(key, id.file.contentHash);
        break;
    case ObjectKind::kHandle:
        appendProcessFields(key, id.handle.owner);
        appendField(key, id.handle.handleValue, U64Format::kDecimal);
        appendField(key, id.handle.objectAddress, U64Format::kHexAddress);
        appendField(key, id.handle.typeName);
        break;
    case ObjectKind::kConnection:
        appendField(key, id.connection.bootId);
        appendField(key, static_cast<std::uint64_t>(id.connection.protocol));
        appendField(key, id.connection.localAddress);
        appendField(key, static_cast<std::uint64_t>(id.connection.localPort));
        appendField(key, id.connection.remoteAddress);
        appendField(key, static_cast<std::uint64_t>(id.connection.remotePort));
        appendField(key, id.connection.observedFirstUtc100ns, U64Format::kDecimal);
        appendField(key, id.connection.observedLastUtc100ns, U64Format::kDecimal);
        appendProcessFields(key, id.connection.owner);
        break;
    case ObjectKind::kDevice:
    case ObjectKind::kService:
    case ObjectKind::kUnknown:
        break;
    }
    // Append bootId, name, and instanceTag for each category: Devices, Services, and non-system objects only have these
    // three. Adding more fields for other categories only increases distinction and will not merge two objects together.
    appendField(key, id.bootId);
    appendField(key, id.name);
    appendField(key, id.instanceTag);
}

// Three-state comparison for weak fields like name/boot cycle follows the semantics in ObjectIdentity.cpp.
enum class WeakCompare { kEqual, kDiffer, kMissing };

WeakCompare compareText(const std::string& a, const std::string& b) noexcept {
    if (a.empty() || b.empty()) {
        return WeakCompare::kMissing;
    }
    return a == b ? WeakCompare::kEqual : WeakCompare::kDiffer;
}

const RelationCoverage& emptyCoverage() {
    static const RelationCoverage kEmpty;  // Default state is NotCollected.
    return kEmpty;
}

const std::vector<std::size_t>& emptyIndexList() {
    static const std::vector<std::size_t> kEmpty;
    return kEmpty;
}

// G-05 / G-03 Shared: Whether a single collection positively proves that 'this link indeed has no data'.
// Both conditions must hold: status is Success, and the coverage provides positive evidence of full coverage.
bool coverageProvesAbsence(const RelationCoverage& coverage) {
    return coverage.outcome.status == CollectionStatus::kSuccess && coverage.coverage.fullyCovered();
}

} // namespace

// ---------------------------------------------------------------------------
// Enum name
// ---------------------------------------------------------------------------
const char* edgeKindName(EdgeKind kind) noexcept {
    switch (kind) {
    case EdgeKind::kUnknown:          return "Unknown";
    case EdgeKind::kOwns:             return "owns";
    case EdgeKind::kLoads:            return "loads";
    case EdgeKind::kMaps:             return "maps";
    case EdgeKind::kOpens:            return "opens";
    case EdgeKind::kCandidateOwner:   return "candidate-owner";
    case EdgeKind::kTemporalNeighbor: return "temporal-neighbor";
    case EdgeKind::kDeviceOf:         return "device-of";
    case EdgeKind::kImageOf:          return "image-of";
    case EdgeKind::kServiceOf:        return "service-of";
    case EdgeKind::kTimelineEntry:    return "timeline-entry";
    }
    return "Unknown";
}

bool edgeKindAllowsConfirmed(EdgeKind kind) noexcept {
    // By definition, 'candidate-owner' means 'ownership supported only by candidate-level evidence'. If it could be Confirmed, this
    // category would be indistinguishable from 'owns'—another form of 'mixing different relationships into a single related edge'.
    return kind != EdgeKind::kCandidateOwner && kind != EdgeKind::kUnknown;
}

bool edgeKindIsSymmetric(EdgeKind kind) noexcept {
    return kind == EdgeKind::kTemporalNeighbor;
}

const char* edgeDirectionName(EdgeDirection direction) noexcept {
    switch (direction) {
    case EdgeDirection::kUnknown:   return "Unknown";
    case EdgeDirection::kFromTo:    return "FromTo";
    case EdgeDirection::kSymmetric: return "Symmetric";
    }
    return "Unknown";
}

const char* edgeCertaintyName(EdgeCertainty certainty) noexcept {
    switch (certainty) {
    case EdgeCertainty::kUnknown:   return "Unknown";
    case EdgeCertainty::kCandidate: return "Candidate";
    case EdgeCertainty::kConfirmed: return "Confirmed";
    }
    return "Unknown";
}

const char* temporalValidityName(TemporalValidity validity) noexcept {
    switch (validity) {
    case TemporalValidity::kUnknown:         return "Unknown";
    case TemporalValidity::kValid:           return "Valid";
    case TemporalValidity::kNotValid:        return "NotValid";
    case TemporalValidity::kIntervalInvalid: return "IntervalInvalid";
    }
    return "Unknown";
}

const char* nodeCategoryName(NodeCategory category) noexcept {
    switch (category) {
    case NodeCategory::kSystemObject:  return "SystemObject";
    case NodeCategory::kTimelineEntry: return "TimelineEntry";
    case NodeCategory::kEvidenceRecord:return "EvidenceRecord";
    }
    return "SystemObject";
}

const char* nodeLifecycleName(NodeLifecycle lifecycle) noexcept {
    switch (lifecycle) {
    case NodeLifecycle::kUnknown:  return "Unknown";
    case NodeLifecycle::kObserved: return "Observed";
    case NodeLifecycle::kEnded:    return "Ended";
    }
    return "Unknown";
}

const char* nodeAdmissionName(NodeAdmission admission) noexcept {
    switch (admission) {
    case NodeAdmission::kAcceptedNew:                     return "AcceptedNew";
    case NodeAdmission::kAcceptedMerged:                  return "AcceptedMerged";
    case NodeAdmission::kAcceptedMergedLifecycleConflict: return "AcceptedMergedLifecycleConflict";
    case NodeAdmission::kRejectedNoIdentity:              return "RejectedNoIdentity";
    case NodeAdmission::kRejectedIdentityConflict:        return "RejectedIdentityConflict";
    }
    return "RejectedNoIdentity";
}

bool nodeAdmissionAccepted(NodeAdmission admission) noexcept {
    switch (admission) {
    case NodeAdmission::kAcceptedNew:
    case NodeAdmission::kAcceptedMerged:
    case NodeAdmission::kAcceptedMergedLifecycleConflict:
        return true;
    case NodeAdmission::kRejectedNoIdentity:
    case NodeAdmission::kRejectedIdentityConflict:
        return false;
    }
    return false;
}

const char* edgeAdmissionName(EdgeAdmission admission) noexcept {
    switch (admission) {
    case EdgeAdmission::kAccepted:                        return "Accepted";
    case EdgeAdmission::kDemotedMissingEvidence:          return "DemotedMissingEvidence";
    case EdgeAdmission::kDemotedCandidateOwnerKind:       return "DemotedCandidateOwnerKind";
    case EdgeAdmission::kDemotedTemporalDirectionDropped: return "DemotedTemporalDirectionDropped";
    case EdgeAdmission::kRejectedUnknownKind:             return "RejectedUnknownKind";
    case EdgeAdmission::kRejectedUnknownDirection:        return "RejectedUnknownDirection";
    case EdgeAdmission::kRejectedMissingEndpoint:         return "RejectedMissingEndpoint";
    case EdgeAdmission::kRejectedDuplicateId:             return "RejectedDuplicateId";
    case EdgeAdmission::kRejectedInvalidInterval:         return "RejectedInvalidInterval";
    }
    return "RejectedUnknownKind";
}

bool edgeAdmissionAccepted(EdgeAdmission admission) noexcept {
    switch (admission) {
    case EdgeAdmission::kAccepted:
    case EdgeAdmission::kDemotedMissingEvidence:
    case EdgeAdmission::kDemotedCandidateOwnerKind:
    case EdgeAdmission::kDemotedTemporalDirectionDropped:
        return true;
    case EdgeAdmission::kRejectedUnknownKind:
    case EdgeAdmission::kRejectedUnknownDirection:
    case EdgeAdmission::kRejectedMissingEndpoint:
    case EdgeAdmission::kRejectedDuplicateId:
    case EdgeAdmission::kRejectedInvalidInterval:
        return false;
    }
    return false;
}

const char* endpointRoleName(EndpointRole role) noexcept {
    switch (role) {
    case EndpointRole::kFrom: return "From";
    case EndpointRole::kTo:   return "To";
    }
    return "To";
}

const char* chainKindName(ChainKind kind) noexcept {
    switch (kind) {
    case ChainKind::kProcessSubjects:      return "ProcessSubjects";
    case ChainKind::kDeviceToService:      return "DeviceToService";
    case ChainKind::kConnectionToTimeline: return "ConnectionToTimeline";
    }
    return "ProcessSubjects";
}

const char* stepAvailabilityName(StepAvailability availability) noexcept {
    switch (availability) {
    case StepAvailability::kPresent:                    return "Present";
    case StepAvailability::kMissingNoData:              return "MissingNoData";
    case StepAvailability::kMissingCoverageIncomplete:  return "MissingCoverageIncomplete";
    case StepAvailability::kMissingNotCollected:        return "MissingNotCollected";
    case StepAvailability::kMissingUnsupported:         return "MissingUnsupported";
    case StepAvailability::kMissingAccessDenied:        return "MissingAccessDenied";
    case StepAvailability::kMissingCollectionFailed:    return "MissingCollectionFailed";
    case StepAvailability::kMissingIdentityUnusable:    return "MissingIdentityUnusable";
    case StepAvailability::kMissingPreviousStepMissing: return "MissingPreviousStepMissing";
    }
    return "MissingNotCollected";
}

bool stepIsMissing(StepAvailability availability) noexcept {
    return availability != StepAvailability::kPresent;
}

const char* isolationStateName(IsolationState state) noexcept {
    switch (state) {
    case IsolationState::kNotIsolated:           return "NotIsolated";
    case IsolationState::kOwnerMissing:          return "OwnerMissing";
    case IsolationState::kObjectUnloaded:        return "ObjectUnloaded";
    case IsolationState::kSourceNotCollected:    return "SourceNotCollected";
    case IsolationState::kObservedInconsistency: return "ObservedInconsistency";
    }
    return "SourceNotCollected";
}

const char* entityListOrderName(EntityListOrder order) noexcept {
    switch (order) {
    case EntityListOrder::kByNodeId:              return "ByNodeId";
    case EntityListOrder::kByDisplayText:         return "ByDisplayText";
    case EntityListOrder::kByKind:                return "ByKind";
    case EntityListOrder::kByEdgeCountDescending: return "ByEdgeCountDescending";
    }
    return "ByNodeId";
}

// ---------------------------------------------------------------------------
// G-02: Node identity
// ---------------------------------------------------------------------------
IdentityStrength NodeIdentity::strength() const noexcept {
    if (category != NodeCategory::kSystemObject) {
        // Timelines and evidence records are not system objects, so they have no lifecycle identity. A record ID constitutes a weak identity.
        return name.empty() ? IdentityStrength::kUnusable : IdentityStrength::kWeak;
    }
    switch (kind) {
    case ObjectKind::kProcess:    return process.strength();
    case ObjectKind::kThread:     return thread.strength();
    case ObjectKind::kDriver:
    case ObjectKind::kModule:     return driver.strength();
    case ObjectKind::kFile:       return file.strength();
    case ObjectKind::kHandle:     return handle.strength();
    case ObjectKind::kConnection: return connection.strength();
    case ObjectKind::kDevice:
    case ObjectKind::kService:
        // F-03 does not define a lifecycle identity for devices/services, so their strength is capped at Weak.
        // This case must be explicitly written out; do not let it appear as reliable as a process.
        return name.empty() ? IdentityStrength::kUnusable : IdentityStrength::kWeak;
    case ObjectKind::kUnknown:
        break;
    }
    return name.empty() ? IdentityStrength::kUnusable : IdentityStrength::kWeak;
}

std::string NodeIdentity::crossSessionKey() const {
    if (category != NodeCategory::kSystemObject) {
        return std::string();
    }
    switch (kind) {
    case ObjectKind::kProcess:    return process.crossSessionKey();
    case ObjectKind::kThread:     return thread.crossSessionKey();
    case ObjectKind::kDriver:
    case ObjectKind::kModule:     return driver.crossSessionKey();
    case ObjectKind::kFile:       return file.crossSessionKey();
    case ObjectKind::kHandle:     return handle.crossSessionKey();
    case ObjectKind::kConnection: return connection.crossSessionKey();
    case ObjectKind::kDevice:
    case ObjectKind::kService:
    case ObjectKind::kUnknown:
        break;
    }
    return std::string();
}

std::string NodeIdentity::nodeKey() const {
    std::string key(nodeCategoryName(category));
    key.push_back(kGroupSep);
    key.append(objectKindName(kind));
    key.push_back(kGroupSep);

    const std::string kStrong = crossSessionKey();
    if (!kStrong.empty()) {
        // Strong identity: instanceTag is excluded; otherwise, the same object would be split into two nodes.
        key.append("strong");
        key.push_back(kGroupSep);
        key.append(kStrong);
        return key;
    }
    if (strength() == IdentityStrength::kUnusable && instanceTag.empty()) {
        // Neither a valid identity nor a discriminator label is provided; such nodes cannot be distinguished from
        // any other observation, and adding them to the graph would falsely imply they represent the same object.
        return std::string();
    }
    key.append("weak");
    appendWeakFields(key, *this);
    return key;
}

ObjectRef NodeIdentity::makeRef(const std::string& evidenceIdIn,
                                const std::string& displayTextIn) const {
    ObjectRef ref;
    ref.kind = kind;
    ref.key = crossSessionKey();  // Insufficient identity results in an empty string, so navigable() is naturally false.
    ref.strength = strength();
    ref.displayText = displayTextIn;
    ref.evidenceId = evidenceIdIn;
    return ref;
}

MatchResult matchNodeIdentity(const NodeIdentity& a, const NodeIdentity& b) noexcept {
    if (a.category != b.category || a.kind != b.kind) {
        return MatchResult::kNoMatch;
    }
    if (a.category == NodeCategory::kSystemObject) {
        switch (a.kind) {
        case ObjectKind::kProcess:    return matchProcessInstance(a.process, b.process);
        case ObjectKind::kThread:     return matchThreadInstance(a.thread, b.thread);
        case ObjectKind::kDriver:
        case ObjectKind::kModule:     return matchDriverInstance(a.driver, b.driver);
        case ObjectKind::kFile:       return matchFileIdentity(a.file, b.file);
        case ObjectKind::kHandle:     return matchHandleIdentity(a.handle, b.handle);
        case ObjectKind::kConnection: return matchConnectionIdentity(a.connection, b.connection);
        case ObjectKind::kDevice:
        case ObjectKind::kService:
        case ObjectKind::kUnknown:
            break;
        }
    }
    // Device/Service/Record: only (bootId, name, instanceTag). A contradiction yields NoMatch; consistency yields at
    // most Candidate — without a lifecycle identifier, there is no qualification to confirm it is the same entity.
    //
    // Check the threshold first, then compare. When all fields are missing, the three compareText calls all return Missing,
    // eventually falling through to the Candidate state. Consequently, two identities with no data would be judged as
    // "possibly the same object." Since MatchResult has no "insufficient information" category, and callers (e.g., historical
    // edge localization) treat Candidate as identity evidence, "no information" must map to NoMatch, not the weak match side.
    if (a.strength() == IdentityStrength::kUnusable || b.strength() == IdentityStrength::kUnusable) {
        return MatchResult::kNoMatch;
    }
    const bool kABlank = a.bootId.empty() && a.name.empty() && a.instanceTag.empty();
    const bool kBBlank = b.bootId.empty() && b.name.empty() && b.instanceTag.empty();
    if (kABlank || kBBlank) {
        return MatchResult::kNoMatch;
    }
    if (compareText(a.bootId, b.bootId) == WeakCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    if (compareText(a.name, b.name) == WeakCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    if (compareText(a.instanceTag, b.instanceTag) == WeakCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    return MatchResult::kCandidate;
}

bool GraphNode::objectNavigable() const noexcept {
    return identity.makeRef(evidenceId, displayText).navigable();
}

bool GraphNode::evidenceOpenable() const noexcept {
    return !evidenceId.empty();
}

// ---------------------------------------------------------------------------
// G-01: Edge
// ---------------------------------------------------------------------------
std::string deriveEdgeId(const GraphEdge& edge) {
    std::string id(edgeKindName(edge.kind));
    appendField(id, edge.fromNodeId);
    appendField(id, edge.toNodeId);
    appendField(id, edge.validFrom100ns, U64Format::kDecimal);
    appendField(id, edge.validTo100ns, U64Format::kDecimal);
    appendField(id, edge.ruleId);
    return id;
}

TemporalValidity edgeValidAt(const GraphEdge& edge, const OptionalU64& utc100ns) noexcept {
    // State the interval inversion first: when both endpoints exist and from > to, the subsequent two if-statements will
    // hit NotValid for **any** timestamp. This edge becomes permanently invisible under any time-based filter, and no
    // value can explain 'invisibility due to a broken interval'. A broken interval is not the same as 'currently invalid'.
    if (edge.validFrom100ns.present && edge.validTo100ns.present &&
        edge.validFrom100ns.value > edge.validTo100ns.value) {
        return TemporalValidity::kIntervalInvalid;
    }
    if (!utc100ns.present) {
        return TemporalValidity::kUnknown;
    }
    if (!edge.validFrom100ns.present && !edge.validTo100ns.present) {
        // Validity is completely unknown. This is neither 'always valid' nor 'expired'.
        return TemporalValidity::kUnknown;
    }
    if (edge.validFrom100ns.present && utc100ns.value < edge.validFrom100ns.value) {
        return TemporalValidity::kNotValid;
    }
    if (edge.validTo100ns.present && utc100ns.value >= edge.validTo100ns.value) {
        return TemporalValidity::kNotValid;
    }
    // When only one end is provided, the other remains unknown: having a start time after
    // the start point but no end time means we cannot assert 'still valid at this moment'.
    if (!edge.validFrom100ns.present || !edge.validTo100ns.present) {
        return TemporalValidity::kUnknown;
    }
    return TemporalValidity::kValid;
}

bool edgeMatchesFilter(const GraphEdge& edge, const EdgeFilter& filter) noexcept {
    if (!filter.kinds.empty() &&
        std::find(filter.kinds.begin(), filter.kinds.end(), edge.kind) == filter.kinds.end()) {
        return false;
    }
    if (!filter.certainties.empty() &&
        std::find(filter.certainties.begin(), filter.certainties.end(), edge.certainty) ==
            filter.certainties.end()) {
        return false;
    }
    if (filter.atUtc100ns.present) {
        const TemporalValidity kValidity = edgeValidAt(edge, filter.atUtc100ns);
        switch (kValidity) {
        case TemporalValidity::kNotValid:
            return false;
        case TemporalValidity::kUnknown:
        case TemporalValidity::kIntervalInvalid:
            // Unknown does not equal invalid. If the interval is broken, we still cannot determine 'is it valid now?', so we follow the same path:
            // Preserved by default; only dropped if the caller explicitly requests excluding unknown validity.
            return !filter.excludeUnknownValidity;
        case TemporalValidity::kValid:
            break;
        }
    }
    return true;
}

EdgeAdmission normalizeEdge(const GraphEdge& input, GraphEdge& out) {
    out = input;
    if (out.kind == EdgeKind::kUnknown) {
        return EdgeAdmission::kRejectedUnknownKind;
    }
    if (out.fromNodeId.empty() || out.toNodeId.empty()) {
        return EdgeAdmission::kRejectedMissingEndpoint;
    }
    if (out.direction == EdgeDirection::kUnknown) {
        // Edges constructed with default values are rejected from the graph: an edge with 'unknown direction' would be misinterpreted as from→to.
        return EdgeAdmission::kRejectedUnknownDirection;
    }
    if (out.validFrom100ns.present && out.validTo100ns.present &&
        out.validFrom100ns.value > out.validTo100ns.value) {
        // G-01: Valid intervals are part of edge identity (deriveEdgeId encodes both endpoints). An edge from > to
        // can still get an independent ID into the graph but remains permanently invisible under any time-based
        // filter, with no explanation anywhere. If the interval is invalid, the edge is invalid; reject directly.
        // from == to is a valid empty interval ("the relationship lasted zero duration") and is excluded.
        return EdgeAdmission::kRejectedInvalidInterval;
    }

    // Deduplicate and sort evidence references: the same set of evidence should not produce 'another edge' (G-08) just by changing order.
    sortUnique(out.evidenceRefs);

    EdgeAdmission admission = EdgeAdmission::kAccepted;

    if (edgeKindIsSymmetric(out.kind)) {
        if (out.direction != EdgeDirection::kSymmetric) {
            // Per the 'exclusion' specification, explicitly forbids rendering temporally adjacent events as deterministic causality; the direction is dropped.
            out.direction = EdgeDirection::kSymmetric;
            admission = EdgeAdmission::kDemotedTemporalDirectionDropped;
        }
        if (out.toNodeId < out.fromNodeId) {
            std::swap(out.fromNodeId, out.toNodeId);
        }
    }

    if (out.certainty == EdgeCertainty::kConfirmed) {
        if (out.evidenceRefs.empty()) {
            // G-01 Condition: Missing-evidence edges must not appear as Confirmed. Highest priority: Reporting "this kind cannot
            // be Confirmed" when evidence is missing prevents callers from assuming switching the kind will yield Confirmed.
            out.certainty = EdgeCertainty::kCandidate;
            admission = EdgeAdmission::kDemotedMissingEvidence;
        } else if (!edgeKindAllowsConfirmed(out.kind)) {
            out.certainty = EdgeCertainty::kCandidate;
            admission = EdgeAdmission::kDemotedCandidateOwnerKind;
        }
    }

    if (out.edgeId.empty()) {
        out.edgeId = deriveEdgeId(out);
    }
    return admission;
}

// ---------------------------------------------------------------------------
// EntityGraph
// ---------------------------------------------------------------------------
void EntityGraph::attachEdgeToNode(const std::string& nodeId, std::size_t edgeIndex) {
    const auto kIt = nodeIndex_.find(nodeId);
    if (kIt == nodeIndex_.end()) {
        // G-06: Neighbor not yet added to the graph — mark as 'unsaved'; never initiate any query here.
        pending_[nodeId].push_back(edgeIndex);
        return;
    }
    adjacency_[kIt->second].push_back(edgeIndex);
    adjacencySorted_[kIt->second] = 0;
}

NodeAdmission EntityGraph::addNode(GraphNode node) {
    if (node.nodeId.empty()) {
        node.nodeId = node.identity.nodeKey();
    }
    if (node.nodeId.empty()) {
        return NodeAdmission::kRejectedNoIdentity;
    }

    const auto kExistingIt = nodeIndex_.find(node.nodeId);
    if (kExistingIt != nodeIndex_.end()) {
        GraphNode& existing = nodes_[kExistingIt->second];
        // G-02: Same nodeId does not imply the same object. During session replay, IDs come from saved data; two
        // records from different sources may carry the same ID but contradictory identities. Directly merging
        // would erase the second observation entirely (the opposite of 'split into two nodes rather than merge
        // one'). Therefore, first check identity: if nodeKey matches, the identity content is consistent and they
        // can be merged; otherwise, if the matcher returns NoMatch, reject and record it, never silently discard.
        if (existing.identity.nodeKey() != node.identity.nodeKey() &&
            matchNodeIdentity(existing.identity, node.identity) == MatchResult::kNoMatch) {
            ++identityConflicts_;
            return NodeAdmission::kRejectedIdentityConflict;
        }
        NodeAdmission admission = NodeAdmission::kAcceptedMerged;
        if (existing.lifecycle != node.lifecycle) {
            if (existing.lifecycle == NodeLifecycle::kUnknown) {
                existing.lifecycle = node.lifecycle;
            } else if (node.lifecycle != NodeLifecycle::kUnknown) {
                // The two observations contradict each other. Do not select the one that
                // 'looks better'; downgrade to Unknown and notify the caller of the conflict.
                existing.lifecycle = NodeLifecycle::kUnknown;
                admission = NodeAdmission::kAcceptedMergedLifecycleConflict;
            }
        }
        if (existing.displayText.empty()) {
            existing.displayText = node.displayText;
        }
        if (existing.evidenceId.empty()) {
            existing.evidenceId = node.evidenceId;
        }
        if (existing.ownerRelation == EdgeKind::kUnknown) {
            existing.ownerRelation = node.ownerRelation;
            existing.ownerKind = node.ownerKind;
        }
        existing.inconsistencyObserved = existing.inconsistencyObserved || node.inconsistencyObserved;
        mergeSortedUnique(existing.inconsistencyEvidenceIds, node.inconsistencyEvidenceIds);
        if (existing.outcome.status == CollectionStatus::kNotCollected) {
            existing.outcome = node.outcome;
        }
        return admission;
    }

    sortUnique(node.inconsistencyEvidenceIds);
    const std::string kNodeId = node.nodeId;
    const std::size_t kIndex = nodes_.size();
    nodes_.push_back(std::move(node));
    nodeIndex_.emplace(kNodeId, kIndex);
    adjacency_.emplace_back();
    adjacencySorted_.push_back(1);

    const auto kPendingIt = pending_.find(kNodeId);
    if (kPendingIt != pending_.end()) {
        adjacency_[kIndex] = std::move(kPendingIt->second);
        adjacencySorted_[kIndex] = 0;
        pending_.erase(kPendingIt);
    }
    return NodeAdmission::kAcceptedNew;
}

EdgeAdmission EntityGraph::addEdge(const GraphEdge& edge) {
    GraphEdge normalized;
    const EdgeAdmission kAdmission = normalizeEdge(edge, normalized);
    if (!edgeAdmissionAccepted(kAdmission)) {
        return kAdmission;
    }
    if (edgeIndex_.find(normalized.edgeId) != edgeIndex_.end()) {
        return EdgeAdmission::kRejectedDuplicateId;
    }
    const std::size_t kIndex = edges_.size();
    const std::string kFromId = normalized.fromNodeId;
    const std::string kToId = normalized.toNodeId;
    const std::string kEdgeId = normalized.edgeId;
    edges_.push_back(std::move(normalized));
    edgeIndex_.emplace(kEdgeId, kIndex);
    attachEdgeToNode(kFromId, kIndex);
    if (kToId != kFromId) {
        attachEdgeToNode(kToId, kIndex);
    }
    return kAdmission;
}

const GraphNode* EntityGraph::findNode(const std::string& nodeId) const noexcept {
    const auto kIt = nodeIndex_.find(nodeId);
    return kIt == nodeIndex_.end() ? nullptr : &nodes_[kIt->second];
}

const GraphEdge* EntityGraph::findEdge(const std::string& edgeId) const noexcept {
    const auto kIt = edgeIndex_.find(edgeId);
    return kIt == edgeIndex_.end() ? nullptr : &edges_[kIt->second];
}

bool EntityGraph::nodeIndexOf(const std::string& nodeId, std::size_t& out) const noexcept {
    const auto kIt = nodeIndex_.find(nodeId);
    if (kIt == nodeIndex_.end()) {
        return false;
    }
    out = kIt->second;
    return true;
}

const std::vector<std::size_t>& EntityGraph::incidentEdges(std::size_t nodeIndex) const {
    if (nodeIndex >= adjacency_.size()) {
        return emptyIndexList();
    }
    if (!adjacencySorted_[nodeIndex]) {
        std::vector<std::size_t>& list = adjacency_[nodeIndex];
        std::sort(list.begin(), list.end(), [this](std::size_t a, std::size_t b) {
            return edges_[a].edgeId < edges_[b].edgeId;
        });
        adjacencySorted_[nodeIndex] = 1;
    }
    return adjacency_[nodeIndex];
}

bool EntityGraph::declareRelationCoverage(EdgeKind kind,
                                          ObjectKind targetKind,
                                          RelationCoverage coverage) {
    if (kind == EdgeKind::kUnknown) {
        // G-05: EdgeKind::Unknown signifies "not filled" and is not a valid relationship. Accepting it would effectively issue a
        // proof to every node lacking an ownerRelation annotation that "this hop has been fully checked and indeed has no owner."
        return false;
    }
    coverage_[std::make_pair(kind, targetKind)] = std::move(coverage);
    return true;
}

std::vector<RelationCoverageEntry> EntityGraph::declaredRelationCoverages() const {
    std::vector<RelationCoverageEntry> entries;
    entries.reserve(coverage_.size());
    for (const auto& entry : coverage_) {
        RelationCoverageEntry out;
        out.kind = entry.first.first;
        out.targetKind = entry.first.second;
        out.coverage = entry.second;
        entries.push_back(std::move(out));
    }
    return entries;  // std::map is already ordered by (kind, targetKind).
}

RelationCoverage EntityGraph::relationCoverage(EdgeKind kind, ObjectKind targetKind) const {
    const auto kIt = coverage_.find(std::make_pair(kind, targetKind));
    if (kIt == coverage_.end()) {
        // Not declared means not collected. The default is never 'collected but empty'.
        return emptyCoverage();
    }
    return kIt->second;
}

// ---------------------------------------------------------------------------
// G-04: Bounded unwind
// ---------------------------------------------------------------------------
namespace {

// The processing state of each edge within a single unwind, ensuring the same edge is not double-counted by both endpoints.
enum class EdgeVisit : unsigned char {
    kUnseen = 0,
    kFilteredOut,
    kIncluded,
    kDeferredByLimit,
    kUnsavedNeighbor,
};

struct ExpansionState final {
    std::vector<char> loaded;
    std::vector<EdgeVisit> edgeVisit;
    std::vector<std::size_t> order;
    std::uint64_t deferredEdges = 0;
};

} // namespace

ExpansionResult expandGraph(const EntityGraph& graph, const ExpansionRequest& request) {
    ExpansionResult result;

    ExpansionLimits limits = request.limits;
    if (!request.continueRequestedByUser) {
        // G-04: Initially allow only the target + one hop, with defaults of 200/500. Exceeding the default requires an
        // explicit request from the caller to continue; do not silently allow a large limits value to be passed in.
        if (limits.maxNodes > kDefaultMaxNodes) {
            limits.maxNodes = kDefaultMaxNodes;
            result.limitsClampedToDefault = true;
        }
        if (limits.maxEdges > kDefaultMaxEdges) {
            limits.maxEdges = kDefaultMaxEdges;
            result.limitsClampedToDefault = true;
        }
        if (limits.maxHops > kDefaultMaxHops) {
            limits.maxHops = kDefaultMaxHops;
            result.hopsClampedToDefault = true;
        }
    }

    ExpansionState state;
    state.loaded.assign(graph.nodeCount(), 0);
    state.edgeVisit.assign(graph.edgeCount(), EdgeVisit::kUnseen);

    std::vector<std::string> roots = request.rootNodeIds;
    sortUnique(roots);  // Input order does not affect loading order (G-08).
    bool anyRootResolved = false;
    for (const std::string& rootId : roots) {
        std::size_t index = 0;
        if (!graph.nodeIndexOf(rootId, index)) {
            UnsavedNeighbor missing;
            missing.missingNodeId = rootId;
            result.unsavedNeighbors.push_back(missing);
            result.limitationKeys.emplace_back("graph.expand.rootNotSaved");
            continue;
        }
        anyRootResolved = true;
        if (state.loaded[index]) {
            continue;
        }
        if (result.loadedNodes >= limits.maxNodes) {
            result.nodeLimitHit = true;
            result.moreAvailable = true;
            continue;
        }
        state.loaded[index] = 1;
        state.order.push_back(index);
        ++result.loadedNodes;
    }

    // Scan incident edges of a node. When allowNewNodes is false, only close the closure
    // (complete edges whose both ends are already loaded) without introducing new nodes.
    const auto kScanNode = [&](std::size_t nodeIndex, bool allowNewNodes) {
        const std::string& nodeId = graph.nodes()[nodeIndex].nodeId;
        for (const std::size_t kEdgeIndex : graph.incidentEdges(nodeIndex)) {
            EdgeVisit& visit = state.edgeVisit[kEdgeIndex];
            if (visit == EdgeVisit::kFilteredOut || visit == EdgeVisit::kIncluded ||
                visit == EdgeVisit::kUnsavedNeighbor) {
                continue;
            }
            if (visit == EdgeVisit::kDeferredByLimit && result.loadedEdges >= limits.maxEdges) {
                // The edge budget is full, so this edge's state will not change: the load check occurs after the budget check,
                // and its other endpoint must be a saved node (edges pointing to unsaved neighbors become UnsavedNeighbor on
                // first visit, never Deferred). Traversing again is merely a wasted hash lookup; on a hub with tens of
                // thousands of edges, this single traversal accounts for the majority of the unwind data overhead.
                // Accounting is unaffected: deferredEdges were already recorded during the first access.
                continue;
            }
            const GraphEdge& edge = graph.edges()[kEdgeIndex];
            if (visit == EdgeVisit::kUnseen) {
                if (!edgeMatchesFilter(edge, request.filter)) {
                    visit = EdgeVisit::kFilteredOut;
                    ++result.filteredEdgeCount;
                    continue;
                }
            }
            const std::string& otherId = (edge.fromNodeId == nodeId) ? edge.toNodeId : edge.fromNodeId;
            std::size_t otherIndex = 0;
            if (!graph.nodeIndexOf(otherId, otherIndex)) {
                // G-06: Neighbor not saved. Record accounting, do not query.
                UnsavedNeighbor missing;
                missing.edgeId = edge.edgeId;
                missing.missingNodeId = otherId;
                missing.relation = edge.kind;
                result.unsavedNeighbors.push_back(missing);
                if (visit == EdgeVisit::kDeferredByLimit) {
                    --state.deferredEdges;
                }
                visit = EdgeVisit::kUnsavedNeighbor;
                continue;
            }
            // Edge budget check first: if this edge cannot fit, do not pull in the node it points to,
            // otherwise you get 'an extra node in the graph with no visible edge bringing it in'.
            if (result.loadedEdges >= limits.maxEdges) {
                if (visit != EdgeVisit::kDeferredByLimit) {
                    visit = EdgeVisit::kDeferredByLimit;
                    ++state.deferredEdges;
                }
                result.edgeLimitHit = true;
                result.moreAvailable = true;
                continue;
            }
            if (!state.loaded[otherIndex]) {
                if (!allowNewNodes || result.loadedNodes >= limits.maxNodes) {
                    if (visit != EdgeVisit::kDeferredByLimit) {
                        visit = EdgeVisit::kDeferredByLimit;
                        ++state.deferredEdges;
                    }
                    result.moreAvailable = true;
                    if (result.loadedNodes >= limits.maxNodes) {
                        result.nodeLimitHit = true;
                    } else {
                        // The node limit has not been reached; the hop count has been exhausted instead. These are distinct causes and must not be conflated.
                        result.hopLimitHit = true;
                    }
                    continue;
                }
                state.loaded[otherIndex] = 1;
                state.order.push_back(otherIndex);
                ++result.loadedNodes;
            }
            if (visit == EdgeVisit::kDeferredByLimit) {
                --state.deferredEdges;
            }
            visit = EdgeVisit::kIncluded;
            ++result.loadedEdges;
        }
    };

    std::size_t levelBegin = 0;
    std::size_t levelEnd = state.order.size();
    for (std::uint64_t hop = 0; hop < limits.maxHops; ++hop) {
        if (levelBegin >= levelEnd) {
            break;
        }
        for (std::size_t i = levelBegin; i < levelEnd; ++i) {
            kScanNode(state.order[i], true);
        }
        levelBegin = levelEnd;
        levelEnd = state.order.size();
    }
    // Closure: No edges between loaded nodes can be hidden, otherwise two nodes visible on the graph would have no visible
    // relationship. Additionally, this pass marks edges from the last layer of nodes to external nodes as 'more available'.
    for (const std::size_t kNodeIndex : state.order) {
        kScanNode(kNodeIndex, false);
    }

    const std::uint64_t kSavedNodes = static_cast<std::uint64_t>(graph.nodeCount());
    const std::uint64_t kSavedEdges = static_cast<std::uint64_t>(graph.edgeCount());

    result.coverage.succeeded = result.loadedNodes;
    result.coverage.skipped = static_cast<std::uint64_t>(result.unsavedNeighbors.size());
    result.coverage.truncated = state.deferredEdges;
    result.coverage.limitHit = result.nodeLimitHit || result.edgeLimitHit;
    if (result.nodeLimitHit) {
        result.coverage.limit = OptionalU64::of(limits.maxNodes);
    } else if (result.edgeLimitHit) {
        result.coverage.limit = OptionalU64::of(limits.maxEdges);
    }

    // G-04: The total count is known only when the traversal has truly reached the end, there are no unsaved neighbors, **and the loaded count
    // equals all nodes and edges saved in the graph**. The first two conditions naturally hold when only one connected component is traversed:
    // an expansion starting from an isolated node will neither set moreAvailable nor have unsaved neighbors, causing loadedNodes to be written
    // as the total count in the export. Readers will see "Total Known, Coverage Complete" when in reality only half the graph was covered.
    // If the loaded count matches the graph size, this path is blocked.
    const bool kWalkedWholeGraph = result.loadedNodes == kSavedNodes && result.loadedEdges == kSavedEdges;
    if (anyRootResolved && !result.moreAvailable && result.unsavedNeighbors.empty() &&
        kWalkedWholeGraph) {
        result.totalKnownNodes = OptionalU64::of(kSavedNodes);
        result.totalKnownEdges = OptionalU64::of(kSavedEdges);
    }
    // Set the total in the ledger to the graph size, not the number loaded this time: letting 'how many were loaded this time'
    // serve as positive evidence for 'how many exist in total' would make fullyCovered() an empty tautology that is always true.
    result.coverage.totalKnown = OptionalU64::of(kSavedNodes);

    result.nodeIds.reserve(state.order.size());
    for (const std::size_t kNodeIndex : state.order) {
        result.nodeIds.push_back(graph.nodes()[kNodeIndex].nodeId);
    }
    for (std::size_t i = 0; i < state.edgeVisit.size(); ++i) {
        if (state.edgeVisit[i] == EdgeVisit::kIncluded) {
            result.edgeIds.push_back(graph.edges()[i].edgeId);
        }
    }
    std::sort(result.nodeIds.begin(), result.nodeIds.end());
    std::sort(result.edgeIds.begin(), result.edgeIds.end());
    std::sort(result.unsavedNeighbors.begin(), result.unsavedNeighbors.end(),
              [](const UnsavedNeighbor& a, const UnsavedNeighbor& b) {
                  if (a.missingNodeId != b.missingNodeId) {
                      return a.missingNodeId < b.missingNodeId;
                  }
                  return a.edgeId < b.edgeId;
              });

    if (roots.empty()) {
        result.limitationKeys.emplace_back("graph.expand.noRoots");
    }
    if (result.limitsClampedToDefault) {
        result.limitationKeys.emplace_back("graph.expand.limitsClampedToDefault");
    }
    if (result.hopsClampedToDefault) {
        result.limitationKeys.emplace_back("graph.expand.hopsClampedToDefault");
    }
    if (result.nodeLimitHit) {
        result.limitationKeys.emplace_back("graph.expand.nodeLimitHit");
    }
    if (result.edgeLimitHit) {
        result.limitationKeys.emplace_back("graph.expand.edgeLimitHit");
    }
    if (result.hopLimitHit) {
        result.limitationKeys.emplace_back("graph.expand.hopLimitHit");
    }
    if (result.moreAvailable) {
        result.limitationKeys.emplace_back("graph.expand.moreAvailable");
    }
    if (!result.unsavedNeighbors.empty()) {
        result.limitationKeys.emplace_back("graph.expand.unsavedNeighbors");
    }
    if (!result.totalKnownNodes.present) {
        result.limitationKeys.emplace_back("graph.expand.totalUnknown");
    }
    if (result.filteredEdgeCount > 0) {
        result.limitationKeys.emplace_back("graph.expand.filterApplied");
    }
    sortUnique(result.limitationKeys);

    // G-06: This layer has no live query exit, so liveQueriesIssued remains at the default 0 throughout.
    // We intentionally omit writing ``= 0`` here: that assignment would flatten any increments occurring within the
    // function body, making the upper-level "always 0" assertion permanently true and forever unable to catch
    // stealthy queries. If a query exit exists, it must increment itself, and only then can this assertion catch it.
    return result;
}

// ---------------------------------------------------------------------------
// G-02: Locate historical edge to live.
// ---------------------------------------------------------------------------
HistoricalEdgeLiveResult resolveHistoricalEdgeToLive(const EntityGraph& graph,
                                                     const HistoricalEdgeLiveRequest& request) {
    HistoricalEdgeLiveResult result;
    const GraphEdge* edge = graph.findEdge(request.edgeId);
    if (edge == nullptr) {
        result.reasonKey = "graph.live.edgeNotFound";
        return result;
    }
    result.edgeFound = true;
    result.savedNodeId =
        (request.endpoint == EndpointRole::kTo) ? edge->toNodeId : edge->fromNodeId;

    const GraphNode* node = graph.findNode(result.savedNodeId);
    if (node == nullptr) {
        result.reasonKey = "graph.live.nodeNotSaved";
        return result;
    }
    result.nodeFound = true;
    result.kind = node->identity.kind;

    if (node->identity.category != NodeCategory::kSystemObject ||
        node->identity.kind != ObjectKind::kProcess) {
        // Currently, only processes have the contract for 'live re-resolution of identity' (LiveNavigation.h). For other
        // categories, this is not a 'mismatch' but rather 'we cannot verify' — these two cases must be distinguished.
        result.liveResolverSupported = false;
        result.identityDecision = LiveNavigationDecision::kRejectIdentityUnverifiable;
        result.reasonKey = "graph.live.noResolverForKind";
        return result;
    }

    result.liveResolverSupported = true;
    result.identityDecision = resolveProcessNavigation(node->identity.process, request.live);
    switch (result.identityDecision) {
    case LiveNavigationDecision::kRejectObjectExited:
        result.reasonKey = "graph.live.objectExited";
        return result;
    case LiveNavigationDecision::kRejectIdentityMismatch:
        // G-02 Core: Same PID, different instances. Never populate liveNodeId and never initiate navigation.
        result.reasonKey = "graph.live.identityMismatch";
        return result;
    case LiveNavigationDecision::kRejectIdentityUnverifiable:
        result.reasonKey = "graph.live.identityUnverifiable";
        return result;
    case LiveNavigationDecision::kAllow:
        break;
    }

    NodeIdentity liveIdentity = node->identity;
    liveIdentity.process = request.live.liveProcess;
    result.liveNodeId = liveIdentity.nodeKey();

    NavigationRequest navigation;
    navigation.page = request.page;
    navigation.object = liveIdentity.makeRef(node->evidenceId, node->displayText);
    navigation.evidenceId = node->evidenceId;
    navigation.requireExactMatch = true;
    result.navigationAttempted = true;
    result.navigation = decideNavigation(navigation,
                                         request.targetPageAvailable,
                                         request.objectPresentInPage,
                                         request.evidencePresentInSession);
    result.reasonKey = (result.navigation == NavigationOutcome::kDelivered)
                           ? "graph.live.delivered"
                           : "graph.live.navigationRejected";
    return result;
}

// ---------------------------------------------------------------------------
// G-03: Investigation chain
// ---------------------------------------------------------------------------
namespace {

struct NeighborScan final {
    std::vector<std::size_t> nodeIndices;   // Sorted by nodeId
    std::vector<std::string> nodeIds;
    std::vector<std::string> edgeIds;
    std::uint64_t matchCount = 0;
    bool truncated = false;
    bool anyIdentityUsable = false;
    bool everyPresentEvidenceOpenable = true;
    bool anyObjectNavigable = false;
    bool everyObjectNavigable = true;
    EdgeCertainty weakestCertainty = EdgeCertainty::kConfirmed;
    std::string evidenceId;
};

int certaintyRank(EdgeCertainty certainty) noexcept {
    switch (certainty) {
    case EdgeCertainty::kUnknown:   return 0;
    case EdgeCertainty::kCandidate: return 1;
    case EdgeCertainty::kConfirmed: return 2;
    }
    return 0;
}

// Traverse one hop from multiple starting points along a specific relation type. neighborRole indicates the position of the **neighbor** within the edge.
NeighborScan scanRelation(const EntityGraph& graph,
                          const std::vector<std::size_t>& sources,
                          EdgeKind relation,
                          NodeCategory expectedCategory,
                          ObjectKind expectedKind,
                          EndpointRole neighborRole,
                          const ChainOptions& options) {
    NeighborScan scan;
    std::vector<std::pair<std::string, std::size_t>> found;
    std::vector<std::string> edgeIds;
    for (const std::size_t kSourceIndex : sources) {
        const std::string& sourceId = graph.nodes()[kSourceIndex].nodeId;
        for (const std::size_t kEdgeIndex : graph.incidentEdges(kSourceIndex)) {
            const GraphEdge& edge = graph.edges()[kEdgeIndex];
            if (edge.kind != relation) {
                continue;
            }
            if (!edgeMatchesFilter(edge, options.filter)) {
                continue;
            }
            const std::string& neighborId =
                (neighborRole == EndpointRole::kTo) ? edge.toNodeId : edge.fromNodeId;
            const std::string& selfId =
                (neighborRole == EndpointRole::kTo) ? edge.fromNodeId : edge.toNodeId;
            if (selfId != sourceId) {
                continue;  // Direction is incorrect; this hop is invalid.
            }
            std::size_t neighborIndex = 0;
            if (!graph.nodeIndexOf(neighborId, neighborIndex)) {
                continue;  // Unsaved neighbors are accounted for by the unwind; the link here is treated as nonexistent.
            }
            const GraphNode& neighbor = graph.nodes()[neighborIndex];
            if (neighbor.identity.category != expectedCategory) {
                continue;
            }
            if (expectedKind != ObjectKind::kUnknown && neighbor.identity.kind != expectedKind) {
                continue;
            }
            found.emplace_back(neighborId, neighborIndex);
            edgeIds.push_back(edge.edgeId);
            if (certaintyRank(edge.certainty) < certaintyRank(scan.weakestCertainty)) {
                scan.weakestCertainty = edge.certainty;
            }
        }
    }
    std::sort(found.begin(), found.end());
    found.erase(std::unique(found.begin(), found.end()), found.end());
    sortUnique(edgeIds);

    scan.matchCount = static_cast<std::uint64_t>(found.size());
    if (found.empty()) {
        scan.weakestCertainty = EdgeCertainty::kUnknown;
        // When there are no nodes, 'every evidence is openable' and 'every object is navigable' are vacuously true. This
        // vacuous truth must not be misinterpreted as 'this link can open the source', so it is explicitly set to false.
        scan.everyPresentEvidenceOpenable = false;
        scan.everyObjectNavigable = false;
    }
    for (const std::pair<std::string, std::size_t>& entry : found) {
        if (static_cast<std::uint64_t>(scan.nodeIds.size()) >= options.maxNodesPerStep) {
            scan.truncated = true;
            // Truncation implies there are still unvisited nodes; the statements 'every evidence
            // is openable' and 'every object is navigable' no longer hold for this iteration.
            scan.everyPresentEvidenceOpenable = false;
            scan.everyObjectNavigable = false;
            break;
        }
        const GraphNode& neighbor = graph.nodes()[entry.second];
        scan.nodeIds.push_back(entry.first);
        scan.nodeIndices.push_back(entry.second);
        if (neighbor.identity.strength() != IdentityStrength::kUnusable) {
            scan.anyIdentityUsable = true;
        }
        if (neighbor.objectNavigable()) {
            scan.anyObjectNavigable = true;
        } else {
            scan.everyObjectNavigable = false;
        }
        if (!neighbor.evidenceOpenable()) {
            scan.everyPresentEvidenceOpenable = false;
        } else if (scan.evidenceId.empty()) {
            scan.evidenceId = neighbor.evidenceId;
        }
    }
    scan.edgeIds = std::move(edgeIds);
    return scan;
}

StepAvailability decideAvailability(const NeighborScan& scan,
                                    const RelationCoverage& coverage,
                                    bool previousStepMissing) {
    // Check for missing previous step first. When the previous step is marked as 'has records but insufficient identity to count as a
    // confirmed hop', traversing one more hop from those objects still yields neighbors; checking matchCount first would incorrectly report
    // this step as Present, causing the UI to show 'previous hop unconfirmed, next hop confirmed and clickable to object page'. When the
    // starting point is invalid, this step's state is 'missing previous step', which is distinct from 'source for this step not collected'.
    if (previousStepMissing) {
        return StepAvailability::kMissingPreviousStepMissing;
    }
    if (scan.matchCount > 0) {
        // Records exist but no usable identity: cannot be treated as a confirmed hop (G-02).
        return scan.anyIdentityUsable ? StepAvailability::kPresent
                                      : StepAvailability::kMissingIdentityUnusable;
    }
    switch (coverage.outcome.status) {
    case CollectionStatus::kSuccess:
        // Only if the account positively proves full coverage is 'missing' truly 'missing'.
        return coverage.coverage.fullyCovered() ? StepAvailability::kMissingNoData
                                                : StepAvailability::kMissingCoverageIncomplete;
    case CollectionStatus::kPartial:
        return StepAvailability::kMissingCoverageIncomplete;
    case CollectionStatus::kNotCollected:
        return StepAvailability::kMissingNotCollected;
    case CollectionStatus::kUnsupported:
        return StepAvailability::kMissingUnsupported;
    case CollectionStatus::kAccessDenied:
        return StepAvailability::kMissingAccessDenied;
    case CollectionStatus::kTimeout:
    case CollectionStatus::kError:
        return StepAvailability::kMissingCollectionFailed;
    }
    return StepAvailability::kMissingNotCollected;
}

ChainStep makeRootStep(const EntityGraph& graph,
                       const std::string& rootNodeId,
                       const char* labelKey,
                       ObjectKind expectedKind,
                       std::vector<std::size_t>& outSources) {
    ChainStep step;
    step.index = 0;
    step.labelKey = labelKey;
    step.expectedKind = expectedKind;
    step.expectedCategory = NodeCategory::kSystemObject;
    step.relationFromPrevious = EdgeKind::kUnknown;

    std::size_t index = 0;
    if (!graph.nodeIndexOf(rootNodeId, index)) {
        // The node does not exist at all: this indicates "not saved/not collected," not "the object is missing."
        step.availability = StepAvailability::kMissingNotCollected;
        step.outcome = CollectionOutcome::notCollected();
        return step;
    }
    const GraphNode& node = graph.nodes()[index];
    step.outcome = node.outcome;
    step.evidenceId = node.evidenceId;
    step.nodeIds.push_back(node.nodeId);
    step.matchCount = 1;
    step.anyObjectNavigable = node.objectNavigable();
    step.everyObjectNavigable = node.objectNavigable();
    step.evidenceOpenable = node.evidenceOpenable();
    if (node.identity.strength() == IdentityStrength::kUnusable) {
        step.availability = StepAvailability::kMissingIdentityUnusable;
    } else {
        step.availability = StepAvailability::kPresent;
    }
    outSources.push_back(index);
    return step;
}

ChainStep makeRelationStep(const EntityGraph& graph,
                           std::size_t stepIndex,
                           const char* labelKey,
                           EdgeKind relation,
                           NodeCategory expectedCategory,
                           ObjectKind expectedKind,
                           EndpointRole neighborRole,
                           const std::vector<std::size_t>& sources,
                           bool previousStepMissing,
                           const ChainOptions& options,
                           std::vector<std::size_t>& outSources) {
    ChainStep step;
    step.index = stepIndex;
    step.labelKey = labelKey;
    step.relationFromPrevious = relation;
    step.expectedCategory = expectedCategory;
    step.expectedKind = expectedKind;

    const RelationCoverage kCoverage = graph.relationCoverage(relation, expectedKind);
    step.outcome = kCoverage.outcome;

    const NeighborScan kScan =
        scanRelation(graph, sources, relation, expectedCategory, expectedKind, neighborRole, options);
    step.availability = decideAvailability(kScan, kCoverage, previousStepMissing);
    step.matchCount = kScan.matchCount;
    step.truncated = kScan.truncated;
    step.nodeIds = kScan.nodeIds;
    step.edgeIds = kScan.edgeIds;
    step.weakestEdgeCertainty = kScan.weakestCertainty;
    step.anyObjectNavigable = kScan.anyObjectNavigable;
    step.everyObjectNavigable = kScan.everyObjectNavigable;
    // G-03: The condition is "each step's source details must be openable." It must be 'every': if even one node in the chain
    // cannot open the original evidence, "this step can open the source" is false. Using 'any' when only 1 of 3 threads has
    // evidence would incorrectly mark it as satisfied, causing the UI to render 3 points while only 1 is actually openable.
    step.evidenceOpenable = kScan.matchCount > 0 && kScan.everyPresentEvidenceOpenable;
    step.evidenceId = kScan.matchCount > 0 ? kScan.evidenceId : kCoverage.evidenceId;
    outSources = kScan.nodeIndices;

    if (previousStepMissing) {
        // The starting point is invalid: Report the findings from this step as-is (matchCount / nodeIds / edgeIds are factual), but do not
        // treat this as a deterministic jump. Therefore, do not enable object navigation for these objects, nor use them as starting points
        // for the next step. Otherwise, a chain with a 'doubtful previous hop' would incorrectly generate a deterministic downstream chain.
        step.anyObjectNavigable = false;
        step.everyObjectNavigable = false;
        outSources.clear();
    }
    return step;
}

} // namespace

std::size_t InvestigationChain::missingStepCount() const noexcept {
    std::size_t count = 0;
    for (const ChainStep& step : steps) {
        if (stepIsMissing(step.availability)) {
            ++count;
        }
    }
    return count;
}

bool InvestigationChain::complete() const noexcept {
    // A default-constructed chain has empty steps—that is not 'complete', it is 'nothing'.
    return !steps.empty() && missingStepCount() == 0;
}

bool InvestigationChain::everyPresentStepOpensSource() const noexcept {
    if (steps.empty()) {
        return false;
    }
    for (const ChainStep& step : steps) {
        if (step.availability == StepAvailability::kPresent && !step.evidenceOpenable) {
            return false;
        }
    }
    return true;
}

InvestigationChain buildChain(const EntityGraph& graph,
                              ChainKind kind,
                              const std::string& rootNodeId,
                              const ChainOptions& options) {
    InvestigationChain chain;
    chain.kind = kind;
    chain.rootNodeId = rootNodeId;

    std::vector<std::size_t> rootSources;
    switch (kind) {
    case ChainKind::kProcessSubjects: {
        ChainStep root = makeRootStep(graph, rootNodeId, "graph.chain.process.root",
                                      ObjectKind::kProcess, rootSources);
        chain.rootFound = !rootSources.empty();
        const bool kRootMissing = stepIsMissing(root.availability);
        chain.steps.push_back(root);

        std::vector<std::size_t> unusedSources;
        chain.steps.push_back(makeRelationStep(graph, 1, "graph.chain.process.threads",
                                               EdgeKind::kOwns, NodeCategory::kSystemObject,
                                               ObjectKind::kThread, EndpointRole::kTo, rootSources,
                                               kRootMissing, options, unusedSources));
        chain.steps.push_back(makeRelationStep(graph, 2, "graph.chain.process.modules",
                                               EdgeKind::kLoads, NodeCategory::kSystemObject,
                                               ObjectKind::kModule, EndpointRole::kTo, rootSources,
                                               kRootMissing, options, unusedSources));
        chain.steps.push_back(makeRelationStep(graph, 3, "graph.chain.process.handles",
                                               EdgeKind::kOwns, NodeCategory::kSystemObject,
                                               ObjectKind::kHandle, EndpointRole::kTo, rootSources,
                                               kRootMissing, options, unusedSources));
        break;
    }
    case ChainKind::kDeviceToService: {
        ChainStep root = makeRootStep(graph, rootNodeId, "graph.chain.device.root",
                                      ObjectKind::kDevice, rootSources);
        chain.rootFound = !rootSources.empty();
        bool previousMissing = stepIsMissing(root.availability);
        chain.steps.push_back(root);

        std::vector<std::size_t> driverSources;
        ChainStep driverStep = makeRelationStep(graph, 1, "graph.chain.device.driverObject",
                                                EdgeKind::kDeviceOf, NodeCategory::kSystemObject,
                                                ObjectKind::kDriver, EndpointRole::kTo, rootSources,
                                                previousMissing, options, driverSources);
        previousMissing = stepIsMissing(driverStep.availability);
        chain.steps.push_back(driverStep);

        std::vector<std::size_t> imageSources;
        ChainStep imageStep = makeRelationStep(graph, 2, "graph.chain.device.driverImage",
                                               EdgeKind::kImageOf, NodeCategory::kSystemObject,
                                               ObjectKind::kFile, EndpointRole::kTo, driverSources,
                                               previousMissing, options, imageSources);
        previousMissing = stepIsMissing(imageStep.availability);
        chain.steps.push_back(imageStep);

        std::vector<std::size_t> serviceSources;
        chain.steps.push_back(makeRelationStep(graph, 3, "graph.chain.device.service",
                                               EdgeKind::kServiceOf, NodeCategory::kSystemObject,
                                               ObjectKind::kService, EndpointRole::kTo, imageSources,
                                               previousMissing, options, serviceSources));
        break;
    }
    case ChainKind::kConnectionToTimeline: {
        ChainStep root = makeRootStep(graph, rootNodeId, "graph.chain.connection.root",
                                      ObjectKind::kConnection, rootSources);
        chain.rootFound = !rootSources.empty();
        bool previousMissing = stepIsMissing(root.availability);
        chain.steps.push_back(root);

        std::vector<std::size_t> processSources;
        // The process owns the connection: Process -(Owns)-> Connection. The neighbor is on the From side.
        ChainStep processStep = makeRelationStep(graph, 1, "graph.chain.connection.process",
                                                 EdgeKind::kOwns, NodeCategory::kSystemObject,
                                                 ObjectKind::kProcess, EndpointRole::kFrom,
                                                 rootSources, previousMissing, options,
                                                 processSources);
        previousMissing = stepIsMissing(processStep.availability);
        chain.steps.push_back(processStep);

        std::vector<std::size_t> timelineSources;
        chain.steps.push_back(makeRelationStep(graph, 2, "graph.chain.connection.timeline",
                                               EdgeKind::kTimelineEntry, NodeCategory::kTimelineEntry,
                                               ObjectKind::kUnknown, EndpointRole::kTo,
                                               processSources, previousMissing, options,
                                               timelineSources));
        break;
    }
    }
    return chain;
}

// ---------------------------------------------------------------------------
// G-05: Isolation and unknown
// ---------------------------------------------------------------------------
IsolationReport classifyIsolation(const EntityGraph& graph,
                                  const std::string& nodeId,
                                  const EdgeFilter& filter) {
    IsolationReport report;
    report.nodeId = nodeId;
    std::size_t index = 0;
    if (!graph.nodeIndexOf(nodeId, index)) {
        report.explanationKey = "graph.isolation.nodeNotSaved";
        report.rawEvidenceMissingKey = "graph.isolation.noRawEvidence";
        report.ownerLookupOutcome = CollectionOutcome::notCollected();
        return report;  // state remains the default SourceNotCollected; this is absolutely not 'normal'.
    }
    report.nodeFound = true;
    const GraphNode& node = graph.nodes()[index];
    report.evidenceId = node.evidenceId;
    report.rawEvidenceAvailable = node.evidenceOpenable();
    if (!report.rawEvidenceAvailable) {
        // G-05: This UI must state "no raw evidence exists" instead of graying out a clickable button.
        report.rawEvidenceMissingKey = "graph.isolation.noRawEvidence";
    }
    report.inconsistencyEvidenceIds = node.inconsistencyEvidenceIds;

    const std::vector<std::size_t>& incident = graph.incidentEdges(index);
    report.edgeCountBeforeFilter = static_cast<std::uint64_t>(incident.size());
    for (const std::size_t kEdgeIndex : incident) {
        if (edgeMatchesFilter(graph.edges()[kEdgeIndex], filter)) {
            ++report.edgeCountAfterFilter;
        }
    }

    // G-05: When ownerRelation is not set, treat it as 'source not collected'. Querying the coverage table with EdgeKind::Unknown
    // would read a cell declared by someone else for a completely different purpose. A single unrelated (Unknown, Unknown) declaration
    // could flip this node from 'we didn't check' to 'we checked thoroughly and found no owner'—even though this relationship was
    // never named. Without a name, 'thoroughly checked' is meaningless; it must fall into the 'not collected' category.
    const bool kOwnerRelationDeclared = node.ownerRelation != EdgeKind::kUnknown;
    const RelationCoverage kOwnerCoverage =
        kOwnerRelationDeclared ? graph.relationCoverage(node.ownerRelation, node.ownerKind)
                              : RelationCoverage{};
    report.ownerLookupOutcome = kOwnerCoverage.outcome;

    if (report.edgeCountAfterFilter > 0) {
        report.isolated = false;
        report.state = IsolationState::kNotIsolated;
        report.explanationKey = "graph.isolation.notIsolated";
        return report;
    }
    report.isolated = true;

    // Ordering explanation: Only 'actual inconsistency' is a statement supported by positive evidence; the other three
    // explain 'why an edge was not seen', so it is checked first. The rest are ordered by 'what can be determined first':
    // object unloaded -> source not fully sampled -> fully sampled but no owner exists. None of these express risk.
    if (node.inconsistencyObserved) {
        report.state = IsolationState::kObservedInconsistency;
        report.explanationKey = "graph.isolation.observedInconsistency";
        return report;
    }
    if (node.lifecycle == NodeLifecycle::kEnded) {
        report.state = IsolationState::kObjectUnloaded;
        report.explanationKey = "graph.isolation.objectUnloaded";
        return report;
    }
    if (!kOwnerRelationDeclared) {
        report.state = IsolationState::kSourceNotCollected;
        report.explanationKey = "graph.isolation.ownerRelationNotDeclared";
        return report;
    }
    if (!coverageProvesAbsence(kOwnerCoverage)) {
        // Collecting nothing, unsupported, rejected, timeout, error, or partial collection all map to this state. However, the
        // original state and error code are preserved verbatim in ownerLookupOutcome so callers can distinguish them at any time.
        report.state = IsolationState::kSourceNotCollected;
        report.explanationKey = "graph.isolation.sourceNotCollected";
        return report;
    }
    report.state = IsolationState::kOwnerMissing;
    report.explanationKey = "graph.isolation.ownerMissing";
    return report;
}

// ---------------------------------------------------------------------------
// G-06 / G-08: List, details, and inference explanation.
// ---------------------------------------------------------------------------
std::vector<EntityListRow> buildEntityList(const EntityGraph& graph,
                                           const ExpansionResult& expansion,
                                           const EdgeFilter& filter,
                                           EntityListOrder order,
                                           std::uint64_t* outMissingNodeCount) {
    std::vector<EntityListRow> rows;
    std::uint64_t missing = 0;
    rows.reserve(expansion.nodeIds.size());
    for (const std::string& nodeId : expansion.nodeIds) {
        std::size_t index = 0;
        if (!graph.nodeIndexOf(nodeId, index)) {
            // Present in view but missing in graph: skip but record. When row counts do not match loadedNodes,
            // the caller must be able to explain the discrepancy, not have the two numbers contradict each other.
            ++missing;
            continue;
        }
        const GraphNode& node = graph.nodes()[index];
        EntityListRow row;
        row.nodeId = node.nodeId;  // G-06: Must share the same ID as the graph, details, and export.
        row.category = node.identity.category;
        row.kind = node.identity.kind;
        row.displayText = node.displayText;
        row.evidenceId = node.evidenceId;
        row.strength = node.identity.strength();
        row.lifecycle = node.lifecycle;
        row.objectNavigable = node.objectNavigable();
        row.evidenceOpenable = node.evidenceOpenable();
        for (const std::size_t kEdgeIndex : graph.incidentEdges(index)) {
            if (edgeMatchesFilter(graph.edges()[kEdgeIndex], filter)) {
                ++row.edgeCount;
            }
        }
        rows.push_back(std::move(row));
    }
    if (outMissingNodeCount != nullptr) {
        *outMissingNodeCount = missing;
    }

    // All sorts fall back to nodeId to ensure a fully deterministic order for
    // the same data; sorting only affects display, not any conclusions (G-08).
    switch (order) {
    case EntityListOrder::kByNodeId:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            return a.nodeId < b.nodeId;
        });
        break;
    case EntityListOrder::kByDisplayText:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            if (a.displayText != b.displayText) {
                return a.displayText < b.displayText;
            }
            return a.nodeId < b.nodeId;
        });
        break;
    case EntityListOrder::kByKind:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            if (a.kind != b.kind) {
                return static_cast<int>(a.kind) < static_cast<int>(b.kind);
            }
            return a.nodeId < b.nodeId;
        });
        break;
    case EntityListOrder::kByEdgeCountDescending:
        std::sort(rows.begin(), rows.end(), [](const EntityListRow& a, const EntityListRow& b) {
            if (a.edgeCount != b.edgeCount) {
                return a.edgeCount > b.edgeCount;
            }
            return a.nodeId < b.nodeId;
        });
        break;
    }
    return rows;
}

EdgeInferenceNote describeEdgeInference(const GraphEdge& edge) {
    // The rule from G-01 that 'missing evidence relationships must not be displayed as certain' cannot hold only on the addEdge path: this
    // function is the inference explanation interface exposed by the header file (G-08 'inference rules and sources can be expanded'), and the
    // caller may entirely likely query an edge that has never entered the graph. Blindly trusting the passed-in certainty would present an
    // externally confirmed relationship with no explanation and zero sources. Therefore, run normalization first, then re-verify the invariant.
    GraphEdge normalized;
    normalizeEdge(edge, normalized);

    EdgeInferenceNote note;
    note.edgeId = normalized.edgeId.empty() ? edge.edgeId : normalized.edgeId;
    note.kind = normalized.kind;
    note.certainty = normalized.certainty;
    note.ruleId = normalized.ruleId;
    note.ruleDescriptionKey = normalized.ruleDescriptionKey;
    note.evidenceRefs = normalized.evidenceRefs;
    sortUnique(note.evidenceRefs);
    // Edges rejected earlier by normalizeEdge (unknown type / missing endpoint / unknown direction
    // / invalid interval) never reach the downgrade step, so we reassert the same invariant here.
    if (note.certainty == EdgeCertainty::kConfirmed &&
        (note.evidenceRefs.empty() || !edgeKindAllowsConfirmed(note.kind))) {
        note.certainty = EdgeCertainty::kCandidate;
    }
    if (note.certainty == EdgeCertainty::kConfirmed) {
        return note;
    }
    if (note.evidenceRefs.empty()) {
        note.notConfirmedReasonKey = "graph.edge.noEvidence";
    } else if (!edgeKindAllowsConfirmed(note.kind)) {
        note.notConfirmedReasonKey = "graph.edge.candidateOwnerKind";
    } else if (note.certainty == EdgeCertainty::kUnknown) {
        note.notConfirmedReasonKey = "graph.edge.certaintyUnknown";
    } else {
        note.notConfirmedReasonKey = "graph.edge.candidateEvidence";
    }
    return note;
}

NodeDetail buildNodeDetail(const EntityGraph& graph,
                           const std::string& nodeId,
                           const EdgeFilter& filter) {
    NodeDetail detail;
    detail.nodeId = nodeId;
    detail.isolation = classifyIsolation(graph, nodeId, filter);
    std::size_t index = 0;
    if (!graph.nodeIndexOf(nodeId, index)) {
        return detail;
    }
    detail.nodeFound = true;
    const GraphNode& node = graph.nodes()[index];
    detail.category = node.identity.category;
    detail.kind = node.identity.kind;
    detail.displayText = node.displayText;
    detail.evidenceId = node.evidenceId;
    detail.strength = node.identity.strength();
    detail.lifecycle = node.lifecycle;

    for (const std::size_t kEdgeIndex : graph.incidentEdges(index)) {
        const GraphEdge& edge = graph.edges()[kEdgeIndex];
        if (!edgeMatchesFilter(edge, filter)) {
            continue;
        }
        if (edge.direction == EdgeDirection::kSymmetric) {
            detail.symmetricEdgeIds.push_back(edge.edgeId);
        } else if (edge.toNodeId == nodeId) {
            detail.incomingEdgeIds.push_back(edge.edgeId);
        } else {
            detail.outgoingEdgeIds.push_back(edge.edgeId);
        }
        detail.inferences.push_back(describeEdgeInference(edge));
    }
    sortUnique(detail.incomingEdgeIds);
    sortUnique(detail.outgoingEdgeIds);
    sortUnique(detail.symmetricEdgeIds);
    std::sort(detail.inferences.begin(), detail.inferences.end(),
              [](const EdgeInferenceNote& a, const EdgeInferenceNote& b) {
                  return a.edgeId < b.edgeId;
              });
    return detail;
}

// ---------------------------------------------------------------------------
// G-08: Conclusion and export
// ---------------------------------------------------------------------------
bool operator==(const GraphConclusion& a, const GraphConclusion& b) {
    return a.conclusion == b.conclusion && a.nodeCount == b.nodeCount &&
           a.edgeCountAfterFilter == b.edgeCountAfterFilter &&
           a.edgeCountBeforeFilter == b.edgeCountBeforeFilter &&
           a.confirmedEdgeCount == b.confirmedEdgeCount &&
           a.candidateEdgeCount == b.candidateEdgeCount &&
           a.unknownCertaintyEdgeCount == b.unknownCertaintyEdgeCount &&
           a.isolatedNodeCount == b.isolatedNodeCount &&
           a.ownerMissingCount == b.ownerMissingCount && a.unloadedCount == b.unloadedCount &&
           a.sourceNotCollectedCount == b.sourceNotCollectedCount &&
           a.inconsistencyCount == b.inconsistencyCount &&
           a.unusableIdentityNodeCount == b.unusableIdentityNodeCount &&
           a.nodesWithoutEvidenceCount == b.nodesWithoutEvidenceCount &&
           a.coverage.requestedBegin == b.coverage.requestedBegin &&
           a.coverage.requestedEnd == b.coverage.requestedEnd &&
           a.coverage.processedBegin == b.coverage.processedBegin &&
           a.coverage.processedEnd == b.coverage.processedEnd &&
           a.coverage.succeeded == b.coverage.succeeded && a.coverage.failed == b.coverage.failed &&
           a.coverage.skipped == b.coverage.skipped &&
           a.coverage.truncated == b.coverage.truncated &&
           a.coverage.limitHit == b.coverage.limitHit &&
           a.coverage.cancelled == b.coverage.cancelled &&
           a.coverage.limit == b.coverage.limit && a.coverage.totalKnown == b.coverage.totalKnown &&
           a.limitationKeys == b.limitationKeys;
}

GraphConclusion summarizeGraph(const EntityGraph& graph, const EdgeFilter& filter) {
    GraphConclusion conclusion;
    conclusion.nodeCount = static_cast<std::uint64_t>(graph.nodeCount());
    conclusion.edgeCountBeforeFilter = static_cast<std::uint64_t>(graph.edgeCount());

    for (const GraphEdge& edge : graph.edges()) {
        if (!edgeMatchesFilter(edge, filter)) {
            continue;
        }
        ++conclusion.edgeCountAfterFilter;
        switch (edge.certainty) {
        case EdgeCertainty::kConfirmed: ++conclusion.confirmedEdgeCount; break;
        case EdgeCertainty::kCandidate: ++conclusion.candidateEdgeCount; break;
        case EdgeCertainty::kUnknown:   ++conclusion.unknownCertaintyEdgeCount; break;
        }
    }

    for (const GraphNode& node : graph.nodes()) {
        if (node.identity.strength() == IdentityStrength::kUnusable) {
            ++conclusion.unusableIdentityNodeCount;
        }
        if (!node.evidenceOpenable()) {
            ++conclusion.nodesWithoutEvidenceCount;
        }
        const IsolationReport kReport = classifyIsolation(graph, node.nodeId, filter);
        if (!kReport.isolated) {
            continue;
        }
        ++conclusion.isolatedNodeCount;
        switch (kReport.state) {
        case IsolationState::kOwnerMissing:          ++conclusion.ownerMissingCount; break;
        case IsolationState::kObjectUnloaded:        ++conclusion.unloadedCount; break;
        case IsolationState::kSourceNotCollected:    ++conclusion.sourceNotCollectedCount; break;
        case IsolationState::kObservedInconsistency: ++conclusion.inconsistencyCount; break;
        case IsolationState::kNotIsolated:           break;
        }
    }

    conclusion.coverage = graph.envelope().coverage;
    // F-05: Without observation, one cannot conclude 'no differences found'. The difference flag is driven solely by
    // **observed inconsistencies**; 'isolated' nodes and 'missing owner' are not differences, nor are they risks (G-05).
    conclusion.conclusion = graph.envelope().deriveConclusion(conclusion.inconsistencyCount > 0);

    if (conclusion.unusableIdentityNodeCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.unusableIdentityNodes");
    }
    if (conclusion.nodesWithoutEvidenceCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.nodesWithoutEvidence");
    }
    if (conclusion.unknownCertaintyEdgeCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.unknownCertaintyEdges");
    }
    if (conclusion.isolatedNodeCount > 0) {
        conclusion.limitationKeys.emplace_back("graph.summary.isolatedNodes");
    }
    if (!conclusion.coverage.fullyCovered()) {
        conclusion.limitationKeys.emplace_back("graph.summary.coverageIncomplete");
    }
    if (!filter.kinds.empty() || !filter.certainties.empty() || filter.atUtc100ns.present) {
        conclusion.limitationKeys.emplace_back("graph.summary.filterApplied");
    }
    sortUnique(conclusion.limitationKeys);
    return conclusion;
}

namespace {

JsonValue stringArray(const std::vector<std::string>& values) {
    JsonArray array;
    array.reserve(values.size());
    for (const std::string& value : values) {
        array.push_back(JsonValue::makeString(value));
    }
    return JsonValue::makeArray(std::move(array));
}

// ---------------------------------------------------------------------------
// Read-back utility. Missing fields always fall back to the field's **default value**: default is not
// equivalent to complete; items not written in the export must not be filled in as "normal" during import.
// ---------------------------------------------------------------------------
const JsonValue* child(const JsonValue& object, const char* name) noexcept {
    return object.find(name);
}

std::string readString(const JsonValue& object, const char* name) {
    const JsonValue* value = object.find(name);
    std::string out;
    if (value != nullptr && value->tryGetString(out)) {
        return out;
    }
    return std::string();
}

bool readBool(const JsonValue& object, const char* name) noexcept {
    const JsonValue* value = object.find(name);
    bool out = false;
    if (value != nullptr && value->tryGetBool(out)) {
        return out;
    }
    return false;
}

std::uint64_t readU64(const JsonValue& object, const char* name) noexcept {
    const JsonValue* value = object.find(name);
    std::uint64_t out = 0;
    if (value != nullptr && value->tryGetU64(out)) {
        return out;
    }
    return 0;
}

OptionalU64 readOptionalU64(const JsonValue& object, const char* name) noexcept {
    const JsonValue* value = object.find(name);
    OptionalU64 out;
    if (value != nullptr && value->tryGetOptionalU64(out)) {
        return out;
    }
    return OptionalU64::unset();
}

std::vector<std::string> readStringArray(const JsonValue& object, const char* name) {
    std::vector<std::string> out;
    const JsonValue* value = object.find(name);
    if (value == nullptr) {
        return out;
    }
    const JsonArray* array = value->asArray();
    if (array == nullptr) {
        return out;
    }
    out.reserve(array->size());
    for (const JsonValue& entry : *array) {
        std::string text;
        if (entry.tryGetString(text)) {
            out.push_back(std::move(text));
        }
    }
    return out;
}

// All enum back-reads use the same *Name() lookup; the name is defined in only one place, so exports and imports do not write independently.
ObjectKind parseObjectKind(const std::string& text) noexcept {
    static constexpr ObjectKind kAll[] = {
        ObjectKind::kUnknown, ObjectKind::kProcess, ObjectKind::kThread,   ObjectKind::kDriver,
        ObjectKind::kModule,  ObjectKind::kFile,    ObjectKind::kHandle,   ObjectKind::kConnection,
        ObjectKind::kDevice,  ObjectKind::kService,
    };
    for (const ObjectKind kKind : kAll) {
        if (text == objectKindName(kKind)) {
            return kKind;
        }
    }
    return ObjectKind::kUnknown;
}

NodeCategory parseNodeCategory(const std::string& text) noexcept {
    static constexpr NodeCategory kAll[] = {
        NodeCategory::kSystemObject, NodeCategory::kTimelineEntry, NodeCategory::kEvidenceRecord,
    };
    for (const NodeCategory kCategory : kAll) {
        if (text == nodeCategoryName(kCategory)) {
            return kCategory;
        }
    }
    return NodeCategory::kSystemObject;
}

NodeLifecycle parseNodeLifecycle(const std::string& text) noexcept {
    static constexpr NodeLifecycle kAll[] = {
        NodeLifecycle::kUnknown, NodeLifecycle::kObserved, NodeLifecycle::kEnded,
    };
    for (const NodeLifecycle kLifecycle : kAll) {
        if (text == nodeLifecycleName(kLifecycle)) {
            return kLifecycle;
        }
    }
    return NodeLifecycle::kUnknown;
}

EdgeKind parseEdgeKind(const std::string& text) noexcept {
    static constexpr EdgeKind kAll[] = {
        EdgeKind::kUnknown,  EdgeKind::kOwns,             EdgeKind::kLoads,
        EdgeKind::kMaps,     EdgeKind::kOpens,            EdgeKind::kCandidateOwner,
        EdgeKind::kTemporalNeighbor, EdgeKind::kDeviceOf, EdgeKind::kImageOf,
        EdgeKind::kServiceOf, EdgeKind::kTimelineEntry,
    };
    for (const EdgeKind kKind : kAll) {
        if (text == edgeKindName(kKind)) {
            return kKind;
        }
    }
    return EdgeKind::kUnknown;
}

EdgeDirection parseEdgeDirection(const std::string& text) noexcept {
    static constexpr EdgeDirection kAll[] = {
        EdgeDirection::kUnknown, EdgeDirection::kFromTo, EdgeDirection::kSymmetric,
    };
    for (const EdgeDirection kDirection : kAll) {
        if (text == edgeDirectionName(kDirection)) {
            return kDirection;
        }
    }
    return EdgeDirection::kUnknown;
}

EdgeCertainty parseEdgeCertainty(const std::string& text) noexcept {
    static constexpr EdgeCertainty kAll[] = {
        EdgeCertainty::kUnknown, EdgeCertainty::kCandidate, EdgeCertainty::kConfirmed,
    };
    for (const EdgeCertainty kCertainty : kAll) {
        if (text == edgeCertaintyName(kCertainty)) {
            return kCertainty;
        }
    }
    return EdgeCertainty::kUnknown;
}

CollectionStatus parseCollectionStatus(const std::string& text) noexcept {
    static constexpr CollectionStatus kAll[] = {
        CollectionStatus::kNotCollected, CollectionStatus::kSuccess,      CollectionStatus::kPartial,
        CollectionStatus::kUnsupported,  CollectionStatus::kAccessDenied, CollectionStatus::kTimeout,
        CollectionStatus::kError,
    };
    for (const CollectionStatus kStatus : kAll) {
        if (text == collectionStatusName(kStatus)) {
            return kStatus;
        }
    }
    return CollectionStatus::kNotCollected;
}

SourceOrigin parseSourceOrigin(const std::string& text) noexcept {
    static constexpr SourceOrigin kAll[] = {
        SourceOrigin::kUnknown,      SourceOrigin::kLiveKernel,   SourceOrigin::kLiveUserMode,
        SourceOrigin::kExternalFile, SourceOrigin::kOfflineSample,
    };
    for (const SourceOrigin kOrigin : kAll) {
        if (text == sourceOriginName(kOrigin)) {
            return kOrigin;
        }
    }
    return SourceOrigin::kUnknown;
}

CaptureMode parseCaptureMode(const std::string& text) noexcept {
    static constexpr CaptureMode kAll[] = {
        CaptureMode::kUnknown, CaptureMode::kSnapshot, CaptureMode::kStreaming, CaptureMode::kReplay,
    };
    for (const CaptureMode kMode : kAll) {
        if (text == captureModeName(kMode)) {
            return kMode;
        }
    }
    return CaptureMode::kUnknown;
}

// DataOrigin lacks a name function in ScanBudget.h; this provides a pair of string literals here for shared read/write usage.
const char* dataOriginText(DataOrigin origin) noexcept {
    return origin == DataOrigin::kSession ? "Session" : "Live";
}

DataOrigin parseDataOrigin(const std::string& text) noexcept {
    // Only "Live" counts as live data; anything unrecognized is treated as session data to avoid missing coverage refreshes.
    return text == "Live" ? DataOrigin::kLive : DataOrigin::kSession;
}

JsonValue coverageToJson(const CoverageAccount& coverage) {
    JsonObject object;
    object.emplace_back("requestedBegin",
                        JsonValue::makeOptionalU64Text(coverage.requestedBegin, U64Format::kDecimal));
    object.emplace_back("requestedEnd",
                        JsonValue::makeOptionalU64Text(coverage.requestedEnd, U64Format::kDecimal));
    object.emplace_back("processedBegin",
                        JsonValue::makeOptionalU64Text(coverage.processedBegin, U64Format::kDecimal));
    object.emplace_back("processedEnd",
                        JsonValue::makeOptionalU64Text(coverage.processedEnd, U64Format::kDecimal));
    object.emplace_back("succeeded", JsonValue::makeU64Text(coverage.succeeded, U64Format::kDecimal));
    object.emplace_back("failed", JsonValue::makeU64Text(coverage.failed, U64Format::kDecimal));
    object.emplace_back("skipped", JsonValue::makeU64Text(coverage.skipped, U64Format::kDecimal));
    object.emplace_back("truncated", JsonValue::makeU64Text(coverage.truncated, U64Format::kDecimal));
    object.emplace_back("limitHit", JsonValue::makeBool(coverage.limitHit));
    object.emplace_back("cancelled", JsonValue::makeBool(coverage.cancelled));
    object.emplace_back("limit",
                        JsonValue::makeOptionalU64Text(coverage.limit, U64Format::kDecimal));
    object.emplace_back("totalKnown",
                        JsonValue::makeOptionalU64Text(coverage.totalKnown, U64Format::kDecimal));
    object.emplace_back("fullyCovered", JsonValue::makeBool(coverage.fullyCovered()));
    object.emplace_back("remaining", JsonValue::makeString(coverage.describeRemaining()));
    return JsonValue::makeObject(std::move(object));
}

// fullyCovered and remaining are derived display fields calculated from other fields and are always ignored on read: the
// account's true value exists in only one place; a boolean in the export file must never redefine whether coverage is complete.
CoverageAccount coverageFromJson(const JsonValue* value) {
    CoverageAccount coverage;
    if (value == nullptr) {
        return coverage;
    }
    coverage.requestedBegin = readOptionalU64(*value, "requestedBegin");
    coverage.requestedEnd = readOptionalU64(*value, "requestedEnd");
    coverage.processedBegin = readOptionalU64(*value, "processedBegin");
    coverage.processedEnd = readOptionalU64(*value, "processedEnd");
    coverage.succeeded = readU64(*value, "succeeded");
    coverage.failed = readU64(*value, "failed");
    coverage.skipped = readU64(*value, "skipped");
    coverage.truncated = readU64(*value, "truncated");
    coverage.limitHit = readBool(*value, "limitHit");
    coverage.cancelled = readBool(*value, "cancelled");
    coverage.limit = readOptionalU64(*value, "limit");
    coverage.totalKnown = readOptionalU64(*value, "totalKnown");
    return coverage;
}

JsonValue outcomeToJson(const CollectionOutcome& outcome) {
    JsonObject object;
    object.emplace_back("status", JsonValue::makeString(collectionStatusName(outcome.status)));
    object.emplace_back("nativeCodeDomain", JsonValue::makeString(outcome.nativeCodeDomain));
    object.emplace_back("nativeCode",
                        JsonValue::makeOptionalU64Text(outcome.nativeCode, U64Format::kDecimal));
    object.emplace_back("message", JsonValue::makeString(outcome.message));
    return JsonValue::makeObject(std::move(object));
}

CollectionOutcome outcomeFromJson(const JsonValue* value) {
    CollectionOutcome outcome;  // Default: NotCollected
    if (value == nullptr) {
        return outcome;
    }
    outcome.status = parseCollectionStatus(readString(*value, "status"));
    outcome.nativeCodeDomain = readString(*value, "nativeCodeDomain");
    outcome.nativeCode = readOptionalU64(*value, "nativeCode");
    outcome.message = readString(*value, "message");
    return outcome;
}

// ---------------------------------------------------------------------------
// G-06: identity payload. Omitting one field causes the object to assume a different identity strength in a restarted session.
// ---------------------------------------------------------------------------
JsonValue processToJson(const ProcessInstanceId& id) {
    JsonObject object;
    object.emplace_back("bootId", JsonValue::makeString(id.bootId));
    object.emplace_back("pid", JsonValue::makeOptionalU64Text(id.pid, U64Format::kDecimal));
    object.emplace_back("createTime100ns",
                        JsonValue::makeOptionalU64Text(id.createTime100ns, U64Format::kDecimal));
    object.emplace_back("eprocessAddress",
                        JsonValue::makeOptionalU64Text(id.eprocessAddress, U64Format::kHexAddress));
    object.emplace_back("imageName", JsonValue::makeString(id.imageName));
    return JsonValue::makeObject(std::move(object));
}

ProcessInstanceId processFromJson(const JsonValue* value) {
    ProcessInstanceId id;
    if (value == nullptr) {
        return id;
    }
    id.bootId = readString(*value, "bootId");
    id.pid = readOptionalU64(*value, "pid");
    id.createTime100ns = readOptionalU64(*value, "createTime100ns");
    id.eprocessAddress = readOptionalU64(*value, "eprocessAddress");
    id.imageName = readString(*value, "imageName");
    return id;
}

JsonValue identityToJson(const NodeIdentity& identity) {
    JsonObject object;
    object.emplace_back("category", JsonValue::makeString(nodeCategoryName(identity.category)));
    object.emplace_back("kind", JsonValue::makeString(objectKindName(identity.kind)));
    object.emplace_back("bootId", JsonValue::makeString(identity.bootId));
    object.emplace_back("name", JsonValue::makeString(identity.name));
    object.emplace_back("instanceTag", JsonValue::makeString(identity.instanceTag));

    // Write only the portion needed for this kind: nodeKey, crossSessionKey, strength, and
    // matchNodeIdentity are all dispatched by kind; bytes in other slots have no meaning in this module.
    switch (identity.kind) {
    case ObjectKind::kProcess:
        object.emplace_back("process", processToJson(identity.process));
        break;
    case ObjectKind::kThread: {
        JsonObject thread;
        thread.emplace_back("process", processToJson(identity.thread.process));
        thread.emplace_back("tid",
                            JsonValue::makeOptionalU64Text(identity.thread.tid, U64Format::kDecimal));
        thread.emplace_back("createTime100ns",
                            JsonValue::makeOptionalU64Text(identity.thread.createTime100ns,
                                                           U64Format::kDecimal));
        thread.emplace_back("ethreadAddress",
                            JsonValue::makeOptionalU64Text(identity.thread.ethreadAddress,
                                                           U64Format::kHexAddress));
        object.emplace_back("thread", JsonValue::makeObject(std::move(thread)));
        break;
    }
    case ObjectKind::kDriver:
    case ObjectKind::kModule: {
        JsonObject driver;
        driver.emplace_back("bootId", JsonValue::makeString(identity.driver.bootId));
        driver.emplace_back("imagePath", JsonValue::makeString(identity.driver.imagePath));
        driver.emplace_back("imageBase",
                            JsonValue::makeOptionalU64Text(identity.driver.imageBase,
                                                           U64Format::kHexAddress));
        driver.emplace_back("imageSize", JsonValue::makeOptionalU64Text(identity.driver.imageSize,
                                                                       U64Format::kDecimal));
        driver.emplace_back("timeDateStamp",
                            JsonValue::makeOptionalU64Text(identity.driver.timeDateStamp,
                                                           U64Format::kDecimal));
        driver.emplace_back("checksum", JsonValue::makeOptionalU64Text(identity.driver.checksum,
                                                                       U64Format::kDecimal));
        driver.emplace_back("pdbSignature", JsonValue::makeString(identity.driver.pdbSignature));
        driver.emplace_back("loadOrderIndex",
                            JsonValue::makeOptionalU64Text(identity.driver.loadOrderIndex,
                                                           U64Format::kDecimal));
        object.emplace_back("driver", JsonValue::makeObject(std::move(driver)));
        break;
    }
    case ObjectKind::kFile: {
        JsonObject file;
        file.emplace_back("path", JsonValue::makeString(identity.file.path));
        file.emplace_back("volumeSerial",
                          JsonValue::makeOptionalU64Text(identity.file.volumeSerial,
                                                         U64Format::kDecimal));
        file.emplace_back("fileId", JsonValue::makeString(identity.file.fileId));
        file.emplace_back("sizeBytes", JsonValue::makeOptionalU64Text(identity.file.sizeBytes,
                                                                     U64Format::kDecimal));
        file.emplace_back("lastWriteUtc100ns",
                          JsonValue::makeOptionalU64Text(identity.file.lastWriteUtc100ns,
                                                         U64Format::kDecimal));
        file.emplace_back("contentHash", JsonValue::makeString(identity.file.contentHash));
        object.emplace_back("file", JsonValue::makeObject(std::move(file)));
        break;
    }
    case ObjectKind::kHandle: {
        JsonObject handle;
        handle.emplace_back("owner", processToJson(identity.handle.owner));
        handle.emplace_back("handleValue",
                            JsonValue::makeOptionalU64Text(identity.handle.handleValue,
                                                           U64Format::kDecimal));
        handle.emplace_back("objectAddress",
                            JsonValue::makeOptionalU64Text(identity.handle.objectAddress,
                                                           U64Format::kHexAddress));
        handle.emplace_back("typeName", JsonValue::makeString(identity.handle.typeName));
        object.emplace_back("handle", JsonValue::makeObject(std::move(handle)));
        break;
    }
    case ObjectKind::kConnection: {
        JsonObject connection;
        connection.emplace_back("bootId", JsonValue::makeString(identity.connection.bootId));
        connection.emplace_back("protocol",
                                JsonValue::makeU64Text(identity.connection.protocol,
                                                       U64Format::kDecimal));
        connection.emplace_back("localAddress",
                                JsonValue::makeString(identity.connection.localAddress));
        connection.emplace_back("localPort",
                                JsonValue::makeU64Text(identity.connection.localPort,
                                                       U64Format::kDecimal));
        connection.emplace_back("remoteAddress",
                                JsonValue::makeString(identity.connection.remoteAddress));
        connection.emplace_back("remotePort",
                                JsonValue::makeU64Text(identity.connection.remotePort,
                                                       U64Format::kDecimal));
        connection.emplace_back("observedFirstUtc100ns",
                                JsonValue::makeOptionalU64Text(
                                    identity.connection.observedFirstUtc100ns, U64Format::kDecimal));
        connection.emplace_back("observedLastUtc100ns",
                                JsonValue::makeOptionalU64Text(
                                    identity.connection.observedLastUtc100ns, U64Format::kDecimal));
        connection.emplace_back("owner", processToJson(identity.connection.owner));
        object.emplace_back("connection", JsonValue::makeObject(std::move(connection)));
        break;
    }
    case ObjectKind::kDevice:
    case ObjectKind::kService:
    case ObjectKind::kUnknown:
        // The complete identity of these three classes consists of the three text fields above (F-03 does not define a lifecycle identity for them).
        break;
    }
    return JsonValue::makeObject(std::move(object));
}

NodeIdentity identityFromJson(const JsonValue* value) {
    NodeIdentity identity;
    if (value == nullptr) {
        return identity;
    }
    identity.category = parseNodeCategory(readString(*value, "category"));
    identity.kind = parseObjectKind(readString(*value, "kind"));
    identity.bootId = readString(*value, "bootId");
    identity.name = readString(*value, "name");
    identity.instanceTag = readString(*value, "instanceTag");

    switch (identity.kind) {
    case ObjectKind::kProcess:
        identity.process = processFromJson(child(*value, "process"));
        break;
    case ObjectKind::kThread: {
        const JsonValue* thread = child(*value, "thread");
        if (thread != nullptr) {
            identity.thread.process = processFromJson(child(*thread, "process"));
            identity.thread.tid = readOptionalU64(*thread, "tid");
            identity.thread.createTime100ns = readOptionalU64(*thread, "createTime100ns");
            identity.thread.ethreadAddress = readOptionalU64(*thread, "ethreadAddress");
        }
        break;
    }
    case ObjectKind::kDriver:
    case ObjectKind::kModule: {
        const JsonValue* driver = child(*value, "driver");
        if (driver != nullptr) {
            identity.driver.bootId = readString(*driver, "bootId");
            identity.driver.imagePath = readString(*driver, "imagePath");
            identity.driver.imageBase = readOptionalU64(*driver, "imageBase");
            identity.driver.imageSize = readOptionalU64(*driver, "imageSize");
            identity.driver.timeDateStamp = readOptionalU64(*driver, "timeDateStamp");
            identity.driver.checksum = readOptionalU64(*driver, "checksum");
            identity.driver.pdbSignature = readString(*driver, "pdbSignature");
            identity.driver.loadOrderIndex = readOptionalU64(*driver, "loadOrderIndex");
        }
        break;
    }
    case ObjectKind::kFile: {
        const JsonValue* file = child(*value, "file");
        if (file != nullptr) {
            identity.file.path = readString(*file, "path");
            identity.file.volumeSerial = readOptionalU64(*file, "volumeSerial");
            identity.file.fileId = readString(*file, "fileId");
            identity.file.sizeBytes = readOptionalU64(*file, "sizeBytes");
            identity.file.lastWriteUtc100ns = readOptionalU64(*file, "lastWriteUtc100ns");
            identity.file.contentHash = readString(*file, "contentHash");
        }
        break;
    }
    case ObjectKind::kHandle: {
        const JsonValue* handle = child(*value, "handle");
        if (handle != nullptr) {
            identity.handle.owner = processFromJson(child(*handle, "owner"));
            identity.handle.handleValue = readOptionalU64(*handle, "handleValue");
            identity.handle.objectAddress = readOptionalU64(*handle, "objectAddress");
            identity.handle.typeName = readString(*handle, "typeName");
        }
        break;
    }
    case ObjectKind::kConnection: {
        const JsonValue* connection = child(*value, "connection");
        if (connection != nullptr) {
            identity.connection.bootId = readString(*connection, "bootId");
            identity.connection.protocol =
                static_cast<std::uint32_t>(readU64(*connection, "protocol"));
            identity.connection.localAddress = readString(*connection, "localAddress");
            identity.connection.localPort =
                static_cast<std::uint16_t>(readU64(*connection, "localPort"));
            identity.connection.remoteAddress = readString(*connection, "remoteAddress");
            identity.connection.remotePort =
                static_cast<std::uint16_t>(readU64(*connection, "remotePort"));
            identity.connection.observedFirstUtc100ns =
                readOptionalU64(*connection, "observedFirstUtc100ns");
            identity.connection.observedLastUtc100ns =
                readOptionalU64(*connection, "observedLastUtc100ns");
            identity.connection.owner = processFromJson(child(*connection, "owner"));
        }
        break;
    }
    case ObjectKind::kDevice:
    case ObjectKind::kService:
    case ObjectKind::kUnknown:
        break;
    }
    return identity;
}

JsonValue envelopeToJson(const EvidenceEnvelope& envelope) {
    JsonObject source;
    source.emplace_back("collectorId", JsonValue::makeString(envelope.source.collectorId));
    source.emplace_back("collectorVersion",
                        JsonValue::makeU64Text(envelope.source.collectorVersion,
                                               U64Format::kDecimal));
    source.emplace_back("sourceGroup", JsonValue::makeString(envelope.source.sourceGroup));
    source.emplace_back("origin", JsonValue::makeString(sourceOriginName(envelope.source.origin)));
    source.emplace_back("dependsOn", JsonValue::makeString(envelope.source.dependsOn));

    JsonObject window;
    window.emplace_back("startUtc100ns",
                        JsonValue::makeOptionalU64Text(envelope.window.startUtc100ns,
                                                       U64Format::kDecimal));
    window.emplace_back("endUtc100ns",
                        JsonValue::makeOptionalU64Text(envelope.window.endUtc100ns,
                                                       U64Format::kDecimal));
    window.emplace_back("startMonotonic",
                        JsonValue::makeOptionalU64Text(envelope.window.startMonotonic,
                                                       U64Format::kDecimal));
    window.emplace_back("endMonotonic",
                        JsonValue::makeOptionalU64Text(envelope.window.endMonotonic,
                                                       U64Format::kDecimal));
    window.emplace_back("monotonicFrequency",
                        JsonValue::makeOptionalU64Text(envelope.window.monotonicFrequency,
                                                       U64Format::kDecimal));
    window.emplace_back("machineId", JsonValue::makeString(envelope.window.machineId));
    window.emplace_back("bootId", JsonValue::makeString(envelope.window.bootId));
    window.emplace_back("sessionId", JsonValue::makeString(envelope.window.sessionId));
    window.emplace_back("mode", JsonValue::makeString(captureModeName(envelope.window.mode)));

    JsonObject object;
    object.emplace_back("evidenceId", JsonValue::makeString(envelope.evidenceId));
    object.emplace_back("source", JsonValue::makeObject(std::move(source)));
    object.emplace_back("window", JsonValue::makeObject(std::move(window)));
    object.emplace_back("outcome", outcomeToJson(envelope.outcome));
    object.emplace_back("coverage", coverageToJson(envelope.coverage));
    return JsonValue::makeObject(std::move(object));
}

EvidenceEnvelope envelopeFromJson(const JsonValue* value) {
    EvidenceEnvelope envelope;  // The default outcome is NotCollected.
    if (value == nullptr) {
        return envelope;
    }
    envelope.evidenceId = readString(*value, "evidenceId");
    const JsonValue* source = child(*value, "source");
    if (source != nullptr) {
        envelope.source.collectorId = readString(*source, "collectorId");
        envelope.source.collectorVersion =
            static_cast<std::uint32_t>(readU64(*source, "collectorVersion"));
        envelope.source.sourceGroup = readString(*source, "sourceGroup");
        envelope.source.origin = parseSourceOrigin(readString(*source, "origin"));
        envelope.source.dependsOn = readString(*source, "dependsOn");
    }
    const JsonValue* window = child(*value, "window");
    if (window != nullptr) {
        envelope.window.startUtc100ns = readOptionalU64(*window, "startUtc100ns");
        envelope.window.endUtc100ns = readOptionalU64(*window, "endUtc100ns");
        envelope.window.startMonotonic = readOptionalU64(*window, "startMonotonic");
        envelope.window.endMonotonic = readOptionalU64(*window, "endMonotonic");
        envelope.window.monotonicFrequency = readOptionalU64(*window, "monotonicFrequency");
        envelope.window.machineId = readString(*window, "machineId");
        envelope.window.bootId = readString(*window, "bootId");
        envelope.window.sessionId = readString(*window, "sessionId");
        envelope.window.mode = parseCaptureMode(readString(*window, "mode"));
    }
    envelope.outcome = outcomeFromJson(child(*value, "outcome"));
    envelope.coverage = coverageFromJson(child(*value, "coverage"));
    return envelope;
}

} // namespace

JsonValue exportGraph(const EntityGraph& graph,
                      const ExpansionResult& expansion,
                      const EdgeFilter& filter) {
    // Calculate nodes and edges first, because the count of 'present in view but absent in graph' entries must be recorded in the view's ledger.
    std::vector<std::string> nodeIds = expansion.nodeIds;
    std::sort(nodeIds.begin(), nodeIds.end());
    JsonArray nodes;
    JsonArray isolation;
    std::uint64_t missingNodes = 0;
    for (const std::string& nodeId : nodeIds) {
        std::size_t index = 0;
        if (!graph.nodeIndexOf(nodeId, index)) {
            // The view references an ID not present in the graph. Skipping is acceptable, but it must be recorded and reported: if
            // the export claims loadedNodes=2 yet contains only 1 node and the ID cannot be found anywhere, it is a contradiction.
            ++missingNodes;
            continue;
        }
        const GraphNode& node = graph.nodes()[index];
        JsonObject object;
        object.emplace_back("nodeId", JsonValue::makeString(node.nodeId));
        object.emplace_back("category",
                            JsonValue::makeString(nodeCategoryName(node.identity.category)));
        object.emplace_back("kind", JsonValue::makeString(objectKindName(node.identity.kind)));
        object.emplace_back("displayText", JsonValue::makeString(node.displayText));
        object.emplace_back("evidenceId", JsonValue::makeString(node.evidenceId));
        object.emplace_back("identityStrength",
                            JsonValue::makeString(identityStrengthName(node.identity.strength())));
        object.emplace_back("crossSessionKey",
                            JsonValue::makeString(node.identity.crossSessionKey()));
        object.emplace_back("lifecycle", JsonValue::makeString(nodeLifecycleName(node.lifecycle)));
        object.emplace_back("objectNavigable", JsonValue::makeBool(node.objectNavigable()));
        object.emplace_back("evidenceOpenable", JsonValue::makeBool(node.evidenceOpenable()));
        // G-05: The relationship type that "should" connect this node to its owner. If not written out, in a reopened session
        // every node reverts to EdgeKind::Unknown, causing all isolation criteria to collapse into "source not collected".
        object.emplace_back("ownerRelation", JsonValue::makeString(edgeKindName(node.ownerRelation)));
        object.emplace_back("ownerKind", JsonValue::makeString(objectKindName(node.ownerKind)));
        object.emplace_back("outcome", outcomeToJson(node.outcome));
        object.emplace_back("inconsistencyObserved",
                            JsonValue::makeBool(node.inconsistencyObserved));
        object.emplace_back("inconsistencyEvidenceIds",
                            stringArray(node.inconsistencyEvidenceIds));
        // Identity payload is placed last: it is the sole basis for re-establishing a session. The preceding items
        // (identityStrength, crossSessionKey, objectNavigable) are merely derived display values calculated from it.
        object.emplace_back("identity", identityToJson(node.identity));
        nodes.push_back(JsonValue::makeObject(std::move(object)));

        const IsolationReport kReport = classifyIsolation(graph, nodeId, filter);
        JsonObject isolationObject;
        isolationObject.emplace_back("nodeId", JsonValue::makeString(kReport.nodeId));
        isolationObject.emplace_back("isolated", JsonValue::makeBool(kReport.isolated));
        // The key is "state" rather than "cause": this describes the observed data state (presence of edges, source
        // collection status, object existence), not a causal or property judgment on any behavior. The export is an artifact
        // for reports and downstream consumers; the terminology seen by readers must match the contract in the header file.
        isolationObject.emplace_back("state",
                                     JsonValue::makeString(isolationStateName(kReport.state)));
        isolationObject.emplace_back("explanationKey",
                                     JsonValue::makeString(kReport.explanationKey));
        isolationObject.emplace_back("rawEvidenceAvailable",
                                     JsonValue::makeBool(kReport.rawEvidenceAvailable));
        isolationObject.emplace_back("rawEvidenceMissingKey",
                                     JsonValue::makeString(kReport.rawEvidenceMissingKey));
        isolationObject.emplace_back("ownerLookupOutcome",
                                     outcomeToJson(kReport.ownerLookupOutcome));
        isolation.push_back(JsonValue::makeObject(std::move(isolationObject)));
    }

    std::vector<std::string> edgeIds = expansion.edgeIds;
    std::sort(edgeIds.begin(), edgeIds.end());
    JsonArray edges;
    std::uint64_t missingEdges = 0;
    for (const std::string& edgeId : edgeIds) {
        const GraphEdge* edge = graph.findEdge(edgeId);
        if (edge == nullptr) {
            ++missingEdges;
            continue;
        }
        const EdgeInferenceNote kNote = describeEdgeInference(*edge);
        JsonObject object;
        object.emplace_back("edgeId", JsonValue::makeString(edge->edgeId));
        object.emplace_back("kind", JsonValue::makeString(edgeKindName(edge->kind)));
        object.emplace_back("direction",
                            JsonValue::makeString(edgeDirectionName(edge->direction)));
        object.emplace_back("from", JsonValue::makeString(edge->fromNodeId));
        object.emplace_back("to", JsonValue::makeString(edge->toNodeId));
        object.emplace_back("validFrom100ns", JsonValue::makeOptionalU64Text(edge->validFrom100ns,
                                                                            U64Format::kDecimal));
        object.emplace_back("validTo100ns", JsonValue::makeOptionalU64Text(edge->validTo100ns,
                                                                          U64Format::kDecimal));
        object.emplace_back("certainty",
                            JsonValue::makeString(edgeCertaintyName(edge->certainty)));
        object.emplace_back("evidenceRefs", stringArray(kNote.evidenceRefs));
        object.emplace_back("ruleId", JsonValue::makeString(edge->ruleId));
        object.emplace_back("ruleDescriptionKey",
                            JsonValue::makeString(edge->ruleDescriptionKey));
        object.emplace_back("notConfirmedReasonKey",
                            JsonValue::makeString(kNote.notConfirmedReasonKey));
        object.emplace_back("sourceGroup", JsonValue::makeString(edge->sourceGroup));
        edges.push_back(JsonValue::makeObject(std::move(object)));
    }

    std::vector<std::string> viewLimitations = expansion.limitationKeys;
    if (missingNodes > 0) {
        viewLimitations.emplace_back("graph.export.viewNodeMissing");
    }
    if (missingEdges > 0) {
        viewLimitations.emplace_back("graph.export.viewEdgeMissing");
    }
    sortUnique(viewLimitations);

    JsonObject root;
    root.emplace_back("schema", JsonValue::makeString(kEntityGraphSchema));

    // Export has two scopes; they must be explicitly defined, otherwise readers may mistake view counts for the full set count (G-04).
    JsonObject scope;
    scope.emplace_back("viewIsExpansionResult", JsonValue::makeBool(true));
    scope.emplace_back("conclusionIsWholeSavedGraph", JsonValue::makeBool(true));
    root.emplace_back("scope", JsonValue::makeObject(std::move(scope)));

    JsonObject view;
    view.emplace_back("loadedNodes",
                      JsonValue::makeU64Text(expansion.loadedNodes, U64Format::kDecimal));
    view.emplace_back("loadedEdges",
                      JsonValue::makeU64Text(expansion.loadedEdges, U64Format::kDecimal));
    // Report actual written count and skipped count separately: when the two numbers don't
    // match, the reader must immediately see the discrepancy rather than counting array lengths.
    view.emplace_back("exportedNodes",
                      JsonValue::makeU64Text(static_cast<std::uint64_t>(nodes.size()),
                                             U64Format::kDecimal));
    view.emplace_back("exportedEdges",
                      JsonValue::makeU64Text(static_cast<std::uint64_t>(edges.size()),
                                             U64Format::kDecimal));
    view.emplace_back("viewNodeMissing", JsonValue::makeU64Text(missingNodes, U64Format::kDecimal));
    view.emplace_back("viewEdgeMissing", JsonValue::makeU64Text(missingEdges, U64Format::kDecimal));
    view.emplace_back("moreAvailable", JsonValue::makeBool(expansion.moreAvailable));
    view.emplace_back("totalKnownNodes", JsonValue::makeOptionalU64Text(expansion.totalKnownNodes,
                                                                       U64Format::kDecimal));
    view.emplace_back("totalKnownEdges", JsonValue::makeOptionalU64Text(expansion.totalKnownEdges,
                                                                       U64Format::kDecimal));
    view.emplace_back("nodeLimitHit", JsonValue::makeBool(expansion.nodeLimitHit));
    view.emplace_back("edgeLimitHit", JsonValue::makeBool(expansion.edgeLimitHit));
    view.emplace_back("hopLimitHit", JsonValue::makeBool(expansion.hopLimitHit));
    view.emplace_back("limitsClampedToDefault",
                      JsonValue::makeBool(expansion.limitsClampedToDefault));
    view.emplace_back("hopsClampedToDefault", JsonValue::makeBool(expansion.hopsClampedToDefault));
    view.emplace_back("filteredEdgeCount",
                      JsonValue::makeU64Text(expansion.filteredEdgeCount, U64Format::kDecimal));
    view.emplace_back("liveQueriesIssued",
                      JsonValue::makeU64Text(expansion.liveQueriesIssued, U64Format::kDecimal));
    view.emplace_back("coverage", coverageToJson(expansion.coverage));
    view.emplace_back("limitationKeys", stringArray(viewLimitations));
    root.emplace_back("view", JsonValue::makeObject(std::move(view)));

    const GraphConclusion kConclusion = summarizeGraph(graph, filter);
    JsonObject summary;
    summary.emplace_back("conclusion",
                         JsonValue::makeString(analysisConclusionName(kConclusion.conclusion)));
    summary.emplace_back("nodeCount",
                         JsonValue::makeU64Text(kConclusion.nodeCount, U64Format::kDecimal));
    summary.emplace_back("edgeCountBeforeFilter",
                         JsonValue::makeU64Text(kConclusion.edgeCountBeforeFilter, U64Format::kDecimal));
    summary.emplace_back("edgeCountAfterFilter",
                         JsonValue::makeU64Text(kConclusion.edgeCountAfterFilter, U64Format::kDecimal));
    summary.emplace_back("confirmedEdgeCount",
                         JsonValue::makeU64Text(kConclusion.confirmedEdgeCount, U64Format::kDecimal));
    summary.emplace_back("candidateEdgeCount",
                         JsonValue::makeU64Text(kConclusion.candidateEdgeCount, U64Format::kDecimal));
    summary.emplace_back("unknownCertaintyEdgeCount",
                         JsonValue::makeU64Text(kConclusion.unknownCertaintyEdgeCount,
                                                U64Format::kDecimal));
    summary.emplace_back("isolatedNodeCount",
                         JsonValue::makeU64Text(kConclusion.isolatedNodeCount, U64Format::kDecimal));
    summary.emplace_back("ownerMissingCount",
                         JsonValue::makeU64Text(kConclusion.ownerMissingCount, U64Format::kDecimal));
    summary.emplace_back("unloadedCount",
                         JsonValue::makeU64Text(kConclusion.unloadedCount, U64Format::kDecimal));
    summary.emplace_back("sourceNotCollectedCount",
                         JsonValue::makeU64Text(kConclusion.sourceNotCollectedCount,
                                                U64Format::kDecimal));
    summary.emplace_back("inconsistencyCount",
                         JsonValue::makeU64Text(kConclusion.inconsistencyCount, U64Format::kDecimal));
    summary.emplace_back("unusableIdentityNodeCount",
                         JsonValue::makeU64Text(kConclusion.unusableIdentityNodeCount,
                                                U64Format::kDecimal));
    summary.emplace_back("nodesWithoutEvidenceCount",
                         JsonValue::makeU64Text(kConclusion.nodesWithoutEvidenceCount,
                                                U64Format::kDecimal));
    summary.emplace_back("coverage", coverageToJson(kConclusion.coverage));
    summary.emplace_back("limitationKeys", stringArray(kConclusion.limitationKeys));
    root.emplace_back("summary", JsonValue::makeObject(std::move(summary)));

    // G-06: Graph-level evidence envelope. Without it, a reopened session can only return NoEvidence—not
    // because no observations were made, but because the observations were not transferred.
    root.emplace_back("envelope", envelopeToJson(graph.envelope()));

    JsonObject policy;
    policy.emplace_back("allowLiveQueries",
                        JsonValue::makeBool(graph.offlinePolicy().allowLiveQueries));
    policy.emplace_back("origin", JsonValue::makeString(dataOriginText(graph.offlinePolicy().origin)));
    root.emplace_back("offlinePolicy", JsonValue::makeObject(std::move(policy)));

    // G-03 / G-05: relationship coverage declarations. Without them, every chain would fall back from "truly collected
    // and none found" to "not collected at all," causing isolated criteria to collapse into the same bucket.
    JsonArray coverageArray;
    for (const RelationCoverageEntry& entry : graph.declaredRelationCoverages()) {
        JsonObject object;
        object.emplace_back("kind", JsonValue::makeString(edgeKindName(entry.kind)));
        object.emplace_back("targetKind", JsonValue::makeString(objectKindName(entry.targetKind)));
        object.emplace_back("outcome", outcomeToJson(entry.coverage.outcome));
        object.emplace_back("coverage", coverageToJson(entry.coverage.coverage));
        object.emplace_back("evidenceId", JsonValue::makeString(entry.coverage.evidenceId));
        coverageArray.push_back(JsonValue::makeObject(std::move(object)));
    }
    root.emplace_back("relationCoverage", JsonValue::makeArray(std::move(coverageArray)));

    // Nodes and edges are output sorted by ID: changing the input order or the sorting method still results in byte-identical exports (G-08).
    root.emplace_back("nodes", JsonValue::makeArray(std::move(nodes)));
    root.emplace_back("edges", JsonValue::makeArray(std::move(edges)));
    root.emplace_back("isolation", JsonValue::makeArray(std::move(isolation)));

    JsonArray unsaved;
    for (const UnsavedNeighbor& neighbor : expansion.unsavedNeighbors) {
        JsonObject object;
        object.emplace_back("edgeId", JsonValue::makeString(neighbor.edgeId));
        object.emplace_back("missingNodeId", JsonValue::makeString(neighbor.missingNodeId));
        object.emplace_back("relation", JsonValue::makeString(edgeKindName(neighbor.relation)));
        object.emplace_back("state", JsonValue::makeString("NotSaved"));
        unsaved.push_back(JsonValue::makeObject(std::move(object)));
    }
    root.emplace_back("unsavedNeighbors", JsonValue::makeArray(std::move(unsaved)));

    return JsonValue::makeObject(std::move(root));
}

GraphImport importGraph(const JsonValue& document) {
    GraphImport result;
    if (document.asObject() == nullptr) {
        result.limitationKeys.emplace_back("graph.import.notAnObject");
        return result;
    }
    if (readString(document, "schema") != kEntityGraphSchema) {
        // If the schema is unrecognized, do not guess. Using half a graph as a whole graph is far more dangerous than outright rejection.
        result.limitationKeys.emplace_back("graph.import.schemaUnknown");
        return result;
    }
    result.schemaRecognised = true;

    result.graph.setEnvelope(envelopeFromJson(child(document, "envelope")));

    const JsonValue* policy = child(document, "offlinePolicy");
    if (policy != nullptr) {
        OfflineExpansionPolicy imported;
        imported.allowLiveQueries = readBool(*policy, "allowLiveQueries");
        imported.origin = parseDataOrigin(readString(*policy, "origin"));
        result.graph.setOfflinePolicy(imported);
    }

    const JsonValue* coverageValue = child(document, "relationCoverage");
    if (coverageValue != nullptr && coverageValue->asArray() != nullptr) {
        for (const JsonValue& entry : *coverageValue->asArray()) {
            RelationCoverage coverage;
            coverage.outcome = outcomeFromJson(child(entry, "outcome"));
            coverage.coverage = coverageFromJson(child(entry, "coverage"));
            coverage.evidenceId = readString(entry, "evidenceId");
            const bool kAccepted = result.graph.declareRelationCoverage(
                parseEdgeKind(readString(entry, "kind")),
                parseObjectKind(readString(entry, "targetKind")), std::move(coverage));
            if (kAccepted) {
                ++result.coverageAccepted;
            } else {
                ++result.coverageRejected;
            }
        }
    }

    const JsonValue* nodesValue = child(document, "nodes");
    if (nodesValue != nullptr && nodesValue->asArray() != nullptr) {
        for (const JsonValue& entry : *nodesValue->asArray()) {
            GraphNode node;
            node.nodeId = readString(entry, "nodeId");
            node.identity = identityFromJson(child(entry, "identity"));
            node.displayText = readString(entry, "displayText");
            node.evidenceId = readString(entry, "evidenceId");
            node.lifecycle = parseNodeLifecycle(readString(entry, "lifecycle"));
            node.ownerRelation = parseEdgeKind(readString(entry, "ownerRelation"));
            node.ownerKind = parseObjectKind(readString(entry, "ownerKind"));
            node.inconsistencyObserved = readBool(entry, "inconsistencyObserved");
            node.inconsistencyEvidenceIds = readStringArray(entry, "inconsistencyEvidenceIds");
            node.outcome = outcomeFromJson(child(entry, "outcome"));
            if (nodeAdmissionAccepted(result.graph.addNode(std::move(node)))) {
                ++result.nodesAccepted;
            } else {
                ++result.nodesRejected;
            }
        }
    }

    const JsonValue* edgesValue = child(document, "edges");
    if (edgesValue != nullptr && edgesValue->asArray() != nullptr) {
        for (const JsonValue& entry : *edgesValue->asArray()) {
            GraphEdge edge;
            edge.edgeId = readString(entry, "edgeId");
            edge.kind = parseEdgeKind(readString(entry, "kind"));
            edge.direction = parseEdgeDirection(readString(entry, "direction"));
            edge.fromNodeId = readString(entry, "from");
            edge.toNodeId = readString(entry, "to");
            edge.validFrom100ns = readOptionalU64(entry, "validFrom100ns");
            edge.validTo100ns = readOptionalU64(entry, "validTo100ns");
            edge.evidenceRefs = readStringArray(entry, "evidenceRefs");
            edge.certainty = parseEdgeCertainty(readString(entry, "certainty"));
            edge.ruleId = readString(entry, "ruleId");
            edge.ruleDescriptionKey = readString(entry, "ruleDescriptionKey");
            edge.sourceGroup = readString(entry, "sourceGroup");
            if (edgeAdmissionAccepted(result.graph.addEdge(edge))) {
                ++result.edgesAccepted;
            } else {
                ++result.edgesRejected;
            }
        }
    }

    if (result.nodesRejected > 0) {
        result.limitationKeys.emplace_back("graph.import.nodesRejected");
    }
    if (result.edgesRejected > 0) {
        result.limitationKeys.emplace_back("graph.import.edgesRejected");
    }
    if (result.coverageRejected > 0) {
        result.limitationKeys.emplace_back("graph.import.coverageRejected");
    }
    sortUnique(result.limitationKeys);
    return result;
}

} // namespace ksword::evidence

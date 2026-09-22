// Offline automated tests for the G module (entity relationships and cross-page investigation).
//
// Coverage IDs: G-01 G-02 G-03 G-04 G-05 G-06 G-08.
// G-07 (keyboard reachability, theme/language) is a UI manual test item; this file does not claim coverage.
//
// Assertion principles (Q-01 / Q-02):
//   * Expected values are all manually calculated and hardcoded. The performance dataset with 10,000 nodes and 50,000 edges is constructed
//     using fixed offsets {1, 7, 113, 1237, 4999}. The one-hop neighborhood size of 11 and edge count of 10 were calculated on paper, not
//     derived by running the production function and copying the results. The same applies to the full graph expansion of 10000/50000.
//   Never treat the output of a production function as an "other-side" input for comparison. The only case where two calls are compared against each other is
//     G-08 requires "consistent conclusions after shuffling input order," and the absolute values of those two
//     instances are hardcoded in assertions, so silent corruption cannot escape if both sides change together.
//   * Branch coverage: EdgeAdmission (8 values), StepAvailability (9 values), IsolationState (5 values),
//     and LiveNavigationDecision (4 values) all have dedicated test cases, leaving no zero-coverage enums.
//   * Unauthorized fields are blocked at compile time: GraphNode, GraphEdge, and GraphConclusion do not contain them
//     color / layout / size / riskScore / malicious / suspicious / threat / causes
//     Compilation will fail without a static_assert for this type of field.

#include "TestSupport.h"

#include "../../../shared/evidence/EntityGraph.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cwchar>
#include <exception>
#include <locale>
#include <string>
#include <type_traits>
#include <vector>

namespace {

using namespace ksword::evidence;

constexpr const char* kBoot = "boot-G-1";
constexpr const char* kBoot2 = "boot-G-2";

// ---------------------------------------------------------------------------
// G-08: Models must not contain fields with undefined risk implications or fields for unauthorized access checks.
// Member detection: once a field is added back, the static_assert immediately fails to compile.
// ---------------------------------------------------------------------------
#define KSWORD_MEMBER_DETECTOR(DetectorName, MemberName)                                    \
    template <typename T, typename = void>                                                  \
    struct DetectorName : std::false_type {};                                               \
    template <typename T>                                                                   \
    struct DetectorName<T, std::void_t<decltype(std::declval<T&>().MemberName)>>             \
        : std::true_type {}

KSWORD_MEMBER_DETECTOR(HasColor, color);
KSWORD_MEMBER_DETECTOR(HasLayout, layout);
KSWORD_MEMBER_DETECTOR(HasPosition, position);
KSWORD_MEMBER_DETECTOR(HasSize, size);
KSWORD_MEMBER_DETECTOR(HasRadius, radius);
KSWORD_MEMBER_DETECTOR(HasRiskScore, riskScore);
KSWORD_MEMBER_DETECTOR(HasMalicious, malicious);
KSWORD_MEMBER_DETECTOR(HasSuspicious, suspicious);
KSWORD_MEMBER_DETECTOR(HasThreat, threat);
KSWORD_MEMBER_DETECTOR(HasIsRootkit, isRootkit);
KSWORD_MEMBER_DETECTOR(HasCauses, causes);
KSWORD_MEMBER_DETECTOR(HasVerdict, verdict);

#define KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(Type)                                     \
    static_assert(!HasColor<Type>::value, #Type " must not carry a color field");            \
    static_assert(!HasLayout<Type>::value, #Type " must not carry a layout field");          \
    static_assert(!HasPosition<Type>::value, #Type " must not carry a position field");      \
    static_assert(!HasSize<Type>::value, #Type " must not carry a size field");              \
    static_assert(!HasRadius<Type>::value, #Type " must not carry a radius field");          \
    static_assert(!HasRiskScore<Type>::value, #Type " must not carry a riskScore field");    \
    static_assert(!HasMalicious<Type>::value, #Type " must not carry a malicious field");    \
    static_assert(!HasSuspicious<Type>::value, #Type " must not carry a suspicious field");  \
    static_assert(!HasThreat<Type>::value, #Type " must not carry a threat field");          \
    static_assert(!HasIsRootkit<Type>::value, #Type " must not carry an isRootkit field");   \
    static_assert(!HasCauses<Type>::value, #Type " must not carry a causes field");          \
    static_assert(!HasVerdict<Type>::value, #Type " must not carry a verdict field")

KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(GraphNode);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(GraphEdge);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(GraphConclusion);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(IsolationReport);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(EntityListRow);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(ChainStep);
KSWORD_ASSERT_NO_VISUAL_OR_VERDICT_FIELDS(ExpansionResult);

// G-06: Offline expansion uses only saved data, never performs hidden runtime queries. At runtime, the count assertion must be
// 0; under the unconditional implementation writing 0 at the function's end, this always holds. Here, we provide a structural
// proof: expandGraph's parameters are only the graph and the request, with no resolver, callback, or client handle available
// to initiate queries. Adding a query path requires changing this signature, which would cause a compile-time failure here.
static_assert(
    std::is_same_v<decltype(expandGraph),
                   ExpansionResult(const EntityGraph&, const ExpansionRequest&)>,
    "ExpandGraph must take only saved data: no resolver, no callback, no live client");

// ---------------------------------------------------------------------------
// Construction helpers
// ---------------------------------------------------------------------------
NodeIdentity processIdentity(const char* boot, std::uint64_t pid, std::uint64_t createTime,
                             const char* image) {
    NodeIdentity id;
    id.category = NodeCategory::kSystemObject;
    id.kind = ObjectKind::kProcess;
    id.process.bootId = boot;
    id.process.pid = OptionalU64::of(pid);
    id.process.createTime100ns = OptionalU64::of(createTime);
    id.process.imageName = image;
    return id;
}

NodeIdentity weakProcessIdentity(std::uint64_t pid, const char* tag) {
    NodeIdentity id;
    id.category = NodeCategory::kSystemObject;
    id.kind = ObjectKind::kProcess;
    id.process.pid = OptionalU64::of(pid);  // No bootId / no creation time -> Weak
    id.instanceTag = tag;
    return id;
}

NodeIdentity threadIdentity(const char* boot, std::uint64_t pid, std::uint64_t processCreate,
                            std::uint64_t tid, std::uint64_t threadCreate) {
    NodeIdentity id;
    id.kind = ObjectKind::kThread;
    id.thread.process.bootId = boot;
    id.thread.process.pid = OptionalU64::of(pid);
    id.thread.process.createTime100ns = OptionalU64::of(processCreate);
    id.thread.tid = OptionalU64::of(tid);
    id.thread.createTime100ns = OptionalU64::of(threadCreate);
    return id;
}

NodeIdentity moduleIdentity(const char* path, const char* pdb, std::uint64_t base) {
    NodeIdentity id;
    id.kind = ObjectKind::kModule;
    id.driver.bootId = kBoot;
    id.driver.imagePath = path;
    id.driver.pdbSignature = pdb;
    id.driver.imageBase = OptionalU64::of(base);
    return id;
}

NodeIdentity driverIdentity(const char* path, const char* pdb, std::uint64_t base) {
    NodeIdentity id = moduleIdentity(path, pdb, base);
    id.kind = ObjectKind::kDriver;
    return id;
}

NodeIdentity handleIdentity(const char* boot, std::uint64_t pid, std::uint64_t processCreate,
                             std::uint64_t handleValue, const char* typeName) {
    NodeIdentity id;
    id.kind = ObjectKind::kHandle;
    id.handle.owner.bootId = boot;
    id.handle.owner.pid = OptionalU64::of(pid);
    id.handle.owner.createTime100ns = OptionalU64::of(processCreate);
    id.handle.handleValue = OptionalU64::of(handleValue);
    id.handle.typeName = typeName;
    return id;
}

NodeIdentity fileIdentity(const char* path, std::uint64_t volume, const char* fileId) {
    NodeIdentity id;
    id.kind = ObjectKind::kFile;
    id.file.path = path;
    id.file.volumeSerial = OptionalU64::of(volume);
    id.file.fileId = fileId;
    return id;
}

NodeIdentity deviceIdentity(const char* boot, const char* name, const char* tag) {
    NodeIdentity id;
    id.kind = ObjectKind::kDevice;
    id.bootId = boot;
    id.name = name;
    id.instanceTag = tag;
    return id;
}

NodeIdentity serviceIdentity(const char* boot, const char* name) {
    NodeIdentity id;
    id.kind = ObjectKind::kService;
    id.bootId = boot;
    id.name = name;
    return id;
}

NodeIdentity connectionIdentity(const char* boot, std::uint16_t localPort,
                                 std::uint64_t firstSeen, std::uint64_t lastSeen) {
    NodeIdentity id;
    id.kind = ObjectKind::kConnection;
    id.connection.bootId = boot;
    id.connection.protocol = 6U;
    id.connection.localAddress = "10.0.0.5";
    id.connection.localPort = localPort;
    id.connection.remoteAddress = "93.184.216.34";
    id.connection.remotePort = 443U;
    id.connection.observedFirstUtc100ns = OptionalU64::of(firstSeen);
    id.connection.observedLastUtc100ns = OptionalU64::of(lastSeen);
    return id;
}

NodeIdentity timelineIdentity(const char* recordId) {
    NodeIdentity id;
    id.category = NodeCategory::kTimelineEntry;
    id.kind = ObjectKind::kUnknown;
    id.name = recordId;
    return id;
}

GraphNode makeNode(const NodeIdentity& identity, const char* display, const char* evidenceId,
                   NodeLifecycle lifecycle) {
    GraphNode node;
    node.identity = identity;
    node.displayText = display;
    node.evidenceId = evidenceId;
    node.lifecycle = lifecycle;
    node.outcome = CollectionOutcome::success();
    return node;
}

GraphEdge makeEdge(EdgeKind kind, const std::string& from, const std::string& to,
                   EdgeCertainty certainty, const char* evidenceRef, const char* ruleId) {
    GraphEdge edge;
    edge.kind = kind;
    edge.direction = EdgeDirection::kFromTo;
    edge.fromNodeId = from;
    edge.toNodeId = to;
    edge.certainty = certainty;
    if (evidenceRef != nullptr) {
        edge.evidenceRefs.emplace_back(evidenceRef);
    }
    edge.ruleId = ruleId;
    edge.ruleDescriptionKey = "graph.rule.description";
    edge.sourceGroup = "r0.enum";
    return edge;
}

RelationCoverage fullySuccessfulCoverage(std::uint64_t total, const char* evidenceId) {
    RelationCoverage coverage;
    coverage.outcome = CollectionOutcome::success();
    coverage.coverage.totalKnown = OptionalU64::of(total);
    coverage.coverage.succeeded = total;
    coverage.evidenceId = evidenceId;
    return coverage;
}

RelationCoverage failedCoverage(CollectionStatus status, const char* domain, std::uint64_t code,
                                const char* message) {
    RelationCoverage coverage;
    coverage.outcome = CollectionOutcome::failure(status, domain, code, message);
    return coverage;
}

bool contains(const std::vector<std::string>& values, const std::string& needle) {
    for (const std::string& value : values) {
        if (value == needle) {
            return true;
        }
    }
    return false;
}

// Per-operation duration. The §7 L4 budget is **per-query** relationship-view p95 <= 200 ms.
// Time each call individually rather than dividing total duration by the number of iterations.
long long microsSince(std::chrono::steady_clock::time_point start) {
    return static_cast<long long>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start)
            .count());
}

std::vector<std::string> filteredEdgeIds(const EntityGraph& graph, const EdgeFilter& filter) {
    std::vector<std::string> ids;
    for (const GraphEdge& edge : graph.edges()) {
        if (edgeMatchesFilter(edge, filter)) {
            ids.push_back(edge.edgeId);
        }
    }
    return ids;
}

// ---------------------------------------------------------------------------
// G-01: Edge semantics and filtering
// ---------------------------------------------------------------------------
void testEdgeSemantics(ksword_tests::Suite& s) {
    EntityGraph graph;

    const std::string kProc = processIdentity(kBoot, 1000, 111, "worker.exe").nodeKey();
    const std::string kThread = threadIdentity(kBoot, 1000, 111, 2000, 222).nodeKey();
    const std::string kModuleNode = moduleIdentity("C:\\Windows\\System32\\ntdll.dll", "PDB-NTDLL", 0x7FFE0000ULL).nodeKey();
    const std::string kHandle = handleIdentity(kBoot, 1000, 111, 0x2C, "File").nodeKey();
    const std::string kFile = fileIdentity("C:\\Windows\\System32\\ntdll.dll", 0xA1B2, "file-1").nodeKey();
    const std::string kOther = processIdentity(kBoot, 1500, 333, "peer.exe").nodeKey();

    s.expect(graph.addNode(makeNode(processIdentity(kBoot, 1000, 111, "worker.exe"), "worker.exe",
                                    "ev-proc", NodeLifecycle::kObserved)) ==
                 NodeAdmission::kAcceptedNew,
             L"G-01 the process node enters the graph");
    graph.addNode(makeNode(threadIdentity(kBoot, 1000, 111, 2000, 222), "tid 2000", "ev-thread",
                           NodeLifecycle::kObserved));
    graph.addNode(makeNode(moduleIdentity("C:\\Windows\\System32\\ntdll.dll", "PDB-NTDLL", 0x7FFE0000ULL),
                           "ntdll.dll", "ev-module", NodeLifecycle::kObserved));
    graph.addNode(makeNode(handleIdentity(kBoot, 1000, 111, 0x2C, "File"), "handle 0x2C",
                           "ev-handle", NodeLifecycle::kObserved));
    graph.addNode(makeNode(fileIdentity("C:\\Windows\\System32\\ntdll.dll", 0xA1B2, "file-1"),
                           "ntdll on disk", "ev-file", NodeLifecycle::kObserved));
    graph.addNode(makeNode(processIdentity(kBoot, 1500, 333, "peer.exe"), "peer.exe", "ev-peer",
                           NodeLifecycle::kObserved));

    // One edge of each of the six edge kinds, each independent.
    GraphEdge owns = makeEdge(EdgeKind::kOwns, kProc, kThread, EdgeCertainty::kConfirmed, "ev-thread",
                              "rule.process.ownsThread");
    GraphEdge loads = makeEdge(EdgeKind::kLoads, kProc, kModuleNode, EdgeCertainty::kConfirmed, "ev-module",
                               "rule.process.loadsModule");
    GraphEdge maps = makeEdge(EdgeKind::kMaps, kProc, kFile, EdgeCertainty::kCandidate, "ev-map",
                              "rule.process.mapsFile");
    GraphEdge opens = makeEdge(EdgeKind::kOpens, kHandle, kFile, EdgeCertainty::kConfirmed, "ev-handle",
                               "rule.handle.opensFile");
    GraphEdge candidateOwner = makeEdge(EdgeKind::kCandidateOwner, kOther, kHandle,
                                        EdgeCertainty::kConfirmed, "ev-guess",
                                        "rule.handle.candidateOwner");
    GraphEdge temporal = makeEdge(EdgeKind::kTemporalNeighbor, kOther, kProc, EdgeCertainty::kCandidate,
                                  "ev-timeline", "rule.temporal.window");

    s.expect(graph.addEdge(owns) == EdgeAdmission::kAccepted, L"G-01 an owns edge with evidence is accepted as given");
    s.expect(graph.addEdge(loads) == EdgeAdmission::kAccepted, L"G-01 a loads edge with evidence is accepted as given");
    s.expect(graph.addEdge(maps) == EdgeAdmission::kAccepted, L"G-01 a maps edge is accepted as given");
    s.expect(graph.addEdge(opens) == EdgeAdmission::kAccepted, L"G-01 an opens edge is accepted as given");
    s.expect(graph.addEdge(candidateOwner) == EdgeAdmission::kDemotedCandidateOwnerKind,
             L"G-01 a candidate-owner edge can never be confirmed, however much evidence it carries");
    s.expect(graph.addEdge(temporal) == EdgeAdmission::kDemotedTemporalDirectionDropped,
             L"G-01 a temporal-neighbor edge loses the direction it was given");

    s.expect(graph.edgeCount() == 6U, L"G-01 six distinct relation kinds coexist as six edges");

    // The six categories can be filtered independently without cross-contamination.
    struct KindCase final {
        EdgeKind kind;
        std::size_t expectedCount;
        const wchar_t* label;
    };
    const KindCase kKindCases[] = {
        {EdgeKind::kOwns, 1U, L"G-01 filtering by owns yields exactly the owns edge"},
        {EdgeKind::kLoads, 1U, L"G-01 filtering by loads yields exactly the loads edge"},
        {EdgeKind::kMaps, 1U, L"G-01 filtering by maps yields exactly the maps edge"},
        {EdgeKind::kOpens, 1U, L"G-01 filtering by opens yields exactly the opens edge"},
        {EdgeKind::kCandidateOwner, 1U, L"G-01 filtering by candidate-owner yields exactly that edge"},
        {EdgeKind::kTemporalNeighbor, 1U, L"G-01 filtering by temporal-neighbor yields exactly that edge"},
    };
    for (const KindCase& testCase : kKindCases) {
        EdgeFilter filter;
        filter.kinds.push_back(testCase.kind);
        const std::vector<std::string> kIds = filteredEdgeIds(graph, filter);
        s.expect(kIds.size() == testCase.expectedCount, testCase.label);
        bool allSameKind = true;
        for (const std::string& id : kIds) {
            const GraphEdge* edge = graph.findEdge(id);
            if (edge == nullptr || edge->kind != testCase.kind) {
                allSameKind = false;
            }
        }
        s.expect(allSameKind, L"G-01 a kind filter never lets another relation type through");
    }

    // Filter by multiple types simultaneously.
    EdgeFilter ownsAndLoads;
    ownsAndLoads.kinds.push_back(EdgeKind::kOwns);
    ownsAndLoads.kinds.push_back(EdgeKind::kLoads);
    s.expect(filteredEdgeIds(graph, ownsAndLoads).size() == 2U,
             L"G-01 a two-kind filter returns exactly those two edges");

    // Deterministic filtering. Manual calculation: Only `owns`, `loads`, and `opens` are `Confirmed`
    // — `candidate-owner` is downgraded, while `maps` and `temporal` are inherently `Candidate`.
    EdgeFilter confirmedOnly;
    confirmedOnly.certainties.push_back(EdgeCertainty::kConfirmed);
    s.expect(filteredEdgeIds(graph, confirmedOnly).size() == 3U,
             L"G-01 exactly three edges survive as confirmed");
    EdgeFilter candidateOnly;
    candidateOnly.certainties.push_back(EdgeCertainty::kCandidate);
    s.expect(filteredEdgeIds(graph, candidateOnly).size() == 3U,
             L"G-01 exactly three edges are candidates");

    // Relationships lacking evidence must not be confirmed.
    GraphEdge noEvidence = makeEdge(EdgeKind::kOwns, kProc, kHandle, EdgeCertainty::kConfirmed, nullptr,
                                    "rule.process.ownsHandle");
    s.expect(graph.addEdge(noEvidence) == EdgeAdmission::kDemotedMissingEvidence,
             L"G-01 a confirmed edge without evidence refs is demoted on admission");
    GraphEdge storedNoEvidence;
    s.expect(normalizeEdge(noEvidence, storedNoEvidence) == EdgeAdmission::kDemotedMissingEvidence &&
                 storedNoEvidence.certainty == EdgeCertainty::kCandidate,
             L"G-01 the stored certainty of an evidence-free edge is candidate, not confirmed");
    const GraphEdge* storedInGraph = graph.findEdge(storedNoEvidence.edgeId);
    s.expect(storedInGraph != nullptr && storedInGraph->certainty == EdgeCertainty::kCandidate,
             L"G-01 the graph never holds a confirmed edge with an empty evidence list");
    bool noConfirmedWithoutEvidence = true;
    for (const GraphEdge& edge : graph.edges()) {
        if (edge.certainty == EdgeCertainty::kConfirmed && edge.evidenceRefs.empty()) {
            noConfirmedWithoutEvidence = false;
        }
    }
    s.expect(noConfirmedWithoutEvidence,
             L"G-01 the whole graph holds no confirmed edge without evidence");

    // Rejection paths: default-constructed, missing endpoint, unknown direction, or duplicate ID.
    GraphEdge defaulted;
    s.expect(graph.addEdge(defaulted) == EdgeAdmission::kRejectedUnknownKind,
             L"G-01 a default-constructed edge is rejected rather than becoming a related edge");
    GraphEdge missingEndpoint = makeEdge(EdgeKind::kOwns, kProc, "", EdgeCertainty::kCandidate,
                                         "ev-x", "rule.x");
    s.expect(graph.addEdge(missingEndpoint) == EdgeAdmission::kRejectedMissingEndpoint,
             L"G-01 an edge missing an endpoint is rejected");
    GraphEdge unknownDirection = makeEdge(EdgeKind::kOwns, kProc, kOther, EdgeCertainty::kCandidate,
                                          "ev-x", "rule.x");
    unknownDirection.direction = EdgeDirection::kUnknown;
    s.expect(graph.addEdge(unknownDirection) == EdgeAdmission::kRejectedUnknownDirection,
             L"G-01 an edge whose direction is unknown is rejected, never read as from-to");
    s.expect(graph.addEdge(owns) == EdgeAdmission::kRejectedDuplicateId,
             L"G-01 the same relation is not stored twice");

    // Three-state validity interval.
    GraphEdge windowed = makeEdge(EdgeKind::kOwns, kProc, kOther, EdgeCertainty::kCandidate, "ev-w",
                                  "rule.window");
    windowed.validFrom100ns = OptionalU64::of(1000);
    windowed.validTo100ns = OptionalU64::of(2000);
    s.expect(edgeValidAt(windowed, OptionalU64::of(1500)) == TemporalValidity::kValid,
             L"G-01 an edge is valid inside its interval");
    s.expect(edgeValidAt(windowed, OptionalU64::of(999)) == TemporalValidity::kNotValid,
             L"G-01 an edge is not valid before its interval");
    s.expect(edgeValidAt(windowed, OptionalU64::of(2000)) == TemporalValidity::kNotValid,
             L"G-01 the interval end is exclusive");
    s.expect(edgeValidAt(windowed, OptionalU64::unset()) == TemporalValidity::kUnknown,
             L"G-01 asking about an unknown instant yields unknown, not valid");
    GraphEdge openEnded = windowed;
    openEnded.validTo100ns = OptionalU64::unset();
    s.expect(edgeValidAt(openEnded, OptionalU64::of(1500)) == TemporalValidity::kUnknown,
             L"G-01 a half-open interval cannot claim the relation still holds");
    s.expect(edgeValidAt(owns, OptionalU64::of(1500)) == TemporalValidity::kUnknown,
             L"G-01 an edge with no interval at all is unknown, not always-valid");

    // Boundary conditions for the four interval notations: from == to is a valid empty interval (relation
    // lasted zero duration), while from > to means the interval itself is broken; these are not the same.
    GraphEdge zeroWidth = windowed;
    zeroWidth.validFrom100ns = OptionalU64::of(1000);
    zeroWidth.validTo100ns = OptionalU64::of(1000);
    s.expect(edgeValidAt(zeroWidth, OptionalU64::of(1000)) == TemporalValidity::kNotValid &&
                 edgeValidAt(zeroWidth, OptionalU64::of(999)) == TemporalValidity::kNotValid,
             L"G-01 a zero-length interval is a real but empty interval, never valid");
    GraphEdge onlyTo = windowed;
    onlyTo.validFrom100ns = OptionalU64::unset();
    s.expect(edgeValidAt(onlyTo, OptionalU64::of(1500)) == TemporalValidity::kUnknown,
             L"G-01 an interval with only an end cannot claim the relation had already started");
    s.expect(edgeValidAt(onlyTo, OptionalU64::of(2500)) == TemporalValidity::kNotValid,
             L"G-01 an interval with only an end still expires at that end");

    GraphEdge reversedInterval = windowed;
    reversedInterval.validFrom100ns = OptionalU64::of(2000);
    reversedInterval.validTo100ns = OptionalU64::of(1000);
    s.expect(edgeValidAt(reversedInterval, OptionalU64::of(500)) ==
                     TemporalValidity::kIntervalInvalid &&
                 edgeValidAt(reversedInterval, OptionalU64::of(1500)) ==
                     TemporalValidity::kIntervalInvalid &&
                 edgeValidAt(reversedInterval, OptionalU64::of(2500)) ==
                     TemporalValidity::kIntervalInvalid,
             L"G-01 a reversed interval is reported as a broken interval at every instant, not as expired");
    s.expect(edgeValidAt(reversedInterval, OptionalU64::unset()) ==
                 TemporalValidity::kIntervalInvalid,
             L"G-01 a reversed interval is broken whether or not an instant was given");
    GraphEdge normalizedReversed;
    s.expect(normalizeEdge(reversedInterval, normalizedReversed) ==
                 EdgeAdmission::kRejectedInvalidInterval,
             L"G-01 an edge whose interval runs backwards is rejected instead of entering the graph invisibly");
    s.expect(!edgeAdmissionAccepted(EdgeAdmission::kRejectedInvalidInterval),
             L"G-01 a broken interval counts as a rejection, not as an accepted demotion");
    const std::size_t kEdgesBeforeReversed = graph.edgeCount();
    s.expect(graph.addEdge(reversedInterval) == EdgeAdmission::kRejectedInvalidInterval &&
                 graph.edgeCount() == kEdgesBeforeReversed,
             L"G-01 the graph never stores an edge that could never be visible at any instant");
    GraphEdge zeroWidthStored;
    s.expect(edgeAdmissionAccepted(normalizeEdge(zeroWidth, zeroWidthStored)),
             L"G-01 a zero-length interval is still a well-formed interval and is admitted");

    EdgeFilter atInstant;
    atInstant.atUtc100ns = OptionalU64::of(1500);
    s.expect(edgeMatchesFilter(windowed, atInstant),
             L"G-01 a time filter keeps an edge that is valid at that instant");
    GraphEdge expired = windowed;
    expired.validFrom100ns = OptionalU64::of(10);
    expired.validTo100ns = OptionalU64::of(20);
    s.expect(!edgeMatchesFilter(expired, atInstant),
             L"G-01 a time filter drops an edge that had already expired");
    s.expect(edgeMatchesFilter(owns, atInstant),
             L"G-01 unknown validity is kept by default because unknown is not invalid");
    EdgeFilter strictInstant = atInstant;
    strictInstant.excludeUnknownValidity = true;
    s.expect(!edgeMatchesFilter(owns, strictInstant),
             L"G-01 unknown validity is dropped only when the caller explicitly asks");

    // The inference explanation can be expanded to include rules and sources (half of G-08; verification is performed here as a side note).
    const GraphEdge* storedOwns = graph.findEdge(deriveEdgeId(owns));
    s.expect(storedOwns != nullptr, L"G-08 the owns edge can be looked up by its derived id");
    if (storedOwns != nullptr) {
        const EdgeInferenceNote kOwnsNote = describeEdgeInference(*storedOwns);
        s.expect(kOwnsNote.ruleId == "rule.process.ownsThread" &&
                     kOwnsNote.evidenceRefs.size() == 1U &&
                     kOwnsNote.notConfirmedReasonKey.empty(),
                 L"G-08 a confirmed edge names its rule and evidence and has no not-confirmed reason");
    }
    GraphEdge candidateOwnerStored;
    normalizeEdge(candidateOwner, candidateOwnerStored);
    s.expect(describeEdgeInference(candidateOwnerStored).notConfirmedReasonKey ==
                 "graph.edge.candidateOwnerKind",
             L"G-08 a candidate-owner edge explains that its kind cannot be confirmed");
    s.expect(describeEdgeInference(storedNoEvidence).notConfirmedReasonKey ==
                 "graph.edge.noEvidence",
             L"G-08 an evidence-free edge explains that it has no evidence");
    GraphEdge unknownCertainty = makeEdge(EdgeKind::kMaps, kProc, kFile, EdgeCertainty::kUnknown,
                                          "ev-m2", "rule.m2");
    s.expect(describeEdgeInference(unknownCertainty).notConfirmedReasonKey ==
                 "graph.edge.certaintyUnknown",
             L"G-08 an unknown-certainty edge says so instead of pretending to be a candidate");
    s.expect(describeEdgeInference(maps).notConfirmedReasonKey == "graph.edge.candidateEvidence",
             L"G-08 a candidate edge with evidence explains that the evidence is only candidate level");

    // Priority downgrade: when there is no evidence and the category cannot be confirmed, the report must state "missing evidence."
    // If phrased as "this category cannot be confirmed," the caller might assume switching the kind would yield Confirmed.
    GraphEdge candidateOwnerNoEvidence = makeEdge(EdgeKind::kCandidateOwner, kOther, kThread,
                                                  EdgeCertainty::kConfirmed, nullptr,
                                                  "rule.handle.candidateOwner2");
    GraphEdge candidateOwnerNoEvidenceStored;
    s.expect(normalizeEdge(candidateOwnerNoEvidence, candidateOwnerNoEvidenceStored) ==
                     EdgeAdmission::kDemotedMissingEvidence &&
                 candidateOwnerNoEvidenceStored.certainty == EdgeCertainty::kCandidate,
             L"G-01 an edge with neither evidence nor a confirmable kind reports the missing evidence first");
    s.expect(describeEdgeInference(candidateOwnerNoEvidence).notConfirmedReasonKey ==
                 "graph.edge.noEvidence",
             L"G-08 the same priority holds in the inference note: no evidence is named before the kind");

    // G-08 inference explanation is for the external interface; callers may pass an edge that has never entered the graph. It must not blindly
    // trust the incoming certainty—otherwise it would present a relationship that is 'confirmed, requires no explanation, and has zero sources'.
    GraphEdge fabricated;
    fabricated.kind = EdgeKind::kOwns;
    fabricated.direction = EdgeDirection::kFromTo;
    fabricated.fromNodeId = kProc;
    fabricated.toNodeId = kThread;
    fabricated.certainty = EdgeCertainty::kConfirmed;  // No evidenceRefs
    const EdgeInferenceNote kFabricatedNote = describeEdgeInference(fabricated);
    s.expect(kFabricatedNote.certainty == EdgeCertainty::kCandidate &&
                 kFabricatedNote.evidenceRefs.empty() &&
                 kFabricatedNote.notConfirmedReasonKey == "graph.edge.noEvidence",
             L"G-01 an unstored confirmed edge with no evidence is described as candidate, with the reason spelled out");
    GraphEdge fabricatedUnknownKind = fabricated;
    fabricatedUnknownKind.kind = EdgeKind::kUnknown;
    s.expect(describeEdgeInference(fabricatedUnknownKind).certainty == EdgeCertainty::kCandidate,
             L"G-01 even an edge the graph would reject outright is never described as confirmed without evidence");

    // The same pair of endpoints, same relationship, and different time intervals constitute two distinct facts, not a single edge
    // (per G-01's "time-valid interval" rule: if identity is not included, the second interval would be discarded as a duplicate).
    EntityGraph intervalGraph;
    intervalGraph.addNode(makeNode(processIdentity(kBoot, 1000, 111, "worker.exe"), "worker.exe",
                                   "ev-proc", NodeLifecycle::kObserved));
    intervalGraph.addNode(makeNode(fileIdentity("C:\\Windows\\System32\\ntdll.dll", 0xA1B2,
                                                 "file-1"),
                                   "ntdll on disk", "ev-file", NodeLifecycle::kObserved));
    GraphEdge firstWindow = makeEdge(EdgeKind::kMaps, kProc, kFile, EdgeCertainty::kCandidate, "ev-m1",
                                     "rule.maps");
    firstWindow.validFrom100ns = OptionalU64::of(1000);
    firstWindow.validTo100ns = OptionalU64::of(2000);
    GraphEdge secondWindow = firstWindow;
    secondWindow.validFrom100ns = OptionalU64::of(5000);
    secondWindow.validTo100ns = OptionalU64::of(6000);
    s.expect(edgeAdmissionAccepted(intervalGraph.addEdge(firstWindow)),
             L"G-01 the first mapping window is admitted");
    s.expect(edgeAdmissionAccepted(intervalGraph.addEdge(secondWindow)) &&
                 intervalGraph.edgeCount() == 2U,
             L"G-01 the same relation over a different interval is a second edge, not a duplicate");
    EdgeFilter earlyInstant;
    earlyInstant.atUtc100ns = OptionalU64::of(1500);
    s.expect(filteredEdgeIds(intervalGraph, earlyInstant).size() == 1U,
             L"G-01 a time filter separates the two intervals of the same relation");

    // Symmetric edge endpoint normalization: A-B and B-A represent the same edge.
    EntityGraph symmetricGraph;
    symmetricGraph.addNode(makeNode(processIdentity(kBoot, 1000, 111, "a.exe"), "a", "ev-a",
                                    NodeLifecycle::kObserved));
    symmetricGraph.addNode(makeNode(processIdentity(kBoot, 1500, 333, "b.exe"), "b", "ev-b",
                                    NodeLifecycle::kObserved));
    GraphEdge forward = makeEdge(EdgeKind::kTemporalNeighbor, kProc, kOther, EdgeCertainty::kCandidate,
                                 "ev-t", "rule.t");
    GraphEdge backward = makeEdge(EdgeKind::kTemporalNeighbor, kOther, kProc, EdgeCertainty::kCandidate,
                                  "ev-t", "rule.t");
    s.expect(edgeAdmissionAccepted(symmetricGraph.addEdge(forward)),
             L"G-01 the first temporal-neighbor edge is admitted");
    s.expect(symmetricGraph.addEdge(backward) == EdgeAdmission::kRejectedDuplicateId,
             L"G-01 the same temporal neighbourhood stated backwards is the same edge");
    s.expect(symmetricGraph.edges().front().direction == EdgeDirection::kSymmetric,
             L"G-01 a temporal-neighbor edge is stored without direction so it cannot read as cause");
}

// ---------------------------------------------------------------------------
// G-02: Lifecycle and old object.
// ---------------------------------------------------------------------------
void testLifecycleIdentity(ksword_tests::Suite& s) {
    // Same PID, different creation time -> two distinct nodes.
    const NodeIdentity kFirstInstance = processIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity kReusedPid = processIdentity(kBoot, 1000, 999, "worker.exe");
    s.expect(kFirstInstance.nodeKey() != kReusedPid.nodeKey(),
             L"G-02 the same pid with a different creation time is a different node");
    s.expect(matchProcessInstance(kFirstInstance.process, kReusedPid.process) == MatchResult::kNoMatch,
             L"G-02 pid reuse is a mismatch, not a weak match");

    // Different boot cycles -> two nodes.
    const NodeIdentity kAcrossBoot = processIdentity(kBoot2, 1000, 111, "worker.exe");
    s.expect(kFirstInstance.nodeKey() != kAcrossBoot.nodeKey(),
             L"G-02 the same pid and creation time in a different boot cycle is a different node");

    // Strong identity node keys must include the cross-session primary key; weak identities have no primary key.
    s.expect(!kFirstInstance.crossSessionKey().empty() &&
                 kFirstInstance.nodeKey().find(kFirstInstance.crossSessionKey()) != std::string::npos,
             L"G-02 a strong node key is built on the cross-session key");
    const NodeIdentity kWeakA = weakProcessIdentity(1000, "observation-1");
    const NodeIdentity kWeakB = weakProcessIdentity(1000, "observation-2");
    s.expect(kWeakA.crossSessionKey().empty() && kWeakA.strength() == IdentityStrength::kWeak,
             L"G-02 a process without a creation time gets no cross-session key");
    s.expect(kWeakA.nodeKey() != kWeakB.nodeKey(),
             L"G-02 two weak observations of the same pid stay two nodes");
    s.expect(kWeakA.nodeKey() != kFirstInstance.nodeKey(),
             L"G-02 a weak observation is never merged into the strong instance");

    // Address reuse: two observations of the same device at the same name and address must be separated.
    const NodeIdentity kDeviceFirst = deviceIdentity(kBoot, "\\Device\\Foo", "epoch-1");
    const NodeIdentity kDeviceSecond = deviceIdentity(kBoot, "\\Device\\Foo", "epoch-2");
    s.expect(kDeviceFirst.nodeKey() != kDeviceSecond.nodeKey(),
             L"G-02 two observations of a reusable device name stay two nodes");
    s.expect(kDeviceFirst.strength() == IdentityStrength::kWeak,
             L"G-02 a device has no lifecycle identity so its strength is capped at weak");
    s.expect(matchNodeIdentity(kDeviceFirst, deviceIdentity(kBoot, "\\Device\\Foo", "epoch-1")) ==
                 MatchResult::kCandidate,
             L"G-02 identical device names are at most a candidate, never confirmed");
    s.expect(matchNodeIdentity(kDeviceFirst, kDeviceSecond) == MatchResult::kNoMatch,
             L"G-02 different instance tags on the same device name are a mismatch");
    s.expect(matchNodeIdentity(kDeviceFirst, serviceIdentity(kBoot, "\\Device\\Foo")) ==
                 MatchResult::kNoMatch,
             L"G-02 a device and a service with the same name are never the same node");

    // "No input" is not "weak match". MatchResult has no "insufficient information" state. Since
    // Candidate is used by the caller as definitive evidence, lack of information must result in NoMatch.
    s.expect(matchNodeIdentity(NodeIdentity{}, NodeIdentity{}) == MatchResult::kNoMatch,
             L"G-02 two default-constructed identities are not a candidate for being the same object");
    NodeIdentity namelessDevice;
    namelessDevice.kind = ObjectKind::kDevice;
    namelessDevice.bootId = kBoot;  // No name -> Unusable
    s.expect(namelessDevice.strength() == IdentityStrength::kUnusable,
             L"G-02 a device with no name has an unusable identity");
    s.expect(matchNodeIdentity(kDeviceFirst, namelessDevice) == MatchResult::kNoMatch,
             L"G-02 a named device and an unusable one are not a candidate match");
    s.expect(matchNodeIdentity(namelessDevice, namelessDevice) == MatchResult::kNoMatch,
             L"G-02 an unusable identity is not even a candidate for being itself");

    // Same base address, different image -> different nodes.
    const NodeIdentity kDriverA = driverIdentity("C:\\Windows\\System32\\drivers\\a.sys", "PDB-A",
                                                0xFFFFF80000000000ULL);
    const NodeIdentity kDriverB = driverIdentity("C:\\Windows\\System32\\drivers\\b.sys", "PDB-B",
                                                0xFFFFF80000000000ULL);
    s.expect(kDriverA.nodeKey() != kDriverB.nodeKey(),
             L"G-02 two images loaded at the same reused base address are different nodes");

    // No identity and no discriminative label -> Rejected.
    EntityGraph graph;
    GraphNode empty;
    s.expect(graph.addNode(empty) == NodeAdmission::kRejectedNoIdentity,
             L"G-02 a node with neither identity nor discriminator is rejected");
    GraphNode tagged;
    tagged.identity.instanceTag = "observation-1";
    s.expect(graph.addNode(tagged) == NodeAdmission::kAcceptedNew,
             L"G-02 a caller-supplied discriminator makes an otherwise unusable record addressable");

    // Merge semantics.
    EntityGraph merged;
    s.expect(merged.addNode(makeNode(kFirstInstance, "worker.exe", "ev-1",
                                     NodeLifecycle::kObserved)) == NodeAdmission::kAcceptedNew,
             L"G-02 the first observation creates the node");
    s.expect(merged.addNode(makeNode(kFirstInstance, "worker.exe", "ev-1",
                                     NodeLifecycle::kObserved)) == NodeAdmission::kAcceptedMerged,
             L"G-02 the same instance observed twice merges into one node");
    s.expect(merged.addNode(makeNode(kFirstInstance, "worker.exe", "ev-2", NodeLifecycle::kEnded)) ==
                 NodeAdmission::kAcceptedMergedLifecycleConflict,
             L"G-02 contradictory lifecycles are reported, not silently resolved");
    s.expect(merged.findNode(kFirstInstance.nodeKey()) != nullptr &&
                 merged.findNode(kFirstInstance.nodeKey())->lifecycle == NodeLifecycle::kUnknown,
             L"G-02 a lifecycle conflict downgrades to unknown instead of picking a side");
    s.expect(merged.nodeCount() == 1U, L"G-02 merging never adds a second node");
    s.expect(merged.addNode(makeNode(kReusedPid, "worker.exe", "ev-3", NodeLifecycle::kObserved)) ==
                 NodeAdmission::kAcceptedNew,
             L"G-02 the pid-reusing instance becomes its own node next to the historical one");
    s.expect(merged.nodeCount() == 2U,
             L"G-02 the historical object survives alongside the current one");

    // Session replay: nodeId is provided by saved data; two records from different sources
    // may share the same ID and contradictory identities. Merging by ID would erase the
    // second observation entirely—exactly the behavior of "merging two objects into one."
    EntityGraph replay;
    GraphNode savedRow = makeNode(kFirstInstance, "worker.exe", "ev-row-7", NodeLifecycle::kObserved);
    savedRow.nodeId = "saved-row-7";
    s.expect(replay.addNode(savedRow) == NodeAdmission::kAcceptedNew,
             L"G-02 a replayed row keeps the node id that was saved with it");
    GraphNode otherObject = makeNode(processIdentity(kBoot, 4444, 999, "evil.exe"), "evil.exe",
                                     "ev-row-7b", NodeLifecycle::kObserved);
    otherObject.nodeId = "saved-row-7";
    s.expect(matchNodeIdentity(savedRow.identity, otherObject.identity) == MatchResult::kNoMatch,
             L"G-02 the two records really are different objects by identity");
    s.expect(replay.addNode(otherObject) == NodeAdmission::kRejectedIdentityConflict,
             L"G-02 a second, contradictory identity on the same node id is rejected, not merged away");
    s.expect(!nodeAdmissionAccepted(NodeAdmission::kRejectedIdentityConflict),
             L"G-02 an identity conflict counts as a rejection, so callers cannot read it as accepted");
    s.expect(replay.identityConflictCount() == 1U,
             L"G-02 the rejected observation is accounted for instead of silently disappearing");
    const GraphNode* keptRow = replay.findNode("saved-row-7");
    s.expect(keptRow != nullptr && keptRow->identity.process.pid == OptionalU64::of(1000) &&
                 keptRow->displayText == "worker.exe" && keptRow->evidenceId == "ev-row-7",
             L"G-02 the first observation is kept intact and never overwritten by the conflicting one");
    s.expect(replay.nodeCount() == 1U,
             L"G-02 a rejected identity conflict does not quietly create a second node either");
    s.expect(replay.addNode(savedRow) == NodeAdmission::kAcceptedMerged,
             L"G-02 the very same record arriving twice still merges");

    // Records with insufficient identity but a discriminator tag provided by the caller must still be mergeable
    // upon repeated observation; the identity threshold must not treat "reading the same row twice" as a conflict.
    GraphNode weakRow;
    weakRow.nodeId = "saved-row-9";
    weakRow.identity.kind = ObjectKind::kProcess;
    weakRow.identity.instanceTag = "row-9";
    weakRow.displayText = "unknown process";
    weakRow.evidenceId = "ev-row-9";
    weakRow.lifecycle = NodeLifecycle::kObserved;
    s.expect(replay.addNode(weakRow) == NodeAdmission::kAcceptedNew &&
                 replay.addNode(weakRow) == NodeAdmission::kAcceptedMerged,
             L"G-02 re-observing the same weak record under the same id still merges");
}

// ---------------------------------------------------------------------------
// G-02: Historical edges must not automatically bind to current objects.
// ---------------------------------------------------------------------------
void testHistoricalEdgeToLive(ksword_tests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity kSavedProcess = processIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity kSavedThread = threadIdentity(kBoot, 1000, 111, 2000, 222);
    const NodeIdentity kSavedDevice = deviceIdentity(kBoot, "\\Device\\Foo", "epoch-1");

    graph.addNode(makeNode(kSavedProcess, "worker.exe", "ev-proc", NodeLifecycle::kEnded));
    graph.addNode(makeNode(kSavedThread, "tid 2000", "ev-thread", NodeLifecycle::kEnded));
    graph.addNode(makeNode(kSavedDevice, "\\Device\\Foo", "ev-device", NodeLifecycle::kEnded));

    GraphEdge owns = makeEdge(EdgeKind::kOwns, kSavedProcess.nodeKey(), kSavedThread.nodeKey(),
                              EdgeCertainty::kConfirmed, "ev-thread", "rule.owns");
    graph.addEdge(owns);
    GraphEdge deviceEdge = makeEdge(EdgeKind::kDeviceOf, kSavedDevice.nodeKey(),
                                    kSavedProcess.nodeKey(), EdgeCertainty::kCandidate, "ev-device",
                                    "rule.deviceOf");
    graph.addEdge(deviceEdge);
    const std::string kOwnsId = deriveEdgeId(owns);
    const std::string kDeviceEdgeId = deriveEdgeId(deviceEdge);

    HistoricalEdgeLiveRequest request;
    request.edgeId = kOwnsId;
    request.endpoint = EndpointRole::kFrom;
    request.page = NavigationPage::kProcess;
    request.targetPageAvailable = true;
    request.objectPresentInPage = true;
    request.evidencePresentInSession = true;

    // 1) PID reuse: The snapshot is another instance with the same PID.
    HistoricalEdgeLiveRequest reused = request;
    reused.live.found = true;
    reused.live.liveProcess = processIdentity(kBoot, 1000, 999, "worker.exe").process;
    const HistoricalEdgeLiveResult kMismatch = resolveHistoricalEdgeToLive(graph, reused);
    s.expect(kMismatch.edgeFound && kMismatch.nodeFound && kMismatch.liveResolverSupported,
             L"G-02 the historical edge and its saved endpoint are found");
    s.expect(kMismatch.identityDecision == LiveNavigationDecision::kRejectIdentityMismatch,
             L"G-02 a reused pid is rejected as an identity mismatch");
    s.expect(kMismatch.liveNodeId.empty(),
             L"G-02 a rejected historical edge never names a live node id");
    s.expect(!kMismatch.navigationAttempted,
             L"G-02 navigation is not even attempted when the identity does not match");
    s.expect(kMismatch.navigation != NavigationOutcome::kDelivered,
             L"G-02 a rejected historical edge never reports a delivered navigation");
    s.expect(kMismatch.reasonKey == "graph.live.identityMismatch",
             L"G-02 the rejection names pid reuse rather than a generic failure");

    // 2) Object has exited.
    HistoricalEdgeLiveRequest exited = request;
    exited.live.found = false;
    const HistoricalEdgeLiveResult kGone = resolveHistoricalEdgeToLive(graph, exited);
    s.expect(kGone.identityDecision == LiveNavigationDecision::kRejectObjectExited &&
                 !kGone.navigationAttempted && kGone.liveNodeId.empty(),
             L"G-02 an object that no longer exists is reported as exited, not as mismatch");

    // 3) Identity is insufficient for confirmation (creation time is missing in the live record).
    HistoricalEdgeLiveRequest unverifiable = request;
    unverifiable.live.found = true;
    unverifiable.live.liveProcess.bootId = kBoot;
    unverifiable.live.liveProcess.pid = OptionalU64::of(1000);
    const HistoricalEdgeLiveResult kWeak = resolveHistoricalEdgeToLive(graph, unverifiable);
    s.expect(kWeak.identityDecision == LiveNavigationDecision::kRejectIdentityUnverifiable &&
                 !kWeak.navigationAttempted && kWeak.liveNodeId.empty(),
             L"G-02 a live record without a creation time cannot confirm the historical object");

    // 4) Identity confirmation matches -> allow navigation.
    HistoricalEdgeLiveRequest allowed = request;
    allowed.live.found = true;
    allowed.live.liveProcess = kSavedProcess.process;
    const HistoricalEdgeLiveResult kOk = resolveHistoricalEdgeToLive(graph, allowed);
    s.expect(kOk.identityDecision == LiveNavigationDecision::kAllow && kOk.navigationAttempted,
             L"G-02 a confirmed identity is the only path that reaches navigation");
    s.expect(kOk.navigation == NavigationOutcome::kDelivered,
             L"G-02 a confirmed identity with a live page and saved evidence is delivered");
    s.expect(kOk.liveNodeId == kSavedProcess.nodeKey(),
             L"G-02 a confirmed match resolves to the very same node id, not a new one");

    // 5) If evidence is not saved, do not silently patch the scene.
    HistoricalEdgeLiveRequest unsavedEvidence = allowed;
    unsavedEvidence.evidencePresentInSession = false;
    s.expect(resolveHistoricalEdgeToLive(graph, unsavedEvidence).navigation ==
                 NavigationOutcome::kEvidenceNotSaved,
             L"G-06 navigation stops when the evidence behind the edge was never saved");

    // 6) Categories without a live re-parsing contract -> explicitly state that validation is not possible, rather than allowing them.
    HistoricalEdgeLiveRequest deviceRequest = request;
    deviceRequest.edgeId = kDeviceEdgeId;
    deviceRequest.endpoint = EndpointRole::kFrom;
    deviceRequest.live.found = true;
    deviceRequest.live.liveProcess = kSavedProcess.process;
    const HistoricalEdgeLiveResult kDevice = resolveHistoricalEdgeToLive(graph, deviceRequest);
    s.expect(kDevice.nodeFound && !kDevice.liveResolverSupported &&
                 kDevice.identityDecision == LiveNavigationDecision::kRejectIdentityUnverifiable &&
                 !kDevice.navigationAttempted,
             L"G-02 a kind without a live resolver is reported unverifiable rather than allowed");
    s.expect(kDevice.reasonKey == "graph.live.noResolverForKind",
             L"G-02 an unverifiable kind explains that no resolver exists, not that it mismatched");

    // 7) Edge does not exist.
    HistoricalEdgeLiveRequest missingEdge = request;
    missingEdge.edgeId = "no-such-edge";
    const HistoricalEdgeLiveResult kNone = resolveHistoricalEdgeToLive(graph, missingEdge);
    s.expect(!kNone.edgeFound && !kNone.navigationAttempted && kNone.liveNodeId.empty(),
             L"G-02 a missing historical edge resolves to nothing at all");
}

// ---------------------------------------------------------------------------
// G-03: Three minimal usable investigation chains
// ---------------------------------------------------------------------------
void testProcessChain(ksword_tests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity kProcess = processIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity kThread = threadIdentity(kBoot, 1000, 111, 2000, 222);
    const NodeIdentity kThreadTwo = threadIdentity(kBoot, 1000, 111, 2100, 223);
    graph.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kThread, "tid 2000", "ev-thread", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kThreadTwo, "tid 2100", "ev-thread", NodeLifecycle::kObserved));

    graph.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kThread.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-thread", "rule.owns"));
    graph.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kThreadTwo.nodeKey(),
                           EdgeCertainty::kCandidate, "ev-thread", "rule.owns"));

    // Thread coverage captured; module coverage not declared; handle coverage is indeed empty.
    graph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kThread,
                                  fullySuccessfulCoverage(2, "ev-thread"));
    graph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kHandle,
                                  fullySuccessfulCoverage(0, "ev-handle"));

    ChainOptions options;
    const InvestigationChain kChain =
        buildChain(graph, ChainKind::kProcessSubjects, kProcess.nodeKey(), options);
    s.expect(kChain.rootFound && kChain.steps.size() == 4U,
             L"G-03 the process chain has a root plus thread, module and handle steps");
    s.expect(kChain.steps[0].availability == StepAvailability::kPresent,
             L"G-03 the process root step is present");
    s.expect(kChain.steps[1].availability == StepAvailability::kPresent &&
                 kChain.steps[1].matchCount == 2U,
             L"G-03 both owned threads are reached in one hop");
    s.expect(kChain.steps[1].weakestEdgeCertainty == EdgeCertainty::kCandidate,
             L"G-03 the thread step reports its weakest edge certainty, not its strongest");
    s.expect(kChain.steps[2].availability == StepAvailability::kMissingNotCollected,
             L"G-03 an undeclared module source is reported as not collected, not as no modules");
    s.expect(kChain.steps[2].outcome.status == CollectionStatus::kNotCollected,
             L"G-03 the not-collected step keeps its collection status");
    s.expect(kChain.steps[3].availability == StepAvailability::kMissingNoData,
             L"G-03 a fully accounted empty handle enumeration is a true empty, not a gap");
    s.expect(kChain.missingStepCount() == 2U && !kChain.complete(),
             L"G-03 the chain reports exactly two missing links and is not complete");
    s.expect(kChain.everyPresentStepOpensSource(),
             L"G-03 every present step can open its source detail");
    s.expect(kChain.steps[1].evidenceOpenable && !kChain.steps[1].evidenceId.empty(),
             L"G-03 the thread step names the evidence that backs it");
    s.expect(kChain.steps[1].anyObjectNavigable && kChain.steps[1].everyObjectNavigable,
             L"G-03 both threads of the thread step can be navigated to, so the step is navigable either way");

    // When only a subset of nodes in a chain carry evidence, the condition "this step can open the source" must be
    // false: G-03 requires that every step can open source details, not merely that "any one step can open it." Manual
    // calculation: 3 threads, only the 1st has an evidenceId. matchCount=3, nodeIds=3, but only 1 can open evidence.
    EntityGraph partialEvidence;
    partialEvidence.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    for (std::uint64_t i = 0; i < 3; ++i) {
        const NodeIdentity kSubject = threadIdentity(kBoot, 1000, 111, 7000 + i, 800 + i);
        partialEvidence.addNode(makeNode(kSubject, "t", (i == 0) ? "ev-thread-0" : "",
                                         NodeLifecycle::kObserved));
        partialEvidence.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kSubject.nodeKey(),
                                         EdgeCertainty::kConfirmed, "ev-thread-0", "rule.owns"));
    }
    const InvestigationChain kMixedChain =
        buildChain(partialEvidence, ChainKind::kProcessSubjects, kProcess.nodeKey(), options);
    s.expect(kMixedChain.steps[1].availability == StepAvailability::kPresent &&
                 kMixedChain.steps[1].matchCount == 3U && kMixedChain.steps[1].nodeIds.size() == 3U,
             L"G-03 all three threads are reached even though only one carries evidence");
    s.expect(!kMixedChain.steps[1].evidenceOpenable,
             L"G-03 a step whose nodes cannot all open their source does not claim to be openable");
    s.expect(!kMixedChain.everyPresentStepOpensSource(),
             L"G-03 one openable node out of three does not satisfy every-step-opens-source");
    s.expect(kMixedChain.steps[1].anyObjectNavigable && kMixedChain.steps[1].everyObjectNavigable,
             L"G-03 object navigation is reported separately from source openability");

    // Coverage only reaches halfway -> must be separated from 'definitely none'.
    EntityGraph partialGraph;
    partialGraph.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    RelationCoverage partial = fullySuccessfulCoverage(9, "ev-thread");
    partial.outcome.status = CollectionStatus::kPartial;
    partial.coverage.succeeded = 3;
    partialGraph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kThread, partial);
    const InvestigationChain kPartialChain =
        buildChain(partialGraph, ChainKind::kProcessSubjects, kProcess.nodeKey(), options);
    s.expect(kPartialChain.steps[1].availability == StepAvailability::kMissingCoverageIncomplete,
             L"G-03 a partially covered enumeration cannot claim there are no threads");

    // Success but no accounting entries filled -> also not considered 'truly absent'.
    EntityGraph unaccounted;
    unaccounted.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    RelationCoverage blank;
    blank.outcome = CollectionOutcome::success();
    unaccounted.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kThread, blank);
    s.expect(buildChain(unaccounted, ChainKind::kProcessSubjects, kProcess.nodeKey(), options)
                     .steps[1]
                     .availability == StepAvailability::kMissingCoverageIncomplete,
             L"G-03 a success with an empty account is not positive evidence of absence");

    // Root node not in data.
    const InvestigationChain kNoRoot =
        buildChain(graph, ChainKind::kProcessSubjects, "not-saved", options);
    s.expect(!kNoRoot.rootFound && kNoRoot.steps[0].availability == StepAvailability::kMissingNotCollected,
             L"G-03 a root that was never saved is reported missing instead of silently empty");
    s.expect(kNoRoot.steps[1].availability == StepAvailability::kMissingPreviousStepMissing,
             L"G-03 a step whose predecessor is missing says so rather than blaming its own source");
    s.expect(!kNoRoot.complete() && kNoRoot.missingStepCount() == 4U,
             L"G-03 a chain with no root is not complete");

    // Neighbors with insufficient identity cannot be treated as a confirmed hop.
    EntityGraph weakGraph;
    weakGraph.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    GraphNode weakThread;
    weakThread.identity.kind = ObjectKind::kThread;   // No tid -> Unusable
    weakThread.identity.instanceTag = "row-7";
    weakThread.displayText = "unknown thread";
    weakThread.evidenceId = "ev-weak";
    weakThread.lifecycle = NodeLifecycle::kObserved;
    weakGraph.addNode(weakThread);
    weakGraph.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(),
                               weakThread.identity.nodeKey(), EdgeCertainty::kCandidate, "ev-weak",
                               "rule.owns"));
    weakGraph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kThread,
                                      fullySuccessfulCoverage(1, "ev-weak"));
    const InvestigationChain kWeakChain =
        buildChain(weakGraph, ChainKind::kProcessSubjects, kProcess.nodeKey(), options);
    s.expect(kWeakChain.steps[1].availability == StepAvailability::kMissingIdentityUnusable &&
                 kWeakChain.steps[1].matchCount == 1U,
             L"G-03 a record with an unusable identity is counted but is not a confirmed hop");
    const GraphNode* storedWeak = weakGraph.findNode(weakThread.identity.nodeKey());
    s.expect(storedWeak != nullptr && !storedWeak->objectNavigable(),
             L"G-02 an unusable identity never becomes navigable just because it has a node id");
    s.expect(storedWeak != nullptr &&
                 storedWeak->identity.makeRef("ev-weak", "unknown thread").key.empty(),
             L"G-02 an unusable identity hands out no navigation key at all");
    s.expect(storedWeak != nullptr && storedWeak->evidenceOpenable(),
             L"G-05 an unusable identity can still open its own raw evidence");
    s.expect(!kWeakChain.steps[1].anyObjectNavigable && !kWeakChain.steps[1].everyObjectNavigable &&
                 kWeakChain.steps[1].evidenceOpenable,
             L"G-03 an unusable hop offers the source detail but not object navigation");
    const GraphNode* storedStrong = graph.findNode(kThread.nodeKey());
    s.expect(storedStrong != nullptr && storedStrong->objectNavigable(),
             L"G-02 a strong identity really is navigable, so the check above is not vacuous");

    // Root node identity insufficient: The chain fails at the very first step.
    EntityGraph unusableRootGraph;
    GraphNode unusableRoot;
    unusableRoot.identity.kind = ObjectKind::kProcess;  // No pid -> Unusable
    unusableRoot.identity.instanceTag = "row-1";
    unusableRoot.displayText = "unknown process";
    unusableRoot.evidenceId = "ev-row";
    unusableRoot.lifecycle = NodeLifecycle::kObserved;
    unusableRootGraph.addNode(unusableRoot);
    const InvestigationChain kUnusableChain = buildChain(
        unusableRootGraph, ChainKind::kProcessSubjects, unusableRoot.identity.nodeKey(), options);
    s.expect(kUnusableChain.rootFound &&
                 kUnusableChain.steps[0].availability == StepAvailability::kMissingIdentityUnusable,
             L"G-03 a root whose identity is unusable is not reported as a usable first step");
    s.expect(kUnusableChain.steps[0].evidenceOpenable &&
                 !kUnusableChain.steps[0].anyObjectNavigable &&
                 !kUnusableChain.steps[0].everyObjectNavigable,
             L"G-03 an unusable root can open its raw evidence but cannot be navigated to");
    s.expect(kUnusableChain.steps[1].availability == StepAvailability::kMissingPreviousStepMissing,
             L"G-03 the hops after an unusable root report the broken predecessor");

    // When the previous link's identity is insufficient, the next link must not proceed to form a 'definite hop' from those objects. Manual calculation:
    // Device -> Driver via DeviceOf (insufficient identity), then Driver -> File via ImageOf. Both edges exist and both declare
    // complete coverage. Link 1 is MissingIdentityUnusable; links 2 and 3 must both report that the previous link is missing.
    EntityGraph brokenPredecessor;
    const NodeIdentity kDeviceRoot = deviceIdentity(kBoot, "\\Device\\Chain", "epoch-1");
    GraphNode unusableDriver;
    unusableDriver.identity.kind = ObjectKind::kDriver;  // No imagePath / pdb -> Unusable
    unusableDriver.identity.instanceTag = "row-3";
    unusableDriver.displayText = "unknown driver";
    unusableDriver.evidenceId = "ev-unknown-driver";
    unusableDriver.lifecycle = NodeLifecycle::kObserved;
    const NodeIdentity kChainImage =
        fileIdentity("C:\\Windows\\System32\\drivers\\chain.sys", 0xA1B2, "file-chain");
    brokenPredecessor.addNode(makeNode(kDeviceRoot, "\\Device\\Chain", "ev-device",
                                       NodeLifecycle::kObserved));
    brokenPredecessor.addNode(unusableDriver);
    brokenPredecessor.addNode(makeNode(kChainImage, "chain.sys", "ev-image", NodeLifecycle::kObserved));
    brokenPredecessor.addEdge(makeEdge(EdgeKind::kDeviceOf, kDeviceRoot.nodeKey(),
                                       unusableDriver.identity.nodeKey(), EdgeCertainty::kConfirmed,
                                       "ev-device", "rule.deviceOf"));
    brokenPredecessor.addEdge(makeEdge(EdgeKind::kImageOf, unusableDriver.identity.nodeKey(),
                                       kChainImage.nodeKey(), EdgeCertainty::kConfirmed, "ev-image",
                                       "rule.imageOf"));
    brokenPredecessor.declareRelationCoverage(EdgeKind::kDeviceOf, ObjectKind::kDriver,
                                              fullySuccessfulCoverage(1, "ev-device"));
    brokenPredecessor.declareRelationCoverage(EdgeKind::kImageOf, ObjectKind::kFile,
                                              fullySuccessfulCoverage(1, "ev-image"));
    const InvestigationChain kBrokenChain =
        buildChain(brokenPredecessor, ChainKind::kDeviceToService, kDeviceRoot.nodeKey(), options);
    s.expect(kBrokenChain.steps[1].availability == StepAvailability::kMissingIdentityUnusable,
             L"G-03 a driver whose identity is unusable is not a confirmed hop");
    s.expect(kBrokenChain.steps[2].availability == StepAvailability::kMissingPreviousStepMissing,
             L"G-03 the hop after an unusable predecessor is not present, however many records it finds");
    s.expect(!kBrokenChain.steps[2].anyObjectNavigable && !kBrokenChain.steps[2].everyObjectNavigable,
             L"G-03 a hop starting from an unverified predecessor offers no object navigation");
    s.expect(kBrokenChain.steps[3].availability == StepAvailability::kMissingPreviousStepMissing &&
                 kBrokenChain.missingStepCount() == 3U,
             L"G-03 the broken predecessor propagates instead of blaming the service source");

    // Maximum items per step.
    EntityGraph manyGraph;
    manyGraph.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    for (std::uint64_t i = 0; i < 5; ++i) {
        const NodeIdentity kExtra = threadIdentity(kBoot, 1000, 111, 3000 + i, 400 + i);
        manyGraph.addNode(makeNode(kExtra, "t", "ev-thread", NodeLifecycle::kObserved));
        manyGraph.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kExtra.nodeKey(),
                                   EdgeCertainty::kConfirmed, "ev-thread", "rule.owns"));
    }
    ChainOptions tight;
    tight.maxNodesPerStep = 2;
    const InvestigationChain kTruncated =
        buildChain(manyGraph, ChainKind::kProcessSubjects, kProcess.nodeKey(), tight);
    s.expect(kTruncated.steps[1].matchCount == 5U && kTruncated.steps[1].nodeIds.size() == 2U &&
                 kTruncated.steps[1].truncated,
             L"G-03 a per-step cap reports the real match count next to the truncated list");
}

void testDeviceChain(ksword_tests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity kDevice = deviceIdentity(kBoot, "\\Device\\Ksword0", "epoch-1");
    const NodeIdentity kDriverObject =
        driverIdentity("\\Driver\\Ksword", "PDB-KSWORD", 0xFFFFF80100000000ULL);
    const NodeIdentity kImage = fileIdentity("C:\\Windows\\System32\\drivers\\ksword.sys", 0xA1B2,
                                             "file-ksword");
    const NodeIdentity kService = serviceIdentity(kBoot, "KswordArk");

    graph.addNode(makeNode(kDevice, "\\Device\\Ksword0", "ev-device", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kDriverObject, "\\Driver\\Ksword", "ev-driver", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kImage, "ksword.sys", "ev-image", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kService, "KswordArk", "ev-service", NodeLifecycle::kObserved));

    graph.addEdge(makeEdge(EdgeKind::kDeviceOf, kDevice.nodeKey(), kDriverObject.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-device", "rule.deviceOf"));
    graph.addEdge(makeEdge(EdgeKind::kImageOf, kDriverObject.nodeKey(), kImage.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-image", "rule.imageOf"));
    graph.addEdge(makeEdge(EdgeKind::kServiceOf, kImage.nodeKey(), kService.nodeKey(),
                           EdgeCertainty::kCandidate, "ev-service", "rule.serviceOf"));

    graph.declareRelationCoverage(EdgeKind::kDeviceOf, ObjectKind::kDriver,
                                  fullySuccessfulCoverage(1, "ev-device"));
    graph.declareRelationCoverage(EdgeKind::kImageOf, ObjectKind::kFile,
                                  fullySuccessfulCoverage(1, "ev-image"));
    graph.declareRelationCoverage(EdgeKind::kServiceOf, ObjectKind::kService,
                                  fullySuccessfulCoverage(1, "ev-service"));

    ChainOptions options;
    const InvestigationChain kChain =
        buildChain(graph, ChainKind::kDeviceToService, kDevice.nodeKey(), options);
    s.expect(kChain.steps.size() == 4U && kChain.complete(),
             L"G-03 the device chain reaches the service in four steps");
    s.expect(kChain.steps[1].relationFromPrevious == EdgeKind::kDeviceOf &&
                 kChain.steps[2].relationFromPrevious == EdgeKind::kImageOf &&
                 kChain.steps[3].relationFromPrevious == EdgeKind::kServiceOf,
             L"G-03 each device-chain hop names its own relation kind rather than a generic link");
    s.expect(kChain.steps[3].nodeIds.size() == 1U && kChain.steps[3].nodeIds[0] == kService.nodeKey(),
             L"G-03 the device chain ends on the service node id, usable by every other view");
    s.expect(kChain.everyPresentStepOpensSource(),
             L"G-03 every device-chain step can open its source detail");

    // If the middle link is denied, report AccessDenied for that cycle and 'previous link missing' for the next.
    EntityGraph denied;
    denied.addNode(makeNode(kDevice, "\\Device\\Ksword0", "ev-device", NodeLifecycle::kObserved));
    denied.addNode(makeNode(kDriverObject, "\\Driver\\Ksword", "ev-driver", NodeLifecycle::kObserved));
    denied.addEdge(makeEdge(EdgeKind::kDeviceOf, kDevice.nodeKey(), kDriverObject.nodeKey(),
                            EdgeCertainty::kConfirmed, "ev-device", "rule.deviceOf"));
    denied.declareRelationCoverage(EdgeKind::kDeviceOf, ObjectKind::kDriver,
                                   fullySuccessfulCoverage(1, "ev-device"));
    denied.declareRelationCoverage(EdgeKind::kImageOf, ObjectKind::kFile,
                                   failedCoverage(CollectionStatus::kAccessDenied, "NTSTATUS",
                                                  0xC0000022ULL, "STATUS_ACCESS_DENIED"));
    const InvestigationChain kDeniedChain =
        buildChain(denied, ChainKind::kDeviceToService, kDevice.nodeKey(), options);
    s.expect(kDeniedChain.steps[2].availability == StepAvailability::kMissingAccessDenied,
             L"G-03 an access-denied image lookup is reported as denied, not as no image");
    s.expect(kDeniedChain.steps[2].outcome.nativeCode == OptionalU64::of(0xC0000022ULL) &&
                 kDeniedChain.steps[2].outcome.nativeCodeDomain == "NTSTATUS",
             L"G-03 the denied step keeps the original NTSTATUS code and domain");
    s.expect(kDeniedChain.steps[3].availability == StepAvailability::kMissingPreviousStepMissing,
             L"G-03 the service step reports that its predecessor is missing, not that services were absent");
    s.expect(kDeniedChain.missingStepCount() == 2U,
             L"G-03 the broken device chain reports exactly two missing links");

    // Two branches: unsupported and timeout.
    EntityGraph unsupported;
    unsupported.addNode(makeNode(kDevice, "\\Device\\Ksword0", "ev-device", NodeLifecycle::kObserved));
    unsupported.declareRelationCoverage(EdgeKind::kDeviceOf, ObjectKind::kDriver,
                                        failedCoverage(CollectionStatus::kUnsupported, "WIN32",
                                                       50ULL, "ERROR_NOT_SUPPORTED"));
    s.expect(buildChain(unsupported, ChainKind::kDeviceToService, kDevice.nodeKey(), options)
                     .steps[1]
                     .availability == StepAvailability::kMissingUnsupported,
             L"G-03 an unsupported capability is its own state, not a collection failure");
    EntityGraph timedOut;
    timedOut.addNode(makeNode(kDevice, "\\Device\\Ksword0", "ev-device", NodeLifecycle::kObserved));
    timedOut.declareRelationCoverage(EdgeKind::kDeviceOf, ObjectKind::kDriver,
                                     failedCoverage(CollectionStatus::kTimeout, "WIN32", 1460ULL,
                                                    "ERROR_TIMEOUT"));
    const ChainStep kTimeoutStep =
        buildChain(timedOut, ChainKind::kDeviceToService, kDevice.nodeKey(), options).steps[1];
    s.expect(kTimeoutStep.availability == StepAvailability::kMissingCollectionFailed &&
                 kTimeoutStep.outcome.status == CollectionStatus::kTimeout,
             L"G-03 a timeout is a collection failure whose original status stays readable");
}

void testConnectionChain(ksword_tests::Suite& s) {
    EntityGraph graph;
    const NodeIdentity kConnection = connectionIdentity(kBoot, 51000, 1000, 2000);
    const NodeIdentity kProcess = processIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity kTimeline = timelineIdentity("tl-000042");

    graph.addNode(makeNode(kConnection, "10.0.0.5:51000", "ev-conn", NodeLifecycle::kEnded));
    graph.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kTimeline, "connect", "ev-timeline", NodeLifecycle::kObserved));

    // Process owns connection: the edge direction is Process -> Connection.
    graph.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kConnection.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-conn", "rule.socketOwner"));
    graph.addEdge(makeEdge(EdgeKind::kTimelineEntry, kProcess.nodeKey(), kTimeline.nodeKey(),
                           EdgeCertainty::kCandidate, "ev-timeline", "rule.timeline"));
    graph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                  fullySuccessfulCoverage(1, "ev-conn"));
    graph.declareRelationCoverage(EdgeKind::kTimelineEntry, ObjectKind::kUnknown,
                                  fullySuccessfulCoverage(1, "ev-timeline"));

    ChainOptions options;
    const InvestigationChain kChain =
        buildChain(graph, ChainKind::kConnectionToTimeline, kConnection.nodeKey(), options);
    s.expect(kChain.steps.size() == 3U && kChain.complete(),
             L"G-03 the connection chain reaches the timeline in three steps");
    s.expect(kChain.steps[1].nodeIds.size() == 1U && kChain.steps[1].nodeIds[0] == kProcess.nodeKey(),
             L"G-03 the connection resolves to the owning process instance, not to a bare pid");
    s.expect(kChain.steps[2].expectedCategory == NodeCategory::kTimelineEntry &&
                 kChain.steps[2].nodeIds.size() == 1U,
             L"G-03 the timeline step reaches a timeline record rather than a system object");

    // Edges in the reverse direction must not be treated as the same hop.
    EntityGraph reversed;
    reversed.addNode(makeNode(kConnection, "10.0.0.5:51000", "ev-conn", NodeLifecycle::kEnded));
    reversed.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    reversed.addEdge(makeEdge(EdgeKind::kOwns, kConnection.nodeKey(), kProcess.nodeKey(),
                              EdgeCertainty::kConfirmed, "ev-conn", "rule.reversed"));
    reversed.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                     fullySuccessfulCoverage(1, "ev-conn"));
    s.expect(buildChain(reversed, ChainKind::kConnectionToTimeline, kConnection.nodeKey(), options)
                     .steps[1]
                     .availability == StepAvailability::kMissingNoData,
             L"G-03 an edge pointing the other way is not walked backwards to fake a hop");

    // Timeline source is not supported.
    EntityGraph noTimeline;
    noTimeline.addNode(makeNode(kConnection, "10.0.0.5:51000", "ev-conn", NodeLifecycle::kEnded));
    noTimeline.addNode(makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved));
    noTimeline.addEdge(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kConnection.nodeKey(),
                                EdgeCertainty::kConfirmed, "ev-conn", "rule.socketOwner"));
    noTimeline.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                       fullySuccessfulCoverage(1, "ev-conn"));
    noTimeline.declareRelationCoverage(EdgeKind::kTimelineEntry, ObjectKind::kUnknown,
                                       failedCoverage(CollectionStatus::kUnsupported, "WIN32", 50ULL,
                                                      "ERROR_NOT_SUPPORTED"));
    const InvestigationChain kPartial =
        buildChain(noTimeline, ChainKind::kConnectionToTimeline, kConnection.nodeKey(), options);
    s.expect(kPartial.steps[2].availability == StepAvailability::kMissingUnsupported &&
                 kPartial.missingStepCount() == 1U && !kPartial.complete(),
             L"G-03 a missing timeline source leaves the chain explicitly incomplete");

    // A default-constructed chain must not be read as 'complete'.
    InvestigationChain empty;
    s.expect(!empty.complete() && !empty.everyPresentStepOpensSource(),
             L"G-03 a default-constructed chain is never complete");
}

// ---------------------------------------------------------------------------
// G-04: Bounded unwind
// ---------------------------------------------------------------------------
void testBoundedExpansion(ksword_tests::Suite& s) {
    // Manual calculation target: one central node + 12 one-hop neighbors + 12 two-hop nodes.
    EntityGraph graph;
    const NodeIdentity kRoot = processIdentity(kBoot, 1000, 111, "root.exe");
    graph.addNode(makeNode(kRoot, "root.exe", "ev-root", NodeLifecycle::kObserved));
    std::vector<std::string> firstHop;
    std::vector<std::string> secondHop;
    for (std::uint64_t i = 0; i < 12; ++i) {
        const NodeIdentity kNear = threadIdentity(kBoot, 1000, 111, 2000 + i, 300 + i);
        graph.addNode(makeNode(kNear, "near", "ev-near", NodeLifecycle::kObserved));
        firstHop.push_back(kNear.nodeKey());
        graph.addEdge(makeEdge(EdgeKind::kOwns, kRoot.nodeKey(), kNear.nodeKey(),
                               EdgeCertainty::kConfirmed, "ev-near", "rule.owns"));

        const NodeIdentity kFar = handleIdentity(kBoot, 1000, 111, 0x100 + i, "File");
        graph.addNode(makeNode(kFar, "far", "ev-far", NodeLifecycle::kObserved));
        secondHop.push_back(kFar.nodeKey());
        graph.addEdge(makeEdge(EdgeKind::kOpens, kNear.nodeKey(), kFar.nodeKey(),
                               EdgeCertainty::kCandidate, "ev-far", "rule.opens"));
    }
    s.expect(graph.nodeCount() == 25U && graph.edgeCount() == 24U,
             L"G-04 the fixture holds 25 nodes and 24 edges as constructed");

    // Default: Only target + one hop.
    ExpansionRequest request;
    request.rootNodeIds.push_back(kRoot.nodeKey());
    const ExpansionResult kOneHop = expandGraph(graph, request);
    s.expect(kOneHop.loadedNodes == 13U && kOneHop.loadedEdges == 12U,
             L"G-04 the default expansion loads the target plus exactly one hop");
    s.expect(kOneHop.moreAvailable && kOneHop.hopLimitHit && !kOneHop.nodeLimitHit,
             L"G-04 stopping at the hop budget is reported as a hop limit, not a node limit");
    s.expect(!kOneHop.totalKnownNodes.present && !kOneHop.totalKnownEdges.present,
             L"G-04 the total is unknown while more remains, and is not faked from the loaded count");
    s.expect(contains(kOneHop.limitationKeys, "graph.expand.totalUnknown") &&
                 contains(kOneHop.limitationKeys, "graph.expand.moreAvailable"),
             L"G-04 the result says out loud that more is available and the total is unknown");
    s.expect(kOneHop.nodeIds.size() == 13U && kOneHop.edgeIds.size() == 12U,
             L"G-04 the id lists match the loaded counts exactly");
    s.expect(!kOneHop.coverage.fullyCovered(),
             L"G-04 a partial expansion never accounts itself as full coverage");

    // Exceeds default limits but no explicit continuation requested -> clamp to default.
    ExpansionRequest greedy = request;
    greedy.limits.maxNodes = 5000;
    greedy.limits.maxEdges = 9000;
    greedy.limits.maxHops = 6;
    const ExpansionResult kClamped = expandGraph(graph, greedy);
    s.expect(kClamped.limitsClampedToDefault && kClamped.hopsClampedToDefault,
             L"G-04 raising the budget without asking to continue is clamped back to the default");
    s.expect(kClamped.loadedNodes == 13U,
             L"G-04 the clamped expansion still only loads the target plus one hop");

    // Explicitly request continuation -> traverse two hops fully.
    ExpansionRequest continued = greedy;
    continued.continueRequestedByUser = true;
    const ExpansionResult kFull = expandGraph(graph, continued);
    s.expect(!kFull.limitsClampedToDefault && !kFull.hopsClampedToDefault,
             L"G-04 an explicit continue is honoured");
    s.expect(kFull.loadedNodes == 25U && kFull.loadedEdges == 24U,
             L"G-04 continuing loads the whole reachable set, all 25 nodes and 24 edges");
    s.expect(!kFull.moreAvailable && kFull.totalKnownNodes == OptionalU64::of(25) &&
                 kFull.totalKnownEdges == OptionalU64::of(24),
             L"G-04 the total becomes known only once the traversal really finished");
    s.expect(kFull.coverage.fullyCovered(),
             L"G-04 a finished expansion accounts itself as full coverage");

    // Node limit hit: distinguish from hop limit.
    ExpansionRequest capped = request;
    capped.limits.maxNodes = 5;
    const ExpansionResult kSmall = expandGraph(graph, capped);
    s.expect(kSmall.loadedNodes == 5U && kSmall.nodeLimitHit && kSmall.moreAvailable,
             L"G-04 the node budget stops the expansion at exactly five nodes");
    s.expect(!kSmall.totalKnownNodes.present && kSmall.coverage.limitHit &&
                 kSmall.coverage.limit == OptionalU64::of(5),
             L"G-04 the account names the budget that actually stopped the scan");
    s.expect(kSmall.coverage.describeRemaining().rfind("limit-hit:", 0) == 0U,
             L"G-04 the remaining description leads with the stop reason");

    // Edge limit hit.
    ExpansionRequest edgeCapped = request;
    edgeCapped.limits.maxEdges = 4;
    const ExpansionResult kFewEdges = expandGraph(graph, edgeCapped);
    s.expect(kFewEdges.loadedEdges == 4U && kFewEdges.edgeLimitHit && kFewEdges.moreAvailable,
             L"G-04 the edge budget stops edge loading at exactly four edges");
    s.expect(kFewEdges.loadedNodes == 5U,
             L"G-04 the edge budget also stops pulling in nodes whose edge cannot be shown");

    // Filter and expand overlay: if only 'Opens' is selected, there are no edges in a single hop.
    ExpansionRequest filtered = request;
    filtered.filter.kinds.push_back(EdgeKind::kOpens);
    const ExpansionResult kOpensOnly = expandGraph(graph, filtered);
    s.expect(kOpensOnly.loadedNodes == 1U && kOpensOnly.loadedEdges == 0U,
             L"G-04 filtering to a relation the root does not have leaves only the root");
    s.expect(kOpensOnly.filteredEdgeCount == 12U,
             L"G-04 the filtered-out edges are counted separately from coverage gaps");
    s.expect(kOpensOnly.coverage.skipped == 0U,
             L"G-04 a user filter is not recorded as a collection gap");
    // New criterion: traversing the reachable set does not equal traversing the entire graph. Only 1 of the 25 saved nodes was
    // loaded, so the total remains unknown. The old assertion incorrectly claimed totalKnownNodes == 1, effectively conflating
    // loadedNodes with the total. A traversal that only completes one connected component would similarly claim the total is known.
    s.expect(!kOpensOnly.totalKnownNodes.present && !kOpensOnly.totalKnownEdges.present,
             L"G-04 a view that loaded 1 of the 25 saved nodes does not claim to know the total");
    s.expect(contains(kOpensOnly.limitationKeys, "graph.expand.totalUnknown"),
             L"G-04 the filtered view says out loud that the total is unknown");
    s.expect(!kOpensOnly.coverage.fullyCovered() &&
                 kOpensOnly.coverage.totalKnown == OptionalU64::of(25),
             L"G-04 the account measures itself against the saved graph, not against its own load count");

    // Disconnected connected component: cannot reach c/d from a; traversal hits a dead end but only sees half the graph.
    // Manual calculation: 4 nodes (a, b, c, d), 2 edges (a-b, c-d); starting from a, install 2 nodes and 1 edge.
    EntityGraph split;
    const NodeIdentity kSplitA = processIdentity(kBoot, 7001, 901, "a.exe");
    const NodeIdentity kSplitB = threadIdentity(kBoot, 7001, 901, 7101, 902);
    const NodeIdentity kSplitC = processIdentity(kBoot, 7002, 903, "c.exe");
    const NodeIdentity kSplitD = threadIdentity(kBoot, 7002, 903, 7102, 904);
    split.addNode(makeNode(kSplitA, "a.exe", "ev-a", NodeLifecycle::kObserved));
    split.addNode(makeNode(kSplitB, "tid 7101", "ev-b", NodeLifecycle::kObserved));
    split.addNode(makeNode(kSplitC, "c.exe", "ev-c", NodeLifecycle::kObserved));
    split.addNode(makeNode(kSplitD, "tid 7102", "ev-d", NodeLifecycle::kObserved));
    split.addEdge(makeEdge(EdgeKind::kOwns, kSplitA.nodeKey(), kSplitB.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-b", "rule.owns"));
    split.addEdge(makeEdge(EdgeKind::kOwns, kSplitC.nodeKey(), kSplitD.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-d", "rule.owns"));
    ExpansionRequest oneComponent;
    oneComponent.rootNodeIds.push_back(kSplitA.nodeKey());
    const ExpansionResult kComponent = expandGraph(split, oneComponent);
    s.expect(kComponent.loadedNodes == 2U && kComponent.loadedEdges == 1U &&
                 !kComponent.moreAvailable && kComponent.unsavedNeighbors.empty(),
             L"G-04 walking one connected component finishes without anything left to fetch");
    s.expect(!kComponent.totalKnownNodes.present && !kComponent.totalKnownEdges.present,
             L"G-04 finishing one component of a split graph still leaves the total unknown");
    s.expect(!kComponent.coverage.fullyCovered(),
             L"G-04 seeing half the saved nodes is never accounted as full coverage");
    s.expect(contains(kComponent.limitationKeys, "graph.expand.totalUnknown"),
             L"G-04 the split-graph view names the unknown total in its limitations");
    s.expect(summarizeGraph(split, EdgeFilter{}).nodeCount == 4U,
             L"G-04 the whole saved graph really holds twice what that view could see");

    // Repeated expand/collapse: results remain stable when the same request is executed repeatedly.
    const ExpansionResult kAgain = expandGraph(graph, request);
    s.expect(kAgain.nodeIds == kOneHop.nodeIds && kAgain.edgeIds == kOneHop.edgeIds &&
                 kAgain.loadedNodes == kOneHop.loadedNodes,
             L"G-04 expanding, collapsing and expanding again yields the identical view");

    // An empty request must not be interpreted as "fully covered".
    ExpansionRequest empty;
    const ExpansionResult kNothing = expandGraph(graph, empty);
    s.expect(kNothing.loadedNodes == 0U && !kNothing.totalKnownNodes.present &&
                 contains(kNothing.limitationKeys, "graph.expand.noRoots"),
             L"G-04 an expansion with no roots reports no roots instead of a complete empty view");

    // Edges blocked by the budget must be recorded. Manual calculation: root + 3
    // neighbors, 3 edges, maxEdges=1 -> 1 installed, 2 deferred, truncated is exactly 2.
    EntityGraph deferGraph;
    const NodeIdentity kDeferRoot = processIdentity(kBoot, 8000, 950, "defer.exe");
    deferGraph.addNode(makeNode(kDeferRoot, "defer.exe", "ev-defer", NodeLifecycle::kObserved));
    for (std::uint64_t i = 0; i < 3; ++i) {
        const NodeIdentity kLeaf = threadIdentity(kBoot, 8000, 950, 8100 + i, 960 + i);
        deferGraph.addNode(makeNode(kLeaf, "t", "ev-leaf", NodeLifecycle::kObserved));
        deferGraph.addEdge(makeEdge(EdgeKind::kOwns, kDeferRoot.nodeKey(), kLeaf.nodeKey(),
                                    EdgeCertainty::kConfirmed, "ev-leaf", "rule.owns"));
    }
    ExpansionRequest oneEdgeOnly;
    oneEdgeOnly.rootNodeIds.push_back(kDeferRoot.nodeKey());
    oneEdgeOnly.limits.maxEdges = 1;
    const ExpansionResult kDeferred = expandGraph(deferGraph, oneEdgeOnly);
    s.expect(kDeferred.loadedEdges == 1U && kDeferred.loadedNodes == 2U && kDeferred.edgeLimitHit,
             L"G-04 the one-edge budget loads exactly one edge and the node it brings in");
    s.expect(kDeferred.coverage.truncated == 2U,
             L"G-04 the two edges left behind by the budget are counted as truncated, not forgotten");
    s.expect(kDeferred.coverage.limitHit && kDeferred.coverage.limit == OptionalU64::of(1),
             L"G-04 the account names the edge budget that stopped the scan");

    // Root nodes already exceed the node budget: extra roots must not be silently dropped. Manual
    // calculation: 3 isolated nodes, maxNodes=2 -> 2 fit, hitting the limit, but more remain.
    EntityGraph rootsGraph;
    std::vector<std::string> rootKeys;
    for (std::uint64_t i = 0; i < 3; ++i) {
        const NodeIdentity kLone = processIdentity(kBoot, 9000 + i, 970 + i, "lone.exe");
        rootsGraph.addNode(makeNode(kLone, "lone.exe", "ev-lone", NodeLifecycle::kObserved));
        rootKeys.push_back(kLone.nodeKey());
    }
    std::sort(rootKeys.begin(), rootKeys.end());
    ExpansionRequest tooManyRoots;
    tooManyRoots.rootNodeIds = rootKeys;
    tooManyRoots.limits.maxNodes = 2;
    const ExpansionResult kDroppedRoot = expandGraph(rootsGraph, tooManyRoots);
    s.expect(kDroppedRoot.loadedNodes == 2U,
             L"G-04 a node budget smaller than the root list loads exactly the budget");
    s.expect(kDroppedRoot.nodeLimitHit && kDroppedRoot.moreAvailable,
             L"G-04 a root that did not fit in the budget is reported, never silently dropped");
    s.expect(!kDroppedRoot.totalKnownNodes.present &&
                 contains(kDroppedRoot.limitationKeys, "graph.expand.nodeLimitHit"),
             L"G-04 dropping a root keeps the total unknown and names the budget in the limitations");

    // When truncating, 'which part to keep' must be independent of the input order of roots: normalize roots before expansion.
    ExpansionRequest reversedRoots = tooManyRoots;
    reversedRoots.rootNodeIds.assign(rootKeys.rbegin(), rootKeys.rend());
    reversedRoots.rootNodeIds.push_back(rootKeys.front());  // Duplicate roots must not occupy an extra slot.
    const ExpansionResult kDroppedReversed = expandGraph(rootsGraph, reversedRoots);
    s.expect(kDroppedReversed.nodeIds == kDroppedRoot.nodeIds &&
                 kDroppedReversed.loadedNodes == 2U,
             L"G-04 handing the same roots in the opposite order truncates to the same two nodes");
}

// ---------------------------------------------------------------------------
// G-04: Performance with 10,000 nodes and 50,000 edges.
// ---------------------------------------------------------------------------
void testLargeDatasetPerformance(ksword_tests::Suite& s) {
    // Fixed structure: ring + chords. Node i points to (i + o) mod N, where o is one of five fixed offsets.
    // Therefore, the number of edges is exactly N * 5 = 50,000, and each node has a degree of exactly 10 (five outgoing and five incoming).
    // The five offsets and their negatives are distinct modulo 10000, and the difference between any two neighbors is not an offset.
    // Thus, the one-hop neighborhood contains exactly 1 + 10 = 11 nodes and 10 edges. These numbers were calculated on paper.
    constexpr std::size_t kNodes = 10000;
    const std::uint64_t kOffsets[5] = {1, 7, 113, 1237, 4999};

    const auto kBuildStart = std::chrono::steady_clock::now();
    EntityGraph graph;
    std::vector<std::string> ids;
    ids.reserve(kNodes);
    for (std::size_t i = 0; i < kNodes; ++i) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "node-%06zu", i);
        GraphNode node;
        node.nodeId = buffer;  // G-06: ID provided by saved data during session replay.
        node.identity.kind = ObjectKind::kProcess;
        node.identity.instanceTag = buffer;
        node.displayText = buffer;
        node.evidenceId = "ev-bulk";
        node.lifecycle = NodeLifecycle::kObserved;
        node.outcome = CollectionOutcome::success();
        graph.addNode(std::move(node));
        ids.emplace_back(buffer);
    }
    for (std::size_t i = 0; i < kNodes; ++i) {
        for (std::size_t k = 0; k < 5; ++k) {
            const std::size_t kTarget = (i + static_cast<std::size_t>(kOffsets[k])) % kNodes;
            GraphEdge edge;
            edge.kind = (k % 2 == 0) ? EdgeKind::kOwns : EdgeKind::kLoads;
            edge.direction = EdgeDirection::kFromTo;
            edge.fromNodeId = ids[i];
            edge.toNodeId = ids[kTarget];
            edge.certainty = EdgeCertainty::kCandidate;
            edge.evidenceRefs.emplace_back("ev-bulk");
            edge.ruleId = "rule.bulk";
            graph.addEdge(edge);
        }
    }
    const auto kBuildEnd = std::chrono::steady_clock::now();
    s.expect(graph.nodeCount() == 10000U && graph.edgeCount() == 50000U,
             L"G-04 the performance dataset really holds 10,000 nodes and 50,000 edges");

    // One-hop expansion: manually calculated 11 nodes and 10 edges.
    ExpansionRequest oneHop;
    oneHop.rootNodeIds.push_back(ids[0]);
    const ExpansionResult kFirstView = expandGraph(graph, oneHop);
    s.expect(kFirstView.loadedNodes == 11U && kFirstView.loadedEdges == 10U,
             L"G-04 one hop out of the ring-and-chord dataset is exactly 11 nodes and 10 edges");
    s.expect(kFirstView.moreAvailable && !kFirstView.totalKnownNodes.present,
             L"G-04 the one-hop view of the large dataset does not claim to know the total");

    // Repeatedly expand/collapse/filter. Collapse = discard previous results and re-expand.
    // Measure each expansion separately: Specification §7 L4 allocates a p95 ≤ 200 ms budget for the relationship view, which applies to
    // a **single** initial screen expansion. Dividing total duration by the number of rounds only reveals the average, not tail latency.
    std::vector<long long> ringRoundsUs;
    ringRoundsUs.reserve(400);
    const auto kLoopStart = std::chrono::steady_clock::now();
    std::uint64_t nodeChecksum = 0;
    for (std::size_t round = 0; round < 200; ++round) {
        ExpansionRequest request;
        request.rootNodeIds.push_back(ids[(round * 37U) % kNodes]);
        const auto kViewStart = std::chrono::steady_clock::now();
        const ExpansionResult kView = expandGraph(graph, request);
        ringRoundsUs.push_back(microsSince(kViewStart));
        nodeChecksum += kView.loadedNodes;

        ExpansionRequest filtered = request;
        filtered.filter.kinds.push_back(EdgeKind::kOwns);
        const auto kFilteredStart = std::chrono::steady_clock::now();
        const ExpansionResult kOwnsView = expandGraph(graph, filtered);
        ringRoundsUs.push_back(microsSince(kFilteredStart));
        nodeChecksum += kOwnsView.loadedNodes;
    }
    const auto kLoopEnd = std::chrono::steady_clock::now();
    // 11 + 7 = 18 per round: Owns retains only three families with offsets {1, 113, 4999}, with three entries each for incoming and outgoing -> 6 neighbors.
    s.expect(nodeChecksum == 200U * 18U,
             L"G-04 every expand/collapse/filter round returns the hand-computed node count");

    // Full graph expansion: explicit request to continue is required.
    const auto kFullStart = std::chrono::steady_clock::now();
    ExpansionRequest whole;
    whole.rootNodeIds.push_back(ids[0]);
    whole.continueRequestedByUser = true;
    whole.limits.maxNodes = 20000;
    whole.limits.maxEdges = 100000;
    whole.limits.maxHops = 64;
    ExpansionResult wholeView;
    for (std::size_t round = 0; round < 10; ++round) {
        wholeView = expandGraph(graph, whole);
    }
    const auto kFullEnd = std::chrono::steady_clock::now();
    s.expect(wholeView.loadedNodes == 10000U && wholeView.loadedEdges == 50000U,
             L"G-04 a fully continued expansion reaches every node and every edge exactly once");
    s.expect(!wholeView.moreAvailable && wholeView.totalKnownNodes == OptionalU64::of(10000),
             L"G-04 the total is known only after the whole dataset was really walked");

    // Full graph conclusion and export.
    const auto kSummaryStart = std::chrono::steady_clock::now();
    EdgeFilter noFilter;
    const GraphConclusion kConclusion = summarizeGraph(graph, noFilter);
    const auto kSummaryEnd = std::chrono::steady_clock::now();
    s.expect(kConclusion.nodeCount == 10000U && kConclusion.edgeCountAfterFilter == 50000U &&
                 kConclusion.isolatedNodeCount == 0U,
             L"G-04 summarising the large dataset counts every node and edge and finds no isolates");

    // Second topology: star. Same 10,000 nodes, but all 49,995 edges are attached to a single hub.
    // In a ring-plus-chord dataset, every node has a constant degree of 10, representing the best case; a real session with 'a process owning tens of
    // thousands of handles' exhibits this shape. Testing only the ring structure fails to detect any degeneracy proportional to a single node's degree.
    const auto kHubBuildStart = std::chrono::steady_clock::now();
    EntityGraph hub;
    std::vector<std::string> hubIds;
    hubIds.reserve(kNodes);
    for (std::size_t i = 0; i < kNodes; ++i) {
        char buffer[32];
        std::snprintf(buffer, sizeof(buffer), "hub-%06zu", i);
        GraphNode node;
        node.nodeId = buffer;
        node.identity.kind = ObjectKind::kProcess;
        node.identity.instanceTag = buffer;
        node.displayText = buffer;
        node.evidenceId = "ev-hub";
        node.lifecycle = NodeLifecycle::kObserved;
        node.outcome = CollectionOutcome::success();
        hub.addNode(std::move(node));
        hubIds.emplace_back(buffer);
    }
    for (std::size_t i = 1; i < kNodes; ++i) {
        for (std::size_t k = 0; k < 5; ++k) {
            char rule[24];
            std::snprintf(rule, sizeof(rule), "rule.hub.%zu", k);
            GraphEdge edge;
            edge.kind = EdgeKind::kOwns;
            edge.direction = EdgeDirection::kFromTo;
            edge.fromNodeId = hubIds[0];
            edge.toNodeId = hubIds[i];
            edge.certainty = EdgeCertainty::kCandidate;
            edge.evidenceRefs.emplace_back("ev-hub");
            edge.ruleId = rule;
            hub.addEdge(edge);
        }
    }
    const auto kHubBuildEnd = std::chrono::steady_clock::now();
    s.expect(hub.nodeCount() == 10000U && hub.edgeCount() == 49995U,
             L"G-04 the hub dataset really holds 10,000 nodes and 49,995 edges on one node");

    // Manual calculation: Default budget is 200 nodes / 500 edges. With each hub neighbor having 5 edges, the edge
    // budget is exhausted first: 500 / 5 = 100 neighbors + 1 hub = 101 nodes and 500 edges. The hit is on the edge
    // limit, not the node limit. These numbers come from the budget definition itself, not copied from a runtime run.
    std::vector<long long> hubRoundsUs;
    hubRoundsUs.reserve(100);
    ExpansionResult hubView;
    for (std::size_t round = 0; round < 100; ++round) {
        ExpansionRequest request;
        request.rootNodeIds.push_back(hubIds[0]);
        const auto kRoundStart = std::chrono::steady_clock::now();
        hubView = expandGraph(hub, request);
        hubRoundsUs.push_back(microsSince(kRoundStart));
    }
    s.expect(hubView.loadedNodes == 101U && hubView.loadedEdges == 500U,
             L"G-04 one hop out of the hub is exactly 101 nodes and 500 edges under the default budget");
    s.expect(hubView.edgeLimitHit && !hubView.nodeLimitHit && hubView.moreAvailable,
             L"G-04 the hub view is stopped by the edge budget and says so");
    s.expect(!hubView.totalKnownNodes.present,
             L"G-04 a budget-stopped hub view never claims to know the total");

    const auto kMs = [](std::chrono::steady_clock::time_point a,
                       std::chrono::steady_clock::time_point b) {
        return static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count());
    };
    const auto kP95Us = [](std::vector<long long> samples) {
        if (samples.empty()) {
            return static_cast<long long>(-1);  // No sample is 'very fast'.
        }
        std::sort(samples.begin(), samples.end());
        std::size_t index = (samples.size() * 95U) / 100U;
        if (index >= samples.size()) {
            index = samples.size() - 1;
        }
        return samples[index];
    };
    const long long kBuildMs = kMs(kBuildStart, kBuildEnd);
    const long long kLoopMs = kMs(kLoopStart, kLoopEnd);
    const long long kFullMs = kMs(kFullStart, kFullEnd);
    const long long kSummaryMs = kMs(kSummaryStart, kSummaryEnd);
    const long long kHubBuildMs = kMs(kHubBuildStart, kHubBuildEnd);
    const long long kRingP95Us = kP95Us(ringRoundsUs);
    const long long kHubP95Us = kP95Us(hubRoundsUs);
    std::wprintf(L"    [G-04 perf] build ring=%lldms hub=%lldms  400 ring rounds=%lldms "
                 L"(p95=%lldus)  100 hub rounds p95=%lldus  10 full walks=%lldms  "
                 L"summarize=%lldms\n",
                 kBuildMs, kHubBuildMs, kLoopMs, kRingP95Us, kHubP95Us, kFullMs, kSummaryMs);

    // Spec §7 L4: Relationship view p95 ≤ 200 ms. The threshold is set right at the budget limit, not at 15 seconds—a 15-second
    // threshold is 75 times looser than the budget, meaning any complexity degradation within that 75x range would go undetected.
    constexpr long long kViewBudgetUs = 200000;
    s.expect(kRingP95Us >= 0 && kRingP95Us < kViewBudgetUs,
             L"G-04 the p95 of a single bounded expansion on the ring dataset is inside the 200 ms view budget");
    s.expect(kHubP95Us >= 0 && kHubP95Us < kViewBudgetUs,
             L"G-04 the p95 of a single bounded expansion on the hub dataset is inside the 200 ms view budget");
    // Note: These three items are not in the initial screen view. Neither graph construction nor 'user explicitly requests traversing the full
    // graph' are subject to the L4 200 ms constraint, but they must still remain linear in complexity—O(V*E) would push them to tens of seconds.
    s.expect(kBuildMs < 2000, L"G-04 building the ring dataset stays linear, not quadratic");
    s.expect(kHubBuildMs < 2000, L"G-04 building the hub dataset stays linear, not quadratic");
    s.expect(kLoopMs < 2000, L"G-04 400 bounded expansions together stay well inside a second-scale budget");
    s.expect(kFullMs < 2000, L"G-04 ten user-requested full traversals stay linear in nodes and edges");
    s.expect(kSummaryMs < 1000, L"G-04 summarising the whole dataset stays linear in nodes and edges");
}

// ---------------------------------------------------------------------------
// G-05: Isolated and unknown do not equal anomalies.
// ---------------------------------------------------------------------------
void testIsolationStates(ksword_tests::Suite& s) {
    EntityGraph graph;
    EdgeFilter noFilter;

    // A default-constructed report must not be interpreted as 'normal'.
    IsolationReport defaulted;
    s.expect(defaulted.state == IsolationState::kSourceNotCollected && !defaulted.isolated &&
                 !defaulted.nodeFound,
             L"G-05 a default isolation report is not a clean bill of health");

    // 1) Missing owner: source fully collected, object exists, but no ownership edge.
    NodeIdentity ownerless = processIdentity(kBoot, 2000, 500, "orphan.exe");
    GraphNode ownerlessNode = makeNode(ownerless, "orphan.exe", "ev-orphan", NodeLifecycle::kObserved);
    ownerlessNode.ownerRelation = EdgeKind::kOwns;
    ownerlessNode.ownerKind = ObjectKind::kProcess;
    graph.addNode(ownerlessNode);
    graph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                  fullySuccessfulCoverage(4, "ev-parents"));

    // 2) Object unloaded.
    NodeIdentity unloaded = driverIdentity("C:\\Windows\\System32\\drivers\\gone.sys", "PDB-GONE",
                                           0xFFFFF80200000000ULL);
    GraphNode unloadedNode = makeNode(unloaded, "gone.sys", "ev-gone", NodeLifecycle::kEnded);
    unloadedNode.ownerRelation = EdgeKind::kOwns;
    unloadedNode.ownerKind = ObjectKind::kProcess;
    graph.addNode(unloadedNode);

    // 3) Source not collected.
    NodeIdentity uncollected = handleIdentity(kBoot, 2000, 500, 0x44, "Key");
    GraphNode uncollectedNode = makeNode(uncollected, "handle 0x44", "ev-handle",
                                         NodeLifecycle::kObserved);
    uncollectedNode.ownerRelation = EdgeKind::kOpens;
    uncollectedNode.ownerKind = ObjectKind::kFile;  // Never declared override.
    graph.addNode(uncollectedNode);

    // 4) Actual inconsistency.
    NodeIdentity conflicting = processIdentity(kBoot, 3000, 600, "conflict.exe");
    GraphNode conflictingNode = makeNode(conflicting, "conflict.exe", "ev-conflict",
                                         NodeLifecycle::kObserved);
    conflictingNode.ownerRelation = EdgeKind::kOwns;
    conflictingNode.ownerKind = ObjectKind::kProcess;
    conflictingNode.inconsistencyObserved = true;
    conflictingNode.inconsistencyEvidenceIds.emplace_back("ev-crossview-7");
    graph.addNode(conflictingNode);

    // 5) Nodes with edges: not isolated.
    NodeIdentity connectedA = processIdentity(kBoot, 4000, 700, "a.exe");
    NodeIdentity connectedB = threadIdentity(kBoot, 4000, 700, 4100, 701);
    graph.addNode(makeNode(connectedA, "a.exe", "ev-a", NodeLifecycle::kObserved));
    graph.addNode(makeNode(connectedB, "tid 4100", "ev-b", NodeLifecycle::kObserved));
    graph.addEdge(makeEdge(EdgeKind::kOwns, connectedA.nodeKey(), connectedB.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-b", "rule.owns"));

    // 6) Owner source denied: Never claim 'no owner exists' just because the 'owner edge' was not observed.
    NodeIdentity denied = processIdentity(kBoot, 5000, 800, "denied.exe");
    GraphNode deniedNode = makeNode(denied, "denied.exe", "ev-denied", NodeLifecycle::kObserved);
    deniedNode.ownerRelation = EdgeKind::kLoads;
    deniedNode.ownerKind = ObjectKind::kModule;
    graph.addNode(deniedNode);
    graph.declareRelationCoverage(EdgeKind::kLoads, ObjectKind::kModule,
                                  failedCoverage(CollectionStatus::kAccessDenied, "NTSTATUS",
                                                 0xC0000022ULL, "STATUS_ACCESS_DENIED"));

    // 7) The owner source only covers a partial set: similarly insufficient to confirm 'no owner exists'.
    NodeIdentity halfSeen = processIdentity(kBoot, 6000, 900, "partial.exe");
    GraphNode halfSeenNode = makeNode(halfSeen, "partial.exe", "ev-partial", NodeLifecycle::kObserved);
    halfSeenNode.ownerRelation = EdgeKind::kMaps;
    halfSeenNode.ownerKind = ObjectKind::kFile;
    graph.addNode(halfSeenNode);
    RelationCoverage halfCoverage = fullySuccessfulCoverage(9, "ev-maps");
    halfCoverage.outcome.status = CollectionStatus::kPartial;
    halfCoverage.coverage.succeeded = 3;
    graph.declareRelationCoverage(EdgeKind::kMaps, ObjectKind::kFile, halfCoverage);

    const IsolationReport kDeniedReport = classifyIsolation(graph, denied.nodeKey(), noFilter);
    s.expect(kDeniedReport.isolated && kDeniedReport.state == IsolationState::kSourceNotCollected,
             L"G-05 a denied owner lookup is never reported as a genuinely missing owner");
    s.expect(kDeniedReport.ownerLookupOutcome.status == CollectionStatus::kAccessDenied &&
                 kDeniedReport.ownerLookupOutcome.nativeCode == OptionalU64::of(0xC0000022ULL),
             L"G-05 the denied owner lookup keeps its original NTSTATUS instead of collapsing");
    const IsolationReport kPartialReport = classifyIsolation(graph, halfSeen.nodeKey(), noFilter);
    s.expect(kPartialReport.isolated && kPartialReport.state == IsolationState::kSourceNotCollected,
             L"G-05 a partially covered owner lookup is never reported as a missing owner");
    s.expect(kPartialReport.ownerLookupOutcome.status == CollectionStatus::kPartial,
             L"G-05 the partially covered owner lookup keeps its partial status");

    const IsolationReport kOwnerMissing = classifyIsolation(graph, ownerless.nodeKey(), noFilter);
    s.expect(kOwnerMissing.isolated && kOwnerMissing.state == IsolationState::kOwnerMissing,
             L"G-05 a live object whose owner source was fully collected is owner-missing");
    s.expect(kOwnerMissing.rawEvidenceAvailable && kOwnerMissing.evidenceId == "ev-orphan",
             L"G-05 an isolated node still points at its own raw evidence");
    s.expect(kOwnerMissing.explanationKey == "graph.isolation.ownerMissing",
             L"G-05 the owner-missing state carries its own explanation key");

    const IsolationReport kUnloadedReport = classifyIsolation(graph, unloaded.nodeKey(), noFilter);
    s.expect(kUnloadedReport.isolated && kUnloadedReport.state == IsolationState::kObjectUnloaded,
             L"G-05 an unloaded object having no current relation is its own state");

    const IsolationReport kUncollectedReport =
        classifyIsolation(graph, uncollected.nodeKey(), noFilter);
    s.expect(kUncollectedReport.isolated &&
                 kUncollectedReport.state == IsolationState::kSourceNotCollected,
             L"G-05 a node whose owner source was never collected is not owner-missing");
    s.expect(kUncollectedReport.ownerLookupOutcome.status == CollectionStatus::kNotCollected,
             L"G-05 the not-collected state keeps the original collection status");

    const IsolationReport kConflictReport = classifyIsolation(graph, conflicting.nodeKey(), noFilter);
    s.expect(kConflictReport.isolated &&
                 kConflictReport.state == IsolationState::kObservedInconsistency,
             L"G-05 an observed inconsistency is reported as such and not as a missing owner");
    s.expect(kConflictReport.inconsistencyEvidenceIds.size() == 1U &&
                 kConflictReport.inconsistencyEvidenceIds[0] == "ev-crossview-7",
             L"G-05 the inconsistency state carries the evidence that recorded it");

    const IsolationReport kConnectedReport = classifyIsolation(graph, connectedA.nodeKey(), noFilter);
    s.expect(!kConnectedReport.isolated && kConnectedReport.state == IsolationState::kNotIsolated &&
                 kConnectedReport.edgeCountAfterFilter == 1U,
             L"G-05 a node with an edge is not isolated");

    // Unsaved node.
    const IsolationReport kUnknownNode = classifyIsolation(graph, "no-such-node", noFilter);
    s.expect(!kUnknownNode.nodeFound && kUnknownNode.state == IsolationState::kSourceNotCollected,
             L"G-05 asking about a node that was never saved does not produce a clean verdict");

    // Isolation caused by filtering must not be misinterpreted as anything other than missing sources: the reason must remain explainable even after edges are filtered out.
    EdgeFilter opensOnly;
    opensOnly.kinds.push_back(EdgeKind::kOpens);
    const IsolationReport kFilteredOut = classifyIsolation(graph, connectedA.nodeKey(), opensOnly);
    s.expect(kFilteredOut.isolated && kFilteredOut.edgeCountBeforeFilter == 1U &&
                 kFilteredOut.edgeCountAfterFilter == 0U,
             L"G-05 a node hidden by the current filter reports both edge counts");
    s.expect(kFilteredOut.rawEvidenceAvailable,
             L"G-05 a node isolated only by the filter can still open its raw evidence");

    // Full graph statistics: one of each of the four types, with no 'no edges implies anomaly' conclusions.
    const GraphConclusion kConclusion = summarizeGraph(graph, noFilter);
    s.expect(kConclusion.isolatedNodeCount == 6U && kConclusion.ownerMissingCount == 1U &&
                 kConclusion.unloadedCount == 1U && kConclusion.sourceNotCollectedCount == 3U &&
                 kConclusion.inconsistencyCount == 1U,
             L"G-05 the four isolation states are counted separately with the right node in each");
    s.expect(kConclusion.conclusion == AnalysisConclusion::kNoEvidence,
             L"G-05 with no session envelope the conclusion is no-evidence, never a clean result");

    // Success but no account fields filled -> still not 'definitely no owner'. This is the positive absence criterion for G-05:
    // Only Success **plus** the positive coverage evidence provided by the accounting is sufficient.
    EntityGraph blankAccount;
    const NodeIdentity kAccounted = processIdentity(kBoot, 7800, 1200, "accounted.exe");
    GraphNode accountedNode = makeNode(kAccounted, "accounted.exe", "ev-accounted",
                                       NodeLifecycle::kObserved);
    accountedNode.ownerRelation = EdgeKind::kOwns;
    accountedNode.ownerKind = ObjectKind::kProcess;
    blankAccount.addNode(accountedNode);
    RelationCoverage blankCoverage;
    blankCoverage.outcome = CollectionOutcome::success();  // Account fields are empty.
    blankAccount.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess, blankCoverage);
    const IsolationReport kBlankReport =
        classifyIsolation(blankAccount, kAccounted.nodeKey(), noFilter);
    s.expect(kBlankReport.isolated && kBlankReport.state == IsolationState::kSourceNotCollected,
             L"G-05 a successful owner lookup with an empty account is not proof that there is no owner");
    s.expect(kBlankReport.ownerLookupOutcome.status == CollectionStatus::kSuccess,
             L"G-05 that verdict keeps the original successful status instead of rewriting it");

    // If ownerRelation is not filled, it equals 'Source not collected', and it must not be overridden by a declaration unrelated to it.
    EntityGraph unlabelledGraph;
    const NodeIdentity kUnlabelled = processIdentity(kBoot, 7700, 1100, "unlabelled.exe");
    unlabelledGraph.addNode(makeNode(kUnlabelled, "unlabelled.exe", "ev-unlabelled",
                                     NodeLifecycle::kObserved));  // ownerRelation remains Unknown
    const NodeIdentity kLabelled = processIdentity(kBoot, 7701, 1101, "labelled.exe");
    GraphNode labelledNode = makeNode(kLabelled, "labelled.exe", "ev-labelled",
                                      NodeLifecycle::kObserved);
    labelledNode.ownerRelation = EdgeKind::kOwns;
    labelledNode.ownerKind = ObjectKind::kProcess;
    unlabelledGraph.addNode(labelledNode);
    unlabelledGraph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                            fullySuccessfulCoverage(2, "ev-parents"));
    const IsolationReport kUnlabelledBefore =
        classifyIsolation(unlabelledGraph, kUnlabelled.nodeKey(), noFilter);
    s.expect(kUnlabelledBefore.isolated &&
                 kUnlabelledBefore.state == IsolationState::kSourceNotCollected &&
                 kUnlabelledBefore.explanationKey == "graph.isolation.ownerRelationNotDeclared",
             L"G-05 a node that never named its owner relation is treated as not collected, with its own explanation");
    s.expect(kUnlabelledBefore.ownerLookupOutcome.status == CollectionStatus::kNotCollected,
             L"G-05 an unnamed owner relation has no collection outcome to report");
    RelationCoverage blanket = fullySuccessfulCoverage(1, "ev-anything");
    s.expect(!unlabelledGraph.declareRelationCoverage(EdgeKind::kUnknown, ObjectKind::kUnknown,
                                                      blanket),
             L"G-05 an unnamed relation cannot be declared covered at all");
    const IsolationReport kUnlabelledAfter =
        classifyIsolation(unlabelledGraph, kUnlabelled.nodeKey(), noFilter);
    s.expect(kUnlabelledAfter.state == IsolationState::kSourceNotCollected &&
                 kUnlabelledAfter.explanationKey == "graph.isolation.ownerRelationNotDeclared",
             L"G-05 declaring coverage for an unnamed relation never flips a node into owner-missing");
    s.expect(classifyIsolation(unlabelledGraph, kLabelled.nodeKey(), noFilter).state ==
                 IsolationState::kOwnerMissing,
             L"G-05 the node that did name its owner relation still reads its own declared coverage");

    // If there is observation but no inconsistency -> NoDifferenceObserved; if there is an inconsistency -> DifferenceObserved.
    EntityGraph observed;
    EvidenceEnvelope envelope;
    envelope.outcome = CollectionOutcome::success();
    envelope.coverage.totalKnown = OptionalU64::of(1);
    envelope.coverage.succeeded = 1;
    observed.setEnvelope(envelope);
    observed.addNode(makeNode(connectedA, "a.exe", "ev-a", NodeLifecycle::kObserved));
    observed.addNode(makeNode(connectedB, "tid 4100", "ev-b", NodeLifecycle::kObserved));
    observed.addEdge(makeEdge(EdgeKind::kOwns, connectedA.nodeKey(), connectedB.nodeKey(),
                              EdgeCertainty::kConfirmed, "ev-b", "rule.owns"));
    s.expect(summarizeGraph(observed, noFilter).conclusion ==
                 AnalysisConclusion::kNoDifferenceObserved,
             L"G-05 a fully collected graph without conflicts observes no difference");
    EntityGraph observedConflict = observed;
    GraphNode conflictCopy = conflictingNode;
    observedConflict.addNode(conflictCopy);
    s.expect(summarizeGraph(observedConflict, noFilter).conclusion ==
                 AnalysisConclusion::kDifferenceObserved,
             L"G-05 only a recorded inconsistency drives the difference conclusion, not isolation");
}

// ---------------------------------------------------------------------------
// G-05: Isolation is not a difference; the gap counter must have non-zero test cases.
// ---------------------------------------------------------------------------
EvidenceEnvelope fullyObservedEnvelope() {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = "r0.graph";
    envelope.source.sourceGroup = "r0.graph";
    envelope.source.origin = SourceOrigin::kOfflineSample;
    envelope.outcome = CollectionOutcome::success();
    envelope.coverage.totalKnown = OptionalU64::of(3);
    envelope.coverage.succeeded = 3;
    envelope.evidenceId = "ev-session";
    return envelope;
}

void testIsolationDoesNotDriveConclusion(ksword_tests::Suite& s) {
    // This is the positive test case for rule G-05 'No 'no edges, no malice'': fully observed, graph contains only
    // isolated nodes, and no recorded inconsistencies exist — the conclusion must be 'no differences found'. Without this,
    // the change that elevates 'isolated nodes' directly to DifferenceObserved would fail to trigger any assertions.
    EdgeFilter noFilter;
    EntityGraph graph;
    graph.setEnvelope(fullyObservedEnvelope());
    graph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                  fullySuccessfulCoverage(3, "ev-parents"));

    const NodeIdentity kOrphan = processIdentity(kBoot, 1100, 210, "orphan.exe");
    GraphNode orphanNode = makeNode(kOrphan, "orphan.exe", "ev-orphan", NodeLifecycle::kObserved);
    orphanNode.ownerRelation = EdgeKind::kOwns;
    orphanNode.ownerKind = ObjectKind::kProcess;
    graph.addNode(orphanNode);

    const NodeIdentity kUngathered = processIdentity(kBoot, 1200, 220, "ungathered.exe");
    GraphNode ungatheredNode = makeNode(kUngathered, "ungathered.exe", "ev-ungathered",
                                        NodeLifecycle::kObserved);
    ungatheredNode.ownerRelation = EdgeKind::kLoads;   // Never declared override.
    ungatheredNode.ownerKind = ObjectKind::kModule;
    graph.addNode(ungatheredNode);

    const NodeIdentity kGone = driverIdentity("C:\\Windows\\System32\\drivers\\gone2.sys",
                                             "PDB-GONE2", 0xFFFFF80300000000ULL);
    GraphNode goneNode = makeNode(kGone, "gone2.sys", "ev-gone2", NodeLifecycle::kEnded);
    goneNode.ownerRelation = EdgeKind::kOwns;
    goneNode.ownerKind = ObjectKind::kProcess;
    graph.addNode(goneNode);

    const GraphConclusion kConclusion = summarizeGraph(graph, noFilter);
    s.expect(kConclusion.nodeCount == 3U && kConclusion.edgeCountBeforeFilter == 0U,
             L"G-05 the fixture is three nodes with no edge at all between them");
    s.expect(kConclusion.isolatedNodeCount == 3U && kConclusion.ownerMissingCount == 1U &&
                 kConclusion.sourceNotCollectedCount == 1U && kConclusion.unloadedCount == 1U,
             L"G-05 all three nodes are isolated and land in three different states");
    s.expect(kConclusion.inconsistencyCount == 0U,
             L"G-05 not one of them is a recorded inconsistency");
    s.expect(kConclusion.conclusion == AnalysisConclusion::kNoDifferenceObserved,
             L"G-05 a fully observed graph made entirely of isolated nodes still observes no difference");

    // Add another orphan node: count changes, conclusion remains unchanged.
    const NodeIdentity kAnotherOrphan = processIdentity(kBoot, 1300, 230, "orphan2.exe");
    GraphNode anotherOrphanNode = makeNode(kAnotherOrphan, "orphan2.exe", "ev-orphan2",
                                           NodeLifecycle::kObserved);
    anotherOrphanNode.ownerRelation = EdgeKind::kOwns;
    anotherOrphanNode.ownerKind = ObjectKind::kProcess;
    graph.addNode(anotherOrphanNode);
    const GraphConclusion kMore = summarizeGraph(graph, noFilter);
    s.expect(kMore.isolatedNodeCount == 4U && kMore.ownerMissingCount == 2U,
             L"G-05 the fourth isolated node really does move the counts");
    s.expect(kMore.conclusion == AnalysisConclusion::kNoDifferenceObserved,
             L"G-05 more isolated nodes never move the conclusion towards a difference");

    // Only recorded inconsistencies can drive conclusions.
    const NodeIdentity kConflicted = processIdentity(kBoot, 1400, 240, "conflict2.exe");
    GraphNode conflictedNode = makeNode(kConflicted, "conflict2.exe", "ev-conflict2",
                                        NodeLifecycle::kObserved);
    conflictedNode.inconsistencyObserved = true;
    conflictedNode.inconsistencyEvidenceIds.emplace_back("ev-crossview-9");
    graph.addNode(conflictedNode);
    const GraphConclusion kWithConflict = summarizeGraph(graph, noFilter);
    s.expect(kWithConflict.inconsistencyCount == 1U &&
                 kWithConflict.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"G-05 one recorded inconsistency is what moves the conclusion, and nothing else does");

    // Two non-zero cases for the "gap counters": insufficient identity + nodes with no original evidence.
    EntityGraph gaps;
    gaps.setEnvelope(fullyObservedEnvelope());
    GraphNode blind;
    blind.nodeId = "row-9";
    blind.identity.kind = ObjectKind::kProcess;     // No PID / creation time -> Unusable
    blind.identity.instanceTag = "row-9";
    blind.displayText = "unknown process";
    blind.evidenceId = "";                          // Unable to open the original evidence.
    blind.lifecycle = NodeLifecycle::kObserved;
    blind.outcome = CollectionOutcome::success();
    s.expect(gaps.addNode(blind) == NodeAdmission::kAcceptedNew,
             L"G-05 a record with only a discriminator still enters the graph");
    const GraphConclusion kGapConclusion = summarizeGraph(gaps, noFilter);
    s.expect(kGapConclusion.unusableIdentityNodeCount == 1U,
             L"G-08 the unusable-identity counter really counts an unusable identity");
    s.expect(kGapConclusion.nodesWithoutEvidenceCount == 1U,
             L"G-08 the missing-evidence counter really counts a node with no evidence id");
    s.expect(contains(kGapConclusion.limitationKeys, "graph.summary.unusableIdentityNodes") &&
                 contains(kGapConclusion.limitationKeys, "graph.summary.nodesWithoutEvidence"),
             L"G-08 both gaps show up in the limitation keys instead of staying silent");
    const IsolationReport kBlindReport = classifyIsolation(gaps, "row-9", noFilter);
    s.expect(kBlindReport.isolated && !kBlindReport.rawEvidenceAvailable,
             L"G-05 an isolated node with no evidence id cannot open any raw evidence");
    s.expect(kBlindReport.rawEvidenceMissingKey == "graph.isolation.noRawEvidence",
             L"G-05 that node says out loud that there is no raw evidence, rather than offering a dead button");
    s.expect(kBlindReport.evidenceId.empty(),
             L"G-05 and it does not invent an evidence id to point at");
}

// ---------------------------------------------------------------------------
// G-06: Offline expansion and cross-view consistency.
// ---------------------------------------------------------------------------
void testOfflineAndCrossView(ksword_tests::Suite& s) {
    EntityGraph graph;
    OfflineExpansionPolicy policy;
    policy.allowLiveQueries = false;
    policy.origin = DataOrigin::kSession;
    graph.setOfflinePolicy(policy);
    s.expect(!graph.offlinePolicy().allowLiveQueries &&
                 graph.offlinePolicy().origin == DataOrigin::kSession,
             L"G-06 an offline session never allows live queries");

    const NodeIdentity kSaved = processIdentity(kBoot, 1000, 111, "saved.exe");
    const NodeIdentity kAlsoSaved = threadIdentity(kBoot, 1000, 111, 2000, 222);
    graph.addNode(makeNode(kSaved, "saved.exe", "ev-saved", NodeLifecycle::kObserved));
    graph.addNode(makeNode(kAlsoSaved, "tid 2000", "ev-thread", NodeLifecycle::kObserved));
    graph.addEdge(makeEdge(EdgeKind::kOwns, kSaved.nodeKey(), kAlsoSaved.nodeKey(),
                           EdgeCertainty::kConfirmed, "ev-thread", "rule.owns"));

    // An edge pointing to a neighbor that has not been saved.
    const std::string kUnsavedId = processIdentity(kBoot, 1200, 150, "never-saved.exe").nodeKey();
    GraphEdge danglingEdge = makeEdge(EdgeKind::kCandidateOwner, kSaved.nodeKey(), kUnsavedId,
                                      EdgeCertainty::kCandidate, "ev-guess", "rule.candidateOwner");
    s.expect(edgeAdmissionAccepted(graph.addEdge(danglingEdge)),
             L"G-06 an edge to an unsaved neighbour is still recorded as a known relation");

    ExpansionRequest request;
    request.rootNodeIds.push_back(kSaved.nodeKey());
    const ExpansionResult kView = expandGraph(graph, request);
    s.expect(kView.liveQueriesIssued == 0U,
             L"G-06 offline expansion issues no live query at all");
    s.expect(kView.unsavedNeighbors.size() == 1U &&
                 kView.unsavedNeighbors[0].missingNodeId == kUnsavedId &&
                 kView.unsavedNeighbors[0].relation == EdgeKind::kCandidateOwner,
             L"G-06 the unsaved neighbour is recorded with the relation that pointed at it");
    s.expect(!contains(kView.nodeIds, kUnsavedId),
             L"G-06 an unsaved neighbour is never materialised as a node");
    s.expect(kView.loadedNodes == 2U && kView.loadedEdges == 1U,
             L"G-06 only the saved part of the neighbourhood is loaded");
    s.expect(!kView.totalKnownNodes.present && kView.coverage.skipped == 1U,
             L"G-06 an unsaved neighbour keeps the total unknown and shows up in the account");
    s.expect(contains(kView.limitationKeys, "graph.expand.unsavedNeighbors"),
             L"G-06 the limitation list names the unsaved neighbours");

    // Root node itself not saved.
    ExpansionRequest missingRoot;
    missingRoot.rootNodeIds.push_back("never-stored");
    const ExpansionResult kNoRoot = expandGraph(graph, missingRoot);
    s.expect(kNoRoot.loadedNodes == 0U && kNoRoot.unsavedNeighbors.size() == 1U &&
                 contains(kNoRoot.limitationKeys, "graph.expand.rootNotSaved"),
             L"G-06 an unsaved root is reported as not saved rather than as an empty graph");

    // Graph, list, details, and export references share the same ID set.
    EdgeFilter noFilter;
    const std::vector<EntityListRow> kRows = buildEntityList(graph, kView, noFilter,
                                                            EntityListOrder::kByNodeId);
    s.expect(kRows.size() == 2U, L"G-06 the list view holds exactly the loaded nodes");
    bool listMatchesGraph = true;
    for (const EntityListRow& row : kRows) {
        if (!contains(kView.nodeIds, row.nodeId)) {
            listMatchesGraph = false;
        }
        const NodeDetail kDetail = buildNodeDetail(graph, row.nodeId, noFilter);
        if (!kDetail.nodeFound || kDetail.nodeId != row.nodeId ||
            kDetail.evidenceId != row.evidenceId) {
            listMatchesGraph = false;
        }
    }
    s.expect(listMatchesGraph,
             L"G-06 list rows and node details use the same entity id and evidence id as the graph");

    const NodeDetail kRootDetail = buildNodeDetail(graph, kSaved.nodeKey(), noFilter);
    s.expect(kRootDetail.outgoingEdgeIds.size() == 2U && kRootDetail.incomingEdgeIds.empty(),
             L"G-06 the detail view separates outgoing from incoming relations");
    s.expect(kRootDetail.inferences.size() == 2U,
             L"G-08 the detail view can expand the rule behind every relation it shows");
    s.expect(!kRootDetail.isolation.isolated,
             L"G-06 the detail view carries the same isolation reading as the graph");

    const JsonValue kExported = exportGraph(graph, kView, noFilter);
    const JsonValue* exportedNodes = kExported.find("nodes");
    const JsonValue* exportedEdges = kExported.find("edges");
    s.expect(exportedNodes != nullptr && exportedNodes->asArray() != nullptr &&
                 exportedNodes->asArray()->size() == 2U,
             L"G-06 the export holds exactly the nodes of the exported view");
    s.expect(exportedEdges != nullptr && exportedEdges->asArray() != nullptr &&
                 exportedEdges->asArray()->size() == 1U,
             L"G-06 the export holds exactly the edges of the exported view");
    bool exportIdsMatch = true;
    if (exportedNodes != nullptr && exportedNodes->asArray() != nullptr) {
        for (const JsonValue& entry : *exportedNodes->asArray()) {
            const JsonValue* idValue = entry.find("nodeId");
            std::string id;
            if (idValue == nullptr || !idValue->tryGetString(id) || !contains(kView.nodeIds, id)) {
                exportIdsMatch = false;
            }
        }
    }
    s.expect(exportIdsMatch, L"G-06 exported node ids are the very ids the graph and list use");

    const JsonValue* exportedUnsaved = kExported.find("unsavedNeighbors");
    s.expect(exportedUnsaved != nullptr && exportedUnsaved->asArray() != nullptr &&
                 exportedUnsaved->asArray()->size() == 1U,
             L"G-06 the export states the unsaved neighbour instead of dropping it");
    const JsonValue* scope = kExported.find("scope");
    s.expect(scope != nullptr && scope->find("viewIsExpansionResult") != nullptr,
             L"G-06 the export says which scope its counts belong to");

    // The exported isolation entry describes the **observed data state**, not causality. The term "cause" is deliberately
    // avoided in the header file and must not appear in artifacts presented to reports or downstream consumers.
    const JsonValue* exportedIsolation = kExported.find("isolation");
    s.expect(exportedIsolation != nullptr && exportedIsolation->asArray() != nullptr &&
                 exportedIsolation->asArray()->size() == 2U,
             L"G-05 the export carries one isolation entry per exported node");
    if (exportedIsolation != nullptr && exportedIsolation->asArray() != nullptr &&
        !exportedIsolation->asArray()->empty()) {
        const JsonValue& firstIsolation = exportedIsolation->asArray()->front();
        const JsonObject* isolationFields = firstIsolation.asObject();
        std::vector<std::string> keys;
        if (isolationFields != nullptr) {
            for (const std::pair<std::string, JsonValue>& field : *isolationFields) {
                keys.push_back(field.first);
            }
        }
        const std::vector<std::string> kExpectedKeys = {
            "nodeId", "isolated", "state", "explanationKey", "rawEvidenceAvailable",
            "rawEvidenceMissingKey", "ownerLookupOutcome",
        };
        s.expect(keys == kExpectedKeys,
                 L"G-05 the exported isolation entry names a data state and nothing that reads as a cause");
        s.expect(firstIsolation.find("cause") == nullptr &&
                     firstIsolation.find("state") != nullptr,
                 L"G-05 the isolation field is called state, the word the header actually promises");
    }

    // IDs present in the view but not in the graph: skipping is allowed, but the count and content must not contradict each other.
    ExpansionResult ghostView = kView;
    ghostView.nodeIds.emplace_back("ghost-node");
    ghostView.edgeIds.emplace_back("ghost-edge");
    std::uint64_t missingRows = 0;
    const std::vector<EntityListRow> kGhostRows =
        buildEntityList(graph, ghostView, noFilter, EntityListOrder::kByNodeId, &missingRows);
    s.expect(kGhostRows.size() == 2U && missingRows == 1U,
             L"G-04 a list row whose node is gone from the graph is counted, not silently dropped");
    const JsonValue kGhostExport = exportGraph(graph, ghostView, noFilter);
    const JsonValue* ghostViewObject = kGhostExport.find("view");
    std::string exportedNodeCount;
    std::string missingNodeCount;
    std::string missingEdgeCount;
    if (ghostViewObject != nullptr) {
        const JsonValue* exportedNodes2 = ghostViewObject->find("exportedNodes");
        const JsonValue* missingNodes = ghostViewObject->find("viewNodeMissing");
        const JsonValue* missingEdges = ghostViewObject->find("viewEdgeMissing");
        if (exportedNodes2 != nullptr) {
            (void)exportedNodes2->tryGetString(exportedNodeCount);
        }
        if (missingNodes != nullptr) {
            (void)missingNodes->tryGetString(missingNodeCount);
        }
        if (missingEdges != nullptr) {
            (void)missingEdges->tryGetString(missingEdgeCount);
        }
    }
    s.expect(exportedNodeCount == "2" && missingNodeCount == "1" && missingEdgeCount == "1",
             L"G-04 the export states how many entries it actually wrote and how many it could not");
    const std::string kGhostText = writeJson(kGhostExport, 0);
    s.expect(kGhostText.find("graph.export.viewNodeMissing") != std::string::npos &&
                 kGhostText.find("graph.export.viewEdgeMissing") != std::string::npos,
             L"G-04 the export names the missing view entries in its own limitation keys");

    // Offline expansion sends no online queries even when there are unsaved neighbors, the budget is hit, and filtering is applied.
    ExpansionRequest pressured;
    pressured.rootNodeIds.push_back(kSaved.nodeKey());
    pressured.limits.maxNodes = 1;
    pressured.limits.maxEdges = 1;
    pressured.filter.kinds.push_back(EdgeKind::kOwns);
    pressured.filter.kinds.push_back(EdgeKind::kCandidateOwner);
    const ExpansionResult kPressuredView = expandGraph(graph, pressured);
    s.expect(kPressuredView.liveQueriesIssued == 0U,
             L"G-06 an expansion that runs out of budget still never issues a live query");
    s.expect(kPressuredView.moreAvailable && kPressuredView.loadedNodes == 1U,
             L"G-06 the pressured expansion really did hit its budget, so the check above is not vacuous");

    // No floating-point values; 64-bit quantities written as strings.
    const std::string kText = writeJson(kExported, 0);
    const JsonParseResult kReparsed = parseJson(kText);
    s.expect(kReparsed.ok(), L"G-06 the export round-trips through the lossless json reader");
    s.expect(kText.find("\"loadedNodes\":\"2\"") != std::string::npos,
             L"F-08 counts are exported as text so 64-bit values never pass through a double");
}

// ---------------------------------------------------------------------------
// G-08: The graph is an evidence view, not the ground truth for analysis.
// ---------------------------------------------------------------------------
struct GraphFixture final {
    std::vector<GraphNode> nodes;
    std::vector<GraphEdge> edges;
};

GraphFixture makeConclusionFixture() {
    GraphFixture fixture;
    const NodeIdentity kProcess = processIdentity(kBoot, 1000, 111, "worker.exe");
    const NodeIdentity kThread = threadIdentity(kBoot, 1000, 111, 2000, 222);
    const NodeIdentity kHandle = handleIdentity(kBoot, 1000, 111, 0x2C, "File");
    const NodeIdentity kOrphan = processIdentity(kBoot, 2000, 500, "orphan.exe");
    const NodeIdentity kEnded = driverIdentity("C:\\gone.sys", "PDB-GONE", 0x1000);
    const NodeIdentity kConflicted = processIdentity(kBoot, 3000, 600, "conflict.exe");

    GraphNode processNode = makeNode(kProcess, "worker.exe", "ev-proc", NodeLifecycle::kObserved);
    processNode.ownerRelation = EdgeKind::kOwns;
    processNode.ownerKind = ObjectKind::kProcess;
    GraphNode orphanNode = makeNode(kOrphan, "orphan.exe", "ev-orphan", NodeLifecycle::kObserved);
    orphanNode.ownerRelation = EdgeKind::kOwns;
    orphanNode.ownerKind = ObjectKind::kProcess;
    GraphNode endedNode = makeNode(kEnded, "gone.sys", "ev-gone", NodeLifecycle::kEnded);
    GraphNode conflictedNode = makeNode(kConflicted, "conflict.exe", "ev-conflict",
                                        NodeLifecycle::kObserved);
    conflictedNode.inconsistencyObserved = true;
    conflictedNode.inconsistencyEvidenceIds.emplace_back("ev-crossview-1");

    fixture.nodes.push_back(processNode);
    fixture.nodes.push_back(makeNode(kThread, "tid 2000", "ev-thread", NodeLifecycle::kObserved));
    fixture.nodes.push_back(makeNode(kHandle, "handle 0x2C", "ev-handle", NodeLifecycle::kObserved));
    fixture.nodes.push_back(orphanNode);
    fixture.nodes.push_back(endedNode);
    fixture.nodes.push_back(conflictedNode);

    fixture.edges.push_back(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kThread.nodeKey(),
                                     EdgeCertainty::kConfirmed, "ev-thread", "rule.owns"));
    fixture.edges.push_back(makeEdge(EdgeKind::kOwns, kProcess.nodeKey(), kHandle.nodeKey(),
                                     EdgeCertainty::kCandidate, "ev-handle", "rule.owns"));
    GraphEdge unknownCertainty = makeEdge(EdgeKind::kMaps, kProcess.nodeKey(), kHandle.nodeKey(),
                                          EdgeCertainty::kUnknown, "ev-map", "rule.maps");
    fixture.edges.push_back(unknownCertainty);
    return fixture;
}

EntityGraph buildFromFixture(const GraphFixture& fixture, bool reverseOrder) {
    EntityGraph graph;
    EvidenceEnvelope envelope;
    envelope.source.collectorId = "r0.graph";
    envelope.source.sourceGroup = "r0.graph";
    envelope.source.origin = SourceOrigin::kOfflineSample;
    envelope.outcome = CollectionOutcome::success();
    envelope.coverage.totalKnown = OptionalU64::of(6);
    envelope.coverage.succeeded = 6;
    envelope.evidenceId = "ev-session";
    graph.setEnvelope(envelope);
    graph.declareRelationCoverage(EdgeKind::kOwns, ObjectKind::kProcess,
                                  fullySuccessfulCoverage(6, "ev-parents"));

    if (reverseOrder) {
        for (std::size_t i = fixture.nodes.size(); i > 0; --i) {
            graph.addNode(fixture.nodes[i - 1]);
        }
        for (std::size_t i = fixture.edges.size(); i > 0; --i) {
            graph.addEdge(fixture.edges[i - 1]);
        }
    } else {
        for (const GraphNode& node : fixture.nodes) {
            graph.addNode(node);
        }
        for (const GraphEdge& edge : fixture.edges) {
            graph.addEdge(edge);
        }
    }
    return graph;
}

void testOrderIndependence(ksword_tests::Suite& s) {
    const GraphFixture kFixture = makeConclusionFixture();
    const EntityGraph kForward = buildFromFixture(kFixture, false);
    const EntityGraph kReversed = buildFromFixture(kFixture, true);
    EdgeFilter noFilter;

    const GraphConclusion kA = summarizeGraph(kForward, noFilter);
    const GraphConclusion kB = summarizeGraph(kReversed, noFilter);

    // First, hardcode the absolute values from the initial pass (calculated independently by hand), then compare the two passes; otherwise, simultaneous failures on both sides could escape detection.
    s.expect(kA.nodeCount == 6U, L"G-08 the fixture has six nodes");
    s.expect(kA.edgeCountBeforeFilter == 3U && kA.edgeCountAfterFilter == 3U,
             L"G-08 the fixture has three edges and no filter drops any of them");
    s.expect(kA.confirmedEdgeCount == 1U && kA.candidateEdgeCount == 1U &&
                 kA.unknownCertaintyEdgeCount == 1U,
             L"G-08 the fixture holds one confirmed, one candidate and one unknown-certainty edge");
    s.expect(kA.isolatedNodeCount == 3U, L"G-08 exactly three fixture nodes have no edge");
    s.expect(kA.ownerMissingCount == 1U && kA.unloadedCount == 1U && kA.inconsistencyCount == 1U &&
                 kA.sourceNotCollectedCount == 0U,
             L"G-08 the three isolated fixture nodes fall into three different states");
    s.expect(kA.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"G-08 the recorded inconsistency drives the fixture conclusion");
    s.expect(kA.unusableIdentityNodeCount == 0U && kA.nodesWithoutEvidenceCount == 0U,
             L"G-08 every fixture node has a usable identity and openable evidence");

    // Compare field by field: the result must be identical regardless of input order.
    s.expect(kA.conclusion == kB.conclusion, L"G-08 the conclusion field survives reordering");
    s.expect(kA.nodeCount == kB.nodeCount, L"G-08 the node count survives reordering");
    s.expect(kA.edgeCountBeforeFilter == kB.edgeCountBeforeFilter,
             L"G-08 the unfiltered edge count survives reordering");
    s.expect(kA.edgeCountAfterFilter == kB.edgeCountAfterFilter,
             L"G-08 the filtered edge count survives reordering");
    s.expect(kA.confirmedEdgeCount == kB.confirmedEdgeCount,
             L"G-08 the confirmed edge count survives reordering");
    s.expect(kA.candidateEdgeCount == kB.candidateEdgeCount,
             L"G-08 the candidate edge count survives reordering");
    s.expect(kA.unknownCertaintyEdgeCount == kB.unknownCertaintyEdgeCount,
             L"G-08 the unknown-certainty edge count survives reordering");
    s.expect(kA.isolatedNodeCount == kB.isolatedNodeCount,
             L"G-08 the isolated node count survives reordering");
    s.expect(kA.ownerMissingCount == kB.ownerMissingCount,
             L"G-08 the owner-missing count survives reordering");
    s.expect(kA.unloadedCount == kB.unloadedCount, L"G-08 the unloaded count survives reordering");
    s.expect(kA.sourceNotCollectedCount == kB.sourceNotCollectedCount,
             L"G-08 the not-collected count survives reordering");
    s.expect(kA.inconsistencyCount == kB.inconsistencyCount,
             L"G-08 the inconsistency count survives reordering");
    s.expect(kA.unusableIdentityNodeCount == kB.unusableIdentityNodeCount,
             L"G-08 the unusable identity count survives reordering");
    s.expect(kA.nodesWithoutEvidenceCount == kB.nodesWithoutEvidenceCount,
             L"G-08 the missing-evidence count survives reordering");
    s.expect(kA.coverage.succeeded == kB.coverage.succeeded &&
                 kA.coverage.totalKnown == kB.coverage.totalKnown &&
                 kA.coverage.limitHit == kB.coverage.limitHit,
             L"G-08 the coverage account survives reordering");
    s.expect(kA.limitationKeys == kB.limitationKeys,
             L"G-08 the limitation keys survive reordering, in the same order");
    s.expect(kA == kB, L"G-08 the whole conclusion compares equal field by field after reordering");

    // Export byte-for-byte consistent.
    ExpansionRequest request;
    for (const GraphNode& node : kFixture.nodes) {
        request.rootNodeIds.push_back(node.identity.nodeKey());
    }
    const ExpansionResult kForwardView = expandGraph(kForward, request);
    ExpansionRequest shuffled;
    for (std::size_t i = request.rootNodeIds.size(); i > 0; --i) {
        shuffled.rootNodeIds.push_back(request.rootNodeIds[i - 1]);
    }
    const ExpansionResult kReversedView = expandGraph(kReversed, shuffled);
    s.expect(kForwardView.loadedNodes == 6U && kForwardView.loadedEdges == 3U,
             L"G-08 the exported view holds all six nodes and three edges");
    s.expect(kForwardView.nodeIds == kReversedView.nodeIds &&
                 kForwardView.edgeIds == kReversedView.edgeIds,
             L"G-08 the loaded id lists are identical whichever order the roots arrive in");
    const std::string kForwardJson = writeJson(exportGraph(kForward, kForwardView, noFilter), 0);
    const std::string kReversedJson = writeJson(exportGraph(kReversed, kReversedView, noFilter), 0);
    s.expect(kForwardJson == kReversedJson,
             L"G-08 the export is byte-for-byte identical after reordering the input");

    // The exporter must guarantee order independence itself, rather than relying on the 'expansion result happening to be ordered'.
    // Here, the ID list is intentionally shuffled before export: without sorting on the export side, this check would fail.
    ExpansionResult shuffledView = kForwardView;
    for (std::size_t i = 0; i + 1 < shuffledView.nodeIds.size(); i += 2) {
        std::swap(shuffledView.nodeIds[i], shuffledView.nodeIds[i + 1]);
    }
    for (std::size_t i = 0; i + 1 < shuffledView.edgeIds.size(); i += 2) {
        std::swap(shuffledView.edgeIds[i], shuffledView.edgeIds[i + 1]);
    }
    s.expect(shuffledView.nodeIds != kForwardView.nodeIds &&
                 shuffledView.edgeIds != kForwardView.edgeIds,
             L"G-08 the shuffled view really is in a different order");
    s.expect(writeJson(exportGraph(kForward, shuffledView, noFilter), 0) == kForwardJson,
             L"G-08 the export canonicalises its own order instead of trusting the caller's");

    // Changing list sort order does not affect conclusions or exports.
    const std::vector<EntityListRow> kById =
        buildEntityList(kForward, kForwardView, noFilter, EntityListOrder::kByNodeId);
    const std::vector<EntityListRow> kByEdges =
        buildEntityList(kForward, kForwardView, noFilter, EntityListOrder::kByEdgeCountDescending);
    const std::vector<EntityListRow> kByKind =
        buildEntityList(kForward, kForwardView, noFilter, EntityListOrder::kByKind);
    s.expect(kById.size() == 6U && kByEdges.size() == 6U && kByKind.size() == 6U,
             L"G-08 every ordering shows the same six rows");
    s.expect(kByEdges.front().edgeCount == 3U,
             L"G-08 ordering by edge count puts the three-edge node first");
    s.expect(summarizeGraph(kForward, noFilter) == kA,
             L"G-08 building the list in another order does not change the conclusion");
    s.expect(writeJson(exportGraph(kForward, kForwardView, noFilter), 0) == kForwardJson,
             L"G-08 exporting again after re-sorting the list yields the same bytes");

    // The sort order actually changed (otherwise the invariant above would be vacuous).
    bool orderActuallyDiffers = false;
    for (std::size_t i = 0; i < kById.size(); ++i) {
        if (kById[i].nodeId != kByEdges[i].nodeId) {
            orderActuallyDiffers = true;
        }
    }
    s.expect(orderActuallyDiffers,
             L"G-08 the two orderings really produce different row orders");

    // Which portion to retain when hitting the limit must also be independent of insertion order. If an adjacency
    // list is traversed in insertion order, the forward and reverse graphs will truncate to two different subsets.
    ExpansionRequest truncating;
    truncating.rootNodeIds.push_back(kFixture.nodes[0].identity.nodeKey());
    truncating.limits.maxNodes = 2;
    const ExpansionResult kTruncatedForward = expandGraph(kForward, truncating);
    const ExpansionResult kTruncatedReversed = expandGraph(kReversed, truncating);
    s.expect(kTruncatedForward.loadedNodes == 2U && kTruncatedForward.nodeLimitHit,
             L"G-08 the truncating expansion really stops at the node budget");
    s.expect(kTruncatedForward.nodeIds == kTruncatedReversed.nodeIds,
             L"G-08 a truncated view keeps the same nodes whichever order the graph was built in");
    s.expect(kTruncatedForward.edgeIds == kTruncatedReversed.edgeIds,
             L"G-08 a truncated view keeps the same edges whichever order the graph was built in");

    // No risk dimensions in the conclusion field: only counts, coverage, and limitation descriptions are readable.
    s.expect(kA.limitationKeys.size() >= 2U &&
                 contains(kA.limitationKeys, "graph.summary.isolatedNodes") &&
                 contains(kA.limitationKeys, "graph.summary.unknownCertaintyEdges"),
             L"G-08 the conclusion explains its own limits instead of scoring anything");
}

// ---------------------------------------------------------------------------
// G-06: The exported component must be able to reconstruct the same graph.
// ---------------------------------------------------------------------------
void testExportImportRoundTrip(ksword_tests::Suite& s) {
    const GraphFixture kFixture = makeConclusionFixture();
    const EntityGraph kOriginal = buildFromFixture(kFixture, false);
    EdgeFilter noFilter;

    ExpansionRequest request;
    for (const GraphNode& node : kFixture.nodes) {
        request.rootNodeIds.push_back(node.identity.nodeKey());
    }
    const ExpansionResult kView = expandGraph(kOriginal, request);
    s.expect(kView.loadedNodes == 6U && kView.loadedEdges == 3U,
             L"G-06 the exported view really covers the whole saved fixture");

    const std::string kText = writeJson(exportGraph(kOriginal, kView, noFilter), 0);
    const JsonParseResult kReparsed = parseJson(kText);
    s.expect(kReparsed.ok(), L"G-06 the export parses back through the lossless json reader");

    const GraphImport kImported = importGraph(kReparsed.value);
    s.expect(kImported.schemaRecognised, L"G-06 the importer recognises the exported schema");
    s.expect(kImported.nodesAccepted == 6U && kImported.nodesRejected == 0U,
             L"G-06 all six saved nodes are reopened, none rejected");
    s.expect(kImported.edgesAccepted == 3U && kImported.edgesRejected == 0U,
             L"G-06 all three saved edges are reopened, none rejected");
    s.expect(kImported.coverageAccepted == 1U && kImported.coverageRejected == 0U,
             L"G-06 the declared relation coverage is reopened with the graph");
    s.expect(kImported.graph.nodeCount() == 6U && kImported.graph.edgeCount() == 3U,
             L"G-06 the reopened graph holds the same six nodes and three edges");

    // Note: Hardcode absolute values first, then compare field-by-field to avoid both sides failing simultaneously.
    const GraphConclusion kBefore = summarizeGraph(kOriginal, noFilter);
    const GraphConclusion kAfter = summarizeGraph(kImported.graph, noFilter);
    s.expect(kAfter.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"G-06 the reopened session still reaches difference-observed instead of falling back to no-evidence");
    s.expect(kAfter.nodeCount == 6U && kAfter.edgeCountAfterFilter == 3U,
             L"G-06 the reopened session counts the same six nodes and three edges");
    s.expect(kAfter.ownerMissingCount == 1U && kAfter.sourceNotCollectedCount == 0U,
             L"G-06 owner-missing does not decay into source-not-collected when the session is reopened");
    s.expect(kAfter.unusableIdentityNodeCount == 0U && kAfter.nodesWithoutEvidenceCount == 0U,
             L"G-06 no identity turns unusable just because the session was written out and read back");
    s.expect(kAfter == kBefore,
             L"G-06 the reopened conclusion equals the saved one field by field");

    // Identity itself: neither navigability nor cross-session primary keys may degrade.
    bool identitiesSurvived = true;
    for (const GraphNode& node : kOriginal.nodes()) {
        const GraphNode* reopened = kImported.graph.findNode(node.nodeId);
        if (reopened == nullptr || reopened->identity.crossSessionKey() != node.identity.crossSessionKey() ||
            reopened->identity.strength() != node.identity.strength() ||
            reopened->objectNavigable() != node.objectNavigable() ||
            reopened->identity.nodeKey() != node.identity.nodeKey() ||
            reopened->ownerRelation != node.ownerRelation ||
            reopened->ownerKind != node.ownerKind) {
            identitiesSurvived = false;
        }
    }
    s.expect(identitiesSurvived,
             L"G-06 every reopened node keeps its identity payload, owner relation and navigability");
    const std::string kProcessKey = processIdentity(kBoot, 1000, 111, "worker.exe").nodeKey();
    const GraphNode* reopenedProcess = kImported.graph.findNode(kProcessKey);
    s.expect(reopenedProcess != nullptr && reopenedProcess->objectNavigable() &&
                 !reopenedProcess->identity.crossSessionKey().empty(),
             L"G-06 the reopened process is still navigable and still has a cross-session key");

    // Chain: the same G-03 investigation chain remains identical ring-by-ring in a reopened session.
    ChainOptions options;
    const InvestigationChain kChainBefore =
        buildChain(kOriginal, ChainKind::kProcessSubjects, kProcessKey, options);
    const InvestigationChain kChainAfter =
        buildChain(kImported.graph, ChainKind::kProcessSubjects, kProcessKey, options);
    s.expect(kChainAfter.steps.size() == 4U &&
                 kChainAfter.steps[0].availability == StepAvailability::kPresent &&
                 kChainAfter.steps[1].availability == StepAvailability::kPresent &&
                 kChainAfter.steps[3].availability == StepAvailability::kPresent,
             L"G-06 the reopened process chain still reaches its thread and handle steps");
    bool chainSurvived = kChainBefore.steps.size() == kChainAfter.steps.size();
    for (std::size_t i = 0; chainSurvived && i < kChainBefore.steps.size(); ++i) {
        const ChainStep& x = kChainBefore.steps[i];
        const ChainStep& y = kChainAfter.steps[i];
        if (x.availability != y.availability || x.matchCount != y.matchCount ||
            x.nodeIds != y.nodeIds || x.edgeIds != y.edgeIds ||
            x.evidenceOpenable != y.evidenceOpenable ||
            x.anyObjectNavigable != y.anyObjectNavigable ||
            x.everyObjectNavigable != y.everyObjectNavigable ||
            x.outcome.status != y.outcome.status) {
            chainSurvived = false;
        }
    }
    s.expect(chainSurvived,
             L"G-06 every chain step is field-for-field what it was before the session was written out");

    // Re-export again: byte-for-byte identical. This definitively rules out issues like "missing fields in the export format itself."
    const ExpansionResult kReopenedView = expandGraph(kImported.graph, request);
    s.expect(kReopenedView.nodeIds == kView.nodeIds && kReopenedView.edgeIds == kView.edgeIds,
             L"G-06 expanding the reopened graph yields the very same id lists");
    s.expect(writeJson(exportGraph(kImported.graph, kReopenedView, noFilter), 0) == kText,
             L"G-06 exporting the reopened session reproduces the saved document byte for byte");

    // Do not guess if the schema is unrecognized: using a partial graph as a complete one is far more dangerous than rejecting it.
    JsonObject strangerFields;
    strangerFields.emplace_back("schema", JsonValue::makeString("ksword.entityGraph.v0"));
    const GraphImport kStranger = importGraph(JsonValue::makeObject(std::move(strangerFields)));
    s.expect(!kStranger.schemaRecognised && kStranger.graph.nodeCount() == 0U &&
                 contains(kStranger.limitationKeys, "graph.import.schemaUnknown"),
             L"G-06 an unrecognised schema is refused outright instead of importing half a graph");
    const GraphImport kNotAnObject = importGraph(JsonValue::makeString("nope"));
    s.expect(!kNotAnObject.schemaRecognised &&
                 contains(kNotAnObject.limitationKeys, "graph.import.notAnObject"),
             L"G-06 a document that is not even an object is refused with its own reason");
}

} // namespace

int runEntityGraphTests() {
    // The suite name contains Chinese characters. std::wcout cannot encode these characters in the default "C" locale, which sets
    // badbit and causes **every subsequent suite's** report to disappear. A suite name should not swallow another suite's output.
    // Temporarily switch to the system locale for output, then restore it, and clear status bits as a fallback.
    //
    // The same issue is even more critical for std::wcerr: the failure line is L"FAIL [" << suiteName << ...; once the suite name
    // conversion fails, badbit is set, and **every subsequent failure line is silently dropped** — if ten failures occur, only
    // half a line appears on screen. Diagnostic information must not disappear just because the name contains Chinese characters.
    const std::locale kPreviousLocale = std::wcout.getloc();
    const std::locale kPreviousErrLocale = std::wcerr.getloc();
    bool imbued = false;
    try {
        std::wcout.imbue(std::locale(""));
        std::wcerr.imbue(std::locale(""));
        imbued = true;
    } catch (const std::exception&) {
        imbued = false;
    }

    ksword_tests::Suite suite(L"G entity graph");
    testEdgeSemantics(suite);
    testLifecycleIdentity(suite);
    testHistoricalEdgeToLive(suite);
    testProcessChain(suite);
    testDeviceChain(suite);
    testConnectionChain(suite);
    testBoundedExpansion(suite);
    testLargeDatasetPerformance(suite);
    testIsolationStates(suite);
    testIsolationDoesNotDriveConclusion(suite);
    testOfflineAndCrossView(suite);
    testOrderIndependence(suite);
    testExportImportRoundTrip(suite);
    suite.report();

    if (imbued) {
        std::wcout.imbue(kPreviousLocale);
        std::wcerr.imbue(kPreviousErrLocale);
    }
    if (!std::wcout.good()) {
        std::wcout.clear();
    }
    if (!std::wcerr.good()) {
        std::wcerr.clear();
    }
    return suite.failures();
}

// Offline automated test for Module D (snapshot comparison and change explanation).
//
// Coverage IDs: D-01, D-02, D-03, D-04, D-05, D-06, D-07, and half of D-08 offline (expected change list
// verification; actual "modify config – take snapshot – cleanup" belongs to target environment testing).
//
// Assert principle (Q-01/Q-02):
//   * Expected values are hardcoded independently: RVA, keys, counts, and enumerations are manually calculated or
//     written constants; the two sides compared never originate from the output of the same function under test.
//   * Assert precise EntitySideState for each "unknown" individually, without collapsing into a
//     single counter—otherwise "Access Denied" and "Truly Absent" would masquerade as each other.
//   * Each negative test case asserts both "no false additions/deletions occurred" and "indeed marked as
//     incomparable"; checking only one would allow lazy implementations that mark everything as incomparable to pass.
//   * Uses hand-written JSON literals as fixtures for persistence, rather than writing then reading to self-verify.

#include "TestSupport.h"

#include "../../../shared/evidence/SnapshotCompare.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

constexpr const char* kBootA = "boot-A";
constexpr const char* kBootB = "boot-B";
constexpr const char* kMachine = "machine-D";
constexpr std::uint64_t kUtcEarlier = 133100000000000000ULL;
constexpr std::uint64_t kUtcLater = 133100006000000000ULL;

// ---------------------------------------------------------------------------
// fixture construction
// ---------------------------------------------------------------------------
EvidenceEnvelope makeEnvelope(const char* collectorId,
                              CollectionStatus status,
                              const char* bootId,
                              std::uint64_t utc,
                              const char* evidenceId) {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = collectorId;
    envelope.source.sourceGroup = collectorId;
    envelope.source.collectorVersion = 7U;
    envelope.source.origin = SourceOrigin::kLiveKernel;
    envelope.outcome.status = status;
    envelope.window.machineId = kMachine;
    envelope.window.bootId = bootId;
    envelope.window.sessionId = "session-1";
    envelope.window.mode = CaptureMode::kSnapshot;
    envelope.window.startUtc100ns = OptionalU64::of(utc);
    envelope.window.endUtc100ns = OptionalU64::of(utc + 1000ULL);
    envelope.evidenceId = evidenceId;
    return envelope;
}

// D-04/F-06: Full coverage requires positive evidence, so the ledger must explicitly state "total n, success n".
SnapshotPartition makePartition(const char* partitionId,
                                ObjectKind kind,
                                CollectionStatus status,
                                const char* bootId,
                                std::uint64_t utc,
                                std::uint64_t count,
                                const char* evidenceId) {
    SnapshotPartition partition;
    partition.partitionId = partitionId;
    partition.kind = kind;
    partition.coversScope = true;
    partition.envelope = makeEnvelope(partitionId, status, bootId, utc, evidenceId);
    partition.envelope.coverage.totalKnown = OptionalU64::of(count);
    partition.envelope.coverage.succeeded = count;
    return partition;
}

Snapshot makeSnapshot(const char* id, const char* bootId, std::uint64_t utc) {
    Snapshot snapshot;
    snapshot.snapshotId = id;
    snapshot.envelope = makeEnvelope("d.snapshot", CollectionStatus::kSuccess, bootId, utc, id);
    snapshot.scope.scopeId = "system";
    snapshot.scope.declared = true;
    snapshot.scope.wholeDomain = true;
    return snapshot;
}

EntityField textField(const char* name, const char* value) {
    EntityField field;
    field.name = name;
    field.kind = FieldValueKind::kText;
    field.text = value;
    return field;
}

EntityField numberField(const char* name, std::uint64_t value, FieldSemantics semantics) {
    EntityField field;
    field.name = name;
    field.semantics = semantics;
    field.kind = FieldValueKind::kNumber;
    field.number = OptionalU64::of(value);
    field.numberFormat = U64Format::kHexAddress;
    return field;
}

// Fields that were not collected must still declare their comparison semantics — semantics are attributes of the column, not of the value retrieved in this instance.
EntityField absentField(const char* name, FieldSemantics semantics = FieldSemantics::kOpaque) {
    EntityField field;
    field.name = name;
    field.semantics = semantics;
    field.kind = FieldValueKind::kAbsent;
    return field;
}

SnapshotEntity makeProcess(const char* partitionId,
                           const char* bootId,
                           std::uint64_t pid,
                           std::uint64_t createTime,
                           const char* imageName,
                           const char* rawId,
                           std::size_t order) {
    SnapshotEntity entity;
    entity.partitionId = partitionId;
    entity.kind = ObjectKind::kProcess;
    entity.process.bootId = bootId;
    entity.process.pid = OptionalU64::of(pid);
    if (createTime != 0ULL) {
        entity.process.createTime100ns = OptionalU64::of(createTime);
    }
    entity.process.imageName = imageName;
    entity.rawRecordId = rawId;
    entity.displayOrder = order;
    return entity;
}

SnapshotEntity makeDriverEntity(const char* partitionId,
                                const char* imagePath,
                                const char* pdb,
                                std::uint64_t stamp,
                                std::uint64_t size,
                                const char* rawId,
                                std::size_t order) {
    SnapshotEntity entity;
    entity.partitionId = partitionId;
    entity.kind = ObjectKind::kDriver;
    entity.driver.imagePath = imagePath;
    entity.driver.pdbSignature = pdb;
    entity.driver.timeDateStamp = OptionalU64::of(stamp);
    entity.driver.imageSize = OptionalU64::of(size);
    entity.rawRecordId = rawId;
    entity.displayOrder = order;
    return entity;
}

SnapshotEntity makeServiceEntity(const char* partitionId,
                                 const char* name,
                                 const char* rawId,
                                 std::size_t order) {
    SnapshotEntity entity;
    entity.partitionId = partitionId;
    entity.kind = ObjectKind::kService;
    entity.logical.domain = "service";
    entity.logical.name = name;
    entity.rawRecordId = rawId;
    entity.displayOrder = order;
    return entity;
}

SnapshotModule makeModule(const char* moduleId,
                          const char* imagePath,
                          const char* pdb,
                          std::uint64_t stamp,
                          std::uint64_t base,
                          std::uint64_t size) {
    SnapshotModule module;
    module.moduleId = moduleId;
    module.identity.imagePath = imagePath;
    module.identity.pdbSignature = pdb;
    module.identity.timeDateStamp = OptionalU64::of(stamp);
    module.identity.imageSize = OptionalU64::of(size);
    module.imageBase = OptionalU64::of(base);
    module.imageSize = OptionalU64::of(size);
    return module;
}

const EntityDelta* findDelta(const SnapshotComparison& comparison, const std::string& display) {
    for (const EntityDelta& delta : comparison.deltas) {
        if (delta.displayText == display) {
            return &delta;
        }
    }
    return nullptr;
}

const EntityDelta* findDeltaByRaw(const SnapshotComparison& comparison, const std::string& rawId) {
    for (const EntityDelta& delta : comparison.deltas) {
        if (delta.earlierRawRecordId == rawId || delta.laterRawRecordId == rawId) {
            return &delta;
        }
    }
    return nullptr;
}

const FieldDelta* findField(const EntityDelta& delta, const std::string& name) {
    for (const FieldDelta& field : delta.fields) {
        if (field.name == name) {
            return &field;
        }
    }
    return nullptr;
}

const PartitionAccount* findAccount(const SnapshotComparison& comparison, const std::string& id) {
    for (const PartitionAccount& account : comparison.partitions) {
        if (account.partitionId == id) {
            return &account;
        }
    }
    return nullptr;
}

bool contains(const std::vector<std::string>& list, const std::string& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

bool textContains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------
// D-01: Snapshot scope and provenance.
// ---------------------------------------------------------------------------
void testScopeAndProvenance(ksword_tests::Suite& s) {
    // --- All six values of compareScopes must have assertions; enum branches must not be zero-covered ---
    SnapshotScope whole;
    whole.scopeId = "system";
    whole.declared = true;
    whole.wholeDomain = true;

    SnapshotScope undeclared;
    undeclared.scopeId = "system";

    SnapshotScope narrowA;
    narrowA.scopeId = "system";
    narrowA.declared = true;
    narrowA.selectors = {"C:", "D:"};

    SnapshotScope narrowSubset;
    narrowSubset.scopeId = "system";
    narrowSubset.declared = true;
    narrowSubset.selectors = {"C:"};

    SnapshotScope narrowOther;
    narrowOther.scopeId = "system";
    narrowOther.declared = true;
    narrowOther.selectors = {"E:"};

    SnapshotScope narrowOverlap;
    narrowOverlap.scopeId = "system";
    narrowOverlap.declared = true;
    narrowOverlap.selectors = {"D:", "E:"};

    SnapshotScope otherDomain;
    otherDomain.scopeId = "network";
    otherDomain.declared = true;
    otherDomain.wholeDomain = true;

    s.expect(compareScopes(whole, whole) == ScopeComparability::kIdentical,
             L"D-01 identical whole-domain scopes compare as identical");
    s.expect(compareScopes(whole, undeclared) == ScopeComparability::kUnknown,
             L"D-01 an undeclared scope is unknown, never assumed identical");
    s.expect(compareScopes(undeclared, undeclared) == ScopeComparability::kUnknown,
             L"D-01 two undeclared scopes stay unknown");
    s.expect(compareScopes(narrowSubset, whole) == ScopeComparability::kEarlierSubsetOfLater,
             L"D-01 earlier narrow vs later whole is EarlierSubsetOfLater");
    s.expect(compareScopes(whole, narrowSubset) == ScopeComparability::kLaterSubsetOfEarlier,
             L"D-01 earlier whole vs later narrow is LaterSubsetOfEarlier");
    s.expect(compareScopes(narrowSubset, narrowA) == ScopeComparability::kEarlierSubsetOfLater,
             L"D-01 selector subset is recognised");
    s.expect(compareScopes(narrowA, narrowOther) == ScopeComparability::kDisjoint,
             L"D-01 disjoint selector sets are disjoint");
    s.expect(compareScopes(narrowA, narrowOverlap) == ScopeComparability::kPartialOverlap,
             L"D-01 partially overlapping selector sets are PartialOverlap");
    s.expect(compareScopes(whole, otherDomain) == ScopeComparability::kDisjoint,
             L"D-01 different scope ids are disjoint");

    s.expect(removalInferable(ScopeComparability::kIdentical),
             L"D-01 removal is inferable when scopes match");
    s.expect(removalInferable(ScopeComparability::kEarlierSubsetOfLater),
             L"D-01 removal is inferable when the later scope covers the earlier one");
    s.expect(!removalInferable(ScopeComparability::kLaterSubsetOfEarlier),
             L"D-01 removal is NOT inferable when the later scope is narrower");
    s.expect(!removalInferable(ScopeComparability::kUnknown),
             L"D-01 removal is NOT inferable when the scope is undeclared");
    s.expect(!removalInferable(ScopeComparability::kPartialOverlap),
             L"D-01 removal is NOT inferable on partial overlap");
    s.expect(!removalInferable(ScopeComparability::kDisjoint),
             L"D-01 removal is NOT inferable on disjoint scopes");
    s.expect(additionInferable(ScopeComparability::kLaterSubsetOfEarlier),
             L"D-01 addition is inferable when the earlier scope covers the later one");
    s.expect(!additionInferable(ScopeComparability::kEarlierSubsetOfLater),
             L"D-01 addition is NOT inferable when the earlier scope is narrower");

    // --- Snapshot 1: Full range ---
    Snapshot fullEarlier = makeSnapshot("full-early", kBootA, kUtcEarlier);
    fullEarlier.partitions.push_back(
        makePartition("processes", ObjectKind::kProcess, CollectionStatus::kSuccess, kBootA,
                      kUtcEarlier, 2U, "ev-early-proc"));
    fullEarlier.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "e-row-1", 0U));
    fullEarlier.entities.push_back(
        makeProcess("processes", kBootA, 200U, 222ULL, "beta.exe", "e-row-2", 1U));

    Snapshot fullLater = makeSnapshot("full-late", kBootA, kUtcLater);
    fullLater.partitions.push_back(
        makePartition("processes", ObjectKind::kProcess, CollectionStatus::kSuccess, kBootA, kUtcLater,
                      1U, "ev-late-proc"));
    fullLater.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));

    const SnapshotComparison kFullPair = compareSnapshots(fullEarlier, fullLater);
    s.expect(kFullPair.scope == ScopeComparability::kIdentical,
             L"D-01 two whole-domain snapshots compare as identical scope");
    s.expect(kFullPair.removedCount == 1U,
             L"D-01 with identical scope and complete coverage a real removal is reported");
    const EntityDelta* beta = findDelta(kFullPair, "beta.exe");
    s.expect(beta != nullptr && beta->change == EntityChange::kRemoved,
             L"D-01 the removed process is the one that disappeared");
    s.expect(beta != nullptr && beta->laterState == EntitySideState::kAbsentCovered,
             L"D-01 the removed process is absent in a covered later snapshot");
    s.expect(kFullPair.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"D-01 a removal makes the conclusion DifferenceObserved");

    // --- Snapshot 2: Partial scope — Core trap of D-01 ---
    Snapshot narrowLater = makeSnapshot("narrow-late", kBootA, kUtcLater);
    narrowLater.scope.wholeDomain = false;
    narrowLater.scope.selectors = {"session-0"};
    narrowLater.partitions.push_back(
        makePartition("processes", ObjectKind::kProcess, CollectionStatus::kSuccess, kBootA, kUtcLater,
                      1U, "ev-late-proc"));
    narrowLater.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));

    const SnapshotComparison kNarrowPair = compareSnapshots(fullEarlier, narrowLater);
    s.expect(kNarrowPair.scope == ScopeComparability::kLaterSubsetOfEarlier,
             L"D-01 a narrower later selection is recognised as such");
    s.expect(kNarrowPair.removedCount == 0U,
             L"D-01 a narrower later selection never reports removals");
    const EntityDelta* narrowBeta = findDelta(kNarrowPair, "beta.exe");
    s.expect(narrowBeta != nullptr && narrowBeta->change == EntityChange::kNotComparable,
             L"D-01 the object outside the later selection is NotComparable, not removed");
    s.expect(narrowBeta != nullptr && narrowBeta->laterState == EntitySideState::kAbsentOutOfScope,
             L"D-01 the later side is marked out of scope rather than absent");
    s.expect(narrowBeta != nullptr &&
                 contains(narrowBeta->limitationKeys, "snapshot.limitation.scopeNotComparable"),
             L"D-01 the scope limitation is stated on the delta");
    s.expect(contains(kNarrowPair.limitationKeys, "snapshot.limitation.scopeDiffers"),
             L"D-01 the report states that the selections differ");
    s.expect(kNarrowPair.conclusion == AnalysisConclusion::kIndeterminate,
             L"D-01 differing selections cannot yield NoDifferenceObserved");
    s.expect(kNarrowPair.selfCheckPassed, L"D-01 narrow-scope comparison passes its self check");

    // Reverse direction: if the earlier range is narrower, additions can be detected, but deletions cannot.
    const SnapshotComparison kWidened = compareSnapshots(narrowLater, fullEarlier);
    s.expect(kWidened.scope == ScopeComparability::kEarlierSubsetOfLater,
             L"D-01 widening the selection is EarlierSubsetOfLater");
    s.expect(kWidened.addedCount == 0U,
             L"D-01 a widened later selection never reports additions");
    s.expect(kWidened.removedCount == 0U,
             L"D-01 a widened selection with no missing object reports no removals");

    // --- Snapshot 3: Partial failure
    Snapshot partialLater = makeSnapshot("partial-late", kBootA, kUtcLater);
    partialLater.partitions.push_back(
        makePartition("processes", ObjectKind::kProcess, CollectionStatus::kPartial, kBootA, kUtcLater,
                      2U, "ev-late-proc"));
    partialLater.partitions.back().envelope.coverage.truncated = 1U;
    partialLater.partitions.back().envelope.coverage.succeeded = 1U;
    partialLater.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));

    const SnapshotComparison kPartialPair = compareSnapshots(fullEarlier, partialLater);
    s.expect(kPartialPair.removedCount == 0U,
             L"D-01 a truncated later snapshot never reports removals");
    const EntityDelta* partialBeta = findDelta(kPartialPair, "beta.exe");
    s.expect(partialBeta != nullptr && partialBeta->change == EntityChange::kInsufficientCoverage,
             L"D-01 a truncated later snapshot yields InsufficientCoverage");
    s.expect(partialBeta != nullptr && partialBeta->laterState == EntitySideState::kUnknownCoverage,
             L"D-01 truncation is reported as unknown coverage, not absence");

    // Status indicates 'incomplete collection' but the ledger appears full: if either the status or the ledger indicates incompleteness, we cannot support a conclusion of absence.
    Snapshot partialButTidy = makeSnapshot("partial-tidy", kBootA, kUtcLater);
    partialButTidy.partitions.push_back(
        makePartition("processes", ObjectKind::kProcess, CollectionStatus::kPartial, kBootA, kUtcLater,
                      1U, "ev-late-proc"));
    partialButTidy.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));
    const SnapshotComparison kTidyPair = compareSnapshots(fullEarlier, partialButTidy);
    s.expect(kTidyPair.removedCount == 0U,
             L"D-01 a Partial status never supports a removal even with a tidy-looking account");
    const EntityDelta* tidyBeta = findDelta(kTidyPair, "beta.exe");
    s.expect(tidyBeta != nullptr && tidyBeta->laterState == EntitySideState::kUnknownCoverage,
             L"D-01 a Partial status is reported as unknown coverage");

    // Snapshots from different machines: additions and deletions lose meaning.
    Snapshot otherMachine = fullLater;
    otherMachine.envelope.window.machineId = "machine-OTHER";
    const SnapshotComparison kCrossMachine = compareSnapshots(fullEarlier, otherMachine);
    s.expect(contains(kCrossMachine.limitationKeys, "snapshot.limitation.machineMismatch"),
             L"D-01 comparing two machines is stated as a limitation");
    s.expect(kCrossMachine.removedCount == 0U,
             L"D-01 two different machines never produce a removal");
    const EntityDelta* crossBeta = findDelta(kCrossMachine, "beta.exe");
    s.expect(crossBeta != nullptr && crossBeta->laterState == EntitySideState::kAbsentOutOfScope,
             L"D-01 the cross-machine object is out of comparable scope, not removed");

    // --- Source and account must be verifiable against each other ---
    const PartitionAccount* account = findAccount(kFullPair, "processes");
    s.expect(account != nullptr && account->earlierStatus == CollectionStatus::kSuccess,
             L"D-01 the partition account records the earlier collection status");
    s.expect(account != nullptr && account->comparable,
             L"D-01 both sides carrying observations makes the partition comparable");
    s.expect(account != nullptr && account->earlierUsableForAbsence && account->laterUsableForAbsence,
             L"D-01 a fully accounted partition may support absence claims");
    s.expect(fullEarlier.envelope.source.collectorVersion == 7U,
             L"D-01 the snapshot envelope carries a collector version");
    s.expect(fullEarlier.envelope.window.bootId == std::string(kBootA),
             L"D-01 the snapshot envelope carries the boot identity");
    s.expect(kFullPair.trust.viewCount >= 4U,
             L"D-01 the trust statement counts both snapshots and their partitions");
    s.expect(kFullPair.boot == CrossBootComparability::kSameBoot,
             L"D-01 two snapshots from one boot are recognised as same-boot");

    // Empty accounts must not receive 'full coverage'.
    Snapshot blankLater = makeSnapshot("blank-late", kBootA, kUtcLater);
    SnapshotPartition blank;
    blank.partitionId = "processes";
    blank.kind = ObjectKind::kProcess;
    blank.coversScope = true;
    blank.envelope = makeEnvelope("processes", CollectionStatus::kSuccess, kBootA, kUtcLater, "ev-b");
    blankLater.partitions.push_back(blank);
    blankLater.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "l-row-1", 0U));
    const SnapshotComparison kBlankPair = compareSnapshots(fullEarlier, blankLater);
    s.expect(kBlankPair.removedCount == 0U,
             L"D-01 an empty coverage account never supports a removal claim");
    const PartitionAccount* blankAccount = findAccount(kBlankPair, "processes");
    s.expect(blankAccount != nullptr && !blankAccount->laterUsableForAbsence,
             L"D-01 an unfilled coverage account is not usable for absence");
    s.expect(blankAccount != nullptr &&
                 contains(blankAccount->limitationKeys, "snapshot.partition.laterCoverageIncomplete"),
             L"D-01 the unfilled account is stated as incomplete coverage");
}

// ---------------------------------------------------------------------------
// D-02 semantic comparison key
// ---------------------------------------------------------------------------
void testSemanticKeys(ksword_tests::Suite& s) {
    s.expect(!kindComparableAcrossBoot(ObjectKind::kProcess),
             L"D-02 process instances are not comparable across boots");
    s.expect(!kindComparableAcrossBoot(ObjectKind::kThread),
             L"D-02 thread instances are not comparable across boots");
    s.expect(!kindComparableAcrossBoot(ObjectKind::kHandle),
             L"D-02 handles are not comparable across boots");
    s.expect(!kindComparableAcrossBoot(ObjectKind::kConnection),
             L"D-02 connections are not comparable across boots");
    s.expect(kindComparableAcrossBoot(ObjectKind::kDriver),
             L"D-02 drivers are comparable across boots by logical identity");
    s.expect(kindComparableAcrossBoot(ObjectKind::kService),
             L"D-02 services are comparable across boots by logical identity");
    s.expect(kindComparableAcrossBoot(ObjectKind::kFile),
             L"D-02 files are comparable across boots by logical identity");

    LogicalObjectId svcA;
    svcA.domain = "service";
    svcA.name = "AcmeSvc";
    LogicalObjectId svcB = svcA;
    LogicalObjectId svcScoped = svcA;
    svcScoped.scopeKey = "policy-2";
    LogicalObjectId svcOtherScope = svcA;
    svcOtherScope.scopeKey = "policy-3";
    LogicalObjectId nameless;
    nameless.domain = "service";

    s.expect(matchLogicalObject(svcA, svcB) == MatchResult::kConfirmed,
             L"D-02 identical logical identities are confirmed");
    s.expect(matchLogicalObject(svcScoped, svcOtherScope) == MatchResult::kNoMatch,
             L"D-02 same name in a different scope is a different object");
    s.expect(matchLogicalObject(svcA, svcScoped) == MatchResult::kCandidate,
             L"D-02 a missing scope key can only produce a candidate");
    s.expect(matchLogicalObject(svcA, nameless) == MatchResult::kCandidate,
             L"D-02 an unusable logical identity is capped at candidate");
    s.expect(nameless.crossSessionKey().empty(),
             L"D-02 an unusable logical identity yields no cross-session key");
    s.expect(!svcA.crossSessionKey().empty(),
             L"D-02 a complete logical identity yields a cross-session key");

    // --- Same name, different object: PID reuse ---
    Snapshot earlier = makeSnapshot("k-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 1U,
                                               "ev-e"));
    earlier.entities.push_back(
        makeProcess("processes", kBootA, 4242U, 900ULL, "svc.exe", "e-1", 0U));

    Snapshot later = makeSnapshot("k-late", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                             CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                             "ev-l"));
    later.entities.push_back(
        makeProcess("processes", kBootA, 4242U, 1700ULL, "svc.exe", "l-1", 0U));

    const SnapshotComparison kReuse = compareSnapshots(earlier, later);
    s.expect(kReuse.deltas.size() == 2U,
             L"D-02 a reused PID with a different creation time stays two objects");
    s.expect(kReuse.removedCount == 1U && kReuse.addedCount == 1U,
             L"D-02 the reused PID produces one removal and one addition, never a modification");
    s.expect(kReuse.modifiedCount == 0U,
             L"D-02 two different process instances are never merged into one modification");

    // --- Sorting changes: No false additions or deletions allowed ---
    Snapshot orderedEarlier = makeSnapshot("o-early", kBootA, kUtcEarlier);
    orderedEarlier.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                      CollectionStatus::kSuccess, kBootA,
                                                      kUtcEarlier, 3U, "ev-e"));
    orderedEarlier.entities.push_back(
        makeProcess("processes", kBootA, 10U, 10ULL, "a.exe", "e-a", 0U));
    orderedEarlier.entities.push_back(
        makeProcess("processes", kBootA, 20U, 20ULL, "b.exe", "e-b", 1U));
    orderedEarlier.entities.push_back(
        makeProcess("processes", kBootA, 30U, 30ULL, "c.exe", "e-c", 2U));

    Snapshot orderedLater = makeSnapshot("o-late", kBootA, kUtcLater);
    orderedLater.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                    CollectionStatus::kSuccess, kBootA, kUtcLater,
                                                    3U, "ev-l"));
    orderedLater.entities.push_back(
        makeProcess("processes", kBootA, 30U, 30ULL, "c.exe", "l-c", 0U));
    orderedLater.entities.push_back(
        makeProcess("processes", kBootA, 10U, 10ULL, "a.exe", "l-a", 1U));
    orderedLater.entities.push_back(
        makeProcess("processes", kBootA, 20U, 20ULL, "b.exe", "l-b", 2U));

    const SnapshotComparison kReordered = compareSnapshots(orderedEarlier, orderedLater);
    s.expect(kReordered.addedCount == 0U && kReordered.removedCount == 0U,
             L"D-02 reordering produces no phantom additions or removals");
    s.expect(kReordered.modifiedCount == 0U, L"D-02 reordering produces no modifications");
    s.expect(kReordered.unchangedCount == 3U, L"D-02 all three reordered objects stay unchanged");
    const EntityDelta* movedA = findDelta(kReordered, "a.exe");
    s.expect(movedA != nullptr && movedA->displayOrderChanged,
             L"D-02 the display-order change is recorded separately from the verdict");
    s.expect(movedA != nullptr && movedA->earlierDisplayOrder == 0U && movedA->laterDisplayOrder == 1U,
             L"D-02 both display orders are preserved for the reader");
    s.expect(kReordered.conclusion == AnalysisConclusion::kNoDifferenceObserved,
             L"D-02 a pure reorder over a fully covered identical scope observes no difference");

    // --- Before and after reboot: Processes must not be hard-mapped across boots; drivers may be
    Snapshot bootOne = makeSnapshot("b1", kBootA, kUtcEarlier);
    bootOne.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 1U,
                                               "ev-p1"));
    bootOne.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 1U,
                                               "ev-d1"));
    bootOne.entities.push_back(makeProcess("processes", kBootA, 500U, 5000ULL, "svchost.exe", "e-p",
                                           0U));
    {
        SnapshotEntity driver = makeDriverEntity("drivers", "\\SystemRoot\\System32\\acme.sys",
                                                 "RSDS-ACME-1", 0x600DU, 0x8000U, "e-d", 0U);
        driver.fields.push_back(numberField("imageBase", 0xFFFFF80000100000ULL,
                                            FieldSemantics::kLoadBaseAddress));
        driver.fields.push_back(textField("startType", "boot"));
        bootOne.entities.push_back(driver);
    }

    Snapshot bootTwo = makeSnapshot("b2", kBootB, kUtcLater);
    bootTwo.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                               CollectionStatus::kSuccess, kBootB, kUtcLater, 1U,
                                               "ev-p2"));
    bootTwo.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                               CollectionStatus::kSuccess, kBootB, kUtcLater, 1U,
                                               "ev-d2"));
    bootTwo.entities.push_back(makeProcess("processes", kBootB, 500U, 9000ULL, "svchost.exe", "l-p",
                                           0U));
    {
        SnapshotEntity driver = makeDriverEntity("drivers", "\\SystemRoot\\System32\\acme.sys",
                                                 "RSDS-ACME-1", 0x600DU, 0x8000U, "l-d", 0U);
        // Image base address after reboot must differ — this is not a discrepancy.
        driver.fields.push_back(numberField("imageBase", 0xFFFFF80000940000ULL,
                                            FieldSemantics::kLoadBaseAddress));
        driver.fields.push_back(textField("startType", "boot"));
        bootTwo.entities.push_back(driver);
    }

    const SnapshotComparison kReboot = compareSnapshots(bootOne, bootTwo);
    s.expect(kReboot.boot == CrossBootComparability::kDifferentBoot,
             L"D-02 different boot ids are recognised");
    s.expect(kReboot.removedCount == 0U && kReboot.addedCount == 0U,
             L"D-02 a reboot does not turn every process into an add/remove pair");
    const EntityDelta* rebootProcess = findDeltaByRaw(kReboot, "e-p");
    s.expect(rebootProcess != nullptr && rebootProcess->change == EntityChange::kNotComparable,
             L"D-02 a process instance across boots is NotComparable");
    s.expect(rebootProcess != nullptr &&
                 rebootProcess->laterState == EntitySideState::kUnknownCrossBoot,
             L"D-02 the cross-boot reason is stated on the process delta");
    s.expect(rebootProcess != nullptr &&
                 contains(rebootProcess->limitationKeys, "snapshot.limitation.crossBootInstance"),
             L"D-02 the cross-boot limitation key is emitted");
    const EntityDelta* rebootDriver = findDelta(kReboot, "\\SystemRoot\\System32\\acme.sys");
    s.expect(rebootDriver != nullptr && rebootDriver->change == EntityChange::kUnchanged,
             L"D-02 the same driver across boots compares as unchanged");
    s.expect(rebootDriver != nullptr && rebootDriver->matchConfidence == MatchConfidence::kConfirmed,
             L"D-02 the driver match across boots is confirmed by image identity");
    const FieldDelta* baseField =
        rebootDriver != nullptr ? findField(*rebootDriver, "imageBase") : nullptr;
    s.expect(baseField != nullptr && baseField->change == FieldChange::kNormalizedUnchanged,
             L"D-02 a changed load base is normalized away instead of becoming a difference");

    // --- Multiple entries for the same stable key: pairing relationship is undetermined; do not force-match the first one nor discard the rest.
    Snapshot dupEarlier = makeSnapshot("d-early", kBootA, kUtcEarlier);
    dupEarlier.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                  CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                  2U, "ev-e"));
    dupEarlier.entities.push_back(
        makeProcess("processes", kBootA, 55U, 550ULL, "dup.exe", "e-dup-1", 0U));
    dupEarlier.entities.push_back(
        makeProcess("processes", kBootA, 55U, 550ULL, "dup.exe", "e-dup-2", 1U));

    Snapshot dupLater = makeSnapshot("d-late", kBootA, kUtcLater);
    dupLater.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                                "ev-l"));
    dupLater.entities.push_back(
        makeProcess("processes", kBootA, 55U, 550ULL, "dup.exe", "l-dup-1", 0U));

    const SnapshotComparison kDup = compareSnapshots(dupEarlier, dupLater);
    s.expect(kDup.deltas.size() == 3U,
             L"D-02 every record behind a duplicated identity key is still reported");
    s.expect(kDup.addedCount == 0U && kDup.removedCount == 0U && kDup.unchangedCount == 0U,
             L"D-02 a duplicated identity key yields no verdict at all");
    s.expect(kDup.notComparableCount == 3U,
             L"D-02 all records behind a duplicated key are NotComparable");
    s.expect(!kDup.deltas.empty() &&
                 contains(kDup.deltas.front().limitationKeys,
                          "snapshot.limitation.duplicateIdentityKey"),
             L"D-02 the duplicated-key limitation is stated");

    // --- Unstable match -> uncertain, do not convert to false additions/deletions ---
    Snapshot weakEarlier = makeSnapshot("w-early", kBootA, kUtcEarlier);
    weakEarlier.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                   CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                   1U, "ev-e"));
    weakEarlier.entities.push_back(
        makeProcess("processes", kBootA, 777U, 0ULL, "weak.exe", "e-w", 0U));

    Snapshot weakLater = makeSnapshot("w-late", kBootA, kUtcLater);
    weakLater.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                 CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                                 "ev-l"));
    weakLater.entities.push_back(
        makeProcess("processes", kBootA, 777U, 0ULL, "weak.exe", "l-w", 0U));

    const SnapshotComparison kWeak = compareSnapshots(weakEarlier, weakLater);
    s.expect(kWeak.deltas.size() == 1U,
             L"D-02 two weak records with the same weak key are reported once");
    s.expect(!kWeak.deltas.empty() && kWeak.deltas.front().matchConfidence == MatchConfidence::kUncertain,
             L"D-02 a weak identity match is marked uncertain");
    s.expect(!kWeak.deltas.empty() && kWeak.deltas.front().identityKey.empty(),
             L"D-02 a weak identity gets no cross-session key");
    s.expect(kWeak.addedCount == 0U && kWeak.removedCount == 0U,
             L"D-02 an unstable match never becomes an add/remove pair");

    // Weak identity with one side missing: still must not be judged as removed.
    Snapshot weakGone = makeSnapshot("w-gone", kBootA, kUtcLater);
    weakGone.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                CollectionStatus::kSuccess, kBootA, kUtcLater, 0U,
                                                "ev-l"));
    const SnapshotComparison kWeakMissing = compareSnapshots(weakEarlier, weakGone);
    s.expect(kWeakMissing.removedCount == 0U,
             L"D-02 a vanished weak-identity record is not reported as removed");
    s.expect(!kWeakMissing.deltas.empty() &&
                 kWeakMissing.deltas.front().change == EntityChange::kNotComparable,
             L"D-02 a vanished weak-identity record is NotComparable");
    s.expect(!kWeakMissing.deltas.empty() &&
                 contains(kWeakMissing.deltas.front().limitationKeys,
                          "snapshot.limitation.identityInsufficient"),
             L"D-02 the insufficient-identity limitation is stated");
}

// ---------------------------------------------------------------------------
// D-03 address normalization
// ---------------------------------------------------------------------------
void testAddressNormalization(ksword_tests::Suite& s) {
    // Manual calculation: base 0xFFFFF80000100000 + 0x1234 = 0xFFFFF80000101234
    //       base 0xFFFFF80000940000 + 0x1234 = 0xFFFFF80000941234
    constexpr std::uint64_t kEarlyBase = 0xFFFFF80000100000ULL;
    constexpr std::uint64_t kLateBase = 0xFFFFF80000940000ULL;
    constexpr std::uint64_t kSize = 0x8000ULL;
    constexpr std::uint64_t kEarlyHook = 0xFFFFF80000101234ULL;
    constexpr std::uint64_t kLateHook = 0xFFFFF80000941234ULL;
    constexpr std::uint64_t kLateHookMoved = 0xFFFFF80000942000ULL;  // RVA 0x2000

    auto makeHookSnapshot = [](const char* id, const char* bootId, std::uint64_t utc,
                               std::uint64_t hookAddress) {
        Snapshot snapshot = makeSnapshot(id, bootId, utc);
        snapshot.partitions.push_back(makePartition("hooks", ObjectKind::kService,
                                                    CollectionStatus::kSuccess, bootId, utc, 1U,
                                                    "ev-hooks"));
        SnapshotEntity entity;
        entity.partitionId = "hooks";
        entity.kind = ObjectKind::kService;
        entity.logical.domain = "hook-point";
        entity.logical.name = "IofCallDriver";
        entity.rawRecordId = id;
        entity.fields.push_back(numberField("target", hookAddress, FieldSemantics::kKernelAddress));
        snapshot.entities.push_back(entity);
        return snapshot;
    };

    // --- Different image, different load base: do not generate false differences ---
    Snapshot earlier = makeHookSnapshot("h-early", kBootA, kUtcEarlier, kEarlyHook);
    earlier.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                         "RSDS-ACME-1", 0x600DU, kEarlyBase, kSize));
    Snapshot later = makeHookSnapshot("h-late", kBootB, kUtcLater, kLateHook);
    later.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys", "RSDS-ACME-1",
                                       0x600DU, kLateBase, kSize));

    const SnapshotComparison kRebased = compareSnapshots(earlier, later);
    const EntityDelta* hook = findDelta(kRebased, "IofCallDriver");
    s.expect(hook != nullptr && hook->change == EntityChange::kUnchanged,
             L"D-03 the same image at a different load base produces no difference");
    const FieldDelta* target = hook != nullptr ? findField(*hook, "target") : nullptr;
    s.expect(target != nullptr && target->change == FieldChange::kNormalizedUnchanged,
             L"D-03 the rebased address is reported as normalized-unchanged");
    s.expect(target != nullptr &&
                 target->normalization.state == AddressNormalizationState::kNormalized,
             L"D-03 normalization only happens when the images are confirmed comparable");
    s.expect(target != nullptr && target->normalization.earlierRva.present &&
                 target->normalization.earlierRva.value == 0x1234ULL,
             L"D-03 the earlier RVA is computed as 0x1234");
    s.expect(target != nullptr && target->normalization.laterRva.present &&
                 target->normalization.laterRva.value == 0x1234ULL,
             L"D-03 the later RVA is computed as 0x1234");
    s.expect(target != nullptr && target->earlierText == std::string("0xFFFFF80000101234"),
             L"D-03 the raw earlier address is still shown to the reader");
    s.expect(target != nullptr && target->laterText == std::string("0xFFFFF80000941234"),
             L"D-03 the raw later address is still shown to the reader");

    // --- Same image, but RVA actually changed -> genuine difference
    Snapshot moved = makeHookSnapshot("h-moved", kBootB, kUtcLater, kLateHookMoved);
    moved.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys", "RSDS-ACME-1",
                                       0x600DU, kLateBase, kSize));
    const SnapshotComparison kMovedPair = compareSnapshots(earlier, moved);
    const EntityDelta* movedHook = findDelta(kMovedPair, "IofCallDriver");
    const FieldDelta* movedTarget = movedHook != nullptr ? findField(*movedHook, "target") : nullptr;
    s.expect(movedTarget != nullptr && movedTarget->change == FieldChange::kChanged,
             L"D-03 a genuinely different RVA in the same image is a real change");
    s.expect(movedTarget != nullptr && movedTarget->normalization.laterRva.present &&
                 movedTarget->normalization.laterRva.value == 0x2000ULL,
             L"D-03 the moved RVA is computed as 0x2000");
    s.expect(movedHook != nullptr && movedHook->change == EntityChange::kModified,
             L"D-03 the entity carrying a changed address is Modified");

    // --- Same RVA across different versions: never treat as identical code
    Snapshot otherVersion = makeHookSnapshot("h-ver", kBootB, kUtcLater, kLateHook);
    otherVersion.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                              "RSDS-ACME-2", 0x700DU, kLateBase, kSize));
    const SnapshotComparison kVersionPair = compareSnapshots(earlier, otherVersion);
    const EntityDelta* versionHook = findDelta(kVersionPair, "IofCallDriver");
    const FieldDelta* versionTarget =
        versionHook != nullptr ? findField(*versionHook, "target") : nullptr;
    s.expect(versionTarget != nullptr && versionTarget->change == FieldChange::kNotComparable,
             L"D-03 the same RVA in a different image version is NOT comparable");
    s.expect(versionTarget != nullptr &&
                 versionTarget->normalization.state ==
                     AddressNormalizationState::kImageVersionDiffers,
             L"D-03 the different-version reason is stated explicitly");
    s.expect(versionTarget != nullptr && versionTarget->normalization.earlierRva.present &&
                 versionTarget->normalization.laterRva.present &&
                 versionTarget->normalization.earlierRva.value ==
                     versionTarget->normalization.laterRva.value,
             L"D-03 the RVAs are equal yet the verdict is still not-comparable");
    s.expect(versionHook != nullptr && versionHook->change == EntityChange::kPartiallyComparable,
             L"D-03 an entity whose only field is not comparable is PartiallyComparable");
    s.expect(kVersionPair.modifiedCount == 0U,
             L"D-03 a version difference does not manufacture a field change");

    // --- Missing modules: do not normalize, do not compare raw values directly ---
    Snapshot noModules = makeHookSnapshot("h-nomod", kBootB, kUtcLater, kLateHook);
    const SnapshotComparison kMissingPair = compareSnapshots(earlier, noModules);
    const EntityDelta* missingHook = findDelta(kMissingPair, "IofCallDriver");
    const FieldDelta* missingTarget =
        missingHook != nullptr ? findField(*missingHook, "target") : nullptr;
    s.expect(missingTarget != nullptr && missingTarget->change == FieldChange::kNotComparable,
             L"D-03 a missing module means the address is not comparable");
    s.expect(missingTarget != nullptr &&
                 missingTarget->normalization.state == AddressNormalizationState::kModuleNotFound,
             L"D-03 the missing-module reason is stated explicitly");
    s.expect(missingTarget != nullptr && missingTarget->normalization.earlierRva.present &&
                 !missingTarget->normalization.laterRva.present,
             L"D-03 the resolvable side keeps its RVA and the other stays unknown");
    s.expect(kMissingPair.modifiedCount == 0U,
             L"D-03 a missing module never manufactures a difference");

    // --- Different modules ---
    Snapshot otherModule = makeHookSnapshot("h-other", kBootB, kUtcLater, kLateHook);
    otherModule.modules.push_back(makeModule("m-other", "\\SystemRoot\\System32\\other.sys",
                                             "RSDS-OTHER", 0x900DU, kLateBase, kSize));
    const SnapshotComparison kOtherPair = compareSnapshots(earlier, otherModule);
    const EntityDelta* otherHook = findDelta(kOtherPair, "IofCallDriver");
    const FieldDelta* otherTarget = otherHook != nullptr ? findField(*otherHook, "target") : nullptr;
    s.expect(otherTarget != nullptr &&
                 otherTarget->normalization.state == AddressNormalizationState::kDifferentModule,
             L"D-03 resolving into a different module is stated as such");
    s.expect(otherTarget != nullptr && otherTarget->change == FieldChange::kNotComparable,
             L"D-03 a different module is not comparable");

    // --- 1. Only candidate-matching images: do not normalize if comparability cannot be confirmed ---
    Snapshot weakModule = makeHookSnapshot("h-weak", kBootB, kUtcLater, kLateHook);
    weakModule.modules.push_back(makeModule("m-copy", "\\Device\\Copy\\acme.sys", "", 0x600DU,
                                            kLateBase, kSize));
    Snapshot weakEarlier = makeHookSnapshot("h-weak-e", kBootA, kUtcEarlier, kEarlyHook);
    weakEarlier.modules.push_back(makeModule("m-orig", "\\SystemRoot\\System32\\acme.sys", "",
                                             0x600DU, kEarlyBase, kSize));
    const SnapshotComparison kWeakPair = compareSnapshots(weakEarlier, weakModule);
    const EntityDelta* weakHook = findDelta(kWeakPair, "IofCallDriver");
    const FieldDelta* weakTarget = weakHook != nullptr ? findField(*weakHook, "target") : nullptr;
    s.expect(weakTarget != nullptr &&
                 weakTarget->normalization.state == AddressNormalizationState::kImageIdentityWeak,
             L"D-03 a candidate-only image match does not license normalization");
    s.expect(weakTarget != nullptr && weakTarget->change == FieldChange::kNotComparable,
             L"D-03 a candidate-only image match yields not-comparable");

    // --- Unknown address: unknown is not a change ---
    Snapshot absentAddress = makeHookSnapshot("h-absent", kBootB, kUtcLater, kLateHook);
    absentAddress.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                               "RSDS-ACME-1", 0x600DU, kLateBase, kSize));
    absentAddress.entities.front().fields.clear();
    absentAddress.entities.front().fields.push_back(
        absentField("target", FieldSemantics::kKernelAddress));
    const SnapshotComparison kAbsentPair = compareSnapshots(earlier, absentAddress);
    const EntityDelta* absentHook = findDelta(kAbsentPair, "IofCallDriver");
    const FieldDelta* absentTarget =
        absentHook != nullptr ? findField(*absentHook, "target") : nullptr;
    s.expect(absentTarget != nullptr && absentTarget->change == FieldChange::kUnknown,
             L"D-03 an uncollected address is unknown, not a change");
    s.expect(absentTarget != nullptr && absentTarget->earlierKnown && !absentTarget->laterKnown,
             L"D-03 the unknown side is flagged rather than rendered as an empty value");
    s.expect(kAbsentPair.modifiedCount == 0U,
             L"D-03 an uncollected address never becomes a modification");
    s.expect(absentTarget != nullptr &&
                 absentTarget->normalization.state == AddressNormalizationState::kValueMissing,
             L"D-03 the missing-value reason is stated instead of a module verdict");

    // Different comparison semantics are declared on both sides of the same field name: it is unclear what is being compared, so no conclusion is given.
    Snapshot mixedSemantics = makeHookSnapshot("h-mixed", kBootB, kUtcLater, kLateHook);
    mixedSemantics.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                                "RSDS-ACME-1", 0x600DU, kLateBase, kSize));
    mixedSemantics.entities.front().fields.clear();
    mixedSemantics.entities.front().fields.push_back(
        numberField("target", kLateHook, FieldSemantics::kOpaque));
    const SnapshotComparison kMixedPair = compareSnapshots(earlier, mixedSemantics);
    const EntityDelta* mixedHook = findDelta(kMixedPair, "IofCallDriver");
    const FieldDelta* mixedTarget = mixedHook != nullptr ? findField(*mixedHook, "target") : nullptr;
    s.expect(mixedTarget != nullptr && mixedTarget->change == FieldChange::kNotComparable,
             L"D-03 two sides declaring different field semantics are not comparable");
    s.expect(kMixedPair.modifiedCount == 0U,
             L"D-03 a semantics mismatch never becomes a modification");

    // --- Module size unknown: Do not treat the entire address space as 'falling within this module' ---
    Snapshot sizelessModule = makeHookSnapshot("h-nosize", kBootB, kUtcLater, kLateHook);
    {
        SnapshotModule module;
        module.moduleId = "m-nosize";
        module.identity.imagePath = "\\SystemRoot\\System32\\acme.sys";
        module.identity.pdbSignature = "RSDS-ACME-1";
        module.identity.timeDateStamp = OptionalU64::of(0x600DU);
        module.identity.imageSize = OptionalU64::of(kSize);
        module.imageBase = OptionalU64::of(kLateBase);  // Size unknown
        sizelessModule.modules.push_back(module);
    }
    const SnapshotComparison kSizelessPair = compareSnapshots(earlier, sizelessModule);
    const EntityDelta* sizelessHook = findDelta(kSizelessPair, "IofCallDriver");
    const FieldDelta* sizelessTarget =
        sizelessHook != nullptr ? findField(*sizelessHook, "target") : nullptr;
    s.expect(sizelessTarget != nullptr &&
                 sizelessTarget->normalization.state == AddressNormalizationState::kModuleNotFound,
             L"D-03 a module with unknown size never claims an address");
    s.expect(kSizelessPair.modifiedCount == 0U,
             L"D-03 a module with unknown size does not manufacture a difference");

    // An address immediately after the image end is outside the half-open interval and must not count as a match.
    Snapshot pastEndEarlier = makeHookSnapshot("h-past-e", kBootA, kUtcEarlier, kEarlyBase + kSize);
    pastEndEarlier.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                                "RSDS-ACME-1", 0x600DU, kEarlyBase, kSize));
    Snapshot pastEndLater = makeHookSnapshot("h-past-l", kBootB, kUtcLater, kLateBase + kSize);
    pastEndLater.modules.push_back(makeModule("m-acme", "\\SystemRoot\\System32\\acme.sys",
                                              "RSDS-ACME-1", 0x600DU, kLateBase, kSize));
    const SnapshotComparison kPastEnd = compareSnapshots(pastEndEarlier, pastEndLater);
    const EntityDelta* pastHook = findDelta(kPastEnd, "IofCallDriver");
    const FieldDelta* pastTarget = pastHook != nullptr ? findField(*pastHook, "target") : nullptr;
    s.expect(pastTarget != nullptr &&
                 pastTarget->normalization.state == AddressNormalizationState::kModuleNotFound,
             L"D-03 an address one byte past the image end is outside the image");

    // --- Weak image identity driver entity: candidate matching is insufficient to eliminate base address differences
    auto makeWeakDriverSnapshot = [](const char* id, const char* bootId, std::uint64_t utc,
                                     std::uint64_t base) {
        Snapshot snapshot = makeSnapshot(id, bootId, utc);
        snapshot.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                                    CollectionStatus::kSuccess, bootId, utc, 1U,
                                                    "ev-drv"));
        SnapshotEntity entity;
        entity.partitionId = "drivers";
        entity.kind = ObjectKind::kDriver;
        entity.driver.imagePath = "\\??\\C:\\tmp\\unsigned.sys";  // No PDB, no stamp/size
        entity.rawRecordId = id;
        entity.fields.push_back(numberField("imageBase", base, FieldSemantics::kLoadBaseAddress));
        snapshot.entities.push_back(entity);
        return snapshot;
    };
    const SnapshotComparison kWeakDriver =
        compareSnapshots(makeWeakDriverSnapshot("wd-e", kBootA, kUtcEarlier, kEarlyBase),
                         makeWeakDriverSnapshot("wd-l", kBootB, kUtcLater, kLateBase));
    const EntityDelta* weakDriverDelta = findDelta(kWeakDriver, "\\??\\C:\\tmp\\unsigned.sys");
    s.expect(weakDriverDelta != nullptr &&
                 weakDriverDelta->matchConfidence == MatchConfidence::kUncertain,
             L"D-03 a driver with only a path matches at most as uncertain");
    const FieldDelta* weakDriverBase =
        weakDriverDelta != nullptr ? findField(*weakDriverDelta, "imageBase") : nullptr;
    s.expect(weakDriverBase != nullptr &&
                 weakDriverBase->normalization.state == AddressNormalizationState::kImageIdentityWeak,
             L"D-03 a candidate-only driver identity does not license base normalization");
    s.expect(weakDriverBase != nullptr && weakDriverBase->change == FieldChange::kNotComparable,
             L"D-03 an unconfirmed image identity leaves the base not comparable");
    s.expect(kWeakDriver.modifiedCount == 0U,
             L"D-03 an unconfirmed image identity does not manufacture a modification");

    // --- LoadBaseAddress normalization is only safe when image identity exists ---
    Snapshot svcEarlier = makeSnapshot("s-early", kBootA, kUtcEarlier);
    svcEarlier.partitions.push_back(makePartition("svc", ObjectKind::kService,
                                                  CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                  1U, "ev-e"));
    {
        SnapshotEntity entity = makeServiceEntity("svc", "AcmeSvc", "e-s", 0U);
        entity.fields.push_back(numberField("imageBase", kEarlyBase, FieldSemantics::kLoadBaseAddress));
        svcEarlier.entities.push_back(entity);
    }
    Snapshot svcLater = makeSnapshot("s-late", kBootA, kUtcLater);
    svcLater.partitions.push_back(makePartition("svc", ObjectKind::kService,
                                                CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                                "ev-l"));
    {
        SnapshotEntity entity = makeServiceEntity("svc", "AcmeSvc", "l-s", 0U);
        entity.fields.push_back(numberField("imageBase", kLateBase, FieldSemantics::kLoadBaseAddress));
        svcLater.entities.push_back(entity);
    }
    const SnapshotComparison kSvcPair = compareSnapshots(svcEarlier, svcLater);
    const EntityDelta* svcDelta = findDelta(kSvcPair, "AcmeSvc");
    const FieldDelta* svcBase = svcDelta != nullptr ? findField(*svcDelta, "imageBase") : nullptr;
    s.expect(svcBase != nullptr && svcBase->change == FieldChange::kNotComparable,
             L"D-03 a load base on an entity without image identity is not comparable");
    s.expect(svcBase != nullptr &&
                 svcBase->normalization.state == AddressNormalizationState::kImageIdentityWeak,
             L"D-03 the missing image identity is stated as the reason");
    s.expect(kSvcPair.modifiedCount == 0U,
             L"D-03 an unnormalizable load base does not become a modification");
}

// ---------------------------------------------------------------------------
// D-04 Unknown does not equal delete
// ---------------------------------------------------------------------------
Snapshot buildFourPartitionSnapshot(const char* id, std::uint64_t utc, const char* prefix) {
    Snapshot snapshot = makeSnapshot(id, kBootA, utc);
    snapshot.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                CollectionStatus::kSuccess, kBootA, utc, 1U,
                                                "ev-proc"));
    snapshot.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                                CollectionStatus::kSuccess, kBootA, utc, 1U,
                                                "ev-drv"));
    snapshot.partitions.push_back(makePartition("services", ObjectKind::kService,
                                                CollectionStatus::kSuccess, kBootA, utc, 1U,
                                                "ev-svc"));
    snapshot.partitions.push_back(makePartition("files", ObjectKind::kFile, CollectionStatus::kSuccess,
                                                kBootA, utc, 1U, "ev-file"));
    snapshot.entities.push_back(
        makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", (std::string(prefix) + "-p").c_str(), 0U));
    snapshot.entities.push_back(makeDriverEntity("drivers", "\\SystemRoot\\System32\\acme.sys",
                                                 "RSDS-ACME-1", 0x600DU, 0x8000U,
                                                 (std::string(prefix) + "-d").c_str(), 0U));
    snapshot.entities.push_back(
        makeServiceEntity("services", "AcmeSvc", (std::string(prefix) + "-s").c_str(), 0U));
    {
        SnapshotEntity file;
        file.partitionId = "files";
        file.kind = ObjectKind::kFile;
        file.file.path = "C:\\Program Files\\Acme\\acme.exe";
        file.file.contentHash = "sha256:aaaa";
        file.rawRecordId = std::string(prefix) + "-f";
        snapshot.entities.push_back(file);
    }
    return snapshot;
}

void testUnknownIsNotRemoval(ksword_tests::Suite& s) {
    const Snapshot kBaseEarlier = buildFourPartitionSnapshot("u-early", kUtcEarlier, "e");
    const Snapshot kBaseLater = buildFourPartitionSnapshot("u-late", kUtcLater, "l");

    const SnapshotComparison kClean = compareSnapshots(kBaseEarlier, kBaseLater);
    s.expect(kClean.unchangedCount == 4U, L"D-04 the untouched baseline compares as four unchanged");
    s.expect(kClean.removedCount == 0U && kClean.addedCount == 0U,
             L"D-04 the untouched baseline reports no additions or removals");
    s.expect(kClean.conclusion == AnalysisConclusion::kNoDifferenceObserved,
             L"D-04 a fully covered identical pair observes no difference");
    s.expect(kClean.selfCheckPassed, L"D-04 the baseline comparison passes its self check");

    struct Injection final {
        const char* partitionId;
        const char* entityRaw;
        CollectionStatus status;
    };
    const Injection kInjections[] = {
        {"processes", "e-p", CollectionStatus::kAccessDenied},
        {"drivers", "e-d", CollectionStatus::kUnsupported},
        {"services", "e-s", CollectionStatus::kTimeout},
        {"files", "e-f", CollectionStatus::kError},
    };

    for (const Injection& injection : kInjections) {
        Snapshot broken = kBaseLater;
        for (SnapshotPartition& partition : broken.partitions) {
            if (partition.partitionId == std::string(injection.partitionId)) {
                partition.envelope.outcome = CollectionOutcome::failure(
                    injection.status, "NTSTATUS", 0xC0000022ULL, "collector reported failure");
                partition.envelope.coverage = CoverageAccount{};
            }
        }
        // A collector that fails to collect produces no rows—this is precisely the scenario where an empty table is read as 'all removed'.
        std::vector<SnapshotEntity> kept;
        for (const SnapshotEntity& entity : broken.entities) {
            if (entity.partitionId != std::string(injection.partitionId)) {
                kept.push_back(entity);
            }
        }
        broken.entities = kept;

        const SnapshotComparison kResult = compareSnapshots(kBaseEarlier, broken);
        s.expect(kResult.removedCount == 0U,
                 L"D-04 an injected collector failure never reports removals");
        const EntityDelta* orphan = findDeltaByRaw(kResult, injection.entityRaw);
        s.expect(orphan != nullptr && orphan->change == EntityChange::kNotComparable,
                 L"D-04 the orphaned entity is NotComparable");
        s.expect(orphan != nullptr && orphan->laterState == EntitySideState::kUnknownSourceFailed,
                 L"D-04 the failed side is marked source-failed, not absent");
        s.expect(orphan != nullptr &&
                     contains(orphan->limitationKeys, "snapshot.limitation.sourceFailed"),
                 L"D-04 the source-failure limitation is stated on the delta");
        const PartitionAccount* account = findAccount(kResult, injection.partitionId);
        s.expect(account != nullptr && account->laterStatus == injection.status,
                 L"D-04 the original collection status is preserved in the account");
        s.expect(account != nullptr && !account->comparable,
                 L"D-04 a failed partition is not comparable");
        s.expect(account != nullptr && account->conclusion == AnalysisConclusion::kNoEvidence,
                 L"D-04 a failed partition concludes NoEvidence, never NoDifferenceObserved");
        // The remaining three partitions are compared normally; a single collector failure does not affect others.
        s.expect(kResult.unchangedCount == 3U,
                 L"D-04 the successfully covered partitions still compare on their own");
        s.expect(kResult.conclusion == AnalysisConclusion::kIndeterminate,
                 L"D-04 a partially failed comparison is Indeterminate");
    }

    // Partition entirely missing: must be explicitly marked as NotCollected and accounted for; it cannot be skipped.
    {
        Snapshot missing = kBaseLater;
        std::vector<SnapshotPartition> keptPartitions;
        for (const SnapshotPartition& partition : missing.partitions) {
            if (partition.partitionId != std::string("drivers")) {
                keptPartitions.push_back(partition);
            }
        }
        missing.partitions = keptPartitions;
        std::vector<SnapshotEntity> keptEntities;
        for (const SnapshotEntity& entity : missing.entities) {
            if (entity.partitionId != std::string("drivers")) {
                keptEntities.push_back(entity);
            }
        }
        missing.entities = keptEntities;

        const SnapshotComparison kResult = compareSnapshots(kBaseEarlier, missing);
        s.expect(kResult.partitions.size() == 4U,
                 L"D-04 an entirely absent partition still appears in the account");
        const PartitionAccount* account = findAccount(kResult, "drivers");
        s.expect(account != nullptr && !account->laterPresent,
                 L"D-04 the absent partition is recorded as absent");
        s.expect(account != nullptr && account->laterStatus == CollectionStatus::kNotCollected,
                 L"D-04 an absent partition is NotCollected, not silently successful");
        s.expect(account != nullptr &&
                     contains(account->limitationKeys, "snapshot.partition.laterNotCollected"),
                 L"D-04 the absent partition states its limitation");
        s.expect(kResult.removedCount == 0U,
                 L"D-04 an entirely absent partition never reports removals");
        s.expect(kResult.conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"D-04 an entirely absent partition cannot yield NoDifferenceObserved");
    }

    // Successfully covered some parts that can still be compared individually: drivers failed while processes actually have one fewer line.
    {
        Snapshot mixed = kBaseLater;
        for (SnapshotPartition& partition : mixed.partitions) {
            if (partition.partitionId == std::string("drivers")) {
                partition.envelope.outcome = CollectionOutcome::failure(
                    CollectionStatus::kAccessDenied, "WIN32", 5ULL, "access denied");
                partition.envelope.coverage = CoverageAccount{};
            }
            if (partition.partitionId == std::string("processes")) {
                partition.envelope.coverage.totalKnown = OptionalU64::of(0U);
                partition.envelope.coverage.succeeded = 0U;
            }
        }
        std::vector<SnapshotEntity> kept;
        for (const SnapshotEntity& entity : mixed.entities) {
            if (entity.partitionId != std::string("drivers") &&
                entity.partitionId != std::string("processes")) {
                kept.push_back(entity);
            }
        }
        mixed.entities = kept;

        const SnapshotComparison kResult = compareSnapshots(kBaseEarlier, mixed);
        s.expect(kResult.removedCount == 1U,
                 L"D-04 a covered partition still reports its own genuine removal");
        const EntityDelta* removed = findDeltaByRaw(kResult, "e-p");
        s.expect(removed != nullptr && removed->change == EntityChange::kRemoved,
                 L"D-04 the removal comes from the partition that really covered its scope");
        const EntityDelta* blocked = findDeltaByRaw(kResult, "e-d");
        s.expect(blocked != nullptr && blocked->change == EntityChange::kNotComparable,
                 L"D-04 the failed partition's entity stays not comparable in the same run");
        s.expect(kResult.conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"D-04 a genuine removal alongside a failure is still DifferenceObserved");
    }

    // The entity references a partition with no declared account: it must be posted and marked as NotCollected; it
    // cannot be silently skipped. 'No account' and 'Account says all collected' must never result in the same outcome.
    {
        Snapshot rogueEarlier = kBaseEarlier;
        SnapshotEntity rogue = makeServiceEntity("rogue", "GhostSvc", "e-rogue", 0U);
        rogueEarlier.entities.push_back(rogue);

        const SnapshotComparison kResult = compareSnapshots(rogueEarlier, kBaseLater);
        const PartitionAccount* account = findAccount(kResult, "rogue");
        s.expect(account != nullptr,
                 L"D-04 a partition referenced only by entities still appears in the account");
        s.expect(account != nullptr && !account->earlierPresent && !account->laterPresent,
                 L"D-04 an undeclared partition is recorded as absent on both sides");
        s.expect(account != nullptr && account->earlierStatus == CollectionStatus::kNotCollected &&
                     account->laterStatus == CollectionStatus::kNotCollected,
                 L"D-04 an undeclared partition is NotCollected on both sides");
        s.expect(account != nullptr && !account->comparable,
                 L"D-04 an undeclared partition is not comparable");
        const EntityDelta* ghost = findDeltaByRaw(kResult, "e-rogue");
        s.expect(ghost != nullptr && ghost->change == EntityChange::kNotComparable,
                 L"D-04 an entity without a collection account cannot be compared");
        s.expect(kResult.removedCount == 0U,
                 L"D-04 an entity without a collection account is never reported as removed");
    }

    // The sole partition also failed: the full comparison has no available observations, so the conclusion must be NoEvidence.
    {
        Snapshot soloEarlier = makeSnapshot("solo-e", kBootA, kUtcEarlier);
        soloEarlier.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                                       CollectionStatus::kSuccess, kBootA,
                                                       kUtcEarlier, 1U, "ev-e"));
        soloEarlier.entities.push_back(
            makeProcess("processes", kBootA, 100U, 111ULL, "alpha.exe", "solo-p", 0U));

        Snapshot soloLater = makeSnapshot("solo-l", kBootA, kUtcLater);
        SnapshotPartition denied = makePartition("processes", ObjectKind::kProcess,
                                                 CollectionStatus::kAccessDenied, kBootA, kUtcLater,
                                                 0U, "ev-l");
        denied.envelope.coverage = CoverageAccount{};
        denied.envelope.outcome = CollectionOutcome::failure(CollectionStatus::kAccessDenied, "WIN32",
                                                             5ULL, "access denied");
        soloLater.partitions.push_back(denied);

        const SnapshotComparison kResult = compareSnapshots(soloEarlier, soloLater);
        s.expect(kResult.conclusion == AnalysisConclusion::kNoEvidence,
                 L"D-04 a comparison with no usable partition concludes NoEvidence");
        s.expect(kResult.removedCount == 0U,
                 L"D-04 a comparison with no usable partition reports no removals");
        s.expect(kResult.notComparableCount == 1U,
                 L"D-04 the orphaned entity is still reported, just not comparable");
    }

    // Failures on the old side must not become 'new'.
    {
        Snapshot brokenEarlier = kBaseEarlier;
        for (SnapshotPartition& partition : brokenEarlier.partitions) {
            if (partition.partitionId == std::string("services")) {
                partition.envelope.outcome = CollectionOutcome::failure(
                    CollectionStatus::kUnsupported, "WIN32", 50ULL, "not supported");
                partition.envelope.coverage = CoverageAccount{};
            }
        }
        std::vector<SnapshotEntity> kept;
        for (const SnapshotEntity& entity : brokenEarlier.entities) {
            if (entity.partitionId != std::string("services")) {
                kept.push_back(entity);
            }
        }
        brokenEarlier.entities = kept;
        const SnapshotComparison kResult = compareSnapshots(brokenEarlier, kBaseLater);
        s.expect(kResult.addedCount == 0U,
                 L"D-04 an earlier-side collector failure never reports additions");
        const EntityDelta* svc = findDeltaByRaw(kResult, "l-s");
        s.expect(svc != nullptr && svc->earlierState == EntitySideState::kUnknownSourceFailed,
                 L"D-04 the failed earlier side is marked source-failed");
    }
}

// ---------------------------------------------------------------------------
// D-05 Change Explanation
// ---------------------------------------------------------------------------
void testChangeExplanation(ksword_tests::Suite& s) {
    Snapshot earlier = makeSnapshot("c-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("services", ObjectKind::kService,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 1U,
                                               "ev-svc-early"));
    {
        SnapshotEntity entity = makeServiceEntity("services", "AcmeSvc", "e-svc", 0U);
        entity.fields.push_back(textField("startType", "manual"));
        entity.fields.push_back(textField("imagePath", "C:\\Program Files\\Acme\\acme.exe"));
        earlier.entities.push_back(entity);
    }

    Snapshot later = makeSnapshot("c-late", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("services", ObjectKind::kService,
                                             CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                             "ev-svc-late"));
    {
        SnapshotEntity entity = makeServiceEntity("services", "AcmeSvc", "l-svc", 0U);
        entity.fields.push_back(textField("startType", "auto"));
        entity.fields.push_back(textField("imagePath", "C:\\Program Files\\Acme\\acme.exe"));
        later.entities.push_back(entity);
    }

    const SnapshotComparison kPlain = compareSnapshots(earlier, later);
    const EntityDelta* svc = findDelta(kPlain, "AcmeSvc");
    s.expect(svc != nullptr && svc->change == EntityChange::kModified,
             L"D-05 a changed configuration field makes the entity Modified");
    s.expect(svc != nullptr && svc->fields.size() == 1U,
             L"D-05 only the field that actually has something to say is reported");
    const FieldDelta* startType = svc != nullptr ? findField(*svc, "startType") : nullptr;
    s.expect(startType != nullptr && startType->earlierText == std::string("manual"),
             L"D-05 the old value is reported verbatim");
    s.expect(startType != nullptr && startType->laterText == std::string("auto"),
             L"D-05 the new value is reported verbatim");
    s.expect(startType != nullptr && startType->earlierKnown && startType->laterKnown,
             L"D-05 both sides are flagged as known");
    s.expect(startType != nullptr && startType->earlierCollectorId == std::string("services"),
             L"D-05 the field change names the collector it came from");
    s.expect(startType != nullptr && startType->earlierEvidenceId == std::string("ev-svc-early"),
             L"D-05 the field change references the earlier evidence id");
    s.expect(startType != nullptr && startType->laterEvidenceId == std::string("ev-svc-late"),
             L"D-05 the field change references the later evidence id");
    s.expect(startType != nullptr && startType->earlierObservedUtc100ns.present &&
                 startType->earlierObservedUtc100ns.value == kUtcEarlier + 1000ULL,
             L"D-05 the field change carries the earlier observation time");
    s.expect(startType != nullptr && startType->laterObservedUtc100ns.present &&
                 startType->laterObservedUtc100ns.value == kUtcLater + 1000ULL,
             L"D-05 the field change carries the later observation time");
    s.expect(svc != nullptr && svc->earlierRawRecordId == std::string("e-svc") &&
                 svc->laterRawRecordId == std::string("l-svc"),
             L"D-05 the delta links back to both source records");

    // Risk explanation and change facts are separated: no priority is generated when no rule is declared.
    s.expect(svc != nullptr && svc->review.priority == ReviewPriority::kNotAssessed,
             L"D-05 with no declared policy a configuration change carries no review priority");
    s.expect(svc != nullptr && svc->review.reasonKeys.empty(),
             L"D-05 with no declared policy there are no review reasons");

    SnapshotCompareOptions options;
    ReviewRule rule;
    rule.partitionId = "services";
    rule.fieldName = "startType";
    rule.priority = ReviewPriority::kNeedsReview;
    rule.reasonKey = "review.service.startTypeChanged";
    options.reviewRules.push_back(rule);
    ReviewRule unrelated;
    unrelated.partitionId = "services";
    unrelated.fieldName = "imagePath";
    unrelated.priority = ReviewPriority::kNeedsReview;
    unrelated.reasonKey = "review.service.imagePathChanged";
    options.reviewRules.push_back(unrelated);

    const SnapshotComparison kReviewed = compareSnapshots(earlier, later, options);
    const EntityDelta* reviewedSvc = findDelta(kReviewed, "AcmeSvc");
    s.expect(reviewedSvc != nullptr && reviewedSvc->review.priority == ReviewPriority::kNeedsReview,
             L"D-05 a declared review rule raises the priority");
    s.expect(reviewedSvc != nullptr &&
                 contains(reviewedSvc->review.reasonKeys, "review.service.startTypeChanged"),
             L"D-05 the declared reason key is attached");
    s.expect(reviewedSvc != nullptr &&
                 !contains(reviewedSvc->review.reasonKeys, "review.service.imagePathChanged"),
             L"D-05 a rule for an unchanged field does not fire");
    s.expect(reviewedSvc != nullptr && reviewedSvc->change == EntityChange::kModified,
             L"D-05 the review priority does not alter the change fact");
    s.expect(kReviewed.modifiedCount == kPlain.modifiedCount,
             L"D-05 declaring a review policy does not change the observed counts");

    // Unknown fields must not be written as 'became null'.
    Snapshot absentLater = later;
    absentLater.entities.front().fields.clear();
    absentLater.entities.front().fields.push_back(absentField("startType"));
    absentLater.entities.front().fields.push_back(
        textField("imagePath", "C:\\Program Files\\Acme\\acme.exe"));
    const SnapshotComparison kAbsentPair = compareSnapshots(earlier, absentLater);
    const EntityDelta* absentSvc = findDelta(kAbsentPair, "AcmeSvc");
    const FieldDelta* absentField =
        absentSvc != nullptr ? findField(*absentSvc, "startType") : nullptr;
    s.expect(absentField != nullptr && absentField->change == FieldChange::kUnknown,
             L"D-05 an uncollected field is unknown rather than changed");
    s.expect(absentField != nullptr && !absentField->laterKnown && absentField->laterText.empty(),
             L"D-05 an uncollected field does not render as an empty value");
    s.expect(absentSvc != nullptr && absentSvc->change == EntityChange::kPartiallyComparable,
             L"D-05 an entity with one unknown field is PartiallyComparable, not Modified");
    s.expect(kAbsentPair.modifiedCount == 0U,
             L"D-05 an uncollected field never counts as a modification");
}

// ---------------------------------------------------------------------------
// D-06 persistence compatibility
// ---------------------------------------------------------------------------
void testPersistence(ksword_tests::Suite& s) {
    // --- Handwritten legacy fixture: only fill fields required by the first format version ---
    const char* legacy =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"versionMinor\":0,"
        "\"snapshotId\":\"legacy-1\","
        "\"partitions\":[{\"partitionId\":\"services\",\"kind\":\"Service\",\"coversScope\":true,"
        "\"envelope\":{\"outcome\":{\"status\":\"Success\"},"
        "\"coverage\":{\"totalKnown\":\"1\",\"succeeded\":\"1\"}}}],"
        "\"entities\":[{\"partitionId\":\"services\",\"kind\":\"Service\",\"rawRecordId\":\"row-1\","
        "\"logical\":{\"domain\":\"service\",\"name\":\"AcmeSvc\"},"
        "\"fields\":[{\"name\":\"startType\",\"kind\":\"Text\",\"text\":\"auto\"}]}]}";
    const SnapshotLoadResult kLegacyResult = readSnapshotJson(legacy);
    s.expect(kLegacyResult.status == SnapshotLoadStatus::kOk,
             L"D-06 a legacy first-version fixture still loads");
    s.expect(kLegacyResult.versionMajor == 1U && kLegacyResult.versionMinor == 0U,
             L"D-06 the legacy fixture reports version 1.0");
    s.expect(kLegacyResult.snapshot.snapshotId == std::string("legacy-1"),
             L"D-06 the legacy snapshot id is read back");
    s.expect(kLegacyResult.snapshot.entities.size() == 1U,
             L"D-06 the legacy fixture yields exactly one entity");
    s.expect(!kLegacyResult.snapshot.entities.empty() &&
                 kLegacyResult.snapshot.entities.front().logical.name == std::string("AcmeSvc"),
             L"D-06 the legacy logical identity is read back");
    s.expect(!kLegacyResult.snapshot.entities.empty() &&
                 kLegacyResult.snapshot.entities.front().fields.size() == 1U &&
                 kLegacyResult.snapshot.entities.front().fields.front().text == std::string("auto"),
             L"D-06 the legacy field value is read back");
    s.expect(!kLegacyResult.snapshot.partitions.empty() &&
                 kLegacyResult.snapshot.partitions.front().envelope.coverage.totalKnown.present &&
                 kLegacyResult.snapshot.partitions.front().envelope.coverage.totalKnown.value == 1ULL,
             L"D-06 the legacy coverage account is read back losslessly");
    s.expect(!kLegacyResult.snapshot.scope.declared,
             L"D-06 a legacy snapshot without a scope block stays undeclared");
    const SnapshotComparison kLegacyPair =
        compareSnapshots(kLegacyResult.snapshot, kLegacyResult.snapshot);
    s.expect(kLegacyPair.scope == ScopeComparability::kUnknown,
             L"D-06 legacy data with no declared scope is still viewable but scope-unknown");
    s.expect(kLegacyPair.removedCount == 0U,
             L"D-06 legacy data with no declared scope never reports removals");

    // --- Future optional fields: retain and write back unchanged.
    const char* future =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"versionMinor\":4,"
        "\"snapshotId\":\"future-1\",\"futureTopLevel\":{\"nested\":\"keep-top\"},"
        "\"entities\":[{\"partitionId\":\"services\",\"kind\":\"Service\","
        "\"logical\":{\"domain\":\"service\",\"name\":\"AcmeSvc\"},"
        "\"futureEntityField\":\"keep-entity\"}]}";
    const SnapshotLoadResult kFutureResult = readSnapshotJson(future);
    s.expect(kFutureResult.status == SnapshotLoadStatus::kOkWithUnknownFields,
             L"D-06 unknown optional fields load with an explicit status");
    s.expect(kFutureResult.ok(), L"D-06 unknown optional fields are not an error");
    s.expect(kFutureResult.versionMinor == 4U,
             L"D-06 a newer minor version is accepted and reported");
    s.expect(contains(kFutureResult.unknownFieldPaths, "root.futureTopLevel"),
             L"D-06 the unknown top-level field is listed");
    s.expect(contains(kFutureResult.unknownFieldPaths, "root.entities[].futureEntityField"),
             L"D-06 the unknown entity field is listed");
    const std::string kRewritten = writeSnapshotJson(kFutureResult.snapshot);
    s.expect(textContains(kRewritten, "keep-top"),
             L"D-06 an unknown top-level field survives a save");
    s.expect(textContains(kRewritten, "keep-entity"),
             L"D-06 an unknown entity field survives a save");
    const SnapshotLoadResult kReloaded = readSnapshotJson(kRewritten);
    s.expect(kReloaded.status == SnapshotLoadStatus::kOkWithUnknownFields,
             L"D-06 the rewritten document still reports its unknown fields");

    // --- Future major version: Explicitly rejected ---
    const char* futureMajor =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":2,\"versionMinor\":0,"
        "\"snapshotId\":\"v2\",\"entities\":[]}";
    const SnapshotLoadResult kMajorResult = readSnapshotJson(futureMajor);
    s.expect(kMajorResult.status == SnapshotLoadStatus::kUnsupportedMajorVersion,
             L"D-06 an unknown major version is rejected explicitly");
    s.expect(!kMajorResult.ok(), L"D-06 an unknown major version is not treated as loadable");
    s.expect(kMajorResult.versionMajor == 2U,
             L"D-06 the rejected major version is reported back");
    s.expect(kMajorResult.snapshot.entities.empty() && kMajorResult.snapshot.snapshotId.empty(),
             L"D-06 a rejected document leaves no half-parsed snapshot behind");

    // --- Malformed format ---
    const SnapshotLoadResult kBroken = readSnapshotJson("{\"schema\":");
    s.expect(kBroken.status == SnapshotLoadStatus::kMalformedJson,
             L"D-06 malformed JSON produces an explicit error state");
    s.expect(!kBroken.errorDetail.empty(),
             L"D-06 the malformed-JSON error keeps the parser's own status name");
    s.expect(kBroken.snapshot.entities.empty(),
             L"D-06 malformed JSON leaves no partially applied snapshot");
    const SnapshotLoadResult kEmpty = readSnapshotJson("");
    s.expect(kEmpty.status == SnapshotLoadStatus::kEmptyInput,
             L"D-06 empty input is distinguished from malformed input");
    const SnapshotLoadResult kWrongSchema =
        readSnapshotJson("{\"schema\":\"other.tool\",\"versionMajor\":1}");
    s.expect(kWrongSchema.status == SnapshotLoadStatus::kWrongSchemaId,
             L"D-06 a foreign schema id is rejected as such");
    const SnapshotLoadResult kNoSchema = readSnapshotJson("{\"versionMajor\":1}");
    s.expect(kNoSchema.status == SnapshotLoadStatus::kMissingSchema,
             L"D-06 a missing schema id is its own error state");
    const SnapshotLoadResult kBadEnum =
        readSnapshotJson("{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,"
                         "\"entities\":[{\"partitionId\":\"p\",\"kind\":\"Alien\"}]}");
    s.expect(kBadEnum.status == SnapshotLoadStatus::kInvalidFieldValue,
             L"D-06 an unknown enum name fails instead of silently defaulting");
    s.expect(textContains(kBadEnum.errorDetail, "Alien"),
             L"D-06 the offending enum value is reported back");
    const SnapshotLoadResult kFloatRejected =
        readSnapshotJson("{\"schema\":\"ksword.snapshot\",\"versionMajor\":1.0}");
    s.expect(kFloatRejected.status == SnapshotLoadStatus::kMalformedJson,
             L"D-06 a floating point number is rejected by the lossless reader");

    // --- Round-trip: Construct a full snapshot first, then verify against the handwritten expected values ---
    Snapshot rich = makeSnapshot("rt-1", kBootA, kUtcEarlier);
    rich.scope.wholeDomain = false;
    rich.scope.selectors = {"C:", "D:"};
    rich.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                            CollectionStatus::kPartial, kBootA, kUtcEarlier, 9U,
                                            "ev-rt"));
    rich.partitions.back().envelope.outcome.nativeCode = OptionalU64::of(0xC0000022ULL);
    rich.partitions.back().envelope.outcome.nativeCodeDomain = "NTSTATUS";
    rich.partitions.back().envelope.outcome.message = "partial enumeration";
    rich.partitions.back().envelope.coverage.truncated = 2U;
    rich.modules.push_back(makeModule("m1", "\\SystemRoot\\acme.sys", "RSDS-1", 0x600DU,
                                      0xFFFFF80000100000ULL, 0x8000ULL));
    {
        SnapshotEntity driver = makeDriverEntity("drivers", "\\SystemRoot\\acme.sys", "RSDS-1",
                                                 0x600DU, 0x8000U, "row-9", 3U);
        driver.fields.push_back(numberField("target", 0xFFFFF80000101234ULL,
                                            FieldSemantics::kKernelAddress));
        driver.fields.push_back(absentField("notes"));
        rich.entities.push_back(driver);
    }
    const std::string kWritten = writeSnapshotJson(rich, 0U);
    s.expect(textContains(kWritten, "\"schema\":\"ksword.snapshot\""),
             L"D-06 the written document declares the schema id");
    s.expect(textContains(kWritten, "0xFFFFF80000101234"),
             L"D-06 a 64-bit address is written as a lossless hex string");
    const SnapshotLoadResult kRoundTrip = readSnapshotJson(kWritten);
    s.expect(kRoundTrip.status == SnapshotLoadStatus::kOk,
             L"D-06 the round-tripped document loads cleanly");
    s.expect(kRoundTrip.snapshot.scope.selectors.size() == 2U &&
                 kRoundTrip.snapshot.scope.selectors.front() == std::string("C:"),
             L"D-06 the declared selection survives the round trip");
    s.expect(!kRoundTrip.snapshot.partitions.empty() &&
                 kRoundTrip.snapshot.partitions.front().envelope.outcome.status ==
                     CollectionStatus::kPartial,
             L"D-06 the collection status survives the round trip");
    s.expect(!kRoundTrip.snapshot.partitions.empty() &&
                 kRoundTrip.snapshot.partitions.front().envelope.outcome.nativeCode.present &&
                 kRoundTrip.snapshot.partitions.front().envelope.outcome.nativeCode.value ==
                     0xC0000022ULL,
             L"D-06 the original native error code survives the round trip");
    s.expect(!kRoundTrip.snapshot.partitions.empty() &&
                 kRoundTrip.snapshot.partitions.front().envelope.coverage.truncated == 2U,
             L"D-06 the truncation count survives the round trip");
    s.expect(!kRoundTrip.snapshot.entities.empty() &&
                 kRoundTrip.snapshot.entities.front().displayOrder == 3U,
             L"D-06 the display order survives the round trip");
    s.expect(kRoundTrip.snapshot.entities.size() == 1U &&
                 kRoundTrip.snapshot.entities.front().fields.size() == 2U,
             L"D-06 both fields survive the round trip");
    s.expect(!kRoundTrip.snapshot.entities.empty() &&
                 kRoundTrip.snapshot.entities.front().fields.front().number.present &&
                 kRoundTrip.snapshot.entities.front().fields.front().number.value ==
                     0xFFFFF80000101234ULL,
             L"D-06 the 64-bit address is restored bit for bit");
    s.expect(!kRoundTrip.snapshot.entities.empty() &&
                 kRoundTrip.snapshot.entities.front().fields.back().kind == FieldValueKind::kAbsent &&
                 !kRoundTrip.snapshot.entities.front().fields.back().number.present,
             L"D-06 an absent value stays absent instead of becoming zero");

    // Explicit 0 and null must be read back as two distinct states.
    const SnapshotLoadResult kZeroVsNull = readSnapshotJson(
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,"
        "\"entities\":[{\"partitionId\":\"p\",\"kind\":\"Service\",\"fields\":["
        "{\"name\":\"a\",\"kind\":\"Number\",\"number\":\"0\"},"
        "{\"name\":\"b\",\"kind\":\"Number\",\"number\":null}]}]}");
    s.expect(kZeroVsNull.ok(), L"D-06 the zero-versus-null fixture loads");
    s.expect(kZeroVsNull.ok() && kZeroVsNull.snapshot.entities.front().fields.front().number.present &&
                 kZeroVsNull.snapshot.entities.front().fields.front().number.value == 0ULL,
             L"D-06 an explicit zero is read back as a present zero");
    s.expect(kZeroVsNull.ok() && !kZeroVsNull.snapshot.entities.front().fields.back().number.present,
             L"D-06 a null value is read back as unknown, not as zero");
}

// ---------------------------------------------------------------------------
// D-07 Desensitization must not break associations
// ---------------------------------------------------------------------------
Snapshot buildSensitiveSnapshot(const char* id, std::uint64_t utc, const char* startType) {
    Snapshot snapshot = makeSnapshot(id, kBootA, utc);
    snapshot.envelope.window.machineId = "WORKSTATION-7";
    snapshot.partitions.push_back(makePartition("files", ObjectKind::kFile, CollectionStatus::kSuccess,
                                                kBootA, utc, 3U, "ev-files"));
    snapshot.partitions.back().envelope.window.machineId = "WORKSTATION-7";
    snapshot.partitions.back().envelope.outcome.message =
        "opened C:\\Users\\alice\\ntuser.dat on WORKSTATION-7";
    snapshot.partitions.push_back(makePartition("services", ObjectKind::kService,
                                                CollectionStatus::kSuccess, kBootA, utc, 1U,
                                                "ev-svc"));
    snapshot.partitions.back().envelope.window.machineId = "WORKSTATION-7";

    auto addFile = [&snapshot](const char* path, const char* hash, const char* rawId) {
        SnapshotEntity entity;
        entity.partitionId = "files";
        entity.kind = ObjectKind::kFile;
        entity.file.path = path;
        entity.file.contentHash = hash;
        entity.rawRecordId = rawId;
        snapshot.entities.push_back(entity);
    };
    addFile("C:\\Users\\alice\\Documents\\report.docx", "sha256:1111", "f-1");
    addFile("C:\\Users\\alice\\AppData\\Local\\Temp\\stage.tmp", "sha256:2222", "f-2");
    addFile("C:\\Users\\bob\\Desktop\\notes.txt", "sha256:3333", "f-3");

    SnapshotEntity service = makeServiceEntity("services", "AcmeSvc", "s-1", 0U);
    service.fields.push_back(textField("startType", startType));
    EntityField owner = textField("owner", "alice");
    owner.redaction = RedactionClass::kUserName;
    service.fields.push_back(owner);
    EntityField sid = textField("ownerSid", "S-1-5-21-1111-2222-3333-1001");
    sid.redaction = RedactionClass::kAccountSid;
    service.fields.push_back(sid);
    service.fields.push_back(textField("logPath", "\\\\WORKSTATION-7\\logs\\alice\\svc.log"));
    snapshot.entities.push_back(service);
    return snapshot;
}

void testRedaction(ksword_tests::Suite& s) {
    const Snapshot kEarlier = buildSensitiveSnapshot("r-early", kUtcEarlier, "manual");
    const Snapshot kLater = buildSensitiveSnapshot("r-late", kUtcLater, "auto");

    const SnapshotComparison kPlain = compareSnapshots(kEarlier, kLater);
    s.expect(kPlain.modifiedCount == 1U,
             L"D-07 the unredacted pair shows exactly one modified object");
    s.expect(kPlain.unchangedCount == 3U,
             L"D-07 the unredacted pair shows three unchanged files");
    s.expect(kPlain.addedCount == 0U && kPlain.removedCount == 0U,
             L"D-07 the unredacted pair has no additions or removals");

    RedactionSession session;
    Snapshot redactedEarlier;
    Snapshot redactedLater;
    session.redact(kEarlier, redactedEarlier);
    session.redact(kLater, redactedLater);

    const std::string kAliceToken = session.replacementFor(RedactionClass::kUserName, "alice");
    const std::string kAliceUpper = session.replacementFor(RedactionClass::kUserName, "ALICE");
    const std::string kBobToken = session.replacementFor(RedactionClass::kUserName, "bob");
    const std::string kHostToken = session.replacementFor(RedactionClass::kHostname, "WORKSTATION-7");
    const std::string kSidToken =
        session.replacementFor(RedactionClass::kAccountSid, "S-1-5-21-1111-2222-3333-1001");
    s.expect(!kAliceToken.empty(), L"D-07 the user name gets a placeholder");
    s.expect(kAliceToken == kAliceUpper,
             L"D-07 the same user in different letter case maps to the same placeholder");
    s.expect(!kBobToken.empty() && kBobToken != kAliceToken,
             L"D-07 two different users never collide onto the same placeholder");
    s.expect(!kHostToken.empty() && kHostToken != kAliceToken,
             L"D-07 the host identifier gets its own placeholder");
    s.expect(!kSidToken.empty(), L"D-07 the account SID gets a placeholder");

    // Multiple paths for the same user must share a single placeholder; associations cannot be flattened.
    std::size_t aliceHits = 0;
    for (const SnapshotEntity& entity : redactedEarlier.entities) {
        if (entity.kind == ObjectKind::kFile && textContains(entity.file.path, kAliceToken)) {
            ++aliceHits;
        }
    }
    s.expect(aliceHits == 2U,
             L"D-07 both of the same user's paths carry the same placeholder");
    s.expect(redactedEarlier.envelope.window.machineId == kHostToken,
             L"D-07 the machine identifier is replaced by its placeholder");

    // Sensitive original values must not remain in any field or export.
    const std::string kExportEarlier = writeSnapshotJson(redactedEarlier);
    const std::string kExportLater = writeSnapshotJson(redactedLater);
    s.expect(!textContains(kExportEarlier, "alice"),
             L"D-07 the user name does not survive anywhere in the earlier export");
    s.expect(!textContains(kExportLater, "alice"),
             L"D-07 the user name does not survive anywhere in the later export");
    s.expect(!textContains(kExportEarlier, "bob"),
             L"D-07 the second user name does not survive in the export");
    s.expect(!textContains(kExportEarlier, "WORKSTATION-7"),
             L"D-07 the host identifier does not survive in the export");
    s.expect(!textContains(kExportEarlier, "S-1-5-21-1111-2222-3333-1001"),
             L"D-07 the account SID does not survive in the export");
    s.expect(!textContains(kExportEarlier, "ntuser.dat") ||
                 !textContains(kExportEarlier, "Users\\alice"),
             L"D-07 the collector message keeps no user path");

    // Source session is not overwritten.
    s.expect(kEarlier.envelope.window.machineId == std::string("WORKSTATION-7"),
             L"D-07 the source snapshot keeps its original machine identifier");
    s.expect(textContains(writeSnapshotJson(kEarlier), "alice"),
             L"D-07 the source session is not overwritten by redaction");

    // Association remains valid: the conclusion derived from comparing the two redacted snapshots matches the original.
    const SnapshotComparison kRedactedPair = compareSnapshots(redactedEarlier, redactedLater);
    s.expect(kRedactedPair.modifiedCount == 1U,
             L"D-07 the redacted pair still shows exactly one modified object");
    s.expect(kRedactedPair.unchangedCount == 3U,
             L"D-07 the redacted pair still shows three unchanged files");
    s.expect(kRedactedPair.addedCount == 0U && kRedactedPair.removedCount == 0U,
             L"D-07 redaction introduces no phantom additions or removals");
    s.expect(kRedactedPair.deltas.size() == kPlain.deltas.size(),
             L"D-07 redaction preserves the number of compared objects");

    // Declaration: which fields were rewritten and which were deleted.
    s.expect(!session.report().replacedFieldPaths.empty(),
             L"D-07 the report lists which fields were rewritten");
    s.expect(session.report().replacementCount > 0U,
             L"D-07 the report counts the replacements it made");
    s.expect(session.report().removedFieldPaths.empty(),
             L"D-07 nothing is silently dropped when message removal is off");
    bool mappingsCoverUsers = false;
    for (const RedactionMapping& mapping : session.report().mappings) {
        if (mapping.cls == RedactionClass::kUserName && mapping.original == std::string("alice")) {
            mappingsCoverUsers = mapping.replacement == kAliceToken;
        }
    }
    s.expect(mappingsCoverUsers, L"D-07 the in-memory mapping table records the user mapping");

    RedactionOptions dropping;
    dropping.dropCollectorMessages = true;
    Snapshot dropped;
    RedactionReport dropReport;
    redactSnapshot(kEarlier, dropping, dropped, dropReport);
    s.expect(contains(dropReport.removedFieldPaths, "partitions[0].envelope.outcome.message"),
             L"D-07 removed content is declared as removed, not merely rewritten");
    s.expect(dropped.partitions.front().envelope.outcome.message.empty(),
             L"D-07 the dropped collector message really is gone");
    s.expect(!textContains(writeSnapshotJson(dropped), "ntuser.dat"),
             L"D-07 the dropped message leaves no residue in the export");
    s.expect(!kEarlier.partitions.front().envelope.outcome.message.empty(),
             L"D-07 dropping content in the copy does not touch the source");
}

// ---------------------------------------------------------------------------
// D-08: Expected change checklist (offline half).
// ---------------------------------------------------------------------------
void testExpectationChecklist(ksword_tests::Suite& s) {
    Snapshot earlier = makeSnapshot("x-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("services", ObjectKind::kService,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 2U,
                                               "ev-e"));
    {
        SnapshotEntity entity = makeServiceEntity("services", "AcmeSvc", "e-1", 0U);
        entity.fields.push_back(textField("startType", "manual"));
        earlier.entities.push_back(entity);
    }
    {
        SnapshotEntity entity = makeServiceEntity("services", "OtherSvc", "e-2", 1U);
        entity.fields.push_back(textField("startType", "auto"));
        earlier.entities.push_back(entity);
    }

    Snapshot later = makeSnapshot("x-late", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("services", ObjectKind::kService,
                                             CollectionStatus::kSuccess, kBootA, kUtcLater, 2U,
                                             "ev-l"));
    {
        SnapshotEntity entity = makeServiceEntity("services", "AcmeSvc", "l-1", 0U);
        entity.fields.push_back(textField("startType", "auto"));  // Modifications within authorized scope.
        later.entities.push_back(entity);
    }
    {
        SnapshotEntity entity = makeServiceEntity("services", "OtherSvc", "l-2", 1U);
        entity.fields.push_back(textField("startType", "disabled"));  // Undeclared change
        later.entities.push_back(entity);
    }

    LogicalObjectId acme;
    acme.domain = "service";
    acme.name = "AcmeSvc";
    LogicalObjectId ghost;
    ghost.domain = "service";
    ghost.name = "GhostSvc";

    const SnapshotComparison kComparison = compareSnapshots(earlier, later);
    s.expect(kComparison.modifiedCount == 2U,
             L"D-08 both configuration changes are observed");

    std::vector<ExpectedChange> expected;
    ExpectedChange want;
    want.partitionId = "services";
    want.identityKey = acme.crossSessionKey();
    want.change = EntityChange::kModified;
    want.fieldNames = {"startType"};
    expected.push_back(want);

    const ExpectationCheck kCheck = checkExpectedChanges(kComparison, expected);
    s.expect(kCheck.satisfied.size() == 1U, L"D-08 the declared change is satisfied");
    s.expect(kCheck.missing.empty(), L"D-08 nothing declared is missing");
    s.expect(kCheck.unexpectedKeys.size() == 1U,
             L"D-08 the undeclared change is listed without any attribution");
    s.expect(kCheck.allSatisfied, L"D-08 all declared expectations are met");

    std::vector<ExpectedChange> overreaching = expected;
    ExpectedChange absent;
    absent.partitionId = "services";
    absent.identityKey = ghost.crossSessionKey();
    absent.change = EntityChange::kRemoved;
    overreaching.push_back(absent);
    const ExpectationCheck kMissingCheck = checkExpectedChanges(kComparison, overreaching);
    s.expect(kMissingCheck.missing.size() == 1U,
             L"D-08 a declared change that never happened is reported missing");
    s.expect(!kMissingCheck.allSatisfied,
             L"D-08 a missing declared change fails the checklist");

    std::vector<ExpectedChange> wrongField = expected;
    wrongField.front().fieldNames = {"imagePath"};
    const ExpectationCheck kFieldCheck = checkExpectedChanges(kComparison, wrongField);
    s.expect(kFieldCheck.satisfied.empty() && kFieldCheck.missing.size() == 1U,
             L"D-08 declaring the wrong field does not count as satisfied");
}

// ---------------------------------------------------------------------------
// D-02 indicates normalization: case/delimiter differences must not result in false additions or deletions.
//
// Service names, registry key names, and kernel module paths are case-insensitive on Windows, yet SCM, registry enumeration,
// PsLoadedModuleList, and disk enumeration may present them differently. If they fall into different identity buckets, this
// directly creates a pair of false add/remove events, which is explicitly prohibited by the pass condition for D-02.
// ---------------------------------------------------------------------------
void testRepresentationFolding(ksword_tests::Suite& s) {
    // --- Logical identity: Case difference only ---
    LogicalObjectId upper;
    upper.domain = "service";
    upper.name = "Schedule";
    LogicalObjectId lower = upper;
    lower.name = "schedule";
    LogicalObjectId other = upper;
    other.name = "Spooler";

    s.expect(upper.crossSessionKey() == lower.crossSessionKey(),
             L"D-02 a case-only service name difference yields the same identity key");
    s.expect(upper.crossSessionKey() != other.crossSessionKey(),
             L"D-02 two genuinely different service names keep different identity keys");
    s.expect(matchLogicalObject(upper, lower) == MatchResult::kCandidate,
             L"D-02 a case-only difference is a candidate, never a confirmed same-object claim");
    s.expect(matchLogicalObject(upper, other) == MatchResult::kNoMatch,
             L"D-02 different service names still do not match");

    // Scopes differing only in case are treated as a single downgrade, not as two distinct objects.
    LogicalObjectId scopedUpper = upper;
    scopedUpper.scopeKey = "S-1-5-21-9-8-7-1001";
    LogicalObjectId scopedLower = upper;
    scopedLower.scopeKey = "s-1-5-21-9-8-7-1001";
    s.expect(matchLogicalObject(scopedUpper, scopedLower) == MatchResult::kCandidate,
             L"D-02 a case-only scope key difference is a candidate, not a different object");

    Snapshot earlier = makeSnapshot("f-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("services", ObjectKind::kService,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 1U,
                                               "ev-e"));
    earlier.entities.push_back(makeServiceEntity("services", "Schedule", "e-1", 0U));

    Snapshot later = makeSnapshot("f-late", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("services", ObjectKind::kService,
                                             CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                             "ev-l"));
    later.entities.push_back(makeServiceEntity("services", "schedule", "l-1", 0U));

    const SnapshotComparison kFolded = compareSnapshots(earlier, later);
    s.expect(kFolded.deltas.size() == 1U,
             L"D-02 a case-only service rename stays one object, not an add/remove pair");
    s.expect(kFolded.addedCount == 0U && kFolded.removedCount == 0U,
             L"D-02 a case-only service rename produces no phantom add or remove");
    s.expect(kFolded.notComparableCount == 0U,
             L"D-02 a case-only service rename is still comparable");
    s.expect(!kFolded.deltas.empty() &&
                 kFolded.deltas.front().matchConfidence == MatchConfidence::kUncertain,
             L"D-02 a case-only match is marked uncertain rather than confirmed");
    s.expect(kFolded.selfCheckPassed, L"D-02 the folded comparison passes its self check");

    // --- Driver image path: different casing and separator styles, but identical image identity ---
    Snapshot drvEarlier = makeSnapshot("dp-early", kBootA, kUtcEarlier);
    drvEarlier.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                                  CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                  1U, "ev-e"));
    drvEarlier.entities.push_back(makeDriverEntity(
        "drivers", "\\SystemRoot\\System32\\DRIVERS\\acme.sys", "", 0x5A1B2C3DULL, 0x8000ULL,
        "e-d", 0U));

    Snapshot drvLater = makeSnapshot("dp-late", kBootA, kUtcLater);
    drvLater.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                                CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                                "ev-l"));
    drvLater.entities.push_back(makeDriverEntity(
        "drivers", "\\systemroot/system32/drivers/acme.sys", "", 0x5A1B2C3DULL, 0x8000ULL, "l-d",
        0U));

    const DriverInstanceId& earlierDriver = drvEarlier.entities.front().driver;
    const DriverInstanceId& laterDriver = drvLater.entities.front().driver;
    s.expect(earlierDriver.crossSessionKey() != laterDriver.crossSessionKey(),
             L"D-02 the raw ObjectIdentity key still differs (the fold lives in the snapshot layer)");
    s.expect(snapshotDriverKey(earlierDriver) == snapshotDriverKey(laterDriver),
             L"D-02 the snapshot-layer driver key folds path case and separators");
    s.expect(snapshotDriverKey(DriverInstanceId{}).empty(),
             L"D-02 an unusable driver identity still yields no snapshot key");

    const SnapshotComparison kDriverFolded = compareSnapshots(drvEarlier, drvLater);
    s.expect(kDriverFolded.deltas.size() == 1U,
             L"D-02 the same driver written with a different path case stays one object");
    s.expect(kDriverFolded.addedCount == 0U && kDriverFolded.removedCount == 0U,
             L"D-02 a path-case difference produces no phantom driver add or remove");
    s.expect(!kDriverFolded.deltas.empty() &&
                 kDriverFolded.deltas.front().matchConfidence == MatchConfidence::kUncertain,
             L"D-02 a path-representation-only driver match is uncertain, not confirmed");

    // Truly different images (with different timeDateStamp values) must still be separated.
    Snapshot drvOther = makeSnapshot("dp-other", kBootA, kUtcLater);
    drvOther.partitions.push_back(makePartition("drivers", ObjectKind::kDriver,
                                                CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                                "ev-o"));
    drvOther.entities.push_back(makeDriverEntity(
        "drivers", "\\SystemRoot\\System32\\DRIVERS\\acme.sys", "", 0x600DBEEFULL, 0x8000ULL,
        "o-d", 0U));
    const SnapshotComparison kDrvChanged = compareSnapshots(drvEarlier, drvOther);
    s.expect(kDrvChanged.deltas.size() == 2U,
             L"D-02 a different image version behind the same path stays two objects");
}

// ---------------------------------------------------------------------------
// D-04: Duplicate identity keys must not overwrite the real collection status on the opposite side.
// ---------------------------------------------------------------------------
void testDuplicateKeyKeepsSideState(ksword_tests::Suite& s) {
    Snapshot earlier = makeSnapshot("dk-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("svc", ObjectKind::kService, CollectionStatus::kSuccess,
                                               kBootA, kUtcEarlier, 2U, "ev-e"));
    earlier.entities.push_back(makeServiceEntity("svc", "Dup", "e-dup-1", 0U));
    earlier.entities.push_back(makeServiceEntity("svc", "Dup", "e-dup-2", 1U));

    Snapshot denied = makeSnapshot("dk-late", kBootA, kUtcLater);
    SnapshotPartition failing = makePartition("svc", ObjectKind::kService,
                                              CollectionStatus::kAccessDenied, kBootA, kUtcLater, 0U,
                                              "ev-l");
    failing.envelope.coverage = CoverageAccount{};
    failing.envelope.outcome = CollectionOutcome::failure(CollectionStatus::kAccessDenied, "NTSTATUS",
                                                          0xC0000022ULL, "STATUS_ACCESS_DENIED");
    denied.partitions.push_back(failing);

    const SnapshotComparison kResult = compareSnapshots(earlier, denied);
    s.expect(kResult.deltas.size() == 2U,
             L"D-04 both records behind the duplicated key are still reported");
    s.expect(kResult.notComparableCount == 2U && kResult.removedCount == 0U,
             L"D-04 a duplicated key over a failed side yields no removals");
    bool allSourceFailed = !kResult.deltas.empty();
    bool allDeclareBoth = !kResult.deltas.empty();
    for (const EntityDelta& delta : kResult.deltas) {
        allSourceFailed = allSourceFailed &&
                          delta.laterState == EntitySideState::kUnknownSourceFailed;
        allDeclareBoth = allDeclareBoth &&
                         contains(delta.limitationKeys, "snapshot.limitation.sourceFailed") &&
                         contains(delta.limitationKeys, "snapshot.limitation.duplicateIdentityKey");
    }
    s.expect(allSourceFailed,
             L"D-04 an access-denied side stays source-failed even on duplicated-key rows");
    s.expect(allDeclareBoth,
             L"D-04 the duplicated-key limitation is added to the real side state, not instead of it");
    const PartitionAccount* account = findAccount(kResult, "svc");
    s.expect(account != nullptr && account->laterStatus == CollectionStatus::kAccessDenied,
             L"D-04 the row state and the partition account agree about the failed side");

    // If the other bucket contains a record with the same key, it is neither absent nor confirmed present.
    Snapshot later = makeSnapshot("dk-ok", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("svc", ObjectKind::kService, CollectionStatus::kSuccess,
                                             kBootA, kUtcLater, 1U, "ev-l"));
    later.entities.push_back(makeServiceEntity("svc", "Dup", "l-dup-1", 0U));

    const SnapshotComparison kAmbiguous = compareSnapshots(earlier, later);
    s.expect(kAmbiguous.deltas.size() == 3U,
             L"D-04 every record behind an ambiguous pairing is still reported");
    bool ambiguousMarked = true;
    for (const EntityDelta& delta : kAmbiguous.deltas) {
        const EntitySideState kOther = delta.earlierState == EntitySideState::kPresent
                                          ? delta.laterState
                                          : delta.earlierState;
        ambiguousMarked = ambiguousMarked &&
                          kOther == EntitySideState::kUnknownAmbiguousIdentity;
    }
    s.expect(ambiguousMarked,
             L"D-04 an unpairable but populated side is UnknownAmbiguousIdentity, not AbsentCovered");
    s.expect(kAmbiguous.removedCount == 0U && kAmbiguous.addedCount == 0U,
             L"D-04 an ambiguous pairing never becomes an add or a remove");
}

// ---------------------------------------------------------------------------
// D-04: Same-name partitions on both sides declare different entity types: not the same collection view, cannot compare.
// ---------------------------------------------------------------------------
void testPartitionKindMismatch(ksword_tests::Suite& s) {
    Snapshot earlier = makeSnapshot("km-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("p", ObjectKind::kService, CollectionStatus::kSuccess,
                                               kBootA, kUtcEarlier, 1U, "ev-e"));
    earlier.entities.push_back(makeServiceEntity("p", "AcmeSvc", "e-1", 0U));

    Snapshot later = makeSnapshot("km-late", kBootA, kUtcLater);
    // The same partition ID in the new snapshot contains a process — two collectors have stored different things.
    later.partitions.push_back(makePartition("p", ObjectKind::kProcess, CollectionStatus::kSuccess,
                                             kBootA, kUtcLater, 1U, "ev-l"));
    later.entities.push_back(makeProcess("p", kBootA, 100U, 111ULL, "alpha.exe", "l-1", 0U));

    const SnapshotComparison kResult = compareSnapshots(earlier, later);
    const PartitionAccount* account = findAccount(kResult, "p");
    s.expect(account != nullptr && !account->comparable,
             L"D-04 a partition whose declared entity kind differs is not comparable");
    s.expect(account != nullptr &&
                 contains(account->limitationKeys, "snapshot.partition.kindMismatch"),
             L"D-04 the kind mismatch is stated on the partition account");
    s.expect(account != nullptr && account->conclusion == AnalysisConclusion::kNoEvidence,
             L"D-04 a kind-mismatched partition concludes NoEvidence");
    s.expect(kResult.removedCount == 0U && kResult.addedCount == 0U,
             L"D-04 a kind mismatch never turns the two different views into an add/remove pair");
    s.expect(kResult.notComparableCount == 2U,
             L"D-04 both records of a kind-mismatched partition are reported as not comparable");
    const EntityDelta* svc = findDeltaByRaw(kResult, "e-1");
    s.expect(svc != nullptr &&
                 contains(svc->limitationKeys, "snapshot.partition.kindMismatch"),
             L"D-04 the row states the kind mismatch, not just a scope excuse");
    s.expect(kResult.conclusion == AnalysisConclusion::kNoEvidence,
             L"D-04 a comparison whose only partition is kind-mismatched has no usable evidence");
    s.expect(kResult.selfCheckPassed && checkComparisonSelfConsistency(kResult),
             L"D-04 the kind-mismatch result is internally consistent");
}

// ---------------------------------------------------------------------------
// The D-01 self-check must return false when presented with a counterexample.
// ---------------------------------------------------------------------------
void testSelfCheckIsFalsifiable(ksword_tests::Suite& s) {
    Snapshot earlier = makeSnapshot("sc-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("services", ObjectKind::kService,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 2U,
                                               "ev-e"));
    earlier.entities.push_back(makeServiceEntity("services", "AcmeSvc", "e-1", 0U));
    earlier.entities.push_back(makeServiceEntity("services", "GoneSvc", "e-2", 1U));

    Snapshot later = makeSnapshot("sc-late", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("services", ObjectKind::kService,
                                             CollectionStatus::kSuccess, kBootA, kUtcLater, 1U,
                                             "ev-l"));
    later.entities.push_back(makeServiceEntity("services", "AcmeSvc", "l-1", 0U));

    const SnapshotComparison kGood = compareSnapshots(earlier, later);
    s.expect(kGood.removedCount == 1U && kGood.unchangedCount == 1U,
             L"D-01 the reference comparison really contains one removal and one unchanged row");
    s.expect(kGood.selfCheckPassed && checkComparisonSelfConsistency(kGood),
             L"D-01 a genuine comparison passes the independent consistency check");

    // 1) Count modified — recalculation per item must detect it.
    SnapshotComparison bumped = kGood;
    bumped.addedCount += 1U;
    s.expect(!checkComparisonSelfConsistency(bumped),
             L"D-01 a counter that disagrees with the rows fails the self check");

    // 2) Removes the account relied upon for the conclusion — self-check the account, do not read the local variable that generated it.
    SnapshotComparison unsupported = kGood;
    for (PartitionAccount& account : unsupported.partitions) {
        account.laterUsableForAbsence = false;
    }
    s.expect(!checkComparisonSelfConsistency(unsupported),
             L"D-01 a removal whose later partition cannot prove completeness fails the self check");

    // 3) The row conclusion contradicts the states on both sides.
    SnapshotComparison forged = kGood;
    for (EntityDelta& delta : forged.deltas) {
        if (delta.change == EntityChange::kUnchanged) {
            delta.change = EntityChange::kRemoved;
            break;
        }
    }
    s.expect(!checkComparisonSelfConsistency(forged),
             L"D-01 a Removed row whose both sides are Present fails the self check");

    // 4) Conclusion is incompatible with the count.
    SnapshotComparison mislabeled = kGood;
    mislabeled.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    s.expect(!checkComparisonSelfConsistency(mislabeled),
             L"D-01 claiming NoDifferenceObserved with an observed removal fails the self check");

    // 5) Partition conclusion was rewritten.
    SnapshotComparison badAccount = kGood;
    for (PartitionAccount& account : badAccount.partitions) {
        account.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    }
    s.expect(!checkComparisonSelfConsistency(badAccount),
             L"D-01 a partition that observed a removal cannot conclude NoDifferenceObserved");
}

// ---------------------------------------------------------------------------
// D-08: Declarations must specify objects; an empty list does not pass.
// ---------------------------------------------------------------------------
void testExpectationBinding(ksword_tests::Suite& s) {
    // Two weak identities (without creation time): identityKey is empty, containing only candidateKey.
    Snapshot earlier = makeSnapshot("eb-early", kBootA, kUtcEarlier);
    earlier.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                               CollectionStatus::kSuccess, kBootA, kUtcEarlier, 2U,
                                               "ev-e"));
    {
        SnapshotEntity one = makeProcess("processes", kBootA, 4242U, 0ULL, "weakone.exe", "e-1", 0U);
        one.fields.push_back(textField("start", "manual"));
        earlier.entities.push_back(one);
        SnapshotEntity two = makeProcess("processes", kBootA, 4243U, 0ULL, "weaktwo.exe", "e-2", 1U);
        two.fields.push_back(textField("start", "auto"));
        earlier.entities.push_back(two);
    }
    Snapshot later = makeSnapshot("eb-late", kBootA, kUtcLater);
    later.partitions.push_back(makePartition("processes", ObjectKind::kProcess,
                                             CollectionStatus::kSuccess, kBootA, kUtcLater, 2U,
                                             "ev-l"));
    {
        SnapshotEntity one = makeProcess("processes", kBootA, 4242U, 0ULL, "weakone.exe", "l-1", 0U);
        one.fields.push_back(textField("start", "auto"));  // Only real changes
        later.entities.push_back(one);
        SnapshotEntity two = makeProcess("processes", kBootA, 4243U, 0ULL, "weaktwo.exe", "l-2", 1U);
        two.fields.push_back(textField("start", "auto"));
        later.entities.push_back(two);
    }

    const SnapshotComparison kComparison = compareSnapshots(earlier, later);
    s.expect(kComparison.modifiedCount == 1U && kComparison.unchangedCount == 1U,
             L"D-08 exactly one of the two weak-identity objects changed");

    // The composition of candidateKey is hardcoded constants, not calculated from the code under test:
    //   "cand" + US + kind name + US + PID (decimal) + US + folded image name
    const std::string kUs(1, '\x1F');
    const std::string kWeakOneKey = "cand" + kUs + "Process" + kUs + "4242" + kUs + "weakone.exe";
    const std::string kWeakTwoKey = "cand" + kUs + "Process" + kUs + "4243" + kUs + "weaktwo.exe";
    const EntityDelta* changed = findDeltaByRaw(kComparison, "e-1");
    s.expect(changed != nullptr && changed->identityKey.empty() &&
                 changed->candidateKey == kWeakOneKey,
             L"D-08 a weak-identity row carries only the hand-computed candidate key");

    // A declaration with an empty identity key points to no object — it must never be incorrectly counted as passing by arbitrarily matching the first entry.
    ExpectedChange nameless;
    nameless.partitionId = "processes";
    nameless.change = EntityChange::kModified;
    nameless.fieldNames = {"start"};
    const ExpectationCheck kNamelessCheck = checkExpectedChanges(kComparison, {nameless});
    s.expect(kNamelessCheck.invalid.size() == 1U && kNamelessCheck.satisfied.empty(),
             L"D-08 a declaration naming no object is invalid, never satisfied");
    s.expect(!kNamelessCheck.allSatisfied &&
                 kNamelessCheck.outcome == ExpectationOutcome::kViolated,
             L"D-08 an unbindable declaration fails the checklist");

    // Declare using candidateKey: must bind to the actual one that changed.
    ExpectedChange rightOne;
    rightOne.partitionId = "processes";
    rightOne.candidateKey = kWeakOneKey;
    rightOne.change = EntityChange::kModified;
    rightOne.fieldNames = {"start"};
    const ExpectationCheck kBound = checkExpectedChanges(kComparison, {rightOne});
    s.expect(kBound.satisfied.size() == 1U && kBound.satisfied.front() == kWeakOneKey,
             L"D-08 a weak-identity change can be declared by candidate key and binds to it");
    s.expect(kBound.allSatisfied && kBound.outcome == ExpectationOutcome::kSatisfied,
             L"D-08 the correctly bound declaration satisfies the checklist");
    s.expect(kBound.unexpectedKeys.empty(),
             L"D-08 the declared weak-identity change is no longer listed as undeclared");

    // Declare as a different weak identity object: it must report missing, not be overridden by the first entry.
    ExpectedChange wrongOne = rightOne;
    wrongOne.candidateKey = kWeakTwoKey;
    const ExpectationCheck kWrong = checkExpectedChanges(kComparison, {wrongOne});
    s.expect(kWrong.missing.size() == 1U && kWrong.satisfied.empty(),
             L"D-08 declaring the object that did not change is reported missing");

    // Empty list: nothing to verify, not a pass.
    const ExpectationCheck kNone = checkExpectedChanges(kComparison, {});
    s.expect(kNone.outcome == ExpectationOutcome::kNotAssessed && !kNone.allSatisfied,
             L"D-08 an empty expectation list is NotAssessed, not a green checklist");
    s.expect(kNone.unexpectedKeys.size() == 1U,
             L"D-08 an empty expectation list still lists the observed change");

    // Comparison with no evidence: nothing to verify.
    const SnapshotComparison kNothing = compareSnapshots(Snapshot{}, Snapshot{});
    s.expect(kNothing.conclusion == AnalysisConclusion::kNoEvidence,
             L"D-08 comparing two empty snapshots yields NoEvidence");
    const ExpectationCheck kOnNothing = checkExpectedChanges(kNothing, {rightOne});
    s.expect(kOnNothing.outcome == ExpectationOutcome::kNotAssessed && !kOnNothing.allSatisfied,
             L"D-08 a declaration checked against a no-evidence comparison is NotAssessed");

    // Declare a partition that could not be compared: unverifiable, neither passing nor 'unchanged'.
    Snapshot brokenLater = later;
    for (SnapshotPartition& partition : brokenLater.partitions) {
        partition.envelope.outcome = CollectionOutcome::failure(CollectionStatus::kAccessDenied,
                                                                "WIN32", 5ULL, "access denied");
        partition.envelope.coverage = CoverageAccount{};
    }
    brokenLater.entities.clear();
    brokenLater.partitions.push_back(makePartition("services", ObjectKind::kService,
                                                   CollectionStatus::kSuccess, kBootA, kUtcLater, 0U,
                                                   "ev-svc"));
    Snapshot brokenEarlier = earlier;
    brokenEarlier.partitions.push_back(makePartition("services", ObjectKind::kService,
                                                     CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                     0U, "ev-svc-e"));
    const SnapshotComparison kBroken = compareSnapshots(brokenEarlier, brokenLater);
    const ExpectationCheck kOnBroken = checkExpectedChanges(kBroken, {rightOne});
    s.expect(kOnBroken.invalid.size() == 1U && kOnBroken.missing.empty(),
             L"D-08 a declaration aimed at a non-comparable partition is invalid, not missing");
    s.expect(!kOnBroken.allSatisfied,
             L"D-08 an unassessable declaration never counts as satisfied");
}

// ---------------------------------------------------------------------------
// D-06 + 7.2: Round-trip under load; overflow and corruption must be distinct states.
//
// The number of JSON nodes written per entity is countable by hand:
//   Entity object 1; partitionId/kind/rawRecordId/displayOrder 4; process 1+5.
//   thread 1+(1+5)+3; driver 1+8; file 1+6; logical 1+3; fields array 1
//   => skeleton has 42 nodes, plus each field (1 object + 7 members) = 8.
// 4 fields -> 74 nodes/entries; 10,000 entries = 740,000 nodes, exceeding the generic
// default maxTotalNodes = 524,288, but still below the node count allowed by
// maxEstimatedNodeBytes (64 MiB) / sizeof(JsonValue), so the error must be NodeLimit.
// ---------------------------------------------------------------------------
constexpr std::size_t kBulkEntityCount = 10000;

Snapshot buildBulkSnapshot() {
    Snapshot snapshot = makeSnapshot("bulk-1", kBootA, kUtcEarlier);
    snapshot.partitions.push_back(makePartition("bulk", ObjectKind::kUnknown,
                                                CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                kBulkEntityCount, "ev-bulk"));
    const ObjectKind kKinds[5] = {ObjectKind::kProcess, ObjectKind::kDriver, ObjectKind::kFile,
                                 ObjectKind::kService, ObjectKind::kModule};
    snapshot.entities.reserve(kBulkEntityCount);
    for (std::size_t i = 0; i < kBulkEntityCount; ++i) {
        const std::string kIndex = formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal);
        SnapshotEntity entity;
        entity.partitionId = "bulk";
        entity.kind = kKinds[i % 5U];
        entity.rawRecordId = "row-" + kIndex;
        entity.displayOrder = i;
        entity.process.bootId = kBootA;
        entity.process.pid = OptionalU64::of(1000ULL + i);
        entity.process.imageName = "image-" + kIndex + ".exe";
        entity.driver.imagePath =
            "\\SystemRoot\\System32\\drivers\\vendor\\deeply\\nested\\module-" + kIndex + ".sys";
        entity.driver.timeDateStamp = OptionalU64::of(0x5A1B0000ULL + i);
        entity.driver.imageSize = OptionalU64::of(0x8000ULL);
        entity.file.path =
            "C:\\Program Files\\Acme Corporation\\Components\\payload-" + kIndex + ".dat";
        entity.file.contentHash = "sha256:" + kIndex;
        entity.logical.domain = "service";
        entity.logical.name = "svc-" + kIndex;
        entity.fields.push_back(numberField("target", 0xFFFFF80000100000ULL + i * 16ULL,
                                            FieldSemantics::kKernelAddress));
        entity.fields.push_back(numberField("imageBase", 0xFFFFF80000000000ULL + i * 4096ULL,
                                            FieldSemantics::kLoadBaseAddress));
        entity.fields.push_back(textField("startType", (i % 2U) == 0U ? "auto" : "manual"));
        entity.fields.push_back(
            textField("displayName", ("Acme Component " + kIndex).c_str()));
        snapshot.entities.push_back(std::move(entity));
    }
    return snapshot;
}

void testPersistenceAtLoad(ksword_tests::Suite& s) {
    // Overflow and corruption must be distinct states; overflow retains the parser's own error code.
    JsonLimits tiny;
    tiny.maxTotalNodes = 4U;
    const SnapshotLoadResult kTooManyNodes = readSnapshotJson(
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"snapshotId\":\"t\","
        "\"entities\":[{\"partitionId\":\"p\",\"kind\":\"Service\"}]}",
        tiny);
    s.expect(kTooManyNodes.status == SnapshotLoadStatus::kLimitExceeded,
             L"D-06 a well-formed document over the node limit is LimitExceeded, not MalformedJson");
    s.expect(kTooManyNodes.errorDetail == std::string("NodeLimit"),
             L"D-06 the limit failure keeps the parser's own reason code");
    s.expect(!kTooManyNodes.ok(), L"D-06 a limit failure is not a loadable result");
    s.expect(kTooManyNodes.snapshot.entities.empty(),
             L"D-06 a limit failure leaves no half-parsed snapshot behind");

    JsonLimits shortBytes;
    shortBytes.maxTotalBytes = 8U;
    const SnapshotLoadResult kTooManyBytes =
        readSnapshotJson("{\"schema\":\"ksword.snapshot\",\"versionMajor\":1}", shortBytes);
    s.expect(kTooManyBytes.status == SnapshotLoadStatus::kLimitExceeded,
             L"D-06 an over-length document is LimitExceeded too");

    // 7.2 L1 round-trip: generic default snapshot read fails, but persisted snapshot read succeeds.
    const Snapshot kBulk = buildBulkSnapshot();
    const std::string kText = writeSnapshotJson(kBulk);
    s.expect(kText.size() > 1024U * 1024U,
             L"D-06 the load-scale document really is large enough to matter");

    const SnapshotLoadResult kWithGenericLimits = readSnapshotJson(kText, JsonLimits{});
    s.expect(kWithGenericLimits.status == SnapshotLoadStatus::kLimitExceeded,
             L"D-06 the generic untrusted-input limits reject the module's own load-scale document");
    s.expect(kWithGenericLimits.errorDetail == std::string("NodeLimit"),
             L"D-06 the generic-limit rejection is the node budget, as counted by hand");

    const JsonLimits kProfile = snapshotJsonLimits();
    s.expect(kProfile.maxTotalNodes >= 740000U * 10U,
             L"D-06 the snapshot profile budgets the documented 100,000-record load");

    const SnapshotLoadResult kLoaded = readSnapshotJson(kText);
    s.expect(kLoaded.status == SnapshotLoadStatus::kOk,
             L"D-06 the default snapshot limits load the module's own load-scale document");
    s.expect(kLoaded.snapshot.entities.size() == kBulkEntityCount,
             L"D-06 every record survives the load-scale round trip");
    // Manual expected value: Address of the 9,999th entry (i = 9999) = 0xFFFFF80000100000 + 9999 * 16.
    const std::uint64_t kExpectedTarget = 0xFFFFF80000100000ULL + 9999ULL * 16ULL;
    s.expect(kLoaded.snapshot.entities.size() == kBulkEntityCount &&
                 kLoaded.snapshot.entities.back().fields.front().number.present &&
                 kLoaded.snapshot.entities.back().fields.front().number.value == kExpectedTarget,
             L"D-06 the last record's 64-bit address survives the load-scale round trip");
    s.expect(kLoaded.snapshot.entities.size() == kBulkEntityCount &&
                 kLoaded.snapshot.entities.back().rawRecordId == std::string("row-9999"),
             L"D-06 the last record keeps its raw record id at load scale");
}

// ---------------------------------------------------------------------------
// D-07: Unknown optional fields must also be redacted; scanning cost is independent of placeholder count; do not deliver incomplete work.
// ---------------------------------------------------------------------------
void testRedactionCoversUnknownFields(ksword_tests::Suite& s) {
    // Hand-written fixture: sensitive original values appear only in the unknown fields of D-06 commitment 'write-back as-is'.
    const char* raw =
        "{\"schema\":\"ksword.snapshot\",\"versionMajor\":1,\"versionMinor\":9,"
        "\"snapshotId\":\"leak-1\","
        "\"vendorNote\":\"collected by alice on WORKSTATION-7\","
        "\"vendorAudit\":{\"operator\":\"alice\",\"rows\":[\"seen by alice\",7]},"
        "\"envelope\":{\"window\":{\"machineId\":\"WORKSTATION-7\"}},"
        "\"partitions\":[{\"partitionId\":\"files\",\"kind\":\"File\",\"coversScope\":true,"
        "\"envelope\":{\"outcome\":{\"status\":\"Success\"},"
        "\"coverage\":{\"totalKnown\":\"1\",\"succeeded\":\"1\"}}}],"
        "\"entities\":[{\"partitionId\":\"files\",\"kind\":\"File\","
        "\"file\":{\"path\":\"C:\\\\Users\\\\alice\\\\a.txt\",\"contentHash\":\"sha256:1111\"},"
        "\"originalPath\":\"C:\\\\Users\\\\alice\\\\secret\\\\a.txt\","
        "\"note-alice\":\"key names can carry it too\"}]}";
    const SnapshotLoadResult kLoaded = readSnapshotJson(raw);
    s.expect(kLoaded.status == SnapshotLoadStatus::kOkWithUnknownFields,
             L"D-07 the fixture really goes through the unknown-field preservation path");
    s.expect(contains(kLoaded.unknownFieldPaths, "root.vendorNote") &&
                 contains(kLoaded.unknownFieldPaths, "root.entities[].originalPath"),
             L"D-07 the unknown fields carrying the sensitive values are the preserved ones");

    Snapshot redacted;
    RedactionReport report;
    redactSnapshot(kLoaded.snapshot, RedactionOptions{}, redacted, report);
    const std::string kExported = writeSnapshotJson(redacted);

    s.expect(!textContains(kExported, "alice"),
             L"D-07 the user name does not survive inside an unknown vendor field");
    s.expect(!textContains(kExported, "WORKSTATION-7"),
             L"D-07 the host identifier does not survive inside an unknown vendor field");
    s.expect(textContains(kExported, "vendorNote"),
             L"D-07 a scrubbed unknown field is kept, not silently dropped");
    s.expect(textContains(kExported, "collected by") && textContains(kExported, " on "),
             L"D-07 only the sensitive substring of the unknown field is replaced");
    s.expect(contains(report.replacedFieldPaths, "unknownFields.vendorNote"),
             L"D-07 the rewritten unknown top-level field is declared by path");
    s.expect(contains(report.replacedFieldPaths, "entities[0].unknownFields.originalPath"),
             L"D-07 the rewritten unknown entity field is declared by path");
    s.expect(contains(report.replacedFieldPaths, "unknownFields.vendorAudit.operator"),
             L"D-07 a nested unknown field is reached and declared by its full path");
    s.expect(contains(report.replacedFieldPaths, "unknownFields.vendorAudit.rows[0]"),
             L"D-07 an unknown array element is reached and declared by index");
    // When a key name contains a sensitive original value, it cannot be renamed (to avoid key collisions); the
    // entire entry must be deleted and declared instead—and the declaration must not copy back the original value.
    bool removedKeyDeclared = false;
    bool removalLeaksOriginal = false;
    for (const std::string& path : report.removedFieldPaths) {
        if (textContains(path, "note-")) {
            removedKeyDeclared = true;
        }
        if (textContains(path, "alice")) {
            removalLeaksOriginal = true;
        }
    }
    s.expect(removedKeyDeclared,
             L"D-07 an unknown field whose key carries the value is removed and declared");
    s.expect(!removalLeaksOriginal,
             L"D-07 the removal declaration does not copy the original value back out");
    s.expect(!textContains(kExported, "note-alice"),
             L"D-07 the removed key name is gone from the export");
    s.expect(kLoaded.snapshot.entities.size() == 1U &&
                 !kLoaded.snapshot.entities.front().unknownFields.empty(),
             L"D-07 the source snapshot keeps its unknown fields untouched");
}

void testRedactionCostAndCancellation(ksword_tests::Suite& s) {
    // The target snapshot contains no 'z'; all usernames in the decoy snapshot start with 'z', so they **never** match.
    // When using a leading-character index, the scan cost is independent of the number of these placeholder names.
    auto makeDecoy = [](std::size_t userCount) {
        Snapshot decoy = makeSnapshot("decoy", kBootA, kUtcEarlier);
        decoy.partitions.push_back(makePartition("files", ObjectKind::kFile,
                                                 CollectionStatus::kSuccess, kBootA, kUtcEarlier,
                                                 userCount, "ev-decoy"));
        for (std::size_t i = 0; i < userCount; ++i) {
            SnapshotEntity entity;
            entity.partitionId = "files";
            entity.kind = ObjectKind::kFile;
            entity.file.path = "C:\\Users\\zeta" +
                               formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) +
                               "\\f.txt";
            entity.file.contentHash = "sha256:decoy";
            decoy.entities.push_back(entity);
        }
        return decoy;
    };

    Snapshot target = makeSnapshot("target", kBootA, kUtcEarlier);
    target.partitions.push_back(makePartition("files", ObjectKind::kFile, CollectionStatus::kSuccess,
                                              kBootA, kUtcEarlier, 200U, "ev-target"));
    for (std::size_t i = 0; i < 200U; ++i) {
        SnapshotEntity entity;
        entity.partitionId = "files";
        entity.kind = ObjectKind::kFile;
        entity.file.path = "C:\\ProgramData\\Acme\\Components\\payload-" +
                           formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) + ".dat";
        entity.file.contentHash = "sha256:target";
        entity.fields.push_back(textField("startType", "auto"));
        target.entities.push_back(entity);
    }
    // The scanned content is field values, not JSON keys, so only the value side is checked for the absence of 'z'/'Z'.
    s.expect(!textContains(target.entities.front().file.path, "z") &&
                 !textContains(target.entities.front().file.path, "Z") &&
                 !textContains(target.envelope.window.machineId, "z") &&
                 !textContains(target.snapshotId, "z"),
             L"D-07 the cost probe's scanned values contain none of the decoy first letters");

    RedactionSession few;
    few.learn(makeDecoy(8U));
    Snapshot outFew;
    few.redact(target, outFew);

    RedactionSession many;
    many.learn(makeDecoy(512U));
    Snapshot outMany;
    many.redact(target, outMany);

    s.expect(few.report().mappings.size() + 504U == many.report().mappings.size(),
             L"D-07 the two sessions really differ by 504 additional placeholders");
    s.expect(few.report().needleComparisons > 0U,
             L"D-07 the scrub really scanned the target text");
    s.expect(few.report().needleComparisons == many.report().needleComparisons,
             L"D-07 scan cost does not grow with placeholders that cannot match");
    s.expect(!textContains(writeSnapshotJson(outMany), "zeta") &&
                 few.report().replacementCount == many.report().replacementCount,
             L"D-07 the decoy placeholders never matched, so both runs replaced the same content");

    // Cancel: Do not deliver partially redacted snapshots.
    RedactionSession cancelling;
    cancelling.setCancelHook([]() { return true; });
    Snapshot cancelled;
    cancelling.redact(target, cancelled);
    s.expect(cancelling.report().cancelled,
             L"D-07 a cancelled redaction says so in its report");
    s.expect(cancelled.entities.empty() && cancelled.snapshotId.empty(),
             L"D-07 a cancelled redaction delivers nothing rather than a half-scrubbed snapshot");
    s.expect(target.entities.size() == 200U,
             L"D-07 cancelling does not touch the source snapshot");

    RedactionSession running;
    Snapshot finished;
    running.redact(target, finished);
    s.expect(!running.report().cancelled && finished.entities.size() == 200U,
             L"D-07 a redaction without a cancel hook still completes normally");
}

} // namespace

int runSnapshotCompareTests() {
    ksword_tests::Suite suite(L"D snapshot compare");
    testScopeAndProvenance(suite);
    testSemanticKeys(suite);
    testRepresentationFolding(suite);
    testAddressNormalization(suite);
    testUnknownIsNotRemoval(suite);
    testDuplicateKeyKeepsSideState(suite);
    testPartitionKindMismatch(suite);
    testSelfCheckIsFalsifiable(suite);
    testChangeExplanation(suite);
    testPersistence(suite);
    testPersistenceAtLoad(suite);
    testRedaction(suite);
    testRedactionCoversUnknownFields(suite);
    testRedactionCostAndCancellation(suite);
    testExpectationChecklist(suite);
    testExpectationBinding(suite);
    suite.report();
    return suite.failures();
}

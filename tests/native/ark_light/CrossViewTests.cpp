// Offline automated tests for the X module (Cross-view difference explanation and verification).
//
// Coverage IDs: X-01 X-02 X-03 X-04 X-05 X-06 X-07 X-08.
// The 'positive detection' for X-08 is constructed by the test itself by deleting records from snapshot copies. The rewriter exists
// only in test code; the production collection path (analyzeCrossView) contains no branches that read the test ground truth.
//
// Assertion principle (Q-02):
//   * Expected values are hardcoded independently, not calculated from the code under test;
//   * Assert exact values for presence / viewStatus / sourceGroup / rawRecordId
//     per view; do not collapse the two types of 'unknown' into a single counter;
//   * Each view's rawRecordId carries its own prefix and is never copied from others — otherwise, ownership errors go undetected.
//   * The view sets for each round are intentionally different (fewer/more in subsequent rounds, or same viewId with a different source
//     group); otherwise, defects like "only checking round 1" and "missing entire rounds being treated as clean" would all escape detection.

#include "TestSupport.h"

#include "../../../shared/evidence/CrossViewDiff.h"

#include <algorithm>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

constexpr const char* kBoot = "boot-X";
constexpr std::uint64_t kUtcBase = 133000000000000000ULL;

EvidenceEnvelope makeEnvelope(const char* collectorId,
                              const char* sourceGroup,
                              CollectionStatus status) {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = collectorId;
    envelope.source.sourceGroup = sourceGroup;
    envelope.source.origin = SourceOrigin::kLiveKernel;
    envelope.source.collectorVersion = 1U;
    envelope.outcome.status = status;
    envelope.window.bootId = kBoot;
    envelope.window.machineId = "machine-1";
    return envelope;
}

// X-06: Full coverage requires positive evidence. Here, "I enumerated n items, all n succeeded" is written to the ledger. An
// empty ledger is not full coverage; thus, a view that omits this step lacks the qualification for "confirmation of absence."
void setAccounting(ViewSnapshot& view) {
    view.envelope.coverage.totalKnown = OptionalU64::of(view.records.size());
    view.envelope.coverage.succeeded = view.records.size();
}

// A dedicated envelope constructor for viewUsableForAbsence.
EvidenceEnvelope makeAccountedEnvelope(CollectionStatus status, std::uint64_t count) {
    EvidenceEnvelope envelope = makeEnvelope("v", "v", status);
    envelope.coverage.totalKnown = OptionalU64::of(count);
    envelope.coverage.succeeded = count;
    return envelope;
}

ViewRecord makeProcessRecord(std::uint64_t pid, std::uint64_t createTime, const char* name,
                             const char* rawId) {
    ViewRecord record;
    record.kind = ObjectKind::kProcess;
    record.process.bootId = kBoot;
    record.process.pid = OptionalU64::of(pid);
    record.process.createTime100ns = OptionalU64::of(createTime);
    record.process.imageName = name;
    record.rawRecordId = rawId;
    return record;
}

ViewRecord makeThreadRecord(std::uint64_t pid, std::uint64_t processCreate, std::uint64_t tid,
                            std::uint64_t threadCreate, const char* rawId) {
    ViewRecord record;
    record.kind = ObjectKind::kThread;
    record.thread.process.bootId = kBoot;
    record.thread.process.pid = OptionalU64::of(pid);
    record.thread.process.createTime100ns = OptionalU64::of(processCreate);
    record.thread.process.imageName = "worker.exe";
    record.thread.tid = OptionalU64::of(tid);
    record.thread.createTime100ns = OptionalU64::of(threadCreate);
    record.rawRecordId = rawId;
    return record;
}

ViewRecord makeDriverRecord(const char* path, std::uint64_t stamp, std::uint64_t size,
                            const char* pdb, const char* rawId) {
    ViewRecord record;
    record.kind = ObjectKind::kDriver;
    record.driver.bootId = kBoot;
    record.driver.imagePath = path;
    record.driver.timeDateStamp = OptionalU64::of(stamp);
    record.driver.imageSize = OptionalU64::of(size);
    record.driver.pdbSignature = pdb;
    record.rawRecordId = rawId;
    return record;
}

const CrossViewFinding* findByDisplay(const CrossViewReport& report, const std::string& needle) {
    for (const CrossViewFinding& finding : report.findings) {
        if (finding.displayText.find(needle) != std::string::npos) {
            return &finding;
        }
    }
    return nullptr;
}

// Locate strong identity and candidate states separately to avoid misidentifying findings with identical displayText.
const CrossViewFinding* findStrong(const CrossViewReport& report, const std::string& needle) {
    for (const CrossViewFinding& finding : report.findings) {
        if (!finding.identityKey.empty() && finding.displayText.find(needle) != std::string::npos) {
            return &finding;
        }
    }
    return nullptr;
}

const CrossViewFinding* findCandidate(const CrossViewReport& report, const std::string& needle) {
    for (const CrossViewFinding& finding : report.findings) {
        if (finding.identityKey.empty() && finding.displayText.find(needle) != std::string::npos) {
            return &finding;
        }
    }
    return nullptr;
}

const ViewHit* hitFor(const CrossViewFinding* finding, const char* viewId) {
    if (finding == nullptr) {
        return nullptr;
    }
    for (const ViewHit& hit : finding->latestHits) {
        if (hit.viewId == viewId) {
            return &hit;
        }
    }
    return nullptr;
}

bool hitIs(const CrossViewFinding* finding, const char* viewId, ObjectPresence presence,
           CollectionStatus status) {
    const ViewHit* hit = hitFor(finding, viewId);
    return hit != nullptr && hit->presence == presence && hit->viewStatus == status;
}

bool hitGroupIs(const CrossViewFinding* finding, const char* viewId, const char* group) {
    const ViewHit* hit = hitFor(finding, viewId);
    return hit != nullptr && hit->sourceGroup == group;
}

bool hitRawIs(const CrossViewFinding* finding, const char* viewId, const char* rawId) {
    const ViewHit* hit = hitFor(finding, viewId);
    return hit != nullptr && hit->rawRecordId == rawId;
}

bool hasLimitationKey(const CrossViewReport& report, const char* key) {
    return std::find(report.trust.limitationKeys.begin(), report.trust.limitationKeys.end(),
                     std::string(key)) != report.trust.limitationKeys.end();
}

// Test-specific snapshot mutator: remove a known record from a view and synchronously correct that view's ledger.
// A collector that "hides a record" is unaware of the missing data and still reports a consistent ledger.
// Exists only in the test translation unit; not referenced in production code.
void removeRecordFromView(SampleRound& round, const std::string& viewId, const std::string& rawId) {
    for (ViewSnapshot& view : round.views) {
        if (view.viewId != viewId) {
            continue;
        }
        view.records.erase(std::remove_if(view.records.begin(), view.records.end(),
                                          [&rawId](const ViewRecord& r) {
                                              return r.rawRecordId == rawId;
                                          }),
                           view.records.end());
        setAccounting(view);
    }
}

// Force the entire view to fail this round (timeout/rejected), clearing records and accounts.
void failView(SampleRound& round, const std::string& viewId, CollectionStatus status) {
    for (ViewSnapshot& view : round.views) {
        if (view.viewId != viewId) {
            continue;
        }
        view.envelope.outcome =
            CollectionOutcome::failure(status, "WIN32", 1460ULL, "collector failed");
        view.records.clear();
        view.envelope.coverage = CoverageAccount{};
    }
}

// Ensure the view is completely absent this round (collector crash / driver unloading, no envelope sent up).
void dropView(SampleRound& round, const std::string& viewId) {
    round.views.erase(std::remove_if(round.views.begin(), round.views.end(),
                                     [&viewId](const ViewSnapshot& v) { return v.viewId == viewId; }),
                      round.views.end());
}

// Baseline round for three views: two views share the same underlying collector (X-01).
// Each view's rawRecordId carries its own prefix without copying others' data; ownership errors must be caught by assertions.
SampleRound makeBaselineRound(std::uint64_t sampleId, std::uint64_t utc) {
    SampleRound round;
    round.sampleId = sampleId;
    round.sampleUtc100ns = OptionalU64::of(utc);

    ViewSnapshot r3Api;
    r3Api.viewId = "r3.toolhelp";
    r3Api.envelope = makeEnvelope("r3.toolhelp", "r3.toolhelp.snapshot", CollectionStatus::kSuccess);
    r3Api.category = ViewEntityCategory::kProcessList;
    r3Api.records = {
        makeProcessRecord(1000U, kUtcBase, "explorer.exe", "r3-1000"),
        makeProcessRecord(2000U, kUtcBase + 100000ULL, "worker.exe", "r3-2000"),
    };
    setAccounting(r3Api);

    ViewSnapshot r0Enum;
    r0Enum.viewId = "r0.process.enum";
    r0Enum.envelope = makeEnvelope("r0.process.enum", "r0.process.enum", CollectionStatus::kSuccess);
    r0Enum.category = ViewEntityCategory::kProcessList;
    r0Enum.records = {
        makeProcessRecord(1000U, kUtcBase, "explorer.exe", "r0-1000"),
        makeProcessRecord(2000U, kUtcBase + 100000ULL, "worker.exe", "r0-2000"),
    };
    setAccounting(r0Enum);

    // Second-level wrapper for the same R0 collector—not a third independent source, but with its own row ID.
    ViewSnapshot r0Wrapper;
    r0Wrapper.viewId = "ui.processTable";
    r0Wrapper.envelope =
        makeEnvelope("ui.processTable", "r0.process.enum", CollectionStatus::kSuccess);
    r0Wrapper.category = ViewEntityCategory::kProcessList;
    r0Wrapper.records = {
        makeProcessRecord(1000U, kUtcBase, "explorer.exe", "ui-1000"),
        makeProcessRecord(2000U, kUtcBase + 100000ULL, "worker.exe", "ui-2000"),
    };
    setAccounting(r0Wrapper);

    round.views = {r3Api, r0Enum, r0Wrapper};
    return round;
}

// ---------------------------------------------------------------------------
// X-01: Source independence visibility
// ---------------------------------------------------------------------------
void testSourceIndependence(ksword_tests::Suite& s) {
    const CrossViewReport kReport = analyzeCrossView({makeBaselineRound(1U, 1000U)});
    s.expect(kReport.roundCount == 1U, L"X-01 the report states how many rounds it analysed");
    s.expect(kReport.viewCount == 3U, L"X-01 the report counts three views");
    s.expect(kReport.trust.viewCount == 3U, L"X-01 the trust statement counts three views");
    s.expect(kReport.latestRoundViewCount == 3U && kReport.minRoundViewCount == 3U,
             L"X-01 latest and minimum per-round view counts are both three here");
    s.expect(kReport.independentSourceGroupCount == 2U &&
                 kReport.trust.independentSourceGroupCount == 2U,
             L"X-01 two wrappers over one collector collapse into one source group");
    s.expect(kReport.selfCheckPassed, L"X-01 the report passes its own consistency check");

    const CrossViewFinding* explorer = findStrong(kReport, "explorer.exe");
    s.expect(explorer != nullptr, L"X-01 the baseline object is present in the report");
    s.expect(explorer != nullptr && explorer->viewCount == 3U &&
                 explorer->independentSourceGroupCount == 2U,
             L"X-01 each finding carries both the view count and the source group count");
    s.expect(explorer != nullptr && explorer->latestHits.size() == 3U,
             L"X-01 the per-view hit list covers every view exactly once");
    s.expect(explorer != nullptr && explorer->strength == IdentityStrength::kStrong,
             L"X-02 an object keyed by boot id, pid and creation time is a strong identity");

    // sourceGroup must come from the envelope's grouping key, not the collectorId — otherwise the wrapper layer is treated
    // as a third independent source, which is exactly what X-01 prohibits ('improving credibility through repeated views').
    s.expect(hitGroupIs(explorer, "ui.processTable", "r0.process.enum"),
             L"X-01 the wrapper view reports the underlying source group, not its own collector id");
    s.expect(hitGroupIs(explorer, "r0.process.enum", "r0.process.enum"),
             L"X-01 the kernel view reports its own source group");
    s.expect(hitGroupIs(explorer, "r3.toolhelp", "r3.toolhelp.snapshot"),
             L"X-01 the user mode view reports its own source group");
    s.expect(hitRawIs(explorer, "r3.toolhelp", "r3-1000") &&
                 hitRawIs(explorer, "r0.process.enum", "r0-1000") &&
                 hitRawIs(explorer, "ui.processTable", "ui-1000"),
             L"X-07 every view hit links back to that view's own raw record id");
    s.expect(!kReport.trust.anyIncompleteCoverage,
             L"X-01 fully accounted successful views are not flagged as incomplete coverage");
    s.expect(hasLimitationKey(kReport, "trust.limitation.noAbsenceProof"),
             L"X-01 agreement across views never claims the absence of hidden objects");
    s.expect(!hasLimitationKey(kReport, "trust.limitation.singleSourceGroup"),
             L"X-01 two independent source groups do not raise the single-source warning");
}

// ---------------------------------------------------------------------------
// X-01 / X-06: Census must span all rounds; views with a full round absent are not "clean".
// ---------------------------------------------------------------------------
void testCrossRoundCensus(ksword_tests::Suite& s) {
    // (a) Subsequent rounds have two fewer views: R0 collector crashed, and neither it nor its UI
    //     wrapper (same source group) sent up an envelope. The entire r0.process.enum source group is gone.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            dropView(*round, "r0.process.enum");
            dropView(*round, "ui.processTable");
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});

        s.expect(kReport.viewCount == 3U,
                 L"X-01 the view set is the union over all rounds, not just the first one");
        s.expect(kReport.latestRoundViewCount == 1U,
                 L"X-01 the latest round only had one view actually present");
        s.expect(kReport.minRoundViewCount == 1U,
                 L"X-01 the worst round is reported alongside the union");
        s.expect(kReport.independentSourceGroupCount == 1U,
                 L"X-01 a source group that vanished after round one cannot prop up the trust count");
        s.expect(hasLimitationKey(kReport, "trust.limitation.singleSourceGroup"),
                 L"X-01 losing the second source group raises the single-source limitation");
        s.expect(kReport.selfCheckPassed, L"X-01 the census stays internally consistent");

        const CrossViewFinding* explorer = findStrong(kReport, "explorer.exe");
        s.expect(explorer != nullptr && explorer->latestHits.size() == 3U,
                 L"X-06 a view missing for the whole round still gets a hit entry");
        s.expect(hitIs(explorer, "r0.process.enum", ObjectPresence::kUnknownViewFailed,
                       CollectionStatus::kNotCollected),
                 L"X-06 a view that was never collected this round is unknown, not absent");
        const ViewHit* dropped = hitFor(explorer, "r0.process.enum");
        s.expect(dropped != nullptr && dropped->sourceGroup.empty(),
                 L"X-01 a view absent for the round contributes no source group for that round");
    }

    // (b) Views absent for the entire round must not trigger 'object ended / no differences found' (the observed topology for BLOCKER 3).
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot kernel;
            kernel.viewId = "r0.process.enum";
            kernel.envelope =
                makeEnvelope("r0.process.enum", "r0.process.enum", CollectionStatus::kSuccess);
            kernel.category = ViewEntityCategory::kProcessList;
            kernel.records = {makeProcessRecord(4242U, kUtcBase + 200000ULL, "ghost.exe", "r0-4242")};
            setAccounting(kernel);

            ViewSnapshot api;
            api.viewId = "r3.api";
            api.envelope = makeEnvelope("r3.api", "r3.api", CollectionStatus::kSuccess);
            api.category = ViewEntityCategory::kProcessList;
            setAccounting(api);

            ViewSnapshot wmi;
            wmi.viewId = "r3.wmi";
            wmi.envelope = makeEnvelope("r3.wmi", "r3.wmi", CollectionStatus::kSuccess);
            wmi.category = ViewEntityCategory::kProcessList;
            setAccounting(wmi);

            round.views = {kernel, api, wmi};
            if (i > 0U) {
                dropView(round, "r0.process.enum");  // Witness view absent for the entire round
            }
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        const CrossViewFinding* ghost = findStrong(kReport, "ghost.exe");
        s.expect(ghost != nullptr, L"X-06 the object reported by the vanished view is still tracked");
        s.expect(ghost != nullptr && ghost->state != DiscrepancyState::kObjectEnded,
                 L"X-06 a view that was never collected cannot prove the object ended");
        s.expect(ghost != nullptr && ghost->state == DiscrepancyState::kUnverifiable,
                 L"X-06 losing the only witnessing view makes the recheck unverifiable");
        s.expect(ghost != nullptr && ghost->conclusion != AnalysisConclusion::kNoDifferenceObserved,
                 L"F-05 a never-collected view can never yield no-difference-observed");
        s.expect(ghost != nullptr && ghost->conclusion == AnalysisConclusion::kIndeterminate,
                 L"F-05 the conclusion for an unverifiable recheck is indeterminate");
        s.expect(ghost != nullptr && ghost->recheckHistory.size() == 3U &&
                     ghost->recheckHistory[1].unusableViews == 1U &&
                     ghost->recheckHistory[1].presentViews == 0U &&
                     ghost->recheckHistory[1].usableAbsentViews == 2U,
                 L"X-06 the recheck history counts the absent view as unusable, not as clean");
    }

    // (c) Subsequent rounds have one additional view, and the final round includes access denied and hit limit.
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot kernel;
            kernel.viewId = "r0.process.enum";
            kernel.envelope =
                makeEnvelope("r0.process.enum", "r0.process.enum", CollectionStatus::kSuccess);
            kernel.category = ViewEntityCategory::kProcessList;
            kernel.records = {makeProcessRecord(1000U, kUtcBase, "explorer.exe", "r0-1000")};
            setAccounting(kernel);
            round.views = {kernel};

            if (i > 0U) {
                ViewSnapshot denied;
                denied.viewId = "r3.wmi";
                denied.envelope = makeEnvelope("r3.wmi", "r3.wmi", CollectionStatus::kAccessDenied);
                denied.category = ViewEntityCategory::kProcessList;
                round.views.push_back(denied);

                ViewSnapshot capped;
                capped.viewId = "r0.scan";
                capped.envelope = makeEnvelope("r0.scan", "r0.scan", CollectionStatus::kSuccess);
                capped.category = ViewEntityCategory::kProcessList;
                capped.envelope.coverage.limitHit = true;
                capped.envelope.coverage.limit = OptionalU64::of(1U);
                round.views.push_back(capped);
            }
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        s.expect(kReport.viewCount == 3U,
                 L"X-01 views that only appear in later rounds still join the union");
        s.expect(kReport.minRoundViewCount == 1U && kReport.latestRoundViewCount == 3U,
                 L"X-01 both the worst and the latest per-round view counts are reported");
        s.expect(kReport.independentSourceGroupCount == 1U,
                 L"X-01 the source group count is the minimum across rounds, not the best round");
        s.expect(kReport.trust.anyIncompleteCoverage,
                 L"X-01 an access denied view in the last round stays visible in the trust statement");
        const CrossViewFinding* explorer = findStrong(kReport, "explorer.exe");
        s.expect(explorer != nullptr && explorer->latestHits.size() == 3U,
                 L"X-01 the finding hit list matches the union view count");
        s.expect(hitIs(explorer, "r3.wmi", ObjectPresence::kUnknownViewFailed,
                       CollectionStatus::kAccessDenied),
                 L"X-06 an access denied view is unknown-failed, never absent");
        s.expect(hitIs(explorer, "r0.scan", ObjectPresence::kUnknownOutOfCoverage,
                       CollectionStatus::kSuccess),
                 L"X-06 a successful but capped view is unknown-out-of-coverage");
    }

    // (d) Same viewId later rotates to a shared source group: independent source count must drop to 1.
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));
            const char* groupA = (i == 0U) ? "group.A" : "group.SHARED";
            const char* groupB = (i == 0U) ? "group.B" : "group.SHARED";

            ViewSnapshot a;
            a.viewId = "view.a";
            a.envelope = makeEnvelope("view.a", groupA, CollectionStatus::kSuccess);
            a.category = ViewEntityCategory::kProcessList;
            a.records = {makeProcessRecord(1000U, kUtcBase, "explorer.exe", "a-1000")};
            setAccounting(a);

            ViewSnapshot b;
            b.viewId = "view.b";
            b.envelope = makeEnvelope("view.b", groupB, CollectionStatus::kSuccess);
            b.category = ViewEntityCategory::kProcessList;
            b.records = {makeProcessRecord(1000U, kUtcBase, "explorer.exe", "b-1000")};
            setAccounting(b);

            round.views = {a, b};
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        s.expect(kReport.viewCount == 2U, L"X-01 the two views are counted once each");
        s.expect(kReport.independentSourceGroupCount == 1U,
                 L"X-01 two views that collapsed into one source group are one independent source");
        const CrossViewFinding* explorer = findStrong(kReport, "explorer.exe");
        s.expect(hitGroupIs(explorer, "view.a", "group.SHARED") &&
                     hitGroupIs(explorer, "view.b", "group.SHARED"),
                 L"X-01 the latest hits report the source group actually in effect");
        s.expect(kReport.selfCheckPassed,
                 L"X-01 claiming more independent sources than the latest round shows fails self check");
    }
}

// ---------------------------------------------------------------------------
// X-06: Failure is not absence.
// ---------------------------------------------------------------------------
void testFailureIsNotAbsence(ksword_tests::Suite& s) {
    s.expect(!viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kTimeout, 3U), true),
             L"X-06 a timed out view cannot confirm absence");
    s.expect(!viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kAccessDenied, 3U), true),
             L"X-06 an access denied view cannot confirm absence");
    s.expect(!viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kUnsupported, 3U), true),
             L"X-06 an unsupported view cannot confirm absence");
    s.expect(!viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kNotCollected, 3U), true),
             L"X-06 a view that was never collected cannot confirm absence");
    s.expect(!viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kPartial, 3U), true),
             L"X-06 a partial view cannot confirm absence");
    s.expect(!viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kSuccess, 3U), false),
             L"X-06 a view that did not cover the target scope cannot confirm absence");
    {
        EvidenceEnvelope truncated = makeAccountedEnvelope(CollectionStatus::kSuccess, 3U);
        truncated.coverage.truncated = 1U;
        s.expect(!viewUsableForAbsence(truncated, true),
                 L"X-06 a truncated view cannot confirm absence");
    }
    {
        EvidenceEnvelope capped = makeAccountedEnvelope(CollectionStatus::kSuccess, 3U);
        capped.coverage.limitHit = true;
        s.expect(!viewUsableForAbsence(capped, true),
                 L"X-06 a view that stopped at its limit cannot confirm absence");
    }
    {
        // Account completely empty: status is success and coverage is claimed, but there is no positive evidence of completeness.
        EvidenceEnvelope blank = makeEnvelope("v", "v", CollectionStatus::kSuccess);
        s.expect(!viewUsableForAbsence(blank, true),
                 L"X-06 an empty coverage account is unknown coverage, not a complete scan");
    }
    {
        // Range criteria: all four endpoints are present, and the processed range covers the requested range.
        EvidenceEnvelope ranged = makeEnvelope("v", "v", CollectionStatus::kSuccess);
        ranged.coverage.requestedBegin = OptionalU64::of(0x1000ULL);
        ranged.coverage.requestedEnd = OptionalU64::of(0x9000ULL);
        ranged.coverage.processedBegin = OptionalU64::of(0x1000ULL);
        ranged.coverage.processedEnd = OptionalU64::of(0x9000ULL);
        s.expect(viewUsableForAbsence(ranged, true),
                 L"X-06 a fully processed requested range is positive evidence of completeness");
        ranged.coverage.processedEnd = OptionalU64::of(0x5000ULL);
        s.expect(!viewUsableForAbsence(ranged, true),
                 L"X-06 a range that stopped early cannot confirm absence");
    }
    s.expect(viewUsableForAbsence(makeAccountedEnvelope(CollectionStatus::kSuccess, 3U), true),
             L"X-06 a complete successful view with a settled account is usable for absence");

    // One view has objects, one is empty but successful, one is access denied, one returns only the upper limit, one is unsupported,
    // and one never ran. Assert exact values per view: the two 'unknown' cases must never collapse into a single counter.
    SampleRound round;
    round.sampleId = 1U;
    round.sampleUtc100ns = OptionalU64::of(1000U);

    ViewSnapshot present;
    present.viewId = "r0.enum";
    present.envelope = makeEnvelope("r0.enum", "r0.enum", CollectionStatus::kSuccess);
    present.category = ViewEntityCategory::kProcessList;
    present.records = {makeProcessRecord(4242U, kUtcBase + 200000ULL, "ghost.exe", "r0-4242")};
    setAccounting(present);

    ViewSnapshot emptySuccess;
    emptySuccess.viewId = "r3.api";
    emptySuccess.envelope = makeEnvelope("r3.api", "r3.api", CollectionStatus::kSuccess);
    emptySuccess.category = ViewEntityCategory::kProcessList;
    setAccounting(emptySuccess);

    ViewSnapshot denied;
    denied.viewId = "r3.wmi";
    denied.envelope = makeEnvelope("r3.wmi", "r3.wmi", CollectionStatus::kAccessDenied);
    denied.category = ViewEntityCategory::kProcessList;

    ViewSnapshot capped;
    capped.viewId = "r0.scan";
    capped.envelope = makeEnvelope("r0.scan", "r0.scan", CollectionStatus::kSuccess);
    capped.category = ViewEntityCategory::kProcessList;
    capped.envelope.coverage.limitHit = true;
    capped.envelope.coverage.limit = OptionalU64::of(1U);

    ViewSnapshot unsupported;
    unsupported.viewId = "r0.hvm";
    unsupported.envelope = makeEnvelope("r0.hvm", "r0.hvm", CollectionStatus::kUnsupported);
    unsupported.category = ViewEntityCategory::kProcessList;

    ViewSnapshot notRun;
    notRun.viewId = "r3.etw";
    notRun.envelope = makeEnvelope("r3.etw", "r3.etw", CollectionStatus::kNotCollected);
    notRun.category = ViewEntityCategory::kProcessList;

    round.views = {present, emptySuccess, denied, capped, unsupported, notRun};
    const CrossViewReport kReport = analyzeCrossView({round});
    const CrossViewFinding* ghost = findStrong(kReport, "ghost.exe");
    s.expect(ghost != nullptr, L"X-06 the object seen by one view is tracked");
    s.expect(ghost != nullptr && ghost->latestHits.size() == 6U,
             L"X-06 every view produces exactly one hit entry");
    s.expect(hitIs(ghost, "r0.enum", ObjectPresence::kPresent, CollectionStatus::kSuccess),
             L"X-06 the view that listed the object reports Present");
    s.expect(hitIs(ghost, "r3.api", ObjectPresence::kAbsentInUsableView, CollectionStatus::kSuccess),
             L"X-06 only the complete successful view counts as absent");
    s.expect(hitIs(ghost, "r3.wmi", ObjectPresence::kUnknownViewFailed, CollectionStatus::kAccessDenied),
             L"X-06 access denied is UnknownViewFailed, not UnknownOutOfCoverage");
    s.expect(hitIs(ghost, "r0.scan", ObjectPresence::kUnknownOutOfCoverage, CollectionStatus::kSuccess),
             L"X-06 a successful capped view is UnknownOutOfCoverage, not UnknownViewFailed");
    s.expect(hitIs(ghost, "r0.hvm", ObjectPresence::kUnknownViewFailed, CollectionStatus::kUnsupported),
             L"X-06 an unsupported view is UnknownViewFailed");
    s.expect(hitIs(ghost, "r3.etw", ObjectPresence::kUnknownViewFailed, CollectionStatus::kNotCollected),
             L"X-06 a view that never ran is UnknownViewFailed");
    s.expect(hitRawIs(ghost, "r0.enum", "r0-4242") && hitRawIs(ghost, "r3.api", ""),
             L"X-07 only the Present hit carries a raw record id");
    s.expect(ghost != nullptr && ghost->state == DiscrepancyState::kPendingRecheck,
             L"X-05 a first-round discrepancy is pending recheck, not a confirmed difference");
    s.expect(ghost != nullptr && ghost->conclusion == AnalysisConclusion::kIndeterminate,
             L"X-06 a partially covered round does not conclude no-difference");

    // Silently corrupted collector: Success reported 500 records, but zero records were actually returned.
    {
        SampleRound broken;
        broken.sampleId = 1U;
        broken.sampleUtc100ns = OptionalU64::of(1000U);

        ViewSnapshot good;
        good.viewId = "r0.enum";
        good.envelope = makeEnvelope("r0.enum", "r0.enum", CollectionStatus::kSuccess);
        good.category = ViewEntityCategory::kProcessList;
        good.records = {makeProcessRecord(1000U, kUtcBase, "explorer.exe", "r0-1000")};
        setAccounting(good);

        ViewSnapshot silent;
        silent.viewId = "r3.broken";
        silent.envelope = makeEnvelope("r3.broken", "r3.broken", CollectionStatus::kSuccess);
        silent.category = ViewEntityCategory::kProcessList;
        silent.envelope.coverage.totalKnown = OptionalU64::of(500U);
        silent.envelope.coverage.succeeded = 500U;

        broken.views = {good, silent};
        const CrossViewReport kBrokenReport = analyzeCrossView({broken, broken, broken});
        const CrossViewFinding* explorer = findStrong(kBrokenReport, "explorer.exe");
        s.expect(hitIs(explorer, "r3.broken", ObjectPresence::kUnknownOutOfCoverage,
                       CollectionStatus::kSuccess),
                 L"X-06 an account claiming 500 successes with zero records is not usable for absence");
        s.expect(explorer != nullptr && explorer->state == DiscrepancyState::kNoDiscrepancy,
                 L"X-06 a silently broken collector must not turn a normal object into a difference");
        s.expect(explorer != nullptr && explorer->conclusion == AnalysisConclusion::kIndeterminate,
                 L"F-05 a round containing an unusable view cannot conclude no-difference-observed");
    }
}

// ---------------------------------------------------------------------------
// X-05: Resampling confirmation (transient / persistent / ended / unrecoverable)
// ---------------------------------------------------------------------------
void testResampleClassification(ksword_tests::Suite& s) {
    // Transient: missing in round 1, appears in round 2.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kTransient,
                 L"X-05 an object that reappears on recheck is transient, not hidden");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"X-05 a transient discrepancy explained under full coverage observes no difference");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 3U &&
                     worker->recheckHistory[1].intervalFromFirst100ns.present &&
                     worker->recheckHistory[1].intervalFromFirst100ns.value == 1000U,
                 L"X-05 the recheck interval is recorded");
        s.expect(worker != nullptr && worker->recheckHistory[0].hits.size() == 3U &&
                     worker->recheckHistory[0].usableAbsentViews == 1U &&
                     worker->recheckHistory[0].presentViews == 2U,
                 L"X-07 every recheck round can be expanded into its per-view hits");
    }

    // Persistent discrepancy: missing in all three rounds.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kPersistent,
                 L"X-05 a discrepancy surviving two rechecks becomes persistent");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"X-05 a persistent discrepancy is reported as an observed difference");
        s.expect(hitIs(worker, "r3.toolhelp", ObjectPresence::kAbsentInUsableView,
                       CollectionStatus::kSuccess),
                 L"X-08 the affected view is named precisely");
    }

    // Only one recheck round is required for upgrade: requiredRecheckRounds = 1.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        removeRecordFromView(r2, "r3.toolhelp", "r3-2000");
        CrossViewOptions options;
        options.requiredRecheckRounds = 1U;
        const CrossViewReport kReport = analyzeCrossView({r1, r2}, options);
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kPersistent,
                 L"X-05 one recheck round is enough when the caller asked for one");
    }

    // When requiring three rounds of re-examination, the same three rounds of input must only stop at the pending review stage.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        CrossViewOptions options;
        options.requiredRecheckRounds = 3U;
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3}, options);
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kPendingRecheck,
                 L"X-05 three required recheck rounds are not met by two available ones");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kIndeterminate,
                 L"F-05 a pending recheck never claims no difference");
    }

    // Object terminated: all views in the review round are available and no longer list it.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
            removeRecordFromView(*round, "r0.process.enum", "r0-2000");
            removeRecordFromView(*round, "ui.processTable", "ui-2000");
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kObjectEnded,
                 L"X-05 an object gone from every usable view is reported as ended, not hidden");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kIndeterminate,
                 L"F-05 object-ended explains the gap but is not a no-difference conclusion");
    }

    // BLOCKER 1: Witness view round timeout; must not be interpreted as 'object ended'.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
            removeRecordFromView(*round, "ui.processTable", "ui-2000");
            failView(*round, "r0.process.enum", CollectionStatus::kTimeout);
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state != DiscrepancyState::kObjectEnded,
                 L"X-06 a timed out witnessing view must not be read as the object having ended");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kUnverifiable,
                 L"X-06 with the witness timed out the recheck stays unverifiable");
        s.expect(hitIs(worker, "r0.process.enum", ObjectPresence::kUnknownViewFailed,
                       CollectionStatus::kTimeout),
                 L"X-06 the timed out witness is reported as UnknownViewFailed with its real status");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kIndeterminate,
                 L"F-05 an unverifiable recheck is indeterminate, never no-difference");
    }

    // Cannot re-verify: all views fail in the re-verification round (all three counts present/usableAbsent are 0 -> skip).
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        for (SampleRound* round : {&r2, &r3}) {
            for (ViewSnapshot& view : round->views) {
                failView(*round, view.viewId, CollectionStatus::kTimeout);
            }
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kUnverifiable,
                 L"X-05 failing rechecks yield unverifiable, never a persistent difference");
    }

    // An empty round (with no views) must not be counted as a valid review.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        SampleRound empty;
        empty.sampleId = 2U;
        empty.sampleUtc100ns = OptionalU64::of(2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        removeRecordFromView(r3, "r3.toolhelp", "r3-2000");
        const CrossViewReport kReport = analyzeCrossView({r1, empty, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kUnverifiable,
                 L"X-05 a round with no views at all is not a usable recheck round");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 3U &&
                     worker->recheckHistory[1].presentViews == 0U &&
                     worker->recheckHistory[1].usableAbsentViews == 0U &&
                     worker->recheckHistory[1].unusableViews == 3U,
                 L"X-06 an empty round marks every union view as unusable, not as clean");
        s.expect(kReport.minRoundViewCount == 0U && kReport.viewCount == 3U,
                 L"X-01 the empty round is reported as zero views without shrinking the union");
    }

    // Thresholds must truly compare round counts: sufficient for recheck, but insufficient rounds of continuous loss -> recheck fails.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        SampleRound r4 = makeBaselineRound(4U, 4000U);
        removeRecordFromView(r1, "r3.toolhelp", "r3-2000");
        removeRecordFromView(r2, "r3.toolhelp", "r3-2000");
        for (SampleRound* round : {&r3, &r4}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
            removeRecordFromView(*round, "ui.processTable", "ui-2000");
            failView(*round, "r0.process.enum", CollectionStatus::kTimeout);
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3, r4});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kUnverifiable,
                 L"X-05 one persistent round out of three rechecks does not reach the threshold of two");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 4U,
                 L"X-07 the recheck history keeps every round from the first discrepancy onward");
    }

    // X-05: Clock rollback. Unsigned naked subtraction turns a 5-second NTP correction into a 5.8e13-year "effective interval".
    {
        SampleRound r1 = makeBaselineRound(1U, kUtcBase);
        SampleRound r2 = makeBaselineRound(2U, kUtcBase - 50000000ULL);
        SampleRound r3 = makeBaselineRound(3U, kUtcBase + 100000000ULL);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->recheckHistory.size() == 3U,
                 L"X-05 all three rounds are kept in the recheck history");
        s.expect(worker != nullptr && !worker->recheckHistory[1].intervalFromFirst100ns.present,
                 L"X-05 a backwards clock leaves the interval unset instead of wrapping around");
        s.expect(worker != nullptr && worker->recheckHistory[1].clockWentBackwards,
                 L"X-05 the backwards clock is stated explicitly rather than silently dropped");
        s.expect(worker != nullptr && worker->recheckHistory[2].intervalFromFirst100ns.present &&
                     worker->recheckHistory[2].intervalFromFirst100ns.value == 100000000ULL &&
                     !worker->recheckHistory[2].clockWentBackwards,
                 L"X-05 a later sample after the correction still gets its real interval");
    }

    // The state and conclusion must be derived from the same evidence window: after three consecutive missing rounds, the entire round times out, yet the persistent discrepancy remains.
    {
        SampleRound r1 = makeBaselineRound(1U, 1000U);
        SampleRound r2 = makeBaselineRound(2U, 2000U);
        SampleRound r3 = makeBaselineRound(3U, 3000U);
        SampleRound r4 = makeBaselineRound(4U, 4000U);
        for (SampleRound* round : {&r1, &r2, &r3}) {
            removeRecordFromView(*round, "r3.toolhelp", "r3-2000");
        }
        for (ViewSnapshot& view : r4.views) {
            failView(r4, view.viewId, CollectionStatus::kTimeout);
        }
        const CrossViewReport kReport = analyzeCrossView({r1, r2, r3, r4});
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kPersistent,
                 L"X-05 a round where every view timed out does not undo the persistent classification");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kDifferenceObserved,
                 L"F-05 a persistent state can never carry a no-evidence conclusion");
        s.expect(worker != nullptr &&
                     stateConclusionConsistent(worker->state, worker->conclusion),
                 L"F-05 state and conclusion pass the contradiction check");
    }
}

// ---------------------------------------------------------------------------
// X-08: Replayable detection positives (process/thread/driver)
// ---------------------------------------------------------------------------
void testReplayablePositives(ksword_tests::Suite& s) {
    // Process
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round = makeBaselineRound(i + 1U, 1000U * (i + 1U));
            removeRecordFromView(round, "r3.toolhelp", "r3-1000");
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        const CrossViewFinding* explorer = findStrong(kReport, "explorer.exe");
        const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
        s.expect(explorer != nullptr && explorer->state == DiscrepancyState::kPersistent,
                 L"X-08 the deleted process record is located exactly");
        s.expect(worker != nullptr && worker->state == DiscrepancyState::kNoDiscrepancy,
                 L"X-08 the untouched process is not reported as a discrepancy");
        s.expect(worker != nullptr && worker->conclusion == AnalysisConclusion::kNoDifferenceObserved,
                 L"X-07 a clean object still reports the coverage it was checked under");
        s.expect(hitIs(explorer, "r3.toolhelp", ObjectPresence::kAbsentInUsableView,
                       CollectionStatus::kSuccess),
                 L"X-08 the affected view is named precisely");
        s.expect(hitRawIs(explorer, "r0.process.enum", "r0-1000") &&
                     hitRawIs(explorer, "ui.processTable", "ui-1000"),
                 L"X-07 each remaining view links back to its own raw source record");
        s.expect(explorer != nullptr && explorer->firstSeenViewId == "r0.process.enum" &&
                     explorer->firstSeenRawRecordId == "r0-1000" &&
                     explorer->firstSeenRoundIndex == 0U,
                 L"X-07 the finding names the earliest source record that reported the object");
    }

    // Thread
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot r0;
            r0.viewId = "r0.thread.enum";
            r0.envelope = makeEnvelope("r0.thread.enum", "r0.thread", CollectionStatus::kSuccess);
            r0.category = ViewEntityCategory::kThreadList;
            r0.records = {
                makeThreadRecord(2000U, kUtcBase + 100000ULL, 3001U, kUtcBase + 110000ULL, "r0-t3001"),
                makeThreadRecord(2000U, kUtcBase + 100000ULL, 3002U, kUtcBase + 120000ULL, "r0-t3002"),
            };
            setAccounting(r0);

            ViewSnapshot r3;
            r3.viewId = "r3.thread.snapshot";
            r3.envelope =
                makeEnvelope("r3.thread.snapshot", "r3.thread", CollectionStatus::kSuccess);
            r3.category = ViewEntityCategory::kThreadList;
            r3.records = {
                makeThreadRecord(2000U, kUtcBase + 100000ULL, 3001U, kUtcBase + 110000ULL, "r3-t3001"),
                makeThreadRecord(2000U, kUtcBase + 100000ULL, 3002U, kUtcBase + 120000ULL, "r3-t3002"),
            };
            setAccounting(r3);

            round.views = {r0, r3};
            removeRecordFromView(round, "r3.thread.snapshot", "r3-t3002");
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        const CrossViewFinding* hidden = findStrong(kReport, "TID 3002");
        const CrossViewFinding* normal = findStrong(kReport, "TID 3001");
        s.expect(hidden != nullptr && hidden->state == DiscrepancyState::kPersistent,
                 L"X-08 the deleted thread record is located exactly");
        s.expect(normal != nullptr && normal->state == DiscrepancyState::kNoDiscrepancy,
                 L"X-08 the untouched thread is clean");
        s.expect(hitRawIs(hidden, "r0.thread.enum", "r0-t3002"),
                 L"X-07 the thread finding links back to the kernel view's own record id");
        s.expect(hitIs(hidden, "r3.thread.snapshot", ObjectPresence::kAbsentInUsableView,
                       CollectionStatus::kSuccess),
                 L"X-08 the affected thread view is named precisely");
    }

    // Driver: The cross-view explanation concerns only the missing items between the two load module lists of the same category.
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot kernelModules;
            kernelModules.viewId = "r0.module.list";
            kernelModules.envelope =
                makeEnvelope("r0.module.list", "r0.module", CollectionStatus::kSuccess);
            kernelModules.category = ViewEntityCategory::kLoadedModuleList;
            kernelModules.records = {
                makeDriverRecord("\\SystemRoot\\System32\\drivers\\ksword.sys", 0x65000000ULL,
                                 0x30000ULL, "GUID-K/1", "r0-mod-ksword"),
                makeDriverRecord("\\SystemRoot\\System32\\ntoskrnl.exe", 0x64000000ULL, 0xA00000ULL,
                                 "GUID-N/1", "r0-mod-ntos"),
            };
            setAccounting(kernelModules);

            // Another **same-category** loaded module view (module enumeration on the R3 side).
            ViewSnapshot userModules;
            userModules.viewId = "r3.module.enum";
            userModules.envelope =
                makeEnvelope("r3.module.enum", "r3.module", CollectionStatus::kSuccess);
            userModules.category = ViewEntityCategory::kLoadedModuleList;
            userModules.records = {
                makeDriverRecord("\\SystemRoot\\System32\\drivers\\ksword.sys", 0x65000000ULL,
                                 0x30000ULL, "GUID-K/1", "r3-mod-ksword"),
                makeDriverRecord("\\SystemRoot\\System32\\ntoskrnl.exe", 0x64000000ULL, 0xA00000ULL,
                                 "GUID-N/1", "r3-mod-ntos"),
            };
            setAccounting(userModules);

            round.views = {kernelModules, userModules};
            removeRecordFromView(round, "r3.module.enum", "r3-mod-ksword");
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        const CrossViewFinding* driver = findStrong(kReport, "ksword.sys");
        const CrossViewFinding* ntos = findStrong(kReport, "ntoskrnl.exe");
        s.expect(driver != nullptr && driver->state == DiscrepancyState::kPersistent,
                 L"X-08 a module missing from another loaded-module view is located exactly");
        s.expect(ntos != nullptr && ntos->state == DiscrepancyState::kNoDiscrepancy,
                 L"X-08 the untouched driver is clean");
        s.expect(hitIs(driver, "r3.module.enum", ObjectPresence::kAbsentInUsableView,
                       CollectionStatus::kSuccess),
                 L"X-08 the affected module view is named precisely");
        s.expect(hitRawIs(driver, "r0.module.list", "r0-mod-ksword"),
                 L"X-07 the driver finding links back to the module list's own record id");
    }
}

// ---------------------------------------------------------------------------
// X-04: Loading a module, DriverObject, DeviceObject, and disk service configuration are four distinct entities.
// ---------------------------------------------------------------------------
void testEntityCategories(ksword_tests::Suite& s) {
    // A boot-start driver: In the loaded module list, it legitimately has no service entries and no device objects.
    std::vector<SampleRound> rounds;
    for (std::uint64_t i = 0; i < 3U; ++i) {
        SampleRound round;
        round.sampleId = i + 1U;
        round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

        ViewSnapshot modules;
        modules.viewId = "r0.module.list";
        modules.envelope = makeEnvelope("r0.module.list", "r0.module", CollectionStatus::kSuccess);
        modules.category = ViewEntityCategory::kLoadedModuleList;
        modules.records = {
            makeDriverRecord("\\SystemRoot\\System32\\drivers\\bootdrv.sys", 0x65000000ULL,
                             0x20000ULL, "GUID-B/1", "r0-mod-boot"),
        };
        setAccounting(modules);

        ViewSnapshot devices;
        devices.viewId = "r0.device.tree";
        devices.envelope = makeEnvelope("r0.device.tree", "r0.device", CollectionStatus::kSuccess);
        devices.category = ViewEntityCategory::kDeviceObjectTree;
        setAccounting(devices);  // This driver created no device objects: a valid empty list.

        ViewSnapshot services;
        services.viewId = "r3.service.registry";
        services.envelope =
            makeEnvelope("r3.service.registry", "r3.service", CollectionStatus::kSuccess);
        services.category = ViewEntityCategory::kServiceConfig;
        services.records = {
            // Service exists but is not currently loaded: it is absent from the loaded module list, which is also a valid state.
            makeDriverRecord("\\SystemRoot\\System32\\drivers\\phantom.sys", 0x66000000ULL,
                             0x10000ULL, "GUID-P/1", "r3-svc-phantom"),
        };
        setAccounting(services);

        round.views = {modules, devices, services};
        rounds.push_back(round);
    }
    const CrossViewReport kReport = analyzeCrossView(rounds);

    const CrossViewFinding* boot = findStrong(kReport, "bootdrv.sys");
    s.expect(boot != nullptr, L"X-04 the loaded boot driver is tracked");
    s.expect(boot != nullptr && boot->state == DiscrepancyState::kNoDiscrepancy,
             L"X-04 a module with no DriverObject and no service entry is not a persistent difference");
    s.expect(boot != nullptr && boot->state != DiscrepancyState::kPersistent,
             L"X-04 legitimate many-to-many structure is never reported as a rootkit");
    s.expect(hitIs(boot, "r0.device.tree", ObjectPresence::kNotComparableCategory,
                   CollectionStatus::kSuccess),
             L"X-04 a device object view is a different entity class, not an absent module");
    s.expect(hitIs(boot, "r3.service.registry", ObjectPresence::kNotComparableCategory,
                   CollectionStatus::kSuccess),
             L"X-04 a service configuration view is a different entity class than a module list");
    s.expect(hitIs(boot, "r0.module.list", ObjectPresence::kPresent, CollectionStatus::kSuccess),
             L"X-04 the loaded module list is the class that actually listed the driver");

    const CrossViewFinding* phantom = findStrong(kReport, "phantom.sys");
    s.expect(phantom != nullptr && phantom->state == DiscrepancyState::kNoDiscrepancy,
             L"X-04 a configured but unloaded service is not a module list discrepancy");
    s.expect(hitIs(phantom, "r0.module.list", ObjectPresence::kNotComparableCategory,
                   CollectionStatus::kSuccess),
             L"X-04 the module list not listing a service entry is a class difference, not a gap");

    // The category base facts must be expandable: the module list shows 1 view, while the device tree shows 0.
    bool sawModuleCategory = false;
    bool sawDeviceCategory = false;
    if (boot != nullptr) {
        for (const CategoryObservation& observation : boot->latestCategories) {
            if (observation.category == ViewEntityCategory::kLoadedModuleList) {
                sawModuleCategory = observation.viewsInCategory == 1U &&
                                    observation.viewsListing == 1U && observation.comparable;
            }
            if (observation.category == ViewEntityCategory::kDeviceObjectTree) {
                sawDeviceCategory = observation.viewsInCategory == 1U &&
                                    observation.viewsListing == 0U &&
                                    observation.usableViewsNotListing == 0U && !observation.comparable;
            }
        }
    }
    s.expect(sawModuleCategory,
             L"X-04 the module class reports one view that listed the driver");
    s.expect(sawDeviceCategory,
             L"X-04 the device object class is reported as a cardinality fact, not as a missing item");

    // Real hidden items of the same category must still be caught — category isolation is not a get-out-of-jail-free card.
    {
        std::vector<SampleRound> hidden;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round = rounds[static_cast<std::size_t>(i)];
            ViewSnapshot second;
            second.viewId = "r3.module.enum";
            second.envelope =
                makeEnvelope("r3.module.enum", "r3.module", CollectionStatus::kSuccess);
            second.category = ViewEntityCategory::kLoadedModuleList;
            setAccounting(second);  // It is a view of the same category, but it does not list bootdrv.sys.
            round.views.push_back(second);
            hidden.push_back(round);
        }
        const CrossViewReport kHiddenReport = analyzeCrossView(hidden);
        const CrossViewFinding* boot2 = findStrong(kHiddenReport, "bootdrv.sys");
        s.expect(boot2 != nullptr && boot2->state == DiscrepancyState::kPersistent,
                 L"X-04 a module missing from a same-class module view is still a persistent difference");
        s.expect(hitIs(boot2, "r3.module.enum", ObjectPresence::kAbsentInUsableView,
                       CollectionStatus::kSuccess),
                 L"X-04 same-class absence is absence, not a class difference");
        s.expect(hitIs(boot2, "r0.device.tree", ObjectPresence::kNotComparableCategory,
                       CollectionStatus::kSuccess),
                 L"X-04 the cross-class views stay out of the absence inference");
    }
}

// ---------------------------------------------------------------------------
// X-02: Identity insufficient prevents merging, but disappearance is also forbidden.
// ---------------------------------------------------------------------------
void testIdentityGuards(ksword_tests::Suite& s) {
    SampleRound round;
    round.sampleId = 1U;
    round.sampleUtc100ns = OptionalU64::of(1000U);

    ViewSnapshot withCreateTime;
    withCreateTime.viewId = "r0.enum";
    withCreateTime.envelope = makeEnvelope("r0.enum", "r0.enum", CollectionStatus::kSuccess);
    withCreateTime.category = ViewEntityCategory::kProcessList;
    withCreateTime.records = {makeProcessRecord(500U, kUtcBase + 300000ULL, "svc.exe", "r0-500")};
    setAccounting(withCreateTime);

    // Only one view has a creation time: the other view's record identity is insufficient to be merged into the same object.
    ViewSnapshot withoutCreateTime;
    withoutCreateTime.viewId = "r3.enum";
    withoutCreateTime.envelope = makeEnvelope("r3.enum", "r3.enum", CollectionStatus::kSuccess);
    withoutCreateTime.category = ViewEntityCategory::kProcessList;
    ViewRecord weak = makeProcessRecord(500U, 0U, "svc.exe", "r3-500");
    weak.process.createTime100ns = OptionalU64::unset();
    withoutCreateTime.records = {weak};
    setAccounting(withoutCreateTime);

    round.views = {withCreateTime, withoutCreateTime};
    const CrossViewReport kReport = analyzeCrossView({round});
    s.expect(kReport.weakIdentityRecords == 1U,
             L"X-02 a record without a creation time is counted as a weak candidate record");
    s.expect(kReport.weakIdentityObjects == 1U,
             L"X-02 weak records are also counted as objects after deduplication");
    s.expect(kReport.findings.size() == 2U,
             L"X-02 the weak record gets its own candidate finding instead of being dropped");

    const CrossViewFinding* strong = findStrong(kReport, "svc.exe");
    const CrossViewFinding* candidate = findCandidate(kReport, "svc.exe");
    s.expect(strong != nullptr && !strong->identityKey.empty() &&
                 strong->strength == IdentityStrength::kStrong,
             L"X-02 the record with a creation time keeps its strong cross-session key");
    s.expect(candidate != nullptr && candidate->identityKey.empty() &&
                 !candidate->candidateKey.empty(),
             L"X-02 the weak record carries a candidate key and no cross-session key");
    s.expect(candidate != nullptr && candidate->strength == IdentityStrength::kWeak,
             L"X-02 the weak record is labelled as a weak association, not a strong one");
    s.expect(candidate != nullptr && candidate->state == DiscrepancyState::kCandidateOnly,
             L"X-02 a candidate object can never be escalated to a persistent difference");
    s.expect(candidate != nullptr && candidate->conclusion == AnalysisConclusion::kIndeterminate,
             L"X-02 a candidate relation is indeterminate, never a confirmed difference");
    s.expect(candidate != nullptr && candidate->kind == ObjectKind::kProcess &&
                 candidate->displayText.find("svc.exe") != std::string::npos,
             L"X-02 the candidate finding still says what was skipped");
    s.expect(hitRawIs(candidate, "r3.enum", "r3-500"),
             L"X-07 the candidate finding links back to the raw record that produced it");
    s.expect(hitIs(candidate, "r0.enum", ObjectPresence::kAbsentInUsableView,
                   CollectionStatus::kSuccess),
             L"X-02 the candidate is still shown per view without being merged into the strong object");
    s.expect(strong != nullptr && candidate != nullptr &&
                 strong->identityKey != candidate->candidateKey,
             L"X-02 the strong key space and the candidate key space never collide");

    // The same weak identity object appears in 3 views × 2 rounds: 6 records, 1 object, but only 1 finding is added.
    {
        SampleRound weakRound;
        weakRound.sampleId = 1U;
        weakRound.sampleUtc100ns = OptionalU64::of(1000U);
        const char* viewIds[] = {"v1", "v2", "v3"};
        const char* rawIds[] = {"v1-weak", "v2-weak", "v3-weak"};
        for (int i = 0; i < 3; ++i) {
            ViewSnapshot view;
            view.viewId = viewIds[i];
            view.envelope = makeEnvelope(viewIds[i], viewIds[i], CollectionStatus::kSuccess);
            view.category = ViewEntityCategory::kProcessList;
            ViewRecord record = makeProcessRecord(666U, 0U, "suspicious.exe", rawIds[i]);
            record.process.createTime100ns = OptionalU64::unset();
            view.records = {record};
            setAccounting(view);
            weakRound.views.push_back(view);
        }
        const CrossViewReport kWeakReport = analyzeCrossView({weakRound, weakRound});
        s.expect(kWeakReport.weakIdentityRecords == 6U,
                 L"X-02 six weak record sightings are counted as six records");
        s.expect(kWeakReport.weakIdentityObjects == 1U,
                 L"X-02 the six sightings deduplicate into a single candidate object");
        s.expect(kWeakReport.findings.size() == 1U,
                 L"X-02 one weak object produces exactly one candidate finding");
        const CrossViewFinding* suspicious = findCandidate(kWeakReport, "suspicious.exe");
        s.expect(suspicious != nullptr && suspicious->latestHits.size() == 3U,
                 L"X-07 the candidate finding expands into per-view hits like any other finding");
        s.expect(hitRawIs(suspicious, "v1", "v1-weak") && hitRawIs(suspicious, "v2", "v2-weak") &&
                     hitRawIs(suspicious, "v3", "v3-weak"),
                 L"X-07 each view keeps its own raw record id for the candidate object");
        s.expect(suspicious != nullptr && suspicious->state == DiscrepancyState::kCandidateOnly,
                 L"X-02 a weak object stays a candidate no matter how many rounds agree");
    }

    // PID reuse: Different creation times for the same PID must be treated as two distinct objects.
    SampleRound reuse;
    reuse.sampleId = 1U;
    reuse.sampleUtc100ns = OptionalU64::of(1000U);
    ViewSnapshot before;
    before.viewId = "r0.enum";
    before.envelope = makeEnvelope("r0.enum", "r0.enum", CollectionStatus::kSuccess);
    before.category = ViewEntityCategory::kProcessList;
    before.records = {
        makeProcessRecord(700U, kUtcBase + 400000ULL, "short.exe", "r0-a"),
        makeProcessRecord(700U, kUtcBase + 500000ULL, "short.exe", "r0-b"),
    };
    setAccounting(before);
    reuse.views = {before};
    const CrossViewReport kReuseReport = analyzeCrossView({reuse});
    s.expect(kReuseReport.findings.size() == 2U,
             L"X-02 the same PID with two creation times stays two distinct objects");
    s.expect(kReuseReport.weakIdentityRecords == 0U,
             L"X-02 records with full lifetime identity are never counted as weak");
}

// ---------------------------------------------------------------------------
// X-03: Thread ownership and lifecycle (TID reuse)
// ---------------------------------------------------------------------------
void testThreadIdentity(ksword_tests::Suite& s) {
    // Same TID with two different creation times: TID reuse, must be two distinct objects.
    {
        SampleRound round;
        round.sampleId = 1U;
        round.sampleUtc100ns = OptionalU64::of(1000U);
        ViewSnapshot view;
        view.viewId = "r0.thread.enum";
        view.envelope = makeEnvelope("r0.thread.enum", "r0.thread", CollectionStatus::kSuccess);
        view.category = ViewEntityCategory::kThreadList;
        view.records = {
            makeThreadRecord(2000U, kUtcBase + 100000ULL, 4001U, kUtcBase + 110000ULL, "r0-t-first"),
            makeThreadRecord(2000U, kUtcBase + 100000ULL, 4001U, kUtcBase + 900000ULL, "r0-t-second"),
        };
        setAccounting(view);
        round.views = {view};
        const CrossViewReport kReport = analyzeCrossView({round});
        s.expect(kReport.findings.size() == 2U,
                 L"X-03 the same TID with two creation times stays two distinct thread instances");
        s.expect(kReport.findings[0].state == DiscrepancyState::kNoDiscrepancy &&
                     kReport.findings[1].state == DiscrepancyState::kNoDiscrepancy,
                 L"X-03 TID reuse alone is never a discrepancy");
    }

    // Same TID attached to a **new process instance** of the same PID: different process creation times mean they are not the same thread.
    {
        std::vector<SampleRound> rounds;
        for (std::uint64_t i = 0; i < 3U; ++i) {
            SampleRound round;
            round.sampleId = i + 1U;
            round.sampleUtc100ns = OptionalU64::of(1000U * (i + 1U));

            ViewSnapshot r0;
            r0.viewId = "r0.thread.enum";
            r0.envelope = makeEnvelope("r0.thread.enum", "r0.thread", CollectionStatus::kSuccess);
            r0.category = ViewEntityCategory::kThreadList;
            ViewSnapshot r3;
            r3.viewId = "r3.thread.snapshot";
            r3.envelope =
                makeEnvelope("r3.thread.snapshot", "r3.thread", CollectionStatus::kSuccess);
            r3.category = ViewEntityCategory::kThreadList;

            // The first two rounds use threads from the old process instance; the last round reuses the PID with the new process instance.
            const std::uint64_t kProcessCreate =
                (i < 2U) ? (kUtcBase + 100000ULL) : (kUtcBase + 700000ULL);
            const std::uint64_t kThreadCreate =
                (i < 2U) ? (kUtcBase + 110000ULL) : (kUtcBase + 710000ULL);
            r0.records = {makeThreadRecord(2000U, kProcessCreate, 5001U, kThreadCreate, "r0-t5001")};
            r3.records = {makeThreadRecord(2000U, kProcessCreate, 5001U, kThreadCreate, "r3-t5001")};
            setAccounting(r0);
            setAccounting(r3);
            round.views = {r0, r3};
            rounds.push_back(round);
        }
        const CrossViewReport kReport = analyzeCrossView(rounds);
        s.expect(kReport.findings.size() == 2U,
                 L"X-03 a reused TID under a new process instance is a second object, not the same one");
        for (const CrossViewFinding& finding : kReport.findings) {
            s.expect(finding.state != DiscrepancyState::kPersistent,
                     L"X-03 a lifecycle race is never escalated into a confirmed hidden thread");
            s.expect(finding.conclusion != AnalysisConclusion::kDifferenceObserved,
                     L"X-03 neither thread instance is reported as an observed difference");
        }
    }
}

// ---------------------------------------------------------------------------
// X-07 / F-05: Evidence is traceable; state and conclusions are not contradictory.
// ---------------------------------------------------------------------------
void testTraceabilityAndInvariants(ksword_tests::Suite& s) {
    // latestHits must come from the **last round**: hits from the first round cannot masquerade as the latest state.
    SampleRound r1 = makeBaselineRound(1U, 1000U);
    SampleRound r2 = makeBaselineRound(2U, 2000U);
    SampleRound r3 = makeBaselineRound(3U, 3000U);
    removeRecordFromView(r2, "r3.toolhelp", "r3-2000");
    removeRecordFromView(r3, "r3.toolhelp", "r3-2000");
    failView(r3, "ui.processTable", CollectionStatus::kAccessDenied);
    const CrossViewReport kReport = analyzeCrossView({r1, r2, r3});

    const CrossViewFinding* worker = findStrong(kReport, "worker.exe");
    s.expect(hitIs(worker, "r3.toolhelp", ObjectPresence::kAbsentInUsableView,
                   CollectionStatus::kSuccess),
             L"X-07 the latest hits describe the last round, not the first");
    s.expect(hitIs(worker, "ui.processTable", ObjectPresence::kUnknownViewFailed,
                   CollectionStatus::kAccessDenied),
             L"X-07 a view that failed only in the last round shows that failure in the latest hits");
    s.expect(worker != nullptr && worker->recheckHistory.size() == 2U,
             L"X-07 the recheck history starts at the first discrepancy round");
    s.expect(worker != nullptr && !worker->recheckHistory.empty() &&
                 worker->recheckHistory[0].hits.size() == 3U,
             L"X-07 the first discrepancy round keeps its own per-view hits");
    s.expect(worker != nullptr && !worker->recheckHistory.empty() &&
                 worker->recheckHistory[0].hits[1].viewId == "r0.process.enum" &&
                 worker->recheckHistory[0].hits[1].rawRecordId == "r0-2000",
             L"X-07 an earlier round still links back to the raw record it reported");
    s.expect(worker != nullptr && worker->firstSeenViewId == "r3.toolhelp" &&
                 worker->firstSeenRawRecordId == "r3-2000",
             L"X-07 the finding names the first source record that ever reported the object");

    for (const CrossViewFinding& finding : kReport.findings) {
        s.expect(stateConclusionConsistent(finding.state, finding.conclusion),
                 L"F-05 no finding pairs a state with a contradictory conclusion");
        s.expect(finding.latestHits.size() == kReport.viewCount,
                 L"X-01 every finding covers the whole view union exactly once");
        s.expect(finding.independentSourceGroupCount <= finding.latestHits.size(),
                 L"X-01 a finding never claims more independent sources than it has views");
    }
    s.expect(kReport.selfCheckPassed,
             L"X-01 the report's own consistency check passes on a normal run");

    // The mapping from state to conclusion must be explicit and cannot be inferred from a default-constructed envelope.
    s.expect(!stateConclusionConsistent(DiscrepancyState::kPersistent,
                                        AnalysisConclusion::kNoEvidence),
             L"F-05 persistent plus no-evidence is rejected as contradictory");
    s.expect(!stateConclusionConsistent(DiscrepancyState::kObjectEnded,
                                        AnalysisConclusion::kNoDifferenceObserved),
             L"F-05 object-ended plus no-difference-observed is rejected as contradictory");
    s.expect(!stateConclusionConsistent(DiscrepancyState::kUnverifiable,
                                        AnalysisConclusion::kDifferenceObserved),
             L"F-05 unverifiable plus difference-observed is rejected as contradictory");
    s.expect(stateConclusionConsistent(DiscrepancyState::kPersistent,
                                       AnalysisConclusion::kDifferenceObserved),
             L"F-05 persistent plus difference-observed is the only allowed pairing");
}

// ---------------------------------------------------------------------------
// X-02: Candidate edges between weak records and strong objects (neither merged nor discarded).
// ---------------------------------------------------------------------------
void testCandidateLinks(ksword_tests::Suite& s) {
    // One view provides full identity (including creation time), while another view with the same PID cannot retrieve the creation time.
    // Expectation: Two independent findings (never merged), each holding a Candidate edge to the other.
    SampleRound round;
    round.sampleId = 1U;
    round.sampleUtc100ns = OptionalU64::of(kUtcBase);

    ViewSnapshot strongView;
    strongView.viewId = "r0.enum";
    strongView.category = ViewEntityCategory::kProcessList;
    strongView.envelope = makeEnvelope("r0.enum", "r0.enum", CollectionStatus::kSuccess);
    strongView.records = { makeProcessRecord(4242U, kUtcBase + 500ULL, "svc.exe", "r0-4242") };
    setAccounting(strongView);

    ViewSnapshot weakView;
    weakView.viewId = "r3.enum";
    weakView.category = ViewEntityCategory::kProcessList;
    weakView.envelope = makeEnvelope("r3.enum", "r3.enum", CollectionStatus::kSuccess);
    ViewRecord weakRecord = makeProcessRecord(4242U, 0U, "svc.exe", "r3-4242");
    weakRecord.process.createTime100ns = OptionalU64::unset();
    weakView.records = { weakRecord };
    setAccounting(weakView);

    round.views = { strongView, weakView };
    const CrossViewReport kReport = analyzeCrossView({ round });

    s.expect(kReport.findings.size() == 2U,
             L"X-02 a weak record and a strong object stay two separate findings");
    s.expect(kReport.weakIdentityObjects == 1U && kReport.candidateLinkCount == 1U,
             L"X-02 exactly one candidate link is built for the one weak object");

    const CrossViewFinding* weakFinding = nullptr;
    const CrossViewFinding* strongFinding = nullptr;
    for (const CrossViewFinding& f : kReport.findings) {
        if (f.identityKey.empty()) {
            weakFinding = &f;
        } else {
            strongFinding = &f;
        }
    }
    s.expect(weakFinding != nullptr && strongFinding != nullptr,
             L"X-02 one finding is weak and the other carries a cross-session key");
    if (weakFinding == nullptr || strongFinding == nullptr) {
        return;
    }

    s.expect(weakFinding->state == DiscrepancyState::kCandidateOnly,
             L"X-02 the weak finding stays candidate-only and never escalates");
    s.expect(weakFinding->candidateLinks.size() == 1U &&
                 weakFinding->candidateLinks[0].strongIdentityKey == strongFinding->identityKey,
             L"X-02 the weak finding points at the strong object it may correspond to");
    s.expect(weakFinding->candidateLinks[0].match == MatchResult::kCandidate,
             L"X-02 a link involving a weak identity is never Confirmed");
    s.expect(weakFinding->candidateLinks[0].basis.find("pid=4242") != std::string::npos,
             L"X-02 the link states which field carried it");
    s.expect(strongFinding->candidateLinks.size() == 1U &&
                 strongFinding->candidateLinks[0].strongIdentityKey == weakFinding->candidateKey,
             L"X-02 the strong object carries the reverse link back to the weak record");

    // Counterexample 1: Same PID but different creation time — this is PID reuse. Match* returns NoMatch; do not create an edge.
    {
        SampleRound reuse = round;
        ViewRecord other = makeProcessRecord(4242U, kUtcBase + 900000ULL, "svc.exe", "r3-other");
        reuse.views[1].records = { other };
        const CrossViewReport kReuseReport = analyzeCrossView({ reuse });
        s.expect(kReuseReport.candidateLinkCount == 0U,
                 L"X-02 a reused PID with a different creation time gets no candidate link");
        s.expect(kReuseReport.findings.size() == 2U,
                 L"X-02 the reused PID still stays two distinct objects");
    }

    // Counterexample 2: Different PIDs — different buckets, so no edge is allowed.
    {
        SampleRound other = round;
        ViewRecord unrelated = makeProcessRecord(9999U, 0U, "other.exe", "r3-9999");
        unrelated.process.createTime100ns = OptionalU64::unset();
        other.views[1].records = { unrelated };
        const CrossViewReport kOtherReport = analyzeCrossView({ other });
        s.expect(kOtherReport.candidateLinkCount == 0U,
                 L"X-02 a different PID gets no candidate link");
    }
}

} // namespace

int runCrossViewTests() {
    ksword_tests::Suite suite(L"X cross-view");
    testSourceIndependence(suite);
    testCrossRoundCensus(suite);
    testFailureIsNotAbsence(suite);
    testResampleClassification(suite);
    testReplayablePositives(suite);
    testEntityCategories(suite);
    testIdentityGuards(suite);
    testThreadIdentity(suite);
    testTraceabilityAndInvariants(suite);
    testCandidateLinks(suite);
    suite.report();
    return suite.failures();
}

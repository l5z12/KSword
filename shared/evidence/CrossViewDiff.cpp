#include "CrossViewDiff.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace ksword::evidence {
namespace {

// The primary key separator does not appear in paths, GUIDs, or numbers to avoid key collisions between "a|b" and "a" + "|b".
constexpr char kSep = '\x1F';

const std::string& groupOf(const SourceRef& source) {
    return source.sourceGroup.empty() ? source.collectorId : source.sourceGroup;
}

std::uint32_t categoryBit(ViewEntityCategory category) noexcept {
    return static_cast<std::uint32_t>(1U) << static_cast<unsigned>(category);
}

// X-04: A view category is qualified to perform missing-item inference on an object only if that object has previously been listed by a view of this category.
// A boot-start driver appearing in the loaded module list but legitimately absent from the device object tree is a structural difference,
// not a discrepancy. Conversely, missing entries between process lists (of the same category) are what cross-view analysis must explain.
bool categoryComparable(std::uint32_t homeMask, ViewEntityCategory category) noexcept {
    return (homeMask & categoryBit(category)) != 0U;
}

// X-06: Positive evidence for the account. A CoverageAccount with all fields defaulting only indicates 'no failure recorded,'
// not 'enumeration completed.' Treating it as full coverage effectively grants 'confirmation of missing data' for free.
bool coverageProvesCompleteness(const CoverageAccount& coverage) noexcept {
    if (coverage.limitHit || coverage.cancelled) {
        return false;  // Early termination: remaining items have not been examined.
    }
    // (a) Counting criteria: the total is declared, and all have been obtained.
    if (coverage.totalKnown.present && coverage.succeeded >= coverage.totalKnown.value) {
        return true;
    }
    // (b) Scope alignment: All four endpoints must be present, and the processed range must fully cover the
    //     requested range. If any endpoint is missing, boundary validation is impossible, and the result is invalid.
    if (coverage.requestedBegin.present && coverage.requestedEnd.present &&
        coverage.processedBegin.present && coverage.processedEnd.present) {
        return coverage.processedBegin.value <= coverage.requestedBegin.value &&
               coverage.processedEnd.value >= coverage.requestedEnd.value;
    }
    return false;  // No account entries filled = unknown override ≠ complete override.
}

// X-06: The account record count does not match the actual returned records, indicating this collector has silently corrupted
// (typical symptoms: status=Success, succeeded=500, records=0). For this view, "not listed" does not mean "does not exist"; it must
// be downgraded to unknown, otherwise it will continuously displace normal objects into persistent differences over several rounds.
bool viewAccountMatchesRecords(const ViewSnapshot& view) noexcept {
    const CoverageAccount& coverage = view.envelope.coverage;
    const std::uint64_t kRecords = static_cast<std::uint64_t>(view.records.size());
    if (coverage.succeeded > kRecords) {
        return false;
    }
    if (coverage.totalKnown.present && coverage.totalKnown.value > kRecords) {
        return false;
    }
    return true;
}

// Whether a view is qualified this round to infer 'non-existence' based on 'not listed'.
bool viewUsableForAbsenceInRound(const ViewSnapshot& view) noexcept {
    return viewUsableForAbsence(view.envelope, view.coversTargetScope) &&
           viewAccountMatchesRecords(view);
}

// Aggregated state of each object in a round.
// Invariant: presentViews + usableAbsentViews + unusableViews + crossCategoryViews == hits.size()
struct RoundState final {
    std::size_t presentViews = 0;
    std::size_t usableAbsentViews = 0;
    std::size_t unusableViews = 0;
    std::size_t crossCategoryViews = 0;
    std::vector<ViewHit> hits;
};

struct ObjectEntry final {
    bool initialized = false;
    bool weak = false;                 // X-02: Insufficient identity; retain only a candidate relationship.
    // The first source record mapped to this object. Keep it to call ObjectIdentity Match*
    // functions when building candidate edges: those functions take typed identities, not string
    // keys. The record lives in the caller's rounds for the entire analyzeCrossView call.
    const ViewRecord* representative = nullptr;
    ObjectKind kind = ObjectKind::kUnknown;
    IdentityStrength strength = IdentityStrength::kUnusable;
    std::string identityKey;
    std::string candidateKey;
    std::string displayText;
    std::uint32_t homeMask = 0;        // X-04: Set of view categories that previously listed this object.
    std::string firstSeenViewId;
    std::string firstSeenRawRecordId;
    std::size_t firstSeenRoundIndex = 0;
    // X-06 / BLOCKER: Views that previously reported this object. The 'object ended' judgment must be supported by all
    // these witness views being available in this round and no longer listing it; timed-out witness views do not count.
    std::vector<std::string> everPresentViews;
    std::vector<RoundState> perRound;
};

// An index for (round, view) records: each record is counted only once per identityKey/candidateKey.
// X-09: Without this table, Step 3 becomes O(rounds × objects × views × records), and each comparison requires reconstructing
// a std::string. With 4000 objects, this takes 13 seconds, making a 10-minute sampling window impossible to complete.
struct ViewIndex final {
    const ViewSnapshot* view = nullptr;
    std::unordered_map<std::string, const ViewRecord*> byKey;
};

void appendKeyField(std::string& key, const std::string& value) {
    key.push_back(kSep);
    key.append(value);
}

void appendKeyField(std::string& key, const OptionalU64& value) {
    key.push_back(kSep);
    if (value.present) {
        key.append(formatU64(value.value, U64Format::kDecimal));
    }
}

// Analysis key: Strong identities use "S" + cross-session primary key; weak identities use "W" + candidate key. The two key
// spaces must be separated; otherwise, weak candidates would collide with strong objects, causing the forbidden mis-merge X-02.
std::string makeAnalysisKey(const std::string& identity, const std::string& candidate) {
    std::string key;
    const bool kWeak = identity.empty();
    const std::string& body = kWeak ? candidate : identity;
    key.reserve(body.size() + 2U);
    key.push_back(kWeak ? 'W' : 'S');
    key.push_back(kSep);
    key.append(body);
    return key;
}

bool containsView(const std::vector<std::string>& list, const std::string& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

// X-04: folds per-view hits of a round into cardinality facts of 'how many views are listed/unlisted per category'.
std::vector<CategoryObservation> buildCategoryObservations(const RoundState& state,
                                                           std::uint32_t homeMask) {
    std::vector<CategoryObservation> result;
    for (const ViewHit& hit : state.hits) {
        auto found = std::find_if(result.begin(), result.end(),
                                  [&hit](const CategoryObservation& observation) {
                                      return observation.category == hit.category;
                                  });
        if (found == result.end()) {
            CategoryObservation observation;
            observation.category = hit.category;
            observation.comparable = categoryComparable(homeMask, hit.category);
            result.push_back(observation);
            found = result.end() - 1;
        }
        ++found->viewsInCategory;
        if (hit.presence == ObjectPresence::kPresent) {
            ++found->viewsListing;
        } else if (hit.presence == ObjectPresence::kAbsentInUsableView) {
            ++found->usableViewsNotListing;
        }
    }
    return result;
}

// X-02: Bucket key for candidate edges. Weak records and strong objects are only worth pairwise comparison if they fall into the
// same bucket—otherwise it becomes O(weak × strong). The bucket key uses only fields that are 'necessarily present on both sides
// and almost never identical across different objects': PID for processes/handles, TID for threads, and image path for drivers.
// Identical bucket keys do not imply the same object; the actual determination is delegated to ObjectIdentity's Match*.
std::string linkBucketKey(const ViewRecord& record) {
    std::string key(1, static_cast<char>(record.kind));
    switch (record.kind) {
    case ObjectKind::kProcess:
        appendKeyField(key, record.process.pid);
        return key;
    case ObjectKind::kThread:
        appendKeyField(key, record.thread.tid);
        return key;
    case ObjectKind::kDriver:
        appendKeyField(key, record.driver.imagePath);
        return key;
    default:
        return std::string();  // No identity model at this level for other categories; do not create candidate edges.
    }
}

// X-02: Dispatch to the corresponding Match* based on type. This is the **only** place in analyzeCrossView that
// actually invokes the ObjectIdentity matcher. Strong objects are still merged via exact crossSessionKey equality
// (that is primary key semantics and must be strict); Match* is only used to find candidates for weak records.
MatchResult matchRecords(const ViewRecord& a, const ViewRecord& b) noexcept {
    if (a.kind != b.kind) {
        return MatchResult::kNoMatch;
    }
    switch (a.kind) {
    case ObjectKind::kProcess: return matchProcessInstance(a.process, b.process);
    case ObjectKind::kThread:  return matchThreadInstance(a.thread, b.thread);
    case ObjectKind::kDriver:  return matchDriverInstance(a.driver, b.driver);
    default:                  return MatchResult::kNoMatch;
    }
}

// Explain the basis of a candidate edge: why the identities may match and what missing evidence prevents confirmation.
std::string describeLinkBasis(const ViewRecord& weak, const ViewRecord& strong) {
    std::string basis;
    switch (weak.kind) {
    case ObjectKind::kProcess:
        basis = "pid=" + formatOptionalU64(weak.process.pid, U64Format::kDecimal);
        if (!weak.process.createTime100ns.present) {
            basis += "；弱侧缺创建时间";
        }
        if (weak.process.bootId.empty() || strong.process.bootId.empty()) {
            basis += "；缺启动标识";
        }
        break;
    case ObjectKind::kThread:
        basis = "tid=" + formatOptionalU64(weak.thread.tid, U64Format::kDecimal);
        if (!weak.thread.createTime100ns.present) {
            basis += "；弱侧缺线程创建时间";
        }
        if (weak.thread.process.strength() != IdentityStrength::kStrong) {
            basis += "；所属进程实例不完整";
        }
        break;
    case ObjectKind::kDriver:
        basis = "path=" + weak.driver.imagePath;
        if (weak.driver.pdbSignature.empty()) {
            basis += "；弱侧缺 PDB 身份";
        }
        if (!weak.driver.timeDateStamp.present || !weak.driver.imageSize.present) {
            basis += "；弱侧缺 PE 头身份";
        }
        break;
    default:
        break;
    }
    return basis;
}

// X-06: Whether all witness views (views that previously reported this object) are currently available and no longer list it.
bool witnessesAllUsablyAbsent(const RoundState& state, const std::vector<std::string>& witnesses) {
    for (const std::string& viewId : witnesses) {
        const auto kFound = std::find_if(state.hits.begin(), state.hits.end(),
                                        [&viewId](const ViewHit& hit) { return hit.viewId == viewId; });
        if (kFound == state.hits.end() || kFound->presence != ObjectPresence::kAbsentInUsableView) {
            return false;
        }
    }
    return !witnesses.empty();
}

} // namespace

const char* objectPresenceName(ObjectPresence presence) noexcept {
    switch (presence) {
    case ObjectPresence::kPresent:               return "Present";
    case ObjectPresence::kAbsentInUsableView:    return "AbsentInUsableView";
    case ObjectPresence::kUnknownViewFailed:     return "UnknownViewFailed";
    case ObjectPresence::kUnknownOutOfCoverage:  return "UnknownOutOfCoverage";
    case ObjectPresence::kNotComparableCategory: return "NotComparableCategory";
    }
    return "UnknownViewFailed";
}

const char* viewEntityCategoryName(ViewEntityCategory category) noexcept {
    switch (category) {
    case ViewEntityCategory::kUnspecified:       return "Unspecified";
    case ViewEntityCategory::kProcessList:       return "ProcessList";
    case ViewEntityCategory::kThreadList:        return "ThreadList";
    case ViewEntityCategory::kLoadedModuleList:  return "LoadedModuleList";
    case ViewEntityCategory::kDriverObjectTable: return "DriverObjectTable";
    case ViewEntityCategory::kDeviceObjectTree:  return "DeviceObjectTree";
    case ViewEntityCategory::kServiceConfig:     return "ServiceConfig";
    }
    return "Unspecified";
}

bool viewUsableForAbsence(const EvidenceEnvelope& envelope, bool coversTargetScope) noexcept {
    // Timeout, access denied, unsupported, or not collected: none of these should be treated as 'the view is confirmed absent'.
    if (envelope.outcome.status != CollectionStatus::kSuccess) {
        return false;
    }
    if (!coversTargetScope) {
        return false;
    }
    // Truncation, hitting the limit, or a single failure will change 'not listed' to 'possibly not scanned'.
    if (!envelope.coverage.fullyCovered()) {
        return false;
    }
    // X-06: Require positive evidence from the ledger again. The negation of fullyCovered() blocks "recorded
    // failures" but not "no records"—the latter also cannot be treated as confirmation of absence.
    return coverageProvesCompleteness(envelope.coverage);
}

const char* discrepancyStateName(DiscrepancyState state) noexcept {
    switch (state) {
    case DiscrepancyState::kNoDiscrepancy:  return "NoDiscrepancy";
    case DiscrepancyState::kPendingRecheck: return "PendingRecheck";
    case DiscrepancyState::kTransient:      return "Transient";
    case DiscrepancyState::kPersistent:     return "Persistent";
    case DiscrepancyState::kObjectEnded:    return "ObjectEnded";
    case DiscrepancyState::kUnverifiable:   return "Unverifiable";
    case DiscrepancyState::kCandidateOnly:  return "CandidateOnly";
    }
    return "Unverifiable";
}

bool stateConclusionConsistent(DiscrepancyState state, AnalysisConclusion conclusion) noexcept {
    switch (state) {
    case DiscrepancyState::kPersistent:
        // Since 'reached review count and always missing' is true, it is impossible to simultaneously have 'no available observations'.
        return conclusion == AnalysisConclusion::kDifferenceObserved;
    case DiscrepancyState::kNoDiscrepancy:
        return conclusion != AnalysisConclusion::kDifferenceObserved;
    case DiscrepancyState::kTransient:
        return conclusion == AnalysisConclusion::kNoDifferenceObserved ||
               conclusion == AnalysisConclusion::kIndeterminate;
    case DiscrepancyState::kObjectEnded:
        // "Object ended" explains the missing item, but it is not "sufficiently covered with no contradictions found".
        return conclusion == AnalysisConclusion::kIndeterminate ||
               conclusion == AnalysisConclusion::kNoEvidence;
    case DiscrepancyState::kPendingRecheck:
    case DiscrepancyState::kUnverifiable:
    case DiscrepancyState::kCandidateOnly:
        return conclusion == AnalysisConclusion::kIndeterminate ||
               conclusion == AnalysisConclusion::kNoEvidence;
    }
    return false;
}

std::string ViewRecord::identityKey() const {
    switch (kind) {
    case ObjectKind::kProcess: return process.crossSessionKey();
    case ObjectKind::kThread:  return thread.crossSessionKey();
    case ObjectKind::kDriver:  return driver.crossSessionKey();
    default:                  return std::string();
    }
}

std::string ViewRecord::candidateKey() const {
    // X-02: All identifiers used here are "reusable," so they can only be used within this analysis session to consolidate multiple
    // copies of the same weak record into a single candidate object. They must never be used to assert object identity across sessions.
    std::string key;
    switch (kind) {
    case ObjectKind::kProcess:
        key = "cand-proc";
        appendKeyField(key, process.bootId);
        appendKeyField(key, process.pid);
        appendKeyField(key, process.imageName);
        break;
    case ObjectKind::kThread:
        key = "cand-thread";
        appendKeyField(key, thread.process.bootId);
        appendKeyField(key, thread.process.pid);
        appendKeyField(key, thread.tid);
        appendKeyField(key, thread.process.imageName);
        break;
    case ObjectKind::kDriver:
        key = "cand-driver";
        appendKeyField(key, driver.bootId);
        appendKeyField(key, driver.imagePath);
        appendKeyField(key, driver.pdbSignature);
        break;
    default:
        // No kind field: must retain by raw record ID at least to allow the report to return to that line (X-07).
        key = "cand-raw";
        appendKeyField(key, rawRecordId);
        break;
    }
    return key;
}

IdentityStrength ViewRecord::strength() const noexcept {
    switch (kind) {
    case ObjectKind::kProcess: return process.strength();
    case ObjectKind::kThread:  return thread.strength();
    case ObjectKind::kDriver:  return driver.strength();
    default:                  return IdentityStrength::kUnusable;
    }
}

std::string ViewRecord::displayText() const {
    switch (kind) {
    case ObjectKind::kProcess:
        return process.imageName + " (" + formatOptionalU64(process.pid, U64Format::kDecimal) + ")";
    case ObjectKind::kThread:
        return "TID " + formatOptionalU64(thread.tid, U64Format::kDecimal) + " @ " +
               thread.process.imageName;
    case ObjectKind::kDriver:
        return driver.imagePath;
    default:
        // X-07: Even without an identity, we must be able to state what was skipped; we cannot leave just an integer.
        return rawRecordId.empty() ? std::string() : ("raw:" + rawRecordId);
    }
}

CrossViewReport analyzeCrossView(const std::vector<SampleRound>& rounds,
                                 const CrossViewOptions& options) {
    CrossViewReport report;
    report.roundCount = rounds.size();
    if (rounds.empty()) {
        return report;
    }

    // -----------------------------------------------------------------------
    // 1) Cross-**all rounds** census: view union, actual view count per round, and independent source group count per round.
    //    X-01: Sources that appear only in round 1 and then crash cannot contribute to trustworthiness. Thus, the
    //    source group count is the minimum of the independent group counts per round, and the view set is the union
    //    (absent rounds explicitly produce NotCollected in step 3, rather than being treated as 'clean this round').
    // -----------------------------------------------------------------------
    std::vector<EvidenceEnvelope> allEnvelopes;
    std::vector<std::string> unionViewIds;
    std::vector<ViewEntityCategory> unionViewCategories;  // Same order as unionViewIds.
    std::size_t minGroupCount = 0;
    std::size_t minRoundViewCount = 0;
    bool firstRound = true;

    for (const SampleRound& round : rounds) {
        std::vector<std::string> roundViewIds;
        std::vector<std::string> roundGroups;
        for (const ViewSnapshot& view : round.views) {
            if (containsView(roundViewIds, view.viewId)) {
                continue;  // Within a round, accept only the first occurrence of a viewId; duplicates do not count as separate views.
            }
            roundViewIds.push_back(view.viewId);
            allEnvelopes.push_back(view.envelope);
            const std::string& group = groupOf(view.envelope.source);
            if (!containsView(roundGroups, group)) {
                roundGroups.push_back(group);
            }
            const auto kFound = std::find(unionViewIds.begin(), unionViewIds.end(), view.viewId);
            if (kFound == unionViewIds.end()) {
                unionViewIds.push_back(view.viewId);
                unionViewCategories.push_back(view.category);
            } else {
                unionViewCategories[static_cast<std::size_t>(kFound - unionViewIds.begin())] =
                    view.category;
            }
        }
        if (firstRound) {
            minGroupCount = roundGroups.size();
            minRoundViewCount = roundViewIds.size();
            firstRound = false;
        } else {
            minGroupCount = (std::min)(minGroupCount, roundGroups.size());
            minRoundViewCount = (std::min)(minRoundViewCount, roundViewIds.size());
        }
        report.latestRoundViewCount = roundViewIds.size();  // After the loop ends, this is the last round.
    }

    report.viewCount = unionViewIds.size();
    report.minRoundViewCount = minRoundViewCount;
    report.independentSourceGroupCount = minGroupCount;

    // Trust statement takes envelopes from **all rounds**: AccessDenied and hit-limit conditions from the final
    // round must not disappear from the restriction statement just because "Round 1 was clean" (X-01/F-11).
    report.trust = buildTrustStatement(allEnvelopes);
    // - buildTrustStatement counts by envelope entries (here, rounds × view count). For the X module, the correct metric is "distinct views" and
    // "independent sources present in every round"; therefore, these two fields are overwritten and the corresponding limitation items are recalculated.
    report.trust.viewCount = report.viewCount;
    report.trust.independentSourceGroupCount = report.independentSourceGroupCount;
    report.trust.limitationKeys.erase(
        std::remove(report.trust.limitationKeys.begin(), report.trust.limitationKeys.end(),
                    std::string("trust.limitation.singleSourceGroup")),
        report.trust.limitationKeys.end());
    if (report.trust.independentSourceGroupCount <= 1U && report.trust.viewCount > 1U) {
        report.trust.limitationKeys.insert(report.trust.limitationKeys.begin(),
                                           "trust.limitation.singleSourceGroup");
    }

    // -----------------------------------------------------------------------
    // 2) Build object set + per (round, view) record index (X-09: identityKey counted only once per entry).
    //    Records with insufficient identity are no longer discarded: they enter an independent candidate
    //    key space, and the report retains kind, displayText, rawRecordId, and per-view hits (X-02/X-07).
    // -----------------------------------------------------------------------
    std::unordered_map<std::string, ObjectEntry> objects;
    std::vector<std::unordered_map<std::string, ViewIndex>> roundIndex(rounds.size());

    for (std::size_t roundIndexNo = 0; roundIndexNo < rounds.size(); ++roundIndexNo) {
        const SampleRound& round = rounds[roundIndexNo];
        std::unordered_map<std::string, ViewIndex>& index = roundIndex[roundIndexNo];
        for (const ViewSnapshot& view : round.views) {
            const auto kInserted = index.try_emplace(view.viewId);
            if (!kInserted.second) {
                continue;  // As in step 1, accept only the first occurrence of each viewId in the same round.
            }
            ViewIndex& viewIndex = kInserted.first->second;
            viewIndex.view = &view;
            viewIndex.byKey.reserve(view.records.size());
            for (const ViewRecord& record : view.records) {
                const std::string kIdentity = record.identityKey();
                const bool kWeak = kIdentity.empty();
                std::string analysisKey =
                    makeAnalysisKey(kIdentity, kWeak ? record.candidateKey() : std::string());
                viewIndex.byKey.emplace(analysisKey, &record);
                if (kWeak) {
                    ++report.weakIdentityRecords;
                }
                ObjectEntry& entry = objects[analysisKey];
                if (!entry.initialized) {
                    entry.initialized = true;
                    entry.weak = kWeak;
                    entry.representative = &record;
                    entry.kind = record.kind;
                    entry.strength = record.strength();
                    entry.identityKey = kIdentity;
                    entry.candidateKey = kWeak ? record.candidateKey() : std::string();
                    entry.displayText = record.displayText();
                    entry.firstSeenViewId = view.viewId;
                    entry.firstSeenRawRecordId = record.rawRecordId;
                    entry.firstSeenRoundIndex = roundIndexNo;
                    entry.perRound.resize(rounds.size());
                    if (kWeak) {
                        ++report.weakIdentityObjects;
                    }
                }
                entry.homeMask |= categoryBit(view.category);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3) Determine existence per round and per view by iterating over the **view union**.
    //    X-06 / F-05: Views that exist in the union but are entirely absent in this round (collector crashed,
    //    driver unloaded, or no NotCollected envelope was sent) must produce a NotCollected hit and be counted
    //    in unusableViews. A view that was never collected cannot be used to infer 'no differences found'.
    // -----------------------------------------------------------------------
    for (std::size_t roundNo = 0; roundNo < rounds.size(); ++roundNo) {
        const std::unordered_map<std::string, ViewIndex>& index = roundIndex[roundNo];
        for (auto& item : objects) {
            const std::string& analysisKey = item.first;
            ObjectEntry& entry = item.second;
            RoundState& state = entry.perRound[roundNo];
            state.hits.reserve(unionViewIds.size());
            for (std::size_t viewNo = 0; viewNo < unionViewIds.size(); ++viewNo) {
                ViewHit hit;
                hit.viewId = unionViewIds[viewNo];
                const auto kViewIt = index.find(unionViewIds[viewNo]);
                if (kViewIt == index.end()) {
                    // Full-round absence: sourceGroup is unknown in this round, leave empty; status is 'never collected'.
                    hit.presence = ObjectPresence::kUnknownViewFailed;
                    hit.viewStatus = CollectionStatus::kNotCollected;
                    hit.category = unionViewCategories[viewNo];
                    ++state.unusableViews;
                    state.hits.push_back(std::move(hit));
                    continue;
                }
                const ViewSnapshot& view = *kViewIt->second.view;
                hit.sourceGroup = groupOf(view.envelope.source);
                hit.viewStatus = view.envelope.outcome.status;
                hit.category = view.category;

                const auto kRecordIt = kViewIt->second.byKey.find(analysisKey);
                if (kRecordIt != kViewIt->second.byKey.end()) {
                    hit.presence = ObjectPresence::kPresent;
                    hit.rawRecordId = kRecordIt->second->rawRecordId;
                    ++state.presentViews;
                    if (!containsView(entry.everPresentViews, hit.viewId)) {
                        entry.everPresentViews.push_back(hit.viewId);
                    }
                } else if (!categoryComparable(entry.homeMask, view.category)) {
                    // X-04: The view of another entity class did not list it; this is a structural phenomenon, not a missing item.
                    hit.presence = ObjectPresence::kNotComparableCategory;
                    ++state.crossCategoryViews;
                } else if (viewUsableForAbsenceInRound(view)) {
                    hit.presence = ObjectPresence::kAbsentInUsableView;
                    ++state.usableAbsentViews;
                } else if (view.envelope.outcome.status == CollectionStatus::kSuccess ||
                           view.envelope.outcome.status == CollectionStatus::kPartial) {
                    hit.presence = ObjectPresence::kUnknownOutOfCoverage;
                    ++state.unusableViews;
                } else {
                    hit.presence = ObjectPresence::kUnknownViewFailed;
                    ++state.unusableViews;
                }
                state.hits.push_back(std::move(hit));
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3.5) X-02: Create edges for weak identity records pointing to "candidate strong objects".
    //
    // The specification requires retaining candidate relationships when identity is insufficient. Previously, weak records resulted in a single
    // isolated CandidateOnly finding, making it unclear in the report which confirmed object it might correspond to; however, merging them backward
    // constitutes the prohibited false merge X-02. Therefore, we create **explicit candidate edges**: the judgment follows ObjectIdentity's Match*
    // logic, and the unified identity threshold ensures results are at most Candidate, while NoMatch pairs are not recorded.
    //
    // Complexity: First bucket by PID/TID/image path, then perform pairwise comparison only within the same bucket. Buckets
    // typically contain only one or two members, resulting in O(strong + weak) complexity rather than O(weak × strong).
    // -----------------------------------------------------------------------
    std::unordered_map<std::string, std::vector<CandidateLink>> linksByAnalysisKey;
    {
        std::unordered_map<std::string, std::vector<const std::pair<const std::string, ObjectEntry>*>> strongBuckets;
        for (const auto& item : objects) {
            const ObjectEntry& entry = item.second;
            if (entry.weak || entry.representative == nullptr) {
                continue;
            }
            const std::string kBucket = linkBucketKey(*entry.representative);
            if (kBucket.empty()) {
                continue;
            }
            strongBuckets[kBucket].push_back(&item);
        }

        for (const auto& item : objects) {
            const ObjectEntry& weakEntry = item.second;
            if (!weakEntry.weak || weakEntry.representative == nullptr) {
                continue;
            }
            const std::string kBucket = linkBucketKey(*weakEntry.representative);
            if (kBucket.empty()) {
                continue;
            }
            const auto kFound = strongBuckets.find(kBucket);
            if (kFound == strongBuckets.end()) {
                continue;
            }
            for (const auto* strongItem : kFound->second) {
                const ObjectEntry& strongEntry = strongItem->second;
                if (strongEntry.representative == nullptr) {
                    continue;
                }
                const MatchResult kVerdict =
                    matchRecords(*weakEntry.representative, *strongEntry.representative);
                if (kVerdict == MatchResult::kNoMatch) {
                    continue;
                }
                CandidateLink link;
                link.strongIdentityKey = strongEntry.identityKey;
                // The unified identity threshold ensures that matches involving the weak side cannot be Confirmed; this additional
                // check prevents future threshold relaxations from quietly upgrading the relationship to Confirmed here.
                link.match = MatchResult::kCandidate;
                link.basis = describeLinkBasis(*weakEntry.representative, *strongEntry.representative);
                linksByAnalysisKey[item.first].push_back(link);

                CandidateLink back;
                back.strongIdentityKey = weakEntry.candidateKey;
                back.match = MatchResult::kCandidate;
                back.basis = link.basis;
                linksByAnalysisKey[strongItem->first].push_back(back);
                ++report.candidateLinkCount;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 4) State machine: initial miss -> resampling -> classification -> conclusion (within the same evidence window as the state).
    // -----------------------------------------------------------------------
    const std::size_t kLastRound = rounds.size() - 1U;
    for (auto& item : objects) {
        ObjectEntry& entry = item.second;
        CrossViewFinding finding;
        finding.kind = entry.kind;
        finding.identityKey = entry.identityKey;
        finding.candidateKey = entry.candidateKey;
        finding.strength = entry.strength;
        finding.displayText = entry.displayText;
        finding.viewCount = unionViewIds.size();
        finding.independentSourceGroupCount = report.independentSourceGroupCount;
        finding.latestRoundViewCount = report.latestRoundViewCount;
        finding.latestHits = entry.perRound[kLastRound].hits;
        finding.latestCategories = buildCategoryObservations(entry.perRound[kLastRound], entry.homeMask);
        finding.firstSeenViewId = entry.firstSeenViewId;
        finding.firstSeenRawRecordId = entry.firstSeenRawRecordId;
        finding.firstSeenRoundIndex = entry.firstSeenRoundIndex;
        {
            const auto kLinks = linksByAnalysisKey.find(item.first);
            if (kLinks != linksByAnalysisKey.end()) {
                finding.candidateLinks = kLinks->second;
            }
        }

        // Round of first discrepancy: some views see it while other available views do not.
        std::size_t firstDiscrepancy = rounds.size();
        for (std::size_t i = 0; i < rounds.size(); ++i) {
            const RoundState& state = entry.perRound[i];
            if (state.presentViews > 0U && state.usableAbsentViews > 0U) {
                firstDiscrepancy = i;
                break;
            }
        }

        OptionalU64 firstUtc;
        if (firstDiscrepancy < rounds.size()) {
            firstUtc = rounds[firstDiscrepancy].sampleUtc100ns;
            for (std::size_t i = firstDiscrepancy; i < rounds.size(); ++i) {
                const RoundState& state = entry.perRound[i];
                RecheckEntry recheck;
                recheck.sampleId = rounds[i].sampleId;
                recheck.sampleUtc100ns = rounds[i].sampleUtc100ns;
                if (firstUtc.present && rounds[i].sampleUtc100ns.present) {
                    // X-05: Unsigned naked subtraction encountering an NTP step-back will wrap around to an astronomical number (≈5.8e13 years) and
                    // appear as a valid interval. First compare values; if a step-back is detected, explicitly mark it and keep the value unset.
                    if (rounds[i].sampleUtc100ns.value >= firstUtc.value) {
                        recheck.intervalFromFirst100ns =
                            OptionalU64::of(rounds[i].sampleUtc100ns.value - firstUtc.value);
                    } else {
                        recheck.clockWentBackwards = true;
                    }
                }
                recheck.presentViews = state.presentViews;
                recheck.usableAbsentViews = state.usableAbsentViews;
                recheck.unusableViews = state.unusableViews;
                recheck.crossCategoryViews = state.crossCategoryViews;
                recheck.hits = state.hits;  // X-07: Unwind per-view hits and source record IDs in each round.
                finding.recheckHistory.push_back(std::move(recheck));
            }
        }

        std::size_t classificationRound = kLastRound;
        if (entry.weak) {
            // X-02: Objects with insufficient identity retain only candidate relationships and are prohibited from participating in any discrepancy upgrades.
            finding.state = DiscrepancyState::kCandidateOnly;
            classificationRound = kLastRound;
        } else if (firstDiscrepancy == rounds.size()) {
            finding.state = DiscrepancyState::kNoDiscrepancy;
        } else {
            const std::size_t kAvailableRecheckRounds = rounds.size() - firstDiscrepancy - 1U;
            bool reappeared = false;
            bool objectEnded = false;
            std::size_t usableRecheckRounds = 0;
            std::size_t persistentRounds = 0;

            for (std::size_t i = firstDiscrepancy + 1U; i < rounds.size(); ++i) {
                const RoundState& state = entry.perRound[i];
                if (state.presentViews == 0U && state.usableAbsentViews == 0U) {
                    // No view is qualified to judge in this round (including the case where no view exists in this round).
                    // We cannot require unusableViews > 0 here: an empty round with zero views results in all three counters being
                    // 0, which would count as a valid recheck and degrade the threshold check into a redundant branch (X-05).
                    continue;
                }
                ++usableRecheckRounds;
                if (state.presentViews > 0U && state.usableAbsentViews == 0U) {
                    reappeared = true;
                    classificationRound = i;
                    break;
                }
                if (objectEnded) {
                    continue;  // Already determined as ended; subsequent checks only look for reappearances.
                }
                if (state.presentViews == 0U && state.usableAbsentViews > 0U) {
                    // X-06 / BLOCKER: The fact that a view previously seen has timed out this round does not mean it is gone.
                    // Only mark 'object ended' if no views are unjudgable in this round AND all witness views are
                    // usable and no longer list it; otherwise, treat as 'unable to re-verify' for this round.
                    if (state.unusableViews == 0U &&
                        witnessesAllUsablyAbsent(state, entry.everPresentViews)) {
                        objectEnded = true;
                        classificationRound = i;
                    }
                    continue;
                }
                ++persistentRounds;  // Condition: presentViews > 0 and usableAbsentViews > 0
            }

            if (reappeared) {
                finding.state = DiscrepancyState::kTransient;
            } else if (objectEnded) {
                finding.state = DiscrepancyState::kObjectEnded;
            } else if (kAvailableRecheckRounds < options.requiredRecheckRounds) {
                finding.state = DiscrepancyState::kPendingRecheck;
            } else if (usableRecheckRounds < options.requiredRecheckRounds) {
                // X-05/X-06: Not enough available views in the recheck rounds to upgrade to a persistent discrepancy.
                finding.state = DiscrepancyState::kUnverifiable;
            } else if (persistentRounds >= options.requiredRecheckRounds) {
                finding.state = DiscrepancyState::kPersistent;
            } else {
                finding.state = DiscrepancyState::kUnverifiable;
            }
        }

        // F-05: The conclusion must be derived from the **same evidence window** as the state; do not recalculate using
        // the last round's forged envelope—that is precisely the source of 'state=Persistent but conclusion=NoEvidence'.
        const std::size_t kWindowBegin =
            (firstDiscrepancy < rounds.size()) ? firstDiscrepancy : 0U;
        const std::size_t kWindowEnd =
            (firstDiscrepancy < rounds.size()) ? classificationRound : kLastRound;
        bool windowHasUsable = false;
        bool windowFullyUsable = true;
        for (std::size_t i = kWindowBegin; i <= kWindowEnd; ++i) {
            const RoundState& state = entry.perRound[i];
            if (state.presentViews > 0U || state.usableAbsentViews > 0U) {
                windowHasUsable = true;
            }
            if (state.unusableViews > 0U) {
                windowFullyUsable = false;
            }
        }

        switch (finding.state) {
        case DiscrepancyState::kPersistent:
            finding.conclusion = AnalysisConclusion::kDifferenceObserved;
            break;
        case DiscrepancyState::kTransient:
            // Missing items are explained by resampling; only when the entire window is usable can we claim 'no difference observed'.
            finding.conclusion = (windowHasUsable && windowFullyUsable)
                                     ? AnalysisConclusion::kNoDifferenceObserved
                                     : AnalysisConclusion::kIndeterminate;
            break;
        case DiscrepancyState::kNoDiscrepancy:
            finding.conclusion = !windowHasUsable ? AnalysisConclusion::kNoEvidence
                                 : (windowFullyUsable ? AnalysisConclusion::kNoDifferenceObserved
                                                      : AnalysisConclusion::kIndeterminate);
            break;
        case DiscrepancyState::kObjectEnded:
            // X-05/F-05: Object termination explains the missing item, but it does not constitute 'sufficient coverage with no contradictions found'.
            finding.conclusion = AnalysisConclusion::kIndeterminate;
            break;
        case DiscrepancyState::kPendingRecheck:
        case DiscrepancyState::kUnverifiable:
        case DiscrepancyState::kCandidateOnly:
            finding.conclusion = windowHasUsable ? AnalysisConclusion::kIndeterminate
                                                 : AnalysisConclusion::kNoEvidence;
            break;
        }

        // Invariant fallback: Prevent contradictory combinations like Persistent+NoEvidence or ObjectEnded+NoDifferenceObserved
        // from leaking. A hit indicates a missing branch in the mapping above; downgrade the entire report.
        if (!stateConclusionConsistent(finding.state, finding.conclusion)) {
            finding.conclusion = AnalysisConclusion::kIndeterminate;
            report.selfCheckPassed = false;
        }

        report.findings.push_back(std::move(finding));
    }

    std::sort(report.findings.begin(), report.findings.end(),
              [](const CrossViewFinding& a, const CrossViewFinding& b) {
                  // Strong identities first, candidates last; sort by key within groups to ensure stable, comparable output.
                  const bool kAWeak = a.identityKey.empty();
                  const bool kBWeak = b.identityKey.empty();
                  if (kAWeak != kBWeak) {
                      return !kAWeak;
                  }
                  const std::string& ka = kAWeak ? a.candidateKey : a.identityKey;
                  const std::string& kb = kBWeak ? b.candidateKey : b.identityKey;
                  if (ka != kb) {
                      return ka < kb;
                  }
                  return a.displayText < b.displayText;
              });

    // Internal consistency self-check (X-01/X-07):
    //   * Each finding's latestHits must fully cover the union of all views
    //     per view; a missing entry indicates a view was silently skipped.
    //   * The number of claimed independent source groups must not exceed the number of source groups actually present in the final
    //     round; otherwise, it relies on a source that is no longer present or duplicates within the same group to inflate credibility.
    for (const CrossViewFinding& finding : report.findings) {
        if (finding.latestHits.size() != report.viewCount ||
            finding.viewCount != report.viewCount) {
            report.selfCheckPassed = false;
            break;
        }
        std::vector<std::string> latestGroups;
        for (const ViewHit& hit : finding.latestHits) {
            if (!hit.sourceGroup.empty() && !containsView(latestGroups, hit.sourceGroup)) {
                latestGroups.push_back(hit.sourceGroup);
            }
        }
        if (finding.independentSourceGroupCount > latestGroups.size()) {
            report.selfCheckPassed = false;
            break;
        }
    }

    return report;
}

} // namespace ksword::evidence

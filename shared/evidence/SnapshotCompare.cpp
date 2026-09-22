#include "SnapshotCompare.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <utility>

namespace ksword::evidence {
namespace {

// Key separator matches ObjectIdentity: it will not appear in paths, GUIDs, or numbers.
constexpr char kSep = '\x1F';

char foldAscii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

// Path normalization: folds case differences and unifies separators only; does not resolve symbolic links (requires live access).
std::string foldPath(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (const char kRaw : path) {
        out.push_back(kRaw == '/' ? '\\' : foldAscii(kRaw));
    }
    return out;
}

std::string foldText(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char kRaw : text) {
        out.push_back(foldAscii(kRaw));
    }
    return out;
}

bool equalPathFold(const std::string& a, const std::string& b) {
    return foldPath(a) == foldPath(b);
}

// No allocation version: Match* is noexcept, so temporary std::string cannot be constructed inside it.
bool equalTextFoldNoAlloc(const std::string& a, const std::string& b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (foldAscii(a[i]) != foldAscii(b[i])) {
            return false;
        }
    }
    return true;
}

void appendKey(std::string& key, const std::string& value) {
    key.push_back(kSep);
    key.append(value);
}

void appendKey(std::string& key, const OptionalU64& value) {
    key.push_back(kSep);
    if (value.present) {
        key.append(formatU64(value.value, U64Format::kDecimal));
    }
}

void pushUnique(std::vector<std::string>& list, std::string value) {
    if (value.empty()) {
        return;
    }
    if (std::find(list.begin(), list.end(), value) == list.end()) {
        list.push_back(std::move(value));
    }
}

// D-05: Render the EntityField into a display string. Absent and "missing number" produce no text; the
// known flag distinguishes them—otherwise, unknown would be read as the specific empty string value.
void renderField(const EntityField* field, bool& known, std::string& text) {
    known = false;
    text.clear();
    if (field == nullptr) {
        return;
    }
    switch (field->kind) {
    case FieldValueKind::kAbsent:
        return;
    case FieldValueKind::kText:
        known = true;
        text = field->text;
        return;
    case FieldValueKind::kNumber:
        if (field->number.present) {
            known = true;
            text = formatU64(field->number.value, field->numberFormat);
        }
        return;
    }
}

const EntityField* findField(const std::vector<EntityField>& fields, const std::string& name) {
    for (const EntityField& field : fields) {
        if (field.name == name) {
            return &field;
        }
    }
    return nullptr;
}

struct ResolvedAddress final {
    bool resolved = false;
    const SnapshotModule* module = nullptr;
    std::uint32_t rva = 0;
};

// D-03: Resolve absolute addresses to 'Image + RVA'. If the module base or size is missing, rvaExtent() returns an empty range;
// an empty range contains no RVA, so such modules are never considered a match—missing information does not equal a match.
ResolvedAddress resolveAddress(const Snapshot& snapshot, const OptionalU64& address) {
    ResolvedAddress result;
    if (!address.present) {
        return result;
    }
    for (const SnapshotModule& module : snapshot.modules) {
        if (!module.imageBase.present) {
            continue;
        }
        if (address.value < module.imageBase.value) {
            continue;
        }
        const std::uint64_t kOffset = address.value - module.imageBase.value;
        if (kOffset > 0xFFFFFFFFULL) {
            continue;
        }
        const RvaRange kExtent = module.rvaExtent();
        const std::uint32_t kRva = static_cast<std::uint32_t>(kOffset);
        if (!kExtent.contains(kRva)) {
            continue;
        }
        result.resolved = true;
        result.module = &module;
        result.rva = kRva;
        return result;
    }
    return result;
}

// When two image identities are incomparable, distinguish between "different versions of the same path" and "not the same module at all".
// D-03 explicitly requires the former not to be treated as identical code, so it must be visible as a distinct unit.
AddressNormalizationState classifyIncomparableImages(const DriverInstanceId& a,
                                                     const DriverInstanceId& b) {
    if (!a.imagePath.empty() && !b.imagePath.empty() && equalPathFold(a.imagePath, b.imagePath)) {
        return AddressNormalizationState::kImageVersionDiffers;
    }
    return AddressNormalizationState::kDifferentModule;
}

MatchResult matchEntityIdentity(const SnapshotEntity& a, const SnapshotEntity& b) noexcept {
    if (a.kind != b.kind) {
        return MatchResult::kNoMatch;
    }
    switch (a.kind) {
    case ObjectKind::kProcess:
        return matchProcessInstance(a.process, b.process);
    case ObjectKind::kThread:
        return matchThreadInstance(a.thread, b.thread);
    case ObjectKind::kDriver:
    case ObjectKind::kModule:
        return matchDriverInstance(a.driver, b.driver);
    case ObjectKind::kFile:
        return matchFileIdentity(a.file, b.file);
    case ObjectKind::kService:
    case ObjectKind::kDevice:
    case ObjectKind::kHandle:
    case ObjectKind::kConnection:
    case ObjectKind::kUnknown:
        return matchLogicalObject(a.logical, b.logical);
    }
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// Logical identity
// ---------------------------------------------------------------------------
IdentityStrength LogicalObjectId::strength() const noexcept {
    if (domain.empty() || name.empty()) {
        return IdentityStrength::kUnusable;
    }
    return IdentityStrength::kStrong;
}

std::string LogicalObjectId::crossSessionKey() const {
    if (strength() != IdentityStrength::kStrong) {
        return std::string();
    }
    // D-02: Fold name/scopeKey to lowercase before inserting into the key. Service names and registry keys are case-insensitive
    // on Windows; differing casing between two collectors **indicates** a change. Not folding would split the same object into
    // two buckets, directly producing a pair of false add/delete events. The domain is a classification label owned by the
    // caller; not folding it is correct. Folding it would merge two distinct domains, which constitutes relaxing the criteria.
    std::string key("logical");
    appendKey(key, domain);
    appendKey(key, foldText(name));
    appendKey(key, foldText(scopeKey));
    return key;
}

MatchResult matchLogicalObject(const LogicalObjectId& a, const LogicalObjectId& b) noexcept {
    if (!a.domain.empty() && !b.domain.empty() && a.domain != b.domain) {
        return MatchResult::kNoMatch;
    }
    // Only if they differ after folding are they considered "different objects"; case-only differences result in downgrade, not negation (see below).
    bool representationDiffers = false;
    if (!a.name.empty() && !b.name.empty()) {
        if (!equalTextFoldNoAlloc(a.name, b.name)) {
            return MatchResult::kNoMatch;
        }
        representationDiffers = representationDiffers || a.name != b.name;
    }
    if (!a.scopeKey.empty() && !b.scopeKey.empty()) {
        if (!equalTextFoldNoAlloc(a.scopeKey, b.scopeKey)) {
            return MatchResult::kNoMatch;  // Same name but different scope are two distinct objects
        }
        representationDiffers = representationDiffers || a.scopeKey != b.scopeKey;
    }
    // F-03 Unified threshold: If either side's identity is insufficient, the strongest result is only Candidate.
    if (a.strength() == IdentityStrength::kUnusable || b.strength() == IdentityStrength::kUnusable) {
        return MatchResult::kCandidate;
    }
    if (a.scopeKey.empty() != b.scopeKey.empty()) {
        return MatchResult::kCandidate;  // Note: One side lacks scope information, so it cannot be confirmed.
    }
    if (representationDiffers) {
        // D-02: Collapsing allows two records to match (no longer fabricating additions/deletions), but inconsistent original text on
        // both sides indicates at least one source is not normalized. In this case, only return "possibly the same", not "confirmed".
        return MatchResult::kCandidate;
    }
    return MatchResult::kConfirmed;
}

std::string snapshotDriverKey(const DriverInstanceId& id) {
    const std::string kRaw = id.crossSessionKey();
    if (kRaw.empty()) {
        return kRaw;  // Insufficient identity: do not emit the primary key, nor attempt to recover it via folding.
    }
    // The first segment of crossSessionKey is imagePath (see ObjectIdentity.cpp). Instead of re-parsing its
    // internal structure, we reconstruct a key with a folded path using the same identity. Differences in case and
    // separator style between PsLoadedModuleList, SCM, and disk enumeration are merely representation differences.
    DriverInstanceId folded = id;
    folded.imagePath = foldPath(id.imagePath);
    std::string key("snapdriver");
    appendKey(key, folded.crossSessionKey());
    return key;
}

bool kindComparableAcrossBoot(ObjectKind kind) noexcept {
    switch (kind) {
    case ObjectKind::kDriver:
    case ObjectKind::kModule:
    case ObjectKind::kFile:
    case ObjectKind::kService:
        // Persistent objects on disk or in the registry remain the same logical object after a reboot; compare logical properties.
        return true;
    case ObjectKind::kProcess:
    case ObjectKind::kThread:
    case ObjectKind::kHandle:
    case ObjectKind::kConnection:
    case ObjectKind::kDevice:
        // Instance objects bind to the startup lifecycle. D-02 explicitly prohibits hard-binding process instances across startups; device objects are
        // similarly part of the runtime object tree and are conservatively excluded as well—conservatism yields fewer conclusions but never incorrect ones.
        return false;
    case ObjectKind::kUnknown:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Enum name
// ---------------------------------------------------------------------------
const char* scopeComparabilityName(ScopeComparability value) noexcept {
    switch (value) {
    case ScopeComparability::kUnknown:              return "Unknown";
    case ScopeComparability::kIdentical:            return "Identical";
    case ScopeComparability::kEarlierSubsetOfLater: return "EarlierSubsetOfLater";
    case ScopeComparability::kLaterSubsetOfEarlier: return "LaterSubsetOfEarlier";
    case ScopeComparability::kPartialOverlap:       return "PartialOverlap";
    case ScopeComparability::kDisjoint:             return "Disjoint";
    }
    return "Unknown";
}

const char* crossBootComparabilityName(CrossBootComparability value) noexcept {
    switch (value) {
    case CrossBootComparability::kUnknownBoot:   return "UnknownBoot";
    case CrossBootComparability::kSameBoot:      return "SameBoot";
    case CrossBootComparability::kDifferentBoot: return "DifferentBoot";
    }
    return "UnknownBoot";
}

const char* redactionClassName(RedactionClass value) noexcept {
    switch (value) {
    case RedactionClass::kNone:       return "None";
    case RedactionClass::kUserName:   return "UserName";
    case RedactionClass::kHostname:   return "Hostname";
    case RedactionClass::kFilePath:   return "FilePath";
    case RedactionClass::kAccountSid: return "AccountSid";
    }
    return "None";
}

bool parseRedactionClassName(std::string_view text, RedactionClass& out) noexcept {
    if (text == "None")       { out = RedactionClass::kNone; return true; }
    if (text == "UserName")   { out = RedactionClass::kUserName; return true; }
    if (text == "Hostname")   { out = RedactionClass::kHostname; return true; }
    if (text == "FilePath")   { out = RedactionClass::kFilePath; return true; }
    if (text == "AccountSid") { out = RedactionClass::kAccountSid; return true; }
    return false;
}

const char* fieldSemanticsName(FieldSemantics value) noexcept {
    switch (value) {
    case FieldSemantics::kOpaque:          return "Opaque";
    case FieldSemantics::kLoadBaseAddress: return "LoadBaseAddress";
    case FieldSemantics::kKernelAddress:   return "KernelAddress";
    }
    return "Opaque";
}

bool parseFieldSemanticsName(std::string_view text, FieldSemantics& out) noexcept {
    if (text == "Opaque")          { out = FieldSemantics::kOpaque; return true; }
    if (text == "LoadBaseAddress") { out = FieldSemantics::kLoadBaseAddress; return true; }
    if (text == "KernelAddress")   { out = FieldSemantics::kKernelAddress; return true; }
    return false;
}

const char* fieldValueKindName(FieldValueKind value) noexcept {
    switch (value) {
    case FieldValueKind::kAbsent: return "Absent";
    case FieldValueKind::kText:   return "Text";
    case FieldValueKind::kNumber: return "Number";
    }
    return "Absent";
}

bool parseFieldValueKindName(std::string_view text, FieldValueKind& out) noexcept {
    if (text == "Absent") { out = FieldValueKind::kAbsent; return true; }
    if (text == "Text")   { out = FieldValueKind::kText; return true; }
    if (text == "Number") { out = FieldValueKind::kNumber; return true; }
    return false;
}

const char* addressNormalizationStateName(AddressNormalizationState value) noexcept {
    switch (value) {
    case AddressNormalizationState::kNotApplicable:       return "NotApplicable";
    case AddressNormalizationState::kValueMissing:        return "ValueMissing";
    case AddressNormalizationState::kModuleNotFound:      return "ModuleNotFound";
    case AddressNormalizationState::kImageIdentityWeak:   return "ImageIdentityWeak";
    case AddressNormalizationState::kImageVersionDiffers: return "ImageVersionDiffers";
    case AddressNormalizationState::kDifferentModule:     return "DifferentModule";
    case AddressNormalizationState::kNormalized:          return "Normalized";
    }
    return "NotApplicable";
}

const char* entitySideStateName(EntitySideState value) noexcept {
    switch (value) {
    case EntitySideState::kPresent:             return "Present";
    case EntitySideState::kAbsentCovered:       return "AbsentCovered";
    case EntitySideState::kAbsentOutOfScope:    return "AbsentOutOfScope";
    case EntitySideState::kUnknownSourceFailed: return "UnknownSourceFailed";
    case EntitySideState::kUnknownCoverage:     return "UnknownCoverage";
    case EntitySideState::kUnknownCrossBoot:    return "UnknownCrossBoot";
    case EntitySideState::kUnknownAmbiguousIdentity: return "UnknownAmbiguousIdentity";
    }
    return "UnknownSourceFailed";
}

const char* matchConfidenceName(MatchConfidence value) noexcept {
    switch (value) {
    case MatchConfidence::kNoMatch:   return "NoMatch";
    case MatchConfidence::kUncertain: return "Uncertain";
    case MatchConfidence::kConfirmed: return "Confirmed";
    }
    return "NoMatch";
}

const char* entityChangeName(EntityChange value) noexcept {
    switch (value) {
    case EntityChange::kUnchanged:            return "Unchanged";
    case EntityChange::kPartiallyComparable:  return "PartiallyComparable";
    case EntityChange::kModified:             return "Modified";
    case EntityChange::kAdded:                return "Added";
    case EntityChange::kRemoved:              return "Removed";
    case EntityChange::kNotComparable:        return "NotComparable";
    case EntityChange::kInsufficientCoverage: return "InsufficientCoverage";
    }
    return "NotComparable";
}

const char* fieldChangeName(FieldChange value) noexcept {
    switch (value) {
    case FieldChange::kUnchanged:           return "Unchanged";
    case FieldChange::kNormalizedUnchanged: return "NormalizedUnchanged";
    case FieldChange::kChanged:             return "Changed";
    case FieldChange::kUnknown:             return "Unknown";
    case FieldChange::kNotComparable:       return "NotComparable";
    }
    return "Unknown";
}

const char* reviewPriorityName(ReviewPriority value) noexcept {
    switch (value) {
    case ReviewPriority::kNotAssessed:   return "NotAssessed";
    case ReviewPriority::kInformational: return "Informational";
    case ReviewPriority::kNeedsReview:   return "NeedsReview";
    }
    return "NotAssessed";
}

const char* snapshotLoadStatusName(SnapshotLoadStatus value) noexcept {
    switch (value) {
    case SnapshotLoadStatus::kOk:                      return "Ok";
    case SnapshotLoadStatus::kOkWithUnknownFields:     return "OkWithUnknownFields";
    case SnapshotLoadStatus::kEmptyInput:              return "EmptyInput";
    case SnapshotLoadStatus::kMalformedJson:           return "MalformedJson";
    case SnapshotLoadStatus::kMissingSchema:           return "MissingSchema";
    case SnapshotLoadStatus::kWrongSchemaId:           return "WrongSchemaId";
    case SnapshotLoadStatus::kUnsupportedMajorVersion: return "UnsupportedMajorVersion";
    case SnapshotLoadStatus::kMissingRequiredField:    return "MissingRequiredField";
    case SnapshotLoadStatus::kInvalidFieldValue:       return "InvalidFieldValue";
    case SnapshotLoadStatus::kLimitExceeded:           return "LimitExceeded";
    }
    return "MalformedJson";
}

JsonLimits snapshotJsonLimits() noexcept {
    // The L1 workload in section 7.2 contains 100,000 entity records across 5 entity types, including addresses and
    // long paths. This module writes such documents at roughly 100 MiB and 6 million JSON nodes. The generic defaults
    // (32 MiB / 524,288 nodes / 64 MiB node budget) cannot even read back the valid file the module just wrote.
    //
    // The limit here is derived backwards from L1:
    //   Bytes: 100 MiB measured -> allow 3 times that amount, rounded to 320 MiB.
    //   Nodes: about 42 + 8 times the field count per entity; allow 16,000,000 for 100,000 entities.
    //   Node bytes: 16,000,000 x sizeof(JsonValue)(approximately 88B) = approximately 1.4 GiB -> allow 2 GiB.
    //   Container members: the entity array alone has 100,000 entries -> allow 2,000,000.
    // Limits remain in force; checks are not disabled. These limits suit snapshot persistence, while callers
    // reading external files may still provide their own JsonLimits.
    JsonLimits limits;
    limits.maxDepth = 64U;
    limits.maxStringBytes = 4u * 1024u * 1024u;
    limits.maxContainerItems = 2u * 1000u * 1000u;
    limits.maxTotalNodes = 16u * 1000u * 1000u;
    limits.maxTotalBytes = 320u * 1024u * 1024u;
    limits.maxEstimatedNodeBytes = 2048u * 1024u * 1024u;
    return limits;
}

// ---------------------------------------------------------------------------
// D-01: Select scope
// ---------------------------------------------------------------------------
ScopeComparability compareScopes(const SnapshotScope& earlier, const SnapshotScope& later) {
    // Cannot validate boundaries without a declared scope. The default value for D-01 must be "Unknown" rather than "Same";
    // otherwise, callers who forget to specify a scope would incorrectly receive permission to "mark as deletable".
    if (!earlier.declared || !later.declared) {
        return ScopeComparability::kUnknown;
    }
    if (earlier.scopeId.empty() || later.scopeId.empty()) {
        return ScopeComparability::kUnknown;
    }
    if (earlier.scopeId != later.scopeId) {
        return ScopeComparability::kDisjoint;
    }
    if (earlier.wholeDomain && later.wholeDomain) {
        return ScopeComparability::kIdentical;
    }
    if (earlier.wholeDomain) {
        return ScopeComparability::kLaterSubsetOfEarlier;
    }
    if (later.wholeDomain) {
        return ScopeComparability::kEarlierSubsetOfLater;
    }

    std::vector<std::string> a = earlier.selectors;
    std::vector<std::string> b = later.selectors;
    std::sort(a.begin(), a.end());
    a.erase(std::unique(a.begin(), a.end()), a.end());
    std::sort(b.begin(), b.end());
    b.erase(std::unique(b.begin(), b.end()), b.end());
    if (a.empty() || b.empty()) {
        // Claiming non-universal but providing no filter options: unclear what is covered.
        return ScopeComparability::kUnknown;
    }
    if (a == b) {
        return ScopeComparability::kIdentical;
    }
    const bool kAInB = std::includes(b.begin(), b.end(), a.begin(), a.end());
    const bool kBInA = std::includes(a.begin(), a.end(), b.begin(), b.end());
    if (kAInB) {
        return ScopeComparability::kEarlierSubsetOfLater;
    }
    if (kBInA) {
        return ScopeComparability::kLaterSubsetOfEarlier;
    }
    std::vector<std::string> common;
    std::set_intersection(a.begin(), a.end(), b.begin(), b.end(), std::back_inserter(common));
    return common.empty() ? ScopeComparability::kDisjoint : ScopeComparability::kPartialOverlap;
}

bool removalInferable(ScopeComparability value) noexcept {
    // Only if the new snapshot's scope covers the old snapshot's scope can 'present in old but absent in new' indicate a removal.
    return value == ScopeComparability::kIdentical ||
           value == ScopeComparability::kEarlierSubsetOfLater;
}

bool additionInferable(ScopeComparability value) noexcept {
    return value == ScopeComparability::kIdentical ||
           value == ScopeComparability::kLaterSubsetOfEarlier;
}

// ---------------------------------------------------------------------------
// Snapshot structure
// ---------------------------------------------------------------------------
RvaRange SnapshotModule::rvaExtent() const noexcept {
    if (!imageSize.present || imageSize.value == 0U || imageSize.value > 0xFFFFFFFFULL) {
        return RvaRange{};  // Empty range: contains no RVAs.
    }
    RvaRange range;
    range.rva = 0U;
    range.length = static_cast<std::uint32_t>(imageSize.value);
    return range;
}

std::string SnapshotEntity::identityKey() const {
    switch (kind) {
    case ObjectKind::kProcess: return process.crossSessionKey();
    case ObjectKind::kThread:  return thread.crossSessionKey();
    case ObjectKind::kDriver:
    case ObjectKind::kModule:  return snapshotDriverKey(driver);
    case ObjectKind::kFile:    return file.crossSessionKey();
    case ObjectKind::kService:
    case ObjectKind::kDevice:
    case ObjectKind::kHandle:
    case ObjectKind::kConnection:
    case ObjectKind::kUnknown: return logical.crossSessionKey();
    }
    return std::string();
}

std::string SnapshotEntity::candidateKey() const {
    // D-02: Weak identity deduplication key **valid only within this comparison**. It is constructed from reusable
    // identifiers, is never a cross-session primary key, and must never be used to claim "this is definitely the same object".
    std::string key("cand");
    appendKey(key, std::string(objectKindName(kind)));
    switch (kind) {
    case ObjectKind::kProcess:
        appendKey(key, process.pid);
        appendKey(key, foldText(process.imageName));
        break;
    case ObjectKind::kThread:
        appendKey(key, thread.process.pid);
        appendKey(key, thread.tid);
        break;
    case ObjectKind::kDriver:
    case ObjectKind::kModule:
        appendKey(key, foldPath(driver.imagePath));
        appendKey(key, driver.pdbSignature);
        break;
    case ObjectKind::kFile:
        appendKey(key, foldPath(file.path));
        appendKey(key, file.contentHash);
        break;
    case ObjectKind::kService:
    case ObjectKind::kDevice:
    case ObjectKind::kHandle:
    case ObjectKind::kConnection:
    case ObjectKind::kUnknown:
        appendKey(key, logical.domain);
        appendKey(key, foldText(logical.name));
        break;
    }
    return key;
}

IdentityStrength SnapshotEntity::strength() const noexcept {
    switch (kind) {
    case ObjectKind::kProcess: return process.strength();
    case ObjectKind::kThread:  return thread.strength();
    case ObjectKind::kDriver:
    case ObjectKind::kModule:  return driver.strength();
    case ObjectKind::kFile:    return file.strength();
    case ObjectKind::kService:
    case ObjectKind::kDevice:
    case ObjectKind::kHandle:
    case ObjectKind::kConnection:
    case ObjectKind::kUnknown: return logical.strength();
    }
    return IdentityStrength::kUnusable;
}

std::string SnapshotEntity::displayText() const {
    switch (kind) {
    case ObjectKind::kProcess:
        return process.imageName.empty() ? std::string("process") : process.imageName;
    case ObjectKind::kThread:
        return std::string("thread");
    case ObjectKind::kDriver:
    case ObjectKind::kModule:
        return driver.imagePath.empty() ? std::string("module") : driver.imagePath;
    case ObjectKind::kFile:
        return file.path.empty() ? std::string("file") : file.path;
    case ObjectKind::kService:
    case ObjectKind::kDevice:
    case ObjectKind::kHandle:
    case ObjectKind::kConnection:
    case ObjectKind::kUnknown:
        return logical.name.empty() ? std::string("object") : logical.name;
    }
    return std::string("object");
}

const SnapshotPartition* Snapshot::findPartition(std::string_view partitionId) const noexcept {
    for (const SnapshotPartition& partition : partitions) {
        if (partition.partitionId == partitionId) {
            return &partition;
        }
    }
    return nullptr;
}

const SnapshotModule* Snapshot::findModule(std::string_view moduleId) const noexcept {
    for (const SnapshotModule& module : modules) {
        if (module.moduleId == moduleId) {
            return &module;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Compare
// ---------------------------------------------------------------------------
namespace {

struct SideContext final {
    const Snapshot* snapshot = nullptr;
    const SnapshotPartition* partition = nullptr;
    bool partitionPresent = false;
};

bool sideCarriesObservation(const SideContext& side) noexcept {
    return side.partitionPresent && side.partition != nullptr &&
           statusCarriesObservation(side.partition->envelope.outcome.status);
}

// D-04 + F-06: Supporting 'definitely absent' requires positive evidence: successful collection, claimed coverage of the snapshot's
// selection range, and integrity evidence from the coverage ledger itself. Default-constructed empty ledgers do not count.
bool sideUsableForAbsence(const SideContext& side) noexcept {
    if (!sideCarriesObservation(side)) {
        return false;
    }
    if (!side.partition->coversScope) {
        return false;
    }
    if (side.partition->envelope.outcome.status == CollectionStatus::kPartial) {
        return false;
    }
    return side.partition->envelope.coverage.fullyCovered();
}

EntitySideState missingSideState(const SideContext& side,
                                 ObjectKind kind,
                                 CrossBootComparability boot,
                                 bool directionInferable) {
    if (!sideCarriesObservation(side)) {
        // Not collected / failed / unsupported / access denied — D-04's red line: this is not "absent".
        return EntitySideState::kUnknownSourceFailed;
    }
    if (!kindComparableAcrossBoot(kind) && boot != CrossBootComparability::kSameBoot) {
        // D-02: Absence is meaningless when an instance object crosses boot boundaries (or cannot be proven to share the same boot).
        return EntitySideState::kUnknownCrossBoot;
    }
    if (!sideUsableForAbsence(side)) {
        return EntitySideState::kUnknownCoverage;
    }
    if (!directionInferable) {
        // D-01: This side is indeed complete, but the relationship between the two selection ranges does not support inference in this direction.
        return EntitySideState::kAbsentOutOfScope;
    }
    return EntitySideState::kAbsentCovered;
}

const char* limitationForState(EntitySideState state) noexcept {
    switch (state) {
    case EntitySideState::kUnknownSourceFailed: return "snapshot.limitation.sourceFailed";
    case EntitySideState::kUnknownCoverage:     return "snapshot.limitation.coverageIncomplete";
    case EntitySideState::kUnknownCrossBoot:    return "snapshot.limitation.crossBootInstance";
    case EntitySideState::kAbsentOutOfScope:    return "snapshot.limitation.scopeNotComparable";
    case EntitySideState::kUnknownAmbiguousIdentity:
        return "snapshot.limitation.duplicateIdentityKey";
    case EntitySideState::kPresent:
    case EntitySideState::kAbsentCovered:       return "";
    }
    return "";
}

EntityChange deriveChange(EntitySideState earlier,
                          EntitySideState later,
                          bool anyChangedField,
                          bool anyIncomparableField) {
    if (earlier == EntitySideState::kPresent && later == EntitySideState::kPresent) {
        if (anyChangedField) {
            return EntityChange::kModified;
        }
        return anyIncomparableField ? EntityChange::kPartiallyComparable : EntityChange::kUnchanged;
    }
    if (earlier == EntitySideState::kPresent) {
        switch (later) {
        case EntitySideState::kAbsentCovered:       return EntityChange::kRemoved;
        case EntitySideState::kUnknownCoverage:     return EntityChange::kInsufficientCoverage;
        case EntitySideState::kAbsentOutOfScope:
        case EntitySideState::kUnknownSourceFailed:
        case EntitySideState::kUnknownCrossBoot:
        case EntitySideState::kUnknownAmbiguousIdentity:
        case EntitySideState::kPresent:             return EntityChange::kNotComparable;
        }
        return EntityChange::kNotComparable;
    }
    if (later == EntitySideState::kPresent) {
        switch (earlier) {
        case EntitySideState::kAbsentCovered:       return EntityChange::kAdded;
        case EntitySideState::kUnknownCoverage:     return EntityChange::kInsufficientCoverage;
        case EntitySideState::kAbsentOutOfScope:
        case EntitySideState::kUnknownSourceFailed:
        case EntitySideState::kUnknownCrossBoot:
        case EntitySideState::kUnknownAmbiguousIdentity:
        case EntitySideState::kPresent:             return EntityChange::kNotComparable;
        }
        return EntityChange::kNotComparable;
    }
    return EntityChange::kNotComparable;
}

FieldDelta compareOneField(const std::string& name,
                           const EntityField* earlierField,
                           const EntityField* laterField,
                           const SnapshotEntity& earlierEntity,
                           const SnapshotEntity& laterEntity,
                           const Snapshot& earlierSnapshot,
                           const Snapshot& laterSnapshot) {
    FieldDelta delta;
    delta.name = name;
    if (earlierField != nullptr) {
        delta.semantics = earlierField->semantics;
    } else if (laterField != nullptr) {
        delta.semantics = laterField->semantics;
    }
    renderField(earlierField, delta.earlierKnown, delta.earlierText);
    renderField(laterField, delta.laterKnown, delta.laterText);

    // If the field is missing on one side, or if the semantic declarations on both sides are inconsistent, no 'change' conclusion is provided.
    if (earlierField == nullptr || laterField == nullptr) {
        delta.change = FieldChange::kUnknown;
        return delta;
    }
    if (earlierField->semantics != laterField->semantics) {
        delta.change = FieldChange::kNotComparable;
        return delta;
    }
    if (earlierField->kind == FieldValueKind::kAbsent || laterField->kind == FieldValueKind::kAbsent) {
        // Absent means 'not collected', not an empty string or 0.
        delta.change = FieldChange::kUnknown;
        if (delta.semantics != FieldSemantics::kOpaque) {
            delta.normalization.state = AddressNormalizationState::kValueMissing;
        }
        return delta;
    }
    if (earlierField->kind != laterField->kind) {
        delta.change = FieldChange::kNotComparable;
        return delta;
    }

    switch (delta.semantics) {
    case FieldSemantics::kOpaque:
        if (earlierField->kind == FieldValueKind::kText) {
            delta.change = (earlierField->text == laterField->text) ? FieldChange::kUnchanged
                                                                    : FieldChange::kChanged;
            return delta;
        }
        if (!earlierField->number.present || !laterField->number.present) {
            delta.change = FieldChange::kUnknown;
            return delta;
        }
        delta.change = (earlierField->number.value == laterField->number.value)
                           ? FieldChange::kUnchanged
                           : FieldChange::kChanged;
        return delta;

    case FieldSemantics::kLoadBaseAddress: {
        // D-03: The load base address itself is not evidence of a difference, provided both sides are indeed the same image.
        if (earlierField->kind != FieldValueKind::kNumber) {
            delta.change = FieldChange::kNotComparable;  // Address field written as text: incorrect representation.
            return delta;
        }
        if (!earlierField->number.present || !laterField->number.present) {
            delta.change = FieldChange::kUnknown;
            delta.normalization.state = AddressNormalizationState::kValueMissing;
            return delta;
        }
        const bool kDriverKind = earlierEntity.kind == ObjectKind::kDriver ||
                                earlierEntity.kind == ObjectKind::kModule;
        if (!kDriverKind || laterEntity.kind != earlierEntity.kind) {
            // Without an image identity to rely on, do not treat "same base address" as "same code".
            delta.normalization.state = AddressNormalizationState::kImageIdentityWeak;
            delta.change = FieldChange::kNotComparable;
            return delta;
        }
        const MatchResult kMatch = matchDriverInstance(earlierEntity.driver, laterEntity.driver);
        if (kMatch == MatchResult::kConfirmed) {
            delta.normalization.state = AddressNormalizationState::kNormalized;
            delta.normalization.earlierRva = OptionalU64::of(0U);
            delta.normalization.laterRva = OptionalU64::of(0U);
            delta.change = (earlierField->number.value == laterField->number.value)
                               ? FieldChange::kUnchanged
                               : FieldChange::kNormalizedUnchanged;
            return delta;
        }
        delta.normalization.state =
            (kMatch == MatchResult::kCandidate)
                ? AddressNormalizationState::kImageIdentityWeak
                : classifyIncomparableImages(earlierEntity.driver, laterEntity.driver);
        delta.change = FieldChange::kNotComparable;
        return delta;
    }

    case FieldSemantics::kKernelAddress: {
        if (earlierField->kind != FieldValueKind::kNumber) {
            delta.change = FieldChange::kNotComparable;
            return delta;
        }
        if (!earlierField->number.present || !laterField->number.present) {
            delta.change = FieldChange::kUnknown;
            delta.normalization.state = AddressNormalizationState::kValueMissing;
            return delta;
        }
        const ResolvedAddress kEarlierHit = resolveAddress(earlierSnapshot, earlierField->number);
        const ResolvedAddress kLaterHit = resolveAddress(laterSnapshot, laterField->number);
        if (!kEarlierHit.resolved || !kLaterHit.resolved) {
            // D-03: When a module is missing, do not normalize or compare raw addresses directly;
            // different load base addresses in two loads would immediately create false differences.
            delta.normalization.state = AddressNormalizationState::kModuleNotFound;
            if (kEarlierHit.resolved) {
                delta.normalization.earlierModuleId = kEarlierHit.module->moduleId;
                delta.normalization.earlierRva = OptionalU64::of(kEarlierHit.rva);
            }
            if (kLaterHit.resolved) {
                delta.normalization.laterModuleId = kLaterHit.module->moduleId;
                delta.normalization.laterRva = OptionalU64::of(kLaterHit.rva);
            }
            delta.change = FieldChange::kNotComparable;
            return delta;
        }
        delta.normalization.earlierModuleId = kEarlierHit.module->moduleId;
        delta.normalization.laterModuleId = kLaterHit.module->moduleId;
        delta.normalization.earlierRva = OptionalU64::of(kEarlierHit.rva);
        delta.normalization.laterRva = OptionalU64::of(kLaterHit.rva);

        const MatchResult kMatch =
            matchDriverInstance(kEarlierHit.module->identity, kLaterHit.module->identity);
        if (kMatch == MatchResult::kConfirmed) {
            delta.normalization.state = AddressNormalizationState::kNormalized;
            if (kEarlierHit.rva != kLaterHit.rva) {
                delta.change = FieldChange::kChanged;
            } else if (earlierField->number.value == laterField->number.value) {
                delta.change = FieldChange::kUnchanged;
            } else {
                delta.change = FieldChange::kNormalizedUnchanged;
            }
            return delta;
        }
        // D-03: normalize only when comparability is confirmed. Identical RVAs in different versions are never identical code.
        delta.normalization.state =
            (kMatch == MatchResult::kCandidate)
                ? AddressNormalizationState::kImageIdentityWeak
                : classifyIncomparableImages(kEarlierHit.module->identity, kLaterHit.module->identity);
        delta.change = FieldChange::kNotComparable;
        return delta;
    }
    }
    delta.change = FieldChange::kUnknown;
    return delta;
}

void fillSideMetadata(EntityDelta& delta,
                      const SnapshotEntity* earlierEntity,
                      const SnapshotEntity* laterEntity,
                      const SideContext& earlierSide,
                      const SideContext& laterSide) {
    if (earlierEntity != nullptr) {
        delta.earlierRawRecordId = earlierEntity->rawRecordId;
        delta.earlierDisplayOrder = earlierEntity->displayOrder;
    }
    if (laterEntity != nullptr) {
        delta.laterRawRecordId = laterEntity->rawRecordId;
        delta.laterDisplayOrder = laterEntity->displayOrder;
    }
    if (earlierSide.partition != nullptr) {
        delta.earlierEvidenceId = earlierSide.partition->envelope.evidenceId;
        delta.earlierObservedUtc100ns = earlierSide.partition->envelope.window.endUtc100ns;
    }
    if (laterSide.partition != nullptr) {
        delta.laterEvidenceId = laterSide.partition->envelope.evidenceId;
        delta.laterObservedUtc100ns = laterSide.partition->envelope.window.endUtc100ns;
    }
    delta.displayOrderChanged = earlierEntity != nullptr && laterEntity != nullptr &&
                                earlierEntity->displayOrder != laterEntity->displayOrder;
}

void applyReviewRules(EntityDelta& delta, const std::vector<ReviewRule>& rules) {
    // D-05: The engine does not invent priorities; it only executes rules declared by the caller. If no rules exist, the status remains NotAssessed.
    for (const ReviewRule& rule : rules) {
        if (!rule.partitionId.empty() && rule.partitionId != delta.partitionId) {
            continue;
        }
        bool applies = false;
        if (rule.fieldName.empty()) {
            applies = delta.change == EntityChange::kModified ||
                      delta.change == EntityChange::kAdded ||
                      delta.change == EntityChange::kRemoved;
        } else {
            for (const FieldDelta& field : delta.fields) {
                if (field.name == rule.fieldName && field.change == FieldChange::kChanged) {
                    applies = true;
                    break;
                }
            }
        }
        if (!applies) {
            continue;
        }
        if (static_cast<int>(rule.priority) > static_cast<int>(delta.review.priority)) {
            delta.review.priority = rule.priority;
        }
        pushUnique(delta.review.reasonKeys, rule.reasonKey);
    }
}

struct EntityBucket final {
    std::vector<const SnapshotEntity*> earlier;
    std::vector<const SnapshotEntity*> later;
};

std::string deltaSortKey(const EntityDelta& delta) {
    std::string key = delta.partitionId;
    key.push_back(kSep);
    key.append(delta.identityKey.empty() ? delta.candidateKey : delta.identityKey);
    key.push_back(kSep);
    key.append(delta.displayText);
    key.push_back(kSep);
    key.append(delta.earlierRawRecordId);
    key.push_back(kSep);
    key.append(delta.laterRawRecordId);
    return key;
}

} // namespace

SnapshotComparison compareSnapshots(const Snapshot& earlier,
                                    const Snapshot& later,
                                    const SnapshotCompareOptions& options) {
    SnapshotComparison result;
    result.scope = compareScopes(earlier.scope, later.scope);

    const std::string& earlierBoot = earlier.envelope.window.bootId;
    const std::string& laterBoot = later.envelope.window.bootId;
    if (earlierBoot.empty() || laterBoot.empty()) {
        result.boot = CrossBootComparability::kUnknownBoot;
    } else {
        result.boot = (earlierBoot == laterBoot) ? CrossBootComparability::kSameBoot
                                                 : CrossBootComparability::kDifferentBoot;
    }

    // D-01: When two snapshots come from different machines, any 'add/delete' operations lose meaning. This does not
    // halt the comparison — logical properties are still compared, but adds/deletes are downgraded to incomparable.
    const std::string& earlierMachine = earlier.envelope.window.machineId;
    const std::string& laterMachine = later.envelope.window.machineId;
    const bool kMachineMismatch =
        !earlierMachine.empty() && !laterMachine.empty() && earlierMachine != laterMachine;

    if (result.scope == ScopeComparability::kUnknown) {
        result.limitationKeys.push_back("snapshot.limitation.scopeUndeclared");
    } else if (result.scope != ScopeComparability::kIdentical) {
        result.limitationKeys.push_back("snapshot.limitation.scopeDiffers");
    }
    if (result.boot == CrossBootComparability::kDifferentBoot) {
        result.limitationKeys.push_back("snapshot.limitation.differentBoot");
    } else if (result.boot == CrossBootComparability::kUnknownBoot) {
        result.limitationKeys.push_back("snapshot.limitation.bootUndeclared");
    }
    if (kMachineMismatch) {
        result.limitationKeys.push_back("snapshot.limitation.machineMismatch");
    }

    const bool kRemovalAllowed = removalInferable(result.scope) && !kMachineMismatch;
    const bool kAdditionAllowed = additionInferable(result.scope) && !kMachineMismatch;

    // ---- Partition ledger: The union of partition IDs from both sides; missing partitions on either side are explicitly marked as NotCollected ----
    std::vector<std::string> partitionIds;
    for (const SnapshotPartition& partition : earlier.partitions) {
        pushUnique(partitionIds, partition.partitionId);
    }
    for (const SnapshotPartition& partition : later.partitions) {
        pushUnique(partitionIds, partition.partitionId);
    }
    // Entities referenced but not declared in the partition ledger must still be accounted for; silently skipping them equates to 'not sampled = normal'.
    for (const SnapshotEntity& entity : earlier.entities) {
        pushUnique(partitionIds, entity.partitionId);
    }
    for (const SnapshotEntity& entity : later.entities) {
        pushUnique(partitionIds, entity.partitionId);
    }
    std::sort(partitionIds.begin(), partitionIds.end());

    std::vector<EvidenceEnvelope> envelopes;
    envelopes.push_back(earlier.envelope);
    envelopes.push_back(later.envelope);

    std::vector<EntityDelta> deltas;

    for (const std::string& partitionId : partitionIds) {
        SideContext earlierSide;
        earlierSide.snapshot = &earlier;
        earlierSide.partition = earlier.findPartition(partitionId);
        earlierSide.partitionPresent = earlierSide.partition != nullptr;

        SideContext laterSide;
        laterSide.snapshot = &later;
        laterSide.partition = later.findPartition(partitionId);
        laterSide.partitionPresent = laterSide.partition != nullptr;

        PartitionAccount account;
        account.partitionId = partitionId;
        account.earlierPresent = earlierSide.partitionPresent;
        account.laterPresent = laterSide.partitionPresent;
        account.earlierStatus = earlierSide.partitionPresent
                                    ? earlierSide.partition->envelope.outcome.status
                                    : CollectionStatus::kNotCollected;
        account.laterStatus = laterSide.partitionPresent
                                  ? laterSide.partition->envelope.outcome.status
                                  : CollectionStatus::kNotCollected;
        account.earlierUsableForAbsence = sideUsableForAbsence(earlierSide);
        account.laterUsableForAbsence = sideUsableForAbsence(laterSide);

        ObjectKind kind = ObjectKind::kUnknown;
        bool kindMismatch = false;
        if (earlierSide.partition != nullptr && laterSide.partition != nullptr) {
            kind = earlierSide.partition->kind;
            kindMismatch = earlierSide.partition->kind != laterSide.partition->kind;
        } else if (earlierSide.partition != nullptr) {
            kind = earlierSide.partition->kind;
        } else if (laterSide.partition != nullptr) {
            kind = laterSide.partition->kind;
        }
        account.kind = kind;

        if (!account.earlierPresent) {
            account.limitationKeys.push_back("snapshot.partition.earlierNotCollected");
        }
        if (!account.laterPresent) {
            account.limitationKeys.push_back("snapshot.partition.laterNotCollected");
        }
        if (account.earlierPresent && !sideCarriesObservation(earlierSide)) {
            account.limitationKeys.push_back("snapshot.partition.earlierNoObservation");
        }
        if (account.laterPresent && !sideCarriesObservation(laterSide)) {
            account.limitationKeys.push_back("snapshot.partition.laterNoObservation");
        }
        if (sideCarriesObservation(earlierSide) && !account.earlierUsableForAbsence) {
            account.limitationKeys.push_back("snapshot.partition.earlierCoverageIncomplete");
        }
        if (sideCarriesObservation(laterSide) && !account.laterUsableForAbsence) {
            account.limitationKeys.push_back("snapshot.partition.laterCoverageIncomplete");
        }
        if (kindMismatch) {
            account.limitationKeys.push_back("snapshot.partition.kindMismatch");
        }
        account.comparable =
            sideCarriesObservation(earlierSide) && sideCarriesObservation(laterSide) && !kindMismatch;

        // D-04: If two partitions with the same name declare different entity types, they do not belong to the same collection view. In this
        // case, 'old present, new absent' might simply mean the two collectors installed different components and cannot be treated as
        // additions or deletions. Since the partition ledger is already marked as not comparable, every individual conclusion must be
        // tightened accordingly; otherwise, the same result set would contain a ledger stating 'no comparison' while the row claims 'deleted'.
        const bool kPartitionRemovalAllowed = kRemovalAllowed && !kindMismatch;
        const bool kPartitionAdditionAllowed = kAdditionAllowed && !kindMismatch;

        if (earlierSide.partition != nullptr) {
            envelopes.push_back(earlierSide.partition->envelope);
        }
        if (laterSide.partition != nullptr) {
            envelopes.push_back(laterSide.partition->envelope);
        }

        // ---- Collect entities in this partition and bucket by identity ----
        std::map<std::string, EntityBucket> strongBuckets;
        std::map<std::string, EntityBucket> weakBuckets;
        for (const SnapshotEntity& entity : earlier.entities) {
            if (entity.partitionId != partitionId) {
                continue;
            }
            const std::string kKey = entity.identityKey();
            if (kKey.empty()) {
                weakBuckets[entity.candidateKey()].earlier.push_back(&entity);
            } else {
                strongBuckets[kKey].earlier.push_back(&entity);
            }
        }
        for (const SnapshotEntity& entity : later.entities) {
            if (entity.partitionId != partitionId) {
                continue;
            }
            const std::string kKey = entity.identityKey();
            if (kKey.empty()) {
                weakBuckets[entity.candidateKey()].later.push_back(&entity);
            } else {
                strongBuckets[kKey].later.push_back(&entity);
            }
        }

        auto makeDelta = [&](const SnapshotEntity* earlierEntity,
                             const SnapshotEntity* laterEntity,
                             const std::string& strongKey,
                             const std::string& weakKey,
                             MatchConfidence confidence) {
            EntityDelta delta;
            delta.partitionId = partitionId;
            delta.identityKey = strongKey;
            delta.candidateKey = weakKey;
            const SnapshotEntity* any = earlierEntity != nullptr ? earlierEntity : laterEntity;
            if (any != nullptr) {
                delta.kind = any->kind;
                delta.strength = any->strength();
                delta.displayText = any->displayText();
            } else {
                delta.kind = kind;
            }
            delta.matchConfidence = confidence;
            fillSideMetadata(delta, earlierEntity, laterEntity, earlierSide, laterSide);

            bool anyChanged = false;
            bool anyIncomparable = false;
            if (earlierEntity != nullptr && laterEntity != nullptr) {
                delta.earlierState = EntitySideState::kPresent;
                delta.laterState = EntitySideState::kPresent;
                std::vector<std::string> names;
                for (const EntityField& field : earlierEntity->fields) {
                    pushUnique(names, field.name);
                }
                for (const EntityField& field : laterEntity->fields) {
                    pushUnique(names, field.name);
                }
                for (const std::string& name : names) {
                    const EntityField* ef = findField(earlierEntity->fields, name);
                    const EntityField* lf = findField(laterEntity->fields, name);
                    FieldDelta field = compareOneField(name, ef, lf, *earlierEntity, *laterEntity,
                                                       earlier, later);
                    field.earlierCollectorId = earlierSide.partition != nullptr
                                                   ? earlierSide.partition->envelope.source.collectorId
                                                   : std::string();
                    field.laterCollectorId = laterSide.partition != nullptr
                                                 ? laterSide.partition->envelope.source.collectorId
                                                 : std::string();
                    field.earlierObservedUtc100ns = delta.earlierObservedUtc100ns;
                    field.laterObservedUtc100ns = delta.laterObservedUtc100ns;
                    field.earlierEvidenceId = delta.earlierEvidenceId;
                    field.laterEvidenceId = delta.laterEvidenceId;
                    if (field.change == FieldChange::kChanged) {
                        anyChanged = true;
                    }
                    if (field.change == FieldChange::kUnknown ||
                        field.change == FieldChange::kNotComparable) {
                        anyIncomparable = true;
                    }
                    if (field.change != FieldChange::kUnchanged) {
                        delta.fields.push_back(std::move(field));
                    }
                }
            } else if (earlierEntity != nullptr) {
                delta.earlierState = EntitySideState::kPresent;
                delta.laterState =
                    missingSideState(laterSide, delta.kind, result.boot, kPartitionRemovalAllowed);
            } else {
                delta.laterState = EntitySideState::kPresent;
                delta.earlierState =
                    missingSideState(earlierSide, delta.kind, result.boot, kPartitionAdditionAllowed);
            }

            delta.change =
                deriveChange(delta.earlierState, delta.laterState, anyChanged, anyIncomparable);

            // D-02: Never produce add/delete when identity is insufficient — unstable matching means uncertain.
            if (delta.matchConfidence == MatchConfidence::kUncertain &&
                (delta.change == EntityChange::kAdded || delta.change == EntityChange::kRemoved)) {
                delta.change = EntityChange::kNotComparable;
                pushUnique(delta.limitationKeys, "snapshot.limitation.identityInsufficient");
            }

            pushUnique(delta.limitationKeys, limitationForState(delta.earlierState));
            pushUnique(delta.limitationKeys, limitationForState(delta.laterState));
            if (kindMismatch) {
                // Otherwise, the reader would only see "range does not support inference in this direction" without seeing the actual cause.
                pushUnique(delta.limitationKeys, "snapshot.partition.kindMismatch");
            }
            applyReviewRules(delta, options.reviewRules);
            deltas.push_back(std::move(delta));
        };

        for (const auto& entry : strongBuckets) {
            const EntityBucket& bucket = entry.second;
            const bool kAmbiguous = bucket.earlier.size() > 1U || bucket.later.size() > 1U;
            if (kAmbiguous) {
                // If multiple entries share the same stable key, the pairing relationship is indeterminate; record as ambiguous without guessing.
                //
                // D-04: The state on the opposite side **must** be derived truthfully; it cannot be uniformly written as UnknownCoverage.
                // Otherwise, the same AccessDenied collector would display as "collected but incomplete coverage" on rows with duplicate
                // keys and as "source failed" on other rows, causing a contradiction between rows and accounts within the same partition.
                // Duplicate keys are **additional** constraints layered on top of the real-side state, not a replacement for it.
                //
                // The other case is equally important: if the opposite bucket contains a record with the same key, that side is neither absent
                // nor confirmed present. Reporting it as present would assert a match for this record; use UnknownAmbiguousIdentity instead.
                auto pushAmbiguous = [&](const SnapshotEntity* earlierEntity,
                                         const SnapshotEntity* laterEntity) {
                    const SnapshotEntity* self =
                        earlierEntity != nullptr ? earlierEntity : laterEntity;
                    EntityDelta delta;
                    delta.partitionId = partitionId;
                    delta.identityKey = entry.first;
                    delta.kind = self->kind;
                    delta.strength = self->strength();
                    delta.displayText = self->displayText();
                    delta.matchConfidence = MatchConfidence::kUncertain;
                    if (earlierEntity != nullptr) {
                        delta.earlierState = EntitySideState::kPresent;
                        delta.laterState =
                            bucket.later.empty()
                                ? missingSideState(laterSide, delta.kind, result.boot,
                                                   kPartitionRemovalAllowed)
                                : EntitySideState::kUnknownAmbiguousIdentity;
                    } else {
                        delta.laterState = EntitySideState::kPresent;
                        delta.earlierState =
                            bucket.earlier.empty()
                                ? missingSideState(earlierSide, delta.kind, result.boot,
                                                   kPartitionAdditionAllowed)
                                : EntitySideState::kUnknownAmbiguousIdentity;
                    }
                    // Pairing relationship is uncertain; therefore, no add/remove/unchanged conclusion is given regardless of the state on either side.
                    delta.change = EntityChange::kNotComparable;
                    pushUnique(delta.limitationKeys, "snapshot.limitation.duplicateIdentityKey");
                    pushUnique(delta.limitationKeys, limitationForState(delta.earlierState));
                    pushUnique(delta.limitationKeys, limitationForState(delta.laterState));
                    if (kindMismatch) {
                        pushUnique(delta.limitationKeys, "snapshot.partition.kindMismatch");
                    }
                    fillSideMetadata(delta, earlierEntity, laterEntity, earlierSide, laterSide);
                    applyReviewRules(delta, options.reviewRules);
                    deltas.push_back(std::move(delta));
                };
                for (const SnapshotEntity* entity : bucket.earlier) {
                    pushAmbiguous(entity, nullptr);
                }
                for (const SnapshotEntity* entity : bucket.later) {
                    pushAmbiguous(nullptr, entity);
                }
                continue;
            }
            const SnapshotEntity* e = bucket.earlier.empty() ? nullptr : bucket.earlier.front();
            const SnapshotEntity* l = bucket.later.empty() ? nullptr : bucket.later.front();
            MatchConfidence confidence = MatchConfidence::kNoMatch;
            if (e != nullptr && l != nullptr) {
                const MatchResult kMatch = matchEntityIdentity(*e, *l);
                if (kMatch == MatchResult::kNoMatch) {
                    // Same key but rejected by identity criteria: split into two uncertain records; never force-match.
                    makeDelta(e, nullptr, entry.first, std::string(), MatchConfidence::kUncertain);
                    makeDelta(nullptr, l, entry.first, std::string(), MatchConfidence::kUncertain);
                    continue;
                }
                confidence = (kMatch == MatchResult::kConfirmed) ? MatchConfidence::kConfirmed
                                                               : MatchConfidence::kUncertain;
            }
            makeDelta(e, l, entry.first, std::string(), confidence);
        }

        for (const auto& entry : weakBuckets) {
            const EntityBucket& bucket = entry.second;
            if (bucket.earlier.size() == 1U && bucket.later.size() == 1U &&
                matchEntityIdentity(*bucket.earlier.front(), *bucket.later.front()) !=
                    MatchResult::kNoMatch) {
                // D-02: Candidate match only — paired but marked uncertain is more honest than fabricating a fake add/delete pair.
                makeDelta(bucket.earlier.front(), bucket.later.front(), std::string(), entry.first,
                          MatchConfidence::kUncertain);
                continue;
            }
            for (const SnapshotEntity* entity : bucket.earlier) {
                makeDelta(entity, nullptr, std::string(), entry.first, MatchConfidence::kUncertain);
            }
            for (const SnapshotEntity* entity : bucket.later) {
                makeDelta(nullptr, entity, std::string(), entry.first, MatchConfidence::kUncertain);
            }
        }

        result.partitions.push_back(std::move(account));
    }

    std::sort(deltas.begin(), deltas.end(), [](const EntityDelta& a, const EntityDelta& b) {
        return deltaSortKey(a) < deltaSortKey(b);
    });

    // ---- Count before filtering Unchanged entries to ensure the metric is not affected by display options ----
    for (const EntityDelta& delta : deltas) {
        switch (delta.change) {
        case EntityChange::kUnchanged:            ++result.unchangedCount; break;
        case EntityChange::kPartiallyComparable:  ++result.partiallyComparableCount; break;
        case EntityChange::kModified:             ++result.modifiedCount; break;
        case EntityChange::kAdded:                ++result.addedCount; break;
        case EntityChange::kRemoved:              ++result.removedCount; break;
        case EntityChange::kNotComparable:        ++result.notComparableCount; break;
        case EntityChange::kInsufficientCoverage: ++result.insufficientCoverageCount; break;
        }
    }

    for (PartitionAccount& account : result.partitions) {
        for (const EntityDelta& delta : deltas) {
            if (delta.partitionId != account.partitionId) {
                continue;
            }
            if (delta.change == EntityChange::kNotComparable ||
                delta.change == EntityChange::kInsufficientCoverage) {
                ++account.entitiesNotComparable;
            } else {
                ++account.entitiesCompared;
            }
        }
        bool partitionDifference = false;
        for (const EntityDelta& delta : deltas) {
            if (delta.partitionId != account.partitionId) {
                continue;
            }
            if (delta.change == EntityChange::kModified || delta.change == EntityChange::kAdded ||
                delta.change == EntityChange::kRemoved) {
                partitionDifference = true;
                break;
            }
        }
        if (!account.comparable) {
            account.conclusion = AnalysisConclusion::kNoEvidence;
        } else if (partitionDifference) {
            account.conclusion = AnalysisConclusion::kDifferenceObserved;
        } else if (account.entitiesNotComparable != 0U || !account.earlierUsableForAbsence ||
                   !account.laterUsableForAbsence || result.scope != ScopeComparability::kIdentical) {
            account.conclusion = AnalysisConclusion::kIndeterminate;
        } else {
            account.conclusion = AnalysisConclusion::kNoDifferenceObserved;
        }
    }

    bool anyComparablePartition = false;
    bool allPartitionsClean = true;
    for (const PartitionAccount& account : result.partitions) {
        if (account.comparable) {
            anyComparablePartition = true;
        }
        if (!account.comparable || !account.earlierUsableForAbsence ||
            !account.laterUsableForAbsence) {
            allPartitionsClean = false;
        }
    }

    const bool kDifferenceFound =
        result.addedCount != 0U || result.removedCount != 0U || result.modifiedCount != 0U;
    if (!anyComparablePartition) {
        // F-05: No available observation does not equate to 'no difference found'.
        result.conclusion = AnalysisConclusion::kNoEvidence;
    } else if (kDifferenceFound) {
        result.conclusion = AnalysisConclusion::kDifferenceObserved;
    } else if (!allPartitionsClean || result.scope != ScopeComparability::kIdentical ||
               kMachineMismatch || result.notComparableCount != 0U ||
               result.insufficientCoverageCount != 0U || result.partiallyComparableCount != 0U) {
        result.conclusion = AnalysisConclusion::kIndeterminate;
    } else {
        result.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    }

    result.trust = buildTrustStatement(envelopes);

    if (options.emitUnchanged) {
        result.deltas = std::move(deltas);
    } else {
        for (EntityDelta& delta : deltas) {
            if (delta.change != EntityChange::kUnchanged) {
                result.deltas.push_back(std::move(delta));
            }
        }
    }

    // ---- Self-check: consider only published results, do not reuse any intermediate variables above ---- The old
    // implementation read local variables like removalAllowed / additionAllowed that **produced** these lines here, making
    // each clause always true: 784 generation combinations and 20 injection corruptions never caused it to become false.
    // Now changed to an independent review of result (see checkComparisonSelfConsistency).
    result.selfCheckPassed = checkComparisonSelfConsistency(result);
    return result;
}

namespace {

bool hasKey(const std::vector<std::string>& list, const char* value) {
    return std::find(list.begin(), list.end(), std::string(value)) != list.end();
}

bool anyFieldChange(const EntityDelta& delta, FieldChange change) {
    for (const FieldDelta& field : delta.fields) {
        if (field.change == change) {
            return true;
        }
    }
    return false;
}

const PartitionAccount* findAccountFor(const SnapshotComparison& comparison,
                                       const std::string& partitionId) {
    for (const PartitionAccount& account : comparison.partitions) {
        if (account.partitionId == partitionId) {
            return &account;
        }
    }
    return nullptr;
}

// Whether a single conclusion is consistent with its own surrounding states and field list.
bool rowConsistent(const EntityDelta& delta,
                   const PartitionAccount& account,
                   bool removalInferable,
                   bool additionInferable) {
    const bool kBothPresent = delta.earlierState == EntitySideState::kPresent &&
                             delta.laterState == EntitySideState::kPresent;
    switch (delta.change) {
    case EntityChange::kRemoved:
        // All criteria for 'removal': the old side is present, the new side is fully captured and absent, the
        // scope allows inference in this direction, and the pairing confidence is not 'uncertain'. Partition
        // accounts are settled by envelope, so this reads the account rather than the original bool.
        return removalInferable && delta.earlierState == EntitySideState::kPresent &&
               delta.laterState == EntitySideState::kAbsentCovered &&
               delta.matchConfidence != MatchConfidence::kUncertain && account.comparable &&
               account.laterPresent && account.laterUsableForAbsence &&
               account.laterStatus == CollectionStatus::kSuccess;
    case EntityChange::kAdded:
        return additionInferable && delta.laterState == EntitySideState::kPresent &&
               delta.earlierState == EntitySideState::kAbsentCovered &&
               delta.matchConfidence != MatchConfidence::kUncertain && account.comparable &&
               account.earlierPresent && account.earlierUsableForAbsence &&
               account.earlierStatus == CollectionStatus::kSuccess;
    case EntityChange::kUnchanged:
        // Normalized fields (same image, different base address) can remain in the manifest; actual changes, unknowns, or incomparables cannot.
        return kBothPresent && !anyFieldChange(delta, FieldChange::kChanged) &&
               !anyFieldChange(delta, FieldChange::kUnknown) &&
               !anyFieldChange(delta, FieldChange::kNotComparable);
    case EntityChange::kModified:
        return kBothPresent && anyFieldChange(delta, FieldChange::kChanged);
    case EntityChange::kPartiallyComparable:
        return kBothPresent && !anyFieldChange(delta, FieldChange::kChanged) &&
               (anyFieldChange(delta, FieldChange::kUnknown) ||
                anyFieldChange(delta, FieldChange::kNotComparable));
    case EntityChange::kInsufficientCoverage:
        return (delta.earlierState == EntitySideState::kPresent &&
                delta.laterState == EntitySideState::kUnknownCoverage) ||
               (delta.laterState == EntitySideState::kPresent &&
                delta.earlierState == EntitySideState::kUnknownCoverage);
    case EntityChange::kNotComparable:
        // If both sides are present yet 'incomparable', the pairing logic contradicts the conclusion; furthermore, a reason must be provided.
        return !kBothPresent && !delta.limitationKeys.empty();
    }
    return false;
}

} // namespace

bool checkComparisonSelfConsistency(const SnapshotComparison& comparison) {
    std::size_t unchanged = 0;
    std::size_t partially = 0;
    std::size_t modified = 0;
    std::size_t added = 0;
    std::size_t removed = 0;
    std::size_t notComparable = 0;
    std::size_t insufficient = 0;
    for (const EntityDelta& delta : comparison.deltas) {
        switch (delta.change) {
        case EntityChange::kUnchanged:            ++unchanged; break;
        case EntityChange::kPartiallyComparable:  ++partially; break;
        case EntityChange::kModified:             ++modified; break;
        case EntityChange::kAdded:                ++added; break;
        case EntityChange::kRemoved:              ++removed; break;
        case EntityChange::kNotComparable:        ++notComparable; break;
        case EntityChange::kInsufficientCoverage: ++insufficient; break;
        }
    }
    if (partially != comparison.partiallyComparableCount || modified != comparison.modifiedCount ||
        added != comparison.addedCount || removed != comparison.removedCount ||
        notComparable != comparison.notComparableCount ||
        insufficient != comparison.insufficientCoverageCount) {
        return false;
    }
    const std::size_t kPublished = comparison.unchangedCount + comparison.partiallyComparableCount +
                                  comparison.modifiedCount + comparison.addedCount +
                                  comparison.removedCount + comparison.notComparableCount +
                                  comparison.insufficientCoverageCount;
    // When emitUnchanged is false, unchanged rows do not enter deltas; this is the only
    // allowed gap. Otherwise, the row count must strictly equal the sum of the counts.
    const bool kUnchangedRowsPresent = unchanged == comparison.unchangedCount;
    if (kUnchangedRowsPresent) {
        if (comparison.deltas.size() != kPublished) {
            return false;
        }
    } else if (unchanged == 0U) {
        if (comparison.deltas.size() + comparison.unchangedCount != kPublished) {
            return false;
        }
    } else {
        return false;
    }

    const bool kMachineMismatch = hasKey(comparison.limitationKeys, "snapshot.limitation.machineMismatch");
    const bool kRemovalInferable = removalInferable(comparison.scope) && !kMachineMismatch;
    const bool kAdditionInferable = additionInferable(comparison.scope) && !kMachineMismatch;

    for (const EntityDelta& delta : comparison.deltas) {
        const PartitionAccount* account = findAccountFor(comparison, delta.partitionId);
        if (account == nullptr) {
            return false;  // Every conclusion must be attached to a collection ledger.
        }
        if (!rowConsistent(delta, *account, kRemovalInferable, kAdditionInferable)) {
            return false;
        }
    }

    bool anyComparablePartition = false;
    bool allPartitionsClean = true;
    for (const PartitionAccount& account : comparison.partitions) {
        // Account self-check: comparable if both sides carry observation and entity types match.
        const bool kBothObserved = statusCarriesObservation(account.earlierStatus) &&
                                  statusCarriesObservation(account.laterStatus);
        const bool kKindMismatch = hasKey(account.limitationKeys, "snapshot.partition.kindMismatch");
        if (account.comparable != (kBothObserved && !kKindMismatch)) {
            return false;
        }
        // 'Eligible but confirmed absent' can only originate from a fully successful collection; Partial or failed states are invalid.
        if (account.earlierUsableForAbsence && account.earlierStatus != CollectionStatus::kSuccess) {
            return false;
        }
        if (account.laterUsableForAbsence && account.laterStatus != CollectionStatus::kSuccess) {
            return false;
        }
        if (!account.earlierPresent && account.earlierStatus != CollectionStatus::kNotCollected) {
            return false;
        }
        if (!account.laterPresent && account.laterStatus != CollectionStatus::kNotCollected) {
            return false;
        }

        std::size_t rowsCompared = 0;
        std::size_t rowsNotComparable = 0;
        bool partitionDifference = false;
        for (const EntityDelta& delta : comparison.deltas) {
            if (delta.partitionId != account.partitionId) {
                continue;
            }
            if (delta.change == EntityChange::kNotComparable ||
                delta.change == EntityChange::kInsufficientCoverage) {
                ++rowsNotComparable;
            } else {
                ++rowsCompared;
            }
            if (delta.change == EntityChange::kModified || delta.change == EntityChange::kAdded ||
                delta.change == EntityChange::kRemoved) {
                partitionDifference = true;
            }
        }
        if (rowsNotComparable != account.entitiesNotComparable) {
            return false;
        }
        if (kUnchangedRowsPresent && rowsCompared != account.entitiesCompared) {
            return false;
        }
        AnalysisConclusion expected = AnalysisConclusion::kNoDifferenceObserved;
        if (!account.comparable) {
            expected = AnalysisConclusion::kNoEvidence;
        } else if (partitionDifference) {
            expected = AnalysisConclusion::kDifferenceObserved;
        } else if (account.entitiesNotComparable != 0U || !account.earlierUsableForAbsence ||
                   !account.laterUsableForAbsence ||
                   comparison.scope != ScopeComparability::kIdentical) {
            expected = AnalysisConclusion::kIndeterminate;
        }
        if (account.conclusion != expected) {
            return false;
        }
        if (account.comparable) {
            anyComparablePartition = true;
        }
        if (!account.comparable || !account.earlierUsableForAbsence ||
            !account.laterUsableForAbsence) {
            allPartitionsClean = false;
        }
    }

    const bool kDifferenceFound = comparison.addedCount != 0U || comparison.removedCount != 0U ||
                                 comparison.modifiedCount != 0U;
    const bool kQualifiesNoDifference =
        anyComparablePartition && !kDifferenceFound && allPartitionsClean &&
        comparison.scope == ScopeComparability::kIdentical && !kMachineMismatch &&
        comparison.notComparableCount == 0U && comparison.insufficientCoverageCount == 0U &&
        comparison.partiallyComparableCount == 0U;
    switch (comparison.conclusion) {
    case AnalysisConclusion::kNoEvidence:
        return !anyComparablePartition;
    case AnalysisConclusion::kDifferenceObserved:
        return anyComparablePartition && kDifferenceFound;
    case AnalysisConclusion::kNoDifferenceObserved:
        return kQualifiesNoDifference;
    case AnalysisConclusion::kIndeterminate:
        return anyComparablePartition && !kDifferenceFound && !kQualifiesNoDifference;
    }
    return false;
}

// ---------------------------------------------------------------------------
// D-08: Expected change list verification.
// ---------------------------------------------------------------------------
const char* expectationOutcomeName(ExpectationOutcome value) noexcept {
    switch (value) {
    case ExpectationOutcome::kNotAssessed: return "NotAssessed";
    case ExpectationOutcome::kSatisfied:   return "Satisfied";
    case ExpectationOutcome::kViolated:    return "Violated";
    }
    return "NotAssessed";
}

namespace {

// D-08: Declarations and result rows must be matched using the **same key**. For strong-identity EntityDelta, use identityKey; for
// weak-identity, identityKey is empty and only candidateKey exists. The old implementation compared only identityKey, causing any
// declaration with an empty identityKey to collide with the "first weak-identity object," effectively verifying an unnamed object.
std::string deltaMatchKey(const EntityDelta& delta) {
    return delta.identityKey.empty() ? delta.candidateKey : delta.identityKey;
}

std::string wantMatchKey(const ExpectedChange& want) {
    return want.identityKey.empty() ? want.candidateKey : want.identityKey;
}

std::string invalidLabel(const ExpectedChange& want) {
    const std::string kKey = wantMatchKey(want);
    return want.partitionId + "/" + (kKey.empty() ? std::string("<no-identity>") : kKey);
}

} // namespace

ExpectationCheck checkExpectedChanges(const SnapshotComparison& comparison,
                                      const std::vector<ExpectedChange>& expected) {
    ExpectationCheck check;
    for (const ExpectedChange& want : expected) {
        const std::string kWantKey = wantMatchKey(want);
        if (kWantKey.empty()) {
            // Declarations not pointing to any object cannot be verified. D-08 requires 'pre-listing the fields and
            // object identities of this change'; an empty identity fails this requirement and cannot count as verified.
            check.invalid.push_back(invalidLabel(want));
            continue;
        }
        const PartitionAccount* account = findAccountFor(comparison, want.partitionId);
        if (account == nullptr || !account->comparable) {
            // The target partition could not be compared at all: neither "observed" nor "unchanged when it should have changed" applies.
            check.invalid.push_back(invalidLabel(want));
            continue;
        }
        const EntityDelta* found = nullptr;
        for (const EntityDelta& delta : comparison.deltas) {
            if (delta.partitionId != want.partitionId || deltaMatchKey(delta) != kWantKey) {
                continue;
            }
            found = &delta;
            break;
        }
        if (found == nullptr || found->change != want.change) {
            check.missing.push_back(kWantKey);
            continue;
        }
        bool fieldsOk = true;
        for (const std::string& fieldName : want.fieldNames) {
            bool hit = false;
            for (const FieldDelta& field : found->fields) {
                if (field.name == fieldName && field.change == FieldChange::kChanged) {
                    hit = true;
                    break;
                }
            }
            if (!hit) {
                fieldsOk = false;
                break;
            }
        }
        if (fieldsOk) {
            check.satisfied.push_back(kWantKey);
        } else {
            check.missing.push_back(kWantKey);
        }
    }

    for (const EntityDelta& delta : comparison.deltas) {
        if (delta.change != EntityChange::kModified && delta.change != EntityChange::kAdded &&
            delta.change != EntityChange::kRemoved) {
            continue;
        }
        const std::string kDeltaKey = deltaMatchKey(delta);
        bool declared = false;
        for (const ExpectedChange& want : expected) {
            if (want.partitionId == delta.partitionId && wantMatchKey(want) == kDeltaKey &&
                !kDeltaKey.empty()) {
                declared = true;
                break;
            }
        }
        if (!declared) {
            // "Other changes are recorded but not attributed": only list the keys here, without adding any explanation.
            check.unexpectedKeys.push_back(kDeltaKey);
        }
    }

    // D-08: Three-state logic. "Nothing declared" and "no evidence in this comparison" are not passes. The old implementation had
    // allSatisfied return true for empty lists and never checked if the comparison had evidence, allowing zero evidence to pass.
    if (expected.empty() || comparison.conclusion == AnalysisConclusion::kNoEvidence ||
        !comparison.selfCheckPassed) {
        check.outcome = ExpectationOutcome::kNotAssessed;
    } else if (check.missing.empty() && check.invalid.empty() &&
               check.satisfied.size() == expected.size()) {
        check.outcome = ExpectationOutcome::kSatisfied;
    } else {
        check.outcome = ExpectationOutcome::kViolated;
    }
    check.allSatisfied = check.outcome == ExpectationOutcome::kSatisfied;
    return check;
}

// ---------------------------------------------------------------------------
// D-06: Persistent
// ---------------------------------------------------------------------------
namespace {

bool parseCollectionStatusName(std::string_view text, CollectionStatus& out) noexcept {
    if (text == "NotCollected") { out = CollectionStatus::kNotCollected; return true; }
    if (text == "Success")      { out = CollectionStatus::kSuccess; return true; }
    if (text == "Partial")      { out = CollectionStatus::kPartial; return true; }
    if (text == "Unsupported")  { out = CollectionStatus::kUnsupported; return true; }
    if (text == "AccessDenied") { out = CollectionStatus::kAccessDenied; return true; }
    if (text == "Timeout")      { out = CollectionStatus::kTimeout; return true; }
    if (text == "Error")        { out = CollectionStatus::kError; return true; }
    return false;
}

bool parseSourceOriginName(std::string_view text, SourceOrigin& out) noexcept {
    if (text == "Unknown")       { out = SourceOrigin::kUnknown; return true; }
    if (text == "LiveKernel")    { out = SourceOrigin::kLiveKernel; return true; }
    if (text == "LiveUserMode")  { out = SourceOrigin::kLiveUserMode; return true; }
    if (text == "ExternalFile")  { out = SourceOrigin::kExternalFile; return true; }
    if (text == "OfflineSample") { out = SourceOrigin::kOfflineSample; return true; }
    return false;
}

bool parseCaptureModeName(std::string_view text, CaptureMode& out) noexcept {
    if (text == "Unknown")   { out = CaptureMode::kUnknown; return true; }
    if (text == "Snapshot")  { out = CaptureMode::kSnapshot; return true; }
    if (text == "Streaming") { out = CaptureMode::kStreaming; return true; }
    if (text == "Replay")    { out = CaptureMode::kReplay; return true; }
    return false;
}

bool parseObjectKindName(std::string_view text, ObjectKind& out) noexcept {
    if (text == "Unknown")    { out = ObjectKind::kUnknown; return true; }
    if (text == "Process")    { out = ObjectKind::kProcess; return true; }
    if (text == "Thread")     { out = ObjectKind::kThread; return true; }
    if (text == "Driver")     { out = ObjectKind::kDriver; return true; }
    if (text == "Module")     { out = ObjectKind::kModule; return true; }
    if (text == "File")       { out = ObjectKind::kFile; return true; }
    if (text == "Handle")     { out = ObjectKind::kHandle; return true; }
    if (text == "Connection") { out = ObjectKind::kConnection; return true; }
    if (text == "Device")     { out = ObjectKind::kDevice; return true; }
    if (text == "Service")    { out = ObjectKind::kService; return true; }
    return false;
}

bool parseU64FormatName(std::string_view text, U64Format& out) noexcept {
    if (text == "Decimal")    { out = U64Format::kDecimal; return true; }
    if (text == "HexAddress") { out = U64Format::kHexAddress; return true; }
    return false;
}

const char* u64FormatName(U64Format value) noexcept {
    return value == U64Format::kHexAddress ? "HexAddress" : "Decimal";
}

JsonValue writeOptional(const OptionalU64& value, U64Format format) {
    return JsonValue::makeOptionalU64Text(value, format);
}

JsonValue writeEnvelopeJson(const EvidenceEnvelope& envelope) {
    JsonObject source;
    source.emplace_back("collectorId", JsonValue::makeString(envelope.source.collectorId));
    source.emplace_back("collectorVersion",
                        JsonValue::makeU64Text(envelope.source.collectorVersion, U64Format::kDecimal));
    source.emplace_back("sourceGroup", JsonValue::makeString(envelope.source.sourceGroup));
    source.emplace_back("origin", JsonValue::makeString(sourceOriginName(envelope.source.origin)));
    source.emplace_back("dependsOn", JsonValue::makeString(envelope.source.dependsOn));

    JsonObject window;
    window.emplace_back("startUtc100ns", writeOptional(envelope.window.startUtc100ns, U64Format::kDecimal));
    window.emplace_back("endUtc100ns", writeOptional(envelope.window.endUtc100ns, U64Format::kDecimal));
    window.emplace_back("startMonotonic", writeOptional(envelope.window.startMonotonic, U64Format::kDecimal));
    window.emplace_back("endMonotonic", writeOptional(envelope.window.endMonotonic, U64Format::kDecimal));
    window.emplace_back("monotonicFrequency",
                        writeOptional(envelope.window.monotonicFrequency, U64Format::kDecimal));
    window.emplace_back("machineId", JsonValue::makeString(envelope.window.machineId));
    window.emplace_back("bootId", JsonValue::makeString(envelope.window.bootId));
    window.emplace_back("sessionId", JsonValue::makeString(envelope.window.sessionId));
    window.emplace_back("mode", JsonValue::makeString(captureModeName(envelope.window.mode)));

    JsonObject outcome;
    outcome.emplace_back("status", JsonValue::makeString(collectionStatusName(envelope.outcome.status)));
    outcome.emplace_back("nativeCode", writeOptional(envelope.outcome.nativeCode, U64Format::kDecimal));
    outcome.emplace_back("nativeCodeDomain", JsonValue::makeString(envelope.outcome.nativeCodeDomain));
    outcome.emplace_back("message", JsonValue::makeString(envelope.outcome.message));

    const CoverageAccount& coverage = envelope.coverage;
    JsonObject cov;
    cov.emplace_back("requestedBegin", writeOptional(coverage.requestedBegin, U64Format::kDecimal));
    cov.emplace_back("requestedEnd", writeOptional(coverage.requestedEnd, U64Format::kDecimal));
    cov.emplace_back("processedBegin", writeOptional(coverage.processedBegin, U64Format::kDecimal));
    cov.emplace_back("processedEnd", writeOptional(coverage.processedEnd, U64Format::kDecimal));
    cov.emplace_back("succeeded", JsonValue::makeU64Text(coverage.succeeded, U64Format::kDecimal));
    cov.emplace_back("failed", JsonValue::makeU64Text(coverage.failed, U64Format::kDecimal));
    cov.emplace_back("skipped", JsonValue::makeU64Text(coverage.skipped, U64Format::kDecimal));
    cov.emplace_back("truncated", JsonValue::makeU64Text(coverage.truncated, U64Format::kDecimal));
    cov.emplace_back("limitHit", JsonValue::makeBool(coverage.limitHit));
    cov.emplace_back("limit", writeOptional(coverage.limit, U64Format::kDecimal));
    cov.emplace_back("cancelled", JsonValue::makeBool(coverage.cancelled));
    cov.emplace_back("totalKnown", writeOptional(coverage.totalKnown, U64Format::kDecimal));

    JsonObject root;
    root.emplace_back("source", JsonValue::makeObject(std::move(source)));
    root.emplace_back("window", JsonValue::makeObject(std::move(window)));
    root.emplace_back("outcome", JsonValue::makeObject(std::move(outcome)));
    root.emplace_back("coverage", JsonValue::makeObject(std::move(cov)));
    root.emplace_back("evidenceId", JsonValue::makeString(envelope.evidenceId));
    return JsonValue::makeObject(std::move(root));
}

JsonValue writeDriverIdentity(const DriverInstanceId& id) {
    JsonObject obj;
    obj.emplace_back("bootId", JsonValue::makeString(id.bootId));
    obj.emplace_back("imagePath", JsonValue::makeString(id.imagePath));
    obj.emplace_back("imageBase", writeOptional(id.imageBase, U64Format::kHexAddress));
    obj.emplace_back("imageSize", writeOptional(id.imageSize, U64Format::kDecimal));
    obj.emplace_back("timeDateStamp", writeOptional(id.timeDateStamp, U64Format::kDecimal));
    obj.emplace_back("checksum", writeOptional(id.checksum, U64Format::kDecimal));
    obj.emplace_back("pdbSignature", JsonValue::makeString(id.pdbSignature));
    obj.emplace_back("loadOrderIndex", writeOptional(id.loadOrderIndex, U64Format::kDecimal));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue writeProcessIdentity(const ProcessInstanceId& id) {
    JsonObject obj;
    obj.emplace_back("bootId", JsonValue::makeString(id.bootId));
    obj.emplace_back("pid", writeOptional(id.pid, U64Format::kDecimal));
    obj.emplace_back("createTime100ns", writeOptional(id.createTime100ns, U64Format::kDecimal));
    obj.emplace_back("eprocessAddress", writeOptional(id.eprocessAddress, U64Format::kHexAddress));
    obj.emplace_back("imageName", JsonValue::makeString(id.imageName));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue writeThreadIdentity(const ThreadInstanceId& id) {
    JsonObject obj;
    obj.emplace_back("process", writeProcessIdentity(id.process));
    obj.emplace_back("tid", writeOptional(id.tid, U64Format::kDecimal));
    obj.emplace_back("createTime100ns", writeOptional(id.createTime100ns, U64Format::kDecimal));
    obj.emplace_back("ethreadAddress", writeOptional(id.ethreadAddress, U64Format::kHexAddress));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue writeFileIdentityJson(const FileIdentity& id) {
    JsonObject obj;
    obj.emplace_back("path", JsonValue::makeString(id.path));
    obj.emplace_back("volumeSerial", writeOptional(id.volumeSerial, U64Format::kDecimal));
    obj.emplace_back("fileId", JsonValue::makeString(id.fileId));
    obj.emplace_back("sizeBytes", writeOptional(id.sizeBytes, U64Format::kDecimal));
    obj.emplace_back("lastWriteUtc100ns", writeOptional(id.lastWriteUtc100ns, U64Format::kDecimal));
    obj.emplace_back("contentHash", JsonValue::makeString(id.contentHash));
    return JsonValue::makeObject(std::move(obj));
}

JsonValue writeLogicalIdentity(const LogicalObjectId& id) {
    JsonObject obj;
    obj.emplace_back("domain", JsonValue::makeString(id.domain));
    obj.emplace_back("name", JsonValue::makeString(id.name));
    obj.emplace_back("scopeKey", JsonValue::makeString(id.scopeKey));
    return JsonValue::makeObject(std::move(obj));
}

// ---- Read Context ----
struct ReadCtx final {
    SnapshotLoadStatus status = SnapshotLoadStatus::kOk;
    std::string detail;
    std::vector<std::string> unknownPaths;

    bool fail(SnapshotLoadStatus s, std::string d) {
        if (status == SnapshotLoadStatus::kOk) {
            status = s;
            detail = std::move(d);
        }
        return false;
    }
    bool ok() const noexcept { return status == SnapshotLoadStatus::kOk; }
};

void collectUnknown(const JsonObject& obj,
                    const std::vector<std::string>& known,
                    const std::string& path,
                    JsonObject* sink,
                    ReadCtx& ctx) {
    for (const auto& member : obj) {
        if (std::find(known.begin(), known.end(), member.first) != known.end()) {
            continue;
        }
        ctx.unknownPaths.push_back(path + "." + member.first);
        if (sink != nullptr) {
            sink->emplace_back(member.first, member.second);
        }
    }
}

bool readString(const JsonValue& obj, const char* name, std::string& out, ReadCtx& ctx,
                bool required, const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        if (required) {
            return ctx.fail(SnapshotLoadStatus::kMissingRequiredField, path + "." + name);
        }
        return true;
    }
    if (!value->tryGetString(out)) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + "." + name);
    }
    return true;
}

bool readOptU64(const JsonValue& obj, const char* name, OptionalU64& out, ReadCtx& ctx,
                const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr) {
        return true;  // Legacy fixtures may be entirely absent; absence implies 'unknown'.
    }
    if (!value->tryGetOptionalU64(out)) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + "." + name);
    }
    return true;
}

bool readU64(const JsonValue& obj, const char* name, std::uint64_t& out, ReadCtx& ctx,
             const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        return true;
    }
    if (!value->tryGetU64(out)) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + "." + name);
    }
    return true;
}

bool readBool(const JsonValue& obj, const char* name, bool& out, ReadCtx& ctx,
              const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        return true;
    }
    if (!value->tryGetBool(out)) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + "." + name);
    }
    return true;
}

// Enums always follow 'unknown name = explicit failure'; never silently fall back to a default enum value.
template <typename Enum, typename Parser>
bool readEnum(const JsonValue& obj, const char* name, Enum& out, Parser parser, ReadCtx& ctx,
              const std::string& path) {
    const JsonValue* value = obj.find(name);
    if (value == nullptr || value->isNull()) {
        return true;
    }
    std::string text;
    if (!value->tryGetString(text)) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + "." + name);
    }
    if (!parser(text, out)) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + "." + name + "=" + text);
    }
    return true;
}

bool readEnvelopeJson(const JsonValue& node, EvidenceEnvelope& envelope, ReadCtx& ctx,
                      const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path);
    }
    if (const JsonValue* source = node.find("source"); source != nullptr) {
        if (source->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + ".source");
        }
        std::uint64_t version = 0;
        if (!readString(*source, "collectorId", envelope.source.collectorId, ctx, false, path) ||
            !readU64(*source, "collectorVersion", version, ctx, path) ||
            !readString(*source, "sourceGroup", envelope.source.sourceGroup, ctx, false, path) ||
            !readEnum(*source, "origin", envelope.source.origin, parseSourceOriginName, ctx, path) ||
            !readString(*source, "dependsOn", envelope.source.dependsOn, ctx, false, path)) {
            return false;
        }
        if (version > 0xFFFFFFFFULL) {
            return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + ".source.collectorVersion");
        }
        envelope.source.collectorVersion = static_cast<std::uint32_t>(version);
    }
    if (const JsonValue* window = node.find("window"); window != nullptr) {
        if (window->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + ".window");
        }
        CaptureWindow& w = envelope.window;
        if (!readOptU64(*window, "startUtc100ns", w.startUtc100ns, ctx, path) ||
            !readOptU64(*window, "endUtc100ns", w.endUtc100ns, ctx, path) ||
            !readOptU64(*window, "startMonotonic", w.startMonotonic, ctx, path) ||
            !readOptU64(*window, "endMonotonic", w.endMonotonic, ctx, path) ||
            !readOptU64(*window, "monotonicFrequency", w.monotonicFrequency, ctx, path) ||
            !readString(*window, "machineId", w.machineId, ctx, false, path) ||
            !readString(*window, "bootId", w.bootId, ctx, false, path) ||
            !readString(*window, "sessionId", w.sessionId, ctx, false, path) ||
            !readEnum(*window, "mode", w.mode, parseCaptureModeName, ctx, path)) {
            return false;
        }
    }
    if (const JsonValue* outcome = node.find("outcome"); outcome != nullptr) {
        if (outcome->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + ".outcome");
        }
        CollectionOutcome& o = envelope.outcome;
        if (!readEnum(*outcome, "status", o.status, parseCollectionStatusName, ctx, path) ||
            !readOptU64(*outcome, "nativeCode", o.nativeCode, ctx, path) ||
            !readString(*outcome, "nativeCodeDomain", o.nativeCodeDomain, ctx, false, path) ||
            !readString(*outcome, "message", o.message, ctx, false, path)) {
            return false;
        }
    }
    if (const JsonValue* cov = node.find("coverage"); cov != nullptr) {
        if (cov->asObject() == nullptr) {
            return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path + ".coverage");
        }
        CoverageAccount& c = envelope.coverage;
        if (!readOptU64(*cov, "requestedBegin", c.requestedBegin, ctx, path) ||
            !readOptU64(*cov, "requestedEnd", c.requestedEnd, ctx, path) ||
            !readOptU64(*cov, "processedBegin", c.processedBegin, ctx, path) ||
            !readOptU64(*cov, "processedEnd", c.processedEnd, ctx, path) ||
            !readU64(*cov, "succeeded", c.succeeded, ctx, path) ||
            !readU64(*cov, "failed", c.failed, ctx, path) ||
            !readU64(*cov, "skipped", c.skipped, ctx, path) ||
            !readU64(*cov, "truncated", c.truncated, ctx, path) ||
            !readBool(*cov, "limitHit", c.limitHit, ctx, path) ||
            !readOptU64(*cov, "limit", c.limit, ctx, path) ||
            !readBool(*cov, "cancelled", c.cancelled, ctx, path) ||
            !readOptU64(*cov, "totalKnown", c.totalKnown, ctx, path)) {
            return false;
        }
    }
    return readString(node, "evidenceId", envelope.evidenceId, ctx, false, path);
}

bool readDriverIdentity(const JsonValue& node, DriverInstanceId& id, ReadCtx& ctx,
                        const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path);
    }
    return readString(node, "bootId", id.bootId, ctx, false, path) &&
           readString(node, "imagePath", id.imagePath, ctx, false, path) &&
           readOptU64(node, "imageBase", id.imageBase, ctx, path) &&
           readOptU64(node, "imageSize", id.imageSize, ctx, path) &&
           readOptU64(node, "timeDateStamp", id.timeDateStamp, ctx, path) &&
           readOptU64(node, "checksum", id.checksum, ctx, path) &&
           readString(node, "pdbSignature", id.pdbSignature, ctx, false, path) &&
           readOptU64(node, "loadOrderIndex", id.loadOrderIndex, ctx, path);
}

bool readProcessIdentity(const JsonValue& node, ProcessInstanceId& id, ReadCtx& ctx,
                         const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path);
    }
    return readString(node, "bootId", id.bootId, ctx, false, path) &&
           readOptU64(node, "pid", id.pid, ctx, path) &&
           readOptU64(node, "createTime100ns", id.createTime100ns, ctx, path) &&
           readOptU64(node, "eprocessAddress", id.eprocessAddress, ctx, path) &&
           readString(node, "imageName", id.imageName, ctx, false, path);
}

bool readThreadIdentity(const JsonValue& node, ThreadInstanceId& id, ReadCtx& ctx,
                        const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path);
    }
    if (const JsonValue* process = node.find("process"); process != nullptr) {
        if (!readProcessIdentity(*process, id.process, ctx, path + ".process")) {
            return false;
        }
    }
    return readOptU64(node, "tid", id.tid, ctx, path) &&
           readOptU64(node, "createTime100ns", id.createTime100ns, ctx, path) &&
           readOptU64(node, "ethreadAddress", id.ethreadAddress, ctx, path);
}

bool readFileIdentityJson(const JsonValue& node, FileIdentity& id, ReadCtx& ctx,
                          const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path);
    }
    return readString(node, "path", id.path, ctx, false, path) &&
           readOptU64(node, "volumeSerial", id.volumeSerial, ctx, path) &&
           readString(node, "fileId", id.fileId, ctx, false, path) &&
           readOptU64(node, "sizeBytes", id.sizeBytes, ctx, path) &&
           readOptU64(node, "lastWriteUtc100ns", id.lastWriteUtc100ns, ctx, path) &&
           readString(node, "contentHash", id.contentHash, ctx, false, path);
}

bool readLogicalIdentity(const JsonValue& node, LogicalObjectId& id, ReadCtx& ctx,
                         const std::string& path) {
    if (node.asObject() == nullptr) {
        return ctx.fail(SnapshotLoadStatus::kInvalidFieldValue, path);
    }
    return readString(node, "domain", id.domain, ctx, false, path) &&
           readString(node, "name", id.name, ctx, false, path) &&
           readString(node, "scopeKey", id.scopeKey, ctx, false, path);
}

const std::vector<std::string>& rootKnownKeys() {
    static const std::vector<std::string> kKeys = {
        "schema", "versionMajor", "versionMinor", "snapshotId",
        "envelope", "scope", "partitions", "modules", "entities"};
    return kKeys;
}

const std::vector<std::string>& entityKnownKeys() {
    static const std::vector<std::string> kKeys = {
        "partitionId", "kind", "rawRecordId", "displayOrder",
        "process", "thread", "driver", "file", "logical", "fields"};
    return kKeys;
}

} // namespace

std::string writeSnapshotJson(const Snapshot& snapshot, unsigned indent) {
    JsonObject root;
    root.emplace_back("schema", JsonValue::makeString(kSnapshotSchemaId));
    root.emplace_back("versionMajor", JsonValue::makeU64Text(kSnapshotSchemaMajor, U64Format::kDecimal));
    root.emplace_back("versionMinor", JsonValue::makeU64Text(kSnapshotSchemaMinor, U64Format::kDecimal));
    root.emplace_back("snapshotId", JsonValue::makeString(snapshot.snapshotId));
    root.emplace_back("envelope", writeEnvelopeJson(snapshot.envelope));

    JsonObject scope;
    scope.emplace_back("scopeId", JsonValue::makeString(snapshot.scope.scopeId));
    scope.emplace_back("declared", JsonValue::makeBool(snapshot.scope.declared));
    scope.emplace_back("wholeDomain", JsonValue::makeBool(snapshot.scope.wholeDomain));
    JsonArray selectors;
    for (const std::string& selector : snapshot.scope.selectors) {
        selectors.push_back(JsonValue::makeString(selector));
    }
    scope.emplace_back("selectors", JsonValue::makeArray(std::move(selectors)));
    root.emplace_back("scope", JsonValue::makeObject(std::move(scope)));

    JsonArray partitions;
    for (const SnapshotPartition& partition : snapshot.partitions) {
        JsonObject obj;
        obj.emplace_back("partitionId", JsonValue::makeString(partition.partitionId));
        obj.emplace_back("kind", JsonValue::makeString(objectKindName(partition.kind)));
        obj.emplace_back("coversScope", JsonValue::makeBool(partition.coversScope));
        obj.emplace_back("envelope", writeEnvelopeJson(partition.envelope));
        partitions.push_back(JsonValue::makeObject(std::move(obj)));
    }
    root.emplace_back("partitions", JsonValue::makeArray(std::move(partitions)));

    JsonArray modules;
    for (const SnapshotModule& module : snapshot.modules) {
        JsonObject obj;
        obj.emplace_back("moduleId", JsonValue::makeString(module.moduleId));
        obj.emplace_back("imageBase", writeOptional(module.imageBase, U64Format::kHexAddress));
        obj.emplace_back("imageSize", writeOptional(module.imageSize, U64Format::kDecimal));
        obj.emplace_back("identity", writeDriverIdentity(module.identity));
        modules.push_back(JsonValue::makeObject(std::move(obj)));
    }
    root.emplace_back("modules", JsonValue::makeArray(std::move(modules)));

    JsonArray entities;
    for (const SnapshotEntity& entity : snapshot.entities) {
        JsonObject obj;
        obj.emplace_back("partitionId", JsonValue::makeString(entity.partitionId));
        obj.emplace_back("kind", JsonValue::makeString(objectKindName(entity.kind)));
        obj.emplace_back("rawRecordId", JsonValue::makeString(entity.rawRecordId));
        obj.emplace_back("displayOrder",
                         JsonValue::makeU64Text(static_cast<std::uint64_t>(entity.displayOrder),
                                                U64Format::kDecimal));
        obj.emplace_back("process", writeProcessIdentity(entity.process));
        obj.emplace_back("thread", writeThreadIdentity(entity.thread));
        obj.emplace_back("driver", writeDriverIdentity(entity.driver));
        obj.emplace_back("file", writeFileIdentityJson(entity.file));
        obj.emplace_back("logical", writeLogicalIdentity(entity.logical));

        JsonArray fields;
        for (const EntityField& field : entity.fields) {
            JsonObject item;
            item.emplace_back("name", JsonValue::makeString(field.name));
            item.emplace_back("semantics", JsonValue::makeString(fieldSemanticsName(field.semantics)));
            item.emplace_back("kind", JsonValue::makeString(fieldValueKindName(field.kind)));
            item.emplace_back("text", JsonValue::makeString(field.text));
            item.emplace_back("number", writeOptional(field.number, field.numberFormat));
            item.emplace_back("numberFormat", JsonValue::makeString(u64FormatName(field.numberFormat)));
            item.emplace_back("redaction", JsonValue::makeString(redactionClassName(field.redaction)));
            fields.push_back(JsonValue::makeObject(std::move(item)));
        }
        obj.emplace_back("fields", JsonValue::makeArray(std::move(fields)));

        // D-06: Unknown optional fields preserved upon reading are written back as-is, ensuring extensions from others are not silently dropped.
        for (const auto& unknown : entity.unknownFields) {
            obj.emplace_back(unknown.first, unknown.second);
        }
        entities.push_back(JsonValue::makeObject(std::move(obj)));
    }
    root.emplace_back("entities", JsonValue::makeArray(std::move(entities)));

    for (const auto& unknown : snapshot.unknownFields) {
        root.emplace_back(unknown.first, unknown.second);
    }
    return writeJson(JsonValue::makeObject(std::move(root)), indent);
}

SnapshotLoadResult readSnapshotJson(std::string_view text) {
    return readSnapshotJson(text, snapshotJsonLimits());
}

SnapshotLoadResult readSnapshotJson(std::string_view text, const JsonLimits& limits) {
    SnapshotLoadResult result;
    if (text.empty()) {
        result.status = SnapshotLoadStatus::kEmptyInput;
        result.errorDetail = "empty";
        return result;
    }
    const JsonParseResult kParsed = parseJson(text, limits);
    if (!kParsed.ok()) {
        // D-06: A **valid** document exceeding the parsing limit and a corrupted document must be
        // in two distinct states. Collapsing both into MalformedJson would make 'this snapshot is
        // too large, raise the limit' and 'this file is corrupted' appear identical in the UI.
        switch (kParsed.status) {
        case JsonParseStatus::kSizeLimit:
        case JsonParseStatus::kNodeLimit:
        case JsonParseStatus::kDepthLimit:
            result.status = SnapshotLoadStatus::kLimitExceeded;
            break;
        default:
            result.status = SnapshotLoadStatus::kMalformedJson;
            break;
        }
        result.errorDetail = jsonParseStatusName(kParsed.status);  // Raw error code, not beautified.
        result.errorOffset = kParsed.errorOffset;
        return result;
    }
    const JsonValue& root = kParsed.value;
    if (root.asObject() == nullptr) {
        result.status = SnapshotLoadStatus::kMalformedJson;
        result.errorDetail = "root is not an object";
        return result;
    }

    const JsonValue* schema = root.find("schema");
    std::string schemaText;
    if (schema == nullptr || !schema->tryGetString(schemaText)) {
        result.status = SnapshotLoadStatus::kMissingSchema;
        result.errorDetail = "schema";
        return result;
    }
    if (schemaText != kSnapshotSchemaId) {
        result.status = SnapshotLoadStatus::kWrongSchemaId;
        result.errorDetail = schemaText;
        return result;
    }
    const JsonValue* majorNode = root.find("versionMajor");
    std::uint64_t major = 0;
    if (majorNode == nullptr || !majorNode->tryGetU64(major)) {
        result.status = SnapshotLoadStatus::kMissingSchema;
        result.errorDetail = "versionMajor";
        return result;
    }
    std::uint64_t minor = 0;
    if (const JsonValue* minorNode = root.find("versionMinor"); minorNode != nullptr) {
        if (!minorNode->tryGetU64(minor)) {
            result.status = SnapshotLoadStatus::kInvalidFieldValue;
            result.errorDetail = "versionMinor";
            return result;
        }
    }
    result.versionMajor = static_cast<std::uint32_t>(major & 0xFFFFFFFFULL);
    result.versionMinor = static_cast<std::uint32_t>(minor & 0xFFFFFFFFULL);
    if (major != kSnapshotSchemaMajor) {
        // D-06: Unknown major version is explicitly rejected; no 'best-effort' partial parsing.
        result.status = SnapshotLoadStatus::kUnsupportedMajorVersion;
        result.errorDetail = formatU64(major, U64Format::kDecimal);
        return result;
    }

    ReadCtx ctx;
    Snapshot snapshot;
    collectUnknown(*root.asObject(), rootKnownKeys(), "root", &snapshot.unknownFields, ctx);

    if (!readString(root, "snapshotId", snapshot.snapshotId, ctx, false, "root")) {
        result.status = ctx.status;
        result.errorDetail = ctx.detail;
        return result;
    }
    if (const JsonValue* envelope = root.find("envelope"); envelope != nullptr) {
        if (!readEnvelopeJson(*envelope, snapshot.envelope, ctx, "root.envelope")) {
            result.status = ctx.status;
            result.errorDetail = ctx.detail;
            return result;
        }
    }
    if (const JsonValue* scope = root.find("scope"); scope != nullptr) {
        if (scope->asObject() == nullptr) {
            result.status = SnapshotLoadStatus::kInvalidFieldValue;
            result.errorDetail = "root.scope";
            return result;
        }
        if (!readString(*scope, "scopeId", snapshot.scope.scopeId, ctx, false, "root.scope") ||
            !readBool(*scope, "declared", snapshot.scope.declared, ctx, "root.scope") ||
            !readBool(*scope, "wholeDomain", snapshot.scope.wholeDomain, ctx, "root.scope")) {
            result.status = ctx.status;
            result.errorDetail = ctx.detail;
            return result;
        }
        if (const JsonValue* selectors = scope->find("selectors"); selectors != nullptr) {
            const JsonArray* array = selectors->asArray();
            if (array == nullptr) {
                result.status = SnapshotLoadStatus::kInvalidFieldValue;
                result.errorDetail = "root.scope.selectors";
                return result;
            }
            for (const JsonValue& item : *array) {
                std::string selector;
                if (!item.tryGetString(selector)) {
                    result.status = SnapshotLoadStatus::kInvalidFieldValue;
                    result.errorDetail = "root.scope.selectors[]";
                    return result;
                }
                snapshot.scope.selectors.push_back(std::move(selector));
            }
        }
    }
    if (const JsonValue* partitions = root.find("partitions"); partitions != nullptr) {
        const JsonArray* array = partitions->asArray();
        if (array == nullptr) {
            result.status = SnapshotLoadStatus::kInvalidFieldValue;
            result.errorDetail = "root.partitions";
            return result;
        }
        for (const JsonValue& item : *array) {
            SnapshotPartition partition;
            if (item.asObject() == nullptr) {
                result.status = SnapshotLoadStatus::kInvalidFieldValue;
                result.errorDetail = "root.partitions[]";
                return result;
            }
            if (!readString(item, "partitionId", partition.partitionId, ctx, true, "root.partitions[]") ||
                !readEnum(item, "kind", partition.kind, parseObjectKindName, ctx, "root.partitions[]") ||
                !readBool(item, "coversScope", partition.coversScope, ctx, "root.partitions[]")) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            if (const JsonValue* envelope = item.find("envelope"); envelope != nullptr) {
                if (!readEnvelopeJson(*envelope, partition.envelope, ctx, "root.partitions[].envelope")) {
                    result.status = ctx.status;
                    result.errorDetail = ctx.detail;
                    return result;
                }
            }
            snapshot.partitions.push_back(std::move(partition));
        }
    }
    if (const JsonValue* modules = root.find("modules"); modules != nullptr) {
        const JsonArray* array = modules->asArray();
        if (array == nullptr) {
            result.status = SnapshotLoadStatus::kInvalidFieldValue;
            result.errorDetail = "root.modules";
            return result;
        }
        for (const JsonValue& item : *array) {
            SnapshotModule module;
            if (item.asObject() == nullptr) {
                result.status = SnapshotLoadStatus::kInvalidFieldValue;
                result.errorDetail = "root.modules[]";
                return result;
            }
            if (!readString(item, "moduleId", module.moduleId, ctx, true, "root.modules[]") ||
                !readOptU64(item, "imageBase", module.imageBase, ctx, "root.modules[]") ||
                !readOptU64(item, "imageSize", module.imageSize, ctx, "root.modules[]")) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            if (const JsonValue* identity = item.find("identity"); identity != nullptr) {
                if (!readDriverIdentity(*identity, module.identity, ctx, "root.modules[].identity")) {
                    result.status = ctx.status;
                    result.errorDetail = ctx.detail;
                    return result;
                }
            }
            snapshot.modules.push_back(std::move(module));
        }
    }
    if (const JsonValue* entities = root.find("entities"); entities != nullptr) {
        const JsonArray* array = entities->asArray();
        if (array == nullptr) {
            result.status = SnapshotLoadStatus::kInvalidFieldValue;
            result.errorDetail = "root.entities";
            return result;
        }
        for (const JsonValue& item : *array) {
            const JsonObject* obj = item.asObject();
            if (obj == nullptr) {
                result.status = SnapshotLoadStatus::kInvalidFieldValue;
                result.errorDetail = "root.entities[]";
                return result;
            }
            SnapshotEntity entity;
            collectUnknown(*obj, entityKnownKeys(), "root.entities[]", &entity.unknownFields, ctx);
            std::uint64_t order = 0;
            if (!readString(item, "partitionId", entity.partitionId, ctx, true, "root.entities[]") ||
                !readEnum(item, "kind", entity.kind, parseObjectKindName, ctx, "root.entities[]") ||
                !readString(item, "rawRecordId", entity.rawRecordId, ctx, false, "root.entities[]") ||
                !readU64(item, "displayOrder", order, ctx, "root.entities[]")) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            entity.displayOrder = static_cast<std::size_t>(order);
            bool identityOk = true;
            if (const JsonValue* node = item.find("process"); node != nullptr) {
                identityOk = readProcessIdentity(*node, entity.process, ctx, "root.entities[].process");
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("thread"); node != nullptr) {
                    identityOk = readThreadIdentity(*node, entity.thread, ctx, "root.entities[].thread");
                }
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("driver"); node != nullptr) {
                    identityOk = readDriverIdentity(*node, entity.driver, ctx, "root.entities[].driver");
                }
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("file"); node != nullptr) {
                    identityOk = readFileIdentityJson(*node, entity.file, ctx, "root.entities[].file");
                }
            }
            if (identityOk) {
                if (const JsonValue* node = item.find("logical"); node != nullptr) {
                    identityOk = readLogicalIdentity(*node, entity.logical, ctx, "root.entities[].logical");
                }
            }
            if (!identityOk) {
                result.status = ctx.status;
                result.errorDetail = ctx.detail;
                return result;
            }
            if (const JsonValue* fields = item.find("fields"); fields != nullptr) {
                const JsonArray* fieldArray = fields->asArray();
                if (fieldArray == nullptr) {
                    result.status = SnapshotLoadStatus::kInvalidFieldValue;
                    result.errorDetail = "root.entities[].fields";
                    return result;
                }
                for (const JsonValue& fieldItem : *fieldArray) {
                    if (fieldItem.asObject() == nullptr) {
                        result.status = SnapshotLoadStatus::kInvalidFieldValue;
                        result.errorDetail = "root.entities[].fields[]";
                        return result;
                    }
                    EntityField field;
                    if (!readString(fieldItem, "name", field.name, ctx, true, "root.entities[].fields[]") ||
                        !readEnum(fieldItem, "semantics", field.semantics, parseFieldSemanticsName, ctx,
                                  "root.entities[].fields[]") ||
                        !readEnum(fieldItem, "kind", field.kind, parseFieldValueKindName, ctx,
                                  "root.entities[].fields[]") ||
                        !readString(fieldItem, "text", field.text, ctx, false, "root.entities[].fields[]") ||
                        !readOptU64(fieldItem, "number", field.number, ctx, "root.entities[].fields[]") ||
                        !readEnum(fieldItem, "numberFormat", field.numberFormat, parseU64FormatName, ctx,
                                  "root.entities[].fields[]") ||
                        !readEnum(fieldItem, "redaction", field.redaction, parseRedactionClassName, ctx,
                                  "root.entities[].fields[]")) {
                        result.status = ctx.status;
                        result.errorDetail = ctx.detail;
                        return result;
                    }
                    entity.fields.push_back(std::move(field));
                }
            }
            snapshot.entities.push_back(std::move(entity));
        }
    }

    if (!ctx.ok()) {
        result.status = ctx.status;
        result.errorDetail = ctx.detail;
        return result;
    }
    result.unknownFieldPaths = ctx.unknownPaths;
    result.status = ctx.unknownPaths.empty() ? SnapshotLoadStatus::kOk
                                             : SnapshotLoadStatus::kOkWithUnknownFields;
    result.snapshot = std::move(snapshot);
    return result;
}

// ---------------------------------------------------------------------------
// D-07: Data masking.
// ---------------------------------------------------------------------------
namespace {

bool isWordChar(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

std::string mapKey(RedactionClass cls, std::string_view original) {
    std::string key(1, static_cast<char>('0' + static_cast<int>(cls)));
    key.push_back(kSep);
    key.append(foldText(original));
    return key;
}

// Extract the segment immediately following the marker from the path. The marker is already folded to lowercase backslashes.
void collectSegmentAfter(const std::string& folded, const std::string& raw, const char* marker,
                         std::vector<std::string>& out) {
    const std::string kNeedle(marker);
    std::size_t pos = 0;
    while ((pos = folded.find(kNeedle, pos)) != std::string::npos) {
        const std::size_t kBegin = pos + kNeedle.size();
        std::size_t end = folded.find('\\', kBegin);
        if (end == std::string::npos) {
            end = folded.size();
        }
        if (end > kBegin) {
            out.push_back(raw.substr(kBegin, end - kBegin));
        }
        pos = kBegin;
    }
}

void collectUncHost(const std::string& folded, const std::string& raw,
                    std::vector<std::string>& out) {
    if (folded.size() < 3U || folded[0] != '\\' || folded[1] != '\\') {
        return;
    }
    std::size_t end = folded.find('\\', 2U);
    if (end == std::string::npos) {
        end = folded.size();
    }
    if (end > 2U) {
        out.push_back(raw.substr(2U, end - 2U));
    }
}

// D-06: The retained unknown optional fields are arbitrary vendor JSON. Sanitization must be able to traverse them (D-07:
// sensitive original values must not be hidden in raw fields), so we provide a depth-limited traversal/rewrite here.
inline constexpr std::size_t kUnknownFieldMaxDepth = 64;

template <typename Fn>
void forEachJsonString(const JsonValue& value, std::size_t depth, Fn&& fn) {
    if (depth > kUnknownFieldMaxDepth) {
        return;
    }
    if (const JsonObject* object = value.asObject(); object != nullptr) {
        for (const auto& member : *object) {
            fn(member.first);  // The key name itself may contain a username.
            forEachJsonString(member.second, depth + 1U, fn);
        }
        return;
    }
    if (const JsonArray* array = value.asArray(); array != nullptr) {
        for (const JsonValue& item : *array) {
            forEachJsonString(item, depth + 1U, fn);
        }
        return;
    }
    if (value.type() == JsonType::kString) {
        std::string text;
        if (value.tryGetString(text)) {
            fn(text);
        }
    }
}

void collectSids(const std::string& raw, std::vector<std::string>& out) {
    const std::string kFolded = foldText(raw);
    std::size_t pos = 0;
    while ((pos = kFolded.find("s-1-", pos)) != std::string::npos) {
        if (pos != 0U && isWordChar(raw[pos - 1U])) {
            ++pos;
            continue;
        }
        std::size_t end = pos;
        while (end < raw.size() && ((raw[end] >= '0' && raw[end] <= '9') || raw[end] == '-' ||
                                    raw[end] == 'S' || raw[end] == 's')) {
            ++end;
        }
        while (end > pos && raw[end - 1U] == '-') {
            --end;  // Do not consume the trailing delimiter into the SID.
        }
        if (end - pos > 4U) {
            out.push_back(raw.substr(pos, end - pos));
        }
        pos = end;
    }
}

} // namespace

std::string RedactionSession::assign(RedactionClass cls, const std::string& original) {
    if (original.empty()) {
        return std::string();
    }
    const std::string kKey = mapKey(cls, original);
    const auto kIt = map_.find(kKey);
    if (kIt != map_.end()) {
        return kIt->second;
    }
    std::string replacement;
    switch (cls) {
    case RedactionClass::kUserName:
        ++userCount_;
        replacement = "<user-" + formatU64(static_cast<std::uint64_t>(userCount_), U64Format::kDecimal) + ">";
        break;
    case RedactionClass::kHostname:
        ++hostCount_;
        replacement = "<host-" + formatU64(static_cast<std::uint64_t>(hostCount_), U64Format::kDecimal) + ">";
        break;
    case RedactionClass::kAccountSid:
        ++sidCount_;
        replacement = "<sid-" + formatU64(static_cast<std::uint64_t>(sidCount_), U64Format::kDecimal) + ">";
        break;
    case RedactionClass::kNone:
    case RedactionClass::kFilePath:
        return std::string();  // The path itself is not replaced entirely — only the user/host segments within it are replaced.
    }
    map_.emplace(kKey, replacement);
    RedactionMapping mapping;
    mapping.cls = cls;
    mapping.original = original;
    mapping.replacement = replacement;
    report_.mappings.push_back(std::move(mapping));
    return replacement;
}

std::string RedactionSession::replacementFor(RedactionClass cls, std::string_view original) const {
    const auto kIt = map_.find(mapKey(cls, original));
    return kIt == map_.end() ? std::string() : kIt->second;
}

void RedactionSession::learn(const Snapshot& source) {
    std::vector<std::string> users;
    std::vector<std::string> hosts;
    std::vector<std::string> sids;

    auto scanPath = [&](const std::string& value) {
        if (value.empty()) {
            return;
        }
        const std::string kFolded = foldPath(value);
        const std::string kRaw = value;
        collectSegmentAfter(kFolded, kRaw, "\\users\\", users);
        collectSegmentAfter(kFolded, kRaw, "\\home\\", users);
        collectSegmentAfter(kFolded, kRaw, "\\documents and settings\\", users);
        collectUncHost(kFolded, kRaw, hosts);
        collectSids(kRaw, sids);
    };

    // D-07: Paths/SIDs in unknown optional fields must also participate in learning. If they are only replaced during
    // export without being learned, usernames that appeared only in vendor extensions will be completely missed.
    auto scanUnknown = [&](const JsonObject& unknown) {
        for (const auto& member : unknown) {
            scanPath(member.first);
            forEachJsonString(member.second, 0U, [&](const std::string& text) { scanPath(text); });
        }
    };

    scanPath(source.envelope.outcome.message);
    scanPath(source.envelope.source.dependsOn);
    if (!source.envelope.window.machineId.empty()) {
        hosts.push_back(source.envelope.window.machineId);
    }
    scanUnknown(source.unknownFields);
    for (const std::string& selector : source.scope.selectors) {
        scanPath(selector);
    }
    for (const SnapshotPartition& partition : source.partitions) {
        scanPath(partition.envelope.outcome.message);
        scanPath(partition.envelope.source.dependsOn);
        if (!partition.envelope.window.machineId.empty()) {
            hosts.push_back(partition.envelope.window.machineId);
        }
    }
    for (const SnapshotModule& module : source.modules) {
        scanPath(module.identity.imagePath);
    }
    for (const SnapshotEntity& entity : source.entities) {
        scanPath(entity.process.imageName);
        scanPath(entity.driver.imagePath);
        scanPath(entity.file.path);
        scanPath(entity.logical.name);
        scanPath(entity.logical.scopeKey);
        scanPath(entity.rawRecordId);
        scanUnknown(entity.unknownFields);
        for (const EntityField& field : entity.fields) {
            scanPath(field.text);
            switch (field.redaction) {
            case RedactionClass::kUserName:
                if (!field.text.empty()) {
                    users.push_back(field.text);
                }
                break;
            case RedactionClass::kHostname:
                if (!field.text.empty()) {
                    hosts.push_back(field.text);
                }
                break;
            case RedactionClass::kAccountSid:
                if (!field.text.empty()) {
                    sids.push_back(field.text);
                }
                break;
            case RedactionClass::kFilePath:
            case RedactionClass::kNone:
                break;
            }
        }
    }

    if (options_.redactUserNames) {
        for (const std::string& user : users) {
            assign(RedactionClass::kUserName, user);
        }
    }
    if (options_.redactHostnames) {
        for (const std::string& host : hosts) {
            assign(RedactionClass::kHostname, host);
        }
    }
    if (options_.redactSids) {
        for (const std::string& sid : sids) {
            assign(RedactionClass::kAccountSid, sid);
        }
    }
}

void RedactionSession::redact(const Snapshot& source, Snapshot& out) {
    // First, learn: free-text fields may contain usernames that only appear in paths elsewhere.
    learn(source);
    out = source;  // Source snapshot is a const input; modifications always apply to a copy.

    // Prefer matching longer original values to avoid short names consuming half of long names first.
    struct Needle final {
        std::string folded;
        const RedactionMapping* mapping = nullptr;
    };
    std::vector<Needle> needles;
    needles.reserve(report_.mappings.size());
    for (const RedactionMapping& mapping : report_.mappings) {
        if (!mapping.original.empty()) {
            needles.push_back(Needle{foldText(mapping.original), &mapping});
        }
    }
    std::sort(needles.begin(), needles.end(), [](const Needle& a, const Needle& b) {
        if (a.folded.size() != b.folded.size()) {
            return a.folded.size() > b.folded.size();
        }
        return a.folded < b.folded;
    });

    // 7.3 / D-07 Performance: The naive implementation attempts **all** placeholders at every word boundary, incurring a cost of
    // text length × placeholder count. Since placeholders are automatically harvested from data (each `Users\` segment, each UNC
    // host, each `S-1-…` segment), they grow with the snapshot, causing the L1 scale to take over ten seconds for the next export.
    // Buckets are formed based on the first character after folding: only candidates matching the first character at each position
    // are tested, and within each bucket, the order remains descending by length, preserving the 'longest match first' semantics.
    std::array<std::vector<const Needle*>, 256> byFirstChar{};
    std::array<bool, 256> firstCharPresent{};
    firstCharPresent.fill(false);
    for (const Needle& needle : needles) {
        const auto kFirst = static_cast<unsigned char>(needle.folded[0]);
        byFirstChar[kFirst].push_back(&needle);
        firstCharPresent[kFirst] = true;
    }

    std::size_t replacements = 0;
    std::size_t comparisons = 0;
    // Scan left-to-right; on a match, output the placeholder and skip the original value. Previously written placeholders
    // are not rescanned; otherwise, an account named "user" would consume "<user-1>" again, creating nesting.
    // Return value: Number of replacements; the caller decides whether to include it in the report (not counted when probing key names).
    auto scrubValue = [&](std::string& value) -> std::size_t {
        if (value.empty() || needles.empty()) {
            return 0U;
        }
        bool anyCandidate = false;
        for (const char kRaw : value) {
            if (firstCharPresent[static_cast<unsigned char>(foldAscii(kRaw))]) {
                anyCandidate = true;
                break;
            }
        }
        if (!anyCandidate) {
            return 0U;  // No candidate's first character appeared: pass the whole string directly without folding or bit-by-bit testing.
        }
        const std::string kFolded = foldText(value);
        std::string rewritten;
        rewritten.reserve(value.size());
        std::size_t index = 0;
        std::size_t hits = 0;
        while (index < value.size()) {
            bool matched = false;
            const bool kLeftOk = index == 0U || !isWordChar(value[index - 1U]);
            if (kLeftOk) {
                const std::vector<const Needle*>& bucket =
                    byFirstChar[static_cast<unsigned char>(kFolded[index])];
                for (const Needle* needle : bucket) {
                    ++comparisons;
                    if (index + needle->folded.size() > value.size()) {
                        continue;
                    }
                    if (kFolded.compare(index, needle->folded.size(), needle->folded) != 0) {
                        continue;
                    }
                    const std::size_t kAfter = index + needle->folded.size();
                    if (kAfter < value.size() && isWordChar(value[kAfter])) {
                        continue;  // Word boundary mismatch: 'alice' should not be replaced within 'aliceworks'.
                    }
                    rewritten.append(needle->mapping->replacement);
                    index = kAfter;
                    matched = true;
                    ++hits;
                    break;
                }
            }
            if (!matched) {
                rewritten.push_back(value[index]);
                ++index;
            }
        }
        if (hits != 0U) {
            value = rewritten;
        }
        return hits;
    };

    auto scrub = [&](std::string& value, const std::string& path) {
        const std::size_t kHits = scrubValue(value);
        if (kHits != 0U) {
            replacements += kHits;
            report_.replacedFieldPaths.push_back(path);
        }
    };

    // 7.3: Locally interruptible work must have cancellation points. On cancellation, do not deliver partially de-sensitized
    // snapshots—that is more dangerous than no de-sensitization (appears processed but still contains original values).
    bool cancelled = false;
    auto checkCancel = [&]() -> bool {
        if (cancelled) {
            return true;
        }
        if (cancel_ && cancel_()) {
            cancelled = true;
        }
        return cancelled;
    };

    // D-07: Unknown optional fields (those D-06 promised to write back verbatim) must also be scrubbed. Vendor extensions
    // commonly contain full user paths; exporting them verbatim hides sensitive original values inside "raw fields".
    // Do not rename the key upon match (renaming causes collisions and breaks the caller's extended semantics); instead,
    // delete the entire member and register it in removedFieldPaths—declare the deletion rather than silently omitting it.
    std::function<bool(const JsonValue&, const std::string&, std::size_t, JsonValue&)> scrubJson =
        [&](const JsonValue& in, const std::string& path, std::size_t depth,
            JsonValue& outValue) -> bool {
        if (depth > kUnknownFieldMaxDepth) {
            return false;  // Delete and declare all subtrees that are too deep to scan; do not allow them through.
        }
        if (const JsonObject* object = in.asObject(); object != nullptr) {
            JsonObject rebuilt;
            for (const auto& member : *object) {
                std::string probe = member.first;
                const std::string kChildPath = path + "." + member.first;
                if (scrubValue(probe) != 0U) {
                    // The key name itself contains the sensitive original value: the deletion declaration must specify the
                    // **replaced** key name; otherwise, this "deleted list" would inadvertently expose the original value.
                    report_.removedFieldPaths.push_back(path + "." + probe);
                    continue;
                }
                JsonValue child;
                if (!scrubJson(member.second, kChildPath, depth + 1U, child)) {
                    report_.removedFieldPaths.push_back(kChildPath);
                    continue;
                }
                rebuilt.emplace_back(member.first, std::move(child));
            }
            outValue = JsonValue::makeObject(std::move(rebuilt));
            return true;
        }
        if (const JsonArray* array = in.asArray(); array != nullptr) {
            JsonArray rebuilt;
            for (std::size_t i = 0; i < array->size(); ++i) {
                const std::string kChildPath =
                    path + "[" + formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) + "]";
                JsonValue child;
                if (!scrubJson((*array)[i], kChildPath, depth + 1U, child)) {
                    report_.removedFieldPaths.push_back(kChildPath);
                    continue;
                }
                rebuilt.push_back(std::move(child));
            }
            outValue = JsonValue::makeArray(std::move(rebuilt));
            return true;
        }
        if (in.type() == JsonType::kString) {
            std::string text;
            if (!in.tryGetString(text)) {
                return false;
            }
            scrub(text, path);
            outValue = JsonValue::makeString(std::move(text));
            return true;
        }
        outValue = in;  // Numbers, booleans, and null do not carry text.
        return true;
    };

    auto scrubUnknown = [&](JsonObject& unknown, const std::string& base) {
        JsonObject rebuilt;
        for (const auto& member : unknown) {
            std::string probe = member.first;
            const std::string kPath = base + "." + member.first;
            if (scrubValue(probe) != 0U) {
                report_.removedFieldPaths.push_back(base + "." + probe);
                continue;
            }
            JsonValue child;
            if (!scrubJson(member.second, kPath, 1U, child)) {
                report_.removedFieldPaths.push_back(kPath);
                continue;
            }
            rebuilt.emplace_back(member.first, std::move(child));
        }
        unknown = std::move(rebuilt);
    };

    scrub(out.snapshotId, "snapshotId");
    scrub(out.envelope.window.machineId, "envelope.window.machineId");
    scrub(out.envelope.source.dependsOn, "envelope.source.dependsOn");
    scrub(out.envelope.evidenceId, "envelope.evidenceId");
    if (options_.dropCollectorMessages) {
        if (!out.envelope.outcome.message.empty()) {
            out.envelope.outcome.message.clear();
            report_.removedFieldPaths.push_back("envelope.outcome.message");
        }
    } else {
        scrub(out.envelope.outcome.message, "envelope.outcome.message");
    }
    for (std::size_t i = 0; i < out.scope.selectors.size(); ++i) {
        scrub(out.scope.selectors[i],
              "scope.selectors[" + formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) + "]");
    }
    scrubUnknown(out.unknownFields, "unknownFields");
    for (std::size_t i = 0; i < out.partitions.size(); ++i) {
        if (checkCancel()) {
            break;
        }
        const std::string kBase =
            "partitions[" + formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) + "]";
        SnapshotPartition& partition = out.partitions[i];
        scrub(partition.envelope.window.machineId, kBase + ".envelope.window.machineId");
        scrub(partition.envelope.source.dependsOn, kBase + ".envelope.source.dependsOn");
        scrub(partition.envelope.evidenceId, kBase + ".envelope.evidenceId");
        if (options_.dropCollectorMessages) {
            if (!partition.envelope.outcome.message.empty()) {
                partition.envelope.outcome.message.clear();
                report_.removedFieldPaths.push_back(kBase + ".envelope.outcome.message");
            }
        } else {
            scrub(partition.envelope.outcome.message, kBase + ".envelope.outcome.message");
        }
    }
    for (std::size_t i = 0; i < out.modules.size(); ++i) {
        const std::string kBase =
            "modules[" + formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) + "]";
        scrub(out.modules[i].identity.imagePath, kBase + ".identity.imagePath");
    }
    for (std::size_t i = 0; i < out.entities.size(); ++i) {
        if (checkCancel()) {
            break;
        }
        const std::string kBase =
            "entities[" + formatU64(static_cast<std::uint64_t>(i), U64Format::kDecimal) + "]";
        SnapshotEntity& entity = out.entities[i];
        scrub(entity.process.imageName, kBase + ".process.imageName");
        scrub(entity.thread.process.imageName, kBase + ".thread.process.imageName");
        scrub(entity.driver.imagePath, kBase + ".driver.imagePath");
        scrub(entity.file.path, kBase + ".file.path");
        scrub(entity.logical.name, kBase + ".logical.name");
        scrub(entity.logical.scopeKey, kBase + ".logical.scopeKey");
        scrub(entity.rawRecordId, kBase + ".rawRecordId");
        for (std::size_t f = 0; f < entity.fields.size(); ++f) {
            scrub(entity.fields[f].text,
                  kBase + ".fields[" + formatU64(static_cast<std::uint64_t>(f), U64Format::kDecimal) +
                      "].text");
        }
        scrubUnknown(entity.unknownFields, kBase + ".unknownFields");
    }
    report_.replacementCount += replacements;
    report_.needleComparisons += comparisons;
    if (cancelled) {
        // Cancellation: do not deliver partial results. The report retains records of work done and explicitly sets cancelled.
        out = Snapshot{};
        report_.cancelled = true;
    }
}

void redactSnapshot(const Snapshot& source,
                    const RedactionOptions& options,
                    Snapshot& out,
                    RedactionReport& report) {
    RedactionSession session(options);
    session.redact(source, out);
    report = session.report();
}

} // namespace ksword::evidence

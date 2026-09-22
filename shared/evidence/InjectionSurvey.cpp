#include "InjectionSurvey.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace ksword::evidence {
namespace {

// Path comparison uses this single normalization: lowercase + backslash. Paths from the two sources often
// differ in case (loader provides the original string from PEB, mapping query provides the device path
// after conversion); character-by-character comparison would generate many false "name mismatch" errors.
std::string normalizePath(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (const char kCh : path) {
        char c = kCh;
        if (c == '/') {
            c = '\\';
        }
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        out.push_back(c);
    }
    return out;
}

std::string fileNameOf(const std::string& path) {
    const std::size_t kSlash = path.find_last_of("\\/");
    return kSlash == std::string::npos ? path : path.substr(kSlash + 1U);
}

// Determines if two paths point to the same file. Device paths (\Device\HarddiskVolume3\...) and DOS paths
// (C:\...) cannot be converted to each other. Therefore, paths with different prefixes but matching filenames and
// suffixes are considered 'compatible' rather than 'inconsistent' to avoid false inconsistencies for every module.
bool pathsCompatible(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) {
        return true;  // If one side is missing, there is no contradiction; the absence is expressed by other criteria.
    }
    const std::string kNa = normalizePath(a);
    const std::string kNb = normalizePath(b);
    if (kNa == kNb) {
        return true;
    }
    // Tail contains: C:\windows\system32\ntdll.dll and
    // \device\harddiskvolume3\windows\system32\ntdll.dll
    const std::string* longer = kNa.size() >= kNb.size() ? &kNa : &kNb;
    const std::string* shorter = kNa.size() >= kNb.size() ? &kNb : &kNa;
    // Remove the drive letter ("c:") from the short string, then check if the long string ends with the remaining part.
    std::string tail = *shorter;
    if (tail.size() >= 2U && tail[1U] == ':') {
        tail = tail.substr(2U);
    }
    if (tail.empty()) {
        return false;
    }
    if (longer->size() >= tail.size() &&
        longer->compare(longer->size() - tail.size(), tail.size(), tail) == 0) {
        return true;
    }
    return fileNameOf(kNa) == fileNameOf(kNb) && !fileNameOf(kNa).empty();
}

void addUnique(std::vector<std::string>& list, const std::string& value) {
    if (value.empty()) {
        return;
    }
    if (std::find(list.begin(), list.end(), value) == list.end()) {
        list.push_back(value);
    }
}

std::string hexText(std::uint64_t value) {
    static const char* const kDigits = "0123456789ABCDEF";
    std::string out = "0x";
    bool started = false;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto kNibble = static_cast<std::size_t>((value >> shift) & 0xFULL);
        if (kNibble != 0U || started || shift == 0) {
            out.push_back(kDigits[kNibble]);
            started = true;
        }
    }
    return out;
}

std::string decText(std::uint64_t value) {
    if (value == 0U) {
        return "0";
    }
    std::string out;
    while (value != 0U) {
        out.push_back(static_cast<char>('0' + static_cast<int>(value % 10U)));
        value /= 10U;
    }
    std::reverse(out.begin(), out.end());
    return out;
}

void addFact(std::vector<std::string>& facts, const char* key, const std::string& value) {
    facts.push_back(std::string(key) + "=" + value);
}

bool outcomeIsSuccess(const CollectionOutcome& outcome) noexcept {
    return outcome.status == CollectionStatus::kSuccess;
}

// The limitationKeys for ImageDiff contain two completely different types of items; they cannot be treated as gaps indiscriminately.
//   * "These bytes have no available disk reference" — zero-padding, section gaps, DVRT points, and relocations cannot be
//     normalized. No comparison is possible; it **defines** the boundary of "covered scope" rather than representing a single failure.
//     Modern system DLLs almost always have DVRT sites; treating them as gaps causes every scan
//     to report 'scope broken', degrading the four-state logic in production to three-state.
//   * "Intended to compare but failed" — due to read failure, no collection, hitting entry limits, module expiration,
//     or reference parsing failure. These genuinely break the declared scope and must suppress "No differences found."
bool imageLimitationIsScopeDefining(const std::string& key) noexcept {
    return key == "integrity.limitation.excludedNotComparable" ||
           key == "integrity.limitation.emptyCompareSet" ||
           key == "integrity.limitation.relocationUnsupportedTypes" ||
           key == "integrity.limitation.relocationDirectoryMissing" ||
           key == "integrity.limitation.relocationDirectoryUnbacked" ||
           key == "integrity.limitation.relocationDirectoryMalformed" ||
           key == "integrity.limitation.relocationsStripped";
}

} // namespace

// ---------------------------------------------------------------------------
// Name table
// ---------------------------------------------------------------------------

const char* surveyModeName(const SurveyMode mode) noexcept {
    switch (mode) {
    case SurveyMode::kFast: return "Fast";
    case SurveyMode::kDeep: return "Deep";
    }
    return "Fast";
}

const char* processArchitectureName(const ProcessArchitecture architecture) noexcept {
    switch (architecture) {
    case ProcessArchitecture::kUnknown: return "Unknown";
    case ProcessArchitecture::kX64: return "X64";
    case ProcessArchitecture::kWow64: return "Wow64";
    case ProcessArchitecture::kX86Native: return "X86Native";
    case ProcessArchitecture::kArm64: return "Arm64";
    case ProcessArchitecture::kArm64Ec: return "Arm64Ec";
    }
    return "Unknown";
}

const char* collectorArchitectureName(const CollectorArchitecture architecture) noexcept {
    switch (architecture) {
    case CollectorArchitecture::kUnknown: return "Unknown";
    case CollectorArchitecture::kNative64: return "Native64";
    case CollectorArchitecture::kWow64: return "Wow64";
    }
    return "Unknown";
}

const char* moduleEnumerationTrustName(const ModuleEnumerationTrust trust) noexcept {
    switch (trust) {
    case ModuleEnumerationTrust::kUnknown: return "Unknown";
    case ModuleEnumerationTrust::kTrusted: return "Trusted";
    case ModuleEnumerationTrust::kFilterIgnoredUnderWow64: return "FilterIgnoredUnderWow64";
    }
    return "Unknown";
}

ModuleEnumerationTrust evaluateModuleEnumerationTrust(
    const CollectorArchitecture collector,
    const ProcessArchitecture target) noexcept {
    if (collector == CollectorArchitecture::kWow64) {
        // Filter parameters are ignored; the result is always the 32-bit view, regardless of the target architecture.
        return ModuleEnumerationTrust::kFilterIgnoredUnderWow64;
    }
    if (collector == CollectorArchitecture::kNative64 &&
        target != ProcessArchitecture::kUnknown) {
        return ModuleEnumerationTrust::kTrusted;
    }
    return ModuleEnumerationTrust::kUnknown;
}

const char* executeProtectionName(const ExecuteProtection protection) noexcept {
    switch (protection) {
    case ExecuteProtection::kUnknown: return "Unknown";
    case ExecuteProtection::kNotExecutable: return "NotExecutable";
    case ExecuteProtection::kExecute: return "Execute";
    case ExecuteProtection::kExecuteRead: return "ExecuteRead";
    case ExecuteProtection::kExecuteReadWrite: return "ExecuteReadWrite";
    case ExecuteProtection::kExecuteWriteCopy: return "ExecuteWriteCopy";
    }
    return "Unknown";
}

bool executeProtectionIsExecutable(const ExecuteProtection protection) noexcept {
    switch (protection) {
    case ExecuteProtection::kExecute:
    case ExecuteProtection::kExecuteRead:
    case ExecuteProtection::kExecuteReadWrite:
    case ExecuteProtection::kExecuteWriteCopy:
        return true;
    case ExecuteProtection::kUnknown:
    case ExecuteProtection::kNotExecutable:
        return false;
    }
    return false;
}

ProtectionFacts classifyWin32Protection(const OptionalU64& rawProtect) noexcept {
    ProtectionFacts facts;
    facts.rawValue = rawProtect;
    if (!rawProtect.present) {
        // No raw value means unknown. It must never default to NotExecutable here, as
        // that would disguise 'permission not found' as 'this memory is non-executable'.
        return facts;
    }

    const auto kRaw = static_cast<std::uint32_t>(rawProtect.value & 0xFFFFFFFFULL);
    facts.guard = (kRaw & kWin32PageGuard) != 0U;

    switch (kRaw & kWin32ProtectBaseMask) {
    case kWin32PageNoAccess:
        facts.execute = ExecuteProtection::kNotExecutable;
        facts.noAccess = true;
        break;
    case kWin32PageReadOnly:
        facts.execute = ExecuteProtection::kNotExecutable;
        facts.readable = true;
        break;
    case kWin32PageReadWrite:
        facts.execute = ExecuteProtection::kNotExecutable;
        facts.readable = true;
        facts.writable = true;
        break;
    case kWin32PageWriteCopy:
        facts.execute = ExecuteProtection::kNotExecutable;
        facts.readable = true;
        facts.writable = true;
        facts.copyOnWrite = true;
        break;
    case kWin32PageExecute:
        facts.execute = ExecuteProtection::kExecute;
        break;
    case kWin32PageExecuteRead:
        facts.execute = ExecuteProtection::kExecuteRead;
        facts.readable = true;
        break;
    case kWin32PageExecuteReadWrite:
        facts.execute = ExecuteProtection::kExecuteReadWrite;
        facts.readable = true;
        facts.writable = true;
        break;
    case kWin32PageExecuteWriteCopy:
        facts.execute = ExecuteProtection::kExecuteWriteCopy;
        facts.readable = true;
        facts.writable = true;
        facts.copyOnWrite = true;
        break;
    default:
        // Low byte is not any known base value: unintelligible. Cannot be treated as executable or non-executable.
        facts.unrecognizedBase = true;
        facts.execute = ExecuteProtection::kUnknown;
        break;
    }
    return facts;
}

RegionProtection toRegionProtection(const ProtectionFacts& facts) noexcept {
    RegionProtection protection;
    protection.readable = facts.readable;
    protection.writable = facts.writable;
    protection.executable = executeProtectionIsExecutable(facts.execute);
    protection.copyOnWrite = facts.copyOnWrite;
    protection.guard = facts.guard;
    protection.noAccess = facts.noAccess;
    protection.rawValue = facts.rawValue;
    return protection;
}

const char* regionCodeClassName(const RegionCodeClass codeClass) noexcept {
    switch (codeClass) {
    case RegionCodeClass::kUnknown: return "Unknown";
    case RegionCodeClass::kNotCommitted: return "NotCommitted";
    case RegionCodeClass::kNonExecutable: return "NonExecutable";
    case RegionCodeClass::kImageExecutable: return "ImageExecutable";
    case RegionCodeClass::kPrivateExecutable: return "PrivateExecutable";
    case RegionCodeClass::kMappedExecutable: return "MappedExecutable";
    }
    return "Unknown";
}

bool isDynamicCodeCandidate(const RegionCodeClass codeClass) noexcept {
    return codeClass == RegionCodeClass::kPrivateExecutable ||
           codeClass == RegionCodeClass::kMappedExecutable;
}

ProtectionFacts effectiveProtection(const RegionRecord& record) noexcept {
    if (record.protection.rawValue.present) {
        return classifyWin32Protection(record.protection.rawValue);
    }
    const RegionProtection& p = record.protection;
    ProtectionFacts facts;
    const bool kAnyFlag = p.readable || p.writable || p.executable || p.copyOnWrite ||
                         p.guard || p.noAccess;
    if (!kAnyFlag) {
        // All defaults = source field left blank. That means unknown, not 'non-executable'.
        return facts;
    }
    facts.readable = p.readable;
    facts.writable = p.writable;
    facts.copyOnWrite = p.copyOnWrite;
    facts.guard = p.guard;
    facts.noAccess = p.noAccess;
    if (p.executable) {
        facts.execute = p.writable ? ExecuteProtection::kExecuteReadWrite
                                   : ExecuteProtection::kExecuteRead;
    } else {
        facts.execute = ExecuteProtection::kNotExecutable;
    }
    return facts;
}

RegionCodeClass classifyRegionCode(const RegionRecord& record) noexcept {
    if (record.state != RegionState::kCommit) {
        return record.state == RegionState::kUnknown ? RegionCodeClass::kUnknown
                                                    : RegionCodeClass::kNotCommitted;
    }
    const ProtectionFacts kFacts = effectiveProtection(record);
    if (kFacts.execute == ExecuteProtection::kUnknown) {
        // Cannot determine the base value or the source lacks protection information — neither case allows a definitive judgment.
        return RegionCodeClass::kUnknown;
    }
    if (!executeProtectionIsExecutable(kFacts.execute)) {
        return RegionCodeClass::kNonExecutable;
    }
    switch (record.type) {
    case RegionType::kImage: return RegionCodeClass::kImageExecutable;
    case RegionType::kPrivate: return RegionCodeClass::kPrivateExecutable;
    case RegionType::kMapped: return RegionCodeClass::kMappedExecutable;
    case RegionType::kUnknown: break;
    }
    return RegionCodeClass::kUnknown;
}

// ---------------------------------------------------------------------------
// Address space index
// ---------------------------------------------------------------------------

std::size_t AddressSpaceIndex::findEntry(const std::uint64_t va) const noexcept {
    // Binary search only within the first searchableCount entries: they are sorted by base in ascending order, have valid and
    // non-overlapping intervals (a property of a single VirtualQueryEx traversal). Trailing incomplete records are excluded from the search.
    std::size_t low = 0;
    std::size_t high = std::min(searchableCount, entries.size());
    while (low < high) {
        const std::size_t kMid = low + (high - low) / 2U;
        const RegionRecord& record = entries[kMid];
        const std::uint64_t kBegin = record.base.value;
        const std::uint64_t kEnd = kBegin + record.size.value;  // Overflow removed during the Build phase.
        if (va < kBegin) {
            high = kMid;
        } else if (va >= kEnd) {
            low = kMid + 1U;
        } else {
            return kMid;
        }
    }
    return kNoEntry;
}

const AllocationGroup* AddressSpaceIndex::groupForEntry(
    const std::size_t entryIndex) const noexcept {
    if (entryIndex >= entryGroup.size()) {
        return nullptr;
    }
    const std::size_t kGroupIndex = entryGroup[entryIndex];
    if (kGroupIndex >= groups.size()) {
        return nullptr;
    }
    return &groups[kGroupIndex];
}

bool AddressSpaceIndex::usableForAbsenceInference() const noexcept {
    return outcomeIsSuccess(outcome) && coverage.fullyCovered();
}

AddressSpaceIndex buildAddressSpaceIndex(std::vector<RegionRecord> records,
                                         const CollectionOutcome& outcome) {
    AddressSpaceIndex index;
    index.outcome = outcome;

    // Records with missing base/size or overflow on addition cannot participate in interval lookup. They are retained
    // (evidence is not lost) but counted in coverage.failed—otherwise 'missing regions' would silently disappear.
    std::vector<RegionRecord> usable;
    std::vector<RegionRecord> broken;
    usable.reserve(records.size());
    for (RegionRecord& record : records) {
        const bool kHasRange = record.base.present && record.size.present &&
                              record.size.value != 0U &&
                              record.base.value <= (UINT64_MAX - record.size.value);
        if (kHasRange) {
            usable.push_back(std::move(record));
        } else {
            broken.push_back(std::move(record));
        }
    }

    std::sort(usable.begin(), usable.end(),
              [](const RegionRecord& a, const RegionRecord& b) {
                  return a.base.value < b.base.value;
              });

    index.entries = std::move(usable);
    const std::size_t kUsableCount = index.entries.size();
    index.searchableCount = kUsableCount;
    for (RegionRecord& record : broken) {
        index.entries.push_back(std::move(record));
    }

    index.codeClasses.reserve(index.entries.size());
    index.entryGroup.reserve(index.entries.size());
    std::unordered_map<std::uint64_t, std::size_t> groupByKey;
    std::uint64_t requestedBegin = 0;
    std::uint64_t requestedEnd = 0;
    bool haveRange = false;

    for (std::size_t i = 0; i < index.entries.size(); ++i) {
        const RegionRecord& record = index.entries[i];
        const RegionCodeClass kCodeClass = classifyRegionCode(record);
        index.codeClasses.push_back(kCodeClass);

        const bool kInRange = i < kUsableCount;
        if (kInRange) {
            const std::uint64_t kBegin = record.base.value;
            const std::uint64_t kEnd = kBegin + record.size.value;
            if (!haveRange) {
                requestedBegin = kBegin;
                requestedEnd = kEnd;
                haveRange = true;
            } else {
                requestedBegin = std::min(requestedBegin, kBegin);
                requestedEnd = std::max(requestedEnd, kEnd);
            }
        }

        const ProtectionFacts kFacts = effectiveProtection(record);
        const bool kExecutable = isDynamicCodeCandidate(kCodeClass) ||
                                kCodeClass == RegionCodeClass::kImageExecutable;
        const std::uint64_t kSize = record.size.present ? record.size.value : 0U;
        if (record.state == RegionState::kCommit) {
            index.committedBytes += kSize;
        }
        if (kExecutable) {
            index.executableBytes += kSize;
        }
        if (isDynamicCodeCandidate(kCodeClass)) {
            ++index.dynamicCodeCandidateCount;
        }

        // Aggregation key: use AllocationBase if present; otherwise, group by its own base.
        // Do not merge regions with 'no AllocationBase' into others' groups—that fabricates ownership.
        const std::uint64_t kKey = record.allocationBase.present
                                      ? record.allocationBase.value
                                      : (record.base.present ? record.base.value : i);
        auto it = groupByKey.find(kKey);
        if (it == groupByKey.end()) {
            AllocationGroup group;
            group.allocationBase = record.allocationBase;
            group.type = record.type;
            group.mappedPath = record.mappedPath;
            groupByKey.emplace(kKey, index.groups.size());
            index.groups.push_back(std::move(group));
            it = groupByKey.find(kKey);
        }
        index.entryGroup.push_back(it->second);
        AllocationGroup& group = index.groups[it->second];
        group.entryIndices.push_back(i);
        if (group.type != record.type) {
            group.typeMixed = true;
            group.type = RegionType::kUnknown;
        }
        if (group.mappedPath != record.mappedPath) {
            group.mappedPathMixed = true;
            group.mappedPath.clear();
        }
        if (record.state == RegionState::kCommit) {
            group.committedBytes += kSize;
        }
        if (kExecutable) {
            group.executableBytes += kSize;
            group.anyExecutable = true;
            if (kFacts.writable) {
                group.anyWritableExecutable = true;
            }
        }
        if (kFacts.guard) {
            group.anyGuard = true;
        }
        if (kCodeClass == RegionCodeClass::kUnknown && record.state == RegionState::kCommit) {
            group.anyProtectionUnknown = true;
        }
    }

    index.coverage.succeeded = kUsableCount;
    index.coverage.failed = index.entries.size() - kUsableCount;
    index.coverage.totalKnown = OptionalU64::of(index.entries.size());
    if (haveRange) {
        index.coverage.requestedBegin = OptionalU64::of(requestedBegin);
        index.coverage.requestedEnd = OptionalU64::of(requestedEnd);
        index.coverage.processedBegin = OptionalU64::of(requestedBegin);
        index.coverage.processedEnd = OptionalU64::of(requestedEnd);
    }
    return index;
}

// ---------------------------------------------------------------------------
// Note: Cheap filtering summary used for the process list.
// ---------------------------------------------------------------------------

const char* surfaceScreenStateName(const SurfaceScreenState state) noexcept {
    switch (state) {
    case SurfaceScreenState::kNotScreened: return "NotScreened";
    case SurfaceScreenState::kAccessDenied: return "AccessDenied";
    case SurfaceScreenState::kIdentityMismatch: return "IdentityMismatch";
    case SurfaceScreenState::kFailed: return "Failed";
    case SurfaceScreenState::kScreened: return "Screened";
    }
    return "NotScreened";
}

bool surfaceScreenCountsAreMeaningful(const SurfaceScreenState state) noexcept {
    return state == SurfaceScreenState::kScreened;
}

ProcessSurfaceScreen summarizeSurfaceScreen(const AddressSpaceIndex& index,
                                            const OptionalU64& screenedUtc100ns) {
    ProcessSurfaceScreen screen;
    screen.screenedUtc100ns = screenedUtc100ns;

    switch (index.outcome.status) {
    case CollectionStatus::kAccessDenied:
        screen.state = SurfaceScreenState::kAccessDenied;
        return screen;   // Count remains 0, but the status indicates this 0 means 'unknown'.
    case CollectionStatus::kNotCollected:
        screen.state = SurfaceScreenState::kNotScreened;
        return screen;
    case CollectionStatus::kUnsupported:
    case CollectionStatus::kTimeout:
    case CollectionStatus::kError:
        screen.state = SurfaceScreenState::kFailed;
        return screen;
    case CollectionStatus::kSuccess:
    case CollectionStatus::kPartial:
        break;
    }

    screen.state = SurfaceScreenState::kScreened;
    screen.regionCount = static_cast<std::uint32_t>(index.entries.size());
    for (std::size_t i = 0; i < index.entries.size() && i < index.codeClasses.size(); ++i) {
        if (!isDynamicCodeCandidate(index.codeClasses[i])) {
            continue;
        }
        ++screen.dynamicCodeRegions;
        const RegionRecord& record = index.entries[i];
        screen.dynamicCodeBytes += record.size.valueOr(0U);
        if (effectiveProtection(record).writable) {
            ++screen.writableExecutableRegions;
        }
    }
    return screen;
}

// ---------------------------------------------------------------------------
// Module cross-view
// ---------------------------------------------------------------------------

const char* moduleCrossIssueName(const ModuleCrossIssue issue) noexcept {
    switch (issue) {
    case ModuleCrossIssue::kImageMappingWithoutLoaderEntry: return "ImageMappingWithoutLoaderEntry";
    case ModuleCrossIssue::kLoaderEntryWithoutImageMapping: return "LoaderEntryWithoutImageMapping";
    case ModuleCrossIssue::kLoaderPathMismatch: return "LoaderPathMismatch";
    case ModuleCrossIssue::kLoaderSizeMismatch: return "LoaderSizeMismatch";
    case ModuleCrossIssue::kMainImageIdentityConflict: return "MainImageIdentityConflict";
    case ModuleCrossIssue::kMappedPathUnavailable: return "MappedPathUnavailable";
    }
    return "MappedPathUnavailable";
}

bool moduleCrossIssueIsContradiction(const ModuleCrossIssue issue) noexcept {
    switch (issue) {
    case ModuleCrossIssue::kLoaderPathMismatch:
    case ModuleCrossIssue::kLoaderSizeMismatch:
    case ModuleCrossIssue::kMainImageIdentityConflict:
        return true;
    case ModuleCrossIssue::kImageMappingWithoutLoaderEntry:
    case ModuleCrossIssue::kLoaderEntryWithoutImageMapping:
    case ModuleCrossIssue::kMappedPathUnavailable:
        return false;
    }
    return false;
}

const char* payloadStructureName(const PayloadStructure structure) noexcept {
    switch (structure) {
    case PayloadStructure::kNotExamined: return "NotExamined";
    case PayloadStructure::kUnreadable: return "Unreadable";
    case PayloadStructure::kNoStructure: return "NoStructure";
    case PayloadStructure::kDataOnlyPeFile: return "DataOnlyPeFile";
    case PayloadStructure::kMappedPeImage: return "MappedPeImage";
    case PayloadStructure::kHeaderErasedPe: return "HeaderErasedPe";
    case PayloadStructure::kBareCode: return "BareCode";
    }
    return "NotExamined";
}

ModuleCrossViewReport evaluateModuleCrossView(const ModuleCrossViewInput& input) {
    ModuleCrossViewReport report;
    report.payloadCandidates = input.payloadView.size();

    const bool kLoaderUsable = outcomeIsSuccess(input.loaderOutcome);
    const bool kImageUsable = outcomeIsSuccess(input.imageOutcome);
    // X-06 same-rule: Only allow stating "this side has what the other side lacks" if both sides succeed.
    // The list collected by the WOW64 collector is inherently incomplete, so it is not qualified for absence inference.
    report.absenceInferenceAllowed =
        kLoaderUsable && kImageUsable &&
        input.loaderTrust != ModuleEnumerationTrust::kFilterIgnoredUnderWow64;

    if (!kLoaderUsable) {
        addUnique(report.coverageGapKeys, kGapLoaderViewUnavailable);
    }
    if (!kImageUsable) {
        addUnique(report.coverageGapKeys, kGapImageViewUnavailable);
    }
    if (!outcomeIsSuccess(input.payloadOutcome)) {
        addUnique(report.coverageGapKeys, kGapPayloadViewUnavailable);
    }
    if (input.loaderTrust == ModuleEnumerationTrust::kFilterIgnoredUnderWow64) {
        addUnique(report.coverageGapKeys, kGapModuleEnumerationWow64);
    }

    // Index mapping views by base address.
    std::unordered_map<std::uint64_t, std::size_t> mappingByBase;
    for (std::size_t i = 0; i < input.imageView.size(); ++i) {
        const ImageMappingEntry& entry = input.imageView[i];
        if (entry.allocationBase.present) {
            mappingByBase.emplace(entry.allocationBase.value, i);
        }
        if (!outcomeIsSuccess(entry.pathOutcome) || entry.mappedPath.empty()) {
            // Path query failure must preserve the cause. It is a gap, not 'no file implantation'.
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::kMappedPathUnavailable;
            finding.base = entry.allocationBase;
            finding.mappedSize = entry.mappedSize;
            finding.inputOutcome = entry.pathOutcome;
            addFact(finding.facts, "mapped.path.status",
                    collectionStatusName(entry.pathOutcome.status));
            if (!entry.pathOutcome.message.empty()) {
                addFact(finding.facts, "mapped.path.message", entry.pathOutcome.message);
            }
            report.findings.push_back(std::move(finding));
            addUnique(report.coverageGapKeys, kGapMappedPathUnavailable);
        }
    }

    std::vector<bool> mappingMatched(input.imageView.size(), false);

    for (const LoaderModuleEntry& loaded : input.loaderView) {
        const bool kHaveBase = loaded.module.imageBase.present;
        auto it = kHaveBase ? mappingByBase.find(loaded.module.imageBase.value)
                           : mappingByBase.end();
        if (it == mappingByBase.end()) {
            if (!report.absenceInferenceAllowed || !kHaveBase) {
                continue;  // Do not produce output if ineligible to infer missing items; the missing key has already been recorded.
            }
            ++report.loaderOnly;
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::kLoaderEntryWithoutImageMapping;
            finding.base = loaded.module.imageBase;
            finding.loaderPath = loaded.module.imagePath;
            finding.loaderSize = loaded.module.imageSize;
            finding.inputOutcome = CollectionOutcome::success();
            addFact(finding.facts, "loader.name", loaded.listedName);
            addFact(finding.facts, "loader.base", hexText(loaded.module.imageBase.value));
            report.findings.push_back(std::move(finding));
            continue;
        }

        mappingMatched[it->second] = true;
        ++report.matchedModules;
        const ImageMappingEntry& mapping = input.imageView[it->second];

        if (!mapping.mappedPath.empty() && !loaded.module.imagePath.empty() &&
            !pathsCompatible(loaded.module.imagePath, mapping.mappedPath)) {
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::kLoaderPathMismatch;
            finding.base = loaded.module.imageBase;
            finding.loaderPath = loaded.module.imagePath;
            finding.mappedPath = mapping.mappedPath;
            finding.inputOutcome = CollectionOutcome::success();
            addFact(finding.facts, "loader.path", loaded.module.imagePath);
            addFact(finding.facts, "mapped.path", mapping.mappedPath);
            report.findings.push_back(std::move(finding));
        }

        if (loaded.module.imageSize.present && mapping.mappedSize.present) {
            const std::uint64_t kDeclared = loaded.module.imageSize.value;
            const std::uint64_t kMapped = mapping.mappedSize.value;
            const std::uint64_t kDiff = kDeclared > kMapped ? kDeclared - kMapped : kMapped - kDeclared;
            if (kDiff > input.sizeToleranceBytes) {
                ModuleCrossFinding finding;
                finding.issue = ModuleCrossIssue::kLoaderSizeMismatch;
                finding.base = loaded.module.imageBase;
                finding.loaderPath = loaded.module.imagePath;
                finding.mappedPath = mapping.mappedPath;
                finding.loaderSize = loaded.module.imageSize;
                finding.mappedSize = mapping.mappedSize;
                finding.inputOutcome = CollectionOutcome::success();
                addFact(finding.facts, "loader.size", hexText(kDeclared));
                addFact(finding.facts, "mapped.size", hexText(kMapped));
                addFact(finding.facts, "size.tolerance", hexText(input.sizeToleranceBytes));
                report.findings.push_back(std::move(finding));
            }
        }
    }

    if (report.absenceInferenceAllowed) {
        for (std::size_t i = 0; i < input.imageView.size(); ++i) {
            if (mappingMatched[i]) {
                continue;
            }
            const ImageMappingEntry& mapping = input.imageView[i];
            ++report.mappingOnly;
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::kImageMappingWithoutLoaderEntry;
            finding.base = mapping.allocationBase;
            finding.mappedPath = mapping.mappedPath;
            finding.mappedSize = mapping.mappedSize;
            finding.inputOutcome = CollectionOutcome::success();
            addFact(finding.facts, "mapped.path", mapping.mappedPath);
            if (mapping.allocationBase.present) {
                addFact(finding.facts, "mapped.base", hexText(mapping.allocationBase.value));
            }
            report.findings.push_back(std::move(finding));
        }
    }

    // Main image: cross-verify the three sources pairwise. Record a discrepancy for any conflicting pair; record a missing source if a source is absent.
    {
        int available = 0;
        if (!input.mainImagePathFromLoader.empty()) { ++available; }
        if (!input.mainImagePathFromKernel.empty()) { ++available; }
        if (!input.mainImagePathFromMapping.empty()) { ++available; }
        if (available < 2) {
            addUnique(report.coverageGapKeys, kGapMainImageSourceMissing);
        }

        std::vector<std::string> conflictFacts;
        const bool kLoaderVsKernel =
            !pathsCompatible(input.mainImagePathFromLoader, input.mainImagePathFromKernel);
        const bool kLoaderVsMapping =
            !pathsCompatible(input.mainImagePathFromLoader, input.mainImagePathFromMapping);
        const bool kKernelVsMapping =
            !pathsCompatible(input.mainImagePathFromKernel, input.mainImagePathFromMapping);
        if (kLoaderVsKernel) {
            addFact(conflictFacts, "main.loader-vs-kernel",
                    input.mainImagePathFromLoader + " | " + input.mainImagePathFromKernel);
        }
        if (kLoaderVsMapping) {
            addFact(conflictFacts, "main.loader-vs-mapping",
                    input.mainImagePathFromLoader + " | " + input.mainImagePathFromMapping);
        }
        if (kKernelVsMapping) {
            addFact(conflictFacts, "main.kernel-vs-mapping",
                    input.mainImagePathFromKernel + " | " + input.mainImagePathFromMapping);
        }
        const bool kBaseConflict = input.mainImageBaseFromLoader.present &&
                                  input.mainImageBaseFromMapping.present &&
                                  input.mainImageBaseFromLoader.value !=
                                      input.mainImageBaseFromMapping.value;
        if (kBaseConflict) {
            addFact(conflictFacts, "main.base.loader",
                    hexText(input.mainImageBaseFromLoader.value));
            addFact(conflictFacts, "main.base.mapping",
                    hexText(input.mainImageBaseFromMapping.value));
        }
        if (!conflictFacts.empty()) {
            ModuleCrossFinding finding;
            finding.issue = ModuleCrossIssue::kMainImageIdentityConflict;
            finding.base = input.mainImageBaseFromLoader;
            finding.loaderPath = input.mainImagePathFromLoader;
            finding.mappedPath = input.mainImagePathFromMapping;
            finding.inputOutcome = CollectionOutcome::success();
            finding.facts = std::move(conflictFacts);
            report.findings.push_back(std::move(finding));
        }
    }

    // Conclusion: No available observations means NoEvidence, not "no differences found".
    // Note: MappedPathUnavailable is not a 'difference'—it's a gap. Including it would
    // misrepresent a single path query failure as 'observed module contradiction'.
    const bool kAnyObservation = kLoaderUsable || kImageUsable;
    const bool kAnyRealDifference =
        std::any_of(report.findings.begin(), report.findings.end(),
                    [](const ModuleCrossFinding& finding) {
                        return finding.issue != ModuleCrossIssue::kMappedPathUnavailable;
                    });
    if (!kAnyObservation) {
        report.conclusion = AnalysisConclusion::kNoEvidence;
    } else if (kAnyRealDifference) {
        report.conclusion = AnalysisConclusion::kDifferenceObserved;
    } else if (report.absenceInferenceAllowed && report.coverageGapKeys.empty()) {
        report.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    } else {
        report.conclusion = AnalysisConclusion::kIndeterminate;
    }
    return report;
}

// ---------------------------------------------------------------------------
// Working set filter
// ---------------------------------------------------------------------------

const char* pageScreenVerdictName(const PageScreenVerdict verdict) noexcept {
    switch (verdict) {
    case PageScreenVerdict::kNotQueried: return "NotQueried";
    case PageScreenVerdict::kInvalidNeedsRecheck: return "InvalidNeedsRecheck";
    case PageScreenVerdict::kPrivatizedCandidate: return "PrivatizedCandidate";
    case PageScreenVerdict::kSharedNotCleared: return "SharedNotCleared";
    }
    return "NotQueried";
}

PageScreenVerdict screenWorkingSetPage(const WorkingSetPageFact& fact) noexcept {
    if (!fact.queried) {
        return PageScreenVerdict::kNotQueried;
    }
    if (!fact.valid) {
        // When Valid is zero, other fields—including Shared—cannot be interpreted as valid page structures.
        return PageScreenVerdict::kInvalidNeedsRecheck;
    }
    // We deliberately ignore shareCount here: Shared indicates "whether
    // it is shareable"; ShareCount == 1 cannot substitute for it.
    return fact.shared ? PageScreenVerdict::kSharedNotCleared
                       : PageScreenVerdict::kPrivatizedCandidate;
}

bool pageSelectedForComparison(const PageScreenVerdict verdict,
                               const SurveyMode mode) noexcept {
    switch (verdict) {
    case PageScreenVerdict::kPrivatizedCandidate:
        return true;
    case PageScreenVerdict::kSharedNotCleared:
    case PageScreenVerdict::kInvalidNeedsRecheck:
        // Deep mode does not exclude any image pages due to 'shared' or 'currently invalid'
        // status: memory merging can restore a modified page to a shareable state.
        return mode == SurveyMode::kDeep;
    case PageScreenVerdict::kNotQueried:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Thread start
// ---------------------------------------------------------------------------

bool ImageCodeExtent::containsAddress(const std::uint64_t address) const noexcept {
    return size != 0U && address >= base && (address - base) < size;
}

bool ImageCodeExtent::addressInCodeExtent(const std::uint64_t address) const noexcept {
    if (!codeExtentKnown || !containsAddress(address)) {
        return false;
    }
    const std::uint64_t kRva = address - base;
    return kRva >= codeBeginRva && kRva < codeEndRva;
}

const char* threadStartLandingName(const ThreadStartLanding landing) noexcept {
    switch (landing) {
    case ThreadStartLanding::kNotCollected: return "NotCollected";
    case ThreadStartLanding::kOutsideIndex: return "OutsideIndex";
    case ThreadStartLanding::kFreeOrReserved: return "FreeOrReserved";
    case ThreadStartLanding::kNonImagePrivate: return "NonImagePrivate";
    case ThreadStartLanding::kNonImageMapped: return "NonImageMapped";
    case ThreadStartLanding::kImageCodeRange: return "ImageCodeRange";
    case ThreadStartLanding::kImageOutsideCode: return "ImageOutsideCode";
    case ThreadStartLanding::kImageLayoutUnknown: return "ImageLayoutUnknown";
    }
    return "NotCollected";
}

const char* threadContextTrustName(const ThreadContextTrust trust) noexcept {
    switch (trust) {
    case ThreadContextTrust::kNotCaptured: return "NotCaptured";
    case ThreadContextTrust::kRunningThreadUntrusted: return "RunningThreadUntrusted";
    case ThreadContextTrust::kWaitingThreadStable: return "WaitingThreadStable";
    case ThreadContextTrust::kSuspendedOrSnapshot: return "SuspendedOrSnapshot";
    }
    return "NotCaptured";
}

ThreadContextTrust classifyThreadContextTrust(const bool captured,
                                              const bool suspendedOrSnapshot,
                                              const bool waitingBeforeAndAfter) noexcept {
    if (!captured) {
        return ThreadContextTrust::kNotCaptured;
    }
    if (suspendedOrSnapshot) {
        return ThreadContextTrust::kSuspendedOrSnapshot;
    }
    // Order matters: Suspend/Snapshot takes precedence over 'waiting both before and after'. When both conditions hold,
    // the former is stronger and does not depend on the assumption that the state remained unchanged during collection.
    return waitingBeforeAndAfter ? ThreadContextTrust::kWaitingThreadStable
                                 : ThreadContextTrust::kRunningThreadUntrusted;
}

bool contextUsableAsExecutionEvidence(const ThreadContextTrust trust) noexcept {
    return trust == ThreadContextTrust::kSuspendedOrSnapshot ||
           trust == ThreadContextTrust::kWaitingThreadStable;
}

const char* stackEvidenceKindName(const StackEvidenceKind kind) noexcept {
    switch (kind) {
    case StackEvidenceKind::kReliableUnwoundFrame: return "ReliableUnwoundFrame";
    case StackEvidenceKind::kHeuristicReturnAddressCandidate:
        return "HeuristicReturnAddressCandidate";
    case StackEvidenceKind::kPlainPointerReference: return "PlainPointerReference";
    }
    return "PlainPointerReference";
}

bool stackEvidenceCountsAsExecution(const StackEvidenceKind kind) noexcept {
    return kind == StackEvidenceKind::kReliableUnwoundFrame;
}

bool payloadCandidateCanRaiseConclusion(const PayloadCandidateEntry& candidate) noexcept {
    return candidate.executableAtScanTime;
}

std::size_t admitStackFrames(const ThreadStackInput& stack) noexcept {
    if (!contextUsableAsExecutionEvidence(stack.trust)) {
        // The context itself is untrustworthy; everything derived from it is invalid. This is not a 'degradation to heuristic';
        // the entire chain is void: if the starting point is wrong, every subsequent step proceeds on an incorrect stack.
        return 0U;
    }
    std::size_t admitted = 0U;
    for (const RawStackFrame& frame : stack.frames) {
        if (!frame.derivedFromUnwindData || !frame.instructionPointer.present) {
            break;
        }
        ++admitted;
        if (!frame.unwindDataAvailableAtPc) {
            // The PC for this frame cannot find unwind data—it remains reliable (computed from the previous frame),
            // but the **next frame** can only be guessed via stack scanning. The reliable prefix ends here.
            // A shellcode frame takes this branch: include the frame itself and discard the frames below it.
            break;
        }
    }
    return admitted;
}

namespace {

// Interpret an address as 'landing' location. This function is shared by the entry point and the first-hop target.
// owningImage is written only when the address falls within a known image; otherwise, it remains nullptr.
// "Cross-module" must be determined by this field, not by path strings: private/anonymous regions have no paths, and
// comparing paths would incorrectly classify "jumping into anonymous executable memory" as "not crossing modules".
ThreadStartLanding classifyLanding(const std::uint64_t address,
                                   const AddressSpaceIndex& index,
                                   const std::vector<ImageCodeExtent>& images,
                                   std::string& owningPath,
                                   const ImageCodeExtent*& owningImage,
                                   bool& executableKnown,
                                   bool& executable) {
    owningPath.clear();
    owningImage = nullptr;
    executableKnown = false;
    executable = false;

    const std::size_t kEntryIndex = index.findEntry(address);
    if (kEntryIndex == AddressSpaceIndex::kNoEntry) {
        return ThreadStartLanding::kOutsideIndex;
    }
    const RegionRecord& record = index.entries[kEntryIndex];
    const ProtectionFacts kFacts = effectiveProtection(record);
    if (kFacts.execute != ExecuteProtection::kUnknown) {
        executableKnown = true;
        executable = executeProtectionIsExecutable(kFacts.execute);
    }
    owningPath = record.mappedPath;

    if (record.state != RegionState::kCommit) {
        return ThreadStartLanding::kFreeOrReserved;
    }
    switch (record.type) {
    case RegionType::kImage: {
        for (const ImageCodeExtent& image : images) {
            if (!image.containsAddress(address)) {
                continue;
            }
            owningImage = &image;
            if (owningPath.empty()) {
                owningPath = image.path;
            }
            if (!image.codeExtentKnown) {
                return ThreadStartLanding::kImageLayoutUnknown;
            }
            return image.addressInCodeExtent(address) ? ThreadStartLanding::kImageCodeRange
                                                      : ThreadStartLanding::kImageOutsideCode;
        }
        // It is MEM_IMAGE, but no known module covers it — code layout is unknown.
        return ThreadStartLanding::kImageLayoutUnknown;
    }
    case RegionType::kPrivate:
        return ThreadStartLanding::kNonImagePrivate;
    case RegionType::kMapped:
        return ThreadStartLanding::kNonImageMapped;
    case RegionType::kUnknown:
        break;
    }
    return ThreadStartLanding::kOutsideIndex;
}

} // namespace

std::vector<ThreadStartFinding> evaluateThreadStarts(
    const std::vector<ThreadStartInput>& threads,
    const AddressSpaceIndex& index,
    const std::vector<ImageCodeExtent>& images) {
    std::vector<ThreadStartFinding> findings;
    findings.reserve(threads.size());

    for (const ThreadStartInput& input : threads) {
        ThreadStartFinding finding;
        finding.thread = input.thread;
        finding.startAddress = input.startAddress;
        finding.outcome = input.startAddressOutcome;
        finding.entryInspected = input.entryInspected;

        if (!input.startAddress.present) {
            // The start address was never collected — no observation, not a 'mismatched ownership'.
            finding.landing = ThreadStartLanding::kNotCollected;
            addFact(finding.facts, "thread.start.status",
                    collectionStatusName(input.startAddressOutcome.status));
            findings.push_back(std::move(finding));
            continue;
        }

        std::string owningPath;
        const ImageCodeExtent* owningImage = nullptr;
        bool executableKnown = false;
        bool executable = false;
        finding.landing = classifyLanding(input.startAddress.value, index, images,
                                          owningPath, owningImage, executableKnown, executable);
        finding.owningPath = owningPath;
        finding.startPageExecutableKnown = executableKnown;
        finding.startPageExecutable = executable;

        addFact(finding.facts, "thread.start.address", hexText(input.startAddress.value));
        addFact(finding.facts, "thread.start.landing", threadStartLandingName(finding.landing));
        if (executableKnown) {
            // The start page being non-executable now is a concurrent fact, **not** used to ignore this clue.
            addFact(finding.facts, "thread.start.page-executable-now",
                    executable ? "true" : "false");
        }

        if (input.immediateBranchTarget.present) {
            std::string branchPath;
            const ImageCodeExtent* branchImage = nullptr;
            bool branchExecKnown = false;
            bool branchExec = false;
            finding.branchTarget = input.immediateBranchTarget;
            finding.branchTargetLanding =
                classifyLanding(input.immediateBranchTarget.value, index, images,
                                branchPath, branchImage, branchExecKnown, branchExec);
            // Note: The starting point appears to be within a legitimate module, but the flow subsequently transitions to other regions. This judgment is only
            // meaningful when the starting point is indeed owned by a known image; in that case, the first jump not returning to the same image indicates leaving it.
            finding.branchLeavesOwningModule =
                owningImage != nullptr &&
                !owningImage->containsAddress(input.immediateBranchTarget.value);
            addFact(finding.facts, "thread.start.branch-target",
                    hexText(input.immediateBranchTarget.value));
            addFact(finding.facts, "thread.start.branch-landing",
                    threadStartLandingName(finding.branchTargetLanding));
            if (!branchPath.empty()) {
                addFact(finding.facts, "thread.start.branch-owner", branchPath);
            }
        } else if (input.entryInspected) {
            // Checked but failed to resolve the jump: this is failure evidence, not 'no jump'.
            addFact(finding.facts, "thread.start.branch", "not-resolved");
        }

        findings.push_back(std::move(finding));
    }
    return findings;
}

// ---------------------------------------------------------------------------
// Comparison plan
// ---------------------------------------------------------------------------

const char* normalizationProfileId(const SurveyMode mode) noexcept {
    // Both modes share the same normalization logic. This function accepts 'mode' solely to
    // prevent callers from 'accidentally' branching—the return value is independent of 'mode'.
    static_cast<void>(mode);
    return kNormalizationProfileId;
}

std::uint32_t normalizationProfileVersion(const SurveyMode mode) noexcept {
    static_cast<void>(mode);
    return kNormalizationProfileVersion;
}

const char* comparisonReasonName(const ComparisonReason reason) noexcept {
    switch (reason) {
    case ComparisonReason::kMainImageEntry: return "MainImageEntry";
    case ComparisonReason::kSuspiciousThreadEntry: return "SuspiciousThreadEntry";
    case ComparisonReason::kWorkingSetScreenedPage: return "WorkingSetScreenedPage";
    case ComparisonReason::kControlFlowReference: return "ControlFlowReference";
    case ComparisonReason::kFullExecutableCoverage: return "FullExecutableCoverage";
    }
    return "MainImageEntry";
}

namespace {

const ImageCodeExtent* findImage(const std::vector<ImageCodeExtent>& images,
                                 const std::string& path) {
    for (const ImageCodeExtent& image : images) {
        if (pathsCompatible(image.path, path) && !image.path.empty() && !path.empty()) {
            return &image;
        }
    }
    return nullptr;
}

DriverInstanceId moduleIdOf(const ImageCodeExtent& image) {
    DriverInstanceId id;
    id.imagePath = image.path;
    id.imageBase = OptionalU64::of(image.base);
    id.imageSize = OptionalU64::of(image.size);
    return id;
}

void pushTarget(ComparisonPlan& plan,
                const ImageCodeExtent& image,
                const RvaRange& range,
                const ComparisonReason reason) {
    if (range.empty()) {
        return;
    }
    ComparisonTarget target;
    target.module = moduleIdOf(image);
    target.range = range;
    target.reason = reason;
    plan.targets.push_back(std::move(target));
}

RvaRange clampToImage(const ImageCodeExtent& image, std::uint64_t rva, std::uint64_t length) {
    RvaRange range;
    if (image.size == 0U || rva >= image.size) {
        return range;
    }
    const std::uint64_t kAvailable = image.size - rva;
    const std::uint64_t kClamped = std::min(length, kAvailable);
    range.rva = static_cast<std::uint32_t>(rva);
    range.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(kClamped, 0xFFFFFFFFULL));
    return range;
}

} // namespace

ComparisonPlan buildComparisonPlan(const ComparisonPlanInput& input) {
    ComparisonPlan plan;
    plan.mode = input.mode;
    plan.normalizationProfileId = normalizationProfileId(input.mode);
    plan.normalizationProfileVersion = normalizationProfileVersion(input.mode);

    const std::uint32_t kWindow = input.entryWindowBytes == 0U ? 64U : input.entryWindowBytes;
    const std::uint32_t kPageSize = input.pageSize == 0U ? 4096U : input.pageSize;

    if (input.mode == SurveyMode::kDeep) {
        // Deep mode: all image ranges that must be executed, without skipping due to 'shared' status.
        for (const ImageCodeExtent& image : input.images) {
            if (image.size == 0U) {
                continue;
            }
            RvaRange range;
            if (image.codeExtentKnown && image.codeEndRva > image.codeBeginRva) {
                range = clampToImage(image, image.codeBeginRva,
                                     image.codeEndRva - image.codeBeginRva);
            } else {
                // When code layout is unknown, cover the entire image range and record the gap:
                // this signifies "we don't know where the code is," not "there is no code."
                range = clampToImage(image, 0U, image.size);
                addUnique(plan.coverageGapKeys, kGapReferenceUncertain);
            }
            pushTarget(plan, image, range, ComparisonReason::kFullExecutableCoverage);
        }
    }

    // Main image entry.
    if (!input.mainImagePath.empty()) {
        const ImageCodeExtent* image = findImage(input.images, input.mainImagePath);
        if (image == nullptr) {
            addUnique(plan.coverageGapKeys, kGapMainImageSourceMissing);
        } else if (!input.mainImageEntryRva.present) {
            addUnique(plan.coverageGapKeys, kGapMainImageSourceMissing);
        } else {
            pushTarget(plan, *image,
                       clampToImage(*image, input.mainImageEntryRva.value, kWindow),
                       ComparisonReason::kMainImageEntry);
        }
    } else {
        addUnique(plan.coverageGapKeys, kGapMainImageSourceMissing);
    }

    for (const ComparisonPlanInput::ThreadEntrySite& site : input.threadEntrySites) {
        const ImageCodeExtent* image = findImage(input.images, site.imagePath);
        if (image == nullptr) {
            addUnique(plan.coverageGapKeys, kGapThreadStartUnavailable);
            continue;
        }
        pushTarget(plan, *image, clampToImage(*image, site.rva, kWindow),
                   ComparisonReason::kSuspiciousThreadEntry);
    }

    for (const ComparisonPlanInput::ScreenedPage& page : input.screenedPages) {
        const ImageCodeExtent* image = findImage(input.images, page.imagePath);
        if (image == nullptr) {
            addUnique(plan.coverageGapKeys, kGapWorkingSetUnavailable);
            continue;
        }
        pushTarget(plan, *image, clampToImage(*image, page.pageRva, kPageSize),
                   ComparisonReason::kWorkingSetScreenedPage);
    }

    for (const ComparisonPlanInput::ThreadEntrySite& site : input.controlFlowSites) {
        const ImageCodeExtent* image = findImage(input.images, site.imagePath);
        if (image == nullptr) {
            continue;
        }
        pushTarget(plan, *image, clampToImage(*image, site.rva, kWindow),
                   ComparisonReason::kControlFlowReference);
    }

    return plan;
}

const char* referenceConfidenceName(const ReferenceConfidence confidence) noexcept {
    switch (confidence) {
    case ReferenceConfidence::kNoReference: return "NoReference";
    case ReferenceConfidence::kReferenceUncertain: return "ReferenceUncertain";
    case ReferenceConfidence::kReferenceVerified: return "ReferenceVerified";
    }
    return "NoReference";
}

const char* imageReferenceSourceName(const ImageReferenceSource source) noexcept {
    switch (source) {
    case ImageReferenceSource::kNone: return "None";
    case ImageReferenceSource::kDiskFile: return "DiskFile";
    case ImageReferenceSource::kSectionObject: return "SectionObject";
    }
    return "None";
}

bool sectionReferenceCoverageComplete(const ImageComparisonOutcome& outcome) noexcept {
    if (outcome.referenceSource != ImageReferenceSource::kSectionObject) {
        return true;  // Other sources are not bound by this account.
    }
    // If no pages were requested, it cannot be considered 'fully covered' — that's a lack of comparison, not a complete one.
    return outcome.sectionPagesRequested != 0U &&
           outcome.sectionPagesAvailable == outcome.sectionPagesRequested;
}

bool referenceSupportsDifferenceClaim(const ReferenceConfidence confidence) noexcept {
    return confidence == ReferenceConfidence::kReferenceVerified;
}

// ---------------------------------------------------------------------------
// J-06: Cross-view of R0 scanning backend
// ---------------------------------------------------------------------------

const char* kernelBackendStateName(const KernelBackendState state) noexcept {
    switch (state) {
    case KernelBackendState::kNotRequested: return "NotRequested";
    case KernelBackendState::kDriverUnavailable: return "DriverUnavailable";
    case KernelBackendState::kProfileUnverified: return "ProfileUnverified";
    case KernelBackendState::kPartial: return "Partial";
    case KernelBackendState::kAvailable: return "Available";
    }
    return "NotRequested";
}

bool kernelBackendSupportsAbsenceInference(const KernelBackendState state) noexcept {
    return state == KernelBackendState::kAvailable;
}

bool KernelVadView::usableForAbsenceInference() const noexcept {
    return kernelBackendSupportsAbsenceInference(state) && !truncated &&
           unreadableNodeCount == 0U && outcomeIsSuccess(outcome);
}

const char* vadLinkIntegrityName(const VadLinkIntegrity integrity) noexcept {
    switch (integrity) {
    case VadLinkIntegrity::kNotChecked: return "NotChecked";
    case VadLinkIntegrity::kConsistent: return "Consistent";
    case VadLinkIntegrity::kInconsistent: return "Inconsistent";
    }
    return "NotChecked";
}

VadLinkIntegrity evaluateVadLinkIntegrity(const KernelVadView& view) noexcept {
    // Hard gate: If traversal is incomplete, all three readings are meaningless. Return "not checked", not "consistent".
    if (!view.integrityValid || view.state != KernelBackendState::kAvailable) {
        return VadLinkIntegrity::kNotChecked;
    }

    // Parent pointer back-reference mismatch: clean unlinking leaves no such trace, but crude rewriting does.
    if (view.parentMismatchNodes != 0U) {
        return VadLinkIntegrity::kInconsistent;
    }
    // VadHint points to a node not found in the tree. VadHint being null is valid (a newly created
    // process hasn't used it yet), so this rule applies only when the hint is known and non-zero.
    if (view.vadHintKnown && view.vadHintAddress.present && view.vadHintAddress.value != 0U &&
        !view.vadHintVisited) {
        return VadLinkIntegrity::kInconsistent;
    }
    // Kernel count exceeds the traversed count: there are nodes not in the tree.
    //
    // Only checks **one-way**: visitedCount < vadCount counts. The reverse (walking out with a count higher than the recorded count)
    // naturally occurs during concurrent collection and kernel tree modification (new VADs attached but count not yet incremented).
    // Counting this as inconsistent would cause stable false positives on busy processes. Only a deficit indicates "something was removed."
    if (view.vadCountKnown && view.vadCount != 0U && view.visitedCount < view.vadCount) {
        return VadLinkIntegrity::kInconsistent;
    }
    return VadLinkIntegrity::kConsistent;
}

bool KernelPteView::usableForAbsenceInference() const noexcept {
    return kernelBackendSupportsAbsenceInference(state) && !truncated &&
           failedTableReads == 0U && outcomeIsSuccess(outcome);
}

const char* kernelRegionCrossIssueName(const KernelRegionCrossIssue issue) noexcept {
    switch (issue) {
    case KernelRegionCrossIssue::kVadOnlyRange: return "VadOnlyRange";
    case KernelRegionCrossIssue::kR3OnlyCommittedRange: return "R3OnlyCommittedRange";
    case KernelRegionCrossIssue::kExecutableBeyondR3View: return "ExecutableBeyondR3View";
    case KernelRegionCrossIssue::kExecutableBeyondVadView: return "ExecutableBeyondVadView";
    }
    return "VadOnlyRange";
}

namespace {

// Whether the range [va, va+len) in the R3 index is fully covered by **committed** regions.
// Note that "coverage" must be confirmed page-by-page: the boundaries of a VirtualQueryEx region and VAD boundaries do not
// necessarily align. Comparing only the start point would incorrectly classify a range that is only half-covered as fully covered.
bool r3CoversCommitted(const AddressSpaceIndex& index,
                       const std::uint64_t begin,
                       const std::uint64_t end) {
    constexpr std::uint64_t kPage = 4096ULL;
    if (end <= begin) {
        return false;
    }
    for (std::uint64_t probe = begin; probe < end; probe += kPage) {
        const std::size_t kEntryIndex = index.findEntry(probe);
        if (kEntryIndex == AddressSpaceIndex::kNoEntry) {
            return false;
        }
        if (index.entries[kEntryIndex].state != RegionState::kCommit) {
            return false;
        }
        // Jump directly to the end of this region to avoid querying page-by-page for a 64 MiB mapping.
        const RegionRecord& record = index.entries[kEntryIndex];
        const std::uint64_t kRegionEnd = record.base.value + record.size.value;
        if (kRegionEnd > probe) {
            probe = (kRegionEnd - kPage) & ~(kPage - 1ULL);
        }
    }
    return true;
}

bool r3RangeIsExecutable(const AddressSpaceIndex& index, const std::uint64_t va) {
    const std::size_t kEntryIndex = index.findEntry(va);
    if (kEntryIndex == AddressSpaceIndex::kNoEntry ||
        kEntryIndex >= index.codeClasses.size()) {
        return false;
    }
    const RegionCodeClass kCodeClass = index.codeClasses[kEntryIndex];
    return kCodeClass == RegionCodeClass::kImageExecutable ||
           kCodeClass == RegionCodeClass::kPrivateExecutable ||
           kCodeClass == RegionCodeClass::kMappedExecutable;
}

bool vadCovers(const KernelVadView& view, const std::uint64_t va) {
    for (const KernelVadRegion& region : view.regions) {
        if (!region.startVa.present || !region.endVaExclusive.present) {
            continue;
        }
        if (va >= region.startVa.value && va < region.endVaExclusive.value) {
            return true;
        }
    }
    return false;
}

} // namespace

KernelCrossViewReport evaluateKernelCrossView(const KernelCrossViewInput& input) {
    KernelCrossViewReport report;

    const bool kVadRequested = input.vadView.state != KernelBackendState::kNotRequested;
    const bool kPteRequested = input.pteView.state != KernelBackendState::kNotRequested;
    if (!kVadRequested && !kPteRequested) {
        // There is no intention to use the kernel backend: skip silently. "No intention to use" is not "intended but unavailable";
        // a gap should not be generated, otherwise, machines without the driver installed would report a false gap on every scan.
        report.conclusion = AnalysisConclusion::kNoEvidence;
        return report;
    }

    // If the kernel view is used, this assertion always holds.
    addUnique(report.capabilityLimitKeys, kLimitKernelTrustAssumption);
    addUnique(report.capabilityLimitKeys, kLimitKernelSectionCompare);

    // The broken-link check is defined here, as this is the entry point for kernel-side criteria. It examines only the tree itself, completely
    // independent of the R3/VAD/page-table cross-check below; even if the cross-view matches perfectly, the tree may still have been unlinked.
    report.linkIntegrity = evaluateVadLinkIntegrity(input.vadView);
    report.linkVisitedCount = input.vadView.visitedCount;
    report.linkVadCount = input.vadView.vadCount;
    report.linkParentMismatchNodes = input.vadView.parentMismatchNodes;
    report.linkVadCountKnown = input.vadView.vadCountKnown;
    report.linkVadHintKnown = input.vadView.vadHintKnown;
    report.linkVadHintVisited = input.vadView.vadHintVisited;
    report.linkVadHintAddress = input.vadView.vadHintAddress;

    if (input.r3Index == nullptr) {
        addUnique(report.coverageGapKeys, kGapAddressSpaceIncomplete);
        report.conclusion = AnalysisConclusion::kNoEvidence;
        return report;
    }
    const AddressSpaceIndex& r3 = *input.r3Index;

    if (kVadRequested) {
        switch (input.vadView.state) {
        case KernelBackendState::kDriverUnavailable:
            addUnique(report.coverageGapKeys, kGapKernelBackendUnavailable);
            break;
        case KernelBackendState::kProfileUnverified:
            // Offset not verified for the current build — no findings are generated.
            addUnique(report.coverageGapKeys, kGapKernelProfileUnverified);
            break;
        case KernelBackendState::kPartial:
            addUnique(report.coverageGapKeys, kGapKernelBackendUnavailable);
            break;
        case KernelBackendState::kAvailable:
        case KernelBackendState::kNotRequested:
            break;
        }
        // VAD protection bit layout is unverified, so compare ranges only, not protections.
        addUnique(report.capabilityLimitKeys, kLimitKernelVadFlagsUnverified);
    }
    if (kPteRequested) {
        switch (input.pteView.state) {
        case KernelBackendState::kDriverUnavailable:
        case KernelBackendState::kProfileUnverified:
        case KernelBackendState::kPartial:
            addUnique(report.coverageGapKeys, kGapKernelBackendUnavailable);
            break;
        case KernelBackendState::kAvailable:
        case KernelBackendState::kNotRequested:
            break;
        }
    }

    const bool kVadUsable = input.vadView.usableForAbsenceInference();
    const bool kR3Usable = r3.usableForAbsenceInference();
    report.absenceInferenceAllowed = kVadUsable && kR3Usable;

    // --- VAD ↔ R3 range intersection.
    if (report.absenceInferenceAllowed) {
        for (const KernelVadRegion& region : input.vadView.regions) {
            if (!region.startVa.present || !region.endVaExclusive.present ||
                region.endVaExclusive.value <= region.startVa.value) {
                continue;
            }
            if (r3CoversCommitted(r3, region.startVa.value, region.endVaExclusive.value)) {
                continue;
            }
            // VAD reports a region here, but R3's VirtualQueryEx does not report it (or reports it as uncommitted).
            ++report.vadOnlyCount;
            KernelRegionCrossFinding finding;
            finding.issue = KernelRegionCrossIssue::kVadOnlyRange;
            finding.startVa = region.startVa;
            finding.endVaExclusive = region.endVaExclusive;
            finding.inputOutcome = input.vadView.outcome;
            addFact(finding.facts, "kernel.vad.start", hexText(region.startVa.value));
            addFact(finding.facts, "kernel.vad.end", hexText(region.endVaExclusive.value));
            addFact(finding.facts, "kernel.vad.private", region.privateMemory ? "true" : "false");
            addFact(finding.facts, "kernel.vad.has-section", region.hasSection ? "true" : "false");
            if (region.vadNodeAddress.present) {
                addFact(finding.facts, "kernel.vad.node", hexText(region.vadNodeAddress.value));
            }
            report.findings.push_back(std::move(finding));
        }

        for (std::size_t i = 0; i < r3.searchableCount && i < r3.entries.size(); ++i) {
            const RegionRecord& record = r3.entries[i];
            if (record.state != RegionState::kCommit) {
                continue;
            }
            if (vadCovers(input.vadView, record.base.value)) {
                continue;
            }
            ++report.r3OnlyCount;
            KernelRegionCrossFinding finding;
            finding.issue = KernelRegionCrossIssue::kR3OnlyCommittedRange;
            finding.startVa = record.base;
            finding.endVaExclusive =
                OptionalU64::of(record.base.value + record.size.value);
            finding.inputOutcome = r3.outcome;
            addFact(finding.facts, "r3.region.start", hexText(record.base.value));
            addFact(finding.facts, "r3.region.type", regionTypeName(record.type));
            report.findings.push_back(std::move(finding));
        }
    }

    // --- Page Table ↔ R3/VAD --- This side does not require "missing page inference" qualification: executable
    // pages reported by the page table are positive observations. A direct conflict with the other side
    // claiming "this region is not executable" does not depend on either side having a complete enumeration.
    if (kPteRequested && statusCarriesObservation(input.pteView.outcome.status)) {
        for (const KernelExecutableExtent& extent : input.pteView.extents) {
            if (!extent.executable || !extent.startVa.present) {
                continue;
            }
            const std::uint64_t kVa = extent.startVa.value;
            const bool kR3Exec = r3RangeIsExecutable(r3, kVa);
            const bool kVadHas = kVadRequested && vadCovers(input.vadView, kVa);

            if (!kR3Exec) {
                ++report.executableBeyondViewCount;
                KernelRegionCrossFinding finding;
                finding.issue = KernelRegionCrossIssue::kExecutableBeyondR3View;
                finding.startVa = extent.startVa;
                finding.endVaExclusive = extent.byteLength.present
                    ? OptionalU64::of(kVa + extent.byteLength.value)
                    : OptionalU64::unset();
                finding.inputOutcome = input.pteView.outcome;
                addFact(finding.facts, "pte.va", hexText(kVa));
                addFact(finding.facts, "pte.page-size", decText(extent.pageSize));
                addFact(finding.facts, "pte.writable", extent.writable ? "true" : "false");
                addFact(finding.facts, "pte.user", extent.userAccessible ? "true" : "false");
                if (extent.firstEntryValue.present) {
                    addFact(finding.facts, "pte.value", hexText(extent.firstEntryValue.value));
                }
                report.findings.push_back(std::move(finding));
            } else if (kVadRequested && input.vadView.state == KernelBackendState::kAvailable &&
                       !kVadHas) {
                ++report.executableBeyondViewCount;
                KernelRegionCrossFinding finding;
                finding.issue = KernelRegionCrossIssue::kExecutableBeyondVadView;
                finding.startVa = extent.startVa;
                finding.inputOutcome = input.pteView.outcome;
                addFact(finding.facts, "pte.va", hexText(kVa));
                report.findings.push_back(std::move(finding));
            }
        }
    }

    /*
     * The conclusion only reaches Indeterminate. The rationale is documented here rather than left as a 'to be discussed later' comment:
     * The legitimate causes for kernel cross-differences (copy-on-write, prototype PTEs, deferred table creation for shared
     * mappings, session spaces, etc.) have not yet been established on real hardware data. Assigning certainty without measurement
     * is exactly what Issue Node 6 aims to avoid. Reconsider upgrading only after establishing a real hardware baseline.
     */
    if (!report.findings.empty()) {
        addUnique(report.capabilityLimitKeys, kLimitKernelBenignBaseline);
    }
    const bool kAnyObservation =
        (kVadRequested && statusCarriesObservation(input.vadView.outcome.status)) ||
        (kPteRequested && statusCarriesObservation(input.pteView.outcome.status));
    if (!kAnyObservation) {
        report.conclusion = AnalysisConclusion::kNoEvidence;
    } else if (!report.findings.empty()) {
        report.conclusion = AnalysisConclusion::kIndeterminate;
    } else if (report.absenceInferenceAllowed && report.coverageGapKeys.empty()) {
        report.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    } else {
        report.conclusion = AnalysisConclusion::kIndeterminate;
    }
    return report;
}

// ---------------------------------------------------------------------------
// Exception
// ---------------------------------------------------------------------------

const char* exceptionCategoryName(const ExceptionCategory category) noexcept {
    switch (category) {
    case ExceptionCategory::kUnspecified: return "Unspecified";
    case ExceptionCategory::kRuntimeDynamicCode: return "RuntimeDynamicCode";
    case ExceptionCategory::kSecurityInstrumentation: return "SecurityInstrumentation";
    case ExceptionCategory::kSoftwareProtection: return "SoftwareProtection";
    case ExceptionCategory::kSystemCompatibility: return "SystemCompatibility";
    }
    return "Unspecified";
}

const char* exceptionAdmissionName(const ExceptionAdmission admission) noexcept {
    switch (admission) {
    case ExceptionAdmission::kAccepted: return "Accepted";
    case ExceptionAdmission::kMissingRuleId: return "MissingRuleId";
    case ExceptionAdmission::kMissingCategory: return "MissingCategory";
    case ExceptionAdmission::kMissingTargetImageIdentity: return "MissingTargetImageIdentity";
    case ExceptionAdmission::kMissingModuleIdentity: return "MissingModuleIdentity";
    case ExceptionAdmission::kEmptyRange: return "EmptyRange";
    case ExceptionAdmission::kRangeTooWide: return "RangeTooWide";
    }
    return "MissingRuleId";
}

ExceptionAdmission admitExceptionRelation(const ExceptionRelation& rule) noexcept {
    if (rule.ruleId.empty()) {
        return ExceptionAdmission::kMissingRuleId;
    }
    if (rule.category == ExceptionCategory::kUnspecified) {
        return ExceptionAdmission::kMissingCategory;
    }
    if (rule.targetImageIdentity.empty()) {
        return ExceptionAdmission::kMissingTargetImageIdentity;
    }
    if (rule.modifiedModuleIdentity.empty()) {
        return ExceptionAdmission::kMissingModuleIdentity;
    }
    if (rule.modifiedRange.empty()) {
        return ExceptionAdmission::kEmptyRange;
    }
    if (rule.modifiedRange.length > kExplanationRuleMaxSpanBytes) {
        // A module-wide "exemption" is equivalent to permanently allowing the entire module.
        return ExceptionAdmission::kRangeTooWide;
    }
    return ExceptionAdmission::kAccepted;
}

const char* exceptionMatchName(const ExceptionMatch match) noexcept {
    switch (match) {
    case ExceptionMatch::kNoRule: return "NoRule";
    case ExceptionMatch::kAllRulesRejected: return "AllRulesRejected";
    case ExceptionMatch::kTargetImageMismatch: return "TargetImageMismatch";
    case ExceptionMatch::kModuleMismatch: return "ModuleMismatch";
    case ExceptionMatch::kRangeNotCovered: return "RangeNotCovered";
    case ExceptionMatch::kBranchTargetMismatch: return "BranchTargetMismatch";
    case ExceptionMatch::kBytesUnavailable: return "BytesUnavailable";
    case ExceptionMatch::kBytesMismatch: return "BytesMismatch";
    case ExceptionMatch::kMatched: return "Matched";
    }
    return "NoRule";
}

std::string moduleIdentityKeyFor(const DriverInstanceId& module) {
    const std::string kKey = module.crossSessionKey();
    return kKey.empty() ? normalizePath(module.imagePath) : kKey;
}

ExceptionMatchResult matchExceptionRelation(const std::vector<ExceptionRelation>& rules,
                                            const ExceptionQuery& query) {
    ExceptionMatchResult result;
    if (rules.empty()) {
        result.match = ExceptionMatch::kNoRule;
        return result;
    }

    // Sort failure reasons by 'how far we got' and report the furthest one to help locate the incorrect rule.
    auto rank = [](const ExceptionMatch match) -> int {
        switch (match) {
        case ExceptionMatch::kAllRulesRejected: return 0;
        case ExceptionMatch::kTargetImageMismatch: return 1;
        case ExceptionMatch::kModuleMismatch: return 2;
        case ExceptionMatch::kRangeNotCovered: return 3;
        case ExceptionMatch::kBranchTargetMismatch: return 4;
        case ExceptionMatch::kBytesUnavailable: return 5;
        case ExceptionMatch::kBytesMismatch: return 6;
        case ExceptionMatch::kMatched: return 7;
        case ExceptionMatch::kNoRule: return -1;
        }
        return -1;
    };

    ExceptionMatch best = ExceptionMatch::kAllRulesRejected;
    std::string bestRuleId;
    std::uint32_t bestRuleVersion = 0;
    ExceptionCategory bestCategory = ExceptionCategory::kUnspecified;

    for (const ExceptionRelation& rule : rules) {
        if (admitExceptionRelation(rule) != ExceptionAdmission::kAccepted) {
            ++result.rejectedRuleCount;
            continue;
        }

        ExceptionMatch outcome = ExceptionMatch::kMatched;
        if (rule.targetImageIdentity != query.targetImageIdentity) {
            outcome = ExceptionMatch::kTargetImageMismatch;
        } else if (rule.modifiedModuleIdentity != query.modifiedModuleIdentity) {
            outcome = ExceptionMatch::kModuleMismatch;
        } else if (!rule.modifiedRange.containsRange(query.range)) {
            // Partial coverage does not count as a hit: otherwise, a rule covering a single byte could explain an entire rewrite.
            outcome = ExceptionMatch::kRangeNotCovered;
        } else if (!rule.allowedBranchTargetModuleIdentity.empty() &&
                   rule.allowedBranchTargetModuleIdentity !=
                       query.actualBranchTargetModuleIdentity) {
            outcome = ExceptionMatch::kBranchTargetMismatch;
        } else if (!rule.expectedBytes.empty()) {
            if (!query.bytesAvailable) {
                // Rule requires byte verification but bytes are unavailable — no match. Whitelists must be fail-closed.
                outcome = ExceptionMatch::kBytesUnavailable;
            } else if (rule.expectedBytes != query.actualBytes) {
                outcome = ExceptionMatch::kBytesMismatch;
            }
        }

        if (rank(outcome) > rank(best)) {
            best = outcome;
            bestRuleId = rule.ruleId;
            bestRuleVersion = rule.ruleVersion;
            bestCategory = rule.category;
        }
        if (outcome == ExceptionMatch::kMatched) {
            break;
        }
    }

    result.match = best;
    result.ruleId = std::move(bestRuleId);
    result.ruleVersion = bestRuleVersion;
    result.category = bestCategory;
    return result;
}

// ---------------------------------------------------------------------------
// Rule ID / gap key / check item key
// ---------------------------------------------------------------------------

const char* const kRuleIdDynamicCodeRegion = "inject.region.dynamic-code";
const char* const kRuleIdImageBytesUnexplained = "inject.image.unexplained-diff";
const char* const kRuleIdImageReferenceUncertain = "inject.image.reference-uncertain";
const char* const kRuleIdImageWithoutLoaderEntry = "inject.module.image-without-loader";
const char* const kRuleIdLoaderEntryWithoutMapping = "inject.module.loader-without-mapping";
const char* const kRuleIdModuleIdentityMismatch = "inject.module.identity-mismatch";
const char* const kRuleIdMainImageConflict = "inject.main-image.conflict";
const char* const kRuleIdThreadStartOutsideImage = "inject.thread.start-outside-image";
const char* const kRuleIdThreadStartUnknown = "inject.thread.start-unknown";
const char* const kRuleIdThreadStartTrampoline = "inject.thread.start-trampoline";
const char* const kRuleIdPayloadStructure = "inject.payload.structure";
const char* const kRuleIdKernelRegionHiddenFromR3 = "inject.kernel.region-hidden-from-r3";
const char* const kRuleIdKernelRegionMissingInVad = "inject.kernel.region-missing-in-vad";
const char* const kRuleIdKernelExecutableBeyondView = "inject.kernel.executable-beyond-view";
const char* const kRuleIdKernelVadLinkBroken = "inject.kernel.vad-link-broken";

const char* const kGapAddressSpaceIncomplete = "inject.gap.address-space";
const char* const kGapLoaderViewUnavailable = "inject.gap.loader-view";
const char* const kGapImageViewUnavailable = "inject.gap.image-view";
const char* const kGapPayloadViewUnavailable = "inject.gap.payload-view";
const char* const kGapMappedPathUnavailable = "inject.gap.mapped-path";
const char* const kGapWorkingSetUnavailable = "inject.gap.working-set";
const char* const kGapThreadStartUnavailable = "inject.gap.thread-start";
const char* const kGapReferenceUncertain = "inject.gap.reference-uncertain";
const char* const kGapBudgetTruncated = "inject.gap.budget-truncated";
const char* const kGapIdentityChanged = "inject.gap.identity-changed";
const char* const kGapIdentityUnverifiable = "inject.gap.identity-unverifiable";
const char* const kGapModuleEnumerationWow64 = "inject.gap.module-enum-wow64";
const char* const kGapMainImageSourceMissing = "inject.gap.main-image-source";
const char* const kGapKernelBackendUnavailable = "inject.gap.kernel-backend";
const char* const kGapKernelProfileUnverified = "inject.gap.kernel-profile";
const char* const kGapVadLinkUncheckable = "inject.gap.vad-link-uncheckable";
const char* const kGapSectionReferenceIncomplete = "inject.gap.section-reference";
const char* const kGapStackWalkUntrusted = "inject.gap.stack-untrusted";
const char* const kLimitNonExecutableNotScanned = "inject.limit.non-executable";
const char* const kLimitStackUnwindUnavailable = "inject.limit.stack-unwind";
const char* const kLimitPayloadHeaderErased = "inject.limit.payload-erased-header";
const char* const kLimitRuntimeAttribution = "inject.limit.runtime-attribution";
const char* const kLimitKernelTrustAssumption = "inject.limit.kernel-trust";
const char* const kLimitKernelVadFlagsUnverified = "inject.limit.kernel-vad-flags";
const char* const kLimitKernelSectionCompare = "inject.limit.kernel-section-compare";
const char* const kLimitKernelBenignBaseline = "inject.limit.kernel-benign-baseline";
const char* const kLimitKernelBackendAbsent = "inject.limit.kernel-backend-absent";

const char* const kCheckAddressSpaceIndex = "inject.check.address-space";
const char* const kCheckModuleCrossView = "inject.check.module-cross-view";
const char* const kCheckWorkingSetScreen = "inject.check.working-set";
const char* const kCheckThreadStart = "inject.check.thread-start";
const char* const kCheckNormalizedImageDiff = "inject.check.image-diff";
const char* const kCheckPayloadStructure = "inject.check.payload-structure";
const char* const kCheckNonExecutableScan = "inject.check.non-executable";
const char* const kCheckReliableStackWalk = "inject.check.stack-walk";
const char* const kCheckKernelVadCrossView = "inject.check.kernel-vad";
const char* const kCheckVadLinkIntegrity = "inject.check.vad-link";
const char* const kCheckKernelPteScan = "inject.check.kernel-pte";

const char* evidenceConfidenceName(const EvidenceConfidence confidence) noexcept {
    switch (confidence) {
    case EvidenceConfidence::kInputIncomplete: return "InputIncomplete";
    case EvidenceConfidence::kSingleObservation: return "SingleObservation";
    case EvidenceConfidence::kCorroboratedIndependent: return "CorroboratedIndependent";
    }
    return "InputIncomplete";
}

bool InjectionFinding::explainedByException() const noexcept {
    return exception.match == ExceptionMatch::kMatched;
}

// ---------------------------------------------------------------------------
// Observation semantics table
// ---------------------------------------------------------------------------

const char* observationClassName(const ObservationClass observation) noexcept {
    switch (observation) {
    case ObservationClass::kPrivateOrMappedExecutablePresent:
        return "PrivateOrMappedExecutablePresent";
    case ObservationClass::kNormalizedImageDiffers: return "NormalizedImageDiffers";
    case ObservationClass::kPayloadStructureWithReliableFrame:
        return "PayloadStructureWithReliableFrame";
    case ObservationClass::kMappedModuleOutsideBaseline: return "MappedModuleOutsideBaseline";
    case ObservationClass::kVadTreeLinkageInconsistent: return "VadTreeLinkageInconsistent";
    case ObservationClass::kScanCompleteNoStrongEvidence: return "ScanCompleteNoStrongEvidence";
    case ObservationClass::kKeyInputUnavailable: return "KeyInputUnavailable";
    }
    return "KeyInputUnavailable";
}

ObservationSemantics semanticsFor(const ObservationClass observation) noexcept {
    ObservationSemantics semantics;
    semantics.observation = observation;
    switch (observation) {
    case ObservationClass::kPrivateOrMappedExecutablePresent:
        semantics.allowedConclusionKey = "inject.semantics.dynamic-code.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.dynamic-code.forbidden";
        semantics.contribution = AnalysisConclusion::kIndeterminate;
        break;
    case ObservationClass::kNormalizedImageDiffers:
        semantics.allowedConclusionKey = "inject.semantics.image-diff.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.image-diff.forbidden";
        semantics.contribution = AnalysisConclusion::kDifferenceObserved;
        break;
    case ObservationClass::kPayloadStructureWithReliableFrame:
        semantics.allowedConclusionKey = "inject.semantics.payload-frame.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.payload-frame.forbidden";
        semantics.contribution = AnalysisConclusion::kDifferenceObserved;
        break;
    case ObservationClass::kMappedModuleOutsideBaseline:
        semantics.allowedConclusionKey = "inject.semantics.module-baseline.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.module-baseline.forbidden";
        semantics.contribution = AnalysisConclusion::kIndeterminate;
        break;
    case ObservationClass::kVadTreeLinkageInconsistent:
        semantics.allowedConclusionKey = "inject.semantics.vad-link.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.vad-link.forbidden";
        // Stops at "needs explanation." Chain removal has no known benign causes, but **the false positive rate for this
        // dimension has not yet been measured on real machines**, and traversal is concurrent with kernel tree modification. Ship
        // as Indeterminate first, then consider upgrading after measurement, for the same reason as kLimitKernelBenignBaseline.
        semantics.contribution = AnalysisConclusion::kIndeterminate;
        break;
    case ObservationClass::kScanCompleteNoStrongEvidence:
        semantics.allowedConclusionKey = "inject.semantics.no-strong-evidence.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.no-strong-evidence.forbidden";
        semantics.contribution = AnalysisConclusion::kNoDifferenceObserved;
        break;
    case ObservationClass::kKeyInputUnavailable:
        semantics.allowedConclusionKey = "inject.semantics.input-unavailable.allowed";
        semantics.forbiddenConclusionKey = "inject.semantics.input-unavailable.forbidden";
        semantics.contribution = AnalysisConclusion::kIndeterminate;
        break;
    }
    return semantics;
}

// ---------------------------------------------------------------------------
// Identity recheck
// ---------------------------------------------------------------------------

const char* identityRecheckVerdictName(const IdentityRecheckVerdict verdict) noexcept {
    switch (verdict) {
    case IdentityRecheckVerdict::kSame: return "Same";
    case IdentityRecheckVerdict::kChanged: return "Changed";
    case IdentityRecheckVerdict::kUnverifiable: return "Unverifiable";
    }
    return "Unverifiable";
}

IdentityRecheckVerdict recheckProcessIdentity(const ProcessInstanceId& before,
                                              const ProcessInstanceId& after) noexcept {
    switch (matchProcessInstance(before, after)) {
    case MatchResult::kConfirmed: return IdentityRecheckVerdict::kSame;
    case MatchResult::kNoMatch: return IdentityRecheckVerdict::kChanged;
    case MatchResult::kCandidate: return IdentityRecheckVerdict::kUnverifiable;
    }
    return IdentityRecheckVerdict::kUnverifiable;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

bool SurveyReport::hasObservation(const ObservationClass observation) const noexcept {
    return std::find(observations.begin(), observations.end(), observation) !=
           observations.end();
}

bool SurveyReport::hasGap(const std::string& gapKey) const noexcept {
    return std::find(coverageGapKeys.begin(), coverageGapKeys.end(), gapKey) !=
           coverageGapKeys.end();
}

bool SurveyReport::hasLimit(const std::string& limitKey) const noexcept {
    return std::find(capabilityLimitKeys.begin(), capabilityLimitKeys.end(), limitKey) !=
           capabilityLimitKeys.end();
}

namespace {

void addObservation(SurveyReport& report, const ObservationClass observation) {
    if (!report.hasObservation(observation)) {
        report.observations.push_back(observation);
    }
}

InjectionFinding makeFinding(const SurveyInput& input, const char* ruleId) {
    InjectionFinding finding;
    finding.ruleId = ruleId;
    finding.ruleVersion = kInjectionSurveyRuleSetVersion;
    finding.detectorVersion = input.detectorVersion;
    finding.payloadProcess = input.processBefore;
    finding.firstObservedUtc100ns = input.collectedUtc100ns;
    // The injector source process is unknown by default, and this module provides no entry point to elevate it.
    finding.injectorAttribution = OwnerAttribution::kUnknown;
    return finding;
}

} // namespace

SurveyReport runInjectionSurvey(const SurveyInput& input) {
    SurveyReport report;
    report.mode = input.mode;
    report.detectorVersion = input.detectorVersion;
    report.process = input.processBefore;
    report.firstObservedUtc100ns = input.collectedUtc100ns;
    report.identity = recheckProcessIdentity(input.processBefore, input.processAfter);

    // --- Identity recheck. If Changed, discard the entire evidence: it may belong to another process instance. ---
    if (report.identity == IdentityRecheckVerdict::kChanged) {
        addUnique(report.coverageGapKeys, kGapIdentityChanged);
        addObservation(report, ObservationClass::kKeyInputUnavailable);
        report.conclusion = AnalysisConclusion::kNoEvidence;
        report.scopeIntact = false;
        report.coverageComplete = false;
        report.notPerformedCheckKeys = {
            kCheckAddressSpaceIndex, kCheckModuleCrossView, kCheckWorkingSetScreen,
            kCheckThreadStart, kCheckNormalizedImageDiff, kCheckPayloadStructure,
        };
        return report;
    }
    if (report.identity == IdentityRecheckVerdict::kUnverifiable) {
        addUnique(report.coverageGapKeys, kGapIdentityUnverifiable);
    }

    const ModuleEnumerationTrust kTrust =
        evaluateModuleEnumerationTrust(input.collectorArchitecture, input.targetArchitecture);
    if (kTrust == ModuleEnumerationTrust::kFilterIgnoredUnderWow64) {
        addUnique(report.coverageGapKeys, kGapModuleEnumerationWow64);
    }

    // --- Address space index ---
    const bool kAddressSpaceUsable = statusCarriesObservation(input.addressSpace.outcome.status);
    if (kAddressSpaceUsable) {
        addUnique(report.completedCheckKeys, kCheckAddressSpaceIndex);
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckAddressSpaceIndex);
    }
    if (!input.addressSpace.usableForAbsenceInference()) {
        addUnique(report.coverageGapKeys, kGapAddressSpaceIncomplete);
    }

    // Do not report the same memory region twice. 'Private Executable' and 'Contains Payload Structure' describe the same memory;
    // reporting both would duplicate a single observation in the evidence list, mirroring the duplicate scoring issue at node 6 (no scores
    // here, but the list noise is identical). Therefore, prioritize the Payload Structure entry and merge it with the Region entry.
    std::unordered_map<std::uint64_t, std::size_t> dynamicFindingByBase;

    for (std::size_t i = 0; i < input.addressSpace.entries.size() &&
                            i < input.addressSpace.codeClasses.size();
         ++i) {
        const RegionCodeClass kCodeClass = input.addressSpace.codeClasses[i];
        if (!isDynamicCodeCandidate(kCodeClass)) {
            continue;
        }
        const RegionRecord& record = input.addressSpace.entries[i];
        ++report.dynamicCodeRegionCount;
        if (record.base.present) {
            dynamicFindingByBase.emplace(record.base.value, report.findings.size());
        }

        InjectionFinding finding = makeFinding(input, kRuleIdDynamicCodeRegion);
        finding.address = record.base;
        finding.size = record.size;
        finding.regionType = record.type;
        finding.protection = record.protection;
        finding.mappedPath = record.mappedPath;
        finding.inputOutcome = input.addressSpace.outcome;
        finding.confidence = EvidenceConfidence::kSingleObservation;
        addFact(finding.facts, "region.code-class", regionCodeClassName(kCodeClass));
        const ProtectionFacts kProtection = classifyWin32Protection(record.protection.rawValue);
        addFact(finding.facts, "region.execute", executeProtectionName(kProtection.execute));
        if (kProtection.writable) {
            addFact(finding.facts, "region.writable", "true");
        }
        if (kProtection.guard) {
            addFact(finding.facts, "region.guard", "true");
        }
        if (record.allocationBase.present) {
            addFact(finding.facts, "region.allocation-base",
                    hexText(record.allocationBase.value));
        }
        if (record.mappedPath.empty() && record.type == RegionType::kMapped) {
            addFact(finding.facts, "region.mapped-path", "unavailable");
            addUnique(finding.coverageGapKeys, kGapMappedPathUnavailable);
        }
        report.findings.push_back(std::move(finding));
    }
    if (report.dynamicCodeRegionCount != 0U) {
        addObservation(report, ObservationClass::kPrivateOrMappedExecutablePresent);
    }

    // --- Module cross view ---
    if (input.moduleCrossView.conclusion != AnalysisConclusion::kNoEvidence) {
        addUnique(report.completedCheckKeys, kCheckModuleCrossView);
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckModuleCrossView);
    }
    for (const std::string& gap : input.moduleCrossView.coverageGapKeys) {
        addUnique(report.coverageGapKeys, gap);
    }
    for (const ModuleCrossFinding& crossFinding : input.moduleCrossView.findings) {
        const char* ruleId = kRuleIdModuleIdentityMismatch;
        switch (crossFinding.issue) {
        case ModuleCrossIssue::kImageMappingWithoutLoaderEntry:
            ruleId = kRuleIdImageWithoutLoaderEntry;
            break;
        case ModuleCrossIssue::kLoaderEntryWithoutImageMapping:
            ruleId = kRuleIdLoaderEntryWithoutMapping;
            break;
        case ModuleCrossIssue::kMainImageIdentityConflict:
            ruleId = kRuleIdMainImageConflict;
            break;
        case ModuleCrossIssue::kMappedPathUnavailable:
            // Path retrieval failure is merely a gap, not a finding; the gap key has already been merged.
            continue;
        case ModuleCrossIssue::kLoaderPathMismatch:
        case ModuleCrossIssue::kLoaderSizeMismatch:
            ruleId = kRuleIdModuleIdentityMismatch;
            break;
        }
        ++report.moduleCrossIssueCount;
        if (moduleCrossIssueIsContradiction(crossFinding.issue)) {
            ++report.moduleCrossConflictCount;
        }
        InjectionFinding finding = makeFinding(input, ruleId);
        finding.address = crossFinding.base;
        finding.size = crossFinding.mappedSize.present ? crossFinding.mappedSize
                                                       : crossFinding.loaderSize;
        finding.regionType = RegionType::kImage;
        finding.mappedPath = crossFinding.mappedPath.empty() ? crossFinding.loaderPath
                                                             : crossFinding.mappedPath;
        finding.moduleName = fileNameOf(finding.mappedPath);
        finding.facts = crossFinding.facts;
        finding.inputOutcome = crossFinding.inputOutcome;
        finding.confidence = EvidenceConfidence::kCorroboratedIndependent;
        addFact(finding.facts, "module.cross-issue", moduleCrossIssueName(crossFinding.issue));
        report.findings.push_back(std::move(finding));
        addObservation(report, ObservationClass::kMappedModuleOutsideBaseline);
    }

    // --- Working set filtering ---
    if (input.workingSetQueried && statusCarriesObservation(input.workingSetOutcome.status)) {
        addUnique(report.completedCheckKeys, kCheckWorkingSetScreen);
        if (!outcomeIsSuccess(input.workingSetOutcome)) {
            addUnique(report.coverageGapKeys, kGapWorkingSetUnavailable);
        }
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckWorkingSetScreen);
        addUnique(report.coverageGapKeys, kGapWorkingSetUnavailable);
    }

    // --- Thread start ---
    if (statusCarriesObservation(input.threadEnumerationOutcome.status) &&
        !input.threadStarts.empty()) {
        addUnique(report.completedCheckKeys, kCheckThreadStart);
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckThreadStart);
        addUnique(report.coverageGapKeys, kGapThreadStartUnavailable);
    }
    for (const ThreadStartFinding& start : input.threadStarts) {
        const bool kAnomalous = start.landing == ThreadStartLanding::kNonImagePrivate ||
                               start.landing == ThreadStartLanding::kNonImageMapped ||
                               start.landing == ThreadStartLanding::kFreeOrReserved ||
                               start.landing == ThreadStartLanding::kImageOutsideCode;
        const bool kUnknown = start.landing == ThreadStartLanding::kNotCollected ||
                             start.landing == ThreadStartLanding::kOutsideIndex ||
                             start.landing == ThreadStartLanding::kImageLayoutUnknown;
        const bool kTrampoline = start.branchTarget.present &&
                                start.branchLeavesOwningModule;
        if (!kAnomalous && !kUnknown && !kTrampoline) {
            continue;
        }

        // A missing start point is not an ownership mismatch. Use different ruleId values, or a
        // result with no observations would raise the conclusion from NoEvidence to Indeterminate.
        const char* ruleId = kRuleIdThreadStartOutsideImage;
        if (kUnknown && !kAnomalous) {
            ruleId = kRuleIdThreadStartUnknown;
        } else if (kTrampoline && !kAnomalous) {
            ruleId = kRuleIdThreadStartTrampoline;
        }

        InjectionFinding finding = makeFinding(input, ruleId);
        finding.address = start.startAddress;
        finding.mappedPath = start.owningPath;
        finding.moduleName = fileNameOf(start.owningPath);
        finding.facts = start.facts;
        finding.relatedThreads.push_back(start.thread);
        finding.inputOutcome = start.outcome;
        finding.confidence = kUnknown ? EvidenceConfidence::kInputIncomplete
                                     : EvidenceConfidence::kSingleObservation;
        if (kUnknown) {
            addUnique(finding.coverageGapKeys, kGapThreadStartUnavailable);
            addUnique(report.coverageGapKeys, kGapThreadStartUnavailable);
        } else {
            ++report.threadStartAnomalyCount;
        }
        report.findings.push_back(std::move(finding));
    }

    // --- Normalized Image Comparison ---
    if (!input.imageComparisons.empty()) {
        addUnique(report.completedCheckKeys, kCheckNormalizedImageDiff);
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckNormalizedImageDiff);
    }
    if (input.plannedComparisonsNotRun != 0U) {
        addUnique(report.coverageGapKeys, kGapBudgetTruncated);
    }

    for (const ImageComparisonOutcome& comparison : input.imageComparisons) {
        const bool kReferenceUsable = referenceSupportsDifferenceClaim(
            comparison.referenceConfidence);
        if (!kReferenceUsable) {
            addUnique(report.coverageGapKeys, kGapReferenceUncertain);
        }
        if (comparison.referenceSource == ImageReferenceSource::kSectionObject) {
            ++report.sectionReferenceComparisons;
            if (!sectionReferenceCoverageComplete(comparison)) {
                // The section object reference cannot resolve a page (the prototype PTE is not in a valid state;
                // by design, this version does not bring the page into memory). The difference is still counted,
                // but "no difference found" is invalid—pages that were not matched are still considered compared.
                addUnique(report.coverageGapKeys, kGapSectionReferenceIncomplete);
            }
        }
        for (const std::string& limitation : comparison.report.limitationKeys) {
            if (imageLimitationIsScopeDefining(limitation)) {
                addUnique(report.capabilityLimitKeys, limitation);
            } else {
                addUnique(report.coverageGapKeys, limitation);
            }
        }

        for (const ImageDiffEntry& entry : comparison.report.entries) {
            if (entry.kind == DiffKind::kMissingLiveBytes) {
                addUnique(report.coverageGapKeys, kGapAddressSpaceIncomplete);
                continue;
            }
            if (entry.explanation == DiffExplanation::kExplained) {
                continue;  // ImageDiff's own rules have already explained this.
            }

            ExceptionQuery query;
            // The target program version identity and the modified module identity are distinct: the former determines "on which
            // program this exemption is valid," while the latter determines "which module was modified." If the target identity is
            // unavailable, leave it empty; any rule requiring a non-empty targetImageIdentity will fail to match (fail-closed).
            query.targetImageIdentity = input.targetImageIdentity;
            query.modifiedModuleIdentity = moduleIdentityKeyFor(comparison.module);
            query.range = RvaRange{ entry.rva, entry.length };
            query.bytesAvailable = !entry.liveBytes.empty();
            query.actualBytes = entry.liveBytes;
            const ExceptionMatchResult kException =
                matchExceptionRelation(input.exceptions, query);

            InjectionFinding finding = makeFinding(
                input, kReferenceUsable ? kRuleIdImageBytesUnexplained
                                       : kRuleIdImageReferenceUncertain);
            finding.address = OptionalU64::of(entry.va);
            finding.size = OptionalU64::of(entry.length);
            finding.regionType = RegionType::kImage;
            finding.mappedPath = comparison.module.imagePath;
            finding.moduleName = fileNameOf(comparison.module.imagePath);
            finding.sectionName = entry.sectionName;
            finding.rva = OptionalU64::of(entry.rva);
            finding.exception = kException;
            finding.inputOutcome = comparison.report.outcome;
            finding.confidence = kReferenceUsable ? EvidenceConfidence::kSingleObservation
                                                 : EvidenceConfidence::kInputIncomplete;
            addFact(finding.facts, "image.reference",
                    referenceConfidenceName(comparison.referenceConfidence));
            addFact(finding.facts, "image.rva", hexText(entry.rva));
            addFact(finding.facts, "image.length", decText(entry.length));
            addFact(finding.facts, "image.normalization", kNormalizationProfileId);
            if (entry.byteEvidenceTruncated) {
                addFact(finding.facts, "image.byte-evidence", "truncated");
            }
            if (kException.match == ExceptionMatch::kMatched) {
                ++report.exceptionExplainedCount;
                addFact(finding.facts, "exception.rule", kException.ruleId);
                addFact(finding.facts, "exception.category",
                        exceptionCategoryName(kException.category));
            } else if (kReferenceUsable) {
                ++report.unexplainedImageDiffCount;
            }
            if (!kReferenceUsable) {
                addUnique(finding.coverageGapKeys, kGapReferenceUncertain);
            }
            report.findings.push_back(std::move(finding));
        }
    }
    if (report.unexplainedImageDiffCount != 0U) {
        addObservation(report, ObservationClass::kNormalizedImageDiffers);
    }

    // --- Stack backtrace: calculate the landing points for each frame within the reliable prefix --- The collection
    // side only provides raw frames and the fact of "whether the previous frame had unwind data"; reliability
    // determination happens entirely here, as this layer has offline testing while the collection side does not.
    struct ReliableFrameHit final {
        std::uint64_t instructionPointer = 0U;
        ThreadInstanceId thread;
        std::size_t depth = 0U;
    };
    std::vector<ReliableFrameHit> reliableFrames;
    for (const ThreadStackInput& stack : input.threadStacks) {
        ++report.stackThreadsWalked;
        const std::size_t kAdmitted = admitStackFrames(stack);
        if (kAdmitted == 0U) {
            continue;
        }
        ++report.stackThreadsTrusted;
        for (std::size_t depth = 0U; depth < kAdmitted; ++depth) {
            const RawStackFrame& frame = stack.frames[depth];
            if (!frame.instructionPointer.present) {
                continue;
            }
            ++report.stackReliableFrameCount;
            ReliableFrameHit hit;
            hit.instructionPointer = frame.instructionPointer.value;
            hit.thread = stack.thread;
            hit.depth = depth;
            reliableFrames.push_back(std::move(hit));
        }
    }
    // This bit is recalculated from actual output and must not trust the value provided by the caller; otherwise, 'capability
    // available' would become a switch that can be trivially set to true, yet it is one of the three gates that elevate the conclusion.
    const bool kStackWalkAvailable = report.stackThreadsTrusted != 0U;
    if (report.stackThreadsWalked != 0U && report.stackThreadsTrusted == 0U) {
        // Done, but no trusted context was obtained. This is a coverage gap, not a capability limitation.
        addUnique(report.coverageGapKeys, kGapStackWalkUntrusted);
    }

    // --- Non-Image Payload Structure ---
    bool payloadExamined = false;
    for (const PayloadCandidateEntry& payload : input.payloadCandidates) {
        if (payload.structure != PayloadStructure::kNotExamined) {
            payloadExamined = true;
        }
        const bool kStructural = payload.structure == PayloadStructure::kMappedPeImage ||
                                payload.structure == PayloadStructure::kHeaderErasedPe ||
                                payload.structure == PayloadStructure::kBareCode ||
                                payload.structure == PayloadStructure::kDataOnlyPeFile;
        if (!kStructural) {
            continue;
        }

        // This memory was already reported as a dynamic code region: merge the structural fact into that entry instead of creating a separate line.
        // Record which entry it falls into; the subsequent "reliable frame entry" will add threads and stack depth to the same entry.
        std::size_t payloadFindingIndex = report.findings.size();
        const auto kExisting = payload.base.present
                                  ? dynamicFindingByBase.find(payload.base.value)
                                  : dynamicFindingByBase.end();
        if (kExisting != dynamicFindingByBase.end() && kExisting->second < report.findings.size()) {
            payloadFindingIndex = kExisting->second;
            InjectionFinding& target = report.findings[kExisting->second];
            addFact(target.facts, "payload.structure", payloadStructureName(payload.structure));
            for (const std::string& fact : payload.structureFacts) {
                target.facts.push_back(fact);
            }
        } else {
            InjectionFinding finding = makeFinding(input, kRuleIdPayloadStructure);
            finding.address = payload.base;
            finding.size = payload.size;
            finding.regionType = payload.type;
            finding.inputOutcome = payload.outcome;
            finding.confidence = EvidenceConfidence::kSingleObservation;
            addFact(finding.facts, "payload.structure", payloadStructureName(payload.structure));
            // This bit determines whether the finding can support a stronger conclusion; its source must be traceable in the evidence.
            addFact(finding.facts, "payload.executable-at-scan",
                    payload.executableAtScanTime ? "true" : "false");
            for (const std::string& fact : payload.structureFacts) {
                finding.facts.push_back(fact);
            }
            report.findings.push_back(std::move(finding));
        }

        // Whether the reliable frame entered this memory region. If the caller (or test) has already
        // computed it, use that; otherwise, re-evaluate using the reliable prefix computed above.
        bool frameEnters = payload.reliableFrameEntersRegion;
        const ReliableFrameHit* enteringFrame = nullptr;
        if (payload.base.present && payload.size.present && payload.size.value != 0U) {
            for (const ReliableFrameHit& hit : reliableFrames) {
                // Subtract instead of add: base + size can wrap around with malformed input.
                if (hit.instructionPointer >= payload.base.value &&
                    hit.instructionPointer - payload.base.value < payload.size.value) {
                    frameEnters = true;
                    enteringFrame = &hit;
                    break;
                }
            }
        }

        // The stronger observation is a self-consistent payload structure with a reliable stack frame entering it. All three conditions are required:
        // Stack walking is available, this memory region is **definitely** entered by a reliable frame, and the structure is not
        // "a PE file within data" (a PE file lying in a buffer is distinct from a PE file that has been loaded and executed).
        if (kStackWalkAvailable && frameEnters &&
            payloadCandidateCanRaiseConclusion(payload) &&
            payload.structure != PayloadStructure::kDataOnlyPeFile) {
            addObservation(report, ObservationClass::kPayloadStructureWithReliableFrame);
            ++report.payloadWithExecutionCount;
            if (enteringFrame != nullptr && payloadFindingIndex < report.findings.size()) {
                // The target must be traceable to a specific thread and stack depth; otherwise, 'reliable frame entry' cannot be verified.
                InjectionFinding& target = report.findings[payloadFindingIndex];
                addFact(target.facts, "stack.frame.pc", hexText(enteringFrame->instructionPointer));
                addFact(target.facts, "stack.frame.depth", decText(enteringFrame->depth));
                addFact(target.facts, "stack.frame.tid",
                        decText(enteringFrame->thread.tid.valueOr(0U)));
                target.relatedThreads.push_back(enteringFrame->thread);
                // Memory structure and thread execution are independent sources; only when combined do they suffice for CorroboratedIndependent.
                target.confidence = EvidenceConfidence::kCorroboratedIndependent;
            }
        }
    }
    if (payloadExamined) {
        addUnique(report.completedCheckKeys, kCheckPayloadStructure);
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckPayloadStructure);
    }

    // --- Cross-view of R0 scanning backend ---
    if (input.kernelVadState != KernelBackendState::kNotRequested ||
        input.kernelPteState != KernelBackendState::kNotRequested) {
        if (input.kernelVadState != KernelBackendState::kNotRequested) {
            if (input.kernelVadState == KernelBackendState::kAvailable) {
                addUnique(report.completedCheckKeys, kCheckKernelVadCrossView);
            } else {
                addUnique(report.notPerformedCheckKeys, kCheckKernelVadCrossView);
            }
        }
        if (input.kernelPteState != KernelBackendState::kNotRequested) {
            if (input.kernelPteState == KernelBackendState::kAvailable) {
                addUnique(report.completedCheckKeys, kCheckKernelPteScan);
            } else {
                addUnique(report.notPerformedCheckKeys, kCheckKernelPteScan);
            }
        }
        for (const std::string& gap : input.kernelCrossView.coverageGapKeys) {
            addUnique(report.coverageGapKeys, gap);
        }
        for (const std::string& limit : input.kernelCrossView.capabilityLimitKeys) {
            addUnique(report.capabilityLimitKeys, limit);
        }
        for (const KernelRegionCrossFinding& crossFinding : input.kernelCrossView.findings) {
            const char* ruleId = kRuleIdKernelExecutableBeyondView;
            switch (crossFinding.issue) {
            case KernelRegionCrossIssue::kVadOnlyRange:
                ruleId = kRuleIdKernelRegionHiddenFromR3;
                break;
            case KernelRegionCrossIssue::kR3OnlyCommittedRange:
                ruleId = kRuleIdKernelRegionMissingInVad;
                break;
            case KernelRegionCrossIssue::kExecutableBeyondR3View:
            case KernelRegionCrossIssue::kExecutableBeyondVadView:
                ruleId = kRuleIdKernelExecutableBeyondView;
                break;
            }
            ++report.kernelCrossIssueCount;
            InjectionFinding finding = makeFinding(input, ruleId);
            finding.address = crossFinding.startVa;
            if (crossFinding.startVa.present && crossFinding.endVaExclusive.present &&
                crossFinding.endVaExclusive.value > crossFinding.startVa.value) {
                finding.size = OptionalU64::of(
                    crossFinding.endVaExclusive.value - crossFinding.startVa.value);
            }
            finding.facts = crossFinding.facts;
            finding.inputOutcome = crossFinding.inputOutcome;
            // Note: Both independent sources are present, so this level is corroborated; however, the conclusion remains 'pending explanation'
            // because the directory of legitimate causes has not yet been established on the physical machine (kLimitKernelBenignBaseline).
            finding.confidence = EvidenceConfidence::kCorroboratedIndependent;
            addFact(finding.facts, "kernel.cross-issue",
                    kernelRegionCrossIssueName(crossFinding.issue));
            report.findings.push_back(std::move(finding));
        }

        // --- VAD Link Break: Internal Tree Consistency --- Complementary to the cross-view
        // dimension above: the former asks "Do the two views agree?", while this one asks "Is this
        // tree internally consistent?". The direct evidence of link breaks appears in the latter.
        const KernelCrossViewReport& kernel = input.kernelCrossView;
        report.vadLinkIntegrity = kernel.linkIntegrity;
        if (kernel.linkIntegrity == VadLinkIntegrity::kConsistent) {
            addUnique(report.completedCheckKeys, kCheckVadLinkIntegrity);
        } else if (kernel.linkIntegrity == VadLinkIntegrity::kNotChecked) {
            // Incomplete traversal (truncated / resumed scan / some nodes unreadable), or the VAD backend was never executed.
            // This is a **gap**: intended to check but failed. Converting to "consistent" means treating the failed check as if the tree is valid.
            addUnique(report.notPerformedCheckKeys, kCheckVadLinkIntegrity);
            if (input.kernelVadState == KernelBackendState::kAvailable) {
                addUnique(report.coverageGapKeys, kGapVadLinkUncheckable);
            }
        } else {
            addUnique(report.completedCheckKeys, kCheckVadLinkIntegrity);
            ++report.vadLinkIssueCount;
            InjectionFinding finding = makeFinding(input, kRuleIdKernelVadLinkBroken);
            // Only up to 'Single Observation': the false positive rate for this dimension has not yet been measured on
            // real hardware. Reconsider upgrading after measurement, for the same reason as kLimitKernelBenignBaseline.
            finding.confidence = EvidenceConfidence::kSingleObservation;
            addFact(finding.facts, "vad.visited", decText(kernel.linkVisitedCount));
            if (kernel.linkVadCountKnown) {
                addFact(finding.facts, "vad.count-from-eprocess", decText(kernel.linkVadCount));
            }
            addFact(finding.facts, "vad.parent-mismatch",
                    decText(kernel.linkParentMismatchNodes));
            if (kernel.linkVadHintKnown) {
                addFact(finding.facts, "vad.hint",
                        hexText(kernel.linkVadHintAddress.valueOr(0U)));
                addFact(finding.facts, "vad.hint-visited",
                        kernel.linkVadHintVisited ? "true" : "false");
            }
            addObservation(report, ObservationClass::kVadTreeLinkageInconsistent);
            report.findings.push_back(std::move(finding));
        }
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckKernelVadCrossView);
        addUnique(report.notPerformedCheckKeys, kCheckKernelPteScan);
        addUnique(report.notPerformedCheckKeys, kCheckVadLinkIntegrity);
    }

    // --- Two additional requirements for deep mode ---
    if (input.mode == SurveyMode::kDeep) {
        if (kStackWalkAvailable) {
            addUnique(report.completedCheckKeys, kCheckReliableStackWalk);
        } else if (report.stackThreadsWalked != 0U) {
            // Attempted but failed to obtain trusted context: The gap is already recorded above; here only record 'not completed'.
            // **Do not** record capability limitations anymore — doing so would confuse "this check failed this time" with "this version does not perform this check".
            addUnique(report.notPerformedCheckKeys, kCheckReliableStackWalk);
        } else {
            addUnique(report.notPerformedCheckKeys, kCheckReliableStackWalk);
            addUnique(report.capabilityLimitKeys, kLimitStackUnwindUnavailable);
        }
        if (input.nonExecutableMemoryScanned) {
            addUnique(report.completedCheckKeys, kCheckNonExecutableScan);
        } else {
            // When the payload is dormant, execute permissions need not be retained, so "scan only executable pages" must be explicitly specified.
            addUnique(report.notPerformedCheckKeys, kCheckNonExecutableScan);
            addUnique(report.capabilityLimitKeys, kLimitNonExecutableNotScanned);
        }
    } else {
        addUnique(report.notPerformedCheckKeys, kCheckNonExecutableScan);
        addUnique(report.notPerformedCheckKeys, kCheckReliableStackWalk);
        addUnique(report.capabilityLimitKeys, kLimitNonExecutableNotScanned);
        addUnique(report.capabilityLimitKeys, kLimitStackUnwindUnavailable);
    }

    // --- Collector-reported gaps and capability limitations.
    for (const std::string& gap : input.extraCoverageGapKeys) {
        addUnique(report.coverageGapKeys, gap);
    }
    for (const std::string& limit : input.extraCapabilityLimitKeys) {
        addUnique(report.capabilityLimitKeys, limit);
    }

    // --- Budget truncation: report truncation explicitly; never return a "clean" result ---
    if (input.budgetStop != BudgetStop::kContinue) {
        addUnique(report.coverageGapKeys, kGapBudgetTruncated);
        report.coverage.limitHit = input.budgetStop != BudgetStop::kCancelled;
        report.coverage.cancelled = input.budgetStop == BudgetStop::kCancelled;
    }

    // --- Accounting ---
    report.coverage.succeeded = report.completedCheckKeys.size();
    report.coverage.skipped = report.notPerformedCheckKeys.size();
    report.coverage.totalKnown =
        OptionalU64::of(report.completedCheckKeys.size() + report.notPerformedCheckKeys.size());
    if (!report.coverageGapKeys.empty()) {
        report.coverage.countsIncomplete = true;
    }

    report.scopeIntact = report.coverageGapKeys.empty() &&
                         report.identity == IdentityRecheckVerdict::kSame &&
                         input.budgetStop == BudgetStop::kContinue;
    report.coverageComplete = report.scopeIntact && report.capabilityLimitKeys.empty();
    if (!report.coverageGapKeys.empty()) {
        addObservation(report, ObservationClass::kKeyInputUnavailable);
    }

    // --- Conclusion ---
    const bool kAnyObservation =
        kAddressSpaceUsable ||
        input.moduleCrossView.conclusion != AnalysisConclusion::kNoEvidence ||
        !input.imageComparisons.empty() || !input.threadStarts.empty();

    if (!kAnyObservation) {
        report.conclusion = AnalysisConclusion::kNoEvidence;
    } else if (report.unexplainedImageDiffCount != 0U ||
               report.moduleCrossConflictCount != 0U ||
               report.payloadWithExecutionCount != 0U) {
        // Only these three categories can support DifferenceObserved: differences remaining after normalization against a trusted reference,
        // cross-view contradictions (not merely 'present in one but not the other'), and payload structures where trusted frames enter them.
        // Private RX is merely dynamic code awaiting explanation and cannot support this tier.
        report.conclusion = AnalysisConclusion::kDifferenceObserved;
    } else if (report.dynamicCodeRegionCount != 0U ||
               report.threadStartAnomalyCount != 0U ||
               report.moduleCrossIssueCount != 0U ||
               report.kernelCrossIssueCount != 0U ||
               report.vadLinkIssueCount != 0U ||
               !report.coverageGapKeys.empty()) {
        report.conclusion = AnalysisConclusion::kIndeterminate;
    } else {
        report.conclusion = AnalysisConclusion::kNoDifferenceObserved;
        addObservation(report, ObservationClass::kScanCompleteNoStrongEvidence);
    }

    // Hard gate: If the declared scope is compromised, it can never be 'No Difference Observed'.
    // Note: We use scopeIntact instead of coverageComplete here. Capability limitations should not permanently
    // pin the conclusion to Indeterminate, otherwise the four-state model degrades to three states in production.
    if (!report.scopeIntact &&
        report.conclusion == AnalysisConclusion::kNoDifferenceObserved) {
        report.conclusion = AnalysisConclusion::kIndeterminate;
    }
    return report;
}

} // namespace ksword::evidence

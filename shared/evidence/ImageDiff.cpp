#include "ImageDiff.h"

#include <algorithm>
#include <utility>

namespace ksword::evidence {
namespace {

constexpr std::size_t kNoRule = static_cast<std::size_t>(-1);

// Set of rules that have already passed admission. The index refers back to the caller's original
// `rules` array, ensuring the `ruleId` and `ruleVersion` within the entries match correctly.
std::size_t ruleIndexForRva(const std::vector<ExplanationRule>& rules,
                            const std::vector<std::size_t>& admitted,
                            std::uint32_t rva) noexcept {
    for (const std::size_t kIndex : admitted) {
        if (rules[kIndex].range.contains(rva)) {
            return kIndex;
        }
    }
    return kNoRule;
}

// Original piece before folding. The key is composed of (kind, readStatus, sectionIndex, ruleIndex); any
// change must break the link—otherwise, the folded readStatus or ruleId would not represent the bytes inside.
struct Piece final {
    std::uint32_t rva = 0;
    std::uint32_t length = 0;
    DiffKind kind = DiffKind::kByteDifference;
    ByteReadStatus readStatus = ByteReadStatus::kRead;
    std::size_t sectionIndex = kInvalidSectionIndex;
    std::size_t ruleIndex = kNoRule;

    std::uint64_t endExclusive() const noexcept {
        return static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(length);
    }

    bool sameKey(const Piece& other) const noexcept {
        return kind == other.kind && readStatus == other.readStatus &&
               sectionIndex == other.sectionIndex && ruleIndex == other.ruleIndex;
    }
};

void appendBytes(std::vector<std::uint8_t>& target,
                 const std::vector<std::uint8_t>& source,
                 std::size_t offset,
                 std::size_t count) {
    if (offset >= source.size()) {
        return;
    }
    const std::size_t kAvailable = std::min(count, source.size() - offset);
    target.insert(target.end(),
                  source.begin() + static_cast<std::ptrdiff_t>(offset),
                  source.begin() + static_cast<std::ptrdiff_t>(offset + kAvailable));
}

} // namespace

// ---------------------------------------------------------------------------
// Enum names
// ---------------------------------------------------------------------------

const char* byteReadStatusName(ByteReadStatus status) noexcept {
    switch (status) {
    case ByteReadStatus::kRead:         return "Read";
    case ByteReadStatus::kUnreadable:   return "Unreadable";
    case ByteReadStatus::kNotCollected: return "NotCollected";
    }
    return "NotCollected";
}

const char* diffExplanationName(DiffExplanation explanation) noexcept {
    switch (explanation) {
    case DiffExplanation::kUnexplained: return "Unexplained";
    case DiffExplanation::kExplained:   return "Explained";
    }
    return "Unexplained";
}

const char* diffKindName(DiffKind kind) noexcept {
    switch (kind) {
    case DiffKind::kByteDifference:   return "ByteDifference";
    case DiffKind::kMissingLiveBytes: return "MissingLiveBytes";
    }
    return "ByteDifference";
}

const char* moduleStalenessVerdictName(ModuleStalenessVerdict verdict) noexcept {
    switch (verdict) {
    case ModuleStalenessVerdict::kSame:         return "Same";
    case ModuleStalenessVerdict::kStale:        return "Stale";
    case ModuleStalenessVerdict::kUnverifiable: return "Unverifiable";
    }
    return "Unverifiable";
}

const char* referenceSourceKindName(ReferenceSourceKind kind) noexcept {
    switch (kind) {
    case ReferenceSourceKind::kLocalDisk:         return "LocalDisk";
    case ReferenceSourceKind::kUserSelectedImage: return "UserSelectedImage";
    case ReferenceSourceKind::kSavedSnapshot:     return "SavedSnapshot";
    }
    return "LocalDisk";
}

const char* targetOwnerKindName(TargetOwnerKind kind) noexcept {
    switch (kind) {
    case TargetOwnerKind::kInsideModule:        return "InsideModule";
    case TargetOwnerKind::kOutsideKnownModules: return "OutsideKnownModules";
    }
    return "OutsideKnownModules";
}

const char* followStepKindName(FollowStepKind kind) noexcept {
    switch (kind) {
    case FollowStepKind::kResolvedCode:       return "ResolvedCode";
    case FollowStepKind::kDirectBranch:       return "DirectBranch";
    case FollowStepKind::kIndirectUnresolved: return "IndirectUnresolved";
    case FollowStepKind::kExportForwarder:    return "ExportForwarder";
    case FollowStepKind::kTargetUnreadable:   return "TargetUnreadable";
    }
    return "TargetUnreadable";
}

const char* followTerminationName(FollowTermination termination) noexcept {
    switch (termination) {
    case FollowTermination::kResolved:            return "Resolved";
    case FollowTermination::kDepthExhausted:      return "DepthExhausted";
    case FollowTermination::kByteBudgetExhausted: return "ByteBudgetExhausted";
    case FollowTermination::kCycleDetected:       return "CycleDetected";
    case FollowTermination::kTargetUnreadable:    return "TargetUnreadable";
    case FollowTermination::kOutsideKnownModules: return "OutsideKnownModules";
    case FollowTermination::kIndirectUnresolved:  return "IndirectUnresolved";
    case FollowTermination::kExportForwarder:     return "ExportForwarder";
    }
    return "TargetUnreadable";
}

// ---------------------------------------------------------------------------
// LiveImageBytes
// ---------------------------------------------------------------------------

RvaRange LiveImageBytes::window() const noexcept {
    RvaRange range;
    range.rva = baseRva;
    const std::uint64_t kCount = static_cast<std::uint64_t>(bytes.size());
    const std::uint64_t kEnd = std::min<std::uint64_t>(
        static_cast<std::uint64_t>(baseRva) + kCount, 0xFFFFFFFFULL);
    range.length = static_cast<std::uint32_t>(kEnd - static_cast<std::uint64_t>(baseRva));
    return range;
}

ByteReadStatus LiveImageBytes::statusAt(std::uint32_t rva) const noexcept {
    if (!wellFormed() || rva < baseRva) {
        return ByteReadStatus::kNotCollected;
    }
    const std::uint64_t kOffset = static_cast<std::uint64_t>(rva) - static_cast<std::uint64_t>(baseRva);
    if (kOffset >= static_cast<std::uint64_t>(status.size())) {
        return ByteReadStatus::kNotCollected;
    }
    return status[static_cast<std::size_t>(kOffset)];
}

bool LiveImageBytes::byteAt(std::uint32_t rva, std::uint8_t& out) const noexcept {
    if (statusAt(rva) != ByteReadStatus::kRead) {
        return false;
    }
    const std::size_t kOffset = static_cast<std::size_t>(rva - baseRva);
    out = bytes[kOffset];
    return true;
}

LiveImageBytes LiveImageBytes::fromBytes(std::uint32_t baseRvaIn, std::vector<std::uint8_t> data) {
    LiveImageBytes live;
    live.baseRva = baseRvaIn;
    live.status.assign(data.size(), ByteReadStatus::kRead);
    live.bytes = std::move(data);
    return live;
}

void LiveImageBytes::markRange(const RvaRange& range, ByteReadStatus newStatus) noexcept {
    if (!wellFormed() || range.empty()) {
        return;
    }
    const std::uint64_t kWindowBegin = baseRva;
    const std::uint64_t kWindowEnd = kWindowBegin + static_cast<std::uint64_t>(status.size());
    const std::uint64_t kBegin = std::max<std::uint64_t>(range.rva, kWindowBegin);
    const std::uint64_t kEnd = std::min<std::uint64_t>(range.endExclusive(), kWindowEnd);
    for (std::uint64_t at = kBegin; at < kEnd; ++at) {
        status[static_cast<std::size_t>(at - kWindowBegin)] = newStatus;
    }
}

// ---------------------------------------------------------------------------
// I-04 rule
// ---------------------------------------------------------------------------

const char* ruleAdmissionName(RuleAdmission admission) noexcept {
    switch (admission) {
    case RuleAdmission::kAccepted:              return "Accepted";
    case RuleAdmission::kUnusable:              return "Unusable";
    case RuleAdmission::kCoversWholeImage:      return "CoversWholeImage";
    case RuleAdmission::kNotScopedToOneSection: return "NotScopedToOneSection";
    }
    return "Unusable";
}

RuleAdmission admitExplanationRule(const PeImageMap& reference,
                                   const ExplanationRule& rule) noexcept {
    if (!rule.usable()) {
        return RuleAdmission::kUnusable;
    }
    if (!reference.valid()) {
        // If the reference image cannot be parsed, there is no 'range' to speak of, so exemption does not apply.
        return RuleAdmission::kNotScopedToOneSection;
    }
    RvaRange imageRange;
    imageRange.rva = 0U;
    imageRange.length = reference.header.sizeOfImage;
    if (rule.range.containsRange(imageRange)) {
        // Covering the whole image = permanent allow for the entire driver. This path is explicitly forbidden in the I-04 condition.
        return RuleAdmission::kCoversWholeImage;
    }
    // Exemption must be precise to the range: the entire paragraph must lie within a single mapped section or within the PE header.
    // Cross-section 'evidence' has no verifiable object—a rule cannot explain what it is interpreting in two sections simultaneously.
    if (reference.headerRange.containsRange(rule.range)) {
        return RuleAdmission::kAccepted;
    }
    for (const SectionMap& section : reference.sections) {
        if (section.status != SectionMapStatus::kMapped) {
            continue;
        }
        if (section.virtualRange().containsRange(rule.range)) {
            return RuleAdmission::kAccepted;
        }
    }
    return RuleAdmission::kNotScopedToOneSection;
}

const ExplanationRule* findExplanationRule(const PeImageMap& reference,
                                           const std::vector<ExplanationRule>& rules,
                                           const RvaRange& span) noexcept {
    for (const ExplanationRule& rule : rules) {
        if (admitExplanationRule(reference, rule) == RuleAdmission::kAccepted &&
            rule.range.containsRange(span)) {
            return &rule;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// I-09: Statistics and identity verification.
// ---------------------------------------------------------------------------

void accumulateStats(ScanCoverageStats& accumulator, const ScanCoverageStats& one) noexcept {
    accumulator.modules.attempted += one.modules.attempted;
    accumulator.modules.succeeded += one.modules.succeeded;
    accumulator.modules.failed += one.modules.failed;
    accumulator.modules.excluded += one.modules.excluded;
    accumulator.modules.notAttempted += one.modules.notAttempted;
    accumulator.bytes.attempted += one.bytes.attempted;
    accumulator.bytes.succeeded += one.bytes.succeeded;
    accumulator.bytes.failed += one.bytes.failed;
    accumulator.bytes.excluded += one.bytes.excluded;
    accumulator.bytes.notAttempted += one.bytes.notAttempted;
    accumulator.pages.attempted += one.pages.attempted;
    accumulator.pages.succeeded += one.pages.succeeded;
    accumulator.pages.failed += one.pages.failed;
    accumulator.pages.excluded += one.pages.excluded;
    accumulator.pages.notAttempted += one.pages.notAttempted;
    if (accumulator.pageSize == 0U) {
        accumulator.pageSize = one.pageSize;
    }
}

ModuleStalenessVerdict checkModuleStillSame(const DriverInstanceId& before,
                                            const DriverInstanceId& after) noexcept {
    if (before.strength() == IdentityStrength::kUnusable) {
        // No usable identity exists before the read; no comparison afterward can confirm it is the same module—do not pretend it is.
        return ModuleStalenessVerdict::kUnverifiable;
    }
    if (after.strength() == IdentityStrength::kUnusable) {
        // No identity can be retrieved after reading: the module has been unloaded, or the verification failed. In either case,
        // continuing to interpret differences using old addresses is disallowed; therefore, conservatively mark as stale.
        return ModuleStalenessVerdict::kStale;
    }
    if (!before.bootId.empty() && !after.bootId.empty() && before.bootId != after.bootId) {
        // Addresses across startup cycles are not comparable.
        return ModuleStalenessVerdict::kStale;
    }
    if (before.imageBase.present && after.imageBase.present &&
        before.imageBase.value != after.imageBase.value) {
        // Base address changed within the same boot cycle: the module was reloaded, invalidating all previously computed RVA→VA mappings.
        return ModuleStalenessVerdict::kStale;
    }

    switch (matchDriverInstance(before, after)) {
    case MatchResult::kConfirmed:
        return ModuleStalenessVerdict::kSame;
    case MatchResult::kNoMatch:
        return ModuleStalenessVerdict::kStale;
    case MatchResult::kCandidate:
        return ModuleStalenessVerdict::kUnverifiable;
    }
    return ModuleStalenessVerdict::kUnverifiable;
}

// ---------------------------------------------------------------------------
// I-10 Comparison basis
// ---------------------------------------------------------------------------

std::vector<std::string> buildTrustNotes(const ReferenceSource& source) {
    std::vector<std::string> notes;
    switch (source.kind) {
    case ReferenceSourceKind::kLocalDisk:
        notes.emplace_back("integrity.reference.localDisk");
        // The local disk is not an immutable trust root: an attacker capable of modifying the kernel can generally also modify files on the disk.
        notes.emplace_back("integrity.reference.localDisk.notATrustRoot");
        notes.emplace_back("integrity.reference.localDisk.sameNameMayBeOtherVersion");
        break;
    case ReferenceSourceKind::kUserSelectedImage:
        notes.emplace_back("integrity.reference.userSelected");
        notes.emplace_back("integrity.reference.userSelected.versionMustBeConfirmed");
        notes.emplace_back("integrity.reference.userSelected.providedByOperator");
        break;
    case ReferenceSourceKind::kSavedSnapshot:
        notes.emplace_back("integrity.reference.savedSnapshot");
        notes.emplace_back("integrity.reference.savedSnapshot.mayPredateChange");
        notes.emplace_back("integrity.reference.savedSnapshot.capturedOnThisMachine");
        break;
    }
    // Signature status and 'byte equality' are distinct concepts; this must be clarified regardless of the source.
    notes.emplace_back("integrity.reference.signatureIsNotByteEquality");
    if (source.identity.strength() == IdentityStrength::kUnusable) {
        notes.emplace_back("integrity.reference.identityUnusable");
    }
    return notes;
}

// ---------------------------------------------------------------------------
// I-05: Diff engine
// ---------------------------------------------------------------------------

ImageDiffReport compareImage(const PeImageMap& reference,
                             const LiveImageBytes& live,
                             const ImageDiffOptions& options) {
    ImageDiffReport report;
    report.reference = options.reference;
    report.trustNotes = buildTrustNotes(options.reference);
    report.staleness = options.staleness;
    report.stats.pageSize = (options.pageSize != 0U) ? options.pageSize : 4096U;
    report.stats.modules.attempted = 1U;

    if (!reference.valid()) {
        // The reference image itself cannot be parsed: produce no differences and never produce "no differences found".
        report.outcome = CollectionOutcome::failure(CollectionStatus::kError, "PE",
                                                    static_cast<std::uint64_t>(reference.status),
                                                    reference.errorDetail);
        report.limitationKeys.emplace_back("integrity.limitation.referenceUnparsable");
        report.stats.modules.failed = 1U;
        report.conclusion = AnalysisConclusion::kNoEvidence;
        return report;
    }

    // 1) Calculate the effective comparison set.
    RvaRange imageRange;
    imageRange.rva = 0U;
    imageRange.length = reference.header.sizeOfImage;
    // The default request set uses rawBackedRanges (the scope before excluding notComparable):
    // non-comparable bytes must be recorded as 'excluded' rather than disappearing from the request.
    std::vector<RvaRange> base = options.compareRanges.empty() ? reference.rawBackedRanges
                                                               : options.compareRanges;
    base = intersectRvaRanges(base, std::vector<RvaRange>{imageRange});

    std::vector<RvaRange> excluded = reference.notComparableRanges;
    excluded.insert(excluded.end(), options.excludedRanges.begin(), options.excludedRanges.end());
    excluded = normalizeRvaRanges(std::move(excluded));

    const std::vector<RvaRange> kEffective = subtractRvaRanges(base, excluded);
    report.excludedRanges = intersectRvaRanges(base, excluded);
    report.excludedBytes = rvaRangesTotalBytes(report.excludedRanges);
    const std::uint64_t kEffectiveBytes = rvaRangesTotalBytes(kEffective);

    // 1b) I-04 rule admission: Overly broad or cross-segment rules are discarded while retaining the restriction key. Silent
    //     ignoring misleads the caller into thinking an exemption is active; silent acceptance effectively whitelists the entire module.
    std::vector<std::size_t> admittedRules;
    admittedRules.reserve(options.rules.size());
    bool sawWholeImageRule = false;
    bool sawUnscopedRule = false;
    bool sawUnusableRule = false;
    for (std::size_t index = 0; index < options.rules.size(); ++index) {
        switch (admitExplanationRule(reference, options.rules[index])) {
        case RuleAdmission::kAccepted:
            admittedRules.push_back(index);
            break;
        case RuleAdmission::kCoversWholeImage:
            sawWholeImageRule = true;
            ++report.rejectedRuleCount;
            break;
        case RuleAdmission::kNotScopedToOneSection:
            sawUnscopedRule = true;
            ++report.rejectedRuleCount;
            break;
        case RuleAdmission::kUnusable:
            sawUnusableRule = true;
            ++report.rejectedRuleCount;
            break;
        }
    }

    // 2) Page-level bitmap. SizeOfImage has a 512MB limit, keeping the bitmap size manageable.
    const std::uint32_t kPageSize = report.stats.pageSize;
    const std::size_t kPageCount =
        static_cast<std::size_t>((static_cast<std::uint64_t>(reference.header.sizeOfImage) +
                                  kPageSize - 1U) / kPageSize);
    std::vector<bool> pageCompared(kPageCount, false);
    std::vector<bool> pageFailed(kPageCount, false);
    std::vector<bool> pageExcluded(kPageCount, false);
    // Pages falling within the effective comparison set. When the hit limit is reached and scanning stops early, this
    // ensures pages that were 'never scanned' are recorded in notAttempted rather than disappearing from the accounting.
    std::vector<bool> pageInEffective(kPageCount, false);
    for (const RvaRange& range : kEffective) {
        for (std::uint64_t at = range.rva; at < range.endExclusive(); at += kPageSize) {
            const std::size_t kPage = static_cast<std::size_t>(at / kPageSize);
            if (kPage < kPageCount) {
                pageInEffective[kPage] = true;
            }
        }
        const std::uint64_t kLastPage = (range.endExclusive() - 1U) / kPageSize;
        if (kLastPage < static_cast<std::uint64_t>(kPageCount)) {
            pageInEffective[static_cast<std::size_t>(kLastPage)] = true;
        }
    }
    for (const RvaRange& range : report.excludedRanges) {
        for (std::uint64_t at = range.rva; at < range.endExclusive(); at += kPageSize) {
            const std::size_t kPage = static_cast<std::size_t>(at / kPageSize);
            if (kPage < kPageCount) {
                pageExcluded[kPage] = true;
            }
        }
        const std::uint64_t kLastPage = (range.endExclusive() - 1U) / kPageSize;
        if (kLastPage < static_cast<std::uint64_t>(kPageCount)) {
            pageExcluded[static_cast<std::size_t>(kLastPage)] = true;
        }
    }

    // 3) Scan byte-by-byte to produce unfolded fragments.
    // pieceCap is the actual upper limit that halts the scan: Since folding occurs after scanning, maxEntries cannot
    // control the number of pieces. It must be treated as a public accounting constraint (F-06) and not kept internal.
    const std::size_t kPieceCap = options.maxEntries * 4U + 16U;
    report.entryLimit = static_cast<std::uint64_t>(options.maxEntries);
    report.pieceLimit = static_cast<std::uint64_t>(kPieceCap);
    std::vector<Piece> pieces;
    Piece current;
    bool haveCurrent = false;
    std::size_t cachedSection = kInvalidSectionIndex;
    bool stopped = false;
    OptionalU64 processedBegin;
    std::uint64_t processedEnd = 0U;

    auto flush = [&]() {
        if (haveCurrent) {
            pieces.push_back(current);
            haveCurrent = false;
        }
    };

    for (const RvaRange& range : kEffective) {
        if (stopped) {
            break;
        }
        if (!processedBegin.present) {
            processedBegin = OptionalU64::of(range.rva);
        }
        for (std::uint64_t at = range.rva; at < range.endExclusive(); ++at) {
            const std::uint32_t kRva = static_cast<std::uint32_t>(at);
            const std::size_t kPage = static_cast<std::size_t>(at / kPageSize);
            if (kPage < kPageCount) {
                pageCompared[kPage] = true;
            }
            report.stats.bytes.attempted += 1U;

            const ByteReadStatus kLiveStatus = live.statusAt(kRva);
            if (kLiveStatus == ByteReadStatus::kRead) {
                std::uint8_t liveByte = 0U;
                const bool kGot = live.byteAt(kRva, liveByte);
                const std::uint8_t kReferenceByte = reference.image[static_cast<std::size_t>(kRva)];
                report.comparedBytes += 1U;
                if (kGot && liveByte == kReferenceByte) {
                    // Identical: Break the current segment without generating any entries.
                    flush();
                    processedEnd = at + 1U;
                    continue;
                }
                report.differingBytes += 1U;
            } else {
                // I-05: Unreadable bytes are missing markers; they are excluded from byte comparison and not counted as differences.
                if (kLiveStatus == ByteReadStatus::kUnreadable) {
                    report.unreadableBytes += 1U;
                } else {
                    report.notCollectedBytes += 1U;
                }
                report.stats.bytes.failed += 1U;
                if (kPage < kPageCount) {
                    pageFailed[kPage] = true;
                }
            }

            // Reaching here indicates the byte must enter an entry: either a true difference or a missing marker.
            if (cachedSection == kInvalidSectionIndex ||
                !reference.sections[cachedSection].virtualRange().contains(kRva) ||
                reference.sections[cachedSection].status != SectionMapStatus::kMapped) {
                cachedSection = sectionIndexForRva(reference, kRva);
            }
            const DiffKind kKind = (kLiveStatus == ByteReadStatus::kRead) ? DiffKind::kByteDifference
                                                                       : DiffKind::kMissingLiveBytes;
            // Missing markers imply no explanation: without a read, there is no basis for verification.
            const std::size_t kRuleIndex = (kKind == DiffKind::kByteDifference)
                                              ? ruleIndexForRva(options.rules, admittedRules, kRva)
                                              : kNoRule;

            Piece candidate;
            candidate.rva = kRva;
            candidate.length = 1U;
            candidate.kind = kKind;
            candidate.readStatus = kLiveStatus;
            candidate.sectionIndex = cachedSection;
            candidate.ruleIndex = kRuleIndex;

            if (haveCurrent && current.sameKey(candidate) && current.endExclusive() == at) {
                current.length += 1U;
            } else {
                flush();
                current = candidate;
                haveCurrent = true;
                if (pieces.size() >= kPieceCap) {
                    // Segment count limit hit: retain the partially produced output and explicitly record it as incomplete.
                    stopped = true;
                    report.limitHit = true;
                    break;
                }
            }
            processedEnd = at + 1U;
        }
    }
    flush();

    report.stats.bytes.succeeded = report.comparedBytes;
    report.stats.bytes.excluded = report.excludedBytes;
    // F-06: When the hit fragment limit is reached, the trailing byte in the effective comparison set that hasn't been processed yet enters no bucket.
    // This is neither a failure nor an exclusion; track it in a separate category so that every outcome is accounted for:
    //   attempted + notAttempted + excluded == total bytes in the request set.
    report.notAttemptedBytes =
        (kEffectiveBytes > report.stats.bytes.attempted)
            ? (kEffectiveBytes - report.stats.bytes.attempted)
            : 0U;
    report.stats.bytes.notAttempted = report.notAttemptedBytes;

    for (std::size_t page = 0; page < kPageCount; ++page) {
        // Exclusion and comparison are independent facts: a page can have both compared bytes and excluded bytes. Counting a
        // page as excluded only when 'the entire page was never compared' causes pages with exclusion windows to report 100%
        // success (I-09). Therefore, check the two buckets separately; the same page can enter both attempted and excluded.
        // excluded。
        if (pageCompared[page]) {
            report.stats.pages.attempted += 1U;
            if (pageFailed[page]) {
                report.stats.pages.failed += 1U;
            } else {
                report.stats.pages.succeeded += 1U;
            }
        }
        if (pageExcluded[page]) {
            report.stats.pages.excluded += 1U;
        }
        if (!pageCompared[page] && pageInEffective[page]) {
            report.stats.pages.notAttempted += 1U;
        }
    }
    report.scanStoppedAtPieceLimit = stopped;

    // 4) Collapse into entries. Collapsing occurs only when keys are identical and the gap
    //    does not exceed collapseGapBytes; all original fragments are retained in subRanges.
    std::vector<std::vector<Piece>> groups;
    for (const Piece& piece : pieces) {
        bool merged = false;
        if (!groups.empty()) {
            std::vector<Piece>& back = groups.back();
            const Piece& last = back.back();
            if (last.sameKey(piece) && piece.rva >= last.endExclusive()) {
                const std::uint64_t kGap = static_cast<std::uint64_t>(piece.rva) - last.endExclusive();
                if (kGap <= static_cast<std::uint64_t>(options.collapseGapBytes)) {
                    bool ruleStillCovers = true;
                    if (piece.ruleIndex != kNoRule) {
                        RvaRange span;
                        span.rva = back.front().rva;
                        span.length = static_cast<std::uint32_t>(piece.endExclusive() - span.rva);
                        // The folded entire segment must still fall within the same rule range; otherwise,
                        // the interleaved gap bytes will be incorrectly interpreted along with it.
                        ruleStillCovers = options.rules[piece.ruleIndex].range.containsRange(span);
                    }
                    if (ruleStillCovers) {
                        back.push_back(piece);
                        merged = true;
                    }
                }
            }
        }
        if (!merged) {
            groups.push_back(std::vector<Piece>{piece});
        }
    }

    std::size_t dropped = 0U;
    for (const std::vector<Piece>& group : groups) {
        if (report.entries.size() >= options.maxEntries) {
            ++dropped;
            continue;
        }
        const Piece& first = group.front();
        const Piece& last = group.back();

        ImageDiffEntry entry;
        entry.kind = first.kind;
        entry.module = options.module;   // I-05: The difference must be traceable to a specific module instance
        entry.rva = first.rva;
        entry.length = static_cast<std::uint32_t>(last.endExclusive() - first.rva);
        entry.va = reference.loadedBase + entry.rva;
        entry.readStatus = first.readStatus;
        entry.sectionIndex = first.sectionIndex;
        entry.sectionName = sectionNameForRva(reference, first.rva);
        entry.evidenceSource = options.evidenceSource;
        entry.collapsed = group.size() > 1U;

        // I-05: Disassembly context. This layer has no decoder, so a request to decode yields only "attempted
        // but failed" plus an explicit reason key; no request means "not attempted". These two states must be
        // distinguishable, and neither affects the original byte evidence already filled above.
        if (options.attemptDisassembly) {
            entry.disassembly.attempted = true;
            entry.disassembly.decoded = false;
            entry.disassembly.unavailableReasonKey = kDisassemblyUnavailableNoDecoder;
        }

        if (first.ruleIndex != kNoRule) {
            const ExplanationRule& rule = options.rules[first.ruleIndex];
            entry.explanation = DiffExplanation::kExplained;
            entry.ruleId = rule.ruleId;
            entry.ruleVersion = rule.ruleVersion;
            entry.ruleEvidence = rule.evidenceText;
        }

        for (const Piece& piece : group) {
            DiffSubRange sub;
            sub.rva = piece.rva;
            sub.length = piece.length;
            appendBytes(sub.referenceBytes, reference.image, static_cast<std::size_t>(piece.rva),
                        static_cast<std::size_t>(piece.length));
            if (piece.readStatus == ByteReadStatus::kRead) {
                for (std::uint32_t offset = 0U; offset < piece.length; ++offset) {
                    std::uint8_t value = 0U;
                    if (live.byteAt(piece.rva + offset, value)) {
                        sub.liveBytes.push_back(value);
                    }
                }
            }
            // When readStatus != Read, liveBytes remains empty: never pad with 00.
            entry.subRanges.push_back(std::move(sub));
        }

        // Byte evidence on an entry has a cap; excess data retains only the complete original range descriptions in subRanges.
        // Truncation must be explicitly indicated so the caller does not assume they received all bytes.
        const std::size_t kByteCap = static_cast<std::size_t>(options.maxBytesPerEntry);
        for (const DiffSubRange& sub : entry.subRanges) {
            const std::size_t kReferenceRoom =
                (entry.referenceBytes.size() < kByteCap) ? (kByteCap - entry.referenceBytes.size()) : 0U;
            if (kReferenceRoom < sub.referenceBytes.size()) {
                entry.byteEvidenceTruncated = true;
            }
            appendBytes(entry.referenceBytes, sub.referenceBytes, 0U, kReferenceRoom);
            if (entry.kind == DiffKind::kByteDifference) {
                const std::size_t kLiveRoom =
                    (entry.liveBytes.size() < kByteCap) ? (kByteCap - entry.liveBytes.size()) : 0U;
                if (kLiveRoom < sub.liveBytes.size()) {
                    entry.byteEvidenceTruncated = true;
                }
                appendBytes(entry.liveBytes, sub.liveBytes, 0U, kLiveRoom);
            }
        }

        if (entry.kind == DiffKind::kByteDifference) {
            ++report.byteDifferenceEntries;
            if (entry.explanation == DiffExplanation::kExplained) {
                ++report.explainedEntries;
            } else {
                ++report.unexplainedEntries;
            }
        } else {
            ++report.missingEntries;
        }
        report.entries.push_back(std::move(entry));
    }

    if (dropped != 0U) {
        report.limitHit = true;
    }

    // 5) Account and conclusion.
    report.coverage.requestedBegin =
        base.empty() ? OptionalU64::unset() : OptionalU64::of(base.front().rva);
    report.coverage.requestedEnd =
        base.empty() ? OptionalU64::unset() : OptionalU64::of(base.back().endExclusive());
    report.coverage.processedBegin = processedBegin;
    report.coverage.processedEnd =
        processedBegin.present ? OptionalU64::of(processedEnd) : OptionalU64::unset();
    report.coverage.succeeded = report.comparedBytes;
    report.coverage.failed = report.unreadableBytes + report.notCollectedBytes;
    report.coverage.skipped = report.excludedBytes + report.notAttemptedBytes;
    report.coverage.truncated = dropped;
    report.coverage.limitHit = report.limitHit;
    if (report.limitHit) {
        // F-06: The actual effective limit in the report. Stopping the scan based on piece count while only writing maxEntries would
        // mislead the caller into thinking the constraint is in terms of entry count (different units). Both are exposed in the report.
        report.coverage.limit = OptionalU64::of(report.scanStoppedAtPieceLimit
                                                    ? report.pieceLimit
                                                    : report.entryLimit);
    }

    // I-09 + I-01: Treat Unverifiable and Stale identically. 'Unable to confirm the module is the same before and after
    // reading' is not 'confirmed to be the same module'. Routing this through the normal path would collapse 'analysis unable
    // to determine' into 'correct empty set', which is precisely the distinction Section 4 of F requires. Observed entries
    // are retained, but the conclusion is capped at Indeterminate, and the collection status is downgraded to Partial.
    const bool kIdentityUncertain = (options.staleness == ModuleStalenessVerdict::kStale) ||
                                   (options.staleness == ModuleStalenessVerdict::kUnverifiable);

    CollectionOutcome outcome;
    if (base.empty()) {
        // Empty comparison set: nothing was compared; never escalate to NoDifferenceObserved simply because "no differences were seen".
        outcome.status = CollectionStatus::kNotCollected;
        outcome.message = "integrity.diff.nothingToCompare";
        report.limitationKeys.emplace_back("integrity.limitation.emptyCompareSet");
    } else if (options.staleness == ModuleStalenessVerdict::kStale) {
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "integrity.diff.moduleStale";
    } else if (options.staleness == ModuleStalenessVerdict::kUnverifiable) {
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "integrity.diff.moduleIdentityUnverifiable";
    } else if (report.coverage.fullyCovered()) {
        outcome.status = CollectionStatus::kSuccess;
    } else {
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "integrity.diff.partialCoverage";
    }
    report.outcome = outcome;

    EvidenceEnvelope envelope;
    envelope.outcome = report.outcome;
    envelope.coverage = report.coverage;
    report.conclusion = envelope.deriveConclusion(report.byteDifferenceEntries != 0U);
    if (kIdentityUncertain) {
        // When identity is inconsistent or unconfirmed, the address may already point to something else;
        // do not upgrade observations to any definitive conclusion — including "no differences found."
        report.conclusion = AnalysisConclusion::kIndeterminate;
    }

    if (options.staleness == ModuleStalenessVerdict::kStale) {
        report.stats.modules.failed = 1U;
    } else if (options.staleness == ModuleStalenessVerdict::kUnverifiable) {
        // Neither success nor failure is recorded: bytes were read, but it's unconfirmed whether they belong to this module.
        // Marking as succeeded would wash out uncertainty in multi-module aggregation, while marking as failed would falsely
        // report a collection failure. The difference between attempted and (succeeded + failed) represents this category.
    } else {
        report.stats.modules.succeeded = 1U;
    }

    if (options.staleness == ModuleStalenessVerdict::kStale) {
        report.limitationKeys.emplace_back("integrity.limitation.moduleStale");
    } else if (options.staleness == ModuleStalenessVerdict::kUnverifiable) {
        report.limitationKeys.emplace_back("integrity.limitation.moduleIdentityUnverifiable");
    }
    if (sawWholeImageRule) {
        report.limitationKeys.emplace_back("integrity.limitation.explanationRuleCoversWholeImage");
    }
    if (sawUnscopedRule) {
        report.limitationKeys.emplace_back("integrity.limitation.explanationRuleNotScopedToSection");
    }
    if (sawUnusableRule) {
        report.limitationKeys.emplace_back("integrity.limitation.explanationRuleUnusable");
    }
    if (report.notAttemptedBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.bytesNotAttempted");
    }
    if (report.unreadableBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.unreadableBytes");
    }
    if (report.notCollectedBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.notCollectedBytes");
    }
    if (report.excludedBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.excludedNotComparable");
    }
    if (report.limitHit) {
        report.limitationKeys.emplace_back("integrity.limitation.entryLimitHit");
    }
    switch (reference.relocation.status) {
    case RelocationStatus::kNotNeeded:
    case RelocationStatus::kApplied:
        break;
    case RelocationStatus::kAppliedWithUnsupported:
        report.limitationKeys.emplace_back("integrity.limitation.relocationUnsupportedTypes");
        break;
    case RelocationStatus::kDirectoryMissing:
        report.limitationKeys.emplace_back("integrity.limitation.relocationDirectoryMissing");
        break;
    case RelocationStatus::kDirectoryUnbacked:
        report.limitationKeys.emplace_back("integrity.limitation.relocationDirectoryUnbacked");
        break;
    case RelocationStatus::kDirectoryMalformed:
        report.limitationKeys.emplace_back("integrity.limitation.relocationDirectoryMalformed");
        break;
    case RelocationStatus::kStripped:
        report.limitationKeys.emplace_back("integrity.limitation.relocationsStripped");
        break;
    }
    return report;
}

// ---------------------------------------------------------------------------
// I-06 Jump target and owner.
// ---------------------------------------------------------------------------

TargetOwner resolveTargetOwner(std::uint64_t address, const std::vector<ModuleRange>& modules) {
    TargetOwner owner;
    for (const ModuleRange& module : modules) {
        if (module.contains(address)) {
            owner.kind = TargetOwnerKind::kInsideModule;
            owner.moduleName = module.name;
            owner.moduleBase = OptionalU64::of(module.base);
            owner.offset = OptionalU64::of(address - module.base);
            return owner;
        }
    }
    // Being outside known modules just means "we don't know who owns it," not a definitive judgment.
    owner.kind = TargetOwnerKind::kOutsideKnownModules;
    return owner;
}

FollowResult followBranchTarget(std::uint64_t startAddress,
                                const std::vector<ModuleRange>& modules,
                                const BranchResolver& resolver,
                                const FollowOptions& options) {
    FollowResult result;
    if (!resolver) {
        result.termination = FollowTermination::kTargetUnreadable;
        return result;
    }

    std::vector<std::uint64_t> visited;
    std::uint64_t address = startAddress;
    std::string previousOwnerName;
    bool havePreviousOwner = false;

    for (;;) {
        const TargetOwner kOwner = resolveTargetOwner(address, modules);

        if (havePreviousOwner && kOwner.moduleName != previousOwnerName) {
            result.crossedModuleBoundary = true;
        }
        previousOwnerName = kOwner.moduleName;
        havePreviousOwner = true;

        if (kOwner.kind == TargetOwnerKind::kOutsideKnownModules) {
            // Do not follow into unknown memory: without module ownership, there are no boundaries to verify against.
            FollowNode node;
            node.address = address;
            node.owner = kOwner;
            node.step = FollowStepKind::kTargetUnreadable;
            result.path.push_back(std::move(node));
            result.termination = FollowTermination::kOutsideKnownModules;
            return result;
        }

        if (std::find(visited.begin(), visited.end(), address) != visited.end()) {
            FollowNode node;
            node.address = address;
            node.owner = kOwner;
            node.step = FollowStepKind::kDirectBranch;
            result.path.push_back(std::move(node));
            result.termination = FollowTermination::kCycleDetected;
            return result;
        }
        visited.push_back(address);

        const BranchStep kStep = resolver(address);
        result.bytesUsed += kStep.bytesConsumed;

        FollowNode node;
        node.address = address;
        node.owner = kOwner;
        node.step = kStep.kind;
        node.forwarderText = kStep.forwarderText;
        result.path.push_back(std::move(node));

        if (result.bytesUsed > options.maxBytes) {
            result.termination = FollowTermination::kByteBudgetExhausted;
            return result;
        }

        switch (kStep.kind) {
        case FollowStepKind::kResolvedCode:
            result.termination = FollowTermination::kResolved;
            return result;
        case FollowStepKind::kIndirectUnresolved:
            result.termination = FollowTermination::kIndirectUnresolved;
            return result;
        case FollowStepKind::kExportForwarder:
            result.termination = FollowTermination::kExportForwarder;
            return result;
        case FollowStepKind::kTargetUnreadable:
            result.termination = FollowTermination::kTargetUnreadable;
            return result;
        case FollowStepKind::kDirectBranch:
            break;
        }

        if (result.depthUsed >= options.maxDepth) {
            result.termination = FollowTermination::kDepthExhausted;
            return result;
        }
        result.depthUsed += 1U;
        address = kStep.target;
    }
}

} // namespace ksword::evidence

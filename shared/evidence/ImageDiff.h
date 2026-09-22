#pragma once

// I module difference engine — I-04 (hot patches and unknown legitimate changes), I-05 (difference localization and context),
// I-06 (jump targets and owners), I-09 (scan coverage and race conditions), I-10 (credibility of disk references).
//
// Input: normalized disk image produced by PeImageMap and raw image bytes read from the scene.
// Output: traceable difference facts. Deliberately omitted items are also part of the criteria:
//   * No fields like isMalicious or isSuspicious exist. Cross-module jumps, RWX, and Microsoft signatures
//     are not conclusions, but facts; the conclusion layer only has the four states of AnalysisConclusion.
//   * There is no entry point for 'module-wide exemption'. ExplanationRule can only apply to specific RVA ranges, and upon a match,
//     ruleId and ruleVersion must be recorded; otherwise, a single signature verification could permanently allow an entire driver.
//   * Bytes that cannot be read are always treated as missing markers and are not padded with 00 for comparison.
//     Padding with 0 would disguise "unread" as "read 0", potentially creating a spurious difference or a spurious match.
//
// C++20、Qt-free、Win32-free。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"
#include "PeImageMap.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// I-05: On-site bytes and read status.
// ---------------------------------------------------------------------------

// Three states instead of optional: failing to read and not attempting to read are distinct; the former is failure evidence, the latter is a coverage gap.
enum class ByteReadStatus {
    kRead,
    kUnreadable,
    kNotCollected,
};

const char* byteReadStatusName(ByteReadStatus status) noexcept;

// A segment of image bytes read from the live system. status and bytes are parallel and equal in length; when status != Read,
// the value in bytes is meaningless, and the caller must check status first. Anything outside the window is marked NotCollected.
struct LiveImageBytes final {
    std::uint32_t baseRva = 0;
    std::vector<std::uint8_t> bytes;
    std::vector<ByteReadStatus> status;

    bool wellFormed() const noexcept { return bytes.size() == status.size(); }
    RvaRange window() const noexcept;

    ByteReadStatus statusAt(std::uint32_t rva) const noexcept;
    // Returns true and writes to out only if status == Read; otherwise, out remains unmodified.
    bool byteAt(std::uint32_t rva, std::uint8_t& out) const noexcept;

    // Construction helper: fill the entire segment with Read.
    static LiveImageBytes fromBytes(std::uint32_t baseRva, std::vector<std::uint8_t> data);
    // Mark a range as unreadable/uncollected. Portions exceeding the window are ignored.
    void markRange(const RvaRange& range, ByteReadStatus newStatus) noexcept;
};

// ---------------------------------------------------------------------------
// I-04: Explanation rule
// ---------------------------------------------------------------------------

// I-04: Maximum span for a single explanation rule. Changes with concrete basis, such as hot patches, released patches,
// and pivots, are instruction-level; 64 KiB far exceeds actual needs. Setting this hard limit unrelated to the reference
// image prevents APIs without image context (usable()) from being bypassed by a rule like range={0,0xFFFFFFFF}, which
// would effectively grant permanent access to the entire driver—a scenario explicitly prohibited by the I-04 condition.
inline constexpr std::uint32_t kExplanationRuleMaxSpanBytes = 0x10000U;

// An explanation rule covers only a specific RVA range. There is no 'whole-module' overload, nor is one planned.
struct ExplanationRule final {
    std::string ruleId;
    std::uint32_t ruleVersion = 0;
    RvaRange range;
    std::string evidenceText;   // Based on the source (e.g., a published patch number), not the conclusion.

    // Structural criterion: ignore the reference image. The effective rule is admitExplanationRule,
    // which also requires the range to fall within a section (or PE header) of the reference image.
    bool usable() const noexcept {
        return !ruleId.empty() && !range.empty() && range.length <= kExplanationRuleMaxSpanBytes;
    }
};

// Rule admission conclusion. Rejection reasons are listed separately so the UI can clearly explain why a specific rule did not take effect.
enum class RuleAdmission {
    kAccepted,
    kUnusable,               // ruleId is null / range is empty / span exceeds hard limit
    kCoversWholeImage,       // Covers or exceeds the entire reference image — full module exemption.
    kNotScopedToOneSection,  // The range does not fully fall within a single mapped section or PE header interval.
};

const char* ruleAdmissionName(RuleAdmission admission) noexcept;

// I-04: Exemptions must be scoped precisely. For a rule to take effect, it must lie entirely within a single mapped section (or
// PE header) of the reference image. Cross-section 'basis' has no verifiable target, and rules covering the entire image amount
// to a direct module-wide bypass. Rejected rules do not participate in matching and leave a restriction key in the report.
RuleAdmission admitExplanationRule(const PeImageMap& reference,
                                   const ExplanationRule& rule) noexcept;

// A match occurs only if the rule range **fully contains** the range being checked AND the rule passes admitExplanationRule.
// Partial coverage does not count — otherwise, a rule covering a single byte could explain an entire rewritten segment.
const ExplanationRule* findExplanationRule(const PeImageMap& reference,
                                           const std::vector<ExplanationRule>& rules,
                                           const RvaRange& span) noexcept;

enum class DiffExplanation {
    kUnexplained,  // Default state. Stop here without specific evidence.
    kExplained,    // RVA range where a specific rule was matched.
};

const char* diffExplanationName(DiffExplanation explanation) noexcept;

// ---------------------------------------------------------------------------
// I-05: Diff entry
// ---------------------------------------------------------------------------

enum class DiffKind {
    kByteDifference,    // Both readable and bytes differ
    kMissingLiveBytes,  // Cannot read from live state — neither a difference nor 'same'.
};

const char* diffKindName(DiffKind kind) noexcept;

// The original sub-range before folding. Folding is merely a merge at the display layer; the original range must be expandable.
struct DiffSubRange final {
    std::uint32_t rva = 0;
    std::uint32_t length = 0;
    std::vector<std::uint8_t> referenceBytes;
    std::vector<std::uint8_t> liveBytes;  // Empty when readStatus != Read; never pad with 00.
};

// I-05 requires each difference to include "a small amount of disassembly before and after". This layer is a pure byte layer without Qt or
// Win32, and contains no decoder, so decoded is always false; text is filled by the upper layer. The structure must be able to distinguish:
//   * Decoding was not attempted (attempted == false) — covers the gap;
//   * Attempted but failed to decode (attempted && !decoded) — failure evidence; must include a reason key.
// If both collapse into the same empty string, it disguises 'not checked' as 'checked and found nothing'.
struct DisassemblyContext final {
    bool attempted = false;
    bool decoded = false;
    std::string beforeText;   // Meaningful only when decoded.
    std::string afterText;    // Meaningful only when decoded.
    // Nonempty i18n key required when attempted but not decoded. Missing is an explicit state, not an empty string.
    std::string unavailableReasonKey;

    bool notAttempted() const noexcept { return !attempted; }
    bool attemptedButUndecoded() const noexcept { return attempted && !decoded; }
};

// The only "attempted but failed" reason this layer can provide: no decoder exists in this layer.
inline constexpr const char* kDisassemblyUnavailableNoDecoder =
    "integrity.disassembly.noDecoderInThisLayer";

struct ImageDiffEntry final {
    DiffKind kind = DiffKind::kByteDifference;
    // I-05: The module instance to which this difference belongs. It distinguishes between same-name different versions and same-path overloads.
    // Null identity means the caller did not provide one; it does not imply "the current module".
    DriverInstanceId module;
    std::string sectionName;                       // Header is "(headers)"; gap is an empty string.
    std::size_t sectionIndex = kInvalidSectionIndex;
    std::uint32_t rva = 0;
    std::uint64_t va = 0;                          // reference.loadedBase + rva
    std::uint32_t length = 0;
    ByteReadStatus readStatus = ByteReadStatus::kRead;
    DiffExplanation explanation = DiffExplanation::kUnexplained;
    std::string ruleId;                            // Non-empty only when Explained.
    std::uint32_t ruleVersion = 0;
    std::string ruleEvidence;
    std::string evidenceSource;                    // The evidence source string for this difference.

    std::vector<std::uint8_t> referenceBytes;
    std::vector<std::uint8_t> liveBytes;
    bool byteEvidenceTruncated = false;            // true when exceeding maxBytesPerEntry

    // I-05: Disassembly context. Its state **must never** affect the raw byte evidence
    // above; failing to decode an instruction does not mean the bytes are unreadable.
    DisassemblyContext disassembly;

    std::vector<DiffSubRange> subRanges;           // Unfolded original sub-ranges
    bool collapsed = false;                        // Collapsed from multiple sub-ranges.
};

// ---------------------------------------------------------------------------
// I-09: Coverage statistics and module identity verification.
// ---------------------------------------------------------------------------

struct CountTriplet final {
    std::uint64_t attempted = 0;
    std::uint64_t succeeded = 0;
    std::uint64_t failed = 0;
    std::uint64_t excluded = 0;
    // Portions that hit the limit and were **never scanned**. They are neither "attempted but failed" nor
    // "excluded as incomparable"; mixing any of these into a bucket will cause the accounting to be off (F-06).
    std::uint64_t notAttempted = 0;
};

struct ScanCoverageStats final {
    CountTriplet modules;
    CountTriplet bytes;
    CountTriplet pages;
    std::uint32_t pageSize = 4096;
};

void accumulateStats(ScanCoverageStats& accumulator, const ScanCoverageStats& one) noexcept;

enum class ModuleStalenessVerdict {
    kSame,          // Identity confirmation before and after read is consistent.
    kStale,         // Unloaded, replaced by a different version, or rebased: do not interpret using old addresses.
    kUnverifiable,  // Insufficient identity: neither confirmable nor negatable.
};

const char* moduleStalenessVerdictName(ModuleStalenessVerdict verdict) noexcept;

// Reuse ObjectIdentity's matchDriverInstance, plus two additional module-specific criteria: check for null.
//   * If no usable identity can be obtained after reading -> Stale. Conservatively mark as expired if the module disappears mid-read; this direction is safe.
//   * Base address change within the same boot cycle -> Stale. The inverse of reloading with the same base; the old RVA-to-VA mapping is now invalid.
ModuleStalenessVerdict checkModuleStillSame(const DriverInstanceId& before,
                                            const DriverInstanceId& after) noexcept;

// ---------------------------------------------------------------------------
// I-10: Comparison basis
// ---------------------------------------------------------------------------

enum class ReferenceSourceKind {
    kLocalDisk,          // Same-named file on the local disk
    kUserSelectedImage,  // User explicitly selected reference image.
    kSavedSnapshot,      // Saved session snapshot.
};

const char* referenceSourceKindName(ReferenceSourceKind kind) noexcept;

struct ReferenceSource final {
    ReferenceSourceKind kind = ReferenceSourceKind::kLocalDisk;
    std::string description;  // Verifiable identifiers such as path or snapshot ID
    FileIdentity identity;    // Fill if available; an empty identity means 'same name does not equal same version'.
};

// Returns i18n keys. The key sets for the three sources differ, but **none include** conclusions like "consistent with disk,
// therefore secure" — byte consistency only indicates agreement with the reference, which itself may have been tampered with.
std::vector<std::string> buildTrustNotes(const ReferenceSource& source);

// ---------------------------------------------------------------------------
// Diff engine
// ---------------------------------------------------------------------------

struct ImageDiffOptions final {
    // Empty means using reference.rawBackedRanges (header + raw backing regions of all mapped sections, before subtracting
    // incomparable ranges). The engine then subtracts the exclusion set and records the difference in coverage.skipped.
    std::vector<RvaRange> compareRanges;
    // Additional excluded ranges by the caller. Typical usage: pass when relocations cannot be applied precisely.
    // PeImageMap::relocation.touchedRanges。
    std::vector<RvaRange> excludedRanges;
    std::vector<ExplanationRule> rules;
    ReferenceSource reference;
    std::string evidenceSource;
    // I-05: Write the module instance for each difference. Empty indicates the caller did not provide an identity.
    DriverInstanceId module;
    // I-05: Whether to request disassembly context. This layer has no decoder; setting true yields only
    // attempted && !decoded plus an explicit reason key—exactly the state that needs to be expressible.
    bool attemptDisassembly = false;

    // I-05 Collapse: merge differences with the same attribute into a single entry if the gap does not exceed this value; sub-ranges remain fully preserved.
    std::uint32_t collapseGapBytes = 0;
    std::size_t maxEntries = 4096;
    std::uint32_t maxBytesPerEntry = 256;
    std::uint32_t pageSize = 4096;
    ModuleStalenessVerdict staleness = ModuleStalenessVerdict::kSame;
};

struct ImageDiffReport final {
    std::vector<ImageDiffEntry> entries;

    // Ranges excluded as incomparable (malformed sections + unsupported relocations + caller-specified).
    std::vector<RvaRange> excludedRanges;

    std::size_t byteDifferenceEntries = 0;
    std::size_t explainedEntries = 0;
    std::size_t unexplainedEntries = 0;
    std::size_t missingEntries = 0;

    std::uint64_t comparedBytes = 0;     // Bytes readable and actually compared by both parties
    std::uint64_t differingBytes = 0;
    std::uint64_t unreadableBytes = 0;
    std::uint64_t notCollectedBytes = 0;
    std::uint64_t excludedBytes = 0;
    // Bytes in the valid comparison set that were never scanned due to hitting the limit. Identity:
    //   comparedBytes + unreadableBytes + notCollectedBytes + notAttemptedBytes
    //     + excludedBytes == Total bytes in the request set
    std::uint64_t notAttemptedBytes = 0;

    // F-06: Both effective limits must be exposed. The scan stops at the piece limit (pieceLimit);
    // the entry limit (entryLimit) only determines how many entries are retained after folding.
    // Reporting only the latter would mislead the caller into thinking the constraint is maxEntries.
    std::uint64_t entryLimit = 0;
    std::uint64_t pieceLimit = 0;
    bool scanStoppedAtPieceLimit = false;

    CollectionOutcome outcome;
    CoverageAccount coverage;
    ScanCoverageStats stats;
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;

    ReferenceSource reference;
    std::vector<std::string> trustNotes;      // Determined solely by the reference.
    std::vector<std::string> limitationKeys;  // Coverage gaps / expiration / relocation / rules rejected
    // I-04: Number of rules rejected by admitExplanationRule. Discards must
    // be visible; otherwise, callers may assume exemptions took effect.
    std::size_t rejectedRuleCount = 0;
    bool limitHit = false;
    ModuleStalenessVerdict staleness = ModuleStalenessVerdict::kSame;
};

ImageDiffReport compareImage(const PeImageMap& reference,
                             const LiveImageBytes& live,
                             const ImageDiffOptions& options);

// ---------------------------------------------------------------------------
// I-06: Jump target and owner
// ---------------------------------------------------------------------------

struct ModuleRange final {
    std::string name;
    std::uint64_t base = 0;
    std::uint64_t size = 0;

    bool contains(std::uint64_t address) const noexcept {
        return size != 0U && address >= base && (address - base) < size;
    }
};

enum class TargetOwnerKind {
    kInsideModule,
    kOutsideKnownModules,  // Outside any known module range. This is a fact, not 'malicious'.
};

const char* targetOwnerKindName(TargetOwnerKind kind) noexcept;

struct TargetOwner final {
    TargetOwnerKind kind = TargetOwnerKind::kOutsideKnownModules;
    std::string moduleName;
    OptionalU64 moduleBase;
    OptionalU64 offset;
};

TargetOwner resolveTargetOwner(std::uint64_t address,
                               const std::vector<ModuleRange>& modules);

// What the caller sees at a specific address. Offline tests provide fixtures directly; live environments fill via disassembly/memory read.
enum class FollowStepKind {
    kResolvedCode,        // Ordinary code, following up to this point.
    kDirectBranch,        // Direct jump/call with a determined target; continue following.
    kIndirectUnresolved,  // Indirect jump; target pointer cannot be resolved.
    kExportForwarder,     // Export forwarding ("DLL.Export"), which is distinct from the previous item.
    kTargetUnreadable,    // Bytes at this address are unreadable.
};

const char* followStepKindName(FollowStepKind kind) noexcept;

struct BranchStep final {
    FollowStepKind kind = FollowStepKind::kTargetUnreadable;
    std::uint64_t target = 0;         // Valid only for DirectBranch.
    std::uint32_t bytesConsumed = 0;  // Bytes consumed during decoding, counted against the maxBytes budget.
    std::string forwarderText;        // Valid only for ExportForwarder.
};

using BranchResolver = std::function<BranchStep(std::uint64_t address)>;

// Each termination reason has a distinct value. Export forwarding and unresolved indirect targets are deliberately not merged — the
// former is a known normal mechanism, while the latter means "we failed to resolve it"; merging them would artificially inflate coverage.
enum class FollowTermination {
    kResolved,
    kDepthExhausted,
    kByteBudgetExhausted,
    kCycleDetected,
    kTargetUnreadable,
    kOutsideKnownModules,
    kIndirectUnresolved,
    kExportForwarder,
};

const char* followTerminationName(FollowTermination termination) noexcept;

struct FollowNode final {
    std::uint64_t address = 0;
    TargetOwner owner;
    FollowStepKind step = FollowStepKind::kTargetUnreadable;
    std::string forwarderText;
};

struct FollowOptions final {
    std::uint32_t maxDepth = 8;
    std::uint64_t maxBytes = 256;
};

struct FollowResult final {
    FollowTermination termination = FollowTermination::kTargetUnreadable;
    std::vector<FollowNode> path;
    std::uint32_t depthUsed = 0;
    std::uint64_t bytesUsed = 0;
    // State only the fact: a module ownership change occurred along the path. Crossing module boundaries does not imply malicious intent.
    bool crossedModuleBoundary = false;
};

FollowResult followBranchTarget(std::uint64_t startAddress,
                                const std::vector<ModuleRange>& modules,
                                const BranchResolver& resolver,
                                const FollowOptions& options = FollowOptions{});

} // namespace ksword::evidence

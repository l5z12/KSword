#pragma once

// Factual model and safety boundaries for module C (offline crash-dump analysis, P2).
//
// Coverage IDs: C-02 C-03 C-04 C-05 C-06 C-07 C-08 C-09 C-10.
// C-01 (DbgEng probing) and 'comparison with real dumps' are out of scope for this file: those require real samples
// and a debugging engine. This file handles only parts that can be fully verified offline using constructed bytes.
//
// This file does not touch disk, does not call DbgEng, and contains no Qt/Win32. Input is bytes already read into memory by the
// caller; output is a fact structure consumable directly by UI/reports. The engine is hosted within the existing MinidumpDock.
//
// Three red lines spanning the entire file (cheating patterns caught during the previous round of adversarial review):
//   1. Missing is always an independent state. Any 'not read' must not
//      degrade to 0, empty string, or 'normal' (trap pointed out in C-03).
//   2. Default construction must not be 'complete', 'trusted', or 'safe'. DumpRecognition
//      defaults to NotADump, StackFrame to TruncatedNoData, SymbolMatch to NotAttempted,
//      ContentPresence to Unknown, and SymbolServerPolicy to no network access.
//   3. No unauthorized judgment fields such as malicious, threat, isRootkit, suspicious, riskScore, rootCause, or
//      liability percentage. C-06 only determines whether there is sufficient evidence to file a case, not a verdict.

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"
#include "ScanBudget.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// Byte reading: all offset-based accesses go through here; out-of-bounds access returns false instead of reading garbage.
// Explicitly assemble little-endian; avoid struct memcpy to prevent assumptions about alignment and padding.
// ---------------------------------------------------------------------------
bool readLittleEndianU32(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint32_t& out) noexcept;

bool readLittleEndianU64(std::span<const std::uint8_t> bytes,
                         std::size_t offset,
                         std::uint64_t& out) noexcept;

// ---------------------------------------------------------------------------
// C-02 File identification and support scope
// ---------------------------------------------------------------------------

// DumpKind: Scope of support for this round. Only KernelSmall/KernelMemory allow retrieving crash facts.
enum class DumpKind {
    kNotADump,      // No known dump signatures in the bytes.
    kUnsupported,   // Signature family recognized, but parsing skipped this round (32-bit kernel dump / non-x64 / truncated header).
    kUserMinidump,  // 'MDMP' user-mode minidump. Red line: never treat as a kernel dump.
    kKernelSmall,   // PAGEDU64 and DumpType ∈ {3 header only, 4 triage}
    kKernelMemory,  // PAGEDU64 and DumpType ∈ {1,2,5,6,7}
};

const char* dumpKindName(DumpKind kind) noexcept;

// Only these two types warrant bugcheck facts. All others are neither parsed nor treated as successfully parsed.
bool dumpKindCarriesKernelFacts(DumpKind kind) noexcept;

// SignatureFamily and DumpKind are distinct concepts and must not be merged into a single field.
// The family remains trustworthy even if the header is truncated (e.g., "definitely MDMP, so
// definitely not a kernel dump"), but kind cannot converge to KernelSmall/KernelMemory. Since
// DumpKind only has the five specified values, this "recognized but incomplete" case uses
// kind=Unsupported + reason=TruncatedHeader, with the family carried solely by this field.
enum class SignatureFamily {
    kNone,
    kMdmp,          // 'MDMP'
    kKernelPage64,  // 'PAGE' + 'DU64'
    kKernelPage32,  // 'PAGE' + 'DUMP'
};

const char* signatureFamilyName(SignatureFamily family) noexcept;

// RecognitionReason: why this kind was obtained. Failure semantics must not collapse into one (Review Mode 4):
// Empty file, too short, truncated, unknown signature, unsupported bit width, unsupported architecture, and
// unsupported DumpType are seven distinct cases; the report and UI must be able to express them separately.
enum class RecognitionReason {
    kRecognized,
    kEmptyFile,                 // 0 bytes
    kTooSmallForSignature,      // Has bytes but fewer than 8, insufficient to read the signature.
    kTruncatedHeader,           // Signature is valid, but the readable bytes are insufficient for the header length of this format.
    kUnknownSignature,          // First 8 bytes do not match any known signature.
    kUnsupportedKernelBitness,  // 'PAGE'+'DUMP': 32-bit kernel dump; not supported in this round.
    kUnsupportedArchitecture,   // Kernel dump but MachineImageType is not x64
    kUnsupportedDumpType,       // DumpType field is not a known value (including PAGE padding).
};

const char* recognitionReasonName(RecognitionReason reason) noexcept;

// C-02: Target architecture classification. Original machine type is preserved; classification does not consume the original value.
enum class TargetArchitecture {
    kUnknown,  // Failed to read a trusted machine type.
    kX86,
    kX64,
    kArm,
    kArm64,
    kOther,    // Note: Read but not in the known table — the original value is in rawMachineType.
};

const char* targetArchitectureName(TargetArchitecture architecture) noexcept;

struct DumpRecognition final {
    DumpKind kind = DumpKind::kNotADump;
    SignatureFamily family = SignatureFamily::kNone;
    RecognitionReason reason = RecognitionReason::kUnknownSignature;
    TargetArchitecture architecture = TargetArchitecture::kUnknown;

    OptionalU64 rawSignature;    // Original first 4 bytes; unset if not read.
    OptionalU64 rawValidDump;    // Secondary 4-byte raw value
    OptionalU64 rawMachineType;  // Original PE machine type.
    OptionalU64 rawDumpType;     // Original value of DUMP_HEADER64.DumpType.
    OptionalU64 fileSize;        // File size declared by the caller.
    OptionalU64 bytesProvided;   // Number of bytes actually provided by the caller.
    OptionalU64 headerBytesRequired;  // Minimum header length required for this family.

    // C-02: "Do not fake successful parsing". True only if fields were genuinely read according to the format.
    bool parseAttempted = false;

    CollectionOutcome outcome;   // Retain error code on failure (domain = "KSWORD_DUMPRECOGNITION")
};

// C-02 main entry point. Inspects only bytes, ignoring file extension and path.
// headBytes must include at least the file header (kernel dumps require 0x2000 bytes to fully read fields after DumpType);
// If totalFileSize is unknown, treat headBytes.size() as the full file size.
//
// **Not noexcept**, and do not revert this: every failure path must construct a CollectionOutcome. The domain
// string "KSWORD_DUMPRECOGNITION" inside it is 22 bytes, exceeding the 15-byte SSO limit of MSVC std::string,
// forcing a heap allocation. Declaring it noexcept would turn a single out-of-memory condition from bad_alloc
// into std::terminate—the main process vanishes, which is exactly the C-01 scenario we must avoid.
// The predicate functions that must never allocate (see the asciiEqualsIgnoreCase section in .cpp) remain noexcept.
DumpRecognition recognizeDump(std::span<const std::uint8_t> headBytes,
                              const OptionalU64& totalFileSize);

// Both "corrupt file" and "unsupported format" map to kind=Unsupported, but they are distinct issues.
// UI text must rely on this function to distinguish; do not check kind alone.
bool recognitionIsDamagedRatherThanUnsupported(const DumpRecognition& recognition) noexcept;

// ---------------------------------------------------------------------------
// C-03 Crash facts
// ---------------------------------------------------------------------------

// DumpFieldAvailability: Three-state logic at the field level. The trap highlighted in C-03 is
// collapsing NotRecorded and NotParsed into Present(0). These three states must remain distinct here.
enum class DumpFieldAvailability {
    kNotParsed,    // Not read in this round (window too small / file truncated / format unparseable) — unknown if present
    kNotRecorded,  // Not written in the dump (PAGE padding / this format lacks this field) — implies absence.
    kPresent,      // Read actual value.
};

const char* dumpFieldAvailabilityName(DumpFieldAvailability availability) noexcept;

struct DumpField final {
    DumpFieldAvailability availability = DumpFieldAvailability::kNotParsed;
    OptionalU64 value;

    static DumpField present(std::uint64_t v) noexcept;
    static DumpField notRecorded() noexcept;
    static DumpField notParsed() noexcept;

    // Invariant: Present ⇔ value.present. Either side holding true independently constitutes a construction bug.
    bool consistent() const noexcept;

    friend bool operator==(const DumpField& a, const DumpField& b) noexcept {
        return a.availability == b.availability && a.value == b.value;
    }
    friend bool operator!=(const DumpField& a, const DumpField& b) noexcept { return !(a == b); }
};

struct BugCheckFacts final {
    DumpKind dumpKind = DumpKind::kNotADump;

    DumpField code;                        // DUMP_HEADER64.BugCheckCode
    std::array<DumpField, 4> parameters{}; // BugCheckParameter[0..3]
    DumpField targetOsMajor;               // MajorVersion
    DumpField targetOsBuild;               // MinorVersion (Kernel build number)
    DumpField processorCount;
    DumpField crashTimeUtc100ns;           // SystemTime（FILETIME）
    DumpField uptime100ns;                 // SystemUpTime
    DumpField writerStatus;                // 0 is a meaningful value, not a missing value
    DumpField directoryTableBase;          // CR3 at crash time.

    // C-03 + Review Mode 4: NotParsed has two sources; the report must distinguish them.
    OptionalU64 bytesProvided;
    OptionalU64 fileSizeDeclared;
    bool windowShorterThanFile = false;

    CollectionOutcome outcome;

    // At least one field actually read a value. When all are false, it is not allowed to render as 'crash information'.
    bool hasAnyFact() const noexcept;
    std::size_t presentFieldCount() const noexcept;
    std::size_t notRecordedFieldCount() const noexcept;
    std::size_t notParsedFieldCount() const noexcept;
    std::size_t fieldCount() const noexcept;
};

// C-03 Main entry point. recognition.kind determines whether to parse:
//   NotADump -> outcome=NotCollected, all NotParsed
//   Unsupported -> outcome=Unsupported, all NotParsed.
//   UserMinidump -> outcome=Unsupported, all fields marked NotRecorded (this format lacks these fields).
//   KernelSmall/KernelMemory -> read field-by-field; any unread fields are marked according to the above three-state logic.
BugCheckFacts extractBugCheckFacts(const DumpRecognition& recognition,
                                   std::span<const std::uint8_t> headBytes);

// ---------------------------------------------------------------------------
// C-04 Symbol exact match
// ---------------------------------------------------------------------------

enum class SymbolMatch {
    kNotAttempted,  // Default: Not attempted. Not 'no symbols'.
    kAbsent,        // Attempted but PDB not found.
    kWrongVersion,  // PDB found but GUID/Age mismatch — red line: must not be used for function names or line numbers.
    kMatched,
};

const char* symbolMatchName(SymbolMatch match) noexcept;

enum class SymbolCacheSource {
    kUnknown,
    kNotLoaded,
    kLocalDirectory,  // Dump to same directory / user-specified local directory
    kLocalCache,      // Local symbol cache (downstream store).
    kSymbolServer,    // Network symbol server
    kDumpEmbedded,    // Dumped embedded (rare)
};

const char* symbolCacheSourceName(SymbolCacheSource source) noexcept;

// PdbIdentity: Store the GUID as raw 16 bytes without converting to a string first; case differences and brace variations would
// otherwise make a mismatched version appear as a match. present defaults to false: without an identifier, it never equals a match.
struct PdbIdentity final {
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t age = 0;
    bool present = false;
    std::string pdbName;  // Foreign text; must pass escapeForReport before generating the report.
};

// Return false if either side has present==false. Two empty identities are not considered 'equal'.
bool samePdbIdentity(const PdbIdentity& a, const PdbIdentity& b) noexcept;

enum class SymbolLoadAttempt {
    kNotAttempted,
    kFileNotFound,
    kLoadFailed,   // File found but cannot be opened / corrupted format
    kFileLoaded,
};

const char* symbolLoadAttemptName(SymbolLoadAttempt attempt) noexcept;

// C-04 Judgment: Load result + both-side identifiers -> Three-state match.
// Default construction (NotAttempted + two empty identities) must return NotAttempted, never Matched.
SymbolMatch deriveSymbolMatch(SymbolLoadAttempt attempt,
                              const PdbIdentity& wanted,
                              const PdbIdentity& loaded) noexcept;

struct ModuleSymbolState final {
    std::string moduleName;  // External text
    PdbIdentity wanted;      // CodeView records declared in the dump
    PdbIdentity loaded;      // Actually loaded
    SymbolMatch match = SymbolMatch::kNotAttempted;
    // Keep both attempt and match: SymbolMatch only has the four values specified by the spec. Both
    // "file not found" and "found but failed to load" map to Absent; their distinction must be
    // preserved via attempt and outcome (Review Mode 4: failure semantics must not collapse into one).
    SymbolLoadAttempt attempt = SymbolLoadAttempt::kNotAttempted;
    SymbolCacheSource cacheSource = SymbolCacheSource::kUnknown;
    CollectionOutcome outcome;  // Preserve the original error code if loading fails.
};

// C-04 Red Line: Only if Matched, are definite function names and line numbers allowed.
bool mayReportFunctionName(const ModuleSymbolState& state) noexcept;
bool mayReportSourceLine(const ModuleSymbolState& state) noexcept;

// Allowed attribution levels. WrongVersion/Absent are limited to "Module+Offset".
enum class SymbolAttribution {
    kModuleOnly,             // Without a base address, it can only be considered a module.
    kModulePlusOffset,       // "Module + 0x offset"
    kFunctionPlusOffset,     // "Module!Function+0xOffset"
    kFunctionAndSourceLine,  // Add "Source File:Line Number".
};

const char* symbolAttributionName(SymbolAttribution attribution) noexcept;

SymbolAttribution allowedAttribution(const ModuleSymbolState& state,
                                     bool moduleBaseKnown) noexcept;

// C-04: Network symbol downloads must be 'user-enabled + cancellable + time-limited'. All three defaults are false.
struct SymbolServerPolicy final {
    bool userEnabled = false;
    bool cancellable = false;
    ScanBudget budget;  // Must include maxDurationNanos; otherwise, the concept of 'time-limited' is meaningless.
};

enum class SymbolServerDecision {
    kAllow,
    kRejectNotEnabled,      // Not enabled by the user
    kRejectNotCancellable,  // No cancellation path
    kRejectNoTimeBudget,    // No time budget
};

const char* symbolServerDecisionName(SymbolServerDecision decision) noexcept;

// Default-constructed policies must be rejected. Evaluation order: switch -> cancel -> timeout.
SymbolServerDecision decideSymbolServerFetch(const SymbolServerPolicy& policy) noexcept;

// ---------------------------------------------------------------------------
// C-05 Stack and modules
// ---------------------------------------------------------------------------

enum class UnwindState {
    kTruncatedNoData,  // Default: no unwind data or the dump lacks this stack memory; stop here.
    kTruncatedCorrupt, // Data is self-contradictory (stack pointer regression/overflow); stop here.
    kGuessed,          // Candidates from stack scanning, not unwind results.
    kUnwound,          // Normal expansion using unwind data.
};

const char* unwindStateName(UnwindState state) noexcept;

// No frames may follow a truncated state; doing so would stitch together guessed frames.
bool unwindStateIsTerminal(UnwindState state) noexcept;

// Only Unwound frames are trustworthy; Guessed frames are not.
bool unwindStateIsTrustworthy(UnwindState state) noexcept;

struct StackFrame final {
    OptionalU64 address;
    OptionalU64 stackPointer;

    std::string moduleName;  // External text
    OptionalU64 moduleBase;
    OptionalU64 offsetInModule;

    SymbolMatch symbolMatch = SymbolMatch::kNotAttempted;
    std::string functionName;  // Non-null is allowed only when symbolMatch == Matched.
    OptionalU64 functionOffset;
    std::string sourceFile;  // Same as above
    OptionalU64 sourceLine;

    UnwindState unwindState = UnwindState::kTruncatedNoData;

    // C-05: Parameters are individually ternary. Unavailable parameters remain unset and are never filled with 0.
    std::vector<OptionalU64> availableArgs;
    bool argsComplete = false;

    // C-05: Attribution ambiguity caused by optimization/inlining must be preserved, not flattened.
    // When attributionAmbiguous is true, candidateFunctions must retain >= 2 candidates.
    bool attributionAmbiguous = false;
    std::vector<std::string> candidateFunctions;
};

struct StackTrace final {
    std::vector<StackFrame> frames;
    CollectionOutcome outcome;
    CoverageAccount coverage;

    std::size_t unwoundCount() const noexcept;
    std::size_t guessedCount() const noexcept;
    std::size_t truncatedCount() const noexcept;
};

// validateStackTrace: Rejects invalid stacks rather than 'correcting' them.
// Check order is fixed (bounds first, then frame-by-frame); return the first violation.
enum class StackValidation {
    kOk,
    kFramesAfterTruncation,              // Frames after a truncated frame imply guessed frames were appended.
    // A function name without matching symbols; functionOffset also counts. Without a resolved function,
    // there is no function-relative offset: the number can only come from a mismatched PDB or a guess.
    kFunctionNameWithoutMatchedSymbols,
    kSourceLineWithoutMatchedSymbols,    // Source line number without matching symbols.
    // Candidate function names without matching symbols. Candidates are also rendered in the UI; pluralizing the names does not change this:
    // Appending "candidate" to names resolved from a mismatched PDB does not make them usable information (C-04 red line).
    kCandidatesWithoutMatchedSymbols,
    kAmbiguityCollapsed,                 // Ambiguity marked but only one candidate retained = ambiguity collapsed.
    kIncompleteArgumentsClaimedComplete, // Claims arguments are complete but contains unknowns.
};

const char* stackValidationName(StackValidation validation) noexcept;

StackValidation validateStackTrace(const StackTrace& trace) noexcept;

// ---------------------------------------------------------------------------
// C-06 Suspicious module explanation
// ---------------------------------------------------------------------------

// Express the three evidence types separately. Their strengths differ significantly; merging them causes distortion.
enum class ModuleEvidenceKind {
    kOnStack,           // Module appears on the stack (possibly just called).
    kFaultingIpModule,  // Faulting IP falls within this module.
    kVerifierReported,  // Driver Verifier explicitly identifies
};

const char* moduleEvidenceKindName(ModuleEvidenceKind kind) noexcept;

struct ModuleEvidenceItem final {
    ModuleEvidenceKind kind = ModuleEvidenceKind::kOnStack;
    std::string moduleName;  // External text

    // The prerequisite for this evidence itself: which frame it came from and how that frame was generated.
    UnwindState frameUnwindState = UnwindState::kTruncatedNoData;
    OptionalU64 frameIndex;

    // Whether the faulting IP comes directly from the trap frame / context record, rather than a return address from an unwind frame.
    // Defaults to false—exemption from inspection is not allowed by default. The FaultingIpModule evidence qualifies as a 'verifiable
    // lead' only if this bit is true or the frame itself is trusted (Unwound). If a frame is already deemed TruncatedCorrupt
    // (internally contradictory data) yet is used to implicate a third-party driver, that constitutes an unauthorized determination.
    bool ipFromContextRecord = false;

    std::string detail;  // Preserve external text verbatim.
};

struct ModuleEvidenceGroup final {
    std::string moduleName;  // Original implementation at first occurrence (for demonstration).
    std::string moduleKey;   // ASCII lowercase group key (no normalization beyond case).

    std::vector<ModuleEvidenceItem> onStack;
    std::vector<ModuleEvidenceItem> faultingIp;
    std::vector<ModuleEvidenceItem> verifier;

    bool isWellKnownSystemModule = false;

    std::size_t evidenceCount() const noexcept;
};

// Known system module list (hardcoded in implementation, not read from dump). A match only reduces 'lead' eligibility, it is not a verdict.
bool isWellKnownSystemModuleName(std::string_view moduleName) noexcept;

// C-06: Does not provide the root cause, only answers 'Is this clue sufficient to open a case?'. No percentages are given.
enum class InvestigationLead {
    kUndetermined,          // Default: insufficient evidence to determine.
    kSystemModuleOnly,      // Stack or IP evidence from system modules (ntoskrnl/hal/...) only: not considered a clue.
    kStackPresenceOnly,     // Appears only on the stack of trusted frames: weak clue
    kFaultingIpAttributed,  // Faulting IP attributed to this module: investigable clue.
    kVerifierNamed,         // Verifier named: The strongest traceable clue, yet still not the root cause.
};

const char* investigationLeadName(InvestigationLead lead) noexcept;

// Each piece of evidence's own prerequisites must hold; otherwise, the lead level cannot be upgraded:
//   * If group.moduleKey is empty, this group has no identity (groupModuleEvidence produces such a group for
//     empty module names). Modules without a name cannot yield any clues and are always marked Undetermined.
//   * The faultingIp evidence requires ipFromContextRecord or that the frame be Unwound; see ModuleEvidenceItem.
//   * onStack evidence requires this frame to be Unwound.
InvestigationLead classifyLead(const ModuleEvidenceGroup& group) noexcept;

// Group by module. O(n log n): one stable_sort + one scan, no pairwise comparisons.
std::vector<ModuleEvidenceGroup> groupModuleEvidence(std::vector<ModuleEvidenceItem> items);

struct SuspectLead final {
    ModuleEvidenceGroup group;
    InvestigationLead lead = InvestigationLead::kUndetermined;
};

struct SuspectReport final {
    std::vector<SuspectLead> leads;
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;
    std::vector<std::string> limitationKeys;  // i18n key; UI handles translation
};

// stackOutcome determines whether observations exist. If no observations exist, the result is NoEvidence, not 'no issues found'.
// This function never returns NoDifferenceObserved: a dump presupposes a
// crash, so 'no difference observed' is a meaningless conclusion here.
SuspectReport buildSuspectReport(std::vector<ModuleEvidenceGroup> groups,
                                 const CollectionOutcome& stackOutcome);

// ---------------------------------------------------------------------------
// C-07 Missing memory boundary
// ---------------------------------------------------------------------------

enum class ContentCategory {
    kIrpObjects,
    kLockObjects,       // ERESOURCE / spinlock
    kFullProcessSpace,  // Full process address space
    kPoolMemory,
    kKernelModuleList,
    kThreadStacks,
    kPhysicalMemory,
};

inline constexpr std::size_t kContentCategoryCount = 7;

const char* contentCategoryName(ContentCategory category) noexcept;

enum class ContentPresence {
    kUnknown,      // Default: undetermined. Red line: must not be treated as 'none' nor as 'present'.
    kNotIncluded,  // Dump format: this file is not included — "Dump Not Included"
    kNotParsable,  // Contains but currently unparseable — "Currently unparseable"
    kIncluded,     // Included and parsable
};

const char* contentPresenceName(ContentPresence presence) noexcept;

struct DumpContentAvailability final {
    // Value initialization results in all Unknown (Unknown is the first enumerator). The default is not 'present'.
    std::array<ContentPresence, kContentCategoryCount> presence{};

    ContentPresence presenceOf(ContentCategory category) const noexcept;
    void set(ContentCategory category, ContentPresence value) noexcept;
};

// Upper bound derived from dump type, not "confirmed inclusion".
// Only mark as NotIncluded if the format definitively excludes it; otherwise mark as Unknown and rely on actual parsing to confirm.
DumpContentAvailability deriveAvailabilityFromKind(DumpKind kind) noexcept;

enum class ContentQueryResult {
    kAvailable,            // Can be parsed
    kNotIncludedInDump,    // "Not included in dump"
    kNotParsableHere,      // "Currently unparsable"
    kUnknownAvailability,  // Not yet determined — must not be treated as 'absent'.
};

const char* contentQueryResultName(ContentQueryResult result) noexcept;

// C-07 Red Line: Do not return an empty object to fake real data for any result that is not Available.
ContentQueryResult queryContent(const DumpContentAvailability& availability,
                               ContentCategory category) noexcept;

// C-07: Data supplemented from outside the dump must have its source marked separately
// and documented in the report; do not combine its counts with data from the dump.
struct ExternalSupplement final {
    bool used = false;
    SourceRef source;         // When used, origin must be ExternalFile.
    std::string disclosureKey;  // Disclosure key that must appear in the report.
};

bool supplementDisclosed(const ExternalSupplement& supplement) noexcept;

// ---------------------------------------------------------------------------
// C-08: Timeout, cancellation, and isolation.
// ---------------------------------------------------------------------------

enum class HelperState {
    kNotStarted,
    kStarting,
    kReady,
    kBusy,
    kStalled,       // No response despite exceeding budget
    kDisconnected,  // Communication disconnected
    kCancelling,    // Cancellation requested; still finalizing (must not falsely report cleanup).
    kExited,
    kFailed,
};

const char* helperStateName(HelperState state) noexcept;
bool helperStateIsTerminal(HelperState state) noexcept;

// "Has this round settled?" Only Ready (started, all required data provided) and Exited
// (normal exit) count as settled; NotStarted/Starting/Busy/Cancelling indicate the
// round is still in progress; Stalled/Disconnected/Failed indicate the round failed.
// This is distinct from helperStateIsTerminal: Terminal indicates whether the process still exists, whereas this indicates whether
// the result set is valid. A Busy helper process may be running perfectly fine, but its result set is inherently incomplete;
// reporting 'success with no differences found' in this case would be equivalent to claiming 'no valid results were ever collected'.
bool helperStateSettled(HelperState state) noexcept;

// C-08 Red Line: Only helpers owned by this module are allowed to be terminated.
struct HelperOwnership final {
    std::string ownerModuleId;  // Initiator
    std::string helperId;       // helper instance ID
    OptionalU64 processId;
    bool startedByThisModule = false;  // Default false — by default, termination is not allowed.
};

enum class TerminateDecision {
    kAllow,
    kRejectNotOwned,          // Not started by this module
    kRejectOwnerMismatch,     // Owner ID does not match the requester.
    kRejectNoHelperIdentity,  // Without a helperId, it is impossible to determine whom to terminate.
};

const char* terminateDecisionName(TerminateDecision decision) noexcept;

TerminateDecision decideHelperTermination(const HelperOwnership& helper,
                                          std::string_view requestingModuleId) noexcept;

// C-08: For blocked, disconnected, or cancelled states, retain partial results and explicitly mark the interruption reason.
struct InterruptedResult final {
    BudgetStop stop = BudgetStop::kContinue;
    HelperState helperState = HelperState::kNotStarted;
    CollectionOutcome outcome;
    CoverageAccount coverage;
    bool partialResultsRetained = false;
    std::vector<std::string> interruptionKeys;  // i18n key
};

// When haveAnyResult is false, the result can never be Partial: an interruption where nothing was collected. If reported as
// Partial, statusCarriesObservation would allow it, leading downstream to infer a positive conclusion—precisely the fallacy
// of 'inferring normalcy from nothing collected.' In this case, the stop reason maps to NotCollected/Timeout/Error.
//
// helperState is an **independent second dimension**; do not look at stop alone: stop==Continue only indicates "budget not
// exhausted" and tells nothing about whether the helper actually ran. When the helper is not settled (helperStateSettled is
// false), Success is always downgraded: if there is a result, downgrade to Partial; if no result, downgrade to NotCollected.
// More severe conclusions like Timeout/Error/NotCollected remain unchanged; this function only downgrades, never upgrades.
InterruptedResult buildInterruptedResult(BudgetStop stop,
                                         HelperState helperState,
                                         const ScanBudget& budget,
                                         CoverageAccount coverage,
                                         bool haveAnyResult);

// ---------------------------------------------------------------------------
// C-09: Untrusted paths and output.
// ---------------------------------------------------------------------------

// escapeForReport: The sole exit point for untrusted text (module names, file paths,
// symbol names, and strings embedded in dumps) before generating HTML reports.
//   Entity references for & < > " ' -> C0 control characters and 0x7F -> "&#65533;" (decimal
//   numeric reference for U+FFFD, pure ASCII output). Bytes >= 0x80 are passed through unchanged
//   to avoid breaking UTF-8. Newlines and tabs are replaced: the presence of newlines in these
// fields is itself anomalous; reports containing newlines do not pass through this function.
std::string escapeForReport(std::string_view untrusted);

// Sanitization of plain text (.txt / TSV) report fields: only control characters that would disrupt row/column structure are
// replaced with '?', without HTML escaping. This is a separate exit path from escapeForReport and must not be substituted for it.
std::string sanitizeForPlainTextField(std::string_view untrusted);

// C-09: Only allow fixed internal whitelist commands. No "parameter splicing" entry points exist — this file provides
// no command constructors; the whitelist consists of complete command strings, passing only via byte-for-byte equality.
std::span<const std::string_view> allowedAnalysisCommands() noexcept;

bool isSafeAnalysisCommand(std::string_view command) noexcept;

enum class CommandRejection {
    kAccepted,
    kEmpty,
    kTooLong,
    kContainsControlCharacter,
    kContainsShellMetacharacter,
    kNotInWhitelist,
};

const char* commandRejectionName(CommandRejection rejection) noexcept;

// Judgment order is fixed: null -> too long -> control characters -> shell metacharacters -> whitelist.
CommandRejection classifyCommandRequest(std::string_view request) noexcept;

// C-09: Path is processed according to data handling rules. The return value is used solely for **validation**; this function never rewrites the path.
enum class PathRisk {
    kOk,
    kEmpty,
    kTooLong,
    kControlCharacter,
    kWildCard,             // Wildcard (* or ?)
    kParentTraversal,      // A path segment equal to ".." exists.
    kAlternateDataStream,  // A colon other than the drive-letter colon.
    // Reserved device names (CON/PRN/AUX/NUL/COM1-9/LPT1-9) or a DOS device namespace prefix.
    // \\.\ / //./（\\.\PhysicalDrive0、\\.\pipe\x、\\?\GLOBALROOT\Device\...）。
    // The latter is neither a remote path nor a file: allowing it to be opened is equivalent to allowing raw disks or
    // named pipes to be fed as dumps, which constitutes an infinite-length, variable, attacker-controlled byte stream.
    kDeviceName,
    // Trailing dot or space. Windows strips them when opening, so the 'determined string' differs
    // from the 'actually opened file' — the determination is unreliable; reject directly.
    kTrailingDotOrSpace,
    kUncOrRemote,          // \\server\share or //server/share (including \\?\UNC\ long path notation)
};

const char* pathRiskName(PathRisk risk) noexcept;

// Win32 long path prefix \\?\ (and \\?\UNC\) is stripped before evaluation: it is the only valid way to open dump files
// exceeding MAX_PATH and is itself harmless. Without stripping, the '?' in the prefix would be treated as a WildCard by
// the scan, causing valid long-path dumps to be rejected with an incorrect UI reason ("contains WildCard"), leaving the
// user unable to fix it. After stripping, \\?\UNC\server\share\x remains classified as UncOrRemote.
PathRisk classifyDumpPath(std::string_view path) noexcept;

// Only Ok and UncOrRemote can be opened; UncOrRemote also requires explicit user confirmation.
bool pathAcceptableForOpen(PathRisk risk) noexcept;
bool pathNeedsExplicitConfirmation(PathRisk risk) noexcept;

// C-09 Defense in Depth: Performs egress checks on already-generated report fragments. Even if
// escaping is forgotten elsewhere, this layer intercepts issues before writing to the file.
enum class ReportOutputRisk {
    kOk,
    kRawControlCharacter,   // Control characters other than \t, \n, and \r.
    // Requires a user click to navigate out: href/action/formaction/cite/content points to
    // http(s)/ftp/file/UNC。
    kExternalLink,
    // External requests automatically sent when opening the report. Both types count because the consequences are the same:
    //   * Tags: img/iframe/object/embed/video/audio/source/link/base/meta/style
    //   * Attributes: External URLs, CSS URL(...) functions, or @import rules appearing in
    //     src, srcset, background, poster, data, or style—even if the tag name itself is benign.
    //     （<div style="background:url(https://…)">、<table background="//…">）。
    kExternalResourceTag,
    kDebuggerMarkupLink,    // DML：<exec cmd="..."> / <link cmd="...">
    // <script> / on*= / javascript: / vbscript: / data:。
    // Before validation, unescape character references in the attribute section: browsers
    // resolve entities before parsing URLs, so "&#106;avascript:" is treated as "javascript:".
    kScriptOrEventHandler,
};

const char* reportOutputRiskName(ReportOutputRisk risk) noexcept;

// One pass scan, taking the highest risk item. Priority:
// Control characters > scripts > DML > external resources (tags or auto-load attributes) > external links > OK.
ReportOutputRisk classifyReportFragment(std::string_view fragment) noexcept;

// ---------------------------------------------------------------------------
// C-10 Report provenance
// ---------------------------------------------------------------------------

struct EngineIdentity final {
    std::string engineId;       // "ksword.dumpfacts" / "dbgeng"
    std::string engineVersion;  // Empty = unknown. Critical: Do not write "0.0" to fake it.
    bool engineAvailable = false;
};

struct DumpInputIdentity final {
    std::string filePath;  // Original path (external text; pass through escapeForReport before adding it to the report).
    OptionalU64 fileSize;
    std::string sha256Hex;  // 64-bit lowercase hexadecimal; empty means not calculated, not "0".
    bool hashComputed = false;
    OptionalU64 lastModifiedUtc100ns;
};

struct DumpReportProvenance final {
    EngineIdentity engine;
    DumpInputIdentity input;
    SourceRef source;               // Note: origin must be OfflineSample
    CaptureWindow window;           // Moment when analysis occurred.
    CoverageAccount analysisScope;  // Analysis scope
    std::vector<ModuleSymbolState> symbolStates;
    DumpContentAvailability availability;
    ExternalSupplement supplement;
};

// C-10: Report exactly what is missing, rather than a single bool 'ok'.
enum class ProvenanceGap {
    kMissingEngineIdentity,
    kMissingEngineVersion,
    kMissingInputPath,
    kMissingInputSize,
    kMissingInputHash,
    kMissingAnalysisWindow,
    kMissingSymbolStates,
    kUnstatedAnalysisScope,
    kWrongSourceOrigin,
    kUndisclosedExternalSupplement,  // Uses data outside the dump without documentation.
};

const char* provenanceGapName(ProvenanceGap gap) noexcept;

std::vector<ProvenanceGap> auditProvenance(const DumpReportProvenance& provenance);

// A default-constructed provenance always returns false (Review Mode 3).
bool provenanceReviewable(const DumpReportProvenance& provenance);

struct ReportField final {
    std::string key;    // ASCII i18n key
    std::string value;  // Value already processed by escapeForReport.
};

// C-09 + C-10: The sole entry point for generating report header fields. All external text is escaped
// here; missing values output the fixed key "dump.value.unknown" instead of "0" or an empty string.
std::vector<ReportField> buildProvenanceFields(const DumpReportProvenance& provenance);

// Placeholder key for missing values in reports. Callers must translate via i18n; do not hardcode Chinese.
inline constexpr std::string_view kUnknownValueKey = "dump.value.unknown";

} // namespace ksword::evidence

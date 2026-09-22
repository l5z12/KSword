#pragma once

// J Module: Process memory injection and integrity check (post-event forensics, no pre-event monitoring records).
//
// This layer addresses the five items from Phase 1 of issue #196:
//   J-01 Full address space index (sub-region permissions must not be consumed by AllocationBase aggregation).
//   J-02 Module cross-view (Loader L / Image Mapping I / Non-image payload candidates P)
//   J-03 Working set page filtering (correct semantics for Valid/Shared).
//   J-04: Thread start and end points
//   J-05: **Range selection** for normalized image comparison, reusing PeImageMap + ImageDiff for normalization. Two
// mandatory concerns span the module: normalized comparison and **explicitly reported gaps in inspection coverage**.
//
// Things deliberately omitted are also part of the criteria:
//   * There are no fields like injectedUtc, injectionMethod, or injectorPid. Post-event memory state cannot prove
//     'who injected, when, and via which API'; providing such fields would inevitably lead to them being filled. The
//     only time field is firstObservedUtc100ns (first observed time). The source field is split into 'process
//     containing the payload' and 'injection source process', with the latter defaulting to OwnerAttribution::Unknown.
//   * No score/weight/+30/+40. Those scores lack sample calibration, and "private executable page", "outside module",
//     and "no image source" are often three descriptions of the same memory region; summing them causes double-counting.
//     Conclusion has only four AnalysisConclusion states plus one observation semantics table (semanticsFor).
//   * No entry points for "whole-process exemption" or "whole-directory exemption". ExceptionRelation must bind target
//     program version + modified module identity + specific RVA range; missing any component results in rejection.
//   * There are no isInjected / isClean flags. The termination condition for fast mode is 'which checks
//     were completed and which candidates were found', not a binary choice. Truncation, access denied, and
//     uncertain reference files all map to coverageGapKeys; never collapse them into 'no anomalies found'.
//
// C++20, Qt-free, Win32-free. Win32 numeric constants like PAGE_* are redeclared here per public documentation
// without including <Windows.h>, consistent with the rationale for PeImageMap's manual PE parsing.

#include "EvidenceEnvelope.h"
#include "ImageDiff.h"
#include "LosslessValue.h"
#include "MemoryRegionEvidence.h"
#include "ObjectIdentity.h"
#include "PeImageMap.h"
#include "ScanBudget.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

// Detector version for this module. Written into each finding for export and rollback.
inline constexpr std::uint32_t kInjectionSurveyRuleSetVersion = 1U;

// ---------------------------------------------------------------------------
// Mode and architecture.
// ---------------------------------------------------------------------------

// Fast mode is for screening; deep mode is for verification and forensics. The difference lies **only in the collection scope and
// read volume**, not in the criteria: the normalized profile sides must be identical for comparison (see normalizationProfileId).
enum class SurveyMode {
    kFast,
    kDeep,
};

const char* surveyModeName(SurveyMode mode) noexcept;

enum class ProcessArchitecture {
    kUnknown,
    kX64,
    kWow64,      // 32-bit process on a 64-bit system
    kX86Native,
    kArm64,
    kArm64Ec,
};

const char* processArchitectureName(ProcessArchitecture architecture) noexcept;

enum class CollectorArchitecture {
    kUnknown,
    kNative64,
    kWow64,      // The collector runs under WOW64.
};

const char* collectorArchitectureName(CollectorArchitecture architecture) noexcept;

// Microsoft documentation: When a 32-bit process calls EnumProcessModulesEx under WOW64, the module filter parameters are ignored.
// This means the WOW64 collector only ever sees the 32-bit view and cannot be treated as a complete 64-bit module list.
enum class ModuleEnumerationTrust {
    kUnknown,                  // Architecture unknown — cannot assume trust.
    kTrusted,                  // Native 64-bit collector
    kFilterIgnoredUnderWow64,  // WOW64 collector: Filter parameters are ignored; view is incomplete.
};

const char* moduleEnumerationTrustName(ModuleEnumerationTrust trust) noexcept;

ModuleEnumerationTrust evaluateModuleEnumerationTrust(CollectorArchitecture collector,
                                                      ProcessArchitecture target) noexcept;

// ---------------------------------------------------------------------------
// J-01: Correct classification of Win32 protection values.
// ---------------------------------------------------------------------------
//
// Low byte is the **exclusive base protection value**, not a set of bits to be ANDed:
//   PAGE_EXECUTE_READ (0x20) & PAGE_EXECUTE (0x10) == 0
// So `protect & PAGE_EXECUTE` misses R-X and RWX pages — exactly the false negatives flagged in the issue.
// The high bits are the combinable modifiers (PAGE_GUARD / PAGE_NOCACHE / ...).

inline constexpr std::uint32_t kWin32ProtectBaseMask = 0xFFU;

inline constexpr std::uint32_t kWin32PageNoAccess = 0x01U;
inline constexpr std::uint32_t kWin32PageReadOnly = 0x02U;
inline constexpr std::uint32_t kWin32PageReadWrite = 0x04U;
inline constexpr std::uint32_t kWin32PageWriteCopy = 0x08U;
inline constexpr std::uint32_t kWin32PageExecute = 0x10U;
inline constexpr std::uint32_t kWin32PageExecuteRead = 0x20U;
inline constexpr std::uint32_t kWin32PageExecuteReadWrite = 0x40U;
inline constexpr std::uint32_t kWin32PageExecuteWriteCopy = 0x80U;

inline constexpr std::uint32_t kWin32PageGuard = 0x100U;
inline constexpr std::uint32_t kWin32PageNoCache = 0x200U;
inline constexpr std::uint32_t kWin32PageWriteCombine = 0x400U;
inline constexpr std::uint32_t kWin32PageTargetsNoUpdate = 0x40000000U;

enum class ExecuteProtection {
    kUnknown,           // Source lacks original value — not "non-executable"
    kNotExecutable,
    kExecute,           // PAGE_EXECUTE
    kExecuteRead,       // PAGE_EXECUTE_READ
    kExecuteReadWrite,  // PAGE_EXECUTE_READWRITE
    kExecuteWriteCopy,  // PAGE_EXECUTE_WRITECOPY
};

const char* executeProtectionName(ExecuteProtection protection) noexcept;

bool executeProtectionIsExecutable(ExecuteProtection protection) noexcept;

// Facts decoded from original PAGE_* values. unrecognizedBase indicates the low byte is not any known
// base value — that means "unrecognized," so it cannot be treated as executable or non-executable.
struct ProtectionFacts final {
    ExecuteProtection execute = ExecuteProtection::kUnknown;
    bool readable = false;
    bool writable = false;
    bool copyOnWrite = false;
    bool noAccess = false;
    bool guard = false;
    bool unrecognizedBase = false;
    OptionalU64 rawValue;
};

ProtectionFacts classifyWin32Protection(const OptionalU64& rawProtect) noexcept;

// Write the parsed result into the common RegionProtection (M-01). Keeping both is intentional:
// RegionProtection is a cross-module generic shape, while ProtectionFacts retains
// Win32-specific 'uninterpretable raw values' and the 'PAGE_GUARD' state.
RegionProtection toRegionProtection(const ProtectionFacts& facts) noexcept;

// Retrieve the 'effective' protection facts for a region record:
//   If a raw PAGE_* value exists, use it as the authoritative source—even if the caller computed it using incorrect bitwise operations.
//     RegionProtection::executable: This layer can also correct the issue (the missed
//     detection pointed out in the issue was `protect & PAGE_EXECUTE` missing R-X / RWX).
//   * Fall back to the boolean field only when there is no raw value; if the boolean field is
//     entirely default, the source was never filled, which means unknown, not "non-executable".
ProtectionFacts effectiveProtection(const RegionRecord& record) noexcept;

// ---------------------------------------------------------------------------
// J-01: Code classification of the region.
// ---------------------------------------------------------------------------
//
// The first round must mark **two types** of committed regions: executable MEM_PRIVATE and executable MEM_MAPPED.
// Scanning only private memory misses mapped non-image code.
// Note: Executable pages in MEM_IMAGE are not "candidates" but also not "allowed"; they follow the J-05 comparison path.
enum class RegionCodeClass {
    kUnknown,            // Type or permission unknown.
    kNotCommitted,       // Not committed, excluded from code classification.
    kNonExecutable,
    kImageExecutable,    // MEM_IMAGE and executable — pass to normalization comparison.
    kPrivateExecutable,  // MEM_PRIVATE and executable — dynamic code candidate
    kMappedExecutable,   // MEM_MAPPED and executable — candidate for dynamic code.
};

const char* regionCodeClassName(RegionCodeClass codeClass) noexcept;

// Candidate = non-image executable memory. This only indicates
// 'dynamic/non-image executable memory exists', not 'injection confirmed'.
bool isDynamicCodeCandidate(RegionCodeClass codeClass) noexcept;

RegionCodeClass classifyRegionCode(const RegionRecord& record) noexcept;

// ---------------------------------------------------------------------------
// J-01: Address space index.
// ---------------------------------------------------------------------------
//
// VirtualQueryEx returns "contiguous regions with identical attributes", not a kernel VAD. Therefore, aggregating by
// AllocationBase is for **display and attribution** only; never merge the permissions of sub-regions into their parent.
// Extracting an RX page from a RW private allocation; after aggregation, only 'this allocation is RW' remains, causing the evidence to be lost.
struct AllocationGroup final {
    OptionalU64 allocationBase;
    std::vector<std::size_t> entryIndices;  // Points back to AddressSpaceIndex::entries

    RegionType type = RegionType::kUnknown;
    bool typeMixed = false;        // Note: More than one Type appeared within the group.
    std::string mappedPath;        // Consistent mapped path within the group; empty if inconsistent.
    bool mappedPathMixed = false;

    std::uint64_t committedBytes = 0;
    std::uint64_t executableBytes = 0;

    bool anyExecutable = false;
    bool anyWritableExecutable = false;
    bool anyGuard = false;
    bool anyProtectionUnknown = false;  // Protection values for sub-regions could not be read or understood.
};

struct AddressSpaceIndex final {
    static constexpr std::size_t kNoEntry = static_cast<std::size_t>(-1);

    // The first searchableCount entries are sorted by base in ascending order with valid intervals and can
    // participate in binary search. The remaining entries have missing base/size or addition overflow;
    // they are retained (evidence is not lost) but excluded from search and counted in coverage.failed.
    std::vector<RegionRecord> entries;
    std::size_t searchableCount = 0;
    std::vector<AllocationGroup> groups;   // Aggregate by allocationBase, in the order of first appearance in entries.
    std::vector<RegionCodeClass> codeClasses;  // Same length as entries.
    std::vector<std::size_t> entryGroup;       // Same length as entries, pointing to the index in groups.

    CollectionOutcome outcome;
    CoverageAccount coverage;

    std::uint64_t committedBytes = 0;
    std::uint64_t executableBytes = 0;
    std::size_t dynamicCodeCandidateCount = 0;

    // Find the index of the sub-region containing `va`. If not covered, return
    // `kNoEntry` — this indicates a coverage gap, not that the address is free.
    std::size_t findEntry(std::uint64_t va) const noexcept;
    const AllocationGroup* groupForEntry(std::size_t entryIndex) const noexcept;

    // Whether the index qualifies for "absence inference": only if collection succeeded and the ledger positively proves complete coverage.
    bool usableForAbsenceInference() const noexcept;
};

// The order of records is irrelevant; they are sorted internally by base. Records missing a base or
// size are excluded from interval lookups but remain in entries and are counted in coverage.failed.
AddressSpaceIndex buildAddressSpaceIndex(std::vector<RegionRecord> records,
                                         const CollectionOutcome& outcome);

// ---------------------------------------------------------------------------
// J-01b: Cheap summary filter for the process list
// ---------------------------------------------------------------------------
//
// This stage performs only the first round of J-01 (enumerating regions and categories), **not** touching modules, PE, working set, or threads.
// Used to add a column to the process list, allowing users to instantly identify which processes have abnormally large dynamic code surfaces.
//
// It is **not a conclusion** and must be treated as such. Empirical test (2026-09-12, 496 processes on local machine):
// 310 openable processes: **284 (92%)** have private/mapped executable memory, and 280 also have RWX memory.
// Therefore, the presence of dynamic code acts as an all-clear alarm signal; what matters is the **count** and its outlier degree
// (e.g., in the same sample, avpui has 841 blocks and kpm has 682 blocks, while most processes have only single-digit counts).
// Cost: 496 processes across the machine took 1073 ms total, with a median of 2.52 ms/process and p95 of 9.5 ms.
enum class SurfaceScreenState {
    kNotScreened,       // Not screened — the column must display "Not Screened", not 0.
    kAccessDenied,      // Failed to open the target (e.g., protected process) — not 'no dynamic code'.
    kIdentityMismatch,  // PID reused
    kFailed,
    kScreened,
};

const char* surfaceScreenStateName(SurfaceScreenState state) noexcept;

// Only Screened counts are meaningful; a 0 in other states means 'unknown', not 'none'.
bool surfaceScreenCountsAreMeaningful(SurfaceScreenState state) noexcept;

struct ProcessSurfaceScreen final {
    SurfaceScreenState state = SurfaceScreenState::kNotScreened;
    std::uint32_t regionCount = 0;
    std::uint32_t dynamicCodeRegions = 0;
    std::uint32_t writableExecutableRegions = 0;
    std::uint64_t dynamicCodeBytes = 0;
    // First observation time, not the 'injection time'.
    OptionalU64 screenedUtc100ns;
};

// Summarize from the built address space index. If index collection fails, return
// the corresponding failure state; never collapse 'not found' into a count of 0.
ProcessSurfaceScreen summarizeSurfaceScreen(const AddressSpaceIndex& index,
                                            const OptionalU64& screenedUtc100ns);

// ---------------------------------------------------------------------------
// J-02: Module cross-view.
// ---------------------------------------------------------------------------

// L: Loader view. Two layers of wrapping by the same collector do not count as two sources, so we do not
// distinguish between the PSAPI, Toolhelp, and PEB linked lists here—their cross-value lies in comparison with I.
struct LoaderModuleEntry final {
    DriverInstanceId module;   // imagePath / imageBase / imageSize
    std::string listedName;    // Name listed by the loader (may differ from the disk filename).
    bool isMainImage = false;
};

// I: Image mapping view. mappedPath is obtained via interfaces like GetMappedFileNameW.
// * Do not trust PEB strings alone; if unavailable, retain the failure reason and never write "no file injection".
struct ImageMappingEntry final {
    OptionalU64 allocationBase;
    OptionalU64 mappedSize;     // Committed span within this allocation group.
    std::string mappedPath;
    CollectionOutcome pathOutcome;
};

// P: structural judgment for non-image payload candidates.
// "Two bytes of 'MZ' are not sufficient evidence": The presence of a PE file in the data buffer is distinct
// from whether that PE has been loaded and executed. Thus, PeWithHeaders represents only a structural fact.
enum class PayloadStructure {
    kNotExamined,     // Not examined — coverage gap
    kUnreadable,      // Intended to check but unreadable
    kNoStructure,     // Checked; no recognizable structure found.
    kDataOnlyPeFile,  // Has complete PE file structure but not mapped (sections not expanded to virtual layout)
    kMappedPeImage,   // Header is self-consistent and section layout is consistent with the memory range.
    kHeaderErasedPe,  // Header erased, but residual structures such as imports, unwind data, and internal references remain.
    kBareCode,        // Executable code without PE structure.
};

const char* payloadStructureName(PayloadStructure structure) noexcept;

struct PayloadCandidateEntry final {
    OptionalU64 base;
    OptionalU64 size;
    RegionType type = RegionType::kUnknown;
    PayloadStructure structure = PayloadStructure::kNotExamined;
    std::vector<std::string> structureFacts;  // key=value, can trace back to source.
    CollectionOutcome outcome;
    // **Reliably unwound call frames** land in this memory. This is not about "stack backtracing capability is available" nor "an
    // address resembling this memory was found by scanning the stack" — only `StackEvidenceKind::ReliableUnwoundFrame` can set this
    // bit. This bit is the sole basis for elevating "payload structure exists in memory" to "payload is associated with execution".
    bool reliableFrameEntersRegion = false;

    // Whether this memory region has execute permissions at the time of collection. In deep mode, non-executable private/mapped memory is also included in
    // structural checks (sleeping payloads can be stored as RW and switched to RX before execution), but the noise profile for that mode is entirely different:
    // Local testing on 330 openable processes and 129937 non-executable committed regions found only 99
    // regions passing PE validity checks in the first page (~0.3 per process). Therefore, non-executable
    // candidates are listed but do not raise conclusions; see payloadCandidateCanRaiseConclusion.
    bool executableAtScanTime = true;
};

// Determines if a payload candidate qualifies to raise a conclusion. Non-executable candidates never qualify:
// A baseline noise of 0.3 per process means including it would cause 'observed differences' to appear routinely on
// clean machines, effectively turning this feature into another always-on alarm. They are still listed as entries.
bool payloadCandidateCanRaiseConclusion(const PayloadCandidateEntry& candidate) noexcept;

enum class ModuleCrossIssue {
    kImageMappingWithoutLoaderEntry,  // Image mapping exists, but no corresponding loader entry.
    kLoaderEntryWithoutImageMapping,  // Base addresses in the list lack valid mappings.
    kLoaderPathMismatch,              // Name/path mismatch with actual mapping.
    kLoaderSizeMismatch,              // Size does not match the actual mapping.
    kMainImageIdentityConflict,       // Contradictory sources for the main image identity
    kMappedPathUnavailable,           // Path query failed — a gap, not a conclusion.
};

const char* moduleCrossIssueName(ModuleCrossIssue issue) noexcept;

// Cross-view issues are categorized into two tiers and cannot be treated equally:
//   * **Contradiction** (this function returns true): Two views say conflicting things about the **same object** — the
//     loader says ntdll.dll, but the mapping points to another file; the three sources of the main image are inconsistent.
//     This supports DifferenceObserved.
//   * **Asymmetric** (returns false): One side has it, the other does not. It has many recorded legitimate causes—such as image
//     mappings that only perform resource mapping (LOAD_LIBRARY_AS_IMAGE_RESOURCE), Windows metadata images, and .NET-related
//     mappings; empirically, explorer.exe consistently shows over a dozen such cases. It can only be classified as Indeterminate.
//   Missing PEB entry 'report exception first' is not 'observed discrepancy'.
bool moduleCrossIssueIsContradiction(ModuleCrossIssue issue) noexcept;

struct ModuleCrossFinding final {
    ModuleCrossIssue issue = ModuleCrossIssue::kMappedPathUnavailable;
    OptionalU64 base;
    std::string loaderPath;
    std::string mappedPath;
    OptionalU64 loaderSize;
    OptionalU64 mappedSize;
    std::vector<std::string> facts;
    CollectionOutcome inputOutcome;
};

struct ModuleCrossViewInput final {
    std::vector<LoaderModuleEntry> loaderView;
    CollectionOutcome loaderOutcome;
    ModuleEnumerationTrust loaderTrust = ModuleEnumerationTrust::kUnknown;

    std::vector<ImageMappingEntry> imageView;
    CollectionOutcome imageOutcome;

    std::vector<PayloadCandidateEntry> payloadView;
    CollectionOutcome payloadOutcome;

    // Three independent sources for the main image. An empty value indicates that source was not retrieved.
    std::string mainImagePathFromLoader;   // First item of the PEB loader list.
    std::string mainImagePathFromKernel;   // QueryFullProcessImageName type
    std::string mainImagePathFromMapping;  // GetMappedFileNameW for the main image allocation
    OptionalU64 mainImageBaseFromLoader;
    OptionalU64 mainImageBaseFromMapping;

    // Tolerance for mapping span relative to the loader's SizeOfImage. The loader reports SizeOfImage, but the
    // mapping span may be slightly larger due to alignment. Without tolerance, this would generate excessive noise.
    std::uint64_t sizeToleranceBytes = 0x10000ULL;
};

struct ModuleCrossViewReport final {
    std::vector<ModuleCrossFinding> findings;
    std::vector<std::string> coverageGapKeys;

    std::size_t matchedModules = 0;
    std::size_t loaderOnly = 0;
    std::size_t mappingOnly = 0;
    std::size_t payloadCandidates = 0;

    // Inference of missing items is allowed only when both side views report Success. If either side fails, is partial, or
    // is unsupported, no missing items are produced, and the gap key is left intact. This follows the same rule as X-06.
    bool absenceInferenceAllowed = false;

    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;
};

ModuleCrossViewReport evaluateModuleCrossView(const ModuleCrossViewInput& input);

// ---------------------------------------------------------------------------
// J-03: Working set page filtering.
// ---------------------------------------------------------------------------

// Result for one page from QueryWorkingSetEx. Field names align with PSAPI_WORKING_SET_EX_BLOCK.
struct WorkingSetPageFact final {
    std::uint64_t va = 0;
    bool queried = false;   // Whether this page has actually been queried.
    bool valid = false;     // When Valid==0, other fields must not be interpreted as valid pages.
    bool shared = false;    // "Shareable" does not mean "currently used by exactly two processes".
    OptionalU64 shareCount; // Retain the original value for export; **do not use** in criteria.
    bool locked = false;
    bool largePage = false;
    bool bad = false;
    OptionalU64 win32Protection;
    OptionalU64 node;
};

enum class PageScreenVerdict {
    kNotQueried,           // Not queried — covers the gap.
    kInvalidNeedsRecheck,  // Valid==0: conservatively mark as pending recheck; do not interpret as valid page.
    kPrivatizedCandidate,  // Valid && !Shared — Privatized/rewritten candidate; compare first.
    kSharedNotCleared,     // Valid && Shared — **not an allow**, deep mode still requires comparison
};

const char* pageScreenVerdictName(PageScreenVerdict verdict) noexcept;

// The criterion deliberately ignores shareCount: Shared indicates 'whether a page is shareable';
// ShareCount == 1 does not substitute for it. Moreover, DFRWS 2023 recorded that memory merging
// can cause modified pages to regain a shareable state, so Shared cannot be used to reverse-allow.
PageScreenVerdict screenWorkingSetPage(const WorkingSetPageFact& fact) noexcept;

// Fast mode prioritizes comparing non-shareable code pages; deep mode does not exclude any image pages via shared state.
bool pageSelectedForComparison(PageScreenVerdict verdict, SurveyMode mode) noexcept;

// ---------------------------------------------------------------------------
// J-04: Thread start and end points.
// ---------------------------------------------------------------------------

// The code range of a module. codeBegin/codeEnd represent the coarse-grained envelope of the union of RVA intervals that **should be
// executed** within the module, used to detect regions that fall inside the image but do not conform to the module's code layout.
struct ImageCodeExtent final {
    std::string path;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint64_t codeBeginRva = 0;
    std::uint64_t codeEndRva = 0;
    bool codeExtentKnown = false;  // false indicates only module scope is known, not code layout.

    bool containsAddress(std::uint64_t address) const noexcept;
    bool addressInCodeExtent(std::uint64_t address) const noexcept;
};

enum class ThreadStartLanding {
    kNotCollected,        // Start address not retrieved — no observation, not "ownership mismatch".
    kOutsideIndex,        // Index does not cover this address — coverage gap.
    kFreeOrReserved,      // Falls within a freed or uncommitted region.
    kNonImagePrivate,     // Falls in private region
    kNonImageMapped,      // Falls within a mapped (non-image) region.
    kImageCodeRange,      // Falls within a code range of an image.
    kImageOutsideCode,    // Located within the image but does not conform to the module's code layout.
    kImageLayoutUnknown,  // Falls within the image, but code layout is unknown and cannot be subdivided.
};

const char* threadStartLandingName(ThreadStartLanding landing) noexcept;

// Collection result for existing thread start points.
struct ThreadStartInput final {
    ThreadInstanceId thread;
    OptionalU64 startAddress;
    CollectionOutcome startAddressOutcome;

    // Entry instruction check (only if budget allows). Three states: not done / done but unreadable / done and readable.
    bool entryInspected = false;
    bool entryReadable = false;
    // The first-hop target after parsing. unset means "not parsed", not "no jump".
    OptionalU64 immediateBranchTarget;
};

// Trust level of the thread context. Microsoft explicitly states: a running thread cannot obtain a valid context via GetThreadContext.
// Therefore, a context obtained without suspending or taking a snapshot must be marked as untrusted and cannot be used as execution evidence.
//
// WaitingThreadStable is the fourth state and the only one this feature actually consumes: **for a
// non-running thread, the context is inherently stable**. Microsoft's warning targets threads 'running on
// another core'—their RIP/RSP change while you are reading them. Threads blocked in NtDelayExecution or
// NtWaitForSingleObject do not have this issue; the values you read are exactly the set they were stopped at.
//
// This state is critical for the entire flow: the hard constraint of this feature is **not suspending the target**, so SuspendedOrSnapshot is never
// reachable; meanwhile, the shellcode form most worth investigating is exactly a beacon that "takes a nap then wakes up", which remains in a waiting state.
// The collection side must check the thread status once before and once after capturing the context; both checks must indicate 'waiting' to allow marking this state.
// Note: If interrupted while suspended, the first unwound return address will not fall within any module; the reliable
// prefix is truncated immediately—the failure direction is 'dare not claim reliability', which is the correct side.
enum class ThreadContextTrust {
    kNotCaptured,
    kRunningThreadUntrusted,
    kWaitingThreadStable,
    kSuspendedOrSnapshot,
};

const char* threadContextTrustName(ThreadContextTrust trust) noexcept;

ThreadContextTrust classifyThreadContextTrust(bool captured,
                                              bool suspendedOrSnapshot,
                                              bool waitingBeforeAndAfter) noexcept;

bool contextUsableAsExecutionEvidence(ThreadContextTrust trust) noexcept;

// Stack observations are stored in three tiers. "Scanning a value in stack memory that looks like a code address" is not
// equivalent to "recovering a call frame"; mixing all three into a single execution evidence type is explicitly prohibited.
enum class StackEvidenceKind {
    kReliableUnwoundFrame,            // Reliably unwound frame.
    kHeuristicReturnAddressCandidate, // Heuristic return address candidate
    kPlainPointerReference,           // Plain pointer reference.
};

const char* stackEvidenceKindName(StackEvidenceKind kind) noexcept;

// Only frames with reliable unwind count as execution evidence.
bool stackEvidenceCountsAsExecution(StackEvidenceKind kind) noexcept;

// A raw stack frame submitted by the collector. **The collector does not verify reliability**; it only answers two facts:
// Where it unwound to, and whether the **previous frame's PC falls within a function where a RUNTIME_FUNCTION can be found**.
// The latter is the sole basis for reliability checks; see admitStackFrames for reasoning.
struct RawStackFrame final {
    OptionalU64 instructionPointer;
    OptionalU64 stackPointer;
    // This frame is derived from the **previous frame's unwind data** (not guessed by stack scanning).
    // The stack top frame comes directly from the thread context and is always true (there is no "previous frame" to unwind).
    bool derivedFromUnwindData = false;
    // Whether unwind data is available for the current frame's PC. This determines reliability for the **next** frame, not the current one.
    bool unwindDataAvailableAtPc = false;
};

// The result of stack collection for a thread.
struct ThreadStackInput final {
    ThreadInstanceId thread;
    ThreadContextTrust trust = ThreadContextTrust::kNotCaptured;
    CollectionOutcome outcome;
    // Arranged from top to bottom of the stack.
    std::vector<RawStackFrame> frames;
    // Reason for unwinding at a stop (e.g., stack read failure, exceeded frame limit...); empty indicates reaching the stack bottom.
    std::string terminationReason;
};

// The single entry point for assessing reliability. Return the **length of the reliable prefix**: the
// number of consecutive frames, starting at the top of the stack, that were calculated from unwind data.
//
// Why prefix instead of per-frame check: x64 lacks a frame pointer chain. Once a frame's PC cannot find
// RUNTIME_FUNCTION (as with shellcode), further traversal relies on stack scanning to guess, where the guessed
// "return addresses" are mixed with many stale, expired values. Once reliability breaks, it never recovers.
//
// Note that this rule **exactly** counts the shellcode frame itself as part of the reliable prefix: it is derived from the caller
// with unwind data (such as KERNELBASE), so it is reliable; the frames below it are unreliable. This is the intended semantics.
//
// If trust is insufficient, always return 0 — if the context itself is untrustworthy,
// anything derived from it is meaningless regardless of apparent reliability.
std::size_t admitStackFrames(const ThreadStackInput& stack) noexcept;

struct ThreadStartFinding final {
    ThreadInstanceId thread;
    OptionalU64 startAddress;
    ThreadStartLanding landing = ThreadStartLanding::kNotCollected;

    // Whether the page containing the start address is executable **now**. The fact that the start page is currently non-executable
    // does not justify ignoring this clue; thus, it is merely a parallel fact bit and does not participate in landing determination.
    bool startPageExecutableKnown = false;
    bool startPageExecutable = false;

    std::string owningPath;   // Empty indicates unknown ownership, not 'no ownership'.
    OptionalU64 branchTarget;
    ThreadStartLanding branchTargetLanding = ThreadStartLanding::kNotCollected;
    bool branchLeavesOwningModule = false;
    bool entryInspected = false;

    std::vector<std::string> facts;
    CollectionOutcome outcome;
};

// Interpret a batch of thread start points using the address space index and module code ranges.
std::vector<ThreadStartFinding> evaluateThreadStarts(
    const std::vector<ThreadStartInput>& threads,
    const AddressSpaceIndex& index,
    const std::vector<ImageCodeExtent>& images);

// ---------------------------------------------------------------------------
// J-05: Scope selection for normalized image comparison.
// ---------------------------------------------------------------------------
//
// Hard constraint: Fast mode and deep mode must use the same normalization logic; fast scan must not perform raw comparison while deep
// scan handles relocations. Therefore, the profile ID is independent of the mode; the two modes only differ in the comparison range.
inline constexpr const char* kNormalizationProfileId = "image.normalize.peimagemap.v1";
inline constexpr std::uint32_t kNormalizationProfileVersion = 1U;

const char* normalizationProfileId(SurveyMode mode) noexcept;
std::uint32_t normalizationProfileVersion(SurveyMode mode) noexcept;

enum class ComparisonReason {
    kMainImageEntry,           // Main image entry
    kSuspiciousThreadEntry,    // Suspicious thread entry.
    kWorkingSetScreenedPage,   // Abnormal image pages screened from the working set
    kControlFlowReference,     // Discovered control flow reference locations
    kFullExecutableCoverage,   // Deep mode: all executable image ranges.
};

const char* comparisonReasonName(ComparisonReason reason) noexcept;

struct ComparisonTarget final {
    DriverInstanceId module;
    RvaRange range;
    ComparisonReason reason = ComparisonReason::kMainImageEntry;
};

// Facts required to build the plan.
struct ComparisonPlanInput final {
    SurveyMode mode = SurveyMode::kFast;
    std::vector<ImageCodeExtent> images;

    // The RVA of the main image entry and the span to compare. unset indicates retrieval failure — a gap key is planned to be reserved.
    std::string mainImagePath;
    OptionalU64 mainImageEntryRva;

    // Suspicious thread entry site (resolved to module path + RVA).
    struct ThreadEntrySite final {
        std::string imagePath;
        std::uint32_t rva = 0;
    };
    std::vector<ThreadEntrySite> threadEntrySites;

    // Abnormal image pages filtered from the working set (module path + page RVA).
    struct ScreenedPage final {
        std::string imagePath;
        std::uint32_t pageRva = 0;
    };
    std::vector<ScreenedPage> screenedPages;

    // Discovered control flow reference locations.
    std::vector<ThreadEntrySite> controlFlowSites;

    std::uint32_t entryWindowBytes = 64U;
    std::uint32_t pageSize = 4096U;
};

struct ComparisonPlan final {
    SurveyMode mode = SurveyMode::kFast;
    std::string normalizationProfileId;
    std::uint32_t normalizationProfileVersion = 0;
    std::vector<ComparisonTarget> targets;
    std::vector<std::string> coverageGapKeys;
};

ComparisonPlan buildComparisonPlan(const ComparisonPlanInput& input);

// Confidence level of the reference file. 'The file under the current path may have been updated or replaced.' When a reliable reference cannot
// be obtained, 'reference image uncertain' must be reported; one cannot automatically attribute all differences to malicious modifications.
enum class ReferenceConfidence {
    kNoReference,        // No reference file at all.
    kReferenceUncertain, // File exists, but cannot confirm it corresponds to the target image version.
    kReferenceVerified,  // Identity verified (PDB signature / TimeDateStamp + SizeOfImage, etc.).
};

const char* referenceConfidenceName(ReferenceConfidence confidence) noexcept;

// Only ReferenceVerified allows expressing the difference as 'Image code modification confirmed'.
bool referenceSupportsDifferenceClaim(ReferenceConfidence confidence) noexcept;

// Source of the reference bytes. The two sources are independent; **simultaneous hits provide the strongest evidence**:
//   DiskFile: The file on disk. Most common, but the file may be
//                     locked, unreadable, or modified by an attacker along with memory.
//   SectionObject: A section object held by the memory manager itself (clean pages pointed to by prototype PTEs).
//                     It is the content at mapping establishment; modifying the disk file does not change it.
enum class ImageReferenceSource {
    kNone,
    kDiskFile,
    kSectionObject,
};

const char* imageReferenceSourceName(ImageReferenceSource source) noexcept;

struct ImageComparisonOutcome final {
    DriverInstanceId module;
    ReferenceConfidence referenceConfidence = ReferenceConfidence::kNoReference;
    ImageReferenceSource referenceSource = ImageReferenceSource::kDiskFile;
    ImageDiffReport report;

    // Coverage accounting for section object references. **Only meaningful when referenceSource == SectionObject.**
    // Prototype PTEs that are not in a valid page state cannot be referenced (by design in this version, pages are
    // not paged in). These pages represent **coverage gaps**, not "no difference found after comparison."
    std::size_t sectionPagesRequested = 0;
    std::size_t sectionPagesAvailable = 0;
};

// Whether the section object reference covers all requested pages. If coverage is incomplete, differences are still valid (what
// was found is found), but "no difference found" cannot be established—pages that were not compared cannot be considered compared.
bool sectionReferenceCoverageComplete(const ImageComparisonOutcome& outcome) noexcept;

// ---------------------------------------------------------------------------
// J-06: Cross-view of R0 scanning backend (issue #196 §V, Layers 1-2)
// ---------------------------------------------------------------------------
//
// This section handles the **second and third independent sources**:
//   * VAD tree (regions tracked by the memory manager itself), independent of R3's VirtualQueryEx;
//   * Page table leaves (how the processor actually views them) are independent of the former two.
//
// Three hard rules:
//   * 'Internal structures are validated against the target build; unsupported versions are explicitly downgraded' — if the profile hasn't been validated, then
//     No findings are produced; only a gap remains. Never use offsets from similar versions to continue reading.
//   The bit layout of MMVAD_FLAGS is unverified, so VAD protection **does not participate** in contradiction checks against R3
//     protection attributes; only ranges are compared. If the bits are guessed wrong, it results in a whole-page false contradiction.
//   * "Kernel collection relies on kernel trust" — A threat with kernel capabilities can modify the metadata read here.
//     If kernel view is used, kLimitKernelTrustAssumption is always set; no guarantee that 'presence of a driver implies inability to hide'.

enum class KernelBackendState {
    kNotRequested,       // The kernel backend is not intended for use this time.
    kDriverUnavailable,  // Driver not loaded / cannot open / insufficient permissions
    kProfileUnverified,  // The driver is present, but DynData has not verified the required offsets for the current build.
    kPartial,            // Executed but with unreadable nodes/entries or truncated by budget.
    kAvailable,          // Completed run
};

const char* kernelBackendStateName(KernelBackendState state) noexcept;

// Only 'Available' allows for 'present here, absent there' logic. 'Partial' turns missing-item inference into guessing.
bool kernelBackendSupportsAbsenceInference(KernelBackendState state) noexcept;

// R0 VAD view region record.
struct KernelVadRegion final {
    OptionalU64 startVa;
    OptionalU64 endVaExclusive;
    OptionalU64 vadNodeAddress;
    bool privateMemory = false;
    bool hasSection = false;          // controlArea != 0
    // Bit layout is unverified — always true. Therefore, protection and vadType can only be displayed.
    bool flagsLayoutAssumed = true;
    OptionalU64 protectionRaw;
    OptionalU64 vadFlagsRaw;
};

struct KernelVadView final {
    std::vector<KernelVadRegion> regions;
    KernelBackendState state = KernelBackendState::kNotRequested;
    CollectionOutcome outcome;
    std::uint64_t visitedCount = 0;
    std::uint64_t unreadableNodeCount = 0;
    bool truncated = false;

    // --- Tree structure integrity (broken link check) --------------------------------------------- integrityValid
    // is the hard gate for this entire group: if false, the following items must not participate in the judgment.
    // Under partial traversal (truncation, resumption, or unreadable nodes), visitedCount is inherently
    // less than vadCount; comparing them for equality causes stable false positives on normal machines.
    bool integrityValid = false;
    bool vadCountKnown = false;      // EPROCESS.VadCount offset is available and has been read.
    bool vadHintKnown = false;       // EPROCESS.VadHint offset is available and has been read.
    std::uint64_t vadCount = 0;      // Count maintained by the kernel itself.
    OptionalU64 vadHintAddress;
    bool vadHintVisited = false;     // Node pointed to by VadHint was visited during traversal.
    std::uint64_t parentMismatchNodes = 0;  // Count of nodes where the parent pointer does not match

    bool usableForAbsenceInference() const noexcept;
};

// Three-state conclusion for broken-link checks. **Deliberately not a boolean**:
//   NotChecked: not performed, or traversal incomplete (unknown, not 'OK').
//   Consistent: traversal completed, all three items match. Inconsistent:
//   traversal completed, at least one item mismatches. Folding NotChecked
// into Consistent is the most common and costly error for this feature:
// 'Failed to check' may be misread as 'tree is valid'.
enum class VadLinkIntegrity {
    kNotChecked,
    kConsistent,
    kInconsistent,
};

const char* vadLinkIntegrityName(VadLinkIntegrity integrity) noexcept;

// Check the link integrity of the VAD tree once. Only verify internal consistency within the tree; it does
// not involve cross-view with R3 (a separate dimension where user mode cannot see but the page table can).
VadLinkIntegrity evaluateVadLinkIntegrity(const KernelVadView& view) noexcept;

// An executable leaf page in the R0 page table view.
struct KernelExecutableExtent final {
    OptionalU64 startVa;
    OptionalU64 byteLength;
    std::uint32_t pageSize = 0;
    bool executable = false;
    bool writable = false;
    bool userAccessible = false;
    bool largePage = false;
    OptionalU64 firstEntryValue;
};

struct KernelPteView final {
    std::vector<KernelExecutableExtent> extents;
    KernelBackendState state = KernelBackendState::kNotRequested;
    CollectionOutcome outcome;
    std::uint64_t tableReads = 0;
    std::uint64_t failedTableReads = 0;
    bool truncated = false;
    OptionalU64 scannedBegin;
    OptionalU64 scannedEnd;

    bool usableForAbsenceInference() const noexcept;
};

enum class KernelRegionCrossIssue {
    kVadOnlyRange,            // VAD contains this range, but R3 VirtualQueryEx does not report it.
    kR3OnlyCommittedRange,    // R3 reported a committed region, but no corresponding entry exists in the VAD tree.
    kExecutableBeyondR3View,  // Page table indicates executable, but the region in the R3 index is non-executable or does not exist.
    kExecutableBeyondVadView, // Page table says executable, but VAD does not cover that region.
};

const char* kernelRegionCrossIssueName(KernelRegionCrossIssue issue) noexcept;

struct KernelRegionCrossFinding final {
    KernelRegionCrossIssue issue = KernelRegionCrossIssue::kVadOnlyRange;
    OptionalU64 startVa;
    OptionalU64 endVaExclusive;
    std::vector<std::string> facts;
    CollectionOutcome inputOutcome;
};

struct KernelCrossViewInput final {
    const AddressSpaceIndex* r3Index = nullptr;   // Required; if null, the entire section produces no output.
    KernelVadView vadView;
    KernelPteView pteView;
    // The page table view only scanned this range. "Page table reports not executable" outside this range does not constitute a missing entry.
    OptionalU64 pteScanBegin;
    OptionalU64 pteScanEnd;
};

struct KernelCrossViewReport final {
    std::vector<KernelRegionCrossFinding> findings;
    std::vector<std::string> coverageGapKeys;
    std::vector<std::string> capabilityLimitKeys;

    std::size_t vadOnlyCount = 0;
    std::size_t r3OnlyCount = 0;
    std::size_t executableBeyondViewCount = 0;
    bool absenceInferenceAllowed = false;

    // Self-consistency of the VAD tree's own links. This is the complementary dimension to the three counts above: the three ask "do the
    // two views agree?", while this one asks "is this tree structurally sound?". The direct trace of link removal appears in the latter.
    VadLinkIntegrity linkIntegrity = VadLinkIntegrity::kNotChecked;
    // Original readings used for validation, returned in results for source tracing.
    std::uint64_t linkVisitedCount = 0;
    std::uint64_t linkVadCount = 0;
    std::uint64_t linkParentMismatchNodes = 0;
    bool linkVadCountKnown = false;
    bool linkVadHintKnown = false;
    bool linkVadHintVisited = false;
    OptionalU64 linkVadHintAddress;

    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;
};

KernelCrossViewReport evaluateKernelCrossView(const KernelCrossViewInput& input);

// ---------------------------------------------------------------------------
// Exception (whitelist): applies only to specific relationships
// ---------------------------------------------------------------------------

// Valid exceptions must cover at least these four sources. Unspecified is
// always rejected: an exemption rule without a category cannot be audited.
enum class ExceptionCategory {
    kUnspecified,
    kRuntimeDynamicCode,       // JIT and other runtime dynamic code.
    kSecurityInstrumentation,  // Security product instrumentation
    kSoftwareProtection,       // Software protection / packing / DRM
    kSystemCompatibility,      // Verified system compatibility modifications
};

const char* exceptionCategoryName(ExceptionCategory category) noexcept;

struct ExceptionRelation final {
    std::string ruleId;
    std::uint32_t ruleVersion = 0;
    ExceptionCategory category = ExceptionCategory::kUnspecified;

    std::string targetImageIdentity;     // Target application version identity (required).
    std::string modifiedModuleIdentity;  // Identity of the modified module (required).
    RvaRange modifiedRange;              // Modified location (required, with a hard upper limit).

    // Allowed jump relationships. Empty indicates no requirement on the jump target for this rule.
    std::string allowedBranchTargetModuleIdentity;
    // Essential target byte check. Non-null only if field bytes are readable; otherwise, a hit is impossible.
    std::vector<std::uint8_t> expectedBytes;

    std::string evidenceText;  // Based on source, not a conclusion.
};

enum class ExceptionAdmission {
    kAccepted,
    kMissingRuleId,
    kMissingCategory,
    kMissingTargetImageIdentity,
    kMissingModuleIdentity,
    kEmptyRange,
    kRangeTooWide,   // Exceeds kExplanationRuleMaxSpanBytes — equivalent to allowing the entire module.
};

const char* exceptionAdmissionName(ExceptionAdmission admission) noexcept;

// Whitelists must target specific relations, not entire processes or directories: missing any of the four required fields
// results in rejection; an empty or overly broad scope results in rejection. Rejected rules do not participate in matching.
ExceptionAdmission admitExceptionRelation(const ExceptionRelation& rule) noexcept;

// The modifiedModuleIdentity in the exception rule **must** be generated using this function; otherwise, the rule will never
// match (matching is strict equality without path normalization). Prefer the cross-session primary key of DriverInstanceId
// (including PDB signature / TimeDateStamp to distinguish same-name different versions); if identity is insufficient,
// degrade to a normalized path (lowercase + backslash). The degraded key cannot distinguish versions; this is the cost of
// 'same name does not equal same version'. Rule authors should supplement module identity rather than relying on paths.
std::string moduleIdentityKeyFor(const DriverInstanceId& module);

struct ExceptionQuery final {
    std::string targetImageIdentity;
    std::string modifiedModuleIdentity;
    RvaRange range;
    // Identity of the branch target module observed in the field. Empty indicates "this fact does not exist".
    std::string actualBranchTargetModuleIdentity;
    // Bytes read from the live target. bytesAvailable=false means no data was obtained, which differs from successfully reading an empty result.
    bool bytesAvailable = false;
    std::vector<std::uint8_t> actualBytes;
};

enum class ExceptionMatch {
    kNoRule,                // No rules present
    kAllRulesRejected,      // Rules exist, but all were rejected by admission checks.
    kTargetImageMismatch,
    kModuleMismatch,
    kRangeNotCovered,       // Partial coverage does not count as a hit
    kBranchTargetMismatch,
    kBytesUnavailable,      // Rule requires byte checking, but bytes were not read on-site -> no match.
    kBytesMismatch,
    kMatched,
};

const char* exceptionMatchName(ExceptionMatch match) noexcept;

struct ExceptionMatchResult final {
    ExceptionMatch match = ExceptionMatch::kNoRule;
    std::string ruleId;
    std::uint32_t ruleVersion = 0;
    ExceptionCategory category = ExceptionCategory::kUnspecified;
    std::size_t rejectedRuleCount = 0;  // Discarded items must be visible.
};

// A match requires the rule scope to **fully contain** the scope being checked. Returns the "closest failure reason":
// If any rule proceeds to a later check, report the reason for that specific rule to help locate where the rule is incorrect.
ExceptionMatchResult matchExceptionRelation(const std::vector<ExceptionRelation>& rules,
                                            const ExceptionQuery& query);

// ---------------------------------------------------------------------------
// Result entry
// ---------------------------------------------------------------------------

extern const char* const kRuleIdDynamicCodeRegion;          // inject.region.dynamic-code
extern const char* const kRuleIdImageBytesUnexplained;      // inject.image.unexplained-diff
extern const char* const kRuleIdImageReferenceUncertain;    // inject.image.reference-uncertain
extern const char* const kRuleIdImageWithoutLoaderEntry;    // inject.module.image-without-loader
extern const char* const kRuleIdLoaderEntryWithoutMapping;  // inject.module.loader-without-mapping
extern const char* const kRuleIdModuleIdentityMismatch;     // inject.module.identity-mismatch
extern const char* const kRuleIdMainImageConflict;          // inject.main-image.conflict
extern const char* const kRuleIdThreadStartOutsideImage;    // inject.thread.start-outside-image
extern const char* const kRuleIdThreadStartUnknown;         // inject.thread.start-unknown
extern const char* const kRuleIdThreadStartTrampoline;      // inject.thread.start-trampoline
extern const char* const kRuleIdPayloadStructure;           // inject.payload.structure
extern const char* const kRuleIdKernelRegionHiddenFromR3;   // inject.kernel.region-hidden-from-r3
extern const char* const kRuleIdKernelRegionMissingInVad;   // inject.kernel.region-missing-in-vad
extern const char* const kRuleIdKernelExecutableBeyondView; // inject.kernel.executable-beyond-view
// Inconsistency in the VAD tree's own links (parent pointer does not resolve upward / VadHint points outside the tree / count exceeds the number of traversed nodes).
// This is direct evidence of "chain removal," complementary to the two dimensions of "invisible to user mode but visible in page tables."
extern const char* const kRuleIdKernelVadLinkBroken;        // inject.kernel.vad-link-broken

// Confidence: not a score, but "how many independent observations support this result".
enum class EvidenceConfidence {
    kInputIncomplete,          // Dependent input is incomplete — can only be used as a clue.
    kSingleObservation,        // Single observation
    kCorroboratedIndependent,  // Two or more independent observations corroborate each other.
};

const char* evidenceConfidenceName(EvidenceConfidence confidence) noexcept;

// The set of fields for each result, corresponding to the checklist in Section 6 of the issue.
// Note that injectedUtc, injectorPid, score, and isMalicious are intentionally absent here.
struct InjectionFinding final {
    std::string ruleId;
    std::uint32_t ruleVersion = kInjectionSurveyRuleSetVersion;
    std::string detectorVersion;

    ProcessInstanceId payloadProcess;  // Process containing the payload.
    // Injection source process. Without a prior record, it is Unknown; never downgrade it to an unspecified system process.
    OwnerAttribution injectorAttribution = OwnerAttribution::kUnknown;
    std::vector<std::string> injectorCandidates;

    OptionalU64 firstObservedUtc100ns;  // First observed time, not the injection time.

    OptionalU64 address;
    OptionalU64 size;
    RegionType regionType = RegionType::kUnknown;
    RegionProtection protection;
    std::string mappedPath;

    std::string moduleName;
    std::string sectionName;
    OptionalU64 rva;

    std::vector<std::string> facts;  // Raw evidence, key=value format, can be traced back to source.
    std::vector<ThreadInstanceId> relatedThreads;
    std::vector<std::string> relatedFrameKeys;

    EvidenceConfidence confidence = EvidenceConfidence::kInputIncomplete;
    ExceptionMatchResult exception;
    std::vector<std::string> coverageGapKeys;
    CollectionOutcome inputOutcome;

    // Exception hit results remain in the list (for verification) but are not counted in the "unexplained" total.
    bool explainedByException() const noexcept;
};

// ---------------------------------------------------------------------------
// Observation semantics table (Issue Section 6).
// ---------------------------------------------------------------------------

enum class ObservationClass {
    kPrivateOrMappedExecutablePresent,   // Private RX/RWX (or mapped executable) present.
    kNormalizedImageDiffers,             // Code still differs from the trusted reference after normalization.
    kPayloadStructureWithReliableFrame,  // Self-consistent payload structure + reliable stack frame entry into it.
    kMappedModuleOutsideBaseline,        // Normally mapped DLL does not match the trusted application baseline
    kVadTreeLinkageInconsistent,         // The VAD tree's own links are inconsistent (evidence of unlinking).
    kScanCompleteNoStrongEvidence,       // Scan completed but no strong evidence found
    kKeyInputUnavailable,                // Critical page/thread/reference file unavailable
};

const char* observationClassName(ObservationClass observation) noexcept;

// What an observation can and cannot conclude. Both keys are i18n keys; the UI must display
// 'conclusions that cannot be drawn' as well—otherwise users may misinterpret 'not checked' as 'none'.
struct ObservationSemantics final {
    ObservationClass observation = ObservationClass::kKeyInputUnavailable;
    const char* allowedConclusionKey = "";
    const char* forbiddenConclusionKey = "";
    AnalysisConclusion contribution = AnalysisConclusion::kNoEvidence;
};

ObservationSemantics semanticsFor(ObservationClass observation) noexcept;

// ---------------------------------------------------------------------------
// Identity recheck
// ---------------------------------------------------------------------------

enum class IdentityRecheckVerdict {
    kSame,
    kChanged,        // Exit, rebuild, or PID reuse — evidence may be linked to another process.
    kUnverifiable,   // Insufficient identity information
};

const char* identityRecheckVerdictName(IdentityRecheckVerdict verdict) noexcept;

IdentityRecheckVerdict recheckProcessIdentity(const ProcessInstanceId& before,
                                              const ProcessInstanceId& after) noexcept;

// ---------------------------------------------------------------------------
// Coverage gap key
// ---------------------------------------------------------------------------

extern const char* const kGapAddressSpaceIncomplete;   // inject.gap.address-space
extern const char* const kGapLoaderViewUnavailable;    // inject.gap.loader-view
extern const char* const kGapImageViewUnavailable;     // inject.gap.image-view
extern const char* const kGapPayloadViewUnavailable;   // inject.gap.payload-view
extern const char* const kGapMappedPathUnavailable;    // inject.gap.mapped-path
extern const char* const kGapWorkingSetUnavailable;    // inject.gap.working-set
extern const char* const kGapThreadStartUnavailable;   // inject.gap.thread-start
extern const char* const kGapReferenceUncertain;       // inject.gap.reference-uncertain
extern const char* const kGapBudgetTruncated;          // inject.gap.budget-truncated
extern const char* const kGapIdentityChanged;          // inject.gap.identity-changed
extern const char* const kGapIdentityUnverifiable;     // inject.gap.identity-unverifiable
extern const char* const kGapModuleEnumerationWow64;   // inject.gap.module-enum-wow64
extern const char* const kGapMainImageSourceMissing;   // inject.gap.main-image-source
extern const char* const kGapKernelBackendUnavailable; // inject.gap.kernel-backend
extern const char* const kGapKernelProfileUnverified;  // inject.gap.kernel-profile
// The VAD backend scan completed, but the tree traversal was truncated, resumed, or some nodes were unreadable; thus, the broken-link criterion does not hold.
extern const char* const kGapVadLinkUncheckable;       // inject.gap.vad-link-uncheckable
// Uses section objects as references, but some pages are inaccessible (prototype PTEs are not in a valid state). Differences
// are still counted, but 'no difference found' cannot be concluded—pages that weren't compared are not considered compared.
extern const char* const kGapSectionReferenceIncomplete; // inject.gap.section-reference
// Stack walking was performed, but the context for at least one thread is not fully trusted (all are running). This represents "intended
// to check but failed," not "not implemented in this version"—the latter is kLimitStackUnwindUnavailable; do not confuse the two.
extern const char* const kGapStackWalkUntrusted;       // inject.gap.stack-untrusted

// ---------------------------------------------------------------------------
// Capability limit keys: These are **two distinct categories** from coverage gaps and must not be mixed in the same table.
// ---------------------------------------------------------------------------
//
//   * Coverage gap (the group above) = "I intended to check something but failed": page read
//     failure, thread retrieval failure, reference file mismatch, budget truncation, or identity
//     doubt. It **must** suppress "no differences found" — the declared range itself is invalid.
//   * Capability limits (this group) = "This version does not do this at all": No CLR runtime attribution, no recognition of
//     header-erased payloads, and no reliable stack unwind backend. It **does not suppress** conclusions, only narrows their scope.
//
// Why they must be separated: Treating capability limits as gaps means every process and every scan is perpetually 'incompletely
// covered'. This degrades the four states of AnalysisConclusion in production to three, making it impossible to distinguish between
// 'scanned and found nothing within scope' and 'scan failed entirely'—precisely the distinction the gap dimension aims to preserve.
extern const char* const kLimitNonExecutableNotScanned;  // inject.limit.non-executable
extern const char* const kLimitStackUnwindUnavailable;   // inject.limit.stack-unwind
// This version identifies payload structures only by the remaining PE header; payloads with erased headers cannot be recognized.
extern const char* const kLimitPayloadHeaderErased;      // inject.limit.payload-erased-header
// This version does not perform runtime attribution for CLR, etc. Empirical test (2026-09-12, deep scan of pwsh.exe):
// There is a 9-byte in-place rewrite on System.Management.Automation.dll; the normalization comparison reports it as an
// 'unexplained difference' exactly as-is. The comparison engine is correct, but the runtime view lacks an explanation. Therefore,
// this item must be explicitly listed; otherwise, users will misinterpret a normal managed runtime rewrite as injection evidence.
extern const char* const kLimitRuntimeAttribution;       // inject.limit.runtime-attribution
// Kernel collection relies on kernel trust: an adversary with kernel capabilities can modify the metadata or reference pages read here.
// If kernel views are used, always enforce this constraint—never claim 'drivers cannot hide'.
extern const char* const kLimitKernelTrustAssumption;    // inject.limit.kernel-trust
// MMVAD_FLAGS bit layout is not build-verified, so VAD protection attributes are excluded from conflict detection.
extern const char* const kLimitKernelVadFlagsUnverified; // inject.limit.kernel-vad-flags
// Layer 3 (comparing process image pages with reference pages from the Image Section Object) is not implemented in this version.
extern const char* const kLimitKernelSectionCompare;     // inject.limit.kernel-section-compare
// The **valid cause directory** for kernel cross-differences has not yet been established on real-machine data. Until established, such
// differences are treated only as "pending explanation" and do not escalate to DifferenceObserved — no measurement means no certainty.
extern const char* const kLimitKernelBenignBaseline;     // inject.limit.kernel-benign-baseline
// This machine has no KswordARK device. This is a **capability limitation**, not a coverage gap: we never claimed to
// support kernel views on a machine without the driver. Treating it as a gap would make scopeIntact always false for
// every scan, reducing the four-state model to three states—similar to the logic behind kLimitNonExecutableNotScanned.
// A real vulnerability exists only if the driver is present but a specific call fails (due to permissions or unverified profile).
extern const char* const kLimitKernelBackendAbsent;      // inject.limit.kernel-backend-absent

// Keys for completed and pending checks. The termination condition for fast mode is
// expressed using these two tables, rather than a single Injected/Clean boolean.
extern const char* const kCheckAddressSpaceIndex;      // inject.check.address-space
extern const char* const kCheckModuleCrossView;        // inject.check.module-cross-view
extern const char* const kCheckWorkingSetScreen;       // inject.check.working-set
extern const char* const kCheckThreadStart;            // inject.check.thread-start
extern const char* const kCheckNormalizedImageDiff;    // inject.check.image-diff
extern const char* const kCheckPayloadStructure;       // inject.check.payload-structure
extern const char* const kCheckNonExecutableScan;      // inject.check.non-executable
extern const char* const kCheckReliableStackWalk;      // inject.check.stack-walk
extern const char* const kCheckKernelVadCrossView;     // inject.check.kernel-vad
extern const char* const kCheckVadLinkIntegrity;       // inject.check.vad-link
extern const char* const kCheckKernelPteScan;          // inject.check.kernel-pte

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

struct SurveyInput final {
    SurveyMode mode = SurveyMode::kFast;
    std::string detectorVersion;

    // Process identity must be captured once before and once after the scan. Since PID is a weak identity, verification
    // results will be Unverifiable; in this case, the conclusion must not be elevated to NoDifferenceObserved.
    ProcessInstanceId processBefore;
    ProcessInstanceId processAfter;
    OptionalU64 collectedUtc100ns;

    ProcessArchitecture targetArchitecture = ProcessArchitecture::kUnknown;
    CollectorArchitecture collectorArchitecture = CollectorArchitecture::kUnknown;

    // Target program version identity (primary image identity string). Exception rules must be bound to it—a
    // write-only exemption like 'allow modifying these bytes in ntdll' would apply to all programs if not bound to
    // the target version. An empty string indicates the value was not retrieved; in this case, no exceptions match.
    std::string targetImageIdentity;

    AddressSpaceIndex addressSpace;
    ModuleCrossViewReport moduleCrossView;

    std::vector<ThreadStartFinding> threadStarts;
    CollectionOutcome threadEnumerationOutcome;

    bool workingSetQueried = false;
    CollectionOutcome workingSetOutcome;
    std::size_t workingSetPagesScreened = 0;
    std::size_t workingSetPrivatizedPages = 0;
    std::size_t workingSetInvalidPages = 0;

    std::vector<ImageComparisonOutcome> imageComparisons;
    // Number of planned comparison targets not executed in this round. >0 indicates a coverage gap.
    std::size_t plannedComparisonsNotRun = 0;

    std::vector<PayloadCandidateEntry> payloadCandidates;

    // Cross-view results from the R0 scanning backend. Default is all NotRequested — if no driver is present, the
    // entire section is silently skipped, leaving no gaps ('not intended to use' is not 'intended to use but failed').
    KernelCrossViewReport kernelCrossView;
    KernelBackendState kernelVadState = KernelBackendState::kNotRequested;
    KernelBackendState kernelPteState = KernelBackendState::kNotRequested;

    // Stack collection results for each thread. Empty means stack backtracing was not performed in this round (due to capability limits, not a gap).
    //
    // There is **no** reliableStackWalkAvailable boolean switch here; this is intentional:
    // "Reliable unwind available" is one of the three gates for elevating the conclusion. Making it a directly assignable
    // field would create a backdoor to bypass admitStackFrames. It must be derived solely from the contents of this vector.
    std::vector<ThreadStackInput> threadStacks;
    // Whether non-executable memory was scanned in deep mode. Since payloads may be dormant without execute permissions,
    // 'scanning only pages with current execute permissions' is a gap that must be explicitly recorded in deep mode.
    bool nonExecutableMemoryScanned = false;

    std::vector<ExceptionRelation> exceptions;
    BudgetStop budgetStop = BudgetStop::kContinue;

    // Extra coverage gaps observed by the collector ("intended to check but failed"). This suppresses "no differences found".
    std::vector<std::string> extraCoverageGapKeys;
    // Collector's self-reported capability limits ("this version does not do this"). Listed but do not suppress conclusions.
    std::vector<std::string> extraCapabilityLimitKeys;
};

struct SurveyReport final {
    SurveyMode mode = SurveyMode::kFast;
    std::string detectorVersion;
    std::uint32_t ruleSetVersion = kInjectionSurveyRuleSetVersion;

    ProcessInstanceId process;
    OptionalU64 firstObservedUtc100ns;
    IdentityRecheckVerdict identity = IdentityRecheckVerdict::kUnverifiable;

    std::vector<InjectionFinding> findings;
    std::vector<ObservationClass> observations;

    std::vector<std::string> coverageGapKeys;      // Intended to check but failed to complete — suppress conclusion
    std::vector<std::string> capabilityLimitKeys;  // Not implemented in this version — only narrows the scope.
    std::vector<std::string> completedCheckKeys;
    std::vector<std::string> notPerformedCheckKeys;

    std::size_t dynamicCodeRegionCount = 0;
    std::size_t unexplainedImageDiffCount = 0;
    std::size_t exceptionExplainedCount = 0;
    std::size_t threadStartAnomalyCount = 0;
    std::size_t moduleCrossIssueCount = 0;      // All cross-view issues.
    std::size_t moduleCrossConflictCount = 0;   // Among the 'conflict' files, only this one can elevate the conclusion.
    std::size_t kernelCrossIssueCount = 0;      // Differences among the R3, VAD, and page-table views.
    // A self-consistent payload structure with a reliably unwound frame entering it. Only this can support
    // DifferenceObserved alongside normalized differences and cross-view contradictions; structure alone is insufficient.
    std::size_t payloadWithExecutionCount = 0;

    // Stack backtrace accounting. Track these three numbers separately as they answer different questions:
    //   walked —— attempted to unwind several threads (0 means no attempt was made in this round)
    //   trusted —— among those, how many had trusted contexts and actually produced reliable
    //   prefixes frames —— total number of frames in the reliable prefix (before deduplication)
    // "large walked but trusted is 0" indicates a gap, not "all threads are normal".
    // Count of VAD tree link inconsistencies. Counted separately and not merged into kernelCrossIssueCount—the
    // latter asks 'do the two views agree?', while this asks 'is this tree internally consistent?'.
    // Use section objects (rather than disk files) as the reference for the number of comparisons performed.
    std::size_t sectionReferenceComparisons = 0;
    std::size_t vadLinkIssueCount = 0;
    VadLinkIntegrity vadLinkIntegrity = VadLinkIntegrity::kNotChecked;

    std::size_t stackThreadsWalked = 0;
    std::size_t stackThreadsTrusted = 0;
    std::size_t stackReliableFrameCount = 0;

    CoverageAccount coverage;
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;

    // Coverage completeness and conclusion are two distinct dimensions.
    //   * scopeIntact: Declares whether the checked scope remains intact. When
    //     false, conclusion can never be NoDifferenceObserved — this is a hard gate.
    //   * coverageComplete: "Nothing missing" including capability restrictions. It is stricter than scopeIntact and
    //     used for display only; using it as a gate would prevent the conclusion from ever reaching NoDifferenceObserved.
    bool scopeIntact = false;
    bool coverageComplete = false;

    bool hasObservation(ObservationClass observation) const noexcept;
    bool hasGap(const std::string& gapKey) const noexcept;
    bool hasLimit(const std::string& limitKey) const noexcept;
};

SurveyReport runInjectionSurvey(const SurveyInput& input);

} // namespace ksword::evidence

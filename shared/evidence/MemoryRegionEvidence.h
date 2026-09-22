#pragma once

// M module: region evidence model, partial read ledger, executable region clues, and pool attribution boundaries.
//
// Corresponding acceptance criteria.
//   M-01 Region information semantics (fields separated by source; do not display 'VAD verified' if VAD was not traversed).
//   M-02: safe read with partial results (holes must be holes; do not mix full success with partial success).
//   M-07: Executable region clues (list facts item by item; do not judge maliciousness based on a single attribute)
//   M-09 Kernel pool attribution boundaries (direct evidence/candidate/unknown tiers; no call stack generated)
//   M-10 Scan budget (range validation and budget stop reuse ScanBudget.h; do not create additional criteria).
//
// This layer lacks malicious/threat/score fields and callStack fields—not due to oversight, but by specification:
// a single attribute can only yield a clue, and without a pre-collected allocation stack, it must be unknown.

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"
#include "ScanBudget.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// M-01: Region information semantics.
// ---------------------------------------------------------------------------
enum class RegionState {
    kUnknown,
    kFree,
    kReserved,
    kCommit,
};

const char* regionStateName(RegionState state) noexcept;

enum class RegionType {
    kUnknown,
    kPrivate,
    kMapped,
    kImage,
};

const char* regionTypeName(RegionType type) noexcept;

// Source of the region record. R3 VirtualQuery and R0 VAD walk are independent evidence streams;
// they must be distinguished in the same table and cannot be merged into a single 'memory region'.
enum class RegionEvidenceSource {
    kR3VirtualQuery,   // User-mode query: Available but cannot see VAD layer facts.
    kR0VadWalk,        // Kernel VAD walk: Requires a validated profile.
    kOfflineSnapshot,  // Region records from a saved session or dump.
};

const char* regionEvidenceSourceName(RegionEvidenceSource source) noexcept;

struct RegionProtection final {
    bool readable = false;
    bool writable = false;
    bool executable = false;
    bool copyOnWrite = false;
    bool guard = false;
    bool noAccess = false;
    OptionalU64 rawValue;  // Raw PAGE_* value; if the source is not provided, it is unset (do not pad with 0).
};

// VAD-side evidence. Only allowed to fill if VAD was actually traversed, and must record which profile was used (M-06 boundary).
struct VadEvidence final {
    OptionalU64 vadNodeAddress;
    OptionalU64 startingVpn;
    OptionalU64 endingVpn;
    OptionalU64 vadFlagsRaw;
    std::string profileId;          // Empty indicates no verifiable profile.
    bool profileVerified = false;   // profile matches the current kernel and has been verified

    // All four key fields must be present and the profile must be verified for this VAD evidence to be considered usable.
    bool complete() const noexcept;
};

struct RegionRecord final {
    OptionalU64 base;
    OptionalU64 size;
    RegionState state = RegionState::kUnknown;
    RegionType type = RegionType::kUnknown;
    RegionProtection protection;
    OptionalU64 allocationBase;
    RegionProtection allocationProtect;
    std::string mappedPath;         // Null indicates 'source not provided', not 'private memory'.
    RegionEvidenceSource source = RegionEvidenceSource::kR3VirtualQuery;

    VadEvidence vad;
    ProcessInstanceId owner;
    std::string evidenceId;         // Points back to the envelope that generated this line.
};

// M-01 hard rule: Never output "VAD verified" if the VAD was not traversed.
// The VAD field alone is insufficient — the source must be R0VadWalk, and the profile must be verified.
bool vadVerified(const RegionRecord& record) noexcept;

// The address range of the region. Returns false if base or size is missing (do not use 0 as a placeholder).
bool regionRange(const RegionRecord& record, AddressRange& out) noexcept;

// ---------------------------------------------------------------------------
// M-02: Safe read with partial results.
// ---------------------------------------------------------------------------

// Maximum span for a single read. Allocation is rejected if exceeded to prevent consuming the entire RAM (M-10) just to complete a progress bar.
constexpr std::uint64_t kMaxReadSpanBytes = 64ULL * 1024ULL * 1024ULL;

// ReadSpan splits 'read bytes' and 'positions that were not read at all' into two separate arrays.
// When present is false, the values in bytes are meaningless; no caller may treat them as
// data. Treating them as data after padding with zeros is explicitly prohibited by M-02.
struct ReadSpan final {
    AddressRange range;
    std::vector<std::uint8_t> bytes;
    std::vector<bool> present;
    CollectionOutcome outcome;
    // M-05: This byte indicates when the data was read. If unset, the source timestamp is unrecorded, meaning we cannot prove it belongs to the
    // same atomic observation as other segments. During merging, it must be downgraded and never assumed to be at the same timestamp by default.
    OptionalU64 observedUtc100ns;

    bool consistent() const noexcept;          // The three lengths are self-consistent.
    std::uint64_t presentCount() const noexcept;
    bool hasHole() const noexcept;
};

// Create an empty span with full holes based on the range. If the length is 0 or exceeds
// kMaxReadSpanBytes, return an empty span with outcome=Error without performing any allocation.
ReadSpan makeEmptyReadSpan(const AddressRange& range);

// Write the actual bytes read into the span and mark them as present. Return false without writing if out of bounds.
bool applyReadChunk(ReadSpan& span,
                    std::uint64_t address,
                    const std::uint8_t* data,
                    std::size_t length);

// Fetch a single byte. Return false for holes—callers cannot obtain "0", so they won't mistake it for data.
bool byteAt(const ReadSpan& span, std::uint64_t address, std::uint8_t& out) noexcept;

// M-02: Precise range of holes (maximal contiguous segments). Returns empty if fully readable.
std::vector<AddressRange> describeHoles(const ReadSpan& span);

// Determine collection status based on hole conditions: Success if fully read, Partial if holes exist,
// Error if nothing read and no more specific error. Full success and partial success are never mixed.
CollectionStatus classifyReadSpan(const ReadSpan& span) noexcept;

// F-06 ledger: request range, success/failure byte counts. Gaps go to failed, not succeeded.
CoverageAccount buildReadCoverage(const ReadSpan& span);

// M-05: Temporal relationship between multiple observation segments. Success is allowed only if it can be proven that they originate from the same observation.
enum class MergeObservationTiming {
    kSingleObservation,       // Only one input segment, or all inputs share the same recorded collection timestamp.
    kMultipleObservations,    // Input originates from two or more distinct collection timestamps.
    kObservationTimeUnknown,  // If at least one segment in the multi-segment input lacks a recorded timestamp, simultaneity cannot be proven.
};

const char* mergeObservationTimingName(MergeObservationTiming timing) noexcept;

// Merge multiple spans. The pass condition for M-05 is 'not wrapping observations from two different times into an atomic snapshot'; thus, the
// criterion is the **collection timestamp**, not the byte values: two segments having identical bytes does not prove they were read simultaneously.
struct MergedReadSpan final {
    ReadSpan span;
    std::vector<AddressRange> conflictingRanges;
    // The collection timestamp for each byte, matching the length of span.bytes; holes or locations where the source timestamp is unrecorded are unset.
    // M-05 requires "time-sliced recording", so source timestamps must be preserved segment-by-segment rather than discarded after merging.
    std::vector<OptionalU64> byteObservedUtc100ns;
    MergeObservationTiming timing = MergeObservationTiming::kSingleObservation;
};

// spans are passed in read order; conflicting bytes retain the last (newer) value and are recorded in conflictingRanges.
// If timing is not SingleObservation, the result is never Success—even if no bytes conflicted.
MergedReadSpan mergeReadSpans(const std::vector<ReadSpan>& spans);

// ---------------------------------------------------------------------------
// M-02 + M-10: bounded read.
// ---------------------------------------------------------------------------

// Result of a single chunked read. F-05: Failures must return the original error code — when only the number of
// bytes copied is returned, STATUS_ACCESS_DENIED, target process exit, and unreadable pages appear identical.
struct ChunkReadResult final {
    std::size_t copied = 0;   // Actual number of bytes copied; 0 < copied < bytes is valid and common.
    CollectionStatus status = CollectionStatus::kNotCollected;
    OptionalU64 nativeCode;         // Original NTSTATUS / Win32 / HRESULT value; unset if unknown.
    std::string nativeCodeDomain;   // "NTSTATUS" / "WIN32" / "HRESULT" / ""
    std::string message;            // Original text from the source, not an explanation we generated.
};

// Chunked read callback. The `copied` field expresses the real driver's "partial copy" semantics (not just
// success/failure states); other fields return failure reasons as-is for `readRangeBounded` to write into the outcome.
using ChunkReader = std::function<void(std::uint64_t address,
                                       std::uint8_t* out,
                                       std::size_t bytes,
                                       ChunkReadResult& result)>;

struct BoundedReadRequest final {
    AddressRange requested;
    AddressRange approved;             // User-approved range; length==0 indicates no limit.
    ScanBudget budget;
    std::uint64_t chunkSize = 0x1000;  // Chunk by page; page boundaries are therefore guaranteed to be covered.
    OptionalU64 observedUtc100ns;      // Write the collection timestamp of this run directly into the span (M-05).

    // Optional: delegate 'elapsed time' and 'cancellation status' to the caller for injection, avoiding clock or thread
    // dependencies at this layer, and enabling offline tests to deterministically trigger time budgets and cancellations.
    std::function<std::uint64_t()> elapsedNanos;
    std::function<bool()> cancelRequested;
};

// M-10: Rejection levels specific to readRangeBounded. RangeValidation is defined in ScanBudget.h, which lacks the "exceeds
// single-span limit" and "no budget" levels; treating them as Ok would mislead the caller into thinking "valid range,
// budget not hit, completed normally." Therefore, these two levels are expressed in this module's own return structure.
enum class BoundedReadRejection {
    kNone,
    kInvalidRange,     // validateRange rejected; see BoundedReadResult::validation for the specific reason.
    kReversedRange,    // In the (begin, end) entry, end < begin.
    kExceedsMaxSpan,   // Request span exceeds kMaxReadSpanBytes.
    kNoBudget,         // request.budget: no upper limit set.
};

const char* boundedReadRejectionName(BoundedReadRejection rejection) noexcept;

struct BoundedReadResult final {
    ReadSpan span;
    CoverageAccount coverage;
    RangeValidation validation = RangeValidation::kOk;
    // When rejection != None, no bytes are read; at this point, stop remaining as
    // Continue is meaningless. The caller must check rejection first, then stop.
    BoundedReadRejection rejection = BoundedReadRejection::kNone;
    BudgetStop stop = BudgetStop::kContinue;
};

// Reject invalid ranges, spans exceeding the limit, or requests without budget; read zero bytes.
// Stop within the valid range based on the budget and retain the completed portion.
BoundedReadResult readRangeBounded(const BoundedReadRequest& request, const ChunkReader& reader);

// M-10: Entry in (begin, end) form. AddressRange uses (begin, length), so reversed ranges cannot exist in that
// representation; thus, 'reversed' can only be checked and explicitly rejected in this entry accepting 'end'. Here, we check
// and reject. request.requested is overridden by begin/end; other fields (budget, block size, callback) are used as-is.
BoundedReadResult readRangeBoundedFromEndpoints(std::uint64_t begin,
                                                std::uint64_t end,
                                                const BoundedReadRequest& request,
                                                const ChunkReader& reader);

// ---------------------------------------------------------------------------
// M-09: Three attribution levels. The attribution field in M-07 also uses this set.
// ---------------------------------------------------------------------------
enum class OwnerAttribution {
    kDirectEvidence,  // Contains pre-collected direct evidence such as allocation events or mapping objects.
    kCandidate,       // Only indirect clues like tag and range hits.
    kUnknown,         // No available evidence means unknown; do not downgrade to 'System' or 'Unknown Driver'.
};

const char* ownerAttributionName(OwnerAttribution attribution) noexcept;

// pool tag -> known users. It is common for the same tag to be used by multiple components, so this is a multi-value map.
struct PoolTagOwnerEntry final {
    std::string tag;
    std::string ownerId;      // Normalized driver/component identifier
    std::string sourceNote;   // Note: Origin of this mapping itself (knowledge base version / local symbols).
};

struct PoolAttributionResult final {
    OwnerAttribution attribution = OwnerAttribution::kUnknown;
    std::vector<std::string> candidateOwners;  // When in Candidate mode, list all candidates, not just one.
    std::vector<std::string> facts;            // Individual facts traceable to their sources.
    // Allocation stacks are available only if collected beforehand. This is solely an
    // availability fact; this module exposes no entry point to generate a call stack (M-09).
    bool allocationStackAvailable = false;
};

// Rule M-09: A tag match can only be a Candidate, even if the table contains only one owner.
PoolAttributionResult attributeByTag(const std::string& tag,
                                     const std::vector<PoolTagOwnerEntry>& knownTagOwners);

// Pre-collected allocation events. If captured is false, none exist; do not construct them.
struct PoolAllocationEvent final {
    bool captured = false;
    DriverInstanceId allocator;
    OptionalU64 eventUtc100ns;
    std::string eventSourceId;  // Collector ID, e.g., "etw.pool.alloc"
};

// DirectEvidence is only possible with a pre-collected allocation event; otherwise, fall back to the tag level.
PoolAttributionResult attributeByAllocationEvent(const PoolAllocationEvent& event,
                                                 const PoolAttributionResult& tagFallback);

// ---------------------------------------------------------------------------
// M-07: Executable region clues.
// ---------------------------------------------------------------------------

// Byte comparison result against the disk image. If no comparison was performed, it remains 'not performed' and cannot be substituted with 'no difference'.
struct ImageBytesComparison final {
    bool compared = false;
    CollectionOutcome outcome;
    std::string onDiskPath;
    std::vector<AddressRange> differingRanges;  // Exact differing ranges in virtual addresses.
    // Without relocation/import-table/hotpatch normalization, differences include legitimate changes and are only leads.
    bool relocationsApplied = false;
};

// Thread start address fact. startAddress is unset if unknown.
struct ThreadStartFact final {
    ThreadInstanceId thread;
    OptionalU64 startAddress;
    bool startAddressInsideRegion = false;
    std::string startAddressMappedPath;  // Empty indicates unknown ownership, not 'no ownership'.
};

struct ExecutableRegionInput final {
    RegionRecord region;
    ImageBytesComparison imageComparison;
    std::vector<ThreadStartFact> threads;
    // Whether direct evidence of region ownership (e.g., section object or mapped file handle) was obtained.
    bool regionOwnerKnown = false;
};

// Output for a single rule. Note: no malicious/score fields here; rules only report facts.
struct ExecutableRegionFinding final {
    std::string ruleId;
    std::uint32_t ruleVersion = 0;
    std::vector<std::string> facts;   // Actual facts the rule is based on, key=value, with source traceability.
    OwnerAttribution attribution = OwnerAttribution::kUnknown;
    std::vector<std::string> candidateOwners;
    CollectionOutcome inputOutcome;   // This rule depends on the input collection status.
};

struct ExecutableRegionReport final {
    std::uint32_t ruleSetVersion = 1;
    std::vector<ExecutableRegionFinding> findings;
    OwnerAttribution attribution = OwnerAttribution::kUnknown;
    // Only when comparison has been performed and completed can the result be DifferenceObserved or NoDifferenceObserved.
    // Pure private RX only reaches Indeterminate (clues exist, but insufficient for a definitive conclusion).
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;
};

// Rule ID constants for stable reference by UI and export.
extern const char* const kRuleIdPrivateExecutable;      // mem.exec.private
extern const char* const kRuleIdImageBytesDiffer;       // mem.exec.image-bytes-differ
extern const char* const kRuleIdThreadOriginMismatch;   // mem.exec.thread-origin-mismatch
// F-05: The start address was never collected, meaning 'no observation', not 'mismatched ownership'. Using the same ruleId
// for both causes a finding with zero observations to incorrectly elevate the conclusion from NoEvidence to Indeterminate.
extern const char* const kRuleIdThreadOriginUnknown;    // mem.exec.thread-origin-unknown

ExecutableRegionReport evaluateExecutableRegion(const ExecutableRegionInput& input);

} // namespace ksword::evidence

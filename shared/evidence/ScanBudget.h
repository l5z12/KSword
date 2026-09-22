#pragma once

// F-10: Decouple from concurrency; M-10: Scan budget; F-09: Session data separated from live evidence.
//
// Pure policy only: no threads, Qt, or Win32. Task IDs are monotonic; old results are not backfilled; budget hit triggers immediate stop while
// retaining partial results; invalid ranges are rejected directly. UI thread models are implemented separately, sharing this single set of criteria.

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"

#include <cstdint>
#include <string>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// F-10: Only the latest request is accepted in the same view.
// ---------------------------------------------------------------------------
enum class TaskState {
    kPending,
    kRunning,
    kCancelling,   // Cancellation requested; background cleanup continues within safety bounds (do not falsely report cleared).
    kCancelled,
    kCompleted,
    kFailed,
};

const char* taskStateName(TaskState state) noexcept;

// States other than terminal indicate background may still hold resources.
bool taskStateIsTerminal(TaskState state) noexcept;

// LatestRequestGate: For a view. Generation is monotonically increasing; only the latest generation's results are
// allowed to be backfilled. Late-arriving older results are discarded (A completing after B does not overwrite B).
class LatestRequestGate final {
public:
    // Start a new request and return the current generation.
    std::uint64_t begin() noexcept { return ++generation_; }

    std::uint64_t current() const noexcept { return generation_; }

    // Ask once when results return: Is this the latest generation?
    bool accepts(std::uint64_t generation) const noexcept { return generation == generation_; }

    // Cancel current request: increment generation; any in-flight results are no longer accepted.
    void cancelCurrent() noexcept { ++generation_; }

private:
    std::uint64_t generation_ = 0;
};

// ---------------------------------------------------------------------------
// M-10: Scan range and budget.
// ---------------------------------------------------------------------------
enum class RangeValidation {
    kOk,
    kEmptyRange,        // begin == end
    kReversed,          // begin > end
    kOverflow,          // begin + length overflows 64-bit.
    kExceedsApproved,   // Exceeds the user-approved range
};

const char* rangeValidationName(RangeValidation validation) noexcept;

struct AddressRange final {
    std::uint64_t begin = 0;
    std::uint64_t length = 0;
    // M-10: Set when the (begin, end) entry is detected with end < begin. When expressing a range as (begin,
    // length), the caller calculating length can wrap the reversed order into a valid small length, making Reversed
    // impossible to generate. This bit carries the "user provided reversed" state directly to validateRange.
    bool reversed = false;

    bool endAddress(std::uint64_t& out) const noexcept;  // Returns false on overflow or reverse order.

    // Endpoint construction. If end < begin, mark as reversed (length remains 0), and validateRange reports Reversed.
    // end == begin indicates an empty range; validateRange reports EmptyRange.
    static AddressRange fromBeginEnd(std::uint64_t begin, std::uint64_t end) noexcept;
};

// approved.length == 0 means "the caller did not restrict to a specific range". This does not equal "allow scanning the full 64-bit address
// space": when no approved window exists, a single request still has a hard ceiling on length; exceeding it results in ExceedsApproved.
inline constexpr std::uint64_t kUnapprovedScanCeilingBytes = 1ULL << 32;  // 4 GiB

// An empty approved length indicates 'no restriction to a specific range', triggering self-validity checks plus the upper ceiling.
RangeValidation validateRange(const AddressRange& request, const AddressRange& approved) noexcept;

// ScanBudget: three independent limits for bytes, pages, and time; stops and retains completed portion upon any limit hit.
struct ScanBudget final {
    OptionalU64 maxBytes;
    OptionalU64 maxPages;
    OptionalU64 maxItems;
    OptionalU64 maxDurationNanos;

    // No flags set implies unbounded — this should never occur in production paths; constructors must explicitly set an upper limit.
    bool bounded() const noexcept;
};

enum class BudgetStop {
    kContinue,
    kBytesExhausted,
    kPagesExhausted,
    kItemsExhausted,
    kTimeExhausted,
    kCancelled,
};

const char* budgetStopName(BudgetStop stop) noexcept;

// Scan progress. Update after processing each batch; when the limit is hit, shouldStop() provides the specific reason.
struct ScanProgress final {
    std::uint64_t bytesDone = 0;
    std::uint64_t pagesDone = 0;
    std::uint64_t itemsDone = 0;
    std::uint64_t elapsedNanos = 0;
    bool cancelRequested = false;
};

BudgetStop evaluateBudget(const ScanBudget& budget, const ScanProgress& progress) noexcept;

// Translate the result of a bounded scan into F-06 accounting: hitting the limit maps to Partial + limitHit.
CollectionOutcome outcomeForStop(BudgetStop stop) noexcept;
void applyStopToCoverage(BudgetStop stop, const ScanBudget& budget, CoverageAccount& coverage);

// ---------------------------------------------------------------------------
// F-09: Offline sessions and live data are separated.
// ---------------------------------------------------------------------------
enum class DataOrigin {
    kLive,     // Current live collection, replaceable by new snapshots.
    kSession,  // Saved session; prevent background refresh from overwriting it.
};

// Judgment upon arrival at the live refresh: session data is never allowed to be overwritten, while live data only accepts updated snapshots.
enum class RefreshDecision {
    kApply,
    kRejectSessionIsImmutable,
    kRejectStaleSnapshot,
    kRejectNotLatestRequest,
};

const char* refreshDecisionName(RefreshDecision decision) noexcept;

RefreshDecision decideRefresh(DataOrigin origin,
                              std::uint64_t currentSnapshotId,
                              std::uint64_t incomingSnapshotId,
                              bool isLatestRequest) noexcept;

// F-09: Offline result navigation to the current site must explicitly re-verify object identity.
enum class LiveNavigationDecision {
    kAllow,              // Present on-site and identity confirmed consistent
    kRejectObjectExited, // Object has exited.
    kRejectIdentityMismatch,  // Same PID/address but identity mismatch (PID reuse).
    kRejectIdentityUnverifiable,  // Identity information is insufficient for verification.
};

const char* liveNavigationDecisionName(LiveNavigationDecision decision) noexcept;

} // namespace ksword::evidence

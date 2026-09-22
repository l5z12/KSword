#include "ScanBudget.h"

#include <limits>

namespace ksword::evidence {

const char* taskStateName(TaskState state) noexcept {
    switch (state) {
    case TaskState::kPending:    return "Pending";
    case TaskState::kRunning:    return "Running";
    case TaskState::kCancelling: return "Cancelling";
    case TaskState::kCancelled:  return "Cancelled";
    case TaskState::kCompleted:  return "Completed";
    case TaskState::kFailed:     return "Failed";
    }
    return "Pending";
}

bool taskStateIsTerminal(TaskState state) noexcept {
    return state == TaskState::kCancelled || state == TaskState::kCompleted || state == TaskState::kFailed;
}

const char* rangeValidationName(RangeValidation validation) noexcept {
    switch (validation) {
    case RangeValidation::kOk:              return "Ok";
    case RangeValidation::kEmptyRange:      return "EmptyRange";
    case RangeValidation::kReversed:        return "Reversed";
    case RangeValidation::kOverflow:        return "Overflow";
    case RangeValidation::kExceedsApproved: return "ExceedsApproved";
    }
    return "Ok";
}

bool AddressRange::endAddress(std::uint64_t& out) const noexcept {
    if (reversed) {
        return false;  // No meaningful end address in the reverse range.
    }
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint64_t>::max)();
    if (length > kMax - begin) {
        return false;
    }
    out = begin + length;
    return true;
}

AddressRange AddressRange::fromBeginEnd(std::uint64_t begin, std::uint64_t end) noexcept {
    AddressRange range;
    range.begin = begin;
    if (end < begin) {
        // M-10: Do not use the wraparound result of (end - begin) as the length; that would disguise a 'reversed' range
        // as a valid huge range or Overflow. Record the reversed state as-is, and let validateRange report Reversed.
        range.reversed = true;
        range.length = 0U;
        return range;
    }
    range.length = end - begin;
    return range;
}

RangeValidation validateRange(const AddressRange& request, const AddressRange& approved) noexcept {
    // Reverse order is checked before empty range validation: a reversed range has length 0; otherwise, it would be falsely reported as EmptyRange.
    if (request.reversed) {
        return RangeValidation::kReversed;
    }
    if (request.length == 0U) {
        return RangeValidation::kEmptyRange;
    }
    std::uint64_t requestEnd = 0U;
    if (!request.endAddress(requestEnd)) {
        return RangeValidation::kOverflow;
    }
    if (approved.reversed) {
        return RangeValidation::kReversed;  // The approval window itself is reversed
    }
    if (approved.length == 0U) {
        // M-10: Unrestricted approved range does not equal permission to scan all RAM. Without a window, the ceiling for a single request is still
        // enforced; otherwise, a request like {begin=0, length=MAX} (scanning the entire 64-bit address space) would incorrectly pass validation.
        if (request.length > kUnapprovedScanCeilingBytes) {
            return RangeValidation::kExceedsApproved;
        }
        return RangeValidation::kOk;
    }
    std::uint64_t approvedEnd = 0U;
    if (!approved.endAddress(approvedEnd)) {
        return RangeValidation::kOverflow;
    }
    if (request.begin < approved.begin || requestEnd > approvedEnd) {
        return RangeValidation::kExceedsApproved;
    }
    return RangeValidation::kOk;
}

bool ScanBudget::bounded() const noexcept {
    return maxBytes.present || maxPages.present || maxItems.present || maxDurationNanos.present;
}

const char* budgetStopName(BudgetStop stop) noexcept {
    switch (stop) {
    case BudgetStop::kContinue:        return "Continue";
    case BudgetStop::kBytesExhausted:  return "BytesExhausted";
    case BudgetStop::kPagesExhausted:  return "PagesExhausted";
    case BudgetStop::kItemsExhausted:  return "ItemsExhausted";
    case BudgetStop::kTimeExhausted:   return "TimeExhausted";
    case BudgetStop::kCancelled:       return "Cancelled";
    }
    return "Continue";
}

BudgetStop evaluateBudget(const ScanBudget& budget, const ScanProgress& progress) noexcept {
    // Cancellation takes precedence over budget: stop immediately when the user cancels, without waiting for the budget to be exhausted.
    if (progress.cancelRequested) {
        return BudgetStop::kCancelled;
    }
    if (budget.maxBytes.present && progress.bytesDone >= budget.maxBytes.value) {
        return BudgetStop::kBytesExhausted;
    }
    if (budget.maxPages.present && progress.pagesDone >= budget.maxPages.value) {
        return BudgetStop::kPagesExhausted;
    }
    if (budget.maxItems.present && progress.itemsDone >= budget.maxItems.value) {
        return BudgetStop::kItemsExhausted;
    }
    if (budget.maxDurationNanos.present && progress.elapsedNanos >= budget.maxDurationNanos.value) {
        return BudgetStop::kTimeExhausted;
    }
    return BudgetStop::kContinue;
}

CollectionOutcome outcomeForStop(BudgetStop stop) noexcept {
    CollectionOutcome outcome;
    switch (stop) {
    case BudgetStop::kContinue:
        outcome.status = CollectionStatus::kSuccess;
        break;
    case BudgetStop::kCancelled:
        // Cancellation is not an error, but the result is indeed incomplete.
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "cancelled";
        break;
    case BudgetStop::kTimeExhausted:
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "budget:time";
        break;
    case BudgetStop::kBytesExhausted:
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "budget:bytes";
        break;
    case BudgetStop::kPagesExhausted:
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "budget:pages";
        break;
    case BudgetStop::kItemsExhausted:
        outcome.status = CollectionStatus::kPartial;
        outcome.message = "budget:items";
        break;
    }
    return outcome;
}

void applyStopToCoverage(BudgetStop stop, const ScanBudget& budget, CoverageAccount& coverage) {
    if (stop == BudgetStop::kContinue) {
        return;
    }
    if (stop == BudgetStop::kCancelled) {
        // F-06: When the user clicks Cancel, the budget record should be marked as "Cancelled". Recording it as
        // "limitHit + limit=unset" causes describeRemaining() to output "limit-hit:unknown" — this misrepresents
        // an active cancellation as "hitting an unknown limit," losing the dimension of the stop reason.
        coverage.cancelled = true;
        return;
    }
    coverage.limitHit = true;
    switch (stop) {
    case BudgetStop::kBytesExhausted: coverage.limit = budget.maxBytes; break;
    case BudgetStop::kPagesExhausted: coverage.limit = budget.maxPages; break;
    case BudgetStop::kItemsExhausted: coverage.limit = budget.maxItems; break;
    case BudgetStop::kTimeExhausted:  coverage.limit = budget.maxDurationNanos; break;
    case BudgetStop::kCancelled:      break;  // Already returned early above.
    case BudgetStop::kContinue:       break;
    }
}

const char* refreshDecisionName(RefreshDecision decision) noexcept {
    switch (decision) {
    case RefreshDecision::kApply:                     return "Apply";
    case RefreshDecision::kRejectSessionIsImmutable:  return "RejectSessionIsImmutable";
    case RefreshDecision::kRejectStaleSnapshot:       return "RejectStaleSnapshot";
    case RefreshDecision::kRejectNotLatestRequest:    return "RejectNotLatestRequest";
    }
    return "Apply";
}

RefreshDecision decideRefresh(DataOrigin origin,
                              std::uint64_t currentSnapshotId,
                              std::uint64_t incomingSnapshotId,
                              bool isLatestRequest) noexcept {
    if (origin == DataOrigin::kSession) {
        // F-09: Saved results cannot be silently overwritten by background refresh.
        return RefreshDecision::kRejectSessionIsImmutable;
    }
    if (!isLatestRequest) {
        return RefreshDecision::kRejectNotLatestRequest;
    }
    if (incomingSnapshotId <= currentSnapshotId) {
        return RefreshDecision::kRejectStaleSnapshot;
    }
    return RefreshDecision::kApply;
}

const char* liveNavigationDecisionName(LiveNavigationDecision decision) noexcept {
    switch (decision) {
    case LiveNavigationDecision::kAllow:                      return "Allow";
    case LiveNavigationDecision::kRejectObjectExited:         return "RejectObjectExited";
    case LiveNavigationDecision::kRejectIdentityMismatch:     return "RejectIdentityMismatch";
    case LiveNavigationDecision::kRejectIdentityUnverifiable: return "RejectIdentityUnverifiable";
    }
    return "RejectIdentityUnverifiable";
}

} // namespace ksword::evidence

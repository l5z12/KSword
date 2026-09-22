#include "MemoryRegionEvidence.h"

#include <algorithm>
#include <limits>

namespace ksword::evidence {
namespace {

constexpr std::uint64_t kU64Max = (std::numeric_limits<std::uint64_t>::max)();

std::string fact(const char* key, const std::string& value) {
    return std::string(key) + "=" + value;
}

std::string factBool(const char* key, bool value) {
    return fact(key, value ? "true" : "false");
}

std::string factCount(const char* key, std::uint64_t value) {
    return fact(key, formatU64(value, U64Format::kDecimal));
}

std::string factAddress(const char* key, const OptionalU64& value) {
    // Write 'unknown' if the value is missing. Writing '0x0000000000000000' would be interpreted by downstream systems as 'address is 0'.
    if (!value.present) {
        return fact(key, "unknown");
    }
    return fact(key, formatU64(value.value, U64Format::kHexAddress));
}

std::string factText(const char* key, const std::string& value) {
    return fact(key, value.empty() ? std::string("unknown") : value);
}

std::string describeRange(const AddressRange& range) {
    return formatU64(range.begin, U64Format::kHexAddress) + "+" +
           formatU64(range.length, U64Format::kDecimal);
}

// M-07/M-09: Region attribution has only three outcomes. If there is no mapped path, it is Unknown; never write "System".
OwnerAttribution regionAttribution(const RegionRecord& region, bool ownerKnown) noexcept {
    if (region.mappedPath.empty()) {
        return OwnerAttribution::kUnknown;
    }
    return ownerKnown ? OwnerAttribution::kDirectEvidence : OwnerAttribution::kCandidate;
}

void appendRegionFacts(const RegionRecord& region, std::vector<std::string>& facts) {
    facts.push_back(factAddress("region.base", region.base));
    facts.push_back(fact("region.size",
                         region.size.present ? formatU64(region.size.value, U64Format::kDecimal)
                                             : std::string("unknown")));
    facts.push_back(fact("region.state", regionStateName(region.state)));
    facts.push_back(fact("region.type", regionTypeName(region.type)));
    facts.push_back(fact("region.source", regionEvidenceSourceName(region.source)));
    facts.push_back(factAddress("region.allocationBase", region.allocationBase));
    facts.push_back(factText("region.mappedPath", region.mappedPath));
    facts.push_back(factBool("protection.readable", region.protection.readable));
    facts.push_back(factBool("protection.writable", region.protection.writable));
    facts.push_back(factBool("protection.executable", region.protection.executable));
    facts.push_back(factBool("vadVerified", vadVerified(region)));
}

// Extract maximal continuous segments from a bitmap of "hit or miss" flags. Hole and conflict ranges share this logic.
std::vector<AddressRange> collectRuns(std::uint64_t begin,
                                      const std::vector<bool>& flags,
                                      bool wanted) {
    std::vector<AddressRange> runs;
    std::size_t i = 0;
    const std::size_t kCount = flags.size();
    while (i < kCount) {
        if (flags[i] != wanted) {
            ++i;
            continue;
        }
        const std::size_t kStart = i;
        while (i < kCount && flags[i] == wanted) {
            ++i;
        }
        AddressRange run;
        run.begin = begin + static_cast<std::uint64_t>(kStart);
        run.length = static_cast<std::uint64_t>(i - kStart);
        runs.push_back(run);
    }
    return runs;
}

// Admission condition during merge. Both passes of mergeReadSpans must use the **same** predicate: a span excluded
// in the first pass but included in the second (e.g., one where begin+length overflows 64-bit) would cause base =
// begin - lowest to compute an enormous value, leading to out-of-bounds reads/writes in present[target] /
// bytes[target]. Consolidating the condition into a single function ensures both passes cannot diverge (M-02).
bool mergeAdmits(const ReadSpan& span, std::uint64_t& end) noexcept {
    return span.consistent() && span.range.length != 0ULL && span.range.endAddress(end);
}

// Reject a bounded read: read zero bytes but log the request range as-is (F-06),
// write the rejection level into rejection, and never pretend it ran normally (M-10).
BoundedReadResult rejectBoundedRead(const BoundedReadRequest& request,
                                    RangeValidation validation,
                                    BoundedReadRejection rejection,
                                    std::uint64_t nativeCode,
                                    std::string message) {
    BoundedReadResult result;
    result.validation = validation;
    result.rejection = rejection;
    result.span.range = request.requested;
    result.span.range.length = 0ULL;
    result.span.observedUtc100ns = request.observedUtc100ns;
    result.span.outcome = CollectionOutcome::failure(CollectionStatus::kError,
                                                     "KSWORD",
                                                     nativeCode,
                                                     std::move(message));
    result.coverage.requestedBegin = OptionalU64::of(request.requested.begin);
    std::uint64_t end = 0ULL;
    if (request.requested.endAddress(end)) {
        result.coverage.requestedEnd = OptionalU64::of(end);
    }
    // The entire rejected segment is left unprocessed and recorded in truncated — a coverage of all zeros would be read as 'nothing to do'.
    result.coverage.truncated = request.requested.length;
    return result;
}

} // namespace

// ---------------------------------------------------------------------------
// M-01
// ---------------------------------------------------------------------------

const char* regionStateName(RegionState state) noexcept {
    switch (state) {
    case RegionState::kUnknown:  return "Unknown";
    case RegionState::kFree:     return "Free";
    case RegionState::kReserved: return "Reserved";
    case RegionState::kCommit:   return "Commit";
    }
    return "Unknown";
}

const char* regionTypeName(RegionType type) noexcept {
    switch (type) {
    case RegionType::kUnknown: return "Unknown";
    case RegionType::kPrivate: return "Private";
    case RegionType::kMapped:  return "Mapped";
    case RegionType::kImage:   return "Image";
    }
    return "Unknown";
}

const char* regionEvidenceSourceName(RegionEvidenceSource source) noexcept {
    switch (source) {
    case RegionEvidenceSource::kR3VirtualQuery:  return "R3VirtualQuery";
    case RegionEvidenceSource::kR0VadWalk:       return "R0VadWalk";
    case RegionEvidenceSource::kOfflineSnapshot: return "OfflineSnapshot";
    }
    return "R3VirtualQuery";
}

bool VadEvidence::complete() const noexcept {
    if (!profileVerified || profileId.empty()) {
        return false;
    }
    if (!vadNodeAddress.present || !startingVpn.present || !endingVpn.present) {
        return false;
    }
    // Reverse interval description chain structure is abnormal; stop per M-06 and do not treat as valid evidence.
    return endingVpn.value >= startingVpn.value;
}

bool vadVerified(const RegionRecord& record) noexcept {
    // Hard rule: Only if the VAD walk (R0VadWalk) was actually performed and all fields are complete, is it valid to claim 'VAD verified'.
    // R3 VirtualQuery results are invalid even if the vad field is manually filled in.
    return record.source == RegionEvidenceSource::kR0VadWalk && record.vad.complete();
}

bool regionRange(const RegionRecord& record, AddressRange& out) noexcept {
    if (!record.base.present || !record.size.present || record.size.value == 0ULL) {
        return false;
    }
    if (record.size.value > kU64Max - record.base.value) {
        return false;
    }
    out.begin = record.base.value;
    out.length = record.size.value;
    return true;
}

// ---------------------------------------------------------------------------
// M-02
// ---------------------------------------------------------------------------

bool ReadSpan::consistent() const noexcept {
    if (bytes.size() != present.size()) {
        return false;
    }
    return static_cast<std::uint64_t>(bytes.size()) == range.length;
}

std::uint64_t ReadSpan::presentCount() const noexcept {
    std::uint64_t count = 0ULL;
    for (std::size_t i = 0; i < present.size(); ++i) {
        if (present[i]) {
            ++count;
        }
    }
    return count;
}

bool ReadSpan::hasHole() const noexcept {
    for (std::size_t i = 0; i < present.size(); ++i) {
        if (!present[i]) {
            return true;
        }
    }
    return false;
}

ReadSpan makeEmptyReadSpan(const AddressRange& range) {
    ReadSpan span;
    span.range = range;
    std::uint64_t end = 0ULL;
    if (range.length == 0ULL || !range.endAddress(end) || range.length > kMaxReadSpanBytes) {
        // Invalid or out-of-range ranges allocate no bytes and do not return 'empty but success'.
        span.range.length = 0ULL;
        span.outcome = CollectionOutcome::failure(CollectionStatus::kError,
                                                  "KSWORD",
                                                  static_cast<std::uint64_t>(RangeValidation::kOverflow),
                                                  "read span range rejected");
        return span;
    }
    const std::size_t kCount = static_cast<std::size_t>(range.length);
    span.bytes.assign(kCount, 0U);
    span.present.assign(kCount, false);
    span.outcome = CollectionOutcome::notCollected();
    return span;
}

bool applyReadChunk(ReadSpan& span,
                    std::uint64_t address,
                    const std::uint8_t* data,
                    std::size_t length) {
    if (length == 0U) {
        return true;
    }
    if (data == nullptr || !span.consistent()) {
        return false;
    }
    if (address < span.range.begin) {
        return false;
    }
    const std::uint64_t kOffset = address - span.range.begin;
    if (kOffset > span.range.length || static_cast<std::uint64_t>(length) > span.range.length - kOffset) {
        return false;
    }
    const std::size_t kBase = static_cast<std::size_t>(kOffset);
    for (std::size_t i = 0; i < length; ++i) {
        span.bytes[kBase + i] = data[i];
        span.present[kBase + i] = true;
    }
    return true;
}

bool byteAt(const ReadSpan& span, std::uint64_t address, std::uint8_t& out) noexcept {
    if (!span.consistent() || address < span.range.begin) {
        return false;
    }
    const std::uint64_t kOffset = address - span.range.begin;
    if (kOffset >= span.range.length) {
        return false;
    }
    const std::size_t kIndex = static_cast<std::size_t>(kOffset);
    if (!span.present[kIndex]) {
        // Hole: The caller cannot retrieve the value, so zero-padding cannot be mistaken for real data (M-02).
        return false;
    }
    out = span.bytes[kIndex];
    return true;
}

std::vector<AddressRange> describeHoles(const ReadSpan& span) {
    if (!span.consistent()) {
        return {};
    }
    return collectRuns(span.range.begin, span.present, false);
}

CollectionStatus classifyReadSpan(const ReadSpan& span) noexcept {
    if (!span.consistent() || span.range.length == 0ULL) {
        return CollectionStatus::kError;
    }
    const std::uint64_t kGot = span.presentCount();
    if (kGot == span.range.length) {
        return CollectionStatus::kSuccess;
    }
    if (kGot == 0ULL) {
        // Reading zero bytes is not "partial success". The specific reason is preserved in span.outcome.
        return CollectionStatus::kError;
    }
    return CollectionStatus::kPartial;
}

CoverageAccount buildReadCoverage(const ReadSpan& span) {
    CoverageAccount coverage;
    std::uint64_t end = 0ULL;
    if (!span.range.endAddress(end)) {
        return coverage;
    }
    coverage.requestedBegin = OptionalU64::of(span.range.begin);
    coverage.requestedEnd = OptionalU64::of(end);
    if (!span.consistent()) {
        return coverage;
    }
    const std::uint64_t kGot = span.presentCount();
    coverage.succeeded = kGot;
    coverage.failed = span.range.length - kGot;
    coverage.totalKnown = OptionalU64::of(span.range.length);
    // The processed range equals the requested range: we indeed attempted to process block by block, though some blocks were unreadable.
    coverage.processedBegin = coverage.requestedBegin;
    coverage.processedEnd = coverage.requestedEnd;
    return coverage;
}

const char* mergeObservationTimingName(MergeObservationTiming timing) noexcept {
    switch (timing) {
    case MergeObservationTiming::kSingleObservation:      return "SingleObservation";
    case MergeObservationTiming::kMultipleObservations:   return "MultipleObservations";
    case MergeObservationTiming::kObservationTimeUnknown: return "ObservationTimeUnknown";
    }
    return "ObservationTimeUnknown";
}

MergedReadSpan mergeReadSpans(const std::vector<ReadSpan>& spans) {
    MergedReadSpan merged;
    bool any = false;
    std::uint64_t lowest = 0ULL;
    std::uint64_t highest = 0ULL;
    std::size_t admitted = 0U;
    bool timeMissing = false;
    bool timeDiffers = false;
    OptionalU64 firstTime;

    for (const ReadSpan& span : spans) {
        std::uint64_t end = 0ULL;
        if (!mergeAdmits(span, end)) {
            continue;
        }
        ++admitted;
        // M-05: For time relationships, only consider segments that were actually merged in.
        if (!span.observedUtc100ns.present) {
            timeMissing = true;
        } else if (!firstTime.present) {
            firstTime = span.observedUtc100ns;
        } else if (firstTime.value != span.observedUtc100ns.value) {
            timeDiffers = true;
        }
        if (!any) {
            lowest = span.range.begin;
            highest = end;
            any = true;
            continue;
        }
        lowest = (std::min)(lowest, span.range.begin);
        highest = (std::max)(highest, end);
    }

    // The criterion is the collection timestamp, not the byte values. Two observations having identical bytes only indicates that this memory region was not
    // modified; it does not prove they are snapshots from the same moment. Using byte equality as evidence of simultaneity is exactly what M-05 prohibits.
    if (timeDiffers) {
        merged.timing = MergeObservationTiming::kMultipleObservations;
    } else if (admitted > 1U && timeMissing) {
        // If some segments in the multi-segment input lack timestamps, simultaneity cannot be proven. Prefer downgrading rather than falsely claiming an atomic snapshot.
        merged.timing = MergeObservationTiming::kObservationTimeUnknown;
    } else {
        merged.timing = MergeObservationTiming::kSingleObservation;
    }

    if (!any) {
        merged.span.outcome = CollectionOutcome::notCollected();
        return merged;
    }

    AddressRange full;
    full.begin = lowest;
    full.length = highest - lowest;
    merged.span = makeEmptyReadSpan(full);
    if (merged.span.range.length == 0ULL) {
        return merged;  // makeEmptyReadSpan has already written the rejection reason into outcome.
    }
    if (merged.timing == MergeObservationTiming::kSingleObservation) {
        merged.span.observedUtc100ns = firstTime;
    }
    merged.byteObservedUtc100ns.assign(merged.span.bytes.size(), OptionalU64::unset());

    std::vector<bool> conflicts(merged.span.bytes.size(), false);
    for (const ReadSpan& span : spans) {
        std::uint64_t end = 0ULL;
        // The admission condition is **exactly the same** as the first pass; not a single character can be omitted (see the comment in mergeAdmits).
        if (!mergeAdmits(span, end)) {
            continue;
        }
        // Re-verify that it indeed falls within the [lowest, highest] range calculated in the first pass. Since lowest/highest are derived
        // from this set of spans, this additional check ensures that the boundary validity of base and target does not depend on the
        // correctness of the previous loop iteration — out-of-bounds reads/writes are BLOCKER issues, so the criteria must be self-validating.
        if (span.range.begin < lowest || end > highest) {
            continue;
        }
        const std::size_t kBase = static_cast<std::size_t>(span.range.begin - lowest);
        for (std::size_t i = 0; i < span.present.size(); ++i) {
            if (!span.present[i]) {
                continue;
            }
            const std::size_t kTarget = kBase + i;
            if (merged.span.present[kTarget] && merged.span.bytes[kTarget] != span.bytes[i]) {
                // If the same address yields different values on two reads, retain the newer value and isolate the conflicting range.
                conflicts[kTarget] = true;
            }
            merged.span.bytes[kTarget] = span.bytes[i];
            merged.span.present[kTarget] = true;
            merged.byteObservedUtc100ns[kTarget] = span.observedUtc100ns;
        }
    }
    merged.conflictingRanges = collectRuns(lowest, conflicts, true);

    CollectionStatus status = classifyReadSpan(merged.span);
    if (status == CollectionStatus::kSuccess &&
        (!merged.conflictingRanges.empty() ||
         merged.timing != MergeObservationTiming::kSingleObservation)) {
        // Only 'full coverage + no conflicts + proven to originate from the same observation' qualifies as Success.
        status = CollectionStatus::kPartial;
    }
    merged.span.outcome.status = status;
    if (!merged.conflictingRanges.empty()) {
        merged.span.outcome.message = "conflicting-observations";
    } else if (merged.timing == MergeObservationTiming::kMultipleObservations) {
        merged.span.outcome.message = "observations-at-different-times";
    } else if (merged.timing == MergeObservationTiming::kObservationTimeUnknown) {
        merged.span.outcome.message = "observation-time-unrecorded";
    }
    return merged;
}

const char* boundedReadRejectionName(BoundedReadRejection rejection) noexcept {
    switch (rejection) {
    case BoundedReadRejection::kNone:           return "None";
    case BoundedReadRejection::kInvalidRange:   return "InvalidRange";
    case BoundedReadRejection::kReversedRange:  return "ReversedRange";
    case BoundedReadRejection::kExceedsMaxSpan: return "ExceedsMaxSpan";
    case BoundedReadRejection::kNoBudget:       return "NoBudget";
    }
    return "InvalidRange";
}

BoundedReadResult readRangeBounded(const BoundedReadRequest& request, const ChunkReader& reader) {
    // Rejection order: first check if the range itself is valid, then check the span limit, and finally check the budget. All three stages must
    // be accurately reflected in the returned structure; any stage masquerading as 'valid range, budget not hit, normal completion' is invalid.
    // Direct violation of M-10 / F-06.
    const RangeValidation kValidation = validateRange(request.requested, request.approved);
    if (kValidation != RangeValidation::kOk) {
        // M-10: Reject invalid or unauthorized ranges without reading a single byte and without leaving the illusion of partial results.
        return rejectBoundedRead(request,
                                 kValidation,
                                 BoundedReadRejection::kInvalidRange,
                                 static_cast<std::uint64_t>(kValidation),
                                 rangeValidationName(kValidation));
    }
    if (request.requested.length > kMaxReadSpanBytes) {
        // Exceeds the single-span limit. Previously, validation was Ok, stop was Continue, and coverage was all zeros; the
        // caller would assume the scan completed normally with no results. This effectively disguised a rejection as success.
        return rejectBoundedRead(request,
                                 RangeValidation::kOk,
                                 BoundedReadRejection::kExceedsMaxSpan,
                                 kMaxReadSpanBytes,
                                 "requested span exceeds kMaxReadSpanBytes");
    }
    if (!request.budget.bounded()) {
        // M-10: Call sites that forgot to set a budget should not be able to read 64 MiB of kernel memory in one go. Unbounded reads are rejected.
        return rejectBoundedRead(request,
                                 RangeValidation::kOk,
                                 BoundedReadRejection::kNoBudget,
                                 0ULL,
                                 "scan budget is unbounded");
    }

    BoundedReadResult result;
    result.validation = RangeValidation::kOk;
    result.span = makeEmptyReadSpan(request.requested);
    result.span.observedUtc100ns = request.observedUtc100ns;
    if (result.span.range.length == 0ULL) {
        // The three criteria above theoretically cover all rejection reasons. Reaching this point indicates that
        // makeEmptyReadSpan has its own fallback criteria active. Return an explicit rejection, not 'empty but success'.
        result.rejection = BoundedReadRejection::kExceedsMaxSpan;
        result.coverage.requestedBegin = OptionalU64::of(request.requested.begin);
        result.coverage.truncated = request.requested.length;
        return result;
    }

    const std::uint64_t kChunkSize = (request.chunkSize == 0ULL) ? 0x1000ULL : request.chunkSize;
    std::uint64_t end = 0ULL;
    (void)request.requested.endAddress(end);  // validateRange ensures no overflow occurs.

    ScanProgress progress;
    std::vector<std::uint8_t> buffer;
    std::uint64_t cursor = request.requested.begin;

    // F-05: The original code of the first failure is preserved as-is. Without it, failures such as
    // STATUS_ACCESS_DENIED, target process exit, and unreadable pages appear identical in the results.
    bool failureCaptured = false;
    CollectionStatus failureStatus = CollectionStatus::kError;
    OptionalU64 failureCode;
    std::string failureDomain;
    std::string failureMessage;

    while (cursor < end) {
        progress.cancelRequested = request.cancelRequested ? request.cancelRequested() : false;
        if (request.elapsedNanos) {
            progress.elapsedNanos = request.elapsedNanos();
        }
        result.stop = evaluateBudget(request.budget, progress);
        if (result.stop != BudgetStop::kContinue) {
            break;
        }

        // Chunk by chunkSize boundaries, so page boundaries will necessarily align with chunk boundaries.
        std::uint64_t chunkEnd = end;
        const std::uint64_t kAligned = cursor - (cursor % kChunkSize);
        if (kAligned <= kU64Max - kChunkSize) {
            const std::uint64_t kBoundary = kAligned + kChunkSize;
            if (kBoundary < chunkEnd) {
                chunkEnd = kBoundary;
            }
        }
        std::uint64_t length = chunkEnd - cursor;
        if (request.budget.maxBytes.present) {
            // Byte budget is precise to the byte: do not exceed the user-approved limit to round up to a block.
            const std::uint64_t kRemaining = (request.budget.maxBytes.value > progress.bytesDone)
                                                ? (request.budget.maxBytes.value - progress.bytesDone)
                                                : 0ULL;
            length = (std::min)(length, kRemaining);
            if (length == 0ULL) {
                result.stop = BudgetStop::kBytesExhausted;
                break;
            }
        }

        buffer.assign(static_cast<std::size_t>(length), 0U);
        ChunkReadResult chunk;
        if (reader) {
            reader(cursor, buffer.data(), buffer.size(), chunk);
        } else {
            chunk.status = CollectionStatus::kError;
            chunk.message = "no chunk reader supplied";
        }
        std::size_t copied = chunk.copied;
        if (copied > buffer.size()) {
            copied = buffer.size();  // Clamp writes to the buffer capacity even if the callback reports a false length; never write out of bounds.
        }
        if (copied > 0U) {
            (void)applyReadChunk(result.span, cursor, buffer.data(), copied);
        }
        if (!failureCaptured && copied < buffer.size()) {
            // Record only the first one: it is the direct cause of 'why this read was incomplete'; the rest are mostly its chain reactions.
            failureCaptured = true;
            // Only fall back to the generic Error when the callback provides no specific status (or claims success but failed to copy fully).
            // If AccessDenied / Unsupported / Timeout, retain the original state.
            failureStatus = (chunk.status == CollectionStatus::kNotCollected ||
                             chunk.status == CollectionStatus::kSuccess ||
                             chunk.status == CollectionStatus::kPartial)
                                ? CollectionStatus::kError
                                : chunk.status;
            failureCode = chunk.nativeCode;
            failureDomain = chunk.nativeCodeDomain;
            failureMessage = chunk.message;
        }

        progress.bytesDone += length;
        progress.pagesDone += 1ULL;
        progress.itemsDone += 1ULL;
        // Advance by the actually attempted length: when the byte budget truncates a block, the cursor must not jump to the end
        // of the whole block, otherwise the skipped bytes would be neither read nor accounted for in the truncation ledger.
        cursor += length;
    }

    // Accounting splits into three non-overlapping categories: successfully read, attempted but unreadable, and never attempted.
    const std::uint64_t kProcessed = cursor - request.requested.begin;
    const std::uint64_t kGot = result.span.presentCount();
    result.coverage = buildReadCoverage(result.span);
    result.coverage.succeeded = kGot;
    result.coverage.failed = (kProcessed > kGot) ? (kProcessed - kGot) : 0ULL;
    result.coverage.truncated = request.requested.length - kProcessed;
    result.coverage.processedEnd = OptionalU64::of(cursor);

    if (result.stop == BudgetStop::kContinue) {
        const CollectionStatus kCoverageStatus = classifyReadSpan(result.span);
        result.span.outcome.status = kCoverageStatus;
        if (kCoverageStatus == CollectionStatus::kPartial) {
            result.span.outcome.message = "unreadable-holes";
        }
        if (kCoverageStatus == CollectionStatus::kError && failureCaptured) {
            // If no bytes are read, the specific type of failure must be preserved (F-05).
            result.span.outcome.status = failureStatus;
        }
    } else {
        // Hit limit or cancelled: Overall result is Partial, with the reason provided by outcomeForStop.
        result.span.outcome = outcomeForStop(result.stop);
        applyStopToCoverage(result.stop, request.budget, result.coverage);
    }
    if (failureCaptured) {
        // Return the original code and source text exactly as-is; never pad with default 0 or empty strings (F-05).
        result.span.outcome.nativeCode = failureCode;
        result.span.outcome.nativeCodeDomain = failureDomain;
        // The stop reason (budget:* / cancelled) is itself the primary cause of this incomplete operation and should not be overwritten
        // by read failure messages; only when the full segment completes is the original source message placed at the front.
        if (!failureMessage.empty() && result.stop == BudgetStop::kContinue) {
            result.span.outcome.message = failureMessage;
        }
    }
    return result;
}

BoundedReadResult readRangeBoundedFromEndpoints(std::uint64_t begin,
                                                std::uint64_t end,
                                                const BoundedReadRequest& request,
                                                const ChunkReader& reader) {
    BoundedReadRequest adjusted = request;
    adjusted.requested.begin = begin;
    adjusted.requested.length = 0ULL;
    if (end < begin) {
        // M-10: Reversed range. AddressRange is expressed as (begin, length); after a successful endAddress(),
        // end is guaranteed to be >= begin, making this check unreachable in that representation—it only takes
        // effect in this entry point accepting 'end'. Here we check and read zero bytes.
        BoundedReadResult rejected = rejectBoundedRead(adjusted,
                                                       RangeValidation::kReversed,
                                                       BoundedReadRejection::kReversedRange,
                                                       static_cast<std::uint64_t>(
                                                           RangeValidation::kReversed),
                                                       rangeValidationName(
                                                           RangeValidation::kReversed));
        // Record the end value provided by the caller as-is so the UI can clearly specify "which segment you requested."
        rejected.coverage.requestedEnd = OptionalU64::of(end);
        return rejected;
    }
    adjusted.requested.length = end - begin;
    return readRangeBounded(adjusted, reader);
}

// ---------------------------------------------------------------------------
// M-09
// ---------------------------------------------------------------------------

const char* ownerAttributionName(OwnerAttribution attribution) noexcept {
    switch (attribution) {
    case OwnerAttribution::kDirectEvidence: return "DirectEvidence";
    case OwnerAttribution::kCandidate:      return "Candidate";
    case OwnerAttribution::kUnknown:        return "Unknown";
    }
    return "Unknown";
}

PoolAttributionResult attributeByTag(const std::string& tag,
                                     const std::vector<PoolTagOwnerEntry>& knownTagOwners) {
    PoolAttributionResult result;
    result.allocationStackAvailable = false;  // This function only checks tags and never has an allocation stack.
    if (tag.empty()) {
        result.attribution = OwnerAttribution::kUnknown;
        result.facts.push_back(fact("pool.tag", "absent"));
        return result;
    }
    result.facts.push_back(fact("pool.tag", tag));

    for (const PoolTagOwnerEntry& entry : knownTagOwners) {
        if (entry.tag != tag || entry.ownerId.empty()) {
            continue;
        }
        if (std::find(result.candidateOwners.begin(), result.candidateOwners.end(), entry.ownerId) !=
            result.candidateOwners.end()) {
            continue;
        }
        result.candidateOwners.push_back(entry.ownerId);
        result.facts.push_back(fact("pool.tagOwner", entry.ownerId));
        if (!entry.sourceNote.empty()) {
            result.facts.push_back(fact("pool.tagOwnerSource", entry.sourceNote));
        }
    }

    result.facts.push_back(factCount("pool.tagOwnerCount",
                                     static_cast<std::uint64_t>(result.candidateOwners.size())));
    if (result.candidateOwners.empty()) {
        result.attribution = OwnerAttribution::kUnknown;
        return result;
    }
    // M-09 Hard rule: A tag is not proof of ownership. Even if the table lists only one owner, it must be marked
    // as a candidate—multiple components sharing the same tag is common, and incomplete tables are also common.
    result.attribution = OwnerAttribution::kCandidate;
    return result;
}

PoolAttributionResult attributeByAllocationEvent(const PoolAllocationEvent& event,
                                                 const PoolAttributionResult& tagFallback) {
    if (!event.captured) {
        // If no allocation event was captured beforehand, fall back to the tag tier without fabricating data.
        PoolAttributionResult result = tagFallback;
        result.allocationStackAvailable = false;
        result.facts.push_back(fact("pool.allocationEvent", "not-captured"));
        return result;
    }
    PoolAttributionResult result;
    result.allocationStackAvailable = true;
    result.attribution = OwnerAttribution::kDirectEvidence;
    const std::string kKey = event.allocator.crossSessionKey();
    if (kKey.empty()) {
        // The event exists, but the allocator identity is insufficient to confirm across sessions: downgrade to candidate status instead of hard-promoting to direct evidence.
        result.attribution = OwnerAttribution::kCandidate;
        result.facts.push_back(fact("pool.allocatorIdentity", "insufficient"));
    }
    if (!event.allocator.imagePath.empty()) {
        result.candidateOwners.push_back(event.allocator.imagePath);
        result.facts.push_back(fact("pool.allocator", event.allocator.imagePath));
    }
    result.facts.push_back(factText("pool.allocationEventSource", event.eventSourceId));
    result.facts.push_back(factAddress("pool.allocationEventUtc100ns", event.eventUtc100ns));
    return result;
}

// ---------------------------------------------------------------------------
// M-07
// ---------------------------------------------------------------------------

const char* const kRuleIdPrivateExecutable = "mem.exec.private";
const char* const kRuleIdImageBytesDiffer = "mem.exec.image-bytes-differ";
const char* const kRuleIdThreadOriginMismatch = "mem.exec.thread-origin-mismatch";
const char* const kRuleIdThreadOriginUnknown = "mem.exec.thread-origin-unknown";

ExecutableRegionReport evaluateExecutableRegion(const ExecutableRegionInput& input) {
    ExecutableRegionReport report;
    report.attribution = regionAttribution(input.region, input.regionOwnerKnown);

    // Rule 1: private executable. This is merely a heuristic; JIT, .NET, and packers all trigger it.
    // Therefore, it reports facts only, not conclusions—keep the attribution unknown if unknown.
    if (input.region.protection.executable && input.region.type == RegionType::kPrivate) {
        ExecutableRegionFinding finding;
        finding.ruleId = kRuleIdPrivateExecutable;
        finding.ruleVersion = 1U;
        appendRegionFacts(input.region, finding.facts);
        finding.facts.push_back(factBool("region.privateExecutable", true));
        finding.attribution = report.attribution;
        if (!input.region.mappedPath.empty()) {
            finding.candidateOwners.push_back(input.region.mappedPath);
        }
        finding.inputOutcome = CollectionOutcome::success();
        report.findings.push_back(finding);
    }

    // Rule 2: Image region bytes are inconsistent with disk.
    bool comparedClean = false;
    bool differenceConfirmed = false;
    const ImageBytesComparison& comparison = input.imageComparison;
    const bool kComparisonAttempted =
        comparison.compared || comparison.outcome.status != CollectionStatus::kNotCollected;
    if (input.region.type == RegionType::kImage && kComparisonAttempted) {
        ExecutableRegionFinding finding;
        finding.ruleId = kRuleIdImageBytesDiffer;
        finding.ruleVersion = 1U;
        appendRegionFacts(input.region, finding.facts);
        finding.facts.push_back(factText("image.onDiskPath", comparison.onDiskPath));
        finding.facts.push_back(factBool("image.compared", comparison.compared));
        finding.facts.push_back(
            fact("image.compareStatus", collectionStatusName(comparison.outcome.status)));
        finding.facts.push_back(factBool("image.relocationsApplied", comparison.relocationsApplied));
        finding.facts.push_back(
            factCount("image.differingRangeCount",
                      static_cast<std::uint64_t>(comparison.differingRanges.size())));
        for (const AddressRange& range : comparison.differingRanges) {
            finding.facts.push_back(fact("image.differingRange", describeRange(range)));
        }
        finding.attribution = report.attribution;
        if (!comparison.onDiskPath.empty()) {
            finding.candidateOwners.push_back(comparison.onDiskPath);
        }
        finding.inputOutcome = comparison.outcome;
        report.findings.push_back(finding);

        const bool kUsable =
            comparison.compared && comparison.outcome.status == CollectionStatus::kSuccess;
        comparedClean = kUsable && comparison.differingRanges.empty();
        // Without relocation/Hotpatch normalization, differences mix with legitimate changes; treat as clues, not conclusions.
        differenceConfirmed =
            kUsable && !comparison.differingRanges.empty() && comparison.relocationsApplied;
    }

    // Rule 3: Thread start address does not match the mapping ownership.
    for (const ThreadStartFact& thread : input.threads) {
        if (!thread.startAddress.present) {
            // If the start address cannot be obtained, do not substitute it with the region base address. This represents 'no observation'
            // rather than 'ownership mismatch'. Sharing a ruleId between them would cause the UI and exporter to treat them as the same clue,
            // and a finding with zero observations would incorrectly elevate the conclusion (F-05). Therefore, keep them as separate entries.
            ExecutableRegionFinding unknownStart;
            unknownStart.ruleId = kRuleIdThreadOriginUnknown;
            unknownStart.ruleVersion = 1U;
            unknownStart.facts.push_back(factAddress("thread.startAddress", thread.startAddress));
            unknownStart.facts.push_back(factText("thread.key", thread.thread.crossSessionKey()));
            unknownStart.facts.push_back(
                fact("thread.identityStrength", identityStrengthName(thread.thread.strength())));
            unknownStart.attribution = OwnerAttribution::kUnknown;
            unknownStart.inputOutcome = CollectionOutcome::notCollected();
            report.findings.push_back(unknownStart);
            continue;
        }
        if (!thread.startAddressInsideRegion) {
            continue;
        }
        const bool kPathUnknown = thread.startAddressMappedPath.empty();
        if (!kPathUnknown && thread.startAddressMappedPath == input.region.mappedPath) {
            continue;  // Ownership matches; no facts to report.
        }

        ExecutableRegionFinding finding;
        finding.ruleId = kRuleIdThreadOriginMismatch;
        finding.ruleVersion = 1U;
        finding.facts.push_back(factAddress("thread.startAddress", thread.startAddress));
        finding.facts.push_back(factText("thread.key", thread.thread.crossSessionKey()));
        finding.facts.push_back(
            fact("thread.identityStrength", identityStrengthName(thread.thread.strength())));
        finding.facts.push_back(factText("thread.startMappedPath", thread.startAddressMappedPath));
        finding.facts.push_back(factText("region.mappedPath", input.region.mappedPath));
        finding.facts.push_back(factBool("thread.startInsideRegion", true));
        if (kPathUnknown) {
            finding.attribution = OwnerAttribution::kUnknown;
        } else {
            // Both paths are non-empty and different: there is no evidence to determine which side is
            // the "true owner", so both are listed as candidates without selecting a conclusion (M-09).
            finding.attribution = OwnerAttribution::kCandidate;
            finding.candidateOwners.push_back(thread.startAddressMappedPath);
            if (!input.region.mappedPath.empty()) {
                finding.candidateOwners.push_back(input.region.mappedPath);
            }
        }
        finding.inputOutcome = CollectionOutcome::success();
        report.findings.push_back(finding);
    }

    // F-05: Indeterminate means 'observed but insufficient to determine', while NoEvidence means 'no available observation'.
    // Therefore, only findings that actually carry observations can elevate the conclusion from NoEvidence
    // to Indeterminate. A finding with inputOutcome=NotCollected cannot elevate any conclusion.
    std::size_t observedFindings = 0U;
    for (const ExecutableRegionFinding& finding : report.findings) {
        if (statusCarriesObservation(finding.inputOutcome.status)) {
            ++observedFindings;
        }
    }

    if (differenceConfirmed) {
        report.conclusion = AnalysisConclusion::kDifferenceObserved;
    } else if (comparedClean) {
        report.conclusion = AnalysisConclusion::kNoDifferenceObserved;
    } else if (observedFindings != 0U) {
        // There is a clue but it is insufficient for a definitive conclusion. A private RX entry alone
        // will always remain here; upgrading it to "malicious" is explicitly prohibited by M-07.
        report.conclusion = AnalysisConclusion::kIndeterminate;
    } else {
        report.conclusion = AnalysisConclusion::kNoEvidence;
    }
    return report;
}

} // namespace ksword::evidence

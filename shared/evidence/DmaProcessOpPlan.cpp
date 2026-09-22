#include "DmaProcessOpPlan.h"

#include <algorithm>

namespace ksword::evidence {

const char* dmaOpPlanStatusName(const DmaOpPlanStatus status) noexcept {
    switch (status) {
        case DmaOpPlanStatus::kOk: return "计划成立";
        case DmaOpPlanStatus::kEmptyPayload: return "载荷为空";
        case DmaOpPlanStatus::kPayloadTooLarge: return "载荷放不下";
        case DmaOpPlanStatus::kPageBytesUnavailable: return "没有目标页的当前内容";
        case DmaOpPlanStatus::kPageBytesWrongSize: return "目标页内容长度不是一页";
        case DmaOpPlanStatus::kOffsetOutOfPage: return "页内偏移超出页范围";
        case DmaOpPlanStatus::kWouldCrossPage: return "写入范围会越过页边界";
        case DmaOpPlanStatus::kNoCave: return "页内没有足够长的空隙";
    }
    return "未知状态";
}

namespace {

// Only recognize these two padding bytes. See the header file for the reason: other repeated bytes might be actual data.
bool isPaddingByte(const std::uint8_t value) noexcept {
    return value == 0x00U || value == 0xCCU;
}

}  // namespace

DmaCodeCave findLargestCodeCave(
    const std::vector<std::uint8_t>& pageBytes,
    const std::size_t minLength) {
    DmaCodeCave best;
    if (pageBytes.empty() || minLength == 0U) {
        return best;
    }

    std::size_t runStart = 0U;
    std::size_t runLength = 0U;
    std::uint8_t runByte = 0U;

    // Scan byte by byte. Only "the same padding byte appearing consecutively" counts as a gap: regions where 0x00 and
    // 0xCC alternate are not padding; merging them into a single segment would overwrite the true content in between.
    for (std::size_t index = 0U; index <= pageBytes.size(); ++index) {
        const bool kContinues =
            (index < pageBytes.size())
            && isPaddingByte(pageBytes[index])
            && (runLength == 0U || pageBytes[index] == runByte);

        if (kContinues) {
            if (runLength == 0U) {
                runStart = index;
                runByte = pageBytes[index];
            }
            ++runLength;
            continue;
        }

        if (runLength > best.length) {
            best.found = true;
            best.offset = runStart;
            best.length = runLength;
            best.fillByte = runByte;
        }
        // The current byte may be the start of another gap.
        if (index < pageBytes.size() && isPaddingByte(pageBytes[index])) {
            runStart = index;
            runByte = pageBytes[index];
            runLength = 1U;
        } else {
            runLength = 0U;
        }
    }

    // Do not return the longest segment when the length is insufficient. Returning it would force the caller to write into a gap
    // that is too short, effectively overwriting real code, while the caller cannot distinguish this from a valid return value.
    if (best.length < minLength) {
        return DmaCodeCave{};
    }
    return best;
}

DmaWritePlan planPayloadIntoCave(
    const std::vector<std::uint8_t>& pageBytes,
    const std::vector<std::uint8_t>& payload,
    const std::size_t minCaveBytes) {
    DmaWritePlan plan;

    if (pageBytes.empty()) {
        plan.status = DmaOpPlanStatus::kPageBytesUnavailable;
        return plan;
    }
    if (pageBytes.size() != static_cast<std::size_t>(kDmaOpPageBytes)) {
        plan.status = DmaOpPlanStatus::kPageBytesWrongSize;
        return plan;
    }
    if (payload.empty()) {
        plan.status = DmaOpPlanStatus::kEmptyPayload;
        return plan;
    }
    if (payload.size() > static_cast<std::size_t>(kDmaOpPageBytes)) {
        plan.status = DmaOpPlanStatus::kPayloadTooLarge;
        return plan;
    }

    const std::size_t kRequired = (std::max)(minCaveBytes, payload.size());
    const DmaCodeCave kCave = findLargestCodeCave(pageBytes, kRequired);
    if (!kCave.found) {
        plan.status = DmaOpPlanStatus::kNoCave;
        return plan;
    }
    if (payload.size() > kCave.length) {
        plan.status = DmaOpPlanStatus::kPayloadTooLarge;
        return plan;
    }

    plan.status = DmaOpPlanStatus::kOk;
    plan.offsetInPage = kCave.offset;
    plan.bytesToWrite = payload;
    plan.originalBytes.assign(
        pageBytes.begin() + static_cast<std::ptrdiff_t>(kCave.offset),
        pageBytes.begin() + static_cast<std::ptrdiff_t>(kCave.offset + payload.size()));
    return plan;
}

DmaWritePlan planBytesAtOffset(
    const std::vector<std::uint8_t>& pageBytes,
    const std::size_t offsetInPage,
    const std::vector<std::uint8_t>& bytes) {
    DmaWritePlan plan;

    if (pageBytes.empty()) {
        plan.status = DmaOpPlanStatus::kPageBytesUnavailable;
        return plan;
    }
    if (pageBytes.size() != static_cast<std::size_t>(kDmaOpPageBytes)) {
        plan.status = DmaOpPlanStatus::kPageBytesWrongSize;
        return plan;
    }
    if (bytes.empty()) {
        plan.status = DmaOpPlanStatus::kEmptyPayload;
        return plan;
    }
    if (offsetInPage >= static_cast<std::size_t>(kDmaOpPageBytes)) {
        plan.status = DmaOpPlanStatus::kOffsetOutOfPage;
        return plan;
    }
    // The out-of-bounds check is written as 'insufficient remaining space' rather than 'start + length exceeds page size': the latter
    // can cause integer wraparound when the length is extremely large, and the comparison after wraparound would incorrectly pass.
    if (bytes.size() > static_cast<std::size_t>(kDmaOpPageBytes) - offsetInPage) {
        plan.status = DmaOpPlanStatus::kWouldCrossPage;
        return plan;
    }

    plan.status = DmaOpPlanStatus::kOk;
    plan.offsetInPage = offsetInPage;
    plan.bytesToWrite = bytes;
    plan.originalBytes.assign(
        pageBytes.begin() + static_cast<std::ptrdiff_t>(offsetInPage),
        pageBytes.begin() + static_cast<std::ptrdiff_t>(offsetInPage + bytes.size()));
    return plan;
}

const char* dmaTargetSharingName(const DmaTargetSharing sharing) noexcept {
    switch (sharing) {
        case DmaTargetSharing::kPrivateConfirmed: return "已确认为进程私有";
        case DmaTargetSharing::kSharedConfirmed: return "已确认被其它进程共享";
        case DmaTargetSharing::kSharingUnknown: return "无法确认是否共享";
    }
    return "未知";
}

DmaTargetSharing evaluateTargetSharing(
    const bool regionIsPrivate,
    const bool comparisonPerformed,
    const bool comparisonMatched) noexcept {
    // MEM_PRIVATE pages are not backed by section objects, so cross-process sharing is not applicable; no further comparison is needed.
    if (regionIsPrivate) {
        return DmaTargetSharing::kPrivateConfirmed;
    }
    // If not compared, **cannot** claim it is private. Just because no other process maps it now does not mean it won't be mapped next.
    // Interpreting 'not found' as 'confirmed private' is precisely the error this criterion aims to prevent.
    if (!comparisonPerformed) {
        return DmaTargetSharing::kSharingUnknown;
    }
    return comparisonMatched
        ? DmaTargetSharing::kSharedConfirmed
        : DmaTargetSharing::kPrivateConfirmed;
}

std::vector<std::uint8_t> undefinedInstructionBytes() {
    return std::vector<std::uint8_t>{0x0FU, 0x0BU};
}

DmaWriteVerification verifyWriteReadback(
    const std::vector<std::uint8_t>& intendedBytes,
    const std::vector<std::uint8_t>& readbackBytes) {
    DmaWriteVerification verification;

    // Both sides being empty does not count as 'verification passed': Without any writes, there is nothing
    // to verify; reporting matched = true would make an operation that did nothing appear successful.
    if (intendedBytes.empty()) {
        verification.matched = false;
        return verification;
    }
    if (readbackBytes.size() < intendedBytes.size()) {
        verification.readbackTooShort = true;
        verification.comparedBytes = readbackBytes.size();
        // The common prefix still needs to be checked: if the prefix is incorrect, it indicates more than just a read shortage.
        for (std::size_t index = 0U; index < readbackBytes.size(); ++index) {
            if (readbackBytes[index] != intendedBytes[index]) {
                verification.firstMismatchOffset = index;
                verification.expectedByte = intendedBytes[index];
                verification.actualByte = readbackBytes[index];
                return verification;
            }
        }
        verification.firstMismatchOffset = readbackBytes.size();
        return verification;
    }

    verification.comparedBytes = intendedBytes.size();
    for (std::size_t index = 0U; index < intendedBytes.size(); ++index) {
        if (readbackBytes[index] != intendedBytes[index]) {
            verification.firstMismatchOffset = index;
            verification.expectedByte = intendedBytes[index];
            verification.actualByte = readbackBytes[index];
            return verification;
        }
    }
    verification.matched = true;
    return verification;
}

}  // namespace ksword::evidence

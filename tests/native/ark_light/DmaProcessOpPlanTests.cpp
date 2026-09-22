// Offline tests for the DMA-based process operation planning layer (shared/evidence/DmaProcessOpPlan.h).
//
// The consequence of an error at this layer differs from elsewhere: it **writes bytes directly into another process**. A wrong
// offset overwrites real code, causing the target to crash immediately due to our action; a wrong range crosses page boundaries,
// and since DMA granularity is one page, the crossed page could be anything. None of these errors return an error code.
//
// Therefore, the three types of assertions must be exhaustive:
//   * Gap criteria: only recognize 0x00/0xCC, do not cross padding bytes, and reject if length is insufficient rather than forcing a match.
//   * Backup (restoration is impossible without a backup, as DMA modifies real pages, not shadow pages);
//   Read-back verification is required (DMA writes provide no self-verification; a driver reporting OK does not guarantee the physical page actually changed).

#include "TestSupport.h"

#include "../../../shared/evidence/DmaProcessOpPlan.h"

#include <cstdint>
#include <vector>

namespace {

using ksword::evidence::DmaOpPlanStatus;
using ksword::evidence::findLargestCodeCave;
using ksword::evidence::kDmaOpMinCaveBytes;
using ksword::evidence::kDmaOpPageBytes;
using ksword::evidence::planBytesAtOffset;
using ksword::evidence::planPayloadIntoCave;
using ksword::evidence::undefinedInstructionBytes;
using ksword::evidence::verifyWriteReadback;

constexpr std::size_t kPage = static_cast<std::size_t>(kDmaOpPageBytes);

// MakePage: A page of "real code" filled with a non-repeating pattern to ensure it is not mistaken for padding.
std::vector<std::uint8_t> makePage() {
    std::vector<std::uint8_t> page(kPage, 0U);
    for (std::size_t i = 0U; i < kPage; ++i) {
        // Intentionally avoid 0x00 and 0xCC; otherwise, the entire page will be treated as a hole.
        const std::uint8_t kV = static_cast<std::uint8_t>((i * 7U + 1U) & 0xFFU);
        page[i] = (kV == 0x00U || kV == 0xCCU) ? 0x55U : kV;
    }
    return page;
}

// Carve a filled segment within the page.
void carveCave(std::vector<std::uint8_t>& page, std::size_t offset,
               std::size_t length, std::uint8_t fill) {
    for (std::size_t i = 0U; i < length; ++i) {
        page[offset + i] = fill;
    }
}

// ------------------------------------------------------------
// I. Cave criteria.
// ------------------------------------------------------------
void testCaveDiscovery(ksword_tests::Suite& suite) {
    {
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 1000U, 200U, 0x00U);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(kCave.found && kCave.offset == 1000U && kCave.length == 200U,
            L"dma op: the zero-filled cave is found at its exact offset and length");
        suite.expect(kCave.fillByte == 0x00U,
            L"dma op: the cave reports which byte fills it");
    }
    {
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 2048U, 128U, 0xCCU);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(kCave.found && kCave.offset == 2048U && kCave.length == 128U,
            L"dma op: an int3-filled cave is found too");
    }
    {
        // Two segments; take the longest one.
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 100U, 80U, 0x00U);
        carveCave(page, 500U, 300U, 0x00U);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(kCave.found && kCave.offset == 500U && kCave.length == 300U,
            L"dma op: the longest cave wins when several qualify");
    }
    {
        // 0x00 and 0xCC adjacent **cannot** be merged into one segment: the byte on the boundary between them belongs to
        // a different padding type; merging them would treat two regions of different origins as a single continuous gap.
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 300U, 100U, 0x00U);
        carveCave(page, 400U, 100U, 0xCCU);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(kCave.found && kCave.length == 100U,
            L"dma op: runs of different padding bytes are not merged into one cave");
    }
    {
        // Must reject if the length is insufficient, rather than returning the longest segment.
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 800U, kDmaOpMinCaveBytes - 1U, 0x00U);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(!kCave.found,
            L"dma op: a cave one byte short of the minimum is refused, not returned anyway");
        suite.expect(kCave.length == 0U,
            L"dma op: a refused cave carries no length a caller could mistake for usable");
    }
    {
        // Exactly equal to the lower bound: the other side of the boundary must be passed.
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 800U, kDmaOpMinCaveBytes, 0x00U);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(kCave.found && kCave.length == kDmaOpMinCaveBytes,
            L"dma op: a cave exactly at the minimum is accepted");
    }
    {
        // Entire page of real code with no padding.
        const std::vector<std::uint8_t> kPageValue = makePage();
        suite.expect(!findLargestCodeCave(kPageValue, kDmaOpMinCaveBytes).found,
            L"dma op: a page of real code yields no cave");
    }
    {
        // Other repeated bytes are not considered padding. A sequence of all 0x41
        // ('A') is likely string data; treating it as a cave would overwrite the data.
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, 600U, 400U, 0x41U);
        suite.expect(!findLargestCodeCave(page, kDmaOpMinCaveBytes).found,
            L"dma op: a long run of some other repeated byte is not treated as padding");
    }
    {
        // Cave adjacent to page end.
        std::vector<std::uint8_t> page = makePage();
        carveCave(page, kPage - 128U, 128U, 0x00U);
        const auto kCave = findLargestCodeCave(page, kDmaOpMinCaveBytes);
        suite.expect(kCave.found && kCave.offset == kPage - 128U && kCave.length == 128U,
            L"dma op: a cave that ends exactly at the page end is found with the right length");
    }
}

// ------------------------------------------------------------
// II. Fill gap + backup.
// ------------------------------------------------------------
void testPlanIntoCave(ksword_tests::Suite& suite) {
    std::vector<std::uint8_t> page = makePage();
    carveCave(page, 1500U, 256U, 0x00U);
    const std::vector<std::uint8_t> kPayload{0x90U, 0x48U, 0x31U, 0xC0U, 0xC3U};

    const auto kPlan = planPayloadIntoCave(page, kPayload, kDmaOpMinCaveBytes);
    suite.expect(kPlan.status == DmaOpPlanStatus::kOk,
        L"dma op: a payload that fits the cave plans successfully");
    suite.expect(kPlan.offsetInPage == 1500U,
        L"dma op: the payload is placed at the cave's offset");
    suite.expect(kPlan.bytesToWrite == kPayload,
        L"dma op: the planned bytes are exactly the payload");
    // Backup must match the write length and contain exactly **that segment** of original bytes.
    suite.expect(kPlan.originalBytes.size() == kPayload.size(),
        L"dma op: the backup is the same length as the write");
    bool backupCorrect = true;
    for (std::size_t i = 0U; i < kPayload.size(); ++i) {
        if (kPlan.originalBytes[i] != page[1500U + i]) {
            backupCorrect = false;
        }
    }
    suite.expect(backupCorrect,
        L"dma op: the backup holds the bytes actually about to be overwritten");

    // Payload exceeds the cavity length: must reject. Forcing a write that doesn't fit will overwrite the real code following the cavity.
    std::vector<std::uint8_t> page2 = makePage();
    carveCave(page2, 2000U, 100U, 0x00U);
    const std::vector<std::uint8_t> kBig(150U, 0x90U);
    suite.expect(planPayloadIntoCave(page2, kBig, kDmaOpMinCaveBytes).status
            == DmaOpPlanStatus::kNoCave,
        L"dma op: a payload longer than every cave is refused");

    // Empty payload, invalid page length.
    suite.expect(planPayloadIntoCave(page, {}, kDmaOpMinCaveBytes).status
            == DmaOpPlanStatus::kEmptyPayload,
        L"dma op: an empty payload is refused");
    suite.expect(planPayloadIntoCave({}, kPayload, kDmaOpMinCaveBytes).status
            == DmaOpPlanStatus::kPageBytesUnavailable,
        L"dma op: planning without the page contents is refused, since there is no backup");
    suite.expect(planPayloadIntoCave(std::vector<std::uint8_t>(100U, 0U), kPayload,
            kDmaOpMinCaveBytes).status == DmaOpPlanStatus::kPageBytesWrongSize,
        L"dma op: page contents of the wrong length are refused");
}

// ------------------------------------------------------------
// III. Fixed-point write and page boundary.
// ------------------------------------------------------------
void testPlanAtOffset(ksword_tests::Suite& suite) {
    const std::vector<std::uint8_t> kPageValue = makePage();
    const std::vector<std::uint8_t> kUd2 = undefinedInstructionBytes();

    suite.expect(kUd2.size() == 2U && kUd2[0] == 0x0FU && kUd2[1] == 0x0BU,
        L"dma op: the undefined instruction is exactly 0F 0B (UD2)");
    // Deliberately not 0xCC: int3 causes a target with a debugger attached to pause rather
    // than exit, and 'paused' and 'exited' appear as the same result on the interface.
    suite.expect(kUd2[0] != 0xCCU,
        L"dma op: int3 is deliberately not used, since a debugger would swallow it");

    const auto kPlan = planBytesAtOffset(kPageValue, 1234U, kUd2);
    suite.expect(kPlan.status == DmaOpPlanStatus::kOk && kPlan.offsetInPage == 1234U,
        L"dma op: a targeted write plans at the requested offset");
    suite.expect(kPlan.originalBytes.size() == 2U
        && kPlan.originalBytes[0] == kPageValue[1234U]
        && kPlan.originalBytes[1] == kPageValue[1235U],
        L"dma op: a targeted write backs up exactly what it overwrites");

    // Test both sides of the page boundary.
    suite.expect(planBytesAtOffset(kPageValue, kPage - 2U, kUd2).status == DmaOpPlanStatus::kOk,
        L"dma op: a write ending exactly at the page end is allowed");
    suite.expect(planBytesAtOffset(kPageValue, kPage - 1U, kUd2).status
            == DmaOpPlanStatus::kWouldCrossPage,
        L"dma op: a write that would cross the page boundary by one byte is refused");
    suite.expect(planBytesAtOffset(kPageValue, kPage, kUd2).status
            == DmaOpPlanStatus::kOffsetOutOfPage,
        L"dma op: an offset at the page end is out of the page");

    // Huge length: the out-of-bounds check must be written as "insufficient remaining space"; writing "start + length
    // > page length" would cause integer wraparound here, and the comparison after wraparound would incorrectly pass.
    const std::vector<std::uint8_t> kHuge(kPage, 0x90U);
    suite.expect(planBytesAtOffset(kPageValue, 4000U, kHuge).status
            == DmaOpPlanStatus::kWouldCrossPage,
        L"dma op: a length that would wrap the offset arithmetic is still refused");
}

// ------------------------------------------------------------
// IV. Readback verification — DMA writes provide no self-verification.
// ------------------------------------------------------------
void testReadbackVerification(ksword_tests::Suite& suite) {
    const std::vector<std::uint8_t> kIntended{0x0FU, 0x0BU, 0x90U, 0x90U};

    const auto kGood = verifyWriteReadback(kIntended, kIntended);
    suite.expect(kGood.matched && kGood.comparedBytes == 4U,
        L"dma op: an identical readback verifies");

    std::vector<std::uint8_t> wrong = kIntended;
    wrong[2] = 0xCCU;
    const auto kBad = verifyWriteReadback(kIntended, wrong);
    suite.expect(!kBad.matched,
        L"dma op: a differing readback does not verify");
    suite.expect(kBad.firstMismatchOffset == 2U && kBad.expectedByte == 0x90U
        && kBad.actualByte == 0xCCU,
        L"dma op: the first mismatch reports its offset and both bytes");

    // A short readback and different content are distinct issues: the former indicates a problem with the readback path, while the latter indicates the write did not land.
    const auto kShortRead = verifyWriteReadback(kIntended, {0x0FU, 0x0BU});
    suite.expect(!kShortRead.matched && kShortRead.readbackTooShort,
        L"dma op: a short readback is reported as short, not merely as different");
    suite.expect(kShortRead.comparedBytes == 2U,
        L"dma op: a short readback reports how much could be compared");

    // When the prefix is incorrect, report the mismatch even if the readback is short—both issues may exist simultaneously.
    const auto kShortAndWrong = verifyWriteReadback(kIntended, {0x0FU, 0xFFU});
    suite.expect(kShortAndWrong.readbackTooShort && kShortAndWrong.firstMismatchOffset == 1U,
        L"dma op: a readback that is both short and wrong reports both facts");

    // Note: Reporting 'verification passed' without any write is the worst case: an empty operation should not appear successful.
    suite.expect(!verifyWriteReadback({}, {}).matched,
        L"dma op: verifying an empty write never reports success");
}


// ------------------------------------------------------------
// 5. Whether the target page is shared by other processes — the most critical criterion in this module.
// ------------------------------------------------------------
void testTargetSharing(ksword_tests::Suite& suite) {
    using ksword::evidence::DmaTargetSharing;
    using ksword::evidence::evaluateTargetSharing;

    // MEM_PRIVATE: Not backed by a section object, cannot be shared, no cross-process comparison needed.
    suite.expect(evaluateTargetSharing(true, false, false)
            == DmaTargetSharing::kPrivateConfirmed,
        L"dma op: a private region is private without needing a cross-process comparison");
    suite.expect(evaluateTargetSharing(true, true, true)
            == DmaTargetSharing::kPrivateConfirmed,
        L"dma op: a private region stays private whatever the comparison said");

    // If compared and physical addresses match, it is the same page = shared. This is the only true reading.
    suite.expect(evaluateTargetSharing(false, true, true)
            == DmaTargetSharing::kSharedConfirmed,
        L"dma op: another process resolving to the same physical page confirms sharing");

    // If compared but physical addresses differ, copy-on-write has occurred; this process holds its own copy.
    suite.expect(evaluateTargetSharing(false, true, false)
            == DmaTargetSharing::kPrivateConfirmed,
        L"dma op: a differing physical address means copy-on-write already happened");

    // **The most critical rule**: not having been compared does not imply private. Not finding a second process does not mean it doesn't exist;
    // Just because no other process maps it now does not mean it won't be mapped in the next moment. Interpreting this entry
    // as "Private" is exactly the error this check aims to prevent; if it occurs, the consequence affects the entire machine.
    suite.expect(evaluateTargetSharing(false, false, false)
            == DmaTargetSharing::kSharingUnknown,
        L"dma op: not having compared is never reported as private");
    suite.expect(evaluateTargetSharing(false, false, true)
            == DmaTargetSharing::kSharingUnknown,
        L"dma op: a matched flag without an actual comparison is still unknown");

    // The three states must be mutually distinct; otherwise, handling one branch by the caller will inadvertently consume another.
    suite.expect(DmaTargetSharing::kPrivateConfirmed != DmaTargetSharing::kSharingUnknown
        && DmaTargetSharing::kSharedConfirmed != DmaTargetSharing::kSharingUnknown,
        L"dma op: the three sharing verdicts are distinct states, not two plus a synonym");
}

}  // namespace

int runDmaProcessOpPlanTests() {
    ksword_tests::Suite suite(L"DMA process op plan");
    testCaveDiscovery(suite);
    testPlanIntoCave(suite);
    testPlanAtOffset(suite);
    testReadbackVerification(suite);
    testTargetSharing(suite);
    suite.report();
    return suite.failures();
}

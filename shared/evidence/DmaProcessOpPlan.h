#pragma once

// DMA-based process operations — planning and validation layer.
//
// This layer answers three questions, all purely arithmetic with no I/O:
//   1. Whether there is a safe writable gap on this page, and where it is located;
//   2. Specify which bytes to overwrite in a single write operation and what the original values were (for backup);
//   3. Verify the correctness of the written data after reading it back.
//
// Why it must be a separate layer and undergo exhaustive testing: miscalculations do not trigger errors. An incorrect gap-finding
// logic overwrites actual code, causing the target process to crash immediately due to our actions. An incorrect coverage range
// calculation crosses page boundaries; since DMA granularity is one page, the crossed-over page could contain anything.
//
// ============================================================
// The essential difference from R-1 injection (not merely 'changing the backend'; the caller must be made aware).
// ============================================================
//
// R-1 injection (KSWORD_ARK_HVM_INJECT) places the payload in **shadow pages** and installs an execution view:
// Execution follows the shadow path, reading/writing/seeing the real page. The real page remains unmodified
// from start to finish, so any scanner reads the original state, and there is a clear trigger point.
//
// DMA has no shadow pages, no execution views, and no triggers. It has only one function: writing bytes to physical pages.
// Thus:
//   * **The real page was truly modified**. Any read path can see it, including our own R3/R0/HVM.
//   * **Not triggered**. The payload lies dormant, waiting for the target to execute it.
//     Writing to a location that will never be executed is equivalent to doing nothing.
//   * **Restoration is the caller's responsibility**. This layer therefore mandates producing backup bytes; without them, restoration is impossible.
//
// ============================================================
// Regarding the "end" ud2 instruction.
// ============================================================
//
// DMA cannot call PsTerminateProcess. Writing a ud2 instruction (0F 0B) to the code the target will execute to force
// an unhandled exception exit is the only method available to DMA that does not rely on kernel structure offsets.
//
// It is **not a reliable terminate**; the naming at this layer is deliberately not "Terminate":
//   * The target may have exception handlers (SEH/VEH) that swallow #UD, so it does not crash, only behaves differently;
//   * Whether it takes effect depends on whether that code block is executed; it cannot be determined in advance.
//   * Will leave crash dumps and event logs;
//   * Irreversible unless the caller writes it back using a backup.
//
// C++20、Qt-free、Win32-free。

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

// DMA transfer granularity is one page; all plans must fit within a single page.
inline constexpr std::uint64_t kDmaOpPageBytes = 4096ULL;

// Minimum gap length. This matches KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES used for R-1
// injection for the same reason: gaps shorter than this are likely not padding but
// coincidentally identical bytes in actual code; writing into them would corrupt the target.
inline constexpr std::size_t kDmaOpMinCaveBytes = 64U;

// DmaOpPlanStatus: Result of a single plan.
//
// Each rejection is an independent status rather than a unified false: the caller uses
// this to tell the user what to fix; the phrase 'Plan Failed' is unhelpful to anyone.
enum class DmaOpPlanStatus : int {
    kOk = 0,
    kEmptyPayload,          // Payload length is 0.
    kPayloadTooLarge,       // Payload exceeds one page or the available gap.
    kPageBytesUnavailable,  // Without the current content of the target page, neither backup nor gap detection is possible.
    kPageBytesWrongSize,    // Provided page content length does not equal one page.
    kOffsetOutOfPage,       // Specified page offset is outside the page.
    kWouldCrossPage,        // The write range crosses a page boundary.
    kNoCave,                // No gap long enough found within the page.
};

const char* dmaOpPlanStatusName(DmaOpPlanStatus status) noexcept;

// DmaCodeCave: A writable gap within a page.
struct DmaCodeCave final {
    bool found = false;
    std::size_t offset = 0;   // Offset within a page.
    std::size_t length = 0;
    std::uint8_t fillByte = 0; // Padding bytes (0x00 or 0xCC) that make up this gap.
};

// findLargestCodeCave：
// - Within one page of bytes, find the **longest** contiguous run of a single fill byte;
// - Only recognizes 0x00 and 0xCC as fill bytes: these are the alignment padding actually produced by the linker and compiler.
//   Any other repeated bytes might be actual data (e.g., a string
//   of all 0x41s); treating them as gaps would overwrite real data.
// - If length is less than minLength, return found = false; do not return 'the longest one'—this prevents the
//   caller from writing into an insufficient gap, which would be equivalent to writing directly into valid code.
DmaCodeCave findLargestCodeCave(
    const std::vector<std::uint8_t>& pageBytes,
    std::size_t minLength);

// DmaWritePlan: Complete write plan for a single operation.
struct DmaWritePlan final {
    DmaOpPlanStatus status = DmaOpPlanStatus::kPageBytesUnavailable;
    std::size_t offsetInPage = 0;
    std::vector<std::uint8_t> bytesToWrite;
    // originalBytes: The original bytes to be overwritten, **same length as bytesToWrite**.
    // This is the sole basis for restoration, so it is a required struct member
    // rather than optional: do not initiate the write if the backup is unavailable.
    std::vector<std::uint8_t> originalBytes;
};

// planPayloadIntoCave：
// - Find a gap within the page and insert the payload;
// - Backup the original bytes that will be overwritten.
DmaWritePlan planPayloadIntoCave(
    const std::vector<std::uint8_t>& pageBytes,
    const std::vector<std::uint8_t>& payload,
    std::size_t minCaveBytes);

// planBytesAtOffset：
// - Perform a single write at the specified page offset without searching for gaps.
// - Used for callers that already know the exact address, such as "write ud2 to this specific address".
DmaWritePlan planBytesAtOffset(
    const std::vector<std::uint8_t>& pageBytes,
    std::size_t offsetInPage,
    const std::vector<std::uint8_t>& bytes);

// kUndefinedInstruction: x86 UD2 instruction, 2 bytes, guaranteed to trigger #UD.
//
// Intentionally avoiding int3 (0xCC): that's a breakpoint. A process with an attached debugger will pause
// instead of exiting. On the interface, "the target paused" and "the target exited" appear as the same result.
std::vector<std::uint8_t> undefinedInstructionBytes();

// ============================================================
// Whether the target page is shared by other processes.
// ============================================================
//
// This is the most severe criterion in this module. DMA writes to **physical pages**, while Copy-on-Write
// relies on page faults—**DMA does not trigger page faults**. Thus, writing a byte to a shared image page
// (any DLL code page) affects **every process mapping it**, not just the target. Writing a UD2 instruction
// to an ntdll code page causes all processes on the machine to crash when they reach that address.
//
// Inferring solely from region type is speculative rather than based on actual data: a MEM_IMAGE page may have
// already become a private copy of this process due to copy-on-write, meaning writes affect only the target;
// alternatively, it may still be a shared page. Both cases appear identical in MEMORY_BASIC_INFORMATION.
//
// The sole metric for cross-process comparison is physical addresses: translating the same virtual address in another process
// mapping the same file yields the same physical address if and only if they share the same page, indicating sharing.
enum class DmaTargetSharing : int {
    // The region is private to the process, or cross-process comparison proves different physical addresses (copy-on-write has occurred).
    kPrivateConfirmed = 0,
    // Cross-process comparison to prove that the same virtual address in another process maps to the same physical page.
    kSharedConfirmed,
    // The region is backed by a section object, but no second process was found for comparison. **Not 'Private'**:
    // Not finding something does not mean it does not exist; the fact that no other process maps it now does not mean it won't be mapped in the next moment.
    kSharingUnknown,
};

const char* dmaTargetSharingName(DmaTargetSharing sharing) noexcept;

// evaluateTargetSharing：
// - regionIsPrivate: whether the target region's type is MEM_PRIVATE;
// - comparisonPerformed: whether the same virtual address was actually translated in another process.
// - comparisonMatched: whether the physical address obtained by that process matches the target
//
// The three inputs are kept separate rather than combined into a single bool: 'not compared' and 'compared but different' are
// entirely distinct cases. Merging them would cause 'no other process found' to be misinterpreted as 'confirmed private'.
DmaTargetSharing evaluateTargetSharing(
    bool regionIsPrivate,
    bool comparisonPerformed,
    bool comparisonMatched) noexcept;

// DmaWriteVerification: Comparison result after writing and reading back.
struct DmaWriteVerification final {
    bool matched = false;
    std::size_t comparedBytes = 0;
    std::size_t firstMismatchOffset = 0;  // Relative to the write start point.
    std::uint8_t expectedByte = 0;
    std::uint8_t actualByte = 0;
    // readbackTooShort: The number of bytes read back is fewer than the number written. This is distinct from 'content mismatch'.
    // The former indicates a problem with the read-back path itself, while the latter indicates that the write did not land.
    bool readbackTooShort = false;
};

// verifyWriteReadback：
// - Compare read-back bytes with intended write bytes byte-by-byte.
//
// Why this step is mandatory rather than optional diagnostics: DMA writes have no self-verification. A driver reporting
// writeStatus=OK only confirms the command was accepted, not that the target physical page actually changed. A silent
// failed write and a successful write appear identical on the UI, yet the caller will assume the payload is in place.
DmaWriteVerification verifyWriteReadback(
    const std::vector<std::uint8_t>& intendedBytes,
    const std::vector<std::uint8_t>& readbackBytes);

}  // namespace ksword::evidence

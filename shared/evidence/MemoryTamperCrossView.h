#pragma once

// Memory content cross-view: detects inconsistencies between 'content read by the CPU' and 'content read bypassing the CPU'.
//
// Division of labor with CrossViewDiff.h: that layer compares **whether objects exist** (process, driver, or device objects are hidden),
// while this layer compares **the content of the same memory region**. Both share the same hard rules but yield different conclusion types.
//
// Why is this layer needed:
// - SLAT/EPT-level hiding: does not modify page tables, does not modify content checksums, and leaves no traces at the API level.
//   It causes the processor to fetch instructions from the real page but read data from the shadow page.
//   Thus, all reads via the CPU—ReadProcessMemory, MmCopyVirtualMemory, or even reads via physical address
//   mapping—see the "clean" bytes in the shadow page, while the actually executed code has been modified.
// - 'Memory vs. Disk Image' alone cannot detect it: the shadow page contains the exact original bytes from
//   disk, so the comparison result will be a perfect match. Such hiding can only be exposed via a read path
//   that bypasses the CPU page tables; in this project, that path is DDMA (Disk Controller Bus Master DMA).
//
// Three hard rules spanning this module (same origin as the X module):
// - T-01: Read failure, channel unavailable, or range not covered are all **not** "this page was not tampered with". When fewer than
//   two comparable views are available, the conclusion must be Inconclusive; it is strictly forbidden to downgrade to Consistent.
// - T-02: A one-time inconsistency does not constitute a conclusion. Memory may be undergoing legitimate writes at any moment (self-modifying code,
//   hot patches, data pages being written); race conditions within the sampling window can produce differences indistinguishable from tampering.
//   Must perform multiple rounds of resampling; only promote to a conclusion if **every round is inconsistent**.
// - T-03: Bytes that cannot be read are always marked as missing and are not padded with 00 for comparison. Padding
//   with zeros would disguise "not read" as "read 0", thereby fabricating a difference or fabricating a match.
//
// This layer does not recognize rootkits nor produce malicious verdicts: it only answers which read paths
// yield different results for the same memory region, and which known pattern the divergence falls into.
//
// C++20、Qt-free、Win32-free。

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

// TamperReadPath: The read path involved in the comparison.
//
// The grouping is the core criterion, not for classification convenience: the first four paths all undergo CPU address translation, so **they will be
// deceived together by SLAT/EPT**; DDMA uses the disk controller's DMA and bypasses the CPU page table; the last two are static references that do
// not reflect the current memory state. Only discrepancies across groups indicate the issue; discrepancies within a group indicate something else.
enum class TamperReadPath : int {
    kUserModeVirtual = 0,  // R3: ReadProcessMemory. Affected by handle permissions and user-mode hooks.
    kKernelVirtual,        // R0: MmCopyVirtualMemory. Bypasses handle permissions while still traversing the CPU page tables.
    kKernelPhysical,       // R0: first translate VA to PA, then read by physical address. Memory access is still initiated by the CPU.
    // HVM: Rewrite page table entries to point to target frames, **without invoking any documented memory manager routines**.
    // It belongs to the CPU group along with the three above—named ring-1—but is implemented in a PASSIVE_LEVEL
    // driver context without entering VMX root, still subject to SLAT/EPT constraints. Grouping it into the DMA
    // category would add an invalid piece of evidence to the conclusion that 'the CPU view is redirected'.
    // Its independence is a separate matter: other drivers hooking MmCopyMemory cannot hook onto it.
    kHvmPrivateWindow,
    kDmaPhysical,          // DDMA: Disk controller DMA reads the same physical page. **Does not go through CPU page tables**.
    kImageSectionClean,    // Clean reference pages for section objects. Static reference, not current memory state.
    kOnDiskImage,          // Corresponding location in the disk file. Static reference, not current memory state.
};

const char* tamperReadPathName(TamperReadPath path) noexcept;

// TamperPathGroup: The group to which the path belongs, determining how a divergence is interpreted.
enum class TamperPathGroup : int {
    kCpuMediated,   // Affected by SLAT/EPT after CPU address translation.
    kDmaMediated,   // Bypass CPU page tables.
    kStaticReference, // Static reference, independent of current memory state.
};

TamperPathGroup groupOf(TamperReadPath path) noexcept;

// TamperSampleStatus: The result of a path within a single sampling round.
//
// Four states instead of bool: 'unable to read', 'did not attempt to read', and 'out of coverage range' are three
// distinct conditions. Collapsing them into 'no data' would degrade 'unable to determine' into 'no issue found'.
enum class TamperSampleStatus : int {
    kNotAttempted = 0,  // This path was not taken in this round (user did not select it or preconditions were not met).
    kUnavailable,       // The channel itself is unavailable (DDMA not configured or driver not loaded).
    kFailed,            // Collection attempted but failed (read denied, VA translation failed, or target process exited).
    kOutOfCoverage,     // Success but does not cover this segment (no corresponding section in the disk image).
    kRead,              // Read successfully; bytes are valid.
};

const char* tamperSampleStatusName(TamperSampleStatus status) noexcept;

// TamperViewSample: An observation of a path within a single sampling round.
struct TamperViewSample final {
    TamperReadPath path = TamperReadPath::kUserModeVirtual;
    TamperSampleStatus status = TamperSampleStatus::kNotAttempted;
    std::vector<std::uint8_t> bytes;  // Only meaningful when status == Read.
    std::string failureText;          // For direct display by the UI; no secondary translation.
};

// TamperRound: A single sampling round. Paths within the same round should be as close to the same moment as possible, and
// rounds should be spaced sufficiently apart; otherwise, T-02's resampling cannot effectively exclude race conditions.
struct TamperRound final {
    std::vector<TamperViewSample> views;
};

// TamperVerdict: cross-view conclusion for a memory segment.
enum class TamperVerdict : int {
    // Fewer than two comparable paths exist, or there are discrepancies but not in every round. **Not 'clean'.**
    kInconclusive = 0,
    // All comparable paths are byte-for-byte consistent.
    kConsistent,
    // Persistent inconsistency between CPU and DMA paths. This is a characteristic of SLAT/EPT
    // redirection: the content read by the processor differs from the actual content in memory.
    kCpuViewRedirected,
    // Persistent inconsistency between R3 and R0, while DMA (if present) is consistent with R0. The user-mode read path is hooked.
    kUserModeViewDiffers,
    // All live paths are consistent with each other but differ from the static reference. Memory was indeed
    // tampered with, and nothing is hidden — this is the signature of a standard inline hook or patch.
    kLiveDiffersFromReference,
    // Persistent disagreement exists, but does not match any of the above patterns.
    kUnexplainedDisagreement,
};

const char* tamperVerdictName(TamperVerdict verdict) noexcept;

// TamperDisagreement: A single discrepancy between a pair of paths.
struct TamperDisagreement final {
    TamperReadPath left = TamperReadPath::kUserModeVirtual;
    TamperReadPath right = TamperReadPath::kUserModeVirtual;
    std::size_t firstDifferingOffset = 0;  // Offset within segment.
    std::size_t differingByteCount = 0;
    std::uint8_t leftByte = 0;
    std::uint8_t rightByte = 0;
    // persistentRounds / comparableRounds: The pair indicates how many rounds were
    // comparable and how many disagreed. T-02 is satisfied only if both are equal and > 1.
    int comparableRounds = 0;
    int disagreeingRounds = 0;
};

// TamperFinding: Complete conclusion for a memory segment.
struct TamperFinding final {
    TamperVerdict verdict = TamperVerdict::kInconclusive;
    // comparableRoundCount: Number of rounds where at least two paths successfully read simultaneously.
    int comparableRoundCount = 0;
    // Status of the last round for each path, used by the UI to explain "why a certain view is missing".
    std::vector<TamperViewSample> lastRoundStatus;
    std::vector<TamperDisagreement> disagreements;
    // inconclusiveReason: When verdict == Inconclusive, specify exactly where the process got stuck,
    // ensuring that "unable to determine" and "no issues found" are never visually confused in the UI.
    std::string inconclusiveReason;
    // cpuMatchesStaticReference: meaningful when CpuViewRedirected is true. If true, the CPU side
    // reads the original bytes from disk or the section object, while the DMA side reads tampered
    // bytes—exactly the effect the hider wants and the most credible shape for this conclusion.
    bool cpuMatchesStaticReference = false;
};

// analyzeTamperRounds：
// - Input: several sampling rounds;
// - Processing: Compare and classify divergence patterns pairwise according to T-01 / T-02 / T-03.
// - Returns: Conclusion and an auditable list of discrepancies.
//
// This function performs no I/O and does not understand PE structures: if the caller intends to use
// a disk image as a reference view, it must first normalize relocations and IATs using PeImageMap
// or ImageDiff before passing it in; otherwise, every normal load will be reported as a difference.
TamperFinding analyzeTamperRounds(const std::vector<TamperRound>& rounds);

}  // namespace ksword::evidence

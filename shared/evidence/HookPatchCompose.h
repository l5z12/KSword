#pragma once

// Patch page construction for HOOK view — pure arithmetic layer.
//
// Note: This layer does not recognize drivers or Qt, does not issue IOCTLs, and only answers four questions provable on the build machine:
// Defines the layout of a shadow byte page, the 5-byte encoding for a near jump, the 14-byte encoding for
// a far jump, and whether a patch fits in the page. Address translation, preconditions, and view assembly
// are handled in upper layers with fallback checks; if these four items fail, no error is raised, but the
// executed page silently becomes garbage. Therefore, they must be hardcoded at compile time.
//
// Note: Why the 'finished page' must be a complete page:
//   The **shadow page** used by the driver-side HOOK is the one actually executed. In steady state, the primary leaf = real page |
//   R | W (no X); in flip state, the secondary leaf = shadow page | X (silently adding R if execute-only capability is missing).
//   Source: drivers/ark/src/features/hvm/hvm_ept_view.c:177-192.
//   Thus, the shadow page is not a "patch fragment" but the full 4096 bytes of "original page bytes + patch": every byte outside
//   the patch interval must match the original page bit-by-bit; otherwise, the processor redirected there will execute garbage.
//
// Why cross-page is directly rejected in this version:
//   Each view in the protocol covers exactly one page, with no PageCount. Under the current flip design, splitting a cross-page patch
//   into two views means the flips for the two pages are independent; any exit in between could cause the guest to execute half an
//   instruction, resulting in a fail-closed state for both backends. Therefore, out-of-bounds errors are reported at this layer.
//
//   **This is not structurally impossible; do not treat it as an impassable wall.** On 2026-09-07, three viable
//   paths were confirmed against the external implementation, none of which are included in this version:
//     (a) Switch to a shorter patch form. DdiMon writes only 1 byte 0xCC, making cross-page scenarios naturally disappear in the most common use case.
//         The cost is intercepting #BP, while our exception bitmap is always 0 (hvm_vmcs.c:1078).
//     (b) Move the patch point forward to the previous instruction boundary so the entire patch falls within the same page.
//     (c) The caller installs/removes them as a pair of single-page views. hyper-reV does this.
//         **No protocol change required**: The previous objection regarding 'two-page flipping being independent'
//         largely becomes invalid on the steady-state shadow side (where flipping no longer occurs on every execution).
//   When releasing across pages, start evaluation from (a), not from (c).
//
// This layer does not perform instruction boundary checks: x86 has variable-length instructions, and linear decoding
// forward from an arbitrary offset is heuristic only. The `InstructionDecoder` in the repository also only supports forward
// decoding. Therefore, whether a "patch cuts an instruction" is neither answered nor pretended to be answered here.
//
// Final note for anyone using this as copy: CLOAK/HOOK is not a security boundary. This layer guarantees only
// correct byte arithmetic and makes no promises about whether patches can defend against a privileged adversary.

#include <array>
#include <cstdint>

namespace ksword::evidence {

// A view that exactly covers one page; page size is a protocol constant, not a tunable parameter.
inline constexpr std::uint32_t kPatchPageBytes = 4096U;

// ---------------------------------------------------------------------------
// Geometry: Does this patch fit within this page?
// ---------------------------------------------------------------------------
enum class CrossPageClassification {
    kInPage,       // [pageOffset, pageOffset + patchLen) falls entirely within this page.
    kCrossesPage,  // Crossing the page end (or the start being outside the page) — the upper layer must reject this and must not split it into two views.
};

const char* crossPageClassificationName(CrossPageClassification classification) noexcept;

// Pure geometric judgment, ignoring patch content and whether the patch is empty. Both pageOffset and patchLen are promoted to 64-bit before addition:
// adding two 32-bit values can wrap around, and the resulting small sum would incorrectly classify an obviously out-of-bounds request as InPage.
CrossPageClassification classifyCrossPage(std::uint32_t pageOffset,
                                          std::uint32_t patchLen) noexcept;

// ---------------------------------------------------------------------------
// Final page
// ---------------------------------------------------------------------------
enum class PatchComposeStatus {
    kOk,
    kOriginalMissing,      // Original page pointer is null.
    kPatchMissing,         // patchLen > 0 but no patch pointer provided.
    kCrossesPageBoundary,  // Geometric out-of-bounds; classifyCrossPage already reports this.
    // An empty patch produces a shadow page identical to the original. Such a HOOK view changes nothing in steady
    // state but makes callers believe the patch is installed. This is a caller error, not a valid identity patch.
    kEmptyPatch,
};

const char* patchComposeStatusName(PatchComposeStatus status) noexcept;

struct ComposedPage final {
    // Defaults to failure state with all-zero bytes: forgetting to check the call site for 'status' yields a
    // page of obviously incorrect zero bytes instead of a page that looks valid but was never constructed.
    PatchComposeStatus status = PatchComposeStatus::kOriginalMissing;
    std::array<std::uint8_t, kPatchPageBytes> bytes{};

    // Echo the request as-is, even when rejecting. The upper layer must write 'you provided offset X, length
    // Y' into the rejection reason; it cannot ask the call site for the value it supposedly remembers.
    std::uint32_t patchOffset = 0;
    std::uint32_t patchLength = 0;

    bool ok() const noexcept { return status == PatchComposeStatus::kOk; }
};

// original must point to kPatchPageBytes readable bytes — this is the caller's contract; this function can only check for null pointers,
// not lengths. After the upper layer assembles a page from R-1 channel fragments, it must first verify that 4096 bytes have been assembled.
//
// The check order is fixed and pinned by unit tests: original page pointer -> patch pointer -> geometry -> empty patch.
// Placing geometry before empty patches ensures composePage and classifyCrossPage always reach consistent
// conclusions for the same parameters (e.g., offset 5000, length 0 both report out-of-bounds).
// For any non-Ok return, keep bytes all zeros to avoid producing 'good enough' partial pages.
ComposedPage composePage(const std::uint8_t* original,
                         std::uint32_t pageOffset,
                         const std::uint8_t* patch,
                         std::uint32_t patchLen) noexcept;

// ---------------------------------------------------------------------------
// Jump encoding
// ---------------------------------------------------------------------------
inline constexpr std::uint32_t kRel32JumpLength = 5U;      // E9 + int32
inline constexpr std::uint32_t kAbsoluteJumpLength = 14U;  // FF 25 + disp32 + 8-byte target

enum class JumpEncodeStatus {
    kOk,
    kDisplacementOutOfRange,  // Displacement cannot fit in int32
};

const char* jumpEncodeStatusName(JumpEncodeStatus status) noexcept;

struct Rel32Jump final {
    JumpEncodeStatus status = JumpEncodeStatus::kDisplacementOutOfRange;
    std::array<std::uint8_t, kRel32JumpLength> bytes{};

    // target - (src + 5), interpreted as a signed value modulo 2^64. Even if out of bounds, fill it in—the upper
    // layer must report the displacement in the rejection reason to explain why a 14-byte absolute jump is required.
    std::int64_t displacement = 0;

    bool ok() const noexcept { return status == JumpEncodeStatus::kOk; }
};

// The displacement base is the next instruction: E9 itself occupies 5 bytes; the processor adds the displacement only after fetching the complete instruction.
// Address arithmetic is performed modulo 2^64, consistent with hardware; a pair of addresses spanning a non-canonical hole
// thus yields a huge displacement and is rejected as-is, rather than wrapping around to an apparently reasonable small number.
Rel32Jump encodeRel32Jump(std::uint64_t srcVa, std::uint64_t targetVa) noexcept;

// FF 25 00000000 + little-endian 8-byte absolute address: RIP-relative indirect jump. disp32 = 0 means
// the 8 bytes immediately following this instruction are used. Thus, the address constant and the jump
// itself reside in the same page, so the patch does not need to allocate writable space elsewhere.
//
// Why it must be provided: The distance between kernel modules often exceeds ±2 GiB. Providing only near jumps causes the
// most common patch form to fail frequently, and these failures tempt developers to modify other areas to work around them.
//
// This encoding never fails, so there is no status bit. Whether the target is canonical or executable
// is not something the encoder can answer; the upper layer must check before installation.
std::array<std::uint8_t, kAbsoluteJumpLength> encodeAbsoluteJump(std::uint64_t targetVa) noexcept;

} // namespace ksword::evidence

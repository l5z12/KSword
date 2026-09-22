#include "HookPatchCompose.h"

namespace ksword::evidence {

const char* crossPageClassificationName(CrossPageClassification classification) noexcept {
    switch (classification) {
    case CrossPageClassification::kInPage:      return "InPage";
    case CrossPageClassification::kCrossesPage: return "CrossesPage";
    }
    // Conservative approach: treat any unrecognized value as out-of-bounds; better to reject an extra patch.
    return "CrossesPage";
}

CrossPageClassification classifyCrossPage(std::uint32_t pageOffset,
                                          std::uint32_t patchLen) noexcept {
    // Promote both operands to 64-bit before adding. In 32-bit arithmetic, 0xFFFFFFFF + 2
    // wraps to 1, which would falsely classify a request exceeding 4 billion bytes as InPage.
    const std::uint64_t kEnd =
        static_cast<std::uint64_t>(pageOffset) + static_cast<std::uint64_t>(patchLen);
    if (kEnd > static_cast<std::uint64_t>(kPatchPageBytes)) {
        return CrossPageClassification::kCrossesPage;
    }
    return CrossPageClassification::kInPage;
}

const char* patchComposeStatusName(PatchComposeStatus status) noexcept {
    switch (status) {
    case PatchComposeStatus::kOk:                  return "Ok";
    case PatchComposeStatus::kOriginalMissing:     return "OriginalMissing";
    case PatchComposeStatus::kPatchMissing:        return "PatchMissing";
    case PatchComposeStatus::kCrossesPageBoundary: return "CrossesPageBoundary";
    case PatchComposeStatus::kEmptyPatch:          return "EmptyPatch";
    }
    return "OriginalMissing";
}

ComposedPage composePage(const std::uint8_t* original,
                         std::uint32_t pageOffset,
                         const std::uint8_t* patch,
                         std::uint32_t patchLen) noexcept {
    ComposedPage result;
    // Echo parameters at the front: every rejection path below must carry the request parameters.
    result.patchOffset = pageOffset;
    result.patchLength = patchLen;

    if (original == nullptr) {
        result.status = PatchComposeStatus::kOriginalMissing;
        return result;
    }
    // When patchLen == 0, a null pointer is not an error; it indicates 'no patch', as explained by EmptyPatch below.
    if (patch == nullptr && patchLen != 0U) {
        result.status = PatchComposeStatus::kPatchMissing;
        return result;
    }
    if (classifyCrossPage(pageOffset, patchLen) == CrossPageClassification::kCrossesPage) {
        result.status = PatchComposeStatus::kCrossesPageBoundary;
        return result;
    }
    if (patchLen == 0U) {
        result.status = PatchComposeStatus::kEmptyPatch;
        return result;
    }

    // Note: First copy the entire page from the original bytes, then overwrite the patch interval. Reversing the order (writing the patch first, then copying the original page)
    // would overwrite the patch. Such an error produces a page of data that still looks like the original and is valid, but installing it results in the patch appearing ineffective.
    for (std::uint32_t i = 0U; i < kPatchPageBytes; ++i) {
        result.bytes[i] = original[i];
    }
    for (std::uint32_t i = 0U; i < patchLen; ++i) {
        result.bytes[pageOffset + i] = patch[i];
    }
    result.status = PatchComposeStatus::kOk;
    return result;
}

const char* jumpEncodeStatusName(JumpEncodeStatus status) noexcept {
    switch (status) {
    case JumpEncodeStatus::kOk:                     return "Ok";
    case JumpEncodeStatus::kDisplacementOutOfRange: return "DisplacementOutOfRange";
    }
    return "DisplacementOutOfRange";
}

Rel32Jump encodeRel32Jump(std::uint64_t srcVa, std::uint64_t targetVa) noexcept {
    Rel32Jump result;

    // Perform modulo 2^64 arithmetic consistent with hardware: srcVa + 5 allows wraparound, and subtracting two addresses also allows wraparound.
    const std::uint64_t kNextVa = srcVa + static_cast<std::uint64_t>(kRel32JumpLength);
    const std::uint64_t kDelta = targetVa - kNextVa;
    // Starting with C++20, converting unsigned to signed is a reinterpretation of the two's complement bit pattern with no implementation-defined behavior.
    result.displacement = static_cast<std::int64_t>(kDelta);

    // Necessary and sufficient condition for encodability: sign-extending the lower 32 bits of delta back to 64 bits must yield delta
    // itself. Expressing this as two intervals places both boundaries explicitly: +0x7FFFFFFF and -0x80000000 are both **valid**.
    constexpr std::uint64_t kPositiveLimit = 0x000000007FFFFFFFULL;
    constexpr std::uint64_t kNegativeLimit = 0xFFFFFFFF80000000ULL;
    if (kDelta > kPositiveLimit && kDelta < kNegativeLimit) {
        result.status = JumpEncodeStatus::kDisplacementOutOfRange;
        return result;  // Keep bytes all zeros to avoid generating a truncated-jump instruction.
    }

    const std::uint32_t kEncoded = static_cast<std::uint32_t>(kDelta & 0xFFFFFFFFULL);
    result.bytes[0] = 0xE9U;  // JMP rel32
    result.bytes[1] = static_cast<std::uint8_t>(kEncoded & 0xFFU);
    result.bytes[2] = static_cast<std::uint8_t>((kEncoded >> 8U) & 0xFFU);
    result.bytes[3] = static_cast<std::uint8_t>((kEncoded >> 16U) & 0xFFU);
    result.bytes[4] = static_cast<std::uint8_t>((kEncoded >> 24U) & 0xFFU);
    result.status = JumpEncodeStatus::kOk;
    return result;
}

std::array<std::uint8_t, kAbsoluteJumpLength> encodeAbsoluteJump(std::uint64_t targetVa) noexcept {
    std::array<std::uint8_t, kAbsoluteJumpLength> bytes{};
    bytes[0] = 0xFFU;  // JMP r/m64（/4）
    // ModRM = 0x25: mod=00, reg=100 (selects /4 for JMP), rm=101. In 64-bit mode, mod=00 with rm=101 means
    // RIP-relative addressing, not 'absolute address disp32'. Writing this incorrectly results in a valid
    // instruction that fetches the jump target from a 32-bit address, making the destination entirely unpredictable.
    bytes[1] = 0x25U;
    // disp32 = 0: The operand is the 8 bytes immediately following these 6 bytes; thus, the address constant is on the same page as the jump.
    bytes[2] = 0x00U;
    bytes[3] = 0x00U;
    bytes[4] = 0x00U;
    bytes[5] = 0x00U;
    for (std::uint32_t i = 0U; i < 8U; ++i) {
        bytes[6U + i] = static_cast<std::uint8_t>((targetVa >> (i * 8U)) & 0xFFULL);
    }
    return bytes;
}

} // namespace ksword::evidence

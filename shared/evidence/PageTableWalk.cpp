#include "PageTableWalk.h"

namespace ksword::evidence {
namespace {

// x64 four-level paging uses a 9-bit index per level.
constexpr std::uint64_t kIndexMask = 0x1FFULL;
constexpr std::uint32_t kShiftPml4 = 39U;
constexpr std::uint32_t kShiftPdpt = 30U;
constexpr std::uint32_t kShiftPd = 21U;
constexpr std::uint32_t kShiftPt = 12U;

constexpr std::uint64_t kEntryBytes = 8ULL;

constexpr std::uint64_t kBitPresent = 1ULL << 0;
constexpr std::uint64_t kBitWritable = 1ULL << 1;
constexpr std::uint64_t kBitUser = 1ULL << 2;
constexpr std::uint64_t kBitLargePage = 1ULL << 7;   // PS
constexpr std::uint64_t kBitPrototype = 1ULL << 10;  // Software PTE: Prototype
constexpr std::uint64_t kBitTransition = 1ULL << 11; // Software PTE: Transition
constexpr std::uint64_t kBitExecuteDisable = 1ULL << 63;

// Physical base address masks corresponding to each page size (starting from bit12/21/30 up to bit51).
constexpr std::uint64_t kFrameMask4KiB = 0x000FFFFFFFFFF000ULL;
constexpr std::uint64_t kFrameMask2MiB = 0x000FFFFFFFE00000ULL;
constexpr std::uint64_t kFrameMask1GiB = 0x000FFFFFC0000000ULL;

// When PS=1, bits below the page frame field and above PAT (bit12) are reserved and must be 0 per hardware requirements.
// 1GiB entries: bit13..29; 2MiB entries: bit13..20.
constexpr std::uint64_t kReservedLow1GiB = 0x000000003FFFE000ULL;
constexpr std::uint64_t kReservedLow2MiB = 0x00000000001FE000ULL;

// Highest bit of the architectural physical-address field. bit52..62 are ignored/protection-key bits and are excluded.
constexpr std::uint64_t kArchAddressMask = 0x000FFFFFFFFFFFFFULL;

std::uint32_t extractIndex(std::uint64_t virtualAddress, std::uint32_t shift) noexcept {
    return static_cast<std::uint32_t>((virtualAddress >> shift) & kIndexMask);
}

// Bitmask for bits below bit51 but above MAXPHYADDR.
// 0 indicates the caller did not provide MAXPHYADDR — this check is explicitly disabled (and correctly marked as unset in
// the result), rather than silently allowing it via a default value. When >= 52, no bits are reserved by the architecture.
std::uint64_t addressReservedMask(std::uint32_t maxPhysAddrBits) noexcept {
    if (maxPhysAddrBits == 0U) {
        return 0ULL;
    }
    std::uint32_t bits = maxPhysAddrBits;
    if (bits < 12U) {
        bits = 12U;  // MAXPHYADDR values below page size do not exist in the architecture; clamp to the lower bound.
    }
    if (bits >= 52U) {
        return 0ULL;
    }
    const std::uint64_t kLow = (1ULL << bits) - 1ULL;
    return kArchAddressMask & ~kLow;
}

// Only meaningful for entries with present=1: when present=0, the remaining bits are OS-defined (M-05).
std::uint64_t reservedMaskForEntry(PageTableLevel level,
                                   bool largePage,
                                   const TranslateOptions& options) noexcept {
    std::uint64_t mask = addressReservedMask(options.maxPhysAddrBits);
    switch (level) {
    case PageTableLevel::kPml4:
        // In 4-level paging, PML4E has no large page format; bit7 is reserved.
        mask |= kBitLargePage;
        break;
    case PageTableLevel::kPdpt:
        if (!options.supports1GiBPages) {
            // Intel SDM: When CPUID.80000001H:EDX.Page1GB == 0, bit7 of the PDPTE is a reserved bit; setting
            // it triggers a reserved-bit #PF. Without this check, when parsing machines that do not support
            // 1GiB pages, we would translate a hardware-invalid table entry into a physical address (M-04).
            mask |= kBitLargePage;
        } else if (largePage) {
            mask |= kReservedLow1GiB;
        }
        break;
    case PageTableLevel::kPd:
        if (largePage) {
            mask |= kReservedLow2MiB;
        }
        break;
    case PageTableLevel::kPt:
        // bit7 of the PTE is PAT, not PS. It is not treated as a reserved bit for large page detection.
        break;
    case PageTableLevel::kNone:
        break;
    }
    return mask;
}

bool readEntry(const PhysicalReader& reader,
               std::uint64_t physicalAddress,
               std::uint64_t& out) {
    if (!reader) {
        return false;
    }
    std::uint8_t buffer[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    if (!reader(physicalAddress, buffer, sizeof(buffer))) {
        return false;
    }
    std::uint64_t value = 0ULL;
    for (std::size_t i = 0; i < sizeof(buffer); ++i) {
        value |= static_cast<std::uint64_t>(buffer[i]) << (8U * i);
    }
    out = value;
    return true;
}

void mergePermissions(EffectivePermissions& permissions,
                      std::uint64_t entry,
                      bool first) noexcept {
    const bool kWritable = (entry & kBitWritable) != 0ULL;
    const bool kUser = (entry & kBitUser) != 0ULL;
    const bool kNx = (entry & kBitExecuteDisable) != 0ULL;
    if (first) {
        permissions.writable = kWritable;
        permissions.userAccessible = kUser;
        permissions.executeDisable = kNx;
        return;
    }
    // Write permission and user accessibility are cumulative AND operations, while NX is a cumulative OR operation — consistent with hardware behavior.
    permissions.writable = permissions.writable && kWritable;
    permissions.userAccessible = permissions.userAccessible && kUser;
    permissions.executeDisable = permissions.executeDisable || kNx;
}

// Unified cleanup when walking to a level fails: never populate physicalAddress.
void failAt(TranslateResult& result,
            TranslationStatus status,
            PageTableLevel level,
            std::uint64_t reservedBits) {
    result.status = status;
    result.failedLevel = level;
    result.reservedBitsSet = reservedBits;
    result.physicalAddress = OptionalU64::unset();
    result.pageFrameBase = OptionalU64::unset();
    result.pageOffset = OptionalU64::unset();
}

} // namespace

const char* pagingModeName(PagingMode mode) noexcept {
    switch (mode) {
    case PagingMode::kLongMode4Level: return "LongMode4Level";
    case PagingMode::kUnsupported:    return "Unsupported";
    }
    return "Unsupported";
}

const char* pageTableLevelName(PageTableLevel level) noexcept {
    switch (level) {
    case PageTableLevel::kNone: return "None";
    case PageTableLevel::kPml4: return "PML4E";
    case PageTableLevel::kPdpt: return "PDPTE";
    case PageTableLevel::kPd:   return "PDE";
    case PageTableLevel::kPt:   return "PTE";
    }
    return "None";
}

const char* translationStatusName(TranslationStatus status) noexcept {
    switch (status) {
    case TranslationStatus::kTranslated:         return "Translated";
    case TranslationStatus::kNotCanonical:       return "NotCanonical";
    case TranslationStatus::kEntryNotPresent:    return "EntryNotPresent";
    case TranslationStatus::kReservedBitSet:     return "ReservedBitSet";
    case TranslationStatus::kPhysicalReadFailed: return "PhysicalReadFailed";
    case TranslationStatus::kUnsupportedMode:    return "UnsupportedMode";
    case TranslationStatus::kContextRejected:    return "ContextRejected";
    }
    return "UnsupportedMode";
}

const char* softwarePteKindName(SoftwarePteKind kind) noexcept {
    switch (kind) {
    case SoftwarePteKind::kTransition: return "Transition";
    case SoftwarePteKind::kPrototype:  return "Prototype";
    case SoftwarePteKind::kPageFile:   return "PageFile";
    case SoftwarePteKind::kDemandZero: return "DemandZero";
    case SoftwarePteKind::kZero:       return "Zero";
    case SoftwarePteKind::kUnknown:    return "Unknown";
    }
    return "Unknown";
}

const char* pageSizeClassName(PageSizeClass size) noexcept {
    switch (size) {
    case PageSizeClass::kSize4KiB: return "4KiB";
    case PageSizeClass::kSize2MiB: return "2MiB";
    case PageSizeClass::kSize1GiB: return "1GiB";
    }
    return "4KiB";
}

std::uint64_t pageSizeBytes(PageSizeClass size) noexcept {
    switch (size) {
    case PageSizeClass::kSize4KiB: return 0x1000ULL;
    case PageSizeClass::kSize2MiB: return 0x200000ULL;
    case PageSizeClass::kSize1GiB: return 0x40000000ULL;
    }
    return 0x1000ULL;
}

bool isCanonicalAddress48(std::uint64_t virtualAddress) noexcept {
    // Level-4 paging uses only the lower 48 bits; bit47 must be sign-extended to bit63.
    const std::uint64_t kUpper = virtualAddress & 0xFFFF000000000000ULL;
    if ((virtualAddress & 0x0000800000000000ULL) != 0ULL) {
        return kUpper == 0xFFFF000000000000ULL;
    }
    return kUpper == 0ULL;
}

SoftwarePteDecode decodeSoftwarePte(std::uint64_t rawEntry) noexcept {
    SoftwarePteDecode decode;
    decode.transitionBit = (rawEntry & kBitTransition) != 0ULL;
    decode.prototypeBit = (rawEntry & kBitPrototype) != 0ULL;

    if (rawEntry == 0ULL) {
        // All-zero entry: mapping was never established. This is not 'page swapped out'; the UI must not reuse the same text for both cases.
        decode.kind = SoftwarePteKind::kZero;
        return decode;
    }
    if (decode.transitionBit && decode.prototypeBit) {
        // The two encoding bits are mutually exclusive in the public software PTE layout; setting both
        // indicates we do not recognize the encoding, so mark as Unknown rather than arbitrarily choosing one.
        decode.kind = SoftwarePteKind::kUnknown;
        return decode;
    }
    if (decode.transitionBit) {
        decode.kind = SoftwarePteKind::kTransition;
        return decode;
    }
    if (decode.prototypeBit) {
        decode.kind = SoftwarePteKind::kPrototype;
        return decode;
    }
    // In MMPTE_SOFTWARE, PageFileHigh occupies bit32..63 and identifies the page's location in the page file.
    // A value of 0 indicates that this entry has no page file location: typically a committed but never-touched demand-zero page (e.g.,
    // entry=0x20, where only the Protection field bit5..9 are set). Previously, any case with a non-zero value where neither of the two
    // encoding bits was set was unconditionally classified as PageFile, and pageFileNumber/pageFileOffset were filled without condition.
    // This effectively fabricated a page file location out of thin air, which is explicitly prohibited by M-05 (no fabricated observations).
    const std::uint64_t kPageFileHigh = rawEntry >> 32U;
    if (kPageFileHigh == 0ULL) {
        decode.kind = SoftwarePteKind::kDemandZero;
        return decode;  // Both OptionalU64 values remain unset.
    }
    decode.kind = SoftwarePteKind::kPageFile;
    decode.pageFileNumber = OptionalU64::of((rawEntry >> 1U) & 0xFULL);
    decode.pageFileOffset = OptionalU64::of(kPageFileHigh);
    return decode;
}

TranslateResult translateVirtualAddress(std::uint64_t virtualAddress,
                                        std::uint64_t pageTableRootPhysical,
                                        const PhysicalReader& reader,
                                        const TranslateOptions& options) {
    TranslateResult result;
    result.virtualAddress = virtualAddress;
    result.mode = options.mode;
    result.supports1GiBPages = options.supports1GiBPages;
    if (options.maxPhysAddrBits != 0U) {
        // This check only takes effect and is recorded in the result if the caller actually provides MAXPHYADDR.
        result.effectiveMaxPhysAddrBits = OptionalU64::of(options.maxPhysAddrBits);
    }

    if (options.mode != PagingMode::kLongMode4Level) {
        // M-04: Unsupported modes are explicitly rejected. LA57 five-level paging is not implemented here, so this
        // code path is taken. Never guess based on four-level paging—the resulting physical address would be forged.
        failAt(result, TranslationStatus::kUnsupportedMode, PageTableLevel::kNone, 0ULL);
        return result;
    }
    if (!isCanonicalAddress48(virtualAddress)) {
        failAt(result, TranslationStatus::kNotCanonical, PageTableLevel::kNone, 0ULL);
        return result;
    }

    const std::uint64_t kAddressReserved = addressReservedMask(options.maxPhysAddrBits);
    // The lower 12 bits of the root in CR3 are PCID/PWT/PCD, not address bits; mask them according to the architecture instead of treating them as errors.
    // But if the address above MAXPHYADDR is set, the value could not have come from hardware.
    if ((pageTableRootPhysical & kAddressReserved) != 0ULL) {
        // If the root is invalid, no level should be traversed; failedLevel remaining as None indicates 'not yet entered PML4E'.
        failAt(result,
               TranslationStatus::kReservedBitSet,
               PageTableLevel::kNone,
               pageTableRootPhysical & kAddressReserved);
        result.pageTableRootPhysical = OptionalU64::of(pageTableRootPhysical);
        return result;
    }
    result.pageTableRootPhysical = OptionalU64::of(pageTableRootPhysical);

    struct LevelPlan final {
        PageTableLevel level;
        std::uint32_t shift;
    };
    const LevelPlan kPlan[4] = {
        {PageTableLevel::kPml4, kShiftPml4},
        {PageTableLevel::kPdpt, kShiftPdpt},
        {PageTableLevel::kPd, kShiftPd},
        {PageTableLevel::kPt, kShiftPt},
    };

    std::uint64_t tableBase = pageTableRootPhysical & kFrameMask4KiB;
    bool firstLevel = true;

    for (const LevelPlan& step : kPlan) {
        PageTableEntryEvidence evidence;
        evidence.level = step.level;
        evidence.index = extractIndex(virtualAddress, step.shift);
        evidence.entryPhysicalAddress =
            tableBase + (static_cast<std::uint64_t>(evidence.index) * kEntryBytes);

        std::uint64_t raw = 0ULL;
        if (!readEntry(reader, evidence.entryPhysicalAddress, raw)) {
            // If the read fails, it fails. The entry's physical address and index are retained so the UI can indicate which level failed.
            result.levels.push_back(evidence);
            failAt(result, TranslationStatus::kPhysicalReadFailed, step.level, 0ULL);
            return result;
        }
        evidence.read = true;
        evidence.rawValue = raw;
        evidence.present = (raw & kBitPresent) != 0ULL;
        // PS bit is interpreted as large page only in PDPTE/PDE; the same bit in PTE represents PAT.
        evidence.largePage = (step.level == PageTableLevel::kPdpt || step.level == PageTableLevel::kPd)
                                 ? ((raw & kBitLargePage) != 0ULL)
                                 : false;

        if (!evidence.present) {
            // M-05: Non-resident entries never produce a physical address; only decode the software PTE to explain why.
            result.levels.push_back(evidence);
            result.softwarePteDecoded = true;
            result.softwarePte = decodeSoftwarePte(raw);
            failAt(result, TranslationStatus::kEntryNotPresent, step.level, 0ULL);
            return result;
        }

        const std::uint64_t kReservedMask =
            reservedMaskForEntry(step.level, evidence.largePage, options);
        const std::uint64_t kViolated = raw & kReservedMask;
        if (kViolated != 0ULL) {
            // M-04: Reserved bit violation is not a 'valid mapping'. Previously, R0 only checked the P bit and treated it as a valid mapping.
            evidence.reservedBitsSet = kViolated;
            result.levels.push_back(evidence);
            failAt(result, TranslationStatus::kReservedBitSet, step.level, kViolated);
            return result;
        }

        mergePermissions(result.permissions, raw, firstLevel);
        firstLevel = false;
        result.levels.push_back(evidence);

        if (evidence.largePage) {
            const PageSizeClass kSizeClass = (step.level == PageTableLevel::kPdpt)
                                                ? PageSizeClass::kSize1GiB
                                                : PageSizeClass::kSize2MiB;
            if (kSizeClass == PageSizeClass::kSize1GiB && !options.supports1GiBPages) {
                // Double insurance: The reserved bit mask above already blocks such entries as ReservedBitSet.
                // This acts as a second barrier: without 1GiB capability, we never produce a 1GiB physical
                // address. Even if the mask is relaxed later, forged physical addresses will not leak (M-04).
                failAt(result, TranslationStatus::kReservedBitSet, step.level, kBitLargePage);
                return result;
            }
            const std::uint64_t kFrameMask =
                (kSizeClass == PageSizeClass::kSize1GiB) ? kFrameMask1GiB : kFrameMask2MiB;
            const std::uint64_t kFrame = raw & kFrameMask;
            const std::uint64_t kOffset = virtualAddress & (pageSizeBytes(kSizeClass) - 1ULL);
            result.pageSize = kSizeClass;
            result.pageFrameBase = OptionalU64::of(kFrame);
            result.pageOffset = OptionalU64::of(kOffset);
            result.physicalAddress = OptionalU64::of(kFrame | kOffset);
            result.status = TranslationStatus::kTranslated;
            result.failedLevel = PageTableLevel::kNone;
            return result;
        }

        tableBase = raw & kFrameMask4KiB;
    }

    // Completed four-level walk with the final level being a normal PTE.
    const std::uint64_t kFrame = result.levels.back().rawValue & kFrameMask4KiB;
    const std::uint64_t kOffset = virtualAddress & (pageSizeBytes(PageSizeClass::kSize4KiB) - 1ULL);
    result.pageSize = PageSizeClass::kSize4KiB;
    result.pageFrameBase = OptionalU64::of(kFrame);
    result.pageOffset = OptionalU64::of(kOffset);
    result.physicalAddress = OptionalU64::of(kFrame | kOffset);
    result.status = TranslationStatus::kTranslated;
    result.failedLevel = PageTableLevel::kNone;
    return result;
}

// ---------------------------------------------------------------------------
// M-03 Context
// ---------------------------------------------------------------------------

const char* contextValidityName(ContextValidity validity) noexcept {
    switch (validity) {
    case ContextValidity::kUsable:                     return "Usable";
    case ContextValidity::kRejectProcessExited:        return "RejectProcessExited";
    case ContextValidity::kRejectIdentityMismatch:     return "RejectIdentityMismatch";
    case ContextValidity::kRejectIdentityUnverifiable: return "RejectIdentityUnverifiable";
    case ContextValidity::kRejectNoPageTableRoot:      return "RejectNoPageTableRoot";
    case ContextValidity::kRejectUnsupportedMode:      return "RejectUnsupportedMode";
    }
    return "RejectIdentityUnverifiable";
}

ContextValidity checkContextUsable(const TranslationContext& saved,
                                   const LiveResolution& live) noexcept {
    // First check identity: process exit or PID reuse are the primary causes of invalidation and the reasons most needed by the UI.
    switch (resolveProcessNavigation(saved.process, live)) {
    case LiveNavigationDecision::kRejectObjectExited:
        return ContextValidity::kRejectProcessExited;
    case LiveNavigationDecision::kRejectIdentityMismatch:
        return ContextValidity::kRejectIdentityMismatch;
    case LiveNavigationDecision::kRejectIdentityUnverifiable:
        return ContextValidity::kRejectIdentityUnverifiable;
    case LiveNavigationDecision::kAllow:
        break;
    }
    if (saved.mode != PagingMode::kLongMode4Level) {
        return ContextValidity::kRejectUnsupportedMode;
    }
    if (!saved.pageTableRootPhysical.present) {
        // No page table root means no address space. Never fall back to "try the current process's CR3".
        return ContextValidity::kRejectNoPageTableRoot;
    }
    return ContextValidity::kUsable;
}

bool contextAllowsLiveReuse(ContextValidity validity) noexcept {
    return validity == ContextValidity::kUsable;
}

bool translateUsingContext(const TranslationContext& context,
                           ContextValidity validity,
                           std::uint64_t virtualAddress,
                           const PhysicalReader& reader,
                           const TranslateOptions& options,
                           TranslateResult& out) {
    out = TranslateResult{};
    if (!contextAllowsLiveReuse(validity)) {
        // Invalidated contexts are prohibited from reuse (M-03). Previously, `out` retained its default value, where the default
        // status was `UnsupportedMode`—causing "process exited" to be rendered by the UI as "page table mode unsupported,"
        // giving the user a false rejection reason. Now, both the status and reason are written exactly as they are.
        out.status = TranslationStatus::kContextRejected;
        out.contextRefusal = validity;
        out.virtualAddress = virtualAddress;
        out.mode = context.mode;
        // The saved root is exported as-is: it is part of the historical observation, not the result of this translation.
        out.pageTableRootPhysical = context.pageTableRootPhysical;
        return false;
    }
    TranslateOptions effective = options;
    effective.mode = context.mode;  // Page table walk mode is determined by the context; the caller cannot provide an alternative.
    out = translateVirtualAddress(virtualAddress,
                                  context.pageTableRootPhysical.value,
                                  reader,
                                  effective);
    return true;
}

} // namespace ksword::evidence

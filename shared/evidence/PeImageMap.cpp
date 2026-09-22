#include "PeImageMap.h"

#include <algorithm>
#include <cstring>

namespace ksword::evidence {
namespace {

// PE structure constants. Deliberately omit #include <Windows.h>: this layer must support unit testing in a Win32-free
// environment, and the I-module requirement mandates a single parsing implementation across the entire codebase.
constexpr std::uint16_t kDosSignature = 0x5A4DU;          // 'MZ'
constexpr std::uint32_t kNtSignature = 0x00004550U;       // 'PE\0\0'
constexpr std::uint16_t kOptionalMagicPe32Plus = 0x020BU;

constexpr std::uint64_t kDosHeaderSize = 0x40U;
constexpr std::uint64_t kElfanewOffset = 0x3CU;
constexpr std::uint64_t kFileHeaderSize = 20U;
constexpr std::uint64_t kOptionalHeader64MinSize = 112U;  // Up to NumberOfRvaAndSizes
constexpr std::uint64_t kDataDirectoryEntrySize = 8U;
constexpr std::uint64_t kSectionHeaderSize = 40U;

constexpr std::uint32_t kDirectoryIndexExport = 0U;
constexpr std::uint32_t kDirectoryIndexBaseReloc = 5U;
constexpr std::uint32_t kDirectoryIndexLoadConfig = 10U;

// Offset of the DVRT entry field within IMAGE_LOAD_CONFIG_DIRECTORY64. Hardcoded constants instead of offsetof because this
// layer does not #include <Windows.h>; these offsets are fixed by the PE specification and do not change with SDK versions.
constexpr std::uint64_t kLoadConfigOffsetStructSize = 0U;            // DWORD Size
constexpr std::uint64_t kLoadConfigOffsetDvrtTableOffset = 224U;     // DWORD
constexpr std::uint64_t kLoadConfigOffsetDvrtTableSection = 228U;    // WORD
// The structure must be long enough to hold DynamicValueRelocTableSection (228 + 2) before it can be considered a DVRT.
// A LoadConfig shorter than this is a version prior to the DVRT field; this is positive evidence that it 'definitely does not exist'.
constexpr std::uint64_t kLoadConfigMinSizeForDvrt = 230U;

constexpr std::uint64_t kDvrtTableHeaderSize = 8U;    // Version + Size
constexpr std::uint64_t kDvrtEntryHeaderSize = 12U;   // Symbol(8) + BaseRelocSize(4)
constexpr std::uint32_t kDvrtTableVersionOne = 1U;

constexpr std::uint32_t kScnCntCode = 0x00000020U;
constexpr std::uint32_t kScnMemExecute = 0x20000000U;
constexpr std::uint32_t kScnMemWrite = 0x80000000U;

constexpr std::uint16_t kFileRelocsStripped = 0x0001U;

// Relocation type ID. Only ABSOLUTE, HIGHLOW, and DIR64 are supported at this layer.
constexpr std::uint16_t kRelAbsolute = 0U;
constexpr std::uint16_t kRelHigh = 1U;
constexpr std::uint16_t kRelLow = 2U;
constexpr std::uint16_t kRelHighLow = 3U;
constexpr std::uint16_t kRelHighAdj = 4U;
constexpr std::uint16_t kRelDir64 = 10U;

constexpr std::uint64_t kRelocationBlockHeaderSize = 8U;  // VirtualAddress + SizeOfBlock

bool readU8(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
            std::uint8_t& out) noexcept {
    if (offset >= size) {
        return false;
    }
    out = data[static_cast<std::size_t>(offset)];
    return true;
}

bool readU16(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
             std::uint16_t& out) noexcept {
    if (offset + 2U > size) {
        return false;
    }
    const std::size_t kAt = static_cast<std::size_t>(offset);
    out = static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[kAt]) |
                                     static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[kAt + 1U]) << 8U));
    return true;
}

bool readU32(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
             std::uint32_t& out) noexcept {
    if (offset + 4U > size) {
        return false;
    }
    const std::size_t kAt = static_cast<std::size_t>(offset);
    out = static_cast<std::uint32_t>(data[kAt]) |
          (static_cast<std::uint32_t>(data[kAt + 1U]) << 8U) |
          (static_cast<std::uint32_t>(data[kAt + 2U]) << 16U) |
          (static_cast<std::uint32_t>(data[kAt + 3U]) << 24U);
    return true;
}

bool readU64(const std::uint8_t* data, std::size_t size, std::uint64_t offset,
             std::uint64_t& out) noexcept {
    std::uint32_t low = 0U;
    std::uint32_t high = 0U;
    if (!readU32(data, size, offset, low) || !readU32(data, size, offset + 4U, high)) {
        return false;
    }
    out = static_cast<std::uint64_t>(low) | (static_cast<std::uint64_t>(high) << 32U);
    return true;
}

bool isPowerOfTwo(std::uint32_t value) noexcept {
    return value != 0U && (value & (value - 1U)) == 0U;
}

PeImageMap makeFailure(PeParseStatus status, const char* detail, std::uint64_t fileSize,
                       std::uint64_t loadedBase) {
    PeImageMap map;
    map.status = status;
    map.errorDetail = detail;
    map.fileSize = fileSize;
    map.loadedBase = loadedBase;
    return map;
}

// Byte width affected by unsupported relocation types. The width is conservative: it is better to
// over-report than to under-report and mistakenly classify overwritten bytes as 'clean differences'.
std::uint32_t unsupportedRelocationSpan(std::uint16_t type) noexcept {
    switch (type) {
    case kRelHigh:
    case kRelLow:
        return 2U;
    case kRelHighAdj:
        return 4U;
    default:
        return 8U;
    }
}

// Byte width per record in a DVRT symbol segment; 0 indicates this layer does not recognize the symbol.
// Width is taken from the record structure in winnt.h; all three variants place the page offset in the lower 12 bits:
//   3 IMPORT_CONTROL_TRANSFER  —— IMAGE_IMPORT_CONTROL_TRANSFER_DYNAMIC_RELOCATION
//     DWORD PageRelativeOffset:12 / IndirectCall:1 / IATIndex:19 = 4 bytes
//   4 INDIR_CONTROL_TRANSFER   —— IMAGE_INDIR_CONTROL_TRANSFER_DYNAMIC_RELOCATION
//     WORD PageRelativeOffset:12 / IndirectCall:1 / RexWPrefix:1 / CfgCheck:1 /
//     Reserved:1 = 2 bytes
//   5 SWITCHTABLE_BRANCH       —— IMAGE_SWITCHTABLE_BRANCH_DYNAMIC_RELOCATION
//     WORD PageRelativeOffset:12 / RegisterNumber:4 = 2 bytes. Note: The active
// KernelCleanImageBaseline::collectDynamicRelocationSites uses 4 bytes for symbol 5, which
// conflicts with winnt.h. This causes the SWITCHTABLE section to skip every other record and treat
// the upper half of the subsequent record as the offset. This layer does not replicate this error.
std::uint32_t dvrtEntryStride(std::uint64_t symbol) noexcept {
    switch (symbol) {
    case kDvrtSymbolImportControlTransfer:
        return 4U;
    case kDvrtSymbolIndirControlTransfer:
    case kDvrtSymbolSwitchtableBranch:
        return 2U;
    default:
        return 0U;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// Interval set operations.
// ---------------------------------------------------------------------------

std::vector<RvaRange> normalizeRvaRanges(std::vector<RvaRange> ranges) {
    std::vector<RvaRange> kept;
    kept.reserve(ranges.size());
    for (const RvaRange& range : ranges) {
        if (!range.empty()) {
            kept.push_back(range);
        }
    }
    std::sort(kept.begin(), kept.end(), [](const RvaRange& a, const RvaRange& b) {
        if (a.rva != b.rva) {
            return a.rva < b.rva;
        }
        return a.length < b.length;
    });

    std::vector<RvaRange> merged;
    merged.reserve(kept.size());
    for (const RvaRange& range : kept) {
        if (!merged.empty()) {
            RvaRange& back = merged.back();
            // Merge adjacent intervals (end == rva): the interval set only describes 'which
            // bytes belong to this category', not which original record they came from.
            if (static_cast<std::uint64_t>(range.rva) <= back.endExclusive()) {
                const std::uint64_t kNewEnd = std::max(back.endExclusive(), range.endExclusive());
                back.length = static_cast<std::uint32_t>(kNewEnd - static_cast<std::uint64_t>(back.rva));
                continue;
            }
        }
        merged.push_back(range);
    }
    return merged;
}

std::vector<RvaRange> subtractRvaRanges(const std::vector<RvaRange>& base,
                                        const std::vector<RvaRange>& cut) {
    const std::vector<RvaRange> kNormalizedBase = normalizeRvaRanges(base);
    const std::vector<RvaRange> kNormalizedCut = normalizeRvaRanges(cut);
    std::vector<RvaRange> result;
    result.reserve(kNormalizedBase.size());

    for (const RvaRange& range : kNormalizedBase) {
        std::uint64_t cursor = range.rva;
        const std::uint64_t kEnd = range.endExclusive();
        for (const RvaRange& hole : kNormalizedCut) {
            const std::uint64_t kHoleBegin = hole.rva;
            const std::uint64_t kHoleEnd = hole.endExclusive();
            if (kHoleEnd <= cursor) {
                continue;
            }
            if (kHoleBegin >= kEnd) {
                break;
            }
            if (kHoleBegin > cursor) {
                RvaRange piece;
                piece.rva = static_cast<std::uint32_t>(cursor);
                piece.length = static_cast<std::uint32_t>(kHoleBegin - cursor);
                result.push_back(piece);
            }
            cursor = std::max(cursor, kHoleEnd);
            if (cursor >= kEnd) {
                break;
            }
        }
        if (cursor < kEnd) {
            RvaRange piece;
            piece.rva = static_cast<std::uint32_t>(cursor);
            piece.length = static_cast<std::uint32_t>(kEnd - cursor);
            result.push_back(piece);
        }
    }
    return normalizeRvaRanges(std::move(result));
}

std::vector<RvaRange> intersectRvaRanges(const std::vector<RvaRange>& base,
                                         const std::vector<RvaRange>& mask) {
    const std::vector<RvaRange> kNormalizedBase = normalizeRvaRanges(base);
    const std::vector<RvaRange> kNormalizedMask = normalizeRvaRanges(mask);
    std::vector<RvaRange> result;
    for (const RvaRange& range : kNormalizedBase) {
        for (const RvaRange& other : kNormalizedMask) {
            if (other.rva >= range.endExclusive()) {
                break;
            }
            if (other.endExclusive() <= range.rva) {
                continue;
            }
            const std::uint64_t kBegin = std::max<std::uint64_t>(range.rva, other.rva);
            const std::uint64_t kEnd = std::min(range.endExclusive(), other.endExclusive());
            if (kEnd > kBegin) {
                RvaRange piece;
                piece.rva = static_cast<std::uint32_t>(kBegin);
                piece.length = static_cast<std::uint32_t>(kEnd - kBegin);
                result.push_back(piece);
            }
        }
    }
    return normalizeRvaRanges(std::move(result));
}

std::uint64_t rvaRangesTotalBytes(const std::vector<RvaRange>& ranges) noexcept {
    std::uint64_t total = 0U;
    for (const RvaRange& range : ranges) {
        total += range.length;
    }
    return total;
}

bool rvaRangesContain(const std::vector<RvaRange>& ranges, std::uint32_t rva) noexcept {
    for (const RvaRange& range : ranges) {
        if (range.contains(rva)) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Enum names
// ---------------------------------------------------------------------------

const char* peParseStatusName(PeParseStatus status) noexcept {
    switch (status) {
    case PeParseStatus::kOk:                        return "Ok";
    case PeParseStatus::kEmptyInput:                return "EmptyInput";
    case PeParseStatus::kTruncatedDosHeader:        return "TruncatedDosHeader";
    case PeParseStatus::kBadDosSignature:           return "BadDosSignature";
    case PeParseStatus::kBadNtHeaderOffset:         return "BadNtHeaderOffset";
    case PeParseStatus::kTruncatedNtHeaders:        return "TruncatedNtHeaders";
    case PeParseStatus::kBadNtSignature:            return "BadNtSignature";
    case PeParseStatus::kUnsupportedOptionalMagic:  return "UnsupportedOptionalMagic";
    case PeParseStatus::kTruncatedOptionalHeader:   return "TruncatedOptionalHeader";
    case PeParseStatus::kInvalidSectionCount:       return "InvalidSectionCount";
    case PeParseStatus::kTruncatedSectionTable:     return "TruncatedSectionTable";
    case PeParseStatus::kSectionTableExceedsHeaders: return "SectionTableExceedsHeaders";
    case PeParseStatus::kInvalidSizeOfImage:        return "InvalidSizeOfImage";
    case PeParseStatus::kInvalidAlignment:          return "InvalidAlignment";
    }
    return "EmptyInput";
}

const char* sectionMapStatusName(SectionMapStatus status) noexcept {
    switch (status) {
    case SectionMapStatus::kMapped:        return "Mapped";
    case SectionMapStatus::kNotComparable: return "NotComparable";
    }
    return "NotComparable";
}

const char* sectionDefectReasonName(SectionDefectReason reason) noexcept {
    switch (reason) {
    case SectionDefectReason::kNone:                   return "None";
    case SectionDefectReason::kZeroVirtualExtent:      return "ZeroVirtualExtent";
    case SectionDefectReason::kVirtualRangeOutOfImage: return "VirtualRangeOutOfImage";
    case SectionDefectReason::kVirtualRangeOverflow:   return "VirtualRangeOverflow";
    case SectionDefectReason::kRawDataOutOfFile:       return "RawDataOutOfFile";
    case SectionDefectReason::kRawRangeOverflow:       return "RawRangeOverflow";
    case SectionDefectReason::kOverlapsEarlierSection: return "OverlapsEarlierSection";
    }
    return "None";
}

const char* relocationStatusName(RelocationStatus status) noexcept {
    switch (status) {
    case RelocationStatus::kNotNeeded:              return "NotNeeded";
    case RelocationStatus::kApplied:                return "Applied";
    case RelocationStatus::kAppliedWithUnsupported: return "AppliedWithUnsupported";
    case RelocationStatus::kDirectoryMissing:       return "DirectoryMissing";
    case RelocationStatus::kDirectoryUnbacked:      return "DirectoryUnbacked";
    case RelocationStatus::kDirectoryMalformed:     return "DirectoryMalformed";
    case RelocationStatus::kStripped:               return "Stripped";
    }
    return "NotNeeded";
}

bool relocationNormalizationSucceeded(RelocationStatus status) noexcept {
    switch (status) {
    case RelocationStatus::kNotNeeded:
    case RelocationStatus::kApplied:
    case RelocationStatus::kAppliedWithUnsupported:
        // AppliedWithUnsupported counts as success: only the byte ranges marked as incomparable
        // cannot be normalized; the rest are indeed already at the target base address.
        return true;
    case RelocationStatus::kDirectoryMissing:
    case RelocationStatus::kDirectoryUnbacked:
    case RelocationStatus::kDirectoryMalformed:
    case RelocationStatus::kStripped:
        return false;
    }
    return false;
}

const char* dvrtStatusName(DvrtStatus status) noexcept {
    switch (status) {
    case DvrtStatus::kNotPresent:              return "NotPresent";
    case DvrtStatus::kParsed:                  return "Parsed";
    case DvrtStatus::kParsedWithUnknownSymbol: return "ParsedWithUnknownSymbol";
    case DvrtStatus::kLoadConfigUnusable:      return "LoadConfigUnusable";
    case DvrtStatus::kTableUnbacked:           return "TableUnbacked";
    case DvrtStatus::kUnsupportedVersion:      return "UnsupportedVersion";
    case DvrtStatus::kMalformed:               return "Malformed";
    }
    return "NotPresent";
}

bool dvrtExtentFullyBounded(DvrtStatus status) noexcept {
    switch (status) {
    case DvrtStatus::kNotPresent:
    case DvrtStatus::kParsed:
    case DvrtStatus::kParsedWithUnknownSymbol:
        // ParsedWithUnknownSymbol counts as boundary completion: the unresolved part is only the bit position within the page. The
        // block header tells us the loader only touches specific pages, which are entirely included in the non-comparable range.
        return true;
    case DvrtStatus::kLoadConfigUnusable:
    case DvrtStatus::kTableUnbacked:
    case DvrtStatus::kUnsupportedVersion:
    case DvrtStatus::kMalformed:
        return false;
    }
    return false;
}

std::vector<RvaRange> DynamicRelocationReport::affectedRanges() const {
    std::vector<RvaRange> merged;
    merged.reserve(siteRanges.size() + unknownSymbolRanges.size());
    merged.insert(merged.end(), siteRanges.begin(), siteRanges.end());
    merged.insert(merged.end(), unknownSymbolRanges.begin(), unknownSymbolRanges.end());
    return normalizeRvaRanges(std::move(merged));
}

const char* rvaKindName(RvaKind kind) noexcept {
    switch (kind) {
    case RvaKind::kOutsideImage:     return "OutsideImage";
    case RvaKind::kHeader:           return "Header";
    case RvaKind::kSectionRawBacked: return "SectionRawBacked";
    case RvaKind::kSectionZeroFill:  return "SectionZeroFill";
    case RvaKind::kSectionGap:       return "SectionGap";
    case RvaKind::kNotComparable:    return "NotComparable";
    }
    return "OutsideImage";
}

const char* fileOffsetKindName(FileOffsetKind kind) noexcept {
    switch (kind) {
    case FileOffsetKind::kOutsideFile:           return "OutsideFile";
    case FileOffsetKind::kHeader:                return "Header";
    case FileOffsetKind::kSectionRawData:        return "SectionRawData";
    case FileOffsetKind::kNotMappedByAnySection: return "NotMappedByAnySection";
    case FileOffsetKind::kNotComparable:         return "NotComparable";
    }
    return "OutsideFile";
}

// ---------------------------------------------------------------------------
// SectionMap / PeHeaderFacts
// ---------------------------------------------------------------------------

bool SectionMap::executable() const noexcept {
    return (characteristics & (kScnMemExecute | kScnCntCode)) != 0U;
}

bool SectionMap::writable() const noexcept {
    return (characteristics & kScnMemWrite) != 0U;
}

RvaRange SectionMap::virtualRange() const noexcept {
    RvaRange range;
    range.rva = virtualAddress;
    range.length = effectiveVirtualSize;
    return range;
}

RvaRange SectionMap::rawBackedRange() const noexcept {
    RvaRange range;
    range.rva = virtualAddress;
    range.length = rawBackedBytes;
    return range;
}

RvaRange SectionMap::zeroFillRange() const noexcept {
    RvaRange range;
    range.rva = virtualAddress + rawBackedBytes;
    range.length = zeroFillBytes;
    return range;
}

bool PeHeaderFacts::relocationsStripped() const noexcept {
    return (fileCharacteristics & kFileRelocsStripped) != 0U;
}

std::vector<RvaRange> PeImageMap::executableRawBackedRanges() const {
    std::vector<RvaRange> ranges;
    for (const SectionMap& section : sections) {
        if (section.status == SectionMapStatus::kMapped && section.executable() &&
            section.rawBackedBytes != 0U) {
            ranges.push_back(section.rawBackedRange());
        }
    }
    return normalizeRvaRanges(std::move(ranges));
}

const SectionMap* PeImageMap::sectionAt(std::size_t index) const noexcept {
    if (index >= sections.size()) {
        return nullptr;
    }
    return &sections[index];
}

// ---------------------------------------------------------------------------
// Parse and map
// ---------------------------------------------------------------------------

namespace {

// Whether the normalized range set fully contains the span. The set must have been normalized by normalizeRvaRanges
// (adjacent ranges merged), so "spanning two adjacent ranges" will not be incorrectly judged as not contained.
bool rangesContainSpan(const std::vector<RvaRange>& normalized, const RvaRange& span) noexcept {
    if (span.empty()) {
        return false;
    }
    for (const RvaRange& range : normalized) {
        if (range.rva > span.rva) {
            break;  // Sorted: subsequent interval start points will only be larger.
        }
        if (range.containsRange(span)) {
            return true;
        }
    }
    return false;
}

// Parse the section table and map each section into the image after boundary validation. Malformed sections do not abort the iteration; they are marked and skipped.
void mapSections(const std::uint8_t* data, std::size_t size, PeImageMap& map) {
    std::vector<RvaRange> accepted;
    accepted.reserve(static_cast<std::size_t>(map.header.sectionCount) + 1U);

    // I-02: The PE header is the first data loaded into the image (via memcpy in buildPeImageMap), so it must
    // participate in overlap checks as an "accepted range." Otherwise, if VirtualAddress falls within the header,
    // the section would be marked Mapped, overwriting the header bytes. This creates a contradiction for the same
    // RVA: translateRva identifies it as a section, while translateFileOffset maps two different file offsets to it.
    // Use the declared SizeOfHeaders rather than the actual copied length: truncating
    // the file does not change the fact that this RVA belongs to the header.
    RvaRange declaredHeaderRange;
    declaredHeaderRange.rva = 0U;
    declaredHeaderRange.length = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(map.header.sizeOfHeaders, map.header.sizeOfImage));
    if (!declaredHeaderRange.empty()) {
        accepted.push_back(declaredHeaderRange);
    }

    std::uint64_t mappedCount = 0U;
    std::uint64_t defectCount = 0U;

    for (std::uint16_t index = 0U; index < map.header.sectionCount; ++index) {
        const std::uint64_t kEntryOffset =
            map.header.sectionTableFileOffset + static_cast<std::uint64_t>(index) * kSectionHeaderSize;

        SectionMap section;
        char rawName[9] = {};
        bool nameOk = true;
        for (std::uint64_t byteIndex = 0U; byteIndex < 8U; ++byteIndex) {
            std::uint8_t nameByte = 0U;
            if (!readU8(data, size, kEntryOffset + byteIndex, nameByte)) {
                nameOk = false;
                break;
            }
            rawName[byteIndex] = static_cast<char>(nameByte);
        }
        // The overall bounds of the section table are validated in buildPeImageMap; retrieving them again here
        // ensures we do not rely on the correctness of upstream validation—out-of-bounds reads must never occur.
        std::uint32_t virtualSize = 0U;
        std::uint32_t virtualAddress = 0U;
        std::uint32_t sizeOfRawData = 0U;
        std::uint32_t pointerToRawData = 0U;
        std::uint32_t characteristics = 0U;
        const bool kFieldsOk =
            nameOk && readU32(data, size, kEntryOffset + 8U, virtualSize) &&
            readU32(data, size, kEntryOffset + 12U, virtualAddress) &&
            readU32(data, size, kEntryOffset + 16U, sizeOfRawData) &&
            readU32(data, size, kEntryOffset + 20U, pointerToRawData) &&
            readU32(data, size, kEntryOffset + 36U, characteristics);

        section.name.assign(rawName, std::char_traits<char>::length(rawName));
        section.virtualSize = virtualSize;
        section.virtualAddress = virtualAddress;
        section.sizeOfRawData = sizeOfRawData;
        section.pointerToRawData = pointerToRawData;
        section.characteristics = characteristics;

        if (!kFieldsOk) {
            section.status = SectionMapStatus::kNotComparable;
            section.defect = SectionDefectReason::kRawDataOutOfFile;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        // Old-style sections with VirtualSize of 0 fall back to SizeOfRawData; if both are 0, there is no virtual range.
        const std::uint32_t kEffective = (virtualSize != 0U) ? virtualSize : sizeOfRawData;
        section.effectiveVirtualSize = kEffective;
        if (kEffective == 0U) {
            section.status = SectionMapStatus::kNotComparable;
            section.defect = SectionDefectReason::kZeroVirtualExtent;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        const std::uint64_t kVirtualEnd =
            static_cast<std::uint64_t>(virtualAddress) + static_cast<std::uint64_t>(kEffective);
        if (kVirtualEnd > 0xFFFFFFFFULL) {
            section.status = SectionMapStatus::kNotComparable;
            section.defect = SectionDefectReason::kVirtualRangeOverflow;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }
        // I-02: New validation: VirtualAddress + VirtualSize must not exceed SizeOfImage.
        if (kVirtualEnd > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
            section.status = SectionMapStatus::kNotComparable;
            section.defect = SectionDefectReason::kVirtualRangeOutOfImage;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        // I-02 Added validation: check if section ranges overlap with the PE header or previously accepted sections. On overlap,
        // retain the first occurrence and mark subsequent ones as not comparable—since it's impossible to determine which
        // represents the true mapping, the later one should not yield a comparison result. Retaining the first ensures reproducible
        // results; the overlapping range is added to notComparableRanges. The first item in 'accepted' is the PE header range.
        bool overlaps = false;
        RvaRange candidate;
        candidate.rva = virtualAddress;
        candidate.length = kEffective;
        for (const RvaRange& earlier : accepted) {
            if (earlier.overlaps(candidate)) {
                overlaps = true;
                break;
            }
        }
        if (overlaps) {
            section.status = SectionMapStatus::kNotComparable;
            section.defect = SectionDefectReason::kOverlapsEarlierSection;
            ++defectCount;
            map.sections.push_back(std::move(section));
            continue;
        }

        // raw supported length: The loader copies only min(SizeOfRawData, VirtualSize) into the image. The
        // tail where raw > virtual is not copied into the image and should not be included in the comparison.
        const std::uint32_t kRawBacked = std::min(sizeOfRawData, kEffective);
        if (kRawBacked != 0U) {
            const std::uint64_t kRawEnd =
                static_cast<std::uint64_t>(pointerToRawData) + static_cast<std::uint64_t>(kRawBacked);
            if (kRawEnd > 0xFFFFFFFFULL) {
                section.status = SectionMapStatus::kNotComparable;
                section.defect = SectionDefectReason::kRawRangeOverflow;
                ++defectCount;
                map.sections.push_back(std::move(section));
                continue;
            }
            // I-02 New validation: PointerToRawData + SizeOfRawData must not exceed the file end.
            // Truncated section: skip only this section; map others normally.
            if (kRawEnd > static_cast<std::uint64_t>(size)) {
                section.status = SectionMapStatus::kNotComparable;
                section.defect = SectionDefectReason::kRawDataOutOfFile;
                ++defectCount;
                map.sections.push_back(std::move(section));
                continue;
            }
        }

        section.rawBackedBytes = kRawBacked;
        section.zeroFillBytes = kEffective - kRawBacked;
        section.status = SectionMapStatus::kMapped;
        section.defect = SectionDefectReason::kNone;

        if (kRawBacked != 0U) {
            std::memcpy(map.image.data() + virtualAddress,
                        data + pointerToRawData,
                        static_cast<std::size_t>(kRawBacked));
        }
        // Zero-filled regions are already 0 (image initialized to 0), so no write is needed, but they must be recorded in zeroFillRanges.

        accepted.push_back(candidate);
        ++mappedCount;
        map.sections.push_back(std::move(section));
    }

    for (const SectionMap& section : map.sections) {
        if (section.status == SectionMapStatus::kMapped) {
            if (section.rawBackedBytes != 0U) {
                map.rawBackedRanges.push_back(section.rawBackedRange());
            }
            if (section.zeroFillBytes != 0U) {
                map.zeroFillRanges.push_back(section.zeroFillRange());
            }
        } else if (section.effectiveVirtualSize != 0U) {
            // Mark the virtual range of a malformed section only if it falls within the image; out-of-bounds parts do not exist.
            const std::uint64_t kEnd = static_cast<std::uint64_t>(section.virtualAddress) +
                                      static_cast<std::uint64_t>(section.effectiveVirtualSize);
            const std::uint64_t kClampedEnd = std::min<std::uint64_t>(kEnd, map.header.sizeOfImage);
            if (section.virtualAddress < map.header.sizeOfImage && kClampedEnd > section.virtualAddress) {
                RvaRange range;
                range.rva = section.virtualAddress;
                range.length = static_cast<std::uint32_t>(kClampedEnd - section.virtualAddress);
                map.notComparableRanges.push_back(range);
            }
        }
    }

    map.sectionCoverage.requestedBegin = OptionalU64::of(0U);
    map.sectionCoverage.requestedEnd = OptionalU64::of(map.header.sectionCount);
    map.sectionCoverage.processedBegin = OptionalU64::of(0U);
    map.sectionCoverage.processedEnd = OptionalU64::of(map.header.sectionCount);
    map.sectionCoverage.succeeded = mappedCount;
    map.sectionCoverage.failed = defectCount;
    map.sectionCoverage.totalKnown = OptionalU64::of(map.header.sectionCount);
}

// I-03 Key Criterion: If normalization fails, map.image contains bytes from the **preferred base address**, while the live
// read contains bytes rewritten by the loader to the target base address. Byte-by-byte comparison then reports an 'unexplained
// code difference' at every relocation point—a bulk false positive explicitly forbidden by I-01. Conversely, if the live read
// also comes from this unnormalized byte stream, it yields a confident 'no difference found'. Both directions are wrong.
// The only honest approach: mark the entire image as incomparable so the diff engine records it as 'excluded',
// resulting in a non-zero coverage.skipped and naturally reducing the conclusion to Indeterminate.
void pushWholeImageNotComparable(PeImageMap& map) {
    if (map.header.sizeOfImage == 0U) {
        return;
    }
    RvaRange whole;
    whole.rva = 0U;
    whole.length = map.header.sizeOfImage;
    map.notComparableRanges.push_back(whole);
}

void markWholeImageNotComparable(PeImageMap& map) {
    // imageNotNormalized describes only the reason 'relocation normalization failed'; other callers (DVRT) must not set
    // it arbitrarily—otherwise the UI would report 'base address not normalized' instead of 'DVRT version unknown'.
    map.relocation.imageNotNormalized = true;
    pushWholeImageNotComparable(map);
}

// I-03: normalize the image from preferredImageBase to loadedBase according to the .reloc directory.
void applyRelocations(PeImageMap& map) {
    RelocationReport& report = map.relocation;
    report.delta = map.loadedBase - map.header.preferredImageBase;

    // Subsequently, verify whether the target has file byte support per entry. First normalize the set to merge adjacent
    // intervals; otherwise, targets spanning two adjacent raw-backed regions would be incorrectly judged as unsupported.
    map.rawBackedRanges = normalizeRvaRanges(std::move(map.rawBackedRanges));

    report.coverage.requestedBegin = OptionalU64::of(map.header.relocationDirectoryRva);
    report.coverage.requestedEnd =
        OptionalU64::of(static_cast<std::uint64_t>(map.header.relocationDirectoryRva) +
                        static_cast<std::uint64_t>(map.header.relocationDirectorySize));
    report.coverage.processedBegin = OptionalU64::of(map.header.relocationDirectoryRva);
    report.coverage.processedEnd = OptionalU64::of(map.header.relocationDirectoryRva);

    if (report.delta == 0U) {
        report.status = RelocationStatus::kNotNeeded;
        report.coverage.processedEnd = report.coverage.requestedEnd;
        report.coverage.totalKnown = OptionalU64::of(0U);
        return;
    }

    if (map.header.relocationsStripped()) {
        // RELOCS_STRIPPED is declared but a base address change is required: normalization is impossible. The caller must see this status;
        // it cannot be silently treated as 'no difference', nor can unnormalized bytes be used as a disk reference for comparison.
        report.status = RelocationStatus::kStripped;
        markWholeImageNotComparable(map);
        return;
    }

    const std::uint32_t kDirRva = map.header.relocationDirectoryRva;
    const std::uint32_t kDirSize = map.header.relocationDirectorySize;
    if (kDirRva == 0U || kDirSize < kRelocationBlockHeaderSize) {
        report.status = RelocationStatus::kDirectoryMissing;
        markWholeImageNotComparable(map);
        return;
    }
    const std::uint64_t kDirEnd = static_cast<std::uint64_t>(kDirRva) + static_cast<std::uint64_t>(kDirSize);
    if (kDirEnd > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
        report.status = RelocationStatus::kDirectoryMalformed;
        markWholeImageNotComparable(map);
        return;
    }

    // The directory must fall within a range backed by actual file bytes; otherwise, reads yield 0-padding, and parsed headers show
    // all 0-length blocks. This does not mean 'the relocation table is empty'; it means 'we never obtained the relocation table'.
    RvaRange directoryRange;
    directoryRange.rva = kDirRva;
    directoryRange.length = kDirSize;
    const std::vector<RvaRange> kBacked =
        intersectRvaRanges(std::vector<RvaRange>{directoryRange}, map.rawBackedRanges);
    if (rvaRangesTotalBytes(kBacked) != static_cast<std::uint64_t>(kDirSize)) {
        report.status = RelocationStatus::kDirectoryUnbacked;
        markWholeImageNotComparable(map);
        return;
    }

    const std::uint8_t* image = map.image.data();
    const std::size_t kImageSize = map.image.size();
    bool malformed = false;
    std::uint32_t consumed = 0U;

    while (consumed < kDirSize) {
        if (kDirSize - consumed < kRelocationBlockHeaderSize) {
            malformed = true;
            break;
        }
        const std::uint64_t kBlockOffset = static_cast<std::uint64_t>(kDirRva) + consumed;
        std::uint32_t blockRva = 0U;
        std::uint32_t blockSize = 0U;
        if (!readU32(image, kImageSize, kBlockOffset, blockRva) ||
            !readU32(image, kImageSize, kBlockOffset + 4U, blockSize)) {
            malformed = true;
            break;
        }
        if (blockSize == 0U) {
            // A block with length 0 causes the loop to stall; handle it as truncation and stop, preserving any already applied parts.
            malformed = true;
            break;
        }
        if (blockSize < kRelocationBlockHeaderSize || blockSize > kDirSize - consumed) {
            malformed = true;
            break;
        }
        const std::uint32_t kEntryBytes = blockSize - static_cast<std::uint32_t>(kRelocationBlockHeaderSize);
        if ((kEntryBytes % 2U) != 0U) {
            malformed = true;
            break;
        }
        const std::uint32_t kEntryCount = kEntryBytes / 2U;

        for (std::uint32_t entryIndex = 0U; entryIndex < kEntryCount; ++entryIndex) {
            std::uint16_t entry = 0U;
            const std::uint64_t kEntryOffset =
                kBlockOffset + kRelocationBlockHeaderSize + static_cast<std::uint64_t>(entryIndex) * 2U;
            if (!readU16(image, kImageSize, kEntryOffset, entry)) {
                malformed = true;
                break;
            }
            ++report.entriesTotal;

            const std::uint16_t kType = static_cast<std::uint16_t>(entry >> 12U);
            const std::uint64_t kTargetRva64 =
                static_cast<std::uint64_t>(blockRva) + static_cast<std::uint64_t>(entry & 0x0FFFU);

            if (kType == kRelAbsolute) {
                // Align padding entries without rewriting any bytes. Record as 'correctly
                // handled'; otherwise, the coverage of a real PE can never be complete.
                ++report.entriesAbsolute;
                continue;
            }

            if (kType == kRelDir64 || kType == kRelHighLow) {
                const std::uint32_t kWidth = (kType == kRelDir64) ? 8U : 4U;
                if (kTargetRva64 + kWidth > static_cast<std::uint64_t>(kImageSize)) {
                    ++report.entriesOutOfRange;
                    continue;
                }
                RvaRange targetSpan;
                targetSpan.rva = static_cast<std::uint32_t>(kTargetRva64);
                targetSpan.length = kWidth;
                // I-02: The target must be fully backed by file bytes. When falling into a zero-filled region, the
                // image contains 0s while the file has no such bytes — reading 0, adding delta, and writing back leaves
                // non-zero values in ranges that "must be 0" by contract, while treating fabricated values as disk
                // references. Crossing raw/zero-filled boundaries is worse: carries can overflow into comparable bytes.
                // Therefore, always reject the application and record it as incomparable.
                if (!rangesContainSpan(map.rawBackedRanges, targetSpan)) {
                    ++report.entriesUnbackedTarget;
                    report.unbackedTargetRanges.push_back(targetSpan);
                    map.notComparableRanges.push_back(targetSpan);
                    continue;
                }
                const std::size_t kAt = static_cast<std::size_t>(kTargetRva64);
                if (kType == kRelDir64) {
                    std::uint64_t value = 0U;
                    std::memcpy(&value, map.image.data() + kAt, sizeof(value));
                    value += report.delta;
                    std::memcpy(map.image.data() + kAt, &value, sizeof(value));
                } else {
                    std::uint32_t value = 0U;
                    std::memcpy(&value, map.image.data() + kAt, sizeof(value));
                    value += static_cast<std::uint32_t>(report.delta & 0xFFFFFFFFULL);
                    std::memcpy(map.image.data() + kAt, &value, sizeof(value));
                }
                ++report.entriesApplied;
                RvaRange touched;
                touched.rva = static_cast<std::uint32_t>(kTargetRva64);
                touched.length = kWidth;
                report.touchedRanges.push_back(touched);
                continue;
            }

            // Unsupported types: mark only the affected byte range as incomparable; never fail the entire image.
            ++report.entriesUnsupported;
            const std::uint32_t kSpan = unsupportedRelocationSpan(kType);
            if (kTargetRva64 < static_cast<std::uint64_t>(map.header.sizeOfImage)) {
                const std::uint64_t kEnd =
                    std::min<std::uint64_t>(kTargetRva64 + kSpan, map.header.sizeOfImage);
                UnsupportedRelocation record;
                record.type = kType;
                record.range.rva = static_cast<std::uint32_t>(kTargetRva64);
                record.range.length = static_cast<std::uint32_t>(kEnd - kTargetRva64);
                report.unsupported.push_back(record);
                map.notComparableRanges.push_back(record.range);
            } else {
                UnsupportedRelocation record;
                record.type = kType;
                record.range.rva = 0U;
                record.range.length = 0U;
                report.unsupported.push_back(record);
            }

            if (kType == kRelHighAdj) {
                // HIGHADJ additionally consumes the following WORD parameter. If not skipped, subsequent entries
                // will shift entirely, treating the parameter as a relocation item and overwriting bytes.
                // The parameter is **not** a relocation entry, so it is not added to entriesTotal. Including
                // it would cause succeeded + failed to always be less than totalKnown, resulting in incomplete
                // coverage and causing describeRemaining() to report a phantom remaining amount (I-03 / F-06).
                if (entryIndex + 1U < kEntryCount) {
                    ++entryIndex;
                    ++report.entriesSkippedParameter;
                } else {
                    malformed = true;
                    break;
                }
            }
        }

        if (malformed) {
            break;
        }
        ++report.blocksProcessed;
        consumed += blockSize;
        report.coverage.processedEnd =
            OptionalU64::of(static_cast<std::uint64_t>(kDirRva) + consumed);
    }

    report.touchedRanges = normalizeRvaRanges(std::move(report.touchedRanges));
    report.unbackedTargetRanges = normalizeRvaRanges(std::move(report.unbackedTargetRanges));

    if (malformed) {
        report.status = RelocationStatus::kDirectoryMalformed;
        // Stop midway: we do not know where the remaining blocks' targets are located (since block headers' VirtualAddress is
        // not guaranteed to be in ascending order), so we cannot define a lower bound for 'which segment remains unnormalized'.
        // Discard already-applied parts from comparison as well — better to mark
        // more as incomparable than to provide a half-normalized disk reference.
        markWholeImageNotComparable(map);
    } else if (report.entriesUnsupported != 0U || report.entriesOutOfRange != 0U ||
               report.entriesUnbackedTarget != 0U) {
        report.status = RelocationStatus::kAppliedWithUnsupported;
    } else {
        report.status = RelocationStatus::kApplied;
    }

    report.coverage.succeeded = report.entriesApplied + report.entriesAbsolute;
    report.coverage.failed =
        report.entriesUnsupported + report.entriesOutOfRange + report.entriesUnbackedTarget;
    report.coverage.totalKnown = OptionalU64::of(report.entriesTotal);
}

// ---------------------------------------------------------------------------
// I-03 DVRT
// ---------------------------------------------------------------------------

// Whether the range [rva, rva+length) falls entirely within the region backed by file bytes.
// This is the foundation of DVRT parsing: if LoadConfig and the table body fall within zero-filled regions, reading them
// yields all zeros, resulting in Size=0 and TableOffset=0, causing the parser to conclude 'no DVRT in this PE'—mistaking
// 'never captured' for 'definitely absent'. Therefore, positive supporting evidence must be required before reading.
bool spanIsRawBacked(const PeImageMap& map, std::uint64_t rva, std::uint64_t length) noexcept {
    if (length == 0U) {
        return false;
    }
    const std::uint64_t kEnd = rva + length;
    if (kEnd > 0xFFFFFFFFULL || kEnd > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
        return false;
    }
    RvaRange span;
    span.rva = static_cast<std::uint32_t>(rva);
    span.length = static_cast<std::uint32_t>(length);
    return rangesContainSpan(map.rawBackedRanges, span);
}

// Walk the payload of a symbol section as a sequence of IMAGE_BASE_RELOCATION blocks.
// Return false indicates the container structure was not traversed successfully. In this case, 'which bytes the loader modifies'
// cannot be defined; the caller must treat the range as unknown rather than assuming 'no points exist in this segment'.
bool walkDvrtBlocks(const PeImageMap& map,
                    std::uint64_t payloadRva,
                    std::uint32_t payloadBytes,
                    std::uint32_t entryStride,
                    DvrtSymbolGroup& group,
                    std::vector<RvaRange>& siteRanges,
                    std::vector<RvaRange>& pageRanges) {
    const std::uint8_t* image = map.image.data();
    const std::size_t kImageSize = map.image.size();
    const std::uint32_t kSizeOfImage = map.header.sizeOfImage;

    std::uint32_t consumed = 0U;
    while (static_cast<std::uint64_t>(payloadBytes - consumed) >= kRelocationBlockHeaderSize) {
        const std::uint64_t kBlockOffset = payloadRva + consumed;
        std::uint32_t blockRva = 0U;
        std::uint32_t blockSize = 0U;
        if (!readU32(image, kImageSize, kBlockOffset, blockRva) ||
            !readU32(image, kImageSize, kBlockOffset + 4U, blockSize)) {
            return false;
        }
        if (static_cast<std::uint64_t>(blockSize) < kRelocationBlockHeaderSize ||
            blockSize > payloadBytes - consumed) {
            return false;
        }
        // The block header must describe a real, existing page. These two conditions are hard invariants of
        // IMAGE_BASE_RELOCATION and serve as validation here: unrecognized symbols that are not actually block containers (e.g.,
        // a payload preceding GUARD_RF_PROLOGUE has its own header) will almost certainly be blocked here rather than misread as
        // a seemingly valid page sequence. Misreading would mark the wrong range, effectively missing the true location.
        if ((blockRva % kRelocationPageBytes) != 0U || blockRva >= kSizeOfImage) {
            return false;
        }
        ++group.blocksWalked;

        const std::uint32_t kEntryBytes =
            blockSize - static_cast<std::uint32_t>(kRelocationBlockHeaderSize);
        if (entryStride == 0U) {
            // Symbol unrecognized: the resolution point cannot be determined, but the block header confines the impact to this page.
            // Page granularity is coarser than the offset, yet it is a provable upper bound, far more precise than 'the entire image is incomparable'.
            const std::uint64_t kPageEnd = std::min<std::uint64_t>(
                static_cast<std::uint64_t>(blockRva) + kRelocationPageBytes, kSizeOfImage);
            RvaRange page;
            page.rva = blockRva;
            page.length = static_cast<std::uint32_t>(kPageEnd - blockRva);
            pageRanges.push_back(page);
        } else {
            for (std::uint32_t offset = 0U; offset + entryStride <= kEntryBytes;
                 offset += entryStride) {
                const std::uint64_t kRecordOffset =
                    kBlockOffset + kRelocationBlockHeaderSize + offset;
                std::uint32_t record = 0U;
                if (entryStride == 4U) {
                    if (!readU32(image, kImageSize, kRecordOffset, record)) {
                        return false;
                    }
                } else {
                    std::uint16_t narrow = 0U;
                    if (!readU16(image, kImageSize, kRecordOffset, narrow)) {
                        return false;
                    }
                    record = narrow;
                }
                // For all three known symbol record types, the page offset is stored in the lower 12 bits.
                const std::uint64_t kSite =
                    static_cast<std::uint64_t>(blockRva) + (record & 0x0FFFU);
                if (kSite >= static_cast<std::uint64_t>(kSizeOfImage)) {
                    // Site beyond image: no bytes to mark; record separately instead of silently dropping.
                    ++group.sitesOutsideImage;
                    continue;
                }
                const std::uint64_t kSiteEnd =
                    std::min<std::uint64_t>(kSite + kDvrtSiteSpan, kSizeOfImage);
                RvaRange range;
                range.rva = static_cast<std::uint32_t>(kSite);
                range.length = static_cast<std::uint32_t>(kSiteEnd - kSite);
                siteRanges.push_back(range);
                ++group.sitesDecoded;
            }
        }
        consumed += blockSize;
    }

    // The remaining bytes cannot hold another block header or block, but they must all be 0 padding. Otherwise,
    // unrecognized records may remain there and the affected range cannot be considered fully bounded.
    for (std::uint32_t index = consumed; index < payloadBytes; ++index) {
        std::uint8_t pad = 0U;
        if (!readU8(image, kImageSize, payloadRva + index, pad) || pad != 0U) {
            return false;
        }
    }
    return true;
}

// I-03: Locate the IMAGE_DYNAMIC_RELOCATION_TABLE from the LoadConfig directory and mark
// loader-writable sites as incomparable. The parsing status of the entire file is
// **unaffected** by this function; DVRT issues only degrade the scope, not cause image failure.
void parseDynamicRelocations(PeImageMap& map) {
    DynamicRelocationReport& report = map.dynamicRelocation;

    // "Indeed no DVRT": The ledger records "0 symbol sections, all processed"; only then can coverage be judged as complete.
    const auto kDeclareNotPresent = [&report]() {
        report.status = DvrtStatus::kNotPresent;
        report.coverage.requestedBegin = OptionalU64::of(0U);
        report.coverage.requestedEnd = OptionalU64::of(0U);
        report.coverage.processedBegin = OptionalU64::of(0U);
        report.coverage.processedEnd = OptionalU64::of(0U);
        report.coverage.totalKnown = OptionalU64::of(0U);
    };
    // "Possible DVRT but unbounded": Lacks the authority to declare any byte as 'no difference';
    // the entire image enters the incomparable range, and the diff engine marks them as 'excluded'.
    const auto kDeclareUnbounded = [&map, &report](DvrtStatus status) {
        report.status = status;
        report.extentUnknown = true;
        pushWholeImageNotComparable(map);
    };

    if (map.header.dataDirectoryCount <= kDirectoryIndexLoadConfig) {
        kDeclareNotPresent();
        return;
    }
    const std::uint32_t kLoadConfigRva = map.header.loadConfigDirectoryRva;
    const std::uint32_t kLoadConfigSize = map.header.loadConfigDirectorySize;
    if (kLoadConfigRva == 0U || kLoadConfigSize == 0U) {
        kDeclareNotPresent();
        return;
    }
    report.loadConfigRva = OptionalU64::of(kLoadConfigRva);
    report.loadConfigDeclaredSize = OptionalU64::of(kLoadConfigSize);
    if (static_cast<std::uint64_t>(kLoadConfigSize) < kLoadConfigMinSizeForDvrt) {
        // The structure declared in the directory is shorter than the version where the DVRT field appears—there is indeed no DVRT.
        kDeclareNotPresent();
        return;
    }
    if (!spanIsRawBacked(map, kLoadConfigRva, kLoadConfigMinSizeForDvrt)) {
        kDeclareUnbounded(DvrtStatus::kLoadConfigUnusable);
        return;
    }

    const std::uint8_t* image = map.image.data();
    const std::size_t kImageSize = map.image.size();
    std::uint32_t structSize = 0U;
    std::uint32_t tableOffset = 0U;
    std::uint16_t tableSectionOneBased = 0U;
    if (!readU32(image, kImageSize, kLoadConfigRva + kLoadConfigOffsetStructSize, structSize) ||
        !readU32(image, kImageSize, kLoadConfigRva + kLoadConfigOffsetDvrtTableOffset, tableOffset) ||
        !readU16(image, kImageSize, kLoadConfigRva + kLoadConfigOffsetDvrtTableSection,
                 tableSectionOneBased)) {
        kDeclareUnbounded(DvrtStatus::kLoadConfigUnusable);
        return;
    }
    report.loadConfigStructSize = OptionalU64::of(structSize);
    if (static_cast<std::uint64_t>(structSize) < kLoadConfigMinSizeForDvrt) {
        // The structure declares itself not that long: the DVRT field does not exist in this version.
        kDeclareNotPresent();
        return;
    }
    if (tableOffset == 0U || tableSectionOneBased == 0U) {
        kDeclareNotPresent();
        return;
    }

    // DynamicValueRelocTableSection uses 1-based section indices, with offsets relative to that section's VirtualAddress.
    const SectionMap* host = map.sectionAt(static_cast<std::size_t>(tableSectionOneBased) - 1U);
    if (host == nullptr || host->status != SectionMapStatus::kMapped) {
        kDeclareUnbounded(DvrtStatus::kLoadConfigUnusable);
        return;
    }
    const std::uint64_t kTableRva =
        static_cast<std::uint64_t>(host->virtualAddress) + static_cast<std::uint64_t>(tableOffset);
    report.tableRva = OptionalU64::of(kTableRva);
    if (!spanIsRawBacked(map, kTableRva, kDvrtTableHeaderSize)) {
        kDeclareUnbounded(DvrtStatus::kTableUnbacked);
        return;
    }

    std::uint32_t version = 0U;
    std::uint32_t tableSize = 0U;
    if (!readU32(image, kImageSize, kTableRva, version) ||
        !readU32(image, kImageSize, kTableRva + 4U, tableSize)) {
        kDeclareUnbounded(DvrtStatus::kTableUnbacked);
        return;
    }
    report.tableVersion = OptionalU64::of(version);
    report.tableSize = OptionalU64::of(tableSize);
    if (version != kDvrtTableVersionOne) {
        // If the version is unrecognized, decode zero bytes. 'Unrecognized' does not mean 'absent'.
        kDeclareUnbounded(DvrtStatus::kUnsupportedVersion);
        return;
    }

    const std::uint64_t kEntriesRva = kTableRva + kDvrtTableHeaderSize;
    report.coverage.requestedBegin = OptionalU64::of(kEntriesRva);
    report.coverage.requestedEnd = OptionalU64::of(kEntriesRva + tableSize);
    report.coverage.processedBegin = OptionalU64::of(kEntriesRva);
    report.coverage.processedEnd = OptionalU64::of(kEntriesRva);

    if (tableSize == 0U) {
        // Version is valid and table is empty: this is positive evidence that "no dynamic relocation sites" holds.
        report.status = DvrtStatus::kParsed;
        report.coverage.processedEnd = report.coverage.requestedEnd;
        report.coverage.totalKnown = OptionalU64::of(0U);
        return;
    }
    if (kEntriesRva + tableSize > static_cast<std::uint64_t>(map.header.sizeOfImage)) {
        kDeclareUnbounded(DvrtStatus::kMalformed);
        return;
    }
    if (!spanIsRawBacked(map, kEntriesRva, tableSize)) {
        kDeclareUnbounded(DvrtStatus::kTableUnbacked);
        return;
    }

    bool tableTruncated = false;   // The table is truncated mid-way: we do not know about the remaining segments.
    std::uint64_t groupsFailed = 0U;
    std::uint32_t consumed = 0U;
    while (static_cast<std::uint64_t>(tableSize - consumed) >= kDvrtEntryHeaderSize) {
        const std::uint64_t kEntryOffset = kEntriesRva + consumed;
        std::uint64_t symbol = 0U;
        std::uint32_t payloadBytes = 0U;
        if (!readU64(image, kImageSize, kEntryOffset, symbol) ||
            !readU32(image, kImageSize, kEntryOffset + 8U, payloadBytes)) {
            tableTruncated = true;
            break;
        }
        consumed += static_cast<std::uint32_t>(kDvrtEntryHeaderSize);
        if (payloadBytes == 0U || payloadBytes > tableSize - consumed) {
            tableTruncated = true;
            break;
        }

        DvrtSymbolGroup group;
        group.symbol = symbol;
        group.payloadBytes = payloadBytes;
        group.entryStride = dvrtEntryStride(symbol);
        group.containerWalked =
            walkDvrtBlocks(map, kEntriesRva + consumed, payloadBytes, group.entryStride, group,
                           report.siteRanges, report.unknownSymbolRanges);
        group.decoded = group.containerWalked && group.entryStride != 0U;

        ++report.groupsTotal;
        report.sitesDecoded += group.sitesDecoded;
        report.sitesOutsideImage += group.sitesOutsideImage;
        if (group.decoded) {
            ++report.groupsDecoded;
        } else if (group.containerWalked) {
            ++report.groupsUnknownSymbol;
        } else {
            ++groupsFailed;
        }
        report.groups.push_back(group);

        if (!group.containerWalked) {
            // None of the containers in this segment were traversed successfully, so the start of subsequent segments is untrusted; stop here.
            break;
        }
        consumed += payloadBytes;
        report.coverage.processedEnd = OptionalU64::of(kEntriesRva + consumed);
    }

    if (!tableTruncated && groupsFailed == 0U) {
        // The table tail is too short for another entry header or symbol segment; it must be padding filled entirely with 0.
        for (std::uint32_t index = consumed; index < tableSize; ++index) {
            std::uint8_t pad = 0U;
            if (!readU8(image, kImageSize, kEntriesRva + index, pad) || pad != 0U) {
                tableTruncated = true;
                break;
            }
        }
    }

    report.siteRanges = normalizeRvaRanges(std::move(report.siteRanges));
    report.unknownSymbolRanges = normalizeRvaRanges(std::move(report.unknownSymbolRanges));

    report.coverage.succeeded = report.groupsDecoded;
    // Unrecognized symbols are not 'failures' but 'skipped site-level decoding': the scope remains bounded by page granularity.
    report.coverage.skipped = report.groupsUnknownSymbol;
    report.coverage.failed = groupsFailed;
    report.coverage.truncated = tableTruncated ? 1U : 0U;

    if (tableTruncated || groupsFailed != 0U) {
        // Keep totalKnown unset: the table is truncated mid-way, and we don't know about subsequent symbol sections.
        kDeclareUnbounded(DvrtStatus::kMalformed);
    } else {
        report.coverage.processedEnd = report.coverage.requestedEnd;
        report.coverage.totalKnown = OptionalU64::of(report.groupsTotal);
        report.status = (report.groupsUnknownSymbol != 0U) ? DvrtStatus::kParsedWithUnknownSymbol
                                                           : DvrtStatus::kParsed;
    }

    // Site ranges and pages with unknown symbols are always added to non-comparable ranges: the loader-modified bytes do not exist on disk, so comparing
    // against original disk values will inevitably trigger an "unexplained difference" (a batch false positive explicitly prohibited by I-01).
    // Even if the entire file above is marked as non-comparable, record it here anyway — siteRanges is an independently exported
    // set, allowing the diff engine to label differences as 'dynamic relocation sites' rather than simply excluding them.
    for (const RvaRange& range : report.siteRanges) {
        map.notComparableRanges.push_back(range);
    }
    for (const RvaRange& range : report.unknownSymbolRanges) {
        map.notComparableRanges.push_back(range);
    }
}

} // namespace

PeImageMap buildPeImageMap(const std::uint8_t* fileBytes,
                           std::size_t fileSize,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options) {
    if (fileBytes == nullptr || fileSize == 0U) {
        return makeFailure(PeParseStatus::kEmptyInput, "pe.parse.emptyInput", fileSize, loadedBase);
    }
    if (fileSize < kDosHeaderSize) {
        return makeFailure(PeParseStatus::kTruncatedDosHeader, "pe.parse.truncatedDosHeader",
                           fileSize, loadedBase);
    }

    std::uint16_t dosMagic = 0U;
    if (!readU16(fileBytes, fileSize, 0U, dosMagic) || dosMagic != kDosSignature) {
        return makeFailure(PeParseStatus::kBadDosSignature, "pe.parse.badDosSignature",
                           fileSize, loadedBase);
    }

    std::uint32_t lfanew = 0U;
    if (!readU32(fileBytes, fileSize, kElfanewOffset, lfanew)) {
        return makeFailure(PeParseStatus::kTruncatedDosHeader, "pe.parse.truncatedDosHeader",
                           fileSize, loadedBase);
    }
    // e_lfanew must be 4-byte aligned and within the file; otherwise, none of the subsequent offsets can be trusted.
    if ((lfanew % 4U) != 0U || static_cast<std::uint64_t>(lfanew) >= fileSize) {
        return makeFailure(PeParseStatus::kBadNtHeaderOffset, "pe.parse.badNtHeaderOffset",
                           fileSize, loadedBase);
    }

    const std::uint64_t kNtOffset = lfanew;
    std::uint32_t ntSignature = 0U;
    if (!readU32(fileBytes, fileSize, kNtOffset, ntSignature)) {
        return makeFailure(PeParseStatus::kTruncatedNtHeaders, "pe.parse.truncatedNtHeaders",
                           fileSize, loadedBase);
    }
    if (ntSignature != kNtSignature) {
        return makeFailure(PeParseStatus::kBadNtSignature, "pe.parse.badNtSignature",
                           fileSize, loadedBase);
    }

    const std::uint64_t kFileHeaderOffset = kNtOffset + 4U;
    std::uint16_t machine = 0U;
    std::uint16_t sectionCount = 0U;
    std::uint32_t timeDateStamp = 0U;
    std::uint16_t sizeOfOptionalHeader = 0U;
    std::uint16_t fileCharacteristics = 0U;
    if (!readU16(fileBytes, fileSize, kFileHeaderOffset + 0U, machine) ||
        !readU16(fileBytes, fileSize, kFileHeaderOffset + 2U, sectionCount) ||
        !readU32(fileBytes, fileSize, kFileHeaderOffset + 4U, timeDateStamp) ||
        !readU16(fileBytes, fileSize, kFileHeaderOffset + 16U, sizeOfOptionalHeader) ||
        !readU16(fileBytes, fileSize, kFileHeaderOffset + 18U, fileCharacteristics)) {
        return makeFailure(PeParseStatus::kTruncatedNtHeaders, "pe.parse.truncatedNtHeaders",
                           fileSize, loadedBase);
    }

    const std::uint64_t kOptionalOffset = kFileHeaderOffset + kFileHeaderSize;
    if (sizeOfOptionalHeader < kOptionalHeader64MinSize) {
        return makeFailure(PeParseStatus::kTruncatedOptionalHeader, "pe.parse.truncatedOptionalHeader",
                           fileSize, loadedBase);
    }
    std::uint16_t optionalMagic = 0U;
    if (!readU16(fileBytes, fileSize, kOptionalOffset, optionalMagic)) {
        return makeFailure(PeParseStatus::kTruncatedOptionalHeader, "pe.parse.truncatedOptionalHeader",
                           fileSize, loadedBase);
    }
    if (optionalMagic != kOptionalMagicPe32Plus) {
        // This layer only supports PE64. PE32 requires a different set of field offsets and is out of scope
        // for this round—explicitly rejecting it is better than reading 32-bit headers using 64-bit offsets.
        return makeFailure(PeParseStatus::kUnsupportedOptionalMagic, "pe.parse.unsupportedOptionalMagic",
                           fileSize, loadedBase);
    }

    PeHeaderFacts header;
    header.machine = machine;
    header.sectionCount = sectionCount;
    header.fileCharacteristics = fileCharacteristics;
    header.timeDateStamp = timeDateStamp;
    header.ntHeadersFileOffset = kNtOffset;

    const bool kOptionalOk =
        readU32(fileBytes, fileSize, kOptionalOffset + 16U, header.entryPointRva) &&
        readU64(fileBytes, fileSize, kOptionalOffset + 24U, header.preferredImageBase) &&
        readU32(fileBytes, fileSize, kOptionalOffset + 32U, header.sectionAlignment) &&
        readU32(fileBytes, fileSize, kOptionalOffset + 36U, header.fileAlignment) &&
        readU32(fileBytes, fileSize, kOptionalOffset + 56U, header.sizeOfImage) &&
        readU32(fileBytes, fileSize, kOptionalOffset + 60U, header.sizeOfHeaders) &&
        readU32(fileBytes, fileSize, kOptionalOffset + 64U, header.checkSum) &&
        readU32(fileBytes, fileSize, kOptionalOffset + 108U, header.numberOfRvaAndSizes);
    if (!kOptionalOk) {
        return makeFailure(PeParseStatus::kTruncatedOptionalHeader, "pe.parse.truncatedOptionalHeader",
                           fileSize, loadedBase);
    }

    const std::uint64_t kDirectoryBase = kOptionalOffset + kOptionalHeader64MinSize;
    // I-02: NumberOfRvaAndSizes is declared by the file itself; must validate again using the **actual length of the optional header**.
    // Checking only that SizeOfOptionalHeader >= 112 is insufficient: if SizeOfOptionalHeader is declared as 112 and
    // NumberOfRvaAndSizes is 16, the directory entries fall after the 112-byte mark, which is already the section table bytes.
    // Thus, an attacker can fully control the RVA and size of the BASERELOC directory using just an 8-byte section name,
    // which determines which bytes are rewritten and which ranges are marked non-comparable. While the read operation
    // itself has bounds checking to prevent out-of-bounds access, the parser must never trust an unverified offset.
    const std::uint32_t kDirectoryRoom = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(sizeOfOptionalHeader) - kOptionalHeader64MinSize) /
        kDataDirectoryEntrySize);
    const std::uint32_t kDirectoryCount =
        std::min<std::uint32_t>({header.numberOfRvaAndSizes, 16U, kDirectoryRoom});
    header.dataDirectoryCount = kDirectoryCount;
    if (kDirectoryCount > kDirectoryIndexExport) {
        const std::uint64_t kAt = kDirectoryBase + kDirectoryIndexExport * kDataDirectoryEntrySize;
        if (!readU32(fileBytes, fileSize, kAt, header.exportDirectoryRva) ||
            !readU32(fileBytes, fileSize, kAt + 4U, header.exportDirectorySize)) {
            header.exportDirectoryRva = 0U;
            header.exportDirectorySize = 0U;
        }
    }
    if (kDirectoryCount > kDirectoryIndexBaseReloc) {
        const std::uint64_t kAt = kDirectoryBase + kDirectoryIndexBaseReloc * kDataDirectoryEntrySize;
        if (!readU32(fileBytes, fileSize, kAt, header.relocationDirectoryRva) ||
            !readU32(fileBytes, fileSize, kAt + 4U, header.relocationDirectorySize)) {
            header.relocationDirectoryRva = 0U;
            header.relocationDirectorySize = 0U;
        }
    }
    // I-03: DVRT entry point. If the directory entry count is less than 11, these two fields are left as 0;
    // parseDynamicRelocations uses this to determine that the LoadConfig directory definitely does not exist.
    if (kDirectoryCount > kDirectoryIndexLoadConfig) {
        const std::uint64_t kAt = kDirectoryBase + kDirectoryIndexLoadConfig * kDataDirectoryEntrySize;
        if (!readU32(fileBytes, fileSize, kAt, header.loadConfigDirectoryRva) ||
            !readU32(fileBytes, fileSize, kAt + 4U, header.loadConfigDirectorySize)) {
            header.loadConfigDirectoryRva = 0U;
            header.loadConfigDirectorySize = 0U;
        }
    }

    if (sectionCount == 0U || sectionCount > options.maxSectionCount) {
        return makeFailure(PeParseStatus::kInvalidSectionCount, "pe.parse.invalidSectionCount",
                           fileSize, loadedBase);
    }
    if (header.sizeOfImage == 0U || header.sizeOfImage > options.maxImageBytes ||
        header.sizeOfImage < header.sizeOfHeaders) {
        return makeFailure(PeParseStatus::kInvalidSizeOfImage, "pe.parse.invalidSizeOfImage",
                           fileSize, loadedBase);
    }
    // Invalid alignment values indicate the entire header is untrustworthy, as all section offset derivations rely on them.
    if (!isPowerOfTwo(header.sectionAlignment) || !isPowerOfTwo(header.fileAlignment) ||
        header.fileAlignment < 512U || header.fileAlignment > 65536U ||
        header.sectionAlignment < header.fileAlignment) {
        return makeFailure(PeParseStatus::kInvalidAlignment, "pe.parse.invalidAlignment",
                           fileSize, loadedBase);
    }

    header.sectionTableFileOffset = kOptionalOffset + sizeOfOptionalHeader;
    const std::uint64_t kSectionTableEnd =
        header.sectionTableFileOffset + static_cast<std::uint64_t>(sectionCount) * kSectionHeaderSize;
    if (kSectionTableEnd > fileSize) {
        return makeFailure(PeParseStatus::kTruncatedSectionTable, "pe.parse.truncatedSectionTable",
                           fileSize, loadedBase);
    }
    // I-02 new validation: section table entry count must be consistent with SizeOfHeaders. If the section table exceeds SizeOfHeaders, the
    // header declaration itself is contradictory, making it impossible to determine which version is authoritative; the entire file is rejected.
    if (kSectionTableEnd > static_cast<std::uint64_t>(header.sizeOfHeaders)) {
        return makeFailure(PeParseStatus::kSectionTableExceedsHeaders,
                           "pe.parse.sectionTableExceedsHeaders", fileSize, loadedBase);
    }

    PeImageMap map;
    map.status = PeParseStatus::kOk;
    map.header = header;
    map.loadedBase = loadedBase;
    map.fileSize = fileSize;
    map.image.assign(static_cast<std::size_t>(header.sizeOfImage), 0U);

    // Header: The file may be shorter than SizeOfHeaders (truncated sample); copy based on the actual readable length.
    const std::uint64_t kHeaderCopy =
        std::min<std::uint64_t>({static_cast<std::uint64_t>(header.sizeOfHeaders),
                                 static_cast<std::uint64_t>(fileSize),
                                 static_cast<std::uint64_t>(header.sizeOfImage)});
    if (kHeaderCopy != 0U) {
        std::memcpy(map.image.data(), fileBytes, static_cast<std::size_t>(kHeaderCopy));
    }
    map.headerRange.rva = 0U;
    map.headerRange.length = static_cast<std::uint32_t>(kHeaderCopy);
    if (kHeaderCopy != 0U) {
        map.rawBackedRanges.push_back(map.headerRange);
    }

    mapSections(fileBytes, fileSize, map);

    // DVRT parsing must validate LoadConfig and table bodies against the "file-byte-backed" criterion; first normalize the
    // set (merge adjacent ranges) to avoid misinterpreting spans crossing two adjacent raw-backed regions as unbacked.
    map.rawBackedRanges = normalizeRvaRanges(std::move(map.rawBackedRanges));
    // Parse before applying .reloc: DVRT entry fields (LoadConfig.Size, TableOffset, TableSection) and
    // table contents (block RVA, page offset) are not VAs and are unaffected by base address relocation.
    // Pre-reading is only to avoid introducing the extra variable 'semi-normalized image'.
    parseDynamicRelocations(map);

    if (options.applyRelocations) {
        applyRelocations(map);
    } else {
        map.relocation.delta = loadedBase - header.preferredImageBase;
        map.relocation.status = (map.relocation.delta == 0U) ? RelocationStatus::kNotNeeded
                                                             : RelocationStatus::kDirectoryMissing;
        if (map.relocation.delta != 0U) {
            // The caller explicitly disabled normalization, but the base address has indeed changed. The
            // criterion is identical to "no relocation directory": this image cannot be used as a disk reference.
            markWholeImageNotComparable(map);
        }
    }

    map.rawBackedRanges = normalizeRvaRanges(std::move(map.rawBackedRanges));
    map.zeroFillRanges = normalizeRvaRanges(std::move(map.zeroFillRanges));
    map.notComparableRanges = normalizeRvaRanges(std::move(map.notComparableRanges));
    // Non-comparable ranges take precedence: bytes covered by malformed sections or unsupported relocations yield no comparison conclusion.
    // rawBackedRanges: Preserves the pre-subtraction scope so the difference engine marks these bytes as 'excluded'.
    map.comparableRanges = subtractRvaRanges(map.rawBackedRanges, map.notComparableRanges);
    map.zeroFillRanges = subtractRvaRanges(map.zeroFillRanges, map.notComparableRanges);
    return map;
}

PeImageMap buildPeImageMap(const std::vector<std::uint8_t>& fileBytes,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options) {
    return buildPeImageMap(fileBytes.empty() ? nullptr : fileBytes.data(), fileBytes.size(),
                           loadedBase, options);
}

// ---------------------------------------------------------------------------
// Translation
// ---------------------------------------------------------------------------

RvaTranslation translateRva(const PeImageMap& map, std::uint32_t rva) noexcept {
    RvaTranslation result;
    if (!map.valid() || rva >= map.header.sizeOfImage) {
        result.kind = RvaKind::kOutsideImage;
        return result;
    }

    for (std::size_t index = 0; index < map.sections.size(); ++index) {
        const SectionMap& section = map.sections[index];
        if (section.effectiveVirtualSize == 0U) {
            continue;
        }
        if (!section.virtualRange().contains(rva)) {
            continue;
        }
        result.sectionIndex = index;
        if (section.status != SectionMapStatus::kMapped) {
            result.kind = RvaKind::kNotComparable;
            return result;
        }
        const std::uint32_t kOffsetInSection = rva - section.virtualAddress;
        if (kOffsetInSection < section.rawBackedBytes) {
            result.kind = RvaKind::kSectionRawBacked;
            result.fileOffset = OptionalU64::of(static_cast<std::uint64_t>(section.pointerToRawData) +
                                                kOffsetInSection);
            return result;
        }
        // Zero fill: The image indeed contains 0s, but there are no corresponding bytes in the file; fileOffset remains unset.
        result.kind = RvaKind::kSectionZeroFill;
        return result;
    }

    if (map.headerRange.contains(rva)) {
        result.kind = RvaKind::kHeader;
        result.fileOffset = OptionalU64::of(rva);
        return result;
    }

    result.kind = RvaKind::kSectionGap;
    return result;
}

FileOffsetTranslation translateFileOffset(const PeImageMap& map, std::uint64_t fileOffset) noexcept {
    FileOffsetTranslation result;
    if (!map.valid() || fileOffset >= map.fileSize) {
        result.kind = FileOffsetKind::kOutsideFile;
        return result;
    }

    for (std::size_t index = 0; index < map.sections.size(); ++index) {
        const SectionMap& section = map.sections[index];
        const std::uint32_t kRawSpan = (section.status == SectionMapStatus::kMapped)
                                          ? section.rawBackedBytes
                                          : section.sizeOfRawData;
        if (kRawSpan == 0U) {
            continue;
        }
        const std::uint64_t kBegin = section.pointerToRawData;
        const std::uint64_t kEnd = kBegin + kRawSpan;
        if (fileOffset < kBegin || fileOffset >= kEnd) {
            continue;
        }
        result.sectionIndex = index;
        if (section.status != SectionMapStatus::kMapped) {
            result.kind = FileOffsetKind::kNotComparable;
            return result;
        }
        result.kind = FileOffsetKind::kSectionRawData;
        result.rva = OptionalU64::of(static_cast<std::uint64_t>(section.virtualAddress) +
                                     (fileOffset - kBegin));
        return result;
    }

    if (map.headerRange.length != 0U && fileOffset < map.headerRange.length) {
        result.kind = FileOffsetKind::kHeader;
        result.rva = OptionalU64::of(fileOffset);
        return result;
    }

    result.kind = FileOffsetKind::kNotMappedByAnySection;
    return result;
}

std::size_t sectionIndexForRva(const PeImageMap& map, std::uint32_t rva) noexcept {
    for (std::size_t index = 0; index < map.sections.size(); ++index) {
        const SectionMap& section = map.sections[index];
        if (section.status == SectionMapStatus::kMapped && section.virtualRange().contains(rva)) {
            return index;
        }
    }
    return kInvalidSectionIndex;
}

std::string sectionNameForRva(const PeImageMap& map, std::uint32_t rva) {
    const std::size_t kIndex = sectionIndexForRva(map, rva);
    if (kIndex != kInvalidSectionIndex) {
        return map.sections[kIndex].name;
    }
    if (map.headerRange.contains(rva)) {
        return std::string("(headers)");
    }
    return std::string();
}

bool readNormalizedBytes(const PeImageMap& map,
                         std::uint32_t rva,
                         std::uint32_t length,
                         std::vector<std::uint8_t>& out) {
    if (!map.valid() || length == 0U) {
        return false;
    }
    const std::uint64_t kEnd = static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(length);
    if (kEnd > static_cast<std::uint64_t>(map.image.size())) {
        return false;
    }
    RvaRange span;
    span.rva = rva;
    span.length = length;
    // I-05: The entire span must fall within comparableRanges, which equals 'bytes backed by file' minus 'marked
    // as non-comparable'. This criterion blocks three types of forgery: non-comparable ranges (malformed sections,
    // unsupported relocations, or unnormalized images), zero-filled regions, and alignment gaps not belonging to
    // any section. While the latter two are indeed 0 in the image, they lack corresponding bytes in the file.
    // Returning 'success + a block of 0s' would cause the caller to treat the padded 0s as real disk content.
    if (!rangesContainSpan(map.comparableRanges, span)) {
        return false;
    }
    out.assign(map.image.begin() + static_cast<std::ptrdiff_t>(rva),
               map.image.begin() + static_cast<std::ptrdiff_t>(kEnd));
    return true;
}

} // namespace ksword::evidence

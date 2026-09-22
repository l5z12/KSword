#pragma once

// The unique PE normalization core for module I: I-02 (correct mapping from file to image) and I-03 (relocation and load-time changes).
//
// Input is raw bytes from a disk file plus the target load base address; output is the image layout, a set of comparable intervals,
// and normalized image bytes. The repository previously had two parallel implementations (mapPeImage in KernelCleanImageBaseline.cpp
// and kernelHookReadPeBytesAtRva in KernelDock.KernelHooks.cpp), where the latter performs no relocations at all;
// The hard constraint for module I is 'no second PE parser can be introduced', so both locations must call this file.
//
// Design rationale (why this check):
//   * Perform boundary checks on all offsets before use; any out-of-bounds access must result in a status code, never reading out of bounds.
//   * Malformed handling is granular: only 'entire file unparseable' is rejected; a malformed section is marked as such.
//     Skip SectionMapStatus::NotComparable and continue mapping other sections; otherwise, a single
//     bad section would disable comparison for the entire module, effectively discarding the evidence.
//   * Unsupported relocation types are handled similarly: only mark the affected byte range as incomparable, preventing the entire image from failing.
//   * An RVA falling in the "zero-filled region" (within VirtualSize but beyond SizeOfRawData) is a distinct state,
//     not "missing from the file" — these two have completely different implications for difference interpretation.
//   * DVRT (Windows 10+ dynamic relocation table) locations are rewritten by the loader at startup; the rewritten
//     bytes do not exist on disk. They cannot be "normalized" nor treated as a clean baseline; they must be marked
//     as incomparable. This is the source of numerous false "unexplained differences" on ntoskrnl (I-03).
//
// This file is C++20, Qt-free, and Win32-free: PE structures are manually parsed by offset without relying on <Windows.h>.

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// RVA range and range set operations
// ---------------------------------------------------------------------------

// RVA range. A length of 0 indicates an empty range and participates in no set operations.
struct RvaRange final {
    std::uint32_t rva = 0;
    std::uint32_t length = 0;

    // Return the upper bound as a 64-bit value to prevent rva + length from wrapping in 32-bit arithmetic.
    constexpr std::uint64_t endExclusive() const noexcept {
        return static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(length);
    }

    constexpr bool empty() const noexcept { return length == 0U; }

    constexpr bool contains(std::uint32_t probe) const noexcept {
        return length != 0U && probe >= rva && static_cast<std::uint64_t>(probe) < endExclusive();
    }

    // Fully contains another range (empty ranges are not 'contained' by any range to avoid misinterpreting an empty set as resolved).
    constexpr bool containsRange(const RvaRange& other) const noexcept {
        return !other.empty() && !empty() && other.rva >= rva &&
               other.endExclusive() <= endExclusive();
    }

    constexpr bool overlaps(const RvaRange& other) const noexcept {
        return !empty() && !other.empty() && rva < other.endExclusive() &&
               other.rva < endExclusive();
    }

    friend constexpr bool operator==(const RvaRange& a, const RvaRange& b) noexcept {
        return a.rva == b.rva && a.length == b.length;
    }

    friend constexpr bool operator!=(const RvaRange& a, const RvaRange& b) noexcept {
        return !(a == b);
    }
};

// Sort and merge overlapping/adjacent ranges. Empty ranges are discarded.
std::vector<RvaRange> normalizeRvaRanges(std::vector<RvaRange> ranges);

// Subtract cut from base and normalize the result. Neither input needs to be sorted beforehand.
std::vector<RvaRange> subtractRvaRanges(const std::vector<RvaRange>& base,
                                        const std::vector<RvaRange>& cut);

// Intersection of base and mask; result is normalized.
std::vector<RvaRange> intersectRvaRanges(const std::vector<RvaRange>& base,
                                         const std::vector<RvaRange>& mask);

std::uint64_t rvaRangesTotalBytes(const std::vector<RvaRange>& ranges) noexcept;

bool rvaRangesContain(const std::vector<RvaRange>& ranges, std::uint32_t rva) noexcept;

// ---------------------------------------------------------------------------
// Parse status
// ---------------------------------------------------------------------------

// Only these cases represent 'entire file unparseable'; other malformed data is degraded by section or range.
enum class PeParseStatus {
    kOk,
    kEmptyInput,
    kTruncatedDosHeader,
    kBadDosSignature,
    kBadNtHeaderOffset,           // e_lfanew out of bounds or misaligned
    kTruncatedNtHeaders,
    kBadNtSignature,
    kUnsupportedOptionalMagic,    // Not PE32+
    kTruncatedOptionalHeader,
    kInvalidSectionCount,         // 0 or exceeds the upper limit.
    kTruncatedSectionTable,       // Section table truncated by end of file
    kSectionTableExceedsHeaders,  // I-02: Section table entry count does not match SizeOfHeaders.
    kInvalidSizeOfImage,          // Note: 0, less than SizeOfHeaders, or exceeding the forensic limit.
    kInvalidAlignment,            // Invalid SectionAlignment / FileAlignment
};

const char* peParseStatusName(PeParseStatus status) noexcept;

// ---------------------------------------------------------------------------
// Section
// ---------------------------------------------------------------------------

enum class SectionMapStatus {
    kMapped,         // Boundary check passed, mapped, and ready for comparison.
    kNotComparable,  // This section is malformed and has been skipped; the covered RVA range yields no comparison conclusions.
};

const char* sectionMapStatusName(SectionMapStatus status) noexcept;

// Specific reason why a single section is deemed incomparable. For UI and reports; do not use binary masking.
enum class SectionDefectReason {
    kNone,
    kZeroVirtualExtent,        // VirtualSize and SizeOfRawData are both 0.
    kVirtualRangeOutOfImage,   // VirtualAddress + VirtualSize exceeds SizeOfImage
    kVirtualRangeOverflow,     // 32-bit wraparound of VirtualAddress + VirtualSize
    kRawDataOutOfFile,         // PointerToRawData + SizeOfRawData exceeds the end of the file.
    kRawRangeOverflow,         // PointerToRawData + SizeOfRawData 32-bit wraparound
    // I-02: Overlaps with previously accepted section ranges, **or** overlaps with the PE header range [0, SizeOfHeaders).
    // Note: Headers are placed in the image before any sections; overlaying sections would cause the same RVA to
    // have two sources. These two types of overlaps are the same class of defect and share a single reason code.
    kOverlapsEarlierSection,
};

const char* sectionDefectReasonName(SectionDefectReason reason) noexcept;

struct SectionMap final {
    std::string name;                 // Up to 8 bytes, trailing NUL removed; uniqueness not guaranteed.
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;    // Original value in the header, which may be 0.
    std::uint32_t pointerToRawData = 0;
    std::uint32_t sizeOfRawData = 0;
    std::uint32_t characteristics = 0;

    // Effective virtual size: if VirtualSize is 0, fall back to SizeOfRawData (legacy linker behavior).
    std::uint32_t effectiveVirtualSize = 0;
    // Actual bytes copied from file into image = min(SizeOfRawData, effectiveVirtualSize).
    // When raw > virtual, trailing padding is not mapped into the image and is therefore excluded from comparison.
    std::uint32_t rawBackedBytes = 0;
    // Zero-fill length = effectiveVirtualSize - rawBackedBytes. These bytes are indeed 0 in the image,
    // but since there are no corresponding bytes in the file, they are distinguished from rawBacked.
    // Contract: The normalization process **never** writes bytes into the zero-fill region. Relocations targeting this area are rejected
    // and marked as NotComparable; otherwise, zeroFillRanges would simultaneously claim "this is 0" while hiding non-zero values.
    std::uint32_t zeroFillBytes = 0;

    SectionMapStatus status = SectionMapStatus::kNotComparable;
    SectionDefectReason defect = SectionDefectReason::kNone;

    bool executable() const noexcept;   // IMAGE_SCN_MEM_EXECUTE or CNT_CODE.
    bool writable() const noexcept;     // IMAGE_SCN_MEM_WRITE

    RvaRange virtualRange() const noexcept;    // [VA, VA + effectiveVirtualSize)
    RvaRange rawBackedRange() const noexcept;  // [VA, VA + rawBackedBytes)
    RvaRange zeroFillRange() const noexcept;   // [VA + rawBackedBytes, VA + effVSize)
};

// ---------------------------------------------------------------------------
// Header facts
// ---------------------------------------------------------------------------
struct PeHeaderFacts final {
    std::uint16_t machine = 0;
    std::uint16_t sectionCount = 0;
    std::uint16_t fileCharacteristics = 0;
    std::uint32_t timeDateStamp = 0;
    std::uint32_t checkSum = 0;
    std::uint64_t preferredImageBase = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint32_t sectionAlignment = 0;
    std::uint32_t fileAlignment = 0;
    std::uint32_t entryPointRva = 0;
    std::uint32_t numberOfRvaAndSizes = 0;   // Original value in the header; may not be trustworthy.
    // I-02: The actual count of data directory entries that fall within the optional header range and can be parsed =
    // min(NumberOfRvaAndSizes, 16, (SizeOfOptionalHeader - 112) / 8)。
    // Directory entries exceeding this count are actually located in the **section table bytes**, not as directories — ignore them all.
    std::uint32_t dataDirectoryCount = 0;
    std::uint32_t exportDirectoryRva = 0;
    std::uint32_t exportDirectorySize = 0;
    std::uint32_t relocationDirectoryRva = 0;
    std::uint32_t relocationDirectorySize = 0;
    // I-03: The DVRT entry resides in the LoadConfig directory (data directory 10). If the directory entry count is less
    // than 11, these two fields are always 0, which is **positive evidence**: "This PE has no LoadConfig directory at all."
    std::uint32_t loadConfigDirectoryRva = 0;
    std::uint32_t loadConfigDirectorySize = 0;
    std::uint64_t ntHeadersFileOffset = 0;
    std::uint64_t sectionTableFileOffset = 0;

    bool relocationsStripped() const noexcept;  // IMAGE_FILE_RELOCS_STRIPPED
};

// ---------------------------------------------------------------------------
// I-03 Relocation
// ---------------------------------------------------------------------------

enum class RelocationStatus {
    kNotNeeded,               // delta == 0, no normalization needed
    kApplied,                 // All entries applied for supported types.
    kAppliedWithUnsupported,  // Some types are unsupported; the corresponding byte ranges are marked as incomparable, while the rest are normalized.
    kDirectoryMissing,        // Relocation required but directory missing or length insufficient.
    kDirectoryUnbacked,       // Directory RVA does not fall within a range backed by file bytes; content is untrusted.
    kDirectoryMalformed,      // Header/entry truncated; remaining part stops.
    kStripped,                // Image declares RELOCS_STRIPPED but requires base address relocation.
};

const char* relocationStatusName(RelocationStatus status) noexcept;

// I-03: When delta != 0, only these three states indicate "the image has been normalized to the target base address". The other four states indicate
// normalization failed; at this point, map.image still resides at the bytes of the preferred base address. Using it as a disk reference for
// comparison would inevitably report spurious differences at every relocation point. Therefore, these states mark the entire image as incomparable.
bool relocationNormalizationSucceeded(RelocationStatus status) noexcept;

// Record unsupported relocation types and their affected byte ranges to explain to the UI why this segment is incomparable.
struct UnsupportedRelocation final {
    std::uint16_t type = 0;
    RvaRange range;
};

struct RelocationReport final {
    RelocationStatus status = RelocationStatus::kNotNeeded;
    std::uint64_t delta = 0;              // loadedBase - preferredImageBase (unsigned wraparound).
    // Count of WORD values that are relocation entries. The parameter WORD after HIGHADJ is not an entry:
    // it describes no relocation target. Counting it would keep succeeded + failed below totalKnown,
    // so any image with HIGHADJ could never have complete relocation coverage (I-03 / F-06).
    std::uint64_t entriesTotal = 0;
    std::uint64_t entriesApplied = 0;     // Entries that actually rewrote bytes.
    std::uint64_t entriesAbsolute = 0;    // ABSOLUTE alignment padding, recorded as 'skip'.
    std::uint64_t entriesUnsupported = 0; // Type unsupported.
    std::uint64_t entriesOutOfRange = 0;  // Target exceeds the image; no bytes changed.
    // The target span is not fully backed by file bytes: it lies in zero-fill space or crosses a
    // raw/zero-fill boundary. Reject these relocations. The loader would write there, but the disk
    // reference contains only fabricated zeros. Rewriting them would violate zeroFillRanges and
    // mistake invented values for original disk contents. Mark the entire range incomparable (I-02).
    std::uint64_t entriesUnbackedTarget = 0;
    // HIGHADJ parameter: tracked separately as "skipped parameters" and not included in entriesTotal (I-03 / F-06).
    std::uint64_t entriesSkippedParameter = 0;
    std::uint32_t blocksProcessed = 0;

    // Set of bytes modified by relocations. The diff engine can exclude these (e.g., when precise normalization is impossible).
    std::vector<RvaRange> touchedRanges;
    std::vector<UnsupportedRelocation> unsupported;
    // Unbacked target ranges that were rejected for application, separated from
    // unsupported: the type is supported, but the issue lies in the target location.
    std::vector<RvaRange> unbackedTargetRanges;

    // I-03: true if delta != 0 but normalization failed, at which point the entire image is added to
    // notComparableRanges. Callers use this to know that "no disk reference is available for this comparison".
    bool imageNotNormalized = false;

    // I-09: feed applied/unsupported items into the unified ledger.
    CoverageAccount coverage;
};

// ---------------------------------------------------------------------------
// I-03 DVRT: Windows 10+ IMAGE_DYNAMIC_RELOCATION_TABLE
// ---------------------------------------------------------------------------
//
// DVRT and .reloc are two different things; do not confuse them:
//   * The .reloc section describes 'replacing the preferred base address with the actual base address'. Since
//     the delta is known, the post-load bytes can be calculated from the disk bytes — this is normalization.
//   * DVRT describes 'the loader rewrites this instruction based on the current system state' (import optimization
//     converts indirect calls via IAT to direct calls; retpoline converts indirect jumps to thunk calls).
//     The rewrite result depends on runtime-known IAT content and CPU mitigation policy switches; the rewritten bytes do not
//     exist on disk. Therefore, DVRT sites cannot be normalized or used as a clean baseline; they must be marked as incomparable.
// The consequence of not marking it is deterministic: every modified call site in ntoskrnl becomes an
// "unexplained code difference," which constitutes the batch false positives explicitly prohibited by I-01.

// Known dynamic relocation symbol IDs (IMAGE_DYNAMIC_RELOCATION_* constants from winnt.h).
inline constexpr std::uint64_t kDvrtSymbolGuardRfPrologue = 1U;
inline constexpr std::uint64_t kDvrtSymbolGuardRfEpilogue = 2U;
inline constexpr std::uint64_t kDvrtSymbolImportControlTransfer = 3U;
inline constexpr std::uint64_t kDvrtSymbolIndirControlTransfer = 4U;
inline constexpr std::uint64_t kDvrtSymbolSwitchtableBranch = 5U;

// Maximum bytes covered by one site. On x64, the rewritten call/jmp uses an 8-byte allowance for prefixes and ModRM. Prefer
// marking a slightly larger range as non-comparable over missing rewritten bytes and reporting them as clean differences.
inline constexpr std::uint32_t kDvrtSiteSpan = 8U;

// Page size described by IMAGE_BASE_RELOCATION blocks. DVRT uses the same block container.
inline constexpr std::uint32_t kRelocationPageBytes = 0x1000U;

enum class DvrtStatus {
    // Positive evidence: This PE indeed lacks DVRT (no LoadConfig directory, LoadConfig structure predates
    // the DVRT field, or table offset is 0). Only this specific type of "absence" is trustworthy.
    kNotPresent,
    kParsed,                  // After table traversal, all symbols are decoded by offset.
    kParsedWithUnknownSymbol, // The table has been traversed, but symbols could not be resolved; the scope of impact is defined at page granularity per block.
    kLoadConfigUnusable,      // LoadConfig directory out of bounds / no file bytes backing it / host sections unavailable.
    kTableUnbacked,           // The table range has no backing file bytes; the 0 values read are synthetic.
    kUnsupportedVersion,      // Table version is not 1; field meanings are unknown.
    kMalformed,               // size out of bounds / invalid block length / truncated entry header
};

const char* dvrtStatusName(DvrtStatus status) noexcept;

// Only these three states fully define 'which bytes DVRT may modify'. In other states, while we know DVRT
// may exist, we cannot define boundaries. Consequently, the entire image is added to notComparableRanges;
// without defined boundaries, we cannot claim 'there is no difference' for any byte.
bool dvrtExtentFullyBounded(DvrtStatus status) noexcept;

// Accounting for a symbol segment (IMAGE_DYNAMIC_RELOCATION64 + its subsequent base relocation block).
struct DvrtSymbolGroup final {
    std::uint64_t symbol = 0;
    std::uint32_t payloadBytes = 0;        // BaseRelocSize
    // Byte width per record; 0 indicates this layer does not recognize the symbol, so the site cannot be decoded.
    std::uint32_t entryStride = 0;
    std::uint64_t blocksWalked = 0;
    std::uint64_t sitesDecoded = 0;
    std::uint64_t sitesOutsideImage = 0;   // Site exceeds SizeOfImage; no range marked.
    // Whether traversal of the container (block-header sequence) completed. Complete traversal bounds affected pages even for unknown symbols.
    bool containerWalked = false;
    // Site-level decoding completed = symbol known and container path validated.
    bool decoded = false;
};

struct DynamicRelocationReport final {
    DvrtStatus status = DvrtStatus::kNotPresent;

    // Use OptionalU64 everywhere: if not read, it remains unset; never use 0 to fake a read value of 0.
    OptionalU64 loadConfigRva;
    OptionalU64 loadConfigDeclaredSize;   // Declared size in the data directory.
    OptionalU64 loadConfigStructSize;     // The Size field of the structure itself.
    OptionalU64 tableRva;
    OptionalU64 tableVersion;
    OptionalU64 tableSize;

    std::uint64_t groupsTotal = 0;
    std::uint64_t groupsDecoded = 0;        // Symbol known and container path valid.
    std::uint64_t groupsUnknownSymbol = 0;  // Symbol unrecognized; boundaries defined only by page.
    std::uint64_t sitesDecoded = 0;
    std::uint64_t sitesOutsideImage = 0;
    std::vector<DvrtSymbolGroup> groups;

    // Byte ranges covered by decoded sites (each site spans kDvrtSiteSpan bytes, truncated by SizeOfImage).
    // This is the set of "independently exportable RVA ranges": the diff engine can use it to exclude or annotate differences.
    std::vector<RvaRange> siteRanges;
    // When symbols are unrecognized but the container path succeeds, this describes the full page range covered by the block.
    // It is coarser than siteRanges but remains a provable upper bound—the loader only modifies bytes within these pages.
    std::vector<RvaRange> unknownSymbolRanges;

    // status is true when not in dvrtExtentFullyBounded, at which point the entire image has been processed.
    // notComparableRanges。
    bool extentUnknown = false;

    // I-09: Account by symbol section.
    CoverageAccount coverage;

    // siteRanges ∪ unknownSymbolRanges, normalized. Single entry point for the diff engine.
    std::vector<RvaRange> affectedRanges() const;
};

// ---------------------------------------------------------------------------
// RVA <-> file offset
// ---------------------------------------------------------------------------

inline constexpr std::size_t kInvalidSectionIndex = static_cast<std::size_t>(-1);

enum class RvaKind {
    kOutsideImage,      // RVA >= SizeOfImage
    kHeader,            // Within SizeOfHeaders.
    kSectionRawBacked,  // Within a section and backed by file bytes.
    kSectionZeroFill,   // Within the section but beyond SizeOfRawData: 0-filled in the image, but absent in the file.
    kSectionGap,        // Within SizeOfImage but not belonging to any mapped section (alignment gap).
    kNotComparable,     // Falls within a section deemed malformed.
};

const char* rvaKindName(RvaKind kind) noexcept;

struct RvaTranslation final {
    RvaKind kind = RvaKind::kOutsideImage;
    // Only Header and SectionRawBacked are present; zero-padding/gaps have no file offset. We keep this
    // unset rather than filling 0, otherwise the caller might read the file header as section content.
    OptionalU64 fileOffset;
    std::size_t sectionIndex = kInvalidSectionIndex;
};

enum class FileOffsetKind {
    kOutsideFile,            // Exceeds file length.
    kHeader,                 // Within SizeOfHeaders.
    kSectionRawData,         // Falls within the raw region of a mapped section.
    kNotMappedByAnySection,  // Present in file but no section maps it into the image (overwrites data/certificates).
    kNotComparable,          // Falls within the raw region of a section deemed malformed.
};

const char* fileOffsetKindName(FileOffsetKind kind) noexcept;

struct FileOffsetTranslation final {
    FileOffsetKind kind = FileOffsetKind::kOutsideFile;
    OptionalU64 rva;
    std::size_t sectionIndex = kInvalidSectionIndex;
};

// ---------------------------------------------------------------------------
// Mapping result
// ---------------------------------------------------------------------------

struct PeMapOptions final {
    // Forensics limit: stop allocating buffers beyond this to prevent malformed SizeOfImage from exhausting memory.
    std::uint32_t maxImageBytes = 512U * 1024U * 1024U;
    std::uint16_t maxSectionCount = 96U;
    bool applyRelocations = true;
};

struct PeImageMap final {
    PeParseStatus status = PeParseStatus::kEmptyInput;
    std::string errorDetail;            // Non-empty only when status != Ok; it is an i18n key, not a full sentence.

    PeHeaderFacts header;
    std::vector<SectionMap> sections;

    std::uint64_t loadedBase = 0;       // Target base address for normalization.
    std::uint64_t fileSize = 0;

    // Normalized image bytes, with size always equal to SizeOfImage (when status == Ok).
    std::vector<std::uint8_t> image;

    RvaRange headerRange;                        // [0, min(SizeOfHeaders, SizeOfImage))
    // All ranges with file byte backing: headers + raw backing regions of all mapped sections. This represents the 'intended comparison range';
    // the diff engine uses this as the request set so that incomparable parts are recorded as 'excluded' rather than 'never requested'.
    std::vector<RvaRange> rawBackedRanges;
    std::vector<RvaRange> zeroFillRanges;        // Zero-fill regions of all mapped sections.
    // Malformed sections, unsupported or file-unbacked relocation targets, and DVRT sites.
    // This covers the entire image when delta != 0 but normalization cannot complete (Stripped
    // / DirectoryMissing / DirectoryUnbacked / DirectoryMalformed), or when DVRT effects
    // cannot be bounded. See relocationNormalizationSucceeded and dvrtExtentFullyBounded.
    std::vector<RvaRange> notComparableRanges;
    // Convenience view: rawBackedRanges minus notComparableRanges.
    std::vector<RvaRange> comparableRanges;

    RelocationReport relocation;
    DynamicRelocationReport dynamicRelocation;

    // I-09: section-level attempt/success/failure accounting.
    CoverageAccount sectionCoverage;

    bool valid() const noexcept { return status == PeParseStatus::kOk; }

    // Raw-backed ranges with executable attributes in mapped sections. Inline hook baselines require only this portion.
    // Consistent with rawBackedRanges: do not pre-subtract notComparableRanges. Let the diff engine perform
    // the subtraction and accounting; otherwise, excluded bytes will silently disappear from coverage.
    std::vector<RvaRange> executableRawBackedRanges() const;

    const SectionMap* sectionAt(std::size_t index) const noexcept;
};

// Main entry point. fileBytes may be nullptr (in which case fileSize must be 0); returns EmptyInput.
PeImageMap buildPeImageMap(const std::uint8_t* fileBytes,
                           std::size_t fileSize,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options = PeMapOptions{});

PeImageMap buildPeImageMap(const std::vector<std::uint8_t>& fileBytes,
                           std::uint64_t loadedBase,
                           const PeMapOptions& options = PeMapOptions{});

RvaTranslation translateRva(const PeImageMap& map, std::uint32_t rva) noexcept;
FileOffsetTranslation translateFileOffset(const PeImageMap& map, std::uint64_t fileOffset) noexcept;

// Find the mapped section containing the given RVA; return kInvalidSectionIndex if not found.
std::size_t sectionIndexForRva(const PeImageMap& map, std::uint32_t rva) noexcept;

// Section name for the given RVA; returns "(headers)" if within the header, or an empty string if in a gap.
std::string sectionNameForRva(const PeImageMap& map, std::uint32_t rva);

// Fetch a byte segment from a normalized image. This is a "disk reference window" interface, so there is only one criterion:
// The requested span must fall entirely within comparableRanges (i.e., ranges backed by file bytes and not marked as incomparable).
// Return false without writing to out if the span is out of bounds, falls into an incomparable range (malformed section,
// unsupported relocations, DVRT sites, or non-normalized images), falls into zero-filled regions, or falls into section gaps.
// Zero-filled regions and gaps are 0 in the image but have no corresponding bytes in the file; returning "success + a block of 0s"
// would cause the caller to treat forged 0s as real disk content (I-05: if it cannot be read, it is missing; never pad with 00).
// Returning false does **not** mean "no difference"; the caller must interpret this as "uncomparable".
bool readNormalizedBytes(const PeImageMap& map,
                         std::uint32_t rva,
                         std::uint32_t length,
                         std::vector<std::uint8_t>& out);

} // namespace ksword::evidence

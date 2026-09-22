// Offline automated tests for the I module (kernel integrity check deepening).
//
// Coverage IDs: I-02 I-03 I-04 I-05 I-06 I-09 I-10.
//
// Partial coverage of the DVRT (Windows 10+ IMAGE_DYNAMIC_RELOCATION_TABLE) section in I-03:
//   * Decodes, records width, range, and accounting for the three supported symbol types (3
//     IMPORT_CONTROL_TRANSFER / 4 INDIR_CONTROL_TRANSFER / 5 SWITCHTABLE_BRANCH) at their respective sites.
//   * Unrecognized symbols are marked as incomparable at the page granularity of the block, preventing the entire image from failing.
//   * Malformed tables (unknown version / size out of bounds / invalid block length / block VA not page-aligned /
//     BaseRelocSize out of bounds / unexplained bytes at the tail) are all downgraded by range; PE parsing still succeeds.
//   * If LoadConfig or the table body falls in zero-filled regions, mark as "unavailable"; never infer "no DVRT".
// Not covered: real ntoskrnl samples (offline tests without binary samples) and field meanings for DVRT version 2+.
//
// All fixtures are synthesized in code as PE64 bytes in this file, with no dependency on sample files on disk. Expected
// values (RVA, file offset, length, zero-fill boundaries) are manually calculated from the constants below and hardcoded,
// not reverse-engineered from the code under test. The code under test only includes shared/evidence/PeImageMap.* and
// shared/evidence/ImageDiff.*; there is no second implementation of mapping or diffing in the tests.
//
// Regarding the source of "actual" bytes (this is the foundation of this test suite): the actual side for all difference comparisons
// is exclusively constructed by independentLoadedImage() in this file; **never** use the normalized map.image from PeImageMap. Using
// the latter would degrade every compareImage assertion to "reference vs. reference": if a few bytes are silently modified in the
// production normalization, the entire test suite would still pass. independentLoadedImage manually calculates based on the PE
// specification and the relocation points declared by the fixture, so "zero unexplained differences" is a meaningful assertion.

#include "TestSupport.h"

#include "../../../shared/evidence/ImageDiff.h"
#include "../../../shared/evidence/PeImageMap.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

// ---------------------------------------------------------------------------
// PE64 fixture constructor
// ---------------------------------------------------------------------------
// Fixed layout (manually calculated; test expectations are based on these constants):
//   0x0000: DOS header, e_lfanew = 0x40
//   0x0040  'PE\0\0'
//   0x0044 IMAGE_FILE_HEADER (20 bytes) 0x0058
//   IMAGE_OPTIONAL_HEADER64 (240 bytes = 112 + 16
//   * 8) 0x0148 Section table, 40 bytes per entry
constexpr std::size_t kNtOffset = 0x40U;
constexpr std::size_t kFileHeaderOffset = kNtOffset + 4U;          // 0x44
constexpr std::size_t kOptionalOffset = kFileHeaderOffset + 20U;   // 0x58
constexpr std::size_t kDataDirectoryOffset = kOptionalOffset + 112U; // 0xC8
constexpr std::size_t kSectionHeaderSize = 40U;
// The section table immediately follows the optional header: since SizeOfOptionalHeader is variable, the section table offset must follow it.
// SizeOfOptionalHeader == 240 corresponds exactly to 0x148.

constexpr std::uint32_t kCharsCode = 0x60000020U;   // CNT_CODE | MEM_EXECUTE | MEM_READ
constexpr std::uint32_t kCharsData = 0xC0000040U;   // CNT_INITIALIZED_DATA | READ | WRITE
constexpr std::uint32_t kCharsReloc = 0x42000040U;  // CNT_INITIALIZED_DATA | DISCARDABLE | READ

struct SectionSpec final {
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t pointerToRawData = 0;
    std::uint32_t sizeOfRawData = 0;
    std::uint32_t characteristics = 0;
    std::vector<std::uint8_t> content;  // Actual bytes written to the file; length may differ from sizeOfRawData.
};

struct PeBuilder final {
    std::uint64_t imageBase = 0x0000000140000000ULL;
    std::uint32_t sectionAlignment = 0x1000U;
    std::uint32_t fileAlignment = 0x200U;
    std::uint32_t sizeOfHeaders = 0x400U;
    std::uint32_t sizeOfImage = 0x5000U;
    std::uint32_t entryPointRva = 0x1000U;
    std::uint16_t machine = 0x8664U;
    std::uint16_t optionalMagic = 0x020BU;
    std::uint16_t sizeOfOptionalHeader = 240U;
    std::uint16_t fileCharacteristics = 0x0022U;  // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    std::uint32_t timeDateStamp = 0x60112233U;
    std::uint32_t checkSum = 0x00ABCDEFU;
    std::uint32_t relocDirectoryRva = 0U;
    std::uint32_t relocDirectorySize = 0U;
    // Data directory 10 = LOAD_CONFIG, the DVRT entry point. Both being 0 indicates 'no LoadConfig'.
    std::uint32_t loadConfigDirectoryRva = 0U;
    std::uint32_t loadConfigDirectorySize = 0U;
    std::uint32_t numberOfRvaAndSizes = 16U;
    std::vector<SectionSpec> sections;
    std::size_t truncateTo = 0U;  // Truncate the generated file to this length if non-0.
};

void ensure(std::vector<std::uint8_t>& buffer, std::size_t needed) {
    if (buffer.size() < needed) {
        buffer.resize(needed, 0U);
    }
}

void put8(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint8_t value) {
    ensure(buffer, at + 1U);
    buffer[at] = value;
}

void put16(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint16_t value) {
    put8(buffer, at, static_cast<std::uint8_t>(value & 0xFFU));
    put8(buffer, at + 1U, static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
}

void put32(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint32_t value) {
    put16(buffer, at, static_cast<std::uint16_t>(value & 0xFFFFU));
    put16(buffer, at + 2U, static_cast<std::uint16_t>((value >> 16U) & 0xFFFFU));
}

void put64(std::vector<std::uint8_t>& buffer, std::size_t at, std::uint64_t value) {
    put32(buffer, at, static_cast<std::uint32_t>(value & 0xFFFFFFFFULL));
    put32(buffer, at + 4U, static_cast<std::uint32_t>((value >> 32U) & 0xFFFFFFFFULL));
}

std::uint64_t readU64At(const std::vector<std::uint8_t>& buffer, std::size_t at) {
    std::uint64_t value = 0U;
    if (at + 8U <= buffer.size()) {
        std::memcpy(&value, buffer.data() + at, sizeof(value));
    }
    return value;
}

std::size_t sectionTableOffset(const PeBuilder& spec) {
    return kOptionalOffset + static_cast<std::size_t>(spec.sizeOfOptionalHeader);
}

std::vector<std::uint8_t> buildPe(const PeBuilder& spec) {
    std::vector<std::uint8_t> file;
    file.assign(spec.sizeOfHeaders, 0U);

    put16(file, 0U, 0x5A4DU);                 // 'MZ'
    put32(file, 0x3CU, static_cast<std::uint32_t>(kNtOffset));
    put32(file, kNtOffset, 0x00004550U);      // 'PE\0\0'

    put16(file, kFileHeaderOffset + 0U, spec.machine);
    put16(file, kFileHeaderOffset + 2U, static_cast<std::uint16_t>(spec.sections.size()));
    put32(file, kFileHeaderOffset + 4U, spec.timeDateStamp);
    put32(file, kFileHeaderOffset + 8U, 0U);
    put32(file, kFileHeaderOffset + 12U, 0U);
    put16(file, kFileHeaderOffset + 16U, spec.sizeOfOptionalHeader);
    put16(file, kFileHeaderOffset + 18U, spec.fileCharacteristics);

    put16(file, kOptionalOffset + 0U, spec.optionalMagic);
    put32(file, kOptionalOffset + 16U, spec.entryPointRva);
    put64(file, kOptionalOffset + 24U, spec.imageBase);
    put32(file, kOptionalOffset + 32U, spec.sectionAlignment);
    put32(file, kOptionalOffset + 36U, spec.fileAlignment);
    put32(file, kOptionalOffset + 56U, spec.sizeOfImage);
    put32(file, kOptionalOffset + 60U, spec.sizeOfHeaders);
    put32(file, kOptionalOffset + 64U, spec.checkSum);
    put32(file, kOptionalOffset + 108U, spec.numberOfRvaAndSizes);
    // Data directory 5 = BASERELOC. Write only if the optional header is long enough to hold the 6th directory (112 + 6*8
    // = 160 bytes); otherwise, those 8 bytes reside in the section table, and writing there would forge section headers.
    if (spec.sizeOfOptionalHeader >= 160U) {
        put32(file, kDataDirectoryOffset + 5U * 8U, spec.relocDirectoryRva);
        put32(file, kDataDirectoryOffset + 5U * 8U + 4U, spec.relocDirectorySize);
    }
    // Directory 10 requires the optional header to be at least 112 + 11 * 8 = 200 bytes long.
    if (spec.sizeOfOptionalHeader >= 200U) {
        put32(file, kDataDirectoryOffset + 10U * 8U, spec.loadConfigDirectoryRva);
        put32(file, kDataDirectoryOffset + 10U * 8U + 4U, spec.loadConfigDirectorySize);
    }

    for (std::size_t index = 0; index < spec.sections.size(); ++index) {
        const SectionSpec& section = spec.sections[index];
        const std::size_t kAt = sectionTableOffset(spec) + index * kSectionHeaderSize;
        for (std::size_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
            const std::uint8_t kValue =
                (byteIndex < section.name.size())
                    ? static_cast<std::uint8_t>(section.name[byteIndex])
                    : static_cast<std::uint8_t>(0U);
            put8(file, kAt + byteIndex, kValue);
        }
        put32(file, kAt + 8U, section.virtualSize);
        put32(file, kAt + 12U, section.virtualAddress);
        put32(file, kAt + 16U, section.sizeOfRawData);
        put32(file, kAt + 20U, section.pointerToRawData);
        put32(file, kAt + 24U, 0U);
        put32(file, kAt + 28U, 0U);
        put16(file, kAt + 32U, 0U);
        put16(file, kAt + 34U, 0U);
        put32(file, kAt + 36U, section.characteristics);
    }

    for (const SectionSpec& section : spec.sections) {
        if (section.content.empty()) {
            continue;
        }
        const std::size_t kAt = static_cast<std::size_t>(section.pointerToRawData);
        ensure(file, kAt + section.content.size());
        std::memcpy(file.data() + kAt, section.content.data(), section.content.size());
    }

    if (spec.truncateTo != 0U && spec.truncateTo < file.size()) {
        file.resize(spec.truncateTo);
    }
    return file;
}

// Deterministic, non-zero padding. Using 0 would allow defects like 'unread bytes are padded with 00' to pass by luck.
std::vector<std::uint8_t> patternBytes(std::size_t count, std::uint32_t seed) {
    std::vector<std::uint8_t> data(count, 0U);
    for (std::size_t index = 0; index < count; ++index) {
        const std::uint32_t kMixed = (static_cast<std::uint32_t>(index) * 7U + seed) % 191U;
        data[index] = static_cast<std::uint8_t>(0x40U + kMixed);
    }
    return data;
}

// Relocation type IDs. Hardcoded on the test fixture side, not taken from the code under test.
constexpr std::uint16_t kRelTypeAbsolute = 0U;
constexpr std::uint16_t kRelTypeHighLow = 3U;
constexpr std::uint16_t kRelTypeHighAdj = 4U;
constexpr std::uint16_t kRelTypeDir64 = 10U;
constexpr std::uint16_t kRelTypeReservedSeven = 7U;   // Types not supported at this level.

struct RelocEntrySpec final {
    std::uint16_t type = 0;
    std::uint32_t rva = 0;
};

// Single .reloc directory block: 8-byte block header + 2 bytes per entry.
std::vector<std::uint8_t> buildRelocBlock(std::uint32_t blockRva,
                                          const std::vector<RelocEntrySpec>& entries) {
    std::vector<std::uint8_t> blob;
    const std::uint32_t kBlockSize = 8U + static_cast<std::uint32_t>(entries.size()) * 2U;
    blob.assign(kBlockSize, 0U);
    put32(blob, 0U, blockRva);
    put32(blob, 4U, kBlockSize);
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const std::uint16_t kPacked = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(entries[index].type) << 12U) |
            static_cast<std::uint16_t>((entries[index].rva - blockRva) & 0x0FFFU));
        put16(blob, 8U + index * 2U, kPacked);
    }
    return blob;
}

// ---------------------------------------------------------------------------
// Fixture's own "loader": does not invoke the code under test.
// ---------------------------------------------------------------------------
// Manually lay out the file into an image per PE spec:
//   * Copy the header: min(SizeOfHeaders, file length, SizeOfImage) bytes.
//   * Copy min(SizeOfRawData, effective VirtualSize) bytes from each section to VirtualAddress; leave the rest at 0
//     (zero-filled). Skip sections whose raw data extends past the file end or whose virtual range exceeds SizeOfImage.
//   * When the base address changes, apply the delta to the DIR64 / HIGHLOW relocation points declared by the stub
//     itself—this is exactly how the real loader behaves, including cases where the target falls within zero-filled regions.
// This is the sole source of 'context' in the diff comparison. Since it shares no code with PeImageMap, assertions like
// 'relocation differences do not produce unexplained differences' truly verify the correctness of production normalization.
std::vector<std::uint8_t> independentLoadedImage(const PeBuilder& spec,
                                                 const std::vector<RelocEntrySpec>& relocEntries,
                                                 std::uint64_t loadedBase) {
    const std::vector<std::uint8_t> kFile = buildPe(spec);
    std::vector<std::uint8_t> image(static_cast<std::size_t>(spec.sizeOfImage), 0U);

    const std::size_t kHeaderCopy =
        std::min<std::size_t>({static_cast<std::size_t>(spec.sizeOfHeaders), kFile.size(),
                               static_cast<std::size_t>(spec.sizeOfImage)});
    if (kHeaderCopy != 0U) {
        std::memcpy(image.data(), kFile.data(), kHeaderCopy);
    }

    for (const SectionSpec& section : spec.sections) {
        const std::uint32_t kEffective =
            (section.virtualSize != 0U) ? section.virtualSize : section.sizeOfRawData;
        if (kEffective == 0U) {
            continue;
        }
        const std::uint64_t kVirtualEnd =
            static_cast<std::uint64_t>(section.virtualAddress) + static_cast<std::uint64_t>(kEffective);
        if (kVirtualEnd > static_cast<std::uint64_t>(spec.sizeOfImage)) {
            continue;
        }
        const std::uint32_t kRawBacked = std::min(section.sizeOfRawData, kEffective);
        if (kRawBacked == 0U) {
            continue;
        }
        const std::uint64_t kRawEnd = static_cast<std::uint64_t>(section.pointerToRawData) +
                                     static_cast<std::uint64_t>(kRawBacked);
        if (kRawEnd > static_cast<std::uint64_t>(kFile.size())) {
            continue;
        }
        std::memcpy(image.data() + section.virtualAddress,
                    kFile.data() + section.pointerToRawData,
                    static_cast<std::size_t>(kRawBacked));
    }

    const std::uint64_t kDelta = loadedBase - spec.imageBase;
    if (kDelta == 0U) {
        return image;
    }
    for (const RelocEntrySpec& entry : relocEntries) {
        if (entry.type == kRelTypeDir64) {
            if (static_cast<std::uint64_t>(entry.rva) + 8U > static_cast<std::uint64_t>(spec.sizeOfImage)) {
                continue;
            }
            std::uint64_t value = 0U;
            std::memcpy(&value, image.data() + entry.rva, sizeof(value));
            value += kDelta;
            std::memcpy(image.data() + entry.rva, &value, sizeof(value));
        } else if (entry.type == kRelTypeHighLow) {
            if (static_cast<std::uint64_t>(entry.rva) + 4U > static_cast<std::uint64_t>(spec.sizeOfImage)) {
                continue;
            }
            std::uint32_t value = 0U;
            std::memcpy(&value, image.data() + entry.rva, sizeof(value));
            value += static_cast<std::uint32_t>(kDelta & 0xFFFFFFFFULL);
            std::memcpy(image.data() + entry.rva, &value, sizeof(value));
        }
        // Other types are not supported at this layer: the production side marks their target ranges as
        // incomparable, so those bytes are never compared; keeping the disk's original value here is sufficient.
    }
    return image;
}

// ---------------------------------------------------------------------------
// Fixture A: section sizes differ + zero padding + gap.
//   SizeOfHeaders 0x400，SizeOfImage 0x5000
//   .text  VA 0x1000  VS 0x0A00  ptr 0x0400  raw 0x0800 -> 0x800 backed by raw data, 0x200 zero-filled
//   .data  VA 0x2000  VS 0x0400  ptr 0x0C00  raw 0x0200 -> 0x200 backed by raw data, 0x200 zero-filled
//   .pad   VA 0x3000  VS 0x0100  ptr 0x0E00  raw 0x0200 -> raw > virtual; backing truncated to 0x100
//   File length: 0x1000
// ---------------------------------------------------------------------------
PeBuilder makeLayoutFixture() {
    PeBuilder spec;
    spec.sizeOfImage = 0x5000U;

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = 0x1000U;
    text.virtualSize = 0x0A00U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x0800U;
    text.characteristics = kCharsCode;
    text.content = patternBytes(0x0800U, 1U);

    SectionSpec data;
    data.name = ".data";
    data.virtualAddress = 0x2000U;
    data.virtualSize = 0x0400U;
    data.pointerToRawData = 0x0C00U;
    data.sizeOfRawData = 0x0200U;
    data.characteristics = kCharsData;
    data.content = patternBytes(0x0200U, 2U);

    SectionSpec pad;
    pad.name = ".pad";
    pad.virtualAddress = 0x3000U;
    pad.virtualSize = 0x0100U;
    pad.pointerToRawData = 0x0E00U;
    pad.sizeOfRawData = 0x0200U;
    pad.characteristics = kCharsData;
    pad.content = patternBytes(0x0200U, 3U);

    spec.sections = {text, data, pad};
    return spec;
}

// ---------------------------------------------------------------------------
// Fixture B: Large .text for difference localization, crossing page boundaries at RVA 0x2000.
//   SizeOfHeaders 0x400，SizeOfImage 0x6000
//   .text VA 0x1000 VS 0x3000 ptr 0x0400 raw 0x3000 (file 0x0400..0x33FF)
//   .data VA 0x4000 VS 0x1000 ptr 0x3400 raw 0x0200 (file 0x3400..0x35FF)
//   Comparable range = [0x0000,0x0400) ∪ [0x1000,0x4200)
// ---------------------------------------------------------------------------
constexpr std::uint64_t kDiffLoadedBase = 0x0000000140000000ULL;

PeBuilder makeDiffFixture() {
    PeBuilder spec;
    spec.imageBase = kDiffLoadedBase;
    spec.sizeOfImage = 0x6000U;

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = 0x1000U;
    text.virtualSize = 0x3000U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x3000U;
    text.characteristics = kCharsCode;
    text.content = patternBytes(0x3000U, 11U);

    SectionSpec data;
    data.name = ".data";
    data.virtualAddress = 0x4000U;
    data.virtualSize = 0x1000U;
    data.pointerToRawData = 0x3400U;
    data.sizeOfRawData = 0x0200U;
    data.characteristics = kCharsData;
    data.content = patternBytes(0x0200U, 12U);

    spec.sections = {text, data};
    return spec;
}

// ---------------------------------------------------------------------------
// Fixture C: Image with .reloc, placing a DIR64 VA pointing to itself at RVA 0x1100.
//   .text  VA 0x1000  VS 0x1000  ptr 0x0400  raw 0x1000
//   .reloc VA 0x2000  ptr 0x1400
//   SizeOfImage 0x3000，ImageBase 0x140000000
// ---------------------------------------------------------------------------
constexpr std::uint64_t kRelocPreferredBase = 0x0000000140000000ULL;
constexpr std::uint64_t kRelocOtherBase = 0x0000000180000000ULL;
constexpr std::uint32_t kRelocTargetRva = 0x1100U;
constexpr std::uint32_t kUnsupportedTargetRva = 0x1150U;

// Construct a fixture using arbitrary raw .reloc bytes. For malformed directory cases, manually write
// block header bytes; expected values are manually calculated per PE spec, bypassing the code under test.
PeBuilder makeRelocSpecRaw(const std::vector<std::uint8_t>& relocBlob,
                           std::uint32_t dirRva,
                           std::uint32_t dirSize) {
    PeBuilder spec;
    spec.imageBase = kRelocPreferredBase;
    spec.sizeOfImage = 0x3000U;

    std::vector<std::uint8_t> textContent = patternBytes(0x1000U, 21U);
    // The value on disk is the 'VA that should exist when loaded at the preferred base'.
    put64(textContent, kRelocTargetRva - 0x1000U, kRelocPreferredBase + kRelocTargetRva);
    put64(textContent, kUnsupportedTargetRva - 0x1000U, kRelocPreferredBase + kUnsupportedTargetRva);

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = 0x1000U;
    text.virtualSize = 0x1000U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x1000U;
    text.characteristics = kCharsCode;
    text.content = textContent;

    SectionSpec reloc;
    reloc.name = ".reloc";
    reloc.virtualAddress = 0x2000U;
    reloc.virtualSize = 0x0200U;
    reloc.pointerToRawData = 0x1400U;
    reloc.sizeOfRawData = 0x0200U;
    reloc.characteristics = kCharsReloc;
    reloc.content = relocBlob;
    reloc.content.resize(0x0200U, 0U);   // Pad with zeros after the directory to ensure raw support covers the entire segment.

    spec.sections = {text, reloc};
    spec.relocDirectoryRva = dirRva;
    spec.relocDirectorySize = dirSize;
    return spec;
}

PeBuilder makeRelocSpec(const std::vector<RelocEntrySpec>& entries) {
    const std::vector<std::uint8_t> kBlob = buildRelocBlock(0x1000U, entries);
    return makeRelocSpecRaw(kBlob, 0x2000U, static_cast<std::uint32_t>(kBlob.size()));
}

std::vector<std::uint8_t> makeRelocImage(const std::vector<RelocEntrySpec>& entries) {
    return buildPe(makeRelocSpec(entries));
}

// ---------------------------------------------------------------------------
// Fixture D: Image with LoadConfig + DVRT (IMAGE_DYNAMIC_RELOCATION_TABLE)
// ---------------------------------------------------------------------------
// Layout (all manually calculated; expected values are based on these constants):
//   SizeOfHeaders 0x400，SizeOfImage 0x4000，ImageBase 0x140000000
//   .text VA 0x1000 VS 0x1000 ptr 0x0400 raw 0x1000 File
//   0x0400..0x13FF .rdata VA 0x2000 VS 0x1000 ptr 0x1400
//   raw 0x1000 File 0x1400..0x23FF File Length 0x2400
//   LoadConfig located at .rdata start → RVA 0x2000
//     +0    DWORD Size
//     +224 DWORD DynamicValueRelocTableOffset (relative to host section VirtualAddress)
//     +228 WORD DynamicValueRelocTableSection (1 = base section index, .rdata = 2).
//   DVRT table → RVA 0x2000 + 0x200 = 0x2200. Table header is 8 bytes; entries start
//   at 0x2208. .reloc (optional) → .rdata offset 0x400, i.e., RVA 0x2400
constexpr std::uint64_t kDvrtPreferredBase = 0x0000000140000000ULL;
constexpr std::uint32_t kDvrtSizeOfImage = 0x4000U;
constexpr std::uint32_t kDvrtTextRva = 0x1000U;
constexpr std::uint32_t kDvrtRdataRva = 0x2000U;
constexpr std::uint32_t kDvrtLoadConfigRva = 0x2000U;
constexpr std::uint32_t kDvrtTableOffsetInSection = 0x200U;
constexpr std::uint32_t kDvrtTableRva = 0x2200U;
constexpr std::uint32_t kDvrtEntriesRva = 0x2208U;
constexpr std::uint32_t kDvrtRelocOffsetInSection = 0x400U;
constexpr std::uint32_t kDvrtRelocRva = 0x2400U;
// IMAGE_LOAD_CONFIG_DIRECTORY64 must be at least 230 bytes to accommodate the DVRT field.
constexpr std::uint32_t kDvrtLoadConfigSize = 320U;
// The production layer provides a conservative byte count for site marking. The test fixture hard-codes this value rather than extracting it from the code under test.
constexpr std::uint32_t kExpectedSiteSpan = 8U;

// A base-relocation block: 8-byte header + multiple records. stride is the record width declared by the fixture.
std::vector<std::uint8_t> dvrtBlock(std::uint32_t blockRva,
                                    std::uint32_t stride,
                                    const std::vector<std::uint32_t>& records,
                                    std::uint32_t sizeOfBlockOverride = 0U) {
    std::vector<std::uint8_t> block;
    const std::uint32_t kSize = 8U + static_cast<std::uint32_t>(records.size()) * stride;
    block.assign(kSize, 0U);
    put32(block, 0U, blockRva);
    put32(block, 4U, (sizeOfBlockOverride != 0U) ? sizeOfBlockOverride : kSize);
    for (std::size_t index = 0; index < records.size(); ++index) {
        const std::size_t kAt = 8U + index * stride;
        if (stride == 4U) {
            put32(block, kAt, records[index]);
        } else {
            put16(block, kAt, static_cast<std::uint16_t>(records[index] & 0xFFFFU));
        }
    }
    return block;
}

// A symbol section: IMAGE_DYNAMIC_RELOCATION64 header (8 bytes for symbol + 4 bytes for BaseRelocSize)
// followed by payload. If sizeOverride is non-0, write this length (used to generate malformed samples).
void appendDvrtGroup(std::vector<std::uint8_t>& entries,
                     std::uint64_t symbol,
                     const std::vector<std::uint8_t>& payload,
                     std::uint32_t sizeOverride = 0U) {
    const std::size_t kAt = entries.size();
    entries.resize(kAt + 12U, 0U);
    put64(entries, kAt, symbol);
    put32(entries, kAt + 8U,
          (sizeOverride != 0U) ? sizeOverride : static_cast<std::uint32_t>(payload.size()));
    entries.insert(entries.end(), payload.begin(), payload.end());
}

// Header + entries. When sizeOverride is non-0, write this length (used to create size overflow samples).
std::vector<std::uint8_t> dvrtTable(std::uint32_t version,
                                    const std::vector<std::uint8_t>& entries,
                                    std::uint32_t sizeOverride = 0U) {
    std::vector<std::uint8_t> table(8U, 0U);
    put32(table, 0U, version);
    put32(table, 4U,
          (sizeOverride != 0U) ? sizeOverride : static_cast<std::uint32_t>(entries.size()));
    table.insert(table.end(), entries.begin(), entries.end());
    return table;
}

// Standard three-segment table. The RVA at each point is manually calculated:
//   Segment 1, symbol 3 IMPORT_CONTROL_TRANSFER: 4-byte records; the low 12 bits are the offset within the page.
//        Block VA 0x1000, records 0x00000120 / 0x00080340 -> sites 0x1120 / 0x1340.
//   Segment 2, symbol 4 INDIR_CONTROL_TRANSFER: 2-byte records.
//        Block VA 0x1000, records 0x1500 / 0x27F0 -> sites 0x1500 / 0x17F0.
//   Segment 3, symbol 5 SWITCHTABLE_BRANCH: 2-byte records (not 4-byte records).
//        Block VA 0x1000, records 0x3900 / 0x1A00 -> sites 0x1900 / 0x1A00.
// Segment sizes: 12 + 16 = 28, 12 + 12 = 24, and 12 + 12 = 24; 76 bytes total.
// The six locations are non-adjacent, each occupying 8 bytes, totaling 48 bytes that cannot be compared.
std::vector<std::uint8_t> canonicalDvrtEntries() {
    std::vector<std::uint8_t> entries;
    appendDvrtGroup(entries, 3U, dvrtBlock(0x1000U, 4U, {0x00000120U, 0x00080340U}));
    appendDvrtGroup(entries, 4U, dvrtBlock(0x1000U, 2U, {0x1500U, 0x27F0U}));
    appendDvrtGroup(entries, 5U, dvrtBlock(0x1000U, 2U, {0x3900U, 0x1A00U}));
    return entries;
}

constexpr std::uint32_t kCanonicalDvrtEntriesBytes = 76U;
constexpr std::uint32_t kCanonicalSiteRva0 = 0x1120U;
constexpr std::uint32_t kCanonicalSiteRva1 = 0x1340U;
constexpr std::uint32_t kCanonicalSiteRva2 = 0x1500U;
constexpr std::uint32_t kCanonicalSiteRva3 = 0x17F0U;
constexpr std::uint32_t kCanonicalSiteRva4 = 0x1900U;
constexpr std::uint32_t kCanonicalSiteRva5 = 0x1A00U;

// The optional DIR64 relocation point in Fixture D. Deliberately avoids the six DVRT points above.
constexpr std::uint32_t kDvrtRelocTargetRva = 0x1180U;

struct DvrtFixtureSpec final {
    std::vector<std::uint8_t> table;                    // DVRT table bytes written to .rdata
    std::uint32_t loadConfigDirectorySize = kDvrtLoadConfigSize;
    std::uint32_t loadConfigStructSize = kDvrtLoadConfigSize;
    std::uint32_t tableOffsetInSection = kDvrtTableOffsetInSection;
    std::uint16_t tableSectionOneBased = 2U;            // .rdata
    bool writeLoadConfigDirectory = true;
    bool includeReloc = false;                          // Place a .reloc at 0x400 in .rdata.
    std::uint32_t rdataRawSize = 0x1000U;               // Reducing this value pushes LoadConfig into the zero-filled region.
};

PeBuilder makeDvrtFixture(const DvrtFixtureSpec& fixture) {
    PeBuilder spec;
    spec.imageBase = kDvrtPreferredBase;
    spec.sizeOfImage = kDvrtSizeOfImage;

    std::vector<std::uint8_t> textContent = patternBytes(0x1000U, 31U);
    if (fixture.includeReloc) {
        // The value on disk is the 'VA that should exist when loaded at the preferred base'.
        put64(textContent, kDvrtRelocTargetRva - kDvrtTextRva,
              kDvrtPreferredBase + kDvrtRelocTargetRva);
    }

    // .rdata is filled with non-zero noise: defects where unread bytes are padded with 00 cannot be masked by "accidentally being 0".
    std::vector<std::uint8_t> rdataContent = patternBytes(0x1000U, 42U);
    put32(rdataContent, 0U, fixture.loadConfigStructSize);
    put32(rdataContent, 224U, fixture.tableOffsetInSection);
    put16(rdataContent, 228U, fixture.tableSectionOneBased);
    for (std::size_t index = 0; index < fixture.table.size(); ++index) {
        rdataContent[static_cast<std::size_t>(fixture.tableOffsetInSection) + index] =
            fixture.table[index];
    }
    if (fixture.includeReloc) {
        const std::vector<std::uint8_t> kRelocBlob =
            buildRelocBlock(kDvrtTextRva, {RelocEntrySpec{kRelTypeDir64, kDvrtRelocTargetRva}});
        for (std::size_t index = 0; index < kRelocBlob.size(); ++index) {
            rdataContent[static_cast<std::size_t>(kDvrtRelocOffsetInSection) + index] =
                kRelocBlob[index];
        }
        spec.relocDirectoryRva = kDvrtRelocRva;
        spec.relocDirectorySize = static_cast<std::uint32_t>(kRelocBlob.size());
    }
    rdataContent.resize(fixture.rdataRawSize);

    SectionSpec text;
    text.name = ".text";
    text.virtualAddress = kDvrtTextRva;
    text.virtualSize = 0x1000U;
    text.pointerToRawData = 0x0400U;
    text.sizeOfRawData = 0x1000U;
    text.characteristics = kCharsCode;
    text.content = textContent;

    SectionSpec rdata;
    rdata.name = ".rdata";
    rdata.virtualAddress = kDvrtRdataRva;
    rdata.virtualSize = 0x1000U;
    rdata.pointerToRawData = 0x1400U;
    rdata.sizeOfRawData = fixture.rdataRawSize;
    rdata.characteristics = kCharsData;
    rdata.content = rdataContent;

    spec.sections = {text, rdata};
    if (fixture.writeLoadConfigDirectory) {
        spec.loadConfigDirectoryRva = kDvrtLoadConfigRva;
        spec.loadConfigDirectorySize = fixture.loadConfigDirectorySize;
    }
    return spec;
}

PeImageMap buildDvrtMap(const DvrtFixtureSpec& fixture, std::uint64_t loadedBase) {
    const PeBuilder kSpec = makeDvrtFixture(fixture);
    return buildPeImageMap(buildPe(kSpec), loadedBase);
}

PeImageMap buildCanonicalDvrtMap() {
    DvrtFixtureSpec fixture;
    fixture.table = dvrtTable(1U, canonicalDvrtEntries());
    return buildDvrtMap(fixture, kDvrtPreferredBase);
}

// ---------------------------------------------------------------------------
// Fixture E: SizeOfImage is not a page multiple, used to verify the site is truncated or falls outside the image.
//   SizeOfImage 0x3F00
//   .text  VA 0x1000 VS 0x1000 ptr 0x0400 raw 0x1000
//   .rdata VA 0x2000 VS 0x1000 ptr 0x1400 raw 0x1000
//   .tail VA 0x3000 VS 0x0F00 ptr 0x2400 raw 0x0F00 → Exactly
// reaches the 0x3F00 block at VA 0x3000, recording 0xEFC / 0xF80:
//   Site 0x3EFC → 8 bytes would exceed 0x3F00, truncated to 4 bytes. Site
//   0x3F80 → already outside the image, mark zero bytes, but track separately.
// ---------------------------------------------------------------------------
constexpr std::uint32_t kClipSizeOfImage = 0x3F00U;
constexpr std::uint32_t kClipSiteRva = 0x3EFCU;
constexpr std::uint32_t kClipSiteLength = 4U;

PeBuilder makeDvrtClipFixture() {
    std::vector<std::uint8_t> entries;
    appendDvrtGroup(entries, 3U, dvrtBlock(0x3000U, 4U, {0x00000EFCU, 0x00000F80U}));

    DvrtFixtureSpec fixture;
    fixture.table = dvrtTable(1U, entries);
    PeBuilder spec = makeDvrtFixture(fixture);
    spec.sizeOfImage = kClipSizeOfImage;

    SectionSpec tail;
    tail.name = ".tail";
    tail.virtualAddress = 0x3000U;
    tail.virtualSize = 0x0F00U;
    tail.pointerToRawData = 0x2400U;
    tail.sizeOfRawData = 0x0F00U;
    tail.characteristics = kCharsData;
    tail.content = patternBytes(0x0F00U, 53U);
    spec.sections.push_back(tail);
    return spec;
}

const SectionMap* findSection(const PeImageMap& map, const char* name) {
    for (const SectionMap& section : map.sections) {
        if (section.name == name) {
            return &section;
        }
    }
    return nullptr;
}

const ImageDiffEntry* entryAt(const ImageDiffReport& report, std::uint32_t rva) {
    for (const ImageDiffEntry& entry : report.entries) {
        if (entry.rva == rva) {
            return &entry;
        }
    }
    return nullptr;
}

// Live image bytes: populated by the fixture's own loader, with no shared code with the tested PeImageMap.
// Deliberately **do not** provide convenience functions like LiveFromMap(map) — that would cause every difference assertion to degrade
// into a reference-to-reference comparison, allowing production normalization corruption to pass all checks as green (BLOCKER Q-01).
LiveImageBytes liveFromSpec(const PeBuilder& spec,
                            std::uint64_t loadedBase,
                            const std::vector<RelocEntrySpec>& relocEntries = {}) {
    return LiveImageBytes::fromBytes(0U, independentLoadedImage(spec, relocEntries, loadedBase));
}

ImageDiffOptions defaultOptions() {
    ImageDiffOptions options;
    options.evidenceSource = "test.offline.fixture";
    options.reference.kind = ReferenceSourceKind::kLocalDisk;
    options.reference.description = "fixture://disk";
    return options;
}

// ---------------------------------------------------------------------------
// Correct mapping of I-02 PE file to image
// ---------------------------------------------------------------------------
void testLayoutMapping(ksword_tests::Suite& s) {
    const std::vector<std::uint8_t> kFile = buildPe(makeLayoutFixture());
    s.expect(kFile.size() == 0x1000U, L"I-02 fixture file length is the hand-computed 0x1000");

    const PeImageMap kMap = buildPeImageMap(kFile, 0x0000000140000000ULL);
    s.expect(kMap.status == PeParseStatus::kOk, L"I-02 a well-formed PE64 parses");
    s.expect(kMap.image.size() == 0x5000U, L"I-02 the mapped image is exactly SizeOfImage bytes");
    s.expect(kMap.header.sectionAlignment == 0x1000U && kMap.header.fileAlignment == 0x200U,
             L"I-02 SectionAlignment and FileAlignment are read, not assumed");

    const SectionMap* text = findSection(kMap, ".text");
    const SectionMap* data = findSection(kMap, ".data");
    const SectionMap* pad = findSection(kMap, ".pad");
    s.expect(text != nullptr && data != nullptr && pad != nullptr,
             L"I-02 all three sections are present in the section list");
    if (text == nullptr || data == nullptr || pad == nullptr) {
        return;
    }

    // raw != virtual: 0x800 bytes are file-backed, while the remaining 0x200 bytes are zero-filled.
    s.expect(text->status == SectionMapStatus::kMapped, L"I-02 .text maps cleanly");
    s.expect(text->rawBackedBytes == 0x0800U, L"I-02 .text raw-backed length is 0x800");
    s.expect(text->zeroFillBytes == 0x0200U, L"I-02 .text zero-fill length is 0x200");
    // raw > virtual: The extra 0x100 trailing bytes cannot fit into the image, so they are excluded from comparison.
    s.expect(pad->rawBackedBytes == 0x0100U,
             L"I-02 a section whose SizeOfRawData exceeds VirtualSize is clamped to VirtualSize");
    s.expect(pad->zeroFillBytes == 0U, L"I-02 the clamped section has no zero fill");

    const RvaTranslation kAtStart = translateRva(kMap, 0x1000U);
    s.expect(kAtStart.kind == RvaKind::kSectionRawBacked &&
                 kAtStart.fileOffset == OptionalU64::of(0x0400U),
             L"I-02 RVA 0x1000 maps to file offset 0x400");
    const RvaTranslation kAtLastRaw = translateRva(kMap, 0x17FFU);
    s.expect(kAtLastRaw.kind == RvaKind::kSectionRawBacked &&
                 kAtLastRaw.fileOffset == OptionalU64::of(0x0BFFU),
             L"I-02 RVA 0x17FF maps to file offset 0xBFF");
    const RvaTranslation kAtZeroFill = translateRva(kMap, 0x1800U);
    s.expect(kAtZeroFill.kind == RvaKind::kSectionZeroFill && !kAtZeroFill.fileOffset.present,
             L"I-02 RVA 0x1800 reports zero-fill and carries no file offset");
    const RvaTranslation kAtZeroFillEnd = translateRva(kMap, 0x19FFU);
    s.expect(kAtZeroFillEnd.kind == RvaKind::kSectionZeroFill,
             L"I-02 the zero-fill window ends at VirtualSize, not at SizeOfRawData");
    const RvaTranslation kAtGap = translateRva(kMap, 0x1A00U);
    s.expect(kAtGap.kind == RvaKind::kSectionGap,
             L"I-02 the alignment gap after a section is neither section nor header");
    const RvaTranslation kAtHeader = translateRva(kMap, 0x0100U);
    s.expect(kAtHeader.kind == RvaKind::kHeader && kAtHeader.fileOffset == OptionalU64::of(0x0100U),
             L"I-02 header RVAs translate one-to-one to file offsets");
    const RvaTranslation kPast = translateRva(kMap, 0x5000U);
    s.expect(kPast.kind == RvaKind::kOutsideImage, L"I-02 RVA == SizeOfImage is outside the image");

    const FileOffsetTranslation kBackToText = translateFileOffset(kMap, 0x0400U);
    s.expect(kBackToText.kind == FileOffsetKind::kSectionRawData &&
                 kBackToText.rva == OptionalU64::of(0x1000U),
             L"I-02 file offset 0x400 translates back to RVA 0x1000");
    const FileOffsetTranslation kBackToHeader = translateFileOffset(kMap, 0x0100U);
    s.expect(kBackToHeader.kind == FileOffsetKind::kHeader,
             L"I-02 file offsets inside SizeOfHeaders translate back to the header");
    const FileOffsetTranslation kPadTail = translateFileOffset(kMap, 0x0F00U);
    s.expect(kPadTail.kind == FileOffsetKind::kNotMappedByAnySection,
             L"I-02 raw bytes past the clamped section are not mapped by any section");
    const FileOffsetTranslation kBeyond = translateFileOffset(kMap, 0x1000U);
    s.expect(kBeyond.kind == FileOffsetKind::kOutsideFile,
             L"I-02 a file offset at the file length is outside the file");

    // Zero-fill regions are indeed 0 in the image, not shifted from subsequent file bytes.
    s.expect(kMap.image[0x1800U] == 0U && kMap.image[0x19FFU] == 0U,
             L"I-02 zero-fill bytes are zero rather than the next file bytes");
    s.expect(kMap.image[0x3000U] == patternBytes(0x0200U, 3U)[0],
             L"I-02 the clamped section still maps its first VirtualSize bytes");
    s.expect(kMap.image[0x3100U] == 0U,
             L"I-02 raw bytes beyond VirtualSize never reach the image");

    s.expect(kMap.sectionCoverage.succeeded == 3U && kMap.sectionCoverage.failed == 0U,
             L"I-02 section coverage accounts three mapped and zero defective sections");
    s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 0x400U + 0x800U + 0x200U + 0x100U,
             L"I-02 comparable bytes are headers plus the raw-backed part of every section");

    // I-05: readNormalizedBytes is the "disk reference window" interface. While zero-filled regions and section gaps are indeed 0 in
    // the image, these bytes do not exist in the file. Returning "success + a block of zeros" would cause the caller to treat the
    // padded zeros as real disk content. The criterion is unified to "the entire segment must be supported by actual file bytes."
    std::vector<std::uint8_t> window;
    s.expect(readNormalizedBytes(kMap, 0x1500U, 0x10U, window) && window.size() == 0x10U &&
                 window[0] == patternBytes(0x0800U, 1U)[0x1500U - 0x1000U],
             L"I-05 a fully raw-backed window is returned and carries the on-disk bytes");
    s.expect(readNormalizedBytes(kMap, 0x0100U, 0x10U, window),
             L"I-05 a window inside the copied headers is raw-backed and readable");
    s.expect(!readNormalizedBytes(kMap, 0x1800U, 0x10U, window),
             L"I-05 a window inside a section's zero fill is refused, not answered with fabricated zeros");
    s.expect(!readNormalizedBytes(kMap, 0x17F8U, 0x10U, window),
             L"I-05 a window straddling the raw/zero-fill boundary is refused as a whole");
    s.expect(!readNormalizedBytes(kMap, 0x1A00U, 0x10U, window),
             L"I-05 a window in an alignment gap claimed by no section is refused");
    s.expect(!readNormalizedBytes(kMap, 0x3100U, 0x10U, window),
             L"I-05 raw bytes clamped away by VirtualSize are not readable through the image either");
}

void testMalformedSections(ksword_tests::Suite& s) {
    // Truncation: the .data raw section extends past the file end; skip only .data, while .text remains comparable.
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x0800U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0800U;
        text.characteristics = kCharsCode;
        text.content = patternBytes(0x0800U, 5U);
        SectionSpec data;
        data.name = ".data";
        data.virtualAddress = 0x2000U;
        data.virtualSize = 0x0200U;
        data.pointerToRawData = 0x0C00U;
        data.sizeOfRawData = 0x0200U;
        data.characteristics = kCharsData;
        data.content = patternBytes(0x0200U, 6U);
        spec.sections = {text, data};
        spec.truncateTo = 0x0D00U;

        const std::vector<std::uint8_t> kFile = buildPe(spec);
        s.expect(kFile.size() == 0x0D00U, L"I-02 the truncated fixture really is 0xD00 bytes");
        const PeImageMap kMap = buildPeImageMap(kFile, 0x0000000140000000ULL);
        s.expect(kMap.status == PeParseStatus::kOk,
                 L"I-02 a truncated section does not reject the whole image");
        const SectionMap* text2 = findSection(kMap, ".text");
        const SectionMap* data2 = findSection(kMap, ".data");
        s.expect(text2 != nullptr && text2->status == SectionMapStatus::kMapped,
                 L"I-02 the intact section keeps mapping after a truncated neighbour");
        s.expect(data2 != nullptr && data2->status == SectionMapStatus::kNotComparable &&
                     data2->defect == SectionDefectReason::kRawDataOutOfFile,
                 L"I-02 the truncated section is skipped and marked RawDataOutOfFile");
        s.expect(kMap.sectionCoverage.succeeded == 1U && kMap.sectionCoverage.failed == 1U,
                 L"I-02 the skipped section is accounted as failed, not silently dropped");
        s.expect(rvaRangesContain(kMap.notComparableRanges, 0x2000U),
                 L"I-02 the truncated section's virtual range is marked not comparable");
        s.expect(!rvaRangesContain(kMap.comparableRanges, 0x2000U),
                 L"I-02 the truncated section contributes no comparable bytes");
        s.expect(kMap.image.size() == 0x3000U,
                 L"I-02 the image buffer is still exactly SizeOfImage after a defect");
    }

    // Overlapping sections: later sections are incomparable; earlier sections are retained, and overlapping bytes are excluded from comparison as a whole.
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x4000U;
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x2000U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x2000U;
        text.characteristics = kCharsCode;
        text.content = patternBytes(0x2000U, 7U);
        SectionSpec overlap;
        overlap.name = ".ovl";
        overlap.virtualAddress = 0x1800U;   // Falls within the .text section [0x1000, 0x3000).
        overlap.virtualSize = 0x0400U;
        overlap.pointerToRawData = 0x2400U;
        overlap.sizeOfRawData = 0x0400U;
        overlap.characteristics = kCharsData;
        overlap.content = patternBytes(0x0400U, 8U);
        spec.sections = {text, overlap};

        const PeImageMap kMap = buildPeImageMap(buildPe(spec), 0x0000000140000000ULL);
        s.expect(kMap.status == PeParseStatus::kOk,
                 L"I-02 overlapping sections do not reject the whole image");
        const SectionMap* overlapped = findSection(kMap, ".ovl");
        s.expect(overlapped != nullptr && overlapped->status == SectionMapStatus::kNotComparable &&
                     overlapped->defect == SectionDefectReason::kOverlapsEarlierSection,
                 L"I-02 the overlapping section is detected and marked");
        s.expect(rvaRangesContain(kMap.comparableRanges, 0x17FFU) &&
                     !rvaRangesContain(kMap.comparableRanges, 0x1800U) &&
                     !rvaRangesContain(kMap.comparableRanges, 0x1BFFU) &&
                     rvaRangesContain(kMap.comparableRanges, 0x1C00U),
                 L"I-02 exactly the overlapped RVA window drops out of the comparable set");
    }

    // Out-of-bounds section: VirtualAddress + VirtualSize exceeds SizeOfImage.
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x0400U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0400U;
        text.characteristics = kCharsCode;
        text.content = patternBytes(0x0400U, 9U);
        SectionSpec past;
        past.name = ".past";
        past.virtualAddress = 0x2000U;
        past.virtualSize = 0x2000U;   // 0x2000 + 0x2000 = 0x4000 > SizeOfImage 0x3000
        past.pointerToRawData = 0x0800U;
        past.sizeOfRawData = 0x0200U;
        past.characteristics = kCharsData;
        past.content = patternBytes(0x0200U, 10U);
        spec.sections = {text, past};

        const PeImageMap kMap = buildPeImageMap(buildPe(spec), 0x0000000140000000ULL);
        const SectionMap* beyond = findSection(kMap, ".past");
        s.expect(beyond != nullptr && beyond->defect == SectionDefectReason::kVirtualRangeOutOfImage,
                 L"I-02 VirtualAddress + VirtualSize past SizeOfImage is rejected per section");
        s.expect(kMap.image.size() == 0x3000U,
                 L"I-02 an out-of-image section never grows the image buffer");
    }

    // Out-of-bounds raw data pointer: must not crash and must not read any bytes.
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec wild;
        wild.name = ".wild";
        wild.virtualAddress = 0x1000U;
        wild.virtualSize = 0x1000U;
        wild.pointerToRawData = 0x7FFFFF00U;   // Far exceeds file length
        wild.sizeOfRawData = 0x1000U;
        wild.characteristics = kCharsCode;
        SectionSpec wrap;
        wrap.name = ".wrap";
        wrap.virtualAddress = 0x2000U;
        wrap.virtualSize = 0x0800U;
        wrap.pointerToRawData = 0xFFFFFF00U;   // ptr + raw wraps around in 32-bit
        wrap.sizeOfRawData = 0x0800U;
        wrap.characteristics = kCharsData;
        spec.sections = {wild, wrap};

        const PeImageMap kMap = buildPeImageMap(buildPe(spec), 0x0000000140000000ULL);
        s.expect(kMap.status == PeParseStatus::kOk,
                 L"I-02 wild raw pointers stay a per-section defect");
        const SectionMap* wildSection = findSection(kMap, ".wild");
        const SectionMap* wrapSection = findSection(kMap, ".wrap");
        s.expect(wildSection != nullptr &&
                     wildSection->defect == SectionDefectReason::kRawDataOutOfFile,
                 L"I-02 a raw pointer past the file end is refused before any read");
        s.expect(wrapSection != nullptr &&
                     wrapSection->defect == SectionDefectReason::kRawRangeOverflow,
                 L"I-02 a raw range that wraps 32 bits is refused before any read");
        bool allZero = true;
        for (std::size_t index = 0x1000U; index < 0x3000U; ++index) {
            if (kMap.image[index] != 0U) {
                allZero = false;
                break;
            }
        }
        s.expect(allZero, L"I-02 nothing is copied into the image for defective sections");
        std::vector<std::uint8_t> scratch;
        s.expect(!readNormalizedBytes(kMap, 0x1000U, 0x10U, scratch),
                 L"I-02 normalized reads inside a defective section are refused");
        s.expect(!readNormalizedBytes(kMap, 0x2FF8U, 0x10U, scratch),
                 L"I-02 normalized reads past SizeOfImage are refused");
    }
}

// I-02: Boundaries between headers and sections, and boundaries of data directories. Both fixtures
// represent 'reading itself is within bounds, but the parser accepts an unverified offset'.
void testHeaderBoundaries(ksword_tests::Suite& s) {
    // The VirtualAddress of section (1) falls within SizeOfHeaders, causing the section content to overwrite the
    //     PE header bytes already placed in the image. Consequently, the same RVA has two contradictory sources.
    {
        PeBuilder spec;
        spec.sizeOfImage = 0x3000U;
        SectionSpec hdrOverlap;
        hdrOverlap.name = ".hdrovl";
        hdrOverlap.virtualAddress = 0x0200U;   // SizeOfHeaders is 0x400.
        hdrOverlap.virtualSize = 0x0200U;
        hdrOverlap.pointerToRawData = 0x0800U;
        hdrOverlap.sizeOfRawData = 0x0200U;
        hdrOverlap.characteristics = kCharsCode;
        hdrOverlap.content = patternBytes(0x0200U, 41U);
        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x0400U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0400U;
        text.characteristics = kCharsCode;
        text.content = patternBytes(0x0400U, 42U);
        spec.sections = {hdrOverlap, text};

        std::vector<std::uint8_t> file = buildPe(spec);
        // The header at offset 0x200 is originally padding with zeros; writing an identifiable
        // value ensures the assertion 'header bytes were not overwritten' is verifiable.
        file[0x0200U] = 0x5CU;

        const PeImageMap kMap = buildPeImageMap(file, 0x0000000140000000ULL);
        s.expect(kMap.status == PeParseStatus::kOk,
                 L"I-02 a section overlapping the headers stays a per-section defect");
        const SectionMap* overlapping = findSection(kMap, ".hdrovl");
        s.expect(overlapping != nullptr &&
                     overlapping->status == SectionMapStatus::kNotComparable &&
                     overlapping->defect == SectionDefectReason::kOverlapsEarlierSection,
                 L"I-02 a section whose VirtualAddress falls inside SizeOfHeaders is refused");
        s.expect(kMap.image[0x0200U] == 0x5CU,
                 L"I-02 the PE header bytes survive: the overlapping section never gets copied over them");
        s.expect(kMap.image[0x0200U] != patternBytes(0x0200U, 41U)[0],
                 L"I-02 the refused section's content is nowhere in the image");
        s.expect(rvaRangesContain(kMap.notComparableRanges, 0x0200U) &&
                     !rvaRangesContain(kMap.comparableRanges, 0x0200U),
                 L"I-02 the contested header window drops out of the comparable set");
        s.expect(rvaRangesContain(kMap.comparableRanges, 0x01FFU),
                 L"I-02 header bytes before the contested window stay comparable");
        // Source tracing must be unidirectional: 0x200 cannot be both a header and a section.
        const RvaTranslation kContested = translateRva(kMap, 0x0200U);
        s.expect(kContested.kind == RvaKind::kNotComparable,
                 L"I-02 a contested RVA reports NotComparable instead of claiming one of the two sources");
        const FileOffsetTranslation kSectionRaw = translateFileOffset(kMap, 0x0800U);
        s.expect(kSectionRaw.kind == FileOffsetKind::kNotComparable,
                 L"I-02 the refused section's raw bytes do not claim an RVA of their own");
        const FileOffsetTranslation kHeaderRaw = translateFileOffset(kMap, 0x0200U);
        s.expect(kHeaderRaw.kind == FileOffsetKind::kHeader && kHeaderRaw.rva == OptionalU64::of(0x0200U),
                 L"I-02 exactly one file offset maps to RVA 0x200, and it is the header one");
        // .text mapped as usual: a bad section should not crash the entire image.
        const SectionMap* text2 = findSection(kMap, ".text");
        s.expect(text2 != nullptr && text2->status == SectionMapStatus::kMapped,
                 L"I-02 the well-formed section keeps mapping next to a header-overlapping one");
    }

    // (2) SizeOfOptionalHeader = 112 and NumberOfRvaAndSizes = 16: directory entries actually fall within the
    //     section table bytes. An attacker can fully control the RVA/size of BASERELOC with just an 8-byte section name.
    {
        PeBuilder spec;
        spec.sizeOfOptionalHeader = 112U;   // Up to NumberOfRvaAndSizes only.
        spec.numberOfRvaAndSizes = 16U;     // But claims to have 16 directories.
        spec.sizeOfImage = 0x3000U;
        spec.relocDirectoryRva = 0x2000U;   // BuildPe will not write it at this length.
        spec.relocDirectorySize = 0x20U;
        SectionSpec reloc;
        reloc.name = ".reloc";              // The 8 bytes of the section name that were misread as a directory.
        reloc.virtualAddress = 0x1000U;
        reloc.virtualSize = 0x0400U;
        reloc.pointerToRawData = 0x0400U;
        reloc.sizeOfRawData = 0x0400U;
        reloc.characteristics = kCharsReloc;
        reloc.content = patternBytes(0x0400U, 43U);
        spec.sections = {reloc};

        const PeImageMap kMap = buildPeImageMap(buildPe(spec), 0x0000000140000000ULL);
        s.expect(kMap.status == PeParseStatus::kOk,
                 L"I-02 a 112-byte optional header still parses; the directories are simply absent");
        s.expect(kMap.header.dataDirectoryCount == 0U,
                 L"I-02 no data directory fits inside a 112-byte optional header");
        s.expect(kMap.header.relocationDirectoryRva == 0U &&
                     kMap.header.relocationDirectorySize == 0U,
                 L"I-02 section-table bytes are never read as a data directory");
        // 0x6C65722E is the little-endian representation of '.rel' — under legacy behavior, relocationDirectoryRva was exactly this value.
        s.expect(kMap.header.relocationDirectoryRva != 0x6C65722EU,
                 L"I-02 the relocation directory RVA is not the ASCII of a section name");
        s.expect(kMap.header.sectionTableFileOffset == kOptionalOffset + 112U,
                 L"I-02 the section table starts right after the declared optional header");
    }
}

void testWholeImageRejection(ksword_tests::Suite& s) {
    const std::vector<std::uint8_t> kEmpty;
    s.expect(buildPeImageMap(kEmpty, 0U).status == PeParseStatus::kEmptyInput,
             L"I-02 an empty buffer is rejected as EmptyInput");

    std::vector<std::uint8_t> notPe = buildPe(makeLayoutFixture());
    notPe[0] = 'Z';
    s.expect(buildPeImageMap(notPe, 0U).status == PeParseStatus::kBadDosSignature,
             L"I-02 a bad DOS signature rejects the whole file");

    // Mismatch between section count and SizeOfHeaders: the section table end (0x148 + 3 * 40 = 0x1E0) exceeds SizeOfHeaders (0x180).
    PeBuilder tight = makeLayoutFixture();
    tight.sizeOfHeaders = 0x180U;
    s.expect(buildPeImageMap(buildPe(tight), 0U).status ==
                 PeParseStatus::kSectionTableExceedsHeaders,
             L"I-02 a section table that overruns SizeOfHeaders rejects the whole file");

    PeBuilder pe32 = makeLayoutFixture();
    pe32.optionalMagic = 0x010BU;
    s.expect(buildPeImageMap(buildPe(pe32), 0U).status == PeParseStatus::kUnsupportedOptionalMagic,
             L"I-02 PE32 is refused rather than read with PE32+ field offsets");

    PeBuilder badAlign = makeLayoutFixture();
    badAlign.fileAlignment = 0x300U;   // Not a power of 2
    s.expect(buildPeImageMap(buildPe(badAlign), 0U).status == PeParseStatus::kInvalidAlignment,
             L"I-02 a non power-of-two FileAlignment rejects the whole file");

    PeBuilder tinyImage = makeLayoutFixture();
    tinyImage.sizeOfImage = 0x100U;    // Less than SizeOfHeaders
    s.expect(buildPeImageMap(buildPe(tinyImage), 0U).status == PeParseStatus::kInvalidSizeOfImage,
             L"I-02 SizeOfImage smaller than SizeOfHeaders rejects the whole file");
}

// ---------------------------------------------------------------------------
// I-03 Relocation and load changes.
// ---------------------------------------------------------------------------
void testRelocationNormalization(ksword_tests::Suite& s) {
    const std::vector<RelocEntrySpec> kEntries = {RelocEntrySpec{kRelTypeDir64, kRelocTargetRva}};
    const PeBuilder kRelocSpec = makeRelocSpec(kEntries);
    const std::vector<std::uint8_t> kFile = buildPe(kRelocSpec);

    const PeImageMap kAtPreferred = buildPeImageMap(kFile, kRelocPreferredBase);
    const PeImageMap kAtOther = buildPeImageMap(kFile, kRelocOtherBase);
    s.expect(kAtPreferred.status == PeParseStatus::kOk && kAtOther.status == PeParseStatus::kOk,
             L"I-03 the relocatable fixture parses at both bases");
    s.expect(kAtPreferred.relocation.status == RelocationStatus::kNotNeeded,
             L"I-03 mapping at the preferred base needs no relocation");
    s.expect(kAtOther.relocation.status == RelocationStatus::kApplied,
             L"I-03 mapping at a different base applies the relocation directory");
    s.expect(kAtOther.relocation.delta == kRelocOtherBase - kRelocPreferredBase,
             L"I-03 the recorded delta is the base difference");
    s.expect(kAtOther.relocation.entriesApplied == 1U &&
                 kAtOther.relocation.entriesUnsupported == 0U,
             L"I-03 exactly one DIR64 entry is applied");

    s.expect(readU64At(kAtPreferred.image, kRelocTargetRva) ==
                 kRelocPreferredBase + kRelocTargetRva,
             L"I-03 at the preferred base the stored VA is the on-disk value");
    s.expect(readU64At(kAtOther.image, kRelocTargetRva) == kRelocOtherBase + kRelocTargetRva,
             L"I-03 at the other base the DIR64 target is rebased");
    s.expect(kAtPreferred.image != kAtOther.image,
             L"I-03 the two normalized images really do differ (the fixture exercises relocation)");

    // The normalized production result must match byte-for-byte the loader image computed by the fixture. This is the only assertion in
    // the suite that directly catches 'normalized bytes modified or omitted': the right-hand side bypasses the code under test entirely.
    s.expect(kAtPreferred.image == independentLoadedImage(kRelocSpec, kEntries, kRelocPreferredBase),
             L"I-03 at the preferred base the normalized image equals the independently loaded image");
    s.expect(kAtOther.image == independentLoadedImage(kRelocSpec, kEntries, kRelocOtherBase),
             L"I-03 at the other base the normalized image equals the independently loaded image byte for byte");

    // Only relocation differences are expected; zero unexplained differences. The snapshot is from an independent loader, not map.image.
    ImageDiffOptions options = defaultOptions();
    const ImageDiffReport kClean =
        compareImage(kAtOther, liveFromSpec(kRelocSpec, kRelocOtherBase, kEntries), options);
    s.expect(kClean.entries.empty() && kClean.unexplainedEntries == 0U,
             L"I-03 a relocation-only base change yields zero unexplained differences against an independently loaded image");
    s.expect(kClean.conclusion == AnalysisConclusion::kNoDifferenceObserved,
             L"I-03 a fully covered clean comparison concludes NoDifferenceObserved");

    // Modify another non-relocation byte — must precisely locate that RVA.
    LiveImageBytes tampered = liveFromSpec(kRelocSpec, kRelocOtherBase, kEntries);
    constexpr std::uint32_t kTamperRva = 0x1200U;
    tampered.bytes[kTamperRva] = static_cast<std::uint8_t>(tampered.bytes[kTamperRva] ^ 0xFFU);
    const ImageDiffReport kTamperedReport = compareImage(kAtOther, tampered, options);
    s.expect(kTamperedReport.entries.size() == 1U,
             L"I-03 changing one non-relocated byte in an independently loaded image produces exactly one difference");
    const ImageDiffEntry* hit = entryAt(kTamperedReport, kTamperRva);
    s.expect(hit != nullptr && hit->length == 1U && hit->rva == kTamperRva,
             L"I-03 the difference is located at the tampered RVA with length 1");
    s.expect(hit != nullptr && hit->explanation == DiffExplanation::kUnexplained,
             L"I-03 a real modification stays unexplained without a rule");

    // Unsupported relocation types: this range is marked non-comparable; others are normalized as usual.
    const std::vector<RelocEntrySpec> kMixedEntries = {
        RelocEntrySpec{kRelTypeDir64, kRelocTargetRva},
        RelocEntrySpec{kRelTypeReservedSeven, kUnsupportedTargetRva},
    };
    const PeBuilder kMixedSpec = makeRelocSpec(kMixedEntries);
    const std::vector<std::uint8_t> kMixedFile = buildPe(kMixedSpec);
    const PeImageMap kMixed = buildPeImageMap(kMixedFile, kRelocOtherBase);
    s.expect(kMixed.status == PeParseStatus::kOk,
             L"I-03 an unsupported relocation type does not fail the whole image");
    s.expect(kMixed.relocation.status == RelocationStatus::kAppliedWithUnsupported,
             L"I-03 the relocation report says some types were unsupported");
    s.expect(kMixed.relocation.entriesApplied == 1U && kMixed.relocation.entriesUnsupported == 1U,
             L"I-03 applied and unsupported relocation entries are counted separately");
    s.expect(kMixed.relocation.unsupported.size() == 1U &&
                 kMixed.relocation.unsupported[0].type == 7U,
             L"I-03 the unsupported relocation type number is recorded");
    s.expect(readU64At(kMixed.image, kRelocTargetRva) == kRelocOtherBase + kRelocTargetRva,
             L"I-03 the supported entry is still normalized alongside an unsupported one");
    s.expect(rvaRangesContain(kMixed.notComparableRanges, kUnsupportedTargetRva) &&
                 rvaRangesContain(kMixed.notComparableRanges, kUnsupportedTargetRva + 7U) &&
                 !rvaRangesContain(kMixed.notComparableRanges, kUnsupportedTargetRva + 8U),
             L"I-03 exactly the affected 8 bytes are marked not comparable");
    s.expect(!rvaRangesContain(kMixed.comparableRanges, kUnsupportedTargetRva) &&
                 rvaRangesContain(kMixed.comparableRanges, kUnsupportedTargetRva - 1U),
             L"I-03 the unsupported range drops out of the comparable set, its neighbours stay");
    s.expect(kMixed.relocation.coverage.failed == 1U &&
                 kMixed.relocation.coverage.succeeded == 1U &&
                 kMixed.relocation.coverage.totalKnown == OptionalU64::of(2U),
             L"I-03 relocation coverage records applied and unsupported entry counts");

    const ImageDiffReport kMixedReport =
        compareImage(kMixed, liveFromSpec(kMixedSpec, kRelocOtherBase, kMixedEntries), options);
    s.expect(kMixedReport.excludedBytes == 8U,
             L"I-03 the diff engine excludes the not-comparable relocation window");
    s.expect(kMixedReport.entries.empty(),
             L"I-03 the excluded window produces no entry at all, not an unexplained difference");
    s.expect(kMixedReport.conclusion == AnalysisConclusion::kIndeterminate,
             L"I-03 an excluded window keeps the conclusion Indeterminate, not NoDifferenceObserved");
    // I-09: Pages containing excluded windows must be counted in both attempted and excluded. Counting a page as
    // excluded only when the entire page was never compared would incorrectly report 100% success for that page.
    // Comparable set = header [0, 0x400) + .text [0x1000, 0x2000) + .reloc [0x2000, 0x2200)
    // → touches pages 0, 1, and 2; the excluded 8 bytes at 0x1150 belong to page 1.
    s.expect(kMixedReport.stats.pages.attempted == 3U && kMixedReport.stats.pages.succeeded == 3U &&
                 kMixedReport.stats.pages.failed == 0U && kMixedReport.stats.pages.excluded == 1U,
             L"I-09 a page that contains an excluded window is counted in both attempted and excluded");
}

// I-03: When relocation cannot be applied, the entire image must be marked as incomparable.
// Create a fixture for each of the three states where normalization was never implemented; both sides of the comparison have had their base addresses changed.
void testRelocationCannotNormalize(ksword_tests::Suite& s) {
    const std::vector<RelocEntrySpec> kEntries = {RelocEntrySpec{kRelTypeDir64, kRelocTargetRva}};
    const ImageDiffOptions kOptions = defaultOptions();

    // Total byte count of the comparable set (manual calculation): header 0x400 + .text 0x1000 + .reloc 0x200 = 0x1600.
    constexpr std::uint64_t kRawBackedTotal = 0x400U + 0x1000U + 0x200U;

    struct Case final {
        PeBuilder spec;
        RelocationStatus expected;
        const wchar_t* label;
    };
    std::vector<Case> cases;

    // (1) RELOCS_STRIPPED: declares no relocation table but requests a base address change.
    {
        PeBuilder stripped = makeRelocSpec(kEntries);
        stripped.fileCharacteristics =
            static_cast<std::uint16_t>(stripped.fileCharacteristics | 0x0001U);
        cases.push_back(Case{stripped, RelocationStatus::kStripped,
                             L"I-03 RELOCS_STRIPPED with a base change"});
    }
    // (2) DirectoryMissing: Both directory RVA and size are 0.
    {
        PeBuilder none = makeRelocSpec(kEntries);
        none.relocDirectoryRva = 0U;
        none.relocDirectorySize = 0U;
        cases.push_back(Case{none, RelocationStatus::kDirectoryMissing,
                             L"I-03 a base change with no relocation directory"});
    }
    // (3) DirectoryUnbacked: The directory RVA falls within the zero-filled/gap region of .text, lacking backing file bytes.
    //     .text raw supports up to 0x2000, .reloc supports [0x2000, 0x2200); the
    //     gap from 0x2200 to SizeOfImage 0x3000 has no section declarations.
    {
        PeBuilder unbacked = makeRelocSpec(kEntries);
        unbacked.relocDirectoryRva = 0x2800U;
        unbacked.relocDirectorySize = 0x20U;
        cases.push_back(Case{unbacked, RelocationStatus::kDirectoryUnbacked,
                             L"I-03 a relocation directory with no file bytes behind it"});
    }

    for (const Case& one : cases) {
        const PeImageMap kMap = buildPeImageMap(buildPe(one.spec), kRelocOtherBase);
        s.expect(kMap.status == PeParseStatus::kOk, one.label);
        s.expect(kMap.relocation.status == one.expected, one.label);
        s.expect(kMap.relocation.imageNotNormalized,
                 L"I-03 a relocation failure marks the map as not normalized");
        s.expect(!relocationNormalizationSucceeded(kMap.relocation.status),
                 L"I-03 the four failure statuses all report normalization as not done");
        // If the entire image is added to the non-comparable set, 0% normalization cannot result in only 0% marked as non-comparable.
        s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 0U,
                 L"I-03 an image that could not be normalized has no comparable bytes left");
        s.expect(rvaRangesContain(kMap.notComparableRanges, 0U) &&
                     rvaRangesContain(kMap.notComparableRanges, kMap.header.sizeOfImage - 1U),
                 L"I-03 the whole image range is marked not comparable");

        // Direction 1: The site contains bytes actually produced by the loader (relocations are active). The old behavior would
        // report unexplained differences at every relocation point—precisely the batch false positives prohibited by I-01.
        const ImageDiffReport kLive =
            compareImage(kMap, liveFromSpec(one.spec, kRelocOtherBase, kEntries), kOptions);
        s.expect(kLive.entries.empty() && kLive.unexplainedEntries == 0U,
                 L"I-03 an un-normalizable image reports zero differences instead of one per relocation site");
        s.expect(kLive.excludedBytes == kRawBackedTotal,
                 L"I-03 every requested byte of an un-normalizable image is accounted as excluded");
        s.expect(kLive.outcome.status == CollectionStatus::kPartial,
                 L"I-03 an un-normalizable image cannot be collected as Success");
        s.expect(kLive.conclusion == AnalysisConclusion::kIndeterminate,
                 L"I-03 an un-normalizable image concludes Indeterminate");

        // Direction 2: The site happens to be unnormalized bytes. The old behavior confidently reports 'no differences found'.
        LiveImageBytes sameAsReference = LiveImageBytes::fromBytes(0U, kMap.image);
        const ImageDiffReport kQuiet = compareImage(kMap, sameAsReference, kOptions);
        s.expect(kQuiet.conclusion == AnalysisConclusion::kIndeterminate,
                 L"I-03 bytes matching an un-normalized reference still cannot conclude NoDifferenceObserved");
        s.expect(kQuiet.outcome.status == CollectionStatus::kPartial && kQuiet.excludedBytes == kRawBackedTotal,
                 L"I-03 the quiet direction is excluded exactly like the loud one");
    }

    // When relocation is needed but the directory is missing, the restriction key must still appear (legacy assertion, criteria not relaxed).
    const PeBuilder kNoRelocSpec = makeDiffFixture();
    const PeImageMap kMissing = buildPeImageMap(buildPe(kNoRelocSpec), kDiffLoadedBase + 0x10000U);
    s.expect(kMissing.relocation.status == RelocationStatus::kDirectoryMissing,
             L"I-03 a base change without a relocation directory is reported, not ignored");
    const ImageDiffReport kMissingReport =
        compareImage(kMissing, liveFromSpec(kNoRelocSpec, kDiffLoadedBase + 0x10000U), kOptions);
    bool sawRelocLimitation = false;
    bool sawExcludedLimitation = false;
    for (const std::string& key : kMissingReport.limitationKeys) {
        if (key == "integrity.limitation.relocationDirectoryMissing") {
            sawRelocLimitation = true;
        }
        if (key == "integrity.limitation.excludedNotComparable") {
            sawExcludedLimitation = true;
        }
    }
    s.expect(sawRelocLimitation,
             L"I-03 the missing relocation directory surfaces as a limitation key");
    s.expect(sawExcludedLimitation && kMissingReport.excludedBytes == 0x400U + 0x3000U + 0x200U,
             L"I-03 a limitation key alone is not enough: the bytes are excluded too");
}

// I-03 / Q-02: Seven RelocationStatus values and several branches reachable only with malformed input.
void testRelocationEdgeCases(ksword_tests::Suite& s) {
    // (1) Four forms of malformed directories. Unified criteria: stop parsing, set state to DirectoryMalformed, and mark the entire
    //     image as incomparable (since the remaining unprocessed blocks cannot be defined, a partially normalized reference is invalid).
    struct MalformedCase final {
        std::vector<std::uint8_t> blob;
        std::uint32_t dirSize;
        const wchar_t* label;
    };
    std::vector<MalformedCase> malformed;
    {
        // blockSize == 0: The loop does not advance.
        std::vector<std::uint8_t> blob(16U, 0U);
        put32(blob, 0U, 0x1000U);
        put32(blob, 4U, 0U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block with SizeOfBlock 0"});
    }
    {
        // blockSize == 4: Header size less than 8 bytes.
        std::vector<std::uint8_t> blob(16U, 0U);
        put32(blob, 0U, 0x1000U);
        put32(blob, 4U, 4U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block smaller than its own header"});
    }
    {
        // blockSize exceeds the remaining directory length: the block header claims 0x40, but the directory only has 0x10.
        std::vector<std::uint8_t> blob(16U, 0U);
        put32(blob, 0U, 0x1000U);
        put32(blob, 4U, 0x40U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block that overruns the directory"});
    }
    {
        // entryBytes is odd: blockSize 11 = 8 + 3.
        std::vector<std::uint8_t> blob(16U, 0U);
        put32(blob, 0U, 0x1000U);
        put32(blob, 4U, 11U);
        malformed.push_back(MalformedCase{blob, 16U, L"I-03 a relocation block with an odd number of entry bytes"});
    }
    for (const MalformedCase& one : malformed) {
        const PeBuilder kSpec = makeRelocSpecRaw(one.blob, 0x2000U, one.dirSize);
        const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kRelocOtherBase);
        s.expect(kMap.status == PeParseStatus::kOk, one.label);
        s.expect(kMap.relocation.status == RelocationStatus::kDirectoryMalformed, one.label);
        s.expect(kMap.relocation.imageNotNormalized &&
                     rvaRangesTotalBytes(kMap.comparableRanges) == 0U,
                 L"I-03 a malformed relocation directory leaves no comparable bytes behind");
        s.expect(readU64At(kMap.image, kRelocTargetRva) == kRelocPreferredBase + kRelocTargetRva,
                 L"I-03 a malformed directory never half-applies a relocation it could not parse");
    }

    // (2) entriesOutOfRange: DIR64 target exceeds SizeOfImage.
    //     Block RVA 0x2000 + offset 0xFFC = 0x2FFC, +8 = 0x3004 > SizeOfImage 0x3000.
    {
        const std::vector<RelocEntrySpec> kEntries = {RelocEntrySpec{kRelTypeDir64, 0x2FFCU}};
        const std::vector<std::uint8_t> kBlob = buildRelocBlock(0x2000U, kEntries);
        const PeBuilder kSpec =
            makeRelocSpecRaw(kBlob, 0x2000U, static_cast<std::uint32_t>(kBlob.size()));
        const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kRelocOtherBase);
        s.expect(kMap.relocation.entriesOutOfRange == 1U && kMap.relocation.entriesApplied == 0U,
                 L"I-03 a DIR64 target past SizeOfImage is counted out of range and never written");
        s.expect(kMap.relocation.status == RelocationStatus::kAppliedWithUnsupported,
                 L"I-03 an out-of-range entry degrades the status instead of failing the image");
        bool tailAllZero = true;
        for (std::size_t at = 0x2FF0U; at < 0x3000U; ++at) {
            if (kMap.image[at] != 0U) {
                tailAllZero = false;
            }
        }
        s.expect(tailAllZero, L"I-03 an out-of-range relocation writes no bytes at all");
    }

    // (3) HIGHADJ: Parameter bytes must be skipped and **must not** be counted as a relocation entry.
    //     In the same block: HIGHADJ@0x1200 + parameters + DIR64@0x1100.
    {
        std::vector<std::uint8_t> blob(8U + 3U * 2U, 0U);
        put32(blob, 0U, 0x1000U);
        put32(blob, 4U, static_cast<std::uint32_t>(blob.size()));
        put16(blob, 8U, static_cast<std::uint16_t>((kRelTypeHighAdj << 12U) | 0x200U));
        put16(blob, 10U, 0x1234U);   // HIGHADJ parameter, not an entry.
        put16(blob, 12U, static_cast<std::uint16_t>((kRelTypeDir64 << 12U) | 0x100U));
        const PeBuilder kSpec =
            makeRelocSpecRaw(blob, 0x2000U, static_cast<std::uint32_t>(blob.size()));
        const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kRelocOtherBase);

        s.expect(kMap.relocation.entriesTotal == 2U,
                 L"I-03 the HIGHADJ parameter word is not counted as a relocation entry");
        s.expect(kMap.relocation.entriesSkippedParameter == 1U,
                 L"I-03 the skipped HIGHADJ parameter word gets its own counter");
        s.expect(kMap.relocation.entriesApplied == 1U && kMap.relocation.entriesUnsupported == 1U,
                 L"I-03 the DIR64 after a HIGHADJ is still applied and the HIGHADJ stays unsupported");
        s.expect(readU64At(kMap.image, kRelocTargetRva) == kRelocOtherBase + kRelocTargetRva,
                 L"I-03 the parameter word is skipped rather than treated as an entry that shifts the rest");
        s.expect(kMap.relocation.coverage.succeeded + kMap.relocation.coverage.failed ==
                     kMap.relocation.coverage.totalKnown.value,
                 L"I-03 relocation coverage closes: succeeded plus failed equals the known entry total");
        s.expect(kMap.relocation.coverage.totalKnown == OptionalU64::of(2U),
                 L"I-03 totalKnown counts entries, not the words consumed by them");
    }

    // (4) I-02: The relocation target must be fully backed by file bytes.
    //     .text VA 0x1000 / VS 0x1000 / raw 0x400 → raw supports
    //     [0x1000, 0x1400), zero-filled [0x1400, 0x2000).
    {
        PeBuilder spec;
        spec.imageBase = kRelocPreferredBase;
        spec.sizeOfImage = 0x3000U;

        // Block RVA 0x1000, two DIR64s: 0x1500 (entirely within zero padding), 0x13FC (crosses boundary).
        const std::vector<RelocEntrySpec> kEntries = {
            RelocEntrySpec{kRelTypeDir64, 0x1500U},
            RelocEntrySpec{kRelTypeDir64, 0x13FCU},
        };
        const std::vector<std::uint8_t> kBlob = buildRelocBlock(0x1000U, kEntries);

        std::vector<std::uint8_t> textContent = patternBytes(0x400U, 31U);
        // Write 0x40001400 into the 4 on-disk bytes at 0x13FC as the low half of the value, making the cross-boundary result easy to calculate by hand.
        put32(textContent, 0x13FCU - 0x1000U, 0x40001400U);

        SectionSpec text;
        text.name = ".text";
        text.virtualAddress = 0x1000U;
        text.virtualSize = 0x1000U;
        text.pointerToRawData = 0x0400U;
        text.sizeOfRawData = 0x0400U;
        text.characteristics = kCharsCode;
        text.content = textContent;

        SectionSpec reloc;
        reloc.name = ".reloc";
        reloc.virtualAddress = 0x2000U;
        reloc.virtualSize = 0x0200U;
        reloc.pointerToRawData = 0x0800U;
        reloc.sizeOfRawData = 0x0200U;
        reloc.characteristics = kCharsReloc;
        reloc.content = kBlob;
        reloc.content.resize(0x0200U, 0U);

        spec.sections = {text, reloc};
        spec.relocDirectoryRva = 0x2000U;
        spec.relocDirectorySize = static_cast<std::uint32_t>(kBlob.size());

        const PeImageMap kMap = buildPeImageMap(buildPe(spec), kRelocOtherBase);
        s.expect(kMap.relocation.entriesUnbackedTarget == 2U && kMap.relocation.entriesApplied == 0U,
                 L"I-02 relocation targets without full file backing are refused, not applied");

        bool zeroFillUntouched = true;
        for (std::size_t at = 0x1500U; at < 0x1508U; ++at) {
            if (kMap.image[at] != 0U) {
                zeroFillUntouched = false;
            }
        }
        s.expect(zeroFillUntouched,
                 L"I-02 a relocation whose target lies in zero fill leaves those bytes zero, keeping the zero-fill contract");
        s.expect(rvaRangesContain(kMap.zeroFillRanges, 0x1503U) == false,
                 L"I-02 the refused zero-fill target drops out of zeroFillRanges rather than hiding a non-zero byte");
        // Cross-boundary target: disk contains 00 14 00 40; the correct result is without adding a delta.
        s.expect(kMap.image[0x13FCU] == 0x00U && kMap.image[0x13FDU] == 0x14U &&
                     kMap.image[0x13FEU] == 0x00U && kMap.image[0x13FFU] == 0x40U,
                 L"I-02 a relocation straddling the raw/zero-fill boundary never carries a delta into comparable bytes");
        s.expect(!rvaRangesContain(kMap.comparableRanges, 0x13FCU) &&
                     !rvaRangesContain(kMap.comparableRanges, 0x1500U),
                 L"I-02 both refused relocation windows leave the comparable set");
        s.expect(rvaRangesContain(kMap.comparableRanges, 0x13FBU),
                 L"I-02 the byte just before a refused window stays comparable");
    }
}

// ---------------------------------------------------------------------------
// I-05 Difference location and context.
// ---------------------------------------------------------------------------
void testDifferenceLocation(ksword_tests::Suite& s) {
    const PeBuilder kSpec = makeDiffFixture();
    const std::vector<std::uint8_t> kFile = buildPe(kSpec);
    const PeImageMap kMap = buildPeImageMap(kFile, kDiffLoadedBase);
    s.expect(kMap.status == PeParseStatus::kOk, L"I-05 the diff fixture parses");
    s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 0x400U + 0x3000U + 0x200U,
             L"I-05 the comparable set is headers plus .text plus the raw part of .data");

    // The disk content of .text is patternBytes(0x3000, 11), starting at RVA 0x1000. Expect
    // all bytes to be generated by this independent generator, not derived from map.image.
    const std::vector<std::uint8_t> kTextPattern = patternBytes(0x3000U, 11U);
    const std::vector<std::uint8_t> kLoaded = independentLoadedImage(kSpec, {}, kDiffLoadedBase);
    s.expect(kLoaded.size() == 0x6000U && kLoaded[0x1000U] == kTextPattern[0],
             L"I-05 the independently loaded image places .text content at RVA 0x1000");

    ImageDiffOptions options = defaultOptions();
    LiveImageBytes live = liveFromSpec(kSpec, kDiffLoadedBase);

    // Modify one known byte each at the start, middle, end, and across page boundaries.
    constexpr std::uint32_t kAtStart = 0x1000U;
    constexpr std::uint32_t kAcrossPage = 0x1FFEU;   // Covers 0x1FFE..0x2001, crossing the 0x2000 page boundary.
    constexpr std::uint32_t kAtMiddle = 0x2800U;
    constexpr std::uint32_t kAtEnd = 0x41FFU;        // The last byte of the comparable range
    live.bytes[kAtStart] = static_cast<std::uint8_t>(live.bytes[kAtStart] ^ 0xFFU);
    for (std::uint32_t offset = 0U; offset < 4U; ++offset) {
        const std::uint32_t kAt = kAcrossPage + offset;
        live.bytes[kAt] = static_cast<std::uint8_t>(live.bytes[kAt] ^ 0x5AU);
    }
    for (std::uint32_t offset = 0U; offset < 3U; ++offset) {
        const std::uint32_t kAt = kAtMiddle + offset;
        live.bytes[kAt] = static_cast<std::uint8_t>(live.bytes[kAt] ^ 0x33U);
    }
    live.bytes[kAtEnd] = static_cast<std::uint8_t>(live.bytes[kAtEnd] ^ 0x01U);

    const ImageDiffReport kReport = compareImage(kMap, live, options);
    s.expect(kReport.entries.size() == 4U, L"I-05 four separated changes produce four entries");
    s.expect(kReport.differingBytes == 1U + 4U + 3U + 1U,
             L"I-05 the differing byte total is 9");

    const ImageDiffEntry* start = entryAt(kReport, kAtStart);
    const ImageDiffEntry* page = entryAt(kReport, kAcrossPage);
    const ImageDiffEntry* middle = entryAt(kReport, kAtMiddle);
    const ImageDiffEntry* tail = entryAt(kReport, kAtEnd);
    s.expect(start != nullptr && start->length == 1U && start->sectionName == ".text",
             L"I-05 the change at the start of .text is located exactly");
    s.expect(page != nullptr && page->length == 4U,
             L"I-05 a change straddling a page boundary stays one range of length 4");
    s.expect(middle != nullptr && middle->length == 3U,
             L"I-05 the change in the middle keeps its exact length");
    s.expect(tail != nullptr && tail->length == 1U && tail->sectionName == ".data",
             L"I-05 the change at the last comparable byte is attributed to .data");
    s.expect(start != nullptr && start->va == kDiffLoadedBase + kAtStart,
             L"I-05 the VA is the loaded base plus the RVA");
    s.expect(page != nullptr && page->referenceBytes.size() == 4U &&
                 page->liveBytes.size() == 4U,
             L"I-05 both before and after bytes are carried for a readable difference");
    // Reference bytes are compared against the independent generator, not map.image (which is 'comparing the implementation against itself').
    s.expect(page != nullptr && page->referenceBytes[0] == kTextPattern[kAcrossPage - 0x1000U] &&
                 page->liveBytes[0] == static_cast<std::uint8_t>(
                                           kTextPattern[kAcrossPage - 0x1000U] ^ 0x5AU),
             L"I-05 the carried reference byte matches the independent pattern generator, not the implementation output");
    s.expect(start != nullptr && start->evidenceSource == "test.offline.fixture",
             L"I-05 every entry carries its evidence source");
    s.expect(kReport.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"I-05 observed differences conclude DifferenceObserved");
    s.expect(kReport.stats.pages.attempted == 5U && kReport.stats.pages.failed == 0U,
             L"I-05 page accounting covers the five pages touched by the comparable set");

    // Header differences are attributed to "(headers)".
    LiveImageBytes headerLive = liveFromSpec(kSpec, kDiffLoadedBase);
    headerLive.bytes[0x0100U] = static_cast<std::uint8_t>(headerLive.bytes[0x0100U] ^ 0xFFU);
    const ImageDiffReport kHeaderReport = compareImage(kMap, headerLive, options);
    const ImageDiffEntry* headerEntry = entryAt(kHeaderReport, 0x0100U);
    s.expect(headerEntry != nullptr && headerEntry->sectionName == "(headers)",
             L"I-05 a difference inside SizeOfHeaders is attributed to the header region");

    // Unreadable live image bytes: missing marker, not a 00 difference.
    LiveImageBytes unreadable = liveFromSpec(kSpec, kDiffLoadedBase);
    RvaRange hole;
    hole.rva = 0x2A00U;
    hole.length = 0x10U;
    for (std::uint32_t offset = 0U; offset < hole.length; ++offset) {
        unreadable.bytes[hole.rva + offset] = 0U;   // If the implementation pads with 00 for comparison, this will become a discrepancy.
    }
    unreadable.markRange(hole, ByteReadStatus::kUnreadable);
    const ImageDiffReport kHoleReport = compareImage(kMap, unreadable, options);
    s.expect(kHoleReport.byteDifferenceEntries == 0U,
             L"I-05 unreadable bytes never turn into byte differences");
    s.expect(kHoleReport.missingEntries == 1U && kHoleReport.entries.size() == 1U,
             L"I-05 the unreadable window becomes exactly one missing marker");
    const ImageDiffEntry* missing = entryAt(kHoleReport, hole.rva);
    s.expect(missing != nullptr && missing->kind == DiffKind::kMissingLiveBytes &&
                 missing->readStatus == ByteReadStatus::kUnreadable && missing->length == 0x10U,
             L"I-05 the missing marker carries Unreadable and the exact window length");
    s.expect(missing != nullptr && missing->liveBytes.empty() &&
                 missing->referenceBytes.size() == 0x10U,
             L"I-05 a missing marker carries reference bytes but no fabricated live bytes");
    s.expect(kHoleReport.unreadableBytes == 0x10U && kHoleReport.comparedBytes ==
                 0x400U + 0x3000U + 0x200U - 0x10U,
             L"I-05 unreadable bytes are excluded from the compared byte total");
    s.expect(kHoleReport.conclusion == AnalysisConclusion::kIndeterminate,
             L"I-05 a partial read cannot conclude NoDifferenceObserved");
    s.expect(kHoleReport.stats.pages.failed == 1U && kHoleReport.stats.pages.succeeded == 4U,
             L"I-05 the page holding the unreadable window is counted as failed");

    // Uncollected and unreadable are distinct states: anything outside the window is marked as NotCollected.
    LiveImageBytes narrow = LiveImageBytes::fromBytes(
        0x1000U, std::vector<std::uint8_t>(kLoaded.begin() + 0x1000, kLoaded.begin() + 0x4000));
    const ImageDiffReport kNarrowReport = compareImage(kMap, narrow, options);
    s.expect(kNarrowReport.notCollectedBytes == 0x400U + 0x200U &&
                 kNarrowReport.unreadableBytes == 0U,
             L"I-05 bytes outside the live window are NotCollected, not Unreadable");

    // Collapse: Not collapsed by default; when enabled, original sub-ranges remain expandable.
    LiveImageBytes gapped = liveFromSpec(kSpec, kDiffLoadedBase);
    gapped.bytes[0x3000U] = static_cast<std::uint8_t>(gapped.bytes[0x3000U] ^ 0xFFU);
    gapped.bytes[0x3004U] = static_cast<std::uint8_t>(gapped.bytes[0x3004U] ^ 0xFFU);
    const ImageDiffReport kUnfolded = compareImage(kMap, gapped, options);
    s.expect(kUnfolded.entries.size() == 2U,
             L"I-05 with no collapse budget two nearby changes stay two entries");

    ImageDiffOptions collapsing = options;
    collapsing.collapseGapBytes = 8U;
    const ImageDiffReport kFolded = compareImage(kMap, gapped, collapsing);
    s.expect(kFolded.entries.size() == 1U && kFolded.entries[0].rva == 0x3000U &&
                 kFolded.entries[0].length == 5U && kFolded.entries[0].collapsed,
             L"I-05 nearby changes collapse into one range of length 5");
    s.expect(kFolded.entries[0].subRanges.size() == 2U &&
                 kFolded.entries[0].subRanges[0].rva == 0x3000U &&
                 kFolded.entries[0].subRanges[0].length == 1U &&
                 kFolded.entries[0].subRanges[1].rva == 0x3004U &&
                 kFolded.entries[0].subRanges[1].length == 1U,
             L"I-05 the collapsed entry still exposes the original sub-ranges");
}

// I-05 requires each difference to include the module instance with a small amount of disassembly before and after. Since this layer has no decoder, the criterion is:
// Note: Fields must exist, and the states of 'not attempted' versus 'attempted but failed to resolve' must be distinguishable.
void testDifferenceContextFields(ksword_tests::Suite& s) {
    const PeBuilder kSpec = makeDiffFixture();
    const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kDiffLoadedBase);
    const std::vector<std::uint8_t> kTextPattern = patternBytes(0x3000U, 11U);

    constexpr std::uint32_t kChangedRva = 0x1400U;
    LiveImageBytes live = liveFromSpec(kSpec, kDiffLoadedBase);
    live.bytes[kChangedRva] = static_cast<std::uint8_t>(live.bytes[kChangedRva] ^ 0x6DU);

    DriverInstanceId module;
    module.bootId = "boot-I";
    module.imagePath = "\\SystemRoot\\System32\\drivers\\fixture.sys";
    module.imageBase = OptionalU64::of(kDiffLoadedBase);
    module.imageSize = OptionalU64::of(0x6000U);
    module.timeDateStamp = OptionalU64::of(0x60112233U);
    module.pdbSignature = "1111AAAA-2222-3333-4444-555566667777-1";

    ImageDiffOptions options = defaultOptions();
    options.module = module;

    const ImageDiffReport kWithoutDisassembly = compareImage(kMap, live, options);
    s.expect(kWithoutDisassembly.entries.size() == 1U,
             L"I-05 the context fixture produces exactly one difference");
    const ImageDiffEntry* plain = entryAt(kWithoutDisassembly, kChangedRva);
    s.expect(plain != nullptr && plain->module.crossSessionKey() == module.crossSessionKey() &&
                 !plain->module.crossSessionKey().empty(),
             L"I-05 every difference carries the module instance it belongs to");
    s.expect(plain != nullptr && plain->disassembly.notAttempted() &&
                 !plain->disassembly.decoded &&
                 plain->disassembly.unavailableReasonKey.empty(),
             L"I-05 with no disassembly requested the context reads as not attempted");

    ImageDiffOptions decoding = options;
    decoding.attemptDisassembly = true;
    const ImageDiffReport kWithDisassembly = compareImage(kMap, live, decoding);
    const ImageDiffEntry* decoded = entryAt(kWithDisassembly, kChangedRva);
    s.expect(decoded != nullptr && decoded->disassembly.attemptedButUndecoded(),
             L"I-05 requesting disassembly in a decoder-free layer yields attempted-but-undecoded, not silence");
    s.expect(decoded != nullptr &&
                 decoded->disassembly.unavailableReasonKey ==
                     "integrity.disassembly.noDecoderInThisLayer",
             L"I-05 a missing disassembly is an explicit reason key, never an empty string");
    s.expect(decoded != nullptr && !decoded->disassembly.notAttempted() &&
                 plain != nullptr && plain->disassembly.notAttempted(),
             L"I-05 not-attempted and attempted-but-undecoded are distinguishable states");

    // Failure to disassemble must not affect the original byte evidence.
    s.expect(decoded != nullptr && decoded->referenceBytes.size() == 1U &&
                 decoded->referenceBytes[0] == kTextPattern[kChangedRva - 0x1000U] &&
                 decoded->liveBytes.size() == 1U &&
                 decoded->liveBytes[0] ==
                     static_cast<std::uint8_t>(kTextPattern[kChangedRva - 0x1000U] ^ 0x6DU),
             L"I-05 a failed disassembly leaves the raw before/after byte evidence intact");
    s.expect(plain != nullptr && decoded != nullptr &&
                 plain->referenceBytes == decoded->referenceBytes &&
                 plain->liveBytes == decoded->liveBytes && plain->rva == decoded->rva &&
                 plain->length == decoded->length,
             L"I-05 asking for disassembly changes nothing about the located difference itself");
}

// ---------------------------------------------------------------------------
// I-04: Hot patching and unknown legitimate changes
// ---------------------------------------------------------------------------
void testExplanationRules(ksword_tests::Suite& s) {
    const PeBuilder kSpec = makeDiffFixture();
    const std::vector<std::uint8_t> kFile = buildPe(kSpec);
    const PeImageMap kMap = buildPeImageMap(kFile, kDiffLoadedBase);

    constexpr std::uint32_t kDocumentedRva = 0x1300U;
    constexpr std::uint32_t kLookalikeRva = 0x1900U;
    constexpr std::uint32_t kOrdinaryRva = 0x2500U;
    const std::vector<std::uint8_t> kPatch = {0xE9U, 0x11U, 0x22U, 0x33U, 0x44U};

    LiveImageBytes live = liveFromSpec(kSpec, kDiffLoadedBase);
    for (std::size_t offset = 0; offset < kPatch.size(); ++offset) {
        live.bytes[kDocumentedRva + offset] = kPatch[offset];
        live.bytes[kLookalikeRva + offset] = kPatch[offset];   // Bytes are identical, but without basis.
    }
    live.bytes[kOrdinaryRva] = static_cast<std::uint8_t>(live.bytes[kOrdinaryRva] ^ 0x7EU);

    ExplanationRule rule;
    rule.ruleId = "hotpatch.fixture.0001";
    rule.ruleVersion = 3U;
    rule.range.rva = kDocumentedRva;
    rule.range.length = static_cast<std::uint32_t>(kPatch.size());
    rule.evidenceText = "fixture: documented hotpatch range";

    ImageDiffOptions options = defaultOptions();
    options.rules = {rule};

    const ImageDiffReport kReport = compareImage(kMap, live, options);
    s.expect(kReport.entries.size() == 3U, L"I-04 three separate changes produce three entries");
    const ImageDiffEntry* documented = entryAt(kReport, kDocumentedRva);
    const ImageDiffEntry* lookalike = entryAt(kReport, kLookalikeRva);
    const ImageDiffEntry* ordinary = entryAt(kReport, kOrdinaryRva);
    s.expect(documented != nullptr && documented->explanation == DiffExplanation::kExplained,
             L"I-04 a change inside a documented RVA range is Explained");
    s.expect(documented != nullptr && documented->ruleId == "hotpatch.fixture.0001" &&
                 documented->ruleVersion == 3U,
             L"I-04 the explained entry records the rule id and rule version");
    s.expect(lookalike != nullptr && lookalike->explanation == DiffExplanation::kUnexplained &&
                 lookalike->ruleId.empty(),
             L"I-04 the same bytes at an undocumented RVA stay Unexplained");
    s.expect(ordinary != nullptr && ordinary->explanation == DiffExplanation::kUnexplained,
             L"I-04 an ordinary code change stays Unexplained");
    s.expect(kReport.explainedEntries == 1U && kReport.unexplainedEntries == 2U,
             L"I-04 explained and unexplained entries are counted separately");
    s.expect(kReport.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"I-04 an explained difference is still an observed difference");

    // When a rule covers only part of the range, the remaining bytes must remain unexplained.
    ImageDiffOptions partialRule = defaultOptions();
    ExplanationRule narrow = rule;
    narrow.range.length = 2U;
    partialRule.rules = {narrow};
    const ImageDiffReport kPartialReport = compareImage(kMap, live, partialRule);
    const ImageDiffEntry* head = entryAt(kPartialReport, kDocumentedRva);
    const ImageDiffEntry* rest = entryAt(kPartialReport, kDocumentedRva + 2U);
    s.expect(head != nullptr && head->length == 2U &&
                 head->explanation == DiffExplanation::kExplained,
             L"I-04 only the covered prefix of a patch is Explained");
    s.expect(rest != nullptr && rest->length == 3U &&
                 rest->explanation == DiffExplanation::kUnexplained,
             L"I-04 the uncovered remainder of the same patch stays Unexplained");

    // Rules for empty ranges are unavailable: there is no 'whole-module exemption' path.
    ImageDiffOptions emptyRule = defaultOptions();
    ExplanationRule emptyRange;
    emptyRange.ruleId = "vendor.signed.microsoft";
    emptyRange.ruleVersion = 1U;
    emptyRange.range.rva = 0U;
    emptyRange.range.length = 0U;
    emptyRule.rules = {emptyRange};
    const ImageDiffReport kEmptyReport = compareImage(kMap, live, emptyRule);
    s.expect(kEmptyReport.explainedEntries == 0U && kEmptyReport.unexplainedEntries == 3U,
             L"I-04 a rule without a concrete RVA range explains nothing");

    // Whole-image rule: a single 'signature valid' claim attempting to explain all differences within a module
    // must be blocked; otherwise, the I-04 requirement 'no permanent pass for entire drivers' becomes meaningless.
    ImageDiffOptions wholeImageRule = defaultOptions();
    ExplanationRule wholeModule;
    wholeModule.ruleId = "vendor.microsoft.signed";
    wholeModule.ruleVersion = 1U;
    wholeModule.range.rva = 0U;
    wholeModule.range.length = 0xFFFFFFFFU;
    wholeModule.evidenceText = "signature is valid";
    wholeImageRule.rules = {wholeModule};
    const ImageDiffReport kWholeReport = compareImage(kMap, live, wholeImageRule);
    s.expect(kWholeReport.entries.size() == 3U && kWholeReport.explainedEntries == 0U &&
                 kWholeReport.unexplainedEntries == 3U,
             L"I-04 a rule spanning the whole image explains nothing at all");
    s.expect(kWholeReport.rejectedRuleCount == 1U,
             L"I-04 the discarded over-broad rule is counted, not silently ignored");
    bool sawBroadKey = false;
    for (const std::string& key : kWholeReport.limitationKeys) {
        if (key == "integrity.limitation.explanationRuleUnusable" ||
            key == "integrity.limitation.explanationRuleCoversWholeImage") {
            sawBroadKey = true;
        }
    }
    s.expect(sawBroadKey, L"I-04 dropping an over-broad rule surfaces an explicit limitation key");

    // Rules exactly matching SizeOfImage also grant whole-module exemption, just with a different syntax.
    ExplanationRule exactImage = wholeModule;
    exactImage.range.length = 0x6000U;
    s.expect(admitExplanationRule(kMap, exactImage) == RuleAdmission::kCoversWholeImage,
             L"I-04 a rule whose range equals SizeOfImage is refused as a whole-module exemption");

    // Cross-section rules have no verifiable object: spanning from the end of .text to .data.
    ExplanationRule crossSection;
    crossSection.ruleId = "hotpatch.fixture.cross";
    crossSection.ruleVersion = 1U;
    crossSection.range.rva = 0x3FF0U;    // .text is [0x1000, 0x4000)
    crossSection.range.length = 0x0100U; // Crosses 0x4000 to enter .data
    s.expect(admitExplanationRule(kMap, crossSection) == RuleAdmission::kNotScopedToOneSection,
             L"I-04 a rule that spans two sections is not scoped to anything checkable");

    // Hard limit: usable() without image context must not be tricked by an overly wide rule.
    ExplanationRule oversized;
    oversized.ruleId = "hotpatch.fixture.oversized";
    oversized.range.rva = 0x1000U;
    oversized.range.length = kExplanationRuleMaxSpanBytes + 1U;
    s.expect(!oversized.usable(),
             L"I-04 a rule wider than the documented hard cap is structurally unusable");
    s.expect(admitExplanationRule(kMap, oversized) == RuleAdmission::kUnusable,
             L"I-04 the hard cap is enforced before any image-relative check");

    RvaRange span;
    span.rva = kDocumentedRva;
    span.length = 5U;
    s.expect(findExplanationRule(kMap, emptyRule.rules, span) == nullptr,
             L"I-04 an empty-range rule never matches a span");
    s.expect(findExplanationRule(kMap, wholeImageRule.rules, span) == nullptr,
             L"I-04 a whole-image rule never matches a span either");
    s.expect(findExplanationRule(kMap, options.rules, span) != nullptr,
             L"I-04 a rule fully containing the span does match");
    RvaRange wider = span;
    wider.length = 6U;
    s.expect(findExplanationRule(kMap, options.rules, wider) == nullptr,
             L"I-04 partial coverage does not count as a match");
}

// ---------------------------------------------------------------------------
// I-06 Jump target and owner
// ---------------------------------------------------------------------------
std::vector<ModuleRange> makeModules() {
    ModuleRange kernel;
    kernel.name = "ntoskrnl.exe";
    kernel.base = 0xFFFFF80000000000ULL;
    kernel.size = 0x00800000ULL;
    ModuleRange driverA;
    driverA.name = "driverA.sys";
    driverA.base = 0xFFFFF80100000000ULL;
    driverA.size = 0x00010000ULL;
    ModuleRange driverB;
    driverB.name = "driverB.sys";
    driverB.base = 0xFFFFF80200000000ULL;
    driverB.size = 0x00010000ULL;
    return {kernel, driverA, driverB};
}

void testBranchFollowing(ksword_tests::Suite& s) {
    const std::vector<ModuleRange> kModules = makeModules();
    const std::uint64_t kKernelStart = 0xFFFFF80000001000ULL;
    const std::uint64_t kDriverAEntry = 0xFFFFF80100000100ULL;

    const TargetOwner kOwner = resolveTargetOwner(0xFFFFF80200000040ULL, kModules);
    s.expect(kOwner.kind == TargetOwnerKind::kInsideModule && kOwner.moduleName == "driverB.sys" &&
                 kOwner.offset == OptionalU64::of(0x40U),
             L"I-06 an address inside a known module resolves to module plus offset");
    const TargetOwner kStranger = resolveTargetOwner(0x0000000000001234ULL, kModules);
    s.expect(kStranger.kind == TargetOwnerKind::kOutsideKnownModules && kStranger.moduleName.empty(),
             L"I-06 an address outside every known module is reported as such, not as malicious");

    // Direct jump to another normal module -> Resolved; cross-module jumps are merely a factual occurrence.
    const BranchResolver kDirectResolver = [&](std::uint64_t address) {
        BranchStep step;
        step.bytesConsumed = 5U;
        if (address == kKernelStart) {
            step.kind = FollowStepKind::kDirectBranch;
            step.target = kDriverAEntry;
        } else {
            step.kind = FollowStepKind::kResolvedCode;
        }
        return step;
    };
    const FollowResult kDirect = followBranchTarget(kKernelStart, kModules, kDirectResolver);
    s.expect(kDirect.termination == FollowTermination::kResolved,
             L"I-06 a direct branch to known code terminates as Resolved");
    s.expect(kDirect.path.size() == 2U && kDirect.path[1].address == kDriverAEntry &&
                 kDirect.path[1].owner.moduleName == "driverA.sys" &&
                 kDirect.path[1].owner.offset == OptionalU64::of(0x100U),
             L"I-06 the resolved target is attributed to the owning module and offset");
    s.expect(kDirect.crossedModuleBoundary,
             L"I-06 crossing into another normal module is recorded as a fact");
    s.expect(kDirect.depthUsed == 1U, L"I-06 one hop consumes exactly one depth unit");

    // Indirect unresolved.
    const BranchResolver kIndirectResolver = [](std::uint64_t) {
        BranchStep step;
        step.kind = FollowStepKind::kIndirectUnresolved;
        step.bytesConsumed = 6U;
        return step;
    };
    const FollowResult kIndirect = followBranchTarget(kKernelStart, kModules, kIndirectResolver);
    s.expect(kIndirect.termination == FollowTermination::kIndirectUnresolved,
             L"I-06 an indirect branch whose pointer cannot be read ends as IndirectUnresolved");

    // Export forwarding must yield a different result than unresolved indirect targets.
    const BranchResolver kForwarderResolver = [](std::uint64_t) {
        BranchStep step;
        step.kind = FollowStepKind::kExportForwarder;
        step.bytesConsumed = 0U;
        step.forwarderText = "NTOSKRNL.ExAllocatePool2";
        return step;
    };
    const FollowResult kForwarder = followBranchTarget(kKernelStart, kModules, kForwarderResolver);
    s.expect(kForwarder.termination == FollowTermination::kExportForwarder,
             L"I-06 an export forwarder ends as ExportForwarder");
    s.expect(kForwarder.termination != kIndirect.termination,
             L"I-06 forwarder and unresolved indirect target are distinct result values");
    s.expect(!kForwarder.path.empty() &&
                 kForwarder.path.back().forwarderText == "NTOSKRNL.ExAllocatePool2",
             L"I-06 the forwarder text is preserved");

    // Loop detection terminates as expected.
    const std::uint64_t kLoopA = 0xFFFFF80000002000ULL;
    const std::uint64_t kLoopB = 0xFFFFF80000003000ULL;
    const BranchResolver kCycleResolver = [&](std::uint64_t address) {
        BranchStep step;
        step.kind = FollowStepKind::kDirectBranch;
        step.bytesConsumed = 5U;
        step.target = (address == kLoopA) ? kLoopB : kLoopA;
        return step;
    };
    const FollowResult kCycle = followBranchTarget(kLoopA, kModules, kCycleResolver);
    s.expect(kCycle.termination == FollowTermination::kCycleDetected,
             L"I-06 a two-node loop terminates with CycleDetected");
    s.expect(kCycle.path.size() == 3U,
             L"I-06 the cycle path stops at the first repeated address");

    // Target unreadable.
    const BranchResolver kUnreadableResolver = [](std::uint64_t) {
        BranchStep step;
        step.kind = FollowStepKind::kTargetUnreadable;
        return step;
    };
    const FollowResult kUnreadable = followBranchTarget(kKernelStart, kModules, kUnreadableResolver);
    s.expect(kUnreadable.termination == FollowTermination::kTargetUnreadable,
             L"I-06 an unreadable target ends as TargetUnreadable");

    // The starting point is outside known modules.
    const FollowResult kOutside = followBranchTarget(0x1234ULL, kModules, kDirectResolver);
    s.expect(kOutside.termination == FollowTermination::kOutsideKnownModules,
             L"I-06 following stops at the edge of known modules");

    // Depth limit.
    const BranchResolver kChainResolver = [](std::uint64_t address) {
        BranchStep step;
        step.kind = FollowStepKind::kDirectBranch;
        step.bytesConsumed = 5U;
        step.target = address + 0x100U;
        return step;
    };
    FollowOptions shallow;
    shallow.maxDepth = 2U;
    shallow.maxBytes = 1024U;
    const FollowResult kDeep = followBranchTarget(kKernelStart, kModules, kChainResolver, shallow);
    s.expect(kDeep.termination == FollowTermination::kDepthExhausted,
             L"I-06 an unbounded chain stops at the depth limit");
    s.expect(kDeep.depthUsed == 2U && kDeep.path.size() == 3U,
             L"I-06 the depth limit is honoured exactly");

    // The byte budget limit and the depth limit are two independent termination conditions.
    FollowOptions tightBytes;
    tightBytes.maxDepth = 64U;
    tightBytes.maxBytes = 8U;
    const FollowResult kBudget = followBranchTarget(kKernelStart, kModules, kChainResolver, tightBytes);
    s.expect(kBudget.termination == FollowTermination::kByteBudgetExhausted,
             L"I-06 exceeding the byte budget is a separate termination reason");
}

// ---------------------------------------------------------------------------
// I-09: Scan coverage and race condition.
// ---------------------------------------------------------------------------
DriverInstanceId makeDriverId() {
    DriverInstanceId id;
    id.bootId = "boot-I";
    id.imagePath = "\\SystemRoot\\System32\\drivers\\fixture.sys";
    id.imageBase = OptionalU64::of(0xFFFFF80100000000ULL);
    id.imageSize = OptionalU64::of(0x10000U);
    id.timeDateStamp = OptionalU64::of(0x60112233U);
    id.pdbSignature = "1111AAAA-2222-3333-4444-555566667777-1";
    return id;
}

void testScanCoverageAndStaleness(ksword_tests::Suite& s) {
    const DriverInstanceId kBefore = makeDriverId();

    s.expect(checkModuleStillSame(kBefore, kBefore) == ModuleStalenessVerdict::kSame,
             L"I-09 an unchanged module identity is Same");

    DriverInstanceId unloaded;   // Cannot retrieve any identity after reading.
    s.expect(checkModuleStillSame(kBefore, unloaded) == ModuleStalenessVerdict::kStale,
             L"I-09 a module that no longer reports any identity is Stale");

    DriverInstanceId newVersion = kBefore;
    newVersion.pdbSignature = "9999BBBB-2222-3333-4444-555566667777-2";
    newVersion.timeDateStamp = OptionalU64::of(0x60998877U);
    s.expect(checkModuleStillSame(kBefore, newVersion) == ModuleStalenessVerdict::kStale,
             L"I-09 a different image version at the same path is Stale");

    DriverInstanceId rebased = kBefore;
    rebased.imageBase = OptionalU64::of(0xFFFFF80300000000ULL);
    s.expect(checkModuleStillSame(kBefore, rebased) == ModuleStalenessVerdict::kStale,
             L"I-09 a reload at another base within one boot is Stale");

    DriverInstanceId otherBoot = kBefore;
    otherBoot.bootId = "boot-II";
    s.expect(checkModuleStillSame(kBefore, otherBoot) == ModuleStalenessVerdict::kStale,
             L"I-09 identities from different boots are not comparable and count as Stale");

    DriverInstanceId weak;
    weak.bootId = "boot-I";
    weak.imagePath = kBefore.imagePath;
    DriverInstanceId weakAgain = weak;
    s.expect(checkModuleStillSame(weak, weakAgain) == ModuleStalenessVerdict::kUnverifiable,
             L"I-09 a path-only identity cannot be confirmed and is Unverifiable, not Same");

    DriverInstanceId nothing;
    s.expect(checkModuleStillSame(nothing, kBefore) == ModuleStalenessVerdict::kUnverifiable,
             L"I-09 without a usable pre-read identity the verdict is Unverifiable");

    // Expired module: The conclusion cannot be upgraded; the account must be explicitly marked as failed.
    const PeBuilder kSpec = makeDiffFixture();
    const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kDiffLoadedBase);
    ImageDiffOptions options = defaultOptions();
    options.staleness = ModuleStalenessVerdict::kStale;
    LiveImageBytes live = liveFromSpec(kSpec, kDiffLoadedBase);
    live.bytes[0x1500U] = static_cast<std::uint8_t>(live.bytes[0x1500U] ^ 0xFFU);
    const ImageDiffReport kStaleReport = compareImage(kMap, live, options);
    s.expect(kStaleReport.conclusion == AnalysisConclusion::kIndeterminate,
             L"I-09 a stale module never yields a confident conclusion");
    s.expect(kStaleReport.stats.modules.attempted == 1U && kStaleReport.stats.modules.failed == 1U &&
                 kStaleReport.stats.modules.succeeded == 0U,
             L"I-09 module level accounting records the stale module as failed");
    bool sawStaleKey = false;
    for (const std::string& key : kStaleReport.limitationKeys) {
        if (key == "integrity.limitation.moduleStale") {
            sawStaleKey = true;
        }
    }
    s.expect(sawStaleKey, L"I-09 staleness surfaces as an explicit limitation key");
    s.expect(!kStaleReport.entries.empty(),
             L"I-09 a stale scan still keeps the observed facts instead of dropping everything");

    // I-09 + I-01: Unverifiable means "unable to determine," not "confirmed unchanged." It must be capped at Indeterminate, just
    // like Stale; routing it through the normal path collapses "analysis unable to determine" into "correct empty set." Using a
    // clean snapshot of bytes here is precisely the scenario where old behavior most easily yields confident conclusions.
    ImageDiffOptions unverifiable = defaultOptions();
    unverifiable.staleness = ModuleStalenessVerdict::kUnverifiable;
    const ImageDiffReport kUnverifiedReport =
        compareImage(kMap, liveFromSpec(kSpec, kDiffLoadedBase), unverifiable);
    s.expect(kUnverifiedReport.differingBytes == 0U && kUnverifiedReport.entries.empty(),
             L"I-09 the unverifiable fixture really does compare a clean image");
    s.expect(kUnverifiedReport.conclusion == AnalysisConclusion::kIndeterminate,
             L"I-09 an unverifiable module identity can never conclude NoDifferenceObserved");
    s.expect(kUnverifiedReport.outcome.status == CollectionStatus::kPartial,
             L"I-09 an unverifiable module identity degrades the collection outcome to Partial");
    s.expect(kUnverifiedReport.stats.modules.attempted == 1U &&
                 kUnverifiedReport.stats.modules.succeeded == 0U &&
                 kUnverifiedReport.stats.modules.failed == 0U,
             L"I-09 an unverifiable module counts as neither a succeeded nor a failed module");
    bool sawUnverifiableKey = false;
    for (const std::string& key : kUnverifiedReport.limitationKeys) {
        if (key == "integrity.limitation.moduleIdentityUnverifiable") {
            sawUnverifiableKey = true;
        }
    }
    s.expect(sawUnverifiableKey,
             L"I-09 the unverifiable identity still surfaces its own limitation key");

    // Statistics by byte, page, and module granularity.
    ImageDiffOptions clean = defaultOptions();
    LiveImageBytes partial = liveFromSpec(kSpec, kDiffLoadedBase);
    RvaRange hole;
    hole.rva = 0x3000U;
    hole.length = 0x1000U;
    partial.markRange(hole, ByteReadStatus::kUnreadable);
    const ImageDiffReport kPartialReport = compareImage(kMap, partial, clean);
    s.expect(kPartialReport.stats.bytes.attempted == 0x400U + 0x3000U + 0x200U,
             L"I-09 byte accounting counts every byte in the effective compare set");
    s.expect(kPartialReport.stats.bytes.failed == 0x1000U,
             L"I-09 unreadable bytes are counted as failed bytes");
    s.expect(kPartialReport.stats.bytes.succeeded ==
                 kPartialReport.stats.bytes.attempted - 0x1000U,
             L"I-09 succeeded plus failed accounts for the whole attempted byte range");
    s.expect(kPartialReport.stats.pages.attempted == 5U && kPartialReport.stats.pages.failed == 1U &&
                 kPartialReport.stats.pages.succeeded == 4U,
             L"I-09 page accounting is independent of byte accounting");

    ScanCoverageStats total;
    accumulateStats(total, kPartialReport.stats);
    accumulateStats(total, kStaleReport.stats);
    s.expect(total.modules.attempted == 2U && total.modules.failed == 1U &&
                 total.modules.succeeded == 1U,
             L"I-09 per-module statistics accumulate across a multi-module scan");

    // F-06: When the limit is hit, the account must be balanced. The actual scan stop condition is the fragment
    // count limit (maxEntries*4+16), not maxEntries itself; the truncated large segment is neither a failure nor an
    // exclusion and must be accounted for separately, otherwise most of the requested bytes would have no trace.
    ImageDiffOptions capped = defaultOptions();
    capped.maxEntries = 4U;                       // Segment limit = 4 * 4 + 16 = 32 (manual calculation).
    LiveImageBytes noisy = liveFromSpec(kSpec, kDiffLoadedBase);
    for (std::uint32_t at = 0x1000U; at < 0x4000U; at += 2U) {
        noisy.bytes[at] = static_cast<std::uint8_t>(noisy.bytes[at] ^ 0xA5U);
    }
    const ImageDiffReport kCappedReport = compareImage(kMap, noisy, capped);
    constexpr std::uint64_t kRequestedBytes = 0x400U + 0x3000U + 0x200U;
    s.expect(kCappedReport.limitHit && kCappedReport.scanStoppedAtPieceLimit,
             L"F-06 the scan really is stopped by the piece limit, not by maxEntries");
    s.expect(kCappedReport.pieceLimit == 32U && kCappedReport.entryLimit == 4U,
             L"F-06 both the piece limit and the entry limit are exposed with their real values");
    s.expect(kCappedReport.coverage.limit == OptionalU64::of(32U),
             L"F-06 the reported limit is the one that actually bound the scan, in its own unit");
    // Manual calculation: The first 0x400 bytes are fully compared. The .text section is byte-interleaved starting at 0x1000. The
    // 32nd fragment settles at 0x103F, and the 33rd fragment triggers the stop at 0x1040 — totaling 0x400 + 0x41 = 1089 bytes.
    s.expect(kCappedReport.stats.bytes.attempted == 1089U,
             L"F-06 the attempted byte count matches the hand-computed stop point");
    s.expect(kCappedReport.notAttemptedBytes == kRequestedBytes - 1089U,
             L"F-06 the untouched tail of the compare set lands in its own bucket");
    s.expect(kCappedReport.stats.bytes.attempted + kCappedReport.stats.bytes.notAttempted +
                     kCappedReport.stats.bytes.excluded ==
                 kRequestedBytes,
             L"F-06 attempted plus notAttempted plus excluded accounts for every requested byte");
    s.expect(kCappedReport.stats.pages.attempted == 2U && kCappedReport.stats.pages.notAttempted == 3U,
             L"F-06 pages never reached by the truncated scan are counted as not attempted");
    s.expect(kCappedReport.entries.size() == 4U && kCappedReport.coverage.truncated != 0U,
             L"F-06 the entry limit still caps how many entries are reported");
    bool sawNotAttemptedKey = false;
    for (const std::string& key : kCappedReport.limitationKeys) {
        if (key == "integrity.limitation.bytesNotAttempted") {
            sawNotAttemptedKey = true;
        }
    }
    s.expect(sawNotAttemptedKey, L"F-06 the unscanned remainder surfaces its own limitation key");
    s.expect(kCappedReport.conclusion == AnalysisConclusion::kDifferenceObserved,
             L"F-06 a truncated scan still reports the differences it did observe");
}

// ---------------------------------------------------------------------------
// I-10: Credibility of disk reference
// ---------------------------------------------------------------------------
bool sameEntries(const ImageDiffReport& a, const ImageDiffReport& b) {
    if (a.entries.size() != b.entries.size()) {
        return false;
    }
    for (std::size_t index = 0; index < a.entries.size(); ++index) {
        const ImageDiffEntry& left = a.entries[index];
        const ImageDiffEntry& right = b.entries[index];
        if (left.rva != right.rva || left.length != right.length || left.va != right.va ||
            left.kind != right.kind || left.readStatus != right.readStatus ||
            left.explanation != right.explanation || left.sectionName != right.sectionName ||
            left.referenceBytes != right.referenceBytes || left.liveBytes != right.liveBytes) {
            return false;
        }
    }
    return true;
}

void testReferenceTrust(ksword_tests::Suite& s) {
    const PeBuilder kSpec = makeDiffFixture();
    const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kDiffLoadedBase);
    LiveImageBytes live = liveFromSpec(kSpec, kDiffLoadedBase);
    live.bytes[0x1800U] = static_cast<std::uint8_t>(live.bytes[0x1800U] ^ 0xFFU);
    live.bytes[0x1801U] = static_cast<std::uint8_t>(live.bytes[0x1801U] ^ 0xFFU);

    ImageDiffOptions fromDisk = defaultOptions();
    fromDisk.reference.kind = ReferenceSourceKind::kLocalDisk;
    fromDisk.reference.description = "C:/Windows/System32/drivers/fixture.sys";

    ImageDiffOptions fromUser = fromDisk;
    fromUser.reference.kind = ReferenceSourceKind::kUserSelectedImage;
    fromUser.reference.description = "D:/reference/fixture.sys";

    ImageDiffOptions fromSnapshot = fromDisk;
    fromSnapshot.reference.kind = ReferenceSourceKind::kSavedSnapshot;
    fromSnapshot.reference.description = "session://2026-09-04/fixture";

    const ImageDiffReport kDiskReport = compareImage(kMap, live, fromDisk);
    const ImageDiffReport kUserReport = compareImage(kMap, live, fromUser);
    const ImageDiffReport kSnapshotReport = compareImage(kMap, live, fromSnapshot);

    s.expect(kDiskReport.entries.size() == 1U && kDiskReport.entries[0].length == 2U,
             L"I-10 the fixture produces one two-byte difference");
    s.expect(sameEntries(kDiskReport, kUserReport) && sameEntries(kDiskReport, kSnapshotReport),
             L"I-10 the same bytes give identical difference entries under every reference source");
    s.expect(kDiskReport.conclusion == kUserReport.conclusion &&
                 kDiskReport.conclusion == kSnapshotReport.conclusion,
             L"I-10 the difference conclusion does not depend on the reference source");

    s.expect(kDiskReport.trustNotes != kUserReport.trustNotes &&
                 kDiskReport.trustNotes != kSnapshotReport.trustNotes &&
                 kUserReport.trustNotes != kSnapshotReport.trustNotes,
             L"I-10 each reference source gets its own trust notes");

    bool sawTrustRootNote = false;
    for (const std::string& key : kDiskReport.trustNotes) {
        if (key == "integrity.reference.localDisk.notATrustRoot") {
            sawTrustRootNote = true;
        }
    }
    s.expect(sawTrustRootNote,
             L"I-10 the local disk reference states it is not a tamper-proof trust root");

    // Trust notes must not contain conclusion keys like "consistent with disk, therefore secure".
    bool sawVerdictKey = false;
    const std::vector<std::vector<std::string>> kAllNotes = {
        kDiskReport.trustNotes, kUserReport.trustNotes, kSnapshotReport.trustNotes};
    for (const std::vector<std::string>& notes : kAllNotes) {
        for (const std::string& key : notes) {
            if (key.find("safe") != std::string::npos ||
                key.find("clean") != std::string::npos ||
                key.find("trusted") != std::string::npos) {
                sawVerdictKey = true;
            }
        }
    }
    s.expect(!sawVerdictKey,
             L"I-10 trust notes never carry a safety verdict, only comparison basis");

    ReferenceSource unknownIdentity;
    unknownIdentity.kind = ReferenceSourceKind::kLocalDisk;
    const std::vector<std::string> kWeakNotes = buildTrustNotes(unknownIdentity);
    bool sawIdentityNote = false;
    for (const std::string& key : kWeakNotes) {
        if (key == "integrity.reference.identityUnusable") {
            sawIdentityNote = true;
        }
    }
    s.expect(sawIdentityNote,
             L"I-10 a reference without a usable file identity says so explicitly");
}

// ---------------------------------------------------------------------------
// I-03 DVRT: Decode supported symbols correctly and add their sites to the non-comparable ranges.
// ---------------------------------------------------------------------------
void testDynamicRelocationSites(ksword_tests::Suite& s) {
    const PeImageMap kMap = buildCanonicalDvrtMap();
    const DynamicRelocationReport& report = kMap.dynamicRelocation;

    s.expect(kMap.valid(), L"I-02 a PE carrying a DVRT still parses");
    s.expect(report.status == DvrtStatus::kParsed, L"I-03 a well formed DVRT parses fully");
    s.expect(!report.extentUnknown && dvrtExtentFullyBounded(report.status),
             L"I-03 a fully parsed DVRT bounds its own affected extent");

    // Table location: LoadConfig RVA, table RVA, version, and length are all manually calculated and hardcoded.
    s.expect(report.loadConfigRva == OptionalU64::of(kDvrtLoadConfigRva),
             L"I-03 the load config directory RVA is recorded");
    s.expect(report.loadConfigDeclaredSize == OptionalU64::of(kDvrtLoadConfigSize),
             L"I-03 the declared load config size is recorded");
    s.expect(report.loadConfigStructSize == OptionalU64::of(kDvrtLoadConfigSize),
             L"I-03 the load config structure size field is recorded");
    s.expect(report.tableRva == OptionalU64::of(kDvrtTableRva),
             L"I-03 the DVRT table RVA is section VA plus table offset");
    s.expect(report.tableVersion == OptionalU64::of(1U), L"I-03 the DVRT table version is recorded");
    s.expect(report.tableSize == OptionalU64::of(kCanonicalDvrtEntriesBytes),
             L"I-03 the DVRT table size is recorded");

    // Three symbol sections. The third is critical: SWITCHTABLE_BRANCH records are 2 bytes wide;
    // using the 4-byte width from the current KernelCleanImageBaseline will miss one site here.
    s.expect(report.groupsTotal == 3U, L"I-03 all three DVRT symbol groups are walked");
    s.expect(report.groupsDecoded == 3U, L"I-03 all three supported symbols decode to sites");
    s.expect(report.groupsUnknownSymbol == 0U, L"I-03 no unknown symbol in the canonical table");
    s.expect(report.groups.size() == 3U, L"I-03 one accounting record per symbol group");
    if (report.groups.size() == 3U) {
        s.expect(report.groups[0].symbol == kDvrtSymbolImportControlTransfer &&
                     report.groups[0].entryStride == 4U && report.groups[0].sitesDecoded == 2U &&
                     report.groups[0].blocksWalked == 1U && report.groups[0].decoded,
                 L"I-03 IMPORT_CONTROL_TRANSFER records are four bytes wide");
        s.expect(report.groups[1].symbol == kDvrtSymbolIndirControlTransfer &&
                     report.groups[1].entryStride == 2U && report.groups[1].sitesDecoded == 2U &&
                     report.groups[1].decoded,
                 L"I-03 INDIR_CONTROL_TRANSFER records are two bytes wide");
        s.expect(report.groups[2].symbol == kDvrtSymbolSwitchtableBranch &&
                     report.groups[2].entryStride == 2U && report.groups[2].sitesDecoded == 2U &&
                     report.groups[2].decoded,
                 L"I-03 SWITCHTABLE_BRANCH records are two bytes wide, not four");
    }

    // The RVAs of all six sites are manually calculated; each occupies 8 bytes and they are non-adjacent.
    s.expect(report.sitesDecoded == 6U, L"I-03 six dynamic relocation sites are decoded");
    s.expect(report.sitesOutsideImage == 0U, L"I-03 every canonical site lands inside the image");
    s.expect(report.siteRanges.size() == 6U, L"I-03 the six sites stay six separate ranges");
    s.expect(rvaRangesTotalBytes(report.siteRanges) == 6U * kExpectedSiteSpan,
             L"I-03 each decoded site covers exactly the conservative site span");
    const std::uint32_t kExpectedSites[6] = {kCanonicalSiteRva0, kCanonicalSiteRva1,
                                            kCanonicalSiteRva2, kCanonicalSiteRva3,
                                            kCanonicalSiteRva4, kCanonicalSiteRva5};
    bool everySiteMatches = report.siteRanges.size() == 6U;
    for (std::size_t index = 0; index < 6U && everySiteMatches; ++index) {
        everySiteMatches = report.siteRanges[index].rva == kExpectedSites[index] &&
                           report.siteRanges[index].length == kExpectedSiteSpan;
    }
    s.expect(everySiteMatches, L"I-03 decoded site RVAs match the hand computed page offsets");
    s.expect(report.unknownSymbolRanges.empty(),
             L"I-03 no page level fallback range when every symbol is understood");
    s.expect(report.affectedRanges().size() == 6U,
             L"I-03 affectedRanges exports the site set for the difference engine");

    // Site is in a non-comparable range: no bytes modified by the loader exist on disk.
    for (std::size_t index = 0; index < 6U; ++index) {
        s.expect(rvaRangesContain(kMap.notComparableRanges, kExpectedSites[index]),
                 L"I-03 every dynamic relocation site is marked not comparable");
        s.expect(!rvaRangesContain(kMap.comparableRanges, kExpectedSites[index]),
                 L"I-03 a dynamic relocation site never stays in the comparable set");
    }
    // Comparable bytes = header 0x400 + .text 0x1000 + .rdata 0x1000 - 6 * 8 = 9168.
    s.expect(rvaRangesTotalBytes(kMap.rawBackedRanges) == 9216U,
             L"I-02 the raw backed set keeps its pre-exclusion size");
    s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 9168U,
             L"I-03 exactly the site bytes are removed from the comparable set");

    // readNormalizedBytes provides the disk reference window: reads crossing a relocation site must fail rather than return a block filled with 0.
    std::vector<std::uint8_t> bytes;
    s.expect(!readNormalizedBytes(kMap, kCanonicalSiteRva0, 8U, bytes),
             L"I-05 reading exactly a dynamic relocation site is refused");
    s.expect(!readNormalizedBytes(kMap, kCanonicalSiteRva0 - 8U, 16U, bytes),
             L"I-05 a span straddling a dynamic relocation site is refused");
    s.expect(readNormalizedBytes(kMap, kCanonicalSiteRva0 - 8U, 8U, bytes) && bytes.size() == 8U,
             L"I-05 the bytes just before a site remain readable");
    s.expect(readNormalizedBytes(kMap, kCanonicalSiteRva0 + kExpectedSiteSpan, 8U, bytes),
             L"I-05 the bytes just after a site remain readable");

    // Account: All three segments processed; total symbol count is known, so coverage can be verified as complete.
    s.expect(report.coverage.totalKnown == OptionalU64::of(3U),
             L"I-09 the DVRT account knows how many symbol groups exist");
    s.expect(report.coverage.succeeded == 3U && report.coverage.failed == 0U &&
                 report.coverage.skipped == 0U && report.coverage.truncated == 0U,
             L"I-09 the DVRT account counts three decoded groups and nothing else");
    s.expect(report.coverage.fullyCovered(),
             L"I-09 a fully walked DVRT reports positive complete coverage");
}

// I-03: DVRT and .reloc are two separate things — base normalization proceeds as usual, and sites are excluded as normal.
void testDynamicRelocationWithBaseChange(ksword_tests::Suite& s) {
    DvrtFixtureSpec fixture;
    fixture.table = dvrtTable(1U, canonicalDvrtEntries());
    fixture.includeReloc = true;
    const std::uint64_t kLoadedBase = kDvrtPreferredBase + 0x40000000ULL;
    const PeImageMap kMap = buildDvrtMap(fixture, kLoadedBase);

    s.expect(kMap.valid(), L"I-02 a DVRT image with a base change still parses");
    s.expect(kMap.relocation.status == RelocationStatus::kApplied,
             L"I-03 the classic .reloc directory still normalizes under a base change");
    s.expect(kMap.relocation.entriesApplied == 1U,
             L"I-03 exactly the one declared DIR64 entry is applied");
    // Manual calculation: Disk stores preferredBase + 0x1180; after normalization, it must be loadedBase + 0x1180.
    s.expect(readU64At(kMap.image, kDvrtRelocTargetRva) == kLoadedBase + kDvrtRelocTargetRva,
             L"I-03 the relocated pointer holds the target base value");
    s.expect(kMap.dynamicRelocation.status == DvrtStatus::kParsed &&
                 kMap.dynamicRelocation.sitesDecoded == 6U,
             L"I-03 base relocation does not disturb DVRT decoding");
    // Bytes rewritten by .reloc remain comparable (they can be computed from disk); DVRT sites do not.
    s.expect(rvaRangesContain(kMap.comparableRanges, kDvrtRelocTargetRva),
             L"I-03 a normalizable relocation target stays comparable");
    s.expect(!rvaRangesContain(kMap.comparableRanges, kCanonicalSiteRva0),
             L"I-03 a dynamic relocation site is not comparable even when .reloc succeeded");
    s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 9168U,
             L"I-03 only the DVRT sites are excluded, not the relocation targets");
}

// I-03: Site truncated by SizeOfImage or falls outside the image.
void testDynamicRelocationSiteClipping(ksword_tests::Suite& s) {
    const PeBuilder kSpec = makeDvrtClipFixture();
    const PeImageMap kMap = buildPeImageMap(buildPe(kSpec), kDvrtPreferredBase);
    const DynamicRelocationReport& report = kMap.dynamicRelocation;

    s.expect(kMap.valid(), L"I-02 the clipping fixture parses");
    s.expect(report.status == DvrtStatus::kParsed, L"I-03 the clipping fixture DVRT parses fully");
    s.expect(report.sitesDecoded == 1U,
             L"I-03 only the site inside SizeOfImage is decoded");
    s.expect(report.sitesOutsideImage == 1U,
             L"I-03 a site past SizeOfImage is counted, not silently dropped");
    s.expect(report.siteRanges.size() == 1U && report.siteRanges[0].rva == kClipSiteRva &&
                 report.siteRanges[0].length == kClipSiteLength,
             L"I-03 a site near the image end is clipped to SizeOfImage");
}

// I-03: Unknown symbols are marked as incomparable only at page granularity per block; the entire image must never fail.
void testDynamicRelocationUnknownSymbol(ksword_tests::Suite& s) {
    std::vector<std::uint8_t> entries;
    appendDvrtGroup(entries, 3U, dvrtBlock(0x1000U, 4U, {0x00000120U}));
    // Symbol 9 is undefined: the container remains a valid base relocation block, but the record's meaning is unknown.
    appendDvrtGroup(entries, 9U, dvrtBlock(0x1000U, 4U, {0x00000700U, 0x00000710U}));

    DvrtFixtureSpec fixture;
    fixture.table = dvrtTable(1U, entries);
    const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
    const DynamicRelocationReport& report = kMap.dynamicRelocation;

    s.expect(kMap.valid(),
             L"I-03 an unknown DVRT symbol does not fail the whole image");
    s.expect(report.status == DvrtStatus::kParsedWithUnknownSymbol,
             L"I-03 an unknown symbol is reported as such, not as a clean parse");
    s.expect(!report.extentUnknown,
             L"I-03 a block container still bounds an unknown symbol to its pages");
    s.expect(report.groupsDecoded == 1U && report.groupsUnknownSymbol == 1U,
             L"I-03 decoded and unknown symbol groups are counted apart");
    s.expect(report.sitesDecoded == 1U,
             L"I-03 an unknown symbol contributes no decoded sites");
    s.expect(report.unknownSymbolRanges.size() == 1U &&
                 report.unknownSymbolRanges[0].rva == 0x1000U &&
                 report.unknownSymbolRanges[0].length == 0x1000U,
             L"I-03 an unknown symbol marks exactly the pages its blocks name");
    // Page-granularity downgrade only consumes the .text page; .rdata remains comparable—this is "downgrade by range".
    s.expect(!rvaRangesContain(kMap.comparableRanges, 0x1700U),
             L"I-03 a byte inside an unknown symbol page is not comparable");
    s.expect(rvaRangesContain(kMap.comparableRanges, kDvrtRdataRva + 0x100U),
             L"I-03 pages outside the unknown symbol stay comparable");
    s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 9216U - 0x1000U,
             L"I-03 exactly one page is removed for the unknown symbol");
    s.expect(report.coverage.skipped == 1U && report.coverage.succeeded == 1U &&
                 report.coverage.failed == 0U,
             L"I-09 an unknown symbol is accounted as skipped, not as success");
    s.expect(!report.coverage.fullyCovered(),
             L"I-09 a skipped symbol group forbids a complete coverage claim");
}

// ---------------------------------------------------------------------------
// I-03 DVRT degradation path: Mark malformed/unknown version/unsupported cases as out-of-range; never silently treat them as 'no DVRT'.
// ---------------------------------------------------------------------------
void testDynamicRelocationDegradation(ksword_tests::Suite& s) {
    // (0) The seven status values must be mutually exclusive: distinct names, with the defining criteria partitioning them into 3 + 4.
    //     Collapsing all statuses into one conflates 'DVRT not present', 'DVRT unparseable', and 'DVRT unreadable'.
    {
        const DvrtStatus kAllStatuses[7] = {
            DvrtStatus::kNotPresent,         DvrtStatus::kParsed,
            DvrtStatus::kParsedWithUnknownSymbol, DvrtStatus::kLoadConfigUnusable,
            DvrtStatus::kTableUnbacked,      DvrtStatus::kUnsupportedVersion,
            DvrtStatus::kMalformed};
        bool namesDistinct = true;
        for (std::size_t left = 0; left < 7U; ++left) {
            for (std::size_t right = left + 1U; right < 7U; ++right) {
                if (std::string(dvrtStatusName(kAllStatuses[left])) ==
                    dvrtStatusName(kAllStatuses[right])) {
                    namesDistinct = false;
                }
            }
        }
        s.expect(namesDistinct, L"I-03 every DVRT status has its own name");
        std::size_t boundedCount = 0;
        for (std::size_t index = 0; index < 7U; ++index) {
            if (dvrtExtentFullyBounded(kAllStatuses[index])) {
                ++boundedCount;
            }
        }
        s.expect(boundedCount == 3U,
                 L"I-03 only not-present, parsed and parsed-with-unknown-symbol bound the extent");
    }

    // (1) The LoadConfig directory is completely absent — this is positive evidence that DVRT is indeed missing.
    {
        const PeImageMap kMap = buildPeImageMap(buildPe(makeLayoutFixture()), 0x140000000ULL);
        const DynamicRelocationReport& report = kMap.dynamicRelocation;
        s.expect(report.status == DvrtStatus::kNotPresent,
                 L"I-03 a PE without a load config directory reports DVRT not present");
        s.expect(!report.extentUnknown && report.siteRanges.empty(),
                 L"I-03 absent DVRT marks nothing not comparable");
        s.expect(report.coverage.totalKnown == OptionalU64::of(0U) &&
                     report.coverage.fullyCovered(),
                 L"I-09 absent DVRT is positive evidence of zero symbol groups");
    }

    // (2) The LoadConfig length declared in the data directory predates the version where DVRT fields appear.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries());
        fixture.loadConfigDirectorySize = 100U;
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kNotPresent,
                 L"I-03 a pre-DVRT load config directory size means DVRT cannot exist");
        s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 9216U,
                 L"I-03 a pre-DVRT load config excludes nothing");
    }

    // (3) The struct's own Size field is too short, despite the data directory declaring a long length.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries());
        fixture.loadConfigStructSize = 200U;
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kNotPresent,
                 L"I-03 the load config Size field also gates the DVRT fields");
        s.expect(kMap.dynamicRelocation.loadConfigStructSize == OptionalU64::of(200U),
                 L"I-03 the structure size that caused the decision is preserved");
    }

    // (4) DVRT table offset is 0 — the structure has the field, but the table is absent.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries());
        fixture.tableOffsetInSection = 0U;
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kNotPresent,
                 L"I-03 a zero DynamicValueRelocTableOffset means no table");
        s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 9216U,
                 L"I-03 a zero table offset excludes nothing");
    }

    // (5) LoadConfig falls in the zero-filled region: reading it yields all zeros, so Size=0 and Offset=0.
    //     Without support validation, one would conclude 'this PE has no DVRT'—mistaking 'never collected' for 'definitely absent'.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries());
        fixture.rdataRawSize = 0x80U;   // LoadConfig requires 230 bytes, but raw is only 0x80.
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = kMap.dynamicRelocation;
        s.expect(report.status == DvrtStatus::kLoadConfigUnusable,
                 L"I-03 an unbacked load config is unusable, never 'no DVRT'");
        s.expect(report.extentUnknown && !dvrtExtentFullyBounded(report.status),
                 L"I-03 an unusable load config leaves the DVRT extent unknown");
        s.expect(kMap.comparableRanges.empty(),
                 L"I-03 an unknown DVRT extent removes every byte from comparison");
        s.expect(!kMap.relocation.imageNotNormalized,
                 L"I-03 a DVRT problem is not reported as a failed base normalization");
    }

    // (6) Host section index out of bounds.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries());
        fixture.tableSectionOneBased = 9U;
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kLoadConfigUnusable,
                 L"I-03 an out of range DynamicValueRelocTableSection is unusable");
        s.expect(kMap.dynamicRelocation.extentUnknown && kMap.comparableRanges.empty(),
                 L"I-03 an unusable host section leaves the extent unknown");
    }

    // (7) Table version is not 1 — 'cannot understand' does not equal 'does not exist'.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(2U, canonicalDvrtEntries());
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = kMap.dynamicRelocation;
        s.expect(kMap.valid(), L"I-03 an unknown DVRT version does not fail the PE parse");
        s.expect(report.status == DvrtStatus::kUnsupportedVersion,
                 L"I-03 an unknown DVRT version is named explicitly");
        s.expect(report.tableVersion == OptionalU64::of(2U),
                 L"I-03 the unrecognised version number is preserved");
        s.expect(report.sitesDecoded == 0U && report.siteRanges.empty(),
                 L"I-03 an unknown version decodes no sites at all");
        s.expect(report.extentUnknown && kMap.comparableRanges.empty(),
                 L"I-03 an unknown version removes every byte from comparison");
    }

    // (8) Version is valid but table is empty: This is positive evidence that "no sites" holds.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, std::vector<std::uint8_t>{});
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = kMap.dynamicRelocation;
        s.expect(report.status == DvrtStatus::kParsed && !report.extentUnknown,
                 L"I-03 an empty but valid DVRT table is a clean parse");
        s.expect(report.coverage.totalKnown == OptionalU64::of(0U) &&
                     report.coverage.fullyCovered(),
                 L"I-09 an empty DVRT table is complete coverage of zero groups");
        s.expect(rvaRangesTotalBytes(kMap.comparableRanges) == 9216U,
                 L"I-03 an empty DVRT table excludes nothing");
    }

    // (9) Table size declaration exceeds the image.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries(), 0x4000U);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.valid(), L"I-03 an oversized DVRT size does not fail the PE parse");
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kMalformed,
                 L"I-03 a DVRT size running past SizeOfImage is malformed");
        s.expect(kMap.dynamicRelocation.extentUnknown && kMap.comparableRanges.empty(),
                 L"I-03 an oversized DVRT size leaves the extent unknown");
    }

    // (10) Block length is invalid (smaller than the block header).
    {
        std::vector<std::uint8_t> entries;
        appendDvrtGroup(entries, 3U, dvrtBlock(0x1000U, 4U, {0x00000120U}, 4U));
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, entries);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.valid(), L"I-03 an invalid DVRT block size does not fail the PE parse");
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kMalformed,
                 L"I-03 a block shorter than its own header is malformed");
        s.expect(kMap.dynamicRelocation.coverage.failed == 1U,
                 L"I-09 the symbol group whose container broke is counted as failed");
        s.expect(kMap.dynamicRelocation.extentUnknown && kMap.comparableRanges.empty(),
                 L"I-03 a broken block container leaves the extent unknown");
    }

    // (11) The block's VirtualAddress is not page-aligned, so it is not a valid block container.
    {
        std::vector<std::uint8_t> entries;
        appendDvrtGroup(entries, 3U, dvrtBlock(0x1004U, 4U, {0x00000120U}));
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, entries);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kMalformed,
                 L"I-03 a block VirtualAddress that is not page aligned is malformed");
        s.expect(kMap.dynamicRelocation.extentUnknown,
                 L"I-03 a misaligned block leaves the extent unknown");
    }

    // (12) BaseRelocSize declared in the symbol section exceeds the remaining bytes in the table.
    {
        std::vector<std::uint8_t> entries;
        appendDvrtGroup(entries, 3U, dvrtBlock(0x1000U, 4U, {0x00000120U}), 0x1000U);
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, entries);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kMalformed,
                 L"I-03 a BaseRelocSize past the table end is malformed");
        s.expect(kMap.dynamicRelocation.groupsTotal == 0U,
                 L"I-03 a symbol group with an impossible payload size is not counted as walked");
        s.expect(kMap.dynamicRelocation.coverage.truncated == 1U,
                 L"I-09 a table that stops early is accounted as truncated");
        s.expect(!kMap.dynamicRelocation.coverage.totalKnown.present,
                 L"I-09 a truncated DVRT walk never claims to know the group total");
    }

    // (13) The payload tail has fewer bytes than a block header, but those bytes are not 0—there might be hidden records.
    {
        std::vector<std::uint8_t> payload = dvrtBlock(0x1000U, 4U, {0x00000120U});
        payload.push_back(0x11U);
        payload.push_back(0x22U);
        payload.push_back(0x33U);
        payload.push_back(0x44U);
        std::vector<std::uint8_t> entries;
        appendDvrtGroup(entries, 3U, payload);
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, entries);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kMalformed,
                 L"I-03 non-zero trailing bytes inside a symbol payload are malformed");
        s.expect(kMap.dynamicRelocation.extentUnknown,
                 L"I-03 unexplained payload bytes leave the extent unknown");
    }

    // (14) The same tail filled with 0 is alignment padding; the container must still parse successfully.
    {
        std::vector<std::uint8_t> payload = dvrtBlock(0x1000U, 4U, {0x00000120U});
        payload.resize(payload.size() + 4U, 0U);
        std::vector<std::uint8_t> entries;
        appendDvrtGroup(entries, 3U, payload);
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, entries);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kParsed,
                 L"I-03 zero padding at the end of a symbol payload is accepted");
        s.expect(kMap.dynamicRelocation.sitesDecoded == 1U,
                 L"I-03 padding does not swallow the decoded site");
    }

    // (15) The table tail has fewer bytes than a single entry header, and those bytes are non-0.
    {
        std::vector<std::uint8_t> entries;
        appendDvrtGroup(entries, 3U, dvrtBlock(0x1000U, 4U, {0x00000120U}));
        entries.push_back(0x55U);
        entries.push_back(0x66U);
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, entries);
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        s.expect(kMap.dynamicRelocation.status == DvrtStatus::kMalformed,
                 L"I-03 non-zero trailing bytes at the table end are malformed");
        s.expect(kMap.dynamicRelocation.coverage.truncated == 1U,
                 L"I-09 unexplained table tail bytes are accounted as truncation");
    }

    // (16) The table body falls in the 0-padded region: all read block headers are forged zeros.
    {
        DvrtFixtureSpec fixture;
        fixture.table = dvrtTable(1U, canonicalDvrtEntries());
        // LoadConfig (first 230 bytes before .rdata) and the header (0x200..0x208) are still supported, but
        // entries span from 0x208 to 0x254 while raw data ends at 0x220 — the latter portion reads zero padding.
        fixture.rdataRawSize = 0x220U;
        const PeImageMap kMap = buildDvrtMap(fixture, kDvrtPreferredBase);
        const DynamicRelocationReport& report = kMap.dynamicRelocation;
        s.expect(report.status == DvrtStatus::kTableUnbacked,
                 L"I-03 a DVRT table without file bytes behind it is unbacked, not empty");
        s.expect(report.extentUnknown && kMap.comparableRanges.empty(),
                 L"I-03 an unbacked DVRT table leaves the extent unknown");
        s.expect(report.sitesDecoded == 0U,
                 L"I-03 an unbacked DVRT table decodes nothing");
    }
}

} // namespace

int runImageIntegrityTests() {
    ksword_tests::Suite suite(L"I image integrity");
    testLayoutMapping(suite);
    testMalformedSections(suite);
    testHeaderBoundaries(suite);
    testWholeImageRejection(suite);
    testRelocationNormalization(suite);
    testRelocationCannotNormalize(suite);
    testRelocationEdgeCases(suite);
    testDynamicRelocationSites(suite);
    testDynamicRelocationWithBaseChange(suite);
    testDynamicRelocationSiteClipping(suite);
    testDynamicRelocationUnknownSymbol(suite);
    testDynamicRelocationDegradation(suite);
    testDifferenceLocation(suite);
    testDifferenceContextFields(suite);
    testExplanationRules(suite);
    testBranchFollowing(suite);
    testScanCoverageAndStaleness(suite);
    testReferenceTrust(suite);
    suite.report();
    return suite.failures();
}

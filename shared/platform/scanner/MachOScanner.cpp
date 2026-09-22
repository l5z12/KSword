#include "ScannerInternal.h"

// ============================================================
// ksword/scanner/macho_scanner.cpp
// Purpose:
// - Parse 32/64-bit thin Mach-O in little- or big-endian form.
// - Parse 32/64-bit fat headers and enumerate every bounded architecture slice.
// - Expose load commands, segments, sections, dylibs, and nlist symbols.
// ============================================================

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint32_t kMagic32 = 0xFEEDFACEU;
        constexpr std::uint32_t kMagic64 = 0xFEEDFACFU;
        constexpr std::uint32_t kFatMagic32 = 0xCAFEBABEU;
        constexpr std::uint32_t kFatMagic64 = 0xCAFEBABFU;

        constexpr std::uint32_t kLoadSegment = 0x1U;
        constexpr std::uint32_t kLoadSymtab = 0x2U;
        constexpr std::uint32_t kLoadDysymtab = 0xBU;
        constexpr std::uint32_t kLoadDylib = 0xCU;
        constexpr std::uint32_t kIdDylib = 0xDU;
        constexpr std::uint32_t kLoadWeakDylib = 0x80000018U;
        constexpr std::uint32_t kLoadSegment64 = 0x19U;
        constexpr std::uint32_t kLoadUuid = 0x1BU;
        constexpr std::uint32_t kLoadCodeSignature = 0x1DU;
        constexpr std::uint32_t kLoadLazyDylib = 0x20U;
        constexpr std::uint32_t kLoadReexportDylib = 0x8000001FU;
        constexpr std::uint32_t kLoadUpwardDylib = 0x80000023U;
        constexpr std::uint32_t kLoadMain = 0x80000028U;

        constexpr std::uint8_t kNStabMask = 0xE0U;
        constexpr std::uint8_t kNExternal = 0x01U;
        constexpr std::uint8_t kNTypeMask = 0x0EU;
        constexpr std::uint8_t kNUndefined = 0x00U;

        struct MachMagic
        {
            bool recognized = false;
            bool universal = false;
            bool is64 = false;
            ByteOrder byteOrder = ByteOrder::kUnknown;
        };

        struct SymtabCommand
        {
            bool present = false;
            std::uint64_t commandOffset = 0;
            std::uint32_t symbolOffset = 0;
            std::uint32_t symbolCount = 0;
            std::uint32_t stringOffset = 0;
            std::uint32_t stringSize = 0;
        };

        MachMagic detectMagic(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() < 4)
            {
                return {};
            }
            const std::array<std::uint8_t, 4> kValue{
                bytes[0], bytes[1], bytes[2], bytes[3]
            };
            if (kValue == std::array<std::uint8_t, 4>{ 0xCE, 0xFA, 0xED, 0xFE })
            {
                return { true, false, false, ByteOrder::kLittleEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xFE, 0xED, 0xFA, 0xCE })
            {
                return { true, false, false, ByteOrder::kBigEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xCF, 0xFA, 0xED, 0xFE })
            {
                return { true, false, true, ByteOrder::kLittleEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xFE, 0xED, 0xFA, 0xCF })
            {
                return { true, false, true, ByteOrder::kBigEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xCA, 0xFE, 0xBA, 0xBE })
            {
                return { true, true, false, ByteOrder::kBigEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xBE, 0xBA, 0xFE, 0xCA })
            {
                return { true, true, false, ByteOrder::kLittleEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xCA, 0xFE, 0xBA, 0xBF })
            {
                return { true, true, true, ByteOrder::kBigEndian };
            }
            if (kValue == std::array<std::uint8_t, 4>{ 0xBF, 0xBA, 0xFE, 0xCA })
            {
                return { true, true, true, ByteOrder::kLittleEndian };
            }
            return {};
        }

        const char* cpuTypeName(const std::uint32_t cpuType)
        {
            switch (cpuType)
            {
            case 7U: return "x86";
            case 0x01000007U: return "x86-64";
            case 12U: return "ARM";
            case 0x0100000CU: return "ARM64";
            case 18U: return "PowerPC";
            case 0x01000012U: return "PowerPC64";
            default: return "Unknown";
            }
        }

        const char* fileTypeName(const std::uint32_t fileType)
        {
            switch (fileType)
            {
            case 1: return "Object";
            case 2: return "Executable";
            case 3: return "Fixed VM library";
            case 4: return "Core";
            case 5: return "Preloaded executable";
            case 6: return "Dynamic library";
            case 7: return "Dynamic linker";
            case 8: return "Bundle";
            case 9: return "Dynamic library stub";
            case 10: return "Debug symbols";
            case 11: return "Kernel extension";
            case 12: return "File set";
            default: return "Unknown";
            }
        }

        const char* loadCommandName(const std::uint32_t command)
        {
            switch (command)
            {
            case kLoadSegment: return "LC_SEGMENT";
            case kLoadSymtab: return "LC_SYMTAB";
            case kLoadDysymtab: return "LC_DYSYMTAB";
            case kLoadDylib: return "LC_LOAD_DYLIB";
            case kIdDylib: return "LC_ID_DYLIB";
            case 0xEU: return "LC_LOAD_DYLINKER";
            case 0xFU: return "LC_ID_DYLINKER";
            case 0x11U: return "LC_ROUTINES";
            case 0x80000012U: return "LC_SUB_UMBRELLA";
            case 0x80000015U: return "LC_LOAD_WEAK_DYLIB_OLD";
            case kLoadWeakDylib: return "LC_LOAD_WEAK_DYLIB";
            case kLoadSegment64: return "LC_SEGMENT_64";
            case kLoadUuid: return "LC_UUID";
            case 0x1CU: return "LC_RPATH";
            case kLoadCodeSignature: return "LC_CODE_SIGNATURE";
            case 0x1EU: return "LC_SEGMENT_SPLIT_INFO";
            case kLoadReexportDylib: return "LC_REEXPORT_DYLIB";
            case kLoadLazyDylib: return "LC_LAZY_LOAD_DYLIB";
            case 0x22U: return "LC_DYLD_INFO";
            case 0x80000022U: return "LC_DYLD_INFO_ONLY";
            case kLoadUpwardDylib: return "LC_LOAD_UPWARD_DYLIB";
            case 0x24U: return "LC_VERSION_MIN_MACOSX";
            case 0x25U: return "LC_VERSION_MIN_IPHONEOS";
            case 0x26U: return "LC_FUNCTION_STARTS";
            case 0x27U: return "LC_DYLD_ENVIRONMENT";
            case kLoadMain: return "LC_MAIN";
            case 0x29U: return "LC_DATA_IN_CODE";
            case 0x2AU: return "LC_SOURCE_VERSION";
            case 0x2BU: return "LC_DYLIB_CODE_SIGN_DRS";
            case 0x2CU: return "LC_ENCRYPTION_INFO_64";
            case 0x2DU: return "LC_LINKER_OPTION";
            case 0x2EU: return "LC_LINKER_OPTIMIZATION_HINT";
            case 0x32U: return "LC_BUILD_VERSION";
            case 0x33U: return "LC_DYLD_EXPORTS_TRIE";
            case 0x34U: return "LC_DYLD_CHAINED_FIXUPS";
            case 0x35U: return "LC_FILESET_ENTRY";
            default: return "LC_UNKNOWN";
            }
        }

        std::string protectionText(const std::uint32_t value)
        {
            std::string text;
            text += (value & 1U) != 0 ? 'R' : '-';
            text += (value & 2U) != 0 ? 'W' : '-';
            text += (value & 4U) != 0 ? 'X' : '-';
            return text;
        }

        const char* nListTypeName(const std::uint8_t type)
        {
            switch (type & kNTypeMask)
            {
            case 0x0: return "UNDF";
            case 0x2: return "ABS";
            case 0x4: return "TEXT";
            case 0x6: return "DATA";
            case 0x8: return "BSS";
            case 0xA: return "INDR";
            case 0xC: return "COMM";
            case 0xE: return "SECT";
            default: return "OTHER";
            }
        }

        std::string sliceFormatName(
            const EndianReader& reader,
            const std::uint64_t offset,
            const std::uint64_t size)
        {
            const std::span<const std::uint8_t> kSlice = reader.slice(offset, size);
            const MachMagic kMagic = detectMagic(kSlice);
            if (!kMagic.recognized)
            {
                return "Unknown";
            }
            if (kMagic.universal)
            {
                return kMagic.is64 ? "Universal64" : "Universal32";
            }
            return kMagic.is64 ? "Mach-O 64" : "Mach-O 32";
        }

        bool parseUniversal(
            const std::span<const std::uint8_t> bytes,
            const MachMagic& magic,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            const EndianReader kReader(bytes, magic.byteOrder);
            std::uint32_t architectureCount = 0;
            if (!kReader.readU32(4, architectureCount))
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "macho.fat_header_truncated",
                    "The universal Mach-O header is truncated.");
                return false;
            }
            if (architectureCount > options.maxContainerEntries)
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "macho.fat_count_excessive",
                    "Universal Mach-O slice count exceeds maxContainerEntries.");
                return false;
            }

            const std::uint64_t kEntrySize = magic.is64 ? 32U : 20U;
            std::uint64_t tableBytes = 0;
            if (!checkedMultiply(architectureCount, kEntrySize, tableBytes) ||
                !kReader.contains(8, tableBytes))
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kError,
                    "macho.fat_table_invalid",
                    "Universal Mach-O architecture table is outside the file.",
                    8);
                return false;
            }

            addField(result.summary, "Format", magic.is64 ? "Universal Mach-O 64" : "Universal Mach-O");
            addField(result.summary, "Byte Order", byteOrderName(magic.byteOrder));
            addField(result.summary, "Slices", decimal(architectureCount));
            addField(result.headers, "Magic", magic.is64 ? hex(kFatMagic64) : hex(kFatMagic32));
            addField(result.headers, "Architecture Count", decimal(architectureCount));

            BinaryTable slices{
                "slices",
                "Universal Slices",
                { "Index", "CPU", "CPU Type", "CPU Subtype", "Offset", "Size",
                  "Alignment Exponent", "Slice Format", "Range Status" },
                {},
                false
            };
            for (std::uint32_t index = 0; index < architectureCount; ++index)
            {
                const std::uint64_t kEntryOffset = 8ULL + index * kEntrySize;
                std::uint32_t cpuType = 0;
                std::uint32_t cpuSubtype = 0;
                std::uint32_t alignment = 0;
                std::uint64_t sliceOffset = 0;
                std::uint64_t sliceSize = 0;
                if (!kReader.readU32(kEntryOffset, cpuType) ||
                    !kReader.readU32(kEntryOffset + 4, cpuSubtype))
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kError,
                        "macho.fat_entry_truncated",
                        "A universal Mach-O architecture entry is truncated.",
                        kEntryOffset);
                    return false;
                }
                if (magic.is64)
                {
                    if (!kReader.readU64(kEntryOffset + 8, sliceOffset) ||
                        !kReader.readU64(kEntryOffset + 16, sliceSize) ||
                        !kReader.readU32(kEntryOffset + 24, alignment))
                    {
                        return false;
                    }
                }
                else
                {
                    std::uint32_t sliceOffset32 = 0;
                    std::uint32_t sliceSize32 = 0;
                    if (!kReader.readU32(kEntryOffset + 8, sliceOffset32) ||
                        !kReader.readU32(kEntryOffset + 12, sliceSize32) ||
                        !kReader.readU32(kEntryOffset + 16, alignment))
                    {
                        return false;
                    }
                    sliceOffset = sliceOffset32;
                    sliceSize = sliceSize32;
                }

                const bool kRangeValid = kReader.contains(sliceOffset, sliceSize);
                if (!kRangeValid)
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kWarning,
                        "macho.slice_range_invalid",
                        "A universal Mach-O slice is outside the file.",
                        sliceOffset);
                }
                appendRow(
                    slices,
                    {
                        decimal(index),
                        cpuTypeName(cpuType),
                        hex(cpuType),
                        hex(cpuSubtype),
                        hex(sliceOffset),
                        hex(sliceSize),
                        decimal(alignment),
                        kRangeValid ? sliceFormatName(kReader, sliceOffset, sliceSize) : "Unavailable",
                        kRangeValid ? "Valid" : "Invalid"
                    },
                    options);
            }
            result.tables.push_back(std::move(slices));
            result.success = true;
            return true;
        }

        bool parseSegment(
            const EndianReader& reader,
            const std::uint64_t commandOffset,
            const std::uint32_t commandSize,
            const bool is64,
            const ScanOptions& options,
            BinaryScanResult& result,
            BinaryTable& segments,
            BinaryTable& sections,
            std::string& detailsOut)
        {
            const std::uint64_t kSegmentHeaderSize = is64 ? 72U : 56U;
            const std::uint64_t kSectionEntrySize = is64 ? 80U : 68U;
            if (commandSize < kSegmentHeaderSize)
            {
                return false;
            }

            const std::string kSegmentName = reader.fixedString(
                commandOffset + 8,
                16,
                options.maxStringBytes);
            std::uint64_t virtualAddress = 0;
            std::uint64_t virtualSize = 0;
            std::uint64_t fileOffset = 0;
            std::uint64_t fileSize = 0;
            std::uint32_t maxProtection = 0;
            std::uint32_t initialProtection = 0;
            std::uint32_t sectionCount = 0;
            std::uint32_t flags = 0;
            if (is64)
            {
                if (!reader.readU64(commandOffset + 24, virtualAddress) ||
                    !reader.readU64(commandOffset + 32, virtualSize) ||
                    !reader.readU64(commandOffset + 40, fileOffset) ||
                    !reader.readU64(commandOffset + 48, fileSize) ||
                    !reader.readU32(commandOffset + 56, maxProtection) ||
                    !reader.readU32(commandOffset + 60, initialProtection) ||
                    !reader.readU32(commandOffset + 64, sectionCount) ||
                    !reader.readU32(commandOffset + 68, flags))
                {
                    return false;
                }
            }
            else
            {
                std::uint32_t virtualAddress32 = 0;
                std::uint32_t virtualSize32 = 0;
                std::uint32_t fileOffset32 = 0;
                std::uint32_t fileSize32 = 0;
                if (!reader.readU32(commandOffset + 24, virtualAddress32) ||
                    !reader.readU32(commandOffset + 28, virtualSize32) ||
                    !reader.readU32(commandOffset + 32, fileOffset32) ||
                    !reader.readU32(commandOffset + 36, fileSize32) ||
                    !reader.readU32(commandOffset + 40, maxProtection) ||
                    !reader.readU32(commandOffset + 44, initialProtection) ||
                    !reader.readU32(commandOffset + 48, sectionCount) ||
                    !reader.readU32(commandOffset + 52, flags))
                {
                    return false;
                }
                virtualAddress = virtualAddress32;
                virtualSize = virtualSize32;
                fileOffset = fileOffset32;
                fileSize = fileSize32;
            }
            if (sectionCount > options.maxContainerEntries)
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kWarning,
                    "macho.section_count_excessive",
                    "A segment section count exceeds maxContainerEntries.",
                    commandOffset);
                return false;
            }
            std::uint64_t sectionBytes = 0;
            if (!checkedMultiply(sectionCount, kSectionEntrySize, sectionBytes) ||
                sectionBytes > commandSize - kSegmentHeaderSize)
            {
                return false;
            }

            appendRow(
                segments,
                {
                    kSegmentName,
                    hex(virtualAddress),
                    hex(virtualSize),
                    hex(fileOffset),
                    hex(fileSize),
                    protectionText(maxProtection),
                    protectionText(initialProtection),
                    decimal(sectionCount),
                    hex(flags)
                },
                options);
            detailsOut = "segment=" + kSegmentName + ", sections=" + decimal(sectionCount);

            for (std::uint32_t index = 0; index < sectionCount; ++index)
            {
                const std::uint64_t kSectionOffset =
                    commandOffset + kSegmentHeaderSize + index * kSectionEntrySize;
                const std::string kSectionName = reader.fixedString(
                    kSectionOffset,
                    16,
                    options.maxStringBytes);
                const std::string kOwningSegment = reader.fixedString(
                    kSectionOffset + 16,
                    16,
                    options.maxStringBytes);
                std::uint64_t address = 0;
                std::uint64_t size = 0;
                std::uint32_t rawOffset = 0;
                std::uint32_t alignment = 0;
                std::uint32_t relocationOffset = 0;
                std::uint32_t relocationCount = 0;
                std::uint32_t sectionFlags = 0;
                if (is64)
                {
                    if (!reader.readU64(kSectionOffset + 32, address) ||
                        !reader.readU64(kSectionOffset + 40, size) ||
                        !reader.readU32(kSectionOffset + 48, rawOffset) ||
                        !reader.readU32(kSectionOffset + 52, alignment) ||
                        !reader.readU32(kSectionOffset + 56, relocationOffset) ||
                        !reader.readU32(kSectionOffset + 60, relocationCount) ||
                        !reader.readU32(kSectionOffset + 64, sectionFlags))
                    {
                        return false;
                    }
                }
                else
                {
                    std::uint32_t address32 = 0;
                    std::uint32_t size32 = 0;
                    if (!reader.readU32(kSectionOffset + 32, address32) ||
                        !reader.readU32(kSectionOffset + 36, size32) ||
                        !reader.readU32(kSectionOffset + 40, rawOffset) ||
                        !reader.readU32(kSectionOffset + 44, alignment) ||
                        !reader.readU32(kSectionOffset + 48, relocationOffset) ||
                        !reader.readU32(kSectionOffset + 52, relocationCount) ||
                        !reader.readU32(kSectionOffset + 56, sectionFlags))
                    {
                        return false;
                    }
                    address = address32;
                    size = size32;
                }
                appendRow(
                    sections,
                    {
                        kOwningSegment,
                        kSectionName,
                        hex(address),
                        hex(size),
                        hex(rawOffset),
                        decimal(alignment),
                        hex(relocationOffset),
                        decimal(relocationCount),
                        hex(sectionFlags)
                    },
                    options);
            }
            return true;
        }

        std::string readDylibName(
            const EndianReader& reader,
            const std::uint64_t commandOffset,
            const std::uint32_t commandSize,
            const ScanOptions& options)
        {
            std::uint32_t nameOffset = 0;
            if (commandSize < 24 ||
                !reader.readU32(commandOffset + 8, nameOffset) ||
                nameOffset >= commandSize)
            {
                return {};
            }
            return reader.cString(
                commandOffset + nameOffset,
                commandOffset + commandSize,
                options.maxStringBytes);
        }

        std::string formatUuid(
            const EndianReader& reader,
            const std::uint64_t commandOffset,
            const std::uint32_t commandSize)
        {
            if (commandSize < 24)
            {
                return {};
            }
            const std::span<const std::uint8_t> kBytes = reader.slice(commandOffset + 8, 16);
            if (kBytes.size() != 16)
            {
                return {};
            }
            std::string value;
            for (std::size_t index = 0; index < kBytes.size(); ++index)
            {
                if (index == 4 || index == 6 || index == 8 || index == 10)
                {
                    value += '-';
                }
                std::ostringstream stream;
                stream << std::uppercase << std::hex << std::setfill('0')
                    << std::setw(2) << static_cast<unsigned int>(kBytes[index]);
                value += stream.str();
            }
            return value;
        }

        void parseSymbols(
            const EndianReader& reader,
            const bool is64,
            const SymtabCommand& symtab,
            const ScanOptions& options,
            BinaryScanResult& result,
            BinaryTable& symbols,
            BinaryTable& imports,
            BinaryTable& exports)
        {
            if (!symtab.present)
            {
                return;
            }
            const std::uint64_t kEntrySize = is64 ? 16U : 12U;
            if (symtab.symbolCount > options.maxContainerEntries)
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kWarning,
                    "macho.symbol_count_limited",
                    "Mach-O symbol count exceeds maxContainerEntries; the table was bounded.",
                    symtab.commandOffset);
            }
            const std::uint64_t kSymbolCount = std::min<std::uint64_t>(
                symtab.symbolCount,
                options.maxContainerEntries);
            std::uint64_t symbolBytes = 0;
            if (!checkedMultiply(kSymbolCount, kEntrySize, symbolBytes) ||
                !reader.contains(symtab.symbolOffset, symbolBytes) ||
                !reader.contains(symtab.stringOffset, symtab.stringSize))
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kWarning,
                    "macho.symbol_range_invalid",
                    "Mach-O symbol or string table is outside the file.",
                    symtab.commandOffset);
                return;
            }
            const std::uint64_t kStringEnd =
                static_cast<std::uint64_t>(symtab.stringOffset) + symtab.stringSize;
            for (std::uint64_t index = 0; index < kSymbolCount; ++index)
            {
                const std::uint64_t kEntryOffset =
                    static_cast<std::uint64_t>(symtab.symbolOffset) + index * kEntrySize;
                std::uint32_t stringIndex = 0;
                std::uint8_t type = 0;
                std::uint8_t section = 0;
                std::uint16_t description = 0;
                std::uint64_t value = 0;
                if (!reader.readU32(kEntryOffset, stringIndex) ||
                    !reader.readU8(kEntryOffset + 4, type) ||
                    !reader.readU8(kEntryOffset + 5, section) ||
                    !reader.readU16(kEntryOffset + 6, description))
                {
                    break;
                }
                if (is64)
                {
                    if (!reader.readU64(kEntryOffset + 8, value))
                    {
                        break;
                    }
                }
                else
                {
                    std::uint32_t value32 = 0;
                    if (!reader.readU32(kEntryOffset + 8, value32))
                    {
                        break;
                    }
                    value = value32;
                }

                std::string name;
                if (stringIndex < symtab.stringSize)
                {
                    name = reader.cString(
                        static_cast<std::uint64_t>(symtab.stringOffset) + stringIndex,
                        kStringEnd,
                        options.maxStringBytes);
                }
                const bool kDebugSymbol = (type & kNStabMask) != 0;
                const bool kExternal = (type & kNExternal) != 0;
                const bool kUndefined = (type & kNTypeMask) == kNUndefined;
                appendRow(
                    symbols,
                    {
                        decimal(index),
                        name,
                        kDebugSymbol ? "STAB" : nListTypeName(type),
                        kExternal ? "Yes" : "No",
                        decimal(section),
                        hex(description),
                        hex(value)
                    },
                    options);

                if (!kDebugSymbol && kExternal && !name.empty())
                {
                    BinaryTable& classification = kUndefined ? imports : exports;
                    appendRow(
                        classification,
                        {
                            name,
                            nListTypeName(type),
                            decimal(section),
                            hex(description),
                            hex(value)
                        },
                        options);
                }
            }
        }

        bool parseThin(
            const std::span<const std::uint8_t> bytes,
            const MachMagic& magic,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            const EndianReader kReader(bytes, magic.byteOrder);
            const std::uint64_t kHeaderSize = magic.is64 ? 32U : 28U;
            if (bytes.size() < kHeaderSize)
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "macho.header_truncated",
                    "The Mach-O header is truncated.");
                return false;
            }

            std::uint32_t cpuType = 0;
            std::uint32_t cpuSubtype = 0;
            std::uint32_t fileType = 0;
            std::uint32_t commandCount = 0;
            std::uint32_t commandsSize = 0;
            std::uint32_t flags = 0;
            std::uint32_t reserved = 0;
            if (!kReader.readU32(4, cpuType) ||
                !kReader.readU32(8, cpuSubtype) ||
                !kReader.readU32(12, fileType) ||
                !kReader.readU32(16, commandCount) ||
                !kReader.readU32(20, commandsSize) ||
                !kReader.readU32(24, flags) ||
                (magic.is64 && !kReader.readU32(28, reserved)))
            {
                return false;
            }
            if (commandCount > options.maxContainerEntries)
            {
                addDiagnostic(
                    result,
                    DiagnosticSeverity::kError,
                    "macho.command_count_excessive",
                    "Mach-O load command count exceeds maxContainerEntries.");
                return false;
            }
            if (!kReader.contains(kHeaderSize, commandsSize))
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kError,
                    "macho.command_region_invalid",
                    "Mach-O load command region is outside the file.",
                    kHeaderSize);
                return false;
            }

            addField(result.summary, "Format", magic.is64 ? "Mach-O 64" : "Mach-O 32");
            addField(result.summary, "Byte Order", byteOrderName(magic.byteOrder));
            addField(result.summary, "Architecture", cpuTypeName(cpuType));
            addField(result.summary, "File Type", fileTypeName(fileType));
            addField(result.summary, "Load Commands", decimal(commandCount));
            addField(result.headers, "Magic", magic.is64 ? hex(kMagic64) : hex(kMagic32));
            addField(result.headers, "CPU Type", std::string(cpuTypeName(cpuType)) + " (" + hex(cpuType) + ")");
            addField(result.headers, "CPU Subtype", hex(cpuSubtype));
            addField(result.headers, "File Type", std::string(fileTypeName(fileType)) + " (" + hex(fileType) + ")");
            addField(result.headers, "Load Command Count", decimal(commandCount));
            addField(result.headers, "Load Commands Size", decimal(commandsSize));
            addField(result.headers, "Flags", hex(flags));
            if (magic.is64)
            {
                addField(result.headers, "Reserved", hex(reserved));
            }

            BinaryTable commands{
                "load_commands",
                "Load Commands",
                { "Index", "Command", "Value", "Offset", "Size", "Details" },
                {},
                false
            };
            BinaryTable segments{
                "segments",
                "Segments",
                { "Name", "VM Address", "VM Size", "File Offset", "File Size",
                  "Max Protection", "Initial Protection", "Section Count", "Flags" },
                {},
                false
            };
            BinaryTable sections{
                "sections",
                "Sections",
                { "Segment", "Name", "Address", "Size", "File Offset", "Alignment",
                  "Relocation Offset", "Relocation Count", "Flags" },
                {},
                false
            };
            BinaryTable dylibs{
                "dynamic_libraries",
                "Dynamic Libraries",
                { "Command", "Path", "Timestamp", "Current Version", "Compatibility Version" },
                {},
                false
            };
            SymtabCommand symtab{};

            const std::uint64_t kCommandEnd = kHeaderSize + commandsSize;
            std::uint64_t commandOffset = kHeaderSize;
            for (std::uint32_t index = 0; index < commandCount; ++index)
            {
                std::uint32_t command = 0;
                std::uint32_t commandSize = 0;
                if (!kReader.readU32(commandOffset, command) ||
                    !kReader.readU32(commandOffset + 4, commandSize) ||
                    commandSize < 8 ||
                    commandSize > kCommandEnd - commandOffset)
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kError,
                        "macho.command_invalid",
                        "A Mach-O load command has an invalid size or range.",
                        commandOffset);
                    return false;
                }

                std::string details;
                if (command == kLoadSegment || command == kLoadSegment64)
                {
                    const bool kCommandIs64 = command == kLoadSegment64;
                    if (kCommandIs64 != magic.is64)
                    {
                        addDiagnosticAt(
                            result,
                            DiagnosticSeverity::kWarning,
                            "macho.segment_class_mismatch",
                            "A segment command class differs from the Mach-O header class.",
                            commandOffset);
                    }
                    if (!parseSegment(
                            kReader,
                            commandOffset,
                            commandSize,
                            kCommandIs64,
                            options,
                            result,
                            segments,
                            sections,
                            details))
                    {
                        addDiagnosticAt(
                            result,
                            DiagnosticSeverity::kError,
                            "macho.segment_invalid",
                            "A Mach-O segment or section table is invalid.",
                            commandOffset);
                        return false;
                    }
                }
                else if (command == kLoadSymtab)
                {
                    if (commandSize < 24 ||
                        !kReader.readU32(commandOffset + 8, symtab.symbolOffset) ||
                        !kReader.readU32(commandOffset + 12, symtab.symbolCount) ||
                        !kReader.readU32(commandOffset + 16, symtab.stringOffset) ||
                        !kReader.readU32(commandOffset + 20, symtab.stringSize))
                    {
                        addDiagnosticAt(
                            result,
                            DiagnosticSeverity::kError,
                            "macho.symtab_command_invalid",
                            "LC_SYMTAB is truncated.",
                            commandOffset);
                        return false;
                    }
                    symtab.present = true;
                    symtab.commandOffset = commandOffset;
                    details = "symbols=" + decimal(symtab.symbolCount);
                }
                else if (command == kLoadDylib ||
                    command == kIdDylib ||
                    command == kLoadWeakDylib ||
                    command == kLoadLazyDylib ||
                    command == kLoadReexportDylib ||
                    command == kLoadUpwardDylib)
                {
                    std::uint32_t timestamp = 0;
                    std::uint32_t currentVersion = 0;
                    std::uint32_t compatibilityVersion = 0;
                    if (commandSize < 24 ||
                        !kReader.readU32(commandOffset + 12, timestamp) ||
                        !kReader.readU32(commandOffset + 16, currentVersion) ||
                        !kReader.readU32(commandOffset + 20, compatibilityVersion))
                    {
                        return false;
                    }
                    const std::string kName =
                        readDylibName(kReader, commandOffset, commandSize, options);
                    details = kName;
                    appendRow(
                        dylibs,
                        {
                            loadCommandName(command),
                            kName,
                            decimal(timestamp),
                            hex(currentVersion),
                            hex(compatibilityVersion)
                        },
                        options);
                }
                else if (command == kLoadMain)
                {
                    std::uint64_t entryOffset = 0;
                    std::uint64_t stackSize = 0;
                    if (commandSize < 24 ||
                        !kReader.readU64(commandOffset + 8, entryOffset) ||
                        !kReader.readU64(commandOffset + 16, stackSize))
                    {
                        return false;
                    }
                    details = "entryoff=" + hex(entryOffset) + ", stack=" + hex(stackSize);
                    addField(result.summary, "Entry File Offset", hex(entryOffset));
                }
                else if (command == kLoadUuid)
                {
                    details = formatUuid(kReader, commandOffset, commandSize);
                    if (!details.empty())
                    {
                        addField(result.summary, "UUID", details);
                    }
                }
                else if (command == kLoadCodeSignature && commandSize >= 16)
                {
                    std::uint32_t dataOffset = 0;
                    std::uint32_t dataSize = 0;
                    if (kReader.readU32(commandOffset + 8, dataOffset) &&
                        kReader.readU32(commandOffset + 12, dataSize))
                    {
                        details = "offset=" + hex(dataOffset) + ", size=" + hex(dataSize);
                    }
                }

                appendRow(
                    commands,
                    {
                        decimal(index),
                        loadCommandName(command),
                        hex(command),
                        hex(commandOffset),
                        decimal(commandSize),
                        details
                    },
                    options);
                commandOffset += commandSize;
            }
            if (commandOffset != kCommandEnd)
            {
                addDiagnosticAt(
                    result,
                    DiagnosticSeverity::kWarning,
                    "macho.command_size_mismatch",
                    "Load commands do not consume the complete sizeofcmds region.",
                    commandOffset);
            }

            BinaryTable symbols{
                "symbols",
                "Symbols",
                { "Index", "Name", "Type", "External", "Section", "Description", "Value" },
                {},
                false
            };
            BinaryTable imports{
                "imports",
                "Imported Symbols",
                { "Name", "Type", "Section", "Description", "Value" },
                {},
                false
            };
            BinaryTable exports{
                "exports",
                "Exported Symbols",
                { "Name", "Type", "Section", "Description", "Value" },
                {},
                false
            };
            parseSymbols(
                kReader,
                magic.is64,
                symtab,
                options,
                result,
                symbols,
                imports,
                exports);

            result.tables.push_back(std::move(commands));
            result.tables.push_back(std::move(segments));
            result.tables.push_back(std::move(sections));
            result.tables.push_back(std::move(dylibs));
            result.tables.push_back(std::move(symbols));
            result.tables.push_back(std::move(imports));
            result.tables.push_back(std::move(exports));
            result.success = true;
            return true;
        }
    }

    bool parseMachO(
        const std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        result.recognized = true;
        const MachMagic kMagic = detectMagic(bytes);
        if (!kMagic.recognized)
        {
            addDiagnostic(
                result,
                DiagnosticSeverity::kError,
                "macho.magic_invalid",
                "Mach-O magic is invalid.");
            return false;
        }

        result.byteOrder = kMagic.byteOrder;
        if (kMagic.universal)
        {
            result.format = BinaryFormat::kMachOUniversal;
            return parseUniversal(bytes, kMagic, options, result);
        }
        result.format = kMagic.is64 ? BinaryFormat::kMachO64 : BinaryFormat::kMachO32;
        return parseThin(bytes, kMagic, options, result);
    }
}

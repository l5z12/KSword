#include "ScannerInternal.h"

// ============================================================
// ksword/scanner/iso9660_scanner.cpp
// Purpose:
// - Parse ISO9660/Joliet volumes and directories from a stable memory snapshot.
// - Does not call system mounting, Shell, or loaders; does not write container members to disk.
// - Pass the member's original range to the attack path detector for read-only association.
// ============================================================

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ks::scanner::detail
{
    namespace
    {
        constexpr std::uint64_t kDescriptorSectorBytes = 2048;
        constexpr std::uint64_t kFirstDescriptorSector = 16;
        constexpr std::size_t kMaximumDescriptors = 64;
        constexpr std::size_t kMaximumDirectoryDepth = 32;

        // VolumeDescriptor: Stores metadata for the selected primary or Joliet supplementary volume.
        struct VolumeDescriptor
        {
            bool valid = false;
            bool joliet = false;
            int jolietLevel = 0;
            std::uint64_t offset = 0;
            std::uint16_t logicalBlockSize = 0;
            std::uint32_t rootExtent = 0;
            std::uint32_t rootSize = 0;
            std::string volumeId;
        };

        // DirectoryTask purpose: replace recursion with an explicit queue to uniformly limit directory depth and cycles.
        struct DirectoryTask
        {
            std::string path;
            std::uint64_t offset = 0;
            std::uint64_t size = 0;
            std::size_t depth = 0;
        };

        bool contains(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            const std::uint64_t length)
        {
            return offset <= bytes.size() && length <= bytes.size() - offset;
        }

        bool readU16Le(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint16_t& valueOut)
        {
            if (!contains(bytes, offset, 2))
            {
                return false;
            }
            valueOut = static_cast<std::uint16_t>(bytes[offset]) |
                static_cast<std::uint16_t>(bytes[offset + 1U] << 8U);
            return true;
        }

        bool readU16Be(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint16_t& valueOut)
        {
            if (!contains(bytes, offset, 2))
            {
                return false;
            }
            valueOut = static_cast<std::uint16_t>(bytes[offset] << 8U) |
                static_cast<std::uint16_t>(bytes[offset + 1U]);
            return true;
        }

        bool readU32Le(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint32_t& valueOut)
        {
            if (!contains(bytes, offset, 4))
            {
                return false;
            }
            valueOut = static_cast<std::uint32_t>(bytes[offset]) |
                (static_cast<std::uint32_t>(bytes[offset + 1U]) << 8U) |
                (static_cast<std::uint32_t>(bytes[offset + 2U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[offset + 3U]) << 24U);
            return true;
        }

        bool readU32Be(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint32_t& valueOut)
        {
            if (!contains(bytes, offset, 4))
            {
                return false;
            }
            valueOut = (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
                (static_cast<std::uint32_t>(bytes[offset + 1U]) << 16U) |
                (static_cast<std::uint32_t>(bytes[offset + 2U]) << 8U) |
                static_cast<std::uint32_t>(bytes[offset + 3U]);
            return true;
        }

        // ISO critical values are stored in both little-endian and big-endian copies; if they mismatch, reject the record immediately.
        bool readBothEndian16(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint16_t& valueOut)
        {
            std::uint16_t little = 0;
            std::uint16_t big = 0;
            if (!readU16Le(bytes, offset, little) ||
                !readU16Be(bytes, offset + 2U, big) ||
                little != big)
            {
                return false;
            }
            valueOut = little;
            return true;
        }

        bool readBothEndian32(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            std::uint32_t& valueOut)
        {
            std::uint32_t little = 0;
            std::uint32_t big = 0;
            if (!readU32Le(bytes, offset, little) ||
                !readU32Be(bytes, offset + 4U, big) ||
                little != big)
            {
                return false;
            }
            valueOut = little;
            return true;
        }

        void appendUtf8(std::string& output, const std::uint32_t codePoint)
        {
            if (codePoint <= 0x7FU)
            {
                output.push_back(static_cast<char>(codePoint));
            }
            else if (codePoint <= 0x7FFU)
            {
                output.push_back(static_cast<char>(0xC0U | (codePoint >> 6U)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
            else
            {
                output.push_back(static_cast<char>(0xE0U | (codePoint >> 12U)));
                output.push_back(static_cast<char>(0x80U | ((codePoint >> 6U) & 0x3FU)));
                output.push_back(static_cast<char>(0x80U | (codePoint & 0x3FU)));
            }
        }

        // decodeUcs2Be accepts only BMP non-surrogate code points; invalid code points are replaced with '?' to preserve directory structure.
        std::string decodeUcs2Be(const std::span<const std::uint8_t> field)
        {
            std::string output;
            for (std::size_t offset = 0; offset + 1U < field.size(); offset += 2U)
            {
                const std::uint16_t kCodePoint =
                    static_cast<std::uint16_t>(field[offset] << 8U) |
                    static_cast<std::uint16_t>(field[offset + 1U]);
                if (kCodePoint == 0)
                {
                    break;
                }
                appendUtf8(
                    output,
                    kCodePoint >= 0xD800U && kCodePoint <= 0xDFFFU
                        ? static_cast<std::uint32_t>('?')
                        : kCodePoint);
            }
            return output;
        }

        std::string decodeAscii(const std::span<const std::uint8_t> field)
        {
            std::string output;
            output.reserve(field.size());
            for (const std::uint8_t kByte : field)
            {
                if (kByte == 0)
                {
                    break;
                }
                output.push_back(
                    kByte >= 0x20U && kByte <= 0x7EU
                        ? static_cast<char>(kByte)
                        : '?');
            }
            return output;
        }

        std::string trimVolumeText(std::string value)
        {
            while (!value.empty() && value.back() == ' ')
            {
                value.pop_back();
            }
            return value;
        }

        // normalizeIdentifier removes the ISO version suffix and replaces path separators to prevent forged hierarchies.
        std::string normalizeIdentifier(std::string value)
        {
            const std::size_t kVersionOffset = value.find(';');
            if (kVersionOffset != std::string::npos)
            {
                value.resize(kVersionOffset);
            }
            if (!value.empty() && value.back() == '.')
            {
                value.pop_back();
            }
            for (char& character : value)
            {
                const unsigned char kByte = static_cast<unsigned char>(character);
                if (character == '/' || character == '\\' || kByte < 0x20U)
                {
                    character = '_';
                }
            }
            return value.empty() ? std::string("<unnamed>") : value;
        }

        bool hasDescriptorSignature(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset)
        {
            static constexpr std::array<std::uint8_t, 5> kSignature{
                'C', 'D', '0', '0', '1'
            };
            return contains(bytes, offset, kDescriptorSectorBytes) &&
                std::equal(
                    kSignature.begin(),
                    kSignature.end(),
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset + 1U)) &&
                bytes[offset + 6U] == 1U;
        }

        int jolietLevel(const std::span<const std::uint8_t> bytes, const std::uint64_t offset)
        {
            if (bytes[offset + 88U] != '%' || bytes[offset + 89U] != '/')
            {
                return 0;
            }
            switch (bytes[offset + 90U])
            {
            case 0x40U: return 1;
            case 0x43U: return 2;
            case 0x45U: return 3;
            default: return 0;
            }
        }

        bool parseDescriptor(
            const std::span<const std::uint8_t> bytes,
            const std::uint64_t offset,
            const bool joliet,
            const int jolietLevel,
            VolumeDescriptor& descriptorOut)
        {
            std::uint16_t blockSize = 0;
            std::uint32_t rootExtent = 0;
            std::uint32_t rootSize = 0;
            if (bytes[offset + 156U] < 34U ||
                !readBothEndian16(bytes, offset + 128U, blockSize) ||
                !readBothEndian32(bytes, offset + 156U + 2U, rootExtent) ||
                !readBothEndian32(bytes, offset + 156U + 10U, rootSize) ||
                blockSize < 512U || blockSize > 32768U ||
                (blockSize & (blockSize - 1U)) != 0)
            {
                return false;
            }

            std::uint64_t rootOffset = 0;
            if (!checkedMultiply(rootExtent, blockSize, rootOffset) ||
                !contains(bytes, rootOffset, rootSize))
            {
                return false;
            }
            const auto kVolumeField = bytes.subspan(
                static_cast<std::size_t>(offset + 40U),
                32U);
            descriptorOut.valid = true;
            descriptorOut.joliet = joliet;
            descriptorOut.jolietLevel = jolietLevel;
            descriptorOut.offset = offset;
            descriptorOut.logicalBlockSize = blockSize;
            descriptorOut.rootExtent = rootExtent;
            descriptorOut.rootSize = rootSize;
            descriptorOut.volumeId = trimVolumeText(
                joliet ? decodeUcs2Be(kVolumeField) : decodeAscii(kVolumeField));
            return true;
        }

        bool alreadyVisited(
            const std::vector<std::pair<std::uint64_t, std::uint64_t>>& visited,
            const std::uint64_t offset,
            const std::uint64_t size)
        {
            return std::find(visited.begin(), visited.end(), std::make_pair(offset, size)) !=
                visited.end();
        }

        std::string joinPath(const std::string& parent, const std::string& name)
        {
            return parent == "/" ? parent + name : parent + "/" + name;
        }
    }

    bool parseIso9660(
        const std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result)
    {
        result.recognized = true;
        result.format = BinaryFormat::kIso9660;
        result.byteOrder = ByteOrder::kBothEndian;

        // Record valid primary volumes first, then prefer the valid Joliet supplementary volume with the highest level.
        VolumeDescriptor primary{};
        VolumeDescriptor selected{};
        for (std::size_t index = 0; index < kMaximumDescriptors; ++index)
        {
            const std::uint64_t kSector = kFirstDescriptorSector + index;
            std::uint64_t descriptorOffset = 0;
            if (!checkedMultiply(kSector, kDescriptorSectorBytes, descriptorOffset) ||
                !contains(bytes, descriptorOffset, kDescriptorSectorBytes))
            {
                break;
            }
            if (!hasDescriptorSignature(bytes, descriptorOffset))
            {
                continue;
            }

            const std::uint8_t kType = bytes[descriptorOffset];
            if (kType == 1U)
            {
                VolumeDescriptor candidate{};
                if (parseDescriptor(bytes, descriptorOffset, false, 0, candidate))
                {
                    primary = candidate;
                }
            }
            else if (kType == 2U)
            {
                const int kLevel = jolietLevel(bytes, descriptorOffset);
                VolumeDescriptor candidate{};
                if (kLevel != 0 &&
                    parseDescriptor(bytes, descriptorOffset, true, kLevel, candidate) &&
                    (!selected.valid || kLevel > selected.jolietLevel))
                {
                    selected = candidate;
                }
            }
            else if (kType == 255U)
            {
                break;
            }
        }

        if (!selected.valid)
        {
            selected = primary;
        }
        if (!selected.valid)
        {
            addDiagnostic(
                result,
                DiagnosticSeverity::kError,
                "iso.volume_descriptor_invalid",
                "ISO9660 volume descriptors or the root directory are invalid.");
            return false;
        }

        addField(result.summary, "Format", selected.joliet ? "ISO9660 + Joliet" : "ISO9660");
        addField(result.summary, "Byte Order", "Both-endian fields");
        addField(result.summary, "Volume ID", selected.volumeId);
        addField(result.summary, "Filename Encoding", selected.joliet ? "Joliet UCS-2BE" : "ISO 646");
        addField(result.summary, "Logical Block Size", decimal(selected.logicalBlockSize));
        addField(result.headers, "Volume Descriptor Offset", hex(selected.offset));
        addField(result.headers, "Root Directory Extent", decimal(selected.rootExtent));
        addField(result.headers, "Root Directory Size", decimal(selected.rootSize));

        BinaryTable entries{
            "container_entries",
            "Container Entries",
            { "Path", "Type", "Offset", "Size", "Extent" },
            {},
            false
        };
        std::vector<ContainerMember> members;
        std::vector<DirectoryTask> pending;
        std::vector<std::pair<std::uint64_t, std::uint64_t>> visited;

        std::uint64_t rootOffset = 0;
        checkedMultiply(selected.rootExtent, selected.logicalBlockSize, rootOffset);
        pending.push_back(DirectoryTask{ "/", rootOffset, selected.rootSize, 0 });
        visited.emplace_back(rootOffset, selected.rootSize);
        members.push_back(ContainerMember{ "/", rootOffset, selected.rootSize, true });
        appendRow(entries, { "/", "Directory", hex(rootOffset), decimal(selected.rootSize), decimal(selected.rootExtent) }, options);

        bool limitReached = false;
        while (!pending.empty() && !limitReached)
        {
            DirectoryTask task = std::move(pending.back());
            pending.pop_back();
            const std::uint64_t kDirectoryEnd = task.offset + task.size;
            std::uint64_t cursor = task.offset;

            while (cursor < kDirectoryEnd)
            {
                if (!contains(bytes, cursor, 1))
                {
                    break;
                }
                const std::uint8_t kRecordLength = bytes[cursor];
                if (kRecordLength == 0)
                {
                    const std::uint64_t kRelative = cursor - task.offset;
                    const std::uint64_t kNextBlock =
                        ((kRelative / selected.logicalBlockSize) + 1U) *
                        selected.logicalBlockSize;
                    cursor = task.offset + kNextBlock;
                    continue;
                }
                if (kRecordLength < 34U ||
                    !contains(bytes, cursor, kRecordLength) ||
                    cursor + kRecordLength > kDirectoryEnd)
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kWarning,
                        "iso.directory_record_invalid",
                        "An ISO9660 directory record is truncated or malformed.",
                        cursor);
                    break;
                }

                const std::uint8_t kIdentifierLength = bytes[cursor + 32U];
                if (33U + kIdentifierLength > kRecordLength)
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kWarning,
                        "iso.identifier_invalid",
                        "An ISO9660 file identifier exceeds its directory record.",
                        cursor);
                    cursor += kRecordLength;
                    continue;
                }
                const auto kIdentifierBytes = bytes.subspan(
                    static_cast<std::size_t>(cursor + 33U),
                    kIdentifierLength);
                const bool kSpecialEntry = kIdentifierLength == 1U &&
                    (kIdentifierBytes[0] == 0U || kIdentifierBytes[0] == 1U);
                if (kSpecialEntry)
                {
                    cursor += kRecordLength;
                    continue;
                }

                std::uint32_t extent = 0;
                std::uint32_t dataSize = 0;
                const std::uint8_t kExtendedAttributeBlocks = bytes[cursor + 1U];
                if (!readBothEndian32(bytes, cursor + 2U, extent) ||
                    !readBothEndian32(bytes, cursor + 10U, dataSize))
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kWarning,
                        "iso.extent_mismatch",
                        "An ISO9660 extent has inconsistent little-endian and big-endian values.",
                        cursor);
                    cursor += kRecordLength;
                    continue;
                }

                std::uint64_t dataBlock = 0;
                std::uint64_t dataOffset = 0;
                if (!checkedAdd(extent, kExtendedAttributeBlocks, dataBlock) ||
                    !checkedMultiply(dataBlock, selected.logicalBlockSize, dataOffset) ||
                    !contains(bytes, dataOffset, dataSize))
                {
                    addDiagnosticAt(
                        result,
                        DiagnosticSeverity::kWarning,
                        "iso.extent_out_of_bounds",
                        "An ISO9660 member extent is outside the image snapshot.",
                        cursor);
                    cursor += kRecordLength;
                    continue;
                }

                const std::string kDecodedName = selected.joliet
                    ? decodeUcs2Be(kIdentifierBytes)
                    : decodeAscii(kIdentifierBytes);
                const std::string kMemberPath = joinPath(
                    task.path,
                    normalizeIdentifier(kDecodedName));
                const std::uint8_t kFlags = bytes[cursor + 25U];
                const bool kDirectory = (kFlags & 0x02U) != 0;
                const bool kMultiExtent = (kFlags & 0x80U) != 0;
                if (members.size() >= options.maxContainerEntries)
                {
                    entries.truncated = true;
                    limitReached = true;
                    break;
                }
                members.push_back(ContainerMember{
                    kMemberPath,
                    dataOffset,
                    dataSize,
                    kDirectory
                });
                appendRow(
                    entries,
                    {
                        kMemberPath,
                        kMultiExtent ? "File (multi-extent)" : (kDirectory ? "Directory" : "File"),
                        hex(dataOffset),
                        decimal(dataSize),
                        decimal(extent)
                    },
                    options);

                if (kDirectory && !kMultiExtent && task.depth < kMaximumDirectoryDepth &&
                    !alreadyVisited(visited, dataOffset, dataSize))
                {
                    visited.emplace_back(dataOffset, dataSize);
                    pending.push_back(DirectoryTask{
                        kMemberPath,
                        dataOffset,
                        dataSize,
                        task.depth + 1U
                    });
                }
                cursor += kRecordLength;
            }
        }

        if (limitReached)
        {
            addDiagnostic(
                result,
                DiagnosticSeverity::kWarning,
                "iso.entry_limit_reached",
                "ISO9660 traversal stopped at ScanOptions.maxContainerEntries.");
        }
        addField(result.summary, "Container Entries", decimal(members.size()));
        result.tables.push_back(std::move(entries));
        detectAttackPathInContainer(bytes, members, options, result);
        addDiagnostic(
            result,
            DiagnosticSeverity::kInformation,
            "iso.read_only_analysis",
            "The image was parsed from a stable byte snapshot without mounting or executing members.");
        result.success = true;
        return true;
    }
}

#pragma once

// ============================================================
// ksword/scanner/scanner_internal.h
// Purpose:
// - Share overflow-safe byte reads and bounded result construction among parsers.
// - Keep parser implementation details out of the public scanner contract.
// ============================================================

#include "BinaryScanner.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <limits>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace ks::scanner::detail
{
    // EndianReader never performs an unaligned typed dereference. Each read first
    // validates the complete byte range and then assembles the requested value.
    class EndianReader
    {
    public:
        EndianReader(std::span<const std::uint8_t> bytes, ByteOrder byteOrder)
            : bytes_(bytes), byteOrder_(byteOrder)
        {
        }

        [[nodiscard]] std::size_t size() const noexcept
        {
            return bytes_.size();
        }

        [[nodiscard]] ByteOrder byteOrder() const noexcept
        {
            return byteOrder_;
        }

        [[nodiscard]] bool contains(std::uint64_t offset, std::uint64_t length) const noexcept
        {
            return offset <= static_cast<std::uint64_t>(bytes_.size()) &&
                length <= static_cast<std::uint64_t>(bytes_.size()) - offset;
        }

        [[nodiscard]] bool readU8(std::uint64_t offset, std::uint8_t& valueOut) const noexcept
        {
            if (!contains(offset, 1))
            {
                return false;
            }
            valueOut = bytes_[static_cast<std::size_t>(offset)];
            return true;
        }

        [[nodiscard]] bool readU16(std::uint64_t offset, std::uint16_t& valueOut) const noexcept
        {
            return readInteger(offset, valueOut);
        }

        [[nodiscard]] bool readU32(std::uint64_t offset, std::uint32_t& valueOut) const noexcept
        {
            return readInteger(offset, valueOut);
        }

        [[nodiscard]] bool readU64(std::uint64_t offset, std::uint64_t& valueOut) const noexcept
        {
            return readInteger(offset, valueOut);
        }

        [[nodiscard]] std::span<const std::uint8_t> slice(
            std::uint64_t offset,
            std::uint64_t length) const noexcept
        {
            if (!contains(offset, length) ||
                length > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
            {
                return {};
            }
            return bytes_.subspan(
                static_cast<std::size_t>(offset),
                static_cast<std::size_t>(length));
        }

        // fixedString reads a fixed-width name and trims at its first NUL byte.
        [[nodiscard]] std::string fixedString(
            std::uint64_t offset,
            std::size_t fieldBytes,
            std::size_t maxStringBytes) const
        {
            const std::size_t kBoundedBytes = std::min(fieldBytes, maxStringBytes);
            if (!contains(offset, kBoundedBytes))
            {
                return {};
            }
            const char* begin = reinterpret_cast<const char*>(
                bytes_.data() + static_cast<std::size_t>(offset));
            std::size_t length = 0;
            while (length < kBoundedBytes && begin[length] != '\0')
            {
                ++length;
            }
            return sanitizeText(std::string(begin, begin + length));
        }

        // cString reads a NUL-terminated string entirely inside a caller-supplied
        // containing range. Missing termination is represented by a bounded prefix.
        [[nodiscard]] std::string cString(
            std::uint64_t offset,
            std::uint64_t containingEnd,
            std::size_t maxStringBytes,
            bool* terminatedOut = nullptr) const
        {
            if (terminatedOut != nullptr)
            {
                *terminatedOut = false;
            }
            if (offset >= containingEnd ||
                containingEnd > static_cast<std::uint64_t>(bytes_.size()))
            {
                return {};
            }

            const std::uint64_t kAvailable = containingEnd - offset;
            const std::size_t kLimit = static_cast<std::size_t>(std::min<std::uint64_t>(
                kAvailable,
                static_cast<std::uint64_t>(maxStringBytes)));
            const char* begin = reinterpret_cast<const char*>(
                bytes_.data() + static_cast<std::size_t>(offset));
            std::size_t length = 0;
            while (length < kLimit && begin[length] != '\0')
            {
                ++length;
            }
            if (terminatedOut != nullptr && length < kLimit && begin[length] == '\0')
            {
                *terminatedOut = true;
            }
            return sanitizeText(std::string(begin, begin + length));
        }

        // sanitizeText prevents control bytes in binary string tables from being
        // interpreted as terminal/UI controls. Tab is preserved for readability.
        static std::string sanitizeText(std::string value)
        {
            for (char& character : value)
            {
                const unsigned char kByte = static_cast<unsigned char>(character);
                if ((kByte < 0x20U && kByte != '\t') || kByte == 0x7FU)
                {
                    character = '.';
                }
            }
            return value;
        }

    private:
        template <typename TUnsigned>
        [[nodiscard]] bool readInteger(std::uint64_t offset, TUnsigned& valueOut) const noexcept
        {
            static_assert(std::is_unsigned_v<TUnsigned>);
            constexpr std::size_t kWidth = sizeof(TUnsigned);
            if (!contains(offset, kWidth) ||
                byteOrder_ == ByteOrder::kUnknown ||
                byteOrder_ == ByteOrder::kBothEndian)
            {
                return false;
            }

            TUnsigned value = 0;
            if (byteOrder_ == ByteOrder::kLittleEndian)
            {
                for (std::size_t index = 0; index < kWidth; ++index)
                {
                    value |= static_cast<TUnsigned>(
                        static_cast<TUnsigned>(bytes_[static_cast<std::size_t>(offset) + index])
                        << (index * 8U));
                }
            }
            else
            {
                for (std::size_t index = 0; index < kWidth; ++index)
                {
                    value = static_cast<TUnsigned>(
                        (value << 8U) |
                        bytes_[static_cast<std::size_t>(offset) + index]);
                }
            }
            valueOut = value;
            return true;
        }

        std::span<const std::uint8_t> bytes_;
        ByteOrder byteOrder_ = ByteOrder::kUnknown;
    };

    // checkedAdd and checkedMultiply are used before every untrusted table offset
    // calculation so crafted counts cannot wrap to a small in-bounds address.
    inline bool checkedAdd(
        std::uint64_t left,
        std::uint64_t right,
        std::uint64_t& valueOut) noexcept
    {
        if (right > std::numeric_limits<std::uint64_t>::max() - left)
        {
            return false;
        }
        valueOut = left + right;
        return true;
    }

    inline bool checkedMultiply(
        std::uint64_t left,
        std::uint64_t right,
        std::uint64_t& valueOut) noexcept
    {
        if (left != 0 && right > std::numeric_limits<std::uint64_t>::max() / left)
        {
            return false;
        }
        valueOut = left * right;
        return true;
    }

    inline std::string hex(std::uint64_t value, std::size_t minimumDigits = 0)
    {
        std::ostringstream stream;
        stream << "0x" << std::uppercase << std::hex;
        if (minimumDigits != 0)
        {
            stream << std::setfill('0') << std::setw(static_cast<int>(minimumDigits));
        }
        stream << value;
        return stream.str();
    }

    inline std::string decimal(std::uint64_t value)
    {
        return std::to_string(value);
    }

    // AddField replaces no existing values; stable ordering is intentional for UI.
    inline void addField(
        std::vector<BinaryField>& fields,
        std::string name,
        std::string value)
    {
        fields.push_back(BinaryField{ std::move(name), std::move(value) });
    }

    inline void addDiagnostic(
        BinaryScanResult& result,
        DiagnosticSeverity severity,
        std::string code,
        std::string message)
    {
        result.diagnostics.push_back(BinaryDiagnostic{
            severity,
            std::move(code),
            std::move(message),
            false,
            0
        });
    }

    inline void addDiagnosticAt(
        BinaryScanResult& result,
        DiagnosticSeverity severity,
        std::string code,
        std::string message,
        std::uint64_t offset)
    {
        result.diagnostics.push_back(BinaryDiagnostic{
            severity,
            std::move(code),
            std::move(message),
            true,
            offset
        });
    }

    // appendRow normalizes row width and applies the per-table row bound.
    inline bool appendRow(
        BinaryTable& table,
        std::vector<std::string> row,
        const ScanOptions& options)
    {
        if (table.rows.size() >= options.maxRowsPerTable)
        {
            table.truncated = true;
            return false;
        }
        row.resize(table.columns.size());
        if (row.size() > table.columns.size())
        {
            row.resize(table.columns.size());
        }
        table.rows.push_back(std::move(row));
        return true;
    }

    inline BinaryTable& addTable(
        BinaryScanResult& result,
        std::string id,
        std::string title,
        std::vector<std::string> columns)
    {
        result.tables.push_back(BinaryTable{
            std::move(id),
            std::move(title),
            std::move(columns),
            {},
            false
        });
        return result.tables.back();
    }

    // Parser entry points are implemented in format-specific translation units.
    bool parseElf(
        std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result);

    bool parseMachO(
        std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result);

    // ContainerMember purpose: Describe the precise read-only range of a member within the parent snapshot.
    struct ContainerMember
    {
        std::string path;
        std::uint64_t offset = 0;
        std::uint64_t size = 0;
        bool directory = false;
    };

    // parseIso9660: Read-only parsing of ISO9660 primary volume and directory records; does not mount the image.
    // Attack path detection is performed on the same stable memory snapshot without extracting or executing container members.
    bool parseIso9660(
        std::span<const std::uint8_t> bytes,
        const ScanOptions& options,
        BinaryScanResult& result);

    // detectAttackPathInPe: Appends behavioral evidence to a single, already-stably-read PE snapshot.
    void detectAttackPathInPe(
        std::span<const std::uint8_t> bytes,
        std::string_view artifact,
        std::uint64_t baseOffset,
        const ScanOptions& options,
        BinaryScanResult& result);

    // detectAttackPathInContainer: Correlates host, same-name dependencies, and embedded payload evidence.
    void detectAttackPathInContainer(
        std::span<const std::uint8_t> bytes,
        const std::vector<ContainerMember>& members,
        const ScanOptions& options,
        BinaryScanResult& result);
}

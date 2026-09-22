#include "NetworkFormatTools.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace ks::network
{
    namespace
    {
        // kHexBytesPerRowDefault is used when callers pass an invalid row width.
        constexpr std::size_t kHexBytesPerRowDefault = 16;

        // isVisibleAsciiByte identifies bytes that can be displayed without escaping.
        // It intentionally limits output to the portable printable ASCII range.
        bool isVisibleAsciiByte(const std::uint8_t byteValue)
        {
            return byteValue >= 32 && byteValue <= 126;
        }

        // normalizeAsciiCharForPreview maps raw bytes to compact preview characters.
        // Whitespace used by text protocols is folded to spaces; binary bytes become dots.
        char normalizeAsciiCharForPreview(const std::uint8_t byteValue)
        {
            if (isVisibleAsciiByte(byteValue))
            {
                return static_cast<char>(byteValue);
            }
            if (byteValue == '\r' || byteValue == '\n' || byteValue == '\t')
            {
                return ' ';
            }
            return '.';
        }

        // trimAscii removes leading and trailing ASCII whitespace from a string.
        // The function is deliberately small and locale-independent for parser stability.
        std::string trimAscii(const std::string& inputText)
        {
            std::size_t beginIndex = 0;
            while (beginIndex < inputText.size() &&
                std::isspace(static_cast<unsigned char>(inputText[beginIndex])) != 0)
            {
                ++beginIndex;
            }

            std::size_t endIndex = inputText.size();
            while (endIndex > beginIndex &&
                std::isspace(static_cast<unsigned char>(inputText[endIndex - 1])) != 0)
            {
                --endIndex;
            }
            return inputText.substr(beginIndex, endIndex - beginIndex);
        }

        // simplifyWhitespace collapses runs of ASCII whitespace to a single space.
        // The result is compact enough for packet preview reuse.
        std::string simplifyWhitespace(const std::string& inputText)
        {
            std::string outputText;
            outputText.reserve(inputText.size());
            bool pendingSpace = false;
            for (const char kCurrentChar : inputText)
            {
                if (std::isspace(static_cast<unsigned char>(kCurrentChar)) != 0)
                {
                    pendingSpace = !outputText.empty();
                    continue;
                }
                if (pendingSpace)
                {
                    outputText.push_back(' ');
                    pendingSpace = false;
                }
                outputText.push_back(kCurrentChar);
            }
            return trimAscii(outputText);
        }

        // splitOnce separates text around the first delimiter occurrence.
        // Returning false means the delimiter is absent or at an unusable position.
        bool splitOnce(
            const std::string& inputText,
            const char delimiter,
            std::string* leftOut,
            std::string* rightOut)
        {
            const std::size_t kDelimiterIndex = inputText.find(delimiter);
            if (kDelimiterIndex == std::string::npos || kDelimiterIndex == 0)
            {
                return false;
            }
            if (leftOut != nullptr)
            {
                *leftOut = trimAscii(inputText.substr(0, kDelimiterIndex));
            }
            if (rightOut != nullptr)
            {
                *rightOut = trimAscii(inputText.substr(kDelimiterIndex + 1));
            }
            return true;
        }

        // tryParseUnsignedDecimal parses a non-negative decimal integer.
        // maxValue bounds the accepted value and avoids silent integer truncation.
        bool tryParseUnsignedDecimal(
            const std::string& inputText,
            const unsigned long long maxValue,
            unsigned long long* valueOut)
        {
            const std::string kTrimmedText = trimAscii(inputText);
            if (kTrimmedText.empty() || valueOut == nullptr)
            {
                return false;
            }

            unsigned long long value = 0;
            for (const char kCurrentChar : kTrimmedText)
            {
                if (!std::isdigit(static_cast<unsigned char>(kCurrentChar)))
                {
                    return false;
                }
                value = (value * 10ULL) + static_cast<unsigned long long>(kCurrentChar - '0');
                if (value > maxValue)
                {
                    return false;
                }
            }

            *valueOut = value;
            return true;
        }

        // appendHexByte appends one uppercase two-digit hexadecimal byte to a stream.
        // Width/fill are set each time because iostream manipulators are sticky.
        void appendHexByte(std::ostringstream& stream, const std::uint8_t byteValue)
        {
            stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(byteValue)
                << std::dec << std::setfill(' ');
        }

        // appendReadableSegmentIfUseful stores a simplified text segment if it is long enough.
        // Short fragments are ignored because they are often random printable binary bytes.
        void appendReadableSegmentIfUseful(
            const std::string& segmentText,
            std::vector<std::string>& readableSegments)
        {
            const std::string kSimplifiedText = simplifyWhitespace(segmentText);
            if (kSimplifiedText.size() >= 4)
            {
                readableSegments.push_back(kSimplifiedText);
            }
        }
    } // namespace

    std::string formatEndpointText(const std::string& ipAddress, const std::uint16_t portNumber)
    {
        // IPv6 literals contain ':' and need brackets before appending the port separator.
        if (ipAddress.find(':') != std::string::npos)
        {
            return "[" + ipAddress + "]:" + std::to_string(portNumber);
        }
        return ipAddress + ":" + std::to_string(portNumber);
    }

    std::string formatByteCount(const std::uint64_t bytesValue)
    {
        // Unit selection follows powers of 1024 to match binary transfer counters.
        static const char* kUnitList[] = { "B", "KB", "MB", "GB", "TB" };
        double normalizedValue = static_cast<double>(bytesValue);
        int unitIndex = 0;
        while (normalizedValue >= 1024.0 && unitIndex < 4)
        {
            normalizedValue /= 1024.0;
            ++unitIndex;
        }

        std::ostringstream stream;
        if (unitIndex == 0)
        {
            stream << bytesValue << " B";
        }
        else
        {
            stream << std::fixed << std::setprecision(2) << normalizedValue << ' ' << kUnitList[unitIndex];
        }
        return stream.str();
    }

    std::string formatBytesPerSecond(const std::uint64_t bytesPerSecond)
    {
        return formatByteCount(bytesPerSecond) + "/s";
    }

    std::string formatUnixTimestampMs(const std::uint64_t timestampMs, const bool includeDate)
    {
        const std::time_t kSeconds = static_cast<std::time_t>(timestampMs / 1000ULL);
        const unsigned int kMilliseconds = static_cast<unsigned int>(timestampMs % 1000ULL);

        std::tm localTime{};
#if defined(_WIN32)
        localtime_s(&localTime, &kSeconds);
#else
        localtime_r(&seconds, &localTime);
#endif

        std::ostringstream stream;
        stream << std::setfill('0');
        if (includeDate)
        {
            stream << std::setw(4) << (localTime.tm_year + 1900) << '-'
                << std::setw(2) << (localTime.tm_mon + 1) << '-'
                << std::setw(2) << localTime.tm_mday << ' ';
        }
        stream << std::setw(2) << localTime.tm_hour << ':'
            << std::setw(2) << localTime.tm_min << ':'
            << std::setw(2) << localTime.tm_sec << '.'
            << std::setw(3) << kMilliseconds;
        return stream.str();
    }

    std::string formatPercent(const double percentValue, const int decimals)
    {
        const int kSafeDecimals = std::clamp(decimals, 0, 6);
        const double kSafePercent = std::clamp(percentValue, 0.0, 100.0);
        std::ostringstream stream;
        stream << std::fixed << std::setprecision(kSafeDecimals) << kSafePercent;
        return stream.str();
    }

    std::string formatBytesToHexPreview(
        const std::vector<std::uint8_t>& byteArray,
        const std::size_t maxBytesToRender)
    {
        if (byteArray.empty())
        {
            return "<empty>";
        }

        const std::size_t kRenderLength = std::min<std::size_t>(byteArray.size(), maxBytesToRender);
        std::ostringstream stream;
        for (std::size_t index = 0; index < kRenderLength; ++index)
        {
            if (index > 0)
            {
                stream << ' ';
            }
            appendHexByte(stream, byteArray[index]);
        }
        if (kRenderLength < byteArray.size())
        {
            stream << " ... (total=" << byteArray.size() << " bytes)";
        }
        return stream.str();
    }

    PayloadByteRange buildPayloadByteRange(const PacketRecord& packetRecord)
    {
        if (packetRecord.packetBytes.empty() || packetRecord.payloadOffset >= packetRecord.packetBytes.size())
        {
            return {};
        }

        const std::size_t kMaxReadableLength = packetRecord.packetBytes.size() - packetRecord.payloadOffset;
        const std::size_t kExpectedPayloadLength = packetRecord.payloadSize == 0
            ? kMaxReadableLength
            : std::min<std::size_t>(static_cast<std::size_t>(packetRecord.payloadSize), kMaxReadableLength);
        return PayloadByteRange{ packetRecord.payloadOffset, kExpectedPayloadLength };
    }

    std::string buildPayloadAsciiPreviewText(
        const PacketRecord& packetRecord,
        const std::size_t previewByteLimit)
    {
        const PayloadByteRange kPayloadRange = buildPayloadByteRange(packetRecord);
        if (kPayloadRange.length == 0)
        {
            return "<empty>";
        }

        const std::size_t kPreviewLength = std::min<std::size_t>(kPayloadRange.length, previewByteLimit);
        std::vector<std::string> readableSegments;
        std::string currentSegment;
        currentSegment.reserve(kPreviewLength);

        for (std::size_t index = 0; index < kPreviewLength; ++index)
        {
            const std::uint8_t kByteValue = packetRecord.packetBytes[kPayloadRange.offset + index];
            if (isVisibleAsciiByte(kByteValue) || kByteValue == ' ' || kByteValue == '\t')
            {
                currentSegment.push_back(isVisibleAsciiByte(kByteValue) ? static_cast<char>(kByteValue) : ' ');
                continue;
            }

            appendReadableSegmentIfUseful(currentSegment, readableSegments);
            currentSegment.clear();
        }
        appendReadableSegmentIfUseful(currentSegment, readableSegments);

        std::string previewText;
        if (!readableSegments.empty())
        {
            for (std::size_t index = 0; index < readableSegments.size(); ++index)
            {
                if (index > 0)
                {
                    previewText += " | ";
                }
                previewText += readableSegments[index];
            }
        }
        else
        {
            previewText.reserve(kPreviewLength);
            for (std::size_t index = 0; index < kPreviewLength; ++index)
            {
                previewText.push_back(normalizeAsciiCharForPreview(packetRecord.packetBytes[kPayloadRange.offset + index]));
            }
            previewText = simplifyWhitespace(previewText);
        }

        if (previewText.empty())
        {
            previewText = "<binary payload>";
        }
        if (kPreviewLength < kPayloadRange.length)
        {
            previewText += " ...";
        }
        if (packetRecord.packetBytesTruncated)
        {
            previewText += " [truncated]";
        }
        return previewText;
    }

    std::string buildPayloadAsciiFullText(const PacketRecord& packetRecord)
    {
        const PayloadByteRange kPayloadRange = buildPayloadByteRange(packetRecord);
        if (kPayloadRange.length == 0)
        {
            return "<empty>";
        }

        std::string asciiText;
        asciiText.reserve(kPayloadRange.length);
        for (std::size_t index = 0; index < kPayloadRange.length; ++index)
        {
            const std::uint8_t kByteValue = packetRecord.packetBytes[kPayloadRange.offset + index];
            if (kByteValue == '\r')
            {
                if (index + 1 < kPayloadRange.length && packetRecord.packetBytes[kPayloadRange.offset + index + 1] == '\n')
                {
                    ++index;
                }
                asciiText.push_back('\n');
                continue;
            }
            if (kByteValue == '\n' || kByteValue == '\t')
            {
                asciiText.push_back(static_cast<char>(kByteValue));
                continue;
            }
            asciiText.push_back(isVisibleAsciiByte(kByteValue) ? static_cast<char>(kByteValue) : '.');
        }

        if (packetRecord.packetBytesTruncated)
        {
            asciiText += "\n[truncated capture]";
        }
        return asciiText;
    }

    std::string buildPayloadHexFullText(const PacketRecord& packetRecord)
    {
        const PayloadByteRange kPayloadRange = buildPayloadByteRange(packetRecord);
        if (kPayloadRange.length == 0)
        {
            return std::string();
        }

        std::ostringstream stream;
        for (std::size_t index = 0; index < kPayloadRange.length; ++index)
        {
            if (index > 0)
            {
                stream << ' ';
            }
            appendHexByte(stream, packetRecord.packetBytes[kPayloadRange.offset + index]);
        }
        return stream.str();
    }

    std::string buildPacketHexAsciiDumpText(
        const PacketRecord& packetRecord,
        const std::size_t bytesPerRow)
    {
        const std::size_t kSafeBytesPerRow = bytesPerRow == 0 ? kHexBytesPerRowDefault : bytesPerRow;
        const std::vector<std::uint8_t>& packetBytes = packetRecord.packetBytes;
        if (packetBytes.empty())
        {
            return "00000000  -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --  |<empty>|";
        }

        std::ostringstream stream;
        stream << "Offset(h)  Hex bytes";
        if (kSafeBytesPerRow < 16)
        {
            stream << "\n";
        }
        else
        {
            stream << "                                              ASCII\n";
        }
        const std::size_t kRowCount = (packetBytes.size() + kSafeBytesPerRow - 1) / kSafeBytesPerRow;
        for (std::size_t rowIndex = 0; rowIndex < kRowCount; ++rowIndex)
        {
            const std::size_t kRowOffset = rowIndex * kSafeBytesPerRow;
            stream << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << kRowOffset
                << std::dec << std::setfill(' ') << "  ";

            std::string asciiColumn;
            asciiColumn.reserve(kSafeBytesPerRow);
            for (std::size_t byteColumn = 0; byteColumn < kSafeBytesPerRow; ++byteColumn)
            {
                const std::size_t kByteIndex = kRowOffset + byteColumn;
                if (kByteIndex < packetBytes.size())
                {
                    appendHexByte(stream, packetBytes[kByteIndex]);
                    asciiColumn.push_back(isVisibleAsciiByte(packetBytes[kByteIndex]) ? static_cast<char>(packetBytes[kByteIndex]) : '.');
                }
                else
                {
                    stream << "  ";
                    asciiColumn.push_back(' ');
                }
                if (byteColumn + 1 < kSafeBytesPerRow)
                {
                    stream << ' ';
                }
            }
            stream << "  |" << asciiColumn << '|';
            if (rowIndex + 1 < kRowCount)
            {
                stream << '\n';
            }
        }

        if (packetRecord.packetBytesTruncated)
        {
            stream << "\n[truncated capture: original bytes exceed retain limit]";
        }
        return stream.str();
    }

    std::string buildPacketCopyHeaderLine(const PacketRecord& packetRecord)
    {
        std::ostringstream stream;
        stream << '#' << packetRecord.sequenceId
            << " | time=" << formatUnixTimestampMs(packetRecord.captureTimestampMs, true)
            << " | pid=" << packetRecord.processId
            << " | protocol=" << packetProtocolToString(packetRecord.protocol)
            << " | direction=" << packetDirectionToString(packetRecord.direction)
            << " | local=" << formatEndpointText(packetRecord.localAddress, packetRecord.localPort)
            << " | remote=" << formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort)
            << " | length=" << packetRecord.payloadSize << '/' << packetRecord.totalPacketSize;
        return stream.str();
    }

    std::string formatIpv4HostOrder(const std::uint32_t ipv4HostOrder)
    {
        std::ostringstream stream;
        stream << ((ipv4HostOrder >> 24) & 0xFFU) << '.'
            << ((ipv4HostOrder >> 16) & 0xFFU) << '.'
            << ((ipv4HostOrder >> 8) & 0xFFU) << '.'
            << (ipv4HostOrder & 0xFFU);
        return stream.str();
    }

    bool tryParseIpv4Text(const std::string& ipv4Text, std::uint32_t* const ipv4HostOrderOut)
    {
        if (ipv4HostOrderOut == nullptr)
        {
            return false;
        }

        const std::string kTrimmedText = trimAscii(ipv4Text);
        if (kTrimmedText.empty())
        {
            return false;
        }

        std::uint32_t ipv4Value = 0;
        std::size_t segmentBegin = 0;
        int segmentCount = 0;
        while (segmentBegin <= kTrimmedText.size())
        {
            const std::size_t kDotIndex = kTrimmedText.find('.', segmentBegin);
            const std::size_t kSegmentEnd = kDotIndex == std::string::npos ? kTrimmedText.size() : kDotIndex;
            if (kSegmentEnd == segmentBegin)
            {
                return false;
            }

            unsigned long long segmentValue = 0;
            if (!tryParseUnsignedDecimal(kTrimmedText.substr(segmentBegin, kSegmentEnd - segmentBegin), 255ULL, &segmentValue))
            {
                return false;
            }

            ipv4Value = (ipv4Value << 8) | static_cast<std::uint32_t>(segmentValue);
            ++segmentCount;
            if (kDotIndex == std::string::npos)
            {
                break;
            }
            segmentBegin = kDotIndex + 1;
        }

        if (segmentCount != 4)
        {
            return false;
        }
        *ipv4HostOrderOut = ipv4Value;
        return true;
    }

    bool tryParseIpv4RangeText(
        const std::string& rangeText,
        std::pair<std::uint32_t, std::uint32_t>* const rangeOut,
        std::string* const normalizedTextOut)
    {
        if (rangeOut == nullptr)
        {
            return false;
        }

        const std::string kTrimmedText = trimAscii(rangeText);
        if (kTrimmedText.empty())
        {
            return false;
        }

        std::string leftText;
        std::string rightText;
        if (splitOnce(kTrimmedText, '/', &leftText, &rightText))
        {
            std::uint32_t baseIpHostOrder = 0;
            unsigned long long prefixValue = 0;
            if (!tryParseIpv4Text(leftText, &baseIpHostOrder) ||
                !tryParseUnsignedDecimal(rightText, 32ULL, &prefixValue))
            {
                return false;
            }

            const unsigned int kPrefixLength = static_cast<unsigned int>(prefixValue);
            const std::uint32_t kNetmask = kPrefixLength == 0
                ? 0U
                : (0xFFFFFFFFU << static_cast<unsigned int>(32U - kPrefixLength));
            const std::uint32_t kRangeBegin = baseIpHostOrder & kNetmask;
            const std::uint32_t kRangeEnd = kRangeBegin | (~kNetmask);
            *rangeOut = { kRangeBegin, kRangeEnd };
            if (normalizedTextOut != nullptr)
            {
                *normalizedTextOut = formatIpv4HostOrder(kRangeBegin) + "/" + std::to_string(kPrefixLength);
            }
            return true;
        }

        if (splitOnce(kTrimmedText, '-', &leftText, &rightText))
        {
            std::uint32_t beginIpHostOrder = 0;
            std::uint32_t endIpHostOrder = 0;
            if (!tryParseIpv4Text(leftText, &beginIpHostOrder) ||
                !tryParseIpv4Text(rightText, &endIpHostOrder))
            {
                return false;
            }

            const std::uint32_t kNormalizedBegin = std::min(beginIpHostOrder, endIpHostOrder);
            const std::uint32_t kNormalizedEnd = std::max(beginIpHostOrder, endIpHostOrder);
            *rangeOut = { kNormalizedBegin, kNormalizedEnd };
            if (normalizedTextOut != nullptr)
            {
                *normalizedTextOut = formatIpv4HostOrder(kNormalizedBegin) + "-" + formatIpv4HostOrder(kNormalizedEnd);
            }
            return true;
        }

        std::uint32_t singleIpHostOrder = 0;
        if (!tryParseIpv4Text(kTrimmedText, &singleIpHostOrder))
        {
            return false;
        }
        *rangeOut = { singleIpHostOrder, singleIpHostOrder };
        if (normalizedTextOut != nullptr)
        {
            *normalizedTextOut = formatIpv4HostOrder(singleIpHostOrder);
        }
        return true;
    }

    bool tryParsePortRangeText(
        const std::string& rangeText,
        std::pair<std::uint16_t, std::uint16_t>* const rangeOut,
        std::string* const normalizedTextOut)
    {
        if (rangeOut == nullptr)
        {
            return false;
        }

        const std::string kTrimmedText = trimAscii(rangeText);
        if (kTrimmedText.empty())
        {
            return false;
        }

        std::string leftText;
        std::string rightText;
        if (splitOnce(kTrimmedText, '-', &leftText, &rightText))
        {
            unsigned long long beginPortValue = 0;
            unsigned long long endPortValue = 0;
            if (!tryParseUnsignedDecimal(leftText, 65535ULL, &beginPortValue) ||
                !tryParseUnsignedDecimal(rightText, 65535ULL, &endPortValue))
            {
                return false;
            }

            const std::uint16_t kNormalizedBegin = static_cast<std::uint16_t>(std::min(beginPortValue, endPortValue));
            const std::uint16_t kNormalizedEnd = static_cast<std::uint16_t>(std::max(beginPortValue, endPortValue));
            *rangeOut = { kNormalizedBegin, kNormalizedEnd };
            if (normalizedTextOut != nullptr)
            {
                *normalizedTextOut = std::to_string(kNormalizedBegin) + "-" + std::to_string(kNormalizedEnd);
            }
            return true;
        }

        unsigned long long singlePortValue = 0;
        if (!tryParseUnsignedDecimal(kTrimmedText, 65535ULL, &singlePortValue))
        {
            return false;
        }
        const std::uint16_t kSinglePort = static_cast<std::uint16_t>(singlePortValue);
        *rangeOut = { kSinglePort, kSinglePort };
        if (normalizedTextOut != nullptr)
        {
            *normalizedTextOut = std::to_string(kSinglePort);
        }
        return true;
    }
} // namespace ks::network

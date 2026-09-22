#include "NetworkDiagnosticsTools.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace ks::network
{
    namespace
    {
        // These values mirror Windows MIB_IPNET_TYPE_* constants without requiring Win32 headers.
        constexpr std::uint32_t kArpTypeInvalid = 2;
        constexpr std::uint32_t kArpTypeDynamic = 3;
        constexpr std::uint32_t kArpTypeStatic = 4;

        // trimAscii keeps parser behavior independent from locale-specific whitespace rules.
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

        // hexNibbleValue converts one hex character to a numeric nibble.
        // It returns -1 for invalid input so callers can produce precise errors.
        int hexNibbleValue(const char currentChar)
        {
            if (currentChar >= '0' && currentChar <= '9')
            {
                return currentChar - '0';
            }
            if (currentChar >= 'a' && currentChar <= 'f')
            {
                return currentChar - 'a' + 10;
            }
            if (currentChar >= 'A' && currentChar <= 'F')
            {
                return currentChar - 'A' + 10;
            }
            return -1;
        }
    } // namespace

    std::string formatHardwareAddress(
        const std::uint8_t* const addressBytes,
        const std::size_t addressLength,
        const char separator)
    {
        if (addressBytes == nullptr || addressLength == 0)
        {
            return std::string();
        }

        std::ostringstream stream;
        for (std::size_t index = 0; index < addressLength; ++index)
        {
            if (index > 0)
            {
                stream << separator;
            }
            stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(addressBytes[index])
                << std::dec << std::setfill(' ');
        }
        return stream.str();
    }

    bool tryParseMacAddressText(
        const std::string& macText,
        std::vector<std::uint8_t>* const macBytesOut,
        std::string* const errorTextOut)
    {
        if (macBytesOut == nullptr)
        {
            return false;
        }
        macBytesOut->clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        std::string normalizedText = trimAscii(macText);
        std::replace(normalizedText.begin(), normalizedText.end(), ':', '-');
        if (normalizedText.empty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = "MAC address is empty.";
            }
            return false;
        }

        std::size_t segmentBegin = 0;
        while (segmentBegin <= normalizedText.size())
        {
            const std::size_t kSeparatorIndex = normalizedText.find('-', segmentBegin);
            const std::size_t kSegmentEnd = kSeparatorIndex == std::string::npos ? normalizedText.size() : kSeparatorIndex;
            if (kSegmentEnd - segmentBegin != 2)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = "MAC address must contain six two-digit hex segments.";
                }
                macBytesOut->clear();
                return false;
            }

            const int kHighNibble = hexNibbleValue(normalizedText[segmentBegin]);
            const int kLowNibble = hexNibbleValue(normalizedText[segmentBegin + 1]);
            if (kHighNibble < 0 || kLowNibble < 0)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = "MAC address contains non-hex characters.";
                }
                macBytesOut->clear();
                return false;
            }
            macBytesOut->push_back(static_cast<std::uint8_t>((kHighNibble << 4) | kLowNibble));

            if (kSeparatorIndex == std::string::npos)
            {
                break;
            }
            segmentBegin = kSeparatorIndex + 1;
        }

        if (macBytesOut->size() != 6)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = "MAC address must contain exactly six segments.";
            }
            macBytesOut->clear();
            return false;
        }
        return true;
    }

    std::string arpEntryTypeToString(const std::uint32_t typeCode)
    {
        switch (typeCode)
        {
        case kArpTypeDynamic:
            return "Dynamic";
        case kArpTypeStatic:
            return "Static";
        case kArpTypeInvalid:
            return "Invalid";
        default:
            return "Unknown";
        }
    }

    std::string formatDnsFlags(const std::uint32_t flagsValue)
    {
        std::ostringstream stream;
        stream << "0x" << std::uppercase << std::hex << flagsValue;
        return stream.str();
    }

    Ipv4ScanRange normalizeIpv4ScanRange(
        const std::uint32_t firstHostOrder,
        const std::uint32_t secondHostOrder,
        const std::uint64_t maxHostCount)
    {
        Ipv4ScanRange range;
        range.beginHostOrder = std::min(firstHostOrder, secondHostOrder);
        range.endHostOrder = std::max(firstHostOrder, secondHostOrder);
        range.hostCount = static_cast<std::uint64_t>(range.endHostOrder) - range.beginHostOrder + 1ULL;
        range.withinLimit = maxHostCount == 0 || range.hostCount <= maxHostCount;
        return range;
    }

    int calculateIntegerProgressPercent(
        const std::uint64_t doneCount,
        const std::uint64_t totalCount)
    {
        if (totalCount == 0)
        {
            return 0;
        }
        const std::uint64_t kClampedDone = std::min(doneCount, totalCount);
        // Uses long double to prevent done*100 overflow at large counts while maintaining floor semantics.
        const long double kProgressValue =
            (static_cast<long double>(kClampedDone) * 100.0L) /
            static_cast<long double>(totalCount);
        return static_cast<int>(std::clamp(kProgressValue, 0.0L, 100.0L));
    }

    std::string formatIcmpEchoDetail(
        const bool alive,
        const std::uint32_t statusCode,
        const std::uint8_t ttlValue)
    {
        if (alive)
        {
            return "TTL=" + std::to_string(static_cast<unsigned int>(ttlValue));
        }
        return "Status=" + std::to_string(statusCode);
    }
} // namespace ks::network

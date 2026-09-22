#include "NetworkNids.h"

#include "NetworkFormatTools.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>

namespace ks::network
{
    namespace
    {
        constexpr std::uint64_t kPortScanWindowMs = 15000;
        constexpr std::uint64_t kPortScanAlertCooldownMs = 30000;
        constexpr std::uint64_t kFlowAlertCooldownMs = 60000;
        constexpr std::uint64_t kOutboundByteWindowMs = 30000;
        constexpr std::uint64_t kOutboundByteThreshold = 8ULL * 1024ULL * 1024ULL;

        // makeBaseAlert: Generates the alert base structure using common packet fields.
        NidsAlert makeBaseAlert(
            const PacketRecord& packetRecord,
            const NidsAlertSeverity severity,
            std::string category,
            std::string ruleId,
            std::string title,
            std::string detail)
        {
            NidsAlert alert;
            alert.timestampMs = packetRecord.captureTimestampMs;
            alert.sequenceId = packetRecord.sequenceId;
            alert.severity = severity;
            alert.category = std::move(category);
            alert.ruleId = std::move(ruleId);
            alert.title = std::move(title);
            alert.detail = std::move(detail);
            alert.processId = packetRecord.processId;
            alert.processName = packetRecord.processName;
            alert.protocol = packetRecord.protocol;
            alert.direction = packetRecord.direction;
            alert.localAddress = packetRecord.localAddress;
            alert.localPort = packetRecord.localPort;
            alert.remoteAddress = packetRecord.remoteAddress;
            alert.remotePort = packetRecord.remotePort;
            return alert;
        }

        // toLowerAscii: Convert only ASCII to avoid introducing localization dependencies.
        std::string toLowerAscii(std::string text)
        {
            for (char& ch : text)
            {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }
            return text;
        }

        // containsCaseInsensitive: Case-insensitive substring matching.
        bool containsCaseInsensitive(const std::string& haystack, const std::string& needle)
        {
            if (needle.empty())
            {
                return true;
            }
            return toLowerAscii(haystack).find(toLowerAscii(needle)) != std::string::npos;
        }

        // startsWithCaseInsensitive: Case-insensitive prefix matching.
        bool startsWithCaseInsensitive(const std::string& text, const std::string& prefix)
        {
            if (text.size() < prefix.size())
            {
                return false;
            }
            for (std::size_t index = 0; index < prefix.size(); ++index)
            {
                const char kLeft = static_cast<char>(std::tolower(static_cast<unsigned char>(text[index])));
                const char kRight = static_cast<char>(std::tolower(static_cast<unsigned char>(prefix[index])));
                if (kLeft != kRight)
                {
                    return false;
                }
            }
            return true;
        }

        // buildEndpointKey: Constructs a deduplication key for the flow.
        std::string buildEndpointKey(const PacketRecord& packetRecord)
        {
            std::ostringstream stream;
            stream << static_cast<int>(packetRecord.protocol)
                << '|'
                << static_cast<int>(packetRecord.direction)
                << '|'
                << packetRecord.processId
                << '|'
                << packetRecord.localAddress
                << ':'
                << packetRecord.localPort
                << '|'
                << packetRecord.remoteAddress
                << ':'
                << packetRecord.remotePort;
            return stream.str();
        }

        // appendPortWindowEvent: Maintains port events within a fixed time window.
        void appendPortWindowEvent(
            NidsEngine::PortScanWindow& window,
            const std::uint64_t nowMs,
            const std::uint16_t port)
        {
            window.eventList.push_back({ nowMs, port });
            while (!window.eventList.empty() &&
                nowMs > window.eventList.front().timestampMs &&
                nowMs - window.eventList.front().timestampMs > kPortScanWindowMs)
            {
                window.eventList.pop_front();
            }
        }

        // countDistinctPorts: Counts the number of distinct ports within the current scanning window.
        std::size_t countDistinctPorts(const std::deque<NidsEngine::PortEvent>& eventList)
        {
            std::unordered_set<std::uint16_t> portSet;
            portSet.reserve(eventList.size());
            for (const NidsEngine::PortEvent& eventItem : eventList)
            {
                portSet.insert(eventItem.port);
            }
            return portSet.size();
        }

        // tryReadTcpFlags: Read TCP flags from reserved IP packet bytes.
        bool tryReadTcpFlags(const PacketRecord& packetRecord, std::uint8_t& flagsOut)
        {
            if (packetRecord.protocol != PacketTransportProtocol::kTcp ||
                packetRecord.packetBytes.size() < 20)
            {
                return false;
            }

            const std::uint8_t kVersion = static_cast<std::uint8_t>(packetRecord.packetBytes[0] >> 4);
            std::size_t tcpOffset = 0;
            if (kVersion == 4)
            {
                const std::size_t kIpv4HeaderLength = static_cast<std::size_t>(packetRecord.packetBytes[0] & 0x0F) * 4;
                if (kIpv4HeaderLength < 20 || packetRecord.packetBytes.size() < kIpv4HeaderLength + 14)
                {
                    return false;
                }
                tcpOffset = kIpv4HeaderLength;
            }
            else if (kVersion == 6)
            {
                if (packetRecord.packetBytes.size() < 54 || packetRecord.packetBytes[6] != 6)
                {
                    return false;
                }
                tcpOffset = 40;
            }
            else
            {
                return false;
            }

            flagsOut = packetRecord.packetBytes[tcpOffset + 13];
            return true;
        }

        // looksLikeTcpProbe: Determines if a TCP packet resembles a port scan probe.
        bool looksLikeTcpProbe(const PacketRecord& packetRecord)
        {
            std::uint8_t flags = 0;
            if (tryReadTcpFlags(packetRecord, flags))
            {
                constexpr std::uint8_t kSynFlag = 0x02;
                constexpr std::uint8_t kAckFlag = 0x10;
                return (flags & kSynFlag) != 0 && (flags & kAckFlag) == 0;
            }

            return packetRecord.payloadSize == 0 && packetRecord.totalPacketSize <= 96;
        }

        // buildScanKey: Constructs a key for the port scan behavior window.
        std::string buildScanKey(const PacketRecord& packetRecord)
        {
            const bool kInbound = packetRecord.direction == PacketDirection::kInbound;
            const std::string& actorAddress = kInbound ? packetRecord.remoteAddress : packetRecord.localAddress;
            const std::string& targetAddress = kInbound ? packetRecord.localAddress : packetRecord.remoteAddress;

            std::ostringstream stream;
            stream << static_cast<int>(packetRecord.protocol)
                << '|'
                << static_cast<int>(packetRecord.direction)
                << '|'
                << packetRecord.processId
                << '|'
                << actorAddress
                << "->"
                << targetAddress;
            return stream.str();
        }

        // readPayloadBytes: Returns a safe view of the payload within the currently reserved bytes.
        std::vector<std::uint8_t> readPayloadBytes(const PacketRecord& packetRecord, const std::size_t limitBytes)
        {
            const PayloadByteRange kPayloadRange = buildPayloadByteRange(packetRecord);
            if (kPayloadRange.length == 0 ||
                kPayloadRange.offset >= packetRecord.packetBytes.size())
            {
                return {};
            }

            const std::size_t kReadLength = std::min<std::size_t>(kPayloadRange.length, limitBytes);
            const auto kBeginIterator = packetRecord.packetBytes.begin() + static_cast<std::ptrdiff_t>(kPayloadRange.offset);
            const auto kEndIterator = kBeginIterator + static_cast<std::ptrdiff_t>(kReadLength);
            return std::vector<std::uint8_t>(kBeginIterator, kEndIterator);
        }

        // readPayloadAscii: Reads the printable ASCII view of the payload.
        std::string readPayloadAscii(const PacketRecord& packetRecord, const std::size_t limitBytes)
        {
            const std::vector<std::uint8_t> kPayloadBytes = readPayloadBytes(packetRecord, limitBytes);
            std::string output;
            output.reserve(kPayloadBytes.size());
            for (const std::uint8_t kByteValue : kPayloadBytes)
            {
                if (kByteValue == '\r' || kByteValue == '\n' || kByteValue == '\t' ||
                    (kByteValue >= 0x20 && kByteValue <= 0x7E))
                {
                    output.push_back(static_cast<char>(kByteValue));
                }
                else
                {
                    output.push_back('.');
                }
            }
            return output;
        }

        // parseDnsQuestion: Parse the domain name and qtype of the first DNS question.
        bool parseDnsQuestion(
            const PacketRecord& packetRecord,
            std::string& domainOut,
            std::uint16_t& qtypeOut)
        {
            const std::vector<std::uint8_t> kPayloadBytes = readPayloadBytes(packetRecord, 512);
            if (kPayloadBytes.size() < 12)
            {
                return false;
            }

            const std::uint16_t kQuestionCount = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(kPayloadBytes[4]) << 8) |
                static_cast<std::uint16_t>(kPayloadBytes[5]));
            if (kQuestionCount == 0)
            {
                return false;
            }

            std::size_t offset = 12;
            std::vector<std::string> labelList;
            labelList.reserve(8);
            while (offset < kPayloadBytes.size())
            {
                const std::uint8_t kLabelLength = kPayloadBytes[offset++];
                if (kLabelLength == 0)
                {
                    break;
                }
                if ((kLabelLength & 0xC0) != 0 || kLabelLength > 63)
                {
                    return false;
                }
                if (offset + kLabelLength > kPayloadBytes.size())
                {
                    return false;
                }

                std::string label;
                label.reserve(kLabelLength);
                for (std::uint8_t labelIndex = 0; labelIndex < kLabelLength; ++labelIndex)
                {
                    const char kCh = static_cast<char>(kPayloadBytes[offset + labelIndex]);
                    if (std::isalnum(static_cast<unsigned char>(kCh)) || kCh == '-' || kCh == '_')
                    {
                        label.push_back(kCh);
                    }
                    else
                    {
                        label.push_back('.');
                    }
                }
                labelList.push_back(std::move(label));
                offset += kLabelLength;
            }

            if (labelList.empty() || offset + 4 > kPayloadBytes.size())
            {
                return false;
            }

            qtypeOut = static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(kPayloadBytes[offset]) << 8) |
                static_cast<std::uint16_t>(kPayloadBytes[offset + 1]));

            std::ostringstream domainStream;
            for (std::size_t index = 0; index < labelList.size(); ++index)
            {
                if (index != 0)
                {
                    domainStream << '.';
                }
                domainStream << labelList[index];
            }
            domainOut = domainStream.str();
            return !domainOut.empty();
        }

        // splitDomainLabels: Splits domain names by dots.
        std::vector<std::string> splitDomainLabels(const std::string& domainText)
        {
            std::vector<std::string> labelList;
            std::string currentLabel;
            for (const char kCh : domainText)
            {
                if (kCh == '.')
                {
                    if (!currentLabel.empty())
                    {
                        labelList.push_back(currentLabel);
                        currentLabel.clear();
                    }
                }
                else
                {
                    currentLabel.push_back(kCh);
                }
            }
            if (!currentLabel.empty())
            {
                labelList.push_back(currentLabel);
            }
            return labelList;
        }

        // shannonEntropy: Calculates rough entropy for ASCII text.
        double shannonEntropy(const std::string& text)
        {
            if (text.empty())
            {
                return 0.0;
            }

            std::array<std::size_t, 256> frequency{};
            for (const unsigned char kCh : text)
            {
                ++frequency[kCh];
            }

            double entropy = 0.0;
            const double kLength = static_cast<double>(text.size());
            for (const std::size_t kCount : frequency)
            {
                if (kCount == 0)
                {
                    continue;
                }
                const double kProbability = static_cast<double>(kCount) / kLength;
                entropy -= kProbability * std::log2(kProbability);
            }
            return entropy;
        }

        // looksRandomDnsLabel: Determines if a DNS label exhibits random or tunneling characteristics.
        bool looksRandomDnsLabel(const std::string& label)
        {
            if (label.size() < 24)
            {
                return false;
            }

            std::size_t digitCount = 0;
            std::size_t alphaCount = 0;
            std::unordered_set<char> uniqueCharSet;
            for (const char kCh : label)
            {
                if (std::isdigit(static_cast<unsigned char>(kCh)))
                {
                    ++digitCount;
                }
                if (std::isalpha(static_cast<unsigned char>(kCh)))
                {
                    ++alphaCount;
                }
                uniqueCharSet.insert(static_cast<char>(std::tolower(static_cast<unsigned char>(kCh))));
            }

            return alphaCount >= 12 &&
                digitCount >= 3 &&
                uniqueCharSet.size() >= 14 &&
                shannonEntropy(label) >= 3.6;
        }

        // hasSuffix: Case-insensitive suffix matching.
        bool hasSuffix(const std::string& text, const std::string& suffix)
        {
            if (text.size() < suffix.size())
            {
                return false;
            }
            return startsWithCaseInsensitive(text.substr(text.size() - suffix.size()), suffix);
        }

        // buildRiskyPortTitle: Returns the description for a risky port.
        bool buildRiskyPortTitle(const std::uint16_t port, std::string& titleOut)
        {
            switch (port)
            {
            case 23:
            case 2323:
                titleOut = "Telnet 端口通信";
                return true;
            case 4444:
            case 1337:
            case 31337:
                titleOut = "常见后门端口通信";
                return true;
            case 6667:
                titleOut = "IRC/C2 常见端口通信";
                return true;
            case 5900:
                titleOut = "VNC 远程控制端口通信";
                return true;
            default:
                return false;
            }
        }

        // buildHttpFirstLine: Extracts the first line of an HTTP request.
        std::string buildHttpFirstLine(const std::string& payloadText)
        {
            const std::size_t kEndPosition = payloadText.find('\n');
            std::string firstLine = kEndPosition == std::string::npos
                ? payloadText
                : payloadText.substr(0, kEndPosition);
            while (!firstLine.empty() && (firstLine.back() == '\r' || firstLine.back() == '\n'))
            {
                firstLine.pop_back();
            }
            if (firstLine.size() > 220)
            {
                firstLine.resize(220);
                firstLine += "...";
            }
            return firstLine;
        }

        // looksLikeHttpRequest: Checks if the payload is a plaintext HTTP request.
        bool looksLikeHttpRequest(const std::string& payloadText)
        {
            static const std::array<const char*, 9> kHttpMethods = {
                "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "TRACE ", "CONNECT "
            };
            for (const char* methodText : kHttpMethods)
            {
                if (startsWithCaseInsensitive(payloadText, methodText))
                {
                    return true;
                }
            }
            return false;
        }

        // buildPacketSummary: Construct a packet endpoint summary.
        std::string buildPacketSummary(const PacketRecord& packetRecord)
        {
            std::ostringstream stream;
            stream << packetProtocolToString(packetRecord.protocol)
                << ' '
                << packetDirectionToString(packetRecord.direction)
                << ' '
                << formatEndpointText(packetRecord.localAddress, packetRecord.localPort)
                << " -> "
                << formatEndpointText(packetRecord.remoteAddress, packetRecord.remotePort);
            return stream.str();
        }

        // appendByteWindowEvent: Maintains a fixed time window for outbound bytes.
        void appendByteWindowEvent(
            NidsEngine::ByteWindow& window,
            const std::uint64_t nowMs,
            const std::uint64_t byteCount)
        {
            window.eventList.push_back({ nowMs, byteCount });
            window.totalBytes += byteCount;
            while (!window.eventList.empty() &&
                nowMs > window.eventList.front().timestampMs &&
                nowMs - window.eventList.front().timestampMs > kOutboundByteWindowMs)
            {
                window.totalBytes = window.totalBytes > window.eventList.front().byteCount
                    ? window.totalBytes - window.eventList.front().byteCount
                    : 0;
                window.eventList.pop_front();
            }
        }
    }

    std::string nidsAlertSeverityToString(const NidsAlertSeverity severity)
    {
        switch (severity)
        {
        case NidsAlertSeverity::kLow:
            return "Low";
        case NidsAlertSeverity::kMedium:
            return "Medium";
        case NidsAlertSeverity::kHigh:
            return "High";
        case NidsAlertSeverity::kCritical:
            return "Critical";
        default:
            return "Unknown";
        }
    }

    std::vector<NidsAlert> NidsEngine::analyzePacket(const PacketRecord& packetRecord)
    {
        std::vector<NidsAlert> alertList;
        analyzePortScan(packetRecord, alertList);
        analyzeDnsPayload(packetRecord, alertList);
        analyzeHttpPayload(packetRecord, alertList);
        analyzeSuspiciousPort(packetRecord, alertList);
        analyzeOutboundByteBurst(packetRecord, alertList);
        return alertList;
    }

    void NidsEngine::reset()
    {
        portScanWindowByKey_.clear();
        outboundByteWindowByKey_.clear();
        flowAlertLastTimestampByKey_.clear();
    }

    void NidsEngine::analyzePortScan(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList)
    {
        if (packetRecord.captureTimestampMs == 0 ||
            packetRecord.direction == PacketDirection::kUnknown)
        {
            return;
        }

        std::uint16_t probePort = 0;
        std::size_t threshold = 0;
        std::string ruleId;
        if (packetRecord.protocol == PacketTransportProtocol::kTcp)
        {
            if (!looksLikeTcpProbe(packetRecord))
            {
                return;
            }
            probePort = packetRecord.direction == PacketDirection::kInbound
                ? packetRecord.localPort
                : packetRecord.remotePort;
            threshold = 18;
            ruleId = "NIDS-SCAN-TCP-PORT-BURST";
        }
        else if (packetRecord.protocol == PacketTransportProtocol::kUdp)
        {
            probePort = packetRecord.direction == PacketDirection::kInbound
                ? packetRecord.localPort
                : packetRecord.remotePort;
            threshold = 24;
            ruleId = "NIDS-SCAN-UDP-PORT-BURST";
        }
        else
        {
            return;
        }

        if (probePort == 0)
        {
            return;
        }

        const std::string kScanKey = buildScanKey(packetRecord);
        PortScanWindow& window = portScanWindowByKey_[kScanKey];
        appendPortWindowEvent(window, packetRecord.captureTimestampMs, probePort);

        const std::size_t kDistinctPortCount = countDistinctPorts(window.eventList);
        if (kDistinctPortCount < threshold)
        {
            return;
        }
        if (window.lastAlertTimestampMs != 0 &&
            packetRecord.captureTimestampMs > window.lastAlertTimestampMs &&
            packetRecord.captureTimestampMs - window.lastAlertTimestampMs < kPortScanAlertCooldownMs)
        {
            return;
        }
        window.lastAlertTimestampMs = packetRecord.captureTimestampMs;

        std::ostringstream detailStream;
        detailStream << buildPacketSummary(packetRecord)
            << ", "
            << kPortScanWindowMs / 1000
            << "s 内探测 "
            << kDistinctPortCount
            << " 个不同端口。";

        alertList.push_back(makeBaseAlert(
            packetRecord,
            NidsAlertSeverity::kHigh,
            "Scan",
            ruleId,
            "短时端口扫描",
            detailStream.str()));
    }

    void NidsEngine::analyzeDnsPayload(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList)
    {
        if (packetRecord.protocol != PacketTransportProtocol::kUdp ||
            packetRecord.payloadSize == 0 ||
            (packetRecord.localPort != 53 && packetRecord.remotePort != 53))
        {
            return;
        }

        std::string domainText;
        std::uint16_t qtype = 0;
        if (!parseDnsQuestion(packetRecord, domainText, qtype))
        {
            return;
        }

        const std::string kDomainLower = toLowerAscii(domainText);
        const std::string kFlowKey = buildEndpointKey(packetRecord) + "|dns|" + kDomainLower;
        std::vector<std::string> labelList = splitDomainLabels(domainText);

        std::size_t longestLabel = 0;
        bool randomLabelFound = false;
        for (const std::string& label : labelList)
        {
            longestLabel = std::max(longestLabel, label.size());
            randomLabelFound = randomLabelFound || looksRandomDnsLabel(label);
        }

        if (hasSuffix(kDomainLower, ".onion"))
        {
            if (!shouldEmitFlowAlert(kFlowKey + "|onion", packetRecord.captureTimestampMs, kFlowAlertCooldownMs))
            {
                return;
            }
            alertList.push_back(makeBaseAlert(
                packetRecord,
                NidsAlertSeverity::kHigh,
                "DNS",
                "NIDS-DNS-ONION-QUERY",
                "DNS 查询 .onion 域名",
                "查询域名: " + domainText));
            return;
        }

        if (domainText.size() >= 90 || longestLabel >= 48 || randomLabelFound)
        {
            if (!shouldEmitFlowAlert(kFlowKey + "|anomaly", packetRecord.captureTimestampMs, kFlowAlertCooldownMs))
            {
                return;
            }

            std::ostringstream detailStream;
            detailStream << "查询域名: " << domainText
                << ", 长度=" << domainText.size()
                << ", 最长标签=" << longestLabel
                << ", qtype=" << qtype;

            alertList.push_back(makeBaseAlert(
                packetRecord,
                NidsAlertSeverity::kMedium,
                "DNS",
                "NIDS-DNS-LONG-RANDOM-DOMAIN",
                "异常 DNS 域名形态",
                detailStream.str()));
            return;
        }

        static const std::array<const char*, 5> kDynamicDnsSuffixes = {
            ".duckdns.org", ".no-ip.org", ".ddns.net", ".hopto.org", ".dynu.net"
        };
        for (const char* suffixText : kDynamicDnsSuffixes)
        {
            if (!hasSuffix(kDomainLower, suffixText))
            {
                continue;
            }
            if (!shouldEmitFlowAlert(kFlowKey + "|ddns", packetRecord.captureTimestampMs, kFlowAlertCooldownMs))
            {
                return;
            }
            alertList.push_back(makeBaseAlert(
                packetRecord,
                NidsAlertSeverity::kLow,
                "DNS",
                "NIDS-DNS-DYNAMIC-DNS",
                "动态 DNS 域名查询",
                "查询域名: " + domainText));
            return;
        }
    }

    void NidsEngine::analyzeHttpPayload(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList)
    {
        if (packetRecord.protocol != PacketTransportProtocol::kTcp ||
            packetRecord.payloadSize == 0)
        {
            return;
        }

        const std::string kPayloadText = readPayloadAscii(packetRecord, 1024);
        if (!looksLikeHttpRequest(kPayloadText))
        {
            return;
        }

        const std::string kPayloadLower = toLowerAscii(kPayloadText);
        NidsAlertSeverity severity = NidsAlertSeverity::kMedium;
        std::string matchedReason;

        static const std::array<const char*, 8> kHighRiskNeedles = {
            "powershell", "cmd.exe", "/shell", "webshell", " nc ", "bash -c", "wget ", "curl "
        };
        for (const char* needleText : kHighRiskNeedles)
        {
            if (kPayloadLower.find(needleText) != std::string::npos)
            {
                severity = NidsAlertSeverity::kHigh;
                matchedReason = needleText;
                break;
            }
        }

        if (matchedReason.empty())
        {
            static const std::array<const char*, 8> kMediumRiskNeedles = {
                "../", "%2e%2e", "/etc/passwd", "union select", "<script", "/cgi-bin/", "/wp-admin", "base64,"
            };
            for (const char* needleText : kMediumRiskNeedles)
            {
                if (kPayloadLower.find(needleText) != std::string::npos)
                {
                    matchedReason = needleText;
                    break;
                }
            }
        }

        if (matchedReason.empty())
        {
            return;
        }

        const std::string kFlowKey = buildEndpointKey(packetRecord) + "|http|" + matchedReason;
        if (!shouldEmitFlowAlert(kFlowKey, packetRecord.captureTimestampMs, kFlowAlertCooldownMs))
        {
            return;
        }

        const std::string kFirstLine = buildHttpFirstLine(kPayloadText);
        alertList.push_back(makeBaseAlert(
            packetRecord,
            severity,
            "HTTP",
            "NIDS-HTTP-SUSPICIOUS-PAYLOAD",
            "明文 HTTP 可疑载荷",
            "命中特征: " + matchedReason + ", 首行: " + kFirstLine));
    }

    void NidsEngine::analyzeSuspiciousPort(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList)
    {
        if (packetRecord.direction == PacketDirection::kUnknown)
        {
            return;
        }

        const std::uint16_t kServicePort = packetRecord.direction == PacketDirection::kInbound
            ? packetRecord.localPort
            : packetRecord.remotePort;
        std::string titleText;
        if (!buildRiskyPortTitle(kServicePort, titleText))
        {
            return;
        }

        if (packetRecord.protocol == PacketTransportProtocol::kTcp &&
            packetRecord.payloadSize == 0 &&
            !looksLikeTcpProbe(packetRecord))
        {
            return;
        }

        const std::string kFlowKey = buildEndpointKey(packetRecord) + "|risky-port|" + std::to_string(kServicePort);
        if (!shouldEmitFlowAlert(kFlowKey, packetRecord.captureTimestampMs, kFlowAlertCooldownMs))
        {
            return;
        }

        std::ostringstream detailStream;
        detailStream << buildPacketSummary(packetRecord)
            << ", 端口="
            << kServicePort
            << ", payload="
            << packetRecord.payloadSize
            << " bytes";

        alertList.push_back(makeBaseAlert(
            packetRecord,
            kServicePort == 4444 || kServicePort == 1337 || kServicePort == 31337
                ? NidsAlertSeverity::kHigh
                : NidsAlertSeverity::kMedium,
            "Port",
            "NIDS-PORT-RISKY-SERVICE",
            titleText,
            detailStream.str()));
    }

    void NidsEngine::analyzeOutboundByteBurst(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList)
    {
        if (packetRecord.direction != PacketDirection::kOutbound ||
            packetRecord.processId == 0 ||
            packetRecord.payloadSize == 0 ||
            packetRecord.captureTimestampMs == 0)
        {
            return;
        }

        const std::string kFlowKey = buildEndpointKey(packetRecord) + "|out-bytes";
        ByteWindow& window = outboundByteWindowByKey_[kFlowKey];
        appendByteWindowEvent(window, packetRecord.captureTimestampMs, packetRecord.payloadSize);
        if (window.totalBytes < kOutboundByteThreshold)
        {
            return;
        }

        if (window.lastAlertTimestampMs != 0 &&
            packetRecord.captureTimestampMs > window.lastAlertTimestampMs &&
            packetRecord.captureTimestampMs - window.lastAlertTimestampMs < kFlowAlertCooldownMs)
        {
            return;
        }
        window.lastAlertTimestampMs = packetRecord.captureTimestampMs;

        std::ostringstream detailStream;
        detailStream << buildPacketSummary(packetRecord)
            << ", "
            << kOutboundByteWindowMs / 1000
            << "s 出站累计 "
            << formatByteCount(window.totalBytes);

        alertList.push_back(makeBaseAlert(
            packetRecord,
            NidsAlertSeverity::kMedium,
            "Flow",
            "NIDS-FLOW-OUTBOUND-BYTE-BURST",
            "短时大流量出站",
            detailStream.str()));
    }

    bool NidsEngine::shouldEmitFlowAlert(
        const std::string& dedupeKey,
        const std::uint64_t nowMs,
        const std::uint64_t cooldownMs)
    {
        if (nowMs == 0)
        {
            return true;
        }

        const auto kIterator = flowAlertLastTimestampByKey_.find(dedupeKey);
        if (kIterator != flowAlertLastTimestampByKey_.end() &&
            nowMs > kIterator->second &&
            nowMs - kIterator->second < cooldownMs)
        {
            return false;
        }
        flowAlertLastTimestampByKey_[dedupeKey] = nowMs;
        return true;
    }
} // namespace ks::network

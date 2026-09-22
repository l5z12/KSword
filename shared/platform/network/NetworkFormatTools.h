#pragma once

// ============================================================
// ksword/network/network_format_tools.h
// Namespace: ks::network
// Purpose:
// - Provide UI-independent formatting and parsing helpers for network data.
// - Keep PacketRecord payload rendering, endpoint text, IPv4 ranges, and byte
//   counters reusable outside NetworkDock.
// - Expose only STL types so this layer remains free of Qt widget/string types.
// ============================================================

#include "Network.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ks::network
{
    // PayloadByteRange describes a safe readable subrange inside PacketRecord::packetBytes.
    // offset is the first payload byte and length is the number of bytes that can be read.
    struct PayloadByteRange
    {
        std::size_t offset = 0;
        std::size_t length = 0;
    };

    // formatEndpointText combines an address and port into host:port text.
    // IPv6 addresses are wrapped in brackets so the port separator stays unambiguous.
    [[nodiscard]] std::string formatEndpointText(
        const std::string& ipAddress,
        std::uint16_t portNumber);

    // formatByteCount converts a byte counter into B/KB/MB/GB/TB text.
    // The return value is stable English text suitable for tables and logs.
    [[nodiscard]] std::string formatByteCount(std::uint64_t bytesValue);

    // formatBytesPerSecond formats a transfer rate by reusing formatByteCount.
    // The input is bytes per second and the return value appends "/s".
    [[nodiscard]] std::string formatBytesPerSecond(std::uint64_t bytesPerSecond);

    // formatUnixTimestampMs converts Unix milliseconds to local timestamp text.
    // includeDate controls whether the date part is included in the returned string.
    [[nodiscard]] std::string formatUnixTimestampMs(
        std::uint64_t timestampMs,
        bool includeDate);

    // formatPercent converts a ratio/percent value into fixed decimal text.
    // decimals is clamped by implementation to a small safe range.
    [[nodiscard]] std::string formatPercent(double percentValue, int decimals = 2);

    // formatBytesToHexPreview renders a single-line hexadecimal preview.
    // At most maxBytesToRender bytes are included; truncated output includes total size.
    [[nodiscard]] std::string formatBytesToHexPreview(
        const std::vector<std::uint8_t>& byteArray,
        std::size_t maxBytesToRender);

    // buildPayloadByteRange calculates the safe payload range for a packet record.
    // It never returns a range extending past packetBytes, even when capture was truncated.
    [[nodiscard]] PayloadByteRange buildPayloadByteRange(const PacketRecord& packetRecord);

    // buildPayloadAsciiPreviewText returns a compact readable payload preview.
    // Text-like payloads keep printable segments; binary payloads fall back to dot mapping.
    [[nodiscard]] std::string buildPayloadAsciiPreviewText(
        const PacketRecord& packetRecord,
        std::size_t previewByteLimit = 180);

    // buildPayloadAsciiFullText returns the full retained payload as ASCII-ish text.
    // CR/LF/TAB are preserved and non-printable bytes are replaced by '.'.
    [[nodiscard]] std::string buildPayloadAsciiFullText(const PacketRecord& packetRecord);

    // buildPayloadHexFullText returns the full retained payload as space-separated HEX.
    // It is intended for replaying captured bytes through the manual request page.
    [[nodiscard]] std::string buildPayloadHexFullText(const PacketRecord& packetRecord);

    // buildPacketHexAsciiDumpText returns an offset + HEX + ASCII dump for retained bytes.
    // bytesPerRow defaults to the conventional 16-byte hex editor row width.
    [[nodiscard]] std::string buildPacketHexAsciiDumpText(
        const PacketRecord& packetRecord,
        std::size_t bytesPerRow = 16);

    // buildPacketCopyHeaderLine returns one metadata line for clipboard packet exports.
    // The line contains sequence, timestamp, PID, protocol, direction, endpoints, and sizes.
    [[nodiscard]] std::string buildPacketCopyHeaderLine(const PacketRecord& packetRecord);

    // formatIpv4HostOrder converts a host-order IPv4 integer into dotted decimal text.
    // The input layout is A.B.C.D as bits 31..0.
    [[nodiscard]] std::string formatIpv4HostOrder(std::uint32_t ipv4HostOrder);

    // tryParseIpv4Text parses dotted decimal IPv4 text into host-order integer output.
    // Returns false on malformed input or null output pointer.
    [[nodiscard]] bool tryParseIpv4Text(
        const std::string& ipv4Text,
        std::uint32_t* ipv4HostOrderOut);

    // tryParseIpv4RangeText parses CIDR, begin-end, or single IPv4 expressions.
    // On success it writes an inclusive range and normalized text if pointers are provided.
    [[nodiscard]] bool tryParseIpv4RangeText(
        const std::string& rangeText,
        std::pair<std::uint32_t, std::uint32_t>* rangeOut,
        std::string* normalizedTextOut = nullptr);

    // tryParsePortRangeText parses either a single port or inclusive begin-end range.
    // On success the range is normalized so first <= second.
    [[nodiscard]] bool tryParsePortRangeText(
        const std::string& rangeText,
        std::pair<std::uint16_t, std::uint16_t>* rangeOut,
        std::string* normalizedTextOut = nullptr);
} // namespace ks::network

#pragma once

// ============================================================
// NetworkDock.InternalHelpers.h
// Purpose:
// 1) Declare helper functions shared across multiple NetworkDock implementation files;
// 2) Avoid scattering utility functions across various .cpp files to ensure consistent behavior;
// 3) Reusable by the "standard .cpp split structure", replacing the original single-compilation-unit anonymous namespace.
// ============================================================

#include "NetworkDock.h"

#include <QIcon>
#include <QString>

#include <cstddef> // std::size_t: Byte length and offset calculations.
#include <cstdint> // std::uint*_t: Network fields and sequence numbers.
#include <string>  // std::string: Underlying network text bridge.
#include <utility> // std::pair: Range return value.
#include <vector>  // std::vector: Container for log bytes.

class QTableWidget;
class QTableWidgetItem;

namespace network_dock_detail
{
    // toQString:
    // - Uniformly converts UTF-8 std::string to QString.
    QString toQString(const std::string& textValue);

    // formatEndpointText:
    // - Format 'Address + Port' into a readable endpoint string;
    // - Automatically outputs IPv6 addresses in [addr]:port format.
    QString formatEndpointText(const std::string& ipAddress, std::uint16_t portNumber);

    // formatBytesToHexText:
    // - Convert the byte array to a single-line hex preview;
    // - Appends total length hint when exceeding the limit.
    QString formatBytesToHexText(
        const std::vector<std::uint8_t>& byteArray,
        std::size_t maxBytesToRender);

    // buildPayloadByteRange:
    // - Calculate the safe range of the payload within packetBytes;
    // - Returns: first=start offset, second=readable length.
    std::pair<std::size_t, std::size_t> buildPayloadByteRange(
        const ks::network::PacketRecord& packetRecord);

    // buildPayloadAsciiPreviewText:
    // - Generate the 'Content Preview' field for the traffic list.
    // - Prioritize extracting readable ASCII fragments; fall back to simplified text if unavailable.
    QString buildPayloadAsciiPreviewText(const ks::network::PacketRecord& packetRecord);

    // buildPayloadAsciiFullText:
    // - Generate full ASCII text of the payload;
    // - Non-printable bytes are replaced with '.'
    QString buildPayloadAsciiFullText(const ks::network::PacketRecord& packetRecord);

    // buildPayloadHexFullText:
    // - Generates the full hexadecimal text of the payload.
    // - For populating the HEX field when replaying captured packets to reconstruct requests.
    QString buildPayloadHexFullText(const ks::network::PacketRecord& packetRecord);

    // buildPacketHexAsciiDumpText:
    // - Generate dump text in the format "offset + HEX + ASCII";
    // - For copying and detailed viewing.
    QString buildPacketHexAsciiDumpText(const ks::network::PacketRecord& packetRecord);

    // buildPacketCopyHeaderLine:
    // - Generate the metadata header for each packet block during copy.
    QString buildPacketCopyHeaderLine(const ks::network::PacketRecord& packetRecord);

    // formatIpv4HostOrder:
    // - Convert host-order IPv4 to dotted-decimal text.
    QString formatIpv4HostOrder(std::uint32_t ipv4HostOrder);

    // tryParseIpv4Text:
    // - Parse IPv4 text and output the host-order 32-bit value.
    bool tryParseIpv4Text(const QString& ipv4Text, std::uint32_t& ipv4HostOrderOut);

    // tryParseIpv4RangeText:
    // - Parse CIDR, range, and single IP expressions;
    // - Outputs the closed interval and normalized text on success.
    bool tryParseIpv4RangeText(
        const QString& rangeText,
        std::pair<std::uint32_t, std::uint32_t>& rangeOut,
        QString& normalizeTextOut);

    // tryParsePortRangeText:
    // - Parses single port or port range expressions;
    // - Outputs the closed interval and normalized text on success.
    bool tryParsePortRangeText(
        const QString& rangeText,
        std::pair<std::uint16_t, std::uint16_t>& rangeOut,
        QString& normalizeTextOut);

    // createPacketCell:
    // - Create a unified read-only table cell.
    QTableWidgetItem* createPacketCell(const QString& cellText);

    // installCopyCurrentRowMenu:
    // - Input: tableWidget is the read-only/audit table requiring right-click copy; actionText is the menu text; processIdColumn is the explicit PID column.
    // - Processing: Install a right-click menu with explicit theme styling to write the current row to the clipboard as TSV; if a PID column exists, open process details.
    // - Returns: None. This helper does not trigger network actions; it only copies UI-visible evidence or opens details for the associated process.
    void installCopyCurrentRowMenu(
        QTableWidget* tableWidget,
        const QString& actionText = QStringLiteral("复制当前行"),
        int processIdColumn = -1);

    // populatePacketRow:
    // - Write the packet entity to the target table row using unified column definitions.
    void populatePacketRow(
        QTableWidget* tableWidget,
        int rowIndex,
        const ks::network::PacketRecord& packetRecord,
        std::uint64_t sequenceId,
        const QIcon& processIcon);

    // showPacketDetailWindow:
    // - Display packet details in a non-modal independent window and activate it.
    void showPacketDetailWindow(const ks::network::PacketRecord& packetRecord);
}

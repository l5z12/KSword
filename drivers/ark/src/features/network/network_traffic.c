/*++

Module Name:

    network_traffic.c

Abstract:

    WFP IPv4/IPv6 IP-packet inspection capture and cursor-based packet query.

Environment:

    Kernel-mode WFP callout driver

--*/

#include <ntddk.h>

// WFP packet-layer ABI exposes NET_BUFFER/NET_BUFFER_LIST.  ndis.h requires
// an explicit NDIS contract before it can provide those definitions.
#ifndef NDIS630
#define NDIS630
#endif
#include <ndis.h>

// Note: WDK WFP/NDIS headers use anonymous unions/bit-fields; disable corresponding warnings only within system header scope.
#pragma warning(push)
#pragma warning(disable:4201 4214)
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)

#include "network_internal.h"

// Note: The four runtime callout/filter slots must match the registration configuration array.
typedef enum KswordArkNetworkTrafficCalloutIndex
{
    kKswordArkTrafficInboundV4 = 0,
    kKswordArkTrafficOutboundV4 = 1,
    kKswordArkTrafficInboundV6 = 2,
    kKswordArkTrafficOutboundV6 = 3
} KswordArkNetworkTrafficCalloutIndex;

// Note: The parser accepts only TCP/UDP and explicitly iterates over these IPv6 extension headers.
#define KSWORD_ARK_IP_PROTOCOL_HOPOPTS 0U
#define KSWORD_ARK_IP_PROTOCOL_TCP 6U
#define KSWORD_ARK_IP_PROTOCOL_UDP 17U
#define KSWORD_ARK_IP_PROTOCOL_ROUTING 43U
#define KSWORD_ARK_IP_PROTOCOL_FRAGMENT 44U
#define KSWORD_ARK_IP_PROTOCOL_ESP 50U
#define KSWORD_ARK_IP_PROTOCOL_AH 51U
#define KSWORD_ARK_IP_PROTOCOL_NONE 59U
#define KSWORD_ARK_IP_PROTOCOL_DSTOPTS 60U
#define KSWORD_ARK_IP_PROTOCOL_MOBILITY 135U
#define KSWORD_ARK_IPV6_MAX_EXTENSION_HEADERS 8UL

// {D2B28BC6-9E08-4D07-9F7B-2BA821D8AA51}
// Note: The per-packet inspection filter shares the same dynamic sublayer with the existing ALE filter.
static const GUID kKswordArkWfpSublayer =
{ 0xd2b28bc6, 0x9e08, 0x4d07, { 0x9f, 0x7b, 0x2b, 0xa8, 0x21, 0xd8, 0xaa, 0x51 } };

// {8FA3AACD-4A2E-414F-9BAF-9C23F6C39904}
static const GUID kKswordArkWfpTrafficInboundV4Callout =
{ 0x8fa3aacd, 0x4a2e, 0x414f, { 0x9b, 0xaf, 0x9c, 0x23, 0xf6, 0xc3, 0x99, 0x04 } };

// {6A89CEFE-06B8-4D17-B747-2D66218CD028}
static const GUID kKswordArkWfpTrafficOutboundV4Callout =
{ 0x6a89cefe, 0x06b8, 0x4d17, { 0xb7, 0x47, 0x2d, 0x66, 0x21, 0x8c, 0xd0, 0x28 } };

// {A4DE4D86-8FB4-428B-8CA9-470BA5F37FA4}
static const GUID kKswordArkWfpTrafficInboundV6Callout =
{ 0xa4de4d86, 0x8fb4, 0x428b, { 0x8c, 0xa9, 0x47, 0x0b, 0xa5, 0xf3, 0x7f, 0xa4 } };

// {DB89C588-C0BA-44E0-B7E2-C9B0148DC0BB}
static const GUID kKswordArkWfpTrafficOutboundV6Callout =
{ 0xdb89c588, 0xc0ba, 0x44e0, { 0xb7, 0xe2, 0xc9, 0xb0, 0x14, 0x8d, 0xc0, 0xbb } };

// Built-in layer GUIDs are copied from the WDK ABI so this driver does not
// depend on the GUID-definition import library for data symbols.
static const GUID kKswordArkFwpmLayerInboundIppacketV4 =
{ 0xc86fd1bf, 0x21cd, 0x497e, { 0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58 } };
static const GUID kKswordArkFwpmLayerOutboundIppacketV4 =
{ 0x1e5c9fae, 0x8a84, 0x4135, { 0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd } };
static const GUID kKswordArkFwpmLayerInboundIppacketV6 =
{ 0xf52032cb, 0x991c, 0x46e7, { 0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca } };
static const GUID kKswordArkFwpmLayerOutboundIppacketV6 =
{ 0xa3b3ab6b, 0x3564, 0x488c, { 0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63 } };

// Note: Runtime/engine registration parameter for per-packet layer.
typedef struct KswordArkNetworkTrafficCalloutConfig
{
    const GUID* calloutKey; // CalloutKey: Stable callout GUID for this driver.
    const GUID* layerKey; // Note: LayerKey: The built-in IP packet layer GUID in BFE.
    PCWSTR calloutName; // CalloutName: BFE diagnostic name.
    PCWSTR filterName; // FilterName: BFE filter diagnostic name.
} KswordArkNetworkTrafficCalloutConfig;

// Note: Array indices align with KswordArkNetworkTrafficCalloutIndex and the runtime ID array.
static const KswordArkNetworkTrafficCalloutConfig kGKswordArkTrafficCalloutConfigs[
    KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT] =
{
    {
        &kKswordArkWfpTrafficInboundV4Callout,
        &kKswordArkFwpmLayerInboundIppacketV4,
        L"KswordARK inbound IPv4 packet callout",
        L"KswordARK inbound IPv4 packet filter"
    },
    {
        &kKswordArkWfpTrafficOutboundV4Callout,
        &kKswordArkFwpmLayerOutboundIppacketV4,
        L"KswordARK outbound IPv4 packet callout",
        L"KswordARK outbound IPv4 packet filter"
    },
    {
        &kKswordArkWfpTrafficInboundV6Callout,
        &kKswordArkFwpmLayerInboundIppacketV6,
        L"KswordARK inbound IPv6 packet callout",
        L"KswordARK inbound IPv6 packet filter"
    },
    {
        &kKswordArkWfpTrafficOutboundV6Callout,
        &kKswordArkFwpmLayerOutboundIppacketV6,
        L"KswordARK outbound IPv6 packet callout",
        L"KswordARK outbound IPv6 packet filter"
    }
};

C_ASSERT(RTL_NUMBER_OF(kGKswordArkTrafficCalloutConfigs) == KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT);
C_ASSERT(sizeof(((KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW*)0)->capturedBytes) ==
    KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);

static USHORT
kswordArkNetworkTrafficReadNetworkU16(
    _In_reads_(2) const UCHAR* bytes
    )
/*++

Routine Description:

    Read a 16-bit integer from an unaligned network byte-order buffer.

--*/
{
    // Note: Caller has verified two-byte boundary; read byte-by-byte to avoid unaligned access.
    return (USHORT)(((USHORT)bytes[0] << 8U) | (USHORT)bytes[1]);
}

static VOID
kswordArkNetworkTrafficAssignEndpoints(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* row,
    _In_reads_(addressLength) const UCHAR* sourceAddress,
    _In_reads_(addressLength) const UCHAR* destinationAddress,
    _In_ ULONG addressLength,
    _In_ USHORT sourcePort,
    _In_ USHORT destinationPort
    )
/*++

Routine Description:

    normalize IP source/destination endpoints to local/remote endpoints based on packet direction.

--*/
{
    // Note: Defend against invalid rows or address widths; prevent writes exceeding the 16-byte protocol field.
    if (row == NULL || sourceAddress == NULL || destinationAddress == NULL ||
        (addressLength != 4UL && addressLength != 16UL)) {
        // Note: Invalid input does not modify the partial row.
        return;
    }

    // Note: The source endpoint of an outbound packet belongs to the local machine.
    if (row->direction == KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND) {
        // Note: Copy local source address.
        RtlCopyMemory(row->localAddress, sourceAddress, addressLength);
        // Note: Copy the remote destination address.
        RtlCopyMemory(row->remoteAddress, destinationAddress, addressLength);
        // Note: normalize source port to local port.
        row->localPort = sourcePort;
        // Note: normalize destination port to remote port.
        row->remotePort = destinationPort;
    }
    else {
        // Note: The destination endpoint of the inbound packet belongs to the local machine.
        RtlCopyMemory(row->localAddress, destinationAddress, addressLength);
        // Note: Source endpoint is remote.
        RtlCopyMemory(row->remoteAddress, sourceAddress, addressLength);
        // Note: normalize destination port to local port.
        row->localPort = destinationPort;
        // Note: normalize source port to remote port.
        row->remotePort = sourcePort;
    }
}

static BOOLEAN
kswordArkNetworkTrafficParseTransport(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* row,
    _In_ ULONG transportOffset,
    _In_ ULONG packetLength,
    _In_ UCHAR protocol,
    _In_reads_(addressLength) const UCHAR* sourceAddress,
    _In_reads_(addressLength) const UCHAR* destinationAddress,
    _In_ ULONG addressLength
    )
/*++

Routine Description:

    Parse TCP/UDP headers, payload boundaries, and normalize endpoint direction.

--*/
{
    // Note: Use the fixed captured prefix as the boundary; never read beyond it based on the length declared by IP.
    const ULONG kCapturedLength = row != NULL ? row->capturedLength : 0UL;
    // Note: Save the transport layer source port.
    USHORT sourcePort = 0U;
    // Note: Save the transport-layer destination port.
    USHORT destinationPort = 0U;
    // Note: Save the offset of the L4 payload within the complete IP packet.
    ULONG payloadOffset = 0UL;

    // Note: All protocol parsing requires at least four bytes for source/destination ports.
    if (row == NULL || sourceAddress == NULL || destinationAddress == NULL ||
        transportOffset > kCapturedLength || kCapturedLength - transportOffset < 4UL ||
        transportOffset > packetLength) {
        // Note: Truncated packets before the transport header cannot form a reliable UI row.
        return FALSE;
    }

    // Note: Read source port in network byte order.
    sourcePort = kswordArkNetworkTrafficReadNetworkU16(&row->capturedBytes[transportOffset]);
    // Note: Read destination port in network byte order.
    destinationPort = kswordArkNetworkTrafficReadNetworkU16(&row->capturedBytes[transportOffset + 2UL]);

    // Note: TCP requires a fixed 20-byte header minimum and reading the data offset.
    if (protocol == KSWORD_ARK_IP_PROTOCOL_TCP) {
        // Note: saves the header length derived from the TCP data offset.
        ULONG tcpHeaderLength = 0UL;

        // Note: Reject incomplete fixed headers; do not fabricate payload boundaries.
        if (kCapturedLength - transportOffset < 20UL) {
            // Note: Wait for a complete subsequent packet; the current row does not enter the ring.
            return FALSE;
        }
        // Note: The high 4 bits represent the 32-bit word count, converted to bytes.
        tcpHeaderLength = (ULONG)(row->capturedBytes[transportOffset + 12UL] >> 4U) * 4UL;
        // Note: data offset must not be less than the fixed header, nor exceed the complete or captured packet.
        if (tcpHeaderLength < 20UL ||
            tcpHeaderLength > packetLength - transportOffset ||
            tcpHeaderLength > kCapturedLength - transportOffset) {
            // Note: Malformed or truncated TCP headers do not enter the trusted protocol stream.
            return FALSE;
        }
        // Note: The payload immediately follows the variable-length TCP header.
        payloadOffset = transportOffset + tcpHeaderLength;
    }
    // Note: The UDP fixed header is 8 bytes and includes an independent datagram length.
    else if (protocol == KSWORD_ARK_IP_PROTOCOL_UDP) {
        // Note: Save the UDP length field.
        ULONG udpLength = 0UL;
        // Note: Save the valid UDP length constrained by the IP total length.
        ULONG boundedUdpLength = 0UL;

        // Note: The UDP fixed header must be fully readable.
        if (kCapturedLength - transportOffset < 8UL || packetLength - transportOffset < 8UL) {
            // Note: an incomplete UDP header cannot form an endpoint record.
            return FALSE;
        }
        // Note: Read network-order UDP datagram length.
        udpLength = (ULONG)kswordArkNetworkTrafficReadNetworkU16(
            &row->capturedBytes[transportOffset + 4UL]);
        // Note: IPv4 or standard IPv6 UDP length must be at least 8 bytes for the header; 0 is reserved only for IPv6 jumbograms.
        if (udpLength != 0UL && udpLength < 8UL) {
            // Note: Malformed UDP length does not enter the ring.
            return FALSE;
        }
        // Note: For jumbograms with 0 length, fall back to the IP-layer visible length; otherwise, take the minimum of IP/UDP lengths.
        boundedUdpLength = udpLength == 0UL ?
            (packetLength - transportOffset) :
            min(udpLength, packetLength - transportOffset);
        // Note: Valid UDP range must still cover the fixed header.
        if (boundedUdpLength < 8UL) {
            // Note: Reject if boundaries are inconsistent.
            return FALSE;
        }
        // Note: payload immediately follows the fixed UDP header.
        payloadOffset = transportOffset + 8UL;
        // Note: UDP payload is limited by an independent length field, not blindly using the entire IP tail.
        row->payloadLength = boundedUdpLength - 8UL;
    }
    else {
        // Note: Traffic monitoring currently only consumes TCP/UDP to avoid forcing ICMP etc. into UI enums.
        return FALSE;
    }

    // Note: Write the stable IP protocol number.
    row->protocol = (ULONG)protocol;
    // Note: Save payload offset.
    row->payloadOffset = payloadOffset;
    // Note: TCP payload length is calculated as the IP total length minus the TCP header length; UDP length was already set above using the UDP length field.
    if (protocol == KSWORD_ARK_IP_PROTOCOL_TCP) {
        // Note: Pre-check ensures payloadOffset does not exceed PacketLength.
        row->payloadLength = packetLength - payloadOffset;
    }
    // Note: Write local/remote addresses and ports according to direction.
    kswordArkNetworkTrafficAssignEndpoints(
        row,
        sourceAddress,
        destinationAddress,
        addressLength,
        sourcePort,
        destinationPort);
    // Note: The TCP/UDP line is fully formed.
    return TRUE;
}

static BOOLEAN
kswordArkNetworkTrafficParseIpv4(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* row
    )
/*++

Routine Description:

    Parse the complete IPv4 header, fragmentation status, and TCP/UDP boundaries.

--*/
{
    // Note: Save the IPv4 IHL byte count.
    ULONG ipHeaderLength = 0UL;
    // Note: Save IPv4 total length.
    ULONG packetLength = 0UL;
    // Note: Save fragment flags/offset fields.
    USHORT fragmentField = 0U;
    // Note: Saves lower 13 bits of fragment offset.
    USHORT fragmentOffset = 0U;
    // Note: Save the IP protocol field.
    UCHAR protocol = 0U;

    // Note: IPv4 fixed header is at least 20 bytes.
    if (row == NULL || row->capturedLength < 20UL ||
        (row->capturedBytes[0] >> 4U) != 4U) {
        // Note: Reject when version or fixed header is invalid.
        return FALSE;
    }
    // Note: IHL is in units of 32-bit words; convert to bytes.
    ipHeaderLength = (ULONG)(row->capturedBytes[0] & 0x0FU) * 4UL;
    // Note: IHL must cover the fixed header and lie within the captured prefix.
    if (ipHeaderLength < 20UL || ipHeaderLength > row->capturedLength) {
        // Note: Cannot locate L4 header when the option area is incomplete.
        return FALSE;
    }
    // Note: Read IPv4 total length.
    packetLength = (ULONG)kswordArkNetworkTrafficReadNetworkU16(&row->capturedBytes[2]);
    // Note: Total length must not be less than the IP header.
    if (packetLength < ipHeaderLength) {
        // Note: Reject malformed total length.
        return FALSE;
    }
    // Note: Trim trailing bytes from the IP packet potentially attached to the NET_BUFFER.
    if (row->capturedLength > packetLength) {
        // Note: The protocol exposes only the current IP packet range to R3.
        row->capturedLength = packetLength;
    }

    // Parse IPv4 fragment fields.
    fragmentField = kswordArkNetworkTrafficReadNetworkU16(&row->capturedBytes[6]);
    // Note: The lower 13 bits represent the fragment offset in 8-byte units.
    fragmentOffset = (USHORT)(fragmentField & 0x1FFFU);
    // Note: Non-initial fragments lack a TCP/UDP header and cannot provide a reliable five-tuple.
    if (fragmentOffset != 0U) {
        // Note: Subsequent fragments are represented by the first fragment and are not written to the error port.
        return FALSE;
    }
    // Note: The MF bit indicates that the first fragment still belongs to the fragmented datagram.
    if ((fragmentField & 0x2000U) != 0U) {
        // Note: Report the first fragment semantics to R3.
        row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED;
    }

    // Note: Write IPv4 protocol attributes.
    row->addressFamily = KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4;
    // Note: IPv4 and IPv6 flags are mutually exclusive.
    row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4;
    // Note: Save complete IP total length.
    row->totalPacketLength = packetLength;
    // Note: Read the IP protocol.
    protocol = row->capturedBytes[9];
    // Note: Parse TCP/UDP headers and normalize source/destination endpoints.
    return kswordArkNetworkTrafficParseTransport(
        row,
        ipHeaderLength,
        packetLength,
        protocol,
        &row->capturedBytes[12],
        &row->capturedBytes[16],
        4UL);
}

static BOOLEAN
kswordArkNetworkTrafficParseIpv6(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* row
    )
/*++

Routine Description:

    Parse the IPv6 base header and bounded extension header chain to locate the TCP/UDP header.

--*/
{
    // Note: IPv6 base header is fixed at 40 bytes.
    const ULONG kBaseHeaderLength = 40UL;
    // Note: Save the IPv6 payload length.
    ULONG ipv6PayloadLength = 0UL;
    // Note: Save the complete packet length.
    ULONG packetLength = 0UL;
    // Note: Save the current next-header value.
    UCHAR nextHeader = 0U;
    // Note: Save the current extension header/L4 offset.
    ULONG transportOffset = kBaseHeaderLength;
    // Note: Limit extension header traversal count to prevent malformed chains from exhausting classify time.
    ULONG extensionCount = 0UL;

    // Note: IPv6 base header must be complete and have version 6.
    if (row == NULL || row->capturedLength < kBaseHeaderLength ||
        (row->capturedBytes[0] >> 4U) != 6U) {
        // Note: Reject when base header is invalid.
        return FALSE;
    }
    // Note: Read network-order payload length.
    ipv6PayloadLength = (ULONG)kswordArkNetworkTrafficReadNetworkU16(&row->capturedBytes[4]);
    // Note: Standard IPv6 packet total length is fixed header plus payload; 0-length jumbogram falls back to NET_BUFFER visible length.
    packetLength = ipv6PayloadLength == 0UL ?
        row->totalPacketLength :
        kBaseHeaderLength + ipv6PayloadLength;
    // Note: The fixed header must reside within the declared complete packet.
    if (packetLength < kBaseHeaderLength) {
        // Note: Reject on integer/protocol boundary anomalies.
        return FALSE;
    }
    // Note: Trim trailing bytes from the IP packet potentially attached to the NET_BUFFER.
    if (row->capturedLength > packetLength) {
        // Note: Retain only the current IPv6 packet range.
        row->capturedLength = packetLength;
    }
    // Note: The 6th byte of the base header is the next header.
    nextHeader = row->capturedBytes[6];

    // Note: Skip allowed extension headers one by one until TCP/UDP is reached or an unsupported protocol is explicitly identified.
    while (nextHeader != KSWORD_ARK_IP_PROTOCOL_TCP &&
        nextHeader != KSWORD_ARK_IP_PROTOCOL_UDP) {
        // Note: Limit extension header count and read boundaries.
        if (extensionCount >= KSWORD_ARK_IPV6_MAX_EXTENSION_HEADERS ||
            transportOffset >= row->capturedLength ||
            transportOffset >= packetLength) {
            // Note: Do not enter the ring for excessively deep or truncated extension chains.
            return FALSE;
        }

        // Note: Hop-by-Hop, Routing, Destination, and Mobility use 8-byte unit lengths.
        if (nextHeader == KSWORD_ARK_IP_PROTOCOL_HOPOPTS ||
            nextHeader == KSWORD_ARK_IP_PROTOCOL_ROUTING ||
            nextHeader == KSWORD_ARK_IP_PROTOCOL_DSTOPTS ||
            nextHeader == KSWORD_ARK_IP_PROTOCOL_MOBILITY) {
            // Note: The first two bytes of the extension header must be readable.
            ULONG extensionLength = 0UL;
            // Note: Check next-header and hdr-ext-len bytes.
            if (row->capturedLength - transportOffset < 2UL ||
                packetLength - transportOffset < 2UL) {
                // Note: Reject truncated extension headers.
                return FALSE;
            }
            // Note: Save the next protocol number.
            nextHeader = row->capturedBytes[transportOffset];
            // Note: Hdr Ext Len excludes the first 8-byte block.
            extensionLength = ((ULONG)row->capturedBytes[transportOffset + 1UL] + 1UL) * 8UL;
            // Note: The extension header must be fully contained within the declared packet length and captured prefix.
            if (extensionLength < 8UL ||
                extensionLength > packetLength - transportOffset ||
                extensionLength > row->capturedLength - transportOffset) {
                // Reject malformed extension length.
                return FALSE;
            }
            // Note: Advance to the next header.
            transportOffset += extensionLength;
        }
        // Note: Fragment header is fixed at 8 bytes.
        else if (nextHeader == KSWORD_ARK_IP_PROTOCOL_FRAGMENT) {
            // Note: Save fragment offset/flags fields.
            USHORT fragmentField = 0U;
            // Note: The complete fragment header must be readable.
            if (row->capturedLength - transportOffset < 8UL ||
                packetLength - transportOffset < 8UL) {
                // Note: Reject truncated fragment header.
                return FALSE;
            }
            // Note: Read the next protocol number.
            nextHeader = row->capturedBytes[transportOffset];
            // Note: Reads network fragment offset/flags in network order.
            fragmentField = kswordArkNetworkTrafficReadNetworkU16(
                &row->capturedBytes[transportOffset + 2UL]);
            // Note: The high 13 bits contain the offset; non-first fragments have no transport layer port.
            if ((fragmentField & 0xFFF8U) != 0U) {
                // Note: Subsequent fragments do not spoof ports.
                return FALSE;
            }
            // Note: Explicitly mark the first fragment of all packets containing a fragment header.
            row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED;
            // Note: Skip fixed fragment header.
            transportOffset += 8UL;
        }
        // Note: Authentication Header uses a 32-bit unit length plus two additional units.
        else if (nextHeader == KSWORD_ARK_IP_PROTOCOL_AH) {
            // Note: Save the total AH length.
            ULONG authenticationHeaderLength = 0UL;
            // Note: The first two bytes of AH must be readable.
            if (row->capturedLength - transportOffset < 2UL ||
                packetLength - transportOffset < 2UL) {
                // Note: Truncate AH rejection.
                return FALSE;
            }
            // Note: Save the next header protocol after AH.
            nextHeader = row->capturedBytes[transportOffset];
            // Note: Payload length is in 32-bit units and subtracts 2.
            authenticationHeaderLength =
                ((ULONG)row->capturedBytes[transportOffset + 1UL] + 2UL) * 4UL;
            // Note: AH must be at least 8 bytes and fully contained within the boundaries.
            if (authenticationHeaderLength < 8UL ||
                authenticationHeaderLength > packetLength - transportOffset ||
                authenticationHeaderLength > row->capturedLength - transportOffset) {
                // Note: Reject malformed AH length.
                return FALSE;
            }
            // Note: Advance to the next header.
            transportOffset += authenticationHeaderLength;
        }
        else {
            // Note: ESP, No Next Header, and other unknown protocols cannot safely locate plaintext TCP/UDP.
            // Note: Unknown protocols are not included in the current TCP/UDP monitoring model.
            return FALSE;
        }
        // Note: Record one extension header advancement.
        extensionCount += 1UL;
    }

    // Note: Write IPv6 protocol attributes.
    row->addressFamily = KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
    // Note: IPv4 and IPv6 flags are mutually exclusive.
    row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6;
    // Note: Saves full IPv6 packet length.
    row->totalPacketLength = packetLength;
    // Note: Source and destination addresses in the base header are located at offsets 8 and 24, respectively.
    return kswordArkNetworkTrafficParseTransport(
        row,
        transportOffset,
        packetLength,
        nextHeader,
        &row->capturedBytes[8],
        &row->capturedBytes[24],
        16UL);
}

static BOOLEAN
kswordArkNetworkTrafficParsePacket(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* row
    )
/*++

Routine Description:

    Dispatch parsing based on IP version and uniformly set the truncation flag.

--*/
{
    // Note: Save the specific IPv4/IPv6 parsing result.
    BOOLEAN parsed = FALSE;
    // Note: At least one version byte is required.
    if (row == NULL || row->capturedLength == 0UL) {
        // Note: Empty packets do not enter the ring.
        return FALSE;
    }

    // Note: High-order nibble selects IPv4/IPv6 parser.
    if ((row->capturedBytes[0] >> 4U) == 4U) {
        // Note: Parse IPv4.
        parsed = kswordArkNetworkTrafficParseIpv4(row);
    }
    else if ((row->capturedBytes[0] >> 4U) == 6U) {
        // Note: Parse IPv6.
        parsed = kswordArkNetworkTrafficParseIpv6(row);
    }
    // Note: Do not expose partial results on parse failure.
    if (!parsed) {
        // Note: The caller abandons the current NET_BUFFER.
        return FALSE;
    }
    // Note: Explicitly mark truncation when the captured prefix is shorter than the full IP packet.
    if (row->capturedLength < row->totalPacketLength) {
        // Note: The R3 detail page can use this to prompt that only the prefix is saved.
        row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED;
    }
    // Note: Complete TCP/UDP lines can be written to the ring.
    return TRUE;
}

static VOID
kswordArkNetworkTrafficRecordPacket(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* packetRow,
    _In_ ULONG captureGeneration
    )
/*++

Routine Description:

    Write parsed per-packet records to a fixed non-paged ring.

--*/
{
    // Note: Get static network runtime.
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    // Note: Save the IRQL before acquiring the per-packet spinlock.
    KIRQL oldIrql = PASSIVE_LEVEL;
    // Note: Save the current write slot.
    ULONG writeIndex = 0UL;

    // Note: Do not write if runtime or row is null.
    if (runtime == NULL || packetRow == NULL) {
        // Note: Does not affect WFP allow/deny decision.
        return;
    }
    if (InterlockedCompareExchange(
            &runtime->trafficCaptureEnabled,
            0L,
            0L) == 0L ||
        (ULONG)InterlockedCompareExchange(
            &runtime->trafficCaptureGeneration,
            0L,
            0L) != captureGeneration) {
        // Note: Do not enter the per-packet ring critical section after UI has stopped.
        return;
    }

    // Note: The spin lock covers the sequence number, overwrite count, and complete single-slot copy.
    KeAcquireSpinLock(&runtime->trafficLock, &oldIrql);
    if (InterlockedCompareExchange(
            &runtime->trafficCaptureEnabled,
            0L,
            0L) == 0L ||
        (ULONG)InterlockedCompareExchange(
            &runtime->trafficCaptureGeneration,
            0L,
            0L) != captureGeneration) {
        // Note: Serialized with disable control to prevent late writes that bypass outer checks.
        KeReleaseSpinLock(&runtime->trafficLock, oldIrql);
        return;
    }
    // Note: Read the next write slot.
    writeIndex = runtime->trafficWriteIndex;
    // Note: Allocate strictly increasing sequence number within the lock.
    packetRow->sequence = runtime->nextTrafficSequence;
    // Note: Advance to next sequence number.
    runtime->nextTrafficSequence += 1ULL;
    // Note: Full fixed-row copy ensures the reader never sees partially written data.
    RtlCopyMemory(&runtime->trafficRing[writeIndex], packetRow, sizeof(*packetRow));
    // Advance and wrap the write pointer.
    runtime->trafficWriteIndex =
        (writeIndex + 1UL) % KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
    // Note: Increment the valid row count when the ring is not full.
    if (runtime->trafficCount < KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY) {
        // Note: Occupy a previously unused slot.
        runtime->trafficCount += 1UL;
    }
    else {
        // Note: Overwrite the oldest packet when the ring is full and increment the dropped count.
        runtime->droppedTrafficCount += 1ULL;
    }
    // Note: IRQL is restored only after per-packet ring metadata and rows are fully processed.
    KeReleaseSpinLock(&runtime->trafficLock, oldIrql);
}

static ULONG
kswordArkNetworkTrafficReadProcessId(
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0* metadata
    )
/*++

Routine Description:

    Attempt to read WFP metadata PID; returns 0 if missing at the IP packet layer, to be filled in by the R3 connection table.

--*/
{
    // Note: Metadata and the PROCESS_ID capability bit must exist.
    if (metadata == NULL ||
        (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0U ||
        metadata->processId > MAXULONG) {
        // Note: Maintain an unknown PID when missing or exceeding the shared protocol width.
        return 0UL;
    }
    // Note: Boundaries are verified; safely narrow to a shared 32-bit PID.
    return (ULONG)metadata->processId;
}

static VOID
kswordArkNetworkTrafficCaptureNetBuffer(
    _Inout_ NET_BUFFER* netBuffer,
    _In_ BOOLEAN inbound,
    _In_ ULONG direction,
    _In_ ULONG ipHeaderSize,
    _In_ ULONG processId,
    _In_ ULONG captureGeneration
    )
/*++

Routine Description:

    Copy a limited packet prefix from a single NET_BUFFER without allocation, restore the data offset, parse, and write to the ring.

--*/
{
    // Note: Construct a complete fixed row on the stack and perform all parsing before entering the spin lock.
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW packetRow = { 0 };
    // Note: Save current visible length of NET_BUFFER.
    ULONG dataLength = 0UL;
    // Note: Save the maximum prefix length to copy this time.
    ULONG captureLength = 0UL;
    // Note: Save the contiguous address returned by NdisGetDataBuffer.
    UCHAR* contiguousBytes = NULL;
    // Note: Record whether the inbound path successfully retreated to the IP header.
    BOOLEAN retreated = FALSE;
    // Note: Save the system time.
    LARGE_INTEGER systemTime = { 0 };

    // Note: Do not access a null NET_BUFFER.
    if (netBuffer == NULL) {
        // Note: Does not affect other packets.
        return;
    }

    // Note: Inbound IPPACKET data offset is within the transport header; ipHeaderSize must be temporarily rolled back.
    if (inbound) {
        // Note: Metadata must provide a non-zero IP header length.
        if (ipHeaderSize == 0UL) {
            // Note: Do not forge per-packet data when unable to restore the complete IP packet.
            return;
        }
        // Note: Do not allocate a new MDL; only retreat within the same NET_BUFFER to preserve the IP header.
        if (NdisRetreatNetBufferDataStart(netBuffer, ipHeaderSize, 0UL, NULL) != NDIS_STATUS_SUCCESS) {
            // Note: On rollback failure, preserve the original data offset and discard the current packet.
            return;
        }
        // Note: All subsequent exit paths must restore this offset.
        retreated = TRUE;
    }

    // Note: Read the full visible IP packet length after fallback.
    dataLength = NET_BUFFER_DATA_LENGTH(netBuffer);
    // Note: Empty packets do not require calling NdisGetDataBuffer.
    if (dataLength != 0UL) {
        // Note: Fixed prefix limit to avoid large copies and non-paged memory bloat in the classify hot path.
        captureLength = min(dataLength, KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);
        // Note: If the MDL is non-contiguous, NDIS copies to the fixed buffer in packetRow.
        contiguousBytes = (UCHAR*)NdisGetDataBuffer(
            netBuffer,
            captureLength,
            packetRow.capturedBytes,
            1UL,
            0UL);
        // Note: The contiguous pointer may directly point to the original MDL; explicitly copy to the stable row.
        if (contiguousBytes != NULL && contiguousBytes != packetRow.capturedBytes) {
            // Note: The copy length is already constrained by the fixed array limit.
            RtlCopyMemory(packetRow.capturedBytes, contiguousBytes, captureLength);
        }
    }

    // Note: Restore the inbound NET_BUFFER data offset before any parsing to avoid affecting subsequent WFP callouts.
    if (retreated) {
        // Note: The rollback amount must exactly match the IpHeaderSize above.
        NdisAdvanceNetBufferDataStart(netBuffer, ipHeaderSize, FALSE, NULL);
    }

    // Note: Drop the current packet when NDIS cannot form a contiguous prefix.
    if (contiguousBytes == NULL || captureLength == 0UL) {
        // Note: Offset has been restored; safe to return.
        return;
    }

    // Note: Write the stable per-packet ABI base fields.
    packetRow.version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    // Note: Write the current fixed row size.
    packetRow.size = sizeof(packetRow);
    // Note: Sequence numbers are allocated within the ring spinlock.
    packetRow.sequence = 0ULL;
    // Note: Read system time in 100ns units starting from 1601 UTC.
    KeQuerySystemTime(&systemTime);
    // Note: Save the capture timestamp.
    packetRow.timestamp100ns = (ULONG64)systemTime.QuadPart;
    // Note: Save the IPPACKET layer direction.
    packetRow.direction = direction;
    // Note: Save the metadata PID; it is 0 if missing.
    packetRow.processId = processId;
    // Note: Save the actual copied prefix length; the parser may further narrow it based on IP total length.
    packetRow.capturedLength = captureLength;
    // Note: Save the total visible length of the NET_BUFFER first; this value is used when the IPv6 jumbogram payload length is 0.
    packetRow.totalPacketLength = dataLength;

    // Note: Only write fully parseable TCP/UDP IPv4/IPv6 packets to the ring.
    if (kswordArkNetworkTrafficParsePacket(&packetRow)) {
        // Note: Enter short spinlock write after successful parsing.
        kswordArkNetworkTrafficRecordPacket(
            &packetRow,
            captureGeneration);
    }
}

static VOID NTAPI
kswordArkNetworkTrafficClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const FWPS_FILTER0* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut
    )
/*++

Routine Description:

    Observational IPPACKET classification: copy the NET_BUFFER prefix one by one and always return CONTINUE.

--*/
{
    // Note: Save the traffic direction derived from the layer.
    ULONG direction = 0UL;
    // Mark inbound layer requiring data offset rollback.
    BOOLEAN inbound = FALSE;
    // Note: Save the metadata IP header length.
    ULONG ipHeaderSize = 0UL;
    // Note: Save the metadata PID, typically completed by the R3 connection table.
    ULONG processId = 0UL;
    // Note: Iterate over potentially linked NBLs.
    NET_BUFFER_LIST* netBufferList = NULL;
    // Note: The packet data plane is explicitly started and stopped by R3; the filter itself remains resident.
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    // Note: Carry the enabled generation to the final write point to reject late packets crossing stop/start boundaries.
    ULONG captureGeneration = 0UL;
    ULONG confirmedGeneration = 0UL;

    // Note: The inspection callout does not read the filter or flow context, nor does it modify or absorb packets.
    UNREFERENCED_PARAMETER(filter);
    // Note: This implementation does not associate with the flow context.
    UNREFERENCED_PARAMETER(flowContext);

    // Note: Explicitly return non-terminating CONTINUE when ACTION_WRITE is held to preserve other WFP policies.
    if (classifyOut != NULL &&
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0U) {
        // Note: Observational callouts never permit/block/absorb.
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (runtime == NULL) {
        // Note: In the stopped state, only maintain the WFP allow semantics; do not parse or copy NET_BUFFER.
        return;
    }
    do {
        captureGeneration = (ULONG)InterlockedCompareExchange(
            &runtime->trafficCaptureGeneration,
            0L,
            0L);
        if (InterlockedCompareExchange(
                &runtime->trafficCaptureEnabled,
                0L,
                0L) == 0L) {
            // Note: In the stopped state, only maintain the WFP allow semantics; do not parse or copy NET_BUFFER.
            return;
        }
        confirmedGeneration = (ULONG)InterlockedCompareExchange(
            &runtime->trafficCaptureGeneration,
            0L,
            0L);
    } while (captureGeneration != confirmedGeneration);

    // Note: Both layer fields and packet data must exist.
    if (inFixedValues == NULL || layerData == NULL) {
        // Note: When data is missing, only CONTINUE is maintained.
        return;
    }

    // Note: Inbound IPv4/IPv6 layers must back up from the transport header to the IP header.
    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4 ||
        inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6) {
        // normalize to inbound direction.
        direction = KSWORD_ARK_NETWORK_DIRECTION_INBOUND;
        // Note: Enable fallback path.
        inbound = TRUE;
    }
    // Note: For outbound IPv4/IPv6 layers, the data offset is already within the IP header.
    else if (inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 ||
        inFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6) {
        // Note: normalize to outbound direction.
        direction = KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND;
    }
    else {
        // Note: Unknown layers do not attempt to interpret LayerData.
        return;
    }

    // Note: For inbound traffic, the actual IPv4 options/IPv6 header chain prefix length provided by WFP must be read.
    if (inbound && inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) != 0U) {
        // Note: Save the rollback amount.
        ipHeaderSize = inMetaValues->ipHeaderSize;
    }
    // Note: Read PID when available; otherwise, R3 resolves via endpoint table.
    processId = kswordArkNetworkTrafficReadProcessId(inMetaValues);

    // Note: LayerData is a NET_BUFFER_LIST at the IPPACKET layer.
    netBufferList = (NET_BUFFER_LIST*)layerData;
    // Note: Traverse the NBL chain to ensure every packet in the coalesced/batch path is observed.
    while (netBufferList != NULL) {
        // Note: Iterate over all NET_BUFFER entries in the current NBL.
        NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
        // Note: Copy and parse each NET_BUFFER individually.
        while (netBuffer != NULL) {
            // Note: This function does not allocate memory and does not hold locks for long periods.
            kswordArkNetworkTrafficCaptureNetBuffer(
                netBuffer,
                inbound,
                direction,
                ipHeaderSize,
                processId,
                captureGeneration);
            // Note: Advance the NET_BUFFER chain within the current NBL.
            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
        // Note: Advance the NBL chain.
        netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList);
    }
}

static NTSTATUS NTAPI
kswordArkNetworkTrafficNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER0* filter
    )
/*++

Routine Description:

    Accept per-packet callout filter lifecycle notifications; no additional context is maintained.

--*/
{
    // Note: Do not distinguish between add/delete notifications.
    UNREFERENCED_PARAMETER(notifyType);
    // Note: The filter key is not involved in per-packet ring processing.
    UNREFERENCED_PARAMETER(filterKey);
    // Note: The filter object does not store custom context.
    UNREFERENCED_PARAMETER(filter);
    // Note: Accept notification.
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkNetworkTrafficRegisterRuntimeCallouts(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Register four runtime callouts for IPv4/IPv6 inbound/outbound IPPACKET layers.

--*/
{
    // Note: Save the callout configuration index.
    ULONG index = 0UL;
    // Note: Save the current registration status.
    NTSTATUS status = STATUS_SUCCESS;

    // Note: Runtime and device object must be valid.
    if (runtime == NULL || runtime->deviceObject == NULL) {
        // Note: FwpsCalloutRegister0 requires a device object.
        return STATUS_INVALID_PARAMETER;
    }

    // Note: Register in stable array order; roll back all registered items uniformly on failure.
    for (index = 0UL; index < KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT; ++index) {
        // Note: Construct an official FWPS_CALLOUT0.
        FWPS_CALLOUT0 callout = { 0 };
        // Note: Write the current stable GUID.
        callout.calloutKey = *kGKswordArkTrafficCalloutConfigs[index].calloutKey;
        // Note: Layer 4 reuses the same observation classify, distinguishing direction via layerId.
        callout.classifyFn = kswordArkNetworkTrafficClassifyFn;
        // Note: Uses stateless notify.
        callout.notifyFn = kswordArkNetworkTrafficNotifyFn;
        // Note: Since no flow context is associated, flowDeleteFn is not required.
        callout.flowDeleteFn = NULL;
        // Note: Register runtime callout and save the ID.
        status = FwpsCalloutRegister0(
            runtime->deviceObject,
            &callout,
            &runtime->trafficCalloutIds[index]);
        // Note: Terminate subsequent registration on failure.
        if (!NT_SUCCESS(status)) {
            // Note: Save the per-packet capability failure status.
            runtime->trafficCaptureStatus = status;
            // Note: Unregister previously successful runtime callouts.
            kswordArkNetworkTrafficUnregisterRuntimeCallouts(runtime);
            // Note: Return the precise error to the parent registration transaction.
            return status;
        }
    }

    // Note: The runtime callout phase succeeded; the engine/filter phase will continue shortly.
    runtime->trafficCaptureStatus = STATUS_SUCCESS;
    // Note: Return success.
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkNetworkTrafficAddEngineObjects(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Add four callout objects and an observation-type inspection filter within the parent BFE transaction.

--*/
{
    // Note: Save the configuration index.
    ULONG index = 0UL;
    // Note: Save the current BFE operation status.
    NTSTATUS status = STATUS_SUCCESS;

    // Note: The parent must have opened the dynamic engine.
    if (runtime == NULL || runtime->engineHandle == NULL) {
        // Note: Cannot add a management object without an engine.
        return STATUS_INVALID_PARAMETER;
    }

    // Note: Add all callout objects first for subsequent filter references.
    for (index = 0UL; index < KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT; ++index) {
        // Note: Construct an official FWPM_CALLOUT0.
        FWPM_CALLOUT0 callout = { 0 };
        // Note: Set a stable callout GUID.
        callout.calloutKey = *kGKswordArkTrafficCalloutConfigs[index].calloutKey;
        // Note: Set diagnostic name.
        callout.displayData.name = (PWSTR)kGKswordArkTrafficCalloutConfigs[index].calloutName;
        // Note: Bind the built-in IPv4/IPv6 IPPACKET layer.
        callout.applicableLayer = *kGKswordArkTrafficCalloutConfigs[index].layerKey;
        // Note: Add callout within the parent transaction.
        status = FwpmCalloutAdd0(runtime->engineHandle, &callout, NULL, NULL);
        // Note: On failure, let the parent transaction handle the abort uniformly.
        if (!NT_SUCCESS(status)) {
            // Note: Save the exact failure status.
            runtime->trafficCaptureStatus = status;
            // Note: Return failure.
            return status;
        }
    }

    // Note: Then add an inspection filter matching all traffic for each callout.
    for (index = 0UL; index < KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT; ++index) {
        // Note: Construct official FWPM_FILTER0.
        FWPM_FILTER0 filter = { 0 };
        // Note: Bind to the current IPPACKET layer.
        filter.layerKey = *kGKswordArkTrafficCalloutConfigs[index].layerKey;
        // Note: Set diagnostic name.
        filter.displayData.name = (PWSTR)kGKswordArkTrafficCalloutConfigs[index].filterName;
        // Note: Reuse the existing KswordARK dynamic sublayer.
        filter.subLayerKey = kKswordArkWfpSublayer;
        // Note: An empty weight allows BFE to select a standard weight within the sublayer.
        filter.weight.type = FWP_EMPTY;
        // Note: inspection action is non-terminating observation and does not override firewall decisions.
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        // Note: Associate the current callout GUID.
        filter.action.calloutKey = *kGKswordArkTrafficCalloutConfigs[index].calloutKey;
        // Note: Match all packets at this layer without conditions.
        filter.numFilterConditions = 0U;
        // Note: Unconditional array.
        filter.filterCondition = NULL;
        // Note: Add the filter and save the ID for explicit unloading.
        status = FwpmFilterAdd0(
            runtime->engineHandle,
            &filter,
            NULL,
            &runtime->trafficFilterIds[index]);
        // Note: On failure, roll back all objects in the parent transaction.
        if (!NT_SUCCESS(status)) {
            // Note: Save the exact failure status.
            runtime->trafficCaptureStatus = status;
            // Note: Return failure.
            return status;
        }
    }

    // Note: Both callout and filter are added to the current transaction.
    runtime->trafficCaptureStatus = STATUS_SUCCESS;
    // Note: Return success.
    return STATUS_SUCCESS;
}

VOID
kswordArkNetworkTrafficDeleteEngineObjects(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Remove per-packet filter/callout objects from the opened engine and clear their IDs.

--*/
{
    // Note: Save the reverse cleanup index.
    LONG index = 0;

    // Note: When no engine is present, only clear filter IDs that may originate from aborted transactions.
    if (runtime == NULL) {
        // Note: Cannot proceed with a null runtime.
        return;
    }

    // Note: Delete the filter first to avoid it still referencing the callout.
    for (index = (LONG)KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT - 1; index >= 0; --index) {
        // Note: Only delete filters that have obtained a non-zero ID.
        if (runtime->engineHandle != NULL && runtime->trafficFilterIds[index] != 0ULL) {
            // Note: Ignore cleanup errors and continue releasing other objects.
            (VOID)FwpmFilterDeleteById0(
                runtime->engineHandle,
                runtime->trafficFilterIds[index]);
        }
        // Note: Clear the local ID regardless of whether BFE was removed with the transaction.
        runtime->trafficFilterIds[index] = 0ULL;
    }

    // Note: Delete engine callout objects in reverse order.
    if (runtime->engineHandle != NULL) {
        // Note: Iterate through all stable callout GUIDs.
        for (index = (LONG)KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT - 1; index >= 0; --index) {
            // Note: Dynamic sessions may have already cleared the object; deletion errors can be ignored.
            (VOID)FwpmCalloutDeleteByKey0(
                runtime->engineHandle,
                kGKswordArkTrafficCalloutConfigs[index].calloutKey);
        }
    }
}

VOID
kswordArkNetworkTrafficUnregisterRuntimeCallouts(
    _Inout_ KswordArkNetworkRuntime* runtime
    )
/*++

Routine Description:

    Unregister the four runtime callouts to support partial initialization and repeated cleanup.

--*/
{
    // Note: Save the reverse cleanup index.
    LONG index = 0;

    // Note: No cleanup needed for a null runtime.
    if (runtime == NULL) {
        // Note: Return directly.
        return;
    }

    // Note: Unregister registered runtime callouts in reverse order.
    for (index = (LONG)KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT - 1; index >= 0; --index) {
        // Note: 0 indicates the slot is unregistered or cleared.
        if (runtime->trafficCalloutIds[index] != 0U) {
            // Note: Ignore single unregistration errors and continue to avoid leaving other callouts behind.
            (VOID)FwpsCalloutUnregisterById0(runtime->trafficCalloutIds[index]);
            // Note: Zero the local runtime ID.
            runtime->trafficCalloutIds[index] = 0U;
        }
    }
    // Note: Per-packet capability flag is retained only when all objects are successfully submitted.
    runtime->runtimeFlags &= ~KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED;
}

NTSTATUS
kswordArkNetworkQueryTrafficPackets(
    _In_ const KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Read fixed IPv4/IPv6 per-packet ring incrementally based on afterSequence.

--*/
{
    // Note: The variable-length response header does not include a placeholder row for entries[1].
    const size_t kResponseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
    // Note: Retrieve the fixed non-paged runtime.
    KswordArkNetworkRuntime* runtime = kswordArkNetworkGetRuntime();
    // Note: Output buffer interpreted as a versioned response.
    KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE* response = NULL;
    // Note: Save the normalized row budget.
    ULONG maxRows = 0UL;
    // Note: Save the output row capacity.
    ULONG outputRowCapacity = 0UL;
    // Note: Calculate capacity using size_t before narrowing.
    size_t outputRowCapacitySize = 0U;
    // Note: Saves valid ring buffer row count.
    ULONG packetCount = 0UL;
    // Note: Save the oldest slot index.
    ULONG oldestIndex = 0UL;
    // Note: Save the number of available rows after the cursor.
    ULONG availableCount = 0UL;
    // Note: Save the actual returned row count.
    ULONG returnedCount = 0UL;
    // Note: Save the maximum number of rows to copy this time.
    ULONG targetReturnCount = 0UL;
    // Note: Preserve ring metadata re-read during line-by-line copy.
    ULONG currentPacketCount = 0UL;
    ULONG currentOldestIndex = 0UL;
    // Note: Save the effective cursor after driver reload.
    ULONG64 effectiveAfterSequence = 0ULL;
    // Note: Save the next stable sequence number to be copied.
    ULONG64 desiredSequence = 0ULL;
    ULONG64 currentOldestSequence = 0ULL;
    ULONG64 currentNewestSequence = 0ULL;
    // Note: Save the IRQL before acquiring the per-packet spinlock.
    KIRQL oldIrql = PASSIVE_LEVEL;

    // Note: All required parameters must be present.
    if (request == NULL || outputBuffer == NULL || bytesWrittenOut == NULL || runtime == NULL) {
        // Note: Unable to form response.
        return STATUS_INVALID_PARAMETER;
    }
    // Note: No output by default on failure path.
    *bytesWrittenOut = 0U;
    // Note: Output must accommodate at least the no-row response header.
    if (outputBufferLength < kResponseHeaderSize) {
        // Note: Let WDF return a clear buffer too small status.
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Note: Only zero the fixed header; actual returned rows will be fully overwritten.
    RtlZeroMemory(outputBuffer, kResponseHeaderSize);
    // Note: Bind response header.
    response = (KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE*)outputBuffer;
    // Note: Write the per-packet sub-protocol version.
    response->version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    // Note: Write fixed-row ABI size.
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
    // Note: Expose the fixed ring capacity.
    response->capacity = KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
    // Note: Report availability only after all four packet filters have been submitted.
    response->status =
        ((runtime->runtimeFlags & KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED) == 0UL) ?
        KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE :
        (InterlockedCompareExchange(
                &runtime->trafficCaptureEnabled,
                0L,
                0L) != 0L ?
            KSWORD_ARK_NETWORK_STATUS_APPLIED :
            KSWORD_ARK_NETWORK_STATUS_DISABLED);
    // Note: Return per-packet registered status when unavailable.
    response->lastStatus =
        (response->status == KSWORD_ARK_NETWORK_STATUS_APPLIED ||
            response->status == KSWORD_ARK_NETWORK_STATUS_DISABLED) ?
        STATUS_SUCCESS :
        runtime->trafficCaptureStatus;

    // Note: v1 uses exact request size, zero flags, and zero reserved fields.
    if (request->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->flags != KSWORD_ARK_NETWORK_TRAFFIC_QUERY_FLAG_NONE ||
        request->reserved != 0ULL) {
        // Note: Protocol errors are expressed via a fixed response; DeviceIoControl transmission still succeeds.
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        // Note: Distinguish version mismatch from other invalid fields.
        response->lastStatus =
            request->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ?
            STATUS_REVISION_MISMATCH :
            STATUS_INVALID_PARAMETER;
        // Note: Error response contains only the header.
        response->size = (ULONG)kResponseHeaderSize;
        // Note: Report fixed header length.
        *bytesWrittenOut = kResponseHeaderSize;
        // Note: Transfer succeeded; semantic errors are in the response.
        return STATUS_SUCCESS;
    }

    // Note: maxRows=0 uses a conservative default budget.
    maxRows = request->maxRows == 0UL ?
        KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS :
        request->maxRows;
    // Note: Clamp the amount copied while holding the lock.
    if (maxRows > KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS) {
        // Note: Use the stable protocol upper limit.
        maxRows = KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS;
    }
    // Note: Calculate output row capacity via division to avoid multiplication-addition overflow.
    outputRowCapacitySize = (outputBufferLength - kResponseHeaderSize) /
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
    // Note: Output capacity must not exceed request budget.
    if (outputRowCapacitySize > (size_t)maxRows) {
        // Note: Narrow to budget.
        outputRowCapacitySize = (size_t)maxRows;
    }
    // Note: maxRows is below the ULONG limit, narrowing the safety margin.
    outputRowCapacity = (ULONG)outputRowCapacitySize;
    // Note: If no return line exists, reuse the request cursor.
    response->nextSequence = request->afterSequence;
    // Note: Prepare to handle the driver reload cursor.
    effectiveAfterSequence = request->afterSequence;

    // Note: Snapshot ring metadata only within the lock; no longer bulk-copy up to 256 large rows.
    KeAcquireSpinLock(&runtime->trafficLock, &oldIrql);
    // Note: Capture the current valid row count.
    packetCount = runtime->trafficCount;
    // Note: Capture cumulative overwrite count.
    response->droppedPacketCount = runtime->droppedTrafficCount;
    // Note: Sequence numbers exist only for non-empty rings.
    if (packetCount != 0UL) {
        // Note: Subtracting the write pointer from the ring capacity yields the oldest valid slot.
        oldestIndex =
            (runtime->trafficWriteIndex +
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                packetCount) %
            KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
        // Note: Report the oldest sequence number that is still recoverable.
        response->oldestSequence = runtime->trafficRing[oldestIndex].sequence;
        // Note: Report the latest sequence number of the last written slot.
        response->newestSequence =
            runtime->trafficRing[
                (runtime->trafficWriteIndex +
                    KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                    1UL) %
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY].sequence;

    }
    // Note: Restore IRQL immediately after the metadata snapshot completes to allow classify to continue writing.
    KeReleaseSpinLock(&runtime->trafficLock, oldIrql);

    if (packetCount != 0UL) {
        // Note: After driver reload or a new capture session, the old R3 cursor may exceed the latest sequence.
        if (effectiveAfterSequence > response->newestSequence) {
            response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET;
            effectiveAfterSequence = 0ULL;
            response->nextSequence = 0ULL;
        }

        // Note: The protocol semantics for afterSequence=0 start from the current oldest row, treating historical coverage as no gap.
        if (effectiveAfterSequence == 0ULL) {
            desiredSequence = response->oldestSequence;
        }
        else if (effectiveAfterSequence < response->newestSequence) {
            desiredSequence = effectiveAfterSequence + 1ULL;
            if (desiredSequence < response->oldestSequence) {
                response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP;
                response->cursorGapCount =
                    response->oldestSequence - desiredSequence;
                desiredSequence = response->oldestSequence;
            }
        }

        if (desiredSequence != 0ULL &&
            desiredSequence <= response->newestSequence) {
            // Note: Sequence numbers are stable and contiguous, so no linear scan of 2048 slots is needed within the lock.
            availableCount = (ULONG)(
                response->newestSequence - desiredSequence + 1ULL);
            targetReturnCount = availableCount < outputRowCapacity
                ? availableCount
                : outputRowCapacity;
        }
    }

    // Note: Each iteration locates and copies exactly one fixed row within the spinlock; the write side is blocked by at most a single-row memcpy.
    while (returnedCount < targetReturnCount &&
        desiredSequence != 0ULL &&
        desiredSequence <= response->newestSequence) {
        ULONG ringIndex = 0UL;
        ULONG64 ringOffset = 0ULL;

        KeAcquireSpinLock(&runtime->trafficLock, &oldIrql);
        currentPacketCount = runtime->trafficCount;
        if (currentPacketCount == 0UL) {
            KeReleaseSpinLock(&runtime->trafficLock, oldIrql);
            break;
        }

        currentOldestIndex =
            (runtime->trafficWriteIndex +
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                currentPacketCount) %
            KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
        currentOldestSequence =
            runtime->trafficRing[currentOldestIndex].sequence;
        currentNewestSequence =
            runtime->trafficRing[
                (runtime->trafficWriteIndex +
                    KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                    1UL) %
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY].sequence;

        // Note: Under high traffic, the target slot may be overwritten between two short locks; jump to the current oldest row and record the gap.
        if (desiredSequence < currentOldestSequence) {
            response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP;
            response->cursorGapCount +=
                currentOldestSequence - desiredSequence;
            desiredSequence = currentOldestSequence;
        }
        if (desiredSequence > currentNewestSequence ||
            desiredSequence > response->newestSequence) {
            KeReleaseSpinLock(&runtime->trafficLock, oldIrql);
            break;
        }

        ringOffset = desiredSequence - currentOldestSequence;
        if (ringOffset >= currentPacketCount) {
            KeReleaseSpinLock(&runtime->trafficLock, oldIrql);
            break;
        }
        ringIndex = (currentOldestIndex + (ULONG)ringOffset) %
            KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
        if (runtime->trafficRing[ringIndex].sequence != desiredSequence) {
            response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
            response->lastStatus = STATUS_DATA_ERROR;
            KeReleaseSpinLock(&runtime->trafficLock, oldIrql);
            break;
        }

        RtlCopyMemory(
            &response->entries[returnedCount],
            &runtime->trafficRing[ringIndex],
            sizeof(runtime->trafficRing[ringIndex]));
        KeReleaseSpinLock(&runtime->trafficLock, oldIrql);

        response->nextSequence = desiredSequence;
        returnedCount += 1UL;
        desiredSequence += 1ULL;
    }

    // Note: Report the available row count after returning the cursor.
    response->availablePacketCount = availableCount;
    // Note: Report the actual number of copied rows.
    response->returnedPacketCount = returnedCount;
    // Note: Explicitly mark the response as truncated when the budget is insufficient.
    if (availableCount > returnedCount) {
        // Note: The caller should immediately continue querying with nextSequence.
        response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED;
    }
    // Note: Calculate the exact variable-length response size; the row count is constrained by a small budget and will not overflow ULONG.
    response->size = (ULONG)(
        kResponseHeaderSize +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW)));
    // Note: Report the exact write length.
    *bytesWrittenOut = response->size;
    // Note: Response formation successful.
    return STATUS_SUCCESS;
}

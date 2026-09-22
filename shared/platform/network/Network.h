#pragma once

// ============================================================
// ksword/network/network.h
// Namespace:
// ks::network Purpose:
// - Provide basic capability for bidirectional TCP/UDP packet capture (IPv4/IPv6 Raw Socket);
// - Provide 'packet port -> process PID' resolution capability (IP Helper table);
// - Provide runtime control capabilities for 'soft rate limiting by PID (Suspend/Resume)'.
// - Provide tool capabilities for TCP/UDP connection snapshot enumeration and TCP connection termination;
// - Provides the capability to execute manually constructed network requests (TCP/UDP Winsock parameters are customizable);
// - Directly callable by NetworkDock UI to decouple UI from underlying packet capture logic.
// ============================================================

#include "../process/Process.h"

#include <array>        // std::array: IPv6 16-byte address container and key type.
#include <algorithm>    // std::clamp/std::sort: normalize rate-limiting parameters and sort snapshots.
#include <atomic>       // std::atomic: Thread execution flag and sequence number generation.
#include <chrono>       // steady_clock/system_clock: Timestamps and refresh throttling.
#include <cstdint>      // Fixed-width integers: PID, port, length, etc.
#include <cstring>      // std::memcpy: Network byte parsing.
#include <functional>   // std::function: Callback interface.
#include <mutex>        // std::mutex: Protect cross-thread shared state.
#include <optional>     // std::optional: Optional action event.
#include <sstream>      // std::ostringstream: assembling status text.
#include <string>       // std::string: Cross-layer text type.
#include <thread>       // std::thread: Background packet capture thread.
#include <unordered_map>// std::unordered_map: Connection mapping and caching.
#include <unordered_set>// std::unordered_set: Fast local address matching.
#include <utility>      // std::pair: Container helper.
#include <vector>       // std::vector: Container for packets and table entries.

// Connection management utility:
// - TCP/UDP connection snapshot enumeration;
// - TCP connection termination (DELETE_TCB).
#include "NetworkConnectionTools.h"

// Manual request tools:
// - Provide configurable Winsock request execution encapsulation.
#include "NetworkRequestTools.h"

// Win32 + Winsock headers.
// Note: winsock2 must be included before winsock.h in the windows.h chain.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Iphlpapi.h>
#include <Mstcpip.h>

// Link dependencies:
// - Ws2_32：socket/bind/select/recv/WsaStartup；
// - Iphlpapi：GetAdaptersAddresses/GetExtendedTcpTable/GetExtendedUdpTable。
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace ks::network
{
    // PacketTransportProtocol: currently only TCP/UDP are of interest.
    enum class PacketTransportProtocol : std::uint8_t
    {
        kTcp = 6,   // IP protocol number 6.
        kUdp = 17   // IP protocol number 17.
    };

    // PacketDirection: Packet direction enumeration.
    enum class PacketDirection : std::uint8_t
    {
        kOutbound = 0, // Outbound (local -> remote).
        kInbound = 1,  // Inbound (remote -> local).
        kUnknown = 2   // Direction cannot be determined.
    };

    // RateLimitActionType: Rate limiting action type.
    enum class RateLimitActionType : std::uint8_t
    {
        kSuspendProcess = 0, // Trigger rate limiting: Suspend process.
        kResumeProcess = 1   // Suspended window timeout: resume process.
    };

    // PacketRecord: Complete data required for displaying a single packet capture event in the UI layer.
    struct PacketRecord
    {
        std::uint64_t sequenceId = 0;         // Packet sequence ID (monotonically increasing; used as the primary key in the UI).
        std::uint64_t captureTimestampMs = 0; // Packet capture timestamp (Unix ms).

        PacketTransportProtocol protocol = PacketTransportProtocol::kTcp; // Protocol type (TCP/UDP).
        PacketDirection direction = PacketDirection::kUnknown;            // Direction (Outbound/Inbound/Unknown).

        std::uint32_t processId = 0;          // Owner process PID (0 indicates not yet resolved).
        std::string processName;              // Owner process name (cached query, may be null).
        std::string sourceText = "R3";        // Data source: R3 packet capture, R0 WFP per-packet logging, or ALE stream authorization events.
        std::uint64_t sourceSequenceId = 0;   // R0 WFP original event sequence ID; R3 packet capture remains 0.
        std::uint32_t sourceFlags = 0;        // R0 WFP event semantic flags; R3 packet capture remains 0.

        std::string localAddress;             // Local address text (IPv4/IPv6).
        std::uint16_t localPort = 0;          // Local port.
        std::string remoteAddress;            // Remote address text (IPv4/IPv6).
        std::uint16_t remotePort = 0;         // Remote port.
        std::string remoteDomain;              // Remote domain: Preferably asynchronously filled back by the local DNS cache.

        std::uint32_t totalPacketSize = 0;    // Total IP packet length (bytes).
        std::uint32_t payloadSize = 0;        // L4 payload length (bytes).
        std::size_t payloadOffset = 0;        // The starting offset of the payload within packetBytes.

        bool localToLocalAmbiguous = false;   // true indicates that both source and destination belong to the local machine (local loopback or dual-address communication on the host); direction requires secondary determination.
        bool packetBytesTruncated = false;    // true indicates that packetBytes was truncated during saving.
        bool wfpAleEventNoPayload = false;    // true indicates an R0 WFP ALE flow authorization event, not a per-packet record containing payload.
        std::vector<std::uint8_t> packetBytes;// Preserved raw packet bytes (for viewing in the details window).
    };

    // ProcessRateLimitRule: Rate limiting policy configuration for a single PID.
    struct ProcessRateLimitRule
    {
        std::uint32_t processId = 0;          // Target PID.
        std::uint64_t processCreationTime100ns = 0; // Creation time of the process instance corresponding to the PID, to prevent erroneous operations due to PID recycling.
        std::uint64_t bytesPerSecond = 0;     // Maximum bytes allowed to send per second (B/s).
        std::uint32_t suspendDurationMs = 250;// Suspend duration (in milliseconds) after exceeding the limit.
        bool enabled = true;                  // Whether to enable this rule.
    };

    // ProcessRateLimitSnapshot: Snapshot structure used when refreshing the rate-limit table in the UI.
    struct ProcessRateLimitSnapshot
    {
        ProcessRateLimitRule rule;            // Rule configuration copy.
        std::uint64_t currentWindowBytes = 0; // Cumulative bytes sent within the current statistics window.
        std::uint64_t triggerCount = 0;       // Trigger count for rate limiting.
        bool currentlySuspended = false;      // Whether the current component is in a 'suspended' state triggered by this component.
    };

    // RateLimitActionEvent: Rate limit action notification (success/failure of suspend/resume).
    struct RateLimitActionEvent
    {
        std::uint64_t timestampMs = 0;            // Action timestamp (Unix milliseconds).
        std::uint32_t processId = 0;              // Target PID.
        RateLimitActionType actionType = RateLimitActionType::kSuspendProcess; // Action type.
        bool actionSucceeded = false;             // Whether the action succeeded.
        std::uint64_t configuredBytesPerSecond = 0;// Rule threshold at that time (B/s).
        std::string detailText;                   // Detailed description text (usable for UI log panels).
    };

    // packetProtocolToString: converts protocol enum to string.
    inline std::string packetProtocolToString(const PacketTransportProtocol protocol)
    {
        switch (protocol)
        {
        case PacketTransportProtocol::kTcp:
            return "TCP";
        case PacketTransportProtocol::kUdp:
            return "UDP";
        default:
            return "UNKNOWN";
        }
    }

    // packetDirectionToString: converts the direction enum to a string.
    inline std::string packetDirectionToString(const PacketDirection direction)
    {
        switch (direction)
        {
        case PacketDirection::kOutbound:
            return "Outbound";
        case PacketDirection::kInbound:
            return "Inbound";
        case PacketDirection::kUnknown:
        default:
            return "Unknown";
        }
    }

    // rateLimitActionTypeToString: Convert rate limit action enum to string.
    inline std::string rateLimitActionTypeToString(const RateLimitActionType actionType)
    {
        switch (actionType)
        {
        case RateLimitActionType::kSuspendProcess:
            return "SuspendProcess";
        case RateLimitActionType::kResumeProcess:
            return "ResumeProcess";
        default:
            return "UnknownAction";
        }
    }

    namespace detail
    {
        // kMaxRetainedPacketBytes：
        // - Prevents memory bloat from retaining a complete single packet.
        // - Retains enough header + main payload to satisfy the 'content viewing' feature.
        constexpr std::size_t kMaxRetainedPacketBytes = 4096;

        // Ipv6Bytes: Fixed 16-byte IPv6 address container (network byte order, stored byte by byte).
        // Notes:
        // - Must be declared before functions like readIpv6Bytes / ipv6BytesToString;
        //   otherwise, MSVC will treat the type as an undefined identifier when parsing
        //   function signatures, triggering a cascade of syntax errors.
        using Ipv6Bytes = std::array<std::uint8_t, 16>;

        // nowTickMs: Returns the current Unix timestamp in milliseconds.
        inline std::uint64_t nowTickMs()
        {
            const auto kNow = std::chrono::system_clock::now();
            const auto kEpochMs = std::chrono::duration_cast<std::chrono::milliseconds>(kNow.time_since_epoch());
            return static_cast<std::uint64_t>(kEpochMs.count());
        }

        // makeWinSockErrorText: assembles a WinSock error code into readable text.
        inline std::string makeWinSockErrorText(const int errorCode)
        {
            std::ostringstream stream;
            stream << "WSAError=" << errorCode;
            return stream.str();
        }

        // readNetworkUInt16: Read a 16-bit integer from network byte order and convert to host byte order.
        inline std::uint16_t readNetworkUInt16(const std::uint8_t* dataPtr)
        {
            std::uint16_t valueNetwork = 0;
            std::memcpy(&valueNetwork, dataPtr, sizeof(valueNetwork));
            return ntohs(valueNetwork);
        }

        // readNetworkUInt32: Read a 32-bit integer from network byte order and convert to host byte order.
        inline std::uint32_t readNetworkUInt32(const std::uint8_t* dataPtr)
        {
            std::uint32_t valueNetwork = 0;
            std::memcpy(&valueNetwork, dataPtr, sizeof(valueNetwork));
            return ntohl(valueNetwork);
        }

        // readIpv6Bytes: reads an IPv6 address from a contiguous 16-byte buffer.
        inline Ipv6Bytes readIpv6Bytes(const std::uint8_t* dataPtr)
        {
            Ipv6Bytes addressBytes{};
            if (dataPtr == nullptr)
            {
                return addressBytes;
            }
            std::memcpy(addressBytes.data(), dataPtr, addressBytes.size());
            return addressBytes;
        }

        // ipv4HostToString: Convert host-order IPv4 to dotted-decimal text.
        inline std::string ipv4HostToString(const std::uint32_t hostOrderIpv4)
        {
            in_addr address{};
            address.s_addr = htonl(hostOrderIpv4);

            char textBuffer[INET_ADDRSTRLEN] = {};
            const PCSTR kConvertResult = ::inet_ntop(AF_INET, &address, textBuffer, static_cast<socklen_t>(sizeof(textBuffer)));
            if (kConvertResult == nullptr)
            {
                return std::string("0.0.0.0");
            }
            return std::string(textBuffer);
        }

        // ipv6BytesToString: Convert 16-byte IPv6 address to text.
        inline std::string ipv6BytesToString(const Ipv6Bytes& ipv6Bytes)
        {
            IN6_ADDR ipv6Address{};
            std::memcpy(&ipv6Address, ipv6Bytes.data(), ipv6Bytes.size());

            char textBuffer[INET6_ADDRSTRLEN] = {};
            const PCSTR kConvertResult = ::inet_ntop(AF_INET6, &ipv6Address, textBuffer, static_cast<socklen_t>(sizeof(textBuffer)));
            if (kConvertResult == nullptr)
            {
                return std::string("::");
            }
            return std::string(textBuffer);
        }

        // localEndpointKey: Local address + port combination key (used for UDP and TCP fallback).
        inline std::uint64_t localEndpointKey(const std::uint32_t localIpv4HostOrder, const std::uint16_t localPortHostOrder)
        {
            return (static_cast<std::uint64_t>(localIpv4HostOrder) << 16) |
                static_cast<std::uint64_t>(localPortHostOrder);
        }

        // Ipv6BytesHasher: IPv6 address hasher used for unordered_set/map.
        struct Ipv6BytesHasher
        {
            std::size_t operator()(const Ipv6Bytes& addressBytes) const
            {
                std::size_t hashValue = 1469598103934665603ULL;
                for (const std::uint8_t kByteValue : addressBytes)
                {
                    hashValue ^= static_cast<std::size_t>(kByteValue);
                    hashValue *= 1099511628211ULL;
                }
                return hashValue;
            }
        };

        // Ipv6LocalEndpointKey: IPv6 local endpoint key (address + port).
        struct Ipv6LocalEndpointKey
        {
            Ipv6Bytes localAddress{};
            std::uint16_t localPort = 0;

            bool operator==(const Ipv6LocalEndpointKey& right) const
            {
                return localAddress == right.localAddress &&
                    localPort == right.localPort;
            }
        };

        // Ipv6LocalEndpointKeyHasher: IPv6 local endpoint key hasher.
        struct Ipv6LocalEndpointKeyHasher
        {
            std::size_t operator()(const Ipv6LocalEndpointKey& keyValue) const
            {
                Ipv6BytesHasher addressHasher;
                std::size_t hashValue = addressHasher(keyValue.localAddress);
                hashValue ^= static_cast<std::size_t>(keyValue.localPort) + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                return hashValue;
            }
        };

        // TcpEndpointKey: TCP four-tuple key.
        struct TcpEndpointKey
        {
            std::uint32_t localIpv4 = 0;   // Local IPv4 (host byte order).
            std::uint16_t localPort = 0;   // Local port (host byte order).
            std::uint32_t remoteIpv4 = 0;  // Remote IPv4 (host byte order).
            std::uint16_t remotePort = 0;  // Remote port (host byte order).

            bool operator==(const TcpEndpointKey& right) const
            {
                return localIpv4 == right.localIpv4 &&
                    localPort == right.localPort &&
                    remoteIpv4 == right.remoteIpv4 &&
                    remotePort == right.remotePort;
            }
        };

        // TcpEndpointKeyV6: IPv6 TCP four-tuple key.
        struct TcpEndpointKeyV6
        {
            Ipv6Bytes localIpv6{};       // Local IPv6 (16 bytes in network byte order).
            std::uint16_t localPort = 0; // Local port (host byte order).
            Ipv6Bytes remoteIpv6{};      // Remote IPv6 (network byte order, 16 bytes).
            std::uint16_t remotePort = 0;// Remote port (host byte order).

            bool operator==(const TcpEndpointKeyV6& right) const
            {
                return localIpv6 == right.localIpv6 &&
                    localPort == right.localPort &&
                    remoteIpv6 == right.remoteIpv6 &&
                    remotePort == right.remotePort;
            }
        };

        // TcpEndpointKeyHasher: TCP four-tuple hasher.
        struct TcpEndpointKeyHasher
        {
            std::size_t operator()(const TcpEndpointKey& key) const
            {
                const std::uint64_t kLeftPart =
                    (static_cast<std::uint64_t>(key.localIpv4) << 32) |
                    (static_cast<std::uint64_t>(key.localPort) << 16) |
                    static_cast<std::uint64_t>(key.remotePort);
                const std::uint64_t kRightPart = static_cast<std::uint64_t>(key.remoteIpv4);
                return static_cast<std::size_t>(kLeftPart ^ (kRightPart * 0x9E3779B97F4A7C15ULL));
            }
        };

        // TcpEndpointKeyV6Hasher: IPv6 TCP four-tuple hasher.
        struct TcpEndpointKeyV6Hasher
        {
            std::size_t operator()(const TcpEndpointKeyV6& keyValue) const
            {
                Ipv6BytesHasher addressHasher;
                std::size_t hashValue = addressHasher(keyValue.localIpv6);
                hashValue ^= static_cast<std::size_t>(keyValue.localPort) + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                const std::size_t kRemoteHash = addressHasher(keyValue.remoteIpv6);
                hashValue ^= kRemoteHash + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                hashValue ^= static_cast<std::size_t>(keyValue.remotePort) + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                return hashValue;
            }
        };

        // CaptureSocketEntry: Information about a Raw Socket bound to a single interface.
        struct CaptureSocketEntry
        {
            SOCKET socketValue = INVALID_SOCKET; // Raw Socket handle.
            int addressFamily = AF_INET;         // Address family (AF_INET / AF_INET6).
            std::uint32_t localIpv4HostOrder = 0;// Bind IPv4 (host byte order, valid when AF_INET is used).
            Ipv6Bytes localIpv6Bytes{};          // Bind IPv6 (16 bytes in network byte order, valid when AF_INET6).
            DWORD captureMode = RCVALL_ON;       // Packet capture mode (RCVALL_ON / RCVALL_IPLEVEL), used for compatibility with different network card drivers.
            std::string localAddressText;        // Bound address text (for log display).
        };

        // enumerateActiveIpv4Addresses：
        // - enumerate currently enabled IPv4 unicast addresses;
        // - For packet capture sockets to bind per interface.
        inline std::vector<std::uint32_t> enumerateActiveIpv4Addresses()
        {
            std::vector<std::uint32_t> ipv4List;

            ULONG requiredBufferLength = 0;
            const ULONG kQueryFlags =
                GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER;

            const ULONG kFirstQueryResult = ::GetAdaptersAddresses(
                AF_INET,
                kQueryFlags,
                nullptr,
                nullptr,
                &requiredBufferLength);

            if (kFirstQueryResult != ERROR_BUFFER_OVERFLOW || requiredBufferLength == 0)
            {
                return ipv4List;
            }

            std::vector<std::uint8_t> buffer(requiredBufferLength, 0);
            auto* adapterList = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            const ULONG kSecondQueryResult = ::GetAdaptersAddresses(
                AF_INET,
                kQueryFlags,
                nullptr,
                adapterList,
                &requiredBufferLength);

            if (kSecondQueryResult != NO_ERROR)
            {
                return ipv4List;
            }

            std::unordered_set<std::uint32_t> uniqueAddressSet;
            for (IP_ADAPTER_ADDRESSES* adapter = adapterList; adapter != nullptr; adapter = adapter->Next)
            {
                // Only collect 'up' network adapters to avoid invalid binds.
                if (adapter->OperStatus != IfOperStatusUp)
                {
                    continue;
                }

                for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
                    unicast != nullptr;
                    unicast = unicast->Next)
                {
                    if (unicast->Address.lpSockaddr == nullptr ||
                        unicast->Address.lpSockaddr->sa_family != AF_INET)
                    {
                        continue;
                    }

                    auto* ipv4Address = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                    const std::uint32_t kHostOrderAddress = ntohl(ipv4Address->sin_addr.s_addr);
                    if (kHostOrderAddress == 0)
                    {
                        continue;
                    }
                    uniqueAddressSet.insert(kHostOrderAddress);
                }
            }

            ipv4List.assign(uniqueAddressSet.begin(), uniqueAddressSet.end());
            return ipv4List;
        }

        // enumerateActiveIpv6Addresses：
        // - enumerate currently enabled IPv6 unicast addresses (including global and link-local addresses).
        // - For IPv6 Raw Sockets to bind per interface.
        inline std::vector<Ipv6Bytes> enumerateActiveIpv6Addresses()
        {
            std::vector<Ipv6Bytes> ipv6List;

            ULONG requiredBufferLength = 0;
            const ULONG kQueryFlags =
                GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER;

            const ULONG kFirstQueryResult = ::GetAdaptersAddresses(
                AF_INET6,
                kQueryFlags,
                nullptr,
                nullptr,
                &requiredBufferLength);

            if (kFirstQueryResult != ERROR_BUFFER_OVERFLOW || requiredBufferLength == 0)
            {
                return ipv6List;
            }

            std::vector<std::uint8_t> buffer(requiredBufferLength, 0);
            auto* adapterList = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            const ULONG kSecondQueryResult = ::GetAdaptersAddresses(
                AF_INET6,
                kQueryFlags,
                nullptr,
                adapterList,
                &requiredBufferLength);

            if (kSecondQueryResult != NO_ERROR)
            {
                return ipv6List;
            }

            std::unordered_set<Ipv6Bytes, Ipv6BytesHasher> uniqueAddressSet;
            for (IP_ADAPTER_ADDRESSES* adapter = adapterList; adapter != nullptr; adapter = adapter->Next)
            {
                if (adapter->OperStatus != IfOperStatusUp)
                {
                    continue;
                }

                for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
                    unicast != nullptr;
                    unicast = unicast->Next)
                {
                    if (unicast->Address.lpSockaddr == nullptr ||
                        unicast->Address.lpSockaddr->sa_family != AF_INET6)
                    {
                        continue;
                    }

                    auto* ipv6Address = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
                    // Filter unspecified address :: to avoid invalid bind.
                    if (::IN6_IS_ADDR_UNSPECIFIED(&ipv6Address->sin6_addr))
                    {
                        continue;
                    }

                    Ipv6Bytes addressBytes{};
                    std::memcpy(addressBytes.data(), &ipv6Address->sin6_addr, addressBytes.size());
                    uniqueAddressSet.insert(addressBytes);
                }
            }

            ipv6List.assign(uniqueAddressSet.begin(), uniqueAddressSet.end());
            return ipv6List;
        }

        // openCaptureSockets：
        // - Create Raw Sockets for each active IPv4/IPv6 address;
        // - Enable SIO_RCVALL to capture IP-layer packets.
        inline std::vector<CaptureSocketEntry> openCaptureSockets(std::string* errorTextOut)
        {
            if (errorTextOut != nullptr)
            {
                errorTextOut->clear();
            }

            std::vector<CaptureSocketEntry> socketList;
            const std::vector<std::uint32_t> kLocalIpv4List = enumerateActiveIpv4Addresses();
            const std::vector<Ipv6Bytes> kLocalIpv6List = enumerateActiveIpv6Addresses();
            if (kLocalIpv4List.empty() && kLocalIpv6List.empty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = "未枚举到可用 IPv4/IPv6 接口。";
                }
                return socketList;
            }

            // configureCaptureSocket purpose: uniformly execute RCVALL, receive buffer, and non-blocking configuration.
            // Notes:
            // - Some drivers/virtual NICs have unstable support for RCVALL_ON;
            // - Add RCVALL_IPLEVEL fallback to significantly reduce the probability of capturing TCP but dropping UDP/inbound traffic;
            auto configureCaptureSocket = [](SOCKET rawSocket, DWORD& captureModeOut) -> bool
                {
                    captureModeOut = RCVALL_ON;
                    const std::array<DWORD, 2> kCaptureModeCandidates =
                    {
                        RCVALL_ON,
                        RCVALL_IPLEVEL
                    };

                    bool captureModeApplied = false;
                    for (const DWORD kCandidateMode : kCaptureModeCandidates)
                    {
                        DWORD receiveAllFlag = kCandidateMode;
                        DWORD bytesReturned = 0;
                        if (::WSAIoctl(
                            rawSocket,
                            SIO_RCVALL,
                            &receiveAllFlag,
                            sizeof(receiveAllFlag),
                            nullptr,
                            0,
                            &bytesReturned,
                            nullptr,
                            nullptr) == SOCKET_ERROR)
                        {
                            continue;
                        }

                        captureModeOut = kCandidateMode;
                        captureModeApplied = true;
                        break;
                    }
                    if (!captureModeApplied)
                    {
                        return false;
                    }

                    // receiveBufferBytes purpose: Increase the kernel receive buffer limit to reduce socket packet loss under burst traffic.
                    int receiveBufferBytes = 8 * 1024 * 1024;
                    (void)::setsockopt(
                        rawSocket,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        reinterpret_cast<const char*>(&receiveBufferBytes),
                        static_cast<int>(sizeof(receiveBufferBytes)));

                    // Set to non-blocking: works with periodic polling via select to prevent thread hangs.
                    u_long nonBlockingEnabled = 1;
                    ::ioctlsocket(rawSocket, FIONBIO, &nonBlockingEnabled);
                    return true;
                };

            // Create an IPv4 packet capture socket first.
            for (const std::uint32_t kLocalIpv4 : kLocalIpv4List)
            {
                SOCKET rawSocket = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
                if (rawSocket == INVALID_SOCKET)
                {
                    continue;
                }

                sockaddr_in bindAddress{};
                bindAddress.sin_family = AF_INET;
                bindAddress.sin_port = 0;
                bindAddress.sin_addr.s_addr = htonl(kLocalIpv4);
                if (::bind(rawSocket, reinterpret_cast<sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                DWORD captureMode = RCVALL_ON;
                if (!configureCaptureSocket(rawSocket, captureMode))
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                CaptureSocketEntry socketEntry;
                socketEntry.socketValue = rawSocket;
                socketEntry.addressFamily = AF_INET;
                socketEntry.localIpv4HostOrder = kLocalIpv4;
                socketEntry.captureMode = captureMode;
                socketEntry.localAddressText = ipv4HostToString(kLocalIpv4);
                socketList.push_back(socketEntry);
            }

            // Create an IPv6 packet capture socket again.
            for (const Ipv6Bytes& localIpv6 : kLocalIpv6List)
            {
                SOCKET rawSocket = ::socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);
                if (rawSocket == INVALID_SOCKET)
                {
                    continue;
                }

                sockaddr_in6 bindAddress{};
                bindAddress.sin6_family = AF_INET6;
                bindAddress.sin6_port = 0;
                std::memcpy(&bindAddress.sin6_addr, localIpv6.data(), localIpv6.size());
                if (::bind(rawSocket, reinterpret_cast<sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                DWORD captureMode = RCVALL_ON;
                if (!configureCaptureSocket(rawSocket, captureMode))
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                CaptureSocketEntry socketEntry;
                socketEntry.socketValue = rawSocket;
                socketEntry.addressFamily = AF_INET6;
                socketEntry.localIpv6Bytes = localIpv6;
                socketEntry.captureMode = captureMode;
                socketEntry.localAddressText = ipv6BytesToString(localIpv6);
                socketList.push_back(socketEntry);
            }

            if (socketList.empty() && errorTextOut != nullptr)
            {
                const int kLastError = ::WSAGetLastError();
                std::ostringstream stream;
                stream << "Raw Socket 打开失败，通常需要管理员权限。"
                    << " " << makeWinSockErrorText(kLastError);
                *errorTextOut = stream.str();
            }

            return socketList;
        }

        // closeCaptureSockets: Closes all Raw Sockets.
        inline void closeCaptureSockets(std::vector<CaptureSocketEntry>& socketList)
        {
            for (CaptureSocketEntry& socketEntry : socketList)
            {
                if (socketEntry.socketValue != INVALID_SOCKET)
                {
                    ::closesocket(socketEntry.socketValue);
                    socketEntry.socketValue = INVALID_SOCKET;
                }
            }
            socketList.clear();
        }

        // parseIpv4Packet：
        // - Parses the TCP/UDP header within the IPv4 packet;
        // - Returns 'local traffic' (retains both outbound and inbound).
        inline bool parseIpv4Packet(
            const std::uint8_t* packetBuffer,
            const std::size_t packetBufferLength,
            const std::unordered_set<std::uint32_t>& localIpv4Set,
            PacketRecord& packetOut)
        {
            if (packetBuffer == nullptr || packetBufferLength < 20)
            {
                return false;
            }

            // IPv4 first byte: high 4 bits = Version, low 4 bits = IHL (32-bit words).
            const std::uint8_t kVersionAndHeaderLength = packetBuffer[0];
            const std::uint8_t kIpVersion = static_cast<std::uint8_t>(kVersionAndHeaderLength >> 4);
            const std::size_t kIpHeaderLength = static_cast<std::size_t>(kVersionAndHeaderLength & 0x0F) * 4ULL;
            if (kIpVersion != 4 || kIpHeaderLength < 20 || packetBufferLength < kIpHeaderLength)
            {
                return false;
            }

            // IP Total Length is in network byte order and may be less than the receive buffer length.
            std::size_t totalLength = static_cast<std::size_t>(readNetworkUInt16(packetBuffer + 2));
            if (totalLength < kIpHeaderLength)
            {
                return false;
            }
            totalLength = std::min(totalLength, packetBufferLength);

            // Protocol field: 6=TCP, 17=UDP.
            const std::uint8_t kProtocolField = packetBuffer[9];
            PacketTransportProtocol protocol = PacketTransportProtocol::kTcp;
            if (kProtocolField == IPPROTO_TCP)
            {
                protocol = PacketTransportProtocol::kTcp;
            }
            else if (kProtocolField == IPPROTO_UDP)
            {
                protocol = PacketTransportProtocol::kUdp;
            }
            else
            {
                return false;
            }

            // Source and destination addresses are stored in host byte order for subsequent comparison and hashing.
            const std::uint32_t kSourceIpv4 = readNetworkUInt32(packetBuffer + 12);
            const std::uint32_t kDestinationIpv4 = readNetworkUInt32(packetBuffer + 16);

            // Direction determination:
            // - source in local address set => Outbound;
            // - destination is in the local address set => Inbound;
            // - Source and destination both in local address set => Local-to-local endpoint communication (initially marked as Unknown, later split into inbound and outbound flows).
            // - If neither side is in the local IP set => unrelated to this host (ignore directly).
            const bool kSourceIsLocal = (localIpv4Set.find(kSourceIpv4) != localIpv4Set.end());
            const bool kDestinationIsLocal = (localIpv4Set.find(kDestinationIpv4) != localIpv4Set.end());
            const bool kLocalToLocalAmbiguous = kSourceIsLocal && kDestinationIsLocal;
            PacketDirection direction = PacketDirection::kUnknown;
            if (kSourceIsLocal && !kDestinationIsLocal)
            {
                direction = PacketDirection::kOutbound;
            }
            else if (!kSourceIsLocal && kDestinationIsLocal)
            {
                direction = PacketDirection::kInbound;
            }

            // Retain only traffic related to the local machine; skip if neither side is a local address.
            if (!kSourceIsLocal && !kDestinationIsLocal)
            {
                return false;
            }

            // sourcePort/destinationPort usage: temporarily store original packet header direction ports (src/dst).
            std::uint16_t sourcePort = 0;
            std::uint16_t destinationPort = 0;
            std::size_t payloadOffset = 0;

            if (protocol == PacketTransportProtocol::kTcp)
            {
                // TCP minimum header is 20 bytes.
                const std::size_t kTcpOffset = kIpHeaderLength;
                if (totalLength < kTcpOffset + 20)
                {
                    return false;
                }

                sourcePort = readNetworkUInt16(packetBuffer + kTcpOffset);
                destinationPort = readNetworkUInt16(packetBuffer + kTcpOffset + 2);

                const std::uint8_t kTcpDataOffsetField = packetBuffer[kTcpOffset + 12];
                const std::size_t kTcpHeaderLength = static_cast<std::size_t>((kTcpDataOffsetField >> 4) & 0x0F) * 4ULL;
                if (kTcpHeaderLength < 20 || totalLength < kTcpOffset + kTcpHeaderLength)
                {
                    return false;
                }
                payloadOffset = kTcpOffset + kTcpHeaderLength;
            }
            else
            {
                // UDP has a fixed 8-byte header.
                const std::size_t kUdpOffset = kIpHeaderLength;
                if (totalLength < kUdpOffset + 8)
                {
                    return false;
                }

                sourcePort = readNetworkUInt16(packetBuffer + kUdpOffset);
                destinationPort = readNetworkUInt16(packetBuffer + kUdpOffset + 2);
                payloadOffset = kUdpOffset + 8;
            }

            // local/remote endpoints are uniformly converted to the semantics of 'local is the host machine' for easier UI and PID resolution.
            // Notes:
            // - For local-to-local communication (localToLocalAmbiguous=true), maintain the original src->dst direction; the
            //   upper layer will emit an additional Inbound record during PID resolution to achieve complete bidirectional display.
            std::uint32_t localIpv4 = kSourceIpv4;
            std::uint32_t remoteIpv4 = kDestinationIpv4;
            std::uint16_t localPort = sourcePort;
            std::uint16_t remotePort = destinationPort;
            if (direction == PacketDirection::kInbound)
            {
                localIpv4 = kDestinationIpv4;
                remoteIpv4 = kSourceIpv4;
                localPort = destinationPort;
                remotePort = sourcePort;
            }

            // Assemble output structure for direct UI use.
            packetOut.protocol = protocol;
            packetOut.direction = direction;
            packetOut.processId = 0;
            packetOut.processName.clear();
            packetOut.localAddress = ipv4HostToString(localIpv4);
            packetOut.localPort = localPort;
            packetOut.remoteAddress = ipv4HostToString(remoteIpv4);
            packetOut.remotePort = remotePort;
            packetOut.totalPacketSize = static_cast<std::uint32_t>(totalLength);
            packetOut.payloadOffset = payloadOffset;
            packetOut.payloadSize = (payloadOffset <= totalLength)
                ? static_cast<std::uint32_t>(totalLength - payloadOffset)
                : 0U;
            packetOut.localToLocalAmbiguous = kLocalToLocalAmbiguous;

            const std::size_t kRetainedLength = std::min(totalLength, kMaxRetainedPacketBytes);
            packetOut.packetBytes.assign(packetBuffer, packetBuffer + kRetainedLength);
            packetOut.packetBytesTruncated = (kRetainedLength < totalLength);

            return true;
        }

        // parseIpv6Packet：
        // - Parse TCP/UDP headers in an IPv6 packet;
        // - Traverse common extension headers to reduce missed captures caused by incorrectly treating traffic as unparseable.
        inline bool parseIpv6Packet(
            const std::uint8_t* packetBuffer,
            const std::size_t packetBufferLength,
            const std::unordered_set<Ipv6Bytes, Ipv6BytesHasher>& localIpv6Set,
            PacketRecord& packetOut)
        {
            if (packetBuffer == nullptr || packetBufferLength < 40)
            {
                return false;
            }

            // IPv6 version field is in the high 4 bits of the first byte.
            const std::uint8_t kVersionField = static_cast<std::uint8_t>(packetBuffer[0] >> 4);
            if (kVersionField != 6)
            {
                return false;
            }

            // payloadLengthValue usage: IPv6 payload length (excluding the fixed 40-byte header).
            const std::size_t kPayloadLengthValue = static_cast<std::size_t>(readNetworkUInt16(packetBuffer + 4));
            std::size_t totalLength = 40 + kPayloadLengthValue;
            if (totalLength < 40)
            {
                return false;
            }
            totalLength = std::min(totalLength, packetBufferLength);

            const Ipv6Bytes kSourceIpv6 = readIpv6Bytes(packetBuffer + 8);
            const Ipv6Bytes kDestinationIpv6 = readIpv6Bytes(packetBuffer + 24);

            const bool kSourceIsLocal = (localIpv6Set.find(kSourceIpv6) != localIpv6Set.end());
            const bool kDestinationIsLocal = (localIpv6Set.find(kDestinationIpv6) != localIpv6Set.end());
            const bool kLocalToLocalAmbiguous = kSourceIsLocal && kDestinationIsLocal;
            PacketDirection direction = PacketDirection::kUnknown;
            if (kSourceIsLocal && !kDestinationIsLocal)
            {
                direction = PacketDirection::kOutbound;
            }
            else if (!kSourceIsLocal && kDestinationIsLocal)
            {
                direction = PacketDirection::kInbound;
            }
            if (!kSourceIsLocal && !kDestinationIsLocal)
            {
                return false;
            }

            // nextHeader usage: Current protocol header type; initial value comes from the fixed IPv6 header.
            std::uint8_t nextHeader = packetBuffer[6];
            // transportOffset: The current header offset being parsed; ultimately points to the start of the TCP/UDP header.
            std::size_t transportOffset = 40;

            // Skip extension headers until TCP/UDP.
            while (true)
            {
                if (nextHeader == IPPROTO_TCP || nextHeader == IPPROTO_UDP)
                {
                    break;
                }

                if (transportOffset >= totalLength)
                {
                    return false;
                }

                // No Next Header: No L4 content, terminate immediately.
                if (nextHeader == 59)
                {
                    return false;
                }

                // Fragment header: Fixed length of 8 bytes.
                if (nextHeader == 44)
                {
                    if (transportOffset + 8 > totalLength)
                    {
                        return false;
                    }

                    // fragmentOffsetField usage: Fragment offset + flags; non-first fragments typically lack TCP/UDP ports, making endpoint reconstruction impossible.
                    const std::uint16_t kFragmentOffsetField = readNetworkUInt16(packetBuffer + transportOffset + 2);
                    const std::uint16_t kFragmentOffset = static_cast<std::uint16_t>((kFragmentOffsetField & 0xFFF8U) >> 3);
                    if (kFragmentOffset != 0)
                    {
                        return false;
                    }

                    nextHeader = packetBuffer[transportOffset];
                    transportOffset += 8;
                    continue;
                }

                // AH header: length unit is 32-bit words, excluding the first two 32-bit words.
                if (nextHeader == 51)
                {
                    if (transportOffset + 2 > totalLength)
                    {
                        return false;
                    }
                    const std::uint8_t kAhLengthUnit = packetBuffer[transportOffset + 1];
                    const std::size_t kAhHeaderLength = static_cast<std::size_t>(kAhLengthUnit + 2U) * 4ULL;
                    if (kAhHeaderLength < 8 || transportOffset + kAhHeaderLength > totalLength)
                    {
                        return false;
                    }

                    nextHeader = packetBuffer[transportOffset];
                    transportOffset += kAhHeaderLength;
                    continue;
                }

                // ESP headers cannot be reliably resolved to ports in user mode; skip this packet directly.
                if (nextHeader == 50)
                {
                    return false;
                }

                // Hop-by-Hop / Routing / Destination Options: Calculate uniformly as (HdrExtLen+1)*8.
                if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60)
                {
                    if (transportOffset + 2 > totalLength)
                    {
                        return false;
                    }
                    const std::uint8_t kExtLengthUnit = packetBuffer[transportOffset + 1];
                    const std::size_t kExtHeaderLength = (static_cast<std::size_t>(kExtLengthUnit) + 1ULL) * 8ULL;
                    if (kExtHeaderLength < 8 || transportOffset + kExtHeaderLength > totalLength)
                    {
                        return false;
                    }

                    nextHeader = packetBuffer[transportOffset];
                    transportOffset += kExtHeaderLength;
                    continue;
                }

                // Other protocol header types are not yet supported.
                return false;
            }

            PacketTransportProtocol protocol = PacketTransportProtocol::kTcp;
            std::uint16_t sourcePort = 0;
            std::uint16_t destinationPort = 0;
            std::size_t payloadOffset = 0;

            if (nextHeader == IPPROTO_TCP)
            {
                protocol = PacketTransportProtocol::kTcp;
                if (transportOffset + 20 > totalLength)
                {
                    return false;
                }

                sourcePort = readNetworkUInt16(packetBuffer + transportOffset);
                destinationPort = readNetworkUInt16(packetBuffer + transportOffset + 2);

                const std::uint8_t kTcpDataOffsetField = packetBuffer[transportOffset + 12];
                const std::size_t kTcpHeaderLength = static_cast<std::size_t>((kTcpDataOffsetField >> 4) & 0x0F) * 4ULL;
                if (kTcpHeaderLength < 20 || transportOffset + kTcpHeaderLength > totalLength)
                {
                    return false;
                }
                payloadOffset = transportOffset + kTcpHeaderLength;
            }
            else
            {
                protocol = PacketTransportProtocol::kUdp;
                if (transportOffset + 8 > totalLength)
                {
                    return false;
                }

                sourcePort = readNetworkUInt16(packetBuffer + transportOffset);
                destinationPort = readNetworkUInt16(packetBuffer + transportOffset + 2);
                payloadOffset = transportOffset + 8;
            }

            Ipv6Bytes localIpv6 = kSourceIpv6;
            Ipv6Bytes remoteIpv6 = kDestinationIpv6;
            std::uint16_t localPort = sourcePort;
            std::uint16_t remotePort = destinationPort;
            if (direction == PacketDirection::kInbound)
            {
                localIpv6 = kDestinationIpv6;
                remoteIpv6 = kSourceIpv6;
                localPort = destinationPort;
                remotePort = sourcePort;
            }

            packetOut.protocol = protocol;
            packetOut.direction = direction;
            packetOut.processId = 0;
            packetOut.processName.clear();
            packetOut.localAddress = ipv6BytesToString(localIpv6);
            packetOut.localPort = localPort;
            packetOut.remoteAddress = ipv6BytesToString(remoteIpv6);
            packetOut.remotePort = remotePort;
            packetOut.totalPacketSize = static_cast<std::uint32_t>(totalLength);
            packetOut.payloadOffset = payloadOffset;
            packetOut.payloadSize = (payloadOffset <= totalLength)
                ? static_cast<std::uint32_t>(totalLength - payloadOffset)
                : 0U;
            packetOut.localToLocalAmbiguous = kLocalToLocalAmbiguous;

            const std::size_t kRetainedLength = std::min(totalLength, kMaxRetainedPacketBytes);
            packetOut.packetBytes.assign(packetBuffer, packetBuffer + kRetainedLength);
            packetOut.packetBytesTruncated = (kRetainedLength < totalLength);

            return true;
        }

        // ConnectionPidResolver：
        // - Periodically refresh the TCP/UDP owning PID table.
        // - Provides mapping capability from 'connection four-tuple/local endpoint' to PID.
        class ConnectionPidResolver final
        {
        public:
            // resolveProcessId: resolve the owning PID by IPv4 endpoint.
            std::uint32_t resolveProcessId(
                const PacketTransportProtocol protocol,
                const std::uint32_t localIpv4,
                const std::uint16_t localPort,
                const std::uint32_t remoteIpv4,
                const std::uint16_t remotePort)
            {
                const std::uint64_t kNowTickMs = nowTickMs();
                refreshIfRequired(kNowTickMs);

                if (protocol == PacketTransportProtocol::kTcp)
                {
                    // First, perform an exact match on the TCP four-tuple.
                    const TcpEndpointKey kExactKey{ localIpv4, localPort, remoteIpv4, remotePort };
                    const auto kExactIterator = tcpPidByQuad_.find(kExactKey);
                    if (kExactIterator != tcpPidByQuad_.end())
                    {
                        return kExactIterator->second;
                    }

                    // Fall back to local endpoint matching (e.g., during certain transient connection phases).
                    const std::uint64_t kLocalExactKey = localEndpointKey(localIpv4, localPort);
                    const auto kLocalExactIterator = tcpPidByLocalEndpoint_.find(kLocalExactKey);
                    if (kLocalExactIterator != tcpPidByLocalEndpoint_.end())
                    {
                        return kLocalExactIterator->second;
                    }

                    // Then attempt the placeholder mapping for 0.0.0.0:port.
                    const std::uint64_t kLocalWildcardKey = localEndpointKey(0, localPort);
                    const auto kLocalWildcardIterator = tcpPidByLocalEndpoint_.find(kLocalWildcardKey);
                    if (kLocalWildcardIterator != tcpPidByLocalEndpoint_.end())
                    {
                        return kLocalWildcardIterator->second;
                    }
                    return 0;
                }

                // UDP primarily maps by local endpoint.
                const std::uint64_t kUdpLocalKey = localEndpointKey(localIpv4, localPort);
                const auto kUdpIterator = udpPidByLocalEndpoint_.find(kUdpLocalKey);
                if (kUdpIterator != udpPidByLocalEndpoint_.end())
                {
                    return kUdpIterator->second;
                }

                // Similarly, provides a 0.0.0.0:port fallback.
                const std::uint64_t kUdpWildcardKey = localEndpointKey(0, localPort);
                const auto kUdpWildcardIterator = udpPidByLocalEndpoint_.find(kUdpWildcardKey);
                if (kUdpWildcardIterator != udpPidByLocalEndpoint_.end())
                {
                    return kUdpWildcardIterator->second;
                }
                return 0;
            }

            // resolveProcessIdV6: resolves the owning PID by IPv6 endpoint.
            std::uint32_t resolveProcessIdV6(
                const PacketTransportProtocol protocol,
                const Ipv6Bytes& localIpv6,
                const std::uint16_t localPort,
                const Ipv6Bytes& remoteIpv6,
                const std::uint16_t remotePort)
            {
                const std::uint64_t kNowTickMs = nowTickMs();
                refreshIfRequired(kNowTickMs);

                if (protocol == PacketTransportProtocol::kTcp)
                {
                    const TcpEndpointKeyV6 kExactKey{ localIpv6, localPort, remoteIpv6, remotePort };
                    const auto kExactIterator = tcpPidByQuadV6_.find(kExactKey);
                    if (kExactIterator != tcpPidByQuadV6_.end())
                    {
                        return kExactIterator->second;
                    }

                    const Ipv6LocalEndpointKey kLocalExactKey{ localIpv6, localPort };
                    const auto kLocalExactIterator = tcpPidByLocalEndpointV6_.find(kLocalExactKey);
                    if (kLocalExactIterator != tcpPidByLocalEndpointV6_.end())
                    {
                        return kLocalExactIterator->second;
                    }

                    // IPv6 wildcard fallback：:::port。
                    const Ipv6Bytes kWildcardAddress{};
                    const Ipv6LocalEndpointKey kLocalWildcardKey{ kWildcardAddress, localPort };
                    const auto kLocalWildcardIterator = tcpPidByLocalEndpointV6_.find(kLocalWildcardKey);
                    if (kLocalWildcardIterator != tcpPidByLocalEndpointV6_.end())
                    {
                        return kLocalWildcardIterator->second;
                    }
                    return 0;
                }

                const Ipv6LocalEndpointKey kUdpLocalKey{ localIpv6, localPort };
                const auto kUdpIterator = udpPidByLocalEndpointV6_.find(kUdpLocalKey);
                if (kUdpIterator != udpPidByLocalEndpointV6_.end())
                {
                    return kUdpIterator->second;
                }

                const Ipv6Bytes kWildcardAddress{};
                const Ipv6LocalEndpointKey kUdpWildcardKey{ kWildcardAddress, localPort };
                const auto kUdpWildcardIterator = udpPidByLocalEndpointV6_.find(kUdpWildcardKey);
                if (kUdpWildcardIterator != udpPidByLocalEndpointV6_.end())
                {
                    return kUdpWildcardIterator->second;
                }
                return 0;
            }

        private:
            // refreshIfRequired: Throttles connection table refreshes to avoid calling IPHLPAPI for every packet.
            void refreshIfRequired(const std::uint64_t nowTickMs)
            {
                // kRefreshIntervalMs: Throttle interval for refreshing the connection table.
                // Reducing to 250ms improves the PID mapping hit rate for short connections and short UDP sessions.
                constexpr std::uint64_t kRefreshIntervalMs = 250;
                if (lastRefreshTickMs_ != 0 &&
                    nowTickMs - lastRefreshTickMs_ < kRefreshIntervalMs)
                {
                    return;
                }

                refreshTcpTable();
                refreshUdpTable();
                lastRefreshTickMs_ = nowTickMs;
            }

            // refreshTcpTable: refresh TCP four-tuple mapping (IPv4 + IPv6).
            void refreshTcpTable()
            {
                tcpPidByQuad_.clear();
                tcpPidByLocalEndpoint_.clear();
                tcpPidByQuadV6_.clear();
                tcpPidByLocalEndpointV6_.clear();

                // Refresh IPv4 first.
                DWORD requiredLength = 0;
                const DWORD kSizeQueryResultV4 = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (kSizeQueryResultV4 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBuffer(requiredLength, 0);
                    DWORD tableLength = requiredLength;
                    const DWORD kResult = ::GetExtendedTcpTable(
                        tableBuffer.data(),
                        &tableLength,
                        FALSE,
                        AF_INET,
                        TCP_TABLE_OWNER_PID_ALL,
                        0);
                    if (kResult == NO_ERROR)
                    {
                        auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
                        if (tcpTable != nullptr)
                        {
                            tcpPidByQuad_.reserve(tcpTable->dwNumEntries);
                            tcpPidByLocalEndpoint_.reserve(tcpTable->dwNumEntries);

                            for (DWORD index = 0; index < tcpTable->dwNumEntries; ++index)
                            {
                                const MIB_TCPROW_OWNER_PID& row = tcpTable->table[index];
                                const std::uint32_t kLocalIpv4 = ntohl(row.dwLocalAddr);
                                const std::uint16_t kLocalPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint32_t kRemoteIpv4 = ntohl(row.dwRemoteAddr);
                                const std::uint16_t kRemotePort = ntohs(static_cast<u_short>(row.dwRemotePort & 0xFFFFu));
                                const std::uint32_t kOwnerPid = row.dwOwningPid;

                                const TcpEndpointKey kQuadKey{ kLocalIpv4, kLocalPort, kRemoteIpv4, kRemotePort };
                                tcpPidByQuad_[kQuadKey] = kOwnerPid;

                                const std::uint64_t kLocalKey = localEndpointKey(kLocalIpv4, kLocalPort);
                                tcpPidByLocalEndpoint_[kLocalKey] = kOwnerPid;
                            }
                        }
                    }
                }

                // Refresh IPv6 again.
                requiredLength = 0;
                const DWORD kSizeQueryResultV6 = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (kSizeQueryResultV6 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBufferV6(requiredLength, 0);
                    DWORD tableLengthV6 = requiredLength;
                    const DWORD kResultV6 = ::GetExtendedTcpTable(
                        tableBufferV6.data(),
                        &tableLengthV6,
                        FALSE,
                        AF_INET6,
                        TCP_TABLE_OWNER_PID_ALL,
                        0);
                    if (kResultV6 == NO_ERROR)
                    {
                        auto* tcpTableV6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tableBufferV6.data());
                        if (tcpTableV6 != nullptr)
                        {
                            tcpPidByQuadV6_.reserve(tcpTableV6->dwNumEntries);
                            tcpPidByLocalEndpointV6_.reserve(tcpTableV6->dwNumEntries);
                            for (DWORD index = 0; index < tcpTableV6->dwNumEntries; ++index)
                            {
                                const MIB_TCP6ROW_OWNER_PID& row = tcpTableV6->table[index];
                                Ipv6Bytes localIpv6{};
                                Ipv6Bytes remoteIpv6{};
                                std::memcpy(localIpv6.data(), row.ucLocalAddr, localIpv6.size());
                                std::memcpy(remoteIpv6.data(), row.ucRemoteAddr, remoteIpv6.size());
                                const std::uint16_t kLocalPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint16_t kRemotePort = ntohs(static_cast<u_short>(row.dwRemotePort & 0xFFFFu));
                                const std::uint32_t kOwnerPid = row.dwOwningPid;

                                const TcpEndpointKeyV6 kQuadKey{ localIpv6, kLocalPort, remoteIpv6, kRemotePort };
                                tcpPidByQuadV6_[kQuadKey] = kOwnerPid;

                                const Ipv6LocalEndpointKey kLocalKey{ localIpv6, kLocalPort };
                                tcpPidByLocalEndpointV6_[kLocalKey] = kOwnerPid;
                            }
                        }
                    }
                }
            }

            // refreshUdpTable: Refreshes the UDP local endpoint mapping (IPv4 + IPv6).
            void refreshUdpTable()
            {
                udpPidByLocalEndpoint_.clear();
                udpPidByLocalEndpointV6_.clear();

                // Refresh IPv4 first.
                DWORD requiredLength = 0;
                const DWORD kSizeQueryResultV4 = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (kSizeQueryResultV4 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBuffer(requiredLength, 0);
                    DWORD tableLength = requiredLength;
                    const DWORD kResult = ::GetExtendedUdpTable(
                        tableBuffer.data(),
                        &tableLength,
                        FALSE,
                        AF_INET,
                        UDP_TABLE_OWNER_PID,
                        0);
                    if (kResult == NO_ERROR)
                    {
                        auto* udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(tableBuffer.data());
                        if (udpTable != nullptr)
                        {
                            udpPidByLocalEndpoint_.reserve(udpTable->dwNumEntries);
                            for (DWORD index = 0; index < udpTable->dwNumEntries; ++index)
                            {
                                const MIB_UDPROW_OWNER_PID& row = udpTable->table[index];
                                const std::uint32_t kLocalIpv4 = ntohl(row.dwLocalAddr);
                                const std::uint16_t kLocalPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint32_t kOwnerPid = row.dwOwningPid;
                                const std::uint64_t kLocalKey = localEndpointKey(kLocalIpv4, kLocalPort);
                                udpPidByLocalEndpoint_[kLocalKey] = kOwnerPid;
                            }
                        }
                    }
                }

                // Refresh IPv6 again.
                requiredLength = 0;
                const DWORD kSizeQueryResultV6 = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (kSizeQueryResultV6 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBufferV6(requiredLength, 0);
                    DWORD tableLengthV6 = requiredLength;
                    const DWORD kResultV6 = ::GetExtendedUdpTable(
                        tableBufferV6.data(),
                        &tableLengthV6,
                        FALSE,
                        AF_INET6,
                        UDP_TABLE_OWNER_PID,
                        0);
                    if (kResultV6 == NO_ERROR)
                    {
                        auto* udpTableV6 = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(tableBufferV6.data());
                        if (udpTableV6 != nullptr)
                        {
                            udpPidByLocalEndpointV6_.reserve(udpTableV6->dwNumEntries);
                            for (DWORD index = 0; index < udpTableV6->dwNumEntries; ++index)
                            {
                                const MIB_UDP6ROW_OWNER_PID& row = udpTableV6->table[index];
                                Ipv6Bytes localIpv6{};
                                std::memcpy(localIpv6.data(), row.ucLocalAddr, localIpv6.size());
                                const std::uint16_t kLocalPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint32_t kOwnerPid = row.dwOwningPid;
                                const Ipv6LocalEndpointKey kLocalKey{ localIpv6, kLocalPort };
                                udpPidByLocalEndpointV6_[kLocalKey] = kOwnerPid;
                            }
                        }
                    }
                }
            }

        private:
            std::uint64_t lastRefreshTickMs_ = 0; // timestamp of the last connection table refresh.

            // TCP mapping (exact four-tuple).
            std::unordered_map<TcpEndpointKey, std::uint32_t, TcpEndpointKeyHasher> tcpPidByQuad_;

            // TCP mapping (local endpoint fallback).
            std::unordered_map<std::uint64_t, std::uint32_t> tcpPidByLocalEndpoint_;

            // UDP mapping (local endpoint).
            std::unordered_map<std::uint64_t, std::uint32_t> udpPidByLocalEndpoint_;

            // TCP IPv6 mapping (four-tuple exact).
            std::unordered_map<TcpEndpointKeyV6, std::uint32_t, TcpEndpointKeyV6Hasher> tcpPidByQuadV6_;

            // TCP IPv6 mapping (local endpoint fallback).
            std::unordered_map<Ipv6LocalEndpointKey, std::uint32_t, Ipv6LocalEndpointKeyHasher> tcpPidByLocalEndpointV6_;

            // UDP IPv6 mapping (local endpoint).
            std::unordered_map<Ipv6LocalEndpointKey, std::uint32_t, Ipv6LocalEndpointKeyHasher> udpPidByLocalEndpointV6_;
        };

        // ProcessNameResolver：
        // - Provide a lightweight cache for PIDs to avoid querying process names across processes for every packet.
        class ProcessNameResolver final
        {
        public:
            // resolveProcessName: Resolves and caches the process name.
            std::string resolveProcessName(const std::uint32_t processId)
            {
                if (processId == 0)
                {
                    return std::string();
                }

                const std::uint64_t kNowTickMs = nowTickMs();
                const auto kCacheIterator = cacheByPid_.find(processId);
                if (kCacheIterator != cacheByPid_.end())
                {
                    constexpr std::uint64_t kCacheTtlMs = 2500;
                    if (kNowTickMs - kCacheIterator->second.lastUpdateTickMs <= kCacheTtlMs)
                    {
                        return kCacheIterator->second.processName;
                    }
                }

                std::string processName = ks::process::getProcessNameByPid(processId);
                if (processName.empty())
                {
                    processName = std::string("PID-") + std::to_string(processId);
                }

                CacheEntry cacheEntry;
                cacheEntry.processName = processName;
                cacheEntry.lastUpdateTickMs = kNowTickMs;
                cacheByPid_[processId] = cacheEntry;
                return processName;
            }

        private:
            // CacheEntry: Process name cache entry.
            struct CacheEntry
            {
                std::string processName;           // Cached process name.
                std::uint64_t lastUpdateTickMs = 0;// Update timestamp.
            };

            std::unordered_map<std::uint32_t, CacheEntry> cacheByPid_; // PID to name cache.
        };
    } // namespace detail

    // TrafficMonitorService：
    // - Exposes Start/Stop and callback registration externally;
    // - Internal thread responsible for packet capture, PID resolution, and rate limiting control.
    class TrafficMonitorService final
    {
    public:
        // PacketCallback: Report a single packet record.
        using PacketCallback = std::function<void(const PacketRecord&)>;

        // StatusCallback: Reports status text (startup failure, thread stop, permission prompts, etc.).
        using StatusCallback = std::function<void(const std::string&)>;

        // RateLimitActionCallback: Report rate-limiting action events (suspend/resume).
        using RateLimitActionCallback = std::function<void(const RateLimitActionEvent&)>;

    public:
        // Constructor: initializes state without starting threads.
        TrafficMonitorService() = default;

        // Destructor: ensures threads are stopped and resources are released.
        ~TrafficMonitorService()
        {
            stopCapture();
        }

        // setPacketCallback: Set packet callback.
        void setPacketCallback(PacketCallback callback)
        {
            std::lock_guard<std::mutex> guard(stateMutex_);
            packetCallback_ = std::move(callback);
        }

        // setStatusCallback: Set status callback.
        void setStatusCallback(StatusCallback callback)
        {
            std::lock_guard<std::mutex> guard(stateMutex_);
            statusCallback_ = std::move(callback);
        }

        // setRateLimitActionCallback: sets the rate limit action callback.
        void setRateLimitActionCallback(RateLimitActionCallback callback)
        {
            std::lock_guard<std::mutex> guard(stateMutex_);
            rateLimitActionCallback_ = std::move(callback);
        }

        // startCapture：
        // - Start the background packet capture thread.
        // - Return true immediately if already running.
        bool startCapture()
        {
            if (running_.load(std::memory_order_relaxed))
            {
                return true;
            }

            // If the previous thread has naturally exited but hasn't been joined yet, clean it up here first.
            if (captureThread_.joinable())
            {
                captureThread_.join();
            }

            running_.store(true, std::memory_order_relaxed);
            try
            {
                captureThread_ = std::thread([this]() { runCaptureThread(); });
            }
            catch (...)
            {
                running_.store(false, std::memory_order_relaxed);
                emitStatus("抓包线程创建失败。");
                return false;
            }
            return true;
        }

        // stopCapture：
        // - Request thread exit;
        // - Block and wait for thread cleanup (including resuming processes suspended due to rate limiting).
        void stopCapture()
        {
            running_.store(false, std::memory_order_relaxed);
            if (captureThread_.joinable())
            {
                captureThread_.join();
            }
        }

        // isRunning: Check if the packet capture thread is running.
        bool isRunning() const
        {
            return running_.load(std::memory_order_relaxed);
        }

        // upsertRateLimitRule：
        // - Adds or updates a rate-limit rule for a specific PID + creation time;
        // - Reject creation when process identity or rate limit is missing to avoid erroneous operations after PID recycling.
        void upsertRateLimitRule(const ProcessRateLimitRule& inputRule)
        {
            if (inputRule.processId == 0 ||
                inputRule.processCreationTime100ns == 0 ||
                inputRule.bytesPerSecond == 0)
            {
                return;
            }

            ProcessRateLimitRule sanitizedRule = inputRule;
            sanitizedRule.suspendDurationMs = std::clamp<std::uint32_t>(sanitizedRule.suspendDurationMs, 50, 2000);

            bool needResumeExistingProcess = false;
            ProcessRateLimitRule existingRule{};
            {
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                RateLimitRuntime& runtime = rateLimitByPid_[sanitizedRule.processId];
                needResumeExistingProcess = runtime.currentlySuspended;
                existingRule = runtime.rule;
                runtime.rule = sanitizedRule;
                runtime.windowStartTickMs = detail::nowTickMs();
                runtime.currentWindowBytes = 0;
                runtime.currentlySuspended = false;
                runtime.resumeTickMs = 0;
                // triggerCount: Retains history for UI to view the total trigger count.
            }

            // Only resume instances matching the old rule identity to avoid mistakenly resuming other processes when the PID has been recycled.
            if (needResumeExistingProcess)
            {
                std::string ignoredDetailText;
                (void)ks::process::resumeProcessIfCreationTimeMatches(
                    existingRule.processId,
                    existingRule.processCreationTime100ns,
                    &ignoredDetailText);
            }
        }

        // removeRateLimitRule: remove the rate limit rule for the specified PID.
        bool removeRateLimitRule(const std::uint32_t processId)
        {
            if (processId == 0)
            {
                return false;
            }

            bool needResumeProcess = false;
            ProcessRateLimitRule existingRule{};
            {
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                const auto kIterator = rateLimitByPid_.find(processId);
                if (kIterator == rateLimitByPid_.end())
                {
                    return false;
                }
                needResumeProcess = kIterator->second.currentlySuspended;
                existingRule = kIterator->second.rule;
                rateLimitByPid_.erase(kIterator);
            }

            // When deleting a rule, restore only the original instance to avoid affecting new processes after PID recycling.
            if (needResumeProcess)
            {
                std::string ignoredDetailText;
                (void)ks::process::resumeProcessIfCreationTimeMatches(
                    existingRule.processId,
                    existingRule.processCreationTime100ns,
                    &ignoredDetailText);
            }
            return true;
        }

        // clearRateLimitRules: Clear all rate-limiting rules.
        void clearRateLimitRules()
        {
            std::vector<ProcessRateLimitRule> rulesNeedResume;
            {
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                rulesNeedResume.reserve(rateLimitByPid_.size());
                for (const auto& [processId, runtime] : rateLimitByPid_)
                {
                    (void)processId;
                    if (runtime.currentlySuspended)
                    {
                        rulesNeedResume.push_back(runtime.rule);
                    }
                }
                rateLimitByPid_.clear();
            }

            // When bulk-clearing rules, restore only the original process instances saved for each rule.
            for (const ProcessRateLimitRule& limitRule : rulesNeedResume)
            {
                std::string ignoredDetailText;
                (void)ks::process::resumeProcessIfCreationTimeMatches(
                    limitRule.processId,
                    limitRule.processCreationTime100ns,
                    &ignoredDetailText);
            }
        }

        // snapshotRateLimitRules：
        // - Returns a snapshot of rate-limiting rules (thread-safe);
        // - UI can be used directly for table refresh.
        std::vector<ProcessRateLimitSnapshot> snapshotRateLimitRules() const
        {
            std::vector<ProcessRateLimitSnapshot> snapshotList;
            std::lock_guard<std::mutex> guard(rateLimitMutex_);
            snapshotList.reserve(rateLimitByPid_.size());

            for (const auto& [processId, runtime] : rateLimitByPid_)
            {
                (void)processId;
                ProcessRateLimitSnapshot snapshot;
                snapshot.rule = runtime.rule;
                snapshot.currentWindowBytes = runtime.currentWindowBytes;
                snapshot.triggerCount = runtime.triggerCount;
                snapshot.currentlySuspended = runtime.currentlySuspended;
                snapshotList.push_back(snapshot);
            }

            std::sort(
                snapshotList.begin(),
                snapshotList.end(),
                [](const ProcessRateLimitSnapshot& left, const ProcessRateLimitSnapshot& right)
                {
                    return left.rule.processId < right.rule.processId;
                });

            return snapshotList;
        }

    private:
        // RateLimitRuntime: Runtime state of the rate limiting rule.
        struct RateLimitRuntime
        {
            ProcessRateLimitRule rule;          // User configuration.
            std::uint64_t windowStartTickMs = 0;// Start time (ms) of the current statistics window.
            std::uint64_t currentWindowBytes = 0;// Current window cumulative sent bytes.
            bool currentlySuspended = false;    // Whether currently suspended by this component.
            std::uint64_t resumeTickMs = 0;     // Scheduled resume timestamp.
            std::uint64_t triggerCount = 0;     // Historical trigger count.
        };

    private:
        // runCaptureThread: Main loop of the background thread.
        void runCaptureThread()
        {
            // initialize WinSock after thread startup.
            WSADATA wsaData{};
            const int kStartupResult = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (kStartupResult != 0)
            {
                std::ostringstream stream;
                stream << "WSAStartup 失败: " << detail::makeWinSockErrorText(kStartupResult);
                emitStatus(stream.str());
                running_.store(false, std::memory_order_relaxed);
                return;
            }

            // Open all available Raw Sockets (binding one by one to active IPv4/IPv6 interfaces).
            std::string socketOpenError;
            std::vector<detail::CaptureSocketEntry> captureSockets = detail::openCaptureSockets(&socketOpenError);
            if (captureSockets.empty())
            {
                std::ostringstream stream;
                stream << "网络监控启动失败: " << socketOpenError;
                emitStatus(stream.str());
                ::WSACleanup();
                running_.store(false, std::memory_order_relaxed);
                return;
            }

            {
                std::size_t ipv4SocketCount = 0;
                std::size_t ipv6SocketCount = 0;
                std::size_t ipLevelFallbackCount = 0;
                for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
                {
                    if (socketEntry.addressFamily == AF_INET)
                    {
                        ++ipv4SocketCount;
                    }
                    else if (socketEntry.addressFamily == AF_INET6)
                    {
                        ++ipv6SocketCount;
                    }
                    if (socketEntry.captureMode == RCVALL_IPLEVEL)
                    {
                        ++ipLevelFallbackCount;
                    }
                }

                std::ostringstream stream;
                stream << "网络监控已启动，绑定接口数: " << captureSockets.size()
                    << "（IPv4=" << ipv4SocketCount
                    << ", IPv6=" << ipv6SocketCount
                    << ", IPLEVEL兜底=" << ipLevelFallbackCount
                    << "）";
                emitStatus(stream.str());
            }

            // Build the set of local addresses for fast packet direction determination.
            std::unordered_set<std::uint32_t> localIpv4Set;
            std::unordered_set<detail::Ipv6Bytes, detail::Ipv6BytesHasher> localIpv6Set;
            for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
            {
                if (socketEntry.addressFamily == AF_INET)
                {
                    localIpv4Set.insert(socketEntry.localIpv4HostOrder);
                }
                else if (socketEntry.addressFamily == AF_INET6)
                {
                    localIpv6Set.insert(socketEntry.localIpv6Bytes);
                }
            }

            // Add loopback addresses:
            // - Loopback addresses may not appear in the enumeration of active network adapters in some environments.
            // - Pre-adding to the set avoids misjudging the direction as Unknown.
            localIpv4Set.insert(0x7F000001U); // 127.0.0.1
            detail::Ipv6Bytes ipv6Loopback{};
            ipv6Loopback[15] = 1;             // ::1
            localIpv6Set.insert(ipv6Loopback);

            detail::ConnectionPidResolver pidResolver;
            detail::ProcessNameResolver processNameResolver;
            std::vector<std::uint8_t> receiveBuffer(65536, 0);

            // Packet capture loop: select wait + recv read + parse + callback.
            while (running_.load(std::memory_order_relaxed))
            {
                const std::uint64_t kNowTickMs = detail::nowTickMs();

                // Process rate-limiting tasks marked for resumption first in each round to prevent processes from hanging for extended periods.
                consumeResumeActions(kNowTickMs);

                fd_set readSet{};
                FD_ZERO(&readSet);
                for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
                {
                    if (socketEntry.socketValue != INVALID_SOCKET)
                    {
                        FD_SET(socketEntry.socketValue, &readSet);
                    }
                }

                // Polling interval further reduced to 25ms:
                // - Reduce socket kernel buffer residency time to lower the probability of packet loss in burst scenarios;
                // - More friendly to capturing short UDP packets and short connections.
                timeval timeout{};
                timeout.tv_sec = 0;
                timeout.tv_usec = 25000;
                const int kSelectResult = ::select(0, &readSet, nullptr, nullptr, &timeout);
                if (kSelectResult == SOCKET_ERROR)
                {
                    const int kSelectError = ::WSAGetLastError();
                    std::ostringstream stream;
                    stream << "select 失败: " << detail::makeWinSockErrorText(kSelectError);
                    emitStatus(stream.str());
                    break;
                }

                if (kSelectResult <= 0)
                {
                    continue;
                }

                for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
                {
                    if (socketEntry.socketValue == INVALID_SOCKET)
                    {
                        continue;
                    }
                    if (FD_ISSET(socketEntry.socketValue, &readSet) == 0)
                    {
                        continue;
                    }

                    // maxPacketsPerSocketPerTick purpose: maximum packets pulled per tick for a single socket to prevent starvation of other interfaces on high-traffic ones.
                    // Increasing the limit reduces backlog accumulation under high traffic and improves retention rates for UDP/inbound burst packets.
                    constexpr std::size_t kMaxPacketsPerSocketPerTick = 1024;
                    std::size_t consumedPacketCount = 0;
                    while (running_.load(std::memory_order_relaxed) &&
                        consumedPacketCount < kMaxPacketsPerSocketPerTick)
                    {
                        const int kReceivedLength = ::recv(
                            socketEntry.socketValue,
                            reinterpret_cast<char*>(receiveBuffer.data()),
                            static_cast<int>(receiveBuffer.size()),
                            0);
                        if (kReceivedLength <= 0)
                        {
                            // recvError purpose: Distinguish between 'currently read empty' (wouldblock) and actual errors.
                            const int kRecvError = ::WSAGetLastError();
                            if (kRecvError == WSAEWOULDBLOCK || kRecvError == WSAETIMEDOUT)
                            {
                                break;
                            }
                            // Real anomaly: Exit the current socket in this round and let the next round of select attempt it.
                            break;
                        }
                        ++consumedPacketCount;

                        PacketRecord packetRecord;
                        bool parseOk = false;
                        if (socketEntry.addressFamily == AF_INET)
                        {
                            parseOk = detail::parseIpv4Packet(
                                receiveBuffer.data(),
                                static_cast<std::size_t>(kReceivedLength),
                                localIpv4Set,
                                packetRecord);
                        }
                        else if (socketEntry.addressFamily == AF_INET6)
                        {
                            parseOk = detail::parseIpv6Packet(
                                receiveBuffer.data(),
                                static_cast<std::size_t>(kReceivedLength),
                                localIpv6Set,
                                packetRecord);
                        }
                        if (!parseOk)
                        {
                            continue;
                        }

                        // captureTickMs usage: multiple records derived from the same original packet (in the local dual-endpoint scenario) share the same capture timestamp.
                        const std::uint64_t kCaptureTickMs = detail::nowTickMs();

                        // finalizeAndEmitRecord purpose:
                        // - Assign sequence number and timestamp to the record.
                        // - Parse process name.
                        // - Perform rate-limiting checks and report to the UI.
                        auto finalizeAndEmitRecord = [&](PacketRecord& record)
                            {
                                record.sequenceId = packetSequence_.fetch_add(1, std::memory_order_relaxed) + 1;
                                record.captureTimestampMs = kCaptureTickMs;
                                record.processName = processNameResolver.resolveProcessName(record.processId);
                                consumeRateLimitForPacket(record);
                                emitPacket(record);
                            };

                        // Port mapping: PID + name cache resolution.
                        if (socketEntry.addressFamily == AF_INET)
                        {
                            // sourceIpv4Host/destinationIpv4Host usage: Preserve the original packet source/destination addresses (host byte order).
                            const std::uint32_t kSourceIpv4Host = detail::readNetworkUInt32(receiveBuffer.data() + 12);
                            const std::uint32_t kDestinationIpv4Host = detail::readNetworkUInt32(receiveBuffer.data() + 16);

                            // Local-to-local endpoint communication: the same original packet is split into Outbound and Inbound records to avoid 'all inbound packets missing'.
                            if (packetRecord.localToLocalAmbiguous)
                            {
                                PacketRecord outboundRecord = packetRecord;
                                outboundRecord.direction = PacketDirection::kOutbound;
                                outboundRecord.localAddress = detail::ipv4HostToString(kSourceIpv4Host);
                                outboundRecord.localPort = packetRecord.localPort;
                                outboundRecord.remoteAddress = detail::ipv4HostToString(kDestinationIpv4Host);
                                outboundRecord.remotePort = packetRecord.remotePort;
                                outboundRecord.localToLocalAmbiguous = false;
                                outboundRecord.processId = pidResolver.resolveProcessId(
                                    outboundRecord.protocol,
                                    kSourceIpv4Host,
                                    outboundRecord.localPort,
                                    kDestinationIpv4Host,
                                    outboundRecord.remotePort);

                                PacketRecord inboundRecord = packetRecord;
                                inboundRecord.direction = PacketDirection::kInbound;
                                inboundRecord.localAddress = detail::ipv4HostToString(kDestinationIpv4Host);
                                inboundRecord.localPort = packetRecord.remotePort;
                                inboundRecord.remoteAddress = detail::ipv4HostToString(kSourceIpv4Host);
                                inboundRecord.remotePort = packetRecord.localPort;
                                inboundRecord.localToLocalAmbiguous = false;
                                inboundRecord.processId = pidResolver.resolveProcessId(
                                    inboundRecord.protocol,
                                    kDestinationIpv4Host,
                                    inboundRecord.localPort,
                                    kSourceIpv4Host,
                                    inboundRecord.remotePort);

                                finalizeAndEmitRecord(outboundRecord);
                                finalizeAndEmitRecord(inboundRecord);
                                continue;
                            }

                            // localIpv4Host/remoteIpv4Host usage: unify address semantics to 'local host is local'.
                            std::uint32_t localIpv4Host = kSourceIpv4Host;
                            std::uint32_t remoteIpv4Host = kDestinationIpv4Host;
                            if (packetRecord.direction == PacketDirection::kInbound)
                            {
                                localIpv4Host = kDestinationIpv4Host;
                                remoteIpv4Host = kSourceIpv4Host;
                            }
                            packetRecord.processId = pidResolver.resolveProcessId(
                                packetRecord.protocol,
                                localIpv4Host,
                                packetRecord.localPort,
                                remoteIpv4Host,
                                packetRecord.remotePort);
                            packetRecord.localToLocalAmbiguous = false;
                            finalizeAndEmitRecord(packetRecord);
                        }
                        else if (socketEntry.addressFamily == AF_INET6)
                        {
                            const detail::Ipv6Bytes kSourceIpv6 = detail::readIpv6Bytes(receiveBuffer.data() + 8);
                            const detail::Ipv6Bytes kDestinationIpv6 = detail::readIpv6Bytes(receiveBuffer.data() + 24);

                            // IPv6 local-to-local communication is also split into bidirectional records to supplement inbound statistics and filtering capabilities.
                            if (packetRecord.localToLocalAmbiguous)
                            {
                                PacketRecord outboundRecord = packetRecord;
                                outboundRecord.direction = PacketDirection::kOutbound;
                                outboundRecord.localAddress = detail::ipv6BytesToString(kSourceIpv6);
                                outboundRecord.localPort = packetRecord.localPort;
                                outboundRecord.remoteAddress = detail::ipv6BytesToString(kDestinationIpv6);
                                outboundRecord.remotePort = packetRecord.remotePort;
                                outboundRecord.localToLocalAmbiguous = false;
                                outboundRecord.processId = pidResolver.resolveProcessIdV6(
                                    outboundRecord.protocol,
                                    kSourceIpv6,
                                    outboundRecord.localPort,
                                    kDestinationIpv6,
                                    outboundRecord.remotePort);

                                PacketRecord inboundRecord = packetRecord;
                                inboundRecord.direction = PacketDirection::kInbound;
                                inboundRecord.localAddress = detail::ipv6BytesToString(kDestinationIpv6);
                                inboundRecord.localPort = packetRecord.remotePort;
                                inboundRecord.remoteAddress = detail::ipv6BytesToString(kSourceIpv6);
                                inboundRecord.remotePort = packetRecord.localPort;
                                inboundRecord.localToLocalAmbiguous = false;
                                inboundRecord.processId = pidResolver.resolveProcessIdV6(
                                    inboundRecord.protocol,
                                    kDestinationIpv6,
                                    inboundRecord.localPort,
                                    kSourceIpv6,
                                    inboundRecord.remotePort);

                                finalizeAndEmitRecord(outboundRecord);
                                finalizeAndEmitRecord(inboundRecord);
                                continue;
                            }

                            detail::Ipv6Bytes localIpv6 = kSourceIpv6;
                            detail::Ipv6Bytes remoteIpv6 = kDestinationIpv6;
                            if (packetRecord.direction == PacketDirection::kInbound)
                            {
                                localIpv6 = kDestinationIpv6;
                                remoteIpv6 = kSourceIpv6;
                            }
                            packetRecord.processId = pidResolver.resolveProcessIdV6(
                                packetRecord.protocol,
                                localIpv6,
                                packetRecord.localPort,
                                remoteIpv6,
                                packetRecord.remotePort);
                            packetRecord.localToLocalAmbiguous = false;
                            finalizeAndEmitRecord(packetRecord);
                        }
                    }
                }
            }

            // Restore all processes suspended by this module before thread exit to avoid residual impact.
            forceResumeAllSuspendedProcesses();

            detail::closeCaptureSockets(captureSockets);
            ::WSACleanup();

            running_.store(false, std::memory_order_relaxed);
            emitStatus("网络监控已停止。");
        }

        // consumeRateLimitForPacket：
        // - Update the send window statistics for the corresponding PID for a single packet;
        // - Trigger suspendProcess if the limit is exceeded;
        void consumeRateLimitForPacket(const PacketRecord& packetRecord)
        {
            // Rate-limiting policies apply only to the 'outbound' direction; inbound traffic is excluded from threshold statistics.
            if (packetRecord.direction != PacketDirection::kOutbound)
            {
                return;
            }

            if (packetRecord.processId == 0)
            {
                return;
            }

            std::optional<RateLimitActionEvent> suspendEvent;
            std::uint64_t expectedCreationTime100ns = 0U;
            {
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                const auto kIterator = rateLimitByPid_.find(packetRecord.processId);
                if (kIterator == rateLimitByPid_.end())
                {
                    return;
                }

                RateLimitRuntime& runtime = kIterator->second;
                if (!runtime.rule.enabled || runtime.rule.bytesPerSecond == 0)
                {
                    return;
                }

                const std::uint64_t kNowTickMs = packetRecord.captureTimestampMs;
                if (runtime.windowStartTickMs == 0 || kNowTickMs - runtime.windowStartTickMs >= 1000)
                {
                    runtime.windowStartTickMs = kNowTickMs;
                    runtime.currentWindowBytes = 0;
                }

                runtime.currentWindowBytes += packetRecord.totalPacketSize;
                if (runtime.currentlySuspended)
                {
                    return;
                }

                if (runtime.currentWindowBytes > runtime.rule.bytesPerSecond)
                {
                    runtime.currentlySuspended = true;
                    runtime.resumeTickMs = kNowTickMs + runtime.rule.suspendDurationMs;
                    runtime.triggerCount += 1;

                    RateLimitActionEvent event;
                    event.timestampMs = kNowTickMs;
                    event.processId = runtime.rule.processId;
                    event.actionType = RateLimitActionType::kSuspendProcess;
                    event.actionSucceeded = false;
                    event.configuredBytesPerSecond = runtime.rule.bytesPerSecond;
                    event.detailText = "触发限速，准备挂起进程。";
                    expectedCreationTime100ns = runtime.rule.processCreationTime100ns;
                    suspendEvent = event;
                }
            }

            if (!suspendEvent.has_value())
            {
                return;
            }

            std::string detailText;
            const bool kSuspendOk = ks::process::suspendProcessIfCreationTimeMatches(
                packetRecord.processId,
                expectedCreationTime100ns,
                &detailText);
            suspendEvent->actionSucceeded = kSuspendOk;
            if (kSuspendOk)
            {
                suspendEvent->detailText = "限速触发：进程已挂起。";
            }
            else
            {
                suspendEvent->detailText = "限速触发失败（挂起失败）: " + detailText;

                // If suspension fails, immediately roll back the "suspended" state to prevent subsequent logic from misinterpreting it.
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                const auto kIterator = rateLimitByPid_.find(packetRecord.processId);
                if (kIterator != rateLimitByPid_.end() &&
                    kIterator->second.rule.processCreationTime100ns == expectedCreationTime100ns)
                {
                    kIterator->second.currentlySuspended = false;
                    kIterator->second.resumeTickMs = 0;
                }
            }

            emitRateLimitAction(*suspendEvent);
        }

        // consumeResumeActions：
        // - Scan all rules to find PIDs that have reached their resume time;
        // - Execute resumeProcess and report the action event.
        void consumeResumeActions(const std::uint64_t nowTickMs)
        {
            std::vector<ProcessRateLimitRule> rulesToResume;
            {
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                for (auto& [processId, runtime] : rateLimitByPid_)
                {
                    (void)processId;
                    if (!runtime.currentlySuspended)
                    {
                        continue;
                    }
                    if (runtime.resumeTickMs > nowTickMs)
                    {
                        continue;
                    }

                    runtime.currentlySuspended = false;
                    runtime.resumeTickMs = 0;
                    rulesToResume.push_back(runtime.rule);
                }
            }

            for (const ProcessRateLimitRule& limitRule : rulesToResume)
            {
                std::string detailText;
                const bool kResumeOk = ks::process::resumeProcessIfCreationTimeMatches(
                    limitRule.processId,
                    limitRule.processCreationTime100ns,
                    &detailText);

                RateLimitActionEvent event;
                event.timestampMs = nowTickMs;
                event.processId = limitRule.processId;
                event.actionType = RateLimitActionType::kResumeProcess;
                event.actionSucceeded = kResumeOk;
                event.configuredBytesPerSecond = 0;
                event.detailText = kResumeOk
                    ? "限速窗口结束：进程已恢复。"
                    : ("进程恢复失败: " + detailText);
                emitRateLimitAction(event);
            }
        }

        // forceResumeAllSuspendedProcesses：
        // - Execute during thread exit phase;
        // - Ensure no processes remain in a "rate-limited suspended" state.
        void forceResumeAllSuspendedProcesses()
        {
            std::vector<ProcessRateLimitRule> rulesToResume;
            {
                std::lock_guard<std::mutex> guard(rateLimitMutex_);
                for (auto& [processId, runtime] : rateLimitByPid_)
                {
                    (void)processId;
                    if (!runtime.currentlySuspended)
                    {
                        continue;
                    }
                    runtime.currentlySuspended = false;
                    runtime.resumeTickMs = 0;
                    rulesToResume.push_back(runtime.rule);
                }
            }

            for (const ProcessRateLimitRule& limitRule : rulesToResume)
            {
                std::string detailText;
                const bool kResumeOk = ks::process::resumeProcessIfCreationTimeMatches(
                    limitRule.processId,
                    limitRule.processCreationTime100ns,
                    &detailText);

                RateLimitActionEvent event;
                event.timestampMs = detail::nowTickMs();
                event.processId = limitRule.processId;
                event.actionType = RateLimitActionType::kResumeProcess;
                event.actionSucceeded = kResumeOk;
                event.configuredBytesPerSecond = 0;
                event.detailText = kResumeOk
                    ? "监控停止：已恢复此前挂起的进程。"
                    : ("监控停止：恢复进程失败: " + detailText);
                emitRateLimitAction(event);
            }
        }

        // emitPacket: Trigger packet callback (thread-safe copy of callback object).
        void emitPacket(const PacketRecord& packetRecord) const
        {
            PacketCallback callbackCopy;
            {
                std::lock_guard<std::mutex> guard(stateMutex_);
                callbackCopy = packetCallback_;
            }
            if (callbackCopy)
            {
                callbackCopy(packetRecord);
            }
        }

        // emitStatus: Trigger status callback.
        void emitStatus(const std::string& statusText) const
        {
            StatusCallback callbackCopy;
            {
                std::lock_guard<std::mutex> guard(stateMutex_);
                callbackCopy = statusCallback_;
            }
            if (callbackCopy)
            {
                callbackCopy(statusText);
            }
        }

        // emitRateLimitAction: Trigger rate-limit action callback.
        void emitRateLimitAction(const RateLimitActionEvent& actionEvent) const
        {
            RateLimitActionCallback callbackCopy;
            {
                std::lock_guard<std::mutex> guard(stateMutex_);
                callbackCopy = rateLimitActionCallback_;
            }
            if (callbackCopy)
            {
                callbackCopy(actionEvent);
            }
        }

    private:
        mutable std::mutex stateMutex_; // Protects the callback function object.
        PacketCallback packetCallback_; // Packet event callback.
        StatusCallback statusCallback_; // Status text callback.
        RateLimitActionCallback rateLimitActionCallback_; // Rate limit action callback.

        std::atomic<bool> running_{ false }; // Packet capture thread running flag.
        std::thread captureThread_;          // Background packet capture thread object.
        std::atomic<std::uint64_t> packetSequence_{ 0 }; // Packet sequence generator.

        mutable std::mutex rateLimitMutex_; // Protects the rate-limit rule container.
        std::unordered_map<std::uint32_t, RateLimitRuntime> rateLimitByPid_; // PID -> rule runtime state.
    };
} // namespace ks::network

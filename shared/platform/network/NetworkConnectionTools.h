#pragma once

// ============================================================
// ksword/network/network_connection_tools.h
// Namespace:
// ks::network Purpose:
// 1) Enumerates TCP connection snapshots (including PID, process name, local/remote endpoints, and status);
// 2) enumerate UDP endpoint snapshots (including PID, process name, and local endpoint);
// 3) Supports terminating connections by executing DELETE_TCB based on specified TCP connection parameters.
//
// Design notes:
// - This file uses "inline implementation within header files" to avoid modifying project files when adding new .cpp files;
// - Intended for direct inclusion by NetworkDock and other tool modules.
// ============================================================

#include "../process/Process.h"

#include <algorithm>    // std::sort: sorting snapshots for stable UI display.
#include <cstddef>      // std::size_t: Container index and length.
#include <cstdint>      // Fixed-width integers: fields such as PID, IP, and Port.
#include <cstring>      // std::memset: Zero-initialize structure for protection.
#include <sstream>      // std::ostringstream: Error details and four-tuple diagnostic text.
#include <string>       // std::string: Cross-layer text representation.
#include <unordered_map>// PID -> Process name cache to avoid repeated queries.
#include <utility>      // std::move: Record object move into container.
#include <vector>       // Snapshot output container.

// Winsock / IP Helper headers:
// - WinSock2 must be included before winsock.h in the windows.h chain.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Iphlpapi.h>

// Link dependencies:
// - Iphlpapi：GetExtendedTcpTable/GetExtendedUdpTable/SetTcpEntry；
// - Ws2_32: Network conversion functions such as inet_ntop, htons, and htonl.
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace ks::network
{
    // TcpConnectionRecord：
    // - TCP connection snapshot record;
    // - Retains both text and host-byte addresses to support UI display and connection control.
    struct TcpConnectionRecord
    {
        std::uint32_t processId = 0;           // Associated process PID.
        std::string processName;               // Name of the owning process (may be empty).
        bool isIpv6 = false;                   // Address family identifier: false=IPv4, true=IPv6.

        std::uint32_t localIpv4HostOrder = 0;  // Local IPv4 (host byte order, used when terminating connections).
        std::uint32_t localIpv4NetworkOrder = 0; // Local IPv4 (network-order raw value; prefer this when submitting to SetTcpEntry).
        std::uint16_t localPort = 0;           // Local port (host byte order).
        std::uint32_t localPortNetworkOrder = 0; // Local port (IP Helper raw DWORD, preserving high bits to maintain compatibility with Windows table layout).
        std::string localAddressText;          // Local address text (IPv4/IPv6).

        std::uint32_t remoteIpv4HostOrder = 0; // Remote IPv4 (host byte order; used when terminating the connection).
        std::uint32_t remoteIpv4NetworkOrder = 0; // Remote IPv4 (network-order raw value, preferred when submitting to SetTcpEntry).
        std::uint16_t remotePort = 0;          // Remote port (host byte order).
        std::uint32_t remotePortNetworkOrder = 0; // Remote port (raw DWORD from IP Helper, preserving high bits to maintain compatibility with Windows table layout).
        std::string remoteAddressText;         // Remote address text (IPv4/IPv6).

        std::uint32_t tcpStateCode = 0;        // Raw value of MIB_TCP_STATE_*.
        std::string tcpStateText;              // Status text (e.g., ESTABLISHED, LISTEN).
    };

    // UdpEndpointRecord：
    // - UDP endpoint snapshot record;
    // - UDP has no "connection state"; only local endpoint + process ownership are retained.
    struct UdpEndpointRecord
    {
        std::uint32_t processId = 0;           // Associated process PID.
        std::string processName;               // Name of the owning process (may be empty).
        bool isIpv6 = false;                   // Address family identifier: false=IPv4, true=IPv6.

        std::uint32_t localIpv4HostOrder = 0;  // Local IPv4 (host byte order).
        std::uint16_t localPort = 0;           // Local port (host byte order).
        std::string localAddressText;          // Local address text (IPv4/IPv6).
    };

    namespace connection_detail
    {
        // ipv4NetworkOrderToText：
        // - Convert 'Network-order IPv4' to dotted-decimal text;
        // - Fallback to "0.0.0.0" on failure.
        inline std::string ipv4NetworkOrderToText(const std::uint32_t ipv4NetworkOrder)
        {
            in_addr ipv4Address{};
            ipv4Address.s_addr = ipv4NetworkOrder;

            char ipv4TextBuffer[INET_ADDRSTRLEN] = {};
            const PCSTR kConvertResult = ::inet_ntop(
                AF_INET,
                &ipv4Address,
                ipv4TextBuffer,
                static_cast<socklen_t>(sizeof(ipv4TextBuffer)));
            if (kConvertResult == nullptr)
            {
                return std::string("0.0.0.0");
            }
            return std::string(ipv4TextBuffer);
        }

        // ipv6BytesToText：
        // - Convert a 16-byte IPv6 address to standard text format.
        // - On failure, fall back to "::".
        inline std::string ipv6BytesToText(const UCHAR ipv6Bytes[16])
        {
            IN6_ADDR ipv6Address{};
            std::memcpy(&ipv6Address, ipv6Bytes, sizeof(ipv6Address));

            char ipv6TextBuffer[INET6_ADDRSTRLEN] = {};
            const PCSTR kConvertResult = ::inet_ntop(
                AF_INET6,
                &ipv6Address,
                ipv6TextBuffer,
                static_cast<socklen_t>(sizeof(ipv6TextBuffer)));
            if (kConvertResult == nullptr)
            {
                return std::string("::");
            }
            return std::string(ipv6TextBuffer);
        }

        // tcpStateCodeToText：
        // - Convert MIB_TCP_STATE_* status codes to human-readable text.
        // - Unrecognized states uniformly return "UNKNOWN".
        inline std::string tcpStateCodeToText(const std::uint32_t stateCode)
        {
            switch (stateCode)
            {
            case MIB_TCP_STATE_CLOSED:      return "CLOSED";
            case MIB_TCP_STATE_LISTEN:      return "LISTEN";
            case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RECV";
            case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
            case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
            case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:     return "CLOSING";
            case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
            default:                        return "UNKNOWN";
            }
        }

        // fillProcessNameCacheIfNeeded：
        // - Lazily query the process name for the PID and write to cache;
        // - Avoid repeated calls to the Query API in the large connection table to prevent performance waste.
        inline const std::string& fillProcessNameCacheIfNeeded(
            const std::uint32_t processId,
            std::unordered_map<std::uint32_t, std::string>& processNameCache)
        {
            const auto kCacheIterator = processNameCache.find(processId);
            if (kCacheIterator != processNameCache.end())
            {
                return kCacheIterator->second;
            }

            const std::string kProcessName = ks::process::getProcessNameByPid(processId);
            const auto kInsertResult = processNameCache.insert({ processId, kProcessName });
            return kInsertResult.first->second;
        }

        // isIpv4TcpEndpointEqual：
        // - Input: a current system TCP row and a UI cached connection record;
        // - Processing: Compare IPv4 four-tuples item by item, and optionally compare PID.
        // - Returns: true if a complete match, otherwise false.
        inline bool isIpv4TcpEndpointEqual(
            const MIB_TCPROW_OWNER_PID& row,
            const TcpConnectionRecord& connectionRecord,
            const bool compareProcessId)
        {
            if (connectionRecord.isIpv6)
            {
                return false;
            }
            if (compareProcessId &&
                static_cast<std::uint32_t>(row.dwOwningPid) != connectionRecord.processId)
            {
                return false;
            }
            const std::uint32_t kRowLocalPort = row.dwLocalPort & 0xFFFFU;
            const std::uint32_t kRowRemotePort = row.dwRemotePort & 0xFFFFU;
            const std::uint32_t kRecordLocalPort = connectionRecord.localPortNetworkOrder & 0xFFFFU;
            const std::uint32_t kRecordRemotePort = connectionRecord.remotePortNetworkOrder & 0xFFFFU;
            return row.dwLocalAddr == connectionRecord.localIpv4NetworkOrder &&
                row.dwRemoteAddr == connectionRecord.remoteIpv4NetworkOrder &&
                kRowLocalPort == kRecordLocalPort &&
                kRowRemotePort == kRecordRemotePort;
        }

        // buildDeleteTcpRowFromOwnerPidRow：
        // - Input: Raw IPv4 TCP row returned by GetExtendedTcpTable.
        // - Processing: Preserve the original address/port DWORD, only changing the status to DELETE_TCB.
        // - Returns: A MIB_TCPROW directly usable by SetTcpEntry.
        inline MIB_TCPROW buildDeleteTcpRowFromOwnerPidRow(const MIB_TCPROW_OWNER_PID& sourceRow)
        {
            MIB_TCPROW tcpRow{};
            std::memset(&tcpRow, 0, sizeof(tcpRow));
            tcpRow.dwState = MIB_TCP_STATE_DELETE_TCB;
            tcpRow.dwLocalAddr = sourceRow.dwLocalAddr;
            tcpRow.dwLocalPort = sourceRow.dwLocalPort;
            tcpRow.dwRemoteAddr = sourceRow.dwRemoteAddr;
            tcpRow.dwRemotePort = sourceRow.dwRemotePort;
            return tcpRow;
        }

        // buildDeleteTcpRowFromRecord：
        // - Input: IPv4 TCP record from UI cache;
        // - Processing: Prefer original network-order addresses/ports saved during enumeration; fall back to host-order conversion only if missing.
        // - Returns: A MIB_TCPROW directly usable by SetTcpEntry.
        inline MIB_TCPROW buildDeleteTcpRowFromRecord(const TcpConnectionRecord& connectionRecord)
        {
            MIB_TCPROW tcpRow{};
            std::memset(&tcpRow, 0, sizeof(tcpRow));
            tcpRow.dwState = MIB_TCP_STATE_DELETE_TCB;
            tcpRow.dwLocalAddr = connectionRecord.localIpv4NetworkOrder != 0
                ? connectionRecord.localIpv4NetworkOrder
                : htonl(connectionRecord.localIpv4HostOrder);
            tcpRow.dwRemoteAddr = connectionRecord.remoteIpv4NetworkOrder != 0
                ? connectionRecord.remoteIpv4NetworkOrder
                : htonl(connectionRecord.remoteIpv4HostOrder);
            tcpRow.dwLocalPort = connectionRecord.localPortNetworkOrder != 0
                ? static_cast<DWORD>(connectionRecord.localPortNetworkOrder & 0xFFFFU)
                : static_cast<DWORD>(htons(connectionRecord.localPort));
            tcpRow.dwRemotePort = connectionRecord.remotePortNetworkOrder != 0
                ? static_cast<DWORD>(connectionRecord.remotePortNetworkOrder & 0xFFFFU)
                : static_cast<DWORD>(htons(connectionRecord.remotePort));
            return tcpRow;
        }

        // getTcpTerminationUnsupportedReason：
        // - Input: UI cached TCP record;
        // - Processing: Reject unsupported termination cases in advance based on the capabilities of SetTcpEntry(DELETE_TCB);
        // - Returns: An empty string if termination is allowed; otherwise, a reason for the UI/log explaining why it is not allowed.
        inline std::string getTcpTerminationUnsupportedReason(const TcpConnectionRecord& connectionRecord)
        {
            // SetTcpEntry only accepts IPv4 MIB_TCPROW; IPv6 rows come from a different table and cannot be converted to MIB_TCPROW.
            if (connectionRecord.isIpv6)
            {
                return "IPv6 TCP 连接暂不支持通过 SetTcpEntry 终止。";
            }

            // LISTEN line represents a server listening endpoint, not an established connection TCB:
            // - Typical remote endpoint is 0.0.0.0:0;
            // - SetTcpEntry(DELETE_TCB) cannot close a listening socket.
            // - To release the port, the process or service holding the listening socket must be terminated or controlled.
            if (connectionRecord.tcpStateCode == MIB_TCP_STATE_LISTEN)
            {
                return "LISTEN 是监听端口，不是已建立 TCP 连接；SetTcpEntry(DELETE_TCB) 不能关闭监听 socket。请结束/停止持有该端口的进程或服务。";
            }

            // CLOSED/DELETE_TCB are no longer actionable active connections; continuing to submit will only yield misleading error codes.
            if (connectionRecord.tcpStateCode == MIB_TCP_STATE_CLOSED ||
                connectionRecord.tcpStateCode == MIB_TCP_STATE_DELETE_TCB)
            {
                return "目标 TCP 行已处于关闭/删除状态，不需要再次提交 DELETE_TCB。";
            }

            // Missing remote endpoint usually indicates it is not a deletable established/half-closed four-tuple.
            if (connectionRecord.remotePort == 0 ||
                connectionRecord.remoteAddressText.empty() ||
                connectionRecord.remoteAddressText == "0.0.0.0")
            {
                return "目标 TCP 行缺少有效远端端点，不是 SetTcpEntry 可终止的连接四元组。";
            }

            return std::string();
        }

        // isTcpConnectionTerminableBySetTcpEntry：
        // - Input: UI cached TCP record;
        // - Processing: Reuse the reason constructor, only checking if DELETE_TCB is executable.
        // - Returns: true if the current record can be submitted to SetTcpEntry; otherwise false.
        inline bool isTcpConnectionTerminableBySetTcpEntry(const TcpConnectionRecord& connectionRecord)
        {
            return getTcpTerminationUnsupportedReason(connectionRecord).empty();
        }

        // formatSetTcpEntryFailure：
        // - Input: SetTcpEntry return code.
        // - Processing: Supplement common error codes with UI-readable diagnostics, especially distinguishing between permission issues, parameter errors, and connection changes.
        // - Returns: UTF-8 text ready for display or logging.
        inline std::string formatSetTcpEntryFailure(const DWORD setResult)
        {
            std::ostringstream stream;
            stream << "SetTcpEntry failed, code=" << setResult;
            if (setResult == ERROR_ACCESS_DENIED)
            {
                stream << " (需要以管理员权限运行，或目标连接受系统策略保护)";
            }
            else if (setResult == ERROR_MR_MID_NOT_FOUND)
            {
                stream << " (系统未提供该错误码的消息文本；常见于向 SetTcpEntry 提交了不支持的 TCP 行，例如 LISTEN 监听端口或已变化的连接)";
            }
            else if (setResult == ERROR_INVALID_PARAMETER)
            {
                stream << " (连接四元组无效、连接状态已变化，或该行不是可删除的 IPv4 TCP 连接)";
            }
            else if (setResult == ERROR_NOT_SUPPORTED)
            {
                stream << " (本机 IPv4 传输未配置或系统不支持该操作)";
            }
            else if (setResult == ERROR_NOT_FOUND)
            {
                stream << " (连接已不存在或快照已过期)";
            }
            return stream.str();
        }

        // appendTcpEndpointText：
        // - Input: connection record;
        // - Processing: Append PID, status, and local/remote endpoints to the existing diagnostic stream.
        // - Returns: Nothing.
        inline void appendTcpEndpointText(
            std::ostringstream& stream,
            const TcpConnectionRecord& connectionRecord)
        {
            stream
                << " pid=" << connectionRecord.processId
                << " state=" << connectionRecord.tcpStateText
                << " local=" << connectionRecord.localAddressText << ":" << connectionRecord.localPort
                << " remote=" << connectionRecord.remoteAddressText << ":" << connectionRecord.remotePort;
        }
    } // namespace connection_detail

    // getTcpTerminationUnsupportedReason：
    // - Input: TCP connection snapshot record;
    // - Processing: Check if the record belongs to an active IPv4 connection supported by SetTcpEntry(DELETE_TCB).
    // - Returns: An empty string if termination is allowed; otherwise, a user-facing reason why it is not allowed.
    inline std::string getTcpTerminationUnsupportedReason(const TcpConnectionRecord& connectionRecord)
    {
        return connection_detail::getTcpTerminationUnsupportedReason(connectionRecord);
    }

    // isTcpConnectionTerminableBySetTcpEntry：
    // - Input: TCP connection snapshot record;
    // - Processing: Reuse pre-termination checks.
    // - Returns: true if the record can be submitted to SetTcpEntry(DELETE_TCB), otherwise false.
    inline bool isTcpConnectionTerminableBySetTcpEntry(const TcpConnectionRecord& connectionRecord)
    {
        return connection_detail::isTcpConnectionTerminableBySetTcpEntry(connectionRecord);
    }

    // enumerateTcpConnectionRecords：
    // - enumerate a snapshot of current system IPv4 + IPv6 TCP connections;
    // Returns true on success and populates recordsOut;
    // - Returns false on failure and writes the error description to errorTextOut.
    inline bool enumerateTcpConnectionRecords(
        std::vector<TcpConnectionRecord>& recordsOut,
        std::string* errorTextOut = nullptr)
    {
        recordsOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        // PID -> process name cache, avoiding redundant queries for the same PID.
        std::unordered_map<std::uint32_t, std::string> processNameCache;

        // appendIpv4Table: Enumerates IPv4 TCP connections and appends them to a unified output container.
        auto appendIpv4Table = [&recordsOut, &processNameCache](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedTcpTable(
                    tcpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + tcpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < tcpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_TCPROW_OWNER_PID& row = tcpTable->table[rowIndex];

                    TcpConnectionRecord record;
                    record.isIpv6 = false;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    record.processName = connection_detail::fillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = ntohl(row.dwLocalAddr);
                    record.localIpv4NetworkOrder = row.dwLocalAddr;
                    record.remoteIpv4HostOrder = ntohl(row.dwRemoteAddr);
                    record.remoteIpv4NetworkOrder = row.dwRemoteAddr;
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localPortNetworkOrder = row.dwLocalPort;
                    record.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                    record.remotePortNetworkOrder = row.dwRemotePort;
                    record.localAddressText = connection_detail::ipv4NetworkOrderToText(row.dwLocalAddr);
                    record.remoteAddressText = connection_detail::ipv4NetworkOrderToText(row.dwRemoteAddr);
                    record.tcpStateCode = static_cast<std::uint32_t>(row.dwState);
                    record.tcpStateText = connection_detail::tcpStateCodeToText(record.tcpStateCode);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        // appendIpv6Table: enumerate IPv6 TCP connections and append to the unified output container.
        auto appendIpv6Table = [&recordsOut, &processNameCache](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET6,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* tcpTable = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedTcpTable(
                    tcpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET6,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + tcpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < tcpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_TCP6ROW_OWNER_PID& row = tcpTable->table[rowIndex];

                    TcpConnectionRecord record;
                    record.isIpv6 = true;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    record.processName = connection_detail::fillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = 0;
                    record.localIpv4NetworkOrder = 0;
                    record.remoteIpv4HostOrder = 0;
                    record.remoteIpv4NetworkOrder = 0;
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localPortNetworkOrder = row.dwLocalPort;
                    record.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                    record.remotePortNetworkOrder = row.dwRemotePort;
                    record.localAddressText = connection_detail::ipv6BytesToText(row.ucLocalAddr);
                    record.remoteAddressText = connection_detail::ipv6BytesToText(row.ucRemoteAddr);
                    record.tcpStateCode = static_cast<std::uint32_t>(row.dwState);
                    record.tcpStateText = connection_detail::tcpStateCodeToText(record.tcpStateCode);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        std::string ipv4Error;
        std::string ipv6Error;
        const bool kIpv4Ok = appendIpv4Table(&ipv4Error);
        const bool kIpv6Ok = appendIpv6Table(&ipv6Error);
        if (!kIpv4Ok && !kIpv6Ok)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = "TCP v4/v6 均枚举失败: " + ipv4Error + " ; " + ipv6Error;
            }
            return false;
        }
        if (errorTextOut != nullptr && (!kIpv4Ok || !kIpv6Ok))
        {
            *errorTextOut = "部分枚举失败: " + ipv4Error + " ; " + ipv6Error;
        }

        // Sort by PID / local endpoint / remote endpoint to ensure stable row order on each UI refresh.
        std::sort(
            recordsOut.begin(),
            recordsOut.end(),
            [](const TcpConnectionRecord& left, const TcpConnectionRecord& right)
            {
                if (left.processId != right.processId)
                {
                    return left.processId < right.processId;
                }
                if (left.isIpv6 != right.isIpv6)
                {
                    return left.isIpv6 < right.isIpv6;
                }
                if (left.localIpv4HostOrder != right.localIpv4HostOrder)
                {
                    return left.localIpv4HostOrder < right.localIpv4HostOrder;
                }
                if (left.localPort != right.localPort)
                {
                    return left.localPort < right.localPort;
                }
                if (left.remoteIpv4HostOrder != right.remoteIpv4HostOrder)
                {
                    return left.remoteIpv4HostOrder < right.remoteIpv4HostOrder;
                }
                if (left.localAddressText != right.localAddressText)
                {
                    return left.localAddressText < right.localAddressText;
                }
                if (left.remoteAddressText != right.remoteAddressText)
                {
                    return left.remoteAddressText < right.remoteAddressText;
                }
                return left.remotePort < right.remotePort;
            });

        return true;
    }

    // enumerateUdpEndpointRecords：
    // - enumerate a snapshot of current system IPv4 + IPv6 UDP endpoints;
    // Returns true on success and populates recordsOut;
    // - Returns false on failure and writes the error description to errorTextOut.
    inline bool enumerateUdpEndpointRecords(
        std::vector<UdpEndpointRecord>& recordsOut,
        std::string* errorTextOut = nullptr)
    {
        recordsOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        // PID name cache to reduce redundant process queries.
        std::unordered_map<std::uint32_t, std::string> processNameCache;

        // appendIpv4Table: Enumerates IPv4 UDP endpoints and appends them to a unified output container.
        auto appendIpv4Table = [&recordsOut, &processNameCache](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedUdpTable(
                    udpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + udpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < udpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_UDPROW_OWNER_PID& row = udpTable->table[rowIndex];

                    UdpEndpointRecord record;
                    record.isIpv6 = false;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    record.processName = connection_detail::fillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = ntohl(row.dwLocalAddr);
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localAddressText = connection_detail::ipv4NetworkOrderToText(row.dwLocalAddr);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        // appendIpv6Table: enumerate IPv6 UDP endpoints and append to the unified output container.
        auto appendIpv6Table = [&recordsOut, &processNameCache](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET6,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* udpTable = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedUdpTable(
                    udpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET6,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + udpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < udpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_UDP6ROW_OWNER_PID& row = udpTable->table[rowIndex];

                    UdpEndpointRecord record;
                    record.isIpv6 = true;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    record.processName = connection_detail::fillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = 0;
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localAddressText = connection_detail::ipv6BytesToText(row.ucLocalAddr);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        std::string ipv4Error;
        std::string ipv6Error;
        const bool kIpv4Ok = appendIpv4Table(&ipv4Error);
        const bool kIpv6Ok = appendIpv6Table(&ipv6Error);
        if (!kIpv4Ok && !kIpv6Ok)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = "UDP v4/v6 均枚举失败: " + ipv4Error + " ; " + ipv6Error;
            }
            return false;
        }
        if (errorTextOut != nullptr && (!kIpv4Ok || !kIpv6Ok))
        {
            *errorTextOut = "部分枚举失败: " + ipv4Error + " ; " + ipv6Error;
        }

        // UDP endpoint sorting rule: PID -> Local Endpoint, ensuring UI row stability.
        std::sort(
            recordsOut.begin(),
            recordsOut.end(),
            [](const UdpEndpointRecord& left, const UdpEndpointRecord& right)
            {
                if (left.processId != right.processId)
                {
                    return left.processId < right.processId;
                }
                if (left.isIpv6 != right.isIpv6)
                {
                    return left.isIpv6 < right.isIpv6;
                }
                if (left.localIpv4HostOrder != right.localIpv4HostOrder)
                {
                    return left.localIpv4HostOrder < right.localIpv4HostOrder;
                }
                if (left.localAddressText != right.localAddressText)
                {
                    return left.localAddressText < right.localAddressText;
                }
                return left.localPort < right.localPort;
            });

        return true;
    }

    // terminateTcpConnectionByRecord：
    // - Terminate the specified TCP connection (calls SetTcpEntry + DELETE_TCB);
    // - Valid only for IPv4 TCP lines;
    // - detailTextOut returns a human-readable description for direct UI user notification.
    inline bool terminateTcpConnectionByRecord(
        const TcpConnectionRecord& connectionRecord,
        std::string* detailTextOut = nullptr)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        // Connection termination capability currently covers only IPv4 (SetTcpEntry); IPv6 connections are display-only and cannot be terminated.
        const std::string kUnsupportedReason = connection_detail::getTcpTerminationUnsupportedReason(connectionRecord);
        if (!kUnsupportedReason.empty())
        {
            if (detailTextOut != nullptr)
            {
                std::ostringstream unsupportedStream;
                unsupportedStream << kUnsupportedReason;
                connection_detail::appendTcpEndpointText(unsupportedStream, connectionRecord);
                *detailTextOut = unsupportedStream.str();
            }
            return false;
        }

        // Windows' public SetTcpEntry only accepts IPv4 MIB_TCPROW:
        // - The documentation/SDK header states that the status can only be set to MIB_TCP_STATE_DELETE_TCB.
        // - Must submit the complete MIB_TCPROW;
        // - Therefore, re-read the current TCP table before closing to submit the original DWORD row count returned by the
        //   system, avoiding ERROR_INVALID_PARAMETER caused by expired UI snapshots or port DWORD reassembly differences.
        ULONG requiredBufferLength = 0;
        DWORD queryResult = ::GetExtendedTcpTable(
            nullptr,
            &requiredBufferLength,
            TRUE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0);

        MIB_TCPROW deleteRow = connection_detail::buildDeleteTcpRowFromRecord(connectionRecord);
        bool matchedCurrentRow = false;
        bool matchedWithoutPid = false;
        if (queryResult == ERROR_INSUFFICIENT_BUFFER && requiredBufferLength > 0)
        {
            std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
            auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
            queryResult = ::GetExtendedTcpTable(
                tcpTable,
                &requiredBufferLength,
                TRUE,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0);
            if (queryResult == NO_ERROR)
            {
                for (DWORD rowIndex = 0; rowIndex < tcpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_TCPROW_OWNER_PID& row = tcpTable->table[rowIndex];
                    if (connection_detail::isIpv4TcpEndpointEqual(row, connectionRecord, true))
                    {
                        deleteRow = connection_detail::buildDeleteTcpRowFromOwnerPidRow(row);
                        matchedCurrentRow = true;
                        break;
                    }
                    if (!matchedWithoutPid &&
                        connection_detail::isIpv4TcpEndpointEqual(row, connectionRecord, false))
                    {
                        matchedWithoutPid = true;
                    }
                }

                if (!matchedCurrentRow)
                {
                    std::ostringstream staleStream;
                    staleStream << "当前 TCP 表未找到完全匹配连接";
                    if (matchedWithoutPid)
                    {
                        staleStream << "（四元组仍存在，但 PID 已变化）";
                    }
                    else
                    {
                        staleStream << "（连接可能已关闭或快照已过期）";
                    }
                    connection_detail::appendTcpEndpointText(staleStream, connectionRecord);
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = staleStream.str();
                    }
                    return false;
                }
            }
        }

        // SetTcpEntry returns NO_ERROR on success; any other value is treated as failure.
        const DWORD kSetResult = ::SetTcpEntry(&deleteRow);
        if (kSetResult != NO_ERROR)
        {
            if (detailTextOut != nullptr)
            {
                std::ostringstream failStream;
                failStream << connection_detail::formatSetTcpEntryFailure(kSetResult);
                connection_detail::appendTcpEndpointText(failStream, connectionRecord);
                if (!matchedCurrentRow)
                {
                    failStream << " (使用缓存行回退提交";
                    if (queryResult != ERROR_INSUFFICIENT_BUFFER && queryResult != NO_ERROR)
                    {
                        failStream << ", GetExtendedTcpTable code=" << queryResult;
                    }
                    failStream << ")";
                }
                *detailTextOut = failStream.str();
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            std::ostringstream successStream;
            successStream << "SetTcpEntry DELETE_TCB succeeded";
            connection_detail::appendTcpEndpointText(successStream, connectionRecord);
            *detailTextOut = successStream.str();
        }
        return true;
    }
} // namespace ks::network

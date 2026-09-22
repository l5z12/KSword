#include "NetToolsModel.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <objbase.h>
// netfw.h is included by the model only for the NET_FW_* enumerations. The rule
// text belongs next to every other display formatter, and duplicating the
// numeric values here would silently drift from the SDK.
#include <netfw.h>

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <mutex>
#include <utility>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace ksword::features::net_tools {
namespace {

// kAnyProtocol is what the firewall store reports for a rule that does not pin a
// transport. It is 256 rather than 0 because 0 is a real IANA protocol number.
constexpr std::int32_t kAnyProtocol = 256;

bool isUdp(const ConnectionProtocol protocol) {
    return protocol == ConnectionProtocol::kUdp4 || protocol == ConnectionProtocol::kUdp6;
}

// protocolOrder groups the table by transport before anything else. An operator
// scanning this page reads all TCP rows together, then all UDP rows; interleaving
// the four tables by address would make that impossible.
int protocolOrder(const ConnectionProtocol protocol) {
    switch (protocol) {
    case ConnectionProtocol::kTcp4: return 0;
    case ConnectionProtocol::kTcp6: return 1;
    case ConnectionProtocol::kUdp4: return 2;
    case ConnectionProtocol::kUdp6: return 3;
    }
    return 4;
}

bool matchesProtocolFilter(const ConnectionEntry& entry, const ConnectionProtocolFilter filter) {
    switch (filter) {
    case ConnectionProtocolFilter::kTcp:
        return !isUdp(entry.protocol);
    case ConnectionProtocolFilter::kUdp:
        return isUdp(entry.protocol);
    case ConnectionProtocolFilter::kAll:
        break;
    }
    return true;
}

bool matchesDirectionFilter(const FirewallRuleEntry& entry, const FirewallDirectionFilter filter) {
    switch (filter) {
    case FirewallDirectionFilter::kInbound:
        return entry.direction == NET_FW_RULE_DIR_IN;
    case FirewallDirectionFilter::kOutbound:
        return entry.direction == NET_FW_RULE_DIR_OUT;
    case FirewallDirectionFilter::kAll:
        break;
    }
    return true;
}

int compareCaseInsensitive(const std::wstring& left, const std::wstring& right) {
    return ::CompareStringOrdinal(
        left.c_str(), static_cast<int>(left.size()), right.c_str(), static_cast<int>(right.size()), TRUE);
}

std::wstring portText(const std::uint16_t port) {
    // Port 0 in a connection table means "unbound", which is a real state for a
    // half-open or listening endpoint, so it is shown rather than blanked.
    return std::to_wstring(static_cast<unsigned int>(port));
}

std::wstring endpointText(const std::wstring& address, const std::uint16_t port, const bool ipv6) {
    if (address.empty()) {
        return portText(port);
    }
    // Bracket notation is not decoration here: an unbracketed IPv6 literal
    // followed by ":443" is ambiguous with the address's own colons.
    return ipv6 ? L"[" + address + L"]:" + portText(port) : address + L":" + portText(port);
}

} // namespace

void ConnectionModel::setEntries(std::vector<ConnectionEntry> entries) {
    allEntries_ = std::move(entries);
    rebuildView();
}

void ConnectionModel::setProtocolFilter(const ConnectionProtocolFilter filter) {
    protocolFilter_ = filter;
    rebuildView();
}

ConnectionProtocolFilter ConnectionModel::protocolFilter() const noexcept {
    return protocolFilter_;
}

const std::vector<ConnectionEntry>& ConnectionModel::entries() const noexcept {
    return entries_;
}

const std::vector<ConnectionEntry>& ConnectionModel::allEntries() const noexcept {
    return allEntries_;
}

const ConnectionEntry* ConnectionModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= entries_.size()) {
        return nullptr;
    }
    return &entries_[static_cast<std::size_t>(index)];
}

std::wstring ConnectionModel::textForColumn(const ConnectionEntry& entry, const int column) const {
    switch (column) {
    case 0: return connectionProtocolText(entry.protocol);
    case 1: return entry.localAddress;
    case 2: return portText(entry.localPort);
    case 3: return entry.remoteAddress;
    case 4: return entry.hasState || entry.remotePort != 0 ? portText(entry.remotePort) : std::wstring{};
    case 5: return entry.hasState ? tcpStateText(entry.state) : std::wstring(L"—");
    case 6: return std::to_wstring(entry.processId);
    case 7: return entry.processName;
    default: break;
    }
    return {};
}

std::vector<NetToolsProperty> ConnectionModel::propertiesForEntry(const ConnectionEntry& entry) const {
    const bool kIpv6 = entry.protocol == ConnectionProtocol::kTcp6 || entry.protocol == ConnectionProtocol::kUdp6;
    std::vector<NetToolsProperty> properties;
    properties.push_back({ L"协议", connectionProtocolText(entry.protocol) });
    properties.push_back({ L"本地端点", endpointText(entry.localAddress, entry.localPort, kIpv6) });
    properties.push_back({ L"远端端点",
        entry.remoteAddress.empty() ? std::wstring(L"—") : endpointText(entry.remoteAddress, entry.remotePort, kIpv6) });
    properties.push_back({ L"连接状态", entry.hasState ? tcpStateText(entry.state) : std::wstring(L"UDP 无连接状态") });
    properties.push_back({ L"进程 ID", std::to_wstring(entry.processId) });
    properties.push_back({ L"进程名", entry.processName.empty() ? std::wstring(L"（无法读取）") : entry.processName });
    properties.push_back({ L"可结束",
        connectionCanClose(entry) ? std::wstring(L"是（SetTcpEntry 删除 TCB）")
                                  : std::wstring(L"否（仅 IPv4 TCP 的已连接状态支持）") });
    return properties;
}

void ConnectionModel::rebuildView() {
    entries_.clear();
    entries_.reserve(allEntries_.size());
    for (const ConnectionEntry& entry : allEntries_) {
        if (matchesProtocolFilter(entry, protocolFilter_)) {
            entries_.push_back(entry);
        }
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const ConnectionEntry& left, const ConnectionEntry& right) {
        const int kLeftOrder = protocolOrder(left.protocol);
        const int kRightOrder = protocolOrder(right.protocol);
        if (kLeftOrder != kRightOrder) {
            return kLeftOrder < kRightOrder;
        }
        if (left.processId != right.processId) {
            return left.processId < right.processId;
        }
        return left.localPort < right.localPort;
    });
}

void FirewallModel::setEntries(std::vector<FirewallRuleEntry> entries) {
    allEntries_ = std::move(entries);
    rebuildView();
}

void FirewallModel::setDirectionFilter(const FirewallDirectionFilter filter) {
    directionFilter_ = filter;
    rebuildView();
}

FirewallDirectionFilter FirewallModel::directionFilter() const noexcept {
    return directionFilter_;
}

const std::vector<FirewallRuleEntry>& FirewallModel::entries() const noexcept {
    return entries_;
}

const std::vector<FirewallRuleEntry>& FirewallModel::allEntries() const noexcept {
    return allEntries_;
}

const FirewallRuleEntry* FirewallModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= entries_.size()) {
        return nullptr;
    }
    return &entries_[static_cast<std::size_t>(index)];
}

std::wstring FirewallModel::textForColumn(const FirewallRuleEntry& entry, const int column) const {
    switch (column) {
    case 0: return entry.name;
    case 1: return firewallDirectionText(entry.direction);
    case 2: return firewallActionText(entry.action);
    case 3: return entry.enabled ? std::wstring(L"启用") : std::wstring(L"停用");
    case 4: return firewallProtocolText(entry.protocol);
    case 5: return entry.localPorts.empty() ? std::wstring(L"任意") : entry.localPorts;
    case 6: return entry.remotePorts.empty() ? std::wstring(L"任意") : entry.remotePorts;
    case 7: return firewallProfilesText(entry.profiles);
    case 8: return entry.applicationName.empty() ? std::wstring(L"任意程序") : entry.applicationName;
    default: break;
    }
    return {};
}

std::vector<NetToolsProperty> FirewallModel::propertiesForEntry(const FirewallRuleEntry& entry) const {
    std::vector<NetToolsProperty> properties;
    properties.push_back({ L"规则名称", entry.name });
    properties.push_back({ L"启用状态", entry.enabled ? L"启用" : L"停用" });
    properties.push_back({ L"方向", firewallDirectionText(entry.direction) });
    properties.push_back({ L"动作", firewallActionText(entry.action) });
    properties.push_back({ L"协议", firewallProtocolText(entry.protocol) });
    properties.push_back({ L"配置文件", firewallProfilesText(entry.profiles) });
    properties.push_back({ L"本地端口", entry.localPorts.empty() ? L"任意" : entry.localPorts });
    properties.push_back({ L"远端端口", entry.remotePorts.empty() ? L"任意" : entry.remotePorts });
    properties.push_back({ L"本地地址", entry.localAddresses.empty() ? L"任意" : entry.localAddresses });
    properties.push_back({ L"远端地址", entry.remoteAddresses.empty() ? L"任意" : entry.remoteAddresses });
    properties.push_back({ L"程序路径", entry.applicationName.empty() ? L"任意程序" : entry.applicationName });
    properties.push_back({ L"服务名", entry.serviceName.empty() ? L"（未限定）" : entry.serviceName });
    properties.push_back({ L"分组", entry.grouping.empty() ? L"（无分组）" : entry.grouping });
    properties.push_back({ L"接口类型", entry.interfaceTypes.empty() ? L"全部" : entry.interfaceTypes });
    properties.push_back({ L"边缘穿越", entry.edgeTraversal ? L"允许" : L"不允许" });
    properties.push_back({ L"描述", entry.description.empty() ? L"（无描述）" : entry.description });
    return properties;
}

void FirewallModel::rebuildView() {
    entries_.clear();
    entries_.reserve(allEntries_.size());
    for (const FirewallRuleEntry& entry : allEntries_) {
        if (matchesDirectionFilter(entry, directionFilter_)) {
            entries_.push_back(entry);
        }
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const FirewallRuleEntry& left, const FirewallRuleEntry& right) {
        return compareCaseInsensitive(left.name, right.name) == CSTR_LESS_THAN;
    });
}

std::wstring connectionProtocolText(const ConnectionProtocol protocol) {
    switch (protocol) {
    case ConnectionProtocol::kTcp4: return L"TCP";
    case ConnectionProtocol::kTcp6: return L"TCPv6";
    case ConnectionProtocol::kUdp4: return L"UDP";
    case ConnectionProtocol::kUdp6: return L"UDPv6";
    }
    return L"未知";
}

std::wstring tcpStateText(const std::uint32_t state) {
    switch (state) {
    case MIB_TCP_STATE_CLOSED: return L"CLOSED";
    case MIB_TCP_STATE_LISTEN: return L"LISTENING";
    case MIB_TCP_STATE_SYN_SENT: return L"SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD: return L"SYN_RECEIVED";
    case MIB_TCP_STATE_ESTAB: return L"ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1: return L"FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return L"FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT: return L"CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return L"CLOSING";
    case MIB_TCP_STATE_LAST_ACK: return L"LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return L"TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB: return L"DELETE_TCB";
    default: break;
    }
    return L"未知(" + std::to_wstring(state) + L")";
}

bool connectionCanClose(const ConnectionEntry& entry) {
    if (entry.protocol != ConnectionProtocol::kTcp4 || !entry.hasState) {
        return false;
    }
    // SYN_SENT through TIME_WAIT are the states that own a TCB worth deleting.
    // CLOSED and LISTEN sit outside that window, and DELETE_TCB means the stack
    // is already tearing the entry down.
    return entry.state >= MIB_TCP_STATE_SYN_SENT && entry.state <= MIB_TCP_STATE_TIME_WAIT;
}

bool connectionIsEstablished(const ConnectionEntry& entry) {
    return entry.hasState && entry.state == MIB_TCP_STATE_ESTAB;
}

bool connectionIsListening(const ConnectionEntry& entry) {
    return entry.hasState && entry.state == MIB_TCP_STATE_LISTEN;
}

std::wstring firewallDirectionText(const std::int32_t direction) {
    switch (direction) {
    case NET_FW_RULE_DIR_IN: return L"入站";
    case NET_FW_RULE_DIR_OUT: return L"出站";
    default: break;
    }
    return L"未知(" + std::to_wstring(direction) + L")";
}

std::wstring firewallActionText(const std::int32_t action) {
    switch (action) {
    case NET_FW_ACTION_BLOCK: return L"阻止";
    case NET_FW_ACTION_ALLOW: return L"允许";
    default: break;
    }
    return L"未知(" + std::to_wstring(action) + L")";
}

std::wstring firewallProtocolText(const std::int32_t protocol) {
    switch (protocol) {
    case 1: return L"ICMPv4";
    case 6: return L"TCP";
    case 17: return L"UDP";
    case 47: return L"GRE";
    case 50: return L"ESP";
    case 51: return L"AH";
    case 58: return L"ICMPv6";
    case kAnyProtocol: return L"任意";
    default: break;
    }
    return L"协议 " + std::to_wstring(protocol);
}

std::wstring firewallProfilesText(const std::int32_t profiles) {
    if ((profiles & NET_FW_PROFILE2_ALL) == NET_FW_PROFILE2_ALL) {
        return L"全部";
    }
    std::wstring text;
    const auto kAppend = [&text](const wchar_t* label) {
        if (!text.empty()) {
            text += L", ";
        }
        text += label;
    };
    if ((profiles & NET_FW_PROFILE2_DOMAIN) != 0) {
        kAppend(L"域");
    }
    if ((profiles & NET_FW_PROFILE2_PRIVATE) != 0) {
        kAppend(L"专用");
    }
    if ((profiles & NET_FW_PROFILE2_PUBLIC) != 0) {
        kAppend(L"公用");
    }
    return text.empty() ? L"（未指定）" : text;
}

bool firewallRuleIsInbound(const FirewallRuleEntry& entry) {
    return entry.direction == NET_FW_RULE_DIR_IN;
}

bool firewallRuleIsOutbound(const FirewallRuleEntry& entry) {
    return entry.direction == NET_FW_RULE_DIR_OUT;
}

bool firewallRuleIsBlocking(const FirewallRuleEntry& entry) {
    return entry.action == NET_FW_ACTION_BLOCK;
}

void ensureWinsockInitialized() {
    // A function-local static is the guard here because this is reached from the
    // async worker threads of three separate tabs at once, and WSAStartup is only
    // reference-counted, not race-free against a first-ever call.
    static std::once_flag once;
    std::call_once(once, [] {
        WSADATA data{};
        (void)::WSAStartup(MAKEWORD(2, 2), &data);
    });
}

std::wstring formatIpv4Address(const std::uint32_t networkOrderAddress) {
    ensureWinsockInitialized();
    IN_ADDR address{};
    address.S_un.S_addr = static_cast<ULONG>(networkOrderAddress);
    wchar_t buffer[INET_ADDRSTRLEN + 1]{};
    if (::InetNtopW(AF_INET, &address, buffer, std::size(buffer)) == nullptr) {
        return L"0.0.0.0";
    }
    return buffer;
}

std::wstring formatIpv6Address(const std::uint8_t* address, const std::uint32_t scopeId) {
    if (address == nullptr) {
        return L"::";
    }
    ensureWinsockInitialized();
    IN6_ADDR value{};
    std::copy_n(address, sizeof(value.u.Byte), value.u.Byte);
    wchar_t buffer[INET6_ADDRSTRLEN + 1]{};
    if (::InetNtopW(AF_INET6, &value, buffer, std::size(buffer)) == nullptr) {
        return L"::";
    }
    std::wstring text = buffer;
    // The scope id is not cosmetic for link-local addresses: fe80::1 on two
    // different interfaces are two different endpoints.
    if (scopeId != 0) {
        text += L"%" + std::to_wstring(scopeId);
    }
    return text;
}

std::wstring formatWin32Error(const std::uint32_t code) {
    LPWSTR text = nullptr;
    const DWORD kLength = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&text),
        0,
        nullptr);
    std::wstring message;
    if (kLength != 0 && text != nullptr) {
        message.assign(text, kLength);
    }
    if (text != nullptr) {
        ::LocalFree(text);
    }
    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
        message.pop_back();
    }
    if (message.empty()) {
        return L"错误码 " + std::to_wstring(code);
    }
    return message + L"（错误码 " + std::to_wstring(code) + L"）";
}

} // namespace Ksword::Features::NetTools

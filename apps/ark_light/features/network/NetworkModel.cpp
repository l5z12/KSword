#include "NetworkModel.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../core/Win32Lean.h"

#include <commctrl.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::network {
namespace {
constexpr ULONG kNetworkAfInet = 2UL;

// Column creates a Network table column.
// Input: Column title, width, and ListView alignment.
// Processing: Package only UI metadata, without accessing R0.
// Return: NetworkAuditColumn value object.
NetworkAuditColumn column(const wchar_t* title, const int width, const int format = LVCFMT_LEFT) {
    return NetworkAuditColumn{ width, format, title };
}

// RowVec creates a dynamic text row.
// Input: Pre-formatted array of cells.
// Processing: Move to NetworkAuditRow to avoid const wchar_t* lifetime issues.
// Returns: a NetworkAuditRow value object.
NetworkAuditRow rowVec(std::vector<std::wstring> cells) {
    NetworkAuditRow row;
    row.cells = std::move(cells);
    return row;
}

// utf8ToWideLossy converts ArkDriverClient's narrow-character diagnostics to wide characters.
// Input: Typically ASCII/UTF-8 style io.message.
// Handling: byte-by-byte promotion; diagnostic text is for table display only.
// Returns: std::wstring; returns an empty string for empty input.
std::wstring utf8ToWideLossy(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const char kCh : text) {
        wide.push_back(static_cast<unsigned char>(kCh));
    }
    return wide;
}

// HexText: Formats a 64-bit integer.
// Input: diagnostic address, flag, or count.
// Processing: Uniformly use 0x prefix with uppercase hexadecimal.
// Returns: A string suitable for direct display in a UI table.
std::wstring hexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// Ipv4Text converts the IPv4 DWORD returned by IP Helper to dotted-decimal notation.
// Input: addr is the IPv4 address field in a MIB_* row.
// Processing: Expand byte-by-byte according to the byte order of the Windows IP Helper public table.
// Returns: Displayable IPv4 text.
std::wstring ipv4Text(const DWORD addr) {
    std::wostringstream stream;
    stream << static_cast<unsigned int>(addr & 0xFFU) << L'.'
           << static_cast<unsigned int>((addr >> 8U) & 0xFFU) << L'.'
           << static_cast<unsigned int>((addr >> 16U) & 0xFFU) << L'.'
           << static_cast<unsigned int>((addr >> 24U) & 0xFFU);
    return stream.str();
}

// networkPortText converts network byte-order ports to native readable decimal.
// Input: portValue comes from MIB_TCPROW_OWNER_PID / MIB_UDPROW_OWNER_PID.
// Processing: Extract only the lower 16 bits and swap high/low bytes; no dependency on ws2_32 library.
// Returns: Port number text.
std::wstring networkPortText(const DWORD portValue) {
    const DWORD kPort = ((portValue & 0xFF00U) >> 8U) | ((portValue & 0x00FFU) << 8U);
    return std::to_wstring(kPort & 0xFFFFU);
}

// win32StatusText formats Win32/IP Helper error codes.
// Input: apiName is the name of the failed API, status is the return code.
// Processing: Retain both decimal and hexadecimal formats to facilitate on-site identification of permission/platform differences.
// Returns: text suitable for the table description column.
std::wstring win32StatusText(const wchar_t* apiName, const DWORD status) {
    std::wostringstream stream;
    stream << apiName << L" failed, status=" << status << L" (" << hexText(status) << L")";
    return stream.str();
}

// IpHelperApi stores dynamically resolved read-only IP Helper entry points.
// Input: loadIpHelperApi populates the fields.
// Handling: NetworkModel calls via function pointers to avoid adding new .vcxproj library dependencies.
// Return: The struct itself has no behavior.
struct IpHelperApi {
    using GetExtendedTcpTableFn = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG);
    using GetExtendedUdpTableFn = DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, UDP_TABLE_CLASS, ULONG);
    using GetIfTableFn = DWORD(WINAPI*)(PMIB_IFTABLE, PULONG, BOOL);
    using GetIpAddrTableFn = DWORD(WINAPI*)(PMIB_IPADDRTABLE, PULONG, BOOL);
    using GetIpForwardTableFn = DWORD(WINAPI*)(PMIB_IPFORWARDTABLE, PULONG, BOOL);

    HMODULE module = nullptr;
    GetExtendedTcpTableFn getExtendedTcpTable = nullptr;
    GetExtendedUdpTableFn getExtendedUdpTable = nullptr;
    GetIfTableFn getIfTable = nullptr;
    GetIpAddrTableFn getIpAddrTable = nullptr;
    GetIpForwardTableFn getIpForwardTable = nullptr;
};

// loadIpHelperApi dynamically loads iphlpapi.dll.
// Input: errorText receives the failure reason and may be empty.
// Processing: Resolve documented read-only APIs required by the AFD/NSI page.
// Returns: on success, api is callable; on failure, the page displays 'unavailable'.
bool loadIpHelperApi(IpHelperApi& api, std::wstring& errorText) {
    api.module = ::LoadLibraryW(L"iphlpapi.dll");
    if (api.module == nullptr) {
        errorText = win32StatusText(L"LoadLibrary(iphlpapi.dll)", ::GetLastError());
        return false;
    }

    auto resolve = [&api](const char* name) -> FARPROC {
        return ::GetProcAddress(api.module, name);
    };

    api.getExtendedTcpTable = reinterpret_cast<IpHelperApi::GetExtendedTcpTableFn>(resolve("GetExtendedTcpTable"));
    api.getExtendedUdpTable = reinterpret_cast<IpHelperApi::GetExtendedUdpTableFn>(resolve("GetExtendedUdpTable"));
    api.getIfTable = reinterpret_cast<IpHelperApi::GetIfTableFn>(resolve("GetIfTable"));
    api.getIpAddrTable = reinterpret_cast<IpHelperApi::GetIpAddrTableFn>(resolve("GetIpAddrTable"));
    api.getIpForwardTable = reinterpret_cast<IpHelperApi::GetIpForwardTableFn>(resolve("GetIpForwardTable"));

    if (api.getExtendedTcpTable == nullptr ||
        api.getExtendedUdpTable == nullptr ||
        api.getIfTable == nullptr ||
        api.getIpAddrTable == nullptr ||
        api.getIpForwardTable == nullptr) {
        errorText = L"iphlpapi.dll 缺少 Network 页所需的只读枚举入口。";
        ::FreeLibrary(api.module);
        api = {};
        return false;
    }
    return true;
}

// protocolStatusText returns generic protocol status text.
// Inputs: ok and unsupported, two ArkDriverClient result status flags.
// Processing: Distinguish between online status, unsupported old drivers, and transmission failures.
// Returns: Chinese status text.
std::wstring protocolStatusText(const bool ok, const bool unsupported) {
    if (ok) {
        return L"OK";
    }
    return unsupported ? L"驱动不支持" : L"驱动不可用/权限不足";
}

// addressText formats the network address.
// Input: Address family and shared protocol 16-byte address.
// Note: IPv4 uses dotted-decimal notation; IPv6 uses compressed hexadecimal groups.
// Returns: readable address; returns <unknown> for unknown address families.
std::wstring addressText(const unsigned long family, const unsigned char bytes[16]) {
    if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) {
        std::wostringstream stream;
        stream << static_cast<unsigned int>(bytes[0]) << L'.'
               << static_cast<unsigned int>(bytes[1]) << L'.'
               << static_cast<unsigned int>(bytes[2]) << L'.'
               << static_cast<unsigned int>(bytes[3]);
        return stream.str();
    }
    if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
        std::wostringstream stream;
        stream << std::hex << std::nouppercase;
        for (int index = 0; index < 16; index += 2) {
            if (index != 0) {
                stream << L":";
            }
            const unsigned int kWord = (static_cast<unsigned int>(bytes[index]) << 8U) |
                static_cast<unsigned int>(bytes[index + 1]);
            stream << kWord;
        }
        return stream.str();
    }
    return L"<unknown>";
}

// fixedWide reads shared protocol fixed-length wide character fields.
// Input: Field pointer and maximum character count.
// Note: scan until NUL or boundary to prevent out-of-bounds access when old drivers fail to write NUL.
// Returns: Safe string; returns "<empty>" for empty fields.
std::wstring fixedWide(const wchar_t* text, const std::size_t maxChars) {
    if (text == nullptr || maxChars == 0U) {
        return L"<empty>";
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    if (length == 0U) {
        return L"<empty>";
    }
    return std::wstring(text, text + length);
}

// addEndpointRows: Appends TCP/UDP endpoint query results.
// Input: protocol name, ArkDriverClient endpoint query result, and output rows.
// Note: Write the IOCTL status row first, followed by endpoint diagnostic rows.
// Returns: Nothing.
void addEndpointRows(const std::wstring& protocol, const ksword::ark::NetworkEndpointAuditResult& query, std::vector<NetworkAuditRow>& rows) {
    rows.push_back(rowVec({
        protocol,
        protocolStatusText(query.io.ok, query.unsupported),
        L"ArkDriverClient",
        L"IOCTL endpoint",
        L"total=" + std::to_wstring(query.totalCount) + L" returned=" + std::to_wstring(query.returnedCount),
        utf8ToWideLossy(query.io.message),
        L"只读 endpoint 快照，不断开连接。"
    }));
    for (const KSWORD_ARK_NETWORK_ENDPOINT_ROW& entry : query.entries) {
        rows.push_back(rowVec({
            protocol,
            std::to_wstring(entry.state),
            std::to_wstring(entry.owningPid),
            addressText(entry.addressFamily, entry.localAddress) + L":" + std::to_wstring(entry.localPort),
            addressText(entry.addressFamily, entry.remoteAddress) + L":" + std::to_wstring(entry.remotePort),
            hexText(entry.endpointObject),
            hexText(entry.flags),
            L"source=" + hexText(entry.sourceFlags) + L" transport=" + hexText(entry.transportObject)
        }));
    }
}

// buildTcpUdpRows: Queries TCP/UDP R0 endpoint cross-view.
// Input: None; Processing: Calls the ArkDriverClient wrapper, avoiding raw DeviceIoControl.
// Returns: Table rows ready for display.
std::vector<NetworkAuditRow> buildTcpUdpRows() {
    std::vector<NetworkAuditRow> rows;
    const ksword::ark::DriverClient kClient;
    addEndpointRows(L"TCP", kClient.queryNetworkTcpEndpoints(), rows);
    addEndpointRows(L"UDP", kClient.queryNetworkUdpEndpoints(), rows);
    rows.push_back(rowVec({ L"安全边界", L"只读", L"UI", L"无断连/无阻断", L"-", L"不调用 set-rules，不修改 WFP 规则。", L"展示 R0 endpoint 审计结果，可与 R3 公开 API 视图对照。" }));
    return rows;
}

// buildWfpRows queries the WFP provider/filter/callout inventory.
// Input: None; Processing: Call ArkDriverClient::queryNetworkWfpInventory.
// Return: WFP table rows.
std::vector<NetworkAuditRow> buildWfpRows() {
    std::vector<NetworkAuditRow> rows;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::NetworkWfpInventoryResult kQuery = kClient.queryNetworkWfpInventory();
    rows.push_back(rowVec({
        L"IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY",
        protocolStatusText(kQuery.io.ok, kQuery.unsupported),
        L"ArkDriverClient",
        L"total=" + std::to_wstring(kQuery.totalCount) + L" returned=" + std::to_wstring(kQuery.returnedCount),
        utf8ToWideLossy(kQuery.io.message),
        L"不删除 callout/filter，不关闭 engine。"
    }));
    for (const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW& entry : kQuery.entries) {
        rows.push_back(rowVec({
            std::to_wstring(entry.objectKind),
            L"layer=" + std::to_wstring(entry.layerId) + L" callout=" + std::to_wstring(entry.calloutId),
            hexText(entry.objectAddress),
            hexText(entry.classifyAddress),
            fixedWide(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS),
            L"flags=" + hexText(entry.flags) + L" field=" + hexText(entry.fieldMask)
        }));
    }
    return rows;
}

// buildNdisRows queries NDIS link audit.
// Input: None; Processing: Invoke ArkDriverClient::queryNetworkNdisChain.
// Returns: NDIS table rows.
std::vector<NetworkAuditRow> buildNdisRows() {
    std::vector<NetworkAuditRow> rows;
    const ksword::ark::DriverClient kClient;
    const ksword::ark::NetworkNdisChainResult kQuery = kClient.queryNetworkNdisChain();
    rows.push_back(rowVec({
        L"IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN",
        protocolStatusText(kQuery.io.ok, kQuery.unsupported),
        L"ArkDriverClient",
        L"total=" + std::to_wstring(kQuery.totalCount) + L" returned=" + std::to_wstring(kQuery.returnedCount),
        utf8ToWideLossy(kQuery.io.message),
        L"不 pause/restart miniport，不 detach filter。"
    }));
    for (const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW& entry : kQuery.entries) {
        rows.push_back(rowVec({
            std::to_wstring(entry.objectKind),
            fixedWide(entry.componentName, KSWORD_ARK_NETWORK_NAME_CHARS),
            L"if=" + std::to_wstring(entry.ifIndex) + L" order=" + std::to_wstring(entry.filterOrder),
            hexText(entry.objectAddress),
            hexText(entry.parentObjectAddress),
            fixedWide(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS),
            L"driver=" + hexText(entry.driverObject) + L" flags=" + hexText(entry.flags)
        }));
    }
    return rows;
}

// appendTcpAfdProjectionRows appends the AFD-facing projection of the TCP owner table.
// Input: Parsed IP Helper API, output row array, and maximum return rows.
// Note: Only call the documented GetExtendedTcpTable; do not read AFD private structures.
// Returns: None; writes diagnostic rows on failure.
void appendTcpAfdProjectionRows(const IpHelperApi& api, std::vector<NetworkAuditRow>& rows, const std::size_t maxRows) {
    DWORD bufferSize = 0UL;
    DWORD status = api.getExtendedTcpTable(nullptr, &bufferSize, FALSE, kNetworkAfInet, TCP_TABLE_OWNER_PID_ALL, 0UL);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0UL) {
        rows.push_back(rowVec({ L"AFD/TCPv4", L"Unavailable", L"GetExtendedTcpTable", L"-", win32StatusText(L"GetExtendedTcpTable(size)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    std::vector<unsigned char> buffer(bufferSize, 0U);
    status = api.getExtendedTcpTable(buffer.data(), &bufferSize, FALSE, kNetworkAfInet, TCP_TABLE_OWNER_PID_ALL, 0UL);
    if (status != ERROR_SUCCESS) {
        rows.push_back(rowVec({ L"AFD/TCPv4", L"Unavailable", L"GetExtendedTcpTable", L"-", win32StatusText(L"GetExtendedTcpTable(data)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    rows.push_back(rowVec({ L"AFD/TCPv4", L"OK", L"GetExtendedTcpTable", L"Owner PID table", L"entries=" + std::to_wstring(table->dwNumEntries), L"R3 documented projection，可与 R0 TCP endpoint 交叉验证。" }));
    const std::size_t kCount = (std::min)(static_cast<std::size_t>(table->dwNumEntries), maxRows);
    for (std::size_t index = 0U; index < kCount; ++index) {
        const MIB_TCPROW_OWNER_PID& entry = table->table[index];
        rows.push_back(rowVec({
            L"TCP",
            L"state=" + std::to_wstring(entry.dwState),
            L"pid=" + std::to_wstring(entry.dwOwningPid),
            ipv4Text(entry.dwLocalAddr) + L":" + networkPortText(entry.dwLocalPort),
            ipv4Text(entry.dwRemoteAddr) + L":" + networkPortText(entry.dwRemotePort),
            L"AFD-facing R3 endpoint; no disconnect/no patch"
        }));
    }
}

// appendUdpAfdProjectionRows: Appends AFD-facing projections from the UDP owner table.
// Input: Parsed IP Helper API, output row array, and maximum return rows.
// Handling: Call only documented GetExtendedUdpTable; do not read private kernel objects.
// Returns: None; writes diagnostic rows on failure.
void appendUdpAfdProjectionRows(const IpHelperApi& api, std::vector<NetworkAuditRow>& rows, const std::size_t maxRows) {
    DWORD bufferSize = 0UL;
    DWORD status = api.getExtendedUdpTable(nullptr, &bufferSize, FALSE, kNetworkAfInet, UDP_TABLE_OWNER_PID, 0UL);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0UL) {
        rows.push_back(rowVec({ L"AFD/UDPv4", L"Unavailable", L"GetExtendedUdpTable", L"-", win32StatusText(L"GetExtendedUdpTable(size)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    std::vector<unsigned char> buffer(bufferSize, 0U);
    status = api.getExtendedUdpTable(buffer.data(), &bufferSize, FALSE, kNetworkAfInet, UDP_TABLE_OWNER_PID, 0UL);
    if (status != ERROR_SUCCESS) {
        rows.push_back(rowVec({ L"AFD/UDPv4", L"Unavailable", L"GetExtendedUdpTable", L"-", win32StatusText(L"GetExtendedUdpTable(data)", status), L"只读；未读取 AFD 私有对象。" }));
        return;
    }

    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    rows.push_back(rowVec({ L"AFD/UDPv4", L"OK", L"GetExtendedUdpTable", L"Owner PID table", L"entries=" + std::to_wstring(table->dwNumEntries), L"R3 documented projection，可与 R0 UDP endpoint 交叉验证。" }));
    const std::size_t kCount = (std::min)(static_cast<std::size_t>(table->dwNumEntries), maxRows);
    for (std::size_t index = 0U; index < kCount; ++index) {
        const MIB_UDPROW_OWNER_PID& entry = table->table[index];
        rows.push_back(rowVec({
            L"UDP",
            L"listen",
            L"pid=" + std::to_wstring(entry.dwOwningPid),
            ipv4Text(entry.dwLocalAddr) + L":" + networkPortText(entry.dwLocalPort),
            L"-",
            L"AFD-facing R3 endpoint; no disconnect/no patch"
        }));
    }
}

// buildAfdRows: constructs the AFD endpoint page.
// Input: None; Processing: Uses the documented TCP/UDP owner table as an AFD socket projection.
// Return: actual R3 evidence rows; returns unavailable placeholder instead of unsupported when API is missing.
std::vector<NetworkAuditRow> buildAfdRows() {
    std::vector<NetworkAuditRow> rows;
    IpHelperApi api;
    std::wstring errorText;
    if (!loadIpHelperApi(api, errorText)) {
        rows.push_back(rowVec({ L"AFD endpoint", L"Unavailable", L"iphlpapi.dll", L"-", errorText, L"未新增 R0 协议；不猜 AFD 私有结构。" }));
        return rows;
    }

    appendTcpAfdProjectionRows(api, rows, 128U);
    appendUdpAfdProjectionRows(api, rows, 128U);
    rows.push_back(rowVec({ L"安全边界", L"只读", L"R3 documented API", L"TCP/UDP owner table", L"无 AFD IOCTL 时以公开端点表替代空占位。", L"不 detach/disable/bypass，不读取 AFD 私有对象。" }));
    ::FreeLibrary(api.module);
    return rows;
}

// buildNsiRows builds the NSI summary page.
// Input: None; Processing: Use IP Helper interfaces, addresses, and routing tables as NSI-facing evidence.
// Returns: actual summary rows; returns unavailable placeholder instead of unsupported when the API is missing.
std::vector<NetworkAuditRow> buildNsiRows() {
    std::vector<NetworkAuditRow> rows;
    IpHelperApi api;
    std::wstring errorText;
    if (!loadIpHelperApi(api, errorText)) {
        rows.push_back(rowVec({ L"NSI summary", L"Unavailable", L"iphlpapi.dll", L"-", errorText, L"未新增 R0 协议；不猜 NSI 私有表。" }));
        return rows;
    }

    ULONG ifBytes = 0UL;
    DWORD status = api.getIfTable(nullptr, &ifBytes, FALSE);
    if (status == ERROR_INSUFFICIENT_BUFFER && ifBytes != 0UL) {
        std::vector<unsigned char> buffer(ifBytes, 0U);
        auto* ifTable = reinterpret_cast<PMIB_IFTABLE>(buffer.data());
        status = api.getIfTable(ifTable, &ifBytes, FALSE);
        if (status == NO_ERROR) {
            rows.push_back(rowVec({ L"Interface table", L"OK", L"GetIfTable", L"NETIO/NSI public projection", L"entries=" + std::to_wstring(ifTable->dwNumEntries), L"只读接口清单。" }));
            const DWORD kCount = (std::min)(ifTable->dwNumEntries, 64UL);
            for (DWORD index = 0UL; index < kCount; ++index) {
                const MIB_IFROW& entry = ifTable->table[index];
                rows.push_back(rowVec({
                    L"Interface",
                    L"ifType=" + std::to_wstring(entry.dwType),
                    L"ifIndex=" + std::to_wstring(entry.dwIndex),
                    std::wstring(entry.wszName),
                    L"mtu=" + std::to_wstring(entry.dwMtu) + L" speed=" + std::to_wstring(entry.dwSpeed),
                    L"documented IP Helper row"
                }));
            }
        }
        else {
            rows.push_back(rowVec({ L"Interface table", L"Unavailable", L"GetIfTable", L"-", win32StatusText(L"GetIfTable(data)", status), L"只读失败。" }));
        }
    }
    else {
        rows.push_back(rowVec({ L"Interface table", L"Unavailable", L"GetIfTable", L"-", win32StatusText(L"GetIfTable(size)", status), L"只读失败。" }));
    }

    ULONG addressBytes = 0UL;
    status = api.getIpAddrTable(nullptr, &addressBytes, FALSE);
    if (status == ERROR_INSUFFICIENT_BUFFER && addressBytes != 0UL) {
        std::vector<unsigned char> buffer(addressBytes, 0U);
        auto* addressTable = reinterpret_cast<PMIB_IPADDRTABLE>(buffer.data());
        status = api.getIpAddrTable(addressTable, &addressBytes, FALSE);
        if (status == NO_ERROR) {
            rows.push_back(rowVec({ L"IPv4 address table", L"OK", L"GetIpAddrTable", L"IPv4", L"entries=" + std::to_wstring(addressTable->dwNumEntries), L"只读地址摘要。" }));
        }
        else {
            rows.push_back(rowVec({ L"IPv4 address table", L"Unavailable", L"GetIpAddrTable", L"IPv4", win32StatusText(L"GetIpAddrTable(data)", status), L"只读失败。" }));
        }
    }
    else {
        rows.push_back(rowVec({ L"IPv4 address table", L"Unavailable", L"GetIpAddrTable", L"IPv4", win32StatusText(L"GetIpAddrTable(size)", status), L"只读失败。" }));
    }

    ULONG routeBytes = 0UL;
    status = api.getIpForwardTable(nullptr, &routeBytes, FALSE);
    if (status == ERROR_INSUFFICIENT_BUFFER && routeBytes != 0UL) {
        std::vector<unsigned char> buffer(routeBytes, 0U);
        auto* routeTable = reinterpret_cast<PMIB_IPFORWARDTABLE>(buffer.data());
        status = api.getIpForwardTable(routeTable, &routeBytes, FALSE);
        if (status == NO_ERROR) {
            rows.push_back(rowVec({ L"IPv4 route table", L"OK", L"GetIpForwardTable", L"IPv4", L"entries=" + std::to_wstring(routeTable->dwNumEntries), L"只读路由摘要。" }));
        }
        else {
            rows.push_back(rowVec({ L"IPv4 route table", L"Unavailable", L"GetIpForwardTable", L"IPv4", win32StatusText(L"GetIpForwardTable(data)", status), L"只读失败。" }));
        }
    }
    else {
        rows.push_back(rowVec({ L"IPv4 route table", L"Unavailable", L"GetIpForwardTable", L"IPv4", win32StatusText(L"GetIpForwardTable(size)", status), L"只读失败。" }));
    }

    rows.push_back(rowVec({ L"安全边界", L"只读", L"R3 documented API", L"IP Helper", L"无 NSI R0 IOCTL 时以公开 NETIO/NSI 投影替代空占位。", L"不读取 NSI 私有结构，不修改接口/路由。" }));
    ::FreeLibrary(api.module);
    return rows;
}

} // namespace

NetworkAuditModel::NetworkAuditModel() {
    // Network I/O and R0 queries are scheduled by NetworkView after its
    // controls are visible, so opening or switching a dock never blocks.
}

void NetworkAuditModel::refresh() {
    // Input for refresh is empty; processing rebuilds all page row data; returns empty.
    // All R0 calls are completed via the ArkDriverClient wrapper.
    pages_ = buildNetworkAuditPages();
}

void NetworkAuditModel::replacePages(std::vector<NetworkAuditPage> pages) {
    pages_ = std::move(pages);
}

const std::vector<NetworkAuditPage>& NetworkAuditModel::pages() const noexcept {
    return pages_;
}

const NetworkAuditPage* NetworkAuditModel::pageAt(const int index) const noexcept {
    if (index < 0 || index >= static_cast<int>(pages_.size())) {
        return nullptr;
    }
    return &pages_[static_cast<std::size_t>(index)];
}

std::vector<NetworkAuditPage> buildNetworkAuditPages() {
    // buildNetworkAuditPages is responsible for the real R0 wrapper integration for ARKLight Network.
    // Input is empty; calls a read-only audit wrapper during processing; returns an array of page descriptions.
    std::vector<NetworkAuditPage> pages;

    pages.push_back({
        NetworkAuditPageId::kTcpUdpCrossView,
        L"TCP/UDP R0 cross-view",
        L"合并 tcpip/netio/runtime 只读 endpoint 快照；驱动未加载时显示 Win32 错误。",
        {
            column(L"协议", 80),
            column(L"状态", 120),
            column(L"PID/来源", 120),
            column(L"Local", 180),
            column(L"Remote", 180),
            column(L"EndpointObject", 170),
            column(L"Flags", 120),
            column(L"说明", 420),
        },
        buildTcpUdpRows()
    });

    pages.push_back({
        NetworkAuditPageId::kAfdEndpoint,
        L"AFD endpoint",
        L"使用 documented TCP/UDP owner table 生成 AFD-facing 端点投影；不猜 AFD 私有结构。",
        {
            column(L"项目", 160),
            column(L"状态", 180),
            column(L"来源", 160),
            column(L"协议/接口", 220),
            column(L"说明", 420),
            column(L"安全边界", 360),
        },
        buildAfdRows()
    });

    pages.push_back({
        NetworkAuditPageId::kWfpInventory,
        L"WFP callout/filter/provider",
        L"展示 WFP provider、sublayer、filter、callout 以及 classify/notify/flowDelete owner module。",
        {
            column(L"ObjectKind/IOCTL", 180),
            column(L"状态/Layer", 160),
            column(L"Object", 170),
            column(L"Classify", 170),
            column(L"Owner", 220),
            column(L"Flags/说明", 460),
        },
        buildWfpRows()
    });

    pages.push_back({
        NetworkAuditPageId::kNdisChain,
        L"NDIS protocol/filter",
        L"展示 miniport、filter、protocol、binding 的只读链路表，并保留对象地址诊断。",
        {
            column(L"Kind/IOCTL", 160),
            column(L"Component", 240),
            column(L"If/Order", 140),
            column(L"Object", 170),
            column(L"Parent", 170),
            column(L"Owner", 220),
            column(L"Flags/Driver", 420),
        },
        buildNdisRows()
    });

    pages.push_back({
        NetworkAuditPageId::kNsiSummary,
        L"NSI 表",
        L"使用 IP Helper 接口/地址/路由表生成 NSI-facing 只读摘要；不猜 NSI 私有结构。",
        {
            column(L"项目", 160),
            column(L"状态", 180),
            column(L"来源", 160),
            column(L"协议/接口", 220),
            column(L"说明", 420),
            column(L"安全边界", 360),
        },
        buildNsiRows()
    });

    return pages;
}

} // namespace Ksword::Features::Network

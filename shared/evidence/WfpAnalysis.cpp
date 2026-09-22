#include "WfpAnalysis.h"

#include <algorithm>
#include <utility>

namespace ksword::evidence {

namespace {

// ---------------------------------------------------------------------------
// Basic utility
// ---------------------------------------------------------------------------
char lowerAscii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool equalsIgnoreCase(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (lowerAscii(a[i]) != lowerAscii(b[i])) {
            return false;
        }
    }
    return true;
}

bool startsWithIgnoreCase(std::string_view text, std::string_view prefix) noexcept {
    if (prefix.size() > text.size()) {
        return false;
    }
    return equalsIgnoreCase(text.substr(0, prefix.size()), prefix);
}

int hexDigit(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

void addKey(std::vector<std::string>& keys, std::string_view key) {
    for (const std::string& existing : keys) {
        if (std::string_view(existing) == key) {
            return;
        }
    }
    keys.emplace_back(key);
}

void mergeKeys(std::vector<std::string>& target, const std::vector<std::string>& source) {
    for (const std::string& key : source) {
        addKey(target, key);
    }
}

// ---------------------------------------------------------------------------
// Three-valued logic (Kleene). This is core to N-02/N-03: the negation of unknown
// remains unknown; unknown never collapses into 'Match' nor into 'No Match'.
// ---------------------------------------------------------------------------
ConditionMatch negateMatch(ConditionMatch value) noexcept {
    switch (value) {
    case ConditionMatch::kMatch:
        return ConditionMatch::kNoMatch;
    case ConditionMatch::kNoMatch:
        return ConditionMatch::kMatch;
    case ConditionMatch::kInsufficientInfo:
        return ConditionMatch::kInsufficientInfo;
    }
    return ConditionMatch::kInsufficientInfo;
}

ConditionMatch andMatch(ConditionMatch a, ConditionMatch b) noexcept {
    if (a == ConditionMatch::kNoMatch || b == ConditionMatch::kNoMatch) {
        return ConditionMatch::kNoMatch;
    }
    if (a == ConditionMatch::kInsufficientInfo || b == ConditionMatch::kInsufficientInfo) {
        return ConditionMatch::kInsufficientInfo;
    }
    return ConditionMatch::kMatch;
}

ConditionMatch orMatch(ConditionMatch a, ConditionMatch b) noexcept {
    if (a == ConditionMatch::kMatch || b == ConditionMatch::kMatch) {
        return ConditionMatch::kMatch;
    }
    if (a == ConditionMatch::kInsufficientInfo || b == ConditionMatch::kInsufficientInfo) {
        return ConditionMatch::kInsufficientInfo;
    }
    return ConditionMatch::kNoMatch;
}

ConditionMatch fromBool(bool value) noexcept {
    return value ? ConditionMatch::kMatch : ConditionMatch::kNoMatch;
}

// ---------------------------------------------------------------------------
// Built-in condition field table. GUIDs copied from Windows SDK fwpmu.h's FWPM_CONDITION_*.
// ---------------------------------------------------------------------------
struct FieldTableEntry final {
    WfpFieldKind kind;
    const char* guid;  // Already in normalized format (lowercase with braces).
    const char* name;
};

constexpr FieldTableEntry kFieldTable[] = {
    { WfpFieldKind::kIpLocalAddress,     "{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}", "FWPM_CONDITION_IP_LOCAL_ADDRESS" },
    { WfpFieldKind::kIpRemoteAddress,    "{b235ae9a-1d64-49b8-a44c-5ff3d9095045}", "FWPM_CONDITION_IP_REMOTE_ADDRESS" },
    // Note: FWPM_CONDITION_ICMP_TYPE is an alias for IP_LOCAL_PORT in the SDK, and FWPM_CONDITION_ICMP_CODE is an alias
    // for IP_REMOTE_PORT. The GUID cannot resolve the exact semantic meaning, so it must be interpreted as a port;
    // distinguishing them requires checking the layer. This must be explicitly stated in the UI and not treated as a port.
    { WfpFieldKind::kIpLocalPort,        "{0c1ba1af-5765-453f-af22-a8f791ac775b}", "FWPM_CONDITION_IP_LOCAL_PORT" },
    { WfpFieldKind::kIpRemotePort,       "{c35a604d-d22b-4e1a-91b4-68f674ee674b}", "FWPM_CONDITION_IP_REMOTE_PORT" },
    { WfpFieldKind::kIpProtocol,         "{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}", "FWPM_CONDITION_IP_PROTOCOL" },
    { WfpFieldKind::kDirection,          "{8784c146-ca97-44d6-9fd1-19fb1840cbf7}", "FWPM_CONDITION_DIRECTION" },
    { WfpFieldKind::kAleAppId,           "{d78e1e87-8644-4ea5-9437-d809ecefc971}", "FWPM_CONDITION_ALE_APP_ID" },
    { WfpFieldKind::kAleUserId,          "{af043a0a-b34d-4f86-979c-c90371af6e66}", "FWPM_CONDITION_ALE_USER_ID" },
    { WfpFieldKind::kIpLocalAddressType, "{6ec7f6c4-376b-45d7-9e9c-d337cedcd237}", "FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE" },
    { WfpFieldKind::kFlags,              "{632ce23b-5167-435c-86d7-e903684aa80c}", "FWPM_CONDITION_FLAGS" },
};

// Fields at this level that can actually be used to determine a connection. IP_LOCAL_ADDRESS_TYPE / FLAGS are recognized by name, but the
// connection description lacks a corresponding dimension — recognizing a name does not imply determinability; must fall back to InsufficientInfo.
bool fieldIsModeled(WfpFieldKind kind) noexcept {
    switch (kind) {
    case WfpFieldKind::kIpLocalAddress:
    case WfpFieldKind::kIpRemoteAddress:
    case WfpFieldKind::kIpLocalPort:
    case WfpFieldKind::kIpRemotePort:
    case WfpFieldKind::kIpProtocol:
    case WfpFieldKind::kDirection:
    case WfpFieldKind::kAleAppId:
    case WfpFieldKind::kAleUserId:
        return true;
    case WfpFieldKind::kIpLocalAddressType:
    case WfpFieldKind::kFlags:
    case WfpFieldKind::kUnknown:
        return false;
    }
    return false;
}

bool dataTypeIsNumeric(WfpDataType type) noexcept {
    switch (type) {
    case WfpDataType::kUint8:
    case WfpDataType::kUint16:
    case WfpDataType::kUint32:
    case WfpDataType::kUint64:
        return true;
    case WfpDataType::kEmpty:
    case WfpDataType::kByteArray16:
    case WfpDataType::kByteBlob:
    case WfpDataType::kSid:
    case WfpDataType::kV4AddrMask:
    case WfpDataType::kV6AddrMask:
    case WfpDataType::kRange:
    case WfpDataType::kUnknown:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Condition signature: used only for generation comparison in N-06, not involved in any matching logic.
// ---------------------------------------------------------------------------
std::string conditionSignature(const WfpCondition& condition) {
    std::string sig = condition.fieldKey.text;
    sig.push_back('|');
    sig += formatU64(condition.rawMatchCode, U64Format::kDecimal);
    sig.push_back('|');
    sig += formatU64(condition.value.rawTypeCode, U64Format::kDecimal);
    sig.push_back('|');
    sig += formatOptionalU64(condition.value.numeric, U64Format::kDecimal);
    sig.push_back('|');
    if (condition.value.v4Present) {
        sig += formatIpAddress(condition.value.v4.address);
        sig.push_back('/');
        sig += formatU64(condition.value.v4.mask, U64Format::kDecimal);
    }
    sig.push_back('|');
    if (condition.value.v6Present) {
        sig += formatIpAddress(condition.value.v6.address);
        sig.push_back('/');
        sig += formatU64(condition.value.v6.prefixLength, U64Format::kDecimal);
    }
    sig.push_back('|');
    if (condition.value.blobText.present) {
        sig += condition.value.blobText.value;
    }
    sig.push_back('|');
    if (condition.value.sidText.present) {
        sig += condition.value.sidText.value;
    }
    sig.push_back('|');
    sig += condition.value.rawText;
    sig.push_back('|');
    sig += formatOptionalU64(condition.value.range.low, U64Format::kDecimal);
    sig.push_back('-');
    sig += formatOptionalU64(condition.value.range.high, U64Format::kDecimal);
    return sig;
}

std::string filterConditionsSignature(const WfpFilter& filter) {
    std::string sig = filter.conditionsTruncated ? "truncated;" : "complete;";
    for (const WfpCondition& condition : filter.conditions) {
        sig += conditionSignature(condition);
        sig.push_back(';');
    }
    return sig;
}

} // namespace

// ---------------------------------------------------------------------------
// Limit key
// ---------------------------------------------------------------------------
bool hasLimitation(const std::vector<std::string>& keys, std::string_view key) noexcept {
    for (const std::string& existing : keys) {
        if (std::string_view(existing) == key) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------
bool parseGuid(std::string_view text, WfpGuid& out) {
    std::string_view body = text;
    if (body.size() >= 2 && body.front() == '{' && body.back() == '}') {
        body = body.substr(1, body.size() - 2);
    }
    if (body.size() != 36U) {
        return false;
    }
    static constexpr std::size_t kHyphen[4] = { 8U, 13U, 18U, 23U };
    for (std::size_t position : kHyphen) {
        if (body[position] != '-') {
            return false;
        }
    }
    std::string normalized;
    normalized.reserve(38U);
    normalized.push_back('{');
    for (std::size_t i = 0; i < body.size(); ++i) {
        const char kC = body[i];
        if (kC == '-') {
            if (i != kHyphen[0] && i != kHyphen[1] && i != kHyphen[2] && i != kHyphen[3]) {
                return false;
            }
            normalized.push_back('-');
            continue;
        }
        if (hexDigit(kC) < 0) {
            return false;
        }
        normalized.push_back(lowerAscii(kC));
    }
    normalized.push_back('}');
    out.text = std::move(normalized);
    return true;
}

WfpGuid guidFromText(std::string_view text) {
    WfpGuid guid;
    if (!parseGuid(text, guid)) {
        return WfpGuid{};
    }
    return guid;
}

// ---------------------------------------------------------------------------
// address
// ---------------------------------------------------------------------------
const char* wfpAddressFamilyName(WfpAddressFamily family) noexcept {
    switch (family) {
    case WfpAddressFamily::kUnknown: return "Unknown";
    case WfpAddressFamily::kIPv4:    return "IPv4";
    case WfpAddressFamily::kIPv6:    return "IPv6";
    }
    return "Unknown";
}

WfpAddress WfpAddress::ipv4FromHostOrder(std::uint32_t hostOrder) noexcept {
    WfpAddress address;
    address.family = WfpAddressFamily::kIPv4;
    address.bytes[0] = static_cast<std::uint8_t>((hostOrder >> 24) & 0xFFU);
    address.bytes[1] = static_cast<std::uint8_t>((hostOrder >> 16) & 0xFFU);
    address.bytes[2] = static_cast<std::uint8_t>((hostOrder >> 8) & 0xFFU);
    address.bytes[3] = static_cast<std::uint8_t>(hostOrder & 0xFFU);
    return address;
}

WfpAddress WfpAddress::ipv6FromBytes(const std::array<std::uint8_t, 16>& raw) noexcept {
    WfpAddress address;
    address.family = WfpAddressFamily::kIPv6;
    address.bytes = raw;
    return address;
}

bool operator==(const WfpAddress& a, const WfpAddress& b) noexcept {
    if (a.family != b.family) {
        return false;
    }
    const std::size_t kLength = (a.family == WfpAddressFamily::kIPv4) ? 4U : 16U;
    if (a.family == WfpAddressFamily::kUnknown) {
        return true;  // Two "unknown" values are structurally equal; the caller must check known() first.
    }
    for (std::size_t i = 0; i < kLength; ++i) {
        if (a.bytes[i] != b.bytes[i]) {
            return false;
        }
    }
    return true;
}

namespace {

bool parseIpv4Bytes(std::string_view text, std::array<std::uint8_t, 4>& out) {
    std::size_t pos = 0;
    for (std::size_t part = 0; part < 4U; ++part) {
        if (part > 0) {
            if (pos >= text.size() || text[pos] != '.') {
                return false;
            }
            ++pos;
        }
        const std::size_t kStart = pos;
        std::uint32_t value = 0;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
            value = value * 10U + static_cast<std::uint32_t>(text[pos] - '0');
            if (value > 255U) {
                return false;
            }
            ++pos;
        }
        const std::size_t kDigits = pos - kStart;
        if (kDigits == 0U || kDigits > 3U) {
            return false;
        }
        // N-02 "Display must match input": Leading zeros are always rejected to align with inet_pton. Historically,
        // inet_addr parsed "010" as octal 8. Accepting it loosely would cause "010.001.001.001" to display as
        // 10.1.1.1 here but as 8.1.1.1 in the system interface—three meanings for the same string with no warning.
        if (kDigits > 1U && text[kStart] == '0') {
            return false;
        }
        out[part] = static_cast<std::uint8_t>(value);
    }
    return pos == text.size();
}

bool parseIpv6Bytes(std::string_view text, std::array<std::uint8_t, 16>& out) {
    std::vector<std::uint8_t> head;
    std::vector<std::uint8_t> tail;
    bool sawDoubleColon = false;
    bool inTail = false;
    std::size_t pos = 0;

    if (!text.empty() && text[0] == ':') {
        if (text.size() < 2U || text[1] != ':') {
            return false;
        }
        sawDoubleColon = true;
        inTail = true;
        pos = 2U;
        if (pos == text.size()) {
            out.fill(0U);
            return true;  // "::"
        }
    }

    while (pos < text.size()) {
        const std::size_t kStart = pos;
        while (pos < text.size() && text[pos] != ':') {
            ++pos;
        }
        const std::string_view kToken = text.substr(kStart, pos - kStart);
        if (kToken.empty()) {
            return false;
        }
        std::vector<std::uint8_t>& target = inTail ? tail : head;
        if (kToken.find('.') != std::string_view::npos) {
            if (pos != text.size()) {
                return false;  // Embedded IPv4 can only appear at the end.
            }
            std::array<std::uint8_t, 4> v4{};
            if (!parseIpv4Bytes(kToken, v4)) {
                return false;
            }
            for (std::uint8_t byte : v4) {
                target.push_back(byte);
            }
            break;
        }
        if (kToken.size() > 4U) {
            return false;
        }
        std::uint32_t group = 0;
        for (char c : kToken) {
            const int kDigit = hexDigit(c);
            if (kDigit < 0) {
                return false;
            }
            group = group * 16U + static_cast<std::uint32_t>(kDigit);
        }
        target.push_back(static_cast<std::uint8_t>((group >> 8) & 0xFFU));
        target.push_back(static_cast<std::uint8_t>(group & 0xFFU));

        if (pos == text.size()) {
            break;
        }
        ++pos;  // Skip ':'.
        if (pos < text.size() && text[pos] == ':') {
            if (sawDoubleColon) {
                return false;
            }
            sawDoubleColon = true;
            inTail = true;
            ++pos;
            if (pos == text.size()) {
                break;  // Ends with "::"
            }
        } else if (pos == text.size()) {
            return false;  // Single ':' at end
        }
    }

    const std::size_t kFilled = head.size() + tail.size();
    if (sawDoubleColon) {
        if (kFilled >= 16U) {
            return false;  // "::" must consume at least one group.
        }
    } else if (kFilled != 16U) {
        return false;
    }
    out.fill(0U);
    for (std::size_t i = 0; i < head.size(); ++i) {
        out[i] = head[i];
    }
    for (std::size_t i = 0; i < tail.size(); ++i) {
        out[16U - tail.size() + i] = tail[i];
    }
    return true;
}

std::string formatHexGroup(std::uint32_t group) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    bool started = false;
    for (int shift = 12; shift >= 0; shift -= 4) {
        const std::uint32_t kNibble = (group >> shift) & 0xFU;
        if (kNibble != 0U || started || shift == 0) {
            text.push_back(kDigits[kNibble]);
            started = true;
        }
    }
    return text;
}

} // namespace

bool parseIpAddress(std::string_view text, WfpAddress& out) {
    if (text.empty()) {
        return false;
    }
    if (text.find(':') != std::string_view::npos) {
        std::array<std::uint8_t, 16> bytes{};
        if (!parseIpv6Bytes(text, bytes)) {
            return false;
        }
        out = WfpAddress::ipv6FromBytes(bytes);
        return true;
    }
    std::array<std::uint8_t, 4> v4{};
    if (!parseIpv4Bytes(text, v4)) {
        return false;
    }
    WfpAddress address;
    address.family = WfpAddressFamily::kIPv4;
    address.bytes.fill(0U);
    for (std::size_t i = 0; i < 4U; ++i) {
        address.bytes[i] = v4[i];
    }
    out = address;
    return true;
}

std::string formatIpAddress(const WfpAddress& address) {
    if (address.family == WfpAddressFamily::kIPv4) {
        std::string text;
        for (std::size_t i = 0; i < 4U; ++i) {
            if (i > 0) {
                text.push_back('.');
            }
            text += formatU64(address.bytes[i], U64Format::kDecimal);
        }
        return text;
    }
    if (address.family != WfpAddressFamily::kIPv6) {
        return std::string();
    }

    std::array<std::uint32_t, 8> groups{};
    for (std::size_t i = 0; i < 8U; ++i) {
        groups[i] = (static_cast<std::uint32_t>(address.bytes[i * 2U]) << 8) |
                    static_cast<std::uint32_t>(address.bytes[i * 2U + 1U]);
    }
    // RFC 5952: compress the longest zero segment (length >= 2); in case of a tie, take the leftmost one.
    std::size_t bestStart = 8U;
    std::size_t bestLength = 0;
    std::size_t runStart = 8U;
    std::size_t runLength = 0;
    for (std::size_t i = 0; i < 8U; ++i) {
        if (groups[i] == 0U) {
            if (runLength == 0U) {
                runStart = i;
            }
            ++runLength;
            if (runLength > bestLength) {
                bestLength = runLength;
                bestStart = runStart;
            }
        } else {
            runLength = 0;
        }
    }
    if (bestLength < 2U) {
        bestStart = 8U;
        bestLength = 0;
    }

    std::string text;
    for (std::size_t i = 0; i < 8U;) {
        if (bestLength > 0U && i == bestStart) {
            text += "::";
            i += bestLength;
            continue;
        }
        if (!text.empty() && text.back() != ':') {
            text.push_back(':');
        }
        text += formatHexGroup(groups[i]);
        ++i;
    }
    if (text.empty()) {
        text = "::";
    }
    return text;
}

bool ipv4HostOrder(const WfpAddress& address, std::uint32_t& out) noexcept {
    if (address.family != WfpAddressFamily::kIPv4) {
        return false;
    }
    out = (static_cast<std::uint32_t>(address.bytes[0]) << 24) |
          (static_cast<std::uint32_t>(address.bytes[1]) << 16) |
          (static_cast<std::uint32_t>(address.bytes[2]) << 8) |
          static_cast<std::uint32_t>(address.bytes[3]);
    return true;
}

bool maskToPrefixLength(std::uint32_t mask, std::uint32_t& outPrefixLength) noexcept {
    const std::uint32_t kInverted = ~mask;
    // The bitwise negation of a contiguous mask is always of the form 2^n - 1. Non-contiguous masks (e.g., 255.0.255.0) are
    // rejected here; the caller must continue presenting them as 'masks' and cannot convert them to prefix lengths (N-02).
    if ((kInverted & (kInverted + 1U)) != 0U) {
        return false;
    }
    std::uint32_t bits = 0;
    std::uint32_t value = mask;
    while (value != 0U) {
        bits += (value & 1U);
        value >>= 1;
    }
    outPrefixLength = bits;
    return true;
}

const char* addressContainmentName(AddressContainment containment) noexcept {
    switch (containment) {
    case AddressContainment::kInside:      return "Inside";
    case AddressContainment::kOutside:     return "Outside";
    case AddressContainment::kUndecidable: return "Undecidable";
    }
    return "Undecidable";
}

AddressContainment classifyV4Containment(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept {
    std::uint32_t addressValue = 0;
    std::uint32_t networkValue = 0;
    // If either side is not a resolved IPv4 address—including offline samples where v4Present is set in the
    // condition but the address was never decoded—this does not constitute evidence of "not being in the subnet."
    if (!ipv4HostOrder(address, addressValue) || !ipv4HostOrder(subnet.address, networkValue)) {
        return AddressContainment::kUndecidable;
    }
    return ((addressValue & subnet.mask) == (networkValue & subnet.mask)) ? AddressContainment::kInside
                                                                         : AddressContainment::kOutside;
}

AddressContainment classifyV6Containment(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept {
    if (address.family != WfpAddressFamily::kIPv6 || prefix.address.family != WfpAddressFamily::kIPv6) {
        return AddressContainment::kUndecidable;
    }
    if (!prefix.prefixLengthValid || prefix.prefixLength > 128U) {
        return AddressContainment::kUndecidable;
    }
    const std::size_t kFullBytes = prefix.prefixLength / 8U;
    const std::size_t kRemainingBits = prefix.prefixLength % 8U;
    for (std::size_t i = 0; i < kFullBytes; ++i) {
        if (address.bytes[i] != prefix.address.bytes[i]) {
            return AddressContainment::kOutside;
        }
    }
    if (kRemainingBits == 0U) {
        return AddressContainment::kInside;
    }
    const std::uint32_t kMask = (0xFFU << (8U - kRemainingBits)) & 0xFFU;
    return ((static_cast<std::uint32_t>(address.bytes[kFullBytes]) & kMask) ==
            (static_cast<std::uint32_t>(prefix.address.bytes[kFullBytes]) & kMask))
               ? AddressContainment::kInside
               : AddressContainment::kOutside;
}

bool addressInV4Subnet(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept {
    return classifyV4Containment(address, subnet) == AddressContainment::kInside;
}

bool addressInV6Prefix(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept {
    return classifyV6Containment(address, prefix) == AddressContainment::kInside;
}

// ---------------------------------------------------------------------------
// Enum name and decoding
// ---------------------------------------------------------------------------
const char* wfpDataTypeName(WfpDataType type) noexcept {
    switch (type) {
    case WfpDataType::kEmpty:       return "Empty";
    case WfpDataType::kUint8:       return "Uint8";
    case WfpDataType::kUint16:      return "Uint16";
    case WfpDataType::kUint32:      return "Uint32";
    case WfpDataType::kUint64:      return "Uint64";
    case WfpDataType::kByteArray16: return "ByteArray16";
    case WfpDataType::kByteBlob:    return "ByteBlob";
    case WfpDataType::kSid:         return "Sid";
    case WfpDataType::kV4AddrMask:  return "V4AddrMask";
    case WfpDataType::kV6AddrMask:  return "V6AddrMask";
    case WfpDataType::kRange:       return "Range";
    case WfpDataType::kUnknown:     return "Unknown";
    }
    return "Unknown";
}

WfpDataType decodeDataType(std::uint32_t rawTypeCode) noexcept {
    // Values come from FWP_DATA_TYPE in the Windows SDK header fwptypes.h.
    switch (rawTypeCode) {
    case 0U:     return WfpDataType::kEmpty;
    case 1U:     return WfpDataType::kUint8;
    case 2U:     return WfpDataType::kUint16;
    case 3U:     return WfpDataType::kUint32;
    case 4U:     return WfpDataType::kUint64;
    case 11U:    return WfpDataType::kByteArray16;
    case 12U:    return WfpDataType::kByteBlob;
    case 13U:    return WfpDataType::kSid;
    case 0x100U: return WfpDataType::kV4AddrMask;
    case 0x101U: return WfpDataType::kV6AddrMask;
    case 0x102U: return WfpDataType::kRange;
    default:     break;
    }
    return WfpDataType::kUnknown;
}

const char* wfpMatchTypeName(WfpMatchType match) noexcept {
    switch (match) {
    case WfpMatchType::kEqual:                return "Equal";
    case WfpMatchType::kGreater:              return "Greater";
    case WfpMatchType::kLess:                 return "Less";
    case WfpMatchType::kGreaterOrEqual:       return "GreaterOrEqual";
    case WfpMatchType::kLessOrEqual:          return "LessOrEqual";
    case WfpMatchType::kRange:                return "Range";
    case WfpMatchType::kFlagsAllSet:          return "FlagsAllSet";
    case WfpMatchType::kFlagsAnySet:          return "FlagsAnySet";
    case WfpMatchType::kFlagsNoneSet:         return "FlagsNoneSet";
    case WfpMatchType::kEqualCaseInsensitive: return "EqualCaseInsensitive";
    case WfpMatchType::kNotEqual:             return "NotEqual";
    case WfpMatchType::kPrefix:               return "Prefix";
    case WfpMatchType::kNotPrefix:            return "NotPrefix";
    case WfpMatchType::kUnknown:              return "Unknown";
    }
    return "Unknown";
}

WfpMatchType decodeMatchType(std::uint32_t rawMatchCode) noexcept {
    // Values are from FWP_MATCH_TYPE (0..12).
    switch (rawMatchCode) {
    case 0U:  return WfpMatchType::kEqual;
    case 1U:  return WfpMatchType::kGreater;
    case 2U:  return WfpMatchType::kLess;
    case 3U:  return WfpMatchType::kGreaterOrEqual;
    case 4U:  return WfpMatchType::kLessOrEqual;
    case 5U:  return WfpMatchType::kRange;
    case 6U:  return WfpMatchType::kFlagsAllSet;
    case 7U:  return WfpMatchType::kFlagsAnySet;
    case 8U:  return WfpMatchType::kFlagsNoneSet;
    case 9U:  return WfpMatchType::kEqualCaseInsensitive;
    case 10U: return WfpMatchType::kNotEqual;
    case 11U: return WfpMatchType::kPrefix;
    case 12U: return WfpMatchType::kNotPrefix;
    default:  break;
    }
    return WfpMatchType::kUnknown;
}

const char* wfpDirectionName(WfpDirection direction) noexcept {
    switch (direction) {
    case WfpDirection::kUnknown:  return "Unknown";
    case WfpDirection::kOutbound: return "Outbound";
    case WfpDirection::kInbound:  return "Inbound";
    case WfpDirection::kForward:  return "Forward";
    }
    return "Unknown";
}

WfpDirection decodeDirectionValue(std::uint64_t rawValue) noexcept {
    // FWP_DIRECTION_ only defines OUTBOUND=0 and INBOUND=1. 2 is FWP_DIRECTION_MAX, not FORWARD.
    switch (rawValue) {
    case 0U: return WfpDirection::kOutbound;
    case 1U: return WfpDirection::kInbound;
    default: break;
    }
    return WfpDirection::kUnknown;
}

const char* wfpActionTypeName(WfpActionType action) noexcept {
    switch (action) {
    case WfpActionType::kUnknown:            return "Unknown";
    case WfpActionType::kBlock:              return "Block";
    case WfpActionType::kPermit:             return "Permit";
    case WfpActionType::kCalloutTerminating: return "CalloutTerminating";
    case WfpActionType::kCalloutInspection:  return "CalloutInspection";
    case WfpActionType::kCalloutUnknown:     return "CalloutUnknown";
    case WfpActionType::kContinue:           return "Continue";
    case WfpActionType::kNone:               return "None";
    case WfpActionType::kNoneNoMatch:        return "NoneNoMatch";
    }
    return "Unknown";
}

WfpActionType decodeActionType(std::uint32_t rawActionCode) noexcept {
    // FWP_ACTION_* = low-order sequence number | flags. Actions with the same sequence number but different flags
    // are not the same action; therefore, compare against the full constant here, not just the lower 8 bits.
    constexpr std::uint32_t kFlagTerminating = 0x00001000U;
    constexpr std::uint32_t kFlagNonTerminating = 0x00002000U;
    constexpr std::uint32_t kFlagCallout = 0x00004000U;
    switch (rawActionCode) {
    case 0x00000001U | kFlagTerminating:                  return WfpActionType::kBlock;
    case 0x00000002U | kFlagTerminating:                  return WfpActionType::kPermit;
    case 0x00000003U | kFlagCallout | kFlagTerminating:   return WfpActionType::kCalloutTerminating;
    case 0x00000004U | kFlagCallout | kFlagNonTerminating: return WfpActionType::kCalloutInspection;
    case 0x00000005U | kFlagCallout:                      return WfpActionType::kCalloutUnknown;
    case 0x00000006U | kFlagNonTerminating:               return WfpActionType::kContinue;
    case 0x00000007U:                                     return WfpActionType::kNone;
    case 0x00000008U:                                     return WfpActionType::kNoneNoMatch;
    default: break;
    }
    return WfpActionType::kUnknown;
}

bool actionIsCallout(WfpActionType action) noexcept {
    switch (action) {
    case WfpActionType::kCalloutTerminating:
    case WfpActionType::kCalloutInspection:
    case WfpActionType::kCalloutUnknown:
        return true;
    case WfpActionType::kUnknown:
    case WfpActionType::kBlock:
    case WfpActionType::kPermit:
    case WfpActionType::kContinue:
    case WfpActionType::kNone:
    case WfpActionType::kNoneNoMatch:
        return false;
    }
    return false;
}

const char* wfpFieldKindName(WfpFieldKind kind) noexcept {
    switch (kind) {
    case WfpFieldKind::kUnknown:            return "Unknown";
    case WfpFieldKind::kIpLocalAddress:     return "IpLocalAddress";
    case WfpFieldKind::kIpRemoteAddress:    return "IpRemoteAddress";
    case WfpFieldKind::kIpLocalPort:        return "IpLocalPort";
    case WfpFieldKind::kIpRemotePort:       return "IpRemotePort";
    case WfpFieldKind::kIpProtocol:         return "IpProtocol";
    case WfpFieldKind::kDirection:          return "Direction";
    case WfpFieldKind::kAleAppId:           return "AleAppId";
    case WfpFieldKind::kAleUserId:          return "AleUserId";
    case WfpFieldKind::kIpLocalAddressType: return "IpLocalAddressType";
    case WfpFieldKind::kFlags:              return "Flags";
    }
    return "Unknown";
}

WfpFieldDescriptor lookupFieldByGuid(const WfpGuid& fieldKey) noexcept {
    WfpFieldDescriptor descriptor;
    if (!fieldKey.known()) {
        return descriptor;
    }
    for (const FieldTableEntry& entry : kFieldTable) {
        if (fieldKey.text == entry.guid) {
            descriptor.kind = entry.kind;
            descriptor.name = entry.name;
            return descriptor;
        }
    }
    return descriptor;
}

WfpGuid fieldGuidFor(WfpFieldKind kind) {
    for (const FieldTableEntry& entry : kFieldTable) {
        if (entry.kind == kind) {
            return guidFromText(entry.guid);
        }
    }
    return WfpGuid{};
}

const char* wfpWeightKindName(WfpWeightKind kind) noexcept {
    switch (kind) {
    case WfpWeightKind::kUnknown:  return "Unknown";
    case WfpWeightKind::kAuto:     return "Auto";
    case WfpWeightKind::kExplicit: return "Explicit";
    }
    return "Unknown";
}

const char* wfpPartitionName(WfpPartition partition) noexcept {
    switch (partition) {
    case WfpPartition::kProviders: return "Providers";
    case WfpPartition::kSubLayers: return "SubLayers";
    case WfpPartition::kLayers:    return "Layers";
    case WfpPartition::kFilters:   return "Filters";
    case WfpPartition::kCallouts:  return "Callouts";
    }
    return "Providers";
}

const char* referenceStateName(ReferenceState state) noexcept {
    switch (state) {
    case ReferenceState::kResolved:            return "Resolved";
    case ReferenceState::kUnknownObject:       return "UnknownObject";
    case ReferenceState::kAmbiguous:           return "Ambiguous";
    case ReferenceState::kNotSpecified:        return "NotSpecified";
    case ReferenceState::kCatalogNotCollected: return "CatalogNotCollected";
    case ReferenceState::kCatalogIncomplete:   return "CatalogIncomplete";
    }
    return "NotSpecified";
}

const char* conditionMatchName(ConditionMatch match) noexcept {
    switch (match) {
    case ConditionMatch::kMatch:            return "Match";
    case ConditionMatch::kNoMatch:          return "NoMatch";
    case ConditionMatch::kInsufficientInfo: return "InsufficientInfo";
    }
    return "InsufficientInfo";
}

const char* weightOrderConfidenceName(WeightOrderConfidence confidence) noexcept {
    switch (confidence) {
    case WeightOrderConfidence::kUnknown:         return "Unknown";
    case WeightOrderConfidence::kExplicitWeight:  return "ExplicitWeight";
    case WeightOrderConfidence::kEffectiveWeight: return "EffectiveWeight";
    }
    return "Unknown";
}

const char* candidateDecisionName(CandidateDecision decision) noexcept {
    switch (decision) {
    case CandidateDecision::kUnknown:          return "Unknown";
    case CandidateDecision::kNoMatchingFilter: return "NoMatchingFilter";
    case CandidateDecision::kBlockCandidate:   return "BlockCandidate";
    case CandidateDecision::kPermitCandidate:  return "PermitCandidate";
    }
    return "Unknown";
}

const char* observationSourceName(ObservationSource source) noexcept {
    switch (source) {
    case ObservationSource::kUnknown:              return "Unknown";
    case ObservationSource::kWfpNetEventEnum:      return "WfpNetEventEnum";
    case ObservationSource::kWfpNetEventSubscribe: return "WfpNetEventSubscribe";
    case ObservationSource::kKernelAleCallout:     return "KernelAleCallout";
    case ObservationSource::kEtwProvider:          return "EtwProvider";
    case ObservationSource::kSecurityAuditLog:     return "SecurityAuditLog";
    case ObservationSource::kOfflineImport:        return "OfflineImport";
    }
    return "Unknown";
}

const char* wfpEventVerdictName(WfpEventVerdict verdict) noexcept {
    switch (verdict) {
    case WfpEventVerdict::kUnknown:   return "Unknown";
    case WfpEventVerdict::kPermitted: return "Permitted";
    case WfpEventVerdict::kBlocked:   return "Blocked";
    }
    return "Unknown";
}

const char* observationTrustName(ObservationTrust trust) noexcept {
    switch (trust) {
    case ObservationTrust::kActualObservation: return "ActualObservation";
    case ObservationTrust::kSourceUnknown:     return "SourceUnknown";
    case ObservationTrust::kSourceUnsupported: return "SourceUnsupported";
    case ObservationTrust::kSourceNotEnabled:  return "SourceNotEnabled";
    }
    return "SourceUnknown";
}

const char* filterLinkStateName(FilterLinkState state) noexcept {
    switch (state) {
    case FilterLinkState::kLinkedByGuid:                    return "LinkedByGuid";
    case FilterLinkState::kLinkedByRuntimeIdSameGeneration: return "LinkedByRuntimeIdSameGeneration";
    case FilterLinkState::kRejectedIdReused:                return "RejectedIdReused";
    case FilterLinkState::kRejectedStaleGeneration:         return "RejectedStaleGeneration";
    case FilterLinkState::kRejectedAmbiguous:               return "RejectedAmbiguous";
    case FilterLinkState::kNoMatch:                         return "NoMatch";
    case FilterLinkState::kCatalogNotCollected:             return "CatalogNotCollected";
    case FilterLinkState::kCatalogIncomplete:               return "CatalogIncomplete";
    case FilterLinkState::kNotSpecified:                    return "NotSpecified";
    }
    return "NotSpecified";
}

const char* wfpNavigationRejectionName(WfpNavigationRejection rejection) noexcept {
    switch (rejection) {
    case WfpNavigationRejection::kNone:              return "None";
    case WfpNavigationRejection::kTargetPageMissing: return "TargetPageMissing";
    case WfpNavigationRejection::kObjectNotPresent:  return "ObjectNotPresent";
    case WfpNavigationRejection::kIdentityUnusable:  return "IdentityUnusable";
    case WfpNavigationRejection::kEvidenceIdMissing: return "EvidenceIdMissing";
    case WfpNavigationRejection::kEvidenceNotSaved:  return "EvidenceNotSaved";
    case WfpNavigationRejection::kSourceNotTrusted:  return "SourceNotTrusted";
    }
    return "ObjectNotPresent";
}

const char* catalogChangeKindName(CatalogChangeKind kind) noexcept {
    switch (kind) {
    case CatalogChangeKind::kAdded:             return "Added";
    case CatalogChangeKind::kRemoved:           return "Removed";
    case CatalogChangeKind::kActionChanged:     return "ActionChanged";
    case CatalogChangeKind::kWeightChanged:     return "WeightChanged";
    case CatalogChangeKind::kConditionsChanged: return "ConditionsChanged";
    case CatalogChangeKind::kRuntimeIdReused:   return "RuntimeIdReused";
    case CatalogChangeKind::kPresenceUnknown:   return "PresenceUnknown";
    }
    return "PresenceUnknown";
}

const char* wfpOwnerAttributionName(WfpOwnerAttribution attribution) noexcept {
    switch (attribution) {
    case WfpOwnerAttribution::kUnknown:        return "Unknown";
    case WfpOwnerAttribution::kCandidate:      return "Candidate";
    case WfpOwnerAttribution::kDirectEvidence: return "DirectEvidence";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// Condition
// ---------------------------------------------------------------------------
bool WfpCondition::interpreted() const noexcept {
    return field != WfpFieldKind::kUnknown && match != WfpMatchType::kUnknown &&
           value.type != WfpDataType::kUnknown;
}

bool WfpCondition::evaluable() const noexcept {
    return interpreted() && fieldIsModeled(field);
}

WfpCondition makeCondition(const WfpGuid& fieldKey, std::uint32_t rawMatchCode, WfpConditionValue value) {
    WfpCondition condition;
    condition.fieldKey = fieldKey;
    const WfpFieldDescriptor kDescriptor = lookupFieldByGuid(fieldKey);
    condition.field = kDescriptor.kind;
    condition.fieldName = kDescriptor.name;
    condition.rawMatchCode = rawMatchCode;
    condition.match = decodeMatchType(rawMatchCode);
    condition.value = std::move(value);
    return condition;
}

// ---------------------------------------------------------------------------
// N-05 attribution
// ---------------------------------------------------------------------------
OwnerAttributionResult deriveOwnerAttribution(const OwnerEvidence& evidence) {
    OwnerAttributionResult result;

    // Signature info only appears if actually read. If not read, it's not read; a certificate isn't added just because the name looks like Microsoft's.
    result.signerCertificateAvailable = evidence.signerCertificateRead && evidence.signerSubject.present;
    if (result.signerCertificateAvailable) {
        result.signerSubject = evidence.signerSubject;
    }

    if (evidence.serviceName.present) {
        result.serviceName = evidence.serviceName;
    }
    if (evidence.displayNameAmbiguous) {
        addKey(result.limitationKeys, "wfp.owner.ambiguous-display-name");
    }

    const bool kHasModuleAddress = evidence.moduleAddress.present;
    const bool kHasDirectModule =
        kHasModuleAddress && evidence.moduleResolved && evidence.resolvedModulePath.present;

    if (kHasDirectModule) {
        // Direct evidence: the address falls within a range of a loaded image, identifying the file.
        result.attribution = WfpOwnerAttribution::kDirectEvidence;
        result.ownerModulePath = evidence.resolvedModulePath;
        return result;
    }

    if (kHasModuleAddress) {
        // Has an address but no image to cover it — typically the module has been unloaded. Keep the address, but do not name the file.
        addKey(result.limitationKeys, "wfp.owner.module-unresolved");
    }

    if (evidence.serviceRecordFound && evidence.serviceImagePath.present) {
        // The service configuration specifies 'who should be loaded by this service', not 'this code is it'. It can only be a candidate.
        result.attribution = WfpOwnerAttribution::kCandidate;
        result.candidateModulePath = evidence.serviceImagePath;
        return result;
    }

    if (evidence.serviceName.present && !evidence.serviceRecordFound) {
        addKey(result.limitationKeys, "wfp.owner.service-not-found");
        result.attribution = WfpOwnerAttribution::kUnknown;
        return result;
    }

    if (evidence.displayName.present) {
        // Display name only. N-05 explicitly forbids guessing driver files by name.
        addKey(result.limitationKeys, "wfp.owner.name-only");
        result.attribution = WfpOwnerAttribution::kUnknown;
        return result;
    }

    if (!kHasModuleAddress) {
        addKey(result.limitationKeys, "wfp.owner.no-evidence");
    }
    result.attribution = WfpOwnerAttribution::kUnknown;
    return result;
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------
void WfpCatalog::setPartitionState(WfpPartition partition, CollectionOutcome outcome, CoverageAccount coverage) {
    WfpPartitionState& state = partitions_[static_cast<std::size_t>(partition)];
    state.outcome = std::move(outcome);
    state.coverage = std::move(coverage);
}

const WfpPartitionState& WfpCatalog::partitionState(WfpPartition partition) const noexcept {
    return partitions_[static_cast<std::size_t>(partition)];
}

bool WfpCatalog::partitionUsableForAbsence(WfpPartition partition) const noexcept {
    const WfpPartitionState& state = partitionState(partition);
    if (state.outcome.status != CollectionStatus::kSuccess) {
        return false;
    }
    // F-06: Full coverage requires positive evidence. An empty ledger = unknown coverage ≠ full enumeration.
    return state.coverage.fullyCovered();
}

bool WfpCatalog::registerKey(Index& index, const WfpGuid& key, std::size_t position) {
    if (!key.known()) {
        return true;  // Rows without GUID cannot enter the index; they rely solely on runtime IDs or remain unassociatable.
    }
    const auto kInserted = index.byGuid.emplace(key.text, position);
    if (!kInserted.second) {
        index.duplicated[key.text] = true;
        return false;
    }
    return true;
}

WfpCatalog::IndexHit WfpCatalog::lookup(const Index& index,
                                        const WfpGuid& key,
                                        WfpPartition partition) const {
    IndexHit hit;
    if (!key.known()) {
        hit.state = ReferenceState::kNotSpecified;
        return hit;
    }
    if (index.duplicated.find(key.text) != index.duplicated.end()) {
        hit.state = ReferenceState::kAmbiguous;
        return hit;
    }
    const auto kIt = index.byGuid.find(key.text);
    if (kIt != index.byGuid.end()) {
        hit.state = ReferenceState::kResolved;
        hit.hasPosition = true;
        hit.position = kIt->second;
        return hit;
    }
    // N-06: Only partitions that can positively prove complete enumeration allow "not found in directory" to imply "object does not exist".
    // The criterion must consistently follow partitionUsableForAbsence alongside analyzeStaticCandidates and diffCatalogs:
    // statusCarriesObservation returns true for Partial; using it would treat a partition enumerated to only 1/9 as 'directory
    // available', thereby claiming 'unknown object' for a GUID (semantically meaning the directory truly contains nothing).
    if (partitionUsableForAbsence(partition)) {
        hit.state = ReferenceState::kUnknownObject;
        return hit;
    }
    hit.state = statusCarriesObservation(partitionState(partition).outcome.status)
                    ? ReferenceState::kCatalogIncomplete
                    : ReferenceState::kCatalogNotCollected;
    return hit;
}

bool WfpCatalog::addProvider(WfpProvider provider) {
    const std::size_t kPosition = providers_.size();
    const bool kUnique = registerKey(providerIndex_, provider.providerKey, kPosition);
    providers_.push_back(std::move(provider));
    return kUnique;
}

bool WfpCatalog::addSubLayer(WfpSubLayer subLayer) {
    const std::size_t kPosition = subLayers_.size();
    const bool kUnique = registerKey(subLayerIndex_, subLayer.subLayerKey, kPosition);
    subLayers_.push_back(std::move(subLayer));
    return kUnique;
}

bool WfpCatalog::addLayer(WfpLayer layer) {
    const std::size_t kPosition = layers_.size();
    const bool kUnique = registerKey(layerIndex_, layer.layerKey, kPosition);
    layers_.push_back(std::move(layer));
    return kUnique;
}

bool WfpCatalog::addCallout(WfpCallout callout) {
    const std::size_t kPosition = callouts_.size();
    const bool kUnique = registerKey(calloutIndex_, callout.calloutKey, kPosition);
    callouts_.push_back(std::move(callout));
    return kUnique;
}

bool WfpCatalog::addFilter(WfpFilter filter) {
    const std::size_t kPosition = filters_.size();
    const bool kUnique = registerKey(filterIndex_, filter.filterKey, kPosition);
    filters_.push_back(std::move(filter));
    return kUnique;
}

ObjectReference WfpCatalog::resolveProvider(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit kHit = lookup(providerIndex_, key, WfpPartition::kProviders);
    reference.state = kHit.state;
    if (kHit.hasPosition) {
        reference.resolvedName = providers_[kHit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveSubLayer(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit kHit = lookup(subLayerIndex_, key, WfpPartition::kSubLayers);
    reference.state = kHit.state;
    if (kHit.hasPosition) {
        reference.resolvedName = subLayers_[kHit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveLayer(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit kHit = lookup(layerIndex_, key, WfpPartition::kLayers);
    reference.state = kHit.state;
    if (kHit.hasPosition) {
        reference.resolvedName = layers_[kHit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveCallout(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit kHit = lookup(calloutIndex_, key, WfpPartition::kCallouts);
    reference.state = kHit.state;
    if (kHit.hasPosition) {
        reference.resolvedName = callouts_[kHit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveFilter(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit kHit = lookup(filterIndex_, key, WfpPartition::kFilters);
    reference.state = kHit.state;
    if (kHit.hasPosition) {
        reference.resolvedName = filters_[kHit.position].displayName;
    }
    return reference;
}

std::vector<WfpGuid> WfpCatalog::findProvidersByDisplayName(std::string_view name) const {
    std::vector<WfpGuid> matches;
    for (const WfpProvider& provider : providers_) {
        if (provider.displayName.present && equalsIgnoreCase(provider.displayName.value, name)) {
            matches.push_back(provider.providerKey);
        }
    }
    return matches;
}

std::vector<WfpGuid> WfpCatalog::findCalloutsByDisplayName(std::string_view name) const {
    std::vector<WfpGuid> matches;
    for (const WfpCallout& callout : callouts_) {
        if (callout.displayName.present && equalsIgnoreCase(callout.displayName.value, name)) {
            matches.push_back(callout.calloutKey);
        }
    }
    return matches;
}

std::vector<std::size_t> WfpCatalog::findFilterIndexesByRuntimeId(const OptionalU64& filterId) const {
    std::vector<std::size_t> matches;
    if (!filterId.present) {
        return matches;
    }
    for (std::size_t i = 0; i < filters_.size(); ++i) {
        if (filters_[i].filterId.present && filters_[i].filterId.value == filterId.value) {
            matches.push_back(i);
        }
    }
    return matches;
}

OwnerEvidence WfpCatalog::providerOwnerEvidence(std::size_t providerIndex) const {
    if (providerIndex >= providers_.size()) {
        return OwnerEvidence{};
    }
    OwnerEvidence evidence = providers_[providerIndex].owner;
    if (evidence.displayName.present) {
        evidence.displayNameAmbiguous = findProvidersByDisplayName(evidence.displayName.value).size() > 1U;
    }
    return evidence;
}

OwnerEvidence WfpCatalog::calloutOwnerEvidence(std::size_t calloutIndex) const {
    if (calloutIndex >= callouts_.size()) {
        return OwnerEvidence{};
    }
    OwnerEvidence evidence = callouts_[calloutIndex].owner;
    if (evidence.displayName.present) {
        evidence.displayNameAmbiguous = findCalloutsByDisplayName(evidence.displayName.value).size() > 1U;
    }
    return evidence;
}

// ---------------------------------------------------------------------------
// N-02 / N-03: single condition evaluation
// ---------------------------------------------------------------------------
namespace {

ConditionMatch compareNumeric(WfpMatchType match,
                              std::uint64_t actual,
                              const WfpConditionValue& value,
                              std::vector<std::string>& keys) {
    if (match == WfpMatchType::kRange) {
        if (value.type != WfpDataType::kRange) {
            addKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::kInsufficientInfo;
        }
        if (!value.range.numeric) {
            // The endpoint is not numeric (original values remain in rawLow/rawHigh) — no comparison is possible, so do not guess.
            addKey(keys, "wfp.condition.range-not-numeric");
            return ConditionMatch::kInsufficientInfo;
        }
        if (!value.range.low.present || !value.range.high.present) {
            // "Missing endpoint" and "type mismatch" are distinct issues; using a single key for both makes the UI unable to clarify what is missing.
            addKey(keys, "wfp.condition.range-endpoint-missing");
            return ConditionMatch::kInsufficientInfo;
        }
        if (value.range.low.value > value.range.high.value) {
            // low > high is an invalid/corrupt FWP_RANGE0. `actual >= low && actual <= high` is always false
            // for any actual, becoming a "certain mismatch" that causes the filter to be skipped directly in
            // decideWithinSubLayer, passing the arbitration decision to rules with lower weight.
            addKey(keys, "wfp.condition.invalid-range");
            return ConditionMatch::kInsufficientInfo;
        }
        return fromBool(actual >= value.range.low.value && actual <= value.range.high.value);
    }
    if (!dataTypeIsNumeric(value.type) || !value.numeric.present) {
        addKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::kInsufficientInfo;
    }
    const std::uint64_t kExpected = value.numeric.value;
    switch (match) {
    case WfpMatchType::kEqual:
        return fromBool(actual == kExpected);
    case WfpMatchType::kNotEqual:
        return fromBool(actual != kExpected);
    case WfpMatchType::kGreater:
        return fromBool(actual > kExpected);
    case WfpMatchType::kLess:
        return fromBool(actual < kExpected);
    case WfpMatchType::kGreaterOrEqual:
        return fromBool(actual >= kExpected);
    case WfpMatchType::kLessOrEqual:
        return fromBool(actual <= kExpected);
    case WfpMatchType::kEqualCaseInsensitive:
    case WfpMatchType::kFlagsAllSet:
    case WfpMatchType::kFlagsAnySet:
    case WfpMatchType::kFlagsNoneSet:
    case WfpMatchType::kPrefix:
    case WfpMatchType::kNotPrefix:
        // Bit flags on scalar types like ports/protocols and prefix comparisons are not modeled at this layer; never guess.
        addKey(keys, "wfp.condition.match-not-modeled");
        return ConditionMatch::kInsufficientInfo;
    case WfpMatchType::kRange:
    case WfpMatchType::kUnknown:
        break;
    }
    addKey(keys, "wfp.condition.unknown-match");
    return ConditionMatch::kInsufficientInfo;
}

bool matchIsNegated(WfpMatchType match) noexcept {
    return match == WfpMatchType::kNotEqual || match == WfpMatchType::kNotPrefix;
}

ConditionMatch compareAddress(WfpMatchType match,
                              const WfpAddress& actual,
                              const WfpConditionValue& value,
                              std::vector<std::string>& keys) {
    const bool kNegated = matchIsNegated(match);
    if (match != WfpMatchType::kEqual && !kNegated) {
        if (match == WfpMatchType::kRange) {
            addKey(keys, "wfp.condition.address-range-not-modeled");
        } else {
            addKey(keys, "wfp.condition.match-not-modeled");
        }
        return ConditionMatch::kInsufficientInfo;
    }

    WfpAddressFamily conditionFamily = WfpAddressFamily::kUnknown;
    switch (value.type) {
    case WfpDataType::kV4AddrMask:
    case WfpDataType::kUint32:
        conditionFamily = WfpAddressFamily::kIPv4;
        break;
    case WfpDataType::kV6AddrMask:
    case WfpDataType::kByteArray16:
        conditionFamily = WfpAddressFamily::kIPv6;
        break;
    case WfpDataType::kEmpty:
    case WfpDataType::kUint8:
    case WfpDataType::kUint16:
    case WfpDataType::kUint64:
    case WfpDataType::kByteBlob:
    case WfpDataType::kSid:
    case WfpDataType::kRange:
    case WfpDataType::kUnknown:
        addKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::kInsufficientInfo;
    }

    // N-02: First confirm that the network address in the condition value is truly resolved before performing comparisons.
    // WfpConditionValue.v4/v6 address defaults to family==Unknown, and when parseIpAddress fails, it does not modify the output
    // by design — in offline samples, a single failed address text parse leaves v4Present=true with an address of unknown family.
    // Passing this through causes the inclusion check to return a 'definite false', which is then inverted by NOT_EQUAL to
    // Match: Deriving a 'blocking candidate' from an address that was never read.
    switch (value.type) {
    case WfpDataType::kV4AddrMask:
        if (!value.v4Present) {
            addKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::kInsufficientInfo;
        }
        if (!value.v4.address.known()) {
            addKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::kInsufficientInfo;
        }
        break;
    case WfpDataType::kV6AddrMask:
        if (!value.v6Present) {
            addKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::kInsufficientInfo;
        }
        if (!value.v6.address.known()) {
            addKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::kInsufficientInfo;
        }
        if (!value.v6.prefixLengthValid) {
            addKey(keys, "wfp.condition.invalid-prefix-length");
            return ConditionMatch::kInsufficientInfo;
        }
        break;
    case WfpDataType::kByteArray16:
        if (!value.singleAddress.known()) {
            addKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::kInsufficientInfo;
        }
        break;
    case WfpDataType::kUint32:
        if (!value.numeric.present) {
            addKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::kInsufficientInfo;
        }
        break;
    case WfpDataType::kEmpty:
    case WfpDataType::kUint8:
    case WfpDataType::kUint16:
    case WfpDataType::kUint64:
    case WfpDataType::kByteBlob:
    case WfpDataType::kSid:
    case WfpDataType::kRange:
    case WfpDataType::kUnknown:
        addKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::kInsufficientInfo;
    }

    if (conditionFamily != actual.family) {
        // Forward comparison: A v4 subnet cannot contain a v6 address, so returning NoMatch is justified.
        // Negated comparison: For 'not equal' across address families, this layer does not assert a truth value and keeps the result unknown.
        if (kNegated) {
            addKey(keys, "wfp.condition.address-family-mismatch");
            return ConditionMatch::kInsufficientInfo;
        }
        addKey(keys, "wfp.condition.address-family-mismatch");
        return ConditionMatch::kNoMatch;
    }

    ConditionMatch positive = ConditionMatch::kInsufficientInfo;
    switch (value.type) {
    case WfpDataType::kV4AddrMask: {
        // Three-state logic: Undecidable must never collapse to NoMatch — negateMatch would flip it to Match.
        const AddressContainment kContainment = classifyV4Containment(actual, value.v4);
        if (kContainment == AddressContainment::kUndecidable) {
            addKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::kInsufficientInfo;
        }
        positive = fromBool(kContainment == AddressContainment::kInside);
        break;
    }
    case WfpDataType::kUint32: {
        const WfpAddress kExpected =
            WfpAddress::ipv4FromHostOrder(static_cast<std::uint32_t>(value.numeric.value & 0xFFFFFFFFULL));
        positive = fromBool(actual == kExpected);
        break;
    }
    case WfpDataType::kV6AddrMask: {
        const AddressContainment kContainment = classifyV6Containment(actual, value.v6);
        if (kContainment == AddressContainment::kUndecidable) {
            addKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::kInsufficientInfo;
        }
        positive = fromBool(kContainment == AddressContainment::kInside);
        break;
    }
    case WfpDataType::kByteArray16:
        positive = fromBool(actual == value.singleAddress);
        break;
    case WfpDataType::kEmpty:
    case WfpDataType::kUint8:
    case WfpDataType::kUint16:
    case WfpDataType::kUint64:
    case WfpDataType::kByteBlob:
    case WfpDataType::kSid:
    case WfpDataType::kRange:
    case WfpDataType::kUnknown:
        addKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::kInsufficientInfo;
    }
    return kNegated ? negateMatch(positive) : positive;
}

ConditionMatch compareText(WfpMatchType match,
                           std::string_view actual,
                           std::string_view expected,
                           std::vector<std::string>& keys) {
    switch (match) {
    case WfpMatchType::kEqual:
    case WfpMatchType::kEqualCaseInsensitive:
        // AppId and SID in WFP use case-insensitive comparison.
        return fromBool(equalsIgnoreCase(actual, expected));
    case WfpMatchType::kNotEqual:
        return fromBool(!equalsIgnoreCase(actual, expected));
    case WfpMatchType::kPrefix:
        return fromBool(startsWithIgnoreCase(actual, expected));
    case WfpMatchType::kNotPrefix:
        return fromBool(!startsWithIgnoreCase(actual, expected));
    case WfpMatchType::kGreater:
    case WfpMatchType::kLess:
    case WfpMatchType::kGreaterOrEqual:
    case WfpMatchType::kLessOrEqual:
    case WfpMatchType::kRange:
    case WfpMatchType::kFlagsAllSet:
    case WfpMatchType::kFlagsAnySet:
    case WfpMatchType::kFlagsNoneSet:
        addKey(keys, "wfp.condition.match-not-modeled");
        return ConditionMatch::kInsufficientInfo;
    case WfpMatchType::kUnknown:
        break;
    }
    addKey(keys, "wfp.condition.unknown-match");
    return ConditionMatch::kInsufficientInfo;
}

} // namespace

ConditionEvaluation evaluateCondition(const WfpCondition& condition, const ConnectionDescription& connection) {
    ConditionEvaluation evaluation;
    evaluation.condition = condition;
    evaluation.result = ConditionMatch::kInsufficientInfo;

    // N-02 Core Trap: A condition that hasn't been understood is not 'unconditional match', but 'insufficient information'.
    if (condition.field == WfpFieldKind::kUnknown) {
        addKey(evaluation.limitationKeys, "wfp.condition.unknown-field");
    }
    if (condition.match == WfpMatchType::kUnknown) {
        addKey(evaluation.limitationKeys, "wfp.condition.unknown-match");
    }
    if (condition.value.type == WfpDataType::kUnknown) {
        addKey(evaluation.limitationKeys, "wfp.condition.unknown-value-type");
    }
    if (!condition.interpreted()) {
        return evaluation;
    }
    if (!fieldIsModeled(condition.field)) {
        addKey(evaluation.limitationKeys, "wfp.condition.field-not-modeled");
        return evaluation;
    }

    switch (condition.field) {
    case WfpFieldKind::kIpLocalPort:
    case WfpFieldKind::kIpRemotePort:
    case WfpFieldKind::kIpProtocol: {
        const OptionalU64& actual = (condition.field == WfpFieldKind::kIpLocalPort)
                                        ? connection.localPort
                                        : (condition.field == WfpFieldKind::kIpRemotePort
                                               ? connection.remotePort
                                               : connection.protocol);
        if (!actual.present) {
            addKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        evaluation.result = compareNumeric(condition.match, actual.value, condition.value,
                                           evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::kIpLocalAddress:
    case WfpFieldKind::kIpRemoteAddress: {
        const WfpAddress& actual = (condition.field == WfpFieldKind::kIpLocalAddress)
                                       ? connection.localAddress
                                       : connection.remoteAddress;
        if (!actual.known()) {
            addKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        evaluation.result = compareAddress(condition.match, actual, condition.value,
                                           evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::kDirection: {
        if (connection.direction == WfpDirection::kUnknown) {
            addKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        if (!dataTypeIsNumeric(condition.value.type) || !condition.value.numeric.present) {
            addKey(evaluation.limitationKeys, "wfp.condition.value-type-mismatch");
            return evaluation;
        }
        const WfpDirection kExpected = decodeDirectionValue(condition.value.numeric.value);
        if (kExpected == WfpDirection::kUnknown) {
            // Value is not in FWP_DIRECTION_ definitions — original value preserved in value.numeric without guessing semantics.
            addKey(evaluation.limitationKeys, "wfp.condition.unknown-direction-value");
            return evaluation;
        }
        if (connection.direction == WfpDirection::kForward) {
            // Forwarded traffic is not within the FWP_DIRECTION_ in/out binary split; no truth assertion is made.
            addKey(evaluation.limitationKeys, "wfp.condition.direction-not-comparable");
            return evaluation;
        }
        if (condition.match == WfpMatchType::kEqual) {
            evaluation.result = fromBool(connection.direction == kExpected);
        } else if (condition.match == WfpMatchType::kNotEqual) {
            evaluation.result = fromBool(connection.direction != kExpected);
        } else {
            addKey(evaluation.limitationKeys, "wfp.condition.match-not-modeled");
        }
        return evaluation;
    }
    case WfpFieldKind::kAleAppId: {
        if (!connection.appId.present) {
            addKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        if (condition.value.type != WfpDataType::kByteBlob) {
            addKey(evaluation.limitationKeys, "wfp.condition.value-type-mismatch");
            return evaluation;
        }
        if (!condition.value.blobText.present) {
            // Bytes are present (blobBytes), but cannot be decoded into a path text — do not treat as 'matches any program'.
            addKey(evaluation.limitationKeys, "wfp.condition.blob-not-decoded");
            return evaluation;
        }
        evaluation.result = compareText(condition.match, connection.appId.value,
                                        condition.value.blobText.value, evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::kAleUserId: {
        if (!connection.userSid.present) {
            addKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        if (condition.value.type != WfpDataType::kSid || !condition.value.sidText.present) {
            addKey(evaluation.limitationKeys, "wfp.condition.value-type-mismatch");
            return evaluation;
        }
        evaluation.result = compareText(condition.match, connection.userSid.value,
                                        condition.value.sidText.value, evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::kIpLocalAddressType:
    case WfpFieldKind::kFlags:
    case WfpFieldKind::kUnknown:
        break;
    }
    addKey(evaluation.limitationKeys, "wfp.condition.field-not-modeled");
    return evaluation;
}

ConditionMatch combineConditionResults(const std::vector<ConditionEvaluation>& evaluations,
                                       bool conditionsTruncated) {
    // FWP semantics: Multiple conditions on the same field are OR, while conditions on different fields are AND.
    std::map<std::string, ConditionMatch> groups;
    for (std::size_t i = 0; i < evaluations.size(); ++i) {
        const ConditionEvaluation& evaluation = evaluations[i];
        std::string key;
        if (evaluation.condition.fieldKey.known()) {
            key = evaluation.condition.fieldKey.text;
        } else {
            // Without a field GUID, it is unknown which field this condition belongs to; it must never be OR-ed with other unknown
            // conditions (as OR-ing can cause a 'match' to mask a 'non-match'). Assign it an exclusive group here and use AND.
            key = "#unkeyed-" + formatU64(i, U64Format::kDecimal);
        }
        const auto kExisting = groups.find(key);
        if (kExisting == groups.end()) {
            groups.emplace(std::move(key), evaluation.result);
        } else {
            kExisting->second = orMatch(kExisting->second, evaluation.result);
        }
    }

    ConditionMatch combined = ConditionMatch::kMatch;  // An empty condition set equals a true "unconditional match".
    for (const auto& entry : groups) {
        combined = andMatch(combined, entry.second);
    }
    if (conditionsTruncated) {
        // The truncated condition content is unknown, equivalent to applying AND with another unknown condition.
        combined = andMatch(combined, ConditionMatch::kInsufficientInfo);
    }
    return combined;
}

// ---------------------------------------------------------------------------
// N-03: Candidate analysis
// ---------------------------------------------------------------------------
FilterCandidate evaluateFilter(const WfpCatalog& catalog,
                               const WfpFilter& filter,
                               const ConnectionDescription& connection) {
    FilterCandidate candidate;
    candidate.filterKey = filter.filterKey;
    candidate.filterId = filter.filterId;
    candidate.displayName = filter.displayName;
    candidate.provider = catalog.resolveProvider(filter.providerKey);
    candidate.layer = catalog.resolveLayer(filter.layerKey);
    candidate.subLayer = catalog.resolveSubLayer(filter.subLayerKey);
    candidate.action = filter.action;
    candidate.dynamicByCallout = actionIsCallout(filter.action);
    if (candidate.dynamicByCallout) {
        candidate.actionCallout = catalog.resolveCallout(filter.actionCalloutKey);
    }

    // effectiveWeight and the weight specified by the caller are in different dimensions; prefer the one calculated by BFE.
    if (filter.effectiveWeight.present) {
        candidate.weightConfidence = WeightOrderConfidence::kEffectiveWeight;
        candidate.orderingWeight = filter.effectiveWeight;
    } else if (filter.weightKind == WfpWeightKind::kExplicit && filter.weight.present) {
        candidate.weightConfidence = WeightOrderConfidence::kExplicitWeight;
        candidate.orderingWeight = filter.weight;
    } else {
        candidate.weightConfidence = WeightOrderConfidence::kUnknown;
        addKey(candidate.limitationKeys, "wfp.filter.weight-unknown");
    }

    candidate.conditions.reserve(filter.conditions.size());
    for (const WfpCondition& condition : filter.conditions) {
        ConditionEvaluation evaluation = evaluateCondition(condition, connection);
        mergeKeys(candidate.limitationKeys, evaluation.limitationKeys);
        candidate.conditions.push_back(std::move(evaluation));
    }
    candidate.match = combineConditionResults(candidate.conditions, filter.conditionsTruncated);

    if (filter.conditionsTruncated) {
        addKey(candidate.limitationKeys, "wfp.filter.conditions-truncated");
    }
    if (filter.action == WfpActionType::kUnknown) {
        addKey(candidate.limitationKeys, "wfp.filter.action-unknown");
    }
    if (candidate.dynamicByCallout) {
        addKey(candidate.limitationKeys, "wfp.filter.dynamic-callout");
    }
    if (candidate.layer.state == ReferenceState::kNotSpecified) {
        addKey(candidate.limitationKeys, "wfp.filter.layer-missing");
    }
    if (candidate.subLayer.state == ReferenceState::kNotSpecified) {
        addKey(candidate.limitationKeys, "wfp.filter.sublayer-missing");
    }
    return candidate;
}

namespace {

// Arbitration within a single sublayer. The return value is always conservative: Unknown if the ordering is unreliable or if there are unreadable conditions.
CandidateDecision decideWithinSubLayer(const std::vector<FilterCandidate>& ordered,
                                       bool orderingReliable) {
    if (orderingReliable) {
        for (const FilterCandidate& candidate : ordered) {
            if (candidate.match == ConditionMatch::kInsufficientInfo) {
                // It might be the winner or it might not — no guessing.
                return CandidateDecision::kUnknown;
            }
            if (candidate.match == ConditionMatch::kNoMatch) {
                continue;
            }
            if (candidate.dynamicByCallout) {
                return CandidateDecision::kUnknown;
            }
            switch (candidate.action) {
            case WfpActionType::kBlock:
                return CandidateDecision::kBlockCandidate;
            case WfpActionType::kPermit:
                return CandidateDecision::kPermitCandidate;
            case WfpActionType::kContinue:
                continue;  // The semantics of FWP_ACTION_CONTINUE is to continue processing.
            case WfpActionType::kUnknown:
            case WfpActionType::kNone:
            case WfpActionType::kNoneNoMatch:
            case WfpActionType::kCalloutTerminating:
            case WfpActionType::kCalloutInspection:
            case WfpActionType::kCalloutUnknown:
                return CandidateDecision::kUnknown;
            }
            return CandidateDecision::kUnknown;
        }
        return CandidateDecision::kNoMatchingFilter;
    }

    // Order is unreliable: conclusions are order-independent only when there is a single candidate.
    std::size_t candidateCount = 0;
    const FilterCandidate* single = nullptr;
    for (const FilterCandidate& candidate : ordered) {
        if (candidate.match == ConditionMatch::kNoMatch) {
            continue;
        }
        ++candidateCount;
        single = &candidate;
    }
    if (candidateCount == 0U) {
        return CandidateDecision::kNoMatchingFilter;
    }
    if (candidateCount > 1U || single == nullptr) {
        return CandidateDecision::kUnknown;
    }
    if (single->match == ConditionMatch::kInsufficientInfo || single->dynamicByCallout) {
        return CandidateDecision::kUnknown;
    }
    switch (single->action) {
    case WfpActionType::kBlock:
        return CandidateDecision::kBlockCandidate;
    case WfpActionType::kPermit:
        return CandidateDecision::kPermitCandidate;
    case WfpActionType::kContinue:
        return CandidateDecision::kNoMatchingFilter;  // Yield to the sole candidate; no other options remain.
    case WfpActionType::kUnknown:
    case WfpActionType::kNone:
    case WfpActionType::kNoneNoMatch:
    case WfpActionType::kCalloutTerminating:
    case WfpActionType::kCalloutInspection:
    case WfpActionType::kCalloutUnknown:
        break;
    }
    return CandidateDecision::kUnknown;
}

// Conservative aggregation across sublayers and layers.
// In real WFP, block overrides permit, but that requires every sublayer to be determined. Additionally, this layer does
// not model FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT (a veto right) or layer default actions. Therefore, if any decision is
// uncertain, the overall result remains Unknown (N-03 explicitly requires retaining Unknown when dynamic behavior exists).
CandidateDecision combineDecisions(const std::vector<CandidateDecision>& decisions) {
    bool sawBlock = false;
    bool sawPermit = false;
    for (CandidateDecision decision : decisions) {
        switch (decision) {
        case CandidateDecision::kUnknown:
            return CandidateDecision::kUnknown;
        case CandidateDecision::kBlockCandidate:
            sawBlock = true;
            break;
        case CandidateDecision::kPermitCandidate:
            sawPermit = true;
            break;
        case CandidateDecision::kNoMatchingFilter:
            break;
        }
    }
    if (sawBlock) {
        return CandidateDecision::kBlockCandidate;
    }
    if (sawPermit) {
        return CandidateDecision::kPermitCandidate;
    }
    return CandidateDecision::kNoMatchingFilter;
}

// N-01: Layers/sublayers referencing uncollected filters use these prefixes to create
// separate buckets. Real GUIDs are always in "{...}" format, so keys starting with '#' cannot
// collide (same approach as combineConditionResults for unkeyed conditions with "#unkeyed-").
constexpr const char* kUnlinkedLayerPrefix = "#unlinked-layer-";
constexpr const char* kUnlinkedSubLayerPrefix = "#unlinked-sublayer-";

bool isUnlinkedBucketKey(const std::string& key) noexcept {
    return key.rfind("#unlinked-", 0U) == 0U;
}

bool orderingIsReliable(const std::vector<FilterCandidate>& filters, bool& mixedScale) {
    mixedScale = false;
    if (filters.empty()) {
        return false;
    }
    const WeightOrderConfidence kFirst = filters.front().weightConfidence;
    std::vector<std::uint64_t> seen;
    for (const FilterCandidate& candidate : filters) {
        if (candidate.weightConfidence == WeightOrderConfidence::kUnknown ||
            !candidate.orderingWeight.present) {
            return false;
        }
        if (candidate.weightConfidence != kFirst) {
            mixedScale = true;
            return false;
        }
        for (std::uint64_t value : seen) {
            if (value == candidate.orderingWeight.value) {
                return false;  // Same weight cannot determine order.
            }
        }
        seen.push_back(candidate.orderingWeight.value);
    }
    return true;
}

} // namespace

StaticCandidateReport analyzeStaticCandidates(const WfpCatalog& catalog,
                                              const ConnectionDescription& connection) {
    StaticCandidateReport report;
    // These two conditions always hold: this layer does not model the default action, nor does it interpret filter flags (including veto rights).
    addKey(report.limitationKeys, "wfp.candidate.layer-default-action-not-modeled");
    addKey(report.limitationKeys, "wfp.candidate.filter-flags-not-modeled");
    // N-06: Only filter partitions that can positively prove enumeration completeness are allowed to produce the 'no matching rules' absence assertion.
    const bool kUsableForAbsence = catalog.partitionUsableForAbsence(WfpPartition::kFilters);
    report.catalogUsableForAbsence = kUsableForAbsence;
    if (!kUsableForAbsence) {
        // The directory enumeration may be incomplete: 'no matching rules' does not mean 'no rules exist'.
        addKey(report.limitationKeys, "wfp.candidate.filter-catalog-incomplete");
    }

    // layerKey -> subLayerKey -> filters。
    // N-01: Filters with missing references each occupy their own bucket; they are neither merged into any
    // known group nor combined with other filters lacking references. The latter is the same fallacy: two rules
    // with unknown layers may not even share the same arbitration scope (one in ALE_AUTH_CONNECT_V4, another in
    // OUTBOUND_TRANSPORT_V4), yet they would be incorrectly judged as "900 overrides 100 → block candidate".
    std::map<std::string, std::map<std::string, std::vector<FilterCandidate>>> buckets;
    std::size_t bucketIndex = 0;
    for (const WfpFilter& filter : catalog.filters()) {
        FilterCandidate candidate = evaluateFilter(catalog, filter, connection);
        const std::string kSuffix = formatU64(bucketIndex, U64Format::kDecimal);
        const std::string kLayerBucket =
            filter.layerKey.known() ? filter.layerKey.text : (std::string(kUnlinkedLayerPrefix) + kSuffix);
        const std::string kSubBucket = filter.subLayerKey.known()
                                          ? filter.subLayerKey.text
                                          : (std::string(kUnlinkedSubLayerPrefix) + kSuffix);
        buckets[kLayerBucket][kSubBucket].push_back(std::move(candidate));
        ++bucketIndex;
        ++report.evaluatedFilterCount;
    }

    std::vector<CandidateDecision> layerDecisions;
    for (auto& layerEntry : buckets) {
        LayerCandidateGroup layerGroup;
        const bool kLayerUnlinked = isUnlinkedBucketKey(layerEntry.first);
        layerGroup.layer =
            catalog.resolveLayer(kLayerUnlinked ? WfpGuid{} : guidFromText(layerEntry.first));
        if (layerGroup.layer.state == ReferenceState::kNotSpecified) {
            addKey(layerGroup.limitationKeys, "wfp.filter.layer-missing");
        }
        layerGroup.unlinkedReference = kLayerUnlinked;

        std::vector<CandidateDecision> subLayerDecisions;
        for (auto& subEntry : layerEntry.second) {
            SubLayerCandidateGroup subGroup;
            const bool kSubUnlinked = isUnlinkedBucketKey(subEntry.first);
            subGroup.unlinkedReference = kLayerUnlinked || kSubUnlinked;
            subGroup.subLayer =
                catalog.resolveSubLayer(kSubUnlinked ? WfpGuid{} : guidFromText(subEntry.first));
            if (subGroup.subLayer.resolved()) {
                for (const WfpSubLayer& subLayer : catalog.subLayers()) {
                    if (subLayer.subLayerKey == subGroup.subLayer.key) {
                        subGroup.subLayerWeight = subLayer.weight;
                        break;
                    }
                }
            }
            if (!subGroup.subLayerWeight.present) {
                addKey(subGroup.limitationKeys, "wfp.layer.sublayer-weight-unknown");
            }
            subGroup.filters = std::move(subEntry.second);

            // Display order: descending by weight (unknown weights last). Whether to rely on this order is a separate decision.
            std::stable_sort(subGroup.filters.begin(), subGroup.filters.end(),
                             [](const FilterCandidate& a, const FilterCandidate& b) {
                                 if (a.orderingWeight.present != b.orderingWeight.present) {
                                     return a.orderingWeight.present;
                                 }
                                 if (!a.orderingWeight.present) {
                                     return false;
                                 }
                                 return a.orderingWeight.value > b.orderingWeight.value;
                             });

            bool mixedScale = false;
            subGroup.orderingReliable = orderingIsReliable(subGroup.filters, mixedScale);
            if (mixedScale) {
                addKey(subGroup.limitationKeys, "wfp.sublayer.weight-scale-mixed");
            }
            if (subGroup.unlinkedReference) {
                // If we don't even know which arbitration scope this rule belongs to, we certainly can't determine the order within that scope.
                subGroup.orderingReliable = false;
                if (kLayerUnlinked) {
                    addKey(subGroup.limitationKeys, "wfp.filter.layer-missing");
                }
                if (kSubUnlinked) {
                    addKey(subGroup.limitationKeys, "wfp.filter.sublayer-missing");
                }
            }
            if (!subGroup.orderingReliable) {
                addKey(subGroup.limitationKeys, "wfp.sublayer.order-unreliable");
            }
            subGroup.decision = decideWithinSubLayer(subGroup.filters, subGroup.orderingReliable);
            if (subGroup.unlinkedReference && subGroup.decision != CandidateDecision::kNoMatchingFilter) {
                // Groups with unknown scope are only allowed to report "rule did not match" or "unknown"; they must never suggest
                // "block" or "allow" candidates. This requires first determining which sublayer it belongs to and who it competes with.
                subGroup.decision = CandidateDecision::kUnknown;
            }
            if (!kUsableForAbsence) {
                // N-03/N-06: When the catalog is insufficient to prove absence, the assertion "no filter matches within
                // this range" also fails at the group level. The limitation key must be applied to the group; if written
                // only at the report level, the UI rendering of SubLayerCandidateGroup::decision will not see any anomaly.
                addKey(subGroup.limitationKeys, "wfp.candidate.filter-catalog-incomplete");
                if (subGroup.decision == CandidateDecision::kNoMatchingFilter) {
                    subGroup.decision = CandidateDecision::kUnknown;
                }
            }
            subLayerDecisions.push_back(subGroup.decision);
            layerGroup.subLayers.push_back(std::move(subGroup));
        }

        // Sublayers are displayed in descending order by UINT16 weight.
        std::stable_sort(layerGroup.subLayers.begin(), layerGroup.subLayers.end(),
                         [](const SubLayerCandidateGroup& a, const SubLayerCandidateGroup& b) {
                             if (a.subLayerWeight.present != b.subLayerWeight.present) {
                                 return a.subLayerWeight.present;
                             }
                             if (!a.subLayerWeight.present) {
                                 return false;
                             }
                             return a.subLayerWeight.value > b.subLayerWeight.value;
                         });
        layerGroup.subLayerOrderingReliable = true;
        std::vector<std::uint64_t> seenWeights;
        for (const SubLayerCandidateGroup& subGroup : layerGroup.subLayers) {
            if (!subGroup.subLayerWeight.present) {
                layerGroup.subLayerOrderingReliable = false;
                break;
            }
            bool duplicate = false;
            for (std::uint64_t value : seenWeights) {
                if (value == subGroup.subLayerWeight.value) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                layerGroup.subLayerOrderingReliable = false;
                break;
            }
            seenWeights.push_back(subGroup.subLayerWeight.value);
        }

        for (const SubLayerCandidateGroup& subGroup : layerGroup.subLayers) {
            if (subGroup.unlinkedReference) {
                layerGroup.unlinkedReference = true;
                break;
            }
        }

        layerGroup.decision = combineDecisions(subLayerDecisions);
        if (!kUsableForAbsence) {
            addKey(layerGroup.limitationKeys, "wfp.candidate.filter-catalog-incomplete");
            if (layerGroup.decision == CandidateDecision::kNoMatchingFilter) {
                layerGroup.decision = CandidateDecision::kUnknown;
            }
        }
        layerDecisions.push_back(layerGroup.decision);
        report.layers.push_back(std::move(layerGroup));
    }

    if (layerDecisions.empty()) {
        // No filters found: this means "truly no rules" only if the directory proves completeness; otherwise, it means "data not collected".
        report.overallDecision =
            kUsableForAbsence ? CandidateDecision::kNoMatchingFilter : CandidateDecision::kUnknown;
    } else {
        report.overallDecision = combineDecisions(layerDecisions);
        if (!kUsableForAbsence && report.overallDecision == CandidateDecision::kNoMatchingFilter) {
            report.overallDecision = CandidateDecision::kUnknown;
        }
    }
    return report;
}

// ---------------------------------------------------------------------------
// N-04: Runtime events
// ---------------------------------------------------------------------------
ObservationTrust classifyObservation(const ObservedFilterHit& hit) noexcept {
    // When the source is unknown, recording our own claim of 'enabled/supported' is meaningless — check the source first.
    if (hit.source == ObservationSource::kUnknown) {
        return ObservationTrust::kSourceUnknown;
    }
    if (hit.source == ObservationSource::kOfflineImport &&
        (hit.originalSource == ObservationSource::kUnknown ||
         hit.originalSource == ObservationSource::kOfflineImport)) {
        // N-04: Offline import only indicates "this record was read from a sample." When the original source is
        // unknown, the sample's own `supported`/`enabled` booleans cannot elevate it to "actual block"—otherwise the
        // source field would only show "Offline Import," making it impossible to distinguish whether the original
        // was from Security Audit 5157, FwpmNetEventEnum, or this tool driver's ALE flow authorization ring.
        return ObservationTrust::kSourceUnknown;
    }
    if (!hit.sourceSupported) {
        return ObservationTrust::kSourceUnsupported;
    }
    if (!hit.sourceEnabled) {
        return ObservationTrust::kSourceNotEnabled;
    }
    return ObservationTrust::kActualObservation;
}

bool describesActualVerdict(const ObservedFilterHit& hit) noexcept {
    return classifyObservation(hit) == ObservationTrust::kActualObservation &&
           hit.verdict != WfpEventVerdict::kUnknown;
}

bool ObservationSourceOutcome::carriesObservation() const noexcept {
    return statusCarriesObservation(outcome.status);
}

std::size_t RuleExplanation::actualHitCount() const noexcept {
    std::size_t count = 0;
    for (const ObservedFilterHit& hit : observations) {
        if (classifyObservation(hit) == ObservationTrust::kActualObservation) {
            ++count;
        }
    }
    return count;
}

std::size_t RuleExplanation::untrustedObservationCount() const noexcept {
    return observations.size() - actualHitCount();
}

bool RuleExplanation::observationsCollected() const noexcept {
    // N-04 / F-05: Only sources that are 'Supported + Enabled + Carrying Observation' give the meaning
    // of 'zero hits' as 'truly no hits'. Return false if nothing was registered (never subscribed).
    for (const ObservationSourceOutcome& entry : sourceOutcomes) {
        if (entry.sourceSupported && entry.sourceEnabled && entry.carriesObservation()) {
            return true;
        }
    }
    return false;
}

bool RuleExplanation::anyObservationSourceFailed() const noexcept {
    for (const ObservationSourceOutcome& entry : sourceOutcomes) {
        if (!entry.carriesObservation()) {
            return true;  // Not collected / subscription failed / access denied — original error code is in outcome.
        }
    }
    return false;
}

bool RuleExplanation::hasActualPath() const noexcept {
    // N-04: Actual path generation is disallowed when no supported and enabled source records exist.
    // Even a large number of static candidates cannot override this.
    return actualHitCount() > 0U;
}

// ---------------------------------------------------------------------------
// N-06: Runtime ID reference.
// ---------------------------------------------------------------------------
FilterReferenceResolution resolveFilterReference(const WfpCatalog& catalog,
                                                 const RuntimeFilterReference& reference) {
    FilterReferenceResolution resolution;
    if (!reference.filterKey.known() && !reference.filterId.present) {
        resolution.state = FilterLinkState::kNotSpecified;
        return resolution;
    }

    if (reference.filterKey.known()) {
        const ObjectReference kObject = catalog.resolveFilter(reference.filterKey);
        switch (kObject.state) {
        case ReferenceState::kResolved: {
            resolution.state = FilterLinkState::kLinkedByGuid;
            const std::vector<WfpFilter>& filters = catalog.filters();
            for (std::size_t i = 0; i < filters.size(); ++i) {
                if (filters[i].filterKey == reference.filterKey) {
                    resolution.hasIndex = true;
                    resolution.filterIndex = i;
                    break;
                }
            }
            if (resolution.hasIndex && reference.filterId.present) {
                const OptionalU64& current = catalog.filters()[resolution.filterIndex].filterId;
                if (!current.present || current.value != reference.filterId.value) {
                    // The GUID is a stable key, so it is included; but if the runtime ID changes, it must be stated.
                    addKey(resolution.limitationKeys, "wfp.link.runtime-id-changed");
                }
            }
            return resolution;
        }
        case ReferenceState::kAmbiguous:
            resolution.state = FilterLinkState::kRejectedAmbiguous;
            return resolution;
        case ReferenceState::kCatalogNotCollected:
            resolution.state = FilterLinkState::kCatalogNotCollected;
            return resolution;
        case ReferenceState::kCatalogIncomplete:
            // Data collected but incomplete: not found does not mean does not exist.
            resolution.state = FilterLinkState::kCatalogIncomplete;
            addKey(resolution.limitationKeys, "wfp.link.catalog-incomplete");
            return resolution;
        case ReferenceState::kUnknownObject:
        case ReferenceState::kNotSpecified:
            break;
        }
        // GUID not found in the catalog. If the same runtime ID is already occupied by another filter, it indicates ID reuse.
        const std::vector<std::size_t> kById = catalog.findFilterIndexesByRuntimeId(reference.filterId);
        if (!kById.empty()) {
            resolution.state = FilterLinkState::kRejectedIdReused;
            addKey(resolution.limitationKeys, "wfp.link.id-reused");
            return resolution;
        }
        // At this point, resolveFilter has already checked for UnknownObject (a directory
        // can positively prove absence), so the NoMatch absence assertion holds.
        resolution.state = FilterLinkState::kNoMatch;
        return resolution;
    }

    // Runtime ID only: IDs are reusable, so generation must be confirmed first.
    const CollectionStatus kFilterStatus = catalog.partitionState(WfpPartition::kFilters).outcome.status;
    if (!statusCarriesObservation(kFilterStatus)) {
        resolution.state = FilterLinkState::kCatalogNotCollected;
        return resolution;
    }
    if (!reference.capturedGeneration.present) {
        resolution.state = FilterLinkState::kRejectedStaleGeneration;
        addKey(resolution.limitationKeys, "wfp.link.generation-unknown");
        return resolution;
    }
    if (reference.capturedGeneration.value != catalog.generation()) {
        resolution.state = FilterLinkState::kRejectedStaleGeneration;
        addKey(resolution.limitationKeys, "wfp.link.stale-generation");
        return resolution;
    }
    // Generation numbers reset to 0 across boots, so "same generation" does not constitute evidence across boots. If both sides have
    // bootIds and they differ, reject immediately; if one side lacks a bootId, only the "same generation" criterion can be retained.
    const std::string& catalogBoot = catalog.captureWindow().bootId;
    if (!reference.bootId.empty() && !catalogBoot.empty() && reference.bootId != catalogBoot) {
        resolution.state = FilterLinkState::kRejectedStaleGeneration;
        addKey(resolution.limitationKeys, "wfp.link.boot-mismatch");
        return resolution;
    }
    const std::vector<std::size_t> kMatches = catalog.findFilterIndexesByRuntimeId(reference.filterId);
    if (kMatches.empty()) {
        // N-06: If the catalog is not fully enumerated, the absence of this ID does not prove the rule is missing.
        if (!catalog.partitionUsableForAbsence(WfpPartition::kFilters)) {
            resolution.state = FilterLinkState::kCatalogIncomplete;
            addKey(resolution.limitationKeys, "wfp.link.catalog-incomplete");
            return resolution;
        }
        resolution.state = FilterLinkState::kNoMatch;
        return resolution;
    }
    if (kMatches.size() > 1U) {
        resolution.state = FilterLinkState::kRejectedAmbiguous;
        return resolution;
    }
    resolution.state = FilterLinkState::kLinkedByRuntimeIdSameGeneration;
    resolution.hasIndex = true;
    resolution.filterIndex = kMatches.front();
    return resolution;
}

FilterReferenceResolution linkObservationToCatalog(const WfpCatalog& catalog,
                                                   const ObservedFilterHit& hit) {
    RuntimeFilterReference reference;
    reference.filterId = hit.filterId;
    reference.filterKey = hit.filterKey;
    reference.capturedGeneration = hit.capturedGeneration;
    reference.bootId = hit.connection.bootId;  // The event's native boot cycle, used for cross-boot protection.
    return resolveFilterReference(catalog, reference);
}

namespace {

// GUID index + two types of rows that distort this index. std::map::emplace silently drops the second row for duplicate
// GUIDs, and rows without a GUID never enter the index — both cause "add/remove/update" conclusions to silently miss rules.
struct FilterGuidIndex final {
    std::map<std::string, std::size_t> byGuid;
    std::vector<std::string> duplicatedGuids;
    std::vector<std::size_t> rowsWithoutGuid;

    bool distorted() const noexcept {
        return !duplicatedGuids.empty() || !rowsWithoutGuid.empty();
    }
};

FilterGuidIndex buildFilterGuidIndex(const std::vector<WfpFilter>& filters) {
    FilterGuidIndex index;
    for (std::size_t i = 0; i < filters.size(); ++i) {
        const WfpFilter& filter = filters[i];
        if (!filter.filterKey.known()) {
            index.rowsWithoutGuid.push_back(i);
            continue;
        }
        const auto kInserted = index.byGuid.emplace(filter.filterKey.text, i);
        if (!kInserted.second) {
            addKey(index.duplicatedGuids, filter.filterKey.text);
        }
    }
    return index;
}

} // namespace

CatalogDelta diffCatalogs(const WfpCatalog& before, const WfpCatalog& after) {
    CatalogDelta delta;
    const bool kBeforeUsable = before.partitionUsableForAbsence(WfpPartition::kFilters);
    const bool kAfterUsable = after.partitionUsableForAbsence(WfpPartition::kFilters);
    if (!kBeforeUsable) {
        addKey(delta.limitationKeys, "wfp.delta.before-incomplete");
    }
    if (!kAfterUsable) {
        addKey(delta.limitationKeys, "wfp.delta.after-incomplete");
    }

    const FilterGuidIndex kBeforeIndex = buildFilterGuidIndex(before.filters());
    const FilterGuidIndex kAfterIndex = buildFilterGuidIndex(after.filters());
    const std::map<std::string, std::size_t>& beforeByGuid = kBeforeIndex.byGuid;
    const std::map<std::string, std::size_t>& afterByGuid = kAfterIndex.byGuid;

    // When indices are distorted, the claim of 'no change between generations' is unfounded—the
    // dropped line might have always existed or just been deleted; this layer doesn't know.
    delta.comparable =
        kBeforeUsable && kAfterUsable && !kBeforeIndex.distorted() && !kAfterIndex.distorted();

    // N-01: A GUID appearing multiple times on one side indicates an inconsistent snapshot. The directory already reports this as Ambiguous;
    // here we must not simply take the first occurrence, but must refuse to make any add/delete/modify conclusions for this GUID.
    std::vector<std::string> ambiguousGuids;
    mergeKeys(ambiguousGuids, kBeforeIndex.duplicatedGuids);
    mergeKeys(ambiguousGuids, kAfterIndex.duplicatedGuids);
    if (!ambiguousGuids.empty()) {
        addKey(delta.limitationKeys, "wfp.delta.duplicate-guid");
    }
    for (const std::string& text : ambiguousGuids) {
        CatalogChange change;
        change.kind = CatalogChangeKind::kPresenceUnknown;
        change.filterKey = guidFromText(text);
        // The runtime ID for ambiguous rows is inherently non-unique; leave it unset rather than arbitrarily picking one.
        addKey(change.limitationKeys, "wfp.delta.duplicate-guid");
        delta.changes.push_back(std::move(change));
    }

    // N-06: Rows with only reusable runtime IDs and no GUID cannot enter the comparison loop. We must emit explainable
    // 'presence unknown' for each row individually, rather than just recording a global key at the delta level indicating
    // 'such rows existed'—the latter hides the count, the specific rows, and whether they were added or deleted.
    if (!kBeforeIndex.rowsWithoutGuid.empty() || !kAfterIndex.rowsWithoutGuid.empty()) {
        addKey(delta.limitationKeys, "wfp.delta.filter-without-guid");
    }
    for (std::size_t row : kBeforeIndex.rowsWithoutGuid) {
        CatalogChange change;
        change.kind = CatalogChangeKind::kPresenceUnknown;
        change.beforeFilterId = before.filters()[row].filterId;
        addKey(change.limitationKeys, "wfp.delta.filter-without-guid");
        delta.changes.push_back(std::move(change));
    }
    for (std::size_t row : kAfterIndex.rowsWithoutGuid) {
        CatalogChange change;
        change.kind = CatalogChangeKind::kPresenceUnknown;
        change.afterFilterId = after.filters()[row].filterId;
        addKey(change.limitationKeys, "wfp.delta.filter-without-guid");
        delta.changes.push_back(std::move(change));
    }

    for (const auto& entry : beforeByGuid) {
        if (hasLimitation(ambiguousGuids, entry.first)) {
            continue;  // PresenceUnknown has already been generated.
        }
        const WfpFilter& oldFilter = before.filters()[entry.second];
        const auto kFound = afterByGuid.find(entry.first);
        if (kFound == afterByGuid.end()) {
            CatalogChange change;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            if (kAfterUsable) {
                change.kind = CatalogChangeKind::kRemoved;
            } else {
                // The new side wasn't fully enumerated — "not present" does not equal "deleted" (do not infer deletion from absence).
                change.kind = CatalogChangeKind::kPresenceUnknown;
                addKey(change.limitationKeys, "wfp.delta.after-incomplete");
            }
            delta.changes.push_back(std::move(change));
            continue;
        }
        const WfpFilter& newFilter = after.filters()[kFound->second];
        if (oldFilter.action != newFilter.action || oldFilter.rawActionCode != newFilter.rawActionCode) {
            CatalogChange change;
            change.kind = CatalogChangeKind::kActionChanged;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            change.afterFilterId = newFilter.filterId;
            delta.changes.push_back(std::move(change));
        }
        if (oldFilter.weightKind != newFilter.weightKind || oldFilter.weight != newFilter.weight ||
            oldFilter.effectiveWeight != newFilter.effectiveWeight) {
            CatalogChange change;
            change.kind = CatalogChangeKind::kWeightChanged;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            change.afterFilterId = newFilter.filterId;
            delta.changes.push_back(std::move(change));
        }
        if (filterConditionsSignature(oldFilter) != filterConditionsSignature(newFilter)) {
            CatalogChange change;
            change.kind = CatalogChangeKind::kConditionsChanged;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            change.afterFilterId = newFilter.filterId;
            delta.changes.push_back(std::move(change));
        }
    }

    for (const auto& entry : afterByGuid) {
        if (beforeByGuid.find(entry.first) != beforeByGuid.end()) {
            continue;
        }
        if (hasLimitation(ambiguousGuids, entry.first)) {
            continue;
        }
        const WfpFilter& newFilter = after.filters()[entry.second];
        CatalogChange change;
        change.filterKey = newFilter.filterKey;
        change.afterFilterId = newFilter.filterId;
        if (kBeforeUsable) {
            change.kind = CatalogChangeKind::kAdded;
        } else {
            change.kind = CatalogChangeKind::kPresenceUnknown;
            addKey(change.limitationKeys, "wfp.delta.before-incomplete");
        }
        delta.changes.push_back(std::move(change));
    }

    // Runtime id reuse: The same filterId refers to a different GUID in each of two generations.
    const std::string& beforeBoot = before.captureWindow().bootId;
    const std::string& afterBoot = after.captureWindow().bootId;
    const bool kBootChanged = !beforeBoot.empty() && !afterBoot.empty() && beforeBoot != afterBoot;
    if (kBootChanged) {
        addKey(delta.limitationKeys, "wfp.delta.boot-changed");
    }
    std::map<std::uint64_t, std::string> beforeById;
    for (const WfpFilter& filter : before.filters()) {
        if (filter.filterId.present && filter.filterKey.known()) {
            beforeById.emplace(filter.filterId.value, filter.filterKey.text);
        }
    }
    for (const WfpFilter& filter : after.filters()) {
        if (!filter.filterId.present || !filter.filterKey.known()) {
            continue;
        }
        const auto kFound = beforeById.find(filter.filterId.value);
        if (kFound == beforeById.end() || kFound->second == filter.filterKey.text) {
            continue;
        }
        CatalogChange change;
        change.kind = CatalogChangeKind::kRuntimeIdReused;
        change.filterKey = filter.filterKey;
        change.beforeFilterId = filter.filterId;
        change.afterFilterId = filter.filterId;
        addKey(change.limitationKeys, "wfp.link.id-reused");
        if (kBootChanged) {
            // ID reordering across boots is inevitable and does not constitute evidence of ID recycling and reallocation within the same session.
            addKey(change.limitationKeys, "wfp.delta.boot-changed");
        }
        delta.changes.push_back(std::move(change));
    }
    return delta;
}

// ---------------------------------------------------------------------------
// N-08: navigation
// ---------------------------------------------------------------------------
namespace {

// outcome reuses the value domain of LiveNavigation (no new navigation results added at this layer); rejection reasons are listed separately in a single dimension.
WfpNavigationRejection rejectionFromOutcome(NavigationOutcome outcome) noexcept {
    switch (outcome) {
    case NavigationOutcome::kDelivered:         return WfpNavigationRejection::kNone;
    case NavigationOutcome::kTargetPageMissing: return WfpNavigationRejection::kTargetPageMissing;
    case NavigationOutcome::kObjectNotPresent:  return WfpNavigationRejection::kObjectNotPresent;
    case NavigationOutcome::kIdentityUnusable:  return WfpNavigationRejection::kIdentityUnusable;
    case NavigationOutcome::kEvidenceIdMissing: return WfpNavigationRejection::kEvidenceIdMissing;
    case NavigationOutcome::kEvidenceNotSaved:  return WfpNavigationRejection::kEvidenceNotSaved;
    }
    return WfpNavigationRejection::kObjectNotPresent;
}

} // namespace

ObjectRef makeFilterRef(const WfpFilter& filter, std::string evidenceId) {
    ObjectRef ref;
    ref.kind = ObjectKind::kUnknown;  // ObjectIdentity does not include WFP filter types.
    ref.evidenceId = std::move(evidenceId);
    ref.displayText = filter.displayName.present ? filter.displayName.value : filter.filterKey.text;
    if (filter.filterKey.known()) {
        ref.key = "wfp-filter|" + filter.filterKey.text;
        ref.strength = IdentityStrength::kStrong;  // GUID is a stable cross-session key.
    } else {
        // References with runtime IDs do not emit keys: filterId is reused, and jumping across sessions may refer to different rules.
        ref.strength = IdentityStrength::kUnusable;
    }
    return ref;
}

ObjectRef makeCalloutRef(const WfpCallout& callout, std::string evidenceId) {
    ObjectRef ref;
    ref.kind = ObjectKind::kUnknown;
    ref.evidenceId = std::move(evidenceId);
    ref.displayText = callout.displayName.present ? callout.displayName.value : callout.calloutKey.text;
    if (callout.calloutKey.known()) {
        ref.key = "wfp-callout|" + callout.calloutKey.text;
        ref.strength = IdentityStrength::kStrong;
    } else {
        ref.strength = IdentityStrength::kUnusable;
    }
    return ref;
}

WfpNavigationResult navigateConnectionToProcess(const ConnectionDescription& connection,
                                                const LiveResolution& live,
                                                bool targetPageAvailable,
                                                bool evidencePresentInSession,
                                                std::string evidenceId) {
    WfpNavigationResult result;
    result.identityRevalidated = true;
    result.liveDecision = resolveProcessNavigation(connection.identity.owner, live);
    result.request.page = NavigationPage::kProcess;
    result.request.evidenceId = evidenceId;

    switch (result.liveDecision) {
    case LiveNavigationDecision::kAllow:
        break;
    case LiveNavigationDecision::kRejectObjectExited:
    case LiveNavigationDecision::kRejectIdentityMismatch:
        // PID reuse / object exited: The object is not present in the context; never delegate the operation to a new process that merely resembles it.
        result.request.object = makeProcessRef(connection.identity.owner, std::move(evidenceId));
        result.outcome = NavigationOutcome::kObjectNotPresent;
        result.rejection = WfpNavigationRejection::kObjectNotPresent;
        return result;
    case LiveNavigationDecision::kRejectIdentityUnverifiable:
        result.request.object = makeProcessRef(connection.identity.owner, std::move(evidenceId));
        result.outcome = NavigationOutcome::kIdentityUnusable;
        result.rejection = WfpNavigationRejection::kIdentityUnusable;
        return result;
    }

    result.request.object = makeProcessRef(live.liveProcess, std::move(evidenceId));
    result.outcome = decideNavigation(result.request, targetPageAvailable, true, evidencePresentInSession);
    result.rejection = rejectionFromOutcome(result.outcome);
    return result;
}

WfpNavigationResult navigateFilterToEvidence(const WfpFilter& filter,
                                             bool targetPageAvailable,
                                             bool objectPresentInPage,
                                             bool evidencePresentInSession,
                                             std::string evidenceId) {
    WfpNavigationResult result;
    result.request.page = NavigationPage::kNetwork;
    result.request.evidenceId = evidenceId;
    result.request.object = makeFilterRef(filter, std::move(evidenceId));
    result.outcome = decideNavigation(result.request, targetPageAvailable, objectPresentInPage,
                                      evidencePresentInSession);
    result.rejection = rejectionFromOutcome(result.outcome);
    return result;
}

WfpNavigationResult navigateObservationToTimeline(const ObservedFilterHit& hit,
                                                  bool targetPageAvailable,
                                                  bool evidencePresentInSession) {
    WfpNavigationResult result;
    result.request.page = NavigationPage::kTimeline;
    result.request.evidenceId = hit.evidenceId;
    result.request.object = makeConnectionRef(hit.connection, hit.evidenceId);
    // First, apply standard navigation criteria: insufficient identity, missing evidence ID, offline without saving, or
    // target page unavailable. These four reasons are distinct. Prioritizing source trustworthiness would cause all of
    // them to be masked by "object not in current data" — even failing to detect that the request lacked an evidence ID.
    result.outcome = decideNavigation(result.request, targetPageAvailable, true, evidencePresentInSession);
    result.rejection = rejectionFromOutcome(result.outcome);
    if (classifyObservation(hit) != ObservationTrust::kActualObservation) {
        // N-04: Records from unsupported, disabled, or untrusted sources cannot be placed on the timeline as the 'actual path traversed'.
        // outcome: Retains the conclusion from the previous standard check; the rejection reason is separately marked as SourceNotTrusted.
        // These two fields together clarify the state of 'untrusted and lacking an evidence ID'.
        result.blockedByUntrustedSource = true;
        if (result.outcome == NavigationOutcome::kDelivered) {
            result.outcome = NavigationOutcome::kObjectNotPresent;
        }
        result.rejection = WfpNavigationRejection::kSourceNotTrusted;
    }
    return result;
}

} // namespace ksword::evidence

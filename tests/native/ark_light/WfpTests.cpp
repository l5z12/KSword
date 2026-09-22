// Offline automated test for Module N (WFP and network rule interpretation).
//
// Coverage IDs: N-01 N-02 N-03 N-04 N-05 N-06 N-08.
// N-07 (end-to-end with own rules): Requires isolated environment testing; this file does not claim to cover it.
//
// Assertion principles (Q-01 / Q-02):
//   * Expected values are always manually calculated and hardcoded: address bytes, mask prefixes, arbitration conclusions, and restriction key strings are written as literals
//     directly, without reverse-calculating from the function under test, and without feeding the production function's output back into itself for 'reference against reference'.
//   * FWP constants (GUIDs for FWP_MATCH_*, FWP_ACTION_*, FWPM_CONDITION_*) are copied independently from the Windows SDK
//     in tests, separate from the table in WfpAnalysis.cpp. If the table is copied incorrectly, this section will fail.
//   * Every enum branch must have an assertion; 'Unknown' and 'Mismatch' must never share the same expected value.

#include "TestSupport.h"

#include "../../../shared/evidence/WfpAnalysis.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace ksword::evidence;

// FWP_MATCH_TYPE (independently copied from SDK fwptypes.h)
constexpr std::uint32_t kMatchEqual = 0U;
constexpr std::uint32_t kMatchGreater = 1U;
constexpr std::uint32_t kMatchLessOrEqual = 4U;
constexpr std::uint32_t kMatchRange = 5U;
constexpr std::uint32_t kMatchFlagsAllSet = 6U;
constexpr std::uint32_t kMatchNotEqual = 10U;
constexpr std::uint32_t kMatchPrefix = 11U;
constexpr std::uint32_t kMatchBogus = 99U;  // Not within 0..12 — must resolve to Unknown.

// FWP_DATA_TYPE (independently copied from SDK fwptypes.h).
constexpr std::uint32_t kTypeUint8 = 1U;
constexpr std::uint32_t kTypeUint16 = 2U;
constexpr std::uint32_t kTypeUint32 = 3U;
constexpr std::uint32_t kTypeByteArray16 = 11U;
constexpr std::uint32_t kTypeByteBlob = 12U;
constexpr std::uint32_t kTypeSid = 13U;
constexpr std::uint32_t kTypeV4AddrMask = 0x100U;
constexpr std::uint32_t kTypeV6AddrMask = 0x101U;
constexpr std::uint32_t kTypeRange = 0x102U;
constexpr std::uint32_t kTypeBogus = 0x777U;

// FWP_ACTION_* (independently copied from SDK fwptypes.h: low-order sequence number | flags)
constexpr std::uint32_t kActionBlock = 0x00000001U | 0x00001000U;
constexpr std::uint32_t kActionPermit = 0x00000002U | 0x00001000U;
constexpr std::uint32_t kActionCalloutTerminating = 0x00000003U | 0x00004000U | 0x00001000U;
constexpr std::uint32_t kActionCalloutInspection = 0x00000004U | 0x00004000U | 0x00002000U;
constexpr std::uint32_t kActionCalloutUnknown = 0x00000005U | 0x00004000U;
constexpr std::uint32_t kActionContinue = 0x00000006U | 0x00002000U;
constexpr std::uint32_t kActionNone = 0x00000007U;
constexpr std::uint32_t kActionNoneNoMatch = 0x00000008U;

// FWPM_CONDITION_* (independent copy of comment lines from SDK fwpmu.h)
constexpr const char* kGuidRemotePort = "{c35a604d-d22b-4e1a-91b4-68f674ee674b}";
constexpr const char* kGuidLocalPort = "{0c1ba1af-5765-453f-af22-a8f791ac775b}";
constexpr const char* kGuidRemoteAddress = "{b235ae9a-1d64-49b8-a44c-5ff3d9095045}";
constexpr const char* kGuidLocalAddress = "{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}";
constexpr const char* kGuidProtocol = "{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}";
constexpr const char* kGuidDirection = "{8784c146-ca97-44d6-9fd1-19fb1840cbf7}";
constexpr const char* kGuidAppId = "{d78e1e87-8644-4ea5-9437-d809ecefc971}";
constexpr const char* kGuidUserId = "{af043a0a-b34d-4f86-979c-c90371af6e66}";
constexpr const char* kGuidFlags = "{632ce23b-5167-435c-86d7-e903684aa80c}";
// A condition GUID (FWPM_CONDITION_INTERFACE_TYPE) not present in the built-in table, used to verify the 'unknown condition' path.
constexpr const char* kGuidUnmodeled = "{daf8cd14-e09e-4c93-a5ae-c5c13b73ffca}";

// Object GUIDs used for test samples. Deliberately set identical display names but different GUIDs for the two providers.
constexpr const char* kProviderA = "{11111111-1111-4111-8111-111111111111}";
constexpr const char* kProviderB = "{22222222-2222-4222-8222-222222222222}";
constexpr const char* kLayerAle = "{33333333-3333-4333-8333-333333333333}";
constexpr const char* kSubLayerHigh = "{44444444-4444-4444-8444-444444444444}";
constexpr const char* kSubLayerLow = "{55555555-5555-4555-8555-555555555555}";
constexpr const char* kCalloutX = "{66666666-6666-4666-8666-666666666666}";
constexpr const char* kFilter1 = "{aaaaaaaa-0000-4000-8000-000000000001}";
constexpr const char* kFilter2 = "{aaaaaaaa-0000-4000-8000-000000000002}";
constexpr const char* kFilter3 = "{aaaaaaaa-0000-4000-8000-000000000003}";
constexpr const char* kFilter4 = "{aaaaaaaa-0000-4000-8000-000000000004}";

// Bounds-safe accessor: no out-of-bounds access on assertion failure (injective verification may reduce group count).
const LayerCandidateGroup& layerAt(const StaticCandidateReport& report, std::size_t index) {
    static const LayerCandidateGroup kEmptyLayer;
    return index < report.layers.size() ? report.layers[index] : kEmptyLayer;
}

const SubLayerCandidateGroup& subAt(const LayerCandidateGroup& group, std::size_t index) {
    static const SubLayerCandidateGroup kEmptySubLayer;
    return index < group.subLayers.size() ? group.subLayers[index] : kEmptySubLayer;
}

const FilterCandidate& filterAt(const SubLayerCandidateGroup& group, std::size_t index) {
    static const FilterCandidate kEmptyFilter;
    return index < group.filters.size() ? group.filters[index] : kEmptyFilter;
}

OptionalText text(const char* value) { return OptionalText::of(std::string(value)); }

WfpGuid g(const char* text) { return guidFromText(text); }

WfpAddress ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    WfpAddress address;
    address.family = WfpAddressFamily::kIPv4;
    address.bytes.fill(0U);
    address.bytes[0] = a;
    address.bytes[1] = b;
    address.bytes[2] = c;
    address.bytes[3] = d;
    return address;
}

WfpConditionValue numericValue(WfpDataType type, std::uint32_t rawTypeCode, std::uint64_t value) {
    WfpConditionValue result;
    result.type = type;
    result.rawTypeCode = rawTypeCode;
    result.numeric = OptionalU64::of(value);
    return result;
}

WfpConditionValue v4MaskValue(const WfpAddress& network, std::uint32_t mask) {
    WfpConditionValue result;
    result.type = WfpDataType::kV4AddrMask;
    result.rawTypeCode = kTypeV4AddrMask;
    result.v4Present = true;
    result.v4.address = network;
    result.v4.mask = mask;
    return result;
}

WfpConditionValue v6PrefixValue(const WfpAddress& network, std::uint32_t prefixLength, bool valid) {
    WfpConditionValue result;
    result.type = WfpDataType::kV6AddrMask;
    result.rawTypeCode = kTypeV6AddrMask;
    result.v6Present = true;
    result.v6.address = network;
    result.v6.prefixLength = prefixLength;
    result.v6.prefixLengthValid = valid;
    return result;
}

WfpConditionValue rangeValue(std::uint64_t low, std::uint64_t high) {
    WfpConditionValue result;
    result.type = WfpDataType::kRange;
    result.rawTypeCode = kTypeRange;
    result.range.elementType = WfpDataType::kUint16;
    result.range.numeric = true;
    result.range.low = OptionalU64::of(low);
    result.range.high = OptionalU64::of(high);
    return result;
}

WfpConditionValue appIdValue(const char* path) {
    WfpConditionValue result;
    result.type = WfpDataType::kByteBlob;
    result.rawTypeCode = kTypeByteBlob;
    result.blobText = text(path);
    result.blobBytes = { 0x01U, 0x02U };
    return result;
}

WfpConditionValue sidValue(const char* sid) {
    WfpConditionValue result;
    result.type = WfpDataType::kSid;
    result.rawTypeCode = kTypeSid;
    result.sidText = text(sid);
    return result;
}

ConnectionDescription makeConnection() {
    ConnectionDescription connection;
    connection.localAddress = ipv4(192U, 168U, 1U, 50U);
    connection.remoteAddress = ipv4(93U, 184U, 216U, 34U);
    connection.localPort = OptionalU64::of(52344U);
    connection.remotePort = OptionalU64::of(443U);
    connection.protocol = OptionalU64::of(6U);  // IPPROTO_TCP
    connection.direction = WfpDirection::kOutbound;
    connection.appId = text("\\device\\harddiskvolume3\\windows\\system32\\curl.exe");
    connection.userSid = text("S-1-5-21-100-200-300-1001");
    return connection;
}

void markPartitionComplete(WfpCatalog& catalog, WfpPartition partition, std::uint64_t count) {
    CoverageAccount coverage;
    coverage.totalKnown = OptionalU64::of(count);
    coverage.succeeded = count;
    catalog.setPartitionState(partition, CollectionOutcome::success(), coverage);
}

WfpFilter makeFilter(const char* key,
                     std::uint64_t filterId,
                     const char* subLayer,
                     std::uint32_t rawAction,
                     WfpActionType action) {
    WfpFilter filter;
    filter.filterKey = g(key);
    filter.filterId = OptionalU64::of(filterId);
    filter.displayName = text(key);
    filter.providerKey = g(kProviderA);
    filter.layerKey = g(kLayerAle);
    filter.subLayerKey = g(subLayer);
    filter.rawActionCode = rawAction;
    filter.action = action;
    return filter;
}

void setEffectiveWeight(WfpFilter& filter, std::uint64_t weight) {
    filter.weightKind = WfpWeightKind::kExplicit;
    filter.weight = OptionalU64::of(weight);
    filter.effectiveWeight = OptionalU64::of(weight);
}

// Condition for remote port == value (the most common 'decidable' condition in this test).
WfpCondition remotePortEquals(std::uint64_t port) {
    return makeCondition(g(kGuidRemotePort), kMatchEqual,
                         numericValue(WfpDataType::kUint16, kTypeUint16, port));
}

// ---------------------------------------------------------------------------
// N-01: Object relationships and unique keys
// ---------------------------------------------------------------------------
void testObjectIdentityAndJoins(ksword_tests::Suite& s) {
    WfpGuid parsed;
    s.expect(parseGuid("{11111111-1111-4111-8111-111111111111}", parsed),
             L"N-01 规范形式的 GUID 可解析");
    s.expect(parsed.text == "{11111111-1111-4111-8111-111111111111}",
             L"N-01 解析结果保持规范文本");

    WfpGuid upper;
    s.expect(parseGuid("A1B2C3D4-E5F6-4788-9AAB-CCDDEEFF0011", upper),
             L"N-01 不带花括号的大写 GUID 也可解析");
    s.expect(upper.text == "{a1b2c3d4-e5f6-4788-9aab-ccddeeff0011}",
             L"N-01 GUID 归一化成小写带花括号");

    WfpGuid untouched;
    untouched.text = "sentinel";
    s.expect(!parseGuid("", untouched), L"N-01 空串不是合法 GUID");
    s.expect(!parseGuid("11111111-1111-4111-8111-11111111111", untouched), L"N-01 少一位的 GUID 被拒绝");
    s.expect(!parseGuid("11111111-1111-4111-8111-11111111111Z", untouched), L"N-01 非十六进制字符被拒绝");
    s.expect(!parseGuid("111111111-111-4111-8111-111111111111", untouched), L"N-01 连字符位置错误被拒绝");
    s.expect(untouched.text == "sentinel", L"N-01 解析失败不修改输出参数");
    s.expect(!guidFromText("not-a-guid").known(), L"N-01 非法文本得到未知 GUID 而不是半成品键");

    WfpCatalog catalog;
    WfpProvider providerA;
    providerA.providerKey = g(kProviderA);
    providerA.displayName = text("Microsoft Corporation");
    WfpProvider providerB;
    providerB.providerKey = g(kProviderB);
    providerB.displayName = text("Microsoft Corporation");  // Same name, different GUID
    s.expect(catalog.addProvider(providerA), L"N-01 首个 provider 入库成功");
    s.expect(catalog.addProvider(providerB), L"N-01 同名异 GUID 的 provider 也能独立入库");
    markPartitionComplete(catalog, WfpPartition::kProviders, 2U);

    s.expect(catalog.providers().size() == 2U, L"N-01 同名不合并：目录里仍是两个 provider");
    const ObjectReference kRefA = catalog.resolveProvider(g(kProviderA));
    const ObjectReference kRefB = catalog.resolveProvider(g(kProviderB));
    s.expect(kRefA.state == ReferenceState::kResolved, L"N-01 provider A 按 GUID 关联成功");
    s.expect(kRefB.state == ReferenceState::kResolved, L"N-01 provider B 按 GUID 关联成功");
    s.expect(kRefA.key.text == std::string(kProviderA), L"N-01 关联结果保留自己的 GUID");
    s.expect(kRefB.key.text == std::string(kProviderB), L"N-01 两个同名对象没有互相顶替");
    s.expect(catalog.findProvidersByDisplayName("Microsoft Corporation").size() == 2U,
             L"N-01 名称查询返回全部同名对象，说明名称不是唯一键");

    // GUID not found in the catalog: partition fully collected -> UnknownObject (do not guess, do not leave raw GUIDs masquerading as resolved).
    const ObjectReference kMissing = catalog.resolveProvider(g("{99999999-9999-4999-8999-999999999999}"));
    s.expect(kMissing.state == ReferenceState::kUnknownObject, L"N-01 缺失关联显示未知对象");
    s.expect(!kMissing.resolvedName.present, L"N-01 未知对象不带解析名称");
    s.expect(kMissing.key.known(), L"N-01 未知对象仍保留原始 GUID 供追查");

    // The reference field itself is null — a distinct state from 'unknown object'.
    const ObjectReference kUnspecified = catalog.resolveProvider(WfpGuid{});
    s.expect(kUnspecified.state == ReferenceState::kNotSpecified, L"N-01 空引用是 NotSpecified 而不是未知对象");

    // Same GUID appears twice: snapshot is inconsistent; must explicitly report ambiguity instead of silently taking the first entry.
    WfpCatalog duplicated;
    WfpProvider dup1;
    dup1.providerKey = g(kProviderA);
    dup1.displayName = text("first");
    WfpProvider dup2;
    dup2.providerKey = g(kProviderA);
    dup2.displayName = text("second");
    s.expect(duplicated.addProvider(dup1), L"N-01 重复 GUID 的第一条正常入库");
    s.expect(!duplicated.addProvider(dup2), L"N-01 重复 GUID 的第二条被标记为重复");
    markPartitionComplete(duplicated, WfpPartition::kProviders, 2U);
    s.expect(duplicated.resolveProvider(g(kProviderA)).state == ReferenceState::kAmbiguous,
             L"N-01 同 GUID 重复时关联结果是 Ambiguous");
    s.expect(duplicated.providers().size() == 2U, L"N-01 重复行仍然保留，不静默丢弃");
}

// ---------------------------------------------------------------------------
// N-01: Action and weight fields
// ---------------------------------------------------------------------------
void testActionAndWeightDecoding(ksword_tests::Suite& s) {
    s.expect(decodeActionType(kActionBlock) == WfpActionType::kBlock, L"N-01 FWP_ACTION_BLOCK 解成 Block");
    s.expect(decodeActionType(kActionPermit) == WfpActionType::kPermit, L"N-01 FWP_ACTION_PERMIT 解成 Permit");
    s.expect(decodeActionType(kActionCalloutTerminating) == WfpActionType::kCalloutTerminating,
             L"N-01 CALLOUT_TERMINATING 正确解码");
    s.expect(decodeActionType(kActionCalloutInspection) == WfpActionType::kCalloutInspection,
             L"N-01 CALLOUT_INSPECTION 正确解码");
    s.expect(decodeActionType(kActionCalloutUnknown) == WfpActionType::kCalloutUnknown,
             L"N-01 CALLOUT_UNKNOWN 正确解码");
    s.expect(decodeActionType(kActionContinue) == WfpActionType::kContinue, L"N-01 CONTINUE 正确解码");
    s.expect(decodeActionType(kActionNone) == WfpActionType::kNone, L"N-01 NONE 正确解码");
    s.expect(decodeActionType(kActionNoneNoMatch) == WfpActionType::kNoneNoMatch,
             L"N-01 NONE_NO_MATCH 正确解码");
    s.expect(decodeActionType(0x00000001U) == WfpActionType::kUnknown,
             L"N-01 缺少 TERMINATING 标志的 0x1 不是 Block 而是 Unknown");
    s.expect(decodeActionType(0xDEADU) == WfpActionType::kUnknown, L"N-01 未知动作码解成 Unknown 而不是放行");

    s.expect(actionIsCallout(WfpActionType::kCalloutTerminating), L"N-01 终结型 callout 属于动态动作");
    s.expect(actionIsCallout(WfpActionType::kCalloutInspection), L"N-01 检查型 callout 属于动态动作");
    s.expect(actionIsCallout(WfpActionType::kCalloutUnknown), L"N-01 未知型 callout 属于动态动作");
    s.expect(!actionIsCallout(WfpActionType::kBlock), L"N-01 Block 不是动态动作");
    s.expect(!actionIsCallout(WfpActionType::kUnknown), L"N-01 未知动作不被当成动态 callout");

    s.expect(decodeDataType(kTypeUint16) == WfpDataType::kUint16, L"N-02 FWP_UINT16 正确解码");
    s.expect(decodeDataType(kTypeV4AddrMask) == WfpDataType::kV4AddrMask, L"N-02 FWP_V4_ADDR_MASK 正确解码");
    s.expect(decodeDataType(kTypeV6AddrMask) == WfpDataType::kV6AddrMask, L"N-02 FWP_V6_ADDR_MASK 正确解码");
    s.expect(decodeDataType(kTypeRange) == WfpDataType::kRange, L"N-02 FWP_RANGE_TYPE 正确解码");
    s.expect(decodeDataType(kTypeBogus) == WfpDataType::kUnknown, L"N-02 未建模数据类型解成 Unknown");
    s.expect(decodeMatchType(kMatchRange) == WfpMatchType::kRange, L"N-02 FWP_MATCH_RANGE 正确解码");
    s.expect(decodeMatchType(kMatchPrefix) == WfpMatchType::kPrefix, L"N-02 FWP_MATCH_PREFIX 正确解码");
    s.expect(decodeMatchType(kMatchBogus) == WfpMatchType::kUnknown, L"N-02 越界比较运算解成 Unknown");

    // weight and effectiveWeight are two distinct fields, neither of which has the type number FWP_VALUE0.
    WfpCatalog catalog;
    WfpFilter automatic = makeFilter(kFilter1, 11U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
    automatic.weightKind = WfpWeightKind::kAuto;  // FWP_EMPTY: Caller did not provide a weight.
    automatic.effectiveWeight = OptionalU64::of(4200U);
    WfpFilter explicitWeight = makeFilter(kFilter2, 12U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    explicitWeight.weightKind = WfpWeightKind::kExplicit;
    explicitWeight.weight = OptionalU64::of(7U);  // No effectiveWeight
    catalog.addFilter(automatic);
    catalog.addFilter(explicitWeight);
    markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

    const ConnectionDescription kConnection = makeConnection();
    const FilterCandidate kAutoCandidate = evaluateFilter(catalog, automatic, kConnection);
    const FilterCandidate kExplicitCandidate = evaluateFilter(catalog, explicitWeight, kConnection);
    s.expect(kAutoCandidate.weightConfidence == WeightOrderConfidence::kEffectiveWeight,
             L"N-01 自动权重的 filter 用 effectiveWeight 排序");
    s.expect(kAutoCandidate.orderingWeight == OptionalU64::of(4200U), L"N-01 排序权重取 effectiveWeight 的值");
    s.expect(kExplicitCandidate.weightConfidence == WeightOrderConfidence::kExplicitWeight,
             L"N-01 没有 effectiveWeight 时退回显式 weight");
    s.expect(kExplicitCandidate.orderingWeight == OptionalU64::of(7U), L"N-01 显式权重值被原样保留");

    WfpFilter noWeight = makeFilter(kFilter3, 13U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    noWeight.weightKind = WfpWeightKind::kAuto;  // Neither effectiveWeight nor explicit weight is present.
    const FilterCandidate kNoWeightCandidate = evaluateFilter(catalog, noWeight, kConnection);
    s.expect(kNoWeightCandidate.weightConfidence == WeightOrderConfidence::kUnknown,
             L"N-01 缺权重元数据时排序依据是 Unknown");
    s.expect(!kNoWeightCandidate.orderingWeight.present, L"N-01 缺权重时不拿 0 冒充权重");
    s.expect(hasLimitation(kNoWeightCandidate.limitationKeys, "wfp.filter.weight-unknown"),
             L"N-01 缺权重会记入限制说明");
}

// ---------------------------------------------------------------------------
// N-02: Address, mask, and prefix
// ---------------------------------------------------------------------------
void testAddressParsing(ksword_tests::Suite& s) {
    WfpAddress v4;
    s.expect(parseIpAddress("192.168.1.50", v4), L"N-02 IPv4 文本可解析");
    s.expect(v4.family == WfpAddressFamily::kIPv4, L"N-02 IPv4 地址族标记正确");
    s.expect(v4.bytes[0] == 192U && v4.bytes[1] == 168U && v4.bytes[2] == 1U && v4.bytes[3] == 50U,
             L"N-02 IPv4 字节按网络序存放");
    s.expect(formatIpAddress(v4) == "192.168.1.50", L"N-02 IPv4 文本往返一致");

    WfpAddress reject;
    s.expect(!parseIpAddress("256.1.1.1", reject), L"N-02 越界八位组被拒绝");
    s.expect(!parseIpAddress("1.2.3", reject), L"N-02 少一段的 IPv4 被拒绝");
    s.expect(!parseIpAddress("1.2.3.4.5", reject), L"N-02 多一段的 IPv4 被拒绝");
    s.expect(!parseIpAddress("1.2.3.a", reject), L"N-02 非数字八位组被拒绝");
    s.expect(!parseIpAddress("", reject), L"N-02 空串不是地址");

    WfpAddress v6;
    s.expect(parseIpAddress("2001:db8::1", v6), L"N-02 压缩形式 IPv6 可解析");
    s.expect(v6.family == WfpAddressFamily::kIPv6, L"N-02 IPv6 地址族标记正确");
    s.expect(v6.bytes[0] == 0x20U && v6.bytes[1] == 0x01U && v6.bytes[2] == 0x0dU && v6.bytes[3] == 0xb8U,
             L"N-02 IPv6 前四字节正确");
    s.expect(v6.bytes[14] == 0x00U && v6.bytes[15] == 0x01U, L"N-02 IPv6 末尾字节正确");
    s.expect(formatIpAddress(v6) == "2001:db8::1", L"N-02 IPv6 按 RFC 5952 压缩输出");

    WfpAddress loopback;
    s.expect(parseIpAddress("::1", loopback), L"N-02 前导 :: 可解析");
    s.expect(loopback.bytes[15] == 1U && loopback.bytes[0] == 0U, L"N-02 ::1 字节正确");
    s.expect(formatIpAddress(loopback) == "::1", L"N-02 ::1 往返一致");

    WfpAddress anyAddress;
    s.expect(parseIpAddress("::", anyAddress), L"N-02 全零 IPv6 可解析");
    s.expect(formatIpAddress(anyAddress) == "::", L"N-02 全零 IPv6 输出 ::");

    WfpAddress mapped;
    s.expect(parseIpAddress("::ffff:192.168.0.1", mapped), L"N-02 内嵌 IPv4 的 IPv6 可解析");
    s.expect(mapped.bytes[10] == 0xffU && mapped.bytes[11] == 0xffU, L"N-02 v4 映射前缀字节正确");
    s.expect(mapped.bytes[12] == 192U && mapped.bytes[15] == 1U, L"N-02 内嵌 IPv4 字节正确");

    WfpAddress full;
    s.expect(parseIpAddress("1:2:3:4:5:6:7:8", full), L"N-02 完整八段 IPv6 可解析");
    s.expect(full.bytes[1] == 1U && full.bytes[15] == 8U, L"N-02 完整八段的首尾正确");
    s.expect(formatIpAddress(full) == "1:2:3:4:5:6:7:8", L"N-02 无零段时不压缩");

    // Longest zero-segment compression, taking the leftmost in case of a tie: 2001:0:0:1:0:0:0:1 -> 2001:0:0:1::1
    std::array<std::uint8_t, 16> raw{};
    raw[0] = 0x20U;
    raw[1] = 0x01U;
    raw[7] = 0x01U;
    raw[15] = 0x01U;
    const WfpAddress kTwoRuns = WfpAddress::ipv6FromBytes(raw);
    s.expect(formatIpAddress(kTwoRuns) == "2001:0:0:1::1", L"N-02 压缩最长零段而不是第一个零段");

    s.expect(!parseIpAddress(":::", reject), L"N-02 三个冒号被拒绝");
    s.expect(!parseIpAddress("1::2::3", reject), L"N-02 两个 :: 被拒绝");
    s.expect(!parseIpAddress("12345::", reject), L"N-02 超长分组被拒绝");
    s.expect(!parseIpAddress("1:2:3:4:5:6:7", reject), L"N-02 段数不足且无 :: 被拒绝");
    s.expect(!parseIpAddress("1:2:3:4:5:6:7:8:9", reject), L"N-02 段数超出被拒绝");
    s.expect(!parseIpAddress("1:2:3:4:5:6:7:", reject), L"N-02 结尾单冒号被拒绝");

    std::uint32_t prefix = 0xFFFFFFFFU;
    s.expect(maskToPrefixLength(0xFFFFFF00U, prefix) && prefix == 24U, L"N-02 255.255.255.0 前缀长度是 24");
    s.expect(maskToPrefixLength(0xFFFFFFFFU, prefix) && prefix == 32U, L"N-02 全 1 掩码前缀长度是 32");
    s.expect(maskToPrefixLength(0U, prefix) && prefix == 0U, L"N-02 全 0 掩码前缀长度是 0");
    s.expect(!maskToPrefixLength(0xFF00FF00U, prefix), L"N-02 非连续掩码不能折成前缀长度");

    const WfpV4AddrMask kSubnet{ ipv4(10U, 0U, 0U, 0U), 0xFF000000U };
    s.expect(addressInV4Subnet(ipv4(10U, 1U, 2U, 3U), kSubnet), L"N-02 10.1.2.3 落在 10/8 内");
    s.expect(!addressInV4Subnet(ipv4(11U, 1U, 2U, 3U), kSubnet), L"N-02 11.1.2.3 不在 10/8 内");

    WfpAddress prefixBase;
    (void)parseIpAddress("2001:db8::", prefixBase);
    WfpV6AddrPrefix v6Prefix;
    v6Prefix.address = prefixBase;
    v6Prefix.prefixLength = 32U;
    v6Prefix.prefixLengthValid = true;
    WfpAddress inside;
    (void)parseIpAddress("2001:db8:1234::9", inside);
    WfpAddress outside;
    (void)parseIpAddress("2001:db9::1", outside);
    s.expect(addressInV6Prefix(inside, v6Prefix), L"N-02 2001:db8:1234::9 落在 2001:db8::/32 内");
    s.expect(!addressInV6Prefix(outside, v6Prefix), L"N-02 2001:db9::1 不在 2001:db8::/32 内");
    WfpV6AddrPrefix invalidPrefix = v6Prefix;
    invalidPrefix.prefixLengthValid = false;
    s.expect(!addressInV6Prefix(inside, invalidPrefix), L"N-02 前缀长度无效时不做包含判定");
}

// ---------------------------------------------------------------------------
// N-02: Condition interpretation with three-state evaluation.
// ---------------------------------------------------------------------------
void testConditionInterpretation(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();

    // Field mapping: GUID -> FWPM_CONDITION_* name
    const WfpCondition kRemotePort = remotePortEquals(443U);
    s.expect(kRemotePort.field == WfpFieldKind::kIpRemotePort, L"N-02 远端端口条件 GUID 解出正确字段");
    s.expect(kRemotePort.fieldName == "FWPM_CONDITION_IP_REMOTE_PORT", L"N-02 字段名与 SDK 符号一致");
    s.expect(fieldGuidFor(WfpFieldKind::kIpRemotePort).text == std::string(kGuidRemotePort),
             L"N-02 字段反查 GUID 与 SDK 一致");
    s.expect(fieldGuidFor(WfpFieldKind::kIpLocalPort).text == std::string(kGuidLocalPort),
             L"N-02 本地端口 GUID 与 SDK 一致");
    s.expect(fieldGuidFor(WfpFieldKind::kIpLocalPort) != fieldGuidFor(WfpFieldKind::kIpRemotePort),
             L"N-02 本地/远端端口是两个不同的条件 GUID");
    s.expect(kRemotePort.interpreted(), L"N-02 端口等值条件被完整解释");
    s.expect(kRemotePort.evaluable(), L"N-02 端口条件可用于判定连接");

    s.expect(evaluateCondition(kRemotePort, kConnection).result == ConditionMatch::kMatch,
             L"N-02 远端端口 443 == 443 判定为匹配");
    s.expect(evaluateCondition(remotePortEquals(8080U), kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 远端端口 443 != 8080 判定为不匹配");

    // Port range
    const WfpCondition kPortRange = makeCondition(g(kGuidRemotePort), kMatchRange, rangeValue(400U, 500U));
    s.expect(kPortRange.match == WfpMatchType::kRange, L"N-02 范围比较运算解码正确");
    s.expect(evaluateCondition(kPortRange, kConnection).result == ConditionMatch::kMatch,
             L"N-02 443 落在 [400,500] 内");
    const WfpCondition kPortRangeMiss = makeCondition(g(kGuidRemotePort), kMatchRange, rangeValue(1U, 100U));
    s.expect(evaluateCondition(kPortRangeMiss, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 443 不在 [1,100] 内");

    // Other numeric comparisons.
    const WfpCondition kPortGreater = makeCondition(g(kGuidRemotePort), kMatchGreater,
                                                   numericValue(WfpDataType::kUint16, kTypeUint16, 1024U));
    s.expect(evaluateCondition(kPortGreater, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 443 > 1024 为不匹配");
    const WfpCondition kPortLessEqual = makeCondition(g(kGuidRemotePort), kMatchLessOrEqual,
                                                     numericValue(WfpDataType::kUint16, kTypeUint16, 443U));
    s.expect(evaluateCondition(kPortLessEqual, kConnection).result == ConditionMatch::kMatch,
             L"N-02 443 <= 443 为匹配");
    const WfpCondition kPortNotEqual = makeCondition(g(kGuidRemotePort), kMatchNotEqual,
                                                    numericValue(WfpDataType::kUint16, kTypeUint16, 80U));
    s.expect(evaluateCondition(kPortNotEqual, kConnection).result == ConditionMatch::kMatch,
             L"N-02 443 != 80 为匹配");

    // Protocol
    const WfpCondition kProtocolTcp = makeCondition(g(kGuidProtocol), kMatchEqual,
                                                   numericValue(WfpDataType::kUint8, kTypeUint8, 6U));
    s.expect(kProtocolTcp.field == WfpFieldKind::kIpProtocol, L"N-02 协议条件 GUID 解出正确字段");
    s.expect(evaluateCondition(kProtocolTcp, kConnection).result == ConditionMatch::kMatch,
             L"N-02 TCP(6) 协议条件匹配");
    const WfpCondition kProtocolUdp = makeCondition(g(kGuidProtocol), kMatchEqual,
                                                   numericValue(WfpDataType::kUint8, kTypeUint8, 17U));
    s.expect(evaluateCondition(kProtocolUdp, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 UDP(17) 协议条件不匹配");

    // IPv4 subnet
    const WfpCondition kRemoteSubnet = makeCondition(g(kGuidRemoteAddress), kMatchEqual,
                                                    v4MaskValue(ipv4(93U, 184U, 0U, 0U), 0xFFFF0000U));
    s.expect(kRemoteSubnet.field == WfpFieldKind::kIpRemoteAddress, L"N-02 远端地址条件 GUID 解出正确字段");
    s.expect(evaluateCondition(kRemoteSubnet, kConnection).result == ConditionMatch::kMatch,
             L"N-02 93.184.216.34 落在 93.184.0.0/16 内");
    const WfpCondition kOtherSubnet = makeCondition(g(kGuidRemoteAddress), kMatchEqual,
                                                   v4MaskValue(ipv4(10U, 0U, 0U, 0U), 0xFF000000U));
    s.expect(evaluateCondition(kOtherSubnet, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 93.184.216.34 不在 10/8 内");

    // A single IPv4 address is expressed as FWP_UINT32 in host byte order.
    const WfpCondition kLocalExact = makeCondition(
        g(kGuidLocalAddress), kMatchEqual,
        numericValue(WfpDataType::kUint32, kTypeUint32, 0xC0A80132ULL));  // 192.168.1.50
    s.expect(evaluateCondition(kLocalExact, kConnection).result == ConditionMatch::kMatch,
             L"N-02 主机序 UINT32 形式的本地地址匹配");

    // IPv6 prefix: Switch connection to v6
    ConnectionDescription v6Connection = makeConnection();
    (void)parseIpAddress("2001:db8:1::5", v6Connection.remoteAddress);
    WfpAddress v6Base;
    (void)parseIpAddress("2001:db8::", v6Base);
    const WfpCondition kV6Prefix = makeCondition(g(kGuidRemoteAddress), kMatchEqual,
                                                v6PrefixValue(v6Base, 32U, true));
    s.expect(evaluateCondition(kV6Prefix, v6Connection).result == ConditionMatch::kMatch,
             L"N-02 IPv6 /32 前缀条件匹配");
    const WfpCondition kV6PrefixMiss = makeCondition(g(kGuidRemoteAddress), kMatchEqual,
                                                    v6PrefixValue(v6Base, 64U, true));
    s.expect(evaluateCondition(kV6PrefixMiss, v6Connection).result == ConditionMatch::kNoMatch,
             L"N-02 IPv6 /64 前缀条件不匹配");
    const WfpCondition kV6BadPrefix = makeCondition(g(kGuidRemoteAddress), kMatchEqual,
                                                   v6PrefixValue(v6Base, 200U, false));
    const ConditionEvaluation kBadPrefixEval = evaluateCondition(kV6BadPrefix, v6Connection);
    s.expect(kBadPrefixEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 非法前缀长度不做真值断言");
    s.expect(hasLimitation(kBadPrefixEval.limitationKeys, "wfp.condition.invalid-prefix-length"),
             L"N-02 非法前缀长度写进限制说明");

    // Single IPv6 address (FWP_BYTE_ARRAY16)
    WfpConditionValue exactV6;
    exactV6.type = WfpDataType::kByteArray16;
    exactV6.rawTypeCode = kTypeByteArray16;
    (void)parseIpAddress("2001:db8:1::5", exactV6.singleAddress);
    const WfpCondition kV6Exact = makeCondition(g(kGuidRemoteAddress), kMatchEqual, exactV6);
    s.expect(evaluateCondition(kV6Exact, v6Connection).result == ConditionMatch::kMatch,
             L"N-02 单个 IPv6 地址等值匹配");

    // Address family mismatch: positive comparison yields NoMatch, negative comparison remains Unknown.
    const ConditionEvaluation kFamilyPositive = evaluateCondition(kRemoteSubnet, v6Connection);
    s.expect(kFamilyPositive.result == ConditionMatch::kNoMatch, L"N-02 IPv4 子网条件对 IPv6 连接判不匹配");
    s.expect(hasLimitation(kFamilyPositive.limitationKeys, "wfp.condition.address-family-mismatch"),
             L"N-02 地址族错配写进限制说明");
    const WfpCondition kRemoteNotSubnet = makeCondition(g(kGuidRemoteAddress), kMatchNotEqual,
                                                       v4MaskValue(ipv4(10U, 0U, 0U, 0U), 0xFF000000U));
    s.expect(evaluateCondition(kRemoteNotSubnet, v6Connection).result == ConditionMatch::kInsufficientInfo,
             L"N-02 跨地址族的否定条件保持信息不足");

    // Range comparison on address is not modeled at this layer.
    const WfpCondition kAddressRange = makeCondition(g(kGuidRemoteAddress), kMatchRange, rangeValue(1U, 2U));
    const ConditionEvaluation kAddressRangeEval = evaluateCondition(kAddressRange, kConnection);
    s.expect(kAddressRangeEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 地址范围条件不猜结果");
    s.expect(hasLimitation(kAddressRangeEval.limitationKeys, "wfp.condition.address-range-not-modeled"),
             L"N-02 地址范围未建模写进限制说明");

    // Direction
    const WfpCondition kOutbound = makeCondition(g(kGuidDirection), kMatchEqual,
                                                numericValue(WfpDataType::kUint32, kTypeUint32, 0U));
    s.expect(kOutbound.field == WfpFieldKind::kDirection, L"N-02 方向条件 GUID 解出正确字段");
    s.expect(evaluateCondition(kOutbound, kConnection).result == ConditionMatch::kMatch,
             L"N-02 FWP_DIRECTION_OUTBOUND(0) 对出站连接匹配");
    const WfpCondition kInbound = makeCondition(g(kGuidDirection), kMatchEqual,
                                               numericValue(WfpDataType::kUint32, kTypeUint32, 1U));
    s.expect(evaluateCondition(kInbound, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 FWP_DIRECTION_INBOUND(1) 对出站连接不匹配");
    const WfpCondition kBogusDirection = makeCondition(g(kGuidDirection), kMatchEqual,
                                                      numericValue(WfpDataType::kUint32, kTypeUint32, 2U));
    const ConditionEvaluation kBogusDirEval = evaluateCondition(kBogusDirection, kConnection);
    s.expect(kBogusDirEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 方向值 2 不在 FWP_DIRECTION_ 定义内，不猜成 FORWARD");
    s.expect(hasLimitation(kBogusDirEval.limitationKeys, "wfp.condition.unknown-direction-value"),
             L"N-02 未知方向值写进限制说明");
    s.expect(kBogusDirEval.condition.value.numeric == OptionalU64::of(2U),
             L"N-02 未知方向值的原始数值被保留");
    ConnectionDescription forwardConnection = makeConnection();
    forwardConnection.direction = WfpDirection::kForward;
    s.expect(evaluateCondition(kOutbound, forwardConnection).result == ConditionMatch::kInsufficientInfo,
             L"N-02 转发流量与 in/out 二分不可比，保持信息不足");

    // AppId
    const WfpCondition kAppId = makeCondition(
        g(kGuidAppId), kMatchEqual,
        appIdValue("\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe"));
    s.expect(kAppId.field == WfpFieldKind::kAleAppId, L"N-02 AppId 条件 GUID 解出正确字段");
    s.expect(evaluateCondition(kAppId, kConnection).result == ConditionMatch::kMatch,
             L"N-02 AppId 大小写不敏感匹配");
    const WfpCondition kAppIdOther = makeCondition(g(kGuidAppId), kMatchEqual,
                                                  appIdValue("\\device\\harddiskvolume3\\windows\\system32\\ping.exe"));
    s.expect(evaluateCondition(kAppIdOther, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 不同 AppId 判不匹配");
    const WfpCondition kAppIdPrefix = makeCondition(g(kGuidAppId), kMatchPrefix,
                                                   appIdValue("\\Device\\HarddiskVolume3\\Windows\\"));
    s.expect(evaluateCondition(kAppIdPrefix, kConnection).result == ConditionMatch::kMatch,
             L"N-02 AppId 前缀比较匹配");
    WfpConditionValue undecodedBlob;
    undecodedBlob.type = WfpDataType::kByteBlob;
    undecodedBlob.rawTypeCode = kTypeByteBlob;
    undecodedBlob.blobBytes = { 0xFFU, 0xFEU, 0x00U };  // Failed to decode path text.
    const WfpCondition kAppIdRaw = makeCondition(g(kGuidAppId), kMatchEqual, undecodedBlob);
    const ConditionEvaluation kAppIdRawEval = evaluateCondition(kAppIdRaw, kConnection);
    s.expect(kAppIdRawEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 解不出文本的 AppId 不能当成匹配任何程序");
    s.expect(hasLimitation(kAppIdRawEval.limitationKeys, "wfp.condition.blob-not-decoded"),
             L"N-02 未解码 blob 写进限制说明");
    s.expect(kAppIdRawEval.condition.value.blobBytes.size() == 3U, L"N-02 未解码 blob 的原始字节被保留");

    // User SID
    const WfpCondition kUserSid = makeCondition(g(kGuidUserId), kMatchEqual,
                                               sidValue("S-1-5-21-100-200-300-1001"));
    s.expect(kUserSid.field == WfpFieldKind::kAleUserId, L"N-02 用户条件 GUID 解出正确字段");
    s.expect(evaluateCondition(kUserSid, kConnection).result == ConditionMatch::kMatch, L"N-02 SID 等值匹配");
    const WfpCondition kOtherSid = makeCondition(g(kGuidUserId), kMatchEqual, sidValue("S-1-5-18"));
    s.expect(evaluateCondition(kOtherSid, kConnection).result == ConditionMatch::kNoMatch,
             L"N-02 不同 SID 判不匹配");

    // ---- Unknown/Unmodeled paths: Never collapse into 'unconditional match' ----
    const WfpCondition kUnknownField = makeCondition(g(kGuidUnmodeled), kMatchEqual,
                                                    numericValue(WfpDataType::kUint32, kTypeUint32, 1U));
    const ConditionEvaluation kUnknownFieldEval = evaluateCondition(kUnknownField, kConnection);
    s.expect(kUnknownField.field == WfpFieldKind::kUnknown, L"N-02 表外条件 GUID 解成未知字段");
    s.expect(kUnknownField.fieldName.empty(), L"N-02 未知字段不编造名称");
    s.expect(!kUnknownField.interpreted(), L"N-02 未知字段的条件不算已解释");
    s.expect(kUnknownFieldEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 未知条件是信息不足，不是无条件匹配");
    s.expect(kUnknownFieldEval.result != ConditionMatch::kMatch, L"N-02 未知条件绝不判匹配");
    s.expect(hasLimitation(kUnknownFieldEval.limitationKeys, "wfp.condition.unknown-field"),
             L"N-02 未知字段写进限制说明");
    s.expect(kUnknownFieldEval.condition.fieldKey.text == std::string(kGuidUnmodeled),
             L"N-02 未知条件保留原始 GUID");

    WfpConditionValue unknownValue;
    unknownValue.type = WfpDataType::kUnknown;
    unknownValue.rawTypeCode = kTypeBogus;
    unknownValue.rawText = "0x0102030405";
    const WfpCondition kUnknownType = makeCondition(g(kGuidRemotePort), kMatchEqual, unknownValue);
    const ConditionEvaluation kUnknownTypeEval = evaluateCondition(kUnknownType, kConnection);
    s.expect(kUnknownTypeEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 未知数据类型是信息不足");
    s.expect(hasLimitation(kUnknownTypeEval.limitationKeys, "wfp.condition.unknown-value-type"),
             L"N-02 未知数据类型写进限制说明");
    s.expect(kUnknownTypeEval.condition.value.rawText == "0x0102030405",
             L"N-02 未知数据类型的原始值被保留");
    s.expect(kUnknownTypeEval.condition.value.rawTypeCode == kTypeBogus,
             L"N-02 未知数据类型的原始类型号被保留");

    const WfpCondition kUnknownMatch = makeCondition(g(kGuidRemotePort), kMatchBogus,
                                                    numericValue(WfpDataType::kUint16, kTypeUint16, 443U));
    const ConditionEvaluation kUnknownMatchEval = evaluateCondition(kUnknownMatch, kConnection);
    s.expect(kUnknownMatch.match == WfpMatchType::kUnknown, L"N-02 越界比较运算解成 Unknown");
    s.expect(kUnknownMatchEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 未知比较运算不按等值处理");
    s.expect(kUnknownMatchEval.condition.rawMatchCode == kMatchBogus, L"N-02 未知比较运算的原始码被保留");

    const WfpCondition kFlagsCondition = makeCondition(g(kGuidFlags), kMatchFlagsAllSet,
                                                      numericValue(WfpDataType::kUint32, kTypeUint32, 4U));
    const ConditionEvaluation kFlagsEval = evaluateCondition(kFlagsCondition, kConnection);
    s.expect(kFlagsCondition.field == WfpFieldKind::kFlags, L"N-02 FLAGS 字段名可解析");
    s.expect(kFlagsCondition.interpreted(), L"N-02 FLAGS 条件的字段与类型都读懂了");
    s.expect(!kFlagsCondition.evaluable(), L"N-02 读懂名字不等于能判定连接");
    s.expect(kFlagsEval.result == ConditionMatch::kInsufficientInfo, L"N-02 未建模字段保持信息不足");
    s.expect(hasLimitation(kFlagsEval.limitationKeys, "wfp.condition.field-not-modeled"),
             L"N-02 未建模字段写进限制说明");

    // The connection description itself is missing attributes.
    ConnectionDescription partial = makeConnection();
    partial.remotePort = OptionalU64::unset();
    const ConditionEvaluation kMissingAttr = evaluateCondition(kRemotePort, partial);
    s.expect(kMissingAttr.result == ConditionMatch::kInsufficientInfo,
             L"N-02 连接缺少端口时不判匹配也不判不匹配");
    s.expect(hasLimitation(kMissingAttr.limitationKeys, "wfp.condition.attribute-unknown"),
             L"N-02 连接属性缺失写进限制说明");
    ConnectionDescription noApp = makeConnection();
    noApp.appId = OptionalText::unset();
    s.expect(evaluateCondition(kAppId, noApp).result == ConditionMatch::kInsufficientInfo,
             L"N-02 连接缺少 AppId 时保持信息不足");

    // Value type mismatch with field semantics.
    const WfpCondition kPortWithBlob = makeCondition(g(kGuidRemotePort), kMatchEqual, appIdValue("x"));
    const ConditionEvaluation kMismatchEval = evaluateCondition(kPortWithBlob, kConnection);
    s.expect(kMismatchEval.result == ConditionMatch::kInsufficientInfo, L"N-02 端口字段配 blob 值不做判定");
    s.expect(hasLimitation(kMismatchEval.limitationKeys, "wfp.condition.value-type-mismatch"),
             L"N-02 值类型错配写进限制说明");
}

// ---------------------------------------------------------------------------
// N-02 / N-03: condition combination
// ---------------------------------------------------------------------------
void testConditionCombination(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();

    std::vector<ConditionEvaluation> none;
    s.expect(combineConditionResults(none, false) == ConditionMatch::kMatch,
             L"N-03 真正的空条件集才是无条件匹配");
    s.expect(combineConditionResults(none, true) == ConditionMatch::kInsufficientInfo,
             L"N-02 条件被截断时不能当成无条件匹配");

    // Same field OR: one match triggers the whole group.
    std::vector<ConditionEvaluation> sameField;
    sameField.push_back(evaluateCondition(remotePortEquals(443U), kConnection));
    sameField.push_back(evaluateCondition(remotePortEquals(80U), kConnection));
    s.expect(sameField[0].result == ConditionMatch::kMatch, L"N-02 同字段第一条命中");
    s.expect(sameField[1].result == ConditionMatch::kNoMatch, L"N-02 同字段第二条不命中");
    s.expect(combineConditionResults(sameField, false) == ConditionMatch::kMatch,
             L"N-03 同一字段的多条条件按 OR 合并");

    // Cross-field AND: A single miss results in overall failure.
    std::vector<ConditionEvaluation> crossField;
    crossField.push_back(evaluateCondition(remotePortEquals(443U), kConnection));
    crossField.push_back(evaluateCondition(
        makeCondition(g(kGuidProtocol), kMatchEqual, numericValue(WfpDataType::kUint8, kTypeUint8, 17U)),
        kConnection));
    s.expect(combineConditionResults(crossField, false) == ConditionMatch::kNoMatch,
             L"N-03 不同字段的条件按 AND 合并");

    // Matching AND Unknown equals Unknown (this is the core principle that 'unknown conditions do not equate to unconditional matches').
    std::vector<ConditionEvaluation> withUnknown;
    withUnknown.push_back(evaluateCondition(remotePortEquals(443U), kConnection));
    withUnknown.push_back(evaluateCondition(
        makeCondition(g("{daf8cd14-e09e-4c93-a5ae-c5c13b73ffca}"), kMatchEqual,
                      numericValue(WfpDataType::kUint32, kTypeUint32, 1U)),
        kConnection));
    s.expect(combineConditionResults(withUnknown, false) == ConditionMatch::kInsufficientInfo,
             L"N-02 命中条件 AND 未知条件的结果是未知");

    // No match AND unknown = no match (unknown cannot pull back a definite negation).
    std::vector<ConditionEvaluation> noMatchWithUnknown;
    noMatchWithUnknown.push_back(evaluateCondition(remotePortEquals(8080U), kConnection));
    noMatchWithUnknown.push_back(withUnknown[1]);
    s.expect(combineConditionResults(noMatchWithUnknown, false) == ConditionMatch::kNoMatch,
             L"N-03 确定的不匹配不会被未知条件抬回未知");

    // Truncation + existing non-match = still non-match
    s.expect(combineConditionResults(noMatchWithUnknown, true) == ConditionMatch::kNoMatch,
             L"N-02 截断不会把确定的不匹配变成未知");
}

// ---------------------------------------------------------------------------
// N-03: Candidate arbitration by layer/sublayer
// ---------------------------------------------------------------------------
WfpCatalog makeArbitrationCatalog(std::uint64_t highWeight, std::uint64_t lowWeight) {
    WfpCatalog catalog;
    catalog.setGeneration(7U);

    // N-06: Collection time and boot cycle follow the catalog; only runtime IDs spanning a boot can be verified.
    CaptureWindow window;
    window.bootId = "boot-N";
    window.machineId = "machine-N";
    window.sessionId = "session-N";
    window.mode = CaptureMode::kSnapshot;
    window.startUtc100ns = OptionalU64::of(133700000000000000ULL);
    window.endUtc100ns = OptionalU64::of(133700000500000000ULL);
    catalog.setCaptureWindow(window);

    WfpProvider provider;
    provider.providerKey = g(kProviderA);
    provider.displayName = text("KSword Test Provider");
    catalog.addProvider(provider);

    WfpLayer layer;
    layer.layerKey = g(kLayerAle);
    layer.displayName = text("ALE_AUTH_CONNECT_V4");
    layer.layerId = OptionalU64::of(48U);
    catalog.addLayer(layer);

    WfpSubLayer high;
    high.subLayerKey = g(kSubLayerHigh);
    high.displayName = text("SubLayerHigh");
    high.weight = OptionalU64::of(highWeight);
    catalog.addSubLayer(high);

    WfpSubLayer low;
    low.subLayerKey = g(kSubLayerLow);
    low.displayName = text("SubLayerLow");
    low.weight = OptionalU64::of(lowWeight);
    catalog.addSubLayer(low);

    WfpCallout callout;
    callout.calloutKey = g(kCalloutX);
    callout.displayName = text("InspectionCallout");
    callout.calloutId = OptionalU64::of(90U);
    callout.registered = true;
    catalog.addCallout(callout);

    markPartitionComplete(catalog, WfpPartition::kProviders, 1U);
    markPartitionComplete(catalog, WfpPartition::kLayers, 1U);
    markPartitionComplete(catalog, WfpPartition::kSubLayers, 2U);
    markPartitionComplete(catalog, WfpPartition::kCallouts, 1U);
    return catalog;
}

void testStaticArbitration(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();

    // --- Scenario A: Within a single sublayer, rules are sorted by weight in descending order; the rule with the highest weight wins.
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter lowPriority = makeFilter(kFilter1, 101U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        setEffectiveWeight(lowPriority, 100U);
        lowPriority.conditions.push_back(remotePortEquals(443U));
        WfpFilter highPriority = makeFilter(kFilter2, 102U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(highPriority, 9000U);
        highPriority.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(lowPriority);
        catalog.addFilter(highPriority);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(kReport.evaluatedFilterCount == 2U, L"N-03 两条规则都参与了候选评估");
        s.expect(kReport.layers.size() == 1U, L"N-03 两条规则归入同一个 layer 分组");
        s.expect(layerAt(kReport, 0U).subLayers.size() == 1U, L"N-03 同 sublayer 的规则归入同一组");
        s.expect(subAt(layerAt(kReport, 0U), 0U).filters.size() == 2U, L"N-03 分组内保留全部两条规则");
        s.expect(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).filterKey.text == std::string(kFilter2),
                 L"N-03 分组内按权重降序：9000 的规则排在前面");
        s.expect(subAt(layerAt(kReport, 0U), 0U).orderingReliable, L"N-03 同量纲且不重复的权重可作为排序依据");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kBlockCandidate,
                 L"N-03 sublayer 内最高权重的匹配规则决定候选结论");
        s.expect(layerAt(kReport, 0U).decision == CandidateDecision::kBlockCandidate, L"N-03 层结论与其唯一 sublayer 一致");
        s.expect(kReport.overallDecision == CandidateDecision::kBlockCandidate, L"N-03 整体候选结论为阻断候选");
        s.expect(layerAt(kReport, 0U).layer.state == ReferenceState::kResolved, L"N-03 layer 关联成功");
        s.expect(subAt(layerAt(kReport, 0U), 0U).subLayerWeight == OptionalU64::of(60000U),
                 L"N-03 sublayer 权重取自 sublayer 对象而不是 filter");
        s.expect(hasLimitation(kReport.limitationKeys, "wfp.candidate.layer-default-action-not-modeled"),
                 L"N-03 明确声明层默认动作未建模");
        s.expect(hasLimitation(kReport.limitationKeys, "wfp.candidate.filter-flags-not-modeled"),
                 L"N-03 明确声明 filter 标志位未建模");
    }

    // --- Scenario B: Different sublayers arbitrate independently; never sort by a global weight.
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        // Place a low-weight filter rule in a high-weight sublayer.
        WfpFilter permitInHighSubLayer =
            makeFilter(kFilter1, 201U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        setEffectiveWeight(permitInHighSubLayer, 10U);
        permitInHighSubLayer.conditions.push_back(remotePortEquals(443U));
        // Place a filter rule with **high** weight in a low-weight sublayer to block traffic.
        WfpFilter blockInLowSubLayer =
            makeFilter(kFilter2, 202U, kSubLayerLow, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(blockInLowSubLayer, 5000U);
        blockInLowSubLayer.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(permitInHighSubLayer);
        catalog.addFilter(blockInLowSubLayer);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(kReport.layers.size() == 1U, L"N-03 两条规则同层");
        s.expect(layerAt(kReport, 0U).subLayers.size() == 2U, L"N-03 不同 sublayer 分成两组");
        s.expect(subAt(layerAt(kReport, 0U), 0U).subLayerWeight == OptionalU64::of(60000U),
                 L"N-03 sublayer 按自己的权重降序排列");
        s.expect(subAt(layerAt(kReport, 0U), 0U).filters.size() == 1U,
                 L"N-03 高权重 sublayer 里只有属于它的那条规则");
        s.expect(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).filterKey.text == std::string(kFilter1),
                 L"N-03 全局权重更高的规则没有被挪进别的 sublayer");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kPermitCandidate,
                 L"N-03 低 filter 权重的规则在自己的 sublayer 里照样胜出");
        s.expect(subAt(layerAt(kReport, 0U), 1U).decision == CandidateDecision::kBlockCandidate,
                 L"N-03 另一个 sublayer 独立得出阻断候选");
        s.expect(layerAt(kReport, 0U).decision == CandidateDecision::kBlockCandidate,
                 L"N-03 全部 sublayer 判明时阻断压过放行");
        s.expect(layerAt(kReport, 0U).subLayerOrderingReliable, L"N-03 sublayer 权重齐备且不重复时顺序可信");
    }

    // --- Scenario C: Different sublayer + Different weight + Missing metadata + Callout dynamic judgment -> Unknown ---
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter permitHigh = makeFilter(kFilter1, 301U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        setEffectiveWeight(permitHigh, 900U);
        permitHigh.conditions.push_back(remotePortEquals(443U));

        WfpFilter blockNoWeight = makeFilter(kFilter2, 302U, kSubLayerLow, kActionBlock, WfpActionType::kBlock);
        blockNoWeight.weightKind = WfpWeightKind::kAuto;  // Missing weight metadata
        blockNoWeight.conditions.push_back(remotePortEquals(443U));

        WfpFilter dynamicCallout =
            makeFilter(kFilter3, 303U, kSubLayerLow, kActionCalloutTerminating, WfpActionType::kCalloutTerminating);
        dynamicCallout.actionCalloutKey = g(kCalloutX);
        setEffectiveWeight(dynamicCallout, 800U);
        dynamicCallout.conditions.push_back(remotePortEquals(443U));

        catalog.addFilter(permitHigh);
        catalog.addFilter(blockNoWeight);
        catalog.addFilter(dynamicCallout);
        markPartitionComplete(catalog, WfpPartition::kFilters, 3U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(kReport.layers.size() == 1U, L"N-03 混合规则组仍在同一层");
        s.expect(layerAt(kReport, 0U).subLayers.size() == 2U, L"N-03 混合规则组按 sublayer 分成两组");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kPermitCandidate,
                 L"N-03 元数据齐备的 sublayer 仍然给出可知结论");
        s.expect(subAt(layerAt(kReport, 0U), 1U).filters.size() == 2U, L"N-03 低权重 sublayer 有两条规则");
        s.expect(!subAt(layerAt(kReport, 0U), 1U).orderingReliable,
                 L"N-03 有规则缺权重时该 sublayer 顺序不可信");
        s.expect(hasLimitation(subAt(layerAt(kReport, 0U), 1U).limitationKeys, "wfp.sublayer.order-unreliable"),
                 L"N-03 顺序不可信写进限制说明");
        s.expect(subAt(layerAt(kReport, 0U), 1U).decision == CandidateDecision::kUnknown,
                 L"N-03 缺元数据 + 动态 callout 的 sublayer 结论保持未知");
        s.expect(layerAt(kReport, 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 有 sublayer 不确定时整层保持未知");
        s.expect(kReport.overallDecision == CandidateDecision::kUnknown,
                 L"N-03 存在动态判断时最终决策必须保留未知");
        s.expect(kReport.overallDecision != CandidateDecision::kBlockCandidate,
                 L"N-03 不确定时不许升级成阻断结论");

        bool sawDynamicKey = false;
        bool calloutResolved = false;
        for (const FilterCandidate& candidate : subAt(layerAt(kReport, 0U), 1U).filters) {
            if (candidate.filterKey.text == std::string(kFilter3)) {
                sawDynamicKey = hasLimitation(candidate.limitationKeys, "wfp.filter.dynamic-callout");
                calloutResolved = candidate.actionCallout.state == ReferenceState::kResolved;
                s.expect(candidate.dynamicByCallout, L"N-03 callout 动作被标为动态判定");
            }
        }
        s.expect(sawDynamicKey, L"N-03 动态 callout 写进该规则的限制说明");
        s.expect(calloutResolved, L"N-01 filter 的 action callout 关联到目录里的 callout 对象");
    }

    // --- Scenario D: No rules match -> NoMatchingFilter, not 'allow' ---
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter unrelated = makeFilter(kFilter1, 401U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(unrelated, 500U);
        unrelated.conditions.push_back(remotePortEquals(8080U));
        catalog.addFilter(unrelated);
        markPartitionComplete(catalog, WfpPartition::kFilters, 1U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kNoMatchingFilter,
                 L"N-03 无规则匹配时结论是「无匹配规则」");
        s.expect(kReport.overallDecision == CandidateDecision::kNoMatchingFilter,
                 L"N-03 无匹配规则不等于放行候选");
        s.expect(kReport.overallDecision != CandidateDecision::kPermitCandidate,
                 L"N-03 不把「没匹配上」翻译成放行");
    }

    // --- Scenario E: Rules with higher weight conditions are unreadable -> the entire sublayer remains unknown ---
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter unreadable = makeFilter(kFilter1, 501U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        setEffectiveWeight(unreadable, 9000U);
        unreadable.conditions.push_back(makeCondition(g(kGuidUnmodeled), kMatchEqual,
                                                      numericValue(WfpDataType::kUint32, kTypeUint32, 1U)));
        WfpFilter definite = makeFilter(kFilter2, 502U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(definite, 10U);
        definite.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(unreadable);
        catalog.addFilter(definite);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).match == ConditionMatch::kInsufficientInfo,
                 L"N-02 读不懂条件的规则匹配结论是信息不足");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 更高权重的规则不确定时不能拿下面的确定规则当结论");
        s.expect(kReport.overallDecision != CandidateDecision::kBlockCandidate,
                 L"N-03 上方存在未知规则时不得给出阻断结论");
    }

    // --- Scenario F: order untrusted but candidate unique -> conclusion is order-independent, can be issued ---
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter noWeightMatch = makeFilter(kFilter1, 601U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        noWeightMatch.weightKind = WfpWeightKind::kAuto;
        noWeightMatch.conditions.push_back(remotePortEquals(443U));
        WfpFilter noWeightMiss = makeFilter(kFilter2, 602U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        noWeightMiss.weightKind = WfpWeightKind::kAuto;
        noWeightMiss.conditions.push_back(remotePortEquals(8080U));
        catalog.addFilter(noWeightMatch);
        catalog.addFilter(noWeightMiss);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(!subAt(layerAt(kReport, 0U), 0U).orderingReliable, L"N-03 两条规则都缺权重时顺序不可信");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kBlockCandidate,
                 L"N-03 唯一候选时结论与顺序无关");
    }

    // --- Scenario G: Mixed weight dimensions -> Refusal to sort
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter effective = makeFilter(kFilter1, 701U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(effective, 900U);
        effective.conditions.push_back(remotePortEquals(443U));
        WfpFilter explicitOnly = makeFilter(kFilter2, 702U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        explicitOnly.weightKind = WfpWeightKind::kExplicit;
        explicitOnly.weight = OptionalU64::of(15U);  // No effectiveWeight
        explicitOnly.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(effective);
        catalog.addFilter(explicitOnly);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(!subAt(layerAt(kReport, 0U), 0U).orderingReliable,
                 L"N-03 effectiveWeight 与显式 weight 混用时顺序不可信");
        s.expect(hasLimitation(subAt(layerAt(kReport, 0U), 0U).limitationKeys, "wfp.sublayer.weight-scale-mixed"),
                 L"N-03 权重量纲混用写进限制说明");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 两个候选且顺序不可信时结论保持未知");
    }

    // --- Scenario H: Rules with truncated conditions must not be treated as unconditional matches ---
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter truncated = makeFilter(kFilter1, 801U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(truncated, 900U);
        truncated.conditions.push_back(remotePortEquals(443U));
        truncated.conditionsTruncated = true;
        catalog.addFilter(truncated);
        markPartitionComplete(catalog, WfpPartition::kFilters, 1U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).match == ConditionMatch::kInsufficientInfo,
                 L"N-02 条件被截断的规则匹配结论是信息不足");
        s.expect(hasLimitation(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).limitationKeys,
                               "wfp.filter.conditions-truncated"),
                 L"N-02 条件截断写进限制说明");
        s.expect(kReport.overallDecision == CandidateDecision::kUnknown, L"N-03 条件截断时结论保持未知");
    }

    // --- Scenario I: Rules missing layer/sublayer metadata are grouped separately and marked ---
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter orphan = makeFilter(kFilter1, 901U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        orphan.layerKey = WfpGuid{};      // Layer reference not captured.
        orphan.subLayerKey = WfpGuid{};   // Failed to capture sublayer reference
        setEffectiveWeight(orphan, 900U);
        orphan.conditions.push_back(remotePortEquals(443U));
        WfpFilter normal = makeFilter(kFilter2, 902U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        setEffectiveWeight(normal, 800U);
        normal.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(orphan);
        catalog.addFilter(normal);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(kReport.layers.size() == 2U, L"N-01 缺 layer 引用的规则不并进已知层");
        bool foundUnspecifiedLayer = false;
        for (const LayerCandidateGroup& group : kReport.layers) {
            if (group.layer.state == ReferenceState::kNotSpecified) {
                foundUnspecifiedLayer = true;
                s.expect(hasLimitation(group.limitationKeys, "wfp.filter.layer-missing"),
                         L"N-01 缺 layer 引用写进限制说明");
                s.expect(group.subLayers.size() == 1U, L"N-01 缺引用的规则自成一组");
                s.expect(subAt(group, 0U).subLayer.state == ReferenceState::kNotSpecified,
                         L"N-01 缺 sublayer 引用也是 NotSpecified");
                s.expect(!subAt(group, 0U).subLayerWeight.present,
                         L"N-03 无法确定 sublayer 时不拿 0 当权重");
            }
        }
        s.expect(foundUnspecifiedLayer, L"N-01 存在一个未指定 layer 的分组");
        for (const LayerCandidateGroup& group : kReport.layers) {
            if (group.layer.state == ReferenceState::kNotSpecified) {
                s.expect(group.unlinkedReference, L"N-01 缺引用的分组被标为「所属范围未知」");
                s.expect(!subAt(group, 0U).orderingReliable,
                         L"N-03 所属范围未知时顺序一律不可信（连和谁竞争都不知道）");
                s.expect(subAt(group, 0U).decision == CandidateDecision::kUnknown,
                         L"N-03 所属范围未知的分组不得给出阻断/放行候选，只能是未知");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// N-01 / N-03: Rules lacking layer/sublayer references each occupy a separate arbitration scope.
//
// The rule 'unknown references do not merge into known groups' and the rule 'unknown references must not merge with each other' are
// the same rule. Two rules of unknown layer membership likely belong to ALE_AUTH_CONNECT_V4 and OUTBOUND_TRANSPORT_V4 respectively.
// Placing them in the same bucket for weighted arbitration effectively invents an arbitration scope that does not exist.
// ---------------------------------------------------------------------------
void testUnlinkedFiltersNeverArbitrateTogether(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();

    // Rules where neither the layer nor the sublayer is collected: Block(900) and Permit(100), both conditions match 443.
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter orphanBlock = makeFilter(kFilter1, 901U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        orphanBlock.layerKey = WfpGuid{};
        orphanBlock.subLayerKey = WfpGuid{};
        setEffectiveWeight(orphanBlock, 900U);
        orphanBlock.conditions.push_back(remotePortEquals(443U));
        WfpFilter orphanPermit = makeFilter(kFilter2, 902U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        orphanPermit.layerKey = WfpGuid{};
        orphanPermit.subLayerKey = WfpGuid{};
        setEffectiveWeight(orphanPermit, 100U);
        orphanPermit.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(orphanBlock);
        catalog.addFilter(orphanPermit);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(kReport.evaluatedFilterCount == 2U, L"N-03 两条无引用规则都参与了评估");
        s.expect(kReport.layers.size() == 2U,
                 L"N-01 两条引用未采集的规则各自独占一个分组，不互相并组");
        s.expect(layerAt(kReport, 0U).subLayers.size() == 1U, L"N-01 第一个未知引用分组里只有一条规则");
        s.expect(subAt(layerAt(kReport, 0U), 0U).filters.size() == 1U,
                 L"N-01 未知引用分组不收第二条规则");
        s.expect(subAt(layerAt(kReport, 1U), 0U).filters.size() == 1U,
                 L"N-01 第二条未知引用规则也自成一组");
        s.expect(!subAt(layerAt(kReport, 0U), 0U).orderingReliable,
                 L"N-03 引用未采集的分组顺序不可信");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 权重 900 的 Block 不因为独占分组就变成阻断候选");
        s.expect(subAt(layerAt(kReport, 1U), 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 权重 100 的 Permit 同样只能是未知");
        s.expect(kReport.overallDecision == CandidateDecision::kUnknown,
                 L"N-03 900 压过 100 这种结论在范围未知时不成立，整体保持未知");
        s.expect(kReport.overallDecision != CandidateDecision::kBlockCandidate,
                 L"N-03 绝不从未知仲裁范围推出阻断候选");
        s.expect(hasLimitation(subAt(layerAt(kReport, 0U), 0U).limitationKeys, "wfp.filter.layer-missing"),
                 L"N-01 缺 layer 引用写进分组自己的限制说明");
        s.expect(hasLimitation(subAt(layerAt(kReport, 0U), 0U).limitationKeys, "wfp.filter.sublayer-missing"),
                 L"N-01 缺 sublayer 引用写进分组自己的限制说明");
    }

    // Two rules where the layer is captured but the sublayer is not: same layer, but each occupies a separate sublayer group.
    {
        WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
        WfpFilter a = makeFilter(kFilter1, 911U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        a.subLayerKey = WfpGuid{};
        setEffectiveWeight(a, 900U);
        a.conditions.push_back(remotePortEquals(443U));
        WfpFilter b = makeFilter(kFilter2, 912U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        b.subLayerKey = WfpGuid{};
        setEffectiveWeight(b, 100U);
        b.conditions.push_back(remotePortEquals(443U));
        catalog.addFilter(a);
        catalog.addFilter(b);
        markPartitionComplete(catalog, WfpPartition::kFilters, 2U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
        s.expect(kReport.layers.size() == 1U, L"N-01 layer 引用还在，两条规则仍归入同一层");
        s.expect(layerAt(kReport, 0U).subLayers.size() == 2U,
                 L"N-01 sublayer 引用未采集时两条规则不共用一个 sublayer 分组");
        s.expect(subAt(layerAt(kReport, 0U), 0U).filters.size() == 1U, L"N-01 每个未知 sublayer 分组只有一条规则");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 sublayer 未知时该分组结论保持未知");
        s.expect(layerAt(kReport, 0U).decision == CandidateDecision::kUnknown,
                 L"N-03 层内有范围未知的分组时整层保持未知");
        s.expect(layerAt(kReport, 0U).unlinkedReference,
                 L"N-01 层分组标出「含有所属范围未知的规则」");
    }
}

// ---------------------------------------------------------------------------
// N-03 / N-06: If the catalog is insufficient to prove absence, 'No Matching Rule' is downgraded to Unknown.
//
// This is an absence assertion: only when the filter partition can positively prove a complete enumeration is it valid to claim
// 'no rules match within this range'. If BFE is inaccessible, the partition is not sampled, or enumeration only reaches 1/9, the
// resulting 'no matching rules' message is identical in the UI to 'no rules match after a complete enumeration of 2000 entries'.
// ---------------------------------------------------------------------------
void testAbsenceRequiresCompleteCatalog(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();

    // (a) Fresh catalog: All partitions are NotCollected.
    {
        WfpCatalog empty;
        const StaticCandidateReport kReport = analyzeStaticCandidates(empty, kConnection);
        s.expect(kReport.layers.empty(), L"N-06 空目录没有任何分组");
        s.expect(kReport.evaluatedFilterCount == 0U, L"N-06 空目录评估了 0 条规则");
        s.expect(!kReport.catalogUsableForAbsence, L"N-06 未采集的分区不能用来推断缺席");
        s.expect(kReport.overallDecision == CandidateDecision::kUnknown,
                 L"N-06 一条规则都没采到时结论是未知，不是「无匹配规则」");
        s.expect(kReport.overallDecision != CandidateDecision::kNoMatchingFilter,
                 L"N-06 没采到绝不等于确实没有规则");
        s.expect(hasLimitation(kReport.limitationKeys, "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 目录不完整写进报告级限制说明");
    }

    // (b) BFE cannot open: partition creation fails with Error + original error code.
    {
        WfpCatalog broken = makeArbitrationCatalog(60000U, 100U);
        broken.setPartitionState(WfpPartition::kFilters,
                                 CollectionOutcome::failure(CollectionStatus::kError, "WIN32", 1753ULL,
                                                            "FwpmEngineOpen0 failed"),
                                 CoverageAccount{});
        const StaticCandidateReport kReport = analyzeStaticCandidates(broken, kConnection);
        s.expect(!kReport.catalogUsableForAbsence, L"N-06 BFE 打不开时目录不可用于缺席推断");
        s.expect(kReport.overallDecision == CandidateDecision::kUnknown,
                 L"N-06 BFE 打不开时结论是未知而不是「无匹配规则」");
        s.expect(broken.partitionState(WfpPartition::kFilters).outcome.nativeCode == OptionalU64::of(1753ULL),
                 L"N-06 原始 Win32 错误码 1753 仍然保留");
    }

    // (c) Partial: Declares 9 entries but enumerates only 1, which does not match.
    {
        WfpCatalog partial = makeArbitrationCatalog(60000U, 100U);
        WfpFilter onlyOne = makeFilter(kFilter1, 1001U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(onlyOne, 500U);
        onlyOne.conditions.push_back(remotePortEquals(8080U));  // Does not match 443.
        partial.addFilter(onlyOne);
        CoverageAccount account;
        account.totalKnown = OptionalU64::of(9U);
        account.succeeded = 1U;
        account.limitHit = true;
        partial.setPartitionState(WfpPartition::kFilters,
                                  CollectionOutcome::failure(CollectionStatus::kPartial, "WIN32", 0ULL,
                                                             "enumeration limit"),
                                  account);

        const StaticCandidateReport kReport = analyzeStaticCandidates(partial, kConnection);
        s.expect(!kReport.catalogUsableForAbsence, L"N-06 只枚举到 1/9 的分区不能推断缺席");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
                 L"N-06 枚举不全时 sublayer 结论降级为未知");
        s.expect(layerAt(kReport, 0U).decision == CandidateDecision::kUnknown,
                 L"N-06 枚举不全时 layer 结论降级为未知");
        s.expect(kReport.overallDecision == CandidateDecision::kUnknown,
                 L"N-06 枚举不全时整体结论降级为未知");
        s.expect(hasLimitation(subAt(layerAt(kReport, 0U), 0U).limitationKeys,
                               "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 目录不完整写进 sublayer 分组的限制说明（不能只写在报告级）");
        s.expect(hasLimitation(layerAt(kReport, 0U).limitationKeys,
                               "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 目录不完整写进 layer 分组的限制说明");
    }

    // (d) Reverse guard: when the ledger can positively prove completeness, "no matching rule" still applies.
    {
        WfpCatalog complete = makeArbitrationCatalog(60000U, 100U);
        WfpFilter unrelated = makeFilter(kFilter1, 1002U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(unrelated, 500U);
        unrelated.conditions.push_back(remotePortEquals(8080U));
        complete.addFilter(unrelated);
        markPartitionComplete(complete, WfpPartition::kFilters, 1U);

        const StaticCandidateReport kReport = analyzeStaticCandidates(complete, kConnection);
        s.expect(kReport.catalogUsableForAbsence, L"N-06 账目正面证明完整时目录可用于缺席推断");
        s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kNoMatchingFilter,
                 L"N-06 完整枚举后确实没有规则匹配才允许说「无匹配规则」");
        s.expect(kReport.overallDecision == CandidateDecision::kNoMatchingFilter,
                 L"N-06 完整枚举的「无匹配规则」结论没有被过度降级");
        s.expect(!hasLimitation(kReport.limitationKeys, "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 完整枚举时不误报目录不完整");
    }

    // (e) Correlation criteria: when a catalog is collected but not fully, 'not present in the catalog' is neither 'unknown object' nor 'NoMatch'.
    {
        WfpCatalog partial = makeArbitrationCatalog(60000U, 100U);
        partial.setGeneration(7U);
        WfpFilter present = makeFilter(kFilter1, 77U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(present, 900U);
        partial.addFilter(present);
        CoverageAccount account;
        account.totalKnown = OptionalU64::of(9U);
        account.succeeded = 1U;
        account.limitHit = true;
        partial.setPartitionState(WfpPartition::kFilters,
                                  CollectionOutcome::failure(CollectionStatus::kPartial, "WIN32", 0ULL,
                                                             "enumeration limit"),
                                  account);

        s.expect(partial.resolveFilter(g(kFilter4)).state == ReferenceState::kCatalogIncomplete,
                 L"N-06 枚举不全时缺失关联是「目录不完整」而不是「未知对象」");
        s.expect(partial.resolveFilter(g(kFilter1)).state == ReferenceState::kResolved,
                 L"N-06 枚举不全不影响已经采到的那条的关联");

        RuntimeFilterReference byGuid;
        byGuid.filterKey = g(kFilter4);
        const FilterReferenceResolution kGuidResult = resolveFilterReference(partial, byGuid);
        s.expect(kGuidResult.state == FilterLinkState::kCatalogIncomplete,
                 L"N-06 枚举不全时按 GUID 找不到不等于「没有这条」");
        s.expect(kGuidResult.state != FilterLinkState::kNoMatch, L"N-06 找不到不等于确实不存在");
        s.expect(hasLimitation(kGuidResult.limitationKeys, "wfp.link.catalog-incomplete"),
                 L"N-06 目录不完整写进关联的限制说明");

        RuntimeFilterReference byId;
        byId.filterId = OptionalU64::of(4242U);
        byId.capturedGeneration = OptionalU64::of(7U);
        byId.bootId = "boot-N";
        const FilterReferenceResolution kIdResult = resolveFilterReference(partial, byId);
        s.expect(kIdResult.state == FilterLinkState::kCatalogIncomplete,
                 L"N-06 枚举不全时运行时 id 找不到同样不下缺席结论");
        s.expect(hasLimitation(kIdResult.limitationKeys, "wfp.link.catalog-incomplete"),
                 L"N-06 运行时 id 关联也写进目录不完整");

        // Reverse guard: NoMatch / UnknownObject only if the complete catalog cannot find the object.
        WfpCatalog complete = makeArbitrationCatalog(60000U, 100U);
        complete.setGeneration(7U);
        complete.addFilter(present);
        markPartitionComplete(complete, WfpPartition::kFilters, 1U);
        s.expect(complete.resolveFilter(g(kFilter4)).state == ReferenceState::kUnknownObject,
                 L"N-06 完整目录里找不到才是「未知对象」");
        s.expect(resolveFilterReference(complete, byGuid).state == FilterLinkState::kNoMatch,
                 L"N-06 完整目录里找不到才是「没有这条」");
    }
}

// ---------------------------------------------------------------------------
// N-02: An unread address is not 'out of subnet'.
//
// In WfpConditionValue.v4/v6, address defaults to family==Unknown. When parseIpAddress fails, it does not modify
// out by design. Consequently, in offline samples, a single failed address text parse leaves v4Present=true with an
// address of unknown family. If the condition treats this as a definite false, the negation of FWP_MATCH_NOT_EQUAL
// flips it to 'match', effectively deriving a block candidate from an address that was never read.
// ---------------------------------------------------------------------------
void testUndecodedAddressNeverMatches(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();

    // Precondition: If parsing fails, out is not modified; the family of an unknown address is Unknown, and the text is an empty string.
    WfpAddress undecoded;
    s.expect(!undecoded.known(), L"N-02 未解析的地址默认是未知地址");
    s.expect(undecoded.family == WfpAddressFamily::kUnknown, L"N-02 未知地址的族是 Unknown");
    s.expect(formatIpAddress(undecoded).empty(), L"N-02 未知地址的展示文本是空串而不是 0.0.0.0");
    s.expect(!parseIpAddress("10.0.0.999", undecoded), L"N-02 越界文本解析失败");
    s.expect(!undecoded.known(), L"N-02 解析失败后地址仍然是未知，不是半成品");

    // Three-state containment judgment: Undecidable and Outside are distinct concepts.
    const WfpV4AddrMask kSubnet{ ipv4(10U, 0U, 0U, 0U), 0xFF000000U };
    s.expect(classifyV4Containment(ipv4(10U, 1U, 2U, 3U), kSubnet) == AddressContainment::kInside,
             L"N-02 10.1.2.3 在 10/8 内");
    s.expect(classifyV4Containment(ipv4(11U, 1U, 2U, 3U), kSubnet) == AddressContainment::kOutside,
             L"N-02 11.1.2.3 确实不在 10/8 内");
    const WfpV4AddrMask kUndecodedSubnet{ WfpAddress{}, 0xFFFFFF00U };
    s.expect(classifyV4Containment(ipv4(10U, 1U, 2U, 3U), kUndecodedSubnet) == AddressContainment::kUndecidable,
             L"N-02 网络地址没解出来时包含判定是「无法判定」而不是「不在里面」");
    s.expect(!addressInV4Subnet(ipv4(10U, 1U, 2U, 3U), kUndecodedSubnet),
             L"N-02 布尔便捷形式对无法判定同样返回 false（调用方不得对它取反）");
    WfpV6AddrPrefix undecodedPrefix;
    undecodedPrefix.prefixLength = 32U;
    undecodedPrefix.prefixLengthValid = true;
    WfpAddress v6Actual;
    (void)parseIpAddress("2001:db8:1::5", v6Actual);
    s.expect(classifyV6Containment(v6Actual, undecodedPrefix) == AddressContainment::kUndecidable,
             L"N-02 v6 网络地址没解出来时同样是「无法判定」");

    // Condition evaluation: both EQUAL and NOT_EQUAL must indicate insufficient information.
    WfpConditionValue badV4;
    badV4.type = WfpDataType::kV4AddrMask;
    badV4.rawTypeCode = kTypeV4AddrMask;
    badV4.v4Present = true;         // Sample claims to include address + mask.
    badV4.v4.mask = 0xFFFFFF00U;    // Mask parsed successfully.
    // badV4.v4.address remains unknown because parsing the address text failed.
    const WfpCondition kV4Equal = makeCondition(g(kGuidRemoteAddress), kMatchEqual, badV4);
    const ConditionEvaluation kV4EqualEval = evaluateCondition(kV4Equal, kConnection);
    s.expect(kV4EqualEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 网络地址没解码时等值比较是信息不足，不是不匹配");
    s.expect(hasLimitation(kV4EqualEval.limitationKeys, "wfp.condition.address-not-decoded"),
             L"N-02 地址未解码写进限制说明");
    const WfpCondition kV4NotEqual = makeCondition(g(kGuidRemoteAddress), kMatchNotEqual, badV4);
    const ConditionEvaluation kV4NotEqualEval = evaluateCondition(kV4NotEqual, kConnection);
    s.expect(kV4NotEqualEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 地址没解码时否定比较仍是信息不足");
    s.expect(kV4NotEqualEval.result != ConditionMatch::kMatch,
             L"N-02 绝不允许把「读不出来」取反成「匹配」");

    WfpConditionValue badV6;
    badV6.type = WfpDataType::kV6AddrMask;
    badV6.rawTypeCode = kTypeV6AddrMask;
    badV6.v6Present = true;
    badV6.v6.prefixLength = 64U;
    badV6.v6.prefixLengthValid = true;
    ConnectionDescription v6Connection = makeConnection();
    (void)parseIpAddress("2001:db8:1::5", v6Connection.remoteAddress);
    const ConditionEvaluation kV6EqualEval =
        evaluateCondition(makeCondition(g(kGuidRemoteAddress), kMatchEqual, badV6), v6Connection);
    s.expect(kV6EqualEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 v6 前缀地址没解码时等值比较是信息不足");
    s.expect(hasLimitation(kV6EqualEval.limitationKeys, "wfp.condition.address-not-decoded"),
             L"N-02 v6 地址未解码写进限制说明");
    s.expect(evaluateCondition(makeCondition(g(kGuidRemoteAddress), kMatchNotEqual, badV6), v6Connection)
                     .result == ConditionMatch::kInsufficientInfo,
             L"N-02 v6 地址没解码时否定比较不得翻成匹配");

    WfpConditionValue badSingle;
    badSingle.type = WfpDataType::kByteArray16;
    badSingle.rawTypeCode = kTypeByteArray16;
    // singleAddress remains unknown.
    const ConditionEvaluation kSingleEval =
        evaluateCondition(makeCondition(g(kGuidRemoteAddress), kMatchNotEqual, badSingle), v6Connection);
    s.expect(kSingleEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 单个 IPv6 地址没解码时否定比较是信息不足");
    s.expect(hasLimitation(kSingleEval.limitationKeys, "wfp.condition.address-not-decoded"),
             L"N-02 未解码的单地址写进限制说明");

    // End-to-end: A Block rule containing only this condition must not become a blocking candidate.
    WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
    WfpFilter blockOnUndecoded = makeFilter(kFilter1, 1101U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(blockOnUndecoded, 900U);
    blockOnUndecoded.conditions.push_back(kV4NotEqual);
    catalog.addFilter(blockOnUndecoded);
    markPartitionComplete(catalog, WfpPartition::kFilters, 1U);
    const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
    s.expect(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).match == ConditionMatch::kInsufficientInfo,
             L"N-02 条件地址没解码的规则匹配结论是信息不足");
    s.expect(hasLimitation(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).limitationKeys,
                           "wfp.condition.address-not-decoded"),
             L"N-02 地址未解码写进该规则的限制说明");
    s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
             L"N-02 从没读出来的地址不得推出阻断候选");
    s.expect(kReport.overallDecision != CandidateDecision::kBlockCandidate,
             L"N-02 未解码地址绝不产生阻断候选");
}

// ---------------------------------------------------------------------------
// N-02: Reading a malformed FWP_RANGE0 is not a 'definite mismatch'
//
// low > high is always false for any actual value. Treating it as a definite NoMatch causes this filter to be
// skipped directly in decideWithinSubLayer, deferring the arbitration decision to rules with lower weights.
// ---------------------------------------------------------------------------
void testMalformedRangeStaysUnknown(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();  // remotePort = 443

    const WfpCondition kInverted = makeCondition(g(kGuidRemotePort), kMatchRange, rangeValue(500U, 400U));
    const ConditionEvaluation kInvertedEval = evaluateCondition(kInverted, kConnection);
    s.expect(kInvertedEval.result == ConditionMatch::kInsufficientInfo,
             L"N-02 low>high 的范围读不出合法区间，判定为信息不足");
    s.expect(kInvertedEval.result != ConditionMatch::kNoMatch,
             L"N-02 非法范围不得变成确定的不匹配");
    s.expect(hasLimitation(kInvertedEval.limitationKeys, "wfp.condition.invalid-range"),
             L"N-02 非法范围写进限制说明");
    s.expect(kInvertedEval.condition.value.range.low == OptionalU64::of(500U) &&
                 kInvertedEval.condition.value.range.high == OptionalU64::of(400U),
             L"N-02 非法范围的原始端点被原样保留");

    // Boundary: low == high is a valid single-point interval.
    s.expect(evaluateCondition(makeCondition(g(kGuidRemotePort), kMatchRange, rangeValue(443U, 443U)),
                               kConnection)
                     .result == ConditionMatch::kMatch,
             L"N-02 [443,443] 单点区间命中 443");
    s.expect(evaluateCondition(makeCondition(g(kGuidRemotePort), kMatchRange, rangeValue(400U, 500U)),
                               kConnection)
                     .result == ConditionMatch::kMatch,
             L"N-02 合法区间 [400,500] 仍然照常命中");

    // Endpoint mismatch and type mismatch are distinct reasons; do not share a single key.
    WfpConditionValue missingHigh = rangeValue(400U, 500U);
    missingHigh.range.high = OptionalU64::unset();
    const ConditionEvaluation kMissingEval =
        evaluateCondition(makeCondition(g(kGuidRemotePort), kMatchRange, missingHigh), kConnection);
    s.expect(kMissingEval.result == ConditionMatch::kInsufficientInfo, L"N-02 缺端点的范围不做判定");
    s.expect(hasLimitation(kMissingEval.limitationKeys, "wfp.condition.range-endpoint-missing"),
             L"N-02 缺端点有自己的限制键");
    s.expect(!hasLimitation(kMissingEval.limitationKeys, "wfp.condition.value-type-mismatch"),
             L"N-02 缺端点不再被塞进「值类型错配」");

    WfpConditionValue textRange = rangeValue(400U, 500U);
    textRange.range.numeric = false;
    textRange.range.rawLow = "aa";
    textRange.range.rawHigh = "bb";
    const ConditionEvaluation kTextEval =
        evaluateCondition(makeCondition(g(kGuidRemotePort), kMatchRange, textRange), kConnection);
    s.expect(kTextEval.result == ConditionMatch::kInsufficientInfo, L"N-02 非数值端点的范围不做判定");
    s.expect(hasLimitation(kTextEval.limitationKeys, "wfp.condition.range-not-numeric"),
             L"N-02 非数值端点有自己的限制键");

    WfpConditionValue notRange = numericValue(WfpDataType::kUint16, kTypeUint16, 443U);
    const ConditionEvaluation kTypeEval =
        evaluateCondition(makeCondition(g(kGuidRemotePort), kMatchRange, notRange), kConnection);
    s.expect(hasLimitation(kTypeEval.limitationKeys, "wfp.condition.value-type-mismatch"),
             L"N-02 比较运算是范围而值不是范围类型，仍报值类型错配");

    // Arbitration: High-weight rules in the read-bad range must not yield conclusions to low-weight rules.
    WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
    WfpFilter broken = makeFilter(kFilter1, 1201U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(broken, 9000U);
    broken.conditions.push_back(kInverted);
    WfpFilter lower = makeFilter(kFilter2, 1202U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
    setEffectiveWeight(lower, 10U);
    lower.conditions.push_back(remotePortEquals(443U));
    catalog.addFilter(broken);
    catalog.addFilter(lower);
    markPartitionComplete(catalog, WfpPartition::kFilters, 2U);
    const StaticCandidateReport kReport = analyzeStaticCandidates(catalog, kConnection);
    s.expect(filterAt(subAt(layerAt(kReport, 0U), 0U), 0U).match == ConditionMatch::kInsufficientInfo,
             L"N-02 读坏范围的规则匹配结论是信息不足");
    s.expect(subAt(layerAt(kReport, 0U), 0U).decision == CandidateDecision::kUnknown,
             L"N-03 高权重规则的范围读不懂时不得把结论让给低权重规则");
    s.expect(kReport.overallDecision != CandidateDecision::kPermitCandidate,
             L"N-03 读坏的范围不得间接抬出放行候选");
}

// ---------------------------------------------------------------------------
// N-02: Reject all leading-zero octets (aligned with inet_pton).
// ---------------------------------------------------------------------------
void testLeadingZeroOctetsRejected(ksword_tests::Suite& s) {
    WfpAddress out;
    out.family = WfpAddressFamily::kIPv6;  // Sentinel: Do not modify out if parsing fails.
    s.expect(!parseIpAddress("010.001.001.001", out),
             L"N-02 带前导零的 IPv4 被拒绝（inet_addr 会按八进制解成 8.1.1.1）");
    s.expect(out.family == WfpAddressFamily::kIPv6, L"N-02 前导零解析失败不修改输出参数");
    s.expect(!parseIpAddress("192.168.01.1", out), L"N-02 单段前导零同样被拒绝");
    s.expect(!parseIpAddress("00.1.1.1", out), L"N-02 00 被拒绝");
    s.expect(!parseIpAddress("::ffff:010.1.1.1", out), L"N-02 内嵌 IPv4 的前导零同样被拒绝");

    WfpAddress zero;
    s.expect(parseIpAddress("0.0.0.0", zero), L"N-02 单个 0 不是前导零，仍然合法");
    s.expect(zero.bytes[0] == 0U && zero.bytes[3] == 0U, L"N-02 0.0.0.0 字节全零");
    s.expect(formatIpAddress(zero) == "0.0.0.0", L"N-02 0.0.0.0 往返一致");
    WfpAddress normal;
    s.expect(parseIpAddress("10.1.1.1", normal), L"N-02 无前导零的地址照常解析");
    s.expect(normal.bytes[0] == 10U && normal.bytes[1] == 1U, L"N-02 10.1.1.1 字节正确");
    WfpAddress mapped;
    s.expect(parseIpAddress("::ffff:192.168.0.1", mapped), L"N-02 无前导零的内嵌 IPv4 照常解析");
    s.expect(mapped.bytes[12] == 192U && mapped.bytes[13] == 168U, L"N-02 内嵌 IPv4 字节仍然正确");
}

// ---------------------------------------------------------------------------
// N-04: actual events separated from static candidates
// ---------------------------------------------------------------------------
ObservedFilterHit makeHit(ObservationSource source, bool supported, bool enabled) {
    ObservedFilterHit hit;
    hit.source = source;
    hit.sourceSupported = supported;
    hit.sourceEnabled = enabled;
    hit.filterId = OptionalU64::of(102U);
    hit.filterKey = g(kFilter2);
    hit.layerId = OptionalU64::of(48U);
    hit.eventUtc100ns = OptionalU64::of(133700000000000000ULL);
    hit.verdict = WfpEventVerdict::kBlocked;
    hit.rawRecordId = "netevent#17";
    hit.capturedGeneration = OptionalU64::of(7U);
    hit.evidenceId = "ev-wfp-1";
    hit.connection.bootId = "boot-N";
    hit.connection.protocol = 6U;
    hit.connection.localAddress = "192.168.1.50";
    hit.connection.localPort = 52344U;
    hit.connection.remoteAddress = "93.184.216.34";
    hit.connection.remotePort = 443U;
    hit.connection.observedFirstUtc100ns = OptionalU64::of(133700000000000000ULL);
    hit.connection.observedLastUtc100ns = OptionalU64::of(133700000010000000ULL);
    return hit;
}

void testObservedEvents(ksword_tests::Suite& s) {
    const ConnectionDescription kConnection = makeConnection();
    WfpCatalog catalog = makeArbitrationCatalog(60000U, 100U);
    WfpFilter blocking = makeFilter(kFilter2, 102U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(blocking, 900U);
    blocking.conditions.push_back(remotePortEquals(443U));
    catalog.addFilter(blocking);
    markPartitionComplete(catalog, WfpPartition::kFilters, 1U);

    // Only static candidates, no runtime records.
    RuleExplanation staticOnly;
    staticOnly.candidates = analyzeStaticCandidates(catalog, kConnection);
    s.expect(staticOnly.candidates.overallDecision == CandidateDecision::kBlockCandidate,
             L"N-03 仅静态候选时也能给出阻断候选");
    s.expect(staticOnly.observations.empty(), L"N-04 仅静态候选时事件集合为空");
    s.expect(staticOnly.actualHitCount() == 0U, L"N-04 没有运行记录就没有实际命中");
    s.expect(!staticOnly.hasActualPath(), L"N-04 静态候选再确定也不生成实际经过路径");

    // A runtime record from an enabled and supported source.
    RuleExplanation withEvent = staticOnly;
    withEvent.observations.push_back(makeHit(ObservationSource::kWfpNetEventEnum, true, true));
    s.expect(classifyObservation(withEvent.observations[0]) == ObservationTrust::kActualObservation,
             L"N-04 已启用且受支持的来源才算实际观测");
    s.expect(withEvent.actualHitCount() == 1U, L"N-04 实际命中计数为 1");
    s.expect(withEvent.untrustedObservationCount() == 0U, L"N-04 没有不可信记录");
    s.expect(withEvent.hasActualPath(), L"N-04 有受支持来源的记录才存在实际经过路径");
    s.expect(describesActualVerdict(withEvent.observations[0]), L"N-04 该记录可以称实际阻断");
    s.expect(withEvent.observations[0].source == ObservationSource::kWfpNetEventEnum,
             L"N-04 事件保留自己的来源标识");
    s.expect(withEvent.candidates.overallDecision == CandidateDecision::kBlockCandidate,
             L"N-04 静态候选结论不因为来了运行记录而改变");

    // Unsupported / disabled / unknown source: the record is retained, but none count as an actual hit.
    const ObservedFilterHit kUnsupported = makeHit(ObservationSource::kEtwProvider, false, true);
    s.expect(classifyObservation(kUnsupported) == ObservationTrust::kSourceUnsupported,
             L"N-04 不受支持的来源被单独标记");
    s.expect(!describesActualVerdict(kUnsupported), L"N-04 不受支持来源的记录不能称实际阻断");

    const ObservedFilterHit kDisabled = makeHit(ObservationSource::kSecurityAuditLog, true, false);
    s.expect(classifyObservation(kDisabled) == ObservationTrust::kSourceNotEnabled,
             L"N-04 未启用的来源被单独标记");
    s.expect(!describesActualVerdict(kDisabled), L"N-04 未启用来源的记录不能称实际阻断");

    ObservedFilterHit unknownSource = makeHit(ObservationSource::kUnknown, true, true);
    s.expect(classifyObservation(unknownSource) == ObservationTrust::kSourceUnknown,
             L"N-04 来源未知时自称受支持也不算数");

    ObservedFilterHit noVerdict = makeHit(ObservationSource::kKernelAleCallout, true, true);
    noVerdict.verdict = WfpEventVerdict::kUnknown;
    s.expect(classifyObservation(noVerdict) == ObservationTrust::kActualObservation,
             L"N-04 来源可信但判定未知，来源分级仍是实际观测");
    s.expect(!describesActualVerdict(noVerdict), L"N-04 判定未知时不渲染成实际阻断/放行");

    RuleExplanation mixed;
    mixed.observations.push_back(kUnsupported);
    mixed.observations.push_back(kDisabled);
    mixed.observations.push_back(unknownSource);
    s.expect(mixed.observations.size() == 3U, L"N-04 不可信记录仍然保留而不是丢弃");
    s.expect(mixed.actualHitCount() == 0U, L"N-04 三条不可信记录都不算实际命中");
    s.expect(mixed.untrustedObservationCount() == 3U, L"N-04 不可信记录被单独计数");
    s.expect(!mixed.hasActualPath(), L"N-04 全是不可信来源时不存在实际经过路径");

    // Event linked to rule in catalog (N-04 requires showing filter reference)
    const FilterReferenceResolution kLink = linkObservationToCatalog(catalog, withEvent.observations[0]);
    s.expect(kLink.state == FilterLinkState::kLinkedByGuid, L"N-04 事件按 filter GUID 关联到规则");
    s.expect(kLink.hasIndex && catalog.filters()[kLink.filterIndex].filterKey.text == std::string(kFilter2),
             L"N-04 关联到的是同一条规则");
}

// ---------------------------------------------------------------------------
// N-04 / F-05: Must distinguish between 'event source not collected' and 'collection succeeded with zero events'.
//
// sourceSupported/sourceEnabled on ObservedFilterHit only exist when there is at least one record. They fail precisely
// in the scenario most needing explanation: collection failure (zero records). Without an independent collection
// ledger, the export can only write "actual hits: 0", which readers may misinterpret as "nothing was blocked".
// ---------------------------------------------------------------------------
void testObservationCollectionOutcomes(ksword_tests::Suite& s) {
    // (a) Never subscribed: no records exist, and no source accounts are present.
    RuleExplanation neverCollected;
    s.expect(neverCollected.observations.empty(), L"N-04 未采集时事件集合为空");
    s.expect(neverCollected.actualHitCount() == 0U, L"N-04 未采集时实际命中为 0");
    s.expect(!neverCollected.observationsCollected(),
             L"N-04 没有任何来源账目时不得声称「事件已采集」");
    s.expect(!neverCollected.hasActualPath(), L"N-04 未采集时没有实际经过路径");

    // (b) Subscription failure: the source is supported and enabled, but FwpmNetEventSubscribe returns an error
    RuleExplanation subscribeFailed;
    {
        ObservationSourceOutcome entry;
        entry.source = ObservationSource::kWfpNetEventSubscribe;
        entry.sourceSupported = true;
        entry.sourceEnabled = true;
        entry.outcome = CollectionOutcome::failure(CollectionStatus::kAccessDenied, "WIN32", 5ULL,
                                                   "FwpmNetEventSubscribe0 access denied");
        subscribeFailed.sourceOutcomes.push_back(entry);
    }
    s.expect(subscribeFailed.actualHitCount() == 0U, L"N-04 订阅失败时实际命中为 0");
    s.expect(!subscribeFailed.observationsCollected(),
             L"N-04 订阅失败不算「事件已采集」，零命中是采集问题");
    s.expect(subscribeFailed.anyObservationSourceFailed(), L"N-04 订阅失败被单独标出");
    s.expect(subscribeFailed.sourceOutcomes[0].outcome.nativeCode == OptionalU64::of(5ULL),
             L"N-04 采集失败保留原始 Win32 错误码 5");
    s.expect(subscribeFailed.sourceOutcomes[0].outcome.nativeCodeDomain == "WIN32",
             L"N-04 采集失败保留错误码域");
    s.expect(!subscribeFailed.sourceOutcomes[0].carriesObservation(),
             L"N-04 AccessDenied 的来源不携带观测");

    // (c) Collection normal, zero events confirmed.
    RuleExplanation collectedEmpty;
    {
        ObservationSourceOutcome entry;
        entry.source = ObservationSource::kWfpNetEventEnum;
        entry.sourceSupported = true;
        entry.sourceEnabled = true;
        entry.outcome = CollectionOutcome::success();
        entry.coverage.totalKnown = OptionalU64::of(0U);
        entry.coverage.succeeded = 0U;
        collectedEmpty.sourceOutcomes.push_back(entry);
    }
    s.expect(collectedEmpty.actualHitCount() == 0U, L"N-04 正确的空集合实际命中也是 0");
    s.expect(collectedEmpty.observationsCollected(),
             L"N-04 受支持且启用的来源跑完了，「零事件」才是真的零事件");
    s.expect(!collectedEmpty.anyObservationSourceFailed(), L"N-04 正常跑完的来源不算失败");
    s.expect(collectedEmpty.sourceOutcomes[0].carriesObservation(), L"N-04 Success 的来源携带观测");

    // The actualHitCount values for all three are identical — only the collection ledger can distinguish them.
    s.expect(neverCollected.actualHitCount() == collectedEmpty.actualHitCount() &&
                 subscribeFailed.actualHitCount() == collectedEmpty.actualHitCount(),
             L"N-04 三种情形的实际命中数都是 0，说明单看命中数分不出来");
    s.expect(neverCollected.observationsCollected() != collectedEmpty.observationsCollected(),
             L"N-04 「未采集」与「采集正常且零事件」在结构上可区分");
    s.expect(subscribeFailed.observationsCollected() != collectedEmpty.observationsCollected(),
             L"N-04 「采集失败」与「采集正常且零事件」在结构上可区分");
    s.expect(neverCollected.anyObservationSourceFailed() != subscribeFailed.anyObservationSourceFailed(),
             L"N-04 「从没订阅」与「订阅失败」在结构上可区分");

    // (d) Source supported but not enabled: Completing the scan does not count as 'observable'.
    RuleExplanation notEnabled;
    {
        ObservationSourceOutcome entry;
        entry.source = ObservationSource::kSecurityAuditLog;
        entry.sourceSupported = true;
        entry.sourceEnabled = false;  // Audit policy is disabled
        entry.outcome = CollectionOutcome::success();
        notEnabled.sourceOutcomes.push_back(entry);
    }
    s.expect(!notEnabled.observationsCollected(),
             L"N-04 来源没启用时「零事件」说明不了问题");
}

// ---------------------------------------------------------------------------
// N-04: Offline import must record the true source separately.
//
// OfflineImport only indicates "this record was read from a sample." When the original source is
// unknown, the supported/enabled booleans filled in the sample cannot elevate it to "actual block."
// ---------------------------------------------------------------------------
void testOfflineImportProvenance(ksword_tests::Suite& s) {
    ObservedFilterHit anonymous = makeHit(ObservationSource::kOfflineImport, true, true);
    s.expect(anonymous.originalSource == ObservationSource::kUnknown,
             L"N-04 离线记录默认没有原始来源");
    s.expect(classifyObservation(anonymous) == ObservationTrust::kSourceUnknown,
             L"N-04 原始来源不明的离线记录是「来源未知」，不是实际观测");
    s.expect(classifyObservation(anonymous) != ObservationTrust::kActualObservation,
             L"N-04 离线样本不能靠自填两个布尔把记录抬成实际观测");
    s.expect(!describesActualVerdict(anonymous), L"N-04 原始来源不明时不得渲染成实际阻断");

    ObservedFilterHit audited = makeHit(ObservationSource::kOfflineImport, true, true);
    audited.originalSource = ObservationSource::kSecurityAuditLog;
    audited.originalSourceDetail = text("Security 5157");
    s.expect(classifyObservation(audited) == ObservationTrust::kActualObservation,
             L"N-04 原始来源填了 5157 安全审计的离线记录才算实际观测");
    s.expect(describesActualVerdict(audited), L"N-04 有原始来源的离线记录可以称实际阻断");
    s.expect(audited.originalSource == ObservationSource::kSecurityAuditLog,
             L"N-04 原始来源被原样保留供来源栏显示");
    s.expect(audited.originalSourceDetail.present && audited.originalSourceDetail.value == "Security 5157",
             L"N-04 原始来源明细被原样保留");
    s.expect(std::string(observationSourceName(audited.originalSource)) == "SecurityAuditLog",
             L"N-04 原始来源有独立可显示的名称");

    // Self-referential offline sources are also invalid.
    ObservedFilterHit selfReferential = makeHit(ObservationSource::kOfflineImport, true, true);
    selfReferential.originalSource = ObservationSource::kOfflineImport;
    s.expect(classifyObservation(selfReferential) == ObservationTrust::kSourceUnknown,
             L"N-04 原始来源写成「离线导入」等于没写");

    // Non-offline sources are not affected by this criterion.
    s.expect(classifyObservation(makeHit(ObservationSource::kWfpNetEventEnum, true, true)) ==
                 ObservationTrust::kActualObservation,
             L"N-04 现场来源不需要填原始来源");

    // Navigation: offline records with unknown origins cannot be treated as 'actual traversed paths'.
    const WfpNavigationResult kBlocked = navigateObservationToTimeline(anonymous, true, true);
    s.expect(kBlocked.blockedByUntrustedSource, L"N-04 原始来源不明的离线记录被拦下");
    s.expect(kBlocked.rejection == WfpNavigationRejection::kSourceNotTrusted,
             L"N-04 拦下原因是「来源不可信」");
    s.expect(kBlocked.outcome != NavigationOutcome::kDelivered, L"N-04 拦下的记录不进时间线");
}

// ---------------------------------------------------------------------------
// N-05: Owner Attribution
// ---------------------------------------------------------------------------
void testOwnerAttribution(ksword_tests::Suite& s) {
    // Direct address evidence
    OwnerEvidence direct;
    direct.displayName = text("Windows Firewall");
    direct.moduleAddress = OptionalU64::of(0xFFFFF80512340000ULL);
    direct.moduleResolved = true;
    direct.resolvedModulePath = text("\\SystemRoot\\System32\\drivers\\mpsdrv.sys");
    const OwnerAttributionResult kDirectResult = deriveOwnerAttribution(direct);
    s.expect(kDirectResult.attribution == WfpOwnerAttribution::kDirectEvidence, L"N-05 模块地址落位是直接证据");
    s.expect(kDirectResult.ownerModulePath.present, L"N-05 直接证据才给出所有者模块路径");
    s.expect(kDirectResult.ownerModulePath.value == "\\SystemRoot\\System32\\drivers\\mpsdrv.sys",
             L"N-05 所有者模块路径与解析结果一致");
    s.expect(!kDirectResult.candidateModulePath.present, L"N-05 直接证据不需要候选路径");
    s.expect(!kDirectResult.signerCertificateAvailable, L"N-05 没读签名就不声称有签名");
    s.expect(!kDirectResult.signerSubject.present, L"N-05 没读签名就不给证书主体");

    // Module unloaded: address exists, but no image covers it.
    OwnerEvidence unloaded;
    unloaded.displayName = text("Some Callout");
    unloaded.moduleAddress = OptionalU64::of(0xFFFFF80599990000ULL);
    unloaded.moduleResolved = false;
    const OwnerAttributionResult kUnloadedResult = deriveOwnerAttribution(unloaded);
    s.expect(kUnloadedResult.attribution == WfpOwnerAttribution::kUnknown, L"N-05 模块卸载时归因是未知");
    s.expect(!kUnloadedResult.ownerModulePath.present, L"N-05 模块卸载时不指名文件");
    s.expect(hasLimitation(kUnloadedResult.limitationKeys, "wfp.owner.module-unresolved"),
             L"N-05 模块未解析写进限制说明");

    // Service configuration: candidate only
    OwnerEvidence service;
    service.displayName = text("Base Filtering Engine");
    service.serviceName = text("BFE");
    service.serviceRecordFound = true;
    service.serviceImagePath = text("%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork");
    const OwnerAttributionResult kServiceResult = deriveOwnerAttribution(service);
    s.expect(kServiceResult.attribution == WfpOwnerAttribution::kCandidate, L"N-05 服务配置只能给候选归因");
    s.expect(kServiceResult.candidateModulePath.present, L"N-05 候选归因给出候选路径");
    s.expect(!kServiceResult.ownerModulePath.present, L"N-05 候选归因不占用直接证据字段");
    s.expect(kServiceResult.serviceName.present && kServiceResult.serviceName.value == "BFE",
             L"N-05 服务名被保留");

    // Service not found
    OwnerEvidence missingService;
    missingService.displayName = text("Ghost Provider");
    missingService.serviceName = text("GhostSvc");
    missingService.serviceRecordFound = false;
    const OwnerAttributionResult kMissingServiceResult = deriveOwnerAttribution(missingService);
    s.expect(kMissingServiceResult.attribution == WfpOwnerAttribution::kUnknown, L"N-05 找不到服务时归因未知");
    s.expect(!kMissingServiceResult.candidateModulePath.present, L"N-05 找不到服务时不编造候选路径");
    s.expect(hasLimitation(kMissingServiceResult.limitationKeys, "wfp.owner.service-not-found"),
             L"N-05 服务未找到写进限制说明");

    // Display name only
    OwnerEvidence nameOnly;
    nameOnly.displayName = text("Microsoft Corporation");
    const OwnerAttributionResult kNameOnlyResult = deriveOwnerAttribution(nameOnly);
    s.expect(kNameOnlyResult.attribution == WfpOwnerAttribution::kUnknown, L"N-05 只有名称时归因未知");
    s.expect(!kNameOnlyResult.ownerModulePath.present, L"N-05 不凭名称猜驱动文件");
    s.expect(!kNameOnlyResult.candidateModulePath.present, L"N-05 不凭名称造候选文件");
    s.expect(hasLimitation(kNameOnlyResult.limitationKeys, "wfp.owner.name-only"),
             L"N-05 只有名称写进限制说明");

    // Nothing
    const OwnerAttributionResult kEmptyResult = deriveOwnerAttribution(OwnerEvidence{});
    s.expect(kEmptyResult.attribution == WfpOwnerAttribution::kUnknown, L"N-05 无证据时归因未知");
    s.expect(hasLimitation(kEmptyResult.limitationKeys, "wfp.owner.no-evidence"),
             L"N-05 无证据写进限制说明");

    // Signature information appears only when actually read.
    OwnerEvidence fabricated = direct;
    fabricated.signerCertificateRead = false;
    fabricated.signerSubject = text("Microsoft Windows");
    const OwnerAttributionResult kFabricatedResult = deriveOwnerAttribution(fabricated);
    s.expect(!kFabricatedResult.signerCertificateAvailable, L"N-05 未读取签名时不声称有证书");
    s.expect(!kFabricatedResult.signerSubject.present, L"N-05 未读取签名时证书主体保持未知");
    OwnerEvidence signed_ = direct;
    signed_.signerCertificateRead = true;
    signed_.signerSubject = text("CN=Microsoft Windows");
    const OwnerAttributionResult kSignedResult = deriveOwnerAttribution(signed_);
    s.expect(kSignedResult.signerCertificateAvailable, L"N-05 真读到签名时才标记可用");
    s.expect(kSignedResult.signerSubject.value == "CN=Microsoft Windows", L"N-05 证书主体原样保留");

    // Same-name component: The catalog side writes 'ambiguous name' into the evidence.
    WfpCatalog catalog;
    WfpCallout first;
    first.calloutKey = g(kCalloutX);
    first.displayName = text("Inspect");
    first.owner.displayName = text("Inspect");
    WfpCallout second;
    second.calloutKey = g("{77777777-7777-4777-8777-777777777777}");
    second.displayName = text("Inspect");
    second.owner.displayName = text("Inspect");
    catalog.addCallout(first);
    catalog.addCallout(second);
    markPartitionComplete(catalog, WfpPartition::kCallouts, 2U);
    s.expect(catalog.callouts().size() == 2U, L"N-01 同名 callout 不因名称相同而合并");
    const OwnerEvidence kAmbiguousEvidence = catalog.calloutOwnerEvidence(0U);
    s.expect(kAmbiguousEvidence.displayNameAmbiguous, L"N-05 同名组件被标记为名称歧义");
    const OwnerAttributionResult kAmbiguousResult = deriveOwnerAttribution(kAmbiguousEvidence);
    s.expect(kAmbiguousResult.attribution == WfpOwnerAttribution::kUnknown, L"N-05 同名组件不因名称获得归因");
    s.expect(hasLimitation(kAmbiguousResult.limitationKeys, "wfp.owner.ambiguous-display-name"),
             L"N-05 名称歧义写进限制说明");

    WfpCatalog unique;
    WfpCallout only;
    only.calloutKey = g(kCalloutX);
    only.displayName = text("Inspect");
    only.owner.displayName = text("Inspect");
    unique.addCallout(only);
    markPartitionComplete(unique, WfpPartition::kCallouts, 1U);
    s.expect(!unique.calloutOwnerEvidence(0U).displayNameAmbiguous, L"N-05 唯一名称不误报歧义");
}

// ---------------------------------------------------------------------------
// N-06: Dynamic changes, BFE unavailable, and old ID reuse
// ---------------------------------------------------------------------------
void testDynamicStateAndIdReuse(ksword_tests::Suite& s) {
    // BFE unavailable: do not generate any fake object rows; partition state explicitly fails.
    WfpCatalog broken;
    broken.setGeneration(3U);
    CollectionOutcome bfeDown = CollectionOutcome::failure(CollectionStatus::kError, "WIN32", 1753ULL,
                                                           "FwpmEngineOpen0 failed");
    broken.setPartitionState(WfpPartition::kProviders, bfeDown, CoverageAccount{});
    s.expect(broken.providers().empty(), L"N-06 BFE 打不开时不伪造 provider 行");
    s.expect(broken.partitionState(WfpPartition::kProviders).outcome.status == CollectionStatus::kError,
             L"N-06 BFE 失败落成分区状态");
    s.expect(broken.partitionState(WfpPartition::kProviders).outcome.nativeCode == OptionalU64::of(1753ULL),
             L"N-06 原始错误码被保留");
    s.expect(broken.partitionState(WfpPartition::kProviders).outcome.nativeCodeDomain == "WIN32",
             L"N-06 错误码域被保留");
    s.expect(!broken.partitionUsableForAbsence(WfpPartition::kProviders),
             L"N-06 失败的分区不能用来推断「这个对象不存在」");
    s.expect(broken.resolveProvider(g(kProviderA)).state == ReferenceState::kCatalogNotCollected,
             L"N-06 没采到时关联结果是「未采集」而不是「未知对象」");

    // Access denied and uncollected are distinct states; neither should be treated as '0 objects'.
    WfpCatalog denied;
    denied.setPartitionState(WfpPartition::kCallouts,
                             CollectionOutcome::failure(CollectionStatus::kAccessDenied, "WIN32", 5ULL,
                                                        "FwpmCalloutEnum0 access denied"),
                             CoverageAccount{});
    s.expect(denied.partitionState(WfpPartition::kCallouts).outcome.status == CollectionStatus::kAccessDenied,
             L"N-06 拒绝访问是独立状态");
    s.expect(!denied.partitionUsableForAbsence(WfpPartition::kCallouts), L"N-06 拒绝访问不能推断缺席");
    s.expect(denied.partitionState(WfpPartition::kFilters).outcome.status == CollectionStatus::kNotCollected,
             L"N-06 没设置过的分区默认是未采集");
    s.expect(!denied.partitionUsableForAbsence(WfpPartition::kFilters), L"N-06 未采集不能推断缺席");

    // Success but the account is completely empty — does not constitute full coverage.
    WfpCatalog blankAccount;
    blankAccount.setPartitionState(WfpPartition::kFilters, CollectionOutcome::success(), CoverageAccount{});
    s.expect(!blankAccount.partitionUsableForAbsence(WfpPartition::kFilters),
             L"N-06 账目空白时不算完整枚举（默认不等于完整）");
    WfpCatalog counted;
    CoverageAccount full;
    full.totalKnown = OptionalU64::of(2U);
    full.succeeded = 2U;
    counted.setPartitionState(WfpPartition::kFilters, CollectionOutcome::success(), full);
    s.expect(counted.partitionUsableForAbsence(WfpPartition::kFilters),
             L"N-06 有正面账目证据时才算完整枚举");
    CoverageAccount truncatedAccount = full;
    truncatedAccount.truncated = 1U;
    WfpCatalog truncatedCatalog;
    truncatedCatalog.setPartitionState(WfpPartition::kFilters, CollectionOutcome::success(), truncatedAccount);
    s.expect(!truncatedCatalog.partitionUsableForAbsence(WfpPartition::kFilters),
             L"N-06 有截断记录时不算完整枚举");

    // Runtime ID association.
    WfpCatalog current = makeArbitrationCatalog(60000U, 100U);
    current.setGeneration(7U);
    WfpFilter alive = makeFilter(kFilter1, 77U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(alive, 900U);
    current.addFilter(alive);
    markPartitionComplete(current, WfpPartition::kFilters, 1U);

    s.expect(current.captureWindow().bootId == "boot-N", L"N-06 目录保留采集时的启动周期");
    s.expect(current.captureWindow().startUtc100ns == OptionalU64::of(133700000000000000ULL),
             L"N-06 目录保留采集时间");
    s.expect(current.captureWindow().mode == CaptureMode::kSnapshot, L"N-06 目录保留采集方式");

    RuntimeFilterReference sameGen;
    sameGen.filterId = OptionalU64::of(77U);
    sameGen.capturedGeneration = OptionalU64::of(7U);
    sameGen.bootId = "boot-N";
    const FilterReferenceResolution kSameGenResult = resolveFilterReference(current, sameGen);
    s.expect(kSameGenResult.state == FilterLinkState::kLinkedByRuntimeIdSameGeneration,
             L"N-06 同一采集代次内可按运行时 id 关联");
    s.expect(kSameGenResult.hasIndex, L"N-06 同代次关联给出命中位置");

    // Generation numbers reset across boots: reject if generation is the same but bootId differs.
    RuntimeFilterReference otherBoot = sameGen;
    otherBoot.bootId = "boot-OTHER";
    const FilterReferenceResolution kOtherBootResult = resolveFilterReference(current, otherBoot);
    s.expect(kOtherBootResult.state == FilterLinkState::kRejectedStaleGeneration,
             L"N-06 代次相同但跨启动周期时拒绝关联");
    s.expect(!kOtherBootResult.hasIndex, L"N-06 跨启动时不给命中位置");
    s.expect(hasLimitation(kOtherBootResult.limitationKeys, "wfp.link.boot-mismatch"),
             L"N-06 跨启动写进限制说明");

    RuntimeFilterReference noBoot = sameGen;
    noBoot.bootId.clear();
    s.expect(resolveFilterReference(current, noBoot).state ==
                 FilterLinkState::kLinkedByRuntimeIdSameGeneration,
             L"N-06 拿不到 bootId 时只能靠代次判据，不额外收紧也不额外放宽");

    RuntimeFilterReference staleGen;
    staleGen.filterId = OptionalU64::of(77U);
    staleGen.capturedGeneration = OptionalU64::of(6U);
    const FilterReferenceResolution kStaleResult = resolveFilterReference(current, staleGen);
    s.expect(kStaleResult.state == FilterLinkState::kRejectedStaleGeneration,
             L"N-06 旧代次的运行时 id 不敢关联");
    s.expect(!kStaleResult.hasIndex, L"N-06 拒绝关联时不给命中位置");
    s.expect(hasLimitation(kStaleResult.limitationKeys, "wfp.link.stale-generation"),
             L"N-06 旧代次写进限制说明");

    RuntimeFilterReference unknownGen;
    unknownGen.filterId = OptionalU64::of(77U);
    const FilterReferenceResolution kUnknownGenResult = resolveFilterReference(current, unknownGen);
    s.expect(kUnknownGenResult.state == FilterLinkState::kRejectedStaleGeneration,
             L"N-06 代次未知的运行时 id 同样不敢关联");
    s.expect(hasLimitation(kUnknownGenResult.limitationKeys, "wfp.link.generation-unknown"),
             L"N-06 代次未知写进限制说明");

    // Old ID reused: reference carries old GUID, but directory has different rule for same ID.
    RuntimeFilterReference reused;
    reused.filterId = OptionalU64::of(77U);
    reused.filterKey = g(kFilter4);  // This GUID is not in the directory.
    reused.capturedGeneration = OptionalU64::of(6U);
    const FilterReferenceResolution kReusedResult = resolveFilterReference(current, reused);
    s.expect(kReusedResult.state == FilterLinkState::kRejectedIdReused, L"N-06 旧 id 被复用时明确拒绝关联");
    s.expect(!kReusedResult.hasIndex, L"N-06 id 复用时绝不误连到新规则");
    s.expect(hasLimitation(kReusedResult.limitationKeys, "wfp.link.id-reused"),
             L"N-06 id 复用写进限制说明");

    // GUID matches but runtime ID changed: keep linked, but report it.
    RuntimeFilterReference movedId;
    movedId.filterKey = g(kFilter1);
    movedId.filterId = OptionalU64::of(999U);
    movedId.capturedGeneration = OptionalU64::of(6U);
    const FilterReferenceResolution kMovedResult = resolveFilterReference(current, movedId);
    s.expect(kMovedResult.state == FilterLinkState::kLinkedByGuid, L"N-06 GUID 是稳定键，跨代次仍可关联");
    s.expect(hasLimitation(kMovedResult.limitationKeys, "wfp.link.runtime-id-changed"),
             L"N-06 运行时 id 变化写进限制说明");

    // The same filterId appears twice in the catalog.
    WfpCatalog ambiguousIds = makeArbitrationCatalog(60000U, 100U);
    ambiguousIds.setGeneration(7U);
    WfpFilter twinA = makeFilter(kFilter1, 55U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    WfpFilter twinB = makeFilter(kFilter2, 55U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
    ambiguousIds.addFilter(twinA);
    ambiguousIds.addFilter(twinB);
    markPartitionComplete(ambiguousIds, WfpPartition::kFilters, 2U);
    RuntimeFilterReference twinRef;
    twinRef.filterId = OptionalU64::of(55U);
    twinRef.capturedGeneration = OptionalU64::of(7U);
    s.expect(resolveFilterReference(ambiguousIds, twinRef).state == FilterLinkState::kRejectedAmbiguous,
             L"N-06 同一运行时 id 有多条时拒绝关联");

    // Nothing provided / Catalog not collected
    s.expect(resolveFilterReference(current, RuntimeFilterReference{}).state == FilterLinkState::kNotSpecified,
             L"N-06 引用什么都没带时状态是 NotSpecified");
    WfpCatalog uncollected;
    RuntimeFilterReference idOnly;
    idOnly.filterId = OptionalU64::of(77U);
    idOnly.capturedGeneration = OptionalU64::of(0U);
    s.expect(resolveFilterReference(uncollected, idOnly).state == FilterLinkState::kCatalogNotCollected,
             L"N-06 filter 分区未采集时无法关联");
    RuntimeFilterReference unknownGuid;
    unknownGuid.filterKey = g(kFilter4);
    s.expect(resolveFilterReference(current, unknownGuid).state == FilterLinkState::kNoMatch,
             L"N-06 GUID 不在完整目录里时是「没有这条」而不是「未采集」");

    // --- Additions, deletions, and modifications between generations ---
    WfpCatalog before = makeArbitrationCatalog(60000U, 100U);
    before.setGeneration(1U);
    WfpFilter keptBefore = makeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(keptBefore, 100U);
    keptBefore.conditions.push_back(remotePortEquals(443U));
    WfpFilter removed = makeFilter(kFilter2, 11U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
    setEffectiveWeight(removed, 200U);
    before.addFilter(keptBefore);
    before.addFilter(removed);
    markPartitionComplete(before, WfpPartition::kFilters, 2U);

    WfpCatalog after = makeArbitrationCatalog(60000U, 100U);
    after.setGeneration(2U);
    WfpFilter keptAfter = makeFilter(kFilter1, 10U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
    setEffectiveWeight(keptAfter, 300U);
    keptAfter.conditions.push_back(remotePortEquals(8080U));
    WfpFilter added = makeFilter(kFilter3, 12U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(added, 400U);
    WfpFilter reuser = makeFilter(kFilter4, 11U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    setEffectiveWeight(reuser, 500U);
    after.addFilter(keptAfter);
    after.addFilter(added);
    after.addFilter(reuser);
    markPartitionComplete(after, WfpPartition::kFilters, 3U);

    const CatalogDelta kDelta = diffCatalogs(before, after);
    s.expect(kDelta.comparable, L"N-06 两侧都完整枚举时才敢做增删对比");
    std::size_t addedCount = 0;
    std::size_t removedCount = 0;
    std::size_t actionChanged = 0;
    std::size_t weightChanged = 0;
    std::size_t conditionsChanged = 0;
    std::size_t idReused = 0;
    std::size_t presenceUnknown = 0;
    for (const CatalogChange& change : kDelta.changes) {
        switch (change.kind) {
        case CatalogChangeKind::kAdded: ++addedCount; break;
        case CatalogChangeKind::kRemoved: ++removedCount; break;
        case CatalogChangeKind::kActionChanged: ++actionChanged; break;
        case CatalogChangeKind::kWeightChanged: ++weightChanged; break;
        case CatalogChangeKind::kConditionsChanged: ++conditionsChanged; break;
        case CatalogChangeKind::kRuntimeIdReused: ++idReused; break;
        case CatalogChangeKind::kPresenceUnknown: ++presenceUnknown; break;
        }
    }
    s.expect(addedCount == 2U, L"N-06 新增两条规则被识别");
    s.expect(removedCount == 1U, L"N-06 删除一条规则被识别");
    s.expect(actionChanged == 1U, L"N-06 动作变化被识别");
    s.expect(weightChanged == 1U, L"N-06 权重变化被识别");
    s.expect(conditionsChanged == 1U, L"N-06 条件变化被识别");
    s.expect(idReused == 1U, L"N-06 运行时 id 复用被单独识别");
    s.expect(presenceUnknown == 0U, L"N-06 两侧完整时不产生「在场未知」");
    s.expect(!hasLimitation(kDelta.limitationKeys, "wfp.delta.boot-changed"),
             L"N-06 同一启动周期内不误报跨启动");

    // Cross-boot re-capture: ID reordering is inevitable and must not be mistaken for ID recycling within the same session.
    WfpCatalog rebooted = after;
    CaptureWindow newBoot = after.captureWindow();
    newBoot.bootId = "boot-N2";
    rebooted.setCaptureWindow(newBoot);
    const CatalogDelta kRebootDelta = diffCatalogs(before, rebooted);
    s.expect(hasLimitation(kRebootDelta.limitationKeys, "wfp.delta.boot-changed"),
             L"N-06 跨启动重采写进限制说明");
    bool rebootIdReuseFlagged = false;
    for (const CatalogChange& change : kRebootDelta.changes) {
        if (change.kind == CatalogChangeKind::kRuntimeIdReused) {
            rebootIdReuseFlagged = hasLimitation(change.limitationKeys, "wfp.delta.boot-changed");
        }
    }
    s.expect(rebootIdReuseFlagged, L"N-06 跨启动的 id 重排在该条变更上单独标注");

    // Incomplete enumeration on the new side: do not treat 'not seen' as 'deleted'.
    WfpCatalog partialAfter = makeArbitrationCatalog(60000U, 100U);
    partialAfter.setGeneration(2U);
    CoverageAccount partialAccount;
    partialAccount.totalKnown = OptionalU64::of(9U);
    partialAccount.succeeded = 1U;
    partialAccount.limitHit = true;
    partialAfter.setPartitionState(WfpPartition::kFilters,
                                   CollectionOutcome::failure(CollectionStatus::kPartial, "WIN32", 0ULL,
                                                              "enumeration limit"),
                                   partialAccount);
    const CatalogDelta kPartialDelta = diffCatalogs(before, partialAfter);
    s.expect(!kPartialDelta.comparable, L"N-06 一侧不完整时对比结论不可比");
    s.expect(hasLimitation(kPartialDelta.limitationKeys, "wfp.delta.after-incomplete"),
             L"N-06 不完整侧写进限制说明");
    bool anyRemoved = false;
    bool anyUnknown = false;
    for (const CatalogChange& change : kPartialDelta.changes) {
        if (change.kind == CatalogChangeKind::kRemoved) {
            anyRemoved = true;
        }
        if (change.kind == CatalogChangeKind::kPresenceUnknown) {
            anyUnknown = true;
        }
    }
    s.expect(!anyRemoved, L"N-06 枚举不完整时不产出「已删除」结论");
    s.expect(anyUnknown, L"N-06 枚举不完整时产出「在场未知」");
}

// ---------------------------------------------------------------------------
// N-01 / N-06: Two types of rows that distort GUID indices in a two-generation comparison.
//
// std::map::emplace silently discards the second row for duplicate GUIDs; rows without a GUID never enter the index.
// Both scenarios would cause the conclusion of 'no changes between generations' to obscure a rule that has vanished out of nowhere.
// ---------------------------------------------------------------------------
void testDeltaRejectsDistortedSnapshots(ksword_tests::Suite& s) {
    // (a) The 'before' side has the same GUID appearing twice (Block/10 and Permit/20), while 'after' has only Block/10.
    {
        WfpCatalog before = makeArbitrationCatalog(60000U, 100U);
        before.setGeneration(1U);
        WfpFilter first = makeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(first, 10U);
        WfpFilter second = makeFilter(kFilter1, 20U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        setEffectiveWeight(second, 20U);
        s.expect(before.addFilter(first), L"N-01 重复 GUID 的第一条 filter 正常入库");
        s.expect(!before.addFilter(second), L"N-01 重复 GUID 的第二条 filter 被标记为重复");
        markPartitionComplete(before, WfpPartition::kFilters, 2U);
        s.expect(before.resolveFilter(g(kFilter1)).state == ReferenceState::kAmbiguous,
                 L"N-01 目录自己已经认得这是歧义");

        WfpCatalog after = makeArbitrationCatalog(60000U, 100U);
        after.setGeneration(2U);
        WfpFilter survivor = makeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        setEffectiveWeight(survivor, 10U);
        after.addFilter(survivor);
        markPartitionComplete(after, WfpPartition::kFilters, 1U);

        const CatalogDelta kDelta = diffCatalogs(before, after);
        s.expect(!kDelta.comparable,
                 L"N-06 一侧快照自相矛盾时不敢宣称两代可比");
        s.expect(hasLimitation(kDelta.limitationKeys, "wfp.delta.duplicate-guid"),
                 L"N-06 重复 GUID 写进对比的限制说明");
        std::size_t presenceUnknown = 0;
        std::size_t others = 0;
        for (const CatalogChange& change : kDelta.changes) {
            if (change.kind == CatalogChangeKind::kPresenceUnknown) {
                ++presenceUnknown;
                s.expect(change.filterKey.text == std::string(kFilter1),
                         L"N-06 歧义条目的变更行带着出问题的那个 GUID");
                s.expect(hasLimitation(change.limitationKeys, "wfp.delta.duplicate-guid"),
                         L"N-06 歧义写进该条变更自己的限制说明");
            } else {
                ++others;
            }
        }
        s.expect(presenceUnknown == 1U, L"N-06 歧义 GUID 产出一条「在场未知」");
        s.expect(others == 0U,
                 L"N-06 对歧义 GUID 不产出任何增删改结论（那条 Permit/20 不许凭空消失）");
    }

    // (b) before has a rule with only a reusable runtime ID and no GUID; after has none
    {
        WfpCatalog before = makeArbitrationCatalog(60000U, 100U);
        before.setGeneration(1U);
        WfpFilter anonymous = makeFilter(kFilter1, 42U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
        anonymous.filterKey = WfpGuid{};  // GUID not captured
        setEffectiveWeight(anonymous, 900U);
        before.addFilter(anonymous);
        markPartitionComplete(before, WfpPartition::kFilters, 1U);

        WfpCatalog after = makeArbitrationCatalog(60000U, 100U);
        after.setGeneration(2U);
        markPartitionComplete(after, WfpPartition::kFilters, 0U);

        const CatalogDelta kDelta = diffCatalogs(before, after);
        s.expect(!kDelta.comparable, L"N-06 有无 GUID 的行时两代对比不可比");
        s.expect(hasLimitation(kDelta.limitationKeys, "wfp.delta.filter-without-guid"),
                 L"N-06 无 GUID 的行写进对比的限制说明");
        s.expect(kDelta.changes.size() == 1U, L"N-06 无 GUID 的行逐条产出变更行，不是只记一个全局键");
        if (!kDelta.changes.empty()) {
            s.expect(kDelta.changes[0].kind == CatalogChangeKind::kPresenceUnknown,
                     L"N-06 无 GUID 的行是「在场未知」");
            s.expect(kDelta.changes[0].beforeFilterId == OptionalU64::of(42U),
                     L"N-06 无 GUID 的行带上旧一侧的运行时 id 供追查");
            s.expect(!kDelta.changes[0].afterFilterId.present,
                     L"N-06 无 GUID 的行不编造新一侧的运行时 id");
            s.expect(!kDelta.changes[0].filterKey.known(), L"N-06 无 GUID 的行不编造 GUID");
            s.expect(hasLimitation(kDelta.changes[0].limitationKeys, "wfp.delta.filter-without-guid"),
                     L"N-06 无 GUID 写进该条变更自己的限制说明");
        }
    }

    // (c) The GUID-less rows on the 'after' side are also produced one by one.
    {
        WfpCatalog before = makeArbitrationCatalog(60000U, 100U);
        markPartitionComplete(before, WfpPartition::kFilters, 0U);
        WfpCatalog after = makeArbitrationCatalog(60000U, 100U);
        WfpFilter anonymous = makeFilter(kFilter1, 77U, kSubLayerHigh, kActionPermit, WfpActionType::kPermit);
        anonymous.filterKey = WfpGuid{};
        after.addFilter(anonymous);
        markPartitionComplete(after, WfpPartition::kFilters, 1U);

        const CatalogDelta kDelta = diffCatalogs(before, after);
        s.expect(kDelta.changes.size() == 1U, L"N-06 新一侧的无 GUID 行也产出一条变更");
        if (!kDelta.changes.empty()) {
            s.expect(kDelta.changes[0].afterFilterId == OptionalU64::of(77U),
                     L"N-06 新一侧无 GUID 行带上新一侧的运行时 id");
            s.expect(!kDelta.changes[0].beforeFilterId.present,
                     L"N-06 新一侧无 GUID 行不编造旧一侧的运行时 id");
        }
    }
}

// ---------------------------------------------------------------------------
// N-08: navigation
// ---------------------------------------------------------------------------
void testNavigation(ksword_tests::Suite& s) {
    WfpFilter withGuid = makeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    const ObjectRef kFilterRef = makeFilterRef(withGuid, "ev-1");
    s.expect(kFilterRef.navigable(), L"N-08 带 GUID 的规则可以导航");
    s.expect(kFilterRef.key == std::string("wfp-filter|") + kFilter1, L"N-08 规则键带前缀且基于 GUID");
    s.expect(kFilterRef.strength == IdentityStrength::kStrong, L"N-08 GUID 是稳定的跨会话键");

    WfpFilter idOnly = withGuid;
    idOnly.filterKey = WfpGuid{};
    const ObjectRef kIdOnlyRef = makeFilterRef(idOnly, "ev-1");
    s.expect(!kIdOnlyRef.navigable(), L"N-08 只有可复用运行时 id 的规则不可导航");
    s.expect(kIdOnlyRef.key.empty(), L"N-08 身份不足时不发主键");
    s.expect(kIdOnlyRef.strength == IdentityStrength::kUnusable, L"N-08 只有运行时 id 时身份不可用");

    const WfpNavigationResult kDelivered = navigateFilterToEvidence(withGuid, true, true, true, "ev-1");
    s.expect(kDelivered.outcome == NavigationOutcome::kDelivered, L"N-08 规则回看关联证据可以送达");
    s.expect(!kDelivered.refetchAttempted, L"N-08 导航层永远不重新发起查询");
    s.expect(kDelivered.request.page == NavigationPage::kNetwork, L"N-08 规则证据落在网络页");
    s.expect(kDelivered.request.evidenceId == "ev-1", L"N-08 导航请求带上证据 id");

    const WfpNavigationResult kUnusable = navigateFilterToEvidence(idOnly, true, true, true, "ev-1");
    s.expect(kUnusable.outcome == NavigationOutcome::kIdentityUnusable, L"N-08 身份不足时拒绝跳转");

    const WfpNavigationResult kNotSaved = navigateFilterToEvidence(withGuid, true, true, false, "ev-1");
    s.expect(kNotSaved.outcome == NavigationOutcome::kEvidenceNotSaved,
             L"N-08 离线会话没保存这段数据时明确显示未保存");
    s.expect(!kNotSaved.refetchAttempted, L"N-08 缺数据时不偷偷重新发起查询");

    const WfpNavigationResult kNoEvidenceId = navigateFilterToEvidence(withGuid, true, true, true, "");
    s.expect(kNoEvidenceId.outcome == NavigationOutcome::kEvidenceIdMissing, L"N-08 没带证据 id 的导航被拒绝");

    const WfpNavigationResult kPageGone = navigateFilterToEvidence(withGuid, false, true, true, "ev-1");
    s.expect(kPageGone.outcome == NavigationOutcome::kTargetPageMissing, L"N-08 目标页不在时说明原因");

    // Connection -> Process Instance
    ConnectionDescription connection = makeConnection();
    connection.identity.bootId = "boot-N";
    connection.identity.protocol = 6U;
    connection.identity.localAddress = "192.168.1.50";
    connection.identity.localPort = 52344U;
    connection.identity.remoteAddress = "93.184.216.34";
    connection.identity.remotePort = 443U;
    connection.identity.observedFirstUtc100ns = OptionalU64::of(133700000000000000ULL);
    connection.identity.owner.bootId = "boot-N";
    connection.identity.owner.pid = OptionalU64::of(4321U);
    connection.identity.owner.createTime100ns = OptionalU64::of(133699000000000000ULL);
    connection.identity.owner.imageName = "curl.exe";

    LiveResolution match;
    match.found = true;
    match.liveProcess = connection.identity.owner;
    const WfpNavigationResult kToProcess =
        navigateConnectionToProcess(connection, match, true, true, "ev-2");
    s.expect(kToProcess.identityRevalidated, L"N-08 跳现场前做过身份复核");
    s.expect(kToProcess.liveDecision == LiveNavigationDecision::kAllow, L"N-08 身份一致时允许跳转");
    s.expect(kToProcess.outcome == NavigationOutcome::kDelivered, L"N-08 身份一致的连接可以跳到进程实例");
    s.expect(kToProcess.request.page == NavigationPage::kProcess, L"N-08 跳转目标是进程页");

    LiveResolution reused;
    reused.found = true;
    reused.liveProcess = connection.identity.owner;
    reused.liveProcess.createTime100ns = OptionalU64::of(133799000000000000ULL);  // PID reused
    const WfpNavigationResult kReusedNav = navigateConnectionToProcess(connection, reused, true, true, "ev-2");
    s.expect(kReusedNav.liveDecision == LiveNavigationDecision::kRejectIdentityMismatch,
             L"N-08 PID 复用被识别为身份不匹配");
    s.expect(kReusedNav.outcome == NavigationOutcome::kObjectNotPresent, L"N-08 PID 复用时不把操作交给新进程");

    LiveResolution gone;
    gone.found = false;
    const WfpNavigationResult kGoneNav = navigateConnectionToProcess(connection, gone, true, true, "ev-2");
    s.expect(kGoneNav.liveDecision == LiveNavigationDecision::kRejectObjectExited, L"N-08 对象已退出被单独识别");
    s.expect(kGoneNav.outcome == NavigationOutcome::kObjectNotPresent, L"N-08 对象已退出时不跳转");

    ConnectionDescription weak = connection;
    weak.identity.owner.createTime100ns = OptionalU64::unset();
    LiveResolution weakLive;
    weakLive.found = true;
    weakLive.liveProcess = weak.identity.owner;
    const WfpNavigationResult kWeakNav = navigateConnectionToProcess(weak, weakLive, true, true, "ev-2");
    s.expect(kWeakNav.liveDecision == LiveNavigationDecision::kRejectIdentityUnverifiable,
             L"N-08 缺创建时间时身份无法确认");
    s.expect(kWeakNav.outcome == NavigationOutcome::kIdentityUnusable, L"N-08 身份无法确认时拒绝跳转");

    // Event execution -> Timeline
    const ObservedFilterHit kTrusted = makeHit(ObservationSource::kKernelAleCallout, true, true);
    const WfpNavigationResult kTimeline = navigateObservationToTimeline(kTrusted, true, true);
    s.expect(kTimeline.request.page == NavigationPage::kTimeline, L"N-08 事件跳转目标是时间线");
    s.expect(!kTimeline.blockedByUntrustedSource, L"N-08 受支持来源的事件不被拦下");
    s.expect(kTimeline.outcome == NavigationOutcome::kDelivered, L"N-08 受支持来源的事件可以进时间线");

    const ObservedFilterHit kUntrusted = makeHit(ObservationSource::kEtwProvider, false, true);
    const WfpNavigationResult kBlocked = navigateObservationToTimeline(kUntrusted, true, true);
    s.expect(kBlocked.blockedByUntrustedSource, L"N-04 来源不受支持的事件被标记拦下");
    s.expect(kBlocked.outcome != NavigationOutcome::kDelivered, L"N-04 不受支持来源不生成实际经过路径");
    s.expect(!kBlocked.refetchAttempted, L"N-08 被拦下时也不重新发起查询");

    const WfpNavigationResult kTimelineNotSaved = navigateObservationToTimeline(kTrusted, true, false);
    s.expect(kTimelineNotSaved.outcome == NavigationOutcome::kEvidenceNotSaved,
             L"N-08 离线缺事件数据时明确显示未保存");
}

// ---------------------------------------------------------------------------
// N-08: three rejection reasons must not collapse into one value
//
// The semantics of NavigationOutcome::ObjectNotPresent are "the page exists, but the object is not in the current data." Including
// "source untrusted" in this value and placing it before standard checks would cause requests without an evidence ID to go undetected.
// ---------------------------------------------------------------------------
void testNavigationRejectionReasonsStayDistinct(ksword_tests::Suite& s) {
    const ObservedFilterHit kTrusted = makeHit(ObservationSource::kKernelAleCallout, true, true);
    ObservedFilterHit untrusted = makeHit(ObservationSource::kEtwProvider, false, true);

    // (a) Trusted source + everything normal
    const WfpNavigationResult kOk = navigateObservationToTimeline(kTrusted, true, true);
    s.expect(kOk.outcome == NavigationOutcome::kDelivered, L"N-08 正常情况下事件送达时间线");
    s.expect(kOk.rejection == WfpNavigationRejection::kNone, L"N-08 送达时没有拒绝原因");
    s.expect(!kOk.blockedByUntrustedSource, L"N-08 可信来源不被拦下");

    // (b) Untrusted source, everything else normal -> Rejection reason: "Untrusted source"
    const WfpNavigationResult kUntrustedOnly = navigateObservationToTimeline(untrusted, true, true);
    s.expect(kUntrustedOnly.blockedByUntrustedSource, L"N-04 不受支持来源被拦下");
    s.expect(kUntrustedOnly.rejection == WfpNavigationRejection::kSourceNotTrusted,
             L"N-08 拒绝原因明确是「来源不可信」而不是「对象不在数据里」");
    s.expect(kUntrustedOnly.outcome != NavigationOutcome::kDelivered,
             L"N-04 不可信来源不生成实际经过路径");

    // (c) Trusted source but request lacks EvidenceId -> EvidenceIdMissing
    ObservedFilterHit trustedNoEvidence = kTrusted;
    trustedNoEvidence.evidenceId.clear();
    const WfpNavigationResult kNoEvidence = navigateObservationToTimeline(trustedNoEvidence, true, true);
    s.expect(kNoEvidence.outcome == NavigationOutcome::kEvidenceIdMissing,
             L"N-08 没带证据 id 的事件导航报 EvidenceIdMissing");
    s.expect(kNoEvidence.rejection == WfpNavigationRejection::kEvidenceIdMissing,
             L"N-08 拒绝原因是「没带证据 id」");
    s.expect(!kNoEvidence.blockedByUntrustedSource, L"N-08 可信来源不因为缺证据 id 被标成来源问题");

    // (d) Untrusted and missing evidence ID -> both reasons are detected.
    ObservedFilterHit untrustedNoEvidence = untrusted;
    untrustedNoEvidence.evidenceId.clear();
    const WfpNavigationResult kBoth = navigateObservationToTimeline(untrustedNoEvidence, true, true);
    s.expect(kBoth.outcome == NavigationOutcome::kEvidenceIdMissing,
             L"N-08 来源不可信不得把「没带证据 id」盖成「对象不在数据里」");
    s.expect(kBoth.rejection == WfpNavigationRejection::kSourceNotTrusted,
             L"N-08 来源不可信仍然作为拒绝原因单列");
    s.expect(kBoth.blockedByUntrustedSource, L"N-08 来源不可信仍然被标记");
    s.expect(kBoth.outcome != kUntrustedOnly.outcome,
             L"N-08 「不可信且没证据 id」与「只是不可信」在 outcome 上可区分");

    // (e) Untrusted source + offline unsaved data segment
    const WfpNavigationResult kNotSaved = navigateObservationToTimeline(untrusted, true, false);
    s.expect(kNotSaved.outcome == NavigationOutcome::kEvidenceNotSaved,
             L"N-08 来源不可信不得把「离线未保存」盖掉");
    s.expect(kNotSaved.rejection == WfpNavigationRejection::kSourceNotTrusted,
             L"N-08 离线未保存时来源不可信仍然作为拒绝原因单列");
    s.expect(!kNotSaved.refetchAttempted, L"N-08 被拦下时也不重新发起查询");

    // (f) TargetPageMissing is not overridden by source issues
    const WfpNavigationResult kPageGone = navigateObservationToTimeline(untrusted, false, true);
    s.expect(kPageGone.outcome == NavigationOutcome::kTargetPageMissing,
             L"N-08 来源不可信不得把「目标页不在」盖掉");

    // (g) The other two navigation paths also include rejection reasons.
    WfpFilter withGuid = makeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::kBlock);
    s.expect(navigateFilterToEvidence(withGuid, true, true, true, "ev-1").rejection ==
                 WfpNavigationRejection::kNone,
             L"N-08 规则回看送达时没有拒绝原因");
    WfpFilter idOnly = withGuid;
    idOnly.filterKey = WfpGuid{};
    s.expect(navigateFilterToEvidence(idOnly, true, true, true, "ev-1").rejection ==
                 WfpNavigationRejection::kIdentityUnusable,
             L"N-08 只有运行时 id 时拒绝原因是身份不可用");
    s.expect(navigateFilterToEvidence(withGuid, false, true, true, "ev-1").rejection ==
                 WfpNavigationRejection::kTargetPageMissing,
             L"N-08 目标页不在时拒绝原因是目标页缺失");
    s.expect(navigateFilterToEvidence(withGuid, true, true, false, "ev-1").rejection ==
                 WfpNavigationRejection::kEvidenceNotSaved,
             L"N-08 离线未保存时拒绝原因是证据未保存");
}

} // namespace

int runWfpTests() {
    ksword_tests::Suite suite(L"N wfp analysis");
    testObjectIdentityAndJoins(suite);
    testActionAndWeightDecoding(suite);
    testAddressParsing(suite);
    testConditionInterpretation(suite);
    testConditionCombination(suite);
    testUndecodedAddressNeverMatches(suite);
    testMalformedRangeStaysUnknown(suite);
    testLeadingZeroOctetsRejected(suite);
    testStaticArbitration(suite);
    testUnlinkedFiltersNeverArbitrateTogether(suite);
    testAbsenceRequiresCompleteCatalog(suite);
    testObservedEvents(suite);
    testObservationCollectionOutcomes(suite);
    testOfflineImportProvenance(suite);
    testOwnerAttribution(suite);
    testDynamicStateAndIdReuse(suite);
    testDeltaRejectsDistortedSnapshots(suite);
    testNavigation(suite);
    testNavigationRejectionReasonsStayDistinct(suite);
    suite.report();
    return suite.failures();
}

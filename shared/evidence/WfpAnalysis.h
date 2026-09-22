#pragma once

// N Module: WFP and network rule interpretation.
//
// This layer is a **pure interpretation layer**: it calls no Fwpm* APIs, contains no Qt/Win32 code, and only consumes objects and conditions passed from
// the adapter layer (or offline samples) to produce auditable interpretations. The enumeration itself is performed within the existing NetworkDock.
//
// Hard rule spanning the entire module:
//   * N-01: Localized display name is not a key. The only unique key is GUID; objects with the same name but different GUIDs are distinct and never merged.
//     Assign 'unknown object' status when no association is found; do not guess and do not leave raw GUIDs masquerading as resolved.
//   * N-02: Unrecognized conditions retain their original values and **never equal 'unconditional
//     match'**. Any unread condition forces the filter's match conclusion to InsufficientInfo.
//   * N-03: Arbitration is per-layer and per-sublayer (based on Microsoft Filter Arbitration, and)
//     zh-CN Knowledge Base [M4] Terminology consistency. It is strictly forbidden to pack all filters into a single global weight sort.
//     If the callout has dynamic determination, missing weight metadata, or unreadable conditions, the final decision defaults to Unknown.
//   * N-04: Static candidates and actual runtime events use two separate data structures. Only records from "enabled and
//     supported" sources can be considered actual hits/blocks; if no such records exist, no "actual path traversed" is generated.
//   * N-05: Display name, service configuration, and module address are three distinct evidence types.
//     Without a direct mapping, do not guess the driver file, and do not fabricate a signature certificate.
//   * N-06: If BFE is unavailable, access is denied, or data was not collected, it must be recorded as a partition state; never masquerade as an object row.
//     filterId and calloutId are reusable runtime IDs; if they cannot be linked across collection generations, the connection is considered unavailable.
//   * N-08: Reuses LiveNavigation's NavigationRequest/decideNavigation. This layer
//     never initiates any queries; offline missing data only reports EvidenceNotSaved.
//
// This layer does not produce judgment fields such as malicious, suspicious, or riskScore.

#include "EvidenceEnvelope.h"
#include "LiveNavigation.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// Generic utility
// ---------------------------------------------------------------------------

// Text representation of "Unknown / Known but potentially empty". An empty string and "unknown" are distinct concepts (AppId not collected ≠ AppId is empty).
struct OptionalText final {
    bool present = false;
    std::string value;

    static OptionalText unset() { return OptionalText{}; }
    static OptionalText of(std::string v) {
        OptionalText t;
        t.present = true;
        t.value = std::move(v);
        return t;
    }
};

// Limitation description key (i18n key, UI handles translation). For querying; avoids callers writing their own loops.
bool hasLimitation(const std::vector<std::string>& keys, std::string_view key) noexcept;

// ---------------------------------------------------------------------------
// N-01: GUID is the unique key.
// ---------------------------------------------------------------------------

// normalize GUID text: lowercase, enclosed in braces, format 8-4-4-4-12. An empty text indicates "unknown/not collected".
struct WfpGuid final {
    std::string text;

    bool known() const noexcept { return !text.empty(); }

    friend bool operator==(const WfpGuid& a, const WfpGuid& b) noexcept { return a.text == b.text; }
    friend bool operator!=(const WfpGuid& a, const WfpGuid& b) noexcept { return !(a == b); }
};

// Parse and normalize. Accepts input with or without braces, any case; fails on incorrect length, misplaced separators, or non-hexadecimal characters.
// Return false on failure without modifying out — partial parse results must never be used as keys.
bool parseGuid(std::string_view text, WfpGuid& out);

// Convenient construction for testing and offline samples: parsing failure returns an unknown GUID where known() == false.
// Callers that care whether "the input is a valid GUID" must use parseGuid, not rely on checking if the return value here is non-empty.
WfpGuid guidFromText(std::string_view text);

// ---------------------------------------------------------------------------
// N-02: Address, mask, and prefix
// ---------------------------------------------------------------------------
enum class WfpAddressFamily {
    kUnknown,
    kIPv4,
    kIPv6,
};

const char* wfpAddressFamilyName(WfpAddressFamily family) noexcept;

struct WfpAddress final {
    WfpAddressFamily family = WfpAddressFamily::kUnknown;
    std::array<std::uint8_t, 16> bytes{};  // Network byte order; IPv4 uses only bytes[0..3].

    bool known() const noexcept { return family != WfpAddressFamily::kUnknown; }

    // WFP IPv4 addresses are stored as host-order UINT32 in FWP_VALUE0; this explicitly converts them to network-order bytes.
    static WfpAddress ipv4FromHostOrder(std::uint32_t hostOrder) noexcept;
    static WfpAddress ipv6FromBytes(const std::array<std::uint8_t, 16>& raw) noexcept;

    friend bool operator==(const WfpAddress& a, const WfpAddress& b) noexcept;
    friend bool operator!=(const WfpAddress& a, const WfpAddress& b) noexcept { return !(a == b); }
};

// Text parsing (offline sample entry point). Supports dotted-decimal IPv4 and RFC 4291 IPv6 (including :: and embedded IPv4).
// Returns false on failure without modifying out.
//
// N-02 "Display consistent with input": Leading zeros in octets are strictly rejected to align with inet_pton. Historically, inet_addr parsed "010" as
// octal (8). If this layer were to loosely accept such input, "010.001.001.001" would be silently rewritten as "10.1.1.1". This creates a silent semantic
// rewrite where the same text string has different meanings across this layer, system interfaces, and other tools; this is not "fault tolerance".
bool parseIpAddress(std::string_view text, WfpAddress& out);

// Display text. IPv6 addresses are compressed per RFC 5952 (lowercase, longest zero segment collapsed to ::, leftmost chosen in case of ties).
// Return an empty string for unknown addresses — callers must not treat an empty string as "0.0.0.0".
std::string formatIpAddress(const WfpAddress& address);

bool ipv4HostOrder(const WfpAddress& address, std::uint32_t& out) noexcept;

// FWP_V4_ADDR_AND_MASK: mask is a **full 32-bit mask**, not a prefix length. Non-contiguous masks are valid
// input and must be preserved as-is, without silently converting to a prefix length (N-02 "Mask/Prefix").
struct WfpV4AddrMask final {
    WfpAddress address;
    std::uint32_t mask = 0;
};

// Only contiguous masks can be converted to prefix lengths; non-contiguous masks return false, allowing the caller to maintain the 'mask' terminology.
bool maskToPrefixLength(std::uint32_t mask, std::uint32_t& outPrefixLength) noexcept;

// FWP_V6_ADDR_AND_MASK: On the v6 side, this is prefixLength (0..128). Values >128 are considered invalid.
struct WfpV6AddrPrefix final {
    WfpAddress address;
    std::uint32_t prefixLength = 0;
    bool prefixLengthValid = false;
};

// N-02: Containment judgment must distinguish between 'definitely not inside' and 'input fundamentally unavailable'. Representing both
// as false in a bool, then having FWP_MATCH_NOT_EQUAL invert it to 'match', effectively derives a conclusion from an unreadable address.
// Criteria for determining 'unavailable': either address family is unknown (parseIpAddress failure leaves out unchanged by design, so
// v4Present/v6Present being true does not imply address resolution), address families on both sides differ, or the v6 prefix length is invalid.
enum class AddressContainment {
    kInside,
    kOutside,
    kUndecidable,
};

const char* addressContainmentName(AddressContainment containment) noexcept;

AddressContainment classifyV4Containment(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept;
AddressContainment classifyV6Containment(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept;

// Concise boolean form: **only** Inside is true. If the caller needs to distinguish Outside from
// Undecidable, they must use the above three-state version. Never invert false here to mean "match".
bool addressInV4Subnet(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept;
bool addressInV6Prefix(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept;

// ---------------------------------------------------------------------------
// N-02: FWP data type / comparison operation / direction
// ---------------------------------------------------------------------------

// Subset of FWP_DATA_TYPE. Unknown indicates "a type was encountered that we have not modeled"; the original value must be preserved.
enum class WfpDataType {
    kEmpty,
    kUint8,
    kUint16,
    kUint32,
    kUint64,
    kByteArray16,  // Single IPv6 address
    kByteBlob,     // AppId, etc.
    kSid,
    kV4AddrMask,
    kV6AddrMask,
    kRange,
    kUnknown,
};

const char* wfpDataTypeName(WfpDataType type) noexcept;

// Maps FWP_DATA_TYPE numeric values to enums. Unmodeled values return Unknown (the original value is retained by the caller in rawTypeCode).
WfpDataType decodeDataType(std::uint32_t rawTypeCode) noexcept;

// FWP_MATCH_TYPE. Unknown represents an incomprehensible comparison operation—it is never Equal.
enum class WfpMatchType {
    kEqual,
    kGreater,
    kLess,
    kGreaterOrEqual,
    kLessOrEqual,
    kRange,
    kFlagsAllSet,
    kFlagsAnySet,
    kFlagsNoneSet,
    kEqualCaseInsensitive,
    kNotEqual,
    kPrefix,
    kNotPrefix,
    kUnknown,
};

const char* wfpMatchTypeName(WfpMatchType match) noexcept;
WfpMatchType decodeMatchType(std::uint32_t rawMatchCode) noexcept;

// FWP_DIRECTION_ only defines OUTBOUND=0 and INBOUND=1. All other values are treated as Unknown; do not
// arbitrarily interpret 2 as FORWARD (that is a forwarding-layer semantic not present in FWP_DIRECTION_).
enum class WfpDirection {
    kUnknown,
    kOutbound,
    kInbound,
    kForward,  // For marking forwarded traffic only on the connection description side; condition parsing does not produce this value.
};

const char* wfpDirectionName(WfpDirection direction) noexcept;
WfpDirection decodeDirectionValue(std::uint64_t rawValue) noexcept;

// FWP_ACTION_TYPE. Unknown does not mean 'allow'.
enum class WfpActionType {
    kUnknown,
    kBlock,
    kPermit,
    kCalloutTerminating,
    kCalloutInspection,
    kCalloutUnknown,
    kContinue,
    kNone,
    kNoneNoMatch,
};

const char* wfpActionTypeName(WfpActionType action) noexcept;
WfpActionType decodeActionType(std::uint32_t rawActionCode) noexcept;

// Callout-type actions mean the final decision is made by the driver at runtime; static analysis must preserve Unknown.
bool actionIsCallout(WfpActionType action) noexcept;

// ---------------------------------------------------------------------------
// N-02: Condition fields
// ---------------------------------------------------------------------------
enum class WfpFieldKind {
    kUnknown,
    kIpLocalAddress,
    kIpRemoteAddress,
    kIpLocalPort,
    kIpRemotePort,
    kIpProtocol,
    kDirection,
    kAleAppId,
    kAleUserId,
    kIpLocalAddressType,
    kFlags,
};

const char* wfpFieldKindName(WfpFieldKind kind) noexcept;

// Built-in field table. GUIDs are from FWPM_CONDITION_* symbols in Windows SDK fwpmu.h.
// Note: The SDK contains several FWPM_CONDITION_* symbols sharing the same GUID (e.g., the RESERVED* series,
// ALE_PACKAGE_ID, and MAC_REMOTE_ADDRESS_TYPE), so the GUID-to-name mapping is not globally one-to-one.
// This table only includes **non-conflicting** common keys; all others fall through to the Unknown branch to preserve the original GUID.
struct WfpFieldDescriptor final {
    WfpFieldKind kind = WfpFieldKind::kUnknown;
    const char* name = "";  // FWPM_CONDITION_* symbol name
};

// Unregistered GUIDs return kind==Unknown and an empty name string.
WfpFieldDescriptor lookupFieldByGuid(const WfpGuid& fieldKey) noexcept;

// Reverse lookup: given field semantics, retrieve its condition GUID (for offline sample construction). Returns unknown GUID if not recorded.
WfpGuid fieldGuidFor(WfpFieldKind kind);

// ---------------------------------------------------------------------------
// N-02: Condition value and condition.
// ---------------------------------------------------------------------------
struct WfpRangeValue final {
    WfpDataType elementType = WfpDataType::kUnknown;
    bool numeric = false;  // Only numeric endpoints are comparable.
    OptionalU64 low;
    OptionalU64 high;
    std::string rawLow;   // Non-numeric endpoints preserved as-is.
    std::string rawHigh;
};

struct WfpConditionValue final {
    WfpDataType type = WfpDataType::kEmpty;
    std::uint32_t rawTypeCode = 0;  // FWP_DATA_TYPE original value, always preserved.

    OptionalU64 numeric;  // Uint8/16/32/64
    WfpV4AddrMask v4;
    bool v4Present = false;
    WfpV6AddrPrefix v6;
    bool v6Present = false;
    WfpAddress singleAddress;  // ByteArray16
    WfpRangeValue range;
    OptionalText blobText;                 // NT device path for AppId (when resolvable).
    std::vector<std::uint8_t> blobBytes;   // Raw bytes, always preserved.
    OptionalText sidText;                  // S-1-5-... text
    std::string rawText;                   // Any raw representation of unmodeled types must never be lost.
};

struct WfpCondition final {
    WfpGuid fieldKey;                // Raw condition GUID.
    WfpFieldKind field = WfpFieldKind::kUnknown;
    std::string fieldName;           // Resolved FWPM_CONDITION_* name; empty if unknown
    WfpMatchType match = WfpMatchType::kUnknown;
    std::uint32_t rawMatchCode = 0;  // FWP_MATCH_TYPE original value, always preserved
    WfpConditionValue value;

    // Whether this layer understood the field name, comparison operator, and value type of this condition.
    bool interpreted() const noexcept;

    // Can it be used to evaluate a connection description? If interpreted() is true but this layer does
    // not model the field semantics (e.g., FLAGS / IP_LOCAL_ADDRESS_TYPE), then evaluable() is false.
    bool evaluable() const noexcept;
};

// Constructing conditions from raw values: field names and comparison operators are resolved via the built-in table; if unresolved, the original value is retained and marked Unknown.
WfpCondition makeCondition(const WfpGuid& fieldKey, std::uint32_t rawMatchCode, WfpConditionValue value);

// ---------------------------------------------------------------------------
// N-05: Owner Attribution
// ---------------------------------------------------------------------------
enum class WfpOwnerAttribution {
    kUnknown,        // No evidence available to locate the binary.
    kCandidate,      // Only indirect evidence like service configuration that indicates "who should be loaded."
    kDirectEvidence, // The module address falls within the range of a loaded image, allowing direct identification of the file.
};

const char* wfpOwnerAttributionName(WfpOwnerAttribution attribution) noexcept;

// Three mutually non-substitutable evidence types. Names are names only.
struct OwnerEvidence final {
    OptionalText displayName;
    bool displayNameAmbiguous = false;  // There is more than one object with the same name but different GUIDs in the directory.

    OptionalText serviceName;      // Object-reported service name
    bool serviceRecordFound = false;
    OptionalText serviceImagePath;  // Only meaningful when serviceRecordFound is true.

    OptionalU64 moduleAddress;   // Actual addresses for fields like classifyFn, notifyFn, and ownerImageBase.
    bool moduleResolved = false; // The address falls within a loaded image range.
    OptionalText resolvedModulePath;

    bool signerCertificateRead = false;  // Only set if signature information was actually read.
    OptionalText signerSubject;
};

struct OwnerAttributionResult final {
    WfpOwnerAttribution attribution = WfpOwnerAttribution::kUnknown;
    OptionalText ownerModulePath;      // Invariant: Only DirectEvidence is allowed to be present.
    OptionalText candidateModulePath;  // "Who it should be" from service configuration is stored separately from direct evidence.
    OptionalText serviceName;
    bool signerCertificateAvailable = false;
    OptionalText signerSubject;        // Invariant: must be unset when available is false.
    std::vector<std::string> limitationKeys;
};

OwnerAttributionResult deriveOwnerAttribution(const OwnerEvidence& evidence);

// ---------------------------------------------------------------------------
// N-01: Object model
// ---------------------------------------------------------------------------

// filter->weight is FWP_VALUE0: FWP_EMPTY indicates "auto-weight", while FWP_UINT64 indicates an explicit weight.
// Displaying weight.type as weight is incorrect (the old NetworkAuditPage implementation had this bug).
enum class WfpWeightKind {
    kUnknown,   // Not collected
    kAuto,      // FWP_EMPTY: Automatically allocated by BFE
    kExplicit,  // FWP_UINT64: Caller explicitly specifies.
};

const char* wfpWeightKindName(WfpWeightKind kind) noexcept;

struct WfpProvider final {
    WfpGuid providerKey;
    OptionalText displayName;
    OptionalText description;
    bool persistent = false;
    OwnerEvidence owner;
};

struct WfpSubLayer final {
    WfpGuid subLayerKey;
    OptionalText displayName;
    WfpGuid providerKey;
    OptionalU64 weight;  // FWPM_SUBLAYER0::weight is a UINT16.
};

struct WfpLayer final {
    WfpGuid layerKey;
    OptionalText displayName;
    OptionalU64 layerId;  // Runtime ID, reusable.
    WfpGuid defaultSubLayerKey;
};

struct WfpCallout final {
    WfpGuid calloutKey;
    OptionalText displayName;
    WfpGuid providerKey;
    WfpGuid applicableLayerKey;
    OptionalU64 calloutId;  // Runtime ID, reusable.
    bool registered = false;  // Entry in directory does not mean the driver callback is registered.
    OwnerEvidence owner;
};

struct WfpFilter final {
    WfpGuid filterKey;
    OptionalU64 filterId;  // Runtime ID, reusable.
    OptionalText displayName;
    WfpGuid providerKey;
    WfpGuid layerKey;
    WfpGuid subLayerKey;

    WfpWeightKind weightKind = WfpWeightKind::kUnknown;
    OptionalU64 weight;           // Valid only when Explicit.
    OptionalU64 effectiveWeight;  // Effective weight calculated by BFE

    WfpActionType action = WfpActionType::kUnknown;
    std::uint32_t rawActionCode = 0;
    WfpGuid actionCalloutKey;  // When action is a callout class, this points to the callout.

    std::vector<WfpCondition> conditions;
    // N-02/N-06: When conditions are truncated, the remaining conditions are unknown; never treat this as 'no more conditions'.
    bool conditionsTruncated = false;
};

// ---------------------------------------------------------------------------
// N-01 / N-06: Directory, partition status, and association.
// ---------------------------------------------------------------------------
enum class WfpPartition {
    kProviders,
    kSubLayers,
    kLayers,
    kFilters,
    kCallouts,
};

const char* wfpPartitionName(WfpPartition partition) noexcept;
inline constexpr std::size_t kWfpPartitionCount = 5;

struct WfpPartitionState final {
    CollectionOutcome outcome;  // Default is NotCollected — "not collected" is the initial state.
    CoverageAccount coverage;
};

enum class ReferenceState {
    kResolved,            // Unique hit in directory
    kUnknownObject,       // GUID has a value and the directory is accessible, but it is empty — display "Unknown Object" without guessing.
    kAmbiguous,           // Same GUID appears multiple times in the directory (snapshot inconsistency).
    kNotSpecified,        // The referenced field itself was not collected or is empty.
    kCatalogNotCollected, // This object was never collected, so association cannot be determined (N-06).
    // N-06: Data was collected but incompletely (Partial / insufficient to prove completeness). In this case, "not in the catalog"
    // is neither "unknown object" (which requires the catalog to positively prove absence) nor "not collected at all"; it must be
    // a distinct category. Otherwise, a 1/9 enumeration and a 2000/2000 complete enumeration would yield the same label.
    kCatalogIncomplete,
};

const char* referenceStateName(ReferenceState state) noexcept;

struct ObjectReference final {
    ReferenceState state = ReferenceState::kNotSpecified;
    WfpGuid key;
    OptionalText resolvedName;  // Invariant: Only Resolved instances are allowed to be present.

    bool resolved() const noexcept { return state == ReferenceState::kResolved; }
};

// Catalog. The only unique key is the GUID: entries with the same name but different GUIDs are necessarily distinct.
class WfpCatalog final {
public:
    void setGeneration(std::uint64_t generation) noexcept { generation_ = generation; }
    std::uint64_t generation() const noexcept { return generation_; }

    void setCaptureWindow(CaptureWindow window) { window_ = std::move(window); }
    const CaptureWindow& captureWindow() const noexcept { return window_; }

    void setPartitionState(WfpPartition partition, CollectionOutcome outcome, CoverageAccount coverage);
    const WfpPartitionState& partitionState(WfpPartition partition) const noexcept;

    // N-06: Only allow treating 'absent in directory' as 'truly non-existent' when 'success + positive account proof is complete'.
    bool partitionUsableForAbsence(WfpPartition partition) const noexcept;

    // Return false if the GUID already exists (duplicate row). The object is still registered, causing subsequent resolve
    // to report Ambiguous. Silently dropping duplicate rows would hide the fact that the snapshot is inconsistent.
    bool addProvider(WfpProvider provider);
    bool addSubLayer(WfpSubLayer subLayer);
    bool addLayer(WfpLayer layer);
    bool addCallout(WfpCallout callout);
    bool addFilter(WfpFilter filter);

    const std::vector<WfpProvider>& providers() const noexcept { return providers_; }
    const std::vector<WfpSubLayer>& subLayers() const noexcept { return subLayers_; }
    const std::vector<WfpLayer>& layers() const noexcept { return layers_; }
    const std::vector<WfpCallout>& callouts() const noexcept { return callouts_; }
    const std::vector<WfpFilter>& filters() const noexcept { return filters_; }

    ObjectReference resolveProvider(const WfpGuid& key) const;
    ObjectReference resolveSubLayer(const WfpGuid& key) const;
    ObjectReference resolveLayer(const WfpGuid& key) const;
    ObjectReference resolveCallout(const WfpGuid& key) const;
    ObjectReference resolveFilter(const WfpGuid& key) const;

    // N-01: Name queries return **all** objects with the matching name. Callers use this to
    // determine "this name is ambiguous" rather than using the name as a key for a join.
    std::vector<WfpGuid> findProvidersByDisplayName(std::string_view name) const;
    std::vector<WfpGuid> findCalloutsByDisplayName(std::string_view name) const;

    // Reverse lookup by runtime ID (IDs may be reused; cross-generation verification is required).
    std::vector<std::size_t> findFilterIndexesByRuntimeId(const OptionalU64& filterId) const;

    // For N-05 use: Record 'number of objects with the same name in the directory > 1' into the evidence.
    OwnerEvidence providerOwnerEvidence(std::size_t providerIndex) const;
    OwnerEvidence calloutOwnerEvidence(std::size_t calloutIndex) const;

private:
    struct Index final {
        std::map<std::string, std::size_t> byGuid;
        std::map<std::string, bool> duplicated;
    };

    // Table lookup result: state + hit position. Names are retrieved by respective resolveXxx
    // functions from their own containers to avoid pointer arithmetic on different types here.
    struct IndexHit final {
        ReferenceState state = ReferenceState::kNotSpecified;
        bool hasPosition = false;
        std::size_t position = 0;
    };

    static bool registerKey(Index& index, const WfpGuid& key, std::size_t position);
    // On miss, the criterion unifies to partitionUsableForAbsence(): only partitions that can
    // positively prove enumeration completeness allow rendering 'not in directory' as UnknownObject.
    IndexHit lookup(const Index& index, const WfpGuid& key, WfpPartition partition) const;

    std::uint64_t generation_ = 0;
    CaptureWindow window_;
    std::array<WfpPartitionState, kWfpPartitionCount> partitions_{};

    std::vector<WfpProvider> providers_;
    std::vector<WfpSubLayer> subLayers_;
    std::vector<WfpLayer> layers_;
    std::vector<WfpCallout> callouts_;
    std::vector<WfpFilter> filters_;

    Index providerIndex_;
    Index subLayerIndex_;
    Index layerIndex_;
    Index calloutIndex_;
    Index filterIndex_;
};

// ---------------------------------------------------------------------------
// N-03: Connection description with three-state matching.
// ---------------------------------------------------------------------------
struct ConnectionDescription final {
    WfpAddress localAddress;
    WfpAddress remoteAddress;
    OptionalU64 localPort;
    OptionalU64 remotePort;
    OptionalU64 protocol;  // IPPROTO_*
    WfpDirection direction = WfpDirection::kUnknown;
    OptionalText appId;   // Normalized NT device path
    OptionalText userSid;
    ConnectionIdentity identity;  // Reuse F-03 identity for N-08 navigation
};

enum class ConditionMatch {
    kMatch,
    kNoMatch,
    kInsufficientInfo,
};

const char* conditionMatchName(ConditionMatch match) noexcept;

struct ConditionEvaluation final {
    WfpCondition condition;
    ConditionMatch result = ConditionMatch::kInsufficientInfo;
    std::vector<std::string> limitationKeys;
};

ConditionEvaluation evaluateCondition(const WfpCondition& condition, const ConnectionDescription& connection);

// All conditions for a filter: OR within the same field, AND across fields (the true FWP semantics), with three-valued logic
// merged per Kleene rules. Empty conditions mean a true "unconditional" match; truncated conditions mean InsufficientInfo.
ConditionMatch combineConditionResults(const std::vector<ConditionEvaluation>& evaluations,
                                       bool conditionsTruncated);

// ---------------------------------------------------------------------------
// N-03: Arbitration and candidates
// ---------------------------------------------------------------------------

// Sort order. effectiveWeight and explicit weight are different dimensions; mixing them for sorting is meaningless.
enum class WeightOrderConfidence {
    kUnknown,          // No comparable weight
    kExplicitWeight,   // Only the weight specified by the caller.
    kEffectiveWeight,  // Effective weight calculated by BFE
};

const char* weightOrderConfidenceName(WeightOrderConfidence confidence) noexcept;

enum class CandidateDecision {
    kUnknown,           // Insufficient data, dynamic decisions, untrusted order, or unproven absence; do not guess.
    // No filter matches within this scope. Layer default actions are outside this model.
    // N-03 Hard Constraint: This is an **absent assertion**, allowed to produce output only if the filter partition positively proves enumeration
    // completeness. If BFE is inaccessible, partitions are not collected, or enumeration only reaches 1/9, the result is Unknown. Otherwise, a
    // complete failure of enumeration would be indistinguishable from 'no rules matched after a complete enumeration of 2000 entries'.
    kNoMatchingFilter,
    kBlockCandidate,
    kPermitCandidate,
};

const char* candidateDecisionName(CandidateDecision decision) noexcept;

struct FilterCandidate final {
    WfpGuid filterKey;
    OptionalU64 filterId;
    OptionalText displayName;
    ObjectReference provider;
    ObjectReference layer;
    ObjectReference subLayer;
    ObjectReference actionCallout;

    WfpActionType action = WfpActionType::kUnknown;
    bool dynamicByCallout = false;

    WeightOrderConfidence weightConfidence = WeightOrderConfidence::kUnknown;
    OptionalU64 orderingWeight;

    ConditionMatch match = ConditionMatch::kInsufficientInfo;
    std::vector<ConditionEvaluation> conditions;
    std::vector<std::string> limitationKeys;
};

struct SubLayerCandidateGroup final {
    ObjectReference subLayer;
    OptionalU64 subLayerWeight;
    std::vector<FilterCandidate> filters;  // When sortable, order by arbitration sequence (descending weight).
    bool orderingReliable = false;         // All filters share the same dimension, have values, and are mutually unequal.
    CandidateDecision decision = CandidateDecision::kUnknown;
    // N-01: Each unlinked reference to a filter that was not collected occupies its own group exclusively and does not
    // arbitrate with any other filter (including other filters with missing references). When the true scope is unknown, two
    // rules are very likely not even in the same arbitration scope, so conclusions like "900 overrides 100" are baseless.
    bool unlinkedReference = false;
    std::vector<std::string> limitationKeys;
};

struct LayerCandidateGroup final {
    ObjectReference layer;
    std::vector<SubLayerCandidateGroup> subLayers;  // In descending order of sublayer weight.
    bool subLayerOrderingReliable = false;
    CandidateDecision decision = CandidateDecision::kUnknown;
    bool unlinkedReference = false;  // See SubLayerCandidateGroup::unlinkedReference
    std::vector<std::string> limitationKeys;
};

struct StaticCandidateReport final {
    std::vector<LayerCandidateGroup> layers;
    // Conservative cross-layer aggregation: if any layer is Unknown, the result is Unknown. This is **not** a determination of the actual packet path.
    CandidateDecision overallDecision = CandidateDecision::kUnknown;
    std::size_t evaluatedFilterCount = 0;
    // N-06: Whether the filter partition can positively prove enumeration completeness. If false, all "no matching rules"
    // in this report are downgraded to Unknown, and each group is tagged with wfp.candidate.filter-catalog-incomplete.
    bool catalogUsableForAbsence = false;
    std::vector<std::string> limitationKeys;
};

FilterCandidate evaluateFilter(const WfpCatalog& catalog,
                               const WfpFilter& filter,
                               const ConnectionDescription& connection);

StaticCandidateReport analyzeStaticCandidates(const WfpCatalog& catalog,
                                              const ConnectionDescription& connection);

// ---------------------------------------------------------------------------
// N-04: Actual runtime event.
// ---------------------------------------------------------------------------
enum class ObservationSource {
    kUnknown,
    kWfpNetEventEnum,       // FwpmNetEventEnum*
    kWfpNetEventSubscribe,  // FwpmNetEventSubscribe*
    kKernelAleCallout,      // ALE stream authorization event ring for this tool driver.
    kEtwProvider,
    kSecurityAuditLog,      // For example, 5152/5157.
    // Imported from an offline sample. This identifies only the import path, not the original evidence
    // source, which must be recorded in ObservedFilterHit::originalSource. Offline records without an
    // original source are untrusted. N-04 requires the source column to distinguish 5157 security
    // auditing, FwpmNetEventEnum, and this tool's driver; merely showing offline import is insufficient.
    kOfflineImport,
};

const char* observationSourceName(ObservationSource source) noexcept;

enum class WfpEventVerdict {
    kUnknown,
    kPermitted,
    kBlocked,
};

const char* wfpEventVerdictName(WfpEventVerdict verdict) noexcept;

struct ObservedFilterHit final {
    ObservationSource source = ObservationSource::kUnknown;
    // When source == OfflineImport, the actual source recorded separately in the sample. Must be filled; leaving it as Unknown means the
    // evidence source for this record is unknown, causing classifyObservation to classify it as SourceUnknown instead of the actual observation.
    // These two fields are meaningless for non-OfflineImport records; keep them at default.
    ObservationSource originalSource = ObservationSource::kUnknown;
    OptionalText originalSourceDetail;  // For example, "Security 5157" / "FwpmNetEventEnum0"
    bool sourceSupported = false;  // This source is supported on the current system
    bool sourceEnabled = false;    // This source was indeed enabled during collection.
    OptionalU64 filterId;          // Runtime ID
    WfpGuid filterKey;
    OptionalU64 layerId;
    OptionalU64 eventUtc100ns;
    WfpEventVerdict verdict = WfpEventVerdict::kUnknown;
    ConnectionIdentity connection;
    std::string rawRecordId;
    OptionalU64 capturedGeneration;  // Collection generation of the record's directory.
    std::string evidenceId;
};

enum class ObservationTrust {
    kActualObservation,  // Enabled and supported — only this level can be called 'actual hit/block'.
    kSourceUnknown,
    kSourceUnsupported,
    kSourceNotEnabled,
};

const char* observationTrustName(ObservationTrust trust) noexcept;

ObservationTrust classifyObservation(const ObservedFilterHit& hit) noexcept;

// N-04: Only records with ActualObservation are allowed to render the verdict as "actual block/allow".
bool describesActualVerdict(const ObservedFilterHit& hit) noexcept;

// N-04 / F-05: Event channel collection status. "ETW subscription failed / FwpmNetEventEnum returned an error / no subscription
// at all" must be structurally distinct from "source supported and enabled, ran normally, and indeed produced zero events".
// Without this distinction, exports can only state "actual hits: 0", which readers would misinterpret as "nothing was blocked".
struct ObservationSourceOutcome final {
    ObservationSource source = ObservationSource::kUnknown;
    bool sourceSupported = false;
    bool sourceEnabled = false;
    CollectionOutcome outcome;   // Default is NotCollected — "not subscribed" is the initial state.
    CoverageAccount coverage;

    // Whether this source path actually executed and returned an observation (even if it is a correct empty set).
    bool carriesObservation() const noexcept;
};

// Static candidates and actual events are separated structurally; exports also follow a two-stage process.
struct RuleExplanation final {
    StaticCandidateReport candidates;
    std::vector<ObservedFilterHit> observations;
    // Accounting for event source collection. Before rendering actualHitCount()==0, you must check it first:
    // When observationsCollected() is false, only report "Event source not
    // collected/Collection failed + original error code"; never report "Actual hit count 0".
    std::vector<ObservationSourceOutcome> sourceOutcomes;

    std::size_t actualHitCount() const noexcept;
    std::size_t untrustedObservationCount() const noexcept;

    // At least one source must be 'supported + enabled + returning observations'. If
    // false, 'zero hits' indicates a collection issue, not 'no hits actually occurred'.
    bool observationsCollected() const noexcept;

    // Note: An observation source exists that failed or was not collected (has an entry but lacks observation status). The UI uses this to display the original error code.
    bool anyObservationSourceFailed() const noexcept;

    // Actual path generation is disallowed when no supported and enabled source records exist.
    bool hasActualPath() const noexcept;
};

// ---------------------------------------------------------------------------
// N-06: Runtime ID reference and invalidation.
// ---------------------------------------------------------------------------
struct RuntimeFilterReference final {
    OptionalU64 filterId;
    WfpGuid filterKey;
    OptionalU64 capturedGeneration;  // Unset when unknown.
    // Boot cycle at collection time. Generation numbers increase only within a boot and restart after reboot, so
    // equal generations across boots do not imply a match. If both sides provide bootId, compare it first (N-06).
    std::string bootId;
};

enum class FilterLinkState {
    kLinkedByGuid,                     // GUID match — still trustworthy across generations.
    kLinkedByRuntimeIdSameGeneration,  // Linked by filterId within the same generation.
    kRejectedIdReused,                 // References a built-in GUID; the object with the same ID in the directory is not the same.
    kRejectedStaleGeneration,          // Generation mismatch or unknown generation with no GUID to verify — refuse connection.
    kRejectedAmbiguous,                // Multiple catalog entries share a GUID or filterId.
    // The catalog positively proves complete enumeration and the item is absent. This is an assertion of absence.
    kNoMatch,
    kCatalogNotCollected,              // Filter partition was not collected; cannot determine.
    // Collected but incomplete: not finding an item does not prove its absence (N-06). This differs from NoMatch.
    kCatalogIncomplete,
    kNotSpecified,                     // Reference with no arguments.
};

const char* filterLinkStateName(FilterLinkState state) noexcept;

struct FilterReferenceResolution final {
    FilterLinkState state = FilterLinkState::kNotSpecified;
    bool hasIndex = false;
    std::size_t filterIndex = 0;
    std::vector<std::string> limitationKeys;
};

FilterReferenceResolution resolveFilterReference(const WfpCatalog& catalog,
                                                 const RuntimeFilterReference& reference);

FilterReferenceResolution linkObservationToCatalog(const WfpCatalog& catalog,
                                                   const ObservedFilterHit& hit);

// Changes between two collections. Only when **both sides can positively prove completeness** can we claim "added/removed".
enum class CatalogChangeKind {
    kAdded,
    kRemoved,
    kActionChanged,
    kWeightChanged,
    kConditionsChanged,
    kRuntimeIdReused,   // The same filterId points to different GUIDs across two generations.
    kPresenceUnknown,   // Insufficient evidence on one side to determine presence.
};

const char* catalogChangeKindName(CatalogChangeKind kind) noexcept;

struct CatalogChange final {
    CatalogChangeKind kind = CatalogChangeKind::kPresenceUnknown;
    WfpGuid filterKey;
    OptionalU64 beforeFilterId;
    OptionalU64 afterFilterId;
    std::vector<std::string> limitationKeys;
};

struct CatalogDelta final {
    std::vector<CatalogChange> changes;
    // Both sides of the filter partition can perform absence inference, and this is true **only if** neither side contains
    // lines that distort GUID indexing (duplicate GUIDs or missing GUIDs). Any such line invalidates the 'add/delete/modify'
    // conclusion: duplicate lines silently drop one entry, and lines without GUIDs never enter the comparison.
    bool comparable = false;
    std::vector<std::string> limitationKeys;
};

CatalogDelta diffCatalogs(const WfpCatalog& before, const WfpCatalog& after);

// ---------------------------------------------------------------------------
// N-08: navigation
// ---------------------------------------------------------------------------

// Object reference for the filter. Since ObjectIdentity::ObjectKind lacks a WFP filter category,
// this uses the Unknown category with a prefixed key to avoid collisions with process/driver keys.
// Only emit the key if the GUID is known; references with only a runtime ID are always Unusable (IDs are reusable).
ObjectRef makeFilterRef(const WfpFilter& filter, std::string evidenceId);
ObjectRef makeCalloutRef(const WfpCallout& callout, std::string evidenceId);

// N-08: Rejection reason. The NavigationOutcome value "object not in current data" is used to represent both "source untrusted" and
// "request missing evidence ID". Three completely different reasons collapse into a single value along the outcome dimension; exporting
// only the outcome loses the distinction. This enum is exported alongside outcome specifically to preserve this differentiation.
enum class WfpNavigationRejection {
    kNone,               // outcome == Delivered
    kTargetPageMissing,
    kObjectNotPresent,   // Page exists, but the object is not in the current data.
    kIdentityUnusable,   // Insufficient identity for the reference (e.g., only a reusable filterId).
    kEvidenceIdMissing,  // The request did not include an evidence ID.
    kEvidenceNotSaved,   // This data was not saved in the offline session.
    kSourceNotTrusted,   // N-04: Source unsupported, disabled, or unknown; cannot be treated as the 'actual path'.
};

const char* wfpNavigationRejectionName(WfpNavigationRejection rejection) noexcept;

struct WfpNavigationResult final {
    NavigationRequest request;
    NavigationOutcome outcome = NavigationOutcome::kObjectNotPresent;
    // Rejection reason parallel to outcome. Outcome reuses the value domain of
    // LiveNavigation (no new values added); the specific rejection type is determined here.
    WfpNavigationRejection rejection = WfpNavigationRejection::kObjectNotPresent;
    // Always false: this layer never re-initiates queries. Offline missing data only reports EvidenceNotSaved.
    bool refetchAttempted = false;

    // Identity revalidation result when jumping from an offline connection to a live one (F-09 / N-08).
    bool identityRevalidated = false;
    LiveNavigationDecision liveDecision = LiveNavigationDecision::kRejectIdentityUnverifiable;

    // N-04: Records with unsupported or disabled sources cannot be treated as the 'actual path traversed' for the timeline.
    bool blockedByUntrustedSource = false;
};

// Navigate from a connection to a process instance. Reject with F-09 if saved/live identities are inconsistent.
WfpNavigationResult navigateConnectionToProcess(const ConnectionDescription& connection,
                                                const LiveResolution& live,
                                                bool targetPageAvailable,
                                                bool evidencePresentInSession,
                                                std::string evidenceId);

// Trace back from a filter to associated evidence (rule → evidence).
WfpNavigationResult navigateFilterToEvidence(const WfpFilter& filter,
                                             bool targetPageAvailable,
                                             bool objectPresentInPage,
                                             bool evidencePresentInSession,
                                             std::string evidenceId);

// Jump from a running event to the timeline. Events without supported sources cannot be sent to the timeline as 'actual paths'.
// Evaluation order: first derive the conclusion using standard navigation criteria (identity / evidence ID / target page / offline save
// status), then override with source trustworthiness—otherwise, 'untrusted source' would incorrectly override 'no evidence ID provided'.
WfpNavigationResult navigateObservationToTimeline(const ObservedFilterHit& hit,
                                                  bool targetPageAvailable,
                                                  bool evidencePresentInSession);

} // namespace ksword::evidence

#pragma once

// S module: Platform security state and explanation.
//
// This layer implements only the **state model**: it does not query WMI, read the registry, or access Win32 APIs. Queries occur in
// existing Qt pages, which populate SecurityField with raw values; this layer is responsible for answering four specific questions:
//   1. Is this capability supported by hardware/system? (hardwareSupport)
//   2. Is it configured to be enabled? (configured)
//   3. Is it actually running? (running)
//   4. How were the three pieces of evidence above obtained, and did the queries succeed? (queryOutcome + per-field outcome)
//
// Hard rules spanning the entire module (implemented per S-01 through S-08):
//   * S-01: Four-dimensional mutual non-derivability. SecurityServicesConfigured and SecurityServicesRunning
//     in Win32_DeviceGuard are two distinct attributes; no line of code at this layer copies one to the other.
//     hardwareSupport is also not inferred from configured/running.
//   * S-01 Query failure does not equal closure. A CapabilityClaim assertion is only valid if the field it points to
//     It is only accepted when it truly carries an observation; otherwise, that dimension remains
//     Unknown. The assertion itself is still listed for human review but does not participate in value
//     determination. Therefore, AccessDenied / Timeout / Unsupported will never become TriState::No.
//   S-01 unknown enumerations are preserved as-is. The Interpret* series returns
//     recognized=false for unrecognized encodings while carrying rawCode and rawText
//     unchanged; it never guesses a recent known value and never defaults to 0.
//   * S-02 normalization does not overwrite the original value. FieldAssessment holds both
//     RawObservation and EnumInterpretation as parallel fields, not as a "parsed replacement".
//   * S-02: Pre-reboot state is not the current value. Use captureWindow.bootId to determine
//     freshness: constant values across different bootIds go only to historicalValue, never to value.
//   * S-05: When multiple sources are inconsistent, display all source values simultaneously; resolved is always Unknown. This
//     layer has no arbitration branches for "taking the favorable value", "taking the latest value", or "prioritizing kernel values".
//   * S-05 pending status requires positive evidence. The pendingActivation flag is set only when a source explicitly provides a
//     'pending restart' or 'pending activation' field, that field carries an observation, and it belongs to the current boot cycle.
//   * S-06 states constraints without recommending fixes. KswordCapabilityExplanation has **no**
//     remediation / suggestion / fixAction fields. Constraint keys must also pass the
//     isStatementOnlyConstraintKey vocabulary check: keys containing action words such as disable/turnoff are
//     rejected and recorded in limitationKeys. Match **words**, not substrings. Otherwise, statement keys
//     such as "hvci.notDisabled" and "driver.uninstalled" would be rejected by the check itself, while actual
//     recommendation keys could enable the capability through fall-through (see explainKswordCapability).
//   * For S-06: If constraints are present but none can be evaluated, availability falls back to Unknown. Constraints represent the
//     "blocking capability" side. Failing to collect constraint evidence means "unclear," not "allowed." We must never let a source
//     claiming observedAvailable=Yes bypass checks directly—that is exactly the "never collected evidence implies normal" fallacy.
//   * S-07 permissions are field-precise. Without an administrator, fields with AccessRequirement::None remain
//     readable; the report is not cleared entirely. Administrator and System are two distinct tiers, each gated
//     by its own three-state control in PrivilegeContext, without sharing a single administrator criterion.
//
// This layer does not produce conclusions like 'System Secure', 'Hardened', or 'Threat Detected', nor does it perform remote attestation derivation.

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// S-01: Three-state logic. Since bool cannot express 'not found', this layer never uses bool to represent state.
// Unknown is placed at index 0 so that any default-constructed state is 'Unknown' rather than 'No'.
// ---------------------------------------------------------------------------
enum class TriState {
    kUnknown,  // No available evidence
    kNo,       // Evidence indicates no
    kYes,      // Evidence indicates yes
};

const char* triStateName(TriState value) noexcept;

// Only 'Yes' and 'No' are 'definite values'. 'Unknown' does not participate in consistency checks and cannot form conflicts with any value.
bool triStateIsDefinite(TriState value) noexcept;

// ---------------------------------------------------------------------------
// S-01 / S-03 / S-04: Capability list. The security-related items at startup are split into independent capabilities to satisfy
// S-03: Express Secure Boot, TPM presence, TPM ready, and measurement logs separately.
// ---------------------------------------------------------------------------
enum class SecurityCapabilityId {
    kUnknown,
    kVirtualizationBasedSecurity,
    kHypervisorEnforcedCodeIntegrity,
    kCredentialGuard,
    kSystemGuardSecureLaunch,
    kKernelDmaProtection,
    kSecureBoot,
    kTpmPresence,          // TPM presence
    kTpmReadiness,         // TPM not ready — this is distinct from 'present or absent'.
    kMeasuredBootLog,      // Whether the measurement log is accessible: if not accessible, the state is Unknown, not "normal".
    kKernelModeCodeIntegrityPolicy,
    kUserModeCodeIntegrityPolicy,
    kTestSigning,
};

const char* securityCapabilityName(SecurityCapabilityId capability) noexcept;

// S-01: The first three dimensions. The fourth dimension, queryOutcome, is of type CollectionOutcome and is
// not in this enum because it describes 'the act of collection' rather than 'the state of the capability'.
enum class SecurityDimension {
    kHardwareSupport,  // Whether hardware/system supports this capability.
    kConfigured,       // Whether it is configured to be enabled.
    kRunning,          // Whether running
};

const char* securityDimensionName(SecurityDimension dimension) noexcept;

// ---------------------------------------------------------------------------
// S-02: The raw value and its normalized interpretation are stored side by side.
// ---------------------------------------------------------------------------

// Source original. The numeric field is populated only if the source itself provides a numeric value; text fields remain unset. No implicit
// conversion is performed (e.g., treating "looks like a number" as a number), which would otherwise merge "0x2" and "2" into a single value.
struct RawObservation final {
    std::string text;
    OptionalU64 numeric;

    bool empty() const noexcept { return text.empty() && !numeric.present; }
};

// Enum normalization result. recognized=false means "I do not recognize this encoding"; in this case,
// normalizedName must be empty — do not substitute a "closest known" name. rawCode/rawText are preserved verbatim
// regardless of recognition (S-01 condition: "New enum values retain original values and are not misinterpreted").
struct EnumInterpretation final {
    bool recognized = false;
    std::string normalizedName;
    OptionalU64 rawCode;
    std::string rawText;
};

// --- Win32_DeviceGuard.SecurityServicesConfigured / SecurityServicesRunning ---
// Based on the publicly documented encoding in Microsoft VBS/Device Guard documentation. Note: these two properties share the
// same encoding table, but **the values come from two different properties**; the interpretation function at this layer does not
// care which source they come from, and the caller must populate them separately into the Configured and Running dimensions.
enum class DeviceGuardService {
    kUnknown,
    kNone,
    kCredentialGuard,
    kHypervisorEnforcedCodeIntegrity,
    kSystemGuardSecureLaunch,
    kSmmFirmwareMeasurement,
};

const char* deviceGuardServiceName(DeviceGuardService service) noexcept;

struct DeviceGuardServiceValue final {
    DeviceGuardService service = DeviceGuardService::kUnknown;
    EnumInterpretation interpretation;
};

DeviceGuardServiceValue interpretDeviceGuardService(const RawObservation& raw);

// --- Win32_DeviceGuard.VirtualizationBasedSecurityStatus ---
enum class VbsStatus {
    kUnknown,
    kDisabled,
    kEnabledNotRunning,
    kEnabledAndRunning,
};

const char* vbsStatusName(VbsStatus status) noexcept;

struct VbsStatusValue final {
    VbsStatus status = VbsStatus::kUnknown;
    EnumInterpretation interpretation;
};

VbsStatusValue interpretVbsStatus(const RawObservation& raw);

// Core separation point for S-01: A single VBS status code indicates both "configured" and "running"
// states. This function splits them into two independent outputs. EnabledNotRunning yields configured=Yes
// and running=No; it never sets running to Yes just because configured is Yes. When the status is unknown
// or unrecognized, both outputs are Unknown; it never defaults "unable to determine" to No.
void vbsStatusToDimensions(VbsStatus status, TriState& configured, TriState& running) noexcept;

// --- Win32_DeviceGuard.AvailableSecurityProperties / RequiredSecurityProperties ---
enum class SecurityProperty {
    kUnknown,
    kNone,
    kBaseVirtualizationSupport,
    kSecureBoot,
    kDmaProtection,
    kSecureMemoryOverwrite,
    kNxProtections,
    kSmmMitigations,
    kModeBasedExecutionControl,
    kApicVirtualization,
};

const char* securityPropertyName(SecurityProperty property) noexcept;

struct SecurityPropertyValue final {
    SecurityProperty property = SecurityProperty::kUnknown;
    EnumInterpretation interpretation;
};

SecurityPropertyValue interpretSecurityProperty(const RawObservation& raw);

// --- S-04：CodeIntegrityPolicyEnforcementStatus / Usermode... ---
enum class CodeIntegrityEnforcement {
    kUnknown,
    kOff,
    kAudit,
    kEnforced,
};

const char* codeIntegrityEnforcementName(CodeIntegrityEnforcement enforcement) noexcept;

struct CodeIntegrityEnforcementValue final {
    CodeIntegrityEnforcement enforcement = CodeIntegrityEnforcement::kUnknown;
    EnumInterpretation interpretation;
};

CodeIntegrityEnforcementValue interpretCodeIntegrityEnforcement(const RawObservation& raw);

// ---------------------------------------------------------------------------
// S-02: Freshness. State across boot cycles is historical, not current.
// ---------------------------------------------------------------------------
enum class FieldFreshness {
    kUnknown,          // Missing bootId, cannot determine which boot this data belongs to.
    kCurrent,          // Consistent with the current boot cycle.
    kHistorical,       // Explicitly from another boot cycle (state prior to restart).
    kDifferentMachine, // machineId present and different — not this machine at all.
};

const char* fieldFreshnessName(FieldFreshness freshness) noexcept;

// Evaluation order: check the machine first, then the boot cycle. If any bootId is missing, the
// result is Unknown; a missing value must not be optimistically treated as 'this current boot'.
FieldFreshness classifyFieldFreshness(const CaptureWindow& field,
                                      const CaptureWindow& current) noexcept;

// Only 'Current' is allowed to represent the 'current state'. 'Unknown' is also excluded: if it cannot be determined, it cannot be determined.
bool freshnessUsableAsCurrent(FieldFreshness freshness) noexcept;

// ---------------------------------------------------------------------------
// S-07: privilege downgrade. Requires field-level precision.
// ---------------------------------------------------------------------------
enum class AccessRequirement {
    kUnknown,        // If not declared, report "Not Declared" in the report as-is; do not assume it is None.
    kNone,           // Readable by standard users.
    kAdministrator,  // Requires administrator
    kSystem,         // Requires SYSTEM/TCB level.
    kKswordDriver,   // Requires this tool's driver to be loaded
};

const char* accessRequirementName(AccessRequirement requirement) noexcept;

struct PrivilegeContext final {
    TriState administrator = TriState::kUnknown;
    // S-07: SYSTEM/TCB and Administrator represent two distinct privilege levels. Without this item,
    // Fields for AccessRequirement::System can only be inferred via administrator impersonation; 'requires SYSTEM but
    // not running' is misinterpreted as 'simply not running'. Default Unknown = not declared = not considered present.
    TriState system = TriState::kUnknown;
    TriState kswordDriverLoaded = TriState::kUnknown;
};

// Field readability in the current context. It is a coarse-grained value used for routing and **does not replace**
// outcome.status. Both Timeout and Error map to QueryFailed, but FieldAssessment.outcome still preserves the original
// status, nativeCode, and message separately to prevent the five failure semantics from collapsing into one.
enum class FieldAvailability {
    kUnknown,
    kReadable,            // Obtained observation
    kBlockedByPrivilege,  // Insufficient privilege (denied, or requires higher privilege that is not currently held).
    kBlockedByDriver,     // Requires this tool's driver, but the driver is not present.
    kNotSupported,        // Current OS/hardware does not support
    kQueryFailed,         // Permissions sufficient but query failed (timeout/error).
    kNotCollected,        // Not run, with no permission reason to explain.
};

const char* fieldAvailabilityName(FieldAvailability availability) noexcept;

// ---------------------------------------------------------------------------
// Input: field
// ---------------------------------------------------------------------------

// A single collection of a security state field. fieldId is a stable identifier; both claim and pending evidence reference it.
struct SecurityField final {
    std::string fieldId;
    // S-02: Original text of the specific query entry. For example
    // "WMI root\\Microsoft\\Windows\\DeviceGuard:Win32_DeviceGuard.SecurityServicesRunning"
    // or "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard:EnableVirtualizationBasedSecurity".
    std::string queryEntry;
    SourceRef source;
    CaptureWindow window;
    CollectionOutcome outcome;
    RawObservation raw;
    EnumInterpretation interpretation;  // Caller fills in using the above Interpret* fields; if not filled, it means "uninterpreted".
    AccessRequirement access = AccessRequirement::kUnknown;
};

// Output: Field assessment. Pass through raw and interpretation data unchanged; assessments only append judgments without rewriting source data.
struct FieldAssessment final {
    std::string fieldId;
    std::string queryEntry;
    SourceRef source;
    CaptureWindow window;
    CollectionOutcome outcome;
    RawObservation raw;
    EnumInterpretation interpretation;
    AccessRequirement access = AccessRequirement::kUnknown;
    FieldAvailability availability = FieldAvailability::kUnknown;
    FieldFreshness freshness = FieldFreshness::kUnknown;
    bool carriesObservation = false;
    bool usableAsCurrent = false;  // carriesObservation && freshness == Current

    // Fact strings for export/UI use: state only observations, no conclusion words.
    std::string describe() const;
};

// ---------------------------------------------------------------------------
// Input: Assertion and pending evidence.
// ---------------------------------------------------------------------------

// An assertion from a source regarding 'a specific dimension of a capability'. fieldId must point to a SecurityField; if it does not,
// it is an unsupported assertion, listed as-is but excluded from value determination (to prevent 'conclusions without sources').
struct CapabilityClaim final {
    SecurityCapabilityId capability = SecurityCapabilityId::kUnknown;
    SecurityDimension dimension = SecurityDimension::kHardwareSupport;
    TriState value = TriState::kUnknown;
    std::string fieldId;
};

// S-05: Pending restart/effective evidence. Must be explicitly provided by the source; this layer must not infer restart requirements from 'inconsistency'.
struct PendingActivationEvidence final {
    SecurityCapabilityId capability = SecurityCapabilityId::kUnknown;
    SecurityDimension dimension = SecurityDimension::kHardwareSupport;
    std::string fieldId;  // Explicitly specify the field for the pending evidence.
    std::string rawText;  // Original source text, e.g., "PendingReboot=1".
};

// Output: how an assertion appears in the report. On conflict, values from all sources are retained here, none lost.
struct SourceClaimView final {
    std::string fieldId;
    std::string sourceGroup;  // Independent source group key (take SourceRef.sourceGroup; fall back to collectorId if null)
    SourceOrigin origin = SourceOrigin::kUnknown;
    TriState value = TriState::kUnknown;  // The value asserted by this source is preserved as-is.
    FieldFreshness freshness = FieldFreshness::kUnknown;
    bool backed = false;          // fieldId parsed to field
    bool carriesObservation = false;
    bool usableAsCurrent = false; // Only if true, value participates in the assignment.
};

// Conclusion for a dimension.
struct DimensionResult final {
    SecurityDimension dimension = SecurityDimension::kHardwareSupport;

    // Current value. Only produced by assertions from usableAsCurrent constants; always Unknown in case of conflicts.
    TriState value = TriState::kUnknown;
    // Historical value spanning boot cycles, displayed separately; never treated as the current value (S-02).
    TriState historicalValue = TriState::kUnknown;

    std::vector<SourceClaimView> claims;  // All sources, including unsupported and historical ones.
    bool conflicted = false;              // Inconsistent values between available sources.
    // S-05: Multiple sources before a reboot may also conflict. Without this flag, two contradictory historical values
    // collapse into historicalValue=Unknown, which looks identical in the report to 'no historical evidence at all'.
    bool historicalConflicted = false;
    std::size_t definiteClaimCount = 0;   // Number of claims contributing to the definite result.
    // Independent source groups. Sources with both sourceGroup and collectorId empty remain separate:
    // two unsigned sources are two sources, not one, or F-11 independent-source counts would be wrong.
    std::size_t distinctSourceGroupCount = 0;

    bool pendingActivation = false;       // True only when explicit pending activation evidence is obtained.
    std::string pendingEvidenceFieldId;
};

// S-01: A capability's four-dimensional state. The three DimensionResult fields
// are independent data; no member function of this type uses one to fill another.
struct CapabilityState final {
    SecurityCapabilityId capability = SecurityCapabilityId::kUnknown;
    DimensionResult hardwareSupport;
    DimensionResult configured;
    DimensionResult running;

    // Fourth dimension: summary of collection results for fields related to this
    // capability. If no claims exist, the state is NotCollected, not 'no issue'.
    CollectionOutcome queryOutcome;

    bool anyClaim = false;             // Whether any claim (even unsupported) has been received.
    bool anyBackedObservation = false; // Whether any backing field actually carries an observation.

    // S-07: Capability-level permission specification, derived from requirements in its supporting field declarations. Administrator
    // and System must be marked separately: folding System into requiresAdministrator would eliminate the 'requires TCB' tier.
    bool requiresAdministrator = false;
    bool requiresSystem = false;
    bool requiresKswordDriver = false;
    std::size_t blockedFieldCount = 0;

    const DimensionResult& dimension(SecurityDimension which) const noexcept;
};

// S-05: A single dimension-level conflict. The claims contain values from **all** sources; the caller displays them side-by-side as-is.
// resolvedValue is always TriState::Unknown — this field's purpose is to encode "I
// won't choose for you" into the type, rather than leaving it to the caller to guess.
struct DimensionConflict final {
    SecurityCapabilityId capability = SecurityCapabilityId::kUnknown;
    SecurityDimension dimension = SecurityDimension::kHardwareSupport;
    std::vector<SourceClaimView> claims;
    TriState resolvedValue = TriState::kUnknown;
    // Conflicting sources for the current boot cycle / conflicting sources before reboot. Both can independently hold
    // true, so use two bits instead of an enum—the caller must specify whether the conflict is 'now' or 'before reboot'.
    bool currentConflict = false;
    bool historicalConflict = false;
    bool pendingActivation = false;
    std::string pendingEvidenceFieldId;
};

// ---------------------------------------------------------------------------
// S-04: WDAC / Code Integrity
// ---------------------------------------------------------------------------

// One policy. The list of policies 'configured on disk' and the list of policies 'currently in effect' are separate and not shared.
struct CodeIntegrityPolicyRecord final {
    std::string policyId;      // GUID original string; no case normalization (to avoid overwriting the original value).
    std::string friendlyName;
    RawObservation enforcementRaw;  // Original audit/enforced encoding for this policy.
    TriState basePolicy = TriState::kUnknown;
    std::string sourceFieldId;
};

// Evaluated policy: explanation alongside the original value.
struct CodeIntegrityPolicyView final {
    std::string policyId;
    std::string friendlyName;
    CodeIntegrityEnforcement enforcement = CodeIntegrityEnforcement::kUnknown;
    EnumInterpretation enforcementInterpretation;
    TriState basePolicy = TriState::kUnknown;
    std::string sourceFieldId;
};

struct CodeIntegrityInput final {
    // Configuration scope: policy files on disk.
    CollectionOutcome configuredOutcome;
    std::vector<CodeIntegrityPolicyRecord> configuredPolicies;
    // Effective scope: policies that are enumerated at runtime and actually take effect.
    CollectionOutcome effectiveOutcome;
    std::vector<CodeIntegrityPolicyRecord> effectivePolicies;
    // Global execution state (one property each for kernel mode and user mode).
    RawObservation kernelModeRaw;
    CollectionOutcome kernelModeOutcome;
    RawObservation userModeRaw;
    CollectionOutcome userModeOutcome;
};

struct CodeIntegrityAssessment final {
    std::vector<CodeIntegrityPolicyView> configuredPolicies;
    CollectionOutcome configuredOutcome;
    bool configuredPolicyKnown = false;

    std::vector<CodeIntegrityPolicyView> effectivePolicies;
    CollectionOutcome effectiveOutcome;
    // S-04 condition: 'retain unknown when actual policy status cannot be found'. When not found,
    // this is false and effectivePolicies remains empty—never substitute with configuredPolicies.
    bool effectivePolicyKnown = false;

    CodeIntegrityEnforcement kernelModeEnforcement = CodeIntegrityEnforcement::kUnknown;
    EnumInterpretation kernelModeInterpretation;
    CodeIntegrityEnforcement userModeEnforcement = CodeIntegrityEnforcement::kUnknown;
    EnumInterpretation userModeInterpretation;

    std::vector<std::string> limitationKeys;

    std::size_t auditPolicyCount() const noexcept;
    std::size_t enforcedPolicyCount() const noexcept;
};

CodeIntegrityAssessment evaluateCodeIntegrity(const CodeIntegrityInput& input);

// S-04: 'Signature valid' does not equal 'Currently allowed to load by policy'. These are two distinct
// fields, each supported by its own outcome; evaluateImageLoad does not derive one from the other.
struct ImageLoadInput final {
    std::string imagePath;
    TriState signatureValid = TriState::kUnknown;
    CollectionOutcome signatureOutcome;
    TriState policyAllowsLoad = TriState::kUnknown;
    CollectionOutcome policyDecisionOutcome;
};

struct ImageLoadAssessment final {
    std::string imagePath;
    TriState signatureValid = TriState::kUnknown;
    TriState allowedByCurrentPolicy = TriState::kUnknown;
    CollectionOutcome signatureOutcome;
    CollectionOutcome policyDecisionOutcome;
    std::vector<std::string> limitationKeys;
};

ImageLoadAssessment evaluateImageLoad(const ImageLoadInput& input);

// ---------------------------------------------------------------------------
// S-06: Why KSword capabilities are unavailable.
// ---------------------------------------------------------------------------
enum class CapabilityConstraintKind {
    kUnknown,
    kVendorUnsupported,      // Missing backend on the CPU vendor side (separately for AMD/Intel).
    kHardwareUnsupported,    // Hardware itself does not support
    kDriverMissing,          // This tool's driver is not loaded.
    kProfileMissing,         // Offset table / profile missing
    kSecurityConfiguration,  // Platform security configuration disallows it (e.g., HVCI is running).
    kPrivilegeInsufficient,  // Access denied
    kQueryUnavailable,       // Related status unavailable; cannot determine.
};

const char* capabilityConstraintKindName(CapabilityConstraintKind kind) noexcept;

// S-06: Constraint keys must be **statements** (e.g., "Current HVCI is running"), not **action recommendations**
// (e.g., "Disable memory integrity"). This vocabulary gate prevents regressions: if someone later tries to inject a
// fix recommendation at this layer, the key will be rejected and a limitation recorded, rather than silently passing.
//
// Matching is performed at the **word** level, not the substring level. Keys are first split into segments by '.', '-', '_', ' ', or
// ':', and then each segment is further split into words using camelCase. A match occurs if: (1) a word exactly equals the action
// word, (2) up to three adjacent words concatenated equal the action word (covering formats like turn-off, please-turn, how-to-fix
// that are split by delimiters), or (3) a word starts with the action word (covering derived nouns like suggestion, remediation).
// After a match, there is a temporal exemption that applies **only to action verbs**: if the matched word is a past
// participle (-ed, e.g., uninstalled, disabled), or if a -ed/-ing word immediately follows the matched word in the
// same segment (e.g., bypassDetected, shutdownPending), it is classified as a **statement** rather than an imperative.
// Note: Persuasive terms like 'recommend', 'suggest', or 'howToFix' do not enjoy exemption (even 'suggested' is still a suggestion).
// Gerunds do not enjoy the first exemption either, otherwise 'fix.byDisablingHvci' could slip in.
// Substring matching cannot do this: it treats
// "hvci.notDisabled"、"dse.isDisabledByPolicy"、"driver.uninstalled"、
// Treat "smm.shutdownPending" and "bypassDetected" as action keys to reject, so these actual
// constraints never enter accepted, while the capability is erroneously allowed via observedAvailable.
bool isStatementOnlyConstraintKey(std::string_view key) noexcept;

struct KswordCapabilityConstraint final {
    CapabilityConstraintKind kind = CapabilityConstraintKind::kUnknown;
    std::string constraintKey;  // i18n key
    std::string sourceFieldId;  // From which field is this constraint derived?
    RawObservation observed;    // Original value of this field.
};

struct KswordCapabilityConstraintView final {
    CapabilityConstraintKind kind = CapabilityConstraintKind::kUnknown;
    std::string constraintKey;
    std::string sourceFieldId;
    RawObservation observed;
    bool backed = false;    // sourceFieldId resolved to a field that carries observation.
    bool accepted = false;  // Key passed the vocabulary gate and has a source field.
};

struct KswordCapabilityInput final {
    std::string capabilityId;  // For example, "kvm.ept.view".
    // Availability directly observed by the source. Accepted only when availabilityOutcome carries an observation.
    TriState observedAvailable = TriState::kUnknown;
    CollectionOutcome availabilityOutcome;
    std::vector<KswordCapabilityConstraint> constraints;
};

// Note: this structure intentionally omits the remediation, suggestedAction, and howToFix fields.
// The S-06 acceptance criteria explicitly prohibit suggesting "disable protection" as the default fix.
//
// Evaluation order for available (earlier takes precedence):
//   1. If any constraint is adopted -> No. The source simultaneously claiming availability is a contradiction, recorded as kConstraintConflict.
//   2. Constraints exist but none were adopted (key rejected / source field not captured / field not
//      referenced), and the source claims observedAvailable=Yes -> Unknown. Record as kConstraintIndeterminate.
//      Evidence that failed to be collected cannot be used to grant access — this is the S-06 manifestation of 'query failure ≠ normal'.
//      Preserve 'No' when the source claims 'No': that is positive evidence of unavailability and should not be overwritten with 'Unknown'.
//   3. If there are no constraints and the availability query carries an observation, adopt observedAvailable.
//   4. Others -> Unknown.
struct KswordCapabilityExplanation final {
    std::string capabilityId;
    TriState available = TriState::kUnknown;
    std::vector<KswordCapabilityConstraintView> constraints;
    std::vector<std::string> rejectedConstraintKeys;
    std::vector<std::string> limitationKeys;

    // S-06 condition: 'Capabilities that cannot run must not start.' Unknown
    // is also disallowed from starting; only an explicit Yes permits launch.
    bool mayStart() const noexcept;
};

KswordCapabilityExplanation explainKswordCapability(const KswordCapabilityInput& input,
                                                    const std::vector<FieldAssessment>& fields);

// ---------------------------------------------------------------------------
// S-08: Actual configuration list
// ---------------------------------------------------------------------------
struct VerifiedConfiguration final {
    std::string configurationId;
    std::string osBuildRaw;  // Raw build string, not parsed into numbers (to avoid losing formats like "26100.1234").
    TriState vbsRunning = TriState::kUnknown;
    TriState hvciRunning = TriState::kUnknown;
    TriState kswordDriverLoaded = TriState::kUnknown;
    std::string evidenceFieldId;
};

enum class SupportClaimStatus {
    kBlocked,            // Not enough for two configurations — the spec requires retaining BLOCKED.
    kPartiallyVerified,  // Only one set was verified.
    kVerified,           // Both standard configuration and VBS/HVCI runtime configuration have been verified.
};

const char* supportClaimStatusName(SupportClaimStatus status) noexcept;

struct SupportClaim final {
    SupportClaimStatus status = SupportClaimStatus::kBlocked;
    bool baselineConfigurationVerified = false;  // Note: VBS not running configuration.
    bool vbsConfigurationVerified = false;       // VBS/HVCI configuration currently in use.
    std::vector<std::string> acceptedConfigurationIds;
    std::vector<std::string> rejectedConfigurationIds;  // Missing build / missing evidence / unknown status
    std::vector<std::string> limitationKeys;
};

// Default (empty list) is Blocked: no record means not verified, not 'all supported'.
SupportClaim evaluateSupportClaim(const std::vector<VerifiedConfiguration>& configurations);

// ---------------------------------------------------------------------------
// Top-level evaluation
// ---------------------------------------------------------------------------
struct SecurityStateInput final {
    // Baseline for the current boot cycle. When bootId is null, freshness for all fields is judged Unknown (indeterminate).
    CaptureWindow currentWindow;
    PrivilegeContext privilege;
    std::vector<SecurityField> fields;
    std::vector<CapabilityClaim> claims;
    std::vector<PendingActivationEvidence> pendingEvidence;

    // Capabilities expected to be covered in this round. A capability that is expected but has no assertions will
    // explicitly generate a status of all Unknown / queryOutcome=NotCollected and be recorded in the ledger—never
    // silently skipped, otherwise a "complete absence" in the round would make the report look clean.
    std::vector<SecurityCapabilityId> requestedCapabilities;
};

struct SecurityStateReport final {
    std::vector<FieldAssessment> fields;
    std::vector<CapabilityState> capabilities;
    std::vector<DimensionConflict> conflicts;

    // envelope.coverage unit is 'expected evidence items for the current platform security state': one item per field, plus one
    // item per absent capability for each full round. succeeded counts only successful observations in the **current boot cycle**;
    // Observations collected successfully but from a different boot cycle or machine are counted as skipped—they cannot answer 'what is the
    // current state'; assuming full coverage would cause a report containing only pre-reboot data to incorrectly conclude 'no differences found'.
    EvidenceEnvelope envelope;
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;
    TrustStatement trust;
    std::vector<std::string> limitationKeys;  // Sorted and deduplicated

    std::size_t readableFieldCount = 0;
    std::size_t blockedFieldCount = 0;      // Unable to read due to permissions or driver.
    std::size_t historicalFieldCount = 0;
    std::size_t missingCapabilityCount = 0; // Count of capabilities that are expected to be covered but have no assertions.

    const FieldAssessment* findField(std::string_view fieldId) const noexcept;
    const CapabilityState* findCapability(SecurityCapabilityId capability) const noexcept;
    const DimensionConflict* findConflict(SecurityCapabilityId capability,
                                          SecurityDimension dimension) const noexcept;
    bool hasLimitation(std::string_view key) const noexcept;
};

SecurityStateReport evaluateSecurityState(const SecurityStateInput& input);

// Limitation keys used in reports. Listed centrally so the UI can translate them using this table.
namespace security_limitation_keys {
inline constexpr const char* kClaimUnbacked = "security.claim.unbacked";
inline constexpr const char* kClaimNotObserved = "security.claim.notObserved";
inline constexpr const char* kFieldHistorical = "security.field.historical";
inline constexpr const char* kFieldForeignMachine = "security.field.foreignMachine";
inline constexpr const char* kFieldFreshnessUnknown = "security.field.freshnessUnknown";
inline constexpr const char* kFieldDuplicateId = "security.field.duplicateId";
inline constexpr const char* kCapabilityNotCollected = "security.capability.notCollected";
inline constexpr const char* kDimensionConflict = "security.dimension.conflict";
inline constexpr const char* kHistoricalConflict = "security.dimension.historicalConflict";
inline constexpr const char* kSourceGroupUnattributed = "security.source.unattributed";
inline constexpr const char* kOutcomeMixedFailures = "security.outcome.mixedFailures";
inline constexpr const char* kPrivilegeDegraded = "security.privilege.degraded";
inline constexpr const char* kSystemPrivilegeDegraded = "security.privilege.systemDegraded";
inline constexpr const char* kDriverDegraded = "security.driver.degraded";
inline constexpr const char* kUnknownEnumPreserved = "security.enum.unknownPreserved";
inline constexpr const char* kMeasuredBootLogUnknown = "security.measuredBoot.logUnknown";
inline constexpr const char* kConfiguredPolicyUnknown = "security.codeIntegrity.configuredUnknown";
inline constexpr const char* kEffectivePolicyUnknown = "security.codeIntegrity.effectiveUnknown";
inline constexpr const char* kPolicyDecisionUnknown = "security.codeIntegrity.policyDecisionUnknown";
inline constexpr const char* kConstraintNonStatement = "security.constraint.nonStatement";
inline constexpr const char* kConstraintUnbacked = "security.constraint.unbacked";
inline constexpr const char* kConstraintConflict = "security.capability.constraintConflict";
// Constraints exist but none can be determined; therefore, the source's self-claimed 'available' status is not accepted.
inline constexpr const char* kConstraintIndeterminate = "security.constraint.indeterminate";
inline constexpr const char* kSupportClaimBlocked = "security.supportClaim.blocked";
inline constexpr const char* kSupportClaimIncomplete = "security.supportClaim.incomplete";
} // namespace security_limitation_keys

} // namespace ksword::evidence

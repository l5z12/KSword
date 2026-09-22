#include "SecurityState.h"

#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include <unordered_set>

namespace ksword::evidence {
namespace {

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

std::string fact(const char* key, const std::string& value) {
    return std::string(key) + "=" + value;
}

// Always write "unknown" for unknown values; never use an empty string or 0 to fake it—an empty string is indistinguishable in concatenated results.
std::string textOrUnknown(const std::string& value) {
    return value.empty() ? std::string("unknown") : value;
}

std::string codeOrUnknown(const OptionalU64& value) {
    return value.present ? formatU64(value.value, U64Format::kDecimal) : std::string("unknown");
}

void addKey(std::vector<std::string>& keys, const char* key) {
    keys.emplace_back(key);
}

void sortUniqueKeys(std::vector<std::string>& keys) {
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
}

// Generic construction for normalized interpretation: regardless of recognition, rawCode and rawText are preserved as-is (S-01/S-02).
EnumInterpretation makeInterpretation(const RawObservation& raw, bool recognized, const char* name) {
    EnumInterpretation interpretation;
    interpretation.recognized = recognized;
    if (recognized) {
        interpretation.normalizedName = name;
    }
    interpretation.rawCode = raw.numeric;
    interpretation.rawText = raw.text;
    return interpretation;
}

// Action/advice word list. Matching any entry means the key is 'teaching the user what to do' rather than 'stating the current status'.
// S-06: prohibit using disable-protection as the default fix via conditions; this closes the door at the vocabulary level.
//
// Split into two categories because the tense exemption applies only to one of them:
//   * Verb — Action verbs. Their -ed past participles represent **states** (e.g., uninstalled,
//     disabled). These are exempted because they are required for true statement keys.
//   * Advice — Verbal acts used for persuasion. Regardless of the form (suggested, recommendation,
//     etc.), recommend / suggest / howToFix always provide advice and are never exempt.
enum class ActionWordClass { kVerb, kAdvice };

struct ActionWordEntry final {
    std::string_view word;
    ActionWordClass kind;
};

const ActionWordEntry kActionWords[] = {
    // "disabl" instead of "disable": English morphology drops the silent 'e' (disable -> disabling). When writing
    // the full form, "disabling" does not start with "disable," so prefix matching would miss the gerund.
    {"disabl", ActionWordClass::kVerb},
    {"turnoff", ActionWordClass::kVerb},
    {"switchoff", ActionWordClass::kVerb},
    {"shutdown", ActionWordClass::kVerb},
    {"uninstall", ActionWordClass::kVerb},
    {"bypass", ActionWordClass::kVerb},
    {"remediat", ActionWordClass::kVerb},
    {"recommend", ActionWordClass::kAdvice},
    {"suggest", ActionWordClass::kAdvice},
    {"workaround", ActionWordClass::kAdvice},
    {"howtofix", ActionWordClass::kAdvice},
    {"pleaseturn", ActionWordClass::kAdvice},
    {"youshould", ActionWordClass::kAdvice},
};

// --- Tokenizing the S-06 vocabulary check --- The old implementation lowercased the entire key and
// performed a **substring** search, matching letter sequences rather than words. Consequently,
// **statement** keys such as "hvci.notDisabled" / "dse.isDisabledByPolicy" / "driver.uninstalled" /
// "smm.shutdownPending" / "bypassDetected" were all rejected by their own check and never reached
// accepted. The capability was instead allowed based on the source's self-reported observedAvailable.
// Now matching by token: first split by delimiters, then split tokens within each segment by camelCase. Segment numbers must be preserved because
// tense exemptions only apply within the same segment ("kvm.disable.running" cannot be absolved by the "running" in an adjacent segment).
struct KeyToken final {
    std::string text;
    // Strips -ing / -ed suffixes to get the stem. Used to handle action phrases split by inflection:
    // "turningOff" becomes "turningoff", but only stem concatenation equals the dictionary entry "turnoff".
    std::string stem;
    std::size_t segment = 0;
};

bool isKeySeparator(char c) noexcept {
    return c == '.' || c == '-' || c == '_' || c == ' ' || c == '/' || c == ':';
}

bool isUpperAscii(char c) noexcept { return c >= 'A' && c <= 'Z'; }
bool isLowerAscii(char c) noexcept { return c >= 'a' && c <= 'z'; }
bool isDigitAscii(char c) noexcept { return c >= '0' && c <= '9'; }

char lowerAscii(char c) noexcept {
    return isUpperAscii(c) ? static_cast<char>(c + ('a' - 'A')) : c;
}

std::string stemWord(const std::string& token) {
    if (token.size() > 5U && token.compare(token.size() - 3U, 3U, "ing") == 0) {
        return token.substr(0, token.size() - 3U);
    }
    if (token.size() > 4U && token.compare(token.size() - 2U, 2U, "ed") == 0) {
        return token.substr(0, token.size() - 2U);
    }
    return token;
}

std::vector<KeyToken> splitKeyTokens(std::string_view key) {
    std::vector<KeyToken> tokens;
    std::string current;
    std::size_t segment = 0;
    bool segmentHasContent = false;
    const auto kFlush = [&tokens, &current, &segment]() {
        if (!current.empty()) {
            tokens.push_back(KeyToken{current, stemWord(current), segment});
            current.clear();
        }
    };
    for (std::size_t i = 0; i < key.size(); ++i) {
        const char kC = key[i];
        if (isKeySeparator(kC)) {
            kFlush();
            if (segmentHasContent) {
                ++segment;
                segmentHasContent = false;
            }
            continue;
        }
        if (!current.empty()) {
            const char kPrevious = key[i - 1];
            // "turnOff" -> turn|off；"HVCIRunning" -> hvci|running。
            const bool kLowerToUpper = (isLowerAscii(kPrevious) || isDigitAscii(kPrevious)) &&
                                      isUpperAscii(kC);
            const bool kAcronymTail = isUpperAscii(kPrevious) && isUpperAscii(kC) &&
                                     (i + 1U) < key.size() && isLowerAscii(key[i + 1U]);
            if (kLowerToUpper || kAcronymTail) {
                kFlush();
            }
        }
        current.push_back(lowerAscii(kC));
        segmentHasContent = true;
    }
    kFlush();
    return tokens;
}

// Past participle. The length threshold filters out short words like 'red' that coincidentally end with the same suffix.
bool isPastParticiple(const std::string& token) noexcept {
    return token.size() > 3U && token.compare(token.size() - 2U, 2U, "ed") == 0;
}

// -ed / -ing inflections are morphological markers for 'stative state': detected / pending / running.
bool isStateFormWord(const std::string& token) noexcept {
    return isPastParticiple(token) ||
           (token.size() > 4U && token.compare(token.size() - 3U, 3U, "ing") == 0);
}

// Tense exemption after hitting an action verb; two valid modes:
//   * The hit fragment contains a past participle ending in -ed (e.g., uninstalled, disabled, turnedOff);
//   * The hit fragment is immediately followed by a -ed/-ing state word (bypassDetected,
//     shutdownPending) within the **same segment** — in this case, the action word is a modified noun.
// The first rule recognizes only -ed forms, not -ing forms: gerunds (e.g., "disabling" in byDisablingHvci, "turning"
// in turningOff) still describe actions. Granting them an exemption would effectively restore the suggested key.
bool actionHitIsStatement(const std::vector<KeyToken>& tokens,
                          std::size_t first,
                          std::size_t last) noexcept {
    for (std::size_t i = first; i <= last; ++i) {
        if (isPastParticiple(tokens[i].text)) {
            return true;
        }
    }
    const std::size_t kNext = last + 1U;
    return kNext < tokens.size() && tokens[kNext].segment == tokens[last].segment &&
           isStateFormWord(tokens[kNext].text);
}

// All assertion views under a capability/dimension — used during dimension build.
struct DimensionBuildResult final {
    DimensionResult result;
    std::vector<std::string> backingFieldIds;
};

// Severity ranking for failure semantics. Used to select a **real** result as the summary when "every supporting check
// fails but for different reasons." AccessDenied ranks first: it is the only category that explains "why the entire block
// has no data." If a synthesized Error overwrites it, we can no longer distinguish between "requires admin" and "broken."
int failureSeverityRank(CollectionStatus status) noexcept {
    switch (status) {
    case CollectionStatus::kAccessDenied: return 5;
    case CollectionStatus::kUnsupported:  return 4;
    case CollectionStatus::kTimeout:      return 3;
    case CollectionStatus::kError:        return 2;
    case CollectionStatus::kNotCollected: return 1;
    case CollectionStatus::kSuccess:
    case CollectionStatus::kPartial:      return 0;
    }
    return 0;
}

// Aggregate multiple collection results into a capability-level fourth dimension.
// Note: This is a **summary**; the original status, nativeCode, and message for each field remain fully
// preserved in FieldAssessment.outcome, and the five failure semantics are not collapsed at that level.
// mixedFailureStatuses is an output parameter: set to true if all operations failed but the failure statuses were inconsistent,
// allowing the caller to record this. The summary necessarily omits other failure types, and this fact must be visible in the report.
CollectionOutcome aggregateOutcomes(const std::vector<const CollectionOutcome*>& outcomes,
                                    bool* mixedFailureStatuses = nullptr) {
    if (mixedFailureStatuses != nullptr) {
        *mixedFailureStatuses = false;
    }
    if (outcomes.empty()) {
        // No supporting evidence — it means 'not collected', not 'no issues'.
        return CollectionOutcome::notCollected();
    }

    std::size_t observed = 0;
    bool anyPartial = false;
    for (const CollectionOutcome* outcome : outcomes) {
        if (statusCarriesObservation(outcome->status)) {
            ++observed;
        }
        if (outcome->status == CollectionStatus::kPartial) {
            anyPartial = true;
        }
    }

    if (observed == outcomes.size()) {
        CollectionOutcome result;
        result.status = anyPartial ? CollectionStatus::kPartial : CollectionStatus::kSuccess;
        return result;
    }
    if (observed != 0U) {
        CollectionOutcome result;
        result.status = CollectionStatus::kPartial;
        return result;
    }

    // No observations recorded. If all failures are identical, preserve them as-is (including nativeCode and source text).
    const CollectionOutcome& first = *outcomes.front();
    bool identical = true;
    bool sameStatus = true;
    for (const CollectionOutcome* outcome : outcomes) {
        if (outcome->status != first.status) {
            sameStatus = false;
            identical = false;
            continue;
        }
        if (outcome->nativeCode != first.nativeCode ||
            outcome->nativeCodeDomain != first.nativeCodeDomain ||
            outcome->message != first.message) {
            identical = false;
        }
    }
    if (identical) {
        return first;
    }
    if (sameStatus) {
        // Status is the same but error codes differ: the status can be retained, but fabricating a 'representative code' would be misleading, so we leave it empty.
        CollectionOutcome result;
        result.status = first.status;
        return result;
    }

    // Statuses differ. Do not synthesize CollectionStatus::Error here—that status has never been returned by any source,
    // effectively inventing a failure and flattening explainable failures like AccessDenied into a generic error (violating
    // S-01's rule that the five failure semantics must not be mixed). Select the single most severe actual result.
    if (mixedFailureStatuses != nullptr) {
        *mixedFailureStatuses = true;
    }
    const CollectionOutcome* chosen = outcomes.front();
    for (const CollectionOutcome* outcome : outcomes) {
        if (failureSeverityRank(outcome->status) > failureSeverityRank(chosen->status)) {
            chosen = outcome;
        }
    }
    // If the selected status appears across multiple supporting items with inconsistent details, no 'representative code' is chosen.
    bool sameDetail = true;
    for (const CollectionOutcome* outcome : outcomes) {
        if (outcome->status != chosen->status) {
            continue;
        }
        if (outcome->nativeCode != chosen->nativeCode ||
            outcome->nativeCodeDomain != chosen->nativeCodeDomain ||
            outcome->message != chosen->message) {
            sameDetail = false;
        }
    }
    if (sameDetail) {
        return *chosen;
    }
    CollectionOutcome result;
    result.status = chosen->status;
    return result;
}

// S-07: Whether the field can be read in the current context.
FieldAvailability computeAvailability(const CollectionOutcome& outcome,
                                      AccessRequirement access,
                                      const PrivilegeContext& privilege) noexcept {
    if (statusCarriesObservation(outcome.status)) {
        // Observation already obtained; regardless of declared permissions, the read succeeded.
        return FieldAvailability::kReadable;
    }
    switch (outcome.status) {
    case CollectionStatus::kAccessDenied:
        return FieldAvailability::kBlockedByPrivilege;
    case CollectionStatus::kUnsupported:
        return FieldAvailability::kNotSupported;
    case CollectionStatus::kTimeout:
    case CollectionStatus::kError:
        return FieldAvailability::kQueryFailed;
    case CollectionStatus::kNotCollected:
        break;
    case CollectionStatus::kSuccess:
    case CollectionStatus::kPartial:
        // Already returned above; these two branches exist solely to ensure the switch covers all enum values.
        return FieldAvailability::kReadable;
    }

    // NotCollected: If the declared access requirements can explain why it didn't run, state that clearly instead of vaguely saying 'no data'.
    // S-07: System accesses its own door. Substituting SYSTEM/TCB with administrator causes this category to vanish entirely; with an
    // administrator present, a field truly requiring SYSTEM is misreported as 'simply not running' rather than 'insufficient permissions'.
    switch (access) {
    case AccessRequirement::kSystem:
        if (privilege.system != TriState::kYes) {
            return FieldAvailability::kBlockedByPrivilege;
        }
        break;
    case AccessRequirement::kAdministrator:
        if (privilege.administrator != TriState::kYes) {
            return FieldAvailability::kBlockedByPrivilege;
        }
        break;
    case AccessRequirement::kKswordDriver:
        if (privilege.kswordDriverLoaded != TriState::kYes) {
            return FieldAvailability::kBlockedByDriver;
        }
        break;
    case AccessRequirement::kUnknown:
    case AccessRequirement::kNone:
        break;
    }
    return FieldAvailability::kNotCollected;
}

} // namespace

// ---------------------------------------------------------------------------
// Enum names
// ---------------------------------------------------------------------------

const char* triStateName(TriState value) noexcept {
    switch (value) {
    case TriState::kUnknown: return "Unknown";
    case TriState::kNo:      return "No";
    case TriState::kYes:     return "Yes";
    }
    return "Unknown";
}

bool triStateIsDefinite(TriState value) noexcept {
    return value == TriState::kYes || value == TriState::kNo;
}

const char* securityCapabilityName(SecurityCapabilityId capability) noexcept {
    switch (capability) {
    case SecurityCapabilityId::kUnknown:                        return "Unknown";
    case SecurityCapabilityId::kVirtualizationBasedSecurity:     return "VirtualizationBasedSecurity";
    case SecurityCapabilityId::kHypervisorEnforcedCodeIntegrity: return "HypervisorEnforcedCodeIntegrity";
    case SecurityCapabilityId::kCredentialGuard:                 return "CredentialGuard";
    case SecurityCapabilityId::kSystemGuardSecureLaunch:         return "SystemGuardSecureLaunch";
    case SecurityCapabilityId::kKernelDmaProtection:             return "KernelDmaProtection";
    case SecurityCapabilityId::kSecureBoot:                      return "SecureBoot";
    case SecurityCapabilityId::kTpmPresence:                     return "TpmPresence";
    case SecurityCapabilityId::kTpmReadiness:                    return "TpmReadiness";
    case SecurityCapabilityId::kMeasuredBootLog:                 return "MeasuredBootLog";
    case SecurityCapabilityId::kKernelModeCodeIntegrityPolicy:   return "KernelModeCodeIntegrityPolicy";
    case SecurityCapabilityId::kUserModeCodeIntegrityPolicy:     return "UserModeCodeIntegrityPolicy";
    case SecurityCapabilityId::kTestSigning:                     return "TestSigning";
    }
    return "Unknown";
}

const char* securityDimensionName(SecurityDimension dimension) noexcept {
    switch (dimension) {
    case SecurityDimension::kHardwareSupport: return "HardwareSupport";
    case SecurityDimension::kConfigured:      return "Configured";
    case SecurityDimension::kRunning:         return "Running";
    }
    return "HardwareSupport";
}

const char* deviceGuardServiceName(DeviceGuardService service) noexcept {
    switch (service) {
    case DeviceGuardService::kUnknown:                         return "Unknown";
    case DeviceGuardService::kNone:                            return "None";
    case DeviceGuardService::kCredentialGuard:                 return "CredentialGuard";
    case DeviceGuardService::kHypervisorEnforcedCodeIntegrity: return "HypervisorEnforcedCodeIntegrity";
    case DeviceGuardService::kSystemGuardSecureLaunch:         return "SystemGuardSecureLaunch";
    case DeviceGuardService::kSmmFirmwareMeasurement:          return "SmmFirmwareMeasurement";
    }
    return "Unknown";
}

const char* vbsStatusName(VbsStatus status) noexcept {
    switch (status) {
    case VbsStatus::kUnknown:           return "Unknown";
    case VbsStatus::kDisabled:          return "Disabled";
    case VbsStatus::kEnabledNotRunning: return "EnabledNotRunning";
    case VbsStatus::kEnabledAndRunning: return "EnabledAndRunning";
    }
    return "Unknown";
}

const char* securityPropertyName(SecurityProperty property) noexcept {
    switch (property) {
    case SecurityProperty::kUnknown:                   return "Unknown";
    case SecurityProperty::kNone:                      return "None";
    case SecurityProperty::kBaseVirtualizationSupport: return "BaseVirtualizationSupport";
    case SecurityProperty::kSecureBoot:                return "SecureBoot";
    case SecurityProperty::kDmaProtection:             return "DmaProtection";
    case SecurityProperty::kSecureMemoryOverwrite:     return "SecureMemoryOverwrite";
    case SecurityProperty::kNxProtections:             return "NxProtections";
    case SecurityProperty::kSmmMitigations:            return "SmmMitigations";
    case SecurityProperty::kModeBasedExecutionControl: return "ModeBasedExecutionControl";
    case SecurityProperty::kApicVirtualization:        return "ApicVirtualization";
    }
    return "Unknown";
}

const char* codeIntegrityEnforcementName(CodeIntegrityEnforcement enforcement) noexcept {
    switch (enforcement) {
    case CodeIntegrityEnforcement::kUnknown:  return "Unknown";
    case CodeIntegrityEnforcement::kOff:      return "Off";
    case CodeIntegrityEnforcement::kAudit:    return "Audit";
    case CodeIntegrityEnforcement::kEnforced: return "Enforced";
    }
    return "Unknown";
}

const char* fieldFreshnessName(FieldFreshness freshness) noexcept {
    switch (freshness) {
    case FieldFreshness::kUnknown:          return "Unknown";
    case FieldFreshness::kCurrent:          return "Current";
    case FieldFreshness::kHistorical:       return "Historical";
    case FieldFreshness::kDifferentMachine: return "DifferentMachine";
    }
    return "Unknown";
}

const char* accessRequirementName(AccessRequirement requirement) noexcept {
    switch (requirement) {
    case AccessRequirement::kUnknown:       return "Unknown";
    case AccessRequirement::kNone:          return "None";
    case AccessRequirement::kAdministrator: return "Administrator";
    case AccessRequirement::kSystem:        return "System";
    case AccessRequirement::kKswordDriver:  return "KswordDriver";
    }
    return "Unknown";
}

const char* fieldAvailabilityName(FieldAvailability availability) noexcept {
    switch (availability) {
    case FieldAvailability::kUnknown:            return "Unknown";
    case FieldAvailability::kReadable:           return "Readable";
    case FieldAvailability::kBlockedByPrivilege: return "BlockedByPrivilege";
    case FieldAvailability::kBlockedByDriver:    return "BlockedByDriver";
    case FieldAvailability::kNotSupported:       return "NotSupported";
    case FieldAvailability::kQueryFailed:        return "QueryFailed";
    case FieldAvailability::kNotCollected:       return "NotCollected";
    }
    return "Unknown";
}

const char* capabilityConstraintKindName(CapabilityConstraintKind kind) noexcept {
    switch (kind) {
    case CapabilityConstraintKind::kUnknown:              return "Unknown";
    case CapabilityConstraintKind::kVendorUnsupported:    return "VendorUnsupported";
    case CapabilityConstraintKind::kHardwareUnsupported:  return "HardwareUnsupported";
    case CapabilityConstraintKind::kDriverMissing:        return "DriverMissing";
    case CapabilityConstraintKind::kProfileMissing:       return "ProfileMissing";
    case CapabilityConstraintKind::kSecurityConfiguration: return "SecurityConfiguration";
    case CapabilityConstraintKind::kPrivilegeInsufficient: return "PrivilegeInsufficient";
    case CapabilityConstraintKind::kQueryUnavailable:     return "QueryUnavailable";
    }
    return "Unknown";
}

const char* supportClaimStatusName(SupportClaimStatus status) noexcept {
    switch (status) {
    case SupportClaimStatus::kBlocked:           return "Blocked";
    case SupportClaimStatus::kPartiallyVerified: return "PartiallyVerified";
    case SupportClaimStatus::kVerified:          return "Verified";
    }
    return "Blocked";
}

// ---------------------------------------------------------------------------
// S-01: Enum interpretation. If unrecognized, treat as unknown — always preserve rawCode and leave normalizedName empty.
// ---------------------------------------------------------------------------

DeviceGuardServiceValue interpretDeviceGuardService(const RawObservation& raw) {
    DeviceGuardServiceValue value;
    if (!raw.numeric.present) {
        // The source does not provide a numeric encoding; we do not guess the text, as guessing incorrectly is worse than not guessing.
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.service = DeviceGuardService::kNone; break;
    case 1U: value.service = DeviceGuardService::kCredentialGuard; break;
    case 2U: value.service = DeviceGuardService::kHypervisorEnforcedCodeIntegrity; break;
    case 3U: value.service = DeviceGuardService::kSystemGuardSecureLaunch; break;
    case 4U: value.service = DeviceGuardService::kSmmFirmwareMeasurement; break;
    default:
        // New service codes added in newer Windows versions: preserve original values, leave interpretation empty, and UI displays 'Unknown Enum N'.
        value.service = DeviceGuardService::kUnknown;
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = makeInterpretation(raw, true, deviceGuardServiceName(value.service));
    return value;
}

VbsStatusValue interpretVbsStatus(const RawObservation& raw) {
    VbsStatusValue value;
    if (!raw.numeric.present) {
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.status = VbsStatus::kDisabled; break;
    case 1U: value.status = VbsStatus::kEnabledNotRunning; break;
    case 2U: value.status = VbsStatus::kEnabledAndRunning; break;
    default:
        value.status = VbsStatus::kUnknown;
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = makeInterpretation(raw, true, vbsStatusName(value.status));
    return value;
}

void vbsStatusToDimensions(VbsStatus status, TriState& configured, TriState& running) noexcept {
    switch (status) {
    case VbsStatus::kDisabled:
        configured = TriState::kNo;
        running = TriState::kNo;
        return;
    case VbsStatus::kEnabledNotRunning:
        // S-01 key separation: configured is Yes, but running is not. Under no circumstances should running be set to Yes here.
        configured = TriState::kYes;
        running = TriState::kNo;
        return;
    case VbsStatus::kEnabledAndRunning:
        configured = TriState::kYes;
        running = TriState::kYes;
        return;
    case VbsStatus::kUnknown:
        break;
    }
    // Unrecognized status code: keep both dimensions unknown, never default to "off".
    configured = TriState::kUnknown;
    running = TriState::kUnknown;
}

SecurityPropertyValue interpretSecurityProperty(const RawObservation& raw) {
    SecurityPropertyValue value;
    if (!raw.numeric.present) {
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.property = SecurityProperty::kNone; break;
    case 1U: value.property = SecurityProperty::kBaseVirtualizationSupport; break;
    case 2U: value.property = SecurityProperty::kSecureBoot; break;
    case 3U: value.property = SecurityProperty::kDmaProtection; break;
    case 4U: value.property = SecurityProperty::kSecureMemoryOverwrite; break;
    case 5U: value.property = SecurityProperty::kNxProtections; break;
    case 6U: value.property = SecurityProperty::kSmmMitigations; break;
    case 7U: value.property = SecurityProperty::kModeBasedExecutionControl; break;
    case 8U: value.property = SecurityProperty::kApicVirtualization; break;
    default:
        value.property = SecurityProperty::kUnknown;
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = makeInterpretation(raw, true, securityPropertyName(value.property));
    return value;
}

CodeIntegrityEnforcementValue interpretCodeIntegrityEnforcement(const RawObservation& raw) {
    CodeIntegrityEnforcementValue value;
    if (!raw.numeric.present) {
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.enforcement = CodeIntegrityEnforcement::kOff; break;
    case 1U: value.enforcement = CodeIntegrityEnforcement::kAudit; break;
    case 2U: value.enforcement = CodeIntegrityEnforcement::kEnforced; break;
    default:
        value.enforcement = CodeIntegrityEnforcement::kUnknown;
        value.interpretation = makeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = makeInterpretation(raw, true, codeIntegrityEnforcementName(value.enforcement));
    return value;
}

// ---------------------------------------------------------------------------
// S-02: Freshness
// ---------------------------------------------------------------------------

FieldFreshness classifyFieldFreshness(const CaptureWindow& field,
                                      const CaptureWindow& current) noexcept {
    // Check the machine ID first: if it is not the same machine, comparing startup cycles is meaningless.
    if (!field.machineId.empty() && !current.machineId.empty() && field.machineId != current.machineId) {
        return FieldFreshness::kDifferentMachine;
    }
    // Missing bootId means we cannot determine the state; do not optimistically assume it is 'this boot'.
    if (field.bootId.empty() || current.bootId.empty()) {
        return FieldFreshness::kUnknown;
    }
    return (field.bootId == current.bootId) ? FieldFreshness::kCurrent : FieldFreshness::kHistorical;
}

bool freshnessUsableAsCurrent(FieldFreshness freshness) noexcept {
    return freshness == FieldFreshness::kCurrent;
}

// ---------------------------------------------------------------------------
// FieldAssessment
// ---------------------------------------------------------------------------

std::string FieldAssessment::describe() const {
    std::string text;
    const auto kAppend = [&text](const std::string& piece) {
        if (!text.empty()) {
            text += ";";
        }
        text += piece;
    };
    kAppend(fact("field", textOrUnknown(fieldId)));
    kAppend(fact("query", textOrUnknown(queryEntry)));
    kAppend(fact("collector", textOrUnknown(source.collectorId)));
    kAppend(fact("origin", sourceOriginName(source.origin)));
    kAppend(fact("boot", textOrUnknown(window.bootId)));
    kAppend(fact("status", collectionStatusName(outcome.status)));
    kAppend(fact("nativeDomain", textOrUnknown(outcome.nativeCodeDomain)));
    kAppend(fact("nativeCode", codeOrUnknown(outcome.nativeCode)));
    // S-02: Outputs raw values and normalized interpretations side-by-side; normalization does not overwrite the original value.
    kAppend(fact("raw", textOrUnknown(raw.text)));
    kAppend(fact("rawNumeric", codeOrUnknown(raw.numeric)));
    kAppend(fact("normalized",
                interpretation.recognized ? textOrUnknown(interpretation.normalizedName)
                                          : std::string("unrecognized")));
    kAppend(fact("interpretedRawCode", codeOrUnknown(interpretation.rawCode)));
    kAppend(fact("access", accessRequirementName(access)));
    kAppend(fact("availability", fieldAvailabilityName(availability)));
    kAppend(fact("freshness", fieldFreshnessName(freshness)));
    return text;
}

const DimensionResult& CapabilityState::dimension(SecurityDimension which) const noexcept {
    switch (which) {
    case SecurityDimension::kHardwareSupport: return hardwareSupport;
    case SecurityDimension::kConfigured:      return configured;
    case SecurityDimension::kRunning:         return running;
    }
    return hardwareSupport;
}

// ---------------------------------------------------------------------------
// S-04: WDAC / Code Integrity
// ---------------------------------------------------------------------------

std::size_t CodeIntegrityAssessment::auditPolicyCount() const noexcept {
    std::size_t count = 0;
    for (const CodeIntegrityPolicyView& policy : effectivePolicies) {
        if (policy.enforcement == CodeIntegrityEnforcement::kAudit) {
            ++count;
        }
    }
    return count;
}

std::size_t CodeIntegrityAssessment::enforcedPolicyCount() const noexcept {
    std::size_t count = 0;
    for (const CodeIntegrityPolicyView& policy : effectivePolicies) {
        if (policy.enforcement == CodeIntegrityEnforcement::kEnforced) {
            ++count;
        }
    }
    return count;
}

namespace {

CodeIntegrityPolicyView makePolicyView(const CodeIntegrityPolicyRecord& record,
                                       std::vector<std::string>& limitations) {
    CodeIntegrityPolicyView view;
    view.policyId = record.policyId;
    view.friendlyName = record.friendlyName;
    view.basePolicy = record.basePolicy;
    view.sourceFieldId = record.sourceFieldId;
    const CodeIntegrityEnforcementValue kValue = interpretCodeIntegrityEnforcement(record.enforcementRaw);
    view.enforcement = kValue.enforcement;
    view.enforcementInterpretation = kValue.interpretation;
    if (!kValue.interpretation.recognized &&
        (record.enforcementRaw.numeric.present || !record.enforcementRaw.text.empty())) {
        addKey(limitations, security_limitation_keys::kUnknownEnumPreserved);
    }
    return view;
}

} // namespace

CodeIntegrityAssessment evaluateCodeIntegrity(const CodeIntegrityInput& input) {
    CodeIntegrityAssessment assessment;
    assessment.configuredOutcome = input.configuredOutcome;
    assessment.effectiveOutcome = input.effectiveOutcome;
    assessment.configuredPolicyKnown = statusCarriesObservation(input.configuredOutcome.status);
    assessment.effectivePolicyKnown = statusCarriesObservation(input.effectiveOutcome.status);

    // Configured and effective policy lists are maintained separately. If a query fails to carry an observed list, the list remains
    // empty; a policy list returned from a failed query is not an observation and cannot replace a list from another scope (S-04).
    if (assessment.configuredPolicyKnown) {
        assessment.configuredPolicies.reserve(input.configuredPolicies.size());
        for (const CodeIntegrityPolicyRecord& record : input.configuredPolicies) {
            assessment.configuredPolicies.push_back(makePolicyView(record, assessment.limitationKeys));
        }
    } else {
        addKey(assessment.limitationKeys, security_limitation_keys::kConfiguredPolicyUnknown);
    }

    if (assessment.effectivePolicyKnown) {
        assessment.effectivePolicies.reserve(input.effectivePolicies.size());
        for (const CodeIntegrityPolicyRecord& record : input.effectivePolicies) {
            assessment.effectivePolicies.push_back(makePolicyView(record, assessment.limitationKeys));
        }
    } else {
        addKey(assessment.limitationKeys, security_limitation_keys::kEffectivePolicyUnknown);
    }

    // Kernel-mode and user-mode execution states are independent attributes; evaluate each outcome separately.
    if (statusCarriesObservation(input.kernelModeOutcome.status)) {
        const CodeIntegrityEnforcementValue kValue = interpretCodeIntegrityEnforcement(input.kernelModeRaw);
        assessment.kernelModeEnforcement = kValue.enforcement;
        assessment.kernelModeInterpretation = kValue.interpretation;
        if (!kValue.interpretation.recognized) {
            addKey(assessment.limitationKeys, security_limitation_keys::kUnknownEnumPreserved);
        }
    } else {
        // Query failure: status remains Unknown, but the raw value is preserved as-is (S-02).
        assessment.kernelModeInterpretation = makeInterpretation(input.kernelModeRaw, false, "");
    }

    if (statusCarriesObservation(input.userModeOutcome.status)) {
        const CodeIntegrityEnforcementValue kValue = interpretCodeIntegrityEnforcement(input.userModeRaw);
        assessment.userModeEnforcement = kValue.enforcement;
        assessment.userModeInterpretation = kValue.interpretation;
        if (!kValue.interpretation.recognized) {
            addKey(assessment.limitationKeys, security_limitation_keys::kUnknownEnumPreserved);
        }
    } else {
        assessment.userModeInterpretation = makeInterpretation(input.userModeRaw, false, "");
    }

    sortUniqueKeys(assessment.limitationKeys);
    return assessment;
}

ImageLoadAssessment evaluateImageLoad(const ImageLoadInput& input) {
    ImageLoadAssessment assessment;
    assessment.imagePath = input.imagePath;
    assessment.signatureOutcome = input.signatureOutcome;
    assessment.policyDecisionOutcome = input.policyDecisionOutcome;

    // S-04: "Signature valid" does not equal "currently allowed to load by policy". Each field only recognizes its own
    // outcome. This function contains no line that writes to signatureValid when determining allowedByCurrentPolicy.
    assessment.signatureValid = statusCarriesObservation(input.signatureOutcome.status)
                                    ? input.signatureValid
                                    : TriState::kUnknown;
    assessment.allowedByCurrentPolicy = statusCarriesObservation(input.policyDecisionOutcome.status)
                                            ? input.policyAllowsLoad
                                            : TriState::kUnknown;
    if (assessment.allowedByCurrentPolicy == TriState::kUnknown) {
        addKey(assessment.limitationKeys, security_limitation_keys::kPolicyDecisionUnknown);
    }
    sortUniqueKeys(assessment.limitationKeys);
    return assessment;
}

// ---------------------------------------------------------------------------
// S-06: Capability constraints
// ---------------------------------------------------------------------------

bool isStatementOnlyConstraintKey(std::string_view key) noexcept {
    if (key.empty()) {
        return false;
    }
    const std::vector<KeyToken> kTokens = splitKeyTokens(key);
    if (kTokens.empty()) {
        return false;
    }
    // Single words allow derivations (suggestions and remediations both start with action verbs); concatenated
    // multi-word phrases must match exactly, otherwise 'turnedoff' would be mistaken for 'turnoff'.
    const auto kHits = [](const std::string& candidate, std::string_view word, std::size_t n) {
        if (candidate.size() < word.size() || candidate.compare(0, word.size(), word) != 0) {
            return false;
        }
        return n == 0U || candidate.size() == word.size();
    };

    for (std::size_t i = 0; i < kTokens.size(); ++i) {
        std::string joined;
        std::string stemmed;
        // Join at most three adjacent words once to cover action phrases like "turn-off",
        // "please-turn", or "how-to-fix" that are split by delimiters or camelCase. Join both the lemma
        // and the stem separately: the lemma catches "turn-off", and the stem catches "turningOff".
        for (std::size_t n = 0; n < 3U && (i + n) < kTokens.size(); ++n) {
            joined += kTokens[i + n].text;
            stemmed += kTokens[i + n].stem;
            for (const ActionWordEntry& entry : kActionWords) {
                if (!kHits(joined, entry.word, n) && !kHits(stemmed, entry.word, n)) {
                    continue;
                }
                // Persuasive words have no tense exemption: regardless of their form, they remain suggestions.
                if (entry.kind == ActionWordClass::kVerb && actionHitIsStatement(kTokens, i, i + n)) {
                    continue;
                }
                return false;
            }
        }
    }
    return true;
}

bool KswordCapabilityExplanation::mayStart() const noexcept {
    // S-06 Condition: "Capabilities that cannot run must not start." Unknown is also not allowed.
    return available == TriState::kYes;
}

KswordCapabilityExplanation explainKswordCapability(const KswordCapabilityInput& input,
                                                    const std::vector<FieldAssessment>& fields) {
    KswordCapabilityExplanation explanation;
    explanation.capabilityId = input.capabilityId;

    bool anyAccepted = false;
    bool anyUnaccepted = false;
    explanation.constraints.reserve(input.constraints.size());
    for (const KswordCapabilityConstraint& constraint : input.constraints) {
        KswordCapabilityConstraintView view;
        view.kind = constraint.kind;
        view.constraintKey = constraint.constraintKey;
        view.sourceFieldId = constraint.sourceFieldId;
        view.observed = constraint.observed;

        const auto kFound = std::find_if(fields.begin(), fields.end(),
                                        [&constraint](const FieldAssessment& field) {
                                            return field.fieldId == constraint.sourceFieldId;
                                        });
        view.backed = (kFound != fields.end()) && kFound->carriesObservation;

        const bool kStatementOnly = isStatementOnlyConstraintKey(constraint.constraintKey);
        if (!kStatementOnly) {
            // This key instructs the user. Reject and log it, preventing it from entering the results.
            explanation.rejectedConstraintKeys.push_back(constraint.constraintKey);
            addKey(explanation.limitationKeys, security_limitation_keys::kConstraintNonStatement);
        } else if (!view.backed) {
            addKey(explanation.limitationKeys, security_limitation_keys::kConstraintUnbacked);
        }

        view.accepted = kStatementOnly && view.backed;
        if (view.accepted) {
            anyAccepted = true;
        } else {
            anyUnaccepted = true;
        }
        explanation.constraints.push_back(std::move(view));
    }

    const bool kAvailabilityObserved = statusCarriesObservation(input.availabilityOutcome.status);
    if (anyAccepted) {
        // A documented constraint implies unavailability. If the source simultaneously claims 'available', that is a contradiction—take
        // the constrained side, because capabilities that cannot run due to conditional requirements will not start.
        explanation.available = TriState::kNo;
        if (kAvailabilityObserved && input.observedAvailable == TriState::kYes) {
            addKey(explanation.limitationKeys, security_limitation_keys::kConstraintConflict);
        }
    } else if (anyUnaccepted && kAvailabilityObserved && input.observedAvailable == TriState::kYes) {
        // Constraints are present, but none can be determined (key rejected / source field not captured / field not referenced).
        // These constraints represent the side that blocks capabilities: if their evidence is not collected, it means the status is
        // **indeterminate**. We cannot allow the source's claimed "available" status to pass through via fall-through to enable the
        // capability. Doing so would equate to "inferring normalcy from lack of evidence," which is the most easily bypassed loophole
        // in S-06's condition that "capabilities that cannot run must not start." Fallback to Unknown, keeping mayStart() as false.
        explanation.available = TriState::kUnknown;
        addKey(explanation.limitationKeys, security_limitation_keys::kConstraintIndeterminate);
    } else if (kAvailabilityObserved) {
        // Accept the claim of "No" as-is: that is positive evidence of unavailability; converting it to Unknown would lose information.
        explanation.available = input.observedAvailable;
    } else {
        // No constraints and no observations mean unknown. Unknown does not equal available.
        explanation.available = TriState::kUnknown;
    }

    sortUniqueKeys(explanation.limitationKeys);
    return explanation;
}

// ---------------------------------------------------------------------------
// S-08: Actual configuration list
// ---------------------------------------------------------------------------

SupportClaim evaluateSupportClaim(const std::vector<VerifiedConfiguration>& configurations) {
    SupportClaim claim;
    for (const VerifiedConfiguration& configuration : configurations) {
        // A configuration is valid only if fully recorded: build raw string, evidence field ID, VBS running status, and driver load status.
        const bool kComplete = !configuration.configurationId.empty() &&
                              !configuration.osBuildRaw.empty() &&
                              !configuration.evidenceFieldId.empty() &&
                              triStateIsDefinite(configuration.vbsRunning) &&
                              triStateIsDefinite(configuration.kswordDriverLoaded);
        if (!kComplete) {
            claim.rejectedConfigurationIds.push_back(configuration.configurationId);
            continue;
        }
        claim.acceptedConfigurationIds.push_back(configuration.configurationId);
        if (configuration.vbsRunning == TriState::kNo) {
            claim.baselineConfigurationVerified = true;
        } else if (triStateIsDefinite(configuration.hvciRunning)) {
            // VBS requires the HVCI state to be fixed; otherwise, it is unclear which configuration is being verified.
            claim.vbsConfigurationVerified = true;
        } else {
            claim.rejectedConfigurationIds.push_back(configuration.configurationId);
            claim.acceptedConfigurationIds.pop_back();
        }
    }

    if (claim.baselineConfigurationVerified && claim.vbsConfigurationVerified) {
        claim.status = SupportClaimStatus::kVerified;
    } else if (claim.baselineConfigurationVerified || claim.vbsConfigurationVerified) {
        claim.status = SupportClaimStatus::kPartiallyVerified;
        addKey(claim.limitationKeys, security_limitation_keys::kSupportClaimIncomplete);
    } else {
        // Empty lists also go through here: no record means no verification, resulting in BLOCKED.
        claim.status = SupportClaimStatus::kBlocked;
        addKey(claim.limitationKeys, security_limitation_keys::kSupportClaimBlocked);
    }
    sortUniqueKeys(claim.limitationKeys);
    return claim;
}

// ---------------------------------------------------------------------------
// Top-level evaluation
// ---------------------------------------------------------------------------

namespace {

using FieldIndex = std::unordered_map<std::string, std::size_t>;

// When the same fieldId appears twice, the index stores this sentinel value.
constexpr std::size_t kAmbiguousFieldIndex = static_cast<std::size_t>(-1);

const FieldAssessment* lookupField(const std::vector<FieldAssessment>& fields,
                                   const FieldIndex& index,
                                   const std::string& fieldId) {
    if (fieldId.empty()) {
        return nullptr;
    }
    const auto kFound = index.find(fieldId);
    if (kFound == index.end()) {
        return nullptr;
    }
    if (kFound->second == kAmbiguousFieldIndex) {
        // S-02: A duplicate fieldId means it is unclear which assertion it refers to. Choosing the first or last one
        // would cause the same input to yield different conclusions when reordered, and SourceClaimView.sourceGroup
        // would record the value under a collector that never provided it. Ambiguous IDs are treated as unresolvable;
        // assertions referencing them degrade to unsupported (value remains Unknown and is marked kClaimUnbacked).
        return nullptr;
    }
    return &fields[kFound->second];
}

DimensionBuildResult buildDimension(SecurityCapabilityId capability,
                                    SecurityDimension dimension,
                                    const SecurityStateInput& input,
                                    const std::vector<FieldAssessment>& fields,
                                    const FieldIndex& index,
                                    std::vector<std::string>& limitations) {
    DimensionBuildResult build;
    build.result.dimension = dimension;

    for (const CapabilityClaim& claim : input.claims) {
        if (claim.capability != capability || claim.dimension != dimension) {
            continue;
        }
        SourceClaimView view;
        view.fieldId = claim.fieldId;
        view.value = claim.value;  // Source assertions preserved as-is; none are dropped in case of conflict.

        const FieldAssessment* field = lookupField(fields, index, claim.fieldId);
        if (field != nullptr) {
            view.backed = true;
            view.sourceGroup = field->source.sourceGroup.empty() ? field->source.collectorId
                                                                 : field->source.sourceGroup;
            view.origin = field->source.origin;
            view.freshness = field->freshness;
            view.carriesObservation = field->carriesObservation;
            view.usableAsCurrent = field->usableAsCurrent;
            build.backingFieldIds.push_back(field->fieldId);
        } else {
            // The assertion points to no field — a conclusion cannot be built on unsupported claims.
            addKey(limitations, security_limitation_keys::kClaimUnbacked);
        }

        if (view.backed && !view.carriesObservation && triStateIsDefinite(claim.value)) {
            // S-01: "Query failure does not imply closure". Here, only record the event and reject the claim without overwriting the source value.
            addKey(limitations, security_limitation_keys::kClaimNotObserved);
        }
        build.result.claims.push_back(std::move(view));
    }

    // Current value: derived only from assertions that are observed and belong to the current boot cycle.
    bool first = true;
    TriState current = TriState::kUnknown;
    std::unordered_set<std::string> groups;
    for (const SourceClaimView& view : build.result.claims) {
        if (!view.usableAsCurrent || !triStateIsDefinite(view.value)) {
            continue;
        }
        ++build.result.definiteClaimCount;
        if (view.sourceGroup.empty()) {
            // When sourceGroup and collectorId are both empty, this evidence is unsigned. Collapsing all unsigned sources
            // into a single empty string group would falsely report 'N independent sources agree' as '1 source' (distorting
            // the independence criterion in F-11). Each unsigned source must be counted separately and explicitly logged.
            groups.insert("\x01unattributed:" + view.fieldId);
            addKey(limitations, security_limitation_keys::kSourceGroupUnattributed);
        } else {
            groups.insert(view.sourceGroup);
        }
        if (first) {
            current = view.value;
            first = false;
        } else if (current != view.value) {
            build.result.conflicted = true;
        }
    }
    build.result.distinctSourceGroupCount = groups.size();
    // S-05: Inconsistency is inconsistency; do not choose on behalf of the caller.
    build.result.value = build.result.conflicted ? TriState::kUnknown : current;

    // S-02: Fixed values across boot cycles are collected separately into historicalValue and are never treated as current values.
    bool historyFirst = true;
    TriState history = TriState::kUnknown;
    bool historyConflict = false;
    for (const SourceClaimView& view : build.result.claims) {
        if (!view.backed || !view.carriesObservation) {
            continue;
        }
        if (view.freshness != FieldFreshness::kHistorical || !triStateIsDefinite(view.value)) {
            continue;
        }
        if (historyFirst) {
            history = view.value;
            historyFirst = false;
        } else if (history != view.value) {
            historyConflict = true;
        }
    }
    // S-05: When the two pre-reboot sources contradict, collapsing historicalValue to Unknown is insufficient—it
    // looks identical to 'no historical evidence' in the report, causing the 'source inconsistency' to vanish.
    build.result.historicalConflicted = historyConflict;
    build.result.historicalValue = historyConflict ? TriState::kUnknown : history;
    if (historyConflict) {
        addKey(limitations, security_limitation_keys::kHistoricalConflict);
    }

    // S-05: pending must be explicitly provided by a source, and that evidence itself must be current and captured.
    for (const PendingActivationEvidence& evidence : input.pendingEvidence) {
        if (evidence.capability != capability || evidence.dimension != dimension) {
            continue;
        }
        const FieldAssessment* field = lookupField(fields, index, evidence.fieldId);
        if (field != nullptr && field->carriesObservation &&
            freshnessUsableAsCurrent(field->freshness)) {
            build.result.pendingActivation = true;
            build.result.pendingEvidenceFieldId = evidence.fieldId;
            break;
        }
    }

    return build;
}

} // namespace

const FieldAssessment* SecurityStateReport::findField(std::string_view fieldId) const noexcept {
    for (const FieldAssessment& field : fields) {
        if (field.fieldId == fieldId) {
            return &field;
        }
    }
    return nullptr;
}

const CapabilityState* SecurityStateReport::findCapability(
    SecurityCapabilityId capability) const noexcept {
    for (const CapabilityState& state : capabilities) {
        if (state.capability == capability) {
            return &state;
        }
    }
    return nullptr;
}

const DimensionConflict* SecurityStateReport::findConflict(
    SecurityCapabilityId capability, SecurityDimension dimension) const noexcept {
    for (const DimensionConflict& conflict : conflicts) {
        if (conflict.capability == capability && conflict.dimension == dimension) {
            return &conflict;
        }
    }
    return nullptr;
}

bool SecurityStateReport::hasLimitation(std::string_view key) const noexcept {
    for (const std::string& limitation : limitationKeys) {
        if (limitation == key) {
            return true;
        }
    }
    return false;
}

SecurityStateReport evaluateSecurityState(const SecurityStateInput& input) {
    SecurityStateReport report;
    std::vector<std::string> limitations;

    // --- 1. Evaluate fields one by one ------------------------------------------------------
    FieldIndex index;
    report.fields.reserve(input.fields.size());
    std::size_t currentObservedFields = 0;
    std::size_t staleObservedFields = 0;
    std::size_t failedFields = 0;
    std::size_t notCollectedFields = 0;
    bool needsAdministrator = false;
    bool needsSystem = false;
    bool needsDriver = false;

    for (const SecurityField& field : input.fields) {
        FieldAssessment assessment;
        assessment.fieldId = field.fieldId;
        assessment.queryEntry = field.queryEntry;
        assessment.source = field.source;
        assessment.window = field.window;
        assessment.outcome = field.outcome;
        assessment.raw = field.raw;                    // S-02: Pass through as-is
        assessment.interpretation = field.interpretation;  // normalize parallel storage; do not overwrite raw.
        assessment.access = field.access;
        assessment.freshness = classifyFieldFreshness(field.window, input.currentWindow);
        assessment.carriesObservation = statusCarriesObservation(field.outcome.status);
        assessment.availability = computeAvailability(field.outcome, field.access, input.privilege);
        assessment.usableAsCurrent =
            assessment.carriesObservation && freshnessUsableAsCurrent(assessment.freshness);

        if (assessment.carriesObservation) {
            // S-02: Successful collection does not imply the current state. Observations spanning boot cycles, machines, or indeterminate boot
            // instances do not contribute to determining 'the current state'. They must be separated from current observations in the ledger;
            // otherwise, a report containing only pre-reboot data would calculate 'full coverage' and erroneously conclude 'no differences found'.
            if (assessment.usableAsCurrent) {
                ++currentObservedFields;
            } else {
                ++staleObservedFields;
            }
        } else if (field.outcome.status == CollectionStatus::kNotCollected) {
            ++notCollectedFields;
        } else {
            ++failedFields;
        }

        switch (assessment.availability) {
        case FieldAvailability::kReadable:
            ++report.readableFieldCount;
            break;
        case FieldAvailability::kBlockedByPrivilege:
        case FieldAvailability::kBlockedByDriver:
            ++report.blockedFieldCount;
            break;
        case FieldAvailability::kUnknown:
        case FieldAvailability::kNotSupported:
        case FieldAvailability::kQueryFailed:
        case FieldAvailability::kNotCollected:
            break;
        }

        switch (assessment.freshness) {
        case FieldFreshness::kHistorical:
            ++report.historicalFieldCount;
            addKey(limitations, security_limitation_keys::kFieldHistorical);
            break;
        case FieldFreshness::kDifferentMachine:
            addKey(limitations, security_limitation_keys::kFieldForeignMachine);
            break;
        case FieldFreshness::kUnknown:
            addKey(limitations, security_limitation_keys::kFieldFreshnessUnknown);
            break;
        case FieldFreshness::kCurrent:
            break;
        }

        // S-01: The caller attempted interpretation but failed to recognize it; the report must indicate 'unknown enum preserved'.
        if (!assessment.interpretation.recognized &&
            (assessment.interpretation.rawCode.present || !assessment.interpretation.rawText.empty())) {
            addKey(limitations, security_limitation_keys::kUnknownEnumPreserved);
        }

        // S-07: Record Administrator and System separately. If combined, "missing SYSTEM" would be reported as "missing
        // Administrator", and in a session that is already an Administrator, nothing would be reported at all.
        if (field.access == AccessRequirement::kAdministrator) {
            needsAdministrator = true;
        }
        if (field.access == AccessRequirement::kSystem) {
            needsSystem = true;
        }
        if (field.access == AccessRequirement::kKswordDriver) {
            needsDriver = true;
        }

        const auto kInserted = index.emplace(assessment.fieldId, report.fields.size());
        if (!kInserted.second) {
            // When the same fieldId appears twice, it is unclear which assertion referencing it applies. This must be reported, and the
            // ID must be marked as ambiguous—ensuring no one points to it is better than randomly pointing to one based on input order.
            addKey(limitations, security_limitation_keys::kFieldDuplicateId);
            kInserted.first->second = kAmbiguousFieldIndex;
        }
        report.fields.push_back(std::move(assessment));
    }

    // S-07: Degradation must be explicitly stated, rather than making the page appear to have 'only these fields'.
    if (needsAdministrator && input.privilege.administrator != TriState::kYes) {
        addKey(limitations, security_limitation_keys::kPrivilegeDegraded);
    }
    if (needsSystem && input.privilege.system != TriState::kYes) {
        addKey(limitations, security_limitation_keys::kSystemPrivilegeDegraded);
    }
    if (needsDriver && input.privilege.kswordDriverLoaded != TriState::kYes) {
        addKey(limitations, security_limitation_keys::kDriverDegraded);
    }

    // --- 2. Capability set: expected + those appearing in assertions -------------------------------
    std::vector<SecurityCapabilityId> order;
    const auto kPushCapability = [&order](SecurityCapabilityId capability) {
        if (std::find(order.begin(), order.end(), capability) == order.end()) {
            order.push_back(capability);
        }
    };
    for (const SecurityCapabilityId kCapability : input.requestedCapabilities) {
        kPushCapability(kCapability);
    }
    for (const CapabilityClaim& claim : input.claims) {
        kPushCapability(claim.capability);
    }

    // --- 3. Evaluate capabilities across four dimensions ------------------------------------------------------
    report.capabilities.reserve(order.size());
    for (const SecurityCapabilityId kCapability : order) {
        CapabilityState state;
        state.capability = kCapability;

        std::vector<std::string> backingFieldIds;
        // Use a hash set for deduplication instead of linear search on a vector: The number of assertions under the same capability is determined
        // by the caller. When enumerating per-policy or per-device, the O(n^2) complexity of std::find would cause second-level freezes.
        std::unordered_set<std::string> backingFieldSeen;
        const SecurityDimension kDimensions[] = {SecurityDimension::kHardwareSupport,
                                                SecurityDimension::kConfigured,
                                                SecurityDimension::kRunning};
        DimensionResult* slots[] = {&state.hardwareSupport, &state.configured, &state.running};
        for (std::size_t i = 0; i < 3U; ++i) {
            DimensionBuildResult build =
                buildDimension(kCapability, kDimensions[i], input, report.fields, index, limitations);
            for (const std::string& fieldId : build.backingFieldIds) {
                if (backingFieldSeen.insert(fieldId).second) {
                    backingFieldIds.push_back(fieldId);
                }
            }
            state.anyClaim = state.anyClaim || !build.result.claims.empty();
            for (const SourceClaimView& view : build.result.claims) {
                if (view.backed && view.carriesObservation) {
                    state.anyBackedObservation = true;
                }
            }
            *slots[i] = std::move(build.result);
        }

        // S-07: Capability-level permissions are derived from their supporting fields, not arbitrarily assigned.
        std::vector<const CollectionOutcome*> outcomes;
        outcomes.reserve(backingFieldIds.size());
        for (const std::string& fieldId : backingFieldIds) {
            const FieldAssessment* field = lookupField(report.fields, index, fieldId);
            if (field == nullptr) {
                continue;
            }
            outcomes.push_back(&field->outcome);
            if (field->access == AccessRequirement::kAdministrator) {
                state.requiresAdministrator = true;
            }
            if (field->access == AccessRequirement::kSystem) {
                state.requiresSystem = true;
            }
            if (field->access == AccessRequirement::kKswordDriver) {
                state.requiresKswordDriver = true;
            }
            if (field->availability == FieldAvailability::kBlockedByPrivilege ||
                field->availability == FieldAvailability::kBlockedByDriver) {
                ++state.blockedFieldCount;
            }
        }
        bool mixedFailures = false;
        state.queryOutcome = aggregateOutcomes(outcomes, &mixedFailures);
        if (mixedFailures) {
            // The summary must explicitly indicate which single failure type was retained; this must be visible in the report.
            addKey(limitations, security_limitation_keys::kOutcomeMixedFailures);
        }

        if (!state.anyClaim) {
            // Expected to be covered but entirely absent in the round: explicitly set to NotCollected and count it
            // in the ledger. Never silently skip it; otherwise, this round will appear 'clean and fully available'.
            ++report.missingCapabilityCount;
            addKey(limitations, security_limitation_keys::kCapabilityNotCollected);
        }

        // S-03: If the measurement log cannot be retrieved, it is Unknown; never output "Measured Boot OK".
        if (kCapability == SecurityCapabilityId::kMeasuredBootLog &&
            state.running.value == TriState::kUnknown) {
            addKey(limitations, security_limitation_keys::kMeasuredBootLogUnknown);
        }

        // --- Conflicts in a separate table: Both current source conflicts and pre-reboot source conflicts must
        // be recorded. If the latter collapses to historicalValue=Unknown, it becomes indistinguishable from
        // 'no historical evidence' in the UI, causing S-05 'display all sources when inconsistent' to fail.
        for (std::size_t i = 0; i < 3U; ++i) {
            const DimensionResult& result = state.dimension(kDimensions[i]);
            if (!result.conflicted && !result.historicalConflicted) {
                continue;
            }
            DimensionConflict conflict;
            conflict.capability = kCapability;
            conflict.dimension = kDimensions[i];
            conflict.claims = result.claims;  // Merge all sources side-by-side without filtering.
            conflict.resolvedValue = TriState::kUnknown;
            conflict.currentConflict = result.conflicted;
            conflict.historicalConflict = result.historicalConflicted;
            conflict.pendingActivation = result.pendingActivation;
            conflict.pendingEvidenceFieldId = result.pendingEvidenceFieldId;
            report.conflicts.push_back(std::move(conflict));
            if (result.conflicted) {
                addKey(limitations, security_limitation_keys::kDimensionConflict);
            }
        }

        report.capabilities.push_back(std::move(state));
    }

    // --- 4. Accounting and Conclusions ------------------------------------------------------ The accounting unit is 'expected evidence
    // items for the current platform security state': one item per field, plus one item per missing capability for the entire round.
    // succeeded counts only **successful observations from the current boot cycle**; observations that were collected successfully but
    // belong to a different boot cycle or a different machine are counted as skipped, as they cannot answer 'what is the current state'.
    CoverageAccount coverage;
    coverage.totalKnown = OptionalU64::of(
        static_cast<std::uint64_t>(input.fields.size() + report.missingCapabilityCount));
    coverage.succeeded = static_cast<std::uint64_t>(currentObservedFields);
    coverage.failed = static_cast<std::uint64_t>(failedFields);
    coverage.skipped = static_cast<std::uint64_t>(notCollectedFields + staleObservedFields +
                                                  report.missingCapabilityCount);

    std::vector<const CollectionOutcome*> allOutcomes;
    allOutcomes.reserve(report.fields.size());
    std::vector<EvidenceEnvelope> fieldEnvelopes;
    fieldEnvelopes.reserve(report.fields.size());
    bool originUniform = !report.fields.empty();
    SourceOrigin commonOrigin = SourceOrigin::kUnknown;
    for (const FieldAssessment& field : report.fields) {
        allOutcomes.push_back(&field.outcome);
        if (&field == &report.fields.front()) {
            commonOrigin = field.source.origin;
        } else if (field.source.origin != commonOrigin) {
            originUniform = false;
        }
        EvidenceEnvelope envelope;
        envelope.source = field.source;
        envelope.window = field.window;
        envelope.outcome = field.outcome;
        envelope.coverage.totalKnown = OptionalU64::of(1U);
        // Same criterion as above: only observations from the current boot cycle count as 'covering' this field.
        envelope.coverage.succeeded = field.usableAsCurrent ? 1U : 0U;
        envelope.coverage.failed = field.carriesObservation ? 0U : 1U;
        envelope.coverage.skipped =
            (field.carriesObservation && !field.usableAsCurrent) ? 1U : 0U;
        envelope.evidenceId = field.fieldId;
        fieldEnvelopes.push_back(std::move(envelope));
    }

    report.envelope.source.collectorId = "s.security.state";
    report.envelope.source.sourceGroup = "s.security.state";
    report.envelope.source.collectorVersion = 1U;
    // When mixing sources, the report-level origin remains Unknown; trust counts by category to indicate
    // origins, and picking a 'primary source' would hide the portion introduced by offline samples (F-11).
    report.envelope.source.origin = originUniform ? commonOrigin : SourceOrigin::kUnknown;
    report.envelope.window = input.currentWindow;
    report.envelope.outcome = aggregateOutcomes(allOutcomes);
    report.envelope.coverage = coverage;
    report.conclusion = report.envelope.deriveConclusion(!report.conflicts.empty());
    report.trust = buildTrustStatement(fieldEnvelopes);

    sortUniqueKeys(limitations);
    report.limitationKeys = std::move(limitations);
    return report;
}

} // namespace ksword::evidence

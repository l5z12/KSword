#pragma once

// Module D: Snapshot comparison and change interpretation.
//
// This is an **entity-level** comparison, not a text-line diff. Snapshots are paired by entity identity, with fields providing old value/new
// value/source/time/evidence reference per item; addresses and sorting do not participate in determining 'whether this object exists'.
//
// Hard rules spanning the entire module (see D-xx comments throughout for the rationale):
//   * D-01: A different selection scope does not mean the object was deleted. A deletion conclusion only holds when "the new snapshot's
//     selection scope completely covers the old snapshot's selection scope"; the reverse applies to additions. An undeclared scope is unknown.
//   * D-02: Identity follows ObjectIdentity. Processes, threads, handles, and connections are instances and are never hard-mapped across boot cycles;
//     drivers, modules, services, and files can be compared by logical identity across boot cycles. When stable matching is impossible, timestamps are used.
//     MatchConfidence::Uncertain: never record a false addition or deletion pair.
//   * D-03: Kernel addresses are normalized to "matching image identity + RVA" only when both sides are confirmed
//     comparable. Same image with different load bases has no difference; same RVA in different versions is not the same code.
//     Missing modules are not normalized.
//   * D-04: When the old snapshot has data but the new snapshot source fails, is unsupported, or is truncated, the
//     conclusion is NotComparable or InsufficientCoverage, never "all objects removed". In the same comparison, partitions
//     that have already been successfully covered are compared normally and are not affected by other partitions.
//   * D-05: The fact of change and the review explanation are two separate fields. The ReviewNote at this level only
//     carries the caller-declared review priority and basis key; the API contains no malicious / threat / risk / suspicious.
//   * D-06: Persist schema with primary/secondary versions. Unknown optional fields are preserved and written back unchanged; unknown primary
//     versions are explicitly rejected. The reader is a pure function that touches no files, so source data is never repaired in-place.
//   * D-07: Masking must use the same replacement value for the same original value within a single export, while different original values
//     must not collide. Both replaced and deleted content must be listed in the manifest. The source snapshot is a const input and must not
//     be overwritten. **Unknown optional fields (those that D-06 promises to write back as-is) must also be masked**; otherwise, sensitive
//     original values hidden within them would be exported as-is, which is explicitly prohibited by D-07 as 'hiding in original fields'.
//
// This file is C++20, Qt-free, and Win32-free, using only the standard library.

#include "EvidenceEnvelope.h"
#include "EvidenceJson.h"
#include "ObjectIdentity.h"
#include "PeImageMap.h"  // Read-only reuse of RvaRange and its interval checks.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace ksword::evidence {

// ---------------------------------------------------------------------------
// D-02: Logical identity of configuration objects.
//
// Objects such as service, rule, and device names persist in the registry or on disk; they remain the same logical object
// after a reboot. Therefore, their identity **does not** include bootId—this is the opposite of ProcessInstanceId.
// ---------------------------------------------------------------------------
struct LogicalObjectId final {
    std::string domain;    // "service" / "rule" / "device" ...; empty means identity is invalid.
    std::string name;      // Domain-unique name
    std::string scopeKey;  // Optional owning scope (policy set / SID / volume); if missing, it degrades gracefully without causing errors.

    IdentityStrength strength() const noexcept;

    // D-02: Case-folding is applied to name/scopeKey here. Service names, registry key names, and SID text are case-insensitive on
    // Windows; the two collectors (SCM and registry enumeration) often provide different casing. This represents a **representation**
    // change, not an object change. Without folding, the two sides would fall into different buckets, directly creating a pair of false
    // add/delete events (D-02 explicitly forbids this). Folding only affects bucketing and does not imply "confirmed as the same object":
    // In matchLogicalObject, two records differing only in case are assigned at most a Candidate status.
    std::string crossSessionKey() const;
};

// If either domain or name is empty -> Candidate (insufficient identity, unified threshold applied).
// name/scopeKey folded differently -> NoMatch (same name but different scopes are two distinct objects).
// Folded to be identical but original case differs -> Candidate: possibly the same, but the two sides are inconsistent;
// insufficient to 'confirm', and absolutely not allowed to generate additions or deletions based on this.
MatchResult matchLogicalObject(const LogicalObjectId& a, const LogicalObjectId& b) noexcept;

// D-02: Identity key for the driver/module at the snapshot layer.
// It folds `imagePath` into a case-insensitive and delimiter-normalized form on top of
// `DriverInstanceId::crossSessionKey()`. Kernel module paths from `PsLoadedModuleList`, SCM, and disk enumeration inherently
// differ in case and `\SystemRoot\` prefix notation; without folding, this would create false additions and deletions.
// Similar to logical identity, folding only affects bucketing: two records with
// different path originals remain only as Candidates in matchDriverInstance.
std::string snapshotDriverKey(const DriverInstanceId& id);

// D-02: Whether this entity type can be compared across boot cycles.
// Instance objects (process/thread/handle/connection/device object) are false — 'absence' across boots is not 'deletion'.
bool kindComparableAcrossBoot(ObjectKind kind) noexcept;

// ---------------------------------------------------------------------------
// D-01: Snapshot selection scope.
// ---------------------------------------------------------------------------
struct SnapshotScope final {
    std::string scopeId;                 // Scope identifier, e.g., "services"; different values on both sides indicate no intersection.
    bool declared = false;               // Whether a selection range has been declared. If not declared, treat as unknown.
    bool wholeDomain = false;            // Claims to cover the entire domain.
    std::vector<std::string> selectors;  // Specific selectors when not global (normalized keys).
};

// Relationship between the scope selections of two snapshots. Naming always uses 'is subset of' to avoid ambiguity between 'wide' and 'narrow'.
enum class ScopeComparability {
    kUnknown,               // At least one side has no declared range; additions and deletions cannot be inferred.
    kIdentical,             // Both ranges are identical.
    kEarlierSubsetOfLater,  // Old ⊂ New: The new snapshot is more comprehensive, allowing detection of deletions but not additions.
    kLaterSubsetOfEarlier,  // New ⊂ Old: can detect additions, cannot detect deletions
    kPartialOverlap,        // Mutually exclusive items — additions and deletions cannot be inferred
    kDisjoint,              // Disjoint
};

const char* scopeComparabilityName(ScopeComparability value) noexcept;

ScopeComparability compareScopes(const SnapshotScope& earlier, const SnapshotScope& later);

// D-01 core criterion: 'Old has new, new has none' is only interpretable as a removal when the new range covers the old range.
bool removalInferable(ScopeComparability value) noexcept;
// Symmetric: Only when the old range covers the new range is "new has old none" allowed to be interpreted as an addition.
bool additionInferable(ScopeComparability value) noexcept;

// D-02: Boot cycle relationship between the two snapshots.
enum class CrossBootComparability {
    kUnknownBoot,    // At least one side lacks a bootId — cannot prove it is the same boot.
    kSameBoot,
    kDifferentBoot,
};

const char* crossBootComparabilityName(CrossBootComparability value) noexcept;

// ---------------------------------------------------------------------------
// field
// ---------------------------------------------------------------------------

// D-07: The sensitive category carried by the field, used for redaction declarations (the value itself does not change comparison semantics).
enum class RedactionClass {
    kNone,
    kUserName,
    kHostname,
    kFilePath,
    kAccountSid,
};

const char* redactionClassName(RedactionClass value) noexcept;
bool parseRedactionClassName(std::string_view text, RedactionClass& out) noexcept;

// D-03: Field comparison semantics. Address fields are never compared by raw value.
enum class FieldSemantics {
    kOpaque,           // Compare by value (text or integer).
    kLoadBaseAddress,  // Image load base address: different base addresses for the same image are not considered a difference.
    kKernelAddress,    // Kernel absolute address: normalized to 'Image Identity + RVA' before comparison.
};

const char* fieldSemanticsName(FieldSemantics value) noexcept;
bool parseFieldSemanticsName(std::string_view text, FieldSemantics& out) noexcept;

// Absent is a distinct state: it is neither an empty string nor 0; comparisons yield only "unknown".
enum class FieldValueKind {
    kAbsent,
    kText,
    kNumber,
};

const char* fieldValueKindName(FieldValueKind value) noexcept;
bool parseFieldValueKindName(std::string_view text, FieldValueKind& out) noexcept;

struct EntityField final {
    std::string name;
    FieldSemantics semantics = FieldSemantics::kOpaque;
    FieldValueKind kind = FieldValueKind::kAbsent;
    std::string text;                              // kind == Text
    OptionalU64 number;                            // kind == Number
    U64Format numberFormat = U64Format::kDecimal;   // Determines display and persistence format only.
    RedactionClass redaction = RedactionClass::kNone;
};

// ---------------------------------------------------------------------------
// D-03: Address normalization materials.
// ---------------------------------------------------------------------------
struct SnapshotModule final {
    std::string moduleId;        // Stable ID used for references within the snapshot.
    DriverInstanceId identity;   // Image identity: pdbSignature or timeDateStamp + imageSize + path
    OptionalU64 imageBase;
    OptionalU64 imageSize;

    // The RVA range covered by this module (reusing PeImageMap's range type). Returns an empty
    // range if the size is unknown or exceeds 32 bits—an empty range contains no RVAs, so all
    // addresses fail to resolve and are never incorrectly treated as 'within this module'.
    RvaRange rvaExtent() const noexcept;
};

// The result of address normalization. Each level must be independently displayable; collapsing them into a single bool is exactly
// D-03: Intended to prohibit ("same RVA in different versions" is treated as "same code").
enum class AddressNormalizationState {
    kNotApplicable,        // This field is not address semantics
    kValueMissing,         // At least one side address is unknown
    kModuleNotFound,       // If the address on at least one side does not fall within any known module -> do not normalize.
    kImageIdentityWeak,    // Images on both sides can only be candidate matches -> not confirmed comparable, not normalized.
    kImageVersionDiffers,  // Two different versions at the same path -> identical RVA does not imply identical code.
    kDifferentModule,      // Parsed to different images on both sides
    kNormalized,           // Confirmed comparable; compared by RVA.
};

const char* addressNormalizationStateName(AddressNormalizationState value) noexcept;

struct AddressNormalization final {
    AddressNormalizationState state = AddressNormalizationState::kNotApplicable;
    std::string earlierModuleId;
    std::string laterModuleId;
    OptionalU64 earlierRva;
    OptionalU64 laterRva;
};

// ---------------------------------------------------------------------------
// snapshot
// ---------------------------------------------------------------------------

// D-01/D-04: A collection partition (typically one per collector), with its own source, status, and coverage accounting.
// The partition is the granularity for D-04 "Partially covered but still independently comparable": a failure in one partition does not affect others.
struct SnapshotPartition final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::kUnknown;
    EvidenceEnvelope envelope;
    bool coversScope = false;  // Whether this partition claims to cover the selection scope of this snapshot.
};

struct SnapshotEntity final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::kUnknown;

    // Identity payload is accessed by kind. Handle/Connection/Device/Service/Unknown are expressed as logical identities at the snapshot
    // layer (instance identities for handles and connections belong to cross-view analysis in the X module, not within D's semantics).
    ProcessInstanceId process;
    ThreadInstanceId thread;
    DriverInstanceId driver;
    FileIdentity file;
    LogicalObjectId logical;

    std::string rawRecordId;      // D-05: Return to source record
    std::size_t displayOrder = 0; // D-02: Used solely to prove 'order changed but objects remained unchanged'.
    std::vector<EntityField> fields;

    // D-06: Unknown optional fields encountered during read are preserved as-is and written back unchanged.
    JsonObject unknownFields;

    // Stable identity key; empty if identity is insufficient. D-02: Driver/module and logical object keys undergo representation
    // normalization (path/name case sensitivity, path separators) first, see snapshotDriverKey / LogicalObjectId.
    std::string identityKey() const;
    std::string candidateKey() const;  // Weak identity deduplication key, valid only within this comparison.
    IdentityStrength strength() const noexcept;
    std::string displayText() const;
};

struct Snapshot final {
    std::string snapshotId;
    EvidenceEnvelope envelope;   // D-01: System/boot identifier, collector version, collection interval
    SnapshotScope scope;
    std::vector<SnapshotPartition> partitions;
    std::vector<SnapshotModule> modules;
    std::vector<SnapshotEntity> entities;

    JsonObject unknownFields;  // D-06: Top-level unknown optional fields.

    const SnapshotPartition* findPartition(std::string_view partitionId) const noexcept;
    const SnapshotModule* findModule(std::string_view moduleId) const noexcept;
};

// ---------------------------------------------------------------------------
// Comparison result
// ---------------------------------------------------------------------------

// The "presence status" of an entity on a given side. Various unknowns are distinct from each other — collapsing into a single "absent" state violates
// the D-04 red line, and conflating "source failure" with "insufficient coverage" is also prohibited by D-04 (as their handling differs completely).
enum class EntitySideState {
    kPresent,              // This side lists this entity
    kAbsentCovered,        // This side collected successfully, the account has positive proof of completeness, and the scope covers it — indeed, nothing is missing.
    kAbsentOutOfScope,     // The selection range on this side does not cover it — it is not 'absent'.
    kUnknownSourceFailed,  // This partition side was not captured, failed, is unsupported, or access was denied.
    kUnknownCoverage,      // This side succeeded but was truncated or the account is insufficient to prove completeness.
    kUnknownCrossBoot,     // D-02: This entity does not compare across boot cycles.
    // D-02: This side has multiple records with the same stable key, so the corresponding record cannot be determined.
    // It is neither absent nor confirmed present; reporting it as present would imply a match between the two sides.
    kUnknownAmbiguousIdentity,
};

const char* entitySideStateName(EntitySideState value) noexcept;

// D-02: Match confidence. Uncertain means "possibly the same, but identity is insufficient to confirm".
enum class MatchConfidence {
    kNoMatch,     // No match, but identity is strong enough that absence itself is meaningful.
    kUncertain,   // Insufficient identity or only candidate evidence — do not claim the same object or claim additions/deletions based on this.
    kConfirmed,   // Stable identity pairing
};

const char* matchConfidenceName(MatchConfidence value) noexcept;

enum class EntityChange {
    kUnchanged,             // Both sides present, all comparable fields match, and no incomparable fields exist.
    kPartiallyComparable,   // Both sides are present, compared fields are consistent, but some fields cannot be compared.
    kModified,              // Present on both sides with at least one field actually changed.
    kAdded,                 // Only present in the new snapshot, and both the range and coverage support the 'addition' conclusion.
    kRemoved,               // Only appears in the old snapshot, and both range and coverage support the 'Removed' conclusion.
    kNotComparable,         // D-04: At least one side unknown / cross-boot / out-of-range — no add/remove conclusion.
    kInsufficientCoverage,  // D-04: Data collected on this side but insufficient coverage to determine.
};

const char* entityChangeName(EntityChange value) noexcept;

enum class FieldChange {
    kUnchanged,
    kNormalizedUnchanged,  // D-03: Original values differ but are identical after normalization (same image, different base address).
    kChanged,
    kUnknown,              // At least one side is unknown — do not treat as a change.
    kNotComparable,        // D-03: Image not comparable / module missing / value representation differs.
};

const char* fieldChangeName(FieldChange value) noexcept;

// D-05: Complete description of a field change. Old value, new value, source, timestamp, and evidence reference are all included here.
struct FieldDelta final {
    std::string name;
    FieldSemantics semantics = FieldSemantics::kOpaque;
    FieldChange change = FieldChange::kUnknown;

    bool earlierKnown = false;
    std::string earlierText;   // Display string; always empty when earlierKnown is false.
    bool laterKnown = false;
    std::string laterText;

    std::string earlierCollectorId;
    std::string laterCollectorId;
    OptionalU64 earlierObservedUtc100ns;
    OptionalU64 laterObservedUtc100ns;
    std::string earlierEvidenceId;
    std::string laterEvidenceId;

    AddressNormalization normalization;
};

// D-05: Review explanation. Stored separately from change facts; defaults to NotAssessed. The engine does not invent priorities;
// it only executes rules declared by the caller. There is no malicious / risk / threat field here, nor will there be.
enum class ReviewPriority {
    kNotAssessed,
    kInformational,
    kNeedsReview,   // Needs human review, not 'malicious'.
};

const char* reviewPriorityName(ReviewPriority value) noexcept;

struct ReviewNote final {
    ReviewPriority priority = ReviewPriority::kNotAssessed;
    std::vector<std::string> reasonKeys;  // i18n key; UI handles translation
};

struct EntityDelta final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::kUnknown;
    std::string identityKey;   // Empty indicates insufficient identity (at this point, candidateKey is non-empty).
    std::string candidateKey;
    IdentityStrength strength = IdentityStrength::kUnusable;
    std::string displayText;

    EntitySideState earlierState = EntitySideState::kUnknownSourceFailed;
    EntitySideState laterState = EntitySideState::kUnknownSourceFailed;
    MatchConfidence matchConfidence = MatchConfidence::kNoMatch;
    EntityChange change = EntityChange::kNotComparable;

    std::vector<FieldDelta> fields;           // Fields with meaningful content (changed/unknown/incomparable).
    std::vector<std::string> limitationKeys;  // Why comparison is not possible

    std::string earlierRawRecordId;
    std::string laterRawRecordId;
    std::string earlierEvidenceId;
    std::string laterEvidenceId;
    OptionalU64 earlierObservedUtc100ns;
    OptionalU64 laterObservedUtc100ns;

    std::size_t earlierDisplayOrder = 0;
    std::size_t laterDisplayOrder = 0;
    bool displayOrderChanged = false;  // D-02: Sort changes are recorded separately without generating additions or deletions.

    ReviewNote review;  // D-05: Mutually non-derivable from the fact fields above.
};

// D-01/D-04: Per-partition accounts. If a partition is absent on one side, it is explicitly
// recorded as NotCollected and included; never treat a full-round absence as if it never happened.
struct PartitionAccount final {
    std::string partitionId;
    ObjectKind kind = ObjectKind::kUnknown;
    bool earlierPresent = false;
    bool laterPresent = false;
    CollectionStatus earlierStatus = CollectionStatus::kNotCollected;
    CollectionStatus laterStatus = CollectionStatus::kNotCollected;
    bool earlierUsableForAbsence = false;  // Whether this side qualifies to support 'definitely absent'.
    bool laterUsableForAbsence = false;
    bool comparable = false;               // Both sides carry observations
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;
    std::size_t entitiesCompared = 0;
    std::size_t entitiesNotComparable = 0;
    std::vector<std::string> limitationKeys;
};

struct SnapshotComparison final {
    ScopeComparability scope = ScopeComparability::kUnknown;
    CrossBootComparability boot = CrossBootComparability::kUnknownBoot;

    std::vector<EntityDelta> deltas;         // Stably sort by (partitionId, key).
    std::vector<PartitionAccount> partitions;
    TrustStatement trust;
    AnalysisConclusion conclusion = AnalysisConclusion::kNoEvidence;

    std::size_t unchangedCount = 0;
    std::size_t partiallyComparableCount = 0;
    std::size_t modifiedCount = 0;
    std::size_t addedCount = 0;
    std::size_t removedCount = 0;
    std::size_t notComparableCount = 0;
    std::size_t insufficientCoverageCount = 0;

    // Internal consistency self-check. If false, the counting method does not align with itemized conclusions; the UI must degrade its display.
    // Criteria are defined in checkComparisonSelfConsistency—it only reads the published fields of this structure, not
    // the intermediate variables that generated them; otherwise, the 'self-check' would merely copy the same variable.
    bool selfCheckPassed = true;

    std::vector<std::string> limitationKeys;
};

// Independently review an already produced comparison result: recalculate counts item by item, verify the partition ledger
// for each addition/deletion, and ensure each conclusion is compatible with its field list. compareSnapshots uses this to
// populate selfCheckPassed; callers may also re-verify results after deserialization or cross-process transmission.
//
// Expose this function separately from compareSnapshots so an independently constructed counterexample can make the
// predicate return false. Otherwise, the invariant cannot be falsified by a test, as happened in the old implementation.
bool checkComparisonSelfConsistency(const SnapshotComparison& comparison);

// D-05: Review rules declared by the caller. An empty partitionId/fieldName indicates "any".
struct ReviewRule final {
    std::string partitionId;
    std::string fieldName;
    ReviewPriority priority = ReviewPriority::kInformational;
    std::string reasonKey;
};

struct SnapshotCompareOptions final {
    std::vector<ReviewRule> reviewRules;
    bool emitUnchanged = true;  // When false, Unchanged entries are not retained in the result (count remains accurate).
};

SnapshotComparison compareSnapshots(const Snapshot& earlier,
                                    const Snapshot& later,
                                    const SnapshotCompareOptions& options = SnapshotCompareOptions{});

// ---------------------------------------------------------------------------
// D-08: Expected change list verification (offline half).
//
// The target environment is responsible for 'modifying only owned objects, capturing pre/post snapshots, and then cleaning up'; this
// layer only verifies that the results exactly contain the pre-declared changes. Undeclared changes are listed but not attributed.
// ---------------------------------------------------------------------------
struct ExpectedChange final {
    std::string partitionId;
    // Choice: Strong identity uses identityKey (= EntityDelta::identityKey); weak identity objects lack a
    // cross-session primary key and must use candidateKey (= EntityDelta::candidateKey) within this comparison only.
    // A declaration where both are empty **does not point to any object** and is recorded as invalid rather than arbitrarily assigned.
    std::string identityKey;
    std::string candidateKey;
    EntityChange change = EntityChange::kModified;
    std::vector<std::string> fieldNames;
};

// D-08: Verification conclusion. Three-state instead of a bool: "nothing declared" and "all declared items observed"
// must never be the same value, or a verification report with an empty checklist would automatically turn green.
enum class ExpectationOutcome {
    kNotAssessed,  // No declaration or no available evidence for this comparison — cannot verify.
    kSatisfied,    // Every declaration is observed in a comparison with evidence.
    kViolated,     // At least one assertion was not observed, or the assertion itself is unverifiable.
};

const char* expectationOutcomeName(ExpectationOutcome value) noexcept;

struct ExpectationCheck final {
    ExpectationOutcome outcome = ExpectationOutcome::kNotAssessed;
    std::vector<std::string> satisfied;
    std::vector<std::string> missing;         // Declared but not observed.
    std::vector<std::string> unexpectedKeys;  // Observed but undeclared; record only.
    // The declaration cannot be checked: the identity key is empty, or its partition is not comparable in this comparison.
    // Elements are the partitionId + '/' + identity key (or "<no-identity>" if the key is empty).
    std::vector<std::string> invalid;
    // Always equivalent to outcome == Satisfied. NotAssessed is also false — lack of verification does not constitute success.
    bool allSatisfied = false;
};

ExpectationCheck checkExpectedChanges(const SnapshotComparison& comparison,
                                      const std::vector<ExpectedChange>& expected);

// ---------------------------------------------------------------------------
// D-06: Persistent
// ---------------------------------------------------------------------------
inline constexpr const char* kSnapshotSchemaId = "ksword.snapshot";
inline constexpr std::uint32_t kSnapshotSchemaMajor = 1;
inline constexpr std::uint32_t kSnapshotSchemaMinor = 0;

enum class SnapshotLoadStatus {
    kOk,
    kOkWithUnknownFields,      // Unknown optional fields present; preserved as-is.
    kEmptyInput,
    kMalformedJson,
    kMissingSchema,
    kWrongSchemaId,
    kUnsupportedMajorVersion,  // Explicitly reject; do not attempt best-effort parsing.
    kMissingRequiredField,
    kInvalidFieldValue,        // Includes unknown enum names; never silently use a default.
    // The document is valid but exceeds this call's parsing limits for bytes, nodes, or depth.
    // It must be distinct from MalformedJson: a valid large snapshot versus a corrupted file require completely
    // different user handling (raising limits vs. file corruption); D-06 requires explicit error states.
    kLimitExceeded,
};

const char* snapshotLoadStatusName(SnapshotLoadStatus value) noexcept;

// D-06 + 7.2: Parsing limits for snapshot persistence.
//
// The default value for JsonLimits is intended for **untrusted input** (32 MiB / 524,288 nodes / 64 MiB node budget),
// whereas the L1 workload specified in section 7.2 consists of 100,000 entity records. A valid document generated by
// this module at that scale is approximately 100 MiB with millions of nodes, so the generic default values cannot
// read it back. Since the snapshot file contains session data just written by the local machine, an explicit
// persistence tier is provided here; callers that need to handle external files can still pass their own JsonLimits.
JsonLimits snapshotJsonLimits() noexcept;

struct SnapshotLoadResult final {
    SnapshotLoadStatus status = SnapshotLoadStatus::kEmptyInput;
    Snapshot snapshot;
    std::uint32_t versionMajor = 0;
    std::uint32_t versionMinor = 0;
    std::vector<std::string> unknownFieldPaths;  // Positions of unknown optional fields that are retained.
    std::string errorDetail;                     // Original error description; do not guess or beautify.
    std::size_t errorOffset = 0;

    bool ok() const noexcept {
        return status == SnapshotLoadStatus::kOk || status == SnapshotLoadStatus::kOkWithUnknownFields;
    }
};

std::string writeSnapshotJson(const Snapshot& snapshot, unsigned indent = 0);

// Pure function: reads text only, opens no files, and writes to no files. On failure, the snapshot remains default-constructed—leaving
// no half-parsed object behind, so the caller cannot "accidentally save back" and overwrite the source data (D-06).
SnapshotLoadResult readSnapshotJson(std::string_view text);
SnapshotLoadResult readSnapshotJson(std::string_view text, const JsonLimits& limits);

// ---------------------------------------------------------------------------
// D-07: Data masking.
// ---------------------------------------------------------------------------
struct RedactionOptions final {
    bool redactUserNames = true;
    bool redactHostnames = true;
    bool redactSids = true;
    // Collector raw error text often contains full paths. When true, the entire string is deleted and registered in removedFieldPaths;
    // when false, it is replaced according to other rules. Deletion and replacement must be distinguishable, hence two separate lists.
    bool dropCollectorMessages = false;
};

struct RedactionMapping final {
    RedactionClass cls = RedactionClass::kNone;
    std::string original;     // Exists in memory only for consistency verification; never written to export.
    std::string replacement;  // Stable placeholders like "<user-1>"
};

struct RedactionReport final {
    std::vector<RedactionMapping> mappings;
    std::vector<std::string> replacedFieldPaths;  // Replaced field paths
    std::vector<std::string> removedFieldPaths;   // Locations of fields deleted entirely.
    std::size_t replacementCount = 0;

    // 7.3: The current redaction was cancelled by the caller. At this point, the redact output is cleared. Partially redacted snapshots are more
    // dangerous than unredacted ones (they appear processed but still contain original values), so partial results are never delivered upon cancellation.
    bool cancelled = false;

    // 7.3 Verifiability: The actual count of 'candidate string comparisons' performed. A naive implementation is text length ×
    //   number of distinct placeholders, where placeholders are automatically harvested from the data and grow with the snapshot.
    // This count makes "scan cost independent of placeholder count" an assertable fact rather than relying on timing.
    std::size_t needleComparisons = 0;
};

// Multiple redactions within the same session share the mapping table—this is exactly "consistent mapping within the same export."
// The source snapshot is a const input and will never be modified under any circumstances.
class RedactionSession final {
public:
    // 7.3: Locally interruptible work must have cancellation points. Return true if the caller requests a stop.
    using CancelHook = std::function<bool()>;

    RedactionSession() = default;
    explicit RedactionSession(RedactionOptions options) : options_(std::move(options)) {}

    // Learn first, then redact: usernames that appear only in paths elsewhere may exist in free-text fields.
    // When requiring full consistency across multiple snapshots, the caller should first call learn on all snapshots, then redact each one individually.
    void learn(const Snapshot& source);

    // On cancellation, out is reset to default-constructed state, and report().cancelled is true.
    void redact(const Snapshot& source, Snapshot& out);

    void setCancelHook(CancelHook hook) { cancel_ = std::move(hook); }

    const RedactionReport& report() const noexcept { return report_; }
    const RedactionOptions& options() const noexcept { return options_; }

    // Query the current placeholder for a given original value; returns an empty string if not registered. Used for testing and consistency checks.
    std::string replacementFor(RedactionClass cls, std::string_view original) const;

private:
    std::string assign(RedactionClass cls, const std::string& original);

    RedactionOptions options_;
    RedactionReport report_;
    CancelHook cancel_;
    std::map<std::string, std::string> map_;  // Key = category + '\x1F' + lowercase original value
    std::size_t userCount_ = 0;
    std::size_t hostCount_ = 0;
    std::size_t sidCount_ = 0;
};

void redactSnapshot(const Snapshot& source,
                    const RedactionOptions& options,
                    Snapshot& out,
                    RedactionReport& report);

} // namespace ksword::evidence

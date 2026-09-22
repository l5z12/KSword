#include "ObjectIdentity.h"

namespace ksword::evidence {
namespace {

// The primary key separator does not appear in paths, GUIDs, or numbers to avoid key collisions between "a|b" and "a" + "|b".
constexpr char kSep = '\x1F';

void appendField(std::string& key, const std::string& value) {
    key.push_back(kSep);
    key.append(value);
}

void appendField(std::string& key, const OptionalU64& value, U64Format format) {
    key.push_back(kSep);
    if (value.present) {
        key.append(formatU64(value.value, format));
    }
}

// Three-state comparison of two optional values: both present and equal -> Equal; both present and unequal -> Differ; either missing -> Missing.
enum class FieldCompare { kEqual, kDiffer, kMissing };

FieldCompare compare(const OptionalU64& a, const OptionalU64& b) noexcept {
    if (!a.present || !b.present) {
        return FieldCompare::kMissing;
    }
    return a.value == b.value ? FieldCompare::kEqual : FieldCompare::kDiffer;
}

FieldCompare compare(const std::string& a, const std::string& b) noexcept {
    if (a.empty() || b.empty()) {
        return FieldCompare::kMissing;
    }
    return a == b ? FieldCompare::kEqual : FieldCompare::kDiffer;
}

// Boot cycle: if both sides exist but differ, they are not the same instance. If one side is missing, the result degrades to uncertain.
FieldCompare compareBoot(const std::string& a, const std::string& b) noexcept {
    return compare(a, b);
}

// F-03 unified identity threshold: if neither side can form even a weak primary key, the strongest possible result is Candidate.
//
// Why must we unify the addition: strength() and crossSessionKey() already indicate 'insufficient identity, no primary key', yet the
// matcher might return Confirmed due to coincidental equality in a few secondary fields (e.g., module records where both imagePath
// and pdb are empty, leaving only timeDateStamp + imageSize). This creates a contradiction and causes monotonicity inversion:
// Adding a different path (more information) can downgrade the result from Confirmed to NoMatch.
// Contradictory evidence still yields NoMatch; here we only restrict the 'Confirmed' tier.
MatchResult capByStrength(MatchResult result, IdentityStrength a, IdentityStrength b) noexcept {
    if (result != MatchResult::kConfirmed) {
        return result;
    }
    if (a == IdentityStrength::kUnusable || b == IdentityStrength::kUnusable) {
        return MatchResult::kCandidate;
    }
    return result;
}

// Path normalization: performs only case folding and delimiter unification; does not resolve symbolic links (which would require live access).
// Used for the primary key of 'content + path' to ensure 'C:\A\B.sys' and 'c:/a/b.sys' are not treated as two distinct objects.
std::string normalizePath(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (const char kRaw : path) {
        char c = kRaw;
        if (c == '/') {
            c = '\\';
        } else if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
        out.push_back(c);
    }
    return out;
}

MatchResult matchProcessInstanceCore(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept;
MatchResult matchThreadInstanceCore(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept;
MatchResult matchDriverInstanceCore(const DriverInstanceId& a, const DriverInstanceId& b) noexcept;
MatchResult matchFileIdentityCore(const FileIdentity& a, const FileIdentity& b) noexcept;
MatchResult matchHandleIdentityCore(const HandleIdentity& a, const HandleIdentity& b) noexcept;
MatchResult matchConnectionIdentityCore(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept;

} // namespace

const char* objectKindName(ObjectKind kind) noexcept {
    switch (kind) {
    case ObjectKind::kUnknown:    return "Unknown";
    case ObjectKind::kProcess:    return "Process";
    case ObjectKind::kThread:     return "Thread";
    case ObjectKind::kDriver:     return "Driver";
    case ObjectKind::kModule:     return "Module";
    case ObjectKind::kFile:       return "File";
    case ObjectKind::kHandle:     return "Handle";
    case ObjectKind::kConnection: return "Connection";
    case ObjectKind::kDevice:     return "Device";
    case ObjectKind::kService:    return "Service";
    }
    return "Unknown";
}

const char* matchResultName(MatchResult result) noexcept {
    switch (result) {
    case MatchResult::kNoMatch:   return "NoMatch";
    case MatchResult::kCandidate: return "Candidate";
    case MatchResult::kConfirmed: return "Confirmed";
    }
    return "Candidate";
}

const char* identityStrengthName(IdentityStrength strength) noexcept {
    switch (strength) {
    case IdentityStrength::kUnusable: return "Unusable";
    case IdentityStrength::kWeak:     return "Weak";
    case IdentityStrength::kStrong:   return "Strong";
    }
    return "Unusable";
}

// ---------------------------------------------------------------------------
// Process
// ---------------------------------------------------------------------------
IdentityStrength ProcessInstanceId::strength() const noexcept {
    if (!pid.present) {
        return IdentityStrength::kUnusable;
    }
    if (createTime100ns.present && !bootId.empty()) {
        return IdentityStrength::kStrong;
    }
    return IdentityStrength::kWeak;
}

std::string ProcessInstanceId::crossSessionKey() const {
    if (strength() != IdentityStrength::kStrong) {
        return std::string();  // F-03: Insufficient identity, do not provide cross-session primary key.
    }
    std::string key("proc");
    appendField(key, bootId);
    appendField(key, pid, U64Format::kDecimal);
    appendField(key, createTime100ns, U64Format::kDecimal);
    return key;
}

MatchResult matchProcessInstance(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept {
    return capByStrength(matchProcessInstanceCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult matchProcessInstanceCore(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept {
    if (compare(a.pid, b.pid) == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    if (compareBoot(a.bootId, b.bootId) == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;  // The same PID across different boot cycles is definitely not the same instance.
    }
    switch (compare(a.createTime100ns, b.createTime100ns)) {
    case FieldCompare::kDiffer:
        return MatchResult::kNoMatch;  // PID reuse: Different creation times indicate different instances.
    case FieldCompare::kEqual:
        // Matching creation times alone are insufficient; the PID must also be present to confirm.
        if (compare(a.pid, b.pid) == FieldCompare::kEqual && !a.bootId.empty() && !b.bootId.empty()) {
            return MatchResult::kConfirmed;
        }
        return MatchResult::kCandidate;
    case FieldCompare::kMissing:
        break;
    }
    // Creation time is missing: the address can only serve as auxiliary evidence for this instance and is insufficient for confirmation.
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// Thread
// ---------------------------------------------------------------------------
IdentityStrength ThreadInstanceId::strength() const noexcept {
    if (!tid.present) {
        return IdentityStrength::kUnusable;
    }
    if (process.strength() == IdentityStrength::kStrong && createTime100ns.present) {
        return IdentityStrength::kStrong;
    }
    return IdentityStrength::kWeak;
}

std::string ThreadInstanceId::crossSessionKey() const {
    if (strength() != IdentityStrength::kStrong) {
        return std::string();
    }
    std::string key("thread");
    appendField(key, process.crossSessionKey());
    appendField(key, tid, U64Format::kDecimal);
    appendField(key, createTime100ns, U64Format::kDecimal);
    return key;
}

MatchResult matchThreadInstance(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept {
    return capByStrength(matchThreadInstanceCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult matchThreadInstanceCore(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept {
    if (compare(a.tid, b.tid) == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    const MatchResult kOwner = matchProcessInstance(a.process, b.process);
    if (kOwner == MatchResult::kNoMatch) {
        // X-03: Incomplete ownership information is not attached to new processes with the same PID.
        return MatchResult::kNoMatch;
    }
    switch (compare(a.createTime100ns, b.createTime100ns)) {
    case FieldCompare::kDiffer:
        return MatchResult::kNoMatch;  // TID reuse
    case FieldCompare::kEqual:
        return kOwner == MatchResult::kConfirmed ? MatchResult::kConfirmed : MatchResult::kCandidate;
    case FieldCompare::kMissing:
        break;
    }
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------
IdentityStrength DriverInstanceId::strength() const noexcept {
    if (imagePath.empty() && pdbSignature.empty()) {
        return IdentityStrength::kUnusable;
    }
    if (!pdbSignature.empty()) {
        return IdentityStrength::kStrong;
    }
    if (timeDateStamp.present && imageSize.present) {
        return IdentityStrength::kStrong;
    }
    return IdentityStrength::kWeak;
}

std::string DriverInstanceId::crossSessionKey() const {
    if (strength() != IdentityStrength::kStrong) {
        return std::string();
    }
    std::string key("driver");
    appendField(key, imagePath);
    appendField(key, pdbSignature);
    appendField(key, timeDateStamp, U64Format::kDecimal);
    appendField(key, imageSize, U64Format::kDecimal);
    return key;
}

MatchResult matchDriverInstance(const DriverInstanceId& a, const DriverInstanceId& b) noexcept {
    return capByStrength(matchDriverInstanceCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult matchDriverInstanceCore(const DriverInstanceId& a, const DriverInstanceId& b) noexcept {
    // I-01: Disk files with the same name are not automatically treated as the corresponding version at load time.
    const FieldCompare kPdb = compare(a.pdbSignature, b.pdbSignature);
    if (kPdb == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    const FieldCompare kStamp = compare(a.timeDateStamp, b.timeDateStamp);
    const FieldCompare kSize = compare(a.imageSize, b.imageSize);
    if (kStamp == FieldCompare::kDiffer || kSize == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    const FieldCompare kPath = compare(a.imagePath, b.imagePath);
    if (kPath == FieldCompare::kDiffer) {
        // Different paths but identical image identity may still be two copies of the same file — keep as a candidate.
        // Note that this also covers the case where stamp and size match: otherwise, 'weak evidence (stamp+size)' yielding
        // NoMatch while 'strong evidence (pdb)' yields Candidate would constitute a reversal of conclusion strength.
        if (kPdb == FieldCompare::kEqual || (kStamp == FieldCompare::kEqual && kSize == FieldCompare::kEqual)) {
            return MatchResult::kCandidate;
        }
        return MatchResult::kNoMatch;
    }
    if (kPdb == FieldCompare::kEqual) {
        return MatchResult::kConfirmed;  // RSDS GUID + Age is the strongest image identity.
    }
    // F-03: timeDateStamp + imageSize is a much weaker combination (identical for any copy from the same build, and the
    // only remaining fields when R0 enumeration cannot retrieve the path). Only when both sides have imagePath present
    // and equal can we discuss "the same loaded instance"; if the path is missing, the result must remain Candidate.
    if (kStamp == FieldCompare::kEqual && kSize == FieldCompare::kEqual && kPath == FieldCompare::kEqual) {
        return MatchResult::kConfirmed;
    }
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// File
// ---------------------------------------------------------------------------
IdentityStrength FileIdentity::strength() const noexcept {
    if (path.empty() && fileId.empty() && contentHash.empty()) {
        return IdentityStrength::kUnusable;
    }
    if (!fileId.empty() && volumeSerial.present) {
        return IdentityStrength::kStrong;  // The (Volume Serial Number, FileId) pair is the true identity of a file object.
    }
    // F-03: Content hash alone does not constitute file object identity; the same byte sequence can exist in
    // both System32 and user directories. Only 'content + path' together form a valid cross-session primary key.
    if (!contentHash.empty() && !path.empty()) {
        return IdentityStrength::kStrong;
    }
    return IdentityStrength::kWeak;
}

std::string FileIdentity::crossSessionKey() const {
    // Object identity key: Hard links share the same (volumeSerial, fileId) across multiple paths. Therefore, when
    // this key is present, excluding the path ensures consistency across different paths of the same file object.
    if (!fileId.empty() && volumeSerial.present) {
        std::string key("file");
        appendField(key, volumeSerial, U64Format::kDecimal);
        appendField(key, fileId);
        return key;
    }
    // Content key: The prefix must be distinct from the object identity key, and it must include the normalized path; otherwise,
    // a genuine driver and an identical byte-for-byte copy deployed elsewhere would share the same primary key (F-03).
    if (!contentHash.empty() && !path.empty()) {
        std::string key("file-content");
        appendField(key, contentHash);
        appendField(key, normalizePath(path));
        return key;
    }
    return std::string();  // Do not provide cross-session primary key if identity is insufficient.
}

MatchResult matchFileIdentity(const FileIdentity& a, const FileIdentity& b) noexcept {
    return capByStrength(matchFileIdentityCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult matchFileIdentityCore(const FileIdentity& a, const FileIdentity& b) noexcept {
    const FieldCompare kHash = compare(a.contentHash, b.contentHash);
    if (kHash == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    const FieldCompare kVolume = compare(a.volumeSerial, b.volumeSerial);
    const FieldCompare kId = compare(a.fileId, b.fileId);
    if (kVolume == FieldCompare::kDiffer || kId == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;  // Same path, different files
    }
    // Only (Volume Serial Number, FileId) constitutes file object identity. Equality
    // implies the same file object, even if the two paths differ (hard links).
    if (kVolume == FieldCompare::kEqual && kId == FieldCompare::kEqual) {
        return MatchResult::kConfirmed;
    }
    // F-03: Path criteria must precede content hash. Content match does not imply the same file object:
    // Genuine drivers under System32 and identical byte-for-byte copies deployed to user directories have the exact
    // same content hash. The earlier implementation here directly returned Confirmed based on the hash; the subsequent
    // rule "different paths imply NoMatch" was never reached, causing the two files to share a single identity.
    if (compare(a.path, b.path) == FieldCompare::kDiffer) {
        return (kHash == FieldCompare::kEqual) ? MatchResult::kCandidate : MatchResult::kNoMatch;
    }
    // Content matches but (volume, fileId) cannot be retrieved: this does not prove it is the same file object; stop at candidate.
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// handle
// ---------------------------------------------------------------------------
IdentityStrength HandleIdentity::strength() const noexcept {
    if (!handleValue.present) {
        return IdentityStrength::kUnusable;
    }
    if (owner.strength() == IdentityStrength::kStrong) {
        return IdentityStrength::kStrong;
    }
    return IdentityStrength::kWeak;
}

std::string HandleIdentity::crossSessionKey() const {
    if (strength() != IdentityStrength::kStrong) {
        return std::string();
    }
    std::string key("handle");
    appendField(key, owner.crossSessionKey());
    appendField(key, handleValue, U64Format::kHexAddress);
    return key;
}

MatchResult matchHandleIdentity(const HandleIdentity& a, const HandleIdentity& b) noexcept {
    return capByStrength(matchHandleIdentityCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult matchHandleIdentityCore(const HandleIdentity& a, const HandleIdentity& b) noexcept {
    if (compare(a.handleValue, b.handleValue) == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    const MatchResult kOwner = matchProcessInstance(a.owner, b.owner);
    if (kOwner == MatchResult::kNoMatch) {
        return MatchResult::kNoMatch;
    }
    if (compare(a.typeName, b.typeName) == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    // Handle values are recycled: even if the owner is confirmed, the objects are considered the same only if their addresses match.
    if (kOwner == MatchResult::kConfirmed && compare(a.objectAddress, b.objectAddress) == FieldCompare::kEqual) {
        return MatchResult::kConfirmed;
    }
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------
IdentityStrength ConnectionIdentity::strength() const noexcept {
    if (localAddress.empty() || protocol == 0U) {
        return IdentityStrength::kUnusable;
    }
    if (observedFirstUtc100ns.present && !bootId.empty()) {
        return IdentityStrength::kStrong;
    }
    return IdentityStrength::kWeak;
}

std::string ConnectionIdentity::fiveTupleKey() const {
    std::string key("conn5");
    appendField(key, formatU64(protocol, U64Format::kDecimal));
    appendField(key, localAddress);
    appendField(key, formatU64(localPort, U64Format::kDecimal));
    appendField(key, remoteAddress);
    appendField(key, formatU64(remotePort, U64Format::kDecimal));
    return key;
}

std::string ConnectionIdentity::crossSessionKey() const {
    if (strength() != IdentityStrength::kStrong) {
        return std::string();
    }
    std::string key = fiveTupleKey();
    appendField(key, bootId);
    appendField(key, observedFirstUtc100ns, U64Format::kDecimal);
    return key;
}

MatchResult matchConnectionIdentity(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept {
    return capByStrength(matchConnectionIdentityCore(a, b), a.strength(), b.strength());
}

namespace {

MatchResult matchConnectionIdentityCore(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept {
    if (a.fiveTupleKey() != b.fiveTupleKey()) {
        return MatchResult::kNoMatch;
    }
    const FieldCompare kBoot = compareBoot(a.bootId, b.bootId);
    if (kBoot == FieldCompare::kDiffer) {
        return MatchResult::kNoMatch;
    }
    // Different connections with the same five-tuple but different time intervals: non-overlapping observation intervals result in NoMatch.
    if (a.observedFirstUtc100ns.present && a.observedLastUtc100ns.present &&
        b.observedFirstUtc100ns.present && b.observedLastUtc100ns.present) {
        const bool kDisjoint = a.observedLastUtc100ns.value < b.observedFirstUtc100ns.value ||
                              b.observedLastUtc100ns.value < a.observedFirstUtc100ns.value;
        if (kDisjoint) {
            return MatchResult::kNoMatch;
        }
        const MatchResult kOwner = matchProcessInstance(a.owner, b.owner);
        if (kOwner == MatchResult::kNoMatch) {
            return MatchResult::kNoMatch;
        }
        // F-03: Cross-boot protection requires positive evidence. When both bootId values are empty, Compare() returns
        // Missing rather than Differ. The earlier implementation skipped the entire protection rule this way, causing
        // the same five-tuple across two machines or two boot sessions to be incorrectly judged as a single connection.
        if (kBoot != FieldCompare::kEqual) {
            return MatchResult::kCandidate;
        }
        // The five-tuple may be reused (the same port can be rebound to a different process in the same
        // boot session); if the owning process is completely unknown, the result can only be a candidate.
        if (kOwner != MatchResult::kConfirmed) {
            return MatchResult::kCandidate;
        }
        return MatchResult::kConfirmed;
    }
    return MatchResult::kCandidate;
}

} // namespace

// ---------------------------------------------------------------------------
// Generic reference
// ---------------------------------------------------------------------------
namespace {

ObjectRef makeRef(ObjectKind kind,
                  std::string key,
                  IdentityStrength strength,
                  std::string display,
                  std::string evidenceId) {
    ObjectRef ref;
    ref.kind = kind;
    ref.key = std::move(key);
    ref.strength = strength;
    ref.displayText = std::move(display);
    ref.evidenceId = std::move(evidenceId);
    return ref;
}

} // namespace

ObjectRef makeProcessRef(const ProcessInstanceId& id, std::string evidenceId) {
    std::string display = id.imageName;
    if (id.pid.present) {
        display += " (" + formatU64(id.pid.value, U64Format::kDecimal) + ")";
    }
    return makeRef(ObjectKind::kProcess, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

ObjectRef makeThreadRef(const ThreadInstanceId& id, std::string evidenceId) {
    std::string display = "TID " + formatOptionalU64(id.tid, U64Format::kDecimal);
    return makeRef(ObjectKind::kThread, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

ObjectRef makeDriverRef(const DriverInstanceId& id, std::string evidenceId) {
    return makeRef(ObjectKind::kDriver, id.crossSessionKey(), id.strength(), id.imagePath,
                   std::move(evidenceId));
}

ObjectRef makeFileRef(const FileIdentity& id, std::string evidenceId) {
    return makeRef(ObjectKind::kFile, id.crossSessionKey(), id.strength(), id.path,
                   std::move(evidenceId));
}

ObjectRef makeHandleRef(const HandleIdentity& id, std::string evidenceId) {
    std::string display = id.typeName + " " + formatOptionalU64(id.handleValue, U64Format::kHexAddress);
    return makeRef(ObjectKind::kHandle, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

ObjectRef makeConnectionRef(const ConnectionIdentity& id, std::string evidenceId) {
    std::string display = id.localAddress + ":" + formatU64(id.localPort, U64Format::kDecimal) + " -> " +
                          id.remoteAddress + ":" + formatU64(id.remotePort, U64Format::kDecimal);
    return makeRef(ObjectKind::kConnection, id.crossSessionKey(), id.strength(), std::move(display),
                   std::move(evidenceId));
}

} // namespace ksword::evidence

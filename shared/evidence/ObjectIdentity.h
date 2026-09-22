#pragma once

// F-03 Stable object identity.
//
// Rule:
//   * Process = startup ID + PID + creation time. Missing creation time yields only a "weak" identity.
//   * Binds the thread to its owning process instance and retains available thread creation identifiers.
//   * Records the obtainable lifecycle identity for drivers, files, handles, and connections separately.
//   * Address, name, and raw PID cannot individually serve as a cross-session primary key.
//   When identity is insufficient, the result is Candidate; it must never be automatically upgraded to Confirmed.
//   * Unified threshold: If strength() == Unusable on either side, all Match* strongest results are given only to Candidate.
//     The matcher must not be more optimistic than strength()/crossSessionKey(): when the latter two indicate "identity insufficient,
//     do not emit primary key", the former cannot claim "definitely the same". Contradictory evidence can still result in NoMatch.

#include "LosslessValue.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::evidence {

enum class ObjectKind {
    kUnknown,
    kProcess,
    kThread,
    kDriver,
    kModule,
    kFile,
    kHandle,
    kConnection,
    kDevice,
    kService,
};

const char* objectKindName(ObjectKind kind) noexcept;

// Match conclusion. Candidate means "possibly the same, but evidence is insufficient to confirm".
enum class MatchResult {
    kNoMatch,    // Sufficient evidence to determine they are not the same.
    kCandidate,  // Missing key fields or only weak evidence.
    kConfirmed,  // Lifecycle identity is complete and consistent.
};

const char* matchResultName(MatchResult result) noexcept;

// Identity strength. Used for UI annotation "weak association".
enum class IdentityStrength {
    kUnusable,  // Does not even constitute a weak primary key.
    kWeak,      // Only reusable identifiers such as PID, name, or address.
    kStrong,    // With lifecycle identifier (creation time / file ID / observation interval).
};

const char* identityStrengthName(IdentityStrength strength) noexcept;

// ---------------------------------------------------------------------------
// Process instance
// ---------------------------------------------------------------------------
struct ProcessInstanceId final {
    std::string bootId;              // Boot identifier; raw PID matching is unavailable across reboots.
    OptionalU64 pid;
    OptionalU64 createTime100ns;     // Weak association if missing
    OptionalU64 eprocessAddress;     // Auxiliary evidence for this collection only; not used for cross-boot matching.
    std::string imageName;           // Auxiliary display, not a primary key.

    IdentityStrength strength() const noexcept;

    // Cross-session primary key. Returns empty string if identity is insufficient; callers must reject treating it as a confirmed object.
    std::string crossSessionKey() const;
};

MatchResult matchProcessInstance(const ProcessInstanceId& a, const ProcessInstanceId& b) noexcept;

// ---------------------------------------------------------------------------
// Thread instance
// ---------------------------------------------------------------------------
struct ThreadInstanceId final {
    ProcessInstanceId process;   // Thread must be bound to a process instance.
    OptionalU64 tid;
    OptionalU64 createTime100ns;
    OptionalU64 ethreadAddress;

    IdentityStrength strength() const noexcept;
    std::string crossSessionKey() const;
};

MatchResult matchThreadInstance(const ThreadInstanceId& a, const ThreadInstanceId& b) noexcept;

// ---------------------------------------------------------------------------
// Driver / module instance
// ---------------------------------------------------------------------------
// X-04: Loaded modules, DriverObject, DeviceObject, and disk service configurations are four distinct entities
// that do not require a one-to-one correspondence; thus, this field describes only the "loaded module instance".
struct DriverInstanceId final {
    std::string bootId;
    std::string imagePath;          // Normalized path; same-name different versions are distinguished by the fields below.
    OptionalU64 imageBase;          // Base address for this load; not comparable across boots.
    OptionalU64 imageSize;
    OptionalU64 timeDateStamp;      // PE header identity
    OptionalU64 checksum;
    std::string pdbSignature;       // RSDS GUID+Age, the strongest image identity.
    OptionalU64 loadOrderIndex;

    IdentityStrength strength() const noexcept;
    std::string crossSessionKey() const;
};

MatchResult matchDriverInstance(const DriverInstanceId& a, const DriverInstanceId& b) noexcept;

// ---------------------------------------------------------------------------
// File identity
// ---------------------------------------------------------------------------
struct FileIdentity final {
    std::string path;               // Files at the same path but different must be distinguished by volumeSerial + fileId.
    OptionalU64 volumeSerial;
    std::string fileId;             // Lossless text representation of a 128-bit FileId
    OptionalU64 sizeBytes;
    OptionalU64 lastWriteUtc100ns;
    std::string contentHash;        // Content identity: The same byte sequence can exist in multiple paths.

    IdentityStrength strength() const noexcept;

    // Two key types with different prefixes do not collide:
    //   "file" = (volumeSerial, fileId) — File object identity; hard links share this. "file-content" = (contentHash,
    //   normalized path) — Degenerate key when only content is known. The content key must include the path:
    // identical hashes with different paths represent "the same bytes" but not "the same file object" (F-03).
    std::string crossSessionKey() const;
};

MatchResult matchFileIdentity(const FileIdentity& a, const FileIdentity& b) noexcept;

// ---------------------------------------------------------------------------
// handle
// ---------------------------------------------------------------------------
struct HandleIdentity final {
    ProcessInstanceId owner;    // Handle value is only meaningful within its owning process instance.
    OptionalU64 handleValue;
    OptionalU64 objectAddress;  // The address may be reused; this serves only as auxiliary evidence for this instance.
    std::string typeName;

    IdentityStrength strength() const noexcept;
    std::string crossSessionKey() const;
};

MatchResult matchHandleIdentity(const HandleIdentity& a, const HandleIdentity& b) noexcept;

// ---------------------------------------------------------------------------
// Network connection
// ---------------------------------------------------------------------------
// The same five-tuple represents different connections at different times, so identity must include the observation interval.
struct ConnectionIdentity final {
    std::string bootId;
    std::uint32_t protocol = 0;     // IPPROTO_*
    std::string localAddress;       // Normalized text (v4/v6).
    std::uint16_t localPort = 0;
    std::string remoteAddress;
    std::uint16_t remotePort = 0;
    OptionalU64 observedFirstUtc100ns;
    OptionalU64 observedLastUtc100ns;
    ProcessInstanceId owner;        // Potentially unknown

    IdentityStrength strength() const noexcept;
    std::string fiveTupleKey() const;
    std::string crossSessionKey() const;
};

// Same five-tuple but non-overlapping observation intervals -> NoMatch (different connections).
// Missing interval -> Candidate.
// Confirmed also requires non-empty, equal bootId values on both sides and a Confirmed match
// for the owning process. Ports can be rebound by another process within the same boot (F-03).
MatchResult matchConnectionIdentity(const ConnectionIdentity& a, const ConnectionIdentity& b) noexcept;

// ---------------------------------------------------------------------------
// Generic reference: used for navigation and evidence references (F-12 / G-01).
// ---------------------------------------------------------------------------
struct ObjectRef final {
    ObjectKind kind = ObjectKind::kUnknown;
    std::string key;             // crossSessionKey(), empty indicates insufficient identity.
    IdentityStrength strength = IdentityStrength::kUnusable;
    std::string displayText;
    std::string evidenceId;      // Envelope that generated this reference.

    bool navigable() const noexcept { return !key.empty() && strength != IdentityStrength::kUnusable; }
};

ObjectRef makeProcessRef(const ProcessInstanceId& id, std::string evidenceId);
ObjectRef makeThreadRef(const ThreadInstanceId& id, std::string evidenceId);
ObjectRef makeDriverRef(const DriverInstanceId& id, std::string evidenceId);
ObjectRef makeFileRef(const FileIdentity& id, std::string evidenceId);
ObjectRef makeHandleRef(const HandleIdentity& id, std::string evidenceId);
ObjectRef makeConnectionRef(const ConnectionIdentity& id, std::string evidenceId);

} // namespace ksword::evidence

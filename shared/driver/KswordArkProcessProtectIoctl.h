#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkProcessProtectIoctl.h
// Purpose:
// - Define the unique R3/R0 protocol for "process protection based on object manager handle callbacks".
// - Protection checks are attached to the pre-callback of registered ObRegisterCallbacks. On a hit, only
//   "privilege reduction" is performed (removing dangerous bits from DesiredAccess), without returning
//   failure. Thus, the initiator receives a privilege-limited handle rather than an OpenProcess failure;
// - Runs in parallel with the general callback rules in KswordArkCallbackIoctl.h: protection
//   checks execute before general rules, and the resulting permission bits are the union of both.
// Notes:
// - This protocol only describes "who is protected, which permissions are revoked, and who is exempted"; it provides no injection or privilege escalation capabilities.
// - Configuration is applied as a one-time full replacement, not incremental updates, to prevent rule table drift between R3 and R0 sides.
// ============================================================

// v2 builds upon v1's handle callback privilege reduction by adding a 'kernel PP layer': the same rule table drives Ob
// callbacks and also enforces PP/PPL on target processes while maintaining that state. Consequently, the rule structure
// grows longer and cannot coexist with v1 via the size field (rules[] is an embedded fixed-length array with a changed
// element stride), so the version number is bumped directly; R0 rejects v1 requests and logs a version mismatch.
#define KSWORD_ARK_PROCESS_PROTECT_PROTOCOL_VERSION 2UL

#define KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_PROTECT_CONFIG   0x90CUL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_PROTECT_STATE  0x90DUL

#define IOCTL_KSWORD_ARK_SET_PROCESS_PROTECT_CONFIG \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_PROTECT_CONFIG, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_PROCESS_PROTECT_STATE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_PROTECT_STATE, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// ------------------------------------------------------------
// Capacity limit
// ------------------------------------------------------------
// Both requests and responses are fixed-length METHOD_BUFFERED packets. The capacity directly
// determines the size of the kernel non-paged buffer, so it is kept in the tens of KB range.
#define KSWORD_ARK_PROCESS_PROTECT_MAX_RULES 32UL
#define KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED 32UL
#define KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS 260U
#define KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS 64U

// ------------------------------------------------------------
// Target matching method
// ------------------------------------------------------------
// PID: Matches only a specific process; the rule naturally becomes invalid after the process exits.
// IMAGE_NAME: Match the image file name (excluding the directory), case-insensitive, e.g., notepad.exe.
// IMAGE_PATH: Match the full image path. R0 receives NT paths (e.g.,
//             \Device\HarddiskVolume3\Windows\notepad.exe), while R3 typically holds Win32 paths
//             (e.g., C:\Windows\notepad.exe). Therefore, the matching logic uses case-insensitive
//             suffix matching after removing the drive letter, allowing both formats to match.
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_NONE 0UL
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_PID 1UL
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_NAME 2UL
#define KSWORD_ARK_PROCESS_PROTECT_TARGET_KIND_IMAGE_PATH 3UL

// ------------------------------------------------------------
// Protection bits: Capabilities to remove from DesiredAccess after a rule match.
// ------------------------------------------------------------
// Each bit determines which access bits to strip from the process handle and thread handle;
// the thread side participates in the check only if the rule opens PROTECT_THREADS.
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD 0x00000008UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME 0x00000010UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION 0x00000020UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE 0x00000040UL
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_ALL \
    (KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_READ | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_SET_INFORMATION | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_DUP_HANDLE)

// Default: Block terminate, write memory, remote thread creation, and suspend; retain read-only observation capability.
#define KSWORD_ARK_PROCESS_PROTECT_ACCESS_DEFAULT \
    (KSWORD_ARK_PROCESS_PROTECT_ACCESS_TERMINATE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_VM_WRITE | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_CREATE_THREAD | \
     KSWORD_ARK_PROCESS_PROTECT_ACCESS_SUSPEND_RESUME)

// ------------------------------------------------------------
// Kernel hardening flags (Layer 2: let the Windows kernel perform protection).
// ------------------------------------------------------------
// The first layer is Ob handle callback privilege reduction, executed by this driver; the second layer marks the target process as PP/PPL,
// handing it to the kernel to enforce execution on all handle paths. Even bypassing this driver's callbacks, the enforcement remains effective.
//
// CLEAR_DEBUG_PORT: Zeroes EPROCESS.DebugPort to detach attached user-mode debuggers from the debug object and
//     prevent subsequent attachments from acquiring the port. Only writes the entire pointer field, not bitfields.
//
// Note: The hardening bits related to BreakOnTermination (Critical Process) and MitigationFlags are intentionally
// omitted. These are bitfields within EPROCESS. DynData provides only field offsets, not bit offsets, and bit ordering
// varies across Windows versions. Hard-coding bit numbers would result in writing to incorrect bits on certain versions.
#define KSWORD_ARK_PROCESS_PROTECT_HARDEN_NONE 0x00000000UL
#define KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_HARDEN_ALL \
    (KSWORD_ARK_PROCESS_PROTECT_HARDEN_CLEAR_DEBUG_PORT)

// ------------------------------------------------------------
// Rule flags
// ------------------------------------------------------------
// ENABLED: Rules that are not set are skipped by R0 but still occupy a slot, allowing R3 to retain drafts.
// PROTECT_THREADS: Also protect thread handles within the process (e.g., THREAD_TERMINATE, SET_CONTEXT).
// APPLY_ON_CREATE: Apply kernel protection during the process creation callback to resolve 'protection lost after target process restart'.
// SELF_HEAL: Automatically restores Protection bytes if they are modified back by external forces during inspection and records one tampering event.
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_ENABLED 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_PROTECT_THREADS 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_APPLY_ON_CREATE 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_RULE_FLAG_SELF_HEAL 0x00000008UL

// ------------------------------------------------------------
// Trusted item flag.
// ------------------------------------------------------------
#define KSWORD_ARK_PROCESS_PROTECT_TRUSTED_FLAG_ENABLED 0x00000001UL

// ------------------------------------------------------------
// Global flags
// ------------------------------------------------------------
// ENABLED: Global switch. When disabled, R0 retains the rule table but performs no privilege reduction.
// LOG_BLOCKED: Writes a Warn record to the R3 log channel for every actual privilege reduction.
// TRUST_SYSTEM: Directly allow handle operations initiated by System(4) / Idle(0). Disabling this would also
//                     de-privilege system paths like process creation and exit cleanup, posing a high risk; it is enabled by default.
// TRUST_PROTECTED_PEERS: Protected processes can open handles to each other without privilege dropping.
// KERNEL_PROTECTION: The master switch for the kernel PP layer. When disabled, the rule table is retained, but rules are no longer enforced or scanned.
// SELF_HEAL_SCAN: Enables a periodic scan thread; if disabled, protection is applied only once at process creation.
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_ENABLED 0x00000001UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_LOG_BLOCKED 0x00000002UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_SYSTEM 0x00000004UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_TRUST_PROTECTED_PEERS 0x00000008UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_KERNEL_PROTECTION 0x00000010UL
#define KSWORD_ARK_PROCESS_PROTECT_FLAG_SELF_HEAL_SCAN 0x00000020UL

// Inspection cycle. Too frequent wastes CPU with many protected processes; too sparse extends the tampering window.
#define KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MIN_MS 1000UL
#define KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_MAX_MS 300000UL
#define KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS 3000UL

// Capacity for the protected process ledger. Once the limit is reached, new processes are excluded from inspection, but enforcement at creation time continues.
#define KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED 256UL

// ------------------------------------------------------------
// Capability status: R3 uses this to distinguish between 'no rules configured' and 'handle callbacks cannot be attached on this machine'.
// ------------------------------------------------------------
#define KSWORD_ARK_PROCESS_PROTECT_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_PROCESS_PROTECT_STATUS_ACTIVE 1UL
#define KSWORD_ARK_PROCESS_PROTECT_STATUS_CALLBACK_UNAVAILABLE 2UL

typedef struct _KSWORD_ARK_PROCESS_PROTECT_RULE
{
    unsigned long ruleId;
    unsigned long flags;
    unsigned long targetKind;
    // Effective only when targetKind is PID; must be 0 for all other matching methods.
    unsigned long targetProcessId;
    unsigned long protectAccessMask;
    // v2: Target PS_PROTECTION byte (assembled via KSWORD_PS_PROTECTION_MAKE).
    // 0 indicates this rule only performs handle callback privilege reduction, without applying kernel PP/PPL.
    unsigned long kernelProtection;
    // v2: Combination of KSWORD_ARK_PROCESS_PROTECT_HARDEN_* flags.
    unsigned long hardenFlags;
    unsigned long reserved;
    wchar_t targetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
    wchar_t ruleName[KSWORD_ARK_PROCESS_PROTECT_NAME_CHARS];
} KSWORD_ARK_PROCESS_PROTECT_RULE;

typedef struct _KSWORD_ARK_PROCESS_PROTECT_TRUSTED
{
    unsigned long flags;
    unsigned long kind;
    unsigned long processId;
    unsigned long reserved;
    wchar_t image[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
} KSWORD_ARK_PROCESS_PROTECT_TRUSTED;

typedef struct _KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long globalFlags;
    unsigned long ruleCount;
    unsigned long trustedCount;
    // v2: Scan interval in milliseconds. 0 indicates using SCAN_INTERVAL_DEFAULT_MS.
    unsigned long scanIntervalMs;
    KSWORD_ARK_PROCESS_PROTECT_RULE rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];
} KSWORD_ARK_PROCESS_PROTECT_CONFIG_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long globalFlags;
    unsigned long ruleCount;

    unsigned long trustedCount;
    // KSWORD_ARK_PROCESS_PROTECT_STATUS_*. When CALLBACK_UNAVAILABLE,
    // the rule table is retained, but no privilege reduction will occur.
    unsigned long capabilityStatus;
    // Original NTSTATUS when handle callback registration fails; 0 if registration succeeds.
    long objectCallbackStatus;
    unsigned long reserved;

    unsigned long long configVersion;
    unsigned long long appliedAtUtc100ns;

    // Statistics counters. `evaluated` counts handle creation/copy operations entering protection evaluation, `stripped` counts
    // instances where permission bits were actually removed, and `trustedBypass` counts instances allowed due to trusted items.
    unsigned long long evaluatedCount;
    unsigned long long strippedCount;
    unsigned long long trustedBypassCount;

    unsigned long long lastBlockedUtc100ns;
    unsigned long lastBlockedInitiatorPid;
    unsigned long lastBlockedTargetPid;
    unsigned long lastBlockedRuleId;
    unsigned long lastBlockedOriginalAccess;
    unsigned long lastBlockedGrantedAccess;
    unsigned long lastBlockedIsThreadObject;
    wchar_t lastBlockedInitiatorImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
    wchar_t lastBlockedTargetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    // ---- v2: Kernel PP Layer ----
    unsigned long scanIntervalMs;
    // Number of protected processes currently valid in the ledger.
    unsigned long trackedProcessCount;
    // kernelApplyCount: count of successful PP/PPL applications (including initial application and recovery during inspection).
    // selfHealCount: Number of times Protection was detected as modified during inspection and successfully restored.
    // kernelApplyFailureCount: Count of failed applications, typically indicating unavailable DynData offsets.
    // hardenApplyCount: Number of hardening actions executed (e.g., clearing DebugPort).
    unsigned long long kernelApplyCount;
    unsigned long long selfHealCount;
    unsigned long long kernelApplyFailureCount;
    unsigned long long hardenApplyCount;
    // Most recent tamper: the observed bytes and expected bytes when reverted.
    unsigned long long lastTamperUtc100ns;
    unsigned long lastTamperProcessId;
    unsigned long lastTamperObservedProtection;
    unsigned long lastTamperExpectedProtection;
    unsigned long lastTamperRuleId;
    // The original NTSTATUS of the most recent failed application; 0 indicates no failure has occurred yet.
    long lastKernelApplyStatus;
    unsigned long reservedV2;
    wchar_t lastTamperImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    unsigned long long ruleHitCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    // v2: number of times kernel protection is applied per rule, tracked separately from ruleHitCounts (handle privilege reduction counts).
    unsigned long long ruleKernelApplyCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_RULE rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];
} KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE;

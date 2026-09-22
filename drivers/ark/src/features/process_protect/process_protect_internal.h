#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "ark/ark_process_protect.h"
#include "ark/ark_log.h"
#include "ark/ark_push_lock.h"

#define KSWORD_ARK_PROCESS_PROTECT_TAG_STATE 'pPbK'

// Shared non-paged allocator within the driver, defined in src/features/callback/callback_runtime.c:
// It uses ExAllocatePool2 when available, otherwise falls back to ExAllocatePoolWithTag.
PVOID
kswordArkAllocateNonPaged(
    _In_ SIZE_T bytes,
    _In_ ULONG poolTag
    );

// Also defined in callback_runtime.c: Resolve the process image path with SeLocateProcessImageName, falling back to the
// short name on failure. The self-repair inspection uses it to add the target image to the most recent tampering record.
BOOLEAN
kswordArkResolveProcessImagePath(
    _In_opt_ PEPROCESS processObject,
    _Out_writes_(destinationChars) PWCHAR destinationBuffer,
    _In_ USHORT destinationChars,
    _Out_opt_ BOOLEAN* pathUnavailableOut
    );

// An entry in the protected process ledger.
// Periodic checks do not retain an EPROCESS reference, which would delay object release. Look up the PID again each round
// and verify its creation time. PID reuse means a PID-only comparison could apply protection to a different process.
typedef struct KswordArkProcessProtectTrackedEntry
{
    ULONG processId;
    ULONG ruleId;
    ULONG ruleIndex;
    UCHAR expectedProtection;
    UCHAR reserved[3];
    ULONG hardenFlags;
    LONGLONG createTimeQuadPart;
} KswordArkProcessProtectTrackedEntry;

// Runtime state. The rule table is protected as a whole by ConfigLock: the judgment path performs only a single linear scan
// of ≤32 entries; the cost of holding the lock is far lower than introducing a snapshot + rundown lifecycle mechanism.
typedef struct KswordArkProcessProtectState
{
    WDFDEVICE device;

    EX_PUSH_LOCK configLock;
    ULONG globalFlags;
    ULONG ruleCount;
    ULONG trustedCount;
    ULONG scanIntervalMs;
    ULONG64 configVersion;
    LARGE_INTEGER appliedAtUtc100ns;
    KSWORD_ARK_PROCESS_PROTECT_RULE rules[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    KSWORD_ARK_PROCESS_PROTECT_TRUSTED trusted[KSWORD_ARK_PROCESS_PROTECT_MAX_TRUSTED];

    // Statistical counters are maintained via atomic operations, excluded from ConfigLock to avoid upgrading the hot path to exclusive locking.
    volatile LONG64 evaluatedCount;
    volatile LONG64 strippedCount;
    volatile LONG64 trustedBypassCount;
    volatile LONG64 ruleHitCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];

    // ---- Kernel PP Layer ----
    EX_PUSH_LOCK trackedLock;
    ULONG trackedCount;
    KswordArkProcessProtectTrackedEntry tracked[KSWORD_ARK_PROCESS_PROTECT_MAX_TRACKED];

    volatile LONG64 kernelApplyCount;
    volatile LONG64 selfHealCount;
    volatile LONG64 kernelApplyFailureCount;
    volatile LONG64 hardenApplyCount;
    volatile LONG64 ruleKernelApplyCounts[KSWORD_ARK_PROCESS_PROTECT_MAX_RULES];
    volatile LONG lastKernelApplyStatus;

    EX_PUSH_LOCK lastTamperLock;
    LARGE_INTEGER lastTamperUtc100ns;
    ULONG lastTamperProcessId;
    ULONG lastTamperObservedProtection;
    ULONG lastTamperExpectedProtection;
    ULONG lastTamperRuleId;
    WCHAR lastTamperImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    // Inspection thread. After Stopping is set, the thread drains and exits; the unload path waits for it to finish before releasing state.
    PKTHREAD scanThread;
    KEVENT scanWakeEvent;
    volatile LONG scanStopping;

    // Snapshot of the most recent interception. Write access requires exclusive ownership of `LastBlockedLock`, while read
    // access is shared, ensuring that R3 observes a complete interception record rather than a stitched-together result.
    EX_PUSH_LOCK lastBlockedLock;
    LARGE_INTEGER lastBlockedUtc100ns;
    ULONG lastBlockedInitiatorPid;
    ULONG lastBlockedTargetPid;
    ULONG lastBlockedRuleId;
    ULONG lastBlockedOriginalAccess;
    ULONG lastBlockedGrantedAccess;
    ULONG lastBlockedIsThreadObject;
    WCHAR lastBlockedInitiatorImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];
    WCHAR lastBlockedTargetImage[KSWORD_ARK_PROCESS_PROTECT_IMAGE_CHARS];

    // Object callback availability is filled back by object_callback.c.
    volatile LONG objectCallbackRegistered;
    volatile LONG objectCallbackStatus;
} KswordArkProcessProtectState;

KswordArkProcessProtectState*
kswordArkProcessProtectGetState(
    VOID
    );

VOID
kswordArkProcessProtectLogFormat(
    _In_ KswordArkProcessProtectState* state,
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    );

VOID
kswordArkProcessProtectCopyFixedWideText(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    );

// Reuse handle callback layer target matching: The kernel PP layer must use the same matching semantics as the privilege
// reduction layer; otherwise, the same rule may result in a contradictory state where a handle is hit but PP is not applied.
BOOLEAN
kswordArkProcessProtectIdentityMatchPublic(
    _In_ ULONG targetKind,
    _In_ ULONG configuredProcessId,
    _In_opt_z_ PCWSTR configuredImage,
    _In_ ULONG candidateProcessId,
    _In_opt_z_ PCWSTR candidateImagePath
    );

// ---- Kernel PP layer (process_protect_kernel.c) ----

NTSTATUS
kswordArkProcessProtectKernelStart(
    _In_ KswordArkProcessProtectState* state
    );

VOID
kswordArkProcessProtectKernelStop(
    _In_ KswordArkProcessProtectState* state
    );

// Called after switching tables: invalidate the old ledger to prevent maintaining protection based on deleted rules.
VOID
kswordArkProcessProtectKernelResetTracking(
    _In_ KswordArkProcessProtectState* state
    );

// Apply a 'match rule → enforce kernel protection → register ledger' sequence to a process.
// ImagePath may be null; if null, only PID-based rules can match.
VOID
kswordArkProcessProtectKernelApplyToProcess(
    _In_ PEPROCESS processObject,
    _In_ ULONG processId,
    _In_opt_z_ PCWSTR imagePath
    );

// Remove the process from the self-healing ledger upon exit to prevent dead PIDs from filling the table.
VOID
kswordArkProcessProtectKernelUntrackProcess(
    _In_ ULONG processId
    );

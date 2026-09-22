/*++

Module Name:

    hvm_ept.h

Abstract:

    Defines four-KiB EPT split, rule, and transient allow-once handling.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"
#include "hvm_ept_local.h"

/* Preserve one temporary EPT permission grant until monitor-trap exit. */
typedef struct KswHvmEptTransient
{
    /* Record whether one permission restoration is pending. */
    BOOLEAN armed;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[3];
    /* Preserve the rule identifier that caused the temporary grant. */
    ULONG ruleId;
    /* Preserve the writable target EPT entry. */
    volatile ULONGLONG* entry;
    /* Preserve the restricted value restored on monitor-trap exit. */
    ULONGLONG restrictedValue;
    /*
     * Preserve the EPT pointer whose translations this grant invalidated.
     *
     * Zero means the grant was made in the shared hierarchy, which is the
     * feature-off case and the historical behavior.  Carrying it inside the
     * record rather than passing it down keeps every restore caller - the
     * monitor-trap exit, the overlapping-violation path and the VMXOFF
     * cleanup - unchanged.
     */
    ULONGLONG eptPointer;
} KswHvmEptTransient;

/* The violation is unruled or unsafe to continue; leave EPT enforcement. */
#define KSW_HVM_EPT_DISPOSITION_DEVIRTUALIZE 0UL
/* One permission was granted for a single instruction; monitor-trap follows. */
#define KSW_HVM_EPT_DISPOSITION_ALLOW_ONCE 1UL
/* The access is denied durably; the dispatcher injects #PF and resumes. */
#define KSW_HVM_EPT_DISPOSITION_INJECT_FAULT 2UL
/*
 * First-touch watch hit: the page's permissions were restored permanently and
 * the hierarchy invalidated.  The dispatcher must resume WITHOUT advancing RIP
 * and WITHOUT arming monitor-trap, so the faulting instruction re-executes and
 * completes normally.
 *
 * This is the only disposition that both records a hit and keeps residency:
 * a strict tripwire records and devirtualizes, allow-once keeps residency but
 * needs monitor-trap to re-restrict, and enforce denies instead of recording.
 * Watch is allow-once minus the re-restrict step, which is exactly why it
 * needs no MTF and therefore works on the nested target.
 */
#define KSW_HVM_EPT_DISPOSITION_WATCH_ONCE 3UL

/*
 * What the watch hit path observed, so the dispatcher can publish evidence
 * without re-deriving any of it in the exit path.
 *
 * Filled only when the disposition is WATCH_ONCE.  FirstHit separates the one
 * processor that won the atomic ARMED -> TRIGGERED transition from the ones
 * that faulted on the same page before the restoration reached them: those
 * must recover silently, never publish a second "first" touch.
 */
typedef struct KswHvmEptWatchHit
{
    /* Set on the single processor that owns this first touch. */
    BOOLEAN firstHit;
    /* The reported guest-linear address fell inside the requested range. */
    BOOLEAN rangeMatch;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR reserved0[2];
    /* The watch identifier, equal to the rule identifier. */
    ULONG watchId;
} KswHvmEptWatchHit;

EXTERN_C_START

/*
 * Split one two-MiB identity leaf into 512 four-KiB entries, or return the
 * existing split.  Shared with the EPT view backend, which needs four-KiB
 * granularity for the same reason rules do.
 */
NTSTATUS
kswordArkHvmEptEnsureSplitLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _Outptr_ KswHvmEptSplit** split
    );

/* Return the writable four-KiB EPT entry for one already split page. */
volatile ULONGLONG*
kswordArkHvmEptFindLeafEntry(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress
    );


/* Read the actual base leaf, including unsplit MTRR-aware large pages.
 * VM-exit safe while residency freezes the EPT allocation/split ledger. */
BOOLEAN
kswordArkHvmEptReadLeaf(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG physicalAddress,
    _Out_ ULONGLONG* leaf,
    _Out_ ULONG* leafShift
    );

/* Build a continuous RAM-plus-MMIO identity window under the runtime lock. */
NTSTATUS
kswordArkHvmBuildEptLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/* Reset EPT rules and restore split leaves before table pages are freed. */
VOID
kswordArkHvmEptResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/* Execute one versioned EPT rule operation under the runtime lock. */
NTSTATUS
kswordArkHvmEptRuleControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* response
    );

/*
 * Handle one EPT violation without allocating or waiting in VMX root.
 * GuestLinearAddressValid tells the aggregation whether a durable denial can
 * be expressed as an injected fault, since that requires a CR2 value.
 */
BOOLEAN
kswordArkHvmEptHandleViolation(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONGLONG guestLinearAddress,
    _In_ ULONG access,
    _In_ BOOLEAN guestLinearAddressValid,
    _In_opt_ const KswHvmEptLocal* local,
    _Out_ KswHvmEptTransient* transient,
    _Out_ ULONG* ruleId,
    _Out_ ULONG* disposition,
    _Out_ KswHvmEptWatchHit* watchHit
    );

/*
 * Invalidate every armed watch because residency is ending.
 *
 * A watch is a claim about a window of time in which someone was looking.  Once
 * residency stops, nothing is looking, so an armed watch that survived into the
 * next residency would report "never touched" for a period it did not observe -
 * a fabricated negative result.  The records are kept so the UI can still list
 * them, but only as INVALIDATED, requiring an explicit re-arm.
 */
VOID
kswordArkHvmEptInvalidateWatchesLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/* Restore and invalidate one armed allow-once permission set. */
BOOLEAN
kswordArkHvmEptRestoreTransient(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptTransient* transient
    );

/* Restore one allow-once permission set on monitor-trap exit. */
BOOLEAN
kswordArkHvmEptHandleMonitorTrap(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmEptTransient* transient
    );

/* Execute single-context INVEPT for the current VMX root. */
UCHAR
kswordArkHvmAsmInveptSingle(
    _In_ ULONGLONG eptPointer
    );

EXTERN_C_END

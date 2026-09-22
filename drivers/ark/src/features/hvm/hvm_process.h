/*++

Module Name:

    hvm_process.h

Abstract:

    R-1 layer process handling: Deny execution based on address space, then determine what to present to the guest upon denial.

    The complete semantics for the protocol side are defined in the HVM_PROCESS section of
    shared/driver/KswordArkHvmIoctl.h; this section only adds three constraints visible only to the driver internals:

    1. Scope is determined by CR3-load exiting. Without it, we cannot know which address space is running; a rejection would
       apply to the entire machine rather than a single process, so missing this bit results in a rejection rather than a downgrade.
    2. The restricted layer is constructed by the EPTP-switching backend, which requires paging and writing the EPT table, and can only
       be done while resident and stopped—following the same rule as EPT specifications and split views. The reason is identical: during
       the resident period, the exit path reads these tables without holding locks, while newly allocated pages may carry stale EPT tags.
    3. Both entry points on the exit path (CR3 load, EPT violation) read this table without
       locking. The table is only modified when resident and stopped, guaranteed by item 2 above.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Determine the action for this execution on the exit path. */
typedef enum KswHvmProcessAction
{
    /* This page is not managed by this module; the caller continues along the original path. */
    kKswHvmProcessActionNone = 0,
    /* Inject #PF (present); the instruction does not retire and the state remains unchanged, allowing resumption in place after rollback. */
    kKswHvmProcessActionFreeze = 1,
    /* Inject #UD, allowing the guest's own unhandled exception path to tear down this process. */
    kKswHvmProcessActionTerminate = 2,
    /*
     * This entry has been unblocked, but this processor is still stuck in the restricted layer.
     *
     * The caller restores the base address from the EPT_POINTER and resumes directly without injecting anything. Without this action, unloading
     * during residency would only affect 'cores that haven't entered yet', while a core already spinning would remain frozen indefinitely.
     */
    kKswHvmProcessActionResume = 3
} KswHvmProcessAction;

/* Execute a versioned process disposal operation and acquire lifecycle ownership independently. */
NTSTATUS
kswordArkHvmProcessControl(
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* response
    );

/* Same as above, but used by a caller that already holds the runtime lock. */
NTSTATUS
kswordArkHvmProcessControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* response
    );

/*
 * Select the hierarchy when the address space is entered.
 *
 * Called in the CR3 load exit; returns TRUE if *TargetEptp is the hierarchy to use for this entry.
 * Returns FALSE if no disposition matches this address space—the caller should switch back to the base.
 *
 * Compare only the hierarchical physical page frame: CR3 low bits with PCID and flags. Comparing them sequentially
 * causes misses on machines with PCID enabled, where the symptom is 'the feature is installed but nothing happens'.
 */
BOOLEAN
kswordArkHvmProcessSelectHierarchy(
    _In_ const KswHvmRuntime* runtime,
    _In_ ULONGLONG guestCr3,
    _Out_ ULONGLONG* targetEptp
    );

/*
 * Action to take when an EPT violation occurs on a page handled by a specific handler.
 *
 * This can only be hit under a restricted hierarchy: non-target address spaces never run in a restricted hierarchy. On a hit, record
 * one interception and return the action to inject; on a miss, return None and let the caller continue along the original path.
 */
KswHvmProcessAction
kswordArkHvmProcessHandleViolation(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access
    );

/* Clear the entire table and release the hierarchy it occupies when the resident component stops or unloads. The caller holds the runtime lock. */
VOID
kswordArkHvmProcessResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

EXTERN_C_END

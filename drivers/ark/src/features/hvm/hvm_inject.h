/*++

Module Name:

    hvm_inject.h

Abstract:

    R-1 layer process injection: separated view + thread hijacking. Protocol semantics are defined in the
    HVM_INJECT section of KswordArkHvmIoctl.h; this file only documents parts visible to the driver internals.

    The trigger is the view's own first execution violation, not an additional rejection. Reason: this page is already occupied
    by the KIND_HOOK view; installing an execution rejection for it would create two layers for the same leaf, while a view
    backend builds only one layer per leaf. Reusing the view violation avoids that conflict and ensures ordering—the RIP is
    modified only after the execution view has been selected, so the payload is guaranteed to be fetched from the shadow page.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Execute a versioned injection operation and acquire lifecycle ownership. */
NTSTATUS
kswordArkHvmInjectControl(
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* response
    );

/* Same as above, but used by a caller that already holds the runtime lock. */
NTSTATUS
kswordArkHvmInjectControlLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* response
    );

/*
 * After switching views, immediately before RESUME, check whether this page requires redirecting RIP.
 *
 * Returns TRUE if *NewRip is the new RIP to be written into the VMCS. Returns FALSE if
 * this #VE is unrelated to injection, and the caller continues along the original path.
 *
 * Returns TRUE only when all three conditions are met: this page has an injection pending, the current CR3 matches its
 * target, and it has not yet been executed. The CR3 check is mandatory—the view is attached to guest physical pages and is
 * visible to the entire machine; other processes executing the same physical page must not be hijacked to run the payload.
 */
BOOLEAN
kswordArkHvmInjectHijackRip(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONGLONG guestPhysicalAddress,
    _In_ ULONG access,
    _In_ ULONGLONG guestCr3,
    _In_ ULONGLONG guestRip,
    _Out_ ULONGLONG* newRip
    );

/* Clear the entire table and detach the views it occupies when the resident component stops or unloads. The caller holds the runtime lock. */
VOID
kswordArkHvmInjectResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

EXTERN_C_END

/*++

Module Name:

    hvm_cr_policy.h

Abstract:

    Declares control- and debug-register policy: pinned CR0/CR4 bits, optional
    address-space switch observation, and debug-register interception.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_exit.h"

EXTERN_C_START

/* Execute one versioned CR policy operation, acquiring lifecycle ownership. */
NTSTATUS
kswordArkHvmCrPolicyControl(
    _In_ const KSWORD_ARK_HVM_CR_POLICY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_CR_POLICY_RESPONSE* response
    );

/* Clear the configured policy and its counters. */
VOID
kswordArkHvmCrPolicyResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/*
 * Complete one MOV-CR exit.  Returns TRUE when the guest may resume with RIP
 * advanced; FALSE leaves the caller on its fail-closed path.
 */
BOOLEAN
kswordArkHvmCrPolicyHandleControlRegister(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmGprFrame* frame,
    _In_ ULONGLONG qualification
    );

/* Complete one MOV-DR exit by recording it and replaying the access. */
BOOLEAN
kswordArkHvmCrPolicyHandleDebugRegister(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmGprFrame* frame,
    _In_ ULONGLONG qualification
    );

EXTERN_C_END

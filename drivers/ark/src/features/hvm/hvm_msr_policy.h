/*++

Module Name:

    hvm_msr_policy.h

Abstract:

    Declares MSR policies: bitmap holes that turn selected MSR accesses back
    into VM exits so the dispatcher can log, deny, or fake them.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_exit.h"

/* The dispatcher completed the access; advance RIP and resume. */
#define KSW_HVM_MSR_POLICY_RESULT_HANDLED 0UL
/* No policy covers the index; the caller keeps its existing behavior. */
#define KSW_HVM_MSR_POLICY_RESULT_UNMATCHED 1UL
/* The access is refused; the caller injects #GP and resumes. */
#define KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT 2UL

EXTERN_C_START

/* Execute one versioned MSR policy operation, acquiring lifecycle ownership. */
NTSTATUS
kswordArkHvmMsrPolicyControl(
    _In_ const KSWORD_ARK_HVM_MSR_POLICY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* response
    );

/* Close every bitmap hole and clear the table before resources are freed. */
VOID
kswordArkHvmMsrPolicyResetLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/*
 * Make every VMX capability MSR read exit, so it can be narrowed.
 *
 * Not a policy: it carries no table slot, cannot be removed, and is not
 * something a caller asked for.  It lives in this module only because the
 * bitmap's bits are owned here, and going through the same choke point is what
 * keeps the "does our half of the bitmap contribute anything" count exact.
 */
VOID
kswordArkHvmMsrArmVmxCapabilityInterceptLocked(
    _Inout_ KswHvmRuntime* runtime
    );

/* Apply the policy covering one intercepted MSR access, if any. */
ULONG
kswordArkHvmMsrPolicyApply(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmGprFrame* frame,
    _In_ BOOLEAN isWrite
    );

EXTERN_C_END

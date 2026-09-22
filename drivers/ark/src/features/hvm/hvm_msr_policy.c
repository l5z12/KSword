/*++

Module Name:

    hvm_msr_policy.c

Abstract:

    MSR policies.

    The bitmap installed during preparation passes every MSR through natively,
    which is what lets residency survive at all.  A policy punches one hole in
    it: the named index starts exiting again and this module decides what the
    guest gets instead of the native access.

    Writes are deliberately weaker than reads.  Replaying an arbitrary WRMSR in
    VMX root would fault on the host IDT with no continuation available, so a
    write policy can only refuse the access or discard it.  Reads are replayed
    under structured exception handling and fall back to an injected #GP, which
    is what the guest would have taken had the index been undefined.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#include "hvm_msr_policy.h"

#include "driver/KswordArkHvmControls.h"

#include "hvm_exit_emulate.h"

#if defined(_M_AMD64)
#include <intrin.h>
#endif

/*
 * The index ranges and the byte/bit arithmetic live in KswordArkHvmControls.h
 * so the host unit tests cover the same code this file executes.  A mistake
 * here is silent: the policy simply lands on a different MSR, which also
 * exists and also accepts the write.
 */

/* Return whether the architectural bitmap covers one MSR index. */
static BOOLEAN
kswordArkHvmMsrPolicyIsCovered(
    _In_ ULONG msrIndex
    )
{
    /* Defer to the shared, unit-tested range check. */
    return KswordArkHvmMsrIndexIsCovered(msrIndex) != 0 ? TRUE : FALSE;
}

/*
 * Set or clear one bitmap bit.  A set bit makes the access exit; the zeroed
 * bitmap installed at preparation therefore passes everything through.
 */
static VOID
kswordArkHvmMsrPolicySetBit(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG msrIndex,
    _In_ BOOLEAN isWrite,
    _In_ BOOLEAN intercept
    )
{
    UCHAR* bitmap = (UCHAR*)runtime->msrBitmapVirtual;
    ULONG byteOffset = 0UL;
    UCHAR mask = 0U;

    /* Do nothing when the bitmap was never reserved. */
    if (bitmap == NULL) {
        /* Return without touching an absent bitmap. */
        return;
    }
    /* Resolve the byte and bit through the shared, unit-tested mapping. */
    if (!KswordArkHvmMsrBitmapLocate(
            msrIndex,
            isWrite ? 1 : 0,
            &byteOffset,
            &mask)) {
        /* An uncovered index has no bit to change. */
        return;
    }
    /*
     * Keep an exact count of the bits our half of the bitmap holds.
     *
     * The nested merge decides whether it can point vmcs02 straight at L1's
     * page, and that is only valid when our half adds nothing.  It used to ask
     * "are there zero MSR policies", which was true of the bitmap right up
     * until something other than a policy set a bit - and then it would have
     * shared L1's page and silently dropped our interception for L2.
     *
     * Counted here rather than by scanning the page because this is the only
     * place a bit changes, and read on every L2 entry.
     */
    if (intercept) {
        if ((bitmap[byteOffset] & mask) == 0U) {
            runtime->msrBitmapInterceptCount += 1UL;
        }
        /* Make the access exit. */
        bitmap[byteOffset] |= mask;
    } else {
        if ((bitmap[byteOffset] & mask) != 0U &&
            runtime->msrBitmapInterceptCount != 0UL) {
            runtime->msrBitmapInterceptCount -= 1UL;
        }
        /* Return the access to the native pass-through path. */
        bitmap[byteOffset] &= (UCHAR)~mask;
    }
}

VOID
kswordArkHvmMsrArmVmxCapabilityInterceptLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Do nothing when the bitmap was never reserved. */
    if (runtime == NULL || runtime->msrBitmapVirtual == NULL) {
        /* Return without arming what has no bitmap. */
        return;
    }
    /*
     * Reads only.  A WRMSR to any of these indices is architecturally #GP
     * because they are read-only, and the processor delivers that itself -
     * intercepting the write would mean emulating a fault we get for free,
     * and would put a second page of exits on a path nothing needs.
     */
    for (index = KSWORD_ARK_HVM_VMX_MSR_BASIC;
         index <= KSWORD_ARK_HVM_VMX_MSR_VMFUNC;
         ++index) {
        kswordArkHvmMsrPolicySetBit(runtime, index, FALSE, TRUE);
    }
}

/* Return the active policy covering one index and direction. */
static KswHvmMsrPolicySlot*
kswordArkHvmMsrPolicyFind(
    _Inout_ KswHvmRuntime* runtime,
    _In_ ULONG msrIndex,
    _In_ ULONG access
    )
{
    ULONG index = 0UL;

    /* Search the bounded policy table without allocation. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
         ++index) {
        KswHvmMsrPolicySlot* policy = &runtime->msrPolicies[index];

        /* Match only installed policies for the exact index and direction. */
        if (policy->active &&
            policy->msrIndex == msrIndex &&
            (policy->access & access) != 0UL) {
            /* Return the exact installed policy. */
            return policy;
        }
    }
    /* Report that no policy covers the access. */
    return NULL;
}

/* Close both bitmap holes one policy owns. */
static VOID
kswordArkHvmMsrPolicyReleaseLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmMsrPolicySlot* policy
    )
{
    /* Return the read access to the native pass-through path. */
    if ((policy->access & KSWORD_ARK_HVM_MSR_ACCESS_READ) != 0UL) {
        /* Clear the read bit for this index. */
        kswordArkHvmMsrPolicySetBit(
            runtime,
            policy->msrIndex,
            FALSE,
            FALSE);
    }
    /* Return the write access to the native pass-through path. */
    if ((policy->access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0UL) {
        /* Clear the write bit for this index. */
        kswordArkHvmMsrPolicySetBit(
            runtime,
            policy->msrIndex,
            TRUE,
            FALSE);
    }
    /* Clear the reusable slot completely. */
    RtlZeroMemory(policy, sizeof(*policy));
    /* Account the released policy. */
    if (runtime->msrPolicyCount != 0UL) {
        /* Keep the published count consistent with the table. */
        runtime->msrPolicyCount -= 1UL;
    }
}

VOID
kswordArkHvmMsrPolicyResetLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    /* Close every hole before the bitmap page is released. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
         ++index) {
        /* Skip inactive records. */
        if (!runtime->msrPolicies[index].active) {
            /* Continue to the next bounded record. */
            continue;
        }
        /* Close the holes and clear the record. */
        kswordArkHvmMsrPolicyReleaseLocked(
            runtime,
            &runtime->msrPolicies[index]);
    }
    /* Leave the table and its counters deterministic. */
    RtlZeroMemory(
        runtime->msrPolicies,
        sizeof(runtime->msrPolicies));
    runtime->msrPolicyCount = 0UL;
}

/* Install one policy over an index no other policy already intercepts. */
static NTSTATUS
kswordArkHvmMsrPolicyAddLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_HVM_MSR_POLICY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* response
    )
{
    KswHvmMsrPolicySlot* policy = NULL;
    ULONG index = 0UL;

    /* Reject an index the architectural bitmap does not describe. */
    if (!kswordArkHvmMsrPolicyIsCovered(request->msrIndex)) {
        /* Publish the stable uncovered-index protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INDEX_UNCOVERED;
        /* Return the exact coverage failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Require at least one direction and reject unknown access bits. */
    if ((request->access &
            (KSWORD_ARK_HVM_MSR_ACCESS_READ |
             KSWORD_ARK_HVM_MSR_ACCESS_WRITE)) == 0UL ||
        (request->access &
            ~(KSWORD_ARK_HVM_MSR_ACCESS_READ |
              KSWORD_ARK_HVM_MSR_ACCESS_WRITE)) != 0UL) {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reject an action outside the defined vocabulary. */
    if (request->action != KSWORD_ARK_HVM_MSR_ACTION_LOG &&
        request->action != KSWORD_ARK_HVM_MSR_ACTION_DENY &&
        request->action != KSWORD_ARK_HVM_MSR_ACTION_FAKE) {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        /* Return the exact parameter failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * A logged write would have to be replayed in VMX root, where an illegal
     * value faults with no continuation.  Refuse the combination instead of
     * offering an action that can bugcheck the machine.
     */
    if (request->action == KSWORD_ARK_HVM_MSR_ACTION_LOG &&
        (request->access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0UL) {
        /* Publish the stable unsafe-combination protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_WRITE_LOG_UNSAFE;
        /* Return the exact policy-contract failure. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Refuse a second policy over the same index and direction. */
    if (kswordArkHvmMsrPolicyFind(
            runtime,
            request->msrIndex,
            request->access) != NULL) {
        /* Publish the stable duplicate protocol status. */
        response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_DUPLICATE;
        /* Return the exact ownership conflict. */
        return STATUS_OBJECT_NAME_COLLISION;
    }
    /* Reserve one bounded table slot. */
    for (index = 0UL;
         index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
         ++index) {
        /* Select the first inactive record. */
        if (!runtime->msrPolicies[index].active) {
            /* Bind the reusable zeroed record. */
            policy = &runtime->msrPolicies[index];
            /* Stop after the first free slot. */
            break;
        }
    }
    /* Report bounded policy capacity exhaustion. */
    if (policy == NULL) {
        /* Publish the stable table-full protocol status. */
        response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_TABLE_FULL;
        /* Return the exact fixed-capacity failure. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    /* Preserve every field before the bitmap starts exiting. */
    policy->msrIndex = request->msrIndex;
    /* Preserve the intercepted directions. */
    policy->access = request->access;
    /* Preserve the action applied to an intercepted access. */
    policy->action = request->action;
    /* Preserve the value returned by a faked read. */
    policy->fakeValue = request->fakeValue;
    /* Assign the next stable protocol identifier. */
    runtime->msrPolicyNextId += 1UL;
    /* Publish the assigned identifier. */
    policy->policyId = runtime->msrPolicyNextId;
    /* Order every field before the record becomes reachable. */
    KeMemoryBarrier();
    /* Publish the installed policy record. */
    policy->active = TRUE;
    /* Account the installed policy. */
    runtime->msrPolicyCount += 1UL;
    /* Open the read hole only after the record can service it. */
    if ((policy->access & KSWORD_ARK_HVM_MSR_ACCESS_READ) != 0UL) {
        /* Make guest reads of this index exit. */
        kswordArkHvmMsrPolicySetBit(
            runtime,
            policy->msrIndex,
            FALSE,
            TRUE);
    }
    /* Open the write hole only after the record can service it. */
    if ((policy->access & KSWORD_ARK_HVM_MSR_ACCESS_WRITE) != 0UL) {
        /* Make guest writes of this index exit. */
        kswordArkHvmMsrPolicySetBit(
            runtime,
            policy->msrIndex,
            TRUE,
            TRUE);
    }
    /* Publish the assigned identifier to the caller. */
    response->policyId = policy->policyId;
    /* Publish the successful installation. */
    response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
    /* Complete the installation successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmMsrPolicyControl(
    _In_ const KSWORD_ARK_HVM_MSR_POLICY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_MSR_POLICY_RESPONSE* response
    )
{
    KswHvmRuntime* runtime = kswordArkHvmGetRuntime();
    BOOLEAN mutating = FALSE;
    ULONG index = 0UL;
    ULONG rows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Reject an incomplete caller contract before acquiring the lock. */
    if (request == NULL || response == NULL || runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response for every failure path. */
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    /* Validate the complete versioned request. */
    if (request->version !=
            KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION ||
        request->size != sizeof(*request)) {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Classify the request before deciding which guards apply. */
    mutating = request->operation != KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY;
    /* Mutating operations redirect real MSR access and need confirmation. */
    if (mutating &&
        (request->confirmationToken !=
                KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
         (request->flags &
                KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED) == 0UL)) {
        /* Publish the stable confirmation-required protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED;
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Serialize against every other lifecycle and EPT operation. */
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&runtime->lock);
    response->generation = runtime->generation;
    if (!runtime->initialized ||
        (mutating && runtime->msrBitmapVirtual == NULL)) {
        /* Publish the stable not-prepared protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_PREPARED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (mutating &&
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L) {
        /*
         * Resident VM exits read this table without taking the PASSIVE_LEVEL
         * lock, and the bitmap is live hardware state.  Keep both immutable
         * until every VCPU has committed its guest-stack return.
         */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_RESIDENT_BUSY;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No policy or bitmap bit was changed. */
        status = STATUS_SUCCESS;
    } else if (request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY) {
        /* Publish every installed policy row. */
        for (index = 0UL;
             index < KSWORD_ARK_HVM_MAX_MSR_POLICIES &&
                rows < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
             ++index) {
            const KswHvmMsrPolicySlot* policy =
                &runtime->msrPolicies[index];

            /* Skip inactive records. */
            if (!policy->active) {
                /* Continue to the next bounded record. */
                continue;
            }
            /* Publish the stable protocol identifier. */
            response->rows[rows].policyId = policy->policyId;
            /* Publish the intercepted index. */
            response->rows[rows].msrIndex = policy->msrIndex;
            /* Publish the intercepted directions. */
            response->rows[rows].access = policy->access;
            /* Publish the configured action. */
            response->rows[rows].action = policy->action;
            /* Publish the faked read value. */
            response->rows[rows].fakeValue = policy->fakeValue;
            /* Publish how often the policy has been applied. */
            response->rows[rows].hitCount = (ULONGLONG)policy->hitCount;
            /* Account the published row. */
            rows += 1UL;
        }
        /* Publish the number of rows written. */
        response->returnedRows = rows;
        /* Publish the successful query. */
        response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR) {
        /* Close every hole and clear the table. */
        kswordArkHvmMsrPolicyResetLocked(runtime);
        /* Publish the successful clear. */
        response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_REMOVE) {
        KswHvmMsrPolicySlot* policy = NULL;

        /* Locate the policy carrying the requested identifier. */
        for (index = 0UL;
             index < KSWORD_ARK_HVM_MAX_MSR_POLICIES;
             ++index) {
            /* Match only installed policies with the exact identifier. */
            if (runtime->msrPolicies[index].active &&
                runtime->msrPolicies[index].policyId ==
                    request->policyId) {
                /* Bind the exact installed policy. */
                policy = &runtime->msrPolicies[index];
                /* Stop after the first match. */
                break;
            }
        }
        if (policy == NULL) {
            /* Publish the stable not-found protocol status. */
            response->status =
                KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_FOUND;
            response->lastStatus = STATUS_NOT_FOUND;
        } else {
            /* Close the holes and clear the record. */
            kswordArkHvmMsrPolicyReleaseLocked(runtime, policy);
            /* Publish the successful removal. */
            response->status = KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK;
        }
        /* Select protocol-level success. */
        status = STATUS_SUCCESS;
    } else if (request->operation ==
        KSWORD_ARK_HVM_MSR_POLICY_OP_ADD) {
        /* Install the requested policy. */
        status = kswordArkHvmMsrPolicyAddLocked(
            runtime,
            request,
            response);
        /* Preserve the authoritative installation status. */
        response->lastStatus = status;
        /* Return a protocol-level result successfully. */
        status = STATUS_SUCCESS;
    } else {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    }
    /* Publish the resulting count on every path. */
    response->policyCount = runtime->msrPolicyCount;
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&runtime->lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}

ULONG
kswordArkHvmMsrPolicyApply(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmGprFrame* frame,
    _In_ BOOLEAN isWrite
    )
{
#if defined(_M_AMD64)
    KswHvmMsrPolicySlot* policy = NULL;
    ULONG msrIndex = 0UL;
    ULONGLONG value = 0ULL;
    BOOLEAN read = FALSE;

    /* Reject invalid fixed pointers in the nonblocking exit path. */
    if (runtime == NULL || frame == NULL) {
        /* Report no policy match. */
        return KSW_HVM_MSR_POLICY_RESULT_UNMATCHED;
    }
    /* The architectural MSR index always arrives in ECX. */
    msrIndex = (ULONG)frame->rcx;
    /* Locate the policy covering this index and direction. */
    policy = kswordArkHvmMsrPolicyFind(
        runtime,
        msrIndex,
        isWrite
            ? KSWORD_ARK_HVM_MSR_ACCESS_WRITE
            : KSWORD_ARK_HVM_MSR_ACCESS_READ);
    /* Leave an unmatched access to the caller's existing behavior. */
    if (policy == NULL) {
        /* Report no policy match. */
        return KSW_HVM_MSR_POLICY_RESULT_UNMATCHED;
    }
    /* Account the applied policy before choosing an outcome. */
    InterlockedIncrement64(&policy->hitCount);
    /* Refuse the access exactly as an undefined index would. */
    if (policy->action == KSWORD_ARK_HVM_MSR_ACTION_DENY) {
        /* Report that the caller must inject the architectural fault. */
        return KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT;
    }
    if (isWrite) {
        /*
         * The only remaining write action is FAKE, which discards the value.
         * LOG is refused at installation because replaying an arbitrary WRMSR
         * in root operation has no safe failure path.
         */
        return KSW_HVM_MSR_POLICY_RESULT_HANDLED;
    }
    /* Return the configured value without touching the real register. */
    if (policy->action == KSWORD_ARK_HVM_MSR_ACTION_FAKE) {
        /* Publish the faked value in the architectural EDX:EAX pair. */
        frame->rax = (ULONGLONG)(ULONG)policy->fakeValue;
        frame->rdx = (ULONGLONG)(ULONG)(policy->fakeValue >> 32);
        /* Report a completely serviced access. */
        return KSW_HVM_MSR_POLICY_RESULT_HANDLED;
    }
    /*
     * LOG performs the native read after recording it.  The index was chosen
     * by an operator and may still be illegal on this part, so the read is
     * guarded and falls back to the fault the guest would have taken.
     */
    read = TRUE;
    __try {
        /* Perform the exact read the guest asked for. */
        value = __readmsr(msrIndex);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Record that no value was produced. */
        read = FALSE;
    }
    /* Deliver the architectural fault when the index turned out illegal. */
    if (!read) {
        /* Report that the caller must inject the architectural fault. */
        return KSW_HVM_MSR_POLICY_RESULT_INJECT_FAULT;
    }
    /* Publish the native value in the architectural EDX:EAX pair. */
    frame->rax = (ULONGLONG)(ULONG)value;
    frame->rdx = (ULONGLONG)(ULONG)(value >> 32);
    /* Report a completely serviced access. */
    return KSW_HVM_MSR_POLICY_RESULT_HANDLED;
#else
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(IsWrite);
    return KSW_HVM_MSR_POLICY_RESULT_UNMATCHED;
#endif
}

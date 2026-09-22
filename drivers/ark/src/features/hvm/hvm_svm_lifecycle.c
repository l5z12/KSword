/* All-processor SVM lifecycle using the existing power/unload transition guard. */
#include "hvm_svm.h"
#include <intrin.h>

/* Debugger-only deterministic fault controls default to inert. */
volatile LONG gKswSvmFaultStage;
/* Exact global processor index selected by the test operator. */
volatile LONG gKswSvmFaultCpu;
/* Only a debugger can arm this internal fault point. */
volatile LONG gKswSvmFaultArmed;

/* Consume a fault only at its requested stage and CPU. */
BOOLEAN kswordSvmFault(ULONG stage, ULONG cpu)
{
    /* A nonmatching stage never consumes the one-shot arm. */
    if ((ULONG)gKswSvmFaultStage != stage || (ULONG)gKswSvmFaultCpu != cpu) { return FALSE; }
    /* Exactly one matching caller may inject a controlled failure. */
    return InterlockedCompareExchange(&gKswSvmFaultArmed, 0, 1) == 1;
}

/* One stack-owned rendezvous survives until every IPI callback returned. */
typedef struct KswSvmRendezvous {
    /* Runtime-private processor identity map. */
    KswSvmState* state;
    /* Start=1, stop=0. */
    BOOLEAN start;
    /* Each target must acknowledge exactly once. */
    volatile LONG seen[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* First authoritative worker failure. */
    volatile LONG failure;
} KswSvmRendezvous;

/* Publish only the first failing NTSTATUS. */
static VOID kswSvmFail(KswSvmRendezvous* call, NTSTATUS status)
{
    /* Do not let later successful CPUs overwrite failure evidence. */
    if (!NT_SUCCESS(status)) { InterlockedCompareExchange(&call->failure, status, STATUS_SUCCESS); }
}

/* Execute on the exact target CPU; no waiting, allocating, or pageable access. */
static ULONG_PTR kswSvmIpi(ULONG_PTR parameter)
{
    /* The broadcast owner retains this object until KeIpiGenericCall returns. */
    KswSvmRendezvous* call = (KswSvmRendezvous*)parameter;
    /* Global index alone is not trusted without group/number comparison. */
    ULONG index = KeGetCurrentProcessorIndex();
    /* Preserve the exact current identity for verification. */
    PROCESSOR_NUMBER number;
    /* This worker's status is independent of other CPU return values. */
    NTSTATUS status = STATUS_SUCCESS;
    /* The context is resolved only after checking array bounds. */
    KswSvmCpu* cpu;
    /* An unrepresented processor invalidates the complete target set. */
    if (index >= call->state->count) { kswSvmFail(call, STATUS_NOT_FOUND); return 0; }
    /* Select only the CPU-owned context. */
    cpu = &call->state->cpus[index];
    /* Partial preparation never supplies an executable CPU context. */
    if (cpu->resource == NULL) { kswSvmFail(call, STATUS_DEVICE_NOT_READY); return 0; }
    /* Obtain the actual Windows group/number pair. */
    KeGetCurrentProcessorNumberEx(&number);
    /* Both duplicate and mismatched participants invalidate the rendezvous. */
    if (number.Group != cpu->resource->row.processorGroup || number.Number != cpu->resource->row.processorNumber ||
        InterlockedIncrement(&call->seen[index]) != 1) { kswSvmFail(call, STATUS_DATA_ERROR); return 0; }
    /* Starting must occur only after this CPU's real VMRUN self-test. */
    if (call->start) {
        /* Check pending power immediately before the architecture transition. */
        if (!cpu->testPassed || cpu->runtime->powerTransitionPending ||
            cpu->runtime->powerTransitionGeneration != call->state->testedPowerGeneration) { status = STATUS_POWER_STATE_INVALID; }
        /* Current processor entry uses only preallocated resources. */
        else if (kswordSvmFault(2, index)) { status = STATUS_CANCELLED; }
        /* A post-continuation fault keeps Active set so rollback must really stop this CPU. */
        else {
            /* Begin a normal resident continuation. */
            cpu->selfTest = 0; cpu->stopRequested = 0; status = kswordSvmEnterCurrent(cpu);
            /* Failure after entry is not allowed to erase its hardware ownership. */
            if (NT_SUCCESS(status) && kswordSvmFault(3, index)) { status = STATUS_CANCELLED; }
        }
    } else if (cpu->active) {
        /* Publish ownership of the private stop operation before VMMCALL. */
        InterlockedExchange(&cpu->stopRequested, 1);
        /* Request complete native restoration, not just exit from VMRUN. */
        if (cpu->nativeReturnSeen || KswordSvmAsmCall(KSW_SVM_CALL_STOP) != 0) { status = STATUS_HV_OPERATION_FAILED; }
        /* The hypercall returned only after EFER/HSAVE/stack restoration. */
        else if ((__readmsr(KSW_SVM_MSR_EFER) & KSW_SVM_EFER_SVME) || __readmsr(KSW_SVM_MSR_HSAVE) != cpu->originalHsave ||
            !kswordSvmVerifyNativeState(cpu)) {
            /* Do not free resources when native ownership readback failed. */
            status = STATUS_HV_OPERATION_FAILED;
            /* The CPU did return natively; never execute a second native VMMCALL on retry. */
            cpu->nativeReturnSeen = 1;
        } else {
            /* Current CPU acknowledges complete native continuation. */
            InterlockedExchange(&cpu->active, 0);
            /* Summary count follows the per-CPU acknowledgement. */
            InterlockedDecrement(&cpu->runtime->residentProcessorCount);
            /* Publish architecture-neutral stopped evidence. */
            cpu->stage = KSWORD_ARK_HVM_STAGE_STOPPED;
            /* Clear the generic resident bit and mark complete devirtualization. */
            cpu->resource->row.stateFlags &= ~KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE;
            /* This bit describes complete native return, not VMXOFF specifically. */
            cpu->resource->row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED;
        }
    }
    /* Preserve per-CPU status even if a different CPU failed first. */
    if (!NT_SUCCESS(status) && NT_SUCCESS(cpu->failureStatus)) {
        /* Preserve the first fault while rollback may later complete successfully. */
        cpu->failureStatus = status; cpu->failureStage = (ULONG)cpu->stage;
    }
    /* A successful rollback must not erase which CPU originally failed. */
    cpu->resource->row.lastStatus = NT_SUCCESS(cpu->failureStatus) ? status : cpu->failureStatus;
    /* Keep the first broadcast failure. */
    kswSvmFail(call, status);
    /* The caller validates all Seen slots, not this single return value. */
    return NT_SUCCESS(status) ? 1 : 0;
}

/* Verify the exact participant set and final ownership, not merely counts. */
static NTSTATUS kswSvmBroadcast(KswSvmState* state, BOOLEAN start)
{
    /* Zero-init guarantees every target begins unacknowledged. */
    KswSvmRendezvous call = {0};
    /* Verification iterates the frozen topology. */
    ULONG index;
    /* Give each callback the same immutable target set. */
    call.state = state; call.start = start;
    /* Synchronous completion establishes lifetime of call and Seen array. */
    (void)KeIpiGenericCall(kswSvmIpi, (ULONG_PTR)&call);
    /* Verify every expected target and its final architecture state. */
    for (index = 0; index < state->count; ++index) {
        /* A missing callback cannot be hidden by a duplicate success elsewhere. */
        if (!kswSvmParticipantValid((ULONG)call.seen[index], (ULONG)state->cpus[index].active, start)) {
            /* Retain the more specific worker error if one already exists. */
            kswSvmFail(&call, STATUS_HV_OPERATION_FAILED);
        }
    }
    /* Report the full rendezvous result. */
    return (NTSTATUS)call.failure;
}

/* Execute a real one-shot guest on every prepared CPU under the shared phase. */
NTSTATUS kswordSvmSelfTest(KswHvmRuntime* runtime, ULONG flags)
{
    /* Prepared runtime owns the exact tested topology. */
    KswSvmState* state = runtime->backendContext;
    /* Reject unsupported controls before taking the transition. */
    NTSTATUS status = kswordSvmValidateFlags(runtime, flags);
    /* Iterate all Windows global processor indices. */
    ULONG index;
    /* Capture the power epoch, not just a transient pending bit. */
    LONG generation = runtime->powerTransitionGeneration;
    /* No self-test may interrupt a live resident or incomplete rollback. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Resource readiness and count both form the preparation contract. */
    if (state == NULL || runtime->residentProcessorCount || runtime->preparedProcessorCount != state->count ||
        state->preparedPowerGeneration != generation) { return STATUS_DEVICE_NOT_READY; }
    /* Share the same phase as resident start/stop and power callbacks. */
    status = kswordArkHvmAcquireResidentTransition(runtime);
    /* Do not wait at an unsafe IRQL when another transition owns the phase. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Invalidate previous test evidence before beginning a new complete set. */
    runtime->selfTestPassedProcessorCount = 0;
    /* Partial tests never publish the aggregate success bit. */
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED);
    /* Clear all private test evidence, including CPUs not reached after a failure. */
    for (index = 0; index < state->count; ++index) {
        /* Invalidate both private and protocol-visible evidence together. */
        state->cpus[index].testPassed = 0;
        /* A CPU not reached by a failed retest must not retain stale success. */
        state->cpus[index].resource->row.stateFlags &= ~KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
    }
    /* No hardware is owned while moving the control thread between processors. */
    kswordArkHvmReleaseResidentTransition(runtime);
    /* Each short hardware window stays on one fixed processor. */
    for (index = 0; index < state->count; ++index) {
        /* Group-aware target binding. */
        GROUP_AFFINITY target = {0}, previous;
        /* IRQL protects the short local hardware window, not phase ownership. */
        KIRQL previousIrql;
        /* Select processor-private execution state. */
        KswSvmCpu* cpu = &state->cpus[index];
        /* A complete sleep/resume cycle invalidates the whole attempted set. */
        if (runtime->powerTransitionPending || runtime->powerTransitionGeneration != generation) { status = STATUS_POWER_STATE_INVALID; break; }
        /* Select the exact prepared group and logical processor. */
        target.Group = cpu->resource->row.processorGroup; target.Mask = (KAFFINITY)1 << cpu->resource->row.processorNumber;
        /* Restore caller affinity immediately after this processor's test. */
        KeSetSystemGroupAffinityThread(&target, &previous);
        /* Acquire the same phase only after the target affinity is established. */
        status = kswordArkHvmAcquireResidentTransition(runtime);
        /* Restore affinity when another transition cannot be joined. */
        if (!NT_SUCCESS(status)) { KeRevertToUserGroupAffinityThread(&previous); break; }
        /* Prevent thread migration during the hardware ownership window. */
        KeRaiseIrql(DISPATCH_LEVEL, &previousIrql);
        /* Select the bounded one-shot CPUID guest. */
        cpu->selfTest = (flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) ? 2U : 1U;
        /* Execute VMRUN and the full native restoration path. */
        status = runtime->powerTransitionPending || runtime->powerTransitionGeneration != generation
            ? STATUS_POWER_STATE_INVALID : kswordSvmEnterCurrent(cpu);
        /* Release phase before lowering IRQL so a queued power DPC cannot wait on its own preempted owner. */
        kswordArkHvmReleaseResidentTransition(runtime);
        /* Restore scheduling context only after hardware ownership has returned. */
        KeLowerIrql(previousIrql);
        /* Return the control thread to its original affinity. */
        KeRevertToUserGroupAffinityThread(&previous);
        /* Preserve exact per-CPU self-test failure. */
        cpu->resource->row.lastStatus = status;
        /* One failed processor invalidates the aggregate result. */
        if (!NT_SUCCESS(status)) { break; }
        /* Record real execution evidence, never merely EFER.SVME=1. */
        cpu->testPassed = 1; cpu->stage = KSWORD_ARK_HVM_STAGE_TESTED;
        /* This generic state does not claim a VMXON instruction executed. */
        cpu->resource->row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
        /* Count only fully restored successful tests. */
        runtime->selfTestPassedProcessorCount++;
    }
    /* Commit the complete test set while serialized with power invalidation. */
    {
        /* Retain the hardware failure if final phase acquisition also fails. */
        NTSTATUS phaseStatus = kswordArkHvmAcquireResidentTransition(runtime);
        /* No aggregate success is published without this final phase. */
        if (!NT_SUCCESS(phaseStatus)) { return NT_SUCCESS(status) ? phaseStatus : status; }
    }
    /* Never join evidence across topology or power epochs. */
    if (NT_SUCCESS(status) && (runtime->powerTransitionPending || runtime->powerTransitionGeneration != generation ||
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != state->count)) { status = STATUS_POWER_STATE_INVALID; }
    /* Publish only the complete validated set. */
    if (NT_SUCCESS(status) && runtime->selfTestPassedProcessorCount == state->count) {
        /* Save the epoch that authorizes future start. */
        state->testedPowerGeneration = generation;
        /* The entire CPU set passed an actual VMRUN/native-return test. */
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED);
    }
    /* Release the shared phase after all local hardware windows are closed. */
    kswordArkHvmReleaseResidentTransition(runtime);
    /* Return the first failure or complete-set success. */
    return status;
}

/* Return unload ownership only after all CPUs are proven native. */
static NTSTATUS kswSvmDisarm(KswHvmRuntime* runtime)
{
    /* A power transition holds the unload guard until S0 resumes. */
    if (runtime->powerTransitionPending || !(runtime->stateFlags & KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED)) { return STATUS_SUCCESS; }
    /* The common guard verifies it still owns the exact driver-unload slot. */
    return kswordArkHvmDisarmUnloadGuard(runtime);
}

/* Two-phase start: enter all targets, then publish Active or roll all targets back. */
NTSTATUS kswordSvmStart(KswHvmRuntime* runtime, ULONG flags)
{
    /* The prepared immutable topology/NPT is the transaction's resource set. */
    KswSvmState* state = runtime->backendContext;
    /* Reject unsupported options before arming unload protection. */
    NTSTATUS status = kswordSvmValidateFlags(runtime, flags);
    /* Rollback status cannot hide the original entry failure. */
    NTSTATUS rollback;
    /* Validate common readiness plus AMD-specific resources. */
    if (!NT_SUCCESS(status)) { return status; }
    /* A passed bounded probe does not authorize an arbitrary nested Windows workload. */
    if (flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) { return STATUS_NOT_SUPPORTED; }
    /* Refuse missing lifecycle guards and partial self-test sets. */
    if (!runtime->residentStartAllowed || state == NULL || !state->npt.rootPa ||
        !(runtime->stateFlags & KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) ||
        runtime->preparedProcessorCount != state->count || runtime->selfTestPassedProcessorCount != state->count) { return STATUS_DEVICE_NOT_READY; }
    /* Never replace a live or uncertain ownership state. */
    if (runtime->residentProcessorCount || (runtime->stateFlags & (KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED))) { return STATUS_INVALID_DEVICE_STATE; }
    /* Serialize against power and other hardware transitions. */
    status = kswordArkHvmAcquireResidentTransition(runtime);
    /* Preserve busy semantics of the existing lifecycle. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Revalidate topology and power immediately before entering. */
    if (runtime->powerTransitionPending || runtime->powerTransitionGeneration != state->testedPowerGeneration ||
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != state->count) {
        /* Failed readiness has not changed hardware ownership. */
        kswordArkHvmReleaseResidentTransition(runtime); return STATUS_POWER_STATE_INVALID;
    }
    /* Protect the driver image before the first CPU enters. */
    status = kswordArkHvmArmUnloadGuard(runtime);
    /* Failed unload ownership must prevent every VMRUN. */
    if (!NT_SUCCESS(status)) { kswordArkHvmReleaseResidentTransition(runtime); return status; }
    /* A fresh start begins a new per-CPU failure ledger after all readiness gates passed. */
    {
        /* Reset only when no CPU from an earlier attempt remains resident. */
        ULONG index;
        /* Keep cleanup evidence until the next authorized start. */
        for (index = 0; index < state->count; ++index) { state->cpus[index].failureStatus = STATUS_SUCCESS; state->cpus[index].failureStage = 0; }
    }
    /* Observers can see Starting, never premature Active. */
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
    /* Each worker publishes a private native/guest continuation acknowledgement. */
    status = kswSvmBroadcast(state, TRUE);
    /* Recheck epoch after rendezvous, including complete sleep/resume cycles. */
    if (NT_SUCCESS(status) && (runtime->powerTransitionPending || runtime->powerTransitionGeneration != state->testedPowerGeneration ||
        runtime->residentProcessorCount != (LONG)state->count)) { status = STATUS_POWER_STATE_INVALID; }
    /* Only full-set entry is a successful resident implementation. */
    if (NT_SUCCESS(status)) {
        /* Publish Active only after all exact target identities acknowledged. */
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE);
        /* The implementation enum now describes observed hardware state. */
        runtime->residentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE;
    } else {
        /* Roll back already-entered CPUs while still holding the same transition. */
        rollback = kswSvmBroadcast(state, FALSE);
        /* Never free retained resources on incomplete rollback. */
        if (!NT_SUCCESS(rollback) || runtime->residentProcessorCount != 0) {
            /* Keep the driver-unload guard armed for all surviving owners. */
            kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
            /* Distinguish partial hardware ownership from unsupported capability. */
            runtime->residentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        } else {
            /* Successful rollback leaves capability-only, not Active. */
            runtime->residentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
            /* Return the unload entry only when power state permits it. */
            rollback = kswSvmDisarm(runtime);
            /* Failed unload restoration is still an incomplete lifecycle. */
            if (!NT_SUCCESS(rollback)) { kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED); }
        }
    }
    /* Starting no longer describes this operation's final state. */
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STARTING);
    /* Release the transaction phase after commit or full rollback attempt. */
    kswordArkHvmReleaseResidentTransition(runtime);
    /* Preserve the original cause of start failure. */
    return status;
}

/* Called both by controls and by the existing power/unload guards. */
NTSTATUS kswordSvmStop(KswHvmRuntime* runtime)
{
    /* Retain private state until the complete operation finishes. */
    KswSvmState* state = runtime->backendContext;
    /* The common phase is required even for a currently empty runtime. */
    NTSTATUS status = kswordArkHvmAcquireResidentTransition(runtime);
    /* Preserve the callback's busy/fail-closed behavior. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Publish the stop transition before sending any private hypercalls. */
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
    /* An absent context needs no IPI, but still needs unload-guard handling. */
    status = state && state->cpus ? kswSvmBroadcast(state, FALSE) : STATUS_SUCCESS;
    /* Full-set native evidence is required in addition to the summary counter. */
    if (NT_SUCCESS(status) && runtime->residentProcessorCount == 0) {
        /* Return the precise driver-unload entry when permitted by power state. */
        status = kswSvmDisarm(runtime);
        /* Clear Active only after all processors are natively restored. */
        kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE);
        /* Keep the backend available for another tested start. */
        runtime->residentImplementation = KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
    } else if (NT_SUCCESS(status)) { status = STATUS_HV_OPERATION_FAILED; }
    /* Failed stop retains all allocations and the unload guard. */
    if (!NT_SUCCESS(status)) { kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED); }
    /* The synchronous stop attempt has ended. */
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
    /* Release the same phase shared with power, self-test and start. */
    kswordArkHvmReleaseResidentTransition(runtime);
    /* Never report a partially stopped machine as successful. */
    return status;
}

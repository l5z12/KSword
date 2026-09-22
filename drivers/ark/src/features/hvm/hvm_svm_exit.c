/* AMD VMEXIT dispatcher: processor-local writes, no pageable code or allocation. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"
#include <intrin.h>

/* Publish raw evidence without global locks or kernel logging in the hot path. */
VOID kswordSvmTrace(KswSvmCpu* cpu, ULONG stage)
{
    /* Only this CPU writes its ring; queries validate the sequence twice. */
    KswSvmTrace* row = &cpu->trace[cpu->tracePosition % KSW_SVM_TRACE_ROWS];
    /* Odd sequence makes a concurrent reader reject an incomplete row. */
    InterlockedIncrement(&row->sequence);
    /* Preserve stage separately from architecture exit code. */
    row->stage = stage;
    /* Raw codes are 64-bit and never index an Intel-sized histogram. */
    row->exitCode = kswSvmRead64(cpu->guest, KSW_VMCB_EXITCODE);
    /* Preserve both architecture-specific exit operands. */
    row->info1 = kswSvmRead64(cpu->guest, KSW_VMCB_EXITINFO1);
    /* NPF's fault GPA is carried in EXITINFO2. */
    row->info2 = kswSvmRead64(cpu->guest, KSW_VMCB_EXITINFO2);
    /* Continuation evidence belongs to this exact exit. */
    row->rip = kswSvmRead64(cpu->guest, KSW_VMCB_RIP);
    /* Preserve current guest stack identity. */
    row->rsp = kswSvmRead64(cpu->guest, KSW_VMCB_RSP);
    /* Preserve current address-space identity. */
    row->cr3 = kswSvmRead64(cpu->guest, KSW_VMCB_CR3);
    /* Retain NRIP even when it is invalid for the exit type. */
    row->nrip = kswSvmRead64(cpu->guest, KSW_VMCB_NRIP);
    /* Event injection is part of the failure diagnosis. */
    row->event = kswSvmRead64(cpu->guest, KSW_VMCB_EVENT);
    /* This is a local timestamp, not an assumed synchronized wall clock. */
    row->tsc = __rdtsc();
    /* Even sequence publishes a complete record with release ordering. */
    InterlockedIncrement(&row->sequence);
    /* The position is published only after the row is complete. */
    InterlockedIncrement((volatile LONG*)&cpu->tracePosition);
}

/* A faulted root cannot safely resume arbitrary guest code. */
static DECLSPEC_NORETURN VOID kswSvmFatal(KswSvmCpu* cpu, ULONG detail)
{
    /* Preserve the final root evidence before invoking the stop path. */
    cpu->stage = KSWORD_ARK_HVM_STAGE_FAILED;
    /* Keep all ownership alive until a known complete native return. */
    kswordArkHvmStateSet(cpu->runtime, KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
    /* A nonblocking final record avoids losing the triggering reason. */
    kswordSvmTrace(cpu, KSWORD_ARK_HVM_STAGE_FAILED);
    /* Follow the existing lifecycle's fail-closed bugcheck convention. */
    KeBugCheckEx(0x20001, 0x53564dUL, (ULONG_PTR)cpu, detail, (ULONG_PTR)kswSvmRead64(cpu->guest, KSW_VMCB_EXITCODE));
}

/* Advance only completed instructions; exceptions keep the faulting RIP. */
static VOID kswSvmAdvance(KswSvmCpu* cpu)
{
    /* NRIP is mandatory for general intercepted guest instructions in v1. */
    ULONGLONG rip = kswSvmRead64(cpu->guest, KSW_VMCB_RIP);
    /* Hardware supplies the length including valid instruction prefixes. */
    ULONGLONG next = kswSvmRead64(cpu->guest, KSW_VMCB_NRIP);
    /* Never assume a zero or stale next-RIP means a two-byte instruction. */
    if (!kswSvmNextRipValid(rip, next)) { kswSvmFatal(cpu, 1); }
    /* Commit only a valid, completed instruction continuation. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RIP, next);
}

/* Inject #GP(0) or #UD without advancing the faulting instruction. */
static VOID kswSvmInject(KswSvmCpu* cpu, ULONG vector)
{
    /* Do not overwrite an event whose delivery was interrupted. */
    if (kswSvmRead64(cpu->guest, KSW_VMCB_EXITINTINFO) & (1ULL << 31)) { kswSvmFatal(cpu, 2); }
    /* Exception type=3, valid=1; #GP includes a zero error code. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_EVENT, kswSvmExceptionEvent(vector));
}

/* Complete only MSRs intentionally owned/intercepted by this backend. */
static VOID kswSvmMsr(KswSvmCpu* cpu)
{
    /* The guest MSR number is carried in ECX. */
    ULONG msr = (ULONG)cpu->gpr[1];
    /* EXITINFO1 bit zero distinguishes WRMSR from RDMSR. */
    BOOLEAN write = (kswSvmRead64(cpu->guest, KSW_VMCB_EXITINFO1) & 1ULL) != 0;
    /* Reconstruct the guest EDX:EAX operand. */
    ULONGLONG value = ((cpu->gpr[2] & 0xffffffffULL) << 32) | (kswSvmRead64(cpu->guest, KSW_VMCB_RAX) & 0xffffffffULL);
    /* EFER reads hide only the backend-owned SVME bit. */
    ULONGLONG efer = kswSvmRead64(cpu->guest, KSW_VMCB_EFER) & ~KSW_SVM_EFER_SVME;
    /* Kernel-only instruction semantics must not be bypassed. */
    if (((PUCHAR)cpu->guest)[KSW_VMCB_CPL] != 0) { kswSvmInject(cpu, 13); return; }
    /* No other software may install SVM ownership or mutate the cache/XSTATE contract. */
    if (write) {
        /* Idempotent EFER writes preserve Windows behavior without permitting nested SVM. */
        if (msr == KSW_SVM_MSR_EFER && value == efer) { kswSvmAdvance(cpu); return; }
        /* Preserve the prepared XSS mask, cache interpretation and disabled supervisor CET. */
        if (kswSvmStateMsrWriteAllowed(msr, value, cpu->caps.pat, cpu->caps.xss)) { kswSvmAdvance(cpu); return; }
        /* Deny changes rather than forwarding writes to host state. */
        kswSvmInject(cpu, 13); return;
    }
    /* Only the SVM ownership registers require emulated reads. */
    if (msr == KSW_SVM_MSR_EFER) { value = efer; }
    /* Never leak or permit replacement of the live HSAVE address. */
    else if (msr == KSW_SVM_MSR_HSAVE) { value = cpu->originalHsave; }
    /* Preserve the firmware observation without changing its lock. */
    else if (msr == KSW_SVM_MSR_VM_CR) { value = cpu->caps.vmCr; }
    /* Out-of-bitmap unknown MSRs fault as unsupported, not as fabricated zero. */
    else { kswSvmInject(cpu, 13); return; }
    /* RDMSR writes zero-extended EAX and EDX. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RAX, (ULONG)value);
    /* Preserve the high result separately from the host's scratch RDX. */
    cpu->gpr[2] = (ULONG)(value >> 32);
    /* Only a successfully completed access advances RIP. */
    kswSvmAdvance(cpu);
}

/* Return 0 to resume and 1 to restore native Windows on this processor. */
ULONG KswordSvmExit(KswSvmCpu* cpu)
{
    /* Decode a full-width architecture code, including INVALID=-1. */
    ULONGLONG code = kswSvmRead64(cpu->guest, KSW_VMCB_EXITCODE);
    /* Count the VMRUN whose exit was actually observed. */
    cpu->tlbRequests++;
    /* Count exits without any interprocessor contention. */
    cpu->resource->row.vmExitCount++;
    /* Preserve a raw vendor-specific exit field for v5 consumers. */
    cpu->resource->row.svmExitCode = code;
    /* Publish raw trace before emulation changes RIP or operands. */
    kswordSvmTrace(cpu, KSWORD_ARK_HVM_STAGE_EXIT);
    /* Route the explicitly requested bounded nested probe before ordinary one-shot handling. */
    if (cpu->selfTest == 2U && cpu->nested) { return kswordSvmNestedProbeExit(cpu); }
    /* INVALID means the guest never executed; return to the saved kernel caller. */
    if (code == KSW_SVM_EXIT_INVALID) {
        /* Keep the failed stage authoritative after native return. */
        cpu->stage = KSWORD_ARK_HVM_STAGE_FAILED;
        /* Preserve the actual failed-entry result. */
        cpu->result = STATUS_HV_OPERATION_FAILED;
        /* Return through the launch continuation only while guest state is still initial. */
        if (cpu->active || cpu->resource->row.vmExitCount != 1) { kswSvmFatal(cpu, 3); }
        /* Use a known kernel continuation with the captured launch stack. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmGuestResume);
        /* Restore the launch stack rather than any rejected RSP. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_RSP, cpu->launchRsp);
        /* Request native restoration, never publication of Active. */
        return 1;
    }
    /* A successful self-test requires a specific executed guest CPUID marker. */
    if (cpu->selfTest) {
        /* No other exit counts as a successful hardware self-test. */
        cpu->result = code == KSW_SVM_EXIT_CPUID && (ULONG)kswSvmRead64(cpu->guest, KSW_VMCB_RAX) == KSW_SVM_TEST_LEAF ? STATUS_SUCCESS : STATUS_HV_OPERATION_FAILED;
        /* The one-shot guest never enters arbitrary Windows execution. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmGuestResume);
        /* Return through the original call stack. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_RSP, cpu->launchRsp);
        /* Complete the self-test through the native-state restoration path. */
        return 1;
    }
    /* CPUID preserves outer VMware identity but hides unimplemented nested SVM. */
    if (code == KSW_SVM_EXIT_CPUID) {
        /* Decode guest leaf/subleaf without using host call operands. */
        ULONG leaf = (ULONG)kswSvmRead64(cpu->guest, KSW_VMCB_RAX);
        /* Intrinsics use signed integers, converted explicitly on both sides. */
        int r[4];
        /* Query the actual outer virtual CPU topology and features. */
        __cpuidex(r, (int)leaf, (int)(ULONG)cpu->gpr[1]);
        /* Nested SVM is not exposed to the monitored Windows instance. */
        kswSvmFilterCpuid(leaf, r);
        /* Store architectural EAX/EBX/ECX/EDX results with zero extension. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_RAX, (ULONG)r[0]);
        /* RBX is not hardware-switched by VMRUN. */
        cpu->gpr[3] = (ULONG)r[1];
        /* RCX is not hardware-switched by VMRUN. */
        cpu->gpr[1] = (ULONG)r[2];
        /* RDX is not hardware-switched by VMRUN. */
        cpu->gpr[2] = (ULONG)r[3];
        /* CPUID completed successfully. */
        kswSvmAdvance(cpu);
    } else if (code == KSW_SVM_EXIT_MSR) {
        /* Emulate ownership-controlled MSRs without root RDMSR exception hazards. */
        kswSvmMsr(cpu);
    } else if (code == KSW_SVM_EXIT_VMMCALL && cpu->gpr[1] == KSW_SVM_CALL_SIGNATURE &&
        ((PUCHAR)cpu->guest)[KSW_VMCB_CPL] == 0) {
        /* A stop operation must have been requested by the pinned lifecycle worker. */
        if (cpu->gpr[2] == KSW_SVM_CALL_STOP && cpu->stopRequested && cpu->active) {
            /* Advance beyond exactly the private hypercall instruction. */
            kswSvmAdvance(cpu);
            /* Return success to the stopping Windows caller. */
            kswSvmWrite64(cpu->guest, KSW_VMCB_RAX, 0);
            /* Native completion is acknowledged by the caller after assembly returns. */
            return 1;
        }
        /* Query is the only non-mutating private operation. */
        if (cpu->gpr[2] == KSW_SVM_CALL_QUERY) {
            /* The caller can compare a private response without changing residency. */
            kswSvmWrite64(cpu->guest, KSW_VMCB_RAX, KSW_SVM_CALL_SIGNATURE);
            /* Query completed successfully. */
            kswSvmAdvance(cpu);
        } else { kswSvmInject(cpu, 6); }
    } else if ((code >= 0x80 && code <= 0x86) || code == 0x7a || code == 0x8d) {
        /* SVM operations are absent from CPUID; XSETBV contract changes are denied. */
        kswSvmInject(cpu, code == 0x8d ? 13 : 6);
    } else {
        /* Unexpected NPF, shutdown, or unknown intercept requires retained evidence. */
        kswSvmFatal(cpu, 4);
    }
    /* Resume only after one of the explicitly handled paths completed. */
    return 0;
}

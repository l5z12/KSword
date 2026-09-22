/* Build AMD control/save state from the currently pinned Windows processor. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"
#include <intrin.h>

/* Decode the GDT format into AMD segment attributes and expanded limits. */
static BOOLEAN kswSvmSegment(KswSvmVmcb* vmcb, ULONG offsetArg, BOOLEAN system)
{
    /* Selector was captured by the assembly helper on this processor. */
    KswSvmSegment* segment = (KswSvmSegment*)((PUCHAR)vmcb + offsetArg);
    /* GDTR was captured in the same operation. */
    KswSvmSegment* gdtr = (KswSvmSegment*)((PUCHAR)vmcb + KSW_VMCB_GDTR);
    /* Null selectors remain architecturally unusable. */
    ULONG offset = segment->selector & ~7U;
    /* Raw descriptor words are read only from the current kernel GDT. */
    ULONGLONG descriptor;
    /* No null-segment memory read. */
    if (offset == 0) { return TRUE; }
    /* Local descriptor tables are outside the initial backend contract. */
    if ((segment->selector & 4U) || offset + (system ? 15U : 7U) > gdtr->limit) { return FALSE; }
    /* Never propagate a failed descriptor read as a zeroed valid segment. */
    __try {
        /* Read the low descriptor. */
        descriptor = *(volatile ULONGLONG*)(ULONG_PTR)(gdtr->base + offset);
        /* Convert access byte and AVL/L/DB/G flags into AMD attributes. */
        segment->attributes = (USHORT)(((descriptor >> 40) & 0xffULL) | ((descriptor >> 44) & 0xf00ULL));
        /* Reconstruct the twenty-bit limit. */
        segment->limit = (ULONG)((descriptor & 0xffffULL) | ((descriptor >> 32) & 0xf0000ULL));
        /* Expand granularity exactly once. */
        if (descriptor & (1ULL << 55)) { segment->limit = (segment->limit << 12) | 0xfffU; }
        /* Reconstruct the low thirty-two base bits. */
        segment->base = ((descriptor >> 16) & 0xffffffULL) | ((descriptor >> 32) & 0xff000000ULL);
        /* Long-mode system segments contain a second descriptor word. */
        if (system) { segment->base |= (*(volatile ULONG*)(ULONG_PTR)(gdtr->base + offset + 8ULL)) * 0x100000000ULL; }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* An unreadable GDT is not a usable entry context. */
        return FALSE;
    }
    /* Segment attributes now match the current Windows descriptor. */
    return TRUE;
}

/* Set one MSRPM bit after validating its architectural range. */
static VOID kswSvmInterceptMsr(KswSvmCpu* cpu, ULONG msr, BOOLEAN writeOnly)
{
    /* Two bits per MSR encode read then write. */
    ULONG bit = kswSvmMsrpmBit(msr, writeOnly ? 1U : 0U);
    /* All callers pass SVM/PAT/XSS encodings inside the three MSRPM windows. */
    if (bit == 0xffffffffU) { return; }
    /* Reads remain allowed when only a write could invalidate saved state. */
    ((PUCHAR)cpu->msrpm)[bit / 8] |= (UCHAR)(1U << (bit & 7));
    /* SVM ownership registers require both directions to be virtualized. */
    if (!writeOnly) { ++bit; ((PUCHAR)cpu->msrpm)[bit / 8] |= (UCHAR)(1U << (bit & 7)); }
}

/* Called before enabling SVME, while pinned at DISPATCH_LEVEL or IPI_LEVEL. */
NTSTATUS kswordSvmBuildVmcb(KswSvmCpu* cpu)
{
    /* Shared NPT remains immutable while any processor is resident. */
    KswSvmState* state = cpu->runtime->backendContext;
    /* Save-area mapping is processor-private. */
    KswSvmVmcb* v = cpu->guest;
    /* Decode the descriptors captured by assembly. */
    ULONG offset;
    /* Recheck privileged state on the pinned target immediately before entry. */
    KswSvmCaps current;
    /* Preparation evidence does not authorize a changed CET/XSTATE or SVM owner. */
    NTSTATUS status = kswordSvmProbeCpu(&current);
    /* No hardware ownership has changed when the live probe fails. */
    if (!NT_SUCCESS(status)) { return status; }
    /* The allocation format and restore mask must match the live CPU contract. */
    if (current.xcr0 != cpu->caps.xcr0 || current.xss != cpu->caps.xss ||
        current.cetPresent != cpu->caps.cetPresent) { return STATUS_NOT_SUPPORTED; }
    /* Only the bounded self-test compares to launch-time thread state, never resident stop. */
    cpu->caps.ucet = current.ucet; cpu->caps.pl3Ssp = current.pl3Ssp;
    /* Reinitialize control and state areas on every fresh launch. */
    RtlZeroMemory(v, sizeof(*v));
    /* Capture selector and GDTR/IDTR values on the target CPU. */
    KswordSvmAsmCaptureSegments(v);
    /* Decode ordinary segments, including FS/GS selector attributes. */
    for (offset = KSW_VMCB_ES; offset <= KSW_VMCB_GS; offset += 16) {
        /* A malformed or LDT-based segment cannot be guessed. */
        if (!kswSvmSegment(v, offset, FALSE)) { return STATUS_NOT_SUPPORTED; }
    }
    /* Decode both long-mode system descriptors. */
    if (!kswSvmSegment(v, KSW_VMCB_LDTR, TRUE) || !kswSvmSegment(v, KSW_VMCB_TR, TRUE)) { return STATUS_NOT_SUPPORTED; }
    /* Intercept CPUID and MSRPM-controlled MSRs, not ordinary I/O or HLT. */
    kswSvmWrite32(v, KSW_VMCB_MISC1, (1U << 18) | (1U << 26) | (1U << 28));
    /* Intercept all SVM operations plus XSETBV; nested SVM is not provided. */
    kswSvmWrite32(v, KSW_VMCB_MISC2, 0x7fU | (1U << 13));
    /* Give the CPU valid permission-map addresses even for disabled intercepts. */
    kswSvmWrite64(v, KSW_VMCB_IOPM, (ULONGLONG)MmGetPhysicalAddress(cpu->iopm).QuadPart);
    /* MSRPM excludes safe native MSRs from exit storms. */
    kswSvmWrite64(v, KSW_VMCB_MSRPM, (ULONGLONG)MmGetPhysicalAddress(cpu->msrpm).QuadPart);
    /* ASIDs are processor-local; every VMRUN conservatively flushes them. */
    kswSvmWrite32(v, KSW_VMCB_ASID, 1);
    /* TLB_CONTROL=1 requests the baseline architectural complete flush. */
    ((PUCHAR)v)[KSW_VMCB_TLB] = 1;
    /* Pass physical IRQs/APIC through: guest IF and CR8 must control delivery.
       APM 15.21.1-2: V_INTR_MASKING=1 uses host IF (zero in our CLI/CLGI
       entry path), starving guest timer interrupts even after guest STI.
       Keep V_IRQ and V_INTR_MASKING clear; we do not emulate an interrupt controller. */
    kswSvmWrite32(v, KSW_VMCB_INTCTL, 0);
    /* Enable nested paging without exposing nested virtualization to Windows. */
    kswSvmWrite64(v, KSW_VMCB_NP, 1);
    /* Publish the fully constructed shared NPT. */
    kswSvmWrite64(v, KSW_VMCB_NCR3, state->npt.rootPa);
    /* Resolve the opaque HSAVE address before entering the assembly host loop. */
    cpu->hsavePa = (ULONGLONG)MmGetPhysicalAddress(cpu->hsave).QuadPart;
    /* CR state is the current guest state, not a stale prepare-time snapshot. */
    kswSvmWrite64(v, KSW_VMCB_CR0, __readcr0());
    /* Capture the current Windows address space for guest execution. */
    kswSvmWrite64(v, KSW_VMCB_CR3, __readcr3());
    /* Preserve supported CR4 features. */
    kswSvmWrite64(v, KSW_VMCB_CR4, __readcr4());
    /* Supervisor CET is verified disabled; user CET stays in the XSAVES area. */
    kswSvmWrite64(v, KSW_VMCB_S_CET, current.scet);
    /* No active kernel shadow stack exists under the admitted S_CET=0 contract. */
    kswSvmWrite64(v, KSW_VMCB_SSP, 0);
    /* Preserve the current interrupt-table address even when supervisor CET is off. */
    kswSvmWrite64(v, KSW_VMCB_ISST, current.isst);
    /* Preserve pending page-fault address and debug register state. */
    kswSvmWrite64(v, KSW_VMCB_CR2, __readcr2());
    /* Debug control registers are not general-purpose registers. */
    kswSvmWrite64(v, KSW_VMCB_DR6, __readdr(6));
    /* Restore guest debug state on native stop as well as VM entry. */
    kswSvmWrite64(v, KSW_VMCB_DR7, __readdr(7));
    /* Read remaining current processor state before SVME ownership changes. */
    __try {
        /* Save exact original ownership registers for rollback. */
        cpu->originalEfer = __readmsr(KSW_SVM_MSR_EFER);
        /* Do not discard pre-entry HSAVE evidence. */
        cpu->originalHsave = __readmsr(KSW_SVM_MSR_HSAVE);
        /* Refuse ownership races after preparation/self-test. */
        if ((cpu->originalEfer & KSW_SVM_EFER_SVME) || cpu->originalHsave) { return STATUS_DEVICE_BUSY; }
        /* VMRUN guest state needs SVME set; MSR reads hide our owned bit. */
        kswSvmWrite64(v, KSW_VMCB_EFER, cpu->originalEfer | KSW_SVM_EFER_SVME);
        /* Preserve current guest PAT without installing another layout. */
        kswSvmWrite64(v, KSW_VMCB_PAT, __readmsr(0x277U));
        /* Identity NPT PAT indices require the prepared host layout. */
        if (kswSvmRead64(v, KSW_VMCB_PAT) != cpu->caps.pat) { return STATUS_NOT_SUPPORTED; }
        /* Long-mode FS/GS base comes from MSRs rather than legacy descriptors. */
        ((KswSvmSegment*)((PUCHAR)v + KSW_VMCB_FS))->base = __readmsr(0xc0000100U);
        /* Preserve the current kernel GS base. */
        ((KswSvmSegment*)((PUCHAR)v + KSW_VMCB_GS))->base = __readmsr(0xc0000101U);
        /* SWAPGS's alternate base is separate from the current GS base. */
        kswSvmWrite64(v, KSW_VMCB_KERNEL_GS, __readmsr(0xc0000102U));
        /* Capture all long-mode syscall MSRs used by VMLOAD/VMSAVE. */
        kswSvmWrite64(v, KSW_VMCB_STAR, __readmsr(0xc0000081U));
        /* SYSCALL target. */
        kswSvmWrite64(v, KSW_VMCB_LSTAR, __readmsr(0xc0000082U));
        /* Compatibility-mode SYSCALL target. */
        kswSvmWrite64(v, KSW_VMCB_CSTAR, __readmsr(0xc0000083U));
        /* SYSCALL flags mask. */
        kswSvmWrite64(v, KSW_VMCB_SFMASK, __readmsr(0xc0000084U));
        /* SYSENTER compatibility state. */
        kswSvmWrite64(v, KSW_VMCB_SYSENTER_CS, __readmsr(0x174U));
        /* SYSENTER stack state. */
        kswSvmWrite64(v, KSW_VMCB_SYSENTER_ESP, __readmsr(0x175U));
        /* SYSENTER instruction state. */
        kswSvmWrite64(v, KSW_VMCB_SYSENTER_EIP, __readmsr(0x176U));
        /* Preserve debug-control MSR. */
        kswSvmWrite64(v, KSW_VMCB_DEBUGCTL, __readmsr(0x1d9U));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* No hardware ownership was changed by the builder. */
        return GetExceptionCode();
    }
    /* Build explicit MSR ownership interception. */
    kswSvmInterceptMsr(cpu, KSW_SVM_MSR_EFER, FALSE);
    /* Guest writes cannot redirect the host-save area. */
    kswSvmInterceptMsr(cpu, KSW_SVM_MSR_HSAVE, FALSE);
    /* Firmware lock state is emulated read-only. */
    kswSvmInterceptMsr(cpu, KSW_SVM_MSR_VM_CR, FALSE);
    /* PAT writes would invalidate every leaf's cache index interpretation. */
    kswSvmInterceptMsr(cpu, 0x277U, TRUE);
    /* XSS must remain equal to the mask used to allocate the per-CPU save area. */
    kswSvmInterceptMsr(cpu, 0xda0U, TRUE);
    /* Enabling kernel shadow stacks would invalidate the private root/native RET path. */
    if (cpu->cetPresent) { kswSvmInterceptMsr(cpu, KSW_SVM_MSR_S_CET, TRUE); }
    /* Build the explicit nested operand only for the opt-in bounded self-test. */
    if (cpu->selfTest == 2U) { return kswordSvmNestedBuildProbe(cpu); }
    /* The assembly wrapper sets final RIP/RSP/RFLAGS immediately before VMRUN. */
    return STATUS_SUCCESS;
}

/* Verify the native state without treating initial user-thread state as a resident snapshot. */
BOOLEAN kswordSvmVerifyNativeState(KswSvmCpu* cpu)
{
    /* All reads execute on the same pinned CPU, after SVM ownership restoration. */
    __try {
        /* XCR0 changes would invalidate either allocated XSTATE layout. */
        if (_xgetbv(0) != cpu->caps.xcr0) { return FALSE; }
        /* Query XSS only on processors that enumerate its instruction family. */
        if ((cpu->caps.xsaveFeatures & 8U) && __readmsr(0xda0U) != cpu->caps.xss) { return FALSE; }
        /* Non-CET virtual CPUs must not execute the optional MSR reads. */
        if (cpu->cetPresent) {
            /* Current guest ISST, not the launch-time address, must be restored on stop. */
            if (__readmsr(KSW_SVM_MSR_S_CET) != 0 ||
                __readmsr(KSW_SVM_MSR_ISST) != kswSvmRead64(cpu->guest, KSW_VMCB_ISST)) { return FALSE; }
            /* Fixed probe code never changes user CET; current-thread values must match exactly. */
            if (cpu->selfTest && (__readmsr(0x6a0U) != cpu->caps.ucet ||
                __readmsr(0x6a7U) != cpu->caps.pl3Ssp)) { return FALSE; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* A failed read is missing restoration evidence, never a fabricated match. */
        return FALSE;
    }
    /* Only actual post-return observations establish this native-state invariant. */
    return TRUE;
}

/* All entry callers are already pinned; no allocation occurs here. */
NTSTATUS kswordSvmEnterCurrent(KswSvmCpu* cpu)
{
    /* Validate current target state before setting SVME or HSAVE. */
    NTSTATUS status = kswordSvmBuildVmcb(cpu);
    /* A failed builder has not entered virtualization. */
    if (!NT_SUCCESS(status)) { cpu->result = status; return status; }
    /* Preserve a deterministic entry failure until guest continuation proves otherwise. */
    cpu->result = STATUS_HV_OPERATION_FAILED;
    /* Entry rejection checks count exits within this launch, not a previous self-test. */
    cpu->resource->row.vmExitCount = 0;
    /* Publish the current phase before executing any privileged transition. */
    cpu->stage = KSWORD_ARK_HVM_STAGE_ENTERING;
    /* A new launch starts with no native-stop acknowledgement. */
    cpu->nativeReturnSeen = 0;
    /* Execute the independently implemented AMD continuation. */
    status = KswordSvmAsmLaunch(cpu);
    /* An invalid VMCB also returns natively, but must never publish Active. */
    if (cpu->stage == KSWORD_ARK_HVM_STAGE_FAILED || cpu->selfTest) { status = cpu->result; }
    /* A self-test succeeds only after ownership registers are natively restored. */
    if (cpu->selfTest &&
        (__readmsr(KSW_SVM_MSR_EFER) != cpu->originalEfer || __readmsr(KSW_SVM_MSR_HSAVE) != cpu->originalHsave ||
            !kswordSvmVerifyNativeState(cpu))) {
        /* Preserve retained ownership evidence instead of publishing a false passed test. */
        cpu->stage = KSWORD_ARK_HVM_STAGE_FAILED;
        /* Returning a recoverable status could release pages still referenced by hardware. */
        kswordArkHvmStateSet(cpu->runtime, KSWORD_ARK_HVM_STATE_FAULTED | KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        /* Fail closed in the restored Windows calling context instead of fabricating self-test success. */
        KeBugCheckEx(0x20001, 0x53564dUL, (ULONG_PTR)cpu, 4, 0);
    }
    /* Publish nested probe completion only after the actual native ownership readback. */
    if (cpu->selfTest == 2U && cpu->nested) {
        /* Retain failed test results as completed evidence, never as successful entries. */
        cpu->nested->completionStatus = status;
        /* Even sequence publishes counters and the precise status together. */
        InterlockedIncrement(&cpu->nested->sequence);
    }
    /* Guest/native continuation, not the host dispatcher, acknowledges completion. */
    if (NT_SUCCESS(status) && !cpu->selfTest) {
        /* Mark the current processor active exactly once after guest continuation. */
        InterlockedExchange(&cpu->active, 1);
        /* Publish the corresponding runtime owner count. */
        InterlockedIncrement(&cpu->runtime->residentProcessorCount);
        /* Retain protocol-visible non-VMX success evidence. */
        cpu->resource->row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE;
        /* Record entry completion for the all-CPU commit check. */
        cpu->stage = KSWORD_ARK_HVM_STAGE_ENTERED;
    }
    /* Return the actual continuation status. */
    return status;
}

/* Bounded executable nesting probe. This is not admission for an arbitrary inner VMM. */
#include "hvm_svm_nested_runtime.h"

/* Only the bounded probe's already owned maps are readable by this adapter.
   General L1 physical reads require the separate NPT01/RAM snapshot adapter. */
static int kswNsvmProbeReadMap(void* context, KswSvmU64 address, unsigned char* page)
{
    /* All source addresses were resolved while building the original outer VMCB. */
    KswSvmCpu* cpu = context;
    /* Original preserves those owned pointers across the virtual VMRUN transition. */
    ULONGLONG msr = kswSvmRead64(&cpu->nested->original, KSW_VMCB_MSRPM);
    /* Disabled IOPM still has an owned, valid physical allocation. */
    ULONGLONG io = kswSvmRead64(&cpu->nested->original, KSW_VMCB_IOPM);
    /* Capture only makes aligned, full-page requests. */
    if (address & 4095ULL) { return 0; }
    /* A caller cannot substitute an arbitrary guest physical address. */
    if (address >= msr && address - msr < KSW_NSVM_MSRPM_BYTES && cpu->msrpm) {
        /* Borrow the stable CPU-private map, never dereference the supplied physical value. */
        RtlCopyMemory(page, (PUCHAR)cpu->msrpm + (SIZE_T)(address - msr), 4096);
        /* One complete owned page was captured. */
        return 1;
    }
    /* Apply the same exact allocation ownership check to all three I/O pages. */
    if (address >= io && address - io < KSW_NSVM_IOPM_BYTES && cpu->iopm) {
        /* No guest-writable mapping survives this copy. */
        RtlCopyMemory(page, (PUCHAR)cpu->iopm + (SIZE_T)(address - io), 4096);
        /* Snapshot capture can proceed to the next owned page. */
        return 1;
    }
    /* Unknown operands terminate the probe; they never become permissive zero pages. */
    return 0;
}

/* Complete the controlled probe using its original, fully captured Windows context. */
static ULONG kswNsvmFinish(KswSvmCpu* cpu, NTSTATUS status)
{
    /* The begin marker is observed before the probe changes any nonvolatile GPR. */
    KswSvmNested* nested = cpu->nested;
    /* Preserve the actual exit before replacing the executable image. */
    if (!NT_SUCCESS(status)) { kswordSvmTrace(cpu, KSWORD_ARK_HVM_STAGE_FAILED); }
    /* Only the bounded probe may return to this initial snapshot. */
    if (nested->begun) {
        /* Restore the Windows state captured immediately after real first entry. */
        RtlCopyMemory(cpu->guest, &nested->original, sizeof(*cpu->guest));
        /* Restore the caller's nonvolatile registers even on an early probe abort. */
        RtlCopyMemory(cpu->gpr, nested->originalGpr, sizeof(cpu->gpr));
    }
    /* No later VMRUN can reference the inner image after this native return request. */
    nested->runningL2 = 0;
    /* The assembly path owns real SVME/HSAVE release; clear only virtual ownership here. */
    nested->msrs.efer &= ~KSW_SVM_EFER_SVME;
    /* A failed test must not leave virtual ownership in the next test's context. */
    nested->msrs.hsave = 0;
    /* Self-test return status remains separate from the assembly continuation's EAX. */
    cpu->result = status;
    /* Restore the known entry CALL chain rather than an arbitrary rejected operand. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmGuestResume);
    /* The original caller stack includes its untouched return address. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RSP, cpu->launchRsp);
    /* CLI inside the test must not leak IF=0 back into Windows. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RFLAGS, cpu->launchFlags);
    /* Request complete native assembly restoration, not another VMRUN. */
    return 1;
}

/* Validate and consume hardware NRIP for a completed virtual instruction. */
static BOOLEAN kswNsvmAdvance(KswSvmCpu* cpu)
{
    /* Never guess the size of an intercepted instruction. */
    ULONGLONG next = kswSvmRead64(cpu->guest, KSW_VMCB_NRIP);
    /* Invalid NRIP aborts this bounded test with complete native restoration. */
    if (!kswSvmNextRipValid(kswSvmRead64(cpu->guest, KSW_VMCB_RIP), next)) { return FALSE; }
    /* The operation completed; exceptions do not use this helper. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RIP, next);
    /* The dispatcher may now reenter its current VMCB. */
    return TRUE;
}

/* Construct the only admitted VMCB12 from the validated current Windows image. */
NTSTATUS kswordSvmNestedBuildProbe(KswSvmCpu* cpu)
{
    /* Resources can only have been acquired by explicit prepare-svm-probe. */
    KswSvmNested* nested = cpu->nested;
    /* A missing pool is a preparation failure, never a reason to allocate at high IRQL. */
    if (!nested || !nested->operand || !nested->stack || !nested->mergedMaps ||
        !nested->shadow.pages || nested->runningL2) { return STATUS_DEVICE_NOT_READY; }
    /* Previous permission snapshots cannot authorize a later probe invocation. */
    nested->permissions.ready = 0;
    /* Reusing this CPU must invalidate previous shadow translations/evidence. */
    if (kswSvmNestedShadowReset(&nested->shadow) != KSW_NSHADOW_OK) { return STATUS_INTEGER_OVERFLOW; }
    /* Invalidate previous published completion before changing any probe evidence. */
    InterlockedIncrement(&nested->sequence);
    /* Each test begins with no successful inner hardware entry or reflection. */
    nested->begun = nested->entries = nested->reflections = nested->faults = 0;
    /* Reset raw evidence separately from the public baseline exit counter. */
    nested->lastExit = nested->lastMarker = 0;
    /* Software GIF is diagnostic in this IF=0 bounded probe, not full NMI virtualization. */
    nested->virtualGif = 1;
    /* Start with the Windows-visible EFER, which has no virtual SVM owner. */
    nested->msrs.efer = cpu->originalEfer;
    /* Never inherit a previous test's virtual save-area declaration. */
    nested->msrs.hsave = 0;
    /* Preserve firmware's observed lock/disable state. */
    nested->msrs.vmCr = cpu->caps.vmCr;
    /* MSR operands use the exact CPU address-width contract. */
    nested->msrs.addressMask = nested->outer->addressMask;
    /* No old operand/control residue is allowed to survive into the next test. */
    RtlZeroMemory(nested->operand, 8192);
    /* Copy only from the VMCB just validated by the regular current-CPU builder. */
    RtlCopyMemory(nested->operand, cpu->guest, sizeof(*cpu->guest));
    /* Inner execution starts at a fixed nonpageable CPUID marker. */
    kswSvmWrite64(nested->operand, KSW_VMCB_RIP, (ULONGLONG)(ULONG_PTR)KswordSvmAsmNestedPayload);
    /* The test never borrows an interruptible user-mode stack. */
    kswSvmWrite64(nested->operand, KSW_VMCB_RSP,
        ((ULONGLONG)(ULONG_PTR)nested->stack + KSW_SVM_STACK_BYTES - 64ULL) & ~15ULL);
    /* No maskable interrupt is expected in the bounded inner instruction sequence. */
    kswSvmWrite64(nested->operand, KSW_VMCB_RFLAGS, 2);
    /* The first inner instruction supplies the marker, not this initialization. */
    kswSvmWrite64(nested->operand, KSW_VMCB_RAX, 0);
    /* A known baseline DR7 prevents an inherited instruction breakpoint from changing the probe. */
    kswSvmWrite64(nested->operand, KSW_VMCB_DR7, 0x400);
    /* The driver-owned identity NPT serves as the initial NPT12 operand. */
    nested->config.innerRoot = nested->outer->rootPa;
    /* The outer root stays immutable apart from hardware/software A/D. */
    nested->config.outerRoot = nested->outer->rootPa;
    /* This bounded test uses the already validated, unchanged hardware PAT at all levels. */
    nested->config.innerPat = nested->config.outerPat = nested->config.hardwarePat = cpu->caps.pat;
    /* Match candidate translations to the newly reset software cache. */
    nested->config.epoch = nested->shadow.epoch;
    /* Both stages run under the same verified virtual CPU address-width capability. */
    nested->config.innerBits = nested->config.outerBits = cpu->caps.physicalBits;
    /* The outer VMM's advertised large-page limit is authoritative. */
    nested->config.innerPage1Gb = nested->config.outerPage1Gb = cpu->caps.page1Gb;
    /* Preserve the current paging owner's NX enablement independently from leaf bits. */
    nested->config.innerNx = nested->config.outerNx = (cpu->originalEfer & (1ULL << 11)) != 0;
    /* Preserve the operand for the first bounded guest instruction sequence. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RAX, nested->operandPa);
    /* Only construction completed here; the self-test still needs actual hardware execution. */
    return STATUS_SUCCESS;
}

/* Reflection restores virtual host core state while retaining VMLOAD-managed state. */
static VOID kswNsvmReflect(KswSvmCpu* cpu)
{
    /* Current image is VMCB02 until the final copy below. */
    KswSvmNested* nested = cpu->nested;
    /* Preserve full-width raw evidence before switching images. */
    nested->lastExit = kswSvmRead64(cpu->guest, KSW_VMCB_EXITCODE);
    /* CPUID marker is still in hardware-saved guest RAX at this point. */
    nested->lastMarker = kswSvmRead64(cpu->guest, KSW_VMCB_RAX);
    /* Hardware VMRUN/VMEXIT do not implicitly execute VMLOAD/VMSAVE for L1. */
    kswSvmNestedCopyVmload(&nested->l1, cpu->guest);
    /* CR2 and DR6 are not part of the automatically restored host-state subset. */
    kswSvmWrite64(&nested->l1, KSW_VMCB_CR2, kswSvmRead64(cpu->guest, KSW_VMCB_CR2));
    /* Preserve current debug status rather than reverting it to a launch snapshot. */
    kswSvmWrite64(&nested->l1, KSW_VMCB_DR6, kswSvmRead64(cpu->guest, KSW_VMCB_DR6));
    /* Reflect the inner exit only into the pre-owned operand page. */
    kswSvmNestedReflectExit(nested->operand, cpu->guest, 1);
    /* Restore the virtual host image captured after advancing its VMRUN continuation. */
    RtlCopyMemory(cpu->guest, &nested->l1, sizeof(*cpu->guest));
    /* VMEXIT forces host CPL zero and CR0.PE, and disables its debug breakpoints. */
    ((PUCHAR)cpu->guest)[KSW_VMCB_CPL] = 0;
    /* Preserve all other host CR0 bits. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_CR0, kswSvmRead64(cpu->guest, KSW_VMCB_CR0) | 1ULL);
    /* RF clears on completed VMRUN and VM is forced clear by VMEXIT. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_RFLAGS, kswSvmRead64(cpu->guest, KSW_VMCB_RFLAGS) & ~0x30000ULL);
    /* Architectural fixed DR7 bit remains one. */
    kswSvmWrite64(cpu->guest, KSW_VMCB_DR7, 0x400);
    /* No inner execution may be mistaken for the final outer CPUID. */
    nested->runningL2 = 0;
    /* Track virtual GIF separately from the real root GIF held by assembly. */
    nested->virtualGif = 0;
    /* Count a reflection only after the complete outer continuation has been restored. */
    ++nested->reflections;
}

/* Resolve a real hardware NPF into the preallocated NPT02. */
static ULONG kswNsvmNpf(KswSvmCpu* cpu)
{
    /* The prepared state survives until the native continuation completes. */
    KswSvmNested* nested = cpu->nested;
    /* Raw NPF context must be preserved through software composition. */
    ULONGLONG info = kswSvmRead64(cpu->guest, KSW_VMCB_EXITINFO1);
    /* Fault GPA is relative to the inner guest, not a host physical address. */
    ULONGLONG gpa = kswSvmRead64(cpu->guest, KSW_VMCB_EXITINFO2);
    /* Install the production physical-window adapter. */
    KswNmmuIo io = { kswordSvmNestedRead, kswordSvmNestedCompareOr, nested };
    /* Preserve the resolver outcome separately from the hardware exit code. */
    ULONG status;
    /* The probe must make bounded progress even with a repeatedly changing source table. */
    if (++nested->faults > 128U) { return kswNsvmFinish(cpu, STATUS_IO_TIMEOUT); }
    /* No allocation, wait, pageable access or OS memory mapping occurs here. */
    status = kswSvmNestedMmuResolve(&nested->config, &io, gpa,
        (ULONG)(info & (KSW_NNPT_WRITE | KSW_NNPT_EXECUTE)), info & (KSW_NMMU_FINAL | KSW_NMMU_TABLE),
        &nested->lastTranslation);
    /* A competing A/D update is retried by the same bounded hardware NPF loop. */
    if (status == KSW_NNPT_RETRY) { return 0; }
    /* Failed translation never falls back to the outer identity root. */
    if (status != KSW_NNPT_OK) { return kswNsvmFinish(cpu, STATUS_HV_OPERATION_FAILED); }
    /* Publish only a candidate from the current shadow epoch. */
    if (kswSvmNestedShadowInstall(&nested->shadow, &nested->lastTranslation) != KSW_NSHADOW_OK) {
        /* Retain raw fault/resolution evidence for KD before returning natively. */
        return kswNsvmFinish(cpu, STATUS_INSUFFICIENT_RESOURCES);
    }
    /* The existing assembly loop issues TLB_CONTROL=1 on every actual VMRUN. */
    return 0;
}

/* Execute virtual SVM only for the exact, driver-owned bounded probe. */
ULONG kswordSvmNestedProbeExit(KswSvmCpu* cpu)
{
    /* No user-provided VM or arbitrary guest physical operand is admitted here. */
    KswSvmNested* nested = cpu->nested;
    /* Retain the exact architecture code, including 64-bit INVALID. */
    ULONGLONG code = kswSvmRead64(cpu->guest, KSW_VMCB_EXITCODE);
    /* Guest accumulator is stored in VMCB, not the host RAX register. */
    ULONGLONG operand = kswSvmRead64(cpu->guest, KSW_VMCB_RAX);
    /* An entry may be rejected before the initial begin hypercall executed. */
    if (code == KSW_SVM_EXIT_INVALID) { return kswNsvmFinish(cpu, STATUS_HV_OPERATION_FAILED); }
    /* First capture occurs before assembly touches any nonvolatile caller register. */
    if (!nested->begun) {
        /* A different first exit cannot count as an executable probe. */
        if (code != KSW_SVM_EXIT_VMMCALL || cpu->gpr[1] != KSW_SVM_CALL_SIGNATURE ||
            cpu->gpr[2] != KSW_NSVM_BEGIN || operand != nested->operandPa) { return kswNsvmFinish(cpu, STATUS_DATA_ERROR); }
        /* Snapshot the actual first guest context, not the pre-VMRUN builder's incomplete RIP/RSP. */
        RtlCopyMemory(&nested->original, cpu->guest, sizeof(*cpu->guest));
        /* Preserve all non-VMCB registers before the probe starts modifying them. */
        RtlCopyMemory(nested->originalGpr, cpu->gpr, sizeof(cpu->gpr));
        /* Publish that controlled native abort is now fully restorable. */
        nested->begun = 1;
        /* Resume immediately after the begin marker. */
        return kswNsvmAdvance(cpu) ? 0 : kswNsvmFinish(cpu, STATUS_DATA_ERROR);
    }
    /* A current inner image needs inner exit routing before ordinary SVM handling. */
    if (nested->runningL2) {
        /* Sparse NPT02 creates demand faults even for guest page-table walks. */
        if (code == KSW_SVM_EXIT_NPF) { return kswNsvmNpf(cpu); }
        /* Only execution of the known inner marker proves this probe's hardware entry. */
        if (code != KSW_SVM_EXIT_CPUID || (ULONG)operand != KSW_NSVM_INNER_MARKER ||
            kswSvmNestedInterceptRequested(&nested->vmcb12, code) != 1U) {
            /* Unknown exits are evidence of failure, never a guessed successful reflection. */
            return kswNsvmFinish(cpu, STATUS_HV_OPERATION_FAILED);
        }
        /* Return to the actual L1 continuation after its intercepted VMRUN. */
        kswNsvmReflect(cpu);
        /* Reenter the restored outer VMCB, not the inner one. */
        return 0;
    }
    /* Every admitted SVM/MSR operation belongs to the kernel-only test sequence. */
    if (((PUCHAR)cpu->guest)[KSW_VMCB_CPL] != 0) { return kswNsvmFinish(cpu, STATUS_ACCESS_DENIED); }
    /* Virtual MSRs are exercised before and after the actual inner execution. */
    if (code == KSW_SVM_EXIT_MSR) {
        /* Reconstruct WRMSR's EDX:EAX operand with architectural truncation. */
        ULONGLONG value = ((cpu->gpr[2] & 0xffffffffULL) << 32) | (operand & 0xffffffffULL);
        /* Intercept info distinguishes reads from writes. */
        ULONG write = (ULONG)(kswSvmRead64(cpu->guest, KSW_VMCB_EXITINFO1) & 1ULL);
        /* No real RDMSR/WRMSR is performed by this virtual ownership handler. */
        if (kswSvmNestedMsrAccess(&nested->msrs, (ULONG)cpu->gpr[1], write, &value) != KSW_NSVM_MSR_OK) {
            /* A rejected test operation terminates the bounded test; it is not a general exception emulator. */
            return kswNsvmFinish(cpu, STATUS_HV_OPERATION_FAILED);
        }
        /* RDMSR writes both guest halves with zero extension. */
        if (!write) { kswSvmWrite64(cpu->guest, KSW_VMCB_RAX, (ULONG)value); cpu->gpr[2] = (ULONG)(value >> 32); }
    } else if (code == 0x82ULL || code == 0x83ULL) {
        /* Software VMLOAD/VMSAVE may access only the dedicated operand in this phase. */
        if (!(nested->msrs.efer & KSW_SVM_EFER_SVME) || operand != nested->operandPa) { return kswNsvmFinish(cpu, STATUS_ACCESS_DENIED); }
        /* VMLOAD changes only its own architectural subset in the current executable image. */
        if (code == 0x82ULL) { kswSvmNestedCopyVmload(cpu->guest, nested->operand); }
        /* VMSAVE leaves all VMRUN controls and automatic state untouched. */
        else { kswSvmNestedCopyVmload(nested->operand, cpu->guest); }
    } else if (code == KSW_SVM_EXIT_VMRUN) {
        /* Keep source ownership separate from the executable combined permission maps. */
        KswNsvmPermissionView outer, inner;
        /* Entry is restricted to the fixed probe operand and its declared virtual HSAVE. */
        if (!(nested->msrs.efer & KSW_SVM_EFER_SVME) || operand != nested->operandPa ||
            nested->msrs.hsave != nested->operandPa + 4096ULL || nested->entries ||
            (kswSvmRead64(cpu->guest, KSW_VMCB_RFLAGS) & 0x200ULL)) { return kswNsvmFinish(cpu, STATUS_INVALID_DEVICE_STATE); }
        /* The operand belongs to this CPU and cannot be changed by another test participant. */
        RtlCopyMemory(&nested->vmcb12, nested->operand, sizeof(nested->vmcb12));
        /* Capture a private L1 map image before changing any executable controls. */
        if (!kswSvmNestedCapturePermissions(&nested->permissions,
            *(ULONG*)(nested->vmcb12.control + KSW_VMCB_MISC1),
            kswSvmRead64(&nested->vmcb12, KSW_VMCB_MSRPM),
            kswSvmRead64(&nested->vmcb12, KSW_VMCB_IOPM), cpu->caps.physicalBits,
            kswNsvmProbeReadMap, cpu) || !kswSvmNestedPermissionView(&nested->permissions, &inner)) {
            /* A partial or foreign map never reaches VMRUN. */
            return kswNsvmFinish(cpu, STATUS_ACCESS_DENIED);
        }
        /* Outer maps are frozen per CPU for the lifetime of this backend prepare. */
        outer.flags = *(ULONG*)(cpu->guest->control + KSW_VMCB_MISC1);
        /* Read the original owned maps, not the inner operand's physical pointers. */
        outer.msr = cpu->msrpm; outer.io = cpu->iopm;
        /* L0 restrictions survive every attempted inner permission relaxation. */
        if (!kswSvmNestedMergePermissions(&outer, &inner, nested->mergedMaps,
            nested->mergedMaps + KSW_NSVM_MSRPM_BYTES)) { return kswNsvmFinish(cpu, STATUS_DATA_ERROR); }
        /* Preserve the correct host continuation; VMRUN completes only after reflection. */
        if (!kswNsvmAdvance(cpu)) { return kswNsvmFinish(cpu, STATUS_DATA_ERROR); }
        /* Capture complete L1 state privately rather than interpreting hardware HSAVE bytes. */
        RtlCopyMemory(&nested->l1, cpu->guest, sizeof(*cpu->guest));
        /* Copy only the automatic guest-state subset; retain L1's current VMLOAD state. */
        kswSvmNestedCopyVmrun(cpu->guest, &nested->vmcb12, 1);
        /* Hardware receives only our owned shadow root, never NPT12 directly. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_NCR3, nested->pages[0].physical);
        /* Hardware sees only the independently owned, complete merged permission maps. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_MSRPM, nested->mergedMapsPa);
        /* IOPM starts after the two contiguous MSRPM pages. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_IOPM, nested->mergedMapsPa + KSW_NSVM_MSRPM_BYTES);
        /* Preserve raw non-map L0 intercepts as well as every fixed inner request. */
        kswSvmWrite32(cpu->guest, KSW_VMCB_MISC1,
            outer.flags | *(ULONG*)(nested->vmcb12.control + KSW_VMCB_MISC1));
        /* Miscellaneous SVM instruction interception remains owned by L0. */
        kswSvmWrite32(cpu->guest, KSW_VMCB_MISC2,
            *(ULONG*)(nested->l1.control + KSW_VMCB_MISC2) | *(ULONG*)(nested->vmcb12.control + KSW_VMCB_MISC2));
        /* The bounded payload injects no event into its inner context. */
        kswSvmWrite64(cpu->guest, KSW_VMCB_EVENT, 0);
        /* Every shadow mapping initially faults and must pass both source translations. */
        nested->runningL2 = 1;
        /* VMRUN sets virtual GIF for its guest, independently from outer host GIF. */
        nested->virtualGif = 1;
        /* Actual success still requires the executed marker and reflected continuation. */
        ++nested->entries;
        /* The assembly host loop performs the real VMRUN with this VMCB02 image. */
        return 0;
    } else if (code == 0x84ULL) {
        /* The probe restores virtual GIF before returning to the Windows continuation. */
        if (!(nested->msrs.efer & KSW_SVM_EFER_SVME)) { return kswNsvmFinish(cpu, STATUS_INVALID_DEVICE_STATE); }
        /* This bounded IF=0 path does not advertise general IRQ/NMI virtualization. */
        nested->virtualGif = 1;
    } else if (code == KSW_SVM_EXIT_CPUID && (ULONG)operand == KSW_NSVM_DONE_MARKER) {
        /* Final success requires both hardware entry/reflection and virtual ownership cleanup. */
        BOOLEAN passed = nested->entries == 1 && nested->reflections == 1 && nested->faults != 0 &&
            nested->lastExit == KSW_SVM_EXIT_CPUID && nested->lastMarker == KSW_NSVM_INNER_MARKER &&
            !(nested->msrs.efer & KSW_SVM_EFER_SVME) && !nested->msrs.hsave && nested->virtualGif;
        /* Complete native restoration before the public per-CPU self-test result is counted. */
        return kswNsvmFinish(cpu, passed ? STATUS_SUCCESS : STATUS_HV_OPERATION_FAILED);
    } else {
        /* The bounded probe has no legitimate unknown instruction/exception exit. */
        return kswNsvmFinish(cpu, STATUS_NOT_SUPPORTED);
    }
    /* Resume only a successfully completed virtual instruction with valid hardware NRIP. */
    return kswNsvmAdvance(cpu) ? 0 : kswNsvmFinish(cpu, STATUS_DATA_ERROR);
}

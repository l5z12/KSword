/* AMD capability discovery and PASSIVE_LEVEL resource ownership. */
#include "hvm_svm.h"
#include "hvm_svm_nested_runtime.h"
#include "../../platform/pool_compat.h"
#include <intrin.h>

/* Read each MSR independently; absent evidence must not look like zero. */
static VOID kswSvmReadEvidence(KswSvmCaps* caps, ULONG msr, ULONG bit, ULONGLONG* value)
{
    /* A VMM may advertise SVM while filtering individual MSRs. */
    __try { *value = __readmsr(msr); caps->valid |= bit; }
    /* Preserve a missing field and its precise exception. */
    __except (EXCEPTION_EXECUTE_HANDLER) { caps->exception = GetExceptionCode(); }
}

/* Preserve the exact admission check independently from its shared NTSTATUS. */
static NTSTATUS kswSvmReject(KswSvmCaps* caps, ULONG reason, NTSTATUS status)
{
    /* Every refusal publishes a stable protocol reason before returning. */
    caps->rejectReason = reason;
    /* Keep the existing status contract for control callers. */
    return status;
}

/* Must execute on the processor whose evidence it returns. */
NTSTATUS kswordSvmProbeCpu(KswSvmCaps* caps)
{
    /* CPUID outputs are signed intrinsics, decoded explicitly below. */
    int r[4];
    /* Start with no valid privileged evidence. */
    RtlZeroMemory(caps, sizeof(*caps));
    /* Never query an unavailable extended leaf. */
    __cpuid(r, (int)0x80000000U);
    /* Preserve the bound for diagnostics. */
    caps->maxLeaf = (ULONG)r[0];
    /* The backend needs both MAXPHYADDR and SVM enumeration. */
    if (caps->maxLeaf < 0x8000000aU) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_CPUID_RANGE, STATUS_NOT_SUPPORTED); }
    /* Discover SVM and one-GiB pages separately. */
    __cpuid(r, (int)0x80000001U);
    /* ECX.SVM is the instruction capability gate. */
    caps->svm = ((ULONG)r[2] & 4U) != 0;
    /* EDX.Page1GB controls large NPT leaf construction. */
    caps->page1Gb = ((ULONG)r[3] & (1U << 26)) != 0;
    /* SVM ASID count and optional features. */
    __cpuid(r, (int)0x8000000aU);
    /* ASID zero is reserved. */
    caps->asidCount = (ULONG)r[1];
    /* Do not infer optional features from the CPU model. */
    caps->features = (ULONG)r[3];
    /* Read the actual address width exposed by the outer VMM. */
    __cpuid(r, (int)0x80000008U);
    /* The four-level NPT implementation validates this width. */
    caps->physicalBits = (ULONG)r[0] & 0xffU;
    /* Stop before touching SVM-only MSRs if SVM is filtered. */
    if (!caps->svm || !(caps->features & 1U) || !kswSvmAsidValid(caps->asidCount, 1)) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_SVM_NPT_ASID, STATUS_NOT_SUPPORTED); }
    /* General user-mode intercepts need NRIP; no unsafe root instruction fetch fallback. */
    if (!(caps->features & 8U)) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_NRIP, STATUS_NOT_SUPPORTED); }
    /* Capture all ownership/cache evidence independently. */
    kswSvmReadEvidence(caps, KSW_SVM_MSR_VM_CR, 1, &caps->vmCr);
    /* EFER.SVME belongs to an existing VMM when already set. */
    kswSvmReadEvidence(caps, KSW_SVM_MSR_EFER, 2, &caps->efer);
    /* A nonzero save address is treated conservatively as ownership conflict. */
    kswSvmReadEvidence(caps, KSW_SVM_MSR_HSAVE, 4, &caps->hsave);
    /* Read the existing PAT rather than writing a preferred layout. */
    kswSvmReadEvidence(caps, 0x277U, 8, &caps->pat);
    /* A filtered MSR makes hardware readiness unproven. */
    if (caps->valid != 15) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_MSR_READ, NT_SUCCESS(caps->exception) ? STATUS_NOT_SUPPORTED : caps->exception); }
    /* Respect firmware SVMDIS and existing virtualization ownership. */
    if (caps->vmCr & 0x10ULL) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_FIRMWARE, STATUS_DEVICE_BUSY); }
    /* An enabled SVM owner remains an unconditional refusal. */
    if (caps->efer & KSW_SVM_EFER_SVME) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_SVME, STATUS_DEVICE_BUSY); }
    /* Preserve the conservative nonzero-HSAVE gate while diagnosing other blockers. */
    if (caps->hsave) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_HSAVE, STATUS_DEVICE_BUSY); }
    /* Capture the CR4 observation before testing individual unsupported state bits. */
    caps->cr4 = __readcr4();
    /* Zero CR4 is only meaningful when this explicit observation bit is set. */
    caps->stateValid |= KSWORD_ARK_SVM_VALID_CR4;
    /* Require an OS-enabled XSAVE path for complete user XSTATE preservation. */
    __cpuid(r, 1);
    /* Preserve the OSXSAVE gate as well as the hardware XSAVE support bit. */
    caps->cpuid1Ecx = (ULONG)r[2];
    /* Publish which leaf was actually executed. */
    caps->stateValid |= KSWORD_ARK_SVM_VALID_CPUID1;
    /* Both XSAVE and OSXSAVE must be present before reading XCR0. */
    if ((caps->cpuid1Ecx & (3U << 26)) != (3U << 26)) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_XSAVE, STATUS_NOT_SUPPORTED); }
    /* Discover the save family before admitting XSS-managed user CET. */
    __cpuidex(r, 0xd, 1);
    /* Preserve the actual XSAVE instruction-family enumeration. */
    caps->xsaveFeatures = (ULONG)r[0];
    /* Raw feature zero is distinguishable from a skipped CPUID leaf. */
    caps->stateValid |= KSWORD_ARK_SVM_VALID_CPUID_D1;
    /* Read-only extended-state inspection never enables unsupported state. */
    __try {
        /* XGETBV is legal only after the verified OSXSAVE gate above. */
        caps->xcr0 = _xgetbv(0);
        /* Publish XCR0 independently from a possibly filtered XSS read. */
        caps->stateValid |= KSWORD_ARK_SVM_VALID_XCR0;
        /* XSS is not assumed to exist on processors without XSAVES. */
        if (caps->xsaveFeatures & 8U) {
            /* Retain the real supervisor-state mask even when a CR4 gate also fails. */
            caps->xss = __readmsr(0xda0U);
            /* An observed zero is now distinguishable from a skipped/failed read. */
            caps->stateValid |= KSWORD_ARK_SVM_VALID_XSS;
        }
        /* Query CET enumeration only when basic leaf seven exists. */
        __cpuid(r, 0);
        /* CPUs without CET retain zero state and never execute a CET MSR read. */
        if ((ULONG)r[0] >= 7U) {
            /* AMD CET_SS enumerates the architectural shadow-stack MSRs. */
            __cpuidex(r, 7, 0);
            /* Record support independently from the current CR4 enable bit. */
            caps->cetPresent = ((ULONG)r[2] >> 7) & 1U;
        }
        /* Even CR4.CET=0 must not hide nonzero supervisor controls. */
        if (caps->cetPresent) {
            /* Supervisor CET cannot run on the current private root stack. */
            caps->scet = __readmsr(KSW_SVM_MSR_S_CET);
            /* Retain the interrupt shadow-stack table for the initial VMCB. */
            caps->isst = __readmsr(KSW_SVM_MSR_ISST);
            /* Bounded self-tests must prove that both user CET MSRs survived the round trip. */
            caps->ucet = __readmsr(0x6a0U);
            /* PL3_SSP is live per-thread state, not a processor preparation constant. */
            caps->pl3Ssp = __readmsr(0x6a7U);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the exact exception instead of fabricating absent supervisor state. */
        caps->exception = GetExceptionCode();
        /* No virtualization ownership was acquired by these reads. */
        return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_XSTATE_READ, caps->exception);
    }
    /* LA57, PKS and user-interrupt state transfers remain unsupported. */
    if (caps->cr4 & KSW_SVM_UNSUPPORTED_CR4) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_CR4, STATUS_NOT_SUPPORTED); }
    /* Only CET_U has a supported supervisor XSTATE save/restore contract. */
    if (caps->xss & ~KSW_SVM_XSS_CET_U) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_XSS, STATUS_NOT_SUPPORTED); }
    /* Never admit supervisor CET or a missing XSAVES path merely by clearing a gate. */
    if (!kswSvmUserCetValid(caps->cr4, caps->xcr0, caps->xss, caps->xsaveFeatures, caps->cetPresent, caps->scet)) {
        /* Keep this distinguishable from unrelated CR4 and XSS refusals. */
        return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_CET_STATE, STATUS_NOT_SUPPORTED);
    }
    /* Validate the advertised compacted supervisor component before executing XSAVES. */
    if (caps->xss) {
        /* D.1 enumerates XSS bits in EDX:ECX. */
        __cpuidex(r, 0xd, 1);
        /* This implementation requires exactly the architecturally defined CET_U component. */
        if (!((ULONG)r[2] & (1U << 11))) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_CET_STATE, STATUS_NOT_SUPPORTED); }
        /* Component eleven contains two eight-byte MSRs and is supervisor-managed. */
        __cpuidex(r, 0xd, 11);
        /* Reject inconsistent outer-VMM enumeration before allocating or entering. */
        if ((ULONG)r[0] != 16U || !((ULONG)r[2] & 1U)) { return kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_CET_STATE, STATUS_NOT_SUPPORTED); }
    }
    /* Capability success does not itself prove that VMRUN works. */
    return kswNptAddressMask(caps->physicalBits) ? STATUS_SUCCESS : kswSvmReject(caps, KSWORD_ARK_SVM_REJECT_PHYSICAL_WIDTH, STATUS_NOT_SUPPORTED);
}

/* Publish hardware evidence separately from runtime implementation state. */
NTSTATUS kswordSvmProbe(KswHvmRuntime* runtime)
{
    /* Probe the current processor; prepare repeats on every target processor. */
    KswSvmCaps caps;
    /* Preserve precise failure while still publishing capability evidence. */
    NTSTATUS status = kswordSvmProbeCpu(&caps);
    /* Preserve each independent source and validity flag for pre-prepare diagnosis. */
    runtime->svmCapabilities.maxLeaf = caps.maxLeaf; runtime->svmCapabilities.features = caps.features;
    /* CPUID enumeration is separate from privileged MSR validity. */
    runtime->svmCapabilities.asidCount = caps.asidCount; runtime->svmCapabilities.physicalBits = caps.physicalBits;
    /* A failed MSR read must remain distinguishable from a returned zero. */
    runtime->svmCapabilities.msrValidMask = caps.valid; runtime->svmCapabilities.exceptionStatus = (ULONG)caps.exception;
    /* Preserve raw ownership and PAT observations without interpreting invalid fields. */
    runtime->svmCapabilities.vmCr = caps.vmCr; runtime->svmCapabilities.efer = caps.efer;
    /* Preserve the remaining independently sampled registers. */
    runtime->svmCapabilities.hsave = caps.hsave; runtime->svmCapabilities.pat = caps.pat;
    /* Admission failure must identify the precise check, not only STATUS_NOT_SUPPORTED. */
    runtime->svmCapabilities.rejectReason = caps.rejectReason; runtime->svmCapabilities.stateValidMask = caps.stateValid;
    /* Record both CPUID leaves used to decide which state reads were legal. */
    runtime->svmCapabilities.cpuid1Ecx = caps.cpuid1Ecx; runtime->svmCapabilities.xsaveFeatures = caps.xsaveFeatures;
    /* Preserve raw extended-state evidence even when preparation is refused. */
    runtime->svmCapabilities.cr4 = caps.cr4; runtime->svmCapabilities.xcr0 = caps.xcr0; runtime->svmCapabilities.xss = caps.xss;
    /* Select SVM independently from generic x64 compiler architecture. */
    runtime->backendId = KSWORD_ARK_HVM_BACKEND_SVM;
    /* Mark the CPU vendor without claiming implementation readiness. */
    runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_AMD;
    /* Publish enumerated instruction and paging capabilities. */
    if (caps.svm) { runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_SVM; }
    /* NPT is not EPT. */
    if (caps.features & 1U) { runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_NPT; }
    /* Record optional next-RIP capability. */
    if (caps.features & 8U) { runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_NRIP; }
    /* Record optional invalidation optimization capability. */
    if (caps.features & 64U) { runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID; }
    /* Record optional decode assists without relying on them. */
    if (caps.features & 128U) { runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS; }
    /* Only a valid VM_CR read can establish firmware-disabled status. */
    if ((caps.valid & 1U) && (caps.vmCr & 0x10ULL)) { runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED; }
    /* Distinguish a usable backend from a missing firmware capability. */
    runtime->queryStatus = NT_SUCCESS(status) ? KSWORD_ARK_HVM_QUERY_STATUS_OK : KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
    /* Refine the firmware diagnosis only when directly observed. */
    if (caps.vmCr & 0x10ULL) { runtime->queryStatus = KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED; }
    /* Retain precise ownership/filtering failures. */
    runtime->lastStatus = status;
    /* Return capability readiness only. */
    return status;
}

/* Reject every optional Intel feature before allocating AMD resources. */
NTSTATUS kswordSvmValidateFlags(KswHvmRuntime* runtime, ULONG flags)
{
    /* Only baseline lifecycle flags have AMD implementations. */
    const ULONG kAllowed = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED | KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
        KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED | KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE;
    /* Unknown/Intel-specific features must not silently degrade to baseline. */
    if (flags & ~kAllowed) { return STATUS_NOT_SUPPORTED; }
    /* Running under a VMM requires opt-in and a specifically supported outer host. */
    if (runtime->featureFlags & KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) {
        /* Do not spoof CPUID or accept an unknown host to make entry pass. */
        if (!(flags & KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) ||
            RtlCompareMemory(runtime->hypervisorVendor, "VMwareVMware", 12) != 12) { return STATUS_NOT_SUPPORTED; }
    }
    /* All required SVM state is validated separately. */
    return STATUS_SUCCESS;
}

/* Allocate a zeroed hardware buffer under the guest physical-address ceiling. */
static PVOID kswSvmAllocateHardware(SIZE_T bytes, ULONG bits)
{
    /* NPT width is checked before this helper is reached. */
    PHYSICAL_ADDRESS highest;
    /* Capture the owned allocation. */
    PVOID result;
    /* Avoid allocating an unrepresentable hardware operand. */
    highest.QuadPart = (LONGLONG)((1ULL << bits) - 1);
    /* VMCB, HSAVE and permission maps require physical contiguity. */
    result = MmAllocateContiguousMemory(bytes, highest);
    /* Reserved fields begin as architectural zero. */
    if (result != NULL) { RtlZeroMemory(result, bytes); }
    /* Caller records the returned pointer immediately. */
    return result;
}

/* All resources are retained if any CPU could still use them. */
VOID kswordSvmRelease(KswHvmRuntime* runtime)
{
    /* A failed prepare may own only a prefix of this allocation set. */
    KswSvmState* state = runtime->backendContext;
    /* Reverse-order release does not dereference a missing state. */
    ULONG index;
    /* Never free even apparently inactive per-CPU pages before a complete stop. */
    if (state == NULL || runtime->residentProcessorCount != 0) { return; }
    /* Check individual owners as well as the summary count. */
    for (index = 0; state->cpus != NULL && index < state->count; ++index) {
        /* A stale summary cannot authorize freeing an active CPU's stack. */
        if (state->cpus[index].active || (state->cpus[index].nested && state->cpus[index].nested->runningL2)) { return; }
    }
    /* Release per-CPU allocations in exact reverse ownership order. */
    for (index = state->count; state->cpus != NULL && index != 0;) {
        /* Select the next owned context. */
        KswSvmCpu* cpu = &state->cpus[--index];
        /* Nested operands/cache pages share the same all-native release boundary. */
        kswordSvmNestedRelease(cpu);
        /* NX XSTATE and host-stack allocations use the same pool tag. */
        if (cpu->xstateAllocation) { ExFreePoolWithTag(cpu->xstateAllocation, 'cSvK'); }
        /* The host stack remains alive until native return acknowledgement. */
        if (cpu->stack) { ExFreePoolWithTag(cpu->stack, 'cSvK'); }
        /* Permission maps and hardware pages are physically contiguous. */
        if (cpu->iopm) { MmFreeContiguousMemory(cpu->iopm); }
        /* Release the MSR bitmap after all exits stopped. */
        if (cpu->msrpm) { MmFreeContiguousMemory(cpu->msrpm); }
        /* Release hardware's opaque host-save area. */
        if (cpu->hsave) { MmFreeContiguousMemory(cpu->hsave); }
        /* Release our explicit host state image. */
        if (cpu->host) { MmFreeContiguousMemory(cpu->host); }
        /* Release the guest control/save image last. */
        if (cpu->guest) { MmFreeContiguousMemory(cpu->guest); }
        /* Remove the runtime's dangling private-context link. */
        runtime->processors[index].backendContext = NULL;
    }
    /* Shared NPT is freed only after all per-CPU owners are gone. */
    kswordNptRelease(&state->npt);
    /* Free the context array when prepare reached its allocation. */
    if (state->cpus) { ExFreePoolWithTag(state->cpus, 'cSvK'); }
    /* Drop runtime state and public preparation evidence together. */
    ExFreePoolWithTag(state, 'sSvK');
    /* Prevent reuse of the released lifetime. */
    runtime->backendContext = NULL;
    /* Clear every stale processor row and count. */
    RtlZeroMemory(runtime->processors, sizeof(runtime->processors));
    /* No prepared CPU survives teardown. */
    runtime->processorCount = runtime->preparedProcessorCount = runtime->selfTestPassedProcessorCount = 0;
    /* NPT never sets an EPT-ready bit. */
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_RESOURCES_READY | KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED);
}

/* Allocate and validate each processor before any CPU executes VMRUN. */
NTSTATUS kswordSvmPrepare(KswHvmRuntime* runtime, ULONG flags)
{
    /* Keep precise failure for the command response. */
    NTSTATUS status = kswordSvmValidateFlags(runtime, flags);
    /* Snapshot all processor groups, never just group zero. */
    ULONG count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    /* Loop index is a Windows global processor index, not APIC ID. */
    ULONG index;
    /* The prepare allocation is owned by Runtime immediately. */
    KswSvmState* state;
    /* Reject unsupported options before changing ownership. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Repeated preparation must not replace a live or partially owned context. */
    if (runtime->backendContext) { return STATUS_ALREADY_REGISTERED; }
    /* Enforce protocol capacity without silently dropping processors. */
    if (count == 0 || count > KSWORD_ARK_HVM_MAX_PROCESSORS) { return STATUS_NOT_SUPPORTED; }
    /* Allocate runtime state from nonpaged NX pool. */
    state = kswordArkAllocateNonPagedPool(sizeof(*state), 'sSvK');
    /* Allocation failure leaves all public readiness clear. */
    if (state == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* initialize every ownership pointer before publishing the context. */
    RtlZeroMemory(state, sizeof(*state));
    /* Publish cleanup ownership, not readiness. */
    runtime->backendContext = state;
    /* Freeze the target count for subsequent allocations. */
    state->count = count;
    /* Bind capability/allocation evidence to the current power epoch. */
    state->preparedPowerGeneration = runtime->powerTransitionGeneration;
    /* Allocate all contexts before pinning individual processors. */
    state->cpus = kswordArkAllocateNonPagedPool(sizeof(KswSvmCpu) * count, 'cSvK');
    /* Release the owned state if the array allocation fails. */
    if (state->cpus == NULL) { kswordSvmRelease(runtime); return STATUS_INSUFFICIENT_RESOURCES; }
    /* Every individual pointer must start null for partial cleanup. */
    RtlZeroMemory(state->cpus, sizeof(KswSvmCpu) * count);
    /* Record target size before preparing rows. */
    runtime->processorCount = count;
    /* Validate capabilities on every actual target processor. */
    for (index = 0; index < count; ++index) {
        /* Private context associated with this Windows processor identity. */
        KswSvmCpu* cpu = &state->cpus[index];
        /* Group-aware target and saved calling affinity. */
        PROCESSOR_NUMBER number;
        /* Group affinity is restored on every path after binding. */
        GROUP_AFFINITY affinity = {0}, previous;
        /* Enumerated XSAVE capacity. */
        int r[4];
        /* Resolve the frozen global index to its actual group and number. */
        status = KeGetProcessorNumberFromIndex(index, &number);
        /* Topology failures cannot be ignored. */
        if (!NT_SUCCESS(status)) { break; }
        /* Set a single-bit mask within the target group. */
        affinity.Group = number.Group; affinity.Mask = (KAFFINITY)1 << number.Number;
        /* Bind only while reading CPU-specific evidence. */
        KeSetSystemGroupAffinityThread(&affinity, &previous);
        /* Require valid SVM ownership evidence on this CPU. */
        status = kswordSvmProbeCpu(&cpu->caps);
        /* Record the currently enabled user XSTATE mask and storage requirement. */
        if (NT_SUCCESS(status)) {
            /* XSS selects a compacted XSAVES area; standard XSAVE cannot save CET_U. */
            cpu->xstateCompacted = cpu->caps.xss != 0;
            /* D.1 EBX includes current XCR0 and XSS; D.0 EBX is standard user state. */
            __cpuidex(r, 0xd, (int)cpu->xstateCompacted); cpu->xstateBytes = (ULONG)r[1];
            /* Save exactly the enabled components using the matching instruction family. */
            cpu->xstateMask = cpu->caps.xcr0 | cpu->caps.xss;
            /* Assembly must never touch CET MSRs on the old non-CET VMware baseline. */
            cpu->cetPresent = cpu->caps.cetPresent;
        }
        /* Never leave the control thread pinned after probing. */
        KeRevertToUserGroupAffinityThread(&previous);
        /* Refuse failed evidence before allocating processor-owned pages. */
        if (!NT_SUCCESS(status)) { break; }
        /* Cross-CPU paging/cache contracts must match exactly. */
        if (index && (cpu->caps.physicalBits != state->cpus[0].caps.physicalBits ||
            cpu->caps.page1Gb != state->cpus[0].caps.page1Gb || cpu->caps.pat != state->cpus[0].caps.pat)) {
            /* Preserve a heterogeneous-machine refusal rather than guessing. */
            status = STATUS_NOT_SUPPORTED; break;
        }
        /* Bound the saved state size before allocation arithmetic. */
        if (cpu->xstateBytes < 576 || cpu->xstateBytes > 65536) { status = STATUS_NOT_SUPPORTED; break; }
        /* Associate common and private state without reusing VMX fields. */
        cpu->runtime = runtime; cpu->resource = &runtime->processors[index];
        /* Retain the System CR3 captured by the common prepare path. */
        cpu->hostCr3 = runtime->hostCr3;
        /* Preserve processor identity in the common row. */
        cpu->resource->row.processorGroup = number.Group; cpu->resource->row.processorNumber = number.Number;
        /* Select the correct protocol decoder. */
        cpu->resource->row.backend = KSWORD_ARK_HVM_BACKEND_SVM;
        /* No VMX instruction result exists on this backend. */
        cpu->resource->row.vmxInstructionResult = 0xffU;
        /* Publish ownership for diagnosis and teardown. */
        cpu->resource->backendContext = cpu;
        /* Allocate all hardware operands before publishing readiness. */
        cpu->guest = kswSvmAllocateHardware(4096, cpu->caps.physicalBits);
        /* Host VMLOAD/VMSAVE image is not the opaque HSAVE page. */
        cpu->host = kswSvmAllocateHardware(4096, cpu->caps.physicalBits);
        /* Hardware-owned host save page. */
        cpu->hsave = kswSvmAllocateHardware(4096, cpu->caps.physicalBits);
        /* Two-page MSR bitmap. */
        cpu->msrpm = kswSvmAllocateHardware(8192, cpu->caps.physicalBits);
        /* Three-page I/O bitmap, even though baseline I/O interception is off. */
        cpu->iopm = kswSvmAllocateHardware(12288, cpu->caps.physicalBits);
        /* Stack and XSAVE storage are NX and need not be physically contiguous. */
        cpu->stack = kswordArkAllocateNonPagedPool(KSW_SVM_STACK_BYTES, 'cSvK');
        /* Include slack for 64-byte alignment. */
        cpu->xstateAllocation = kswordArkAllocateNonPagedPool(cpu->xstateBytes + 63, 'cSvK');
        /* A partial per-CPU allocation set is not ready. */
        if (!cpu->guest || !cpu->host || !cpu->hsave || !cpu->msrpm || !cpu->iopm || !cpu->stack || !cpu->xstateAllocation) {
            /* Release all allocations through the shared ledger below. */
            status = STATUS_INSUFFICIENT_RESOURCES; break;
        }
        /* Clear XSAVE's reserved header bytes before its first use. */
        RtlZeroMemory(cpu->xstateAllocation, cpu->xstateBytes + 63);
        /* XSAVE/XRSTOR require 64-byte alignment. */
        cpu->xstate = (PVOID)(((ULONG_PTR)cpu->xstateAllocation + 63) & ~(ULONG_PTR)63);
        /* Keep the Windows x64 shadow space and the context anchor within the stack. */
        cpu->stackTop = ((ULONGLONG)(ULONG_PTR)cpu->stack + KSW_SVM_STACK_BYTES - 64) & ~15ULL;
        /* Cache hardware addresses outside VMEXIT. */
        cpu->guestPa = (ULONGLONG)MmGetPhysicalAddress(cpu->guest).QuadPart;
        /* Explicit host VMLOAD image. */
        cpu->hostPa = (ULONGLONG)MmGetPhysicalAddress(cpu->host).QuadPart;
        /* Record prepared state only after all allocations succeeded. */
        cpu->stage = KSWORD_ARK_HVM_STAGE_PREPARED;
        /* Publish generic resource evidence, never VMXON success. */
        cpu->resource->row.stateFlags = KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY;
        /* Count only complete per-CPU resource sets. */
        runtime->preparedProcessorCount++;
        /* Exercise reverse cleanup after a complete owned CPU allocation set. */
        if (kswordSvmFault(1, index)) { status = STATUS_CANCELLED; break; }
    }
    /* NPT uses the common cache/address-width contract established above. */
    if (NT_SUCCESS(status)) { status = kswordNptBuild(&state->npt, &state->cpus[0].caps); }
    /* Probe resources are opt-in and never allocated by ordinary prepare. */
    if (NT_SUCCESS(status) && (flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE)) {
        /* Prepare every CPU before publishing any enhanced self-test readiness. */
        for (index = 0; index < count; ++index) {
            /* No mapping/stack allocation occurs in the later VMEXIT path. */
            status = kswordSvmNestedPrepare(&state->cpus[index], index);
            /* The common reverse ledger unwinds the full partially allocated set. */
            if (!NT_SUCCESS(status)) { break; }
        }
    }
    /* No preparation evidence may span a sleep/resume or topology change. */
    if (NT_SUCCESS(status) && (runtime->powerTransitionPending || runtime->powerTransitionGeneration != state->preparedPowerGeneration ||
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) != count)) { status = STATUS_POWER_STATE_INVALID; }
    /* Nothing may remain marked ready after partial prepare. */
    if (!NT_SUCCESS(status)) { kswordSvmRelease(runtime); return status; }
    /* Publish resources only; actual SVM execution is a separate self-test. */
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_RESOURCES_READY);
    /* No CPU has yet entered SVM. */
    return STATUS_SUCCESS;
}

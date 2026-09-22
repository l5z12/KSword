/*++

Module Name:

    hvm_runtime.c

Abstract:

    Owns the VT-x capability snapshot, per-processor VMX regions, serialized
    lifecycle control, VMXON/VMXOFF validation, and an explicitly confirmed
    one-shot VMCALL guest.  EPT hierarchy construction is implemented by the
    dedicated builder module.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_internal.h"
#include "hvm_backend.h"
#include "hvm_metrics.h"
#include "hvm_nested_ept.h"
// kswordArkAllocateNonPagedPool: L1 bitmap copies do not enter hardware; a standard pool suffices.
#include "../../platform/pool_compat.h"

/* Tag the per-processor copy of L1's MSR bitmap. */
#define KSW_HVM_L2_BITMAP_POOL_TAG 'BvHK'
#include "hvm_cr_policy.h"
#include "hvm_ept_view.h"
#include "hvm_inject.h"
#include "hvm_process.h"
#include "hvm_ept_domain.h"
#include "hvm_ept_switch.h"
#include "hvm_guest.h"
#include "hvm_memory.h"
#include "hvm_phys_window.h"
#include "hvm_msr_policy.h"
#include "hvm_ept.h"
#include "hvm_event.h"
#include "hvm_evmcs.h"
#include "hvm_mtrr.h"
#include "hvm_nested.h"
#include "hvm_resident.h"

#if defined(_M_AMD64)
#include <intrin.h>

NTKERNELAPI VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE routine,
    _In_opt_ PVOID context
    );

/*
 * Declared the same way hvm_memory.c declares them: attaching is the only way
 * to read a process's page-directory base without hardcoding an EPROCESS
 * offset that Windows never promised to keep.
 */
NTKERNELAPI VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

NTKERNELAPI LOGICAL
KeSignalCallDpcSynchronize(
    _Inout_ PVOID systemArgument2
    );

NTKERNELAPI VOID
KeSignalCallDpcDone(
    _In_ PVOID systemArgument1
    );

#define KSW_HVM_IA32_VMX_PINBASED_CTLS 0x481UL
#define KSW_HVM_IA32_VMX_EXIT_CTLS 0x483UL
#define KSW_HVM_IA32_VMX_ENTRY_CTLS 0x484UL
#define KSW_HVM_IA32_VMX_MISC 0x485UL
#define KSW_HVM_IA32_VMX_TRUE_PINBASED_CTLS 0x48DUL
#define KSW_HVM_IA32_VMX_TRUE_EXIT_CTLS 0x48FUL
#define KSW_HVM_IA32_VMX_TRUE_ENTRY_CTLS 0x490UL
#define KSW_HVM_IA32_VMX_PROCBASED_CTLS3 0x492UL
#define KSW_HVM_IA32_VMX_EXIT_CTLS2 0x493UL
#define KSW_HVM_VMX_ACTIVATE_TERTIARY (1ULL << 17)
#define KSW_HVM_VMX_ACTIVATE_SECONDARY (1ULL << 31)
#define KSW_HVM_VMX_EXIT_ACTIVATE_SECONDARY (1ULL << 31)
#define KSW_HVM_VMX_ENABLE_EPT (1ULL << 1)
#define KSW_HVM_VMX_ENABLE_VPID (1ULL << 5)

/* These slots only store raw capability facts that must be consistent across logical processors by architecture. */
typedef enum KswHvmCapabilitySlot
{
    kKswordHvmCapFeatureControl = 0,
    kKswordHvmCapVmxBasic,
    kKswordHvmCapCr0Fixed0,
    kKswordHvmCapCr0Fixed1,
    kKswordHvmCapCr4Fixed0,
    kKswordHvmCapCr4Fixed1,
    kKswordHvmCapPrimaryControls,
    kKswordHvmCapTruePrimaryControls,
    kKswordHvmCapSecondaryControls,
    kKswordHvmCapTertiaryControls,
    kKswordHvmCapExitControls,
    kKswordHvmCapTrueExitControls,
    kKswordHvmCapSecondaryExitControls,
    kKswordHvmCapEntryControls,
    kKswordHvmCapTrueEntryControls,
    kKswordHvmCapPinControls,
    kKswordHvmCapTruePinControls,
    kKswordHvmCapVmxMisc,
    kKswordHvmCapEptVpid,
    kKswordHvmCapCpuidMaxBasic,
    kKswordHvmCapCpuid7Subleaf0Ebx,
    kKswordHvmCapCpuid7Subleaf0EcxEdx,
    kKswordHvmCapCpuid7Subleaf1EaxEdx,
    kKswordHvmCapCpuidDSubleaf1EaxEcx,
    kKswordHvmCapCpuidMaxExtended,
    kKswordHvmCapCpuidExtended1Edx,
    kKswordHvmCapCpuidExtended8Eax,
    kKswordHvmCapCpuid7MaxSubleaf,
    kKswordHvmCapCount
} KswHvmCapabilitySlot;

typedef struct KswHvmCapabilityVerifyContext
{
    ULONGLONG reference[kKswordHvmCapCount];
    volatile LONG sampleCount;
    volatile LONG failureCount;
    volatile LONG mismatchCount;
    volatile LONG firstMismatchProcessor;
    volatile LONG firstMismatchSlot;
} KswHvmCapabilityVerifyContext;
#endif

#define KSW_HVM_LIFECYCLE_BUGCHECK_CODE 0x00020001UL
#define KSW_HVM_POWER_FAILURE_SIGNATURE 0x48564D50UL
#define KSW_HVM_UNLOAD_FAILURE_SIGNATURE 0x48564D55UL

static KswHvmRuntime gKswordHvm;

KswHvmRuntime*
kswordArkHvmGetRuntime(
    VOID
    )
{
    /* Return the process-wide nonpaged runtime for VM-exit telemetry. */
    return &gKswordHvm;
}

static VOID
kswordArkHvmCopyAscii(
    _Out_writes_(destinationChars) CHAR* destination,
    _In_ ULONG destinationChars,
    _In_reads_bytes_(sourceBytes) const CHAR* source,
    _In_ ULONG sourceBytes
    )
{
    ULONG copyBytes = 0UL;

    /* Keep every protocol string bounded and NUL terminated. */
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    RtlZeroMemory(destination, destinationChars);
    if (source == NULL || sourceBytes == 0UL) {
        return;
    }
    copyBytes = sourceBytes < (destinationChars - 1UL)
        ? sourceBytes
        : (destinationChars - 1UL);
    RtlCopyMemory(destination, source, copyBytes);
}

#if defined(_M_AMD64)
static NTSTATUS
kswordArkHvmSampleCapabilityFacts(
    _Out_writes_(KswordHvmCapCount) ULONGLONG* sample
    )
{
    int registers[4] = { 0 };
    ULONGLONG vmxBasic = 0ULL;
    ULONGLONG primaryControls = 0ULL;
    ULONGLONG secondaryControls = 0ULL;
    ULONGLONG exitControls = 0ULL;
    ULONG maxBasicLeaf = 0UL;
    ULONG maxStructuredSubleaf = 0UL;
    ULONG maxExtendedLeaf = 0UL;

    if (sample == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(
        sample,
        sizeof(ULONGLONG) * kKswordHvmCapCount);

    /* Each gated MSR uses the gating bit on the same logical processor for judgment. */
    __try {
        sample[kKswordHvmCapFeatureControl] =
            __readmsr(KSW_IA32_FEATURE_CONTROL);
        vmxBasic = __readmsr(KSW_IA32_VMX_BASIC);
        sample[kKswordHvmCapVmxBasic] = vmxBasic;
        sample[kKswordHvmCapCr0Fixed0] =
            __readmsr(KSW_IA32_VMX_CR0_FIXED0);
        sample[kKswordHvmCapCr0Fixed1] =
            __readmsr(KSW_IA32_VMX_CR0_FIXED1);
        sample[kKswordHvmCapCr4Fixed0] =
            __readmsr(KSW_IA32_VMX_CR4_FIXED0);
        sample[kKswordHvmCapCr4Fixed1] =
            __readmsr(KSW_IA32_VMX_CR4_FIXED1);

        primaryControls = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS);
        exitControls = __readmsr(KSW_HVM_IA32_VMX_EXIT_CTLS);
        sample[kKswordHvmCapPrimaryControls] = primaryControls;
        sample[kKswordHvmCapExitControls] = exitControls;
        sample[kKswordHvmCapEntryControls] =
            __readmsr(KSW_HVM_IA32_VMX_ENTRY_CTLS);
        sample[kKswordHvmCapPinControls] =
            __readmsr(KSW_HVM_IA32_VMX_PINBASED_CTLS);
        sample[kKswordHvmCapVmxMisc] =
            __readmsr(KSW_HVM_IA32_VMX_MISC);

        if ((vmxBasic & (1ULL << 55)) != 0ULL) {
            sample[kKswordHvmCapTruePrimaryControls] =
                __readmsr(KSW_IA32_VMX_TRUE_PROCBASED_CTLS);
            sample[kKswordHvmCapTrueExitControls] =
                __readmsr(KSW_HVM_IA32_VMX_TRUE_EXIT_CTLS);
            sample[kKswordHvmCapTrueEntryControls] =
                __readmsr(KSW_HVM_IA32_VMX_TRUE_ENTRY_CTLS);
            sample[kKswordHvmCapTruePinControls] =
                __readmsr(KSW_HVM_IA32_VMX_TRUE_PINBASED_CTLS);
        }

        if (((primaryControls >> 32) &
                KSW_HVM_VMX_ACTIVATE_SECONDARY) != 0ULL) {
            secondaryControls =
                __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
            sample[kKswordHvmCapSecondaryControls] =
                secondaryControls;
            if (((secondaryControls >> 32) &
                    (KSW_HVM_VMX_ENABLE_EPT |
                     KSW_HVM_VMX_ENABLE_VPID)) != 0ULL) {
                sample[kKswordHvmCapEptVpid] =
                    __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
            }
        }
        if (((primaryControls >> 32) &
                KSW_HVM_VMX_ACTIVATE_TERTIARY) != 0ULL) {
            sample[kKswordHvmCapTertiaryControls] =
                __readmsr(KSW_HVM_IA32_VMX_PROCBASED_CTLS3);
        }
        if (((exitControls >> 32) &
                KSW_HVM_VMX_EXIT_ACTIVATE_SECONDARY) != 0ULL) {
            sample[kKswordHvmCapSecondaryExitControls] =
                __readmsr(KSW_HVM_IA32_VMX_EXIT_CTLS2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    /* CPUID samples only capability leaves, excluding leaves that vary by processor such as cache and core type. */
    __cpuid(registers, 0);
    maxBasicLeaf = (ULONG)registers[0];
    sample[kKswordHvmCapCpuidMaxBasic] = maxBasicLeaf;
    if (maxBasicLeaf >= 7UL) {
        __cpuidex(registers, 7, 0);
        maxStructuredSubleaf = (ULONG)registers[0];
        sample[kKswordHvmCapCpuid7MaxSubleaf] =
            maxStructuredSubleaf;
        sample[kKswordHvmCapCpuid7Subleaf0Ebx] =
            (ULONG)registers[1];
        sample[kKswordHvmCapCpuid7Subleaf0EcxEdx] =
            ((ULONGLONG)(ULONG)registers[2] << 32) |
            (ULONG)registers[3];
        if (maxStructuredSubleaf >= 1UL) {
            __cpuidex(registers, 7, 1);
            sample[kKswordHvmCapCpuid7Subleaf1EaxEdx] =
                ((ULONGLONG)(ULONG)registers[0] << 32) |
                (ULONG)registers[3];
        }
    }
    if (maxBasicLeaf >= 0xDUL) {
        __cpuidex(registers, 0xD, 1);
        sample[kKswordHvmCapCpuidDSubleaf1EaxEcx] =
            ((ULONGLONG)(ULONG)registers[0] << 32) |
            (ULONG)registers[2];
    }

    __cpuid(registers, (int)0x80000000UL);
    maxExtendedLeaf = (ULONG)registers[0];
    sample[kKswordHvmCapCpuidMaxExtended] = maxExtendedLeaf;
    if (maxExtendedLeaf >= 0x80000001UL) {
        __cpuid(registers, (int)0x80000001UL);
        sample[kKswordHvmCapCpuidExtended1Edx] =
            (ULONG)registers[3];
    }
    if (maxExtendedLeaf >= 0x80000008UL) {
        __cpuid(registers, (int)0x80000008UL);
        sample[kKswordHvmCapCpuidExtended8Eax] =
            (ULONG)registers[0];
    }
    return STATUS_SUCCESS;
}

static VOID
kswordArkHvmVerifyCapabilitiesDpc(
    _In_ struct _KDPC* dpc,
    _In_opt_ PVOID deferredContext,
    _In_opt_ PVOID systemArgument1,
    _In_opt_ PVOID systemArgument2
    )
{
    KswHvmCapabilityVerifyContext* context =
        (KswHvmCapabilityVerifyContext*)deferredContext;
    ULONGLONG sample[kKswordHvmCapCount] = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG slot = 0UL;
    ULONG processor = KeGetCurrentProcessorNumberEx(NULL);

    UNREFERENCED_PARAMETER(dpc);
    status = kswordArkHvmSampleCapabilityFacts(sample);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&context->failureCount);
    } else {
        for (slot = 0UL; slot < kKswordHvmCapCount; ++slot) {
            if (sample[slot] == context->reference[slot]) {
                continue;
            }
            if (InterlockedIncrement(&context->mismatchCount) == 1L) {
                context->firstMismatchProcessor = (LONG)processor;
                context->firstMismatchSlot = (LONG)slot;
            }
            break;
        }
    }
    InterlockedIncrement(&context->sampleCount);
    KeSignalCallDpcSynchronize(systemArgument2);
    KeSignalCallDpcDone(systemArgument1);
}

static NTSTATUS
kswordArkHvmVerifyUniformCapabilities(
    VOID
    )
{
    KswHvmCapabilityVerifyContext context = { 0 };
    ULONG processorCountBefore = 0UL;
    ULONG processorCountAfter = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    status = kswordArkHvmSampleCapabilityFacts(context.reference);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    context.firstMismatchProcessor = -1L;
    context.firstMismatchSlot = -1L;
    processorCountBefore =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (processorCountBefore == 0UL ||
        processorCountBefore > KSWORD_ARK_HVM_MAX_PROCESSORS) {
        return STATUS_NOT_SUPPORTED;
    }

    KeGenericCallDpc(kswordArkHvmVerifyCapabilitiesDpc, &context);
    processorCountAfter =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (processorCountAfter != processorCountBefore ||
        context.sampleCount != (LONG)processorCountBefore ||
        context.failureCount != 0L ||
        context.mismatchCount != 0L) {
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkHvmReadCapabilities(
    _Inout_ KswHvmRuntime* runtime
    )
{
    int registers[4] = { 0 };
    CHAR vendor[13] = { 0 };
    CHAR hypervisorVendor[13] = { 0 };
    ULONG leaf1Ecx = 0UL;
    ULONGLONG primaryControls = 0ULL;
    ULONGLONG secondaryControls = 0ULL;

    /* CPUID leaf zero provides an exact CPU vendor identity. */
    __cpuid(registers, 0);
    RtlCopyMemory(vendor + 0, &registers[1], sizeof(ULONG));
    RtlCopyMemory(vendor + 4, &registers[3], sizeof(ULONG));
    RtlCopyMemory(vendor + 8, &registers[2], sizeof(ULONG));
    kswordArkHvmCopyAscii(
        runtime->cpuVendor,
        RTL_NUMBER_OF(runtime->cpuVendor),
        vendor,
        12UL);
    /* Sample outer identity before vendor dispatch, including AMD. */
    __cpuid(registers, 1);
    if (((ULONG)registers[2] & (1UL << 31)) != 0UL) {
        /* Preserve actual outer VMM evidence instead of hiding it. */
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT;
        /* Hypervisor vendor order is EBX, ECX, EDX. */
        __cpuid(registers, (int)0x40000000UL);
        RtlCopyMemory(runtime->hypervisorVendor, &registers[1], 4);
        RtlCopyMemory(runtime->hypervisorVendor + 4, &registers[2], 4);
        RtlCopyMemory(runtime->hypervisorVendor + 8, &registers[3], 4);
    }
    /* AMD has an independent SVM/NPT implementation and capability gate. */
    if (RtlCompareMemory(vendor, "AuthenticAMD", 12UL) == 12UL) {
        /* Hardware probe does not publish Active or self-test evidence. */
        return NT_SUCCESS(kswordHvmBackend(KSWORD_ARK_HVM_BACKEND_SVM)->probeCapabilities(runtime));
    }
    if (RtlCompareMemory(vendor, "GenuineIntel", 12UL) != 12UL) {
        runtime->queryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        runtime->lastStatus = STATUS_NOT_SUPPORTED;
        return FALSE;
    }
    /* Select the existing VMX implementation explicitly. */
    runtime->backendId = KSWORD_ARK_HVM_BACKEND_VMX;
    runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_INTEL;

    /* Leaf one exposes both VMX and an already-active hypervisor. */
    __cpuid(registers, 1);
    leaf1Ecx = (ULONG)registers[2];
    if ((leaf1Ecx & (1UL << 5)) != 0UL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_VMX;
    }
    if ((leaf1Ecx & (1UL << 31)) != 0UL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT;
        __cpuid(registers, (int)0x40000000UL);
        RtlCopyMemory(hypervisorVendor + 0, &registers[1], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 4, &registers[2], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 8, &registers[3], sizeof(ULONG));
        kswordArkHvmCopyAscii(
            runtime->hypervisorVendor,
            RTL_NUMBER_OF(runtime->hypervisorVendor),
            hypervisorVendor,
            12UL);
        /*
         * Leaf 0x40000000 EAX reports the highest hypervisor leaf, so the
         * interface leaf is only meaningful when it is inside that range.
         * Sampling once here is deliberate: the exit path must not execute
         * CPUID, which would add an exit of its own in VMX root, and this
         * identity cannot change while the machine is running.
         */
        if ((ULONG)registers[0] >= 0x40000001UL) {
            __cpuid(registers, (int)0x40000001UL);
            /*
             * The same signature is spelled KSW_HV_INTERFACE_SIGNATURE in
             * hvm_evmcs.c.  Two spellings of one magic number can drift apart
             * silently, and this one now gates hypercall forwarding, whose
             * failure mode is the 0x1E bugcheck.  Change both or neither.
             */
            runtime->hypervisorInterfaceIsHv1 =
                ((ULONG)registers[0] == 0x31237648UL) ? TRUE : FALSE;
        }
    }

    /* Stop before VMX MSR access when CPUID does not advertise VMX. */
    if ((runtime->featureFlags & KSWORD_ARK_HVM_FEATURE_VMX) == 0ULL) {
        runtime->queryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        runtime->lastStatus = STATUS_NOT_SUPPORTED;
        return FALSE;
    }

    /* VMX-specific MSRs are read under SEH to fail closed on a virtual CPU. */
    __try {
        runtime->featureControl = __readmsr(KSW_IA32_FEATURE_CONTROL);
        runtime->vmxBasic = __readmsr(KSW_IA32_VMX_BASIC);
        runtime->vmxMisc = __readmsr(KSW_HVM_IA32_VMX_MISC);
        runtime->cr0Fixed0 = __readmsr(KSW_IA32_VMX_CR0_FIXED0);
        runtime->cr0Fixed1 = __readmsr(KSW_IA32_VMX_CR0_FIXED1);
        runtime->cr4Fixed0 = __readmsr(KSW_IA32_VMX_CR4_FIXED0);
        runtime->cr4Fixed1 = __readmsr(KSW_IA32_VMX_CR4_FIXED1);
        primaryControls =
            __readmsr(
                (runtime->vmxBasic & (1ULL << 55)) != 0ULL
                ? KSW_IA32_VMX_TRUE_PROCBASED_CTLS
                : KSW_IA32_VMX_PROCBASED_CTLS);
        secondaryControls =
            __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
        runtime->vmxEptVpidCapabilities =
            __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        runtime->queryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        runtime->lastStatus = GetExceptionCode();
        return FALSE;
    }

    /* Decode the firmware gate without changing IA32_FEATURE_CONTROL. */
    if ((runtime->featureControl & 0x1ULL) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED;
    }
    if ((runtime->featureControl & 0x4ULL) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX;
    }
    if ((runtime->vmxBasic & (1ULL << 55)) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS;
    }
    /*
     * Publish the MSR bitmap as a discovered capability rather than assuming
     * it.  Without this control every RDMSR and WRMSR exits unconditionally,
     * and no resident guest survives the resulting exit storm.
     */
    if (((primaryControls >> 32) & (1ULL << 28)) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_MSR_BITMAP;
    }
    /* This build completes every unconditional exit inside the dispatcher. */
    runtime->featureFlags |=
        KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION;

    /*
     * Report EPT-violation #VE as a discovered capability.  Discovery says
     * only that the processor can reflect EPT violations into the guest; it
     * says nothing about whether doing so is safe here, and the control stays
     * off unless a caller sets CONTROL_FLAG_ENABLE_VE.
     */
    if (((secondaryControls >> 32) & (1ULL << 18)) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_EPT_VIOLATION_VE;
    }
    /*
     * Every EPT leaf and every unused slot this build installs carries
     * suppress-#VE, so enabling the control above cannot reflect a violation
     * the driver did not deliberately opt a page into.  Callers use this bit
     * to tell a safe-by-construction EPT from one where enabling #VE would
     * hand the guest a fault it has no handler for.
     */
    runtime->featureFlags |=
        KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT;

    /*
     * VM functions.  Discovery is two-level: the secondary control has to be
     * allowed, and then IA32_VMX_VMFUNC says which functions exist.  Only
     * function 0 (EPTP switching) is of interest here.
     */
    if (((secondaryControls >> 32) & (1ULL << 13)) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_VM_FUNCTIONS;
        runtime->vmFunctionCapabilities =
            __readmsr(KSW_IA32_VMX_VMFUNC);
        if ((runtime->vmFunctionCapabilities & 0x1ULL) != 0ULL) {
            runtime->featureFlags |=
                KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING;
        }
    }

    /* The high dword of each control MSR is its allowed-one mask. */
    if ((((secondaryControls >> 32) & (1ULL << 1)) != 0ULL) &&
        ((runtime->vmxEptVpidCapabilities &
            KSW_EPT_CAP_PAGE_WALK_4) != 0ULL)) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_EPT;
    }
    if ((runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_WB) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_WB;
    }
    if ((runtime->vmxEptVpidCapabilities &
            KSW_EPT_CAP_PAGE_WALK_4) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL;
    }
    if ((runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_2MB) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_2MB;
    }
    if ((runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_AD) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_AD;
    }
    if ((runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_INVEPT) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_INVEPT;
    }
    if ((runtime->vmxEptVpidCapabilities &
            KSW_EPT_CAP_INVEPT_SINGLE) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE;
    }
    if ((runtime->vmxEptVpidCapabilities &
            KSW_EPT_CAP_INVEPT_ALL) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_INVEPT_ALL;
    }
    if ((runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_VPID) != 0ULL) {
        runtime->featureFlags |= KSWORD_ARK_HVM_FEATURE_VPID;
    }
    /* Publish monitor-trap support from the primary allowed-one mask. */
    if ((((primaryControls >> 32) &
            (1ULL << 27)) != 0ULL)) {
        /* Publish the protocol-visible monitor-trap feature. */
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG;
    }

    /*
     * A virtual CPU that exposes VMX while setting the hypervisor-present bit
     * is a nested-capable candidate.  The later self-test remains opt-in and
     * is the authoritative proof.
     */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (runtime->featureFlags & KSWORD_ARK_HVM_FEATURE_VMX) != 0ULL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED;
    }

    /* Firmware-disabled VMX is reported distinctly from unsupported silicon. */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX) == 0ULL) {
        runtime->queryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED;
        runtime->lastStatus = STATUS_HV_FEATURE_UNAVAILABLE;
        return FALSE;
    }

    /* Advertise the bounded guest only when its complete EPT baseline exists. */
    if ((runtime->featureFlags &
            (KSWORD_ARK_HVM_FEATURE_EPT |
             KSWORD_ARK_HVM_FEATURE_EPT_WB |
             KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
             KSWORD_ARK_HVM_FEATURE_EPT_2MB)) ==
        (KSWORD_ARK_HVM_FEATURE_EPT |
         KSWORD_ARK_HVM_FEATURE_EPT_WB |
         KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
         KSWORD_ARK_HVM_FEATURE_EPT_2MB)) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST |
            KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY |
            KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT |
            KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING |
            KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT;
    }

    /* A usable capability snapshot is now available. */
    runtime->queryStatus = KSWORD_ARK_HVM_QUERY_STATUS_OK;
    runtime->lastStatus = STATUS_SUCCESS;
    return TRUE;
}
#endif

NTSTATUS
kswordArkHvmArmUnloadGuard(
    _Inout_ KswHvmRuntime* runtime
    )
{
    PVOID previous = NULL;
    PDRIVER_UNLOAD captured = NULL;

    /*
     * The capture point must be the moment of **arming**, not a snapshot from DriverEntry.
     *
     * The reason is that DriverEntry cannot capture the final value: the image entry point for this driver is
     * not DriverEntry itself, but the KMDF stub statically linked via WDK's wdfdriverentry.lib. The stub calls
     * our DriverEntry first, and **only after it returns** does it replace DriverObject->DriverUnload with
     * FxStubDriverUnload from within the image. The disassembled sequence from the built KswordARK.sys is:
     *
     *   call  <DriverEntry in the INIT section>
     *   jns   <continue only on success>
     *   mov   rax,[rdi+68h]        ; read DriverObject->DriverUnload
     *   mov   [WdfDriverStubDisplacedDriverUnload],rax
     *   lea   rax,[FxStubDriverUnload]
     *   mov [rdi+68h],rax ; Overwrite
     *
     * Live testing shows driverUnload = image base + 0xB0360, which is exactly the target of that LEA instruction. Within the entire .text
     * section, the only RIP-relative LEAs pointing to this address are the installation point and the instruction itself; there are no
     * absolute pointers. Therefore, this instruction must be the sole loader. The writer is not in this repository, so no grep can find it.
     *
     * Consequence: EnableResidentLifecycle catches the framework unload installed by WdfDriverCreate (in
     * Wdf01000.sys), but by the time the slot is armed, it is already a stub within the image, causing the
     * CAS to inevitably mismatch. Thus, START_RESIDENT **always** returns LIFECYCLE_GUARD_FAILED. Moving
     * the catch point before or after DriverEntry is futile: all positions occur before the overwrite.
     *
     * After changing to deferred capture, one of the two safety invariants remains unchanged, while the second one was actually fixed:
     *   (1) Use CAS only to swap out "the exact value I just read," never blindly write; the
     *       mismatch check below is preserved verbatim. It now verifies whether a third party intervened
     *       between the read and the CAS, remaining a true race guard with the correct baseline.
     *   (2) When disarming, we restore the one we originally displaced. If the old code's CAS happened to
     *       succeed, Disarm would unload the Wdf01000.sys framework and reinstall it in the slot, bypassing
     *       the FxStubDriverUnload inside the image—a potential error far more severe than this failure.
     */
    if (runtime == NULL ||
        runtime->driverObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Treat the exact already-armed state as idempotent success. */
    if (InterlockedCompareExchange(
            &runtime->unloadGuardArmed,
            1L,
            1L) != 0L) {
        return runtime->driverObject->DriverUnload == NULL
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }
    /*
     * Read the entry currently hooked in the slot. If NULL, it means either
     * someone else has replaced it, or KMDF never installed an unload handler.
     * Both cases must fail-closed, as Disarm will have no recoverable value.
     */
    captured = runtime->driverObject->DriverUnload;
    if (captured == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Remove only the exact unload entry observed one instruction ago. */
    previous = InterlockedCompareExchangePointer(
        (PVOID volatile*)&runtime->driverObject->DriverUnload,
        NULL,
        (PVOID)captured);
    if (previous != (PVOID)captured) {
        /* Never overwrite a third-party or otherwise unexpected entry. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Publish the exact displaced entry so Disarm restores that same value. */
    runtime->originalDriverUnload = captured;
    InterlockedExchange(&runtime->unloadGuardArmed, 1L);
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmDisarmUnloadGuard(
    _Inout_ KswHvmRuntime* runtime
    )
{
    PVOID previous = NULL;

    /* Nothing was removed when the guard is already idle. */
    if (runtime == NULL ||
        InterlockedCompareExchange(
            &runtime->unloadGuardArmed,
            0L,
            0L) == 0L) {
        return STATUS_SUCCESS;
    }
    if (runtime->driverObject == NULL ||
        runtime->originalDriverUnload == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Restore the original entry only when the guarded slot is still NULL. */
    previous = InterlockedCompareExchangePointer(
        (PVOID volatile*)&runtime->driverObject->DriverUnload,
        (PVOID)runtime->originalDriverUnload,
        NULL);
    if (previous != NULL &&
        previous != (PVOID)runtime->originalDriverUnload) {
        /* Preserve the guard state instead of clobbering an unexpected owner. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    InterlockedExchange(&runtime->unloadGuardArmed, 0L);
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED);
    return STATUS_SUCCESS;
}

VOID
kswordArkHvmInvalidatePowerResumeEvidence(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;

    if (runtime == NULL) {
        return;
    }
    /* Require a fresh per-CPU VMXON/VMXOFF proof after every S0 transition. */
    runtime->selfTestPassedProcessorCount = 0UL;
    /*
     * The per-processor EPT latch is capability-derived evidence like the
     * self-test count, and a resume can land on a machine whose firmware or
     * outer hypervisor changed what it exposes.  Destroy it here or a stale
     * TRUE would let a post-resume start build hierarchies on capabilities
     * nobody re-proved.
     */
    runtime->localEptArmed = FALSE;
    runtime->featureFlags &= ~KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED;
    /* Same argument, same lifetime: execute-only is a capability too. */
    runtime->eptpSwitchArmed = FALSE;
    runtime->featureFlags &= ~KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED;
    /* The pool is derived from that capability and must not outlive it. */
    kswordArkHvmEptSwitchRelease(runtime);
    kswordArkHvmStateClear(
        runtime,
        KSWORD_ARK_HVM_STATE_SELF_TESTED |
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
            KSWORD_ARK_HVM_STATE_GUEST_READY |
            KSWORD_ARK_HVM_STATE_GUEST_RUNNING |
            KSWORD_ARK_HVM_STATE_GUEST_EXITED |
            KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
            KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
            KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
    runtime->residentImplementation =
        runtime->residentStartAllowed
            ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
            : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    for (index = 0UL; index < runtime->processorCount; ++index) {
        runtime->processors[index].row.stateFlags &=
            ~(KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
              KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED |
              KSWORD_ARK_HVM_CPU_STATE_EXCEPTION |
              KSWORD_ARK_HVM_CPU_STATE_CONFLICT |
              KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED |
              KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED |
              KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED |
              KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE |
              KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED |
              KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED);
        runtime->processors[index].row.vmxInstructionResult = 0UL;
        runtime->processors[index].row.lastStatus =
            STATUS_DEVICE_NOT_READY;
    }
}

NTSTATUS
kswordArkHvmAcquireResidentTransition(
    _Inout_ KswHvmRuntime* runtime
    )
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    if (runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    for (;;) {
        /* Claim only the phase bit while the ordinary spin lock is held. */
        KeAcquireSpinLock(
            &runtime->residentTransitionStateLock,
            &oldIrql);
        if (InterlockedCompareExchange(
                &runtime->residentTransitionActive,
                1L,
                0L) == 0L) {
            /* Reset the reusable notification event for this exact owner. */
            KeClearEvent(&runtime->residentTransitionIdleEvent);
            KeReleaseSpinLock(
                &runtime->residentTransitionStateLock,
                oldIrql);
            return STATUS_SUCCESS;
        }
        KeReleaseSpinLock(
            &runtime->residentTransitionStateLock,
            oldIrql);

        if (KeGetCurrentIrql() > APC_LEVEL) {
            /* Never spin at DISPATCH_LEVEL behind a preempted phase owner. */
            return STATUS_DEVICE_BUSY;
        }
        /* Suspend a control thread instead of spinning behind an IPI. */
        (void)KeWaitForSingleObject(
            &runtime->residentTransitionIdleEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL);
    }
}

VOID
kswordArkHvmReleaseResidentTransition(
    _Inout_ KswHvmRuntime* runtime
    )
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    NT_ASSERT(Runtime != NULL);
    /* Publish idle and signal its event as one short state-locked commit. */
    KeAcquireSpinLock(
        &runtime->residentTransitionStateLock,
        &oldIrql);
    NT_ASSERT(InterlockedCompareExchange(
        &Runtime->ResidentTransitionActive,
        0L,
        0L) != 0L);
    InterlockedExchange(
        &runtime->residentTransitionActive,
        0L);
    KeSetEvent(
        &runtime->residentTransitionIdleEvent,
        IO_NO_INCREMENT,
        FALSE);
    KeReleaseSpinLock(
        &runtime->residentTransitionStateLock,
        oldIrql);
}

static NTSTATUS
kswordArkHvmCompleteDeferredPowerResumeLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* State two means S0 resumed while an HVM operation was still draining. */
    if (InterlockedCompareExchange(
            &runtime->powerTransitionPending,
            0L,
            0L) != 2L) {
        return STATUS_SUCCESS;
    }
    /* Never reopen entry while an operation, context, or rollback is live. */
    if (runtime->busy ||
        InterlockedCompareExchange(
            &runtime->residentContextPreparing,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L ||
        (runtime->stateFlags &
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0UL) {
        return STATUS_DEVICE_BUSY;
    }
    /* Restore unload ownership before publishing the reopened lifecycle. */
    status = kswordArkHvmDisarmUnloadGuard(runtime);
    if (NT_SUCCESS(status)) {
        kswordArkHvmInvalidatePowerResumeEvidence(runtime);
        InterlockedExchange(&runtime->powerTransitionPending, 0L);
        kswordArkHvmStateClear(
            runtime,
            KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING);
    }
    return status;
}

static VOID NTAPI
kswordArkHvmPowerStateCallback(
    _In_opt_ PVOID callbackContext,
    _In_opt_ PVOID argument1,
    _In_opt_ PVOID argument2
    )
{
    KswHvmRuntime* runtime =
        (KswHvmRuntime*)callbackContext;
    NTSTATUS status = STATUS_SUCCESS;

    /* Process only the system working-state lock notification. */
    if (runtime == NULL ||
        argument1 != (PVOID)(ULONG_PTR)PO_CB_SYSTEM_STATE_LOCK) {
        return;
    }
    if ((ULONG_PTR)argument2 == FALSE) {
        /* Block every new resident transition before taking its phase gate. */
        InterlockedExchange(&runtime->powerTransitionPending, 1L);
        InterlockedIncrement(&runtime->powerTransitionGeneration);
        kswordArkHvmStateSet(
            runtime,
            KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING);
        /* Synchronously complete all-CPU VMXOFF before leaving S0. */
        status = kswordArkHvmResidentStop(runtime);
        runtime->lastStatus = status;
        InterlockedIncrement((volatile LONG*)&runtime->generation);
        if (!NT_SUCCESS(status)) {
            kswordArkHvmStateSet(
                runtime,
                KSWORD_ARK_HVM_STATE_FAULTED |
                    KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
            /*
             * A DISPATCH_LEVEL phase collision cannot wait safely.  Fail
             * closed even before resident count is published so an in-flight
             * transient VMX window cannot cross the S0 boundary.
             */
            if (status == STATUS_DEVICE_BUSY ||
                InterlockedCompareExchange(
                    &runtime->residentProcessorCount,
                    0L,
                    0L) != 0L) {
                KeBugCheckEx(
                    KSW_HVM_LIFECYCLE_BUGCHECK_CODE,
                    (ULONG_PTR)KSW_HVM_POWER_FAILURE_SIGNATURE,
                    (ULONG_PTR)runtime->residentProcessorCount,
                    (ULONG_PTR)status,
                    (ULONG_PTR)runtime->stateFlags);
            }
        }
        return;
    }

    /* Mark S0 resumed, then reopen only after every HVM operation drains. */
    InterlockedExchange(&runtime->powerTransitionPending, 2L);
    status = kswordArkHvmAcquireResidentTransition(runtime);
    if (NT_SUCCESS(status)) {
        if (runtime->busy ||
            InterlockedCompareExchange(
                &runtime->residentContextPreparing,
                0L,
                0L) != 0L) {
            /* Keep the gate closed until the active control path drains. */
            status = STATUS_DEVICE_BUSY;
        } else {
            status =
                kswordArkHvmCompleteDeferredPowerResumeLocked(runtime);
        }
        kswordArkHvmReleaseResidentTransition(runtime);
    }
    runtime->lastStatus = status;
    InterlockedIncrement((volatile LONG*)&runtime->generation);
}

static VOID
kswordArkHvmProcessorChangeCallback(
    _In_opt_ PVOID callbackContext,
    _In_ PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT changeContext,
    _Inout_ PNTSTATUS operationStatus
    )
{
    KswHvmRuntime* runtime =
        (KswHvmRuntime*)callbackContext;

    /* Preserve the exact prepared/self-tested CPU set until full teardown. */
    if (runtime != NULL &&
        changeContext != NULL &&
        operationStatus != NULL &&
        changeContext->State == KeProcessorAddStartNotify &&
        NT_SUCCESS(*operationStatus) &&
        ((runtime->stateFlags &
             (KSWORD_ARK_HVM_STATE_BUSY |
              KSWORD_ARK_HVM_STATE_RESOURCES_READY |
              KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
              KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
              KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING)) != 0UL)) {
        *operationStatus = STATUS_DEVICE_BUSY;
    }
}

static VOID
kswordArkHvmFreeResourcesLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
    ULONG index = 0UL;
    NTSTATUS residentStatus = STATUS_SUCCESS;

    /* Drain active or retained resident contexts before releasing VMX pages. */
    residentStatus = kswordArkHvmResidentStop(runtime);
    /* Preserve resources while any processor or unload guard remains unsafe. */
    if (!NT_SUCCESS(residentStatus) ||
        InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L) != 0L) {
        /* Publish explicit rollback-required evidence. */
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        /* Preserve the authoritative stop failure. */
        runtime->lastStatus = residentStatus;
        /* Return without releasing live VMX resources. */
        return;
    }
    /* AMD owns separate resources and must not enter Intel cleanup helpers. */
    if (kswordHvmBackend(runtime->backendId) != NULL) {
        /* Stop above already proved that hardware ownership was returned. */
        kswordHvmBackend(runtime->backendId)->releaseResources(runtime);
        return;
    }
    /* Drop the control-register policy along with the VMCS it fed. */
    kswordArkHvmCrPolicyResetLocked(runtime);
    /* Close every MSR bitmap hole before the bitmap page is released. */
    kswordArkHvmMsrPolicyResetLocked(runtime);
    /*
     * Unpublish every EPTP list slot first.  While a slot still names a
     * domain, one guest VMFUNC can switch onto tables this teardown is about
     * to dismantle.
     */
    kswordArkHvmEptDomainResetLocked(runtime);
    /*
     * Release the hierarchy occupied by each R-1 process disposal before the hierarchy page pool is freed.
     *
     * Placed before the view because they share the same pool: releasing the pool while
     * records still reference a hierarchy level would desynchronize the ledger and pages.
     */
    kswordArkHvmProcessResetLocked(runtime);
    /*
     * Remove each R-1 injection's execution view, and do so before the view table is cleared.
     *
     * Placed here because injection relies on view identifiers to detach views: if the view is cleared first, the identifier held by
     * the injection handle points to a non-existent view, causing the detachment to fail silently and leading to shadow page leaks.
     */
    kswordArkHvmInjectResetLocked(runtime);
    kswordArkHvmNestedPageResetLocked(runtime);
    /* Restore view leaves and free shadows before rules touch the same pages. */
    kswordArkHvmEptViewResetLocked(runtime);
    /* Restore baseline EPT leaves before releasing split table pages. */
    kswordArkHvmEptResetLocked(runtime);

    /* Free per-processor VMXON and VMCS pages symmetrically. */
    for (index = 0UL; index < runtime->processorCount; ++index) {
        if (runtime->processors[index].vmxonVirtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].vmxonVirtual);
        }
        if (runtime->processors[index].vmcsVirtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].vmcsVirtual);
        }
        if (runtime->processors[index].veInfoVirtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].veInfoVirtual);
        }
        if (runtime->processors[index].vmcs02Virtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].vmcs02Virtual);
        }
        if (runtime->processors[index].l2MsrBitmapVirtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].l2MsrBitmapVirtual);
        }
        if (runtime->processors[index].l2IoBitmapAVirtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].l2IoBitmapAVirtual);
        }
        if (runtime->processors[index].l2IoBitmapBVirtual != NULL) {
            MmFreeContiguousMemory(
                runtime->processors[index].l2IoBitmapBVirtual);
        }
        if (runtime->processors[index].l2MsrBitmapL1Copy != NULL) {
            ExFreePool(runtime->processors[index].l2MsrBitmapL1Copy);
        }
        RtlZeroMemory(
            &runtime->processors[index],
            sizeof(runtime->processors[index]));
    }

    /* Every EPT table page is tracked exactly once in the allocation ledger. */
    for (index = 0UL; index < runtime->eptPageCount; ++index) {
        if (runtime->eptPages[index].virtualAddress != NULL) {
            MmFreeContiguousMemory(
                runtime->eptPages[index].virtualAddress);
        }
    }

    /* Release the shared MSR bitmap only after every VMCS reference is gone. */
    if (runtime->msrBitmapVirtual != NULL) {
        MmFreeContiguousMemory(runtime->msrBitmapVirtual);
        runtime->msrBitmapVirtual = NULL;
        runtime->msrBitmapPhysical.QuadPart = 0LL;
    }

    /* Clear all resource-derived state while preserving capability evidence. */
    RtlZeroMemory(runtime->processors, sizeof(runtime->processors));
    RtlZeroMemory(runtime->eptPages, sizeof(runtime->eptPages));
    RtlZeroMemory(runtime->eptPdpt, sizeof(runtime->eptPdpt));
    RtlZeroMemory(runtime->eptPd, sizeof(runtime->eptPd));
    RtlZeroMemory(&runtime->mtrr, sizeof(runtime->mtrr));
    runtime->eptPml4 = NULL;
    runtime->processorCount = 0UL;
    runtime->preparedProcessorCount = 0UL;
    runtime->selfTestPassedProcessorCount = 0UL;
    runtime->residentProcessorCount = 0L;
    runtime->eptRuleCount = 0UL;
    runtime->eptPageCount = 0UL;
    runtime->eptPml4Entries = 0UL;
    runtime->eptPdptEntries = 0UL;
    runtime->eptLargePageEntries = 0UL;
    runtime->eptPointer = 0ULL;
    /* The arm latch is resource-derived and must not outlive the resources. */
    runtime->localEptArmed = FALSE;
    runtime->featureFlags &= ~KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED;
    /* The second backend's latch has exactly the same lifetime. */
    runtime->eptpSwitchArmed = FALSE;
    runtime->featureFlags &= ~KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED;
    /* Release the pool with the resources it was derived from. */
    kswordArkHvmEptSwitchRelease(runtime);
    runtime->mappedRamBytes = 0ULL;
    runtime->highestMappedPhysicalAddress = 0ULL;
    runtime->vmExitCount = 0ULL;
    runtime->lastExitQualification = 0ULL;
    runtime->lastGuestRip = 0ULL;
    runtime->lastGuestRsp = 0ULL;
    runtime->lastExitReason = KSWORD_ARK_HVM_EXIT_REASON_NONE;
    runtime->lastExitInstructionLength = 0UL;
    runtime->lastVmInstructionError = 0UL;
    runtime->lastLaunchProcessorGroup = 0xFFFFU;
    runtime->lastLaunchProcessorNumber = 0xFFU;
    runtime->lastLaunchWasNested = 0U;
    runtime->residentImplementation =
        runtime->residentStartAllowed
            ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
            : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    runtime->eptImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
    kswordArkHvmStateClear(
        runtime,
        KSWORD_ARK_HVM_STATE_RESOURCES_READY |
            KSWORD_ARK_HVM_STATE_EPT_READY |
            KSWORD_ARK_HVM_STATE_SELF_TESTED |
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
            KSWORD_ARK_HVM_STATE_EPT_TRUNCATED |
            KSWORD_ARK_HVM_STATE_GUEST_READY |
            KSWORD_ARK_HVM_STATE_GUEST_RUNNING |
            KSWORD_ARK_HVM_STATE_GUEST_EXITED |
            KSWORD_ARK_HVM_STATE_NESTED_ACTIVE |
            KSWORD_ARK_HVM_STATE_NESTED_VALIDATED |
            KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
            KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
            KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
            KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE |
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
}

PVOID
kswordArkHvmAllocateEptPageLocked(
    _Inout_ KswHvmRuntime* runtime,
    _Out_ PHYSICAL_ADDRESS* physicalAddress
    )
{
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PVOID page = NULL;
    ULONGLONG* entries = NULL;
    SIZE_T index = 0;

    /* Enforce a bounded allocation ledger before allocating nonpaged memory. */
    if (physicalAddress == NULL) {
        return NULL;
    }
    physicalAddress->QuadPart = 0LL;
    if (runtime->eptPageCount >= KSW_HVM_MAX_EPT_PAGES) {
        return NULL;
    }
    highest.QuadPart = MAXLONGLONG;
    page = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    if (page == NULL) {
        return NULL;
    }

    /*
     * Prime table pages so every unused slot is not-present AND
     * non-convertible.  A zeroed slot leaves suppress-#VE clear, which makes
     * it convertible: with "EPT-violation #VE" enabled, every access to an
     * unmapped GPA would reflect a #VE into a guest that has no handler for
     * it.  Setting only bit 63 leaves the slot not-present - no read, write,
     * or execute permission - so nothing about translation changes; only
     * convertibility does.  Slots that later become real entries are
     * overwritten whole, so they carry whatever their writer chose.
     */
    entries = (ULONGLONG*)page;
    for (index = 0;
         index < (SIZE_T)(KSW_HVM_PAGE_BYTES / sizeof(ULONGLONG));
         index += 1) {
        entries[index] = KSW_EPT_SUPPRESS_VE;
    }
    *physicalAddress = MmGetPhysicalAddress(page);
    runtime->eptPages[runtime->eptPageCount].virtualAddress = page;
    runtime->eptPages[runtime->eptPageCount].physicalAddress =
        *physicalAddress;
    runtime->eptPageCount += 1UL;
    return page;
}

static NTSTATUS
kswordArkHvmAllocateProcessorResourcesLocked(
    _Inout_ KswHvmRuntime* runtime
    )
{
#if defined(_M_AMD64)
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    USHORT groupCount = 0U;
    USHORT group = 0U;
    ULONG processorIndex = 0UL;
    ULONG revision = (ULONG)(runtime->vmxBasic & 0x7FFFFFFFULL);

    /* enumerate every active group without exceeding the stable protocol cap. */
    highest.QuadPart = MAXLONGLONG;
    /*
     * Every processor shares one MSR bitmap because the policy is global.
     * A zeroed bitmap keeps guest MSR access native; without the bitmap the
     * CPU exits on every RDMSR and WRMSR and no resident guest survives.
     */
    if (runtime->msrBitmapVirtual == NULL) {
        runtime->msrBitmapVirtual =
            MmAllocateContiguousMemorySpecifyCache(
                (SIZE_T)KSW_HVM_PAGE_BYTES,
                lowest,
                highest,
                boundary,
                MmCached);
        if (runtime->msrBitmapVirtual == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(
            runtime->msrBitmapVirtual,
            (SIZE_T)KSW_HVM_PAGE_BYTES);
        runtime->msrBitmapPhysical =
            MmGetPhysicalAddress(runtime->msrBitmapVirtual);
        runtime->msrBitmapInterceptCount = 0UL;
        /*
         * Make the VMX capability MSRs exit, so what we advertise can be
         * narrowed to what we implement.
         *
         * Armed here, at the one place the bitmap is created, because a guest
         * that reads these before we intercept them has already been told the
         * machine's real capabilities - and a hypervisor reads them once, at
         * its own initialization, then never again.  There is no second chance
         * to correct the answer.
         */
        kswordArkHvmMsrArmVmxCapabilityInterceptLocked(runtime);
    }
    groupCount = KeQueryActiveGroupCount();
    for (group = 0U;
         group < groupCount &&
            processorIndex < KSWORD_ARK_HVM_MAX_PROCESSORS;
         ++group) {
        /* Query the exact active mask for this processor group. */
        KAFFINITY activeMask = KeQueryGroupAffinity(group);
        UCHAR processorNumber = 0U;

        /* Group masks are at most 64 bits on supported Windows targets. */
        for (processorNumber = 0U;
             processorNumber < (UCHAR)(sizeof(KAFFINITY) * 8U) &&
                processorIndex < KSWORD_ARK_HVM_MAX_PROCESSORS;
             ++processorNumber) {
            KswHvmCpuResource* cpu = NULL;

            /* Skip offline and absent logical processors. */
            if ((activeMask &
                    (((KAFFINITY)1) << processorNumber)) == 0) {
                continue;
            }
            cpu = &runtime->processors[processorIndex];
            cpu->row.processorGroup = group;
            cpu->row.processorNumber = processorNumber;
            cpu->row.vmxInstructionResult = 0xFFU;
            cpu->row.lastExitReason =
                KSWORD_ARK_HVM_EXIT_REASON_NONE;
            /*
             * Publish the in-progress slot to cleanup before either allocation;
             * this prevents a partial VMXON/VMCS pair from escaping rollback.
             */
            runtime->processorCount = processorIndex + 1UL;

            /* VMXON and VMCS regions are independent physical 4-KiB pages. */
            cpu->vmxonVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            cpu->vmcsVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            /*
             * The #VE information area is per-processor by architecture: two
             * processors sharing one page would race on the busy handshake.
             */
            cpu->veInfoVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            /*
             * The vmcs02 region is reserved unconditionally rather than only
             * when nested dispatch is enabled: residency start flags are not
             * known here, and one page per processor is cheaper than a second
             * allocation path that only ever runs on the rarer branch.
             */
            cpu->vmcs02Virtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            /*
             * The three bitmap pages vmcs02 points at while L2 runs.
             *
             * Reserved on the same unconditional basis as vmcs02 itself: the
             * residency start flags are not known here, and three pages per
             * processor is cheaper than a second allocation path that only
             * runs on the rarer branch.  They must be contiguous and
             * page-aligned because the processor reads them by physical
             * address out of the VMCS.
             */
            cpu->l2MsrBitmapVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            cpu->l2IoBitmapAVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            cpu->l2IoBitmapBVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            /* L1's unmerged copy never reaches hardware, so pool suffices. */
            cpu->l2MsrBitmapL1Copy =
                kswordArkAllocateNonPagedPool(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    KSW_HVM_L2_BITMAP_POOL_TAG);
            if (cpu->vmxonVirtual == NULL ||
                cpu->vmcsVirtual == NULL ||
                cpu->veInfoVirtual == NULL ||
                cpu->vmcs02Virtual == NULL ||
                cpu->l2MsrBitmapVirtual == NULL ||
                cpu->l2IoBitmapAVirtual == NULL ||
                cpu->l2IoBitmapBVirtual == NULL ||
                cpu->l2MsrBitmapL1Copy == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            /*
             * Start every bitmap at all-ones, not zero.
             *
             * Zero means "nothing exits", so a merge that never ran would hand
             * L2 unmediated access to every MSR and every port.  All-ones
             * means "everything exits", which is merely slow and keeps both
             * hypervisors in control.  The failure direction has to be the
             * conservative one, because nothing downstream can detect the
             * other.
             */
            RtlFillMemory(
                cpu->l2MsrBitmapVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES,
                0xFF);
            RtlFillMemory(
                cpu->l2IoBitmapAVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES,
                0xFF);
            RtlFillMemory(
                cpu->l2IoBitmapBVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES,
                0xFF);
            RtlFillMemory(
                cpu->l2MsrBitmapL1Copy,
                (SIZE_T)KSW_HVM_PAGE_BYTES,
                0xFF);
            cpu->l2MsrBitmapPhysical =
                MmGetPhysicalAddress(cpu->l2MsrBitmapVirtual);
            cpu->l2IoBitmapAPhysical =
                MmGetPhysicalAddress(cpu->l2IoBitmapAVirtual);
            cpu->l2IoBitmapBPhysical =
                MmGetPhysicalAddress(cpu->l2IoBitmapBVirtual);
            RtlZeroMemory(
                cpu->vmcs02Virtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            *(volatile ULONG*)cpu->vmcs02Virtual = revision;
            cpu->vmcs02Physical =
                MmGetPhysicalAddress(cpu->vmcs02Virtual);

            /*
             * Latch the area busy before it can ever be reachable from a
             * VMCS.  Nothing in this driver clears it, so the processor keeps
             * choosing the EPT-violation exit over a #VE delivery even if the
             * control is enabled and a leaf is convertible.  See the busy
             * field's comment in hvm_internal.h.
             */
            RtlZeroMemory(
                cpu->veInfoVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            *(volatile ULONG*)((PUCHAR)cpu->veInfoVirtual +
                KSW_VE_INFO_OFFSET_BUSY) = KSW_VE_INFO_BUSY;
            cpu->veInfoPhysical =
                MmGetPhysicalAddress(cpu->veInfoVirtual);

            /* Both regions start with the CPU-advertised VMCS revision ID. */
            RtlZeroMemory(
                cpu->vmxonVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            RtlZeroMemory(
                cpu->vmcsVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            *(volatile ULONG*)cpu->vmxonVirtual = revision;
            *(volatile ULONG*)cpu->vmcsVirtual = revision;
            cpu->vmxonPhysical =
                MmGetPhysicalAddress(cpu->vmxonVirtual);
            cpu->vmcsPhysical =
                MmGetPhysicalAddress(cpu->vmcsVirtual);
            cpu->row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY;
            cpu->row.lastStatus = STATUS_SUCCESS;
            runtime->preparedProcessorCount += 1UL;
            processorIndex += 1UL;
        }
    }
    runtime->processorCount = processorIndex;
    /*
     * Every prepared processor now owns an information area, latched busy.
     * Callers read this together with VE_SUPPRESSED_BY_DEFAULT to tell which
     * of the two safeties are actually in place on this runtime.
     */
    if (processorIndex > 0UL) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_VE_INFO_READY;
    }
    if (runtime->processorCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Runtime);
    return STATUS_NOT_SUPPORTED;
#endif
}

/*
 * Read the page-directory base of the System process.
 *
 * The same technique the memory window already uses: Windows publishes no
 * stable EPROCESS DirectoryTableBase offset, and a hardcoded one fails
 * silently after an update because a wrong CR3 still walks.  So attach and
 * read the register the hardware is actually using.
 *
 * Detaching before the value is consumed is sound: it names a physical page
 * that stays resident for the life of the System process, and nothing here
 * dereferences a virtual address in that address space.
 */
static NTSTATUS
kswordArkHvmCaptureSystemDirectoryBase(
    _Out_ ULONGLONG* directoryBase
    )
{
#if defined(_M_AMD64)
    DECLSPEC_ALIGN(16) UCHAR attachState[128];

    /* Reject an incomplete caller contract before touching anything. */
    if (directoryBase == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    *directoryBase = 0ULL;
    /* Refuse to guess when the exported System process is unavailable. */
    if (PsInitialSystemProcess == NULL) {
        /* Return the exact unusable-state failure. */
        return STATUS_UNSUCCESSFUL;
    }
    RtlZeroMemory(attachState, sizeof(attachState));
    /* Attach only long enough to read the register. */
    KeStackAttachProcess((PVOID)PsInitialSystemProcess, (PVOID)attachState);
    *directoryBase = (ULONGLONG)__readcr3();
    KeUnstackDetachProcess((PVOID)attachState);
    /* Refuse a base that could never translate the host entry point. */
    if (*directoryBase == 0ULL) {
        /* Return the exact unusable-state failure. */
        return STATUS_UNSUCCESSFUL;
    }
    /* Complete the capture successfully. */
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(DirectoryBase);
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS
kswordArkHvmPrepareLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* request
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Do not replace live resource state with a second allocation set. */
    if ((runtime->stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0UL) {
        return STATUS_ALREADY_REGISTERED;
    }

    /* Capture a durable host address space before allocating any SVM resources. */
    if (kswordHvmBackend(runtime->backendId) != NULL) {
        /* Preparation is visible to the existing power-transition guard. */
        InterlockedExchange(&runtime->residentContextPreparing, 1);
        status = kswordArkHvmCaptureSystemDirectoryBase(&runtime->hostCr3);
        /* Vendor preparation validates every CPU and its complete NPT coverage. */
        if (NT_SUCCESS(status)) { status = kswordHvmBackend(runtime->backendId)->prepareResources(runtime, request->flags); }
        /* No SVM instruction executes in this allocation phase. */
        InterlockedExchange(&runtime->residentContextPreparing, 0);
        return status;
    }
    /* Nested preparation is accepted only when VMX is explicitly exposed. */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (((request->flags &
              KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) ||
         ((runtime->featureFlags &
              KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL))) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

#if defined(_M_AMD64)
    /* Verify uniform capabilities across all logical processors before any resource allocation or VMXON. */
    status = kswordArkHvmVerifyUniformCapabilities();
    if (!NT_SUCCESS(status)) {
        return status;
    }
#else
    return STATUS_NOT_SUPPORTED;
#endif

    /*
     * Capture the host page-directory base before anything else, while this is
     * still a PASSIVE_LEVEL path that may attach to another process.
     *
     * This runs on the thread that issued the IOCTL, so __readcr3() here would
     * hand back the requesting user-mode process's top-level page table - the
     * very value that must never reach HOST_CR3.  See KswHvmRuntime::HostCr3
     * for what happens when that page is freed underneath a live VMCS.
     */
    status = kswordArkHvmCaptureSystemDirectoryBase(&runtime->hostCr3);
    /* Refuse to prepare without a host address space that outlives the caller. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact capture failure. */
        return status;
    }

    /* Capture MTRR state before choosing EPT leaf memory types. */
    status = kswordArkHvmMtrrCapture(&runtime->mtrr);
    /* Stop when memory typing cannot be established safely. */
    if (!NT_SUCCESS(status)) {
        /* Release any stale partial state before returning the failure. */
        kswordArkHvmFreeResourcesLocked(runtime);
        /* Return the authoritative MTRR capture failure. */
        return status;
    }

    /* Allocate every per-CPU VMX pair before creating the EPT hierarchy. */
    status = kswordArkHvmAllocateProcessorResourcesLocked(runtime);
    if (!NT_SUCCESS(status)) {
        kswordArkHvmFreeResourcesLocked(runtime);
        return status;
    }
    /* Base EPT construction belongs to prepare, before resident insertion. */
    kswordArkHvmMetricsStamp(KSW_HVM_TIME_EPT_BEGIN);
    status = kswordArkHvmBuildEptLocked(runtime);
    /* Record failures as well as successful hierarchy construction. */
    kswordArkHvmMetricsStamp(KSW_HVM_TIME_EPT_END);
    if (!NT_SUCCESS(status)) {
        kswordArkHvmFreeResourcesLocked(runtime);
        return status;
    }

    /*
     * Arm per-processor EPT only when it was asked for AND both controls it
     * depends on exist.  Single-context INVEPT is what makes one processor's
     * flip invalidate only its own translations; the Monitor Trap Flag is
     * what bounds the window to one instruction.  Without either, private
     * hierarchies would cost pages and buy nothing.
     *
     * Assigned in both directions rather than conditionally set: this routine
     * refuses to run while RESOURCES_READY is set, so it never sees a zeroed
     * runtime and a stale TRUE would survive.
     */
    runtime->localEptArmed =
        ((request->flags &
             KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT) != 0UL &&
         (runtime->featureFlags &
             (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
              KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG)) ==
             (KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE |
              KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG))
        ? TRUE
        : FALSE;
    if (runtime->localEptArmed) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED;
    } else {
        runtime->featureFlags &=
            ~KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED;
    }
    /*
     * A reused bit would be silent and total: the new flag would simply mean
     * whatever the older one means, every gate would agree, and nothing would
     * report an error.  Both new encodings are therefore proven disjoint from
     * every value already defined, at compile time.
     */
    C_ASSERT((KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH &
              (KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
               KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
               KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
               KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST |
               KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS |
               KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
               KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS |
               KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE |
               KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC |
               KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT)) == 0UL);
    C_ASSERT((KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED &
              (KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED |
               KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY |
               KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING |
               KSWORD_ARK_HVM_FEATURE_VM_FUNCTIONS |
               KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG |
               KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE)) == 0ULL);
    /*
     * Arm the EPTP-switching split-view backend only when it was asked for
     * AND both capabilities it depends on exist.
     *
     * The pair is deliberately *not* the pair above.  Single-context INVEPT is
     * shared: a hierarchy switch still has to drop translations built from the
     * hierarchy being left.  The second one is execute-only EPT leaves rather
     * than the Monitor Trap Flag, because this backend never single-steps -
     * it leaves the guest running on a second hierarchy until an access of the
     * opposite kind faults it back.  That difference is the entire point: the
     * Monitor Trap Flag is not offered to a nested guest, execute-only leaves
     * are, and both CLOAK and HOOK are refused outright without the latter
     * (KswordArkHvmEptSwKindPermissions checks it before it looks at kind).
     *
     * Execute-only has no KSWORD_ARK_HVM_FEATURE_* bit of its own, so it is
     * read from the capability MSR image rather than from FeatureFlags - a
     * fully populated FeatureFlags still cannot answer this question.
     *
     * Assigned in both directions for the same reason as LocalEptArmed above:
     * this routine refuses to run while RESOURCES_READY is set, so a stale
     * TRUE would otherwise survive.
     */
    runtime->eptpSwitchArmed =
        ((request->flags &
             KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH) != 0UL &&
         (runtime->featureFlags &
             KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL &&
         (runtime->vmxEptVpidCapabilities & KSW_EPT_CAP_EXECUTE_ONLY) != 0ULL)
        ? TRUE
        : FALSE;
    if (runtime->eptpSwitchArmed) {
        runtime->featureFlags |=
            KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED;
    } else {
        runtime->featureFlags &=
            ~KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED;
    }
    /*
     * Reserve the secondary-hierarchy page pool while still at PASSIVE_LEVEL
     * and while a failure can still be reported as a refused prepare.  Only
     * the pool: no hierarchy is built here, because a hierarchy is keyed by
     * the leaf it relaxes and no view exists yet.
     *
     * A failure unarms the backend rather than failing the whole prepare.
     * The alternative would turn a machine that simply cannot spare 512 KiB
     * of nonpaged pool into a machine where HVM does not start at all, and
     * the caller can see exactly what happened: EPTP_SWITCH_ARMED is absent
     * from the published capabilities.
     */
    if (runtime->eptpSwitchArmed) {
        status = kswordArkHvmEptSwitchReserve(runtime);
        if (!NT_SUCCESS(status)) {
            kswordArkHvmEptSwitchRelease(runtime);
            runtime->eptpSwitchArmed = FALSE;
            runtime->featureFlags &=
                ~KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED;
        }
    }
    /* Resource readiness is published only after both allocation phases pass. */
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_RESOURCES_READY);
    /* Publish active EPT maturity only after the complete hierarchy exists. */
    runtime->eptImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE;
    return STATUS_SUCCESS;
}

#if defined(_M_AMD64)
static NTSTATUS
kswordArkHvmSelfTestProcessor(
    _Inout_ KswHvmRuntime* runtime,
    _Inout_ KswHvmCpuResource* cpu
    )
{
    GROUP_AFFINITY targetAffinity = { 0 };
    GROUP_AFFINITY oldAffinity = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    ULONGLONG originalCr0 = 0ULL;
    ULONGLONG originalCr4 = 0ULL;
    ULONGLONG requiredCr0 = 0ULL;
    ULONGLONG requiredCr4 = 0ULL;
    unsigned __int64 vmxonPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN transitionOwned = FALSE;
    BOOLEAN irqlRaised = FALSE;
    BOOLEAN cr4Changed = FALSE;
    BOOLEAN vmxOwned = FALSE;
    KswHvmVmcS12State* nativeScratch = NULL;

    /* Allocate before affinity/IRQL changes; never put 16 KiB on a kernel stack. */
    nativeScratch = (KswHvmVmcS12State*)kswordArkAllocateNonPagedPool(
        sizeof(*nativeScratch), 'iVKH');
    if (nativeScratch == NULL) {
        cpu->row.lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Bind the current system thread to the exact resource-owning processor. */
    targetAffinity.Group = cpu->row.processorGroup;
    targetAffinity.Mask =
        ((KAFFINITY)1) << cpu->row.processorNumber;
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &oldAffinity);
    affinitySet = TRUE;

    /* Own the transition phase without holding its state spin lock over VMX. */
    status = kswordArkHvmAcquireResidentTransition(runtime);
    if (!NT_SUCCESS(status)) {
        goto Complete;
    }
    transitionOwned = TRUE;
    /* Prevent thread migration while this CPU temporarily owns VMX root. */
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    irqlRaised = TRUE;
    __try {
        /* A leaving-S0 callback always wins before any new VMXON. */
        if (InterlockedCompareExchange(
                &runtime->powerTransitionPending,
                0L,
                0L) != 0L) {
            status = STATUS_POWER_STATE_INVALID;
            __leave;
        }
        originalCr0 = __readcr0();
        originalCr4 = __readcr4();
        requiredCr0 =
            (originalCr0 | runtime->cr0Fixed0) &
            runtime->cr0Fixed1;
        requiredCr4 =
            ((originalCr4 | runtime->cr4Fixed0) &
                runtime->cr4Fixed1) |
            KSW_CR4_VMXE;

        /*
         * Never steal a VMX root already owned by another component, and never
         * alter CR0 or clear a live CR4 feature merely to make the test pass.
         */
        if ((originalCr4 & KSW_CR4_VMXE) != 0ULL ||
            requiredCr0 != originalCr0 ||
            (requiredCr4 & originalCr4) != originalCr4) {
            cpu->row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_CONFLICT;
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        /* Enter VMX root briefly using the page assigned to this processor. */
        __writecr4(requiredCr4);
        cr4Changed = TRUE;
        vmxonPhysical =
            (unsigned __int64)cpu->vmxonPhysical.QuadPart;
        vmxResult = __vmx_on(&vmxonPhysical);
        cpu->row.vmxInstructionResult = vmxResult;
        cpu->row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }

        vmxOwned = TRUE;
        /* Verify hardware field persistence and the importer on this exact CPU. */
        status = kswordArkHvmNestedVmcsNativeSelfTest(cpu, nativeScratch);
        /* All private VMCSs have been cleared before relinquishing VMX. */
        (void)__vmx_off();
        vmxOwned = FALSE;
        if (NT_SUCCESS(status)) {
            cpu->row.stateFlags |= KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        cpu->row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
            KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
        status = GetExceptionCode();
    }

    /* Exceptions after VMXON must not leave ownership behind. */
    if (vmxOwned) {
        unsigned __int64 physical = (ULONGLONG)cpu->vmcsPhysical.QuadPart;
        (void)__vmx_vmclear(&physical);
        physical = (ULONGLONG)cpu->vmcs02Physical.QuadPart;
        (void)__vmx_vmclear(&physical);
        __vmx_off();
    }
    /* Restore the original control register before lowering IRQL. */
    if (cr4Changed) {
        __try {
            __writecr4(originalCr4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            cpu->row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
        }
    }
Complete:
    if (transitionOwned) {
        kswordArkHvmReleaseResidentTransition(runtime);
    }
    if (irqlRaised) {
        KeLowerIrql(oldIrql);
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }
    ExFreePool(nativeScratch);
    cpu->row.lastStatus = status;
    return status;
}
#endif

static NTSTATUS
kswordArkHvmSelfTestLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* request
    )
{
#if defined(_M_AMD64)
    ULONG index = 0UL;
    ULONG passed = 0UL;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    NTSTATUS transitionStatus = STATUS_SUCCESS;
    LONG powerGeneration = 0L;

    /* AMD self-test executes a real one-shot VMRUN on each target CPU. */
    if (kswordHvmBackend(runtime->backendId) != NULL) {
        return kswordHvmBackend(runtime->backendId)->selfTest(runtime, request->flags);
    }
    /* The test operates only on a complete prepared resource set. */
    if ((runtime->stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL) {
        return STATUS_DEVICE_NOT_READY;
    }
    powerGeneration = InterlockedCompareExchange(
        &runtime->powerTransitionGeneration,
        0L,
        0L);

    /* Nested execution requires a second explicit opt-in at self-test time. */
    if ((runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Test each processor independently and retain every local result row. */
    for (index = 0UL; index < runtime->processorCount; ++index) {
        NTSTATUS status =
            kswordArkHvmSelfTestProcessor(
                runtime,
                &runtime->processors[index]);
        if (NT_SUCCESS(status)) {
            passed += 1UL;
        } else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }
    /* Publish one coherent test epoch, never a pre/post-sleep mixture. */
    transitionStatus = kswordArkHvmAcquireResidentTransition(runtime);
    if (!NT_SUCCESS(transitionStatus)) {
        return transitionStatus;
    }
    if (InterlockedCompareExchange(
            &runtime->powerTransitionPending,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &runtime->powerTransitionGeneration,
            0L,
            0L) != powerGeneration) {
        kswordArkHvmInvalidatePowerResumeEvidence(runtime);
        kswordArkHvmReleaseResidentTransition(runtime);
        return STATUS_POWER_STATE_INVALID;
    }
    runtime->selfTestPassedProcessorCount = passed;
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_SELF_TESTED);
    if (passed == runtime->processorCount &&
        runtime->processorCount != 0UL) {
        kswordArkHvmStateSet(
            runtime,
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
                KSWORD_ARK_HVM_STATE_GUEST_READY);
        kswordArkHvmReleaseResidentTransition(runtime);
        return STATUS_SUCCESS;
    }
    kswordArkHvmStateClear(
        runtime,
        KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
            KSWORD_ARK_HVM_STATE_GUEST_READY);
    kswordArkHvmReleaseResidentTransition(runtime);
    return NT_SUCCESS(firstFailure)
        ? STATUS_UNSUCCESSFUL
        : firstFailure;
#else
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS
kswordArkHvmLaunchGuestLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* request
    )
{
#if defined(_M_AMD64)
    KswHvmCpuResource* cpu = NULL;
    KswHvmGuestLaunchInput launchInput = { 0 };
    KswHvmGuestLaunchResult launchResult = { 0 };
    ULONG index = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN nestedLaunch = FALSE;
    LONG powerGeneration = 0L;

    /* Bind every prerequisite and VMX transition to one power epoch. */
    powerGeneration = InterlockedCompareExchange(
        &runtime->powerTransitionGeneration,
        0L,
        0L);
    if (InterlockedCompareExchange(
            &runtime->powerTransitionPending,
            0L,
            0L) != 0L) {
        return STATUS_POWER_STATE_INVALID;
    }
    /* Require a complete prepared and self-tested backend before VM entry. */
    if ((runtime->stateFlags &
            (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
             KSWORD_ARK_HVM_STATE_EPT_READY |
             KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
             KSWORD_ARK_HVM_STATE_GUEST_READY)) !=
        (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
         KSWORD_ARK_HVM_STATE_EPT_READY |
         KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
         KSWORD_ARK_HVM_STATE_GUEST_READY)) {
        return STATUS_DEVICE_NOT_READY;
    }
    /* Require the one-shot semantic bit so the command cannot drift silently. */
    if ((request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST) == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Detect whether this launch would execute as an explicitly nested guest. */
    nestedLaunch =
        (runtime->featureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL;
    /* Reject nested execution unless both exposure and explicit opt-in exist. */
    if (nestedLaunch &&
        (((request->flags &
              KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) ||
         ((runtime->featureFlags &
              KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL))) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Clear the previous launch's per-CPU evidence before selecting a target. */
    for (index = 0UL; index < runtime->processorCount; ++index) {
        runtime->processors[index].row.stateFlags &=
            ~(KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED |
              KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED |
              KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED);
        runtime->processors[index].row.lastExitReason =
            KSWORD_ARK_HVM_EXIT_REASON_NONE;
    }
    /* Select the first processor whose VMXON/VMXOFF self-test succeeded. */
    for (index = 0UL; index < runtime->processorCount; ++index) {
        if ((runtime->processors[index].row.stateFlags &
                KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED) != 0UL) {
            cpu = &runtime->processors[index];
            break;
        }
    }
    /* Refuse VM entry when no processor retained a passing self-test. */
    if (cpu == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Copy the exact processor identity into the launch contract. */
    launchInput.processorGroup = cpu->row.processorGroup;
    /* Copy the group-relative processor number into the launch contract. */
    launchInput.processorNumber = cpu->row.processorNumber;
    /* Publish whether the launch is intentionally nested. */
    launchInput.nestedLaunch = nestedLaunch ? 1U : 0U;
    /* Reference the processor-owned VMXON physical page. */
    launchInput.vmxonPhysical = cpu->vmxonPhysical;
    /* Reference the processor-owned VMCS physical page. */
    launchInput.vmcsPhysical = cpu->vmcsPhysical;
    /* Copy the VMCS revision/control mode evidence. */
    launchInput.vmxBasic = runtime->vmxBasic;
    /* Copy the CR0 required-one mask. */
    launchInput.cr0Fixed0 = runtime->cr0Fixed0;
    /* Copy the CR0 allowed-one mask. */
    launchInput.cr0Fixed1 = runtime->cr0Fixed1;
    /* Copy the CR4 required-one mask. */
    launchInput.cr4Fixed0 = runtime->cr4Fixed0;
    /* Copy the CR4 allowed-one mask. */
    launchInput.cr4Fixed1 = runtime->cr4Fixed1;
    /* Reference the prepared RAM identity-map EPT pointer. */
    launchInput.eptPointer = runtime->eptPointer;
    /* Share the runtime-owned transition phase and power epoch. */
    launchInput.runtime = runtime;
    launchInput.expectedPowerTransitionGeneration = powerGeneration;

    /* Replace the previous one-shot state with an observable running state. */
    kswordArkHvmStateClear(
        runtime,
        KSWORD_ARK_HVM_STATE_GUEST_EXITED |
            KSWORD_ARK_HVM_STATE_NESTED_VALIDATED);
    /* Publish guest-running state before entering VMX root. */
    kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_GUEST_RUNNING);
    /* Preserve the selected processor identity for both success and failure. */
    runtime->lastLaunchProcessorGroup = cpu->row.processorGroup;
    /* Preserve the selected group-relative processor number. */
    runtime->lastLaunchProcessorNumber = cpu->row.processorNumber;
    /* Preserve the launch environment as protocol-visible evidence. */
    runtime->lastLaunchWasNested = nestedLaunch ? 1U : 0U;
    /* Execute the bounded guest and wait for its exit continuation. */
    status = kswordArkHvmLaunchControlledGuest(
        &launchInput,
        &launchResult);
    /* Clear transient one-shot guest-running state after the launch returns. */
    kswordArkHvmStateClear(runtime, KSWORD_ARK_HVM_STATE_GUEST_RUNNING);

    /* Preserve the exact final VMX instruction result on the selected CPU. */
    cpu->row.vmxInstructionResult =
        launchResult.vmxInstructionResult;
    /* Preserve the launch status on the selected CPU row. */
    cpu->row.lastStatus = status;
    /* Publish current-VMCS evidence when VMPTRLD completed. */
    if (launchResult.vmcsLoaded != 0U) {
        cpu->row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED;
    }
    /* Publish successful VM-entry evidence only when a host exit occurred. */
    if (launchResult.guestLaunched != 0U) {
        cpu->row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED;
    }
    /* Publish VM-exit dispatch evidence and increment its monotonic counter. */
    if (launchResult.vmExitHandled != 0U) {
        cpu->row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED;
        runtime->vmExitCount += 1ULL;
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_GUEST_EXITED);
        runtime->lastExitReason =
            launchResult.exit.reason &
            KSW_HVM_VMEXIT_REASON_BASIC_MASK;
        cpu->row.lastExitReason =
            runtime->lastExitReason;
    } else {
        runtime->lastExitReason =
            KSWORD_ARK_HVM_EXIT_REASON_NONE;
    }
    /* Preserve exit qualification even when the exit was unexpected. */
    runtime->lastExitQualification =
        launchResult.exit.qualification;
    /* Preserve the guest instruction pointer at the exit boundary. */
    runtime->lastGuestRip = launchResult.exit.guestRip;
    /* Preserve the guest stack pointer at the exit boundary. */
    runtime->lastGuestRsp = launchResult.exit.guestRsp;
    /* Preserve the decoded VM-exit instruction length. */
    runtime->lastExitInstructionLength =
        launchResult.exit.instructionLength;
    /* Prefer launch-time VMfail detail, then retain exit-time diagnostic state. */
    runtime->lastVmInstructionError =
        launchResult.vmInstructionError != 0UL
        ? launchResult.vmInstructionError
        : launchResult.exit.vmInstructionError;
    /* Record that nested VM entry and the expected VMCALL exit both completed. */
    if (NT_SUCCESS(status) && nestedLaunch) {
        kswordArkHvmStateSet(runtime, KSWORD_ARK_HVM_STATE_NESTED_VALIDATED);
    }
    return status;
#else
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_SUPPORTED;
#endif
}

static ULONG
kswordArkHvmControlStatusFromNtStatus(
    _In_ ULONG command,
    _In_ NTSTATUS status
    )
{
    /* Map backend failures to stable UI-facing protocol states. */
    if (NT_SUCCESS(status)) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_OK;
    }
    if (status == STATUS_ALREADY_REGISTERED) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED;
    }
    if (status == STATUS_DEVICE_NOT_READY) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED;
    }
    if (status == STATUS_HV_FEATURE_UNAVAILABLE) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT;
    }
    /*
     * The identity window is too small for this machine's address space.
     *
     * Mapped before the NOT_SUPPORTED case on purpose, and carried by its own
     * NTSTATUS for the same reason: every other refusal on the residency path
     * collapses into UNSUPPORTED_CPU, and this one is the opposite statement -
     * the processor is fine, our window is not.  Falling through to the
     * command catch-all below would be worse still: START_RESIDENT would
     * report RENDEZVOUS_FAILED for something that never reached a rendezvous.
     */
    if (status == STATUS_SECTION_TOO_BIG) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL;
    }
    if (status == STATUS_NOT_SUPPORTED) {
        if (command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED) {
            return
                KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED;
        }
        return KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
    }
    if (status == STATUS_INSUFFICIENT_RESOURCES) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
    }
    if (status == STATUS_NOT_IMPLEMENTED) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION;
    }
    if (status == STATUS_REVISION_MISMATCH) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED;
    }
    if (status == STATUS_POWER_STATE_INVALID) {
        return
            KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED;
    }
    if (status == STATUS_INVALID_DEVICE_STATE) {
        return
            KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED;
    }
    if (command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
        command == KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED;
    }
    if (command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
        status == STATUS_UNEXPECTED_IO_ERROR) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT;
    }
    if (command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED;
    }
    if (command == KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED;
    }
    return KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
}

NTSTATUS
kswordArkHvmInitialize(
    VOID
    )
{
    /* initialize the lock before publishing any observable runtime state. */
    RtlZeroMemory(&gKswordHvm, sizeof(gKswordHvm));
    ExInitializePushLock(&gKswordHvm.lock);
    KeInitializeSpinLock(
        &gKswordHvm.residentTransitionStateLock);
    KeInitializeEvent(
        &gKswordHvm.residentTransitionIdleEvent,
        NotificationEvent,
        TRUE);
    /*
     * Reserve the ring -1 memory window here rather than at first use: the
     * self-map discovery it depends on is cheap once and pointless to retry,
     * and a failed reservation only downgrades the feature to its fallback.
     */
    kswordArkHvmMemoryInitialize();
    /*
     * Reserve the per-processor VM-exit windows immediately after, because
     * they borrow the self-map base the call above discovers.  Reversing the
     * order leaves every window unreserved with no other symptom.
     */
    kswordArkHvmPhysWindowInitializeAll();
    gKswordHvm.initialized = TRUE;
    /*
     * The one place a plain store to StateFlags is correct: this runs before
     * ExRegisterCallback publishes the power callback, so the second writer
     * that forces every other mutation through the interlocked helpers does
     * not exist yet.  It is an assignment, not a bit operation, and there is
     * nothing to lose an update to.
     */
    gKswordHvm.stateFlags = (LONG)KSWORD_ARK_HVM_STATE_INITIALIZED;
    gKswordHvm.generation = 1UL;
    gKswordHvm.lastExitReason =
        KSWORD_ARK_HVM_EXIT_REASON_NONE;
    gKswordHvm.lastLaunchProcessorGroup = 0xFFFFU;
    gKswordHvm.lastLaunchProcessorNumber = 0xFFU;
    gKswordHvm.residentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    gKswordHvm.eptImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    gKswordHvm.nestedImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    gKswordHvm.evmcsImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    gKswordHvm.nestedState =
        KSWORD_ARK_HVM_NESTED_STATE_DISABLED;
    gKswordHvm.evmcsState =
        KSWORD_ARK_HVM_EVMCS_STATE_UNAVAILABLE;
    /* initialize the nonpaged event ring before any control operation. */
    kswordArkHvmEventInitialize();

#if defined(_M_AMD64)
    /* Capability failure disables HVM only; it does not fail driver startup. */
    if (kswordArkHvmReadCapabilities(&gKswordHvm)) {
        /*
         * Keep resident mode unavailable until WdfDriverCreate installs the
         * final unload entry and every lifecycle callback binds successfully.
         * Nonresident VMX and EPT research capabilities remain available.
         */
        gKswordHvm.residentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        /* AMD has no Intel nested/eVMCS subsystem to initialize. */
        if (gKswordHvm.backendId == KSWORD_ARK_HVM_BACKEND_SVM) { return STATUS_SUCCESS; }
        /* Publish EPT capability without claiming a prepared hierarchy. */
        gKswordHvm.eptImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
        /* Publish nested capability without claiming instruction dispatch. */
        gKswordHvm.nestedImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
        /* Publish capability-only nested state. */
        gKswordHvm.nestedState =
            KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY;
        /* Discover TLFS eVMCS capability from synthetic CPUID leaves. */
        kswordArkHvmEvmcsDiscover(&gKswordHvm);
    }
#else
    g_KswordHvm.QueryStatus =
        KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
    g_KswordHvm.LastStatus = STATUS_NOT_SUPPORTED;
#endif
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmEnableResidentLifecycle(
    _In_ PDRIVER_OBJECT driverObject
    )
{
#if defined(_M_AMD64)
    static const ULONGLONG kRequiredFeatures =
        KSWORD_ARK_HVM_FEATURE_INTEL |
        KSWORD_ARK_HVM_FEATURE_VMX |
        KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED |
        KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX |
        KSWORD_ARK_HVM_FEATURE_EPT |
        KSWORD_ARK_HVM_FEATURE_EPT_WB |
        KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
        KSWORD_ARK_HVM_FEATURE_EPT_2MB |
        KSWORD_ARK_HVM_FEATURE_INVEPT |
        KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE;
    UNICODE_STRING callbackName =
        RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    /* AMD and every other non-Intel vendor remain a hard driver-side denial. */
    if (driverObject == NULL || !gKswordHvm.initialized) {
        return STATUS_INVALID_PARAMETER;
    }
    if (gKswordHvm.queryStatus != KSWORD_ARK_HVM_QUERY_STATUS_OK) {
        return gKswordHvm.lastStatus;
    }
    if (gKswordHvm.backendId != KSWORD_ARK_HVM_BACKEND_SVM &&
        (gKswordHvm.featureFlags & kRequiredFeatures) != kRequiredFeatures) {
        gKswordHvm.lastStatus = STATUS_NOT_SUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }
    /*
     * An outer hypervisor is deliberately NOT checked here.  The guards this
     * routine installs - power transitions, processor topology changes and the
     * DriverUnload interlock - protect our own resident state, which needs the
     * same protection whether we run on bare metal or as someone else's guest.
     * Refusing to register them merely made resident mode permanently
     * unavailable inside every virtual machine, which is also every
     * environment where this code can be developed safely.
     *
     * Whether residency may actually start under an outer hypervisor is decided
     * by kswordArkHvmResidentStart, which requires explicit opt-in.
     */
    if (driverObject->DriverUnload == NULL) {
        gKswordHvm.lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Capture the final KMDF unload entry before publishing resident support. */
    gKswordHvm.driverObject = driverObject;
    /*
     * This snapshot is **no longer** the comparison baseline during arming—the KMDF stub will overwrite
     * this slot after DriverEntry returns, so any value captured anywhere in DriverEntry is stale (see
     * the comment in kswordArkHvmArmUnloadGuard). The actual capture happens at the moment of arming.
     * Retain this only as a diagnostic trace from the DriverEntry phase; the disarm operation uses the value written during the arm phase.
     */
    gKswordHvm.originalDriverUnload = driverObject->DriverUnload;
    gKswordHvm.processorChangeRegistration =
        KeRegisterProcessorChangeCallback(
            kswordArkHvmProcessorChangeCallback,
            &gKswordHvm,
            0UL);
    if (gKswordHvm.processorChangeRegistration == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &callbackName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ExCreateCallback(
        &gKswordHvm.powerStateCallbackObject,
        &objectAttributes,
        FALSE,
        TRUE);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }
    gKswordHvm.powerStateCallbackRegistration =
        ExRegisterCallback(
            gKswordHvm.powerStateCallbackObject,
            kswordArkHvmPowerStateCallback,
            &gKswordHvm);
    if (gKswordHvm.powerStateCallbackRegistration == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }

    /* Page overrides also require an exact VMM-process lifetime guard. */
    status = gKswordHvm.backendId == KSWORD_ARK_HVM_BACKEND_VMX
        ? kswordArkHvmNestedPageGuardInitialize() : STATUS_SUCCESS;
    /* Roll back the earlier callback registrations if this guard is unavailable. */
    if (!NT_SUCCESS(status)) { goto Failure; }
    /* Publish resident/EPT controls only after every fail-closed guard exists. */
    gKswordHvm.featureFlags |=
        KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
        KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS |
        KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD |
        KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD |
        KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD |
        KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED;
    /* Only the Intel backend implements EPT rule controls. */
    if (gKswordHvm.backendId == KSWORD_ARK_HVM_BACKEND_VMX) { gKswordHvm.featureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_RULES; }
    gKswordHvm.residentStartAllowed = TRUE;
    gKswordHvm.residentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
    gKswordHvm.lastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;

Failure:
    /* No callback may retain a pointer into an unavailable HVM runtime. */
    kswordArkHvmNestedPageGuardShutdown();
    /* Roll back partial callback ownership before leaving resident disabled. */
    if (gKswordHvm.powerStateCallbackRegistration != NULL) {
        ExUnregisterCallback(
            gKswordHvm.powerStateCallbackRegistration);
        gKswordHvm.powerStateCallbackRegistration = NULL;
    }
    if (gKswordHvm.powerStateCallbackObject != NULL) {
        ObDereferenceObject(gKswordHvm.powerStateCallbackObject);
        gKswordHvm.powerStateCallbackObject = NULL;
    }
    if (gKswordHvm.processorChangeRegistration != NULL) {
        KeDeregisterProcessorChangeCallback(
            gKswordHvm.processorChangeRegistration);
        gKswordHvm.processorChangeRegistration = NULL;
    }
    gKswordHvm.driverObject = NULL;
    gKswordHvm.originalDriverUnload = NULL;
    gKswordHvm.residentStartAllowed = FALSE;
    gKswordHvm.residentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    gKswordHvm.lastStatus = status;
    return status;
#else
    UNREFERENCED_PARAMETER(DriverObject);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
kswordArkHvmUninitialize(
    VOID
    )
{
    PCALLBACK_OBJECT powerCallbackObject = NULL;
    PVOID powerCallbackRegistration = NULL;
    PVOID processorChangeRegistration = NULL;

    /* Unload is serialized against query/control before releasing pages. */
    if (!gKswordHvm.initialized) {
        return;
    }
    /*
     * Close the per-processor windows before the module window they derived
     * from, mirroring the initialization order in reverse.
     */
    kswordArkHvmPhysWindowShutdownAll();
    /* Close the ring -1 window before any other teardown can use it. */
    kswordArkHvmMemoryShutdown();
    /* Drain process notifications before releasing any referenced page owners. */
    kswordArkHvmNestedPageGuardShutdown();
    /* Block new residency before draining either lifecycle callback. */
    gKswordHvm.residentStartAllowed = FALSE;
    InterlockedExchange(
        &gKswordHvm.powerTransitionPending,
        1L);
    powerCallbackRegistration =
        gKswordHvm.powerStateCallbackRegistration;
    powerCallbackObject =
        gKswordHvm.powerStateCallbackObject;
    processorChangeRegistration =
        gKswordHvm.processorChangeRegistration;
    gKswordHvm.powerStateCallbackRegistration = NULL;
    gKswordHvm.powerStateCallbackObject = NULL;
    gKswordHvm.processorChangeRegistration = NULL;
    if (powerCallbackRegistration != NULL) {
        ExUnregisterCallback(powerCallbackRegistration);
    }
    if (processorChangeRegistration != NULL) {
        KeDeregisterProcessorChangeCallback(
            processorChangeRegistration);
    }
    KeEnterCriticalRegion();
    kswordArkAcquirePushLockExclusive(&gKswordHvm.lock);
    kswordArkHvmFreeResourcesLocked(&gKswordHvm);
    /* Publish uninitialized only after every resident CPU completed VMXOFF. */
    if (InterlockedCompareExchange(
            &gKswordHvm.residentProcessorCount,
            0L,
            0L) == 0L) {
        NTSTATUS transitionStatus = STATUS_SUCCESS;

        /* Restore the captured KMDF unload entry after complete VMXOFF. */
        transitionStatus =
            kswordArkHvmAcquireResidentTransition(&gKswordHvm);
        if (NT_SUCCESS(transitionStatus)) {
            transitionStatus =
                kswordArkHvmDisarmUnloadGuard(&gKswordHvm);
            kswordArkHvmReleaseResidentTransition(&gKswordHvm);
        }
        if (!NT_SUCCESS(transitionStatus)) {
            kswordArkHvmStateSet(
                &gKswordHvm,
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        }
        /* Publish completed HVM teardown. */
        gKswordHvm.initialized = FALSE;
    } else {
        /* Preserve explicit rollback-required evidence on unsafe unload. */
        kswordArkHvmStateSet(
            &gKswordHvm,
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
        /* Returning would unmap code still executing from resident host state. */
        KeBugCheckEx(
            KSW_HVM_LIFECYCLE_BUGCHECK_CODE,
            (ULONG_PTR)KSW_HVM_UNLOAD_FAILURE_SIGNATURE,
            (ULONG_PTR)gKswordHvm.residentProcessorCount,
            (ULONG_PTR)gKswordHvm.lastStatus,
            (ULONG_PTR)gKswordHvm.stateFlags);
    }
    kswordArkReleasePushLockExclusive(&gKswordHvm.lock);
    KeLeaveCriticalRegion();
    if (powerCallbackObject != NULL) {
        ObDereferenceObject(powerCallbackObject);
    }
    gKswordHvm.driverObject = NULL;
    gKswordHvm.originalDriverUnload = NULL;
}

/* The caller holds the resource lock; CPU writers never contend on a global sum. */
static ULONGLONG kswordArkHvmTotalVmExitCountLocked(VOID)
{
    ULONG index;
    /* One-shot exits are counted separately from the resident per-CPU rows. */
    ULONGLONG count = (ULONGLONG)gKswordHvm.vmExitCount;
    /* The sum is observational, as were the separately queried reason histograms. */
    for (index = 0UL; index < gKswordHvm.processorCount; ++index) {
        /* Aligned x64 reads cannot tear; each resident row has a single writer. */
        count += *(volatile ULONGLONG*)&gKswordHvm.processors[index].row.vmExitCount;
    }
    /* Include every resident dispatch, including early reflected L2 exits. */
    return count;
}

NTSTATUS
kswordArkHvmQuery(
    _Out_ KSWORD_ARK_QUERY_HVM_RESPONSE* response
    )
{
    ULONG index = 0UL;
    ULONG eventCount = 0UL;
    ULONG droppedEventCount = 0UL;
    ULONG overwrittenEventCount = 0UL;
    ULONGLONG publishedEventCount = 0ULL;

    /* A fixed response makes status queries deterministic across UI refreshes. */
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    if (!gKswordHvm.initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Snapshot all state under a shared push lock. */
    KeEnterCriticalRegion();
    kswordArkAcquirePushLockShared(&gKswordHvm.lock);
    response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->queryStatus = gKswordHvm.busy
        ? KSWORD_ARK_HVM_QUERY_STATUS_BUSY
        : gKswordHvm.queryStatus;
    response->stateFlags = gKswordHvm.stateFlags |
        (gKswordHvm.busy ? KSWORD_ARK_HVM_STATE_BUSY : 0UL);
    response->generation = gKswordHvm.generation;
    response->processorCount = gKswordHvm.processorCount;
    response->preparedProcessorCount =
        gKswordHvm.preparedProcessorCount;
    response->selfTestPassedProcessorCount =
        gKswordHvm.selfTestPassedProcessorCount;
    response->residentProcessorCount =
        (ULONG)InterlockedCompareExchange(
            &gKswordHvm.residentProcessorCount,
            0L,
            0L);
    response->residentImplementation =
        gKswordHvm.residentImplementation;
    response->eptImplementation =
        gKswordHvm.eptImplementation;
    response->nestedImplementation =
        gKswordHvm.nestedImplementation;
    response->evmcsImplementation =
        gKswordHvm.evmcsImplementation;
    /*
     * Ask the window module rather than keep a cached count.
     *
     * The windows are reserved at driver initialization and released at
     * unload, so a cached copy could only ever be wrong in one direction -
     * stale-high after a release - and that is precisely the direction that
     * makes a missing window look present.
     */
    response->physWindowReadyCount =
        kswordArkHvmPhysWindowReadyCount();
    response->eptRuleCount =
        gKswordHvm.eptRuleCount;
    kswordArkHvmEventGetCounts(
        &eventCount,
        &droppedEventCount,
        &overwrittenEventCount,
        &publishedEventCount);
    response->eventCount = eventCount;
    response->droppedEventCount =
        droppedEventCount;
    response->overwrittenEventCount =
        overwrittenEventCount;
    response->publishedEventCount =
        publishedEventCount;
    response->nestedState =
        gKswordHvm.nestedState;
    /*
     * Publish the durable refusal count alongside the transient state.  The
     * state answers "what is happening right now"; this answers "did it ever
     * happen", and only the second one survives the VMXOFF that follows a
     * refused launch.
     */
    response->nestedL2LaunchRefusedCount =
        (ULONG)InterlockedCompareExchange(
            (volatile LONG*)&gKswordHvm.nestedL2LaunchRefusedCount,
            0L,
            0L);
    /* Report which refusal produced the most recent one of those. */
    response->nestedLastRefusalSite = (unsigned short)
        InterlockedCompareExchange(
            &gKswordHvm.nestedLastRefusalSite,
            0L,
            0L);
    /*
     * Same shape, and durable for the same reason: the per-processor vmcs12
     * pools are released at devirtualization, so an eviction that happened
     * during a residency would otherwise leave no trace at all.
     */
    response->nestedVmcs12EvictionCount =
        (ULONG)InterlockedCompareExchange(
            (volatile LONG*)&gKswordHvm.nestedVmcs12EvictionCount,
            0L,
            0L);
    /*
     * And the fuse.  A real L1 does not run our probe, so this is the only
     * place "we had to stop somebody's guest" is readable at all.
     */
    response->nestedFuseTripCount =
        (ULONG)InterlockedCompareExchange(
            (volatile LONG*)&gKswordHvm.nestedFuseTripCount,
            0L,
            0L);
    response->evmcsState =
        gKswordHvm.evmcsState;
    response->evmcsVersion =
        gKswordHvm.evmcsVersion;
    response->evmcsFlags =
        gKswordHvm.evmcsFlags;
    response->evmcsVpAssistMsr =
        gKswordHvm.evmcsVpAssistMsr;
    response->eptPageCount = gKswordHvm.eptPageCount;
    response->eptPml4Entries = gKswordHvm.eptPml4Entries;
    response->eptPdptEntries = gKswordHvm.eptPdptEntries;
    response->eptLargePageEntries =
        gKswordHvm.eptLargePageEntries;
    response->featureFlags = gKswordHvm.featureFlags;
    response->vmxBasic = gKswordHvm.vmxBasic;
    response->vmxEptVpidCapabilities =
        gKswordHvm.vmxEptVpidCapabilities;
    response->featureControl = gKswordHvm.featureControl;
    response->cr0Fixed0 = gKswordHvm.cr0Fixed0;
    response->cr0Fixed1 = gKswordHvm.cr0Fixed1;
    response->cr4Fixed0 = gKswordHvm.cr4Fixed0;
    response->cr4Fixed1 = gKswordHvm.cr4Fixed1;
    response->eptPointer = gKswordHvm.eptPointer;
    response->mappedRamBytes = gKswordHvm.mappedRamBytes;
    response->highestMappedPhysicalAddress =
        gKswordHvm.highestMappedPhysicalAddress;
    response->vmExitCount = kswordArkHvmTotalVmExitCountLocked();
    response->lastExitQualification =
        gKswordHvm.lastExitQualification;
    response->lastGuestRip = gKswordHvm.lastGuestRip;
    response->lastGuestRsp = gKswordHvm.lastGuestRsp;
    response->lastExitReason = gKswordHvm.lastExitReason;
    response->lastExitInstructionLength =
        gKswordHvm.lastExitInstructionLength;
    response->lastVmInstructionError =
        gKswordHvm.lastVmInstructionError;
    response->lastLaunchProcessorGroup =
        gKswordHvm.lastLaunchProcessorGroup;
    response->lastLaunchProcessorNumber =
        gKswordHvm.lastLaunchProcessorNumber;
    response->lastLaunchWasNested =
        gKswordHvm.lastLaunchWasNested;
    response->lastStatus = gKswordHvm.lastStatus;
    kswordArkHvmCopyAscii(
        response->cpuVendor,
        RTL_NUMBER_OF(response->cpuVendor),
        gKswordHvm.cpuVendor,
        RTL_NUMBER_OF(gKswordHvm.cpuVendor));
    kswordArkHvmCopyAscii(
        response->hypervisorVendor,
        RTL_NUMBER_OF(response->hypervisorVendor),
        gKswordHvm.hypervisorVendor,
        RTL_NUMBER_OF(gKswordHvm.hypervisorVendor));
    /* Publish the controls actually enforced, next to what allowed them. */
    response->activePinControls = gKswordHvm.activeControls.pin;
    response->activePrimaryControls = gKswordHvm.activeControls.primary;
    response->activeSecondaryControls = gKswordHvm.activeControls.secondary;
    response->activeExitControls = gKswordHvm.activeControls.exit;
    response->activeEntryControls = gKswordHvm.activeControls.entry;
    response->pinCapability = gKswordHvm.activeControls.pinCapability;
    response->primaryCapability = gKswordHvm.activeControls.primaryCapability;
    response->secondaryCapability =
        gKswordHvm.activeControls.secondaryCapability;
    response->exitCapability = gKswordHvm.activeControls.exitCapability;
    response->entryCapability = gKswordHvm.activeControls.entryCapability;
    for (index = 0UL;
         index < gKswordHvm.processorCount &&
            index < KSWORD_ARK_HVM_MAX_PROCESSORS;
         ++index) {
        ULONG slot = 0UL;

        response->processors[index] =
            gKswordHvm.processors[index].row;
        /* Legacy Intel rows keep their architecture decoder explicit. */
        response->processors[index].backend = gKswordHvm.backendId;
        /*
         * Sum the per-processor exit histogram into the reported aggregate.
         *
         * Summed here rather than reported per processor because the
         * per-processor form would repeat a 96-entry array 256 times in every
         * response.  Widened to 64 bits on the way in, so the total does not
         * add a wrap of its own to whatever the 32-bit columns already did.
         */
        for (slot = 0UL;
             slot < KSWORD_ARK_HVM_EXIT_REASON_SLOTS;
             ++slot) {
            response->exitReasonCount[slot] +=
                (unsigned long long)
                    gKswordHvm.processors[index].exitReasonCount[slot];
        }
    }
    kswordHvmBackendQuery(&gKswordHvm, response);
    kswordArkReleasePushLockShared(&gKswordHvm.lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

/*
 * Hold residency for a bounded window and report whether it survived.  Entering
 * and leaving VMX non-root once only proves the transition works; a soak is the
 * evidence that the dispatcher completes the exits ordinary system activity
 * generates instead of failing closed into devirtualization.
 */
static NTSTATUS
kswordArkHvmSoakLocked(
    _Inout_ KswHvmRuntime* runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* request,
    _Inout_ KSWORD_ARK_CONTROL_HVM_RESPONSE* response
    )
{
    LARGE_INTEGER interval = { 0 };
    ULONG requested = request->soakMilliseconds;
    ULONG elapsed = 0UL;
    LONG expectedResident = 0L;
    LONG observedResident = 0L;
    LONG lowestResident = 0L;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS stopStatus = STATUS_SUCCESS;

    /* Clamp the window so a malformed request cannot hold VMX indefinitely. */
    if (requested < KSWORD_ARK_HVM_SOAK_MIN_MILLISECONDS) {
        requested = KSWORD_ARK_HVM_SOAK_MIN_MILLISECONDS;
    }
    if (requested > KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS) {
        requested = KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS;
    }
    /* Publish the measurement depth before the flag that consumes it. */
    kswordArkHvmSetVmreadBenchIterations(
        runtime,
        request->vmreadBenchIterations);
    /* Enter resident VMX through the same all-processor rendezvous as START. */
    status = kswordArkHvmResidentStart(
        runtime,
        request->flags);
    /* Leave every soak counter at zero when residency never started. */
    if (!NT_SUCCESS(status)) {
        /* Return the exact rendezvous failure without publishing evidence. */
        return status;
    }
    /* Every prepared processor must stay resident for the whole window. */
    expectedResident = (LONG)runtime->processorCount;
    /* Track the worst residency observed rather than only the final value. */
    lowestResident = expectedResident;
    /* Sample on a fixed slice instead of one uninterruptible long wait. */
    interval.QuadPart =
        -((LONGLONG)KSW_HVM_SOAK_SLICE_MILLISECONDS * 10000LL);
    while (elapsed < requested) {
        /* Wait exactly one slice without allowing an alert to shorten it. */
        KeDelayExecutionThread(
            KernelMode,
            FALSE,
            &interval);
        /* Account the slice that just completed. */
        elapsed += KSW_HVM_SOAK_SLICE_MILLISECONDS;
        /* Read how many processors still run in VMX non-root. */
        observedResident = InterlockedCompareExchange(
            &runtime->residentProcessorCount,
            0L,
            0L);
        /* Preserve the lowest residency seen anywhere in the window. */
        if (observedResident < lowestResident) {
            lowestResident = observedResident;
        }
        /* Stop early once residency collapsed on every processor. */
        if (observedResident == 0L) {
            break;
        }
    }
    /* Leave resident VMX through the all-processor rollback path. */
    stopStatus = kswordArkHvmResidentStop(runtime);
    /* Publish the window that actually elapsed. */
    response->soakElapsedMilliseconds = elapsed;
    /* Publish how many processors left VMX non-root without being asked. */
    response->soakUnexpectedDevirtualizations =
        (ULONG)(expectedResident - lowestResident);
    /* A soak that lost any processor did not prove sustained residency. */
    if (response->soakUnexpectedDevirtualizations != 0UL) {
        /* Preserve a stop failure, otherwise report the residency failure. */
        return NT_SUCCESS(stopStatus)
            ? STATUS_HV_OPERATION_FAILED
            : stopStatus;
    }
    /* Publish sustained residency only after one complete clean window. */
    runtime->featureFlags |=
        KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED;
    /* Return the authoritative stop status for a clean soak. */
    return stopStatus;
}

NTSTATUS
kswordArkHvmControl(
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* request,
    _Out_ KSWORD_ARK_CONTROL_HVM_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS deferredResumeStatus = STATUS_SUCCESS;
    ULONG oldStateFlags = 0UL;
    ULONG oldGeneration = 0UL;
    ULONG eventCount = 0UL;
    ULONG droppedEventCount = 0UL;
    ULONG overwrittenEventCount = 0UL;
    ULONGLONG publishedEventCount = 0ULL;
    ULONG allowedFlags = 0UL;

    /* Validate the complete versioned request before acquiring the state lock. */
    if (request == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(response, sizeof(*response));
    response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    /* Reject old wire layouts before interpreting command-specific fields. */
    if (request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION) { return STATUS_REVISION_MISMATCH; }
    /* Select the exact flag vocabulary accepted by this command. */
    switch (request->command) {
    case KSWORD_ARK_HVM_CONTROL_PREPARE:
        /*
         * Prepare may opt in to an already exposed nested host, and it is
         * where a split-view backend has to be selected: both backends decide
         * what the EPT hierarchies look like, and those are built here.
         *
         * ENABLE_EPTP_SWITCH and ENABLE_LOCAL_EPT are both admitted for exactly
         * that reason: this prepare path *reads* both of them when it decides
         * what to build.
         *
         * ENABLE_LOCAL_EPT was the standing defect this comment used to
         * describe: it was read here but was never in this whitelist, so every
         * request carrying it died as INVALID_REQUEST before arming could
         * happen, and LocalEptArmed was unreachable through the protocol.  The
         * damage was not that the feature was off - it was that the UI offered
         * a switch for it, sent it on START_RESIDENT (where the whitelist does
         * accept it), and the driver then refused at the LocalEptArmed check
         * with STATUS_NOT_SUPPORTED, surfacing as UNSUPPORTED_CPU.  A user who
         * ticked that box was told their CPU could not do this, permanently and
         * across sessions, by a machine that could.
         *
         * Admitting it weakens nothing.  The assignment below still clears it
         * when INVEPT_SINGLE or MONITOR_TRAP_FLAG is missing, and the
         * EPTP_SWITCH/LOCAL_EPT/VMFUNC exclusion above still rejects the
         * conflicting combinations before a single page is allocated.
         */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT |
            KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE;
        /* Stop after selecting the prepare flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_SELF_TEST:
        /* Self-test additionally requires the explicit force bit. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE;
        /* Stop after selecting the self-test flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_TEARDOWN:
    case KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT:
        /* Teardown and stop accept no feature-enabling side flags. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
        /* Stop after selecting the stop flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST:
        /* One-shot launch requires its semantic marker and optional nesting. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST;
        /* Stop after selecting the one-shot flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_START_RESIDENT:
        /*
         * Resident start accepts event and partial nested-dispatch selection,
         * plus ALLOW_NESTED, which is the explicit opt-in for running as L1
         * underneath another hypervisor.
         */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
            /*
             * These three were missing, which made the entire #VE / VMFUNC /
             * per-processor-EPT feature set unreachable through the protocol:
             * kswordArkHvmResidentStart reads all three and gates each one
             * against its capability, but the request never got that far - it
             * was rejected here as INVALID_REQUEST, an answer that says nothing
             * about why.  The Qt client sends all three, so starting residency
             * from the UI could not work at all while the command line could.
             *
             * Admitting them does not weaken anything: every one is refused
             * downstream with STATUS_NOT_SUPPORTED when its capability is
             * absent, and the mutually exclusive combinations are refused too.
             * The only change is that the refusal now names the reason.
             */
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT |
            /*
             * Measurement load.  Enables no feature and changes no exit's
             * semantics; it only makes every exit do extra discarded VMREADs so
             * their cost shows up as reduced throughput.
             */
            KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH |
            /*
             * Diagnostic retention choice.  Enables no feature and changes no
             * exit's semantics; it only decides whether routine exits occupy
             * ring slots that the four evidence classes would otherwise hold.
             */
            KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS |
            /*
             * Identity choice, not a capability.  Narrows what guest user mode
             * learns from CPUID about the hypervisor underneath; every other
             * exit keeps its exact semantics.
             */
            KSWORD_ARK_HVM_CONTROL_FLAG_HIDE_HYPERVISOR |
            /* Keep the full-read reference available without rebuilding a driver. */
            KSWORD_ARK_HVM_CONTROL_FLAG_FULL_EXIT_SNAPSHOT;
        /* Stop after selecting the resident-start flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_SOAK:
        /* A soak is a bounded resident start, so it accepts the same flags. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
            KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS;
        /* Stop after selecting the soak flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED:
        /* Validation accepts only explicit nested/eVMCS discovery selectors. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS;
        /* Stop after selecting the validation flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_RESET_FAULT:
        /* Fault reset accepts confirmation and force only. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE;
        /* Stop after selecting the reset flag set. */
        break;
    default:
        /* Leave the mask empty so the existing command check rejects it. */
        allowedFlags = 0UL;
        /* Stop after selecting the invalid-command sentinel. */
        break;
    }
    if (request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        (request->command != KSWORD_ARK_HVM_CONTROL_SOAK &&
            request->soakMilliseconds != 0UL) ||
        /*
         * Same rule as soakMilliseconds: a field is allowed to be non-zero only for requests that explicitly declare it.
         * This field was previously reserved and required to be 0; now it carries the measurement depth, so the 'must
         * be 0' constraint narrows to 'must be 0 when no measurement is requested', while other cases remain rejected.
         */
        ((request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH) == 0UL &&
            request->vmreadBenchIterations != 0UL) ||
        (request->flags & ~allowedFlags) != 0UL ||
        request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        (request->command != KSWORD_ARK_HVM_CONTROL_PREPARE &&
         request->command != KSWORD_ARK_HVM_CONTROL_SELF_TEST &&
         request->command != KSWORD_ARK_HVM_CONTROL_TEARDOWN &&
         request->command !=
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
         request->command !=
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT &&
         request->command !=
            KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT &&
         request->command !=
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED &&
         request->command !=
            KSWORD_ARK_HVM_CONTROL_SOAK &&
         request->command !=
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT)) {
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    /*
     * The two split-view backends describe the same leaf in incompatible
     * ways, so a request may not select both.
     *
     * Per-processor hierarchies exist to bound a leaf *write* to one
     * processor; EPTP switching never writes a leaf at run time, and its
     * hierarchy index means something different on every processor already.
     * Composing them is not merely redundant - the composite has no defined
     * meaning, and the failure mode of guessing one would be a silent
     * whole-machine hang rather than an error.
     *
     * Refused here, before any allocation, so the caller gets a reason
     * instead of a half-built runtime.
     */
    if ((request->flags & KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE) &&
        gKswordHvm.backendId != KSWORD_ARK_HVM_BACKEND_SVM) {
        /* Never reinterpret the AMD test flag as an Intel preparation option. */
        response->status = KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
        /* Return the precise unsupported backend selection without executing hardware. */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Keep semantic failures available in the normal protocol response. */
        return STATUS_SUCCESS;
    }
    if ((request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH) != 0UL &&
        (request->flags &
            (KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT |
             KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC)) != 0UL) {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        /* Publish the authoritative flag-contract failure. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    /* Require one explicit partial subsystem selector for validation. */
    if (request->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED &&
        (request->flags &
            (KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
             KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS)) == 0UL) {
        /* Publish the stable invalid-request protocol status. */
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        /* Publish the authoritative flag-contract failure. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    if ((request->command == KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
         request->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST ||
         request->command ==
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
         request->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED ||
         request->command ==
            KSWORD_ARK_HVM_CONTROL_SOAK ||
         request->command ==
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT) &&
        (request->flags & KSWORD_ARK_HVM_CONTROL_FLAG_FORCE) == 0UL) {
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
        response->lastStatus = STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }
    if (request->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
        (request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST) == 0UL) {
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!gKswordHvm.initialized) {
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
        response->lastStatus = STATUS_DEVICE_NOT_READY;
        return STATUS_SUCCESS;
    }

    /* Serialize all lifecycle changes and honor generation-bound requests. */
    KeEnterCriticalRegion();
    kswordArkAcquirePushLockExclusive(&gKswordHvm.lock);
    oldStateFlags = gKswordHvm.stateFlags;
    oldGeneration = gKswordHvm.generation;
    if (gKswordHvm.busy) {
        status = STATUS_DEVICE_BUSY;
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_BUSY;
        goto Complete;
    }
    if (request->expectedGeneration != 0UL &&
        request->expectedGeneration != gKswordHvm.generation) {
        status = STATUS_REVISION_MISMATCH;
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED;
        goto Complete;
    }
    if (gKswordHvm.queryStatus != KSWORD_ARK_HVM_QUERY_STATUS_OK) {
        status = gKswordHvm.lastStatus;
        response->status =
            gKswordHvm.queryStatus ==
                KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED
            ? KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED
            : KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
        goto Complete;
    }
    /* Keep all new HVM work closed until the S0 transition fully drains. */
    if (InterlockedCompareExchange(
            &gKswordHvm.powerTransitionPending,
            0L,
            0L) != 0L &&
        request->command != KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT) {
        status = STATUS_POWER_STATE_INVALID;
        response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED;
        goto Complete;
    }

    /* AMD rejects unimplemented Intel/research commands before any mutation. */
    if (kswordHvmBackend(gKswordHvm.backendId) != NULL) {
        /* Cleanup must remain available without a fresh outer-VMM entry opt-in. */
        status = STATUS_SUCCESS;
        /* Only commands acquiring hardware ownership need start policy. */
        if (request->command == KSWORD_ARK_HVM_CONTROL_PREPARE ||
            request->command == KSWORD_ARK_HVM_CONTROL_SELF_TEST || request->command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT) {
            /* Reject unsupported environment/options before allocation or entry. */
            status = kswordHvmBackend(gKswordHvm.backendId)->validateStartFlags(&gKswordHvm, request->flags);
        }
        if (NT_SUCCESS(status) && request->command != KSWORD_ARK_HVM_CONTROL_PREPARE &&
            request->command != KSWORD_ARK_HVM_CONTROL_SELF_TEST && request->command != KSWORD_ARK_HVM_CONTROL_START_RESIDENT &&
            request->command != KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT && request->command != KSWORD_ARK_HVM_CONTROL_TEARDOWN &&
            request->command != KSWORD_ARK_HVM_CONTROL_RESET_FAULT) { status = STATUS_NOT_SUPPORTED; }
        /* FORCE is never a substitute for an implemented backend capability. */
        if (!NT_SUCCESS(status)) { response->status = KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST; goto Complete; }
    }
    /* Publish busy state while the selected lifecycle command executes. */
    gKswordHvm.busy = TRUE;
    kswordArkHvmStateSet(&gKswordHvm, KSWORD_ARK_HVM_STATE_BUSY);
    if (request->command == KSWORD_ARK_HVM_CONTROL_PREPARE) {
        /* Measure preparation separately from resident insertion. */
        kswordArkHvmMetricsBegin(request->command);
        status = kswordArkHvmPrepareLocked(
            &gKswordHvm,
            request);
        /* Preserve both successful and failed preparation intervals. */
        kswordArkHvmMetricsEnd(status);
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        status = kswordArkHvmSelfTestLocked(
            &gKswordHvm,
            request);
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
        status = kswordArkHvmLaunchGuestLocked(
            &gKswordHvm,
            request);
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_START_RESIDENT) {
        /* Publish the measurement depth before the flag that consumes it. */
        kswordArkHvmSetVmreadBenchIterations(
            &gKswordHvm,
            request->vmreadBenchIterations);
        /* Enter resident VMX only through the all-processor rendezvous. */
        kswordArkHvmMetricsBegin(request->command);
        status = kswordArkHvmResidentStart(
            &gKswordHvm,
            request->flags);
        /* Finalize after complete startup or its rollback. */
        kswordArkHvmMetricsEnd(status);
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT) {
        /* Leave resident VMX through the all-processor rollback path. */
        kswordArkHvmMetricsBegin(request->command);
        status = kswordArkHvmResidentStop(
            &gKswordHvm);
        /* Preserve timing after the per-CPU contexts have been released. */
        kswordArkHvmMetricsEnd(status);
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_SOAK) {
        /* Hold residency for a bounded window and report whether it held. */
        status = kswordArkHvmSoakLocked(
            &gKswordHvm,
            request,
            response);
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED) {
        NTSTATUS nestedStatus = STATUS_SUCCESS;
        NTSTATUS evmcsStatus = STATUS_SUCCESS;

        /* Validate nested VMX only when its partial subsystem was selected. */
        if ((request->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX) != 0UL) {
            /* Validate bounded VMX dispatch without claiming L2 active. */
            nestedStatus = kswordArkHvmNestedValidate(
                &gKswordHvm);
        }
        /* Validate TLFS eVMCS only when the caller explicitly requests it. */
        if ((request->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS) != 0UL) {
            /* Evaluate guest-partition eVMCS v1 capability and ownership. */
            evmcsStatus = kswordArkHvmEvmcsValidate(
                &gKswordHvm);
        }
        /* Prefer a hard failure from either selected subsystem. */
        if (!NT_SUCCESS(nestedStatus) &&
            nestedStatus != STATUS_NOT_IMPLEMENTED) {
            status = nestedStatus;
        } else if (!NT_SUCCESS(evmcsStatus) &&
            evmcsStatus != STATUS_NOT_IMPLEMENTED) {
            status = evmcsStatus;
        } else if (nestedStatus == STATUS_NOT_IMPLEMENTED ||
                   evmcsStatus == STATUS_NOT_IMPLEMENTED) {
            /* Preserve explicit partial maturity when no hard failure exists. */
            status = STATUS_NOT_IMPLEMENTED;
        } else {
            /* Both selected capability validations completed successfully. */
            status = STATUS_SUCCESS;
        }
    } else if (request->command ==
        KSWORD_ARK_HVM_CONTROL_RESET_FAULT) {
        /* Refuse fault reset while any processor remains resident. */
        if (InterlockedCompareExchange(
                &gKswordHvm.residentProcessorCount,
                0L,
                0L) != 0L) {
            /* Preserve the exact active-lifecycle conflict. */
            status = STATUS_DEVICE_BUSY;
        } else {
            /* Clear only recoverable fault and rollback evidence. */
            kswordArkHvmStateClear(
                &gKswordHvm,
                KSWORD_ARK_HVM_STATE_FAULTED |
                    KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
            /* Publish successful recoverable fault reset. */
            status = STATUS_SUCCESS;
        }
    } else {
        /* Stop resident VMX and release every reversible resource. */
        kswordArkHvmFreeResourcesLocked(&gKswordHvm);
        /* Report incomplete teardown while any CPU still owns VMX resources. */
        status = InterlockedCompareExchange(
            &gKswordHvm.residentProcessorCount,
            0L,
            0L) == 0L
            ? STATUS_SUCCESS
            : STATUS_HV_OPERATION_FAILED;
    }
    gKswordHvm.busy = FALSE;
    kswordArkHvmStateClear(&gKswordHvm, KSWORD_ARK_HVM_STATE_BUSY);
    /* Finish a resume that waited for this exact control operation to drain. */
    deferredResumeStatus =
        kswordArkHvmAcquireResidentTransition(&gKswordHvm);
    if (NT_SUCCESS(deferredResumeStatus)) {
        deferredResumeStatus =
            kswordArkHvmCompleteDeferredPowerResumeLocked(&gKswordHvm);
        kswordArkHvmReleaseResidentTransition(&gKswordHvm);
    }
    if (!NT_SUCCESS(deferredResumeStatus) &&
        deferredResumeStatus != STATUS_DEVICE_BUSY &&
        NT_SUCCESS(status)) {
        status = deferredResumeStatus;
    }
    gKswordHvm.lastStatus = status;
    if (!NT_SUCCESS(status) &&
        status != STATUS_NOT_IMPLEMENTED &&
        status != STATUS_POWER_STATE_INVALID &&
        status != STATUS_DEVICE_BUSY) {
        kswordArkHvmStateSet(&gKswordHvm, KSWORD_ARK_HVM_STATE_FAULTED);
    } else if (NT_SUCCESS(status)) {
        kswordArkHvmStateClear(&gKswordHvm, KSWORD_ARK_HVM_STATE_FAULTED);
    }
    gKswordHvm.generation += 1UL;
    response->status =
        kswordArkHvmControlStatusFromNtStatus(
            request->command,
            status);

Complete:
    /* Always return a complete before/after lifecycle summary. */
    response->oldStateFlags = oldStateFlags;
    response->newStateFlags = gKswordHvm.stateFlags;
    response->oldGeneration = oldGeneration;
    response->newGeneration = gKswordHvm.generation;
    response->preparedProcessorCount =
        gKswordHvm.preparedProcessorCount;
    response->selfTestPassedProcessorCount =
        gKswordHvm.selfTestPassedProcessorCount;
    response->failedProcessorCount =
        gKswordHvm.processorCount >=
            gKswordHvm.selfTestPassedProcessorCount
        ? gKswordHvm.processorCount -
            gKswordHvm.selfTestPassedProcessorCount
        : 0UL;
    response->residentProcessorCount =
        (ULONG)InterlockedCompareExchange(
            &gKswordHvm.residentProcessorCount,
            0L,
            0L);
    response->residentImplementation =
        gKswordHvm.residentImplementation;
    response->eptImplementation =
        gKswordHvm.eptImplementation;
    response->nestedImplementation =
        gKswordHvm.nestedImplementation;
    response->evmcsImplementation =
        gKswordHvm.evmcsImplementation;
    response->eptRuleCount =
        gKswordHvm.eptRuleCount;
    kswordArkHvmEventGetCounts(
        &eventCount,
        &droppedEventCount,
        &overwrittenEventCount,
        &publishedEventCount);
    response->eventCount = eventCount;
    /* The control response carries only the retained count; loss goes in query. */
    UNREFERENCED_PARAMETER(droppedEventCount);
    UNREFERENCED_PARAMETER(overwrittenEventCount);
    UNREFERENCED_PARAMETER(publishedEventCount);
    response->eptPageCount = gKswordHvm.eptPageCount;
    /*
     * Published on every control call, not only on the refusal that needs it.
     *
     * A field that only carries a value when something went wrong has no
     * occasion on which it can be shown to be right.
     */
    response->eptPml4EntryBudget = KSW_HVM_MAX_PML4_ENTRIES;
    response->eptPointer = gKswordHvm.eptPointer;
    response->mappedRamBytes = gKswordHvm.mappedRamBytes;
    response->vmExitCount = kswordArkHvmTotalVmExitCountLocked();
    response->lastExitQualification =
        gKswordHvm.lastExitQualification;
    response->lastGuestRip = gKswordHvm.lastGuestRip;
    response->lastGuestRsp = gKswordHvm.lastGuestRsp;
    response->lastExitReason = gKswordHvm.lastExitReason;
    response->lastExitInstructionLength =
        gKswordHvm.lastExitInstructionLength;
    response->lastVmInstructionError =
        gKswordHvm.lastVmInstructionError;
    response->launchProcessorGroup =
        gKswordHvm.lastLaunchProcessorGroup;
    response->launchProcessorNumber =
        gKswordHvm.lastLaunchProcessorNumber;
    response->launchWasNested =
        gKswordHvm.lastLaunchWasNested;
    response->lastStatus = status;
    kswordArkReleasePushLockExclusive(&gKswordHvm.lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

/* Architecture MSR numbers, used only in platform probing. */
#define KSW_HVM_IA32_EFER           0xC0000080UL
#define KSW_HVM_IA32_FS_BASE        0xC0000100UL
#define KSW_HVM_IA32_GS_BASE        0xC0000101UL
#define KSW_HVM_IA32_KERNEL_GS_BASE 0xC0000102UL
#define KSW_HVM_IA32_U_CET          0x000006A0UL
#define KSW_HVM_IA32_S_CET          0x000006A2UL

NTSTATUS
kswordArkHvmPlatformProbe(
    _Out_ KSWORD_ARK_HVM_PLATFORM_RESPONSE* response
    )
{
#if defined(_M_AMD64)
    int registers[4] = { 0 };

    /* Reject an incomplete caller contract before touching anything. */
    if (response == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Start from a deterministic response on every path. */
    RtlZeroMemory(response, sizeof(*response));
    /* Publish the response protocol identity. */
    response->version = KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    response->size = sizeof(*response);
    /* Record the sampling IRQL so a caller can confirm this was passive. */
    response->irql = (ULONG)KeGetCurrentIrql();

    /*
     * CR4 and CPUID cannot fault here, but every MSR below can: the CET pair
     * only exists when the processor implements shadow stacks, and reading an
     * unimplemented MSR is #GP.  Each read therefore gets its own guard and
     * its own valid bit - a shared guard would let one missing MSR erase the
     * values that were already read, and a shared valid bit could not say
     * which one was missing.
     */
    response->cr4 = (ULONGLONG)__readcr4();
    response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_CR4;

    __cpuidex(registers, 7, 0);
    response->cpuid7Ecx = (ULONG)registers[2];
    response->cpuid7Edx = (ULONG)registers[3];
    response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_CPUID7;

    __try {
        response->efer = __readmsr(KSW_HVM_IA32_EFER);
        response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_EFER;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->exceptionCode = (ULONG)GetExceptionCode();
    }
    __try {
        response->fsBase = __readmsr(KSW_HVM_IA32_FS_BASE);
        response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_FS_BASE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->exceptionCode = (ULONG)GetExceptionCode();
    }
    __try {
        response->gsBase = __readmsr(KSW_HVM_IA32_GS_BASE);
        response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_GS_BASE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->exceptionCode = (ULONG)GetExceptionCode();
    }
    __try {
        response->kernelGsBase = __readmsr(KSW_HVM_IA32_KERNEL_GS_BASE);
        response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_KERNEL_GS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->exceptionCode = (ULONG)GetExceptionCode();
    }
    __try {
        response->supervisorCet = __readmsr(KSW_HVM_IA32_S_CET);
        response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_S_CET;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->exceptionCode = (ULONG)GetExceptionCode();
    }
    __try {
        response->userCet = __readmsr(KSW_HVM_IA32_U_CET);
        response->validMask |= KSWORD_ARK_HVM_PLATFORM_VALID_U_CET;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->exceptionCode = (ULONG)GetExceptionCode();
    }
    /* Complete the read-only probe successfully. */
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Response);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
#endif
}

NTSTATUS
kswordArkHvmEptRuleControl(
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Validate the complete fixed protocol contract before locking. */
    if (request == NULL ||
        response == NULL ||
        request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        (request->flags &
            ~(KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
              KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
              KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED |
              KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE |
              /*
               * Note: The whitelist must be a superset of the self-use bits.
               *
               * WATCH_ONCE and REARM / WATCH_QUERY were initially added only to the protocol header and the inner ...Locked
               * function, but this outer contract gate was not updated accordingly. Consequently, every watch request is
               * rejected with STATUS_INVALID_PARAMETER before reaching the dispatch logic, causing the user side to only
               * see win32=87. This cannot be caught in offline tests: the gate has no host-side counterpart, so no amount
               * of assertions will reach this line. It only manifests on a real machine during the first call.
               */
              KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE)) != 0UL ||
        (request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_ADD &&
         request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_REMOVE &&
         request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_CLEAR &&
         request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_QUERY &&
         request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_REARM &&
         request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY)) {
        /* Return the exact fixed-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Reading the entire watch table is equivalent to reading a single rule: aside from the protocol header, any field with a value
     * indicates the caller treats it as a different operation; it is better to reject than to read based on an ambiguous request.
     */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY &&
        (request->flags != 0UL ||
         request->confirmationToken != 0UL ||
         request->expectedGeneration != 0UL ||
         request->ruleId != 0UL ||
         request->deniedAccess != 0UL ||
         request->physicalAddress != 0ULL ||
         request->pageCount != 0ULL ||
         request->requestedAddress != 0ULL ||
         request->requestedLength != 0ULL ||
         request->requestedAccess != 0UL ||
         request->addressKind != 0UL)) {
        /* Return the exact operation-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Rearm only locates existing records by ID; its access type, page address, and request scope come from the snapshot
     * stored during installation. If the request includes these fields again, it implies the caller believes they can
     * modify them at this stage—that is a misunderstanding that must be rejected, as changes would have no effect.
     */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_REARM &&
        (request->ruleId == 0UL ||
         request->deniedAccess != 0UL ||
         request->physicalAddress != 0ULL ||
         request->pageCount != 0ULL ||
         request->requestedAddress != 0ULL ||
         request->requestedLength != 0ULL ||
         request->requestedAccess != 0UL ||
         request->addressKind != 0UL ||
         (request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE)) != 0UL)) {
        /* Return the exact re-arm contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reject fields that are meaningless for a read-only rule query. */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_QUERY &&
        (request->flags != 0UL ||
         request->confirmationToken != 0UL ||
         request->expectedGeneration != 0UL ||
         request->deniedAccess != 0UL ||
         request->physicalAddress != 0ULL ||
         request->pageCount != 0ULL ||
         request->requestedAddress != 0ULL ||
         request->requestedLength != 0ULL ||
         request->requestedAccess != 0UL ||
         request->addressKind != 0UL)) {
        /* Return the exact operation-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require a clean identifier-only removal contract. */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_REMOVE &&
        (request->ruleId == 0UL ||
         request->deniedAccess != 0UL ||
         request->physicalAddress != 0ULL ||
         request->pageCount != 0ULL ||
         request->requestedAddress != 0ULL ||
         request->requestedLength != 0ULL ||
         request->requestedAccess != 0UL ||
         request->addressKind != 0UL ||
         (request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE)) != 0UL)) {
        /* Return the exact removal-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require a field-free clear request beyond confirmation metadata. */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_CLEAR &&
        (request->ruleId != 0UL ||
         request->deniedAccess != 0UL ||
         request->physicalAddress != 0ULL ||
         request->pageCount != 0ULL ||
         request->requestedAddress != 0ULL ||
         request->requestedLength != 0ULL ||
         request->requestedAccess != 0UL ||
         request->addressKind != 0UL ||
         (request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE)) != 0UL)) {
        /* Return the exact clear-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require add requests to allocate a new stable rule identifier. */
    if (request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_ADD &&
        request->ruleId != 0UL) {
        /* Return the exact add-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Refuse ENFORCE outright.  Its dispositon injects #PF at the faulting
     * linear address, but the denial lives in EPT and the guest cannot see EPT:
     * its own page tables say the page is fine, so the fault handler repairs
     * nothing, returns, re-executes, faults again.  Measured: the machine
     * livelocks with no bugcheck and no exception ever delivered, so even SEH
     * in the faulting thread cannot break out.
     *
     * "Durable denial" is not reachable by injection while the guest is blind
     * to the mechanism doing the denying - that is what split views are for,
     * and they redirect rather than refuse.  Until this rides on a view,
     * refusing at install is the only disposition that cannot hang a machine.
     */
    if ((request->flags &
            KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE) != 0UL) {
        /* initialize the complete protocol response before refusing. */
        RtlZeroMemory(response, sizeof(*response));
        /* Publish the response protocol identity. */
        response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        /* Publish the complete fixed response size. */
        response->size = sizeof(*response);
        /* Publish the stable unimplemented-disposition status. */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED;
        /* Publish the authoritative refusal. */
        response->lastStatus = STATUS_NOT_IMPLEMENTED;
        /* Return a protocol-level result successfully. */
        return STATUS_SUCCESS;
    }
    /* Reject rule control before runtime initialization. */
    if (!gKswordHvm.initialized) {
        /* Return the explicit lifecycle boundary. */
        return STATUS_DEVICE_NOT_READY;
    }
    /* Serialize rule table, EPT split, and cross-CPU invalidation changes. */
    KeEnterCriticalRegion();
    /* Acquire exclusive lifecycle ownership for the complete rule operation. */
    ExAcquirePushLockExclusive(&gKswordHvm.lock);
    /* Reject concurrent long-running lifecycle mutation. */
    if (gKswordHvm.busy) {
        /* initialize the complete busy protocol response. */
        RtlZeroMemory(response, sizeof(*response));
        /* Publish the response protocol identity. */
        response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        /* Publish the complete fixed response size. */
        response->size = sizeof(*response);
        /* Publish an explicit partial/busy result. */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        /* Publish the authoritative busy NTSTATUS. */
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (request->operation !=
                   KSWORD_ARK_HVM_EPT_RULE_QUERY &&
               /*
                * Reading the watch table has to work WHILE resident - that is
                * the entire window in which a hit can happen.  Excluding it
                * from the freeze would mean a watch could fire and nothing
                * could ever be read back until residency stopped.
                *
                * Safe for the same reason the plain query is: it only reads
                * the rule records, publishes no field, and touches no leaf.
                */
               request->operation !=
                   KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY &&
               InterlockedCompareExchange(
                   &gKswordHvm.residentProcessorCount,
                   0L,
                   0L) != 0L) {
        /*
         * Resident VM exits scan rules without taking this PASSIVE_LEVEL lock.
         * Keep the entire rule table and every split leaf immutable until all
         * VCPUs have committed their guest-stack return.
         */
        RtlZeroMemory(response, sizeof(*response));
        /* Publish the fixed response identity for the fail-closed rejection. */
        response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        response->size = sizeof(*response);
        /*
         * Say what actually happened: the table is frozen for the duration of
         * residency and nothing was attempted.
         *
         * This used to report PARTIAL, whose text is "some processors did not
         * complete the invalidation" - a description of an event that never
         * occurred, pointing whoever reads it at the invalidation machinery
         * instead of at the one action that resolves it: stop residency first.
         */
        response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN;
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* No rule, split entry, generation, or EPT translation was changed. */
        status = STATUS_SUCCESS;
    } else {
        /* Execute the bounded EPT rule operation under lifecycle ownership. */
        status = kswordArkHvmEptRuleControlLocked(
            &gKswordHvm,
            request,
            response);
    }
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&gKswordHvm.lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}

NTSTATUS
kswordArkHvmEventControl(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* response
    )
{
    /* Validate the complete fixed protocol contract. */
    if (request == NULL ||
        response == NULL ||
        request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        request->size != sizeof(*request) ||
        request->flags != 0UL ||
        request->reserved != 0UL ||
        (request->operation !=
            KSWORD_ARK_HVM_EVENT_QUERY_READ &&
         request->operation !=
            KSWORD_ARK_HVM_EVENT_QUERY_CLEAR)) {
        /* Return the exact fixed-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Execute read-only sequence snapshot without lifecycle locking. */
    if (request->operation ==
        KSWORD_ARK_HVM_EVENT_QUERY_READ) {
        /* Return the bounded sequence-validated event batch. */
        return kswordArkHvmEventQuery(
            request,
            response);
    }
    /* Serialize reset against resident lifecycle mutation. */
    KeEnterCriticalRegion();
    /* Acquire exclusive lifecycle ownership for the complete ring reset. */
    ExAcquirePushLockExclusive(&gKswordHvm.lock);
    /* Refuse reset while VM-exit writers can still publish concurrently. */
    if (InterlockedCompareExchange(
            &gKswordHvm.residentProcessorCount,
            0L,
            0L) != 0L) {
        /* Release exclusive lifecycle ownership. */
        ExReleasePushLockExclusive(&gKswordHvm.lock);
        /* Leave the critical region after releasing the push lock. */
        KeLeaveCriticalRegion();
        /* Return the explicit active-writer conflict. */
        return STATUS_DEVICE_BUSY;
    }
    /* Reset the complete stopped event ring. */
    kswordArkHvmEventReset();
    /* Clear protocol-visible retained-event state. */
    kswordArkHvmStateClear(&gKswordHvm, KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE);
    /* initialize the complete empty response. */
    RtlZeroMemory(response, sizeof(*response));
    /* Publish the response protocol identity. */
    response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    response->size = sizeof(*response);
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&gKswordHvm.lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Complete the stopped event reset successfully. */
    return STATUS_SUCCESS;
}

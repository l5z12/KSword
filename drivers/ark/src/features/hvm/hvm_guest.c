/*++

Module Name:

    hvm_guest.c

Abstract:

    Executes a bounded one-shot long-mode guest that immediately issues
    VMCALL, records the resulting VM exit, leaves VMX operation, and restores
    the saved assembly-wrapper continuation on the same logical processor.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_guest.h"
#include "hvm_internal.h"
#include "hvm_descriptor.h"
#include "../../platform/pool_compat.h"

#if defined(_M_AMD64)
#include <intrin.h>

#define KSW_HVM_GUEST_STACK_BYTES 0x4000U
#define KSW_HVM_HOST_STACK_BYTES  0x4000U
#define KSW_HVM_GUEST_POOL_TAG    'gHvK'
#define KSW_HVM_CR4_VMXE          (1ULL << 13)
#define KSW_HVM_VMCS_INSTRUCTION_ERROR 0x4400U
#define KSW_HVM_BUGCHECK_CODE     0x00020001UL
#define KSW_HVM_VMCS_EXIT_CONTROLS 0x400CUL
#define KSW_HVM_VMCS_GUEST_DEBUGCTL 0x2802UL
#define KSW_HVM_VMCS_GUEST_PKRS 0x2818UL
#define KSW_HVM_VMCS_GUEST_DR7 0x681AUL
#define KSW_HVM_VMCS_GUEST_S_CET 0x6828UL
#define KSW_HVM_VMCS_GUEST_SSP 0x682AUL
#define KSW_HVM_VMCS_GUEST_INTERRUPT_SSP_TABLE 0x682CUL
#define KSW_HVM_VMCS_GUEST_UINV 0x0814UL
#define KSW_HVM_EXIT_SAVE_DEBUG_CONTROLS (1UL << 2)
#define KSW_HVM_EXIT_CLEAR_UINV (1UL << 27)
#define KSW_HVM_EXIT_LOAD_CET (1UL << 28)
#define KSW_HVM_EXIT_LOAD_PKRS (1UL << 29)
#define KSW_HVM_IA32_PKRS 0x6E1UL
#define KSW_HVM_IA32_UINTR_MISC 0x988UL

typedef struct KswHvmActiveGuest
{
    ULONGLONG launchStackPointer;
    volatile LONG vmxActive;
    volatile LONG cr4Restored;
    NTSTATUS exitStatus;
    ULONGLONG originalCr4;
    unsigned __int64 vmcsPhysical;
    KswHvmGuestLaunchResult result;
    ULONGLONG guestSCet;
    ULONGLONG guestSsp;
    ULONGLONG guestInterruptSspTable;
    ULONGLONG guestPkrs;
    ULONGLONG guestUinv;
    ULONGLONG guestDebugControl;
    ULONGLONG guestDr7;
    UCHAR cetStateManaged;
    UCHAR pkrsStateManaged;
    UCHAR uinvStateManaged;
    UCHAR debugStateManaged;
    ULONG reserved;
    ULONGLONG originalRflags;
    /* Preserve the caller's exact tables even if VM entry itself fails. */
    KswHvmSegmentSnapshot originalTables;
} KswHvmActiveGuest;

/* Keep the assembly continuation pointer at the documented field-zero offset. */
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, launchStackPointer) == 0);
/* Maintain stability of extended state offsets used by one-time exit assembly. */
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, guestSCet) == 96);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, guestSsp) == 104);
C_ASSERT(FIELD_OFFSET(
    KswHvmActiveGuest,
    guestInterruptSspTable) == 112);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, guestPkrs) == 120);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, guestDebugControl) == 136);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, guestDr7) == 144);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, cetStateManaged) == 152);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, pkrsStateManaged) == 153);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, uinvStateManaged) == 154);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, debugStateManaged) == 155);
C_ASSERT(FIELD_OFFSET(KswHvmActiveGuest, originalRflags) == 160);

static KswHvmActiveGuest* volatile gKswordHvmActiveGuest = NULL;

static KswHvmActiveGuest*
kswordArkHvmReadActiveGuest(
    VOID
    )
{
    /* Read the single active launch pointer with full interlocked ordering. */
    return (KswHvmActiveGuest*)InterlockedCompareExchangePointer(
        (PVOID volatile*)&gKswordHvmActiveGuest,
        NULL,
        NULL);
}

static VOID
kswordArkHvmClearActiveGuest(
    _In_ KswHvmActiveGuest* context
    )
{
    /* Clear only the exact launch context that currently owns VMX root. */
    (void)InterlockedCompareExchangePointer(
        (PVOID volatile*)&gKswordHvmActiveGuest,
        NULL,
        context);
}

PVOID
KswordARKHvmVmExitDispatch(
    VOID
    )
{
    KswHvmActiveGuest* context = NULL;
    NTSTATUS telemetryStatus = STATUS_UNSUCCESSFUL;
    ULONG basicReason = KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    UCHAR vmclearResult = 0xFFU;
    SIZE_T exitControls = 0U;
    SIZE_T value = 0U;

    /* Resolve the launch context before reading the current VMCS. */
    context = kswordArkHvmReadActiveGuest();
    /* A VM exit without an owning launch cannot be resumed safely. */
    if (context == NULL) {
        KeBugCheckEx(
            KSW_HVM_BUGCHECK_CODE,
            (ULONG_PTR)0x48564D01UL,
            0U,
            0U,
            0U);
    }

    /* Capture all protocol-visible exit fields while the VMCS remains current. */
    telemetryStatus = kswordArkHvmReadVmExitTelemetry(
        &context->result.exit);
    /* Derive the Intel basic reason without discarding the raw protocol field. */
    basicReason =
        context->result.exit.reason &
        KSW_HVM_VMEXIT_REASON_BASIC_MASK;
    /* Mark the guest launched because control reached a valid host exit entry. */
    context->result.guestLaunched = 1U;
    /* Mark the exit handled before restoring the launch continuation. */
    context->result.vmExitHandled = 1U;
    /* Select success only for a readable, non-entry-failure VMCALL exit. */
    if (NT_SUCCESS(telemetryStatus) &&
        (context->result.exit.reason &
            KSW_HVM_VMEXIT_REASON_ENTRY_FAILURE) == 0UL &&
        basicReason == KSW_HVM_VMEXIT_REASON_VMCALL) {
        context->exitStatus = STATUS_SUCCESS;
    } else if (!NT_SUCCESS(telemetryStatus)) {
        context->exitStatus = telemetryStatus;
    } else {
        context->exitStatus = STATUS_UNEXPECTED_IO_ERROR;
    }

    /* Save optional guest state written back by hardware to the VMCS before VMCLEAR. */
    if (kswordArkHvmVmcsFieldLoad(
            KSW_HVM_VMCS_EXIT_CONTROLS,
            &exitControls) != 0U) {
        context->exitStatus = STATUS_HV_OPERATION_FAILED;
    } else {
        if ((exitControls & KSW_HVM_EXIT_LOAD_CET) != 0U) {
            if (kswordArkHvmVmcsFieldLoad(
                    KSW_HVM_VMCS_GUEST_S_CET,
                    &value) == 0U) {
                context->guestSCet = (ULONGLONG)value;
                if (kswordArkHvmVmcsFieldLoad(
                        KSW_HVM_VMCS_GUEST_SSP,
                        &value) == 0U) {
                    context->guestSsp = (ULONGLONG)value;
                    if (kswordArkHvmVmcsFieldLoad(
                            KSW_HVM_VMCS_GUEST_INTERRUPT_SSP_TABLE,
                            &value) == 0U) {
                        context->guestInterruptSspTable =
                            (ULONGLONG)value;
                        context->cetStateManaged = 1U;
                    }
                }
            }
            if (context->cetStateManaged == 0U) {
                context->exitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
        if ((exitControls & KSW_HVM_EXIT_LOAD_PKRS) != 0U) {
            if (kswordArkHvmVmcsFieldLoad(KSW_HVM_VMCS_GUEST_PKRS, &value) == 0U) {
                context->guestPkrs = (ULONGLONG)value;
                context->pkrsStateManaged = 1U;
            } else {
                context->exitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
        if ((exitControls & KSW_HVM_EXIT_CLEAR_UINV) != 0U) {
            if (kswordArkHvmVmcsFieldLoad(KSW_HVM_VMCS_GUEST_UINV, &value) == 0U) {
                context->guestUinv = (ULONGLONG)value & 0xFFULL;
                context->uinvStateManaged = 1U;
            } else {
                context->exitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
        if ((exitControls & KSW_HVM_EXIT_SAVE_DEBUG_CONTROLS) != 0U) {
            if (kswordArkHvmVmcsFieldLoad(
                    KSW_HVM_VMCS_GUEST_DEBUGCTL,
                    &value) == 0U) {
                context->guestDebugControl = (ULONGLONG)value;
                if (kswordArkHvmVmcsFieldLoad(
                        KSW_HVM_VMCS_GUEST_DR7,
                        &value) == 0U) {
                    context->guestDr7 = (ULONGLONG)value;
                    context->debugStateManaged = 1U;
                }
            }
            if (context->debugStateManaged == 0U) {
                context->exitStatus = STATUS_HV_OPERATION_FAILED;
            }
        }
    }

    /* Return the current VMCS to clear state before leaving VMX operation. */
    vmclearResult = __vmx_vmclear(&context->vmcsPhysical);
    /* Preserve VMCLEAR failure as a launch failure without hiding exit evidence. */
    if (vmclearResult != 0U &&
        NT_SUCCESS(context->exitStatus)) {
        context->exitStatus = STATUS_HV_OPERATION_FAILED;
        context->result.vmxInstructionResult = vmclearResult;
    }
    /* Leave VMX operation before restoring the original CR4 value. */
    __vmx_off();
    /* VMXOFF retains host table bases and 0xFFFF limits; undo both here. */
    if (!kswordArkHvmRestoreDescriptorTables(
            &context->originalTables, KSW_HVM_DESCRIPTOR_ONESHOT)) {
        /* A native return with unverified tables cannot be allowed. */
        KeBugCheckEx(KSW_HVM_BUGCHECK_CODE, 0x48564D02UL, 0U, 0U, 0U);
    }
    /* Restore non-CET state loaded or cleared by the VM-exit to root mode. */
    if (context->pkrsStateManaged != 0U) {
        __writemsr(KSW_HVM_IA32_PKRS, context->guestPkrs);
    }
    if (context->uinvStateManaged != 0U) {
        ULONGLONG uintrMisc = __readmsr(KSW_HVM_IA32_UINTR_MISC);

        uintrMisc &= ~(0xFFULL << 32);
        uintrMisc |= (context->guestUinv & 0xFFULL) << 32;
        __writemsr(KSW_HVM_IA32_UINTR_MISC, uintrMisc);
    }
    /* Publish that cleanup no longer owns an active VMX root. */
    InterlockedExchange(&context->vmxActive, 0L);
    /* Restore the launcher's exact pre-VMX control-register state. */
    __writecr4(context->originalCr4);
    /* Publish the completed CR4 restoration to the C cleanup path. */
    InterlockedExchange(&context->cr4Restored, 1L);
    /* Remove the global owner before execution resumes on its original stack. */
    kswordArkHvmClearActiveGuest(context);
    /* Return the context whose field zero contains the wrapper stack pointer. */
    return context;
}

NTSTATUS
kswordArkHvmLaunchControlledGuest(
    _In_ const KswHvmGuestLaunchInput* input,
    _Out_ KswHvmGuestLaunchResult* result
    )
{
    KswHvmActiveGuest context = { 0 };
    KswHvmVmcsInput vmcsInput = { 0 };
    GROUP_AFFINITY targetAffinity = { 0 };
    GROUP_AFFINITY oldAffinity = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    PVOID guestStack = NULL;
    PVOID hostStack = NULL;
    ULONGLONG originalCr0 = 0ULL;
    ULONGLONG requiredCr0 = 0ULL;
    ULONGLONG requiredCr4 = 0ULL;
    unsigned __int64 vmxonPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN transitionOwned = FALSE;
    BOOLEAN irqlRaised = FALSE;
    BOOLEAN cr4Changed = FALSE;

    /* Validate the fixed launch contract before allocating nonpaged stacks. */
    if (input == NULL ||
        result == NULL ||
        input->runtime == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Start with deterministic diagnostics even when allocation fails. */
    RtlZeroMemory(result, sizeof(*result));
    /* Use 0xFF to distinguish an instruction that was never attempted. */
    result->vmxInstructionResult = 0xFFU;
    /* Allocate a private non-executable stack for the controlled guest. */
    guestStack = kswordArkAllocateNonPagedPool(
        KSW_HVM_GUEST_STACK_BYTES,
        KSW_HVM_GUEST_POOL_TAG);
    /* Allocate a separate stack used only by the VM-exit entry path. */
    hostStack = kswordArkAllocateNonPagedPool(
        KSW_HVM_HOST_STACK_BYTES,
        KSW_HVM_GUEST_POOL_TAG);
    /* Fail before affinity changes when either bounded stack is unavailable. */
    if (guestStack == NULL || hostStack == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Complete;
    }
    /* Remove stale data from both stacks before VM-entry state references them. */
    RtlZeroMemory(guestStack, KSW_HVM_GUEST_STACK_BYTES);
    /* Remove stale data from the dedicated host-exit stack. */
    RtlZeroMemory(hostStack, KSW_HVM_HOST_STACK_BYTES);

    /* Bind the launch thread to the exact VMX resource-owning processor. */
    targetAffinity.Group = input->processorGroup;
    /* Build the single-processor affinity mask without narrowing. */
    targetAffinity.Mask =
        ((KAFFINITY)1) << input->processorNumber;
    /* Apply the group affinity and retain the caller's original affinity. */
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &oldAffinity);
    /* Record the affinity transition for symmetric cleanup. */
    affinitySet = TRUE;
    /* Own the transition phase without holding its state spin lock over VMX. */
    status = kswordArkHvmAcquireResidentTransition(input->runtime);
    if (!NT_SUCCESS(status)) {
        goto Complete;
    }
    transitionOwned = TRUE;
    /* Prevent thread migration while this CPU temporarily owns VMX root. */
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    irqlRaised = TRUE;

    /* Protect privileged state transitions from virtual-CPU exceptions. */
    __try {
        /* A leaving-S0 callback always wins before any new VMXON. */
        if (InterlockedCompareExchange(
                &input->runtime->powerTransitionPending,
                0L,
                0L) != 0L ||
            InterlockedCompareExchange(
                &input->runtime->powerTransitionGeneration,
                0L,
                0L) != input->expectedPowerTransitionGeneration) {
            status = STATUS_POWER_STATE_INVALID;
            __leave;
        }
        /* Capture CR0 before checking fixed-bit compatibility. */
        originalCr0 = __readcr0();
        /* Capture CR4 for both conflict detection and exact restoration. */
        context.originalCr4 = __readcr4();
        /* Capture Windows state before any VM entry can replace its tables. */
        KswordARKHvmCaptureSegments(&context.originalTables);
        /* Calculate the architecturally required CR0 without changing it. */
        requiredCr0 =
            (originalCr0 | input->cr0Fixed0) &
            input->cr0Fixed1;
        /* Calculate VMX-root CR4 while preserving every active host feature. */
        requiredCr4 =
            ((context.originalCr4 | input->cr4Fixed0) &
                input->cr4Fixed1) |
            KSW_HVM_CR4_VMXE;
        /*
         * Refuse to steal an existing VMX root, alter CR0, or clear an active
         * CR4 feature merely to make the controlled launch pass.
         */
        if ((context.originalCr4 & KSW_HVM_CR4_VMXE) != 0ULL ||
            requiredCr0 != originalCr0 ||
            (requiredCr4 & context.originalCr4) != context.originalCr4) {
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        /* Enable VMX instructions on the selected logical processor. */
        __writecr4(requiredCr4);
        /* Record the CR4 transition for symmetric cleanup. */
        cr4Changed = TRUE;
        /* Copy the VMXON region physical address into intrinsic storage. */
        vmxonPhysical =
            (unsigned __int64)input->vmxonPhysical.QuadPart;
        /* Enter VMX root using the processor-specific VMXON region. */
        vmxResult = __vmx_on(&vmxonPhysical);
        /* Preserve the exact VMX instruction result for UI diagnostics. */
        context.result.vmxInstructionResult = vmxResult;
        /* Stop when VMXON fails validly or invalidly. */
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }
        /* Record active VMX ownership before any later fallible instruction. */
        InterlockedExchange(&context.vmxActive, 1L);
        /* Copy the VMCS physical address for launch and exit cleanup. */
        context.vmcsPhysical =
            (unsigned __int64)input->vmcsPhysical.QuadPart;
        /* Clear the VMCS launch state before making it current. */
        vmxResult = __vmx_vmclear(&context.vmcsPhysical);
        /* Preserve a failed VMCLEAR result. */
        context.result.vmxInstructionResult = vmxResult;
        /* Stop when the VMCS cannot be cleared. */
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }
        /* Load the processor-specific VMCS as current. */
        vmxResult = __vmx_vmptrld(&context.vmcsPhysical);
        /* Preserve a failed VMPTRLD result. */
        context.result.vmxInstructionResult = vmxResult;
        /* Stop when the VMCS cannot be made current. */
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }
        /* Publish current-VMCS evidence to the runtime result. */
        context.result.vmcsLoaded = 1U;

        /* Copy immutable capability and EPT inputs into the VMCS builder. */
        vmcsInput.vmxBasic = input->vmxBasic;
        /* Copy CR0 fixed-zero requirements into the VMCS builder. */
        vmcsInput.cr0Fixed0 = input->cr0Fixed0;
        /* Copy CR0 fixed-one permissions into the VMCS builder. */
        vmcsInput.cr0Fixed1 = input->cr0Fixed1;
        /* Copy CR4 fixed-zero requirements into the VMCS builder. */
        vmcsInput.cr4Fixed0 = input->cr4Fixed0;
        /* Copy CR4 fixed-one permissions into the VMCS builder. */
        vmcsInput.cr4Fixed1 = input->cr4Fixed1;
        /* Reference the prebuilt identity-mapped EPT hierarchy. */
        vmcsInput.eptPointer = input->eptPointer;
        /* Share the same MSR bitmap so one-shot and resident behave alike. */
        vmcsInput.msrBitmapPhysical =
            (ULONGLONG)input->runtime->msrBitmapPhysical.QuadPart;
        /* Align the guest stack top to the x64 ABI boundary. */
        vmcsInput.guestStackPointer =
            ((ULONGLONG)(ULONG_PTR)guestStack +
                KSW_HVM_GUEST_STACK_BYTES) &
            ~0xFULL;
        /* Align the VM-exit stack top before its assembly entry reserves home space. */
        vmcsInput.hostStackPointer =
            ((ULONGLONG)(ULONG_PTR)hostStack +
                KSW_HVM_HOST_STACK_BYTES) &
            ~0xFULL;
        /*
         * The one-shot guest keeps the caller's own address space, and that is
         * not an inconsistency with the resident path - the two have opposite
         * requirements.
         *
         * Residency outlives the process that started it, so HOST_CR3 must name
         * an address space that survives that process; it therefore uses the
         * System one and restores the guest CR3 by hand after VMXOFF.  This
         * guest runs to completion inside one IOCTL on the caller's own thread,
         * and this file never touches CR3 at all - so whatever HOST_CR3 holds
         * is still loaded when VMXOFF returns and the thread walks back out to
         * user mode.  Pointing it at the System space leaves the caller running
         * on an address space whose user half belongs to somebody else: the
         * kernel half matches, so nothing faults until the return to ring 3,
         * and then the process dies with an access violation that looks
         * nothing like a hypervisor bug.  Measured exactly that.
         */
        vmcsInput.hostCr3 = (ULONGLONG)__readcr3();
        /* Enter the fixed assembly stub that immediately executes VMCALL. */
        vmcsInput.guestInstructionPointer =
            (ULONGLONG)(ULONG_PTR)KswordARKHvmControlledGuestEntry;
        /* Route every VM exit through the non-returning assembly entry. */
        vmcsInput.hostInstructionPointer =
            (ULONGLONG)(ULONG_PTR)KswordARKHvmVmExitEntry;
        /* Program the complete VMCS before publishing the active context. */
        status = kswordArkHvmConfigureVmcs(
            &vmcsInput,
            &context.result.vmInstructionError);
        /* Stop when any control or state field is rejected. */
        if (!NT_SUCCESS(status)) {
            __leave;
        }

        /* Claim the single active launch slot before entering the assembly wrapper. */
        if (InterlockedCompareExchangePointer(
                (PVOID volatile*)&gKswordHvmActiveGuest,
                &context,
                NULL) != NULL) {
            status = STATUS_DEVICE_BUSY;
            __leave;
        }
        /* Attempt VM entry while preserving an assembly-level return stack. */
        vmxResult = KswordARKHvmAsmLaunch(&context);
        /* Preserve the wrapper's VM-entry result for protocol diagnostics. */
        context.result.vmxInstructionResult = vmxResult;
        /* A handled VM exit returns through the saved wrapper stack with zero. */
        if (context.result.vmExitHandled != 0U) {
            status = context.exitStatus;
            __leave;
        }

        /* Read VMfailValid detail while the failed VMCS remains current. */
        if (vmxResult == 1U) {
            SIZE_T instructionError = 0U;

            /* Preserve the VM-instruction error when VMREAD succeeds. */
            if (kswordArkHvmVmcsFieldLoad(
                    KSW_HVM_VMCS_INSTRUCTION_ERROR,
                    &instructionError) == 0U) {
                context.result.vmInstructionError =
                    (ULONG)instructionError;
            }
        }
        /* Any direct return from VMLAUNCH is a failed controlled launch. */
        status = STATUS_HV_OPERATION_FAILED;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve the privileged exception as the authoritative failure. */
        status = GetExceptionCode();
    }

    /* Remove a launch slot that failed before the exit dispatcher cleared it. */
    kswordArkHvmClearActiveGuest(&context);
    /* Leave VMX root on every failure path that still owns it. */
    if (InterlockedCompareExchange(
            &context.vmxActive,
            0L,
            0L) != 0L) {
        /* Reset the VMCS launch state before VMXOFF when possible. */
        (void)__vmx_vmclear(&context.vmcsPhysical);
        /* Leave VMX operation before restoring CR4. */
        __vmx_off();
        /* Publish completed VMX cleanup. */
        InterlockedExchange(&context.vmxActive, 0L);
    }
    /* Restore CR4 only after VMX operation has ended. */
    if (cr4Changed &&
        InterlockedCompareExchange(
            &context.cr4Restored,
            0L,
            0L) == 0L) {
        __try {
            /* Restore the exact control-register value captured before VMXON. */
            __writecr4(context.originalCr4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            /* Preserve restoration failure over an earlier result. */
            status = GetExceptionCode();
        }
    }

Complete:
    /* Reopen the power callback only after privileged cleanup is complete. */
    if (transitionOwned) {
        kswordArkHvmReleaseResidentTransition(input->runtime);
    }
    /* Restore the caller's exact IRQL after all VMX state is native again. */
    if (irqlRaised) {
        KeLowerIrql(oldIrql);
    }
    /* Restore the caller's group affinity after returning to passive migration. */
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }
    /* Release the private guest stack after no VMCS references it. */
    if (guestStack != NULL) {
        ExFreePool(guestStack);
    }
    /* Release the private VM-exit stack after the continuation is restored. */
    if (hostStack != NULL) {
        ExFreePool(hostStack);
    }
    /* Publish the authoritative operation status in both channels. */
    context.result.status = status;
    /* Copy the complete result only after all cleanup is finished. */
    *result = context.result;
    return status;
}

#else

NTSTATUS
KswordARKHvmLaunchControlledGuest(
    _In_ const KSW_HVM_GUEST_LAUNCH_INPUT* Input,
    _Out_ KSW_HVM_GUEST_LAUNCH_RESULT* Result
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Input);
    /* Clear a supplied result before returning the architecture boundary. */
    if (Result != NULL) {
        RtlZeroMemory(Result, sizeof(*Result));
        Result->Status = STATUS_NOT_SUPPORTED;
        Result->VmxInstructionResult = 0xFFU;
    }
    return STATUS_NOT_SUPPORTED;
}

PVOID
KswordARKHvmVmExitDispatch(
    VOID
    )
{
    /* The non-x64 project excludes the assembly entry, so this is unreachable. */
    KeBugCheckEx(
        0x00020001UL,
        (ULONG_PTR)0x48564D03UL,
        0U,
        0U,
        0U);
}

#endif

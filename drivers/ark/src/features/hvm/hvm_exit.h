/*++

Module Name:

    hvm_exit.h

Abstract:

    Defines the resident VM-exit register frame and dispatcher contract.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

/* Preserve guest GPRs in the exact order emitted by hvm_entry.asm. */
typedef struct KswHvmGprFrame
{
    /* Preserve guest RAX. */
    ULONGLONG rax;
    /* Preserve guest RCX. */
    ULONGLONG rcx;
    /* Preserve guest RDX. */
    ULONGLONG rdx;
    /* Preserve guest RBX. */
    ULONGLONG rbx;
    /* Preserve guest RBP. */
    ULONGLONG rbp;
    /* Preserve guest RSI. */
    ULONGLONG rsi;
    /* Preserve guest RDI. */
    ULONGLONG rdi;
    /* Preserve guest R8. */
    ULONGLONG r8;
    /* Preserve guest R9. */
    ULONGLONG r9;
    /* Preserve guest R10. */
    ULONGLONG r10;
    /* Preserve guest R11. */
    ULONGLONG r11;
    /* Preserve guest R12. */
    ULONGLONG r12;
    /* Preserve guest R13. */
    ULONGLONG r13;
    /* Preserve guest R14. */
    ULONGLONG r14;
    /* Preserve guest R15. */
    ULONGLONG r15;
} KswHvmGprFrame;

/*
 * KswordARKHvmAsmForwardHypercall indexes this frame with literal byte offsets
 * because it runs after the C dispatcher may have clobbered every scratch
 * register.  A field reordered here would silently hand the outer hypervisor
 * the wrong operands - a class of bug with no diagnostic surface at all, since
 * the forwarded call would simply return a wrong answer.  Lock the four
 * offsets the Hyper-V x64 hypercall ABI actually uses.
 */
C_ASSERT(FIELD_OFFSET(KswHvmGprFrame, rax) == 0x00);
C_ASSERT(FIELD_OFFSET(KswHvmGprFrame, rcx) == 0x08);
C_ASSERT(FIELD_OFFSET(KswHvmGprFrame, rdx) == 0x10);
C_ASSERT(FIELD_OFFSET(KswHvmGprFrame, r8) == 0x38);
/* The assembly entry pushes exactly fifteen registers ahead of the context. */
C_ASSERT(sizeof(KswHvmGprFrame) == 15 * sizeof(ULONGLONG));

/* Forward-declare the per-processor resident context. */
struct KswHvmResidentVcpu;

/* Request VMRESUME after a fully handled exit. */
#define KSW_HVM_EXIT_ACTION_RESUME 0UL
/* Request devirtualization onto the captured guest continuation. */
#define KSW_HVM_EXIT_ACTION_DEVIRTUALIZE 1UL
/* Request a bounded fatal trap when no safe guest continuation exists. */
#define KSW_HVM_EXIT_ACTION_FATAL 2UL

EXTERN_C_START

/* Dispatch one resident VM exit without allocation or waiting. */
ULONG
KswordARKHvmResidentVmExitDispatch(
    _Inout_ KswHvmGprFrame* frame,
    _Inout_ struct KswHvmResidentVcpu* context
    );

/*
 * Re-issue one guest VMCALL from VMX root so the hypervisor above us answers
 * it.  Only legitimate while KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT is set.
 *
 * Returns zero when the call was answered and the frame now holds the result,
 * and one when nothing serviced it - in which case the frame is untouched and
 * the caller must not advance past the instruction.  CPUID advertising a
 * hypervisor is not proof that one answers VMCALL, and handing the guest back
 * its own pre-call RAX as a hypercall status would corrupt the VMBus paths
 * silently rather than stopping.
 */
ULONG
KswordARKHvmAsmForwardHypercall(
    _Inout_ KswHvmGprFrame* frame,
    _Inout_ PVOID fxState
    );

/* Convert VMRESUME failure into a bounded devirtualization continuation. */
ULONG
KswordARKHvmResidentVmResumeFailure(
    _Inout_ struct KswHvmResidentVcpu* context,
    _In_ UCHAR instructionResult
    );

EXTERN_C_END

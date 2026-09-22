/*++

Module Name:

    hvm_exit_emulate.h

Abstract:

    Declares root-mode emulation for the VM exits a resident guest cannot
    avoid, plus the architectural exception injection they depend on.

Environment:

    Kernel-mode Driver Framework, VMX root operation.

--*/

#pragma once

#include "hvm_exit.h"

EXTERN_C_START

/* Arm one hardware exception for the next VM entry without advancing RIP. */
BOOLEAN
kswordArkHvmExitInjectException(
    _In_ ULONG vector,
    _In_ BOOLEAN deliverErrorCode,
    _In_ ULONG errorCode
    );

/* Arm #UD for an instruction this hypervisor deliberately refuses. */
BOOLEAN
kswordArkHvmExitInjectUndefinedOpcode(
    VOID
    );

/* Arm #GP with a zero error code for an architecturally invalid operand. */
BOOLEAN
kswordArkHvmExitInjectGeneralProtection(
    VOID
    );

/*
 * Arm #PF for a durably denied EPT access.  CR2 is not part of the VMCS, so
 * the faulting address is published straight into the shared register.
 */
BOOLEAN
kswordArkHvmExitInjectPageFault(
    _In_ ULONGLONG guestLinearAddress,
    _In_ ULONG access
    );

/* Complete an unconditional INVD exit without discarding modified lines. */
BOOLEAN
kswordArkHvmExitEmulateInvd(
    VOID
    );

/* Validate and apply one guest XSETBV, or request the architectural fault. */
BOOLEAN
kswordArkHvmExitEmulateXsetbv(
    _In_ const KswHvmGprFrame* frame,
    _Out_ BOOLEAN* injectFault
    );

/*
 * Resolve one MSR exit that fell outside the architectural bitmap ranges.
 * HypervisorPresent enables forwarding the reserved 0x40000000-0x4FFFFFFF
 * window to the hypervisor beneath us; every other index still faults.
 */
/*
 * Answer a VMX capability MSR read with what we actually implement.
 *
 * Returns TRUE when the access was fully serviced and the caller should
 * advance RIP.  Returns FALSE for every index outside the capability range,
 * leaving those to the paths that already own them.
 *
 * Deliberately consulted before the policy engine and not overridable by it.
 * A policy that passed one of these through natively would hand a guest the
 * machine's real capabilities, which is the single thing this exists to stop -
 * and it would do so silently, because a pass-through leaves no trace anywhere.
 */
BOOLEAN
kswordArkHvmExitFilterVmxCapabilityMsr(
    _Inout_ KswHvmGprFrame* frame,
    _In_ BOOLEAN isWrite
    );

BOOLEAN
kswordArkHvmExitEmulateMsr(
    _Inout_ KswHvmGprFrame* frame,
    _In_ BOOLEAN isWrite,
    _In_ BOOLEAN hypervisorPresent,
    _Out_ BOOLEAN* injectFault
    );

EXTERN_C_END

#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * The HVM protocol separates capability discovery from implementation state.
 * A capability-only or partial result must never be interpreted as a resident
 * hypervisor.  ACTIVE is published only after every selected processor has
 * entered VMX non-root operation and the rollback rendezvous is available.
 */
#define KSWORD_ARK_HVM_PROTOCOL_VERSION 6UL

/* V6 reports why SVM discovery stopped without interpreting missing values as zero. */
#define KSWORD_ARK_SVM_REJECT_NONE 0UL
#define KSWORD_ARK_SVM_REJECT_CPUID_RANGE 1UL
#define KSWORD_ARK_SVM_REJECT_SVM_NPT_ASID 2UL
#define KSWORD_ARK_SVM_REJECT_NRIP 3UL
#define KSWORD_ARK_SVM_REJECT_MSR_READ 4UL
#define KSWORD_ARK_SVM_REJECT_FIRMWARE 5UL
#define KSWORD_ARK_SVM_REJECT_SVME 6UL
#define KSWORD_ARK_SVM_REJECT_HSAVE 7UL
#define KSWORD_ARK_SVM_REJECT_CR4 8UL
#define KSWORD_ARK_SVM_REJECT_XSAVE 9UL
#define KSWORD_ARK_SVM_REJECT_XSTATE_READ 10UL
#define KSWORD_ARK_SVM_REJECT_XSS 11UL
#define KSWORD_ARK_SVM_REJECT_PHYSICAL_WIDTH 12UL
/* V6 additive reason: no structure size or existing field interpretation changes. */
#define KSWORD_ARK_SVM_REJECT_CET_STATE 13UL
/* Independent validity bits for the extended state observations. */
#define KSWORD_ARK_SVM_VALID_CR4 1UL
#define KSWORD_ARK_SVM_VALID_CPUID1 2UL
#define KSWORD_ARK_SVM_VALID_CPUID_D1 4UL
#define KSWORD_ARK_SVM_VALID_XCR0 8UL
#define KSWORD_ARK_SVM_VALID_XSS 16UL

/* V5 describes architecture independently from capability flags. */
#define KSWORD_ARK_HVM_BACKEND_NONE 0UL
#define KSWORD_ARK_HVM_BACKEND_VMX 1UL
#define KSWORD_ARK_HVM_BACKEND_SVM 2UL
/* Translation type must not mislabel AMD NPT as EPT. */
#define KSWORD_ARK_HVM_SLAT_NONE 0UL
#define KSWORD_ARK_HVM_SLAT_EPT 1UL
#define KSWORD_ARK_HVM_SLAT_NPT 2UL
/* Generic execution stage, independent of VMX instruction result codes. */
#define KSWORD_ARK_HVM_STAGE_NONE 0UL
#define KSWORD_ARK_HVM_STAGE_PREPARED 1UL
#define KSWORD_ARK_HVM_STAGE_TESTED 2UL
#define KSWORD_ARK_HVM_STAGE_ENTERING 3UL
#define KSWORD_ARK_HVM_STAGE_ENTERED 4UL
#define KSWORD_ARK_HVM_STAGE_EXIT 5UL
#define KSWORD_ARK_HVM_STAGE_STOPPED 6UL
#define KSWORD_ARK_HVM_STAGE_FAILED 7UL

/*
 * Discriminator for VMCS configuration failure, carried in the existing lastVmInstructionError field.
 *
 * Rationale: During VMCS programming, there are at least eight distinct return points
 * where START_RESIDENT fails with the exact same symptom — on every processor line,
 * vmxInstructionResult=3 ("never-attempted VM entry" from the assembly wrapper),
 * stateFlags=0x27、lastStatus=STATUS_HV_OPERATION_FAILED、
 * lastVmInstructionError=0. From the protocol perspective, it is impossible to distinguish which one caused it.
 *
 * Pay special attention: lastVmInstructionError=0 **cannot** be used to rule out VMWRITE failures:
 * The value 0 has three sources: not reaching the write path, VMfailInvalid without an error code, and
 * VMfailValid followed by a failed read of VMCS 0x4400 itself. Treating 0 as 'no VMWRITE failure' is incorrect.
 *
 * Encoding (bit 31 is the discriminator flag; when 0, the value remains an architecture VM-instruction error,
 * preserving the old semantics, so this is not a protocol-breaking change and requires no version bump):
 *
 *   bits 31: 1 = KSword discriminator; bits 30-24: site ID
 *   (KSWORD_ARK_HVM_VMCS_DIAG_SITE_*); bits 23-8: detail (VMCS field
 *   encoding / missing capability bitmask / low 16 bits of exception
 *   code); bits 7-0: VM-instruction error (0 if unavailable)
 */
#define KSWORD_ARK_HVM_VMCS_DIAG_FLAG 0x80000000UL

#define KSWORD_ARK_HVM_VMCS_DIAG_MAKE(site, detail, arch)      \
    (KSWORD_ARK_HVM_VMCS_DIAG_FLAG |                           \
     (((unsigned long)(site)   & 0x7FUL)   << 24) |            \
     (((unsigned long)(detail) & 0xFFFFUL) <<  8) |            \
      ((unsigned long)(arch)   & 0xFFUL))

#define KSWORD_ARK_HVM_VMCS_DIAG_IS(v)     (((v) & KSWORD_ARK_HVM_VMCS_DIAG_FLAG) != 0UL)
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE(v)   (((v) >> 24) & 0x7FUL)
#define KSWORD_ARK_HVM_VMCS_DIAG_DETAIL(v) (((v) >>  8) & 0xFFFFUL)
#define KSWORD_ARK_HVM_VMCS_DIAG_ARCH(v)    ((v)        & 0xFFUL)

/* VMWRITE rejected. detail = VMCS field encoding, arch = architecture error code (0 = not retrieved). */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_VMWRITE            1UL
/* Enabled optional CR4 states lack VMCS transfer capability. detail = the STATE_* mask below. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER  2UL
/* Provides MSR bitmap page but primary controls did not acquire USE_MSR_BITMAPS. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_BITMAP         3UL
/* CR3/DR interception requested but corresponding primary control not acquired. detail: 1=TrackCr3 2=InterceptDr. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_CR_POLICY          4UL
/* Required primary/secondary/exit/entry controls are missing. detail = CTL_* mask below. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS  5UL
/* Save and load of debug state are not paired. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_DEBUG_PAIRING      6UL
/* Optional exit/entry controls are not paired. detail = STATE_* bitmask. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING      7UL
/* Required secondary instruction control is missing. detail = bit number of the lowest missing bit (0-31). */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_INSTRUCTION_CTL    8UL
/* An exception is thrown when reading the optional status MSR and is caught locally. detail = lower 16 bits of the exception code. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_EXCEPTION      16UL
/* Throw an exception when reading capability MSRs and catch it locally. detail = lower 16 bits of the exception code. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_CAP_EXCEPTION      17UL
/* The unconditional I/O exit for diagnostics was requested but the capability MSR disallows it; the predicate will silently fail. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_DIAG_IO_EXITING    18UL
/* Note: Host page directory base address is zero; loading it causes a triple fault with no BSOD or dump. */
#define KSWORD_ARK_HVM_VMCS_DIAG_SITE_HOST_CR3           19UL

/* STATE_* masks: which optional processor state had the issue. */
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_CET   0x0001UL
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_PKS   0x0002UL
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_UINTR 0x0004UL
#define KSWORD_ARK_HVM_VMCS_DIAG_STATE_FRED  0x0008UL

/* CTL_* masks: REQUIRED_CONTROLS indicates which specific category is missing at the site. */
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_SECONDARY_ACTIVATE 0x0001UL
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_EPT                0x0002UL
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_HOST_64            0x0004UL
#define KSWORD_ARK_HVM_VMCS_DIAG_CTL_ENTRY_IA32E        0x0008UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM   0x8CAUL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM 0x8CBUL
// 0x8CC-0x8CD are occupied by driver-dispatch and SLAT/IOMMU on main.
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE 0x8B8UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS   0x8B9UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_MEMORY   0x8BAUL

#define IOCTL_KSWORD_ARK_QUERY_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KSWORD_ARK_CONTROL_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EPT_RULE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EVENTS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/*
 * Ring -1 memory access.  Reads are as privileged as writes here because the
 * access path deliberately avoids the documented memory-manager entry points,
 * so the whole interface requires write access rather than only the mutating
 * half of it.
 */
#define IOCTL_KSWORD_ARK_HVM_MEMORY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_MEMORY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_VENDOR_CHARS 16U
#define KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS 16U
#define KSWORD_ARK_HVM_MAX_PROCESSORS 256UL
/*
 * Slots in the per-reason exit histogram.
 *
 * Intel basic exit reasons are a dense small integer space; this is sized past
 * every reason currently defined so that a processor running on newer silicon
 * counts its exits somewhere rather than nowhere.  A reason at or beyond this
 * bound is simply not counted - never folded into a neighbouring slot, which
 * would turn an unknown exit into a plausible-looking one.
 */
#define KSWORD_ARK_HVM_EXIT_REASON_SLOTS 96UL
#define KSWORD_ARK_HVM_MAX_EPT_RULES 128UL
#define KSWORD_ARK_HVM_MAX_EVENT_ROWS 64UL

#define KSWORD_ARK_HVM_FEATURE_INTEL                  0x0000000000000001ULL
#define KSWORD_ARK_HVM_FEATURE_VMX                    0x0000000000000002ULL
#define KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED 0x0000000000000004ULL
#define KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX        0x0000000000000008ULL
#define KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS          0x0000000000000010ULL
#define KSWORD_ARK_HVM_FEATURE_EPT                    0x0000000000000020ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_WB                 0x0000000000000040ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL            0x0000000000000080ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_2MB                0x0000000000000100ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_AD                 0x0000000000000200ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT                 0x0000000000000400ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE          0x0000000000000800ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT_ALL             0x0000000000001000ULL
#define KSWORD_ARK_HVM_FEATURE_VPID                   0x0000000000002000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT     0x0000000000004000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED     0x0000000000008000ULL
#define KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST          0x0000000000010000ULL
#define KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY        0x0000000000020000ULL
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM            0x0000000000040000ULL
#define KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS     0x0000000000080000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT            0x0000000000100000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_RULES                0x0000000000200000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING           0x0000000000400000ULL
#define KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT           0x0000000000800000ULL
#define KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG        0x0000000001000000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH      0x0000000002000000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_ACTIVE        0x0000000004000000ULL
#define KSWORD_ARK_HVM_FEATURE_SHADOW_EPT               0x0000000008000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE     0x0000000010000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1          0x0000000020000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_ACTIVE      0x0000000040000000ULL
#define KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION 0x0000000080000000ULL
#define KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD         0x0000000100000000ULL
#define KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD  0x0000000200000000ULL
#define KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD       0x0000000400000000ULL
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED 0x0000000800000000ULL
/*
 * The MSR bitmap is what makes residency survivable: without it every RDMSR
 * and WRMSR exits unconditionally into a dispatcher that cannot complete them.
 */
#define KSWORD_ARK_HVM_FEATURE_MSR_BITMAP                 0x0000001000000000ULL
/* The dispatcher completes every unconditional exit instead of devirtualizing. */
#define KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION             0x0000002000000000ULL
/* A timed soak proved residency survives ordinary system activity. */
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED         0x0000004000000000ULL
/*
 * AMD capability evidence.  These bits report what the processor can do, not
 * whether the software can start or has actually passed a hardware round trip.
 * Backend status and per-CPU execution evidence carry those separate results.
 */
#define KSWORD_ARK_HVM_FEATURE_AMD                        0x0000008000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM                        0x0000010000000000ULL
#define KSWORD_ARK_HVM_FEATURE_NPT                        0x0000020000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM_NRIP                   0x0000040000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS         0x0000080000000000ULL
#define KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID          0x0000100000000000ULL
/* The firmware disabled SVM through VM_CR.SVMDIS. */
#define KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED      0x0000200000000000ULL
/*
 * Virtualization exception (#VE) support.
 *
 * Reported because the hardware has it, NOT because it is safe to turn on
 * here.  In this product the guest being virtualized is the running Windows
 * itself, and its IDT[20] is KiVirtualizationException - it does not expect a
 * #VE we manufacture.  Worse, the architectural default is inverted: an EPT
 * leaf with bit 63 clear is *convertible*, so enabling the control without
 * first setting suppress-#VE on every leaf reflects ordinary EPT violations
 * into a guest that cannot handle them, which is #GP -> #DF -> triple fault.
 *
 * The driver therefore always sets suppress-#VE on every leaf it builds, and
 * the conversion control itself stays off unless the caller opts in per start.
 */
#define KSWORD_ARK_HVM_FEATURE_EPT_VIOLATION_VE           0x0000400000000000ULL
/* Per-processor virtualization-exception information areas are allocated. */
#define KSWORD_ARK_HVM_FEATURE_VE_INFO_READY              0x0000800000000000ULL
/* Every EPT leaf this build installs carries suppress-#VE. */
#define KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT   0x0001000000000000ULL

/*
 * VM functions (VMFUNC) and EPTP switching.
 *
 * The single most important property of VMFUNC is that it performs NO CPL
 * check.  Any ring-3 code in the guest can execute it and switch the active
 * EPTP to any entry in the list, without a VM exit and without the driver
 * being told.  An EPTP list is therefore not a private hypervisor mechanism -
 * it is an interface published to every thread in the system.
 *
 * The consequence for design: a domain reachable through the list must never
 * grant a permission the default view does not already grant.  Otherwise the
 * list becomes a privilege-escalation primitive that costs an attacker one
 * instruction.  The driver enforces that as an install-time check, and the
 * whole mechanism stays off unless a caller opts in per start.
 */
#define KSWORD_ARK_HVM_FEATURE_VM_FUNCTIONS               0x0002000000000000ULL
/* EPTP switching (VM function 0) is available on this processor. */
#define KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING             0x0004000000000000ULL
/* The EPTP list page is allocated and every unused slot reads as invalid. */
#define KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY            0x0008000000000000ULL

/*
 * Per-processor private EPT hierarchies.
 *
 * Both flip mechanisms in this driver - the allow-once transient grant and
 * the CLOAK/HOOK split view - work by writing one EPT leaf and letting the
 * guest retire a single instruction.  With one shared hierarchy that write is
 * visible to every other processor for the whole window, which is why both
 * features refuse to run unless the topology is exactly one processor.
 *
 * Armed, each processor walks its own copy of the few tables on the path to a
 * flippable leaf, and everything else stays shared.  A flip then reaches only
 * the processor that took the exit, and the refusal can be lifted.
 */
#define KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED            0x0010000000000000ULL
/*
 * The EPTP-switching split-view backend is armed for this runtime.
 *
 * Published only when the caller opted in with ENABLE_EPTP_SWITCH *and* both
 * capabilities it depends on are present.  Absent means the MTF backend is in
 * force, which is also what an unarmed runtime reports - so read this bit,
 * not the request flags, to know which backend a given residency is using.
 */
#define KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED          0x0020000000000000ULL

#define KSWORD_ARK_HVM_STATE_INITIALIZED      0x00000001UL
#define KSWORD_ARK_HVM_STATE_RESOURCES_READY  0x00000002UL
#define KSWORD_ARK_HVM_STATE_EPT_READY        0x00000004UL
#define KSWORD_ARK_HVM_STATE_SELF_TESTED      0x00000008UL
#define KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED 0x00000010UL
#define KSWORD_ARK_HVM_STATE_BUSY             0x00000020UL
#define KSWORD_ARK_HVM_STATE_FAULTED          0x00000040UL
#define KSWORD_ARK_HVM_STATE_EPT_TRUNCATED    0x00000080UL
#define KSWORD_ARK_HVM_STATE_GUEST_READY      0x00000100UL
#define KSWORD_ARK_HVM_STATE_GUEST_RUNNING    0x00000200UL
#define KSWORD_ARK_HVM_STATE_GUEST_EXITED     0x00000400UL
#define KSWORD_ARK_HVM_STATE_NESTED_ACTIVE    0x00000800UL
#define KSWORD_ARK_HVM_STATE_NESTED_VALIDATED 0x00001000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_STARTING 0x00002000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE   0x00004000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING 0x00008000UL
#define KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE  0x00010000UL
#define KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE  0x00020000UL
#define KSWORD_ARK_HVM_STATE_NESTED_PARTIAL    0x00040000UL
#define KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL     0x00080000UL
#define KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED 0x00100000UL
#define KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING 0x00200000UL
#define KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED       0x00400000UL
/*
 * Residency is running underneath another hypervisor - we are L1, not L0.
 * This is a degraded mode, not a failure: every VMX operation is emulated
 * by the outer hypervisor, so exits cost far more and the capability set is
 * whatever the outer one chose to expose.  It is published so the UI never
 * presents nested residency as equivalent to bare-metal residency.
 */
#define KSWORD_ARK_HVM_STATE_RESIDENT_NESTED         0x00800000UL
/* EPT-violation-to-#VE conversion is armed on every resident processor. */
#define KSWORD_ARK_HVM_STATE_VE_ACTIVE              0x01000000UL
/* EPTP switching is armed: guest code can switch views with one VMFUNC. */
#define KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE          0x02000000UL

#define KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY  0x00000001UL
#define KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED     0x00000002UL
#define KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED 0x00000004UL
#define KSWORD_ARK_HVM_CPU_STATE_EXCEPTION       0x00000008UL
#define KSWORD_ARK_HVM_CPU_STATE_CONFLICT        0x00000010UL
#define KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED      0x00000020UL
#define KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED   0x00000040UL
#define KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED   0x00000080UL
#define KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE  0x00000100UL
#define KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED   0x00000200UL
#define KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED    0x00000400UL
#define KSWORD_ARK_HVM_CPU_STATE_NESTED_PARTIAL   0x00000800UL
#define KSWORD_ARK_HVM_CPU_STATE_EVMCS_PARTIAL    0x00001000UL

#define KSWORD_ARK_HVM_QUERY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU       1UL
#define KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED     2UL
#define KSWORD_ARK_HVM_QUERY_STATUS_HYPERVISOR_CONFLICT   3UL
#define KSWORD_ARK_HVM_QUERY_STATUS_RESOURCES_UNAVAILABLE 4UL
#define KSWORD_ARK_HVM_QUERY_STATUS_SELF_TEST_FAILED      5UL
#define KSWORD_ARK_HVM_QUERY_STATUS_BUSY                  6UL
/*
 * The processor supports hardware virtualization, but this build has no
 * backend for it.  Distinct from UNSUPPORTED_CPU on purpose: the user should
 * know the machine is capable and the software is what is missing.
 */
#define KSWORD_ARK_HVM_QUERY_STATUS_BACKEND_NOT_IMPLEMENTED 7UL
#define KSWORD_ARK_HVM_QUERY_STATUS_PARTIAL               7UL
#define KSWORD_ARK_HVM_QUERY_STATUS_ROLLBACK_REQUIRED     8UL

#define KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED     0UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL         2UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE          3UL

#define KSWORD_ARK_HVM_CONTROL_PREPARE   1UL
#define KSWORD_ARK_HVM_CONTROL_SELF_TEST 2UL
#define KSWORD_ARK_HVM_CONTROL_TEARDOWN  3UL
#define KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST 4UL
/*
 * START_RESIDENT is available only when the driver publishes the guarded
 * resident-lifecycle feature.  The driver must stop every VCPU before a power
 * transition and must prevent image unload while any VCPU remains resident.
 */
#define KSWORD_ARK_HVM_CONTROL_START_RESIDENT 5UL
#define KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT  6UL
#define KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED 7UL
#define KSWORD_ARK_HVM_CONTROL_RESET_FAULT     8UL
/*
 * SOAK starts residency, holds it for the requested bounded window, and stops
 * it again.  It is the only control that proves residency survives ordinary
 * system activity rather than merely entering and leaving VMX non-root once.
 */
#define KSWORD_ARK_HVM_CONTROL_SOAK            9UL

/* Bound one soak window so a stuck request can never hold VMX indefinitely. */
#define KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS 30000UL
/* Keep a soak long enough for scheduler, timer and MSR activity to occur. */
#define KSWORD_ARK_HVM_SOAK_MIN_MILLISECONDS 100UL

#define KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_FORCE        0x00000002UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED 0x00000004UL
/* AMD-only bounded nested VMRUN probe; accepted by prepare/self-test, never resident. */
#define KSWORD_ARK_HVM_CONTROL_FLAG_SVM_NESTED_PROBE 0x00008000UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST 0x00000008UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS 0x00000010UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX 0x00000020UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS      0x00000040UL
/*
 * Turn on EPT-violation-to-#VE conversion for this residency.
 *
 * DANGEROUS AND OFF BY DEFAULT.  The guest here is the running Windows, whose
 * IDT[20] handler is not prepared for a #VE the hypervisor invented.  Even with
 * suppress-#VE set on every leaf, any page whose bit 63 is later cleared will
 * deliver a real #VE into that handler.  Enabling this is only meaningful when
 * something inside the guest is known to handle vector 20.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE         0x00000080UL
/*
 * Turn on VM functions and EPTP switching for this residency.
 *
 * OFF BY DEFAULT.  VMFUNC has no CPL check, so arming this publishes every
 * domain in the EPTP list to unprivileged guest code.  Only meaningful when
 * every listed domain has been checked to grant no more than the default view.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC   0x00000100UL
/*
 * Give every processor its own EPT hierarchy for this residency.
 *
 * OFF BY DEFAULT, and refused rather than silently downgraded: a caller that
 * asked for per-processor isolation and got a shared hierarchy would install
 * views on a multicore box believing each flip is local, which is precisely
 * the corruption the flag exists to prevent.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT 0x00000200UL
/*
 * Select the EPTP-switching split-view backend for this runtime.
 *
 * OFF BY DEFAULT.  With the flag absent nothing changes: the driver keeps the
 * existing "write the leaf, single-step under the Monitor Trap Flag, write it
 * back" backend, byte for byte.
 *
 * The two backends answer the same question with different machinery, and the
 * difference is not performance - it is which capability they require:
 *
 *   write-leaf + MTF   needs INVEPT_SINGLE and MONITOR_TRAP_FLAG.
 *   switch EPTP        needs INVEPT_SINGLE and execute-only EPT leaves
 *                      (IA32_VMX_EPT_VPID_CAP bit 0).  It needs NEITHER the
 *                      Monitor Trap Flag NOR VM functions.
 *
 * That is the whole reason this flag exists: a nested Hyper-V guest is not
 * offered the Monitor Trap Flag, so the MTF backend cannot install a single
 * view there, while execute-only leaves are available and measured.
 *
 * Refused rather than silently downgraded, for the same reason as
 * ENABLE_LOCAL_EPT: a caller that asked for a backend which never writes an
 * EPT leaf at run time, and silently got one that does, would reason about
 * cross-processor visibility on a false premise.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH 0x00000400UL
/*
 * For measurement: execute an extra batch of VMREADs on each VM exit, then discard the results.
 *
 * The rationale for this value is an unmeasured number: under nesting, how expensive is L1 VMREAD execution? It determines whether
 * changing VMCS field access to read shared pages is worthwhile—a significant engineering effort involving mapping over 100 fields and
 * potentially losing several newer fields (interrupt shadow stack table, PKRS, UINV). Work should not begin without clear benefits.
 *
 * Measuring single-instruction cycle counts requires taking timestamps on the exit path, which incurs observation overhead.
 * Adding load is cleaner instead: read N times, observe the drop in exit throughput, and derive the single-operation cost. This
 * approach does not alter the semantics of any exit—the read values are discarded, and normal telemetry continues unchanged.
 *
 * Set this flag only when this measurement is needed. Exiting becomes slower while set, which is exactly what it measures.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_VMREAD_BENCH 0x00000800UL
/*
 * Default value used when the count is not provided in the request.
 *
 * Use 512 instead of dozens: Empirical tests show that 32 iterations are completely drowned in noise (three alternating rounds
 * yielded +18.1% / -13.5% / -6%, with inconsistent signs; the baseline itself had a 14% variance). This only indicates that 'effect
 * < noise', not that VMREAD is cheap. To draw a conclusion, the signal must be amplified until it is measurable; otherwise,
 * 'unmeasurable' and 'non-existent' are indistinguishable. 512 iterations provided a clean signal (four rounds: -42% ~ -43.9%).
 */
#define KSWORD_ARK_HVM_VMREAD_BENCH_DEFAULT 512UL
/*
 * Maximum count.
 *
 * Running this many times per exit stalls the guest if the value is too large; this path runs in
 * VMX root with interrupts disabled, holding the exit stack, where no one can recover if it hangs.
 * The limit turns a typo into a single trapped measurement instead of a machine requiring a reboot.
 */
#define KSWORD_ARK_HVM_VMREAD_BENCH_MAX 4096UL
/*
 * Log every standard exit entry into the event ring. Disabled by default.
 *
 * Disabling this keeps room for evidence in the ring. A test on 2026-09-07 with 2 vCPU and 30 seconds
 * of resident operation published 682829 entries, had 0 slot-acquisition failures, and evicted 681805
 * entries through wraparound. The problem was never an inability to write: the ring wrapped 22 times
 * per second. At 22750 exits per second, all 1024 slots are overwritten in 45 milliseconds.
 *
 * These 680,000 entries are almost all of the same type: normal exits (type VMEXIT). Their aggregated exit reason
 * histogram is already provided for free; retaining them individually serves only one purpose: to squeeze out the four
 * truly rare evidence types—EPT violations, nested VMX, fatal exits, and lifecycle events—within 45ms. Polling for a
 * rare event requires a speed faster than the ring flip rate, a condition that cannot be met on physical hardware.
 *
 * Therefore, by default only those four types remain; ordinary exits are handled by the histogram and lastExit* fields. When
 * per-trace is needed, set this bit to restore the original behavior — **the capability is not removed, just not the default**.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS 0x00001000UL

/*
 * Hide the presence of a hypervisor from user-mode CPUID.
 *
 * Why this bit is needed: the first blocking reading observed on real hardware is not due to insufficient capability, but due to identity.
 * VMware Workstation 17.6 first uses CPUID during initialization to detect that the outer
 * layer is Hyper-V, then requests Windows Hypervisor Platform. Since this guest does not have
 * WHP installed, the mismatch causes it to refuse to start any virtual machine before loading:
 *
 *     IOPL_Init: Hyper-V detected by CPUID
 *     WHP_CanBeInstalled: Hyper-V is not present, function should not be called.
 *     [msg.vmx.nestedHyperV] ... not compatible ...
 *     Module 'IOPL' initialization failed.
 *
 * The identity it sees is not what we selected—it is the L0 Hyper-V identity passed through
 * us. Once resident, every CPUID instruction exits to us, and we decide the response.
 * Passing the outer identity unchanged to our own guest is fundamentally incorrect.
 *
 * Impact is deliberately minimized: **only modify when the guest is at CPL=3**. Windows kernel's
 * own Hyper-V enlightenment uses CPL=0 CPUID and hypercall pages; that path remains untouched.
 * This distinction is not an optimization; it is necessary because if a kernel bound to an outer
 * hypervisor at boot is later told "there is no hypervisor," the consequences are unpredictable.
 * The target we need to deceive (vmware-vmx.exe) happens to reside entirely in user mode.
 *
 * This is not 'perfectly masquerading as bare metal' nor intended to be: it only addresses identity-based rejection. Any software performing the
 * same check within the kernel will still see the truth; at that point, the readings will directly inform us whether to relax the restrictions.
 */
#define KSWORD_ARK_HVM_CONTROL_FLAG_HIDE_HYPERVISOR 0x00002000UL
/* Same-binary performance reference: retain unused CPUID diagnostic VMREADs. */
#define KSWORD_ARK_HVM_CONTROL_FLAG_FULL_EXIT_SNAPSHOT 0x00004000UL

#define KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN 0x48564D43UL

#define KSWORD_ARK_HVM_CONTROL_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU       3UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED     4UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT   5UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED      6UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED          7UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED       8UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED      9UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED         10UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_BUSY                  11UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED   12UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT     13UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION 14UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED      15UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED      16UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED     17UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED      18UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED 19UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED   20UL
/* Per-processor EPT was requested but the runtime never armed the capability. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_NOT_ARMED      21UL
/* More flippable leaves than one private hierarchy is allowed to mirror. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_LEAF_SET_TOO_LARGE 22UL
/* The private hierarchies would not fit the reserved page budget. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_PAGE_BUDGET_EXHAUSTED 23UL
/* A flippable leaf had no live split to mirror; the caller must add it first. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_SPLIT_MISSING  24UL
/* The independent post-build walk disagreed with what the build published. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_VERIFY_FAILED  25UL
/* VMFUNC publishes one EPTP list to every processor; the two cannot coexist. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_VMFUNC 26UL
/* Nested VMX composes its own EPT pointer and cannot share this mechanism. */
#define KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_NESTED 27UL
/*
 * The guest physical address space on this machine exceeds the size of the identity-mapped window supported by this version.
 *
 * Separated from UNSUPPORTED_CPU because they require opposite actions: the former says 'switch to a
 * different machine', while this one says 'this machine supports everything, but our window is too small'.
 *
 * The cost of mixing these two is empirically verified: on an Intel Core Ultra system, CPUID.80000008H:EAX reports a physical address width
 * of 45 bits (32 TiB), while the configured window was only 8 TiB. Consequently, the builder truncated the address, set EPT_TRUNCATED, and
 * rejected the resident request, ultimately translating this to "processor not supported"—a message issued by a processor that fully
 * supports all required capabilities. Users were forced to check the CPU and BIOS, both of which were found to be correct.
 *
 * When the UI sees this code, it must report three values: the host's physical address width
 * (readable via a single CPUID instruction in user mode), where this version is actually mapped
 * (highestMappedPhysicalAddress from the query response), and the number of PML4 entries required.
 */
#define KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL 28UL

#define KSWORD_ARK_HVM_EXIT_REASON_NONE   0xFFFFFFFFUL
#define KSWORD_ARK_HVM_EXIT_REASON_VMCALL 18UL
#define KSWORD_ARK_HVM_EXIT_REASON_EPT_VIOLATION 48UL
#define KSWORD_ARK_HVM_EXIT_REASON_EPT_MISCONFIGURATION 49UL
#define KSWORD_ARK_HVM_EXIT_REASON_INVEPT 50UL
#define KSWORD_ARK_HVM_EXIT_REASON_INVVPID 53UL
#define KSWORD_ARK_HVM_EXIT_REASON_MONITOR_TRAP 37UL

#define KSWORD_ARK_HVM_EPT_ACCESS_READ    0x00000001UL
#define KSWORD_ARK_HVM_EPT_ACCESS_WRITE   0x00000002UL
#define KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE 0x00000004UL

#define KSWORD_ARK_HVM_EPT_RULE_ADD    1UL
#define KSWORD_ARK_HVM_EPT_RULE_REMOVE 2UL
#define KSWORD_ARK_HVM_EPT_RULE_CLEAR  3UL
#define KSWORD_ARK_HVM_EPT_RULE_QUERY  4UL
/*
 * Rearm a WATCH_ONCE rule that has already been triggered.
 *
 * Not 'ADD another rule': keep watchId unchanged and retain the historical hit count; otherwise the UI would
 * show a new record, while this feature's purpose is to answer 'how many times the same target was touched'.
 */
#define KSWORD_ARK_HVM_EPT_RULE_REARM  5UL
/* Read back the entire watch table. A standard QUERY returns only one entry at a time, but the list page requires all entries. */
#define KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY 6UL

#define KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG          0x00000001UL
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE   0x00000002UL
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED 0x00000004UL
/*
 * ENFORCE turns a rule from a tripwire into durable denial: the access is
 * refused with an injected #PF and residency continues, instead of recording
 * the hit and devirtualizing.  Unlike ALLOW_ONCE it never edits the shared EPT
 * leaf, so it is safe on any processor count.
 *
 * The guest sees a page fault at an address its own page tables map, which is
 * exactly what denial means here.  Kernel-mode targets can therefore bugcheck
 * the moment a driver touches the protected page - that is the intended
 * behavior of a deny rule, not a defect, and it is why the flag requires
 * explicit confirmation.
 *
 * A rule can only deny an access whose guest-linear address the CPU reported,
 * because CR2 has to be set for the injected fault to mean anything.  When it
 * is unavailable the rule falls back to tripwire behavior.
 */
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE      0x00000008UL
/*
 * WATCH_ONCE: First-touch attribution.
 *
 * Unlike the other three dispositions on the same page, this one warrants a line-by-line comparison:
 *
 * - Exit virtualization after a strict tripwire hit. This is a valid safety fallback because it
 *   guarantees that the guest can eventually complete the access. However, it is unusable for a user-level
 *   request to see who touches the address next: catching one access costs the entire machine its VMM.
 * - ALLOW_ONCE permits one instruction, then uses monitor-trap to reclaim permissions. It requires MTF, while nested...
 *   Hyper-V does not provide MTF in practice, so it is permanently unavailable on the target
 *   machine; under multi-core sharing, the relaxed window remains visible across the entire machine.
 * - ENFORCE is a persistent deny; note #PF — marked as UNIMPLEMENTED (livelock).
 *
 * WATCH_ONCE is exactly "ALLOW_ONCE" without the revocation step:
 *
 *     EPT violation
 *         ↓
 *     Atomic ARMED → TRIGGERED transition (only one CPU wins).
 *         ↓
 *     Permanently restore permissions for this page (this rule will no longer deny).
 *         ↓
 *     INVEPT
 *         ↓
 *     RIP not advanced, VMRESUME.
 *         ↓
 *     Original instruction re-execution and normal completion; continue resident.
 *
 * Since there is no 'reclaim' step, it **does not require MTF**, nor the 'single-core or private-level' gate:
 * permissions change unidirectionally toward being relaxed. If other processors see the relaxed permissions
 * early, their accesses simply complete normally—and this watch was already decided to no longer block.
 *
 * Semantically, it is **not** a security boundary: it does not block access, only records a snapshot once and then yields.
 */
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE   0x00000010UL

/*
 * Watch lifecycle.
 *
 * The rule's presence in the table alone cannot express this timeline: after a hit, the rule must remain in the table (to
 * report hitCount and the context of the last hit), yet it no longer blocks any access. These two concerns must be separated.
 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_NONE        0UL
/* Installed and currently intercepting, waiting for the first access. */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED       1UL
/* A CPU won the atomic transition and is restoring permissions. Transient state. */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED   2UL
/* Hit and disarmed; permissions restored. To check again, explicit REARM is required. */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED    3UL
/*
 * The generation associated with this watch no longer exists because it was paused, released, or faulted.
 *
 * Separated from DISARMED because they imply completely different things to the user: DISARMED means 'the
 * target was tampered with, here is the evidence', while INVALIDATED means 'I saw nothing because no one was
 * watching in the middle'. Displaying the latter as the former equates to reporting a non-existent observation.
 */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED 4UL
/* Failed during installation; interception was never entered. */
#define KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED     5UL

/* Event successfully published on hit. */
#define KSWORD_ARK_HVM_EPT_WATCH_HIT_NONE      0UL
#define KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED 1UL
/*
 * Hit occurred, but the event ring buffer did not capture it
 *
 * This must be distinguished from 'never hit': both appear identical in the event list (no event), but the conclusions are
 * opposite—one means the target was untouched, while the other means the target was touched but the evidence was lost.
 */
#define KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST 2UL

#define KSWORD_ARK_HVM_EPT_RULE_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED          6UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL               7UL
/*
 * The requested action cannot be implemented under the current mechanism; reject it during installation.
 *
 * Currently, there is only one source: ENFORCE. Its semantics are 'persistent denial', implemented by injecting a #PF
 * into the guest. The denial occurs at the EPT layer; the guest page table indicates the page is valid, so the page-fault
 * handler performs no fix, returns, re-executes, violates again, and injects another #PF. In practice, this causes an
 * infinite livelock that hangs the entire machine, and the exception never reaches user mode, so SEH cannot handle it.
 *
 * Given that the guest cannot see EPT, injecting a fault that the guest can resolve on its own is impossible.
 * Actually reading a substitute page requires redirection through split views rather than denying
 * access. Reject the request here instead of installing a rule that hangs the machine when triggered.
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED         8UL
/*
 * The handling of this rule on this machine cannot be safely implemented; reject it during installation.
 *
 * Currently the only source is ALLOW_ONCE on multicore machines. It temporarily relaxes EPT leaf
 * permissions for one instruction and restores them through a monitor-trap. With a shared hierarchy,
 * that window is visible to the whole machine: other processors receive the relaxed permissions at the
 * same moment. The runtime gate in the allAllowOnce branch of hvm_ept.c therefore requires exclusive use
 * of a single processor or a private hierarchy. If neither condition holds, the result is fail-closed.
 *
 * The issue is not the rule itself, but that it is applied too late: the rule appears to install successfully
 * until it is actually hit, at which point the entire machine exits VMX (fail-closed now halts the whole machine,
 * not just the current core; see hvm_internal.h's ResidentFaultStopRequested). The user sees 'installed' and then
 * virtualization silently disappears at some point, with no link established between these two events.
 *
 * This exit path in the private hierarchy fails under nesting: it requires LocalEptArmed, which in turn requires INVEPT_SINGLE.
 * **And** MONITOR_TRAP_FLAG: nested Hyper-V does not provide MTF. Therefore, on a nested target machine, the
 * combination of "multi-core + ALLOW_ONCE" is permanently unavailable and should be clarified during installation.
 *
 * This is not 'ALLOW_ONCE is impossible'; it is 'impossible on this machine'.
 * Single-core or multi-core systems with private EPT are still allowed through.
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE 9UL
/*
 * This page is already occupied by another EPT mechanism (split view, execution domain, or another watch).
 *
 * No automatic merging or silent overwriting: The two mechanisms have conflicting expectations for the same leaf entry.
 * The last write wins, and the winner modifies the loser's functionality without the loser's knowledge. Each page has a
 * single explicit owner; on conflict, clearly indicate the owner so the user can decide which one to withdraw first.
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT         10UL
/*
 * Resident and running; the rule table is frozen throughout the entire resident period.
 *
 * This is not 'partial success': no fields were modified. It previously reused PARTIAL ("some processors failed to complete invalidation")
 * reporting, but the description refers to an event that never occurred, misleading users toward the invalidation mechanism for investigation.
 *
 * Freezing itself is not conservative but required: during residency, the VM-exit path must not acquire PASSIVE-level locks to scan the
 * rule table and split leaves; if the PASSIVE side modifies it concurrently, it becomes a race condition with no diagnostic surface.
 *
 * Install, rearm, and remove all EPT rules, including memory watches, while the resident hypervisor is stopped. They
 * take effect after startup, using the same configuration window as split views, MSR policies, and CR policies.
 */
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN       11UL

#define KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT          1UL
#define KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION   2UL
#define KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX      3UL
#define KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT      4UL
#define KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE       5UL
/* Page-control stages use ruleId as operation id, not an EPT rule id. */
#define KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE     6UL

#define KSWORD_ARK_HVM_EVENT_QUERY_READ  1UL
#define KSWORD_ARK_HVM_EVENT_QUERY_CLEAR 2UL

#define KSWORD_ARK_HVM_NESTED_STATE_DISABLED        0UL
#define KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY  2UL
#define KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON        3UL
#define KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT  4UL
#define KSWORD_ARK_HVM_NESTED_STATE_L2_PARTIAL      5UL
/*
 * L2 is executing under a composed hierarchy.
 *
 * Distinct from L2_PARTIAL, which means an L2 entry was attempted and refused.
 * This one means the processor is actually running L1's guest, so a reader
 * that sees it can conclude the merge and the shadow hierarchy both held.
 */
#define KSWORD_ARK_HVM_NESTED_STATE_L2_ACTIVE       6UL

#define KSWORD_ARK_HVM_EVMCS_STATE_UNAVAILABLE     0UL
#define KSWORD_ARK_HVM_EVMCS_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_EVMCS_STATE_V1_PARTIAL       2UL
#define KSWORD_ARK_HVM_EVMCS_STATE_ACTIVE           3UL

#define KSWORD_ARK_HVM_EVMCS_FLAG_ROOT_PARTITION      0x00000001UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_READABLE  0x00000002UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_ENABLED   0x00000004UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_OWNERSHIP_CONFLICT  0x00000008UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_CLEAN_FIELDS        0x00000010UL

typedef struct _KSWORD_ARK_HVM_CPU_ROW
{
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char vmxInstructionResult;
    unsigned long stateFlags;
    long lastStatus;
    unsigned long lastExitReason;
    unsigned long long vmExitCount;
    unsigned long nestedState;
    unsigned short evmcsVersion;
    unsigned short reserved;
    /* Architecture-specific instruction evidence is never overloaded. */
    unsigned long backend;
    /* Common stage used by the AMD execution path. */
    unsigned long executionStage;
    /* Raw SVM EXITCODE is 64-bit and sparse; zero if not valid. */
    unsigned long long svmExitCode;
} KSWORD_ARK_HVM_CPU_ROW;

typedef struct _KSWORD_ARK_QUERY_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_HVM_REQUEST;

/* AMD probe evidence remains available even when resource preparation is refused. */
typedef struct _KSWORD_ARK_HVM_SVM_CAPABILITIES {
    /* MSR validity: VM_CR=1, EFER=2, VM_HSAVE_PA=4, PAT=8. */
    unsigned long maxLeaf, features, asidCount, physicalBits, msrValidMask, exceptionStatus;
    /* Raw observations are meaningful only with the matching valid bit. */
    unsigned long long vmCr, efer, hsave, pat;
    /* V6 admission diagnostics; raw XSS=0 is evidence only when its valid bit is set. */
    unsigned long rejectReason, stateValidMask, cpuid1Ecx, xsaveFeatures;
    /* Read-only observations; discovery never changes these registers. */
    unsigned long long cr4, xcr0, xss;
} KSWORD_ARK_HVM_SVM_CAPABILITIES;

typedef struct _KSWORD_ARK_QUERY_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    /* V5 backend identity, independent of the CPU vendor string. */
    unsigned long backend;
    /* NONE/EPT/NPT; NPT is not represented by an EPT-ready feature bit. */
    unsigned long slatType;
    /* Common translation readiness independent of EPT implementation. */
    unsigned long slatReady;
    /* Actual AMD control/save backend status; zero on VMX. */
    unsigned long backendStatus;
    /* Power epoch is separate from the command-by-command generation counter. */
    unsigned long powerGeneration;
    /* Captured probe evidence, independent of allocation and execution. */
    KSWORD_ARK_HVM_SVM_CAPABILITIES svmCapabilities;
    unsigned long queryStatus;
    unsigned long stateFlags;
    unsigned long generation;
    unsigned long processorCount;
    unsigned long preparedProcessorCount;
    unsigned long selfTestPassedProcessorCount;
    unsigned long residentProcessorCount;
    unsigned long residentImplementation;
    unsigned long eptImplementation;
    unsigned long nestedImplementation;
    unsigned long evmcsImplementation;
    /*
     * Number of processors ready with a safe physical mapping window for exit.
     *
     * Report separately because the window's preparation phase self-check is completely invisible from the outside: if it fails, only the
     * paths requiring it (nested L2 entry, shadow EPT synthesis) silently reject, while status bits, implementation maturity, and processor
     * count remain unchanged. A self-check that yields no observable result is indistinguishable from no self-check when reading values.
     *
     * The denominator for comparison is **not processorCount**. That represents the 'count of prepared processors',
     * which is 0 before resources are prepared; the window is created during **driver initialization**. Using it as
     * a denominator immediately after driver load results in 'N / 0', falsely reporting a healthy machine as faulty.
     *
     * The correct denominator is the logical processor count retrieved by the caller
     * (GetActiveProcessorCount / KeQueryActiveProcessorCountEx, ALL_PROCESSOR_GROUPS): equality
     * indicates every core is present. This field is zero before driver initialization.
     */
    unsigned long physWindowReadyCount;
    unsigned long eptRuleCount;
    unsigned long eventCount;
    /*
     * Events a VM exit tried to publish and could not - the only real loss.
     *
     * A publisher in VMX root never waits, so when it finds its slot owned by
     * another processor it discards the event and counts it here.  A nonzero
     * value is contention: two processors mapped to the same slot at the same
     * moment.  This is the number that justifies changing the ring's shape.
     *
     * This field used to carry max(displacement, publication loss), which made
     * it unreadable - displacement dominates by three orders of magnitude and
     * is not necessarily a loss at all, so the combined number always looked
     * catastrophic and never distinguished the two causes.
     */
    unsigned long droppedEventCount;
    /*
     * Events pushed out of the ring by wrap since residency started.
     *
     * Not a loss on its own: a consumer polling faster than the ring fills has
     * already read them.  It becomes a loss exactly when it grows between two
     * consecutive reads by more than the ring capacity, which is a comparison
     * only the caller can make because only the caller knows its own interval.
     */
    unsigned long overwrittenEventCount;
    /*
     * Total events ever published, as the denominator for the two above.
     *
     * Full width rather than 32-bit: at the exit rates measured under nested
     * virtualization a 32-bit total wraps within hours, and a wrapped total
     * silently turns both ratios above into nonsense.
     */
    unsigned long long publishedEventCount;
    unsigned long nestedState;
    unsigned long evmcsState;
    unsigned short evmcsVersion;
    /*
     * The site that last refused L2 entry, 1..7; 0 indicates no refusal occurred.
     *
     * Occupies the original 'reservedVersion' slot (no readers or writers), keeping the structure size unchanged.
     *
     * Rationale: Seven different conditions return the same architecture error code 7 (invalid control field) because the architecture defines
     * only this single code number, with no second field to specify which condition triggered it. L1 receives and reports 7; from an external
     * perspective, all seven scenarios appear identical, yet the only critical information needed is which specific condition occurred.
     * See the assignment points in hvm_nested_l2.c for the meaning of these IDs.
     */
    unsigned short nestedLastRefusalSite;
    unsigned long evmcsFlags;
    /*
     * Number of fuse trips due to no progress, cumulative across the entire machine.
     *
     * The fuse itself is **invisible** elsewhere: its reading is only available within the nested probe
     * lines, and the real L1 (VMware's VMM or other hypervisors) does not run our probes. Thus, the
     * event "L2 was stopped by us" cannot be read anywhere in a real scenario — yet this is precisely
     * the moment we need to know: the machine is up, but a guest of a hypervisor has been stopped by us.
     *
     * Occupies the original reservedEvmcs slot (no readers or writers), keeping the structure
     * size unchanged so that each field read by the old GUI remains at the same offset.
     */
    unsigned long nestedFuseTripCount;
    unsigned long long evmcsVpAssistMsr;
    unsigned long eptPageCount;
    unsigned long eptPml4Entries;
    unsigned long eptPdptEntries;
    unsigned long eptLargePageEntries;
    unsigned long long featureFlags;
    unsigned long long vmxBasic;
    unsigned long long vmxEptVpidCapabilities;
    unsigned long long featureControl;
    unsigned long long cr0Fixed0;
    unsigned long long cr0Fixed1;
    unsigned long long cr4Fixed0;
    unsigned long long cr4Fixed1;
    unsigned long long eptPointer;
    unsigned long long mappedRamBytes;
    unsigned long long highestMappedPhysicalAddress;
    unsigned long long vmExitCount;
    unsigned long long lastExitQualification;
    unsigned long long lastGuestRip;
    unsigned long long lastGuestRsp;
    unsigned long lastExitReason;
    unsigned long lastExitInstructionLength;
    unsigned long lastVmInstructionError;
    unsigned short lastLaunchProcessorGroup;
    unsigned char lastLaunchProcessorNumber;
    unsigned char lastLaunchWasNested;
    long lastStatus;
    /*
     * Times an L1 guest asked us to launch an L2 and we refused.
     *
     * This has to be a monotonic counter and not a state, because nestedState
     * is transient: it reaches L2_PARTIAL at the refused VMLAUNCH and is reset
     * to DISPATCH_READY on the next VMXOFF, so a two-second poll almost always
     * misses it.  A nonzero value here is the only durable evidence that some
     * other hypervisor on this machine - VMware, VirtualBox, WSL2, Docker -
     * tried to start a VM underneath us and could not.  Without it the user
     * sees "my VM stopped working" and nothing points at us.
     *
     * Occupies the former reserved slot, so the structure size is unchanged
     * and the protocol version does not move.
     */
    unsigned long nestedL2LaunchRefusedCount;
    char cpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    char hypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    /*
     * Exits so far by Intel basic exit reason, summed over every processor.
     *
     * `vmExitCount` says how many exits happened and `lastExitReason` says what
     * the most recent one was; neither says where the exits go, which is the
     * question that actually comes up.  Reading "lastExitReason 18" a hundred
     * times does not distinguish VMCALL being 99% of the traffic from VMCALL
     * being rare and merely last.
     *
     * Summed rather than reported per processor because the per-processor form
     * would add this array 256 times over.  The driver keeps it per processor
     * internally - that is what makes it free of interlocked access - and adds
     * the columns up here.
     *
     * Indexes past the last reason Intel defines stay zero.  A processor's own
     * counter is 32-bit and wraps after roughly five days at ten thousand exits
     * a second; this sum is 64-bit, so it only inherits a wrap that already
     * happened rather than adding one.
     */
    unsigned long long exitReasonCount[KSWORD_ARK_HVM_EXIT_REASON_SLOTS];
    /*
     * The execution controls actually enforced, and the capability MSR each was
     * adjusted against.
     *
     * Reported because "which exits does this machine take" and "which of them
     * did we ask for" are different questions.  A control bit set in the active
     * value that the driver's request did not contain is one the capability
     * MSR's allowed-0 half made mandatory - which is how an outer hypervisor's
     * demand is told apart from a mistake in our own control computation.
     * Without this the distinction is only reachable by reading source.
     *
     * Zero until residency has been configured at least once.
     */
    unsigned long activePinControls;
    unsigned long activePrimaryControls;
    unsigned long activeSecondaryControls;
    unsigned long activeExitControls;
    unsigned long activeEntryControls;
    /*
     * Number of vmcs12 instances dropped because the per-processor pool was full.
     *
     * An L1 often holds multiple VMCS instances and continuously switches among them via VMPTRLD. When an evicted instance
     * is reloaded via VMPTRLD, its fields are all zero — from L1's perspective, this looks identical to the defect where
     * the hypervisor models only a single vmcs12. Therefore, if a real issue occurs, this count is the only thing that can
     * distinguish the two: a non-zero value indicates the pool is too small, while zero requires investigation elsewhere.
     *
     * Placed in runtime rather than per-processor: the pool is released during un-virtualization. A counter that disappears
     * with the object under test can only answer 'is it happening now?', but the question is 'has it ever happened?'.
     *
     * Occupies the original activeControlsReserved slot (which is merely explicit alignment padding with no readers or writers); the
     * structure size remains unchanged, the protocol version is unchanged, and every field read by the old GUI remains at the same offset.
     */
    unsigned long nestedVmcs12EvictionCount;
    unsigned long long pinCapability;
    unsigned long long primaryCapability;
    unsigned long long secondaryCapability;
    unsigned long long exitCapability;
    unsigned long long entryCapability;
    KSWORD_ARK_HVM_CPU_ROW processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
} KSWORD_ARK_QUERY_HVM_RESPONSE;

typedef struct _KSWORD_ARK_CONTROL_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long command;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    /* Requested soak window in milliseconds; only SOAK reads this field. */
    unsigned long soakMilliseconds;
    /*
     * Perform extra VMREADs per VM exit to discard results.
     *
     * Read this field only when START_RESIDENT is set and the VMREAD_BENCH bit is present; 0 means use the default value.
     *
     * Made configurable instead of a compile-time constant because **this value must be adjustable on the
     * fly**: at 32, the three alternating rounds show inconsistent signs (+18.1% / -13.5% / -6%), completely
     * drowned in noise; only at 512 is a clean signal obtained (four rounds: -42% ~ -43.9%). Distinguishing
     * 'unmeasurable' from 'non-existent' requires amplifying the signal. Forcing a driver recompile for
     * every value change encourages accepting the first reading—the very path to a wrong conclusion.
     *
     * Reuse the original reserved slot; keep the structure size and protocol version unchanged.
     */
    unsigned long vmreadBenchIterations;
} KSWORD_ARK_CONTROL_HVM_REQUEST;

typedef struct _KSWORD_ARK_CONTROL_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long oldStateFlags;
    unsigned long newStateFlags;
    unsigned long oldGeneration;
    unsigned long newGeneration;
    unsigned long preparedProcessorCount;
    unsigned long selfTestPassedProcessorCount;
    unsigned long failedProcessorCount;
    unsigned long residentProcessorCount;
    unsigned long residentImplementation;
    unsigned long eptImplementation;
    unsigned long nestedImplementation;
    unsigned long evmcsImplementation;
    unsigned long eptRuleCount;
    unsigned long eventCount;
    unsigned long eptPageCount;
    unsigned long lastExitReason;
    unsigned long long eptPointer;
    unsigned long long mappedRamBytes;
    unsigned long long vmExitCount;
    unsigned long long lastExitQualification;
    unsigned long long lastGuestRip;
    unsigned long long lastGuestRsp;
    unsigned long lastExitInstructionLength;
    unsigned long lastVmInstructionError;
    unsigned short launchProcessorGroup;
    unsigned char launchProcessorNumber;
    unsigned char launchWasNested;
    long lastStatus;
    /*
     * Number of PML4 entries in the identity mapping window for this driver, with each entry covering 512 GiB.
     *
     * Occupies the original reserved2 slot (no readers or writers), keeping the structure size and protocol version unchanged.
     *
     * The sole reason for this: when EPT_WINDOW_TOO_SMALL is configured, the interface must be able to state "how many entries
     * the host needs" and "how many entries this build has". The former can be calculated by the interface itself using a single
     * CPUID instruction, but the latter cannot—it is a compile-time constant of this driver, and the value held by an interface
     * built from an old header file is exactly wrong. This message needs to be accurate precisely when versions are mismatched.
     *
     * Populate on every control call, not just on failure: A field that only has a value when something
     * goes wrong; otherwise, there is no way to confirm it is correct when nothing goes wrong.
     */
    unsigned long eptPml4EntryBudget;
    /* Milliseconds residency actually held during the last soak. */
    unsigned long soakElapsedMilliseconds;
    /*
     * Processors that left VMX non-root on their own during the soak.  Any
     * nonzero value means an exit reason reached the fail-closed path, so the
     * soak did not prove sustained residency.
     */
    unsigned long soakUnexpectedDevirtualizations;
} KSWORD_ARK_CONTROL_HVM_RESPONSE;

typedef struct _KSWORD_ARK_HVM_EPT_RULE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long ruleId;
    /*
     * EPT permissions removed while resident.  This is a tripwire mask, not a
     * durable access-control guarantee: a strict hit records and devirtualizes
     * without injecting an exception, so the same native access may retry and
     * succeed after VMXOFF.  Removing READ also removes WRITE; when execute-only
     * EPT is unsupported it removes EXECUTE as well.
     */
    unsigned long deniedAccess;
    unsigned long long physicalAddress;
    unsigned long long pageCount;
    /*
     * —— Fields below serve only WATCH_ONCE; all other handling is ignored ———
     *
     * These record what the user requested, not what the hardware actually monitors. These two are never
     * equal on EPT: EPT permissions are 4 KiB page-granular, while users often access 8-byte boundaries.
     * The watch created by DriverObject->MajorFunction[14]. The driver does not monitor more finely just by storing
     * these two values; they are stored so that upon a hit, it can answer 'whether this access falls within the
     * specific bytes you truly care about' and allow the UI to display both sets of numbers side-by-side accurately.
     *
     * Discarding them and keeping only the page address would cause the interface to report 'your target was accessed'
     * for other offsets within a page—a statement that reads correctly but is actually completely irrelevant.
     */
    unsigned long long requestedAddress;
    unsigned long long requestedLength;
    /*
     * The items selected by the user, before architecture normalization.
     *
     * deniedAccess is the normalized **actual** effective mask (removing READ necessarily removes
     * WRITE; if there is no execute-only, EXECUTE must also be removed). Both must be retained:
     * Only keep the normalized value, and the UI will display "you requested read monitoring" as "you requested read-write monitoring",
     * which alters the user's request. Only keep the request value, and the UI will falsely claim only read monitoring occurred.
     */
    unsigned long requestedAccess;
    /* Address kind for the request; see KSWORD_ARK_HVM_WATCH_ADDRESS_*. Echo-only. */
    unsigned long addressKind;
} KSWORD_ARK_HVM_EPT_RULE_REQUEST;

/* requestedAddress is a kernel virtual address; it is translated to a physical page by the driver during installation. */
#define KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL  0UL
/* requestedAddress is a physical address; do not translate. */
#define KSWORD_ARK_HVM_WATCH_ADDRESS_PHYSICAL 1UL

/* Maximum number of entries reported in a single watch table snapshot. */
#define KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS 32UL

/* A complete protocol snapshot of a watch entry. */
typedef struct _KSWORD_ARK_HVM_EPT_WATCH_ROW
{
    /* Same value as ruleId: a watch is an EPT rule with a WATCH_ONCE disposition. */
    unsigned long watchId;
    /* See KSWORD_ARK_HVM_EPT_WATCH_STATE_*. */
    unsigned long state;
    /* The access type requested by the user, before normalization. */
    unsigned long requestedAccess;
    /* Actual access type loaded into EPT, already normalized. */
    unsigned long effectiveAccess;
    /* Address kind during installation. */
    unsigned long addressKind;
    /*
     * Cumulative hit count.
     *
     * A one-shot watch typically reaches 1; after REARM, it continues to accumulate, so this field answers
     * "how many times the target has been hit in total" rather than "whether it was hit in the current round."
     */
    unsigned long hitCount;
    /* Sequence number of the most recent hit; used with lastHitStatus to determine if evidence exists. */
    unsigned long long lastHitSequence;
    /* See KSWORD_ARK_HVM_EPT_WATCH_HIT_*. */
    unsigned long lastHitStatus;
    /*
     * HVM generation when this round was armed.
     *
     * Stopping resident mode, releasing it, or encountering a fault advances the generation. A
     * mismatch means the watch crossed an unobserved gap, so any no-hit result it reports is invalid.
     */
    unsigned long armedGeneration;
    /* The address and length requested by the user, echoed back as-is. */
    unsigned long long requestedAddress;
    unsigned long long requestedLength;
    /* Actual monitored physical pages and offsets within pages. */
    unsigned long long physicalPage;
    unsigned long long pageCount;
    /* The most recent hit context, displayed directly in the UI without needing to scan the event ring. */
    unsigned long long lastHitRip;
    unsigned long long lastHitGuestLinearAddress;
    unsigned long long lastHitGuestPhysicalAddress;
    unsigned long long lastHitCr3;
    unsigned long long lastHitRsp;
    unsigned long long lastHitTimestamp;
    unsigned short lastHitProcessorGroup;
    unsigned char lastHitProcessorNumber;
    /* Whether the CPU reported a valid guest linear address upon a hit. */
    unsigned char lastHitGuestLinearValid;
    /* Whether the matched GLA falls within the requestedAddress/Length range. */
    unsigned long lastHitRangeMatch;
} KSWORD_ARK_HVM_EPT_WATCH_ROW;

typedef struct _KSWORD_ARK_HVM_EPT_RULE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long ruleId;
    unsigned long ruleCount;
    unsigned long generation;
    unsigned long implementation;
    /* Effective tripwire mask after architectural permission normalization. */
    unsigned long deniedAccess;
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long long pageCount;
    long lastStatus;
    unsigned long reserved2;
    /*
     * ——— The following fields serve WATCH_ONCE ——
     *
     * Append at the end of the structure rather than inserting in the middle: inserting fields in the middle
     * shifts offsets of all existing fields. If either side of an incremental build (.sys or GUI) is not
     * rebuilt, the read values will be misaligned—such faults provide no compile-time or runtime warnings.
     */
    /* Identifier for another mechanism occupying this page; meaningful only during LEAF_CONFLICT. */
    unsigned long conflictOwnerId;
    /* See KSWORD_ARK_HVM_WATCH_CONFLICT_*. */
    unsigned long conflictOwnerKind;
    /* Number of rows returned by WATCH_QUERY, and the total number of rows in the table. */
    unsigned long returnedWatchRows;
    unsigned long watchRowCount;
    /* Complete snapshot of the single watch entry returned for a single operation (ADD / REARM / QUERY). */
    KSWORD_ARK_HVM_EPT_WATCH_ROW watch;
    /* For WATCH_QUERY only. */
    KSWORD_ARK_HVM_EPT_WATCH_ROW watchRows[KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS];
} KSWORD_ARK_HVM_EPT_RULE_RESPONSE;

/* This page has no other owner. */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_NONE   0UL
/* Occupied by an EPT split view (CLOAK / HOOK). */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW   1UL
/* Occupied by another EPT rule. */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_RULE   2UL
/* Occupied by another watch rule. */
#define KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH  3UL

typedef struct _KSWORD_ARK_HVM_EVENT_ROW
{
    unsigned long long sequence;
    unsigned long long timestamp;
    unsigned long long guestPhysicalAddress;
    unsigned long long guestLinearAddress;
    unsigned long long guestRip;
    unsigned long long qualification;
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char reserved0;
    unsigned long type;
    unsigned long exitReason;
    unsigned long access;
    unsigned long ruleId;
    long status;
    unsigned long reserved1;
    /*
     * —— Fields added on 2026-09-19 to support watch hit attribution ———
     *
     * Append to the end; offsets of all existing fields remain unchanged.
     *
     * These three must be captured at the VM-exit context: RSP and CR3 are no longer the values at the
     * moment of the hit once VMRESUME returns. Asking from R0 afterward yields answers from another thread.
     * In contrast, module names, symbols, and PIDs are not included here—resolving Windows objects in the
     * VMX root risks the entire machine; those are left for R0 normal context and R3 post-processing.
     */
    unsigned long long guestRsp;
    /*
     * Guest CR3 at the moment of match.
     *
     * It is the sole trusted source for 'which address space was active' and an input for PID attribution.
     * However, it is merely an observation: KVA shadowing, system address space, kernel worker threads,
     * and CR3 reuse can invalidate the CR3 → PID mapping. Thus, the protocol reports only the observed
     * CR3, leaving 'which process it resolved to' and 'confidence level' for the upper layer to annotate.
     */
    unsigned long long guestCr3;
    /* The state of this watch after a hit; see KSWORD_ARK_HVM_EPT_WATCH_STATE_*. */
    unsigned long watchState;
    /* See KSWORD_ARK_HVM_EVENT_FLAG_*. */
    unsigned long eventFlags;
} KSWORD_ARK_HVM_EVENT_ROW;

/* CPU reported a valid Guest Linear Address (EPT violation qualification bit 7). */
#define KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID   0x00000001UL
/* This GLA falls within the byte range requested by the user, not merely within the same page. */
#define KSWORD_ARK_HVM_EVENT_FLAG_RANGE_MATCH 0x00000002UL
/* This entry is the first hit of the watch. */
#define KSWORD_ARK_HVM_EVENT_FLAG_WATCH_HIT   0x00000004UL

typedef struct _KSWORD_ARK_HVM_EVENT_QUERY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long maxRows;
    unsigned long long afterSequence;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_HVM_EVENT_QUERY_REQUEST;

typedef struct _KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long returnedRows;
    unsigned long availableRows;
    /* Rows overwritten or unavailable in this nonblocking sequence snapshot. */
    unsigned long droppedRows;
    unsigned long reserved;
    unsigned long long newestSequence;
    KSWORD_ARK_HVM_EVENT_ROW rows[KSWORD_ARK_HVM_MAX_EVENT_ROWS];
} KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE;

/*
 * Ring -1 memory access.
 *
 * The point of this interface is not that it can read memory - the kernel can
 * already do that - but that it reaches memory without calling the documented
 * memory-manager routines an attacker or a competing product may have hooked.
 * It rewrites a private page-table entry and reads through its own window.
 *
 * When the self-map discovery that window depends on fails, the driver falls
 * back to MmCopyMemory and says so in usedDirectWindow, so a caller can always
 * tell whether the hook-free path was actually taken.
 */
/*
 * Version 2 adds processId.  The layout changed, so the version had to move
 * with it: a v1 caller and a v2 driver would disagree about where address
 * begins, and a silent disagreement about a memory-write target is the worst
 * kind there is.
 */
#define KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION 2UL

/* Bound one transfer so METHOD_BUFFERED request snapshots stay small. */
#define KSWORD_ARK_HVM_MEMORY_MAX_BYTES 1024UL

#define KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL  1UL
#define KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL 2UL
#define KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL   3UL
#define KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL  4UL
#define KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE      5UL
/* Report whether the private window is available without touching memory. */
#define KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW   6UL

#define KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED 0x00000001UL
/* Refuse the request outright when the private window is unavailable. */
#define KSWORD_ARK_HVM_MEMORY_FLAG_REQUIRE_WINDOW 0x00000002UL

/* Reuse the HVM control token so one confirmation vocabulary covers the area. */
#define KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN 0x48564D43UL

#define KSWORD_ARK_HVM_MEMORY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE    3UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID       4UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED    5UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED         6UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL               7UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_BUSY                  8UL
/* The requested process could not be looked up or has already exited. */
#define KSWORD_ARK_HVM_MEMORY_STATUS_PROCESS_LOOKUP_FAILED 9UL

typedef struct _KSWORD_ARK_HVM_MEMORY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long length;
    /*
     * Target process for virtual operations.  Zero keeps the historical
     * behavior: resolve through directoryBase, or through the calling thread
     * when that is zero too.
     *
     * The driver resolves the process to a page-directory base internally and
     * never reports it back.  Handing a caller another process CR3 would be
     * handing it a ready-made argument for a page-table walk from user mode,
     * which is a capability this interface has no reason to grant.
     */
    unsigned long processId;
    /* Keep the 64-bit fields naturally aligned without undefined padding. */
    unsigned long reserved0;
    /* Physical address for physical operations, virtual for the rest. */
    unsigned long long address;
    /*
     * Target page-directory base for virtual operations.  Ignored when
     * processId is nonzero.  Zero means the address is resolved through the
     * page tables of the current process.
     */
    unsigned long long directoryBase;
    unsigned char data[KSWORD_ARK_HVM_MEMORY_MAX_BYTES];
} KSWORD_ARK_HVM_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_HVM_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long bytesTransferred;
    /* Physical address the access actually resolved to. */
    unsigned long long physicalAddress;
    /* Nonzero when the private page-table window carried the access. */
    unsigned char usedDirectWindow;
    /* Nonzero when the private window exists at all on this system. */
    unsigned char windowReady;
    unsigned short reserved0;
    long ntStatus;
    unsigned char data[KSWORD_ARK_HVM_MEMORY_MAX_BYTES];
} KSWORD_ARK_HVM_MEMORY_RESPONSE;

/*
 * EPT split views: one guest-physical page backed by two different frames
 * depending on how it is accessed.
 *
 * CLOAK backs execution with the real page and every read or write with a
 * shadow, so code keeps running while memory scanners see whatever the shadow
 * holds.  HOOK is the mirror image: reads and writes see the real page while
 * execution is redirected into a shadow that carries the patched instructions,
 * which is a breakpoint no byte comparison can find.
 *
 * Both are implemented by flipping the shared EPT leaf on violation and
 * restoring it on the following monitor-trap exit, exactly like an allow-once
 * rule.  That makes them subject to the same constraint: the leaf is shared by
 * every processor, so a view is only safe while exactly one VCPU is resident.
 * Multi-processor views need per-processor EPT hierarchies, which this
 * protocol version does not provide.
 */
#define KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION 1UL

/* Bound the number of simultaneously installed views. */
#define KSWORD_ARK_HVM_MAX_VIEWS 32UL
/* One view covers exactly one four-KiB page, which is the shadow's size. */
#define KSWORD_ARK_HVM_VIEW_PAGE_BYTES 4096UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_VIEW 0x8BBUL
#define IOCTL_KSWORD_ARK_HVM_VIEW \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_VIEW, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_VIEW_OP_ADD    1UL
#define KSWORD_ARK_HVM_VIEW_OP_REMOVE 2UL
#define KSWORD_ARK_HVM_VIEW_OP_CLEAR  3UL
#define KSWORD_ARK_HVM_VIEW_OP_QUERY  4UL

/* Execution sees the real page; reads and writes see the shadow. */
#define KSWORD_ARK_HVM_VIEW_KIND_CLOAK 1UL
/* Reads and writes see the real page; execution runs from the shadow. */
#define KSWORD_ARK_HVM_VIEW_KIND_HOOK  2UL

#define KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED 0x00000001UL
/* Seed the shadow from the target page instead of the supplied bytes. */
#define KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET 0x00000002UL
/* Seed the shadow with zeroes instead of the supplied bytes. */
#define KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO 0x00000004UL
/* Record every view flip in the HVM event ring. */
#define KSWORD_ARK_HVM_VIEW_FLAG_LOG 0x00000008UL

#define KSWORD_ARK_HVM_VIEW_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED          6UL
/* The page already carries a view or an EPT rule; they cannot share a leaf. */
#define KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT         7UL
/* CLOAK needs execute-only EPT leaves, which this processor cannot encode. */
#define KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED 8UL
/* Views flip the shared leaf, so more than one resident VCPU is refused. */
#define KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE 9UL
#define KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED       10UL

typedef struct _KSWORD_ARK_HVM_VIEW_ROW
{
    unsigned long viewId;
    unsigned long kind;
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long long shadowPhysicalAddress;
    /* Times the leaf flipped to the secondary view since installation. */
    unsigned long long flipCount;
} KSWORD_ARK_HVM_VIEW_ROW;

typedef struct _KSWORD_ARK_HVM_VIEW_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long kind;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long viewId;
    unsigned long expectedGeneration;
    unsigned long long physicalAddress;
    unsigned char shadow[KSWORD_ARK_HVM_VIEW_PAGE_BYTES];
} KSWORD_ARK_HVM_VIEW_REQUEST;

typedef struct _KSWORD_ARK_HVM_VIEW_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long viewId;
    unsigned long viewCount;
    unsigned long generation;
    unsigned long returnedRows;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_HVM_VIEW_ROW rows[KSWORD_ARK_HVM_MAX_VIEWS];
} KSWORD_ARK_HVM_VIEW_RESPONSE;

/*
 * MSR policy.
 *
 * The MSR bitmap installed by P0 passes every MSR through natively, which is
 * what makes residency survivable.  A policy punches a hole in it: the named
 * MSR starts exiting again, and the dispatcher applies the configured action
 * instead of the native access.
 *
 * Writes are deliberately more restricted than reads.  Replaying an arbitrary
 * WRMSR in VMX root would fault on the host IDT with no continuation if the
 * value were illegal, so a write policy can only deny the access or swallow
 * it - never "log it and let it through".  Reads are replayed under structured
 * exception handling and fall back to an injected #GP.
 *
 * Only indices the bitmap actually covers can carry a policy: 0x00000000-
 * 0x00001FFF and 0xC0000000-0xC0001FFF.  Anything outside those ranges exits
 * unconditionally and is handled as an undefined MSR.
 */
#define KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION 1UL

/* Bound the number of simultaneously installed MSR policies. */
#define KSWORD_ARK_HVM_MAX_MSR_POLICIES 64UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_MSR_POLICY 0x8BCUL
#define IOCTL_KSWORD_ARK_HVM_MSR_POLICY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_MSR_POLICY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_MSR_POLICY_OP_ADD    1UL
#define KSWORD_ARK_HVM_MSR_POLICY_OP_REMOVE 2UL
#define KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR  3UL
#define KSWORD_ARK_HVM_MSR_POLICY_OP_QUERY  4UL

/* Intercept guest reads of the MSR. */
#define KSWORD_ARK_HVM_MSR_ACCESS_READ  0x00000001UL
/* Intercept guest writes of the MSR. */
#define KSWORD_ARK_HVM_MSR_ACCESS_WRITE 0x00000002UL

/* Record the access and then perform it natively. Reads only. */
#define KSWORD_ARK_HVM_MSR_ACTION_LOG    1UL
/* Refuse the access by injecting #GP, exactly as an undefined index would. */
#define KSWORD_ARK_HVM_MSR_ACTION_DENY   2UL
/* Return the configured value for reads; discard the value for writes. */
#define KSWORD_ARK_HVM_MSR_ACTION_FAKE   3UL

#define KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED 0x00000001UL

#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_TABLE_FULL            5UL
/* The index falls outside the two ranges the architectural bitmap covers. */
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_INDEX_UNCOVERED       6UL
/* A write policy cannot replay the access, so LOG is refused for writes. */
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_WRITE_LOG_UNSAFE      7UL
/* Policies edit the shared bitmap, so they are refused while resident. */
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_RESIDENT_BUSY         8UL
#define KSWORD_ARK_HVM_MSR_POLICY_STATUS_DUPLICATE             9UL

typedef struct _KSWORD_ARK_HVM_MSR_POLICY_ROW
{
    unsigned long policyId;
    unsigned long msrIndex;
    unsigned long access;
    unsigned long action;
    unsigned long long fakeValue;
    /* Times the dispatcher applied this policy since installation. */
    unsigned long long hitCount;
} KSWORD_ARK_HVM_MSR_POLICY_ROW;

typedef struct _KSWORD_ARK_HVM_MSR_POLICY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long policyId;
    unsigned long msrIndex;
    unsigned long access;
    unsigned long action;
    unsigned long expectedGeneration;
    unsigned long long fakeValue;
} KSWORD_ARK_HVM_MSR_POLICY_REQUEST;

typedef struct _KSWORD_ARK_HVM_MSR_POLICY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long policyId;
    unsigned long policyCount;
    unsigned long returnedRows;
    unsigned long generation;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_HVM_MSR_POLICY_ROW rows[KSWORD_ARK_HVM_MAX_MSR_POLICIES];
} KSWORD_ARK_HVM_MSR_POLICY_RESPONSE;

/*
 * Control- and debug-register policy.
 *
 * CR0 and CR4 protection works through the VMCS guest/host masks: a masked bit
 * is owned by the hypervisor, the guest reads it from a shadow, and any attempt
 * to change it exits.  That is how CR0.WP or CR4.SMEP can be pinned against a
 * rootkit that would otherwise just clear them.
 *
 * CR3-load exiting is the only way to observe every address-space switch, and
 * it is also the most expensive control in this protocol: Windows switches CR3
 * thousands of times per second, and each switch becomes a VM exit.  It is off
 * by default and the UI says what it costs.
 *
 * Like MSR policy and EPT views, this configuration is consumed when the VMCS
 * is built, so it must be set before residency starts.
 */
#define KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_CR_POLICY 0x8BDUL
#define IOCTL_KSWORD_ARK_HVM_CR_POLICY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_CR_POLICY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_CR_POLICY_OP_SET   1UL
#define KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR 2UL
#define KSWORD_ARK_HVM_CR_POLICY_OP_QUERY 3UL

#define KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED 0x00000001UL
/*
 * Observe every address-space switch.  Expensive: each CR3 load becomes a VM
 * exit, and Windows performs thousands per second.
 */
#define KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3 0x00000002UL
/* Intercept guest access to the debug registers. */
#define KSWORD_ARK_HVM_CR_POLICY_FLAG_INTERCEPT_DR 0x00000004UL
/* Record every intercepted control-register access in the event ring. */
#define KSWORD_ARK_HVM_CR_POLICY_FLAG_LOG 0x00000008UL

#define KSWORD_ARK_HVM_CR_POLICY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_NOT_PREPARED          3UL
/* The masks are consumed when the VMCS is built, so residency blocks changes. */
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_RESIDENT_BUSY         4UL
/* A pinned bit must be one the fixed-bit MSRs allow the guest to hold. */
#define KSWORD_ARK_HVM_CR_POLICY_STATUS_BIT_NOT_PINNABLE      5UL

typedef struct _KSWORD_ARK_HVM_CR_POLICY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    /* Bits the guest must not change; it reads them from the shadow. */
    unsigned long long cr0PinnedMask;
    unsigned long long cr4PinnedMask;
} KSWORD_ARK_HVM_CR_POLICY_REQUEST;

typedef struct _KSWORD_ARK_HVM_CR_POLICY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long flags;
    unsigned long generation;
    unsigned long reserved;
    unsigned long long cr0PinnedMask;
    unsigned long long cr4PinnedMask;
    /* Value each pinned register held when the policy was installed. */
    unsigned long long cr0PinnedValue;
    unsigned long long cr4PinnedValue;
    /* Times a guest write to a pinned bit was refused. */
    unsigned long long refusedWriteCount;
    /* Times an address-space switch was observed. */
    unsigned long long cr3SwitchCount;
    /* Times debug-register access was intercepted. */
    unsigned long long debugAccessCount;
    long lastStatus;
    unsigned long reserved2;
} KSWORD_ARK_HVM_CR_POLICY_RESPONSE;

/*
 * EPT execution domains.
 *
 * A domain is a fork of the default identity view, published in the EPTP list
 * so guest code can switch onto it with one VMFUNC.  That last part is the
 * whole design constraint: VMFUNC performs no CPL check, so every domain in
 * the list is reachable by unprivileged code in any process, without a VM exit
 * and without the driver being notified.
 *
 * The interface therefore offers exactly one editing direction.  A domain is
 * born byte-for-byte identical to the default view and can only have
 * permissions REMOVED.  There is no operation that grants anything, so a
 * thread that switches into a domain can never end up with access it did not
 * already have - the worst it can do to itself is take an EPT violation.
 *
 * Domains are also inert until residency is started with ENABLE_VMFUNC.
 * Building the list costs a page and changes nothing on its own.
 */
#define KSWORD_ARK_HVM_DOMAIN_PROTOCOL_VERSION 1UL

/* Bound the domains a caller may enumerate in one response. */
#define KSWORD_ARK_HVM_MAX_DOMAIN_ROWS 8UL

/*
 * Read-only platform probe.
 *
 * The rationale is narrow: there are three quantities that can independently veto the path of 'returning from virtualization to user
 * mode', yet the repository has never recorded their measured values on the target machine — CR4.CET (if shadow stacks are enabled).
 * ring-3 IRET has its own protocol (IA32_U_CET/IA32_PL3_SSP are not VMCS fields), KVA shadow
 * (if enabled, GUEST_CR3 is the user shadow PML4 upon user-mode exit; writing it back after
 * VMXOFF erases the kernel), and whether GS base is actually what we think it is.
 *
 * This IOCTL is **read-only**: it does not enter VMX, does not modify any execution path, does not allocate, and does not lock.
 * Each value is paired with a 'read-ack' bit, because 0 is a valid value for
 * many things—using a failed read as 0 is worse than not reading at all.
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_PLATFORM 0x8BFUL
#define IOCTL_KSWORD_ARK_HVM_PLATFORM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_PLATFORM, METHOD_BUFFERED, FILE_READ_ACCESS)

#define KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION 1UL

/* Each valid bit corresponds to a successful field read; one bit per field, with no global switch. */
#define KSWORD_ARK_HVM_PLATFORM_VALID_CR4        0x00000001UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_S_CET      0x00000002UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_U_CET      0x00000004UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_FS_BASE    0x00000008UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_GS_BASE    0x00000010UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_KERNEL_GS  0x00000020UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_CPUID7     0x00000040UL
#define KSWORD_ARK_HVM_PLATFORM_VALID_EFER       0x00000080UL
/* All eight fields must be read to complete calibration; missing any one means this round fails its purpose. */
#define KSW_PLATFORM_VALID_ALL                   0x000000FFUL

typedef struct _KSWORD_ARK_HVM_PLATFORM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_HVM_PLATFORM_REQUEST;

typedef struct _KSWORD_ARK_HVM_PLATFORM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    /* Which fields were actually read. See KSWORD_ARK_HVM_PLATFORM_VALID_*. */
    unsigned long validMask;
    /* Exception code thrown when reading a field; 0 if no exception is thrown. */
    unsigned long exceptionCode;
    /* CR4；bit23 = CET。 */
    unsigned long long cr4;
    /* IA32_S_CET (0x6A2): Kernel shadow stack control. */
    unsigned long long supervisorCet;
    /* IA32_U_CET (0x6A0): User shadow stack control. */
    unsigned long long userCet;
    /* IA32_FS_BASE (0xC0000100)。 */
    unsigned long long fsBase;
    /* IA32_GS_BASE (0xC0000101): In kernel mode, it should be KPCR. */
    unsigned long long gsBase;
    /* IA32_KERNEL_GS_BASE (0xC0000102): in kernel mode, it should be the user TEB. */
    unsigned long long kernelGsBase;
    /* IA32_EFER (0xC0000080)。 */
    unsigned long long efer;
    /* CPUID.(EAX=7,ECX=0)：ECX bit7 = CET_SS，EDX bit20 = CET_IBT。 */
    unsigned long cpuid7Ecx;
    unsigned long cpuid7Edx;
    /* IRQL at the time of sampling, used to confirm this is indeed a PASSIVE_LEVEL reading. */
    unsigned long irql;
    unsigned long reserved2;
} KSWORD_ARK_HVM_PLATFORM_RESPONSE;

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_DOMAIN 0x8BEUL
#define IOCTL_KSWORD_ARK_HVM_DOMAIN \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_DOMAIN, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/* Fork one domain from the default view. */
#define KSWORD_ARK_HVM_DOMAIN_OP_CREATE   1UL
/* Remove permissions from one physical range inside one domain. */
#define KSWORD_ARK_HVM_DOMAIN_OP_RESTRICT 2UL
/* Release every domain and unpublish the whole list. */
#define KSWORD_ARK_HVM_DOMAIN_OP_RESET    3UL
/* Report the current domains without changing anything. */
#define KSWORD_ARK_HVM_DOMAIN_OP_QUERY    4UL

#define KSWORD_ARK_HVM_DOMAIN_FLAG_UI_CONFIRMED 0x00000001UL

#define KSWORD_ARK_HVM_DOMAIN_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_TABLE_FULL            5UL
/* Denying read requires execute-only translation the processor lacks. */
#define KSWORD_ARK_HVM_DOMAIN_STATUS_EXECUTE_ONLY_UNSUPPORTED 6UL
#define KSWORD_ARK_HVM_DOMAIN_STATUS_RESOURCE_FAILED       7UL
/* The processor does not offer EPTP switching, so a list would be inert. */
#define KSWORD_ARK_HVM_DOMAIN_STATUS_UNSUPPORTED           8UL
/* Domains cannot be edited while residency holds the tables live. */
#define KSWORD_ARK_HVM_DOMAIN_STATUS_RESIDENT_ACTIVE       9UL

typedef struct _KSWORD_ARK_HVM_DOMAIN_ROW
{
    unsigned long domainIndex;
    /* Nonzero when the slot holds a live domain. */
    unsigned long active;
    /* Paging structures this domain forked away from the shared hierarchy. */
    unsigned long privateTableCount;
    unsigned long reserved;
    /* EPT pointer published in the list slot; zero when the slot is unused. */
    unsigned long long eptPointer;
} KSWORD_ARK_HVM_DOMAIN_ROW;

typedef struct _KSWORD_ARK_HVM_DOMAIN_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long domainIndex;
    /* Permissions to remove, using the EPT_ACCESS bits. */
    unsigned long deniedAccess;
    unsigned long long physicalAddress;
    unsigned long long byteCount;
} KSWORD_ARK_HVM_DOMAIN_REQUEST;

typedef struct _KSWORD_ARK_HVM_DOMAIN_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long domainIndex;
    unsigned long domainCount;
    unsigned long generation;
    unsigned long returnedRows;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    unsigned long long featureFlags;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_DOMAIN_ROW rows[KSWORD_ARK_HVM_MAX_DOMAIN_ROWS];
} KSWORD_ARK_HVM_DOMAIN_RESPONSE;

/*
 * R-1 layer process handling.
 *
 * The word "process" in the name requires careful interpretation: the hypervisor does not recognize processes; it only sees CR3 and guest physical pages.
 * This path's purpose is to **reject execution in the target address space**, then decide what to tell the guest upon rejection.
 * The difference between the two operations lies only in which vector is injected:
 *
 *   Freeze injection #PF (present=1). The faulting instruction never retires, and the process state remains unchanged
 *         by a single byte. Removing the rule allows it to resume from the exact spot. This is true suspension—the essence
 *         of reversibility distinguishes it from termination, not a matter of degree. The cost is explicit: the frozen
 *         thread spins on the fault, consuming its time slice. The machine does not hang, but that core idles.
 *   Ends the #UD injection. If the user-mode handler doesn't process the exception, Windows follows its own process teardown path.
 *         We do not call any kernel APIs; the process is terminated by the guest itself.
 *
 * Scope is determined by CR3 rather than per-page permission checks: The channel remains open for CR3 load/exiting. When the
 * address space switches in, it selects the restricted hierarchy; when it switches out, it selects the base hierarchy. This ensures
 * the non-target process never runs under the restricted hierarchy, eliminating the need for MTF-based flip-flopping ("deny once,
 * allow once"). Since nested target machines lack MTF support, the per-page permission check path cannot function there.
 *
 * **Not a security boundary.** Shares the same nature as stealth hooks: failure implies allow. If the target process can remap
 * its own code page to a different guest physical page (via relocation, self-modification, or remapping), it is no longer on
 * the page being denied; code capable of modifying CR3 is also unconstrained by this mechanism. This is a handling path
 * outside R0, used to take action when kernel APIs are blocked, not to defend against an adversary aware of its existence.
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_PROCESS 0x90FUL
#define IOCTL_KSWORD_ARK_HVM_PROCESS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_PROCESS, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/*
 * Version 2 adds CR3 attribution (OP_RESOLVE_CR3).
 *
 * Since requests and responses have grown, the version must be updated: old interfaces paired with new drivers will be
 * rejected immediately due to size mismatches, which is the desired outcome. These structures contain process identities;
 * a silent misread of 'a few bytes more or less' would incorrectly attribute an access to a different process.
 */
#define KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION 2UL

/* Read-only current disposition table. */
#define KSWORD_ARK_HVM_PROCESS_OP_QUERY     0UL
/* Freeze: reject execution + inject #PF, reversible. */
#define KSWORD_ARK_HVM_PROCESS_OP_FREEZE    1UL
/* Terminate: reject execution + inject #UD, irreversible. */
#define KSWORD_ARK_HVM_PROCESS_OP_TERMINATE 2UL
/*
 * Revoke a disposition.
 *
 * When resident and stopped, this performs a full revoke: clear records and release hierarchy. While resident,
 * this is a **release**: records and hierarchy remain, but no one will switch into them, and the core spinning in
 * a restricted hierarchy will revert the EPT_POINTER to the base on its next violation and continue execution.
 *
 * Two scenarios are not conservative: releasing pages at a certain level while a core is actively referencing them
 * during residency causes memory corruption with no symptoms; clearing records while a core spins leaves frozen threads
 * frozen forever—thus 'unfreezing' would require shutting down the entire hypervisor, rendering it only half-functional.
 */
#define KSWORD_ARK_HVM_PROCESS_OP_RELEASE   3UL
/*
 * Released but hierarchy not yet reclaimed. Will only appear on records revoked during residency.
 *
 * As an explicit state rather than directly clearing the record: the exit path relies on 'this page belongs to a
 * released disposition' to know to switch the pointer back to the base; if the record is cleared, it knows nothing.
 */
#define KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED 3UL
/* Clear the entire table. */
#define KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL 4UL
/*
 * Associate an observed CR3 with a specific process. Read-only; do not touch any HVM state.
 *
 * The reason for existence is memory monitoring: when a hit occurs, the recorded CR3 is meaningless to users.
 * However, this **must be done in the driver**—the criterion is the register value read after attaching; user
 * mode cannot read other processes' CR3 values, nor is there any other way to obtain the same criterion.
 *
 * This path does not return the CR3 of any process; it only returns 'which PID's CR3 matches the one provided'.
 * The direction is one-way: the caller must already have a CR3 to query
 * anything, and the only source of that CR3 is a self-installed monitor hit.
 *
 * The result is best-effort, and every item listed in §11 holds true: PIDs get recycled, address spaces
 * disappear between events and resolution, kernel worker threads borrow other address spaces, and under
 * KVA Shadow, user mode and kernel mode do not use the same CR3. Therefore, the protocol only reports 'how
 * many were scanned' and 'who matched,' leaving the UI to label them as inferred rather than factual.
 */
#define KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3 5UL

#define KSWORD_ARK_HVM_PROCESS_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED 2UL
/*
 * Resident and running, but installation requires it to be stopped.
 *
 * Using 3 is not arbitrary: this code was originally named NOT_RESIDENT, shared by two conditions, but the actual
 * occurrence is almost always this one (residency is established before the process is handled). Keeping it at 3 ensures
 * that when the new interface configures an old driver, the advice remains correct; reversing the numbering would cause the
 * interface to say "not yet prepared" in that window—exactly opposite to reality, leading users further astray if followed.
 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED 3UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED 4UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND             6UL
#define KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED         7UL
/*
 * Missing CR3-load exiting. The scope depends entirely on it: without it, we cannot determine which address space is running. Rejecting
 * would apply to the entire machine rather than a single process—that is a scenario requiring execution denial, not a downgrade.
 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED 8UL
/* Missing EPTP switch backend; without a second level, the 'restricted' option is unavailable. */
#define KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED  9UL
/* Translation of that page in the target address space to a guest physical address failed. */
#define KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED    10UL
/* Refuse to act on self or system processes. */
#define KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET      11UL
/*
 * The driver has not been prepared yet; nothing exists in the runtime.
 *
 * Split into two separate codes because they represent opposite actions: one is 'not started yet, prepare first',
 * the other is 'running, stop first'. Merging them into a single code named NOT_RESIDENT was worse—the name
 * described the exact opposite of the actual condition, causing troubleshooting to proceed in the wrong direction.
 */
#define KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED          12UL

/* Table upper limit. Each entry occupies one EPT restricted level; the number of levels is determined by the EPTP list capacity. */
#define KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS 8UL

typedef struct _KSWORD_ARK_HVM_PROCESS_ROW
{
    /* Specify the PID for the disposition action. Since the PID may be recycled, the check is based on directoryBase not matching it. */
    unsigned long processId;
    /* The disposition type for this entry takes OP_FREEZE or OP_TERMINATE. */
    unsigned long disposition;
    /* Target address space. Lower bits of PCID/flags are masked, leaving only hierarchical physical page frames. */
    unsigned long long directoryBase;
    /* Guest physical address of the page that was denied execution. */
    unsigned long long guestPhysicalAddress;
    /* The guest linear address provided during dispatch, used to trace how this page was selected. */
    unsigned long long guestLinearAddress;
    /* Number of times this entry has been intercepted. If frozen, it will continue to grow, which is evidence of spinning. */
    unsigned long long interceptCount;
    /* The restricted hierarchy index occupied by this entry. */
    unsigned long hierarchyIndex;
    unsigned long reserved;
} KSWORD_ARK_HVM_PROCESS_ROW;

typedef struct _KSWORD_ARK_HVM_PROCESS_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long processId;
    /*
     * Guest linear address to be rejected. Setting to 0 indicates the driver should fetch the entry page of the process's main image.
     *
     * Allowing the caller to specify is because there is no universal answer to 'which page represents this
     * process': the entry page is valid for a freshly started process but may not be executed again for a
     * process already running in a message loop; rejecting an unexecuted page is equivalent to doing nothing.
     */
    unsigned long long guestLinearAddress;
    /*
     * OP_RESOLVE_CR3: The CR3 to be attributed. All other operations must be zero.
     *
     * Use a separate field instead of guestLinearAddress: that field represents a linear address in other
     * operations. Both are 64-bit and look like addresses; if passed incorrectly, no error occurs. A comparison
     * expecting a page directory base would silently and permanently fail, appearing as if 'the process has exited'.
     */
    unsigned long long directoryBase;
} KSWORD_ARK_HVM_PROCESS_REQUEST;

typedef struct _KSWORD_ARK_HVM_PROCESS_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long returnedRows;
    unsigned long rowCount;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_PROCESS_ROW rows[KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS];
    /*
     * Result of OP_RESOLVE_CR3. Placed after rows, so offsets of all preceding fields remain unchanged.
     *
     * resolvedProcessId being 0 indicates no match (0 is the Idle process, which will never be the answer).
     */
    unsigned long resolvedProcessId;
    /*
     * Actual count of processes that queried CR3.
     *
     * This must be reported separately from "matched whom"; otherwise, "scanned 180 processes but none matched"
     * and "failed to scan any" appear identical in the UI, yet they require opposite actions: the former
     * indicates the address space no longer exists, while the latter indicates the attribution run never started.
     */
    unsigned long resolvedScannedProcesses;
} KSWORD_ARK_HVM_PROCESS_RESPONSE;

/*
 * R-1 layer process injection.
 *
 * This injection path is **distinct** from the R0 path (ZwAllocateVirtualMemory + ZwCreateThreadEx, see
 * process_inject.c); they are not the same operation with a different label. The R0 path invokes kernel APIs at
 * every step, making each step visible to process/thread creation callbacks, image load callbacks, PatchGuard,
 * and EDR. This path invokes no kernel APIs and adds no threads or memory regions to the target process.
 *
 * Mechanism is **separated view + thread hijacking**, in four steps:
 *
 *   1. Select a page in the target address space that is already executable and will be executed.
 *   2. Create a shadow page = a full copy of the real page + inject payload into its gaps (tail padding, code cave);
 *   3. Install a KIND_HOOK view: **Read/Write/Execute access the real page, but execution runs on the
 *      shadow page**. Consequently, the payload exists only in the execution view; any read operation on
 *      this page (integrity checks, memory dumps, or self-inspection) sees the unmodified original bytes.
 *   4. On a controlled VM exit, point RIP to the shadow payload location;
 *      after payload execution, jump back to the original instruction.
 *
 * **Do not create new mappings or modify guest page tables.** That path competes with Windows' memory manager for the same page
 * tables: PTEs we insert can be reclaimed at any time, and reclamation happens in places we cannot see, causing the target to
 * crash at an unpredictable moment. Writing into gaps within existing executable pages avoids touching any management structures.
 *
 * Hard constraints on the payload
 *
 * The payload executes at an arbitrary instruction boundary of an arbitrary thread—not a new thread, but borrowing
 * an existing running thread for a brief moment. This is not an implementation shortcut; it is the essence of this
 * channel: R-1 has no concept of 'creating threads' and can only interject into existing execution flows. Thus:
 *
 *   - Must be position-independent, reentrant, and short. The borrowed thread may hold a lock or be
 *     mid-system call; doing anything blocking or reentrant on the same lock inside will cause a deadlock.
 *   - Do not return via 'ret'. CET shadow stacks are enabled on this machine; return
 *     addresses pushed by the hypervisor do not match the shadow stack, causing a direct #CP
 *     fault. The driver's own wrapper must use absolute jumps to return, avoiding 'ret'.
 *   - Registers and flags are saved and restored by the driver package's shell; the payload itself need not do so, but also
 *     **Do not** assume there are other protections outside the shell.
 *
 * ## This is not a stealth guarantee
 *
 * Shares the same nature as stealth hooks: the execution view can be dismantled by the same means (see stealth hook security boundary decision).
 * This bypasses checks like 'read this page', not an adversary aware of this mechanism.
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_INJECT 0x910UL
#define IOCTL_KSWORD_ARK_HVM_INJECT \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_INJECT, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION 1UL

/* Read-only current injection table. */
#define KSWORD_ARK_HVM_INJECT_OP_QUERY   0UL
/* One-time injection: create shadow, install view, arm trigger. */
#define KSWORD_ARK_HVM_INJECT_OP_ARM     1UL
/* Revoke a single operation: Detach the view and cancel the trigger. Payloads that have already been executed cannot be revoked. */
#define KSWORD_ARK_HVM_INJECT_OP_RELEASE 2UL
/* Clear the entire table. */
#define KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL 3UL

/*
 * Upper limit of the payload body.
 *
 * The shadow page is only one page in size. The shellcode (which saves/restores registers and flags, plus an absolute jump
 * back) takes up dozens of bytes, and the original content of the real page must remain untouched within that page. Only the
 * gaps are usable. We use 1024 instead of "whatever remains": a limit that floats with the target page's content would cause
 * the same payload to fit in one process but fail in another, making the failure reason appear unrelated to the payload.
 */
#define KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES 1024UL

/*
 * Two payload types, maintaining the same classification as the R0 injection.
 *
 * SHELLCODE is the primitive for this channel: position-independent machine code running on a borrowed thread.
 * DLL_PATH is a higher-level abstraction: the shellcode places the path address in RCX and then
 * calls LoadLibraryW provided by the caller. We support two types instead of just shellcode
 * because "injecting a DLL" is the actual operation; requiring each caller to manually
 * construct machine code to call LoadLibraryW would duplicate error-prone code many times.
 */
#define KSWORD_ARK_HVM_INJECT_TYPE_SHELLCODE 1UL
#define KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH  2UL

/*
 * The gap must be at least this long to be recognized.
 *
 * A gap that is too short is likely not padding but just consecutive zero bytes in actual code; writing into it would crash the target.
 */
#define KSWORD_ARK_HVM_INJECT_MIN_CAVE_BYTES 64UL

#define KSWORD_ARK_HVM_INJECT_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED          2UL
#define KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED 3UL
#define KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED 4UL
#define KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED    5UL
#define KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL            6UL
#define KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND             7UL
#define KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED         8UL
#define KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET      9UL
/* Prerequisite: scope relies on CR3-load exiting; without it, the rejection would apply to the entire machine rather than a single process. */
#define KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED 10UL
/* Prerequisite: View execution and restricted hierarchy are both provided by the EPTP switch backend. */
#define KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED  11UL
/* No sufficiently large gap can be found in this page to place the shellcode payload. */
#define KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE               12UL
/* Inject view execution failed. */
#define KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED           13UL
/* The target page is non-executable: placing the payload in a page that will never be executed is equivalent to doing nothing. */
#define KSWORD_ARK_HVM_INJECT_STATUS_PAGE_NOT_EXECUTABLE   14UL

#define KSWORD_ARK_HVM_MAX_INJECTIONS 4UL

typedef struct _KSWORD_ARK_HVM_INJECT_ROW
{
    /* PID at dispatch. PID is reclaimed based on directoryBase. */
    unsigned long processId;
    /* Payload body length. */
    unsigned long payloadBytes;
    /* Target address space; the lower bits of PCID and flags are masked. */
    unsigned long long directoryBase;
    /* Guest linear address (page-aligned) of the page being hijacked. */
    unsigned long long guestLinearAddress;
    /* Guest physical address of the page. */
    unsigned long long guestPhysicalAddress;
    /* Offset of the shellcode within the page, i.e., the location where RIP will be pointed. */
    unsigned long caveOffset;
    /* Total bytes occupied by the shell loader. */
    unsigned long caveBytes;
    /* Number of times the payload has been executed. Should be 1 after one-time injection completes. */
    unsigned long long executionCount;
    /* The execution view identifier occupied by this injection. */
    unsigned long viewId;
    /*
     * The type of padding byte constituting this gap: 0x00 / 0xCC / 0x90.
     *
     * Reporting it enables attribution: 0xCC and 0x90 are compiler-inserted alignment padding between functions; 0x00 is mostly
     * section tails or uninitialized regions. When an issue occurs, 'which type is used' determines what to suspect—for
     * example, if an incident happens on 0xCC where padding was expected, investigate whether data was actually embedded there.
     */
    unsigned long caveFiller;
} KSWORD_ARK_HVM_INJECT_ROW;

typedef struct _KSWORD_ARK_HVM_INJECT_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long processId;
    /*
     * Any guest linear address within the page to be hijacked. **Required**.
     *
     * The driver does not guess which page will be executed. There is no universal answer to "which page will be executed," and guessing
     * wrong results in the payload being loaded but never executed—indistinguishable from success from the outside. The caller can answer
     * better: take the location currently being executed by a specific thread of the target; that page **by definition** will be executed.
     *
     * The driver cannot determine this answer: the user-mode RIP must be retrieved from the thread's trap frame, which
     * is trivial for the caller in PASSIVE context but would require significant overhead for the driver to handle.
     */
    unsigned long long guestLinearAddress;
    /* See KSWORD_ARK_HVM_INJECT_TYPE_*. */
    unsigned long injectType;
    /* Length of the payload body, excluding the driver package wrapper. */
    unsigned long payloadBytes;
    /*
     * DLL-specific: Customer linear address of LoadLibraryW in the target process.
     *
     * Parsed by the caller, not the driver: The base address of the same DLL differs across
     * processes, and the caller is already enumerating the target module table. Having the
     * driver parse it again duplicates work and risks inconsistency with what the caller sees.
     */
    unsigned long long loadLibraryAddress;
    /*
     * Payload body.
     *
     * SHELLCODE: position-independent, reentrant machine code; registers and flags are saved and restored by the shell.
     * DLL_PATH: A null-terminated UTF-16 path. The shell places its address into
     *           RCX before calling loadLibraryAddress. The call and its corresponding ret
     *           are paired, so they do not corrupt the CET shadow stack—only pushing a
     *           return address without a corresponding call would do so.
     */
    unsigned char payload[KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES];
} KSWORD_ARK_HVM_INJECT_REQUEST;

typedef struct _KSWORD_ARK_HVM_INJECT_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long returnedRows;
    unsigned long rowCount;
    unsigned long generation;
    long lastStatus;
    unsigned long reserved;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_INJECT_ROW rows[KSWORD_ARK_HVM_MAX_INJECTIONS];
} KSWORD_ARK_HVM_INJECT_RESPONSE;

/*
 * Nested VMX self-test.
 *
 * ## Why this must be done in the driver
 *
 * VMX instructions can only execute at CPL 0, so this section cannot be constructed from existing IOCTLs in the tool like probe-xonly
 * does. What it needs to verify is exactly whether "our nested dispatch correctly services the guest when it executes VMX instructions
 * according to architectural semantics" — which requires someone to actually execute a VMX instruction in the **guest context**.
 *
 * It is not contradictory for the driver to perform this operation: the driver's L0 component runs in VMX
 * root, while this IOCTL path runs inside the guest. Executing VMXON in the guest inevitably triggers a
 * VM exit, which is handled by our own dispatch logic—this is precisely the object under test.
 *
 * ## Hard prerequisite
 *
 * When nested dispatch is disabled, `kswordArkHvmNestedHandleExit` returns 'not handled', and the exit path
 * injects a #UD. Since that #UD lands in our own kernel code, it causes a BSOD. Therefore, this command must
 * be rejected when nested mode is disabled or the processor is not resident, rather than 'trying it out'.
 *
 * Similarly, executing VMXON without setting CR4.VMXE triggers a #UD. A read-back confirmation is required before proceeding.
 */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PROBE 0x911UL
#define IOCTL_KSWORD_ARK_HVM_NESTED_PROBE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PROBE, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION 1UL

/* The entire self-check completed successfully (each step's result still needs to be reviewed individually). */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK 0UL
/* The request itself violates the contract. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_INVALID_REQUEST 1UL
/* Missing UI_CONFIRMED. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIRMATION_REQUIRED 2UL
/* This processor is not resident, or nested dispatch is disabled—proceeding would crash the system. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NOT_ARMED 3UL
/* Failed to allocate the two pages required for self-check. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NO_RESOURCES 4UL
/* Note: CR4.VMXE cannot be set; subsequent steps will not execute. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_VMXE_REFUSED 5UL
/* A required VMCS12 configuration write failed; L2 was not entered. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIGURATION_FAILED 6UL

/* This step was never executed. */
#define KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED 3UL

/*
 * Run concurrently on **every** processor, not just the current one.
 *
 * Single-core success does not guarantee multi-core success: each core has its own vmcs02, shadow hierarchy, and mapping windows, which are structurally
 * independent. This project has already encountered issues due to 'structural independence' multiple times (e.g., stale tags for shared EPT roots).
 * fail-closed: Stops only one core. Concurrency is the only way to turn this statement into a read.
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_FLAG_ALL_PROCESSORS 0x00010000UL
/*
 * Instruct the L1 probe to request accessed/dirty bits in the EPT12 pointer to verify the **denial**.
 *
 * This is a negative test case: A/D must be blocked at the step where shadow layers are armed, not allowed
 * through and then having the hardware place it in our shadow leaf, causing L1 to read its own EPT12 and find
 * all zeros. In the latter case, no reads change, and L1 will skip pages that the guest actually modified.
 *
 * Expected result: VMLAUNCH returns Intel error 7 (invalid control field), and 'L2 executed' is false.
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_FLAG_REQUEST_AD 0x00020000UL
/*
 * Let L1 virtualize the **currently running context**, not a toy code snippet.
 *
 * This is the boundary between "whether we can support a real hypervisor" and "whether we can support the
 * L2 micro-program we wrote." A real hypervisor (our own resident path, VMware's VMM) does the same thing:
 * Capture the current processor state, redirect the VMCS guest RIP to the instruction immediately following itself,
 * and execute VMLAUNCH, so **it** becomes the guest. The toy L2 uses synthesized RIP, a synthesized stack, and a
 * one-page identity-mapped code segment; segment registers, CR3, and page tables need not be taken seriously.
 *
 * Use a separate flag instead of replacing the original L2: The MSR routing criterion depends on instruction offsets
 * determined by the L2 program. Replacing it would dismantle a hard-won, already-green criterion to adopt a new one.
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_FLAG_SELF_VIRTUALIZE 0x00040000UL

/*
 * Three meaningful breakpoints in the L2 program, specified as byte offsets from the start of the code page.
 *
 * Placed in the protocol header rather than hardcoding separately because it follows a **build-then-verify** pattern: the driver arranges
 * instructions based on these offsets, and the tool interprets `l2RipOffset` using the same offsets. If written separately, a one-byte
 * change in the program's encoding would not trigger an error in the verification logic, but would instead cause incorrect results.
 *
 *   TRAPPED = second RDMSR. Stopping here confirms the processor is indeed checking the L1 bitmap.
 *   OPEN = First RDMSR. If execution halts here despite being allowed, it indicates a fallback page for 'block all' checks.
 *   FALLBACK = CPUID. Reaching here indicates MSR interception never occurred.
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_RIP_OPEN_MSR 5ULL
#define KSWORD_ARK_HVM_NESTED_PROBE_RIP_TRAPPED_MSR 12ULL
#define KSWORD_ARK_HVM_NESTED_PROBE_RIP_CPUID 14ULL

/* Maximum number of rows for per-core results. */
#define KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS 64UL

typedef struct _KSWORD_ARK_HVM_NESTED_PROBE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long confirmationToken;
} KSWORD_ARK_HVM_NESTED_PROBE_REQUEST;

/* All readings from a processor's previous complete self-test. */
typedef struct _KSWORD_ARK_HVM_NESTED_PROBE_ROW
{
    unsigned long status;
    unsigned long processorIndex;
    /*
     * Architecture result for each step: 0=success, 1=VMfailValid, 2=VMfailInvalid, 3=not executed.
     *
     * We use architectural values instead of booleans because 'failure' has two distinct meanings: VMfailValid indicates we
     * recognized the instruction and returned an error code, while VMfailInvalid indicates the current VMCS was not even valid.
     * Merging into a single boolean conflates 'dispatched but rejected' with 'never dispatched'.
     */
    unsigned long vmxonResult;
    unsigned long vmptrldResult;
    unsigned long vmwriteResult;
    unsigned long vmreadResult;
    unsigned long vmptrstResult;
    unsigned long vmxoffResult;
    /* Check if the field written and read back matches bit-by-bit. */
    unsigned long vmreadMatched;
    /* Whether the pointer returned by VMPTRST matches the one just loaded via VMPTRLD. */
    unsigned long vmptrstMatched;
    /* The actual value read back; use it for attribution if it does not match. */
    unsigned long long vmreadValue;
    /* Value to write. */
    unsigned long long vmwriteValue;
    /* Number of nested VMX instructions dispatched by this processor during self-check. */
    unsigned long long dispatchedInstructions;
    /* Nested state of this processor at the end of self-check. */
    unsigned long nestedStateAfter;
    /* Intel error code from the last VMfailValid. */
    unsigned long lastInstructionError;
    /* VMLAUNCH architectural result; 0 may also mean 'entered and returned', check l2Reached. */
    unsigned long vmlaunchResult;
    /*
     * L2 has actually started and the exit was reflected back to L1.
     *
     * This bit is the sole positive criterion for the entire chain: a value of 1 indicates that the vmcs02
     * merge was accepted by hardware, L2 executed an instruction, the exit was caught by us, we dispatched it
     * to L1, and the L1 host processor truly regained control. If any link in the chain breaks, the value is 0.
     */
    unsigned long l2Reached;
    /* Exit reason read by L1 from vmcs12; 0x80000021 indicates an invalid guest state. */
    unsigned long long l2ExitReason;
    /* Qualification as above. */
    unsigned long long l2Qualification;
    /* L2 instruction pointer. */
    unsigned long long l2GuestRip;
    /*
     * This indicates whether L2 is running on L1's native EPT12 (1) or on our own hierarchy (0).
     *
     * Report separately because the two branches validate different things: when set to 1, every L2 access must pass
     * through both EPT12 and EPT01, following the shadow-layer composite path; when 0, that path is not involved at all.
     * If this bit is not reported, a single 'L2 completed' reading cannot clarify whether the synthesis was actually verified.
     */
    unsigned long ept12Armed;
    /* Number of leaf pages synthesized by the shadow layer for this run. */
    unsigned long shadowFillCount;
    /* Violations denied by EPT12 itself and passed to L1. */
    unsigned long shadowDenyCount;
    /* Count of failed merges due to page table exhaustion. */
    unsigned long shadowExhaustionCount;
    /*
     * Architectural result of an INVEPT issued by L1.
     *
     * Record separately because it validates something distinct: L1 issuing INVEPT notifies that "a mapping I installed is
     * now invalid," which is its only notification channel—our shadow is discarded only when the EPT pointer itself changes.
     * Note: A failure in this field indicates that the notification was not delivered to L1.
     */
    unsigned long inveptResult;
    /* Whether the shadow generation advanced after INVEPT. */
    unsigned long shadowGenerationAdvanced;
    /*
     * vmcs02 carries the actual control bits and three bitmap addresses at VM entry.
     *
     * This group is **read back**, not computed during the merge process — they differ only when "a
     * field was never written," which is exactly the failure this exposes. Control bits are the union
     * of L1's and ours, so `USE_MSR_BITMAPS` (bit 28) will always remain active because we require it;
     * if the corresponding `msrBitmap` is 0, the processor will use physical page 0 as the MSR bitmap.
     *
     * In this state, no other readings change: VM entry succeeds, L2 continues running, and exits still
     * occur. Only by viewing these two fields together can we determine who decides L2's MSR/IO interception.
     */
    unsigned long vmcs02PrimaryControls;
    unsigned long vmcs02SecondaryControls;
    unsigned long long vmcs02MsrBitmap;
    unsigned long long vmcs02IoBitmapA;
    unsigned long long vmcs02IoBitmapB;
    /*
     * Offset from the start of the code page when L2 stops.
     *
     * This entry itself is the criterion for MSR bitmap merging; no other corroboration is needed. L2 programs involve two.
     * RDMSR: The first L1 bitmap bit is clear (should not exit), while the second is set (should exit).
     *
     *   12 = Stop at second entry — processor checks L1 bitmap; 5 = Stop at
     *    first entry — checks 'all intercept' fallback page, indicating L1 page
     *   read failed; 14 = Reached CPUID — MSR interception never occurred
     *
     * All three outcomes result in an exit and can be successfully reflected; only the stop location distinguishes them.
     */
    unsigned long long l2RipOffset;
    /* Number of L2 MSR exits dispatched to L1 versus those handled locally. */
    unsigned long long l2MsrExitsReflected;
    unsigned long long l2MsrExitsHandled;
    /* Same as above, port exit. */
    unsigned long long l2IoExitsReflected;
    unsigned long long l2IoExitsHandled;
    /* Whether the previous merge read every required page. */
    unsigned long bitmapMergeComplete;
    /* Whether L1 requested MSR bitmap filtering (determines which branch to take for ownership judgment). */
    unsigned long l1UsesMsrBitmap;
    /*
     * L1 requested accessed/dirty in the EPT12 pointer, so it was rejected.
     *
     * Report separately, because once rejected at L1, only a generic 'invalid control field'
     * remains—architecturally correct, but it doesn't specify which control. Without this, 'L2 fails
     * to start' cannot be distinguished as either unsupported capability or a corrupted EPT pointer.
     */
    unsigned long l1RequestedAccessedDirty;
    /*
     * Whether A/D is truly being maintained and rolled back to the L1 table, and how many entries were rolled back.
     *
     * Separate from the previous field: the previous field indicates what L1 **requested**, while these two fields indicate what we **achieved**.
     * The two differ only when the processor does not support the feature or when the record table overflows;
     * these are precisely the scenarios the reader must distinguish. A partial propagation is worse than none:
     * L1 may read "these pages were written, those were not," where the second part is false and undetectable.
     */
    /*
     * Whether each field remains after the two vmcs12 instances alternate.
     *
     * A single VMCS cannot reveal this: the dispatcher models only one vmcs12 yet can still exercise every item above.
     * Real hypervisors (VMware, VirtualBox, Hyper-V) maintain at least one VMCS per vCPU and constantly
     * switch via VMPTRLD. Whether a field survives a single switch is the prerequisite for supporting them.
     *
     * The sequence is the minimal failure case: write A, write B, read A, read B. A dispatcher
     * modeling only one instance will return the value of B (or zero) when A is requested.
     */
    unsigned long vmcsSwitchResult;
    unsigned long vmcsSwitchMatched;
    unsigned long long vmcsSwitchValueA;
    unsigned long long vmcsSwitchValueB;
    unsigned long accessedDirtyActive;
    unsigned long adPropagatedCount;
    unsigned long adOverflowCount;
    /*
     * Cycle counts for bitmap merging and total L2 entry cycles.
     *
     * Report both numbers together because the cost of merging only makes sense as a **share**. 'Three pages copied
     * per entry' is a shape, not a measurement; deciding whether to add a cache based on that shape is a gamble.
     *
     * All are cumulative values; dividing by l2EntryCount yields the mean. RDTSC under the outer hypervisor returns the value
     * it is willing to expose — the ratio of entries within the same invocation is sufficient, but absolute time is not.
     */
    unsigned long long l2MergeCycles;
    unsigned long long l2EntryCycles;
    unsigned long long l2EntryCount;
    /*
     * Actual capacity of the pool for vmcs12 copies, and whether overflowed copies are recorded.
     *
     * The aforementioned pair of 'alternating copies' only proves that **more than one** exists. A real hypervisor often holds a dozen or more
     * copies. The claim that 'we can store N copies' has always been an assertion in header file comments, with no supporting measurements.
     *
     * Approach: Write two distinct values to regions beyond the pool depth, then read them back in reverse order from
     * the most recently used. Reverse reading is mandatory; reading forward would overwrite older entries with each
     * read, destroying the measurement itself and resulting in all zeros, falsely suggesting the pool does not exist.
     *
     * The k-th bit of the mask indicates that the k-th read was returned. Reporting only the count is insufficient:
     * LRU, FIFO, and random eviction can all yield the same survival count, but which specific entries survive
     * differs entirely. This distinction determines whether a vmcs12 frequently used by L1 will be evicted.
     *
     * evictionDelta is the eviction count for this specific processor within this window, taken from its own record rather than the
     * runtime global total. Since each processor runs a worker thread simultaneously, taking the difference from a shared counter
     * would incorrectly attribute work done by other cores to this line, appearing precise but describing a different reality.
     * It exists solely because this counter is always read as 0 elsewhere,
     * and a counter that has never been observed to change is unverified.
     */
    unsigned long long vmcs12DepthMask;
    unsigned long vmcs12DepthRegions;
    unsigned long vmcs12DepthSurvived;
    unsigned long vmcs12EvictionDelta;
    unsigned long vmcs12DepthReserved;
    /*
     * The VMX capabilities read by the guest **at this moment** are taken from the guest context's RDMSR.
     *
     * This is the only location where capability filtering can be falsified. The query interface reports raw values captured
     * at driver load time (via IOCTL, bypassing the MSR bitmap), so it always reflects hardware truth. The two fields below
     * use RDMSR and, once resident, are narrowed by our logic. A discrepancy between the two confirms the filtering is active.
     *
     * Without this entry, the assertion 'we filtered capabilities' is merely a code statement that appears correct. If a
     * bit is missing in the bitmap or the exit route fails to reach the filter function, the behavior remains unchanged.
     */
    unsigned long long guestVmxProcbased2;
    unsigned long long guestVmxEptVpidCap;
    /*
     * L1 wrote; we previously never copied those fields into vmcs02; read
     * back the values from the **currently loaded vmcs02** before entry.
     *
     * Same technique and rationale as the MSR bitmap group: The computed value
     * differs from the value the processor actually uses only when "this field was
     * never written," which is precisely the kind of failure that leaves no trace.
     *
     * The MSR region is one layer more hidden than the bitmap: the bitmap at least has a control bit that theoretically could be
     * omitted, whereas the MSR region's count field is unconditionally effective, with no capability bit to indicate "not supported".
     * L1 intends to load a batch of MSRs when entering L2, but we do not load them;
     * L2 runs with our MSR values, while L1 believes it is using its own batch.
     */
    unsigned long long vmcs02TscOffset;
    unsigned long long vmcs02EntryMsrLoadAddress;
    unsigned long long vmcs02ExitMsrStoreAddress;
    unsigned long vmcs02EntryMsrLoadCount;
    unsigned long vmcs02ExitMsrStoreCount;
    /*
     * Self-virtualization: L1 turns itself into a guest, runs a full cycle, and returns.
     *
     * The three slots represent three arrivals at the same capture point; all three are required:
     *   reachedL2: VM entry succeeded; we are now executing our own code as L2.
     *   exitReason: The reason L1 reads from vmcs12 after the CPUID instruction
     *                  exits in L2; it should be 10. This field proves the exit was correctly
     *                  delivered to L1, not consumed by the outer layer. returnedToL1: L1's host
     *   processor finished running, executed VMXOFF, and restored the context.
     *
     * Checking reachedL2 alone is insufficient: being unable to exit after
     * entering is just as fatal as never entering at all for a real hypervisor.
     */
    unsigned long selfVirtAttempted;
    unsigned long selfVirtReachedL2;
    unsigned long selfVirtReturnedToL1;
    unsigned long selfVirtCpuidPassedThrough;
    /*
     * A marker written by L2 to the slot it found itself, reported separately from the global marker above.
     *
     * The two witnesses ask two different questions: the global marker asks 'Did L2's storage actually enter memory?'
     * (RIP-relative addressing, independent of any inherited state); this slot asks 'Is the path for L2 to find its own
     * slot via GS valid?' Combining them into a single slot would collapse two distinct failure modes into the same 0.
     */
    unsigned long selfVirtSlotMarker;
    unsigned long long selfVirtExitReason;
    unsigned long long selfVirtGuestRip;
    /*
     * Report the entry RIP that L1 wrote into vmcs12 alongside the exit RIP.
     *
     * This must be compared **within the same run**. The driver's base address changes on each
     * load, so comparing absolute addresses across two runs proves nothing—I once misjudged
     * this, mistaking "addresses move when I change code" for "L2 is running our code."
     *
     * The difference between the two is the answer: a difference of a few dozen bytes confirms L2 started exactly where
     * we specified and reached that CPUID; a wildly different difference means it didn't start from there at all.
     */
    unsigned long long selfVirtEntryRip;
    /*
     * Number of L2 entries and exits dispatched to L1 in this round.
     *
     * "Exit reason is 10 and returned to L1" cannot express **how many exits occurred**. A
     * clean round-trip and "consumed once by ourselves, then L2 runs, followed by a reflection"
     * appear identical when reading a single exit reason, yet their meanings are opposite.
     */
    unsigned long selfVirtEntryCount;
    unsigned long selfVirtReflectCount;
    /*
     * **All** exit counts for L2, and the count of L1 resuming L2.
     *
     * The difference between total exits and dispatched exits represents exactly how many exits were consumed by us,
     * which the L1 never knew its guest asked about. This is the crux of nested correctness: we answer the L1's guest
     * on its behalf, and the L1 remains unaware. Counting only dispatched exits will never reveal this difference.
     *
     * Resume count listed separately: the return path uses VMRESUME instead of VMLAUNCH — different instructions, different behavior.
     * Launch-state check. A vmcs12 that passes the initial entry check may still fail here.
     */
    unsigned long selfVirtTotalExitCount;
    unsigned long selfVirtResumeCount;
    /*
     * No-progress fuse: L2 keeps exiting on the same instruction with the same reason.
     *
     * These three fields are the **only things left after a hang**. Verified: such hangs cause no
     * BSOD, no dump, and no events in the host Hyper-V logs—the processor stays busy, so no timeouts
     * trigger, and the machine simply stops responding. The fuse converts this into a readable record.
     *
     * The progress determination key is RIP + exit reason + RCX. Looking at RIP alone is wrong:
     * with I/O interception, REP string instructions exit at the same RIP on every iteration,
     * which is fully legal; RCX is what distinguishes that case from 'truly not moving forward'.
     */
    unsigned long l2FuseTripped;
    unsigned long l2FuseReason;
    unsigned long l2FuseCount;
    /* Formerly reserved: host bits 0..4, memory operands bit 5, L2 SSE bit 6. */
    unsigned long hostStateChecks;
    unsigned long long l2FuseRip;
} KSWORD_ARK_HVM_NESTED_PROBE_ROW;

/*
 * Probe writes the TSC offset into vmcs12.
 *
 * The value itself has no architectural meaning; it only needs to be instantly recognizable and impossible to be a 'field not written' 0. Both sides of the comparison share
 * this definition to avoid a scenario where one side is updated while the other still compares against the old value, which would result in a condition that is always true.
 */
#define KSWORD_ARK_HVM_NESTED_PROBE_TSC_OFFSET 0x0000ABCD00000000ULL

typedef struct _KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    /* Overall result: if any row fails to meet the criteria, the result is not OK. */
    unsigned long status;
    /* The number of processors actually executed in this run. */
    unsigned long returnedRows;
    unsigned long long stateFlags;
    KSWORD_ARK_HVM_NESTED_PROBE_ROW rows[
        KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS];
} KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE;

/* One live L2 page override, keyed by EPT12 root and L2 GPA. */
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PAGE 0x915UL
#define IOCTL_KSWORD_ARK_HVM_NESTED_PAGE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_NESTED_PAGE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/* Version 4 adds leafShift/stagePageIndex and the STAGE operation. */
#define KSWORD_ARK_HVM_NESTED_PAGE_VERSION 4UL
/* Leaf granularities an override may be published at: 4 KiB, 2 MiB, 1 GiB.
   A leaf larger than 4 KiB applies one permission set to every page beneath it,
   so it is admitted only where EPT12's own leaf already covers the whole region.
   A request that cannot be honoured at the granularity asked for is refused; it
   is never narrowed to a smaller leaf, because a caller that asked to own a
   region must not silently receive one page of it. */
#define KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_4K 12UL
#define KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_2M 21UL
#define KSWORD_ARK_HVM_NESTED_PAGE_SHIFT_1G 30UL
/* Revocation withdraws the policy; backing still requires an acknowledged drain. */
#define KSWORD_ARK_HVM_PAGE_LEASE_VALID 0UL
#define KSWORD_ARK_HVM_PAGE_LEASE_OWNER_EXITED 1UL
#define KSWORD_ARK_HVM_PAGE_LEASE_TRANSLATION_CHANGED 2UL
#define KSWORD_ARK_HVM_PAGE_LEASE_SOURCE_UNREADABLE 3UL
/* A region admitted by scanning stopped meeting the condition it was admitted
   on: one of its source leaves now grants different access or a different memory
   type than the rest. Detected by sampling rather than at every composition, so
   the region may have been serving for a short while after the change. */
#define KSWORD_ARK_HVM_PAGE_LEASE_REGION_DRIFTED 4UL
#define KSWORD_ARK_HVM_NESTED_PAGE_QUERY 0UL
#define KSWORD_ARK_HVM_NESTED_PAGE_MAP 1UL
#define KSWORD_ARK_HVM_NESTED_PAGE_REMOVE 2UL
/* Overwrite one 4-KiB page of the published region's replacement backing.
   MAP initializes the whole region from the original bytes, so a freshly mapped
   region is indistinguishable from the source until a stage changes part of it.
   This exists because the request carries one page inline and a 2-MiB region is
   512 of them; sending them all through one buffer would make the structure
   larger than the thing it configures. */
#define KSWORD_ARK_HVM_NESTED_PAGE_STAGE 3UL
#define KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED 1UL
/*
 * Admit a large leaf by reading every source entry under the region instead of
 * by requiring the source's own leaf to be at least as coarse.
 *
 * Off by default, and deliberately not implied by asking for a large leaf,
 * because what it buys is paid for with a weaker lease. The coarse-source rule
 * leaves one source entry to watch, and the existing per-fill validation watches
 * it. A region admitted by scanning has up to 512, and re-reading 512 physical
 * entries inside the exit path is not affordable: the measured composition rate
 * on the evaluated machine is roughly 8.2e4 fills per second per the evaluation,
 * so immediate detection would cost tens of millions of reads per second.
 *
 * So a scanned region's lease still detects drift on the first page's path
 * immediately, and does not immediately detect a change to the other entries.
 * That is a real reduction in what the lease proves, which is why it is a flag
 * the caller has to set rather than a silent fallback, and why the response
 * reports which rule admitted the region.
 */
#define KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE 2UL
/*
 * Report a digest of the published region and of the source it was cloned from.
 *
 * Verifying what a region actually contains needs some way to read it back, and
 * the alternative - a general "read this physical address" request - would be a
 * far larger surface than the question deserves, reachable by every caller that
 * can reach this device. A digest answers the questions that matter (is the
 * clone still identical to the source, did a staged write change exactly the
 * page it named) without handing out the bytes.
 *
 * Off by default because it reads the whole region twice: 2 MiB per side is
 * cheap once and wasteful on every status poll.
 */
#define KSWORD_ARK_HVM_NESTED_PAGE_DIGEST 4UL
/* Explicit lab faults are local to this one request and never remain armed. */
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT 8UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK 0x700UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ALLOCATE 1UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_CANCEL 2UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_ROLLBACK 3UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_COMMIT_FLUSH 4UL
#define KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH 5UL
/* Stage ids are carried in the NESTED_PAGE event's exitReason field. */
#define KSW_HVM_PAGE_BEGIN 1UL
#define KSW_HVM_PAGE_ALLOCATE_BEGIN 2UL
#define KSW_HVM_PAGE_ALLOCATE_END 3UL
#define KSW_HVM_PAGE_PUBLISHED 4UL
#define KSW_HVM_PAGE_FLUSH_BEGIN 5UL
#define KSW_HVM_PAGE_FLUSH_END 6UL
#define KSW_HVM_PAGE_UNPUBLISHED 7UL
#define KSW_HVM_PAGE_ROLLBACK_BEGIN 8UL
#define KSW_HVM_PAGE_ROLLBACK_END 9UL
#define KSW_HVM_PAGE_RECLAIMED 10UL
#define KSW_HVM_PAGE_END 11UL
typedef struct _KSWORD_ARK_HVM_NESTED_PAGE_REQUEST {
    unsigned long version, size, operation, flags;
    unsigned long long confirmationToken;
    unsigned long long ept12Pointer, guestPhysicalPage;
    unsigned long expectedGeneration, ownerProcessId;
    unsigned char shadow[4096];
    /* Exact Windows process creation time; prevents PID reuse at map admission. */
    unsigned long long ownerCreationTime;
    /* Granularity to publish the override at. Zero is read as 4 KiB so that a
       caller written against version 3 keeps its exact previous meaning. */
    unsigned long leafShift;
    /* MAP: unused. STAGE: which 4-KiB page of the region `shadow` replaces. */
    unsigned long stagePageIndex;
} KSWORD_ARK_HVM_NESTED_PAGE_REQUEST;
typedef struct _KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE {
    unsigned long version, size, status, lastStatus;
    unsigned long generation, active, retired, residentProcessors;
    unsigned long long ept12Pointer, guestPhysicalPage, shadowPhysicalPage;
    unsigned long long originalPhysicalPage, composedCount;
    unsigned long rootCount, operationId;
    unsigned long long ept12Roots[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Process exit revokes the lease; explicit removal drains and frees backing. */
    unsigned long ownerProcessId, ownerExited;
    unsigned long long ownerCreationTime;
    /* A revoked lease is retained until removal acknowledges every CPU. */
    unsigned long leaseRevocationReason, sourceEntryCount;
    /* Source backing and normalized path captured before publication. */
    unsigned long long sourcePhysicalPage;
    unsigned long long sourceEntryAddress[4], sourceEntryValue[4];
    /* Granularity actually published, the region it owns, and the granularity
       EPT12's own leaf terminated on. The last is what limits the first, so a
       refusal can be read without walking the source tables again. */
    unsigned long leafShift, sourceLeafShift;
    unsigned long long regionBytes, regionPageCount;
    /* Count of STAGE operations applied to the live region since publication. */
    unsigned long long stagedPageCount;
    /* Which rule admitted the region: 0 the source's own leaf was coarse enough,
       1 every source entry was read and found to agree. A caller that did not
       ask for the scan can never see 1 here. */
    unsigned long admittedByScan;
    /* Source leaves examined by that scan, and the access bits they shared. */
    unsigned long long scannedLeafCount, scannedSharedBits;
    /* Digests of the source region and of the replacement serving in its place,
       zero unless the digest flag was set. Equal means the clone still matches;
       a staged write is expected to make exactly the backing digest differ. */
    unsigned long long sourceDigest, backingDigest, digestBytes;
} KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE;

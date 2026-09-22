/*++

Module Name:

    hvm_vmcs.c

Abstract:

    Builds one long-mode VMCS from the current processor state and captures
    deterministic VM-exit telemetry for the controlled one-shot guest.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_vmcs.h"
#include "hvm_metrics.h"

#include "driver/KswordArkHvmControls.h"
/* KSWORD_ARK_HVM_VMCS_DIAG_*: Encoding for configuration failure codes, shared with user-mode tools. */
#include "driver/KswordArkHvmIoctl.h"

#if defined(_M_AMD64)
#include <intrin.h>

#define KSW_IA32_SYSENTER_CS  0x174UL
#define KSW_IA32_SYSENTER_ESP 0x175UL
#define KSW_IA32_SYSENTER_EIP 0x176UL
#define KSW_IA32_DEBUGCTL     0x1D9UL
#define KSW_IA32_PAT          0x277UL
#define KSW_IA32_S_CET        0x6A2UL
#define KSW_IA32_INTERRUPT_SSP_TABLE 0x6A8UL
#define KSW_IA32_PKRS         0x6E1UL
#define KSW_IA32_UINTR_MISC   0x988UL
#define KSW_IA32_FRED_RSP1    0x1CDUL
#define KSW_IA32_FRED_RSP2    0x1CEUL
#define KSW_IA32_FRED_RSP3    0x1CFUL
#define KSW_IA32_FRED_STKLVLS 0x1D0UL
#define KSW_IA32_FRED_SSP1    0x1D1UL
#define KSW_IA32_FRED_SSP2    0x1D2UL
#define KSW_IA32_FRED_SSP3    0x1D3UL
#define KSW_IA32_FRED_CONFIG  0x1D4UL
#define KSW_IA32_FS_BASE      0xC0000100UL
#define KSW_IA32_GS_BASE      0xC0000101UL
#define KSW_IA32_EFER         0xC0000080UL

#define KSW_IA32_VMX_PINBASED_CTLS      0x481UL
#define KSW_IA32_VMX_PROCBASED_CTLS     0x482UL
#define KSW_IA32_VMX_EXIT_CTLS          0x483UL
#define KSW_IA32_VMX_ENTRY_CTLS         0x484UL
#define KSW_IA32_VMX_PROCBASED_CTLS2    0x48BUL
#define KSW_IA32_VMX_TRUE_PINBASED_CTLS 0x48DUL
#define KSW_IA32_VMX_TRUE_PROCBASED_CTLS 0x48EUL
#define KSW_IA32_VMX_TRUE_EXIT_CTLS     0x48FUL
#define KSW_IA32_VMX_TRUE_ENTRY_CTLS    0x490UL
#define KSW_IA32_VMX_EXIT_CTLS2         0x493UL

#define KSW_VMX_BASIC_TRUE_CONTROLS (1ULL << 55)
/*
 * Pin-based control bit 3: NMI exiting.
 *
 * Requested for resident mode only, and requested for one reason: it is the
 * only way to make a sibling processor leave VMX non-root on demand from a
 * VM-exit handler.  KeIpiGenericCall is unusable there (VMX root, IRQL
 * indeterminate), an ordinary IPI is delivered straight to the guest without
 * an exit, and the VMX preemption timer is a per-VMCS field we cannot write on
 * another processor.  An NMI IPI plus this control is what is left.
 *
 * Why a sibling has to leave at all - measured 2026-09-07 on 2 vCPU:
 * we forward the guest's HvCallFlushVirtualAddressSpace/List to L0, and L0
 * invalidates what it believes is the L1 VP, but that VP is running our L2.
 * A sibling that never exits keeps the stale translation.  `hvm_ctl tlb-probe`
 * measured 97% of reads succeeding through a mapping VirtualProtect had already
 * returned from revoking (174,787,358 of 180,208,570), against exactly zero
 * with residency stopped.  Forcing an exit before each read - `tlb-probe-exit`,
 * which just runs CPUID - took that to zero with residency still up, which is
 * what makes this control worth its cost: without VPID, VM entry invalidates
 * the linear mappings tagged VPID 0000H, so one exit is enough.
 *
 * The cost is close to nothing.  NMIs are rare on a healthy machine, so this
 * control adds no exits of its own; what it adds is the obligation to handle
 * the ones that do arrive, which the dispatcher now does by reinjecting.
 */
#define KSW_VMX_PIN_NMI_EXITING (1UL << 3)
/*
 * Pin-based control bit 5: virtual NMIs.
 *
 * Requested together with NMI exiting, and meaningless without it.  It changes
 * what blocking-by-NMI in the guest interruptibility state means: with it, the
 * processor tracks *virtual* NMI blocking on the guest's behalf, set when an
 * NMI is injected and cleared by the guest's IRET, rather than the physical
 * blocking that a host-owned NMI would otherwise impose.
 *
 * That is the state the redelivery path reads before handing an NMI back.  The
 * read is correct either way - blocking-by-NMI is a defined guest field with or
 * without this control - so this is requested for accuracy rather than as a
 * dependency, and losing it to the capability MSR costs correctness in only one
 * narrow case: a host-swallowed NMI would leave physical blocking visible as
 * guest blocking, and the guest's NMI would be held slightly longer than
 * necessary.  Held, not lost.
 */
#define KSW_VMX_PIN_VIRTUAL_NMIS (1UL << 5)

#define KSW_VMX_PRIMARY_HLT_EXITING (1UL << 7)
#define KSW_VMX_PRIMARY_CR3_LOAD_EXITING (1UL << 15)
#define KSW_VMX_PRIMARY_MOV_DR_EXITING (1UL << 23)
/*
 * Diagnostic switch: Requests unconditional I/O exit in resident mode (SDM Table 25-6 bit 24).
 *
 * Why this exists: When the host hangs permanently, the host counter shows 100,000 I/O interceptions per second, but perfmon provides
 * no port decomposition. The only observation channel (the kernel debugger) itself uses the serial port—the reporting channel is the
 * phenomenon under investigation. Enabling this bit causes the first port access to become exit reason 30, with the exit qualifier...
 * bits31:16 represent the port number, and this value is returned via IOCTL through
 * the existing lastExitQualification, completely bypassing the serial port.
 *
 * Why the machine does not hang: The dispatcher lacks a branch for reason 30 (it is absent from the constant table
 * in hvm_exit.c), causing handled to be set to FALSE in the else block. Subsequently, DeactivateCurrent returns
 * DEVIRTUALIZE, which executes VMXOFF and resumes the guest in place. One exit, one answer, the machine stays alive.
 *
 * Precondition: bit25 (use I/O bitmaps) must remain 0. SDM 25.1.3 specifies that bit24 is ignored
 * when bit25 is 1, silently disabling this diagnostic. This driver never requests bit25 or writes
 * IO_BITMAP_A/B; enabling the bitmaps for another purpose in the future would break this diagnostic.
 *
 * Setting to 0 restores original behavior; no other changes required.
 */
#define KSW_HVM_DIAG_UNCONDITIONAL_IO_EXITING 0
#define KSW_VMX_PRIMARY_UNCOND_IO_EXITING (1UL << 24)
#define KSW_VMX_PRIMARY_USE_MSR_BITMAPS (1UL << 28)
/* Identify the secondary control converting EPT violations into guest #VE. */
#define KSW_VMX_SECONDARY_EPT_VIOLATION_VE (1UL << 18)
/* Identify the secondary control enabling the VMFUNC instruction. */
#define KSW_VMX_SECONDARY_ENABLE_VM_FUNCTIONS (1UL << 13)
/* Identify VM function 0, EPTP switching, inside the function controls. */
#define KSW_VMX_VM_FUNCTION_EPTP_SWITCHING (1ULL << 0)
#define KSW_VMX_PRIMARY_SECONDARY_CONTROLS (1UL << 31)
#define KSW_VMX_SECONDARY_EPT (1UL << 1)
#define KSW_VMX_SECONDARY_RDTSCP (1UL << 3)
#define KSW_VMX_SECONDARY_INVPCID (1UL << 12)
#define KSW_VMX_SECONDARY_XSAVES (1UL << 20)
#define KSW_VMX_SECONDARY_USER_WAIT (1UL << 26)
#define KSW_VMX_SECONDARY_PCONFIG (1UL << 27)
#define KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS (1UL << 2)
#define KSW_VMX_EXIT_HOST_64_BIT (1UL << 9)
#define KSW_VMX_EXIT_SAVE_PAT (1UL << 18)
#define KSW_VMX_EXIT_LOAD_PAT (1UL << 19)
#define KSW_VMX_EXIT_SAVE_EFER (1UL << 20)
#define KSW_VMX_EXIT_LOAD_EFER (1UL << 21)
#define KSW_VMX_EXIT_CLEAR_UINV (1UL << 27)
#define KSW_VMX_EXIT_LOAD_CET (1UL << 28)
#define KSW_VMX_EXIT_LOAD_PKRS (1UL << 29)
#define KSW_VMX_EXIT_SECONDARY_CONTROLS (1UL << 31)
#define KSW_VMX_SECONDARY_EXIT_SAVE_FRED (1ULL << 0)
#define KSW_VMX_SECONDARY_EXIT_LOAD_FRED (1ULL << 1)
#define KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS (1UL << 2)
#define KSW_VMX_ENTRY_IA32E_GUEST (1UL << 9)
#define KSW_VMX_ENTRY_LOAD_PAT (1UL << 14)
#define KSW_VMX_ENTRY_LOAD_EFER (1UL << 15)
#define KSW_VMX_ENTRY_LOAD_UINV (1UL << 19)
#define KSW_VMX_ENTRY_LOAD_CET (1UL << 20)
#define KSW_VMX_ENTRY_LOAD_PKRS (1UL << 22)
#define KSW_VMX_ENTRY_LOAD_FRED (1UL << 23)
#define KSW_CR4_CET (1ULL << 23)
#define KSW_CR4_PKS (1ULL << 24)
#define KSW_CR4_UINTR (1ULL << 25)
#define KSW_CR4_FRED (1ULL << 32)
#define KSW_CET_SHADOW_STACK_ENABLED (1ULL << 0)
#define KSW_VMX_SEGMENT_UNUSABLE (1UL << 16)

#define KSW_VMCS_GUEST_ES_SELECTOR 0x0800UL
#define KSW_VMCS_GUEST_CS_SELECTOR 0x0802UL
#define KSW_VMCS_GUEST_SS_SELECTOR 0x0804UL
#define KSW_VMCS_GUEST_DS_SELECTOR 0x0806UL
#define KSW_VMCS_GUEST_FS_SELECTOR 0x0808UL
#define KSW_VMCS_GUEST_GS_SELECTOR 0x080AUL
#define KSW_VMCS_GUEST_LDTR_SELECTOR 0x080CUL
#define KSW_VMCS_GUEST_TR_SELECTOR 0x080EUL
#define KSW_VMCS_HOST_ES_SELECTOR 0x0C00UL
#define KSW_VMCS_HOST_CS_SELECTOR 0x0C02UL
#define KSW_VMCS_HOST_SS_SELECTOR 0x0C04UL
#define KSW_VMCS_HOST_DS_SELECTOR 0x0C06UL
#define KSW_VMCS_HOST_FS_SELECTOR 0x0C08UL
#define KSW_VMCS_HOST_GS_SELECTOR 0x0C0AUL
#define KSW_VMCS_HOST_TR_SELECTOR 0x0C0CUL
#define KSW_VMCS_GUEST_UINV 0x0814UL

#define KSW_VMCS_MSR_BITMAP 0x2004UL
/* Name the 64-bit control field holding the #VE information-area address. */
#define KSW_VMCS_VE_INFO_ADDRESS 0x202AUL
/* Name the 64-bit control field selecting which VM functions are enabled. */
#define KSW_VMCS_VM_FUNCTION_CONTROLS 0x2018UL
/* Name the 64-bit control field holding the EPTP list address. */
#define KSW_VMCS_EPTP_LIST_ADDRESS 0x2024UL
#define KSW_VMCS_XSS_EXITING_BITMAP 0x202CUL
#define KSW_VMCS_PCONFIG_EXITING_BITMAP 0x203EUL
#define KSW_VMCS_SECONDARY_EXIT_CONTROLS 0x2044UL
#define KSW_VMCS_INJECTED_EVENT_DATA 0x2052UL
#define KSW_VMCS_EPT_POINTER 0x201AUL
#define KSW_VMCS_GUEST_LINK_POINTER 0x2800UL
#define KSW_VMCS_GUEST_DEBUGCTL 0x2802UL
#define KSW_VMCS_GUEST_PAT 0x2804UL
#define KSW_VMCS_GUEST_EFER 0x2806UL
#define KSW_VMCS_GUEST_PKRS 0x2818UL
#define KSW_VMCS_GUEST_FRED_CONFIG 0x281AUL
#define KSW_VMCS_GUEST_FRED_RSP1 0x281CUL
#define KSW_VMCS_GUEST_FRED_RSP2 0x281EUL
#define KSW_VMCS_GUEST_FRED_RSP3 0x2820UL
#define KSW_VMCS_GUEST_FRED_STKLVLS 0x2822UL
#define KSW_VMCS_GUEST_FRED_SSP1 0x2824UL
#define KSW_VMCS_GUEST_FRED_SSP2 0x2826UL
#define KSW_VMCS_GUEST_FRED_SSP3 0x2828UL
#define KSW_VMCS_HOST_PAT 0x2C00UL
#define KSW_VMCS_HOST_EFER 0x2C02UL
#define KSW_VMCS_HOST_PKRS 0x2C06UL
#define KSW_VMCS_HOST_FRED_CONFIG 0x2C08UL
#define KSW_VMCS_HOST_FRED_RSP1 0x2C0AUL
#define KSW_VMCS_HOST_FRED_RSP2 0x2C0CUL
#define KSW_VMCS_HOST_FRED_RSP3 0x2C0EUL
#define KSW_VMCS_HOST_FRED_STKLVLS 0x2C10UL
#define KSW_VMCS_HOST_FRED_SSP1 0x2C12UL
#define KSW_VMCS_HOST_FRED_SSP2 0x2C14UL
#define KSW_VMCS_HOST_FRED_SSP3 0x2C16UL

#define KSW_VMCS_PIN_CONTROLS 0x4000UL
#define KSW_VMCS_PRIMARY_CONTROLS 0x4002UL
#define KSW_VMCS_EXCEPTION_BITMAP 0x4004UL
#define KSW_VMCS_PAGE_FAULT_MASK 0x4006UL
#define KSW_VMCS_PAGE_FAULT_MATCH 0x4008UL
#define KSW_VMCS_CR3_TARGET_COUNT 0x400AUL
#define KSW_VMCS_EXIT_CONTROLS 0x400CUL
#define KSW_VMCS_EXIT_MSR_STORE_COUNT 0x400EUL
#define KSW_VMCS_EXIT_MSR_LOAD_COUNT 0x4010UL
#define KSW_VMCS_ENTRY_CONTROLS 0x4012UL
#define KSW_VMCS_ENTRY_MSR_LOAD_COUNT 0x4014UL
#define KSW_VMCS_ENTRY_INTERRUPTION_INFO 0x4016UL
#define KSW_VMCS_ENTRY_EXCEPTION_ERROR 0x4018UL
#define KSW_VMCS_ENTRY_INSTRUCTION_LENGTH 0x401AUL
#define KSW_VMCS_TPR_THRESHOLD 0x401CUL
#define KSW_VMCS_SECONDARY_CONTROLS 0x401EUL

#define KSW_VMCS_INSTRUCTION_ERROR 0x4400UL
#define KSW_VMCS_EXIT_REASON 0x4402UL
#define KSW_VMCS_EXIT_INSTRUCTION_LENGTH 0x440CUL

#define KSW_VMCS_GUEST_ES_LIMIT 0x4800UL
#define KSW_VMCS_GUEST_CS_LIMIT 0x4802UL
#define KSW_VMCS_GUEST_SS_LIMIT 0x4804UL
#define KSW_VMCS_GUEST_DS_LIMIT 0x4806UL
#define KSW_VMCS_GUEST_FS_LIMIT 0x4808UL
#define KSW_VMCS_GUEST_GS_LIMIT 0x480AUL
#define KSW_VMCS_GUEST_LDTR_LIMIT 0x480CUL
#define KSW_VMCS_GUEST_TR_LIMIT 0x480EUL
#define KSW_VMCS_GUEST_GDTR_LIMIT 0x4810UL
#define KSW_VMCS_GUEST_IDTR_LIMIT 0x4812UL
#define KSW_VMCS_GUEST_ES_ACCESS 0x4814UL
#define KSW_VMCS_GUEST_CS_ACCESS 0x4816UL
#define KSW_VMCS_GUEST_SS_ACCESS 0x4818UL
#define KSW_VMCS_GUEST_DS_ACCESS 0x481AUL
#define KSW_VMCS_GUEST_FS_ACCESS 0x481CUL
#define KSW_VMCS_GUEST_GS_ACCESS 0x481EUL
#define KSW_VMCS_GUEST_LDTR_ACCESS 0x4820UL
#define KSW_VMCS_GUEST_TR_ACCESS 0x4822UL
#define KSW_VMCS_GUEST_INTERRUPTIBILITY 0x4824UL
#define KSW_VMCS_GUEST_ACTIVITY 0x4826UL
#define KSW_VMCS_GUEST_SMBASE 0x4828UL
#define KSW_VMCS_GUEST_SYSENTER_CS 0x482AUL
#define KSW_VMCS_HOST_SYSENTER_CS 0x4C00UL

#define KSW_VMCS_CR0_MASK 0x6000UL
#define KSW_VMCS_CR4_MASK 0x6002UL
#define KSW_VMCS_CR0_SHADOW 0x6004UL
#define KSW_VMCS_CR4_SHADOW 0x6006UL
#define KSW_VMCS_EXIT_QUALIFICATION 0x6400UL

#define KSW_VMCS_GUEST_CR0 0x6800UL
#define KSW_VMCS_GUEST_CR3 0x6802UL
#define KSW_VMCS_GUEST_CR4 0x6804UL
#define KSW_VMCS_GUEST_ES_BASE 0x6806UL
#define KSW_VMCS_GUEST_CS_BASE 0x6808UL
#define KSW_VMCS_GUEST_SS_BASE 0x680AUL
#define KSW_VMCS_GUEST_DS_BASE 0x680CUL
#define KSW_VMCS_GUEST_FS_BASE 0x680EUL
#define KSW_VMCS_GUEST_GS_BASE 0x6810UL
#define KSW_VMCS_GUEST_LDTR_BASE 0x6812UL
#define KSW_VMCS_GUEST_TR_BASE 0x6814UL
#define KSW_VMCS_GUEST_GDTR_BASE 0x6816UL
#define KSW_VMCS_GUEST_IDTR_BASE 0x6818UL
#define KSW_VMCS_GUEST_DR7 0x681AUL
#define KSW_VMCS_GUEST_RSP 0x681CUL
#define KSW_VMCS_GUEST_RIP 0x681EUL
#define KSW_VMCS_GUEST_RFLAGS 0x6820UL
#define KSW_VMCS_GUEST_PENDING_DEBUG 0x6822UL
#define KSW_VMCS_GUEST_SYSENTER_ESP 0x6824UL
#define KSW_VMCS_GUEST_SYSENTER_EIP 0x6826UL
#define KSW_VMCS_GUEST_S_CET 0x6828UL
#define KSW_VMCS_GUEST_SSP 0x682AUL
#define KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE 0x682CUL

#define KSW_VMCS_HOST_CR0 0x6C00UL
#define KSW_VMCS_HOST_CR3 0x6C02UL
#define KSW_VMCS_HOST_CR4 0x6C04UL
#define KSW_VMCS_HOST_FS_BASE 0x6C06UL
#define KSW_VMCS_HOST_GS_BASE 0x6C08UL
#define KSW_VMCS_HOST_TR_BASE 0x6C0AUL
#define KSW_VMCS_HOST_GDTR_BASE 0x6C0CUL
#define KSW_VMCS_HOST_IDTR_BASE 0x6C0EUL
#define KSW_VMCS_HOST_SYSENTER_ESP 0x6C10UL
#define KSW_VMCS_HOST_SYSENTER_EIP 0x6C12UL
#define KSW_VMCS_HOST_RSP 0x6C14UL
#define KSW_VMCS_HOST_RIP 0x6C16UL
#define KSW_VMCS_HOST_S_CET 0x6C18UL
#define KSW_VMCS_HOST_SSP 0x6C1AUL
#define KSW_VMCS_HOST_INTERRUPT_SSP_TABLE 0x6C1CUL

typedef struct KswHvmVmcsWrite
{
    SIZE_T field;
    SIZE_T value;
} KswHvmVmcsWrite;

/* Keep every assembly-written segment snapshot offset compile-time checked. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, gdtr) == 0);
/* Keep the packed IDTR offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, idtr) == 10);
/* Keep the packed ES offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, es) == 20);
/* Keep the packed CS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, cs) == 22);
/* Keep the packed SS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, ss) == 24);
/* Keep the packed DS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, ds) == 26);
/* Keep the packed FS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, fs) == 28);
/* Keep the packed GS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, gs) == 30);
/* Keep the packed LDTR offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, ldtr) == 32);
/* Keep the packed TR offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KswHvmSegmentSnapshot, tr) == 34);

/*
 * The only two places in this driver allowed to execute a VMCS access
 * instruction directly.
 *
 * Everything else goes through the FieldLoad / FieldStore pair below.  The
 * indirection is not decoration: VMREAD and VMWRITE are the two operations
 * whose *implementation* has to change wholesale when the field storage does,
 * and a driver that spells them out at every call site cannot make that change
 * without editing every one of those sites correctly.
 *
 * Spelled as macros rather than called directly so that a mechanical search for
 * `kswordArkHvmVmcsFieldLoad(` / `kswordArkHvmVmcsFieldStore(` finds exactly the call sites that still
 * bypass the seam - which is zero, and should stay zero.
 */
#define KSW_HVM_RAW_VMREAD __vmx_vmread
#define KSW_HVM_RAW_VMWRITE __vmx_vmwrite

UCHAR
kswordArkHvmVmcsFieldLoad(
    _In_ SIZE_T field,
    _Out_ SIZE_T* value
    )
{
    /* Reject a missing destination before touching the current VMCS. */
    if (value == NULL) {
        /* Report the same failure shape a VMREAD of an invalid field gives. */
        return 1U;
    }
    return KSW_HVM_RAW_VMREAD(field, value);
}

UCHAR
kswordArkHvmVmcsFieldStore(
    _In_ SIZE_T field,
    _In_ SIZE_T value
    )
{
    return KSW_HVM_RAW_VMWRITE(field, value);
}

static ULONG
kswordArkHvmAdjustControls(
    _In_ ULONG desired,
    _In_ ULONGLONG capability
    )
{
    /*
     * The arithmetic lives in KswordArkHvmControls.h so the host unit tests
     * exercise the same code the driver runs, rather than a copy that can
     * drift.  Getting this wrong is invisible until VM entry fails with only
     * an error number to go on, which is exactly what happens under a nested
     * hypervisor that exposes a narrower control surface.
     */
    return KswordArkHvmAdjustControls(desired, capability);
}

NTSTATUS
kswordArkHvmReadSegment(
    _In_ const KswHvmSegmentSnapshot* snapshot,
    _In_ USHORT selector,
    _Out_ KswHvmSegmentState* segment
    )
{
    const UCHAR* table = NULL;
    ULONG tableLimit = 0UL;
    ULONG descriptorOffset = 0UL;
    UCHAR descriptor[16] = { 0 };
    ULONG rawLimit = 0UL;
    ULONGLONG rawBase = 0ULL;

    /* Validate both fixed arguments before dereferencing descriptor memory. */
    if (snapshot == NULL || segment == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Publish a deterministic unusable descriptor for a null selector. */
    RtlZeroMemory(segment, sizeof(*segment));
    /* Preserve the selector exactly as captured for guest-state programming. */
    segment->selector = selector;
    /* Mark null segments unusable as required by VM-entry validation. */
    if ((selector & 0xFFF8U) == 0U) {
        segment->accessRights = KSW_VMX_SEGMENT_UNUSABLE;
        return STATUS_SUCCESS;
    }

    /* Use the GDT for ordinary kernel selectors. */
    if ((selector & 0x4U) == 0U) {
        table = (const UCHAR*)(ULONG_PTR)snapshot->gdtr.base;
        tableLimit = snapshot->gdtr.limit;
    } else {
        KswHvmSegmentState ldt = { 0 };

        /* Reject a recursive LDT lookup when no LDTR is active. */
        if ((snapshot->ldtr & 0xFFF8U) == 0U ||
            (snapshot->ldtr & 0x4U) != 0U) {
            return STATUS_INVALID_PARAMETER;
        }
        /* Resolve the LDT system descriptor from the GDT first. */
        if (!NT_SUCCESS(kswordArkHvmReadSegment(
                snapshot,
                snapshot->ldtr,
                &ldt))) {
            return STATUS_INVALID_PARAMETER;
        }
        /* Use the resolved LDT base and limit for the target descriptor. */
        table = (const UCHAR*)(ULONG_PTR)ldt.base;
        tableLimit = ldt.limit;
    }

    /* Convert the selector index into an eight-byte descriptor offset. */
    descriptorOffset = (ULONG)(selector & 0xFFF8U);
    /* Require a complete legacy descriptor within the selected table. */
    if (table == NULL ||
        descriptorOffset > tableLimit ||
        tableLimit - descriptorOffset < 7UL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Copy the descriptor through a guarded access because GDT/LDT is dynamic. */
    __try {
        RtlCopyMemory(descriptor, table + descriptorOffset, 8U);
        /* System descriptors carry the high base dword in the next slot. */
        if ((descriptor[5] & 0x10U) == 0U &&
            tableLimit - descriptorOffset >= 15UL) {
            RtlCopyMemory(descriptor + 8, table + descriptorOffset + 8UL, 8U);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    /* Require the complete high-base slot for every active system descriptor. */
    if ((descriptor[5] & 0x10U) == 0U &&
        tableLimit - descriptorOffset < 15UL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Decode the 20-bit descriptor limit. */
    rawLimit =
        (ULONG)descriptor[0] |
        ((ULONG)descriptor[1] << 8) |
        ((ULONG)(descriptor[6] & 0x0FU) << 16);
    /* Expand page-granular limits to their inclusive byte limit. */
    if ((descriptor[6] & 0x80U) != 0U) {
        rawLimit = (rawLimit << 12) | 0xFFFUL;
    }
    /* Decode the low 32 bits of the descriptor base. */
    rawBase =
        ((ULONGLONG)descriptor[2]) |
        ((ULONGLONG)descriptor[3] << 8) |
        ((ULONGLONG)descriptor[4] << 16) |
        ((ULONGLONG)descriptor[7] << 24);
    /* Decode the high system-segment base when the descriptor owns it. */
    if ((descriptor[5] & 0x10U) == 0U) {
        rawBase |=
            ((ULONGLONG)descriptor[8]) << 32 |
            ((ULONGLONG)descriptor[9]) << 40 |
            ((ULONGLONG)descriptor[10]) << 48 |
            ((ULONGLONG)descriptor[11]) << 56;
    }
    /* Publish the normalized byte limit. */
    segment->limit = rawLimit;
    /* Publish the VMCS-format access-rights field. */
    segment->accessRights =
        (ULONG)descriptor[5] |
        ((ULONG)(descriptor[6] & 0xF0U) << 8);
    /* Publish the complete descriptor base. */
    segment->base = rawBase;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkHvmWriteVmcs(
    _In_reads_(writeCount) const KswHvmVmcsWrite* writes,
    _In_ ULONG writeCount,
    _Out_ ULONG* vmInstructionError
    )
{
    ULONG index = 0UL;
    ULONG architecturalError = 0UL;

    /* Reject an invalid write ledger before invoking VMX instructions. */
    if (writes == NULL || vmInstructionError == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear the diagnostic until an instruction reports a valid failure. */
    *vmInstructionError = 0UL;
    /* Apply each field in deterministic order and stop at the first failure. */
    for (index = 0UL; index < writeCount; ++index) {
        UCHAR result = 0U;

        /* Write the encoded field through the compiler VMX intrinsic. */
        result = kswordArkHvmVmcsFieldStore(writes[index].field, writes[index].value);
        /* Continue only when VMWRITE reports success. */
        if (result == 0U) {
            continue;
        }
        /* Read the extended VM-instruction error when VMfailValid is reported. */
        if (result == 1U) {
            SIZE_T instructionError = 0U;

            /* Preserve a readable VMCS error code when VMREAD succeeds. */
            if (kswordArkHvmVmcsFieldLoad(
                    (SIZE_T)KSW_VMCS_INSTRUCTION_ERROR,
                    &instructionError) == 0U) {
                architecturalError = (ULONG)instructionError;
            }
        }
        /*
         * The **field** that was rejected is the only useful information, but the previous version discarded it: here only the
         * error code is recorded. An error code of 0 has three sources (VMfailInvalid without a code, VMREAD 0x4400 failing
         * itself, and never reaching this point), so "error=0" was mistakenly treated as "no VMWRITE failure occurred".
         * Now encode the field code and VMX result together into the same field;
         * semantics are defined in KSWORD_ARK_HVM_VMCS_DIAG_* of KswordArkHvmIoctl.h.
         */
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_VMWRITE,
            (ULONG)writes[index].field,
            architecturalError);
        return STATUS_HV_OPERATION_FAILED;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmConfigureVmcs(
    _In_ const KswHvmVmcsInput* input,
    _Out_ ULONG* vmInstructionError
    )
{
    KswHvmSegmentSnapshot snapshot = { 0 };
    KswHvmSegmentState es = { 0 };
    KswHvmSegmentState cs = { 0 };
    KswHvmSegmentState ss = { 0 };
    KswHvmSegmentState ds = { 0 };
    KswHvmSegmentState fs = { 0 };
    KswHvmSegmentState gs = { 0 };
    KswHvmSegmentState ldtr = { 0 };
    KswHvmSegmentState tr = { 0 };
    ULONGLONG pinCapability = 0ULL;
    ULONGLONG primaryCapability = 0ULL;
    ULONGLONG secondaryCapability = 0ULL;
    ULONGLONG exitCapability = 0ULL;
    ULONGLONG entryCapability = 0ULL;
    ULONGLONG secondaryExitCapability = 0ULL;
    ULONGLONG guestCr0 = 0ULL;
    ULONGLONG guestCr4 = 0ULL;
    ULONGLONG hardwareCr4 = 0ULL;
    ULONGLONG fsBase = 0ULL;
    ULONGLONG gsBase = 0ULL;
    ULONGLONG pat = 0ULL;
    ULONGLONG efer = 0ULL;
    ULONGLONG debugControl = 0ULL;
    ULONGLONG sysenterCs = 0ULL;
    ULONGLONG sysenterEsp = 0ULL;
    ULONGLONG sysenterEip = 0ULL;
    ULONGLONG nativeSCet = 0ULL;
    ULONGLONG nativeSsp = 0ULL;
    ULONGLONG nativeInterruptSspTable = 0ULL;
    ULONGLONG nativePkrs = 0ULL;
    ULONGLONG nativeUinv = 0ULL;
    ULONGLONG nativeFredConfig = 0ULL;
    ULONGLONG nativeFredRsp1 = 0ULL;
    ULONGLONG nativeFredRsp2 = 0ULL;
    ULONGLONG nativeFredRsp3 = 0ULL;
    ULONGLONG nativeFredStackLevels = 0ULL;
    ULONGLONG nativeFredSsp1 = 0ULL;
    ULONGLONG nativeFredSsp2 = 0ULL;
    ULONGLONG nativeFredSsp3 = 0ULL;
    ULONG pinControls = 0UL;
    ULONG primaryControls = 0UL;
    ULONG secondaryControls = 0UL;
    ULONG exitControls = 0UL;
    ULONG entryControls = 0UL;
    ULONG secondaryExitControls = 0UL;
    ULONG requiredInstructionControls = 0UL;
    ULONG maxBasicLeaf = 0UL;
    ULONG maxStructuredSubleaf = 0UL;
    ULONG maxExtendedLeaf = 0UL;
    int registers[4] = { 0 };
    BOOLEAN cetCpuSupported = FALSE;
    BOOLEAN pksCpuSupported = FALSE;
    BOOLEAN uintrCpuSupported = FALSE;
    BOOLEAN uintrXsaveSupported = FALSE;
    BOOLEAN fredCpuSupported = FALSE;
    BOOLEAN cetStateSupported = FALSE;
    BOOLEAN pkrsStateSupported = FALSE;
    BOOLEAN uinvStateSupported = FALSE;
    BOOLEAN fredStateSupported = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Validate fixed inputs before reading processor state or MSRs. */
    if (input == NULL || vmInstructionError == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* initialize the diagnostic before any fallible operation. */
    *vmInstructionError = 0UL;
    /*
     * A zero host page-directory base would silently produce a VMCS whose exit
     * handler cannot be translated, and the failure mode is a triple fault with
     * no bugcheck and no dump.  Refuse before writing anything.
     */
    if (input->hostCr3 == 0ULL) {
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_HOST_CR3, 0UL, 0UL);
        return STATUS_INVALID_PARAMETER;
    }
    /* Capture descriptor tables and selectors on the launch processor. */
    KswordARKHvmCaptureSegments(&snapshot);
    /* Resolve every guest-visible segment from its active descriptor table. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.es, &es);
    /* Stop when the ES descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve CS after ES succeeds. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.cs, &cs);
    /* Stop when the CS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve SS after CS succeeds. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.ss, &ss);
    /* Stop when the SS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve DS after SS succeeds. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.ds, &ds);
    /* Stop when the DS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve FS after DS succeeds. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.fs, &fs);
    /* Stop when the FS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve GS after FS succeeds. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.gs, &gs);
    /* Stop when the GS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve LDTR after ordinary data segments succeed. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.ldtr, &ldtr);
    /* Stop when an active LDTR descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve the mandatory task-register descriptor last. */
    status = kswordArkHvmReadSegment(&snapshot, snapshot.tr, &tr);
    /* Stop when the task-register descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Generate the instruction allow mask based on CPUID capabilities currently exposed to Windows by the processor. */
    __cpuid(registers, 0);
    maxBasicLeaf = (ULONG)registers[0];
    if (maxBasicLeaf >= 7UL) {
        __cpuidex(registers, 7, 0);
        maxStructuredSubleaf = (ULONG)registers[0];
        if (((ULONG)registers[1] & (1UL << 10)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_INVPCID;
        }
        if (((ULONG)registers[2] & (1UL << 5)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_USER_WAIT;
        }
        if (((ULONG)registers[3] & (1UL << 18)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_PCONFIG;
        }
        cetCpuSupported =
            (((ULONG)registers[2] & (1UL << 7)) != 0UL) ||
            (((ULONG)registers[3] & (1UL << 20)) != 0UL);
        pksCpuSupported =
            ((ULONG)registers[2] & (1UL << 31)) != 0UL;
        uintrCpuSupported =
            ((ULONG)registers[3] & (1UL << 5)) != 0UL;
        if (maxStructuredSubleaf >= 1UL) {
            __cpuidex(registers, 7, 1);
            fredCpuSupported =
                ((ULONG)registers[0] & (1UL << 17)) != 0UL;
        }
    }
    if (maxBasicLeaf >= 0xDUL) {
        __cpuidex(registers, 0xD, 1);
        if (((ULONG)registers[0] & (1UL << 3)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_XSAVES;
        }
        uintrXsaveSupported =
            ((ULONG)registers[2] & (1UL << 14)) != 0UL;
    }
    __cpuid(registers, (int)0x80000000UL);
    maxExtendedLeaf = (ULONG)registers[0];
    if (maxExtendedLeaf >= 0x80000001UL) {
        __cpuid(registers, (int)0x80000001UL);
        if (((ULONG)registers[3] & (1UL << 27)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_RDTSCP;
        }
    }

    /* Read VMX controls and long-mode state under exception protection. */
    __try {
        /* Select true control MSRs when IA32_VMX_BASIC advertises them. */
        if ((input->vmxBasic & KSW_VMX_BASIC_TRUE_CONTROLS) != 0ULL) {
            pinCapability = __readmsr(KSW_IA32_VMX_TRUE_PINBASED_CTLS);
            primaryCapability = __readmsr(KSW_IA32_VMX_TRUE_PROCBASED_CTLS);
            exitCapability = __readmsr(KSW_IA32_VMX_TRUE_EXIT_CTLS);
            entryCapability = __readmsr(KSW_IA32_VMX_TRUE_ENTRY_CTLS);
        } else {
            pinCapability = __readmsr(KSW_IA32_VMX_PINBASED_CTLS);
            primaryCapability = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS);
            exitCapability = __readmsr(KSW_IA32_VMX_EXIT_CTLS);
            entryCapability = __readmsr(KSW_IA32_VMX_ENTRY_CTLS);
        }
        /* Read secondary controls independently of the true-control mode. */
        secondaryCapability = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
        /* Note: Read secondary VM-exit capability only when the primary exit control allows activation. */
        if ((((ULONG)(exitCapability >> 32)) &
                KSW_VMX_EXIT_SECONDARY_CONTROLS) != 0UL) {
            secondaryExitCapability =
                __readmsr(KSW_IA32_VMX_EXIT_CTLS2);
        }
        /* Capture long-mode bases and model-specific guest/host state. */
        fsBase = __readmsr(KSW_IA32_FS_BASE);
        /* Capture the active kernel GS base. */
        gsBase = __readmsr(KSW_IA32_GS_BASE);
        /* Preserve PAT across the one-shot transition. */
        pat = __readmsr(KSW_IA32_PAT);
        /* Preserve EFER and its long-mode bits across the transition. */
        efer = __readmsr(KSW_IA32_EFER);
        /* Save debug control state for use with paired VM-entry/exit control fields. */
        debugControl = __readmsr(KSW_IA32_DEBUGCTL);
        /* Preserve SYSENTER state for both guest and host. */
        sysenterCs = __readmsr(KSW_IA32_SYSENTER_CS);
        /* Preserve the SYSENTER stack pointer. */
        sysenterEsp = __readmsr(KSW_IA32_SYSENTER_ESP);
        /* Preserve the SYSENTER instruction pointer. */
        sysenterEip = __readmsr(KSW_IA32_SYSENTER_EIP);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /*
         * Exceptions are swallowed locally into NTSTATUS here and cannot propagate to the outer __except block of the
         * caller, so the EXCEPTION bit on the per-processor line will not be set. Consequently, the absence of the
         * EXCEPTION bit cannot be used to rule out this path. The exception code must be preserved to be visible.
         */
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_CAP_EXCEPTION,
            (ULONG)GetExceptionCode() & 0xFFFFUL,
            0UL);
        return GetExceptionCode();
    }

    hardwareCr4 = __readcr4();
    cetStateSupported =
        cetCpuSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_LOAD_CET) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_CET) != 0UL);
    pkrsStateSupported =
        pksCpuSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_LOAD_PKRS) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_PKRS) != 0UL);
    uinvStateSupported =
        uintrCpuSupported &&
        uintrXsaveSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_CLEAR_UINV) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_UINV) != 0UL);
    fredStateSupported =
        fredCpuSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_SECONDARY_CONTROLS) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_FRED) != 0UL) &&
        ((((ULONG)(secondaryExitCapability >> 32)) &
            (KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
             KSW_VMX_SECONDARY_EXIT_LOAD_FRED)) ==
            (KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
             KSW_VMX_SECONDARY_EXIT_LOAD_FRED));

    /* Processor states that are already enabled but lack full VMCS transfer capabilities must be rejected before VM-entry. */
    if ((!cetStateSupported &&
            (hardwareCr4 & KSW_CR4_CET) != 0ULL) ||
        (!pkrsStateSupported &&
            (hardwareCr4 & KSW_CR4_PKS) != 0ULL) ||
        (!uinvStateSupported &&
            (hardwareCr4 & KSW_CR4_UINTR) != 0ULL) ||
        (!fredStateSupported &&
            (hardwareCr4 & KSW_CR4_FRED) != 0ULL)) {
        /*
         * This is a contradiction on bare metal: if CPUID reports a processor with a certain state, the corresponding LOAD_* control
         * must be present in the capability MSR. This can only coexist in nested virtualization when the CPUID leaf and VMX capability
         * MSR are synthesized by two independent L0 code paths. Therefore, it is crucial to track which state is being referenced.
         */
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER,
            ((!cetStateSupported && (hardwareCr4 & KSW_CR4_CET) != 0ULL)
                ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_CET : 0UL) |
            ((!pkrsStateSupported && (hardwareCr4 & KSW_CR4_PKS) != 0ULL)
                ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_PKS : 0UL) |
            ((!uinvStateSupported && (hardwareCr4 & KSW_CR4_UINTR) != 0ULL)
                ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_UINTR : 0UL) |
            ((!fredStateSupported && (hardwareCr4 & KSW_CR4_FRED) != 0ULL)
                ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_FRED : 0UL),
            0UL);
        return STATUS_NOT_SUPPORTED;
    }

    /* Read only optional state registers supported by both the CPU and VMX controls. */
    __try {
        if (cetStateSupported) {
            nativeSCet = __readmsr(KSW_IA32_S_CET);
            nativeInterruptSspTable =
                __readmsr(KSW_IA32_INTERRUPT_SSP_TABLE);
            if (input->residentMode == 0U &&
                (hardwareCr4 & KSW_CR4_CET) != 0ULL &&
                (nativeSCet & KSW_CET_SHADOW_STACK_ENABLED) != 0ULL) {
                nativeSsp = KswordARKHvmAsmReadSsp();
                if (nativeSsp == 0ULL) {
                    status = STATUS_NOT_SUPPORTED;
                    __leave;
                }
            }
        }
        if (pkrsStateSupported) {
            nativePkrs = __readmsr(KSW_IA32_PKRS);
        }
        if (uinvStateSupported) {
            nativeUinv =
                (__readmsr(KSW_IA32_UINTR_MISC) >> 32) & 0xFFULL;
        }
        if (fredStateSupported) {
            nativeFredConfig = __readmsr(KSW_IA32_FRED_CONFIG);
            nativeFredRsp1 = __readmsr(KSW_IA32_FRED_RSP1);
            nativeFredRsp2 = __readmsr(KSW_IA32_FRED_RSP2);
            nativeFredRsp3 = __readmsr(KSW_IA32_FRED_RSP3);
            nativeFredStackLevels =
                __readmsr(KSW_IA32_FRED_STKLVLS);
            nativeFredSsp1 = __readmsr(KSW_IA32_FRED_SSP1);
            nativeFredSsp2 = __readmsr(KSW_IA32_FRED_SSP2);
            nativeFredSsp3 = __readmsr(KSW_IA32_FRED_SSP3);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Same as above: this path also does not set the EXCEPTION bit in the per-processor row. */
        status = GetExceptionCode();
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_EXCEPTION,
            (ULONG)status & 0xFFFFUL,
            0UL);
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Long mode takes the architecturally active FS base from its MSR. */
    fs.base = fsBase;
    /* Long mode takes the architecturally active GS base from its MSR. */
    gs.base = gsBase;
    /* Keep guest CR0 within the fixed-bit envelope advertised by the CPU. */
    guestCr0 = (__readcr0() | input->cr0Fixed0) & input->cr0Fixed1;
    /* Keep guest CR4 within fixed bits under explicit nested-VMX policy. */
    guestCr4 =
        (((input->enableNestedVmx != 0U
            ? (hardwareCr4 | (1ULL << 13))
            : (hardwareCr4 & ~(1ULL << 13))) |
            input->cr4Fixed0)) &
        input->cr4Fixed1;
    /*
     * Request NMI exiting for resident mode only; see the constant's comment.
     * A one-shot guest never needs a sibling flushed, and every control it does
     * not request is one less way for its VM entry to fail.
     */
    pinControls = kswordArkHvmAdjustControls(
        (input->residentMode != 0U
            ? (KSW_VMX_PIN_NMI_EXITING | KSW_VMX_PIN_VIRTUAL_NMIS)
            : 0UL),
        pinCapability);
    /*
     * Virtual NMIs without NMI exiting is an illegal combination that fails VM
     * entry.  The adjust above can produce exactly that if the capability MSR
     * happens to allow one and require the other, so drop the dependent bit
     * rather than let a control pair we did not verify reach VMLAUNCH.
     */
    if ((pinControls & KSW_VMX_PIN_NMI_EXITING) == 0UL) {
        pinControls &= ~(ULONG)KSW_VMX_PIN_VIRTUAL_NMIS;
    }
    /* Activate secondary controls and reserve HLT exits for one-shot guests. */
    primaryControls = kswordArkHvmAdjustControls(
        (input->residentMode == 0U
            ? KSW_VMX_PRIMARY_HLT_EXITING
            : 0UL) |
            /*
             * Without this control every RDMSR and WRMSR exits unconditionally,
             * which no resident guest can survive.  Request it exactly when the
             * caller owns a bitmap page to point the VMCS field at.
             */
            (input->msrBitmapPhysical != 0ULL
                ? KSW_VMX_PRIMARY_USE_MSR_BITMAPS
                : 0UL) |
            /*
             * CR3-load exiting turns every address-space switch into a VM
             * exit.  It is requested only when a policy explicitly asks for
             * it, because Windows switches CR3 thousands of times a second.
             */
            (input->trackCr3 != 0U
                ? KSW_VMX_PRIMARY_CR3_LOAD_EXITING
                : 0UL) |
            (input->interceptDr != 0U
                ? KSW_VMX_PRIMARY_MOV_DR_EXITING
                : 0UL) |
#if KSW_HVM_DIAG_UNCONDITIONAL_IO_EXITING
            /*
             * Request only for resident mode; keep the one-time controlled guest unchanged as
             * a control group—it executes vmcall/hlt and does not perform port access anyway.
             */
            (Input->ResidentMode != 0U
                ? KSW_VMX_PRIMARY_UNCOND_IO_EXITING
                : 0UL) |
#endif
            KSW_VMX_PRIMARY_SECONDARY_CONTROLS,
        primaryCapability);
    /* Enable EPT simultaneously with the instruction execution gate observed by Windows via CPUID. */
    secondaryControls = kswordArkHvmAdjustControls(
        KSW_VMX_SECONDARY_EPT |
            /*
             * Request EPT-violation #VE only when the caller asked for it and
             * owns an information area.  AdjustControls clamps against the
             * capability MSR, so a request the processor cannot honor becomes
             * "off" here rather than a VM-entry failure later.
             */
            ((input->enableVe != 0U && input->veInfoPhysical != 0ULL)
                ? KSW_VMX_SECONDARY_EPT_VIOLATION_VE
                : 0UL) |
            /*
             * VM functions only when asked and only with a list to switch
             * within.  Arming this without a list would let guest code run
             * VMFUNC against uninitialized entries.
             */
            ((input->enableVmFunctions != 0U &&
                input->eptpListPhysical != 0ULL)
                ? KSW_VMX_SECONDARY_ENABLE_VM_FUNCTIONS
                : 0UL) |
            requiredInstructionControls,
        secondaryCapability);
    /* Pairwise save debug controls, PAT, EFER, and supported extended processor states. */
    exitControls = kswordArkHvmAdjustControls(
        KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS |
            KSW_VMX_EXIT_HOST_64_BIT |
            KSW_VMX_EXIT_SAVE_PAT |
            KSW_VMX_EXIT_LOAD_PAT |
            KSW_VMX_EXIT_SAVE_EFER |
            KSW_VMX_EXIT_LOAD_EFER |
            (uinvStateSupported
                ? KSW_VMX_EXIT_CLEAR_UINV
                : 0UL) |
            (cetStateSupported
                ? KSW_VMX_EXIT_LOAD_CET
                : 0UL) |
            (pkrsStateSupported
                ? KSW_VMX_EXIT_LOAD_PKRS
                : 0UL) |
            (fredStateSupported
                ? KSW_VMX_EXIT_SECONDARY_CONTROLS
                : 0UL),
        exitCapability);
    /* VM-entry uses state load controls symmetric to VM-exit. */
    entryControls = kswordArkHvmAdjustControls(
        KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS |
            KSW_VMX_ENTRY_IA32E_GUEST |
            KSW_VMX_ENTRY_LOAD_PAT |
            KSW_VMX_ENTRY_LOAD_EFER |
            (uinvStateSupported
                ? KSW_VMX_ENTRY_LOAD_UINV
                : 0UL) |
            (cetStateSupported
                ? KSW_VMX_ENTRY_LOAD_CET
                : 0UL) |
            (pkrsStateSupported
                ? KSW_VMX_ENTRY_LOAD_PKRS
                : 0UL) |
            (fredStateSupported
                ? KSW_VMX_ENTRY_LOAD_FRED
                : 0UL),
        entryCapability);
    if (fredStateSupported) {
        secondaryExitControls = kswordArkHvmAdjustControls(
            (ULONG)(KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
                KSW_VMX_SECONDARY_EXIT_LOAD_FRED),
            secondaryExitCapability);
    }

    /*
     * A caller that owns a bitmap page requires the control to actually engage.
     * Silently continuing would leave every MSR access exiting into a
     * dispatcher path that cannot sustain a resident guest.
     */
    if (input->msrBitmapPhysical != 0ULL &&
        (primaryControls & KSW_VMX_PRIMARY_USE_MSR_BITMAPS) == 0UL) {
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_BITMAP, 0UL, 0UL);
        return STATUS_NOT_SUPPORTED;
    }
#if KSW_HVM_DIAG_UNCONDITIONAL_IO_EXITING
    /*
     * For the same reason: diagnostic bits disabled by capability MSRs must be reported. Silently continuing
     * results in 'the experiment finished but nothing was tested'—this line has already failed once (the suite
     * passed fully even when not integrated into the project), so we must prevent a recurrence in another form.
     */
    if (Input->ResidentMode != 0U &&
        (primaryControls & KSW_VMX_PRIMARY_UNCOND_IO_EXITING) == 0UL) {
        *VmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_DIAG_IO_EXITING, 0UL, 0UL);
        return STATUS_NOT_SUPPORTED;
    }
#endif
    /*
     * A policy that asked for these controls must actually get them; silently
     * running without the interception it configured would be worse than
     * refusing to launch.
     */
    if ((input->trackCr3 != 0U &&
            (primaryControls & KSW_VMX_PRIMARY_CR3_LOAD_EXITING) == 0UL) ||
        (input->interceptDr != 0U &&
            (primaryControls & KSW_VMX_PRIMARY_MOV_DR_EXITING) == 0UL)) {
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_CR_POLICY,
            ((input->trackCr3 != 0U &&
                (primaryControls & KSW_VMX_PRIMARY_CR3_LOAD_EXITING) == 0UL)
                ? 1UL : 0UL) |
            ((input->interceptDr != 0U &&
                (primaryControls & KSW_VMX_PRIMARY_MOV_DR_EXITING) == 0UL)
                ? 2UL : 0UL),
            0UL);
        return STATUS_NOT_SUPPORTED;
    }
    /* Reject hardware that cannot activate the required secondary controls. */
    if ((primaryControls & KSW_VMX_PRIMARY_SECONDARY_CONTROLS) == 0UL ||
        (secondaryControls & KSW_VMX_SECONDARY_EPT) == 0UL ||
        (secondaryControls & requiredInstructionControls) !=
            requiredInstructionControls ||
        (exitControls & KSW_VMX_EXIT_HOST_64_BIT) == 0UL ||
        (entryControls & KSW_VMX_ENTRY_IA32E_GUEST) == 0UL) {
        const ULONG kMissingInstruction =
            requiredInstructionControls & ~secondaryControls;

        /*
         * The `requiredInstructionControls` field is handled separately: its mask is assembled via CPUID, while
         * `AdjustControls` performs a **silent clamp** (`(Desired | mustBeOne) & mayBeOne`). If a bit requested by L0 is not
         * provided, no error is raised; the bit is simply cleared. The consequences of this entirely rest on this single check.
         * Record the bit index of the lowest missing bit; this is far more useful than recording "this entire criterion failed."
         */
        if (kMissingInstruction != 0UL) {
            ULONG bitIndex = 0UL;

            while (bitIndex < 31UL &&
                   (kMissingInstruction & (1UL << bitIndex)) == 0UL) {
                ++bitIndex;
            }
            *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
                KSWORD_ARK_HVM_VMCS_DIAG_SITE_INSTRUCTION_CTL,
                bitIndex,
                0UL);
        } else {
            *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
                KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS,
                (((primaryControls & KSW_VMX_PRIMARY_SECONDARY_CONTROLS) == 0UL)
                    ? KSWORD_ARK_HVM_VMCS_DIAG_CTL_SECONDARY_ACTIVATE : 0UL) |
                (((secondaryControls & KSW_VMX_SECONDARY_EPT) == 0UL)
                    ? KSWORD_ARK_HVM_VMCS_DIAG_CTL_EPT : 0UL) |
                (((exitControls & KSW_VMX_EXIT_HOST_64_BIT) == 0UL)
                    ? KSWORD_ARK_HVM_VMCS_DIAG_CTL_HOST_64 : 0UL) |
                (((entryControls & KSW_VMX_ENTRY_IA32E_GUEST) == 0UL)
                    ? KSWORD_ARK_HVM_VMCS_DIAG_CTL_ENTRY_IA32E : 0UL),
                0UL);
        }
        return STATUS_NOT_SUPPORTED;
    }
    /* Debug state must be saved and loaded in pairs; unidirectional switching is prohibited. */
    if (((exitControls & KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS) != 0UL) !=
        ((entryControls & KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS) != 0UL)) {
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_DEBUG_PAIRING,
            (((exitControls & KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS) != 0UL)
                ? 1UL : 0UL) |
            (((entryControls & KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS) != 0UL)
                ? 2UL : 0UL),
            0UL);
        return STATUS_NOT_SUPPORTED;
    }
    if ((cetStateSupported &&
            ((exitControls & KSW_VMX_EXIT_LOAD_CET) == 0UL ||
             (entryControls & KSW_VMX_ENTRY_LOAD_CET) == 0UL)) ||
        (pkrsStateSupported &&
            ((exitControls & KSW_VMX_EXIT_LOAD_PKRS) == 0UL ||
             (entryControls & KSW_VMX_ENTRY_LOAD_PKRS) == 0UL)) ||
        (uinvStateSupported &&
            ((exitControls & KSW_VMX_EXIT_CLEAR_UINV) == 0UL ||
             (entryControls & KSW_VMX_ENTRY_LOAD_UINV) == 0UL)) ||
        (fredStateSupported &&
            (((exitControls &
                KSW_VMX_EXIT_SECONDARY_CONTROLS) == 0UL) ||
             ((entryControls & KSW_VMX_ENTRY_LOAD_FRED) == 0UL) ||
             ((secondaryExitControls &
                (ULONG)(KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
                    KSW_VMX_SECONDARY_EXIT_LOAD_FRED)) !=
                (ULONG)(KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
                    KSW_VMX_SECONDARY_EXIT_LOAD_FRED))))) {
        *vmInstructionError = KSWORD_ARK_HVM_VMCS_DIAG_MAKE(
            KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING,
            (cetStateSupported ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_CET : 0UL) |
            (pkrsStateSupported ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_PKS : 0UL) |
            (uinvStateSupported ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_UINTR : 0UL) |
            (fredStateSupported ? KSWORD_ARK_HVM_VMCS_DIAG_STATE_FRED : 0UL),
            0UL);
        return STATUS_NOT_SUPPORTED;
    }

    /*
     * Record what is about to be enforced, alongside what it was adjusted
     * against.  A control bit set here that the request did not ask for is one
     * the capability MSR made mandatory - which is the only way to tell an
     * outer hypervisor's demand apart from a mistake of ours.
     */
    if (input->activeControls != NULL) {
        input->activeControls->pin = pinControls;
        input->activeControls->primary = primaryControls;
        input->activeControls->secondary = secondaryControls;
        input->activeControls->exit = exitControls;
        input->activeControls->entry = entryControls;
        input->activeControls->pinCapability = pinCapability;
        input->activeControls->primaryCapability = primaryCapability;
        input->activeControls->secondaryCapability = secondaryCapability;
        input->activeControls->exitCapability = exitCapability;
        input->activeControls->entryCapability = entryCapability;
    }
    /* Build the complete fixed VMCS write ledger on the launch stack. */
    {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_PIN_CONTROLS, pinControls },
            { KSW_VMCS_PRIMARY_CONTROLS, primaryControls },
            { KSW_VMCS_SECONDARY_CONTROLS, secondaryControls },
            { KSW_VMCS_EXIT_CONTROLS, exitControls },
            { KSW_VMCS_ENTRY_CONTROLS, entryControls },
            { KSW_VMCS_EXCEPTION_BITMAP, 0U },
            { KSW_VMCS_PAGE_FAULT_MASK, 0U },
            { KSW_VMCS_PAGE_FAULT_MATCH, 0U },
            { KSW_VMCS_CR3_TARGET_COUNT, 0U },
            { KSW_VMCS_EXIT_MSR_STORE_COUNT, 0U },
            { KSW_VMCS_EXIT_MSR_LOAD_COUNT, 0U },
            { KSW_VMCS_ENTRY_MSR_LOAD_COUNT, 0U },
            { KSW_VMCS_ENTRY_INTERRUPTION_INFO, 0U },
            { KSW_VMCS_ENTRY_EXCEPTION_ERROR, 0U },
            { KSW_VMCS_ENTRY_INSTRUCTION_LENGTH, 0U },
            { KSW_VMCS_TPR_THRESHOLD, 0U },
            { KSW_VMCS_MSR_BITMAP, (SIZE_T)input->msrBitmapPhysical },
            { KSW_VMCS_EPT_POINTER, (SIZE_T)input->eptPointer },
            { KSW_VMCS_GUEST_LINK_POINTER, (SIZE_T)MAXULONGLONG },
            { KSW_VMCS_GUEST_DEBUGCTL, (SIZE_T)debugControl },
            { KSW_VMCS_CR0_MASK, (SIZE_T)input->cr0PinnedMask },
            { KSW_VMCS_CR4_MASK, (SIZE_T)input->cr4PinnedMask },
            { KSW_VMCS_CR0_SHADOW, (SIZE_T)guestCr0 },
            { KSW_VMCS_CR4_SHADOW, (SIZE_T)guestCr4 },
            { KSW_VMCS_GUEST_ES_SELECTOR, es.selector },
            { KSW_VMCS_GUEST_CS_SELECTOR, cs.selector },
            { KSW_VMCS_GUEST_SS_SELECTOR, ss.selector },
            { KSW_VMCS_GUEST_DS_SELECTOR, ds.selector },
            { KSW_VMCS_GUEST_FS_SELECTOR, fs.selector },
            { KSW_VMCS_GUEST_GS_SELECTOR, gs.selector },
            { KSW_VMCS_GUEST_LDTR_SELECTOR, ldtr.selector },
            { KSW_VMCS_GUEST_TR_SELECTOR, tr.selector },
            { KSW_VMCS_GUEST_ES_LIMIT, es.limit },
            { KSW_VMCS_GUEST_CS_LIMIT, cs.limit },
            { KSW_VMCS_GUEST_SS_LIMIT, ss.limit },
            { KSW_VMCS_GUEST_DS_LIMIT, ds.limit },
            { KSW_VMCS_GUEST_FS_LIMIT, fs.limit },
            { KSW_VMCS_GUEST_GS_LIMIT, gs.limit },
            { KSW_VMCS_GUEST_LDTR_LIMIT, ldtr.limit },
            { KSW_VMCS_GUEST_TR_LIMIT, tr.limit },
            { KSW_VMCS_GUEST_GDTR_LIMIT, snapshot.gdtr.limit },
            { KSW_VMCS_GUEST_IDTR_LIMIT, snapshot.idtr.limit },
            { KSW_VMCS_GUEST_ES_ACCESS, es.accessRights },
            { KSW_VMCS_GUEST_CS_ACCESS, cs.accessRights },
            { KSW_VMCS_GUEST_SS_ACCESS, ss.accessRights },
            { KSW_VMCS_GUEST_DS_ACCESS, ds.accessRights },
            { KSW_VMCS_GUEST_FS_ACCESS, fs.accessRights },
            { KSW_VMCS_GUEST_GS_ACCESS, gs.accessRights },
            { KSW_VMCS_GUEST_LDTR_ACCESS, ldtr.accessRights },
            { KSW_VMCS_GUEST_TR_ACCESS, tr.accessRights },
            { KSW_VMCS_GUEST_INTERRUPTIBILITY, 0U },
            { KSW_VMCS_GUEST_ACTIVITY, 0U },
            { KSW_VMCS_GUEST_CR0, (SIZE_T)guestCr0 },
            { KSW_VMCS_GUEST_CR3, (SIZE_T)__readcr3() },
            { KSW_VMCS_GUEST_CR4, (SIZE_T)guestCr4 },
            { KSW_VMCS_GUEST_ES_BASE, (SIZE_T)es.base },
            { KSW_VMCS_GUEST_CS_BASE, (SIZE_T)cs.base },
            { KSW_VMCS_GUEST_SS_BASE, (SIZE_T)ss.base },
            { KSW_VMCS_GUEST_DS_BASE, (SIZE_T)ds.base },
            { KSW_VMCS_GUEST_FS_BASE, (SIZE_T)fs.base },
            { KSW_VMCS_GUEST_GS_BASE, (SIZE_T)gs.base },
            { KSW_VMCS_GUEST_LDTR_BASE, (SIZE_T)ldtr.base },
            { KSW_VMCS_GUEST_TR_BASE, (SIZE_T)tr.base },
            { KSW_VMCS_GUEST_GDTR_BASE, (SIZE_T)snapshot.gdtr.base },
            { KSW_VMCS_GUEST_IDTR_BASE, (SIZE_T)snapshot.idtr.base },
            { KSW_VMCS_GUEST_DR7, (SIZE_T)__readdr(7) },
            { KSW_VMCS_GUEST_RSP, (SIZE_T)input->guestStackPointer },
            { KSW_VMCS_GUEST_RIP, (SIZE_T)input->guestInstructionPointer },
            { KSW_VMCS_GUEST_RFLAGS,
                (SIZE_T)(input->guestRflags != 0ULL
                    ? (input->guestRflags | 0x2ULL)
                    : 0x2ULL) },
            { KSW_VMCS_GUEST_PENDING_DEBUG, 0U },
            { KSW_VMCS_GUEST_SYSENTER_CS, (SIZE_T)sysenterCs },
            { KSW_VMCS_GUEST_SYSENTER_ESP, (SIZE_T)sysenterEsp },
            { KSW_VMCS_GUEST_SYSENTER_EIP, (SIZE_T)sysenterEip },
            { KSW_VMCS_GUEST_PAT, (SIZE_T)pat },
            { KSW_VMCS_GUEST_EFER, (SIZE_T)efer },
            { KSW_VMCS_HOST_ES_SELECTOR, es.selector & 0xFFF8U },
            { KSW_VMCS_HOST_CS_SELECTOR, cs.selector & 0xFFF8U },
            { KSW_VMCS_HOST_SS_SELECTOR, ss.selector & 0xFFF8U },
            { KSW_VMCS_HOST_DS_SELECTOR, ds.selector & 0xFFF8U },
            { KSW_VMCS_HOST_FS_SELECTOR, fs.selector & 0xFFF8U },
            { KSW_VMCS_HOST_GS_SELECTOR, gs.selector & 0xFFF8U },
            { KSW_VMCS_HOST_TR_SELECTOR, tr.selector & 0xFFF8U },
            { KSW_VMCS_HOST_SYSENTER_CS, (SIZE_T)sysenterCs },
            { KSW_VMCS_HOST_CR0, (SIZE_T)__readcr0() },
            /*
             * Never __readcr3() here.  This runs on the thread that asked for
             * residency, so the live CR3 names that process's top-level page
             * table; when the process exits, the page is freed and the next VM
             * exit cannot translate HOST_RIP - #PF, then #DF, then a triple
             * fault that resets the machine with no bugcheck and no dump.
             */
            { KSW_VMCS_HOST_CR3, (SIZE_T)input->hostCr3 },
            { KSW_VMCS_HOST_CR4, (SIZE_T)__readcr4() },
            { KSW_VMCS_HOST_FS_BASE, (SIZE_T)fsBase },
            { KSW_VMCS_HOST_GS_BASE, (SIZE_T)gsBase },
            { KSW_VMCS_HOST_TR_BASE, (SIZE_T)tr.base },
            { KSW_VMCS_HOST_GDTR_BASE, (SIZE_T)snapshot.gdtr.base },
            /* Run VMX root on the private IDT when one was built. */
            { KSW_VMCS_HOST_IDTR_BASE,
              (SIZE_T)(input->hostIdtBase != 0ULL
                  ? (ULONG_PTR)input->hostIdtBase
                  : (ULONG_PTR)snapshot.idtr.base) },
            { KSW_VMCS_HOST_SYSENTER_ESP, (SIZE_T)sysenterEsp },
            { KSW_VMCS_HOST_SYSENTER_EIP, (SIZE_T)sysenterEip },
            { KSW_VMCS_HOST_RSP, (SIZE_T)input->hostStackPointer },
            { KSW_VMCS_HOST_RIP, (SIZE_T)input->hostInstructionPointer },
            { KSW_VMCS_HOST_PAT, (SIZE_T)pat },
            { KSW_VMCS_HOST_EFER, (SIZE_T)efer }
        };

        /* The ledger now contains all captured state and selected controls. */
        if (input->residentMode != 0U) {
            /* This boundary precedes the first write from the fixed ledger. */
            kswordArkHvmMetricsCpuStamp(input->metricsCpuIndex, KSW_HVM_TIME_STATE_CAPTURED);
        }
        /* Write all fields implemented by every processor first. */
        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /*
     * GUEST_SMBASE (0x4828) is handled on a best-effort basis alone; it is the
     * only field in this write list that can fail without affecting correctness.
     *
     * Rationale: SMBASE is only consumed under the dual-monitor treatment for SMI and SMM
     * (SDM 32.15). This driver never activates that mechanism and never requests "entry to
     * SMM"; thus, VM entry does not check this field, and writing it is purely for hygiene.
     *
     * However, it fails in nested virtualization: when Hyper-V acts as L0, it rejects this field encoding
     * (error code 0x81482800 = Site 1 VMWRITE / detail 0x4828 / architecture error code 0). An error code
     * of 0 indicates either VMfailInvalid or an inability to read even VMCS 0x4400; both point to 'L0
     * does not implement this encoding'. Placing this in a write list that must succeed causes the entire
     * START_RESIDENT to fail to start in nested mode, with the failure point completely invisible.
     *
     * Native behavior remains unchanged: that VMWRITE executes and succeeds there as well.
     *
     * On failure, **do not write** *VmInstructionError — otherwise a harmless failure leaves a discriminator
     * that masks subsequent real failures or makes successful configurations appear to have failed.
     */
    (void)kswordArkHvmVmcsFieldStore(KSW_VMCS_GUEST_SMBASE, 0U);

    /*
     * Publish the information area only once the control has survived
     * clamping.  The field does not exist on a processor without the control,
     * and writing an absent field fails VMWRITE.
     */
    if ((secondaryControls & KSW_VMX_SECONDARY_EPT_VIOLATION_VE) != 0UL) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_VE_INFO_ADDRESS, (SIZE_T)input->veInfoPhysical }
        };

        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /*
     * Publish the EPTP list and the function-enable mask together.  Both
     * fields exist only when the secondary control survived clamping, and the
     * function controls must name EPTP switching explicitly - enabling VM
     * functions without selecting a function makes every VMFUNC fail.
     */
    if ((secondaryControls &
            KSW_VMX_SECONDARY_ENABLE_VM_FUNCTIONS) != 0UL) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_EPTP_LIST_ADDRESS,
                (SIZE_T)input->eptpListPhysical },
            { KSW_VMCS_VM_FUNCTION_CONTROLS,
                (SIZE_T)KSW_VMX_VM_FUNCTION_EPTP_SWITCHING }
        };

        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /* Explicitly clear the corresponding exit bitmap after allowing XSAVES and PCONFIG. */
    if ((secondaryControls & KSW_VMX_SECONDARY_XSAVES) != 0UL) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_XSS_EXITING_BITMAP, 0U }
        };

        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if ((secondaryControls & KSW_VMX_SECONDARY_PCONFIG) != 0UL) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_PCONFIG_EXITING_BITMAP, 0U }
        };

        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (cetStateSupported) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_GUEST_S_CET, (SIZE_T)nativeSCet },
            { KSW_VMCS_GUEST_SSP, (SIZE_T)nativeSsp },
            { KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE,
                (SIZE_T)nativeInterruptSspTable },
            { KSW_VMCS_HOST_S_CET, 0U },
            { KSW_VMCS_HOST_SSP, 0U },
            { KSW_VMCS_HOST_INTERRUPT_SSP_TABLE, 0U }
        };

        /* VM-exit disables CET in root mode; VM-entry restores the guest's original state. */
        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (pkrsStateSupported) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_GUEST_PKRS, (SIZE_T)nativePkrs },
            { KSW_VMCS_HOST_PKRS, 0U }
        };

        /* The guest preserves the original PKRS; root mode uses an unrestricted access state. */
        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (uinvStateSupported) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_GUEST_UINV, (SIZE_T)nativeUinv }
        };

        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (fredStateSupported) {
        const KswHvmVmcsWrite kWrites[] = {
            { KSW_VMCS_SECONDARY_EXIT_CONTROLS,
                (SIZE_T)secondaryExitControls },
            { KSW_VMCS_GUEST_FRED_CONFIG,
                (SIZE_T)nativeFredConfig },
            { KSW_VMCS_GUEST_FRED_RSP1,
                (SIZE_T)nativeFredRsp1 },
            { KSW_VMCS_GUEST_FRED_RSP2,
                (SIZE_T)nativeFredRsp2 },
            { KSW_VMCS_GUEST_FRED_RSP3,
                (SIZE_T)nativeFredRsp3 },
            { KSW_VMCS_GUEST_FRED_STKLVLS,
                (SIZE_T)nativeFredStackLevels },
            { KSW_VMCS_GUEST_FRED_SSP1,
                (SIZE_T)nativeFredSsp1 },
            { KSW_VMCS_GUEST_FRED_SSP2,
                (SIZE_T)nativeFredSsp2 },
            { KSW_VMCS_GUEST_FRED_SSP3,
                (SIZE_T)nativeFredSsp3 },
            { KSW_VMCS_HOST_FRED_CONFIG,
                (SIZE_T)nativeFredConfig },
            { KSW_VMCS_HOST_FRED_RSP1,
                (SIZE_T)nativeFredRsp1 },
            { KSW_VMCS_HOST_FRED_RSP2,
                (SIZE_T)nativeFredRsp2 },
            { KSW_VMCS_HOST_FRED_RSP3,
                (SIZE_T)nativeFredRsp3 },
            { KSW_VMCS_HOST_FRED_STKLVLS,
                (SIZE_T)nativeFredStackLevels },
            { KSW_VMCS_HOST_FRED_SSP1,
                (SIZE_T)nativeFredSsp1 },
            { KSW_VMCS_HOST_FRED_SSP2,
                (SIZE_T)nativeFredSsp2 },
            { KSW_VMCS_HOST_FRED_SSP3,
                (SIZE_T)nativeFredSsp3 },
            { KSW_VMCS_INJECTED_EVENT_DATA, 0U }
        };

        status = kswordArkHvmWriteVmcs(
            kWrites,
            (ULONG)RTL_NUMBER_OF(kWrites),
            vmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHvmReadVmExitTelemetryEx(
    _Out_ KswHvmVmexitTelemetry* telemetry,
    _In_ BOOLEAN sparseCpuid
    )
{
    SIZE_T value = 0U;
    BOOLEAN sparse = FALSE;

    /* Reject a missing telemetry destination before VMREAD. */
    if (telemetry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear every field so a partial failure never exposes stale state. */
    RtlZeroMemory(telemetry, sizeof(*telemetry));
    /* Read the full exit-reason field, including entry-failure information. */
    if (kswordArkHvmVmcsFieldLoad(KSW_VMCS_EXIT_REASON, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Preserve only the protocol-visible 32-bit exit reason. */
    telemetry->reason = (ULONG)value;
    /* Exact reason matching excludes VM-entry failures and preserves their diagnostics. */
    sparse = sparseCpuid && telemetry->reason == 10UL;
    /* Read the exit qualification associated with the basic reason. */
    if (!sparse && kswordArkHvmVmcsFieldLoad(KSW_VMCS_EXIT_QUALIFICATION, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* CPUID supplies no exit qualification; zero does not masquerade as a read value. */
    telemetry->qualification = sparse ? 0ULL : (ULONGLONG)value;
    /* Read the guest instruction pointer at the point of exit. */
    if (kswordArkHvmVmcsFieldLoad(KSW_VMCS_GUEST_RIP, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the guest instruction pointer. */
    telemetry->guestRip = (ULONGLONG)value;
    /* Read the guest stack pointer at the point of exit. */
    if (kswordArkHvmVmcsFieldLoad(KSW_VMCS_GUEST_RSP, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the guest stack pointer. */
    telemetry->guestRsp = (ULONGLONG)value;
    /* Read the instruction length for deterministic VMCALL evidence. */
    if (kswordArkHvmVmcsFieldLoad(KSW_VMCS_EXIT_INSTRUCTION_LENGTH, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the bounded instruction length. */
    telemetry->instructionLength = (ULONG)value;
    /* Read the VM-instruction error field as additional diagnostic evidence. */
    if (!sparse && kswordArkHvmVmcsFieldLoad(KSW_VMCS_INSTRUCTION_ERROR, &value) == 0U) {
        telemetry->vmInstructionError = (ULONG)value;
    }
    return STATUS_SUCCESS;
}

NTSTATUS kswordArkHvmReadVmExitTelemetry(KswHvmVmexitTelemetry* telemetry)
{
    /* One-shot and failure diagnostics retain the complete existing snapshot. */
    return kswordArkHvmReadVmExitTelemetryEx(telemetry, FALSE);
}

#else

NTSTATUS KswordARKHvmReadVmExitTelemetryEx(KSW_HVM_VMEXIT_TELEMETRY* Telemetry,
    BOOLEAN SparseCpuid)
{
    /* Non-x64 builds have no VMCS telemetry implementation. */
    UNREFERENCED_PARAMETER(Telemetry);
    /* Preserve the same unsupported contract for either snapshot policy. */
    UNREFERENCED_PARAMETER(SparseCpuid);
    /* Do not report a fabricated snapshot as success. */
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmConfigureVmcs(
    _In_ const KSW_HVM_VMCS_INPUT* Input,
    _Out_ ULONG* VmInstructionError
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Input);
    /* Publish an empty diagnostic when a destination was supplied. */
    if (VmInstructionError != NULL) {
        *VmInstructionError = 0UL;
    }
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmReadVmExitTelemetry(
    _Out_ KSW_HVM_VMEXIT_TELEMETRY* Telemetry
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Telemetry);
    return STATUS_NOT_SUPPORTED;
}

#endif

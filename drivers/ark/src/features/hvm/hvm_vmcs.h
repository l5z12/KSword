#pragma once

#include "ark/ark_driver.h"

#define KSW_HVM_VMEXIT_REASON_BASIC_MASK 0x0000FFFFUL
#define KSW_HVM_VMEXIT_REASON_ENTRY_FAILURE 0x80000000UL
#define KSW_HVM_VMEXIT_REASON_VMCALL 18UL

#pragma pack(push, 1)
typedef struct KswHvmDescriptorTable
{
    USHORT limit;
    ULONGLONG base;
} KswHvmDescriptorTable;

typedef struct KswHvmSegmentSnapshot
{
    KswHvmDescriptorTable gdtr;
    KswHvmDescriptorTable idtr;
    USHORT es;
    USHORT cs;
    USHORT ss;
    USHORT ds;
    USHORT fs;
    USHORT gs;
    USHORT ldtr;
    USHORT tr;
} KswHvmSegmentSnapshot;
#pragma pack(pop)

typedef struct KswHvmVmcsInput
{
    ULONGLONG vmxBasic;
    ULONGLONG cr0Fixed0;
    ULONGLONG cr0Fixed1;
    ULONGLONG cr4Fixed0;
    ULONGLONG cr4Fixed1;
    ULONGLONG eptPointer;
    ULONGLONG guestStackPointer;
    ULONGLONG hostStackPointer;
    ULONGLONG guestInstructionPointer;
    ULONGLONG hostInstructionPointer;
    ULONGLONG guestRflags;
    /*
     * Page-directory base loaded into HOST_CR3 on every VM exit.  Must name an
     * address space that outlives residency - the System process one - not the
     * CR3 that happens to be current while the VMCS is written, which belongs
     * to whichever process asked for residency.  Zero is refused.
     */
    ULONGLONG hostCr3;
    ULONGLONG msrBitmapPhysical;
    /*
     * Per-processor #VE information area.  Zero means the caller has none, in
     * which case the EPT-violation #VE control is never requested.
     */
    ULONGLONG veInfoPhysical;
    /*
     * EPTP list published to VMFUNC.  Zero means the caller has none, in which
     * case VM functions are never requested.
     */
    ULONGLONG eptpListPhysical;
    /* CR0/CR4 bits owned by the hypervisor; the guest reads them from shadow. */
    ULONGLONG cr0PinnedMask;
    ULONGLONG cr4PinnedMask;
    /* Nonzero makes every address-space switch exit. Expensive by design. */
    UCHAR trackCr3;
    /* Nonzero makes guest debug-register access exit. */
    UCHAR interceptDr;
    UCHAR residentMode;
    UCHAR enableNestedVmx;
    /* Only resident builders contribute to transition timing. */
    ULONG metricsCpuIndex;
    /*
     * Nonzero requests EPT-violation #VE.  This alone delivers nothing: a
     * violation still converts only on a leaf whose suppress-#VE bit is clear
     * (this driver sets it everywhere) and only when the information area is
     * not busy (allocation latches it busy).  Both must also be undone before
     * a single #VE can reach the guest.
     */
    UCHAR enableVe;
    /*
     * Nonzero arms VM functions and EPTP switching.  VMFUNC performs no CPL
     * check, so arming this publishes every list entry to unprivileged guest
     * code.  Domains are forkable only in the narrowing direction, which is
     * what keeps that from being an escalation path.
     */
    UCHAR enableVmFunctions;
    USHORT reserved;
    /*
     * Interrupt descriptor table to install as HOST_IDTR_BASE, or zero to keep
     * using the guest's own.
     *
     * VMX root runs on whatever IDT this field names, and until now that was
     * the guest's - which is correct for everything the host does on purpose,
     * because the host raises no exceptions.  It stops being correct as soon
     * as something *sends* this processor an NMI: an NMI that lands while the
     * processor is in VMX root is not converted into a VM exit no matter what
     * the pin controls say, so it is delivered through this IDT, and the
     * guest's vector 2 belongs to Windows, which bugchecks 0x80 on an NMI it
     * cannot attribute.  Measured 2026-09-07 - that is exactly how the first
     * cross-processor flush attempt failed.
     *
     * A private IDT is therefore a precondition for sending NMIs at all, not
     * an optimization.  Zero keeps the previous behavior exactly.
     */
    ULONGLONG hostIdtBase;
    /*
     * Where to record the controls that end up enforced, or NULL to record
     * nothing.  Purely diagnostic: configuration behaves identically either
     * way.
     */
    struct KswHvmActiveControls* activeControls;
} KswHvmVmcsInput;

typedef struct KswHvmVmexitTelemetry
{
    ULONG reason;
    ULONG instructionLength;
    ULONG vmInstructionError;
    ULONG reserved;
    ULONGLONG qualification;
    ULONGLONG guestRip;
    ULONGLONG guestRsp;
} KswHvmVmexitTelemetry;

/*
 * What was actually written into the VMCS execution-control fields, and the
 * capability MSR each one was adjusted against.
 *
 * "Which exits does this machine take" and "which of them did we ask for" are
 * different questions, and the second one used to be answerable only by reading
 * the source and reasoning.  The exit histogram made the gap concrete: HLT is
 * the single largest exit reason on the nested target, while resident mode
 * requests no HLT exiting at all - so either the outer hypervisor forces the
 * bit through the allowed-0 half of the capability MSR, or the control is being
 * computed wrongly, and reasoning cannot tell those two apart.
 *
 * The adjusted result is what is kept, not the request: the request is a
 * compile-time constant anyone can read, while the value the processor
 * enforces is the one that explains the exits.  A bit set here that the
 * request did not ask for is, by construction, one the capability MSR made
 * mandatory.
 */
typedef struct KswHvmActiveControls
{
    ULONG pin;
    ULONG primary;
    ULONG secondary;
    ULONG exit;
    ULONG entry;
    /* Keep the 64-bit members below naturally aligned. */
    ULONG reserved;
    ULONGLONG pinCapability;
    ULONGLONG primaryCapability;
    ULONGLONG secondaryCapability;
    ULONGLONG exitCapability;
    ULONGLONG entryCapability;
} KswHvmActiveControls;

EXTERN_C_START

/*
 * Read one field of the current VMCS.  Returns 0 on success, matching the
 * VMREAD intrinsic this currently forwards to.
 *
 * Every VMCS access in the driver goes through here and its write counterpart.
 * The reason is that field storage is not fixed: under a hypervisor offering
 * the enlightened VMCS, "the current VMCS" is a shared page to be read with
 * ordinary loads, and the VMREAD instruction is both unnecessary and, on the
 * hot exit path, expensive.  Switching storage is one edit here; it is 60-odd
 * edits if every call site spells the instruction out, and the failure mode of
 * missing one is a field silently read from the wrong place.
 *
 * Callers must not assume the field was actually read on failure - Value is
 * left untouched, exactly as the intrinsic leaves it.
 */
UCHAR
kswordArkHvmVmcsFieldLoad(
    _In_ SIZE_T field,
    _Out_ SIZE_T* value
    );

/* Write one field of the current VMCS.  Returns 0 on success. */
UCHAR
kswordArkHvmVmcsFieldStore(
    _In_ SIZE_T field,
    _In_ SIZE_T value
    );

VOID
KswordARKHvmCaptureSegments(
    _Out_ KswHvmSegmentSnapshot* snapshot
    );

/* Describe one resolved segment in the layout VMCS guest state expects. */
typedef struct KswHvmSegmentState
{
    USHORT selector;
    ULONG limit;
    ULONG accessRights;
    ULONGLONG base;
} KswHvmSegmentState;

/*
 * Resolve one selector against a captured descriptor-table snapshot.
 *
 * Exported rather than kept private because anything constructing guest state
 * needs exactly this decoding - the system-segment high base, the unusable
 * marker for a null selector, the packed access-rights format.  A second copy
 * would be a second place for those three to drift, and the symptom of drift
 * is a VM entry that fails on guest state with no indication which field.
 */
NTSTATUS
kswordArkHvmReadSegment(
    _In_ const KswHvmSegmentSnapshot* snapshot,
    _In_ USHORT selector,
    _Out_ KswHvmSegmentState* segment
    );

ULONGLONG
KswordARKHvmAsmReadSsp(
    VOID
    );

VOID
KswordARKHvmControlledGuestEntry(
    VOID
    );

VOID
KswordARKHvmVmExitEntry(
    VOID
    );

NTSTATUS
kswordArkHvmConfigureVmcs(
    _In_ const KswHvmVmcsInput* input,
    _Out_ ULONG* vmInstructionError
    );

NTSTATUS
kswordArkHvmReadVmExitTelemetry(
    _Out_ KswHvmVmexitTelemetry* telemetry
    );

/* Omit only fields that have no architectural meaning for a successful CPUID exit. */
NTSTATUS kswordArkHvmReadVmExitTelemetryEx(KswHvmVmexitTelemetry* telemetry,
    BOOLEAN sparseCpuid);

EXTERN_C_END

/* Processor-owned AMD backend state; all hardware pages are nonpaged. */
#pragma once
#include "hvm_internal.h"
#include "hvm_metrics.h"
#include "hvm_svm_arch.h"

/* Bound the static NPT allocation ledger to 64 MiB of hardware tables. */
#define KSW_NPT_MAX_PAGES 16384UL
/* Per-processor stack is private to the SVM host loop. */
#define KSW_SVM_STACK_BYTES 32768UL
/* Bound nonblocking per-processor exit evidence. */
#define KSW_SVM_TRACE_ROWS 64UL

/* Own every table allocation until all processors have stopped. */
typedef struct KswNpt {
    /* Virtual table pages, recorded before publishing a parent entry. */
    PVOID* pages;
    /* Number of owned table pages. */
    ULONG pageCount;
    /* Physical address of the PML4. */
    ULONGLONG rootPa;
    /* Exclusive, complete guest physical coverage. */
    ULONGLONG limit;
    /* Address-width mask. */
    ULONGLONG addressMask;
    /* Host PAT index for WB. */
    ULONG wbIndex;
    /* Host PAT index for UC. */
    ULONG ucIndex;
    /* Allow a one-GiB leaf only when enumerated. */
    BOOLEAN page1Gb;
    /* Immutable RAM inventory retained for nested physical-operand admission. */
    PPHYSICAL_MEMORY_RANGE ranges;
} KswNpt;

/* One immutable-capability snapshot per processor. */
typedef struct KswSvmCaps {
    /* Maximum supported extended CPUID leaf. */
    ULONG maxLeaf;
    /* Enumerated ASID count including reserved zero. */
    ULONG asidCount;
    /* CPUID.8000000A EDX. */
    ULONG features;
    /* Physical-address width accepted by NPT. */
    ULONG physicalBits;
    /* Valid register mask: VM_CR=1, EFER=2, HSAVE=4, PAT=8. */
    ULONG valid;
    /* Last exception while reading privileged evidence. */
    NTSTATUS exception;
    /* Firmware SVM gate. */
    ULONGLONG vmCr;
    /* Original virtualization ownership evidence. */
    ULONGLONG efer;
    /* Existing HSAVE ownership must never be overwritten blindly. */
    ULONGLONG hsave;
    /* Cache layout must remain identical on every participating CPU. */
    ULONGLONG pat;
    /* Admission refusal and independent extended-state observation validity. */
    ULONG rejectReason, stateValid, cpuid1Ecx, xsaveFeatures;
    /* Read-only architectural state, never inferred from CPUID support alone. */
    ULONGLONG cr4, xcr0, xss;
    /* Valid only when CET was enumerated and both MSRs were read successfully. */
    ULONGLONG scet, isst;
    /* Current-thread user CET observations for bounded self-test return verification. */
    ULONGLONG ucet, pl3Ssp;
    /* CPUID.7.0 ECX.CET_SS; unsupported CPUs must not touch CET MSRs. */
    ULONG cetPresent;
    /* The VMM may filter one-GiB page support. */
    BOOLEAN page1Gb;
    /* Explicit SVM instruction availability. */
    BOOLEAN svm;
} KswSvmCaps;

/* Raw, CPU-local, seqlock-protected telemetry. */
typedef struct KswSvmTrace {
    /* Odd while a writer is modifying the record. */
    volatile LONG sequence;
    /* Stage follows the shared diagnostic stage namespace. */
    ULONG stage;
    /* Exact architecture exit code, including INVALID. */
    ULONGLONG exitCode;
    /* Raw exit operands. */
    ULONGLONG info1, info2;
    /* Guest continuation and address-space identity. */
    ULONGLONG rip, rsp, cr3;
    /* Next-RIP and event injection evidence. */
    ULONGLONG nrip, event;
    /* CPU-local timestamp; not a cross-CPU wall clock. */
    ULONGLONG tsc;
} KswSvmTrace;

/* Assembly consumes only the fixed prefix, whose offsets are asserted below. */
typedef struct KswSvmCpu {
    /* 00: hardware VMCB physical address. */
    ULONGLONG guestPa;
    /* 08: host extended state image physical address. */
    ULONGLONG hostPa;
    /* 10: guest VMCB kernel mapping. */
    KswSvmVmcb* guest;
    /* 18: dedicated host stack top. */
    ULONGLONG stackTop;
    /* 20: original launch stack/continuation. */
    ULONGLONG launchRsp;
    /* 28: XSAVE area, 64-byte aligned. */
    PVOID xstate;
    /* 30: requested XCR0 | XSS bits, paired with the selected save format. */
    ULONGLONG xstateMask;
    /* 38: original EFER before this CPU entered SVM. */
    ULONGLONG originalEfer;
    /* 40: original VM_HSAVE_PA. */
    ULONGLONG originalHsave;
    /* 48: GPR slots in x86 register-number order. RSP/RAX also live in VMCB. */
    ULONGLONG gpr[16];
    /* C8: executable launch result. */
    NTSTATUS result;
    /* CC: nonzero until the native continuation has completed. */
    volatile LONG active;
    /* D0: stop request observed by the private VMMCALL handler. */
    volatile LONG stopRequested;
    /* D4: one-shot self-test exits directly to the launch continuation. */
    ULONG selfTest;
    /* D8: captured RFLAGS before CLGI/CLI. */
    ULONGLONG launchFlags;
    /* E0: original CR0 while the host temporarily clears TS/EM for XSAVE. */
    ULONGLONG hostCr0;
    /* E8: permanently mapped System address space for VMRUN host state. */
    ULONGLONG hostCr3;
    /* F0: native-return scratch (RSP, RIP, RFLAGS). */
    ULONGLONG returnRsp, returnRip, returnFlags;
    /* 108: physical address written to VM_HSAVE_PA before launch. */
    ULONGLONG hsavePa;
    /* 110: zero selects XSAVE64; one selects compacted XSAVES64/XRSTORS64. */
    ULONG xstateCompacted;
    /* 114: CET MSRs exist and native return must restore ISST_ADDR/S_CET. */
    ULONG cetPresent;
    /* Resource and runtime ownership beyond the assembly prefix. */
    KswHvmRuntime* runtime;
    /* Public row owns processor identity and common states. */
    KswHvmCpuResource* resource;
    /* Captured capability image used for all entry checks. */
    KswSvmCaps caps;
    /* Host extended-state page, separate from hardware HSAVE. */
    KswSvmVmcb* host;
    /* Hardware private host-save page and its physical address. */
    PVOID hsave;
    /* MSR permission map. */
    PVOID msrpm;
    /* I/O permission map. */
    PVOID iopm;
    /* Allocation bases retained for release. */
    PVOID stack, xstateAllocation;
    /* XSAVE capacity; XCR0 changes are validated against this before entry. */
    ULONG xstateBytes;
    /* Entry-stage evidence independent of VMX status bits. */
    volatile LONG stage;
    /* Per-CPU self-test success marker. */
    ULONG testPassed;
    /* Prevent a second VMMCALL after a native return whose ownership readback failed. */
    ULONG nativeReturnSeen;
    /* Preserve the originating failure across a successful cleanup rendezvous. */
    NTSTATUS failureStatus;
    /* Stage associated with the original failed entry/stop. */
    ULONG failureStage;
    /* Published ring position; only current processor writes. */
    ULONG tracePosition;
    /* Number of actual VMRUN attempts (each requests full TLB invalidation). */
    ULONGLONG tlbRequests;
    /* Fixed-capacity raw exit history. */
    KswSvmTrace trace[KSW_SVM_TRACE_ROWS];
    /* Optional bounded nested-probe state; appended after every assembly-visible field. */
    struct KswSvmNested* nested;
} KswSvmCpu;
/* Assert all assembly-visible anchors against the C compiler. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, gpr) == 0x48);
C_ASSERT(FIELD_OFFSET(KswSvmCpu, result) == 0xc8);
C_ASSERT(FIELD_OFFSET(KswSvmCpu, launchFlags) == 0xd8);
C_ASSERT(FIELD_OFFSET(KswSvmCpu, hostCr3) == 0xe8);
C_ASSERT(FIELD_OFFSET(KswSvmCpu, returnRsp) == 0xf0);
/* The assembler uses this final fixed-prefix field during initial ownership setup. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, hsavePa) == 0x108);
/* Keep the format selector and optional native-return MSR guard paired with MASM. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, xstateCompacted) == 0x110);
C_ASSERT(FIELD_OFFSET(KswSvmCpu, cetPresent) == 0x114);
/* MASM native restoration consumes these exact ordinary-VMCB offsets. */
C_ASSERT(KSW_VMCB_S_CET == 0x5e0 && KSW_VMCB_SSP == 0x5e8 && KSW_VMCB_ISST == 0x5f0);

/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, guestPa) == 0x0);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, hostPa) == 0x8);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, guest) == 0x10);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, stackTop) == 0x18);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, launchRsp) == 0x20);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, xstate) == 0x28);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, xstateMask) == 0x30);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, originalEfer) == 0x38);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, originalHsave) == 0x40);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, active) == 0xcc);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, stopRequested) == 0xd0);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, selfTest) == 0xd4);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, hostCr0) == 0xe0);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, returnRip) == 0xf8);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KswSvmCpu, returnFlags) == 0x100);

/* Runtime-private state, allocated only by prepare. */
typedef struct KswSvmState {
    /* Shared immutable identity map. */
    KswNpt npt;
    /* Per-processor ownership array. */
    KswSvmCpu* cpus;
    /* Frozen topology size. */
    ULONG count;
    /* Power generation that produced the self-test evidence. */
    LONG testedPowerGeneration;
    /* Preparation and execution must use the same power epoch. */
    LONG preparedPowerGeneration;
} KswSvmState;

/* PASSIVE_LEVEL resource and capability helpers. */
NTSTATUS kswordSvmProbeCpu(KswSvmCaps* caps);
NTSTATUS kswordSvmProbe(KswHvmRuntime* runtime);
NTSTATUS kswordSvmValidateFlags(KswHvmRuntime* runtime, ULONG flags);
NTSTATUS kswordSvmPrepare(KswHvmRuntime* runtime, ULONG flags);
VOID kswordSvmRelease(KswHvmRuntime* runtime);
NTSTATUS kswordSvmSelfTest(KswHvmRuntime* runtime, ULONG flags);
NTSTATUS kswordSvmStart(KswHvmRuntime* runtime, ULONG flags);
NTSTATUS kswordSvmStop(KswHvmRuntime* runtime);
NTSTATUS kswordNptBuild(KswNpt* npt, const KswSvmCaps* caps);
VOID kswordNptRelease(KswNpt* npt);
/* Processor-pinned, nonpageable execution helpers. */
NTSTATUS kswordSvmBuildVmcb(KswSvmCpu* cpu);
NTSTATUS kswordSvmEnterCurrent(KswSvmCpu* cpu);
/* Called only after the assembly continuation has returned to native Windows. */
BOOLEAN kswordSvmVerifyNativeState(KswSvmCpu* cpu);
VOID kswordSvmTrace(KswSvmCpu* cpu, ULONG stage);
ULONG KswordSvmExit(KswSvmCpu* cpu);
/* AMD assembly wrappers, never called on Intel. */
NTSTATUS KswordSvmAsmLaunch(KswSvmCpu* cpu);
ULONGLONG KswordSvmAsmCall(ULONGLONG operation);
VOID KswordSvmAsmCaptureSegments(KswSvmVmcb* vmcb);
VOID KswordSvmAsmGuestResume(VOID);
VOID KswordSvmAsmTestGuest(VOID);
/* The caller holds the shared runtime lock across diagnostic resource reads. */
VOID kswordSvmMetrics(KswHvmRuntime* runtime, KSWORD_ARK_HVM_METRICS_RESPONSE* response);

/* KD-only one-shot fault controls: stage 1=allocation, 2=before entry, 3=after continuation. */
extern volatile LONG gKswSvmFaultStage;
/* Windows global index is checked against the frozen topology before use. */
extern volatile LONG gKswSvmFaultCpu;
/* An explicit debugger write of one arms precisely one matching fault. */
extern volatile LONG gKswSvmFaultArmed;
/* No registry, command-line or user-mode production interface enables these hooks. */
BOOLEAN kswordSvmFault(ULONG stage, ULONG cpu);

/* Driver-owned, explicitly requested nested-SVM hardware probe resources. */
#pragma once
#if defined(KSW_SVM_NESTED_HOST_TEST)
/* Test builds execute the same dispatcher with explicit host-only platform substitutes. */
#include "svm_nested_probe_fixture.h"
#else
#include "hvm_svm.h"
#include "hvm_phys_window.h"
#endif
#include "hvm_svm_nested_shadow.h"
#include "hvm_svm_nested_state.h"
#include "hvm_svm_nested_msr.h"
#include "hvm_svm_nested_permissions.h"
/* Enough sparse tables for the bounded probe; exhaustion returns a failed test. */
#define KSW_NSVM_PROBE_PAGES 64U
/* Private markers distinguish the inner exit from the final outer continuation. */
#define KSW_NSVM_INNER_MARKER 0x4b534e31U
/* The final CPUID may succeed only after virtual ownership was relinquished. */
#define KSW_NSVM_DONE_MARKER 0x4b534e32U
/* Private VMMCALL opens the known probe before any nonvolatile register changes. */
#define KSW_NSVM_BEGIN 3ULL
/* Per-CPU state is retained until native return and common release. */
typedef struct KswSvmNested {
    /* Saved initial Windows image supports bounded-test abort, never arbitrary VM abort. */
    KswSvmVmcb original;
    /* VMRUN's virtual host state is separate from its opaque HSAVE page. */
    KswSvmVmcb l1;
    /* Snapshot of the complete, driver-owned VMCB12. */
    KswSvmVmcb vmcb12;
    /* Immutable permission evidence belongs to the same VMRUN as Vmcb12. */
    KswNsvmPermissionImage permissions;
    /* One contiguous allocation: merged MSRPM followed by merged IOPM. */
    PUCHAR mergedMaps;
    /* Derived at PASSIVE_LEVEL and checked against MAXPHYADDR before use. */
    ULONGLONG mergedMapsPa;
    /* Preserve nonvolatile caller state even if the controlled probe aborts. */
    ULONGLONG originalGpr[16];
    /* Two contiguous pages: VMCB12 operand followed by virtual HSAVE. */
    KswSvmVmcb* operand;
    /* Operand identity is resolved before any SVM instruction executes. */
    ULONGLONG operandPa;
    /* Private nonpaged stack for the bounded inner guest. */
    PVOID stack;
    /* Preallocated translation cache and ownership descriptors. */
    KswNshadow shadow;
    /* All pool pages are tracked even when preparation fails partway. */
    KswNshadowPage pages[KSW_NSVM_PROBE_PAGES];
    /* Prepared physical window, never shared across CPUs. */
    KswHvmPhysWindow* window;
    /* Runtime identity map/RAM inventory lifetime is held by the SVM backend. */
    KswNpt* outer;
    /* Translation policy remains fixed throughout one probe. */
    KswNmmuConfig config;
    /* Last resolution is retained for KD diagnostics, including failed NPF ownership. */
    KswNmmuResult lastTranslation;
    /* Virtual registers do not grant access to the real host's SVM ownership. */
    KswNsvmMsrs msrs;
    /* Probe entry/reflection counters are evidence, not general nested support flags. */
    ULONG begun, runningL2, entries, reflections, faults, virtualGif;
    /* Odd during a probe; even only after verified native EFER/HSAVE restoration. */
    volatile LONG sequence;
    /* Published together with the completed sequence, including failed probes. */
    NTSTATUS completionStatus;
    /* Precise raw inner exit and marker before reflection changes the current image. */
    ULONGLONG lastExit, lastMarker;
} KswSvmNested;
/* Resource acquisition is PASSIVE_LEVEL only and uses the backend release ledger. */
NTSTATUS kswordSvmNestedPrepare(KswSvmCpu* cpu, ULONG index);
/* Never call until common ownership checks prove the processor is native. */
VOID kswordSvmNestedRelease(KswSvmCpu* cpu);
/* Set up the driver-owned operand after the regular VMCB builder completed. */
NTSTATUS kswordSvmNestedBuildProbe(KswSvmCpu* cpu);
/* Probe-only dispatcher: zero resumes a VMCB; one restores the original Windows caller. */
ULONG kswordSvmNestedProbeExit(KswSvmCpu* cpu);
/* Physical RAM callbacks for production MMU resolution, not the host-test adapter. */
int kswordSvmNestedRead(void* context, KswSvmU64 address, KswSvmU64* value);
/* Atomic source A/D commit through the same per-processor physical window. */
int kswordSvmNestedCompareOr(void* context, KswSvmU64 address, KswSvmU64 expected, KswSvmU64 bits);
/* Assembly markers are also used to validate the exact probe continuation. */
VOID KswordSvmAsmNestedProbe(VOID);
/* Inner code performs a unique intercepted CPUID; it never runs an OS. */
VOID KswordSvmAsmNestedPayload(VOID);

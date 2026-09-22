/*
 * hvm_ctl: Minimal CLI tool for KSword HVM control and status (no Qt dependency).
 *
 * Purpose: KswordCLI only provides read-only hvm-status and hvm-events. Starting HVM requires
 * IOCTL_KSWORD_ARK_CONTROL_HVM, which is typically initiated by the kernel page of the Qt main process.
 * A Qt-independent entry point is required on test machines without a GUI.
 *
 * **Protocol structures are no longer manually copied.** The previous version redeclared request/response structures and
 * command IDs in this file, causing a mismatch between the per-processor flag set and the allowedFlags in hvm_runtime.c:
 * SELF_TEST lacked the FORCE bit, causing the driver to always return CONFIRMATION_REQUIRED. That status code appeared
 * to indicate "security policy not enabled," misleading the investigation down an irrelevant path. Now directly
 * including the authoritative header from shared/driver makes structure drift errors impossible at compile time.
 *
 * The flag set accepted by each command must match the allowedFlags switch in hvm_runtime.c bit-by-bit:
 * An extra bit indicates INVALID_REQUEST (`flags & ~allowedFlags`), while the absence of FORCE indicates
 * CONFIRMATION_REQUIRED. Both types of rejection occur before any actual action is taken and are indistinguishable; therefore,
 * this file uses an explicit table to fix them and annotates the corresponding driver line numbers in the comments.
 *
 * Grading is important; do not skip steps:
 *   status: Read-only query that does not modify state. Automation scripts should run this first to decide the next step.
 *   prepare: Allocate per-processor resources without entering VMX. Failure is only a resource issue.
 *   Self-test: perform VMXON followed by VMXOFF on each processor. This is the first actual entry into
 *               VMX root mode, but it is not persistent; it reverts upon exit. Run this first in nested environments.
 *   resident: VMM resident on all processors with EPT enabled. After this step, the system runs continuously in VMX non-root mode.
 *   soak: Run for a bounded duration then stop to prove stability under normal system activity.
 *   stop: Stop resident mode.
 *   teardown: Release resources.
 *   reset-fault clears FAULTED / ROLLBACK_REQUIRED. Repeatedly calling prepare will set the state
 *               to FAULTED (when already ready, it returns STATUS_ALREADY_REGISTERED, an NT_ERROR, which
 *               routes to the FAULTED branch in hvm_runtime.c). Once in the FAULTED state, START_RESIDENT is
 *               immediately rejected (via the INVALID_DEVICE_STATE branch in hvm_resident.c).
 *               Automation must be able to escape this pitfall on its own.
 *
 * Exit code: 0 = protocol status OK; 2 = protocol status not OK (value corresponds to status in --json).
 *         1 = Transport layer failure (device open failure, DeviceIoControl failure, buffer too short).
 *
 * Compile: cl /nologo /W4 /WX /O2 hvm_ctl.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <tlhelp32.h>
/* __cpuid: tlb-probe-exit uses it to force an unconditional VM exit. */
#include <intrin.h>

/* The sole source of truth for the protocol. Manually copying it creates a silent drift. */
#include "../../shared/driver/KswordArkHvmIoctl.h"
#include "../../shared/driver/KswordArkHvmMetricsIoctl.h"
/* Constants for capability filtering whitelist; the criteria are shared with the driver reference. */
#include "../../shared/driver/KswordArkHvmControls.h"
/* acl-probe must verify access gateways for these two destructive IOCTLs and retrieve their control codes. */
#include "../../shared/driver/KswordArkProcessIoctl.h"
#include "../../shared/driver/KswordArkMemoryIoctl.h"
/* Reuse the main program's R0 descriptor protocol for gdt-dump. */
#include "../../shared/driver/KswordArkKernelIoctl.h"

#define KSW_DEVICE_PATH L"\\\\.\\KswordARKLog"

#include "HvmCommandCatalog.h"
#include "../../shared/driver/KswordArkHvmRequest.h"
typedef HvmCommandSpec HvmCtlVerb;

static const char* controlStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_CONTROL_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU:       return "UNSUPPORTED_CPU";
    case KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED:     return "FIRMWARE_DISABLED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT:   return "HYPERVISOR_CONFLICT";
    case KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED:      return "ALREADY_PREPARED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED:       return "RESOURCE_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED:      return "SELF_TEST_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED:         return "VERIFY_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_BUSY:                  return "BUSY";
    case KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED:   return "GUEST_LAUNCH_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT:     return "UNEXPECTED_VMEXIT";
    case KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION: return "PARTIAL_IMPLEMENTATION";
    case KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED:     return "RENDEZVOUS_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED:     return "ROLLBACK_REQUIRED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED:    return "NESTED_UNSUPPORTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED:     return "EVMCS_UNSUPPORTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED:
        return "POWER_TRANSITION_BLOCKED";
    /*
     * The previous version omitted the section above 20, causing the real failure of START_RESIDENT to be
     * printed as "UNKNOWN", disguising a failure with a definite protocol name as an "unknown status code".
     * LIFECYCLE_GUARD_FAILED is particularly critical: it is the sole mapping target for
     * STATUS_INVALID_DEVICE_STATE (via kswordArkHvmControlStatusFromNtStatus in hvm_runtime.c). The name itself
     * points to kswordArkHvmArmUnloadGuard; seeing it eliminates the need to guess which gate was triggered.
     */
    case KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED:
        return "LIFECYCLE_GUARD_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_NOT_ARMED:
        return "LOCAL_EPT_NOT_ARMED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_LEAF_SET_TOO_LARGE:
        return "LOCAL_EPT_LEAF_SET_TOO_LARGE";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_PAGE_BUDGET_EXHAUSTED:
        return "LOCAL_EPT_PAGE_BUDGET_EXHAUSTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_SPLIT_MISSING:
        return "LOCAL_EPT_SPLIT_MISSING";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_VERIFY_FAILED:
        return "LOCAL_EPT_VERIFY_FAILED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_VMFUNC:
        return "LOCAL_EPT_CONFLICTS_WITH_VMFUNC";
    case KSWORD_ARK_HVM_CONTROL_STATUS_LOCAL_EPT_CONFLICTS_WITH_NESTED:
        return "LOCAL_EPT_CONFLICTS_WITH_NESTED";
    case KSWORD_ARK_HVM_CONTROL_STATUS_EPT_WINDOW_TOO_SMALL:
        return "EPT_WINDOW_TOO_SMALL";
    default: return "UNKNOWN";
    }
}

static const char* implementationName(unsigned long v)
{
    switch (v) {
    case KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED:     return "UNSUPPORTED";
    case KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY: return "CAPABILITY_ONLY";
    case KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL:         return "PARTIAL";
    case KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE:          return "ACTIVE";
    default: return "UNKNOWN";
    }
}

/* Expand state bits one by one. Names are more readable than hex values and allow log filtering via grep. */
typedef struct HvmStateBit { unsigned long bit; const char* name; } HvmStateBit;

static const HvmStateBit kGStateBits[] = {
    { KSWORD_ARK_HVM_STATE_INITIALIZED,      "INITIALIZED" },
    { KSWORD_ARK_HVM_STATE_RESOURCES_READY,  "RESOURCES_READY" },
    { KSWORD_ARK_HVM_STATE_EPT_READY,        "EPT_READY" },
    { KSWORD_ARK_HVM_STATE_SELF_TESTED,      "SELF_TESTED" },
    { KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED, "SELF_TEST_PASSED" },
    { KSWORD_ARK_HVM_STATE_BUSY,             "BUSY" },
    { KSWORD_ARK_HVM_STATE_FAULTED,          "FAULTED" },
    { KSWORD_ARK_HVM_STATE_EPT_TRUNCATED,    "EPT_TRUNCATED" },
    { KSWORD_ARK_HVM_STATE_GUEST_READY,      "GUEST_READY" },
    { KSWORD_ARK_HVM_STATE_GUEST_RUNNING,    "GUEST_RUNNING" },
    { KSWORD_ARK_HVM_STATE_GUEST_EXITED,     "GUEST_EXITED" },
    { KSWORD_ARK_HVM_STATE_NESTED_ACTIVE,    "NESTED_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_NESTED_VALIDATED, "NESTED_VALIDATED" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_STARTING, "RESIDENT_STARTING" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE,   "RESIDENT_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING, "RESIDENT_STOPPING" },
    { KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE,  "EPT_RULES_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE,  "EVENTS_AVAILABLE" },
    { KSWORD_ARK_HVM_STATE_NESTED_PARTIAL,    "NESTED_PARTIAL" },
    { KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL,     "EVMCS_PARTIAL" },
    { KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED, "ROLLBACK_REQUIRED" },
    { KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING, "POWER_TRANSITION_PENDING" },
    { KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED,       "UNLOAD_GUARD_ARMED" },
    { KSWORD_ARK_HVM_STATE_RESIDENT_NESTED,          "RESIDENT_NESTED" },
    { KSWORD_ARK_HVM_STATE_VE_ACTIVE,                "VE_ACTIVE" },
    { KSWORD_ARK_HVM_STATE_VMFUNC_ACTIVE,            "VMFUNC_ACTIVE" },
};

static void printStateBits(const char* prefix, unsigned long flags)
{
    size_t i;
    unsigned long known = 0UL;
    printf("%s0x%08lX =", prefix, flags);
    for (i = 0U; i < sizeof(kGStateBits) / sizeof(kGStateBits[0]); ++i) {
        known |= kGStateBits[i].bit;
        if ((flags & kGStateBits[i].bit) != 0UL) {
            printf(" %s", kGStateBits[i].name);
        }
    }
    if ((flags & ~known) != 0UL) {
        /* Unknown bits must be explicitly reported. Silently dropping them treats new states as non-existent. */
        printf("  (未知位 0x%08lX)", flags & ~known);
    }
    if (flags == 0UL) { printf(" <无>"); }
    printf("\n");
}

/* Array of status bit names in JSON. Fields are for machine criteria, not human-readable alignment. */
static void printStateBitsJson(unsigned long flags)
{
    size_t i;
    int first = 1;
    printf("[");
    for (i = 0U; i < sizeof(kGStateBits) / sizeof(kGStateBits[0]); ++i) {
        if ((flags & kGStateBits[i].bit) != 0UL) {
            printf("%s\"%s\"", first ? "" : ",", kGStateBits[i].name);
            first = 0;
        }
    }
    printf("]");
}

/*
 * Bitwise expansion of IA32_VMX_EPT_VPID_CAP (MSR 0x48C).
 *
 * **Bit 0 (execute-only) is the make-or-break prerequisite for the split-view backend**, yet it has no
 * corresponding KSWORD_ARK_HVM_FEATURE_* bit—no matter how complete featureFlags is, it cannot answer this.
 * KswordArkHvmEptSwDecide checks it before kind dispatch; when it is 0, it uniformly rejects
 * both CLOAK and HOOK, meaning no switch occurs. Thus, it must be handled separately.
 *
 * Bit definitions are from SDM Appendix A.10.
 */
typedef struct EptCapBit { unsigned bit; const char* name; const char* note; } EptCapBit;

static const EptCapBit kGEptCapBits[] = {
    {  0, "EXECUTE_ONLY",     "**分离视图后端的硬前提**" },
    {  6, "PAGE_WALK_4",      "4 级页遍历" },
    {  8, "MEMORY_TYPE_UC",   "EPTP 可用 UC" },
    { 14, "MEMORY_TYPE_WB",   "EPTP 可用 WB" },
    { 16, "PDE_2MB",          "2MiB 大叶" },
    { 17, "PDPTE_1GB",        "1GiB 大叶" },
    { 20, "INVEPT",           "支持 INVEPT" },
    { 21, "ACCESSED_DIRTY",   "叶 A/D 位" },
    { 22, "ADVANCED_VE_INFO", "#VE 信息页扩展" },
    { 25, "INVEPT_SINGLE",    "single-context" },
    { 26, "INVEPT_ALL",       "all-context" },
    { 32, "INVVPID",          "支持 INVVPID" },
};

static void printEptVpidCapability(const char* indent, unsigned long long cap)
{
    size_t i;
    printf("%sEPT/VPID cap : 0x%016llX\n", indent, cap);
    if (cap == 0ULL) {
        printf("%s  （为 0：驱动未采集或本机不支持 EPT）\n", indent);
        return;
    }
    for (i = 0U; i < sizeof(kGEptCapBits) / sizeof(kGEptCapBits[0]); ++i) {
        const int kOn = ((cap >> kGEptCapBits[i].bit) & 1ULL) != 0ULL;
        printf("%s  [%s] bit %-2u %-16s %s\n",
               indent, kOn ? "X" : " ", kGEptCapBits[i].bit,
               kGEptCapBits[i].name, kGEptCapBits[i].note);
    }
}

/*
 * Bitwise expansion of featureFlags.
 *
 * Previously, only a single 64-bit hex value was printed. The hard prerequisite for the split view,
 * MONITOR_TRAP_FLAG, is hidden in bit24. Consequently, the decision of whether the guest lacks
 * MTF—which determines the entire HOOK path—cannot be read by name on the machine; it requires
 * manual hex conversion, which is the most error-prone step with no feedback if done incorrectly.
 */
typedef struct HvmFeatureBit
{
    unsigned long long bit;
    const char* name;
} HvmFeatureBit;

static const HvmFeatureBit kGFeatureBits[] = {
    { KSWORD_ARK_HVM_FEATURE_INTEL,                     "INTEL" },
    { KSWORD_ARK_HVM_FEATURE_VMX,                       "VMX" },
    { KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED,    "FEATURE_CONTROL_LOCKED" },
    { KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX,           "VMX_OUTSIDE_SMX" },
    { KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS,             "TRUE_CONTROLS" },
    { KSWORD_ARK_HVM_FEATURE_EPT,                       "EPT" },
    { KSWORD_ARK_HVM_FEATURE_EPT_WB,                    "EPT_WB" },
    { KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL,               "EPT_4_LEVEL" },
    { KSWORD_ARK_HVM_FEATURE_EPT_2MB,                   "EPT_2MB" },
    { KSWORD_ARK_HVM_FEATURE_EPT_AD,                    "EPT_AD" },
    { KSWORD_ARK_HVM_FEATURE_INVEPT,                    "INVEPT" },
    { KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE,             "INVEPT_SINGLE" },
    { KSWORD_ARK_HVM_FEATURE_INVEPT_ALL,                "INVEPT_ALL" },
    { KSWORD_ARK_HVM_FEATURE_VPID,                      "VPID" },
    { KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT,        "HYPERVISOR_PRESENT" },
    { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED,        "NESTED_VMX_EXPOSED" },
    { KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST,            "ONE_SHOT_GUEST" },
    { KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY,          "VMEXIT_TELEMETRY" },
    { KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM,              "RESIDENT_VMM" },
    { KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS,      "MULTICORE_RENDEZVOUS" },
    { KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT,             "EPT_4KB_SPLIT" },
    { KSWORD_ARK_HVM_FEATURE_EPT_RULES,                 "EPT_RULES" },
    { KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING,            "EPT_EVENT_RING" },
    { KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT,            "MTRR_AWARE_EPT" },
    { KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG,         "MONITOR_TRAP_FLAG" },
    { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH,       "NESTED_VMX_DISPATCH" },
    { KSWORD_ARK_HVM_FEATURE_NESTED_VMX_ACTIVE,         "NESTED_VMX_ACTIVE" },
    { KSWORD_ARK_HVM_FEATURE_SHADOW_EPT,                "SHADOW_EPT" },
    { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE,      "HYPERV_EVMCS_CAPABLE" },
    { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1,           "HYPERV_EVMCS_V1" },
    { KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_ACTIVE,       "HYPERV_EVMCS_ACTIVE" },
    { KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION, "VMX_INSTRUCTION_EMULATION" },
    { KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD,         "POWER_STATE_GUARD" },
    { KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD,  "PROCESSOR_TOPOLOGY_GUARD" },
    { KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD,       "DRIVER_UNLOAD_GUARD" },
    { KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED, "RESIDENT_LIFECYCLE_GUARDED" },
    { KSWORD_ARK_HVM_FEATURE_MSR_BITMAP,                "MSR_BITMAP" },
    { KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION,            "EXIT_EMULATION" },
    { KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED,        "RESIDENT_SUSTAINED" },
    { KSWORD_ARK_HVM_FEATURE_AMD,                       "AMD" },
    { KSWORD_ARK_HVM_FEATURE_SVM,                       "SVM" },
    { KSWORD_ARK_HVM_FEATURE_NPT,                       "NPT" },
    { KSWORD_ARK_HVM_FEATURE_SVM_NRIP,                  "SVM_NRIP" },
    { KSWORD_ARK_HVM_FEATURE_SVM_DECODE_ASSISTS,        "SVM_DECODE_ASSISTS" },
    { KSWORD_ARK_HVM_FEATURE_SVM_FLUSH_BY_ASID,         "SVM_FLUSH_BY_ASID" },
    { KSWORD_ARK_HVM_FEATURE_SVM_FIRMWARE_DISABLED,     "SVM_FIRMWARE_DISABLED" },
    { KSWORD_ARK_HVM_FEATURE_EPT_VIOLATION_VE,          "EPT_VIOLATION_VE" },
    { KSWORD_ARK_HVM_FEATURE_VE_INFO_READY,             "VE_INFO_READY" },
    { KSWORD_ARK_HVM_FEATURE_VE_SUPPRESSED_BY_DEFAULT,  "VE_SUPPRESSED_BY_DEFAULT" },
    { KSWORD_ARK_HVM_FEATURE_VM_FUNCTIONS,              "VM_FUNCTIONS" },
    { KSWORD_ARK_HVM_FEATURE_EPTP_SWITCHING,            "EPTP_SWITCHING" },
    { KSWORD_ARK_HVM_FEATURE_EPTP_LIST_READY,           "EPTP_LIST_READY" },
    { KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED,           "LOCAL_EPT_ARMED" },
    { KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED,         "EPTP_SWITCH_ARMED" },
};

/*
 * Separate the bits actually checked during the separated view installation phase; **print them regardless of whether they are set**.
 * Only listing set bits turns 'missing a capability' into an invisible message —
 * whereas missing bits are exactly what need to be seen at a glance on this line.
 */
static void printViewPrerequisites(const char* indent, unsigned long long flags)
{
    static const HvmFeatureBit kRequired[] = {
        { KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE,     "INVEPT_SINGLE" },
        { KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG, "MONITOR_TRAP_FLAG" },
        { KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED,   "LOCAL_EPT_ARMED" },
    };
    const int kEptpSwitch =
        (flags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
    size_t i;
    /*
     * First clarify which backend is currently in use. The two backends require **different capability
     * sets**; without specifying the backend, checking the following items would lead to the incorrect
     * conclusion 'MTF is missing so installation fails', which is invalid under EPTP switching.
     */
    printf("%s分离视图后端 : %s\n", indent,
           kEptpSwitch ? "EPTP 切换（不需要 MTF）"
                      : "写叶 + monitor-trap（默认）");
    printf("%s分离视图前提 :\n", indent);
    for (i = 0U; i < sizeof(kRequired) / sizeof(kRequired[0]); ++i) {
        const int kOn = (flags & kRequired[i].bit) != 0ULL;
        const char* note = "";
        if (kOn == 0) {
            if (kRequired[i].bit == KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) {
                note = "（多核才需要；1 vCPU 上不影响安装）";
            } else if (kRequired[i].bit ==
                           KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG &&
                       kEptpSwitch != 0) {
                note = "（EPTP 切换后端不需要它）";
            } else {
                note = "**缺这一位，view add 必被拒**";
            }
        }
        printf("%s  [%s] %-18s %s\n", indent, kOn ? "X" : " ",
               kRequired[i].name, note);
    }
}

static void printFeatureBits(const char* indent, unsigned long long flags)
{
    size_t i;
    unsigned long long known = 0ULL;
    int printed = 0;
    printf("%s能力位       : 0x%016llX =", indent, flags);
    for (i = 0U; i < sizeof(kGFeatureBits) / sizeof(kGFeatureBits[0]); ++i) {
        known |= kGFeatureBits[i].bit;
        if ((flags & kGFeatureBits[i].bit) != 0ULL) {
            /* Line too long; wrap every four words while preserving grep-friendly word forms. */
            if (printed != 0 && (printed % 4) == 0) {
                printf("\n%s               ", indent);
            }
            printf(" %s", kGFeatureBits[i].name);
            printed += 1;
        }
    }
    if (flags == 0ULL) { printf(" <无>"); }
    printf("\n");
    if ((flags & ~known) != 0ULL) {
        /* Unknown bits must be explicitly reported. Silently dropping them treats new capabilities as non-existent. */
        printf("%s               (未知位 0x%016llX)\n", indent, flags & ~known);
    }
    printViewPrerequisites(indent, flags);
}

static void printFeatureBitsJson(unsigned long long flags)
{
    size_t i;
    int first = 1;
    printf("[");
    for (i = 0U; i < sizeof(kGFeatureBits) / sizeof(kGFeatureBits[0]); ++i) {
        if ((flags & kGFeatureBits[i].bit) != 0ULL) {
            printf("%s\"%s\"", first ? "" : ",", kGFeatureBits[i].name);
            first = 0;
        }
    }
    printf("]");
}

/*
 * One row per processor. This is the only place that can answer 'which core and which VMX instruction is stuck'.
 *
 * The worker (kswordArkHvmResidentStartCurrent in hvm_resident.c) returns STATUS_HV_OPERATION_FAILED
 * for failure at any VMXON / VMCLEAR / VMPTRLD / VMWRITE / VMLAUNCH step. The protocol layer reduces
 * all of these to RENDEZVOUS_FAILED, so the response alone does not identify the failing step. Before
 * each failure, however, the worker stores the VMX instruction result in Row.vmxInstructionResult and
 * accumulates progress in Row.stateFlags. Together, these identify where it failed.
 *
 * The value of vmxInstructionResult is defined in SDM 30.2:
 *   0 = Success; 1 = VMfailValid (VMCS valid, error code in VMCS field 0x4400);
 *   2 = VMfailInvalid (no current VMCS, cannot retrieve error code).
 */
static const HvmStateBit kGCpuStateBits[] = {
    { KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY,  "RESOURCE_READY" },
    { KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED,     "SELF_TESTED" },
    { KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED, "VMXON_SUCCEEDED" },
    { KSWORD_ARK_HVM_CPU_STATE_EXCEPTION,       "EXCEPTION" },
    { KSWORD_ARK_HVM_CPU_STATE_CONFLICT,        "CONFLICT" },
    { KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED,     "VMCS_LOADED" },
    { KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED,  "GUEST_LAUNCHED" },
    { KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED,  "VMEXIT_HANDLED" },
    { KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE, "RESIDENT_ACTIVE" },
    { KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED,  "STOP_REQUESTED" },
    { KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED,   "DEVIRTUALIZED" },
    { KSWORD_ARK_HVM_CPU_STATE_NESTED_PARTIAL,  "NESTED_PARTIAL" },
    { KSWORD_ARK_HVM_CPU_STATE_EVMCS_PARTIAL,   "EVMCS_PARTIAL" },
};

static const char* vmxResultName(unsigned char r)
{
    switch (r) {
    case 0U:    return "成功";
    case 1U:    return "VMfailValid（错误码见 VMCS 0x4400）";
    case 2U:    return "VMfailInvalid（无当前 VMCS）";
    case 0xFFU: return "未执行";
    default:    return "?";
    }
}

static void printCpuRows(const KSWORD_ARK_QUERY_HVM_RESPONSE* rsp, int asJson)
{
    unsigned long i;
    unsigned long count = rsp->processorCount;
    size_t b;

    if (count > KSWORD_ARK_HVM_MAX_PROCESSORS) {
        count = KSWORD_ARK_HVM_MAX_PROCESSORS;
    }
    if (asJson) {
        printf(",\"processors\":[");
        for (i = 0UL; i < count; ++i) {
            const KSWORD_ARK_HVM_CPU_ROW* row = &rsp->processors[i];
            int first = 1;
            printf("%s{\"index\":%lu,\"group\":%u,\"number\":%u,"
                   "\"backend\":%lu,\"executionStage\":%lu,\"svmExitCode\":\"0x%016llX\",\"vmxInstructionResult\":%u,\"stateFlags\":%lu,"
                   "\"stateHex\":\"0x%08lX\",\"lastStatus\":\"0x%08lX\","
                   "\"lastExitReason\":%lu,\"vmExitCount\":%llu,\"stateNames\":[",
                   (i == 0UL) ? "" : ",", i,
                   (unsigned)row->processorGroup, (unsigned)row->processorNumber,
                   row->backend, row->executionStage, row->svmExitCode, (unsigned)row->vmxInstructionResult, row->stateFlags,
                   row->stateFlags, (unsigned long)row->lastStatus,
                   row->lastExitReason, row->vmExitCount);
            for (b = 0U; b < sizeof(kGCpuStateBits) / sizeof(kGCpuStateBits[0]); ++b) {
                if ((row->stateFlags & kGCpuStateBits[b].bit) != 0UL) {
                    printf("%s\"%s\"", first ? "" : ",", kGCpuStateBits[b].name);
                    first = 0;
                }
            }
            printf("]}");
        }
        printf("]");
        return;
    }

    printf("\n  --- 每处理器 ---\n");
    for (i = 0UL; i < count; ++i) {
        const KSWORD_ARK_HVM_CPU_ROW* row = &rsp->processors[i];
        printf("  CPU %lu (组 %u 号 %u): vmxResult=%u (%s)  lastStatus=0x%08lX\n",
               i, (unsigned)row->processorGroup, (unsigned)row->processorNumber,
               (unsigned)row->vmxInstructionResult,
               vmxResultName(row->vmxInstructionResult),
               (unsigned long)row->lastStatus);
        printf("      状态 0x%08lX =", row->stateFlags);
        for (b = 0U; b < sizeof(kGCpuStateBits) / sizeof(kGCpuStateBits[0]); ++b) {
            if ((row->stateFlags & kGCpuStateBits[b].bit) != 0UL) {
                printf(" %s", kGCpuStateBits[b].name);
            }
        }
        if (row->stateFlags == 0UL) { printf(" <无>"); }
        printf("\n");
        if (row->vmExitCount != 0ULL || row->lastExitReason != 0UL) {
            printf("      退出 count=%llu lastReason=%lu\n",
                   row->vmExitCount, row->lastExitReason);
        }
    }
}

/*
 * Decoding of lastVmInstructionError.
 *
 * When bit 31 is 0, it represents an architectural VM-instruction error (SDM Table 30-1).
 * When bit 31 is set, it is a discriminator code written by the driver. During VMCS configuration, at least eight different
 * return points fail with the exact same symptoms (result=3 and stateFlags=0x27 on every processor), making it impossible to
 * distinguish which one failed based solely on the protocol. The encoding is defined in shared/driver/KswordArkHvmIoctl.h.
 */
static const char* archVmInstructionErrorName(unsigned long e)
{
    switch (e) {
    case 0UL:  return "（无）";
    case 7UL:  return "VM entry with invalid control fields";
    case 8UL:  return "VM entry with invalid host-state fields";
    case 12UL: return "VMWRITE to read-only / unsupported component";
    case 26UL: return "VM entry with events blocked by MOV SS";
    default:   return "见 SDM Table 30-1";
    }
}

static const char* diagSiteName(unsigned long site)
{
    switch (site) {
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_VMWRITE:
        return "VMWRITE 被拒（detail = VMCS 字段编码）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER:
        return "CR4 里启用的可选状态没有 VMCS 传输能力";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_BITMAP:
        return "给了 MSR bitmap 页但没拿到 USE_MSR_BITMAPS";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_CR_POLICY:
        return "CR3/DR 拦截被请求但对应控制没拿到";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS:
        return "必需的 primary/secondary/exit/entry 控制缺失";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_DEBUG_PAIRING:
        return "调试状态的保存与加载控制不成对";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING:
        return "可选状态的 exit/entry 控制不成对";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_INSTRUCTION_CTL:
        return "必需的 secondary 指令控制缺失（detail = 最低缺失位号）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_MSR_EXCEPTION:
        return "读可选状态 MSR 抛异常（detail = 异常码低 16 位）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_CAP_EXCEPTION:
        return "读能力/主机 MSR 抛异常（detail = 异常码低 16 位）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_DIAG_IO_EXITING:
        return "诊断用的无条件 I/O 退出被能力 MSR 夹掉（判据会静默失效）";
    case KSWORD_ARK_HVM_VMCS_DIAG_SITE_HOST_CR3:
        return "主机页目录基址为零（装上去会三重故障，无蓝屏无转储）";
    default:
        return "未知站点";
    }
}

static void printStateMask(unsigned long mask)
{
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_CET) != 0UL)   { printf(" CET"); }
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_PKS) != 0UL)   { printf(" PKS"); }
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_UINTR) != 0UL) { printf(" UINTR"); }
    if ((mask & KSWORD_ARK_HVM_VMCS_DIAG_STATE_FRED) != 0UL)  { printf(" FRED"); }
}

static void printVmInstructionError(const char* indent, unsigned long v)
{
    unsigned long site;
    unsigned long detail;

    if (v == 0UL) {
        printf("%svmInstrError : 0（无）\n", indent);
        return;
    }
    if (!KSWORD_ARK_HVM_VMCS_DIAG_IS(v)) {
        printf("%svmInstrError : %lu  %s\n", indent, v, archVmInstructionErrorName(v));
        return;
    }
    site = KSWORD_ARK_HVM_VMCS_DIAG_SITE(v);
    detail = KSWORD_ARK_HVM_VMCS_DIAG_DETAIL(v);
    printf("%svmInstrError : 0x%08lX  【驱动判别码】\n", indent, v);
    printf("%s  站点 %lu : %s\n", indent, site, diagSiteName(site));
    printf("%s  detail 0x%04lX (%lu)", indent, detail, detail);
    if (site == KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_NO_TRANSFER ||
        site == KSWORD_ARK_HVM_VMCS_DIAG_SITE_STATE_PAIRING) {
        printf("  ->");
        printStateMask(detail);
    } else if (site == KSWORD_ARK_HVM_VMCS_DIAG_SITE_REQUIRED_CONTROLS) {
        printf("  ->");
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_SECONDARY_ACTIVATE) != 0UL) {
            printf(" 无 SECONDARY_CONTROLS");
        }
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_EPT) != 0UL) { printf(" 无 EPT"); }
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_HOST_64) != 0UL) {
            printf(" 无 HOST_64_BIT");
        }
        if ((detail & KSWORD_ARK_HVM_VMCS_DIAG_CTL_ENTRY_IA32E) != 0UL) {
            printf(" 无 ENTRY_IA32E");
        }
    }
    printf("\n");
    printf("%s  架构错误码 %lu  %s\n", indent,
           KSWORD_ARK_HVM_VMCS_DIAG_ARCH(v),
           archVmInstructionErrorName(KSWORD_ARK_HVM_VMCS_DIAG_ARCH(v)));
}

/* ------------------------------------------------------------------------ */
/* Exit telemetry: decoding of reason + qualification.                                    */
/* ------------------------------------------------------------------------ */

/*
 * These values (lastExitReason / lastExitQualification / lastGuestRip / lastGuestRsp /
 * lastExitInstructionLength) have always been part of the protocol, but were never printed.
 * These are currently the only **non-serial-port** exit observation surface—the kernel debugger's
 * reporting channel itself is port I/O, which is precisely the phenomenon under investigation. There
 * is no logical implication between "kd did not print" and "that instruction did not execute."
 */
static const char* exitReasonName(unsigned long r)
{
    switch (r) {
    case 0UL:  return "EXCEPTION_OR_NMI";
    case 1UL:  return "EXTERNAL_INTERRUPT";
    case 2UL:  return "TRIPLE_FAULT";
    case 3UL:  return "INIT_SIGNAL";
    case 4UL:  return "SIPI";
    case 7UL:  return "INTERRUPT_WINDOW";
    case 8UL:  return "NMI_WINDOW";
    case 9UL:  return "TASK_SWITCH";
    case 10UL: return "CPUID";
    case 11UL: return "GETSEC";
    case 12UL: return "HLT";
    case 13UL: return "INVD";
    case 14UL: return "INVLPG";
    case 15UL: return "RDPMC";
    case 16UL: return "RDTSC";
    case 17UL: return "RSM";
    case 18UL: return "VMCALL";
    /*
     * 19..27 are the family generated when **another hypervisor runs beneath us**.
     * The IDs match those in hvm_nested.c's KSW_VMX_EXIT_* (the authoritative definitions on the
     * dispatch side); changes to either side must be synchronized. This section was written because,
     * when viewing the first VMware histogram on real hardware, these nine reasons originally
     * printed as 'see SDM Appendix C', yet they are precisely the lines that must be inspected.
     */
    case 19UL: return "VMCLEAR";
    case 20UL: return "VMLAUNCH";
    case 21UL: return "VMPTRLD";
    case 22UL: return "VMPTRST";
    case 23UL: return "VMREAD";
    case 24UL: return "VMRESUME";
    case 25UL: return "VMWRITE";
    case 26UL: return "VMXOFF";
    case 27UL: return "VMXON";
    case 28UL: return "MOV_CR";
    case 29UL: return "MOV_DR";
    case 30UL: return "IO_INSTRUCTION";
    case 31UL: return "RDMSR";
    case 32UL: return "WRMSR";
    case 33UL: return "VM_ENTRY_FAILURE_GUEST_STATE";
    case 34UL: return "VM_ENTRY_FAILURE_MSR_LOADING";
    case 36UL: return "MWAIT";
    case 37UL: return "MONITOR_TRAP_FLAG";
    case 39UL: return "MONITOR";
    case 40UL: return "PAUSE";
    case 48UL: return "EPT_VIOLATION";
    case 49UL: return "EPT_MISCONFIGURATION";
    case 50UL: return "INVEPT";
    case 51UL: return "RDTSCP";
    case 52UL: return "VMX_PREEMPTION_TIMER";
    case 53UL: return "INVVPID";
    case 54UL: return "WBINVD";
    case 55UL: return "XSETBV";
    case 58UL: return "INVPCID";
    case 59UL: return "VMFUNC";
    default:   return "见 SDM Appendix C";
    }
}

/*
 * Exit reason 30 qualification layout (SDM Table 28-5):
 *   Bits 2:0: Access width (0=1B,
 *   1=2B, 3=4B). Bit 3: Direction
 *   (1=IN). Bit 4: String instruction.
 *   Bit 5: REP prefix. Bit 6: Operand
 *   encoding (1=DX, 0=Immediate).
 *   bits31:16: Port number
 */
static void printIoQualification(const char* indent, unsigned long long q)
{
    static const unsigned int kSizes[8] = { 1U, 2U, 0U, 4U, 0U, 0U, 0U, 0U };
    unsigned int width = kSizes[(unsigned int)(q & 0x7ULL)];
    unsigned int port = (unsigned int)((q >> 16) & 0xFFFFULL);

    printf("%s  端口         : 0x%04X (%u)\n", indent, port, port);
    printf("%s  方向/宽度    : %s  %u 字节%s%s  操作数=%s\n", indent,
           ((q >> 3) & 1ULL) ? "IN " : "OUT",
           width,
           ((q >> 4) & 1ULL) ? "  字符串" : "",
           ((q >> 5) & 1ULL) ? "  REP" : "",
           ((q >> 6) & 1ULL) ? "DX" : "立即数");
}

/*
 * Execution control: the actual effective value and which bits are **forced**.
 *
 * The low 32 bits of the capability MSR encode allowed-0: a set bit requires the corresponding control bit to be 1, regardless of the requester's preference.
 * So `force` = lower 32 bits, and `what we actively requested` = `active & ~force`.
 *
 * This distinction is the sole reason this function exists: looking only at the active value, we cannot tell if
 * an exit was intercepted by us (which can be optimized away) or forced by the outer hypervisor (which cannot).
 */
static void printControlLine(const char* name,
                             unsigned long active,
                             unsigned long long capability)
{
    unsigned long forced = (unsigned long)(capability & 0xFFFFFFFFULL);
    unsigned long forcedActive = active & forced;
    unsigned long requested = active & ~forced;

    printf("  %-10s: 0x%08lX   被强制 0x%08lX   自选 0x%08lX\n",
           name, active, forcedActive, requested);
}

static void printActiveControls(const KSWORD_ARK_QUERY_HVM_RESPONSE* rsp)
{
    if (rsp->activePinControls == 0UL &&
        rsp->activePrimaryControls == 0UL &&
        rsp->activeExitControls == 0UL) {
        printf("  执行控制     : （尚未配置过常驻，无记录）\n");
        return;
    }
    printf("  执行控制     : 生效值 / 能力 MSR 的 allowed-0 强制位\n");
    printControlLine("pin", rsp->activePinControls, rsp->pinCapability);
    printControlLine("primary", rsp->activePrimaryControls,
                     rsp->primaryCapability);
    printControlLine("secondary", rsp->activeSecondaryControls,
                     rsp->secondaryCapability);
    printControlLine("exit", rsp->activeExitControls, rsp->exitCapability);
    printControlLine("entry", rsp->activeEntryControls, rsp->entryCapability);
    /*
     * HLT exiting is singled out: it is the largest item on the exit histogram, yet resident mode does not
     * request it. Whether it is forced directly determines if this large overhead block can be modified.
     */
    {
        unsigned long hlt = 1UL << 7;
        unsigned long forced =
            (unsigned long)(rsp->primaryCapability & 0xFFFFFFFFULL);

        if ((rsp->activePrimaryControls & hlt) != 0UL) {
            printf("    HLT exiting: 生效%s\n",
                   ((forced & hlt) != 0UL)
                       ? "，且**被能力 MSR 强制**（外层要求，我们关不掉）"
                       : "，但**没有被强制** —— 是我们自己请求的");
        } else {
            printf("    HLT exiting: 未生效\n");
        }
    }
}

/*
 * Histogram of exit reasons: where the exit time was spent.
 *
 * `count` and `lastExitReason` together cannot answer this question — reading "reason=18" one
 * hundred times does not distinguish whether VMCALLs account for 99% or merely happened to be last.
 *
 * Print only non-zero entries, sorted by count descending, because the **head** matters: the one or two reasons accounting for the
 * vast majority of exits define the machine's performance and behavioral profile; the tail (one or two occurrences) is usually noise.
 */
static void printExitReasonHistogram(
    const char* indent,
    const KSWORD_ARK_QUERY_HVM_RESPONSE* rsp)
{
    unsigned long order[KSWORD_ARK_HVM_EXIT_REASON_SLOTS];
    unsigned long nonZero = 0UL;
    unsigned long i = 0UL;
    unsigned long j = 0UL;
    unsigned long long total = 0ULL;

    for (i = 0UL; i < KSWORD_ARK_HVM_EXIT_REASON_SLOTS; ++i) {
        if (rsp->exitReasonCount[i] != 0ULL) {
            order[nonZero++] = i;
            total += rsp->exitReasonCount[i];
        }
    }
    if (nonZero == 0UL) {
        return;
    }
    /* Insertion sort: at most 96 items, and almost always single-digit. */
    for (i = 1UL; i < nonZero; ++i) {
        unsigned long key = order[i];
        j = i;
        while (j > 0UL &&
               rsp->exitReasonCount[order[j - 1UL]] <
                   rsp->exitReasonCount[key]) {
            order[j] = order[j - 1UL];
            --j;
        }
        order[j] = key;
    }
    printf("%s退出分布     : 合计 %llu，%lu 种原因\n", indent, total, nonZero);
    for (i = 0UL; i < nonZero; ++i) {
        unsigned long reason = order[i];
        unsigned long long value = rsp->exitReasonCount[reason];

        printf("%s  %5.1f%%  %10llu  reason=%-3lu %s\n",
               indent,
               (double)value * 100.0 / (double)total,
               value,
               reason,
               exitReasonName(reason));
    }
}

static void printExitTelemetry(const char* indent,
                               unsigned long long count,
                               unsigned long reason,
                               unsigned long long qualification,
                               unsigned long long guestRip,
                               unsigned long long guestRsp,
                               unsigned long instructionLength)
{
    printf("%s退出         : count=%llu  reason=%lu (%s)  instrLen=%lu\n",
           indent, count, reason, exitReasonName(reason), instructionLength);
    if (count == 0ULL && reason == 0UL && qualification == 0ULL &&
        guestRip == 0ULL) {
        printf("%s  （尚无退出记录）\n", indent);
        return;
    }
    printf("%s  qualification: 0x%016llX\n", indent, qualification);
    printf("%s  guestRip     : 0x%016llX   guestRsp: 0x%016llX\n",
           indent, guestRip, guestRsp);
    if (reason == 30UL) {
        printIoQualification(indent, qualification);
    }
}

static HANDLE openDevice(void)
{
    HANDLE h = CreateFileW(KSW_DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "打不开 %ls：win32=%lu\n", KSW_DEVICE_PATH, GetLastError());
        fprintf(stderr, "  2 = 设备不存在（驱动没加载）；5 = 拒绝访问（需要管理员）\n");
    }
    return h;
}

/* ------------------------------------------------------------------------ */
/* Read-only query                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * Execute CPUID from **user mode** to report the hypervisor identity seen by the guest.
 *
 * This is the criterion for resident-nested-hidehv, and it is the closest one to any state field: it follows
 * the exact path VMware takes to determine "is there a hypervisor below" — same privilege level, same leaf.
 * Having an additional "hidden=on" flag in the status only proves the request was accepted, not that the dispatcher
 * actually modified the return value; the four registers read here directly indicate whether the modification occurred.
 *
 * No driver handle required: while running, this CPUID instruction itself will exit to us.
 */
/*
 * Name which of the entry path's refusals stopped the last L2 launch.
 *
 * The numbers are assigned in hvm_nested_l2.c at the refusal sites themselves.
 * They exist because all seven report the same architectural error to L1 —
 * Intel has one number for "invalid control field" and no field to say which —
 * so from outside, seven different problems produce one indistinguishable
 * symptom.
 */
static const char* refusalSiteName(unsigned short site)
{
    switch (site) {
    case 0U: return "没有拒绝过";
    case 1U: return "熔断已跳闸，拒绝再次进入同一个 L2";
    case 2U: return "缺资源（vmcs02 页 / 物理窗口）";
    case 3U: return "L1 的 EPT12 指针不可用（影子层次装不起来）";
    case 4U: return "没有可用的 EPT 指针";
    case 5U: return "位图页缺失（MSR / IO 位图合并没产出页）";
    case 6U: return "virtual-APIC 页地址读回来是零（该校验默认**关闭**，见 KSW_L2_ENFORCE_VIRTUAL_APIC_PAGE）";
    case 7U: return "vmcs02 的 VMPTRLD 失败";
    case 8U: return "virtual-APIC 页地址非零但未页对齐（同上，默认关闭）";
    default: return "未知编号";
    }
}

static int doCpuidView(int asJson)
{
    int leaf1[4] = { 0, 0, 0, 0 };
    int hv[4] = { 0, 0, 0, 0 };
    int hvVendor[4] = { 0, 0, 0, 0 };
    char vendor[13];
    int present = 0;

    __cpuidex(leaf1, 1, 0);
    __cpuidex(hv, 0x40000000, 0);
    /* Keep an unmodified copy for constructing the vendor string. */
    hvVendor[0] = hv[0];
    hvVendor[1] = hv[1];
    hvVendor[2] = hv[2];
    hvVendor[3] = hv[3];
    /* CPUID.1:ECX bit 31 — the bit architecturally reserved for "hypervisor present". */
    present = ((unsigned int)leaf1[2] & 0x80000000U) != 0U ? 1 : 0;
    /* Vendor string is 12 bytes in EBX, ECX, EDX order. */
    memcpy(vendor + 0, &hvVendor[1], 4);
    memcpy(vendor + 4, &hvVendor[2], 4);
    memcpy(vendor + 8, &hvVendor[3], 4);
    vendor[12] = '\0';
    {
        size_t i = 0;
        /* Replace all non-printable bytes with dots to prevent control characters from messing up the output. */
        for (i = 0; i < 12; ++i) {
            if (vendor[i] < 0x20 || vendor[i] > 0x7E) {
                vendor[i] = (vendor[i] == '\0') ? '\0' : '.';
            }
        }
    }

    if (asJson) {
        printf("{\"kind\":\"cpuidView\",\"hypervisorPresent\":%s,"
               "\"leaf1Ecx\":\"0x%08X\","
               "\"hvLeafEax\":\"0x%08X\",\"hvVendor\":",
               present ? "true" : "false",
               (unsigned int)leaf1[2],
               (unsigned int)hvVendor[0]);
        kswordHvmPrintJsonString(vendor);
        printf(",\"hidden\":%s}\n",
               (!present && hvVendor[0] == 0) ? "true" : "false");
        return 0;
    }

    printf("\n=== 来宾用户态看到的 CPUID ===\n");
    printf("  CPUID.1:ECX          : 0x%08X\n", (unsigned int)leaf1[2]);
    printf("  bit31 hypervisor 位  : %s\n", present ? "**有**" : "无");
    printf("  CPUID.40000000:EAX   : 0x%08X\n", (unsigned int)hvVendor[0]);
    printf("  hypervisor 厂商      : \"%s\"\n", vendor);
    printf("  结论                 : %s\n",
           (!present && hvVendor[0] == 0)
               ? "用户态问不出下面有 hypervisor（隐藏生效）"
               : "用户态能看出下面有 hypervisor");
    printf("\n  这两个值就是 VMware 的 IOPL_Init 用来判断的那两个。它认出外层是\n"
           "  别人家的 hypervisor 就会去要 WHP，要不到就在装载任何虚拟机之前拒绝。\n");
    return 0;
}

static const char* svmProbeRejectName(unsigned long reason)
{
    switch (reason) {
    case KSWORD_ARK_SVM_REJECT_NONE: return "NONE";
    case KSWORD_ARK_SVM_REJECT_CPUID_RANGE: return "CPUID_RANGE";
    case KSWORD_ARK_SVM_REJECT_SVM_NPT_ASID: return "SVM_NPT_ASID";
    case KSWORD_ARK_SVM_REJECT_NRIP: return "NRIP_REQUIRED";
    case KSWORD_ARK_SVM_REJECT_MSR_READ: return "MSR_READ_FAILED";
    case KSWORD_ARK_SVM_REJECT_FIRMWARE: return "FIRMWARE_DISABLED";
    case KSWORD_ARK_SVM_REJECT_SVME: return "SVME_ALREADY_ENABLED";
    case KSWORD_ARK_SVM_REJECT_HSAVE: return "HSAVE_NONZERO";
    case KSWORD_ARK_SVM_REJECT_CR4: return "CR4_UNSUPPORTED_STATE";
    case KSWORD_ARK_SVM_REJECT_XSAVE: return "XSAVE_OSXSAVE_REQUIRED";
    case KSWORD_ARK_SVM_REJECT_XSTATE_READ: return "XSTATE_READ_FAILED";
    case KSWORD_ARK_SVM_REJECT_XSS: return "XSS_NONZERO";
    case KSWORD_ARK_SVM_REJECT_PHYSICAL_WIDTH: return "PHYSICAL_WIDTH_UNSUPPORTED";
    case KSWORD_ARK_SVM_REJECT_CET_STATE: return "CET_STATE_UNSUPPORTED";
    default: return "UNKNOWN";
    }
}

static int doQuery(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST req;
    KSWORD_ARK_QUERY_HVM_RESPONSE rsp;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);

    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (returned < sizeof(rsp)) {
        fprintf(stderr, "QUERY_HVM 响应过短：%lu 字节（需要 %zu）\n",
                returned, sizeof(rsp));
        return 1;
    }

    if (asJson) {
        printf("{\"kind\":\"query\",\"queryStatus\":%lu,\"stateFlags\":%lu,"
               "\"stateFlagsHex\":\"0x%08lX\",\"stateNames\":",
               rsp.queryStatus, rsp.stateFlags, rsp.stateFlags);
        printStateBitsJson(rsp.stateFlags);
        printf(",\"backend\":%lu,\"slatType\":%lu,\"slatReady\":%lu,\"backendStatus\":\"0x%08lX\",\"powerGeneration\":%lu",
               rsp.backend, rsp.slatType, rsp.slatReady, rsp.backendStatus, rsp.powerGeneration);
        printf(",\"svmProbe\":{\"maxLeaf\":%lu,\"features\":%lu,\"asidCount\":%lu,\"physicalBits\":%lu,\"msrValidMask\":%lu,\"exceptionStatus\":\"0x%08lX\",\"vmCr\":\"0x%016llX\",\"efer\":\"0x%016llX\",\"hsave\":\"0x%016llX\",\"pat\":\"0x%016llX\"",
               rsp.svmCapabilities.maxLeaf, rsp.svmCapabilities.features, rsp.svmCapabilities.asidCount, rsp.svmCapabilities.physicalBits,
               rsp.svmCapabilities.msrValidMask, rsp.svmCapabilities.exceptionStatus, rsp.svmCapabilities.vmCr,
               rsp.svmCapabilities.efer, rsp.svmCapabilities.hsave, rsp.svmCapabilities.pat);
        printf(",\"rejectReason\":%lu,\"rejectReasonName\":\"%s\",\"stateValidMask\":%lu,\"cpuid1Ecx\":\"0x%08lX\",\"xsaveFeatures\":\"0x%08lX\",\"cr4\":\"0x%016llX\",\"xcr0\":\"0x%016llX\",\"xss\":\"0x%016llX\"}",
               rsp.svmCapabilities.rejectReason, svmProbeRejectName(rsp.svmCapabilities.rejectReason),
               rsp.svmCapabilities.stateValidMask, rsp.svmCapabilities.cpuid1Ecx, rsp.svmCapabilities.xsaveFeatures,
               rsp.svmCapabilities.cr4, rsp.svmCapabilities.xcr0, rsp.svmCapabilities.xss);
        printf(",\"featureNames\":");
        printFeatureBitsJson(rsp.featureFlags);
        printf(",\"generation\":%lu,\"processorCount\":%lu,"
               "\"preparedProcessorCount\":%lu,\"selfTestPassedProcessorCount\":%lu,"
               "\"residentProcessorCount\":%lu,"
               "\"residentImplementation\":\"%s\",\"eptImplementation\":\"%s\","
               "\"nestedImplementation\":\"%s\",\"evmcsImplementation\":\"%s\","
               "\"featureFlags\":\"0x%016llX\","
               "\"vmxEptVpidCapabilities\":\"0x%016llX\","
               "\"eptExecuteOnly\":%s,"
               "\"eptPointer\":\"0x%016llX\","
               /*
                * Shape of the identity mapping: where the window coverage extends and the count of entries at each level.
                *
                * The UI always displays these values, but the command line does not. Thus, 'what the machine's mapping
                * looks like' can only be answered by the UI, yet troubleshooting this situation often occurs without a UI.
                */
               "\"highestMappedPhysicalAddress\":\"0x%016llX\","
               "\"eptPml4Entries\":%lu,\"eptPdptEntries\":%lu,"
               "\"eptLargePageEntries\":%lu,"
               "\"eptPageCount\":%lu,\"mappedRamMiB\":%llu,\"vmExitCount\":%llu,"
               "\"lastExitReason\":%lu,\"lastExitQualification\":\"0x%016llX\","
               "\"lastGuestRip\":\"0x%016llX\",\"lastGuestRsp\":\"0x%016llX\","
               "\"lastExitInstructionLength\":%lu,"
               "\"lastStatus\":\"0x%08lX\","
               "\"vmxBasic\":\"0x%016llX\","
               "\"cr0Fixed0\":\"0x%016llX\",\"cr0Fixed1\":\"0x%016llX\","
               "\"cr4Fixed0\":\"0x%016llX\",\"cr4Fixed1\":\"0x%016llX\","
               "\"lastVmInstructionError\":%lu,"
               "\"eventCount\":%lu,"
               "\"droppedEventCount\":%lu,"
               "\"overwrittenEventCount\":%lu,"
               "\"publishedEventCount\":%llu,"
               "\"nestedL2LaunchRefusedCount\":%lu,"
               "\"nestedVmcs12EvictionCount\":%lu,"
               "\"nestedFuseTripCount\":%lu,"
               "\"nestedLastRefusalSite\":%u,"
               "\"nestedLastRefusalSiteText\":",
               rsp.generation, rsp.processorCount,
               rsp.preparedProcessorCount, rsp.selfTestPassedProcessorCount,
               rsp.residentProcessorCount,
               implementationName(rsp.residentImplementation),
               implementationName(rsp.eptImplementation),
               implementationName(rsp.nestedImplementation),
               implementationName(rsp.evmcsImplementation),
               rsp.featureFlags,
               rsp.vmxEptVpidCapabilities,
               ((rsp.vmxEptVpidCapabilities & 1ULL) != 0ULL) ? "true" : "false",
               rsp.eptPointer,
               rsp.highestMappedPhysicalAddress,
               rsp.eptPml4Entries, rsp.eptPdptEntries,
               rsp.eptLargePageEntries,
               rsp.eptPageCount, rsp.mappedRamBytes / (1024ULL * 1024ULL),
               rsp.vmExitCount,
               rsp.lastExitReason, rsp.lastExitQualification,
               rsp.lastGuestRip, rsp.lastGuestRsp,
               rsp.lastExitInstructionLength,
               (unsigned long)rsp.lastStatus,
               rsp.vmxBasic,
               rsp.cr0Fixed0, rsp.cr0Fixed1,
               rsp.cr4Fixed0, rsp.cr4Fixed1,
               rsp.lastVmInstructionError,
               rsp.eventCount, rsp.droppedEventCount,
               rsp.overwrittenEventCount, rsp.publishedEventCount,
               rsp.nestedL2LaunchRefusedCount,
               rsp.nestedVmcs12EvictionCount,
               rsp.nestedFuseTripCount,
               (unsigned)rsp.nestedLastRefusalSite);
        kswordHvmPrintJsonString(refusalSiteName(rsp.nestedLastRefusalSite));
        /*
         * Only emit non-zero items; the key is the exit reason code.
         *
         * Most of the 96 entries are always zero; sending them all would add a large block of empty "0" values
         * to every status JSON, whereas the script needs to know "where time was spent in this exit round".
         */
        {
            unsigned long slot = 0UL;
            int emitted = 0;

            printf(",\"exitReasonCount\":{");
            for (slot = 0UL;
                 slot < KSWORD_ARK_HVM_EXIT_REASON_SLOTS;
                 ++slot) {
                if (rsp.exitReasonCount[slot] == 0ULL) {
                    continue;
                }
                printf("%s\"%lu\":%llu",
                       emitted ? "," : "",
                       slot,
                       rsp.exitReasonCount[slot]);
                emitted = 1;
            }
            printf("}");
        }
        printCpuRows(&rsp, 1);
        printf("}\n");
        return 0;
    }

    printf("\n=== HVM 状态（只读）===\n");
    printf("  queryStatus  : %lu\n", rsp.queryStatus);
    printStateBits("  状态位       : ", rsp.stateFlags);
    printf("  代次         : %lu\n", rsp.generation);
    printf("  处理器       : total=%lu prepared=%lu selfTestPassed=%lu resident=%lu\n",
           rsp.processorCount, rsp.preparedProcessorCount,
           rsp.selfTestPassedProcessorCount, rsp.residentProcessorCount);
    printf("  实现         : resident=%s ept=%s nested=%s evmcs=%s\n",
           implementationName(rsp.residentImplementation),
           implementationName(rsp.eptImplementation),
           implementationName(rsp.nestedImplementation),
           implementationName(rsp.evmcsImplementation));
    /*
     * Two persistent nested counters: how many times L2 launches were refused and how many vmcs12 instances were evicted.
     *
     * Print unconditionally, without the 'show only if non-zero' check. Zero itself is a value that must be read; omitting
     * this line makes it impossible to distinguish between 'never occurred' and 'this tool does not yet recognize this
     * field'—the latter case appears during protocol changes, precisely when trusting the reading is most critical.
     *
     * The specific meaning of a non-zero eviction count is: an L1's VMCS count exceeds the pool capacity. The evicted
     * VMCS will have all fields zeroed upon the next VMPTRLD, appearing to L1 as if it only models a single vmcs12 (a
     * known defect). Thus, this count is the only post-hoc indicator to distinguish between the two scenarios.
     */
    printf("  嵌套计数     : 拒绝 L2 启动 %lu 次   vmcs12 驱逐 %lu 份%s\n",
           rsp.nestedL2LaunchRefusedCount,
           rsp.nestedVmcs12EvictionCount,
           (rsp.nestedVmcs12EvictionCount != 0UL)
               ? "  **池子装不下这个 L1 的 VMCS**"
               : "");
    printf("                 无进展熔断跳闸 %lu 次%s\n",
           rsp.nestedFuseTripCount,
           (rsp.nestedFuseTripCount != 0UL)
               ? "  **我们停掉过某个 L1 的来宾：它在原地打转**"
               : "");
    printf("                 末次拒绝原因 : %u = %s\n",
           (unsigned)rsp.nestedLastRefusalSite,
           refusalSiteName(rsp.nestedLastRefusalSite));
    /*
     * Count of processors ready to exit the safe physical window.
     *
     * Its preparation-phase self-check is invisible elsewhere: if it fails, nested L2 entry and shadow EPT
     * synthesis quietly reject it, while status bits, maturity, and processor counts remain unchanged. A
     * self-check that yields no result is indistinguishable from no self-check based on readings.
     *
     * Comparing against processorCount is incorrect: the window is created during driver initialization, not during resource
     * preparation. Thus, even before any resources are ready, the window should be full. Here, we use the logical processor
     * count as the denominator; otherwise, immediately after loading the driver, we would see an unintelligible "N / 0".
     */
    printf("  退出安全窗口 : %lu / %lu 个处理器已就绪%s\n",
           rsp.physWindowReadyCount,
           (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS),
           rsp.physWindowReadyCount >=
                   (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
               ? ""
               : "  **不足：缺窗口的核上嵌套 L2 与影子 EPT 会被拒**");
    printFeatureBits("  ", rsp.featureFlags);
    printEptVpidCapability("  ", rsp.vmxEptVpidCapabilities);
    printf("  EPT          : pointer=0x%016llX pages=%lu mappedRam=%llu MiB\n",
           rsp.eptPointer, rsp.eptPageCount,
           rsp.mappedRamBytes / (1024ULL * 1024ULL));
    printf("  lastStatus   : 0x%08lX\n", (unsigned long)rsp.lastStatus);
    /*
     * These five values were queried long ago but never printed. The fixed bits in CR0/CR4 are the primary basis for
     * determining 'what L0 allows' — in nested virtualization, they are synthesized by L0 and may differ from bare metal.
     */
    printf("  vmxBasic     : 0x%016llX\n", rsp.vmxBasic);
    printf("  CR0 fixed    : fixed0=0x%016llX fixed1=0x%016llX\n",
           rsp.cr0Fixed0, rsp.cr0Fixed1);
    printf("  CR4 fixed    : fixed0=0x%016llX fixed1=0x%016llX\n",
           rsp.cr4Fixed0, rsp.cr4Fixed1);
    printVmInstructionError("  ", rsp.lastVmInstructionError);
    printExitTelemetry("  ", rsp.vmExitCount, rsp.lastExitReason,
                       rsp.lastExitQualification, rsp.lastGuestRip,
                       rsp.lastGuestRsp, rsp.lastExitInstructionLength);
    printExitReasonHistogram("  ", &rsp);
    printActiveControls(&rsp);
    printf("  CPU / HV     : %.12s / %.12s\n", rsp.cpuVendor, rsp.hypervisorVendor);
    printCpuRows(&rsp, 0);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle control                                                              */
/* ------------------------------------------------------------------------ */

static int doControl(HANDLE h, const HvmCtlVerb* verb,
                     unsigned long soakMs, int asJson)
{
    KSWORD_ARK_CONTROL_HVM_REQUEST req;
    KSWORD_ARK_CONTROL_HVM_RESPONSE rsp;
    DWORD returned = 0;

    KSWORD_ARK_QUERY_HVM_RESPONSE snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    KSWORD_ARK_QUERY_HVM_REQUEST query;
    memset(&query, 0, sizeof(query));
    query.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    query.size = sizeof(query);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &query, sizeof(query),
                         &snapshot, sizeof(snapshot), &returned, NULL) || returned != sizeof(snapshot)) {
        fprintf(stderr, "HVM state query failed before control: Win32 %lu\n", GetLastError());
        return 1;
    }
    if (snapshot.queryStatus != 0) {
        /* A capability refusal must be distinguishable from an empty/crashed CLI. */
        if (asJson) {
            printf("{\"kind\":\"control\",\"command\":\"%s\",\"stage\":\"capability-query\","
                   "\"controlSubmitted\":false,\"queryStatus\":%lu,\"lastStatus\":\"0x%08lX\","
                   "\"generation\":%lu,\"stateFlags\":%lu}\n", verb->name,
                   snapshot.queryStatus, (unsigned long)snapshot.lastStatus,
                   snapshot.generation, snapshot.stateFlags);
        } else {
            fprintf(stderr, "HVM control refused before submission: queryStatus=%lu NTSTATUS=0x%08lX\n",
                    snapshot.queryStatus, (unsigned long)snapshot.lastStatus);
        }
        return 2;
    }
    memset(&rsp, 0, sizeof(rsp));
    KswordArkHvmBuildControlRequest(&req, verb->command, verb->flags,
                                   snapshot.generation, soakMs);

    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        /*
         * When a security policy denies the request, the path taken is 'return non-success NTSTATUS'. DeviceIoControl will fail, but
         * the response buffer is still populated. Therefore, do not abandon immediately; first check if the buffer is long enough.
         */
        DWORD win32 = GetLastError();
        if (returned < sizeof(rsp)) {
            if (asJson) {
                printf("{\"kind\":\"control\",\"command\":\"%s\",\"transport\":\"failed\","
                       "\"win32\":%lu,\"bytesReturned\":%lu}\n",
                       verb->name, win32, returned);
            } else {
                fprintf(stderr, "  DeviceIoControl 失败：win32=%lu，返回 %lu 字节\n",
                        win32, returned);
            }
            return 1;
        }
        /* Buffer complete: continue interpreting results per protocol; status and lastStatus will be printed below. */
    }
    if (returned < sizeof(rsp)) {
        if (asJson) {
            printf("{\"kind\":\"control\",\"command\":\"%s\",\"transport\":\"short\","
                   "\"bytesReturned\":%lu}\n", verb->name, returned);
        } else {
            fprintf(stderr, "  响应过短：%lu 字节（需要 %zu）\n",
                    returned, sizeof(rsp));
        }
        return 1;
    }

    if (asJson) {
        printf("{\"kind\":\"control\",\"command\":\"%s\",\"status\":%lu,"
               "\"statusName\":\"%s\",\"lastStatus\":\"0x%08lX\","
               "\"oldStateFlags\":%lu,\"newStateFlags\":%lu,"
               "\"oldStateHex\":\"0x%08lX\",\"newStateHex\":\"0x%08lX\","
               "\"newStateNames\":",
               verb->name, rsp.status, controlStatusName(rsp.status),
               (unsigned long)rsp.lastStatus,
               rsp.oldStateFlags, rsp.newStateFlags,
               rsp.oldStateFlags, rsp.newStateFlags);
        printStateBitsJson(rsp.newStateFlags);
        printf(",\"oldGeneration\":%lu,\"newGeneration\":%lu,"
               "\"preparedProcessorCount\":%lu,\"selfTestPassedProcessorCount\":%lu,"
               "\"failedProcessorCount\":%lu,\"residentProcessorCount\":%lu,"
               "\"residentImplementation\":\"%s\",\"eptImplementation\":\"%s\","
               "\"nestedImplementation\":\"%s\",\"evmcsImplementation\":\"%s\","
               "\"eptPointer\":\"0x%016llX\",\"eptPageCount\":%lu,"
               "\"eptPml4EntryBudget\":%lu,"
               "\"eptRuleCount\":%lu,\"mappedRamMiB\":%llu,"
               "\"vmExitCount\":%llu,\"lastExitReason\":%lu,"
               "\"lastExitQualification\":\"0x%016llX\","
               "\"lastGuestRip\":\"0x%016llX\",\"lastGuestRsp\":\"0x%016llX\","
               "\"lastExitInstructionLength\":%lu,"
               "\"lastVmInstructionError\":%lu,"
               "\"soakElapsedMilliseconds\":%lu,"
               "\"soakUnexpectedDevirtualizations\":%lu}\n",
               rsp.oldGeneration, rsp.newGeneration,
               rsp.preparedProcessorCount, rsp.selfTestPassedProcessorCount,
               rsp.failedProcessorCount, rsp.residentProcessorCount,
               implementationName(rsp.residentImplementation),
               implementationName(rsp.eptImplementation),
               implementationName(rsp.nestedImplementation),
               implementationName(rsp.evmcsImplementation),
               rsp.eptPointer, rsp.eptPageCount, rsp.eptPml4EntryBudget,
               rsp.eptRuleCount,
               rsp.mappedRamBytes / (1024ULL * 1024ULL),
               rsp.vmExitCount, rsp.lastExitReason,
               rsp.lastExitQualification, rsp.lastGuestRip,
               rsp.lastGuestRsp, rsp.lastExitInstructionLength,
               rsp.lastVmInstructionError,
               rsp.soakElapsedMilliseconds,
               rsp.soakUnexpectedDevirtualizations);
        return (rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) ? 0 : 2;
    }

    printf("\n=== %s（command=%lu，flags=0x%lX）===\n",
           verb->description, verb->command, verb->flags);
    printf("  status       : %lu (%s)   lastStatus=0x%08lX\n",
           rsp.status, controlStatusName(rsp.status),
           (unsigned long)rsp.lastStatus);
    printStateBits("  旧状态位     : ", rsp.oldStateFlags);
    printStateBits("  新状态位     : ", rsp.newStateFlags);
    printf("  代次         : %lu -> %lu\n", rsp.oldGeneration, rsp.newGeneration);
    /*
     * failedProcessorCount is calculated in hvm_runtime.c as ProcessorCount -
     * SelfTestPassedProcessorCount; it is **not** a failure count. After PREPARE, it must equal the
     * total processor count, signifying only that "no processor has passed self-test yet". This
     * comment clarifies the meaning to avoid misinterpreting it as "all four cores have failed".
     */
    printf("  处理器       : prepared=%lu selfTestPassed=%lu resident=%lu\n",
           rsp.preparedProcessorCount, rsp.selfTestPassedProcessorCount,
           rsp.residentProcessorCount);
    printf("               （未通过自检 = %lu，注意这不是失败计数）\n",
           rsp.failedProcessorCount);
    printf("  实现         : resident=%s ept=%s nested=%s evmcs=%s\n",
           implementationName(rsp.residentImplementation),
           implementationName(rsp.eptImplementation),
           implementationName(rsp.nestedImplementation),
           implementationName(rsp.evmcsImplementation));
    printf("  EPT          : pointer=0x%016llX pages=%lu rules=%lu mappedRam=%llu MiB\n",
           rsp.eptPointer, rsp.eptPageCount, rsp.eptRuleCount,
           rsp.mappedRamBytes / (1024ULL * 1024ULL));
    /*
     * The window size is a compile-time constant for this driver; the copy in this tool's own header file is incorrect when
     * versions are mismatched—yet it is precisely when versions are mismatched that knowing this value is most critical.
     */
    printf("               （身份映射窗口 = %lu 个 PML4 项 = %llu TiB）\n",
           rsp.eptPml4EntryBudget,
           ((unsigned long long)rsp.eptPml4EntryBudget * 512ULL) / 1024ULL);
    printExitTelemetry("  ", rsp.vmExitCount, rsp.lastExitReason,
                       rsp.lastExitQualification, rsp.lastGuestRip,
                       rsp.lastGuestRsp, rsp.lastExitInstructionLength);
    printVmInstructionError("  ", rsp.lastVmInstructionError);
    if (verb->command == KSWORD_ARK_HVM_CONTROL_SOAK) {
        printf("  soak         : elapsed=%lu ms  意外退虚拟化=%lu\n",
               rsp.soakElapsedMilliseconds,
               rsp.soakUnexpectedDevirtualizations);
    }
    /*
     * The name NOT_PREPARED is misleading; upon receiving it, the missing bit must be identified.
     *
     * Entering resident mode requires all **four** status bits to be set (hvm_runtime.c:1920-1928):
     * RESOURCES_READY | EPT_READY | SELF_TEST_PASSED | GUEST_READY。
     * If any of the four required bits are missing, the same STATUS_DEVICE_NOT_READY is returned, which is mapped to
     * NOT_PREPARED (hvm_runtime.c:2086-2088). Consequently, even though the resources are ready and only a self-test
     * remains, the system reports "Not Prepared"—a literal message that misleads users into performing another prepare.
     * However, repeating prepare returns ALREADY_PREPARED and sets the state to FAULTED, making the situation worse.
     *
     * These four missing states are indistinguishable in the protocol (one code) but fully distinguishable in **state
     * flags**, which are included in the response as newStateFlags. Therefore, do not guess; read it directly.
     */
    if (rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED) {
        const unsigned long kF = rsp.newStateFlags;
        printf("  ** NOT_PREPARED 拆解 **：进入常驻要求四个位齐备，"
               "缺哪一个都报这同一个码。\n");
        printf("     RESOURCES_READY  : %s\n",
               (kF & KSWORD_ARK_HVM_STATE_RESOURCES_READY) ? "有" : "**缺** -> prepare");
        printf("     EPT_READY        : %s\n",
               (kF & KSWORD_ARK_HVM_STATE_EPT_READY) ? "有" : "**缺** -> prepare");
        printf("     SELF_TEST_PASSED : %s\n",
               (kF & KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) ? "有" : "**缺** -> self-test");
        printf("     GUEST_READY      : %s\n",
               (kF & KSWORD_ARK_HVM_STATE_GUEST_READY) ? "有" : "**缺** -> self-test");
        if ((kF & KSWORD_ARK_HVM_STATE_FAULTED) != 0UL ||
            (kF & KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0UL) {
            printf("     另外 FAULTED/ROLLBACK_REQUIRED 已置位，"
                   "先 reset-fault，否则后续命令还会被拒。\n");
        }
    }
    return (rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) ? 0 : 2;
}

/* ------------------------------------------------------------------------ */
/* Platform probe: three metrics that can rule out 'returning to user mode from virtualization'.                              */
/* ------------------------------------------------------------------------ */

/*
 * KVA shadow is accessible from user mode; the driver does not need to guess the address of nt!KiKvaShadow:
 * SystemKernelVaShadowInformation is a class for NtQuerySystemInformation that directly
 * exposes bits like KvaShadowEnabled. Hard-coding symbols is both fragile and unnecessary.
 */
#define KSW_SYSTEM_KERNEL_VA_SHADOW_INFORMATION 196

typedef struct KswKvaShadowInfo
{
    unsigned long flags;
} KswKvaShadowInfo;

typedef LONG (__stdcall* KswNtQuerySystemInformation)(
    ULONG systemInformationClass,
    PVOID systemInformation,
    ULONG systemInformationLength,
    PULONG returnLength);

/* Returns 0 if found (*Flags valid); non-zero if not found, with reason written to stderr. */
static int queryKvaShadow(unsigned long* flags)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    KswNtQuerySystemInformation fn = NULL;
    KswKvaShadowInfo info;
    ULONG returned = 0;
    LONG st = 0;

    if (ntdll == NULL) { return 1; }
    fn = (KswNtQuerySystemInformation)(void*)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (fn == NULL) { return 2; }
    memset(&info, 0, sizeof(info));
    st = fn(KSW_SYSTEM_KERNEL_VA_SHADOW_INFORMATION,
            &info, (ULONG)sizeof(info), &returned);
    if (st < 0) {
        fprintf(stderr, "NtQuerySystemInformation(196) 失败：0x%08lX\n",
                (unsigned long)st);
        return 3;
    }
    *flags = info.flags;
    return 0;
}

static int doProbePlatform(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_PLATFORM_REQUEST req;
    KSWORD_ARK_HVM_PLATFORM_RESPONSE rsp;
    DWORD returned = 0;
    unsigned long kva = 0UL;
    int kvaOk = 0;
    int cetActive = 0;
    int cetSupported = 0;
    int incomplete = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_PLATFORM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        fprintf(stderr, "PLATFORM 探针失败：win32=%lu\n", GetLastError());
        return 1;
    }
    kvaOk = (queryKvaShadow(&kva) == 0);

    /*
     * A probe "finishing" does not equal "calibrated". If any of the eight fields is unread or the KVA query fails, this
     * round has not fulfilled its purpose—must set the exit code to non-zero. Otherwise, the control script records OK and
     * acceptance records PASS, while in reality nothing was calibrated. This line has already suffered a similar loss once.
     */
    if (rsp.validMask != KSW_PLATFORM_VALID_ALL || !kvaOk) {
        incomplete = 1;
    }

    /* CR4.CET is bit23; CPUID.(7,0).ECX bit7 indicates the existence of CET_SS. */
    cetActive = ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_CR4) != 0UL) &&
                ((rsp.cr4 & (1ULL << 23)) != 0ULL);
    cetSupported =
        ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_CPUID7) != 0UL) &&
        ((rsp.cpuid7Ecx & (1UL << 7)) != 0UL);

    if (asJson) {
        printf("{\"kind\":\"probe-platform\",\"validMask\":\"0x%08lX\","
               "\"exceptionCode\":\"0x%08lX\",\"irql\":%lu,"
               "\"cr4\":\"0x%016llX\",\"cetActive\":%s,\"cetSupported\":%s,"
               "\"supervisorCet\":\"0x%016llX\",\"userCet\":\"0x%016llX\","
               "\"efer\":\"0x%016llX\",\"fsBase\":\"0x%016llX\","
               "\"gsBase\":\"0x%016llX\",\"kernelGsBase\":\"0x%016llX\","
               "\"cpuid7Ecx\":\"0x%08lX\",\"cpuid7Edx\":\"0x%08lX\","
               "\"kvaQueryOk\":%s,\"kvaFlags\":\"0x%08lX\","
               "\"kvaShadowEnabled\":%s}\n",
               rsp.validMask, rsp.exceptionCode, rsp.irql,
               rsp.cr4, cetActive ? "true" : "false",
               cetSupported ? "true" : "false",
               rsp.supervisorCet, rsp.userCet, rsp.efer,
               rsp.fsBase, rsp.gsBase, rsp.kernelGsBase,
               rsp.cpuid7Ecx, rsp.cpuid7Edx,
               kvaOk ? "true" : "false", kva,
               (kvaOk && (kva & 1UL)) ? "true" : "false");
        return incomplete ? 3 : 0;
    }

    printf("\n=== 平台探针（只读，不进 VMX）===\n");
    printf("  采样 IRQL    : %lu %s\n", rsp.irql,
           rsp.irql == 0UL ? "(PASSIVE_LEVEL，符合预期)" : "(**不是 PASSIVE**)");
    printf("  有效位       : 0x%08lX", rsp.validMask);
    if (rsp.exceptionCode != 0UL) {
        printf("   最后一次读异常 0x%08lX", rsp.exceptionCode);
    }
    printf("\n\n");

    printf("  [1] 影子栈 (CET)\n");
    printf("      CPUID.(7,0).ECX bit7 : %s\n",
           cetSupported ? "支持 CET_SS" : "不支持");
    printf("      CR4.CET(bit23)       : %s   (CR4 = 0x%016llX)\n",
           cetActive ? "**开着**" : "关着", rsp.cr4);
    if ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_S_CET) != 0UL) {
        printf("      IA32_S_CET           : 0x%016llX\n", rsp.supervisorCet);
    } else {
        printf("      IA32_S_CET           : 读不到（这台机器没有这个 MSR）\n");
    }
    if ((rsp.validMask & KSWORD_ARK_HVM_PLATFORM_VALID_U_CET) != 0UL) {
        printf("      IA32_U_CET           : 0x%016llX\n", rsp.userCet);
    } else {
        printf("      IA32_U_CET           : 读不到\n");
    }
    /*
     * CR4.CET and "a shadow stack is actually in use" are two different things; do not confuse them.
     * CR4.CET=1 only indicates that CET is enabled on this machine; whether shadow stacks
     * are actually in use depends on SH_STK_EN in IA32_S_CET (kernel) and IA32_U_CET (user).
     * Moreover, U_CET is swapped in and out by the OS **per thread** — reading 0 here only indicates
     * that **this specific thread** has no user shadow stack, and says nothing about other threads.
     */
    if (!cetActive) {
        printf("      => 不构成阻碍\n");
    } else if ((rsp.supervisorCet & 1ULL) != 0ULL) {
        printf("      => 内核影子栈**在用**（S_CET.SH_STK_EN=1）：退虚拟化要回到\n"
               "         内核态本身就得管影子栈 —— 这是硬阻碍\n");
    } else {
        printf("      => CET 在 CR4 里开着，但内核影子栈没启用（S_CET=0）。\n"
               "         ring-3 的 IRET 只在目标线程有用户影子栈时才走那套协议，\n"
               "         而 U_CET 是每线程的、这里读到的 0 只代表当前线程 ——\n"
               "         **算复杂度而不是硬阻碍，且未标定**。\n");
    }

    printf("\n  [2] 内核地址空间隔离 (KVA shadow)\n");
    if (!kvaOk) {
        printf("      查询失败 —— **不要当成\"没开\"**，这一项算未标定\n");
    } else {
        printf("      Flags                : 0x%08lX\n", kva);
        printf("      KvaShadowEnabled     : %s\n",
               (kva & 1UL) ? "**开着**" : "关着");
        printf("      => %s\n", (kva & 1UL)
            ? "用户态退出时 GUEST_CR3 是用户影子 PML4；VMXOFF 之后写回去"
              "\n         等于把内核从地址空间里抹掉 —— **三重故障**"
            : "不构成阻碍");
    }

    printf("\n  [3] GS base\n");
    printf("      IA32_GS_BASE         : 0x%016llX  (内核态下应当是 KPCR)\n",
           rsp.gsBase);
    printf("      IA32_KERNEL_GS_BASE  : 0x%016llX  (应当是用户 TEB)\n",
           rsp.kernelGsBase);
    printf("      IA32_FS_BASE         : 0x%016llX\n", rsp.fsBase);
    printf("      IA32_EFER            : 0x%016llX\n", rsp.efer);

    printf("\n  判定：");
    if (!kvaOk) {
        printf("KVA shadow 未标定，不下结论。\n");
    } else if ((kva & 1UL) != 0UL) {
        printf("**KVA shadow 开着** —— 用户态退出时写回 guest CR3 会抹掉内核，\n");
        printf("        跨特权级返回这条路不成立，而且现有的 CR3 恢复也有隐患。\n");
    } else if (cetActive && (rsp.supervisorCet & 1ULL) != 0ULL) {
        printf("**内核影子栈在用** —— 跨特权级返回这条路不成立。\n");
    } else {
        printf("两个否决理由都**不成立**（KVA shadow 关、内核影子栈没启用）。\n");
        printf("        顺带：现有的 `__writecr3(GuestCr3)` 在这台机器上没有隐患。\n");
        printf("        但 fail-open 那条**承重**理由不受影响，仍然拦着 ——\n");
        printf("        见 docs/next/用户态退虚拟化决策.md。\n");
    }
    if (incomplete) {
        printf("\n  ** 本轮没有标定完 **  validMask=0x%08lX（期望 0x%08lX）%s\n",
               rsp.validMask, (unsigned long)KSW_PLATFORM_VALID_ALL,
               kvaOk ? "" : "，且 KVA 查询失败");
        printf("     上面的判定只能当参考，不要拿它下结论。\n");
    }
    return incomplete ? 3 : 0;
}

/* ------------------------------------------------------------------------ */
/* Negative probe: verify that the cases expected to be rejected are indeed rejected.                                  */
/* ------------------------------------------------------------------------ */

/* Defined in the execute-only probe section below; shared by both locations. */
static int probeControl(HANDLE h, unsigned long command, unsigned long flags,
                        const char* what);

/*
 * This group consists entirely of **negative** predicates—each expects to be rejected, and expects to be rejected at
 * a **specific location**. Positive paths are easy to test; negative paths often fail by merely checking "it failed"
 * without verifying where, which is exactly where this line repeatedly incurs losses: a generic INVALID_REQUEST and
 * a precise capability rejection look identical in behavior but have completely different meanings.
 *
 * All requests are sent without modifying any state. Each is independently evaluated; a failure in one does not affect the others.
 */

/*
 * Tri-state, not bi-state.
 *
 * "Rejected" and "rejected at **that specific point**" are two different things. When prerequisites are not established, the
 * driver returns NOT_PREPARED first; at that time, any assertion of `status != some_value` will **silently PASS** without actually
 * testing anything. Such silent PASS-throughs are far more dangerous than FAIL results, so they are treated as a separate state.
 */
#define NEG_PASS 0
#define NEG_FAIL 1
#define NEG_VOID 2   /* No distinguishing power: the prerequisite was not established, so this case was not tested in this run. */

typedef struct NegCase
{
    const char* name;
    int verdict;
    unsigned long observed;
    long observedNt;
    const char* expectation;
    const char* remark;   /* May be NULL. */
} NegCase;

static const char* negName(int v)
{
    return (v == NEG_PASS) ? "PASS" : ((v == NEG_FAIL) ? "FAIL" : "空过");
}

static void negReport(const NegCase* c, int asJson, int first)
{
    if (asJson) {
        printf("%s{\"name\":\"%s\",\"verdict\":\"%s\",\"status\":%lu,"
               "\"lastStatus\":\"0x%08lX\",\"expected\":\"%s\"",
               first ? "" : ",", c->name, negName(c->verdict),
               c->observed, (unsigned long)c->observedNt, c->expectation);
        if (c->remark != NULL) { printf(",\"remark\":\"%s\"", c->remark); }
        printf("}");
        return;
    }
    printf("  [%-4s] %-34s status=%-2lu nt=0x%08lX\n",
           negName(c->verdict), c->name, c->observed,
           (unsigned long)c->observedNt);
    if (c->verdict != NEG_PASS) {
        printf("          期望：%s\n", c->expectation);
    }
    if (c->remark != NULL) {
        printf("          注：%s\n", c->remark);
    }
}

static int doProbeFlags(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rreq;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rrsp;
    KSWORD_ARK_CONTROL_HVM_REQUEST creq;
    KSWORD_ARK_CONTROL_HVM_RESPONSE crsp;
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;
    NegCase cases[4];
    unsigned int n = 0U;
    unsigned int i = 0U;
    int failed = 0;
    int voided = 0;

    memset(cases, 0, sizeof(cases));

    /* --- 1. ENFORCE must be rejected during installation, and must be UNIMPLEMENTED, not something else --- */
    memset(&rreq, 0, sizeof(rreq));
    memset(&rrsp, 0, sizeof(rrsp));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    rreq.deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_READ;
    rreq.physicalAddress = 0x1000ULL;
    rreq.pageCount = 1ULL;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                          &rrsp, (DWORD)sizeof(rrsp), &returned, NULL);
    cases[n].name = "ENFORCE 安装期拒绝";
    cases[n].observed = rrsp.status;
    cases[n].observedNt = rrsp.lastStatus;
    cases[n].expectation = "status=8 UNIMPLEMENTED（不是 0，也不是笼统的 1）";
    /*
     * This rule is independent of the prepare state: the rejection point is outside the lock
     * and before the Initialized check, so it has full discriminative power at any time.
     */
    cases[n].verdict =
        (rrsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED)
            ? NEG_PASS : NEG_FAIL;
    ++n;

    /* --- 2. ENABLE_VE must pass the whitelist check first, then be rejected by **capabilities** --- */
    memset(&creq, 0, sizeof(creq));
    memset(&crsp, 0, sizeof(crsp));
    creq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    creq.size = (unsigned long)sizeof(creq);
    creq.command = KSWORD_ARK_HVM_CONTROL_START_RESIDENT;
    creq.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VE;
    creq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &creq, sizeof(creq),
                          &crsp, (DWORD)sizeof(crsp), &returned, NULL);
    cases[n].name = "ENABLE_VE 死在能力门而非白名单";
    cases[n].observed = crsp.status;
    cases[n].observedNt = crsp.lastStatus;
    cases[n].expectation =
        "status=3 UNSUPPORTED_CPU（过了白名单、死在 #VE 能力判定）";
    /*
     * Three-state logic is mandatory here. The driver's pre-checks (RESOURCES_READY | EPT_READY |
     * SELF_TEST_PASSED all required) are placed **before all capability gates**; if not all are met,
     * it returns NOT_PREPARED immediately. Writing `status != 1` back then would have caused an
     * immediate false PASS—the whitelist's actual allow/deny decision would never have been verified.
     */
    if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST) {
        cases[n].verdict = NEG_FAIL;
        cases[n].remark = "白名单回归了：请求在门口就被拒，没到能力判定";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED) {
        cases[n].verdict = NEG_VOID;
        cases[n].remark =
            "前置未建立（要 prepare + self-test 都过），本条这次无区分力";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU) {
        cases[n].verdict = NEG_PASS;
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) {
        cases[n].verdict = NEG_FAIL;
        cases[n].remark = "**常驻被真的起起来了** —— 靶机居然有 #VE，需要停掉";
    } else {
        cases[n].verdict = NEG_VOID;
        cases[n].remark = "拒绝了，但不是在 #VE 能力门上，判不出白名单";
    }
    ++n;

    /*
     * Must clear FAULTED between test cases; otherwise, subsequent cases pass for the wrong reason.
     *
     * Actual test: The rejected START_RESIDENT in test case 2 sets the state to FAULTED. Thus, test
     * case 3 hits the FAULTED/ROLLBACK/UNLOAD_GUARD gate in hvm_resident.c (returning
     * STATUS_INVALID_DEVICE_STATE, protocol status=20 LIFECYCLE_GUARD_FAILED). It was indeed rejected,
     * but not by a mutual exclusion check. Reporting the 'mutual exclusion gate PASS' is false.
     */
    (void)probeControl(h, KSWORD_ARK_HVM_CONTROL_RESET_FAULT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE,
                       "RESET_FAULT(用例间清场)");

    /* --- 3. LOCAL_EPT + VMFUNC are mutually exclusive and must be rejected --- */
    memset(&creq, 0, sizeof(creq));
    memset(&crsp, 0, sizeof(crsp));
    creq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    creq.size = (unsigned long)sizeof(creq);
    creq.command = KSWORD_ARK_HVM_CONTROL_START_RESIDENT;
    creq.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_LOCAL_EPT |
                 KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_VMFUNC;
    creq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &creq, sizeof(creq),
                          &crsp, (DWORD)sizeof(crsp), &returned, NULL);
    cases[n].name = "LOCAL_EPT + VMFUNC 被拒";
    cases[n].observed = crsp.status;
    cases[n].observedNt = crsp.lastStatus;
    cases[n].expectation = "被拒；但在嵌套靶机上拒它的是 VMFUNC 能力门，不是互斥门";
    /*
     * Clarify why this test cannot detect the mutual exclusion gate: VMFUNC capability checks occur before mutual exclusion
     * checks, and nested Hyper-V does not expose EPTP switching, so the mutual exclusion branch is never reached.
     * Reporting 'Mutual Exclusion Gate PASS' would be dishonest.
     */
    if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK) {
        cases[n].verdict = NEG_FAIL;
        cases[n].remark = "**没拒绝** —— 两个互斥的能力被同时接受了";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED) {
        cases[n].verdict = NEG_VOID;
        cases[n].remark = "前置未建立，本条这次无区分力";
    } else if (crsp.status ==
                   KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED) {
        /*
         * It is rejected by the FAULTED/ROLLBACK/UNLOAD_GUARD gate, not the capability gate or the mutex
         * gate—the residue from the previous test case was not cleared. Count as a pass-by-empty, not a pass.
         */
        cases[n].verdict = NEG_VOID;
        cases[n].remark =
            "拒在生命周期守卫（状态里还带 FAULTED/ROLLBACK）——"
            "用例间清场没生效，本条无区分力";
    } else if (crsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU) {
        cases[n].verdict = NEG_PASS;
        cases[n].remark =
            "拒在 VMFUNC 能力门（靶机不暴露 EPTP switching）——"
            "**互斥门本身在这台机器上测不到**";
    } else {
        cases[n].verdict = NEG_PASS;
        cases[n].remark = "被拒了，但不是在能力门也不是在互斥门上";
    }
    ++n;

    /* --- 4. The above three steps should not enable the resident mode. */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                          &qrsp, (DWORD)sizeof(qrsp), &returned, NULL);
    cases[n].name = "负向用例没有留下常驻";
    cases[n].observed = qrsp.residentProcessorCount;
    cases[n].observedNt = qrsp.lastStatus;
    cases[n].expectation = "residentProcessorCount = 0";
    cases[n].verdict =
        (qrsp.residentProcessorCount == 0UL) ? NEG_PASS : NEG_FAIL;
    ++n;

    for (i = 0U; i < n; ++i) {
        if (cases[i].verdict == NEG_FAIL) { failed = 1; }
        if (cases[i].verdict == NEG_VOID) { voided = 1; }
    }

    if (asJson) {
        printf("{\"kind\":\"probe-flags\",\"failed\":%s,\"inconclusive\":%s,"
               "\"cases\":[",
               failed ? "true" : "false", voided ? "true" : "false");
        for (i = 0U; i < n; ++i) { negReport(&cases[i], 1, i == 0U); }
        printf("]}\n");
        return failed ? 2 : (voided ? 3 : 0);
    }

    printf("\n=== 负向探针（全部期望被拒绝）===\n");
    for (i = 0U; i < n; ++i) { negReport(&cases[i], 0, i == 0U); }
    if (failed) {
        printf("\n  判定：**有用例没有按预期被拒绝** —— 看上面标 FAIL 的那几条\n");
    } else if (voided) {
        printf("\n  判定：没有 FAIL，但**有用例空过** —— 前置没建立，那几条这次\n");
        printf("        什么都没测到。先 prepare + self-test 再跑，否则等于没测。\n");
    } else {
        printf("\n  判定：四条全部在**该拒绝的地方**拒绝了\n");
    }
    /* Skipped and failed cases return separately so scripts can distinguish between 'not tested' and 'test failure'. */
    return failed ? 2 : (voided ? 3 : 0);
}

/* ------------------------------------------------------------------------ */
/* execute-only probe                                                         */
/* ------------------------------------------------------------------------ */

/*
 * Answers two different questions; neither requires modifying the driver:
 *
 *   Does the Q1 driver consider execute-only available? ADD a rule that only
 *      denies READ, then return the normalized deniedAccess upon read attempt.
 *      The protocol comment is explicit: rejecting READ implies rejecting WRITE; and if
 *      execute-only is unsupported, EXECUTE is rejected as well. Thus, reading back 0x3 preserves
 *      X, while reading back 0x7 indicates that this machine cannot encode an execute-only leaf.
 *
 *   Q2: Does the hypervisor below recognize this permission? This is the real issue in nested virtualization:
 *      when L0 synthesizes shadow EPT for L1, it may promote X-only permissions to RX. If this promotion occurs,
 *      CLOAK will **silently fail** — no error code, no event, no BSOD, just the inability to hide. Therefore,
 *      the only solution is empirical testing: actually read that page to see if it triggers a violation.
 *
 * Observe **whether resident operation was lost**, not whether the read raised an exception.
 *
 * Previously used ENFORCE (triggering #PF, expecting SEH to catch it), which caused an infinite loop: The
 * injected #PF lands on the guest's own page fault handler, but the guest's page table indicates the page
 * is valid — the rejection occurs at the EPT layer, invisible to the guest. Consequently, the guest makes
 * no fix, returns, re-executes the instruction, triggers another EPT violation, another #PF, and loops
 * forever without SEH ever getting a chance to intervene. In practice, the entire script hangs there.
 *
 * Strict hits without ENFORCE take a different path: the dispatcher returns FALSE ⇒ virtualization
 * is exited (see "Unruled accesses and any strict overlapping rule devirtualize" in hvm_ept.c).
 * After VMXOFF, the instruction is re-executed natively, **the read completes normally**, and
 * residentProcessorCount drops to 0. This path terminates based on an integer condition, not an
 * exception. The cost is losing residency, but the probe stops anyway after running.
 *
 * Order is fixed by the driver; do not change arbitrarily: **Any operation modifying rules during
 * the resident phase is rejected** (the ResidentProcessorCount != 0 branch in hvm_runtime.c returns
 * PARTIAL / STATUS_DEVICE_BUSY). Reason: the exit path scans the rule table without a PASSIVE_LEVEL
 * lock, so the rule table and every split leaf must remain immutable during the resident phase.
 * Therefore, the sequence must be: install rules → start resident → read → stop resident → clear rules.
 *
 * That page belongs to the current process's memory and must remain valid until it becomes resident. Therefore, the entire operation
 * must be completed within the **same process**, including the START_RESIDENT and STOP_RESIDENT commands issued by this tool itself.
 */

/* Send a lifecycle control command; only care about success or failure. */
static int probeControl(HANDLE h, unsigned long command, unsigned long flags,
                        const char* what)
{
    KSWORD_ARK_CONTROL_HVM_REQUEST req;
    KSWORD_ARK_CONTROL_HVM_RESPONSE rsp;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.command = command;
    req.flags = flags;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL) ||
        rsp.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK) {
        fprintf(stderr, "%s 失败：status=%lu (%s) nt=0x%08lX win32=%lu\n",
                what, rsp.status, controlStatusName(rsp.status),
                (unsigned long)rsp.lastStatus, GetLastError());
        return 0;
    }
    return 1;
}
/*
 * tlb-probe: Directly test whether cross-processor TLB invalidation still works when resident.
 *
 * This addresses the unmeasured vulnerability flagged in the hvm_exit.c forwarding path: we forward the
 * guest's HvCallFlushVirtualAddressSpace/List calls verbatim to L0, while the sibling logical processor is
 * currently running as our guest. It is unknown whether L0's invalidation covers the nested guest context.
 * The comment predicts silent data corruption, bugchecks at unrelated symbols, and a requirement for
 * at least two virtual processors. These match the 0x139 incident on 2026-09-07 point for point.
 *
 * The commented testing approach suggests "single-processor vs. multi-processor long-term comparison," but that is a statistical experiment relying
 * on low-probability crash forensics; if no crash occurs after running, it proves nothing. Here, we switch to a **deterministic** criterion.
 *
 * The semantics returned by VirtualProtect are "all processors have seen the new
 * protection," which is internally realized via cross-core TLB shootdowns. In a
 * Hyper-V guest, that shootdown follows the hypercall we forward. Therefore:
 *
 *   1. The main thread changes a page to PAGE_NOACCESS, **wait for VirtualProtect to return**
 *   2. Only after returning, increment the epoch to an odd number to declare 'any content read from now on is a violation'.
 *   3. Worker threads bound to other processors read this page during odd epochs.
 *   4. Reading **success** is a mistranslation—it uses a mapping that should have already been invalidated.
 *
 * Read once before and once after the epoch, requiring them to be identical, is to rule out the case where the window was already closed before the read:
 * Do not count if the window changes; prefer missing counts over false positives.
 *
 * The criterion is not 'crashed or not', but the violation count. Run one round each before and after in both resident (enabled) and non-resident
 * (disabled) states to create the single-core/multi-core deterministic comparison: violations must be 0 when resident but disabled (this is the
 * baseline proving the probe itself is functional); only if violations remain 0 when resident and enabled can we confirm no forwarding loss occurred.
 *
 * Pure user-mode: no IOCTLs touched (only check resident status once at the start for
 * reporting), no page table modifications, no driver interaction. The machine cannot crash.
 */
typedef struct KswTlbWorker
{
    volatile unsigned char* page;
    volatile LONG* epoch;
    volatile LONG* stop;
    unsigned long processorIndex;
    /*
     * When set, execute a CPUID instruction before each read.
     *
     * CPUID is an unconditional VM exit, making this the cheapest method to force an exit from user mode on this
     * processor. It validates the prerequisite for the fix: when VPID is disabled, VM entry fails to associate the
     * linear mapping with VPID 0000H, so forcing a sibling core to exit once should suffice to flush stale translations.
     *
     * If the precondition holds ⇒ violation count should collapse to 0; only then does implementing "send NMI to wake sibling cores during flush forwarding"
     * make sense. If the precondition fails ⇒ violations persist, rendering that code change fundamentally invalid, saving the entire implementation effort.
     */
    int forceExit;
    unsigned long long reads;
    unsigned long long violations;
    unsigned long long faults;
} KswTlbWorker;

static DWORD WINAPI tlbProbeWorker(LPVOID param)
{
    KswTlbWorker* w = (KswTlbWorker*)param;
    DWORD_PTR mask = (DWORD_PTR)1 << (w->processorIndex & 63U);

    /* Bind to CPU core. If binding fails, continue execution; missing one core's coverage is not an error. */
    (void)SetThreadAffinityMask(GetCurrentThread(), mask);

    while (InterlockedCompareExchange((LONG*)w->stop, 0L, 0L) == 0L) {
        LONG e1 = InterlockedCompareExchange((LONG*)w->epoch, 0L, 0L);
        LONG e2 = 0L;
        int ok = 0;

        /* Measure only within the 'Access Denied' window; reading content during even epochs is normal. */
        if ((e1 & 1L) == 0L) {
            YieldProcessor();
            continue;
        }
        if (w->forceExit) {
            int regs[4];
            /* Unconditional VM exit. The exit-then-enter sequence should flush the linear mapping cache for this core. */
            __cpuid(regs, 0);
        }
        __try {
            /* volatile ensures this access is actually issued and not optimized away. */
            (void)w->page[0];
            ok = 1;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            ok = 0;
        }
        e2 = InterlockedCompareExchange((LONG*)w->epoch, 0L, 0L);
        w->reads += 1ULL;
        if (!ok) {
            /* Got an AV: this is the **correct** result; the failure has taken effect. */
            w->faults += 1ULL;
        } else if (e2 == e1) {
            /*
             * The entire read occurred within the same odd epoch, meaning it happened
             * completely after VirtualProtect(NOACCESS) returned but before it was released,
             * yet the read succeeded — this case should have already been invalidated.
             */
            w->violations += 1ULL;
        }
    }
    return 0;
}

static int doTlbProbe(HANDLE h, int asJson, unsigned long durationMs,
                      int forceExit)
{
    KswTlbWorker workers[64];
    HANDLE threads[64];
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;
    SYSTEM_INFO si;
    volatile unsigned char* page = NULL;
    volatile LONG epoch = 0L;
    volatile LONG stop = 0L;
    unsigned long processorCount = 0UL;
    unsigned long residentBefore = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned long workerCount = 0UL;
    unsigned long i = 0UL;
    unsigned long long totalReads = 0ULL;
    unsigned long long totalViolations = 0ULL;
    unsigned long long totalFaults = 0ULL;
    unsigned long long cycles = 0ULL;
    DWORD startTick = 0;
    DWORD oldProtect = 0;
    int rc = 1;

    memset(workers, 0, sizeof(workers));
    memset(threads, 0, sizeof(threads));

    if (durationMs == 0UL) {
        durationMs = 5000UL;
    }

    /* Read status once for reporting; start/stop residency is the caller's responsibility. */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentBefore = qrsp.residentProcessorCount;
        processorCount = qrsp.processorCount;
    }

    GetSystemInfo(&si);
    if (processorCount == 0UL) {
        processorCount = (unsigned long)si.dwNumberOfProcessors;
    }

    /*
     * One worker thread per processor; the main thread is separate. This also runs on single-core
     * systems—the point of that iteration is the baseline: with no sibling processors, violations must be 0.
     */
    workerCount = (unsigned long)si.dwNumberOfProcessors;
    if (workerCount == 0UL) {
        workerCount = 1UL;
    }
    if (workerCount > 64UL) {
        workerCount = 64UL;
    }

    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    page[0] = 0xA5U;

    for (i = 0UL; i < workerCount; ++i) {
        workers[i].page = page;
        workers[i].epoch = &epoch;
        workers[i].stop = &stop;
        workers[i].processorIndex = i;
        workers[i].forceExit = forceExit;
        threads[i] = CreateThread(NULL, 0, tlbProbeWorker,
                                  &workers[i], 0, NULL);
        if (threads[i] == NULL) {
            fprintf(stderr, "CreateThread 失败：win32=%lu\n", GetLastError());
            InterlockedExchange((LONG*)&stop, 1L);
            goto cleanup;
        }
    }

    startTick = GetTickCount();
    for (;;) {
        unsigned long spin = 0UL;

        if ((GetTickCount() - startTick) >= durationMs) {
            break;
        }
        /* Closing the door. Once VirtualProtect returns, all processors should see the new protection. */
        if (!VirtualProtect((LPVOID)page, 4096, PAGE_NOACCESS, &oldProtect)) {
            fprintf(stderr, "VirtualProtect(NOACCESS) 失败：win32=%lu\n",
                    GetLastError());
            break;
        }
        /* The window is declared to start only after returning; reversing the order would cause normal reads to be misidentified as violations. */
        InterlockedIncrement((LONG*)&epoch);
        for (spin = 0UL; spin < 20000UL; ++spin) {
            YieldProcessor();
        }
        /* Close the window first, then release protection, also to avoid misjudgment. */
        InterlockedIncrement((LONG*)&epoch);
        if (!VirtualProtect((LPVOID)page, 4096, PAGE_READWRITE, &oldProtect)) {
            fprintf(stderr, "VirtualProtect(READWRITE) 失败：win32=%lu\n",
                    GetLastError());
            break;
        }
        page[0] = 0xA5U;
        cycles += 1ULL;
    }
    InterlockedExchange((LONG*)&stop, 1L);
    rc = 0;

cleanup:
    for (i = 0UL; i < workerCount; ++i) {
        if (threads[i] != NULL) {
            (void)WaitForSingleObject(threads[i], 10000);
            (void)CloseHandle(threads[i]);
        }
    }
    /* Protect pages that might be stuck in NOACCESS; release protection first before freeing. */
    (void)VirtualProtect((LPVOID)page, 4096, PAGE_READWRITE, &oldProtect);

    for (i = 0UL; i < workerCount; ++i) {
        totalReads += workers[i].reads;
        totalViolations += workers[i].violations;
        totalFaults += workers[i].faults;
    }

    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentAfter = qrsp.residentProcessorCount;
    }

    if (asJson) {
        printf("{\"kind\":\"%s\",\"durationMs\":%lu,"
               "\"processorCount\":%lu,\"workerThreads\":%lu,"
               "\"residentBefore\":%lu,\"residentAfter\":%lu,"
               "\"protectCycles\":%llu,\"windowedReads\":%llu,"
               "\"faults\":%llu,\"violations\":%llu,\"verdict\":\"%s\"}\n",
               forceExit ? "tlb-probe-exit" : "tlb-probe",
               durationMs, processorCount, workerCount,
               residentBefore, residentAfter,
               cycles, totalReads, totalFaults, totalViolations,
               totalViolations != 0ULL
                   ? "stale-translation-observed"
                   : (totalReads == 0ULL ? "no-samples" : "coherent"));
    } else {
        printf("\n=== 跨处理器 TLB 失效探针 ===\n");
        printf("  时长/处理器数 : %lu ms / %lu（工作线程 %lu）\n",
               durationMs, processorCount, workerCount);
        printf("  常驻核数      : %lu -> %lu\n", residentBefore, residentAfter);
        printf("  保护翻转      : %llu 轮\n", cycles);
        printf("  窗口内取样    : %llu 次   AV %llu 次\n",
               totalReads, totalFaults);
        printf("  **违规**      : %llu 次\n", totalViolations);
        if (totalViolations != 0ULL) {
            printf("  判定          : stale-translation-observed\n");
            printf("    有处理器在 VirtualProtect(NOACCESS) 已经返回之后，仍然\n"
                   "    用一条本该失效的映射读到了内容。这正是转发段注释里那条\n"
                   "    unmeasured 隐患的形状。\n");
        } else if (totalReads == 0ULL) {
            printf("  判定          : no-samples（窗口没被取到，加长时长或核数）\n");
        } else {
            printf("  判定          : coherent（本轮没观察到陈旧翻译）\n");
            printf("    注意这是**没观察到**，不是证明不存在。要有说服力，\n"
                   "    常驻不起那一轮必须也是 0（基线），且取样数要足够大。\n");
        }
    }
    (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    return rc;
}

/*
 * rule-allowonce: Install an ALLOW_ONCE rule and check if the gate allows it during installation.
 *
 * Why a dedicated verb: ALLOW_ONCE temporarily relaxes an EPT leaf for a single instruction and then reverts it
 * Monitor-trap restoration: that window is visible across the entire machine at the **shared** layer. At runtime, a
 * gate blocks execution (fail-closed if conditions aren't met), but that is too late—rules are installed and reported
 * as successful; the VMX session only exits upon a real hit. Rejections must occur during installation, not later.
 *
 * This path is reachable in production: the second item in the KernelHvmTab dropdown of the GUI invokes
 * it, and no prior tool verb sets this flag—so installing this gate makes it impossible to verify.
 *
 * This verb reports only **facts**, not correctness judgments for the caller: processor count, two relevant capability bits, and the
 * installation return status. The criteria are left to the outside layer; it should be false when multi-core and without armed private EPT.
 * gate-refused: 'installed' is valid only in other cases. Once installed, delete it immediately to avoid leaving dirty state.
 */
static int doRuleAllowOnceGate(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rreq;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long processorCount = 0UL;
    unsigned long long features = 0ULL;
    int hasInveptSingle = 0;
    int hasMonitorTrap = 0;
    int removed = 0;
    const char* verdict = "unknown";
    int rc = 1;

    /* --- 0. Resident mode must not be running: the rule table is immutable during residency --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (qrsp.residentProcessorCount != 0UL) {
        fprintf(stderr,
                "常驻正在跑（residentProcessorCount=%lu）。\n"
                "常驻期间规则表是不可变的，装不上规则。先 hvm_ctl stop。\n",
                qrsp.residentProcessorCount);
        return 1;
    }
    processorCount = qrsp.processorCount;
    features = qrsp.featureFlags;
    hasInveptSingle =
        (features & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL;
    hasMonitorTrap =
        (features & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL;

    /* --- 1. Allocate a page of private memory and map it to a real physical page --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA. This IOCTL has its own version number and UI_CONFIRMED bit. */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu nt=0x%08lX win32=%lu\n",
                mrsp.status, (unsigned long)mrsp.ntStatus, GetLastError());
        goto cleanup;
    }
    physical = mrsp.physicalAddress;

    /* --- 3. Install an ALLOW_ONCE rule to see if the watchdog allows it --- */
    memset(&rreq, 0, sizeof(rreq));
    memset(&rrsp, 0, sizeof(rrsp));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
    /* ENFORCE will be rejected earlier by the UNIMPLEMENTED gate, and ALLOW_ONCE will be lost during storage. */
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    rreq.deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
    rreq.physicalAddress = physical & ~0xFFFULL;
    rreq.pageCount = 1ULL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                         &rrsp, (DWORD)sizeof(rrsp), &returned, NULL)) {
        fprintf(stderr, "EPT_RULE ADD 下发失败：win32=%lu\n", GetLastError());
        goto cleanup;
    }

    if (rrsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE) {
        verdict = "gate-refused";
    } else if (rrsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        verdict = "installed";
        /* Uninstall immediately upon installation — this verb only probes the door, leaving no rules behind. */
        memset(&rreq, 0, sizeof(rreq));
        rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        rreq.size = (unsigned long)sizeof(rreq);
        rreq.operation = KSWORD_ARK_HVM_EPT_RULE_REMOVE;
        rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
        rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        rreq.ruleId = rrsp.ruleId;
        {
            KSWORD_ARK_HVM_EPT_RULE_RESPONSE drsp;
            memset(&drsp, 0, sizeof(drsp));
            removed = DeviceIoControl(
                h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                &drsp, (DWORD)sizeof(drsp), &returned, NULL) &&
                drsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK;
        }
    } else {
        verdict = "other-status";
    }
    rc = 0;

    if (asJson) {
        printf("{\"kind\":\"rule-allowonce\",\"processorCount\":%lu,"
               "\"inveptSingle\":%s,\"monitorTrapFlag\":%s,"
               "\"status\":%lu,\"lastStatus\":\"0x%08lX\","
               "\"ruleRemoved\":%s,\"verdict\":\"%s\"}\n",
               processorCount,
               hasInveptSingle ? "true" : "false",
               hasMonitorTrap ? "true" : "false",
               rrsp.status, (unsigned long)rrsp.lastStatus,
               removed ? "true" : "false",
               verdict);
    } else {
        printf("处理器数        : %lu\n", processorCount);
        printf("INVEPT_SINGLE   : %s\n", hasInveptSingle ? "有" : "无");
        printf("MONITOR_TRAP    : %s\n", hasMonitorTrap ? "有" : "无");
        printf("ALLOW_ONCE 安装 : status=%lu nt=0x%08lX\n",
               rrsp.status, (unsigned long)rrsp.lastStatus);
        printf("判定            : %s\n", verdict);
        if (strcmp(verdict, "gate-refused") == 0) {
            printf("  安装期的门拒了这条规则 —— 这台机器上 ALLOW_ONCE 无法安全\n"
                   "  实现（多核共享层次，放宽窗口全机可见），拒在安装期而不是\n"
                   "  等它某次命中把整机退出 VMX。\n");
        } else if (strcmp(verdict, "installed") == 0) {
            printf("  规则装上了（已删除）。只有单核、或者武装了私有 EPT 的多核\n"
                   "  才应该走到这里。\n");
        }
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    return rc;
}

static int doProbeExecuteOnly(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rreq;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long effectiveDenied = 0UL;
    unsigned long ruleId = 0UL;
    int faulted = 0;
    int started = 0;
    int probed = 0;
    int enforced = 0;
    unsigned long residentAfter = 0UL;
    /* Number of resident cores before the read. The criterion is a decrease, not a drop to 0; see the comment where resident mode is started. */
    unsigned long residentBefore = 0UL;
    /* Duration waited for other processors to self-unload. 0 indicates the count dropped after the first sample. */
    unsigned long residentSettleMs = 0UL;
    unsigned char observed = 0U;
    int rc = 1;

    /* --- 0. The resident hypervisor must **not** be running: installing rules requires a mutable rule table --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (qrsp.residentProcessorCount != 0UL) {
        fprintf(stderr,
                "常驻正在跑（residentProcessorCount=%lu）。\n"
                "常驻期间规则表是不可变的，装不上规则。先 hvm_ctl stop。\n",
                qrsp.residentProcessorCount);
        return 1;
    }

    /* --- 1. Allocate a page of our own memory and write a marker. */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    /* First allocate a real physical page so TRANSLATE has data to translate. */
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    /*
     * This IOCTL has its own protocol version, not the generic one. Using the wrong version
     * triggers a version check in hvm_memory.c, returning status=1 / STATUS_INVALID_PARAMETER,
     * which looks identical to "invalid parameters." Learned this the hard way.
     * Similarly, it has its own UI_CONFIRMED bit; providing a token alone is insufficient.
     */
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu (%s) nt=0x%08lX win32=%lu\n",
                mrsp.status,
                mrsp.status == KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST
                    ? "INVALID_REQUEST，多半是 version/size/reserved0"
                    : (mrsp.status ==
                       KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED
                          ? "CONFIRMATION_REQUIRED，缺 UI_CONFIRMED 位或 token"
                          : "见 KswordArkHvmIoctl.h 的 MEMORY_STATUS_*"),
                (unsigned long)mrsp.ntStatus, GetLastError());
        goto cleanup;
    }
    physical = mrsp.physicalAddress;

    /* --- 3. Install an ENFORCE rule that only rejects READ operations, then read back the valid mask (Q1) --- */
    memset(&rreq, 0, sizeof(rreq));
    memset(&rrsp, 0, sizeof(rrsp));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
    /* Do not use ENFORCE — see the function header comment; that path leads to an infinite loop. */
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    rreq.deniedAccess = KSWORD_ARK_HVM_EPT_ACCESS_READ;
    rreq.physicalAddress = physical & ~0xFFFULL;
    rreq.pageCount = 1ULL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                         &rrsp, (DWORD)sizeof(rrsp), &returned, NULL) ||
        rrsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        fprintf(stderr, "EPT_RULE ADD 失败：status=%lu nt=0x%08lX win32=%lu\n",
                rrsp.status, (unsigned long)rrsp.lastStatus, GetLastError());
        goto cleanup;
    }
    effectiveDenied = rrsp.deniedAccess;
    ruleId = rrsp.ruleId;

    /* --- 4. Start resident. Rules are installed; now EPT truly begins enforcement. */
    if (!probeControl(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
                      "START_RESIDENT")) {
        goto cleanup_rules;
    }
    started = 1;

    /*
     * Record the number of resident cores before reading—the criterion requires a **decrease**, not a drop to **0**.
     *
     * Origin of this criterion: fail-closed originally only retired the current processor. The
     * KeIpiGenericCall mechanism handles planned start/stop/failures but does not support fail-closed, as that
     * path resides in VMX root with uncertain IRQL, making IPIs impossible. Consequently, on 1 vCPU, "retiring
     * the current core" and "full stop" are indistinguishable, so residentAfter==0 holds. On 2 vCPUs, the same
     * correct behavior leaves the other core resident, so residentAfter==1; the old criterion then incorrectly
     * judged "not forced" because the driver remained unchanged, treating the core count as a constant.
     * Measured on 2026-09-07: A 1 vCPU configuration reports execute-only-enforced; a 2 vCPU configuration reports not-enforced.
     *
     * **Driver-side fix later**: The core that failed sets ResidentFaultStopRequested;
     * other processors see this on their next VM exit and self-unwind, resulting in a true
     * full-system halt (2 vCPU test on the same day: residentBefore=2 -> residentAfter=0).
     *
     * The predicate remains in the 'before -> after' form, **intentionally not reverted to ==0**: it
     * holds for both behaviors, whereas ==0 holds for only one. Tightening a broader predicate to
     * exactly match the current implementation turns the next behavioral change into a false positive.
     */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentBefore = qrsp.residentProcessorCount;
    }

    /*
     * --- 5. Read that page, but **the driver must perform the read**; do not access page[0] directly here ---
     *
     * Strict match handling triggers a fail-closed virtualization exit, and the exit path
     * (ResidentDevirtualize in hvm_entry.asm) performs a **same-privilege-level return**:
     * It pushes DevirtualizeRsp onto RSP, pushes RIP/RFLAGS on top, then returns.
     * That path only holds when the guest is in kernel mode. A user-mode read violation causes
     * it to return a ring-3 RSP/RIP on ring 0, which directly triggers a BSOD in practice.
     *
     * OP_READ_PHYSICAL is clean: actual access occurs within the driver's private window, in kernel mode, on the same
     * physical page, still triggering rules, while returning from virtualization goes back to the kernel context.
     */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = physical;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL)) {
        fprintf(stderr, "READ_PHYSICAL 未返回：win32=%lu\n", GetLastError());
        goto cleanup_rules;
    }
    if (mrsp.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK &&
        mrsp.bytesTransferred >= 1UL) {
        /* Read succeeded; record the returned byte. */
        observed = mrsp.data[0];
    } else {
        /* A read failure itself indicates being blocked; record it. */
        faulted = 1;
    }
    /* This read definitely occurred, providing basis for the judgment. */
    probed = 1;

    /*
     * --- 5b. Re-read the resident status; this is the actual criterion.
     *
     * **Bounded polling, not a single immediate read.** Full system shutdown ensures **eventual consistency**, not instantaneous consistency:
     * The core that failed exits immediately and sets ResidentFaultStopRequested; other
     * processors wait for their next VM exit to see the flag and exit themselves. Since IPIs
     * cannot be sent from VMX root, this is the only channel to deliver the request to them.
     *
     * Sampling immediately after reading measures a race, not the mechanism. In a test on 2026-09-07 with 2 vCPU, 5
     * consecutive immediate samples returned residentAfter=1 in 4 cases and 0 in 1 case. The same driver and code
     * path produced readings alternating between 0 and 1; drawing a conclusion from any one reading is incorrect.
     *
     * Actual latency is very short: with a soak rate of ~5500 exits/second, another core typically
     * collides with an exit within milliseconds. Thus, a few hundred milliseconds upper bound is
     * sufficiently wide while still exposing true failures where exits cannot be settled.
     *
     * Report waitedMs instead of hiding the wait: the criterion is 'dropped to 0 and how long it
     * took'; a probe that silently retries to success is indistinguishable from a false green.
     */
    {
        const unsigned long kSettleBudgetMs = 500UL;
        const unsigned long kSettleStepMs = 10UL;
        unsigned long waited = 0UL;

        for (;;) {
            memset(&qreq, 0, sizeof(qreq));
            memset(&qrsp, 0, sizeof(qrsp));
            qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
            qreq.size = (unsigned long)sizeof(qreq);
            if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM,
                                 &qreq, sizeof(qreq),
                                 &qrsp, (DWORD)sizeof(qrsp),
                                 &returned, NULL)) {
                fprintf(stderr, "读后 QUERY_HVM 失败：win32=%lu\n",
                        GetLastError());
                probed = 0;
                goto cleanup_rules;
            }
            residentAfter = qrsp.residentProcessorCount;
            /* Reaching 0 is the terminal state; no further waiting is needed. */
            if (residentAfter == 0UL) {
                break;
            }
            /* If the budget is exhausted, report the current value immediately without further waiting. */
            if (waited >= kSettleBudgetMs) {
                break;
            }
            Sleep(kSettleStepMs);
            waited += kSettleStepMs;
        }
        residentSettleMs = waited;
    }

    /* --- 6. Stop the resident component first, otherwise the rule cleanup below will be rejected --- */
    (void)probeControl(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
                       "STOP_RESIDENT");
    started = 0;

cleanup_rules:
    /* Rules can only be cleared after stopping the resident component. */
    if (started) {
        (void)probeControl(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                           KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
                           "STOP_RESIDENT");
        started = 0;
    }
    memset(&rreq, 0, sizeof(rreq));
    rreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    rreq.size = (unsigned long)sizeof(rreq);
    rreq.operation = KSWORD_ARK_HVM_EPT_RULE_CLEAR;
    rreq.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
    rreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    (void)DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &rreq, sizeof(rreq),
                          &rrsp, (DWORD)sizeof(rrsp), &returned, NULL);

    /*
     * Never print a verdict if the read was never actually performed. faulted==0 has two sources: "read
     * without fault" and "never reached the read step"; mixing them creates a false negative. A false
     * negative on this line leads to the worst-case conclusion ("L0 does not honor permissions").
     */
    if (!probed) {
        fprintf(stderr, "探针没有跑到读那一步，不输出判定。\n");
        rc = 1;
        goto cleanup;
    }

    /*
     * Criterion: Fewer cores are running the resident hypervisor **after** the read than before it.
     *
     * Missing '=' means strict hit triggers fail-closed virtualization exit = permissions are truly enforced.
     * No decrease means no EPT violation occurred during that read, indicating L0 failed to honor the removal of permissions.
     *
     * **Do not write residentAfter == 0**; there are two reasons:
     *
     * Historical reason: fail-closed originally only rolled back the current processor. On an N-core system,
     * the correct behavior leaves N-1 cores active, not 0. The old check condition happened to hold for 1 vCPU,
     * but on multi-core systems it incorrectly classified correct behavior as failure (tested on 2026-09-07).
     *
     * The second point still holds: after the driver switches to a full-machine stop, reaching '0' is a **final** state, not
     * immediate (other cores must wait for their next VM exit). The bounded polling above tests for this final state, but
     * even if polling times out, the fact that the count is 'less' proves EPT was forced at least once—that is the question
     * this probe answers. Tightening the criterion to ==0 would turn a single scheduling jitter into a false positive.
     * Whether the full machine shutdown has truly completed depends on residentAfterRead and residentSettleMs.
     *
     * residentBefore == 0 indicates the prior QUERY failed, so "missing" is meaningless; fall back to checking only faulted
     * — when lacking a baseline, prefer not to conclude rather than drawing conclusions from a non-existent difference.
     */
    enforced = faulted ||
        (residentBefore > 0UL && residentAfter < residentBefore);
    rc = enforced ? 0 : 2;

    if (asJson) {
        printf("{\"kind\":\"probe-xonly\",\"physicalAddress\":\"0x%016llX\","
               "\"ruleId\":%lu,\"requestedDenied\":1,\"effectiveDenied\":%lu,"
               "\"executeOnlyEncodable\":%s,\"residentBeforeRead\":%lu,"
               "\"residentAfterRead\":%lu,\"residentSettleMs\":%lu,"
               "\"readFaulted\":%s,\"observedByte\":%u,\"enforced\":%s,"
               "\"verdict\":\"%s\"}\n",
               physical, ruleId, effectiveDenied,
               ((effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL)
                   ? "true" : "false",
               residentBefore,
               residentAfter,
               residentSettleMs,
               faulted ? "true" : "false",
               (unsigned)observed,
               enforced ? "true" : "false",
               enforced
                   ? (((effectiveDenied &
                        KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL)
                          ? "execute-only-enforced" : "enforced-without-x-only")
                   : "not-enforced");
        goto cleanup;
    }

    printf("\n=== execute-only 探针 ===\n");
    printf("  目标物理页   : 0x%016llX   ruleId=%lu\n",
           physical & ~0xFFFULL, ruleId);
    printf("  请求拒绝     : READ\n");
    printf("  有效拒绝     : 0x%lX  (%s%s%s)\n", effectiveDenied,
           (effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_READ) ? "R" : "-",
           (effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) ? "W" : "-",
           (effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) ? "X" : "-");
    if ((effectiveDenied & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL) {
        printf("  Q1 驱动侧   : EXECUTE 被保住了 => 能编码出 execute-only 叶\n");
    } else {
        printf("  Q1 驱动侧   : EXECUTE 也被拒了 => 这台机器编码不出 "
               "execute-only，CLOAK 无从谈起\n");
    }
    printf("  读回字节     : 0x%02X   常驻核数 %lu -> %lu（等了 %lu ms）%s\n",
           (unsigned)observed, residentBefore, residentAfter,
           residentSettleMs,
           faulted ? "   （读本身抛了异常）" : "");
    printf("  判据         : 常驻核数**降下来了**即视为强制生效，"
           "不是「降到 0」。\n");
    printf("                 失败关闭的核当场退出并置位全机停机请求，其余核要\n");
    printf("                 等各自下次 VM exit 才自退 —— 从 VMX root 发不了\n");
    printf("                 IPI，那是唯一的通道。所以「降到 0」是**最终**成立，\n");
    printf("                 上面的毫秒数就是等它成立花的时间（0 = 一读就已降完）。\n");
    if (enforced) {
        printf("  Q2 L0 侧    : 那次读**产生了 EPT 违规**（常驻被 fail-closed "
               "打回原生）\n");
        printf("\n  判定：EPT 权限在嵌套下被真正强制。\n");
    } else {
        printf("  Q2 L0 侧    : 那次读**什么都没触发**，常驻原样还在\n");
        printf("\n  判定：**L0 没有兑现被移除的权限。**\n");
        printf("  CLOAK/HOOK 在这台机器上会静默失效（无错误码、无事件、"
               "无蓝屏，只是藏不住）。\n");
        printf("  换 EPTP 切换后端**解决不了**这个问题 —— 那是分离视图怎么切，\n");
        printf("  不是切过去之后权限算不算数。\n");
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    return rc;
}

/* ------------------------------------------------------------------------ */
/* EPT split view (CLOAK / HOOK)                                              */
/* ------------------------------------------------------------------------ */

static const char* viewStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_VIEW_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND:             return "NOT_FOUND";
    case KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL:            return "TABLE_FULL";
    case KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED:          return "SPLIT_FAILED";
    case KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT:         return "LEAF_CONFLICT";
    case KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED:
        return "EXECUTE_ONLY_UNSUPPORTED";
    case KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE:
        return "MULTIPROCESSOR_UNSAFE";
    case KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED:       return "RESOURCE_FAILED";
    default:                                               return "<未知>";
    }
}

static const char* viewKindName(unsigned long k)
{
    return (k == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) ? "CLOAK"
         : ((k == KSWORD_ARK_HVM_VIEW_KIND_HOOK) ? "HOOK" : "<未知>");
}

static const char* eventTypeName(unsigned long t)
{
    switch (t) {
    case KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT:        return "VMEXIT";
    case KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION: return "EPT_VIOLATION";
    case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX:    return "NESTED_VMX";
    case KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT:    return "FATAL_EXIT";
    case KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE:     return "LIFECYCLE";
    case KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE:   return "NESTED_PAGE";
    default:                                      return "<未知>";
    }
}

/* Write the access bitmask in rwx format; missing bits are represented as '-'. */
static void eventAccessText(unsigned long access, char out[4])
{
    out[0] = (access & KSWORD_ARK_HVM_EPT_ACCESS_READ)    ? 'r' : '-';
    out[1] = (access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE)   ? 'w' : '-';
    out[2] = (access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) ? 'x' : '-';
    out[3] = '\0';
}

/*
 * events: Read the event ring line by line.
 *
 * Why this verb is mandatory: On the backend (b) (EPTP switch), flipCount is structurally always 0—the only
 * increment point is at hvm_ept_view.c:903, but that backend returns early at :821. Consequently, there is
 * originally no readable number indicating whether this view was actually touched by hardware on this backend.
 *
 * The event ring records one line per EPT violation, including the access bits and ruleId (the viewId is
 * carried by the view flip). **If access includes 'x' and ruleId matches a HOOK view's ID, it is the
 * first-hand positive evidence that an instruction fetch landed on that page and triggered redirection**
 * — precisely the missing measurement in the roadmap's 'HOOK direction not yet measured' item.
 *
 * Prior to this, hvm_ctl only reported two aggregated integers (eventCount
 * / droppedEventCount), indicating "how many" but not "which ones".
 *
 * **Event ring is consumptive**: once the cursor advances, old rows cannot be re-read. Therefore, `afterSequence` must be advanced by the caller; do
 * not expect to re-run and read the same batch. A non-zero `droppedRows` indicates the ring was overwritten; in that case, "not reading a specific
 * entry" does not imply "the event never occurred"—these two concepts must be distinguished, otherwise it introduces another false positive criterion.
 */
static int doEvents(HANDLE h, unsigned long long afterSequence, unsigned long maxRows, int asJson)
{
    KSWORD_ARK_HVM_EVENT_QUERY_REQUEST req;
    KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    unsigned long i;
    unsigned long execRows = 0UL;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    /*
     * operation must be explicitly set to READ.
     *
     * READ is 1, not 0. If this field is not written after memset, the sent operation code is unknown.
     * The driver returns STATUS_INVALID_PARAMETER per contract (hvm_event.c:186-192, also validating
     * version and size). This is a clean rejection, not a crash, but the caller observes "no rows read,"
     * which is easily mistaken for "the event ring is empty." These two scenarios must be distinguished.
     */
    req.operation = KSWORD_ARK_HVM_EVENT_QUERY_READ;
    req.maxRows = maxRows;
    req.afterSequence = afterSequence;

    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EVENTS,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        /* Write to stdout instead of stderr: callers often only check stdout; writing
         * failures to stderr makes 'IOCTL rejected' look identical to 'event ring is empty'. */
        printf("\n=== 事件环：读取失败 ===\n");
        printf("  IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
               (int)ok, returned, GetLastError());
        printf("  这是**读不到**，不是**没有事件**。两者不能混为一谈。\n");
        return 1;
    }

    for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
        if ((rsp.rows[i].access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) {
            ++execRows;
        }
    }

    if (asJson) {
        printf("{\"kind\":\"events\",\"returnedRows\":%lu,\"availableRows\":%lu,"
               "\"droppedRows\":%lu,\"newestSequence\":%llu,"
               "\"afterSequence\":%llu,\"executeRows\":%lu,\"rows\":[",
               rsp.returnedRows, rsp.availableRows, rsp.droppedRows,
               rsp.newestSequence, afterSequence, execRows);
        for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
            char acc[4];
            eventAccessText(rsp.rows[i].access, acc);
            printf("%s{\"sequence\":%llu,\"type\":%lu,\"typeName\":\"%s\","
                   "\"exitReason\":%lu,\"access\":%lu,\"accessText\":\"%s\","
                   "\"ruleId\":%lu,\"guestPhysicalAddress\":\"0x%016llX\","
                   "\"guestLinearAddress\":\"0x%016llX\",\"guestRip\":\"0x%016llX\","
                   "\"qualification\":\"0x%016llX\",\"status\":\"0x%08lX\","
                   "\"processor\":%u,\"processorGroup\":%u,\"timestampQpc\":%llu",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].sequence, rsp.rows[i].type,
                   eventTypeName(rsp.rows[i].type),
                   rsp.rows[i].exitReason, rsp.rows[i].access, acc,
                   rsp.rows[i].ruleId, rsp.rows[i].guestPhysicalAddress,
                   rsp.rows[i].guestLinearAddress, rsp.rows[i].guestRip,
                   rsp.rows[i].qualification, (unsigned long)rsp.rows[i].status,
                   (unsigned)rsp.rows[i].processorNumber,
                   (unsigned)rsp.rows[i].processorGroup, rsp.rows[i].timestamp);
            if (rsp.rows[i].type == KSWORD_ARK_HVM_EVENT_TYPE_NESTED_PAGE) {
                /* Typed aliases disambiguate fields reused by the fixed event ABI. */
                printf(",\"pageOperationId\":%lu,\"pageStage\":%lu,\"pageOperation\":%lu,"
                       "\"faultMode\":%llu,\"ept12Pointer\":\"0x%016llX\","
                       "\"replacementBacking\":\"0x%016llX\"",
                       rsp.rows[i].ruleId, rsp.rows[i].exitReason, rsp.rows[i].access,
                       (rsp.rows[i].qualification & KSWORD_ARK_HVM_NESTED_PAGE_FAULT_MASK) >> KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT,
                       rsp.rows[i].guestLinearAddress, rsp.rows[i].guestRip);
            }
            putchar('}');
        }
        printf("]}\n");
        return 0;
    }

    printf("\n=== 事件环（afterSequence=%llu）===\n", afterSequence);
    printf("  本次读回 %lu 行；环里可读 %lu 行；最新序号 %llu\n",
           rsp.returnedRows, rsp.availableRows, rsp.newestSequence);
    if (rsp.droppedRows != 0UL) {
        printf("  **丢弃 %lu 行**：环被覆盖过。此时「没读到某条」不等于「它没发生」。\n",
               rsp.droppedRows);
    }
    if (rsp.returnedRows == 0UL) {
        printf("  （这一段没有新事件）\n");
        return 0;
    }
    printf("  %-8s %-14s %-4s %-6s %-18s %-18s %s\n",
           "序号", "类型", "访问", "ruleId", "GPA", "GuestRIP", "exitReason");
    for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
        char acc[4];
        eventAccessText(rsp.rows[i].access, acc);
        printf("  %-8llu %-14s %-4s %-6lu 0x%016llX 0x%016llX %lu\n",
               rsp.rows[i].sequence, eventTypeName(rsp.rows[i].type), acc,
               rsp.rows[i].ruleId, rsp.rows[i].guestPhysicalAddress,
               rsp.rows[i].guestRip, rsp.rows[i].exitReason);
    }
    printf("\n  其中 access 含 x 的 %lu 行。\n", execRows);
    printf("  含 x 且 ruleId 等于某条 HOOK 视图编号的行 = 取指落在该页并触发了重定向，\n"
           "  那是「HOOK 方向」的正向证据；一行都没有则是**无读数**（那一页没被执行过），\n"
           "  既不是成功也不是失败。\n");
    return 0;
}

/*
 * Send a view IOCTL once.
 *
 * **Returning FALSE does not mean no response.** The security policy gate (hvm_ioctl.c)
 * writes the complete response to the output buffer before returning a failed NTSTATUS when
 * denying access; thus DeviceIoControl returns FALSE, while status/lastStatus remain valid.
 * Checking only the return value would misreport a 'policy denial' as a 'transport-layer failure'.
 */
static int viewIoctl(HANDLE h,
                     KSWORD_ARK_HVM_VIEW_REQUEST* req,
                     KSWORD_ARK_HVM_VIEW_RESPONSE* rsp)
{
    DWORD returned = 0;
    BOOL ok;

    req->version = KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION;
    req->size = (unsigned long)sizeof(*req);
    memset(rsp, 0, sizeof(*rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_VIEW, req, (DWORD)sizeof(*req),
                         rsp, (DWORD)sizeof(*rsp), &returned, NULL);
    if (returned >= sizeof(*rsp)) {
        /* Use the response if complete, regardless of whether ok is true or false. */
        return 0;
    }
    fprintf(stderr, "VIEW IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
            (int)ok, returned, GetLastError());
    return 1;
}

static int doViewQuery(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_VIEW_REQUEST req;
    KSWORD_ARK_HVM_VIEW_RESPONSE rsp;
    unsigned long i;

    memset(&req, 0, sizeof(req));
    /* The QUERY response is sent before the gate is confirmed, so no token is required and no state is modified. */
    req.operation = KSWORD_ARK_HVM_VIEW_OP_QUERY;
    if (viewIoctl(h, &req, &rsp) != 0) { return 1; }

    if (asJson) {
        printf("{\"kind\":\"view-query\",\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"viewCount\":%lu,\"generation\":%lu,"
               "\"rows\":[",
               rsp.status, viewStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.viewCount, rsp.generation);
        for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
            printf("%s{\"viewId\":%lu,\"kind\":\"%s\",\"flags\":%lu,"
                   "\"physicalAddress\":\"0x%016llX\","
                   "\"shadowPhysicalAddress\":\"0x%016llX\",\"flipCount\":%llu}",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].viewId, viewKindName(rsp.rows[i].kind),
                   rsp.rows[i].flags, rsp.rows[i].physicalAddress,
                   rsp.rows[i].shadowPhysicalAddress, rsp.rows[i].flipCount);
        }
        printf("]}\n");
        return (rsp.status == KSWORD_ARK_HVM_VIEW_STATUS_OK) ? 0 : 2;
    }

    printf("\n=== EPT 分离视图（只读）===\n");
    printf("  status       : %lu (%s)  lastStatus=0x%08lX\n",
           rsp.status, viewStatusName(rsp.status),
           (unsigned long)rsp.lastStatus);
    printf("  已装视图数   : %lu   代次=%lu\n", rsp.viewCount, rsp.generation);
    if (rsp.returnedRows == 0UL) {
        printf("  （没有任何已安装的视图）\n");
    }
    for (i = 0UL; i < rsp.returnedRows && i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
        printf("  #%-3lu %-5s pa=0x%016llX shadow=0x%016llX flips=%llu flags=0x%lX\n",
               rsp.rows[i].viewId, viewKindName(rsp.rows[i].kind),
               rsp.rows[i].physicalAddress, rsp.rows[i].shadowPhysicalAddress,
               rsp.rows[i].flipCount, rsp.rows[i].flags);
    }
    return (rsp.status == KSWORD_ARK_HVM_VIEW_STATUS_OK) ? 0 : 2;
}

/*
 * view-probe: **Attribution** probe, not a 'try to install' probe.
 *
 * During installation, three different gates return the same MULTIPROCESSOR_UNSAFE(9):
 *   Outer layer 'always resident' (hvm_ept_view.c:850), ninth
 *   check 'multi-core without LOCAL_EPT' (:633), tenth check
 *   'missing INVEPT_SINGLE / MONITOR_TRAP_FLAG' (:645).
 * Thus, a bare 'status=9' proves nothing—it matches the 'silent skip' pattern
 * seen in the probe-flags round: all green reports but no actual testing.
 *
 * Therefore, query the status first to determine if the capability gate is actually testable; if not, report
 * the third state as 'skipped' with an explanation of the missing component, never counting it as passed.
 */
static int doViewProbe(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    int verdict = NEG_VOID;
    const char* reason = "未判定";
    const char* expectation = "";
    int haveCaps = 0;
    int eptpSwitch = 0;
    int installed = 0;
    int attempted = 0;
    /*
     * This skip indicates either 'unable to query on this machine' or 'not ready this time'.
     *
     * Neither counts as passing, but only the latter has something to fix. If the former is also marked BLOCKED, the suite will
     * always report PARTIAL on such machines, and no one will notice a permanently non-green report when a real issue occurs.
     */
    int notApplicable = 0;
    unsigned long installedId = 0UL;
    int rc = 3;

    /*
     * Skipping the path causes a goto to the installation step, where vrsp has never been written.
     * If not zeroed, it prints status=0—which is exactly OK. A 'nothing
     * tested' state would become a 'passed' one. This line prevents that.
     */
    memset(&vrsp, 0, sizeof(vrsp));

    /* --- 0. Retrieve the status first to determine whether attribution is possible --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }

    /*
     * Capability completeness must be **queried from the backend**; the two backends do not require the same set.
     * If we only check MTF, the EPTP switch backend will incorrectly mark a normal installation as FAIL. The
     * criterion is outdated relative to the target object, representing another form of false positive on this line.
     */
    eptpSwitch =
        (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
    haveCaps =
        ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL) &&
        (eptpSwitch != 0 ||
         (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL);

    if (qrsp.residentProcessorCount != 0UL) {
        reason = "常驻正在跑：外层门会先返回同一个 MULTIPROCESSOR_UNSAFE，"
                 "这一次测不到能力门。先 hvm_ctl stop。";
        goto report;
    }
    if ((qrsp.stateFlags & KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        reason = "EPT_READY 没置位：会先命中 NOT_PREPARED。先 hvm_ctl prepare。";
        goto report;
    }
    if (qrsp.processorCount != 1UL &&
        (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) == 0ULL) {
        /*
         * The two types of 'cannot arm' have completely different consequences and must be separated.
         *
         * The driver requires **both** `INVEPT_SINGLE` **and** `MONITOR_TRAP_FLAG` to arm the private
         * EPT (see `LocalEptArmed` assignment in `hvm_runtime.c`). On machines lacking MTF—nesting
         * All Hyper-V guests lack this bit, so it can never be armed. Consequently, the multi-core safety gate
         * always triggers first, making this test case structurally incapable of attribution on such machines.
         *
         * This isn't 'not ready this time'; it's 'this machine cannot answer this question'. Marking it
         * as BLOCKED would cause the suite to always report PARTIAL, and a report that never turns green
         * is effectively no report: if a real issue arises later, no one would notice the extra line.
         *
         * Conversely, if MTF is present but not armed, it indicates the caller missed sending a bit; this should
         * indeed be BLOCKED—there is something to fix, and without fixing it, the test cannot detect the issue.
         */
        if ((qrsp.featureFlags &
                KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) == 0ULL) {
            reason = "多核 + 本机无 Monitor Trap Flag：私有 EPT 永远武装不上，"
                     "多核安全门必先命中且与能力门同码 —— "
                     "**这台机器上问不出这个问题**，不是这次没准备好。";
            notApplicable = 1;
            goto report;
        }
        reason = "多核且 LOCAL_EPT 未武装（本机有 MTF，可以武装）："
                 "第九道门会先命中，与能力门**同码**，无法归因。"
                 "先跑 prepare-localept。";
        goto report;
    }

    /* --- 1. Back one page of our own memory with a real physical page --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA (this IOCTL has its own protocol version and acknowledgment bit) --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu nt=0x%08lX win32=%lu\n",
                mrsp.status, (unsigned long)mrsp.ntStatus, GetLastError());
        rc = 1;
        goto cleanup;
    }
    physical = mrsp.physicalAddress & ~0xFFFULL;

    /* --- 3. Issue a HOOK view installation. */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    vreq.kind = KSWORD_ARK_HVM_VIEW_KIND_HOOK;
    /* SEED_FROM_TARGET: The shadow copies from the target page, so there is no need to fill 4 KiB manually. */
    vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET;
    vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    vreq.physicalAddress = physical;
    attempted = 1;
    if (viewIoctl(h, &vreq, &vrsp) != 0) { rc = 1; goto cleanup; }

    /* --- 4. Verdict --- */
    if (haveCaps == 0) {
        /* Capability missing: The only possible match is the capability gate; status=9 is attributable. */
        expectation = "status=9 MULTIPROCESSOR_UNSAFE（能力门）";
        if (vrsp.status == KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE) {
            verdict = NEG_PASS;
            reason = "能力门确实是拦路的那一道：既没有 MONITOR_TRAP_FLAG，"
                     "也没有武装 EPTP 切换后端，两个后端都装不上。";
            rc = 0;
        } else {
            verdict = NEG_FAIL;
            reason = "缺能力却没被能力门拒 —— 门序与预期不符，先查代码再下结论。";
            rc = 2;
        }
    } else {
        /* Full capabilities: This machine should truly be able to install it. */
        expectation = "status=0 OK（能力齐全，视图应当装得上）";
        if (vrsp.status == KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            verdict = NEG_PASS;
            installed = 1;
            installedId = vrsp.viewId;
            reason = eptpSwitch
                ? "**EPTP 切换后端在缺 MTF 的机器上把 HOOK 视图装上了。**"
                  "次层次已构造并逐级复核通过。已立即移除。"
                : "**本机不缺 MTF，HOOK 视图真的装上了。**已立即移除。";
            rc = 0;
        } else {
            verdict = NEG_FAIL;
            reason = "能力齐全却装不上 —— 看 status 名字定位是哪一道门。";
            rc = 2;
        }
    }

    /* --- 5. Uninstall immediately after installation; the probe leaves no state --- */
    if (installed != 0) {
        KSWORD_ARK_HVM_VIEW_REQUEST rreq2;
        KSWORD_ARK_HVM_VIEW_RESPONSE rrsp2;
        memset(&rreq2, 0, sizeof(rreq2));
        rreq2.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        rreq2.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        rreq2.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        rreq2.viewId = installedId;
        if (viewIoctl(h, &rreq2, &rrsp2) != 0 ||
            rrsp2.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            /* If unloading is incomplete, report loudly to prevent the next probe from hitting LEAF_CONFLICT. */
            fprintf(stderr,
                    "**视图没能移除**：status=%lu (%s)。请手动 view-query 核对。\n",
                    rrsp2.status, viewStatusName(rrsp2.status));
            rc = 2;
        }
    }

report:
    if (asJson) {
        /*
         * attempted must be present. If empty, the subsequent status fields are zeroed. If the machine
         * criterion checks only status, it will misinterpret "no request was ever sent" as "OK returned."
         */
        printf("{\"kind\":\"view-probe\",\"verdict\":\"%s\",\"attempted\":%s,"
               "\"notApplicable\":%s,"
               "\"processorCount\":%lu,\"residentProcessorCount\":%lu,"
               "\"eptReady\":%s,\"monitorTrapFlag\":%s,\"inveptSingle\":%s,"
               "\"localEptArmed\":%s,\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"installed\":%s,"
               "\"expected\":\"%s\",\"reason\":\"%s\"}\n",
               negName(verdict), attempted ? "true" : "false",
               notApplicable ? "true" : "false",
               qrsp.processorCount, qrsp.residentProcessorCount,
               ((qrsp.stateFlags & KSWORD_ARK_HVM_STATE_EPT_READY) != 0UL)
                   ? "true" : "false",
               ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL)
                   ? "true" : "false",
               ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL)
                   ? "true" : "false",
               ((qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) != 0ULL)
                   ? "true" : "false",
               vrsp.status, viewStatusName(vrsp.status),
               (unsigned long)vrsp.lastStatus,
               installed ? "true" : "false",
               expectation, reason);
    } else {
        printf("\n=== view-probe（分离视图安装期归因）===\n");
        printf("  处理器       : total=%lu resident=%lu\n",
               qrsp.processorCount, qrsp.residentProcessorCount);
        printViewPrerequisites("  ", qrsp.featureFlags);
        if (verdict == NEG_VOID && notApplicable) {
            printf("  [不适用] 这台机器上**问不出**这个问题\n");
            printf("         %s\n", reason);
        } else if (verdict == NEG_VOID) {
            printf("  [空过] 这一次**测不到**能力门\n");
            printf("         %s\n", reason);
        } else {
            printf("  [%-4s] status=%lu (%s) lastStatus=0x%08lX\n",
                   negName(verdict), vrsp.status, viewStatusName(vrsp.status),
                   (unsigned long)vrsp.lastStatus);
            printf("         期望：%s\n", expectation);
            printf("         %s\n", reason);
        }
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    /*
     * Exit code 4 = this machine cannot query this issue, separated from 3 (not ready this time).
     *
     * The reason for separating them is not aesthetics: 3 means 'something needs fixing', 4 means 'nothing can be
     * fixed'. Merging them would cause the suite to always report PARTIAL on machines without MTF, and a report that
     * never turns green is equivalent to no report at all—the extra line added when a real issue occurs will be ignored.
     */
    if (rc == 3 && notApplicable) {
        rc = 4;
    }
    return rc;
}

/*
 * view-effect: End-to-end criterion for whether the detached view is actually effective.
 *
 * All previous probes answer 'whether it can be installed'. This one answers 'after
 * installation, does a real access retrieve shadow content?' — this is the true purpose of
 * CLOAK/HOOK and the only metric that cannot be fooled by 'installed but useless' scenarios.
 *
 * Approach: Write 0xA5 to the true page, install a **CLOAK** view and zero out the shadow (CLOAK semantics: execute sees
 * true page, read/write sees shadow), make it resident, then **have the driver read** the physical address of that page.
 *
 *   Reading 0x00 indicates a switch occurred and the view is now effective.
 *   If 0xA5 is read → a real page was read; no switch occurred (installed but unused).
 *   Resident removed → fail-closed triggered (scheduler rejected, or forward-progress ledger determined it lacks forward progress).
 *
 * The driver must perform the read instead of accessing page[0] directly here, for the same reason as probe-xonly:
 * A fail-closed de-virtualization returns at the **same privilege level**: user-mode triggers return with ring-3
 * RSP/RIP on ring 0, causing an immediate BSOD. When using OP_READ_PHYSICAL, the actual access occurs within the
 * driver's kernel-mode window, hitting the same leaf, while de-virtualization returns to the kernel context.
 *
 * Precondition: The caller must run prepare-eptpsw and self-test first. This command starts and stops the resident
 * hypervisor itself because the page belongs to this process and must remain alive until resident startup.
 */
/* Defined later; view-effect must be used immediately after installing the view to generate the leaf. */
static int doEptLeaf(HANDLE h, unsigned long long target, int asJson);
/*
 * Defined later. view-effect runs an **add-after-self-check** at the exact moment the view is still attached and resident
 * in memory — this is the only window where both layers of view-verify can be truly tested. Installing a persistent view
 * via CLI is unsafe (after the process exits, that page is freed, leaving the view pointing to released memory).
 */
static int doViewVerify(HANDLE h, int asJson);

static int doViewEffect(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    DWORD returned = 0;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long viewId = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned char observed = 0U;
    int installed = 0;
    int started = 0;
    int probed = 0;
    int readFailed = 0;
    int eptpSwitch = 0;
    const char* verdictText = "未判定";
    int rc = 3;

    memset(&vrsp, 0, sizeof(vrsp));
    /* --- 0. Precondition: prepare has completed and the resident hypervisor is not running --- */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    eptpSwitch =
        (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;
    if (qrsp.residentProcessorCount != 0UL) {
        verdictText = "常驻正在跑：视图表不可变，装不上。先 stop。";
        goto report;
    }
    if ((qrsp.stateFlags & KSWORD_ARK_HVM_STATE_EPT_READY) == 0UL) {
        verdictText = "EPT_READY 没置位。先 prepare-eptpsw。";
        goto report;
    }

    /* --- 1. True page write flag --- */
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;

    /* --- 2. VA -> PA --- */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu nt=0x%08lX\n",
                mrsp.status, (unsigned long)mrsp.ntStatus);
        rc = 1;
        goto cleanup;
    }
    physical = mrsp.physicalAddress & ~0xFFFULL;

    /* --- 3. Install CLOAK view; shadow filled with zeros --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    vreq.kind = KSWORD_ARK_HVM_VIEW_KIND_CLOAK;
    vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO;
    vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    vreq.physicalAddress = physical;
    if (viewIoctl(h, &vreq, &vrsp) != 0) { rc = 1; goto cleanup; }
    if (vrsp.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        verdictText = "视图装不上，这一项测不到生效与否。";
        rc = 3;
        goto report;
    }
    installed = 1;
    viewId = vrsp.viewId;
    /*
     * Immediately output the leaf from the base after installation.
     *
     * This step answers the question that cannot be answered elsewhere: ADD reported success, but **did the leaf actually change**?
     * The failure mode "installed but not effective" has two entirely different causes (the leaf was never restricted
     * / the leaf was restricted but that access did not reach it), yet they appear identical in the final reading.
     */
    if (!asJson) {
        (void)doEptLeaf(h, physical, 0);
    }

    /* --- 4. Start resident: EPT enforcement begins only after the view is installed --- */
    if (!probeControl(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                      KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                      KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                      KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED,
                      "START_RESIDENT")) {
        verdictText = "常驻起不来，这一项测不到生效与否。";
        rc = 3;
        goto cleanup_view;
    }
    started = 1;

    /* --- 5. Instruct the driver to read that page. */
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = physical;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL)) {
        fprintf(stderr, "READ_PHYSICAL 未返回：win32=%lu\n", GetLastError());
        goto cleanup_view;
    }
    if (mrsp.status == KSWORD_ARK_HVM_MEMORY_STATUS_OK &&
        mrsp.bytesTransferred >= 1UL) {
        observed = mrsp.data[0];
    } else {
        readFailed = 1;
    }
    probed = 1;
    /* The view is still installed and the resident hypervisor is running; this is the only opportunity for the post-addition self-test to test both layers. */
    if (!asJson) {
        (void)doViewVerify(h, 0);
    }
    /*
     * These two fields determine whether this read actually passed through the leaf page we modified.
     *
     * resolvedPhysical differs from target ⇒ the read actually accesses a different page;
     * usedDirectWindow ⇒ Uses the driver's private page table window. The mapping mechanism here differs from
     * standard kernel access; 'no violation triggered' may simply mean it bypassed this leaf entry, not that
     * EPT is inactive. Without these two readings, the two causes are indistinguishable in the final result.
     */
    if (!asJson) {
        printf("  读实际解析到 : 0x%016llX   （目标 0x%016llX）\n",
               mrsp.physicalAddress, physical);
        printf("  私有窗口     : usedDirectWindow=%u windowReady=%u\n",
               (unsigned)mrsp.usedDirectWindow, (unsigned)mrsp.windowReady);
    }

    /* --- 6. Whether the resident component is still present is a criterion as important as the read-back value. */
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                        &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        residentAfter = qrsp.residentProcessorCount;
    } else {
        probed = 0;
    }

    /* --- 7. Verdict --- */
    if (!probed) {
        verdictText = "读后查询失败，无法判定。";
        rc = 3;
    } else if (residentAfter == 0UL) {
        verdictText = "**常驻掉了** —— 走了 fail-closed："
                      "规划器拒绝，或前进性台账判这次切换不前进。";
        rc = 2;
    } else if (readFailed) {
        verdictText = "常驻还在但读失败了，语义不明，按未通过处理。";
        rc = 2;
    } else if (observed == 0x00U) {
        verdictText = "**视图生效**：读回影子内容（0x00），真页的 0xA5 没有泄露，"
                      "且常驻全程未掉 —— EPTP 切换真的服务了这次违规。";
        rc = 0;
    } else if (observed == 0xA5U) {
        verdictText = "**视图没生效**：读回真页的 0xA5。"
                      "装上了但那次读没有被重定向到影子。";
        rc = 2;
    } else {
        verdictText = "读回一个既不是影子也不是真页的值，判未通过。";
        rc = 2;
    }

cleanup_view:
    if (started) {
        (void)probeControl(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                           KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED,
                           "STOP_RESIDENT");
        started = 0;
    }
    if (installed) {
        KSWORD_ARK_HVM_VIEW_REQUEST rreq2;
        KSWORD_ARK_HVM_VIEW_RESPONSE rrsp2;
        memset(&rreq2, 0, sizeof(rreq2));
        rreq2.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        rreq2.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        rreq2.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        rreq2.viewId = viewId;
        if (viewIoctl(h, &rreq2, &rrsp2) != 0 ||
            rrsp2.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
            fprintf(stderr, "**视图没能移除**：status=%lu (%s)\n",
                    rrsp2.status, viewStatusName(rrsp2.status));
            rc = 2;
        }
        installed = 0;
    }

report:
    if (asJson) {
        printf("{\"kind\":\"view-effect\",\"eptpSwitchArmed\":%s,"
               "\"installed\":%s,\"probed\":%s,\"readFailed\":%s,"
               "\"observedByte\":%u,\"residentAfter\":%lu,"
               "\"physicalAddress\":\"0x%016llX\",\"exitCode\":%d,"
               "\"verdict\":\"%s\"}\n",
               eptpSwitch ? "true" : "false",
               probed ? "true" : "false",
               probed ? "true" : "false",
               readFailed ? "true" : "false",
               (unsigned)observed, residentAfter, physical, rc, verdictText);
    } else {
        printf("\n=== view-effect（分离视图是否真的生效）===\n");
        printf("  后端         : %s\n",
               eptpSwitch ? "EPTP 切换" : "写叶 + monitor-trap");
        printf("  物理页       : 0x%016llX\n", physical);
        printf("  读回字节     : 0x%02X   （影子=0x00，真页=0xA5）\n",
               (unsigned)observed);
        printf("  读后常驻数   : %lu   （0 表示走了 fail-closed）\n",
               residentAfter);
        printf("  判定         : %s\n", verdictText);
    }

cleanup:
    if (page != NULL) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        (void)VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
    return rc;
}

/*
 * ept-leaf <physical_address>: Walk through the EPT from user mode and print each of the four levels.
 *
 * The rationale for this reading is that the same value is repeatedly missing: 'the rule/view is installed' and 'that leaf is
 * actually restricted' are two different things, and the protocol only answers the former (the deniedAccess in the ADD response is
 * a **normalized request**, not the leaf's current value). Without this reading, 'installed but not effective' can only be guessed.
 *
 * No driver modification required: The EPT table is allocated as normal guest physical memory and identity-mapped as
 * RWX, so existing OP_READ_PHYSICAL can be used to read it. The root address is retrieved from eptPointer in the status.
 *
 * The read value is at the **base** level. The secondary level after EPTP switching is not on
 * this chain (by design), so this command answers what this page in the base currently allows.
 */
static int doEptLeaf(HANDLE h, unsigned long long target, int asJson)
{
    static const char* const kLevelName[4] = { "PML4", "PDPT", "PD  ", "PT  " };
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;
    unsigned long long table = 0ULL;
    unsigned long long entry = 0ULL;
    unsigned long long entries[4];
    unsigned long indices[4];
    int level = 0;
    int large = 0;
    int ok = 1;

    memset(entries, 0, sizeof(entries));
    memset(indices, 0, sizeof(indices));
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (qrsp.eptPointer == 0ULL) {
        fprintf(stderr, "eptPointer 为零：EPT 还没建好，先 prepare。\n");
        return 3;
    }
    /* Extract only the root address; the lower 12 bits contain fields for memory type, level, AD, etc. */
    table = qrsp.eptPointer & 0x000FFFFFFFFFF000ULL;
    indices[0] = (unsigned long)((target >> 39) & 0x1FFULL);
    indices[1] = (unsigned long)((target >> 30) & 0x1FFULL);
    indices[2] = (unsigned long)((target >> 21) & 0x1FFULL);
    indices[3] = (unsigned long)((target >> 12) & 0x1FFULL);

    for (level = 0; level < 4; ++level) {
        memset(&mreq, 0, sizeof(mreq));
        memset(&mrsp, 0, sizeof(mrsp));
        mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
        mreq.size = (unsigned long)sizeof(mreq);
        mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
        mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
        mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
        mreq.address = table + ((unsigned long long)indices[level] * 8ULL);
        mreq.length = 8UL;
        if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                             &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
            mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
            mrsp.bytesTransferred < 8UL) {
            fprintf(stderr, "读第 %d 级失败：status=%lu nt=0x%08lX\n",
                    level, mrsp.status, (unsigned long)mrsp.ntStatus);
            ok = 0;
            break;
        }
        entry = 0ULL;
        {
            int b = 0;
            for (b = 7; b >= 0; --b) {
                entry = (entry << 8) | (unsigned long long)mrsp.data[b];
            }
        }
        entries[level] = entry;
        /* An entry of zero indicates no mapping at this level; proceeding further is meaningless. */
        if (entry == 0ULL) { break; }
        /* Large pages are marked with bit7 on PDPT/PD; stop immediately upon a match. */
        if (level >= 1 && level <= 2 && (entry & 0x80ULL) != 0ULL) {
            large = 1;
            break;
        }
        table = entry & 0x000FFFFFFFFFF000ULL;
    }

    if (asJson) {
        printf("{\"kind\":\"ept-leaf\",\"target\":\"0x%016llX\","
               "\"eptPointer\":\"0x%016llX\",\"largePage\":%s,\"levels\":[",
               target, qrsp.eptPointer, large ? "true" : "false");
        for (level = 0; level < 4; ++level) {
            printf("%s{\"level\":\"%s\",\"index\":%lu,\"entry\":\"0x%016llX\","
                   "\"r\":%s,\"w\":%s,\"x\":%s}",
                   level == 0 ? "" : ",",
                   kLevelName[level], indices[level], entries[level],
                   (entries[level] & 1ULL) ? "true" : "false",
                   (entries[level] & 2ULL) ? "true" : "false",
                   (entries[level] & 4ULL) ? "true" : "false");
        }
        printf("],\"ok\":%s}\n", ok ? "true" : "false");
        return ok ? 0 : 1;
    }
    printf("\n=== EPT 叶（基座层次）===\n");
    printf("  目标 GPA     : 0x%016llX\n", target);
    printf("  eptPointer   : 0x%016llX\n", qrsp.eptPointer);
    for (level = 0; level < 4; ++level) {
        printf("  %s [%3lu] = 0x%016llX   R=%d W=%d X=%d%s\n",
               kLevelName[level], indices[level], entries[level],
               (entries[level] & 1ULL) ? 1 : 0,
               (entries[level] & 2ULL) ? 1 : 0,
               (entries[level] & 4ULL) ? 1 : 0,
               (level >= 1 && level <= 2 && (entries[level] & 0x80ULL))
                   ? "   <大页，到此为止>" : "");
        if (entries[level] == 0ULL) { break; }
        if (level >= 1 && level <= 2 && (entries[level] & 0x80ULL)) { break; }
    }
    return ok ? 0 : 1;
}

/*
 * Retrieve the leaf entry value at the **base** level for a single page. The no-output version of doEptLeaf.
 *
 * It uses OP_READ_PHYSICAL: the EPT table is allocated by the driver and identity-mapped as RWX
 * normal guest physical memory, so user mode can read it. Return 0 indicates a successful read.
 */
static int eptLeafEntry(HANDLE h, unsigned long long target,
                        unsigned long long* entry)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;
    unsigned long long table = 0ULL;
    unsigned long long value = 0ULL;
    unsigned long idx[4];
    int level = 0;

    if (entry == NULL) { return 1; }
    *entry = 0ULL;
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL) ||
        qrsp.eptPointer == 0ULL) {
        return 1;
    }
    table = qrsp.eptPointer & 0x000FFFFFFFFFF000ULL;
    idx[0] = (unsigned long)((target >> 39) & 0x1FFULL);
    idx[1] = (unsigned long)((target >> 30) & 0x1FFULL);
    idx[2] = (unsigned long)((target >> 21) & 0x1FFULL);
    idx[3] = (unsigned long)((target >> 12) & 0x1FFULL);
    for (level = 0; level < 4; ++level) {
        int b = 0;
        memset(&mreq, 0, sizeof(mreq));
        memset(&mrsp, 0, sizeof(mrsp));
        mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
        mreq.size = (unsigned long)sizeof(mreq);
        mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
        mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
        mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
        mreq.address = table + ((unsigned long long)idx[level] * 8ULL);
        mreq.length = 8UL;
        if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                             &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
            mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
            mrsp.bytesTransferred < 8UL) {
            return 1;
        }
        value = 0ULL;
        for (b = 7; b >= 0; --b) {
            value = (value << 8) | (unsigned long long)mrsp.data[b];
        }
        if (value == 0ULL) { return 1; }
        /* Huge page: This is not a level-4 leaf; the caller's expectation is invalid. */
        if (level >= 1 && level <= 2 && (value & 0x80ULL) != 0ULL) { return 1; }
        if (level == 3) { break; }
        table = value & 0x000FFFFFFFFFF000ULL;
    }
    *entry = value;
    return 0;
}

/* Read the first byte of a page; return 0 on success. */
static int readPhysicalByte(HANDLE h, unsigned long long physical,
                            unsigned char* value)
{
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;

    if (value == NULL) { return 1; }
    *value = 0U;
    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = physical;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
        mrsp.bytesTransferred < 1UL) {
        return 1;
    }
    *value = mrsp.data[0];
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Self-check                                                                       */
/* ------------------------------------------------------------------------ */

/*
 * Three states, consistent with elsewhere: capability satisfied / not satisfied / **no distinguishing power**.
 *
 * The third state is the key focus here. If a self-check item reports OK even when its prerequisites are not established,
 * the all-green result only indicates it was never queried. We have repeatedly suffered from this on this line.
 */
#define SC_OK    0
#define SC_BLOCK 1
#define SC_VOID  2
/*
 * State 4: **Info**. Neither pass nor fail, but a fact determining the next path.
 *
 * Added because hard-coding the Monitor Trap Flag into a pass/fail binary state creates a false criterion.
 * This machine lacks MTF, yet the EPTP switching backend successfully installed and verified the view. Reporting
 * it as 'blocked' would make a fully functional machine appear unusable. 'Appearing unusable while actually
 * functional' and 'appearing functional while actually unusable' are two sides of the same underlying issue.
 */
#define SC_INFO  3

typedef struct ScItem
{
    const char* name;
    int state;
    const char* detail;   /* Why and what can be done. Do not return only status codes. */
} ScItem;

static const char* scName(int s)
{
    switch (s) {
    case SC_OK:    return "OK";
    case SC_BLOCK: return "阻塞";
    case SC_VOID:  return "未标定";
    default:       return "信息";
    }
}

/*
 * Pre-use self-test: Determine whether this machine can perform the requested operation and whether its current state is clean.
 *
 * Read-only: QUERY_HVM + PLATFORM. Neither enters VMX, nor allocates resources, nor modifies any execution path.
 * Split into two groups: capabilities (whether the machine supports them) and status (whether it is currently ready to work)—because their remediation
 * methods are completely different: insufficient capabilities require changing the machine or backend, while a dirty status can be fixed by stop/teardown.
 */
static int doSelfCheck(HANDLE h, int asJson)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    KSWORD_ARK_HVM_PLATFORM_REQUEST preq;
    KSWORD_ARK_HVM_PLATFORM_RESPONSE prsp;
    DWORD returned = 0;
    ScItem items[16];
    unsigned long count = 0UL;
    unsigned long blocked = 0UL;
    unsigned long voided = 0UL;
    unsigned long i = 0UL;
    int platformOk = 0;
    int mtf = 0;
    int execOnly = 0;
    int inveptSingle = 0;
    int eptpArmed = 0;
    const char* backend = "两个后端都不可用";

    memset(items, 0, sizeof(items));
    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu —— 驱动没加载？\n",
                GetLastError());
        return 1;
    }
    if (qrsp.backend == KSWORD_ARK_HVM_BACKEND_SVM) {
        int ready = qrsp.queryStatus == KSWORD_ARK_HVM_QUERY_STATUS_OK &&
            (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED) != 0;
        if (asJson) {
            printf("{\"kind\":\"selfcheck\",\"backend\":\"SVM\",\"capabilityReady\":%s,\"prepared\":%lu,\"tested\":%lu,\"resident\":%lu,\"lastStatus\":\"0x%08lX\"}\n",
                   ready ? "true" : "false", qrsp.preparedProcessorCount, qrsp.selfTestPassedProcessorCount,
                   qrsp.residentProcessorCount, qrsp.backendStatus);
        } else {
            printf("Experimental SVM/NPT: capability=%d prepared=%lu tested=%lu resident=%lu status=0x%08lX\n",
                   ready, qrsp.preparedProcessorCount, qrsp.selfTestPassedProcessorCount, qrsp.residentProcessorCount, qrsp.backendStatus);
        }
        return ready ? 0 : 2;
    }
    memset(&preq, 0, sizeof(preq));
    memset(&prsp, 0, sizeof(prsp));
    /*
     * The PLATFORM has its own protocol version, not the generic one. Using the wrong
     * one causes the version check to fail, which looks identical to 'register read
     * failure'. MEMORY IOCTL has the same pitfall; we've already encountered it here.
     */
    preq.version = KSWORD_ARK_HVM_PLATFORM_PROTOCOL_VERSION;
    preq.size = (unsigned long)sizeof(preq);
    platformOk =
        DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_PLATFORM, &preq, sizeof(preq),
                        &prsp, (DWORD)sizeof(prsp), &returned, NULL) &&
        returned >= sizeof(prsp);

    mtf = (qrsp.featureFlags &
           KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG) != 0ULL;
    inveptSingle = (qrsp.featureFlags &
           KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE) != 0ULL;
    execOnly = (qrsp.vmxEptVpidCapabilities & 1ULL) != 0ULL;
    eptpArmed = (qrsp.featureFlags &
           KSWORD_ARK_HVM_FEATURE_EPTP_SWITCH_ARMED) != 0ULL;

    /* ---- Group 1: Capabilities (whether the machine provides them) ---- */
    items[count].name = "VMX 可用";
    items[count].state = (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_VMX)
        ? SC_OK : SC_BLOCK;
    items[count].detail = (qrsp.featureFlags & KSWORD_ARK_HVM_FEATURE_VMX)
        ? "CPUID 报告 VT-x"
        : "CPUID 里没有 VT-x。注意：常驻期间驱动会按设计抹掉这一位，"
          "所以先确认常驻没在跑（本自检下面有这一项）";
    count++;

    items[count].name = "EPT + 四级页遍历";
    items[count].state =
        ((qrsp.featureFlags & (KSWORD_ARK_HVM_FEATURE_EPT |
                               KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL)) ==
         (KSWORD_ARK_HVM_FEATURE_EPT | KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL))
        ? SC_OK : SC_BLOCK;
    items[count].detail = "分离视图与 EPT 规则都建立在四级 EPT 上";
    count++;

    items[count].name = "INVEPT single-context";
    items[count].state = inveptSingle ? SC_OK : SC_BLOCK;
    items[count].detail = inveptSingle
        ? "两个分离视图后端都需要它，用来丢弃被换掉那一侧的翻译"
        : "缺它则任何一个后端都无法保证换过去之后旧翻译不再被使用";
    count++;

    items[count].name = "execute-only EPT 叶";
    items[count].state = execOnly ? SC_OK : SC_BLOCK;
    items[count].detail = execOnly
        ? "IA32_VMX_EPT_VPID_CAP bit0 置位：CLOAK 可编码，EPTP 切换后端可用"
        : "缺它 CLOAK 的主值不得不放开读，什么也藏不住；"
          "EPTP 切换后端也整体不可用（它对 CLOAK 与 HOOK 一视同仁地要求这一位）";
    count++;

    /*
     * MTF is **information**, not a criterion: it determines which backend to use, not whether it can be used.
     * The actual gate is the available disaggregated view backend listed below.
     */
    items[count].name = "Monitor Trap Flag";
    items[count].state = SC_INFO;
    items[count].detail = mtf
        ? "有：默认「写叶 + 单步」后端可用"
        : "没有（嵌套 Hyper-V 不向客户机通告它）。**这不阻塞** —— "
          "EPTP 切换后端不需要 MTF，用 prepare 时请求那个后端即可";
    count++;

    /* ---- Backend availability: Synthesize the above items into an executable conclusion ---- */
    if (inveptSingle && mtf) { backend = "写叶 + monitor-trap（默认）"; }
    if (inveptSingle && execOnly) {
        backend = mtf ? "两个都可用（默认后端 / EPTP 切换）" : "仅 EPTP 切换";
    }
    items[count].name = "可用的分离视图后端";
    items[count].state = (inveptSingle && (mtf || execOnly)) ? SC_OK : SC_BLOCK;
    items[count].detail = backend;
    count++;

    items[count].name = "当前武装的后端";
    items[count].state = SC_OK;
    items[count].detail = eptpArmed
        ? "EPTP 切换（已武装）"
        : "写叶 + monitor-trap（默认）。要换成 EPTP 切换必须在 PREPARE 时请求 —— "
          "已经 prepare 过的运行时改开关不会生效，要先 teardown";
    count++;

    /* ---- Group two: State (whether work can start now) ---- */
    {
        const int kFaulted =
            (qrsp.stateFlags & KSWORD_ARK_HVM_STATE_FAULTED) != 0UL;
        const int kRollback =
            (qrsp.stateFlags & KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0UL;
        items[count].name = "无 FAULTED / ROLLBACK_REQUIRED";
        items[count].state = (kFaulted || kRollback) ? SC_BLOCK : SC_OK;
        items[count].detail = (kFaulted || kRollback)
            ? "状态里带故障位，START_RESIDENT 会被直接拒。先 reset-fault"
            : "状态干净";
        count++;
    }

    items[count].name = "常驻未在跑";
    items[count].state = (qrsp.residentProcessorCount == 0UL)
        ? SC_OK : SC_BLOCK;
    items[count].detail = (qrsp.residentProcessorCount == 0UL)
        ? "视图表与规则表可改"
        : "常驻期间视图表与规则表**不可变**（退出路径不取那把锁就读它们）。"
          "装视图/规则的顺序只能是 prepare → 装 → START_RESIDENT。先 stop";
    count++;

    /*
     * processorCount is 0 **before** PREPARE: the driver has not counted processors at that time.
     * Using an uninitialized field to check `!= 1` would misclassify 'not yet tested' as 'blocked', which is a recurring
     * pattern of false positives/misses on this line. Therefore, first distinguish whether a test has been performed.
     */
    items[count].name = "单处理器拓扑或已武装私有 EPT";
    if (qrsp.processorCount == 0UL) {
        items[count].state = SC_VOID;
        items[count].detail = "PREPARE 之前驱动还没数处理器，这一项**这次没测到**。"
                              "prepare 之后再跑一次自检";
    } else if (qrsp.processorCount == 1UL ||
               (qrsp.featureFlags &
                    KSWORD_ARK_HVM_FEATURE_LOCAL_EPT_ARMED) != 0ULL) {
        items[count].state = SC_OK;
        items[count].detail = (qrsp.processorCount == 1UL)
            ? "1 vCPU：多核安全门不触发"
            : "多核，但私有 EPT 层次已武装";
    } else {
        items[count].state = SC_BLOCK;
        items[count].detail = "多核且没有私有 EPT 层次：视图安装会被拒"
                              "（翻转窗口对别的处理器可见）";
    }
    count++;

    /* ---- Group 3: Platform calibration (report as uncalibrated if unreadable, do not guess)---- */
    if (!platformOk || prsp.validMask != KSW_PLATFORM_VALID_ALL) {
        items[count].name = "平台标定（CET / KVA shadow / GS base）";
        items[count].state = SC_VOID;
        items[count].detail = "PLATFORM 探针没能读全八个字段。"
            "这一项**不算通过也不算失败** —— 没标定的量不能拿来下结论";
        count++;
    } else {
        const int kCet = (prsp.cr4 & (1ULL << 23)) != 0ULL;
        items[count].name = "CET（CR4 bit23）";
        items[count].state = SC_OK;
        items[count].detail = kCet
            ? "开着。注意：CR4.CET=1 时任何清 CR0.WP 的老式改内存写法都会吃 #GP"
            : "关着";
        count++;
    }

    /* ---- Summary ---- */
    for (i = 0UL; i < count; ++i) {
        if (items[i].state == SC_BLOCK) { blocked++; }
        if (items[i].state == SC_VOID)  { voided++; }
    }

    if (asJson) {
        printf("{\"kind\":\"selfcheck\",\"blocked\":%lu,\"void\":%lu,"
               "\"backend\":\"%s\",\"items\":[", blocked, voided, backend);
        for (i = 0UL; i < count; ++i) {
            printf("%s{\"name\":\"%s\",\"state\":\"%s\",\"detail\":\"%s\"}",
                   (i == 0UL) ? "" : ",",
                   items[i].name, scName(items[i].state), items[i].detail);
        }
        printf("]}\n");
    } else {
        printf("\n=== 使用前自检（只读，不进 VMX）===\n");
        for (i = 0UL; i < count; ++i) {
            printf("  [%-6s] %s\n", scName(items[i].state), items[i].name);
            printf("           %s\n", items[i].detail);
        }
        printf("\n  阻塞 %lu 项，未标定 %lu 项。\n", blocked, voided);
        if (blocked == 0UL) {
            printf("  可以开工。分离视图后端：%s\n", backend);
        }
    }
    /* Return 2 if blocked; return 3 if only voided; return 0 if all good. */
    return (blocked != 0UL) ? 2 : ((voided != 0UL) ? 3 : 0);
}

/*
 * Post-add self-check: iterate through each installed view to answer two **distinct** questions.
 *
 * The two-layer design isn't for granularity; it's because real-world tests showed they can return contradictory answers.
 * When a shared EPT root does not invalidate across residency boundaries, the leaf is correctly written with the primary value (struct
 * pair) while the processor continues using the old translation (completely ineffective). Combining these two conditions into a single
 * "view is normal" status creates exactly the worst-case failure for this project: installed, reporting green, yet completely useless.
 *
 *   Structure: Does the leaf in the base hierarchy contain this view's primary value? This can be checked even when the resident hypervisor is stopped.
 *   Effectiveness: Was a real access actually redirected? This is meaningful only while the resident hypervisor **is running**.
 *
 * This layer only distinguishes CLOAK: CLOAK redirects **reads** to the shadow, while we can only initiate reads.
 * The HOOK redirects instruction fetches. Reads should naturally see the true page; using a read to verify a HOOK yields a false
 * "not active" conclusion. Therefore, explicitly report "no distinguishing power" instead of providing an incorrect judgment.
 */
static int doViewVerify(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;
    unsigned long i = 0UL;
    unsigned long bad = 0UL;
    unsigned long voidCount = 0UL;
    int residentRunning = 0;

    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        fprintf(stderr, "QUERY_HVM 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    residentRunning = (qrsp.residentProcessorCount != 0UL);

    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_QUERY;
    if (viewIoctl(h, &vreq, &vrsp) != 0) { return 1; }
    if (vrsp.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        fprintf(stderr, "VIEW QUERY 返回 %lu (%s)\n",
                vrsp.status, viewStatusName(vrsp.status));
        return 1;
    }

    if (!asJson) {
        printf("\n=== 添加后自检：已安装视图 %lu 条 ===\n", vrsp.returnedRows);
        printf("  常驻状态 : %s\n", residentRunning
            ? "在跑 —— 生效层可测"
            : "**没在跑** —— 生效层这次无区分力（没有 EPT 强制，读当然看到真页）");
    } else {
        printf("{\"kind\":\"view-verify\",\"resident\":%s,\"rows\":[",
               residentRunning ? "true" : "false");
    }

    for (i = 0UL; i < vrsp.returnedRows && i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
        const KSWORD_ARK_HVM_VIEW_ROW* row = &vrsp.rows[i];
        unsigned long long leaf = 0ULL;
        int structOk = 0;
        int structKnown = (eptLeafEntry(h, row->physicalAddress, &leaf) == 0);
        const char* structText = "叶读不到（页可能仍是 2MiB 大页，或表已变）";
        const char* effectText = "";
        int effectState = SC_VOID;
        unsigned char viaEpt = 0U;
        unsigned char viaShadow = 0U;

        if (structKnown) {
            const int kR = (leaf & 1ULL) != 0ULL;
            const int kW = (leaf & 2ULL) != 0ULL;
            const int kX = (leaf & 4ULL) != 0ULL;
            const unsigned long long kFrame = leaf & 0x000FFFFFFFFFF000ULL;
            if (row->kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
                structOk = (!kR && !kW && kX &&
                            kFrame == (row->physicalAddress &
                                      0x000FFFFFFFFFF000ULL));
                structText = structOk
                    ? "叶 = execute-only 指向真页：CLOAK 主值，正确"
                    : "叶不是 CLOAK 的主值（应为 execute-only 指向真页）";
            } else {
                structOk = (kR && kW && !kX &&
                            kFrame == (row->physicalAddress &
                                      0x000FFFFFFFFFF000ULL));
                structText = structOk
                    ? "叶 = RW 指向真页、拒绝执行：HOOK 主值，正确"
                    : "叶不是 HOOK 的主值（应为 RW 指向真页且不可执行）";
            }
        }

        /* ---- Effect Layer ---- */
        if (!residentRunning) {
            effectState = SC_VOID;
            effectText = "常驻没在跑，没有 EPT 强制 —— 这次测不到";
        } else if (row->kind != KSWORD_ARK_HVM_VIEW_KIND_CLOAK) {
            effectState = SC_VOID;
            effectText = "HOOK 重定向的是取指，用读验不出来 —— **无区分力**，"
                         "不是没生效";
        } else if (readPhysicalByte(h, row->physicalAddress, &viaEpt) != 0 ||
                   readPhysicalByte(h, row->shadowPhysicalAddress,
                                    &viaShadow) != 0) {
            effectState = SC_VOID;
            effectText = "读失败，判不了";
        } else if (viaEpt == viaShadow) {
            /*
             * Equality serves as evidence only when "shadow and real page contents were already different".
             * If the shadow is copied from the target page (SEED_FROM_TARGET), both sides are inherently
             * identical; equality proves nothing here. Must report 'no distinction' instead of passing.
             */
            if ((row->flags &
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET) != 0UL) {
                effectState = SC_VOID;
                effectText = "读回值与影子相同，但影子是从目标页拷来的，"
                             "两者本就一样 —— **无区分力**";
            } else {
                effectState = SC_OK;
                effectText = "读被重定向到影子（读回值 == 影子内容）";
            }
        } else {
            effectState = SC_BLOCK;
            effectText = "读回的**不是**影子内容 —— 重定向没有发生";
        }

        if (!structOk) { bad++; }
        if (effectState == SC_BLOCK) { bad++; }
        if (effectState == SC_VOID) { voidCount++; }

        if (asJson) {
            printf("%s{\"viewId\":%lu,\"kind\":\"%s\","
                   "\"physicalAddress\":\"0x%016llX\",\"leaf\":\"0x%016llX\","
                   "\"structOk\":%s,\"effect\":\"%s\",\"flips\":%llu}",
                   (i == 0UL) ? "" : ",",
                   row->viewId, viewKindName(row->kind),
                   row->physicalAddress, leaf,
                   structOk ? "true" : "false",
                   scName(effectState), row->flipCount);
        } else {
            printf("\n  #%-3lu %-5s pa=0x%016llX flips=%llu\n",
                   row->viewId, viewKindName(row->kind),
                   row->physicalAddress, row->flipCount);
            printf("    结构 [%-6s] %s\n",
                   structKnown ? (structOk ? "OK" : "阻塞") : "未标定",
                   structText);
            printf("    生效 [%-6s] %s\n", scName(effectState), effectText);
        }
    }

    if (asJson) {
        printf("],\"bad\":%lu,\"void\":%lu}\n", bad, voidCount);
    } else {
        if (vrsp.returnedRows == 0UL) {
            printf("  （没有已安装的视图，这次什么都没测到）\n");
        }
        printf("\n  不合格 %lu 项，无区分力 %lu 项。\n", bad, voidCount);
    }
    if (vrsp.returnedRows == 0UL) { return 3; }
    return (bad != 0UL) ? 2 : ((voidCount != 0UL) ? 3 : 0);
}

/*
 * CR Policy: Here, we perform only the one task required for R-1 process handling—enabling or disabling CR3 tracing.
 *
 * Do not perform cr0/cr4 pinning: that is a different class of operation. A wrong mask write could prevent the guest from ever modifying a
 * specific control register bit. This tool's purpose is to run a single verification command on the target machine, not to configure policies.
 */
static const char* crPolicyStatusName(unsigned long s)
{
    switch (s) {
    case 0UL:  return "OK";
    default:   return "NOT_OK";
    }
}

static int doCrTrackCr3(HANDLE h, int enable, int asJson)
{
    KSWORD_ARK_HVM_CR_POLICY_REQUEST req;
    KSWORD_ARK_HVM_CR_POLICY_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_CR_POLICY_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = enable
        ? KSWORD_ARK_HVM_CR_POLICY_OP_SET
        : KSWORD_ARK_HVM_CR_POLICY_OP_CLEAR;
    req.flags = KSWORD_ARK_HVM_CR_POLICY_FLAG_UI_CONFIRMED |
        (enable ? KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3 : 0UL);
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_CR_POLICY, &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        fprintf(stderr, "CR_POLICY IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"cr-track-cr3\",\"enable\":%d,\"status\":%lu,"
               "\"flags\":%lu,\"generation\":%lu,\"cr3SwitchCount\":%llu}\n",
               enable, rsp.status, rsp.flags, rsp.generation, rsp.cr3SwitchCount);
        return (rsp.status == 0UL) ? 0 : 2;
    }
    printf("\n=== CR3 追踪 %s ===\n", enable ? "打开" : "关闭");
    printf("  status       : %lu (%s)\n", rsp.status, crPolicyStatusName(rsp.status));
    printf("  策略位       : 0x%lX  TRACK_CR3=%s\n", rsp.flags,
           ((rsp.flags & KSWORD_ARK_HVM_CR_POLICY_FLAG_TRACK_CR3) != 0UL)
               ? "是" : "否");
    printf("  代次         : %lu   已观察地址空间切换 %llu 次\n",
           rsp.generation, rsp.cr3SwitchCount);
    printf("  注意：这一位在**常驻启动时**写进 VMCS，常驻起来之后再改不生效。\n");
    return (rsp.status == 0UL) ? 0 : 2;
}

static const char* injectStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_INJECT_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_INJECT_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_INJECT_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED:
        return "REQUIRES_RESIDENT_STOPPED";
    case KSWORD_ARK_HVM_INJECT_STATUS_PROCESS_LOOKUP_FAILED: return "PROCESS_LOOKUP_FAILED";
    case KSWORD_ARK_HVM_INJECT_STATUS_TRANSLATION_FAILED:    return "TRANSLATION_FAILED";
    case KSWORD_ARK_HVM_INJECT_STATUS_TABLE_FULL:            return "TABLE_FULL";
    case KSWORD_ARK_HVM_INJECT_STATUS_NOT_FOUND:             return "NOT_FOUND";
    case KSWORD_ARK_HVM_INJECT_STATUS_ALREADY_ARMED:         return "ALREADY_ARMED";
    case KSWORD_ARK_HVM_INJECT_STATUS_PROTECTED_TARGET:      return "PROTECTED_TARGET";
    case KSWORD_ARK_HVM_INJECT_STATUS_CR3_TRACKING_REQUIRED: return "CR3_TRACKING_REQUIRED";
    case KSWORD_ARK_HVM_INJECT_STATUS_EPTP_SWITCH_REQUIRED:  return "EPTP_SWITCH_REQUIRED";
    case KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE:               return "NO_CAVE";
    case KSWORD_ARK_HVM_INJECT_STATUS_VIEW_FAILED:           return "VIEW_FAILED";
    case KSWORD_ARK_HVM_INJECT_STATUS_PAGE_NOT_EXECUTABLE:   return "PAGE_NOT_EXECUTABLE";
    default:                                                 return "UNKNOWN";
    }
}

static int injectIoctl(HANDLE h,
                       KSWORD_ARK_HVM_INJECT_REQUEST* req,
                       KSWORD_ARK_HVM_INJECT_RESPONSE* rsp)
{
    DWORD returned = 0;
    BOOL ok;

    req->version = KSWORD_ARK_HVM_INJECT_PROTOCOL_VERSION;
    req->size = (unsigned long)sizeof(*req);
    memset(rsp, 0, sizeof(*rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_INJECT, req, (DWORD)sizeof(*req),
                         rsp, (DWORD)sizeof(*rsp), &returned, NULL);
    if (returned >= sizeof(*rsp)) {
        /* Use the response if complete, regardless of whether ok is true or false. */
        return 0;
    }
    fprintf(stderr, "INJECT IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
            (int)ok, returned, GetLastError());
    return 1;
}

static void printInjectTable(const KSWORD_ARK_HVM_INJECT_RESPONSE* rsp, int asJson)
{
    unsigned long i;

    if (asJson) {
        printf("{\"kind\":\"hvm-inject\",\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"rowCount\":%lu,\"generation\":%lu,"
               "\"rows\":[",
               rsp->status, injectStatusName(rsp->status),
               (unsigned long)rsp->lastStatus, rsp->rowCount, rsp->generation);
        for (i = 0UL; i < rsp->returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_INJECTIONS; ++i) {
            printf("%s{\"processId\":%lu,\"payloadBytes\":%lu,"
                   "\"directoryBase\":\"0x%016llX\","
                   "\"guestLinearAddress\":\"0x%016llX\","
                   "\"guestPhysicalAddress\":\"0x%016llX\","
                   "\"caveOffset\":%lu,\"caveBytes\":%lu,\"caveFiller\":%lu,"
                   "\"executionCount\":%llu,\"viewId\":%lu}",
                   (i == 0UL) ? "" : ",",
                   rsp->rows[i].processId, rsp->rows[i].payloadBytes,
                   rsp->rows[i].directoryBase, rsp->rows[i].guestLinearAddress,
                   rsp->rows[i].guestPhysicalAddress,
                   rsp->rows[i].caveOffset, rsp->rows[i].caveBytes,
                   rsp->rows[i].caveFiller,
                   rsp->rows[i].executionCount, rsp->rows[i].viewId);
        }
        printf("]}\n");
        return;
    }
    printf("\n=== R-1 进程注入 ===\n");
    printf("  status       : %lu (%s)  lastStatus=0x%08lX\n",
           rsp->status, injectStatusName(rsp->status),
           (unsigned long)rsp->lastStatus);
    printf("  表内条数     : %lu   代次=%lu\n", rsp->rowCount, rsp->generation);
    if (rsp->returnedRows == 0UL) {
        printf("  （表里没有任何注入）\n");
    }
    for (i = 0UL; i < rsp->returnedRows &&
                  i < KSWORD_ARK_HVM_MAX_INJECTIONS; ++i) {
        printf("  pid=%-6lu cr3=0x%016llX gpa=0x%016llX gla=0x%016llX\n",
               rsp->rows[i].processId, rsp->rows[i].directoryBase,
               rsp->rows[i].guestPhysicalAddress,
               rsp->rows[i].guestLinearAddress);
        printf("           空隙偏移=%lu 长度=%lu 填充=0x%02lX 载荷=%lu 执行=%llu 视图#%lu\n",
               rsp->rows[i].caveOffset, rsp->rows[i].caveBytes,
               rsp->rows[i].caveFiller,
               rsp->rows[i].payloadBytes, rsp->rows[i].executionCount,
               rsp->rows[i].viewId);
    }
    if (rsp->status == KSWORD_ARK_HVM_INJECT_STATUS_NO_CAVE) {
        printf("  ** 这一页没有足够长的空隙 **：外壳加载荷放不下。换一页，或用\n");
        printf("     hvm_target 打印的 probe 页（整页空白，专为首次验证准备）。\n");
    }
    if (rsp->status == KSWORD_ARK_HVM_INJECT_STATUS_REQUIRES_RESIDENT_STOPPED) {
        printf("  ** 常驻正在跑 **：装注入要在常驻停着时做。\n");
        printf("     顺序：stop -> inject-test -> self-test -> resident。\n");
    }
}

/*
 * inject-test: Minimal observable payload — write a constant to a known address.
 *
 * Selected for initial validation due to clean criteria: if the marker value changes from 0 to this constant, it proves the shell is working.
 * The heartbeat continues to advance, proving the borrowed thread was successfully returned. Both conditions are indispensable: observing only
 * that the process hasn't crashed does not prove the payload ran, and observing only that the marker changed does not prove the thread is usable.
 *
 *   48 B8 <imm64>   mov rax, markerAddress
 *   C7 00 <imm32>   mov dword ptr [rax], value
 *
 * Use absolute addresses instead of RIP-relative: the shell's landing spot within the page is determined by the driver
 * finding a gap, so the caller cannot calculate the relative distance. The shell is responsible for saving and restoring RAX.
 */
static int doInjectTest(HANDLE h, unsigned long pid,
                        unsigned long long gla,
                        unsigned long long markerAddress,
                        unsigned long value, int asJson)
{
    KSWORD_ARK_HVM_INJECT_REQUEST req;
    KSWORD_ARK_HVM_INJECT_RESPONSE rsp;
    unsigned long cursor = 0UL;
    unsigned long i;

    memset(&req, 0, sizeof(req));
    req.operation = KSWORD_ARK_HVM_INJECT_OP_ARM;
    req.injectType = KSWORD_ARK_HVM_INJECT_TYPE_SHELLCODE;
    req.processId = pid;
    req.guestLinearAddress = gla;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;

    req.payload[cursor++] = 0x48U;
    req.payload[cursor++] = 0xB8U;
    for (i = 0UL; i < 8UL; ++i) {
        req.payload[cursor++] =
            (unsigned char)((markerAddress >> (i * 8U)) & 0xFFULL);
    }
    req.payload[cursor++] = 0xC7U;
    req.payload[cursor++] = 0x00U;
    for (i = 0UL; i < 4UL; ++i) {
        req.payload[cursor++] =
            (unsigned char)((value >> (i * 8U)) & 0xFFUL);
    }
    req.payloadBytes = cursor;

    if (injectIoctl(h, &req, &rsp) != 0) { return 1; }
    printInjectTable(&rsp, asJson);
    return (rsp.status == KSWORD_ARK_HVM_INJECT_STATUS_OK) ? 0 : 2;
}

/*
 * inject-dll: Passes a DLL path to LoadLibraryW in the target process.
 *
 * loadLibraryAddress is provided by the caller, not resolved by the driver: the same module has different
 * base addresses in different processes, and the caller is already enumerating the target's module table.
 * Having the driver resolve it again duplicates work and risks inconsistency with what the caller sees.
 *
 * Path is passed as UTF-16 (LoadLibraryW); length excludes the trailing null. The
 * driver pads bytes beyond the length with zeros, so the terminator is redundant.
 */
static int doInjectDll(HANDLE h, unsigned long pid,
                       unsigned long long gla,
                       unsigned long long loadLibrary,
                       const char* path, int asJson)
{
    KSWORD_ARK_HVM_INJECT_REQUEST req;
    KSWORD_ARK_HVM_INJECT_RESPONSE rsp;
    int wideChars;

    /*
     * Resolve in-place if 0.
     *
     * kernel32 has the same base address for all processes within a single boot (system DLL ASLR is re-based per
     * boot, not per process), so the LoadLibraryW resolved in this process holds true for the target as well. Letting
     * this native program resolve it directly avoids the PowerShell interop layer for the caller—the failure mode of
     * that layer is a **silent return of 0**, which would only result in an "Invalid parameter" error if passed in.
     */
    if (loadLibrary == 0ULL) {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC resolved = (kernel32 != NULL)
            ? GetProcAddress(kernel32, "LoadLibraryW")
            : NULL;

        if (resolved == NULL) {
            fprintf(stderr, "解析 LoadLibraryW 失败：win32=%lu\n", GetLastError());
            return 1;
        }
        loadLibrary = (unsigned long long)(ULONG_PTR)resolved;
        fprintf(stderr, "LoadLibraryW = 0x%016llX（就地解析）\n", loadLibrary);
    }

    memset(&req, 0, sizeof(req));
    req.operation = KSWORD_ARK_HVM_INJECT_OP_ARM;
    req.injectType = KSWORD_ARK_HVM_INJECT_TYPE_DLL_PATH;
    req.processId = pid;
    req.guestLinearAddress = gla;
    req.loadLibraryAddress = loadLibrary;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;

    /* No trailing null: the driver pads with zeros, and the padded zero happens to be the string terminator. */
    wideChars = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
        (wchar_t*)req.payload,
        (int)(KSWORD_ARK_HVM_INJECT_MAX_PAYLOAD_BYTES / sizeof(wchar_t)));
    if (wideChars <= 1) {
        fprintf(stderr, "路径转换失败或为空：%s\n", path);
        return 1;
    }
    req.payloadBytes = (unsigned long)((wideChars - 1) * (int)sizeof(wchar_t));

    if (injectIoctl(h, &req, &rsp) != 0) { return 1; }
    printInjectTable(&rsp, asJson);
    return (rsp.status == KSWORD_ARK_HVM_INJECT_STATUS_OK) ? 0 : 2;
}

static int doInjectSimple(HANDLE h, unsigned long op, unsigned long pid, int asJson)
{
    KSWORD_ARK_HVM_INJECT_REQUEST req;
    KSWORD_ARK_HVM_INJECT_RESPONSE rsp;

    memset(&req, 0, sizeof(req));
    req.operation = op;
    req.processId = pid;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
    if (injectIoctl(h, &req, &rsp) != 0) { return 1; }
    printInjectTable(&rsp, asJson);
    return (rsp.status == KSWORD_ARK_HVM_INJECT_STATUS_OK) ? 0 : 2;
}

/* Translate the architectural result of a VMX instruction into a directly readable predicate. */
static const char* nestedProbeStepName(unsigned long r)
{
    switch (r) {
    case 0UL: return "成功";
    case 1UL: return "VMfailValid";
    case 2UL: return "VMfailInvalid";
    case KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED: return "**没执行到**";
    default:  return "?";
    }
}

static const char* nestedProbeStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK: return "OK";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_INVALID_REQUEST:
        return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIRMATION_REQUIRED:
        return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NOT_ARMED:
        return "NOT_ARMED（本核没常驻，或嵌套派发没开）";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_NO_RESOURCES:
        return "NO_RESOURCES";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_VMXE_REFUSED:
        return "VMXE_REFUSED（CR4.VMXE 置不上）";
    case KSWORD_ARK_HVM_NESTED_PROBE_STATUS_CONFIGURATION_FAILED:
        return "CONFIGURATION_FAILED（VMCS12 配置未通过，未进入 L2）";
    default: return "UNKNOWN";
    }
}

/*
 * Use a **read-only handle** to call a destructive IOCTL to see if the I/O manager blocks it.
 *
 * This is the only valid criterion for the fix regarding the access bit. Merely seeing FILE_WRITE_ACCESS in the header is insufficient—the
 * access bit is part of CTL_CODE. If the driver and client versions are inconsistent, the control codes won't match, causing the call to
 * fail for reasons unrelated to permissions, while appearing identical from the outside. Therefore, both aspects must be verified here:
 * Read-only handles must be rejected (win32=5); read-write handles must reach the driver (returning the driver's semantic result, not 5).
 * Only when both conditions hold is it confirmed that the gate is functioning correctly rather than the control code being misaligned.
 */
/* Read the selected CPU's complete GDT through the existing R0 descriptor API.
 * CPL3 SGDT is not the kernel's table view on every Windows configuration.
 * The R0 collector performs and restores its own group affinity; this command
 * must not leave the GUI worker pinned or allocate executable user memory.
 */
static int doGdtDump(HANDLE h, int asJson, int cpu)
{
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST req;
    KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE* rsp = NULL;
    GROUP_AFFINITY group = { 0 };
    unsigned char data[4096] = { 0 };
    unsigned char covered[4096] = { 0 };
    const DWORD kHeader = (DWORD)FIELD_OFFSET(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE, entries);
    const DWORD kCapacity = kHeader + KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS *
        (DWORD)sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
    DWORD returned = 0, win32Error = 0;
    unsigned long long base = 0ULL;
    unsigned long limit = 0UL, want = 0UL, i;
    const char* failure = "GDT_INCOMPLETE";
    int result = 1;

    /* Preserve the existing CPU-within-current-group command meaning. */
    if (cpu < 0 || cpu >= (int)(sizeof(KAFFINITY) * 8U)) {
        fprintf(stderr, "GDT: CPU_OR_GROUP_INVALID (%lu)\n", (unsigned long)ERROR_INVALID_PARAMETER);
        return 1;
    }
    if (!GetThreadGroupAffinity(GetCurrentThread(), &group)) {
        fprintf(stderr, "GDT: CPU_OR_GROUP_INVALID (%lu)\n", GetLastError());
        return 1;
    }
    rsp = (KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*)calloc(1, kCapacity);
    if (rsp == NULL) {
        fprintf(stderr, "GDT: ALLOCATION_FAILED (%lu)\n", (unsigned long)ERROR_NOT_ENOUGH_MEMORY);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
    req.requestSize = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU |
        KSWORD_ARK_DRIVER_INTEGRITY_FLAG_GDT_ENTRIES;
    req.maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY,
                         &req, (DWORD)sizeof(req), rsp, kCapacity, &returned, NULL)) {
        failure = "R0_QUERY_FAILED";
        win32Error = GetLastError();
        goto done;
    }
    /* Never parse another protocol layout or rows outside the returned buffer. */
    if (returned < kHeader || returned > kCapacity ||
        rsp->version != KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION ||
        rsp->entrySize != sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE) ||
        rsp->returnedCount > (returned - kHeader) / sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE)) {
        failure = "R0_RESPONSE_INVALID";
        goto done;
    }
    /* Broader integrity rows may be partial; require complete selected-table data. */
    for (i = 0UL; i < rsp->returnedCount; ++i) {
        const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE* row = &rsp->entries[i];
        unsigned long offset, bytes, j;
        if (row->evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR ||
            row->processorGroup != group.Group || row->processorNumber != (unsigned long)cpu) {
            continue;
        }
        if ((row->fieldMask & KSWORD_ARK_DRIVER_INTEGRITY_FIELD_DESCRIPTOR) == 0UL ||
            (row->descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED) != 0UL ||
            row->descriptorTableBase == 0ULL || row->descriptorTableLimit >= sizeof(data)) {
            goto done;
        }
        if (want == 0UL) {
            base = row->descriptorTableBase;
            limit = row->descriptorTableLimit;
            want = limit + 1UL;
        }
        offset = row->descriptorSelector;
        bytes = row->descriptorSize;
        if (row->descriptorTableBase != base || row->descriptorTableLimit != limit ||
            (bytes != 8UL && bytes != 16UL) || offset > want || bytes > want - offset ||
            row->objectAddress != base + offset) {
            goto done;
        }
        /* Reject overlapping or missing slots instead of inventing zero bytes. */
        for (j = 0UL; j < bytes; ++j) {
            if (covered[offset + j] != 0U) { goto done; }
            covered[offset + j] = 1U;
        }
        memcpy(data + offset, &row->descriptorRawLow, 8U);
        if (bytes == 16UL) { memcpy(data + offset + 8UL, &row->descriptorRawHigh, 8U); }
    }
    if (want == 0UL) { goto done; }
    for (i = 0UL; i < want; ++i) {
        if (covered[i] == 0U) { goto done; }
    }
    if (asJson) {
        printf("{\"kind\":\"gdt-dump\",\"cpu\":%d,\"base\":\"0x%016llX\","
               "\"limit\":\"0x%04lX\",\"bytes\":%lu,\"processorGroup\":%u,\"source\":\"R0\",\"data\":\"",
               cpu, base, limit, want, (unsigned)group.Group);
        for (i = 0UL; i < want; ++i) { printf("%02X", data[i]); }
        printf("\"}\n");
    } else {
        printf("=== GDT（CPU %d）===\n", cpu);
        printf("  base=0x%016llX  limit=0x%04X  读回 %lu 字节\n",
               base, (unsigned)limit, want);
        for (i = 0UL; i + 8UL <= want; i += 8UL) {
            printf("  [%02lX] %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   i, data[i], data[i+1], data[i+2], data[i+3],
                   data[i+4], data[i+5], data[i+6], data[i+7]);
        }
    }
    result = 0;
done:
    if (result != 0) { fprintf(stderr, "GDT: %s (%lu)\n", failure, win32Error); }
    free(rsp);
    return result;
}

static int doAclProbe(HANDLE rw, int asJson)
{
    static const struct { const char* name; DWORD code; } kProbes[] = {
        { "TERMINATE_PROCESS",    IOCTL_KSWORD_ARK_TERMINATE_PROCESS },
        { "SUSPEND_PROCESS",      IOCTL_KSWORD_ARK_SUSPEND_PROCESS },
        { "READ_PHYSICAL_MEMORY", IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY },
        { "READ_VIRTUAL_MEMORY",  IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY },
    };
    unsigned char scratch[512];
    HANDLE ro;
    size_t i;
    int failed = 0;

    ro = CreateFileW(KSW_DEVICE_PATH, GENERIC_READ,
                     FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ro == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "只读句柄都打不开：win32=%lu —— 这一项测不了\n",
                GetLastError());
        return 1;
    }
    if (!asJson) {
        printf("\n=== 访问位闸门（只读句柄 vs 读写句柄）===\n");
    }
    for (i = 0; i < sizeof(kProbes) / sizeof(kProbes[0]); ++i) {
        DWORD returned = 0;
        DWORD roErr, rwErr;

        memset(scratch, 0, sizeof(scratch));
        SetLastError(0);
        (void)DeviceIoControl(ro, kProbes[i].code, scratch, (DWORD)sizeof(scratch),
                              scratch, (DWORD)sizeof(scratch), &returned, NULL);
        roErr = GetLastError();
        memset(scratch, 0, sizeof(scratch));
        SetLastError(0);
        (void)DeviceIoControl(rw, kProbes[i].code, scratch, (DWORD)sizeof(scratch),
                              scratch, (DWORD)sizeof(scratch), &returned, NULL);
        rwErr = GetLastError();
        /*
         * Read-only must be 5 (Access Denied); read-write must not be 5.
         *
         * Any semantic error returned by the read/write side counts as a pass. The input is all zeros, so
         * the driver will probably report invalid parameters; that proves the request reached the driver.
         */
        {
            const int kPass = (roErr == ERROR_ACCESS_DENIED) &&
                             (rwErr != ERROR_ACCESS_DENIED);
            if (!kPass) { failed = 1; }
            if (asJson) {
                printf("%s{\"kind\":\"acl-probe\",\"ioctl\":\"%s\","
                       "\"readOnlyWin32\":%lu,\"readWriteWin32\":%lu,"
                       "\"pass\":%d}\n",
                       "", kProbes[i].name, roErr, rwErr, kPass);
            } else {
                printf("  %-22s 只读 win32=%-5lu  读写 win32=%-5lu  => %s\n",
                       kProbes[i].name, roErr, rwErr,
                       kPass ? "**PASS**" : "FAIL");
            }
        }
    }
    CloseHandle(ro);
    if (!asJson) {
        printf("\n  判据：只读句柄必须 win32=5（被 I/O 管理器挡在驱动之外），\n"
               "        且同一条在读写句柄上**不是** 5 —— 后者排除\"控制码对不上\"\n"
               "        这个与权限无关却长得一样的原因。\n");
    }
    return failed ? 2 : 0;
}

/* Determine if a row meets the positive criteria. */
static int nestedProbeRowPassed(const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r)
{
    return (r->status == KSWORD_ARK_HVM_NESTED_PROBE_STATUS_OK &&
            r->vmxonResult == 0UL && r->vmptrldResult == 0UL &&
            r->vmwriteResult == 0UL && r->vmreadResult == 0UL &&
            r->vmreadMatched == 1UL && r->vmptrstMatched == 1UL &&
            r->l2Reached == 1UL &&
            /*
             * The termination exit corresponds to the second RDMSR, not CPUID.
             *
             * The L2 program consists of two RDMSR instructions: the first has a clear bit in L1's bitmap and must be allowed; the
             * second has a set bit and must cause an exit. Both generate "some exit"; only **where execution stops** distinguishes
             * whether the processor checked L1's bitmap or the fallback page for "full interception". Thus, the criterion requires
             * both the reason and the offset; missing either degrades the check to merely "the reflection link is open".
             */
            (r->l2ExitReason & 0xFFFFULL) == 31ULL &&
            r->l2RipOffset ==
                KSWORD_ARK_HVM_NESTED_PROBE_RIP_TRAPPED_MSR &&
            /*
             * Both sets of vmcs12 fields must survive the switch.
             *
             * This field was previously excluded from the criteria because it would always fail. Now it
             * acts as a gate: any change that reverts vmcs12 to "model only one copy" will immediately
             * turn red here, rather than waiting for someone to test with a real hypervisor.
             */
            r->vmcsSwitchMatched == 1UL &&
            /*
             * Cache eviction must preserve every region in its backing page.
             * The probe writes distinct values to more regions than the pool
             * holds and reloads all of them. Losing even an evicted region is
             * a failure; the eviction count proves the cache overflow ran.
             */
            r->vmcs12DepthRegions > 2UL &&
            r->vmcs12DepthRegions <= 64UL &&
            r->vmcs12DepthSurvived == r->vmcs12DepthRegions &&
            r->vmcs12DepthMask ==
                (~0ULL >> (64UL - r->vmcs12DepthRegions)) &&
            r->vmcs12EvictionDelta >= 1UL &&
            /*
             * The capabilities we declare must equal the capabilities we implement.
             *
             * These three bits represent features that L1 is most likely to enable while we have the least implementation for:
             * VPID, VMFUNC, and VMCS shadowing. We do not copy any of their corresponding vmcs02 fields. Without filtering, L1
             * would read the host's actual values and enable them, causing us to silently fail to honor them. There is no
             * error reporting anywhere along this path, which is the same family of defect as the MSR bitmap issue.
             *
             * The value is read from the guest context's RDMSR, so this check verifies two things: the
             * relevant bits are indeed set in the bitmap, and the exit truly reached the filter function. If
             * either is missing, the value read here is the host's true value, and the VPID bit will be set.
             *
             * Non-zero requires a single column: all zeros means this field was never filled (old driver,
             * or read occurred before the resident component started), and 'all zeros' also makes the
             * following three checks pass — an unexecuted check must not appear to have passed.
             */
            /*
             * Fields written by L1 into vmcs12 must actually be present in vmcs02.
             *
             * The TSC offset comparison checks against a specific constant, not 'non-zero': non-zero only
             * indicates someone wrote something, whereas here we must verify if the value written is the L1 value.
             *
             * The MSR load table provides stronger evidence. A PASS requires successful vmlaunch
             * and l2Reached=true, as checked above. The table is real and the count is 1, proving
             * that the processor used L1's table, not merely that the fields were populated.
             */
            r->vmcs02TscOffset ==
                KSWORD_ARK_HVM_NESTED_PROBE_TSC_OFFSET &&
            r->vmcs02EntryMsrLoadAddress != 0ULL &&
            r->vmcs02EntryMsrLoadCount == 1UL &&
            r->vmcs02ExitMsrStoreAddress != 0ULL &&
            r->guestVmxEptVpidCap != 0ULL &&
            (r->guestVmxEptVpidCap &
                ~KSWORD_ARK_HVM_VMX_EPT_CAP_ALLOWED) == 0ULL &&
            ((r->guestVmxProcbased2 >> 32) &
                ((1ULL << 5) | (1ULL << 13) | (1ULL << 14))) == 0ULL &&
            r->l1UsesMsrBitmap == 1UL &&
            r->bitmapMergeComplete == 1UL &&
            /* That RDMSR was dispatched to L1, not consumed locally by us. */
            r->l2MsrExitsReflected >= 1ULL &&
            /* The bitmap address must have actually been written into vmcs02. */
            r->vmcs02MsrBitmap != 0ULL &&
            r->inveptResult == 0UL &&
            r->shadowGenerationAdvanced == 1UL &&
            r->hostStateChecks == 0x3FUL) ? 1 : 0;
}

static void printNestedProbeRow(const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r)
{
    printf("  L1 host 状态与内存操作数实测：0x%02lX（完整通过 = 0x3F）\n", r->hostStateChecks);
    printf("  --- CPU %lu ---   status %lu (%s)\n",
           r->processorIndex, r->status,
           nestedProbeStatusName(r->status));
    printf("    VMXON %s  VMPTRLD %s  VMWRITE %s  VMREAD %s  VMPTRST %s  VMXOFF %s\n",
           nestedProbeStepName(r->vmxonResult),
           nestedProbeStepName(r->vmptrldResult),
           nestedProbeStepName(r->vmwriteResult),
           nestedProbeStepName(r->vmreadResult),
           nestedProbeStepName(r->vmptrstResult),
           nestedProbeStepName(r->vmxoffResult));
    printf("    读回 0x%016llX %s   指针 %s\n",
           r->vmreadValue,
           r->vmreadMatched ? "**逐位相同**" : "不相同",
           r->vmptrstMatched ? "**相符**" : "不符");
    printf("    EPT12 %s   影子叶 %lu 张  拒绝 %lu  耗尽 %lu\n",
           r->ept12Armed ? "**已装**" : "未装",
           r->shadowFillCount, r->shadowDenyCount,
           r->shadowExhaustionCount);
    printf("    VMLAUNCH %s   L2 跑过 %s   退出原因 0x%llX%s   停在 0x%llX\n",
           nestedProbeStepName(r->vmlaunchResult),
           r->l2Reached ? "**是**" : "否",
           r->l2ExitReason,
           ((r->l2ExitReason & 0x80000000ULL) != 0ULL)
               ? "(entry 失败)"
               : (((r->l2ExitReason & 0xFFFFULL) == 10ULL) ? "(CPUID)" : ""),
           r->l2GuestRip);
    printf("    INVEPT %s   影子代次 %s\n",
           nestedProbeStepName(r->inveptResult),
           r->shadowGenerationAdvanced ? "**真的前进了**" : "没变");
    /*
     * Control bits and bitmap address at the moment of vmcs02 entry.
     *
     * The control bits are the union of L1's and ours, so USE_MSR_BITMAPS (bit 28) is always active.
     * A paired address of 0 means the processor uses physical page 0 as a bitmap. Viewing the two fields
     * separately appears normal; only when viewed together can one determine who manages L2 MSR/IO interception.
     */
    printf("    vmcs02 控制  primary=0x%08lX%s  secondary=0x%08lX\n",
           r->vmcs02PrimaryControls,
           ((r->vmcs02PrimaryControls & (1UL << 28)) != 0UL)
               ? " [USE_MSR_BITMAPS]"
               : "",
           r->vmcs02SecondaryControls);
    printf("    vmcs02 位图  msr=0x%016llX%s  io_a=0x%016llX  io_b=0x%016llX\n",
           r->vmcs02MsrBitmap,
           (((r->vmcs02PrimaryControls & (1UL << 28)) != 0UL) &&
            r->vmcs02MsrBitmap == 0ULL)
               ? "  **位开着而地址为 0：处理器会读物理页 0**"
               : "",
           r->vmcs02IoBitmapA,
           r->vmcs02IoBitmapB);
    /*
     * Fields that L1 wrote but we never copied before.
     *
     * The MSR region is more concealed than bitmaps: its count field takes effect unconditionally, with
     * no capability bits to indicate "not supported." Therefore, not copying means the L1-installed
     * MSRs were never installed, while L2 runs with our values, and neither side reports any errors.
     */
    printf("    vmcs02 透传  tsc_offset=0x%016llX%s  "
           "entry_msr=0x%016llX x%lu  exit_msr=0x%016llX x%lu\n",
           r->vmcs02TscOffset,
           (r->vmcs02TscOffset == KSWORD_ARK_HVM_NESTED_PROBE_TSC_OFFSET)
               ? " **L1 的值到位了**"
               : ((r->vmcs02TscOffset == 0ULL)
                      ? " **是 0 —— 字段没写过**"
                      : " **不是 L1 写的值**"),
           r->vmcs02EntryMsrLoadAddress, r->vmcs02EntryMsrLoadCount,
           r->vmcs02ExitMsrStoreAddress, r->vmcs02ExitMsrStoreCount);
    /*
     * MSR routing criterion row. The stop point is the answer; the three outcomes each have a fixed offset.
     */
    /*
     * Switching between two vmcs12 instances. A single VMCS cannot reveal this, but a real hypervisor will always switch.
     */
    printf("    vmcs12 切换  %s   A 读回 0x%016llX   B 读回 0x%016llX\n",
           (r->vmcsSwitchResult == KSWORD_ARK_HVM_NESTED_PROBE_STEP_SKIPPED)
               ? "**没执行到**"
               : (r->vmcsSwitchMatched
                      ? "**两份各自的字段都还在**"
                      : "**字段丢了 —— 只建模了一份 vmcs12**"),
           r->vmcsSwitchValueA, r->vmcsSwitchValueB);
    /* Cache overflow must keep every VMCS recoverable from its region. */
    if (r->vmcs12DepthRegions != 0UL) {
        unsigned long slot = 0UL;

        printf("    vmcs12 深度  测 %lu 份，活下来 %lu 份   驱逐 %lu 次%s\n",
               r->vmcs12DepthRegions, r->vmcs12DepthSurvived,
               r->vmcs12EvictionDelta,
               (r->vmcs12EvictionDelta == 0UL)
                   ? "  **一次都没驱逐 —— 计数器没动，或者池子根本没满**"
                   : "");
        printf("                 存活位图 ");
        /* Oldest on the left, newest on the right, matching write order. */
        for (slot = 0UL; slot < r->vmcs12DepthRegions; ++slot) {
            printf("%c", ((r->vmcs12DepthMask >> slot) & 1ULL) ? '#' : '.');
        }
        printf("   （左=最先写，右=最后写；'.' 是丢失的字段，全部应为 '#'）\n");
    }
    /*
     * Guest-visible VMX capabilities: the only place where capability filtering can be falsified.
     *
     * The three listed features are those 'most likely to be enabled by L1 but least implemented by us': VPID requires
     * the VPID field and INVVPID; VMFUNC requires 0x2018; VMCS shadowing requires 0x2026/0x2028. We do not copy any of
     * these fields into vmcs02. If they are still set, it indicates that the filtering has not taken effect.
     */
    if (r->guestVmxProcbased2 != 0ULL || r->guestVmxEptVpidCap != 0ULL) {
        const unsigned long long kSecondary = r->guestVmxProcbased2 >> 32;
        const unsigned long long kVpidBits =
            r->guestVmxEptVpidCap &
            ((1ULL << 32) | (0xFULL << 40));

        printf("    来宾看到的   secondary 可置位=0x%08llX  "
               "ept_vpid=0x%016llX\n",
               kSecondary, r->guestVmxEptVpidCap);
        printf("                 VPID %s   VMFUNC %s   VMCS影子 %s   "
               "INVVPID %s\n",
               ((kSecondary >> 5) & 1ULL) ? "**还宣告着**" : "已收",
               ((kSecondary >> 13) & 1ULL) ? "**还宣告着**" : "已收",
               ((kSecondary >> 14) & 1ULL) ? "**还宣告着**" : "已收",
               (kVpidBits & (1ULL << 43)) != 0ULL
                   ? "**错误宣告类型 3**" : "类型 0/1/2 按能力保留");
    }
    printf("    MSR 路由     L1 用位图 %s   合并 %s   L2 停在 +%llu %s\n",
           r->l1UsesMsrBitmap ? "是" : "否",
           r->bitmapMergeComplete ? "完整" : "**不完整（回退成全部拦截）**",
           r->l2RipOffset,
           (r->l2RipOffset == KSWORD_ARK_HVM_NESTED_PROBE_RIP_TRAPPED_MSR)
               ? "**第二条 RDMSR —— 查的确实是 L1 那张位图**"
               : ((r->l2RipOffset == KSWORD_ARK_HVM_NESTED_PROBE_RIP_OPEN_MSR)
                      ? "**第一条 RDMSR —— 本该放行却拦了，查的不是 L1 的页**"
                      : ((r->l2RipOffset ==
                              KSWORD_ARK_HVM_NESTED_PROBE_RIP_CPUID)
                             ? "**走到了 CPUID —— MSR 拦截根本没发生**"
                             : "（预期之外的位置）")));
    printf("    MSR/IO 归属  MSR 投递 %llu / 就地 %llu   IO 投递 %llu / 就地 %llu\n",
           r->l2MsrExitsReflected, r->l2MsrExitsHandled,
           r->l2IoExitsReflected, r->l2IoExitsHandled);
    /*
     * Merge cost is reported only as a share, not as isolated cycle counts.
     *
     * Deciding whether to add a cache based solely on "merge took N cycles" is insufficient; what matters is its share
     * within a single L2 entry. If the share is small, the cache yields no savings, making further optimization pointless.
     */
    if (r->l2EntryCount != 0ULL && r->l2EntryCycles != 0ULL) {
        printf("    合并代价     %llu / %llu 周期 = **%.1f%%** 的 L2 进入成本"
               "（%llu 次进入，均摊 %llu 周期/次）\n",
               r->l2MergeCycles, r->l2EntryCycles,
               (double)r->l2MergeCycles * 100.0 / (double)r->l2EntryCycles,
               r->l2EntryCount,
               r->l2MergeCycles / r->l2EntryCount);
    }
    printf("    派发 %llu 条   嵌套状态 %lu   末次错误号 %lu   => %s\n",
           r->dispatchedInstructions, r->nestedStateAfter,
           r->lastInstructionError,
           nestedProbeRowPassed(r) ? "**PASS**" : "FAIL");
}

/*
 * Install a policy to intercept reads of this MSR and then execute natively.
 *
 * The only reason for its existence is that the branch in nested routing where "this exit belongs to us and someone must service
 * it" has no other way to be triggered. The L1 bitmap is constructed by the probe itself, while our side's bitmap defaults to
 * all zeros. With neither side blocking, the merged bit remains clear, so that branch never executes. Yet it is precisely the
 * branch that **silently hangs** on error: no instruction is emulated, RIP does not advance, and L2 re-executes indefinitely.
 *
 * The semantics of the LOG action are exactly 'record then execute natively', which aligns with what local handling requires.
 * The policy modifies a shared bitmap, so the driver accepts it only while the resident hypervisor is stopped; install it before resident startup.
 */
static int doMsrPolicy(HANDLE h, unsigned long operation,
                       unsigned long msrIndex, int asJson)
{
    KSWORD_ARK_HVM_MSR_POLICY_REQUEST req;
    KSWORD_ARK_HVM_MSR_POLICY_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_MSR_POLICY_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = operation;
    req.flags = KSWORD_ARK_HVM_MSR_POLICY_FLAG_UI_CONFIRMED;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.msrIndex = msrIndex;
    req.access = KSWORD_ARK_HVM_MSR_ACCESS_READ;
    req.action = KSWORD_ARK_HVM_MSR_ACTION_LOG;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MSR_POLICY,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        fprintf(stderr,
                "MSR_POLICY IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"msr-policy\",\"op\":%lu,\"msr\":\"0x%lX\","
               "\"status\":%lu,\"policyId\":%lu,\"count\":%lu}\n",
               operation, msrIndex, rsp.status, rsp.policyId,
               rsp.policyCount);
    } else {
        printf("=== MSR 策略 ===\n");
        printf("  操作     : %lu   MSR 0x%lX   访问=读   动作=LOG（记一笔再原生执行）\n",
               operation, msrIndex);
        printf("  status   : %lu%s\n", rsp.status,
               (rsp.status == 8UL)
                   ? "  **RESIDENT_BUSY：策略要改共享位图，先停常驻**"
                   : "");
        printf("  策略 id  : %lu   当前条数 %lu\n",
               rsp.policyId, rsp.policyCount);
    }
    return (rsp.status == KSWORD_ARK_HVM_MSR_POLICY_STATUS_OK) ? 0 : 2;
}

/*
 * L1 requests accessed/dirty in the EPT12 pointer: This should now be **accepted and actually propagated**.
 *
 * This test case originally verified that the operation 'must be rejected'. Rejection was the only honest choice at the time: allowing it
 * without propagation would cause the hardware to place data in our shadow leaf. L1 reading its own EPT12 would yield all zeros, allowing
 * it to skip pages it truly modified. No reads along the path would change. Now that propagation is implemented, the criterion is inverted.
 *
 * Expectation: L2 must actually run (VMLAUNCH succeeds, l2Reached), and the driver must report A/D as being in the **maintenance** state.
 * Merely seeing that it 'ran' is insufficient — it can run without maintenance; the distinction lies entirely in that specific flag.
 */
/*
 * Self-virtualization: making L1 turn the context it is currently running into a guest.
 *
 * This is the boundary between 'holding up a hypervisor' and 'holding up a test program'. Previously, L2 ran on
 * a synthesized code page with a synthesized RIP and stack; segment registers, CR3, and page tables were not
 * taken literally. Our own resident path, along with VMware's VMM, does the same thing: capture the current
 * state, redirect the guest RIP to the next instruction, perform VMLAUNCH, and thus become their own guest.
 *
 * The criteria require all three conditions: entry to L2 (reachedL2), the L2 exit dispatched to
 * L1 (exitReason is 10, read from vmcs12), and L1 regaining control to finalize (returnedToL1).
 * Checking only the first cell is insufficient: if one can enter but not exit, it is just as fatal for a true hypervisor as being unable to enter at all.
 */
/* Determine if a row's self-virtualization result passed. In multi-core mode, every row must pass. */
static int selfVirtRowPassed(const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r)
{
    return (r->selfVirtAttempted == 1UL &&
            r->selfVirtReachedL2 == 1UL &&
            r->selfVirtSlotMarker == 1UL &&
            r->selfVirtReturnedToL1 == 1UL &&
            r->hostStateChecks == 0x7FUL &&
            r->selfVirtCpuidPassedThrough == 0UL &&
            (r->selfVirtExitReason & 0xFFFFULL) == 10ULL &&
            /*
             * Round-trip count exceeds one, and all L1-armed exits have arrived.
             *
             * A single entry/exit is not a hypervisor; the return path uses VMRESUME, which is a different instruction
             * with a separate launch-state check. Passing the initial entry does not imply passing this one.
             *
             * This check verifies that **every single CPUID instruction has reached L1** (dispatch count equals round-trip
             * count), not that 'all exits have reached L1'. I previously implemented the latter incorrectly: testing showed
             * 29 exits but only 9 dispatched; the missing 20 were shadow EPT leaf entries. Since L1's EPT12 authorized
             * those accesses, synthesizing the leaves is inherently our responsibility; L1 never required visibility into
             * them. Requiring them to also dispatch would incorrectly mark every **correct** execution as FAIL.
             */
            r->selfVirtResumeCount >= 1UL &&
            r->selfVirtEntryCount == r->selfVirtResumeCount + 1UL &&
            r->selfVirtReflectCount ==
                r->selfVirtResumeCount + 1UL) ? 1 : 0;
}

static int doNestedSelfVirtualize(HANDLE h, int asJson, int allProcessors)
{
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST req;
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r;
    int passed;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                KSWORD_ARK_HVM_NESTED_PROBE_FLAG_SELF_VIRTUALIZE;
    if (allProcessors) {
        req.flags |= KSWORD_ARK_HVM_NESTED_PROBE_FLAG_ALL_PROCESSORS;
    }
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp) || rsp.returnedRows == 0UL) {
        fprintf(stderr,
                "NESTED_PROBE(self) 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    r = &rsp.rows[0];
    /* If not established beforehand, it doesn't count as detected, following the same logic as the A/D case. */
    if (r->vmxonResult != 0UL || r->vmptrldResult != 0UL) {
        if (!asJson) {
            printf("=== 嵌套自虚拟化 ===\n");
            printf("  **空过**：VMXON/VMPTRLD 没成功，这一轮没走到进入那道门。\n");
        }
        return 3;
    }
    /*
     * Five slots, none can be missing.
     *
     * slotMarker is single-column, not parallel. reachedL2: the former checks if the L2-inherited GS base address is
     * correct (finding the slot requires GS), while the latter checks if L2 memory is accessible (RIP-relative addressing).
     * The two failure reasons are entirely different; merging them would collapse distinct failures into a single 0.
     */
    passed = selfVirtRowPassed(r);
    /*
     * In multi-core mode, check row by row; **any row FAIL results in an overall FAIL**.
     *
     * Each processor has its own vmcs02, its own shadow hierarchy, and its own mapping window; structurally, they do not interfere with one
     * another. This repository has already failed multiple times with the assumption that 'single-core success implies multi-core success'.
     */
    if (allProcessors) {
        unsigned long row = 0UL;

        for (row = 0UL; row < rsp.returnedRows &&
                        row < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++row) {
            if (!selfVirtRowPassed(&rsp.rows[row])) { passed = 0; }
        }
        if (!asJson) {
            printf("\n=== 嵌套自虚拟化（多核，%lu 个处理器各起一个线程）===\n",
                   rsp.returnedRows);
            for (row = 0UL; row < rsp.returnedRows &&
                            row < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++row) {
                const KSWORD_ARK_HVM_NESTED_PROBE_ROW* q = &rsp.rows[row];

                printf("  CPU %lu: 进 L2 %s  写入 %s/%s  往返 %lu  "
                       "投递 %lu/%lu  原因 %llu  状态/SSE 0x%02lX  => %s\n",
                       q->processorIndex,
                       q->selfVirtReachedL2 ? "是" : "**否**",
                       q->selfVirtReachedL2 ? "到" : "**丢**",
                       q->selfVirtSlotMarker ? "到" : "**丢**",
                       q->selfVirtResumeCount,
                       q->selfVirtReflectCount, q->selfVirtTotalExitCount,
                       q->selfVirtExitReason & 0xFFFFULL,
                       q->hostStateChecks,
                       selfVirtRowPassed(q) ? "**PASS**" : "FAIL");
            }
            printf("\n  判据：每一行都要过。每核有自己的 vmcs02、影子层次与映射窗口，\n"
                   "        结构上互不干涉 —— 单核跑通推不出多核跑通。\n");
            printf("  => %s\n", passed ? "**PASS**" : "FAIL");
            return passed ? 0 : 2;
        }
    }
    if (asJson) {
        printf("{\"kind\":\"nested-selfvirt\",\"attempted\":%lu,"
               "\"reachedL2\":%lu,\"returnedToL1\":%lu,"
               "\"cpuidPassedThrough\":%lu,\"slotMarker\":%lu,"
               "\"exitReason\":%llu,\"guestRip\":\"0x%016llX\","
               "\"entryRip\":\"0x%016llX\","
               "\"entryCount\":%lu,\"reflectCount\":%lu,"
               "\"totalExitCount\":%lu,\"resumeCount\":%lu,"
               "\"vmlaunch\":%lu,\"lastInstructionError\":%lu,"
               "\"fuseTripped\":%lu,\"fuseReason\":%lu,\"fuseCount\":%lu,"
               "\"fuseRip\":\"0x%016llX\","
               "\"hostStateChecks\":%lu,"
               "\"pass\":%d}\n",
               r->selfVirtAttempted, r->selfVirtReachedL2,
               r->selfVirtReturnedToL1, r->selfVirtCpuidPassedThrough,
               r->selfVirtSlotMarker,
               r->selfVirtExitReason & 0xFFFFULL, r->selfVirtGuestRip,
               r->selfVirtEntryRip,
               r->selfVirtEntryCount, r->selfVirtReflectCount,
               r->selfVirtTotalExitCount, r->selfVirtResumeCount,
               r->vmlaunchResult, r->lastInstructionError,
               r->l2FuseTripped, r->l2FuseReason, r->l2FuseCount,
               r->l2FuseRip, r->hostStateChecks, passed);
    } else {
        printf("\n=== 嵌套自虚拟化（L1 把自己变成来宾）===\n");
        printf("  L2 的写入   : 全局标记 %s   经槽位 %s\n",
               r->selfVirtReachedL2 ? "**到了**" : "**没到**",
               r->selfVirtSlotMarker ? "**到了**" : "**没到**");
        printf("  进入 L2     : %s%s\n",
               r->selfVirtReachedL2 ? "**是**" : "**否**",
               r->selfVirtReachedL2
                   ? "  —— 同一段代码，低一个特权域在跑"
                   : "  —— L2 的存储没有回到 L1 眼里（两者含义不同，见上一行）");
        if (!r->selfVirtReachedL2) {
            printf("  VMLAUNCH    : 结果 %lu   指令错误号 %lu\n",
                   r->vmlaunchResult, r->lastInstructionError);
            printVmInstructionError("  ", r->lastInstructionError);
        }
        /*
         * Difference between entry and exit RIP — comparison within the same round, unaffected by load base address.
         */
        if (r->selfVirtEntryRip != 0ULL) {
            const long long kDelta =
                (long long)(r->selfVirtGuestRip - r->selfVirtEntryRip);

            /*
             * The two RIPs are reported side-by-side only; no difference calculation is performed.
             *
             * L2 now starts from the resume stub in the assembly launcher, while exit occurs in C; they are inherently in different
             * functions, so the difference is necessarily large. I used this difference as a criterion, so it applies to a single instance.
             * The "completely correct" run printed "L2 did not start from the location we specified." This is a criterion
             * that holds only under a specific code layout; changing the layout turns it into a false negative.
             *
             * The question of whether L2 is actually running is now answered by
             * the launcher's return value, without relying on address inference.
             */
            (void)kDelta;
            printf("  入口/退出   : 0x%016llX -> 0x%016llX"
                   "（resume 桩与退出点本就不同函数，不比差值）\n",
                   r->selfVirtEntryRip, r->selfVirtGuestRip);
        }
        /*
         * The exit reason here is a **one-bit response**, not just a diagnostic.
         *
         * L2 cannot use memory sessions — the question "can L1 see L2's writes to memory" is exactly what's being asked,
         * so any reply written to memory is unreadable precisely when it matters. The exit reason path has been verified
         * in both directions: CPUID shows L2 reads back its own written value, while VMCALL shows it cannot be read back.
         */
        printf("  L2 的退出   : 原因 %llu %s   停在 0x%016llX\n",
               r->selfVirtExitReason & 0xFFFFULL,
               ((r->selfVirtExitReason & 0xFFFFULL) == 10ULL)
                   ? "**CPUID —— L2 读回了自己写的值**"
                   : (((r->selfVirtExitReason & 0xFFFFULL) == 18ULL)
                          ? "**VMCALL —— L2 连自己刚写的值都读不回来**"
                          : "**既不是 CPUID 也不是 VMCALL —— 走到了别处**"),
               r->selfVirtGuestRip);
        printf("  回到 L1     : %s\n",
               r->selfVirtReturnedToL1
                   ? "**是** —— L1 的宿主处理器跑完并交还了上下文"
                   : "**否** —— 进去了没回来");
        /*
         * Entry count = 1 + resume count: The initial VMLAUNCH plus each subsequent VMRESUME.
         *
         * All exits and dispatched exits must be equal. The difference represents **exits we answered on behalf of L1 for its own
         * guest**, which L1 will never know about. Looking only at the dispatched count, this difference is always invisible.
         */
        printf("  往返        : 进入 %lu 次（VMLAUNCH 1 + VMRESUME %lu）\n",
               r->selfVirtEntryCount, r->selfVirtResumeCount);
        printf("  退出归属    : 共 %lu 次   投递给 L1 %lu 次   我们自己处理 %lu 次\n",
               r->selfVirtTotalExitCount, r->selfVirtReflectCount,
               (r->selfVirtTotalExitCount >= r->selfVirtReflectCount)
                   ? (r->selfVirtTotalExitCount - r->selfVirtReflectCount)
                   : 0UL);
        printf("                 %s\n",
               (r->selfVirtReflectCount == r->selfVirtResumeCount + 1UL)
                   ? "每一条 CPUID 都到了 L1；自己处理的那些是影子 EPT 填叶，"
                     "本就该是我们的"
                   : "**L1 armed 的退出没有全部到达 —— 我们替它回答了它的来宾**");
        /*
         * The fuse trip count. This is the only thing left behind when a hang occurs — without
         * it, the same failure is unreadable in the guest and invisible in the host logs.
         */
        if (r->l2FuseTripped) {
            printf("  **熔断跳闸** : L2 在同一条指令上以同样的原因退出了 %lu 次\n",
                   r->l2FuseCount);
            printf("                 退出原因 %lu   停在 0x%016llX\n",
                   r->l2FuseReason, r->l2FuseRip);
            printf("                 —— 这就是之前那次挂死的样子，只是这回被拦住了\n");
        } else {
            printf("  熔断        : 未跳闸（L2 一直在往前走）\n");
        }
        if (r->selfVirtCpuidPassedThrough) {
            printf("  **CPUID 没有退出** —— 架构上不该发生，记下来而不是当它没发生\n");
        }
        printf("\n  判据：进得去、L2 的退出被投递给 L1（原因 10）、L1 拿回控制权，\n"
               "        三格缺一不可。进得去出不来，对一个真 hypervisor 来说\n"
               "        跟进不去一样是死的。\n");
        printf("  => %s\n", passed ? "**PASS**" : "FAIL");
    }
    return passed ? 0 : 2;
}

static int doNestedProbeAdRefusal(HANDLE h, int asJson)
{
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST req;
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r;
    int passed;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                KSWORD_ARK_HVM_NESTED_PROBE_FLAG_REQUEST_AD;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp) || rsp.returnedRows == 0UL) {
        fprintf(stderr,
                "NESTED_PROBE(AD) 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    r = &rsp.rows[0];
    /*
     * If not established beforehand, it doesn't count as a test. If VMXON failed, the
     * A/D gate was never reached in this round; reporting success is a null pass.
     */
    if (r->vmxonResult != 0UL || r->vmptrldResult != 0UL) {
        if (!asJson) {
            printf("=== 嵌套 A/D 拒绝（负向）===\n");
            printf("  **空过**：VMXON/VMPTRLD 没成功，这一轮没走到 A/D 那道门。\n");
        }
        return 3;
    }
    /*
     * Treat the two cells separately, as they use different encodings.
     *
     * vmlaunchResult is the **step result** (0 = success, 1 = VMfailValid, 2 = VMfailInvalid);
     * lastInstructionError is the Intel error code. We require failure via VMfailValid.
     * **And** the error code is 7 (invalid control field). If only the former is checked,
     * any failure can be masked; if only the latter is checked, VMfailInvalid carries no
     * error code, so the read value would be stale data left by the previous instruction.
     */
    /*
     * All three slots are required.
     *
     * l2Reached only indicates that L2 is running; it can run without maintaining A/D bits.
     * l1RequestedAccessedDirty: Only indicates that the request reached the driver.
     * accessedDirtyActive is the only thing this test case truly
     * asks: "Are we actually maintaining and will we roll back?"
     */
    passed = (r->l2Reached == 1UL &&
              r->l1RequestedAccessedDirty == 1UL &&
              r->accessedDirtyActive == 1UL) ? 1 : 0;
    if (asJson) {
        printf("{\"kind\":\"nested-ad\",\"l2Reached\":%lu,"
               "\"requested\":%lu,\"active\":%lu,\"propagated\":%lu,"
               "\"overflow\":%lu,\"pass\":%d}\n",
               r->l2Reached, r->l1RequestedAccessedDirty,
               r->accessedDirtyActive, r->adPropagatedCount,
               r->adOverflowCount, passed);
    } else {
        printf("=== 嵌套 accessed/dirty ===\n");
        printf("  L1 的 EPT12 指针带上了 accessed/dirty 位（EPTP bit 6）。\n");
        printf("  L2 跑过      : %s\n",
               r->l2Reached ? "是" : "**否 —— 带上 A/D 之后进不去了**");
        printf("  请求到达     : %s\n",
               r->l1RequestedAccessedDirty ? "是" : "**否**");
        printf("  正在维护     : %s\n",
               r->accessedDirtyActive
                   ? "是（EPTP bit 6 已置，退出时折回 EPT12）"
                   : "**否 —— 处理器不支持，或记录表溢出**");
        printf("  已折回条数   : %lu   溢出次数 : %lu%s\n",
               r->adPropagatedCount, r->adOverflowCount,
               (r->adOverflowCount != 0UL)
                   ? "  **溢出后已关闭维护：半套传播比没有更糟**"
                   : "");
        printf("  => %s\n", passed ? "**PASS**" : "FAIL");
        printf("\n  判据：三格缺一不可。「L2 跑过」不够 —— 不维护 A/D 也一样跑得\n"
               "        起来；「请求到达」也不够 —— 那只说明请求进了驱动。只有\n"
               "        「正在维护」为是，才意味着硬件在置位而我们会把它折回 L1\n"
               "        自己的表。折不回去时 L1 读回全零，会跳过来宾真正写过的页。\n");
    }
    return passed ? 0 : 2;
}

static int doNestedProbe(HANDLE h, int asJson, int allProcessors)
{
    KSWORD_ARK_HVM_NESTED_PROBE_REQUEST req;
    KSWORD_ARK_HVM_NESTED_PROBE_RESPONSE rsp;
    DWORD returned = 0;
    BOOL ok;
    unsigned long i;
    int failed = 0;

    memset(&req, 0, sizeof(req));
    req.version = KSWORD_ARK_HVM_NESTED_PROBE_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
    if (allProcessors) {
        req.flags |= KSWORD_ARK_HVM_NESTED_PROBE_FLAG_ALL_PROCESSORS;
    }
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    memset(&rsp, 0, sizeof(rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PROBE,
                         &req, (DWORD)sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL);
    if (returned < sizeof(rsp)) {
        fprintf(stderr,
                "NESTED_PROBE IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
                (int)ok, returned, GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"nested-probe\",\"status\":%lu,\"rows\":%lu,\"row\":[",
               rsp.status, rsp.returnedRows);
        for (i = 0; i < rsp.returnedRows &&
                    i < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++i) {
            const KSWORD_ARK_HVM_NESTED_PROBE_ROW* r = &rsp.rows[i];
            printf("%s{\"cpu\":%lu,\"status\":%lu,\"vmxon\":%lu,"
                   "\"vmptrld\":%lu,\"vmwrite\":%lu,\"vmread\":%lu,"
                   "\"vmptrst\":%lu,\"vmxoff\":%lu,\"vmreadMatched\":%lu,"
                   "\"vmptrstMatched\":%lu,\"vmlaunch\":%lu,\"l2Reached\":%lu,"
                   "\"ept12Armed\":%lu,\"shadowFill\":%lu,\"shadowDeny\":%lu,"
                   "\"shadowExhaustion\":%lu,\"dispatched\":%llu,"
                   "\"l2ExitReason\":\"0x%llX\",\"l2GuestRip\":\"0x%llX\","
                   "\"lastInstructionError\":%lu,"
                   /*
                    * The fields used as criteria must be included in the record.
                    *
                    * Without them, the archived record is just a pass=1 — where this round's
                    * PASS relied on "L2 stopped at +12" and "bitmap address non-zero". When
                    * reviewing an old record later, missing these fields forces a re-run.
                    */
                   "\"l2RipOffset\":%llu,\"vmcs02MsrBitmap\":\"0x%llX\","
                   "\"vmcs02Primary\":\"0x%08lX\",\"mergeComplete\":%lu,"
                   "\"l1UsesMsrBitmap\":%lu,\"msrReflected\":%llu,"
                   "\"msrHandled\":%llu,\"ioReflected\":%llu,"
                   "\"ioHandled\":%llu,"
                   /* Similarly: switching between two vmcs12 instances is now one of the criteria. */
                   "\"vmcsSwitchResult\":%lu,\"vmcsSwitchMatched\":%lu,"
                   "\"vmcsSwitchValueA\":\"0x%llX\","
                   "\"vmcsSwitchValueB\":\"0x%llX\","
                   "\"vmcs12DepthRegions\":%lu,"
                   "\"vmcs12DepthSurvived\":%lu,"
                   "\"vmcs12DepthMask\":\"0x%llX\","
                   "\"vmcs12EvictionDelta\":%lu,"
                   /* Capability filtering: the value the guest reads now, which serves as the criterion. */
                   "\"guestVmxProcbased2\":\"0x%016llX\","
                   "\"guestVmxEptVpidCap\":\"0x%016llX\","
                   /* Newly added fields are passed through: the criteria depend on these fields. */
                   "\"vmcs02TscOffset\":\"0x%016llX\","
                   "\"vmcs02EntryMsrLoadAddress\":\"0x%016llX\","
                   "\"vmcs02EntryMsrLoadCount\":%lu,"
                   "\"vmcs02ExitMsrStoreAddress\":\"0x%016llX\","
                   "\"vmcs02ExitMsrStoreCount\":%lu,"
                   "\"inveptResult\":%lu,\"shadowGenerationAdvanced\":%lu,"
                   "\"hostStateChecks\":%lu,"
                   "\"pass\":%d}",
                   (i == 0) ? "" : ",",
                   r->processorIndex, r->status, r->vmxonResult,
                   r->vmptrldResult, r->vmwriteResult, r->vmreadResult,
                   r->vmptrstResult, r->vmxoffResult, r->vmreadMatched,
                   r->vmptrstMatched, r->vmlaunchResult, r->l2Reached,
                   r->ept12Armed, r->shadowFillCount, r->shadowDenyCount,
                   r->shadowExhaustionCount, r->dispatchedInstructions,
                   r->l2ExitReason, r->l2GuestRip,
                   r->lastInstructionError,
                   r->l2RipOffset, r->vmcs02MsrBitmap,
                   r->vmcs02PrimaryControls, r->bitmapMergeComplete,
                   r->l1UsesMsrBitmap, r->l2MsrExitsReflected,
                   r->l2MsrExitsHandled, r->l2IoExitsReflected,
                   r->l2IoExitsHandled,
                   r->vmcsSwitchResult, r->vmcsSwitchMatched,
                   r->vmcsSwitchValueA, r->vmcsSwitchValueB,
                   r->vmcs12DepthRegions, r->vmcs12DepthSurvived,
                   r->vmcs12DepthMask, r->vmcs12EvictionDelta,
                   r->guestVmxProcbased2, r->guestVmxEptVpidCap,
                   r->vmcs02TscOffset,
                   r->vmcs02EntryMsrLoadAddress, r->vmcs02EntryMsrLoadCount,
                   r->vmcs02ExitMsrStoreAddress, r->vmcs02ExitMsrStoreCount,
                   r->inveptResult, r->shadowGenerationAdvanced, r->hostStateChecks,
                   nestedProbeRowPassed(r));
        }
        printf("]}\n");
    } else {
        printf("\n=== 嵌套 VMX 自检（客户机上下文里真的执行 VMX 指令）===\n");
        printf("  整体 status : %lu (%s)   跑了 %lu 个处理器\n",
               rsp.status, nestedProbeStatusName(rsp.status),
               rsp.returnedRows);
        for (i = 0; i < rsp.returnedRows &&
                    i < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++i) {
            printNestedProbeRow(&rsp.rows[i]);
        }
        printf("\n  判据：每一行都要 VMXON/VMPTRLD/VMWRITE/VMREAD/VMPTRST 全成功、\n"
               "        读回逐位相同、指针相符、「L2 跑过」为是，且终止退出是\n"
               "        **第二条 RDMSR（原因 31，停在 +12）并被投递给 L1**。\n"
               "        L2 先读一个 L1 位图里清着的 MSR（必须放行），再读一个置着的\n"
               "        （必须退出）；两种结局都产生退出，只有停在哪里能区分处理器\n"
               "        查的是 L1 那张位图还是\"全部拦截\"的回退页。停在 +5 就是回退，\n"
               "        走到 +14 就是 MSR 拦截根本没发生。\n"
               "        还要求**两份 vmcs12 交替之后各自的字段都还在**：写 A、写 B、\n"
               "        读 A、读 B，只建模一份的派发器会把 B 的值或零当成 A 的还回来。\n"
               "        真 hypervisor 每个 vCPU 至少一份 VMCS 且不停 VMPTRLD 切换，\n"
               "        字段活不过一次切换就托不住它们。\n"
               "        还要超出缓存容量并逐份读回：缓存挤出计数必须增长，所有区域的\n"
               "        独有字段都必须保留，存活掩码全部置位。区域页负责保存状态，\n"
               "        缓存被挤出不能让 VMCS 的字段丢失。\n"
               "        最后一格是**能力过滤**：来宾自己 RDMSR 读回来的能力里，VPID、\n"
               "        VMFUNC、VMCS shadowing 必须已经收掉 —— 这三样的 vmcs02 字段我们\n"
               "        一个都不拷，宣告了就是答应做不到的事，而 L1 照着开之后整条路\n"
               "        上不会有任何一处报错。对照 status 里的 EPT/VPID cap（那是驱动\n"
               "        加载时采的硬件真值），两个数不一样才说明过滤是活的。\n"
               "        INVVPID 指令的类型 0/1/2 按白名单保留，与 enable-VPID 控制位\n"
               "        分开判定；类型 3 和白名单以外的 EPT 能力不得宣告。\n"
               "        还要求 L1 写进 vmcs12 的 **TSC 偏移与 MSR 载入表真的到了\n"
               "        vmcs02**：偏移比的是具体常量而非非零，载入表是真表且计数为 1\n"
               "        ——这一行 PASS 就意味着 VM entry 带着这张表成功了，也就是处理器\n"
               "        确实走了 L1 那张表。MSR 区的计数字段无条件生效，没有任何能力位\n"
               "        能表示「我不支持」，所以不拷就是**静默地不装**。\n"
               "        多核模式下，**任何一行 FAIL 就是整体 FAIL** —— 这正是它要验的东西。\n");
    }
    for (i = 0; i < rsp.returnedRows &&
                i < KSWORD_ARK_HVM_NESTED_PROBE_MAX_ROWS; ++i) {
        if (!nestedProbeRowPassed(&rsp.rows[i])) { failed = 1; }
    }
    return (rsp.returnedRows > 0 && !failed) ? 0 : 2;
}

static const char* processStatusName(unsigned long s)
{
    switch (s) {
    case KSWORD_ARK_HVM_PROCESS_STATUS_OK:                    return "OK";
    case KSWORD_ARK_HVM_PROCESS_STATUS_INVALID_REQUEST:       return "INVALID_REQUEST";
    case KSWORD_ARK_HVM_PROCESS_STATUS_CONFIRMATION_REQUIRED: return "CONFIRMATION_REQUIRED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED:          return "NOT_PREPARED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED:
        return "REQUIRES_RESIDENT_STOPPED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_PROCESS_LOOKUP_FAILED: return "PROCESS_LOOKUP_FAILED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_TABLE_FULL:            return "TABLE_FULL";
    case KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND:             return "NOT_FOUND";
    case KSWORD_ARK_HVM_PROCESS_STATUS_ALREADY_ARMED:         return "ALREADY_ARMED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED: return "CR3_TRACKING_REQUIRED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED:  return "EPTP_SWITCH_REQUIRED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_TRANSLATION_FAILED:    return "TRANSLATION_FAILED";
    case KSWORD_ARK_HVM_PROCESS_STATUS_PROTECTED_TARGET:      return "PROTECTED_TARGET";
    default:                                                  return "UNKNOWN";
    }
}

static const char* processDispositionName(unsigned long d)
{
    switch (d) {
    case KSWORD_ARK_HVM_PROCESS_OP_FREEZE:    return "冻结";
    case KSWORD_ARK_HVM_PROCESS_OP_TERMINATE: return "结束";
    /* Released, but the hierarchy has not been reclaimed; it is only cleared when the resident hypervisor stops. */
    case KSWORD_ARK_HVM_PROCESS_DISPOSITION_RELEASED: return "已解除";
    default:                                  return "?";
    }
}

static int processIoctl(HANDLE h,
                        KSWORD_ARK_HVM_PROCESS_REQUEST* req,
                        KSWORD_ARK_HVM_PROCESS_RESPONSE* rsp)
{
    DWORD returned = 0;
    BOOL ok;

    req->version = KSWORD_ARK_HVM_PROCESS_PROTOCOL_VERSION;
    req->size = (unsigned long)sizeof(*req);
    memset(rsp, 0, sizeof(*rsp));
    ok = DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_PROCESS, req, (DWORD)sizeof(*req),
                         rsp, (DWORD)sizeof(*rsp), &returned, NULL);
    if (returned >= sizeof(*rsp)) {
        /* Use the response if complete, regardless of whether ok is true or false. */
        return 0;
    }
    fprintf(stderr, "PROCESS IOCTL 无完整响应：ok=%d returned=%lu win32=%lu\n",
            (int)ok, returned, GetLastError());
    return 1;
}

/* ——— Memory monitoring (first access attribution) ——— */

static const char* watchStateName(unsigned long state)
{
    switch (state) {
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED: return "armed";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_TRIGGERED: return "triggered";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED: return "disarmed";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED: return "invalidated";
    case KSWORD_ARK_HVM_EPT_WATCH_STATE_FAULTED: return "faulted";
    default: break;
    }
    return "none";
}

static const char* watchHitStatusName(unsigned long status)
{
    switch (status) {
    case KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED: return "published";
    /*
     * "Hit but event lost" and "Never hit" appear identical in the event list, yet their conclusions are exactly opposite.
     * Automated criteria must distinguish between these two cases, so it is given a distinct name rather than a null value.
     */
    case KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST: return "event-lost";
    default: break;
    }
    return "none";
}

static const char* watchRuleStatusName(unsigned long status)
{
    switch (status) {
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_OK: return "ok";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST: return "invalid-request";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED: return "confirmation-required";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED: return "not-prepared";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND: return "not-found";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL: return "table-full";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED: return "split-failed";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL: return "partial";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_UNIMPLEMENTED: return "unimplemented";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_MULTIPROCESSOR_UNSAFE: return "multiprocessor-unsafe";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT: return "leaf-conflict";
    case KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN: return "resident-frozen";
    default: break;
    }
    return "unknown";
}

static const char* watchConflictName(unsigned long kind)
{
    switch (kind) {
    case KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW: return "view";
    case KSWORD_ARK_HVM_WATCH_CONFLICT_RULE: return "rule";
    case KSWORD_ARK_HVM_WATCH_CONFLICT_WATCH: return "watch";
    default: break;
    }
    return "none";
}

/* Write the access mask in rwx format, using '-' for unset bits. */
static void watchAccessText(unsigned long access, char out[4])
{
    out[0] = (access & KSWORD_ARK_HVM_EPT_ACCESS_READ) ? 'r' : '-';
    out[1] = (access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) ? 'w' : '-';
    out[2] = (access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) ? 'x' : '-';
    out[3] = '\0';
}

static void printWatchRow(const KSWORD_ARK_HVM_EPT_WATCH_ROW* row, int asJson)
{
    char requested[4];
    char effective[4];

    watchAccessText(row->requestedAccess, requested);
    watchAccessText(row->effectiveAccess, effective);
    if (asJson) {
        printf("{\"watchId\":%lu,\"state\":\"%s\",\"addressKind\":\"%s\","
               "\"requestedAddress\":\"0x%016llX\",\"requestedLength\":%llu,"
               "\"physicalPage\":\"0x%016llX\",\"effectiveBytes\":4096,"
               "\"requestedAccess\":\"%s\",\"effectiveAccess\":\"%s\","
               "\"hitCount\":%lu,\"lastHitSequence\":%llu,"
               "\"lastHitStatus\":\"%s\",\"armedGeneration\":%lu,"
               "\"lastHitRip\":\"0x%016llX\",\"lastHitRsp\":\"0x%016llX\","
               "\"lastHitCr3\":\"0x%016llX\",\"lastHitGpa\":\"0x%016llX\","
               "\"lastHitGla\":\"0x%016llX\",\"lastHitGlaValid\":%s,"
               "\"lastHitRangeMatch\":%s,\"lastHitCpu\":\"%u:%u\"}",
               row->watchId, watchStateName(row->state),
               row->addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                   ? "virtual" : "physical",
               row->requestedAddress, row->requestedLength,
               row->physicalPage, requested, effective,
               row->hitCount, row->lastHitSequence,
               watchHitStatusName(row->lastHitStatus), row->armedGeneration,
               row->lastHitRip, row->lastHitRsp, row->lastHitCr3,
               row->lastHitGuestPhysicalAddress, row->lastHitGuestLinearAddress,
               row->lastHitGuestLinearValid ? "true" : "false",
               row->lastHitRangeMatch ? "true" : "false",
               (unsigned)row->lastHitProcessorGroup,
               (unsigned)row->lastHitProcessorNumber);
        return;
    }
    printf("  #%-4lu %-11s  %s 0x%016llX (%llu B)  页=0x%016llX(4096 B)"
           "  请求=%s 实际=%s  命中=%lu(%s)\n",
           row->watchId, watchStateName(row->state),
           row->addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
               ? "VA" : "PA",
           row->requestedAddress, row->requestedLength, row->physicalPage,
           requested, effective, row->hitCount,
           watchHitStatusName(row->lastHitStatus));
    if (row->hitCount != 0UL) {
        printf("        rip=0x%016llX rsp=0x%016llX cr3=0x%016llX cpu=%u:%u seq=%llu\n",
               row->lastHitRip, row->lastHitRsp, row->lastHitCr3,
               (unsigned)row->lastHitProcessorGroup,
               (unsigned)row->lastHitProcessorNumber,
               row->lastHitSequence);
        printf("        gpa=0x%016llX gla=0x%016llX(%s) 落在请求范围内=%s\n",
               row->lastHitGuestPhysicalAddress,
               row->lastHitGuestLinearAddress,
               row->lastHitGuestLinearValid ? "有效" : "处理器未报告",
               row->lastHitGuestLinearValid
                   ? (row->lastHitRangeMatch ? "是" : "否")
                   : "无法判断");
    }
}

/* Issue a watch operation once and print the result. */
static int doWatch(HANDLE h, unsigned long op, unsigned long watchId,
                   unsigned long long physicalPage,
                   unsigned long long requestedAddress,
                   unsigned long long requestedLength,
                   unsigned long access, unsigned long addressKind, int asJson)
{
    KSWORD_ARK_HVM_EPT_RULE_REQUEST req;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    DWORD returned = 0;
    unsigned long i = 0UL;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = op;
    /*
     * Each operation **only** fills its own specific fields; all others must be zeroed.
     *
     * The driver enforces a "field must be empty" contract for REMOVE, REARM, and WATCH_QUERY: if a value is present, the caller
     * treated it as a different operation, and the entire request is rejected as invalid parameters. Unconditionally filling these
     * fields appears simpler but causes all three operations to be rejected constantly, resulting in a single visible error: win32=87.
     */
    if (op == KSWORD_ARK_HVM_EPT_RULE_ADD) {
        req.deniedAccess = access;
        req.physicalAddress = physicalPage;
        /* A monitoring constant one page: the driver side also rejects other values. */
        req.pageCount = 1ULL;
        req.requestedAddress = requestedAddress;
        req.requestedLength = requestedLength;
        req.requestedAccess = access;
        req.addressKind = addressKind;
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE;
    } else if (op == KSWORD_ARK_HVM_EPT_RULE_REARM ||
               op == KSWORD_ARK_HVM_EPT_RULE_REMOVE) {
        req.ruleId = watchId;
    }
    if (op != KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
        req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    }
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        fprintf(stderr, "EPT_RULE 下发失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (asJson) {
        printf("{\"kind\":\"watch\",\"operation\":%lu,\"status\":%lu,"
               "\"statusName\":\"%s\",\"lastStatus\":\"0x%08lX\","
               "\"generation\":%lu,\"watchCount\":%lu,"
               "\"conflictOwnerKind\":\"%s\",\"conflictOwnerId\":%lu,"
               "\"watches\":[",
               op, rsp.status, watchRuleStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.generation,
               rsp.watchRowCount,
               watchConflictName(rsp.conflictOwnerKind), rsp.conflictOwnerId);
        if (rsp.returnedWatchRows != 0UL) {
            for (i = 0UL; i < rsp.returnedWatchRows &&
                          i < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS; ++i) {
                if (i != 0UL) { printf(","); }
                printWatchRow(&rsp.watchRows[i], 1);
            }
        } else if (rsp.watch.watchId != 0UL) {
            printWatchRow(&rsp.watch, 1);
        }
        printf("]}\n");
    } else {
        printf("\n=== R-1 内存监视 ===\n");
        printf("  status       : %lu (%s)  lastStatus=0x%08lX  代次=%lu\n",
               rsp.status, watchRuleStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.generation);
        if (rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT) {
            printf("  ** 这一页已经被 %s #%lu 占着 **：一页只能有一个主人。\n",
                   watchConflictName(rsp.conflictOwnerKind), rsp.conflictOwnerId);
            printf("     先把它撤掉再装监视；这里不会静默覆盖别人的叶项。\n");
        }
        if (rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN) {
            printf("  ** 常驻运行中 **：退出路径不取 PASSIVE 锁就扫规则表，所以\n");
            printf("     整张表在常驻期间冻结。先 stop，装完监视再 resident。\n");
        }
        if (rsp.returnedWatchRows != 0UL) {
            printf("  表内条数     : %lu\n", rsp.watchRowCount);
            for (i = 0UL; i < rsp.returnedWatchRows &&
                          i < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS; ++i) {
                printWatchRow(&rsp.watchRows[i], 0);
            }
        } else if (rsp.watch.watchId != 0UL) {
            printWatchRow(&rsp.watch, 0);
        } else if (op == KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
            printf("  （表里没有任何监视）\n");
        }
        printf("\n  监视单位是 4 KiB 物理页，不是上面的请求长度；命中不阻止访问。\n");
    }
    return rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK ? 0 : 2;
}

/* Translate a kernel virtual address to a physical address. Returns non-zero on failure. */
static int watchTranslate(HANDLE h, unsigned long long virtualAddress,
                          unsigned long long* physicalOut)
{
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    DWORD returned = 0;

    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = virtualAddress;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
        mrsp.physicalAddress == 0ULL) {
        fprintf(stderr, "翻译失败：status=%lu nt=0x%08lX win32=%lu\n",
                mrsp.status, (unsigned long)mrsp.ntStatus, GetLastError());
        return 1;
    }
    *physicalOut = mrsp.physicalAddress;
    return 0;
}

/*
 * End-to-end self-test for the first access to the watch.
 *
 * Run all checks for Issue #195, Section 22, Item 1 (WRITE First-touch) within a single process without
 * writing a separate test driver: allocate and lock a page, write to it, and verify the hit context.
 *
 * Why must it be the same process: RIP criterion. To prove 'the recorded RIP is that write instruction',
 * a known write instruction address must be available for comparison; doing this across processes only
 * allows module-granularity comparison, which cannot answer 'whether a wrong instruction was recorded'.
 *
 * Use a four-state check instead of a boolean:
 *   PASS: Actual execution passed with evidence. FAIL: Logic error.
 *   BLOCKED: Cannot determine status on this machine (not resident, pages
 *   cannot be split, or capability insufficient)—not a code issue, but must
 *            not be recorded as PASS. 'Cannot determine' and 'execution failed' must
 * be separated; otherwise, BLOCKED cases may be treated as FAIL (stalling
 * indefinitely without turning green) or as PASS (masking a real issue).
 */

/*
 * Case limit.
 *
 * The version written as 12 actually filled 13 entries, causing watchCase to write past the end of the array and
 * triggering a 0xC0000005 exception directly on the target machine. Reserve margin and add a guard in watchCase: the sole
 * purpose of this code is to produce trusted criteria; a self-crashing self-test yields 'no reading', not 'failure'.
 */
#define KSW_WATCH_SELFTEST_CASES 16U

typedef struct KswWatchCase
{
    const char* name;
    const char* expectation;
    const char* verdict;
    const char* remark;
    unsigned long long observed;
} KswWatchCase;

/*
 * The type of access being tested during self-check.
 *
 * The 'kind' field in all three self-test JSONs is 'watch-selftest', so the acceptance script cannot distinguish between item 1
 * and item 3 based on kind alone. Explicitly including the access type in the output allows a single record to identify which
 * item it is evidence for; otherwise, pasting the three results side-by-side yields identical output, providing no evidence.
 */
static const char* watchSelfTestAccessName(unsigned long access)
{
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL) { return "execute"; }
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) { return "write"; }
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) { return "read"; }
    return "none";
}

static void watchCase(KswWatchCase* slot, const char* name,
                      const char* expectation, int ok,
                      unsigned long long observed, const char* remark)
{
    /* A buffer overflow is worse than any single check: it yields no reading at all, rather than a failed reading. */
    if (slot == NULL) { return; }
    slot->name = name;
    slot->expectation = expectation;
    slot->verdict = ok ? "PASS" : "FAIL";
    slot->observed = observed;
    slot->remark = remark;
}

/* Read the count of resident processors. On failure, return 0xFFFFFFFF so the caller can distinguish a read failure from a zero count. */
static unsigned long watchResidentCount(HANDLE h)
{
    KSWORD_ARK_QUERY_HVM_REQUEST qreq;
    KSWORD_ARK_QUERY_HVM_RESPONSE qrsp;
    DWORD returned = 0;

    memset(&qreq, 0, sizeof(qreq));
    memset(&qrsp, 0, sizeof(qrsp));
    qreq.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    qreq.size = (unsigned long)sizeof(qreq);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_QUERY_HVM, &qreq, sizeof(qreq),
                         &qrsp, (DWORD)sizeof(qrsp), &returned, NULL)) {
        return 0xFFFFFFFFUL;
    }
    return qrsp.residentProcessorCount;
}

/* Issue a watch operation and return the response to the caller as-is. Return 0 to indicate the IOCTL itself succeeded. */
static int watchIoctl(HANDLE h, unsigned long op, unsigned long watchId,
                      unsigned long long physicalPage,
                      unsigned long long requestedAddress,
                      unsigned long long requestedLength,
                      unsigned long access,
                      KSWORD_ARK_HVM_EPT_RULE_RESPONSE* rsp)
{
    KSWORD_ARK_HVM_EPT_RULE_REQUEST req;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(rsp, 0, sizeof(*rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = op;
    /* Same logic as DoWatch: only fill fields permitted for this operation; leave the rest zeroed. */
    if (op == KSWORD_ARK_HVM_EPT_RULE_ADD) {
        req.deniedAccess = access;
        req.physicalAddress = physicalPage;
        req.pageCount = 1ULL;
        req.requestedAddress = requestedAddress;
        req.requestedLength = requestedLength;
        req.requestedAccess = access;
        req.addressKind = KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL;
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_WATCH_ONCE;
    } else if (op == KSWORD_ARK_HVM_EPT_RULE_REARM ||
               op == KSWORD_ARK_HVM_EPT_RULE_REMOVE) {
        req.ruleId = watchId;
    }
    if (op != KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY) {
        req.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
        req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    }
    return DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EPT_RULE, &req, sizeof(req),
                           rsp, (DWORD)sizeof(*rsp), &returned, NULL) ? 0 : 1;
}

/* Search for a watch entry in the entire table. Return NULL if not found. */
static const KSWORD_ARK_HVM_EPT_WATCH_ROW* watchFindRow(
    const KSWORD_ARK_HVM_EPT_RULE_RESPONSE* rsp, unsigned long watchId)
{
    unsigned long i;

    for (i = 0UL; i < rsp->returnedWatchRows &&
                  i < KSWORD_ARK_HVM_MAX_EPT_WATCH_ROWS; ++i) {
        if (rsp->watchRows[i].watchId == watchId) {
            return &rsp->watchRows[i];
        }
    }
    return NULL;
}

/*
 * Advance the lifecycle one step within the self-check.
 *
 * Self-check must start and stop the resident component itself: watch, like other EPT rules, can only be installed when the resident component is active
 * (the rule table is frozen during the resident's lifetime because scanning it without acquiring a PASSIVE lock on the exit path would be unsafe). Since
 * hits only occur while the resident is running, delegating these two tasks to the caller to manually interleave means the decision criteria depend on a
 * series of unverified preconditions. Missing any single step results in an outcome that appears as 'feature not working' but is actually a silent failure.
 */
static int watchLifecycle(HANDLE h, unsigned long command, unsigned long flags)
{
    KSWORD_ARK_CONTROL_HVM_REQUEST req;
    KSWORD_ARK_CONTROL_HVM_RESPONSE rsp;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(&rsp, 0, sizeof(rsp));
    KswordArkHvmBuildControlRequest(&req, command, flags, 0UL, 0UL);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_CONTROL_HVM, &req, sizeof(req),
                         &rsp, (DWORD)sizeof(rsp), &returned, NULL)) {
        return 1;
    }
    return rsp.status == KSWORD_ARK_HVM_CONTROL_STATUS_OK ? 0 : 2;
}

/*
 * End-to-end self-test, parameterized by access type.
 *
 * Issue #195, Section 22, items 1/2/3 (WRITE/READ/EXECUTE first access) follow the same flow with different access
 * types, so they share a single implementation rather than being copied three times. Copying them separately would
 * lead to three divergent implementations that should remain aligned, especially the two boundary criteria: 'hit does
 * not block access' and 'hit does not end resident state', which must be identical across all three access types.
 *
 * Access takes KSWORD_ARK_HVM_EPT_ACCESS_*. EXECUTE goes to executable pages; others go to data pages.
 * The trigger method varies (write one byte / read one byte / call once), but the criteria table is the same.
 */
static int doWatchSelfTestAccess(HANDLE h, int asJson, unsigned long access)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_MEMORY_REQUEST mreq;
    KSWORD_ARK_HVM_MEMORY_RESPONSE mrsp;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long residentBefore = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned long watchId = 0UL;
    unsigned long firstHitCount = 0UL;
    unsigned long secondHitCount = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    int failures = 0;
    int blocked = 0;
    int executeWatch = 0;
    /* volatile: The access triggering the read must never be optimized away, otherwise a hit will never occur. */
    volatile unsigned char observed = 0U;
    DWORD returned = 0;

    memset(cases, 0, sizeof(cases));

    /*
     * --- 0. Stop the resident hypervisor first ---
     *
     * This sequence is forced by the mechanism, not preference: the rule table is frozen during the resident phase, so 'watch'
     * can only be installed while stopped; since hits occur only while running, it must be restarted after installation.
     * Completing this self-check cycle ensures the criteria do not depend on the caller remembering to interleave these steps.
     */
    if (watchResidentCount(h) != 0UL) {
        (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    }
    /* Resource preparation and per-core self-tests are prerequisites for starting the resident hypervisor; repeating them is idempotent. */
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_PREPARE,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);

    /* --- 1. Allocate a page of private memory and map it to a real physical page --- */
    executeWatch = (access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) != 0UL;
    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE,
        executeWatch ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);
    if (page == NULL) {
        fprintf(stderr, "VirtualAlloc 失败：win32=%lu\n", GetLastError());
        return 1;
    }
    (void)VirtualLock((LPVOID)page, 4096);
    /* Write once to ensure the page is truly committed; this write occurs **before installing the monitor** and should not be recorded as a hit. */
    page[0] = 0xA5U;
    if (executeWatch) {
        /*
         * 0xC3 = ret. For execution monitoring to work, there must be a valid, callable target. The 'shortest valid function'
         * is exactly a ret instruction: it touches no registers, and the state after returning is identical to the state
         * before the call. Thus, the criterion 'original execution completes normally' is not polluted by side effects.
         */
        page[0] = 0xC3U;
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)page, 4096);
    }

    memset(&mreq, 0, sizeof(mreq));
    memset(&mrsp, 0, sizeof(mrsp));
    mreq.version = KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION;
    mreq.size = (unsigned long)sizeof(mreq);
    mreq.operation = KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE;
    mreq.flags = KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED;
    mreq.confirmationToken = KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN;
    mreq.address = (unsigned long long)(ULONG_PTR)page;
    mreq.length = 1UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_MEMORY, &mreq, sizeof(mreq),
                         &mrsp, (DWORD)sizeof(mrsp), &returned, NULL) ||
        mrsp.status != KSWORD_ARK_HVM_MEMORY_STATUS_OK ||
        mrsp.physicalAddress == 0ULL) {
        fprintf(stderr, "TRANSLATE 失败：status=%lu win32=%lu\n",
                mrsp.status, GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    physical = mrsp.physicalAddress;
    physicalPage = physical & ~0xFFFULL;

    /* --- 2. Install a write monitor rule */
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   access, &rsp) != 0) {
        fprintf(stderr, "watch ADD 下发失败：win32=%lu\n", GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    if (rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        /*
         * Installation failures fall into two categories: capability/occupancy issues are BLOCKED (unresolvable on this
         * machine), while others are FAIL. Merging them into a single 'failure' state would either prevent a machine that
         * cannot be installed from ever turning green, or allow a genuine defect to be dismissed as an environmental issue.
         */
        blocked = rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_RESIDENT_FROZEN ||
                  rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT ||
                  rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED ||
                  rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED;
        if (asJson) {
            printf("{\"kind\":\"watch-selftest\",\"access\":\"%s\","
                   "\"verdict\":\"%s\",\"reason\":\"add-refused\",\"status\":%lu,"
                   "\"statusName\":\"%s\",\"cases\":[]}\n",
                   watchSelfTestAccessName(access),
                   blocked ? "BLOCKED" : "FAIL", rsp.status,
                   watchRuleStatusName(rsp.status));
        } else {
            printf("\n=== 内存监视端到端自检（%s）===\n",
                   watchSelfTestAccessName(access));
            printf("  %s：装不上监视，status=%lu (%s)\n",
                   blocked ? "BLOCKED" : "FAIL", rsp.status,
                   watchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return blocked ? 3 : 2;
    }
    watchId = rsp.ruleId;

    watchCase(&cases[n++], "安装成功并分配了非零编号",
              "status=OK 且 watchId != 0",
              watchId != 0UL, watchId, NULL);
    /*
     * Normalization criteria are divided into two types because the architecture itself is divided into two types.
     *
     * Refusing a read necessarily refuses a write (EPT does not support leaf entries that are readable but not writable); if
     * execute-only capability is absent, execution must also be refused. Write and execute are independently valid and do not trigger
     * any relaxation. Combining these into a single assertion would either make READ always fail or allow WRITE's relaxation to pass
     * through—the latter being the cause of silent defects where the monitored range is silently larger than the user expects.
     */
    if ((access & KSWORD_ARK_HVM_EPT_ACCESS_READ) != 0UL) {
        watchCase(&cases[n++], "请求读时实际掩码必然连带写",
                  "effective 包含 READ|WRITE，且是 requested 的超集",
                  (rsp.watch.effectiveAccess &
                      (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                       KSWORD_ARK_HVM_EPT_ACCESS_WRITE)) ==
                      (KSWORD_ARK_HVM_EPT_ACCESS_READ |
                       KSWORD_ARK_HVM_EPT_ACCESS_WRITE) &&
                  (rsp.watch.effectiveAccess & access) == access,
                  rsp.watch.effectiveAccess,
                  "EPT 不存在可写不可读的叶 —— 界面必须把请求与实际两栏都摆出来");
    } else {
        watchCase(&cases[n++], "实际生效的访问掩码等于请求的",
                  "写/执行监视不触发架构归一化（只有拒绝读才会）",
                  rsp.watch.effectiveAccess == access,
                  rsp.watch.effectiveAccess, NULL);
    }
    watchCase(&cases[n++], "武装后状态为 ARMED",
              "state = 1 (armed)",
              rsp.watch.state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED,
              rsp.watch.state, NULL);
    watchCase(&cases[n++], "装监视之前的那次访问没有被记成命中",
              "hitCount = 0",
              rsp.watch.hitCount == 0UL, rsp.watch.hitCount, NULL);

    /*
     * --- 3. Start resident, then trigger a write ---
     *
     * residentBefore is sampled here, not at the start of self-check: the acceptance criteria asks whether the hit caused the processor to
     * exit virtualization. Therefore, one must compare the readings before and after the hit, rather than comparing against the reading at
     * the start of self-check—the latter would incorrectly include the processor exit caused by the self-check itself in the delta.
     */
    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest\",\"access\":\"%s\","
                   "\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n",
                   watchSelfTestAccessName(access));
        } else {
            printf("\n=== 内存监视端到端自检（%s）===\n",
                   watchSelfTestAccessName(access));
            printf("  BLOCKED：监视装上了，但这台机器起不了常驻，命中路径问不出来。\n");
        }
        (void)watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL,
                         0ULL, 0ULL, 0UL, &rsp);
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    residentBefore = watchResidentCount(h);
    /* The address triggering that instruction is the RIP criterion. */
    if (executeWatch) {
        ((void (*)(void))(void*)page)();
    } else if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        page[0] = 0x5AU;
    } else {
        observed = page[0];
    }

    /* --- 4. Read back and verify item by item --- */
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) != 0) {
        fprintf(stderr, "watch QUERY 下发失败：win32=%lu\n", GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    row = watchFindRow(&rsp, watchId);
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 2;
    }
    firstHitCount = row->hitCount;

    watchCase(&cases[n++], "被监视的访问触发了一次命中",
              "hitCount = 1",
              row->hitCount == 1UL, row->hitCount, NULL);
    watchCase(&cases[n++], "命中后自动解除",
              "state = 3 (disarmed)",
              row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              row->state, NULL);
    watchCase(&cases[n++], "命中的客户物理地址落在被监视的那一页里",
              "gpa & ~0xFFF = 被监视页",
              (row->lastHitGuestPhysicalAddress & ~0xFFFULL) == physicalPage,
              row->lastHitGuestPhysicalAddress, NULL);
    watchCase(&cases[n++], "命中现场记下了非零的 RIP",
              "rip != 0",
              row->lastHitRip != 0ULL, row->lastHitRip, NULL);
    /*
     * GLA criteria have two states.
     *
     * The processor may not report the linear address; in that case, it cannot be said to be correct or incorrect.
     * Treating 'not reported' as FAIL would cause a machine that architecturally does not provide this information to never turn green;
     * Reporting PASS would assert a fact that was never observed, so record these cases separately.
     */
    if (row->lastHitGuestLinearValid) {
        watchCase(&cases[n++], "有效的客户线性地址指向实际被访问的地址",
                  "gla = &page[0]",
                  row->lastHitGuestLinearAddress ==
                      (unsigned long long)(ULONG_PTR)page,
                  row->lastHitGuestLinearAddress, NULL);
    } else {
        cases[n].name = "有效的客户线性地址指向实际被访问的地址";
        cases[n].expectation = "gla = &page[0]";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "处理器这次没报告客户线性地址 —— 问不出来，不是错";
        ++n;
    }
    watchCase(&cases[n++], "事件证据没有丢",
              "lastHitStatus = 1 (published)",
              row->lastHitStatus == KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED,
              row->lastHitStatus,
              "丢了说明事件环被别的退出挤爆，与监视本身是否命中无关");

    /* --- 5. A second access should not generate a new fault. */
    if (executeWatch) {
        ((void (*)(void))(void*)page)();
    } else if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        page[0] = 0xB2U;
    } else {
        observed = page[0];
    }
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
        secondHitCount = row != NULL ? row->hitCount : 0xFFFFFFFFUL;
    } else {
        secondHitCount = 0xFFFFFFFFUL;
    }
    watchCase(&cases[n++], "第二次访问不再产生命中",
              "hitCount 不变",
              secondHitCount == firstHitCount, secondHitCount,
              "一次性监视命中后已经不再拦截，再访问应当完全无感");

    /* --- 6. The access completed and no core stopped running the resident hypervisor --- */
    if (executeWatch) {
        /* Returning to this point is evidence of "execution ultimately completed". */
        watchCase(&cases[n++], "被监视的执行最终真的完成了",
                  "两次调用都正常返回",
                  page[0] == 0xC3U, (unsigned long long)page[0],
                  "命中不阻止访问 —— 这正是它与 ENFORCE 的分界");
    } else if ((access & KSWORD_ARK_HVM_EPT_ACCESS_WRITE) != 0UL) {
        watchCase(&cases[n++], "被监视的写最终真的完成了",
                  "page[0] = 0xB2",
                  page[0] == 0xB2U, (unsigned long long)page[0],
                  "命中不阻止访问 —— 这正是它与 ENFORCE 的分界");
    } else {
        watchCase(&cases[n++], "被监视的读最终真的完成了",
                  "读回装监视前写下的 0xA5",
                  observed == 0xA5U, (unsigned long long)observed,
                  "命中不阻止访问 —— 这正是它与 ENFORCE 的分界");
    }
    residentAfter = watchResidentCount(h);
    watchCase(&cases[n++], "命中没有让任何处理器退出虚拟化",
              "residentAfter = residentBefore",
              residentAfter == residentBefore, residentAfter,
              "这是 WATCH_ONCE 与严格 tripwire 的**根本**区别");

    /*
     * --- 7. Cleanup: Stop the resident component first, then remove monitoring, leaving no residual state on the machine.
     *
     * Order cannot be reversed: the rule table is frozen during residency. Revocation attempts while residency is active are directly
     * rejected, leaving the monitor in the table. The next self-check triggers LEAF_CONFLICT without revealing the root cause.
     */
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    (void)watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL, 0ULL,
                     0ULL, 0UL, &rsp);
    VirtualFree((LPVOID)page, 0, MEM_RELEASE);

    for (i = 0UL; i < n; ++i) {
        if (cases[i].verdict[0] == 'F') { ++failures; }
        if (cases[i].verdict[0] == 'B') { ++blocked; }
    }
    if (asJson) {
        printf("{\"kind\":\"watch-selftest\",\"access\":\"%s\",\"verdict\":\"%s\","
               "\"watchId\":%lu,\"residentBefore\":%lu,\"residentAfter\":%lu,"
               "\"physicalPage\":\"0x%016llX\",\"failures\":%d,\"blocked\":%d,"
               "\"cases\":[",
               watchSelfTestAccessName(access),
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS-WITH-BLOCKED" : "PASS"),
               watchId, residentBefore, residentAfter, physicalPage,
               failures, blocked);
        for (i = 0UL; i < n; ++i) {
            printf("%s{\"name\":", i != 0UL ? "," : "");
            kswordHvmPrintJsonString(cases[i].name);
            printf(",\"expectation\":");
            kswordHvmPrintJsonString(cases[i].expectation);
            printf(",\"verdict\":\"%s\",\"observed\":\"0x%016llX\"",
                   cases[i].verdict, cases[i].observed);
            if (cases[i].remark != NULL) {
                printf(",\"remark\":");
                kswordHvmPrintJsonString(cases[i].remark);
            }
            printf("}");
        }
        printf("]}\n");
    } else {
        printf("\n=== 内存监视端到端自检（%s，watch #%lu，页 0x%016llX）===\n",
               watchSelfTestAccessName(access), watchId, physicalPage);
        printf("  常驻处理器：命中前 %lu，命中后 %lu\n",
               residentBefore, residentAfter);
        for (i = 0UL; i < n; ++i) {
            printf("  [%-7s] %-34s  期望：%s\n", cases[i].verdict,
                   cases[i].name, cases[i].expectation);
            printf("            实测 0x%016llX%s%s\n", cases[i].observed,
                   cases[i].remark != NULL ? "  — " : "",
                   cases[i].remark != NULL ? cases[i].remark : "");
        }
        printf("\n  结论：%s（失败 %d，问不出来 %d，共 %lu 条）\n",
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS（含问不出来的项）" : "PASS"),
               failures, blocked, n);
    }
    /* Exit code: 0 for all passed, 2 for failures, 3 for items that could not be queried without failures. */
    return failures != 0 ? 2 : (blocked != 0 ? 3 : 0);
}

/* Read a batch of events. Return 0 indicates the IOCTL itself succeeded. */
static int watchEventQuery(HANDLE h, unsigned long long afterSequence,
                           KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* rsp)
{
    KSWORD_ARK_HVM_EVENT_QUERY_REQUEST req;
    DWORD returned = 0;

    memset(&req, 0, sizeof(req));
    memset(rsp, 0, sizeof(*rsp));
    req.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    req.size = (unsigned long)sizeof(req);
    req.operation = KSWORD_ARK_HVM_EVENT_QUERY_READ;
    req.maxRows = KSWORD_ARK_HVM_MAX_EVENT_ROWS;
    req.afterSequence = afterSequence;
    return DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_EVENTS, &req, sizeof(req),
                           rsp, (DWORD)sizeof(*rsp), &returned, NULL) ? 0 : 1;
}

/* Print a batch of test case results uniformly; shared by three extended self-checks. */
static int watchReportCases(const char* kind, const char* title,
                            const KswWatchCase* cases, unsigned long n,
                            int asJson, const char* extraJson)
{
    int failures = 0;
    int blocked = 0;
    unsigned long i;

    for (i = 0UL; i < n; ++i) {
        if (cases[i].verdict[0] == 'F') { ++failures; }
        if (cases[i].verdict[0] == 'B') { ++blocked; }
    }
    if (asJson) {
        printf("{\"kind\":\"%s\",\"verdict\":\"%s\",\"failures\":%d,"
               "\"blocked\":%d%s,\"cases\":[", kind,
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS-WITH-BLOCKED" : "PASS"),
               failures, blocked, extraJson != NULL ? extraJson : "");
        for (i = 0UL; i < n; ++i) {
            printf("%s{\"name\":", i != 0UL ? "," : "");
            kswordHvmPrintJsonString(cases[i].name);
            printf(",\"expectation\":");
            kswordHvmPrintJsonString(cases[i].expectation);
            printf(",\"verdict\":\"%s\",\"observed\":\"0x%016llX\"",
                   cases[i].verdict, cases[i].observed);
            if (cases[i].remark != NULL) {
                printf(",\"remark\":");
                kswordHvmPrintJsonString(cases[i].remark);
            }
            printf("}");
        }
        printf("]}\n");
    } else {
        printf("\n=== %s ===\n", title);
        for (i = 0UL; i < n; ++i) {
            printf("  [%-7s] %-38s  期望：%s\n", cases[i].verdict,
                   cases[i].name, cases[i].expectation);
            printf("            实测 0x%016llX%s%s\n", cases[i].observed,
                   cases[i].remark != NULL ? "  — " : "",
                   cases[i].remark != NULL ? cases[i].remark : "");
        }
        printf("\n  结论：%s（失败 %d，问不出来 %d，共 %lu 条）\n",
               failures != 0 ? "FAIL" : (blocked != 0 ? "PASS（含问不出来的项）" : "PASS"),
               failures, blocked, n);
    }
    return failures != 0 ? 2 : (blocked != 0 ? 3 : 0);
}

/* Unified cleanup for stopping resident mode, removing watches, and releasing pages. Order must not be reversed: the table is frozen during resident mode. */
static void watchTeardown(HANDLE h, unsigned long watchId, volatile unsigned char* page)
{
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;

    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    if (watchId != 0UL) {
        (void)watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL,
                         0ULL, 0ULL, 0UL, &rsp);
    }
    if (page != NULL) {
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    }
}

/* Pause the resident component and prepare for its resumption. This sequence must be executed at the start of all three extension self-checks. */
static void watchPrepareResidency(HANDLE h)
{
    if (watchResidentCount(h) != 0UL) {
        (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    }
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_PREPARE,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
}

/*
 * Allocate a page, map it, lock it, and translate it to its physical page. Returns non-zero on failure.
 *
 * The 'landing' step cannot be skipped: VirtualAlloc only commits; pages with no bytes written may lack
 * physical frames during translation. Mapping a monitor to such a translated address targets a page unrelated
 * to the VA, leading to a scenario where the address installs and reads back successfully but never hits.
 */
static int watchAllocatePage(HANDLE h, volatile unsigned char** pageOut,
                             unsigned long long* physicalPageOut)
{
    volatile unsigned char* page = NULL;
    unsigned long long physical = 0ULL;

    page = (volatile unsigned char*)VirtualAlloc(
        NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (page == NULL) { return 1; }
    (void)VirtualLock((LPVOID)page, 4096);
    page[0] = 0xA5U;
    if (watchTranslate(h, (unsigned long long)(ULONG_PTR)page, &physical) != 0) {
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    *pageOut = page;
    *physicalPageOut = physical & ~0xFFFULL;
    return 0;
}

/* SMP self-test thread shared state. */
typedef struct KswWatchSmpThread
{
    volatile unsigned char* page;
    /* The main thread sets this to 1 only after all threads are ready, to squeeze the two writes as close together as possible. */
    volatile LONG* go;
    volatile LONG* ready;
    unsigned long index;
    unsigned char value;
    /* The thread sets the flag to 1 after writing; the main thread uses it to distinguish between 'not started' and 'started but with incorrect value'. */
    volatile LONG completed;
} KswWatchSmpThread;

static DWORD WINAPI watchSmpThread(LPVOID parameter)
{
    KswWatchSmpThread* self = (KswWatchSmpThread*)parameter;

    /* Report in, then spin waiting for the command. Spinning instead of waiting for a kernel object: the goal is to minimize the time difference. */
    InterlockedIncrement(self->ready);
    while (InterlockedCompareExchange(self->go, 0L, 0L) == 0L) {
        YieldProcessor();
    }
    /* Each thread writes to its own slot, allowing 'who wrote' and 'whether it was written correctly' to be verified independently. */
    self->page[self->index] = self->value;
    InterlockedExchange(&self->completed, 1L);
    return 0;
}

/*
 * Acceptance test item 5: SMP simultaneous hit.
 *
 * The question is not "can it hit" (the first item already answered that), but rather **whether two processors hitting the same page
 * almost simultaneously will each count it as the first hit**. The criteria focus on three things: only 1 logical processor hits first;
 * both processors remain alive and run to completion; and page permissions are eventually restored to allow access from both sides.
 *
 * Thread affinity covers only processor group 0. Cross-group affinity requires SetThreadGroupAffinity, but this target is a
 * single-group, 2 vCPU machine. Rather than adding unreachable code, explicitly record the limitation if there is more than one group:
 * BLOCKED: Claiming coverage for uncovered cases is worse than no coverage.
 */
static int doWatchSelfTestSmp(HANDLE h, int asJson)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KswWatchSmpThread threads[8];
    HANDLE handles[8];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long residentBefore = 0UL;
    unsigned long residentAfter = 0UL;
    unsigned long watchId = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    unsigned long threadCount = 0UL;
    unsigned long completed = 0UL;
    unsigned long correct = 0UL;
    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;
    volatile LONG go = 0L;
    volatile LONG ready = 0L;
    DWORD waitResult = 0;
    int blocked = 0;

    memset(cases, 0, sizeof(cases));
    memset(threads, 0, sizeof(threads));
    memset(handles, 0, sizeof(handles));

    if (GetActiveProcessorGroupCount() > 1) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"multi-processor-group\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：本机有多个处理器组，这段只安排得了第 0 组的亲和性。\n");
        }
        return 3;
    }
    if (!GetProcessAffinityMask(GetCurrentProcess(), &processAffinity,
                                &systemAffinity) || processAffinity == 0) {
        fprintf(stderr, "读不到进程亲和性掩码：win32=%lu\n", GetLastError());
        return 1;
    }
    /* If a processor cannot be scheduled 'simultaneously', it is a lack of conditions, not a functional issue. */
    for (i = 0UL; i < 64UL; ++i) {
        if ((processAffinity & ((DWORD_PTR)1 << i)) != 0 && threadCount < 8UL) {
            threads[threadCount].index = i;
            ++threadCount;
        }
    }
    if (threadCount < 2UL) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"single-processor\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：只有一个可用处理器，安排不出同时访问。\n");
        }
        return 3;
    }

    watchPrepareResidency(h);
    if (watchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 4096ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, watchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;

    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-smp\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视 SMP 同时命中自检 ===\n");
            printf("  BLOCKED：起不了常驻，命中路径问不出来。\n");
        }
        watchTeardown(h, watchId, page);
        return 3;
    }
    residentBefore = watchResidentCount(h);

    for (i = 0UL; i < threadCount; ++i) {
        threads[i].page = page;
        threads[i].go = &go;
        threads[i].ready = &ready;
        threads[i].value = (unsigned char)(0x40U + i);
        handles[i] = CreateThread(NULL, 0, watchSmpThread, &threads[i],
                                  CREATE_SUSPENDED, NULL);
        if (handles[i] == NULL) { break; }
        /* CPU affinity binding is a prerequisite for "simultaneous" execution: if all threads land on the same core, access becomes sequential. */
        (void)SetThreadAffinityMask(handles[i],
                                    (DWORD_PTR)1 << threads[i].index);
        (void)ResumeThread(handles[i]);
    }
    if (i != threadCount) {
        /* Thread startup failed: release any threads that were already started to avoid leaving dangling threads. */
        InterlockedExchange(&go, 1L);
        (void)WaitForMultipleObjects((DWORD)i, handles, TRUE, 5000);
        for (n = 0UL; n < i; ++n) { CloseHandle(handles[n]); }
        fprintf(stderr, "起线程失败：win32=%lu\n", GetLastError());
        watchTeardown(h, watchId, page);
        return 1;
    }
    /* Wait for all threads to report in before issuing the command together. */
    for (i = 0UL; i < 20000UL; ++i) {
        if ((unsigned long)InterlockedCompareExchange(&ready, 0L, 0L) >=
            threadCount) { break; }
        Sleep(1);
    }
    InterlockedExchange(&go, 1L);
    /*
     * Five seconds. The hit path itself is microsecond-level; waiting this long serves solely to distinguish between "deadlock" and "slow execution":
     * Timeout implies FAIL, as this path has no reason to require seconds.
     */
    waitResult = WaitForMultipleObjects((DWORD)threadCount, handles, TRUE, 5000);
    for (i = 0UL; i < threadCount; ++i) {
        if (InterlockedCompareExchange(&threads[i].completed, 0L, 0L) != 0L) {
            ++completed;
        }
    }
    n = 0UL;
    watchCase(&cases[n++], "全部参与线程都跑完了，没有卡住",
              "WaitForMultipleObjects 不超时",
              waitResult != WAIT_TIMEOUT, (unsigned long long)waitResult,
              "超时就是死锁 —— 这条路径没有任何理由需要秒级时间");
    watchCase(&cases[n++], "每个处理器上的写都完成了",
              "completed = 线程数",
              completed == threadCount, completed, NULL);

    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
    }
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        for (i = 0UL; i < threadCount; ++i) { CloseHandle(handles[i]); }
        watchTeardown(h, watchId, page);
        return 2;
    }
    /*
     * This is the core criterion for the entire self-check.
     *
     * hitCount must be exactly 1: under multi-core contention, 'each core counts its own first hit' is precisely
     * what the ARMED->TRIGGERED atomic transition must block. When this fails, the behavior is entirely normal: the
     * page is restored, the thread finishes, the machine doesn't crash; only the same 'first hit' is recorded twice.
     */
    watchCase(&cases[n++], "只有一个逻辑首命中",
              "hitCount = 1",
              row->hitCount == 1UL, row->hitCount,
              "多核竞争下各算一次第一次的错误不会有任何其它症状");
    watchCase(&cases[n++], "命中后自动解除",
              "state = 3 (disarmed)",
              row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              row->state, NULL);
    watchCase(&cases[n++], "首命中记在一个具体处理器上",
              "命中的处理器号在参与集合内",
              row->lastHitProcessorNumber < 64U &&
                  (processAffinity &
                   ((DWORD_PTR)1 << row->lastHitProcessorNumber)) != 0,
              (unsigned long long)row->lastHitProcessorNumber, NULL);

    /* Each thread writes to its own cell, so permission restoration can be verified cell by cell. */
    for (i = 0UL; i < threadCount; ++i) {
        if (page[threads[i].index] == threads[i].value) { ++correct; }
    }
    watchCase(&cases[n++], "所有被监视的写最终都落了盘",
              "每个线程写下的字节都读得回来",
              correct == threadCount, correct,
              "少一格说明权限恢复只对某一个处理器生效");
    residentAfter = watchResidentCount(h);
    watchCase(&cases[n++], "两个处理器都还在虚拟化里",
              "residentAfter = residentBefore",
              residentAfter == residentBefore && residentBefore >= 2UL,
              ((unsigned long long)residentBefore << 32) | residentAfter,
              "高 32 位是命中前，低 32 位是命中后");

    for (i = 0UL; i < threadCount; ++i) { CloseHandle(handles[i]); }
    watchTeardown(h, watchId, page);
    (void)blocked;
    return watchReportCases("watch-selftest-smp",
                            "内存监视 SMP 同时命中自检", cases, n, asJson, NULL);
}

/*
 * Acceptance test item 7: VA mapping changes.
 *
 * The first version explicitly **does not** track VA remapping. This is not an oversight but a commitment: the monitor binds to
 * a specific physical page at the moment of installation, and where that VA points subsequently is irrelevant. Thus, this
 * self-test must verify that it 'did not follow,' not that it 'did follow': after decommit/recommit, writing to the new page
 * must yield a hit count of **zero**, while the monitor continues to correctly report it is watching the original physical page.
 *
 * Record as BLOCKED when different physical pages cannot be obtained: the memory manager may return the same page
 * frame, in which case this question cannot be asked on this machine, indicating the function is not incorrect.
 */
static int doWatchSelfTestRemap(HANDLE h, int asJson)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long armedPage = 0ULL;
    unsigned long long currentPage = 0ULL;
    unsigned long long virtualAddress = 0ULL;
    unsigned long watchId = 0UL;
    unsigned long n = 0UL;
    unsigned long attempt = 0UL;
    char extra[192];

    memset(cases, 0, sizeof(cases));

    watchPrepareResidency(h);
    if (watchAllocatePage(h, &page, &armedPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    virtualAddress = (unsigned long long)(ULONG_PTR)page;
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, armedPage,
                   virtualAddress, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-remap\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视 VA 重映射自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, watchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;

    /*
     * Page swap: Uncommit and recommit the same VA. The memory manager does not guarantee a different physical
     * page, so retry multiple times and **only proceed to the next check if the page actually changed**.
     */
    currentPage = armedPage;
    for (attempt = 0UL; attempt < 16UL && currentPage == armedPage; ++attempt) {
        (void)VirtualUnlock((LPVOID)page, 4096);
        if (!VirtualFree((LPVOID)page, 4096, MEM_DECOMMIT)) { break; }
        if (VirtualAlloc((LPVOID)page, 4096, MEM_COMMIT, PAGE_READWRITE) == NULL) {
            break;
        }
        (void)VirtualLock((LPVOID)page, 4096);
        page[0] = 0x3CU;
        if (watchTranslate(h, virtualAddress, &currentPage) != 0) { break; }
        currentPage &= ~0xFFFULL;
    }
    if (currentPage == armedPage) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-remap\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"backing-page-unchanged\","
                   "\"armedPage\":\"0x%016llX\",\"cases\":[]}\n", armedPage);
        } else {
            printf("\n=== 内存监视 VA 重映射自检 ===\n");
            printf("  BLOCKED：解提交再提交后拿回了同一个页框，制造不出重映射。\n");
        }
        watchTeardown(h, watchId, page);
        return 3;
    }

    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
    }
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        watchTeardown(h, watchId, page);
        return 2;
    }
    watchCase(&cases[n++], "监视仍绑定在装它时那个物理页上",
              "physicalPage = Arm 时的页",
              row->physicalPage == armedPage, row->physicalPage,
              "第一版不跟踪重映射 —— 这是承诺，不是遗漏");
    watchCase(&cases[n++], "监视如实报告它当初解析的那个虚拟地址",
              "requestedAddress = 原 VA",
              row->requestedAddress == virtualAddress, row->requestedAddress,
              "两栏都留着，界面才判得出当前映射已经不是这一页");
    watchCase(&cases[n++], "当前 VA 已经指向另一个物理页",
              "当前翻译 != Arm 时的页",
              currentPage != armedPage, currentPage, NULL);
    watchCase(&cases[n++], "重映射没有把监视状态改掉",
              "state = 1 (armed)",
              row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED, row->state,
              NULL);

    /* Start resident and write new pages. It should not hit; a hit indicates the watch has silently followed. */
    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0) {
        page[0] = 0x71U;
        if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                       0ULL, 0UL, &rsp) == 0) {
            row = watchFindRow(&rsp, watchId);
        }
        watchCase(&cases[n++], "写新映射不会命中原监视",
                  "hitCount 仍为 0",
                  row != NULL && row->hitCount == 0UL,
                  row != NULL ? row->hitCount : 0xFFFFFFFFULL,
                  "命中了才说明监视悄悄跟着 VA 跑了");
    } else {
        cases[n].name = "写新映射不会命中原监视";
        cases[n].expectation = "hitCount 仍为 0";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "这台机器起不了常驻，命中路径问不出来";
        ++n;
    }

    watchTeardown(h, watchId, page);
    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"armedPage\":\"0x%016llX\",\"currentPage\":\"0x%016llX\"",
                      armedPage, currentPage);
    return watchReportCases("watch-selftest-remap",
                            "内存监视 VA 重映射自检", cases, n, asJson, extra);
}

/*
 * Acceptance test item 9: Event evidence loss.
 *
 * The only error shape to guard against here is: a hit occurred, but the line carrying the context was overwritten by a ring buffer,
 * resulting in 'no events' on the UI. The user interprets this as 'the target was not touched'—the exact opposite of the conclusion.
 *
 * The self-test does not induce uncontrollable concurrent event loss. It uses deterministic **ring-buffer wraparound** instead: start resident
 * mode with TRACE_ROUTINE_EXITS enabled. The ring wraps about twenty times per second, evicting the hit record within tens of milliseconds.
 * Next, we examine two things side by side: the event query failing to retrieve the row (droppedRows is non-zero, and the
 * oldest sequence number has passed it), while self-monitoring still reports a hit along with the current RIP/RSP/CR3.
 *
 * Leave an untouched monitor entry in the table as a control: only if the two readings differ does the claim of 'being
 * distinguishable' have evidence; otherwise, a record of all zeros can be interpreted as either a miss or a loss.
 */
static int doWatchSelfTestEvidence(HANDLE h, int asJson)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE erspBefore;
    KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE erspAfter;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* control = NULL;
    volatile unsigned char* page = NULL;
    volatile unsigned char* quiet = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long long quietPage = 0ULL;
    unsigned long long hitSequence = 0ULL;
    unsigned long watchId = 0UL;
    unsigned long quietId = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    int foundBefore = 0;
    int foundAfter = 0;
    char extra[192];

    memset(cases, 0, sizeof(cases));
    memset(&erspBefore, 0, sizeof(erspBefore));
    memset(&erspAfter, 0, sizeof(erspAfter));

    watchPrepareResidency(h);
    if (watchAllocatePage(h, &page, &physicalPage) != 0 ||
        watchAllocatePage(h, &quiet, &quietPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        if (page != NULL) { VirtualFree((LPVOID)page, 0, MEM_RELEASE); }
        return 1;
    }
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-evidence\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视事件丢失自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, watchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;
    /* Control group: installed but never touched. */
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, quietPage,
                   (unsigned long long)(ULONG_PTR)quiet, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) == 0 &&
        rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        quietId = rsp.ruleId;
    }

    /*
     * Enable resident mode with TRACE_ROUTINE_EXITS. This flag is normally off; when enabled, it triggers ring transitions twenty-plus
     * times per second, which serves as the necessary stress source for this self-check without needing to generate one separately.
     */
    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_TRACE_ROUTINE_EXITS) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-evidence\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视事件丢失自检 ===\n");
            printf("  BLOCKED：起不了常驻，命中路径问不出来。\n");
        }
        if (quietId != 0UL) {
            (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                                 KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
            (void)watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, quietId, 0ULL,
                             0ULL, 0ULL, 0UL, &rsp);
        }
        watchTeardown(h, watchId, page);
        VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);
        return 3;
    }

    page[0] = 0x5AU;

    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
    }
    if (row == NULL) {
        fprintf(stderr, "读不回刚装上的监视 #%lu\n", watchId);
        watchTeardown(h, watchId, page);
        VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);
        return 2;
    }
    hitSequence = row->lastHitSequence;
    watchCase(&cases[n++], "命中确实发生了",
              "hitCount = 1 且 state = 3 (disarmed)",
              row->hitCount == 1UL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              ((unsigned long long)row->hitCount << 32) | row->state, NULL);
    watchCase(&cases[n++], "命中现场记在监视自己身上",
              "rip / cr3 非零",
              row->lastHitRip != 0ULL && row->lastHitCr3 != 0ULL,
              row->lastHitRip,
              "环会回绕，只存在事件行里的现场等于没存");

    /* Just hit; this row should still be in the ring. */
    if (hitSequence > 0ULL &&
        watchEventQuery(h, hitSequence - 1ULL, &erspBefore) == 0) {
        for (i = 0UL; i < erspBefore.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
            if (erspBefore.rows[i].sequence == hitSequence) { foundBefore = 1; }
        }
    }
    watchCase(&cases[n++], "命中事件先是取得回来的",
              "环里能按序号找到那一行",
              foundBefore, hitSequence,
              "取不回来说明它一开始就没发布，那是另一个问题");

    /*
     * Allow the ring to wrap around. On a 2 vCPU system with tracing enabled, the ring cycles approximately 20 times per second; with 8192
     * slots, it completes a full cycle in tens of milliseconds. Two seconds is a buffer for slower machines, not a required wait time.
     */
    Sleep(2000);

    if (hitSequence > 0ULL &&
        watchEventQuery(h, hitSequence - 1ULL, &erspAfter) == 0) {
        for (i = 0UL; i < erspAfter.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_EVENT_ROWS; ++i) {
            if (erspAfter.rows[i].sequence == hitSequence) { foundAfter = 1; }
        }
    }
    if (foundAfter) {
        /* The ring buffer did not wrap: the stress test was not generated, so this issue cannot be reproduced on this machine. */
        cases[n].name = "命中事件被环挤掉之后仍能证明命中过";
        cases[n].expectation = "按序号已经取不回那一行";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = erspAfter.newestSequence;
        cases[n].remark = "两秒里环没有转过去，造不出丢失条件";
        ++n;
    } else {
        watchCase(&cases[n++], "命中事件被环挤掉之后仍能证明命中过",
                  "droppedRows 非零且按序号取不回那一行",
                  erspAfter.droppedRows != 0UL,
                  (unsigned long long)erspAfter.droppedRows,
                  "这正是界面绝不能显示成\"没有事件\"的那一刻");
    }

    /* Re-read the watch: evidence is lost, but the hit record remains. */
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
        control = quietId != 0UL ? watchFindRow(&rsp, quietId) : NULL;
    }
    watchCase(&cases[n++], "事件没了，监视仍然报得出命中过",
              "hitCount = 1 且 state = 3 (disarmed)",
              row != NULL && row->hitCount == 1UL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_DISARMED,
              row != NULL
                  ? (((unsigned long long)row->hitCount << 32) | row->state)
                  : 0ULL,
              "命中状态不依赖事件是否发布成功");
    if (control != NULL) {
        watchCase(&cases[n++], "与从没被碰过的监视读数不同",
                  "对照组 hitCount = 0 且 state = 1 (armed)",
                  control->hitCount == 0UL &&
                      control->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED,
                  ((unsigned long long)control->hitCount << 32) | control->state,
                  "两者读数相同的话，\"区分得开\"就没有证据");
    } else {
        cases[n].name = "与从没被碰过的监视读数不同";
        cases[n].expectation = "对照组 hitCount = 0 且 state = 1 (armed)";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "对照监视没装上（第二页可能与别的规则冲突）";
        ++n;
    }

    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    if (quietId != 0UL) {
        (void)watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, quietId, 0ULL,
                         0ULL, 0ULL, 0UL, &rsp);
    }
    (void)watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, watchId, 0ULL,
                     0ULL, 0ULL, 0UL, &rsp);
    VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    VirtualFree((LPVOID)quiet, 0, MEM_RELEASE);

    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"hitSequence\":%llu,\"newestSequence\":%llu,"
                      "\"droppedRows\":%lu",
                      hitSequence, erspAfter.newestSequence,
                      erspAfter.droppedRows);
    return watchReportCases("watch-selftest-evidence",
                            "内存监视事件丢失自检", cases, n, asJson, extra);
}

/*
 * Process attribution for P1: Map the CR3 hit in the context back to a PID.
 *
 * The self-test runs on itself, so there is a precise criterion for 'correctness': the attributed result must be the **current process's**
 * PID. This is critical because the two failure modes of attribution have vastly different consequences—failing to attribute is merely a
 * limitation (document it in the UI), while attributing to the **wrong process** creates false evidence that leads people to the wrong target.
 *
 * A lack of match on this machine may be entirely normal: the hit originates from user-mode code. When KVA Shadow is enabled,
 * user-mode runs with a user CR3, while the driver attaches and reads back the kernel CR3; these are inherently unequal.
 * Thus, "no match" is recorded as BLOCKED with the scan count displayed, while "matched someone else" is recorded as FAIL.
 *
 * Note why this does not weaken the feature: the true attribution target is kernel
 * writes (SSDT, DriverObject, callbacks), and those that match record the kernel CR3.
 */
static int doWatchSelfTestProcess(HANDLE h, int asJson)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_PROCESS_REQUEST preq;
    KSWORD_ARK_HVM_PROCESS_RESPONSE prsp;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long long hitCr3 = 0ULL;
    unsigned long watchId = 0UL;
    unsigned long ownPid = (unsigned long)GetCurrentProcessId();
    unsigned long n = 0UL;
    char extra[192];

    memset(cases, 0, sizeof(cases));
    memset(&prsp, 0, sizeof(prsp));

    watchPrepareResidency(h);
    if (watchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-process\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视进程归因自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, watchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;

    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-process\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视进程归因自检 ===\n");
            printf("  BLOCKED：起不了常驻，命中路径问不出来。\n");
        }
        watchTeardown(h, watchId, page);
        return 3;
    }
    page[0] = 0x5AU;
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
    }
    hitCr3 = row != NULL ? row->lastHitCr3 : 0ULL;
    watchCase(&cases[n++], "命中现场记下了非零的 CR3",
              "cr3 != 0",
              hitCr3 != 0ULL, hitCr3,
              "没有 CR3 就没有归因的输入，后面几条都无从谈起");

    /* Stop resident first, then attribute: attribution is post-processing and should not require the resident to still be running. */
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);

    memset(&preq, 0, sizeof(preq));
    preq.operation = KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3;
    preq.directoryBase = hitCr3;
    if (processIoctl(h, &preq, &prsp) != 0) {
        fprintf(stderr, "归因下发失败：win32=%lu\n", GetLastError());
        watchTeardown(h, watchId, page);
        return 1;
    }
    watchCase(&cases[n++], "归因扫描真的跑起来了",
              "scanned > 0",
              prsp.resolvedScannedProcesses != 0UL,
              prsp.resolvedScannedProcesses,
              "扫描数为零说明一个进程都没问成，那与「扫过都不是它」是两回事");
    if (prsp.resolvedProcessId != 0UL) {
        watchCase(&cases[n++], "归出来的就是本进程",
                  "resolvedProcessId = GetCurrentProcessId()",
                  prsp.resolvedProcessId == ownPid,
                  ((unsigned long long)prsp.resolvedProcessId << 32) | ownPid,
                  "归到别的进程上是假证据，比归不出来坏得多");
    } else {
        cases[n].name = "归出来的就是本进程";
        cases[n].expectation = "resolvedProcessId = GetCurrentProcessId()";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = (unsigned long long)prsp.resolvedScannedProcesses;
        cases[n].remark = "没匹配上。命中来自用户态，而 KVA Shadow 下用户 CR3 "
                          "与驱动读回的内核 CR3 天生不等——内核写的归因不受影响";
        ++n;
    }
    /* Query with a value that can never belong to any process; it must cleanly return "not found". */
    memset(&preq, 0, sizeof(preq));
    preq.operation = KSWORD_ARK_HVM_PROCESS_OP_RESOLVE_CR3;
    preq.directoryBase = 0x0000FFFFFFFFF000ULL;
    if (processIoctl(h, &preq, &prsp) == 0) {
        watchCase(&cases[n++], "问一个不存在的地址空间会干净地答没有",
                  "status = 6 (not-found) 且 pid = 0",
                  prsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_NOT_FOUND &&
                      prsp.resolvedProcessId == 0UL,
                  ((unsigned long long)prsp.status << 32) |
                      prsp.resolvedProcessId,
                  "随便匹配一个出来才是最坏的失败方式");
    }

    watchTeardown(h, watchId, page);
    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"hitCr3\":\"0x%016llX\",\"ownPid\":%lu",
                      hitCr3, ownPid);
    return watchReportCases("watch-selftest-process",
                            "内存监视进程归因自检", cases, n, asJson, extra);
}

/*
 * Acceptance test item 6: View conflict.
 *
 * A page can have only one owner. This self-test first assigns the page to the CLOAK view, then requests the same page via the monitor. Three
 * conditions must be verified: it cannot be installed, the owner must be clearly identified, and the original view remains completely untouched.
 *
 * The third case is the most easily overlooked yet most critical: an implementation that 'rejects but inadvertently
 * modifies another's leaf node'. From the return value perspective, it is identical to the correct implementation.
 * Symptoms only appear when that view is used next, by which time no one will associate it with this installation.
 */
static int doWatchSelfTestConflict(HANDLE h, int asJson)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_VIEW_REQUEST vreq;
    KSWORD_ARK_HVM_VIEW_RESPONSE vrsp;
    KSWORD_ARK_HVM_VIEW_RESPONSE vafter;
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long viewId = 0UL;
    unsigned long n = 0UL;
    unsigned long i = 0UL;
    int viewInstalled = 0;
    char extra[128];

    memset(cases, 0, sizeof(cases));
    memset(&vrsp, 0, sizeof(vrsp));
    memset(&vafter, 0, sizeof(vafter));

    /*
     * This self-check requires attaching a **real** detached view, so prepare must include EPTP switching.
     *
     * A standard prepare can pass, but the subsequent view installation hits the capability gate (status=9), causing
     * the entire self-check to be marked BLOCKED. That BLOCKED status implies 'this machine cannot install views,'
     * which is factually incorrect: the failure occurs only because we didn't request that backend. A BLOCKED state
     * caused by our own design is worse than FAIL, as it misleads users into investigating the machine.
     */
    if (watchResidentCount(h) != 0UL) {
        (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    }
    /*
     * Teardown before prepare.
     *
     * If resources are already prepared, calling prepare again with different flags returns ALREADY_PREPARED rather than 'reconfigure
     * with new flags'—the backend selection is finalized at the prepare moment. Without teardown, the backend cannot be changed; the
     * consequence is that view installation is rejected by capability gates, appearing as if the machine does not support it.
     *
     * Clarify the cost: teardown clears everything currently in the runtime, including monitors
     * and views installed elsewhere. This is a self-check command, not a daily operation.
     */
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_TEARDOWN,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_PREPARE,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPTP_SWITCH);
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_SELF_TEST,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                         KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                         KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED);
    if (watchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }

    /* --- 1. Assign this page to a CLOAK view first --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_ADD;
    vreq.kind = KSWORD_ARK_HVM_VIEW_KIND_CLOAK;
    /* SEED_FROM_TARGET: The shadow copies from the target page, so there is no need to fill 4 KiB manually. */
    vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED |
                 KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET;
    vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    vreq.physicalAddress = physicalPage;
    if (viewIoctl(h, &vreq, &vrsp) != 0) {
        fprintf(stderr, "视图安装下发失败：win32=%lu\n", GetLastError());
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 1;
    }
    if (vrsp.status != KSWORD_ARK_HVM_VIEW_STATUS_OK) {
        /*
         * View installation failed ⇒ Cannot determine how monitoring behaves when a view is occupied on this machine.
         * This is a precondition failure, not a monitoring defect.
         */
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-conflict\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"view-add-refused\",\"viewStatus\":%lu,"
                   "\"cases\":[]}\n", vrsp.status);
        } else {
            printf("\n=== 内存监视视图冲突自检 ===\n");
            printf("  BLOCKED：这台机器装不上分离视图，status=%lu。\n", vrsp.status);
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    viewInstalled = 1;
    viewId = vrsp.viewId;
    watchCase(&cases[n++], "对照用的分离视图装上了",
              "status=OK 且 viewId != 0",
              viewId != 0UL, viewId, NULL);

    /* --- 2. Instruct the monitor to request the same page. */
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0) {
        fprintf(stderr, "watch ADD 下发失败：win32=%lu\n", GetLastError());
        goto cleanup;
    }
    watchCase(&cases[n++], "监视没装上",
              "status = 10 (leaf-conflict)",
              rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_LEAF_CONFLICT,
              rsp.status,
              "静默覆盖别人的叶项才是最坏的结果，而它从返回值上看是成功");
    watchCase(&cases[n++], "说得清是谁占着这一页",
              "conflictOwnerKind = 1 (view) 且 conflictOwnerId = 该视图",
              rsp.conflictOwnerKind == KSWORD_ARK_HVM_WATCH_CONFLICT_VIEW &&
                  rsp.conflictOwnerId == viewId,
              ((unsigned long long)rsp.conflictOwnerKind << 32) |
                  rsp.conflictOwnerId,
              "高 32 位是占有者类型，低 32 位是它的编号");
    /* The rejected entry should not leave anything in the table. */
    watchCase(&cases[n++], "被拒的监视没有留下编号",
              "ruleId = 0",
              rsp.ruleId == 0UL, rsp.ruleId, NULL);

    /* --- 3. The original view must remain unchanged --- */
    memset(&vreq, 0, sizeof(vreq));
    vreq.operation = KSWORD_ARK_HVM_VIEW_OP_QUERY;
    if (viewIoctl(h, &vreq, &vafter) == 0) {
        const KSWORD_ARK_HVM_VIEW_ROW* row = NULL;

        for (i = 0UL; i < vafter.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_VIEWS; ++i) {
            if (vafter.rows[i].viewId == viewId) { row = &vafter.rows[i]; }
        }
        watchCase(&cases[n++], "原视图还在，物理页没变",
                  "同一个 viewId 仍在表里且指向同一页",
                  row != NULL && row->physicalAddress == physicalPage,
                  row != NULL ? row->physicalAddress : 0ULL, NULL);
        watchCase(&cases[n++], "原视图的类型没被改掉",
                  "kind 仍是 CLOAK",
                  row != NULL && row->kind == KSWORD_ARK_HVM_VIEW_KIND_CLOAK,
                  row != NULL ? row->kind : 0xFFFFFFFFULL,
                  "被拒的安装顺手改了别人的叶项，返回值上完全看不出来");
    } else {
        cases[n].name = "原视图还在，物理页没变";
        cases[n].expectation = "同一个 viewId 仍在表里且指向同一页";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "视图查询下发失败，核对不了";
        ++n;
    }

cleanup:
    if (viewInstalled) {
        memset(&vreq, 0, sizeof(vreq));
        vreq.operation = KSWORD_ARK_HVM_VIEW_OP_REMOVE;
        vreq.flags = KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED;
        vreq.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        vreq.viewId = viewId;
        (void)viewIoctl(h, &vreq, &vrsp);
    }
    VirtualFree((LPVOID)page, 0, MEM_RELEASE);
    (void)_snprintf_s(extra, sizeof(extra), _TRUNCATE,
                      ",\"viewId\":%lu,\"physicalPage\":\"0x%016llX\"",
                      viewId, physicalPage);
    return watchReportCases("watch-selftest-conflict",
                            "内存监视视图冲突自检", cases, n, asJson, extra);
}

/*
 * Acceptance test item 8: Resident restart.
 *
 * This case aims to prevent 'old monitors silently continuing to take effect in the next resident state'. The consequence
 * of silently continuing is not an extra event, but **a monitor that the user believes is already invalid still modifying
 * EPT leaf nodes**—while the target page it corresponds to may have already been reclaimed and assigned to someone else.
 *
 * The criteria are in three parts: after stopping the resident component, the state must become INVALIDATED (not remain
 * ARMED); restarting the resident component must not automatically revert to ARMED; and explicit REARM is required to re-arm.
 */
static int doWatchSelfTestRestart(HANDLE h, int asJson)
{
    KswWatchCase cases[KSW_WATCH_SELFTEST_CASES];
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE rsp;
    const KSWORD_ARK_HVM_EPT_WATCH_ROW* row = NULL;
    volatile unsigned char* page = NULL;
    unsigned long long physicalPage = 0ULL;
    unsigned long armedGeneration = 0UL;
    unsigned long watchId = 0UL;
    unsigned long n = 0UL;

    memset(cases, 0, sizeof(cases));

    watchPrepareResidency(h);
    if (watchAllocatePage(h, &page, &physicalPage) != 0) {
        fprintf(stderr, "准备测试页失败：win32=%lu\n", GetLastError());
        return 1;
    }
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL, physicalPage,
                   (unsigned long long)(ULONG_PTR)page, 8ULL,
                   KSWORD_ARK_HVM_EPT_ACCESS_WRITE, &rsp) != 0 ||
        rsp.status != KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-restart\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"add-refused\",\"status\":%lu,\"cases\":[]}\n",
                   rsp.status);
        } else {
            printf("\n=== 内存监视常驻重启自检 ===\n");
            printf("  BLOCKED：装不上监视，status=%lu (%s)\n",
                   rsp.status, watchRuleStatusName(rsp.status));
        }
        VirtualFree((LPVOID)page, 0, MEM_RELEASE);
        return 3;
    }
    watchId = rsp.ruleId;
    armedGeneration = rsp.watch.armedGeneration;

    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) != 0) {
        if (asJson) {
            printf("{\"kind\":\"watch-selftest-restart\",\"verdict\":\"BLOCKED\","
                   "\"reason\":\"resident-start-refused\",\"cases\":[]}\n");
        } else {
            printf("\n=== 内存监视常驻重启自检 ===\n");
            printf("  BLOCKED：起不了常驻，这条路径问不出来。\n");
        }
        watchTeardown(h, watchId, page);
        return 3;
    }
    /* --- Stop resident --- */
    (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                         KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0) {
        row = watchFindRow(&rsp, watchId);
    }
    watchCase(&cases[n++], "停常驻之后监视被标成已失效",
              "state = 4 (invalidated)",
              row != NULL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED,
              row != NULL ? row->state : 0xFFFFFFFFULL,
              "留在 ARMED 就等于宣称它还在盯着，而那时它一条叶项都没装");

    /* --- Restarting the resident component: it must not revert to ARMED state on its own */
    if (watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_START_RESIDENT,
                       KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
                       KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
                       KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0) {
        row = NULL;
        if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                       0ULL, 0UL, &rsp) == 0) {
            row = watchFindRow(&rsp, watchId);
        }
        watchCase(&cases[n++], "下一次常驻不会静默恢复旧监视",
                  "state 仍为 4 (invalidated)",
                  row != NULL &&
                      row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_INVALIDATED,
                  row != NULL ? row->state : 0xFFFFFFFFULL, NULL);
        /* Write once: since it is already invalid, it should not match. */
        page[0] = 0x6EU;
        row = NULL;
        if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL, 0ULL, 0ULL,
                       0ULL, 0UL, &rsp) == 0) {
            row = watchFindRow(&rsp, watchId);
        }
        watchCase(&cases[n++], "失效的监视不再命中",
                  "hitCount 仍为 0",
                  row != NULL && row->hitCount == 0UL,
                  row != NULL ? row->hitCount : 0xFFFFFFFFULL,
                  "命中了说明叶项其实还装着，只是状态位说它失效了");
        (void)watchLifecycle(h, KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT,
                             KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED);
    } else {
        cases[n].name = "下一次常驻不会静默恢复旧监视";
        cases[n].expectation = "state 仍为 4 (invalidated)";
        cases[n].verdict = "BLOCKED";
        cases[n].observed = 0ULL;
        cases[n].remark = "第二次起常驻被拒，这一段问不出来";
        ++n;
    }

    /* --- Explicit rearm --- */
    row = NULL;
    if (watchIoctl(h, KSWORD_ARK_HVM_EPT_RULE_REARM, watchId, 0ULL, 0ULL,
                   0ULL, 0UL, &rsp) == 0 &&
        rsp.status == KSWORD_ARK_HVM_EPT_RULE_STATUS_OK) {
        row = &rsp.watch;
    }
    watchCase(&cases[n++], "显式重新武装之后回到 ARMED",
              "state = 1 (armed)",
              row != NULL &&
                  row->state == KSWORD_ARK_HVM_EPT_WATCH_STATE_ARMED,
              row != NULL ? row->state : 0xFFFFFFFFULL, NULL);
    watchCase(&cases[n++], "重新武装换了一个新的武装代次",
              "armedGeneration != 安装时的那个",
              row != NULL && row->armedGeneration != armedGeneration,
              row != NULL ? row->armedGeneration : 0ULL,
              "代次不变就分不出这条证据来自哪一次常驻");

    watchTeardown(h, watchId, page);
    return watchReportCases("watch-selftest-restart",
                            "内存监视常驻重启自检", cases, n, asJson, NULL);
}

/*
 * R-1 process actions.
 *
 * When op is QUERY, all other parameters are ignored. For FREEZE and TERMINATE, pid and the guest linear
 * address (in hexadecimal) are required. The driver does not guess the page; guessing wrong results in
 * rejecting an address that will never be executed, which appears identical to success from the outside.
 */
static int doProcess(HANDLE h, unsigned long op, unsigned long pid,
                     unsigned long long gla, int asJson)
{
    KSWORD_ARK_HVM_PROCESS_REQUEST req;
    KSWORD_ARK_HVM_PROCESS_RESPONSE rsp;
    unsigned long i;

    memset(&req, 0, sizeof(req));
    req.operation = op;
    req.processId = pid;
    req.guestLinearAddress = gla;
    req.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    req.flags = KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
    if (processIoctl(h, &req, &rsp) != 0) { return 1; }

    if (asJson) {
        printf("{\"kind\":\"hvm-process\",\"status\":%lu,\"statusName\":\"%s\","
               "\"lastStatus\":\"0x%08lX\",\"rowCount\":%lu,\"generation\":%lu,"
               "\"rows\":[",
               rsp.status, processStatusName(rsp.status),
               (unsigned long)rsp.lastStatus, rsp.rowCount, rsp.generation);
        for (i = 0UL; i < rsp.returnedRows &&
                      i < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS; ++i) {
            printf("%s{\"processId\":%lu,\"disposition\":%lu,"
                   "\"directoryBase\":\"0x%016llX\","
                   "\"guestPhysicalAddress\":\"0x%016llX\","
                   "\"guestLinearAddress\":\"0x%016llX\","
                   "\"interceptCount\":%llu,\"hierarchyIndex\":%lu}",
                   (i == 0UL) ? "" : ",",
                   rsp.rows[i].processId, rsp.rows[i].disposition,
                   rsp.rows[i].directoryBase, rsp.rows[i].guestPhysicalAddress,
                   rsp.rows[i].guestLinearAddress, rsp.rows[i].interceptCount,
                   rsp.rows[i].hierarchyIndex);
        }
        printf("]}\n");
        return (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK) ? 0 : 2;
    }

    printf("\n=== R-1 进程处置 ===\n");
    printf("  status       : %lu (%s)  lastStatus=0x%08lX\n",
           rsp.status, processStatusName(rsp.status),
           (unsigned long)rsp.lastStatus);
    printf("  表内条数     : %lu   代次=%lu\n", rsp.rowCount, rsp.generation);
    if (rsp.returnedRows == 0UL) {
        printf("  （表里没有任何处置）\n");
    }
    for (i = 0UL; i < rsp.returnedRows &&
                  i < KSWORD_ARK_HVM_MAX_PROCESS_DISPOSITIONS; ++i) {
        printf("  pid=%-6lu %s  cr3=0x%016llX gpa=0x%016llX gla=0x%016llX 拦截=%llu 层次#%lu\n",
               rsp.rows[i].processId,
               processDispositionName(rsp.rows[i].disposition),
               rsp.rows[i].directoryBase, rsp.rows[i].guestPhysicalAddress,
               rsp.rows[i].guestLinearAddress, rsp.rows[i].interceptCount,
               rsp.rows[i].hierarchyIndex);
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_CR3_TRACKING_REQUIRED) {
        printf("  ** 缺 CR3 追踪 **：作用域完全靠它。先用 cr-policy 打开 TRACK_CR3，\n");
        printf("     再起常驻——这一位在常驻启动时写进 VMCS，起来之后改不了。\n");
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_EPTP_SWITCH_REQUIRED) {
        printf("  ** 缺 EPTP 切换后端 **：没有第二套层次就没有\"受限\"可选。\n");
        printf("     prepare 时带 ENABLE_EPTP_SWITCH。\n");
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_REQUIRES_RESIDENT_STOPPED) {
        printf("  ** 常驻正在跑 **：安装要在常驻**停着**时做——常驻期间退出路径\n");
        printf("     不持锁读这张表与它的层次。与 EPT 规则、分离视图同一条规矩。\n");
        printf("     顺序：stop -> proc-freeze/terminate -> self-test -> resident。\n");
    }
    if (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_NOT_PREPARED) {
        printf("  ** 还没 prepare **：运行时里什么都没有。先 prepare-eptpsw。\n");
    }
    return (rsp.status == KSWORD_ARK_HVM_PROCESS_STATUS_OK) ? 0 : 2;
}

static int doMetrics(HANDLE h, int asJson)
{
    static const char* const kGlobalNames[KSW_HVM_TIME_GLOBAL_STAGES] = {
        "resourcesBegin", "resourcesEnd", "eptBegin", "eptEnd", "rendezvousBegin", "rendezvousEnd"
    };
    static const char* const kCpuNames[KSW_HVM_TIME_CPU_STAGES] = {
        "ipiEnter", "ipiLeave", "vmcsBegin", "stateCaptured", "vmcsWritten", "entryBefore", "entryAfter"
    };
    KSWORD_ARK_HVM_METRICS_REQUEST request = { 0 };
    KSWORD_ARK_HVM_METRICS_RESPONSE* response;
    DWORD returned = 0;
    unsigned long i, j;
    response = (KSWORD_ARK_HVM_METRICS_RESPONSE*)calloc(1, sizeof(*response));
    if (!response) { fprintf(stderr, "metrics: allocation failed\n"); return 1; }
    request.version = KSWORD_ARK_HVM_METRICS_VERSION;
    request.size = sizeof(request);
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_METRICS,
                         &request, (DWORD)sizeof(request), response, (DWORD)sizeof(*response),
                         &returned, NULL)) {
        fprintf(stderr, "metrics query failed: Win32 %lu\n", GetLastError());
        free(response);
        return 1;
    }
    if (returned != sizeof(*response) || response->size != sizeof(*response) ||
        response->version != KSWORD_ARK_HVM_METRICS_VERSION ||
        response->processorCount > KSWORD_ARK_HVM_MAX_PROCESSORS || response->qpcFrequency == 0) {
        fprintf(stderr, "metrics: incompatible or incomplete response\n");
        free(response);
        return 1;
    }
    if (asJson) {
        /* Decimal strings preserve every bit in JavaScript and JSON consumers. */
        printf("{\"kind\":\"hvm-metrics\",\"version\":%lu,\"transitionCoherent\":%s,"
               "\"transitionSequence\":%lu,\"command\":%lu,\"lastStatus\":\"0x%08lX\","
               "\"processorCount\":%lu,\"qpcFrequency\":\"%llu\","
               "\"snapshotBeginQpc\":\"%llu\",\"snapshotEndQpc\":\"%llu\","
               "\"commandBeginQpc\":\"%llu\",\"commandEndQpc\":\"%llu\","
               "\"inveptAttempts\":\"%llu\",\"inveptSucceeded\":\"%llu\",\"inveptFailed\":\"%llu\","
               "\"ruleAllocations\":\"%llu\",\"ruleFrees\":\"%llu\","
               "\"replacementAllocations\":\"%llu\",\"replacementFrees\":\"%llu\","
               "\"globalValidMask\":%lu,\"globalQpc\":{",
               response->version, response->transitionCoherent ? "true" : "false",
               response->transitionSequence, response->command, response->lastStatus,
               response->processorCount, response->qpcFrequency,
               response->snapshotBeginQpc, response->snapshotEndQpc,
               response->commandBeginQpc, response->commandEndQpc,
               response->inveptAttempts, response->inveptSucceeded, response->inveptFailed,
               response->ruleAllocations, response->ruleFrees,
               response->replacementAllocations, response->replacementFrees,
               response->globalValidMask);
    } else {
        printf("metrics version=%lu coherent=%lu sequence=%lu command=%lu nt=0x%08lX cpus=%lu\n"
               "QPC frequency=%llu snapshot=[%llu,%llu] command=[%llu,%llu]\n"
               "INVEPT attempts=%llu success=%llu failure=%llu\n"
               "nested-page objects allocated=%llu freed=%llu; replacement pages allocated=%llu freed=%llu\n"
               "global validMask=0x%lX\n",
               response->version, response->transitionCoherent, response->transitionSequence,
               response->command, response->lastStatus, response->processorCount,
               response->qpcFrequency, response->snapshotBeginQpc, response->snapshotEndQpc,
               response->commandBeginQpc, response->commandEndQpc,
               response->inveptAttempts, response->inveptSucceeded, response->inveptFailed,
               response->ruleAllocations, response->ruleFrees,
               response->replacementAllocations, response->replacementFrees, response->globalValidMask);
    }
    for (i = 0; i < KSW_HVM_TIME_GLOBAL_STAGES; ++i) {
        if (asJson) { printf("%s\"%s\":\"%llu\"", i ? "," : "", kGlobalNames[i], response->globalQpc[i]); }
        else { printf("  %s=%llu\n", kGlobalNames[i], response->globalQpc[i]); }
    }
    if (asJson) { printf("},\"processors\":["); }
    for (i = 0; i < response->processorCount; ++i) {
        const KSWORD_ARK_HVM_METRICS_CPU* cpu = &response->processors[i];
        if (asJson) { printf("%s{\"group\":%u,\"number\":%u,\"validMask\":%lu,\"qpc\":{",
                            i ? "," : "", (unsigned)cpu->group, (unsigned)cpu->number, cpu->validMask); }
        else { printf("cpu=%u:%u validMask=0x%lX\n", (unsigned)cpu->group, (unsigned)cpu->number, cpu->validMask); }
        for (j = 0; j < KSW_HVM_TIME_CPU_STAGES; ++j) {
            if (asJson) { printf("%s\"%s\":\"%llu\"", j ? "," : "", kCpuNames[j], cpu->qpc[j]); }
            else { printf("  %s=%llu\n", kCpuNames[j], cpu->qpc[j]); }
        }
        if (asJson) { printf("}}"); }
    }
    if (asJson) { printf("],\"shadowEpt\":["); }
    for (i = 0; i < response->shadowProcessorCount && i < KSWORD_ARK_HVM_MAX_PROCESSORS; ++i) {
        const KSWORD_ARK_HVM_SHADOW_METRICS* row = &response->shadowProcessors[i];
        if (asJson) {
            printf("%s{\"index\":%lu,\"pagesUsed\":%lu,\"trackedPages\":%lu,\"trackedOverflow\":%lu,"
                   "\"fills\":%lu,\"denied\":%lu,\"exhausted\":%lu,\"kept\":%lu,\"dropped\":%lu,"
                   "\"adPending\":%lu,\"adPropagated\":%lu,\"adOverflow\":%lu,\"verifyMismatch\":%lu}",
                   i ? "," : "", row->index, row->pagesUsed, row->trackedPages, row->trackedOverflow,
                   row->fills, row->denied, row->exhausted, row->kept, row->dropped,
                   row->adPending, row->adPropagated, row->adOverflow, row->verifyMismatch);
        } else {
            printf("shadow cpu=%lu fills=%lu kept=%lu dropped=%lu pages=%lu tracked=%lu overflow=%lu "
                   "adPending=%lu adOverflow=%lu mismatch=%lu\n", row->index, row->fills,
                   row->kept, row->dropped, row->pagesUsed, row->trackedPages, row->trackedOverflow,
                   row->adPending, row->adOverflow, row->verifyMismatch);
        }
    }
    if (asJson) { printf("],\"backend\":%lu,\"svmProcessors\":[", response->backend); }
    for (i = 0; i < response->svmProcessorCount && i < KSWORD_ARK_HVM_MAX_PROCESSORS; ++i) {
        const KSWORD_ARK_HVM_SVM_METRICS* row = &response->svmProcessors[i];
        if (asJson) {
            printf("%s{\"group\":%u,\"number\":%u,\"valid\":%lu,\"sequence\":%lu,\"stage\":%lu,\"asid\":%lu,\"generation\":%lu,"
                   "\"exitCode\":\"0x%016llX\",\"exitInfo1\":\"0x%016llX\",\"exitInfo2\":\"0x%016llX\","
                   "\"rip\":\"0x%016llX\",\"rsp\":\"0x%016llX\",\"cr3\":\"0x%016llX\",\"nrip\":\"0x%016llX\","
                   "\"event\":\"0x%016llX\",\"tsc\":\"%llu\",\"vmcbPa\":\"0x%016llX\",\"hsavePa\":\"0x%016llX\","
                   "\"nptRootPa\":\"0x%016llX\",\"tlbRequests\":\"%llu\",\"ringPosition\":%lu,\"ringOverwritten\":%lu,\"msrValidMask\":%lu,\"svmFeatures\":%lu,\"asidCount\":%lu,\"physicalBits\":%lu,\"observedVmCr\":\"0x%016llX\",\"observedEfer\":\"0x%016llX\",\"observedHsave\":\"0x%016llX\",\"failureStatus\":\"0x%08lX\",\"failureStage\":%lu,",
                   i ? "," : "", (unsigned)row->group, (unsigned)row->number, row->valid, row->sequence,
                   row->stage, row->asid, row->generation, row->exitCode, row->exitInfo1, row->exitInfo2,
                   row->rip, row->rsp, row->cr3, row->nrip, row->event, row->tsc, row->vmcbPa, row->hsavePa,
                   row->nptRootPa, row->tlbRequests, row->ringPosition, row->ringOverwritten, row->msrValidMask, row->svmFeatures, row->asidCount, row->physicalBits, row->observedVmCr, row->observedEfer, row->observedHsave, row->failureStatus, row->failureStage);
            printf("\"nestedProbe\":{\"valid\":%lu,\"sequence\":%lu,\"status\":\"0x%08lX\",\"entries\":%lu,\"reflections\":%lu,\"faults\":%lu,\"exit\":\"0x%016llX\",\"marker\":\"0x%016llX\"}}",
                   row->nestedProbeValid, row->nestedProbeSequence, row->nestedProbeStatus,
                   row->nestedProbeEntries, row->nestedProbeReflections, row->nestedProbeFaults,
                   row->nestedProbeExit, row->nestedProbeMarker);
        } else {
            printf("SVM cpu=%u:%u stage=%lu valid=%lu exit=0x%016llX info1=0x%016llX info2=0x%016llX flush=%llu\n",
                   (unsigned)row->group, (unsigned)row->number, row->stage, row->valid,
                   row->exitCode, row->exitInfo1, row->exitInfo2, row->tlbRequests);
        }
    }
    if (asJson) { printf("]}\n"); }
    free(response);
    return 0;
}

/* Resolve a process lease through Windows APIs, without calling the VMM. */
static int resolveNestedPageOwner(DWORD requested, DWORD* owner, ULONGLONG* created)
{
    HANDLE process;
    FILETIME birth, exited, kernel, user;
    ULARGE_INTEGER value;
    if (requested == 0UL) {
        PROCESSENTRY32W entry = { 0 };
        DWORD count = 0UL;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) { return 0; }
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, L"vmware-vmx.exe") == 0) {
                    requested = entry.th32ProcessID;
                    ++count;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        if (count != 1UL) {
            fprintf(stderr, "Select an explicit VMM owner PID when there is not exactly one vmware-vmx process.\n");
            return 0;
        }
    }
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, requested);
    if (process == NULL) { return 0; }
    if (!GetProcessTimes(process, &birth, &exited, &kernel, &user)) {
        CloseHandle(process);
        return 0;
    }
    CloseHandle(process);
    value.LowPart = birth.dwLowDateTime;
    value.HighPart = birth.dwHighDateTime;
    *owner = requested;
    *created = value.QuadPart;
    return 1;
}

static int doNestedPageEx(HANDLE h, int asJson, unsigned long operation,
                          unsigned long long eptp, unsigned long long gpa,
                          unsigned char fill, unsigned long faultMode, unsigned long ownerPid,
                          unsigned long leafShift, unsigned long stagePageIndex,
                          unsigned long extraFlags)
{
    KSWORD_ARK_HVM_NESTED_PAGE_REQUEST request = { 0 };
    KSWORD_ARK_HVM_NESTED_PAGE_RESPONSE response = { 0 };
    DWORD returned = 0;
    unsigned long index;
    request.version = KSWORD_ARK_HVM_NESTED_PAGE_VERSION;
    request.size = sizeof(request);
    /*
     * A query issues only the first request, so a flag meant for it has to be
     * set here. Only for a query, though: the other operations use this first
     * request to read the generation, and a flag the driver accepts only on the
     * real operation would make that read a rejected request.
     */
    request.flags = (operation == KSWORD_ARK_HVM_NESTED_PAGE_QUERY) ? extraFlags : 0UL;
    if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PAGE,
                         &request, sizeof(request), &response, sizeof(response),
                         &returned, NULL) || returned != sizeof(response)) {
        fprintf(stderr, "nested-page query failed: Win32 %lu\n", GetLastError());
        return 1;
    }
    if (operation != KSWORD_ARK_HVM_NESTED_PAGE_QUERY) {
        if (response.status != 0UL) { return 2; }
        request.operation = operation;
        request.flags = KSWORD_ARK_HVM_NESTED_PAGE_CONFIRMED | extraFlags |
            (faultMode << KSWORD_ARK_HVM_NESTED_PAGE_FAULT_SHIFT);
        request.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
        request.expectedGeneration = response.generation;
        request.ept12Pointer = eptp;
        request.guestPhysicalPage = gpa;
        /* Zero keeps the driver's version-3 meaning; only MAP carries either. */
        request.leafShift = (operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP) ? leafShift : 0UL;
        request.stagePageIndex =
            (operation == KSWORD_ARK_HVM_NESTED_PAGE_STAGE) ? stagePageIndex : 0UL;
        memset(request.shadow, fill, sizeof(request.shadow));
        if (operation == KSWORD_ARK_HVM_NESTED_PAGE_MAP &&
            !resolveNestedPageOwner(ownerPid, &request.ownerProcessId, &request.ownerCreationTime)) {
            fprintf(stderr, "Cannot establish a VMM process lifetime lease.\n");
            return 1;
        }
        if (!DeviceIoControl(h, IOCTL_KSWORD_ARK_HVM_NESTED_PAGE,
                             &request, sizeof(request), &response, sizeof(response),
                             &returned, NULL) || returned != sizeof(response)) {
            fprintf(stderr, "nested-page operation failed: Win32 %lu\n", GetLastError());
            return 1;
        }
    }
    if (asJson) {
        printf("{\"kind\":\"nested-page\",\"operationId\":%lu,\"faultMode\":%lu,\"status\":%lu,\"lastStatus\":\"0x%08lX\","
               "\"generation\":%lu,\"active\":%lu,\"retired\":%lu,\"residentProcessors\":%lu,"
               "\"ept12Pointer\":\"0x%016llX\",\"guestPhysicalPage\":\"0x%016llX\","
               "\"shadowPhysicalPage\":\"0x%016llX\",\"originalPhysicalPage\":\"0x%016llX\","
               "\"composedCount\":%llu,\"ownerProcessId\":%lu,\"ownerExited\":%lu,\"ownerCreationTime\":\"%llu\","
               "\"leafShift\":%lu,\"sourceLeafShift\":%lu,\"regionBytes\":%llu,\"regionPageCount\":%llu,\"stagedPageCount\":%llu,"
               "\"admittedByScan\":%lu,\"scannedLeafCount\":%llu,\"scannedSharedBits\":\"0x%016llX\","
               "\"sourceDigest\":\"0x%016llX\",\"backingDigest\":\"0x%016llX\",\"digestBytes\":%llu,"
               "\"leaseRevocationReason\":%lu,\"sourcePhysicalPage\":\"0x%016llX\",\"sourceEntryCount\":%lu,\"sourcePath\":[",
               response.operationId, faultMode, response.status, response.lastStatus, response.generation, response.active,
               response.retired, response.residentProcessors, response.ept12Pointer,
               response.guestPhysicalPage, response.shadowPhysicalPage,
               response.originalPhysicalPage, response.composedCount, response.ownerProcessId,
               response.ownerExited, response.ownerCreationTime,
               response.leafShift, response.sourceLeafShift, response.regionBytes,
               response.regionPageCount, response.stagedPageCount,
               response.admittedByScan, response.scannedLeafCount,
               response.scannedSharedBits,
               response.sourceDigest, response.backingDigest, response.digestBytes,
               response.leaseRevocationReason,
               response.sourcePhysicalPage, response.sourceEntryCount);
        for (index = 0; index < response.sourceEntryCount && index < 4; ++index) {
            printf("%s{\"address\":\"0x%016llX\",\"value\":\"0x%016llX\"}", index ? "," : "",
                   response.sourceEntryAddress[index], response.sourceEntryValue[index]);
        }
        printf("],\"roots\":[");
    } else {
        printf("nested-page status=%lu nt=0x%08lX generation=%lu active=%lu retired=%lu cpus=%lu\n"
               "leaf=%lu source-leaf=%lu region=%llu bytes (%llu pages) staged=%llu\n"
               "EPT12=0x%016llX GPA=0x%016llX shadow=0x%016llX original=0x%016llX composed=%llu\n",
               response.status, response.lastStatus, response.generation, response.active,
               response.retired, response.residentProcessors,
               response.leafShift, response.sourceLeafShift, response.regionBytes,
               response.regionPageCount, response.stagedPageCount,
               response.ept12Pointer,
               response.guestPhysicalPage, response.shadowPhysicalPage,
               response.originalPhysicalPage, response.composedCount);
        printf("ownerPid=%lu ownerCreated=%llu ownerExited=%lu\n", response.ownerProcessId,
               response.ownerCreationTime, response.ownerExited);
        printf("leaseRevocationReason=%lu sourcePhysicalPage=0x%016llX sourceEntryCount=%lu\n",
               response.leaseRevocationReason, response.sourcePhysicalPage, response.sourceEntryCount);
    }
    for (index = 0UL; index < response.rootCount && index < KSWORD_ARK_HVM_MAX_PROCESSORS; ++index) {
        if (asJson) { printf("%s\"0x%016llX\"", index ? "," : "", response.ept12Roots[index]); }
        else { printf("EPT12 root[%lu]=0x%016llX\n", index, response.ept12Roots[index]); }
    }
    if (asJson) { printf("]}\n"); }
    return response.status == 0UL ? 0 : 2;
}

/* Every command except the scanning one sets no extra request flags. */
static int doNestedPage(HANDLE h, int asJson, unsigned long operation,
                        unsigned long long eptp, unsigned long long gpa,
                        unsigned char fill, unsigned long faultMode, unsigned long ownerPid,
                        unsigned long leafShift, unsigned long stagePageIndex)
{
    return doNestedPageEx(h, asJson, operation, eptp, gpa, fill, faultMode,
                          ownerPid, leafShift, stagePageIndex, 0UL);
}


int kswordHvmCommandMain(int argc, char** argv)
{
    const HvmCommandSpec* spec;
    const char* name;
    unsigned long long v[KSW_HVM_COMMAND_MAX_ARGS];
    char error[256];
    int argi = 1, asJson = 0, validateOnly = 0, rc = 0;
    HANDLE h;
    (void)SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    while (argi < argc) {
        if (strcmp(argv[argi], "--json") == 0) { asJson = 1; ++argi; }
        else if (strcmp(argv[argi], "--validate") == 0) { validateOnly = 1; ++argi; }
        else { break; }
    }
    name = argi < argc ? argv[argi++] : "status";
    spec = kswordHvmFindCommand(name);
    if (!spec) {
        fprintf(stderr, "Unknown HVM command: %s\n", name);
        return 2;
    }
    if (kswordHvmValidateArguments(spec, argc - argi, (const char* const*)(argv + argi),
                                   v, error, sizeof(error)) != 0) {
        fprintf(stderr, "Invalid or missing argument: %s (%s)\n", error, spec->name);
        return 2;
    }
    if (validateOnly) {
        unsigned int i;
        printf("{\"kind\":\"validated\",\"command\":\"%s\",\"operation\":%lu,\"flags\":%lu,\"values\":[",
               spec->name, spec->command, spec->flags);
        for (i = 0; i < spec->argumentCount; ++i) { printf("%s\"0x%016llX\"", i ? "," : "", v[i]); }
        printf("],\"arguments\":[");
        for (i = 0; i < spec->argumentCount; ++i) {
            if (i) { putchar(','); }
            kswordHvmPrintJsonString((int)i < argc - argi ? argv[argi + i] : spec->arguments[i].defaultValue);
        }
        putchar(']');
        if (spec->handler == kHvmControl) {
            KSWORD_ARK_CONTROL_HVM_REQUEST request;
            KswordArkHvmBuildControlRequest(&request, spec->command, spec->flags, 0, (unsigned long)v[0]);
            printf(",\"controlRequest\":{\"version\":%lu,\"size\":%lu,\"command\":%lu,\"flags\":%lu,"
                   "\"expectedGeneration\":%lu,\"soakMilliseconds\":%lu,\"vmreadBenchIterations\":%lu}",
                   request.version, request.size, request.command, request.flags,
                   request.expectedGeneration, request.soakMilliseconds, request.vmreadBenchIterations);
        }
        printf("}\n");
        return 0;
    }
    if (spec->handler == kHvmHelp || spec->handler == kHvmCommands) {
        kswordHvmPrintCommands(asJson);
        return 0;
    }
    if (spec->handler == kHvmCpuid) { return doCpuidView(asJson); }
    h = openDevice();
    if (h == INVALID_HANDLE_VALUE) {
        if (asJson) { printf("{\"kind\":\"error\",\"reason\":\"device-open-failed\"}\n"); }
        return 1;
    }
    switch (spec->handler) {
    case kHvmControl: rc = doControl(h, spec, (unsigned long)v[0], asJson); break;
    case kHvmStatus: rc = doQuery(h, asJson); break;
    case kHvmMetrics: rc = doMetrics(h, asJson); break;
    case kHvmPageQuery: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_QUERY, 0, 0, 0, 0, 0, 0, 0); break;
    case kHvmPageMap: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], (unsigned char)v[2], 0, (unsigned long)v[3], 0, 0); break;
    /* Fill is zero and unused: a region map clones the original, and the driver
       ignores the inline page whenever the granularity is larger than 4 KiB. */
    case kHvmPageMapRegion: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], 0, 0, (unsigned long)v[3], (unsigned long)v[2], 0); break;
    case kHvmPageMapRegionScan: rc = doNestedPageEx(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], 0, 0, (unsigned long)v[3], (unsigned long)v[2], 0, KSWORD_ARK_HVM_NESTED_PAGE_SCAN_SOURCE); break;
    case kHvmPageDigest: rc = doNestedPageEx(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_QUERY, 0, 0, 0, 0, 0, 0, 0, KSWORD_ARK_HVM_NESTED_PAGE_DIGEST); break;
    case kHvmPageStage: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_STAGE, 0, 0, (unsigned char)v[1], 0, 0, 0, (unsigned long)v[0]); break;
    case kHvmPageMapTest: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_MAP, v[0], v[1], (unsigned char)v[2], (unsigned long)v[3], 0, 0, 0); break;
    case kHvmPageRemove: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_REMOVE, 0, 0, 0, 0, 0, 0, 0); break;
    case kHvmPageRemoveTest: rc = doNestedPage(h, asJson, KSWORD_ARK_HVM_NESTED_PAGE_REMOVE, 0, 0, 0, KSWORD_ARK_HVM_NESTED_PAGE_FAULT_REMOVE_FLUSH, 0, 0, 0); break;
    case kHvmAcl: rc = doAclProbe(h, asJson); break;
    case kHvmNestedProbe: rc = doNestedProbe(h, asJson, 0); break;
    case kHvmNestedProbeAll: rc = doNestedProbe(h, asJson, 1); break;
    case kHvmNestedAd: rc = doNestedProbeAdRefusal(h, asJson); break;
    case kHvmSelfvirt: rc = doNestedSelfVirtualize(h, asJson, 0); break;
    case kHvmSelfvirtAll: rc = doNestedSelfVirtualize(h, asJson, 1); break;
    case kHvmGdt: rc = doGdtDump(h, asJson, (int)v[0]); break;
    case kHvmMsrLog: rc = doMsrPolicy(h, KSWORD_ARK_HVM_MSR_POLICY_OP_ADD, (unsigned long)v[0], asJson); break;
    case kHvmMsrClear: rc = doMsrPolicy(h, KSWORD_ARK_HVM_MSR_POLICY_OP_CLEAR, 0, asJson); break;
    case kHvmXonly: rc = doProbeExecuteOnly(h, asJson); break;
    case kHvmAllowOnce: rc = doRuleAllowOnceGate(h, asJson); break;
    case kHvmTlb: rc = doTlbProbe(h, asJson, (unsigned long)v[0], 0); break;
    case kHvmTlbExit: rc = doTlbProbe(h, asJson, (unsigned long)v[0], 1); break;
    case kHvmPlatform: rc = doProbePlatform(h, asJson); break;
    case kHvmFlags: rc = doProbeFlags(h, asJson); break;
    case kHvmViewQuery: rc = doViewQuery(h, asJson); break;
    case kHvmViewProbe: rc = doViewProbe(h, asJson); break;
    case kHvmViewEffect: rc = doViewEffect(h, asJson); break;
    case kHvmSelfcheck: rc = doSelfCheck(h, asJson); break;
    case kHvmViewVerify: rc = doViewVerify(h, asJson); break;
    case kHvmEvents: rc = doEvents(h, v[0], (unsigned long)v[1], asJson); break;
    case kHvmEptLeaf: rc = doEptLeaf(h, v[0], asJson); break;
    case kHvmCrOn: rc = doCrTrackCr3(h, 1, asJson); break;
    case kHvmCrOff: rc = doCrTrackCr3(h, 0, asJson); break;
    case kHvmInjectQuery: rc = doInjectSimple(h, KSWORD_ARK_HVM_INJECT_OP_QUERY, 0, asJson); break;
    case kHvmInjectClear: rc = doInjectSimple(h, KSWORD_ARK_HVM_INJECT_OP_RELEASE_ALL, 0, asJson); break;
    case kHvmInjectRelease: rc = doInjectSimple(h, KSWORD_ARK_HVM_INJECT_OP_RELEASE, (unsigned long)v[0], asJson); break;
    case kHvmInjectTest: rc = doInjectTest(h, (unsigned long)v[0], v[1], v[2], (unsigned long)v[3], asJson); break;
    case kHvmInjectDll: rc = doInjectDll(h, (unsigned long)v[0], v[1], v[2], argv[argi + 3], asJson); break;
    case kHvmProcQuery: rc = doProcess(h, KSWORD_ARK_HVM_PROCESS_OP_QUERY, 0, 0, asJson); break;
    case kHvmProcClear: rc = doProcess(h, KSWORD_ARK_HVM_PROCESS_OP_RELEASE_ALL, 0, 0, asJson); break;
    case kHvmProcRelease: rc = doProcess(h, KSWORD_ARK_HVM_PROCESS_OP_RELEASE, (unsigned long)v[0], 0, asJson); break;
    case kHvmProcFreeze: rc = doProcess(h, KSWORD_ARK_HVM_PROCESS_OP_FREEZE, (unsigned long)v[0], v[1], asJson); break;
    case kHvmProcTerminate: rc = doProcess(h, KSWORD_ARK_HVM_PROCESS_OP_TERMINATE, (unsigned long)v[0], v[1], asJson); break;
    case kHvmWatchAddVa: {
        unsigned long long physical = 0ULL;

        /*
         * Translate once and bind it.
         *
         * Afterwards, if the guest remaps the same virtual address to a different physical page, this watch will not follow it.
         * Here, the translation result is written to the output as-is to allow automated checks to verify 'exactly which
         * page I am monitoring', rather than assuming the binding relationship holds just by looking at a virtual address.
         */
        rc = watchTranslate(h, v[0], &physical);
        if (rc == 0) {
            rc = doWatch(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL,
                         physical & ~0xFFFULL, v[0], v[1],
                         (unsigned long)v[2],
                         KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL, asJson);
        }
        break;
    }
    case kHvmWatchAddPa:
        rc = doWatch(h, KSWORD_ARK_HVM_EPT_RULE_ADD, 0UL,
                     v[0] & ~0xFFFULL, v[0], v[1], (unsigned long)v[2],
                     KSWORD_ARK_HVM_WATCH_ADDRESS_PHYSICAL, asJson);
        break;
    case kHvmWatchList:
        rc = doWatch(h, KSWORD_ARK_HVM_EPT_RULE_WATCH_QUERY, 0UL,
                     0ULL, 0ULL, 0ULL, 0UL, 0UL, asJson);
        break;
    case kHvmWatchRearm:
        rc = doWatch(h, KSWORD_ARK_HVM_EPT_RULE_REARM, (unsigned long)v[0],
                     0ULL, 0ULL, 0ULL, 0UL, 0UL, asJson);
        break;
    case kHvmWatchRemove:
        rc = doWatch(h, KSWORD_ARK_HVM_EPT_RULE_REMOVE, (unsigned long)v[0],
                     0ULL, 0ULL, 0ULL, 0UL, 0UL, asJson);
        break;
    case kHvmWatchSelfTest:
        rc = doWatchSelfTestAccess(h, asJson, KSWORD_ARK_HVM_EPT_ACCESS_WRITE);
        break;
    case kHvmWatchSelfTestRead:
        rc = doWatchSelfTestAccess(h, asJson, KSWORD_ARK_HVM_EPT_ACCESS_READ);
        break;
    case kHvmWatchSelfTestExec:
        rc = doWatchSelfTestAccess(h, asJson, KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE);
        break;
    case kHvmWatchSelfTestSmp:
        rc = doWatchSelfTestSmp(h, asJson);
        break;
    case kHvmWatchSelfTestRemap:
        rc = doWatchSelfTestRemap(h, asJson);
        break;
    case kHvmWatchSelfTestEvidence:
        rc = doWatchSelfTestEvidence(h, asJson);
        break;
    case kHvmWatchSelfTestConflict:
        rc = doWatchSelfTestConflict(h, asJson);
        break;
    case kHvmWatchSelfTestRestart:
        rc = doWatchSelfTestRestart(h, asJson);
        break;
    case kHvmWatchSelfTestProcess:
        rc = doWatchSelfTestProcess(h, asJson);
        break;
    default: rc = 2; break;
    }
    CloseHandle(h);
    return rc;
}

int kswordHvmCommandMainWide(int argc, wchar_t** argv)
{
    char** utf8;
    int i, result = 1;
    if (argc < 1) { return 2; }
    utf8 = (char**)calloc((size_t)argc + 1, sizeof(*utf8));
    if (utf8 == NULL) { return 1; }
    for (i = 0; i < argc; ++i) {
        int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, NULL, 0, NULL, NULL);
        if (length <= 0) { goto cleanup; }
        utf8[i] = (char*)malloc((size_t)length);
        if (utf8[i] == NULL || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            argv[i], -1, utf8[i], length, NULL, NULL)) { goto cleanup; }
    }
    result = kswordHvmCommandMain(argc, utf8);
cleanup:
    for (i = 0; i < argc; ++i) { free(utf8[i]); }
    free(utf8);
    return result;
}

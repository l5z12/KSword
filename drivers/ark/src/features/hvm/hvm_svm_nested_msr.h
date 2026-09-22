/* Software ownership of SVM MSRs; never forwards an operand to a physical MSR. */
#pragma once
#include "hvm_svm_arch.h"
/* Return codes distinguish an owned access, #GP, and an unrelated MSR. */
#define KSW_NSVM_MSR_OK 0U
/* A rejected access must preserve RIP and inject #GP(0). */
#define KSW_NSVM_MSR_GP 1U
/* The outer dispatcher retains ownership of other intercepted MSRs. */
#define KSW_NSVM_MSR_OTHER 2U
/* Virtual state belongs to one logical processor, not to a process or APIC ID. */
typedef struct KswNsvmMsrs {
    /* EFER.SVME is guest-owned here, distinct from the real backend-owned bit. */
    KswSvmU64 efer;
    /* Hardware's opaque HSAVE format is never used for virtual host state. */
    KswSvmU64 hsave;
    /* Firmware configuration is exposed read-only by this first implementation. */
    KswSvmU64 vmCr;
    /* Validated address mask captured at prepare. */
    KswSvmU64 addressMask;
} KswNsvmMsrs;
/* Baseline admits SVME transitions, aligned HSAVE and idempotent VM_CR only. */
static __inline unsigned int kswSvmNestedMsrAccess(KswNsvmMsrs* state,
    unsigned int msr, unsigned int write, KswSvmU64* value)
{
    /* EFER changes beyond virtual SVM ownership need separate mode validation. */
    if (msr == KSW_SVM_MSR_EFER) {
        /* An unimplemented paging-mode change cannot silently reach real EFER. */
        if (write && ((*value ^ state->efer) & ~KSW_SVM_EFER_SVME)) { return KSW_NSVM_MSR_GP; }
        /* Virtual firmware disable remains authoritative. */
        if (write && (*value & KSW_SVM_EFER_SVME) && (state->vmCr & 0x10ULL)) { return KSW_NSVM_MSR_GP; }
        /* Update only the software image. */
        if (write) { state->efer = *value; }
        /* RDMSR must report the virtual bit, not the monitor's real SVME. */
        else { *value = state->efer; }
        /* This MSR access completed. */
        return KSW_NSVM_MSR_OK;
    }
    /* HSAVE is a virtual address/ownership declaration, not a WRMSR passthrough. */
    if (msr == KSW_SVM_MSR_HSAVE) {
        /* Refuse reserved low/high bits and absent address-width evidence. */
        if (write && (!state->addressMask || (*value & ~state->addressMask))) { return KSW_NSVM_MSR_GP; }
        /* Zero is useful when the guest relinquishes ownership. */
        if (write) { state->hsave = *value; }
        /* Never disclose the real host-save page. */
        else { *value = state->hsave; }
        /* No physical ownership register was touched. */
        return KSW_NSVM_MSR_OK;
    }
    /* Firmware configuration is read-only except harmless identical writes. */
    if (msr == KSW_SVM_MSR_VM_CR) {
        /* Changes to locks or firmware disable are outside this implementation. */
        if (write && *value != state->vmCr) { return KSW_NSVM_MSR_GP; }
        /* Return only the captured virtual firmware image. */
        *value = state->vmCr;
        /* The read or identical write completed. */
        return KSW_NSVM_MSR_OK;
    }
    /* Let the outer policy decide unrelated MSRs. */
    return KSW_NSVM_MSR_OTHER;
}

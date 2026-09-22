/* Architectural state subsets for software SVM nesting, APM 15.5.1/15.5.2/15.6. */
#pragma once
#include "hvm_svm_arch.h"

/* VMLOAD/VMSAVE state is separate from the state switched by VMRUN/VMEXIT. */
void kswSvmNestedCopyVmload(KswSvmVmcb* destination, const KswSvmVmcb* source);
/* Baseline VMRUN state only; the entry owner separately validates all controls. */
void kswSvmNestedCopyVmrun(KswSvmVmcb* destination, const KswSvmVmcb* source,
    unsigned int nestedPaging);
/* Save a hardware exit to VMCB12 without leaking host addresses or changing controls. */
void kswSvmNestedReflectExit(KswSvmVmcb* vmcb12, const KswSvmVmcb* vmcb02,
    unsigned int nestedPaging);
/* Raw intercept classification precedes MSRPM/IOPM fine-grained checks by the caller. */
unsigned int kswSvmNestedInterceptRequested(const KswSvmVmcb* vmcb12,
    KswSvmU64 exitCode);
/* Unknown exit ranges must not silently become handled/reenter decisions. */
#define KSW_NSVM_INTERCEPT_UNKNOWN 2U

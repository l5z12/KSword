/* Vendor dispatch without introducing a function-pointer call on every VMEXIT. */
#include "hvm_backend.h"
#if defined(_M_AMD64)
#include "hvm_svm.h"
/* Baseline AMD lifecycle; optional Intel features never reach these operations. */
static const KswHvmBackendOps kKswSvmOps = {
    /* Hardware probe and strict option validator. */
    kswordSvmProbe, kswordSvmValidateFlags,
    /* Independent resource ownership and release. */
    kswordSvmPrepare, kswordSvmRelease,
    /* Shared-phase CPU self-test, start and stop. */
    kswordSvmSelfTest, kswordSvmStart, kswordSvmStop
};
#endif

/* Backend choice is explicit; non-x64 architectures never link SVM assembly. */
const KswHvmBackendOps* kswordHvmBackend(ULONG backend)
{
#if defined(_M_AMD64)
    /* Only SVM takes the new execution boundary in this increment. */
    if (backend == KSWORD_ARK_HVM_BACKEND_SVM) { return &kKswSvmOps; }
#else
    /* ARM64 has no AMD64 SVM backend. */
    UNREFERENCED_PARAMETER(Backend);
#endif
    /* Intel remains handled by existing VMX functions and tests. */
    return NULL;
}

/* Caller holds the runtime lifetime lock; CPU-local counters may still change. */
VOID kswordHvmBackendQuery(KswHvmRuntime* runtime, KSWORD_ARK_QUERY_HVM_RESPONSE* response)
{
    /* Always identify the architecture even before prepare. */
    response->backend = runtime->backendId;
    /* Consumers must not mistake a successful control for a power transition. */
    response->powerGeneration = (ULONG)runtime->powerTransitionGeneration;
    /* Missing privileged evidence never becomes an implicit zero-valued success. */
    response->svmCapabilities = runtime->svmCapabilities;
    /* No active backend means no claimed translation implementation. */
    response->slatType = runtime->backendId == KSWORD_ARK_HVM_BACKEND_SVM ? KSWORD_ARK_HVM_SLAT_NPT :
        (runtime->backendId == KSWORD_ARK_HVM_BACKEND_VMX ? KSWORD_ARK_HVM_SLAT_EPT : KSWORD_ARK_HVM_SLAT_NONE);
    /* Generic readiness follows real prepared ownership. */
    response->slatReady = (runtime->stateFlags & KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0;
    /* Retain a backend-specific status without overloading VM-instruction error. */
    response->backendStatus = (ULONG)runtime->lastStatus;
#if defined(_M_AMD64)
    /* AMD rows describe SVM state, not a zero-valued VMX result. */
    if (runtime->backendId == KSWORD_ARK_HVM_BACKEND_SVM && runtime->backendContext != NULL) {
        /* Resources are kept alive by the query caller's shared lock. */
        KswSvmState* state = runtime->backendContext;
        /* Traverse the exact prepared CPU set. */
        ULONG index;
        /* NPT readiness requires an actual complete root. */
        response->slatReady = state->npt.rootPa != 0;
        /* Read public row additions without dereferencing unrelated Intel contexts. */
        for (index = 0; index < state->count; ++index) {
            /* CPU-local stages are naturally aligned atomic words. */
            response->processors[index].executionStage = (ULONG)state->cpus[index].stage;
            /* Make the correct decoder explicit per CPU. */
            response->processors[index].backend = KSWORD_ARK_HVM_BACKEND_SVM;
        }
    }
#endif
}

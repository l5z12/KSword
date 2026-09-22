/* Narrow backend boundary; Intel continues through the existing VMX adapter. */
#pragma once
#include "hvm_internal.h"

/* Execution policy is selected once, never guessed from a VM-exit number. */
typedef struct KswHvmBackendOps {
    /* Probe current hardware without claiming VMRUN evidence. */
    NTSTATUS (*probeCapabilities)(KswHvmRuntime*);
    /* Reject unimplemented options before any allocation. */
    NTSTATUS (*validateStartFlags)(KswHvmRuntime*, ULONG);
    /* PASSIVE_LEVEL resource preparation. */
    NTSTATUS (*prepareResources)(KswHvmRuntime*, ULONG);
    /* Release only after native ownership is proven. */
    VOID (*releaseResources)(KswHvmRuntime*);
    /* Run the complete processor-pinned self-test set. */
    NTSTATUS (*selfTest)(KswHvmRuntime*, ULONG);
    /* Transactional all-CPU resident start. */
    NTSTATUS (*start)(KswHvmRuntime*, ULONG);
    /* Transactional all-CPU native return. */
    NTSTATUS (*stop)(KswHvmRuntime*);
} KswHvmBackendOps;
/* NULL selects the unchanged legacy Intel VMX execution path. */
const KswHvmBackendOps* kswordHvmBackend(ULONG backend);
/* Query processor state using the selected vendor's interpretation. */
VOID kswordHvmBackendQuery(KswHvmRuntime* runtime, KSWORD_ARK_QUERY_HVM_RESPONSE* response);

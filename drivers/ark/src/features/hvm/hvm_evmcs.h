/*++

Module Name:

    hvm_evmcs.h

Abstract:

    Defines TLFS feature discovery and explicit eVMCS v1 implementation state.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* Discover Hyper-V eVMCS support from TLFS CPUID leaves only. */
VOID
kswordArkHvmEvmcsDiscover(
    _Inout_ KswHvmRuntime* runtime
    );

/* Validate whether eVMCS v1 can be activated in the current partition. */
NTSTATUS
kswordArkHvmEvmcsValidate(
    _Inout_ KswHvmRuntime* runtime
    );

EXTERN_C_END

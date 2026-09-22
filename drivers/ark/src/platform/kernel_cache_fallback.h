#pragma once

#include "dyndata_fallback_resolver.h"

EXTERN_C_START

VOID
kswordArkDriverResolveKernelCacheFallback(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* ntoskrnlIdentity,
    _Inout_ PkswRuntimeKernelLayout layout
    );

EXTERN_C_END

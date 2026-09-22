#pragma once

#include "ark_dyndata.h"

EXTERN_C_START

ULONG
kswordArkDynDataCountFieldDescriptors(
    VOID
    );

ULONG
kswordArkDynDataCopyFieldDescriptors(
    _In_ const KswDynState* state,
    _Out_writes_opt_(entryCapacity) KSW_DYN_FIELD_ENTRY* entries,
    _In_ ULONG entryCapacity
    );

ULONG64
kswordArkDynDataComputeCapabilities(
    _In_ const KswDynState* state
    );

EXTERN_C_END

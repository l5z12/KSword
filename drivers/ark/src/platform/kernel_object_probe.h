#pragma once

#include <ntddk.h>

EXTERN_C_START

BOOLEAN
kswordArkKernelProbeResourceIsSystemResource(
    _In_ ULONG_PTR address
    );

BOOLEAN
kswordArkKernelProbeListHeadIsSane(
    _In_ ULONG_PTR listHeadAddress
    );

BOOLEAN
kswordArkKernelProbeRangeIsResident(
    _In_opt_ const volatile VOID* address,
    _In_ SIZE_T size
    );

EXTERN_C_END

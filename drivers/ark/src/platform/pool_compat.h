#pragma once

#include "ark/ark_driver.h"

EXTERN_C_START

PVOID
kswordArkAllocateNonPagedPool(
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG poolTag
    );

EXTERN_C_END

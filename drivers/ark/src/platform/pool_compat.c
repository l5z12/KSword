/*++

Module Name:

    pool_compat.c

Abstract:

    Nonpaged-pool allocation compatibility for kernels that do not export
    ExAllocatePool2.

Environment:

    Kernel-mode Driver Framework

--*/

#include "pool_compat.h"

typedef PVOID
(NTAPI* KswExAllocatePooL2Routine)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

PVOID
kswordArkAllocateNonPagedPool(
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG poolTag
    )
/*++

Routine Description:

    Allocate nonpaged memory without creating a static ExAllocatePool2 import.
    New kernels use ExAllocatePool2; earlier kernels fall back to
    ExAllocatePoolWithTag with the non-executable nonpaged pool type.

Arguments:

    NumberOfBytes - Number of bytes requested by the caller.
    PoolTag - Four-character allocation tag owned by the caller.

Return Value:

    Allocated nonpaged buffer, or NULL when the request cannot be satisfied.

--*/
{
    UNICODE_STRING routineName;
    KswExAllocatePooL2Routine allocatePool2 = NULL;

    if (numberOfBytes == 0U) {
        return NULL;
    }

    RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
    allocatePool2 = (KswExAllocatePooL2Routine)MmGetSystemRoutineAddress(&routineName);
    if (allocatePool2 != NULL) {
        return allocatePool2(POOL_FLAG_NON_PAGED, numberOfBytes, poolTag);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, numberOfBytes, poolTag);
#pragma warning(pop)
}

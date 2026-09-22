#pragma once

#include <ntddk.h>
#include <wdf.h>

EXTERN_C_START

// Shared validation helpers keep WDF buffer retrieval and common access checks
// out of feature handlers while leaving semantic checks in each feature owner.
NTSTATUS
kswordArkRetrieveRequiredInputBuffer(
    _In_ WDFREQUEST request,
    _In_ size_t requiredLength,
    _Outptr_result_bytebuffer_(*actualLengthOut) PVOID* bufferOut,
    _Out_ size_t* actualLengthOut
    );

NTSTATUS
kswordArkRetrieveOptionalInputBuffer(
    _In_ WDFREQUEST request,
    _In_ size_t suppliedInputLength,
    _In_ size_t requiredLength,
    _Outptr_result_bytebuffer_(*actualLengthOut) PVOID* bufferOut,
    _Out_ size_t* actualLengthOut,
    _Out_ BOOLEAN* presentOut
    );

NTSTATUS
kswordArkRetrieveRequiredOutputBuffer(
    _In_ WDFREQUEST request,
    _In_ size_t requiredLength,
    _Outptr_result_bytebuffer_(*actualLengthOut) PVOID* bufferOut,
    _Out_ size_t* actualLengthOut
    );

NTSTATUS
kswordArkValidateUserPid(
    _In_ ULONG processId
    );

NTSTATUS
kswordArkValidateDeviceIoControlWriteAccess(
    _In_ WDFREQUEST request
    );

EXTERN_C_END

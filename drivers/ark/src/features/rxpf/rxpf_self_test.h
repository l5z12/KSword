#pragma once

#include <ntddk.h>

EXTERN_C_START

_Must_inspect_result_
NTSTATUS
kswRxpfRunConcurrentExecutionTest(
    _In_ PVOID pageAddress,
    _In_ ULONGLONG expectedValue,
    _Out_ ULONGLONG* returnedValueOut,
    _Out_ ULONG* workerCountOut
    );

EXTERN_C_END

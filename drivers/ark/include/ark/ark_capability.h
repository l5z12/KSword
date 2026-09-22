#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkCapabilityIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkCapabilityQuery(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

VOID
kswordArkCapabilityInitialize(
    VOID
    );

VOID
kswordArkCapabilityRecordLastError(
    _In_ NTSTATUS status,
    _In_z_ PCSTR sourceText,
    _In_z_ PCSTR summaryText
    );

BOOLEAN
kswordArkCapabilityIsIoctlAllowed(
    _In_ ULONG64 requiredCapability,
    _Out_opt_ NTSTATUS* deniedStatusOut
    );

EXTERN_C_END

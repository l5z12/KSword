#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkKernelObjectIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkKernelObjectIoctlEnumTypeTable(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END

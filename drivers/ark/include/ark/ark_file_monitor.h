#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkFileMonitorIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkFileMonitorInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath,
    _In_opt_ WDFDEVICE device
    );

VOID
kswordArkFileMonitorUninitialize(
    VOID
    );

NTSTATUS
kswordArkFileMonitorControl(
    _In_ const KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST* request
    );

NTSTATUS
kswordArkFileMonitorQueryStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkFileMonitorDrain(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

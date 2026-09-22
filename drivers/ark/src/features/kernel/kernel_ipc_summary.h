#pragma once

#include <ntddk.h>

#include "driver/KswordArkKernelObjectIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverQueryIpcSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

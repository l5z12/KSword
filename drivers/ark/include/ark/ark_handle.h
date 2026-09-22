#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkHandleIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverEnumerateProcessHandles(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryHandleObject(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

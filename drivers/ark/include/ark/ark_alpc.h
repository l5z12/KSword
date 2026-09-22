#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkAlpcIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverQueryAlpcPort(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_ALPC_PORT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

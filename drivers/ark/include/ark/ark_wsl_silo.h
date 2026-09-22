#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkWslSiloIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverQueryWslSilo(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_WSL_SILO_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkPreflightIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkPreflightQuery(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_QUERY_PREFLIGHT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkRedirectIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkRedirectInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_opt_ WDFDEVICE device
    );

VOID
kswordArkRedirectUninitialize(
    VOID
    );

NTSTATUS
kswordArkRedirectSetRules(
    _In_ const KSWORD_ARK_REDIRECT_SET_RULES_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkRedirectQueryStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

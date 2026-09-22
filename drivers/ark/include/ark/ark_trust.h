#pragma once

#include <ntddk.h>
#include "driver/KswordArkTrustIoctl.h"

EXTERN_C_START

VOID
kswordArkTrustInitialize(
    VOID
    );

NTSTATUS
kswordArkDriverQueryImageTrust(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryImageSignature(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

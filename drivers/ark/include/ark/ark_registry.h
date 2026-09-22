#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkRegistryIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverReadRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverEnumRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverSetRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverDeleteRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverCreateRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverDeleteRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverRenameRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_RENAME_REGISTRY_VALUE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverRenameRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

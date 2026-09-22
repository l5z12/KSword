#pragma once

#include <ntddk.h>

#include "driver/KswordArkStorageIoctl.h"
#include "driver/KswordArkStorageForensicsIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkStorageQueryVolumeStackAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkStorageQueryBitLockerFveAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkStorageQueryMountMgrMappingAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkStorageQueryFileSystemIntegrityAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkStorageQueryRawDiskBackend(
    _In_ const KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST* request,
    _Out_ KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE* response
    );

NTSTATUS
kswordArkStorageReadRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_READ_REQUEST* request,
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkStorageWriteRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_WRITE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ KSWORD_ARK_RAW_DISK_WRITE_RESPONSE* response
    );

EXTERN_C_END

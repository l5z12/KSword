#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkKernelObjectIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkKernelObjectIoctlEnumCidTable(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkKernelObjectIoctlQueryObjectSummary(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkKernelObjectIoctlQueryIpcSummary(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

NTSTATUS
kswordArkDriverEnumerateCidTable(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_CID_TABLE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryKernelObjectSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryIpcSummary(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkMemoryIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverQueryVirtualMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverReadVirtualMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverWriteVirtualMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* request,
    _In_ size_t requestBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverReadPhysicalMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverWritePhysicalMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST* request,
    _In_ size_t requestBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverTranslateVirtualAddress(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverQueryPageTableEntry(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * Note: R0 kernel executable page conservative scan backend. Input is shared protocol request and METHOD_BUFFERED output
 * buffer; processing only reads loaded kernel module snapshots, PE section metadata, and page table resolution results
 * without writing PTEs, modifying CR0, or committing the full kernel address space; STATUS_SUCCESS indicates a valid
 * response header, while scan integrity and partial/conservative status are expressed via response->status/lastStatus.
 */
NTSTATUS
kswordArkDriverScanKernelExecutableMemory(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

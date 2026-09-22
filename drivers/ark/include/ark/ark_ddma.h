#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkDdmaIoctl.h"

EXTERN_C_START

/*
 * Note: DDMA (Disk Direct Memory Access) backend. Leverages the \Driver\Disk device stack's ATA_PASS_THROUGH_DIRECT
 * + ATA_FLAGS_USE_DMA to allow the disk controller to perform bus-master DMA on arbitrary physical addresses. The
 * data path bypasses CPU page tables and SLAT/EPT, enabling reads of physical pages redirected by upper-layer
 * virtualization; the trade-off is the necessity to borrow a disk sector as a transit buffer.
 *
 * All three functions require PASSIVE_LEVEL (internally waiting for IRP completion). Returning STATUS_SUCCESS only
 * indicates the response packet is valid; the semantic result is always expressed via the status field in the response.
 */

NTSTATUS
kswordArkDriverDdmaQueryCapability(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverDdmaReadPhysical(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverDdmaWritePhysical(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST* request,
    _In_ size_t requestBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

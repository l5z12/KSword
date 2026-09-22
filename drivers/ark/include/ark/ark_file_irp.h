#pragma once

#include <ntddk.h>
#include "driver/KswordArkFileIrpIoctl.h"

EXTERN_C_START

/*
 * kswordArkDriverSubmitFileIrp
 * Inputs:
 * - Request is a fixed snapshot of the IOCTL handler request, already copied and
 *   boundary-checked, followed by inline input data passed separately via InputData/InputBytes
 *   to avoid the backend touching the METHOD_BUFFERED system buffer again.
 * Processing:
 * - Parse the target device stack based on targetLayer, allocate the IRP and fill the IO_STACK_LOCATION manually, dispatch
 *   directly to the target driver via IoCallDriver/PoCallDriver, and wait synchronously using a timed completion event.
 * Return behavior:
 * Returns STATUS_SUCCESS when the buffer is usable; specific semantics are written to the response status and
 *   per-stage NTSTATUS. Only return a failure NTSTATUS when the buffer or parameters are fundamentally unusable.
 */
NTSTATUS
kswordArkDriverSubmitFileIrp(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request,
    _In_reads_bytes_opt_(inputBytes) const void* inputData,
    _In_ ULONG inputBytes,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkDriverEnumerateDirectoryByIrp
 * Inputs:
 * - Request specifies the directory's NT path, paged window, and stack layers to bypass.
 * Processing:
 * - Directly dispatch custom IRP_MJ_DIRECTORY_CONTROL/IRP_MN_QUERY_DIRECTORY to the target
 *   layer, converting the FILE_ID_BOTH_DIR_INFORMATION chain into fixed-protocol lines
 *   identical to those from ZwQueryDirectoryFile, facilitating line-by-line diffing in R3.
 * Return behavior:
 * - Consistent with kswordArkDriverEnumerateDirectory: if the buffer is valid, return
 *   STATUS_SUCCESS; the directory semantic results are stored in queryStatus/lastStatus.
 */
NTSTATUS
kswordArkDriverEnumerateDirectoryByIrp(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

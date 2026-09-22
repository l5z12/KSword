#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkThreadIoctl.h"

EXTERN_C_START

/*
 * kswordArkDriverQueryThreadCrossView
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe the METHOD_BUFFERED response
 *   storage supplied by the caller.
 * - Request optionally selects read-only evidence sources, owner PID, TID range,
 *   and traversal node budget.
 * Processing:
 * - Collects thread evidence from psGetNextProcessThread, per-process
 *   ThreadListHead walks, and PspCidTable without accepting R3 object pointers.
 * Return behavior:
 * - Returns request-level NTSTATUS. Source failures and anomalies are encoded in
 *   the response header/rows.
 */
NTSTATUS
kswordArkDriverQueryThreadCrossView(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_THREAD_CROSSVIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkThreadIoctlQueryCrossView
 * Inputs:
 * - Device and Request are the WDF dispatch objects for the unregistered thread
 *   cross-view IOCTL.
 * - InputBufferLength/OutputBufferLength are validated with common WDF helpers.
 * Processing:
 * - Retrieves the optional fixed request and required output buffer, then calls
 *   the read-only thread backend.
 * Return behavior:
 * - Returns the WDF buffer retrieval status or backend status and writes the
 *   response byte count through BytesReturned.
 */
NTSTATUS
kswordArkThreadIoctlQueryCrossView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END

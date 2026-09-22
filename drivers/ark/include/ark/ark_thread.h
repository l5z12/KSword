#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkThreadIoctl.h"

EXTERN_C_START

// Called once by DriverEntry to initialize the global lifecycle registry for thread termination APCs.
VOID
kswordArkThreadApcInitialize(
    VOID
    );

// Called during the earliest phase of driver unload; stop queuing, cancel queue items, and wait for all APC callbacks to exit.
VOID
kswordArkThreadApcUninitialize(
    VOID
    );

NTSTATUS
kswordArkDriverEnumerateThreads(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_THREAD_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkDriverTerminateThreadById
 * Inputs:
 * - ProcessId and ThreadId identify one target thread; ExitStatus supplies its
 *   termination status.
 * Processing:
 * - Resolves the process with the CID-first termination resolver, references
 *   the ETHREAD by TID, verifies ownership, then ends only that thread.
 * Return behavior:
 * - Returns STATUS_SUCCESS when the specified thread is terminated or already
 *   terminating; otherwise returns validation, resolution, or termination status.
 */
NTSTATUS
kswordArkDriverTerminateThreadById(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ ULONG threadId,
    _In_ NTSTATUS exitStatus
    );

// Forces termination of an already referenced ETHREAD; the caller is responsible for identity/module security validation and object reference lifecycle management.
NTSTATUS
kswordArkDriverTerminateReferencedThread(
    _In_ PETHREAD threadObject,
    _In_ NTSTATUS exitStatus
    );

// Experimental raw backend: does not automatically fall back between the two APIs, ensuring UI and logs accurately reflect the actual call.
NTSTATUS
kswordArkDriverTerminateReferencedThreadPsp(
    _In_ PETHREAD threadObject,
    _In_ NTSTATUS exitStatus
    );

NTSTATUS
kswordArkDriverTerminateReferencedThreadZwOrNt(
    _In_ PETHREAD threadObject,
    _In_ NTSTATUS exitStatus
    );

// Schedule PsTerminateSystemThread to execute within the context of the target system thread itself.
// SpecialToNormal=FALSE: enqueue directly to Normal Kernel APC.
// SpecialToNormal=TRUE: First queue a Special Kernel APC, then have it queue a Normal Kernel APC.
NTSTATUS
kswordArkDriverQueueTerminateSystemThreadApc(
    _In_ PETHREAD threadObject,
    _In_ BOOLEAN specialToNormal
    );

/*
 * kswordArkThreadIoctlTerminate
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_TERMINATE_THREAD.
 * Processing:
 * - Validates the fixed request, evaluates process-termination safety policy,
 *   then forwards the requested PID/TID pair to the thread backend.
 * Return behavior:
 * - Returns validation, safety, or backend status and writes request size on success.
 */
NTSTATUS
kswordArkThreadIoctlTerminate(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkThreadIoctlSetSuspended
 * Inputs:
 * - WDF request buffer for IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED.
 * Processing:
 * - Validates PID/TID/action, applies suspend safety policy when needed, then
 *   opens a kernel thread handle after verifying ETHREAD ownership.
 * Return behavior:
 * - Returns validation, safety, ownership, or Zw/Nt suspend/resume status.
 */
NTSTATUS
kswordArkThreadIoctlSetSuspended(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkThreadIoctlControlDriverThread
 * Inputs:
 * - Fixed IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD request.
 * Processing:
 * - Revalidates PID 4 identity, live start address, loaded-driver ownership,
 *   protected-module exclusions, and central safety policy before mutation.
 * Return behavior:
 * - Returns validation, policy, or suspend/resume/terminate backend status.
 */
NTSTATUS
kswordArkThreadIoctlControlDriverThread(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkDriverQueryThreadDetail
 * Inputs:
 * - Response/OutputBufferLength describe a fixed METHOD_BUFFERED response.
 * - Request supplies a TID and optional PID consistency check.
 * Processing:
 * - References ETHREAD by TID and samples PDB/DynData-backed fields with guarded
 *   reads.
 * Return behavior:
 * - Returns STATUS_SUCCESS when response.status contains the query outcome.
 */
NTSTATUS
kswordArkDriverQueryThreadDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_THREAD_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_THREAD_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkThreadIoctlQueryDetail
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL.
 * Processing:
 * - Retrieves fixed request/response buffers and forwards to the feature backend.
 * Return behavior:
 * - Returns WDF retrieval status or backend status; BytesReturned is fixed
 *   response size on success.
 */
NTSTATUS
kswordArkThreadIoctlQueryDetail(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkDriverQueryThreadRuntimeFields
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe a variable METHOD_BUFFERED response.
 * - Request/InputBufferLength describe TID/PID plus PDB runtime field sample items.
 * Processing:
 * - References ETHREAD by TID and reads only bounded small fields from that object.
 * Return behavior:
 * - Returns STATUS_SUCCESS when response metadata is valid; row statuses carry
 *   individual sampling results.
 */
NTSTATUS
kswordArkDriverQueryThreadRuntimeFields(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_reads_bytes_(inputBufferLength) const KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkThreadIoctlQueryRuntimeFields
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS.
 * Processing:
 * - Retrieves variable buffers and forwards to the thread runtime sampler backend.
 * Return behavior:
 * - Returns validation/backend NTSTATUS and writes the actual response byte count.
 */
NTSTATUS
kswordArkThreadIoctlQueryRuntimeFields(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END

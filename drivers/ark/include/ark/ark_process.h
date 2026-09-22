#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkProcessIoctl.h"

EXTERN_C_START

NTSTATUS
kswordArkDriverTerminateProcessByPid(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG processId,
    _In_ NTSTATUS exitStatus,
    _In_ ULONG64 expectedCreateTime100ns
    );

NTSTATUS
kswordArkDriverSuspendProcessByPid(
    _In_ ULONG processId
    );

NTSTATUS
kswordArkDriverResumeProcessByPid(
    _In_ ULONG processId
    );

NTSTATUS
kswordArkDriverSetProcessPplLevelByPid(
    _In_ ULONG processId,
    _In_ UCHAR protectionLevel
    );

/*
 * kswordArkDriverApplyProcessProtectionToObject
 * Inputs:
 * - processObject is the target EPROCESS for which the caller already holds a reference;
 * - protectionLevel is the target PS_PROTECTION byte; 0 indicates clearing protection.
 * Processing:
 * - Shares the same signer-to-signature-level table as the PID-based entry, but skips
 *   PsLookupProcessByProcessId: The object obtained in the process creation callback by the PP
 *   guard is the object itself, and the PID may have been modified by DKOM or already reused.
 * Return behavior:
 * - Returns the NTSTATUS from signature level parsing or EPROCESS write.
 */
NTSTATUS
kswordArkDriverApplyProcessProtectionToObject(
    _In_ PEPROCESS processObject,
    _In_ UCHAR protectionLevel
    );

/*
 * kswordArkDriverSetProcessIntegrityByPid
 * Inputs:
 * - ProcessId selects the target process by PID.
 * - IntegrityRid is the S-1-16-* mandatory label RID to assign.
 * Processing:
 * - First opens the process primary token through kernel Zw* token APIs and
 *   calls ZwSetInformationToken(TokenIntegrityLevel).
 * - If the documented API rejects the label and current-kernel PDB DynData has
 *   _EPROCESS.Token plus _TOKEN integrity offsets, falls back to in-place
 *   mandatory SID replacement inside the token's UserAndGroups array.
 * Return behavior:
 * - Returns STATUS_SUCCESS when either path applies the label; otherwise
 *   returns the relevant API, DynData, validation, or guarded-access status.
 */
NTSTATUS
kswordArkDriverSetProcessIntegrityByPid(
    _In_ ULONG processId,
    _In_ ULONG integrityRid
    );

/*
 * kswordArkDriverQueryProcessTokenPrivilegesByPid
 * Inputs:
 * - ProcessId selects the target process through ZwOpenProcess.
 * - Entries/EntryCapacity describe caller-owned protocol entry storage.
 * Processing:
 * - Opens the primary token with TOKEN_QUERY and reads TokenPrivileges through
 *   ZwQueryInformationToken; no private TOKEN layout is accessed.
 * Return behavior:
 * - TotalCount receives the native token count, ReturnedCount receives copied
 *   entries, and STATUS_BUFFER_OVERFLOW denotes a valid truncated snapshot.
 */
NTSTATUS
kswordArkDriverQueryProcessTokenPrivilegesByPid(
    _In_ ULONG processId,
    _Out_writes_to_(entryCapacity, *returnedCount) KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* entries,
    _In_ ULONG entryCapacity,
    _Out_ ULONG* totalCount,
    _Out_ ULONG* returnedCount
    );

/*
 * kswordArkDriverAdjustProcessTokenPrivilegeByPid
 * Inputs:
 * - ProcessId selects the target process.
 * - PrivilegeLuid identifies one token privilege; Enable selects enabled or disabled.
 * Processing:
 * - Opens the primary token with TOKEN_ADJUST_PRIVILEGES and calls
 *   ZwAdjustPrivilegesToken for exactly one LUID.
 * Return behavior:
 * - Returns the documented Zw* API status without private offsets or fallback writes.
 */
NTSTATUS
kswordArkDriverAdjustProcessTokenPrivilegeByPid(
    _In_ ULONG processId,
    _In_ LUID privilegeLuid,
    _In_ BOOLEAN enable
    );

/*
 * kswordArkDriverDescribeLastProcessIntegrityAttempt
 * Inputs:
 * - Buffer/BufferBytes provide caller-owned ANSI storage for a diagnostic line.
 * Processing:
 * - Copies the last process-integrity API/fallback status snapshot captured in
 *   this driver instance; the data is best-effort and intended for logs.
 * Return behavior:
 * - Returns STATUS_SUCCESS when text was copied; otherwise returns a buffer or
 *   parameter status. The routine does not modify process or token state.
 */
NTSTATUS
kswordArkDriverDescribeLastProcessIntegrityAttempt(
    _Out_writes_bytes_(bufferBytes) CHAR* buffer,
    _In_ SIZE_T bufferBytes
    );

/*
 * kswordArkDriverQueryProcessTokenPrivileges
 * Inputs:
 * - ProcessId selects the target process and ExpectedCreateTime100ns optionally
 *   binds that PID to the process instance observed by R3.
 * Processing:
 * - Opens the primary token through kernel handles and queries TokenPrivileges.
 * - Copies bounded LUID/attribute rows into the shared fixed response.
 * Return behavior:
 * - Returns STATUS_SUCCESS for a complete snapshot, STATUS_BUFFER_OVERFLOW for
 *   a usable truncated snapshot, or the process/token query status on failure.
 */
NTSTATUS
kswordArkDriverQueryProcessTokenPrivileges(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _Out_ KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE* response
    );

/*
 * kswordArkDriverAdjustProcessTokenPrivileges
 * Inputs:
 * - ProcessId/ExpectedCreateTime100ns identify one stable process instance.
 * - Entries contains validated LUID plus enable/disable/remove actions.
 * Processing:
 * - Opens the primary token with TOKEN_ADJUST_PRIVILEGES and applies entries in
 *   request order through ZwAdjustPrivilegesToken.
 * Return behavior:
 * - AppliedCountOut reports the committed prefix. FailedIndexOut identifies the
 *   first rejected row, making partial mutation explicit to R3.
 */
NTSTATUS
kswordArkDriverAdjustProcessTokenPrivileges(
    _In_ ULONG processId,
    _In_ ULONG64 expectedCreateTime100ns,
    _In_reads_(entryCount) const KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY* entries,
    _In_ ULONG entryCount,
    _Out_ ULONG* appliedCountOut,
    _Out_ ULONG* failedIndexOut,
    _Out_ ULONG64* processCreateTime100nsOut
    );

NTSTATUS
kswordArkDriverEnumerateProcesses(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_PROCESS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkDriverSetProcessVisibility(
    _In_ ULONG processId,
    _In_ ULONG action,
    _In_ ULONG flags,
    _Out_ ULONG* statusOut,
    _Out_ ULONG* hiddenCountOut
    );

NTSTATUS
kswordArkDriverSetProcessSpecialFlags(
    _In_ ULONG processId,
    _In_ ULONG action,
    _In_ ULONG flags,
    _In_ ULONG64 expectedCreateTime100ns,
    _Out_ ULONG* operationStatusOut,
    _Out_ ULONG* appliedFlagsOut,
    _Out_ ULONG* touchedThreadCountOut
    );

NTSTATUS
kswordArkDriverDkomProcess(
    _In_ ULONG processId,
    _In_ ULONG action,
    _In_ ULONG flags,
    _Out_ ULONG* operationStatusOut,
    _Out_ ULONG* removedEntriesOut,
    _Out_ ULONG64* pspCidTableAddressOut,
    _Out_ ULONG64* processObjectAddressOut
    );

NTSTATUS
kswordArkDriverInjectProcess(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_INJECT_PROCESS_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_reads_bytes_(inputBufferLength) const KSWORD_ARK_INJECT_PROCESS_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkProcessIoctlInjectProcess(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkDriverQueryProcessCrossView
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe the caller-owned METHOD_BUFFERED
 *   response storage.
 * - Request optionally selects read-only evidence sources and PID bounds.
 * Processing:
 * - Collects process evidence from public enumeration, ActiveProcessLinks, and
 *   PspCidTable without modifying process objects or kernel tables.
 * Return behavior:
 * - Returns an NTSTATUS for request-level validation/allocation. Per-source
 *   read/capability results are reported in the response header and rows.
 */
NTSTATUS
kswordArkDriverQueryProcessCrossView(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkDriverQueryProcessDetail
 * Inputs:
 * - Response/OutputBufferLength describe a fixed METHOD_BUFFERED response.
 * - Request supplies a PID and read-only field groups; no R3 kernel pointer is
 *   trusted.
 * Processing:
 * - References EPROCESS by PID and samples PDB/DynData-backed fields with guarded
 *   reads.
 * Return behavior:
 * - Returns STATUS_SUCCESS when the response packet is valid; response.status
 *   carries lookup/capability/read completeness.
 */
NTSTATUS
kswordArkDriverQueryProcessDetail(
    _Out_writes_bytes_(outputBufferLength) KSWORD_ARK_PROCESS_DETAIL_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_DETAIL_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkProcessIoctlQueryCrossView
 * Inputs:
 * - Device and Request are the WDF dispatch objects for the unregistered
 *   process cross-view IOCTL.
 * - InputBufferLength/OutputBufferLength are validated through WDF helpers.
 * Processing:
 * - Retrieves an optional fixed request plus required output buffer, then calls
 *   the read-only backend. It never accepts R3-provided EPROCESS addresses.
 * Return behavior:
 * - Returns the WDF buffer retrieval status or backend status and writes the
 *   byte count through BytesReturned.
 */
NTSTATUS
kswordArkProcessIoctlQueryCrossView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkProcessIoctlQueryDetail
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL.
 * Processing:
 * - Retrieves fixed request/response buffers and forwards to the feature backend.
 * Return behavior:
 * - Returns WDF retrieval status or backend status; BytesReturned is fixed
 *   response size on success.
 */
NTSTATUS
kswordArkProcessIoctlQueryDetail(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

/*
 * kswordArkDriverQueryProcessRuntimeFields
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe a variable METHOD_BUFFERED response.
 * - Request/InputBufferLength describe PID plus PDB runtime field sample items.
 * Processing:
 * - References EPROCESS by PID and reads only bounded small fields from that object.
 * Return behavior:
 * - Returns STATUS_SUCCESS when the response header is valid; per-row statuses
 *   describe rejected offsets, rejected sizes, and read failures.
 */
NTSTATUS
kswordArkDriverQueryProcessRuntimeFields(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE* response,
    _In_ size_t outputBufferLength,
    _In_reads_bytes_(inputBufferLength) const KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST* request,
    _In_ size_t inputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * kswordArkProcessIoctlQueryRuntimeFields
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS.
 * Processing:
 * - Retrieves variable input/output buffers and forwards to the read-only backend.
 * Return behavior:
 * - Returns validation/backend NTSTATUS and writes the actual response byte count.
 */
NTSTATUS
kswordArkProcessIoctlQueryRuntimeFields(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END

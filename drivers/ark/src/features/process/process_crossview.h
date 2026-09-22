#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "ark/ark_dyndata.h"
#include "driver/KswordArkProcessIoctl.h"

EXTERN_C_START

/*
 * KswCrossviewCidEntry
 * Inputs:
 * - Filled by the read-only CID-table walker for one decoded process/thread
 *   candidate.
 * Processing:
 * - The walker validates type and references live objects when possible before
 *   invoking the callback. Dangling rows are reported without trusting R3 input.
 * Return behavior:
 * - Plain callback payload; ownership of referenced Object remains with the
 *   walker and is released immediately after the callback returns.
 */
typedef struct KswCrossviewCidEntry
{
    PVOID object;
    ULONG64 objectAddress;
    ULONG cidValue;
    BOOLEAN referenced;
    BOOLEAN typeMatched;
    NTSTATUS referenceStatus;
} KswCrossviewCidEntry, *PkswCrossviewCidEntry;

/*
 * KswCrossviewCidCallback
 * Inputs:
 * - Entry describes one type-matched CID table object or a dangling candidate.
 * - Context is the caller-owned builder state.
 * Processing:
 * - The callback merges the evidence row into its process or thread response.
 * Return behavior:
 * - No return value; enumeration continues until the bounded walker stops.
 */
typedef VOID (*KswCrossviewCidCallback)(
    _In_ const KswCrossviewCidEntry* entry,
    _Inout_opt_ PVOID context
    );

BOOLEAN
kswordArkCrossViewOffsetPresent(
    _In_ ULONG offset
    );

ULONG
kswordArkCrossViewNormalizeOffset(
    _In_ ULONG offset
    );

BOOLEAN
kswordArkCrossViewPointerAligned(
    _In_ ULONG_PTR address
    );

VOID
kswordArkCrossViewFillFieldOffsets(
    _In_ const KswDynState* dynState,
    _Out_ KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS* offsets
    );

NTSTATUS
kswordArkCrossViewReadMemory(
    _In_ const VOID* address,
    _Out_writes_bytes_(bytesToRead) VOID* buffer,
    _In_ SIZE_T bytesToRead
    );

NTSTATUS
kswordArkCrossViewReadPointerAddress(
    _In_ const VOID* address,
    _Out_ PVOID* pointerOut
    );

NTSTATUS
kswordArkCrossViewReadUlong64Address(
    _In_ const VOID* address,
    _Out_ ULONGLONG* valueOut
    );

NTSTATUS
kswordArkCrossViewReadPointerField(
    _In_ const VOID* object,
    _In_ ULONG offset,
    _Out_ PVOID* pointerOut
    );

NTSTATUS
kswordArkCrossViewResolvePspCidTableAddress(
    _In_ const KswDynState* dynState,
    _Inout_ KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS* offsets,
    _Out_ PVOID* pspCidTableAddressOut,
    _Out_ ULONG64* missingCapabilityMaskOut,
    _Out_ BOOLEAN* usedDynDataGlobalOut
    );

NTSTATUS
kswordArkCrossViewWalkCidTable(
    _In_ const KswDynState* dynState,
    _In_ PVOID pspCidTableAddress,
    _In_ POBJECT_TYPE expectedObjectType,
    _In_ ULONG maxNodes,
    _In_ KswCrossviewCidCallback callback,
    _Inout_opt_ PVOID context,
    _Out_opt_ ULONG* visitedEntriesOut
    );

/*
 * kswordArkCrossViewReferenceProcessByActiveList
 * Inputs:
 * - DynState supplies EPROCESS.ActiveProcessLinks and UniqueProcessId offsets.
 * - ProcessId is matched against ActiveProcessLinks process identity evidence.
 * Processing:
 * - Walks the kernel active process list, type-checks each candidate, and
 *   returns a referenced EPROCESS without calling NtOpenProcess/ZwOpenProcess.
 * Return behavior:
 * - On STATUS_SUCCESS ProcessOut owns one reference; caller must dereference it.
 */
NTSTATUS
kswordArkCrossViewReferenceProcessByActiveList(
    _In_ const KswDynState* dynState,
    _In_ ULONG processId,
    _In_ ULONG maxNodes,
    _Outptr_ PEPROCESS* processOut,
    _Out_opt_ ULONG* uniqueProcessIdOut,
    _Out_opt_ ULONG* visitedEntriesOut
    );

NTSTATUS
kswordArkDriverQueryProcessCrossView(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

NTSTATUS
kswordArkProcessIoctlQueryCrossView(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    );

EXTERN_C_END

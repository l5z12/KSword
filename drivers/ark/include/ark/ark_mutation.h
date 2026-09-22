#pragma once

#include <ntddk.h>
#include <wdf.h>

#include "driver/KswordArkMutationIoctl.h"

EXTERN_C_START

/*
 * Inputs: none. Processing: initialize the mutation transaction lock, counters,
 * and rings if they have not already been initialized. Return: none.
 */
VOID
kswordArkMutationInitialize(
    VOID
    );

/*
 * Inputs: none. Processing: release every process-object reference owned by a
 * live global transaction slot during driver unload. Return: none.
 */
VOID
kswordArkMutationUninitialize(
    VOID
    );

/*
 * Inputs: WDF device for optional logging, borrowed requestor PID/process
 * identity, shared PREPARE request, and output response buffer. Processing:
 * validate target, snapshot before bytes, bind the transaction to a referenced
 * process object, allocate transactionId, and append audit without writing
 * target memory. Return: NTSTATUS plus KSWORD_ARK_MUTATION_RESPONSE bytes.
 */
NTSTATUS
kswordArkMutationPrepare(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG requestorProcessId,
    _In_ PEPROCESS requestorProcessObject,
    _In_ const KSWORD_ARK_MUTATION_PREPARE_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * Inputs: WDF device for optional safety logging, borrowed requestor identity,
 * transactionId request, and output response buffer. Processing: require the
 * same stable process object, dry-run without FORCE; with FORCE, require target
 * revalidation, before-byte match, safety allow, supported write, and
 * verification. Return: NTSTATUS plus KSWORD_ARK_MUTATION_RESPONSE bytes.
 */
NTSTATUS
kswordArkMutationCommit(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG requestorProcessId,
    _In_ PEPROCESS requestorProcessObject,
    _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * Inputs: WDF device for optional safety logging, borrowed requestor identity,
 * transactionId request, and output response buffer. Processing: require the
 * same stable process object, dry-run without FORCE; with FORCE, restore before
 * snapshot when supported and report idempotent success if already restored.
 * Return: NTSTATUS plus KSWORD_ARK_MUTATION_RESPONSE bytes.
 */
NTSTATUS
kswordArkMutationRollback(
    _In_opt_ WDFDEVICE device,
    _In_ ULONG requestorProcessId,
    _In_ PEPROCESS requestorProcessObject,
    _In_ const KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* request,
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    );

/*
 * Inputs: output response buffer and optional audit query request. Processing:
 * copy recent audit ring entries and redact byteData unless explicitly requested.
 * Return: NTSTATUS plus KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE bytes.
 */
NTSTATUS
kswordArkMutationQueryAudit(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    );

EXTERN_C_END

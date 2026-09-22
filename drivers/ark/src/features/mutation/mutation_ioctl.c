/*++

Module Name:

    mutation_ioctl.c

Abstract:

    IOCTL handlers for the controlled mutation transaction backend.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "mutation_transaction.h"
#include "../../dispatch/ioctl_validation.h"
#include "ark/ark_log.h"

#include <ntstrsafe.h>
#include <stdarg.h>

static NTSTATUS
kswordArkMutationRequestorIdentity(
    _In_ WDFREQUEST request,
    _Out_ ULONG* processIdOut,
    _Outptr_ PEPROCESS* processObjectOut)
/*++

Routine Description:

    Captures the process identifier and stable process object attached to the
    original IOCTL IRP. The object identity, rather than the reusable PID alone,
    is bound to PREPARE state and must match for COMMIT/ROLLBACK.

--*/
{
    PIRP irp = NULL;
    PEPROCESS processObject = NULL;
    ULONG processId = 0UL;

    if (request == NULL ||
        processIdOut == NULL ||
        processObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *processIdOut = 0UL;
    *processObjectOut = NULL;

    irp = WdfRequestWdmGetIrp(request);
    if (irp == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    processId = IoGetRequestorProcessId(irp);
    processObject = IoGetRequestorProcess(irp);
    if (processId == 0UL || processObject == NULL) {
        return STATUS_ACCESS_DENIED;
    }

    *processIdOut = processId;
    *processObjectOut = processObject;
    return STATUS_SUCCESS;
}

static VOID
kswordArkMutationIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...)
/*++

Routine Description:

    Formats one mutation IOCTL diagnostic log entry. The message records only
    transaction metadata and never dumps before/after bytes.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level text.
    FormatText - printf-style format string.
    ... - Format arguments.

Return Value:

    None. Formatting or enqueue failures are ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;
    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (VOID)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

NTSTATUS
kswordArkMutationIoctlPrepare(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
/*++

Routine Description:

    Handles the registered IOCTL_KSWORD_ARK_MUTATION_PREPARE entry. The handler
    validates write access, copies METHOD_BUFFERED input before output is cleared,
    and delegates target validation and before-byte snapshotting to the backend.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input buffer length supplied by dispatch.
    OutputBufferLength - Output buffer length supplied by dispatch.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from access checks, buffer retrieval, or the transaction backend.

--*/
{
    KSWORD_ARK_MUTATION_PREPARE_REQUEST* inputRequest = NULL;
    KSWORD_ARK_MUTATION_PREPARE_REQUEST requestCopy;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG requestorProcessId = 0UL;
    PEPROCESS requestorProcessObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation prepare denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkMutationRequestorIdentity(
        request,
        &requestorProcessId,
        &requestorProcessObject);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation prepare denied: requestor PID unavailable, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_MUTATION_PREPARE_REQUEST),
        (PVOID*)&inputRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation prepare input invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlCopyMemory(&requestCopy, inputRequest, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_MUTATION_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation prepare output invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkMutationPrepare(
        device,
        requestorProcessId,
        requestorProcessObject,
        &requestCopy,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation prepare backend rejected: kind=%lu, status=0x%08X.", (unsigned long)requestCopy.targetKind, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        KSWORD_ARK_MUTATION_RESPONSE* response = (KSWORD_ARK_MUTATION_RESPONSE*)outputBuffer;
        kswordArkMutationIoctlLog(device, "Info", "Mutation prepare response: tx=%I64u, kind=%lu, status=%lu, last=0x%08X.", response->transactionId, (unsigned long)response->targetKind, (unsigned long)response->status, (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMutationIoctlCommit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
/*++

Routine Description:

    Handles the registered IOCTL_KSWORD_ARK_MUTATION_COMMIT entry. The handler only
    accepts a transaction request, copies it before output reuse, and leaves all
    before-match, FORCE, safety policy, and write decisions to the backend.

Arguments:

    Device - WDF device used for logging and safety policy logs.
    Request - Current IOCTL request.
    InputBufferLength - Input buffer length supplied by dispatch.
    OutputBufferLength - Output buffer length supplied by dispatch.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from access checks, buffer retrieval, or the transaction backend.

--*/
{
    KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* inputRequest = NULL;
    KSWORD_ARK_MUTATION_TRANSACTION_REQUEST requestCopy;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG requestorProcessId = 0UL;
    PEPROCESS requestorProcessObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation commit denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkMutationRequestorIdentity(
        request,
        &requestorProcessId,
        &requestorProcessObject);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation commit denied: requestor PID unavailable, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_MUTATION_TRANSACTION_REQUEST),
        (PVOID*)&inputRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation commit input invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlCopyMemory(&requestCopy, inputRequest, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_MUTATION_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation commit output invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkMutationCommit(
        device,
        requestorProcessId,
        requestorProcessObject,
        &requestCopy,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation commit backend failed: tx=%I64u, status=0x%08X.", requestCopy.transactionId, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        KSWORD_ARK_MUTATION_RESPONSE* response = (KSWORD_ARK_MUTATION_RESPONSE*)outputBuffer;
        kswordArkMutationIoctlLog(device, "Info", "Mutation commit response: tx=%I64u, status=%lu, last=0x%08X.", response->transactionId, (unsigned long)response->status, (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMutationIoctlRollback(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
/*++

Routine Description:

    Handles the registered IOCTL_KSWORD_ARK_MUTATION_ROLLBACK entry. Rollback is
    driven only by transactionId and is idempotent when current bytes already
    match the before snapshot.

Arguments:

    Device - WDF device used for logging and safety policy logs.
    Request - Current IOCTL request.
    InputBufferLength - Input buffer length supplied by dispatch.
    OutputBufferLength - Output buffer length supplied by dispatch.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from access checks, buffer retrieval, or the transaction backend.

--*/
{
    KSWORD_ARK_MUTATION_TRANSACTION_REQUEST* inputRequest = NULL;
    KSWORD_ARK_MUTATION_TRANSACTION_REQUEST requestCopy;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    ULONG requestorProcessId = 0UL;
    PEPROCESS requestorProcessObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation rollback denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }
    status = kswordArkMutationRequestorIdentity(
        request,
        &requestorProcessId,
        &requestorProcessObject);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation rollback denied: requestor PID unavailable, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_MUTATION_TRANSACTION_REQUEST),
        (PVOID*)&inputRequest,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation rollback input invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    RtlCopyMemory(&requestCopy, inputRequest, sizeof(requestCopy));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_MUTATION_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation rollback output invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkMutationRollback(
        device,
        requestorProcessId,
        requestorProcessObject,
        &requestCopy,
        outputBuffer,
        actualOutputLength,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation rollback backend failed: tx=%I64u, status=0x%08X.", requestCopy.transactionId, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_MUTATION_RESPONSE)) {
        KSWORD_ARK_MUTATION_RESPONSE* response = (KSWORD_ARK_MUTATION_RESPONSE*)outputBuffer;
        kswordArkMutationIoctlLog(device, "Info", "Mutation rollback response: tx=%I64u, status=%lu, last=0x%08X.", response->transactionId, (unsigned long)response->status, (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkMutationIoctlQueryAudit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned)
/*++

Routine Description:

    Handles the registered IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT entry. The input is
    optional; when omitted the backend returns the newest entries that fit in the
    caller's output buffer without byteData.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input buffer length supplied by dispatch.
    OutputBufferLength - Output buffer length supplied by dispatch.
    BytesReturned - Receives response byte count.

Return Value:

    NTSTATUS from buffer retrieval or audit query backend.

--*/
{
    KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST requestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = IoValidateDeviceIoControlAccess(
        WdfRequestWdmGetIrp(request),
        FILE_READ_ACCESS);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation audit query denied: read access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    status = kswordArkRetrieveOptionalInputBuffer(
        request,
        inputBufferLength,
        sizeof(KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation audit query input invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }
    if (hasInput) {
        RtlCopyMemory(&requestCopy, inputBuffer, sizeof(requestCopy));
    }
    if (hasInput &&
        (requestCopy.flags &
         KSWORD_ARK_MUTATION_QUERY_AUDIT_FLAG_INCLUDE_BYTES) != 0UL) {
        status = kswordArkValidateDeviceIoControlWriteAccess(request);
        if (!NT_SUCCESS(status)) {
            kswordArkMutationIoctlLog(device, "Warn", "Mutation audit byte query denied: write access required, status=0x%08X.", (unsigned int)status);
            return status;
        }
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Error", "Mutation audit query output invalid: status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkMutationQueryAudit(
        outputBuffer,
        actualOutputLength,
        hasInput ? &requestCopy : NULL,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkMutationIoctlLog(device, "Warn", "Mutation audit query backend failed: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_MUTATION_AUDIT_RESPONSE_HEADER_SIZE) {
        KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE* response = (KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*)outputBuffer;
        kswordArkMutationIoctlLog(device, "Info", "Mutation audit query response: total=%lu, returned=%lu, next=%I64u.", (unsigned long)response->totalCount, (unsigned long)response->returnedCount, response->nextSequence);
    }

    return STATUS_SUCCESS;
}

/*++

Module Name:

    kernel_piddb_ioctl.c

Abstract:

    WDF adapters for PiDDB enumeration and safety-gated exact deletion.

--*/

#include "kernel_piddb.h"
#include "../../dispatch/ioctl_validation.h"

NTSTATUS
kswordArkKernelIoctlQueryPiDdb(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_ARK_QUERY_PIDDB_REQUEST requestSnapshot = { 0 };

    /* Retrieve complete fixed input and a variable response header. */
    UNREFERENCED_PARAMETER(device);
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_PIDDB_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_QUERY_PIDDB_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_QUERY_PIDDB_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }
    /* Preserve METHOD_BUFFERED input before output retrieval exposes the same system buffer. */
    RtlCopyMemory(
        &requestSnapshot,
        inputBuffer,
        sizeof(requestSnapshot));
    status = WdfRequestRetrieveOutputBuffer(
        request,
        KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE ||
        actualOutputLength < KSWORD_ARK_QUERY_PIDDB_RESPONSE_HEADER_SIZE) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    /* The backend bounds every row by the actual WDF output length. */
    return kswordArkPiDdbQuery(
        &requestSnapshot,
        (KSWORD_ARK_QUERY_PIDDB_RESPONSE*)outputBuffer,
        actualOutputLength,
        bytesReturned);
}

NTSTATUS
kswordArkKernelIoctlDeletePiDdb(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    KSWORD_ARK_DELETE_PIDDB_REQUEST deleteRequestSnapshot = { 0 };
    const KSWORD_ARK_DELETE_PIDDB_REQUEST* deleteRequest = NULL;
    KSWORD_ARK_DELETE_PIDDB_RESPONSE* deleteResponse = NULL;

    /* Require write access and complete fixed buffers for every delete phase. */
    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;
    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = WdfRequestRetrieveInputBuffer(
        request,
        sizeof(KSWORD_ARK_DELETE_PIDDB_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status) ||
        inputBufferLength < sizeof(KSWORD_ARK_DELETE_PIDDB_REQUEST) ||
        actualInputLength < sizeof(KSWORD_ARK_DELETE_PIDDB_REQUEST)) {
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }
    /* Preserve METHOD_BUFFERED input before output retrieval exposes the same system buffer. */
    RtlCopyMemory(
        &deleteRequestSnapshot,
        inputBuffer,
        sizeof(deleteRequestSnapshot));
    status = WdfRequestRetrieveOutputBuffer(
        request,
        sizeof(KSWORD_ARK_DELETE_PIDDB_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status) ||
        outputBufferLength < sizeof(KSWORD_ARK_DELETE_PIDDB_RESPONSE) ||
        actualOutputLength < sizeof(KSWORD_ARK_DELETE_PIDDB_RESPONSE)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    deleteRequest = &deleteRequestSnapshot;
    deleteResponse =
        (KSWORD_ARK_DELETE_PIDDB_RESPONSE*)outputBuffer;

    /* Evaluate the central kernel-patch safety policy only for mutation. */
    if ((deleteRequest->flags &
            KSWORD_ARK_PIDDB_DELETE_FLAG_FORCE) != 0UL) {
        KswordArkSafetyContext safetyContext = { 0 };

        safetyContext.operation =
            KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.contextFlags =
            (deleteRequest->flags &
                KSWORD_ARK_PIDDB_DELETE_FLAG_UI_CONFIRMED) != 0UL
            ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
            : 0UL;
        safetyContext.targetText =
            L"Exact PiDDB cache entry removal";
        safetyContext.targetTextChars =
            (USHORT)(RTL_NUMBER_OF(
                L"Exact PiDDB cache entry removal") - 1U);
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            RtlZeroMemory(deleteResponse, sizeof(*deleteResponse));
            deleteResponse->version =
                KSWORD_ARK_PIDDB_PROTOCOL_VERSION;
            deleteResponse->size = sizeof(*deleteResponse);
            deleteResponse->status =
                KSWORD_ARK_PIDDB_DELETE_STATUS_DELETE_FAILED;
            deleteResponse->lastStatus = status;
            *bytesReturned = sizeof(*deleteResponse);
            return status;
        }
    }

    /* Perform either the read-only identity preflight or exact deletion. */
    status = kswordArkPiDdbDelete(
        deleteRequest,
        deleteResponse);
    *bytesReturned = sizeof(*deleteResponse);
    return status;
}

/*++

Module Name:

    process_privilege_ioctl.c

Abstract:

    IOCTL handlers for documented process-token privilege operations.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL.

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

static size_t
kswordArkProcessTokenPrivilegeResponseHeaderSize(VOID)
{
    return KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE_HEADER_SIZE;
}

NTSTATUS
kswordArkProcessIoctlQueryTokenPrivileges(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_REQUEST requestSnapshot;
    KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE* response = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t responseHeaderSize = kswordArkProcessTokenPrivilegeResponseHeaderSize();
    size_t entryCapacity = 0U;
    ULONG totalCount = 0UL;
    ULONG returnedCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(device);
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        responseHeaderSize,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    response = (KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, responseHeaderSize);
    response->size = (ULONG)responseHeaderSize;
    response->version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
    response->processId = requestSnapshot.processId;
    response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY);
    response->lastStatus = STATUS_INVALID_PARAMETER;
    *bytesReturned = responseHeaderSize;

    if (requestSnapshot.size != sizeof(requestSnapshot) ||
        requestSnapshot.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
        requestSnapshot.flags != 0UL) {
        return STATUS_SUCCESS;
    }

    status = kswordArkValidateUserPid(requestSnapshot.processId);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    entryCapacity = (actualOutputLength - responseHeaderSize) /
        sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY);
    if (entryCapacity > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES) {
        entryCapacity = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES;
    }

    operationStatus = kswordArkDriverQueryProcessTokenPrivilegesByPid(
        requestSnapshot.processId,
        response->entries,
        (ULONG)entryCapacity,
        &totalCount,
        &returnedCount);

    response->totalCount = totalCount;
    response->returnedCount = returnedCount;
    response->lastStatus = operationStatus;
    if (operationStatus == STATUS_BUFFER_OVERFLOW) {
        response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL;
    }
    else if (NT_SUCCESS(operationStatus)) {
        response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK;
    }

    *bytesReturned = responseHeaderSize +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY));
    response->size = (ULONG)*bytesReturned;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkProcessIoctlAdjustTokenPrivilege(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_REQUEST requestSnapshot;
    KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE* response = NULL;
    KswordArkSafetyContext safetyContext;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    LUID privilegeLuid;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(requestSnapshot),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(*response),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    response = (KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE*)outputBuffer;
    RtlZeroMemory(response, sizeof(*response));
    response->size = sizeof(*response);
    response->version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
    response->processId = requestSnapshot.processId;
    response->luidLowPart = requestSnapshot.luidLowPart;
    response->luidHighPart = requestSnapshot.luidHighPart;
    response->action = requestSnapshot.action;
    response->status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED;
    response->lastStatus = STATUS_INVALID_PARAMETER;
    *bytesReturned = sizeof(*response);

    if (requestSnapshot.size != sizeof(requestSnapshot) ||
        requestSnapshot.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
        requestSnapshot.reserved != 0UL ||
        requestSnapshot.flags != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED ||
        (requestSnapshot.action != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE &&
         requestSnapshot.action != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE)) {
        return STATUS_SUCCESS;
    }

    status = kswordArkValidateUserPid(requestSnapshot.processId);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&safetyContext, sizeof(safetyContext));
    safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_PROCESS_SET_PROTECTION;
    safetyContext.targetProcessId = requestSnapshot.processId;
    safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
    status = kswordArkSafetyEvaluate(device, &safetyContext);
    if (!NT_SUCCESS(status)) {
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    privilegeLuid.LowPart = requestSnapshot.luidLowPart;
    privilegeLuid.HighPart = requestSnapshot.luidHighPart;
    operationStatus = kswordArkDriverAdjustProcessTokenPrivilegeByPid(
        requestSnapshot.processId,
        privilegeLuid,
        requestSnapshot.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE);
    response->lastStatus = operationStatus;
    response->status = NT_SUCCESS(operationStatus)
        ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK
        : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED;

    return STATUS_SUCCESS;
}

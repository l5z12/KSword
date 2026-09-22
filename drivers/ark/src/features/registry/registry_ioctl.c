/*++

Module Name:

    registry_ioctl.c

Abstract:

    IOCTL handlers for KswordARK registry read operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// Non-paged pool tag for the registry IOCTL request copy to prevent METHOD_BUFFERED output from overwriting the input buffer.
#define KSWORD_ARK_REGISTRY_IOCTL_TAG 'iRsK'

static VOID
kswordArkRegistryIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and write the registry IOCTL log. Note: Log failure does not affect the main
    IOCTL, as the read result has already been returned to R3 via a structured response.

Arguments:

    Device - The WDF device object.
    levelText - Log level.
    FormatText - printf-style ANSI template.
    ... - Template arguments.

Return Value:

    None. This function has no return value.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(
        logMessage,
        sizeof(logMessage),
        formatText,
        arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

typedef NTSTATUS (*KswordArkRegistryOperationBackend)(
    PVOID outputBuffer,
    size_t outputBufferLength,
    const VOID* request,
    size_t* bytesWrittenOut);

NTSTATUS
kswordArkRegistryIoctlReadValue(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE. Note: The handler is responsible only
    for WDF buffer validation; registry reading is implemented in registry_query.c.

Arguments:

    Device: WDF device object, used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Input length; must include the fixed request.
    OutputBufferLength: Output length; must accommodate the fixed response.
    BytesReturned - Returns the number of bytes written.

Return Value:

    NTSTATUS from validation or feature backend.

--*/
{
    KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST* readRequest = NULL;
    KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST readRequestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry read ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    readRequest = (KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST*)inputBuffer;

    // For METHOD_BUFFERED, input and output may point to the same SystemBuffer. Copy the entire request first to avoid
    // corrupting the version, keyPath, valueName, and read length parameters when obtaining and initializing the response later.
    RtlCopyMemory(&readRequestCopy, readRequest, sizeof(readRequestCopy));
    readRequest = &readRequestCopy;

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry read ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverReadRegistryValue(
        outputBuffer,
        actualOutputLength,
        readRequest,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry read failed before response: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE)) {
        KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE* response =
            (KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE*)outputBuffer;
        kswordArkRegistryIoctlLog(
            device,
            (response->status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS ||
             response->status == KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND) ? "Info" : "Warn",
            "R0 registry read response: status=%lu, type=%lu, data=%lu/%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->valueType,
            (unsigned long)response->dataBytes,
            (unsigned long)response->requiredBytes,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkRegistryIoctlEnumKey(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
{
    KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST enumRequestCopy;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST), &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry enum ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    enumRequest = (KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST*)inputBuffer;

    // The enumeration request must also be copied before obtaining the output buffer. The lastStatus field of the output response
    // happens to overwrite the start of the request's keyPath, causing the backend to report STATUS_OBJECT_PATH_SYNTAX_BAD.
    RtlCopyMemory(&enumRequestCopy, enumRequest, sizeof(enumRequestCopy));
    enumRequest = &enumRequestCopy;

    if ((enumRequest->flags & ~(KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES)) != 0UL) {
        kswordArkRegistryIoctlLog(device, "Warn", "R0 registry enum ioctl: flags rejected, flags=0x%08X.", (unsigned int)enumRequest->flags);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE), &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry enum ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumRegistryKey(outputBuffer, actualOutputLength, enumRequest, bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry enum failed before response: status=0x%08X.", (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE)) {
        KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE* response = (KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE*)outputBuffer;
        kswordArkRegistryIoctlLog(
            device,
            response->status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS ? "Info" : "Warn",
            "R0 registry enum response: status=%lu, subkeys=%lu/%lu, values=%lu/%lu, last=0x%08X.",
            (unsigned long)response->status,
            (unsigned long)response->returnedSubKeyCount,
            (unsigned long)response->subKeyCount,
            (unsigned long)response->returnedValueCount,
            (unsigned long)response->valueCount,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkRegistryIoctlOperation(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputStructureBytes,
    _In_ PCSTR operationName,
    _In_ KswordArkRegistryOperationBackend backend,
    _Out_ size_t* bytesReturned
    )
{
    PVOID inputBuffer = NULL;
    PVOID requestCopy = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (bytesReturned == NULL || backend == NULL || inputStructureBytes == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Warn", "R0 registry %s denied: write access required, status=0x%08X.", operationName, (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(request, inputStructureBytes, &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry %s ioctl: input invalid, status=0x%08X.", operationName, (unsigned int)status);
        return status;
    }

    // Write request sizes vary; using a non-paged pool copy unifies behavior to avoid METHOD_BUFFERED input/output
    // sharing SystemBuffer, preventing corruption of keyPath or write data when the backend zeroes the response.
#pragma warning(push)
#pragma warning(disable:4996)
    requestCopy = ExAllocatePoolWithTag(
        NonPagedPoolNx,
        inputStructureBytes,
        KSWORD_ARK_REGISTRY_IOCTL_TAG);
#pragma warning(pop)
    if (requestCopy == NULL) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry %s ioctl: request copy allocation failed.", operationName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(requestCopy, inputBuffer, inputStructureBytes);

    status = kswordArkRetrieveRequiredOutputBuffer(request, sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE), &outputBuffer, &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        // Release the allocated request copy even when output buffer validation fails.
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_REGISTRY_IOCTL_TAG);
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry %s ioctl: output invalid, status=0x%08X.", operationName, (unsigned int)status);
        return status;
    }

    status = backend(outputBuffer, actualOutputLength, requestCopy, bytesReturned);
    // Backend has synchronized the read copy; the request lifecycle ends here.
    ExFreePoolWithTag(requestCopy, KSWORD_ARK_REGISTRY_IOCTL_TAG);
    if (!NT_SUCCESS(status)) {
        kswordArkRegistryIoctlLog(device, "Error", "R0 registry %s failed before response: status=0x%08X.", operationName, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = (KSWORD_ARK_REGISTRY_OPERATION_RESPONSE*)outputBuffer;
        kswordArkRegistryIoctlLog(
            device,
            response->status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS ? "Info" : "Warn",
            "R0 registry %s response: status=%lu, last=0x%08X.",
            operationName,
            (unsigned long)response->status,
            (unsigned int)response->lastStatus);
    }

    return STATUS_SUCCESS;
}

NTSTATUS kswordArkRegistryIoctlSetValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned)
{
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkRegistryIoctlOperation(device, request, sizeof(KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST), "set-value", (KswordArkRegistryOperationBackend)kswordArkDriverSetRegistryValue, bytesReturned);
}

NTSTATUS kswordArkRegistryIoctlDeleteValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned)
{
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkRegistryIoctlOperation(device, request, sizeof(KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST), "delete-value", (KswordArkRegistryOperationBackend)kswordArkDriverDeleteRegistryValue, bytesReturned);
}

NTSTATUS kswordArkRegistryIoctlCreateKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned)
{
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkRegistryIoctlOperation(device, request, sizeof(KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST), "create-key", (KswordArkRegistryOperationBackend)kswordArkDriverCreateRegistryKey, bytesReturned);
}

NTSTATUS kswordArkRegistryIoctlDeleteKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned)
{
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkRegistryIoctlOperation(device, request, sizeof(KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST), "delete-key", (KswordArkRegistryOperationBackend)kswordArkDriverDeleteRegistryKey, bytesReturned);
}

NTSTATUS kswordArkRegistryIoctlRenameValue(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned)
{
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkRegistryIoctlOperation(device, request, sizeof(KSWORD_ARK_RENAME_REGISTRY_VALUE_REQUEST), "rename-value", (KswordArkRegistryOperationBackend)kswordArkDriverRenameRegistryValue, bytesReturned);
}

NTSTATUS kswordArkRegistryIoctlRenameKey(_In_ WDFDEVICE device, _In_ WDFREQUEST request, _In_ size_t inputBufferLength, _In_ size_t outputBufferLength, _Out_ size_t* bytesReturned)
{
    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);
    return kswordArkRegistryIoctlOperation(device, request, sizeof(KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST), "rename-key", (KswordArkRegistryOperationBackend)kswordArkDriverRenameRegistryKey, bytesReturned);
}

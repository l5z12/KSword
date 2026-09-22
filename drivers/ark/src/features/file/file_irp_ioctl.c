/*++

Module Name:

    file_irp_ioctl.c

Abstract:

    IOCTL handlers for the self-built file IRP path. This layer does exactly three things: fully
    snapshot METHOD_BUFFERED requests, perform protocol and security boundary validation, and
    invoke the IRP engine in file_irp_request.c, keeping the dispatch layer thin and auditable.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "ark/ark_file_irp.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG 'oIsK'

static VOID
kswordArkFileIrpIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one file-IRP handler log message.

Arguments:

    Device - WDF device that owns the log channel.
    levelText - Log level string.
    FormatText - printf-style ANSI message template.
    ... - Template arguments.

Return Value:

    None. Formatting or enqueue failures are ignored.

--*/
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), formatText, arguments))) {
        (void)kswordArkDriverEnqueueLogFrame(device, levelText, logMessage);
    }
    va_end(arguments);
}

static BOOLEAN
kswordArkFileIrpIoctlPathIsValid(
    _In_reads_(maxChars) PCWSTR path,
    _In_ USHORT pathLengthChars,
    _In_ USHORT maxChars
    )
/*++

Routine Description:

    Validate the fixed-width character path field: length must be non-zero, within capacity, and NUL-terminated.

Arguments:

    Path - Fixed path buffer.
    PathLengthChars - Declared character count.
    MaxChars - buffer capacity.

Return Value:

    TRUE indicates it is safe to use for constructing a UNICODE_STRING.

--*/
{
    if (pathLengthChars == 0U || pathLengthChars >= maxChars) {
        return FALSE;
    }
    return path[pathLengthChars] == L'\0';
}

NTSTATUS
kswordArkFileIrpIoctlEnumDirectory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY. Read-only enumeration; no token confirmation required.
    The only difference from IOCTL_KSWORD_ARK_ENUM_DIRECTORY is which layer the request is dispatched to.

Arguments:

    Device: WDF device object, for logging only.
    Request - Current IOCTL request.
    InputBufferLength/OutputBufferLength - declared lengths provided by the dispatch layer.
    BytesReturned - Total length of the received protocol header and valid directory rows.

Return Value:

    NTSTATUS indicates the result of WDF buffering or protocol processing; directory semantics are stored in response fields.

--*/
{
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST* directoryRequest = NULL;
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST requestSnapshot;
    KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE* directoryResponse = NULL;
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
        sizeof(KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Error",
            "R0 irp-directory ioctl: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input and output share the same system buffer; once the response header is zeroed,
     * path/startIndex/targetLayer are erased, so a full snapshot must be taken before validation.
     */
    directoryRequest = (KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, directoryRequest, sizeof(requestSnapshot));

    if (requestSnapshot.version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
        requestSnapshot.size != (ULONG)sizeof(requestSnapshot) ||
        requestSnapshot.flags != 0UL ||
        requestSnapshot.targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
        requestSnapshot.maxEntries == 0UL ||
        requestSnapshot.maxEntries > KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES ||
        requestSnapshot.startIndex >= KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES ||
        requestSnapshot.maxEntries >
            KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES - requestSnapshot.startIndex ||
        requestSnapshot.reserved != 0U ||
        !kswordArkFileIrpIoctlPathIsValid(
            requestSnapshot.path,
            requestSnapshot.pathLengthChars,
            (USHORT)KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Warn",
            "R0 irp-directory ioctl: request rejected, version=%lu, layer=%lu, start=%lu, max=%lu, chars=%u.",
            (unsigned long)requestSnapshot.version,
            (unsigned long)requestSnapshot.targetLayer,
            (unsigned long)requestSnapshot.startIndex,
            (unsigned long)requestSnapshot.maxEntries,
            (unsigned int)requestSnapshot.pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
            sizeof(KSWORD_ARK_DIRECTORY_ENTRY),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Error",
            "R0 irp-directory ioctl: output invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateDirectoryByIrp(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Error",
            "R0 irp-directory ioctl: feature failed, chars=%u, status=0x%08X.",
            (unsigned int)requestSnapshot.pathLengthChars,
            (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        directoryResponse =
            (KSWORD_ARK_FILE_IRP_ENUM_DIRECTORY_RESPONSE*)outputBuffer;
        if (directoryResponse->queryStatus !=
                KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK &&
            directoryResponse->queryStatus !=
                KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL) {
            kswordArkFileIrpIoctlLog(
                device,
                "Warn",
                "R0 irp-directory semantic failure: layer=%lu, query=%lu, status=0x%08X.",
                (unsigned long)directoryResponse->targetLayer,
                (unsigned long)directoryResponse->queryStatus,
                (unsigned int)directoryResponse->lastStatus);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileIrpIoctlSubmit(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handling IOCTL_KSWORD_ARK_FILE_IRP_SUBMIT. The request is variable-length (fixed header + inline input data), and
    METHOD_BUFFERED causes input and output to share the same system buffer: the response's outputData is written
    starting at offset 1152, which would overwrite the request's trailing inputData. Therefore, this handler must copy
    the entire request (including inline data) into an independent pool buffer before passing it to the IRP engine.

Arguments:

    Device - WDF device object, used for logging and security policies.
    Request - Current IOCTL request.
    InputBufferLength/OutputBufferLength - declared lengths provided by the dispatch layer.
    BytesReturned - Total length of the received response header and output data.

Return Value:

    STATUS_SUCCESS indicates the response packet is constructed; the true semantics of the IRP are in the response fields.

--*/
{
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* submitRequest = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* requestCopy = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE* submitResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    size_t requiredInputLength = 0U;
    size_t copyLength = 0U;
    ULONG inputBytes = 0UL;
    ULONG safetyOperation = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0U;

    status = kswordArkValidateDeviceIoControlWriteAccess(request);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Warn",
            "R0 irp-submit denied: write access required, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE,
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Error",
            "R0 irp-submit ioctl: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    submitRequest = (KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*)inputBuffer;
    inputBytes = submitRequest->inputBytes;
    if (inputBytes > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES) {
        kswordArkFileIrpIoctlLog(
            device,
            "Warn",
            "R0 irp-submit ioctl: inline input too large, bytes=%lu.",
            (unsigned long)inputBytes);
        return STATUS_INVALID_PARAMETER;
    }

    requiredInputLength =
        (size_t)KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE + inputBytes;
    if (actualInputLength < requiredInputLength) {
        kswordArkFileIrpIoctlLog(
            device,
            "Warn",
            "R0 irp-submit ioctl: declared input exceeds buffer, need=%Iu, have=%Iu.",
            requiredInputLength,
            actualInputLength);
        return STATUS_INVALID_PARAMETER;
    }

    copyLength = requiredInputLength;
#pragma warning(push)
#pragma warning(disable:4996)
    requestCopy = (KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        copyLength,
        KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
#pragma warning(pop)
    if (requestCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(requestCopy, inputBuffer, copyLength);

    if (requestCopy->version != KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION ||
        requestCopy->size != KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE ||
        (requestCopy->flags & ~KSWORD_ARK_FILE_IRP_FLAG_ALL) != 0UL ||
        requestCopy->majorFunction >= KSWORD_ARK_FILE_IRP_MAJOR_COUNT ||
        requestCopy->minorFunction > 0xFFUL ||
        requestCopy->targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
        requestCopy->outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES ||
        requestCopy->timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS ||
        requestCopy->reserved0 != 0UL ||
        requestCopy->reserved1 != 0UL ||
        requestCopy->patternLengthChars >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS ||
        !kswordArkFileIrpIoctlPathIsValid(
            requestCopy->path,
            requestCopy->pathLengthChars,
            (USHORT)KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Warn",
            "R0 irp-submit ioctl: request rejected, version=%lu, major=%lu, layer=%lu, flags=0x%08X, chars=%u.",
            (unsigned long)requestCopy->version,
            (unsigned long)requestCopy->majorFunction,
            (unsigned long)requestCopy->targetLayer,
            (unsigned int)requestCopy->flags,
            (unsigned int)requestCopy->pathLengthChars);
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
        return STATUS_INVALID_PARAMETER;
    }
    if (requestCopy->patternLengthChars != 0U &&
        requestCopy->pattern[requestCopy->patternLengthChars] != L'\0') {
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Safety policy: write semantics go through the file write gate; PnP/power and other non-file semantics are handled as kernel modifications.
     * Validate the token again in the IRP engine; neither check may be omitted.
     */
    safetyOperation = KSWORD_ARK_SAFETY_OPERATION_NONE;
    switch (requestCopy->majorFunction) {
    case IRP_MJ_WRITE:
    case IRP_MJ_SET_INFORMATION:
    case IRP_MJ_SET_EA:
    case IRP_MJ_SET_VOLUME_INFORMATION:
    case IRP_MJ_SET_SECURITY:
    case IRP_MJ_SET_QUOTA:
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        safetyOperation = KSWORD_ARK_SAFETY_OPERATION_FILE_DELETE;
        break;
    case IRP_MJ_POWER:
    case IRP_MJ_PNP:
    case IRP_MJ_SYSTEM_CONTROL:
    case IRP_MJ_SHUTDOWN:
    case IRP_MJ_DEVICE_CHANGE:
        safetyOperation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        break;
    default:
        break;
    }

    if (safetyOperation != KSWORD_ARK_SAFETY_OPERATION_NONE) {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = safetyOperation;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags =
            ((requestCopy->flags & KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED) != 0UL)
                ? KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED
                : 0UL;
        safetyContext.targetText = requestCopy->path;
        safetyContext.targetTextChars = requestCopy->pathLengthChars;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkFileIrpIoctlLog(
                device,
                "Warn",
                "R0 irp-submit denied by safety policy: major=%lu, chars=%u, status=0x%08X.",
                (unsigned long)requestCopy->majorFunction,
                (unsigned int)requestCopy->pathLengthChars,
                (unsigned int)status);
            ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
            return status;
        }
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Error",
            "R0 irp-submit ioctl: output invalid, status=0x%08X.",
            (unsigned int)status);
        ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
        return status;
    }

    status = kswordArkDriverSubmitFileIrp(
        outputBuffer,
        actualOutputLength,
        requestCopy,
        (inputBytes != 0UL) ? requestCopy->inputData : NULL,
        inputBytes,
        bytesReturned);

    if (NT_SUCCESS(status) &&
        *bytesReturned >= KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) {
        submitResponse = (KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*)outputBuffer;
        kswordArkFileIrpIoctlLog(
            device,
            (submitResponse->status == KSWORD_ARK_FILE_IRP_STATUS_OK)
                ? "Info"
                : "Warn",
            "R0 irp-submit: major=%lu, minor=%lu, layer=%lu, protocol=%lu, create=0x%08X, op=0x%08X, out=%lu.",
            (unsigned long)submitResponse->majorFunction,
            (unsigned long)submitResponse->minorFunction,
            (unsigned long)submitResponse->targetLayer,
            (unsigned long)submitResponse->status,
            (unsigned int)submitResponse->createStatus,
            (unsigned int)submitResponse->operationStatus,
            (unsigned long)submitResponse->outputBytes);
    }
    else if (!NT_SUCCESS(status)) {
        kswordArkFileIrpIoctlLog(
            device,
            "Error",
            "R0 irp-submit ioctl: engine failed, major=%lu, status=0x%08X.",
            (unsigned long)requestCopy->majorFunction,
            (unsigned int)status);
    }

    ExFreePoolWithTag(requestCopy, KSWORD_ARK_FILE_IRP_IOCTL_POOL_TAG);
    return status;
}

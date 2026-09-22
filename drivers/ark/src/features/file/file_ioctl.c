/*++

Module Name:

    file_ioctl.c

Abstract:

    IOCTL handlers for KswordARK file operations.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

// Recursive deletion requires a temporary buffer for statistics when the caller provides no output buffer; use a dedicated tag to facilitate leak detection.
#define KSWORD_ARK_FILE_IOCTL_POOL_TAG 'iFsK'

static VOID
kswordArkFileIoctlLog(
    _In_ WDFDEVICE device,
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and enqueue one file-handler log message.

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

typedef struct KswordArkFileIntegrityWorkContext
{
    KEVENT completionEvent;
    KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST request;
    NTSTATUS operationStatus;
} KswordArkFileIntegrityWorkContext, *PkswordArkFileIntegrityWorkContext;

static VOID
kswordArkFileIntegritySystemWorker(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_opt_ PVOID context
    )
/*++

Routine Description:

    Run the file mandatory-label update from a system worker thread.
    Note: File objects allow a System Mandatory Label, but Windows checks whether the current security
    subject may raise the object label to the target RID. An IOCTL handler may run in the initiating
    process's High/Medium token context, where setting System directly with ZwSetSecurityObject
    returns STATUS_INVALID_LABEL. A system thread executes this worker, allowing the backend to keep
    using the kernel API while meeting the subject requirements for a System label.

Arguments:

    DeviceObject - WDM device object passed by IoQueueWorkItem; currently used
        only to satisfy the callback signature.
    Context - Points to KswordArkFileIntegrityWorkContext containing an
        owned request snapshot and a completion event.

Return Value:

    None. The NTSTATUS is written to Context->OperationStatus and the waiting
    IOCTL thread is released via CompletionEvent.

--*/
{
    PkswordArkFileIntegrityWorkContext workContext =
        (PkswordArkFileIntegrityWorkContext)context;

    UNREFERENCED_PARAMETER(deviceObject);

    if (workContext == NULL) {
        return;
    }

    workContext->operationStatus =
        kswordArkDriverSetFileIntegrity(&workContext->request);
    KeSetEvent(&workContext->completionEvent, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS
kswordArkFileIoctlSetIntegrityViaSystemWorker(
    _In_ WDFDEVICE device,
    _In_ const KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST* request
    )
/*++

Routine Description:

    Queue and wait for the file-integrity operation on a system worker thread.
    Note: This helper only changes the execution context, not the file backend
    logic. Actual file opening, Mandatory Label SID/ACL/SD construction, and
    ZwSetSecurityObject remain centralized in kswordArkDriverSetFileIntegrity.

Arguments:

    Device - KMDF device used to allocate an IO_WORKITEM bound to the WDM
        device object.
    Request - Validated IOCTL request snapshot. The helper copies it into the
        stack work context before queueing, so callback does not reference the
        METHOD_BUFFERED system buffer or caller stack.

Return Value:

    STATUS_SUCCESS or a backend NTSTATUS when the worker ran; allocation,
    IRQL, or device-state errors are returned before queueing.

--*/
{
    PDEVICE_OBJECT deviceObject = NULL;
    PIO_WORKITEM workItem = NULL;
    KswordArkFileIntegrityWorkContext workContext;
    NTSTATUS waitStatus = STATUS_SUCCESS;

    if (device == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    deviceObject = WdfDeviceWdmGetDeviceObject(device);
    if (deviceObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    workItem = IoAllocateWorkItem(deviceObject);
    if (workItem == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&workContext, sizeof(workContext));
    KeInitializeEvent(&workContext.completionEvent, NotificationEvent, FALSE);
    RtlCopyMemory(&workContext.request, request, sizeof(workContext.request));
    workContext.operationStatus = STATUS_UNSUCCESSFUL;

    IoQueueWorkItem(
        workItem,
        kswordArkFileIntegritySystemWorker,
        DelayedWorkQueue,
        &workContext);

    waitStatus = KeWaitForSingleObject(
        &workContext.completionEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL);

    IoFreeWorkItem(workItem);
    if (!NT_SUCCESS(waitStatus)) {
        return waitStatus;
    }
    return workContext.operationStatus;
}

NTSTATUS
kswordArkFileIoctlDeletePath(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_DELETE_PATH. The handler validates flags, path
    length, and null termination before invoking the file delete feature.
    Note: When the RECURSIVE flag is set, the directory tree is deleted in post-order within R0. If
    the caller provides an output buffer, statistics are written to KSWORD_ARK_DELETE_PATH_RESPONSE;
    legacy callers without an output buffer only receive the aggregated NTSTATUS.

Arguments:

    Device - WDF device used for logging.
    Request - Current IOCTL request.
    InputBufferLength - Caller input length; consumed by WDF retrieval.
    OutputBufferLength - Caller output length; response packet is optional.
    BytesReturned - Receives sizeof(response) when a response was written.

Return Value:

    NTSTATUS from validation, kswordArkDriverDeletePath or the recursive
    delete feature. Return STATUS_SUCCESS in the response packet; the semantic result is in deleteStatus.

--*/
{
    KSWORD_ARK_DELETE_PATH_REQUEST requestSnapshot;
    KSWORD_ARK_DELETE_PATH_RESPONSE* deleteResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    BOOLEAN responsePresent = FALSE;
    BOOLEAN responseAllocated = FALSE;
    BOOLEAN isDirectory = FALSE;
    BOOLEAN isRecursive = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS operationStatus = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(request, sizeof(KSWORD_ARK_DELETE_PATH_REQUEST), &inputBuffer, &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(device, "Error", "R0 delete ioctl: input buffer invalid, status=0x%08X", (unsigned int)status);
        return status;
    }

    /*
     * The input and output views for METHOD_BUFFERED share the same system buffer.
     * Must perform a full snapshot request first; otherwise, writing the response packet will overwrite the flags/path.
     */
    RtlCopyMemory(&requestSnapshot, inputBuffer, sizeof(requestSnapshot));

    isDirectory = ((requestSnapshot.flags & KSWORD_ARK_DELETE_PATH_FLAG_DIRECTORY) != 0UL) ? TRUE : FALSE;
    isRecursive = ((requestSnapshot.flags & KSWORD_ARK_DELETE_PATH_FLAG_RECURSIVE) != 0UL) ? TRUE : FALSE;

    if ((requestSnapshot.flags & (~KSWORD_ARK_DELETE_PATH_FLAG_ALL)) != 0UL) {
        kswordArkFileIoctlLog(device, "Warn", "R0 delete ioctl: flags rejected, flags=0x%08X.", (unsigned int)requestSnapshot.flags);
        return STATUS_INVALID_PARAMETER;
    }

    if ((requestSnapshot.flags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK) ==
        KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK) {
        kswordArkFileIoctlLog(device, "Warn", "R0 delete ioctl: backend flags are mutually exclusive, flags=0x%08X.", (unsigned int)requestSnapshot.flags);
        return STATUS_INVALID_PARAMETER;
    }

    if (isRecursive && !isDirectory) {
        kswordArkFileIoctlLog(device, "Warn", "R0 delete ioctl: recursive flag requires directory flag, flags=0x%08X.", (unsigned int)requestSnapshot.flags);
        return STATUS_INVALID_PARAMETER;
    }

    if (requestSnapshot.pathLengthChars == 0U || requestSnapshot.pathLengthChars >= KSWORD_ARK_DELETE_PATH_MAX_CHARS) {
        kswordArkFileIoctlLog(device, "Warn", "R0 delete ioctl: path length rejected, chars=%u.", (unsigned int)requestSnapshot.pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    if (requestSnapshot.path[requestSnapshot.pathLengthChars] != L'\0') {
        kswordArkFileIoctlLog(device, "Warn", "R0 delete ioctl: path not null-terminated, chars=%u.", (unsigned int)requestSnapshot.pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }
    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_FILE_DELETE;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.targetText = requestSnapshot.path;
        safetyContext.targetTextChars = requestSnapshot.pathLengthChars;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            kswordArkFileIoctlLog(device, "Warn", "R0 delete denied by safety policy: chars=%u, status=0x%08X.", (unsigned int)requestSnapshot.pathLengthChars, (unsigned int)status);
            return status;
        }
    }

    // Response is optional: Legacy R3 only sends requests without receiving responses; maintain the legacy contract of returning NTSTATUS.
    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_DELETE_PATH_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    responsePresent = NT_SUCCESS(status) ? TRUE : FALSE;
    status = STATUS_SUCCESS;

    if (responsePresent) {
        deleteResponse = (KSWORD_ARK_DELETE_PATH_RESPONSE*)outputBuffer;
    }
    else if (isRecursive) {
        // Recursive statistics are a required state for the traversal process; when no output buffer is available, temporary pool memory is used to hold the data.
#pragma warning(push)
#pragma warning(disable:4996)
        deleteResponse = (KSWORD_ARK_DELETE_PATH_RESPONSE*)ExAllocatePoolWithTag(
            NonPagedPoolNx,
            sizeof(KSWORD_ARK_DELETE_PATH_RESPONSE),
            KSWORD_ARK_FILE_IOCTL_POOL_TAG);
#pragma warning(pop)
        if (deleteResponse == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        responseAllocated = TRUE;
    }

    if (deleteResponse != NULL) {
        RtlZeroMemory(deleteResponse, sizeof(*deleteResponse));
        deleteResponse->size = sizeof(*deleteResponse);
        deleteResponse->version = KSWORD_ARK_DELETE_PATH_RESPONSE_VERSION;
        deleteResponse->requestFlags = requestSnapshot.flags;
        deleteResponse->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_UNKNOWN;
    }

    kswordArkFileIoctlLog(
        device,
        "Info",
        "R0 delete ioctl: chars=%u, directory=%u, recursive=%u, response=%u.",
        (unsigned int)requestSnapshot.pathLengthChars,
        (unsigned int)isDirectory,
        (unsigned int)isRecursive,
        (unsigned int)responsePresent);

    if (!isRecursive) {
        operationStatus = kswordArkDriverDeletePathWithFlags(
            requestSnapshot.path,
            requestSnapshot.pathLengthChars,
            isDirectory,
            requestSnapshot.flags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK);
        if (NT_SUCCESS(operationStatus)) {
            kswordArkFileIoctlLog(device, "Info", "R0 delete success: chars=%u, directory=%u.", (unsigned int)requestSnapshot.pathLengthChars, (unsigned int)isDirectory);
        }
        else {
            kswordArkFileIoctlLog(device, "Error", "R0 delete failed: chars=%u, directory=%u, status=0x%08X.", (unsigned int)requestSnapshot.pathLengthChars, (unsigned int)isDirectory, (unsigned int)operationStatus);
        }

        if (!responsePresent) {
            return operationStatus;
        }

        deleteResponse->visitedCount = 1U;
        deleteResponse->lastStatus = operationStatus;
        if (NT_SUCCESS(operationStatus)) {
            if (isDirectory) {
                deleteResponse->deletedDirectoryCount = 1U;
            }
            else {
                deleteResponse->deletedFileCount = 1U;
            }
            deleteResponse->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED;
            deleteResponse->lastStatus = STATUS_SUCCESS;
        }
        else {
            deleteResponse->failedCount = 1U;
            deleteResponse->deleteStatus = KSWORD_ARK_DELETE_PATH_STATUS_FAILED;
            deleteResponse->failedPathLengthChars = requestSnapshot.pathLengthChars;
            RtlCopyMemory(
                deleteResponse->failedPath,
                requestSnapshot.path,
                (SIZE_T)requestSnapshot.pathLengthChars * sizeof(WCHAR));
            deleteResponse->failedPath[requestSnapshot.pathLengthChars] = L'\0';
        }
        *bytesReturned = sizeof(*deleteResponse);
        return STATUS_SUCCESS;
    }

    operationStatus = kswordArkDriverDeletePathTree(&requestSnapshot, deleteResponse);
    if (!NT_SUCCESS(operationStatus)) {
        kswordArkFileIoctlLog(
            device,
            "Error",
            "R0 recursive delete aborted: chars=%u, status=0x%08X.",
            (unsigned int)requestSnapshot.pathLengthChars,
            (unsigned int)operationStatus);
        if (responseAllocated) {
            ExFreePoolWithTag(deleteResponse, KSWORD_ARK_FILE_IOCTL_POOL_TAG);
        }
        return operationStatus;
    }

    kswordArkFileIoctlLog(
        device,
        deleteResponse->deleteStatus == KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED ? "Info" : "Warn",
        "R0 recursive delete done: chars=%u, state=%lu, files=%lu, dirs=%lu, failed=%lu, visited=%lu, depth=%lu, flags=0x%08X, last=0x%08X.",
        (unsigned int)requestSnapshot.pathLengthChars,
        (unsigned long)deleteResponse->deleteStatus,
        (unsigned long)deleteResponse->deletedFileCount,
        (unsigned long)deleteResponse->deletedDirectoryCount,
        (unsigned long)deleteResponse->failedCount,
        (unsigned long)deleteResponse->visitedCount,
        (unsigned long)deleteResponse->maxDepthReached,
        (unsigned int)deleteResponse->responseFlags,
        (unsigned int)deleteResponse->lastStatus);

    if (responsePresent) {
        *bytesReturned = sizeof(*deleteResponse);
        return STATUS_SUCCESS;
    }

    // Callers of non-responsive packets can only rely on NTSTATUS for judgment, so partial failures are folded into a failure status.
    if (deleteResponse->deleteStatus != KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED) {
        operationStatus = deleteResponse->lastStatus != STATUS_SUCCESS
            ? deleteResponse->lastStatus
            : STATUS_UNSUCCESSFUL;
    }
    if (responseAllocated) {
        ExFreePoolWithTag(deleteResponse, KSWORD_ARK_FILE_IOCTL_POOL_TAG);
    }
    return operationStatus;
}

NTSTATUS
kswordArkFileIoctlQueryFileInfo(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handles IOCTL_KSWORD_ARK_QUERY_FILE_INFO. Note: The handler is responsible only for WDF
    buffer retrieval and basic path/flags validation; the actual read-only file attribute
    query is performed by file_actions.c to keep the IOCTL layer thin and auditable.

Arguments:

    Device - WDF device object used for recording logs.
    Request - Current IOCTL request.
    InputBufferLength - input length, actually validated by WDF.
    OutputBufferLength - Output length, actually validated by WDF.
    BytesReturned - Bytes written by the driver.

Return Value:

    NTSTATUS indicates buffer validation or feature query results.

--*/
{
    KSWORD_ARK_QUERY_FILE_INFO_REQUEST* queryRequest = NULL;
    KSWORD_ARK_QUERY_FILE_INFO_REQUEST requestSnapshot;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0;
    size_t actualOutputLength = 0;
    const ULONG kAllowedFlags =
        KSWORD_ARK_QUERY_FILE_INFO_FLAG_DIRECTORY |
        KSWORD_ARK_QUERY_FILE_INFO_FLAG_OPEN_REPARSE_POINT |
        KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_OBJECT_NAME |
        KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_SECTION_POINTERS;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(inputBufferLength);
    UNREFERENCED_PARAMETER(outputBufferLength);

    if (bytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesReturned = 0;

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_FILE_INFO_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(device, "Error", "R0 query-file-info ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input and output share the same SystemBuffer; copying the full request first ensures that clearing
     * and writing the response in the backend does not overwrite flags/pathLengthChars/path. The response size field and
     * the request's pathLengthChars both reside at offset +4; without taking a snapshot, subsequent ZwCreateFile calls
     * would interpret sizeof(RESPONSE) as the path character count, causing a kernel out-of-bounds read.
     */
    queryRequest = (KSWORD_ARK_QUERY_FILE_INFO_REQUEST*)inputBuffer;
    RtlCopyMemory(&requestSnapshot, queryRequest, sizeof(requestSnapshot));

    if ((requestSnapshot.flags & ~kAllowedFlags) != 0UL) {
        kswordArkFileIoctlLog(device, "Warn", "R0 query-file-info ioctl: flags rejected, flags=0x%08X.", (unsigned int)requestSnapshot.flags);
        return STATUS_INVALID_PARAMETER;
    }
    if (requestSnapshot.pathLengthChars == 0U ||
        requestSnapshot.pathLengthChars >= KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS ||
        requestSnapshot.path[requestSnapshot.pathLengthChars] != L'\0') {
        kswordArkFileIoctlLog(device, "Warn", "R0 query-file-info ioctl: path rejected, chars=%u.", (unsigned int)requestSnapshot.pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_QUERY_FILE_INFO_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(device, "Error", "R0 query-file-info ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkDriverQueryFileInfo(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(device, "Error", "R0 query-file-info failed: chars=%u, status=0x%08X.", (unsigned int)requestSnapshot.pathLengthChars, (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= sizeof(KSWORD_ARK_QUERY_FILE_INFO_RESPONSE)) {
        KSWORD_ARK_QUERY_FILE_INFO_RESPONSE* response = (KSWORD_ARK_QUERY_FILE_INFO_RESPONSE*)outputBuffer;
        kswordArkFileIoctlLog(
            device,
            "Info",
            "R0 query-file-info success: chars=%u, status=%lu, fields=0x%08X.",
            (unsigned int)requestSnapshot.pathLengthChars,
            (unsigned long)response->queryStatus,
            (unsigned int)response->fieldFlags);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileIoctlEnumDirectory(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_ENUM_DIRECTORY. The handler copies only METHOD_BUFFERED requests, validates paged
    memory and path boundaries, then calls file_directory_query.c to perform a read-only directory query.

Arguments:

    Device - WDF device object, used for error logging only.
    Request - Current directory enumeration request.
    InputBufferLength/OutputBufferLength - declared lengths provided by the dispatch layer.
    BytesReturned: Total length of the protocol header and valid directory lines received.

Return Value:

    NTSTATUS indicates the result of WDF buffering or protocol handling; directory open errors are stored in the response semantic field.

--*/
{
    KSWORD_ARK_ENUM_DIRECTORY_REQUEST* directoryRequest = NULL;
    KSWORD_ARK_ENUM_DIRECTORY_REQUEST requestSnapshot;
    KSWORD_ARK_ENUM_DIRECTORY_RESPONSE* directoryResponse = NULL;
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
        sizeof(KSWORD_ARK_ENUM_DIRECTORY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(
            device,
            "Error",
            "R0 directory-enum ioctl: input invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED input and output may share the same system buffer; copy the complete
     * request first. Subsequent response zeroing will not overwrite path/startIndex/maxEntries.
     */
    directoryRequest = (KSWORD_ARK_ENUM_DIRECTORY_REQUEST*)inputBuffer;
    RtlCopyMemory(
        &requestSnapshot,
        directoryRequest,
        sizeof(requestSnapshot));

    if (requestSnapshot.version != KSWORD_ARK_DIRECTORY_ENUM_PROTOCOL_VERSION ||
        requestSnapshot.size != (ULONG)sizeof(requestSnapshot) ||
        requestSnapshot.flags != 0UL ||
        requestSnapshot.maxEntries == 0UL ||
        requestSnapshot.maxEntries > KSWORD_ARK_DIRECTORY_ENUM_MAX_PAGE_ENTRIES ||
        requestSnapshot.startIndex >= KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES ||
        requestSnapshot.maxEntries >
            KSWORD_ARK_DIRECTORY_ENUM_MAX_TOTAL_ENTRIES - requestSnapshot.startIndex ||
        requestSnapshot.pathLengthChars == 0U ||
        requestSnapshot.pathLengthChars >= KSWORD_ARK_DIRECTORY_ENUM_PATH_MAX_CHARS ||
        requestSnapshot.path[requestSnapshot.pathLengthChars] != L'\0' ||
        requestSnapshot.reserved != 0U) {
        kswordArkFileIoctlLog(
            device,
            "Warn",
            "R0 directory-enum ioctl: request rejected, version=%lu, size=%lu, flags=0x%08X, start=%lu, max=%lu, chars=%u.",
            (unsigned long)requestSnapshot.version,
            (unsigned long)requestSnapshot.size,
            (unsigned int)requestSnapshot.flags,
            (unsigned long)requestSnapshot.startIndex,
            (unsigned long)requestSnapshot.maxEntries,
            (unsigned int)requestSnapshot.pathLengthChars);
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE +
            sizeof(KSWORD_ARK_DIRECTORY_ENTRY),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(
            device,
            "Error",
            "R0 directory-enum ioctl: output invalid, status=0x%08X.",
            (unsigned int)status);
        return status;
    }

    status = kswordArkDriverEnumerateDirectory(
        outputBuffer,
        actualOutputLength,
        &requestSnapshot,
        bytesReturned);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(
            device,
            "Error",
            "R0 directory-enum ioctl: feature failed, chars=%u, status=0x%08X.",
            (unsigned int)requestSnapshot.pathLengthChars,
            (unsigned int)status);
        return status;
    }

    if (*bytesReturned >= KSWORD_ARK_ENUM_DIRECTORY_RESPONSE_HEADER_SIZE) {
        directoryResponse =
            (KSWORD_ARK_ENUM_DIRECTORY_RESPONSE*)outputBuffer;
        if (directoryResponse->queryStatus !=
                KSWORD_ARK_DIRECTORY_ENUM_STATUS_OK &&
            directoryResponse->queryStatus !=
                KSWORD_ARK_DIRECTORY_ENUM_STATUS_PARTIAL) {
            kswordArkFileIoctlLog(
                device,
                "Warn",
                "R0 directory-enum semantic failure: chars=%u, query=%lu, status=0x%08X.",
                (unsigned int)requestSnapshot.pathLengthChars,
                (unsigned long)directoryResponse->queryStatus,
                (unsigned int)directoryResponse->lastStatus);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileIoctlSetIntegrity(
    _In_ WDFDEVICE device,
    _In_ WDFREQUEST request,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesReturned
    )
/*++

Routine Description:

    Handle IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY. Note: The handler validates the path, flags,
    and fixed response buffer; the backend only calls ZwCreateFile/ZwSetSecurityObject to
    write LABEL_SECURITY_INFORMATION, without patching filesystem private objects.

Arguments:

    Device - WDF device used for logging and safety policy.
    Request - Current IOCTL request.
    InputBufferLength - Input length; validated by WDF helper.
    OutputBufferLength - Output length; validated by WDF helper.
    BytesReturned - Receives sizeof(response) when output is valid.

Return Value:

    STATUS_SUCCESS once the response packet is valid. The actual file operation
    status is stored in response->status/lastStatus.

--*/
{
    KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST* integrityRequest = NULL;
    KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST integrityRequestSnapshot;
    KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE* integrityResponse = NULL;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t actualInputLength = 0U;
    size_t actualOutputLength = 0U;
    const ULONG kAllowedFlags =
        KSWORD_ARK_FILE_INTEGRITY_FLAG_DIRECTORY |
        KSWORD_ARK_FILE_INTEGRITY_FLAG_UI_CONFIRMED;
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
        kswordArkFileIoctlLog(device, "Warn", "R0 file-integrity denied: write access required, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = kswordArkRetrieveRequiredInputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST),
        &inputBuffer,
        &actualInputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(device, "Error", "R0 file-integrity ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    /*
     * METHOD_BUFFERED can map the input and output views to the same system
     * buffer.  Copy the whole fixed request first so response initialization
     * cannot erase flags/integrityRid/pathLengthChars/path before validation.
     */
    integrityRequest = (KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST*)inputBuffer;
    RtlCopyMemory(&integrityRequestSnapshot, integrityRequest, sizeof(integrityRequestSnapshot));

    status = kswordArkRetrieveRequiredOutputBuffer(
        request,
        sizeof(KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE),
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        kswordArkFileIoctlLog(device, "Error", "R0 file-integrity ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    integrityResponse = (KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE*)outputBuffer;
    RtlZeroMemory(integrityResponse, sizeof(*integrityResponse));
    integrityResponse->size = sizeof(*integrityResponse);
    integrityResponse->version = KSWORD_ARK_FILE_INTEGRITY_PROTOCOL_VERSION;
    integrityResponse->flags = integrityRequestSnapshot.flags;
    integrityResponse->integrityRid = integrityRequestSnapshot.integrityRid;
    integrityResponse->status = KSWORD_ARK_FILE_INTEGRITY_STATUS_FAILED;
    integrityResponse->lastStatus = STATUS_INVALID_PARAMETER;
    integrityResponse->pathLengthChars = integrityRequestSnapshot.pathLengthChars;
    *bytesReturned = sizeof(*integrityResponse);

    if (integrityRequestSnapshot.size != sizeof(integrityRequestSnapshot) ||
        integrityRequestSnapshot.version != KSWORD_ARK_FILE_INTEGRITY_PROTOCOL_VERSION ||
        (integrityRequestSnapshot.flags & ~kAllowedFlags) != 0UL ||
        integrityRequestSnapshot.pathLengthChars == 0U ||
        integrityRequestSnapshot.pathLengthChars >= KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS ||
        integrityRequestSnapshot.path[integrityRequestSnapshot.pathLengthChars] != L'\0') {
        kswordArkFileIoctlLog(
            device,
            "Warn",
            "R0 file-integrity ioctl: request rejected, size=%lu, version=%lu, flags=0x%08X, chars=%u.",
            (unsigned long)integrityRequestSnapshot.size,
            (unsigned long)integrityRequestSnapshot.version,
            (unsigned int)integrityRequestSnapshot.flags,
            (unsigned int)integrityRequestSnapshot.pathLengthChars);
        return STATUS_SUCCESS;
    }

    {
        KswordArkSafetyContext safetyContext;
        RtlZeroMemory(&safetyContext, sizeof(safetyContext));
        safetyContext.operation = KSWORD_ARK_SAFETY_OPERATION_KERNEL_PATCH;
        safetyContext.targetProcessId = 0UL;
        safetyContext.contextFlags = KSWORD_ARK_SAFETY_CONTEXT_FLAG_UI_CONFIRMED;
        safetyContext.targetText = integrityRequestSnapshot.path;
        safetyContext.targetTextChars = integrityRequestSnapshot.pathLengthChars;
        status = kswordArkSafetyEvaluate(device, &safetyContext);
        if (!NT_SUCCESS(status)) {
            integrityResponse->lastStatus = status;
            kswordArkFileIoctlLog(device, "Warn", "R0 file-integrity denied by safety policy: chars=%u, status=0x%08X.", (unsigned int)integrityRequestSnapshot.pathLengthChars, (unsigned int)status);
            return STATUS_SUCCESS;
        }
    }

    operationStatus = kswordArkFileIoctlSetIntegrityViaSystemWorker(
        device,
        &integrityRequestSnapshot);
    integrityResponse->lastStatus = operationStatus;
    integrityResponse->status = NT_SUCCESS(operationStatus)
        ? KSWORD_ARK_FILE_INTEGRITY_STATUS_APPLIED
        : KSWORD_ARK_FILE_INTEGRITY_STATUS_FAILED;

    if (NT_SUCCESS(operationStatus)) {
        kswordArkFileIoctlLog(
            device,
            "Info",
            "R0 file-integrity success: chars=%u, rid=0x%08lX, flags=0x%08lX.",
            (unsigned int)integrityRequestSnapshot.pathLengthChars,
            (unsigned long)integrityRequestSnapshot.integrityRid,
            (unsigned long)integrityRequestSnapshot.flags);
    }
    else {
        kswordArkFileIoctlLog(
            device,
            "Error",
            "R0 file-integrity failed: chars=%u, rid=0x%08lX, flags=0x%08lX, status=0x%08X.",
            (unsigned int)integrityRequestSnapshot.pathLengthChars,
            (unsigned long)integrityRequestSnapshot.integrityRid,
            (unsigned long)integrityRequestSnapshot.flags,
            (unsigned int)operationStatus);
    }

    return STATUS_SUCCESS;
}

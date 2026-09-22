/*++

Module Name:

    file_monitor_runtime.c

Abstract:

    Phase-12 file-system minifilter runtime and event ring buffer.

Environment:

    Kernel-mode minifilter + KMDF control device

--*/

#include <fltKernel.h>
#include "file_monitor_internal.h"
#include "ark/ark_driver.h"

#include <stdarg.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_FILE_MONITOR_TAG 'mFsK'
#define KSWORD_ARK_FILE_MONITOR_INSTANCE_KEY_NAME L"Instances"
#define KSWORD_ARK_FILE_MONITOR_DEFAULT_INSTANCE_NAME L"KswordARK Instance"
#define KSWORD_ARK_FILE_MONITOR_ALTITUDE_TEXT L"385210"

typedef struct KswordArkFileMonitorRuntime
{
    PFLT_FILTER filter;
    WDFDEVICE device;
    EX_PUSH_LOCK controlLock;
    KSPIN_LOCK ringLock;
    ULONG headIndex;
    ULONG tailIndex;
    ULONG queuedCount;
    ULONG droppedCount;
    ULONG operationMask;
    ULONG processIdFilter;
    ULONG runtimeFlags;
    LONG64 sequence;
    NTSTATUS registerStatus;
    NTSTATUS startStatus;
    NTSTATUS lastErrorStatus;
    KSWORD_ARK_FILE_MONITOR_EVENT ring[KSWORD_ARK_FILE_MONITOR_RING_CAPACITY];
} KswordArkFileMonitorRuntime;

static KswordArkFileMonitorRuntime gKswordArkFileMonitorRuntime;

static NTSTATUS FLTAPI
kswordArkFileMonitorUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags
    );

FLT_PREOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Outptr_result_maybenull_ PVOID* completionContext
    );

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_opt_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags
    );

static const FLT_OPERATION_REGISTRATION kGKswordArkFileMonitorOperations[] =
{
    { IRP_MJ_CREATE, 0, kswordArkMinifilterPreOperation, kswordArkMinifilterPostOperation },
    { IRP_MJ_READ, 0, kswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_WRITE, 0, kswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_SET_INFORMATION, 0, kswordArkMinifilterPreOperation, kswordArkMinifilterPostOperation },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, kswordArkMinifilterPreOperation, kswordArkMinifilterPostOperation },
    { IRP_MJ_CLEANUP, 0, kswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_CLOSE, 0, kswordArkMinifilterPreOperation, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION kGKswordArkFileMonitorRegistration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    kGKswordArkFileMonitorOperations,
    kswordArkFileMonitorUnloadCallback,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static ULONG
kswordArkFileMonitorAdvanceIndex(
    _In_ ULONG currentIndex
    )
/*++

Routine Description:

    Advance the ring buffer index. Note: Capacity is fixed at 2^n; do not assume
    otherwise. Use modulo for readability and safe capacity adjustments later.

Arguments:

    CurrentIndex - current index.

Return Value:

    Next index.

--*/
{
    return (currentIndex + 1UL) % KSWORD_ARK_FILE_MONITOR_RING_CAPACITY;
}

static VOID
kswordArkFileMonitorLog(
    _In_z_ PCSTR levelText,
    _In_z_ PCSTR messageText
    )
/*++

Routine Description:

    Write to file monitor runtime logs. Note: During early minifilter initialization, the Device may
    be null; in this case, only WDF logging is skipped, which does not affect FltMgr registration.

Arguments:

    levelText - Log level.
    MessageText - Log body.

Return Value:

    None.

--*/
{
    WDFDEVICE device = gKswordArkFileMonitorRuntime.device;

    if (device == WDF_NO_HANDLE || device == NULL) {
        return;
    }

    (VOID)kswordArkDriverEnqueueLogFrame(
        device,
        levelText != NULL ? levelText : "Info",
        messageText != NULL ? messageText : "");
}

static VOID
kswordArkFileMonitorLogFormat(
    _In_z_ PCSTR levelText,
    _In_z_ _Printf_format_string_ PCSTR formatText,
    ...
    )
/*++

Routine Description:

    Format and write to file monitor runtime logs. Note: The initialization/startup path is not a hot path;
    using a small stack buffer to supplement NTSTATUS is allowed to avoid R3 seeing only Win32 error=22.

Arguments:

    levelText - Log level.
    FormatText - printf-style format string.
    ... - Format arguments.

Return Value:

    None. This function has no return value.

--*/
{
    CHAR logBuffer[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    if (formatText == NULL) {
        return;
    }

    va_start(arguments, formatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logBuffer, sizeof(logBuffer), formatText, arguments))) {
        kswordArkFileMonitorLog(levelText, logBuffer);
    }
    va_end(arguments);
}

static NTSTATUS
kswordArkFileMonitorWriteRegistryStringValue(
    _In_ HANDLE keyHandle,
    _In_z_ PCWSTR valueNameText,
    _In_z_ PCWSTR valueDataText
    )
/*++

Routine Description:

    Write the minifilter instance registry string value. Note: FltRegisterFilter depends on Instances\DefaultInstance
    and the instance Altitude; SCM CreateService does not automatically generate these values.

Arguments:

    KeyHandle - The handle to the opened target key.
    ValueNameText - REG_SZ value name.
    ValueDataText: REG_SZ string data.

Return Value:

    Return status of ZwSetValueKey.

--*/
{
    UNICODE_STRING valueName;
    UNICODE_STRING valueData;

    if (keyHandle == NULL || valueNameText == NULL || valueDataText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&valueName, valueNameText);
    RtlInitUnicodeString(&valueData, valueDataText);
    return ZwSetValueKey(
        keyHandle,
        &valueName,
        0UL,
        REG_SZ,
        valueData.Buffer,
        (ULONG)valueData.Length + sizeof(WCHAR));
}

static NTSTATUS
kswordArkFileMonitorWriteRegistryDwordValue(
    _In_ HANDLE keyHandle,
    _In_z_ PCWSTR valueNameText,
    _In_ ULONG valueData
    )
/*++

Routine Description:

    Write a DWORD value to the minifilter instance registry. Note: Flags=0 indicates
    the default instance can auto-attach, consistent with the INF configuration.

Arguments:

    KeyHandle - The handle to the opened target key.
    ValueNameText: REG_DWORD value name.
    ValueData - DWORD data.

Return Value:

    Return status of ZwSetValueKey.

--*/
{
    UNICODE_STRING valueName;

    if (keyHandle == NULL || valueNameText == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlInitUnicodeString(&valueName, valueNameText);
    return ZwSetValueKey(
        keyHandle,
        &valueName,
        0UL,
        REG_DWORD,
        &valueData,
        sizeof(valueData));
}

static NTSTATUS
kswordArkFileMonitorCreateSubKey(
    _In_opt_ HANDLE rootHandle,
    _In_ PUNICODE_STRING keyName,
    _Out_ HANDLE* keyHandleOut
    )
/*++

Routine Description:

    Create or open a relative registry key. Note: Use RootHandle to create levels sequentially
    to avoid length truncation or escape errors when concatenating the RegistryPath string.

Arguments:

    RootHandle - Parent key handle, which may be null; if null, KeyName must be an absolute path.
    KeyName - Subkey name or absolute key path.
    KeyHandleOut - Returns the newly opened key handle.

Return Value:

    Return status of ZwCreateKey.

--*/
{
    OBJECT_ATTRIBUTES objectAttributes;
    ULONG disposition = 0UL;

    if (keyName == NULL || keyName->Buffer == NULL || keyHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *keyHandleOut = NULL;
    InitializeObjectAttributes(
        &objectAttributes,
        keyName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        rootHandle,
        NULL);
    return ZwCreateKey(
        keyHandleOut,
        KEY_READ | KEY_WRITE,
        &objectAttributes,
        0UL,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition);
}

static NTSTATUS
kswordArkFileMonitorEnsureRegistryInstances(
    _In_ PUNICODE_STRING registryPath
    )
/*++

Routine Description:

    Ensure the Instances configuration required by FltMgr exists under the service key. Note: The official INF
    installation writes these values, but the current R3 quick-start path registers the .sys file directly via
    CreateServiceW. Therefore, the driver must self-heal within DriverEntry to ensure FltRegisterFilter is usable.

Arguments:

    RegistryPath: Absolute service registry path passed to DriverEntry.

Return Value:

    STATUS_SUCCESS or a failure status from the underlying registry write operation.

--*/
{
    UNICODE_STRING instancesKeyName;
    UNICODE_STRING instanceKeyName;
    HANDLE serviceKeyHandle = NULL;
    HANDLE instancesKeyHandle = NULL;
    HANDLE instanceKeyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS closeStatus = STATUS_SUCCESS;

    if (registryPath == NULL || registryPath->Buffer == NULL || registryPath->Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkFileMonitorCreateSubKey(NULL, registryPath, &serviceKeyHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&instancesKeyName, KSWORD_ARK_FILE_MONITOR_INSTANCE_KEY_NAME);
    status = kswordArkFileMonitorCreateSubKey(serviceKeyHandle, &instancesKeyName, &instancesKeyHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(serviceKeyHandle);
        return status;
    }

    status = kswordArkFileMonitorWriteRegistryStringValue(
        instancesKeyHandle,
        L"DefaultInstance",
        KSWORD_ARK_FILE_MONITOR_DEFAULT_INSTANCE_NAME);
    if (!NT_SUCCESS(status)) {
        ZwClose(instancesKeyHandle);
        ZwClose(serviceKeyHandle);
        return status;
    }

    RtlInitUnicodeString(&instanceKeyName, KSWORD_ARK_FILE_MONITOR_DEFAULT_INSTANCE_NAME);
    status = kswordArkFileMonitorCreateSubKey(instancesKeyHandle, &instanceKeyName, &instanceKeyHandle);
    if (!NT_SUCCESS(status)) {
        ZwClose(instancesKeyHandle);
        ZwClose(serviceKeyHandle);
        return status;
    }

    status = kswordArkFileMonitorWriteRegistryStringValue(
        instanceKeyHandle,
        L"Altitude",
        KSWORD_ARK_FILE_MONITOR_ALTITUDE_TEXT);
    if (NT_SUCCESS(status)) {
        status = kswordArkFileMonitorWriteRegistryDwordValue(
            instanceKeyHandle,
            L"Flags",
            0UL);
    }

    closeStatus = ZwClose(instanceKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }
    closeStatus = ZwClose(instancesKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }
    closeStatus = ZwClose(serviceKeyHandle);
    if (NT_SUCCESS(status) && !NT_SUCCESS(closeStatus)) {
        status = closeStatus;
    }

    return status;
}

static VOID
kswordArkFileMonitorCopyNameToEvent(
    _Inout_ KSWORD_ARK_FILE_MONITOR_EVENT* event,
    _In_opt_ PCUNICODE_STRING fileName
    )
/*++

Routine Description:

    Copy the normalized/opened name returned by FltMgr to the event. Note: Fixed arrays are always null-terminated.
    Explicitly mark truncated paths as TRUNCATED to prevent R3 from mistaking them for complete paths.

Arguments:

    Event - Event to be filled.
    FileName: File name as UNICODE_STRING; may be null.

Return Value:

    None.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG charsToCopy = 0UL;

    if (event == NULL || fileName == NULL || fileName->Buffer == NULL || fileName->Length == 0U) {
        return;
    }

    sourceChars = (ULONG)(fileName->Length / sizeof(WCHAR));
    charsToCopy = sourceChars;
    if (charsToCopy >= KSWORD_ARK_FILE_MONITOR_PATH_CHARS) {
        charsToCopy = KSWORD_ARK_FILE_MONITOR_PATH_CHARS - 1UL;
        event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_PATH_TRUNCATED;
    }

    if (charsToCopy > 0UL) {
        RtlCopyMemory(
            event->path,
            fileName->Buffer,
            (SIZE_T)charsToCopy * sizeof(WCHAR));
        event->path[charsToCopy] = L'\0';
        event->pathLengthChars = charsToCopy;
        event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_PATH_PRESENT;
    }
}

static VOID
kswordArkFileMonitorFillCommonEvent(
    _Out_ KSWORD_ARK_FILE_MONITOR_EVENT* event,
    _In_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_ ULONG operationType,
    _In_ BOOLEAN isPostOperation,
    _In_ BOOLEAN includeLegacySequence
    )
/*++

Routine Description:

    Populate common fields of the file event. Note: No blocking is performed here; only fields required for collection and
    display are captured. Even if path resolution fails, context such as PID, MajorFunction, and FileObject is retained.

Arguments:

    Event - Output event.
    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    OperationType - Protocol operation type.
    IsPostOperation - TRUE indicates the post-callback records the result.

Return Value:

    None.

--*/
{
    PFLT_FILE_NAME_INFORMATION nameInformation = NULL;
    NTSTATUS nameStatus = STATUS_SUCCESS;

    RtlZeroMemory(event, sizeof(*event));
    event->version = KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION;
    event->size = sizeof(*event);
    event->operationType = operationType;
    event->majorFunction = data->Iopb->MajorFunction;
    event->minorFunction = data->Iopb->MinorFunction;
    event->processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(data);
    event->threadId = HandleToULong(PsGetCurrentThreadId());
    if (includeLegacySequence) {
        event->sequence = (ULONG64)InterlockedIncrement64(&gKswordArkFileMonitorRuntime.sequence);
    }
    KeQuerySystemTimePrecise((PLARGE_INTEGER)&event->timeUtc100ns);

    if (fltObjects != NULL && fltObjects->FileObject != NULL) {
        event->fileObjectAddress = (ULONG64)(ULONG_PTR)fltObjects->FileObject;
    }

    if (isPostOperation) {
        event->resultStatus = data->IoStatus.Status;
        event->fieldFlags |=
            KSWORD_ARK_FILE_MONITOR_FIELD_RESULT_PRESENT |
            KSWORD_ARK_FILE_MONITOR_FIELD_POST_OPERATION;
    }

    if (event->processId <= 4UL) {
        event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_SYSTEM_PROCESS;
    }

    if (data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        event->desiredAccess = data->Iopb->Parameters.Create.SecurityContext != NULL ?
            data->Iopb->Parameters.Create.SecurityContext->DesiredAccess :
            0UL;
        event->shareAccess = data->Iopb->Parameters.Create.ShareAccess;
        event->createOptions = data->Iopb->Parameters.Create.Options;
        event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_ACCESS_PRESENT;
    }
    else if (data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        event->fileInformationClass = data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    }
    else if (data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) {
        event->fsControlCode = data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
        event->fsInputBufferLength = data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength;
        event->fsOutputBufferLength = data->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength;
        event->fieldFlags |= KSWORD_ARK_FILE_MONITOR_FIELD_FSCTL_PRESENT;
    }

    // Post-operation callbacks may run at DISPATCH_LEVEL; name queries and FileName buffer access are only allowed at APC_LEVEL and below.
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    // When monitoring new callbacks separately, only copy the existing FileObject name without triggering name query allocation.
    if (!includeLegacySequence) {
        if (fltObjects != NULL &&
            fltObjects->FileObject != NULL &&
            fltObjects->FileObject->FileName.Buffer != NULL) {
            kswordArkFileMonitorCopyNameToEvent(event, &fltObjects->FileObject->FileName);
        }
        return;
    }

    nameStatus = FltGetFileNameInformation(
        data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInformation);
    if (NT_SUCCESS(nameStatus) && nameInformation != NULL) {
        (VOID)FltParseFileNameInformation(nameInformation);
        kswordArkFileMonitorCopyNameToEvent(event, &nameInformation->Name);
    }
    else if (fltObjects != NULL &&
        fltObjects->FileObject != NULL &&
        fltObjects->FileObject->FileName.Buffer != NULL) {
        kswordArkFileMonitorCopyNameToEvent(event, &fltObjects->FileObject->FileName);
    }

    if (nameInformation != NULL) {
        FltReleaseFileNameInformation(nameInformation);
    }
}

static VOID
kswordArkFileMonitorPublishCallbackEvent(
    _In_ const KSWORD_ARK_FILE_MONITOR_EVENT* event
    )
{
    KswordArkCallbackMonitorEventInput monitorInput;
    UNICODE_STRING pathText;

    // Old file events have completed path resolution; map directly to the unified callback telemetry structure to avoid redundant name lookups.
    if (event == NULL ||
        !kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)) {
        return;
    }
    RtlZeroMemory(&monitorInput, sizeof(monitorInput));
    RtlZeroMemory(&pathText, sizeof(pathText));
    if ((event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_PATH_PRESENT) != 0UL) {
        RtlInitUnicodeString(&pathText, event->path);
        monitorInput.path = &pathText;
    }
    monitorInput.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
    monitorInput.operation = event->operationType;
    monitorInput.originatingProcessId = event->processId;
    monitorInput.originatingThreadId = event->threadId;
    monitorInput.detailCode = ((event->majorFunction & 0xFFUL) << 8) |
        (event->minorFunction & 0xFFUL);
    monitorInput.originalAccess = event->desiredAccess;
    monitorInput.desiredAccess = event->desiredAccess;
    monitorInput.address = event->fileObjectAddress;
    if ((event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_ACCESS_PRESENT) != 0UL) {
        monitorInput.flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_ACCESS_PRESENT;
    }
    if ((event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_RESULT_PRESENT) != 0UL) {
        monitorInput.flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_STATUS_PRESENT;
        monitorInput.resultStatus = event->resultStatus;
    }
    if ((event->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_POST_OPERATION) != 0UL) {
        monitorInput.flags |= KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_POST_OPERATION;
    }
    kswordArkCallbackMonitorPublish(&monitorInput);
}

static VOID
kswordArkFileMonitorPushEvent(
    _In_ const KSWORD_ARK_FILE_MONITOR_EVENT* event
    )
/*++

Routine Description:

    Put events into a fixed ring buffer. Note: When full, discard the oldest event and increment droppedCount;
    R3 later displays the dropped count in the status bar to prompt the user to narrow the filter scope.

Arguments:

    Event - Filled event.

Return Value:

    None.

--*/
{
    KIRQL oldIrql;
    ULONG slotIndex = 0UL;

    if (event == NULL) {
        return;
    }

    KeAcquireSpinLock(&gKswordArkFileMonitorRuntime.ringLock, &oldIrql);

    slotIndex = gKswordArkFileMonitorRuntime.tailIndex;
    RtlCopyMemory(
        &gKswordArkFileMonitorRuntime.ring[slotIndex],
        event,
        sizeof(*event));
    gKswordArkFileMonitorRuntime.tailIndex =
        kswordArkFileMonitorAdvanceIndex(gKswordArkFileMonitorRuntime.tailIndex);

    if (gKswordArkFileMonitorRuntime.queuedCount == KSWORD_ARK_FILE_MONITOR_RING_CAPACITY) {
        gKswordArkFileMonitorRuntime.headIndex =
            kswordArkFileMonitorAdvanceIndex(gKswordArkFileMonitorRuntime.headIndex);
        gKswordArkFileMonitorRuntime.droppedCount += 1UL;
        gKswordArkFileMonitorRuntime.runtimeFlags |= KSWORD_ARK_FILE_MONITOR_RUNTIME_DROPPED;
    }
    else {
        gKswordArkFileMonitorRuntime.queuedCount += 1UL;
    }

    KeReleaseSpinLock(&gKswordArkFileMonitorRuntime.ringLock, oldIrql);
}

static BOOLEAN
kswordArkFileMonitorShouldCapture(
    _In_ PFLT_CALLBACK_DATA data,
    _In_ ULONG operationType
    )
/*++

Routine Description:

    Check if the current event matches the runtime filtering conditions. Note: The first version performs coarse filtering based
    only on operation type and PID; path/extension filtering is deferred to the R3 virtualization list and subsequent rule layers.

Arguments:

    Data - FltMgr callback data。
    OperationType - Protocol operation type.

Return Value:

    TRUE indicates collection should occur.

--*/
{
    ULONG processId = 0UL;

    if ((gKswordArkFileMonitorRuntime.runtimeFlags & KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED) == 0UL) {
        return FALSE;
    }
    if (operationType == 0UL ||
        (operationType & gKswordArkFileMonitorRuntime.operationMask) == 0UL) {
        return FALSE;
    }

    processId = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(data);
    if (gKswordArkFileMonitorRuntime.processIdFilter != 0UL &&
        gKswordArkFileMonitorRuntime.processIdFilter != processId) {
        return FALSE;
    }

    return TRUE;
}

FLT_PREOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _Outptr_result_maybenull_ PVOID* completionContext
    )
/*++

Routine Description:

    Minifilter pre-operation callback. Note: Create/SetInfo require post results and thus request
    a post callback; Read/Write/Cleanup/Close directly record pre-events to reduce overhead.

Arguments:

    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    CompletionContext: This implementation does not allocate context and always returns NULL.

Return Value:

    FLT_PREOP_SUCCESS_NO_CALLBACK or FLT_PREOP_SUCCESS_WITH_CALLBACK.

--*/
{
    ULONG operationType = 0UL;
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    KSWORD_ARK_FILE_MONITOR_EVENT event;
    BOOLEAN redirected = FALSE;
    BOOLEAN legacyCapture = FALSE;
    BOOLEAN callbackCapture = FALSE;

    if (completionContext != NULL) {
        *completionContext = NULL;
    }

    operationType = kswordArkMinifilterMapMajorToOperation(
        data->Iopb->MajorFunction,
        data->Iopb->MinorFunction,
        &data->Iopb->Parameters);

    if (operationType != 0UL &&
        kswordArkCallbackIsMinifilterBypassPid((ULONG)(ULONG_PTR)FltGetRequestorProcessId(data))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    callbackStatus = kswordArkMinifilterApplyRule(
        data,
        fltObjects,
        operationType);
    if (callbackStatus == FLT_PREOP_COMPLETE) {
        // Operations denied by rules have no post-callback, but the final status is still reported to the independent telemetry channel.
        if (kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)) {
            operationType = kswordArkFileMonitorMapMajorToOperation(
                data->Iopb->MajorFunction,
                data->Iopb->MinorFunction,
                &data->Iopb->Parameters);
            if (operationType != 0UL) {
                kswordArkFileMonitorFillCommonEvent(
                    &event,
                    data,
                    fltObjects,
                    operationType,
                    TRUE,
                    FALSE);
                kswordArkFileMonitorPublishCallbackEvent(&event);
            }
        }
        return FLT_PREOP_COMPLETE;
    }

    if (data->Iopb->MajorFunction == IRP_MJ_CREATE) {
        (VOID)kswordArkRedirectTryRewriteFileCreate(
            data,
            fltObjects,
            &redirected);
        UNREFERENCED_PARAMETER(redirected);
    }

    operationType = kswordArkFileMonitorMapMajorToOperation(
        data->Iopb->MajorFunction,
        data->Iopb->MinorFunction,
        &data->Iopb->Parameters);
    legacyCapture = kswordArkFileMonitorShouldCapture(data, operationType);
    callbackCapture = operationType != 0UL &&
        kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER);
    if (!legacyCapture && !callbackCapture) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (data->Iopb->MajorFunction == IRP_MJ_CREATE ||
        data->Iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL ||
        data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    kswordArkFileMonitorFillCommonEvent(
        &event,
        data,
        fltObjects,
        operationType,
        FALSE,
        legacyCapture);
    if (legacyCapture) {
        kswordArkFileMonitorPushEvent(&event);
    }
    if (callbackCapture) {
        kswordArkFileMonitorPublishCallbackEvent(&event);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
FLTAPI
kswordArkMinifilterPostOperation(
    _Inout_ PFLT_CALLBACK_DATA data,
    _In_ PCFLT_RELATED_OBJECTS fltObjects,
    _In_opt_ PVOID completionContext,
    _In_ FLT_POST_OPERATION_FLAGS flags
    )
/*++

Routine Description:

    minifilter post-operation callback. Note: record the final NTSTATUS for Create/SetInfo
    here; if FltMgr is draining, do not access potentially unstable context.

Arguments:

    Data - FltMgr callback data。
    FltObjects - FltMgr related objects。
    CompletionContext - Unused.
    Flags - post operation flags。

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING。

--*/
{
    ULONG operationType = 0UL;
    KSWORD_ARK_FILE_MONITOR_EVENT event;
    BOOLEAN legacyCapture = FALSE;
    BOOLEAN callbackCapture = FALSE;

    UNREFERENCED_PARAMETER(completionContext);

    if ((flags & FLTFL_POST_OPERATION_DRAINING) != 0UL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    operationType = kswordArkFileMonitorMapMajorToOperation(
        data->Iopb->MajorFunction,
        data->Iopb->MinorFunction,
        &data->Iopb->Parameters);
    legacyCapture = kswordArkFileMonitorShouldCapture(data, operationType);
    callbackCapture = operationType != 0UL &&
        kswordArkCallbackMonitorIsEnabled(KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER);
    if (!legacyCapture && !callbackCapture) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    kswordArkFileMonitorFillCommonEvent(
        &event,
        data,
        fltObjects,
        operationType,
        TRUE,
        legacyCapture);
    if (legacyCapture) {
        kswordArkFileMonitorPushEvent(&event);
    }
    if (callbackCapture) {
        kswordArkFileMonitorPublishCallbackEvent(&event);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static NTSTATUS FLTAPI
kswordArkFileMonitorUnloadCallback(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags
    )
/*++

Routine Description:

    FltMgr requests to unload the filter. Note: Actual resource release is uniformly
    handled by kswordArkFileMonitorUninitialize called during WDF driver unload.

Arguments:

    Flags - FltMgr unload flags。

Return Value:

    STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER(flags);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileMonitorInitialize(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath,
    _In_opt_ WDFDEVICE device
    )
/*++

Routine Description:

    initialize Phase-12 minifilter runtime. Note: Only register the filter; do not start collection by default.
    StartFiltering is explicitly triggered by a control IOCTL to avoid generating high-frequency file events immediately upon driver loading.

Arguments:

    DriverObject: The driver object passed to DriverEntry.
    RegistryPath - registry path passed to DriverEntry.
    Device - Control device used for logs; may be null initially.

Return Value:

    STATUS_SUCCESS or a failure status from FltRegisterFilter.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS registryStatus = STATUS_SUCCESS;

    RtlZeroMemory(&gKswordArkFileMonitorRuntime, sizeof(gKswordArkFileMonitorRuntime));
    gKswordArkFileMonitorRuntime.device = device;
    gKswordArkFileMonitorRuntime.operationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL;
    gKswordArkFileMonitorRuntime.registerStatus = STATUS_NOT_SUPPORTED;
    gKswordArkFileMonitorRuntime.startStatus = STATUS_NOT_SUPPORTED;
    ExInitializePushLock(&gKswordArkFileMonitorRuntime.controlLock);
    KeInitializeSpinLock(&gKswordArkFileMonitorRuntime.ringLock);

    registryStatus = kswordArkFileMonitorEnsureRegistryInstances(registryPath);
    if (!NT_SUCCESS(registryStatus)) {
        /*
         * Note: Do not terminate initialization immediately if instance registry completion fails. If the driver was installed
         * via INF, FltMgr may still complete registration from existing configuration; if it is indeed missing, the subsequent
         * FltRegisterFilter call will return a failure status closer to FltMgr's perspective and write it to RegisterStatus.
         */
        gKswordArkFileMonitorRuntime.lastErrorStatus = registryStatus;
        kswordArkFileMonitorLogFormat(
            "Warn",
            "KswordARK file monitor ensure minifilter registry instances failed, status=0x%08X.",
            registryStatus);
    }

    status = FltRegisterFilter(
        driverObject,
        &kGKswordArkFileMonitorRegistration,
        &gKswordArkFileMonitorRuntime.filter);
    gKswordArkFileMonitorRuntime.registerStatus = status;
    if (!NT_SUCCESS(status)) {
        gKswordArkFileMonitorRuntime.filter = NULL;
        gKswordArkFileMonitorRuntime.lastErrorStatus = status;
        kswordArkFileMonitorLogFormat(
            "Warn",
            "KswordARK file monitor FltRegisterFilter failed, status=0x%08X, registryStatus=0x%08X.",
            status,
            registryStatus);
        return status;
    }

    gKswordArkFileMonitorRuntime.runtimeFlags |= KSWORD_ARK_FILE_MONITOR_RUNTIME_REGISTERED;
    gKswordArkFileMonitorRuntime.lastErrorStatus = STATUS_SUCCESS;
    kswordArkFileMonitorLog("Info", "KswordARK file monitor minifilter registered.");
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileMonitorEnsureFilteringStarted(
    VOID
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    // Both monitoring entry points share a single FltStartFiltering call; the control lock eliminates concurrent startup races.
    kswordArkAcquirePushLockExclusive(&gKswordArkFileMonitorRuntime.controlLock);
    if (gKswordArkFileMonitorRuntime.filter == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
    }
    else if (gKswordArkFileMonitorRuntime.startStatus == STATUS_NOT_SUPPORTED) {
        status = FltStartFiltering(gKswordArkFileMonitorRuntime.filter);
        gKswordArkFileMonitorRuntime.startStatus = status;
    }
    else {
        status = gKswordArkFileMonitorRuntime.startStatus;
    }

    // Started indicates the FltMgr engine is running and no longer correlates with whether the legacy file monitoring page is collecting data.
    gKswordArkFileMonitorRuntime.lastErrorStatus = status;
    kswordArkMinifilterCallbackUpdateState(
        gKswordArkFileMonitorRuntime.filter,
        gKswordArkFileMonitorRuntime.registerStatus,
        gKswordArkFileMonitorRuntime.startStatus,
        NT_SUCCESS(status) ? TRUE : FALSE);
    kswordArkReleasePushLockExclusive(&gKswordArkFileMonitorRuntime.controlLock);
    return status;
}

VOID
kswordArkFileMonitorUninitialize(
    VOID
    )
/*++

Routine Description:

    Unregister Phase-12 minifilter runtime. Note: Clear the STARTED flag before
    unloading, then let FltUnregisterFilter wait for in-flight callbacks to complete.

Arguments:

    None.

Return Value:

    None.

--*/
{
    gKswordArkFileMonitorRuntime.runtimeFlags &= ~KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED;
    kswordArkMinifilterCallbackUpdateState(
        gKswordArkFileMonitorRuntime.filter,
        gKswordArkFileMonitorRuntime.registerStatus,
        gKswordArkFileMonitorRuntime.startStatus,
        FALSE);

    if (gKswordArkFileMonitorRuntime.filter != NULL) {
        FltUnregisterFilter(gKswordArkFileMonitorRuntime.filter);
        gKswordArkFileMonitorRuntime.filter = NULL;
    }

    gKswordArkFileMonitorRuntime.runtimeFlags = 0UL;
    kswordArkMinifilterCallbackUpdateState(NULL, STATUS_NOT_SUPPORTED, STATUS_NOT_SUPPORTED, FALSE);
}

NTSTATUS
kswordArkFileMonitorControl(
    _In_ const KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST* request
    )
/*++

Routine Description:

    Handle Start/Stop/Clear control commands. Note: Start calls FltStartFiltering on the first
    invocation; subsequent Start calls only update filter conditions and the STARTED flag.

Arguments:

    Request - Control request.

Return Value:

    STATUS_SUCCESS or a failure status from FltStartFiltering/parameter validation.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;

    if (request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    switch (request->action) {
    case KSWORD_ARK_FILE_MONITOR_ACTION_START:
        if (gKswordArkFileMonitorRuntime.filter == NULL) {
            gKswordArkFileMonitorRuntime.lastErrorStatus = STATUS_INVALID_DEVICE_STATE;
            return STATUS_INVALID_DEVICE_STATE;
        }

        if (request->operationMask != 0UL) {
            gKswordArkFileMonitorRuntime.operationMask =
                request->operationMask & KSWORD_ARK_FILE_MONITOR_OPERATION_ALL;
        }
        if (gKswordArkFileMonitorRuntime.operationMask == 0UL) {
            gKswordArkFileMonitorRuntime.operationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL;
        }
        gKswordArkFileMonitorRuntime.processIdFilter = request->processId;

        status = kswordArkFileMonitorEnsureFilteringStarted();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        gKswordArkFileMonitorRuntime.runtimeFlags |= KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED;
        gKswordArkFileMonitorRuntime.lastErrorStatus = STATUS_SUCCESS;
        kswordArkMinifilterCallbackUpdateState(
            gKswordArkFileMonitorRuntime.filter,
            gKswordArkFileMonitorRuntime.registerStatus,
            gKswordArkFileMonitorRuntime.startStatus,
            TRUE);
        kswordArkFileMonitorLog("Info", "KswordARK file monitor started.");
        return STATUS_SUCCESS;

    case KSWORD_ARK_FILE_MONITOR_ACTION_STOP:
        gKswordArkFileMonitorRuntime.runtimeFlags &= ~KSWORD_ARK_FILE_MONITOR_RUNTIME_STARTED;
        kswordArkMinifilterCallbackUpdateState(
            gKswordArkFileMonitorRuntime.filter,
            gKswordArkFileMonitorRuntime.registerStatus,
            gKswordArkFileMonitorRuntime.startStatus,
            NT_SUCCESS(gKswordArkFileMonitorRuntime.startStatus) ? TRUE : FALSE);
        kswordArkFileMonitorLog("Info", "KswordARK file monitor stopped.");
        return STATUS_SUCCESS;

    case KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR:
        KeAcquireSpinLock(&gKswordArkFileMonitorRuntime.ringLock, &oldIrql);
        gKswordArkFileMonitorRuntime.headIndex = 0UL;
        gKswordArkFileMonitorRuntime.tailIndex = 0UL;
        gKswordArkFileMonitorRuntime.queuedCount = 0UL;
        gKswordArkFileMonitorRuntime.droppedCount = 0UL;
        gKswordArkFileMonitorRuntime.runtimeFlags &= ~KSWORD_ARK_FILE_MONITOR_RUNTIME_DROPPED;
        /*
         * Note: QueuedCount is the sole indicator of event visibility in the ring. Clearing only resets
         * metadata; subsequent producers will fully overwrite old events before republishing slots. Zeroing a
         * static ring larger than 1 MiB is prohibited within a spinlock critical section at DISPATCH_LEVEL.
         */
        KeReleaseSpinLock(&gKswordArkFileMonitorRuntime.ringLock, oldIrql);
        return STATUS_SUCCESS;

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS
kswordArkFileMonitorQueryStatus(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Returns the file monitor runtime status. Note: R3 can use this to
    display registered/started status, queuedCount, and droppedCount.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response length.
    BytesWrittenOut - Bytes received for writing.

Return Value:

    STATUS_SUCCESS or buffer error.

--*/
{
    KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE* response = NULL;
    KIRQL oldIrql;

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->operationMask = gKswordArkFileMonitorRuntime.operationMask;
    response->processIdFilter = gKswordArkFileMonitorRuntime.processIdFilter;
    response->ringCapacity = KSWORD_ARK_FILE_MONITOR_RING_CAPACITY;
    response->sequence = (ULONG64)gKswordArkFileMonitorRuntime.sequence;
    response->registerStatus = gKswordArkFileMonitorRuntime.registerStatus;
    response->startStatus = gKswordArkFileMonitorRuntime.startStatus;
    response->lastErrorStatus = gKswordArkFileMonitorRuntime.lastErrorStatus;

    KeAcquireSpinLock(&gKswordArkFileMonitorRuntime.ringLock, &oldIrql);
    response->runtimeFlags = gKswordArkFileMonitorRuntime.runtimeFlags;
    response->queuedCount = gKswordArkFileMonitorRuntime.queuedCount;
    response->droppedCount = gKswordArkFileMonitorRuntime.droppedCount;
    KeReleaseSpinLock(&gKswordArkFileMonitorRuntime.ringLock, oldIrql);

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkFileMonitorDrain(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Retrieve events from the file monitor ring buffer. Note: Retrieval implies consumption; R3 should append events
    to the virtualization list based on returnedCount. When the buffer is insufficient, only return events that fit.

Arguments:

    OutputBuffer - Response buffer.
    OutputBufferLength - Response length.
    Request - Optional request limiting maxEvents.
    BytesWrittenOut - Receives the actual number of bytes written.

Return Value:

    STATUS_SUCCESS or buffer error.

--*/
{
    KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE* response = NULL;
    ULONG maxEvents = 0UL;
    ULONG capacityByBuffer = 0UL;
    ULONG eventsToReturn = 0UL;
    ULONG eventIndex = 0UL;
    KIRQL oldIrql;
    const size_t kHeaderSize =
        sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) -
        sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);

    if (outputBuffer == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < kHeaderSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_FILE_MONITOR_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);
    response->ringCapacity = KSWORD_ARK_FILE_MONITOR_RING_CAPACITY;

    capacityByBuffer = (ULONG)((outputBufferLength - kHeaderSize) / sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));
    maxEvents = capacityByBuffer;
    if (request != NULL && request->maxEvents != 0UL && request->maxEvents < maxEvents) {
        maxEvents = request->maxEvents;
    }

    KeAcquireSpinLock(&gKswordArkFileMonitorRuntime.ringLock, &oldIrql);
    response->totalQueuedBeforeDrain = gKswordArkFileMonitorRuntime.queuedCount;
    response->droppedCount = gKswordArkFileMonitorRuntime.droppedCount;
    response->runtimeFlags = gKswordArkFileMonitorRuntime.runtimeFlags;

    eventsToReturn = gKswordArkFileMonitorRuntime.queuedCount;
    if (eventsToReturn > maxEvents) {
        eventsToReturn = maxEvents;
    }
    KeReleaseSpinLock(&gKswordArkFileMonitorRuntime.ringLock, oldIrql);

    /*
     * Note: Claim and copy exactly one fixed-size event within the lock on each iteration, then release the lock immediately.
     * This prevents the producer from overwriting a slot being copied and limits each DISPATCH_LEVEL critical section to one
     * event; previously, a single critical section could copy more than 1 MiB. Consumed slots do not need clearing: HeadIndex
     * and QueuedCount already make them invisible, and the producer overwrites all contents before publishing the slot again.
     */
    for (eventIndex = 0UL; eventIndex < eventsToReturn; ++eventIndex) {
        ULONG slotIndex = 0UL;

        KeAcquireSpinLock(&gKswordArkFileMonitorRuntime.ringLock, &oldIrql);
        if (gKswordArkFileMonitorRuntime.queuedCount == 0UL) {
            KeReleaseSpinLock(&gKswordArkFileMonitorRuntime.ringLock, oldIrql);
            break;
        }

        slotIndex = gKswordArkFileMonitorRuntime.headIndex;
        RtlCopyMemory(
            &response->events[eventIndex],
            &gKswordArkFileMonitorRuntime.ring[slotIndex],
            sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));
        gKswordArkFileMonitorRuntime.headIndex =
            kswordArkFileMonitorAdvanceIndex(gKswordArkFileMonitorRuntime.headIndex);
        gKswordArkFileMonitorRuntime.queuedCount -= 1UL;
        KeReleaseSpinLock(&gKswordArkFileMonitorRuntime.ringLock, oldIrql);
    }

    response->returnedCount = eventIndex;

    *bytesWrittenOut = kHeaderSize + ((size_t)eventIndex * sizeof(KSWORD_ARK_FILE_MONITOR_EVENT));
    return STATUS_SUCCESS;
}

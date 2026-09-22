/*++

Module Name:

    storage_audit.c

Abstract:

    Read-only Storage, BitLocker/FVE, MountMgr, and file-system integrity audit
    backends for KswordARK. This file never exports encryption secrets, never
    mutates device stacks, and never patches dispatch tables.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_storage.h"
#include "../kernel/hook_scan_support.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSW_STORAGE_RESPONSE_HEADER_SIZE(ResponseType, RowType) (sizeof(ResponseType) - sizeof(RowType))
#define KSW_STORAGE_TAG 'tSsK'
#define KSW_STORAGE_FVEVOL_ABSENT_INDEX 0xFFFFFFFFUL
#define KSW_STORAGE_FAST_IO_FIELD(FieldName) { FIELD_OFFSET(FAST_IO_DISPATCH, FieldName), #FieldName }

typedef struct KswStorageFastIoField
{
    ULONG offset;
    PCSTR name;
} KswStorageFastIoField, *PkswStorageFastIoField;

typedef struct KswStorageLimits
{
    ULONG maxRows;
    ULONG maxDepth;
} KswStorageLimits, *PkswStorageLimits;

typedef struct KswStorageStackResult
{
    ULONG totalRows;
    ULONG returnedRows;
    ULONG fieldFlags;
    ULONG responseFlags;
    ULONG fvevolPresent;
    ULONG fvevolPosition;
    NTSTATUS lastStatus;
    BOOLEAN truncated;
} KswStorageStackResult, *PkswStorageStackResult;

NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING objectName,
    _In_ ULONG attributes,
    _In_opt_ PACCESS_STATE passedAccessState,
    _In_opt_ ACCESS_MASK desiredAccess,
    _In_ POBJECT_TYPE objectType,
    _In_ KPROCESSOR_MODE accessMode,
    _Inout_opt_ PVOID parseContext,
    _Out_ PVOID* object
    );

extern POBJECT_TYPE* IoDriverObjectType;

NTKERNELAPI
PDEVICE_OBJECT
IoGetLowerDeviceObject(
    _In_ PDEVICE_OBJECT deviceObject
    );

static const KswStorageFastIoField kGKswordStorageFastIoFields[] = {
    KSW_STORAGE_FAST_IO_FIELD(FastIoCheckIfPossible),
    KSW_STORAGE_FAST_IO_FIELD(FastIoRead),
    KSW_STORAGE_FAST_IO_FIELD(FastIoWrite),
    KSW_STORAGE_FAST_IO_FIELD(FastIoQueryBasicInfo),
    KSW_STORAGE_FAST_IO_FIELD(FastIoQueryStandardInfo),
    KSW_STORAGE_FAST_IO_FIELD(FastIoLock),
    KSW_STORAGE_FAST_IO_FIELD(FastIoUnlockSingle),
    KSW_STORAGE_FAST_IO_FIELD(FastIoUnlockAll),
    KSW_STORAGE_FAST_IO_FIELD(FastIoUnlockAllByKey),
    KSW_STORAGE_FAST_IO_FIELD(FastIoDeviceControl),
    KSW_STORAGE_FAST_IO_FIELD(AcquireFileForNtCreateSection),
    KSW_STORAGE_FAST_IO_FIELD(ReleaseFileForNtCreateSection),
    KSW_STORAGE_FAST_IO_FIELD(FastIoDetachDevice),
    KSW_STORAGE_FAST_IO_FIELD(FastIoQueryNetworkOpenInfo),
    KSW_STORAGE_FAST_IO_FIELD(AcquireForModWrite),
    KSW_STORAGE_FAST_IO_FIELD(MdlRead),
    KSW_STORAGE_FAST_IO_FIELD(MdlReadComplete),
    KSW_STORAGE_FAST_IO_FIELD(PrepareMdlWrite),
    KSW_STORAGE_FAST_IO_FIELD(MdlWriteComplete),
    KSW_STORAGE_FAST_IO_FIELD(FastIoReadCompressed),
    KSW_STORAGE_FAST_IO_FIELD(FastIoWriteCompressed),
    KSW_STORAGE_FAST_IO_FIELD(MdlReadCompleteCompressed),
    KSW_STORAGE_FAST_IO_FIELD(MdlWriteCompleteCompressed),
    KSW_STORAGE_FAST_IO_FIELD(FastIoQueryOpen),
    KSW_STORAGE_FAST_IO_FIELD(ReleaseForModWrite),
    KSW_STORAGE_FAST_IO_FIELD(AcquireForCcFlush),
    KSW_STORAGE_FAST_IO_FIELD(ReleaseForCcFlush)
};

static const PCWSTR kGKswordStorageFileSystemDriverNames[] = {
    L"\\FileSystem\\Ntfs",
    L"\\FileSystem\\Refs",
    L"\\FileSystem\\Fastfat",
    L"\\FileSystem\\exFat"
};

static VOID
kswordStorageCopyWide(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_z_ PCWSTR source
    )
/*++
Routine Description:
    Copy a NUL-terminated wide string into a fixed protocol buffer and always
    terminate the destination.
Arguments:
    Destination - Fixed protocol buffer to receive text.
    DestinationChars - Destination capacity in WCHAR units.
    Source - Optional source text.
Return Value:
    None. Invalid inputs leave no output beyond best-effort NUL termination.
--*/
{
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL) {
        return;
    }
    (VOID)RtlStringCchCopyW(destination, destinationChars, source);
    destination[destinationChars - 1UL] = L'\0';
}

static VOID
kswordStorageCopyUnicode(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_opt_ PCUNICODE_STRING source
    )
/*++
Routine Description:
    Copy a bounded UNICODE_STRING into a fixed protocol buffer without assuming
    that the source is NUL terminated.
Arguments:
    Destination - Fixed protocol buffer to receive text.
    DestinationChars - Destination capacity in WCHAR units.
    Source - Optional kernel UNICODE_STRING.
Return Value:
    None. Empty or invalid sources produce an empty string.
--*/
{
    ULONG charsToCopy = 0UL;
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }
    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }
    charsToCopy = (ULONG)(source->Length / sizeof(WCHAR));
    if (charsToCopy >= destinationChars) {
        charsToCopy = destinationChars - 1UL;
    }
    RtlCopyMemory(destination, source->Buffer, (SIZE_T)charsToCopy * sizeof(WCHAR));
    destination[charsToCopy] = L'\0';
}

static VOID
kswordStorageFormatDetail(
    _Out_writes_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars,
    _In_z_ PCWSTR formatText,
    ...
    )
/*++
Routine Description:
    Format one diagnostic detail string for a bounded protocol row.
Arguments:
    Destination - Fixed protocol buffer to receive formatted text.
    DestinationChars - Destination capacity in WCHAR units.
    FormatText - printf-style wide format string.
    ... - Format arguments.
Return Value:
    None. Formatting failures leave a terminated best-effort buffer.
--*/
{
    va_list arguments;
    if (destination == NULL || destinationChars == 0UL || formatText == NULL) {
        return;
    }
    destination[0] = L'\0';
    va_start(arguments, formatText);
    (VOID)RtlStringCbVPrintfW(destination, (SIZE_T)destinationChars * sizeof(WCHAR), formatText, arguments);
    va_end(arguments);
    destination[destinationChars - 1UL] = L'\0';
}

static BOOLEAN
kswordStorageDriverNameIsFvevol(
    _In_reads_(textChars) const WCHAR* text,
    _In_ ULONG textChars
    )
/*++
Routine Description:
    Check whether a bounded DriverObject name identifies fvevol.
Arguments:
    Text - Bounded driver-name buffer.
    TextChars - Maximum number of WCHARs to inspect.
Return Value:
    TRUE for names containing fvevol; otherwise FALSE.
--*/
{
    ULONG index = 0UL;
    if (text == NULL || textChars == 0UL) {
        return FALSE;
    }
    while (index + 5UL < textChars && text[index] != L'\0') {
        WCHAR c0 = RtlDowncaseUnicodeChar(text[index]);
        WCHAR c1 = RtlDowncaseUnicodeChar(text[index + 1UL]);
        WCHAR c2 = RtlDowncaseUnicodeChar(text[index + 2UL]);
        WCHAR c3 = RtlDowncaseUnicodeChar(text[index + 3UL]);
        WCHAR c4 = RtlDowncaseUnicodeChar(text[index + 4UL]);
        WCHAR c5 = RtlDowncaseUnicodeChar(text[index + 5UL]);
        if (c0 == L'f' && c1 == L'v' && c2 == L'e' && c3 == L'v' && c4 == L'o' && c5 == L'l') {
            return TRUE;
        }
        ++index;
    }
    return FALSE;
}

static KswStorageLimits
kswordStorageMakeLimits(
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request
    )
/*++
Routine Description:
    normalize caller-supplied row and depth budgets to conservative hard caps.
Arguments:
    Request - Optional request packet.
Return Value:
    Normalized limits used by the read-only collectors.
--*/
{
    KswStorageLimits limits;
    limits.maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS;
    limits.maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH;
    if (request != NULL && request->maxRows != 0UL) {
        limits.maxRows = request->maxRows;
    }
    if (request != NULL && request->maxDepth != 0UL) {
        limits.maxDepth = request->maxDepth;
    }
    if (limits.maxRows > KSWORD_ARK_STORAGE_HARD_MAX_ROWS) {
        limits.maxRows = KSWORD_ARK_STORAGE_HARD_MAX_ROWS;
    }
    if (limits.maxDepth > KSWORD_ARK_STORAGE_HARD_STACK_DEPTH) {
        limits.maxDepth = KSWORD_ARK_STORAGE_HARD_STACK_DEPTH;
    }
    return limits;
}

static NTSTATUS
kswordStorageBuildRequestPath(
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ UNICODE_STRING* path
    )
/*++
Routine Description:
    Validate and expose the optional request NT volume path as a bounded
    UNICODE_STRING.
Arguments:
    Request - Optional storage audit request.
    Path - Receives the bounded path view when present.
Return Value:
    STATUS_SUCCESS when a non-empty path is present; STATUS_NOT_FOUND when the
    caller did not provide a path; STATUS_INVALID_PARAMETER for malformed input.
--*/
{
    if (path == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(path, sizeof(*path));
    if (request == NULL || request->volumePathLengthChars == 0U) {
        return STATUS_NOT_FOUND;
    }
    if (request->volumePathLengthChars >= KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    path->Buffer = (PWCHAR)request->volumePath;
    path->Length = (USHORT)(request->volumePathLengthChars * sizeof(WCHAR));
    path->MaximumLength = path->Length;
    return STATUS_SUCCESS;
}

static ULONG
kswordStorageComputeCapacityRows(
    _In_ size_t outputBufferLength,
    _In_ size_t headerBytes,
    _In_ size_t rowBytes
    )
/*++
Routine Description:
    Convert an output buffer size into the number of variable rows that fit.
Arguments:
    OutputBufferLength - Caller output buffer length.
    HeaderBytes - Response header size without the first row.
    RowBytes - Size of one row.
Return Value:
    Number of rows that fit after the response header.
--*/
{
    if (outputBufferLength <= headerBytes || rowBytes == 0U) {
        return 0UL;
    }
    return (ULONG)((outputBufferLength - headerBytes) / rowBytes);
}

static NTSTATUS
kswordStorageReferenceVolumeDevice(
    _In_ const UNICODE_STRING* volumePath,
    _Outptr_ PFILE_OBJECT* fileObjectOut,
    _Outptr_ PDEVICE_OBJECT* deviceObjectOut
    )
/*++
Routine Description:
    Reference a volume device object by NT path using IoGetDeviceObjectPointer.
    The routine requests only read-attribute access and never sends state
    changing controls to the target volume.
Arguments:
    VolumePath - NT path supplied by the caller.
    FileObjectOut - Receives the referenced file object that owns the device
        reference lifetime.
    DeviceObjectOut - Receives the related device object.
Return Value:
    NTSTATUS from validation or IoGetDeviceObjectPointer.
--*/
{
    if (volumePath == NULL || volumePath->Buffer == NULL || fileObjectOut == NULL || deviceObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileObjectOut = NULL;
    *deviceObjectOut = NULL;
    return IoGetDeviceObjectPointer((PUNICODE_STRING)volumePath, FILE_READ_ATTRIBUTES, fileObjectOut, deviceObjectOut);
}

static VOID
kswordStorageAppendStackRow(
    _Inout_ KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE* response,
    _In_ ULONG capacityRows,
    _In_ ULONG stackIndex,
    _In_ PDEVICE_OBJECT deviceObject,
    _In_opt_ PCUNICODE_STRING requestPath,
    _Inout_ KswStorageStackResult* result
    )
/*++
Routine Description:
    Append one read-only device stack row and update derived FVE position flags.
Arguments:
    Response - Volume stack response under construction.
    CapacityRows - Number of rows that fit in the caller output buffer.
    StackIndex - Zero-based stack walk index.
    DeviceObject - Device object sampled for this row.
    RequestPath - Optional request path copied into each row for correlation.
    Result - Mutable aggregate counters and flags.
Return Value:
    None. Rows beyond capacity are counted and marked truncated.
--*/
{
    KSWORD_ARK_VOLUME_STACK_ROW* row = NULL;
    if (response == NULL || result == NULL || deviceObject == NULL) {
        return;
    }
    result->totalRows += 1UL;
    if (result->returnedRows >= capacityRows) {
        result->truncated = TRUE;
        result->responseFlags |= KSWORD_ARK_STORAGE_RISK_STACK_TRUNCATED;
        return;
    }
    row = &response->rows[result->returnedRows];
    RtlZeroMemory(row, sizeof(*row));
    row->rowType = 1UL;
    row->stackIndex = stackIndex;
    row->deviceType = deviceObject->DeviceType;
    row->deviceCharacteristics = deviceObject->Characteristics;
    row->deviceObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject;
    row->attachedDeviceAddress = (ULONGLONG)(ULONG_PTR)deviceObject->AttachedDevice;
    row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)deviceObject->DriverObject;
    row->confidence = KSWORD_ARK_STORAGE_CONFIDENCE_STACK_DERIVED;
    row->lastStatus = STATUS_SUCCESS;
    row->fieldFlags = KSWORD_ARK_STORAGE_FIELD_VOLUME_DEVICE_PRESENT;
    if (requestPath != NULL) {
        kswordStorageCopyUnicode(row->volumeDeviceName, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, requestPath);
        row->fieldFlags |= KSWORD_ARK_STORAGE_FIELD_NT_DEVICE_PATH_PRESENT;
    }
    if (deviceObject->DriverObject != NULL) {
        kswordStorageCopyUnicode(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS, &deviceObject->DriverObject->DriverName);
        row->fieldFlags |= KSWORD_ARK_STORAGE_FIELD_DRIVER_NAME_PRESENT;
    }
    if (kswordStorageDriverNameIsFvevol(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS)) {
        row->fieldFlags |= KSWORD_ARK_STORAGE_FIELD_FVEVOL_PRESENT;
        result->fvevolPresent = KSWORD_ARK_STORAGE_FVE_STATUS_PRESENT;
        if (result->fvevolPosition == KSW_STORAGE_FVEVOL_ABSENT_INDEX) {
            result->fvevolPosition = stackIndex;
        }
    }
    kswordStorageFormatDetail(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS, L"Read-only stack row captured from DeviceObject=0x%p.", deviceObject);
    result->returnedRows += 1UL;
}

static NTSTATUS
kswordStorageCollectVolumeStackIntoResponse(
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Inout_ KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE* response,
    _In_ ULONG capacityRows,
    _Out_ KswStorageStackResult* result
    )
/*++
Routine Description:
    Resolve an optional volume path and walk the attached/lower device stack in
    a bounded read-only fashion.
Arguments:
    Request - Optional storage audit request with an NT volume path filter.
    Response - Response whose rows receive stack entries.
    CapacityRows - Number of row slots available in Response.
    Result - Receives aggregate status and fvevol position information.
Return Value:
    STATUS_SUCCESS for completed or supported-empty output; otherwise the first
    resolution or stack-walk failure status.
--*/
{
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT baseDevice = NULL;
    PDEVICE_OBJECT currentDevice = NULL;
    PDEVICE_OBJECT lowerDevice = NULL;
    UNICODE_STRING requestPath;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG depth = 0UL;
    ULONG index = 0UL;
    KswStorageLimits limits = kswordStorageMakeLimits(request);

    if (response == NULL || result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(result, sizeof(*result));
    result->fvevolPresent = KSWORD_ARK_STORAGE_FVE_STATUS_NOT_PRESENT;
    result->fvevolPosition = KSW_STORAGE_FVEVOL_ABSENT_INDEX;
    result->lastStatus = STATUS_SUCCESS;

    status = kswordStorageBuildRequestPath(request, &requestPath);
    if (status == STATUS_NOT_FOUND) {
        result->lastStatus = status;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        result->lastStatus = status;
        return status;
    }

    status = kswordStorageReferenceVolumeDevice(&requestPath, &fileObject, &baseDevice);
    if (!NT_SUCCESS(status)) {
        result->lastStatus = status;
        return status;
    }

    currentDevice = IoGetAttachedDeviceReference(baseDevice);
    while (currentDevice != NULL && depth < limits.maxDepth) {
        lowerDevice = IoGetLowerDeviceObject(currentDevice);
        kswordStorageAppendStackRow(response, capacityRows, index, currentDevice, &requestPath, result);
        if (result->returnedRows != 0UL && result->returnedRows <= capacityRows) {
            response->rows[result->returnedRows - 1UL].lowerDeviceAddress = (ULONGLONG)(ULONG_PTR)lowerDevice;
        }
        ObDereferenceObject(currentDevice);
        currentDevice = lowerDevice;
        lowerDevice = NULL;
        ++depth;
        ++index;
    }

    if (currentDevice != NULL) {
        result->truncated = TRUE;
        result->responseFlags |= KSWORD_ARK_STORAGE_RISK_STACK_TRUNCATED;
        ObDereferenceObject(currentDevice);
    }
    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    if (result->fvevolPresent != KSWORD_ARK_STORAGE_FVE_STATUS_PRESENT) {
        result->responseFlags |= KSWORD_ARK_STORAGE_RISK_FVEVOL_ABSENT;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkStorageQueryVolumeStackAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Build a bounded read-only volume device stack response for an optional NT
    volume path filter.
Arguments:
    OutputBuffer - Response buffer supplied by WDF.
    OutputBufferLength - Response buffer length.
    Request - Optional storage audit request.
    BytesWrittenOut - Receives the number of response bytes written.
Return Value:
    NTSTATUS from validation or stack collection.
--*/
{
    const size_t kHeaderBytes = KSW_STORAGE_RESPONSE_HEADER_SIZE(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE, KSWORD_ARK_VOLUME_STACK_ROW);
    KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE* response = (KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE*)outputBuffer;
    KswStorageLimits limits = kswordStorageMakeLimits(request);
    KswStorageStackResult result;
    ULONG capacityRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || outputBufferLength < kHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = 0;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    capacityRows = kswordStorageComputeCapacityRows(outputBufferLength, kHeaderBytes, sizeof(KSWORD_ARK_VOLUME_STACK_ROW));
    if (capacityRows > limits.maxRows) {
        capacityRows = limits.maxRows;
    }
    response->version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->rowSize = sizeof(KSWORD_ARK_VOLUME_STACK_ROW);
    response->maxRows = limits.maxRows;
    response->fvevolPosition = KSW_STORAGE_FVEVOL_ABSENT_INDEX;

    status = kswordStorageCollectVolumeStackIntoResponse(request, response, capacityRows, &result);
    response->lastStatus = result.lastStatus;
    response->responseFlags = result.responseFlags;
    response->fieldFlags = result.fieldFlags;
    response->totalRows = result.totalRows;
    response->returnedRows = result.returnedRows;
    response->fvevolPresent = result.fvevolPresent;
    response->fvevolPosition = result.fvevolPosition;
    response->queryStatus = (result.returnedRows == 0UL) ? KSWORD_ARK_STORAGE_QUERY_STATUS_EMPTY : KSWORD_ARK_STORAGE_QUERY_STATUS_OK;
    if (result.truncated) {
        response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_PARTIAL;
    }
    *bytesWrittenOut = kHeaderBytes + ((size_t)response->returnedRows * sizeof(KSWORD_ARK_VOLUME_STACK_ROW));
    return status;
}

NTSTATUS
kswordArkStorageQueryBitLockerFveAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Return a safe BitLocker/FVE status row derived only from the visible volume
    stack position of fvevol. No key or protector payload is read or serialized.
Arguments:
    OutputBuffer - Response buffer supplied by WDF.
    OutputBufferLength - Response buffer length.
    Request - Optional storage audit request with a volume path filter.
    BytesWrittenOut - Receives the number of response bytes written.
Return Value:
    STATUS_SUCCESS for safe output, or buffer validation status.
--*/
{
    const size_t kHeaderBytes = KSW_STORAGE_RESPONSE_HEADER_SIZE(KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE, KSWORD_ARK_BITLOCKER_FVE_ROW);
    KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE* response = (KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE*)outputBuffer;
    KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE* stackResponse = NULL;
    KswStorageStackResult stackResult;
    UNICODE_STRING requestPath;
    ULONG capacityRows = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || outputBufferLength < kHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = 0;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    capacityRows = kswordStorageComputeCapacityRows(outputBufferLength, kHeaderBytes, sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW));
    if (capacityRows == 0UL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    stackResponse = (KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE*)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE) + (KSWORD_ARK_STORAGE_HARD_STACK_DEPTH * sizeof(KSWORD_ARK_VOLUME_STACK_ROW)), KSW_STORAGE_TAG);
#pragma warning(pop)
    if (stackResponse == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(stackResponse, sizeof(KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE) + (KSWORD_ARK_STORAGE_HARD_STACK_DEPTH * sizeof(KSWORD_ARK_VOLUME_STACK_ROW)));

    response->version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->rowSize = sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW);
    response->maxRows = kswordStorageMakeLimits(request).maxRows;
    status = kswordStorageCollectVolumeStackIntoResponse(request, stackResponse, KSWORD_ARK_STORAGE_HARD_STACK_DEPTH, &stackResult);

    response->lastStatus = stackResult.lastStatus;
    response->returnedRows = 1UL;
    response->totalRows = 1UL;
    response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_OK;
    response->rows[0].fvevolPresent = stackResult.fvevolPresent;
    response->rows[0].fvevolStackPosition = stackResult.fvevolPosition;
    response->rows[0].protectionStatus = KSWORD_ARK_STORAGE_FVE_STATUS_UNKNOWN;
    response->rows[0].conversionStatus = KSWORD_ARK_STORAGE_FVE_STATUS_UNKNOWN;
    response->rows[0].lockStatus = KSWORD_ARK_STORAGE_FVE_STATUS_UNKNOWN;
    response->rows[0].lastStatus = stackResult.lastStatus;
    response->rows[0].confidence = (stackResult.returnedRows == 0UL) ? KSWORD_ARK_STORAGE_CONFIDENCE_PARTIAL : KSWORD_ARK_STORAGE_CONFIDENCE_STACK_DERIVED;
    response->rows[0].fieldFlags = KSWORD_ARK_STORAGE_FIELD_STATUS_DERIVED_FROM_STACK;
    response->rows[0].riskFlags = stackResult.responseFlags | KSWORD_ARK_STORAGE_RISK_STATUS_UNCONFIRMED;
    if (NT_SUCCESS(kswordStorageBuildRequestPath(request, &requestPath))) {
        kswordStorageCopyUnicode(response->rows[0].volumeDeviceName, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, &requestPath);
        response->rows[0].fieldFlags |= KSWORD_ARK_STORAGE_FIELD_NT_DEVICE_PATH_PRESENT;
    }
    if (stackResult.fvevolPresent == KSWORD_ARK_STORAGE_FVE_STATUS_PRESENT) {
        response->fieldFlags |= KSWORD_ARK_STORAGE_FIELD_FVEVOL_PRESENT;
        response->rows[0].fieldFlags |= KSWORD_ARK_STORAGE_FIELD_FVEVOL_PRESENT;
        kswordStorageFormatDetail(response->rows[0].detail, KSWORD_ARK_STORAGE_DETAIL_CHARS, L"fvevol is present in the read-only device stack; FVE private state and protector material are not read.");
    }
    else {
        kswordStorageFormatDetail(response->rows[0].detail, KSWORD_ARK_STORAGE_DETAIL_CHARS, L"fvevol was not observed or the volume path was unavailable; FVE private state remains unknown by design.");
    }

    ExFreePoolWithTag(stackResponse, KSW_STORAGE_TAG);
    *bytesWrittenOut = kHeaderBytes + sizeof(KSWORD_ARK_BITLOCKER_FVE_ROW);
    return status;
}

NTSTATUS
kswordArkStorageQueryMountMgrMappingAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    enumerate simple drive-letter symbolic links from the DOS device namespace.
    This read-only seed does not parse or modify the MountMgr database.
Arguments:
    OutputBuffer - Response buffer supplied by WDF.
    OutputBufferLength - Response buffer length.
    Request - Optional request; currently used only for common row limits.
    BytesWrittenOut - Receives the number of response bytes written.
Return Value:
    STATUS_SUCCESS for bounded symbolic-link output, or buffer validation status.
--*/
{
    const size_t kHeaderBytes = KSW_STORAGE_RESPONSE_HEADER_SIZE(KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE, KSWORD_ARK_MOUNTMGR_MAPPING_ROW);
    KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE* response = (KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE*)outputBuffer;
    KswStorageLimits limits = kswordStorageMakeLimits(request);
    ULONG capacityRows = 0UL;
    WCHAR linkNameBuffer[] = L"\\DosDevices\\A:";
    WCHAR driveBuffer[] = L"A:";
    WCHAR targetBuffer[KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS];
    ULONG letterIndex = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || outputBufferLength < kHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = 0;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    capacityRows = kswordStorageComputeCapacityRows(outputBufferLength, kHeaderBytes, sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW));
    if (capacityRows > limits.maxRows) {
        capacityRows = limits.maxRows;
    }
    response->version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->rowSize = sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW);
    response->maxRows = limits.maxRows;
    response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_EMPTY;

    for (letterIndex = 0UL; letterIndex < 26UL; ++letterIndex) {
        UNICODE_STRING linkName;
        UNICODE_STRING targetName;
        OBJECT_ATTRIBUTES attributes;
        HANDLE linkHandle = NULL;
        NTSTATUS status;
        ULONG rowIndex;

        linkNameBuffer[12] = (WCHAR)(L'A' + letterIndex);
        driveBuffer[0] = (WCHAR)(L'A' + letterIndex);
        RtlInitUnicodeString(&linkName, linkNameBuffer);
        InitializeObjectAttributes(&attributes, &linkName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        status = ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &attributes);
        if (!NT_SUCCESS(status)) {
            continue;
        }
        RtlZeroMemory(targetBuffer, sizeof(targetBuffer));
        targetName.Buffer = targetBuffer;
        targetName.Length = 0U;
        targetName.MaximumLength = sizeof(targetBuffer);
        status = ZwQuerySymbolicLinkObject(linkHandle, &targetName, NULL);
        ZwClose(linkHandle);
        if (!NT_SUCCESS(status)) {
            continue;
        }

        response->totalRows += 1UL;
        if (response->returnedRows >= capacityRows) {
            response->responseFlags |= KSWORD_ARK_STORAGE_RISK_STACK_TRUNCATED;
            response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_PARTIAL;
            continue;
        }
        rowIndex = response->returnedRows;
        response->returnedRows += 1UL;
        response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_OK;
        response->rows[rowIndex].fieldFlags = KSWORD_ARK_STORAGE_FIELD_DOS_NAME_PRESENT | KSWORD_ARK_STORAGE_FIELD_NT_DEVICE_PATH_PRESENT;
        response->rows[rowIndex].confidence = KSWORD_ARK_STORAGE_CONFIDENCE_STACK_DERIVED;
        response->rows[rowIndex].lastStatus = STATUS_SUCCESS;
        kswordStorageCopyWide(response->rows[rowIndex].driveLetter, KSWORD_ARK_STORAGE_DRIVE_LETTER_CHARS, driveBuffer);
        kswordStorageCopyUnicode(response->rows[rowIndex].ntDevicePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, &targetName);
        kswordStorageFormatDetail(response->rows[rowIndex].detail, KSWORD_ARK_STORAGE_DETAIL_CHARS, L"Drive-letter symbolic link queried read-only; Volume GUID correlation is left to R3 or future reviewed MountMgr schema.");
    }

    response->fieldFlags = (response->returnedRows == 0UL) ? 0UL : (KSWORD_ARK_STORAGE_FIELD_DOS_NAME_PRESENT | KSWORD_ARK_STORAGE_FIELD_NT_DEVICE_PATH_PRESENT);
    response->lastStatus = STATUS_SUCCESS;
    *bytesWrittenOut = kHeaderBytes + ((size_t)response->returnedRows * sizeof(KSWORD_ARK_MOUNTMGR_MAPPING_ROW));
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordStorageReferenceFileSystemDriver(
    _In_z_ PCWSTR driverName,
    _Outptr_ PDRIVER_OBJECT* driverObjectOut
    )
/*++
Routine Description:
    Reference one file-system DriverObject by namespace name for read-only
    dispatch and FastIo sampling.
Arguments:
    DriverName - NUL-terminated driver object name.
    DriverObjectOut - Receives a referenced DriverObject on success.
Return Value:
    NTSTATUS from validation or ObReferenceObjectByName.
--*/
{
    UNICODE_STRING objectName;
    if (driverName == NULL || driverObjectOut == NULL || IoDriverObjectType == NULL || *IoDriverObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *driverObjectOut = NULL;
    RtlInitUnicodeString(&objectName, driverName);
    return ObReferenceObjectByName(&objectName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)driverObjectOut);
}

static VOID
kswordStorageFillOwnerModule(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONGLONG targetAddress,
    _Inout_ KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW* row
    )
/*++
Routine Description:
    Resolve a dispatch target address to a loaded module name using the existing
    SystemModuleInformation helper.
Arguments:
    ModuleInfo - Optional module snapshot.
    TargetAddress - Function pointer being classified.
    Row - Row to receive owner module fields and risk flags.
Return Value:
    None. Unresolved targets are explicitly flagged as unknown.
--*/
{
    const KswHookSystemModuleEntry* owner = NULL;
    const UCHAR* fileName = NULL;
    ULONG fileNameBytes = 0UL;
    if (row == NULL || targetAddress == 0ULL) {
        return;
    }
    owner = kswordArkHookFindModuleForAddress(moduleInfo, (ULONG_PTR)targetAddress);
    if (owner == NULL) {
        row->riskFlags |= KSWORD_ARK_STORAGE_RISK_OWNER_UNKNOWN | KSWORD_ARK_STORAGE_RISK_TARGET_OUTSIDE_MODULES;
        row->confidence = KSWORD_ARK_STORAGE_CONFIDENCE_PARTIAL;
        return;
    }
    row->fieldFlags |= KSWORD_ARK_STORAGE_FIELD_OWNER_MODULE_PRESENT;
    row->ownerModuleBase = (ULONGLONG)(ULONG_PTR)owner->imageBase;
    row->ownerModuleSize = owner->imageSize;
    kswordArkHookGetModuleFileName(owner, &fileName, &fileNameBytes);
    kswordArkHookCopyBoundedAnsiToWide(fileName, fileNameBytes, row->ownerModuleName, KSWORD_ARK_STORAGE_MODULE_NAME_CHARS);
}

static VOID
kswordStorageAppendFsIntegrityRow(
    _Inout_ KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE* response,
    _In_ ULONG capacityRows,
    _In_ ULONG fileSystemKind,
    _In_ PDRIVER_OBJECT driverObject,
    _In_ ULONG slotType,
    _In_ ULONG slotIndex,
    _In_ ULONGLONG slotAddress,
    _In_ ULONGLONG targetAddress,
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_z_ PCWSTR detailText
    )
/*++
Routine Description:
    Append one DriverObject dispatch or FastIo evidence row to a bounded
    response.
Arguments:
    Response - File-system integrity response under construction.
    CapacityRows - Number of rows available in the response buffer.
    FileSystemKind - Stable index of the file-system driver being sampled.
    DriverObject - Referenced DriverObject being described.
    SlotType - MajorFunction or FastIo slot classifier.
    SlotIndex - Slot index within the classifier.
    SlotAddress - Address of the sampled slot field.
    TargetAddress - Function pointer value read from the slot.
    ModuleInfo - Optional module snapshot used for owner attribution.
    DetailText - Human-readable row detail.
Return Value:
    None. Rows beyond capacity are counted and mark the response partial.
--*/
{
    KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW* row = NULL;
    if (response == NULL || driverObject == NULL) {
        return;
    }
    response->totalRows += 1UL;
    if (response->returnedRows >= capacityRows) {
        response->responseFlags |= KSWORD_ARK_STORAGE_RISK_STACK_TRUNCATED;
        response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_PARTIAL;
        return;
    }
    row = &response->rows[response->returnedRows];
    RtlZeroMemory(row, sizeof(*row));
    row->fileSystemKind = fileSystemKind;
    row->slotType = slotType;
    row->slotIndex = slotIndex;
    row->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    row->driverStart = (ULONGLONG)(ULONG_PTR)driverObject->DriverStart;
    row->driverSize = driverObject->DriverSize;
    row->slotAddress = slotAddress;
    row->targetAddress = targetAddress;
    row->confidence = KSWORD_ARK_STORAGE_CONFIDENCE_CONFIRMED;
    row->lastStatus = STATUS_SUCCESS;
    row->fieldFlags = KSWORD_ARK_STORAGE_FIELD_DRIVER_NAME_PRESENT;
    kswordStorageCopyUnicode(row->driverName, KSWORD_ARK_STORAGE_DRIVER_NAME_CHARS, &driverObject->DriverName);
    kswordStorageFillOwnerModule(moduleInfo, targetAddress, row);
    kswordStorageCopyWide(row->detail, KSWORD_ARK_STORAGE_DETAIL_CHARS, detailText);
    response->returnedRows += 1UL;
}

NTSTATUS
kswordArkStorageQueryFileSystemIntegrityAudit(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_opt_ const KSWORD_ARK_STORAGE_AUDIT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++
Routine Description:
    Query NTFS/ReFS/FAT/exFAT DriverObject dispatch and FastIo targets in a
    read-only manner. The routine records owner-module evidence but never
    rewrites or disables any pointer.
Arguments:
    OutputBuffer - Response buffer supplied by WDF.
    OutputBufferLength - Response buffer length.
    Request - Optional storage audit request controlling row budget and flags.
    BytesWrittenOut - Receives the number of response bytes written.
Return Value:
    STATUS_SUCCESS for completed or supported-empty output, or buffer status.
--*/
{
    const size_t kHeaderBytes = KSW_STORAGE_RESPONSE_HEADER_SIZE(KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE, KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW);
    KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE* response = (KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE*)outputBuffer;
    KswHookSystemModuleInformation* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    KswStorageLimits limits = kswordStorageMakeLimits(request);
    ULONG capacityRows = 0UL;
    ULONG fsIndex = 0UL;
    ULONG flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT;
    NTSTATUS moduleStatus;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || outputBufferLength < kHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *bytesWrittenOut = 0;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    capacityRows = kswordStorageComputeCapacityRows(outputBufferLength, kHeaderBytes, sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW));
    if (capacityRows > limits.maxRows) {
        capacityRows = limits.maxRows;
    }
    if (request != NULL && request->flags != 0UL) {
        flags = request->flags;
    }
    response->version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->rowSize = sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW);
    response->maxRows = limits.maxRows;
    response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_EMPTY;

    moduleStatus = kswordArkHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    response->lastStatus = moduleStatus;
    UNREFERENCED_PARAMETER(moduleInfoBytes);

    for (fsIndex = 0UL; fsIndex < RTL_NUMBER_OF(kGKswordStorageFileSystemDriverNames); ++fsIndex) {
        PDRIVER_OBJECT driverObject = NULL;
        NTSTATUS status;

        status = kswordStorageReferenceFileSystemDriver(kGKswordStorageFileSystemDriverNames[fsIndex], &driverObject);
        if (!NT_SUCCESS(status)) {
            continue;
        }

        if ((flags & KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DISPATCH) != 0UL) {
            ULONG majorIndex;
            for (majorIndex = 0UL; majorIndex <= IRP_MJ_MAXIMUM_FUNCTION; ++majorIndex) {
                PVOID target = (PVOID)driverObject->MajorFunction[majorIndex];
                WCHAR detail[KSWORD_ARK_STORAGE_DETAIL_CHARS];
                kswordStorageFormatDetail(detail, RTL_NUMBER_OF(detail), L"MajorFunction[%lu] sampled read-only.", majorIndex);
                kswordStorageAppendFsIntegrityRow(response, capacityRows, fsIndex, driverObject, KSWORD_ARK_STORAGE_SLOT_TYPE_MAJOR_FUNCTION, majorIndex, (ULONGLONG)(ULONG_PTR)&driverObject->MajorFunction[majorIndex], (ULONGLONG)(ULONG_PTR)target, NT_SUCCESS(moduleStatus) ? moduleInfo : NULL, detail);
            }
        }

        if ((flags & KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_FAST_IO) != 0UL && driverObject->FastIoDispatch != NULL) {
            ULONG fastIndex;
            for (fastIndex = 0UL; fastIndex < RTL_NUMBER_OF(kGKswordStorageFastIoFields); ++fastIndex) {
                const UCHAR* fieldAddress = (const UCHAR*)driverObject->FastIoDispatch + kGKswordStorageFastIoFields[fastIndex].offset;
                PVOID target = NULL;
                WCHAR detail[KSWORD_ARK_STORAGE_DETAIL_CHARS];
                RtlCopyMemory(&target, fieldAddress, sizeof(target));
                kswordStorageFormatDetail(detail, RTL_NUMBER_OF(detail), L"FastIoDispatch.%S sampled read-only.", kGKswordStorageFastIoFields[fastIndex].name);
                kswordStorageAppendFsIntegrityRow(response, capacityRows, fsIndex, driverObject, KSWORD_ARK_STORAGE_SLOT_TYPE_FAST_IO, fastIndex, (ULONGLONG)(ULONG_PTR)fieldAddress, (ULONGLONG)(ULONG_PTR)target, NT_SUCCESS(moduleStatus) ? moduleInfo : NULL, detail);
            }
        }

        ObDereferenceObject(driverObject);
    }

    if (moduleInfo != NULL) {
        ExFreePool(moduleInfo);
    }
    if (response->totalRows != 0UL && response->queryStatus == KSWORD_ARK_STORAGE_QUERY_STATUS_EMPTY) {
        response->queryStatus = KSWORD_ARK_STORAGE_QUERY_STATUS_OK;
    }
    *bytesWrittenOut = kHeaderBytes + ((size_t)response->returnedRows * sizeof(KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW));
    return STATUS_SUCCESS;
}

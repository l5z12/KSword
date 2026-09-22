/*++

Module Name:

    registry_query.c

Abstract:

    R0 registry read helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif

#define KSWORD_ARK_REGISTRY_QUERY_TAG 'gRsK'

NTKERNELAPI
NTSTATUS
ZwRenameKey(
    _In_ HANDLE keyHandle,
    _In_ PUNICODE_STRING newName
    );

static USHORT
KswordARKRegistryBoundedWideLength(
    _In_reads_(maxChars) const WCHAR* text,
    _In_ USHORT maxChars
    )
/*++

Routine Description:

    Calculate the actual length of the shared protocol fixed-length WCHAR string. Note: R3 passes
    a fixed array; do not assume NUL termination, so the scan range must be explicitly limited.

Arguments:

    Text: Base address of a fixed array.
    MaxChars - Maximum number of characters allowed to scan.

Return Value:

    Character count excluding NUL; return 0 for null pointer or zero capacity.

--*/
{
    USHORT index = 0U;

    if (text == NULL || maxChars == 0U) {
        return 0U;
    }

    for (index = 0U; index < maxChars; ++index) {
        if (text[index] == L'\0') {
            break;
        }
    }
    return index;
}

static BOOLEAN
kswordArkRegistryValidateKernelPath(
    _In_ const UNICODE_STRING* keyPath
    )
/*++

Routine Description:

    Validate that the registry path is an NT kernel namespace path. Note: The driver only accepts \REGISTRY\...
    paths to prevent R3 from passing UI-style paths like HKLM/HKCU directly, which would cause ambiguity.

Arguments:

    KeyPath: The key path to be checked.

Return Value:

    TRUE indicates ZwOpenKey can proceed; FALSE indicates an invalid path.

--*/
{
    UNICODE_STRING prefix;

    if (keyPath == NULL || keyPath->Buffer == NULL || keyPath->Length == 0U) {
        return FALSE;
    }

    RtlInitUnicodeString(&prefix, L"\\REGISTRY\\");
    return RtlPrefixUnicodeString(&prefix, keyPath, TRUE);
}

static VOID
kswordArkRegistryPrepareResponse(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Outptr_ KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE** responseOut
    )
/*++

Routine Description:

    initialize the fixed response packet. Note: All failure paths should return structured responses
    so R3 can display lastStatus and status enums instead of just seeing a DeviceIoControl failure.

Arguments:

    OutputBuffer - WDF output buffer.
    OutputBufferLength - Output buffer length.
    ResponseOut - Returns a pointer to the response structure.

Return Value:

    None. This function has no return value.

--*/
{
    KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE* response = NULL;

    if (responseOut == NULL) {
        return;
    }
    *responseOut = NULL;

    if (outputBuffer == NULL ||
        outputBufferLength < sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE)) {
        return;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REGISTRY_READ_STATUS_UNKNOWN;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *responseOut = response;
}

static NTSTATUS
kswordArkRegistryBuildKernelPath(
    _In_reads_(KSWORD_ARK_REGISTRY_PATH_CHARS) const WCHAR* sourcePath,
    _Out_ UNICODE_STRING* pathOut
    )
/*++

Routine Description:

    Construct UNICODE_STRING from the fixed path array in the shared protocol. Note: All R0
    registry operations must pass through here to uniformly check for NUL, length, and
    \REGISTRY\ prefix, avoiding scattered path validation logic at individual Zw* call sites.

Arguments:

    SourcePath: fixed WCHAR path array in the request.
    PathOut - Output UNICODE_STRING; Buffer points to SourcePath; no memory allocation.

Return Value:

    STATUS_SUCCESS or path parameter error status.

--*/
{
    USHORT pathChars = 0U;

    if (sourcePath == NULL || pathOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(pathOut, sizeof(*pathOut));
    pathChars = KswordARKRegistryBoundedWideLength(
        sourcePath,
        (USHORT)KSWORD_ARK_REGISTRY_PATH_CHARS);
    if (pathChars == 0U || pathChars >= KSWORD_ARK_REGISTRY_PATH_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    pathOut->Buffer = (PWSTR)sourcePath;
    pathOut->Length = (USHORT)(pathChars * sizeof(WCHAR));
    pathOut->MaximumLength = pathOut->Length;
    if (!kswordArkRegistryValidateKernelPath(pathOut)) {
        return STATUS_OBJECT_PATH_SYNTAX_BAD;
    }

    return STATUS_SUCCESS;
}

static VOID
kswordArkRegistryBuildValueName(
    _In_reads_(KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS) const WCHAR* sourceName,
    _In_ BOOLEAN namePresent,
    _Out_ UNICODE_STRING* nameOut
    )
/*++

Routine Description:

    Construct UNICODE_STRING from the fixed value name array in the shared
    protocol. Note: The default value is represented by an empty UNICODE_STRING;
    ZwQueryValueKey, ZwSetValueKey, and ZwDeleteValueKey all accept this form.

Arguments:

    SourceName - Array of value names in the request.
    NamePresent - TRUE indicates a named value in the array; FALSE indicates the default value.
    NameOut - Output value name as UNICODE_STRING.

Return Value:

    None. This function has no return value.

--*/
{
    USHORT nameChars = 0U;

    RtlZeroMemory(nameOut, sizeof(*nameOut));
    if (!namePresent || sourceName == NULL) {
        return;
    }

    nameChars = KswordARKRegistryBoundedWideLength(
        sourceName,
        (USHORT)KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS);
    nameOut->Buffer = (PWSTR)sourceName;
    nameOut->Length = (USHORT)(nameChars * sizeof(WCHAR));
    nameOut->MaximumLength = nameOut->Length;
}

static VOID
kswordArkRegistryPrepareOperationResponse(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _Outptr_ KSWORD_ARK_REGISTRY_OPERATION_RESPONSE** responseOut
    )
/*++

Routine Description:

    initialize the generic write operation response. Note: Actions such as create, delete, and rename only
    require the aggregated status and the underlying NTSTATUS, so they share this response structure.

Arguments:

    OutputBuffer - Output buffer.
    OutputBufferLength - Output buffer length.
    ResponseOut - Output response pointer.

Return Value:

    None. This function has no return value.

--*/
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;

    if (responseOut == NULL) {
        return;
    }
    *responseOut = NULL;

    if (outputBuffer == NULL ||
        outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_REGISTRY_OPERATION_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_UNKNOWN;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *responseOut = response;
}

static ULONG
kswordArkRegistryMapOperationStatus(
    _In_ NTSTATUS status
    )
/*++

Routine Description:

    Convert NTSTATUS to a user-friendly registry operation status for R3. Note: The IOCTL itself should return
    STATUS_SUCCESS whenever possible; actual success or failure is placed within the structured response.

Arguments:

    Status - Underlying Zw* return status.

Return Value:

    KSWORD_ARK_REGISTRY_OPERATION_STATUS_*。

--*/
{
    if (NT_SUCCESS(status)) {
        return KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
    }
    if (status == STATUS_OBJECT_NAME_NOT_FOUND ||
        status == STATUS_OBJECT_PATH_NOT_FOUND) {
        return KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND;
    }
    if (status == STATUS_OBJECT_NAME_COLLISION) {
        return KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS;
    }
    return KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
}

NTSTATUS
kswordArkDriverReadRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Read a specified registry value. Note: This function performs only read-only ZwOpenKey/ZwQueryValueKey
    operations. Data is copied up to KSWORD_ARK_REGISTRY_DATA_MAX_BYTES; if exceeded, a truncated status is returned.

Arguments:

    OutputBuffer - Output response buffer.
    OutputBufferLength - Output buffer length.
    Request - Shared protocol request.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates a structured response was written; parameter or output buffer errors return failure.

--*/
{
    KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    ULONG resultLength = 0UL;
    ULONG queryLength = 0UL;
    ULONG maxDataBytes = KSWORD_ARK_REGISTRY_DATA_MAX_BYTES;
    ULONG boundedQueryLength = 0UL;
    PKEY_VALUE_PARTIAL_INFORMATION valueInformation = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    USHORT valueNameChars = 0U;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    kswordArkRegistryPrepareResponse(outputBuffer, outputBufferLength, &response);
    if (response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    if ((request->flags & KSWORD_ARK_REGISTRY_READ_FLAG_VALUE_NAME_PRESENT) != 0UL) {
        valueNameChars = KswordARKRegistryBoundedWideLength(
            request->valueName,
            (USHORT)KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS);
        if (valueNameChars >= KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS) {
            response->status = KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
            response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }
    }
    else {
        valueNameChars = 0U;
    }

    valueName.Buffer = (PWSTR)request->valueName;
    valueName.Length = (USHORT)(valueNameChars * sizeof(WCHAR));
    valueName.MaximumLength = valueName.Length;

    InitializeObjectAttributes(
        &objectAttributes,
        &keyPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        response->status = (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) ?
            KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND :
            KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        NULL,
        0UL,
        &resultLength);
    if (resultLength == 0UL &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        response->status = (status == STATUS_OBJECT_NAME_NOT_FOUND) ?
            KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND :
            KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = status;
        ZwClose(keyHandle);
        return STATUS_SUCCESS;
    }

    if (resultLength < (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) {
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = STATUS_INFO_LENGTH_MISMATCH;
        ZwClose(keyHandle);
        return STATUS_SUCCESS;
    }

    if (request->maxDataBytes != 0UL &&
        request->maxDataBytes < maxDataBytes) {
        maxDataBytes = request->maxDataBytes;
    }
    if (maxDataBytes > KSWORD_ARK_REGISTRY_DATA_MAX_BYTES) {
        maxDataBytes = KSWORD_ARK_REGISTRY_DATA_MAX_BYTES;
    }

    boundedQueryLength =
        (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
        maxDataBytes;
    if (boundedQueryLength < (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) {
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = STATUS_INTEGER_OVERFLOW;
        ZwClose(keyHandle);
        return STATUS_SUCCESS;
    }
    if (boundedQueryLength > resultLength) {
        boundedQueryLength = resultLength;
    }
    if (boundedQueryLength < (ULONG)sizeof(KEY_VALUE_PARTIAL_INFORMATION)) {
        boundedQueryLength = (ULONG)sizeof(KEY_VALUE_PARTIAL_INFORMATION);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    valueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        boundedQueryLength,
        KSWORD_ARK_REGISTRY_QUERY_TAG);
#pragma warning(pop)
    if (valueInformation == NULL) {
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(keyHandle);
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(valueInformation, boundedQueryLength);

    queryLength = boundedQueryLength;
    status = ZwQueryValueKey(
        keyHandle,
        &valueName,
        KeyValuePartialInformation,
        valueInformation,
        queryLength,
        &resultLength);
    ZwClose(keyHandle);

    if (!NT_SUCCESS(status) &&
        status != STATUS_BUFFER_TOO_SMALL &&
        status != STATUS_BUFFER_OVERFLOW) {
        response->status = (status == STATUS_OBJECT_NAME_NOT_FOUND) ?
            KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND :
            KSWORD_ARK_REGISTRY_READ_STATUS_FAILED;
        response->lastStatus = status;
        ExFreePoolWithTag(valueInformation, KSWORD_ARK_REGISTRY_QUERY_TAG);
        return STATUS_SUCCESS;
    }

    if (status == STATUS_BUFFER_TOO_SMALL) {
        response->requiredBytes = (resultLength > (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) ?
            (resultLength - (ULONG)FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data)) :
            0UL;
        response->dataBytes = 0UL;
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_BUFFER_TOO_SMALL;
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        ExFreePoolWithTag(valueInformation, KSWORD_ARK_REGISTRY_QUERY_TAG);
        return STATUS_SUCCESS;
    }

    response->valueType = valueInformation->Type;
    response->requiredBytes = valueInformation->DataLength;

    response->dataBytes = valueInformation->DataLength;
    if (response->dataBytes > maxDataBytes) {
        response->dataBytes = maxDataBytes;
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_BUFFER_TOO_SMALL;
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
    }
    else {
        response->status = KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS;
        response->lastStatus = STATUS_SUCCESS;
    }

    if (response->dataBytes != 0UL) {
        RtlCopyMemory(response->data, valueInformation->Data, response->dataBytes);
    }

    ExFreePoolWithTag(valueInformation, KSWORD_ARK_REGISTRY_QUERY_TAG);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverEnumRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Enumerates subkeys and values of the specified registry key. Note: R3 tree expansion and value list
    refresh are performed in R0 while online to avoid mixing Win32 and R0 read paths on the same UI page.

Arguments:

    OutputBuffer - Output enumeration response.
    OutputBufferLength - Output buffer length.
    Request - Enumeration request.
    BytesWrittenOut - Bytes written returned.

Return Value:

    STATUS_SUCCESS indicates that the structured response has been written; parameter errors return a failure status.

--*/
{
    KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    HANDLE keyHandle = NULL;
    ULONG subKeyIndex = 0UL;
    ULONG valueIndex = 0UL;
    ULONG maxSubKeys = KSWORD_ARK_REGISTRY_ENUM_MAX_SUBKEYS;
    ULONG maxValues = KSWORD_ARK_REGISTRY_ENUM_MAX_VALUES;
    ULONG maxValueDataBytes = KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_REGISTRY_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_UNKNOWN;
    response->lastStatus = STATUS_UNSUCCESSFUL;
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &keyPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &objectAttributes);
    if (!NT_SUCCESS(status)) {
        response->status = (status == STATUS_OBJECT_NAME_NOT_FOUND ||
            status == STATUS_OBJECT_PATH_NOT_FOUND) ?
            KSWORD_ARK_REGISTRY_ENUM_STATUS_NOT_FOUND :
            KSWORD_ARK_REGISTRY_ENUM_STATUS_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    if (request->maxSubKeys != 0UL && request->maxSubKeys < maxSubKeys) {
        maxSubKeys = request->maxSubKeys;
    }
    if (request->maxValues != 0UL && request->maxValues < maxValues) {
        maxValues = request->maxValues;
    }
    if (request->maxValueDataBytes != 0UL && request->maxValueDataBytes < maxValueDataBytes) {
        maxValueDataBytes = request->maxValueDataBytes;
    }

    if ((request->flags & KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS) != 0UL) {
        for (subKeyIndex = 0UL; ; ++subKeyIndex) {
            UCHAR informationBuffer[sizeof(KEY_BASIC_INFORMATION) + (KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS * sizeof(WCHAR))] = { 0 };
            PKEY_BASIC_INFORMATION keyInformation = (PKEY_BASIC_INFORMATION)informationBuffer;
            ULONG resultLength = 0UL;
            ULONG copyBytes = 0UL;

            status = ZwEnumerateKey(
                keyHandle,
                subKeyIndex,
                KeyBasicInformation,
                keyInformation,
                sizeof(informationBuffer),
                &resultLength);
            if (status == STATUS_NO_MORE_ENTRIES) {
                break;
            }
            if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
                response->lastStatus = status;
                break;
            }

            response->subKeyCount += 1UL;
            if (response->returnedSubKeyCount >= maxSubKeys ||
                response->returnedSubKeyCount >= KSWORD_ARK_REGISTRY_ENUM_MAX_SUBKEYS) {
                response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
                continue;
            }

            copyBytes = keyInformation->NameLength;
            if (copyBytes > ((KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS - 1U) * sizeof(WCHAR))) {
                copyBytes = (KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS - 1U) * sizeof(WCHAR);
                response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
            }
            if (copyBytes != 0UL) {
                RtlCopyMemory(
                    response->subKeys[response->returnedSubKeyCount].name,
                    keyInformation->Name,
                    copyBytes);
            }
            response->returnedSubKeyCount += 1UL;
        }
    }

    if ((request->flags & KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES) != 0UL) {
        for (valueIndex = 0UL; ; ++valueIndex) {
            UCHAR informationBuffer[sizeof(KEY_VALUE_FULL_INFORMATION) +
                (KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS * sizeof(WCHAR)) +
                KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES] = { 0 };
            PKEY_VALUE_FULL_INFORMATION valueInformation = (PKEY_VALUE_FULL_INFORMATION)informationBuffer;
            ULONG resultLength = 0UL;
            ULONG nameBytes = 0UL;
            ULONG dataBytes = 0UL;

            status = ZwEnumerateValueKey(
                keyHandle,
                valueIndex,
                KeyValueFullInformation,
                valueInformation,
                sizeof(informationBuffer),
                &resultLength);
            if (status == STATUS_NO_MORE_ENTRIES) {
                break;
            }
            if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
                response->lastStatus = status;
                break;
            }

            response->valueCount += 1UL;
            if (response->returnedValueCount >= maxValues ||
                response->returnedValueCount >= KSWORD_ARK_REGISTRY_ENUM_MAX_VALUES) {
                response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
                continue;
            }

            nameBytes = valueInformation->NameLength;
            if (nameBytes > ((KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS - 1U) * sizeof(WCHAR))) {
                nameBytes = (KSWORD_ARK_REGISTRY_VALUE_NAME_CHARS - 1U) * sizeof(WCHAR);
                response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
            }
            if (nameBytes != 0UL) {
                RtlCopyMemory(
                    response->values[response->returnedValueCount].name,
                    valueInformation->Name,
                    nameBytes);
                response->values[response->returnedValueCount].flags |=
                    KSWORD_ARK_REGISTRY_ENUM_VALUE_FLAG_NAME_PRESENT;
            }

            response->values[response->returnedValueCount].valueType = valueInformation->Type;
            response->values[response->returnedValueCount].requiredBytes = valueInformation->DataLength;
            dataBytes = valueInformation->DataLength;
            if (dataBytes > maxValueDataBytes) {
                dataBytes = maxValueDataBytes;
                response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
            }
            if (dataBytes > KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES) {
                dataBytes = KSWORD_ARK_REGISTRY_ENUM_VALUE_DATA_MAX_BYTES;
                response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
            }
            if (dataBytes != 0UL &&
                valueInformation->DataOffset != 0UL &&
                valueInformation->DataOffset < sizeof(informationBuffer) &&
                dataBytes <= (sizeof(informationBuffer) - valueInformation->DataOffset)) {
                RtlCopyMemory(
                    response->values[response->returnedValueCount].data,
                    ((PUCHAR)valueInformation) + valueInformation->DataOffset,
                    dataBytes);
                response->values[response->returnedValueCount].dataBytes = dataBytes;
            }
            response->returnedValueCount += 1UL;
        }
    }

    ZwClose(keyHandle);
    if (response->status == KSWORD_ARK_REGISTRY_ENUM_STATUS_UNKNOWN) {
        response->status = KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS;
    }
    if (response->lastStatus == STATUS_UNSUCCESSFUL) {
        response->lastStatus = STATUS_SUCCESS;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverSetRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    kswordArkRegistryPrepareOperationResponse(outputBuffer, outputBufferLength, &response);
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION ||
        request->dataBytes > KSWORD_ARK_REGISTRY_DATA_MAX_BYTES) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (NT_SUCCESS(status)) {
        kswordArkRegistryBuildValueName(
            request->valueName,
            ((request->flags & KSWORD_ARK_REGISTRY_SET_FLAG_VALUE_NAME_PRESENT) != 0UL),
            &valueName);
        InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objectAttributes);
        if (NT_SUCCESS(status)) {
            status = ZwSetValueKey(
                keyHandle,
                &valueName,
                0UL,
                request->valueType,
                (PVOID)request->data,
                request->dataBytes);
            ZwClose(keyHandle);
        }
    }

    response->status = kswordArkRegistryMapOperationStatus(status);
    response->lastStatus = status;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverDeleteRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    HANDLE keyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    kswordArkRegistryPrepareOperationResponse(outputBuffer, outputBufferLength, &response);
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (NT_SUCCESS(status)) {
        kswordArkRegistryBuildValueName(
            request->valueName,
            ((request->flags & KSWORD_ARK_REGISTRY_DELETE_VALUE_FLAG_NAME_PRESENT) != 0UL),
            &valueName);
        InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objectAttributes);
        if (NT_SUCCESS(status)) {
            status = ZwDeleteValueKey(keyHandle, &valueName);
            ZwClose(keyHandle);
        }
    }

    response->status = kswordArkRegistryMapOperationStatus(status);
    response->lastStatus = status;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverCreateRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    HANDLE keyHandle = NULL;
    ULONG disposition = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    kswordArkRegistryPrepareOperationResponse(outputBuffer, outputBufferLength, &response);
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwCreateKey(
            &keyHandle,
            KEY_READ | KEY_WRITE,
            &objectAttributes,
            0UL,
            NULL,
            REG_OPTION_NON_VOLATILE,
            &disposition);
        if (NT_SUCCESS(status)) {
            ZwClose(keyHandle);
        }
    }

    response->status = kswordArkRegistryMapOperationStatus(status);
    response->lastStatus = status;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverDeleteRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    HANDLE keyHandle = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    kswordArkRegistryPrepareOperationResponse(outputBuffer, outputBufferLength, &response);
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenKey(&keyHandle, DELETE, &objectAttributes);
        if (NT_SUCCESS(status)) {
            status = ZwDeleteKey(keyHandle);
            ZwClose(keyHandle);
        }
    }

    response->status = kswordArkRegistryMapOperationStatus(status);
    response->lastStatus = status;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverRenameRegistryValue(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_RENAME_REGISTRY_VALUE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    UNICODE_STRING oldValueName;
    UNICODE_STRING newValueName;
    HANDLE keyHandle = NULL;
    ULONG resultLength = 0UL;
    PKEY_VALUE_PARTIAL_INFORMATION valueInformation = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    kswordArkRegistryPrepareOperationResponse(outputBuffer, outputBufferLength, &response);
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (NT_SUCCESS(status)) {
        kswordArkRegistryBuildValueName(request->oldValueName, TRUE, &oldValueName);
        kswordArkRegistryBuildValueName(request->newValueName, TRUE, &newValueName);
        InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenKey(&keyHandle, KEY_QUERY_VALUE | KEY_SET_VALUE, &objectAttributes);
    }
    if (NT_SUCCESS(status)) {
        status = ZwQueryValueKey(keyHandle, &oldValueName, KeyValuePartialInformation, NULL, 0UL, &resultLength);
        if (status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW) {
#pragma warning(push)
#pragma warning(disable:4996)
            valueInformation = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(
                NonPagedPoolNx,
                resultLength,
                KSWORD_ARK_REGISTRY_QUERY_TAG);
#pragma warning(pop)
            if (valueInformation == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else {
                RtlZeroMemory(valueInformation, resultLength);
                status = ZwQueryValueKey(keyHandle, &oldValueName, KeyValuePartialInformation, valueInformation, resultLength, &resultLength);
            }
        }
        if (NT_SUCCESS(status) && valueInformation != NULL) {
            status = ZwSetValueKey(
                keyHandle,
                &newValueName,
                0UL,
                valueInformation->Type,
                valueInformation->Data,
                valueInformation->DataLength);
            if (NT_SUCCESS(status)) {
                status = ZwDeleteValueKey(keyHandle, &oldValueName);
            }
        }
        if (valueInformation != NULL) {
            ExFreePoolWithTag(valueInformation, KSWORD_ARK_REGISTRY_QUERY_TAG);
        }
        ZwClose(keyHandle);
    }

    response->status = kswordArkRegistryMapOperationStatus(status);
    response->lastStatus = status;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverRenameRegistryKey(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
{
    KSWORD_ARK_REGISTRY_OPERATION_RESPONSE* response = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING keyPath;
    UNICODE_STRING newKeyName;
    HANDLE keyHandle = NULL;
    USHORT newNameChars = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_REGISTRY_OPERATION_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    kswordArkRegistryPrepareOperationResponse(outputBuffer, outputBufferLength, &response);
    *bytesWrittenOut = sizeof(*response);

    if (request->version != KSWORD_ARK_REGISTRY_PROTOCOL_VERSION) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_REVISION_MISMATCH;
        return STATUS_SUCCESS;
    }

    newNameChars = KswordARKRegistryBoundedWideLength(
        request->newKeyName,
        (USHORT)KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS);
    if (newNameChars == 0U || newNameChars >= KSWORD_ARK_REGISTRY_ENUM_KEY_NAME_CHARS) {
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    newKeyName.Buffer = (PWSTR)request->newKeyName;
    newKeyName.Length = (USHORT)(newNameChars * sizeof(WCHAR));
    newKeyName.MaximumLength = newKeyName.Length;

    status = kswordArkRegistryBuildKernelPath(request->keyPath, &keyPath);
    if (NT_SUCCESS(status)) {
        InitializeObjectAttributes(&objectAttributes, &keyPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        status = ZwOpenKey(&keyHandle, KEY_WRITE, &objectAttributes);
        if (NT_SUCCESS(status)) {
            status = ZwRenameKey(keyHandle, &newKeyName);
            ZwClose(keyHandle);
        }
    }

    response->status = kswordArkRegistryMapOperationStatus(status);
    response->lastStatus = status;
    return STATUS_SUCCESS;
}

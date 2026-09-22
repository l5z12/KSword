/*++

Module Name:

    handle_object_query.c

Abstract:

    Object type/name and restricted proxy query for PID+handle inputs.

Environment:

    Kernel-mode Driver Framework

--*/

#include "handle_support.h"

#define KSWORD_ARK_HANDLE_POOL_TAG 'hOsK'
#define KSWORD_ARK_OBJECT_PROXY_ALLOWED_TYPE_MASK 0x0000007FUL

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

typedef PVOID
(NTAPI* KswordArkExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID process,
    _Out_ PVOID apcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID apcState
    );

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

NTKERNELAPI
POBJECT_TYPE
NTAPI
ObGetObjectType(
    _In_ PVOID object
    );

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

static PVOID
kswordArkHandleAllocateNonPaged(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate a temporary nonpaged buffer for object-name queries. Note:
    Prefer ExAllocatePool2; fall back to ExAllocatePoolWithTag for older WDKs/systems.

Arguments:

    BufferBytes - Number of bytes to allocate.

Return Value:

    Nonpaged buffer pointer or NULL.

--*/
{
    static volatile LONG allocatorResolved = 0;
    static KswordArkExAllocatePooL2Fn exAllocatePool2Fn = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        exAllocatePool2Fn = (KswordArkExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (exAllocatePool2Fn != NULL) {
        return exAllocatePool2Fn(POOL_FLAG_NON_PAGED, bufferBytes, KSWORD_ARK_HANDLE_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSWORD_ARK_HANDLE_POOL_TAG);
#pragma warning(pop)
}

static VOID
kswordArkHandleCopyUnicodeStringToFixed(
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _In_opt_ const UNICODE_STRING* source,
    _Out_opt_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Copy a counted Unicode string into a fixed protocol buffer. Note: All output strings
    are forced to be NUL-terminated, and truncation status is explicitly reported.

Arguments:

    Destination - Fixed WCHAR buffer in the response packet.
    DestinationChars - Capacity of Destination in WCHARs.
    Source - Optional counted source string.
    TruncatedOut - Optional truncation flag.

Return Value:

    None.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG copyChars = 0UL;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || source->Buffer == NULL || source->Length == 0U) {
        return;
    }

    sourceChars = (ULONG)(source->Length / sizeof(WCHAR));
    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1UL;
        if (truncatedOut != NULL) {
            *truncatedOut = TRUE;
        }
    }

    RtlCopyMemory(destination, source->Buffer, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}

NTSTATUS
kswordArkHandleQueryTypeName(
    _In_ POBJECT_TYPE objectType,
    _In_ const KswDynState* dynState,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _Out_ BOOLEAN* truncatedOut,
    _Out_ ULONG* sourceOut
    )
/*++

Routine Description:

    Read OBJECT_TYPE.Name via DynData offset. Note: System Informer's OtName field provides the UNICODE_STRING
    offset; if missing, this query degrades to failure but does not affect basic object information.

Arguments:

    ObjectType - Object type pointer returned by ObGetObjectType.
    DynState - Active DynData snapshot.
    Destination - Fixed output buffer.
    DestinationChars - Destination capacity in WCHARs.
    TruncatedOut - Receives truncation flag.

Return Value:

    STATUS_SUCCESS when type name was copied; otherwise a failure status.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING typeName;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    USHORT index = 0U;
    USHORT lastSeparator = 0U;
    BOOLEAN separatorFound = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (sourceOut != NULL) {
        *sourceOut = KSWORD_ARK_OBJECT_TYPE_NAME_SOURCE_NONE;
    }
    if (objectType == NULL || dynState == NULL || destination == NULL ||
        destinationChars == 0UL || sourceOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // OBJECT_TYPE objects are named in \ObjectTypes.  Prefer that stable object
    // namespace projection and keep the private OtName field only as fallback.
    status = ObQueryNameString(objectType, NULL, 0UL, &requiredBytes);
    if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL ||
        status == STATUS_BUFFER_OVERFLOW) {
        allocationBytes = requiredBytes;
        if (allocationBytes < sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)) {
            allocationBytes = sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
        }
        if (allocationBytes <= 64UL * 1024UL) {
            nameInfo = (POBJECT_NAME_INFORMATION)kswordArkHandleAllocateNonPaged(
                allocationBytes);
        }
        if (nameInfo != NULL) {
            RtlZeroMemory(nameInfo, allocationBytes);
            status = ObQueryNameString(
                objectType,
                nameInfo,
                allocationBytes,
                &requiredBytes);
            if (NT_SUCCESS(status) && nameInfo->Name.Buffer != NULL) {
                typeName = nameInfo->Name;
                for (index = 0U;
                    index < (USHORT)(typeName.Length / sizeof(WCHAR));
                    ++index) {
                    if (typeName.Buffer[index] == L'\\') {
                        lastSeparator = index;
                        separatorFound = TRUE;
                    }
                }
                if (separatorFound &&
                    lastSeparator + 1U < typeName.Length / sizeof(WCHAR)) {
                    typeName.Buffer += lastSeparator + 1U;
                    typeName.Length = (USHORT)(typeName.Length -
                        ((lastSeparator + 1U) * sizeof(WCHAR)));
                    typeName.MaximumLength = typeName.Length;
                }
                kswordArkHandleCopyUnicodeStringToFixed(
                    destination,
                    destinationChars,
                    &typeName,
                    truncatedOut);
                *sourceOut = KSWORD_ARK_OBJECT_TYPE_NAME_SOURCE_OBJECT_NAMESPACE;
                ExFreePoolWithTag(nameInfo, KSWORD_ARK_HANDLE_POOL_TAG);
                return STATUS_SUCCESS;
            }
            ExFreePoolWithTag(nameInfo, KSWORD_ARK_HANDLE_POOL_TAG);
        }
    }

    if (!kswordArkHandleIsOffsetPresent(dynState->kernel.otName)) {
        return NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
    }

    RtlZeroMemory(&typeName, sizeof(typeName));
    __try {
        RtlCopyMemory(&typeName, (PUCHAR)objectType + dynState->kernel.otName, sizeof(typeName));
        kswordArkHandleCopyUnicodeStringToFixed(destination, destinationChars, &typeName, truncatedOut);
        *sourceOut = KSWORD_ARK_OBJECT_TYPE_NAME_SOURCE_DYNDATA_OTNAME;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkHandleQueryObjectName(
    _In_ PVOID object,
    _Out_writes_(destinationChars) WCHAR* destination,
    _In_ ULONG destinationChars,
    _Out_ BOOLEAN* truncatedOut
    )
/*++

Routine Description:

    Query object name with ObQueryNameString. Note: First query the required length, then allocate a temporary
    buffer to read; returning an empty name is still considered success, and the UI displays 'unnamed'.

Arguments:

    Object - Referenced object body.
    Destination - Fixed output buffer.
    DestinationChars - Destination capacity in WCHARs.
    TruncatedOut - Receives truncation flag.

Return Value:

    STATUS_SUCCESS when the object-name query completed; otherwise NTSTATUS.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (truncatedOut != NULL) {
        *truncatedOut = FALSE;
    }
    if (object == NULL || destination == NULL || destinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    destination[0] = L'\0';
    status = ObQueryNameString(object, NULL, 0, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {
        if (NT_SUCCESS(status)) {
            return STATUS_SUCCESS;
        }
        return status;
    }

    allocationBytes = requiredBytes;
    if (allocationBytes < sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR)) {
        allocationBytes = sizeof(OBJECT_NAME_INFORMATION) + sizeof(WCHAR);
    }
    if (allocationBytes > (64UL * 1024UL)) {
        allocationBytes = 64UL * 1024UL;
    }

    nameInfo = (POBJECT_NAME_INFORMATION)kswordArkHandleAllocateNonPaged(allocationBytes);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(object, nameInfo, allocationBytes, &requiredBytes);
    if (NT_SUCCESS(status)) {
        kswordArkHandleCopyUnicodeStringToFixed(destination, destinationChars, &nameInfo->Name, truncatedOut);
    }
    ExFreePoolWithTag(nameInfo, KSWORD_ARK_HANDLE_POOL_TAG);

    return status;
}

static BOOLEAN
kswordArkHandleIsProxyTypeAllowed(
    _In_ ULONG objectTypeIndex
    )
/*++

Routine Description:

    Apply a conservative first-pass proxy whitelist. Note: The first version only allows a very low type index
    range and still applies privilege reduction; unknown or oversized types are denied by default without guessing.

Arguments:

    ObjectTypeIndex - Object type index decoded from OBJECT_TYPE.

Return Value:

    TRUE when the proxy policy may attempt a downgraded open.

--*/
{
    if (objectTypeIndex == 0UL || objectTypeIndex >= 32UL) {
        return FALSE;
    }

    return ((KSWORD_ARK_OBJECT_PROXY_ALLOWED_TYPE_MASK & (1UL << objectTypeIndex)) != 0UL) ? TRUE : FALSE;
}

VOID
kswordArkHandleMaybeOpenProxyHandle(
    _In_ PVOID object,
    _In_ POBJECT_TYPE objectType,
    _In_ ULONG objectTypeIndex,
    _Inout_ KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response
    )
/*++

Routine Description:

    Preserve the legacy proxy-handle policy fields without opening a proxy
    Note: This audit path returns only policy denial/downgrade reasons;
    it does not create, close, or duplicate any target object handles.

Arguments:

    Object - Referenced object body.
    ObjectType - Object type pointer.
    ObjectTypeIndex - Decoded object type index.
    Response - Mutable response carrying policy/result fields.

Return Value:

    None. The response is annotated in place.

--*/
{
    if (response == NULL) {
        return;
    }

    response->proxyStatus = KSWORD_ARK_OBJECT_PROXY_STATUS_NOT_REQUESTED;
    if (object == NULL || objectType == NULL) {
        return;
    }
    if (!kswordArkHandleIsProxyTypeAllowed(objectTypeIndex)) {
        response->proxyStatus = KSWORD_ARK_OBJECT_PROXY_STATUS_DENIED_BY_POLICY;
        return;
    }

    //
    // This task performs only R0 handle decoding enhancement; even if the type is within the old proxy whitelist,
    // no proxy handles are opened or closed to avoid audit queries having side effects on target object operations.
    //
    response->proxyPolicyFlags =
        KSWORD_ARK_OBJECT_PROXY_POLICY_DOWNGRADED |
        KSWORD_ARK_OBJECT_PROXY_POLICY_TYPE_WHITELISTED;
    response->proxyStatus = KSWORD_ARK_OBJECT_PROXY_STATUS_DENIED_BY_POLICY;
}

NTSTATUS
kswordArkDriverQueryHandleObject(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query object type/name details through a caller-supplied PID + handle value.
    Note: The function does not accept arbitrary object addresses, so it will not
    promote Phase-4 displayed addresses to credentials for subsequent operations.

Arguments:

    OutputBuffer - Fixed response buffer.
    OutputBufferLength - Capacity of OutputBuffer.
    Request - Query request containing target PID and handle value.
    BytesWrittenOut - Receives sizeof(response) on success/failure with packet.

Return Value:

    STATUS_SUCCESS when the response packet is populated, or validation failure.

--*/
{
    KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE* response = NULL;
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    PVOID object = NULL;
    PVOID objectHeader = NULL;
    POBJECT_TYPE objectType = NULL;
    OBJECT_HANDLE_INFORMATION handleInformation;
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    BOOLEAN attached = FALSE;
    BOOLEAN truncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requestFlags = 0UL;

    if (outputBuffer == NULL || bytesWrittenOut == NULL || request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->processId == 0UL || request->handleValue == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_HANDLE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = request->processId;
    response->handleValue = request->handleValue;
    response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE;
    response->proxyStatus = KSWORD_ARK_OBJECT_PROXY_STATUS_NOT_REQUESTED;
    response->requestedAccess = request->requestedAccess;
    response->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    response->grantedAccessReadStatus = STATUS_UNSUCCESSFUL;
    response->objectHeaderDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
    response->objectHeaderReadStatus = STATUS_UNSUCCESSFUL;
    response->nameInfoStatus = KSWORD_ARK_OBJECT_NAME_INFO_STATUS_NOT_REQUESTED;

    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&handleInformation, sizeof(handleInformation));
    kswordArkDynDataSnapshot(&dynState);
    kswordArkHandlePrepareObjectDynData(response, &dynState);
    requestFlags = (request->flags == 0UL) ? KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL : request->flags;

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_PROCESS_LOOKUP_FAILED;
        response->objectReferenceStatus = status;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(attachState, sizeof(attachState));
    __try {
        KeStackAttachProcess((PVOID)processObject, attachState);
        attached = TRUE;
        status = ObReferenceObjectByHandle(
            (HANDLE)(ULONG_PTR)request->handleValue,
            0,
            NULL,
            UserMode,
            &object,
            &handleInformation);
        KeUnstackDetachProcess(attachState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        if (attached) {
            KeUnstackDetachProcess(attachState);
            attached = FALSE;
        }
    }
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED;
        response->objectReferenceStatus = status;
        ObDereferenceObject(processObject);
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    response->objectReferenceStatus = STATUS_SUCCESS;
    response->objectAddress = (ULONG64)(ULONG_PTR)object;
    response->actualGrantedAccess = handleInformation.GrantedAccess;
    response->grantedAccessDecodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_OK;
    response->grantedAccessReadStatus = STATUS_SUCCESS;
    response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_PRESENT;
    response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_HEADER_BODY_PRESENT;
    objectHeader = kswordArkHandleGetObjectHeaderFromBody(object);

    __try {
        objectType = ObGetObjectType(object);
        if (NT_SUCCESS(kswordArkHandleReadObjectTypeIndex(objectType, &dynState, &response->objectTypeIndex))) {
            response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_TYPE_INDEX_PRESENT;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->typeStatus = GetExceptionCode();
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_TYPE_QUERY_FAILED;
    }

    kswordArkHandleFillQueryObjectHeaderAudit(
        response,
        objectHeader,
        object,
        objectType,
        &dynState);
    if (response->objectTypeIndexSource == KSWORD_ARK_OBJECT_TYPE_SOURCE_NONE) {
        response->objectTypeIndexSource = kswordArkHandleMergeTypeIndexSource(
            ((response->fieldFlags & KSWORD_ARK_OBJECT_INFO_FIELD_TYPE_INDEX_PRESENT) != 0UL) ? TRUE : FALSE,
            response->objectTypeIndex,
            ((response->fieldFlags & KSWORD_ARK_OBJECT_INFO_FIELD_HEADER_TYPE_INDEX_PRESENT) != 0UL) ? TRUE : FALSE,
            response->objectHeaderTypeIndex);
    }
    if (response->objectHeaderDecodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_DYNDATA_MISSING &&
        response->queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_HEADER_DYNDATA_MISSING;
    }
    else if (response->objectHeaderDecodeStatus == KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_READ_FAILED &&
        response->queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_HEADER_QUERY_FAILED;
    }

    if ((requestFlags & KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_TYPE_NAME) != 0UL) {
        truncated = FALSE;
        status = kswordArkHandleQueryTypeName(
            objectType,
            &dynState,
            response->typeName,
            KSWORD_ARK_OBJECT_TYPE_NAME_CHARS,
            &truncated,
            &response->objectTypeNameSource);
        response->typeStatus = status;
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_TYPE_NAME_PRESENT;
            if (truncated) {
                response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_TRUNCATED;
            }
        }
        else if (response->queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE) {
            response->objectTypeNameSource = KSWORD_ARK_OBJECT_TYPE_NAME_SOURCE_QUERY_FAILED;
            response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_TYPE_QUERY_FAILED;
        }
    }

    if ((requestFlags & KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_OBJECT_NAME) != 0UL) {
        truncated = FALSE;
        status = kswordArkHandleQueryObjectName(
            object,
            response->objectName,
            KSWORD_ARK_OBJECT_NAME_CHARS,
            &truncated);
        response->nameStatus = status;
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_NAME_PRESENT;
            if (truncated) {
                response->nameInfoStatus = KSWORD_ARK_OBJECT_NAME_INFO_STATUS_QUERY_TRUNCATED;
                response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_TRUNCATED;
            }
            else {
                response->nameInfoStatus = KSWORD_ARK_OBJECT_NAME_INFO_STATUS_QUERY_OK;
            }
        }
        else if (response->queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE) {
            response->nameInfoStatus = KSWORD_ARK_OBJECT_NAME_INFO_STATUS_QUERY_FAILED;
            response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_QUERY_FAILED;
        }
        else if (response->nameInfoStatus == KSWORD_ARK_OBJECT_NAME_INFO_STATUS_NOT_REQUESTED) {
            response->nameInfoStatus = KSWORD_ARK_OBJECT_NAME_INFO_STATUS_QUERY_FAILED;
        }
    }

    if ((requestFlags & KSWORD_ARK_QUERY_OBJECT_FLAG_REQUEST_PROXY_HANDLE) != 0UL) {
        kswordArkHandleMaybeOpenProxyHandle(object, objectType, response->objectTypeIndex, response);
    }

    if (response->queryStatus == KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_OK;
    }
    if (response->queryStatus != KSWORD_ARK_OBJECT_QUERY_STATUS_OK &&
        response->queryStatus != KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_TRUNCATED &&
        response->fieldFlags != 0UL) {
        response->queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_PARTIAL;
    }

    ObDereferenceObject(object);
    ObDereferenceObject(processObject);
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

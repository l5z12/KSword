/*++

Module Name:

    section_query.c

Abstract:

    Phase-7 process SectionObject and ControlArea mapping inspection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_section.h"

#include "ark/ark_dyndata.h"
#include "section_support.h"

#define KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE) - sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY))

#define KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE) - sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY))

#ifndef RTL_NUMBER_OF
#define RTL_NUMBER_OF(A) (sizeof(A) / sizeof((A)[0]))
#endif

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE processId,
    _Outptr_ PEPROCESS* process
    );

static NTSTATUS
kswordArkSectionOpenFileObjectByPath(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _Outptr_result_maybenull_ PFILE_OBJECT* fileObjectOut,
    _Out_opt_ HANDLE* fileHandleOut
    )
/*++

Routine Description:

    Open and reference a FILE_OBJECT using the NT path provided by R3. Note: The caller passes only
    the file path, not the kernel FILE_OBJECT address; the returned object reference must be released.

Arguments:

    PathText - NT path, e.g., \??\C:\Windows\System32\kernel32.dll.
    PathLengthChars - character count excluding NUL.
    FileObjectOut - Receives the FILE_OBJECT after acquiring a reference.
    FileHandleOut - Optional kernel handle output; caller must call ZwClose.

Return Value:

    STATUS_SUCCESS or error codes from ZwCreateFile/ObReferenceObjectByHandle.

--*/
{
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileObjectOut != NULL) {
        *fileObjectOut = NULL;
    }
    if (fileHandleOut != NULL) {
        *fileHandleOut = NULL;
    }
    if (pathText == NULL ||
        pathLengthChars == 0U ||
        pathLengthChars >= KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS ||
        fileObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&filePath, sizeof(filePath));
    filePath.Buffer = (PWCH)pathText;
    filePath.Length = (USHORT)(pathLengthChars * sizeof(WCHAR));
    filePath.MaximumLength = filePath.Length + sizeof(WCHAR);

    InitializeObjectAttributes(
        &objectAttributes,
        &filePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        NULL,
        0U);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        return status;
    }

    *fileObjectOut = fileObject;
    if (fileHandleOut != NULL) {
        *fileHandleOut = fileHandle;
    }
    else {
        ZwClose(fileHandle);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverQueryProcessSection(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query the target process's main image SectionObject, ControlArea, and mapping summary. Note: Input accepts only the
    PID; all returned addresses are diagnostic display values and must not be used as credentials for subsequent IOCTLs.

Arguments:

    OutputBuffer - Output response packet.
    OutputBufferLength - Output buffer capacity.
    Request - Request packet containing PID and maximum mapping entry count.
    BytesWrittenOut - Actual number of bytes written received.

Return Value:

    STATUS_SUCCESS indicates the response header is valid; query failure details are written to response->queryStatus.

--*/
{
    KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE* response = NULL;
    KswDynState dynState;
    PEPROCESS processObject = NULL;
    PFILE_OBJECT imageFileObject = NULL;
    PVOID sectionObject = NULL;
    PVOID controlArea = NULL;
    BOOLEAN remoteUnsupported = FALSE;
    ULONG requestFlags = 0UL;
    ULONG maxMappings = 0UL;
    size_t entryCapacity = 0U;
    size_t totalBytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN hasPrivateSectionLayout = FALSE;
    BOOLEAN hasMappingLayout = FALSE;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->processId == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    response = (KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_SECTION_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY);
    response->processId = request->processId;
    response->queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    kswordArkSectionPrepareOffsets(response, &dynState);
    hasPrivateSectionLayout =
        kswordArkSectionIsOffsetPresent(dynState.kernel.epSectionObject) &&
        kswordArkSectionIsOffsetPresent(dynState.kernel.mmSectionControlArea);
    hasMappingLayout =
        kswordArkSectionIsOffsetPresent(dynState.kernel.mmControlAreaListHead) &&
        kswordArkSectionIsOffsetPresent(dynState.kernel.mmControlAreaLock);

    requestFlags = (request->flags == 0UL) ? KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL : request->flags;
    maxMappings = request->maxMappings;
    if (maxMappings == 0UL) {
        maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT;
    }
    if (maxMappings > KSWORD_ARK_SECTION_MAPPING_LIMIT_MAX) {
        maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_MAX;
    }

    entryCapacity = (outputBufferLength - KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY);
    if (entryCapacity > (size_t)maxMappings) {
        entryCapacity = (size_t)maxMappings;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        *bytesWrittenOut = KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (hasPrivateSectionLayout) {
        status = kswordArkSectionReadProcessSectionObject(
            processObject,
            &dynState,
            &sectionObject);
        response->lastStatus = status;
        if (NT_SUCCESS(status) && sectionObject != NULL) {
            response->sectionObjectAddress = (ULONG64)(ULONG_PTR)sectionObject;
            response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_SECTION_OBJECT_PRESENT;
            if ((requestFlags & (KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_CONTROL_AREA |
                    KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_MAPPINGS)) != 0UL) {
                status = kswordArkSectionReadControlArea(
                    sectionObject,
                    &dynState,
                    &controlArea,
                    &remoteUnsupported);
                response->lastStatus = status;
            }
        }
    }
    if (controlArea == NULL &&
        (requestFlags & (KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_CONTROL_AREA |
            KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_MAPPINGS)) != 0UL) {
        status = kswordArkSectionReferenceProcessImageControlArea(
            processObject,
            &imageFileObject,
            &controlArea);
        response->lastStatus = status;
    }

    if (controlArea != NULL) {
        response->controlAreaAddress = (ULONG64)(ULONG_PTR)controlArea;
        response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_CONTROL_AREA_PRESENT;
    }
    if (remoteUnsupported) {
        response->fieldFlags |= KSWORD_ARK_SECTION_FIELD_REMOTE_MAPPING_UNSUPPORTED;
        response->queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_REMOTE_UNSUPPORTED;
    }
    else if (controlArea == NULL) {
        response->queryStatus =
            KSWORD_ARK_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING;
    }

    if ((requestFlags & KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_MAPPINGS) != 0UL &&
        controlArea != NULL && !remoteUnsupported) {
        if (hasMappingLayout) {
            status = kswordArkSectionEnumerateMappings(
                controlArea,
                &dynState,
                response,
                entryCapacity);
            response->lastStatus = status;
            if (!NT_SUCCESS(status)) {
                response->queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED;
            }
        }
        else {
            response->lastStatus = STATUS_NOT_SUPPORTED;
            response->queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_PARTIAL;
        }
    }

    if (response->queryStatus == KSWORD_ARK_SECTION_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = ((response->fieldFlags & KSWORD_ARK_SECTION_FIELD_MAPPING_TRUNCATED) != 0UL) ?
            KSWORD_ARK_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL :
            KSWORD_ARK_SECTION_QUERY_STATUS_OK;
    }
    else if (response->queryStatus != KSWORD_ARK_SECTION_QUERY_STATUS_OK &&
        response->fieldFlags != 0UL) {
        response->queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_PARTIAL;
    }

    if (imageFileObject != NULL) {
        ObDereferenceObject(imageFileObject);
    }
    ObDereferenceObject(processObject);
    totalBytesWritten = KSWORD_ARK_SECTION_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY));
    *bytesWrittenOut = totalBytesWritten;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverQueryFileSectionMappings(
    _Out_writes_bytes_to_(outputBufferLength, *bytesWrittenOut) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query the current process mappings for the file's Data/Image ControlArea. Note: Input is the
    file path only; the driver opens the FILE_OBJECT and reads SectionObjectPointer internally.
    The ControlArea address is for diagnostic display only and is not accepted from R3.

Arguments:

    OutputBuffer - Output response packet.
    OutputBufferLength - Output buffer capacity.
    Request - Request packet containing the NT path, flags, and maximum mapping entry count.
    BytesWrittenOut - Actual number of bytes written received.

Return Value:

    STATUS_SUCCESS indicates the response header is valid; failure details are written to response->queryStatus.

--*/
{
    KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE* response = NULL;
    KswDynState dynState;
    PFILE_OBJECT fileObject = NULL;
    HANDLE fileHandle = NULL;
    PSECTION_OBJECT_POINTERS sectionPointers = NULL;
    PVOID dataControlArea = NULL;
    PVOID imageControlArea = NULL;
    ULONG requestFlags = 0UL;
    ULONG maxMappings = 0UL;
    size_t entryCapacity = 0U;
    size_t totalBytesWritten = 0U;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS mappingStatus = STATUS_SUCCESS;
    BOOLEAN hasMappingLayout = FALSE;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->pathLengthChars == 0U ||
        request->pathLengthChars >= KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS ||
        request->path[request->pathLengthChars] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&dynState, sizeof(dynState));
    kswordArkDynDataSnapshot(&dynState);

    response = (KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_SECTION_PROTOCOL_VERSION;
    response->entrySize = sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY);
    response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    response->dynDataCapabilityMask = dynState.capabilityMask;
    response->mmControlAreaListHeadOffset = kswordArkSectionNormalizeOffset(dynState.kernel.mmControlAreaListHead);
    response->mmControlAreaLockOffset = kswordArkSectionNormalizeOffset(dynState.kernel.mmControlAreaLock);
    hasMappingLayout =
        kswordArkSectionIsOffsetPresent(dynState.kernel.mmControlAreaListHead) &&
        kswordArkSectionIsOffsetPresent(dynState.kernel.mmControlAreaLock);

    requestFlags = (request->flags == 0UL) ? KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL : request->flags;
    maxMappings = request->maxMappings;
    if (maxMappings == 0UL) {
        maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT;
    }
    if (maxMappings > KSWORD_ARK_SECTION_MAPPING_LIMIT_MAX) {
        maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_MAX;
    }

    entryCapacity = (outputBufferLength - KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE) / sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY);
    if (entryCapacity > (size_t)maxMappings) {
        entryCapacity = (size_t)maxMappings;
    }

    status = kswordArkSectionOpenFileObjectByPath(
        request->path,
        request->pathLengthChars,
        &fileObject,
        &fileHandle);
    response->lastStatus = status;
    if (!NT_SUCCESS(status) || fileObject == NULL) {
        if (NT_SUCCESS(status)) {
            response->lastStatus = STATUS_UNSUCCESSFUL;
            if (fileHandle != NULL) {
                ZwClose(fileHandle);
            }
        }
        response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OPEN_FAILED;
        *bytesWrittenOut = KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    response->fileObjectAddress = (ULONG64)(ULONG_PTR)fileObject;
    response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_FILE_OBJECT_PRESENT;

    __try {
        sectionPointers = fileObject->SectionObjectPointer;
        response->sectionObjectPointersAddress = (ULONG64)(ULONG_PTR)sectionPointers;
        if (sectionPointers != NULL) {
            dataControlArea = sectionPointers->DataSectionObject;
            imageControlArea = sectionPointers->ImageSectionObject;
            response->dataSectionObjectAddress = (ULONG64)(ULONG_PTR)sectionPointers->DataSectionObject;
            response->imageSectionObjectAddress = (ULONG64)(ULONG_PTR)sectionPointers->ImageSectionObject;
            response->sharedCacheMapAddress = (ULONG64)(ULONG_PTR)sectionPointers->SharedCacheMap;
            response->dataControlAreaAddress = (ULONG64)(ULONG_PTR)dataControlArea;
            response->imageControlAreaAddress = (ULONG64)(ULONG_PTR)imageControlArea;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        response->lastStatus = status;
        response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OBJECT_FAILED;
    }

    if (response->queryStatus == KSWORD_ARK_FILE_SECTION_QUERY_STATUS_FILE_OBJECT_FAILED) {
        ObDereferenceObject(fileObject);
        ZwClose(fileHandle);
        *bytesWrittenOut = KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (sectionPointers == NULL) {
        response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_SECTION_POINTERS_MISSING;
        ObDereferenceObject(fileObject);
        ZwClose(fileHandle);
        *bytesWrittenOut = KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_SECTION_POINTERS_PRESENT;
    if (dataControlArea != NULL) {
        response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_DATA_CONTROL_AREA_PRESENT;
    }
    if (imageControlArea != NULL) {
        response->fieldFlags |= KSWORD_ARK_FILE_SECTION_FIELD_IMAGE_CONTROL_AREA_PRESENT;
    }

    if ((requestFlags & KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_DATA_IMAGE) != 0UL &&
        dataControlArea != NULL) {
        mappingStatus = hasMappingLayout ?
            kswordArkSectionEnumerateFileControlAreaMappings(
                dataControlArea,
                KSWORD_ARK_FILE_SECTION_KIND_DATA,
                &dynState,
                response,
                entryCapacity) :
            STATUS_NOT_SUPPORTED;
        response->lastStatus = mappingStatus;
        if (!NT_SUCCESS(mappingStatus)) {
            response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED;
        }
    }

    if ((requestFlags & KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_IMAGE) != 0UL &&
        imageControlArea != NULL) {
        mappingStatus = hasMappingLayout ?
            kswordArkSectionEnumerateFileControlAreaMappings(
                imageControlArea,
                KSWORD_ARK_FILE_SECTION_KIND_IMAGE,
                &dynState,
                response,
                entryCapacity) :
            STATUS_NOT_SUPPORTED;
        response->lastStatus = mappingStatus;
        if (!NT_SUCCESS(mappingStatus) &&
            response->queryStatus == KSWORD_ARK_FILE_SECTION_QUERY_STATUS_UNAVAILABLE) {
            response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_MAPPING_QUERY_FAILED;
        }
    }

    if (dataControlArea == NULL && imageControlArea == NULL) {
        response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_CONTROL_AREA_MISSING;
        response->lastStatus = STATUS_NOT_FOUND;
    }
    else if (!hasMappingLayout &&
        (requestFlags & (KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_DATA_IMAGE |
            KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_IMAGE)) != 0UL) {
        response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_PARTIAL;
        response->lastStatus = STATUS_NOT_SUPPORTED;
    }
    else if (response->queryStatus == KSWORD_ARK_FILE_SECTION_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = ((response->fieldFlags & KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_TRUNCATED) != 0UL) ?
            KSWORD_ARK_FILE_SECTION_QUERY_STATUS_BUFFER_TOO_SMALL :
            KSWORD_ARK_FILE_SECTION_QUERY_STATUS_OK;
    }
    else if (response->queryStatus != KSWORD_ARK_FILE_SECTION_QUERY_STATUS_OK &&
        (response->fieldFlags & KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_LIST_PRESENT) != 0UL) {
        response->queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_PARTIAL;
    }

    ObDereferenceObject(fileObject);
    ZwClose(fileHandle);
    totalBytesWritten = KSWORD_ARK_FILE_SECTION_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY));
    *bytesWrittenOut = totalBytesWritten;
    return STATUS_SUCCESS;
}

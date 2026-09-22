/*++

Module Name:

    file_actions.c

Abstract:

    This file contains kernel file operations, including deletion and
    read-only Phase-10 file information queries.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include "ark/ark_driver.h"
#include "ark/ark_file_irp.h"

#include <ntstrsafe.h>

#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000UL
#endif

#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000UL
#endif

#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001UL
#endif

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040UL
#endif

#ifndef ACCESS_SYSTEM_SECURITY
#define ACCESS_SYSTEM_SECURITY 0x01000000L
#endif

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010L
#endif

#ifndef STATUS_INVALID_SID
#define STATUS_INVALID_SID ((NTSTATUS)0xC0000078L)
#endif

#ifndef STATUS_INVALID_LABEL
#define STATUS_INVALID_LABEL ((NTSTATUS)0xC0000446L)
#endif

#ifndef SECURITY_MANDATORY_UNTRUSTED_RID
#define SECURITY_MANDATORY_UNTRUSTED_RID 0x00000000UL
#endif

#ifndef SECURITY_MANDATORY_LOW_RID
#define SECURITY_MANDATORY_LOW_RID 0x00001000UL
#endif

#ifndef SECURITY_MANDATORY_MEDIUM_RID
#define SECURITY_MANDATORY_MEDIUM_RID 0x00002000UL
#endif

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x100UL)
#endif

#ifndef SECURITY_MANDATORY_HIGH_RID
#define SECURITY_MANDATORY_HIGH_RID 0x00003000UL
#endif

#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID 0x00004000UL
#endif

#ifndef FILE_DISPOSITION_DELETE
#define FILE_DISPOSITION_DELETE 0x00000001UL
#endif

#ifndef FILE_DISPOSITION_POSIX_SEMANTICS
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002UL
#endif

#ifndef FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK
#define FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK 0x00000004UL
#endif

#ifndef FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010UL
#endif

// Use the documented value 64 for FileDispositionInformationEx to support
// older WDK headers where the enum constant may be missing.
#define KSWORD_FILE_DISPOSITION_INFORMATION_EX_CLASS_VALUE ((FILE_INFORMATION_CLASS)64)

typedef struct KswordFileDispositionInformationEx
{
    ULONG flags;
} KswordFileDispositionInformationEx, *PkswordFileDispositionInformationEx;

typedef enum KswordArkMmflushType
{
    kKswordArkMmFlushForDelete = 0,
    kKswordArkMmFlushForWrite = 1
} KswordArkMmflushType;

typedef PVOID
(NTAPI* KswordArkFileExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

NTKERNELAPI
NTSTATUS
ObQueryNameString(
    _In_ PVOID object,
    _Out_writes_bytes_opt_(length) POBJECT_NAME_INFORMATION objectNameInfo,
    _In_ ULONG length,
    _Out_ PULONG returnLength
    );

NTKERNELAPI
BOOLEAN
MmFlushImageSection(
    _In_ PSECTION_OBJECT_POINTERS sectionPointer,
    _In_ KswordArkMmflushType flushType
    );

static PVOID
KswordARKDriverFileAllocateNonPaged(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate temporary buffer for file query. Note: Prefer dynamically resolving ExAllocatePool2; fall back to
    ExAllocatePoolWithTag for legacy systems or WDK compatibility paths to prevent driver load failure due to missing imports.

Arguments:

    BufferBytes - Number of bytes to allocate.

Return Value:

    Non-paged pool pointer; returns NULL on failure.

--*/
{
    static volatile LONG allocatorResolved = 0;
    static KswordArkFileExAllocatePooL2Fn exAllocatePool2Fn = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&allocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        exAllocatePool2Fn = (KswordArkFileExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (exAllocatePool2Fn != NULL) {
        return exAllocatePool2Fn(POOL_FLAG_NON_PAGED, bufferBytes, 'fOsK');
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, 'fOsK');
#pragma warning(pop)
}

static VOID
kswordArkDriverCopyWideStringToFixedBuffer(
    _Out_writes_(destinationChars) PWSTR destination,
    _In_ USHORT destinationChars,
    _In_reads_opt_(sourceChars) PCWSTR source,
    _In_ USHORT sourceChars
    )
/*++

Routine Description:

    Copy the kernel UNICODE_STRING or request path to a fixed response buffer. Note: Always preserve the NUL
    terminator during copy; truncate if length is insufficient to prevent R3 fixed array out-of-bounds parsing.

Arguments:

    Destination - Fixed-width character array in the response packet.
    DestinationChars - Number of elements in Destination.
    Source - source wide-character pointer, may be null.
    SourceChars - The number of source characters, excluding the NUL terminator.

Return Value:

    None. This function has no return value.

--*/
{
    USHORT copyChars = 0U;

    if (destination == NULL || destinationChars == 0U) {
        return;
    }

    destination[0] = L'\0';
    if (source == NULL || sourceChars == 0U) {
        return;
    }

    copyChars = sourceChars;
    if (copyChars >= destinationChars) {
        copyChars = destinationChars - 1U;
    }

    RtlCopyMemory(destination, source, (SIZE_T)copyChars * sizeof(WCHAR));
    destination[copyChars] = L'\0';
}

static NTSTATUS
kswordArkDriverQueryFileObjectName(
    _In_ PVOID object,
    _Out_writes_(objectNameChars) PWSTR objectName,
    _In_ USHORT objectNameChars
    )
/*++

Routine Description:

    Query FILE_OBJECT object name. Note: Uses a two-step ObQueryNameString query: first to
    get the length, then to allocate NonPagedPoolNx and copy into a fixed response array.

Arguments:

    Object - Referenced kernel object, typically FILE_OBJECT or DEVICE_OBJECT.
    ObjectName - Array of object names in the response packet.
    ObjectNameChars: Length of the ObjectName array.

Return Value:

    STATUS_SUCCESS or an ObQueryNameString/memory allocation error.

--*/
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    ULONG requiredBytes = 0UL;
    ULONG allocationBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (objectName != NULL && objectNameChars > 0U) {
        objectName[0] = L'\0';
    }
    if (object == NULL || objectName == NULL || objectNameChars == 0U) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObQueryNameString(object, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH &&
        status != STATUS_BUFFER_OVERFLOW &&
        status != STATUS_BUFFER_TOO_SMALL &&
        !NT_SUCCESS(status)) {
        return status;
    }
    if (requiredBytes < sizeof(OBJECT_NAME_INFORMATION)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    allocationBytes = requiredBytes + sizeof(WCHAR);
    nameInfo = (POBJECT_NAME_INFORMATION)KswordARKDriverFileAllocateNonPaged(allocationBytes);
    if (nameInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(nameInfo, allocationBytes);
    status = ObQueryNameString(object, nameInfo, allocationBytes, &requiredBytes);
    if (NT_SUCCESS(status)) {
        const USHORT kSourceChars = (USHORT)(nameInfo->Name.Length / sizeof(WCHAR));
        kswordArkDriverCopyWideStringToFixedBuffer(
            objectName,
            objectNameChars,
            nameInfo->Name.Buffer,
            kSourceChars);
    }

    ExFreePoolWithTag(nameInfo, 'fOsK');
    return status;
}

static VOID
kswordArkDriverFillFileObjectAuditFields(
    _In_ PFILE_OBJECT fileObject,
    _Inout_ KSWORD_ARK_QUERY_FILE_INFO_RESPONSE* response
    )
/*++

Routine Description:

    Copy public FILE_OBJECT audit fields into the response. Note: This function only reads WDK public fields of FILE_OBJECT;
    all addresses are for diagnostic display only and must not be used as credentials for subsequent operations.

Arguments:

    FileObject: already referenced FILE_OBJECT.
    Response - Writable response packet.

Return Value:

    None. This function has no return value.

--*/
{
    if (fileObject == NULL || response == NULL) {
        return;
    }

    __try {
        response->deviceObjectAddress = (ULONG64)(ULONG_PTR)fileObject->DeviceObject;
        response->vpbAddress = (ULONG64)(ULONG_PTR)fileObject->Vpb;
        response->fsContextAddress = (ULONG64)(ULONG_PTR)fileObject->FsContext;
        response->fsContext2Address = (ULONG64)(ULONG_PTR)fileObject->FsContext2;
        response->deletePending = (fileObject->DeletePending != FALSE) ? 1UL : 0UL;
        response->readAccess = (fileObject->ReadAccess != FALSE) ? 1UL : 0UL;
        response->writeAccess = (fileObject->WriteAccess != FALSE) ? 1UL : 0UL;
        response->deleteAccess = (fileObject->DeleteAccess != FALSE) ? 1UL : 0UL;
        response->sharedRead = (fileObject->SharedRead != FALSE) ? 1UL : 0UL;
        response->sharedWrite = (fileObject->SharedWrite != FALSE) ? 1UL : 0UL;
        response->sharedDelete = (fileObject->SharedDelete != FALSE) ? 1UL : 0UL;
        response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_SHARE_ACCESS_PRESENT;
        if (fileObject->DeviceObject != NULL) {
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_DEVICE_OBJECT_PRESENT;
        }
        if (fileObject->Vpb != NULL) {
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_VPB_PRESENT;
        }
        if (fileObject->FsContext != NULL || fileObject->FsContext2 != NULL) {
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_FS_CONTEXT_PRESENT;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->objectStatus = GetExceptionCode();
        if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
            response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED;
        }
    }
}

static VOID
kswordArkDriverFillFileVpbAuditFields(
    _In_ PFILE_OBJECT fileObject,
    _Inout_ KSWORD_ARK_QUERY_FILE_INFO_RESPONSE* response
    )
/*++

Routine Description:

    Copy public VPB fields for the file object's mounted volume. Note: VPB may be absent
    or changing, so reads are placed in SEH; failure only degrades the current response.

Arguments:

    FileObject: already referenced FILE_OBJECT.
    Response - Writable response packet.

Return Value:

    None. This function has no return value.

--*/
{
    PVPB vpb = NULL;
    USHORT labelChars = 0U;

    if (fileObject == NULL || response == NULL) {
        return;
    }

    __try {
        vpb = fileObject->Vpb;
        if (vpb == NULL) {
            return;
        }
        response->vpbFlags = (ULONG)vpb->Flags;
        response->vpbSerialNumber = vpb->SerialNumber;
        labelChars = (USHORT)(vpb->VolumeLabelLength / sizeof(WCHAR));
        if (labelChars > RTL_NUMBER_OF(vpb->VolumeLabel)) {
            labelChars = (USHORT)RTL_NUMBER_OF(vpb->VolumeLabel);
        }
        if (labelChars >= KSWORD_ARK_FILE_INFO_VOLUME_LABEL_MAX_CHARS) {
            labelChars = KSWORD_ARK_FILE_INFO_VOLUME_LABEL_MAX_CHARS - 1U;
        }
        kswordArkDriverCopyWideStringToFixedBuffer(
            response->volumeLabel,
            KSWORD_ARK_FILE_INFO_VOLUME_LABEL_MAX_CHARS,
            vpb->VolumeLabel,
            labelChars);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        response->objectStatus = GetExceptionCode();
        if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
            response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED;
        }
    }
}

static NTSTATUS
kswordArkDriverOpenFileForQuery(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ ULONG flags,
    _Out_ HANDLE* fileHandleOut
    )
/*++

Routine Description:

    Open the target path for read-only file attribute queries. Note: Open permissions are limited to
    FILE_READ_ATTRIBUTES/SYNCHRONIZE, and READ/WRITE/DELETE sharing is allowed to prevent the query
    operation itself from altering resource ownership or blocking files held by other processes.

Arguments:

    PathText - NT path, typically \??\C:\...
    PathLengthChars: path character count, excluding NUL.
    Flags - KSWORD_ARK_QUERY_FILE_INFO_FLAG_*。
    FileHandleOut - receives a kernel handle; caller is responsible for ZwClose.

Return Value:

    NTSTATUS returned by ZwCreateFile.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG createOptions = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileHandleOut = NULL;
    if (pathText == NULL || pathLengthChars == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * The upper bound must be verified before constructing the UNICODE_STRING. targetPath.Buffer points directly to the
     * caller's buffer; if Length exceeds the actual buffer capacity, ObpCaptureObjectName will copy up to Length and read
     * into pages beyond allocation, causing a direct PAGE_FAULT_IN_NONPAGED_AREA. We do not assume the caller has already
     * validated this; instead, we ensure any length error degrades to STATUS_INVALID_PARAMETER rather than a bugcheck.
     */
    if (pathLengthChars >= KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)pathText;
    targetPath.Length = (USHORT)(pathLengthChars * sizeof(WCHAR));
    targetPath.MaximumLength = targetPath.Length + sizeof(WCHAR);

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    createOptions = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT;
    if ((flags & KSWORD_ARK_QUERY_FILE_INFO_FLAG_OPEN_REPARSE_POINT) != 0UL) {
        createOptions |= FILE_OPEN_REPARSE_POINT;
    }
    if ((flags & KSWORD_ARK_QUERY_FILE_INFO_FLAG_DIRECTORY) != 0UL) {
        createOptions |= FILE_DIRECTORY_FILE;
    }
    else {
        createOptions |= FILE_NON_DIRECTORY_FILE;
    }

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        fileHandleOut,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        createOptions,
        NULL,
        0U);

    return status;
}

typedef struct KswordArkFileLabelSdBuffer
{
    SECURITY_DESCRIPTOR_RELATIVE securityDescriptor;
    UCHAR aclBuffer[sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + SECURITY_MAX_SID_SIZE];
} KswordArkFileLabelSdBuffer, *PkswordArkFileLabelSdBuffer;

static BOOLEAN
kswordArkDriverIsSupportedFileMandatoryIntegrityRid(
    _In_ ULONG integrityRid
    )
/*++

Routine Description:

    Validate a mandatory-integrity RID before building a file-object label.
    Note: ProtectedProcess/SecureProcess RIDs represent token/process integrity semantics,
    not Mandatory Labels acceptable for file SACLs. Rejecting early avoids passing an invalid
    SID to ZwSetSecurityObject, which would only result in a later STATUS_INVALID_LABEL.

Arguments:

    IntegrityRid: The last RID in the S-1-16-* range.

Return Value:

    TRUE indicates the RID can be used for file/directory LABEL_SECURITY_INFORMATION; FALSE
    indicates the requester supplied an integrity level unsuitable for a file object.

--*/
{
    switch (integrityRid) {
    case SECURITY_MANDATORY_UNTRUSTED_RID:
    case SECURITY_MANDATORY_LOW_RID:
    case SECURITY_MANDATORY_MEDIUM_RID:
    case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
    case SECURITY_MANDATORY_HIGH_RID:
    case SECURITY_MANDATORY_SYSTEM_RID:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS
kswordArkDriverBuildFileMandatoryIntegritySid(
    _In_ ULONG integrityRid,
    _Out_writes_bytes_(SECURITY_MAX_SID_SIZE) PSID sidBuffer
    )
/*++

Routine Description:

    Build an S-1-16-* mandatory integrity SID for file-object label assignment.

Arguments:

    IntegrityRid - Mandatory label RID.
    SidBuffer - Caller-provided SECURITY_MAX_SID_SIZE storage.

Return Value:

    STATUS_SUCCESS or an RTL SID construction status.

--*/
{
    SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PULONG subAuthority = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (sidBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!kswordArkDriverIsSupportedFileMandatoryIntegrityRid(integrityRid)) {
        return STATUS_INVALID_LABEL;
    }

    RtlZeroMemory(sidBuffer, SECURITY_MAX_SID_SIZE);
    status = RtlInitializeSid(sidBuffer, &mandatoryLabelAuthority, 1);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    subAuthority = RtlSubAuthoritySid(sidBuffer, 0);
    if (subAuthority == NULL) {
        return STATUS_INVALID_SID;
    }
    *subAuthority = integrityRid;

    return RtlValidSid(sidBuffer) ? STATUS_SUCCESS : STATUS_INVALID_SID;
}

static NTSTATUS
kswordArkDriverBuildLabelSecurityDescriptor(
    _In_ ULONG integrityRid,
    _Out_ KswordArkFileLabelSdBuffer* descriptorBuffer
    )
/*++

Routine Description:

    Build a self-relative security descriptor containing only a SACL with one
    SYSTEM_MANDATORY_LABEL_ACE. Note: This descriptor is used exclusively for
    ZwSetSecurityObject(LABEL_SECURITY_INFORMATION) and does not carry Owner/DACL.

Arguments:

    IntegrityRid - Mandatory label RID.
    DescriptorBuffer - Writable descriptor+ACL storage.

Return Value:

    STATUS_SUCCESS or RTL ACL/SID construction failure.

--*/
{
    UCHAR sidBuffer[SECURITY_MAX_SID_SIZE] = { 0 };
    UCHAR aceBuffer[sizeof(SYSTEM_MANDATORY_LABEL_ACE) + SECURITY_MAX_SID_SIZE] = { 0 };
    PACL sacl = NULL;
    PSYSTEM_MANDATORY_LABEL_ACE mandatoryAce = (PSYSTEM_MANDATORY_LABEL_ACE)aceBuffer;
    ULONG sidLength = 0UL;
    ULONG aceLength = 0UL;
    ULONG aclLength = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (descriptorBuffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(descriptorBuffer, sizeof(*descriptorBuffer));
    status = kswordArkDriverBuildFileMandatoryIntegritySid(integrityRid, (PSID)sidBuffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    sidLength = RtlLengthSid((PSID)sidBuffer);
    aceLength = FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) + sidLength;
    aclLength = sizeof(ACL) + aceLength;
    if (aclLength > sizeof(descriptorBuffer->aclBuffer) || aceLength > 0xFFFFUL) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    sacl = (PACL)descriptorBuffer->aclBuffer;
    status = RtlCreateAcl(sacl, aclLength, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    mandatoryAce->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
    mandatoryAce->Header.AceFlags = 0;
    mandatoryAce->Header.AceSize = (USHORT)aceLength;
    mandatoryAce->Mask = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
    status = RtlCopySid(
        sidLength,
        (PSID)&mandatoryAce->SidStart,
        (PSID)sidBuffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlAddAce(sacl, ACL_REVISION, MAXULONG, mandatoryAce, aceLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * Build SECURITY_DESCRIPTOR_RELATIVE manually instead of depending on
     * RtlCreateSecurityDescriptorRelative, which is not present in every WDK
     * header set.  The descriptor carries only a SACL because
     * ZwSetSecurityObject(LABEL_SECURITY_INFORMATION) consumes just the
     * mandatory-label information for this operation.
     */
    descriptorBuffer->securityDescriptor.Revision = SECURITY_DESCRIPTOR_REVISION;
    descriptorBuffer->securityDescriptor.Sbz1 = 0;
    descriptorBuffer->securityDescriptor.Control =
        (SECURITY_DESCRIPTOR_CONTROL)(SE_SELF_RELATIVE | SE_SACL_PRESENT);
    descriptorBuffer->securityDescriptor.Owner = 0;
    descriptorBuffer->securityDescriptor.Group = 0;
    descriptorBuffer->securityDescriptor.Sacl =
        FIELD_OFFSET(KswordArkFileLabelSdBuffer, aclBuffer);
    descriptorBuffer->securityDescriptor.Dacl = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkDriverOpenFileForIntegritySet(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ ULONG flags,
    _Out_ HANDLE* fileHandleOut
    )
/*++

Routine Description:

    Open a file or directory for mandatory label writes.

Arguments:

    PathText - NT path.
    PathLengthChars - Character length excluding NUL.
    Flags - KSWORD_ARK_FILE_INTEGRITY_FLAG_*.
    FileHandleOut - Receives a kernel handle.

Return Value:

    ZwCreateFile status.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG createOptions = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileHandleOut = NULL;
    if (pathText == NULL || pathLengthChars == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    /*
     * Same as kswordArkDriverOpenFileForQuery: an excessively long Length causes the kernel to read pages beyond the
     * caller's buffer when capturing ObjectName. The upper bound is re-validated here, independent of handler checks.
     */
    if (pathLengthChars >= KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&targetPath, sizeof(targetPath));
    targetPath.Buffer = (PWCH)pathText;
    targetPath.Length = (USHORT)(pathLengthChars * sizeof(WCHAR));
    targetPath.MaximumLength = targetPath.Length + sizeof(WCHAR);

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    createOptions = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
    if ((flags & KSWORD_ARK_FILE_INTEGRITY_FLAG_DIRECTORY) != 0UL) {
        createOptions |= FILE_DIRECTORY_FILE;
    }
    else {
        createOptions |= FILE_NON_DIRECTORY_FILE;
    }

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        fileHandleOut,
        WRITE_OWNER | READ_CONTROL | ACCESS_SYSTEM_SECURITY | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        createOptions,
        NULL,
        0U);
    return status;
}

NTSTATUS
kswordArkDriverSetFileIntegrity(
    _In_ const KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST* request
    )
/*++

Routine Description:

    Set a file or directory mandatory integrity label using kernel security
    APIs. Note: This function only calls ZwCreateFile and
    ZwSetSecurityObject(LABEL_SECURITY_INFORMATION) and does not modify private file system structures.

Arguments:

    Request - Validated IOCTL request.

Return Value:

    NTSTATUS from open, descriptor construction, or ZwSetSecurityObject.

--*/
{
    HANDLE fileHandle = NULL;
    KswordArkFileLabelSdBuffer descriptorBuffer;
    NTSTATUS status = STATUS_SUCCESS;

    if (request == NULL ||
        request->pathLengthChars == 0U ||
        request->pathLengthChars >= KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS ||
        request->path[request->pathLengthChars] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkDriverBuildLabelSecurityDescriptor(
        request->integrityRid,
        &descriptorBuffer);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDriverOpenFileForIntegritySet(
        request->path,
        request->pathLengthChars,
        request->flags,
        &fileHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwSetSecurityObject(
        fileHandle,
        LABEL_SECURITY_INFORMATION,
        &descriptorBuffer.securityDescriptor);

    ZwClose(fileHandle);
    return status;
}

NTSTATUS
kswordArkDriverQueryFileInfo(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_FILE_INFO_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query basic file information. Note: This function is the R0 backend for Phase-10 file object information,
    performing only read-only attribute queries. Object addresses and SectionObjectPointer are used solely for
    UI diagnostic display; R3 is prohibited from passing these addresses as credentials in subsequent IOCTLs.

Arguments:

    OutputBuffer - Response packet buffer.
    OutputBufferLength - Length of the response packet buffer.
    Request - Request packet containing NT path and query flags.
    BytesWrittenOut - receives sizeof(KSWORD_ARK_QUERY_FILE_INFO_RESPONSE).

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; failure details are written to response->queryStatus.

--*/
{
    KSWORD_ARK_QUERY_FILE_INFO_RESPONSE* response = NULL;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    FILE_BASIC_INFORMATION basicInformation;
    FILE_STANDARD_INFORMATION standardInformation;
    IO_STATUS_BLOCK ioStatusBlock;
    PSECTION_OBJECT_POINTERS sectionPointers = NULL;
    ULONG requestFlags = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_FILE_INFO_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->pathLengthChars == 0U ||
        request->pathLengthChars >= KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS ||
        request->path[request->pathLengthChars] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    RtlZeroMemory(&basicInformation, sizeof(basicInformation));
    RtlZeroMemory(&standardInformation, sizeof(standardInformation));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));

    response = (KSWORD_ARK_QUERY_FILE_INFO_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_FILE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE;
    response->openStatus = STATUS_SUCCESS;
    response->basicStatus = STATUS_NOT_SUPPORTED;
    response->standardStatus = STATUS_NOT_SUPPORTED;
    response->objectStatus = STATUS_NOT_SUPPORTED;
    response->nameStatus = STATUS_NOT_SUPPORTED;
    response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_REQUEST_PATH_PRESENT;
    kswordArkDriverCopyWideStringToFixedBuffer(
        response->ntPath,
        KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS,
        request->path,
        request->pathLengthChars);

    requestFlags = request->flags;
    if (requestFlags == 0UL) {
        requestFlags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL;
    }

    status = kswordArkDriverOpenFileForQuery(
        request->path,
        request->pathLengthChars,
        requestFlags,
        &fileHandle);
    response->openStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_OPEN_FAILED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &basicInformation,
        (ULONG)sizeof(basicInformation),
        FileBasicInformation);
    response->basicStatus = status;
    if (NT_SUCCESS(status)) {
        response->fileAttributes = basicInformation.FileAttributes;
        response->creationTime = basicInformation.CreationTime.QuadPart;
        response->lastAccessTime = basicInformation.LastAccessTime.QuadPart;
        response->lastWriteTime = basicInformation.LastWriteTime.QuadPart;
        response->changeTime = basicInformation.ChangeTime.QuadPart;
        response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_BASIC_PRESENT;
        if ((basicInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0UL) {
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_DIRECTORY;
        }
    }
    else {
        response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_BASIC_FAILED;
    }

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &standardInformation,
        (ULONG)sizeof(standardInformation),
        FileStandardInformation);
    response->standardStatus = status;
    if (NT_SUCCESS(status)) {
        response->allocationSize = standardInformation.AllocationSize.QuadPart;
        response->endOfFile = standardInformation.EndOfFile.QuadPart;
        response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_STANDARD_PRESENT;
        if (standardInformation.Directory != FALSE) {
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_DIRECTORY;
        }
    }
    else if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_STANDARD_FAILED;
    }

    if ((requestFlags & (KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_OBJECT_NAME |
        KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_SECTION_POINTERS)) != 0UL) {
        status = ObReferenceObjectByHandle(
            fileHandle,
            0,
            *IoFileObjectType,
            KernelMode,
            (PVOID*)&fileObject,
            NULL);
        response->objectStatus = status;
        if (NT_SUCCESS(status)) {
            response->fileObjectAddress = (ULONG64)(ULONG_PTR)fileObject;
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_FILE_OBJECT_PRESENT;
            kswordArkDriverFillFileObjectAuditFields(fileObject, response);
            kswordArkDriverFillFileVpbAuditFields(fileObject, response);
            if (fileObject->DeviceObject != NULL) {
                (VOID)kswordArkDriverQueryFileObjectName(
                    fileObject->DeviceObject,
                    response->deviceName,
                    KSWORD_ARK_FILE_INFO_DEVICE_NAME_MAX_CHARS);
            }
        }
        else if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
            response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED;
        }
    }

    if (fileObject != NULL &&
        (requestFlags & KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_OBJECT_NAME) != 0UL) {
        status = kswordArkDriverQueryFileObjectName(
            fileObject,
            response->objectName,
            KSWORD_ARK_FILE_INFO_OBJECT_NAME_MAX_CHARS);
        response->nameStatus = status;
        if (NT_SUCCESS(status)) {
            response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_OBJECT_NAME_PRESENT;
        }
        else if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
            response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_NAME_FAILED;
        }
    }

    if (fileObject != NULL &&
        (requestFlags & KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_SECTION_POINTERS) != 0UL) {
        __try {
            sectionPointers = fileObject->SectionObjectPointer;
            response->sectionObjectPointersAddress = (ULONG64)(ULONG_PTR)sectionPointers;
            if (sectionPointers != NULL) {
                response->dataSectionObjectAddress = (ULONG64)(ULONG_PTR)sectionPointers->DataSectionObject;
                response->imageSectionObjectAddress = (ULONG64)(ULONG_PTR)sectionPointers->ImageSectionObject;
                response->sharedCacheMapAddress = (ULONG64)(ULONG_PTR)sectionPointers->SharedCacheMap;
                response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_SECTION_POINTERS_PRESENT;
                if (sectionPointers->DataSectionObject != NULL) {
                    response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_DATA_SECTION_PRESENT;
                }
                if (sectionPointers->ImageSectionObject != NULL) {
                    response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_IMAGE_SECTION_PRESENT;
                }
                if (sectionPointers->SharedCacheMap != NULL) {
                    response->fieldFlags |= KSWORD_ARK_FILE_INFO_FIELD_SHARED_CACHE_MAP_PRESENT;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            response->objectStatus = GetExceptionCode();
            if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
                response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED;
            }
        }
    }

    if (response->queryStatus == KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_OK;
    }
    else if (response->fieldFlags != 0UL &&
        response->queryStatus != KSWORD_ARK_FILE_INFO_STATUS_OK) {
        response->queryStatus = KSWORD_ARK_FILE_INFO_STATUS_PARTIAL;
    }

    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    ZwClose(fileHandle);
    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkDriverShouldRetryDeleteWithDispositionEx(
    _In_ NTSTATUS deleteStatus,
    _In_ BOOLEAN isDirectory
    )
/*++

Routine Description:

    Decide whether delete failure should trigger FileDispositionInformationEx
    fallback. This fallback is file-only and targets common "in-use" failures.

Arguments:

    deleteStatus - First delete attempt status.
    isDirectory - TRUE when target is directory.

Return Value:

    BOOLEAN

--*/
{
    if (isDirectory) {
        return FALSE;
    }

    switch (deleteStatus) {
    case STATUS_ACCESS_DENIED:
    case STATUS_SHARING_VIOLATION:
    case STATUS_CANNOT_DELETE:
    case STATUS_USER_MAPPED_FILE:
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOLEAN
kswordArkDriverIsDispositionExUnsupportedStatus(
    _In_ NTSTATUS dispositionStatus
    )
/*++

Routine Description:

    Check if FileDispositionInformationEx failed due to system or file system unsupported.
    Note: This failure does not imply the target file is undeletable; the caller must preserve the
    original state of FileDispositionInformation to avoid misdiagnosing the issue as a parameter error.

Arguments:

    dispositionStatus - return value of ZwSetInformationFile(FileDispositionInformationEx).

Return Value:

    TRUE indicates the Ex delete path should be treated as unavailable; FALSE indicates a genuine deletion failure.

--*/
{
    switch (dispositionStatus) {
    case STATUS_INVALID_INFO_CLASS:
    case STATUS_NOT_SUPPORTED:
    case STATUS_INVALID_PARAMETER:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS
kswordArkDriverSetFileDispositionExFlags(
    _In_ HANDLE fileHandle,
    _In_ ULONG dispositionFlags
    )
/*++

Routine Description:

    Mark the file for deletion using the caller-specified FileDispositionInformationEx flags.
    Note: Extract the thin wrapper around ZwSetInformationFile to allow the main deletion flow to first attempt POSIX
    unlink semantics, then fall back to the legacy force-image-check combination when compatibility requires it.

Arguments:

    fileHandle: File handle opened with DELETE access.
    dispositionFlags: combination of FILE_DISPOSITION_* flags.

Return Value:

    NTSTATUS returned by ZwSetInformationFile.

--*/
{
    KswordFileDispositionInformationEx dispositionInformationEx;
    IO_STATUS_BLOCK ioStatusBlock;

    RtlZeroMemory(&dispositionInformationEx, sizeof(dispositionInformationEx));
    dispositionInformationEx.flags = dispositionFlags;

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    return ZwSetInformationFile(
        fileHandle,
        &ioStatusBlock,
        &dispositionInformationEx,
        (ULONG)sizeof(dispositionInformationEx),
        KSWORD_FILE_DISPOSITION_INFORMATION_EX_CLASS_VALUE);
}

static NTSTATUS
kswordArkDriverFlushImageSectionForDelete(
    _In_ HANDLE fileHandle
    )
/*++

Routine Description:

    Ask the memory manager to flush the target file's image section before a
    delete retry. Note: Common failure codes for running EXE/DLLs are STATUS_CANNOT_DELETE; the
    root cause is typically that FileObject->SectionObjectPointer->ImageSectionObject still exists.
    MmFlushImageSection(MmFlushForDelete) is a public safety pre-check for deletion: if the image section
    has no active mappings, it cleans up and allows subsequent deletion; if the process is still running, it
    returns FALSE, and this function retains STATUS_CANNOT_DELETE, avoiding unsafe ControlArea manipulation.

Arguments:

    fileHandle - The handle to the opened target file.

Return Value:

    STATUS_SUCCESS indicates the image section is safe to clean up or does not require cleanup.
    STATUS_CANNOT_DELETE indicates active image sections remain; the caller should prompt to terminate the process or reboot before deletion.
    Other NTSTATUS values indicate failure to reference the FILE_OBJECT.

--*/
{
    PFILE_OBJECT fileObject = NULL;
    PSECTION_OBJECT_POINTERS sectionPointers = NULL;
    NTSTATUS status;
    BOOLEAN flushOk;

    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&fileObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    sectionPointers = fileObject->SectionObjectPointer;
    if (sectionPointers == NULL || sectionPointers->ImageSectionObject == NULL) {
        ObDereferenceObject(fileObject);
        return STATUS_SUCCESS;
    }

    flushOk = MmFlushImageSection(sectionPointers, kKswordArkMmFlushForDelete);
    ObDereferenceObject(fileObject);
    return flushOk ? STATUS_SUCCESS : STATUS_CANNOT_DELETE;
}

static NTSTATUS
kswordArkDriverDeleteFileWithDispositionEx(
    _In_ HANDLE fileHandle
    )
/*++

Routine Description:

    Retry file deletion with FileDispositionInformationEx. Prefer POSIX_SEMANTICS +
    IGNORE_READONLY_ATTRIBUTE without FORCE_IMAGE_SECTION_CHECK. If a file is still mapped by a
    process image/module section, this lets the kernel remove its directory entry using POSIX
    unlink semantics, rather than fail because we explicitly requested an image section check.
    Try the legacy force-image-check combination only when the preferred Ex combination is
    unsupported or its parameters are incompatible, to accommodate differences in older systems.

Arguments:

    fileHandle: File handle opened with DELETE access.

Return Value:

    NTSTATUS. Success indicates the target has been marked for deletion; if Ex is unsupported, the preferred attempt status
    is returned, and the upper layer will continue using the traditional deletion's firstDeleteStatus as the final diagnosis.

--*/
{
    const ULONG kPreferredDispositionFlags =
        FILE_DISPOSITION_DELETE
        | FILE_DISPOSITION_POSIX_SEMANTICS
        | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    const ULONG kLegacyDispositionFlags =
        kPreferredDispositionFlags
        | FILE_DISPOSITION_FORCE_IMAGE_SECTION_CHECK;
    NTSTATUS status;
    NTSTATUS legacyStatus;

    status = kswordArkDriverSetFileDispositionExFlags(fileHandle, kPreferredDispositionFlags);
    if (NT_SUCCESS(status)) {
        return status;
    }

    if (!kswordArkDriverIsDispositionExUnsupportedStatus(status)) {
        return status;
    }

    legacyStatus = kswordArkDriverSetFileDispositionExFlags(fileHandle, kLegacyDispositionFlags);
    if (NT_SUCCESS(legacyStatus)) {
        return legacyStatus;
    }

    if (!kswordArkDriverIsDispositionExUnsupportedStatus(legacyStatus)) {
        return legacyStatus;
    }

    return status;
}

static NTSTATUS
kswordArkDriverNormalizeReadOnlyAttribute(
    _In_ HANDLE fileHandle
    )
/*++

Routine Description:

    Clear FILE_ATTRIBUTE_READONLY before delete so driver delete can handle
    read-only files without an extra user-mode retry.

Arguments:

    fileHandle - Open file or directory handle.

Return Value:

    NTSTATUS

--*/
{
    FILE_BASIC_INFORMATION basicInformation;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    RtlZeroMemory(&basicInformation, sizeof(basicInformation));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));

    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &basicInformation,
        (ULONG)sizeof(basicInformation),
        FileBasicInformation);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if ((basicInformation.FileAttributes & FILE_ATTRIBUTE_READONLY) == 0U) {
        return STATUS_SUCCESS;
    }

    basicInformation.FileAttributes &= ~((ULONG)FILE_ATTRIBUTE_READONLY);
    if (basicInformation.FileAttributes == 0U) {
        basicInformation.FileAttributes = FILE_ATTRIBUTE_NORMAL;
    }

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    return ZwSetInformationFile(
        fileHandle,
        &ioStatusBlock,
        &basicInformation,
        (ULONG)sizeof(basicInformation),
        FileBasicInformation);
}

static NTSTATUS
kswordArkDriverDeletePathByIrp(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ BOOLEAN isDirectory
    )
/*++

Routine Description:

    Submit IRP_MJ_SET_INFORMATION / FileDispositionInformation using the existing generic IRP engine. The
    target is fixed at the top of the RELATED stack, so CREATE, the target request, and CLEANUP/CLOSE all
    traverse the full file system stack; this backend will not fall back to ZwSetInformationFile.

Arguments:

    pathText/pathLengthChars: Validated NT path.
    isDirectory - TRUE indicates directory semantics are required during the CREATE phase.

Return Value:

    First failure NTSTATUS for CREATE, target IRP, or teardown phase; returns STATUS_SUCCESS upon completion.

--*/
{
    KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST* request = NULL;
    KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE* response = NULL;
    FILE_DISPOSITION_INFORMATION dispositionInformation;
    const SIZE_T kRequestBytes = KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE;
    const SIZE_T kResponseBytes = KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE;
    size_t bytesWritten = 0U;
    NTSTATUS transportStatus;
    NTSTATUS resultStatus = STATUS_UNSUCCESSFUL;

    if (pathText == NULL || pathLengthChars == 0U ||
        pathLengthChars >= KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    request = (KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST*)
        KswordARKDriverFileAllocateNonPaged(kRequestBytes);
    response = (KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE*)
        KswordARKDriverFileAllocateNonPaged(kResponseBytes);
    if (request == NULL || response == NULL) {
        resultStatus = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(request, kRequestBytes);
    request->version = KSWORD_ARK_FILE_IRP_PROTOCOL_VERSION;
    request->size = KSWORD_ARK_FILE_IRP_SUBMIT_REQUEST_HEADER_SIZE;
    request->flags =
        KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED |
        KSWORD_ARK_FILE_IRP_FLAG_OPEN_REPARSE_POINT;
    if (isDirectory) {
        request->flags |= KSWORD_ARK_FILE_IRP_FLAG_DIRECTORY_INTENT;
    }
    request->confirmationToken = KSWORD_ARK_FILE_IRP_CONFIRMATION_TOKEN;
    request->majorFunction = IRP_MJ_SET_INFORMATION;
    request->targetLayer = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
    request->timeoutMs = KSWORD_ARK_FILE_IRP_DEFAULT_TIMEOUT_MS;
    request->desiredAccess = DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    request->shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    request->createDisposition = FILE_OPEN;
    request->createOptions = isDirectory ? 0UL : FILE_NON_DIRECTORY_FILE;
    request->fileAttributes = FILE_ATTRIBUTE_NORMAL;
    request->informationClass = FileDispositionInformation;
    request->inputBytes = (ULONG)sizeof(dispositionInformation);
    request->pathLengthChars = pathLengthChars;
    RtlCopyMemory(
        request->path,
        pathText,
        (SIZE_T)pathLengthChars * sizeof(WCHAR));
    request->path[pathLengthChars] = L'\0';

    RtlZeroMemory(&dispositionInformation, sizeof(dispositionInformation));
    dispositionInformation.DeleteFile = TRUE;
    transportStatus = kswordArkDriverSubmitFileIrp(
        response,
        kResponseBytes,
        request,
        &dispositionInformation,
        (ULONG)sizeof(dispositionInformation),
        &bytesWritten);
    if (!NT_SUCCESS(transportStatus)) {
        resultStatus = transportStatus;
        goto Exit;
    }
    if (bytesWritten < KSWORD_ARK_FILE_IRP_SUBMIT_RESPONSE_HEADER_SIZE) {
        resultStatus = STATUS_INFO_LENGTH_MISMATCH;
        goto Exit;
    }
    if (!NT_SUCCESS(response->createStatus)) {
        resultStatus = response->createStatus;
        goto Exit;
    }
    if ((response->stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OPERATION) == 0UL) {
        resultStatus = response->operationStatus;
        goto Exit;
    }
    if (!NT_SUCCESS(response->operationStatus)) {
        resultStatus = response->operationStatus;
        goto Exit;
    }
    if ((response->stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLEANUP) != 0UL &&
        !NT_SUCCESS(response->cleanupStatus)) {
        resultStatus = response->cleanupStatus;
        goto Exit;
    }
    if ((response->stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLOSE) != 0UL &&
        !NT_SUCCESS(response->closeStatus)) {
        resultStatus = response->closeStatus;
        goto Exit;
    }

    resultStatus = STATUS_SUCCESS;

Exit:
    if (response != NULL) {
        ExFreePoolWithTag(response, 'fOsK');
    }
    if (request != NULL) {
        ExFreePoolWithTag(request, 'fOsK');
    }
    return resultStatus;
}

NTSTATUS
kswordArkDriverDeletePath(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ BOOLEAN isDirectory
    )
{
    return kswordArkDriverDeletePathWithFlags(
        pathText,
        pathLengthChars,
        isDirectory,
        0UL);
}

NTSTATUS
kswordArkDriverDeletePathWithFlags(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ BOOLEAN isDirectory,
    _In_ ULONG deleteFlags
    )
/*++

Routine Description:

    Select the backend for deleting a single NT path (Zw*, custom IRP, or POSIX unlink) based on deleteFlags.
    The directory must be empty; recursive post-order scheduling is handled uniformly by file_delete_recursive.c.

Arguments:

    pathText - Target NT path, for example \??\C:\Temp\a.txt.
    pathLengthChars - Character length excluding trailing null.
    isDirectory - TRUE when target should be opened as directory.
    deleteFlags: Mutually exclusive backend flags within KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK.

Return Value:

    NTSTATUS

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;
    FILE_DISPOSITION_INFORMATION dispositionInformation;
    ACCESS_MASK desiredAccess;
    ULONG createOptions;
    NTSTATUS status;
    NTSTATUS firstDeleteStatus = STATUS_SUCCESS;

    if (pathText == NULL || pathLengthChars == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((deleteFlags & (~KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK)) != 0UL ||
        (deleteFlags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK) ==
            KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_MASK) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((deleteFlags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_IRP) != 0UL) {
        return kswordArkDriverDeletePathByIrp(pathText, pathLengthChars, isDirectory);
    }

    RtlInitUnicodeString(&targetPath, pathText);
    if (targetPath.Length == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    if (targetPath.Length != (USHORT)(pathLengthChars * sizeof(WCHAR))) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &targetPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    desiredAccess = DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    createOptions = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_OPEN_REPARSE_POINT;
    if (isDirectory) {
        createOptions |= FILE_DIRECTORY_FILE;
    }
    else {
        createOptions |= FILE_NON_DIRECTORY_FILE;
    }

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        &fileHandle,
        desiredAccess,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        createOptions,
        NULL,
        0U);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = kswordArkDriverNormalizeReadOnlyAttribute(fileHandle);
    if (!NT_SUCCESS(status) && status != STATUS_INVALID_PARAMETER) {
        ZwClose(fileHandle);
        return status;
    }

    if ((deleteFlags & KSWORD_ARK_DELETE_PATH_FLAG_BACKEND_POSIX) != 0UL) {
        status = kswordArkDriverDeleteFileWithDispositionEx(fileHandle);
        if (!NT_SUCCESS(status) &&
            (status == STATUS_CANNOT_DELETE || status == STATUS_USER_MAPPED_FILE)) {
            const NTSTATUS kFlushStatus = kswordArkDriverFlushImageSectionForDelete(fileHandle);
            if (NT_SUCCESS(kFlushStatus)) {
                status = kswordArkDriverDeleteFileWithDispositionEx(fileHandle);
            }
            else if (status == STATUS_CANNOT_DELETE) {
                status = kFlushStatus;
            }
        }
        ZwClose(fileHandle);
        return status;
    }

    dispositionInformation.DeleteFile = TRUE;
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwSetInformationFile(
        fileHandle,
        &ioStatusBlock,
        &dispositionInformation,
        (ULONG)sizeof(dispositionInformation),
        FileDispositionInformation);
    firstDeleteStatus = status;

    if (!NT_SUCCESS(status) &&
        kswordArkDriverShouldRetryDeleteWithDispositionEx(status, isDirectory)) {
        NTSTATUS fallbackStatus = kswordArkDriverDeleteFileWithDispositionEx(fileHandle);
        if (!NT_SUCCESS(fallbackStatus) &&
            (fallbackStatus == STATUS_CANNOT_DELETE || fallbackStatus == STATUS_USER_MAPPED_FILE)) {
            const NTSTATUS kFlushStatus = kswordArkDriverFlushImageSectionForDelete(fileHandle);
            if (NT_SUCCESS(kFlushStatus)) {
                fallbackStatus = kswordArkDriverDeleteFileWithDispositionEx(fileHandle);
            }
            else if (fallbackStatus == STATUS_CANNOT_DELETE) {
                fallbackStatus = kFlushStatus;
            }
        }
        if (NT_SUCCESS(fallbackStatus)) {
            status = fallbackStatus;
        }
        else if (fallbackStatus != STATUS_INVALID_INFO_CLASS &&
            fallbackStatus != STATUS_NOT_SUPPORTED &&
            fallbackStatus != STATUS_INVALID_PARAMETER) {
            // Return explicit fallback failure; keep first status for unsupported cases.
            status = fallbackStatus;
        }
        else {
            status = firstDeleteStatus;
        }
    }

    ZwClose(fileHandle);
    return status;
}

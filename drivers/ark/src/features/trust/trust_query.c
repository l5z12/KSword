/*++

Module Name:

    trust_query.c

Abstract:

    Phase-14 kernel Code Integrity and cached image trust diagnostics.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSWORD_ARK_TRUST_SYSTEM_CODEINTEGRITY_INFORMATION 103UL
#define KSWORD_ARK_TRUST_SYSTEM_SECUREBOOT_INFORMATION 145UL
#define KSWORD_ARK_TRUST_POOL_TAG 'tIsK'
#define KSWORD_ARK_TRUST_SYSTEM_MODULE_INFORMATION_CLASS 11UL
#define KSWORD_ARK_SIGNATURE_READ_CHUNK_BYTES 4096UL
#define KSWORD_ARK_SIGNATURE_MAX_ENUMERATED_ENTRIES 4096UL
#define KSWORD_ARK_SIGNATURE_FNV1A64_OFFSET 14695981039346656037ULL
#define KSWORD_ARK_SIGNATURE_FNV1A64_PRIME 1099511628211ULL

#ifndef STATUS_INVALID_IMAGE_NOT_MZ
#define STATUS_INVALID_IMAGE_NOT_MZ ((NTSTATUS)0xC000012FUL)
#endif

typedef struct KswordArkSignatureWinCertificateHeader
{
    ULONG length;
    USHORT revision;
    USHORT certificateType;
} KswordArkSignatureWinCertificateHeader;

typedef struct KswordArkTrustSystemModuleEntry
{
    HANDLE section;
    PVOID mappedBase;
    PVOID imageBase;
    ULONG imageSize;
    ULONG flags;
    USHORT loadOrderIndex;
    USHORT initOrderIndex;
    USHORT loadCount;
    USHORT offsetToFileName;
    UCHAR fullPathName[256];
} KswordArkTrustSystemModuleEntry;

typedef struct KswordArkTrustSystemModuleInformation
{
    ULONG numberOfModules;
    KswordArkTrustSystemModuleEntry modules[1];
} KswordArkTrustSystemModuleInformation;

static const UCHAR kGKswordArkNestedSignatureOidDer[] = {
    0x06U, 0x0AU, 0x2BU, 0x06U, 0x01U, 0x04U,
    0x01U, 0x82U, 0x37U, 0x02U, 0x04U, 0x01U
};


typedef struct KswordArkSystemCodeintegrityInformation
{
    ULONG length;
    ULONG codeIntegrityOptions;
} KswordArkSystemCodeintegrityInformation;

typedef struct KswordArkSystemSecurebootInformation
{
    BOOLEAN secureBootEnabled;
    BOOLEAN secureBootCapable;
} KswordArkSystemSecurebootInformation;

typedef UCHAR KswordArkSeSigningLevel;
typedef KswordArkSeSigningLevel* PkswordArkSeSigningLevel;

typedef PVOID
(NTAPI* KswordArkTrustExAllocatePooL2Fn)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
    );

typedef NTSTATUS
(NTAPI* KswordArkSeGetCachedSigningLevelFn)(
    _In_ PFILE_OBJECT fileObject,
    _Out_ PULONG flags,
    _Out_ PkswordArkSeSigningLevel signingLevel,
    _Out_writes_bytes_to_opt_(*thumbprintSize, *thumbprintSize) PUCHAR thumbprint,
    _Inout_opt_ PULONG thumbprintSize,
    _Out_opt_ PULONG thumbprintAlgorithm
    );

typedef NTSTATUS
(NTAPI* KswordArkZwQuerySystemInformationFn)(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

static volatile LONG gKswordArkTrustAllocatorResolved = 0;
static KswordArkTrustExAllocatePooL2Fn gKswordArkTrustExAllocatePool2 = NULL;
static volatile LONG gKswordArkTrustSeSigningResolved = 0;
static KswordArkSeGetCachedSigningLevelFn gKswordArkTrustSeGetCachedSigningLevel = NULL;
static volatile LONG gKswordArkTrustCiValidateResolved = 0;
static BOOLEAN gKswordArkTrustCiValidatePresent = FALSE;
static KswordArkSystemCodeintegrityInformation gKswordArkTrustCodeIntegrity;
static KswordArkSystemSecurebootInformation gKswordArkTrustSecureBoot;
static NTSTATUS gKswordArkTrustCodeIntegrityStatus = STATUS_NOT_SUPPORTED;
static NTSTATUS gKswordArkTrustSecureBootStatus = STATUS_NOT_SUPPORTED;

static PVOID
kswordArkTrustAllocateNonPaged(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate temporary buffer for trust query. Note: Prefer ExAllocatePool2, with fallback to ExAllocatePoolWithTag
    on older systems to ensure the driver import table does not depend on new kernel exports.

Arguments:

    BufferBytes - The number of bytes requested for allocation.

Return Value:

    Returns a non-paged pool pointer; returns NULL on failure.

--*/
{
    if (bufferBytes == 0U) {
        return NULL;
    }

    if (InterlockedCompareExchange(&gKswordArkTrustAllocatorResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        gKswordArkTrustExAllocatePool2 =
            (KswordArkTrustExAllocatePooL2Fn)MmGetSystemRoutineAddress(&routineName);
    }

    if (gKswordArkTrustExAllocatePool2 != NULL) {
        return gKswordArkTrustExAllocatePool2(POOL_FLAG_NON_PAGED, bufferBytes, KSWORD_ARK_TRUST_POOL_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSWORD_ARK_TRUST_POOL_TAG);
#pragma warning(pop)
}

static VOID
kswordArkTrustCopyWideStringToFixedBuffer(
    _Out_writes_(destinationChars) PWSTR destination,
    _In_ USHORT destinationChars,
    _In_reads_opt_(sourceChars) PCWSTR source,
    _In_ USHORT sourceChars
    )
/*++

Routine Description:

    Copy the request path to the fixed response array. Note: The protocol fixed array is always
    NUL-terminated; R3 can directly construct std::wstring without scanning uninitialized memory.

Arguments:

    Destination - Response wide-character array.
    DestinationChars: Response array capacity.
    Source - input wide-character array, may be null.
    SourceChars: Number of input characters, excluding NUL.

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

static KswordArkSeGetCachedSigningLevelFn
kswordArkTrustResolveSeGetCachedSigningLevel(
    VOID
    )
/*++

Routine Description:

    Dynamically resolve SeGetCachedSigningLevel. Note: Availability of exports varies across
    different WDKs and system versions, so it is not included in the static import table.

Arguments:

    None.

Return Value:

    Returns a function pointer; returns NULL if unavailable.

--*/
{
    if (InterlockedCompareExchange(&gKswordArkTrustSeSigningResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"SeGetCachedSigningLevel");
        gKswordArkTrustSeGetCachedSigningLevel =
            (KswordArkSeGetCachedSigningLevelFn)MmGetSystemRoutineAddress(&routineName);
    }

    return gKswordArkTrustSeGetCachedSigningLevel;
}

static BOOLEAN
kswordArkTrustResolveCiValidateExportPresence(
    VOID
    )
/*++

Routine Description:

    Probe whether CI validation exports exist. Note: Phase-14 does not directly call CiValidateFileObject;
    it only exposes availability to avoid hardcoding private CI policy structures into the protocol.

Arguments:

    None.

Return Value:

    TRUE indicates that ci.dll/ci.sys currently exports CiValidateFileObject.

--*/
{
    if (InterlockedCompareExchange(&gKswordArkTrustCiValidateResolved, 1L, 0L) == 0L) {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"CiValidateFileObject");
        gKswordArkTrustCiValidatePresent =
            (MmGetSystemRoutineAddress(&routineName) != NULL) ? TRUE : FALSE;
    }

    return gKswordArkTrustCiValidatePresent;
}

static NTSTATUS
kswordArkTrustOpenFileForTrustQuery(
    _In_reads_(pathLengthChars) PCWSTR pathText,
    _In_ USHORT pathLengthChars,
    _In_ ULONG flags,
    _In_ BOOLEAN readFileData,
    _Out_ HANDLE* fileHandleOut
    )
/*++

Routine Description:

    Open the target file for trust query. Note: Only read attributes and obtain the FILE_OBJECT; do
    not request write access, do not modify file content, and do not trigger delete/lock-fix logic.

Arguments:

    PathText - NT path, e.g., \??\C:\Windows\System32\ntoskrnl.exe.
    PathLengthChars: path character count, excluding NUL.
    Flags - KSWORD_ARK_TRUST_QUERY_FLAG_*。
    ReadFileData: when TRUE, also request FILE_READ_DATA for direct certificate table reading.
    FileHandleOut - receives a kernel handle; caller is responsible for ZwClose.

Return Value:

    NTSTATUS returned by ZwCreateFile.

--*/
{
    UNICODE_STRING targetPath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    ULONG createOptions = 0UL;
    ULONG shareAccess = FILE_SHARE_READ | FILE_SHARE_DELETE;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileHandleOut = NULL;
    if (pathText == NULL || pathLengthChars == 0U) {
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

    createOptions = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_NON_DIRECTORY_FILE;
    if ((flags & KSWORD_ARK_TRUST_QUERY_FLAG_OPEN_REPARSE_POINT) != 0UL) {
        createOptions |= FILE_OPEN_REPARSE_POINT;
    }
    if (!readFileData) {
        shareAccess |= FILE_SHARE_WRITE;
    }

    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwCreateFile(
        fileHandleOut,
        (readFileData ? FILE_READ_DATA : 0UL) |
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        shareAccess,
        FILE_OPEN,
        createOptions,
        NULL,
        0U);

    return status;
}

static NTSTATUS
kswordArkTrustReferenceFileObject(
    _In_ HANDLE fileHandle,
    _Outptr_ PFILE_OBJECT* fileObjectOut
    )
/*++

Routine Description:

    Obtain a reference to FILE_OBJECT from the kernel handle. Note: Subsequent signing level queries require
    FILE_OBJECT; after successfully obtaining the reference, the caller must call ObDereferenceObject.

Arguments:

    FileHandle: Kernel handle returned by ZwCreateFile.
    FileObjectOut: Receives a FILE_OBJECT pointer.

Return Value:

    STATUS_SUCCESS or the return value of ObReferenceObjectByHandle.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (fileObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileObjectOut = NULL;
    if (fileHandle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObReferenceObjectByHandle(
        fileHandle,
        0,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)fileObjectOut,
        NULL);

    return status;
}

static NTSTATUS
kswordArkTrustQueryCachedSigningLevel(
    _In_ PFILE_OBJECT fileObject,
    _Inout_ KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE* response
    )
/*++

Routine Description:

    Query the kernel cache signing level of the file object. Note: This value represents the kernel CI perspective, not the complete
    Authenticode certificate chain result; the R3 page must be displayed in a separate column from the WinVerifyTrust result.

Arguments:

    FileObject: already referenced FILE_OBJECT.
    Response - response packet containing signing level, flags, and thumbprint.

Return Value:

    STATUS_SUCCESS or the status from the underlying SeGetCachedSigningLevel.

--*/
{
    KswordArkSeGetCachedSigningLevelFn seGetCachedSigningLevel = NULL;
    KswordArkSeSigningLevel signingLevel = KSWORD_ARK_SIGNING_LEVEL_UNCHECKED;
    UCHAR thumbprint[KSWORD_ARK_TRUST_THUMBPRINT_MAX_BYTES] = { 0 };
    ULONG thumbprintSize = sizeof(thumbprint);
    ULONG thumbprintAlgorithm = 0UL;
    ULONG signingFlags = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileObject == NULL || response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    seGetCachedSigningLevel = kswordArkTrustResolveSeGetCachedSigningLevel();
    if (seGetCachedSigningLevel == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    status = seGetCachedSigningLevel(
        fileObject,
        &signingFlags,
        &signingLevel,
        thumbprint,
        &thumbprintSize,
        &thumbprintAlgorithm);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    response->signingLevel = signingLevel;
    response->signingLevelFlags = signingFlags;
    response->thumbprintAlgorithm = thumbprintAlgorithm;
    response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_SIGNING_LEVEL_PRESENT;
    if (thumbprintSize > sizeof(response->thumbprint)) {
        thumbprintSize = sizeof(response->thumbprint);
    }
    response->thumbprintSize = thumbprintSize;
    if (thumbprintSize > 0UL) {
        RtlCopyMemory(response->thumbprint, thumbprint, thumbprintSize);
        response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_THUMBPRINT_PRESENT;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkTrustQueryFileSize(
    _In_ HANDLE fileHandle,
    _Out_ ULONGLONG* fileSizeOut
    )
{
    FILE_STANDARD_INFORMATION standardInformation;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileHandle == NULL || fileSizeOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *fileSizeOut = 0ULL;
    RtlZeroMemory(&standardInformation, sizeof(standardInformation));
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatusBlock,
        &standardInformation,
        sizeof(standardInformation),
        FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (standardInformation.EndOfFile.QuadPart < 0) {
        return STATUS_FILE_CORRUPT_ERROR;
    }
    *fileSizeOut = (ULONGLONG)standardInformation.EndOfFile.QuadPart;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkTrustReadFileAt(
    _In_ HANDLE fileHandle,
    _In_ ULONGLONG fileOffset,
    _Out_writes_bytes_(bufferBytes) PVOID buffer,
    _In_ ULONG bufferBytes
    )
{
    LARGE_INTEGER byteOffset;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileHandle == NULL || buffer == NULL || bufferBytes == 0UL ||
        fileOffset > 0x7FFFFFFFFFFFFFFFULL) {
        return STATUS_INVALID_PARAMETER;
    }
    byteOffset.QuadPart = (LONGLONG)fileOffset;
    RtlZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        buffer,
        bufferBytes,
        &byteOffset,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (ioStatusBlock.Information != bufferBytes) {
        return STATUS_END_OF_FILE;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkTrustIsKnownCertificateType(
    _In_ USHORT certificateType
    )
{
    return certificateType == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_TYPE_X509 ||
        certificateType == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_TYPE_PKCS_SIGNED_DATA ||
        certificateType == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_TYPE_RESERVED_1 ||
        certificateType == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_TYPE_TS_STACK_SIGNED ||
        certificateType == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_TYPE_PKCS1_SIGN;
}

static NTSTATUS
kswordArkTrustScanCertificateContent(
    _In_ HANDLE fileHandle,
    _In_ ULONGLONG contentOffset,
    _In_ ULONG contentBytes,
    _Out_writes_bytes_(scratchBytes) PUCHAR scratch,
    _In_ ULONG scratchBytes,
    _Out_ ULONG* nestedSignatureCountOut,
    _Out_ ULONGLONG* contentHashOut,
    _Out_ ULONG* bytesScannedOut,
    _Out_ UCHAR* firstByteOut
    )
{
    const ULONG kPatternBytes = (ULONG)sizeof(kGKswordArkNestedSignatureOidDer);
    ULONG remainingBytes = contentBytes;
    ULONG consumedBytes = 0UL;
    ULONG carryBytes = 0UL;
    ULONG nestedCount = 0UL;
    ULONGLONG hashValue = KSWORD_ARK_SIGNATURE_FNV1A64_OFFSET;
    NTSTATUS status = STATUS_SUCCESS;

    if (fileHandle == NULL || scratch == NULL ||
        scratchBytes < (KSWORD_ARK_SIGNATURE_READ_CHUNK_BYTES + kPatternBytes) ||
        nestedSignatureCountOut == NULL || contentHashOut == NULL ||
        bytesScannedOut == NULL || firstByteOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *nestedSignatureCountOut = 0UL;
    *contentHashOut = hashValue;
    *bytesScannedOut = 0UL;
    *firstByteOut = 0U;

    while (remainingBytes != 0UL) {
        ULONG readBytes = remainingBytes;
        ULONG totalBytes = 0UL;
        ULONG index = 0UL;
        if (readBytes > KSWORD_ARK_SIGNATURE_READ_CHUNK_BYTES) {
            readBytes = KSWORD_ARK_SIGNATURE_READ_CHUNK_BYTES;
        }
        status = kswordArkTrustReadFileAt(
            fileHandle,
            contentOffset + consumedBytes,
            scratch + carryBytes,
            readBytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (consumedBytes == 0UL && readBytes != 0UL) {
            *firstByteOut = scratch[carryBytes];
        }
        for (index = 0UL; index < readBytes; ++index) {
            hashValue ^= scratch[carryBytes + index];
            hashValue *= KSWORD_ARK_SIGNATURE_FNV1A64_PRIME;
        }
        totalBytes = carryBytes + readBytes;
        if (totalBytes >= kPatternBytes) {
            for (index = 0UL; index <= (totalBytes - kPatternBytes); ++index) {
                if (RtlCompareMemory(
                    scratch + index,
                    kGKswordArkNestedSignatureOidDer,
                    kPatternBytes) == kPatternBytes) {
                    nestedCount += 1UL;
                }
            }
        }
        carryBytes = (totalBytes < (kPatternBytes - 1UL)) ? totalBytes : (kPatternBytes - 1UL);
        if (carryBytes != 0UL) {
            RtlMoveMemory(scratch, scratch + totalBytes - carryBytes, carryBytes);
        }
        consumedBytes += readBytes;
        remainingBytes -= readBytes;
    }

    *nestedSignatureCountOut = nestedCount;
    *contentHashOut = hashValue;
    *bytesScannedOut = consumedBytes;
    return STATUS_SUCCESS;
}

static BOOLEAN
kswordArkTrustCertificatePaddingNonzero(
    _In_ HANDLE fileHandle,
    _In_ ULONGLONG paddingOffset,
    _In_ ULONG paddingBytes,
    _Out_ NTSTATUS* readStatusOut
    )
{
    UCHAR padding[8] = { 0 };
    ULONG index = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (readStatusOut == NULL) {
        return FALSE;
    }
    *readStatusOut = STATUS_SUCCESS;
    if (paddingBytes == 0UL) {
        return FALSE;
    }
    if (paddingBytes > sizeof(padding)) {
        *readStatusOut = STATUS_INVALID_PARAMETER;
        return FALSE;
    }
    status = kswordArkTrustReadFileAt(fileHandle, paddingOffset, padding, paddingBytes);
    *readStatusOut = status;
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    for (index = 0UL; index < paddingBytes; ++index) {
        if (padding[index] != 0U) {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS
kswordArkTrustEnumerateCertificateTable(
    _In_ HANDLE fileHandle,
    _Inout_ KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE* response
    )
{
    PUCHAR scratch = NULL;
    ULONGLONG cursor = response->certificateTableOffset;
    ULONGLONG remaining = response->certificateTableSize;
    ULONG totalScannedBytes = 0UL;
    NTSTATUS resultStatus = STATUS_SUCCESS;

    scratch = (PUCHAR)kswordArkTrustAllocateNonPaged(
        KSWORD_ARK_SIGNATURE_READ_CHUNK_BYTES + sizeof(kGKswordArkNestedSignatureOidDer));
    if (scratch == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (remaining != 0ULL) {
        KswordArkSignatureWinCertificateHeader certificateHeader;
        KSWORD_ARK_IMAGE_SIGNATURE_CERTIFICATE_ENTRY localEntry;
        KSWORD_ARK_IMAGE_SIGNATURE_CERTIFICATE_ENTRY* entry = &localEntry;
        ULONGLONG alignedLength = 0ULL;
        ULONG contentBytes = 0UL;
        ULONG scanBytes = 0UL;
        ULONG scanBudget = 0UL;
        ULONG paddingBytes = 0UL;
        UCHAR firstContentByte = 0U;
        NTSTATUS status = STATUS_SUCCESS;

        if (response->certificateCount >= KSWORD_ARK_SIGNATURE_MAX_ENUMERATED_ENTRIES) {
            response->structuralFlags |=
                KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_OUTPUT_TRUNCATED |
                KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_SCAN_LIMIT_REACHED;
            resultStatus = STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (remaining < sizeof(certificateHeader)) {
            response->structuralFlags |=
                KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_HEADER_TRUNCATED |
                KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_TRAILING_BYTES;
            resultStatus = STATUS_FILE_CORRUPT_ERROR;
            break;
        }

        RtlZeroMemory(&certificateHeader, sizeof(certificateHeader));
        status = kswordArkTrustReadFileAt(
            fileHandle,
            cursor,
            &certificateHeader,
            sizeof(certificateHeader));
        if (!NT_SUCCESS(status)) {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERTIFICATE_READ_FAILED;
            resultStatus = status;
            break;
        }
        if (certificateHeader.length < sizeof(certificateHeader)) {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_LENGTH_INVALID;
            resultStatus = STATUS_FILE_CORRUPT_ERROR;
            break;
        }
        alignedLength = ((ULONGLONG)certificateHeader.length + 7ULL) & ~7ULL;
        if (alignedLength > 0xFFFFFFFFULL ||
            certificateHeader.length > remaining || alignedLength > remaining) {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_RANGE_INVALID;
            resultStatus = STATUS_FILE_CORRUPT_ERROR;
            break;
        }

        RtlZeroMemory(&localEntry, sizeof(localEntry));
        if (response->returnedCertificateCount < KSWORD_ARK_IMAGE_SIGNATURE_MAX_ENTRIES) {
            entry = &response->certificates[response->returnedCertificateCount];
            response->returnedCertificateCount += 1UL;
        }
        else {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_OUTPUT_TRUNCATED;
        }
        RtlZeroMemory(entry, sizeof(*entry));
        entry->fileOffset = cursor;
        entry->length = certificateHeader.length;
        entry->alignedLength = (ULONG)alignedLength;
        entry->revision = certificateHeader.revision;
        entry->certificateType = certificateHeader.certificateType;
        entry->readStatus = STATUS_NOT_SUPPORTED;
        if ((certificateHeader.length & 7UL) == 0UL) {
            entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_LENGTH_ALIGNED;
        }
        if (certificateHeader.revision == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_REVISION_1_0 ||
            certificateHeader.revision == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_REVISION_2_0) {
            entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_REVISION_VALID;
        }
        else {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_REVISION;
        }
        if (!kswordArkTrustIsKnownCertificateType(certificateHeader.certificateType)) {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_TYPE;
        }
        if (certificateHeader.certificateType == KSWORD_ARK_IMAGE_SIGNATURE_WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
            entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_PKCS_SIGNED_DATA;
            response->pkcs7CertificateCount += 1UL;
        }

        contentBytes = certificateHeader.length - (ULONG)sizeof(certificateHeader);
        scanBudget = (totalScannedBytes < KSWORD_ARK_IMAGE_SIGNATURE_MAX_SCAN_BYTES)
            ? (KSWORD_ARK_IMAGE_SIGNATURE_MAX_SCAN_BYTES - totalScannedBytes)
            : 0UL;
        scanBytes = (contentBytes < scanBudget) ? contentBytes : scanBudget;
        if (scanBytes != 0UL) {
            status = kswordArkTrustScanCertificateContent(
                fileHandle,
                cursor + sizeof(certificateHeader),
                scanBytes,
                scratch,
                KSWORD_ARK_SIGNATURE_READ_CHUNK_BYTES + (ULONG)sizeof(kGKswordArkNestedSignatureOidDer),
                &entry->nestedSignatureCount,
                &entry->contentHashFnv1a64,
                &entry->contentBytesScanned,
                &firstContentByte);
            entry->readStatus = status;
            if (!NT_SUCCESS(status)) {
                response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERTIFICATE_READ_FAILED;
                resultStatus = status;
                break;
            }
            entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_CONTENT_READ;
            if (firstContentByte == 0x30U) {
                entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_DER_SEQUENCE;
            }
            if (entry->nestedSignatureCount != 0UL) {
                entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_NESTED_SIGNATURE_OID;
                response->nestedSignatureCount += entry->nestedSignatureCount;
            }
            totalScannedBytes += entry->contentBytesScanned;
        }
        else if (contentBytes == 0UL) {
            entry->readStatus = STATUS_SUCCESS;
            entry->contentHashFnv1a64 = KSWORD_ARK_SIGNATURE_FNV1A64_OFFSET;
            entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_CONTENT_READ;
        }
        if (scanBytes < contentBytes) {
            entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_SCAN_LIMITED;
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_SCAN_LIMIT_REACHED;
        }

        paddingBytes = (ULONG)alignedLength - certificateHeader.length;
        if (paddingBytes != 0UL) {
            NTSTATUS paddingStatus = STATUS_SUCCESS;
            if (kswordArkTrustCertificatePaddingNonzero(
                fileHandle,
                cursor + certificateHeader.length,
                paddingBytes,
                &paddingStatus)) {
                entry->flags |= KSWORD_ARK_IMAGE_SIGNATURE_ENTRY_PADDING_NONZERO;
                response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_PADDING_NONZERO;
            }
            if (!NT_SUCCESS(paddingStatus)) {
                entry->readStatus = paddingStatus;
                response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERTIFICATE_READ_FAILED;
                resultStatus = paddingStatus;
                break;
            }
        }

        response->certificateCount += 1UL;
        cursor += alignedLength;
        remaining -= alignedLength;
    }

    response->certificateBytesScanned = totalScannedBytes;
    response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_CERTIFICATES_ENUMERATED;
    if (response->nestedSignatureCount != 0UL) {
        response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_NESTED_SIGNATURE_PRESENT;
    }
    if (response->pkcs7CertificateCount > 1UL) {
        response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_MULTIPLE_PKCS7_ENTRIES;
    }
    ExFreePoolWithTag(scratch, KSWORD_ARK_TRUST_POOL_TAG);
    return resultStatus;
}

static NTSTATUS
kswordArkTrustParsePeCertificateTable(
    _In_ HANDLE fileHandle,
    _Inout_ KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE* response
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_FILE_HEADER fileHeader;
    IMAGE_DATA_DIRECTORY securityDirectory;
    ULONGLONG optionalHeaderOffset = 0ULL;
    ULONG peSignature = 0UL;
    USHORT optionalMagic = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    status = kswordArkTrustReadFileAt(fileHandle, 0ULL, &dosHeader, sizeof(dosHeader));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return STATUS_INVALID_IMAGE_NOT_MZ;
    }
    response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_DOS_HEADER;
    if (dosHeader.e_lfanew <= 0 ||
        (ULONGLONG)dosHeader.e_lfanew > response->fileSize ||
        (response->fileSize - (ULONGLONG)dosHeader.e_lfanew) <
            (sizeof(peSignature) + sizeof(fileHeader) + sizeof(optionalMagic))) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    response->peHeaderOffset = (ULONGLONG)dosHeader.e_lfanew;
    status = kswordArkTrustReadFileAt(
        fileHandle,
        response->peHeaderOffset,
        &peSignature,
        sizeof(peSignature));
    if (!NT_SUCCESS(status) || peSignature != IMAGE_NT_SIGNATURE) {
        return NT_SUCCESS(status) ? STATUS_INVALID_IMAGE_FORMAT : status;
    }
    RtlZeroMemory(&fileHeader, sizeof(fileHeader));
    status = kswordArkTrustReadFileAt(
        fileHandle,
        response->peHeaderOffset + sizeof(peSignature),
        &fileHeader,
        sizeof(fileHeader));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    optionalHeaderOffset = response->peHeaderOffset + sizeof(peSignature) + sizeof(fileHeader);
    if (optionalHeaderOffset > response->fileSize ||
        fileHeader.SizeOfOptionalHeader > (response->fileSize - optionalHeaderOffset)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }
    status = kswordArkTrustReadFileAt(
        fileHandle,
        optionalHeaderOffset,
        &optionalMagic,
        sizeof(optionalMagic));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&securityDirectory, sizeof(securityDirectory));
    response->peMachine = fileHeader.Machine;
    response->optionalHeaderMagic = optionalMagic;
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        ULONG requiredBytes = FIELD_OFFSET(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            ((IMAGE_DIRECTORY_ENTRY_SECURITY + 1UL) * sizeof(IMAGE_DATA_DIRECTORY));
        ULONG readBytes = fileHeader.SizeOfOptionalHeader;
        if (fileHeader.SizeOfOptionalHeader < requiredBytes) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        if (readBytes > sizeof(optionalHeader32)) {
            readBytes = sizeof(optionalHeader32);
        }
        RtlZeroMemory(&optionalHeader32, sizeof(optionalHeader32));
        status = kswordArkTrustReadFileAt(fileHandle, optionalHeaderOffset, &optionalHeader32, readBytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        response->sizeOfHeaders = optionalHeader32.SizeOfHeaders;
        if (optionalHeader32.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
            response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_NT_HEADERS;
            response->certificateStatus = STATUS_NOT_FOUND;
            return STATUS_SUCCESS;
        }
        securityDirectory = optionalHeader32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        ULONG requiredBytes = FIELD_OFFSET(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
            ((IMAGE_DIRECTORY_ENTRY_SECURITY + 1UL) * sizeof(IMAGE_DATA_DIRECTORY));
        ULONG readBytes = fileHeader.SizeOfOptionalHeader;
        if (fileHeader.SizeOfOptionalHeader < requiredBytes) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
        if (readBytes > sizeof(optionalHeader64)) {
            readBytes = sizeof(optionalHeader64);
        }
        RtlZeroMemory(&optionalHeader64, sizeof(optionalHeader64));
        status = kswordArkTrustReadFileAt(fileHandle, optionalHeaderOffset, &optionalHeader64, readBytes);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        response->sizeOfHeaders = optionalHeader64.SizeOfHeaders;
        if (optionalHeader64.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
            response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_NT_HEADERS;
            response->certificateStatus = STATUS_NOT_FOUND;
            return STATUS_SUCCESS;
        }
        securityDirectory = optionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    }
    else {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    response->fieldFlags |=
        KSWORD_ARK_IMAGE_SIGNATURE_FIELD_NT_HEADERS |
        KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SECURITY_DIRECTORY;
    response->certificateTableOffset = securityDirectory.VirtualAddress;
    response->certificateTableSize = securityDirectory.Size;
    if (securityDirectory.VirtualAddress == 0UL && securityDirectory.Size == 0UL) {
        response->certificateStatus = STATUS_NOT_FOUND;
        return STATUS_SUCCESS;
    }
    if (securityDirectory.VirtualAddress == 0UL || securityDirectory.Size == 0UL) {
        response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OUT_OF_RANGE;
        response->certificateStatus = STATUS_FILE_CORRUPT_ERROR;
        return STATUS_FILE_CORRUPT_ERROR;
    }
    if ((securityDirectory.VirtualAddress & 7UL) != 0UL) {
        response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_UNALIGNED;
    }
    if (response->sizeOfHeaders != 0UL && securityDirectory.VirtualAddress < response->sizeOfHeaders) {
        response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OVERLAPS_HEADERS;
    }
    if ((ULONGLONG)securityDirectory.VirtualAddress > response->fileSize ||
        (ULONGLONG)securityDirectory.Size >
            (response->fileSize - (ULONGLONG)securityDirectory.VirtualAddress)) {
        response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OUT_OF_RANGE;
        response->certificateStatus = STATUS_FILE_CORRUPT_ERROR;
        return STATUS_FILE_CORRUPT_ERROR;
    }

    response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_CERTIFICATE_TABLE;
    status = kswordArkTrustEnumerateCertificateTable(fileHandle, response);
    response->certificateStatus = status;
    return status;
}

static BOOLEAN
kswordArkTrustLoadedModuleNameMatches(
    _In_reads_(requestPathChars) PCWSTR requestPath,
    _In_ USHORT requestPathChars,
    _In_ const KswordArkTrustSystemModuleEntry* moduleEntry
    )
{
    ANSI_STRING ansiName;
    UNICODE_STRING moduleName;
    UNICODE_STRING requestName;
    CHAR boundedName[257] = { 0 };
    USHORT requestNameStart = requestPathChars;
    ULONG sourceOffset = 0UL;
    ULONG copyBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN matches = FALSE;

    if (requestPath == NULL || requestPathChars == 0U || moduleEntry == NULL) {
        return FALSE;
    }
    while (requestNameStart != 0U) {
        WCHAR character = requestPath[requestNameStart - 1U];
        if (character == L'\\' || character == L'/') {
            break;
        }
        requestNameStart -= 1U;
    }
    sourceOffset = (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName))
        ? moduleEntry->offsetToFileName
        : 0UL;
    while (sourceOffset + copyBytes < sizeof(moduleEntry->fullPathName) &&
        copyBytes < (sizeof(boundedName) - 1UL) &&
        moduleEntry->fullPathName[sourceOffset + copyBytes] != '\0') {
        boundedName[copyBytes] = (CHAR)moduleEntry->fullPathName[sourceOffset + copyBytes];
        copyBytes += 1UL;
    }
    if (copyBytes == 0UL) {
        return FALSE;
    }
    boundedName[copyBytes] = '\0';
    RtlInitAnsiString(&ansiName, boundedName);
    RtlZeroMemory(&moduleName, sizeof(moduleName));
    status = RtlAnsiStringToUnicodeString(&moduleName, &ansiName, TRUE);
    if (!NT_SUCCESS(status)) {
        return FALSE;
    }
    requestName.Buffer = (PWCH)(requestPath + requestNameStart);
    requestName.Length = (USHORT)((requestPathChars - requestNameStart) * sizeof(WCHAR));
    requestName.MaximumLength = requestName.Length;
    matches = RtlEqualUnicodeString(&requestName, &moduleName, TRUE);
    RtlFreeUnicodeString(&moduleName);
    return matches;
}

static NTSTATUS
kswordArkTrustMatchLoadedModule(
    _In_ const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST* request,
    _Inout_ KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE* response
    )
{
    KswordArkTrustSystemModuleInformation* moduleInformation = NULL;
    ULONG requiredBytes = 0UL;
    ULONG index = 0UL;
    ULONG boundedCount = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    status = ZwQuerySystemInformation(
        KSWORD_ARK_TRUST_SYSTEM_MODULE_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes < (ULONG)FIELD_OFFSET(KswordArkTrustSystemModuleInformation, modules) ||
        requiredBytes > (16UL * 1024UL * 1024UL)) {
        return NT_SUCCESS(status) ? STATUS_INFO_LENGTH_MISMATCH : status;
    }
    moduleInformation = (KswordArkTrustSystemModuleInformation*)
        kswordArkTrustAllocateNonPaged(requiredBytes);
    if (moduleInformation == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(moduleInformation, requiredBytes);
    status = ZwQuerySystemInformation(
        KSWORD_ARK_TRUST_SYSTEM_MODULE_INFORMATION_CLASS,
        moduleInformation,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInformation, KSWORD_ARK_TRUST_POOL_TAG);
        return status;
    }
    boundedCount = (requiredBytes - FIELD_OFFSET(KswordArkTrustSystemModuleInformation, modules)) /
        sizeof(KswordArkTrustSystemModuleEntry);
    if (boundedCount > moduleInformation->numberOfModules) {
        boundedCount = moduleInformation->numberOfModules;
    }
    status = STATUS_NOT_FOUND;
    for (index = 0UL; index < boundedCount; ++index) {
        const KswordArkTrustSystemModuleEntry* moduleEntry = &moduleInformation->modules[index];
        if ((ULONGLONG)(ULONG_PTR)moduleEntry->imageBase != request->expectedModuleBase) {
            continue;
        }
        response->matchedModuleBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
        response->matchedModuleSize = moduleEntry->imageSize;
        response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE;
        if (kswordArkTrustLoadedModuleNameMatches(
            request->path,
            request->pathLengthChars,
            moduleEntry)) {
            response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH;
        }
        else {
            response->structuralFlags |= KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH;
            status = STATUS_DATA_ERROR;
        }
        if ((response->fieldFlags & KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH) != 0UL) {
            status = STATUS_SUCCESS;
        }
        break;
    }
    ExFreePoolWithTag(moduleInformation, KSWORD_ARK_TRUST_POOL_TAG);
    return status;
}

VOID
kswordArkTrustInitialize(
    VOID
    )
/*++

Routine Description:

    initialize Phase-14 global CI/SecureBoot snapshots. Note: Refer to System Informer
    DriverEntry's handling of SystemCodeIntegrityInformation; retain status codes on query failure.

Arguments:

    None.

Return Value:

    None. This function has no return value.

--*/
{
    RtlZeroMemory(&gKswordArkTrustCodeIntegrity, sizeof(gKswordArkTrustCodeIntegrity));
    RtlZeroMemory(&gKswordArkTrustSecureBoot, sizeof(gKswordArkTrustSecureBoot));

    gKswordArkTrustCodeIntegrity.length = sizeof(gKswordArkTrustCodeIntegrity);
    gKswordArkTrustCodeIntegrityStatus = ZwQuerySystemInformation(
        KSWORD_ARK_TRUST_SYSTEM_CODEINTEGRITY_INFORMATION,
        &gKswordArkTrustCodeIntegrity,
        sizeof(gKswordArkTrustCodeIntegrity),
        NULL);
    if (!NT_SUCCESS(gKswordArkTrustCodeIntegrityStatus)) {
        RtlZeroMemory(&gKswordArkTrustCodeIntegrity, sizeof(gKswordArkTrustCodeIntegrity));
    }

    gKswordArkTrustSecureBootStatus = ZwQuerySystemInformation(
        KSWORD_ARK_TRUST_SYSTEM_SECUREBOOT_INFORMATION,
        &gKswordArkTrustSecureBoot,
        sizeof(gKswordArkTrustSecureBoot),
        NULL);
    if (!NT_SUCCESS(gKswordArkTrustSecureBootStatus)) {
        RtlZeroMemory(&gKswordArkTrustSecureBoot, sizeof(gKswordArkTrustSecureBoot));
    }
}

NTSTATUS
kswordArkDriverQueryImageTrust(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IMAGE_TRUST_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Query the kernel-side status of image trust. Note: This interface is read-only, returning
    the global CI policy, Secure Boot status, and optional file cached signing level;
    certificate subject/issuer/catalog queries remain the responsibility of R3 Authenticode.

Arguments:

    OutputBuffer: METHOD_BUFFERED output buffer.
    OutputBufferLength - Output buffer length.
    Request - Query request.
    BytesWrittenOut - Bytes received for writing.

Return Value:

    STATUS_SUCCESS indicates the response packet is valid; the specific failure reason is placed in response->queryStatus.

--*/
{
    KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE* response = NULL;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    ULONG requestFlags = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->pathLengthChars >= KSWORD_ARK_TRUST_PATH_MAX_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->pathLengthChars != 0U &&
        request->path[request->pathLengthChars] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_TRUST_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->queryStatus = KSWORD_ARK_TRUST_STATUS_UNAVAILABLE;
    response->trustSource = KSWORD_ARK_TRUST_SOURCE_NONE;
    response->signingLevel = KSWORD_ARK_SIGNING_LEVEL_UNCHECKED;
    response->codeIntegrityStatus = gKswordArkTrustCodeIntegrityStatus;
    response->secureBootStatus = gKswordArkTrustSecureBootStatus;
    response->openStatus = STATUS_NOT_SUPPORTED;
    response->objectStatus = STATUS_NOT_SUPPORTED;
    response->signingLevelStatus = STATUS_NOT_SUPPORTED;
    response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_AUTHENTICODE_DEFERRED_R3;

    requestFlags = (request->flags == 0UL) ? KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_ALL : request->flags;
    if ((requestFlags & KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_GLOBAL_CI) != 0UL) {
        if (NT_SUCCESS(gKswordArkTrustCodeIntegrityStatus)) {
            response->codeIntegrityOptions = gKswordArkTrustCodeIntegrity.codeIntegrityOptions;
            response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_GLOBAL_CI_PRESENT;
            response->trustSource = KSWORD_ARK_TRUST_SOURCE_SYSTEM_CODE_INTEGRITY;
        }
        if (NT_SUCCESS(gKswordArkTrustSecureBootStatus)) {
            response->secureBootEnabled = (ULONG)gKswordArkTrustSecureBoot.secureBootEnabled;
            response->secureBootCapable = (ULONG)gKswordArkTrustSecureBoot.secureBootCapable;
            response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_SECURE_BOOT_PRESENT;
        }
        if (kswordArkTrustResolveCiValidateExportPresence()) {
            response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_CI_VALIDATE_EXPORT_PRESENT;
        }
    }

    if (request->pathLengthChars != 0U) {
        response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_REQUEST_PATH_PRESENT;
        kswordArkTrustCopyWideStringToFixedBuffer(
            response->ntPath,
            KSWORD_ARK_TRUST_PATH_MAX_CHARS,
            request->path,
            request->pathLengthChars);
    }

    if ((requestFlags & KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_FILE_SIGNING_LEVEL) != 0UL &&
        request->pathLengthChars != 0U) {
        status = kswordArkTrustOpenFileForTrustQuery(
            request->path,
            request->pathLengthChars,
            requestFlags,
            FALSE,
            &fileHandle);
        response->openStatus = status;
        if (!NT_SUCCESS(status)) {
            response->queryStatus = KSWORD_ARK_TRUST_STATUS_FILE_OPEN_FAILED;
            *bytesWrittenOut = sizeof(*response);
            return STATUS_SUCCESS;
        }

        response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_FILE_OPENED;
        status = kswordArkTrustReferenceFileObject(fileHandle, &fileObject);
        response->objectStatus = status;
        if (NT_SUCCESS(status)) {
            response->fileObjectAddress = (ULONG64)(ULONG_PTR)fileObject;
            response->fieldFlags |= KSWORD_ARK_TRUST_FIELD_FILE_OBJECT_PRESENT;
            status = kswordArkTrustQueryCachedSigningLevel(fileObject, response);
            response->signingLevelStatus = status;
            if (NT_SUCCESS(status)) {
                response->trustSource = KSWORD_ARK_TRUST_SOURCE_SE_CACHED_SIGNING_LEVEL;
            }
        }
    }

    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }

    if ((response->fieldFlags & KSWORD_ARK_TRUST_FIELD_SIGNING_LEVEL_PRESENT) != 0UL ||
        (response->fieldFlags & KSWORD_ARK_TRUST_FIELD_GLOBAL_CI_PRESENT) != 0UL) {
        response->queryStatus = KSWORD_ARK_TRUST_STATUS_OK;
    }
    else if ((requestFlags & KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_FILE_SIGNING_LEVEL) != 0UL &&
        request->pathLengthChars != 0U) {
        response->queryStatus = KSWORD_ARK_TRUST_STATUS_SIGNING_LEVEL_UNAVAILABLE;
    }
    else if ((requestFlags & KSWORD_ARK_TRUST_QUERY_FLAG_INCLUDE_GLOBAL_CI) != 0UL) {
        response->queryStatus = KSWORD_ARK_TRUST_STATUS_CI_UNAVAILABLE;
    }
    else {
        response->queryStatus = KSWORD_ARK_TRUST_STATUS_INVALID_REQUEST;
    }

    if ((response->queryStatus == KSWORD_ARK_TRUST_STATUS_OK) &&
        ((response->fieldFlags & KSWORD_ARK_TRUST_FIELD_AUTHENTICODE_DEFERRED_R3) != 0UL)) {
        response->queryStatus = KSWORD_ARK_TRUST_STATUS_PARTIAL;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkDriverQueryImageSignature(
    _Out_writes_bytes_(outputBufferLength) PVOID outputBuffer,
    _In_ size_t outputBufferLength,
    _In_ const KSWORD_ARK_QUERY_IMAGE_SIGNATURE_REQUEST* request,
    _Out_ size_t* bytesWrittenOut
    )
/*++

Routine Description:

    Read PE certificate-table evidence and cached Code Integrity signing state
    entirely from kernel mode. The structural result does not claim that a
    certificate chain is trusted; the cached signing level remains a separate
    field group.

--*/
{
    KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE* response = NULL;
    KSWORD_ARK_QUERY_IMAGE_TRUST_RESPONSE cachedSigning;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    ULONG requestFlags = 0UL;
    ULONG openFlags = 0UL;
    BOOLEAN anySuccess = FALSE;
    BOOLEAN anyFailure = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (outputBuffer == NULL || request == NULL || bytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *bytesWrittenOut = 0U;
    if (outputBufferLength < sizeof(KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (request->pathLengthChars == 0U ||
        request->pathLengthChars >= KSWORD_ARK_TRUST_PATH_MAX_CHARS ||
        request->path[request->pathLengthChars] != L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    requestFlags = (request->flags == 0UL)
        ? KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT
        : request->flags;
    RtlZeroMemory(outputBuffer, outputBufferLength);
    response = (KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE*)outputBuffer;
    response->version = KSWORD_ARK_IMAGE_SIGNATURE_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->requestFlags = requestFlags;
    response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_UNAVAILABLE;
    response->openStatus = STATUS_NOT_SUPPORTED;
    response->fileSizeStatus = STATUS_NOT_SUPPORTED;
    response->objectStatus = STATUS_NOT_SUPPORTED;
    response->parseStatus = STATUS_NOT_SUPPORTED;
    response->certificateStatus = STATUS_NOT_SUPPORTED;
    response->signingLevelStatus = STATUS_NOT_SUPPORTED;
    response->loadedModuleStatus = STATUS_NOT_SUPPORTED;
    response->signingLevel = KSWORD_ARK_SIGNING_LEVEL_UNCHECKED;
    response->expectedModuleBase = request->expectedModuleBase;
    response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_REQUEST_PATH;
    kswordArkTrustCopyWideStringToFixedBuffer(
        response->ntPath,
        KSWORD_ARK_TRUST_PATH_MAX_CHARS,
        request->path,
        request->pathLengthChars);

    if ((requestFlags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE) != 0UL) {
        response->loadedModuleStatus = kswordArkTrustMatchLoadedModule(request, response);
        if (NT_SUCCESS(response->loadedModuleStatus)) {
            anySuccess = TRUE;
        }
        else {
            anyFailure = TRUE;
        }
    }

    if ((requestFlags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_OPEN_REPARSE_POINT) != 0UL) {
        openFlags |= KSWORD_ARK_TRUST_QUERY_FLAG_OPEN_REPARSE_POINT;
    }
    status = kswordArkTrustOpenFileForTrustQuery(
        request->path,
        request->pathLengthChars,
        openFlags,
        TRUE,
        &fileHandle);
    response->openStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_FILE_OPEN_FAILED;
        *bytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_FILE_OPENED;

    response->fileSizeStatus = kswordArkTrustQueryFileSize(fileHandle, &response->fileSize);
    if (NT_SUCCESS(response->fileSizeStatus)) {
        response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_FILE_SIZE;
    }

    response->objectStatus = kswordArkTrustReferenceFileObject(fileHandle, &fileObject);
    if (NT_SUCCESS(response->objectStatus)) {
        /* Keep fileObjectAddress reserved to avoid adding a new kernel-pointer leak. */
        response->fileObjectAddress = 0ULL;
    }

    if ((requestFlags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_INCLUDE_PE_CERTIFICATE_TABLE) != 0UL) {
        if (NT_SUCCESS(response->fileSizeStatus)) {
            response->parseStatus = kswordArkTrustParsePeCertificateTable(fileHandle, response);
        }
        else {
            response->parseStatus = response->fileSizeStatus;
        }
        if (NT_SUCCESS(response->parseStatus)) {
            anySuccess = TRUE;
        }
        else {
            anyFailure = TRUE;
        }
    }

    if ((requestFlags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_INCLUDE_CACHED_SIGNING_LEVEL) != 0UL) {
        if (fileObject != NULL) {
            RtlZeroMemory(&cachedSigning, sizeof(cachedSigning));
            response->signingLevelStatus =
                kswordArkTrustQueryCachedSigningLevel(fileObject, &cachedSigning);
            if (NT_SUCCESS(response->signingLevelStatus)) {
                response->signingLevel = cachedSigning.signingLevel;
                response->signingLevelFlags = cachedSigning.signingLevelFlags;
                response->thumbprintAlgorithm = cachedSigning.thumbprintAlgorithm;
                response->thumbprintSize = cachedSigning.thumbprintSize;
                if (response->thumbprintSize > sizeof(response->thumbprint)) {
                    response->thumbprintSize = sizeof(response->thumbprint);
                }
                if (response->thumbprintSize != 0UL) {
                    RtlCopyMemory(
                        response->thumbprint,
                        cachedSigning.thumbprint,
                        response->thumbprintSize);
                    response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_THUMBPRINT;
                }
                response->fieldFlags |= KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SIGNING_LEVEL;
                anySuccess = TRUE;
            }
            else {
                anyFailure = TRUE;
            }
        }
        else {
            response->signingLevelStatus = response->objectStatus;
            anyFailure = TRUE;
        }
    }

    if (fileObject != NULL) {
        ObDereferenceObject(fileObject);
    }
    ZwClose(fileHandle);

    if ((response->structuralFlags &
        (KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_UNALIGNED |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OUT_OF_RANGE |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_HEADER_TRUNCATED |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_LENGTH_INVALID |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_RANGE_INVALID |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_REVISION |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_UNKNOWN_TYPE |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_ENTRY_OUTPUT_TRUNCATED |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_TRAILING_BYTES |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_PADDING_NONZERO |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_SCAN_LIMIT_REACHED |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERTIFICATE_READ_FAILED |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH |
         KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_CERT_TABLE_OVERLAPS_HEADERS)) != 0UL) {
        anyFailure = TRUE;
    }

    if ((requestFlags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_INCLUDE_PE_CERTIFICATE_TABLE) != 0UL &&
        response->parseStatus == STATUS_INVALID_IMAGE_NOT_MZ) {
        response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_NOT_PE;
    }
    else if ((requestFlags & KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_INCLUDE_PE_CERTIFICATE_TABLE) != 0UL &&
        !NT_SUCCESS(response->parseStatus)) {
        response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_MALFORMED_PE;
    }
    else if (anySuccess && anyFailure) {
        response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_PARTIAL;
    }
    else if (anySuccess) {
        response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_OK;
    }
    else {
        response->queryStatus = KSWORD_ARK_IMAGE_SIGNATURE_STATUS_UNAVAILABLE;
    }

    *bytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

/*++

Module Name:

    kernel_module_identity.c

Abstract:

    Loaded-kernel-module identity resolver used by DynData exact matching.

Environment:

    Kernel-mode Driver Framework

--*/

#include "kernel_module_identity.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSW_MODULE_IDENTITY_TAG 'iDsK'
#define KSW_SYSTEM_MODULE_INFORMATION_CLASS 11UL

typedef PVOID
(NTAPI* KswExAllocatePooL2Routine)(
    _In_ POOL_FLAGS flags,
    _In_ SIZE_T numberOfBytes,
    _In_ ULONG tag
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

typedef struct KswSystemModuleEntry
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
} KswSystemModuleEntry, *PkswSystemModuleEntry;

typedef struct KswSystemModuleInformation
{
    ULONG numberOfModules;
    KswSystemModuleEntry modules[1];
} KswSystemModuleInformation, *PkswSystemModuleInformation;

static CHAR
kswordArkAsciiLower(
    _In_ CHAR character
    )
/*++

Routine Description:

    Convert one ASCII character to lowercase for bounded module-name matching.

Arguments:

    Character - Input ANSI character.

Return Value:

    Lowercase ASCII character when applicable; otherwise the original byte.

--*/
{
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character + ('a' - 'A'));
    }

    return character;
}

static PVOID
kswordArkAllocateModuleIdentityBuffer(
    _In_ SIZE_T bufferBytes
    )
/*++

Routine Description:

    Allocate the transient SystemModuleInformation buffer. Newer kernels expose
    ExAllocatePool2, while older targets need the deprecated fallback.

Arguments:

    BufferBytes - Number of nonpaged bytes to allocate.

Return Value:

    Nonpaged allocation pointer, or NULL on failure.

--*/
{
    UNICODE_STRING routineName;
    KswExAllocatePooL2Routine allocatePool2 = NULL;

    if (bufferBytes == 0U) {
        return NULL;
    }

    RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
    allocatePool2 = (KswExAllocatePooL2Routine)MmGetSystemRoutineAddress(&routineName);
    if (allocatePool2 != NULL) {
        return allocatePool2(POOL_FLAG_NON_PAGED, bufferBytes, KSW_MODULE_IDENTITY_TAG);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    return ExAllocatePoolWithTag(NonPagedPoolNx, bufferBytes, KSW_MODULE_IDENTITY_TAG);
#pragma warning(pop)
}

static BOOLEAN
kswordArkBoundedAnsiEqualsInsensitive(
    _In_reads_bytes_(leftBytes) const UCHAR* leftText,
    _In_ ULONG leftBytes,
    _In_z_ PCSTR rightText
    )
/*++

Routine Description:

    Compare a bounded ANSI filename from SystemModuleInformation with a constant
    NUL-terminated filename without assuming the bounded string is terminated.

Arguments:

    LeftText - Bounded ANSI filename buffer.
    LeftBytes - Maximum readable bytes in LeftText.
    RightText - Constant filename to match.

Return Value:

    TRUE when both strings match case-insensitively; otherwise FALSE.

--*/
{
    ULONG index = 0UL;

    if (leftText == NULL || leftBytes == 0UL || rightText == NULL) {
        return FALSE;
    }

    for (index = 0UL; index < leftBytes; ++index) {
        const CHAR kLeftCharacter = (CHAR)leftText[index];
        const CHAR kRightCharacter = rightText[index];

        if (kRightCharacter == '\0') {
            return (kLeftCharacter == '\0') ? TRUE : FALSE;
        }
        if (kLeftCharacter == '\0') {
            return FALSE;
        }
        if (kswordArkAsciiLower(kLeftCharacter) != kswordArkAsciiLower(kRightCharacter)) {
            return FALSE;
        }
    }

    return (rightText[index] == '\0') ? TRUE : FALSE;
}

static VOID
kswordArkCopyBoundedAnsiToWide(
    _In_reads_bytes_(sourceBytes) const UCHAR* sourceText,
    _In_ ULONG sourceBytes,
    _Out_writes_(destinationChars) PWCHAR destinationText,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Copy a bounded ANSI module name into the shared wide-character identity
    packet while guaranteeing termination.

Arguments:

    sourceText - Bounded ANSI source string.
    SourceBytes - Maximum readable source bytes.
    DestinationText - Wide-character output buffer.
    DestinationChars - Output buffer capacity in WCHARs.

Return Value:

    None.

--*/
{
    ULONG index = 0UL;

    if (destinationText == NULL || destinationChars == 0UL) {
        return;
    }

    destinationText[0] = L'\0';
    if (sourceText == NULL || sourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index + 1UL < destinationChars && index < sourceBytes; ++index) {
        if (sourceText[index] == '\0') {
            break;
        }
        destinationText[index] = (WCHAR)sourceText[index];
    }
    destinationText[index] = L'\0';
}

static NTSTATUS
kswordArkReadLoadedImagePeIdentity(
    _In_ PVOID imageBase,
    _Out_ ULONG* machineOut,
    _Out_ ULONG* timeDateStampOut,
    _Out_ ULONG* sizeOfImageOut
    )
/*++

Routine Description:

    Read PE header identity values from a loaded kernel image. The caller already
    received the base address from the trusted kernel module list; guarded reads
    still prevent a malformed image from breaking driver initialization.

Arguments:

    ImageBase - Loaded image base address.
    MachineOut - Receives IMAGE_FILE_HEADER.Machine.
    TimeDateStampOut - Receives IMAGE_FILE_HEADER.TimeDateStamp.
    SizeOfImageOut - Receives IMAGE_OPTIONAL_HEADER.SizeOfImage.

Return Value:

    STATUS_SUCCESS on a valid PE header, or an image/parameter failure status.

--*/
{
    PIMAGE_DOS_HEADER dosHeader = NULL;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    ULONG peOffset = 0UL;

    if (imageBase == NULL || machineOut == NULL || timeDateStampOut == NULL || sizeOfImageOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *machineOut = 0UL;
    *timeDateStampOut = 0UL;
    *sizeOfImageOut = 0UL;

    __try {
        dosHeader = (PIMAGE_DOS_HEADER)imageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew <= 0) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        peOffset = (ULONG)dosHeader->e_lfanew;
        if (peOffset > 0x100000UL) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)imageBase + peOffset);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        *machineOut = (ULONG)ntHeaders->FileHeader.Machine;
        *timeDateStampOut = ntHeaders->FileHeader.TimeDateStamp;
        *sizeOfImageOut = ntHeaders->OptionalHeader.SizeOfImage;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkFillModuleIdentityFromEntry(
    _In_ const KswSystemModuleEntry* moduleEntry,
    _In_ ULONG classId,
    _Out_ KSW_DYN_MODULE_IDENTITY_PACKET* identityOut
    )
/*++

Routine Description:

    Convert one SystemModuleInformation row into the shared DynData identity
    packet used by exact profile matching and UI diagnostics.

Arguments:

    ModuleEntry - Loaded module row from ZwQuerySystemInformation.
    ClassId - KSW_DYN_PROFILE_CLASS_* value selected by filename matching.
    IdentityOut - Output identity packet.

Return Value:

    STATUS_SUCCESS when PE identity was parsed; otherwise an image failure.

--*/
{
    const UCHAR* fileNameText = NULL;
    ULONG fileNameBytes = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG imageSizeFromPe = 0UL;

    if (moduleEntry == NULL || identityOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(identityOut, sizeof(*identityOut));
    if (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName)) {
        fileNameText = moduleEntry->fullPathName + moduleEntry->offsetToFileName;
        fileNameBytes = (ULONG)(sizeof(moduleEntry->fullPathName) - moduleEntry->offsetToFileName);
    }
    else {
        fileNameText = moduleEntry->fullPathName;
        fileNameBytes = (ULONG)sizeof(moduleEntry->fullPathName);
    }

    status = kswordArkReadLoadedImagePeIdentity(
        moduleEntry->imageBase,
        &identityOut->machine,
        &identityOut->timeDateStamp,
        &imageSizeFromPe);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    identityOut->present = 1UL;
    identityOut->classId = classId;
    identityOut->sizeOfImage = (imageSizeFromPe != 0UL) ? imageSizeFromPe : moduleEntry->imageSize;
    identityOut->imageBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;
    kswordArkCopyBoundedAnsiToWide(
        fileNameText,
        fileNameBytes,
        identityOut->moduleName,
        KSW_DYN_MODULE_NAME_CHARS);

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkQueryKernelModuleIdentity(
    _In_reads_(nameMatchCount) const KswKernelModuleNameMatch* nameMatches,
    _In_ ULONG nameMatchCount,
    _Out_ KSW_DYN_MODULE_IDENTITY_PACKET* identityOut
    )
/*++

Routine Description:

    Query the loaded kernel module list and return the first module whose file
    name matches one of the supplied DynData module names.

Arguments:

    NameMatches - Accepted filenames plus their DynData class ids.
    NameMatchCount - Number of rows in NameMatches.
    IdentityOut - Receives module identity for exact DynData matching.

Return Value:

    STATUS_SUCCESS on match, STATUS_NOT_FOUND when absent, or a query/allocation
    status when the module list cannot be read.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    KswSystemModuleInformation* moduleInformation = NULL;
    ULONG moduleIndex = 0UL;

    if (nameMatches == NULL || nameMatchCount == 0UL || identityOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(identityOut, sizeof(*identityOut));
    status = ZwQuerySystemInformation(
        KSW_SYSTEM_MODULE_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    moduleInformation = (KswSystemModuleInformation*)kswordArkAllocateModuleIdentityBuffer(requiredBytes);
    if (moduleInformation == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        KSW_SYSTEM_MODULE_INFORMATION_CLASS,
        moduleInformation,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInformation, KSW_MODULE_IDENTITY_TAG);
        return status;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleInformation->numberOfModules; ++moduleIndex) {
        const KswSystemModuleEntry* moduleEntry = &moduleInformation->modules[moduleIndex];
        const UCHAR* fileNameText = moduleEntry->fullPathName;
        ULONG fileNameBytes = (ULONG)sizeof(moduleEntry->fullPathName);
        ULONG matchIndex = 0UL;

        if (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName)) {
            fileNameText = moduleEntry->fullPathName + moduleEntry->offsetToFileName;
            fileNameBytes = (ULONG)(sizeof(moduleEntry->fullPathName) - moduleEntry->offsetToFileName);
        }

        for (matchIndex = 0UL; matchIndex < nameMatchCount; ++matchIndex) {
            if (!kswordArkBoundedAnsiEqualsInsensitive(fileNameText, fileNameBytes, nameMatches[matchIndex].fileName)) {
                continue;
            }

            status = kswordArkFillModuleIdentityFromEntry(
                moduleEntry,
                nameMatches[matchIndex].classId,
                identityOut);
            ExFreePoolWithTag(moduleInformation, KSW_MODULE_IDENTITY_TAG);
            return status;
        }
    }

    ExFreePoolWithTag(moduleInformation, KSW_MODULE_IDENTITY_TAG);
    return STATUS_NOT_FOUND;
}

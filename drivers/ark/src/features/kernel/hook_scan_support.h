#pragma once

#include "ark/ark_driver.h"

#include <ntimage.h>
#include <ntstrsafe.h>

#define KSW_HOOK_SCAN_TAG 'hHsK'

typedef struct KswHookSystemModuleEntry
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
} KswHookSystemModuleEntry, *PkswHookSystemModuleEntry;

typedef struct KswHookSystemModuleInformation
{
    ULONG numberOfModules;
    KswHookSystemModuleEntry modules[1];
} KswHookSystemModuleInformation, *PkswHookSystemModuleInformation;

EXTERN_C_START

CHAR
kswordArkHookAsciiLower(
    _In_ CHAR character
    );

BOOLEAN
kswordArkHookBoundedAnsiEqualsInsensitive(
    _In_reads_bytes_(leftBytes) const UCHAR* leftText,
    _In_ ULONG leftBytes,
    _In_z_ PCSTR rightText
    );

BOOLEAN
kswordArkHookWideModuleFilterMatches(
    _In_reads_bytes_(fileNameBytes) const UCHAR* fileNameText,
    _In_ ULONG fileNameBytes,
    _In_reads_(filterChars) const WCHAR* filterText,
    _In_ ULONG filterChars
    );

VOID
kswordArkHookCopyAnsi(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ size_t destinationBytes,
    _In_opt_z_ const CHAR* source
    );

VOID
kswordArkHookCopyBoundedAnsiToWide(
    _In_reads_bytes_(sourceBytes) const UCHAR* sourceText,
    _In_ ULONG sourceBytes,
    _Out_writes_(destinationChars) PWCHAR destinationText,
    _In_ ULONG destinationChars
    );

BOOLEAN
kswordArkHookValidateRvaRange(
    _In_ ULONG rva,
    _In_ ULONG bytes,
    _In_ ULONG imageSize
    );

NTSTATUS
kswordArkHookBuildModuleSnapshot(
    _Outptr_result_bytebuffer_(*bufferBytesOut) KswHookSystemModuleInformation** moduleInfoOut,
    _Out_ ULONG* bufferBytesOut
    );

const KswHookSystemModuleEntry*
kswordArkHookFindModuleForAddress(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG_PTR address
    );

VOID
kswordArkHookGetModuleFileName(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Outptr_result_buffer_(*fileNameBytesOut) const UCHAR** fileNameOut,
    _Out_ ULONG* fileNameBytesOut
    );

BOOLEAN
kswordArkHookReadMemorySafe(
    _In_ const VOID* source,
    _Out_writes_bytes_(bytesToRead) VOID* destination,
    _In_ SIZE_T bytesToRead
    );

BOOLEAN
kswordArkHookMultiplyUlong(
    _In_ ULONG leftValue,
    _In_ ULONG rightValue,
    _Out_ ULONG* productOut
    );

BOOLEAN
kswordArkHookAddRvaOffset(
    _In_ ULONG baseRva,
    _In_ ULONG index,
    _In_ ULONG elementBytes,
    _Out_ ULONG* rvaOut
    );

BOOLEAN
kswordArkHookImageAddressFromRva(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_ ULONG_PTR* addressOut
    );

BOOLEAN
kswordArkHookReadImageBytes(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_writes_bytes_(bytesToRead) VOID* destination,
    _In_ SIZE_T bytesToRead
    );

BOOLEAN
kswordArkHookReadImageNtHeaders(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Out_ IMAGE_NT_HEADERS* ntHeadersOut
    );

BOOLEAN
kswordArkHookGetDataDirectory(
    _In_ const IMAGE_NT_HEADERS* ntHeaders,
    _In_ ULONG directoryIndex,
    _Out_ IMAGE_DATA_DIRECTORY* directoryOut
    );

BOOLEAN
kswordArkHookReadImageUlong(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_ ULONG* valueOut
    );

BOOLEAN
kswordArkHookReadImageUshort(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_ USHORT* valueOut
    );

BOOLEAN
kswordArkHookCopyImageAnsi(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ size_t destinationBytes
    );

BOOLEAN
kswordArkHookIsRvaInsideDirectory(
    _In_ ULONG rva,
    _In_ const IMAGE_DATA_DIRECTORY* directory
    );

EXTERN_C_END

/*++

Module Name:

    hook_scan_support.c

Abstract:

    Safe kernel image read helpers for hook_scan.c.

Environment:

    Kernel-mode Driver Framework

--*/

#include "hook_scan_support.h"

#define KSW_HOOK_SCAN_SYSTEM_MODULE_INFORMATION_CLASS 11UL

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG systemInformationClass,
    _Out_writes_bytes_opt_(systemInformationLength) PVOID systemInformation,
    _In_ ULONG systemInformationLength,
    _Out_opt_ PULONG returnLength
    );

CHAR
kswordArkHookAsciiLower(
    _In_ CHAR character
    )
/*++

Routine Description:

    Convert an ASCII character to lowercase. Note: Used only for module name comparison; does not handle localized characters.

Arguments:

    Character - Input character.

Return Value:

    Lowercase character or original character.

--*/
{
    if (character >= 'A' && character <= 'Z') {
        return (CHAR)(character + ('a' - 'A'));
    }
    return character;
}

BOOLEAN
kswordArkHookBoundedAnsiEqualsInsensitive(
    _In_reads_bytes_(leftBytes) const UCHAR* leftText,
    _In_ ULONG leftBytes,
    _In_z_ PCSTR rightText
    )
/*++

Routine Description:

    Compare limited-length ANSI strings with constant strings. Note: The FullPathName in
    SystemModuleInformation is a fixed-size array; do not assume the filename region is NUL-terminated.

Arguments:

    LeftText - Finite-length text.
    LeftBytes: Maximum byte count for a finite-length text.
    RightText - NUL-terminated constant text.

Return Value:

    TRUE indicates case-insensitive equality.

--*/
{
    ULONG index = 0UL;

    if (leftText == NULL || leftBytes == 0UL || rightText == NULL) {
        return FALSE;
    }

    for (index = 0UL; index < leftBytes; ++index) {
        CHAR leftChar = (CHAR)leftText[index];
        CHAR rightChar = rightText[index];

        if (rightChar == '\0') {
            return leftChar == '\0';
        }
        if (leftChar == '\0') {
            return FALSE;
        }
        if (kswordArkHookAsciiLower(leftChar) != kswordArkHookAsciiLower(rightChar)) {
            return FALSE;
        }
    }

    return rightText[index] == '\0';
}

BOOLEAN
kswordArkHookWideModuleFilterMatches(
    _In_reads_bytes_(fileNameBytes) const UCHAR* fileNameText,
    _In_ ULONG fileNameBytes,
    _In_reads_(filterChars) const WCHAR* filterText,
    _In_ ULONG filterChars
    )
/*++

Routine Description:

    Check if the module filter matches the current module name. Note: R3 passes WCHAR,
    while the kernel module list is ANSI; here, only ASCII filename matching is performed.

Arguments:

    FileNameText - Module filename in ANSI.
    FileNameBytes - Maximum number of bytes in the module filename.
    FilterText - UI filter text.
    FilterChars - Number of filter text characters.

Return Value:

    TRUE indicates a match or an empty filter.

--*/
{
    ULONG index = 0UL;
    ULONG filterLength = 0UL;
    ULONG startIndex = 0UL;

    if (filterText == NULL || filterChars == 0UL || filterText[0] == L'\0') {
        return TRUE;
    }
    if (fileNameText == NULL || fileNameBytes == 0UL) {
        return FALSE;
    }

    // Note: The R3 filter box often contains only 'ntoskrnl' or 'win32k', so full filename equality is not enforced.
    while (filterLength < filterChars && filterText[filterLength] != L'\0') {
        ++filterLength;
    }
    if (filterLength == 0UL) {
        return TRUE;
    }
    if (filterLength > fileNameBytes) {
        return FALSE;
    }

    // Note: Perform case-insensitive substring matching within a bounded-length ANSI filename without relying on NUL termination.
    for (startIndex = 0UL; startIndex + filterLength <= fileNameBytes; ++startIndex) {
        BOOLEAN matched = TRUE;

        for (index = 0UL; index < filterLength; ++index) {
            WCHAR filterChar = filterText[index];
            CHAR fileChar = (CHAR)fileNameText[startIndex + index];

            if (fileChar == '\0') {
                matched = FALSE;
                break;
            }
            if (filterChar >= L'A' && filterChar <= L'Z') {
                filterChar = (WCHAR)(filterChar + (L'a' - L'A'));
            }
            fileChar = kswordArkHookAsciiLower(fileChar);
            if ((WCHAR)fileChar != filterChar) {
                matched = FALSE;
                break;
            }
        }

        if (matched) {
            return TRUE;
        }
    }

    return FALSE;
}

VOID
kswordArkHookCopyAnsi(
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ size_t destinationBytes,
    _In_opt_z_ const CHAR* source
    )
/*++

Routine Description:

    Copy ANSI text to a fixed buffer. Note: All protocol strings are forced to be NUL-terminated.

Arguments:

    Destination - Target buffer.
    DestinationBytes: target byte count.
    Source - Source text.

Return Value:

    None. This function has no return value.

--*/
{
    if (destination == NULL || destinationBytes == 0U) {
        return;
    }

    destination[0] = '\0';
    if (source == NULL) {
        return;
    }

    (VOID)RtlStringCbCopyNA(destination, destinationBytes, source, destinationBytes - 1U);
    destination[destinationBytes - 1U] = '\0';
}

VOID
kswordArkHookCopyBoundedAnsiToWide(
    _In_reads_bytes_(sourceBytes) const UCHAR* sourceText,
    _In_ ULONG sourceBytes,
    _Out_writes_(destinationChars) PWCHAR destinationText,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Copy a limited-length ANSI module name to the WCHAR protocol field. Note: Used solely for displaying the module file name.

Arguments:

    sourceText: Source ANSI text.
    SourceBytes - Maximum number of source bytes.
    DestinationText: Target WCHAR buffer.
    DestinationChars: Target character capacity.

Return Value:

    None. This function has no return value.

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

BOOLEAN
kswordArkHookValidateRvaRange(
    _In_ ULONG rva,
    _In_ ULONG bytes,
    _In_ ULONG imageSize
    )
/*++

Routine Description:

    Validate that the PE RVA falls within the loaded image range. Note: Prevent out-of-bounds
    access caused by malicious or malformed driver headers before parsing import/export tables.

Arguments:

    Rva - Starting RVA.
    Bytes - Number of bytes to read.
    ImageSize: Image size.

Return Value:

    TRUE indicates a valid range.

--*/
{
    if (rva >= imageSize || bytes > imageSize) {
        return FALSE;
    }
    return rva <= (imageSize - bytes);
}

NTSTATUS
kswordArkHookBuildModuleSnapshot(
    _Outptr_result_bytebuffer_(*bufferBytesOut) KswHookSystemModuleInformation** moduleInfoOut,
    _Out_ ULONG* bufferBytesOut
    )
/*++

Routine Description:

    Query the snapshot of loaded kernel modules. Note: Inline, IAT, and EAT detection
    all rely on this snapshot to resolve address ownership and module boundaries.

Arguments:

    ModuleInfoOut: Returns the allocated module snapshot.
    BufferBytesOut: Returns the snapshot byte count.

Return Value:

    STATUS_SUCCESS or query/allocation error.

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    KswHookSystemModuleInformation* moduleInfo = NULL;

    if (moduleInfoOut == NULL || bufferBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *moduleInfoOut = NULL;
    *bufferBytesOut = 0UL;

    // ZwQuerySystemInformation can enter pageable system services; do not
    // issue the query while special APC delivery is blocked.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = ZwQuerySystemInformation(
        KSW_HOOK_SCAN_SYSTEM_MODULE_INFORMATION_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    moduleInfo = (KswHookSystemModuleInformation*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        requiredBytes,
        KSW_HOOK_SCAN_TAG);
#pragma warning(pop)
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        KSW_HOOK_SCAN_SYSTEM_MODULE_INFORMATION_CLASS,
        moduleInfo,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        return status;
    }

    *moduleInfoOut = moduleInfo;
    *bufferBytesOut = requiredBytes;
    return STATUS_SUCCESS;
}

const KswHookSystemModuleEntry*
kswordArkHookFindModuleForAddress(
    _In_opt_ const KswHookSystemModuleInformation* moduleInfo,
    _In_ ULONG_PTR address
    )
/*++

Routine Description:

    Find the kernel module associated with the given address. Note: Used to determine if a jump target exits the current module.

Arguments:

    ModuleInfo - module snapshot.
    Address: Address to be classified.

Return Value:

    Return the module entry on a hit; otherwise return NULL.

--*/
{
    ULONG moduleIndex = 0UL;

    if (moduleInfo == NULL || address == 0U) {
        return NULL;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->numberOfModules; ++moduleIndex) {
        const KswHookSystemModuleEntry* moduleEntry = &moduleInfo->modules[moduleIndex];
        const ULONG_PTR kImageBase = (ULONG_PTR)moduleEntry->imageBase;
        const ULONG_PTR kImageEnd = kImageBase + (ULONG_PTR)moduleEntry->imageSize;

        if (address >= kImageBase && address < kImageEnd) {
            return moduleEntry;
        }
    }

    return NULL;
}

VOID
kswordArkHookGetModuleFileName(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Outptr_result_buffer_(*fileNameBytesOut) const UCHAR** fileNameOut,
    _Out_ ULONG* fileNameBytesOut
    )
/*++

Routine Description:

    Retrieve the module file name portion. Note: SystemModuleInformation stores the full
    path and file name offset; this function uniformly handles out-of-bounds offsets.

Arguments:

    ModuleEntry - Module entry.
    FileNameOut - Returns the file name pointer.
    FileNameBytesOut - Returns the remaining number of bytes.

Return Value:

    None. This function has no return value.

--*/
{
    if (fileNameOut == NULL || fileNameBytesOut == NULL) {
        return;
    }
    *fileNameOut = NULL;
    *fileNameBytesOut = 0UL;
    if (moduleEntry == NULL) {
        return;
    }

    if (moduleEntry->offsetToFileName < sizeof(moduleEntry->fullPathName)) {
        *fileNameOut = moduleEntry->fullPathName + moduleEntry->offsetToFileName;
        *fileNameBytesOut = (ULONG)(sizeof(moduleEntry->fullPathName) - moduleEntry->offsetToFileName);
    }
    else {
        *fileNameOut = moduleEntry->fullPathName;
        *fileNameBytesOut = (ULONG)sizeof(moduleEntry->fullPathName);
    }
}

BOOLEAN
kswordArkHookReadMemorySafe(
    _In_ const VOID* source,
    _Out_writes_bytes_(bytesToRead) VOID* destination,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Safely read kernel memory. Note: When scanning arbitrary kernel modules, do not assume every PE directory is
    trustworthy; therefore, a read failure should only fail the current line without affecting the entire enumeration.

Arguments:

    Source - Source address.
    Destination - Target buffer.
    BytesToRead - Length to read.

Return Value:

    TRUE indicates successful read.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (source == NULL || destination == NULL || bytesToRead == 0U) {
        return FALSE;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)source;
    __try {
        status = MmCopyMemory(
            destination,
            copyAddress,
            bytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }

    if (!NT_SUCCESS(status) || copiedBytes != bytesToRead) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
kswordArkHookMultiplyUlong(
    _In_ ULONG leftValue,
    _In_ ULONG rightValue,
    _Out_ ULONG* productOut
    )
/*++

Routine Description:

    Note: Safely compute the ULONG product. The number of PE table entries comes from the target
    image; check for multiplication overflow before proceeding with RVA range validation.

Arguments:

    LeftValue - Left operand.
    RightValue: Right operand.
    ProductOut - Returned product.

Return Value:

    TRUE indicates the product is valid; FALSE indicates invalid parameters or overflow.

--*/
{
    ULONGLONG product = 0ULL;

    if (productOut == NULL) {
        return FALSE;
    }
    *productOut = 0UL;

    product = (ULONGLONG)leftValue * (ULONGLONG)rightValue;
    if (product > MAXULONG) {
        return FALSE;
    }

    *productOut = (ULONG)product;
    return TRUE;
}

BOOLEAN
kswordArkHookAddRvaOffset(
    _In_ ULONG baseRva,
    _In_ ULONG index,
    _In_ ULONG elementBytes,
    _Out_ ULONG* rvaOut
    )
/*++

Routine Description:

    Safely calculate the RVA of an array element. Note: IAT/EAT array indices may come
    from malformed PE; prevent ULONG addition from wrapping back into the image range.

Arguments:

    BaseRva - Starting RVA of the array.
    Index: Element index.
    ElementBytes - size of a single element.
    RvaOut: Returned element RVA.

Return Value:

    TRUE indicates the result did not overflow.

--*/
{
    ULONGLONG offset = 0ULL;
    ULONGLONG result = 0ULL;

    if (rvaOut == NULL || elementBytes == 0UL) {
        return FALSE;
    }
    *rvaOut = 0UL;

    offset = (ULONGLONG)index * (ULONGLONG)elementBytes;
    result = (ULONGLONG)baseRva + offset;
    if (result > MAXULONG) {
        return FALSE;
    }

    *rvaOut = (ULONG)result;
    return TRUE;
}

BOOLEAN
kswordArkHookImageAddressFromRva(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_ ULONG_PTR* addressOut
    )
/*++

Routine Description:

    Convert valid RVA to kernel virtual address. Note: Reuse image boundary validation before
    conversion and additionally prevent pointer wraparound during base address + RVA calculation.

Arguments:

    ModuleEntry: Current module snapshot entry.
    Rva - RVA to be converted.
    AddressOut: Returns the virtual address value.

Return Value:

    TRUE indicates the address is usable for read-only probing.

--*/
{
    ULONG_PTR imageBase = 0U;

    if (moduleEntry == NULL || moduleEntry->imageBase == NULL || addressOut == NULL) {
        return FALSE;
    }
    *addressOut = 0U;

    if (!kswordArkHookValidateRvaRange(rva, 1UL, moduleEntry->imageSize)) {
        return FALSE;
    }

    imageBase = (ULONG_PTR)moduleEntry->imageBase;
    if ((ULONG_PTR)rva > (((ULONG_PTR)(~(ULONG_PTR)0)) - imageBase)) {
        return FALSE;
    }

    *addressOut = imageBase + (ULONG_PTR)rva;
    return TRUE;
}

BOOLEAN
kswordArkHookReadImageBytes(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_writes_bytes_(bytesToRead) VOID* destination,
    _In_ SIZE_T bytesToRead
    )
/*++

Routine Description:

    Safely read loaded image bytes by RVA. Note: All PE directory accesses should go through this
    function to avoid dereferencing module addresses that may be unloaded or cause page faults.

Arguments:

    ModuleEntry: Current module snapshot entry.
    Rva - Starting RVA.
    Destination - Output buffer.
    BytesToRead - Number of bytes to read.

Return Value:

    TRUE indicates a complete read was successful.

--*/
{
    ULONG_PTR sourceAddress = 0U;

    if (moduleEntry == NULL || destination == NULL || bytesToRead == 0U || bytesToRead > MAXULONG) {
        return FALSE;
    }
    if (!kswordArkHookValidateRvaRange(rva, (ULONG)bytesToRead, moduleEntry->imageSize)) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }
    if (!kswordArkHookImageAddressFromRva(moduleEntry, rva, &sourceAddress)) {
        RtlZeroMemory(destination, bytesToRead);
        return FALSE;
    }

    return kswordArkHookReadMemorySafe((const VOID*)sourceAddress, destination, bytesToRead);
}

BOOLEAN
kswordArkHookReadImageNtHeaders(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _Out_ IMAGE_NT_HEADERS* ntHeadersOut
    )
/*++

Routine Description:

    Safely read image NT headers. Validate header boundaries first, following System Informer's
    approach, but use MmCopyMemory for the actual access to avoid a PAGE_FAULT on a malformed header.

Arguments:

    ModuleEntry: Current module snapshot entry.
    NtHeadersOut - Returns a copy of the NT header.

Return Value:

    TRUE indicates that both the DOS/NT signature and header range are valid.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    ULONG peOffset = 0UL;

    if (moduleEntry == NULL || ntHeadersOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    RtlZeroMemory(ntHeadersOut, sizeof(*ntHeadersOut));

    if (!kswordArkHookReadImageBytes(moduleEntry, 0UL, &dosHeader, sizeof(dosHeader))) {
        return FALSE;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0) {
        return FALSE;
    }

    peOffset = (ULONG)dosHeader.e_lfanew;
    if (!kswordArkHookValidateRvaRange(peOffset, sizeof(*ntHeadersOut), moduleEntry->imageSize)) {
        return FALSE;
    }
    if (!kswordArkHookReadImageBytes(moduleEntry, peOffset, ntHeadersOut, sizeof(*ntHeadersOut))) {
        return FALSE;
    }

    if (ntHeadersOut->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
#if defined(_M_AMD64)
    if (ntHeadersOut->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return FALSE;
    }
#endif

    return TRUE;
}

BOOLEAN
kswordArkHookGetDataDirectory(
    _In_ const IMAGE_NT_HEADERS* ntHeaders,
    _In_ ULONG directoryIndex,
    _Out_ IMAGE_DATA_DIRECTORY* directoryOut
    )
/*++

Routine Description:

    Retrieve data directories from the local NT header copy. Note: First check
    NumberOfRvaAndSizes to prevent missing target directories in old or corrupted images.

Arguments:

    NtHeaders - Local copy of the NT headers.
    DirectoryIndex - Index under IMAGE_DIRECTORY_ENTRY_*.
    DirectoryOut - Returns a copy of the directory.

Return Value:

    TRUE indicates the directory field exists.

--*/
{
    if (ntHeaders == NULL || directoryOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(directoryOut, sizeof(*directoryOut));

    if (directoryIndex >= ntHeaders->OptionalHeader.NumberOfRvaAndSizes ||
        directoryIndex >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return FALSE;
    }

    *directoryOut = ntHeaders->OptionalHeader.DataDirectory[directoryIndex];
    return TRUE;
}

BOOLEAN
kswordArkHookReadImageUlong(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_ ULONG* valueOut
    )
/*++

Routine Description:

    Read ULONG from image RVA. Note: Used for import/export table arrays;
    callers must not directly dereference the target image address.

Arguments:

    ModuleEntry: Current module snapshot entry.
    Rva - The RVA where the ULONG is located.
    ValueOut - Returned read value.

Return Value:

    TRUE indicates a complete read was successful.

--*/
{
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0UL;
    return kswordArkHookReadImageBytes(moduleEntry, rva, valueOut, sizeof(*valueOut));
}

BOOLEAN
kswordArkHookReadImageUshort(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_ USHORT* valueOut
    )
/*++

Routine Description:

    Read a USHORT from the image RVA. Note: Used to read the export ordinal array;
    return FALSE on failure instead of triggering an exception in the scanning thread.

Arguments:

    ModuleEntry: Current module snapshot entry.
    Rva - RVA where the USHORT resides.
    ValueOut - Returned read value.

Return Value:

    TRUE indicates a complete read was successful.

--*/
{
    if (valueOut == NULL) {
        return FALSE;
    }
    *valueOut = 0U;
    return kswordArkHookReadImageBytes(moduleEntry, rva, valueOut, sizeof(*valueOut));
}

BOOLEAN
kswordArkHookCopyImageAnsi(
    _In_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONG rva,
    _Out_writes_bytes_(destinationBytes) CHAR* destination,
    _In_ size_t destinationBytes
    )
/*++

Routine Description:

    Copy a NUL-terminated ANSI string from the image RVA. Note: Both export names and imported module names come
    from the target image; byte-by-byte safe reads prevent blue screens caused by cross-page bad addresses.

Arguments:

    ModuleEntry: Current module snapshot entry.
    RVA: String start RVA.
    Destination: target ANSI buffer.
    DestinationBytes: Target byte capacity.

Return Value:

    TRUE indicates a NUL character was read; FALSE indicates invalid parameters, out-of-bounds access, or string truncation.

--*/
{
    size_t index = 0U;
    CHAR oneChar = '\0';

    if (destination == NULL || destinationBytes == 0U) {
        return FALSE;
    }
    destination[0] = '\0';

    if (moduleEntry == NULL || !kswordArkHookValidateRvaRange(rva, 1UL, moduleEntry->imageSize)) {
        return FALSE;
    }

    for (index = 0U; index + 1U < destinationBytes; ++index) {
        ULONG charRva = 0UL;

        if ((ULONGLONG)rva + (ULONGLONG)index > MAXULONG) {
            destination[index] = '\0';
            return FALSE;
        }

        charRva = rva + (ULONG)index;
        if (!kswordArkHookReadImageBytes(moduleEntry, charRva, &oneChar, sizeof(oneChar))) {
            destination[index] = '\0';
            return FALSE;
        }

        destination[index] = oneChar;
        if (oneChar == '\0') {
            return TRUE;
        }
    }

    destination[destinationBytes - 1U] = '\0';
    return FALSE;
}

BOOLEAN
kswordArkHookIsRvaInsideDirectory(
    _In_ ULONG rva,
    _In_ const IMAGE_DATA_DIRECTORY* directory
    )
/*++

Routine Description:

    Check if the RVA falls within the specified PE data directory. Note: Export forwarder strings
    reside in the export directory; this function handles the directory end address without overflow.

Arguments:

    Rva - RVA to be checked.
    Directory - Copy of the data directory.

Return Value:

    TRUE indicates the RVA falls within the directory range.

--*/
{
    ULONG directoryEnd = 0UL;

    if (directory == NULL || directory->VirtualAddress == 0UL || directory->Size == 0UL) {
        return FALSE;
    }
    if (directory->Size > MAXULONG - directory->VirtualAddress) {
        return FALSE;
    }

    directoryEnd = directory->VirtualAddress + directory->Size;
    return rva >= directory->VirtualAddress && rva < directoryEnd;
}

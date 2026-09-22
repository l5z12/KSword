/*++

Module Name:

    kernel_image_section_map.c

Abstract:

    Read-only classification of a kernel virtual address into its containing image's PE section, used by descriptor tables or hook-class evidence
    to verify if a target pointer truly resides within a module's executable section. This file does not write memory or modify page protections.

Environment:

    Kernel mode, <= DISPATCH_LEVEL (all image accesses are protected via the MmCopyMemory path).

--*/

#include "kernel_image_section_map.h"

// Maximum number of sections to traverse per image to prevent infinite loops caused by forged NumberOfSections values.
#define KSW_IMAGE_SECTION_MAX_SECTIONS 96UL

static VOID
kswordArkImageCopySectionName(
    _In_reads_bytes_(IMAGE_SIZEOF_SHORT_NAME) const UCHAR* rawName,
    _Out_writes_opt_z_(destinationChars) PWCHAR destination,
    _In_ ULONG destinationChars
    )
/*++

Routine Description:

    Convert the 8-byte ANSI raw value of the PE section name into a bounded wide string.

Arguments:

    RawName - Original bytes of IMAGE_SECTION_HEADER::Name.
    Destination - Optional output buffer.
    DestinationChars - Output capacity (character count).

Return Value:

    None. Return immediately if no buffer is provided.

--*/
{
    ULONG index = 0UL;

    /* The caller may not care about the section name, so no copy is needed. */
    if (destination == NULL || destinationChars == 0UL) {
        return;
    }

    /* Write the terminator first to ensure any early return path leaves a valid string. */
    destination[0] = L'\0';

    /* Convert byte-by-byte; stop upon encountering NUL or the buffer end. */
    for (index = 0UL; index < IMAGE_SIZEOF_SHORT_NAME && (index + 1UL) < destinationChars; ++index) {
        /* Section names are not required to be NUL-terminated, so check each byte explicitly. */
        if (rawName[index] == 0U) {
            break;
        }
        /* Replace non-printable bytes with '?' to avoid injecting binary noise into the UI. */
        destination[index] = (rawName[index] >= 0x20U && rawName[index] < 0x7FU)
            ? (WCHAR)rawName[index]
            : L'?';
    }

    /* Append null terminator based on actual write length. */
    destination[index] = L'\0';
}

ULONG
kswordArkImageClassifyAddress(
    _In_opt_ const KswHookSystemModuleEntry* moduleEntry,
    _In_ ULONGLONG address,
    _Out_writes_opt_z_(sectionNameChars) PWCHAR sectionName,
    _In_ ULONG sectionNameChars,
    _Out_opt_ ULONG* sectionCharacteristicsOut
    )
/*++

Routine Description:

    Determine which PE section of the associated image the address falls into and return whether that section is executable.

Arguments:

    ModuleEntry - Snapshot entry of the loaded module to which the address belongs.
    Address - Kernel virtual address pending classification.
    SectionName - optional, receives the name of the matched section.
    Capacity of SectionNameChars minus SectionName.
    SectionCharacteristicsOut - Optional, receives the Characteristics of the matched section.

Return Value:

    One of KSW_IMAGE_SECTION_RESULT_*.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    ULONG sectionTableRva = 0UL;
    ULONG sectionCount = 0UL;
    ULONG sectionIndex = 0UL;
    ULONG targetRva = 0UL;
    ULONGLONG imageBase = 0ULL;

    /* Unified initialization of optional outputs; callers need not zero them again on failure paths. */
    if (sectionName != NULL && sectionNameChars != 0UL) {
        sectionName[0] = L'\0';
    }
    if (sectionCharacteristicsOut != NULL) {
        *sectionCharacteristicsOut = 0UL;
    }

    /* No RVA calculation is possible without a module entry or when the image size is zero. */
    if (moduleEntry == NULL || moduleEntry->imageSize == 0UL) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* Retrieve the image base address to convert VA to RVA subsequently. */
    imageBase = (ULONGLONG)(ULONG_PTR)moduleEntry->imageBase;

    /* The address must actually fall within the image range; otherwise, this classification is meaningless. */
    if (imageBase == 0ULL ||
        address < imageBase ||
        (address - imageBase) >= (ULONGLONG)moduleEntry->imageSize) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* At this point, the difference is guaranteed to be less than ImageSize (ULONG), so the conversion will not truncate. */
    targetRva = (ULONG)(address - imageBase);

    /* Read the DOS header only to obtain e_lfanew for locating the section table. */
    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    if (!kswordArkHookReadImageBytes(moduleEntry, 0UL, &dosHeader, sizeof(dosHeader))) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* If the DOS signature or PE offset is invalid, treat as unclassifiable without making any guesses. */
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* The NT header is read by a common helper function, which also validates the PE/OptionalHeader signature. */
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    if (!kswordArkHookReadImageNtHeaders(moduleEntry, &ntHeaders)) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* Reject traversal if section count is zero or abnormally large to avoid being stuck by a crafted header. */
    sectionCount = ntHeaders.FileHeader.NumberOfSections;
    if (sectionCount == 0UL || sectionCount > KSW_IMAGE_SECTION_MAX_SECTIONS) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* The section table immediately follows the optional header: e_lfanew + 4 (Signature) + FileHeader + SizeOfOptionalHeader. */
    sectionTableRva = (ULONG)dosHeader.e_lfanew;
    if (!kswordArkHookAddRvaOffset(sectionTableRva, 1UL, sizeof(ULONG), &sectionTableRva) ||
        !kswordArkHookAddRvaOffset(sectionTableRva, 1UL, sizeof(IMAGE_FILE_HEADER), &sectionTableRva) ||
        !kswordArkHookAddRvaOffset(sectionTableRva, 1UL, ntHeaders.FileHeader.SizeOfOptionalHeader, &sectionTableRva)) {
        return KSW_IMAGE_SECTION_RESULT_UNKNOWN;
    }

    /* Iteratively compare whether the target RVA falls within [VirtualAddress, VirtualAddress + section length). */
    for (sectionIndex = 0UL; sectionIndex < sectionCount; ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG sectionHeaderRva = 0UL;
        ULONG sectionLength = 0UL;

        /* Calculate the RVA of the section header at sectionIndex; terminate traversal on overflow. */
        if (!kswordArkHookAddRvaOffset(sectionTableRva, sectionIndex, sizeof(IMAGE_SECTION_HEADER), &sectionHeaderRva)) {
            break;
        }

        /* Section headers must be entirely within the image to allow reading. */
        RtlZeroMemory(&sectionHeader, sizeof(sectionHeader));
        if (!kswordArkHookReadImageBytes(moduleEntry, sectionHeaderRva, &sectionHeader, sizeof(sectionHeader))) {
            break;
        }

        /* The in-memory section length is the maximum of VirtualSize and SizeOfRawData to support both alignment styles. */
        sectionLength = sectionHeader.Misc.VirtualSize;
        if (sectionLength < sectionHeader.SizeOfRawData) {
            sectionLength = sectionHeader.SizeOfRawData;
        }

        /* Sections with zero length do not occupy address space; skip directly. */
        if (sectionLength == 0UL) {
            continue;
        }

        /* If the target RVA falls within this section range, complete the classification. */
        if (targetRva >= sectionHeader.VirtualAddress &&
            (targetRva - sectionHeader.VirtualAddress) < sectionLength) {
            /* Fill in the section name and Characteristics for the upper layer to generate human-readable evidence. */
            kswordArkImageCopySectionName(sectionHeader.Name, sectionName, sectionNameChars);
            if (sectionCharacteristicsOut != NULL) {
                *sectionCharacteristicsOut = sectionHeader.Characteristics;
            }
            /* Only sections with MEM_EXECUTE are considered valid code landing points. */
            return ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0UL)
                ? KSW_IMAGE_SECTION_RESULT_EXECUTABLE
                : KSW_IMAGE_SECTION_RESULT_NON_EXECUTABLE;
        }
    }

    /* If no match is found after traversal, the address is in the PE header region or a section gap. */
    return KSW_IMAGE_SECTION_RESULT_OUTSIDE_SECTIONS;
}

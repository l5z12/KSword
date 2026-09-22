/*++

Module Name:

    runtime_signature_scan.c

Abstract:

    Shared x64 runtime-signature support.  The scanner begins at stable PE
    exports, follows a bounded number of direct relative calls or jumps, and
    records only RIP-relative references that resolve into the same loaded
    image.  It deliberately does not publish a candidate: feature-specific
    callers must still require a unique match and validate the live structure.

Environment:

    Kernel mode, PASSIVE_LEVEL initialization or read-only query paths.

--*/

#include "runtime_signature_scan.h"
#include <ntimage.h>

NTSYSAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
    _In_ PVOID imageBase,
    _In_ PCCH routineName
    );

typedef struct KswRuntimeRoutineWork
{
    ULONG_PTR address;
    ULONG depth;
} KswRuntimeRoutineWork, *PkswRuntimeRoutineWork;

BOOLEAN
kswordArkRuntimeReadMemory(
    _In_ const VOID* address,
    _Out_writes_bytes_(size) VOID* buffer,
    _In_ SIZE_T size
    )
/*++

Routine Description:

    Copy a bounded kernel-memory range while containing invalid candidates.

Return Value:

    TRUE only when the complete range was readable.

--*/
{
    MM_COPY_ADDRESS sourceAddress;
    SIZE_T bytesTransferred = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (address == NULL || buffer == NULL || size == 0U) {
        return FALSE;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }
    RtlZeroMemory(&sourceAddress, sizeof(sourceAddress));
    sourceAddress.VirtualAddress = (PVOID)address;
    status = MmCopyMemory(
        buffer,
        sourceAddress,
        size,
        MM_COPY_MEMORY_VIRTUAL,
        &bytesTransferred);
    return NT_SUCCESS(status) && bytesTransferred == size;
}

BOOLEAN
kswordArkRuntimeAddressInImage(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    )
/*++

Routine Description:

    Validate a non-wrapping address range against the loaded image interval.

Return Value:

    TRUE when every requested byte is contained by the image.

--*/
{
    ULONG_PTR imageEnd = 0U;

    if (view == NULL || view->base == 0U || view->size == 0UL ||
        requiredBytes == 0U || view->base > MAXULONG_PTR - view->size) {
        return FALSE;
    }
    imageEnd = view->base + view->size;
    return address >= view->base && address < imageEnd &&
        requiredBytes <= imageEnd - address;
}

static BOOLEAN
kswordArkRuntimeRangeInSection(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes,
    _In_ ULONG requiredCharacteristics,
    _In_ ULONG rejectedCharacteristics
    )
/*++

Routine Description:

    Match one range against a PE section with required and rejected flags.

Return Value:

    TRUE when one complete section range satisfies the policy.

--*/
{
    ULONG index = 0UL;

    if (!kswordArkRuntimeAddressInImage(view, address, requiredBytes)) {
        return FALSE;
    }
    for (index = 0UL; index < view->sectionCount; ++index) {
        const KswRuntimeImageSection* section = &view->sections[index];

        if ((section->characteristics & requiredCharacteristics) !=
                requiredCharacteristics ||
            (section->characteristics & rejectedCharacteristics) != 0UL ||
            address < section->start || address >= section->end ||
            requiredBytes > section->end - address) {
            continue;
        }
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
kswordArkRuntimeAddressIsExecutable(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    )
{
    return kswordArkRuntimeRangeInSection(
        view,
        address,
        requiredBytes,
        IMAGE_SCN_MEM_EXECUTE,
        0UL);
}

BOOLEAN
kswordArkRuntimeAddressIsWritableData(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR address,
    _In_ SIZE_T requiredBytes
    )
{
    return kswordArkRuntimeRangeInSection(
        view,
        address,
        requiredBytes,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        IMAGE_SCN_MEM_EXECUTE);
}

BOOLEAN
kswordArkRuntimeInitializeImageView(
    _In_ PVOID imageBase,
    _In_ ULONG imageSize,
    _Out_ PkswRuntimeImageView viewOut
    )
/*++

Routine Description:

    Parse a loaded PE image and retain bounded virtual section intervals.

Return Value:

    TRUE when DOS, NT, optional, and section headers are internally consistent.

--*/
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG_PTR base = (ULONG_PTR)imageBase;
    ULONG_PTR ntAddress = 0U;
    ULONG_PTR sectionAddress = 0U;
    ULONG sectionCount = 0UL;
    ULONG index = 0UL;

    if (viewOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(viewOut, sizeof(*viewOut));
    if (imageBase == NULL || imageSize < sizeof(dosHeader) ||
        !kswordArkRuntimeReadMemory(imageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew <= 0 ||
        (ULONG)dosHeader.e_lfanew > imageSize - sizeof(ntHeaders) ||
        base > MAXULONG_PTR - (ULONG)dosHeader.e_lfanew) {
        return FALSE;
    }

    ntAddress = base + (ULONG)dosHeader.e_lfanew;
    if (!kswordArkRuntimeReadMemory(
            (const VOID*)ntAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections > KSW_RUNTIME_IMAGE_MAX_SECTIONS ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL ||
        ntHeaders.OptionalHeader.SizeOfImage > imageSize) {
        return FALSE;
    }

    sectionCount = ntHeaders.FileHeader.NumberOfSections;
    sectionAddress = ntAddress + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    if (sectionAddress < ntAddress || sectionAddress < base ||
        sectionCount > (imageSize / sizeof(IMAGE_SECTION_HEADER)) ||
        sectionAddress - base >= imageSize ||
        (SIZE_T)sectionCount * sizeof(IMAGE_SECTION_HEADER) >
            imageSize - (sectionAddress - base)) {
        return FALSE;
    }

    viewOut->base = base;
    viewOut->size = ntHeaders.OptionalHeader.SizeOfImage;
    for (index = 0UL; index < sectionCount; ++index) {
        IMAGE_SECTION_HEADER sectionHeader;
        ULONG virtualBytes = 0UL;
        ULONG_PTR start = 0U;
        ULONG_PTR end = 0U;

        if (!kswordArkRuntimeReadMemory(
                (const VOID*)(sectionAddress +
                    ((ULONG_PTR)index * sizeof(sectionHeader))),
                &sectionHeader,
                sizeof(sectionHeader))) {
            RtlZeroMemory(viewOut, sizeof(*viewOut));
            return FALSE;
        }
        virtualBytes = max(sectionHeader.Misc.VirtualSize, sectionHeader.SizeOfRawData);
        if (virtualBytes == 0UL || sectionHeader.VirtualAddress >= viewOut->size ||
            virtualBytes > viewOut->size - sectionHeader.VirtualAddress ||
            base > MAXULONG_PTR - sectionHeader.VirtualAddress) {
            continue;
        }
        start = base + sectionHeader.VirtualAddress;
        if (start > MAXULONG_PTR - virtualBytes) {
            continue;
        }
        end = start + virtualBytes;
        viewOut->sections[viewOut->sectionCount].start = start;
        viewOut->sections[viewOut->sectionCount].end = end;
        viewOut->sections[viewOut->sectionCount].characteristics =
            sectionHeader.Characteristics;
        viewOut->sectionCount += 1UL;
    }

    if (viewOut->sectionCount == 0UL) {
        RtlZeroMemory(viewOut, sizeof(*viewOut));
        return FALSE;
    }
    return TRUE;
}

PVOID
kswordArkRuntimeFindExport(
    _In_ const KswRuntimeImageView* view,
    _In_z_ PCSTR exportName
    )
/*++

Routine Description:

    Resolve one export and require its address to remain in the supplied image.

Return Value:

    Export address or NULL.

--*/
{
    PVOID address = NULL;

    if (view == NULL || exportName == NULL || view->base == 0U) {
        return NULL;
    }
    address = RtlFindExportedRoutineByName((PVOID)view->base, exportName);
    return kswordArkRuntimeAddressInImage(view, (ULONG_PTR)address, 1U)
        ? address
        : NULL;
}

static BOOLEAN
kswordArkRuntimeResolveRelativeTarget(
    _In_ ULONG_PTR nextInstruction,
    _In_ LONG displacement,
    _Out_ ULONG_PTR* targetOut
    )
{
    ULONG_PTR magnitude = 0U;

    if (targetOut == NULL) {
        return FALSE;
    }
    if (displacement >= 0) {
        if (nextInstruction > MAXULONG_PTR - (ULONG)displacement) {
            return FALSE;
        }
        *targetOut = nextInstruction + (ULONG)displacement;
        return TRUE;
    }
    magnitude = (ULONG_PTR)(-(LONGLONG)displacement);
    if (nextInstruction < magnitude) {
        return FALSE;
    }
    *targetOut = nextInstruction - magnitude;
    return TRUE;
}

static BOOLEAN
kswordArkRuntimeDecodeRipReference(
    _In_ ULONG_PTR instructionAddress,
    _Out_ ULONG_PTR* targetOut,
    _Out_opt_ ULONG* instructionBytesOut
    )
/*++

Routine Description:

    Decode the small x64 instruction subset used for RIP-relative data access.
    Unsupported encodings are ignored instead of guessed.

Return Value:

    TRUE when a complete supported instruction resolved safely.

--*/
{
#if defined(_M_AMD64) || defined(_M_X64)
    UCHAR bytes[16];
    ULONG cursor = 0UL;
    ULONG modRmOffset = 0UL;
    ULONG displacementOffset = 0UL;
    ULONG instructionBytes = 0UL;
    BOOLEAN supportedOpcode = FALSE;
    LONG displacement = 0L;

    if (targetOut == NULL ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)instructionAddress,
            bytes,
            sizeof(bytes))) {
        return FALSE;
    }

    while (cursor < 4UL &&
           (bytes[cursor] == 0x66U || bytes[cursor] == 0xF2U ||
            bytes[cursor] == 0xF3U ||
            (bytes[cursor] >= 0x40U && bytes[cursor] <= 0x4FU))) {
        cursor += 1UL;
    }
    if (cursor >= sizeof(bytes)) {
        return FALSE;
    }

    if (bytes[cursor] == 0x0FU) {
        cursor += 1UL;
        if (cursor >= sizeof(bytes)) {
            return FALSE;
        }
        supportedOpcode = bytes[cursor] == 0xB6U || bytes[cursor] == 0xB7U ||
            bytes[cursor] == 0xBEU || bytes[cursor] == 0xBFU;
    }
    else {
        supportedOpcode = bytes[cursor] == 0x8BU || bytes[cursor] == 0x8DU ||
            bytes[cursor] == 0x89U || bytes[cursor] == 0x39U ||
            bytes[cursor] == 0x3BU || bytes[cursor] == 0x63U ||
            bytes[cursor] == 0x85U || bytes[cursor] == 0xFFU;
    }
    if (!supportedOpcode) {
        return FALSE;
    }

    modRmOffset = cursor + 1UL;
    if (modRmOffset >= sizeof(bytes) || (bytes[modRmOffset] & 0xC7U) != 0x05U) {
        return FALSE;
    }
    displacementOffset = modRmOffset + 1UL;
    instructionBytes = displacementOffset + sizeof(displacement);
    if (instructionBytes > sizeof(bytes)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + displacementOffset, sizeof(displacement));
    if (!kswordArkRuntimeResolveRelativeTarget(
            instructionAddress + instructionBytes,
            displacement,
            targetOut)) {
        return FALSE;
    }
    if (instructionBytesOut != NULL) {
        *instructionBytesOut = instructionBytes;
    }
    return TRUE;
#else
    UNREFERENCED_PARAMETER(InstructionAddress);
    UNREFERENCED_PARAMETER(TargetOut);
    UNREFERENCED_PARAMETER(InstructionBytesOut);
    return FALSE;
#endif
}

static BOOLEAN
kswordArkRuntimeDecodeDirectBranch(
    _In_ ULONG_PTR instructionAddress,
    _Out_ ULONG_PTR* targetOut
    )
{
    UCHAR bytes[5];
    LONG displacement = 0L;

    if (targetOut == NULL ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)instructionAddress,
            bytes,
            sizeof(bytes)) ||
        (bytes[0] != 0xE8U && bytes[0] != 0xE9U)) {
        return FALSE;
    }
    RtlCopyMemory(&displacement, bytes + 1UL, sizeof(displacement));
    return kswordArkRuntimeResolveRelativeTarget(
        instructionAddress + sizeof(bytes),
        displacement,
        targetOut);
}

static BOOLEAN
kswordArkRuntimeAppendReference(
    _Inout_updates_(capacity) KswRuntimeDataReference* references,
    _In_ ULONG capacity,
    _Inout_ ULONG* count,
    _In_ ULONG_PTR address,
    _In_ ULONG_PTR routineAddress,
    _In_ ULONG_PTR instructionAddress
    )
{
    ULONG index = 0UL;

    if (references == NULL || count == NULL || *count > capacity) {
        return FALSE;
    }
    for (index = 0UL; index < *count; ++index) {
        if (references[index].address == address &&
            references[index].routineAddress == routineAddress) {
            return TRUE;
        }
    }
    if (*count >= capacity) {
        return FALSE;
    }
    references[*count].address = address;
    references[*count].routineAddress = routineAddress;
    references[*count].instructionAddress = instructionAddress;
    *count += 1UL;
    return TRUE;
}

static ULONG
kswordArkRuntimeScanRoutine(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG_PTR routineAddress,
    _In_ ULONG scanBytes,
    _Inout_updates_(referenceCapacity) KswRuntimeDataReference* references,
    _In_ ULONG referenceCapacity,
    _Inout_ ULONG* referenceCount,
    _Out_writes_opt_(branchCapacity) ULONG_PTR* branchTargets,
    _In_ ULONG branchCapacity
    )
{
    ULONG offset = 0UL;
    ULONG branchCount = 0UL;

    if (view == NULL || references == NULL || referenceCount == NULL ||
        !kswordArkRuntimeAddressIsExecutable(view, routineAddress, 1U)) {
        return 0UL;
    }

    for (offset = 0UL; offset < scanBytes; ++offset) {
        ULONG_PTR instructionAddress = routineAddress + offset;
        ULONG_PTR target = 0U;

        if (!kswordArkRuntimeAddressIsExecutable(view, instructionAddress, 1U)) {
            break;
        }
        if (kswordArkRuntimeDecodeRipReference(instructionAddress, &target, NULL) &&
            kswordArkRuntimeAddressInImage(view, target, 1U) &&
            !kswordArkRuntimeAddressIsExecutable(view, target, 1U)) {
            if (!kswordArkRuntimeAppendReference(
                    references,
                    referenceCapacity,
                    referenceCount,
                    target,
                    routineAddress,
                    instructionAddress)) {
                break;
            }
        }
        if (branchTargets != NULL && branchCount < branchCapacity &&
            kswordArkRuntimeDecodeDirectBranch(instructionAddress, &target) &&
            kswordArkRuntimeAddressIsExecutable(view, target, 1U)) {
            ULONG branchIndex = 0UL;
            BOOLEAN duplicate = FALSE;

            for (branchIndex = 0UL; branchIndex < branchCount; ++branchIndex) {
                if (branchTargets[branchIndex] == target) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                branchTargets[branchCount++] = target;
            }
        }
    }
    return branchCount;
}

ULONG
kswordArkRuntimeCollectAnchoredDataReferences(
    _In_ const KswRuntimeImageView* view,
    _In_reads_(anchorCount) PCSTR const* anchorNames,
    _In_ ULONG anchorCount,
    _In_ ULONG maxCallDepth,
    _In_ ULONG routineScanBytes,
    _Out_writes_(referenceCapacity) KswRuntimeDataReference* references,
    _In_ ULONG referenceCapacity
    )
/*++

Routine Description:

    Scan stable exports and a bounded direct-call graph for image data references.

Return Value:

    Number of unique address/routine pairs stored in References.

--*/
{
    KswRuntimeRoutineWork work[KSW_RUNTIME_SIGNATURE_MAX_ROUTINES];
    ULONG workCount = 0UL;
    ULONG workIndex = 0UL;
    ULONG referenceCount = 0UL;
    ULONG anchorIndex = 0UL;

    if (view == NULL || anchorNames == NULL || anchorCount == 0UL ||
        routineScanBytes == 0UL || references == NULL || referenceCapacity == 0UL) {
        return 0UL;
    }
    RtlZeroMemory(references, (SIZE_T)referenceCapacity * sizeof(*references));
    RtlZeroMemory(work, sizeof(work));

    for (anchorIndex = 0UL;
         anchorIndex < anchorCount && workCount < RTL_NUMBER_OF(work);
         ++anchorIndex) {
        ULONG_PTR address = (ULONG_PTR)kswordArkRuntimeFindExport(
            view,
            anchorNames[anchorIndex]);
        ULONG index = 0UL;
        BOOLEAN duplicate = FALSE;

        if (address == 0U || !kswordArkRuntimeAddressIsExecutable(view, address, 1U)) {
            continue;
        }
        for (index = 0UL; index < workCount; ++index) {
            if (work[index].address == address) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate) {
            work[workCount].address = address;
            work[workCount].depth = 0UL;
            workCount += 1UL;
        }
    }

    while (workIndex < workCount && referenceCount < referenceCapacity) {
        ULONG_PTR branches[KSW_RUNTIME_SIGNATURE_MAX_ROUTINES];
        ULONG branchCount = 0UL;
        ULONG branchIndex = 0UL;

        RtlZeroMemory(branches, sizeof(branches));
        branchCount = kswordArkRuntimeScanRoutine(
            view,
            work[workIndex].address,
            routineScanBytes,
            references,
            referenceCapacity,
            &referenceCount,
            branches,
            RTL_NUMBER_OF(branches));
        if (work[workIndex].depth < maxCallDepth) {
            for (branchIndex = 0UL;
                 branchIndex < branchCount && workCount < RTL_NUMBER_OF(work);
                 ++branchIndex) {
                ULONG existingIndex = 0UL;
                BOOLEAN duplicate = FALSE;

                for (existingIndex = 0UL; existingIndex < workCount; ++existingIndex) {
                    if (work[existingIndex].address == branches[branchIndex]) {
                        duplicate = TRUE;
                        break;
                    }
                }
                if (!duplicate) {
                    work[workCount].address = branches[branchIndex];
                    work[workCount].depth = work[workIndex].depth + 1UL;
                    workCount += 1UL;
                }
            }
        }
        workIndex += 1UL;
    }
    return referenceCount;
}

ULONG
kswordArkRuntimeCollectExecutableDataReferences(
    _In_ const KswRuntimeImageView* view,
    _In_ ULONG scanByteBudget,
    _Out_writes_(referenceCapacity) KswRuntimeDataReference* references,
    _In_ ULONG referenceCapacity
    )
/*++

Routine Description:

    Scan executable PE sections when a module exposes no stable public anchor.
    The caller supplies a global byte budget and must still perform unique,
    feature-specific live validation before using any reference.

Return Value:

    Number of stored unique address/section-start pairs.

--*/
{
    ULONG referenceCount = 0UL;
    ULONG scannedBytes = 0UL;
    ULONG sectionIndex = 0UL;

    if (view == NULL || scanByteBudget == 0UL || references == NULL ||
        referenceCapacity == 0UL) {
        return 0UL;
    }
    RtlZeroMemory(references, (SIZE_T)referenceCapacity * sizeof(*references));
    for (sectionIndex = 0UL;
         sectionIndex < view->sectionCount && scannedBytes < scanByteBudget &&
             referenceCount < referenceCapacity;
         ++sectionIndex) {
        const KswRuntimeImageSection* section = &view->sections[sectionIndex];
        ULONG sectionBytes = 0UL;
        ULONG remainingBudget = scanByteBudget - scannedBytes;

        if ((section->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            section->end <= section->start) {
            continue;
        }
        sectionBytes = (ULONG)min(
            section->end - section->start,
            (ULONG_PTR)remainingBudget);
        (VOID)kswordArkRuntimeScanRoutine(
            view,
            section->start,
            sectionBytes,
            references,
            referenceCapacity,
            &referenceCount,
            NULL,
            0UL);
        scannedBytes += sectionBytes;
    }
    return referenceCount;
}

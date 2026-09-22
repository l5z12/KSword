/*++

Module Name:

    ssdt_fallback.c

Abstract:

    Identity-bound runtime fallback for KeServiceDescriptorTableShadow. The
    resolver follows references from the exported KeAddSystemServiceTable
    anchor and accepts only one writable descriptor array whose native and GUI
    service tables both pass live semantic validation.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>
#include <ntimage.h>
#include "ssdt_fallback.h"
#include "../../platform/runtime_signature_scan.h"

#define KSW_SSDT_FALLBACK_REFERENCE_CAPACITY 128UL
#define KSW_SSDT_FALLBACK_ROUTINE_SCAN_BYTES 0x0300UL
#define KSW_SSDT_FALLBACK_MIN_NATIVE_SERVICES 0x0080UL
#define KSW_SSDT_FALLBACK_MAX_NATIVE_SERVICES 0x2000UL
#define KSW_SSDT_FALLBACK_MIN_GUI_SERVICES 0x0080UL
#define KSW_SSDT_FALLBACK_MAX_GUI_SERVICES 0x4000UL
#define KSW_SSDT_FALLBACK_SAMPLE_COUNT 8UL
#define KSW_SSDT_FALLBACK_REQUIRED_NATIVE_SAMPLES 5UL
#define KSW_SSDT_FALLBACK_REQUIRED_GUI_SAMPLES 4UL

#if defined(_M_AMD64)

typedef struct KswSsdtFallbackDescriptor
{
    PVOID serviceTableBase;
    PVOID serviceCounterTableBase;
    ULONG_PTR numberOfServices;
    PVOID paramTableBase;
} KswSsdtFallbackDescriptor, *PkswSsdtFallbackDescriptor;

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_ PVOID pcValue,
    _Outptr_ PVOID* baseOfImage
    );

static BOOLEAN
kswordArkDriverSsdtReadImageSize(
    _In_ PVOID imageBase,
    _Out_ ULONG* imageSizeOut
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG_PTR ntHeaderAddress = 0U;

    if (imageBase == NULL || imageSizeOut == NULL) {
        return FALSE;
    }
    *imageSizeOut = 0UL;
    if (!kswordArkRuntimeReadMemory(imageBase, &dosHeader, sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 || dosHeader.e_lfanew > 0x00100000L) {
        return FALSE;
    }
    ntHeaderAddress = (ULONG_PTR)imageBase + (ULONG)dosHeader.e_lfanew;
    if (ntHeaderAddress < (ULONG_PTR)imageBase ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)ntHeaderAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage < 0x1000UL) {
        return FALSE;
    }
    *imageSizeOut = ntHeaders.OptionalHeader.SizeOfImage;
    return TRUE;
}

static BOOLEAN
kswordArkDriverSsdtAddressIsExecutableImageCode(
    _In_ ULONG_PTR address,
    _In_opt_ const KswRuntimeImageView* requiredImage
    )
{
    PVOID imageBase = NULL;
    ULONG imageSize = 0UL;
    KswRuntimeImageView imageView;

    if (address < (ULONG_PTR)MmSystemRangeStart ||
        RtlPcToFileHeader((PVOID)address, &imageBase) == NULL ||
        imageBase == NULL ||
        (requiredImage != NULL && (ULONG_PTR)imageBase != requiredImage->base) ||
        !kswordArkDriverSsdtReadImageSize(imageBase, &imageSize) ||
        !kswordArkRuntimeInitializeImageView(imageBase, imageSize, &imageView)) {
        return FALSE;
    }
    return kswordArkRuntimeAddressIsExecutable(&imageView, address, 1U);
}

static ULONG_PTR
kswordArkDriverSsdtDecodeRoutine(
    _In_ ULONG_PTR serviceTableBase,
    _In_ ULONG serviceIndex
    )
{
    LONG encodedOffset = 0L;
    LONG_PTR signedOffset = 0;

    if (serviceTableBase < (ULONG_PTR)MmSystemRangeStart ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)(serviceTableBase + ((ULONG_PTR)serviceIndex * sizeof(LONG))),
            &encodedOffset,
            sizeof(encodedOffset))) {
        return 0U;
    }
    signedOffset = ((LONG_PTR)encodedOffset) >> 4;
    if (signedOffset > 0 && serviceTableBase > MAXULONG_PTR - (ULONG_PTR)signedOffset) {
        return 0U;
    }
    if (signedOffset < 0 && serviceTableBase < (ULONG_PTR)(-signedOffset)) {
        return 0U;
    }
    return (ULONG_PTR)((LONG_PTR)serviceTableBase + signedOffset);
}

static BOOLEAN
kswordArkDriverSsdtValidateTable(
    _In_ const KswSsdtFallbackDescriptor* descriptor,
    _In_ ULONG minimumServices,
    _In_ ULONG maximumServices,
    _In_ ULONG requiredSamples,
    _In_opt_ const KswRuntimeImageView* requiredImage,
    _In_ BOOLEAN rejectRequiredImage
    )
{
    ULONG sampleIndex = 0UL;
    ULONG validSamples = 0UL;
    ULONG serviceCount = 0UL;
    ULONG_PTR tableBase = 0U;

    if (descriptor == NULL || descriptor->serviceTableBase == NULL ||
        descriptor->numberOfServices < minimumServices ||
        descriptor->numberOfServices > maximumServices ||
        descriptor->numberOfServices > MAXULONG) {
        return FALSE;
    }
    serviceCount = (ULONG)descriptor->numberOfServices;
    tableBase = (ULONG_PTR)descriptor->serviceTableBase;
    if (tableBase < (ULONG_PTR)MmSystemRangeStart ||
        (tableBase & (sizeof(LONG) - 1U)) != 0U) {
        return FALSE;
    }

    for (sampleIndex = 0UL; sampleIndex < KSW_SSDT_FALLBACK_SAMPLE_COUNT; ++sampleIndex) {
        const ULONG kServiceIndex = (ULONG)(((ULONG64)(serviceCount - 1UL) * sampleIndex) /
            (KSW_SSDT_FALLBACK_SAMPLE_COUNT - 1UL));
        const ULONG_PTR kRoutineAddress = kswordArkDriverSsdtDecodeRoutine(
            tableBase,
            kServiceIndex);
        PVOID routineImage = NULL;

        if (kRoutineAddress == 0U ||
            !kswordArkDriverSsdtAddressIsExecutableImageCode(
                kRoutineAddress,
                rejectRequiredImage ? NULL : requiredImage)) {
            continue;
        }
        if (rejectRequiredImage && requiredImage != NULL) {
            if (RtlPcToFileHeader((PVOID)kRoutineAddress, &routineImage) == NULL ||
                routineImage == NULL ||
                (ULONG_PTR)routineImage == requiredImage->base) {
                continue;
            }
        }
        validSamples += 1UL;
    }
    return validSamples >= requiredSamples;
}

static BOOLEAN
kswordArkDriverSsdtValidateCandidate(
    _In_ const KswRuntimeImageView* ntoskrnlView,
    _In_ ULONG_PTR candidateAddress
    )
{
    KswSsdtFallbackDescriptor descriptors[2];

    if (ntoskrnlView == NULL ||
        !kswordArkRuntimeAddressIsWritableData(
            ntoskrnlView,
            candidateAddress,
            sizeof(descriptors)) ||
        !kswordArkRuntimeReadMemory(
            (const VOID*)candidateAddress,
            descriptors,
            sizeof(descriptors))) {
        return FALSE;
    }
    if (!kswordArkDriverSsdtValidateTable(
            &descriptors[0],
            KSW_SSDT_FALLBACK_MIN_NATIVE_SERVICES,
            KSW_SSDT_FALLBACK_MAX_NATIVE_SERVICES,
            KSW_SSDT_FALLBACK_REQUIRED_NATIVE_SAMPLES,
            ntoskrnlView,
            FALSE)) {
        return FALSE;
    }
    return kswordArkDriverSsdtValidateTable(
        &descriptors[1],
        KSW_SSDT_FALLBACK_MIN_GUI_SERVICES,
        KSW_SSDT_FALLBACK_MAX_GUI_SERVICES,
        KSW_SSDT_FALLBACK_REQUIRED_GUI_SAMPLES,
        ntoskrnlView,
        TRUE);
}

#endif

LONG
kswordArkDriverResolveShadowSsdtRva(
    _In_ const KSW_DYN_MODULE_IDENTITY_PACKET* ntoskrnlIdentity
    )
/*++

Routine Description:

    Follow the stable KeAddSystemServiceTable export into its bounded call
    graph, validate every referenced writable address as a two-entry service
    descriptor array, and publish only a unique match.

Arguments:

    NtoskrnlIdentity - Current loaded ntoskrnl identity and image bounds.

Return Value:

    Non-negative image RVA for one validated shadow table, or -1 when missing
    or ambiguous.

--*/
{
#if !defined(_M_AMD64)
    UNREFERENCED_PARAMETER(NtoskrnlIdentity);
    return -1;
#else
    static PCSTR const kAnchors[] = { "KeAddSystemServiceTable" };
    KswRuntimeImageView imageView;
    KswRuntimeDataReference references[KSW_SSDT_FALLBACK_REFERENCE_CAPACITY];
    ULONG referenceCount = 0UL;
    ULONG referenceIndex = 0UL;
    ULONG_PTR uniqueAddress = 0U;

    if (ntoskrnlIdentity == NULL || ntoskrnlIdentity->present == 0UL ||
        ntoskrnlIdentity->imageBase == 0ULL ||
        ntoskrnlIdentity->sizeOfImage == 0UL ||
        !kswordArkRuntimeInitializeImageView(
            (PVOID)(ULONG_PTR)ntoskrnlIdentity->imageBase,
            ntoskrnlIdentity->sizeOfImage,
            &imageView)) {
        return -1;
    }

    RtlZeroMemory(references, sizeof(references));
    referenceCount = kswordArkRuntimeCollectAnchoredDataReferences(
        &imageView,
        kAnchors,
        RTL_NUMBER_OF(kAnchors),
        1UL,
        KSW_SSDT_FALLBACK_ROUTINE_SCAN_BYTES,
        references,
        RTL_NUMBER_OF(references));
    for (referenceIndex = 0UL; referenceIndex < referenceCount; ++referenceIndex) {
        const ULONG_PTR kCandidateAddress = references[referenceIndex].address;

        if (!kswordArkDriverSsdtValidateCandidate(&imageView, kCandidateAddress)) {
            continue;
        }
        if (uniqueAddress == 0U) {
            uniqueAddress = kCandidateAddress;
        }
        else if (uniqueAddress != kCandidateAddress) {
            return -1;
        }
    }

    if (uniqueAddress == 0U || uniqueAddress < imageView.base ||
        uniqueAddress - imageView.base > MAXLONG) {
        return -1;
    }
    return (LONG)(uniqueAddress - imageView.base);
#endif
}

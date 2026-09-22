/*++

Module Name:

    bugcheck_bgp.c

Abstract:

    Fail-closed physical-machine BGP resolver and crash-time drawing adapter.
    The private-kernel feature resolver follows the DriverGUI BgpDraw backend.

--*/

#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#include <aux_klib.h>
#include <ntimage.h>

#include "generated/bgp_signatures.h"

#define KSWORD_ARK_BGP_POOL_TAG 'pBgK'
#define KSWORD_ARK_BGP_SCAN_POOL_TAG 'sBgK'
#define KSWORD_ARK_BGP_MAX_IMAGE_SECTIONS 96UL
#define KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE (64UL * 1024UL)
#define KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES \
    (KSWORD_ARK_BGP_FEATURE_CLEAR | KSWORD_ARK_BGP_FEATURE_DRAW | \
     KSWORD_ARK_BGP_FEATURE_ACQUIRE | KSWORD_ARK_BGP_FEATURE_RELEASE | \
     KSWORD_ARK_BGP_FEATURE_RESOLUTION | KSWORD_ARK_BGP_FEATURE_BPP | \
     KSWORD_ARK_BGP_FEATURE_PARSE | KSWORD_ARK_BGP_FEATURE_DESTROY)

typedef struct KswordArkBgpImageSection
{
    UCHAR name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG virtualAddress;
    ULONG virtualSize;
    ULONG characteristics;
} KswordArkBgpImageSection, *PkswordArkBgpImageSection;

typedef struct KswordArkBgpImageView
{
    PUCHAR imageBase;
    ULONG imageSize;
    ULONG sectionCount;
    KswordArkBgpImageSection sections[KSWORD_ARK_BGP_MAX_IMAGE_SECTIONS];
} KswordArkBgpImageView, *PkswordArkBgpImageView;

KswordArkBgpContext gKswordArkBgp;

VOID
kswordArkBugcheckBgpRecordStage(
    _In_ LONG stage,
    _In_ NTSTATUS status
    )
{
    LONG timelineIndex;

    timelineIndex = InterlockedIncrement(&gKswordArkBgp.timelineCount) - 1;
    InterlockedExchange(&gKswordArkBgp.stage, stage);
    if (timelineIndex >= 0 &&
        timelineIndex < (LONG)RTL_NUMBER_OF(gKswordArkBgp.timeline)) {
        InterlockedExchange(
            &gKswordArkBgp.timeline[timelineIndex].status,
            (LONG)status);
        InterlockedExchange(
            &gKswordArkBgp.timeline[timelineIndex].stage,
            stage);
    }
}

static PVOID
kswordArkBugcheckBgpGetExport(
    _In_z_ PCWSTR name
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, name);
    return MmGetSystemRoutineAddress(&routineName);
}

static BOOLEAN
kswordArkBugcheckBgpRvaRangeValid(
    _In_ ULONG imageSize,
    _In_ ULONG rva,
    _In_ SIZE_T requiredBytes
    )
{
    return imageSize != 0UL &&
        requiredBytes != 0U &&
        rva < imageSize &&
        requiredBytes <= (SIZE_T)(imageSize - rva);
}

static BOOLEAN
kswordArkBugcheckBgpAddressForRva(
    _In_ const KswordArkBgpImageView* view,
    _In_ ULONG rva,
    _In_ SIZE_T requiredBytes,
    _Out_ PUCHAR* addressOut
    )
{
    ULONG_PTR base;

    if (view == NULL || addressOut == NULL || view->imageBase == NULL ||
        !kswordArkBugcheckBgpRvaRangeValid(
            view->imageSize,
            rva,
            requiredBytes)) {
        return FALSE;
    }

    base = (ULONG_PTR)view->imageBase;
    if (base > MAXULONG_PTR - rva) {
        return FALSE;
    }
    *addressOut = (PUCHAR)(base + rva);
    return TRUE;
}

static BOOLEAN
kswordArkBugcheckBgpInitializeImageView(
    _In_reads_bytes_(imageSize) PUCHAR imageBase,
    _In_ ULONG imageSize,
    _Out_ PkswordArkBgpImageView view
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG ntHeadersRva;
    ULONG sectionHeadersRva;
    ULONG sectionHeadersBytes;
    ULONG sectionIndex;
    ULONG_PTR base;
    PUCHAR ntHeadersAddress;

    if (view == NULL) {
        return FALSE;
    }
    RtlZeroMemory(view, sizeof(*view));
    if (imageBase == NULL || imageSize < sizeof(dosHeader) ||
        !kswordArkRuntimeReadMemory(
            imageBase,
            &dosHeader,
            sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0) {
        return FALSE;
    }

    base = (ULONG_PTR)imageBase;
    ntHeadersRva = (ULONG)dosHeader.e_lfanew;
    if (!kswordArkBugcheckBgpRvaRangeValid(
            imageSize,
            ntHeadersRva,
            sizeof(ntHeaders)) ||
        base > MAXULONG_PTR - ntHeadersRva) {
        return FALSE;
    }
    ntHeadersAddress = (PUCHAR)(base + ntHeadersRva);
    if (!kswordArkRuntimeReadMemory(
            ntHeadersAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders.FileHeader.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64) ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL ||
        ntHeaders.OptionalHeader.SizeOfImage > imageSize ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections >
            KSWORD_ARK_BGP_MAX_IMAGE_SECTIONS) {
        return FALSE;
    }

    if (ntHeadersRva >
            MAXULONG - FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) ||
        ntHeadersRva + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) >
            MAXULONG - ntHeaders.FileHeader.SizeOfOptionalHeader) {
        return FALSE;
    }
    sectionHeadersRva =
        ntHeadersRva +
        FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    sectionHeadersBytes =
        (ULONG)ntHeaders.FileHeader.NumberOfSections *
        (ULONG)sizeof(IMAGE_SECTION_HEADER);
    if (!kswordArkBugcheckBgpRvaRangeValid(
            ntHeaders.OptionalHeader.SizeOfImage,
            sectionHeadersRva,
            sectionHeadersBytes)) {
        return FALSE;
    }

    if (base > MAXULONG_PTR - ntHeaders.OptionalHeader.SizeOfImage) {
        return FALSE;
    }
    view->imageBase = imageBase;
    view->imageSize = ntHeaders.OptionalHeader.SizeOfImage;

    for (sectionIndex = 0;
         sectionIndex < ntHeaders.FileHeader.NumberOfSections;
         ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        PkswordArkBgpImageSection section;
        ULONG sectionHeaderRva;
        ULONG sectionSize;
        ULONG priorIndex;
        PUCHAR sectionHeaderAddress;

        sectionHeaderRva = sectionHeadersRva +
            sectionIndex * (ULONG)sizeof(sectionHeader);
        if (!kswordArkBugcheckBgpRvaRangeValid(
                view->imageSize,
                sectionHeaderRva,
                sizeof(sectionHeader)) ||
            !kswordArkBugcheckBgpAddressForRva(
                view,
                sectionHeaderRva,
                sizeof(sectionHeader),
                &sectionHeaderAddress) ||
            !kswordArkRuntimeReadMemory(
                sectionHeaderAddress,
                &sectionHeader,
                sizeof(sectionHeader))) {
            RtlZeroMemory(view, sizeof(*view));
            return FALSE;
        }

        sectionSize = max(
            sectionHeader.Misc.VirtualSize,
            sectionHeader.SizeOfRawData);
        if (sectionSize == 0UL) {
            continue;
        }
        if (!kswordArkBugcheckBgpRvaRangeValid(
                view->imageSize,
                sectionHeader.VirtualAddress,
                sectionSize)) {
            RtlZeroMemory(view, sizeof(*view));
            return FALSE;
        }

        for (priorIndex = 0;
             priorIndex < view->sectionCount;
             ++priorIndex) {
            const KswordArkBgpImageSection* prior;
            ULONG priorEnd;
            ULONG sectionEnd;

            prior = &view->sections[priorIndex];
            priorEnd = prior->virtualAddress + prior->virtualSize;
            sectionEnd = sectionHeader.VirtualAddress + sectionSize;
            if (sectionHeader.VirtualAddress < priorEnd &&
                prior->virtualAddress < sectionEnd) {
                RtlZeroMemory(view, sizeof(*view));
                return FALSE;
            }
        }

        section = &view->sections[view->sectionCount++];
        RtlCopyMemory(
            section->name,
            sectionHeader.Name,
            sizeof(section->name));
        section->virtualAddress = sectionHeader.VirtualAddress;
        section->virtualSize = sectionSize;
        section->characteristics = sectionHeader.Characteristics;
    }

    if (view->sectionCount == 0UL) {
        RtlZeroMemory(view, sizeof(*view));
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
kswordArkBugcheckBgpAddressInSection(
    _In_ const KswordArkBgpImageView* view,
    _In_opt_ PVOID address,
    _In_ SIZE_T requiredBytes,
    _In_ BOOLEAN allowPaged
    )
{
    ULONG_PTR addressValue;
    ULONG_PTR imageBase;
    ULONG_PTR addressRva;
    ULONG sectionIndex;

    if (view == NULL || view->imageBase == NULL || address == NULL ||
        requiredBytes == 0U) {
        return FALSE;
    }
    addressValue = (ULONG_PTR)address;
    imageBase = (ULONG_PTR)view->imageBase;
    if (addressValue < imageBase) {
        return FALSE;
    }
    addressRva = addressValue - imageBase;
    if (addressRva > MAXULONG ||
        !kswordArkBugcheckBgpRvaRangeValid(
            view->imageSize,
            (ULONG)addressRva,
            requiredBytes)) {
        return FALSE;
    }

    for (sectionIndex = 0;
         sectionIndex < view->sectionCount;
         ++sectionIndex) {
        const KswordArkBgpImageSection* section;
        ULONG offsetInSection;

        section = &view->sections[sectionIndex];
        if ((ULONG)addressRva < section->virtualAddress ||
            (ULONG)addressRva >=
                section->virtualAddress + section->virtualSize) {
            continue;
        }
        offsetInSection = (ULONG)addressRva - section->virtualAddress;
        if (requiredBytes >
                (SIZE_T)(section->virtualSize - offsetInSection) ||
            (section->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            (section->characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0UL ||
            (!allowPaged &&
             (section->characteristics & IMAGE_SCN_MEM_NOT_PAGED) == 0UL)) {
            return FALSE;
        }
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
kswordArkBugcheckBgpMatches(
    _In_reads_bytes_(signature->length) const UCHAR* address,
    _In_ const BgpSignature* signature
    )
{
    ULONG byteIndex;

    for (byteIndex = 0; byteIndex < signature->length; ++byteIndex) {
        if (signature->mask[byteIndex] == 'x' &&
            address[byteIndex] != signature->bytes[byteIndex]) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
kswordArkBugcheckBgpSectionNameMatches(
    _In_reads_(IMAGE_SIZEOF_SHORT_NAME) const UCHAR* actual,
    _In_z_ const CHAR* expected
    )
{
    ULONG characterIndex;

    for (characterIndex = 0;
         characterIndex < IMAGE_SIZEOF_SHORT_NAME;
         ++characterIndex) {
        if ((CHAR)actual[characterIndex] != expected[characterIndex]) {
            return FALSE;
        }
        if (actual[characterIndex] == '\0') {
            return TRUE;
        }
    }

    return expected[IMAGE_SIZEOF_SHORT_NAME] == '\0';
}

static BOOLEAN
kswordArkBugcheckBgpDecodeRelativeCallAt(
    _In_reads_bytes_(length) const UCHAR* bytes,
    _In_ ULONG length,
    _In_ ULONG offset,
    _In_ ULONG_PTR originalAddress,
    _Out_ PVOID* targetOut
    )
{
    LONG displacement;
    ULONG_PTR nextInstruction;
    ULONG_PTR target;
    ULONG_PTR magnitude;

    if (bytes == NULL || targetOut == NULL || offset > length ||
        length - offset < 5UL || bytes[offset] != 0xE8U ||
        originalAddress > MAXULONG_PTR - offset) {
        return FALSE;
    }
    *targetOut = NULL;

    nextInstruction = originalAddress + offset;
    if (nextInstruction > MAXULONG_PTR - 5UL) {
        return FALSE;
    }
    nextInstruction += 5UL;
    RtlCopyMemory(&displacement, bytes + offset + 1UL, sizeof(displacement));

    if (displacement >= 0) {
        if (nextInstruction > MAXULONG_PTR - (ULONG)displacement) {
            return FALSE;
        }
        target = nextInstruction + (ULONG)displacement;
    } else {
        magnitude = (ULONG_PTR)(-(LONGLONG)displacement);
        if (nextInstruction < magnitude) {
            return FALSE;
        }
        target = nextInstruction - magnitude;
    }

    *targetOut = (PVOID)target;
    return TRUE;
}

static VOID
kswordArkBugcheckBgpAcceptSignatureMatch(
    _In_ const KswordArkBgpImageView* view,
    _In_ const BgpSignature* signature,
    _In_ PUCHAR originalMatch,
    _In_reads_bytes_(signature->length) const UCHAR* snapshotMatch,
    _Inout_updates_(BgpSignatureCount) PVOID* addresses,
    _Inout_updates_(BgpSignatureCount) const BgpSignature** matchedSignatures,
    _Inout_updates_(BgpSignatureCount) PVOID* directCallTargets,
    _Inout_updates_(BgpSignatureCount) BOOLEAN* ambiguous
    )
{
    PVOID directCallTarget;
    PVOID resolvedAddress;
    ULONG_PTR matchAddress;
    ULONG targetIndex;

    if (view == NULL || signature == NULL || originalMatch == NULL ||
        snapshotMatch == NULL || addresses == NULL ||
        matchedSignatures == NULL || directCallTargets == NULL ||
        ambiguous == NULL) {
        return;
    }

    targetIndex = signature->target;
    matchAddress = (ULONG_PTR)originalMatch;
    if (targetIndex >= kBgpSignatureCount ||
        matchAddress < signature->entryOffset) {
        return;
    }
    resolvedAddress = (PVOID)(matchAddress - signature->entryOffset);
    if (!kswordArkBugcheckBgpAddressInSection(
            view,
            resolvedAddress,
            1U,
            signature->allowPaged)) {
        return;
    }

    directCallTarget = NULL;
    if (signature->directCallOffset != MAXULONG) {
        if (!kswordArkBugcheckBgpDecodeRelativeCallAt(
                snapshotMatch,
                signature->length,
                signature->directCallOffset,
                matchAddress,
                &directCallTarget) ||
            !kswordArkBugcheckBgpAddressInSection(
                view,
                directCallTarget,
                1U,
                TRUE)) {
            return;
        }
    } else if ((signature->semanticFlags &
                BGP_SEMANTIC_REQUIRE_DIRECT_CALL) != 0UL) {
        return;
    }

    if (addresses[targetIndex] == NULL) {
        addresses[targetIndex] = resolvedAddress;
        matchedSignatures[targetIndex] = signature;
        directCallTargets[targetIndex] = directCallTarget;
    } else if (addresses[targetIndex] != resolvedAddress ||
               directCallTargets[targetIndex] != directCallTarget) {
        ambiguous[targetIndex] = TRUE;
    }
}

static NTSTATUS
kswordArkBugcheckBgpValidateSignatureTable(
    _Out_ PULONG maximumAnchorPrefix,
    _Out_ PULONG maximumAnchorSuffix
    )
{
    ULONG bucketIndex;
    ULONG signatureIndex;

    if (maximumAnchorPrefix == NULL || maximumAnchorSuffix == NULL ||
        BGP_SIGNATURE_ANCHOR_BUCKETS == 0UL ||
        (BGP_SIGNATURE_ANCHOR_BUCKETS &
         (BGP_SIGNATURE_ANCHOR_BUCKETS - 1UL)) != 0UL ||
        kGBgpSignatureAnchorBuckets[0] != 0UL ||
        kGBgpSignatureAnchorBuckets[BGP_SIGNATURE_ANCHOR_BUCKETS] !=
            BGP_SIGNATURE_TABLE_COUNT) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *maximumAnchorPrefix = 0UL;
    *maximumAnchorSuffix = 0UL;
    for (bucketIndex = 0;
         bucketIndex < BGP_SIGNATURE_ANCHOR_BUCKETS;
         ++bucketIndex) {
        if (kGBgpSignatureAnchorBuckets[bucketIndex] >
                kGBgpSignatureAnchorBuckets[bucketIndex + 1UL] ||
            kGBgpSignatureAnchorBuckets[bucketIndex + 1UL] >
                BGP_SIGNATURE_TABLE_COUNT) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    for (signatureIndex = 0;
         signatureIndex < BGP_SIGNATURE_TABLE_COUNT;
         ++signatureIndex) {
        const BgpSignature* signature;
        ULONG nameIndex;
        ULONG anchorSuffix;
        BOOLEAN sectionNameTerminated;

        signature = &kGBgpSignatures[signatureIndex];
        sectionNameTerminated = FALSE;
        if (signature->section != NULL) {
            for (nameIndex = 0;
                 nameIndex <= IMAGE_SIZEOF_SHORT_NAME;
                 ++nameIndex) {
                if (signature->section[nameIndex] == '\0') {
                    sectionNameTerminated = TRUE;
                    break;
                }
            }
        }

        if (signature->bytes == NULL || signature->mask == NULL ||
            !sectionNameTerminated || signature->length < sizeof(ULONG) ||
            signature->anchorOffset >
                signature->length - sizeof(ULONG) ||
            signature->target >= kBgpSignatureCount ||
            (signature->directCallOffset != MAXULONG &&
             (signature->directCallOffset > signature->length ||
              signature->length - signature->directCallOffset < 5UL)) ||
            ((signature->semanticFlags &
              BGP_SEMANTIC_REQUIRE_DIRECT_CALL) != 0UL &&
             signature->directCallOffset == MAXULONG)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        anchorSuffix = signature->length - signature->anchorOffset;
        *maximumAnchorPrefix = max(
            *maximumAnchorPrefix,
            signature->anchorOffset);
        *maximumAnchorSuffix = max(
            *maximumAnchorSuffix,
            anchorSuffix);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckBgpScanSignatures(
    _In_ const KswordArkBgpImageView* view,
    _Inout_updates_(BgpSignatureCount) PVOID* addresses,
    _Inout_updates_(BgpSignatureCount) const BgpSignature** matchedSignatures,
    _Inout_updates_(BgpSignatureCount) PVOID* directCallTargets,
    _Inout_updates_(BgpSignatureCount) BOOLEAN* ambiguous
    )
{
    PUCHAR snapshot;
    ULONG maximumAnchorPrefix;
    ULONG maximumAnchorSuffix;
    ULONG snapshotCapacity;
    ULONG sectionIndex;
    NTSTATUS status;

    if (view == NULL || addresses == NULL || matchedSignatures == NULL ||
        directCallTargets == NULL || ambiguous == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    maximumAnchorPrefix = 0UL;
    maximumAnchorSuffix = 0UL;
    status = kswordArkBugcheckBgpValidateSignatureTable(
        &maximumAnchorPrefix,
        &maximumAnchorSuffix);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE >
            MAXULONG - maximumAnchorPrefix ||
        KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE + maximumAnchorPrefix >
            MAXULONG - maximumAnchorSuffix) {
        return STATUS_INTEGER_OVERFLOW;
    }
    snapshotCapacity =
        KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE +
        maximumAnchorPrefix +
        maximumAnchorSuffix;
    snapshot = (PUCHAR)kswordArkAllocateNonPagedPool(
        snapshotCapacity,
        KSWORD_ARK_BGP_SCAN_POOL_TAG);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    for (sectionIndex = 0;
         sectionIndex < view->sectionCount;
         ++sectionIndex) {
        const KswordArkBgpImageSection* section;
        ULONG scanLimit;
        ULONG scanStart;
        ULONG signatureIndex;
        BOOLEAN relevantSection;

        section = &view->sections[sectionIndex];
        if ((section->characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            (section->characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0UL ||
            section->virtualSize < sizeof(ULONG)) {
            continue;
        }

        relevantSection = FALSE;
        for (signatureIndex = 0;
             signatureIndex < BGP_SIGNATURE_TABLE_COUNT;
             ++signatureIndex) {
            if (kswordArkBugcheckBgpSectionNameMatches(
                    section->name,
                    kGBgpSignatures[signatureIndex].section)) {
                relevantSection = TRUE;
                break;
            }
        }
        if (!relevantSection) {
            continue;
        }

        scanLimit = section->virtualSize - sizeof(ULONG) + 1UL;
        scanStart = 0UL;
        while (scanStart < scanLimit) {
            PUCHAR sourceAddress;
            NTSTATUS abortStatus;
            ULONG scanEnd;
            ULONG readStart;
            ULONG readEnd;
            ULONG readBytes;
            ULONG anchorPosition;

            // Each 64 KiB snapshot block is a cancellable boundary; unloading no longer waits for the full kernel image scan to complete.
            abortStatus = kswordArkBugcheckControlCheckAbort();
            if (!NT_SUCCESS(abortStatus)) {
                status = abortStatus;
                goto Exit;
            }

            scanEnd = scanStart + min(
                KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE,
                scanLimit - scanStart);
            readStart = scanStart > maximumAnchorPrefix
                ? scanStart - maximumAnchorPrefix
                : 0UL;
            readEnd = scanEnd;
            if (maximumAnchorSuffix > section->virtualSize - readEnd) {
                readEnd = section->virtualSize;
            } else {
                readEnd += maximumAnchorSuffix;
            }
            readBytes = readEnd - readStart;
            if (readBytes == 0UL || readBytes > snapshotCapacity ||
                section->virtualAddress > MAXULONG - readStart ||
                !kswordArkBugcheckBgpAddressForRva(
                    view,
                    section->virtualAddress + readStart,
                    readBytes,
                    &sourceAddress)) {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto Exit;
            }
            if (!kswordArkRuntimeReadMemory(
                    sourceAddress,
                    snapshot,
                    readBytes)) {
                status = STATUS_PARTIAL_COPY;
                goto Exit;
            }

            for (anchorPosition = scanStart;
                 anchorPosition < scanEnd;
                 ++anchorPosition) {
                ULONG anchor;
                ULONG anchorSnapshotOffset;
                ULONG bucket;
                ULONG bucketEnd;

                anchorSnapshotOffset = anchorPosition - readStart;
                if (anchorSnapshotOffset > readBytes ||
                    readBytes - anchorSnapshotOffset < sizeof(anchor)) {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    goto Exit;
                }
                RtlCopyMemory(
                    &anchor,
                    snapshot + anchorSnapshotOffset,
                    sizeof(anchor));
                bucket = anchor & (BGP_SIGNATURE_ANCHOR_BUCKETS - 1UL);
                signatureIndex = kGBgpSignatureAnchorBuckets[bucket];
                bucketEnd = kGBgpSignatureAnchorBuckets[bucket + 1UL];
                for (;
                     signatureIndex < bucketEnd;
                     ++signatureIndex) {
                    const BgpSignature* signature;
                    PUCHAR originalCandidate;
                    const UCHAR* snapshotCandidate;
                    ULONG candidatePosition;
                    ULONG candidateSnapshotOffset;
                    ULONG candidateRva;

                    signature = &kGBgpSignatures[signatureIndex];
                    if (signature->anchorValue != anchor ||
                        signature->anchorOffset > anchorPosition) {
                        continue;
                    }
                    candidatePosition =
                        anchorPosition - signature->anchorOffset;
                    if (signature->entryOffset > candidatePosition ||
                        signature->length >
                            section->virtualSize - candidatePosition ||
                        (!signature->allowPaged &&
                         (section->characteristics &
                          IMAGE_SCN_MEM_NOT_PAGED) == 0UL) ||
                        !kswordArkBugcheckBgpSectionNameMatches(
                            section->name,
                            signature->section) ||
                        candidatePosition < readStart) {
                        continue;
                    }

                    candidateSnapshotOffset =
                        candidatePosition - readStart;
                    if (candidateSnapshotOffset > readBytes ||
                        signature->length >
                            readBytes - candidateSnapshotOffset ||
                        section->virtualAddress >
                            MAXULONG - candidatePosition) {
                        status = STATUS_INVALID_IMAGE_FORMAT;
                        goto Exit;
                    }
                    candidateRva =
                        section->virtualAddress + candidatePosition;
                    if (!kswordArkBugcheckBgpAddressForRva(
                            view,
                            candidateRva,
                            signature->length,
                            &originalCandidate)) {
                        status = STATUS_INVALID_IMAGE_FORMAT;
                        goto Exit;
                    }

                    snapshotCandidate =
                        snapshot + candidateSnapshotOffset;
                    if (kswordArkBugcheckBgpMatches(
                            snapshotCandidate,
                            signature)) {
                        kswordArkBugcheckBgpAcceptSignatureMatch(
                            view,
                            signature,
                            originalCandidate,
                            snapshotCandidate,
                            addresses,
                            matchedSignatures,
                            directCallTargets,
                            ambiguous);
                    }
                }
            }
            scanStart = scanEnd;
        }
    }

Exit:
    ExFreePoolWithTag(snapshot, KSWORD_ARK_BGP_SCAN_POOL_TAG);
    return status;
}

static NTSTATUS
kswordArkBugcheckBgpGetKernelImage(
    _Out_ PUCHAR* imageBase,
    _Out_ PULONG imageSize
    )
{
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG requiredBytes;
    NTSTATUS status;

    *imageBase = NULL;
    *imageSize = 0;
    requiredBytes = 0;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AuxKlibQueryModuleInformation(
        &requiredBytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        NULL);
    if (!NT_SUCCESS(status) || requiredBytes < sizeof(AUX_MODULE_EXTENDED_INFO)) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    modules = (PAUX_MODULE_EXTENDED_INFO)kswordArkAllocateNonPagedPool(
        requiredBytes,
        KSWORD_ARK_BGP_POOL_TAG);
    if (modules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = AuxKlibQueryModuleInformation(
        &requiredBytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules);
    if (NT_SUCCESS(status)) {
        *imageBase = (PUCHAR)modules[0].BasicInfo.ImageBase;
        *imageSize = modules[0].ImageSize;
    }

    ExFreePoolWithTag(modules, KSWORD_ARK_BGP_POOL_TAG);
    return status;
}

static BOOLEAN
kswordArkBugcheckBgpCrashTargetsAreNonPaged(
    _In_ const KswordArkBgpImageView* view,
    _In_reads_(BgpSignatureCount) PVOID* addresses
    )
{
    const ULONG kCrashTargets[] = {
        kBgpSignatureClear,
        kBgpSignatureDraw,
        kBgpSignatureAcquire,
        kBgpSignatureRelease,
        kBgpSignatureResolution,
        kBgpSignatureBpp
    };
    ULONG targetIndex;

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(kCrashTargets);
         ++targetIndex) {
        ULONG signatureTarget;

        signatureTarget = kCrashTargets[targetIndex];
        if (!kswordArkBugcheckBgpAddressInSection(
                view,
                addresses[signatureTarget],
                1U,
                FALSE)) {
            return FALSE;
        }
    }

    return TRUE;
}

NTSTATUS
kswordArkBugcheckBgpResolveFunctions(
    VOID
    )
{
    KswordArkBgpImageView imageView;
    PUCHAR imageBase;
    ULONG imageSize;
    PVOID addresses[kBgpSignatureCount] = { NULL };
    const BgpSignature* matchedSignatures[kBgpSignatureCount] = { NULL };
    PVOID directCallTargets[kBgpSignatureCount] = { NULL };
    BOOLEAN ambiguous[kBgpSignatureCount] = { FALSE };
    PkswordArkInbvAcquireDisplayOwnership acquireOwnership;
    PVOID semanticBpp;
    NTSTATUS status;
    ULONG targetIndex;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&imageView, sizeof(imageView));
    imageBase = NULL;
    imageSize = 0;
    semanticBpp = NULL;
    InterlockedExchange(&gKswordArkBgp.resolvedSnapshotReady, 0);
    KeMemoryBarrier();
    status = kswordArkBugcheckBgpGetKernelImage(&imageBase, &imageSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!kswordArkBugcheckBgpInitializeImageView(
            imageBase,
            imageSize,
            &imageView)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    status = kswordArkBugcheckBgpScanSignatures(
        &imageView,
        addresses,
        matchedSignatures,
        directCallTargets,
        ambiguous);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        if (ambiguous[targetIndex]) {
            addresses[targetIndex] = NULL;
            matchedSignatures[targetIndex] = NULL;
            directCallTargets[targetIndex] = NULL;
        }
    }

    if (addresses[kBgpSignatureClear] != NULL &&
        addresses[kBgpSignatureDraw] != NULL &&
        directCallTargets[kBgpSignatureClear] != NULL &&
        directCallTargets[kBgpSignatureClear] ==
            directCallTargets[kBgpSignatureDraw] &&
        kswordArkBugcheckBgpAddressInSection(
            &imageView,
            directCallTargets[kBgpSignatureClear],
            1U,
            FALSE)) {
        semanticBpp = directCallTargets[kBgpSignatureClear];
    }

    // Require the BPP entry to have its own unique signature in addition to
    // being the common direct-call target of Clear and Draw.  This avoids a
    // second live image read after the bounded scan snapshot is released.
    if (semanticBpp == NULL ||
        addresses[kBgpSignatureBpp] != semanticBpp ||
        matchedSignatures[kBgpSignatureBpp] == NULL) {
        addresses[kBgpSignatureBpp] = NULL;
        matchedSignatures[kBgpSignatureBpp] = NULL;
    }

    if (!kswordArkBugcheckBgpCrashTargetsAreNonPaged(
            &imageView,
            addresses) ||
        !kswordArkBugcheckBgpAddressInSection(
            &imageView,
            addresses[kBgpSignatureParse],
            1U,
            TRUE) ||
        !kswordArkBugcheckBgpAddressInSection(
            &imageView,
            addresses[kBgpSignatureDestroy],
            1U,
            TRUE)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        if (addresses[targetIndex] == NULL ||
            matchedSignatures[targetIndex] == NULL) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }

    acquireOwnership =
        (PkswordArkInbvAcquireDisplayOwnership)
            kswordArkBugcheckBgpGetExport(L"InbvAcquireDisplayOwnership");
    if (acquireOwnership == NULL ||
        !kswordArkBugcheckBgpAddressInSection(
            &imageView,
            (PVOID)(ULONG_PTR)acquireOwnership,
            1U,
            FALSE)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Publish only after every pointer and semantic relationship has passed.
    // Bugcheck callbacks consume this fixed nonpaged context and never rescan
    // ntoskrnl or decode live instructions at HIGH_LEVEL.
    gKswordArkBgp.clear =
        (PkswordArkBgpClearScreen)addresses[kBgpSignatureClear];
    gKswordArkBgp.draw =
        (PkswordArkBgpDrawRectangle)addresses[kBgpSignatureDraw];
    gKswordArkBgp.acquire =
        (PkswordArkBgpLock)addresses[kBgpSignatureAcquire];
    gKswordArkBgp.release =
        (PkswordArkBgpLock)addresses[kBgpSignatureRelease];
    gKswordArkBgp.getResolution =
        (PkswordArkBgpGetResolution)addresses[kBgpSignatureResolution];
    gKswordArkBgp.getBpp =
        (PkswordArkBgpGetBpp)addresses[kBgpSignatureBpp];
    gKswordArkBgp.parseBitmap =
        (PkswordArkBgpParseBitmap)addresses[kBgpSignatureParse];
    gKswordArkBgp.destroyRectangle =
        (PkswordArkBgpDestroyRectangle)addresses[kBgpSignatureDestroy];
    gKswordArkBgp.acquireOwnership = acquireOwnership;
    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        gKswordArkBgp.signatureFamily[targetIndex] =
            matchedSignatures[targetIndex]->family;
    }
    gKswordArkBgp.featureMask =
        KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES |
        KSWORD_ARK_BGP_FEATURE_INBV;
    KeMemoryBarrier();
    InterlockedExchange(&gKswordArkBgp.resolvedSnapshotReady, 1);

    return STATUS_SUCCESS;
}

/*
 * The private nt!Bgp* routines are deliberately absent from the kernel GFIDS
 * table on supported systems, even though Windows itself calls them directly.
 * Keep CFG enabled for the complete driver and suppress it only in these
 * non-inlined adapters after the resolver has validated the kernel image,
 * executable/nonpaged section, signature family, semantic relationship, and
 * uniqueness of every published address.  This prevents guard_icall_bugcheck
 * without turning a missing GFIDS entry into a global BGP feature disable.
 */
static
DECLSPEC_NOINLINE
PVOID
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeGetResolution(
    _Out_ PVOID resolution
    )
{
    return gKswordArkBgp.getResolution(resolution);
}

static
DECLSPEC_NOINLINE
ULONG
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeGetBpp(
    VOID
    )
{
    return gKswordArkBgp.getBpp();
}

static
DECLSPEC_NOINLINE
VOID
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeAcquireOwnership(
    VOID
    )
{
    gKswordArkBgp.acquireOwnership();
}

static
DECLSPEC_NOINLINE
VOID
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeAcquire(
    VOID
    )
{
    gKswordArkBgp.acquire();
}

DECLSPEC_NOINLINE
VOID
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeRelease(
    VOID
    )
{
    gKswordArkBgp.release();
}

static
DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeClear(
    _In_ ULONG argbColor
    )
{
    return gKswordArkBgp.clear(argbColor);
}

static
DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeDraw(
    _In_ PVOID rectangle,
    _In_ const VOID* position
    )
{
    return gKswordArkBgp.draw(rectangle, position);
}

DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeParseBitmap(
    _In_ const VOID* bitmap,
    _Out_ PVOID* rectangle
    )
{
    return gKswordArkBgp.parseBitmap(bitmap, rectangle);
}

DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
kswordArkBugcheckBgpInvokeDestroyRectangle(
    _In_opt_ PVOID rectangle
    )
{
    return gKswordArkBgp.destroyRectangle(rectangle);
}

NTSTATUS
kswordArkBugcheckBgpReadScreen(
    _Out_ PkswordArkBgpScreenInfo screen
    )
{
    ULONG resolution[3];
    ULONG bitsPerPixel;

    RtlZeroMemory(resolution, sizeof(resolution));
    RtlZeroMemory(screen, sizeof(*screen));
    if (InterlockedCompareExchange(
            &gKswordArkBgp.resolvedSnapshotReady,
            0,
            0) == 0 ||
        gKswordArkBgp.getResolution == NULL ||
        gKswordArkBgp.getBpp == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (kswordArkBugcheckBgpInvokeGetResolution(resolution) == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    bitsPerPixel = kswordArkBugcheckBgpInvokeGetBpp();
    gKswordArkBgp.probeWidth = resolution[0];
    gKswordArkBgp.probeHeight = resolution[1];
    gKswordArkBgp.probeBpp = bitsPerPixel;
    // Treat the pre-ownership BPP sentinel as a deferred screen probe because
    // some BGP implementations also hide the resolution until ownership.
    if (bitsPerPixel == KSWORD_ARK_BGP_UNOWNED_BPP) {
        screen->width = resolution[0];
        screen->height = resolution[1];
        screen->bitsPerPixel = bitsPerPixel;
        return STATUS_SUCCESS;
    }

    // Require a complete supported mode after BGP exposes the real screen.
    if (resolution[0] == 0 ||
        resolution[1] == 0 ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_NOT_SUPPORTED;
    }

    screen->width = resolution[0];
    screen->height = resolution[1];
    screen->bitsPerPixel = bitsPerPixel;
    return STATUS_SUCCESS;
}

ULONG
kswordArkBugcheckBgpGetCurrentBpp(
    VOID
    )
{
    return gKswordArkBgp.screen.bitsPerPixel;
}

NTSTATUS
kswordArkBugcheckBgpValidateBitmap(
    _In_reads_bytes_(bitmapLength) const VOID* bitmap,
    _In_ ULONG bitmapLength
    )
{
    const KswordArkBgpBitmapFileHeader* fileHeader;
    const KswordArkBgpBitmapInfoHeader* infoHeader;
    ULONG64 rowBytes;
    ULONG64 requiredBytes;

    if (bitmap == NULL ||
        bitmapLength <
            sizeof(KswordArkBgpBitmapFileHeader) +
            sizeof(KswordArkBgpBitmapInfoHeader)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    fileHeader = (const KswordArkBgpBitmapFileHeader*)bitmap;
    infoHeader = (const KswordArkBgpBitmapInfoHeader*)(
        (const UCHAR*)bitmap + sizeof(*fileHeader));
    if (fileHeader->type != 0x4D42U ||
        fileHeader->size > bitmapLength ||
        fileHeader->size < fileHeader->pixelOffset ||
        fileHeader->pixelOffset < sizeof(*fileHeader) + sizeof(*infoHeader) ||
        infoHeader->size != sizeof(*infoHeader) ||
        infoHeader->width <= 0 ||
        infoHeader->height <= 0 ||
        infoHeader->planes != 1U ||
        infoHeader->compression != 0UL ||
        (infoHeader->bitsPerPixel != 24U &&
         infoHeader->bitsPerPixel != 32U)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (gKswordArkBgp.screen.width != 0 &&
        gKswordArkBgp.screen.height != 0 &&
        (gKswordArkBgp.screen.bitsPerPixel == 24UL ||
         gKswordArkBgp.screen.bitsPerPixel == 32UL) &&
        ((ULONG)infoHeader->width > gKswordArkBgp.screen.width ||
         (ULONG)infoHeader->height > gKswordArkBgp.screen.height)) {
        return STATUS_NOT_SUPPORTED;
    }

    rowBytes =
        (((ULONG64)(ULONG)infoHeader->width *
          infoHeader->bitsPerPixel + 31ULL) / 32ULL) * 4ULL;
    requiredBytes =
        (ULONG64)fileHeader->pixelOffset +
        rowBytes * (ULONG)infoHeader->height;
    if (rowBytes > MAXULONG ||
        requiredBytes > bitmapLength ||
        requiredBytes > fileHeader->size) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkBugcheckBgpBeginDraw(
    VOID
    )
{
    KswordArkBgpScreenInfo crashScreen;
    NTSTATUS status;

    if (InterlockedCompareExchange(&gKswordArkBgp.drawStarted, 1, 0) != 0) {
        return STATUS_DEVICE_BUSY;
    }
    KeMemoryBarrier();
    if (InterlockedCompareExchange(
            &gKswordArkBgp.resourceUpdateActive,
            0,
            0) != 0) {
        status = STATUS_DEVICE_BUSY;
        InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
        kswordArkBugcheckBgpRecordStage(
            (LONG)(kKswordArkBgpStageRejected | 4UL),
            status);
        return status;
    }

    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageCallbackEntered,
        STATUS_SUCCESS);
    if (InterlockedCompareExchange(
            &gKswordArkBgp.resolvedSnapshotReady,
            0,
            0) == 0 ||
        InterlockedCompareExchange(
            &gKswordArkBgp.state,
            0,
            0) != kKswordArkBgpStateArmed ||
        gKswordArkBgp.acquireOwnership == NULL ||
        gKswordArkBgp.acquire == NULL ||
        gKswordArkBgp.release == NULL) {
        status = STATUS_DEVICE_NOT_READY;
        InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
        kswordArkBugcheckBgpRecordStage(
            (LONG)(kKswordArkBgpStageRejected | 1UL),
            status);
        return status;
    }

    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageOwnershipBefore,
        STATUS_PENDING);
    kswordArkBugcheckBgpInvokeAcquireOwnership();
    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageOwnershipAfter,
        STATUS_SUCCESS);

    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageAcquireBefore,
        STATUS_PENDING);
    kswordArkBugcheckBgpInvokeAcquire();
    InterlockedExchange(&gKswordArkBgp.lockHeld, 1);
    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageAcquireAfter,
        STATUS_SUCCESS);

    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageScreenBefore,
        STATUS_PENDING);
    status = kswordArkBugcheckBgpReadScreen(&crashScreen);
    InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
    if (NT_SUCCESS(status)) {
        gKswordArkBgp.screen = crashScreen;
    }
    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageScreenAfter,
        status);
    if (!NT_SUCCESS(status) ||
        (crashScreen.bitsPerPixel != 24UL &&
         crashScreen.bitsPerPixel != 32UL) ||
        gKswordArkBgp.requiredWidth > crashScreen.width ||
        gKswordArkBgp.requiredHeight > crashScreen.height) {
        status = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
        InterlockedExchange(
            &gKswordArkBgp.state,
            kKswordArkBgpStateRejected);
        kswordArkBugcheckBgpRecordStage(
            (LONG)(kKswordArkBgpStageRejected | 2UL),
            status);
        kswordArkBugcheckBgpRecordStage(
            kKswordArkBgpStageReleaseBefore,
            STATUS_PENDING);
        kswordArkBugcheckBgpInvokeRelease();
        InterlockedExchange(&gKswordArkBgp.lockHeld, 0);
        kswordArkBugcheckBgpRecordStage(
            kKswordArkBgpStageReleaseAfter,
            STATUS_SUCCESS);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkBugcheckBgpClearScreen(
    _In_ ULONG argbColor
    )
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&gKswordArkBgp.lockHeld, 0, 0) == 0 ||
        gKswordArkBgp.clear == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageClearBefore,
        STATUS_PENDING);
    status = kswordArkBugcheckBgpInvokeClear(argbColor);
    InterlockedExchange(&gKswordArkBgp.clearStatus, (LONG)status);
    InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageClearAfter,
        status);
    return status;
}

NTSTATUS
kswordArkBugcheckBgpDrawRectangle(
    _In_ PVOID rectangle,
    _In_ LONG x,
    _In_ LONG y
    )
{
    KswordArkBgpPosition position;
    NTSTATUS status;

    if (rectangle == NULL ||
        InterlockedCompareExchange(&gKswordArkBgp.lockHeld, 0, 0) == 0 ||
        gKswordArkBgp.draw == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (InterlockedCompareExchange(
            &gKswordArkBgp.drawStageStarted,
            1,
            0) == 0) {
        kswordArkBugcheckBgpRecordStage(
            kKswordArkBgpStageDrawBefore,
            STATUS_PENDING);
    }

    position.x = x;
    position.y = y;
    status = kswordArkBugcheckBgpInvokeDraw(rectangle, &position);
    InterlockedExchange(&gKswordArkBgp.drawStatus, (LONG)status);
    InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)status);
    return status;
}

VOID
kswordArkBugcheckBgpFinishDraw(
    _In_ NTSTATUS drawStatus
    )
{
    if (InterlockedCompareExchange(
            &gKswordArkBgp.drawStageStarted,
            1,
            0) == 0) {
        kswordArkBugcheckBgpRecordStage(
            kKswordArkBgpStageDrawBefore,
            drawStatus);
    }
    InterlockedExchange(&gKswordArkBgp.drawStatus, (LONG)drawStatus);
    InterlockedExchange(&gKswordArkBgp.lastStatus, (LONG)drawStatus);
    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageDrawAfter,
        drawStatus);

    if (InterlockedExchange(&gKswordArkBgp.lockHeld, 0) != 0 &&
        gKswordArkBgp.release != NULL) {
        kswordArkBugcheckBgpRecordStage(
            kKswordArkBgpStageReleaseBefore,
            STATUS_PENDING);
        kswordArkBugcheckBgpInvokeRelease();
        kswordArkBugcheckBgpRecordStage(
            kKswordArkBgpStageReleaseAfter,
            STATUS_SUCCESS);
    }

    InterlockedIncrement64(&gKswordArkBgp.drawCount);
    InterlockedExchange(
        &gKswordArkBgp.state,
        NT_SUCCESS(drawStatus)
            ? kKswordArkBgpStateDrawn
            : kKswordArkBgpStateRejected);
    kswordArkBugcheckBgpRecordStage(
        kKswordArkBgpStageComplete,
        drawStatus);
}

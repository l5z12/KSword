/*++

Module Name:

    bugcheck_panel.c

Abstract:

    PASSIVE_LEVEL preparation and crash-time rendering for the physical BGP
    diagnostic panel. The callback path uses only fixed nonpaged buffers and
    rectangles created before the bugcheck occurs.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_bgp.h"
#include "bugcheck_layout.h"
#include "bugcheck_panel.h"
#include "../../platform/pool_compat.h"

#include "generated/ascii_font_8x12.h"
#include "generated/main_logo_bitmap.h"

#define KSWORD_ARK_PANEL_POOL_TAG 'lPgK'
#define KSWORD_ARK_PANEL_BACKGROUND_ARGB 0xFF050F21UL
#define KSWORD_ARK_PANEL_GLYPH_ADVANCE 9L
#define KSWORD_ARK_PANEL_GLYPH_BORDER 1UL
#define KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH \
    (DRIVERGUI_FONT_WIDTH + (KSWORD_ARK_PANEL_GLYPH_BORDER * 2UL))
#define KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT \
    (DRIVERGUI_FONT_HEIGHT + (KSWORD_ARK_PANEL_GLYPH_BORDER * 2UL))
#define KSWORD_ARK_PANEL_COLOR_COUNT \
    ((ULONG)kKswordArkBugcheckLayoutColorCount)
#define KSWORD_ARK_PANEL_BPP24_INDEX 0UL
#define KSWORD_ARK_PANEL_BPP32_INDEX 1UL
#define KSWORD_ARK_PANEL_BPP_VARIANT_COUNT 2UL
#define KSWORD_ARK_PANEL_VERDICT_SET_COUNT 2UL

#pragma pack(push, 1)
typedef struct KswordArkPanelBitmapFileHeader
{
    USHORT type;
    ULONG size;
    USHORT reserved1;
    USHORT reserved2;
    ULONG pixelOffset;
} KswordArkPanelBitmapFileHeader, *PkswordArkPanelBitmapFileHeader;

typedef struct KswordArkPanelBitmapInfoHeader
{
    ULONG size;
    LONG width;
    LONG height;
    USHORT planes;
    USHORT bitsPerPixel;
    ULONG compression;
    ULONG imageSize;
    LONG xPelsPerMeter;
    LONG yPelsPerMeter;
    ULONG colorsUsed;
    ULONG colorsImportant;
} KswordArkPanelBitmapInfoHeader, *PkswordArkPanelBitmapInfoHeader;
#pragma pack(pop)

typedef struct KswordArkPanelVariant
{
    ULONG bitsPerPixel;
    PVOID logoRectangle;
    PVOID glyphRectangles[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
    PVOID frameHorizontalRectangles[kKswordArkBugcheckLayoutFrameCount];
    PVOID frameVerticalRectangles[kKswordArkBugcheckLayoutFrameCount];
    // Keep the source BMPs resident for the lifetime of the parsed glyphs.
    // BgpGxParseBitmap is private and its ownership contract is not documented.
    // A persistent nonpaged backing buffer prevents a small-rectangle parser
    // from retaining a reused preparation stack buffer.
    PUCHAR glyphBitmaps[KSWORD_ARK_PANEL_COLOR_COUNT][DRIVERGUI_FONT_COUNT];
    PUCHAR frameHorizontalBitmaps[kKswordArkBugcheckLayoutFrameCount];
    PUCHAR frameVerticalBitmaps[kKswordArkBugcheckLayoutFrameCount];
} KswordArkPanelVariant, *PkswordArkPanelVariant;

typedef struct KswordArkPanelVerdictItem
{
    PVOID rectangle;
    PUCHAR backingBitmap;
    ULONG width;
    ULONG height;
} KswordArkPanelVerdictItem, *PkswordArkPanelVerdictItem;

typedef struct KswordArkPanelVerdictSet
{
    BOOLEAN complete;
    KswordArkPanelVerdictItem
        items[KSWORD_ARK_PANEL_BPP_VARIANT_COUNT]
             [KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT]
             [KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT];
} KswordArkPanelVerdictSet, *PkswordArkPanelVerdictSet;

typedef struct KswordArkPanelState
{
    volatile LONG ready;
    volatile LONG activeVariant;
    volatile LONG activeVerdictSet;
    volatile LONG preferredLanguage;
    KswordArkPanelVariant variants[KSWORD_ARK_PANEL_BPP_VARIANT_COUNT];
    KswordArkPanelVerdictSet
        verdictSets[KSWORD_ARK_PANEL_VERDICT_SET_COUNT];
} KswordArkPanelState, *PkswordArkPanelState;

static KswordArkPanelState gKswordArkPanel;

C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN ==
    KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN);
C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_OURS ==
    KSWORD_ARK_BUGCHECK_MODULE_OURS);
C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_MICROSOFT ==
    KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT);
C_ASSERT(
    KSWORD_ARK_BUGCHECK_VERDICT_CLASS_THIRD_PARTY ==
    KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY);

static NTSTATUS
kswordArkBugcheckPanelInitializeBitmap(
    _Out_writes_bytes_(bitmapCapacity) UCHAR* bitmap,
    _In_ ULONG bitmapCapacity,
    _In_ ULONG width,
    _In_ ULONG height,
    _In_ ULONG bitsPerPixel,
    _Out_ PULONG bitmapLength,
    _Out_ PULONG bitmapStride,
    _Out_ PUCHAR* pixelBytes
    )
{
    PkswordArkPanelBitmapFileHeader fileHeader;
    PkswordArkPanelBitmapInfoHeader infoHeader;
    ULONG64 stride;
    ULONG64 imageBytes;
    ULONG64 totalBytes;

    if (bitmap == NULL ||
        bitmapLength == NULL ||
        bitmapStride == NULL ||
        pixelBytes == NULL ||
        width == 0 ||
        height == 0 ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }

    stride = (((ULONG64)width * bitsPerPixel + 31ULL) / 32ULL) * 4ULL;
    imageBytes = stride * height;
    totalBytes =
        sizeof(KswordArkPanelBitmapFileHeader) +
        sizeof(KswordArkPanelBitmapInfoHeader) +
        imageBytes;
    if (stride > MAXULONG ||
        imageBytes > MAXULONG ||
        totalBytes > bitmapCapacity ||
        totalBytes > MAXULONG) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(bitmap, (SIZE_T)totalBytes);
    fileHeader = (PkswordArkPanelBitmapFileHeader)bitmap;
    infoHeader = (PkswordArkPanelBitmapInfoHeader)(bitmap + sizeof(*fileHeader));
    fileHeader->type = 0x4D42U;
    fileHeader->size = (ULONG)totalBytes;
    fileHeader->pixelOffset = sizeof(*fileHeader) + sizeof(*infoHeader);
    infoHeader->size = sizeof(*infoHeader);
    infoHeader->width = (LONG)width;
    infoHeader->height = (LONG)height;
    infoHeader->planes = 1U;
    infoHeader->bitsPerPixel = (USHORT)bitsPerPixel;
    infoHeader->imageSize = (ULONG)imageBytes;

    *bitmapLength = (ULONG)totalBytes;
    *bitmapStride = (ULONG)stride;
    *pixelBytes = bitmap + fileHeader->pixelOffset;
    return STATUS_SUCCESS;
}

typedef NTSTATUS
(NTAPI *PkswordArkZwQueryDefaultUiLanguage)(
    _Out_ PUSHORT defaultUiLanguageId
    );

static ULONG
kswordArkBugcheckPanelQueryPreferredLanguage(
    VOID
    )
{
    UNICODE_STRING routineName;
    PkswordArkZwQueryDefaultUiLanguage queryLanguage;
    USHORT languageId;

    languageId = 0;
    RtlInitUnicodeString(&routineName, L"ZwQueryDefaultUILanguage");
    queryLanguage = (PkswordArkZwQueryDefaultUiLanguage)
        MmGetSystemRoutineAddress(&routineName);
    if (queryLanguage != NULL &&
        NT_SUCCESS(queryLanguage(&languageId)) &&
        (languageId & 0x03FFU) == 0x0004U) {
        return KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_CHINESE;
    }
    return KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH;
}

static VOID
kswordArkBugcheckPanelReleaseVerdictSet(
    _Inout_ PkswordArkPanelVerdictSet verdictSet
    )
{
    ULONG variantIndex;

    if (verdictSet == NULL) {
        return;
    }
    verdictSet->complete = FALSE;
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT;
         ++variantIndex) {
        ULONG language;

        for (language = 0;
             language < KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT;
             ++language) {
            ULONG classification;

            for (classification = 0;
                 classification < KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT;
                 ++classification) {
                PkswordArkPanelVerdictItem item;

                item = &verdictSet->items[variantIndex]
                    [language][classification];
                kswordArkBugcheckBgpDestroyRectangle(item->rectangle);
                item->rectangle = NULL;
                if (item->backingBitmap != NULL) {
                    ExFreePoolWithTag(
                        item->backingBitmap,
                        KSWORD_ARK_PANEL_POOL_TAG);
                    item->backingBitmap = NULL;
                }
                item->width = 0;
                item->height = 0;
            }
        }
    }
}

static NTSTATUS
kswordArkBugcheckPanelValidateVerdictPacket(
    _In_reads_bytes_(packetLength) const VOID* packet,
    _In_ ULONG packetLength,
    _Out_ const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY** entriesArg
    )
{
    const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER* header;
    const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entries;
    ULONG64 entriesBytes;
    ULONG64 minimumDataOffset;
    ULONG64 totalDataBytes;
    ULONG seenMask;
    ULONG index;

    if (packet == NULL || entriesArg == NULL ||
        packetLength < sizeof(*header)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *entriesArg = NULL;
    header = (const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER*)packet;
    entriesBytes =
        (ULONG64)sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY) *
        KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT;
    minimumDataOffset = (ULONG64)sizeof(*header) + entriesBytes;
    if (header->version != KSWORD_ARK_BUGCHECK_VERDICT_PROTOCOL_VERSION ||
        header->size != sizeof(*header) ||
        header->magic != KSWORD_ARK_BUGCHECK_VERDICT_MAGIC ||
        header->resourceCount !=
            KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT ||
        header->entriesOffset != sizeof(*header) ||
        header->totalSize != packetLength ||
        header->flags != 0 || header->reserved != 0 ||
        minimumDataOffset > packetLength) {
        return STATUS_INVALID_PARAMETER;
    }

    entries = (const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY*)(
        (const UCHAR*)packet + header->entriesOffset);
    totalDataBytes = 0;
    seenMask = 0;
    for (index = 0;
         index < KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT;
         ++index) {
        const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entry;
        ULONG64 expectedStride;
        ULONG64 expectedBytes;
        ULONG64 dataEnd;
        ULONG bitIndex;
        ULONG bit;

        entry = &entries[index];
        expectedStride = (ULONG64)entry->width * 4ULL;
        expectedBytes = expectedStride * entry->height;
        dataEnd = (ULONG64)entry->dataOffset + entry->dataLength;
        if (entry->language >=
                KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT ||
            entry->classification >=
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT ||
            entry->width == 0 || entry->height == 0 ||
            entry->width > KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH ||
            entry->height > KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT ||
            entry->format != KSWORD_ARK_BUGCHECK_VERDICT_FORMAT_BGRA32 ||
            expectedStride != entry->stride ||
            expectedBytes == 0 || expectedBytes != entry->dataLength ||
            entry->dataOffset < minimumDataOffset ||
            dataEnd > packetLength) {
            return STATUS_INVALID_PARAMETER;
        }

        bitIndex = entry->language *
            KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT +
            entry->classification;
        bit = 1UL << bitIndex;
        if ((seenMask & bit) != 0) {
            return STATUS_INVALID_PARAMETER;
        }
        seenMask |= bit;
        totalDataBytes += entry->dataLength;
        if (totalDataBytes >
            KSWORD_ARK_BUGCHECK_VERDICT_MAX_DATA_BYTES) {
            return STATUS_INVALID_PARAMETER;
        }
    }

    if (seenMask !=
        ((1UL << KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT) - 1UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *entriesArg = entries;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckPanelPrepareVerdictItem(
    _In_ ULONG bitsPerPixel,
    _In_ const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entry,
    _In_reads_bytes_(entry->dataLength) const UCHAR* sourcePixels,
    _Out_ PkswordArkPanelVerdictItem item
    )
{
    PUCHAR bitmap;
    PUCHAR pixels;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG y;
    NTSTATUS status;

    if (entry == NULL || sourcePixels == NULL || item == NULL ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(item, sizeof(*item));
    bitmapCapacity64 =
        sizeof(KswordArkPanelBitmapFileHeader) +
        sizeof(KswordArkPanelBitmapInfoHeader) +
        ((((ULONG64)entry->width * bitsPerPixel + 31ULL) / 32ULL) *
         4ULL * entry->height);
    if (bitmapCapacity64 > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }
    bitmapCapacity = (ULONG)bitmapCapacity64;
    bitmap = (PUCHAR)kswordArkAllocateNonPagedPool(
        bitmapCapacity,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = kswordArkBugcheckPanelInitializeBitmap(
        bitmap,
        bitmapCapacity,
        entry->width,
        entry->height,
        bitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    bytesPerPixel = bitsPerPixel / 8UL;
    for (y = 0; y < entry->height; ++y) {
        const UCHAR* sourceRow;
        PUCHAR destinationRow;
        ULONG x;

        sourceRow = sourcePixels + ((SIZE_T)y * entry->stride);
        destinationRow = pixels +
            ((SIZE_T)(entry->height - 1UL - y) * bitmapStride);
        for (x = 0; x < entry->width; ++x) {
            const UCHAR* sourcePixel;
            PUCHAR destinationPixel;
            ULONG alpha;

            sourcePixel = sourceRow + ((SIZE_T)x * 4UL);
            destinationPixel = destinationRow +
                ((SIZE_T)x * bytesPerPixel);
            alpha = sourcePixel[3];
            destinationPixel[0] = (UCHAR)(
                (sourcePixel[0] * alpha +
                 KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE *
                    (255UL - alpha)) / 255UL);
            destinationPixel[1] = (UCHAR)(
                (sourcePixel[1] * alpha +
                 KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN *
                    (255UL - alpha)) / 255UL);
            destinationPixel[2] = (UCHAR)(
                (sourcePixel[2] * alpha +
                 KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED *
                    (255UL - alpha)) / 255UL);
            if (bytesPerPixel == 4UL) {
                destinationPixel[3] = 0xFFU;
            }
        }
    }

    status = kswordArkBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        &item->rectangle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }
    item->backingBitmap = bitmap;
    item->width = entry->width;
    item->height = entry->height;
    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkBugcheckPanelInstallVerdictResources(
    _In_reads_bytes_(packetLength) const VOID* packet,
    _In_ ULONG packetLength
    )
{
    const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entries;
    PkswordArkPanelVerdictSet verdictSet;
    LONG activeSet;
    ULONG stagingSet;
    ULONG index;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InterlockedCompareExchange(&gKswordArkPanel.ready, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }
    status = kswordArkBugcheckPanelValidateVerdictPacket(
        packet,
        packetLength,
        &entries);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = kswordArkBugcheckBgpBeginResourceUpdate();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    activeSet = InterlockedCompareExchange(
        &gKswordArkPanel.activeVerdictSet,
        0,
        0);
    stagingSet = activeSet == 0 ? 1UL : 0UL;
    verdictSet = &gKswordArkPanel.verdictSets[stagingSet];
    kswordArkBugcheckPanelReleaseVerdictSet(verdictSet);
    status = STATUS_SUCCESS;
    for (index = 0;
         index < KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT &&
             NT_SUCCESS(status);
         ++index) {
        const KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_ENTRY* entry;
        ULONG variantIndex;

        entry = &entries[index];
        for (variantIndex = 0;
             variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT &&
                 NT_SUCCESS(status);
             ++variantIndex) {
            ULONG bitsPerPixel;

            bitsPerPixel = variantIndex == KSWORD_ARK_PANEL_BPP24_INDEX
                ? 24UL
                : 32UL;
            status = kswordArkBugcheckPanelPrepareVerdictItem(
                bitsPerPixel,
                entry,
                (const UCHAR*)packet + entry->dataOffset,
                &verdictSet->items[variantIndex]
                    [entry->language][entry->classification]);
        }
    }

    if (NT_SUCCESS(status)) {
        verdictSet->complete = TRUE;
        KeMemoryBarrier();
        InterlockedExchange(
            &gKswordArkPanel.activeVerdictSet,
            (LONG)stagingSet);
    } else {
        kswordArkBugcheckPanelReleaseVerdictSet(verdictSet);
    }
    kswordArkBugcheckBgpEndResourceUpdate();
    return status;
}

static NTSTATUS
kswordArkBugcheckPanelPrepareLogoRectangle(
    _In_ ULONG bitsPerPixel,
    _In_ ULONG width,
    _In_ ULONG height,
    _Out_ PVOID* rectangle
    )
{
    UCHAR* bitmap;
    PUCHAR pixels;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG destinationY;
    NTSTATUS status;

    if (rectangle == NULL ||
        width == 0 ||
        height == 0 ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *rectangle = NULL;

    bytesPerPixel = bitsPerPixel / 8UL;
    bitmapCapacity64 =
        sizeof(KswordArkPanelBitmapFileHeader) +
        sizeof(KswordArkPanelBitmapInfoHeader) +
        ((((ULONG64)width *
           bitsPerPixel + 31ULL) / 32ULL) * 4ULL) *
            height;
    if (bitmapCapacity64 > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }

    bitmapCapacity = (ULONG)bitmapCapacity64;
    bitmap = (UCHAR*)kswordArkAllocateNonPagedPool(
        bitmapCapacity,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = kswordArkBugcheckPanelInitializeBitmap(
        bitmap,
        bitmapCapacity,
        width,
        height,
        bitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (NT_SUCCESS(status)) {
        for (destinationY = 0;
             destinationY < height;
             ++destinationY) {
            ULONG destinationX;
            ULONG sourceY;
            PUCHAR destinationRow;
            const UCHAR* sourceRow;

            sourceY = (destinationY * DRIVERGUI_MAINLOGO_HEIGHT) / height;
            destinationRow =
                pixels +
                ((SIZE_T)(height - 1UL - destinationY) *
                 bitmapStride);
            sourceRow =
                kGDriverGuiMainLogoBgra +
                 ((SIZE_T)sourceY * DRIVERGUI_MAINLOGO_STRIDE);
            for (destinationX = 0;
                 destinationX < width;
                 ++destinationX) {
                ULONG alpha;
                ULONG sourceBlue;
                ULONG sourceGreen;
                ULONG sourceRed;
                ULONG sourceX;
                PUCHAR destinationPixel;
                const UCHAR* sourcePixel;

                sourceX = (destinationX * DRIVERGUI_MAINLOGO_WIDTH) / width;
                destinationPixel =
                    destinationRow + ((SIZE_T)destinationX * bytesPerPixel);
                sourcePixel = sourceRow + ((SIZE_T)sourceX * 4UL);
                sourceBlue = sourcePixel[0];
                sourceGreen = sourcePixel[1];
                sourceRed = sourcePixel[2];
                alpha = sourcePixel[3];

                // Keep the KSwordDEV artwork legible on the dark crash canvas.
                if (alpha != 0 && sourceRed < 72UL &&
                    sourceGreen < 72UL && sourceBlue < 72UL) {
                    sourceRed = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED;
                    sourceGreen = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN;
                    sourceBlue = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE;
                }
                destinationPixel[0] = (UCHAR)(
                    (sourceBlue * alpha +
                     KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE *
                         (255UL - alpha)) / 255UL);
                destinationPixel[1] = (UCHAR)(
                    (sourceGreen * alpha +
                     KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN *
                         (255UL - alpha)) / 255UL);
                destinationPixel[2] = (UCHAR)(
                    (sourceRed * alpha +
                     KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED *
                         (255UL - alpha)) / 255UL);
                if (bytesPerPixel == 4UL) {
                    destinationPixel[3] = 0xFFU;
                }
            }
        }

        status = kswordArkBugcheckBgpParseBitmap(
            bitmap,
            bitmapLength,
            rectangle);
    }

    ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
    return status;
}

static NTSTATUS
kswordArkBugcheckPanelPrepareLogos(
    _In_ ULONG variantIndex,
    _In_ ULONG bitsPerPixel
    )
{
    NTSTATUS status;

    if (variantIndex >= KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    status = kswordArkBugcheckPanelPrepareLogoRectangle(
        bitsPerPixel,
        KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_WIDTH,
        KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_HEIGHT,
        &gKswordArkPanel.variants[variantIndex].logoRectangle);
    if (!NT_SUCCESS(status)) {
        kswordArkBugcheckBgpDestroyRectangle(
            gKswordArkPanel.variants[variantIndex].logoRectangle);
        gKswordArkPanel.variants[variantIndex].logoRectangle = NULL;
    }
    return status;
}

static VOID
kswordArkBugcheckPanelWriteGlyphPixel(
    _Out_writes_bytes_(bytesPerPixel) PUCHAR pixel,
    _In_ ULONG bytesPerPixel,
    _In_ ULONG colorIndex,
    _In_ BOOLEAN foreground
    )
{
    if (!foreground) {
        // BGP's parsed 32-bit rectangles are rendered as opaque pixels.
        // Match every padded glyph cell to the dark crash canvas.
        pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE;
        pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN;
        pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED;
        if (bytesPerPixel == 4UL) {
            // BGP requires opaque pixels for reliable 32-bit glyph rendering.
            pixel[3] = 0xFFU;
        }
        return;
    }

    if (colorIndex == kKswordArkBugcheckLayoutColorAccent) {
        pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_BLUE;
        pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_GREEN;
        pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_RED;
    } else if (colorIndex == kKswordArkBugcheckLayoutColorWarning) {
        pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_BLUE;
        pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_GREEN;
        pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_RED;
    } else if (colorIndex == kKswordArkBugcheckLayoutColorMuted) {
        pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_BLUE;
        pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_GREEN;
        pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_RED;
    } else {
        pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE;
        pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN;
        pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED;
    }
    if (bytesPerPixel == 4UL) {
        pixel[3] = 0xFFU;
    }
}

static NTSTATUS
kswordArkBugcheckPanelPrepareGlyph(
    _In_ ULONG variantIndex,
    _In_ ULONG bitsPerPixel,
    _In_ ULONG colorIndex,
    _In_ ULONG glyphIndex
    )
{
    PUCHAR bitmap;
    PUCHAR pixels;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG bitmapRowIndex;
    ULONG bitmapColumnIndex;
    ULONG rowIndex;
    PVOID* rectangle;
    NTSTATUS status;

    if (variantIndex >= KSWORD_ARK_PANEL_BPP_VARIANT_COUNT ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }

    bitmap = (PUCHAR)kswordArkAllocateNonPagedPool(
        1024UL,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = kswordArkBugcheckPanelInitializeBitmap(
        bitmap,
        1024UL,
        KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH,
        KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT,
        bitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    bytesPerPixel = bitsPerPixel / 8UL;
    // Paint the complete padded cell before overlaying foreground bits.
    for (bitmapRowIndex = 0;
         bitmapRowIndex < KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT;
         ++bitmapRowIndex) {
        PUCHAR destinationRow;

        destinationRow =
            pixels +
            ((SIZE_T)(KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT -
                      1UL - bitmapRowIndex) * bitmapStride);
        for (bitmapColumnIndex = 0;
             bitmapColumnIndex < KSWORD_ARK_PANEL_GLYPH_BITMAP_WIDTH;
             ++bitmapColumnIndex) {
            kswordArkBugcheckPanelWriteGlyphPixel(
                destinationRow +
                    ((SIZE_T)bitmapColumnIndex * bytesPerPixel),
                bytesPerPixel,
                colorIndex,
                FALSE);
        }
    }
    for (rowIndex = 0;
         rowIndex < DRIVERGUI_FONT_HEIGHT;
         ++rowIndex) {
        ULONG columnIndex;
        UCHAR rowBits;
        PUCHAR destinationRow;

        rowBits = kGDriverGuiFont8x12[glyphIndex][rowIndex];
        destinationRow =
            pixels +
            ((SIZE_T)(KSWORD_ARK_PANEL_GLYPH_BITMAP_HEIGHT -
                      1UL - KSWORD_ARK_PANEL_GLYPH_BORDER - rowIndex) *
             bitmapStride);
        for (columnIndex = 0;
             columnIndex < DRIVERGUI_FONT_WIDTH;
             ++columnIndex) {
            BOOLEAN foreground;

            foreground =
                (rowBits & (UCHAR)(1U << (7UL - columnIndex))) != 0;
            kswordArkBugcheckPanelWriteGlyphPixel(
                destinationRow +
                    ((SIZE_T)(KSWORD_ARK_PANEL_GLYPH_BORDER + columnIndex) *
                     bytesPerPixel),
                bytesPerPixel,
                colorIndex,
                foreground);
        }
    }

    rectangle = &gKswordArkPanel.variants[variantIndex]
        .glyphRectangles[colorIndex][glyphIndex];
    status = kswordArkBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        rectangle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    gKswordArkPanel.variants[variantIndex]
        .glyphBitmaps[colorIndex][glyphIndex] = bitmap;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckPanelPrepareGlyphs(
    _In_ ULONG variantIndex,
    _In_ ULONG bitsPerPixel
    )
{
    ULONG colorIndex;

    for (colorIndex = 0;
         colorIndex < KSWORD_ARK_PANEL_COLOR_COUNT;
         ++colorIndex) {
        ULONG glyphIndex;

        for (glyphIndex = 0;
             glyphIndex < DRIVERGUI_FONT_COUNT;
             ++glyphIndex) {
            NTSTATUS status;

            status = kswordArkBugcheckPanelPrepareGlyph(
                variantIndex,
                bitsPerPixel,
                colorIndex,
                glyphIndex);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckPanelPrepareSolidRectangle(
    _In_ ULONG bitsPerPixel,
    _In_ ULONG width,
    _In_ ULONG height,
    _Out_ PVOID* rectangle,
    _Out_ PUCHAR* backingBitmap
    )
{
    PUCHAR bitmap;
    PUCHAR pixels;
    ULONG64 bitmapCapacity64;
    ULONG bitmapCapacity;
    ULONG bitmapLength;
    ULONG bitmapStride;
    ULONG bytesPerPixel;
    ULONG x;
    ULONG y;
    NTSTATUS status;

    if (rectangle == NULL || backingBitmap == NULL ||
        width == 0 || height == 0 ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    *rectangle = NULL;
    *backingBitmap = NULL;

    bitmapCapacity64 =
        sizeof(KswordArkPanelBitmapFileHeader) +
        sizeof(KswordArkPanelBitmapInfoHeader) +
        ((((ULONG64)width * bitsPerPixel + 31ULL) / 32ULL) *
         4ULL * height);
    if (bitmapCapacity64 > MAXULONG) {
        return STATUS_INTEGER_OVERFLOW;
    }
    bitmapCapacity = (ULONG)bitmapCapacity64;
    bitmap = (PUCHAR)kswordArkAllocateNonPagedPool(
        bitmapCapacity,
        KSWORD_ARK_PANEL_POOL_TAG);
    if (bitmap == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pixels = NULL;
    status = kswordArkBugcheckPanelInitializeBitmap(
        bitmap,
        bitmapCapacity,
        width,
        height,
        bitsPerPixel,
        &bitmapLength,
        &bitmapStride,
        &pixels);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    bytesPerPixel = bitsPerPixel / 8UL;
    for (y = 0; y < height; ++y) {
        PUCHAR row;

        row = pixels + ((SIZE_T)y * bitmapStride);
        for (x = 0; x < width; ++x) {
            PUCHAR pixel;

            pixel = row + ((SIZE_T)x * bytesPerPixel);
            pixel[0] = KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_BLUE;
            pixel[1] = KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_GREEN;
            pixel[2] = KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_RED;
            if (bytesPerPixel == 4UL) {
                pixel[3] = 0xFFU;
            }
        }
    }

    status = kswordArkBugcheckBgpParseBitmap(
        bitmap,
        bitmapLength,
        rectangle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(bitmap, KSWORD_ARK_PANEL_POOL_TAG);
        return status;
    }

    // Retain the source because the private parser's ownership is undocumented.
    *backingBitmap = bitmap;
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckPanelPrepareFrames(
    _In_ ULONG variantIndex,
    _In_ ULONG bitsPerPixel
    )
{
    KswordArkBugcheckLayoutFrame frame;

    if (variantIndex >= KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    for (frame = kKswordArkBugcheckLayoutFrameCompactColumn;
         frame < kKswordArkBugcheckLayoutFrameCount;
         frame = (KswordArkBugcheckLayoutFrame)(frame + 1)) {
        ULONG width;
        ULONG height;
        NTSTATUS status;

        if (!kswordArkBugcheckLayoutGetFrameMetrics(
                frame,
                &width,
                &height)) {
            return STATUS_INVALID_PARAMETER;
        }

        status = kswordArkBugcheckPanelPrepareSolidRectangle(
            bitsPerPixel,
            width,
            1UL,
            &gKswordArkPanel.variants[variantIndex]
                .frameHorizontalRectangles[frame],
            &gKswordArkPanel.variants[variantIndex]
                .frameHorizontalBitmaps[frame]);
        if (NT_SUCCESS(status)) {
            status = kswordArkBugcheckPanelPrepareSolidRectangle(
                bitsPerPixel,
                1UL,
                height,
                &gKswordArkPanel.variants[variantIndex]
                    .frameVerticalRectangles[frame],
                &gKswordArkPanel.variants[variantIndex]
                    .frameVerticalBitmaps[frame]);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
kswordArkBugcheckPanelInitialize(
    VOID
    )
{
    KswordArkBgpScreenInfo screen;
    ULONG variantIndex;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&gKswordArkPanel, sizeof(gKswordArkPanel));
    InterlockedExchange(&gKswordArkPanel.activeVerdictSet, -1);
    InterlockedExchange(
        &gKswordArkPanel.preferredLanguage,
        (LONG)kswordArkBugcheckPanelQueryPreferredLanguage());
    kswordArkBugcheckBgpRecordPreparation(
        kKswordArkBgpPreparationValidatePanelScreen,
        STATUS_PENDING);
    status = kswordArkBugcheckBgpGetScreenInfo(&screen);
    if (!NT_SUCCESS(status)) {
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationValidatePanelScreen,
            status);
        kswordArkBugcheckBgpRejectPreparation(status);
        return status;
    }
    // Accept the fully hidden pre-ownership mode so both supported rectangle
    // variants can still be prepared at PASSIVE_LEVEL.
    if (screen.bitsPerPixel != KSWORD_ARK_BGP_UNOWNED_BPP &&
        (screen.width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
         screen.height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT ||
         (screen.bitsPerPixel != 24UL &&
          screen.bitsPerPixel != 32UL))) {
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationValidatePanelScreen,
            STATUS_NOT_SUPPORTED);
        kswordArkBugcheckBgpRejectPreparation(STATUS_NOT_SUPPORTED);
        return STATUS_NOT_SUPPORTED;
    }

    kswordArkBugcheckBgpRecordPreparation(
        kKswordArkBgpPreparationValidatePanelScreen,
        STATUS_SUCCESS);
    status = STATUS_SUCCESS;
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT &&
             NT_SUCCESS(status);
         ++variantIndex) {
        ULONG bitsPerPixel;

        bitsPerPixel = variantIndex == KSWORD_ARK_PANEL_BPP24_INDEX
            ? 24UL
            : 32UL;
        gKswordArkPanel.variants[variantIndex].bitsPerPixel = bitsPerPixel;
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationPrepareLogo,
            STATUS_PENDING);
        status = kswordArkBugcheckPanelPrepareLogos(
            variantIndex,
            bitsPerPixel);
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationPrepareLogo,
            status);
        if (NT_SUCCESS(status)) {
            kswordArkBugcheckBgpRecordPreparation(
                kKswordArkBgpPreparationPrepareGlyphs,
                STATUS_PENDING);
            status = kswordArkBugcheckPanelPrepareGlyphs(
                variantIndex,
                bitsPerPixel);
            if (NT_SUCCESS(status)) {
                // Frames are parsed with glyph resources before the crash.
                status = kswordArkBugcheckPanelPrepareFrames(
                    variantIndex,
                    bitsPerPixel);
            }
            kswordArkBugcheckBgpRecordPreparation(
                kKswordArkBgpPreparationPrepareGlyphs,
                status);
        }
    }
    if (NT_SUCCESS(status)) {
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationArm,
            STATUS_PENDING);
        status = kswordArkBugcheckBgpArm(
            KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH,
            KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT);
        kswordArkBugcheckBgpRecordPreparation(
            kKswordArkBgpPreparationArm,
            status);
    }
    if (!NT_SUCCESS(status)) {
        kswordArkBugcheckPanelShutdown();
        kswordArkBugcheckBgpRejectPreparation(status);
        return status;
    }

    InterlockedExchange(&gKswordArkPanel.ready, 1);
    kswordArkBugcheckBgpRecordPreparation(
        kKswordArkBgpPreparationComplete,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

VOID
kswordArkBugcheckPanelShutdown(
    VOID
    )
{
    ULONG variantIndex;
    ULONG colorIndex;
    ULONG verdictSetIndex;

    InterlockedExchange(&gKswordArkPanel.ready, 0);
    InterlockedExchange(&gKswordArkPanel.activeVariant, 0);
    InterlockedExchange(&gKswordArkPanel.activeVerdictSet, -1);
    for (verdictSetIndex = 0;
         verdictSetIndex < KSWORD_ARK_PANEL_VERDICT_SET_COUNT;
         ++verdictSetIndex) {
        kswordArkBugcheckPanelReleaseVerdictSet(
            &gKswordArkPanel.verdictSets[verdictSetIndex]);
    }
    for (variantIndex = 0;
         variantIndex < KSWORD_ARK_PANEL_BPP_VARIANT_COUNT;
         ++variantIndex) {
        kswordArkBugcheckBgpDestroyRectangle(
            gKswordArkPanel.variants[variantIndex].logoRectangle);
        gKswordArkPanel.variants[variantIndex].logoRectangle = NULL;
        for (colorIndex = 0;
             colorIndex < KSWORD_ARK_PANEL_COLOR_COUNT;
             ++colorIndex) {
            ULONG glyphIndex;

            for (glyphIndex = 0;
                 glyphIndex < DRIVERGUI_FONT_COUNT;
                 ++glyphIndex) {
                kswordArkBugcheckBgpDestroyRectangle(
                    gKswordArkPanel.variants[variantIndex]
                        .glyphRectangles[colorIndex][glyphIndex]);
                gKswordArkPanel.variants[variantIndex]
                    .glyphRectangles[colorIndex][glyphIndex] = NULL;
                if (gKswordArkPanel.variants[variantIndex]
                        .glyphBitmaps[colorIndex][glyphIndex] != NULL) {
                    ExFreePoolWithTag(
                        gKswordArkPanel.variants[variantIndex]
                            .glyphBitmaps[colorIndex][glyphIndex],
                        KSWORD_ARK_PANEL_POOL_TAG);
                    gKswordArkPanel.variants[variantIndex]
                        .glyphBitmaps[colorIndex][glyphIndex] = NULL;
                }
            }
        }
        {
            KswordArkBugcheckLayoutFrame frame;

            for (frame = kKswordArkBugcheckLayoutFrameCompactColumn;
                 frame < kKswordArkBugcheckLayoutFrameCount;
                 frame = (KswordArkBugcheckLayoutFrame)(frame + 1)) {
                kswordArkBugcheckBgpDestroyRectangle(
                    gKswordArkPanel.variants[variantIndex]
                        .frameHorizontalRectangles[frame]);
                gKswordArkPanel.variants[variantIndex]
                    .frameHorizontalRectangles[frame] = NULL;
                kswordArkBugcheckBgpDestroyRectangle(
                    gKswordArkPanel.variants[variantIndex]
                        .frameVerticalRectangles[frame]);
                gKswordArkPanel.variants[variantIndex]
                    .frameVerticalRectangles[frame] = NULL;
                if (gKswordArkPanel.variants[variantIndex]
                        .frameHorizontalBitmaps[frame] != NULL) {
                    ExFreePoolWithTag(
                        gKswordArkPanel.variants[variantIndex]
                            .frameHorizontalBitmaps[frame],
                        KSWORD_ARK_PANEL_POOL_TAG);
                    gKswordArkPanel.variants[variantIndex]
                        .frameHorizontalBitmaps[frame] = NULL;
                }
                if (gKswordArkPanel.variants[variantIndex]
                        .frameVerticalBitmaps[frame] != NULL) {
                    ExFreePoolWithTag(
                        gKswordArkPanel.variants[variantIndex]
                            .frameVerticalBitmaps[frame],
                        KSWORD_ARK_PANEL_POOL_TAG);
                    gKswordArkPanel.variants[variantIndex]
                        .frameVerticalBitmaps[frame] = NULL;
                }
            }
        }
    }
}

static NTSTATUS
kswordArkBugcheckPanelDrawText(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_z_ PCSTR text,
    _In_ ULONG colorIndex
    )
{
    LONG activeVariant;
    LONG cursorX;

    UNREFERENCED_PARAMETER(context);
    if (text == NULL || colorIndex >= KSWORD_ARK_PANEL_COLOR_COUNT) {
        return STATUS_INVALID_PARAMETER;
    }

    activeVariant = InterlockedCompareExchange(
        &gKswordArkPanel.activeVariant,
        0,
        0);
    if (activeVariant < 0 ||
        activeVariant >= (LONG)KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_DEVICE_NOT_READY;
    }

    cursorX = x;
    while (*text != '\0') {
        UCHAR character;
        ULONG glyphIndex;
        NTSTATUS status;

        character = (UCHAR)*text;
        if (character < DRIVERGUI_FONT_FIRST ||
            character > DRIVERGUI_FONT_LAST) {
            character = (UCHAR)'?';
        }
        glyphIndex = character - DRIVERGUI_FONT_FIRST;
        if (character != (UCHAR)' ') {
            status = kswordArkBugcheckBgpDrawRectangle(
                gKswordArkPanel.variants[activeVariant]
                    .glyphRectangles[colorIndex][glyphIndex],
                cursorX - (LONG)KSWORD_ARK_PANEL_GLYPH_BORDER,
                y - (LONG)KSWORD_ARK_PANEL_GLYPH_BORDER);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        cursorX += KSWORD_ARK_PANEL_GLYPH_ADVANCE;
        ++text;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkBugcheckPanelDrawFrame(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_ KswordArkBugcheckLayoutFrame frame
    )
{
    LONG activeVariant;
    ULONG width;
    ULONG height;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(context);
    if (!kswordArkBugcheckLayoutGetFrameMetrics(
            frame,
            &width,
            &height)) {
        return STATUS_INVALID_PARAMETER;
    }

    activeVariant = InterlockedCompareExchange(
        &gKswordArkPanel.activeVariant,
        0,
        0);
    if (activeVariant < 0 ||
        activeVariant >= (LONG)KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_DEVICE_NOT_READY;
    }

    // Each frame uses four rectangles parsed before the bugcheck occurs.
    status = kswordArkBugcheckBgpDrawRectangle(
        gKswordArkPanel.variants[activeVariant]
            .frameHorizontalRectangles[frame],
        x,
        y);
    if (NT_SUCCESS(status)) {
        status = kswordArkBugcheckBgpDrawRectangle(
            gKswordArkPanel.variants[activeVariant]
                .frameHorizontalRectangles[frame],
            x,
            y + (LONG)height - 1L);
    }
    if (NT_SUCCESS(status)) {
        status = kswordArkBugcheckBgpDrawRectangle(
            gKswordArkPanel.variants[activeVariant]
                .frameVerticalRectangles[frame],
            x,
            y);
    }
    if (NT_SUCCESS(status)) {
        status = kswordArkBugcheckBgpDrawRectangle(
            gKswordArkPanel.variants[activeVariant]
                .frameVerticalRectangles[frame],
            x + (LONG)width - 1L,
            y);
    }
    return status;
}

static NTSTATUS
kswordArkBugcheckPanelDrawVerdict(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_ ULONG classification
    )
{
    LONG activeSet;
    LONG activeVariant;
    LONG preferredLanguage;
    PkswordArkPanelVerdictSet verdictSet;
    PkswordArkPanelVerdictItem item;

    UNREFERENCED_PARAMETER(context);
    activeSet = InterlockedCompareExchange(
        &gKswordArkPanel.activeVerdictSet,
        0,
        0);
    activeVariant = InterlockedCompareExchange(
        &gKswordArkPanel.activeVariant,
        0,
        0);
    preferredLanguage = InterlockedCompareExchange(
        &gKswordArkPanel.preferredLanguage,
        0,
        0);
    if (activeSet < 0 ||
        activeSet >= (LONG)KSWORD_ARK_PANEL_VERDICT_SET_COUNT ||
        activeVariant < 0 ||
        activeVariant >= (LONG)KSWORD_ARK_PANEL_BPP_VARIANT_COUNT) {
        return STATUS_NOT_FOUND;
    }
    if (preferredLanguage < 0 ||
        preferredLanguage >=
            (LONG)KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_COUNT) {
        preferredLanguage =
            KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH;
    }
    if (classification >= KSWORD_ARK_BUGCHECK_VERDICT_CLASS_COUNT) {
        classification = KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN;
    }

    verdictSet = &gKswordArkPanel.verdictSets[activeSet];
    if (!verdictSet->complete) {
        return STATUS_NOT_FOUND;
    }
    item = &verdictSet->items[activeVariant]
        [preferredLanguage][classification];
    if (item->rectangle == NULL) {
        return STATUS_NOT_FOUND;
    }
    return kswordArkBugcheckBgpDrawRectangle(item->rectangle, x, y);
}

NTSTATUS
kswordArkBugcheckPanelDraw(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    )
{
    KswordArkBgpDumpState bgpState;
    KswordArkBugcheckLayoutCanvas canvas;
    LONG activeVariant;
    LONG originX;
    NTSTATUS status;

    if (diagnostics == NULL ||
        InterlockedCompareExchange(&gKswordArkPanel.ready, 0, 0) == 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = kswordArkBugcheckBgpBeginDraw();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    activeVariant = kswordArkBugcheckBgpGetCurrentBpp() == 24UL
        ? (LONG)KSWORD_ARK_PANEL_BPP24_INDEX
        : (LONG)KSWORD_ARK_PANEL_BPP32_INDEX;
    InterlockedExchange(&gKswordArkPanel.activeVariant, activeVariant);
    kswordArkBugcheckBgpSnapshot(&bgpState);
    originX = kswordArkBugcheckLayoutOriginX(
        bgpState.screenWidth,
        bgpState.screenHeight);

    // Clear only after BeginDraw has acquired ownership and validated geometry.
    status = kswordArkBugcheckBgpClearScreen(
        KSWORD_ARK_PANEL_BACKGROUND_ARGB);
    if (NT_SUCCESS(status)) {
        status = kswordArkBugcheckBgpDrawRectangle(
            gKswordArkPanel.variants[activeVariant].logoRectangle,
            originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X,
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y);
    }
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(&canvas, sizeof(canvas));
        canvas.width = bgpState.screenWidth;
        canvas.height = bgpState.screenHeight;
        canvas.drawText = kswordArkBugcheckPanelDrawText;
        canvas.drawFrame = kswordArkBugcheckPanelDrawFrame;
        canvas.drawVerdict = kswordArkBugcheckPanelDrawVerdict;
        status = kswordArkBugcheckLayoutDraw(
            &canvas,
            diagnostics,
            callbackMask,
            moduleCount);
    }

    kswordArkBugcheckBgpFinishDraw(status);
    return status;
}

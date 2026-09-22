/*++

Module Name:

    bugcheck_svga.c

Abstract:

    VMware SVGA-II detection, framebuffer/FIFO access, and crash-safe panel drawing.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_font.h"
#include "bugcheck_layout.h"

#define KSW_SVGA_PCI_MAX_BUSES 256UL
#define KSW_SVGA_PCI_MAX_DEVICES 32UL
#define KSW_SVGA_PCI_MAX_FUNCTIONS 8UL

#define KSW_SVGA_PCI_BAR_IO 0x00000001UL
#define KSW_SVGA_PCI_BAR_MEM_TYPE_MASK 0x00000006UL
#define KSW_SVGA_PCI_BAR_MEM_TYPE_64 0x00000004UL
#define KSW_SVGA_PCI_BAR_IO_MASK 0xFFFFFFFCUL
#define KSW_SVGA_PCI_BAR_MEM_MASK 0xFFFFFFF0UL

#define KSW_SVGA_ID_INVALID 0xFFFFFFFFUL
#define KSW_SVGA_ID_0 0x90000000UL
#define KSW_SVGA_ID_1 0x90000001UL
#define KSW_SVGA_ID_2 0x90000002UL
#define KSW_SVGA_ID_3 0x90000003UL

#define KSW_SVGA_INDEX_PORT 0UL
#define KSW_SVGA_VALUE_PORT 1UL

#define KSW_SVGA_REG_ID 0UL
#define KSW_SVGA_REG_ENABLE 1UL
#define KSW_SVGA_REG_WIDTH 2UL
#define KSW_SVGA_REG_HEIGHT 3UL
#define KSW_SVGA_REG_DEPTH 6UL
#define KSW_SVGA_REG_BITS_PER_PIXEL 7UL
#define KSW_SVGA_REG_RED_MASK 9UL
#define KSW_SVGA_REG_GREEN_MASK 10UL
#define KSW_SVGA_REG_BLUE_MASK 11UL
#define KSW_SVGA_REG_BYTES_PER_LINE 12UL
#define KSW_SVGA_REG_FB_START 13UL
#define KSW_SVGA_REG_FB_OFFSET 14UL
#define KSW_SVGA_REG_VRAM_SIZE 15UL
#define KSW_SVGA_REG_FB_SIZE 16UL
#define KSW_SVGA_REG_CAPABILITIES 17UL
#define KSW_SVGA_REG_MEM_SIZE 19UL
#define KSW_SVGA_REG_CONFIG_DONE 20UL
#define KSW_SVGA_REG_SYNC 21UL
#define KSW_SVGA_REG_BUSY 22UL

#define KSW_SVGA_FIFO_MIN 0UL
#define KSW_SVGA_FIFO_MAX 1UL
#define KSW_SVGA_FIFO_NEXT_CMD 2UL
#define KSW_SVGA_FIFO_STOP 3UL
#define KSW_SVGA_FIFO_HEADER_DWORDS 4UL
#define KSW_SVGA_CMD_UPDATE 1UL

typedef struct KswSvgaPciBar
{
    BOOLEAN present;
    BOOLEAN ioSpace;
    BOOLEAN is64Bit;
    ULONGLONG address;
} KswSvgaPciBar, *PkswSvgaPciBar;

#if defined(_AMD64_) || defined(_M_AMD64)

static VOID
kswordArkSvgaWriteRegister(
    _In_ ULONG ioBase,
    _In_ ULONG Register,
    _In_ ULONG value
    )
{
    WRITE_PORT_ULONG(
        (PULONG)(ULONG_PTR)(ioBase + KSW_SVGA_INDEX_PORT),
        Register);
    WRITE_PORT_ULONG(
        (PULONG)(ULONG_PTR)(ioBase + KSW_SVGA_VALUE_PORT),
        value);
}

static ULONG
kswordArkSvgaReadRegister(
    _In_ ULONG ioBase,
    _In_ ULONG Register
    )
{
    WRITE_PORT_ULONG(
        (PULONG)(ULONG_PTR)(ioBase + KSW_SVGA_INDEX_PORT),
        Register);
    return READ_PORT_ULONG(
        (PULONG)(ULONG_PTR)(ioBase + KSW_SVGA_VALUE_PORT));
}

static ULONG
kswordArkSvgaProbeId(
    _In_ ULONG ioBase
    )
{
    static const ULONG kIds[] = {
        KSW_SVGA_ID_3,
        KSW_SVGA_ID_2,
        KSW_SVGA_ID_1,
        KSW_SVGA_ID_0
    };
    ULONG index;

    for (index = 0; index < RTL_NUMBER_OF(kIds); ++index) {
        kswordArkSvgaWriteRegister(ioBase, KSW_SVGA_REG_ID, kIds[index]);
        if (kswordArkSvgaReadRegister(ioBase, KSW_SVGA_REG_ID) == kIds[index]) {
            return kIds[index];
        }
    }
    return KSW_SVGA_ID_INVALID;
}

static VOID
kswordArkSvgaParseBar(
    _In_ ULONG rawBar,
    _In_ ULONG nextRawBar,
    _Out_ PkswSvgaPciBar bar
    )
{
    RtlZeroMemory(bar, sizeof(*bar));
    if (rawBar == 0 || rawBar == 0xFFFFFFFFUL) {
        return;
    }

    bar->present = TRUE;
    if ((rawBar & KSW_SVGA_PCI_BAR_IO) != 0) {
        bar->ioSpace = TRUE;
        bar->address = rawBar & KSW_SVGA_PCI_BAR_IO_MASK;
        return;
    }

    bar->is64Bit =
        ((rawBar & KSW_SVGA_PCI_BAR_MEM_TYPE_MASK) == KSW_SVGA_PCI_BAR_MEM_TYPE_64)
            ? TRUE
            : FALSE;
    bar->address = rawBar & KSW_SVGA_PCI_BAR_MEM_MASK;
    if (bar->is64Bit) {
        bar->address |= ((ULONGLONG)nextRawBar << 32);
    }
}

static BOOLEAN
kswordArkSvgaFindVmwareDisplay(
    _Out_ PPCI_COMMON_CONFIG configArg,
    _Out_writes_(KSWORD_ARK_PCI_BAR_COUNT) PkswSvgaPciBar bars,
    _Out_ PULONG busOut,
    _Out_ PULONG deviceOut,
    _Out_ PULONG functionOut
    )
{
    ULONG bus;
    ULONG device;
    ULONG function;
    ULONG bytesRead;
    ULONG barIndex;
    PCI_SLOT_NUMBER slot;
    PCI_COMMON_CONFIG config;

    RtlZeroMemory(configArg, sizeof(*configArg));
    RtlZeroMemory(bars, sizeof(KswSvgaPciBar) * KSWORD_ARK_PCI_BAR_COUNT);

    for (bus = 0; bus < KSW_SVGA_PCI_MAX_BUSES; ++bus) {
        for (device = 0; device < KSW_SVGA_PCI_MAX_DEVICES; ++device) {
            for (function = 0; function < KSW_SVGA_PCI_MAX_FUNCTIONS; ++function) {
                RtlZeroMemory(&slot, sizeof(slot));
                slot.u.bits.DeviceNumber = device;
                slot.u.bits.FunctionNumber = function;
                RtlZeroMemory(&config, sizeof(config));

#pragma warning(push)
#pragma warning(disable: 4996)
                bytesRead = HalGetBusDataByOffset(
                    PCIConfiguration,
                    bus,
                    slot.u.AsULONG,
                    &config,
                    0,
                    sizeof(config));
#pragma warning(pop)
                if (bytesRead < PCI_COMMON_HDR_LENGTH ||
                    config.VendorID != KSWORD_ARK_VMWARE_VENDOR_ID ||
                    config.BaseClass != 0x03 ||
                    (config.HeaderType & 0x7FUL) != PCI_DEVICE_TYPE) {
                    continue;
                }

                *configArg = config;
                for (barIndex = 0; barIndex < KSWORD_ARK_PCI_BAR_COUNT; ++barIndex) {
                    const ULONG kNextRawBar = (barIndex + 1UL) < KSWORD_ARK_PCI_BAR_COUNT
                        ? config.u.type0.BaseAddresses[barIndex + 1UL]
                        : 0;
                    kswordArkSvgaParseBar(
                        config.u.type0.BaseAddresses[barIndex],
                        kNextRawBar,
                        &bars[barIndex]);
                }

                *busOut = bus;
                *deviceOut = device;
                *functionOut = function;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN
kswordArkSvgaValidateGeometry(
    _Inout_ PkswordArkSvgaContext context
    )
{
    ULONGLONG visibleBytes;
    ULONG bytesPerPixel;

    if (context->width == 0 || context->height == 0 ||
        context->width > 16384UL || context->height > 16384UL ||
        (context->bpp != 15UL && context->bpp != 16UL &&
         context->bpp != 24UL && context->bpp != 32UL)) {
        return FALSE;
    }

    bytesPerPixel = (context->bpp + 7UL) / 8UL;
    if (bytesPerPixel == 0 ||
        context->pitch < context->width * bytesPerPixel ||
        context->pitch > (1024UL * 1024UL)) {
        return FALSE;
    }

    visibleBytes = (ULONGLONG)context->pitch * context->height;
    if (visibleBytes == 0 || visibleBytes > (256ULL * 1024ULL * 1024ULL)) {
        return FALSE;
    }
    if (context->fbSize != 0 &&
        ((ULONGLONG)context->fbOffset >= context->fbSize ||
         visibleBytes + context->fbOffset > context->fbSize)) {
        return FALSE;
    }

    context->framebufferLength = (SIZE_T)visibleBytes;
    return TRUE;
}

NTSTATUS
kswordArkBugcheckSvgaInitialize(
    _Inout_ PkswordArkSvgaContext context
    )
{
    PCI_COMMON_CONFIG config;
    KswSvgaPciBar bars[KSWORD_ARK_PCI_BAR_COUNT];
    PkswSvgaPciBar fifoBar;
    ULONG bus;
    ULONG device;
    ULONG function;
    ULONG svgaId;
    ULONG fifoBytes;
    PHYSICAL_ADDRESS physical;
    PVOID mapped;

    if (context == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(context, sizeof(*context));
    RtlZeroMemory(&config, sizeof(config));
    RtlZeroMemory(bars, sizeof(bars));

    if (!kswordArkSvgaFindVmwareDisplay(
            &config,
            bars,
            &bus,
            &device,
            &function)) {
        return STATUS_NOT_SUPPORTED;
    }

    // Require the VMware SVGA-II port/framebuffer BAR layout before touching it.
    if (!bars[0].present || !bars[0].ioSpace ||
        !bars[1].present || bars[1].ioSpace ||
        bars[0].address == 0 || bars[0].address > MAXULONG) {
        return STATUS_NOT_SUPPORTED;
    }

    svgaId = kswordArkSvgaProbeId((ULONG)bars[0].address);
    if (svgaId == KSW_SVGA_ID_INVALID) {
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    context->found = TRUE;
    context->bus = bus;
    context->device = device;
    context->function = function;
    context->vendorId = config.VendorID;
    context->deviceId = config.DeviceID;
    context->ioBase = (ULONG)bars[0].address;
    context->width = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_WIDTH);
    context->height = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_HEIGHT);
    context->depth = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_DEPTH);
    context->bpp = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_BITS_PER_PIXEL);
    context->pitch = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_BYTES_PER_LINE);
    context->fbOffset = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_FB_OFFSET);
    context->fbSize = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_FB_SIZE);
    context->vramSize = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_VRAM_SIZE);
    context->redMask = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_RED_MASK);
    context->greenMask = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_GREEN_MASK);
    context->blueMask = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_BLUE_MASK);
    context->capabilities = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_CAPABILITIES);

    if (!kswordArkSvgaValidateGeometry(context) ||
        bars[1].address > (ULONGLONG)MAXLONGLONG - context->fbOffset) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    physical.QuadPart = (LONGLONG)(bars[1].address + context->fbOffset);
    mapped = MmMapIoSpace(physical, context->framebufferLength, MmNonCached);
    if (mapped == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    context->framebufferPhysical = physical;
    context->framebuffer = (volatile UCHAR*)mapped;
    context->mapped = TRUE;

    fifoBar = bars[1].is64Bit ? &bars[3] : &bars[2];
    if (fifoBar->present && !fifoBar->ioSpace) {
        fifoBytes = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_MEM_SIZE);
        if (fifoBytes >= 4096UL && fifoBytes <= (16UL * 1024UL * 1024UL)) {
            physical.QuadPart = (LONGLONG)fifoBar->address;
            mapped = MmMapIoSpace(physical, fifoBytes, MmNonCached);
            if (mapped != NULL) {
                context->fifoPhysical = physical;
                context->fifoLength = fifoBytes;
                context->fifo = (volatile ULONG*)mapped;
                context->fifoMapped = TRUE;
            }
        }
    }

    return STATUS_SUCCESS;
}

VOID
kswordArkBugcheckSvgaShutdown(
    _Inout_ PkswordArkSvgaContext context
    )
{
    if (context == NULL) {
        return;
    }
    if (context->fifoMapped && context->fifo != NULL) {
        MmUnmapIoSpace((PVOID)context->fifo, context->fifoLength);
    }
    if (context->mapped && context->framebuffer != NULL) {
        MmUnmapIoSpace((PVOID)context->framebuffer, context->framebufferLength);
    }
    RtlZeroMemory(context, sizeof(*context));
}

static VOID
kswordArkSvgaPortSyncNoLog(
    _In_ PkswordArkSvgaContext context
    )
{
    ULONG spin;

    if (context == NULL || context->ioBase == 0) {
        return;
    }
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_SYNC, 1UL);
    for (spin = 0; spin < 1000000UL; ++spin) {
        if (kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_BUSY) == 0) {
            break;
        }
        KeStallExecutionProcessor(1);
    }
}

VOID
kswordArkBugcheckSvgaModeSetNoLog(
    _Inout_ PkswordArkSvgaContext context
    )
{
    ULONG configDone;

    if (context == NULL || !context->mapped ||
        context->framebuffer == NULL || context->ioBase == 0) {
        return;
    }

    configDone = kswordArkSvgaReadRegister(context->ioBase, KSW_SVGA_REG_CONFIG_DONE);
    if (configDone == 0) {
        configDone = 1;
    }
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_ENABLE, 0UL);
    KeStallExecutionProcessor(1000);
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_WIDTH, context->width);
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_HEIGHT, context->height);
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_BITS_PER_PIXEL, context->bpp);
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_ENABLE, 1UL);
    kswordArkSvgaWriteRegister(context->ioBase, KSW_SVGA_REG_CONFIG_DONE, configDone);
    KeStallExecutionProcessor(1000);
    kswordArkSvgaPortSyncNoLog(context);
}

static BOOLEAN
kswordArkSvgaFifoUpdateNoLog(
    _Inout_ PkswordArkSvgaContext context,
    _In_ ULONG x,
    _In_ ULONG y,
    _In_ ULONG width,
    _In_ ULONG height
    )
{
    volatile ULONG* fifo;
    ULONG min;
    ULONG max;
    ULONG next;
    ULONG stop;
    ULONG freeBytes;
    ULONG values[5];
    ULONG index;

    if (context == NULL || !context->fifoMapped || context->fifo == NULL ||
        context->fifoLength < (KSW_SVGA_FIFO_HEADER_DWORDS * sizeof(ULONG))) {
        return FALSE;
    }

    fifo = context->fifo;
    min = fifo[KSW_SVGA_FIFO_MIN];
    max = fifo[KSW_SVGA_FIFO_MAX];
    next = fifo[KSW_SVGA_FIFO_NEXT_CMD];
    stop = fifo[KSW_SVGA_FIFO_STOP];
    if (min < KSW_SVGA_FIFO_HEADER_DWORDS * sizeof(ULONG) ||
        max > context->fifoLength || min >= max ||
        next < min || next >= max || stop < min || stop >= max ||
        ((min | max | next | stop) & 3UL) != 0) {
        return FALSE;
    }

    if (next >= stop) {
        freeBytes = (max - next) + (stop - min);
    } else {
        freeBytes = stop - next;
    }
    if (freeBytes <= sizeof(values)) {
        return FALSE;
    }

    values[0] = KSW_SVGA_CMD_UPDATE;
    values[1] = x;
    values[2] = y;
    values[3] = width;
    values[4] = height;
    for (index = 0; index < RTL_NUMBER_OF(values); ++index) {
        fifo[next / sizeof(ULONG)] = values[index];
        next += sizeof(ULONG);
        if (next == max) {
            next = min;
        }
    }
    KeMemoryBarrier();
    fifo[KSW_SVGA_FIFO_NEXT_CMD] = next;
    KeMemoryBarrier();
    kswordArkSvgaPortSyncNoLog(context);
    return TRUE;
}

static ULONG
kswordArkSvgaPackChannel(
    _In_ UCHAR value,
    _In_ ULONG mask
    )
{
    ULONG shift = 0;
    ULONG bits = 0;
    ULONG work = mask;
    ULONG maximum;

    if (mask == 0) {
        return 0;
    }
    while ((work & 1UL) == 0) {
        ++shift;
        work >>= 1;
    }
    while ((work & 1UL) != 0) {
        ++bits;
        work >>= 1;
    }
    maximum = bits >= 31 ? MAXULONG : ((1UL << bits) - 1UL);
    return ((((ULONG)value * maximum) + 127UL) / 255UL) << shift;
}

static ULONG
kswordArkSvgaPixelFromRgb(
    _In_ PkswordArkSvgaContext context,
    _In_ UCHAR red,
    _In_ UCHAR green,
    _In_ UCHAR blue
    )
{
    ULONG redMask = context->redMask;
    ULONG greenMask = context->greenMask;
    ULONG blueMask = context->blueMask;

    if (redMask == 0 || greenMask == 0 || blueMask == 0) {
        if (context->bpp == 15) {
            redMask = 0x7C00UL;
            greenMask = 0x03E0UL;
            blueMask = 0x001FUL;
        } else if (context->bpp == 16) {
            redMask = 0xF800UL;
            greenMask = 0x07E0UL;
            blueMask = 0x001FUL;
        } else {
            redMask = 0x00FF0000UL;
            greenMask = 0x0000FF00UL;
            blueMask = 0x000000FFUL;
        }
    }

    return kswordArkSvgaPackChannel(red, redMask) |
           kswordArkSvgaPackChannel(green, greenMask) |
           kswordArkSvgaPackChannel(blue, blueMask);
}

static VOID
kswordArkSvgaWritePixel(
    _In_ PkswordArkSvgaContext context,
    _In_ ULONG x,
    _In_ ULONG y,
    _In_ ULONG pixel
    )
{
    volatile UCHAR* destination;
    ULONG bytesPerPixel;

    if (context == NULL || !context->mapped || context->framebuffer == NULL ||
        x >= context->width || y >= context->height) {
        return;
    }
    bytesPerPixel = (context->bpp + 7UL) / 8UL;
    destination = context->framebuffer + ((SIZE_T)y * context->pitch) +
                  ((SIZE_T)x * bytesPerPixel);
    if (bytesPerPixel == 4) {
        *(volatile ULONG*)destination = pixel;
    } else if (bytesPerPixel == 3) {
        destination[0] = (UCHAR)(pixel & 0xFF);
        destination[1] = (UCHAR)((pixel >> 8) & 0xFF);
        destination[2] = (UCHAR)((pixel >> 16) & 0xFF);
    } else if (bytesPerPixel == 2) {
        *(volatile USHORT*)destination = (USHORT)pixel;
    }
}

static VOID
kswordArkSvgaFillRect(
    _In_ PkswordArkSvgaContext context,
    _In_ ULONG left,
    _In_ ULONG top,
    _In_ ULONG right,
    _In_ ULONG bottom,
    _In_ ULONG pixel
    )
{
    ULONG x;
    ULONG y;

    if (context == NULL || left >= context->width || top >= context->height) {
        return;
    }
    if (right > context->width) {
        right = context->width;
    }
    if (bottom > context->height) {
        bottom = context->height;
    }
    for (y = top; y < bottom; ++y) {
        for (x = left; x < right; ++x) {
            kswordArkSvgaWritePixel(context, x, y, pixel);
        }
    }
}

static VOID
kswordArkSvgaDrawCharacter(
    _In_ PkswordArkSvgaContext context,
    _In_ ULONG x,
    _In_ ULONG y,
    _In_ CHAR character,
    _In_ ULONG color,
    _In_ ULONG scale
    )
{
    ULONG row;
    ULONG column;
    ULONG dx;
    ULONG dy;
    UCHAR bits;
    ULONG glyphIndex;

    if ((UCHAR)character < KSWORD_ARK_BUGCHECK_FONT_FIRST ||
        (UCHAR)character > KSWORD_ARK_BUGCHECK_FONT_LAST) {
        character = '?';
    }
    if (scale == 0) {
        scale = 1;
    }

    glyphIndex = (UCHAR)character - KSWORD_ARK_BUGCHECK_FONT_FIRST;
    for (row = 0; row < KSWORD_ARK_BUGCHECK_FONT_HEIGHT; ++row) {
        bits = kGKswordArkBugcheckFont8x12[glyphIndex][row];
        for (column = 0; column < KSWORD_ARK_BUGCHECK_FONT_WIDTH; ++column) {
            if ((bits & (0x80U >> column)) == 0) {
                continue;
            }
            for (dy = 0; dy < scale; ++dy) {
                for (dx = 0; dx < scale; ++dx) {
                    kswordArkSvgaWritePixel(
                        context,
                        x + column * scale + dx,
                        y + row * scale + dy,
                        color);
                }
            }
        }
    }
}

static VOID
kswordArkSvgaDrawText(
    _In_ PkswordArkSvgaContext context,
    _In_ ULONG x,
    _In_ ULONG y,
    _In_z_ PCSTR text,
    _In_ ULONG color,
    _In_ ULONG scale
    )
{
    ULONG cursor = x;

    if (text == NULL) {
        return;
    }
    while (*text != '\0') {
        kswordArkSvgaDrawCharacter(context, cursor, y, *text, color, scale);
        cursor += (KSWORD_ARK_BUGCHECK_FONT_WIDTH + 1UL) * scale;
        if (cursor >= context->width) {
            break;
        }
        ++text;
    }
}

static BOOLEAN
kswordArkSvgaDrawBitmap(
    _In_ PkswordArkBugcheckState state,
    _In_ ULONG destinationX,
    _In_ ULONG destinationY,
    _In_ ULONG destinationWidth,
    _In_ ULONG destinationHeight
    )
{
    ULONG backgroundBlue;
    ULONG backgroundGreen;
    ULONG backgroundRed;
    ULONG width;
    ULONG height;
    ULONG x;
    ULONG y;
    ULONG pixel;

    if (state == NULL || destinationWidth == 0 || destinationHeight == 0 ||
        InterlockedCompareExchange(&state->bitmap.valid, 1, 1) == 0 ||
        destinationX >= state->svga.width || destinationY >= state->svga.height) {
        return FALSE;
    }

    width = destinationWidth;
    height = destinationHeight;
    if (destinationX + width > state->svga.width) {
        width = state->svga.width - destinationX;
    }
    if (destinationY + height > state->svga.height) {
        height = state->svga.height - destinationY;
    }

    backgroundRed = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED;
    backgroundGreen = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN;
    backgroundBlue = KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE;
    for (y = 0; y < height; ++y) {
        ULONG sourceY;

        sourceY = (y * state->bitmap.height) / height;
        for (x = 0; x < width; ++x) {
            ULONG alpha;
            ULONG sourceBlue;
            ULONG sourceGreen;
            ULONG sourceRed;
            ULONG sourceX;
            const UCHAR* source;

            sourceX = (x * state->bitmap.width) / width;
            source = gKswordArkBugcheckBitmapPixels +
                ((SIZE_T)sourceY * state->bitmap.stride) +
                ((SIZE_T)sourceX * 4UL);
            sourceBlue = source[0];
            sourceGreen = source[1];
            sourceRed = source[2];
            alpha = source[3];
            pixel = kswordArkSvgaPixelFromRgb(
                &state->svga,
                (UCHAR)((sourceRed * alpha +
                         backgroundRed * (255UL - alpha)) / 255UL),
                (UCHAR)((sourceGreen * alpha +
                         backgroundGreen * (255UL - alpha)) / 255UL),
                (UCHAR)((sourceBlue * alpha +
                         backgroundBlue * (255UL - alpha)) / 255UL));
            kswordArkSvgaWritePixel(
                &state->svga,
                destinationX + x,
                destinationY + y,
                pixel);
        }
    }
    return TRUE;
}

typedef struct KswordArkSvgaLayoutContext
{
    PkswordArkSvgaContext svga;
    ULONG colors[kKswordArkBugcheckLayoutColorCount];
    ULONG border;
} KswordArkSvgaLayoutContext, *PkswordArkSvgaLayoutContext;

static NTSTATUS
kswordArkSvgaLayoutDrawText(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_z_ PCSTR text,
    _In_ ULONG colorIndex
    )
{
    PkswordArkSvgaLayoutContext layout;

    layout = (PkswordArkSvgaLayoutContext)context;
    if (layout == NULL || layout->svga == NULL || text == NULL ||
        x < 0 || y < 0 ||
        colorIndex >= (ULONG)kKswordArkBugcheckLayoutColorCount) {
        return STATUS_INVALID_PARAMETER;
    }

    kswordArkSvgaDrawText(
        layout->svga,
        (ULONG)x,
        (ULONG)y,
        text,
        layout->colors[colorIndex],
        1UL);
    return STATUS_SUCCESS;
}

static NTSTATUS
kswordArkSvgaLayoutDrawFrame(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_ KswordArkBugcheckLayoutFrame frame
    )
{
    PkswordArkSvgaLayoutContext layout;
    ULONG width;
    ULONG height;
    ULONG left;
    ULONG top;

    layout = (PkswordArkSvgaLayoutContext)context;
    if (layout == NULL || layout->svga == NULL || x < 0 || y < 0 ||
        !kswordArkBugcheckLayoutGetFrameMetrics(frame, &width, &height)) {
        return STATUS_INVALID_PARAMETER;
    }

    left = (ULONG)x;
    top = (ULONG)y;
    // Draw one-pixel outlines without allocating any crash-time resources.
    kswordArkSvgaFillRect(
        layout->svga,
        left,
        top,
        left + width,
        top + 1UL,
        layout->border);
    kswordArkSvgaFillRect(
        layout->svga,
        left,
        top + height - 1UL,
        left + width,
        top + height,
        layout->border);
    kswordArkSvgaFillRect(
        layout->svga,
        left,
        top,
        left + 1UL,
        top + height,
        layout->border);
    kswordArkSvgaFillRect(
        layout->svga,
        left + width - 1UL,
        top,
        left + width,
        top + height,
        layout->border);
    return STATUS_SUCCESS;
}

VOID
kswordArkBugcheckSvgaDrawPanelNoLog(
    _Inout_ PkswordArkBugcheckState state
    )
{
    KswordArkBugcheckLayoutCanvas canvas;
    KswordArkSvgaLayoutContext layout;
    PkswordArkSvgaContext svga;
    LONG originX;
    ULONG background;
    ULONG callbackMask;

    if (state == NULL ||
        InterlockedCompareExchange(&state->active, 1, 1) == 0) {
        return;
    }
    svga = &state->svga;
    if (!svga->mapped || svga->framebuffer == NULL ||
        svga->width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
        svga->height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT) {
        return;
    }

    RtlZeroMemory(&layout, sizeof(layout));
    layout.svga = svga;
    background = kswordArkSvgaPixelFromRgb(
        svga,
        KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED,
        KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN,
        KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE);
    layout.colors[kKswordArkBugcheckLayoutColorText] =
        kswordArkSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE);
    layout.colors[kKswordArkBugcheckLayoutColorAccent] =
        kswordArkSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_BLUE);
    layout.colors[kKswordArkBugcheckLayoutColorMuted] =
        kswordArkSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_BLUE);
    layout.colors[kKswordArkBugcheckLayoutColorWarning] =
        kswordArkSvgaPixelFromRgb(
            svga,
            KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_RED,
            KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_GREEN,
            KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_BLUE);
    layout.border = kswordArkSvgaPixelFromRgb(
        svga,
        KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_RED,
        KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_GREEN,
        KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_BLUE);

    kswordArkSvgaFillRect(
        svga,
        0UL,
        0UL,
        svga->width,
        svga->height,
        background);
    originX = kswordArkBugcheckLayoutOriginX(
        svga->width,
        svga->height);
    if (!kswordArkSvgaDrawBitmap(
            state,
            (ULONG)(originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X),
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y,
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_WIDTH,
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_HEIGHT)) {
        // The text fallback deliberately uses the requested KSwordDEV brand.
        kswordArkSvgaDrawText(
            svga,
            (ULONG)(originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X),
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y + 18UL,
            "KSWORDDEV",
            layout.colors[kKswordArkBugcheckLayoutColorAccent],
            2UL);
        kswordArkSvgaDrawText(
            svga,
            (ULONG)(originX + KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X),
            KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y + 50UL,
            "KERNEL TOOLKIT",
            layout.colors[kKswordArkBugcheckLayoutColorMuted],
            1UL);
    }

    callbackMask = 0UL;
    if (state->classicRegistered) {
        callbackMask |= 0x1UL;
    }
    if (state->secondaryRegistered) {
        callbackMask |= 0x2UL;
    }
    if (state->dumpIoRegistered) {
        callbackMask |= 0x4UL;
    }
    if (state->triageRegistered) {
        callbackMask |= 0x8UL;
    }

    RtlZeroMemory(&canvas, sizeof(canvas));
    canvas.context = &layout;
    canvas.width = svga->width;
    canvas.height = svga->height;
    canvas.drawText = kswordArkSvgaLayoutDrawText;
    canvas.drawFrame = kswordArkSvgaLayoutDrawFrame;
    (VOID)kswordArkBugcheckLayoutDraw(
        &canvas,
        &state->diagnostics,
        callbackMask,
        state->moduleCount);

    KeMemoryBarrier();
    if (!kswordArkSvgaFifoUpdateNoLog(
            svga,
            0UL,
            0UL,
            svga->width,
            svga->height)) {
        kswordArkSvgaPortSyncNoLog(svga);
    }
}

#else

NTSTATUS
KswordARKBugcheckSvgaInitialize(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(*Context));
    }
    return STATUS_NOT_SUPPORTED;
}

VOID
KswordARKBugcheckSvgaShutdown(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(*Context));
    }
}

VOID
KswordARKBugcheckSvgaModeSetNoLog(
    _Inout_ PKSWORD_ARK_SVGA_CONTEXT Context
    )
{
    UNREFERENCED_PARAMETER(Context);
}

VOID
KswordARKBugcheckSvgaDrawPanelNoLog(
    _Inout_ PKSWORD_ARK_BUGCHECK_STATE State
    )
{
    UNREFERENCED_PARAMETER(State);
}

#endif

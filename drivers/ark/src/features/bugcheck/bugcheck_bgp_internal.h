#pragma once

#include "bugcheck_bgp.h"

typedef NTSTATUS
(*PkswordArkBgpClearScreen)(
    _In_ ULONG argbColor
    );

typedef NTSTATUS
(*PkswordArkBgpDrawRectangle)(
    _In_ PVOID rectangle,
    _In_ const VOID* position
    );

typedef VOID
(*PkswordArkBgpLock)(
    VOID
    );

typedef PVOID
(*PkswordArkBgpGetResolution)(
    _Out_ PVOID resolution
    );

typedef ULONG
(*PkswordArkBgpGetBpp)(
    VOID
    );

typedef NTSTATUS
(*PkswordArkBgpParseBitmap)(
    _In_ const VOID* bitmap,
    _Out_ PVOID* rectangle
    );

typedef NTSTATUS
(*PkswordArkBgpDestroyRectangle)(
    _In_opt_ PVOID rectangle
    );

typedef VOID
(*PkswordArkInbvAcquireDisplayOwnership)(
    VOID
    );

typedef struct KswordArkBgpPosition
{
    LONG x;
    LONG y;
} KswordArkBgpPosition, *PkswordArkBgpPosition;

#pragma pack(push, 1)
typedef struct KswordArkBgpBitmapFileHeader
{
    USHORT type;
    ULONG size;
    USHORT reserved1;
    USHORT reserved2;
    ULONG pixelOffset;
} KswordArkBgpBitmapFileHeader, *PkswordArkBgpBitmapFileHeader;

typedef struct KswordArkBgpBitmapInfoHeader
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
} KswordArkBgpBitmapInfoHeader, *PkswordArkBgpBitmapInfoHeader;
#pragma pack(pop)

typedef struct KswordArkBgpContext
{
    PkswordArkBgpClearScreen clear;
    PkswordArkBgpDrawRectangle draw;
    PkswordArkBgpLock acquire;
    PkswordArkBgpLock release;
    PkswordArkBgpGetResolution getResolution;
    PkswordArkBgpGetBpp getBpp;
    PkswordArkBgpParseBitmap parseBitmap;
    PkswordArkBgpDestroyRectangle destroyRectangle;
    PkswordArkInbvAcquireDisplayOwnership acquireOwnership;
    volatile LONG resolvedSnapshotReady;
    ULONG featureMask;
    ULONG signatureFamily[KSWORD_ARK_BGP_SIGNATURE_COUNT];
    KswordArkBgpScreenInfo screen;
    ULONG requiredWidth;
    ULONG requiredHeight;
    volatile LONG state;
    volatile LONG preparationStage;
    volatile LONG preparationStatus;
    ULONG probeWidth;
    ULONG probeHeight;
    ULONG probeBpp;
    volatile LONG stage;
    volatile LONG drawStarted;
    volatile LONG resourceUpdateActive;
    volatile LONG lockHeld;
    volatile LONG drawStageStarted;
    volatile LONG64 drawCount;
    volatile LONG lastStatus;
    volatile LONG clearStatus;
    volatile LONG drawStatus;
    volatile LONG timelineCount;
    struct
    {
        volatile LONG stage;
        volatile LONG status;
    } timeline[KSWORD_ARK_BGP_TIMELINE_COUNT];
} KswordArkBgpContext, *PkswordArkBgpContext;

extern KswordArkBgpContext gKswordArkBgp;

// Resolver and rectangle preparation use the controller-owned deadline and unload cancellation.
NTSTATUS
kswordArkBugcheckControlCheckAbort(
    VOID
    );

VOID
kswordArkBugcheckBgpRecordStage(
    _In_ LONG stage,
    _In_ NTSTATUS status
    );

NTSTATUS
kswordArkBugcheckBgpResolveFunctions(
    VOID
    );

NTSTATUS
kswordArkBugcheckBgpReadScreen(
    _Out_ PkswordArkBgpScreenInfo screen
    );

// Invoke the validated private BGP parser without applying CFG to the private
// kernel target itself.  The resolver remains responsible for validating the
// target image, section, signature family, and uniqueness before publication.
NTSTATUS
kswordArkBugcheckBgpInvokeParseBitmap(
    _In_ const VOID* bitmap,
    _Out_ PVOID* rectangle
    );

// Invoke the validated private BGP rectangle destructor through the same
// narrowly scoped no-CFG boundary used by the remaining private BGP calls.
NTSTATUS
kswordArkBugcheckBgpInvokeDestroyRectangle(
    _In_opt_ PVOID rectangle
    );

// Invoke the validated private BGP lock release routine without extending the
// CFG exception to the lifecycle caller or any unrelated driver code.
VOID
kswordArkBugcheckBgpInvokeRelease(
    VOID
    );

NTSTATUS
kswordArkBugcheckBgpValidateBitmap(
    _In_reads_bytes_(bitmapLength) const VOID* bitmap,
    _In_ ULONG bitmapLength
    );

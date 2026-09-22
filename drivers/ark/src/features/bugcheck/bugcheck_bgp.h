#pragma once

#include <ntddk.h>

#define KSWORD_ARK_BGP_FEATURE_CLEAR       0x00000001UL
#define KSWORD_ARK_BGP_FEATURE_DRAW        0x00000002UL
#define KSWORD_ARK_BGP_FEATURE_ACQUIRE     0x00000004UL
#define KSWORD_ARK_BGP_FEATURE_RELEASE     0x00000008UL
#define KSWORD_ARK_BGP_FEATURE_RESOLUTION  0x00000010UL
#define KSWORD_ARK_BGP_FEATURE_BPP         0x00000020UL
#define KSWORD_ARK_BGP_FEATURE_PARSE       0x00000040UL
#define KSWORD_ARK_BGP_FEATURE_DESTROY     0x00000080UL
#define KSWORD_ARK_BGP_FEATURE_INBV        0x00000100UL
#define KSWORD_ARK_BGP_UNOWNED_BPP         1UL

#define KSWORD_ARK_BGP_SIGNATURE_COUNT 8UL
#define KSWORD_ARK_BGP_TIMELINE_COUNT 16UL

typedef enum KswordArkBgpState
{
    kKswordArkBgpStateUninitialized = 0,
    kKswordArkBgpStateQueryOnly,
    kKswordArkBgpStateReady,
    kKswordArkBgpStateArmed,
    kKswordArkBgpStateDrawn,
    kKswordArkBgpStateRejected,
    kKswordArkBgpStateUnloading
} KswordArkBgpState;

typedef enum KswordArkBgpStage
{
    kKswordArkBgpStageIdle = 0,
    kKswordArkBgpStageCallbackEntered = 0x0100,
    kKswordArkBgpStageOwnershipBefore = 0x0200,
    kKswordArkBgpStageOwnershipAfter = 0x0201,
    kKswordArkBgpStageAcquireBefore = 0x0300,
    kKswordArkBgpStageAcquireAfter = 0x0301,
    kKswordArkBgpStageScreenBefore = 0x0350,
    kKswordArkBgpStageScreenAfter = 0x0351,
    kKswordArkBgpStageClearBefore = 0x0400,
    kKswordArkBgpStageClearAfter = 0x0401,
    kKswordArkBgpStageDrawBefore = 0x0500,
    kKswordArkBgpStageDrawAfter = 0x0501,
    kKswordArkBgpStageReleaseBefore = 0x0600,
    kKswordArkBgpStageReleaseAfter = 0x0601,
    kKswordArkBgpStageComplete = 0x0700,
    kKswordArkBgpStageRejected = 0x80000000UL
} KswordArkBgpStage;

// These values identify the exact PASSIVE_LEVEL preparation operation that
// most recently ran, so a load-time report can distinguish resolver, display,
// bitmap, glyph, and arming failures without doing file I/O during a bugcheck.
typedef enum KswordArkBgpPreparationStage
{
    kKswordArkBgpPreparationIdle = 0,
    kKswordArkBgpPreparationResolveFunctions,
    kKswordArkBgpPreparationReadScreen,
    kKswordArkBgpPreparationBackendReady,
    kKswordArkBgpPreparationValidatePanelScreen,
    kKswordArkBgpPreparationPrepareLogo,
    kKswordArkBgpPreparationPrepareGlyphs,
    kKswordArkBgpPreparationArm,
    kKswordArkBgpPreparationComplete
} KswordArkBgpPreparationStage;

typedef struct KswordArkBgpScreenInfo
{
    ULONG width;
    ULONG height;
    ULONG bitsPerPixel;
    ULONG reserved;
} KswordArkBgpScreenInfo, *PkswordArkBgpScreenInfo;

typedef struct KswordArkBgpTimelineEntry
{
    ULONG stage;
    ULONG status;
} KswordArkBgpTimelineEntry, *PkswordArkBgpTimelineEntry;

typedef struct KswordArkBgpDumpState
{
    ULONG version;
    ULONG size;
    ULONG state;
    ULONG preparationStage;
    ULONG preparationStatus;
    ULONG stage;
    ULONG lastStatus;
    ULONG clearStatus;
    ULONG drawStatus;
    ULONG featureMask;
    ULONG screenWidth;
    ULONG screenHeight;
    ULONG screenBpp;
    ULONG requiredWidth;
    ULONG requiredHeight;
    ULONG64 drawCount;
    ULONG signatureFamily[KSWORD_ARK_BGP_SIGNATURE_COUNT];
    ULONG timelineCount;
    KswordArkBgpTimelineEntry timeline[KSWORD_ARK_BGP_TIMELINE_COUNT];
} KswordArkBgpDumpState, *PkswordArkBgpDumpState;

NTSTATUS
kswordArkBugcheckBgpInitialize(
    VOID
    );

VOID
kswordArkBugcheckBgpShutdown(
    VOID
    );

NTSTATUS
kswordArkBugcheckBgpGetScreenInfo(
    _Out_ PkswordArkBgpScreenInfo screen
    );

NTSTATUS
kswordArkBugcheckBgpParseBitmap(
    _In_reads_bytes_(bitmapLength) const VOID* bitmap,
    _In_ ULONG bitmapLength,
    _Out_ PVOID* rectangle
    );

// Runtime verdict resources arrive after the panel has been armed.  This gate
// keeps the private bitmap parser and the bugcheck drawing path mutually
// exclusive without making the crash callback wait on a pageable lock.
NTSTATUS
kswordArkBugcheckBgpBeginResourceUpdate(
    VOID
    );

VOID
kswordArkBugcheckBgpEndResourceUpdate(
    VOID
    );

VOID
kswordArkBugcheckBgpDestroyRectangle(
    _In_opt_ PVOID rectangle
    );

NTSTATUS
kswordArkBugcheckBgpArm(
    _In_ ULONG requiredWidth,
    _In_ ULONG requiredHeight
    );

VOID
kswordArkBugcheckBgpRejectPreparation(
    _In_ NTSTATUS status
    );

// Record one load-time preparation operation in nonpaged BGP state. The
// caller supplies the operation and its current or final NTSTATUS value.
VOID
kswordArkBugcheckBgpRecordPreparation(
    _In_ KswordArkBgpPreparationStage stage,
    _In_ NTSTATUS status
    );

// Return the latest BGP BPP value cached by the crash-time screen probe.
// The caller uses it only after display ownership has been acquired.
ULONG
kswordArkBugcheckBgpGetCurrentBpp(
    VOID
    );

NTSTATUS
kswordArkBugcheckBgpBeginDraw(
    VOID
    );

NTSTATUS
kswordArkBugcheckBgpClearScreen(
    _In_ ULONG argbColor
    );

NTSTATUS
kswordArkBugcheckBgpDrawRectangle(
    _In_ PVOID rectangle,
    _In_ LONG x,
    _In_ LONG y
    );

VOID
kswordArkBugcheckBgpFinishDraw(
    _In_ NTSTATUS drawStatus
    );

VOID
kswordArkBugcheckBgpSnapshot(
    _Out_ PkswordArkBgpDumpState snapshot
    );

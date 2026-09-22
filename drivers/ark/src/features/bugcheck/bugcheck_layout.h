#pragma once

#include <ntddk.h>

#include "bugcheck_internal.h"

#define KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH 640UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT 480UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH 1024UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_FULL_HEIGHT 768UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH 1280UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_HEIGHT 720UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_WIDTH 240UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_HEIGHT 84UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X 16L
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y 12L

#define KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED 5U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN 15U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE 33U
#define KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED 226U
#define KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN 232U
#define KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE 244U
#define KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_RED 68U
#define KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_GREEN 126U
#define KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_BLUE 255U
#define KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_RED 148U
#define KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_GREEN 163U
#define KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_BLUE 190U
#define KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_RED 255U
#define KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_GREEN 92U
#define KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_BLUE 104U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_RED 24U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_GREEN 45U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_BLUE 75U

typedef enum KswordArkBugcheckLayoutColor
{
    kKswordArkBugcheckLayoutColorText = 0,
    kKswordArkBugcheckLayoutColorAccent,
    kKswordArkBugcheckLayoutColorMuted,
    kKswordArkBugcheckLayoutColorWarning,
    kKswordArkBugcheckLayoutColorCount
} KswordArkBugcheckLayoutColor;

typedef enum KswordArkBugcheckLayoutFrame
{
    kKswordArkBugcheckLayoutFrameCompactColumn = 0,
    kKswordArkBugcheckLayoutFrameCompactWide,
    kKswordArkBugcheckLayoutFrameFullTopLeft,
    kKswordArkBugcheckLayoutFrameFullTopMiddle,
    kKswordArkBugcheckLayoutFrameFullTopRight,
    kKswordArkBugcheckLayoutFrameFullMiddleLeft,
    kKswordArkBugcheckLayoutFrameFullMiddleMiddle,
    kKswordArkBugcheckLayoutFrameFullMiddleRight,
    kKswordArkBugcheckLayoutFrameFullBottomLeft,
    kKswordArkBugcheckLayoutFrameFullBottomRight,
    kKswordArkBugcheckLayoutFrameDetailedTopLeft,
    kKswordArkBugcheckLayoutFrameDetailedTopMiddle,
    kKswordArkBugcheckLayoutFrameDetailedTopRight,
    kKswordArkBugcheckLayoutFrameDetailedMiddleThread,
    kKswordArkBugcheckLayoutFrameDetailedMiddleStack,
    kKswordArkBugcheckLayoutFrameDetailedMiddleModule,
    kKswordArkBugcheckLayoutFrameDetailedMiddleBlackbox,
    kKswordArkBugcheckLayoutFrameDetailedBottomCpu,
    kKswordArkBugcheckLayoutFrameDetailedBottomDump,
    kKswordArkBugcheckLayoutFrameDetailedBottomEvent,
    kKswordArkBugcheckLayoutFrameDetailedBottomHelp,
    kKswordArkBugcheckLayoutFrameCount
} KswordArkBugcheckLayoutFrame;

typedef NTSTATUS
(*PkswordArkBugcheckLayoutDrawText)(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_z_ PCSTR text,
    _In_ ULONG colorIndex
    );

typedef NTSTATUS
(*PkswordArkBugcheckLayoutDrawFrame)(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_ KswordArkBugcheckLayoutFrame frame
    );

typedef NTSTATUS
(*PkswordArkBugcheckLayoutDrawVerdict)(
    _In_opt_ PVOID context,
    _In_ LONG x,
    _In_ LONG y,
    _In_ ULONG classification
    );

typedef struct KswordArkBugcheckLayoutCanvas
{
    PVOID context;
    ULONG width;
    ULONG height;
    PkswordArkBugcheckLayoutDrawText drawText;
    PkswordArkBugcheckLayoutDrawFrame drawFrame;
    PkswordArkBugcheckLayoutDrawVerdict drawVerdict;
} KswordArkBugcheckLayoutCanvas,
  *PkswordArkBugcheckLayoutCanvas;

BOOLEAN
kswordArkBugcheckLayoutIsCompact(
    _In_ ULONG width,
    _In_ ULONG height
    );

BOOLEAN
kswordArkBugcheckLayoutIsDetailed(
    _In_ ULONG width,
    _In_ ULONG height
    );

LONG
kswordArkBugcheckLayoutOriginX(
    _In_ ULONG width,
    _In_ ULONG height
    );

BOOLEAN
kswordArkBugcheckLayoutGetFrameMetrics(
    _In_ KswordArkBugcheckLayoutFrame frame,
    _Out_ PULONG width,
    _Out_ PULONG height
    );

NTSTATUS
kswordArkBugcheckLayoutDraw(
    _In_ const KswordArkBugcheckLayoutCanvas* canvas,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    );

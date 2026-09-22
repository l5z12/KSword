#include <ntddk.h>
#include <stdio.h>
#include <string.h>

#include "../../drivers/ark/src/features/bugcheck/bugcheck_layout.h"
#include "../../drivers/ark/src/features/bugcheck/bugcheck_decode.h"

#define REPLAY_MAX_LINES 96UL
#define REPLAY_MAX_FRAMES 8UL
#define REPLAY_GLYPH_ADVANCE 9UL
#define REPLAY_GLYPH_HEIGHT 12UL

typedef struct ReplayLine
{
    LONG x;
    LONG y;
    ULONG color;
    CHAR text[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} ReplayLine;

typedef struct ReplayFrame
{
    LONG x;
    LONG y;
    KswordArkBugcheckLayoutFrame frame;
} ReplayFrame;

typedef struct ReplayContext
{
    ULONG lineCount;
    ULONG frameCount;
    ULONG verdictCount;
    LONG verdictX;
    LONG verdictY;
    ReplayLine lines[REPLAY_MAX_LINES];
    ReplayFrame frames[REPLAY_MAX_FRAMES];
} ReplayContext;

KswordArkBugcheckState gKswordArkBugcheckState;
UCHAR gKswordArkBugcheckBitmapPixels[KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES];

PCSTR
kswordArkBugcheckName(
    _In_ ULONG bugCheckCode
    )
{
    switch (BugCheckCode) {
    case 0x000000D1: return "DRIVER_IRQL_NOT_LESS_OR_EQUAL";
    case 0x000000D5: return "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL";
    case 0x000000EF: return "CRITICAL_PROCESS_DIED";
    case 0x00000124: return "WHEA_UNCORRECTABLE_ERROR";
    default: return "UNKNOWN_BUGCHECK_CODE";
    }
}

PCSTR
kswordArkBugcheckModuleClassText(
    _In_ ULONG classification
    )
{
    switch (Classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS: return "KSWORDARK";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT: return "MICROSOFT";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY: return "THIRD-PARTY";
    default: return "UNKNOWN";
    }
}

PCSTR
kswordArkBugcheckConfidenceText(
    _In_ ULONG confidence
    )
{
    switch (Confidence) {
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH: return "HIGH";
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_MEDIUM: return "MEDIUM";
    case KSWORD_ARK_BUGCHECK_CONFIDENCE_LOW: return "LOW";
    default: return "NONE";
    }
}

PCSTR
kswordArkBugcheckVerdictText(
    _In_ ULONG classification
    )
{
    UNREFERENCED_PARAMETER(Classification);
    return "The dump provides the final attribution.";
}

PCSTR
kswordArkBugcheckReasonText(
    _In_ ULONG reason
    )
{
    UNREFERENCED_PARAMETER(Reason);
    return "DumpIo";
}

PCSTR
kswordArkBugcheckDumpTypeText(
    _In_ ULONG dumpType
    )
{
    UNREFERENCED_PARAMETER(DumpType);
    return "Header";
}

static NTSTATUS
replayDrawText(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG ColorIndex
    )
{
    ReplayContext* replay = (ReplayContext*)Context;
    ReplayLine* line;

    if (replay == NULL || replay->LineCount >= REPLAY_MAX_LINES) {
        return STATUS_BUFFER_OVERFLOW;
    }
    line = &replay->Lines[replay->LineCount++];
    line->X = X;
    line->Y = Y;
    line->Color = ColorIndex;
    (void)strncpy_s(line->Text, sizeof(line->Text), Text, _TRUNCATE);
    return STATUS_SUCCESS;
}

static NTSTATUS
replayDrawFrame(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame
    )
{
    ReplayContext* replay = (ReplayContext*)Context;
    ReplayFrame* recorded;

    if (replay == NULL || replay->FrameCount >= REPLAY_MAX_FRAMES) {
        return STATUS_BUFFER_OVERFLOW;
    }
    recorded = &replay->Frames[replay->FrameCount++];
    recorded->X = X;
    recorded->Y = Y;
    recorded->frame = frame;
    return STATUS_SUCCESS;
}

static NTSTATUS
replayDrawVerdict(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG Classification
    )
{
    ReplayContext* replay = (ReplayContext*)Context;

    UNREFERENCED_PARAMETER(Classification);
    if (replay == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    ++replay->VerdictCount;
    replay->VerdictX = X;
    replay->VerdictY = Y;
    return STATUS_SUCCESS;
}

static const ReplayLine*
replayFindLine(
    _In_ const ReplayContext* replay,
    _In_z_ PCSTR fragment
    )
{
    ULONG index;

    for (index = 0; index < Replay->LineCount; ++index) {
        if (strstr(Replay->Lines[index].Text, Fragment) != NULL) {
            return &Replay->Lines[index];
        }
    }
    return NULL;
}

static int
replayRequireLine(
    _In_ const ReplayContext* replay,
    _In_z_ PCSTR fragment
    )
{
    if (ReplayFindLine(replay, Fragment) == NULL) {
        printf("FAIL missing line: %s\n", Fragment);
        return 1;
    }
    return 0;
}

static int
replayRejectLine(
    _In_ const ReplayContext* replay,
    _In_z_ PCSTR fragment
    )
{
    if (ReplayFindLine(replay, Fragment) != NULL) {
        printf("FAIL unexpected line: %s\n", Fragment);
        return 1;
    }
    return 0;
}

static int
replayRequireLineColor(
    _In_ const ReplayContext* replay,
    _In_z_ PCSTR fragment,
    _In_ ULONG expectedColor
    )
{
    const ReplayLine* line;

    line = ReplayFindLine(replay, Fragment);
    if (line == NULL || line->Color != ExpectedColor) {
        printf(
            "FAIL line color: fragment=%s actual=%lu expected=%lu\n",
            Fragment,
            line == NULL ? MAXULONG : line->Color,
            ExpectedColor);
        return 1;
    }
    return 0;
}

static int
replayRequireLineCount(
    _In_ const ReplayContext* replay,
    _In_ ULONG expectedCount,
    _In_z_ PCSTR name
    )
{
    if (replay->LineCount != ExpectedCount) {
        printf(
            "FAIL %s line count: actual=%lu expected=%lu\n",
            Name,
            replay->LineCount,
            ExpectedCount);
        return 1;
    }
    return 0;
}

static int
replayValidateBounds(
    _In_ const ReplayContext* replay,
    _In_ ULONG width,
    _In_ ULONG height,
    _In_z_ PCSTR name
    )
{
    ULONG index;
    int failures = 0;

    for (index = 0; index < Replay->LineCount; ++index) {
        const REPLAY_LINE* line = &Replay->Lines[index];
        SIZE_T length = strlen(line->Text);

        if (line->X < 0 || line->Y < 0 ||
            (ULONG)line->X + (ULONG)(length * REPLAY_GLYPH_ADVANCE) > Width ||
            (ULONG)line->Y + REPLAY_GLYPH_HEIGHT > Height) {
            printf(
                "FAIL %s text bounds: x=%ld y=%ld text=%s\n",
                Name,
                line->X,
                line->Y,
                line->Text);
            ++failures;
        }
        if (line->Color >= KswordArkBugcheckLayoutColorCount) {
            printf("FAIL %s invalid color: %s\n", Name, line->Text);
            ++failures;
        }
        if (strstr(line->Text, "...") != NULL) {
            printf("FAIL %s clipped line: %s\n", Name, line->Text);
            ++failures;
        }
    }

    for (index = 0; index < Replay->FrameCount; ++index) {
        const REPLAY_FRAME* frame = &Replay->Frames[index];
        ULONG frameWidth;
        ULONG frameHeight;

        if (!KswordARKBugcheckLayoutGetFrameMetrics(
                frame->Frame,
                &frameWidth,
                &frameHeight) ||
            frame->X < 0 || frame->Y < 0 ||
            (ULONG)frame->X + frameWidth > Width ||
            (ULONG)frame->Y + frameHeight > Height) {
            printf(
                "FAIL %s frame bounds: x=%ld y=%ld frame=%lu\n",
                Name,
                frame->X,
                frame->Y,
                (ULONG)frame->Frame);
            ++failures;
        }
    }
    return failures;
}

static int
replayCheckDecoder(
    _In_ ULONG bugCheckCode,
    _In_ ULONG_PTR parameter1,
    _In_ ULONG_PTR parameter2,
    _In_ ULONG_PTR parameter3,
    _In_ ULONG_PTR parameter4,
    _In_ BOOLEAN expectedDecoded,
    _In_ ULONG expectedParameter,
    _In_ ULONG_PTR expectedAddress,
    _In_ ULONG expectedConfidence
    )
{
    KswordArkBugcheckDiagnostics diagnostics;
    ULONG_PTR address;
    ULONG parameter;
    ULONG confidence;
    BOOLEAN decoded;

    RtlZeroMemory(&diagnostics, sizeof(diagnostics));
    diagnostics.BugCheckCode = BugCheckCode;
    diagnostics.Parameter1 = Parameter1;
    diagnostics.Parameter2 = Parameter2;
    diagnostics.Parameter3 = Parameter3;
    diagnostics.Parameter4 = Parameter4;
    decoded = KswordARKBugcheckDecodePrimaryAddress(
        &diagnostics,
        &address,
        &parameter,
        &confidence);
    if (decoded != ExpectedDecoded || parameter != ExpectedParameter ||
        address != ExpectedAddress || confidence != ExpectedConfidence) {
        printf(
            "FAIL decoder 0x%08lX: decoded=%u param=%lu address=0x%p conf=%lu\n",
            BugCheckCode,
            (ULONG)decoded,
            parameter,
            (PVOID)address,
            confidence);
        return 1;
    }
    return 0;
}

static int
replayCheckRole(
    _In_ ULONG bugCheckCode,
    _In_ ULONG_PTR subtype,
    _In_ ULONG parameterIndex,
    _In_z_ PCSTR expectedRole
    )
{
    KswordArkBugcheckDiagnostics diagnostics;
    PCSTR role;

    RtlZeroMemory(&diagnostics, sizeof(diagnostics));
    diagnostics.BugCheckCode = BugCheckCode;
    diagnostics.Parameter1 = Subtype;
    role = KswordARKBugcheckDecodeParameterRole(&diagnostics, ParameterIndex);
    if (strcmp(role, ExpectedRole) != 0) {
        printf(
            "FAIL role 0x%08lX param%lu: actual=%s expected=%s\n",
            BugCheckCode,
            ParameterIndex,
            role,
            ExpectedRole);
        return 1;
    }
    return 0;
}

static VOID
replayInitializeCriticalProcess(
    _Out_ KswordArkBugcheckDiagnostics* diagnostics
    )
{
    RtlZeroMemory(diagnostics, sizeof(*diagnostics));
    diagnostics->Captured = 1;
    diagnostics->BugCheckCode = 0x000000EF;
    diagnostics->Parameter1 = 0xFFFFFA5887F26E80ULL;
    diagnostics->Parameter2 = 0;
    diagnostics->Irql = 15;
    diagnostics->Cpu = 0;
    diagnostics->ProcessObject = diagnostics->Parameter1;
    diagnostics->ProcessId = 644;
    diagnostics->ProcessSource = KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CRITICAL;
    diagnostics->CandidateClass = KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN;
    diagnostics->CandidateConfidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE;
    (void)strncpy_s(
        diagnostics->ProcessName,
        sizeof(diagnostics->ProcessName),
        "csrss.exe",
        _TRUNCATE);
    (void)strncpy_s(
        diagnostics->CandidateModule,
        sizeof(diagnostics->CandidateModule),
        "(none)",
        _TRUNCATE);
}

static VOID
replayInitializeDriverFault(
    _Out_ KswordArkBugcheckDiagnostics* diagnostics
    )
{
    RtlZeroMemory(diagnostics, sizeof(*diagnostics));
    diagnostics->Captured = 1;
    diagnostics->BugCheckCode = 0x000000D1;
    diagnostics->Parameter1 = 0x30;
    diagnostics->Parameter2 = 2;
    diagnostics->Parameter3 = 1;
    diagnostics->Parameter4 = 0xFFFFF80412345678ULL;
    diagnostics->FaultAddress = diagnostics->Parameter4;
    diagnostics->FaultParameter = 4;
    diagnostics->Irql = 15;
    diagnostics->Cpu = 1;
    diagnostics->CandidateAddress = diagnostics->Parameter4;
    diagnostics->CandidateModuleBase = 0xFFFFF80412340000ULL;
    diagnostics->CandidateModuleOffset = 0x5678;
    diagnostics->CandidateModuleSize = 0x18000;
    diagnostics->CandidateParameter = 4;
    diagnostics->CandidateClass = KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY;
    diagnostics->CandidateConfidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH;
    (void)strncpy_s(
        diagnostics->CandidateModule,
        sizeof(diagnostics->CandidateModule),
        "badfilter.sys",
        _TRUNCATE);
}

static VOID
replayUseLongDriverName(
    _Inout_ KswordArkBugcheckDiagnostics* diagnostics
    )
{
    (void)strncpy_s(
        diagnostics->CandidateModule,
        sizeof(diagnostics->CandidateModule),
        "very_long_security_monitoring_filter_component_x64_release.sys",
        _TRUNCATE);
}

static VOID
replayInitializeUnattributedHardwareFault(
    _Out_ KswordArkBugcheckDiagnostics* diagnostics
    )
{
    RtlZeroMemory(diagnostics, sizeof(*diagnostics));
    diagnostics->Captured = 1;
    diagnostics->BugCheckCode = 0x00000124;
    diagnostics->Irql = 15;
    diagnostics->Cpu = 2;
    diagnostics->CandidateClass = KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN;
    diagnostics->CandidateConfidence = KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE;
}

static VOID
replayAddCrashContext(
    _Inout_ KswordArkBugcheckDiagnostics* diagnostics
    )
{
    diagnostics->ProcessObject = 0xFFFFFA5887F26000ULL;
    diagnostics->ProcessId = 812;
    diagnostics->ProcessSource = KSWORD_ARK_BUGCHECK_PROCESS_SOURCE_CONTEXT;
    (void)strncpy_s(
        diagnostics->ProcessName,
        sizeof(diagnostics->ProcessName),
        "worker.exe",
        _TRUNCATE);
}

static int
replayDrawScenario(
    _In_z_ PCSTR name,
    _In_ ULONG width,
    _In_ ULONG height,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _Out_ ReplayContext* replay
    )
{
    KswordArkBugcheckLayoutCanvas canvas;
    NTSTATUS status;
    int failures = 0;

    RtlZeroMemory(replay, sizeof(*replay));
    RtlZeroMemory(&canvas, sizeof(canvas));
    canvas.Context = replay;
    canvas.Width = Width;
    canvas.Height = Height;
    canvas.DrawText = ReplayDrawText;
    canvas.drawFrame = ReplayDrawFrame;
    canvas.drawVerdict = ReplayDrawVerdict;
    status = KswordARKBugcheckLayoutDraw(&canvas, diagnostics, 0x0F, 186);
    if (!NT_SUCCESS(status)) {
        printf("FAIL %s layout status 0x%08lX\n", Name, (ULONG)status);
        return 1;
    }
    failures += ReplayValidateBounds(replay, Width, Height, Name);
    if (replay->VerdictCount != 1UL) {
        printf("FAIL %s verdict count: %lu\n", Name, replay->VerdictCount);
        ++failures;
    }
    return failures;
}

int
main(void)
{
    ReplayContext replay;
    KswordArkBugcheckDiagnostics diagnostics;
    int failures = 0;

    failures += ReplayCheckDecoder(
        0x000000EF,
        0xFFFFFA5887F26E80ULL,
        0,
        0,
        0,
        FALSE,
        0,
        0,
        KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE);
    failures += ReplayCheckDecoder(
        0x000000D1,
        0x30,
        2,
        1,
        0xFFFFF80412345678ULL,
        TRUE,
        4,
        0xFFFFF80412345678ULL,
        KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH);
    failures += ReplayCheckDecoder(
        0x000000C4,
        0xE6,
        0xFFFFF80422345678ULL,
        2,
        0,
        TRUE,
        2,
        0xFFFFF80422345678ULL,
        KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH);
    failures += ReplayCheckDecoder(
        0x000000C9,
        0x12,
        0xFFFFF80432345678ULL,
        0,
        0,
        TRUE,
        2,
        0xFFFFF80432345678ULL,
        KSWORD_ARK_BUGCHECK_CONFIDENCE_HIGH);
    failures += ReplayCheckDecoder(
        0x000000C4,
        0x10,
        0xFFFFF80442345678ULL,
        0,
        0,
        FALSE,
        0,
        0,
        KSWORD_ARK_BUGCHECK_CONFIDENCE_NONE);
    failures += ReplayCheckRole(0x000000EF, 0, 1, "PROCESS OBJECT");
    failures += ReplayCheckRole(0x000000D1, 0, 4, "INSTRUCTION");
    failures += ReplayCheckRole(0x0000009F, 3, 4, "BLOCKED IRP");
    failures += ReplayCheckRole(0x000000EA, 0, 3, "DRIVER NAME");
    failures += ReplayCheckRole(0x000000C4, 0xFA, 2, "COMPLETION ROUTINE");
    failures += ReplayCheckRole(0x000000C4, 0xFA, 3, "IRQL BEFORE");
    failures += ReplayCheckRole(0x000000C4, 0xFA, 4, "IRQL AFTER");
    failures += ReplayCheckRole(0x000000C4, 0xFB, 2, "COMPLETION ROUTINE");
    failures += ReplayCheckRole(0x000000C4, 0xFB, 3, "APC DISABLE CURRENT");
    failures += ReplayCheckRole(0x000000C4, 0xFB, 4, "APC DISABLE BEFORE");
    failures += ReplayCheckRole(0x000000C4, 0x110, 2, "ISR ADDRESS");
    failures += ReplayCheckRole(0x000000C4, 0x110, 3, "CONTEXT BEFORE");
    failures += ReplayCheckRole(0x000000C4, 0x110, 4, "CONTEXT AFTER");
    failures += ReplayCheckRole(0x000000C4, 0x111, 2, "ISR ADDRESS");
    failures += ReplayCheckRole(0x000000C4, 0x111, 3, "IRQL BEFORE");
    failures += ReplayCheckRole(0x000000C4, 0x111, 4, "IRQL AFTER");

    replayInitializeCriticalProcess(&diagnostics);
    failures += ReplayDrawScenario(
        "critical-1024x768",
        1024,
        768,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(&replay, "CRASH SUMMARY");
    failures += ReplayRequireLine(&replay, "PRIMARY EVIDENCE");
    failures += ReplayRequireLine(&replay, "TECHNICAL EVIDENCE");
    failures += ReplayRequireLine(&replay, "NEXT ACTION");
    failures += ReplayRequireLine(&replay, "CRITICAL_PROCESS_DIED");
    failures += ReplayRequireLine(&replay, "0x000000EF");
    failures += ReplayRequireLineColor(
        &replay,
        "CRITICAL_PROCESS_DIED",
        kKswordArkBugcheckLayoutColorAccent);
    failures += ReplayRequireLineColor(
        &replay,
        "0x000000EF",
        kKswordArkBugcheckLayoutColorWarning);
    failures += ReplayRequireLine(&replay, "csrss.exe");
    failures += ReplayRequireLine(&replay, "CRITICAL PROCESS / PID 644");
    failures += ReplayRequireLine(&replay, "OBJECT TYPE  PROCESS");
    failures += ReplayRequireLine(&replay, "P1 PROCESS OBJECT");
    failures += ReplayRequireLine(&replay, "P2 OBJECT TYPE");
    failures += ReplayRejectLine(&replay, "P3 RESERVED");
    failures += ReplayRejectLine(&replay, "P4 RESERVED");
    failures += ReplayRejectLine(&replay, "NOT IDENTIFIED");
    failures += ReplayRejectLine(&replay, "NOT AVAILABLE");
    failures += ReplayRejectLine(&replay, "DIRECT CODE ADDRESS");
    failures += ReplayRejectLine(&replay, "DUMP REQUIRED");
    failures += ReplayRequireLineCount(
        &replay,
        20UL,
        "critical-1024x768");
    if (replay.FrameCount != 4UL || replay.VerdictX != 688L ||
        replay.VerdictY != 12L) {
        printf("FAIL critical-1024x768 evidence-layout geometry\n");
        ++failures;
    }

    replayInitializeDriverFault(&diagnostics);
    failures += ReplayDrawScenario(
        "driver-1280x768",
        1280,
        768,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(&replay, "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
    failures += ReplayRequireLine(&replay, "0x000000D1");
    failures += ReplayRequireLineColor(
        &replay,
        "0x000000D1",
        kKswordArkBugcheckLayoutColorWarning);
    failures += ReplayRequireLine(&replay, "badfilter.sys");
    failures += ReplayRequireLineColor(
        &replay,
        "badfilter.sys",
        kKswordArkBugcheckLayoutColorAccent);
    failures += ReplayRequireLine(
        &replay,
        "THIRD-PARTY CODE / CONFIDENCE HIGH");
    failures += ReplayRequireLine(&replay, "MODULE OFFSET");
    failures += ReplayRequireLine(&replay, "DOCUMENTED CODE ADDRESS IN P4");
    failures += ReplayRequireLine(&replay, "P1 MEMORY");
    failures += ReplayRequireLine(&replay, "P2 IRQL");
    failures += ReplayRequireLine(&replay, "P3 ACCESS TYPE");
    failures += ReplayRequireLine(&replay, "P4 INSTRUCTION");
    failures += ReplayRequireLineCount(
        &replay,
        21UL,
        "driver-1280x768");
    if (replay.FrameCount != 4UL || replay.VerdictX != 816L ||
        replay.VerdictY != 12L) {
        printf("FAIL driver-1280x768 centered evidence-layout geometry\n");
        ++failures;
    }

    replayInitializeUnattributedHardwareFault(&diagnostics);
    failures += ReplayDrawScenario(
        "unattributed-1024x768",
        1024,
        768,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(&replay, "WHEA_UNCORRECTABLE_ERROR");
    failures += ReplayRequireLine(&replay, "NO SAFE LIVE ATTRIBUTION");
    failures += ReplayRequireLine(&replay, "ANALYZE THE SAVED DUMP STACK");
    failures += ReplayRejectLine(&replay, "NOT IDENTIFIED");
    failures += ReplayRejectLine(&replay, "NOT AVAILABLE");
    failures += ReplayRejectLine(&replay, "P1 PARAMETER");
    failures += ReplayRejectLine(&replay, "P2 PARAMETER");
    failures += ReplayRejectLine(&replay, "P3 PARAMETER");
    failures += ReplayRejectLine(&replay, "P4 PARAMETER");
    failures += ReplayRequireLineCount(
        &replay,
        16UL,
        "unattributed-1024x768");

    replayAddCrashContext(&diagnostics);
    failures += ReplayDrawScenario(
        "context-640x480",
        640,
        480,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(&replay, "worker.exe / PID 812");
    failures += ReplayRequireLine(&replay, "CRASH CONTEXT");
    failures += ReplayRequireLine(&replay, "CONTEXT ONLY; NOT THE CULPRIT");
    failures += ReplayRequireLine(&replay, "ROOT CAUSE NEEDS DUMP STACK");
    failures += ReplayRequireLineCount(
        &replay,
        13UL,
        "context-640x480");

    replayInitializeDriverFault(&diagnostics);
    failures += ReplayDrawScenario(
        "driver-640x480",
        640,
        480,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(&replay, "0x000000D1");
    failures += ReplayRequireLine(&replay, "PRIMARY EVIDENCE");
    failures += ReplayRequireLine(&replay, "badfilter.sys");
    failures += ReplayRequireLine(&replay, "CODE IP");
    failures += ReplayRequireLine(&replay, "1  KEEP THE CRASH DUMP");
    failures += ReplayRequireLine(&replay, "2  ANALYZE IN KSWORDARK");
    failures += ReplayRequireLineCount(
        &replay,
        13UL,
        "driver-640x480");
    if (replay.FrameCount != 2UL || replay.VerdictX != 304L ||
        replay.VerdictY != 94L) {
        printf("FAIL driver-640x480 compact geometry\n");
        ++failures;
    }

    replayUseLongDriverName(&diagnostics);
    failures += ReplayDrawScenario(
        "long-driver-640x480",
        640,
        480,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(
        &replay,
        "very_long_security_monitoring_fi");
    failures += ReplayRequireLine(
        &replay,
        "lter_component_x64_release.sys");
    failures += ReplayRequireLine(&replay, "P4 IP");
    failures += ReplayRequireLineCount(
        &replay,
        13UL,
        "long-driver-640x480");

    failures += ReplayDrawScenario(
        "long-driver-1024x768",
        1024,
        768,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(
        &replay,
        "very_long_security_monitoring_filter_component_x64_rel");
    failures += ReplayRequireLine(&replay, "ease.sys");
    failures += ReplayRequireLine(&replay, "P4 CODE IP");
    failures += ReplayRequireLineCount(
        &replay,
        21UL,
        "long-driver-1024x768");

    replayInitializeUnattributedHardwareFault(&diagnostics);
    diagnostics.BugCheckCode = 0x000000D5;
    failures += ReplayDrawScenario(
        "long-stop-name-640x480",
        640,
        480,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(
        &replay,
        "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL");

    replayInitializeCriticalProcess(&diagnostics);
    failures += ReplayDrawScenario(
        "critical-640x480",
        640,
        480,
        &diagnostics,
        &replay);
    failures += ReplayRequireLine(&replay, "0x000000EF");
    failures += ReplayRequireLine(&replay, "csrss.exe / PID 644");
    failures += ReplayRequireLine(&replay, "CRITICAL PROCESS");
    failures += ReplayRequireLine(&replay, "ROOT CAUSE NEEDS DUMP STACK");
    failures += ReplayRejectLine(&replay, "NOT IDENTIFIED");
    failures += ReplayRequireLineCount(
        &replay,
        13UL,
        "critical-640x480");

    if (failures != 0) {
        printf("RESULT FAIL (%d contract violations)\n", failures);
        return 1;
    }
    printf("RESULT PASS (evidence-first layout plus documented parsers)\n");
    return 0;
}

#include "../../drivers/ark/src/features/bugcheck/bugcheck_layout.c"
#include "../../drivers/ark/src/features/bugcheck/bugcheck_decode.c"

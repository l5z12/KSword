/*++

Module Name:

    bugcheck_layout.c

Abstract:

    Shared crash-safe information layout for the BGP and VMware framebuffer
    bugcheck renderers. The implementation formats only captured data and uses
    caller-supplied drawing callbacks without allocation or pageable services.

--*/

#include "bugcheck_layout.h"
#include "bugcheck_decode.h"

#include <ntstrsafe.h>
#include <stdarg.h>

typedef struct KswordArkBugcheckLayoutFrameMetrics
{
    ULONG width;
    ULONG height;
} KswordArkBugcheckLayoutFrameMetrics;

typedef struct KswordArkBugcheckLayoutWriter
{
    const KswordArkBugcheckLayoutCanvas* canvas;
    LONG originX;
    NTSTATUS status;
    CHAR line[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} KswordArkBugcheckLayoutWriter;

static const KswordArkBugcheckLayoutFrameMetrics
    kGKswordArkBugcheckLayoutFrames[kKswordArkBugcheckLayoutFrameCount] = {
        { 296UL, 112UL },
        { 608UL, 126UL },
        { 344UL, 184UL },
        { 312UL, 184UL },
        { 328UL, 184UL },
        { 344UL, 174UL },
        { 312UL, 174UL },
        { 328UL, 174UL },
        { 484UL, 176UL },
        { 500UL, 176UL },
        { 470UL, 207UL },
        { 350UL, 207UL },
        { 416UL, 207UL },
        { 314UL, 162UL },
        { 328UL, 162UL },
        { 278UL, 162UL },
        { 316UL, 162UL },
        { 480UL, 205UL },
        { 348UL, 205UL },
        { 412UL, 98UL },
        { 412UL, 103UL }
    };

C_ASSERT(
    RTL_NUMBER_OF(kGKswordArkBugcheckLayoutFrames) ==
    kKswordArkBugcheckLayoutFrameCount);

BOOLEAN
kswordArkBugcheckLayoutIsDetailed(
    _In_ ULONG width,
    _In_ ULONG height
    )
{
    // Keep one predictable two-column information hierarchy on physical 2K
    // displays as well as virtual crash modes.  The legacy dense renderer
    // remains compiled for reference but is no longer selected.
    UNREFERENCED_PARAMETER(width);
    UNREFERENCED_PARAMETER(height);
    return FALSE;
}

BOOLEAN
kswordArkBugcheckLayoutIsCompact(
    _In_ ULONG width,
    _In_ ULONG height
    )
{
    // The 640x480 crash fallback needs its dedicated two-column layout.
    return !kswordArkBugcheckLayoutIsDetailed(width, height) &&
        (width < KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH ||
         height < KSWORD_ARK_BUGCHECK_LAYOUT_FULL_HEIGHT);
}

LONG
kswordArkBugcheckLayoutOriginX(
    _In_ ULONG width,
    _In_ ULONG height
    )
{
    ULONG canvasWidth;

    // Center whichever fixed canvas the current crash mode can safely fit.
    if (kswordArkBugcheckLayoutIsDetailed(width, height)) {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH;
    } else if (kswordArkBugcheckLayoutIsCompact(width, height)) {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH;
    } else {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH;
    }
    if (width > canvasWidth) {
        return (LONG)((width - canvasWidth) / 2UL);
    }
    return 0L;
}

BOOLEAN
kswordArkBugcheckLayoutGetFrameMetrics(
    _In_ KswordArkBugcheckLayoutFrame frame,
    _Out_ PULONG width,
    _Out_ PULONG height
    )
{
    if (width == NULL || height == NULL ||
        frame < kKswordArkBugcheckLayoutFrameCompactColumn ||
        frame >= kKswordArkBugcheckLayoutFrameCount) {
        return FALSE;
    }

    *width = kGKswordArkBugcheckLayoutFrames[frame].width;
    *height = kGKswordArkBugcheckLayoutFrames[frame].height;
    return TRUE;
}

static VOID
kswordArkBugcheckLayoutClipLine(
    _Inout_updates_z_(capacity) PCHAR text,
    _In_ ULONG capacity,
    _In_ ULONG maximumCharacters
    )
{
    SIZE_T length;

    if (text == NULL || capacity == 0 || maximumCharacters == 0) {
        return;
    }
    if (maximumCharacters >= capacity) {
        maximumCharacters = capacity - 1UL;
    }

    length = 0;
    while (length + 1UL < capacity && text[length] != '\0') {
        ++length;
    }
    if (length <= maximumCharacters) {
        return;
    }

    if (maximumCharacters > 3UL) {
        text[maximumCharacters - 3UL] = '.';
        text[maximumCharacters - 2UL] = '.';
        text[maximumCharacters - 1UL] = '.';
    }
    text[maximumCharacters] = '\0';
}

static VOID
kswordArkBugcheckLayoutWriteFormatted(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ LONG x,
    _In_ LONG y,
    _In_ ULONG colorIndex,
    _In_ ULONG maximumCharacters,
    _In_z_ _Printf_format_string_ PCSTR format,
    ...
    )
{
    va_list arguments;

    if (writer == NULL || !NT_SUCCESS(writer->status)) {
        return;
    }

    va_start(arguments, format);
    writer->status = RtlStringCbVPrintfA(
        writer->line,
        sizeof(writer->line),
        format,
        arguments);
    va_end(arguments);
    if (!NT_SUCCESS(writer->status)) {
        return;
    }

    kswordArkBugcheckLayoutClipLine(
        writer->line,
        (ULONG)RTL_NUMBER_OF(writer->line),
        maximumCharacters);
    writer->status = writer->canvas->drawText(
        writer->canvas->context,
        writer->originX + x,
        y,
        writer->line,
        colorIndex);
}

static VOID
kswordArkBugcheckLayoutWriteFrame(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ LONG x,
    _In_ LONG y,
    _In_ KswordArkBugcheckLayoutFrame frame
    )
{
    if (writer == NULL || !NT_SUCCESS(writer->status)) {
        return;
    }

    writer->status = writer->canvas->drawFrame(
        writer->canvas->context,
        writer->originX + x,
        y,
        frame);
}

static BOOLEAN
kswordArkBugcheckLayoutWriteVerdict(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ LONG x,
    _In_ LONG y,
    _In_ ULONG classification
    )
{
    NTSTATUS status;

    if (writer == NULL || !NT_SUCCESS(writer->status) ||
        writer->canvas->drawVerdict == NULL) {
        return FALSE;
    }
    status = writer->canvas->drawVerdict(
        writer->canvas->context,
        writer->originX + x,
        y,
        classification);
    if (NT_SUCCESS(status)) {
        return TRUE;
    }
    if (status != STATUS_NOT_FOUND &&
        status != STATUS_DEVICE_NOT_READY &&
        status != STATUS_DEVICE_BUSY) {
        writer->status = status;
    }
    return FALSE;
}

static PCSTR
kswordArkBugcheckLayoutModuleText(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    // Resolver notes are not evidence and therefore stay off the screen.
    if (diagnostics->candidateModule[0] == '\0' ||
        diagnostics->candidateModule[0] == '(') {
        return NULL;
    }
    // A cached basename is safe to display as the primary module evidence.
    return diagnostics->candidateModule;
}

static BOOLEAN
kswordArkBugcheckLayoutHasProcess(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    return diagnostics->processObject != 0 &&
        diagnostics->processName[0] != '\0';
}

static ULONG
kswordArkBugcheckLayoutTextLength(
    _In_opt_z_ PCSTR text,
    _In_ ULONG maximumLength
    )
{
    ULONG length;

    // Bound every scan because module names live in a fixed crash snapshot.
    length = 0;
    while (text != NULL && length < maximumLength && text[length] != '\0') {
        ++length;
    }
    // The caller uses the bounded result only to choose a fixed layout branch.
    return length;
}

static PCSTR
kswordArkBugcheckLayoutCriticalObjectText(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    if (diagnostics->parameter2 == 0) {
        return "PROCESS";
    }
    if (diagnostics->parameter2 == 1) {
        return "THREAD";
    }
    return "UNKNOWN";
}

static BOOLEAN
kswordArkBugcheckLayoutTextStartsWith(
    _In_opt_z_ PCSTR text,
    _In_z_ PCSTR prefix
    )
{
    // Null strings cannot satisfy a semantic prefix check.
    if (text == NULL || prefix == NULL) {
        return FALSE;
    }
    // Compare only the fixed prefix so the crash path needs no CRT helper.
    while (*prefix != '\0') {
        if (*text != *prefix) {
            return FALSE;
        }
        ++text;
        ++prefix;
    }
    // Every prefix character matched the candidate text.
    return TRUE;
}

static BOOLEAN
kswordArkBugcheckLayoutShouldShowParameter(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG parameterIndex,
    _In_ ULONG_PTR value
    )
{
    PCSTR role;

    // Decode the documented role without dereferencing the captured value.
    role = kswordArkBugcheckDecodeParameterRole(diagnostics, parameterIndex);
    // Reserved fields never help the first-look diagnosis.
    if (kswordArkBugcheckLayoutTextStartsWith(role, "RESERVED")) {
        return FALSE;
    }
    // Any nonzero documented or generic value remains available as evidence.
    if (value != 0) {
        return TRUE;
    }
    // A semantic zero can encode PROCESS, READ, IRQL 0, or another real state.
    return !kswordArkBugcheckLayoutTextStartsWith(role, "PARAMETER");
}

static VOID
kswordArkBugcheckLayoutWriteTechnicalParameter(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ LONG x,
    _In_ LONG y,
    _In_ ULONG maximumCharacters,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG parameterIndex,
    _In_ ULONG_PTR value
    )
{
    kswordArkBugcheckLayoutWriteFormatted(
        writer,
        x,
        y,
        kKswordArkBugcheckLayoutColorText,
        maximumCharacters,
        "P%lu %s  0x%p",
        parameterIndex,
        kswordArkBugcheckDecodeParameterRole(diagnostics, parameterIndex),
        (PVOID)value);
}

static ULONG
kswordArkBugcheckLayoutWriteTechnicalParameters(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ LONG x,
    _In_ LONG startY,
    _In_ ULONG maximumCharacters,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG maximumLines
    )
{
    ULONG_PTR values[4];
    ULONG parameterIndex;
    ULONG lineCount;

    // Snapshot the four fixed bugcheck values into bounded stack storage.
    values[0] = diagnostics->parameter1;
    values[1] = diagnostics->parameter2;
    values[2] = diagnostics->parameter3;
    values[3] = diagnostics->parameter4;
    // Emit only semantic or nonzero values and never exceed the panel budget.
    lineCount = 0;
    for (parameterIndex = 1;
         parameterIndex <= RTL_NUMBER_OF(values) && lineCount < maximumLines;
         ++parameterIndex) {
        if (!kswordArkBugcheckLayoutShouldShowParameter(
                diagnostics,
                parameterIndex,
                values[parameterIndex - 1UL])) {
            continue;
        }
        kswordArkBugcheckLayoutWriteTechnicalParameter(
            writer,
            x,
            startY + (LONG)(lineCount * 22UL),
            maximumCharacters,
            diagnostics,
            parameterIndex,
            values[parameterIndex - 1UL]);
        ++lineCount;
    }
    // The caller uses the count to place one optional context line.
    return lineCount;
}

static PCSTR
kswordArkBugcheckLayoutHumanCauseText(
    _In_ ULONG bugCheckCode
    )
{
    switch (bugCheckCode) {
    case 0x0000000A:
        return "KERNEL CODE ACCESSED INVALID MEMORY AT HIGH IRQL.";
    case 0x000000D1:
        return "A DRIVER ACCESSED INVALID MEMORY AT HIGH IRQL.";
    case 0x0000001E:
    case 0x0000003B:
    case 0x0000007E:
        return "A KERNEL EXCEPTION WAS NOT HANDLED.";
    case 0x00000050:
        return "KERNEL CODE ACCESSED AN INVALID MEMORY PAGE.";
    case 0x000000BE:
        return "KERNEL CODE TRIED TO WRITE PROTECTED MEMORY.";
    case 0x0000009F:
        return "A DRIVER DID NOT COMPLETE A POWER TRANSITION.";
    case 0x000000EF:
        return "A WINDOWS CRITICAL PROCESS TERMINATED.";
    case 0x00000116:
    case 0x00000117:
        return "THE DISPLAY DRIVER OR GPU STOPPED RESPONDING.";
    case 0x00000124:
        return "HARDWARE REPORTED AN UNRECOVERABLE ERROR.";
    case 0x00000133:
        return "A DPC OR INTERRUPT HANDLER TOOK TOO LONG.";
    default:
        return "WINDOWS STOPPED TO PROTECT SYSTEM DATA.";
    }
}

static PCSTR
kswordArkBugcheckLayoutFallbackVerdictText(
    _In_ ULONG classification
    )
{
    switch (classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS:
        return "KSWORDARK MAY BE INVOLVED.";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT:
        return "MICROSOFT CODE IS INVOLVED.";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY:
        return "THIRD-PARTY CODE IS INVOLVED.";
    default:
        return "NO CULPRIT IS CONFIRMED.";
    }
}

static VOID
kswordArkBugcheckLayoutWriteHeader(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ BOOLEAN compact
    )
{
    // The neutral product label establishes context without competing for focus.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 280L, 18L, kKswordArkBugcheckLayoutColorMuted,
        compact ? 40UL : 42UL,
        "KSWORD ARK CRASH DIAGNOSTICS");
    // The symbolic bugcheck name is the first high-contrast diagnostic fact.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 280L, 42L, kKswordArkBugcheckLayoutColorAccent,
        compact ? 40UL : 42UL,
        "%s", kswordArkBugcheckName(diagnostics->bugCheckCode));
    // The numeric stop code is the page's only red signal and visual anchor.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 280L, 66L, kKswordArkBugcheckLayoutColorWarning,
        compact ? 40UL : 42UL,
        "0x%08lX", diagnostics->bugCheckCode);

    // Prefer the pre-rendered Windows UI-font verdict whenever it is ready.
    if (!kswordArkBugcheckLayoutWriteVerdict(
            writer,
            compact ? 304L : 688L,
            compact ? 94L : 12L,
            diagnostics->candidateClass)) {
        LONG verdictX;
        LONG verdictY;
        ULONG maximumCharacters;

        verdictX = compact ? 304L : 688L;
        verdictY = compact ? 94L : 20L;
        maximumCharacters = compact ? 35UL : 34UL;
        // The crash-safe fallback stays white like the normal verdict card.
        kswordArkBugcheckLayoutWriteFormatted(
            writer,
            verdictX,
            verdictY,
            kKswordArkBugcheckLayoutColorText,
            maximumCharacters,
            "%s",
            kswordArkBugcheckLayoutFallbackVerdictText(
                diagnostics->candidateClass));
        // One concise line explains where final attribution comes from.
        kswordArkBugcheckLayoutWriteFormatted(
            writer,
            verdictX,
            verdictY + 20L,
            kKswordArkBugcheckLayoutColorText,
            maximumCharacters,
            "FINAL ATTRIBUTION NEEDS THE DUMP.");
    }
}

static VOID
kswordArkBugcheckLayoutDrawCompact(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    )
{
    PCSTR moduleText;
    ULONG moduleLength;
    ULONG_PTR values[4];
    ULONG parameterIndex;

    // Compact rendering intentionally excludes callback and cache telemetry.
    UNREFERENCED_PARAMETER(callbackMask);
    UNREFERENCED_PARAMETER(moduleCount);
    // Resolve the optional module basename once for the evidence branch.
    moduleText = kswordArkBugcheckLayoutModuleText(diagnostics);
    // Measure only the fixed snapshot capacity to select one- or two-line text.
    moduleLength = kswordArkBugcheckLayoutTextLength(
        moduleText,
        KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL);
    // Keep the raw values bounded on the stack for one optional fallback fact.
    values[0] = diagnostics->parameter1;
    values[1] = diagnostics->parameter2;
    values[2] = diagnostics->parameter3;
    values[3] = diagnostics->parameter4;
    // Preserve the two-panel compact geometry used by 640x480 crash modes.
    kswordArkBugcheckLayoutWriteFrame(
        writer, 16L, 292L, kKswordArkBugcheckLayoutFrameCompactColumn);
    kswordArkBugcheckLayoutWriteFrame(
        writer, 328L, 292L, kKswordArkBugcheckLayoutFrameCompactColumn);

    // The left panel contains only the strongest evidence available now.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 28L, 302L, kKswordArkBugcheckLayoutColorMuted, 29UL,
        "PRIMARY EVIDENCE");
    if (moduleText != NULL &&
        diagnostics->candidateClass != KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN) {
        // A resolved module is the highest-value compact attribution result.
        if (moduleLength > 32UL) {
            // A long basename receives two complete lines instead of ellipsis.
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 24L, 320L, kKswordArkBugcheckLayoutColorAccent, 32UL,
                "%.*s", 32, moduleText);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 24L, 338L, kKswordArkBugcheckLayoutColorAccent, 32UL,
                "%s", moduleText + 32UL);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 28L, 356L, kKswordArkBugcheckLayoutColorText, 29UL,
                "%s / %s",
                kswordArkBugcheckModuleClassText(diagnostics->candidateClass),
                kswordArkBugcheckConfidenceText(
                    diagnostics->candidateConfidence));
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 28L, 374L, kKswordArkBugcheckLayoutColorMuted, 29UL,
                "P%lu IP  0x%p",
                diagnostics->candidateParameter,
                (PVOID)diagnostics->faultAddress);
        } else {
            // Short basenames leave room for both offset and code address.
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 24L, 320L, kKswordArkBugcheckLayoutColorAccent, 32UL,
                "%s", moduleText);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 28L, 338L, kKswordArkBugcheckLayoutColorText, 29UL,
                "%s / %s",
                kswordArkBugcheckModuleClassText(diagnostics->candidateClass),
                kswordArkBugcheckConfidenceText(
                    diagnostics->candidateConfidence));
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 28L, 356L, kKswordArkBugcheckLayoutColorText, 29UL,
                "OFFSET  0x%p", (PVOID)diagnostics->candidateModuleOffset);
            if (diagnostics->faultAddress != 0) {
                // The documented code address remains visible without clutter.
                kswordArkBugcheckLayoutWriteFormatted(
                    writer, 28L, 374L, kKswordArkBugcheckLayoutColorMuted, 29UL,
                    "CODE IP  0x%p", (PVOID)diagnostics->faultAddress);
            }
        }
    } else if (diagnostics->bugCheckCode == 0x000000EF &&
               kswordArkBugcheckLayoutHasProcess(diagnostics)) {
        // For 0xEF, the cached critical process is evidence, not the culprit.
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 320L, kKswordArkBugcheckLayoutColorAccent, 29UL,
            "%s / PID %Iu",
            diagnostics->processName,
            diagnostics->processId);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 338L, kKswordArkBugcheckLayoutColorText, 29UL,
            "CRITICAL %s",
            kswordArkBugcheckLayoutCriticalObjectText(diagnostics));
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 356L, kKswordArkBugcheckLayoutColorText, 29UL,
            "OBJECT  0x%p", (PVOID)diagnostics->processObject);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 374L, kKswordArkBugcheckLayoutColorMuted, 29UL,
            "ROOT CAUSE NEEDS DUMP STACK");
    } else if (kswordArkBugcheckLayoutHasProcess(diagnostics)) {
        // Non-0xEF process hits identify crash context, never the culprit.
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 320L, kKswordArkBugcheckLayoutColorAccent, 29UL,
            "%s / PID %Iu",
            diagnostics->processName,
            diagnostics->processId);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 338L, kKswordArkBugcheckLayoutColorText, 29UL,
            "CRASH CONTEXT");
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 356L, kKswordArkBugcheckLayoutColorMuted, 29UL,
            "CONTEXT ONLY; NOT THE CULPRIT");
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 374L, kKswordArkBugcheckLayoutColorMuted, 29UL,
            "ROOT CAUSE NEEDS DUMP STACK");
    } else {
        // A failed live attribution consumes only two lines, never a full card.
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 320L, kKswordArkBugcheckLayoutColorMuted, 29UL,
            "NO SAFE LIVE ATTRIBUTION");
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 28L, 340L, kKswordArkBugcheckLayoutColorText, 29UL,
            "ANALYZE THE SAVED DUMP STACK");
        for (parameterIndex = 1;
             parameterIndex <= RTL_NUMBER_OF(values);
             ++parameterIndex) {
            if (!kswordArkBugcheckLayoutShouldShowParameter(
                    diagnostics,
                    parameterIndex,
                    values[parameterIndex - 1UL])) {
                continue;
            }
            // One compact parameter preserves context without crowding the card.
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 28L, 366L, kKswordArkBugcheckLayoutColorMuted, 29UL,
                "P%lu %s",
                parameterIndex,
                kswordArkBugcheckDecodeParameterRole(
                    diagnostics,
                    parameterIndex));
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 28L, 384L, kKswordArkBugcheckLayoutColorText, 29UL,
                "0x%p", (PVOID)values[parameterIndex - 1UL]);
            break;
        }
    }

    // The right card is deliberately limited to three actionable steps.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 340L, 302L, kKswordArkBugcheckLayoutColorMuted, 29UL,
        "NEXT ACTION");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 340L, 326L, kKswordArkBugcheckLayoutColorText, 29UL,
        "1  KEEP THE CRASH DUMP");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 340L, 350L, kKswordArkBugcheckLayoutColorText, 29UL,
        "2  ANALYZE IN KSWORDARK");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 340L, 374L, kKswordArkBugcheckLayoutColorText, 29UL,
        "3  ATTACH DUMP WHEN REPORTING");

    // The 228..284 band remains empty for Windows dump progress text.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 16L, 442L, kKswordArkBugcheckLayoutColorMuted, 68UL,
        "WINDOWS IS WRITING THE CRASH DUMP. DO NOT POWER OFF.");
}

static VOID
kswordArkBugcheckLayoutDrawFull(
    _Inout_ KswordArkBugcheckLayoutWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    )
{
    PCSTR moduleText;
    ULONG moduleLength;
    ULONG parameterLines;

    // Runtime callback and cache telemetry never belong on the user surface.
    UNREFERENCED_PARAMETER(callbackMask);
    UNREFERENCED_PARAMETER(moduleCount);
    // Resolve the optional module basename before selecting the evidence path.
    moduleText = kswordArkBugcheckLayoutModuleText(diagnostics);
    // Measure within the fixed snapshot so long names receive a complete row.
    moduleLength = kswordArkBugcheckLayoutTextLength(
        moduleText,
        KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL);

    // Retain the accepted four-panel geometry and restore generous whitespace.
    kswordArkBugcheckLayoutWriteFrame(
        writer, 16L, 156L, kKswordArkBugcheckLayoutFrameFullBottomLeft);
    kswordArkBugcheckLayoutWriteFrame(
        writer, 508L, 156L, kKswordArkBugcheckLayoutFrameFullBottomRight);
    kswordArkBugcheckLayoutWriteFrame(
        writer, 16L, 348L, kKswordArkBugcheckLayoutFrameFullBottomLeft);
    kswordArkBugcheckLayoutWriteFrame(
        writer, 508L, 348L, kKswordArkBugcheckLayoutFrameFullBottomRight);

    // The summary explains the stop without repeating the header identity.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 28L, 168L, kKswordArkBugcheckLayoutColorMuted, 50UL,
        "CRASH SUMMARY");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 28L, 194L, kKswordArkBugcheckLayoutColorText, 50UL,
        "%s", kswordArkBugcheckLayoutHumanCauseText(
            diagnostics->bugCheckCode));
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 28L, 226L, kKswordArkBugcheckLayoutColorMuted, 50UL,
        "CPU %lu / IRQL %lu", diagnostics->cpu, diagnostics->irql);

    // The evidence panel displays resolved facts and suppresses empty fields.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 520L, 168L, kKswordArkBugcheckLayoutColorMuted, 52UL,
        "PRIMARY EVIDENCE");
    if (moduleText != NULL &&
        diagnostics->candidateClass != KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN) {
        // A documented code address mapped to a module is primary attribution.
        if (moduleLength > 54UL) {
            // Split the rare long basename while retaining class and exact IP.
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 516L, 190L, kKswordArkBugcheckLayoutColorAccent, 54UL,
                "%.*s", 54, moduleText);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 516L, 214L, kKswordArkBugcheckLayoutColorAccent, 54UL,
                "%s", moduleText + 54UL);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 520L, 238L, kKswordArkBugcheckLayoutColorText, 52UL,
                "%s CODE / CONFIDENCE %s",
                kswordArkBugcheckModuleClassText(diagnostics->candidateClass),
                kswordArkBugcheckConfidenceText(
                    diagnostics->candidateConfidence));
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 520L, 262L, kKswordArkBugcheckLayoutColorMuted, 52UL,
                "P%lu CODE IP  0x%p",
                diagnostics->candidateParameter,
                (PVOID)diagnostics->faultAddress);
        } else {
            // Short basenames leave room for offset and documented source.
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 516L, 190L, kKswordArkBugcheckLayoutColorAccent, 54UL,
                "%s", moduleText);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 520L, 214L, kKswordArkBugcheckLayoutColorText, 52UL,
                "%s CODE / CONFIDENCE %s",
                kswordArkBugcheckModuleClassText(diagnostics->candidateClass),
                kswordArkBugcheckConfidenceText(
                    diagnostics->candidateConfidence));
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 520L, 238L, kKswordArkBugcheckLayoutColorText, 52UL,
                "MODULE OFFSET  0x%p",
                (PVOID)diagnostics->candidateModuleOffset);
            kswordArkBugcheckLayoutWriteFormatted(
                writer, 520L, 262L, kKswordArkBugcheckLayoutColorMuted, 52UL,
                "DOCUMENTED CODE ADDRESS IN P%lu",
                diagnostics->candidateParameter);
        }
    } else if (diagnostics->bugCheckCode == 0x000000EF &&
               kswordArkBugcheckLayoutHasProcess(diagnostics)) {
        // A cached 0xEF process identifies the victim but not terminating code.
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 190L, kKswordArkBugcheckLayoutColorAccent, 52UL,
            "%s", diagnostics->processName);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 214L, kKswordArkBugcheckLayoutColorText, 52UL,
            "CRITICAL PROCESS / PID %Iu", diagnostics->processId);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 238L, kKswordArkBugcheckLayoutColorText, 52UL,
            "OBJECT TYPE  %s",
            kswordArkBugcheckLayoutCriticalObjectText(diagnostics));
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 262L, kKswordArkBugcheckLayoutColorMuted, 52UL,
            "ROOT CAUSE REQUIRES THE DUMP STACK");
    } else if (kswordArkBugcheckLayoutHasProcess(diagnostics)) {
        // Other process cache hits are context only and never culprit claims.
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 190L, kKswordArkBugcheckLayoutColorAccent, 52UL,
            "%s", diagnostics->processName);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 214L, kKswordArkBugcheckLayoutColorText, 52UL,
            "CRASH CONTEXT / PID %Iu", diagnostics->processId);
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 238L, kKswordArkBugcheckLayoutColorMuted, 52UL,
            "CONTEXT ONLY; ANALYZE THE DUMP STACK");
    } else {
        // A live miss is stated once instead of filling the panel with failures.
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 190L, kKswordArkBugcheckLayoutColorMuted, 52UL,
            "NO SAFE LIVE ATTRIBUTION");
        kswordArkBugcheckLayoutWriteFormatted(
            writer, 520L, 216L, kKswordArkBugcheckLayoutColorText, 52UL,
            "ANALYZE THE SAVED DUMP STACK");
    }

    // Technical evidence includes only semantic or nonzero stop parameters.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 28L, 360L, kKswordArkBugcheckLayoutColorMuted, 50UL,
        "TECHNICAL EVIDENCE");
    parameterLines = kswordArkBugcheckLayoutWriteTechnicalParameters(
        writer,
        28L,
        384L,
        50UL,
        diagnostics,
        4UL);
    if (parameterLines < 4UL) {
        // CPU and IRQL use only genuinely unused space in the technical panel.
        kswordArkBugcheckLayoutWriteFormatted(
            writer,
            28L,
            384L + (LONG)(parameterLines * 22UL),
            kKswordArkBugcheckLayoutColorMuted,
            50UL,
            "CPU %lu / IRQL %lu",
            diagnostics->cpu,
            diagnostics->irql);
    }

    // Three short actions replace repeated warnings and generic advice.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 520L, 360L, kKswordArkBugcheckLayoutColorMuted, 52UL,
        "NEXT ACTION");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 520L, 388L, kKswordArkBugcheckLayoutColorText, 52UL,
        "1  KEEP THE NEWEST CRASH DUMP");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 520L, 418L, kKswordArkBugcheckLayoutColorText, 52UL,
        "2  ANALYZE IN KSWORDARK OR WINDBG");
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 520L, 448L, kKswordArkBugcheckLayoutColorText, 52UL,
        "3  ATTACH THE DUMP WHEN REPORTING");

    // The bottom band carries the single power-loss warning for the whole page.
    kswordArkBugcheckLayoutWriteFormatted(
        writer, 16L, 724L, kKswordArkBugcheckLayoutColorMuted, 80UL,
        "WAITING FOR WINDOWS TO COMPLETE THE CRASH DUMP. DO NOT POWER OFF.");
}

NTSTATUS
kswordArkBugcheckLayoutDraw(
    _In_ const KswordArkBugcheckLayoutCanvas* canvas,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    )
{
    KswordArkBugcheckLayoutWriter writer;
    BOOLEAN compact;

    if (canvas == NULL || diagnostics == NULL ||
        canvas->drawText == NULL || canvas->drawFrame == NULL ||
        canvas->width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
        canvas->height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&writer, sizeof(writer));
    writer.canvas = canvas;
    writer.originX = kswordArkBugcheckLayoutOriginX(
        canvas->width,
        canvas->height);
    writer.status = STATUS_SUCCESS;
    compact = kswordArkBugcheckLayoutIsCompact(canvas->width, canvas->height);
    kswordArkBugcheckLayoutWriteHeader(&writer, diagnostics, compact);
    if (compact) {
        kswordArkBugcheckLayoutDrawCompact(
            &writer,
            diagnostics,
            callbackMask,
            moduleCount);
    } else {
        kswordArkBugcheckLayoutDrawFull(
            &writer,
            diagnostics,
            callbackMask,
            moduleCount);
    }
    return writer.status;
}

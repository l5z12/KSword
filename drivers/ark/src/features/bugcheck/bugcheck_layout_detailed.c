/*++

Module Name:

    bugcheck_layout_detailed.c

Abstract:

    Information-dense 1280x720 crash layout for the physical BGP and VMware
    framebuffer renderers. Unavailable debugger data is labeled explicitly
    instead of being fabricated or collected through unsafe crash-time work.

--*/

#include "bugcheck_layout_detailed.h"

#include <ntstrsafe.h>
#include <stdarg.h>

typedef struct KswordArkBugcheckDetailedWriter
{
    const KswordArkBugcheckLayoutCanvas* canvas;
    LONG originX;
    NTSTATUS status;
    CHAR line[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} KswordArkBugcheckDetailedWriter;

// This helper clips every formatted row before it reaches the fixed canvas.
static VOID
kswordArkBugcheckDetailedClipLine(
    _Inout_updates_z_(capacity) PCHAR text,
    _In_ ULONG capacity,
    _In_ ULONG maximumCharacters
    )
{
    SIZE_T length;

    if (text == NULL || capacity == 0UL || maximumCharacters == 0UL) {
        return;
    }
    if (maximumCharacters >= capacity) {
        maximumCharacters = capacity - 1UL;
    }

    length = 0UL;
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

// This helper formats into a fixed stack buffer and never allocates memory.
static VOID
kswordArkBugcheckDetailedWrite(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
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

    kswordArkBugcheckDetailedClipLine(
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

// This helper forwards a pre-generated frame to the active renderer.
static VOID
kswordArkBugcheckDetailedFrame(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
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

// This helper removes internal resolver notes from the public module label.
static PCSTR
kswordArkBugcheckDetailedModuleText(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    if (diagnostics->candidateModule[0] == '\0' ||
        diagnostics->candidateModule[0] == '(') {
        return "NOT IDENTIFIED";
    }
    return diagnostics->candidateModule;
}

// This helper returns a safe source label when no resolver supplied one.
static PCSTR
kswordArkBugcheckDetailedSourceText(
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    if (diagnostics->candidateSource[0] == '\0') {
        return "NOT IDENTIFIED";
    }
    return diagnostics->candidateSource;
}

// The header exposes captured state and the availability contract at a glance.
static VOID
kswordArkBugcheckDetailedDrawHeader(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 280L, 18L, kKswordArkBugcheckLayoutColorAccent, 58UL,
        "KSWORD ARK CRASH DIAGNOSTICS");
    kswordArkBugcheckDetailedWrite(
        writer, 280L, 40L, kKswordArkBugcheckLayoutColorText, 72UL,
        "A FATAL KERNEL ERROR HAS OCCURRED.");
    kswordArkBugcheckDetailedWrite(
        writer, 280L, 56L, kKswordArkBugcheckLayoutColorMuted, 72UL,
        "THE SYSTEM STOPPED TO PROTECT DATA AND PRESERVE CRASH CONTEXT.");
    kswordArkBugcheckDetailedWrite(
        writer, 280L, 72L, kKswordArkBugcheckLayoutColorWarning, 72UL,
        "AMBER FIELDS REQUIRE MEMORY.DMP ANALYSIS AFTER RESTART.");
    kswordArkBugcheckDetailedWrite(
        writer, 1122L, 18L, kKswordArkBugcheckLayoutColorText, 16UL,
        "CRASH CPU %02lu", diagnostics->cpu);
    kswordArkBugcheckDetailedWrite(
        writer, 1122L, 36L, kKswordArkBugcheckLayoutColorText, 16UL,
        "IRQL      %02lu", diagnostics->irql);
    kswordArkBugcheckDetailedWrite(
        writer, 1122L, 54L, kKswordArkBugcheckLayoutColorText, 16UL,
        "CALLBACKS 0x%02lX", callbackMask & 0x0FUL);
    kswordArkBugcheckDetailedWrite(
        writer, 1122L, 72L, kKswordArkBugcheckLayoutColorWarning, 16UL,
        "UPTIME DUMP ONLY");
}

// The BugCheck panel contains only callback arguments and derived verdicts.
static VOID
kswordArkBugcheckDetailedDrawBugcheck(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 112L, kKswordArkBugcheckLayoutColorMuted, 48UL,
        "BUGCHECK");
    kswordArkBugcheckDetailedWrite(
        writer, 388L, 112L, kKswordArkBugcheckLayoutColorAccent, 12UL,
        "[CAPTURED]");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 134L, kKswordArkBugcheckLayoutColorAccent, 48UL,
        "%s", kswordArkBugcheckName(diagnostics->bugCheckCode));
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 152L, kKswordArkBugcheckLayoutColorAccent, 48UL,
        "0x%08lX", diagnostics->bugCheckCode);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 174L, kKswordArkBugcheckLayoutColorText, 48UL,
        "ARG1  0x%p", (PVOID)diagnostics->parameter1);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 190L, kKswordArkBugcheckLayoutColorText, 48UL,
        "ARG2  0x%p", (PVOID)diagnostics->parameter2);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 206L, kKswordArkBugcheckLayoutColorText, 48UL,
        "ARG3  0x%p", (PVOID)diagnostics->parameter3);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 222L, kKswordArkBugcheckLayoutColorText, 48UL,
        "ARG4  0x%p", (PVOID)diagnostics->parameter4);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 242L, kKswordArkBugcheckLayoutColorText, 48UL,
        "FAULT PARAM %lu  %s",
        diagnostics->faultParameter,
        diagnostics->faultMeaning);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 258L, kKswordArkBugcheckLayoutColorText, 48UL,
        "FAULT IP  0x%p", (PVOID)diagnostics->faultAddress);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 278L, kKswordArkBugcheckLayoutColorAccent, 48UL,
        "%s", kswordArkBugcheckVerdictText(diagnostics->candidateClass));
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 294L, kKswordArkBugcheckLayoutColorText, 48UL,
        "CONFIDENCE %s",
        kswordArkBugcheckConfidenceText(diagnostics->candidateConfidence));
}

// The fault panel separates captured callback values from debugger registers.
static VOID
kswordArkBugcheckDetailedDrawFaultContext(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    PCSTR moduleText;

    moduleText = kswordArkBugcheckDetailedModuleText(diagnostics);
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 112L, kKswordArkBugcheckLayoutColorMuted, 35UL,
        "FAULT CONTEXT");
    kswordArkBugcheckDetailedWrite(
        writer, 778L, 112L, kKswordArkBugcheckLayoutColorWarning, 8UL,
        "[MIXED]");
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 136L, kKswordArkBugcheckLayoutColorAccent, 35UL,
        "RIP     0x%p", (PVOID)diagnostics->faultAddress);
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 152L, kKswordArkBugcheckLayoutColorText, 35UL,
        "CPU     %lu", diagnostics->cpu);
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 168L, kKswordArkBugcheckLayoutColorText, 35UL,
        "IRQL    %lu", diagnostics->irql);
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 184L, kKswordArkBugcheckLayoutColorText, 35UL,
        "SOURCE  %s", kswordArkBugcheckDetailedSourceText(diagnostics));
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 200L, kKswordArkBugcheckLayoutColorText, 35UL,
        "MODULE  %s", moduleText);
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 216L, kKswordArkBugcheckLayoutColorText, 35UL,
        "CLASS   %s",
        kswordArkBugcheckModuleClassText(diagnostics->candidateClass));
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 232L, kKswordArkBugcheckLayoutColorText, 35UL,
        "CONF    %s",
        kswordArkBugcheckConfidenceText(diagnostics->candidateConfidence));
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 252L, kKswordArkBugcheckLayoutColorWarning, 35UL,
        "RSP     DUMP ONLY");
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 268L, kKswordArkBugcheckLayoutColorWarning, 35UL,
        "RFLAGS  DUMP ONLY");
    kswordArkBugcheckDetailedWrite(
        writer, 504L, 284L, kKswordArkBugcheckLayoutColorWarning, 35UL,
        "CR2     DUMP ONLY");
}

// Instruction bytes are never dereferenced in the high-IRQL callback path.
static VOID
kswordArkBugcheckDetailedDrawInstruction(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 112L, kKswordArkBugcheckLayoutColorMuted, 43UL,
        "FAULTING INSTRUCTION");
    kswordArkBugcheckDetailedWrite(
        writer, 1160L, 112L, kKswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 138L, kKswordArkBugcheckLayoutColorWarning, 43UL,
        "PREVIOUS   REQUIRES MEMORY.DMP");
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 158L, kKswordArkBugcheckLayoutColorAccent, 43UL,
        "> CURRENT  0x%p", (PVOID)diagnostics->faultAddress);
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 178L, kKswordArkBugcheckLayoutColorWarning, 43UL,
        "NEXT       REQUIRES MEMORY.DMP");
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 206L, kKswordArkBugcheckLayoutColorText, 43UL,
        "ADDRESS   0x%p", (PVOID)diagnostics->candidateAddress);
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 224L, kKswordArkBugcheckLayoutColorText, 43UL,
        "ACCESS    %s", diagnostics->faultMeaning);
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 242L, kKswordArkBugcheckLayoutColorWarning, 43UL,
        "BYTES     NOT READ AT BUGCHECK IRQL");
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 260L, kKswordArkBugcheckLayoutColorWarning, 43UL,
        "SYMBOL    RESOLVE AFTER RESTART");
    kswordArkBugcheckDetailedWrite(
        writer, 860L, 282L, kKswordArkBugcheckLayoutColorMuted, 43UL,
        "WINDBG    .TRAP / .CXR / UB / U");
}

// Thread and process details are intentionally deferred to dump analysis.
static VOID
kswordArkBugcheckDetailedDrawThread(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 323L, kKswordArkBugcheckLayoutColorMuted, 32UL,
        "CURRENT THREAD / PROCESS");
    kswordArkBugcheckDetailedWrite(
        writer, 226L, 323L, kKswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 348L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "THREAD   NOT CAPTURED");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 364L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "PROCESS  NOT CAPTURED");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 380L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "START    DUMP ONLY");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 396L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "STATE    DUMP ONLY");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 412L, kKswordArkBugcheckLayoutColorText, 32UL,
        "CPU      %lu", diagnostics->cpu);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 428L, kKswordArkBugcheckLayoutColorText, 32UL,
        "IRQL     %lu", diagnostics->irql);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 448L, kKswordArkBugcheckLayoutColorMuted, 32UL,
        "WINDBG   !THREAD / !PROCESS");
}

// Stack walking is represented honestly because unwind work is not crash-safe.
static VOID
kswordArkBugcheckDetailedDrawStack(
    _Inout_ KswordArkBugcheckDetailedWriter* writer
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 323L, kKswordArkBugcheckLayoutColorMuted, 34UL,
        "STACK TRACE / TOP FRAMES");
    kswordArkBugcheckDetailedWrite(
        writer, 558L, 323L, kKswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 348L, kKswordArkBugcheckLayoutColorWarning, 34UL,
        "#00  REQUIRES MEMORY.DMP");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 364L, kKswordArkBugcheckLayoutColorWarning, 34UL,
        "#01  REQUIRES UNWIND METADATA");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 380L, kKswordArkBugcheckLayoutColorWarning, 34UL,
        "#02  REQUIRES REGISTER CONTEXT");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 396L, kKswordArkBugcheckLayoutColorWarning, 34UL,
        "#03  RESOLVE WITH SYMBOLS");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 416L, kKswordArkBugcheckLayoutColorText, 34UL,
        "COMMAND  !ANALYZE -V");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 432L, kKswordArkBugcheckLayoutColorText, 34UL,
        "COMMAND  KV / .TRAP / .CXR");
    kswordArkBugcheckDetailedWrite(
        writer, 346L, 448L, kKswordArkBugcheckLayoutColorMuted, 34UL,
        "NO UNSAFE LIVE STACK WALK ATTEMPTED");
}

// Module identity is resolved from the nonpaged cache prepared before failure.
static VOID
kswordArkBugcheckDetailedDrawModule(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 323L, kKswordArkBugcheckLayoutColorMuted, 28UL,
        "FAULTING MODULE");
    kswordArkBugcheckDetailedWrite(
        writer, 848L, 323L, kKswordArkBugcheckLayoutColorAccent, 10UL,
        "[CAPTURED]");
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 348L, kKswordArkBugcheckLayoutColorAccent, 28UL,
        "%s", kswordArkBugcheckDetailedModuleText(diagnostics));
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 368L, kKswordArkBugcheckLayoutColorText, 28UL,
        "BASE   0x%p", (PVOID)diagnostics->candidateModuleBase);
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 384L, kKswordArkBugcheckLayoutColorText, 28UL,
        "SIZE   0x%08lX", diagnostics->candidateModuleSize);
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 400L, kKswordArkBugcheckLayoutColorText, 28UL,
        "OFFSET 0x%p", (PVOID)diagnostics->candidateModuleOffset);
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 416L, kKswordArkBugcheckLayoutColorText, 28UL,
        "CLASS  %s",
        kswordArkBugcheckModuleClassText(diagnostics->candidateClass));
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 432L, kKswordArkBugcheckLayoutColorText, 28UL,
        "SOURCE %s", kswordArkBugcheckDetailedSourceText(diagnostics));
    kswordArkBugcheckDetailedWrite(
        writer, 678L, 448L, kKswordArkBugcheckLayoutColorWarning, 28UL,
        "VERSION / PDB  DUMP ONLY");
}

// Windows blackbox streams are listed without claiming callback availability.
static VOID
kswordArkBugcheckDetailedDrawBlackbox(
    _Inout_ KswordArkBugcheckDetailedWriter* writer
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 323L, kKswordArkBugcheckLayoutColorMuted, 32UL,
        "BLACKBOX SNAPSHOT");
    kswordArkBugcheckDetailedWrite(
        writer, 1160L, 323L, kKswordArkBugcheckLayoutColorWarning, 11UL,
        "[DUMP ONLY]");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 348L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "BSD       QUERY AFTER RESTART");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 364L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "NTFS      QUERY AFTER RESTART");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 380L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "PNP       QUERY AFTER RESTART");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 396L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "WINLOGON  QUERY AFTER RESTART");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 416L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "LAST DRIVER   NOT CAPTURED");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 432L, kKswordArkBugcheckLayoutColorWarning, 32UL,
        "LAST PROCESS  NOT CAPTURED");
    kswordArkBugcheckDetailedWrite(
        writer, 960L, 448L, kKswordArkBugcheckLayoutColorMuted, 32UL,
        "WINDBG  !BLACKBOXBSD / NTFS / PNP");
}

// The processor panel reports only state that the callback captures safely.
static VOID
kswordArkBugcheckDetailedDrawCpu(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ PCSTR moduleText
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 489L, kKswordArkBugcheckLayoutColorMuted, 50UL,
        "CPU SUMMARY");
    kswordArkBugcheckDetailedWrite(
        writer, 342L, 489L, kKswordArkBugcheckLayoutColorWarning, 18UL,
        "[CRASH CPU LIVE]");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 514L, kKswordArkBugcheckLayoutColorMuted, 50UL,
        "CPU  STATE       IRQL  CURRENT FUNCTION");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 536L, kKswordArkBugcheckLayoutColorAccent, 50UL,
        "%02lu   BUGCHECK    %02lu    %s+0x%p",
        diagnostics->cpu,
        diagnostics->irql,
        moduleText,
        (PVOID)diagnostics->candidateModuleOffset);
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 558L, kKswordArkBugcheckLayoutColorWarning, 50UL,
        "OTHER CPU STATES REQUIRE MEMORY.DMP");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 578L, kKswordArkBugcheckLayoutColorWarning, 50UL,
        "ACTIVE CPU COUNT NOT CAPTURED AT BUGCHECK");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 602L, kKswordArkBugcheckLayoutColorText, 50UL,
        "WINDBG  !PRCB / !RUNAWAY / ~* KV");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 622L, kKswordArkBugcheckLayoutColorMuted, 50UL,
        "GROUP NUMBER AND PER-CPU THREADS ARE DUMP ONLY");
    kswordArkBugcheckDetailedWrite(
        writer, 28L, 650L, kKswordArkBugcheckLayoutColorAccent, 50UL,
        "CAPTURED CPU / IRQL  %lu / %lu",
        diagnostics->cpu,
        diagnostics->irql);
}

// The dump panel presents callback state without inventing a percentage.
static VOID
kswordArkBugcheckDetailedDrawDump(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 489L, kKswordArkBugcheckLayoutColorMuted, 36UL,
        "DUMP STATUS");
    kswordArkBugcheckDetailedWrite(
        writer, 750L, 489L, kKswordArkBugcheckLayoutColorAccent, 10UL,
        "[CAPTURED]");
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 514L, kKswordArkBugcheckLayoutColorText, 36UL,
        "TYPE      %s",
        kswordArkBugcheckDumpTypeText(diagnostics->lastDumpType));
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 530L, kKswordArkBugcheckLayoutColorAccent, 36UL,
        "STAGE     %s",
        kswordArkBugcheckReasonText(diagnostics->lastReason));
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 546L, kKswordArkBugcheckLayoutColorText, 36UL,
        "OFFSET    0x%p", (PVOID)(ULONG_PTR)diagnostics->dumpOffset);
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 562L, kKswordArkBugcheckLayoutColorText, 36UL,
        "CHUNK     0x%08lX", diagnostics->dumpBufferLength);
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 578L, kKswordArkBugcheckLayoutColorText, 36UL,
        "CALLBACKS 0x%02lX", callbackMask & 0x0FUL);
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 594L, kKswordArkBugcheckLayoutColorText, 36UL,
        "MODULES   %lu", moduleCount);
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 610L, kKswordArkBugcheckLayoutColorText, 36UL,
        "DRIVER    0x%p", gKswordArkBugcheckState.driverObject);
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 626L, kKswordArkBugcheckLayoutColorText, 36UL,
        "DEVICE    0x%p", gKswordArkBugcheckState.deviceObject);
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 646L, kKswordArkBugcheckLayoutColorWarning, 36UL,
        "PERCENT   CONTROLLED BY WINDOWS");
    kswordArkBugcheckDetailedWrite(
        writer, 512L, 662L, kKswordArkBugcheckLayoutColorMuted, 36UL,
        "DO NOT POWER OFF DURING DUMP WRITING");
}

// Event metadata states clearly which identifiers only exist after reboot.
static VOID
kswordArkBugcheckDetailedDrawEvent(
    _Inout_ KswordArkBugcheckDetailedWriter* writer,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 489L, kKswordArkBugcheckLayoutColorMuted, 43UL,
        "EVENT INFO");
    kswordArkBugcheckDetailedWrite(
        writer, 1130L, 489L, kKswordArkBugcheckLayoutColorWarning, 14UL,
        "[MIXED SOURCE]");
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 514L, kKswordArkBugcheckLayoutColorText, 43UL,
        "PERF COUNTER  0x%p",
        (PVOID)(ULONG_PTR)diagnostics->perfCounter.QuadPart);
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 530L, kKswordArkBugcheckLayoutColorText, 43UL,
        "BUGCHECK      0x%08lX", diagnostics->bugCheckCode);
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 546L, kKswordArkBugcheckLayoutColorWarning, 43UL,
        "EVENT TIME / REPORT ID  ASSIGNED AFTER RESTART");
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 562L, kKswordArkBugcheckLayoutColorMuted, 43UL,
        "DUMP TARGET   MEMORY.DMP");
}

// Static recovery guidance occupies the last detailed panel.
static VOID
kswordArkBugcheckDetailedDrawHelp(
    _Inout_ KswordArkBugcheckDetailedWriter* writer
    )
{
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 591L, kKswordArkBugcheckLayoutColorMuted, 43UL,
        "NEXT ACTION");
    kswordArkBugcheckDetailedWrite(
        writer, 1120L, 591L, kKswordArkBugcheckLayoutColorAccent, 15UL,
        "[SAFE GUIDANCE]");
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 614L, kKswordArkBugcheckLayoutColorText, 43UL,
        "> PRESERVE THE NEWEST CRASH DUMP.");
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 630L, kKswordArkBugcheckLayoutColorText, 43UL,
        "> AFTER RESTART ATTACH THIS SCREEN AND MEMORY.DMP.");
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 646L, kKswordArkBugcheckLayoutColorText, 43UL,
        "> RESOLVE AMBER FIELDS WITH WINDBG OR KSWORDARK.");
    kswordArkBugcheckDetailedWrite(
        writer, 864L, 662L, kKswordArkBugcheckLayoutColorWarning, 43UL,
        "> DO NOT POWER OFF WHILE WINDOWS WRITES THE DUMP.");
}

// The public entry renders the complete 1280x720 information architecture.
NTSTATUS
kswordArkBugcheckLayoutDrawDetailed(
    _In_ const KswordArkBugcheckLayoutCanvas* canvas,
    _In_ const KswordArkBugcheckDiagnostics* diagnostics,
    _In_ ULONG callbackMask,
    _In_ ULONG moduleCount
    )
{
    KswordArkBugcheckDetailedWriter writer;
    PCSTR moduleText;

    if (canvas == NULL || diagnostics == NULL ||
        canvas->drawText == NULL || canvas->drawFrame == NULL ||
        canvas->width < KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH ||
        canvas->height < KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_HEIGHT) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&writer, sizeof(writer));
    writer.canvas = canvas;
    writer.originX = kswordArkBugcheckLayoutOriginX(
        canvas->width,
        canvas->height);
    writer.status = STATUS_SUCCESS;
    moduleText = kswordArkBugcheckDetailedModuleText(diagnostics);

    // Every frame uses resources created at PASSIVE_LEVEL before the failure.
    kswordArkBugcheckDetailedFrame(
        &writer, 16L, 100L, kKswordArkBugcheckLayoutFrameDetailedTopLeft);
    kswordArkBugcheckDetailedFrame(
        &writer, 492L, 100L, kKswordArkBugcheckLayoutFrameDetailedTopMiddle);
    kswordArkBugcheckDetailedFrame(
        &writer, 848L, 100L, kKswordArkBugcheckLayoutFrameDetailedTopRight);
    kswordArkBugcheckDetailedFrame(
        &writer, 16L, 311L, kKswordArkBugcheckLayoutFrameDetailedMiddleThread);
    kswordArkBugcheckDetailedFrame(
        &writer, 334L, 311L, kKswordArkBugcheckLayoutFrameDetailedMiddleStack);
    kswordArkBugcheckDetailedFrame(
        &writer, 666L, 311L, kKswordArkBugcheckLayoutFrameDetailedMiddleModule);
    kswordArkBugcheckDetailedFrame(
        &writer, 948L, 311L, kKswordArkBugcheckLayoutFrameDetailedMiddleBlackbox);
    kswordArkBugcheckDetailedFrame(
        &writer, 16L, 477L, kKswordArkBugcheckLayoutFrameDetailedBottomCpu);
    kswordArkBugcheckDetailedFrame(
        &writer, 500L, 477L, kKswordArkBugcheckLayoutFrameDetailedBottomDump);
    kswordArkBugcheckDetailedFrame(
        &writer, 852L, 477L, kKswordArkBugcheckLayoutFrameDetailedBottomEvent);
    kswordArkBugcheckDetailedFrame(
        &writer, 852L, 579L, kKswordArkBugcheckLayoutFrameDetailedBottomHelp);

    kswordArkBugcheckDetailedDrawHeader(&writer, diagnostics, callbackMask);
    kswordArkBugcheckDetailedDrawBugcheck(&writer, diagnostics);
    kswordArkBugcheckDetailedDrawFaultContext(&writer, diagnostics);
    kswordArkBugcheckDetailedDrawInstruction(&writer, diagnostics);
    kswordArkBugcheckDetailedDrawThread(&writer, diagnostics);
    kswordArkBugcheckDetailedDrawStack(&writer);
    kswordArkBugcheckDetailedDrawModule(&writer, diagnostics);
    kswordArkBugcheckDetailedDrawBlackbox(&writer);
    kswordArkBugcheckDetailedDrawCpu(&writer, diagnostics, moduleText);
    kswordArkBugcheckDetailedDrawDump(
        &writer,
        diagnostics,
        callbackMask,
        moduleCount);
    kswordArkBugcheckDetailedDrawEvent(&writer, diagnostics);
    kswordArkBugcheckDetailedDrawHelp(&writer);
    kswordArkBugcheckDetailedWrite(
        &writer, 16L, 700L, kKswordArkBugcheckLayoutColorMuted, 72UL,
        "BLUE=CAPTURED  AMBER=DUMP ONLY  WAITING FOR WINDOWS DUMP COMPLETION");
    return writer.status;
}

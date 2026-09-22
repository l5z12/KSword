#pragma once

// ============================================================
// DumpAutoCheck.h
// Purpose:
// - After startup, check if any new crash dumps were generated in the system recently (default:
//   within 24 hours); if so, mainWindow asks the user whether to parse them immediately.
// - Determine if a parsing result is related to KSword's own components: if matched, guide the user to report it, as
//   such crashes are defects that must be fixed for this project, not issues like 'someone else's driver is broken'.
// - Provide reporting guidance text (QQ Group / GitHub Issues / trigger flow that must be explained).
// Design constraints:
// - Scanning performs only directory enumeration and timestamp comparison without opening or parsing files, making it safe to place on the startup path.
// - Whether to show a dialog and whether to remember 'asked' status are decided by the caller (mainWindow) based
//   on persistent settings; this module does not read or write configuration, ensuring testability and reusability.
// ============================================================

#include <QDateTime>
#include <QString>
#include <QStringList>

namespace ks::minidump
{
    struct DumpParseResult;

    // RecentDumpInfo: The latest dump found in a single scan.
    struct RecentDumpInfo
    {
        bool found = false;        // found: Whether a dump matching the time condition was found.
        QString filePath;          // filePath: Full path of the dump file.
        QDateTime modifiedTime;    // modifiedTime: File last modified time (local time zone).
        qint64 fileSizeBytes = 0;  // fileSizeBytes: File size in bytes.
        bool isKernelDump = false; // isKernelDump: true = BSOD dump, false = other.
        int totalRecentCount = 0;  // totalRecentCount: Total number of dumps within the time window (including this one).
    };

    // findRecentDump purpose: Locate the most recent system crash dump within the time window.
    // Scan C:\Windows\Minidump\*.dmp and C:\Windows\MEMORY.DMP;
    // Pass maxAgeHours time window (in hours; <=0 defaults to 24 hours);
    // Returns the most recent entry; found=false if no dump exists within the window.
    // The function performs directory enumeration only and does not open file contents.
    RecentDumpInfo findRecentDump(int maxAgeHours = 24);

    // KswordRelevance: Determines the relevance of the parsed result to KSword's own components.
    struct KswordRelevance
    {
        bool related = false;        // related: Whether the KSword proprietary module was matched.
        bool inBlameList = false;    // inBlameList: The hit is a 'blame module candidate' (strongest signal).
        bool inStack = false;        // inStack: Appears in a suspected call stack.
        bool inUnloadedList = false; // inUnloadedList: Present in the unloaded module list.
        bool onlyLoaded = false;     // onlyLoaded: Appears only in the loaded module table—this only indicates the program was running at that time.
        QStringList matchedModules;  // matchedModules: Matched module names (deduplicated).
        QString summary;             // summary: A one-sentence description of the hit intensity, ready for display.
    };

    // evaluateKswordRelevance purpose: determine if the parse result points to KSword's own components.
    // Accepts the completed parse result; returns the relevance determination.
    // Evidence ranking: suspected culprit > call stack > unloaded-module table > present only in the loaded-module table.
    // The last layer does not constitute evidence 'related to KSword'—since KSword is running, it must appear in the module
    // table. Prompting the user to report based on this would only generate noise; thus, related returns false for this layer.
    KswordRelevance evaluateKswordRelevance(const DumpParseResult& result);

    // kswordQqGroupUrl / kswordIssuesUrl: Return the reporting channel addresses.
    QString kswordQqGroupUrl();
    QString kswordIssuesUrl();

    // buildKswordReportGuidance purpose: Generate the report guidance body for 'KSword hit' scenarios.
    // Pass relevance (determination result) and dumpFilePath (dump file path);
    // Return value: Multi-line Chinese text ready for the dialog, including key points of the trigger process that must be provided.
    QString buildKswordReportGuidance(
        const KswordRelevance& relevance,
        const QString& dumpFilePath);
}

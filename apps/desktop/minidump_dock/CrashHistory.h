#pragma once

// ============================================================
// CrashHistory.h
// Purpose:
// - Read system event logs and summarize recent crash facts into a timeline:
//   BSOD records (stop code + parameters + dump path), abnormal shutdowns,
//   and file system filter load records (including image timestamps);
// - Answer two questions that cannot be resolved by examining a single dump in isolation:
//   1) Was this a BSOD or a 'hard hang without a dump'? Both exhibit similar symptoms, but the former produces a
//      dump for analysis while the latter generates none, requiring entirely different troubleshooting approaches;
//   2) Identify which driver build was running in the system at the time of the crash.
//
// Why it's needed (lessons from practice):
// - After fixing a driver bug, recompiling, and reloading, the system crashed again. Without checking the dump, it was impossible to determine if the
//   crash occurred in the fixed version. Only by reading the image timestamp from the filter load records and matching it against the build timestamp
//   could we confirm that "the fix did not take effect" rather than "the wrong version was installed," avoiding a full round of misdiagnosis.
// - Two non-dump hard hangs occurred on the same night. In the event log, they appear as
//   abnormal shutdowns with BugcheckCode=0; if this class is not distinguished from blue
//   screens, two completely different issues will be mixed together when tracing the cause.
//
// Limitation:
// - Read-only system logs (readable by standard users); do not access security logs.
// - Event logs become unqueryable after being cleared or scrolled over; longer time windows increase the likelihood of incomplete data.
// ============================================================

#include <QDateTime>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <vector>

namespace ks::minidump
{
    // CrashEventKind: The nature of a record on the timeline.
    enum class CrashEventKind
    {
        kBugCheck,      // BugCheck: A blue screen with a stop code and a dump file.
        kHardHang,      // HardHang: Abnormal shutdown without a stop code—hard hang with no dump.
        kBugCheckReboot,// BugCheckReboot: Abnormal shutdown with a stop code, corresponding to a specific blue screen.
        kFilterLoad,    // FilterLoad: File system filter loaded, including image timestamp.
    };

    // CrashHistoryEntry: A record on the timeline.
    struct CrashHistoryEntry
    {
        QDateTime time;                             // time: Event time (local time zone).
        CrashEventKind kind = CrashEventKind::kBugCheck; // kind: Record type.
        QString kindText;                           // kindText: Chinese phrase for the nature.
        QString summary;                            // summary: One-sentence summary.
        QString detail;                             // detail: Key field details.
        std::uint32_t bugCheckCode = 0;             // bugCheckCode: Stop code; 0 if none.
        QString dumpPath;                           // dumpPath: Path to the dump file; may be null.
    };

    // collectCrashHistory purpose: Aggregate crash/hang/filter load records from the last maxDays.
    // Accepts maxDays (time window in days; <=0 defaults to 30), filterNameFilter (substring filter for names; if empty, no filter
    //load records are collected to avoid flooding with hundreds of irrelevant drivers), and errorOut (output for failure reason);
    // Returns records sorted in reverse chronological order; if reading the log fails, returns an empty table and writes to errorOut.
    std::vector<CrashHistoryEntry> collectCrashHistory(
        int maxDays,
        const QString& filterNameFilter,
        QString* errorOut);

    // crashEventKindText purpose: Convert record type into a Chinese phrase.
    // Input kind; returns text ready for table display.
    QString crashEventKindText(CrashEventKind kind);
}

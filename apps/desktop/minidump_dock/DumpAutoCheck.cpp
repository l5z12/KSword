#include "DumpAutoCheck.h"

// ============================================================
// DumpAutoCheck.cpp
// Notes:
// - The 'related to KSword' check is deliberately layered: Presence in the loaded module table alone is not evidence,
//   as KSword is always in the table during runtime. Relying on this for reporting would only generate noise.
//   What matters is whether it appears among the suspected culprits, in the call stack, or in the unloaded-module table;
// - Reporting guidelines emphasize the 'trigger process': crash reports without reproduction steps are basically
//   impossible to locate, and users often only paste a stop code, so list exactly what to write item by item.
// ============================================================

#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"
#include "../internationalization/LanguageManager.h"

#include <QDir>
#include <QFileInfo>
#include <QSet>

#include <algorithm>

namespace ks::minidump
{
    namespace
    {
        // kKswordModulePrefix: Unified prefix for KSword's own modules.
        // The driver artifact is KswordARK.sys, while user-mode components include
        // Ksword5.1.exe, KswordARKLight.exe, KswordHUD.exe, etc. Prefix matching
        // is more robust against renaming than enumerating each name individually.
        const QString kKswordModulePrefix = QStringLiteral("ksword");

        // kExtraKswordModules: Components belonging to this project but without the 'ksword' prefix.
        const char* const kExtraKswordModules[] = {
            "apimonitor_x64.dll",
        };

        // isKswordModule purpose: determine if the module name belongs to KSword's own components.
        // Input moduleName (module name or full path); comparison considers only the filename part and is case-insensitive.
        bool isKswordModule(const QString& moduleName)
        {
            const QString kBaseName = baseModuleName(moduleName).trimmed().toLower();
            if (kBaseName.isEmpty())
            {
                return false;
            }
            if (kBaseName.startsWith(kKswordModulePrefix))
            {
                return true;
            }
            for (const char* const kExtraName : kExtraKswordModules)
            {
                if (kBaseName == QString::fromLatin1(kExtraName))
                {
                    return true;
                }
            }
            return false;
        }

        // appendMatched function: Adds deduplicated matched module names to the list.
        void appendMatched(QStringList& matched, const QString& moduleName)
        {
            const QString kBaseName = baseModuleName(moduleName).trimmed();
            if (kBaseName.isEmpty())
            {
                return;
            }
            for (const QString& existing : matched)
            {
                if (existing.compare(kBaseName, Qt::CaseInsensitive) == 0)
                {
                    return;
                }
            }
            matched.append(kBaseName);
        }

        // scanDumpDirectory purpose: merge dump files from a directory into the candidate set.
        // Accepts directoryPath, cutoffTime lower bound, and output parameters.
        // Silently return if the directory does not exist; this is a normal state if dumps were never installed or a blue screen never occurred.
        void scanDumpDirectory(
            const QString& directoryPath,
            const QDateTime& cutoffTime,
            RecentDumpInfo& best)
        {
            QDir directory(directoryPath);
            if (!directory.exists())
            {
                return;
            }
            const QFileInfoList kEntries = directory.entryInfoList(
                QStringList{ QStringLiteral("*.dmp") },
                QDir::Files | QDir::Readable,
                QDir::Time);
            for (const QFileInfo& entry : kEntries)
            {
                const QDateTime kModifiedTime = entry.lastModified();
                if (!kModifiedTime.isValid() || kModifiedTime < cutoffTime)
                {
                    continue;
                }
                ++best.totalRecentCount;
                if (best.found && best.modifiedTime >= kModifiedTime)
                {
                    continue;
                }
                best.found = true;
                best.filePath = QDir::toNativeSeparators(entry.absoluteFilePath());
                best.modifiedTime = kModifiedTime;
                best.fileSizeBytes = entry.size();
                best.isKernelDump = true;
            }
        }

        // scanSingleDumpFile purpose: merge a specific dump file into the candidate set.
        void scanSingleDumpFile(
            const QString& filePath,
            const QDateTime& cutoffTime,
            RecentDumpInfo& best)
        {
            const QFileInfo kEntry(filePath);
            if (!kEntry.exists() || !kEntry.isFile() || !kEntry.isReadable())
            {
                return;
            }
            const QDateTime kModifiedTime = kEntry.lastModified();
            if (!kModifiedTime.isValid() || kModifiedTime < cutoffTime)
            {
                return;
            }
            ++best.totalRecentCount;
            if (best.found && best.modifiedTime >= kModifiedTime)
            {
                return;
            }
            best.found = true;
            best.filePath = QDir::toNativeSeparators(kEntry.absoluteFilePath());
            best.modifiedTime = kModifiedTime;
            best.fileSizeBytes = kEntry.size();
            best.isKernelDump = true;
        }
    }

    RecentDumpInfo findRecentDump(const int maxAgeHours)
    {
        RecentDumpInfo best{};
        const int kEffectiveHours = maxAgeHours > 0 ? maxAgeHours : 24;
        const QDateTime kCutoffTime =
            QDateTime::currentDateTime().addSecs(-static_cast<qint64>(kEffectiveHours) * 3600);

        // System directory is retrieved from an environment variable rather than hard-coded as C:\Windows.
        // It is not uncommon for the system drive to be non-C:.
        QString windowsDirectory = qEnvironmentVariable("SystemRoot");
        if (windowsDirectory.isEmpty())
        {
            windowsDirectory = qEnvironmentVariable("windir");
        }
        if (windowsDirectory.isEmpty())
        {
            windowsDirectory = QStringLiteral("C:/Windows");
        }

        const QDir kWindowsDir(windowsDirectory);
        scanDumpDirectory(kWindowsDir.filePath(QStringLiteral("Minidump")), kCutoffTime, best);
        scanSingleDumpFile(kWindowsDir.filePath(QStringLiteral("MEMORY.DMP")), kCutoffTime, best);
        return best;
    }

    KswordRelevance evaluateKswordRelevance(const DumpParseResult& result)
    {
        KswordRelevance relevance{};

        // Layer 1: Candidate module for the incident. After attribution weighting, it still points to KSword, representing the strongest signal.
        for (const BlameEntry& blame : result.analysis.blame)
        {
            if (isKswordModule(blame.moduleName))
            {
                relevance.inBlameList = true;
                appendMatched(relevance.matchedModules, blame.moduleName);
            }
        }

        // Layer 2: Suspected call stack. Stack scanning may produce false positives, but the presence of a KSword module on the stack still warrants investigation.
        for (const StackFrameEntry& frame : result.stackFrames)
        {
            if (isKswordModule(frame.moduleName))
            {
                relevance.inStack = true;
                appendMatched(relevance.matchedModules, frame.moduleName);
            }
        }

        // Layer 3: Unloaded module table. If a KSword module is still hit after the driver is unloaded, it usually
        // means there are callbacks or pending operations that were not properly cleaned up along the unload path.
        for (const UnloadedModuleEntry& unloaded : result.unloadedModules)
        {
            if (isKswordModule(unloaded.name))
            {
                relevance.inUnloadedList = true;
                appendMatched(relevance.matchedModules, unloaded.name);
            }
        }

        relevance.related =
            relevance.inBlameList || relevance.inStack || relevance.inUnloadedList;

        if (!relevance.related)
        {
            // Presence in the loaded modules table alone is not evidence: KSword is always in the table during runtime.
            for (const ModuleEntry& moduleEntry : result.modules)
            {
                if (isKswordModule(moduleEntry.name))
                {
                    relevance.onlyLoaded = true;
                    appendMatched(relevance.matchedModules, moduleEntry.name);
                }
            }
            return relevance;
        }

        if (relevance.inBlameList)
        {
            relevance.summary = QStringLiteral(
                "归因结果把 KSword 组件列为肇事模块候选，这是最强的关联信号。");
        }
        else if (relevance.inUnloadedList)
        {
            relevance.summary = QStringLiteral(
                "崩溃现场命中了已卸载的 KSword 驱动，通常意味着卸载时有回调或挂起操作未取消。");
        }
        else
        {
            relevance.summary = QStringLiteral(
                "疑似调用栈上出现了 KSword 组件的地址。栈扫描存在误报，"
                "但仍建议上报由开发者复核。");
        }
        return relevance;
    }

    QString kswordQqGroupUrl()
    {
        return QStringLiteral("https://qm.qq.com/q/5tWNPfIxkk");
    }

    QString kswordIssuesUrl()
    {
        return QStringLiteral("https://github.com/KSwordDEV/KSword/issues");
    }

    QString buildKswordReportGuidance(
        const KswordRelevance& relevance,
        const QString& dumpFilePath)
    {
        QStringList lines;
        lines.append(ks::i18n::sourceText(relevance.summary));
        if (!relevance.matchedModules.isEmpty())
        {
            lines.append(ks::i18n::sourceText(QStringLiteral("命中组件：%1"))
                .arg(relevance.matchedModules.join(ks::i18n::text(
                    QStringLiteral("minidump.report.module_separator"),
                    QStringLiteral("、")))));
        }
        lines.append(QString());
        lines.append(ks::i18n::sourceText(
            QStringLiteral("这属于 KSword 自身的问题，请反馈给开发者。提交时请一并说明：")));
        lines.append(ks::i18n::sourceText(QStringLiteral(
            "1. 崩溃前你在 KSword 里做了什么：打开了哪个页面、点了哪个功能、"
            "目标进程/驱动/文件是什么；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("2. 是否可以稳定复现，以及复现的具体步骤；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("3. 当时 R0 驱动是否已启用，是否刚做过加载/卸载操作；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("4. 系统版本与 KSword 版本；")));
        lines.append(ks::i18n::sourceText(
            QStringLiteral("5. 附上本页的“导出报告”结果，必要时附转储文件本身。")));
        if (!dumpFilePath.isEmpty())
        {
            lines.append(ks::i18n::sourceText(
                QStringLiteral("   转储文件：%1")).arg(dumpFilePath));
        }
        lines.append(QString());
        lines.append(ks::i18n::sourceText(
            QStringLiteral("反馈渠道：QQ 群，或 GitHub Issues。")));
        return lines.join(QStringLiteral("\n"));
    }
}

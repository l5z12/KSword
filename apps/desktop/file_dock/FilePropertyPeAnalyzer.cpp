#include "FilePropertyPeAnalyzer.h"

// ============================================================
// FilePropertyPeAnalyzer.cpp
// Purpose:
// - Purpose: Retain the QString API for the FileDock property window;
// - Delegate PE reading, headers, section tables, and import/export/directory parsing to ks::file.
// - The UI layer is only responsible for displaying the returned text in CodeEditorWidget.
// ============================================================

#include "../../../shared/platform/file/PeAnalyzer.h"

#include <QSet>

#include <string>

namespace file_dock_detail
{
    namespace
    {
        // formatRvaText:
        // - Formats import thunk RVA into a unified hexadecimal text for the UI.
        // - Input: RVA parsed by the backend security analyzer; output always includes the 0x prefix.
        QString formatRvaText(const std::uint32_t rvaValue)
        {
            return QStringLiteral("0x%1")
                .arg(rvaValue, 8, 16, QLatin1Char('0'))
                .toUpper();
        }
    }

    QString buildPeAnalysisText(const QString& filePath)
    {
        // Input filePath comes from the Qt UI; converted to std::wstring before passing to the non-UI backend.
        // Return value remains QString to keep the FileDock property window call site unchanged.
        const std::wstring kReportText = ks::file::buildPeAnalysisText(filePath.toStdWString());
        return QString::fromStdWString(kReportText);
    }

    PeDependencyResult analyzePeDependencies(const QString& filePath)
    {
        // Input filePath comes from the property window; processing logic reuses ks::file::analyzePeFile
        // for secure parsing of PE32/PE32+ headers and Import Directory; returns a Qt table model.
        PeDependencyResult dependencyResult{};
        const ks::file::PeAnalysisResult kAnalysisResult =
            ks::file::analyzePeFile(filePath.toStdWString());

        dependencyResult.success = kAnalysisResult.success;
        dependencyResult.isPe = kAnalysisResult.success;
        if (!kAnalysisResult.success)
        {
            const QString kReportText = QString::fromStdWString(kAnalysisResult.reportText).trimmed();
            const bool kClearlyNotPe =
                kReportText.contains(QStringLiteral("不是有效的 MZ 文件")) ||
                kReportText.contains(QStringLiteral("文件过小"));
            dependencyResult.isPe = !kClearlyNotPe;
            dependencyResult.errorText = kClearlyNotPe
                ? QStringLiteral("不适用：目标不是 EXE/DLL PE 文件。\n%1").arg(kReportText)
                : QStringLiteral("PE 解析失败：Import Directory 无法读取。\n%1").arg(kReportText);
            return dependencyResult;
        }

        QSet<QString> seenDllNames;
        for (const ks::file::PeImportModuleSummary& module : kAnalysisResult.importModules)
        {
            const QString kDllName = QString::fromStdString(module.dllName).trimmed();
            if (!kDllName.isEmpty() && !seenDllNames.contains(kDllName.toLower()))
            {
                seenDllNames.insert(kDllName.toLower());
                dependencyResult.dllNames.push_back(kDllName);
            }

            if (module.imports.empty())
            {
                PeDependencyRow row{};
                row.dllName = kDllName;
                row.importMode = QStringLiteral("<无函数项>");
                row.diagnosticText = QString::fromStdString(module.diagnosticText);
                dependencyResult.rows.push_back(row);
                continue;
            }

            for (const ks::file::PeImportFunctionSummary& function : module.imports)
            {
                PeDependencyRow row{};
                row.dllName = QString::fromStdString(function.dllName);
                row.functionName = QString::fromStdString(function.functionName);
                row.importMode = function.importByOrdinal
                    ? QStringLiteral("Ordinal")
                    : QStringLiteral("Name");
                row.ordinalText = function.importByOrdinal
                    ? QString::number(function.ordinal)
                    : QStringLiteral("-");
                row.hintText = function.importByOrdinal
                    ? QStringLiteral("-")
                    : QString::number(function.hint);
                row.thunkRvaText = formatRvaText(function.thunkRva);
                row.diagnosticText = QString::fromStdString(module.diagnosticText);
                dependencyResult.rows.push_back(row);
            }
        }

        if (dependencyResult.dllNames.isEmpty() && dependencyResult.rows.isEmpty())
        {
            dependencyResult.errorText = QStringLiteral("该 PE 没有 Import Directory 或未声明依赖 DLL。");
        }
        return dependencyResult;
    }
}

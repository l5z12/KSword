#pragma once

// ============================================================
// FilePropertyPeAnalyzer.h
// Purpose:
// 1) Provides PE header parsing text for the file properties window;
// 2) Output the import table, export table, and section overview.
// 3) Decouple from the FileDock UI to facilitate future expansion of resource tables and relocation tables.
// ============================================================

#include <QString>
#include <QStringList>
#include <QVector>

namespace file_dock_detail
{
    // PeDependencyRow:
    // - Convert ks::file import table structure into a single row displayable by Qt UI;
    // - Each row corresponds to an imported function; a DLL name row alone can be indicated by an empty functionName.
    struct PeDependencyRow
    {
        QString dllName;       // dllName: Dependent DLL name.
        QString functionName;  // functionName: Function name; empty when importing by ordinal.
        QString ordinalText;   // ordinalText: The Ordinal text imported by ordinal.
        QString hintText;      // hintText: Hint text for imported names.
        QString importMode;    // importMode: Name or Ordinal.
        QString thunkRvaText;  // thunkRvaText: Thunk/IAT RVA text.
        QString diagnosticText; // diagnosticText: Diagnostic analysis for this DLL or function.
    };

    // PeDependencyResult:
    // - Aggregates structured data and error text required for the 'Dependent DLLs' page.
    // - When success=false, errorText can be displayed directly to the user.
    struct PeDependencyResult
    {
        bool success = false;       // success: Whether PE parsing succeeded.
        bool isPe = false;          // isPe: Whether the target is a PE file; ordinary text files are false.
        QString errorText;          // errorText: Reason for failure or inapplicability.
        QStringList dllNames;       // dllNames: Deduplicated list of dependent DLL names.
        QVector<PeDependencyRow> rows; // rows: function-level import entries.
    };

    // buildPeAnalysisText:
    // - Read and parse the PE structure of the specified file.
    // - Returns text that can be directly displayed in a CodeEditorWidget.
    // Parameter filePath: Full path of the target file.
    // Returns: Parsed result text; if parsing fails, returns a human-readable error description.
    QString buildPeAnalysisText(const QString& filePath);

    // analyzePeDependencies:
    // - Read the PE Import Directory and convert it to a dependency DLL / import function table;
    // - Supports PE32 and PE32+; returns explicit error text for corrupted PE files.
    // Parameter filePath: Target EXE/DLL or other file path.
    // Returns: PeDependencyResult; the UI decides whether to display the table or a prompt based on success/isPe.
    PeDependencyResult analyzePeDependencies(const QString& filePath);
}

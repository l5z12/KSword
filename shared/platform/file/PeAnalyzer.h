#pragma once

// ============================================================
// ksword/file/pe_analyzer.h
// Namespace: ks::file.
// Purpose:
// - Provide PE parsing capabilities without Qt dependencies.
// - Parse PE headers, section tables, import/export tables, data directories, and common directory summaries.
// - The UI layer is only responsible for converting std::wstring reports into editor text.
// ============================================================

#include <cstdint>
#include <string>
#include <vector>

namespace ks::file
{
    // PeSectionSummary:
    // - Saves common UI/log fields from the section table;
    // - analyzePeFile can be used for subsequent non-textual display.
    struct PeSectionSummary
    {
        std::string name;
        std::uint32_t virtualAddress = 0;
        std::uint32_t virtualSize = 0;
        std::uint32_t rawOffset = 0;
        std::uint32_t rawSize = 0;
        std::uint32_t characteristics = 0;
        double entropy = 0.0;
    };

    // PeImportFunctionSummary:
    // - Stores structured information for a single imported function;
    // - The UI can directly use this structure to populate the "Dependent DLLs" table without reverse parsing from the text report.
    struct PeImportFunctionSummary
    {
        std::string dllName;             // dllName: Name of the imported DLL.
        std::string functionName;        // functionName: Function name when imported by name; empty when imported by ordinal.
        std::uint16_t hint = 0;          // hint: IMAGE_IMPORT_BY_NAME.Hint; 0 when importing by ordinal.
        std::uint16_t ordinal = 0;       // ordinal: the ordinal when importing by ordinal; 0 when importing by name.
        std::uint32_t thunkRva = 0;      // thunkRva: RVA of the current thunk/IAT entry for easy location.
        bool importByOrdinal = false;    // importByOrdinal: true=Ordinal import; false=Name import.
    };

    // PeImportModuleSummary:
    // - Saves the DLL and its function list corresponding to an IMAGE_IMPORT_DESCRIPTOR;
    // - descriptorIndex is used for display and corrupted import table diagnosis.
    struct PeImportModuleSummary
    {
        std::string dllName;                         // dllName: Name of the DLL pointed to by the import descriptor.
        std::uint32_t descriptorIndex = 0;           // descriptorIndex: Import descriptor index.
        std::vector<PeImportFunctionSummary> imports; // imports: Imported functions parsed under this DLL.
        std::string diagnosticText;                  // diagnosticText: Explanation for local parsing failures or truncation.
    };

    // PeAnalysisResult:
    // - Aggregate PE parsing result text and structured section table summary.
    // - When success=false, reportText stores a human-readable failure reason.
    struct PeAnalysisResult
    {
        bool success = false;
        bool isPe64 = false;
        std::uint16_t machine = 0;
        std::uint16_t subsystem = 0;
        std::uint32_t entryPointRva = 0;
        std::uint32_t entryPointFileOffset = 0;
        bool entryPointFileOffsetValid = false;
        std::uint64_t imageBase = 0;
        std::vector<PeSectionSummary> sections;
        std::vector<PeImportModuleSummary> importModules;
        std::wstring reportText;
    };

    // analyzePeFile purpose: reads the file and parses the PE structure, returning structured results and report text.
    PeAnalysisResult analyzePeFile(const std::wstring& filePath);

    // analyzePeBytes purpose: Directly parse PE bytes from raw disk, memory snapshots, or other evidence sources.
    PeAnalysisResult analyzePeBytes(
        const std::vector<std::uint8_t>& fileBytes);

    // buildPeAnalysisText purpose: maintains compatibility with the existing 'display text directly' call pattern in the property window.
    std::wstring buildPeAnalysisText(const std::wstring& filePath);

    // buildPeAnalysisText: Returns a human-readable analysis report of in-memory PE bytes.
    std::wstring buildPeAnalysisText(
        const std::vector<std::uint8_t>& fileBytes);

    // buildPeAnalysisTextUtf8 purpose: Allow non-Qt callers to pass UTF-8 file paths and receive UTF-8 reports.
    std::string buildPeAnalysisTextUtf8(const std::string& filePathUtf8);
}

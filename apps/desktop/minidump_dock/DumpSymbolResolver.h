#pragma once

// ============================================================
// DumpSymbolResolver.h
// Purpose:
// - Uses DbgHelp to load PDBs, upgrading call stacks from "module+0xoffset" to
//   "module!function+0xoffset", and appends "source_file:line_number" when available;
// - Before symbol resolution, verify that the image on disk is the same one loaded at the time of the crash:
//   Compare the PE TimeDateStamp and SizeOfImage recorded in the dump with the corresponding fields in the disk file. If they
//   do not match, mark the image as mismatched and treat all function names and line numbers in this module as untrustworthy.
//
// Why this validation is mandatory (lessons from practice):
// - Locates a driver blue screen where the driver was recompiled after the crash, causing the PDB on disk to be outdated.
//   The symbolization tool still provides function names and line numbers, but the line numbers are globally offset.
//   An error of just one line is enough to misdirect debugging to completely unrelated code. If the tool does not
//   actively report 'mismatch', users have no chance to realize they are reading fake data. Therefore, this module
//   prefers to refuse providing line numbers rather than providing line numbers without a matching conclusion.
//
// Limitation:
// - DbgHelp is not thread-safe; this module serializes access via a process-level mutex and is used only by the parsing worker.
// - Do not download symbols over the network: search paths are restricted to local directories to avoid resolution hanging on network operations.
// - The module table in kernel dumps comes from the loader list and typically lacks CodeView records; therefore,
//   matching relies primarily on the TimeDateStamp/SizeOfImage pair, which is sufficient to identify "recompiled" modules.
// Call method:
// - After resolution, call applySymbols() on the same worker thread to upgrade the result in place.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // SymbolMatchState and ModuleSymbolStatus are defined in MinidumpFormat.h:
    // DumpParseResult must directly hold per-module conclusions; placing it here would create a circular header dependency.

    // ResolvedSymbol: A single address-to-symbol resolution result.
    struct ResolvedSymbol
    {
        bool valid = false;             // valid: Whether the function name was resolved.
        QString moduleName;             // moduleName: Owning module name.
        QString functionName;           // functionName: Function name (undecorated).
        std::uint64_t displacement = 0; // displacement: Byte offset relative to the function entry point.
        QString sourceFile;             // sourceFile: Source file path; may be null.
        std::uint32_t sourceLine = 0;   // sourceLine: Source code line number; 0 indicates not retrieved.
        SymbolMatchState match = SymbolMatchState::kNotChecked; // match: Match conclusion for the owning module.

        // functionText purpose: Construct 'Module!Function+0xOffset'.
        // Returns an empty string when no function name is available; the caller should fall back to the existing 'module+offset'.
        QString functionText() const;

        // sourceText purpose: Constructs 'File:Line'.
        // Return an empty string when line number information is missing. Also return an empty string when the image does not match—an incorrect line number is more harmful than missing line numbers.
        QString sourceText() const;
    };

    // SymbolResolver purpose: Manages a DbgHelp session for a single resolution pass; automatically calls SymCleanup during destruction.
    // Holds the process-level DbgHelp mutex serially throughout its lifetime, so do not retain instances for long periods.
    class SymbolResolver
    {
    public:
        SymbolResolver();
        ~SymbolResolver();

        SymbolResolver(const SymbolResolver&) = delete;
        SymbolResolver& operator=(const SymbolResolver&) = delete;

        // begin: Establish a DbgHelp session and verify images and load symbols one by one according to the module table.
        // Parameters: searchPath is the symbol search path (semicolon-separated); modules is the module table from the dump.
        // Returns whether the session was established successfully (resolve always returns an invalid result on failure).
        bool begin(const QString& searchPath, const std::vector<ModuleEntry>& modules);

        // resolve purpose: Translates a code address into a function name and source location.
        // Input: target machine virtual address. Output: resolution result; valid=false if not found.
        ResolvedSymbol resolve(std::uint64_t address) const;

        // moduleStatus: Returns the symbol loading and matching conclusion for each module.
        // Returns a read-only reference to the internal status table, ordered consistently with the input module table.
        const std::vector<ModuleSymbolStatus>& moduleStatus() const;

    private:
        // Loaded: An address range and matching conclusion for a registered module.
        struct Loaded
        {
            std::uint64_t base = 0; // base: Load base address.
            std::uint64_t end = 0;  // end: end address (exclusive).
            QString name;           // name: Module name.
            SymbolMatchState state = SymbolMatchState::kNotChecked; // state: Matching conclusion.
        };

        void* handle_ = nullptr;                    // m_handle: Pseudo-process handle for SymInitialize.
        bool initialized_ = false;                  // m_initialized: Whether the session is established.
        std::vector<Loaded> loaded_;                // m_loaded: Registered modules sorted by base in ascending order.
        std::vector<ModuleSymbolStatus> status_;    // m_status: Per-module conclusions for UI display.
    };

    // buildDefaultSymbolSearchPath purpose: constructs the default local symbol search path.
    // Input dumpFilePath (dump file path) to include its directory in the search.
    // Returns a semicolon-separated path string containing only local directories, excluding any symbol servers.
    QString buildDefaultSymbolSearchPath(const QString& dumpFilePath);

    // applySymbols purpose: symbolize the parse result, upgrading the call stack and culprit candidates in-place.
    // Passes searchPath (symbol search path; empty string uses the default path) and result (parse result, modified in-place);
    // Populates result.symbolStatus and symbolSearchPath, and appends a diagnostics warning if an image mismatch is
    // detected—such warnings must be visible to the user, otherwise they may use incorrect line numbers when modifying code.
    void applySymbols(const QString& searchPath, DumpParseResult& result);

    // symbolMatchStateText: Converts the match conclusion into a Chinese phrase.
    // Input: state; returns text directly suitable for table display.
    QString symbolMatchStateText(SymbolMatchState state);
}

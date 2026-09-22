#pragma once

// ============================================================
// MinidumpParser.h
// Purpose:
// - Declare the main entry point for dump file parsing: parseDumpFile.
// - Automatically detect file type at the entry point.
//   MDMP (user-mode minidump) is parsed in this module; PAGEDU64/PAGEDUMP
//   (kernel dump) is delegated to KernelDumpParser for parsing.
// Call method:
// - MinidumpDock calls parseDumpFile(filePath) within a thread pool worker.
// - Return value DumpParseResult is self-contained with all display data and has no lifecycle dependency on file mappings.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // parseDumpFile purpose: open and parse a dump file.
    // Input: filePath is the full path to the dump file. Return a self-contained parsing result:
    // - recognized=false: the signature does not correspond to a supported dump format;
    // - recognized=true and success=false: The format is recognized but the file is corrupted or truncated; errorText provides the reason.
    // - success=true: Core information is displayed; non-fatal issues are recorded in diagnostics.
    // This function reads the target file only and is safe for samples from any source; all internal offset accesses include boundary checks.
    DumpParseResult parseDumpFile(const QString& filePath);
}

#pragma once

// ============================================================
// KernelDumpParser.h
// Purpose:
// - Declare kernel dump (blue screen DMP) parsing functions.
// - Supports 64-bit PAGEDU64 headers (including TRIAGE driver lists for mini-dumps)
//   and 32-bit PAGEDUMP headers (containing only critical header information);
// - Produces display data including BugCheck code, parameters, system version, and driver list.
// Call method:
// - Called exclusively by parseDumpFile in MinidumpParser.cpp after detecting the PAGE signature;
// - view is the mapped read-only file view; result is pre-initialized by the caller with filePath/fileSize.
// ============================================================

#include "MinidumpFormat.h"

namespace ks::minidump
{
    // parseKernelDump64 function: Parses 64-bit kernel dumps (signature PAGEDU64).
    // Accepts a read-only file view (view) and an output structure (result); upon return, result.success indicates success or failure.
    void parseKernelDump64(const DumpFileView& view, DumpParseResult& result);

    // parseKernelDump32 purpose: Parse 32-bit kernel dumps (signature PAGEDUMP), header information only.
    // Accepts a read-only file view (view) and an output structure (result); upon return, result.success indicates success or failure.
    void parseKernelDump32(const DumpFileView& view, DumpParseResult& result);
}

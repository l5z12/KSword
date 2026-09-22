#pragma once

// ============================================================
// MinidumpParser.Internal.h
// Purpose:
// - Internal shared header between MinidumpParser.cpp and MinidumpParser.Streams.cpp.
// - Declares parsing limit constants, generic formatting/read helper functions, and per-stream parsing functions;
// - For internal use by MinidumpDock implementation files only; not exposed externally.
// Call method:
// - Both implementation files include this header. Auxiliary functions are implemented in
//   `MinidumpParser.cpp`, and stream parsing functions are implemented in `MinidumpParser.Streams.cpp`.
// ============================================================

#include "DumpMemoryReader.h"
#include "DumpStackWalker.h"
#include "DumpSymbolIndex.h"
#include "MinidumpFormat.h"

// windows.h must be included before minidumpapiset.h (the latter depends on basic type definitions).
#include <windows.h>
#include <minidumpapiset.h>

namespace ks::minidump::detail
{
    // kMaxListEntries: Parsing limit for thread/module/handle lists to prevent malformed counts from crashing the UI.
    constexpr std::uint64_t kMaxListEntries = 100000;
    // kMaxMemoryRows: Maximum number of rows to fill in the memory region table; excess rows are counted but not displayed.
    constexpr std::uint64_t kMaxMemoryRows = 20000;
    // kMaxStringBytes: Maximum allowed bytes for a single MINIDUMP_STRING (defense against malformed lengths).
    constexpr std::uint32_t kMaxStringBytes = 64 * 1024;
    // kMaxCommentBytes: Maximum bytes to read from the comment stream to prevent overflow of the overview due to excessively long comments.
    constexpr std::uint32_t kMaxCommentBytes = 4096;

    // Hex function: Format an unsigned integer as uppercase hexadecimal text with a 0x prefix.
    // Accepts value: the numeric value; returns a string like 0x7FF6A1B2.
    QString hex(std::uint64_t value);

    // timeTToText: Converts a time_t second value to local time text.
    // Accepts secondsSince1970; returns text in yyyy-MM-dd HH:mm:ss format, or an empty string if the input is 0.
    QString timeTToText(std::uint64_t secondsSince1970);

    // byteCountText: Formats a byte count into readable text as 'value + unit'.
    // Input: byte count. Output: text like "1.5 MB (1572864 bytes)".
    QString byteCountText(std::uint64_t bytes);

    // readMinidumpString: Reads MINIDUMP_STRING (UTF-16) by RVA.
    // Pass view (file view) and rva (string location); returns decoded text, or empty string on invalid input.
    QString readMinidumpString(const DumpFileView& view, std::uint64_t rva);

    // findStream purpose: Locate the first stream of a specified type in the stream directory.
    // Pass view, directory parameters, and target type; returns true and outputs the location description if found.
    bool findStream(
        const DumpFileView& view,
        std::uint64_t directoryRva,
        std::uint32_t streamCount,
        std::uint32_t streamType,
        MINIDUMP_LOCATION_DESCRIPTOR* locationOut);

    // instructionPointerFromContext: extracts the instruction pointer from the thread CONTEXT according to the CPU architecture.
    // Pass view, context location, and SYSTEM_INFO architecture ID; returns 0 on failure.
    std::uint64_t instructionPointerFromContext(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& contextLocation,
        std::uint16_t architecture);

    // ================= Stream Parsing Functions (implementation in MinidumpParser.Streams.cpp) =================

    // parseSystemInfo: Parses SystemInfoStream and fills the overview.
    // Also output the architecture number for thread context parsing.
    void parseSystemInfo(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result,
        std::uint16_t* architectureOut);

    // parseMiscInfo: Parses all versions (v1..v4) of the MiscInfoStream:
    // Process ID/time, CPU frequency, integrity level, DEP policy, protected process status, time zone, and system build string.
    void parseMiscInfo(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseProcessVmCounters purpose: Parse ProcessVmCountersStream (22) to extract working set,
    // private bytes, and page file usage—critical data for diagnosing memory exhaustion crashes.
    void parseProcessVmCounters(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseExceptionStream purpose: Parses ExceptionStream to produce exception details and the crashing thread ID.
    // modules: Used to translate exception addresses to 'module name + offset'; the index must be built before calling.
    // contextLocationOut: Outputs the CONTEXT location of the crashed thread for register extraction.
    void parseExceptionStream(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        std::uint16_t architecture,
        const ModuleIndex& modules,
        DumpParseResult& result,
        std::uint32_t* faultingThreadIdOut,
        MINIDUMP_LOCATION_DESCRIPTOR* contextLocationOut);

    // parseThreadList purpose: Parse ThreadListStream/ThreadExListStream into a thread array.
    // modules: Used to annotate module ownership of thread instruction pointers.
    // scanInputsOut collects stack memory locations for each thread for subsequent call stack reconstruction.
    void parseThreadList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        bool isExtendedList,
        std::uint16_t architecture,
        std::uint32_t faultingThreadId,
        const ModuleIndex& modules,
        DumpParseResult& result,
        std::vector<StackScanInput>* scanInputsOut,
        DumpMemoryReader* memory);

    // parseThreadInfoList purpose: Merge the starting address and CPU time from ThreadInfoListStream into the thread table.
    void parseThreadInfoList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseThreadNames purpose: Merge thread names from ThreadNamesStream into the thread table.
    void parseThreadNames(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseModuleList purpose: Parse ModuleListStream into a module array (including version and PDB).
    void parseModuleList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseUnloadedModuleList purpose: Parse UnloadedModuleListStream.
    void parseUnloadedModuleList(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseMemoryLists purpose: Parse memory regions and build a virtual address index.
    // For display, the region table prioritizes MemoryInfoList by information density, followed by Memory64List/MemoryList;
    // The memory index can only come from the latter two sources—MemoryInfoList describes region attributes only and
    // contains no data, so the two paths must be kept separate and cannot return early after retrieving MemoryInfoList.
    void parseMemoryLists(
        const DumpFileView& view,
        std::uint64_t directoryRva,
        std::uint32_t streamCount,
        DumpParseResult& result,
        DumpMemoryReader* memory);

    // parseHandleData: Parses HandleDataStream into an array of handles.
    void parseHandleData(
        const DumpFileView& view,
        const MINIDUMP_LOCATION_DESCRIPTOR& location,
        DumpParseResult& result);

    // parseComments: Reads ANSI/Unicode comment streams and appends them to the overview.
    void parseComments(
        const DumpFileView& view,
        std::uint64_t directoryRva,
        std::uint32_t streamCount,
        DumpParseResult& result);

    // dumpTypeFlagText: Converts MINIDUMP_TYPE bit flags into a list of constant name strings.
    QString dumpTypeFlagText(std::uint64_t flags);
}

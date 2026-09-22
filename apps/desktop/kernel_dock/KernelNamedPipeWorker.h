#pragma once

// ============================================================
// KernelNamedPipeWorker.h
// Purpose:
// 1) Provide an R3 directory enumeration worker for Named Pipes;
// 2) Read named pipe entries via the NPFS file system directory;
// 3) Do not enumerate process handles, do not rely on R0 IOCTLs, and do not modify the shared/driver protocol.
// ============================================================

#include <QString>

#include <cstdint>
#include <vector>

// KernelNamedPipeEntry：
// - Input source: NPFS directory entries returned by NtQueryDirectoryFile;
// - Processing: The worker organizes the file name, attributes, timestamps, and source directory into fields ready for UI display.
// - Return behavior: Written to rowsOut by runKernelNamedPipeSnapshotTask; may be empty.
struct KernelNamedPipeEntry
{
    QString pipeName;             // pipeName: Pipe name, excluding the \Device\NamedPipe prefix.
    QString ntPath;               // ntPath: Full NT path, e.g., \Device\NamedPipe\InitShutdown.
    QString sourceDirectory;      // sourceDirectory: The candidate directory this line originates from.
    QString statusText;           // statusText: Single-line status, typically STATUS_SUCCESS.
    bool querySucceeded = false;  // querySucceeded: Whether this entry originates from a successful directory query.
    std::uint32_t attributes = 0; // attributes：FILE_DIRECTORY_INFORMATION.FileAttributes。
    QString attributesText;       // attributesText: Text representation of attribute bits.
    QString lastWriteTimeText;    // lastWriteTimeText: last write time; displays <Unavailable> if unavailable.
    std::int64_t lastWriteTime = 0; // lastWriteTime: Raw FILETIME value in 100ns units.
};

// KernelNamedPipeDirectoryStatus：
// - Input source: One NtOpenFile/NtQueryDirectoryFile attempt per candidate directory;
// - Processing logic: Log open, query, returned row count, and final NTSTATUS.
// - Return behavior: Used to display path candidates and failure reasons in the details panel.
struct KernelNamedPipeDirectoryStatus
{
    QString candidatePath;          // candidatePath: NT path to attempt opening.
    QString statusText;             // statusText: Formatted NTSTATUS or diagnostic text.
    bool openSucceeded = false;     // openSucceeded: Whether NtOpenFile succeeded.
    bool querySucceeded = false;    // querySucceeded: indicates whether NtQueryDirectoryFile completed fully to STATUS_NO_MORE_FILES.
    std::uint32_t lastStatus = 0;   // lastStatus: Unsigned view of the last NTSTATUS.
    std::size_t returnedRows = 0;   // returnedRows: Number of entries returned by the candidate directory.
};

// KernelNamedPipeSnapshot：
// - Input source: runKernelNamedPipeSnapshotTask aggregates all candidate paths;
// - Logic: Aggregate deduplicated pipe rows and the status of each candidate path.
// - Return behavior: UI determines status color and message based on taskSucceeded/anyQuerySucceeded.
struct KernelNamedPipeSnapshot
{
    std::vector<KernelNamedPipeEntry> rows;                  // rows: Deduplicated list of named pipes.
    std::vector<KernelNamedPipeDirectoryStatus> directories; // directories: List of candidate path statuses.
    QString summaryText;                                     // summaryText: Summary suitable for status bar display.
    QString errorText;                                       // errorText: Fatal error, e.g., missing ntdll entry point.
    bool taskSucceeded = false;                              // taskSucceeded: Whether the worker completed the task.
    bool anyQuerySucceeded = false;                          // anyQuerySucceeded: Whether at least one candidate directory enumeration succeeded.
    std::uint64_t elapsedMs = 0;                              // elapsedMs: Background elapsed time.
};

// runKernelNamedPipeSnapshotTask：
// - Input: No explicit input; the worker uses the fixed candidate path \Device\NamedPipe and equivalent paths internally;
// - Processing logic: Dynamically resolve NtOpenFile/NtQueryDirectoryFile to enumerate named pipes via NPFS file directory.
// - Return: KernelNamedPipeSnapshot, containing rows, candidate status, elapsed time, and error text.
KernelNamedPipeSnapshot runKernelNamedPipeSnapshotTask();

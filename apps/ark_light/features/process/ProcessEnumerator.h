#pragma once

#include "../../core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ksword::features::process {

// ProcessSnapshotRow is the raw R3 process record produced from
// NtQuerySystemInformation(SystemProcessInformation). Inputs are kernel-returned
// SYSTEM_PROCESS_INFORMATION fields plus optional Win32 image-path enrichment;
// consumers should treat each row as a point-in-time snapshot.
struct ProcessSnapshotRow {
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    ULONG handleCount = 0;
    ULONG sessionId = 0;
    ULONG threadCount = 0;
    LONG basePriority = 0;
    ULONGLONG kernelTime100ns = 0;
    ULONGLONG userTime100ns = 0;
    ULONGLONG cycleTime = 0;
    // creationTime100ns distinguishes a recycled PID from the snapshot process instance.
    ULONGLONG creationTime100ns = 0;
    SIZE_T workingSetBytes = 0;
    // peakWorkingSetBytes: Peak working set from NtQuery snapshot, used for the "Memory" column display.
    SIZE_T peakWorkingSetBytes = 0;
    SIZE_T privatePageBytes = 0;
    SIZE_T virtualSizeBytes = 0;
    // Usage of commitBytes/pagedPoolBytes/nonPagedPoolBytes: Original memory statistics from SystemProcessInformation.
    SIZE_T commitBytes = 0;
    SIZE_T pagedPoolBytes = 0;
    SIZE_T nonPagedPoolBytes = 0;
    ULONG pageFaultCount = 0;
    // Purpose of workingSetDeltaBytes/pageFaultDelta: Dynamic memory increments calculated from adjacent snapshots.
    LONGLONG workingSetDeltaBytes = 0;
    LONGLONG pageFaultDelta = 0;
    // I/O counts and transfer volumes are sourced from SystemProcessInformation to avoid per-process handle queries.
    ULONGLONG ioReadOperations = 0;
    ULONGLONG ioWriteOperations = 0;
    ULONGLONG ioOtherOperations = 0;
    ULONGLONG ioReadBytes = 0;
    ULONGLONG ioWriteBytes = 0;
    ULONGLONG ioOtherBytes = 0;
    double cpuUsagePercent = 0.0;
    std::wstring imageName;
    std::wstring imagePath;
    std::uintptr_t r0ProcessObjectAddress = 0;
    ULONG r0SourceMask = 0;
    ULONG r0AnomalyFlags = 0;
    ULONG r0Confidence = 0;
    // r0KernelOnly: Marks that this line is returned only by R0 enumeration and is not visible in the R3 public list.
    bool r0KernelOnly = false;
    // r0EnumFlags/r0EnumStatus purpose: Stores flags/status from the R0 process enumeration protocol for hidden process diagnosis and highlighting.
    std::uint32_t r0EnumFlags = 0;
    std::uint32_t r0EnumStatus = 0;
    // r0EnumImagePath: Stores the image path read by R0; serves as diagnostic evidence when R3 lacks a path or a synthetic hidden row is present.
    std::wstring r0EnumImagePath;
    std::wstring r0AuditSummary;
    std::wstring r0AuditDetail;
    // detailTexts usage: stores extended column text collected on-demand from the main process library; the key is the integer value of ProcessColumnId.
    std::unordered_map<std::uint8_t, std::wstring> detailTexts;
};

// ProcessEnumerationResult groups all rows from one enumeration pass. success is
// false only for fatal NtApi failures; partial per-process enrichment failures
// leave individual imagePath fields empty and keep success true.
struct ProcessEnumerationResult {
    bool success = false;
    LONG ntStatus = 0;
    std::wstring diagnosticText;
    std::vector<ProcessSnapshotRow> rows;
};

// enumerateProcessesByNtQuerySystemInformation queries the system process list
// using dynamically-bound NtQuerySystemInformation. Inputs: none. Processing:
// grow a raw buffer, parse SYSTEM_PROCESS_INFORMATION entries, and enrich image
// paths through QueryFullProcessImageNameW when permissions allow. Return value:
// a ProcessEnumerationResult containing rows or a fatal diagnostic.
ProcessEnumerationResult enumerateProcessesByNtQuerySystemInformation();

// queryProcessImagePath opens one process with PROCESS_QUERY_LIMITED_INFORMATION
// and queries its full executable path. Input is a PID. Processing is best-effort
// and never terminates or modifies the target process. Return value is an empty
// string when access is denied, PID is invalid, or the image path is unavailable.
std::wstring queryProcessImagePath(DWORD processId);

} // namespace Ksword::Features::Process

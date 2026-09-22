#pragma once

// ============================================================
// ProcessColumns.h
// Purpose: Define stable column IDs, column groups, and view presets for the ARKLight process list.
// All list, filter, and column selection UIs operate via the description table in this file to avoid scattered column indices.
// ============================================================

#include "ProcessEnumerator.h"

#include <commctrl.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::features::process {

// ProcessColumnGroup usage: Provide semantic grouping for the 'Select Columns' window and header menu.
enum class ProcessColumnGroup : std::uint8_t {
    kGeneral,
    kPerformance,
    kMemory,
    kIo,
    kSecurity,
    kKernel
};

// ProcessColumnId usage: Stable logical column identifiers for the process table; do not rely on their display order.
enum class ProcessColumnId : std::uint8_t {
    kName, kPid, kParentPid, kPath, kCommandLine, kUser, kStartTime, kSessionId, kStatus, kDescription, kProcessType,
    kCpu, kCpuTime, kCycleTime, kDisk, kGpu, kNet, kThreadCount, kBasePriority, kPowerThrottling, kGpuEngine, kGpuDedicatedMemory, kGpuSharedMemory,
    kWorkingSet, kPeakWorkingSet, kWorkingSetDelta, kPrivateWorkingSet, kVirtualMemory, kCommitSize, kPagedPool, kNonPagedPool, kPageFaults, kPageFaultDelta,
    kIoReads, kIoWrites, kIoOther, kIoReadBytes, kIoWriteBytes, kIoOtherBytes,
    kSignature, kIsAdmin, kPplLevel, kUacVirtualization, kDataExecutionPrevention, kControlFlowGuard, kHardwareStackProtection, kPackageName, kDpiAwareness, kEnterpriseContext, kJobObject,
    kProtection, kPpl, kHandleCount, kHandleTable, kSectionObject, kR0Status, kEprocess, kR0Source, kR0Anomaly,
    kCount
};

// ProcessViewPreset usage: Built-in column presets; Custom represents the current layout modified by the user.
enum class ProcessViewPreset : std::uint8_t {
    kMonitor, kDetail, kMemory, kDiskIo, kGpu, kSecurity, kKernel, kCustom
};

// ProcessColumnDescriptor purpose: Describes a column's title, group, width, and ListView alignment.
struct ProcessColumnDescriptor {
    ProcessColumnId id;
    ProcessColumnGroup group;
    const wchar_t* title;
    int width;
    int format;
    bool locked;
};

const std::vector<ProcessColumnDescriptor>& processColumnDescriptors();
const ProcessColumnDescriptor* findProcessColumn(ProcessColumnId id);
std::vector<ProcessColumnId> defaultProcessColumns(ProcessViewPreset preset);
const wchar_t* processViewPresetTitle(ProcessViewPreset preset);
const wchar_t* processColumnGroupTitle(ProcessColumnGroup group);
std::wstring processColumnText(const ProcessSnapshotRow& row, ProcessColumnId column);

} // namespace Ksword::Features::Process

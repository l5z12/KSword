#include "ProcessColumns.h"

#include <array>
#include <cwchar>

namespace ksword::features::process {
namespace {

// numberText purpose: Formats an unsigned count into text directly displayable by a ListView.
std::wstring numberText(ULONGLONG value) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%llu", static_cast<unsigned long long>(value));
    return buffer;
}

// bytesText: Converts byte counts to compact capacity text to avoid unreadable large integers in tables.
std::wstring bytesText(ULONGLONG value) {
    const wchar_t* suffixes[] = { L"B", L"KiB", L"MiB", L"GiB", L"TiB" };
    double display = static_cast<double>(value);
    int suffix = 0;
    while (display >= 1024.0 && suffix < 4) { display /= 1024.0; ++suffix; }
    wchar_t buffer[64]{};
    if (suffix == 0) {
        ::swprintf_s(buffer, L"%llu %s", static_cast<unsigned long long>(value), suffixes[suffix]);
    } else {
        ::swprintf_s(buffer, L"%.1f %s", display, suffixes[suffix]);
    }
    return buffer;
}

// TimeText purpose: Convert 100ns cumulative CPU time to seconds, suitable for task manager-style process tables.
std::wstring timeText(ULONGLONG time100ns) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"%.2f s", static_cast<double>(time100ns) / 10000000.0);
    return buffer;
}

const std::vector<ProcessColumnDescriptor> kColumns = {
    { ProcessColumnId::kName, ProcessColumnGroup::kGeneral, L"进程", 250, LVCFMT_LEFT, true },
    { ProcessColumnId::kPid, ProcessColumnGroup::kGeneral, L"PID", 78, LVCFMT_RIGHT, true },
    { ProcessColumnId::kParentPid, ProcessColumnGroup::kGeneral, L"父 PID", 78, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPath, ProcessColumnGroup::kGeneral, L"映像路径", 380, LVCFMT_LEFT, false },
    { ProcessColumnId::kCommandLine, ProcessColumnGroup::kGeneral, L"命令行", 360, LVCFMT_LEFT, false },
    { ProcessColumnId::kUser, ProcessColumnGroup::kGeneral, L"用户", 140, LVCFMT_LEFT, false },
    { ProcessColumnId::kStartTime, ProcessColumnGroup::kGeneral, L"启动时间", 150, LVCFMT_LEFT, false },
    { ProcessColumnId::kSessionId, ProcessColumnGroup::kGeneral, L"会话", 70, LVCFMT_RIGHT, false },
    { ProcessColumnId::kStatus, ProcessColumnGroup::kGeneral, L"状态", 95, LVCFMT_LEFT, false },
    { ProcessColumnId::kDescription, ProcessColumnGroup::kGeneral, L"描述", 200, LVCFMT_LEFT, false },
    { ProcessColumnId::kProcessType, ProcessColumnGroup::kGeneral, L"类型", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::kCpu, ProcessColumnGroup::kPerformance, L"CPU", 74, LVCFMT_RIGHT, false },
    { ProcessColumnId::kCpuTime, ProcessColumnGroup::kPerformance, L"CPU 时间", 105, LVCFMT_RIGHT, false },
    { ProcessColumnId::kCycleTime, ProcessColumnGroup::kPerformance, L"周期", 125, LVCFMT_RIGHT, false },
    { ProcessColumnId::kDisk, ProcessColumnGroup::kPerformance, L"磁盘", 90, LVCFMT_RIGHT, false },
    { ProcessColumnId::kGpu, ProcessColumnGroup::kPerformance, L"GPU", 74, LVCFMT_RIGHT, false },
    { ProcessColumnId::kNet, ProcessColumnGroup::kPerformance, L"网络", 90, LVCFMT_RIGHT, false },
    { ProcessColumnId::kThreadCount, ProcessColumnGroup::kPerformance, L"线程", 70, LVCFMT_RIGHT, false },
    { ProcessColumnId::kBasePriority, ProcessColumnGroup::kPerformance, L"基础优先级", 95, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPowerThrottling, ProcessColumnGroup::kPerformance, L"效率模式", 95, LVCFMT_LEFT, false },
    { ProcessColumnId::kGpuEngine, ProcessColumnGroup::kPerformance, L"GPU 引擎", 140, LVCFMT_LEFT, false },
    { ProcessColumnId::kGpuDedicatedMemory, ProcessColumnGroup::kPerformance, L"专用 GPU 内存", 125, LVCFMT_RIGHT, false },
    { ProcessColumnId::kGpuSharedMemory, ProcessColumnGroup::kPerformance, L"共享 GPU 内存", 125, LVCFMT_RIGHT, false },
    { ProcessColumnId::kWorkingSet, ProcessColumnGroup::kMemory, L"工作集", 110, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPeakWorkingSet, ProcessColumnGroup::kMemory, L"峰值工作集", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::kWorkingSetDelta, ProcessColumnGroup::kMemory, L"工作集增量", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPrivateWorkingSet, ProcessColumnGroup::kMemory, L"专用工作集", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::kVirtualMemory, ProcessColumnGroup::kMemory, L"虚拟内存", 118, LVCFMT_RIGHT, false },
    { ProcessColumnId::kCommitSize, ProcessColumnGroup::kMemory, L"提交大小", 110, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPagedPool, ProcessColumnGroup::kMemory, L"分页池", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::kNonPagedPool, ProcessColumnGroup::kMemory, L"非分页池", 105, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPageFaults, ProcessColumnGroup::kMemory, L"页面错误", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::kPageFaultDelta, ProcessColumnGroup::kMemory, L"页面错误增量", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::kIoReads, ProcessColumnGroup::kIo, L"I/O 读取", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::kIoWrites, ProcessColumnGroup::kIo, L"I/O 写入", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::kIoOther, ProcessColumnGroup::kIo, L"I/O 其他", 100, LVCFMT_RIGHT, false },
    { ProcessColumnId::kIoReadBytes, ProcessColumnGroup::kIo, L"I/O 读取字节", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::kIoWriteBytes, ProcessColumnGroup::kIo, L"I/O 写入字节", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::kIoOtherBytes, ProcessColumnGroup::kIo, L"I/O 其他字节", 120, LVCFMT_RIGHT, false },
    { ProcessColumnId::kSignature, ProcessColumnGroup::kSecurity, L"数字签名", 120, LVCFMT_LEFT, false },
    { ProcessColumnId::kIsAdmin, ProcessColumnGroup::kSecurity, L"管理员", 82, LVCFMT_LEFT, false },
    { ProcessColumnId::kPplLevel, ProcessColumnGroup::kSecurity, L"PPL 级别", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::kUacVirtualization, ProcessColumnGroup::kSecurity, L"UAC 虚拟化", 105, LVCFMT_LEFT, false },
    { ProcessColumnId::kDataExecutionPrevention, ProcessColumnGroup::kSecurity, L"DEP", 85, LVCFMT_LEFT, false },
    { ProcessColumnId::kControlFlowGuard, ProcessColumnGroup::kSecurity, L"CFG", 85, LVCFMT_LEFT, false },
    { ProcessColumnId::kHardwareStackProtection, ProcessColumnGroup::kSecurity, L"硬件堆栈保护", 130, LVCFMT_LEFT, false },
    { ProcessColumnId::kPackageName, ProcessColumnGroup::kSecurity, L"程序包名称", 220, LVCFMT_LEFT, false },
    { ProcessColumnId::kDpiAwareness, ProcessColumnGroup::kSecurity, L"DPI 感知", 115, LVCFMT_LEFT, false },
    { ProcessColumnId::kEnterpriseContext, ProcessColumnGroup::kSecurity, L"企业上下文", 110, LVCFMT_LEFT, false },
    { ProcessColumnId::kJobObject, ProcessColumnGroup::kSecurity, L"作业对象", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::kProtection, ProcessColumnGroup::kKernel, L"保护状态", 115, LVCFMT_LEFT, false },
    { ProcessColumnId::kPpl, ProcessColumnGroup::kKernel, L"PPL", 70, LVCFMT_LEFT, false },
    { ProcessColumnId::kHandleCount, ProcessColumnGroup::kKernel, L"句柄", 85, LVCFMT_RIGHT, false },
    { ProcessColumnId::kHandleTable, ProcessColumnGroup::kKernel, L"对象表", 95, LVCFMT_LEFT, false },
    { ProcessColumnId::kSectionObject, ProcessColumnGroup::kKernel, L"SectionObject", 125, LVCFMT_LEFT, false },
    { ProcessColumnId::kR0Status, ProcessColumnGroup::kKernel, L"R0 状态", 100, LVCFMT_LEFT, false },
    { ProcessColumnId::kEprocess, ProcessColumnGroup::kKernel, L"EPROCESS", 150, LVCFMT_RIGHT, false },
    { ProcessColumnId::kR0Source, ProcessColumnGroup::kKernel, L"R0 来源", 150, LVCFMT_LEFT, false },
    { ProcessColumnId::kR0Anomaly, ProcessColumnGroup::kKernel, L"R0 异常", 180, LVCFMT_LEFT, false },
};

} // namespace

const std::vector<ProcessColumnDescriptor>& processColumnDescriptors() { return kColumns; }
const ProcessColumnDescriptor* findProcessColumn(ProcessColumnId id) {
    for (const auto& column : kColumns) if (column.id == id) return &column;
    return nullptr;
}

std::vector<ProcessColumnId> defaultProcessColumns(ProcessViewPreset preset) {
    using C = ProcessColumnId;
    switch (preset) {
    case ProcessViewPreset::kDetail: return { C::kName, C::kPid, C::kParentPid, C::kPath, C::kCommandLine, C::kUser, C::kStartTime, C::kSessionId, C::kStatus, C::kSignature };
    case ProcessViewPreset::kMemory: return { C::kName, C::kPid, C::kWorkingSet, C::kPeakWorkingSet, C::kWorkingSetDelta, C::kPrivateWorkingSet, C::kVirtualMemory, C::kCommitSize, C::kPagedPool, C::kNonPagedPool, C::kPageFaults, C::kPageFaultDelta };
    case ProcessViewPreset::kDiskIo: return { C::kName, C::kPid, C::kDisk, C::kIoReads, C::kIoWrites, C::kIoOther, C::kIoReadBytes, C::kIoWriteBytes, C::kIoOtherBytes };
    case ProcessViewPreset::kGpu: return { C::kName, C::kPid, C::kGpu, C::kGpuEngine, C::kGpuDedicatedMemory, C::kGpuSharedMemory, C::kCpu, C::kWorkingSet };
    case ProcessViewPreset::kSecurity: return { C::kName, C::kPid, C::kSignature, C::kIsAdmin, C::kPplLevel, C::kUacVirtualization, C::kDataExecutionPrevention, C::kControlFlowGuard, C::kHardwareStackProtection, C::kPackageName, C::kDpiAwareness, C::kJobObject };
    case ProcessViewPreset::kKernel: return { C::kName, C::kPid, C::kProtection, C::kPpl, C::kHandleCount, C::kHandleTable, C::kSectionObject, C::kR0Status, C::kEprocess, C::kR0Source, C::kR0Anomaly };
    case ProcessViewPreset::kMonitor:
    case ProcessViewPreset::kCustom:
    default: return { C::kName, C::kPid, C::kCpu, C::kWorkingSet, C::kPrivateWorkingSet, C::kVirtualMemory, C::kThreadCount, C::kSessionId, C::kPageFaults };
    }
}

const wchar_t* processViewPresetTitle(ProcessViewPreset preset) {
    switch (preset) { case ProcessViewPreset::kMonitor: return L"监视"; case ProcessViewPreset::kDetail: return L"详细"; case ProcessViewPreset::kMemory: return L"内存"; case ProcessViewPreset::kDiskIo: return L"磁盘 I/O"; case ProcessViewPreset::kGpu: return L"GPU"; case ProcessViewPreset::kSecurity: return L"安全"; case ProcessViewPreset::kKernel: return L"内核"; default: return L"自定义"; }
}
const wchar_t* processColumnGroupTitle(ProcessColumnGroup group) {
    switch (group) { case ProcessColumnGroup::kGeneral: return L"常规"; case ProcessColumnGroup::kPerformance: return L"性能"; case ProcessColumnGroup::kMemory: return L"内存"; case ProcessColumnGroup::kIo: return L"磁盘 I/O"; case ProcessColumnGroup::kSecurity: return L"安全与策略"; default: return L"内核扩展"; }
}

std::wstring processColumnText(const ProcessSnapshotRow& row, ProcessColumnId column) {
    using C = ProcessColumnId;
    const auto kCollected = row.detailTexts.find(static_cast<std::uint8_t>(column));
    if (kCollected != row.detailTexts.end()) return kCollected->second;
    switch (column) {
    case C::kName: return row.imageName; case C::kPid: return numberText(row.processId); case C::kParentPid: return numberText(row.parentProcessId); case C::kPath: return row.imagePath.empty() ? L"<访问被拒绝>" : row.imagePath; case C::kSessionId: return numberText(row.sessionId); case C::kThreadCount: return numberText(row.threadCount); case C::kBasePriority: return numberText(row.basePriority); case C::kCpu: { wchar_t b[32]{}; ::swprintf_s(b, L"%.1f%%", row.cpuUsagePercent); return b; }
    case C::kCpuTime: return timeText(row.kernelTime100ns + row.userTime100ns); case C::kCycleTime: return numberText(row.cycleTime); case C::kWorkingSet: return bytesText(row.workingSetBytes); case C::kPeakWorkingSet: return bytesText(row.peakWorkingSetBytes); case C::kWorkingSetDelta: return (row.workingSetDeltaBytes >= 0 ? L"+" : L"") + bytesText(static_cast<ULONGLONG>(row.workingSetDeltaBytes >= 0 ? row.workingSetDeltaBytes : -row.workingSetDeltaBytes)); case C::kPrivateWorkingSet: return bytesText(row.privatePageBytes); case C::kVirtualMemory: return bytesText(row.virtualSizeBytes); case C::kCommitSize: return bytesText(row.commitBytes); case C::kPagedPool: return bytesText(row.pagedPoolBytes); case C::kNonPagedPool: return bytesText(row.nonPagedPoolBytes); case C::kPageFaults: return numberText(row.pageFaultCount); case C::kPageFaultDelta: return (row.pageFaultDelta >= 0 ? L"+" : L"") + numberText(static_cast<ULONGLONG>(row.pageFaultDelta >= 0 ? row.pageFaultDelta : -row.pageFaultDelta)); case C::kIoReads: return numberText(row.ioReadOperations); case C::kIoWrites: return numberText(row.ioWriteOperations); case C::kIoOther: return numberText(row.ioOtherOperations); case C::kIoReadBytes: return bytesText(row.ioReadBytes); case C::kIoWriteBytes: return bytesText(row.ioWriteBytes); case C::kIoOtherBytes: return bytesText(row.ioOtherBytes); case C::kHandleCount: return numberText(row.handleCount); case C::kEprocess: { wchar_t b[32]{}; ::swprintf_s(b, L"0x%0*llX", sizeof(void*) == 8 ? 16 : 8, static_cast<unsigned long long>(row.r0ProcessObjectAddress)); return row.r0ProcessObjectAddress ? b : L"-"; }
    case C::kR0Source: return row.r0AuditSummary.empty() ? L"不可用" : row.r0AuditSummary; case C::kR0Anomaly: return row.r0AuditDetail.empty() ? L"-" : row.r0AuditDetail; case C::kR0Status: return row.r0KernelOnly ? L"仅 R0" : (row.r0AuditSummary.empty() ? L"不可用" : L"已审计"); case C::kProcessType: return row.r0KernelOnly ? L"仅内核" : L"进程"; case C::kStatus: return L"运行中";
    default: return L"不可用";
    }
}

} // namespace Ksword::Features::Process

#include "PerformanceSampler.h"

#include <pdh.h>
#include <pdhmsg.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <map>
#include <utility>

// PDH is not in the project-wide link line because this is the only module that
// samples performance counters. Declaring the dependency here keeps the addition
// next to the code that needs it.
#pragma comment(lib, "Pdh.lib")

namespace ksword::features::hardware_stats {
namespace {

// Rate counters are a delta between two collections, so the first collection
// only establishes a baseline. Waiting one interval before the second one is
// what makes the very first table the user sees carry real numbers instead of a
// column of dashes that silently fills in a second later.
constexpr DWORD kPrimingIntervalMs = 1000;

// MetricFormat picks the renderer for one scalar counter.
enum class MetricFormat {
    kPercent,
    kBytes,
    kMegabytesAsBytes,   // PDH reports Available MBytes; the table shows bytes.
    kBytesPerSecond,
    kCount,
    kRate,
    kDecimal,
    kUpTime
};

enum class SystemCounterId {
    kCpuTotal,
    kCpuUser,
    kCpuPrivileged,
    kCpuInterrupts,
    kCpuDpcQueued,
    kMemAvailable,
    kMemCommitted,
    kMemCommitLimit,
    kMemCommitPercent,
    kMemCache,
    kMemPoolPaged,
    kMemPoolNonpaged,
    kMemPagesPerSecond,
    kMemPageFaults,
    kDiskCurrentQueue,
    kDiskAverageQueue,
    kDiskBusyPercent,
    kDiskReadBytes,
    kDiskWriteBytes,
    kDiskReads,
    kDiskWrites,
    kSystemProcesses,
    kSystemThreads,
    kSystemContextSwitches,
    kSystemUpTime,
    kCount
};

// ScalarCounterSpec is one non-wildcard counter and how to display it. The
// alternate path exists because "Processor Information" replaced "Processor" as
// the correct object on machines with processor groups, while the older object
// is still the only one present in some virtualized guests.
struct ScalarCounterSpec {
    const wchar_t* path;
    const wchar_t* alternatePath;
    const wchar_t* group;
    const wchar_t* name;
    MetricFormat format;
    bool uncapped;
};

const std::array<ScalarCounterSpec, static_cast<std::size_t>(SystemCounterId::kCount)>& scalarSpecs() {
    static const std::array<ScalarCounterSpec, static_cast<std::size_t>(SystemCounterId::kCount)> kSpecs = { {
        { L"\\Processor Information(_Total)\\% Processor Time", L"\\Processor(_Total)\\% Processor Time",
          L"CPU", L"总占用率", MetricFormat::kPercent, false },
        { L"\\Processor Information(_Total)\\% User Time", L"\\Processor(_Total)\\% User Time",
          L"CPU", L"用户态占用率", MetricFormat::kPercent, false },
        { L"\\Processor Information(_Total)\\% Privileged Time", L"\\Processor(_Total)\\% Privileged Time",
          L"CPU", L"内核态占用率", MetricFormat::kPercent, false },
        { L"\\Processor Information(_Total)\\Interrupts/sec", L"\\Processor(_Total)\\Interrupts/sec",
          L"CPU", L"中断速率", MetricFormat::kRate, false },
        { L"\\Processor Information(_Total)\\DPCs Queued/sec", L"\\Processor(_Total)\\DPCs Queued/sec",
          L"CPU", L"DPC 入队速率", MetricFormat::kRate, false },

        { L"\\Memory\\Available MBytes", nullptr, L"内存", L"可用物理内存", MetricFormat::kMegabytesAsBytes, false },
        { L"\\Memory\\Committed Bytes", nullptr, L"内存", L"已提交内存", MetricFormat::kBytes, false },
        { L"\\Memory\\Commit Limit", nullptr, L"内存", L"提交上限", MetricFormat::kBytes, false },
        { L"\\Memory\\% Committed Bytes In Use", nullptr, L"内存", L"提交使用率", MetricFormat::kPercent, false },
        { L"\\Memory\\Cache Bytes", nullptr, L"内存", L"系统缓存", MetricFormat::kBytes, false },
        { L"\\Memory\\Pool Paged Bytes", nullptr, L"内存", L"分页池", MetricFormat::kBytes, false },
        { L"\\Memory\\Pool Nonpaged Bytes", nullptr, L"内存", L"非分页池", MetricFormat::kBytes, false },
        { L"\\Memory\\Pages/sec", nullptr, L"内存", L"页面调度速率", MetricFormat::kRate, false },
        { L"\\Memory\\Page Faults/sec", nullptr, L"内存", L"缺页速率", MetricFormat::kRate, false },

        { L"\\PhysicalDisk(_Total)\\Current Disk Queue Length", nullptr, L"磁盘", L"当前队列长度", MetricFormat::kDecimal, false },
        { L"\\PhysicalDisk(_Total)\\Avg. Disk Queue Length", nullptr, L"磁盘", L"平均队列长度", MetricFormat::kDecimal, false },
        { L"\\PhysicalDisk(_Total)\\% Disk Time", nullptr, L"磁盘", L"磁盘忙碌比例", MetricFormat::kPercent, true },
        { L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", nullptr, L"磁盘", L"读取吞吐", MetricFormat::kBytesPerSecond, false },
        { L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", nullptr, L"磁盘", L"写入吞吐", MetricFormat::kBytesPerSecond, false },
        { L"\\PhysicalDisk(_Total)\\Disk Reads/sec", nullptr, L"磁盘", L"读取 IOPS", MetricFormat::kRate, false },
        { L"\\PhysicalDisk(_Total)\\Disk Writes/sec", nullptr, L"磁盘", L"写入 IOPS", MetricFormat::kRate, false },

        { L"\\System\\Processes", nullptr, L"系统", L"进程数", MetricFormat::kCount, false },
        { L"\\System\\Threads", nullptr, L"系统", L"线程数", MetricFormat::kCount, false },
        { L"\\System\\Context Switches/sec", nullptr, L"系统", L"上下文切换速率", MetricFormat::kRate, false },
        { L"\\System\\System Up Time", nullptr, L"系统", L"系统运行时间", MetricFormat::kUpTime, false },
    } };
    return kSpecs;
}

enum class DiskCounterId {
    kReadBytes,
    kWriteBytes,
    kReads,
    kWrites,
    kCurrentQueue,
    kAverageQueue,
    kBusyPercent,
    kReadLatency,
    kWriteLatency,
    kCount
};

const std::array<const wchar_t*, static_cast<std::size_t>(DiskCounterId::kCount)>& diskCounterPaths() {
    static const std::array<const wchar_t*, static_cast<std::size_t>(DiskCounterId::kCount)> kPaths = { {
        L"\\PhysicalDisk(*)\\Disk Read Bytes/sec",
        L"\\PhysicalDisk(*)\\Disk Write Bytes/sec",
        L"\\PhysicalDisk(*)\\Disk Reads/sec",
        L"\\PhysicalDisk(*)\\Disk Writes/sec",
        L"\\PhysicalDisk(*)\\Current Disk Queue Length",
        L"\\PhysicalDisk(*)\\Avg. Disk Queue Length",
        L"\\PhysicalDisk(*)\\% Disk Time",
        L"\\PhysicalDisk(*)\\Avg. Disk sec/Read",
        L"\\PhysicalDisk(*)\\Avg. Disk sec/Write",
    } };
    return kPaths;
}

std::wstring toLowerCopy(const std::wstring& text) {
    std::wstring lowered = text;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return lowered;
}

// englishCounterIndexMap reads the English perflib name table exactly once.
//
// Perflib stores its name tables per language under a numeric subkey, and 009 is
// always US English regardless of the installed UI language. The table alternates
// index and name, so it gives the English-name-to-index direction that
// PdhLookupPerfNameByIndexW cannot provide on its own. This is the only way to
// reach a localized counter name without hard-coding counter indexes, which are
// not contractually stable across Windows releases.
const std::map<std::wstring, DWORD>& englishCounterIndexMap() {
    static const std::map<std::wstring, DWORD> kTable = []() -> std::map<std::wstring, DWORD> {
        std::map<std::wstring, DWORD> result;
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib\\009",
                0,
                KEY_QUERY_VALUE,
                &key) != ERROR_SUCCESS) {
            return result;
        }

        DWORD type = 0;
        DWORD bytes = 0;
        if (::RegQueryValueExW(key, L"Counter", nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
            type != REG_MULTI_SZ || bytes < sizeof(wchar_t)) {
            ::RegCloseKey(key);
            return result;
        }

        std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 2, L'\0');
        if (::RegQueryValueExW(key, L"Counter", nullptr, &type,
                reinterpret_cast<LPBYTE>(buffer.data()), &bytes) != ERROR_SUCCESS) {
            ::RegCloseKey(key);
            return result;
        }
        ::RegCloseKey(key);

        const wchar_t* cursor = buffer.data();
        const wchar_t* end = buffer.data() + buffer.size();
        while (cursor < end && *cursor) {
            const std::wstring kIndexText(cursor);
            cursor += kIndexText.size() + 1;
            if (cursor >= end || !*cursor) {
                break;
            }
            const std::wstring kName(cursor);
            cursor += kName.size() + 1;

            wchar_t* parseEnd = nullptr;
            const unsigned long kIndex = std::wcstoul(kIndexText.c_str(), &parseEnd, 10);
            if (kIndex == 0 || parseEnd == kIndexText.c_str() || kName.empty()) {
                continue;
            }
            // Perflib repeats some names across indexes; the first entry wins so
            // the mapping stays deterministic between runs.
            result.emplace(toLowerCopy(kName), static_cast<DWORD>(kIndex));
        }
        return result;
    }();
    return kTable;
}

// localizedPerfName translates one English object or counter name into the name
// the local machine actually publishes. Output is empty when the name is unknown
// to perflib, which is the signal to abandon the fallback rather than build a
// half-translated path.
std::wstring localizedPerfName(const std::wstring& englishName) {
    const auto& table = englishCounterIndexMap();
    const auto kFound = table.find(toLowerCopy(englishName));
    if (kFound == table.end()) {
        return {};
    }

    DWORD size = 0;
    ::PdhLookupPerfNameByIndexW(nullptr, kFound->second, nullptr, &size);
    if (size == 0) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(size) + 1, L'\0');
    if (::PdhLookupPerfNameByIndexW(nullptr, kFound->second, buffer.data(), &size) != ERROR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

// splitCounterPath breaks "\Object(Instance)\Counter" into its parts. Output is
// false for anything that is not a two-segment local counter path, which is all
// this module ever builds.
bool splitCounterPath(const std::wstring& path,
    std::wstring& objectName,
    std::wstring& instanceName,
    std::wstring& counterName) {
    if (path.size() < 4 || path.front() != L'\\') {
        return false;
    }
    const std::size_t kLastSeparator = path.rfind(L'\\');
    if (kLastSeparator == 0 || kLastSeparator + 1 >= path.size()) {
        return false;
    }

    counterName = path.substr(kLastSeparator + 1);
    std::wstring objectPart = path.substr(1, kLastSeparator - 1);
    instanceName.clear();
    if (!objectPart.empty() && objectPart.back() == L')') {
        const std::size_t kOpen = objectPart.find(L'(');
        if (kOpen != std::wstring::npos) {
            instanceName = objectPart.substr(kOpen + 1, objectPart.size() - kOpen - 2);
            objectPart = objectPart.substr(0, kOpen);
        }
    }
    objectName = objectPart;
    return !objectName.empty() && !counterName.empty();
}

// localizeCounterPath rebuilds an English path in the machine's own language.
// Instance names are deliberately left alone: perflib localizes object and
// counter names but instances such as "_Total", "0 C:" or an adapter description
// are data, not translatable resources.
std::wstring localizeCounterPath(const std::wstring& englishPath) {
    std::wstring objectName;
    std::wstring instanceName;
    std::wstring counterName;
    if (!splitCounterPath(englishPath, objectName, instanceName, counterName)) {
        return {};
    }

    std::wstring localizedObject = localizedPerfName(objectName);
    std::wstring localizedCounter = localizedPerfName(counterName);
    if (localizedObject.empty() || localizedCounter.empty()) {
        return {};
    }

    PDH_COUNTER_PATH_ELEMENTS_W elements{};
    elements.szMachineName = nullptr;
    elements.szObjectName = localizedObject.data();
    elements.szInstanceName = instanceName.empty() ? nullptr : instanceName.data();
    elements.szParentInstance = nullptr;
    elements.dwInstanceIndex = static_cast<DWORD>(-1);
    elements.szCounterName = localizedCounter.data();

    DWORD size = 0;
    if (::PdhMakeCounterPathW(&elements, nullptr, &size, 0) != PDH_MORE_DATA || size == 0) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(size) + 1, L'\0');
    if (::PdhMakeCounterPathW(&elements, buffer.data(), &size, 0) != ERROR_SUCCESS) {
        return {};
    }
    return std::wstring(buffer.data());
}

// compareInstanceNames orders PDH instance names the way a person reads them.
// Instances like "0,10" and "0,2" or "10 D:" and "2 C:" would otherwise sort
// lexicographically and interleave the cores and disks out of order.
bool compareInstanceNames(const std::wstring& left, const std::wstring& right) {
    std::size_t leftIndex = 0;
    std::size_t rightIndex = 0;
    while (leftIndex < left.size() && rightIndex < right.size()) {
        const bool kLeftDigit = std::iswdigit(left[leftIndex]) != 0;
        const bool kRightDigit = std::iswdigit(right[rightIndex]) != 0;
        if (kLeftDigit && kRightDigit) {
            unsigned long long leftValue = 0;
            unsigned long long rightValue = 0;
            while (leftIndex < left.size() && std::iswdigit(left[leftIndex])) {
                leftValue = leftValue * 10ULL + static_cast<unsigned long long>(left[leftIndex] - L'0');
                ++leftIndex;
            }
            while (rightIndex < right.size() && std::iswdigit(right[rightIndex])) {
                rightValue = rightValue * 10ULL + static_cast<unsigned long long>(right[rightIndex] - L'0');
                ++rightIndex;
            }
            if (leftValue != rightValue) {
                return leftValue < rightValue;
            }
            continue;
        }
        const wchar_t kLeftChar = static_cast<wchar_t>(std::towlower(left[leftIndex]));
        const wchar_t kRightChar = static_cast<wchar_t>(std::towlower(right[rightIndex]));
        if (kLeftChar != kRightChar) {
            return kLeftChar < kRightChar;
        }
        ++leftIndex;
        ++rightIndex;
    }
    return left.size() < right.size();
}

std::wstring formatMetricValue(const MetricFormat format, const double value) {
    switch (format) {
    case MetricFormat::kPercent:
        return formatPercent(value);
    case MetricFormat::kBytes:
        return formatByteSize(value);
    case MetricFormat::kMegabytesAsBytes:
        return formatByteSize(value * 1024.0 * 1024.0);
    case MetricFormat::kBytesPerSecond:
        return formatByteRate(value);
    case MetricFormat::kCount:
        return formatCount(value);
    case MetricFormat::kRate:
        return formatRate(value);
    case MetricFormat::kUpTime:
        return formatUpTime(value);
    case MetricFormat::kDecimal:
    default:
        return formatDecimal(value);
    }
}

// appendStaticMetric adds a row that does not come from PDH at all. Physical RAM
// and the logical processor count are reported by the plain Win32 APIs, which
// answer even on machines where the performance counter registry is damaged --
// exactly the machines where an all-PDH table would be empty and useless.
void appendStaticMetric(PerformanceSnapshot& snapshot,
    const wchar_t* group,
    const wchar_t* name,
    const std::wstring& value,
    const wchar_t* source,
    const double numericValue) {
    PerformanceMetricRow row{};
    row.group = group;
    row.name = name;
    row.value = value;
    row.source = source;
    row.numericValue = numericValue;
    row.valid = true;
    snapshot.metrics.push_back(std::move(row));
}

void appendSystemStaticMetrics(PerformanceSnapshot& snapshot) {
    const DWORD kLogicalProcessors = ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (kLogicalProcessors != 0) {
        appendStaticMetric(snapshot, L"CPU", L"逻辑处理器数",
            formatCount(static_cast<double>(kLogicalProcessors)), L"GetActiveProcessorCount",
            static_cast<double>(kLogicalProcessors));
    }
    const WORD kProcessorGroups = ::GetActiveProcessorGroupCount();
    if (kProcessorGroups != 0) {
        appendStaticMetric(snapshot, L"CPU", L"处理器组数",
            formatCount(static_cast<double>(kProcessorGroups)), L"GetActiveProcessorGroupCount",
            static_cast<double>(kProcessorGroups));
    }

    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (::GlobalMemoryStatusEx(&memory)) {
        const double kTotal = static_cast<double>(memory.ullTotalPhys);
        const double kAvailable = static_cast<double>(memory.ullAvailPhys);
        appendStaticMetric(snapshot, L"内存", L"物理内存总量", formatByteSize(kTotal),
            L"GlobalMemoryStatusEx", kTotal);
        appendStaticMetric(snapshot, L"内存", L"物理内存已用", formatByteSize(kTotal - kAvailable),
            L"GlobalMemoryStatusEx", kTotal - kAvailable);
        appendStaticMetric(snapshot, L"内存", L"物理内存使用率",
            formatPercent(static_cast<double>(memory.dwMemoryLoad)), L"GlobalMemoryStatusEx",
            static_cast<double>(memory.dwMemoryLoad));
    }
}

} // namespace

// Counter pairs one PDH handle with the path that actually produced it. The
// resolved path is kept for display because it is the only visible evidence of
// whether the English or the localized route was taken.
struct PerformanceSampler::Counter {
    PDH_HCOUNTER handle = nullptr;
    std::wstring englishPath;
    std::wstring resolvedPath;
    bool localized = false;
    bool available = false;
};

struct PerformanceSampler::Impl {
    PDH_HQUERY query = nullptr;
    bool opened = false;
    bool primed = false;
    std::size_t localizedCount = 0;
    std::size_t missingCount = 0;
    std::vector<Counter> scalars;
    Counter cpuPerCore;
    Counter gpuEngine;
    Counter networkReceived;
    Counter networkSent;
    std::vector<Counter> diskCounters;
};

namespace {

// readScalar formats one counter handle. Output is false when PDH has no usable
// value for this pass, which happens legitimately for a rate counter whose
// instance appeared between two collections.
bool readScalar(const PDH_HCOUNTER handle, const bool uncapped, double& value) {
    if (!handle) {
        return false;
    }
    PDH_FMT_COUNTERVALUE formatted{};
    const DWORD kFormat = PDH_FMT_DOUBLE | (uncapped ? PDH_FMT_NOCAP100 : 0u);
    const PDH_STATUS kStatus = ::PdhGetFormattedCounterValue(handle, kFormat, nullptr, &formatted);
    if (kStatus != ERROR_SUCCESS || formatted.CStatus != ERROR_SUCCESS) {
        return false;
    }
    value = formatted.doubleValue;
    return true;
}

// readArray expands one wildcard counter into instance/value pairs.
std::vector<std::pair<std::wstring, double>> readArray(const PDH_HCOUNTER handle, const bool uncapped) {
    std::vector<std::pair<std::wstring, double>> values;
    if (!handle) {
        return values;
    }

    DWORD bufferSize = 0;
    DWORD itemCount = 0;
    const DWORD kFormat = PDH_FMT_DOUBLE | (uncapped ? PDH_FMT_NOCAP100 : 0u);
    const PDH_STATUS kProbe = ::PdhGetFormattedCounterArrayW(handle, kFormat, &bufferSize, &itemCount, nullptr);
    if (kProbe != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0) {
        return values;
    }

    std::vector<unsigned char> raw(bufferSize, 0);
    auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(raw.data());
    if (::PdhGetFormattedCounterArrayW(handle, kFormat, &bufferSize, &itemCount, items) != ERROR_SUCCESS) {
        return values;
    }

    values.reserve(itemCount);
    for (DWORD index = 0; index < itemCount; ++index) {
        const PDH_FMT_COUNTERVALUE_ITEM_W& item = items[index];
        if (item.FmtValue.CStatus != ERROR_SUCCESS) {
            continue;
        }
        values.emplace_back(item.szName ? std::wstring(item.szName) : std::wstring(),
            item.FmtValue.doubleValue);
    }
    return values;
}

} // namespace

PerformanceSampler::PerformanceSampler(const PerformanceScope scope)
    : scope_(scope), impl_(std::make_unique<Impl>()) {
}

PerformanceSampler::~PerformanceSampler() {
    std::scoped_lock lock(mutex_);
    closeQuery();
}

void PerformanceSampler::closeQuery() {
    if (impl_ && impl_->query) {
        // Closing the query releases every counter handle it owns, so the
        // per-counter handles are only cleared, never closed individually.
        ::PdhCloseQuery(impl_->query);
        impl_->query = nullptr;
    }
    if (impl_) {
        impl_->opened = false;
        impl_->primed = false;
        impl_->scalars.clear();
        impl_->diskCounters.clear();
        impl_->cpuPerCore = Counter{};
        impl_->gpuEngine = Counter{};
        impl_->networkReceived = Counter{};
        impl_->networkSent = Counter{};
    }
}

bool PerformanceSampler::addCounter(const wchar_t* englishPath, Counter& counter) {
    counter = Counter{};
    if (!impl_ || !impl_->query || !englishPath) {
        return false;
    }
    counter.englishPath = englishPath;

    // PdhAddEnglishCounterW is the documented contract for locale-independent
    // paths and is tried first. Hard-coding the English text into PdhAddCounterW
    // instead would fail on every non-English Windows, because the counter and
    // object names in a path are localized resources.
    PDH_HCOUNTER handle = nullptr;
    if (::PdhAddEnglishCounterW(impl_->query, englishPath, 0, &handle) == ERROR_SUCCESS && handle) {
        counter.handle = handle;
        counter.resolvedPath = englishPath;
        counter.available = true;
        return true;
    }

    // The English mapping lives in the Perflib 009 registry table, which can be
    // missing or corrupt on systems where the counters were rebuilt by hand. In
    // that case the same path is reassembled in the machine's own language and
    // added through the ordinary PdhAddCounterW.
    const std::wstring kLocalizedPath = localizeCounterPath(englishPath);
    if (kLocalizedPath.empty()) {
        return false;
    }
    handle = nullptr;
    if (::PdhAddCounterW(impl_->query, kLocalizedPath.c_str(), 0, &handle) != ERROR_SUCCESS || !handle) {
        return false;
    }
    counter.handle = handle;
    counter.resolvedPath = kLocalizedPath;
    counter.localized = true;
    counter.available = true;
    if (impl_) {
        ++impl_->localizedCount;
    }
    return true;
}

bool PerformanceSampler::ensureOpen(std::wstring& diagnostic) {
    if (impl_->opened && impl_->query) {
        return true;
    }

    closeQuery();
    const PDH_STATUS kStatus = ::PdhOpenQueryW(nullptr, 0, &impl_->query);
    if (kStatus != ERROR_SUCCESS || !impl_->query) {
        impl_->query = nullptr;
        // PDH returns its own status codes rather than Win32 error codes, so the
        // raw value is shown instead of being run through FormatMessage, which
        // would print an unrelated system message for the same number.
        wchar_t code[32] = {};
        swprintf_s(code, L"0x%08lX", static_cast<unsigned long>(kStatus));
        diagnostic = L"PdhOpenQueryW 失败（" + std::wstring(code) + L"），性能计数器不可用。";
        return false;
    }

    impl_->localizedCount = 0;
    impl_->missingCount = 0;

    if (scope_ == PerformanceScope::kSystem) {
        const auto& specs = scalarSpecs();
        impl_->scalars.resize(specs.size());
        for (std::size_t index = 0; index < specs.size(); ++index) {
            if (!addCounter(specs[index].path, impl_->scalars[index]) &&
                specs[index].alternatePath != nullptr) {
                addCounter(specs[index].alternatePath, impl_->scalars[index]);
            }
            if (!impl_->scalars[index].available) {
                ++impl_->missingCount;
            }
        }
        if (!addCounter(L"\\Processor Information(*)\\% Processor Time", impl_->cpuPerCore)) {
            addCounter(L"\\Processor(*)\\% Processor Time", impl_->cpuPerCore);
        }
        if (!addCounter(L"\\GPU Engine(*)\\Utilization Percentage", impl_->gpuEngine)) {
            ++impl_->missingCount;
        }
        addCounter(L"\\Network Interface(*)\\Bytes Received/sec", impl_->networkReceived);
        addCounter(L"\\Network Interface(*)\\Bytes Sent/sec", impl_->networkSent);
    } else {
        const auto& paths = diskCounterPaths();
        impl_->diskCounters.resize(paths.size());
        for (std::size_t index = 0; index < paths.size(); ++index) {
            if (!addCounter(paths[index], impl_->diskCounters[index])) {
                ++impl_->missingCount;
            }
        }
    }

    // A query with no counters cannot be collected, and PDH reports that as a
    // generic failure later; failing here names the real problem instead.
    const bool kAnyCounter = std::any_of(impl_->scalars.begin(), impl_->scalars.end(),
                               [](const Counter& counter) { return counter.available; }) ||
        std::any_of(impl_->diskCounters.begin(), impl_->diskCounters.end(),
            [](const Counter& counter) { return counter.available; }) ||
        impl_->cpuPerCore.available || impl_->gpuEngine.available || impl_->networkReceived.available;
    if (!kAnyCounter) {
        closeQuery();
        diagnostic = L"没有任何性能计数器可用，系统的 Perflib 计数器表可能已损坏（可用管理员权限运行 lodctr /R 重建）。";
        return false;
    }

    ::PdhCollectQueryData(impl_->query);
    impl_->opened = true;
    impl_->primed = false;
    return true;
}

void PerformanceSampler::collectSystemMetrics(PerformanceSnapshot& snapshot) {
    appendSystemStaticMetrics(snapshot);

    const auto& specs = scalarSpecs();
    for (std::size_t index = 0; index < specs.size() && index < impl_->scalars.size(); ++index) {
        const Counter& counter = impl_->scalars[index];
        PerformanceMetricRow row{};
        row.group = specs[index].group;
        row.name = specs[index].name;
        row.source = counter.available ? counter.resolvedPath : std::wstring(specs[index].path);
        double value = 0.0;
        if (counter.available && readScalar(counter.handle, specs[index].uncapped, value)) {
            row.numericValue = value;
            row.value = formatMetricValue(specs[index].format, value);
            row.valid = true;
        } else {
            row.value = counter.available ? L"正在采样…" : L"不可用";
        }
        snapshot.metrics.push_back(std::move(row));
    }

    if (impl_->cpuPerCore.available) {
        auto cores = readArray(impl_->cpuPerCore.handle, false);
        // "Processor Information" publishes both a per-group rollup ("0,_Total")
        // and a machine-wide one ("_Total"); both are already reported as the CPU
        // total, so leaving them in would double-count the per-core section.
        cores.erase(std::remove_if(cores.begin(), cores.end(),
                        [](const std::pair<std::wstring, double>& item) {
                            return item.first.empty() ||
                                item.first.find(L"_Total") != std::wstring::npos;
                        }),
            cores.end());
        std::sort(cores.begin(), cores.end(),
            [](const std::pair<std::wstring, double>& left, const std::pair<std::wstring, double>& right) {
                return compareInstanceNames(left.first, right.first);
            });
        for (const auto& core : cores) {
            PerformanceMetricRow row{};
            row.group = L"CPU 每核";
            row.name = L"核心 " + core.first;
            row.numericValue = core.second;
            row.value = formatPercent(core.second);
            row.source = impl_->cpuPerCore.resolvedPath;
            row.valid = true;
            snapshot.metrics.push_back(std::move(row));
        }
    }

    // GPU Engine publishes one counter instance per active engine. These values
    // are concurrent, so summing them would invent a "total GPU" percentage.
    // Lite reports the maximum sampled engine instead and preserves both the
    // counter-unavailable and no-instance states as explicit non-values.
    {
        PerformanceMetricRow row{};
        row.group = L"GPU";
        row.name = L"最大引擎利用率（非总和）";
        row.source = impl_->gpuEngine.available
            ? impl_->gpuEngine.resolvedPath
            : L"\\GPU Engine(*)\\Utilization Percentage";
        if (!impl_->gpuEngine.available) {
            row.value = L"未提供（GPU Engine 性能计数器不可用）";
        } else {
            const auto kEngines = readArray(impl_->gpuEngine.handle, false);
            if (kEngines.empty()) {
                row.value = L"未枚举到 GPU 引擎实例";
            } else {
                const auto kPeak = std::max_element(kEngines.begin(), kEngines.end(),
                    [](const std::pair<std::wstring, double>& left, const std::pair<std::wstring, double>& right) {
                        return left.second < right.second;
                    });
                row.numericValue = std::clamp(kPeak->second, 0.0, 100.0);
                row.value = formatPercent(row.numericValue) + L"（" + kPeak->first + L"）";
                row.valid = true;
            }
        }
        snapshot.metrics.push_back(std::move(row));
    }

    if (impl_->networkReceived.available || impl_->networkSent.available) {
        const auto kReceived = readArray(impl_->networkReceived.handle, false);
        const auto kSent = readArray(impl_->networkSent.handle, false);
        std::map<std::wstring, std::pair<double, double>> adapters;
        for (const auto& item : kReceived) {
            adapters[item.first].first = item.second;
        }
        for (const auto& item : kSent) {
            adapters[item.first].second = item.second;
        }

        double totalReceived = 0.0;
        double totalSent = 0.0;
        for (const auto& adapter : adapters) {
            totalReceived += adapter.second.first;
            totalSent += adapter.second.second;
        }
        appendStaticMetric(snapshot, L"网络", L"接收合计", formatByteRate(totalReceived),
            impl_->networkReceived.resolvedPath.c_str(), totalReceived);
        appendStaticMetric(snapshot, L"网络", L"发送合计", formatByteRate(totalSent),
            impl_->networkSent.resolvedPath.c_str(), totalSent);

        std::vector<std::pair<std::wstring, std::pair<double, double>>> ordered(adapters.begin(), adapters.end());
        std::sort(ordered.begin(), ordered.end(), [](const auto& left, const auto& right) {
            const double kLeftTotal = left.second.first + left.second.second;
            const double kRightTotal = right.second.first + right.second.second;
            if (kLeftTotal != kRightTotal) {
                return kLeftTotal > kRightTotal;
            }
            return compareInstanceNames(left.first, right.first);
        });
        for (const auto& adapter : ordered) {
            PerformanceMetricRow row{};
            row.group = L"网络";
            row.name = adapter.first;
            row.numericValue = adapter.second.first + adapter.second.second;
            row.value = L"↓ " + formatByteRate(adapter.second.first) +
                L"   ↑ " + formatByteRate(adapter.second.second);
            row.source = impl_->networkReceived.available
                ? impl_->networkReceived.resolvedPath
                : impl_->networkSent.resolvedPath;
            row.valid = true;
            snapshot.metrics.push_back(std::move(row));
        }
    }
}

void PerformanceSampler::collectDiskRows(PerformanceSnapshot& snapshot) {
    const auto kReadValues = [this](const DiskCounterId id, const bool uncapped) {
        const std::size_t kIndex = static_cast<std::size_t>(id);
        if (kIndex >= impl_->diskCounters.size() || !impl_->diskCounters[kIndex].available) {
            return std::vector<std::pair<std::wstring, double>>{};
        }
        return readArray(impl_->diskCounters[kIndex].handle, uncapped);
    };

    std::map<std::wstring, DiskActivityRow> rows;
    const auto kMerge = [&rows](const std::vector<std::pair<std::wstring, double>>& values,
                           double DiskActivityRow::*field) {
        for (const auto& item : values) {
            if (item.first.empty()) {
                continue;
            }
            DiskActivityRow& row = rows[item.first];
            row.instance = item.first;
            row.*field = item.second;
        }
    };

    kMerge(kReadValues(DiskCounterId::kReadBytes, false), &DiskActivityRow::readBytesPerSecond);
    kMerge(kReadValues(DiskCounterId::kWriteBytes, false), &DiskActivityRow::writeBytesPerSecond);
    kMerge(kReadValues(DiskCounterId::kReads, false), &DiskActivityRow::readsPerSecond);
    kMerge(kReadValues(DiskCounterId::kWrites, false), &DiskActivityRow::writesPerSecond);
    kMerge(kReadValues(DiskCounterId::kCurrentQueue, false), &DiskActivityRow::currentQueueLength);
    kMerge(kReadValues(DiskCounterId::kAverageQueue, false), &DiskActivityRow::averageQueueLength);
    // A RAID set or a disk with several outstanding requests genuinely exceeds
    // 100 % busy time, and capping it would hide the busiest spindles.
    kMerge(kReadValues(DiskCounterId::kBusyPercent, true), &DiskActivityRow::busyPercent);
    kMerge(kReadValues(DiskCounterId::kReadLatency, false), &DiskActivityRow::readLatencySeconds);
    kMerge(kReadValues(DiskCounterId::kWriteLatency, false), &DiskActivityRow::writeLatencySeconds);

    snapshot.disks.reserve(rows.size());
    for (auto& entry : rows) {
        snapshot.disks.push_back(std::move(entry.second));
    }
    std::sort(snapshot.disks.begin(), snapshot.disks.end(),
        [](const DiskActivityRow& left, const DiskActivityRow& right) {
            // "_Total" is the summary line and belongs at the top rather than
            // sorted in among the physical spindles by name.
            const bool kLeftTotal = left.instance.find(L"_Total") != std::wstring::npos;
            const bool kRightTotal = right.instance.find(L"_Total") != std::wstring::npos;
            if (kLeftTotal != kRightTotal) {
                return kLeftTotal;
            }
            return compareInstanceNames(left.instance, right.instance);
        });
}

PerformanceSnapshot PerformanceSampler::sample() {
    std::scoped_lock lock(mutex_);
    PerformanceSnapshot snapshot{};
    if (!impl_) {
        snapshot.diagnosticText = L"性能采样器未初始化。";
        return snapshot;
    }

    std::wstring diagnostic;
    if (!ensureOpen(diagnostic)) {
        snapshot.diagnosticText = diagnostic;
        return snapshot;
    }

    if (!impl_->primed) {
        ::Sleep(kPrimingIntervalMs);
        impl_->primed = true;
    }

    const PDH_STATUS kStatus = ::PdhCollectQueryData(impl_->query);
    if (kStatus != ERROR_SUCCESS) {
        // A collection failure is usually a transient provider fault; dropping
        // the query makes the next pass rebuild it instead of returning the same
        // error forever.
        closeQuery();
        snapshot.diagnosticText = L"PdhCollectQueryData 失败，已丢弃当前查询并将在下次采样时重建。";
        return snapshot;
    }

    if (scope_ == PerformanceScope::kSystem) {
        collectSystemMetrics(snapshot);
    } else {
        collectDiskRows(snapshot);
    }

    snapshot.success = true;
    if (impl_->localizedCount > 0) {
        snapshot.counterResolutionText = L"计数器路径：本地化回退 " + std::to_wstring(impl_->localizedCount) + L" 项";
    } else {
        snapshot.counterResolutionText = L"计数器路径：英文名解析";
    }
    if (impl_->missingCount > 0) {
        snapshot.counterResolutionText += L"，缺失 " + std::to_wstring(impl_->missingCount) + L" 项";
    }
    return snapshot;
}

std::shared_ptr<PerformanceSampler> makePerformanceSampler(const PerformanceScope scope) {
    return std::make_shared<PerformanceSampler>(scope);
}

} // namespace Ksword::Features::hardware_stats

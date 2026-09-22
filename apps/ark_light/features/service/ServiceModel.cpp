#include "ServiceModel.h"

#include <algorithm>
#include <cwctype>

namespace ksword::features::service {
namespace {

std::wstring lowerText(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return value;
}

// statePriority ranks states for the "running first" order. Running services
// come first, then the ones in mid-transition (which are what an operator is
// usually waiting on), then everything stopped.
int statePriority(const std::uint32_t currentState) {
    switch (currentState) {
    case SERVICE_RUNNING:
        return 0;
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
        return 1;
    case SERVICE_PAUSED:
        return 2;
    default:
        return 3;
    }
}

// startTypePriority ranks start types so the ones that run without anyone
// asking sort to the top.
int startTypePriority(const std::uint32_t startType) {
    switch (startType) {
    case SERVICE_BOOT_START:
        return 0;
    case SERVICE_SYSTEM_START:
        return 1;
    case SERVICE_AUTO_START:
        return 2;
    case SERVICE_DEMAND_START:
        return 3;
    default:
        return 4;
    }
}

std::wstring joinText(const std::vector<std::wstring>& values) {
    std::wstring text;
    for (const std::wstring& value : values) {
        if (value.empty()) {
            continue;
        }
        if (!text.empty()) {
            text += L", ";
        }
        text += value;
    }
    return text;
}

std::wstring knownOrUnknown(const bool known, const std::wstring& value) {
    if (!known) {
        return L"未知";
    }
    return value.empty() ? L"-" : value;
}

} // namespace

void ServiceModel::setEntries(std::vector<ServiceEntry> entries) {
    entries_ = std::move(entries);
    sortEntries();
}

void ServiceModel::setSortMode(const ServiceSortMode mode) {
    sortMode_ = mode;
    sortEntries();
}

ServiceSortMode ServiceModel::sortMode() const noexcept {
    return sortMode_;
}

const std::vector<ServiceEntry>& ServiceModel::entries() const noexcept {
    return entries_;
}

const ServiceEntry* ServiceModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= entries_.size()) {
        return nullptr;
    }
    return &entries_[static_cast<std::size_t>(index)];
}

void ServiceModel::sortEntries() {
    // Every mode falls back to the service name so the order is total: without
    // that tie-break, two refreshes of the same machine can hand back rows in
    // different positions and the table appears to shuffle on its own.
    const auto kByName = [](const ServiceEntry& left, const ServiceEntry& right) {
        return lowerText(left.serviceName) < lowerText(right.serviceName);
    };
    switch (sortMode_) {
    case ServiceSortMode::kRunningFirst:
        std::stable_sort(entries_.begin(), entries_.end(), [&kByName](const ServiceEntry& left, const ServiceEntry& right) {
            const int kLeftRank = statePriority(left.currentState);
            const int kRightRank = statePriority(right.currentState);
            return kLeftRank != kRightRank ? kLeftRank < kRightRank : kByName(left, right);
        });
        break;
    case ServiceSortMode::kAutoStartFirst:
        std::stable_sort(entries_.begin(), entries_.end(), [&kByName](const ServiceEntry& left, const ServiceEntry& right) {
            const int kLeftRank = startTypePriority(left.startType);
            const int kRightRank = startTypePriority(right.startType);
            return kLeftRank != kRightRank ? kLeftRank < kRightRank : kByName(left, right);
        });
        break;
    case ServiceSortMode::kNameAscending:
    default:
        std::stable_sort(entries_.begin(), entries_.end(), kByName);
        break;
    }
}

std::wstring ServiceModel::textForColumn(const ServiceEntry& entry, const int column) const {
    switch (column) {
    case 0:
        return entry.serviceName;
    case 1:
        return entry.displayName;
    case 2:
        return entry.hasStatus ? serviceStateText(entry.currentState) : L"未知";
    case 3:
        return entry.hasConfig ? serviceStartTypeText(entry.startType, entry.delayedAutoStart) : L"未知";
    case 4:
        // A stopped service has no process, and printing 0 would read as a real
        // PID rather than as "not running".
        return entry.processId != 0 ? std::to_wstring(entry.processId) : L"-";
    case 5:
        return entry.accountName;
    case 6:
        return entry.riskText;
    default:
        return {};
    }
}

std::vector<ServiceProperty> ServiceModel::propertiesForEntry(const ServiceEntry& entry) const {
    return servicePropertiesForEntry(entry);
}

std::vector<ServiceProperty> servicePropertiesForEntry(const ServiceEntry& entry) {
    std::vector<ServiceProperty> properties;
    properties.push_back({ L"服务名", entry.serviceName });
    properties.push_back({ L"显示名", entry.displayName });
    properties.push_back({ L"状态", entry.hasStatus ? serviceStateText(entry.currentState) : L"未知" });
    properties.push_back({ L"启动类型", entry.hasConfig ? serviceStartTypeText(entry.startType, entry.delayedAutoStart) : L"未知" });
    properties.push_back({ L"服务类型", entry.hasStatus || entry.hasConfig ? serviceTypeText(entry.serviceType) : L"未知" });
    properties.push_back({ L"进程 ID", entry.hasStatus && entry.processId != 0 ? std::to_wstring(entry.processId) : entry.hasStatus ? L"-" : L"未知" });
    properties.push_back({ L"登录账户", knownOrUnknown(entry.hasConfig, entry.accountName) });
    properties.push_back({ L"可执行路径", knownOrUnknown(entry.hasConfig, entry.binaryPath) });
    properties.push_back({ L"加载顺序组", knownOrUnknown(entry.hasConfig, entry.loadOrderGroup) });
    properties.push_back({ L"加载顺序标记", entry.hasConfig ? std::to_wstring(entry.tagId) : L"未知" });
    properties.push_back({ L"依赖项", knownOrUnknown(entry.hasConfig, entry.dependencies) });
    properties.push_back({ L"直接依赖服务", knownOrUnknown(entry.hasConfig, joinText(entry.dependencyServiceNames)) });
    properties.push_back({ L"依赖加载顺序组", knownOrUnknown(entry.hasConfig, joinText(entry.dependencyLoadOrderGroups)) });
    properties.push_back({ L"错误控制", entry.hasConfig ? std::to_wstring(entry.errorControl) : L"未知" });
    if (entry.hasStatus) {
        properties.push_back({ L"Win32 退出码", std::to_wstring(entry.win32ExitCode) });
        properties.push_back({ L"服务特定退出码", std::to_wstring(entry.serviceSpecificExitCode) });
        properties.push_back({ L"状态检查点", std::to_wstring(entry.checkPoint) });
        properties.push_back({ L"等待提示(毫秒)", std::to_wstring(entry.waitHint) });
        properties.push_back({ L"服务标志", std::to_wstring(entry.serviceFlags) });
        properties.push_back({ L"接受的控制", std::to_wstring(entry.controlsAccepted) });
    }
    if (!entry.riskText.empty()) {
        properties.push_back({ L"风险", entry.riskText });
    }
    if (!entry.diagnosticText.empty()) {
        properties.push_back({ L"采集说明", entry.diagnosticText });
    }
    properties.push_back({ L"描述", knownOrUnknown(entry.hasDescription, entry.description) });
    return properties;
}

std::wstring serviceStateText(const std::uint32_t currentState) {
    switch (currentState) {
    case SERVICE_STOPPED:
        return L"已停止";
    case SERVICE_START_PENDING:
        return L"正在启动";
    case SERVICE_STOP_PENDING:
        return L"正在停止";
    case SERVICE_RUNNING:
        return L"正在运行";
    case SERVICE_CONTINUE_PENDING:
        return L"正在继续";
    case SERVICE_PAUSE_PENDING:
        return L"正在暂停";
    case SERVICE_PAUSED:
        return L"已暂停";
    default:
        return L"未知(" + std::to_wstring(currentState) + L")";
    }
}

std::wstring serviceStartTypeText(const std::uint32_t startType, const bool delayedAutoStart) {
    switch (startType) {
    case SERVICE_BOOT_START:
        return L"引导";
    case SERVICE_SYSTEM_START:
        return L"系统";
    case SERVICE_AUTO_START:
        return delayedAutoStart ? L"自动(延迟)" : L"自动";
    case SERVICE_DEMAND_START:
        return L"手动";
    case SERVICE_DISABLED:
        return L"禁用";
    default:
        return L"未知(" + std::to_wstring(startType) + L")";
    }
}

std::wstring serviceTypeText(const std::uint32_t serviceType) {
    std::wstring text;
    const auto kAppend = [&text](const wchar_t* label) {
        if (!text.empty()) {
            text += L" | ";
        }
        text += label;
    };
    if ((serviceType & SERVICE_KERNEL_DRIVER) != 0) {
        kAppend(L"内核驱动");
    }
    if ((serviceType & SERVICE_FILE_SYSTEM_DRIVER) != 0) {
        kAppend(L"文件系统驱动");
    }
    if ((serviceType & SERVICE_WIN32_OWN_PROCESS) != 0) {
        kAppend(L"独占进程");
    }
    if ((serviceType & SERVICE_WIN32_SHARE_PROCESS) != 0) {
        kAppend(L"共享进程");
    }
    if ((serviceType & SERVICE_INTERACTIVE_PROCESS) != 0) {
        kAppend(L"可交互");
    }
    return text.empty() ? L"未知(" + std::to_wstring(serviceType) + L")" : text;
}

bool serviceIsTransitioning(const ServiceEntry& entry) {
    switch (entry.currentState) {
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
        return true;
    default:
        return false;
    }
}

bool serviceCanStart(const ServiceEntry& entry) {
    if (!entry.hasStatus || serviceIsTransitioning(entry)) {
        return false;
    }
    // A disabled service cannot be started until its start type changes, and the
    // SCM rejects the attempt with an error that reads like a permission fault.
    if (entry.hasConfig && entry.startType == SERVICE_DISABLED) {
        return false;
    }
    return entry.currentState == SERVICE_STOPPED;
}

bool serviceCanStop(const ServiceEntry& entry) {
    if (!entry.hasStatus || serviceIsTransitioning(entry)) {
        return false;
    }
    if ((entry.controlsAccepted & SERVICE_ACCEPT_STOP) == 0) {
        return false;
    }
    return entry.currentState == SERVICE_RUNNING || entry.currentState == SERVICE_PAUSED;
}

bool serviceCanPause(const ServiceEntry& entry) {
    if (!entry.hasStatus || serviceIsTransitioning(entry)) {
        return false;
    }
    if ((entry.controlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) == 0) {
        return false;
    }
    return entry.currentState == SERVICE_RUNNING;
}

bool serviceCanContinue(const ServiceEntry& entry) {
    if (!entry.hasStatus || serviceIsTransitioning(entry)) {
        return false;
    }
    if ((entry.controlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) == 0) {
        return false;
    }
    return entry.currentState == SERVICE_PAUSED;
}

} // namespace Ksword::Features::Service

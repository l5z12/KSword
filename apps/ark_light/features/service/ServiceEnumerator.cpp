#include "ServiceEnumerator.h"

#include "../../../../shared/platform/service/Service.h"

#include <algorithm>
#include <cwctype>
#include <string>
#include <utility>

namespace ksword::features::service {
namespace {

std::wstring widenUtf8(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int kRequired = ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (kRequired <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(kRequired), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), wide.data(), kRequired);
    return wide;
}

std::wstring lowerText(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return value;
}

std::wstring trimText(std::wstring value) {
    const auto kBegin = std::find_if_not(value.begin(), value.end(), [](const wchar_t ch) { return std::iswspace(ch) != 0; });
    const auto kEnd = std::find_if_not(value.rbegin(), value.rend(), [](const wchar_t ch) { return std::iswspace(ch) != 0; }).base();
    return kBegin >= kEnd ? std::wstring{} : std::wstring(kBegin, kEnd);
}

// expandDependencyList turns the SCM's double-null-terminated dependency block
// into one readable line. The reusable layer hands it over with the embedded
// nulls intact so callers can decide how to present it.
std::wstring expandDependencyList(const std::wstring& multiSz) {
    std::wstring text;
    std::size_t cursor = 0;
    while (cursor < multiSz.size()) {
        const std::size_t kEnd = multiSz.find(L'\0', cursor);
        const std::wstring kItem = multiSz.substr(cursor, kEnd == std::wstring::npos ? std::wstring::npos : kEnd - cursor);
        if (!kItem.empty()) {
            if (!text.empty()) {
                text += L", ";
            }
            text += kItem;
        }
        if (kEnd == std::wstring::npos) {
            break;
        }
        cursor = kEnd + 1;
    }
    return text;
}

// splitDependencyList preserves the SCM distinction between a service short
// name and a +load-order-group entry. The formatted dependency string remains
// useful for the existing list view, while these vectors let detail consumers
// export or render the two meanings without parsing presentation text.
void splitDependencyList(const std::wstring& multiSz,
    std::vector<std::wstring>* serviceNames,
    std::vector<std::wstring>* loadOrderGroups) {
    if (!serviceNames || !loadOrderGroups) {
        return;
    }
    serviceNames->clear();
    loadOrderGroups->clear();
    std::size_t cursor = 0;
    while (cursor < multiSz.size()) {
        const std::size_t kEnd = multiSz.find(L'\0', cursor);
        const std::wstring kItem = multiSz.substr(cursor, kEnd == std::wstring::npos ? std::wstring::npos : kEnd - cursor);
        if (!kItem.empty()) {
            if (kItem.front() == L'+' && kItem.size() > 1) {
                loadOrderGroups->push_back(kItem.substr(1));
            } else {
                serviceNames->push_back(kItem);
            }
        }
        if (kEnd == std::wstring::npos) {
            break;
        }
        cursor = kEnd + 1;
    }
}

std::wstring joinNames(const std::vector<std::wstring>& names) {
    std::wstring text;
    for (const std::wstring& name : names) {
        if (name.empty()) {
            continue;
        }
        if (!text.empty()) {
            text += L", ";
        }
        text += name;
    }
    return text;
}

// executablePathFromCommandLine extracts just the image path from a service's
// binary path. Quoted paths are taken verbatim; an unquoted one is cut at the
// first space that ends a token looking like an executable, since service
// command lines routinely carry arguments (-k netsvcs and friends).
std::wstring executablePathFromCommandLine(const std::wstring& commandLine) {
    const std::wstring kTrimmed = trimText(commandLine);
    if (kTrimmed.empty()) {
        return {};
    }
    if (kTrimmed.front() == L'"') {
        const std::size_t kClosing = kTrimmed.find(L'"', 1);
        return kClosing == std::wstring::npos ? kTrimmed.substr(1) : kTrimmed.substr(1, kClosing - 1);
    }
    // Driver paths often arrive in NT form; those have no arguments at all.
    const std::wstring kLowered = lowerText(kTrimmed);
    const std::size_t kExtension = kLowered.find(L".exe");
    if (kExtension != std::wstring::npos) {
        return kTrimmed.substr(0, kExtension + 4);
    }
    const std::size_t kSpace = kTrimmed.find(L' ');
    return kSpace == std::wstring::npos ? kTrimmed : kTrimmed.substr(0, kSpace);
}

// resolveImagePath maps a service image path onto something the filesystem can
// answer for. The SCM stores driver paths relative to the system root and in NT
// device form, neither of which GetFileAttributesW understands as-is.
std::wstring resolveImagePath(const std::wstring& imagePath) {
    std::wstring path = trimText(imagePath);
    if (path.empty()) {
        return {};
    }
    const std::wstring kLowered = lowerText(path);
    if (kLowered.rfind(L"\\systemroot\\", 0) == 0) {
        wchar_t systemRoot[MAX_PATH]{};
        if (::GetWindowsDirectoryW(systemRoot, MAX_PATH) > 0) {
            return std::wstring(systemRoot) + path.substr(11);
        }
        return {};
    }
    if (kLowered.rfind(L"\\??\\", 0) == 0) {
        return path.substr(4);
    }
    if (kLowered.rfind(L"system32\\", 0) == 0 || kLowered.rfind(L"\\system32\\", 0) == 0) {
        wchar_t systemRoot[MAX_PATH]{};
        if (::GetWindowsDirectoryW(systemRoot, MAX_PATH) > 0) {
            const std::wstring kSuffix = path.front() == L'\\' ? path.substr(1) : path;
            return std::wstring(systemRoot) + L"\\" + kSuffix;
        }
        return {};
    }
    if (path.size() >= 2 && path[1] == L':') {
        return path;
    }
    return {};
}

bool fileExists(const std::wstring& path) {
    if (path.empty()) {
        return false;
    }
    const DWORD kAttributes = ::GetFileAttributesW(path.c_str());
    return kAttributes != INVALID_FILE_ATTRIBUTES && (kAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool isUnderSystemDirectory(const std::wstring& resolvedPath) {
    if (resolvedPath.empty()) {
        return false;
    }
    wchar_t systemRoot[MAX_PATH]{};
    if (::GetWindowsDirectoryW(systemRoot, MAX_PATH) == 0) {
        return false;
    }
    const std::wstring kLowered = lowerText(resolvedPath);
    const std::wstring kLoweredRoot = lowerText(std::wstring(systemRoot));
    return kLowered.rfind(kLoweredRoot, 0) == 0;
}

bool isSystemAccount(const std::wstring& accountName) {
    const std::wstring kLowered = lowerText(accountName);
    return kLowered == L"localsystem" ||
        kLowered == L"nt authority\\system" ||
        kLowered == L".\\localsystem";
}

// buildRiskText flags the service configurations that matter in an audit. Every
// check below describes a concrete, verifiable property of the configuration --
// none of them is a verdict about whether the service is malicious, and the text
// is worded so the operator can go and check the same thing by hand.
std::wstring buildRiskText(const ServiceEntry& entry) {
    std::vector<std::wstring> flags;

    const std::wstring kImagePath = executablePathFromCommandLine(entry.binaryPath);
    const std::wstring kResolvedPath = resolveImagePath(kImagePath);

    // An unquoted path containing spaces lets Windows try C:\Program.exe before
    // the real target. It is a long-standing local privilege-escalation surface
    // and is trivially checkable, so it is worth naming precisely.
    const std::wstring kTrimmedCommand = trimText(entry.binaryPath);
    if (!kTrimmedCommand.empty() && kTrimmedCommand.front() != L'"' &&
        kImagePath.find(L' ') != std::wstring::npos) {
        flags.push_back(L"未加引号路径");
    }

    if (!kResolvedPath.empty() && !fileExists(kResolvedPath)) {
        flags.push_back(L"映像缺失");
    }

    if (isSystemAccount(entry.accountName) && !kResolvedPath.empty() && !isUnderSystemDirectory(kResolvedPath)) {
        flags.push_back(L"系统账户·非系统目录");
    }

    const bool kIsDriver = (entry.serviceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
    if (kIsDriver && (entry.startType == SERVICE_BOOT_START || entry.startType == SERVICE_SYSTEM_START ||
            entry.startType == SERVICE_AUTO_START)) {
        flags.push_back(L"驱动·自启");
    }

    std::wstring text;
    for (const std::wstring& flag : flags) {
        if (!text.empty()) {
            text += L" / ";
        }
        text += flag;
    }
    return text;
}

bool isExplicitlyUnsupportedOptionalQueryError(const std::uint32_t win32Error) {
    switch (win32Error) {
    case ERROR_CALL_NOT_IMPLEMENTED:
    case ERROR_NOT_SUPPORTED:
    case ERROR_OLD_WIN_VERSION:
        return true;
    default:
        return false;
    }
}

ServiceDetailSection optionalQueryFailure(const std::string& errorText, const std::uint32_t win32Error) {
    ServiceDetailSection section{};
    section.availability = isExplicitlyUnsupportedOptionalQueryError(win32Error)
        ? ServiceDetailAvailability::kUnsupported
        : ServiceDetailAvailability::kPartial;
    const std::wstring kDetail = widenUtf8(errorText);
    section.diagnosticText = serviceDetailAvailabilityText(section.availability) + L"：";
    if (!kDetail.empty()) {
        section.diagnosticText += kDetail;
    } else if (win32Error != ERROR_SUCCESS) {
        section.diagnosticText += L"Win32 错误 " + std::to_wstring(win32Error);
    } else {
        section.diagnosticText += L"服务控制管理器未返回诊断。";
    }
    return section;
}

ServiceDetailSection optionalQueryInvalidInput(const wchar_t* detail) {
    ServiceDetailSection section{};
    section.availability = ServiceDetailAvailability::kPartial;
    section.diagnosticText = L"Partial：";
    section.diagnosticText += detail ? detail : L"查询输入无效。";
    return section;
}

std::wstring failureActionText(const std::uint32_t actionType, const std::uint32_t delayMs) {
    std::wstring action;
    switch (actionType) {
    case SC_ACTION_NONE:
        action = L"不执行操作";
        break;
    case SC_ACTION_RESTART:
        action = L"重启服务";
        break;
    case SC_ACTION_REBOOT:
        action = L"重启计算机";
        break;
    case SC_ACTION_RUN_COMMAND:
        action = L"运行恢复命令";
        break;
    default:
        action = L"未知操作(" + std::to_wstring(actionType) + L")";
        break;
    }
    return action + L"（延迟 " + std::to_wstring(delayMs) + L" 毫秒）";
}

std::wstring sectionStatusValue(const ServiceDetailSection& section) {
    return section.diagnosticText.empty()
        ? serviceDetailAvailabilityText(section.availability)
        : section.diagnosticText;
}

void appendFailureSettingsProperties(std::vector<ServiceProperty>* properties,
    const ServiceFailureSettingsSnapshot& settings,
    const ServiceDetailSection& status) {
    if (!properties) {
        return;
    }
    properties->push_back({ L"恢复策略查询", sectionStatusValue(status) });
    if (status.availability != ServiceDetailAvailability::kAvailable) {
        return;
    }

    properties->push_back({ L"故障恢复配置", settings.hasFailureActions ? L"已配置" : L"未配置" });
    properties->push_back({ L"恢复计数重置周期", settings.hasFailureActions
        ? std::to_wstring(settings.resetPeriodSeconds) + L" 秒"
        : L"-" });
    properties->push_back({ L"恢复重启消息", settings.hasFailureActions
        ? (settings.rebootMessage.empty() ? L"-" : settings.rebootMessage)
        : L"-" });
    properties->push_back({ L"恢复命令", settings.hasFailureActions
        ? (settings.command.empty() ? L"-" : settings.command)
        : L"-" });
    properties->push_back({ L"非崩溃失败也触发恢复", settings.hasFailureActionsFlag
        ? (settings.failureActionsOnNonCrash ? L"是" : L"否")
        : L"未报告" });
    for (std::size_t index = 0; index < settings.actions.size(); ++index) {
        const ServiceFailureActionSnapshot& action = settings.actions[index];
        properties->push_back({
            L"第 " + std::to_wstring(index + 1) + L" 次失败后的操作",
            action.actionText,
        });
    }
}

void appendReverseDependencyProperties(std::vector<ServiceProperty>* properties,
    const ServiceDependencySnapshot& dependencies,
    const ServiceDetailSection& status) {
    if (!properties) {
        return;
    }
    properties->push_back({ L"反向依赖查询", sectionStatusValue(status) });
    if (status.availability == ServiceDetailAvailability::kAvailable) {
        const std::wstring kNames = joinNames(dependencies.directDependentServiceNames);
        properties->push_back({ L"直接反向依赖服务", kNames.empty() ? L"无" : kNames });
    }
}

ServiceEntry buildEntry(const ks::service::ServiceRecord& record) {
    ServiceEntry entry{};
    entry.serviceName = record.serviceName;
    entry.displayName = record.displayName.empty() ? record.serviceName : record.displayName;
    entry.description = record.description;
    entry.hasStatus = record.hasStatus;
    entry.hasConfig = record.hasConfig;
    entry.hasDescription = record.hasDescription;

    if (record.hasStatus) {
        entry.serviceType = record.status.serviceType;
        entry.currentState = record.status.currentState;
        entry.controlsAccepted = record.status.controlsAccepted;
        entry.win32ExitCode = record.status.win32ExitCode;
        entry.serviceSpecificExitCode = record.status.serviceSpecificExitCode;
        entry.checkPoint = record.status.checkPoint;
        entry.waitHint = record.status.waitHint;
        entry.serviceFlags = record.status.serviceFlags;
        entry.processId = record.status.processId;
    }
    if (record.hasConfig) {
        // The config's service type is the configured one; the status block
        // reports what the SCM currently has loaded. They agree in practice, and
        // the configured value is the one that survives a stopped service.
        entry.serviceType = record.config.serviceType != 0 ? record.config.serviceType : entry.serviceType;
        entry.startType = record.config.startType;
        entry.errorControl = record.config.errorControl;
        entry.tagId = record.config.tagId;
        entry.binaryPath = record.config.binaryPath;
        entry.loadOrderGroup = record.config.loadOrderGroup;
        entry.dependencies = expandDependencyList(record.config.dependenciesMultiSz);
        splitDependencyList(record.config.dependenciesMultiSz,
            &entry.dependencyServiceNames,
            &entry.dependencyLoadOrderGroups);
        entry.accountName = record.config.accountName;
        entry.delayedAutoStart = record.config.delayedAutoStart;
        if (entry.displayName.empty()) {
            entry.displayName = record.config.displayName;
        }
    }

    // A service whose status or config could not be read is kept in the table
    // with the reason attached. Silently dropping it would hide the services an
    // audit most wants to see, since an unreadable config usually means a
    // permission or tampering issue rather than an empty result.
    std::wstring diagnostic;
    if (!record.hasStatus && !record.statusErrorText.empty()) {
        diagnostic += L"状态读取失败：" + widenUtf8(record.statusErrorText);
    }
    if (!record.hasConfig && !record.configErrorText.empty()) {
        if (!diagnostic.empty()) {
            diagnostic += L"；";
        }
        diagnostic += L"配置读取失败：" + widenUtf8(record.configErrorText);
    }
    if (!record.hasDescription && !record.descriptionErrorText.empty()) {
        if (!diagnostic.empty()) {
            diagnostic += L"；";
        }
        diagnostic += L"描述读取失败：" + widenUtf8(record.descriptionErrorText);
    }
    entry.diagnosticText = std::move(diagnostic);

    if (entry.accountName.empty()) {
        entry.accountName = entry.hasConfig ? L"-" : L"未知";
    }
    entry.riskText = buildRiskText(entry);
    return entry;
}

} // namespace

std::wstring serviceDetailAvailabilityText(const ServiceDetailAvailability availability) {
    switch (availability) {
    case ServiceDetailAvailability::kAvailable:
        return L"Available";
    case ServiceDetailAvailability::kUnsupported:
        return L"Unsupported";
    case ServiceDetailAvailability::kPartial:
    default:
        return L"Partial";
    }
}

std::wstring resolveServiceImagePathForBrowser(const std::wstring& binaryPath) {
    return resolveImagePath(executablePathFromCommandLine(binaryPath));
}

ServiceDetailSnapshot queryServiceReadOnlyDetails(const ServiceEntry& entry) {
    ServiceDetailSnapshot snapshot{};
    snapshot.entry = entry;
    snapshot.properties = servicePropertiesForEntry(entry);
    snapshot.dependencies.directServiceNames = entry.dependencyServiceNames;
    snapshot.dependencies.loadOrderGroups = entry.dependencyLoadOrderGroups;

    if (entry.serviceName.empty()) {
        snapshot.failureSettingsStatus = optionalQueryInvalidInput(L"服务名为空，无法查询恢复策略。");
        snapshot.reverseDependenciesStatus = optionalQueryInvalidInput(L"服务名为空，无法查询反向依赖。");
        appendFailureSettingsProperties(&snapshot.properties, snapshot.failureSettings, snapshot.failureSettingsStatus);
        appendReverseDependencyProperties(&snapshot.properties, snapshot.dependencies, snapshot.reverseDependenciesStatus);
        return snapshot;
    }

    ks::service::FailureSettings failureSettings;
    std::string failureErrorText;
    std::uint32_t failureWin32Error = ERROR_SUCCESS;
    if (ks::service::queryServiceFailureSettings(
            entry.serviceName, &failureSettings, &failureErrorText, &failureWin32Error)) {
        snapshot.failureSettings.resetPeriodSeconds = failureSettings.resetPeriodSeconds;
        snapshot.failureSettings.rebootMessage = failureSettings.rebootMessage;
        snapshot.failureSettings.command = failureSettings.command;
        snapshot.failureSettings.failureActionsOnNonCrash = failureSettings.failureActionsOnNonCrash;
        snapshot.failureSettings.hasFailureActions = failureSettings.hasFailureActions;
        snapshot.failureSettings.hasFailureActionsFlag = failureSettings.hasFailureActionsFlag;
        snapshot.failureSettings.actions.reserve(failureSettings.actions.size());
        for (const ks::service::FailureAction& action : failureSettings.actions) {
            ServiceFailureActionSnapshot row{};
            row.actionType = action.type;
            row.delayMs = action.delayMs;
            row.actionText = failureActionText(row.actionType, row.delayMs);
            snapshot.failureSettings.actions.push_back(std::move(row));
        }
    } else {
        snapshot.failureSettingsStatus = optionalQueryFailure(failureErrorText, failureWin32Error);
    }

    std::vector<std::wstring> reverseDependencies;
    std::string reverseErrorText;
    std::uint32_t reverseWin32Error = ERROR_SUCCESS;
    if (ks::service::queryDependentServiceNames(
            entry.serviceName, SERVICE_STATE_ALL, &reverseDependencies, &reverseErrorText, &reverseWin32Error)) {
        snapshot.dependencies.directDependentServiceNames = std::move(reverseDependencies);
    } else {
        snapshot.reverseDependenciesStatus = optionalQueryFailure(reverseErrorText, reverseWin32Error);
    }

    appendFailureSettingsProperties(&snapshot.properties, snapshot.failureSettings, snapshot.failureSettingsStatus);
    appendReverseDependencyProperties(&snapshot.properties, snapshot.dependencies, snapshot.reverseDependenciesStatus);
    return snapshot;
}

ServiceEnumerationResult enumerateServices() {
    ServiceEnumerationResult result{};

    std::vector<ks::service::ServiceRecord> records;
    std::string errorText;
    std::uint32_t win32Error = 0;
    // Drivers are enumerated alongside Win32 services on purpose: on an ARK page
    // the kernel and file-system driver services are the interesting half, and
    // splitting them into a separate view would only hide them.
    const std::uint32_t kTypeMask =
        SERVICE_WIN32 | SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_ADAPTER | SERVICE_RECOGNIZER_DRIVER;
    if (!ks::service::enumerateServiceRecords(kTypeMask, SERVICE_STATE_ALL, &records, &errorText, &win32Error)) {
        result.success = false;
        result.diagnosticText = L"服务枚举失败：" + widenUtf8(errorText);
        return result;
    }

    result.entries.reserve(records.size());
    for (const ks::service::ServiceRecord& record : records) {
        result.entries.push_back(buildEntry(record));
    }
    result.success = true;
    return result;
}

ServiceEnumerationResult querySingleService(const std::wstring& serviceName) {
    ServiceEnumerationResult result{};
    if (serviceName.empty()) {
        result.diagnosticText = L"服务名为空，无法查询。";
        return result;
    }

    ks::service::ServiceRecord record;
    std::string errorText;
    std::uint32_t win32Error = 0;
    if (!ks::service::queryServiceRecord(serviceName, &record, &errorText, &win32Error)) {
        result.diagnosticText = L"查询服务失败：" + widenUtf8(errorText);
        return result;
    }
    result.entries.push_back(buildEntry(record));
    result.success = true;
    return result;
}

} // namespace Ksword::Features::Service

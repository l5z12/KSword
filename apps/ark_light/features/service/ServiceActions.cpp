#include "ServiceActions.h"

#include "../../../../shared/platform/service/Service.h"

#include <string>

namespace ksword::features::service {
namespace {

// kTransitionTimeoutMs bounds every wait. The SCM reports a service's own
// waitHint, but a service that ignores its hint would otherwise hang the worker
// thread indefinitely; 30 seconds matches what the Services MMC snap-in allows
// before it gives up and tells the user the request timed out.
constexpr std::uint32_t kTransitionTimeoutMs = 30000;

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

ServiceActionResult finishTransition(
    const bool succeeded,
    const std::wstring& serviceName,
    const wchar_t* actionLabel,
    const ks::service::ServiceStatus& finalStatus,
    const std::string& errorText) {
    ServiceActionResult result{};
    result.success = succeeded;
    if (succeeded) {
        result.message = std::wstring(L"服务 ") + serviceName + L" " + actionLabel + L"成功，当前状态：" +
            serviceStateText(finalStatus.currentState) + L"。";
        return result;
    }
    result.message = std::wstring(L"服务 ") + serviceName + L" " + actionLabel + L"失败：" + widenUtf8(errorText);
    return result;
}

} // namespace

ServiceActionResult startServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    const bool kSucceeded = ks::service::startServiceByName(
        serviceName, kTransitionTimeoutMs, SERVICE_RUNNING, &finalStatus, &errorText);
    return finishTransition(kSucceeded, serviceName, L"启动", finalStatus, errorText);
}

ServiceActionResult stopServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    const bool kSucceeded = ks::service::stopServiceByName(
        serviceName, kTransitionTimeoutMs, SERVICE_STOPPED, &finalStatus, &errorText);
    return finishTransition(kSucceeded, serviceName, L"停止", finalStatus, errorText);
}

ServiceActionResult pauseServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    const bool kSucceeded = ks::service::controlServiceByName(
        serviceName,
        SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        SERVICE_CONTROL_PAUSE,
        kTransitionTimeoutMs,
        SERVICE_PAUSED,
        &finalStatus,
        &errorText);
    return finishTransition(kSucceeded, serviceName, L"暂停", finalStatus, errorText);
}

ServiceActionResult continueServiceEntry(const std::wstring& serviceName) {
    ks::service::ServiceStatus finalStatus{};
    std::string errorText;
    const bool kSucceeded = ks::service::controlServiceByName(
        serviceName,
        SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS,
        SERVICE_CONTROL_CONTINUE,
        kTransitionTimeoutMs,
        SERVICE_RUNNING,
        &finalStatus,
        &errorText);
    return finishTransition(kSucceeded, serviceName, L"继续", finalStatus, errorText);
}

ServiceActionResult applyServiceStartType(const std::wstring& serviceName, const ServiceStartTypeChoice choice) {
    ServiceActionResult result{};
    if (serviceName.empty()) {
        result.message = L"未选择服务，无法修改启动类型。";
        return result;
    }

    ks::service::ServiceConfigUpdate update{};
    update.changeStartType = true;
    bool wantsDelayedAutoStart = false;
    const wchar_t* choiceLabel = L"";
    switch (choice) {
    case ServiceStartTypeChoice::kAutomatic:
        update.startType = SERVICE_AUTO_START;
        choiceLabel = L"自动";
        break;
    case ServiceStartTypeChoice::kAutomaticDelayed:
        update.startType = SERVICE_AUTO_START;
        wantsDelayedAutoStart = true;
        choiceLabel = L"自动(延迟)";
        break;
    case ServiceStartTypeChoice::kManual:
        update.startType = SERVICE_DEMAND_START;
        choiceLabel = L"手动";
        break;
    case ServiceStartTypeChoice::kDisabled:
        update.startType = SERVICE_DISABLED;
        choiceLabel = L"禁用";
        break;
    }

    std::string errorText;
    if (!ks::service::changeServiceConfiguration(serviceName, update, &errorText)) {
        result.message = std::wstring(L"服务 ") + serviceName + L" 启动类型修改失败：" + widenUtf8(errorText);
        return result;
    }

    // The delayed flag only has meaning for automatic start, and Windows keeps
    // it in a separate config block. It is written on both automatic choices so
    // switching away from delayed actually clears it.
    if (update.startType == SERVICE_AUTO_START) {
        std::string delayedErrorText;
        if (!ks::service::setDelayedAutoStart(serviceName, wantsDelayedAutoStart, &delayedErrorText)) {
            result.success = false;
            result.message = std::wstring(L"服务 ") + serviceName + L" 启动类型已改为自动，但延迟启动标志写入失败：" +
                widenUtf8(delayedErrorText);
            return result;
        }
    }

    result.success = true;
    result.message = std::wstring(L"服务 ") + serviceName + L" 启动类型已改为" + choiceLabel + L"。";
    return result;
}

} // namespace Ksword::Features::Service

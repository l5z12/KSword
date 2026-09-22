#include "RegistryFeature.h"

#include "RegistrySearchView.h"
#include "RegistryView.h"
#include "../../ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace ksword::features::registry {
namespace {

constexpr int kRegistryBrowserTab = 63110;
constexpr int kRegistrySearchTab = 63111;

} // namespace

HWND createRegistryFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<ksword::ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kRegistryBrowserTab, L"注册表浏览", L"按需浏览当前 WinAPI 或现有 R0 注册表视图。",
        [](HWND host, const RECT& pageBounds) { return createRegistryView(host, pageBounds); } });
    tabs.push_back({ kRegistrySearchTab, L"递归搜索", L"只读、有界的当前进程 WinAPI 注册表搜索。",
        [](HWND host, const RECT& pageBounds) { return createRegistrySearchView(host, pageBounds); } });

    ksword::ui::WorkspaceOptions options{};
    options.tabControlId = 63101;
    options.initialTabId = kRegistryBrowserTab;
    options.margin = 6;
    return ksword::ui::createWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

bool requestRegistryFeatureNavigate(HWND page, const std::wstring& path) {
    if (!page || path.empty() || !ksword::ui::activateWorkspaceHostTab(page, kRegistryBrowserTab, true)) {
        return false;
    }
    HWND browserPage = ksword::ui::workspaceHostPage(page, kRegistryBrowserTab, true);
    return requestRegistryViewNavigate(browserPage, path);
}

} // namespace Ksword::Features::Registry

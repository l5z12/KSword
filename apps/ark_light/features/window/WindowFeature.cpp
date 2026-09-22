#include "WindowFeature.h"

#include "WindowView.h"
#include "../window_tools/WindowToolsClipboardView.h"
#include "../window_tools/WindowToolsHotkeyView.h"
#include "../window_tools/WindowToolsHierarchyView.h"
#include "../../ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace ksword::features::window {
namespace {

constexpr int kWindowManagerTab = 62410;
constexpr int kClipboardTab = 62411;
constexpr int kHotkeyTab = 62412;
constexpr int kHierarchyTab = 62413;

} // namespace

HWND createWindowFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<ksword::ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kWindowManagerTab, L"窗口管理", L"按需枚举窗口并加载层级诊断。",
        [](HWND host, const RECT& pageBounds) { return createWindowFeatureView(host, pageBounds); } });
    tabs.push_back({ kClipboardTab, L"剪贴板查看", L"按需读取当前剪贴板格式。",
        [](HWND host, const RECT& pageBounds) {
            return window_tools::createClipboardInspectorView(host, pageBounds);
        } });
    tabs.push_back({ kHotkeyTab, L"热键占用探测", L"按需扫描全局热键占用。",
        [](HWND host, const RECT& pageBounds) { return window_tools::createHotkeyProbeView(host, pageBounds); } });
    tabs.push_back({ kHierarchyTab, L"层级诊断", L"按需枚举窗口层级并导出可见报告。",
        [](HWND host, const RECT& pageBounds) { return window_tools::createWindowHierarchyView(host, pageBounds); } });

    ksword::ui::WorkspaceOptions options{};
    options.tabControlId = 62401;
    options.initialTabId = kWindowManagerTab;
    options.margin = 6;
    return ksword::ui::createWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

bool requestWindowFeatureQuery(HWND page, const std::wstring& query) {
    if (!page || query.empty() || !ksword::ui::activateWorkspaceHostTab(page, kWindowManagerTab, true)) {
        return false;
    }
    HWND windowPage = ksword::ui::workspaceHostPage(page, kWindowManagerTab, true);
    return requestWindowFeatureViewQuery(windowPage, query);
}

} // namespace Ksword::Features::Window

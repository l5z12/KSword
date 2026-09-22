#include "SysToolsFeature.h"

#include "ContextMenuView.h"
#include "EventLogView.h"
#include "FileHolderView.h"
#include "IoctlDecoderView.h"
#include "SystemTimeView.h"
#include "../../ui/WorkspaceHost.h"

#include <utility>
#include <vector>

namespace ksword::features::sys_tools {
namespace {

constexpr int kFileHolderTab = 67010;
constexpr int kEventLogTab = 67011;
constexpr int kContextMenuTab = 67012;
constexpr int kSystemTimeTab = 67013;
constexpr int kIoctlDecoderTab = 67014;

} // namespace

HWND createSysToolsFeaturePage(HWND parent, const RECT& bounds) {
    std::vector<ksword::ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kFileHolderTab, L"文件占用", L"按需扫描文件占用者。",
        [](HWND host, const RECT& pageBounds) { return createFileHolderView(host, pageBounds); } });
    tabs.push_back({ kEventLogTab, L"事件日志", L"按需查询事件日志。",
        [](HWND host, const RECT& pageBounds) { return createEventLogView(host, pageBounds); } });
    tabs.push_back({ kContextMenuTab, L"右键菜单", L"按需扫描 Shell 扩展。",
        [](HWND host, const RECT& pageBounds) { return createContextMenuView(host, pageBounds); } });
    tabs.push_back({ kSystemTimeTab, L"系统时间", L"按需采集系统时间和时区证据。",
        [](HWND host, const RECT& pageBounds) { return createSystemTimeView(host, pageBounds); } });
    tabs.push_back({ kIoctlDecoderTab, L"IOCTL 解码", L"离线拆解 CTL_CODE 位字段，不访问驱动。",
        [](HWND host, const RECT& pageBounds) { return createIoctlDecoderView(host, pageBounds); } });

    ksword::ui::WorkspaceOptions options{};
    options.tabControlId = 67001;
    options.initialTabId = kFileHolderTab;
    options.margin = 8;
    return ksword::ui::createWorkspaceHost(parent, bounds, std::move(tabs), std::move(options));
}

} // namespace Ksword::Features::SysTools

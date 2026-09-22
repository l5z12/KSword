#include "DriverFeature.h"

#include "DriverActions.h"
#include "DriverDebugOutputView.h"
#include "DriverEnumerator.h"
#include "DriverModel.h"
#include "DriverObjectView.h"
#include "DriverOverviewView.h"
#include "DriverUnloadedView.h"
#include "../kernel/KernelFeature.h"
#include "../../ui/Controls.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TabUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/WorkspaceHost.h"

#include <commctrl.h>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

namespace ksword::features::driver {
namespace {

constexpr wchar_t kDriverFeatureClass[] = L"KswordARKLight.DriverFeaturePage";
constexpr int kRefreshButtonId = 65001;
constexpr int kExportButtonId = 65002;
constexpr int kTabControlId = 65003;
constexpr int kStatusTextId = 65004;
constexpr int kOverviewTabIndex = 0;
constexpr int kObjectTabIndex = 1;
constexpr int kIntegrityTabIndex = 2;
// Unloaded-driver evidence sits next to integrity because they answer the same
// question from opposite ends: integrity checks the drivers that are still here,
// this one checks the traces of the ones that are not.
constexpr int kUnloadedTabIndex = 3;
constexpr int kDynDataCapabilitiesTabIndex = 4;
constexpr int kDriverStatusTabIndex = 5;
constexpr int kDynDataTabIndex = 6;
constexpr int kDebugOutputTabIndex = 7;
constexpr int kLoadingOverlayId = 65009;
constexpr UINT kMsgRefreshCompleted = WM_APP + 590;

// DriverFeaturePageState owns the root page HWND, local driver views, and
// retained KernelPage-backed migration tabs. Inputs arrive through Win32
// messages; processing coordinates refresh/export for local tables and keeps
// every migrated page HWND alive for the lifetime of this dock page.
struct DriverFeaturePageState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND statusText = nullptr;
    HWND workspace = nullptr;
    HWND overviewView = nullptr;
    HWND objectView = nullptr;
    HWND integrityView = nullptr;
    HWND unloadedView = nullptr;
    HWND dynDataCapabilitiesView = nullptr;
    HWND driverStatusView = nullptr;
    HWND dynDataView = nullptr;
    HWND debugOutputView = nullptr;
    HWND loadingOverlay = nullptr;
    DriverModel model;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<DriverEnumerationResult>> refreshTask;
};

// stateFromWindow returns the page state stored on the HWND. Input is the page
// window; processing reads GWLP_USERDATA; output is null during creation or
// after destruction.
DriverFeaturePageState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// Width returns a non-negative rectangle width. Input is a RECT; output is the
// usable client width in pixels.
int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns a non-negative rectangle height. Input is a RECT; output is
// the usable client height in pixels.
int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// layoutChildren positions the toolbar, tab control, and active subview.
// Input is page state; processing uses the current client rect; no value is
// returned.
void layoutChildren(DriverFeaturePageState& state) {
    if (!state.hwnd) {
        return;
    }

    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    const int kMargin = 8;
    const int kToolbarHeight = 30;
    const int kButtonWidth = 82;
    const int kButtonGap = 6;

    ::MoveWindow(state.refreshButton, kMargin, kMargin, kButtonWidth, 24, TRUE);
    ::MoveWindow(state.exportButton, kMargin + kButtonWidth + kButtonGap, kMargin, kButtonWidth, 24, TRUE);
    ::MoveWindow(state.statusText, kMargin + (kButtonWidth + kButtonGap) * 2 + 16, kMargin + 2, std::max(80, kWidth - 240), 20, TRUE);

    const int kTabTop = kMargin + kToolbarHeight;
    ::MoveWindow(state.workspace, kMargin, kTabTop, std::max(100, kWidth - kMargin * 2), std::max(100, kHeight - kTabTop - kMargin), TRUE);
    if (state.loadingOverlay) {
        RECT workspaceBounds{};
        ::GetWindowRect(state.workspace, &workspaceBounds);
        ::MapWindowPoints(nullptr, state.hwnd, reinterpret_cast<POINT*>(&workspaceBounds), 2);
        ::MoveWindow(state.loadingOverlay,
            workspaceBounds.left,
            workspaceBounds.top,
            std::max(1, width(workspaceBounds)),
            std::max(1, height(workspaceBounds)),
            TRUE);
    }
}

// setStatus writes a short footer message. Inputs are page state and text;
// processing updates the read-only static control; no value is returned.
void setStatus(DriverFeaturePageState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

// refreshFeatureModel pulls the latest snapshot and redraws the local driver
// overview/object subviews. Input is page state; processing uses DriverActions
// and the local model only; KernelPage-backed migration tabs keep their own
// refresh controls and state; no value is returned.
void refreshFeatureModel(DriverFeaturePageState& state) {
    if (!state.refreshTask) {
        return;
    }
    setStatus(state, state.refreshTask->running() ? L"驱动刷新已排队，等待当前快照完成…" : L"正在后台刷新驱动概览和对象信息…");
    ::EnableWindow(state.refreshButton, FALSE);
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在加载驱动快照…");
    state.refreshTask->request(
        [] { return enumerateDriverSnapshot(); },
        [&state](std::uint64_t, std::optional<DriverEnumerationResult>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(state.refreshButton, TRUE);
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                setStatus(state, L"驱动后台枚举异常结束。请检查权限和驱动状态。");
                return;
            }
            state.model.setOverviewRows(std::move(snapshot->overviewRows));
            state.model.setObjectRows(std::move(snapshot->objectRows));
            refreshDriverOverviewView(state.overviewView);
            refreshDriverObjectView(state.objectView);
            setStatus(state, snapshot->diagnosticText.empty() ? L"驱动数据已刷新。" : snapshot->diagnosticText);
        });
}

// exportCurrentTabTsv saves the active local table as UTF-8 TSV. It only uses
// the pre-filtered visible-row export helpers and leaves Kernel-rendered tabs
// with their own page-local export commands.
void exportCurrentTabTsv(DriverFeaturePageState& state) {
    const int kCurrentTab = ksword::ui::workspaceHostActiveTabId(state.workspace);
    if (kCurrentTab == kIntegrityTabIndex ||
        kCurrentTab == kDynDataCapabilitiesTabIndex ||
        kCurrentTab == kDriverStatusTabIndex ||
        kCurrentTab == kDynDataTabIndex ||
        kCurrentTab == kDebugOutputTabIndex) {
        setStatus(state, L"当前页使用自身的复制或导出命令。");
        return;
    }

    // WorkspaceHost defers page creation after a tab switch. A toolbar command
    // is synchronous, so materialize only the local exportable page before
    // reading its visible virtual-list rows.
    const HWND kActivePage = ksword::ui::workspaceHostPage(state.workspace, kCurrentTab, true);
    if (!kActivePage) {
        setStatus(state, L"当前页尚未就绪，无法导出 TSV。");
        return;
    }

    std::wstring tsv;
    const wchar_t* suggestedFileName = L"ksword-arklight-driver-overview.tsv";
    const wchar_t* dialogTitle = L"导出驱动概览 TSV";
    if (kCurrentTab == kObjectTabIndex) {
        tsv = exportDriverObjectViewTsv(kActivePage);
        suggestedFileName = L"ksword-arklight-driver-objects.tsv";
        dialogTitle = L"导出驱动对象 TSV";
    } else if (kCurrentTab == kUnloadedTabIndex) {
        tsv = exportDriverUnloadedViewTsv(kActivePage);
        suggestedFileName = L"ksword-arklight-unloaded-drivers.tsv";
        dialogTitle = L"导出已卸载驱动 TSV";
    } else if (kCurrentTab == kOverviewTabIndex) {
        tsv = exportDriverOverviewViewTsv(kActivePage);
    } else {
        setStatus(state, L"当前页不支持顶栏 TSV 导出。");
        return;
    }

    if (tsv.empty()) {
        setStatus(state, L"当前没有可导出的可见 TSV 内容。");
        return;
    }

    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd,
        suggestedFileName,
        dialogTitle,
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        tsv,
        &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(state, L"当前可见 TSV 已导出并记录到证据会话。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(state, L"已取消 TSV 导出。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
    default:
        setStatus(state, L"TSV 导出失败：" + error);
        break;
    }
}

// createChildControls builds the page toolbar, local driver tabs, and retained
// KernelPage-backed migration tabs. Input is page state with hwnd already
// stored; processing creates each child page exactly once; output is true when
// all required child HWNDs exist.
bool createChildControls(DriverFeaturePageState& state) {
    state.refreshButton = ksword::ui::createButton(state.hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(state.hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.statusText = ksword::ui::createText(state.hwnd, kStatusTextId, L"准备刷新驱动数据。", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.statusText) {
        return false;
    }

    std::vector<ksword::ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kOverviewTabIndex, L"驱动概览", L"按需创建驱动概览视图。",
        [&state](HWND host, const RECT& bounds) {
            state.overviewView = createDriverOverviewView(host, bounds, &state.model);
            return state.overviewView;
        } });
    tabs.push_back({ kObjectTabIndex, L"对象信息", L"按需创建驱动对象视图。",
        [&state](HWND host, const RECT& bounds) {
            state.objectView = createDriverObjectView(host, bounds, &state.model);
            return state.objectView;
        } });
    tabs.push_back({ kIntegrityTabIndex, L"驱动完整性", L"按需加载驱动完整性审计。",
        [&state](HWND host, const RECT& bounds) {
            state.integrityView = kernel::createKernelSingleFeaturePage(host, 65005, bounds, kernel::KernelFeatureId::kDriverIntegrity);
            return state.integrityView;
        } });
    tabs.push_back({ kUnloadedTabIndex, L"已卸载驱动", L"按需查询已卸载驱动证据。",
        [&state](HWND host, const RECT& bounds) {
            state.unloadedView = createDriverUnloadedView(host, bounds);
            return state.unloadedView;
        } });
    tabs.push_back({ kDynDataCapabilitiesTabIndex, L"DynData能力", L"按需加载 DynData 能力矩阵。",
        [&state](HWND host, const RECT& bounds) {
            state.dynDataCapabilitiesView = kernel::createKernelSingleFeaturePage(host, 65006, bounds, kernel::KernelFeatureId::kDynDataCapabilities);
            return state.dynDataCapabilitiesView;
        } });
    tabs.push_back({ kDriverStatusTabIndex, L"驱动状态", L"按需加载驱动状态页。",
        [&state](HWND host, const RECT& bounds) {
            state.driverStatusView = kernel::createKernelSingleFeaturePage(host, 65007, bounds, kernel::KernelFeatureId::kDriverStatus);
            return state.driverStatusView;
        } });
    tabs.push_back({ kDynDataTabIndex, L"动态偏移 / DynData", L"按需加载动态偏移页。",
        [&state](HWND host, const RECT& bounds) {
            state.dynDataView = kernel::createKernelSingleFeaturePage(host, 65008, bounds, kernel::KernelFeatureId::kDynData);
            return state.dynDataView;
        } });
    tabs.push_back({ kDebugOutputTabIndex, L"调试输出", L"按需启动驱动调试输出接收。",
        [&state](HWND host, const RECT& bounds) {
            state.debugOutputView = createDriverDebugOutputView(host, bounds);
            return state.debugOutputView;
        } });

    ksword::ui::WorkspaceOptions options{};
    options.tabControlId = kTabControlId;
    options.initialTabId = kOverviewTabIndex;
    options.pageActivated = [&state](const int tabId, HWND) {
        if (tabId == kOverviewTabIndex && state.overviewView) {
            refreshDriverOverviewView(state.overviewView);
        } else if (tabId == kObjectTabIndex && state.objectView) {
            refreshDriverObjectView(state.objectView);
        }
    };
    state.workspace = ksword::ui::createWorkspaceHost(
        state.hwnd, { 0, 0, 1, 1 }, std::move(tabs), std::move(options));
    if (!state.workspace) {
        return false;
    }
    state.loadingOverlay = ksword::ui::createLoadingOverlay(state.hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(state.hwnd);
    return true;
}

// registerDriverFeatureClass installs the root page class once. There is no
// input; processing is idempotent; output is true when the class can be used.
bool registerDriverFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DriverFeaturePageState* state = stateFromWindow(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DriverFeaturePageState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!createChildControls(*state)) {
                    // CreateWindowExW returns nullptr after WM_CREATE fails;
                    // ownership then stays with createDriverFeaturePage. Clear
                    // the HWND association so the ensuing WM_NCDESTROY cannot
                    // free the state before that caller releases it.
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<DriverEnumerationResult>>(hwnd, kMsgRefreshCompleted);
                layoutChildren(*state);
                refreshFeatureModel(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                layoutChildren(*state);
            }
            return 0;
        case kMsgRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_COMMAND:
            if (state && HIWORD(wParam) == BN_CLICKED) {
                switch (LOWORD(wParam)) {
                case kRefreshButtonId:
                    refreshFeatureModel(*state);
                    return 0;
                case kExportButtonId:
                    exportCurrentTabTsv(*state);
                    return 0;
                default:
                    break;
                }
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
        }
        case WM_NCDESTROY:
            if (state && state->refreshTask) {
                state->refreshTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }

        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kDriverFeatureClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createDriverFeaturePage(HWND parent, const RECT& bounds) {
    if (!parent || !registerDriverFeatureClass()) {
        return nullptr;
    }

    auto* state = new DriverFeaturePageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kDriverFeatureClass,
        L"驱动",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

void resizeDriverFeaturePage(HWND page, const RECT& bounds) {
    if (page) {
        ::MoveWindow(page,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

} // namespace Ksword::Features::Driver

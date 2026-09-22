#include "NetworkView.h"

#include "NetworkModel.h"
#include "../net_tools/NetToolsConnectionView.h"
#include "../net_tools/NetToolsDiagnosticView.h"
#include "../net_tools/NetToolsFirewallView.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TabUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"
#include "../../ui/WorkspaceHost.h"

#include <algorithm>
#include <commctrl.h>
#include <windowsx.h>

#include <cstdint>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::network {
namespace {

constexpr wchar_t kNetworkViewClass[] = L"KswordARKLight.NetworkFeatureView";
constexpr wchar_t kNetworkAuditPageClass[] = L"KswordARKLight.NetworkAuditPage";

constexpr int kTabControlId = 69005;
constexpr int kAuditRefreshButtonId = 69001;
constexpr int kAuditExportButtonId = 69002;
constexpr int kAuditStatusTextId = 69003;
constexpr int kAuditSummaryTextId = 69004;
constexpr int kAuditListViewId = 69006;
constexpr int kAuditFilterBarId = 69007;
constexpr int kAuditLoadingOverlayId = 69008;

constexpr UINT kMenuCopyCell = 69101;
constexpr UINT kMenuCopyRow = 69102;
constexpr UINT kMenuCopyVisible = 69103;
constexpr UINT kMsgRefreshCompleted = WM_APP + 595;
constexpr UINT kMsgFilterCompleted = WM_APP + 596;

constexpr int kConnectionTabIndex = 0;
constexpr int kDiagnosticTabIndex = 1;
constexpr int kFirewallTabIndex = 2;
constexpr int kFirstAuditTabIndex = 3;
constexpr int kAuditTabCount = 5;

struct NetworkViewState;

struct NetworkFilterResult final {
    int auditIndex = -1;
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct NetworkAuditPageState final {
    NetworkViewState* owner = nullptr;
    int auditIndex = -1;
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND statusText = nullptr;
    HWND summaryText = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView list;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    int contextColumn = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<NetworkFilterResult>> filterTask;
};

struct NetworkViewState final {
    HWND hwnd = nullptr;
    HWND workspace = nullptr;
    HWND connectionView = nullptr;
    HWND diagnosticView = nullptr;
    HWND firewallView = nullptr;
    NetworkAuditModel model;
    std::vector<std::unique_ptr<NetworkAuditPageState>> auditPages;
    bool auditRefreshStarted = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<std::vector<NetworkAuditPage>>> refreshTask;
};

NetworkViewState* networkStateFromWindow(HWND hwnd) {
    return reinterpret_cast<NetworkViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

NetworkAuditPageState* auditStateFromWindow(HWND hwnd) {
    return reinterpret_cast<NetworkAuditPageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

int height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

NetworkAuditPageState* auditPageFor(NetworkViewState& state, const int auditIndex) {
    if (auditIndex < 0 || auditIndex >= static_cast<int>(state.auditPages.size())) {
        return nullptr;
    }
    return state.auditPages[static_cast<std::size_t>(auditIndex)].get();
}

void setStatus(NetworkAuditPageState& page, const std::wstring& text) {
    if (page.statusText) {
        ::SetWindowTextW(page.statusText, text.c_str());
    }
}

void setSummary(NetworkAuditPageState& page, const std::wstring& text) {
    if (page.summaryText) {
        ::SetWindowTextW(page.summaryText, text.c_str());
    }
}

bool copyTextToClipboard(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"网络审计");
}

std::vector<std::wstring> columnTitles(const NetworkAuditPage& page) {
    std::vector<std::wstring> titles;
    titles.reserve(page.columns.size());
    for (const NetworkAuditColumn& column : page.columns) {
        titles.push_back(column.title);
    }
    return titles;
}

std::wstring buildVisiblePageTsv(const NetworkAuditPageState& page) {
    if (!page.owner) {
        return {};
    }
    const NetworkAuditPage* audit = page.owner->model.pageAt(page.auditIndex);
    return audit ? ksword::ui::buildVisibleVirtualListTsv(columnTitles(*audit), page.list) : std::wstring();
}

void applyColumns(NetworkAuditPageState& page, const NetworkAuditPage& audit) {
    ksword::ui::clearListViewColumns(page.list.hwnd());
    std::vector<ksword::ui::ListViewColumn> columns;
    columns.reserve(audit.columns.size());
    for (std::size_t index = 0; index < audit.columns.size(); ++index) {
        columns.push_back({ static_cast<int>(index), audit.columns[index].width, audit.columns[index].format, audit.columns[index].title });
    }
    page.list.addColumns(columns);
}

void applyNetworkFilter(NetworkViewState& state, NetworkFilterResult result) {
    NetworkAuditPageState* page = auditPageFor(state, result.auditIndex);
    if (!page || result.generation != page->displayGeneration || result.query != page->filterQuery ||
        result.useRegex != page->filterUseRegex) {
        return;
    }
    page->list.setVisibleIndexes(std::move(result.visibleIndexes));
    if (!page->filterQuery.empty()) {
        setStatus(*page, L"Network 筛选结果 " + std::to_wstring(page->list.rowCount()) + L" 项。");
    }
}

void requestNetworkFilter(NetworkAuditPageState& page, std::wstring query) {
    if (!page.owner) {
        return;
    }
    page.filterQuery = std::move(query);
    page.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(page.filterBar);
    const auto kRows = page.filterRows;
    const int kAuditIndex = page.auditIndex;
    const std::uint64_t kGeneration = page.displayGeneration;
    const bool kUseRegex = page.filterUseRegex;
    if (!page.filterTask || !kRows) {
        return;
    }
    page.filterTask->request(
        [kRows, kAuditIndex, kGeneration, kUseRegex, query = page.filterQuery]() mutable {
            NetworkFilterResult result{};
            result.auditIndex = kAuditIndex;
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&page](std::uint64_t, std::optional<NetworkFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setStatus(page, L"Network 筛选任务异常结束，已保留当前可见结果。");
                return;
            }
            if (page.owner) {
                applyNetworkFilter(*page.owner, std::move(*result));
            }
        });
}

void renderAuditPage(NetworkAuditPageState& page) {
    if (!page.owner) {
        return;
    }
    const NetworkAuditPage* audit = page.owner->model.pageAt(page.auditIndex);
    if (!audit) {
        setSummary(page, L"正在等待后台 Network 审计快照…");
        page.list.setRows({});
        page.filterRows.reset();
        return;
    }
    applyColumns(page, *audit);
    auto rows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>();
    rows->reserve(audit->rows.size());
    for (std::size_t index = 0; index < audit->rows.size(); ++index) {
        ksword::ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(index);
        row.cells = audit->rows[index].cells;
        for (const std::wstring& cell : row.cells) {
            row.stableKey += L"|" + cell;
        }
        rows->push_back(std::move(row));
    }
    page.list.setRows(*rows);
    page.list.setVisibleIndexes({});
    page.filterRows = std::move(rows);
    ++page.displayGeneration;
    setSummary(page, audit->summary);
    requestNetworkFilter(page, page.filterBar ? ksword::ui::getFilterBarText(page.filterBar) : page.filterQuery);
}

void renderAllAuditPages(NetworkViewState& state) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page) {
            renderAuditPage(*page);
        }
    }
}

void setAuditRefreshEnabled(NetworkViewState& state, const BOOL enabled) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page && page->refreshButton) {
            ::EnableWindow(page->refreshButton, enabled);
        }
    }
}

void setAuditLoading(NetworkViewState& state, const bool visible, const wchar_t* text) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page) {
            ksword::ui::setLoadingOverlay(page->loadingOverlay, visible, text);
        }
    }
}

void setAuditStatusForAll(NetworkViewState& state, const std::wstring& text) {
    for (const std::unique_ptr<NetworkAuditPageState>& page : state.auditPages) {
        if (page) {
            setStatus(*page, text);
        }
    }
}

void beginNetworkRefresh(NetworkViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.model.pages().empty();
    setAuditStatusForAll(state, state.refreshTask->running()
        ? L"Network 刷新已排队，等待当前快照完成…"
        : L"正在后台采集 TCP、UDP、WFP、NDIS、AFD 和 NSI 审计…");
    setAuditRefreshEnabled(state, FALSE);
    if (kFirstLoad) {
        setAuditLoading(state, true, L"正在加载 Network 审计…");
    }
    state.refreshTask->request(
        [] { return buildNetworkAuditPages(); },
        [&state](std::uint64_t, std::optional<std::vector<NetworkAuditPage>>&& pages, std::exception_ptr error) {
            setAuditRefreshEnabled(state, TRUE);
            setAuditLoading(state, false, L"");
            if (error || !pages.has_value()) {
                setAuditStatusForAll(state, L"Network 后台审计异常结束。请检查驱动状态与访问权限。");
                return;
            }
            state.model.replacePages(std::move(*pages));
            renderAllAuditPages(state);
            setAuditStatusForAll(state, L"Network R0 与 R3 审计快照已刷新。");
        });
}

std::wstring selectedRowsText(const NetworkAuditPageState& page, const bool allVisible) {
    const HWND kList = page.list.hwnd();
    const auto& rows = page.list.rows();
    std::wstring text;
    const auto& visible = page.list.visibleIndexes();
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            continue;
        }
        const std::size_t kSource = visible[item];
        if (kSource < rows.size()) {
            for (std::size_t column = 0; column < rows[kSource].cells.size(); ++column) {
                if (column != 0) {
                    text.push_back(L'\t');
                }
                text += rows[kSource].cells[column];
            }
            text += L"\r\n";
        }
    }
    return text;
}

std::wstring selectedCellText(const NetworkAuditPageState& page) {
    const HWND kList = page.list.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = page.list.visibleIndexes();
    const auto& rows = page.list.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return {};
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || page.contextColumn < 0 || static_cast<std::size_t>(page.contextColumn) >= rows[kSource].cells.size()) {
        return {};
    }
    return rows[kSource].cells[static_cast<std::size_t>(page.contextColumn)];
}

void showListContextMenu(NetworkAuditPageState& page, POINT point) {
    POINT client = point;
    ::ScreenToClient(page.list.hwnd(), &client);
    LVHITTESTINFO hit{};
    hit.pt = client;
    const int kHitItem = ListView_SubItemHitTest(page.list.hwnd(), &hit);
    if (kHitItem >= 0) {
        page.contextColumn = hit.iSubItem;
        ListView_SetItemState(page.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(page.list.hwnd(), kHitItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool kHasSelection = ListView_GetNextItem(page.list.hwnd(), -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!page.list.visibleIndexes().empty() ? 0U : MF_GRAYED), kMenuCopyVisible, L"复制可见结果");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, point.x, point.y, 0, page.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kMenuCopyCell) {
        setStatus(page, copyTextToClipboard(page.hwnd, selectedCellText(page)) ? L"已复制单元格。" : L"复制单元格失败。");
    } else if (kCommand == kMenuCopyRow) {
        setStatus(page, copyTextToClipboard(page.hwnd, selectedRowsText(page, false)) ? L"已复制行。" : L"复制行失败。");
    } else if (kCommand == kMenuCopyVisible) {
        setStatus(page, copyTextToClipboard(page.hwnd, selectedRowsText(page, true)) ? L"已复制可见结果。" : L"复制可见结果失败。");
    }
}

void exportAuditPage(NetworkAuditPageState& page) {
    const std::wstring kText = buildVisiblePageTsv(page);
    if (kText.empty()) {
        setStatus(page, L"没有可导出的当前可见 Network 审计结果。");
        return;
    }
    std::wstring error;
    const std::wstring kFileName = L"network_audit_" + std::to_wstring(page.auditIndex + 1) + L".tsv";
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        page.hwnd, kFileName.c_str(), L"导出 Network 审计",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(page, L"已导出当前可见 Network 审计结果。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(page, L"已取消导出 Network 审计结果。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        setStatus(page, L"导出 Network 审计结果失败：" + error);
        break;
    }
}

void layoutAuditPage(NetworkAuditPageState& page) {
    RECT client{};
    ::GetClientRect(page.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);
    constexpr int kMargin = 8;
    constexpr int kButtonGap = 6;
    ::MoveWindow(page.refreshButton, kMargin, kMargin, 64, 24, TRUE);
    ::MoveWindow(page.exportButton, kMargin + 64 + kButtonGap, kMargin, 82, 24, TRUE);
    ::MoveWindow(page.statusText, kMargin + 64 + kButtonGap + 82 + 16, kMargin + 2,
        (std::max)(100, kWidth - 188), 20, TRUE);
    const int kSummaryTop = kMargin + 30;
    ::MoveWindow(page.summaryText, kMargin, kSummaryTop, (std::max)(100, kWidth - kMargin * 2), 38, TRUE);
    const int kFilterTop = kSummaryTop + 42;
    ::MoveWindow(page.filterBar, kMargin, kFilterTop, (std::max)(100, kWidth - kMargin * 2), 24, TRUE);
    const int kListTop = kFilterTop + 28;
    const int kListHeight = (std::max)(1, kHeight - kListTop - kMargin);
    ::MoveWindow(page.list.hwnd(), kMargin, kListTop, (std::max)(1, kWidth - kMargin * 2), kListHeight, TRUE);
    ::MoveWindow(page.loadingOverlay, kMargin, kListTop, (std::max)(1, kWidth - kMargin * 2), kListHeight, TRUE);
}

bool createAuditPageControls(NetworkAuditPageState& page) {
    page.refreshButton = ksword::ui::createButton(page.hwnd, kAuditRefreshButtonId, L"刷新", 0, 0, 0, 0);
    page.exportButton = ksword::ui::createButton(page.hwnd, kAuditExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    page.statusText = ksword::ui::createText(page.hwnd, kAuditStatusTextId, L"Network 审计准备就绪。", 0, 0, 0, 0);
    page.summaryText = ksword::ui::createText(page.hwnd, kAuditSummaryTextId, L"", 0, 0, 0, 0);
    page.filterBar = ksword::ui::createFilterBar(page.hwnd, kAuditFilterBarId, L"筛选当前页所有列和详情文本", 0, 0, 0, 0);
    if (!page.refreshButton || !page.exportButton || !page.statusText || !page.summaryText || !page.filterBar ||
        !page.list.create(page.hwnd, kAuditListViewId, 0, 0, 1, 1, LVS_SHOWSELALWAYS)) {
        return false;
    }
    ListView_SetExtendedListViewStyle(page.list.hwnd(),
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    page.loadingOverlay = ksword::ui::createLoadingOverlay(page.hwnd, kAuditLoadingOverlayId, { 0, 0, 1, 1 });
    if (!page.loadingOverlay) {
        return false;
    }
    ksword::ui::setWindowFontRecursive(page.hwnd);
    return true;
}

LRESULT CALLBACK networkAuditPageProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    NetworkAuditPageState* page = auditStateFromWindow(hwnd);
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        page = create ? static_cast<NetworkAuditPageState*>(create->lpCreateParams) : nullptr;
        if (page) {
            page->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        }
    }
    switch (message) {
    case WM_CREATE:
        if (!page || !createAuditPageControls(*page)) {
            return -1;
        }
        page->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<NetworkFilterResult>>(
            hwnd, kMsgFilterCompleted);
        layoutAuditPage(*page);
        return 0;
    case WM_SIZE:
        if (page) {
            layoutAuditPage(*page);
        }
        return 0;
    case WM_COMMAND:
        if (page && LOWORD(wParam) == kAuditFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            requestNetworkFilter(*page, ksword::ui::getFilterBarText(page->filterBar));
            return 0;
        }
        if (page && HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kAuditRefreshButtonId) {
            beginNetworkRefresh(*page->owner);
            return 0;
        }
        if (page && HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kAuditExportButtonId) {
            exportAuditPage(*page);
            return 0;
        }
        break;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(lParam);
        if (page && header && header->hwndFrom == page->list.hwnd()) {
            LRESULT result = 0;
            if (page->list.handleNotify(*header, result)) {
                return result;
            }
            if (header->code == NM_RCLICK) {
                POINT point{};
                ::GetCursorPos(&point);
                showListContextMenu(*page, point);
                return 0;
            }
        }
        break;
    }
    case kMsgFilterCompleted:
        if (page && page->filterTask && page->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (page && reinterpret_cast<HWND>(wParam) == page->list.hwnd()) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(page->list.hwnd(), &rect);
                point = { rect.left + 20, rect.top + 20 };
            }
            showListContextMenu(*page, point);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        if (page) {
            if (page->filterTask) {
                page->filterTask->cancel();
            }
            page->list.detach();
            page->hwnd = nullptr;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool registerNetworkAuditPageClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = networkAuditPageProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kNetworkAuditPageClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

void layoutNetworkChildren(NetworkViewState& state) {
    if (!state.workspace) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    ::MoveWindow(state.workspace, 0, 0, (std::max)(1, width(client)), (std::max)(1, height(client)), TRUE);
}

bool createNetworkChildren(NetworkViewState& state) {
    if (!registerNetworkAuditPageClass()) {
        return false;
    }
    constexpr const wchar_t* kTabTitles[] = {
        L"连接管理", L"网络诊断", L"防火墙规则", L"TCP/UDP R0 cross-view", L"AFD endpoint",
        L"WFP callout/filter/provider", L"NDIS protocol/filter", L"NSI / interfaces / routes"
    };
    state.auditPages.resize(kAuditTabCount);
    std::vector<ksword::ui::WorkspaceTabDescriptor> tabs;
    tabs.push_back({ kConnectionTabIndex, kTabTitles[kConnectionTabIndex], L"按需枚举当前 TCP/UDP 连接。",
        [&state](HWND host, const RECT& bounds) {
            state.connectionView = net_tools::createNetToolsConnectionView(host, bounds);
            return state.connectionView;
        } });
    tabs.push_back({ kDiagnosticTabIndex, kTabTitles[kDiagnosticTabIndex], L"按需执行网络诊断命令。",
        [&state](HWND host, const RECT& bounds) {
            state.diagnosticView = net_tools::createNetToolsDiagnosticView(host, bounds);
            return state.diagnosticView;
        } });
    tabs.push_back({ kFirewallTabIndex, kTabTitles[kFirewallTabIndex], L"按需枚举防火墙规则。",
        [&state](HWND host, const RECT& bounds) {
            state.firewallView = net_tools::createNetToolsFirewallView(host, bounds);
            return state.firewallView;
        } });
    for (int auditIndex = 0; auditIndex < kAuditTabCount; ++auditIndex) {
        const int kTabId = kFirstAuditTabIndex + auditIndex;
        tabs.push_back({ kTabId, kTabTitles[kTabId], L"按需创建 R0/R3 网络栈审计页。",
            [&state, auditIndex](HWND host, const RECT& bounds) -> HWND {
                auto page = std::make_unique<NetworkAuditPageState>();
                page->owner = &state;
                page->auditIndex = auditIndex;
                page->hwnd = ::CreateWindowExW(
                    0, kNetworkAuditPageClass, L"",
                    WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
                    bounds.left, bounds.top, width(bounds), height(bounds), host, nullptr,
                    ::GetModuleHandleW(nullptr), page.get());
                if (!page->hwnd) {
                    return nullptr;
                }
                HWND hwnd = page->hwnd;
                state.auditPages[static_cast<std::size_t>(auditIndex)] = std::move(page);
                renderAuditPage(*state.auditPages[static_cast<std::size_t>(auditIndex)]);
                return hwnd;
            } });
    }
    ksword::ui::WorkspaceOptions options{};
    options.tabControlId = kTabControlId;
    options.initialTabId = kConnectionTabIndex;
    options.margin = 6;
    options.pageActivated = [&state](const int tabId, HWND) {
        if (tabId >= kFirstAuditTabIndex) {
            NetworkAuditPageState* page = auditPageFor(state, tabId - kFirstAuditTabIndex);
            if (page) {
                renderAuditPage(*page);
            }
            if (!state.auditRefreshStarted && state.refreshTask) {
                state.auditRefreshStarted = true;
                beginNetworkRefresh(state);
            }
        }
    };
    state.workspace = ksword::ui::createWorkspaceHost(
        state.hwnd, { 0, 0, 1, 1 }, std::move(tabs), std::move(options));
    return state.workspace != nullptr;
}

bool registerNetworkViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = [](HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) -> LRESULT {
        NetworkViewState* state = networkStateFromWindow(hwnd);
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            state = create ? static_cast<NetworkViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (message) {
        case WM_CREATE:
            if (!state || !createNetworkChildren(*state)) {
                return -1;
            }
            state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<std::vector<NetworkAuditPage>>>(hwnd, kMsgRefreshCompleted);
            layoutNetworkChildren(*state);
            return 0;
        case WM_SIZE:
            if (state) {
                layoutNetworkChildren(*state);
            }
            return 0;
        case kMsgRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NCDESTROY:
            if (state) {
                if (state->refreshTask) {
                    state->refreshTask->cancel();
                }
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    };
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kNetworkViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createNetworkFeatureView(HWND parent, const RECT& bounds) {
    if (!parent || !registerNetworkViewClass()) {
        return nullptr;
    }
    auto* state = new NetworkViewState();
    HWND hwnd = ::CreateWindowExW(0, kNetworkViewClass, L"Network", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, width(bounds), height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

bool requestNetworkFeatureViewProcess(HWND view, const DWORD processId) {
    NetworkViewState* state = networkStateFromWindow(view);
    if (!state || processId == 0 || !state->workspace ||
        !ksword::ui::activateWorkspaceHostTab(state->workspace, kConnectionTabIndex, true)) {
        return false;
    }
    state->connectionView = ksword::ui::workspaceHostPage(state->workspace, kConnectionTabIndex, true);
    return net_tools::requestNetToolsConnectionProcessFilter(state->connectionView, processId);
}

} // namespace Ksword::Features::Network

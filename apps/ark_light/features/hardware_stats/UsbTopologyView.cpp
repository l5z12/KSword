#include "UsbTopologyView.h"

#include "DeviceTopologyEnumerator.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::hardware_stats {
namespace {

constexpr wchar_t kUsbTopologyViewClass[] = L"KswordARKLight.HardwareStats.UsbTopologyView";

constexpr int kRefreshButtonId = 66301;
constexpr int kFilterBarId = 66302;
constexpr int kNodeListId = 66303;
constexpr int kDetailListId = 66304;
constexpr int kLoadingOverlayId = 66305;
constexpr int kExportButtonId = 66306;

constexpr UINT kMenuCopyRow = 66351;
constexpr UINT kMenuCopyVisible = 66352;
constexpr UINT kMenuCopyDetail = 66353;
constexpr UINT kMenuRefresh = 66354;

constexpr UINT kMsgRefreshCompleted = WM_APP + 670;
constexpr UINT kMsgFilterCompleted = WM_APP + 671;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 180;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 11;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct UsbFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct UsbTopologyViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView nodeList;
    UsbTopologySnapshot snapshot;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待 USB 拓扑快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<UsbTopologySnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<UsbFilterResult>> filterTask;
};

UsbTopologyViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<UsbTopologyViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void addColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void setDetailText(HWND list, int row, int column, const std::wstring& text) {
    if (column == 0) {
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(text.c_str());
        ListView_InsertItem(list, &item);
        return;
    }
    ListView_SetItemText(list, row, column, const_cast<LPWSTR>(text.c_str()));
}

bool copyText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T kBytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, kBytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), kBytes);
    ::GlobalUnlock(memory);
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

int selectedNodeIndex(const UsbTopologyViewState& state) {
    const HWND kList = state.nodeList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.nodeList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kNodeIndex = visible[static_cast<std::size_t>(kSelected)];
    return kNodeIndex < state.snapshot.nodes.size() ? static_cast<int>(kNodeIndex) : -1;
}

const UsbNode* selectedNode(const UsbTopologyViewState& state) {
    const int kIndex = selectedNodeIndex(state);
    return kIndex >= 0 ? &state.snapshot.nodes[static_cast<std::size_t>(kIndex)] : nullptr;
}

std::wstring stableKeyFromListItem(const UsbTopologyViewState& state, int item) {
    const auto& visible = state.nodeList.visibleIndexes();
    const auto& rows = state.nodeList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

std::vector<std::pair<std::wstring, std::wstring>> propertiesForNode(const UsbNode& node) {
    std::vector<std::pair<std::wstring, std::wstring>> properties;
    properties.emplace_back(L"设备描述", node.description);
    properties.emplace_back(L"节点类型", usbNodeKindText(node.kind));
    properties.emplace_back(L"层级深度", std::to_wstring(node.depth));
    properties.emplace_back(L"制造商", node.manufacturer);
    properties.emplace_back(L"厂商 ID (VID)", node.vendorId.empty() ? std::wstring(L"—") : L"0x" + node.vendorId);
    properties.emplace_back(L"产品 ID (PID)", node.productId.empty() ? std::wstring(L"—") : L"0x" + node.productId);
    properties.emplace_back(L"版本 (REV)", node.revision.empty() ? std::wstring(L"—") : node.revision);
    properties.emplace_back(L"序列号", node.serialNumber.empty() ? std::wstring(L"设备未上报") : node.serialNumber);
    properties.emplace_back(L"端口", node.portText);
    properties.emplace_back(L"位置信息", node.locationInfo);
    properties.emplace_back(L"设备类", node.deviceClass);
    properties.emplace_back(L"驱动服务", node.service);
    properties.emplace_back(L"驱动键", node.driverKey);
    properties.emplace_back(L"状态", node.statusText);
    properties.emplace_back(L"问题", node.problemText.empty() ? std::wstring(L"无") : node.problemText);
    properties.emplace_back(L"实例 ID", node.instanceId);
    properties.emplace_back(L"父实例 ID", node.parentInstanceId);
    properties.emplace_back(L"硬件 ID", node.hardwareIds);
    return properties;
}

void showDetail(UsbTopologyViewState& state) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const UsbNode* node = selectedNode(state);
    if (!node) {
        setDetailText(state.detailList, 0, 0, L"选择");
        setDetailText(state.detailList, 0, 1, L"未选择 USB 节点");
        return;
    }
    const auto kProperties = propertiesForNode(*node);
    for (int row = 0; row < static_cast<int>(kProperties.size()); ++row) {
        setDetailText(state.detailList, row, 0, kProperties[static_cast<std::size_t>(row)].first);
        setDetailText(state.detailList, row, 1, kProperties[static_cast<std::size_t>(row)].second);
    }
}

std::wstring rowsAsText(const UsbTopologyViewState& state, bool visibleRows) {
    const auto& rows = state.nodeList.rows();
    const auto& visible = state.nodeList.visibleIndexes();
    const HWND kList = state.nodeList.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows &&
            (!kList || (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t kRowIndex = visible[item];
        if (kRowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[kRowIndex].cells;
        for (std::size_t column = 0; column < (std::min)(static_cast<std::size_t>(kColumnCount), cells.size()); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

std::wstring detailAsText(const UsbTopologyViewState& state) {
    const UsbNode* node = selectedNode(state);
    if (!node) {
        return {};
    }
    std::wstring text;
    for (const auto& property : propertiesForNode(*node)) {
        text += property.first + L"\t" + property.second + L"\r\n";
    }
    return text;
}

void applyUsbFilter(UsbTopologyViewState& state, UsbFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.nodeList.hwnd()) {
        return;
    }

    state.nodeList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.nodeList.visibleIndexes();
    const auto& rows = state.nodeList.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t kSourceIndex = visible[item];
        if (kSourceIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && rows[kSourceIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && rows[kSourceIndex].stableKey == result.topStableKey) {
            topItem = static_cast<int>(item);
        }
    }

    HWND list = state.nodeList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    showDetail(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestUsbFilter(UsbTopologyViewState& state,
    std::wstring query,
    std::wstring selectedStableKey,
    std::wstring topStableKey) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const auto kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    const bool kUseRegex = state.filterUseRegex;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.filterQuery,
            selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            UsbFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<UsbFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"USB 筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyUsbFilter(state, std::move(*result));
        });
}

void buildRows(UsbTopologyViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.snapshot.nodes.size());
    for (const UsbNode& node : state.snapshot.nodes) {
        ksword::ui::VirtualListRow row{};
        // The PnP instance ID is unique per devnode and survives replug as long
        // as the device reports a serial number, which makes it the right key for
        // restoring the selection after a refresh.
        row.stableKey = node.instanceId;
        row.itemData = static_cast<LPARAM>(node.index);
        row.cells.reserve(kColumnCount + 3);
        row.cells.push_back(indentedName(node.description, node.depth));
        row.cells.push_back(usbNodeKindText(node.kind));
        row.cells.push_back(node.vendorId.empty() ? std::wstring() : L"0x" + node.vendorId);
        row.cells.push_back(node.productId.empty() ? std::wstring() : L"0x" + node.productId);
        row.cells.push_back(node.serialNumber);
        row.cells.push_back(node.portText);
        row.cells.push_back(node.service);
        row.cells.push_back(node.deviceClass);
        row.cells.push_back(node.statusText);
        row.cells.push_back(node.locationInfo);
        row.cells.push_back(node.instanceId);
        // Detail-only text joins the filter input without becoming a column, so a
        // search for a manufacturer or a raw hardware ID still finds the row.
        row.cells.push_back(node.manufacturer);
        row.cells.push_back(node.hardwareIds);
        row.cells.push_back(node.problemText);
        if (!node.problemText.empty()) {
            row.textColor = RGB(176, 32, 32);
        }
        rows.push_back(std::move(row));
    }

    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.nodeList.setSharedRows(filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void beginUsbRefresh(UsbTopologyViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.nodeList.rows().empty();
    state.statusText = state.refreshTask->running()
        ? L"USB 刷新已排队，等待当前快照完成…"
        : L"正在后台枚举 USB 设备树…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在枚举 USB 设备树…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.refreshTask->request(
        [] { return enumerateUsbTopology(); },
        [&state](std::uint64_t, std::optional<UsbTopologySnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"USB 枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"USB 枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND kList = state.nodeList.hwnd();
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1);
            const std::wstring kTopStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetTopIndex(kList) : -1);

            std::size_t hubs = 0;
            std::size_t controllers = 0;
            std::size_t problems = 0;
            for (const UsbNode& node : snapshot->nodes) {
                if (node.kind == UsbNodeKind::kHub) {
                    ++hubs;
                } else if (node.kind == UsbNodeKind::kHostController) {
                    ++controllers;
                }
                if (!node.problemText.empty()) {
                    ++problems;
                }
            }
            const std::size_t kTotal = snapshot->nodes.size();

            state.snapshot = std::move(*snapshot);
            buildRows(state);
            state.statusText = L"共 " + std::to_wstring(kTotal) + L" 个节点，主控制器 " +
                std::to_wstring(controllers) + L"，集线器 " + std::to_wstring(hubs) +
                L"，异常 " + std::to_wstring(problems) + L"。";
            requestUsbFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey,
                kTopStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void showContextMenu(UsbTopologyViewState& state, POINT screenPoint) {
    const UsbNode* node = selectedNode(state);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (node ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (node ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(kCommand)) {
    case kMenuCopyRow:
        state.statusText = copyText(state.hwnd, rowsAsText(state, false)) ? L"已复制选中行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyVisible:
        state.statusText = copyText(state.hwnd, rowsAsText(state, true)) ? L"已复制可见行。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuCopyDetail:
        state.statusText = copyText(state.hwnd, detailAsText(state)) ? L"已复制详情。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kMenuRefresh:
        beginUsbRefresh(state);
        break;
    default:
        break;
    }
}

void layoutView(UsbTopologyViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, kGap, kGap, 80, kRowHeight, TRUE);
    }
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, kGap + 80 + kGap, kGap, 78, kRowHeight, TRUE);
    }
    const int kSecondRowY = kGap + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kDetailTop = (std::max)(kListTop, kHeight - kStatusHeight - kDetailHeight);
    const int kListHeight = (std::max)(0, kDetailTop - kListTop - kGap);
    if (HWND list = state.nodeList.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.detailList) {
        ::MoveWindow(state.detailList, kGap, kDetailTop, (std::max)(0, kWidth - kGap * 2),
            (std::max)(0, kHeight - kStatusHeight - kDetailTop - kGap), TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(UsbTopologyViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选设备描述、VID/PID、序列号、驱动与实例 ID", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.filterBar) {
        return false;
    }

    if (!state.nodeList.create(hwnd, kNodeListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.nodeList.addColumns({
        { 0, 320, LVCFMT_LEFT, L"设备" },
        { 1, 80, LVCFMT_LEFT, L"类型" },
        { 2, 70, LVCFMT_LEFT, L"VID" },
        { 3, 70, LVCFMT_LEFT, L"PID" },
        { 4, 140, LVCFMT_LEFT, L"序列号" },
        { 5, 70, LVCFMT_LEFT, L"端口" },
        { 6, 110, LVCFMT_LEFT, L"驱动服务" },
        { 7, 110, LVCFMT_LEFT, L"设备类" },
        { 8, 90, LVCFMT_LEFT, L"状态" },
        { 9, 180, LVCFMT_LEFT, L"位置信息" },
        { 10, 300, LVCFMT_LEFT, L"实例 ID" },
    });
    if (HWND list = state.nodeList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }

    state.detailList = ksword::ui::createReportListView(hwnd, kDetailListId, 0, 0, 1, 1, LVS_SINGLESEL);
    if (state.detailList) {
        addColumn(state.detailList, 0, L"属性", 160);
        addColumn(state.detailList, 1, L"值", 700);
        ListView_SetExtendedListViewStyle(state.detailList,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.detailList || !state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK usbTopologyViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<UsbTopologyViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->refreshTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<UsbTopologySnapshot>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<UsbFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            showDetail(*state);
            beginUsbRefresh(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int kId = LOWORD(wParam);
            const int kNotification = HIWORD(wParam);
            if (kId == kFilterBarId && kNotification == EN_CHANGE) {
                requestUsbFilter(*state, ksword::ui::getFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (kId == kRefreshButtonId && kNotification == BN_CLICKED) {
                beginUsbRefresh(*state);
                return 0;
            }
            if (kId == kExportButtonId && kNotification == BN_CLICKED) {
                if (state->nodeList.visibleIndexes().empty()) {
                    state->statusText = L"没有可导出的可见结果。";
                } else {
                    std::wstring error;
                    switch (ksword::ui::saveUtf8TextFileWithDialog(hwnd, L"usb_topology.tsv", L"导出 USB 拓扑",
                        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", exportUsbTopologyViewTsv(hwnd), &error)) {
                    case ksword::ui::SaveTextFileResult::kSaved: state->statusText = L"USB 拓扑可见结果已导出。"; break;
                    case ksword::ui::SaveTextFileResult::kCancelled: state->statusText = L"已取消导出 USB 拓扑结果。"; break;
                    case ksword::ui::SaveTextFileResult::kFailed: state->statusText = L"导出 USB 拓扑结果失败：" + error; break;
                    }
                }
                ::InvalidateRect(hwnd, nullptr, TRUE);
                return 0;
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->nodeList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->nodeList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        showDetail(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->nodeList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, ksword::ui::appTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            ksword::ui::drawTextLine(dc, state->statusText, statusRect,
                ksword::ui::appTheme().mutedTextColor, ksword::ui::systemUiFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    default:
        if (state) {
            if (msg == kMsgRefreshCompleted && state->refreshTask) {
                state->refreshTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->nodeList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureUsbTopologyViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = usbTopologyViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kUsbTopologyViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

UsbTopologyViewState* verifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kUsbTopologyViewClass) != 0) {
        return nullptr;
    }
    return stateFromWindow(view);
}

} // namespace

HWND createUsbTopologyView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureUsbTopologyViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kUsbTopologyViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void refreshUsbTopologyView(HWND view) {
    if (UsbTopologyViewState* state = verifiedState(view)) {
        beginUsbRefresh(*state);
    }
}

std::wstring exportUsbTopologyViewTsv(HWND view) {
    UsbTopologyViewState* state = verifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text = L"设备\t类型\tVID\tPID\t序列号\t端口\t驱动服务\t设备类\t状态\t位置信息\t实例 ID\r\n";
    text += rowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::hardware_stats

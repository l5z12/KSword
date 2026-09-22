#include "BusDeviceView.h"

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

constexpr wchar_t kBusDeviceViewClass[] = L"KswordARKLight.HardwareStats.BusDeviceView";

constexpr int kRefreshButtonId = 66401;
constexpr int kAllBusesCheckId = 66402;
constexpr int kFilterBarId = 66403;
constexpr int kBusListId = 66404;
constexpr int kDetailListId = 66405;
constexpr int kLoadingOverlayId = 66406;
constexpr int kExportButtonId = 66407;

constexpr UINT kMenuCopyRow = 66451;
constexpr UINT kMenuCopyVisible = 66452;
constexpr UINT kMenuCopyDetail = 66453;
constexpr UINT kMenuRefresh = 66454;

constexpr UINT kMsgRefreshCompleted = WM_APP + 675;
constexpr UINT kMsgFilterCompleted = WM_APP + 676;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 180;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 12;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct BusFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct BusDeviceViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND allBusesCheck = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView busList;
    BusDeviceSnapshot snapshot;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待总线设备快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    bool includeAllEnumerators = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<BusDeviceSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<BusFilterResult>> filterTask;
};

BusDeviceViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<BusDeviceViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
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

const BusDeviceRow* selectedRow(const BusDeviceViewState& state) {
    const HWND kList = state.busList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.busList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return nullptr;
    }
    const std::size_t kRowIndex = visible[static_cast<std::size_t>(kSelected)];
    return kRowIndex < state.snapshot.rows.size() ? &state.snapshot.rows[kRowIndex] : nullptr;
}

std::wstring stableKeyFromListItem(const BusDeviceViewState& state, int item) {
    const auto& visible = state.busList.visibleIndexes();
    const auto& rows = state.busList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

std::vector<std::pair<std::wstring, std::wstring>> propertiesForRow(const BusDeviceRow& row) {
    std::vector<std::pair<std::wstring, std::wstring>> properties;
    properties.emplace_back(L"设备描述", row.description);
    properties.emplace_back(L"制造商", row.manufacturer);
    properties.emplace_back(L"枚举器", row.enumeratorName);
    properties.emplace_back(L"总线类型", row.busTypeText);
    properties.emplace_back(L"总线类型 GUID", row.busTypeGuid);
    properties.emplace_back(L"传统总线类型", row.legacyBusType);
    properties.emplace_back(L"总线号", row.busNumber);
    properties.emplace_back(L"地址", row.address);
    properties.emplace_back(L"槽位号", row.uiNumber);
    properties.emplace_back(L"位置信息", row.locationInfo);
    properties.emplace_back(L"位置路径", row.locationPaths);
    properties.emplace_back(L"已分配资源", row.resourceText.empty() ? std::wstring(L"无独占资源") : row.resourceText);
    properties.emplace_back(L"设备类", row.deviceClass);
    properties.emplace_back(L"驱动服务", row.service);
    properties.emplace_back(L"驱动键", row.driverKey);
    properties.emplace_back(L"状态", row.statusText);
    properties.emplace_back(L"问题", row.problemText.empty() ? std::wstring(L"无") : row.problemText);
    properties.emplace_back(L"实例 ID", row.instanceId);
    return properties;
}

void showDetail(BusDeviceViewState& state) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const BusDeviceRow* row = selectedRow(state);
    if (!row) {
        setDetailText(state.detailList, 0, 0, L"选择");
        setDetailText(state.detailList, 0, 1, L"未选择总线设备");
        return;
    }
    const auto kProperties = propertiesForRow(*row);
    for (int index = 0; index < static_cast<int>(kProperties.size()); ++index) {
        setDetailText(state.detailList, index, 0, kProperties[static_cast<std::size_t>(index)].first);
        setDetailText(state.detailList, index, 1, kProperties[static_cast<std::size_t>(index)].second);
    }
}

std::wstring rowsAsText(const BusDeviceViewState& state, bool visibleRows) {
    const auto& rows = state.busList.rows();
    const auto& visible = state.busList.visibleIndexes();
    const HWND kList = state.busList.hwnd();
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

std::wstring detailAsText(const BusDeviceViewState& state) {
    const BusDeviceRow* row = selectedRow(state);
    if (!row) {
        return {};
    }
    std::wstring text;
    for (const auto& property : propertiesForRow(*row)) {
        text += property.first + L"\t" + property.second + L"\r\n";
    }
    return text;
}

void applyBusFilter(BusDeviceViewState& state, BusFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.busList.hwnd()) {
        return;
    }

    state.busList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.busList.visibleIndexes();
    const auto& rows = state.busList.rows();
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

    HWND list = state.busList.hwnd();
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

void requestBusFilter(BusDeviceViewState& state,
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
            BusFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<BusFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"总线筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyBusFilter(state, std::move(*result));
        });
}

void buildRows(BusDeviceViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.snapshot.rows.size());
    for (std::size_t index = 0; index < state.snapshot.rows.size(); ++index) {
        const BusDeviceRow& device = state.snapshot.rows[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = device.instanceId;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount + 3);
        row.cells.push_back(device.description);
        row.cells.push_back(device.enumeratorName);
        row.cells.push_back(device.busTypeText);
        row.cells.push_back(device.legacyBusType);
        row.cells.push_back(device.busNumber);
        row.cells.push_back(device.address);
        row.cells.push_back(device.uiNumber);
        row.cells.push_back(device.locationInfo);
        row.cells.push_back(device.resourceText);
        row.cells.push_back(device.service);
        row.cells.push_back(device.statusText);
        row.cells.push_back(device.instanceId);
        // Detail-only text joins the filter input without becoming a column.
        row.cells.push_back(device.manufacturer);
        row.cells.push_back(device.locationPaths);
        row.cells.push_back(device.busTypeGuid);
        if (!device.problemText.empty()) {
            row.textColor = RGB(176, 32, 32);
        }
        rows.push_back(std::move(row));
    }

    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.busList.setSharedRows(filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void beginBusRefresh(BusDeviceViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.busList.rows().empty();
    state.statusText = state.refreshTask->running()
        ? L"总线刷新已排队，等待当前快照完成…"
        : L"正在后台枚举总线设备与资源分配…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在枚举总线设备…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    const bool kIncludeAll = state.includeAllEnumerators;
    state.refreshTask->request(
        [kIncludeAll] { return enumerateBusDevices(kIncludeAll); },
        [&state](std::uint64_t, std::optional<BusDeviceSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"总线枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"总线枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND kList = state.busList.hwnd();
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1);
            const std::wstring kTopStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetTopIndex(kList) : -1);

            std::size_t withResources = 0;
            std::size_t problems = 0;
            for (const BusDeviceRow& row : snapshot->rows) {
                if (!row.resourceText.empty()) {
                    ++withResources;
                }
                if (!row.problemText.empty()) {
                    ++problems;
                }
            }
            const std::size_t kTotal = snapshot->rows.size();

            state.snapshot = std::move(*snapshot);
            buildRows(state);
            state.statusText = L"共 " + std::to_wstring(kTotal) + L" 个设备，占用硬件资源 " +
                std::to_wstring(withResources) + L"，异常 " + std::to_wstring(problems) + L"。";
            requestBusFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey,
                kTopStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void showContextMenu(BusDeviceViewState& state, POINT screenPoint) {
    const BusDeviceRow* row = selectedRow(state);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (row ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (row ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
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
        beginBusRefresh(state);
        break;
    default:
        break;
    }
}

void layoutView(BusDeviceViewState& state) {
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
    if (state.allBusesCheck) {
        ::MoveWindow(state.allBusesCheck, kGap + 80 + kGap + 78 + kGap, kGap, 200, kRowHeight, TRUE);
    }
    const int kSecondRowY = kGap + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kDetailTop = (std::max)(kListTop, kHeight - kStatusHeight - kDetailHeight);
    const int kListHeight = (std::max)(0, kDetailTop - kListTop - kGap);
    if (HWND list = state.busList.hwnd()) {
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

bool createChildControls(BusDeviceViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.allBusesCheck = ::CreateWindowExW(0, WC_BUTTONW, L"包含全部枚举器（较慢）",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAllBusesCheckId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选设备、总线类型、位置、资源与实例 ID", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.allBusesCheck || !state.filterBar) {
        return false;
    }

    if (!state.busList.create(hwnd, kBusListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.busList.addColumns({
        { 0, 280, LVCFMT_LEFT, L"设备" },
        { 1, 90, LVCFMT_LEFT, L"枚举器" },
        { 2, 100, LVCFMT_LEFT, L"总线类型" },
        { 3, 110, LVCFMT_LEFT, L"传统总线类型" },
        { 4, 70, LVCFMT_RIGHT, L"总线号" },
        { 5, 160, LVCFMT_LEFT, L"地址" },
        { 6, 70, LVCFMT_RIGHT, L"槽位" },
        { 7, 170, LVCFMT_LEFT, L"位置信息" },
        { 8, 300, LVCFMT_LEFT, L"已分配资源" },
        { 9, 110, LVCFMT_LEFT, L"驱动服务" },
        { 10, 90, LVCFMT_LEFT, L"状态" },
        { 11, 300, LVCFMT_LEFT, L"实例 ID" },
    });
    if (HWND list = state.busList.hwnd()) {
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

LRESULT CALLBACK busDeviceViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<BusDeviceViewState>();
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
                std::make_unique<ksword::ui::AsyncSnapshotTask<BusDeviceSnapshot>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<BusFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            showDetail(*state);
            beginBusRefresh(*state);
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
                requestBusFilter(*state, ksword::ui::getFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                switch (kId) {
                case kRefreshButtonId:
                    beginBusRefresh(*state);
                    return 0;
                case kExportButtonId:
                    if (state->busList.visibleIndexes().empty()) {
                        state->statusText = L"没有可导出的可见结果。";
                    } else {
                        std::wstring error;
                        switch (ksword::ui::saveUtf8TextFileWithDialog(hwnd, L"system_bus.tsv", L"导出系统总线",
                            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", exportBusDeviceViewTsv(hwnd), &error)) {
                        case ksword::ui::SaveTextFileResult::kSaved: state->statusText = L"系统总线可见结果已导出。"; break;
                        case ksword::ui::SaveTextFileResult::kCancelled: state->statusText = L"已取消导出系统总线结果。"; break;
                        case ksword::ui::SaveTextFileResult::kFailed: state->statusText = L"导出系统总线结果失败：" + error; break;
                        }
                    }
                    ::InvalidateRect(hwnd, nullptr, TRUE);
                    return 0;
                case kAllBusesCheckId:
                    state->includeAllEnumerators =
                        ::SendMessageW(state->allBusesCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
                    // The scope decides which devnodes are enumerated at all, so
                    // it can only take effect through a new background pass.
                    beginBusRefresh(*state);
                    return 0;
                default:
                    break;
                }
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->busList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->busList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        showDetail(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->busList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
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
            state->busList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureBusDeviceViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = busDeviceViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kBusDeviceViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

BusDeviceViewState* verifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kBusDeviceViewClass) != 0) {
        return nullptr;
    }
    return stateFromWindow(view);
}

} // namespace

HWND createBusDeviceView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureBusDeviceViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kBusDeviceViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void refreshBusDeviceView(HWND view) {
    if (BusDeviceViewState* state = verifiedState(view)) {
        beginBusRefresh(*state);
    }
}

std::wstring exportBusDeviceViewTsv(HWND view) {
    BusDeviceViewState* state = verifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text =
        L"设备\t枚举器\t总线类型\t传统总线类型\t总线号\t地址\t槽位\t位置信息\t已分配资源\t驱动服务\t状态\t实例 ID\r\n";
    text += rowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::hardware_stats

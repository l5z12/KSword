#include "StartupView.h"

#include "StartupActions.h"
#include "StartupEnumerator.h"
#include "StartupModel.h"
#include "../file/PathNavigator.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/FilterBar.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::startup {
namespace {

constexpr wchar_t kStartupViewClass[] = L"KswordARKLight.Startup.FeatureView";
constexpr int kRefreshButtonId = 63001;
constexpr int kEnableButtonId = 63002;
constexpr int kDisableButtonId = 63003;
constexpr int kDeleteButtonId = 63004;
constexpr int kOpenButtonId = 63005;
constexpr int kEntryListId = 63006;
constexpr int kDetailListId = 63007;
constexpr int kFilterBarId = 63008;
constexpr int kLoadingOverlayId = 63009;
constexpr UINT kStartupMenuEnable = 63601;
constexpr UINT kStartupMenuDisable = 63602;
constexpr UINT kStartupMenuDelete = 63603;
constexpr UINT kStartupMenuOpen = 63604;
constexpr UINT kStartupMenuCopyCell = 63605;
constexpr UINT kStartupMenuCopyRow = 63606;
constexpr UINT kStartupMenuCopyVisible = 63607;
constexpr UINT kStartupMenuCopyDetail = 63608;
constexpr UINT kStartupMenuRefresh = 63609;
constexpr UINT kStartupMenuOpenProvenance = 63610;
constexpr UINT kMsgRefreshCompleted = WM_APP + 575;
constexpr UINT kMsgFilterCompleted = WM_APP + 576;
constexpr UINT kMsgActionCompleted = WM_APP + 577;
constexpr int kHeaderHeight = 66;
constexpr int kGap = 6;
constexpr int kDetailHeight = 220;

int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

struct StartupFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct StartupActionTaskResult final {
    StartupActionResult action;
    bool refreshRequired = false;
};

// StartupViewState holds immutable display rows separately from the model.
// Worker threads create snapshots only; the UI thread installs snapshots and
// responds to owner-data requests for visible rows.
struct StartupViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND enableButton = nullptr;
    HWND disableButton = nullptr;
    HWND deleteButton = nullptr;
    HWND openButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView entryList;
    StartupModel model;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待启动项快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    bool actionInProgress = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<StartupEnumerationResult>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<StartupFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<StartupActionTaskResult>> actionTask;
};

void addColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void setListText(HWND list, int row, int column, const std::wstring& text) {
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

std::wstring listText(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(4096, L'\0');
    ListView_GetItemText(list, row, column, buffer.data(), static_cast<int>(buffer.size()));
    return std::wstring(buffer.data());
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

std::wstring stableKeyForEntry(const StartupEntry& entry) {
    return std::to_wstring(static_cast<int>(entry.kind)) + L"|" +
        std::to_wstring(static_cast<int>(entry.scope)) + L"|" +
        entry.registrySubKey + L"|" + entry.registryValueName + L"|" +
        entry.filePath + L"|" + entry.disabledFilePath + L"|" +
        entry.serviceName + L"|" + entry.taskPath + L"|" + entry.name;
}

int selectedModelIndex(const StartupViewState& state) {
    const HWND kList = state.entryList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.entryList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(kModelIndex) : -1;
}

const StartupEntry* findSelectedEntry(const StartupViewState& state) {
    return state.model.entryAt(selectedModelIndex(state));
}

std::wstring stableKeyFromListItem(const StartupViewState& state, int item) {
    const auto& visible = state.entryList.visibleIndexes();
    const auto& rows = state.entryList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

void setActionControlsEnabled(StartupViewState& state, bool enabled);

void showDetail(StartupViewState& state, int modelIndex) {
    const StartupEntry* entry = state.model.entryAt(modelIndex);
    setActionControlsEnabled(state, !state.actionInProgress);
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    if (!entry) {
        setListText(state.detailList, 0, 0, L"选择");
        setListText(state.detailList, 0, 1, L"未选择启动项");
        return;
    }
    const std::vector<StartupProperty> kProperties = state.model.propertiesForEntry(*entry);
    for (int row = 0; row < static_cast<int>(kProperties.size()); ++row) {
        setListText(state.detailList, row, 0, kProperties[static_cast<std::size_t>(row)].name);
        setListText(state.detailList, row, 1, kProperties[static_cast<std::size_t>(row)].value);
    }
}

// entryAllowsStartupActions separates mutable startup rows from read-only service
// observations. It is used by both toolbar and context-menu state; StartupActions
// independently enforces the same boundary for posted commands.
bool entryAllowsStartupActions(const StartupEntry* entry) {
    return entry != nullptr && entry->kind != StartupEntryKind::kDriverService &&
        entry->kind != StartupEntryKind::kRegistryOnlyService;
}

void setActionControlsEnabled(StartupViewState& state, bool enabled) {
    const bool kAllowActions = enabled && entryAllowsStartupActions(findSelectedEntry(state));
    for (HWND control : { state.enableButton, state.disableButton, state.deleteButton, state.openButton }) {
        if (control) {
            ::EnableWindow(control, kAllowActions);
        }
    }
}

void applyStartupFilter(StartupViewState& state, StartupFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.entryList.hwnd()) {
        return;
    }

    state.entryList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.entryList.visibleIndexes();
    const auto& rows = state.entryList.rows();
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

    HWND list = state.entryList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        showDetail(state, selectedModelIndex(state));
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        showDetail(state, selectedModelIndex(state));
    } else {
        showDetail(state, -1);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(state.entryList.rows().size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestStartupFilter(StartupViewState& state,
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
        [kRows, kGeneration, kUseRegex, query = state.filterQuery, selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            StartupFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<StartupFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"启动项筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyStartupFilter(state, std::move(*result));
        });
}

void buildRows(StartupViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    const auto& entries = state.model.entries();
    rows.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const StartupEntry& entry = entries[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = stableKeyForEntry(entry);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(6);
        for (int column = 0; column != 6; ++column) {
            row.cells.push_back(state.model.textForColumn(entry, column));
        }
        // Detail-only fields are included in the background filter without
        // adding hidden columns or running another enumeration.
        row.cells.push_back(entry.description);
        row.cells.push_back(entry.publisher);
        for (const StartupProperty& property : entry.properties) {
            row.cells.push_back(property.name);
            row.cells.push_back(property.value);
        }
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.entryList.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void beginStartupRefresh(StartupViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.entryList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"启动项刷新已排队，等待当前快照完成…" : L"正在后台枚举启动项…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在加载启动项…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return enumerateStartupEntries(); },
        [&state](std::uint64_t, std::optional<StartupEnumerationResult>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"启动项刷新异常结束，请检查访问权限。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"启动项枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring kSelectedStableKey = stableKeyFromListItem(state, ListView_GetNextItem(state.entryList.hwnd(), -1, LVNI_SELECTED));
            const std::wstring kTopStableKey = stableKeyFromListItem(state, ListView_GetTopIndex(state.entryList.hwnd()));
            const std::size_t kEntryCount = snapshot->entries.size();
            state.model.setEntries(std::move(snapshot->entries));
            buildRows(state);
            state.statusText = L"已加载 " + std::to_wstring(kEntryCount) + L" 个启动项。";
            if (!snapshot->diagnosticText.empty() && snapshot->diagnosticText != L"OK") {
                state.statusText += L" " + snapshot->diagnosticText;
            }
            requestStartupFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey,
                kTopStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

StartupActionTaskResult executeAction(const StartupEntry& entry, int commandId) {
    StartupActionTaskResult result{};
    switch (commandId) {
    case kEnableButtonId:
        result.action = enableStartupEntry(entry);
        break;
    case kDisableButtonId:
        result.action = disableStartupEntry(entry);
        break;
    case kDeleteButtonId:
        result.action = deleteStartupEntry(entry);
        break;
    case kOpenButtonId:
        result.action = openStartupEntryLocation(entry);
        break;
    default:
        result.action = { false, L"未知启动项操作。" };
        break;
    }
    result.refreshRequired = result.action.success && commandId != kOpenButtonId;
    return result;
}

void runAction(StartupViewState& state, int commandId) {
    const StartupEntry* selected = findSelectedEntry(state);
    if (!selected) {
        state.statusText = L"未选择启动项。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (!entryAllowsStartupActions(selected)) {
        state.statusText = selected->kind == StartupEntryKind::kRegistryOnlyService
            ? L"该服务本次未由 SCM 返回（可能受访问过滤），仅供只读调查，不能启用、禁用、删除或打开位置。"
            : L"驱动启动项仅供 SCM 只读调查，不能启用、禁用、删除或打开位置。";
        setActionControlsEnabled(state, false);
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"启动项操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const StartupEntry kEntry = *selected;
    state.actionInProgress = true;
    setActionControlsEnabled(state, false);
    state.statusText = L"正在后台执行启动项操作…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [kEntry, commandId] { return executeAction(kEntry, commandId); },
        [&state](std::uint64_t, std::optional<StartupActionTaskResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            setActionControlsEnabled(state, true);
            if (error || !result.has_value()) {
                state.statusText = L"启动项操作异常结束。";
            } else {
                state.statusText = result->action.message;
                if (result->refreshRequired) {
                    beginStartupRefresh(state);
                    return;
                }
            }
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring selectedRowsAsText(const StartupViewState& state, bool visibleRows) {
    const auto& rows = state.entryList.rows();
    const auto& visible = state.entryList.visibleIndexes();
    const HWND kList = state.entryList.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!visibleRows && (!kList || (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t kRowIndex = visible[item];
        if (kRowIndex >= rows.size()) {
            continue;
        }
        const auto& cells = rows[kRowIndex].cells;
        for (std::size_t column = 0; column < std::min<std::size_t>(6, cells.size()); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

void copyCurrentDetail(StartupViewState& state) {
    std::wstring text;
    const int kRows = state.detailList ? ListView_GetItemCount(state.detailList) : 0;
    for (int row = 0; row < kRows; ++row) {
        text += listText(state.detailList, row, 0);
        text += L'\t';
        text += listText(state.detailList, row, 1);
        text += L"\r\n";
    }
    state.statusText = copyText(state.hwnd, text) ? L"已复制启动项详细信息。" : L"复制启动项详细信息失败。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void copyCell(StartupViewState& state) {
    const HWND kList = state.entryList.hwnd();
    const int kRow = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    if (kRow < 0) {
        state.statusText = L"未选择启动项。";
    } else {
        const auto& visible = state.entryList.visibleIndexes();
        const auto& rows = state.entryList.rows();
        const std::size_t kIndex = static_cast<std::size_t>(kRow) < visible.size() ? visible[static_cast<std::size_t>(kRow)] : rows.size();
        const std::wstring kText = kIndex < rows.size() && !rows[kIndex].cells.empty() ? rows[kIndex].cells.front() : std::wstring{};
        state.statusText = copyText(state.hwnd, kText) ? L"已复制单元格。" : L"复制单元格失败。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// StartupProvenanceRoute carries one exact, cached source route. It deliberately
// contains no command-line parsing, no filesystem probe and no registry-view
// emulation: unavailable means Lite cannot name a precise target.
struct StartupProvenanceRoute final {
    bool available = false;
    ksword::core::NavigationRequest request;
    std::wstring menuText = L"打开来源";
    std::wstring unavailableText = L"当前启动项没有可精确导航的来源。";
    std::wstring successText;
    std::wstring failureText = L"关联模块当前无法接收该启动项来源。";
};

std::wstring registryRootText(const HKEY root) {
    if (root == HKEY_CURRENT_USER) {
        return L"HKCU";
    }
    if (root == HKEY_LOCAL_MACHINE) {
        return L"HKLM";
    }
    return {};
}

StartupProvenanceRoute buildStartupProvenanceRoute(const StartupEntry& entry) {
    StartupProvenanceRoute route;
    switch (entry.kind) {
    case StartupEntryKind::kRegistryRun:
    case StartupEntryKind::kRegistryRunOnce: {
        route.menuText = L"打开来源注册表键";
        route.failureText = L"注册表模块当前无法接收该启动项来源键。";
        route.successText = L"已打开启动项来源注册表键；Lite 不会伪称已选中具体值。";
        std::wstring subKey;
        std::wstring rootText;
        if (entry.state == StartupEntryState::kDisabled) {
            rootText = L"HKCU";
            subKey = entry.disabledRegistrySubKey;
        } else {
            if (entry.registryRoot == HKEY_LOCAL_MACHINE && (entry.registryView & KEY_WOW64_32KEY) != 0U) {
                route.unavailableText = L"该启动项位于 HKLM 32 位注册表视图；Lite 注册表浏览器不能精确定位，已不跳转。";
                return route;
            }
            rootText = registryRootText(entry.registryRoot);
            subKey = entry.registrySubKey;
        }
        if (rootText.empty() || subKey.empty()) {
            route.unavailableText = L"启动项注册表来源不完整，无法精确定位。";
            return route;
        }
        route.request.target = ksword::core::NavigationTarget::kRegistryBrowser;
        route.request.entity.kind = ksword::core::EntityKind::kRegistryKey;
        route.request.entity.text = rootText + L"\\" + subKey;
        route.available = true;
        return route;
    }
    case StartupEntryKind::kStartupFolder: {
        route.menuText = L"打开当前启动目录";
        route.failureText = L"文件模块当前无法接收启动项存储目录。";
        route.successText = L"已打开启动项当前存储目录。";
        const std::wstring kDirectory =
            ksword::features::file::PathNavigator::normalizeKnownDirectoryPath(entry.location);
        if (kDirectory.empty()) {
            route.unavailableText = L"启动项存储目录不是可精确导航的 DOS/UNC 路径。";
            return route;
        }
        route.request.target = ksword::core::NavigationTarget::kFileBrowser;
        route.request.entity.kind = ksword::core::EntityKind::kFile;
        route.request.entity.text = kDirectory;
        route.available = true;
        return route;
    }
    case StartupEntryKind::kScheduledTaskFacade: {
        route.menuText = L"打开任务存储目录";
        route.failureText = L"文件模块当前无法接收计划任务存储目录。";
        route.successText = L"已打开计划任务存储文件所在目录。";
        const std::wstring kDirectory =
            ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(entry.location);
        if (kDirectory.empty()) {
            route.unavailableText = L"计划任务存储文件不是可精确导航的 DOS/UNC 路径。";
            return route;
        }
        route.request.target = ksword::core::NavigationTarget::kFileBrowser;
        route.request.entity.kind = ksword::core::EntityKind::kFile;
        route.request.entity.text = kDirectory;
        route.available = true;
        return route;
    }
    case StartupEntryKind::kService:
        route.unavailableText = L"服务启动项没有可精确导航的注册表或文件存储来源。";
        return route;
    case StartupEntryKind::kDriverService:
        route.unavailableText = L"驱动启动项只显示 SCM 快照；Lite 不会打开或管理驱动位置。";
        return route;
    case StartupEntryKind::kRegistryOnlyService:
        route.unavailableText = L"该服务本次未由 SCM 返回（可能受访问过滤）；Lite 不会打开或管理该位置。";
        return route;
    }
    return route;
}

void openSelectedStartupProvenance(StartupViewState& state) {
    const StartupEntry* entry = findSelectedEntry(state);
    if (!entry) {
        state.statusText = L"未选择启动项。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const StartupProvenanceRoute kRoute = buildStartupProvenanceRoute(*entry);
    if (!kRoute.available) {
        state.statusText = kRoute.unavailableText;
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const bool kRouted = ksword::ui::requestEntityNavigation(state.hwnd, kRoute.request);
    state.statusText = kRouted ? kRoute.successText : kRoute.failureText;
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showStartupContextMenu(StartupViewState& state, POINT screenPoint) {
    HWND list = state.entryList.hwnd();
    if (!list) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_HitTest(list, &hit);
    if (kHitRow >= 0 && (ListView_GetItemState(list, kHitRow, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
        ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(list, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        showDetail(state, selectedModelIndex(state));
    }

    const StartupEntry* selectedEntry = findSelectedEntry(state);
    const bool kHasEntry = selectedEntry != nullptr && !state.actionInProgress;
    const bool kCanRunActions = kHasEntry && entryAllowsStartupActions(selectedEntry);
    const StartupProvenanceRoute kProvenance = selectedEntry
        ? buildStartupProvenanceRoute(*selectedEntry)
        : StartupProvenanceRoute{};
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING, kStartupMenuRefresh, L"刷新");
    HMENU actionMenu = ::CreatePopupMenu();
    if (actionMenu) {
        ::AppendMenuW(actionMenu, MF_STRING | (kCanRunActions ? 0U : MF_GRAYED), kStartupMenuEnable, L"启用");
        ::AppendMenuW(actionMenu, MF_STRING | (kCanRunActions ? 0U : MF_GRAYED), kStartupMenuDisable, L"禁用");
        ::AppendMenuW(actionMenu, MF_STRING | (kCanRunActions ? 0U : MF_GRAYED), kStartupMenuDelete, L"删除");
        ::AppendMenuW(actionMenu, MF_STRING | (kCanRunActions ? 0U : MF_GRAYED), kStartupMenuOpen, L"打开位置");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(actionMenu), L"启动项操作");
    }
    HMENU investigationMenu = ::CreatePopupMenu();
    if (investigationMenu) {
        ::AppendMenuW(investigationMenu, MF_STRING | (kProvenance.available ? 0U : MF_GRAYED),
            kStartupMenuOpenProvenance, kProvenance.menuText.c_str());
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry ? 0U : MF_GRAYED), kStartupMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry ? 0U : MF_GRAYED), kStartupMenuCopyRow, L"复制行");
        ::AppendMenuW(copyMenu, MF_STRING | (!state.entryList.visibleIndexes().empty() ? 0U : MF_GRAYED), kStartupMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasEntry ? 0U : MF_GRAYED), kStartupMenuCopyDetail, L"复制详细信息");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    switch (kCommand) {
    case kStartupMenuRefresh: beginStartupRefresh(state); break;
    case kStartupMenuEnable: runAction(state, kEnableButtonId); break;
    case kStartupMenuDisable: runAction(state, kDisableButtonId); break;
    case kStartupMenuDelete: runAction(state, kDeleteButtonId); break;
    case kStartupMenuOpen: runAction(state, kOpenButtonId); break;
    case kStartupMenuOpenProvenance: openSelectedStartupProvenance(state); break;
    case kStartupMenuCopyCell: copyCell(state); break;
    case kStartupMenuCopyRow:
        state.statusText = copyText(state.hwnd, selectedRowsAsText(state, false)) ? L"已复制行。" : L"复制行失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kStartupMenuCopyVisible:
        state.statusText = copyText(state.hwnd, selectedRowsAsText(state, true)) ? L"已复制可见结果。" : L"复制可见结果失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    case kStartupMenuCopyDetail: copyCurrentDetail(state); break;
    default: break;
    }
}

void layoutView(StartupViewState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    int x = kGap;
    ::MoveWindow(state.refreshButton, x, kGap, 78, 24, TRUE); x += 84;
    ::MoveWindow(state.enableButton, x, kGap, 78, 24, TRUE); x += 84;
    ::MoveWindow(state.disableButton, x, kGap, 78, 24, TRUE); x += 84;
    ::MoveWindow(state.deleteButton, x, kGap, 78, 24, TRUE); x += 84;
    ::MoveWindow(state.openButton, x, kGap, 94, 24, TRUE);
    ::MoveWindow(state.filterBar, kGap, 35, std::max(80, kWidth - kGap * 2), 24, TRUE);

    const int kDetailHeightValue = kHeight > 500 ? kDetailHeight : std::max(80, kHeight / 3);
    const int kListTop = kHeaderHeight + kGap;
    const int kListHeight = std::max(80, kHeight - kListTop - kDetailHeightValue - (kGap * 2));
    ::MoveWindow(state.entryList.hwnd(), kGap, kListTop, std::max(80, kWidth - (kGap * 2)), kListHeight, TRUE);
    ::MoveWindow(state.detailList, kGap, kListTop + kListHeight + kGap, std::max(80, kWidth - (kGap * 2)), kDetailHeightValue, TRUE);
    ::MoveWindow(state.loadingOverlay, kGap, kListTop, std::max(80, kWidth - (kGap * 2)), kListHeight, TRUE);
}

bool createChildControls(StartupViewState& state) {
    state.refreshButton = ksword::ui::createButton(state.hwnd, kRefreshButtonId, L"刷新", 0, 0, 78, 24);
    state.enableButton = ksword::ui::createButton(state.hwnd, kEnableButtonId, L"启用", 0, 0, 78, 24);
    state.disableButton = ksword::ui::createButton(state.hwnd, kDisableButtonId, L"禁用", 0, 0, 78, 24);
    state.deleteButton = ksword::ui::createButton(state.hwnd, kDeleteButtonId, L"删除", 0, 0, 78, 24);
    state.openButton = ksword::ui::createButton(state.hwnd, kOpenButtonId, L"打开位置", 0, 0, 94, 24);
    state.filterBar = ksword::ui::createFilterBar(state.hwnd, kFilterBarId, L"筛选名称、类型、命令、位置和详情", 0, 0, 200, 24);
    state.detailList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        0, 0, 100, 100, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailListId)), ::GetModuleHandleW(nullptr), nullptr);
    if (!state.refreshButton || !state.enableButton || !state.disableButton || !state.deleteButton || !state.openButton ||
        !state.filterBar || !state.detailList || !state.entryList.create(state.hwnd, kEntryListId, 0, 0, 100, 100)) {
        return false;
    }
    ::SendMessageW(state.entryList.hwnd(), WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ::SendMessageW(state.detailList, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ListView_SetExtendedListViewStyle(state.entryList.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    ListView_SetExtendedListViewStyle(state.detailList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    state.entryList.addColumns({
        { 0, 230, LVCFMT_LEFT, L"名称" }, { 1, 130, LVCFMT_LEFT, L"类型" }, { 2, 120, LVCFMT_LEFT, L"范围" },
        { 3, 90, LVCFMT_LEFT, L"状态" }, { 4, 360, LVCFMT_LEFT, L"命令" }, { 5, 360, LVCFMT_LEFT, L"位置" }
    });
    addColumn(state.detailList, 0, L"属性", 170);
    addColumn(state.detailList, 1, L"值", 760);
    state.loadingOverlay = ksword::ui::createLoadingOverlay(state.hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    setActionControlsEnabled(state, false);
    return true;
}

bool registerStartupViewClass() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        auto* state = reinterpret_cast<StartupViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg) {
        case WM_NCCREATE: {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            state = create ? static_cast<StartupViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
            return TRUE;
        }
        case WM_CREATE:
            if (!state || !createChildControls(*state)) {
                return -1;
            }
            state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<StartupEnumerationResult>>(hwnd, kMsgRefreshCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<StartupFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask = std::make_unique<ksword::ui::AsyncSnapshotTask<StartupActionTaskResult>>(hwnd, kMsgActionCompleted);
            layoutView(*state);
            beginStartupRefresh(*state);
            return 0;
        case WM_SIZE:
            if (state) {
                layoutView(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                requestStartupFilter(*state,
                    ksword::ui::getFilterBarText(state->filterBar),
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->entryList.hwnd(), -1, LVNI_SELECTED)),
                    stableKeyFromListItem(*state, ListView_GetTopIndex(state->entryList.hwnd())));
                return 0;
            }
            if (state && LOWORD(wParam) == kRefreshButtonId) {
                beginStartupRefresh(*state);
                return 0;
            }
            if (state && (LOWORD(wParam) == kEnableButtonId || LOWORD(wParam) == kDisableButtonId || LOWORD(wParam) == kDeleteButtonId || LOWORD(wParam) == kOpenButtonId)) {
                runAction(*state, LOWORD(wParam));
                return 0;
            }
            break;
        case kMsgRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgActionCompleted:
            if (state && state->actionTask && state->actionTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NOTIFY: {
            const auto* notify = reinterpret_cast<NMHDR*>(lParam);
            if (state && notify && notify->idFrom == kEntryListId) {
                LRESULT result = 0;
                if (state->entryList.handleNotify(*notify, result)) {
                    return result;
                }
                if (notify->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(notify);
                    if ((changed->uNewState & LVIS_SELECTED) != 0) {
                        showDetail(*state, selectedModelIndex(*state));
                    }
                    return 0;
                }
                if (notify->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showStartupContextMenu(*state, point);
                    return 0;
                }
            }
            break;
        }
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->entryList.hwnd()) {
                POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (point.x == -1 && point.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->entryList.hwnd(), &rc);
                    point = { rc.left + 20, rc.top + 20 };
                }
                showStartupContextMenu(*state, point);
                return 0;
            }
            break;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, ksword::ui::appTheme().panelBrush());
            RECT textRc{ 430, 7, rc.right - kGap, 31 };
            ksword::ui::drawTextLine(dc, state ? state->statusText : L"启动项", textRc, ksword::ui::appTheme().mutedTextColor,
                ksword::ui::systemUiFont(), DT_SINGLELINE | DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_NCDESTROY:
            if (state) {
                if (state->refreshTask) state->refreshTask->cancel();
                if (state->filterTask) state->filterTask->cancel();
                if (state->actionTask) state->actionTask->cancel();
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
    wc.hbrBackground = ksword::ui::appTheme().panelBrush();
    wc.lpszClassName = kStartupViewClass;
    return ::RegisterClassW(&wc) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

} // namespace

HWND createStartupFeatureView(HWND parent, const RECT& bounds) {
    if (!parent || !registerStartupViewClass()) {
        return nullptr;
    }
    auto* state = new StartupViewState();
    HWND hwnd = ::CreateWindowExW(0, kStartupViewClass, L"启动项",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, width(bounds), height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

} // namespace Ksword::Features::Startup

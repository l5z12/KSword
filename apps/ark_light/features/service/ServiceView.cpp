#include "ServiceView.h"

#include "ServiceActions.h"
#include "ServiceEnumerator.h"
#include "ServiceModel.h"
#include "../audit_common/AuditFormatting.h"
#include "../file/PathNavigator.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::service {
namespace {

constexpr wchar_t kServiceViewClass[] = L"KswordARKLight.Service.FeatureView";

constexpr int kRefreshButtonId = 64001;
constexpr int kStartButtonId = 64002;
constexpr int kStopButtonId = 64003;
constexpr int kPauseButtonId = 64004;
constexpr int kContinueButtonId = 64005;
constexpr int kStartTypeComboId = 64006;
constexpr int kApplyStartTypeButtonId = 64007;
constexpr int kSortComboId = 64008;
constexpr int kFilterBarId = 64009;
constexpr int kServiceListId = 64010;
constexpr int kDetailListId = 64011;
constexpr int kLoadingOverlayId = 64012;

constexpr UINT kMenuStart = 64601;
constexpr UINT kMenuStop = 64602;
constexpr UINT kMenuPause = 64603;
constexpr UINT kMenuContinue = 64604;
constexpr UINT kMenuCopyRow = 64605;
constexpr UINT kMenuCopyVisible = 64606;
constexpr UINT kMenuCopyDetail = 64607;
constexpr UINT kMenuRefresh = 64608;
constexpr UINT kMenuOpenProcess = 64609;
constexpr UINT kMenuOpenConfiguredImageDirectory = 64610;
constexpr UINT kMenuExportVisible = 64611;
constexpr UINT kMenuExportDetail = 64612;

constexpr UINT kMsgRefreshCompleted = WM_APP + 640;
constexpr UINT kMsgFilterCompleted = WM_APP + 641;
constexpr UINT kMsgActionCompleted = WM_APP + 642;
constexpr UINT kMsgDetailCompleted = WM_APP + 643;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 200;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 7;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct ServiceFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct ServiceActionTaskResult final {
    ServiceActionResult action;
    bool refreshRequired = false;
};

struct ServiceViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;
    HWND pauseButton = nullptr;
    HWND continueButton = nullptr;
    HWND startTypeCombo = nullptr;
    HWND applyStartTypeButton = nullptr;
    HWND sortCombo = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView serviceList;
    ServiceModel model;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待服务快照…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::optional<ServiceDetailSnapshot> detailSnapshot;
    std::wstring detailRequestServiceName;
    std::uint64_t detailRequestDisplayGeneration = 0;
    std::uint64_t detailSnapshotDisplayGeneration = 0;
    bool actionInProgress = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ServiceEnumerationResult>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ServiceFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ServiceActionTaskResult>> actionTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ServiceDetailSnapshot>> detailTask;
};

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
    return !text.empty() && ksword::ui::copyTextToClipboard(owner, text, L"服务模块");
}

int selectedModelIndex(const ServiceViewState& state) {
    const HWND kList = state.serviceList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.serviceList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(kModelIndex) : -1;
}

const ServiceEntry* selectedEntry(const ServiceViewState& state) {
    return state.model.entryAt(selectedModelIndex(state));
}

bool hasCurrentDetailSnapshot(const ServiceViewState& state, const ServiceEntry& entry) {
    return state.detailSnapshot.has_value() &&
        state.detailSnapshotDisplayGeneration == state.displayGeneration &&
        state.detailSnapshot->entry.serviceName == entry.serviceName;
}

std::vector<ServiceProperty> detailPropertiesForEntry(const ServiceViewState& state, const ServiceEntry& entry) {
    if (hasCurrentDetailSnapshot(state, entry)) {
        return state.detailSnapshot->properties;
    }
    return state.model.propertiesForEntry(entry);
}

std::wstring stableKeyFromListItem(const ServiceViewState& state, int item) {
    const auto& visible = state.serviceList.visibleIndexes();
    const auto& rows = state.serviceList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

void showDetail(ServiceViewState& state, int modelIndex) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const ServiceEntry* entry = state.model.entryAt(modelIndex);
    if (!entry) {
        setDetailText(state.detailList, 0, 0, L"选择");
        setDetailText(state.detailList, 0, 1, L"未选择服务");
        return;
    }
    const std::vector<ServiceProperty> kProperties = detailPropertiesForEntry(state, *entry);
    for (int row = 0; row < static_cast<int>(kProperties.size()); ++row) {
        setDetailText(state.detailList, row, 0, kProperties[static_cast<std::size_t>(row)].name);
        setDetailText(state.detailList, row, 1, kProperties[static_cast<std::size_t>(row)].value);
    }
}

// requestServiceReadOnlyDetails deliberately uses the selected list snapshot as
// its only input. The worker never mutates a service, re-enumerates the list or
// opens a driver device; it merely asks the SCM for two optional read-only
// sections. The display-generation and service-name checks prevent a result
// from one selection or refresh from being painted onto another row.
void requestServiceReadOnlyDetails(ServiceViewState& state, const int modelIndex) {
    const ServiceEntry* entry = state.model.entryAt(modelIndex);
    if (!entry || !state.detailTask || entry->serviceName.empty()) {
        return;
    }
    if (hasCurrentDetailSnapshot(state, *entry)) {
        return;
    }

    const std::wstring kServiceName = entry->serviceName;
    const std::uint64_t kDisplayGeneration = state.displayGeneration;
    if (state.detailTask->running() &&
        state.detailRequestServiceName == kServiceName &&
        state.detailRequestDisplayGeneration == kDisplayGeneration) {
        return;
    }

    const ServiceEntry kEntrySnapshot = *entry;
    state.detailRequestServiceName = kServiceName;
    state.detailRequestDisplayGeneration = kDisplayGeneration;
    state.statusText = L"正在补充所选服务的只读恢复策略和直接反向依赖…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.detailTask->request(
        [kEntrySnapshot] { return queryServiceReadOnlyDetails(kEntrySnapshot); },
        [&state, kServiceName, kDisplayGeneration](std::uint64_t,
            std::optional<ServiceDetailSnapshot>&& snapshot,
            std::exception_ptr error) {
            const ServiceEntry* selected = selectedEntry(state);
            const bool kStillSelected = selected != nullptr && selected->serviceName == kServiceName;
            const bool kStillCurrent = state.displayGeneration == kDisplayGeneration &&
                state.detailRequestServiceName == kServiceName &&
                state.detailRequestDisplayGeneration == kDisplayGeneration;
            if (!kStillSelected || !kStillCurrent) {
                return;
            }
            if (error || !snapshot.has_value()) {
                state.statusText = L"所选服务的可选只读详情查询异常结束；基础快照仍可用。";
                showDetail(state, selectedModelIndex(state));
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            state.detailSnapshot = std::move(*snapshot);
            state.detailSnapshotDisplayGeneration = kDisplayGeneration;
            state.statusText = L"已补充所选服务的只读恢复策略和直接反向依赖。";
            showDetail(state, selectedModelIndex(state));
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

// updateActionButtons keeps each button's enabled state tied to what the SCM
// would actually accept right now. Offering a control the service does not
// implement only produces an error dialog after the fact.
void updateActionButtons(ServiceViewState& state) {
    const ServiceEntry* entry = state.actionInProgress ? nullptr : selectedEntry(state);
    const bool kCanStart = entry != nullptr && serviceCanStart(*entry);
    const bool kCanStop = entry != nullptr && serviceCanStop(*entry);
    const bool kCanPause = entry != nullptr && serviceCanPause(*entry);
    const bool kCanContinue = entry != nullptr && serviceCanContinue(*entry);
    if (state.startButton) {
        ::EnableWindow(state.startButton, kCanStart);
    }
    if (state.stopButton) {
        ::EnableWindow(state.stopButton, kCanStop);
    }
    if (state.pauseButton) {
        ::EnableWindow(state.pauseButton, kCanPause);
    }
    if (state.continueButton) {
        ::EnableWindow(state.continueButton, kCanContinue);
    }
    const bool kCanApplyStartType = entry != nullptr && entry->hasConfig && !state.actionInProgress;
    if (state.applyStartTypeButton) {
        ::EnableWindow(state.applyStartTypeButton, kCanApplyStartType);
    }
    if (state.startTypeCombo) {
        ::EnableWindow(state.startTypeCombo, kCanApplyStartType);
    }
}

// syncStartTypeCombo points the combo at the selected service's current setting
// so "apply" without touching the combo is a no-op rather than a silent change
// to whatever option happened to be showing.
void syncStartTypeCombo(ServiceViewState& state) {
    if (!state.startTypeCombo) {
        return;
    }
    const ServiceEntry* entry = selectedEntry(state);
    int index = -1;
    if (entry != nullptr && entry->hasConfig) {
        switch (entry->startType) {
        case SERVICE_AUTO_START:
            index = entry->delayedAutoStart ? 1 : 0;
            break;
        case SERVICE_DEMAND_START:
            index = 2;
            break;
        case SERVICE_DISABLED:
            index = 3;
            break;
        default:
            // Boot and system start have no combo entry: they are driver-only
            // settings this page deliberately does not offer to set.
            index = -1;
            break;
        }
    }
    ::SendMessageW(state.startTypeCombo, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
}

void refreshSelectionDependentUi(ServiceViewState& state) {
    const int kSelectedModelIndex = selectedModelIndex(state);
    showDetail(state, kSelectedModelIndex);
    requestServiceReadOnlyDetails(state, kSelectedModelIndex);
    syncStartTypeCombo(state);
    updateActionButtons(state);
}

void applyServiceFilter(ServiceViewState& state, ServiceFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.serviceList.hwnd()) {
        return;
    }

    state.serviceList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.serviceList.visibleIndexes();
    const auto& rows = state.serviceList.rows();
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

    HWND list = state.serviceList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    refreshSelectionDependentUi(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestServiceFilter(ServiceViewState& state,
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
            ServiceFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ServiceFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"服务筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyServiceFilter(state, std::move(*result));
        });
}

void buildRows(ServiceViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    const auto& entries = state.model.entries();
    rows.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const ServiceEntry& entry = entries[index];
        ksword::ui::VirtualListRow row{};
        // The short name alone identifies a service on one machine, so it is a
        // stable key across refreshes even as state and PID change.
        row.stableKey = entry.serviceName;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount + 4);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(state.model.textForColumn(entry, column));
        }
        // Detail-only text joins the filter input without becoming a column, so
        // searching for a binary path or a description works from the same box.
        row.cells.push_back(entry.binaryPath);
        row.cells.push_back(entry.description);
        row.cells.push_back(entry.dependencies);
        row.cells.push_back(entry.diagnosticText);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.serviceList.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
    // A fresh enumeration or re-sort changes the row snapshot. Any optional
    // detail captured for the old order/data must not be displayed until the
    // newly selected row has completed its own read-only enrichment.
    state.detailSnapshot.reset();
    state.detailRequestServiceName.clear();
    state.detailRequestDisplayGeneration = 0;
    state.detailSnapshotDisplayGeneration = 0;
}

void beginServiceRefresh(ServiceViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.serviceList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"服务刷新已排队，等待当前快照完成…" : L"正在后台枚举服务…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在加载服务列表…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return enumerateServices(); },
        [&state](std::uint64_t, std::optional<ServiceEnumerationResult>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"服务刷新异常结束，请检查访问权限。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"服务枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, ListView_GetNextItem(state.serviceList.hwnd(), -1, LVNI_SELECTED));
            const std::wstring kTopStableKey =
                stableKeyFromListItem(state, ListView_GetTopIndex(state.serviceList.hwnd()));
            const std::size_t kTotal = snapshot->entries.size();
            std::size_t running = 0;
            std::size_t risky = 0;
            for (const ServiceEntry& entry : snapshot->entries) {
                if (entry.currentState == SERVICE_RUNNING) {
                    ++running;
                }
                if (!entry.riskText.empty()) {
                    ++risky;
                }
            }
            state.model.setEntries(std::move(snapshot->entries));
            buildRows(state);
            state.statusText = L"共 " + std::to_wstring(kTotal) + L" 个服务，运行中 " + std::to_wstring(running) +
                L"，带风险标签 " + std::to_wstring(risky) + L"。";
            requestServiceFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey,
                kTopStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

// confirmStop is the one prompt on this page. Starting, pausing and continuing
// are recoverable by doing the opposite; stopping a running service takes work
// away from whatever depends on it, and the SCM does not put it back. The
// default button is No so a stray Enter cannot stop a service.
bool confirmStop(HWND owner, const ServiceEntry& entry) {
    const std::wstring kText =
        L"将停止服务：" + entry.displayName + L"（" + entry.serviceName + L"）\n\n" +
        L"依赖该服务的组件会一并受影响，系统不会自动恢复它们。\n\n是否继续？";
    return ::MessageBoxW(owner, kText.c_str(), L"停止服务", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

ServiceActionTaskResult executeAction(const std::wstring& serviceName, int commandId) {
    ServiceActionTaskResult result{};
    switch (commandId) {
    case kStartButtonId:
        result.action = startServiceEntry(serviceName);
        break;
    case kStopButtonId:
        result.action = stopServiceEntry(serviceName);
        break;
    case kPauseButtonId:
        result.action = pauseServiceEntry(serviceName);
        break;
    case kContinueButtonId:
        result.action = continueServiceEntry(serviceName);
        break;
    default:
        result.action = { false, L"未知服务操作。" };
        break;
    }
    // Every transition changes the state column, so the table is always stale
    // afterwards -- including after a failure, where the service may have moved
    // partway before erroring out.
    result.refreshRequired = true;
    return result;
}

void runAction(ServiceViewState& state, int commandId) {
    const ServiceEntry* selected = selectedEntry(state);
    if (!selected) {
        state.statusText = L"未选择服务。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"服务操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (commandId == kStopButtonId && !confirmStop(state.hwnd, *selected)) {
        state.statusText = L"已取消停止服务。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const std::wstring kServiceName = selected->serviceName;
    state.actionInProgress = true;
    updateActionButtons(state);
    state.statusText = L"正在后台执行服务操作，最长等待 30 秒…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [kServiceName, commandId] { return executeAction(kServiceName, commandId); },
        [&state](std::uint64_t, std::optional<ServiceActionTaskResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            if (error || !result.has_value()) {
                state.statusText = L"服务操作异常结束。";
                updateActionButtons(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.statusText = result->action.message;
            if (result->refreshRequired) {
                beginServiceRefresh(state);
                return;
            }
            updateActionButtons(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void runApplyStartType(ServiceViewState& state) {
    const ServiceEntry* selected = selectedEntry(state);
    if (!selected || !state.startTypeCombo) {
        state.statusText = L"未选择服务。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.actionInProgress || !state.actionTask) {
        state.statusText = L"服务操作正在执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const LRESULT kSelection = ::SendMessageW(state.startTypeCombo, CB_GETCURSEL, 0, 0);
    if (kSelection == CB_ERR) {
        state.statusText = L"请先选择要应用的启动类型。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    ServiceStartTypeChoice choice = ServiceStartTypeChoice::kManual;
    switch (static_cast<int>(kSelection)) {
    case 0: choice = ServiceStartTypeChoice::kAutomatic; break;
    case 1: choice = ServiceStartTypeChoice::kAutomaticDelayed; break;
    case 2: choice = ServiceStartTypeChoice::kManual; break;
    case 3: choice = ServiceStartTypeChoice::kDisabled; break;
    default: break;
    }

    const std::wstring kServiceName = selected->serviceName;
    state.actionInProgress = true;
    updateActionButtons(state);
    state.statusText = L"正在写入服务启动类型…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.actionTask->request(
        [kServiceName, choice] {
            ServiceActionTaskResult result{};
            result.action = applyServiceStartType(kServiceName, choice);
            result.refreshRequired = result.action.success;
            return result;
        },
        [&state](std::uint64_t, std::optional<ServiceActionTaskResult>&& result, std::exception_ptr error) {
            state.actionInProgress = false;
            if (error || !result.has_value()) {
                state.statusText = L"启动类型写入异常结束。";
                updateActionButtons(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.statusText = result->action.message;
            if (result->refreshRequired) {
                beginServiceRefresh(state);
                return;
            }
            updateActionButtons(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring rowsAsText(const ServiceViewState& state, bool visibleRows) {
    const auto& rows = state.serviceList.rows();
    const auto& visible = state.serviceList.visibleIndexes();
    const HWND kList = state.serviceList.hwnd();
    std::vector<std::vector<std::wstring>> tsvRows;
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
        std::vector<std::wstring> tsvRow;
        tsvRow.reserve(kColumnCount);
        for (std::size_t column = 0; column < (std::min)(static_cast<std::size_t>(kColumnCount), cells.size()); ++column) {
            tsvRow.push_back(cells[column]);
        }
        tsvRows.push_back(std::move(tsvRow));
    }
    return ksword::features::audit_common::buildTsv({}, tsvRows);
}

std::wstring visibleRowsAsTsv(const ServiceViewState& state) {
    const std::wstring kRows = rowsAsText(state, true);
    if (kRows.empty()) {
        return {};
    }
    return ksword::features::audit_common::buildTsv({
        L"服务名", L"显示名", L"状态", L"启动类型", L"PID", L"账户", L"风险",
    }, {}) + kRows;
}

std::wstring detailAsText(const ServiceViewState& state) {
    const ServiceEntry* entry = selectedEntry(state);
    if (!entry) {
        return {};
    }
    const std::vector<ServiceProperty> kProperties = detailPropertiesForEntry(state, *entry);
    std::vector<std::vector<std::wstring>> rows;
    rows.reserve(kProperties.size());
    for (const ServiceProperty& property : kProperties) {
        rows.push_back({ property.name, property.value });
    }
    return ksword::features::audit_common::buildTsv({}, rows);
}

std::wstring detailAsTsv(const ServiceViewState& state) {
    const std::wstring kRows = detailAsText(state);
    if (kRows.empty()) {
        return {};
    }
    return ksword::features::audit_common::buildTsv({ L"属性", L"值" }, {}) + kRows;
}

void exportVisibleServices(ServiceViewState& state) {
    const std::wstring kText = visibleRowsAsTsv(state);
    if (kText.empty()) {
        state.statusText = L"没有可导出的服务行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd,
        L"services.tsv",
        L"导出可见服务结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        kText,
        &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        state.statusText = L"已导出当前可见服务结果。";
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        state.statusText = L"已取消导出服务结果。";
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        state.statusText = L"导出服务结果失败：" + error;
        break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void exportSelectedServiceDetail(ServiceViewState& state) {
    const std::wstring kText = detailAsTsv(state);
    if (kText.empty()) {
        state.statusText = L"未选择可导出的服务详情。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd,
        L"service_detail.tsv",
        L"导出所选服务详情",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        kText,
        &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        state.statusText = L"已导出所选服务的当前详情。";
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        state.statusText = L"已取消导出服务详情。";
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        state.statusText = L"导出服务详情失败：" + error;
        break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void openSelectedServiceProcess(ServiceViewState& state) {
    const ServiceEntry* entry = selectedEntry(state);
    if (!entry || !entry->hasStatus || entry->processId == 0U) {
        state.statusText = L"服务快照没有可导航的运行 PID。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const DWORD kProcessId = entry->processId;
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    const bool kRouted = ksword::ui::requestEntityNavigation(state.hwnd, request);
    state.statusText = kRouted
        ? L"已请求打开当前 PID " + std::to_wstring(kProcessId) + L" 的进程详细信息；服务快照归属会重新校验。"
        : L"无法导航到该服务快照的当前进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void openSelectedServiceImageDirectory(ServiceViewState& state) {
    const ServiceEntry* entry = selectedEntry(state);
    if (!entry || !entry->hasConfig) {
        state.statusText = L"服务配置不可用，无法定位配置映像。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const std::wstring kImagePath = resolveServiceImagePathForBrowser(entry->binaryPath);
    const std::wstring kDirectory =
        ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(kImagePath);
    if (kDirectory.empty()) {
        state.statusText = L"服务配置映像不是可精确导航的 DOS/UNC 文件路径。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kFileBrowser;
    request.entity.kind = ksword::core::EntityKind::kFile;
    request.entity.text = kDirectory;
    const bool kRouted = ksword::ui::requestEntityNavigation(state.hwnd, request);
    state.statusText = kRouted
        ? L"已在文件模块打开服务配置映像所在目录。"
        : L"文件模块当前无法接收服务配置映像所在目录。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showServiceContextMenu(ServiceViewState& state, POINT screenPoint) {
    const HWND kList = state.serviceList.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_SubItemHitTest(kList, &hit);
    if (kHitRow >= 0 && (ListView_GetItemState(kList, kHitRow, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
        ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(kList, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        refreshSelectionDependentUi(state);
    }

    const ServiceEntry* entry = selectedEntry(state);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool kBusy = state.actionInProgress;
    const UINT kStartFlags = MF_STRING | ((entry && serviceCanStart(*entry) && !kBusy) ? MF_ENABLED : MF_GRAYED);
    const UINT kStopFlags = MF_STRING | ((entry && serviceCanStop(*entry) && !kBusy) ? MF_ENABLED : MF_GRAYED);
    const UINT kPauseFlags = MF_STRING | ((entry && serviceCanPause(*entry) && !kBusy) ? MF_ENABLED : MF_GRAYED);
    const UINT kContinueFlags = MF_STRING | ((entry && serviceCanContinue(*entry) && !kBusy) ? MF_ENABLED : MF_GRAYED);
    const bool kCanOpenProcess = entry != nullptr && entry->hasStatus && entry->processId != 0U;
    const std::wstring kImagePath = entry && entry->hasConfig
        ? resolveServiceImagePathForBrowser(entry->binaryPath)
        : std::wstring{};
    const bool kCanOpenConfiguredImageDirectory =
        !ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(kImagePath).empty();
    ::AppendMenuW(menu, kStartFlags, kMenuStart, L"启动");
    ::AppendMenuW(menu, kStopFlags, kMenuStop, L"停止");
    ::AppendMenuW(menu, kPauseFlags, kMenuPause, L"暂停");
    ::AppendMenuW(menu, kContinueFlags, kMenuContinue, L"继续");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
    ::AppendMenuW(menu, MF_STRING, kMenuExportVisible, L"导出可见服务 TSV…");
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuExportDetail, L"导出所选服务详情 TSV…");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    HMENU investigationMenu = ::CreatePopupMenu();
    if (investigationMenu) {
        ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenProcess ? 0U : MF_GRAYED),
            kMenuOpenProcess, L"打开当前 PID 的进程详情");
        ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenConfiguredImageDirectory ? 0U : MF_GRAYED),
            kMenuOpenConfiguredImageDirectory, L"打开配置映像所在目录");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
    }
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(kCommand)) {
    case kMenuStart:
        runAction(state, kStartButtonId);
        break;
    case kMenuStop:
        runAction(state, kStopButtonId);
        break;
    case kMenuPause:
        runAction(state, kPauseButtonId);
        break;
    case kMenuContinue:
        runAction(state, kContinueButtonId);
        break;
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
    case kMenuExportVisible:
        exportVisibleServices(state);
        break;
    case kMenuExportDetail:
        exportSelectedServiceDetail(state);
        break;
    case kMenuOpenProcess:
        openSelectedServiceProcess(state);
        break;
    case kMenuOpenConfiguredImageDirectory:
        openSelectedServiceImageDirectory(state);
        break;
    case kMenuRefresh:
        beginServiceRefresh(state);
        break;
    default:
        break;
    }
}

void layoutView(ServiceViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    const int kFirstRowY = kGap;
    const auto kPlace = [&cursorX, kFirstRowY](HWND control, int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, kFirstRowY, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    kPlace(state.refreshButton, 64);
    kPlace(state.startButton, 64);
    kPlace(state.stopButton, 64);
    kPlace(state.pauseButton, 64);
    kPlace(state.continueButton, 64);
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.startTypeCombo) {
        ::MoveWindow(state.startTypeCombo, cursorX, kFirstRowY, 120, kRowHeight * 8, TRUE);
    }
    cursorX += 120 + kGap;
    if (state.applyStartTypeButton) {
        ::MoveWindow(state.applyStartTypeButton, cursorX, kFirstRowY, 96, kRowHeight, TRUE);
    }

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    if (state.sortCombo) {
        ::MoveWindow(state.sortCombo, kGap, kSecondRowY, 140, kRowHeight * 6, TRUE);
    }
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap + 140 + kGap, kSecondRowY,
            (std::max)(120, kWidth - (kGap * 3) - 140), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kDetailTop = (std::max)(kListTop, kHeight - kStatusHeight - kDetailHeight);
    const int kListHeight = (std::max)(0, kDetailTop - kListTop - kGap);
    if (HWND list = state.serviceList.hwnd()) {
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

bool createChildControls(ServiceViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.startButton = ksword::ui::createButton(hwnd, kStartButtonId, L"启动", 0, 0, 0, 0);
    state.stopButton = ksword::ui::createButton(hwnd, kStopButtonId, L"停止", 0, 0, 0, 0);
    state.pauseButton = ksword::ui::createButton(hwnd, kPauseButtonId, L"暂停", 0, 0, 0, 0);
    state.continueButton = ksword::ui::createButton(hwnd, kContinueButtonId, L"继续", 0, 0, 0, 0);
    state.applyStartTypeButton = ksword::ui::createButton(hwnd, kApplyStartTypeButtonId, L"应用启动类型", 0, 0, 0, 0);

    state.startTypeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kStartTypeComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.sortCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSortComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.startTypeCombo || !state.sortCombo) {
        return false;
    }
    for (const wchar_t* label : { L"自动", L"自动(延迟)", L"手动", L"禁用" }) {
        ::SendMessageW(state.startTypeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    for (const wchar_t* label : { L"名称升序", L"运行中优先", L"自动启动优先" }) {
        ::SendMessageW(state.sortCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.sortCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选服务名、显示名、状态、账户、路径与描述", 0, 0, 0, 0);

    if (!state.serviceList.create(hwnd, kServiceListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.serviceList.addColumns({
        { 0, 180, LVCFMT_LEFT, L"服务名" },
        { 1, 240, LVCFMT_LEFT, L"显示名" },
        { 2, 90, LVCFMT_LEFT, L"状态" },
        { 3, 100, LVCFMT_LEFT, L"启动类型" },
        { 4, 70, LVCFMT_RIGHT, L"PID" },
        { 5, 170, LVCFMT_LEFT, L"账户" },
        { 6, 180, LVCFMT_LEFT, L"风险" },
    });
    if (HWND list = state.serviceList.hwnd()) {
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
    if (!state.refreshButton || !state.startButton || !state.stopButton || !state.pauseButton ||
        !state.continueButton || !state.applyStartTypeButton || !state.filterBar || !state.detailList ||
        !state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK serviceViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ServiceViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<ServiceViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ServiceEnumerationResult>>(hwnd, kMsgRefreshCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ServiceFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ServiceActionTaskResult>>(hwnd, kMsgActionCompleted);
            state->detailTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ServiceDetailSnapshot>>(hwnd, kMsgDetailCompleted);
            layoutView(*state);
            showDetail(*state, -1);
            updateActionButtons(*state);
            beginServiceRefresh(*state);
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
                requestServiceFilter(*state, ksword::ui::getFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (kId == kSortComboId && kNotification == CBN_SELCHANGE) {
                const LRESULT kSelection = ::SendMessageW(state->sortCombo, CB_GETCURSEL, 0, 0);
                ServiceSortMode mode = ServiceSortMode::kNameAscending;
                if (kSelection == 1) {
                    mode = ServiceSortMode::kRunningFirst;
                } else if (kSelection == 2) {
                    mode = ServiceSortMode::kAutoStartFirst;
                }
                // Re-sorting reorders the model, so the row snapshot and every
                // cached visible index derived from it have to be rebuilt.
                const std::wstring kSelectedStableKey =
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->serviceList.hwnd(), -1, LVNI_SELECTED));
                state->model.setSortMode(mode);
                buildRows(*state);
                requestServiceFilter(*state,
                    ksword::ui::getFilterBarText(state->filterBar), kSelectedStableKey, {});
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                switch (kId) {
                case kRefreshButtonId:
                    beginServiceRefresh(*state);
                    return 0;
                case kStartButtonId:
                case kStopButtonId:
                case kPauseButtonId:
                case kContinueButtonId:
                    runAction(*state, kId);
                    return 0;
                case kApplyStartTypeButtonId:
                    runApplyStartType(*state);
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
                if (state->serviceList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->serviceList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        refreshSelectionDependentUi(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->serviceList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showServiceContextMenu(*state, point);
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
            if (msg == kMsgActionCompleted && state->actionTask) {
                state->actionTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgDetailCompleted && state->detailTask) {
                state->detailTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before destruction so a completion callback cannot run
            // against a half-torn-down state.
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->actionTask) {
                state->actionTask->cancel();
            }
            if (state->detailTask) {
                state->detailTask->cancel();
            }
            state->serviceList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureServiceViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = serviceViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kServiceViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createServiceView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureServiceViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kServiceViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::Service

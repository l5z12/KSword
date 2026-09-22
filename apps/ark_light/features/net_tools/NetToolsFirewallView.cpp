#include "NetToolsFirewallView.h"

#include "NetToolsEnumerator.h"
#include "NetToolsModel.h"
#include "../file/PathNavigator.h"
#include "../../core/EntityRef.h"
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
#include <climits>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::net_tools {
namespace {

constexpr wchar_t kFirewallViewClass[] = L"KswordARKLight.NetTools.FirewallView";

constexpr int kRefreshButtonId = 66301;
constexpr int kDirectionComboId = 66302;
constexpr int kFilterBarId = 66303;
constexpr int kRuleListId = 66304;
constexpr int kDetailListId = 66305;
constexpr int kLoadingOverlayId = 66306;
constexpr int kExportButtonId = 66307;

constexpr UINT kMenuCopyRow = 66351;
constexpr UINT kMenuCopyVisible = 66352;
constexpr UINT kMenuCopyDetail = 66353;
constexpr UINT kMenuRefresh = 66354;
constexpr UINT kMenuOpenApplicationDirectory = 66355;

constexpr UINT kMsgRefreshCompleted = WM_APP + 678;
constexpr UINT kMsgFilterCompleted = WM_APP + 679;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 200;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 9;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct FirewallFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct FirewallViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND directionCombo = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView ruleList;
    FirewallModel model;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在等待防火墙规则快照…";
    std::wstring profileSummary;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FirewallEnumerationResult>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FirewallFilterResult>> filterTask;
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

int selectedModelIndex(const FirewallViewState& state) {
    const HWND kList = state.ruleList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.ruleList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(kModelIndex) : -1;
}

const FirewallRuleEntry* selectedEntry(const FirewallViewState& state) {
    return state.model.entryAt(selectedModelIndex(state));
}

std::wstring stableKeyFromListItem(const FirewallViewState& state, int item) {
    const auto& visible = state.ruleList.visibleIndexes();
    const auto& rows = state.ruleList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

// firewallStableKey identifies one rule across refreshes. Rule names are not
// unique -- Windows ships whole groups of same-named rules that differ only by
// direction, protocol or program -- so the key has to carry those too.
std::wstring firewallStableKey(const FirewallRuleEntry& entry) {
    return entry.name + L"|" + std::to_wstring(entry.direction) + L"|" + std::to_wstring(entry.protocol) + L"|" +
        entry.localPorts + L"|" + entry.remotePorts + L"|" + entry.applicationName;
}

void showDetail(FirewallViewState& state, int modelIndex) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const FirewallRuleEntry* entry = state.model.entryAt(modelIndex);
    if (!entry) {
        setDetailText(state.detailList, 0, 0, L"选择");
        setDetailText(state.detailList, 0, 1, L"未选择规则");
        return;
    }
    const std::vector<NetToolsProperty> kProperties = state.model.propertiesForEntry(*entry);
    for (int row = 0; row < static_cast<int>(kProperties.size()); ++row) {
        setDetailText(state.detailList, row, 0, kProperties[static_cast<std::size_t>(row)].name);
        setDetailText(state.detailList, row, 1, kProperties[static_cast<std::size_t>(row)].value);
    }
}

void applyFirewallFilter(FirewallViewState& state, FirewallFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.ruleList.hwnd()) {
        return;
    }

    state.ruleList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.ruleList.visibleIndexes();
    const auto& rows = state.ruleList.rows();
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

    HWND list = state.ruleList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(list, topItem, FALSE);
    }
    showDetail(state, selectedModelIndex(state));
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 条规则。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestFirewallFilter(FirewallViewState& state,
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
            FirewallFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<FirewallFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"防火墙规则筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyFirewallFilter(state, std::move(*result));
        });
}

void buildRows(FirewallViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    const auto& entries = state.model.entries();
    rows.reserve(entries.size());
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const FirewallRuleEntry& entry = entries[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = firewallStableKey(entry);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount + 5);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(state.model.textForColumn(entry, column));
        }
        // Detail-only text joins the filter input without becoming a column, so
        // searching for a service name or an address range works from the same
        // box that filters the visible columns.
        row.cells.push_back(entry.description);
        row.cells.push_back(entry.grouping);
        row.cells.push_back(entry.serviceName);
        row.cells.push_back(entry.localAddresses);
        row.cells.push_back(entry.remoteAddresses);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.ruleList.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

std::wstring summaryText(const FirewallViewState& state) {
    std::size_t inbound = 0;
    std::size_t outbound = 0;
    std::size_t blocking = 0;
    std::size_t disabled = 0;
    for (const FirewallRuleEntry& entry : state.model.allEntries()) {
        if (firewallRuleIsInbound(entry)) {
            ++inbound;
        } else if (firewallRuleIsOutbound(entry)) {
            ++outbound;
        }
        if (firewallRuleIsBlocking(entry)) {
            ++blocking;
        }
        if (!entry.enabled) {
            ++disabled;
        }
    }
    std::wstring text = L"共 " + std::to_wstring(state.model.allEntries().size()) + L" 条规则（入站 " +
        std::to_wstring(inbound) + L"，出站 " + std::to_wstring(outbound) + L"，阻止 " +
        std::to_wstring(blocking) + L"，已停用 " + std::to_wstring(disabled) + L"），当前显示 " +
        std::to_wstring(state.model.entries().size()) + L" 条。";
    if (!state.profileSummary.empty()) {
        text += L" 防火墙状态：" + state.profileSummary + L"。";
    }
    return text;
}

void beginFirewallRefresh(FirewallViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.ruleList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"防火墙刷新已排队，等待当前快照完成…" : L"正在后台枚举防火墙规则…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在加载防火墙规则…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return enumerateFirewallRules(); },
        [&state](std::uint64_t, std::optional<FirewallEnumerationResult>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"防火墙规则刷新异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty() ? L"防火墙规则枚举失败。" : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, ListView_GetNextItem(state.ruleList.hwnd(), -1, LVNI_SELECTED));
            const std::wstring kTopStableKey =
                stableKeyFromListItem(state, ListView_GetTopIndex(state.ruleList.hwnd()));
            state.profileSummary = snapshot->profileSummary;
            state.model.setEntries(std::move(snapshot->entries));
            buildRows(state);
            state.statusText = summaryText(state);
            requestFirewallFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey,
                kTopStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void exportVisibleFirewallRules(FirewallViewState& state) {
    static const std::vector<std::wstring> kColumnTitles = {
        L"规则名称", L"方向", L"动作", L"启用", L"协议", L"本地端口", L"远端端口", L"配置文件", L"程序"
    };
    const std::wstring kText = ksword::ui::buildVisibleVirtualListTsv(kColumnTitles, state.ruleList);
    if (kText.empty()) {
        state.statusText = L"没有可导出的当前可见防火墙规则。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd, L"network_firewall_rules.tsv", L"导出防火墙规则",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        state.statusText = L"已导出当前可见防火墙规则。";
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        state.statusText = L"已取消导出防火墙规则。";
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        state.statusText = L"导出防火墙规则失败：" + error;
        break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

std::wstring rowsAsText(const FirewallViewState& state, bool visibleRows) {
    const auto& rows = state.ruleList.rows();
    const auto& visible = state.ruleList.visibleIndexes();
    const HWND kList = state.ruleList.hwnd();
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

std::wstring detailAsText(const FirewallViewState& state) {
    const FirewallRuleEntry* entry = selectedEntry(state);
    if (!entry) {
        return {};
    }
    std::wstring text;
    for (const NetToolsProperty& property : state.model.propertiesForEntry(*entry)) {
        text += property.name + L"\t" + property.value + L"\r\n";
    }
    return text;
}

// selectRowAtPoint keeps row-scoped context commands tied to the rule the user
// right-clicked. Empty-space clicks clear a prior selection, so no operation
// silently acts on an unrelated firewall rule.
void selectRowAtPoint(FirewallViewState& state, const POINT screenPoint) {
    const HWND kList = state.ruleList.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kClickedItem = ListView_SubItemHitTest(kList, &hit);
    ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    const auto& visible = state.ruleList.visibleIndexes();
    if (kClickedItem >= 0 && static_cast<std::size_t>(kClickedItem) < visible.size()) {
        ListView_SetItemState(kList, kClickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    showDetail(state, selectedModelIndex(state));
}

// applicationDirectoryForEntry keeps the strict source-path contract intact
// across the FileBrowser boundary. FileBrowser accepts user-entered paths and
// expands environment tokens, so a firewall rule directory containing '%' must
// stay unavailable instead of being turned into a different target later.
std::wstring applicationDirectoryForEntry(const FirewallRuleEntry* entry) {
    if (!entry) {
        return {};
    }
    const std::wstring kDirectory =
        ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(entry->applicationName);
    return kDirectory.find(L'%') == std::wstring::npos ? kDirectory : std::wstring{};
}

// openSelectedApplicationDirectory accepts only an already explicit DOS or UNC
// application file path from the current firewall rule. It does not expand
// variables, split command lines, or translate device paths into a guessed file
// system target.
void openSelectedApplicationDirectory(FirewallViewState& state) {
    const FirewallRuleEntry* entry = selectedEntry(state);
    const std::wstring kDirectory = applicationDirectoryForEntry(entry);
    if (kDirectory.empty()) {
        state.statusText = L"所选规则未提供可安全定位的程序文件路径。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kFileBrowser;
    request.entity.kind = ksword::core::EntityKind::kFile;
    request.entity.text = kDirectory;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已在文件模块打开防火墙规则程序所在目录。"
        : L"文件模块当前无法接收防火墙规则程序所在目录。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showFirewallContextMenu(FirewallViewState& state, POINT screenPoint) {
    selectRowAtPoint(state, screenPoint);
    const FirewallRuleEntry* entry = selectedEntry(state);
    const bool kHasApplicationDirectory = !applicationDirectoryForEntry(entry).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    // There is no rule mutation in this menu on purpose: the page is an audit
    // view, and a mis-click that flips a rule changes the machine's exposure.
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (entry ? MF_ENABLED : MF_GRAYED), kMenuCopyDetail, L"复制详情");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasApplicationDirectory ? MF_ENABLED : MF_GRAYED),
        kMenuOpenApplicationDirectory, L"打开规则程序所在目录");
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
    case kMenuOpenApplicationDirectory:
        openSelectedApplicationDirectory(state);
        break;
    case kMenuRefresh:
        beginFirewallRefresh(state);
        break;
    default:
        break;
    }
}

void layoutView(FirewallViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    const int kFirstRowY = kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, kGap, kFirstRowY, 64, kRowHeight, TRUE);
    }
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, kGap + 64 + kGap, kFirstRowY, 82, kRowHeight, TRUE);
    }
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.directionCombo) {
        ::MoveWindow(state.directionCombo, kGap + 64 + kGap + 82 + kGap, kFirstRowY, 120, kRowHeight * 6, TRUE);
    }

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kDetailTop = (std::max)(kListTop, kHeight - kStatusHeight - kDetailHeight);
    const int kListHeight = (std::max)(0, kDetailTop - kListTop - kGap);
    if (HWND list = state.ruleList.hwnd()) {
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

bool createChildControls(FirewallViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);

    state.directionCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDirectionComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.directionCombo) {
        return false;
    }
    for (const wchar_t* label : { L"全部方向", L"仅入站", L"仅出站" }) {
        ::SendMessageW(state.directionCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.directionCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选规则名、程序、端口、分组、服务与地址", 0, 0, 0, 0);

    if (!state.ruleList.create(hwnd, kRuleListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.ruleList.addColumns({
        { 0, 240, LVCFMT_LEFT, L"规则名称" },
        { 1, 70, LVCFMT_LEFT, L"方向" },
        { 2, 70, LVCFMT_LEFT, L"动作" },
        { 3, 60, LVCFMT_LEFT, L"启用" },
        { 4, 80, LVCFMT_LEFT, L"协议" },
        { 5, 110, LVCFMT_LEFT, L"本地端口" },
        { 6, 110, LVCFMT_LEFT, L"远端端口" },
        { 7, 110, LVCFMT_LEFT, L"配置文件" },
        { 8, 260, LVCFMT_LEFT, L"程序" },
    });
    if (HWND list = state.ruleList.hwnd()) {
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
    if (!state.refreshButton || !state.exportButton || !state.filterBar || !state.detailList || !state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK firewallViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<FirewallViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<FirewallViewState>();
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
                std::make_unique<ksword::ui::AsyncSnapshotTask<FirewallEnumerationResult>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<FirewallFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            showDetail(*state, -1);
            beginFirewallRefresh(*state);
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
                requestFirewallFilter(*state, ksword::ui::getFilterBarText(state->filterBar), {}, {});
                return 0;
            }
            if (kId == kDirectionComboId && kNotification == CBN_SELCHANGE) {
                const LRESULT kSelection = ::SendMessageW(state->directionCombo, CB_GETCURSEL, 0, 0);
                FirewallDirectionFilter filter = FirewallDirectionFilter::kAll;
                if (kSelection == 1) {
                    filter = FirewallDirectionFilter::kInbound;
                } else if (kSelection == 2) {
                    filter = FirewallDirectionFilter::kOutbound;
                }
                // Changing the direction filter reorders the model, so the row
                // snapshot and every cached visible index have to be rebuilt.
                const std::wstring kSelectedStableKey =
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->ruleList.hwnd(), -1, LVNI_SELECTED));
                state->model.setDirectionFilter(filter);
                buildRows(*state);
                state->statusText = summaryText(*state);
                requestFirewallFilter(*state,
                    ksword::ui::getFilterBarText(state->filterBar), kSelectedStableKey, {});
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                if (kId == kRefreshButtonId) {
                    beginFirewallRefresh(*state);
                    return 0;
                }
                if (kId == kExportButtonId) {
                    exportVisibleFirewallRules(*state);
                    return 0;
                }
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->ruleList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->ruleList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        showDetail(*state, selectedModelIndex(*state));
                    }
                    return 0;
                }
                if (header->hwndFrom == state->ruleList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showFirewallContextMenu(*state, point);
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
            // Cancel before destruction so a completion callback cannot run
            // against a half-torn-down state.
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->ruleList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureFirewallViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = firewallViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kFirewallViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createNetToolsFirewallView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureFirewallViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kFirewallViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::NetTools

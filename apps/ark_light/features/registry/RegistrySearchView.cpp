#include "RegistrySearchView.h"

#include "RegistryActions.h"
#include "RegistrySearchModel.h"
#include "../../core/EntityRef.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::registry {
namespace {

constexpr wchar_t kRegistrySearchViewClass[] = L"KswordARKLight.RegistrySearchView";
constexpr int kSearchHintId = 68200;
constexpr int kPathLabelId = 68201;
constexpr int kPathEditId = 68202;
constexpr int kQueryLabelId = 68203;
constexpr int kQueryEditId = 68204;
constexpr int kSearchButtonId = 68205;
constexpr int kStopButtonId = 68206;
constexpr int kExportButtonId = 68207;
constexpr int kFilterBarId = 68208;
constexpr int kResultListId = 68209;
constexpr int kStatusId = 68210;

constexpr UINT kMenuGoToKey = 68251;
constexpr UINT kMenuCopyCell = 68252;
constexpr UINT kMenuCopyRow = 68253;
constexpr UINT kMenuCopyVisible = 68254;
constexpr UINT kMenuExportVisible = 68255;

constexpr UINT kMsgSearchCompleted = WM_APP + 570;
constexpr UINT kMsgFilterCompleted = WM_APP + 571;

struct RegistrySearchFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct RegistrySearchViewState final {
    HWND hwnd = nullptr;
    HWND hintText = nullptr;
    HWND pathLabel = nullptr;
    HWND pathEdit = nullptr;
    HWND queryLabel = nullptr;
    HWND queryEdit = nullptr;
    HWND searchButton = nullptr;
    HWND stopButton = nullptr;
    HWND exportButton = nullptr;
    HWND filterBar = nullptr;
    HWND statusText = nullptr;
    ksword::ui::VirtualListView list;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<RegistrySearchSnapshot>> searchTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<RegistrySearchFilterResult>> filterTask;
    std::shared_ptr<std::atomic_bool> cancelToken;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::vector<RegistrySearchHit> hits;
    std::uint64_t displayGeneration = 0;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::wstring searchStatusText;
    int lastSubItem = 0;
    bool creationSucceeded = false;
};

RegistrySearchViewState* stateFromWindow(HWND hwnd) noexcept {
    return reinterpret_cast<RegistrySearchViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int width(const RECT& rect) noexcept {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

int height(const RECT& rect) noexcept {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

HWND createEdit(HWND parent, int id) {
    HWND edit = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        1,
        1,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (edit) {
        ::SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    return edit;
}

std::wstring windowText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1U, L'\0');
    const int kCopied = ::GetWindowTextW(hwnd, text.data(), kLength + 1);
    text.resize(kCopied > 0 ? static_cast<std::size_t>(kCopied) : 0U);
    return text;
}

const wchar_t* entryKindText(const RegistrySearchEntryKind kind) {
    return kind == RegistrySearchEntryKind::kKey ? L"键" : L"值";
}

std::vector<ksword::ui::ListViewColumn> searchColumns() {
    return {
        { 0, 64, LVCFMT_LEFT, L"类型" },
        { 1, 270, LVCFMT_LEFT, L"键路径" },
        { 2, 150, LVCFMT_LEFT, L"值名称" },
        { 3, 100, LVCFMT_LEFT, L"值类型" },
        { 4, 330, LVCFMT_LEFT, L"数据预览" },
        { 5, 76, LVCFMT_RIGHT, L"字节" },
        { 6, 56, LVCFMT_RIGHT, L"深度" },
        { 7, 76, LVCFMT_LEFT, L"预览" }
    };
}

void renderStatus(const RegistrySearchViewState& state) {
    if (state.statusText) {
        std::wstring text = state.searchStatusText;
        if (!state.filterQuery.empty()) {
            text += L"；筛选显示 " + std::to_wstring(state.list.visibleIndexes().size()) +
                L" / " + std::to_wstring(state.list.rows().size()) + L" 项。";
        }
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

void setStatus(RegistrySearchViewState& state, std::wstring text) {
    state.searchStatusText = std::move(text);
    renderStatus(state);
}

void setSearchControlsRunning(RegistrySearchViewState& state, const bool running) {
    if (state.searchButton) {
        ::EnableWindow(state.searchButton, running ? FALSE : TRUE);
    }
    if (state.pathEdit) {
        ::EnableWindow(state.pathEdit, running ? FALSE : TRUE);
    }
    if (state.queryEdit) {
        ::EnableWindow(state.queryEdit, running ? FALSE : TRUE);
    }
    if (state.stopButton) {
        ::EnableWindow(state.stopButton, running ? TRUE : FALSE);
    }
}

std::wstring stableKeyForHit(const RegistrySearchHit& hit, const std::size_t sourceIndex) {
    return std::to_wstring(static_cast<unsigned int>(hit.kind)) + L"|" + hit.keyPath + L"|" +
        hit.valueName + L"|" + std::to_wstring(hit.depth) + L"|" + std::to_wstring(sourceIndex);
}

std::wstring stableKeyFromListItem(const RegistrySearchViewState& state, const int item) {
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kRowIndex = visible[static_cast<std::size_t>(item)];
    return kRowIndex < rows.size() ? rows[kRowIndex].stableKey : std::wstring{};
}

const RegistrySearchHit* hitForListItem(const RegistrySearchViewState& state, const int item) {
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return nullptr;
    }
    const std::size_t kRowIndex = visible[static_cast<std::size_t>(item)];
    if (kRowIndex >= rows.size() || rows[kRowIndex].itemData < 0) {
        return nullptr;
    }
    const std::size_t kSourceIndex = static_cast<std::size_t>(rows[kRowIndex].itemData);
    return kSourceIndex < state.hits.size() ? &state.hits[kSourceIndex] : nullptr;
}

const RegistrySearchHit* selectedHit(const RegistrySearchViewState& state) {
    return hitForListItem(state, state.list.hwnd()
        ? ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED)
        : -1);
}

std::vector<std::size_t> visibleHitIndexes(const RegistrySearchViewState& state) {
    std::vector<std::size_t> indexes;
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    indexes.reserve(visible.size());
    for (const std::size_t kRowIndex : visible) {
        if (kRowIndex >= rows.size() || rows[kRowIndex].itemData < 0) {
            continue;
        }
        const std::size_t kHitIndex = static_cast<std::size_t>(rows[kRowIndex].itemData);
        if (kHitIndex < state.hits.size()) {
            indexes.push_back(kHitIndex);
        }
    }
    return indexes;
}

void applyFilter(RegistrySearchViewState& state, RegistrySearchFilterResult result) {
    if (!state.list.hwnd() || result.generation != state.displayGeneration ||
        result.query != state.filterQuery || result.useRegex != state.filterUseRegex) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t kRowIndex = visible[item];
        if (kRowIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && rows[kRowIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && rows[kRowIndex].stableKey == result.topStableKey) {
            topItem = static_cast<int>(item);
        }
    }
    ListView_SetItemState(state.list.hwnd(), -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem < 0 && !visible.empty()) {
        selectedItem = 0;
    }
    if (selectedItem >= 0) {
        ListView_SetItemState(state.list.hwnd(), selectedItem,
            LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        ListView_EnsureVisible(state.list.hwnd(), topItem, FALSE);
    }
    renderStatus(state);
}

void requestFilter(RegistrySearchViewState& state, std::wstring selectedStableKey, std::wstring topStableKey) {
    state.filterQuery = state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : std::wstring{};
    state.filterUseRegex = state.filterBar && ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const auto kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, query = state.filterQuery, useRegex = state.filterUseRegex,
            selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            RegistrySearchFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, result.useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<RegistrySearchFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setStatus(state, L"注册表搜索筛选异常结束，已保留当前可见结果。");
                return;
            }
            applyFilter(state, std::move(*result));
        });
}

void populateHits(RegistrySearchViewState& state) {
    const std::wstring kSelectedStableKey = stableKeyFromListItem(
        state, ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED));
    const std::wstring kTopStableKey = stableKeyFromListItem(state, ListView_GetTopIndex(state.list.hwnd()));
    auto rows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>();
    rows->reserve(state.hits.size());
    for (std::size_t index = 0; index < state.hits.size(); ++index) {
        const RegistrySearchHit& hit = state.hits[index];
        if (!hit.valid) {
            continue;
        }
        ksword::ui::VirtualListRow row{};
        row.stableKey = stableKeyForHit(hit, index);
        row.itemData = static_cast<LPARAM>(index);
        row.cells = {
            entryKindText(hit.kind),
            hit.keyPath,
            hit.valueName.empty() ? std::wstring(L"(默认)") : hit.valueName,
            hit.valueTypeText,
            hit.dataPreview,
            std::to_wstring(hit.dataByteCount),
            std::to_wstring(hit.depth),
            hit.dataPreviewTruncated ? std::wstring(L"已截断") : std::wstring(L"完整")
        };
        rows->push_back(std::move(row));
    }
    state.list.setSharedRows(rows);
    state.filterRows = std::move(rows);
    ++state.displayGeneration;
    requestFilter(state, kSelectedStableKey, kTopStableKey);
}

void beginSearch(RegistrySearchViewState& state) {
    if (!state.searchTask || state.searchTask->running()) {
        setStatus(state, L"注册表搜索正在运行或等待停止。");
        return;
    }

    RegistrySearchRequest request{};
    request.startPath = windowText(state.pathEdit);
    request.query = windowText(state.queryEdit);
    const RegistrySearchValidation kValidation = validateRegistrySearchRequest(request);
    if (!kValidation.valid) {
        RegistrySearchSnapshot invalid{};
        invalid.request = kValidation.request;
        invalid.normalizedQuery = kValidation.normalizedQuery;
        invalid.stopReason = RegistrySearchStopReason::kInvalidRequest;
        invalid.errorText = kValidation.errorText;
        setStatus(state, buildRegistrySearchStatusText(invalid));
        return;
    }

    request = kValidation.request;
    const auto kToken = std::make_shared<std::atomic_bool>(false);
    state.cancelToken = kToken;
    setSearchControlsRunning(state, true);
    setStatus(state, L"正在后台搜索当前进程 WinAPI 注册表视图…");
    state.searchTask->request(
        [request = std::move(request), kToken]() {
            return searchRegistryWinApi(request, kToken);
        },
        [&state, kToken](std::uint64_t, std::optional<RegistrySearchSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.cancelToken != kToken) {
                return;
            }
            setSearchControlsRunning(state, false);
            if (error || !snapshot.has_value()) {
                setStatus(state, L"注册表搜索后台任务异常结束，当前结果未替换。");
                return;
            }
            state.hits = std::move(snapshot->hits);
            populateHits(state);
            setStatus(state, snapshot->statusText.empty()
                ? buildRegistrySearchStatusText(*snapshot)
                : snapshot->statusText);
        });
}

void stopSearch(RegistrySearchViewState& state) {
    if (!state.cancelToken || !state.searchTask || !state.searchTask->running()) {
        return;
    }
    state.cancelToken->store(true, std::memory_order_relaxed);
    if (state.stopButton) {
        ::EnableWindow(state.stopButton, FALSE);
    }
    setStatus(state, L"正在请求停止注册表搜索；将保留已扫描的只读结果。");
}

void navigateToSelectedKey(RegistrySearchViewState& state) {
    const RegistrySearchHit* hit = selectedHit(state);
    if (!hit || hit->keyPath.empty()) {
        setStatus(state, L"请选择一个可定位的注册表搜索结果。");
        return;
    }
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kRegistryBrowser;
    request.entity.kind = ksword::core::EntityKind::kRegistryKey;
    request.entity.text = hit->keyPath;
    setStatus(state, ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已转到注册表浏览器；浏览器会重新确认当前路径。"
        : L"无法将该结果转到注册表浏览器。");
}

std::wstring selectedCellText(const RegistrySearchViewState& state) {
    const int kSelected = state.list.hwnd()
        ? ListView_GetNextItem(state.list.hwnd(), -1, LVNI_SELECTED)
        : -1;
    const auto& visible = state.list.visibleIndexes();
    const auto& rows = state.list.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return {};
    }
    const std::size_t kRowIndex = visible[static_cast<std::size_t>(kSelected)];
    if (kRowIndex >= rows.size() || rows[kRowIndex].cells.empty()) {
        return {};
    }
    const int kSubItem = (std::max)(0, (std::min)(state.lastSubItem, static_cast<int>(rows[kRowIndex].cells.size()) - 1));
    return rows[kRowIndex].cells[static_cast<std::size_t>(kSubItem)];
}

void copySelectedCell(RegistrySearchViewState& state) {
    const std::wstring kText = selectedCellText(state);
    setStatus(state, !kText.empty() && ksword::ui::copyTextToClipboard(state.hwnd, kText, L"注册表搜索单元格")
        ? L"已复制搜索单元格。"
        : L"复制搜索单元格失败。");
}

void copySelectedRow(RegistrySearchViewState& state) {
    const RegistrySearchHit* hit = selectedHit(state);
    const std::wstring kText = hit ? buildRegistrySearchTsv({ *hit }) : std::wstring{};
    setStatus(state, !kText.empty() && ksword::ui::copyTextToClipboard(state.hwnd, kText, L"注册表搜索行")
        ? L"已复制搜索行。"
        : L"复制搜索行失败。");
}

void copyVisibleRows(RegistrySearchViewState& state) {
    const std::wstring kText = buildVisibleRegistrySearchTsv(state.hits, visibleHitIndexes(state));
    setStatus(state, !kText.empty() && ksword::ui::copyTextToClipboard(state.hwnd, kText, L"注册表搜索可见结果")
        ? L"已复制可见搜索结果。"
        : L"复制可见搜索结果失败。");
}

void exportVisibleRows(RegistrySearchViewState& state) {
    const std::wstring kText = buildVisibleRegistrySearchTsv(state.hits, visibleHitIndexes(state));
    if (kText.empty()) {
        setStatus(state, L"当前没有可导出的搜索结果。");
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd,
        L"ksword-arklight-registry-search.tsv",
        L"导出注册表搜索可见结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        kText,
        &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(state, L"注册表搜索可见结果已导出。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(state, L"已取消导出注册表搜索结果。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
    default:
        setStatus(state, L"导出注册表搜索结果失败：" + error);
        break;
    }
}

void showContextMenu(RegistrySearchViewState& state, POINT screenPoint) {
    const bool kHasSelection = selectedHit(state) != nullptr;
    const bool kHasVisibleRows = !visibleHitIndexes(state).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuGoToKey, L"转到键");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (kHasVisibleRows ? 0U : MF_GRAYED), kMenuCopyVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasVisibleRows ? 0U : MF_GRAYED), kMenuExportVisible, L"导出可见 TSV");
    const UINT kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    switch (kCommand) {
    case kMenuGoToKey:
        navigateToSelectedKey(state);
        break;
    case kMenuCopyCell:
        copySelectedCell(state);
        break;
    case kMenuCopyRow:
        copySelectedRow(state);
        break;
    case kMenuCopyVisible:
        copyVisibleRows(state);
        break;
    case kMenuExportVisible:
        exportVisibleRows(state);
        break;
    default:
        break;
    }
}

void layoutChildren(RegistrySearchViewState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = (std::max)(1, width(client));
    const int kHeight = (std::max)(1, height(client));
    constexpr int kMargin = 8;
    constexpr int kHintHeight = 21;
    constexpr int kRowTop = kMargin + kHintHeight + 4;
    constexpr int kRowHeight = 25;
    constexpr int kFilterTop = kRowTop + kRowHeight + 6;
    constexpr int kFilterHeight = 27;
    constexpr int kStatusHeight = 22;
    constexpr int kGap = 6;
    constexpr int kLabelWidth = 34;
    constexpr int kSearchWidth = 54;
    constexpr int kStopWidth = 54;
    constexpr int kExportWidth = 88;
    const int kActionsWidth = kSearchWidth + kStopWidth + kExportWidth + kGap * 2;
    const int kFieldWidth = (std::max)(80, (kWidth - kMargin * 2 - kLabelWidth * 2 - kActionsWidth - kGap * 4) / 2);
    const int kPathLeft = kMargin + kLabelWidth;
    const int kQueryLabelLeft = kPathLeft + kFieldWidth + kGap;
    const int kQueryLeft = kQueryLabelLeft + kLabelWidth;
    const int kSearchLeft = kQueryLeft + kFieldWidth + kGap;
    const int kListTop = kFilterTop + kFilterHeight + 6;
    const int kListHeight = (std::max)(1, kHeight - kListTop - kStatusHeight - kMargin - 4);

    ::MoveWindow(state.hintText, kMargin, kMargin, (std::max)(1, kWidth - kMargin * 2), kHintHeight, TRUE);
    ::MoveWindow(state.pathLabel, kMargin, kRowTop, kLabelWidth, kRowHeight, TRUE);
    ::MoveWindow(state.pathEdit, kPathLeft, kRowTop, kFieldWidth, kRowHeight, TRUE);
    ::MoveWindow(state.queryLabel, kQueryLabelLeft, kRowTop, kLabelWidth, kRowHeight, TRUE);
    ::MoveWindow(state.queryEdit, kQueryLeft, kRowTop, kFieldWidth, kRowHeight, TRUE);
    ::MoveWindow(state.searchButton, kSearchLeft, kRowTop, kSearchWidth, kRowHeight, TRUE);
    ::MoveWindow(state.stopButton, kSearchLeft + kSearchWidth + kGap, kRowTop, kStopWidth, kRowHeight, TRUE);
    ::MoveWindow(state.exportButton, kSearchLeft + kSearchWidth + kStopWidth + kGap * 2, kRowTop, kExportWidth, kRowHeight, TRUE);
    ::MoveWindow(state.filterBar, kMargin, kFilterTop, (std::max)(1, kWidth - kMargin * 2), kFilterHeight, TRUE);
    ::MoveWindow(state.list.hwnd(), kMargin, kListTop, (std::max)(1, kWidth - kMargin * 2), kListHeight, TRUE);
    ::MoveWindow(state.statusText, kMargin, kListTop + kListHeight + 4, (std::max)(1, kWidth - kMargin * 2), kStatusHeight, TRUE);
}

bool createChildControls(RegistrySearchViewState& state) {
    state.hintText = ksword::ui::createText(
        state.hwnd, kSearchHintId,
        L"仅搜索当前进程的 WinAPI 注册表视图；不使用驱动，不切换或降级现有 R0 浏览模式。",
        0, 0, 1, 1);
    state.pathLabel = ksword::ui::createText(state.hwnd, kPathLabelId, L"起点", 0, 0, 1, 1);
    state.pathEdit = createEdit(state.hwnd, kPathEditId);
    state.queryLabel = ksword::ui::createText(state.hwnd, kQueryLabelId, L"关键字", 0, 0, 1, 1);
    state.queryEdit = createEdit(state.hwnd, kQueryEditId);
    state.searchButton = ksword::ui::createButton(state.hwnd, kSearchButtonId, L"搜索", 0, 0, 1, 1);
    state.stopButton = ksword::ui::createButton(state.hwnd, kStopButtonId, L"停止", 0, 0, 1, 1);
    state.exportButton = ksword::ui::createButton(state.hwnd, kExportButtonId, L"导出 TSV", 0, 0, 1, 1);
    state.filterBar = ksword::ui::createFilterBar(state.hwnd, kFilterBarId, L"筛选类型、路径、名称、预览和状态", 0, 0, 1, 1);
    state.statusText = ksword::ui::createText(state.hwnd, kStatusId, L"", 0, 0, 1, 1);
    if (!state.hintText || !state.pathLabel || !state.pathEdit || !state.queryLabel || !state.queryEdit ||
        !state.searchButton || !state.stopButton || !state.exportButton || !state.filterBar || !state.statusText ||
        !state.list.create(state.hwnd, kResultListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS)) {
        return false;
    }
    if (!state.list.addColumns(searchColumns())) {
        return false;
    }
    ListView_SetExtendedListViewStyle(
        state.list.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    ::SetWindowTextW(state.pathEdit, L"HKLM\\SOFTWARE");
    setSearchControlsRunning(state, false);
    ksword::ui::setWindowFontRecursive(state.hwnd);
    setStatus(state, L"输入起始路径和关键字后开始有界只读搜索。");
    return true;
}

LRESULT CALLBACK registrySearchViewProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    RegistrySearchViewState* state = stateFromWindow(hwnd);
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = create ? static_cast<RegistrySearchViewState*>(create->lpCreateParams) : nullptr;
        if (state) {
            state->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        }
    }

    switch (message) {
    case WM_CREATE:
        if (!state || !createChildControls(*state)) {
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return -1;
        }
        state->searchTask = std::make_unique<ksword::ui::AsyncSnapshotTask<RegistrySearchSnapshot>>(hwnd, kMsgSearchCompleted);
        state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<RegistrySearchFilterResult>>(hwnd, kMsgFilterCompleted);
        layoutChildren(*state);
        state->creationSucceeded = true;
        return 0;
    case WM_SIZE:
        if (state) {
            layoutChildren(*state);
        }
        return 0;
    case kMsgSearchCompleted:
        if (state && state->searchTask && state->searchTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header && header->hwndFrom == state->list.hwnd()) {
                LRESULT result = 0;
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->code == NM_CLICK || header->code == NM_RCLICK || header->code == NM_DBLCLK) {
                    const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(lParam);
                    if (activate && activate->iItem >= 0) {
                        state->lastSubItem = activate->iSubItem;
                        ListView_SetItemState(state->list.hwnd(), activate->iItem,
                            LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                }
                if (header->code == NM_DBLCLK) {
                    navigateToSelectedKey(*state);
                    return 0;
                }
                if (header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_COMMAND:
        if (state) {
            const int kId = LOWORD(wParam);
            const int kCode = HIWORD(wParam);
            if (kId == kFilterBarId && kCode == EN_CHANGE) {
                requestFilter(*state,
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->list.hwnd(), -1, LVNI_SELECTED)),
                    stableKeyFromListItem(*state, ListView_GetTopIndex(state->list.hwnd())));
                return 0;
            }
            if (kCode == BN_CLICKED && kId == kSearchButtonId) {
                beginSearch(*state);
                return 0;
            }
            if (kCode == BN_CLICKED && kId == kStopButtonId) {
                stopSearch(*state);
                return 0;
            }
            if (kCode == BN_CLICKED && kId == kExportButtonId) {
                exportVisibleRows(*state);
                return 0;
            }
            if (kId == kQueryEditId && kCode == EN_UPDATE) {
                return 0;
            }
        }
        break;
    case WM_CONTEXTMENU:
        if (state && reinterpret_cast<HWND>(wParam) == state->list.hwnd()) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(state->list.hwnd(), &rect);
                point = { rect.left + 24, rect.top + 24 };
            }
            showContextMenu(*state, point);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_NCDESTROY:
        if (state) {
            if (state->cancelToken) {
                state->cancelToken->store(true, std::memory_order_relaxed);
            }
            if (state->searchTask) {
                state->searchTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->list.detach();
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            if (state->creationSucceeded) {
                delete state;
            }
        }
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool registerRegistrySearchViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = registrySearchViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kRegistrySearchViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createRegistrySearchView(HWND parent, const RECT& bounds) {
    if (!parent || !registerRegistrySearchViewClass()) {
        return nullptr;
    }
    auto* state = new RegistrySearchViewState();
    HWND page = ::CreateWindowExW(
        0,
        kRegistrySearchViewClass,
        L"Registry Search",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        (std::max)(1, width(bounds)),
        (std::max)(1, height(bounds)),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!page) {
        delete state;
    }
    return page;
}

} // namespace Ksword::Features::Registry

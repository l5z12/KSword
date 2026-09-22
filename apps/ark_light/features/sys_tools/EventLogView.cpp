#include "EventLogView.h"

#include "EventLogReader.h"
#include "../../core/EntityRef.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::sys_tools {
namespace {

constexpr wchar_t kEventLogViewClass[] = L"KswordARKLight.SysTools.EventLogView";

constexpr int kChannelComboId = 67201;
constexpr int kLevelComboId = 67202;
constexpr int kCountComboId = 67203;
constexpr int kRefreshButtonId = 67204;
constexpr int kFilterBarId = 67205;
constexpr int kListId = 67206;
constexpr int kDetailEditId = 67207;
constexpr int kLoadingOverlayId = 67208;

constexpr UINT kMenuCopyRow = 67611;
constexpr UINT kMenuCopyVisible = 67612;
constexpr UINT kMenuCopyMessage = 67613;
constexpr UINT kMenuRefresh = 67614;
constexpr UINT kMenuOpenProcess = 67615;

constexpr UINT kMsgQueryCompleted = WM_APP + 705;
constexpr UINT kMsgFilterCompleted = WM_APP + 706;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kDetailHeight = 140;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 6;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct EventLogFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct EventLogViewState final {
    HWND hwnd = nullptr;
    HWND channelCombo = nullptr;
    HWND levelCombo = nullptr;
    HWND countCombo = nullptr;
    HWND refreshButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailEdit = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView list;
    std::vector<EventLogEntry> entries;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在读取系统日志…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<EventLogQueryResult>> queryTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<EventLogFilterResult>> filterTask;
};

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

std::wstring cellText(const EventLogEntry& entry, const int column) {
    switch (column) {
    case 0:
        return entry.timeText;
    case 1:
        return entry.levelText;
    case 2:
        return entry.providerName;
    case 3:
        return std::to_wstring(entry.eventId);
    case 4:
        return entry.processId != 0 ? std::to_wstring(entry.processId) : L"—";
    case 5:
        return entry.message;
    default:
        return {};
    }
}

// levelRowColor tints the two severities an operator is actually scanning for.
// Information rows keep the default color so the tinted ones still stand out.
COLORREF levelRowColor(const std::uint8_t level) {
    switch (level) {
    case 1:
    case 2:
        return RGB(176, 32, 32);
    case 3:
        return RGB(158, 104, 0);
    default:
        return CLR_DEFAULT;
    }
}

int selectedModelIndex(const EventLogViewState& state) {
    const HWND kList = state.list.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.list.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex < state.entries.size() ? static_cast<int>(kModelIndex) : -1;
}

const EventLogEntry* selectedEntry(const EventLogViewState& state) {
    const int kIndex = selectedModelIndex(state);
    return kIndex >= 0 ? &state.entries[static_cast<std::size_t>(kIndex)] : nullptr;
}

std::wstring detailTextForEntry(const EventLogEntry& entry) {
    std::wostringstream stream;
    stream << L"时间：" << entry.timeText << L"\r\n"
        << L"级别：" << entry.levelText << L"\r\n"
        << L"来源：" << entry.providerName << L"\r\n"
        << L"事件 ID：" << entry.eventId << L"\r\n"
        << L"记录号：" << entry.recordId << L"\r\n"
        << L"进程 ID：" << (entry.processId != 0 ? std::to_wstring(entry.processId) : std::wstring(L"—")) << L"\r\n"
        << L"计算机：" << entry.computer << L"\r\n\r\n"
        << entry.message;
    return stream.str();
}

void showDetail(EventLogViewState& state) {
    if (!state.detailEdit) {
        return;
    }
    const int kIndex = selectedModelIndex(state);
    if (kIndex < 0) {
        ::SetWindowTextW(state.detailEdit, L"选择一条记录查看完整描述。");
        return;
    }
    const std::wstring kText = detailTextForEntry(state.entries[static_cast<std::size_t>(kIndex)]);
    ::SetWindowTextW(state.detailEdit, kText.c_str());
}

// selectRowAtPoint makes a right-click command apply to the event under the
// pointer, never to a selection that was left by a prior record.
void selectRowAtPoint(EventLogViewState& state, const POINT screenPoint) {
    const HWND kList = state.list.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kClickedItem = ListView_SubItemHitTest(kList, &hit);
    ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (kClickedItem >= 0 && static_cast<std::size_t>(kClickedItem) < state.list.visibleIndexes().size()) {
        ListView_SetItemState(kList, kClickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    showDetail(state);
}

void applyFilterResult(EventLogViewState& state, EventLogFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.list.hwnd()) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    showDetail(state);
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestFilter(EventLogViewState& state, std::wstring query) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const auto kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    const bool kUseRegex = state.filterUseRegex;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.filterQuery]() mutable {
            EventLogFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<EventLogFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                return;
            }
            applyFilterResult(state, std::move(*result));
        });
}

void buildRows(EventLogViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.entries.size());
    for (std::size_t index = 0; index < state.entries.size(); ++index) {
        const EventLogEntry& entry = state.entries[index];
        ksword::ui::VirtualListRow row{};
        // The channel record number is unique and monotonic per channel, which
        // is exactly what a stable key needs to survive a refresh.
        row.stableKey = std::to_wstring(entry.recordId);
        row.itemData = static_cast<LPARAM>(index);
        row.textColor = levelRowColor(entry.level);
        row.cells.reserve(kColumnCount + 1);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(cellText(entry, column));
        }
        row.cells.push_back(entry.computer);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.list.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

EventLogQueryRequest currentRequest(const EventLogViewState& state) {
    EventLogQueryRequest request{};
    const LRESULT kChannel = state.channelCombo ? ::SendMessageW(state.channelCombo, CB_GETCURSEL, 0, 0) : 0;
    request.channel = kChannel == 1 ? EventLogChannel::kApplication : EventLogChannel::kSystem;

    const LRESULT kLevel = state.levelCombo ? ::SendMessageW(state.levelCombo, CB_GETCURSEL, 0, 0) : 0;
    switch (static_cast<int>(kLevel)) {
    case 1: request.level = EventLogLevelFilter::kCritical; break;
    case 2: request.level = EventLogLevelFilter::kError; break;
    case 3: request.level = EventLogLevelFilter::kWarning; break;
    case 4: request.level = EventLogLevelFilter::kInformation; break;
    default: request.level = EventLogLevelFilter::kAll; break;
    }

    const LRESULT kCount = state.countCombo ? ::SendMessageW(state.countCombo, CB_GETCURSEL, 0, 0) : 0;
    switch (static_cast<int>(kCount)) {
    case 1: request.maxCount = 500; break;
    case 2: request.maxCount = 1000; break;
    case 3: request.maxCount = 2000; break;
    default: request.maxCount = 200; break;
    }
    return request;
}

void beginQuery(EventLogViewState& state) {
    if (!state.queryTask) {
        return;
    }
    const EventLogQueryRequest kRequest = currentRequest(state);
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    state.statusText = L"正在后台读取事件日志并解析描述…";
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在读取事件日志…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.queryTask->request(
        [kRequest] { return queryEventLog(kRequest); },
        [&state](std::uint64_t, std::optional<EventLogQueryResult>&& query, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !query.has_value()) {
                state.statusText = L"事件日志读取异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!query->success) {
                state.entries.clear();
                buildRows(state);
                state.list.resetVisibleIndexes();
                state.statusText = query->diagnosticText.empty() ? L"事件日志读取失败。" : query->diagnosticText;
                showDetail(state);
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            state.entries = std::move(query->entries);
            buildRows(state);
            std::wostringstream summary;
            summary << query->channelPath << L" 通道读取 " << state.entries.size() << L" 条记录，耗时 "
                << query->elapsedMs << L" ms";
            if (query->unresolvedMessages != 0) {
                summary << L"，其中 " << query->unresolvedMessages << L" 条描述无法解析";
            }
            summary << L"。";
            if (!query->diagnosticText.empty()) {
                summary << query->diagnosticText;
            }
            state.statusText = summary.str();
            requestFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : std::wstring{});
            showDetail(state);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring rowsAsText(const EventLogViewState& state, const bool allVisible) {
    const auto& rows = state.list.rows();
    const auto& visible = state.list.visibleIndexes();
    const HWND kList = state.list.hwnd();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible &&
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

// openSelectedEventProcess intentionally routes only the current numeric PID.
// An event records its provider PID, not a stable process identity, so the
// process page must resolve the current instance before opening details.
void openSelectedEventProcess(EventLogViewState& state) {
    const EventLogEntry* entry = selectedEntry(state);
    if (!entry || entry->processId == 0U) {
        state.statusText = L"当前事件记录没有可导航的 PID。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = entry->processId;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已请求打开当前 PID " + std::to_wstring(entry->processId) +
            L" 的进程详细信息；该 PID 来自事件提供程序，目标页会重新解析当前进程实例。"
        : L"无法导航到该事件记录的当前 PID。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showContextMenu(EventLogViewState& state, POINT screenPoint) {
    selectRowAtPoint(state, screenPoint);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const EventLogEntry* entry = selectedEntry(state);
    const bool kHasSelection = entry != nullptr;
    const bool kHasCurrentProcess = entry && entry->processId != 0U;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyMessage, L"复制完整描述");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasCurrentProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenProcess, L"查看当前 PID 的进程详细信息");
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
    case kMenuCopyMessage: {
        const int kIndex = selectedModelIndex(state);
        const std::wstring kText = kIndex >= 0
            ? detailTextForEntry(state.entries[static_cast<std::size_t>(kIndex)])
            : std::wstring{};
        state.statusText = copyText(state.hwnd, kText) ? L"已复制完整描述。" : L"复制失败。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        break;
    }
    case kMenuOpenProcess:
        openSelectedEventProcess(state);
        break;
    case kMenuRefresh:
        beginQuery(state);
        break;
    default:
        break;
    }
}

void layoutView(EventLogViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    const int kFirstRowY = kGap;
    const auto kPlaceCombo = [&cursorX, kFirstRowY](HWND control, int controlWidth) {
        if (control) {
            // A drop-down list sizes its popup from the control height, not from
            // the item count, so the height passed here is intentionally tall.
            ::MoveWindow(control, cursorX, kFirstRowY, controlWidth, kRowHeight * 8, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    kPlaceCombo(state.channelCombo, 120);
    kPlaceCombo(state.levelCombo, 100);
    kPlaceCombo(state.countCombo, 100);
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, kFirstRowY, 72, kRowHeight, TRUE);
    }

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kDetailTop = (std::max)(kListTop, kHeight - kStatusHeight - kDetailHeight);
    const int kListHeight = (std::max)(0, kDetailTop - kListTop - kGap);
    if (HWND list = state.list.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.detailEdit) {
        ::MoveWindow(state.detailEdit, kGap, kDetailTop, (std::max)(0, kWidth - kGap * 2),
            (std::max)(0, kHeight - kStatusHeight - kDetailTop - kGap), TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

HWND createDropDown(HWND parent, int id) {
    return ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr), nullptr);
}

bool createChildControls(EventLogViewState& state) {
    HWND hwnd = state.hwnd;
    state.channelCombo = createDropDown(hwnd, kChannelComboId);
    state.levelCombo = createDropDown(hwnd, kLevelComboId);
    state.countCombo = createDropDown(hwnd, kCountComboId);
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    if (!state.channelCombo || !state.levelCombo || !state.countCombo || !state.refreshButton) {
        return false;
    }
    for (const wchar_t* label : { L"系统 (System)", L"应用程序 (Application)" }) {
        ::SendMessageW(state.channelCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    for (const wchar_t* label : { L"全部级别", L"关键", L"错误", L"警告", L"信息" }) {
        ::SendMessageW(state.levelCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    for (const wchar_t* label : { L"最近 200 条", L"最近 500 条", L"最近 1000 条", L"最近 2000 条" }) {
        ::SendMessageW(state.countCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.channelCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state.levelCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state.countCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选时间、级别、来源、事件 ID 与描述", 0, 0, 0, 0);
    if (!state.filterBar) {
        return false;
    }

    if (!state.list.create(hwnd, kListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list.addColumns({
        { 0, 140, LVCFMT_LEFT, L"时间" },
        { 1, 60, LVCFMT_LEFT, L"级别" },
        { 2, 210, LVCFMT_LEFT, L"来源" },
        { 3, 80, LVCFMT_RIGHT, L"事件 ID" },
        { 4, 70, LVCFMT_RIGHT, L"PID" },
        { 5, 620, LVCFMT_LEFT, L"描述" },
    });
    if (HWND list = state.list.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }

    state.detailEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"选择一条记录查看完整描述。",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.detailEdit) {
        return false;
    }
    ::SendMessageW(state.detailEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    // Event descriptions are long and unstructured, so the pane gets the shared
    // Ctrl+F find bar rather than forcing the reader to scroll them by hand.
    ksword::ui::attachTextFindSupport(state.detailEdit);

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK eventLogViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<EventLogViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<EventLogViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->queryTask = std::make_unique<ksword::ui::AsyncSnapshotTask<EventLogQueryResult>>(hwnd, kMsgQueryCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<EventLogFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            beginQuery(*state);
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
                requestFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            if (kNotification == CBN_SELCHANGE &&
                (kId == kChannelComboId || kId == kLevelComboId || kId == kCountComboId)) {
                // Channel, level and count all change what the query itself
                // asks for, so each of them has to re-read rather than re-filter.
                beginQuery(*state);
                return 0;
            }
            if (kNotification == BN_CLICKED && kId == kRefreshButtonId) {
                beginQuery(*state);
                return 0;
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        showDetail(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_RCLICK) {
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
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    default:
        if (state) {
            if (msg == kMsgQueryCompleted && state->queryTask) {
                state->queryTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->queryTask) {
                state->queryTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->list.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureEventLogViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = eventLogViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kEventLogViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createEventLogView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureEventLogViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kEventLogViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::SysTools

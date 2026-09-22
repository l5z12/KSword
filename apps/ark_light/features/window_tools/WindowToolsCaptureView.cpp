#include "WindowToolsCaptureView.h"

#include "WindowToolsCommon.h"
#include "../../core/Common.h"
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

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::window_tools {
namespace {

constexpr wchar_t kCaptureViewClass[] = L"KswordARKLight.WindowTools.CaptureView";

constexpr int kRefreshButtonId = 67101;
constexpr int kAffinityComboId = 67102;
constexpr int kApplyButtonId = 67103;
constexpr int kFilterBarId = 67104;
constexpr int kWindowListId = 67105;
constexpr int kLoadingOverlayId = 67106;
constexpr int kExportButtonId = 67107;

constexpr UINT kMenuApply = 67621;
constexpr UINT kMenuCopyRow = 67622;
constexpr UINT kMenuCopyVisible = 67623;
constexpr UINT kMenuRefresh = 67624;
constexpr UINT kMenuOpenCurrentProcess = 67625;

constexpr UINT kMsgRefreshCompleted = WM_APP + 672;
constexpr UINT kMsgFilterCompleted = WM_APP + 673;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 7;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct CaptureFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct CaptureViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND affinityCombo = nullptr;
    HWND applyButton = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView windowList;
    std::vector<TopLevelWindowInfo> windows;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在枚举顶层窗口…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<std::vector<TopLevelWindowInfo>>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<CaptureFilterResult>> filterTask;
};

// kAffinityChoices is the combo order. WDA_EXCLUDEFROMCAPTURE is offered even on
// systems that predate it: the call simply fails there, and a reported failure
// is more useful than silently hiding an option the user came looking for.
constexpr DWORD kAffinityChoices[] = { WDA_NONE, WDA_MONITOR, WDA_EXCLUDEFROMCAPTURE };

int selectedModelIndex(const CaptureViewState& state) {
    const HWND kList = state.windowList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.windowList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex < state.windows.size() ? static_cast<int>(kModelIndex) : -1;
}

const TopLevelWindowInfo* findSelectedWindow(const CaptureViewState& state) {
    const int kIndex = selectedModelIndex(state);
    return kIndex >= 0 ? &state.windows[static_cast<std::size_t>(kIndex)] : nullptr;
}

std::wstring stableKeyFromListItem(const CaptureViewState& state, const int item) {
    const auto& visible = state.windowList.visibleIndexes();
    const auto& rows = state.windowList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

void updateActionButtons(CaptureViewState& state) {
    const bool kHasSelection = findSelectedWindow(state) != nullptr;
    if (state.applyButton) {
        ::EnableWindow(state.applyButton, kHasSelection);
    }
}

void applyCaptureFilter(CaptureViewState& state, CaptureFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.windowList.hwnd()) {
        return;
    }

    state.windowList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.windowList.visibleIndexes();
    const auto& rows = state.windowList.rows();
    int selectedItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t kSourceIndex = visible[item];
        if (kSourceIndex < rows.size() && rows[kSourceIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
            break;
        }
    }

    HWND list = state.windowList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, selectedItem, FALSE);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    updateActionButtons(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 个窗口。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestCaptureFilter(CaptureViewState& state, std::wstring query, std::wstring selectedStableKey) {
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
            selectedStableKey = std::move(selectedStableKey)]() mutable {
            CaptureFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<CaptureFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"窗口筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            applyCaptureFilter(state, std::move(*result));
        });
}

void buildRows(CaptureViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.windows.size());
    for (std::size_t index = 0; index < state.windows.size(); ++index) {
        const TopLevelWindowInfo& info = state.windows[index];
        ksword::ui::VirtualListRow row{};
        // The handle value identifies a window across two refreshes closely
        // enough to restore the selection. It is not a durable identity -- a
        // recycled handle can point at a different window -- which is why every
        // action revalidates with IsWindow before touching it.
        row.stableKey = hwndText(info.hwnd);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(hwndText(info.hwnd));
        row.cells.push_back(info.title.empty() ? L"(无标题)" : info.title);
        row.cells.push_back(info.className);
        row.cells.push_back(std::to_wstring(info.processId));
        row.cells.push_back(info.processName);
        row.cells.push_back(displayAffinityText(info.displayAffinity, info.displayAffinityKnown));
        row.cells.push_back(info.visible ? L"是" : L"否");
        // Protected windows are the reason to open this tab, so they are tinted
        // instead of leaving the user to read the affinity column line by line.
        if (info.displayAffinityKnown && info.displayAffinity != WDA_NONE) {
            row.textColor = ksword::ui::appTheme().accentDarkColor;
        }
        rows.push_back(std::move(row));
    }
    auto shared = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.windowList.setRows(*shared);
    state.filterRows = std::move(shared);
    ++state.displayGeneration;
}

void beginRefresh(CaptureViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool kFirstLoad = state.windowList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"刷新已排队，等待当前快照完成…" : L"正在后台枚举顶层窗口…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在枚举窗口捕获保护状态…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return enumerateTopLevelWindowInfo(); },
        [&state](std::uint64_t, std::optional<std::vector<TopLevelWindowInfo>>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"窗口枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, ListView_GetNextItem(state.windowList.hwnd(), -1, LVNI_SELECTED));
            std::size_t protectedCount = 0;
            std::size_t unknownCount = 0;
            for (const TopLevelWindowInfo& info : *snapshot) {
                if (!info.displayAffinityKnown) {
                    ++unknownCount;
                } else if (info.displayAffinity != WDA_NONE) {
                    ++protectedCount;
                }
            }
            const std::size_t kTotal = snapshot->size();
            state.windows = std::move(*snapshot);
            buildRows(state);
            state.statusText = L"共 " + std::to_wstring(kTotal) + L" 个顶层窗口，已设置捕获保护 " +
                std::to_wstring(protectedCount) + L" 个，查询失败 " + std::to_wstring(unknownCount) + L" 个。";
            requestCaptureFilter(state,
                state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
                kSelectedStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void exportVisibleRows(CaptureViewState& state) {
    const std::wstring kText = ksword::ui::buildVisibleVirtualListTsv(
        { L"窗口句柄", L"标题", L"类名", L"PID", L"进程", L"捕获保护", L"可见" }, state.windowList);
    if (kText.empty()) {
        state.statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(state.hwnd, L"capture_protection.tsv", L"导出窗口捕获保护",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved: state.statusText = L"窗口捕获保护可见结果已导出。"; break;
    case ksword::ui::SaveTextFileResult::kCancelled: state.statusText = L"已取消导出窗口捕获保护结果。"; break;
    case ksword::ui::SaveTextFileResult::kFailed: state.statusText = L"导出窗口捕获保护结果失败：" + error; break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

DWORD selectedAffinityChoice(const CaptureViewState& state) {
    const LRESULT kSelection = state.affinityCombo ? ::SendMessageW(state.affinityCombo, CB_GETCURSEL, 0, 0) : CB_ERR;
    if (kSelection == CB_ERR || kSelection < 0 ||
        static_cast<std::size_t>(kSelection) >= sizeof(kAffinityChoices) / sizeof(kAffinityChoices[0])) {
        return WDA_NONE;
    }
    return kAffinityChoices[static_cast<std::size_t>(kSelection)];
}

// confirmApply guards the only mutating call on this page. Changing display
// affinity is not a read: WDA_MONITOR and WDA_EXCLUDEFROMCAPTURE make the target
// window disappear from screen sharing and remote sessions, which is invisible
// on the local screen and easy to leave behind by accident.
bool confirmApply(HWND owner, const TopLevelWindowInfo& info, const DWORD affinity) {
    const std::wstring kTitle = info.title.empty() ? L"(无标题)" : info.title;
    const std::wstring kText =
        L"将修改其他窗口的捕获保护属性：\n\n"
        L"窗口：" + kTitle + L"\n"
        L"句柄：" + hwndText(info.hwnd) + L"    类名：" + info.className + L"\n"
        L"进程：" + info.processName + L"（PID " + std::to_wstring(info.processId) + L"）\n\n"
        L"新的属性：" + displayAffinityText(affinity, true) + L"\n\n"
        L"设置为非 WDA_NONE 后，该窗口在屏幕共享、录屏和远程会话中会变成黑块或直接消失，"
        L"而本机屏幕上看不出任何变化。\n\n是否继续？";
    return ::MessageBoxW(owner, kText.c_str(), L"设置窗口捕获保护", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

// applyAffinity performs the change on the UI thread.
//
// SetWindowDisplayAffinity is designed for a process protecting its own windows.
// Against a foreign window it commonly fails with ERROR_ACCESS_DENIED, and it
// always fails for a window that is not top-level. The Win32 error is reported
// verbatim rather than smoothed over, because "access denied" is the answer the
// user needs, not a generic failure message.
void applyAffinity(CaptureViewState& state) {
    const TopLevelWindowInfo* selected = findSelectedWindow(state);
    if (!selected) {
        state.statusText = L"未选择窗口。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const TopLevelWindowInfo kInfo = *selected;
    if (!::IsWindow(kInfo.hwnd)) {
        state.statusText = L"目标窗口已关闭，请刷新后重试。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const DWORD kAffinity = selectedAffinityChoice(state);
    if (!confirmApply(state.hwnd, kInfo, kAffinity)) {
        state.statusText = L"已取消设置窗口捕获保护。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const bool kApplied = ::SetWindowDisplayAffinity(kInfo.hwnd, kAffinity) != FALSE;
    const DWORD kError = kApplied ? 0 : ::GetLastError();
    std::wstring message;
    if (kApplied) {
        // Read the value back instead of trusting the return code: the system
        // may downgrade an unsupported request, and only a re-query shows it.
        DWORD current = 0;
        if (::GetWindowDisplayAffinity(kInfo.hwnd, &current)) {
            message = L"已设置为 " + displayAffinityText(current, true) + L"。";
        } else {
            message = L"设置调用成功，但回读属性失败。";
        }
    } else {
        message = L"设置失败（错误码 " + std::to_wstring(kError) + L"）：" +
            ksword::core::lastErrorMessage(kError);
        if (kError == ERROR_ACCESS_DENIED) {
            message += L" 该 API 主要用于进程保护自身窗口，跨进程设置通常被拒绝。";
        }
    }

    beginRefresh(state);
    state.statusText = std::move(message);
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// currentProcessIdForWindow uses the selected snapshot only to recover the
// HWND. The current process owner is read at command time because both the HWND
// and the snapshot PID can be stale while this page stays open.
DWORD currentProcessIdForWindow(const HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd)) {
        return 0;
    }
    DWORD processId = 0;
    return ::GetWindowThreadProcessId(hwnd, &processId) != 0U ? processId : 0U;
}

// openSelectedWindowProcess is intentionally read-only and keeps the existing
// capture-protection action untouched. The process page resolves this live PID
// again before opening details, without a source-side process handle.
void openSelectedWindowProcess(CaptureViewState& state) {
    const TopLevelWindowInfo* selected = findSelectedWindow(state);
    const DWORD kProcessId = selected ? currentProcessIdForWindow(selected->hwnd) : 0U;
    if (kProcessId == 0U) {
        state.statusText = L"当前选中窗口已关闭或无法读取所属 PID。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已请求打开刚读取到的当前选中窗口所属 PID " + std::to_wstring(kProcessId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前选中窗口所属的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showContextMenu(CaptureViewState& state, const POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const TopLevelWindowInfo* selectedWindow = findSelectedWindow(state);
    const bool kHasSelection = selectedWindow != nullptr;
    const bool kHasCurrentProcess = selectedWindow && currentProcessIdForWindow(selectedWindow->hwnd) != 0U;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuApply, L"应用所选捕获保护");
    ::AppendMenuW(menu, MF_STRING | (kHasCurrentProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenCurrentProcess, L"查看当前选中窗口所属进程的详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(kCommand)) {
    case kMenuApply:
        applyAffinity(state);
        return;
    case kMenuOpenCurrentProcess:
        openSelectedWindowProcess(state);
        return;
    case kMenuCopyRow:
        state.statusText = copyTextToClipboard(state.hwnd, rowsAsTsv(state.windowList, false, kColumnCount))
            ? L"已复制选中行。" : L"复制失败。";
        break;
    case kMenuCopyVisible:
        state.statusText = copyTextToClipboard(state.hwnd, rowsAsTsv(state.windowList, true, kColumnCount))
            ? L"已复制可见行。" : L"复制失败。";
        break;
    case kMenuRefresh:
        beginRefresh(state);
        return;
    default:
        return;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void layoutView(CaptureViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, kGap, 64, kRowHeight, TRUE);
    }
    cursorX += 64 + kGap;
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, cursorX, kGap, 78, kRowHeight, TRUE);
    }
    cursorX += 78 + kGap;
    // The combo needs room for its drop-down list, which Win32 sizes from the
    // control height rather than from the item count.
    if (state.affinityCombo) {
        ::MoveWindow(state.affinityCombo, cursorX, kGap, 300, kRowHeight * 6, TRUE);
    }
    cursorX += 300 + kGap;
    if (state.applyButton) {
        ::MoveWindow(state.applyButton, cursorX, kGap, 140, kRowHeight, TRUE);
    }

    const int kSecondRowY = kGap * 2 + kRowHeight;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kListHeight = (std::max)(0, kHeight - kStatusHeight - kListTop - kGap);
    if (HWND list = state.windowList.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(CaptureViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.applyButton = ksword::ui::createButton(hwnd, kApplyButtonId, L"应用到选中窗口", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId, L"筛选句柄、标题、类名、进程与保护状态", 0, 0, 0, 0);
    state.affinityCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAffinityComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.refreshButton || !state.exportButton || !state.applyButton || !state.filterBar || !state.affinityCombo) {
        return false;
    }
    for (const DWORD kChoice : kAffinityChoices) {
        const std::wstring kLabel = displayAffinityText(kChoice, true);
        ::SendMessageW(state.affinityCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(kLabel.c_str()));
    }
    ::SendMessageW(state.affinityCombo, CB_SETCURSEL, 0, 0);

    if (!state.windowList.create(hwnd, kWindowListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.windowList.addColumns({
        { 0, 130, LVCFMT_LEFT, L"窗口句柄" },
        { 1, 260, LVCFMT_LEFT, L"标题" },
        { 2, 180, LVCFMT_LEFT, L"类名" },
        { 3, 70,  LVCFMT_RIGHT, L"PID" },
        { 4, 160, LVCFMT_LEFT, L"进程" },
        { 5, 280, LVCFMT_LEFT, L"捕获保护" },
        { 6, 60,  LVCFMT_LEFT, L"可见" },
    });
    if (HWND list = state.windowList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK captureViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<CaptureViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<CaptureViewState>();
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
                std::make_unique<ksword::ui::AsyncSnapshotTask<std::vector<TopLevelWindowInfo>>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<CaptureFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
            updateActionButtons(*state);
            beginRefresh(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (state) {
            const int kId = LOWORD(wParam);
            const int kNotification = HIWORD(wParam);
            if (kId == kFilterBarId && kNotification == EN_CHANGE) {
                requestCaptureFilter(*state, ksword::ui::getFilterBarText(state->filterBar),
                    stableKeyFromListItem(*state, ListView_GetNextItem(state->windowList.hwnd(), -1, LVNI_SELECTED)));
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                if (kId == kRefreshButtonId) {
                    beginRefresh(*state);
                    return 0;
                }
                if (kId == kExportButtonId) {
                    exportVisibleRows(*state);
                    return 0;
                }
                if (kId == kApplyButtonId) {
                    applyAffinity(*state);
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
                if (state->windowList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->windowList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        updateActionButtons(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->windowList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
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
            state->windowList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureCaptureViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = captureViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kCaptureViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createCaptureProtectionView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureCaptureViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kCaptureViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::window_tools

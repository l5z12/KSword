#include "DriverDebugOutputView.h"

#include "DriverActions.h"
#include "DriverModel.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ksword::features::driver {
namespace {

constexpr wchar_t kDriverDebugOutputClass[] = L"KswordARKLight.DriverDebugOutputView";
constexpr int kStartButtonId = 64301;
constexpr int kStopButtonId = 64302;
constexpr int kClearButtonId = 64303;
constexpr int kQueryButtonId = 64304;
constexpr int kFilterBarId = 64305;
constexpr int kListId = 64306;
constexpr UINT_PTR kDrainTimerId = 64307;
constexpr UINT kDrainIntervalMs = 150;
constexpr std::size_t kMaximumRecords = 2000;
constexpr UINT kMsgControlCompleted = WM_APP + 600;
constexpr UINT kMsgDrainCompleted = WM_APP + 601;
constexpr UINT kMsgFilterCompleted = WM_APP + 602;
constexpr UINT kMenuCopyCell = 64351;
constexpr UINT kMenuCopyRow = 64352;
constexpr UINT kMenuCopyVisible = 64353;

struct DebugRecordRow {
    std::uint64_t sequence = 0;
    std::uint64_t interruptTime100ns = 0;
    std::uint32_t componentId = 0;
    std::uint32_t level = 0;
    std::uint32_t flags = 0;
    std::wstring text;
};

struct ControlSnapshot {
    std::uint64_t requestId = 0;
    std::uint64_t captureSession = 0;
    unsigned long action = 0;
    ksword::ark::DebugOutputControlResult result;
};

struct DrainSnapshot {
    std::uint64_t captureSession = 0;
    ksword::ark::DebugOutputDrainResult result;
};

struct FilterSnapshot {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct DriverDebugOutputViewState {
    HWND hwnd = nullptr;
    HWND startButton = nullptr;
    HWND stopButton = nullptr;
    HWND clearButton = nullptr;
    HWND queryButton = nullptr;
    HWND filterBar = nullptr;
    HWND statusText = nullptr;
    HWND listView = nullptr;
    ksword::ui::VirtualListView virtualList;
    std::deque<DebugRecordRow> records;
    std::vector<DebugRecordRow> visibleRows;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    std::uint64_t controlRequestId = 0;
    std::uint64_t captureSession = 0;
    std::uint64_t nextSequence = 0;
    int contextColumn = 0;
    bool capturing = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ControlSnapshot>> controlTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<DrainSnapshot>> drainTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FilterSnapshot>> filterTask;
};

DriverDebugOutputViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverDebugOutputViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

std::wstring utf8ToWide(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int kSourceLength = static_cast<int>(std::min<std::size_t>(value.size(), static_cast<std::size_t>(INT_MAX)));
    int targetLength = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), kSourceLength, nullptr, 0);
    if (targetLength <= 0) {
        targetLength = ::MultiByteToWideChar(CP_ACP, 0, value.data(), kSourceLength, nullptr, 0);
    }
    if (targetLength <= 0) {
        return L"<无法解码的调试输出>";
    }
    std::wstring converted(static_cast<std::size_t>(targetLength), L'\0');
    if (::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), kSourceLength, converted.data(), targetLength) <= 0) {
        ::MultiByteToWideChar(CP_ACP, 0, value.data(), kSourceLength, converted.data(), targetLength);
    }
    return converted;
}

std::wstring hex32(const std::uint32_t value) {
    wchar_t buffer[16]{};
    std::swprintf(buffer, std::size(buffer), L"0x%08X", static_cast<unsigned int>(value));
    return buffer;
}

std::wstring debugStableKey(const DebugRecordRow& row) {
    return std::to_wstring(row.sequence);
}

std::vector<std::wstring> debugCells(const DebugRecordRow& row) {
    return {
        std::to_wstring(row.sequence),
        std::to_wstring(row.interruptTime100ns),
        hex32(row.componentId),
        hex32(row.level),
        hex32(row.flags),
        row.text
    };
}

std::vector<ksword::ui::VirtualListRow> buildVirtualRows(const std::deque<DebugRecordRow>& records) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(records.size());
    for (const DebugRecordRow& record : records) {
        ksword::ui::VirtualListRow row{};
        row.stableKey = debugStableKey(record);
        row.cells = debugCells(record);
        rows.push_back(std::move(row));
    }
    return rows;
}

std::wstring stableKeyAt(const DriverDebugOutputViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return debugStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void restoreListPosition(DriverDebugOutputViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring kKey = debugStableKey(state.visibleRows[index]);
        if (!selectedKey.empty() && kKey == selectedKey) {
            selectedIndex = static_cast<int>(index);
        }
        if (!topKey.empty() && kKey == topKey) {
            topIndex = static_cast<int>(index);
        }
    }
    if (selectedIndex >= 0) {
        ListView_SetItemState(state.listView, selectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topIndex >= 0) {
        ListView_EnsureVisible(state.listView, topIndex, FALSE);
    }
}

void setStatus(DriverDebugOutputViewState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

void updateControls(DriverDebugOutputViewState& state) {
    const bool kControlBusy = state.controlTask && state.controlTask->running();
    ::EnableWindow(state.startButton, !kControlBusy && !state.capturing);
    ::EnableWindow(state.stopButton, !kControlBusy && state.capturing);
    ::EnableWindow(state.queryButton, !kControlBusy);
}

std::wstring controlStatusText(const ksword::ark::DebugOutputControlResult& result) {
    if (!result.io.ok) {
        if (result.unsupported) {
            return L"当前 KswordARK 驱动不支持内核调试输出 IOCTL。";
        }
        return L"调试输出控制失败：" + utf8ToWide(result.io.message) +
            L"（Win32=" + std::to_wstring(result.io.win32Error) + L"）。";
    }
    return L"调试输出能力：环容量=" + std::to_wstring(result.ringCapacity) +
        L"，排队=" + std::to_wstring(result.queuedCount) +
        L"，最新序号=" + std::to_wstring(result.latestSequence) +
        L"，累计丢弃=" + std::to_wstring(result.droppedCount) + L"。";
}

std::wstring buildVisibleTsv(const DriverDebugOutputViewState& state, const bool selectedOnly) {
    std::wstring text = L"序号\t中断时间(100ns)\t组件\t级别\t标记\t文本\r\n";
    const int kSelected = ListView_GetNextItem(state.listView, -1, LVNI_SELECTED);
    const int kStart = selectedOnly ? kSelected : 0;
    const int kEnd = selectedOnly ? kSelected + 1 : static_cast<int>(state.visibleRows.size());
    for (int index = kStart; index >= 0 && index < kEnd; ++index) {
        const std::vector<std::wstring> kCells = debugCells(state.visibleRows[static_cast<std::size_t>(index)]);
        for (std::size_t cell = 0; cell < kCells.size(); ++cell) {
            if (cell != 0) {
                text += L'\t';
            }
            text += DriverModel::sanitizeTsvCell(kCells[cell]);
        }
        text += L"\r\n";
    }
    return text;
}

void requestFilter(DriverDebugOutputViewState& state, std::wstring query) {
    if (!state.filterTask || !state.filterRows) {
        return;
    }
    state.filterQuery = std::move(query);
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const std::uint64_t kGeneration = state.snapshotGeneration;
    const auto kRows = state.filterRows;
    const bool kUseRegex = state.filterUseRegex;
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.filterQuery]() mutable {
            FilterSnapshot result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<FilterSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value() || result->generation != state.snapshotGeneration ||
                result->query != state.filterQuery || result->useRegex != state.filterUseRegex) {
                return;
            }
            const std::wstring kSelectedKey = stableKeyAt(state, ListView_GetNextItem(state.listView, -1, LVNI_SELECTED));
            const std::wstring kTopKey = stableKeyAt(state, ListView_GetTopIndex(state.listView));
            state.visibleRows.clear();
            state.visibleRows.reserve(result->visibleIndexes.size());
            for (const std::size_t kIndex : result->visibleIndexes) {
                if (kIndex < state.records.size()) {
                    state.visibleRows.push_back(state.records[kIndex]);
                }
            }
            state.virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            restoreListPosition(state, kSelectedKey, kTopKey);
        });
}

void rebuildVirtualRows(DriverDebugOutputViewState& state) {
    state.filterRows = std::make_shared<const std::vector<ksword::ui::VirtualListRow>>(buildVirtualRows(state.records));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    requestFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery);
}

void clearRows(DriverDebugOutputViewState& state) {
    state.records.clear();
    state.visibleRows.clear();
    rebuildVirtualRows(state);
}

void requestDrain(DriverDebugOutputViewState& state) {
    if (!state.capturing || !state.drainTask) {
        return;
    }
    const std::uint64_t kSession = state.captureSession;
    const std::uint64_t kAfterSequence = state.nextSequence;
    state.drainTask->request(
        [kSession, kAfterSequence] {
            DrainSnapshot snapshot{};
            snapshot.captureSession = kSession;
            ksword::ark::DriverClient client;
            ksword::ark::DriverHandle handle = client.open();
            if (!handle.isValid()) {
                snapshot.result.io.ok = false;
                snapshot.result.io.win32Error = ::GetLastError();
                snapshot.result.io.message = "unable to open KswordARK device for debug-output drain";
                return snapshot;
            }
            snapshot.result = client.drainDebugOutput(handle, kAfterSequence, KSWORD_ARK_DEBUG_OUTPUT_MAX_DRAIN_RECORDS);
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<DrainSnapshot>&& snapshot, std::exception_ptr error) {
            if (error || !snapshot.has_value() || snapshot->captureSession != state.captureSession || !state.capturing) {
                return;
            }
            const ksword::ark::DebugOutputDrainResult& result = snapshot->result;
            if (!result.io.ok) {
                state.capturing = false;
                ::KillTimer(state.hwnd, kDrainTimerId);
                setStatus(state, result.unsupported
                    ? L"当前 KswordARK 驱动不支持内核调试输出读取 IOCTL。"
                    : L"读取内核调试输出失败：" + utf8ToWide(result.io.message));
                updateControls(state);
                return;
            }
            state.nextSequence = result.nextSequence;
            for (const ksword::ark::DebugOutputRecord& record : result.records) {
                DebugRecordRow row{};
                row.sequence = record.sequence;
                row.interruptTime100ns = record.interruptTime100ns;
                row.componentId = record.componentId;
                row.level = record.level;
                row.flags = record.flags;
                row.text = utf8ToWide(record.text);
                state.records.push_back(std::move(row));
            }
            while (state.records.size() > kMaximumRecords) {
                state.records.pop_front();
            }
            if (!result.records.empty()) {
                rebuildVirtualRows(state);
            }
            setStatus(state, L"正在捕获内核调试输出：本次=" + std::to_wstring(result.records.size()) +
                L"，缓存=" + std::to_wstring(state.records.size()) + L"/" + std::to_wstring(kMaximumRecords) +
                L"，驱动丢弃=" + std::to_wstring(result.droppedCount) +
                L"，游标覆盖=" + std::to_wstring(result.lostBeforeFirst) + L"。");
        });
}

void requestControl(DriverDebugOutputViewState& state, const unsigned long action, const std::uint64_t session) {
    if (!state.controlTask) {
        return;
    }
    const std::uint64_t kRequestId = ++state.controlRequestId;
    updateControls(state);
    state.controlTask->request(
        [kRequestId, session, action] {
            ControlSnapshot snapshot{};
            snapshot.requestId = kRequestId;
            snapshot.captureSession = session;
            snapshot.action = action;
            ksword::ark::DriverClient client;
            ksword::ark::DriverHandle handle = client.open();
            if (!handle.isValid()) {
                snapshot.result.io.ok = false;
                snapshot.result.io.win32Error = ::GetLastError();
                snapshot.result.io.message = "unable to open KswordARK device for debug-output control";
                return snapshot;
            }
            snapshot.result = client.controlDebugOutput(handle, action);
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<ControlSnapshot>&& snapshot, std::exception_ptr error) {
            if (error || !snapshot.has_value() || snapshot->requestId != state.controlRequestId) {
                setStatus(state, L"调试输出后台控制异常结束。");
                updateControls(state);
                return;
            }
            const ControlSnapshot& completed = *snapshot;
            setStatus(state, controlStatusText(completed.result));
            if (completed.action == KSWORD_ARK_DEBUG_OUTPUT_ACTION_START && completed.result.io.ok &&
                completed.captureSession == state.captureSession) {
                state.capturing = true;
                state.nextSequence = 0;
                ::SetTimer(state.hwnd, kDrainTimerId, kDrainIntervalMs, nullptr);
                requestDrain(state);
            }
            if (completed.action == KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP && completed.captureSession == state.captureSession) {
                state.capturing = false;
                ::KillTimer(state.hwnd, kDrainTimerId);
            }
            updateControls(state);
        });
    updateControls(state);
}

void startCapture(DriverDebugOutputViewState& state) {
    if (state.capturing) {
        return;
    }
    ++state.captureSession;
    state.nextSequence = 0;
    clearRows(state);
    setStatus(state, L"正在后台注册 R0 内核调试输出回调…");
    requestControl(state, KSWORD_ARK_DEBUG_OUTPUT_ACTION_START, state.captureSession);
}

void stopCapture(DriverDebugOutputViewState& state) {
    ++state.captureSession;
    state.capturing = false;
    ::KillTimer(state.hwnd, kDrainTimerId);
    setStatus(state, L"正在后台停止 R0 内核调试输出回调…");
    requestControl(state, KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP, state.captureSession);
}

void queryCapability(DriverDebugOutputViewState& state) {
    setStatus(state, L"正在后台查询调试输出能力…");
    requestControl(state, KSWORD_ARK_DEBUG_OUTPUT_ACTION_QUERY, state.captureSession);
}

std::vector<ksword::ui::ListViewColumn> columns() {
    return {
        { 0, 110, LVCFMT_RIGHT, L"序号" },
        { 1, 160, LVCFMT_RIGHT, L"中断时间 (100ns)" },
        { 2, 120, LVCFMT_LEFT, L"组件" },
        { 3, 120, LVCFMT_LEFT, L"级别" },
        { 4, 120, LVCFMT_LEFT, L"标记" },
        { 5, 760, LVCFMT_LEFT, L"调试文本" },
    };
}

void showContextMenu(DriverDebugOutputViewState& state, POINT screenPoint) {
    POINT client = screenPoint;
    ::ScreenToClient(state.listView, &client);
    LVHITTESTINFO hit{};
    hit.pt = client;
    const int kItem = ListView_HitTest(state.listView, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    if (kItem >= 0) {
        ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state.listView, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const int kSelected = ListView_GetNextItem(state.listView, -1, LVNI_SELECTED);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kSelected >= 0 ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kSelected >= 0 ? 0U : MF_GRAYED), kMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!state.visibleRows.empty() ? 0U : MF_GRAYED), kMenuCopyVisible, L"复制可见结果");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kMenuCopyCell && kSelected >= 0 && kSelected < static_cast<int>(state.visibleRows.size())) {
        const std::vector<std::wstring> kCells = debugCells(state.visibleRows[static_cast<std::size_t>(kSelected)]);
        const std::size_t kColumn = static_cast<std::size_t>(std::max(0, state.contextColumn));
        DriverActions::copyTextToClipboard(state.hwnd, kColumn < kCells.size() ? kCells[kColumn] : std::wstring{});
    } else if (kCommand == kMenuCopyRow && kSelected >= 0) {
        DriverActions::copyTextToClipboard(state.hwnd, buildVisibleTsv(state, true));
    } else if (kCommand == kMenuCopyVisible) {
        DriverActions::copyTextToClipboard(state.hwnd, buildVisibleTsv(state, false));
    }
}

void layout(DriverDebugOutputViewState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kWidth = std::max(0, static_cast<int>(rc.right - rc.left));
    const int kHeight = std::max(0, static_cast<int>(rc.bottom - rc.top));
    const int kMargin = 6;
    const int kButtonWidth = 82;
    const int kGap = 5;
    const int kToolbarHeight = 28;
    ::MoveWindow(state.startButton, kMargin, kMargin, kButtonWidth, 24, TRUE);
    ::MoveWindow(state.stopButton, kMargin + (kButtonWidth + kGap), kMargin, kButtonWidth, 24, TRUE);
    ::MoveWindow(state.clearButton, kMargin + (kButtonWidth + kGap) * 2, kMargin, 64, 24, TRUE);
    ::MoveWindow(state.queryButton, kMargin + (kButtonWidth + kGap) * 2 + 69, kMargin, 88, 24, TRUE);
    ::MoveWindow(state.statusText, kMargin + (kButtonWidth + kGap) * 2 + 162, kMargin + 2,
        std::max(100, kWidth - kMargin * 2 - (kButtonWidth + kGap) * 2 - 162), 20, TRUE);
    ::MoveWindow(state.filterBar, kMargin, kMargin + kToolbarHeight, std::max(100, kWidth - kMargin * 2), 28, TRUE);
    ::MoveWindow(state.listView, 0, kMargin + kToolbarHeight + 32, kWidth,
        std::max(40, kHeight - kMargin - kToolbarHeight - 32), TRUE);
}

bool createChildControls(DriverDebugOutputViewState& state) {
    state.startButton = ksword::ui::createButton(state.hwnd, kStartButtonId, L"开始捕获", 0, 0, 0, 0);
    state.stopButton = ksword::ui::createButton(state.hwnd, kStopButtonId, L"停止捕获", 0, 0, 0, 0);
    state.clearButton = ksword::ui::createButton(state.hwnd, kClearButtonId, L"清空", 0, 0, 0, 0);
    state.queryButton = ksword::ui::createButton(state.hwnd, kQueryButtonId, L"查询能力", 0, 0, 0, 0);
    state.statusText = ksword::ui::createText(state.hwnd, 0, L"准备查询内核调试输出能力。", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(state.hwnd, kFilterBarId,
        L"筛选序号、组件、级别、标记和调试文本", 0, 0, 0, 0);
    if (!state.startButton || !state.stopButton || !state.clearButton || !state.queryButton || !state.statusText || !state.filterBar ||
        !state.virtualList.create(state.hwnd, kListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.listView = state.virtualList.hwnd();
    state.virtualList.addColumns(columns());
    state.controlTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ControlSnapshot>>(state.hwnd, kMsgControlCompleted);
    state.drainTask = std::make_unique<ksword::ui::AsyncSnapshotTask<DrainSnapshot>>(state.hwnd, kMsgDrainCompleted);
    state.filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<FilterSnapshot>>(state.hwnd, kMsgFilterCompleted);
    ksword::ui::setWindowFontRecursive(state.hwnd);
    rebuildVirtualRows(state);
    updateControls(state);
    return true;
}

bool registerViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kDriverDebugOutputClass;
    wc.lpfnWndProc = [](HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DriverDebugOutputViewState* state = stateFromWindow(hwnd);
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DriverDebugOutputViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }
        switch (message) {
        case WM_CREATE:
            if (!state || !createChildControls(*state)) {
                return -1;
            }
            layout(*state);
            queryCapability(*state);
            return 0;
        case WM_SIZE:
            if (state) {
                layout(*state);
            }
            return 0;
        case WM_TIMER:
            if (state && wParam == kDrainTimerId) {
                requestDrain(*state);
                return 0;
            }
            break;
        case kMsgControlCompleted:
            if (state && state->controlTask && state->controlTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgDrainCompleted:
            if (state && state->drainTask && state->drainTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_COMMAND:
            if (!state) {
                break;
            }
            if (LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                requestFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            if (HIWORD(wParam) == BN_CLICKED) {
                switch (LOWORD(wParam)) {
                case kStartButtonId: startCapture(*state); return 0;
                case kStopButtonId: stopCapture(*state); return 0;
                case kClearButtonId: clearRows(*state); setStatus(*state, L"已清空本地有界调试输出缓存。"); return 0;
                case kQueryButtonId: queryCapability(*state); return 0;
                default: break;
                }
            }
            break;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                LRESULT result = 0;
                if (header && state->virtualList.handleNotify(*header, result)) {
                    return result;
                }
                if (header && header->hwndFrom == state->listView && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
            break;
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->listView) {
                POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (point.x == -1 && point.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->listView, &rc);
                    point = { rc.left + 24, rc.top + 24 };
                }
                showContextMenu(*state, point);
                return 0;
            }
            break;
        case WM_NCDESTROY:
            if (state) {
                if (state->capturing) {
                    std::thread([] {
                        ksword::ark::DriverClient client;
                        ksword::ark::DriverHandle handle = client.open();
                        if (handle.isValid()) {
                            (void)client.controlDebugOutput(handle, KSWORD_ARK_DEBUG_OUTPUT_ACTION_STOP);
                        }
                    }).detach();
                }
                ++state->captureSession;
                ::KillTimer(hwnd, kDrainTimerId);
                if (state->controlTask) state->controlTask->cancel();
                if (state->drainTask) state->drainTask->cancel();
                if (state->filterTask) state->filterTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, message, wParam, lParam);
    };
    registered = ::RegisterClassW(&wc) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createDriverDebugOutputView(HWND parent, const RECT& bounds) {
    if (!parent || !registerViewClass()) {
        return nullptr;
    }
    auto* state = new DriverDebugOutputViewState();
    HWND hwnd = ::CreateWindowExW(0, kDriverDebugOutputClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

void resizeDriverDebugOutputView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view, bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, TRUE);
    }
}

} // namespace Ksword::Features::Driver

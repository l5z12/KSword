#include "PerformanceView.h"

#include "PerformanceSampler.h"
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
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::hardware_stats {
namespace {

constexpr wchar_t kPerformanceViewClass[] = L"KswordARKLight.HardwareStats.PerformanceView";

constexpr int kRefreshButtonId = 66101;
constexpr int kPauseButtonId = 66102;
constexpr int kIntervalComboId = 66103;
constexpr int kFilterBarId = 66104;
constexpr int kMetricListId = 66105;
constexpr int kLoadingOverlayId = 66106;
constexpr int kExportButtonId = 66107;

constexpr UINT kMenuCopyRow = 66151;
constexpr UINT kMenuCopyVisible = 66152;
constexpr UINT kMenuRefresh = 66153;

constexpr UINT kMsgSampleCompleted = WM_APP + 660;
constexpr UINT_PTR kSampleTimerId = 1;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 4;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct PerformanceViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND pauseButton = nullptr;
    HWND intervalCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView metricList;
    std::shared_ptr<PerformanceSampler> sampler;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<PerformanceSnapshot>> sampleTask;
    std::wstring statusText = L"正在打开性能计数器…";
    std::wstring resolutionText;
    bool paused = false;
    bool everLoaded = false;
    UINT intervalMs = 1000;
};

PerformanceViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<PerformanceViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
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

std::wstring stableKeyFromListItem(const PerformanceViewState& state, int item) {
    const auto& visible = state.metricList.visibleIndexes();
    const auto& rows = state.metricList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

std::wstring rowsAsText(const PerformanceViewState& state, bool visibleRows) {
    const auto& rows = state.metricList.rows();
    const auto& visible = state.metricList.visibleIndexes();
    const HWND kList = state.metricList.hwnd();
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

// applyFilter recomputes the visible set on the UI thread.
//
// Every other table in this product filters on a worker because its snapshots
// run to thousands of rows. This one is a fixed handful of counters that is
// rebuilt once per second, and AsyncSnapshotTask starts a thread per request:
// pushing a sixty-row substring scan through it would cost one extra thread
// every tick to save work measured in microseconds.
void applyFilter(PerformanceViewState& state,
    const std::wstring& selectedStableKey,
    const std::wstring& topStableKey) {
    HWND list = state.metricList.hwnd();
    if (!list) {
        return;
    }
    const std::wstring kQuery = ksword::ui::getFilterBarText(state.filterBar);
    const bool kUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    state.metricList.setVisibleIndexes(
        ksword::ui::VirtualListView::filterRowIndexes(state.metricList.rows(), kQuery, kUseRegex));

    const auto& visible = state.metricList.visibleIndexes();
    const auto& rows = state.metricList.rows();
    int selectedItem = -1;
    int topItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t kSourceIndex = visible[item];
        if (kSourceIndex >= rows.size()) {
            continue;
        }
        if (selectedItem < 0 && !selectedStableKey.empty() && rows[kSourceIndex].stableKey == selectedStableKey) {
            selectedItem = static_cast<int>(item);
        }
        if (topItem < 0 && !topStableKey.empty() && rows[kSourceIndex].stableKey == topStableKey) {
            topItem = static_cast<int>(item);
        }
    }
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topItem >= 0) {
        // The table is rewritten every tick, so restoring the previous top row is
        // what stops the list from jumping back to the top under the cursor.
        ListView_EnsureVisible(list, topItem, FALSE);
    }
}

void buildRows(PerformanceViewState& state, const PerformanceSnapshot& snapshot) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(snapshot.metrics.size());
    for (std::size_t index = 0; index < snapshot.metrics.size(); ++index) {
        const PerformanceMetricRow& metric = snapshot.metrics[index];
        ksword::ui::VirtualListRow row{};
        // Group plus name identifies a metric across refreshes even though the
        // row order can shift when adapters or cores appear and disappear.
        row.stableKey = metric.group + L"\x1F" + metric.name;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(metric.group);
        row.cells.push_back(metric.name);
        row.cells.push_back(metric.value);
        row.cells.push_back(metric.source);
        if (!metric.valid) {
            row.textColor = ksword::ui::appTheme().mutedTextColor;
        }
        rows.push_back(std::move(row));
    }
    state.metricList.setRows(std::move(rows));
}

void updatePauseButton(PerformanceViewState& state) {
    if (state.pauseButton) {
        ::SetWindowTextW(state.pauseButton, state.paused ? L"继续" : L"暂停");
    }
}

void beginSample(PerformanceViewState& state) {
    if (!state.sampleTask || !state.sampler) {
        return;
    }
    if (!state.everLoaded) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在打开性能计数器并等待首个采样周期…");
    }

    const std::shared_ptr<PerformanceSampler> kSampler = state.sampler;
    state.sampleTask->request(
        // The sampler is captured by shared_ptr so an in-flight collection keeps
        // it alive even if this page is destroyed before the worker returns.
        [kSampler] { return kSampler->sample(); },
        [&state](std::uint64_t, std::optional<PerformanceSnapshot>&& snapshot, std::exception_ptr error) {
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"性能采样异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty()
                    ? L"性能计数器不可用。"
                    : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND kList = state.metricList.hwnd();
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1);
            const std::wstring kTopStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetTopIndex(kList) : -1);

            buildRows(state, *snapshot);
            applyFilter(state, kSelectedStableKey, kTopStableKey);
            state.everLoaded = true;
            state.resolutionText = snapshot->counterResolutionText;

            SYSTEMTIME now{};
            ::GetLocalTime(&now);
            wchar_t stamp[32] = {};
            swprintf_s(stamp, L"%02u:%02u:%02u",
                static_cast<unsigned>(now.wHour), static_cast<unsigned>(now.wMinute),
                static_cast<unsigned>(now.wSecond));
            state.statusText = L"共 " + std::to_wstring(snapshot->metrics.size()) + L" 项指标，最近采样 " +
                stamp + L"。" + state.resolutionText;
            if (state.paused) {
                state.statusText += L"（已暂停自动刷新）";
            }
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void showContextMenu(PerformanceViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING, kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"立即刷新");

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
    case kMenuRefresh:
        beginSample(state);
        break;
    default:
        break;
    }
}

void layoutView(PerformanceViewState& state) {
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
    kPlace(state.refreshButton, 80);
    kPlace(state.exportButton, 78);
    kPlace(state.pauseButton, 64);
    if (state.intervalCombo) {
        // Win32 sizes the drop-down list from the control height rather than
        // from the item count, so the height here is the opened list height.
        ::MoveWindow(state.intervalCombo, cursorX, kFirstRowY, 120, kRowHeight * 6, TRUE);
    }

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kListHeight = (std::max)(0, kHeight - kStatusHeight - kListTop - kGap);
    if (HWND list = state.metricList.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(PerformanceViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"立即刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.pauseButton = ksword::ui::createButton(hwnd, kPauseButtonId, L"暂停", 0, 0, 0, 0);
    state.intervalCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIntervalComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.refreshButton || !state.exportButton || !state.pauseButton || !state.intervalCombo) {
        return false;
    }
    for (const wchar_t* label : { L"每 1 秒", L"每 2 秒", L"每 5 秒" }) {
        ::SendMessageW(state.intervalCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.intervalCombo, CB_SETCURSEL, 0, 0);

    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选分组、指标名称、数值与计数器路径", 0, 0, 0, 0);
    if (!state.filterBar) {
        return false;
    }

    if (!state.metricList.create(hwnd, kMetricListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.metricList.addColumns({
        { 0, 100, LVCFMT_LEFT, L"分组" },
        { 1, 220, LVCFMT_LEFT, L"指标" },
        { 2, 200, LVCFMT_LEFT, L"当前值" },
        { 3, 460, LVCFMT_LEFT, L"计数器路径" },
    });
    if (HWND list = state.metricList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(list, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }

    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK performanceViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<PerformanceViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->sampler = makePerformanceSampler(PerformanceScope::kSystem);
            state->sampleTask =
                std::make_unique<ksword::ui::AsyncSnapshotTask<PerformanceSnapshot>>(hwnd, kMsgSampleCompleted);
            layoutView(*state);
            ::SetTimer(hwnd, kSampleTimerId, state->intervalMs, nullptr);
            beginSample(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layoutView(*state);
        }
        return 0;
    case WM_TIMER:
        if (state && wParam == kSampleTimerId) {
            // A hidden tab keeps its timer running, and sampling it would burn a
            // PDH collection and a worker thread every second for a table nobody
            // is looking at.
            if (!state->paused && ::IsWindowVisible(hwnd)) {
                beginSample(*state);
            }
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (state && wParam != 0 && !state->paused) {
            beginSample(*state);
        }
        break;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        {
            const int kId = LOWORD(wParam);
            const int kNotification = HIWORD(wParam);
            if (kId == kFilterBarId && kNotification == EN_CHANGE) {
                const HWND kList = state->metricList.hwnd();
                const std::wstring kSelectedStableKey =
                    stableKeyFromListItem(*state, kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1);
                applyFilter(*state, kSelectedStableKey, {});
                return 0;
            }
            if (kId == kIntervalComboId && kNotification == CBN_SELCHANGE) {
                const LRESULT kSelection = ::SendMessageW(state->intervalCombo, CB_GETCURSEL, 0, 0);
                UINT interval = 1000;
                if (kSelection == 1) {
                    interval = 2000;
                } else if (kSelection == 2) {
                    interval = 5000;
                }
                state->intervalMs = interval;
                ::SetTimer(hwnd, kSampleTimerId, interval, nullptr);
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                switch (kId) {
                case kRefreshButtonId:
                    beginSample(*state);
                    return 0;
                case kExportButtonId: {
                    if (state->metricList.visibleIndexes().empty()) {
                        state->statusText = L"没有可导出的可见结果。";
                    } else {
                        std::wstring error;
                        switch (ksword::ui::saveUtf8TextFileWithDialog(hwnd, L"performance.tsv", L"导出性能监控",
                            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", exportPerformanceViewTsv(hwnd), &error)) {
                        case ksword::ui::SaveTextFileResult::kSaved: state->statusText = L"性能监控可见结果已导出。"; break;
                        case ksword::ui::SaveTextFileResult::kCancelled: state->statusText = L"已取消导出性能监控结果。"; break;
                        case ksword::ui::SaveTextFileResult::kFailed: state->statusText = L"导出性能监控结果失败：" + error; break;
                        }
                    }
                    ::InvalidateRect(hwnd, nullptr, TRUE);
                    return 0;
                }
                case kPauseButtonId:
                    state->paused = !state->paused;
                    updatePauseButton(*state);
                    state->statusText = state->paused ? L"已暂停自动刷新。" : L"已恢复自动刷新。";
                    ::InvalidateRect(hwnd, nullptr, TRUE);
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
                if (state->metricList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->metricList.hwnd() && header->code == NM_RCLICK) {
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
        if (state && msg == kMsgSampleCompleted && state->sampleTask) {
            state->sampleTask->consume(hwnd, wParam, lParam);
            return 0;
        }
        if (msg == WM_NCDESTROY && state) {
            ::KillTimer(hwnd, kSampleTimerId);
            // Cancelling first guarantees no completion callback can run against
            // a half-torn-down state.
            if (state->sampleTask) {
                state->sampleTask->cancel();
            }
            state->metricList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensurePerformanceViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = performanceViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kPerformanceViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

PerformanceViewState* verifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kPerformanceViewClass) != 0) {
        return nullptr;
    }
    return stateFromWindow(view);
}

} // namespace

HWND createPerformanceView(HWND parent, const RECT& bounds) {
    if (!parent || !ensurePerformanceViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kPerformanceViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void refreshPerformanceView(HWND view) {
    if (PerformanceViewState* state = verifiedState(view)) {
        beginSample(*state);
    }
}

std::wstring exportPerformanceViewTsv(HWND view) {
    PerformanceViewState* state = verifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text = L"分组\t指标\t当前值\t计数器路径\r\n";
    text += rowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::hardware_stats

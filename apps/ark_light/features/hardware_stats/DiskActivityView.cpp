#include "DiskActivityView.h"

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

constexpr wchar_t kDiskActivityViewClass[] = L"KswordARKLight.HardwareStats.DiskActivityView";

constexpr int kRefreshButtonId = 66201;
constexpr int kPauseButtonId = 66202;
constexpr int kIntervalComboId = 66203;
constexpr int kFilterBarId = 66204;
constexpr int kDiskListId = 66205;
constexpr int kLoadingOverlayId = 66206;
constexpr int kExportButtonId = 66207;

constexpr UINT kMenuCopyRow = 66251;
constexpr UINT kMenuCopyVisible = 66252;
constexpr UINT kMenuRefresh = 66253;

constexpr UINT kMsgSampleCompleted = WM_APP + 665;
constexpr UINT_PTR kSampleTimerId = 1;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 10;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct DiskActivityViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND pauseButton = nullptr;
    HWND intervalCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView diskList;
    std::shared_ptr<PerformanceSampler> sampler;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<PerformanceSnapshot>> sampleTask;
    std::wstring statusText = L"正在打开 PhysicalDisk 计数器…";
    bool paused = false;
    bool everLoaded = false;
    UINT intervalMs = 1000;
};

DiskActivityViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<DiskActivityViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
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

std::wstring stableKeyFromListItem(const DiskActivityViewState& state, int item) {
    const auto& visible = state.diskList.visibleIndexes();
    const auto& rows = state.diskList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t kSourceIndex = visible[static_cast<std::size_t>(item)];
    return kSourceIndex < rows.size() ? rows[kSourceIndex].stableKey : std::wstring{};
}

std::wstring rowsAsText(const DiskActivityViewState& state, bool visibleRows) {
    const auto& rows = state.diskList.rows();
    const auto& visible = state.diskList.visibleIndexes();
    const HWND kList = state.diskList.hwnd();
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

// applyFilter recomputes the visible set on the UI thread. As on the performance
// tab, the row set is a handful of disks rebuilt once per second, so paying for
// a worker thread per keystroke and per tick would cost more than the scan.
void applyFilter(DiskActivityViewState& state,
    const std::wstring& selectedStableKey,
    const std::wstring& topStableKey) {
    HWND list = state.diskList.hwnd();
    if (!list) {
        return;
    }
    const std::wstring kQuery = ksword::ui::getFilterBarText(state.filterBar);
    const bool kUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    state.diskList.setVisibleIndexes(
        ksword::ui::VirtualListView::filterRowIndexes(state.diskList.rows(), kQuery, kUseRegex));

    const auto& visible = state.diskList.visibleIndexes();
    const auto& rows = state.diskList.rows();
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
        ListView_EnsureVisible(list, topItem, FALSE);
    }
}

void buildRows(DiskActivityViewState& state, const PerformanceSnapshot& snapshot) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(snapshot.disks.size());
    for (std::size_t index = 0; index < snapshot.disks.size(); ++index) {
        const DiskActivityRow& disk = snapshot.disks[index];
        ksword::ui::VirtualListRow row{};
        // The PDH instance name ("0 C:") is the only identity a physical disk has
        // in this object, and it survives across sampling passes.
        row.stableKey = disk.instance;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(disk.instance);
        row.cells.push_back(formatByteRate(disk.readBytesPerSecond));
        row.cells.push_back(formatByteRate(disk.writeBytesPerSecond));
        row.cells.push_back(formatRate(disk.readsPerSecond));
        row.cells.push_back(formatRate(disk.writesPerSecond));
        row.cells.push_back(formatDecimal(disk.currentQueueLength));
        row.cells.push_back(formatDecimal(disk.averageQueueLength));
        row.cells.push_back(formatPercent(disk.busyPercent));
        row.cells.push_back(formatLatency(disk.readLatencySeconds));
        row.cells.push_back(formatLatency(disk.writeLatencySeconds));
        rows.push_back(std::move(row));
    }
    state.diskList.setRows(std::move(rows));
}

void updatePauseButton(DiskActivityViewState& state) {
    if (state.pauseButton) {
        ::SetWindowTextW(state.pauseButton, state.paused ? L"继续" : L"暂停");
    }
}

void beginSample(DiskActivityViewState& state) {
    if (!state.sampleTask || !state.sampler) {
        return;
    }
    if (!state.everLoaded) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在打开磁盘计数器并等待首个采样周期…");
    }

    const std::shared_ptr<PerformanceSampler> kSampler = state.sampler;
    state.sampleTask->request(
        [kSampler] { return kSampler->sample(); },
        [&state](std::uint64_t, std::optional<PerformanceSnapshot>&& snapshot, std::exception_ptr error) {
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"磁盘采样异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!snapshot->success) {
                state.statusText = snapshot->diagnosticText.empty()
                    ? L"PhysicalDisk 计数器不可用。"
                    : snapshot->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            const HWND kList = state.diskList.hwnd();
            const std::wstring kSelectedStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1);
            const std::wstring kTopStableKey =
                stableKeyFromListItem(state, kList ? ListView_GetTopIndex(kList) : -1);

            buildRows(state, *snapshot);
            applyFilter(state, kSelectedStableKey, kTopStableKey);
            state.everLoaded = true;

            SYSTEMTIME now{};
            ::GetLocalTime(&now);
            wchar_t stamp[32] = {};
            swprintf_s(stamp, L"%02u:%02u:%02u",
                static_cast<unsigned>(now.wHour), static_cast<unsigned>(now.wMinute),
                static_cast<unsigned>(now.wSecond));
            state.statusText = L"共 " + std::to_wstring(snapshot->disks.size()) + L" 个磁盘实例（含 _Total 汇总行），最近采样 " +
                stamp + L"。" + snapshot->counterResolutionText;
            if (state.paused) {
                state.statusText += L"（已暂停自动刷新）";
            }
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void showContextMenu(DiskActivityViewState& state, POINT screenPoint) {
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

void layoutView(DiskActivityViewState& state) {
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
        ::MoveWindow(state.intervalCombo, cursorX, kFirstRowY, 120, kRowHeight * 6, TRUE);
    }

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kListHeight = (std::max)(0, kHeight - kStatusHeight - kListTop - kGap);
    if (HWND list = state.diskList.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(DiskActivityViewState& state) {
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

    state.filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId, L"筛选磁盘实例名", 0, 0, 0, 0);
    if (!state.filterBar) {
        return false;
    }

    if (!state.diskList.create(hwnd, kDiskListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.diskList.addColumns({
        { 0, 150, LVCFMT_LEFT, L"物理磁盘" },
        { 1, 120, LVCFMT_RIGHT, L"读取吞吐" },
        { 2, 120, LVCFMT_RIGHT, L"写入吞吐" },
        { 3, 100, LVCFMT_RIGHT, L"读 IOPS" },
        { 4, 100, LVCFMT_RIGHT, L"写 IOPS" },
        { 5, 100, LVCFMT_RIGHT, L"当前队列" },
        { 6, 100, LVCFMT_RIGHT, L"平均队列" },
        { 7, 100, LVCFMT_RIGHT, L"忙碌比例" },
        { 8, 100, LVCFMT_RIGHT, L"读延迟" },
        { 9, 100, LVCFMT_RIGHT, L"写延迟" },
    });
    if (HWND list = state.diskList.hwnd()) {
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

LRESULT CALLBACK diskActivityViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<DiskActivityViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->sampler = makePerformanceSampler(PerformanceScope::kPhysicalDisk);
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
                const HWND kList = state->diskList.hwnd();
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
                    if (state->diskList.visibleIndexes().empty()) {
                        state->statusText = L"没有可导出的可见结果。";
                    } else {
                        std::wstring error;
                        switch (ksword::ui::saveUtf8TextFileWithDialog(hwnd, L"disk_activity.tsv", L"导出磁盘活动",
                            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", exportDiskActivityViewTsv(hwnd), &error)) {
                        case ksword::ui::SaveTextFileResult::kSaved: state->statusText = L"磁盘活动可见结果已导出。"; break;
                        case ksword::ui::SaveTextFileResult::kCancelled: state->statusText = L"已取消导出磁盘活动结果。"; break;
                        case ksword::ui::SaveTextFileResult::kFailed: state->statusText = L"导出磁盘活动结果失败：" + error; break;
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
                if (state->diskList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->diskList.hwnd() && header->code == NM_RCLICK) {
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
            if (state->sampleTask) {
                state->sampleTask->cancel();
            }
            state->diskList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureDiskActivityViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = diskActivityViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kDiskActivityViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

DiskActivityViewState* verifiedState(HWND view) {
    if (!view) {
        return nullptr;
    }
    wchar_t className[64] = {};
    if (::GetClassNameW(view, className, ARRAYSIZE(className)) <= 0 ||
        std::wcscmp(className, kDiskActivityViewClass) != 0) {
        return nullptr;
    }
    return stateFromWindow(view);
}

} // namespace

HWND createDiskActivityView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureDiskActivityViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kDiskActivityViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void refreshDiskActivityView(HWND view) {
    if (DiskActivityViewState* state = verifiedState(view)) {
        beginSample(*state);
    }
}

std::wstring exportDiskActivityViewTsv(HWND view) {
    DiskActivityViewState* state = verifiedState(view);
    if (!state) {
        return {};
    }
    std::wstring text =
        L"物理磁盘\t读取吞吐\t写入吞吐\t读 IOPS\t写 IOPS\t当前队列\t平均队列\t忙碌比例\t读延迟\t写延迟\r\n";
    text += rowsAsText(*state, true);
    return text;
}

} // namespace Ksword::Features::hardware_stats

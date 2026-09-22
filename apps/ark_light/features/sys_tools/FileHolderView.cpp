#include "FileHolderView.h"

#include "FileHolderScanner.h"
#include "../../core/EntityRef.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::sys_tools {
namespace {

constexpr wchar_t kFileHolderViewClass[] = L"KswordARKLight.SysTools.FileHolderView";

constexpr int kPathEditId = 67101;
constexpr int kBrowseButtonId = 67102;
constexpr int kScanButtonId = 67103;
constexpr int kSubPathCheckId = 67104;
constexpr int kFilterBarId = 67105;
constexpr int kListId = 67106;
constexpr int kLoadingOverlayId = 67107;

constexpr UINT kMenuCopyRow = 67601;
constexpr UINT kMenuCopyVisible = 67602;
constexpr UINT kMenuOpenLocation = 67603;
constexpr UINT kMenuRescan = 67604;
constexpr UINT kMenuOpenProcessDetails = 67605;

constexpr UINT kMsgScanCompleted = WM_APP + 700;
constexpr UINT kMsgFilterCompleted = WM_APP + 701;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 6;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct FileHolderFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct FileHolderViewState final {
    HWND hwnd = nullptr;
    HWND pathEdit = nullptr;
    HWND browseButton = nullptr;
    HWND scanButton = nullptr;
    HWND subPathCheck = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    ksword::ui::VirtualListView list;
    std::vector<FileHolderEntry> entries;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"输入文件或目录路径后点击“扫描占用”。";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    bool scanInProgress = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FileHolderScanResult>> scanTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FileHolderFilterResult>> filterTask;
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

std::wstring windowText(HWND control) {
    if (!control) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(control);
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1, L'\0');
    const int kCopied = ::GetWindowTextW(control, text.data(), kLength + 1);
    text.resize(kCopied > 0 ? static_cast<std::size_t>(kCopied) : 0);
    return text;
}

std::wstring formatHandleValue(const std::uint64_t handleValue) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << handleValue;
    return stream.str();
}

std::wstring cellText(const FileHolderEntry& entry, const int column) {
    switch (column) {
    case 0:
        return entry.processName;
    case 1:
        return std::to_wstring(entry.processId);
    case 2:
        return formatHandleValue(entry.handleValue);
    case 3:
        return entry.accessText;
    case 4:
        return entry.win32Name;
    case 5:
        return entry.processPath;
    default:
        return {};
    }
}

void applyFilterResult(FileHolderViewState& state, FileHolderFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.list.hwnd()) {
        return;
    }
    state.list.setVisibleIndexes(std::move(result.visibleIndexes));
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void requestFilter(FileHolderViewState& state, std::wstring query) {
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
            FileHolderFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<FileHolderFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                return;
            }
            applyFilterResult(state, std::move(*result));
        });
}

void buildRows(FileHolderViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.entries.size());
    for (std::size_t index = 0; index < state.entries.size(); ++index) {
        const FileHolderEntry& entry = state.entries[index];
        ksword::ui::VirtualListRow row{};
        // PID plus handle value is unique for the lifetime of one snapshot,
        // which is all a stable key has to survive here.
        row.stableKey = std::to_wstring(entry.processId) + L"#" + formatHandleValue(entry.handleValue);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount + 1);
        for (int column = 0; column < kColumnCount; ++column) {
            row.cells.push_back(cellText(entry, column));
        }
        // The raw NT path is searchable without occupying a column of its own.
        row.cells.push_back(entry.objectName);
        rows.push_back(std::move(row));
    }
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.list.setRows(*filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

void beginScan(FileHolderViewState& state) {
    if (!state.scanTask) {
        return;
    }
    const std::wstring kTarget = windowText(state.pathEdit);
    if (kTarget.empty()) {
        state.statusText = L"请先输入要检查的文件或目录路径。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.scanInProgress) {
        state.statusText = L"扫描正在进行中，请等待当前遍历结束。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    const bool kIncludeSubPaths =
        state.subPathCheck && ::SendMessageW(state.subPathCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
    state.scanInProgress = true;
    if (state.scanButton) {
        ::EnableWindow(state.scanButton, FALSE);
    }
    state.statusText = L"正在后台枚举全系统句柄，这在繁忙机器上需要数秒…";
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在遍历全系统句柄…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);

    state.scanTask->request(
        [kTarget, kIncludeSubPaths] { return scanFileHolders(kTarget, kIncludeSubPaths); },
        [&state](std::uint64_t, std::optional<FileHolderScanResult>&& scan, std::exception_ptr error) {
            state.scanInProgress = false;
            if (state.scanButton) {
                ::EnableWindow(state.scanButton, TRUE);
            }
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !scan.has_value()) {
                state.statusText = L"占用扫描异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            if (!scan->success) {
                state.entries.clear();
                buildRows(state);
                state.list.resetVisibleIndexes();
                state.statusText = scan->diagnosticText.empty() ? L"占用扫描失败。" : scan->diagnosticText;
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }

            state.entries = std::move(scan->entries);
            buildRows(state);
            std::wostringstream summary;
            summary << L"匹配 " << state.entries.size() << L" 个句柄；系统句柄 " << scan->totalHandles
                << L"，其中 File " << scan->fileHandles << L"，已解析 " << scan->inspectedHandles
                << L"，跳过 " << scan->skippedHandles << L"，超时放弃 " << scan->timedOutHandles
                << L"；耗时 " << scan->elapsedMs << L" ms；目标 " << scan->targetNtPath;
            if (!scan->diagnosticText.empty()) {
                summary << L"。" << scan->diagnosticText;
            }
            state.statusText = summary.str();
            requestFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : std::wstring{});
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void browseForTarget(FileHolderViewState& state) {
    wchar_t buffer[MAX_PATH * 4] = {};
    const std::wstring kCurrent = windowText(state.pathEdit);
    if (!kCurrent.empty() && kCurrent.size() < std::size(buffer)) {
        ::wcscpy_s(buffer, kCurrent.c_str());
    }
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = state.hwnd;
    dialog.lpstrFilter = L"所有文件\0*.*\0";
    dialog.lpstrFile = buffer;
    dialog.nMaxFile = static_cast<DWORD>(std::size(buffer));
    dialog.lpstrTitle = L"选择要检查占用的文件";
    // OFN_NODEREFERENCELINKS keeps a shortcut file as itself: the question here
    // is who holds the .lnk, not who holds its target.
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_NODEREFERENCELINKS;
    if (::GetOpenFileNameW(&dialog) && state.pathEdit) {
        ::SetWindowTextW(state.pathEdit, buffer);
    }
}

int selectedModelIndex(const FileHolderViewState& state) {
    const HWND kList = state.list.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.list.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex < state.entries.size() ? static_cast<int>(kModelIndex) : -1;
}

std::wstring rowsAsText(const FileHolderViewState& state, const bool allVisible) {
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

// openHoldingProcessLocation selects the holding process image in Explorer. It
// is deliberately the only shell action on this page: killing the process from
// here would be a destructive operation dressed up as navigation.
void openHoldingProcessLocation(FileHolderViewState& state) {
    const int kIndex = selectedModelIndex(state);
    if (kIndex < 0) {
        return;
    }
    const std::wstring& path = state.entries[static_cast<std::size_t>(kIndex)].processPath;
    if (path.empty()) {
        state.statusText = L"该进程的映像路径不可读，无法定位。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const std::wstring kParameters = L"/select,\"" + path + L"\"";
    ::ShellExecuteW(state.hwnd, L"open", L"explorer.exe", kParameters.c_str(), nullptr, SW_SHOWNORMAL);
}

// openHoldingProcessDetails routes the selected holder PID to the current
// Process Details view. The holder scan has no creation time, so the target
// view resolves the current process instance for that PID before opening it.
void openHoldingProcessDetails(FileHolderViewState& state) {
    const int kIndex = selectedModelIndex(state);
    if (kIndex < 0) {
        return;
    }
    const FileHolderEntry& entry = state.entries[static_cast<std::size_t>(kIndex)];
    if (entry.processId == 0) {
        state.statusText = L"该占用记录没有有效的进程标识。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = entry.processId;
    const bool kRouted = ksword::ui::requestEntityNavigation(state.hwnd, request);
    state.statusText = kRouted
        ? L"已请求打开当前 PID " + std::to_wstring(entry.processId) + L" 的进程详细信息；目标页会重新解析该 PID 的进程实例。"
        : L"无法导航到当前 PID 对应的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void showContextMenu(FileHolderViewState& state, POINT screenPoint) {
    const HWND kList = state.list.hwnd();
    int clickedItem = -1;
    if (kList) {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(kList, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        clickedItem = ListView_HitTest(kList, &hit);
    }
    if (clickedItem >= 0 && static_cast<std::size_t>(clickedItem) < state.list.visibleIndexes().size()) {
        ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(kList, clickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const int kSelectedIndex = selectedModelIndex(state);
    const bool kHasSelection = kSelectedIndex >= 0;
    const bool kHasProcess = kHasSelection &&
        state.entries[static_cast<std::size_t>(kSelectedIndex)].processId != 0;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuOpenLocation, L"定位进程文件");
    ::AppendMenuW(menu, MF_STRING | (kHasProcess ? MF_ENABLED : MF_GRAYED), kMenuOpenProcessDetails, L"查看进程详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRescan, L"重新扫描");

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
    case kMenuOpenLocation:
        openHoldingProcessLocation(state);
        break;
    case kMenuOpenProcessDetails:
        openHoldingProcessDetails(state);
        break;
    case kMenuRescan:
        beginScan(state);
        break;
    default:
        break;
    }
}

void layoutView(FileHolderViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    const int kFirstRowY = kGap;
    const int kBrowseWidth = 60;
    const int kScanWidth = 90;
    const int kEditWidth = (std::max)(120, kWidth - kGap * 4 - kBrowseWidth - kScanWidth);
    if (state.pathEdit) {
        ::MoveWindow(state.pathEdit, kGap, kFirstRowY, kEditWidth, kRowHeight, TRUE);
    }
    if (state.browseButton) {
        ::MoveWindow(state.browseButton, kGap * 2 + kEditWidth, kFirstRowY, kBrowseWidth, kRowHeight, TRUE);
    }
    if (state.scanButton) {
        ::MoveWindow(state.scanButton, kGap * 3 + kEditWidth + kBrowseWidth, kFirstRowY, kScanWidth, kRowHeight, TRUE);
    }

    const int kSecondRowY = kFirstRowY + kRowHeight + kGap;
    const int kCheckWidth = 150;
    if (state.subPathCheck) {
        ::MoveWindow(state.subPathCheck, kGap, kSecondRowY, kCheckWidth, kRowHeight, TRUE);
    }
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap * 2 + kCheckWidth, kSecondRowY,
            (std::max)(120, kWidth - kGap * 3 - kCheckWidth), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kListHeight = (std::max)(0, kHeight - kListTop - kStatusHeight - kGap);
    if (HWND list = state.list.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }
}

bool createChildControls(FileHolderViewState& state) {
    HWND hwnd = state.hwnd;
    state.pathEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPathEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.browseButton = ksword::ui::createButton(hwnd, kBrowseButtonId, L"浏览…", 0, 0, 0, 0);
    state.scanButton = ksword::ui::createButton(hwnd, kScanButtonId, L"扫描占用", 0, 0, 0, 0);
    state.subPathCheck = ::CreateWindowExW(0, L"BUTTON", L"包含子路径（目录）",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSubPathCheckId)),
        ::GetModuleHandleW(nullptr), nullptr);
    state.filterBar = ksword::ui::createFilterBar(
        hwnd, kFilterBarId, L"筛选进程名、PID、访问权限与路径", 0, 0, 0, 0);
    if (!state.pathEdit || !state.browseButton || !state.scanButton || !state.subPathCheck || !state.filterBar) {
        return false;
    }

    if (!state.list.create(hwnd, kListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list.addColumns({
        { 0, 180, LVCFMT_LEFT, L"进程" },
        { 1, 70, LVCFMT_RIGHT, L"PID" },
        { 2, 90, LVCFMT_LEFT, L"句柄" },
        { 3, 220, LVCFMT_LEFT, L"访问权限" },
        { 4, 320, LVCFMT_LEFT, L"占用路径" },
        { 5, 320, LVCFMT_LEFT, L"进程映像" },
    });
    if (HWND list = state.list.hwnd()) {
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

LRESULT CALLBACK fileHolderViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<FileHolderViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<FileHolderViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            state->scanTask = std::make_unique<ksword::ui::AsyncSnapshotTask<FileHolderScanResult>>(hwnd, kMsgScanCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<FileHolderFilterResult>>(hwnd, kMsgFilterCompleted);
            layoutView(*state);
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
            if (kNotification == BN_CLICKED) {
                switch (kId) {
                case kBrowseButtonId:
                    browseForTarget(*state);
                    return 0;
                case kScanButtonId:
                    beginScan(*state);
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
                if (state->list.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
                if (header->hwndFrom == state->list.hwnd() && header->code == NM_DBLCLK) {
                    openHoldingProcessLocation(*state);
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
            if (msg == kMsgScanCompleted && state->scanTask) {
                state->scanTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            // Cancel before teardown so a completion callback cannot run against
            // a half-destroyed state.
            if (state->scanTask) {
                state->scanTask->cancel();
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

bool ensureFileHolderViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = fileHolderViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kFileHolderViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createFileHolderView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureFileHolderViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kFileHolderViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::SysTools

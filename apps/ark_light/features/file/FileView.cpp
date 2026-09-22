#include "FileView.h"

#include "FileActions.h"
#include "FileSystemEnumerator.h"
#include "PathNavigator.h"

#include "../../ui/Controls.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ksword::features::file {
namespace {

constexpr wchar_t kFileViewClass[] = L"KswordARKLight.FileView";
constexpr int kButtonBackId = 52001;
constexpr int kButtonForwardId = 52002;
constexpr int kButtonUpId = 52003;
constexpr int kButtonRefreshId = 52004;
constexpr int kPathEditId = 52005;
constexpr int kButtonGoId = 52006;
constexpr int kListId = 52007;
constexpr int kStatusId = 52008;
constexpr int kFilterBarId = 52009;
constexpr UINT kColumnMenuBaseId = 52500;
constexpr UINT kMsgDirectoryRefreshCompleted = WM_APP + 540;
constexpr UINT kMsgFilterCompleted = WM_APP + 541;
constexpr UINT kMsgFileActionCompleted = WM_APP + 542;
constexpr UINT kMsgExternalNavigate = WM_APP + 543;

// FileColumnSpec describes one report column. Inputs are static id/title/width
// values; processing uses the same table for initial creation and user column
// visibility toggles; no runtime ownership is stored here.
struct FileColumnSpec {
    int index;
    int defaultWidth;
    const wchar_t* title;
};

// FilePresentationRow is the immutable text snapshot delivered to the virtual
// ListView. FileEntry remains available for actions while formatting happens
// once per completed directory snapshot instead of during every repaint.
struct FilePresentationRow {
    std::vector<std::wstring> cells;
    int imageIndex = -2; // -2 means the visible-row icon has not been requested.
};

struct DirectoryRefreshSnapshot {
    std::wstring directory;
    DirectoryEnumerationResult result;
};

struct FileFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
    std::wstring selectedPath;
    std::wstring topPath;
};

// FileActionTaskResult carries a fully materialized backend operation result.
// UI-only effects such as clipboard writes and dialogs are applied only after
// this immutable result returns to the window thread.
struct FileActionTaskResult {
    FileActionResult result;
};

constexpr FileColumnSpec kFileColumns[] = {
    { 0, 260, L"名称" },
    { 1, 90, L"类型" },
    { 2, 110, L"大小" },
    { 3, 150, L"修改时间" },
    { 4, 80, L"标志" },
    { 5, 420, L"完整路径" },
};

// FileViewState owns every child HWND and model object used by one File page.
// Inputs are created during WM_CREATE; processing in fileViewProc updates this
// state in response to navigation, list notifications and menu commands; the
// object is deleted on WM_NCDESTROY and has no independent return behavior.
struct FileViewState {
    HWND hwnd = nullptr;
    HWND backButton = nullptr;
    HWND forwardButton = nullptr;
    HWND upButton = nullptr;
    HWND refreshButton = nullptr;
    HWND pathEdit = nullptr;
    HWND goButton = nullptr;
    HWND filterBar = nullptr;
    HWND list = nullptr;
    HWND status = nullptr;
    HWND loadingOverlay = nullptr;
    HIMAGELIST imageList = nullptr;
    PathNavigator navigator;
    FileSystemEnumerator enumerator;
    std::vector<FileEntry> entries;
    std::vector<FilePresentationRow> presentationRows;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::vector<std::size_t> visibleIndexes;
    std::wstring displayTextScratch;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::wstring enumerationStatusText;
    std::uint64_t displayGeneration = 0;
    bool hideOverlayAfterFilter = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<DirectoryRefreshSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FileFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<FileActionTaskResult>> actionTask;
    std::unordered_map<std::wstring, int> iconCache;
    bool columnVisible[std::size(kFileColumns)] = { true, true, true, true, true, true };
};

// registerFileViewClass registers the native page class once per process. Input
// is the module instance; processing installs a normal Win32 WNDCLASS; output is
// true when the class is available or was already registered.
bool registerFileViewClass(HINSTANCE instance);

// fileViewProc dispatches the custom page messages. Inputs are Win32 window
// procedure arguments; processing routes to stateful helpers; output is a Win32
// LRESULT.
LRESULT CALLBACK fileViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// stateFromWindow returns the per-page state pointer stored in GWLP_USERDATA.
// Input is a page HWND; output may be null before WM_CREATE finishes.
FileViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<FileViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// setStatus writes a short status line for user feedback. Inputs are state and
// text; processing updates the child STATIC; no value is returned.
void setStatus(FileViewState& state, const std::wstring& text) {
    if (state.status) {
        ::SetWindowTextW(state.status, text.c_str());
    }
}

// createFileImageList creates the small-icon image list used by the report
// control. There is no input; processing asks comctl32 for system small-icon
// dimensions; output is owned by FileViewState and destroyed on WM_NCDESTROY.
HIMAGELIST createFileImageList() {
    return ImageList_Create(
        ::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        32,
        32);
}

// fallbackIconQueryPath chooses a stable synthetic path for generic shell
// icons. Input is a FileEntry kind/name; processing preserves file extensions
// when possible; output is used only with SHGFI_USEFILEATTRIBUTES.
std::wstring fallbackIconQueryPath(const FileEntry& entry) {
    if (entry.kind == FileEntryKind::kDirectory) {
        return L"folder";
    }
    if (entry.kind == FileEntryKind::kDrive) {
        return entry.fullPath.empty() ? L"C:\\" : entry.fullPath;
    }

    const std::size_t kDot = entry.name.find_last_of(L'.');
    if (kDot != std::wstring::npos && kDot + 1 < entry.name.size()) {
        return std::wstring(L"file") + entry.name.substr(kDot);
    }
    return L"file";
}

// fileIconCacheKey builds a deterministic cache key for the shell icon. Input
// is one enumerated file row; processing uses the real path for drives,
// directories and reparse points, and extension-based keys for normal files;
// output indexes FileViewState::iconCache.
std::wstring fileIconCacheKey(const FileEntry& entry) {
    std::wstring key = std::to_wstring(static_cast<int>(entry.kind)) + L"|";
    if (entry.kind != FileEntryKind::kFile || entry.reparsePoint) {
        return key + entry.fullPath;
    }

    const std::size_t kDot = entry.name.find_last_of(L'.');
    if (kDot != std::wstring::npos) {
        key += entry.name.substr(kDot);
    } else {
        key += L"<no-extension>";
    }
    key += L"|" + std::to_wstring(entry.attributes & FILE_ATTRIBUTE_REPARSE_POINT);
    return key;
}

// addFileIconFromShell resolves one icon through SHGetFileInfoW and copies it
// into the page image list. Inputs are the image list and file row; processing
// first tries the real path, then a generic attributes-based fallback; output is
// the image index or -1 when the shell cannot provide an icon.
int addFileIconFromShell(HIMAGELIST imageList, const FileEntry& entry) {
    if (!imageList) {
        return -1;
    }

    SHFILEINFOW info{};
    DWORD attributes = entry.attributes;
    if (entry.kind == FileEntryKind::kDirectory) {
        attributes |= FILE_ATTRIBUTE_DIRECTORY;
    }
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    if (!entry.fullPath.empty() &&
        ::SHGetFileInfoW(entry.fullPath.c_str(), attributes, &info, sizeof(info), flags) &&
        info.hIcon) {
        const int kIndex = ImageList_AddIcon(imageList, info.hIcon);
        ::DestroyIcon(info.hIcon);
        return kIndex;
    }

    const std::wstring kFallback = fallbackIconQueryPath(entry);
    flags |= SHGFI_USEFILEATTRIBUTES;
    if (::SHGetFileInfoW(kFallback.c_str(), attributes, &info, sizeof(info), flags) && info.hIcon) {
        const int kIndex = ImageList_AddIcon(imageList, info.hIcon);
        ::DestroyIcon(info.hIcon);
        return kIndex;
    }
    return -1;
}

// iconIndexForEntry returns a cached small icon index for one file row. Inputs
// are page state and FileEntry; processing extracts/caches through Shell APIs;
// output is a ListView image index or -1 when no icon is available.
int iconIndexForEntry(FileViewState& state, const FileEntry& entry) {
    const std::wstring kKey = fileIconCacheKey(entry);
    const auto kFound = state.iconCache.find(kKey);
    if (kFound != state.iconCache.end()) {
        return kFound->second;
    }

    const int kIndex = addFileIconFromShell(state.imageList, entry);
    if (kIndex >= 0) {
        state.iconCache.emplace(kKey, kIndex);
    }
    return kIndex;
}

// createChildControls creates the toolbar, path edit, report list and status
// controls. Input is the initialized state; output is true when the core list
// and edit controls are available.
bool createChildControls(FileViewState& state) {
    state.backButton = ksword::ui::createButton(state.hwnd, kButtonBackId, L"后退", 0, 0, 64, 24);
    state.forwardButton = ksword::ui::createButton(state.hwnd, kButtonForwardId, L"前进", 0, 0, 64, 24);
    state.upButton = ksword::ui::createButton(state.hwnd, kButtonUpId, L"向上", 0, 0, 64, 24);
    state.refreshButton = ksword::ui::createButton(state.hwnd, kButtonRefreshId, L"刷新", 0, 0, 64, 24);
    state.goButton = ksword::ui::createButton(state.hwnd, kButtonGoId, L"转到", 0, 0, 64, 24);
    state.pathEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 200, 24, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPathEditId)), ::GetModuleHandleW(nullptr), nullptr);
    state.filterBar = ksword::ui::createFilterBar(state.hwnd, kFilterBarId, L"筛选名称、类型、路径和属性", 0, 0, 200, 24);
    state.list = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
        0, 0, 400, 300, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kListId)), ::GetModuleHandleW(nullptr), nullptr);
    state.status = ksword::ui::createText(state.hwnd, kStatusId, L"", 0, 0, 300, 20);

    if (state.pathEdit) {
        ::SendMessageW(state.pathEdit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    if (!state.pathEdit || !state.filterBar || !state.list) {
        return false;
    }

    ::SendMessageW(state.list, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ListView_SetExtendedListViewStyle(state.list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);
    state.imageList = createFileImageList();
    if (state.imageList) {
        ListView_SetImageList(state.list, state.imageList, LVSIL_SMALL);
    }

    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    for (const FileColumnSpec& spec : kFileColumns) {
        column.pszText = const_cast<LPWSTR>(spec.title);
        column.cx = spec.defaultWidth;
        column.iSubItem = spec.index;
        ListView_InsertColumn(state.list, spec.index, &column);
    }

    return true;
}

// layoutFileView positions all child controls within the page client rect.
// Input is state plus current client size; processing calls MoveWindow; no value
// is returned.
void layoutFileView(FileViewState& state) {
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kMargin = 8;
    const int kButtonW = 64;
    const int kButtonH = 26;
    const int kGap = 6;
    const int kStatusH = 22;
    int x = kMargin;
    int y = kMargin;

    ::MoveWindow(state.backButton, x, y, kButtonW, kButtonH, TRUE);
    x += kButtonW + kGap;
    ::MoveWindow(state.forwardButton, x, y, kButtonW, kButtonH, TRUE);
    x += kButtonW + kGap;
    ::MoveWindow(state.upButton, x, y, kButtonW, kButtonH, TRUE);
    x += kButtonW + kGap;
    ::MoveWindow(state.refreshButton, x, y, kButtonW, kButtonH, TRUE);
    x += kButtonW + kGap;

    const int kGoW = 64;
    const int kEditW = std::max(120, static_cast<int>(rc.right - x - kGoW - kGap - kMargin));
    ::MoveWindow(state.pathEdit, x, y, kEditW, kButtonH, TRUE);
    x += kEditW + kGap;
    ::MoveWindow(state.goButton, x, y, kGoW, kButtonH, TRUE);

    const int kFilterTop = y + kButtonH + 5;
    ::MoveWindow(state.filterBar, kMargin, kFilterTop, std::max(80, static_cast<int>(rc.right - kMargin * 2)), kButtonH, TRUE);
    const int kListTop = kFilterTop + kButtonH + 5;
    const int kListH = std::max(80, static_cast<int>(rc.bottom - kListTop - kStatusH - kMargin));
    ::MoveWindow(state.list, kMargin, kListTop, std::max(80, static_cast<int>(rc.right - kMargin * 2)), kListH, TRUE);
    ::MoveWindow(state.status, kMargin, kListTop + kListH + 2, std::max(80, static_cast<int>(rc.right - kMargin * 2)), kStatusH, TRUE);
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay,
            kMargin,
            kListTop,
            std::max(80, static_cast<int>(rc.right - kMargin * 2)),
            kListH,
            TRUE);
    }
}

// entryTypeText converts a model kind into a Chinese display string. Input is a
// FileEntry; output is a static text label for the list view.
const wchar_t* entryTypeText(const FileEntry& entry) {
    if (entry.kind == FileEntryKind::kDrive) {
        return L"驱动器";
    }
    if (entry.kind == FileEntryKind::kDirectory) {
        return entry.reparsePoint ? L"目录/链接" : L"目录";
    }
    return entry.reparsePoint ? L"文件/链接" : L"文件";
}

// applyColumnVisibility adjusts report-column widths without rebuilding rows.
// Input is the FileView state; processing keeps column zero visible and sets
// hidden columns to zero width; no value is returned.
void applyColumnVisibility(FileViewState& state) {
    if (!state.list) {
        return;
    }
    for (std::size_t index = 0; index < std::size(kFileColumns); ++index) {
        const FileColumnSpec& spec = kFileColumns[index];
        const bool kVisible = index == 0 || state.columnVisible[index];
        ListView_SetColumnWidth(state.list, spec.index, kVisible ? spec.defaultWidth : 0);
    }
}

// showColumnMenu displays the retained "Select Columns" action as a compact Win32
// checkable popup. Inputs are state and screen point; processing toggles one
// column at a time; no value is returned.
void showColumnMenu(FileViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    for (std::size_t index = 0; index < std::size(kFileColumns); ++index) {
        const UINT kFlags = MF_STRING |
            (state.columnVisible[index] ? MF_CHECKED : MF_UNCHECKED) |
            (index == 0 ? MF_GRAYED : 0U);
        ::AppendMenuW(menu, kFlags, kColumnMenuBaseId + static_cast<UINT>(index), kFileColumns[index].title);
    }
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand >= kColumnMenuBaseId && kCommand < kColumnMenuBaseId + std::size(kFileColumns)) {
        const std::size_t kIndex = static_cast<std::size_t>(kCommand - kColumnMenuBaseId);
        if (kIndex != 0) {
            state.columnVisible[kIndex] = !state.columnVisible[kIndex];
            applyColumnVisibility(state);
            setStatus(state, L"已更新文件列表列显示。");
        }
    }
}

// visibleEntryIndex translates an owner-data item to its immutable source index.
// It never asks ListView for an LVITEM because owner-data lists retain no row
// storage for us to read back.
std::size_t visibleEntryIndex(const FileViewState& state, const int item) {
    if (item < 0 || static_cast<std::size_t>(item) >= state.visibleIndexes.size()) {
        return static_cast<std::size_t>(-1);
    }
    return state.visibleIndexes[static_cast<std::size_t>(item)];
}

std::wstring selectedEntryPath(const FileViewState& state) {
    const int kSelected = state.list ? ListView_GetNextItem(state.list, -1, LVNI_SELECTED) : -1;
    const std::size_t kEntryIndex = visibleEntryIndex(state, kSelected);
    return kEntryIndex < state.entries.size() ? state.entries[kEntryIndex].fullPath : std::wstring{};
}

std::wstring topEntryPath(const FileViewState& state) {
    const int kTopItem = state.list ? ListView_GetTopIndex(state.list) : -1;
    const std::size_t kEntryIndex = visibleEntryIndex(state, kTopItem);
    return kEntryIndex < state.entries.size() ? state.entries[kEntryIndex].fullPath : std::wstring{};
}

void requestFileFilter(FileViewState& state,
    const std::wstring& query,
    std::wstring selectedPath,
    std::wstring topPath);

// buildPresentationRows materializes every display field once, after the
// directory worker returns. Scrolling then asks only for visible cached text.
void buildPresentationRows(FileViewState& state, DirectoryEnumerationResult result) {
    state.entries = std::move(result.entries);
    state.enumerationStatusText = result.statusText;
    state.presentationRows.clear();
    state.presentationRows.reserve(state.entries.size());
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>();
    filterRows->reserve(state.entries.size());

    for (const FileEntry& entry : state.entries) {
        FilePresentationRow row{};
        row.cells = {
            entry.name,
            entryTypeText(entry),
            FileSystemEnumerator::formatSize(entry.size, entry.kind),
            FileSystemEnumerator::formatLastWriteTime(entry.lastWriteTime),
            FileSystemEnumerator::formatAttributes(entry.attributes),
            entry.fullPath
        };
        ksword::ui::VirtualListRow filterRow{};
        filterRow.stableKey = entry.fullPath;
        filterRow.cells = row.cells;
        state.presentationRows.push_back(std::move(row));
        filterRows->push_back(std::move(filterRow));
    }
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;
}

// applyFileFilter installs a background-produced visible-index map and restores
// selection/scroll position by full path whenever those entries still exist.
void applyFileFilter(FileViewState& state, FileFilterResult result) {
    if (!state.list || result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex) {
        return;
    }
    state.visibleIndexes = std::move(result.visibleIndexes);
    int selectedItem = -1;
    int topItem = -1;
    {
        ksword::ui::ScopedListViewRedrawLock redrawLock(state.list);
        ListView_SetItemCountEx(state.list,
            static_cast<int>(std::min<std::size_t>(state.visibleIndexes.size(), static_cast<std::size_t>(INT_MAX))),
            LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
        ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        for (std::size_t item = 0; item < state.visibleIndexes.size(); ++item) {
            const std::size_t kEntryIndex = state.visibleIndexes[item];
            if (kEntryIndex >= state.entries.size()) {
                continue;
            }
            const std::wstring& path = state.entries[kEntryIndex].fullPath;
            if (selectedItem < 0 && !result.selectedPath.empty() && path == result.selectedPath) {
                selectedItem = static_cast<int>(item);
            }
            if (topItem < 0 && !result.topPath.empty() && path == result.topPath) {
                topItem = static_cast<int>(item);
            }
        }
        if (selectedItem >= 0) {
            ListView_SetItemState(state.list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        if (topItem >= 0) {
            ListView_EnsureVisible(state.list, topItem, FALSE);
        } else if (selectedItem >= 0) {
            ListView_EnsureVisible(state.list, selectedItem, FALSE);
        }
    }
    ::InvalidateRect(state.list, nullptr, FALSE);
    const std::wstring kFilterSuffix = result.query.empty()
        ? L""
        : L"；筛选 " + std::to_wstring(state.visibleIndexes.size()) + L" / " + std::to_wstring(state.entries.size()) + L" 项";
    setStatus(state, state.enumerationStatusText + kFilterSuffix);
    if (state.hideOverlayAfterFilter) {
        state.hideOverlayAfterFilter = false;
        ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
    }
}

// requestFileFilter uses the cached value snapshot only. Input changes are
// debounced by FilterBar and coalesced here, without another filesystem walk.
void requestFileFilter(FileViewState& state,
    const std::wstring& query,
    std::wstring selectedPath,
    std::wstring topPath) {
    state.filterQuery = query;
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> kRows = state.filterRows;
    const std::uint64_t kGeneration = state.displayGeneration;
    const bool kUseRegex = state.filterUseRegex;
    if (!state.filterTask || !kRows) {
        return;
    }
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query, selectedPath = std::move(selectedPath), topPath = std::move(topPath)]() mutable {
            FileFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedPath = std::move(selectedPath);
            result.topPath = std::move(topPath);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<FileFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setStatus(state, L"文件筛选任务异常结束。已保留当前结果。");
                if (state.hideOverlayAfterFilter) {
                    state.hideOverlayAfterFilter = false;
                    ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
                }
                return;
            }
            applyFileFilter(state, std::move(*result));
        });
}

// applyDirectoryRefresh accepts only the completed worker snapshot and starts
// a cached background filter pass. No FindFirstFile/FindNextFile work runs in
// UI message handlers.
void applyDirectoryRefresh(FileViewState& state, DirectoryRefreshSnapshot snapshot) {
    if (snapshot.directory != state.navigator.currentPath()) {
        return;
    }
    const std::wstring kSelectedPath = selectedEntryPath(state);
    const std::wstring kTopPath = topEntryPath(state);
    buildPresentationRows(state, std::move(snapshot.result));
    state.visibleIndexes.clear();
    ListView_SetItemCountEx(state.list, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    applyColumnVisibility(state);
    ::EnableWindow(state.backButton, state.navigator.canNavigateBack());
    ::EnableWindow(state.forwardButton, state.navigator.canNavigateForward());
    state.hideOverlayAfterFilter = true;
    requestFileFilter(state,
        state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery,
        kSelectedPath,
        kTopPath);
}

// refreshCurrentPath schedules directory enumeration and leaves the previous
// immutable table available under a loading overlay until the latest result is
// installed. Repeated navigation and refresh commands are coalesced.
void refreshCurrentPath(FileViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const std::wstring kCurrent = state.navigator.currentPath();
    ::SetWindowTextW(state.pathEdit, kCurrent.empty() ? L"此电脑" : kCurrent.c_str());
    setStatus(state, state.refreshTask->running() ? L"目录刷新已排队，等待当前枚举完成…" : L"正在后台枚举目录…");
    ::EnableWindow(state.refreshButton, FALSE);
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在后台加载目录…");
    state.refreshTask->request(
        [kCurrent]() {
            FileSystemEnumerator enumerator;
            return DirectoryRefreshSnapshot{ kCurrent, enumerator.enumerate(kCurrent) };
        },
        [&state](std::uint64_t, std::optional<DirectoryRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            ::EnableWindow(state.refreshButton, TRUE);
            if (error || !snapshot.has_value()) {
                ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
                setStatus(state, L"目录枚举任务异常结束。请检查路径与访问权限。");
                return;
            }
            applyDirectoryRefresh(state, std::move(*snapshot));
        });
}

// navigateTo updates only the lightweight navigator on the UI thread, then
// schedules the potentially slow filesystem snapshot in refreshCurrentPath.
void navigateTo(FileViewState& state, const std::wstring& path) {
    state.navigator.navigateTo(path);
    refreshCurrentPath(state);
}

// textFromWindow reads a child window's Unicode text. Input is an HWND; output
// is the current text content or empty when the HWND is null.
std::wstring textFromWindow(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<size_t>(kLength) + 1, L'\0');
    if (kLength > 0) {
        ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    }
    text.resize(static_cast<size_t>(kLength));
    return text;
}

// selectedEntry copies the currently selected list row into an output model.
// Inputs are state and output pointer; output is true when a row is selected.
bool selectedEntry(const FileViewState& state, FileEntry* entry) {
    const int kSelected = ListView_GetNextItem(state.list, -1, LVNI_SELECTED);
    const std::size_t kEntryIndex = visibleEntryIndex(state, kSelected);
    if (kEntryIndex >= state.entries.size()) {
        return false;
    }
    if (entry) {
        *entry = state.entries[kEntryIndex];
    }
    return true;
}

// applyFileActionResult runs only on the window thread. It keeps clipboard and
// modal UI ownership out of the worker while following any refresh/navigation
// request produced by the completed immutable file-action result.
void applyFileActionResult(FileViewState& state, FileActionResult result) {
    if (!result.clipboardText.empty() && !FileActions::copyTextToClipboard(state.hwnd, result.clipboardText)) {
        if (!result.statusText.empty()) {
            result.statusText += L"；复制到剪贴板失败。";
        } else {
            result.statusText = L"复制到剪贴板失败。";
        }
    }
    if (!result.statusText.empty()) {
        setStatus(state, result.statusText);
    }
    if (result.navigateRequested) {
        navigateTo(state, result.navigatePath);
    } else if (result.refreshRequested) {
        refreshCurrentPath(state);
    }
    if (!result.dialogText.empty()) {
        ::MessageBoxW(
            state.hwnd,
            result.dialogText.c_str(),
            result.dialogTitle.empty() ? L"文件操作" : result.dialogTitle.c_str(),
            MB_OK | (result.dialogFlags == 0 ? MB_ICONINFORMATION : result.dialogFlags));
    }
}

// beginFileAction performs UI-only preflight synchronously, then runs every
// shell, filesystem, Restart Manager, security and R0 operation through the
// dedicated action task. A running action rejects duplicate requests while the
// prior directory snapshot remains interactive.
void beginFileAction(FileViewState& state, const FileActionId action, FileActionContext context) {
    if (action == FileActionId::kNone) {
        return;
    }
    if (!state.actionTask) {
        setStatus(state, L"文件操作任务不可用。");
        return;
    }
    if (state.actionTask->running()) {
        setStatus(state, L"另一个文件操作正在后台执行，请等待完成。");
        return;
    }

    const FileActionPreparation kPreparation = FileActions::prepareBackground(action, context);
    if (!kPreparation.ready) {
        setStatus(state, kPreparation.statusText.empty() ? L"已取消文件操作。" : kPreparation.statusText);
        return;
    }

    context.backgroundExecution = true;
    context.owner = nullptr;
    setStatus(state, L"正在后台执行文件操作…");
    state.actionTask->request(
        [action, context = std::move(context)]() mutable {
            FileActionTaskResult completed{};
            completed.result = FileActions::execute(action, context);
            return completed;
        },
        [&state](std::uint64_t, std::optional<FileActionTaskResult>&& completed, std::exception_ptr error) {
            if (error || !completed.has_value()) {
                setStatus(state, L"文件后台操作异常结束。请检查访问权限和驱动状态。");
                return;
            }
            applyFileActionResult(state, std::move(completed->result));
        });
}

// openSelectedEntry either navigates into directories/drives or schedules a
// ShellExecute request for files. It never blocks the file page message loop.
void openSelectedEntry(FileViewState& state) {
    FileEntry entry;
    if (!selectedEntry(state, &entry)) {
        return;
    }
    if (entry.kind == FileEntryKind::kDrive || entry.kind == FileEntryKind::kDirectory) {
        navigateTo(state, entry.fullPath);
        return;
    }
    FileActionContext context;
    context.owner = state.hwnd;
    context.currentDirectory = state.navigator.currentPath();
    context.selectedEntry = entry;
    context.hasSelection = true;
    beginFileAction(state, FileActionId::kOpenRun, std::move(context));
}

// showContextMenu builds a context object, displays the FileActions menu, then
// executes the selected command. Inputs are state and screen coordinate; no
// value is returned.
void showContextMenu(FileViewState& state, POINT screenPoint) {
    if (state.actionTask && state.actionTask->running()) {
        setStatus(state, L"另一个文件操作正在后台执行，请等待完成。");
        return;
    }
    FileActionContext context;
    context.owner = state.hwnd;
    context.currentDirectory = state.navigator.currentPath();
    context.hasSelection = selectedEntry(state, &context.selectedEntry);
    const FileActionId kAction = FileActions::showContextMenu(state.hwnd, context, screenPoint);
    if (kAction == FileActionId::kSelectColumns) {
        showColumnMenu(state, screenPoint);
        return;
    }
    beginFileAction(state, kAction, std::move(context));
}

// handleCommand processes toolbar button commands. Inputs are state and command
// id; output is true only when the command belongs to FileView.
bool handleCommand(FileViewState& state, int commandId) {
    switch (commandId) {
    case kButtonBackId:
        if (state.navigator.navigateBack()) {
            refreshCurrentPath(state);
        }
        return true;
    case kButtonForwardId:
        if (state.navigator.navigateForward()) {
            refreshCurrentPath(state);
        }
        return true;
    case kButtonUpId:
        state.navigator.navigateUp();
        refreshCurrentPath(state);
        return true;
    case kButtonRefreshId:
        refreshCurrentPath(state);
        return true;
    case kButtonGoId:
        navigateTo(state, textFromWindow(state.pathEdit));
        return true;
    default:
        return false;
    }
}

// handleNotify processes list-view notifications. Inputs are state and NMHDR;
// output is true only when the notification was consumed.
bool handleNotify(FileViewState& state, const NMHDR* hdr) {
    if (!hdr || hdr->hwndFrom != state.list) {
        return false;
    }
    if (hdr->code == LVN_GETDISPINFOW) {
        auto* displayInfo = reinterpret_cast<NMLVDISPINFOW*>(const_cast<NMHDR*>(hdr));
        const std::size_t kEntryIndex = visibleEntryIndex(state, displayInfo->item.iItem);
        if (kEntryIndex >= state.presentationRows.size()) {
            return true;
        }
        FilePresentationRow& row = state.presentationRows[kEntryIndex];
        if ((displayInfo->item.mask & LVIF_TEXT) != 0) {
            const int kColumn = displayInfo->item.iSubItem;
            state.displayTextScratch = kColumn >= 0 && static_cast<std::size_t>(kColumn) < row.cells.size()
                ? row.cells[static_cast<std::size_t>(kColumn)]
                : std::wstring{};
            displayInfo->item.pszText = state.displayTextScratch.data();
        }
        if ((displayInfo->item.mask & LVIF_PARAM) != 0) {
            displayInfo->item.lParam = static_cast<LPARAM>(kEntryIndex);
        }
        if ((displayInfo->item.mask & LVIF_IMAGE) != 0) {
            if (row.imageIndex == -2) {
                row.imageIndex = iconIndexForEntry(state, state.entries[kEntryIndex]);
            }
            if (row.imageIndex >= 0) {
                displayInfo->item.iImage = row.imageIndex;
            }
        }
        return true;
    }
    if (hdr->code == NM_DBLCLK) {
        openSelectedEntry(state);
        return true;
    }
    if (hdr->code == NM_RCLICK) {
        POINT pt{};
        ::GetCursorPos(&pt);
        POINT client = pt;
        ::ScreenToClient(state.list, &client);
        LVHITTESTINFO hit{};
        hit.pt = client;
        const int kItem = ListView_HitTest(state.list, &hit);
        if (kItem >= 0) {
            ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(state.list, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        showContextMenu(state, pt);
        return true;
    }
    return false;
}

bool registerFileViewClass(HINSTANCE instance) {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = fileViewProc;
    wc.hInstance = instance;
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kFileViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
        return true;
    }
    return false;
}

LRESULT CALLBACK fileViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    FileViewState* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_CREATE: {
        auto ownedState = std::make_unique<FileViewState>();
        ownedState->hwnd = hwnd;
        state = ownedState.get();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        if (!createChildControls(*state)) {
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return -1;
        }
        ownedState.release();
        state->loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, 52010, { 0, 0, 1, 1 });
        state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<DirectoryRefreshSnapshot>>(hwnd, kMsgDirectoryRefreshCompleted);
        state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<FileFilterResult>>(hwnd, kMsgFilterCompleted);
        state->actionTask = std::make_unique<ksword::ui::AsyncSnapshotTask<FileActionTaskResult>>(hwnd, kMsgFileActionCompleted);
        refreshCurrentPath(*state);
        return 0;
    }
    case WM_SIZE:
        if (state) {
            layoutFileView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            requestFileFilter(*state,
                ksword::ui::getFilterBarText(state->filterBar),
                selectedEntryPath(*state),
                topEntryPath(*state));
            return 0;
        }
        if (state && handleCommand(*state, LOWORD(wParam))) {
            return 0;
        }
        break;
    case kMsgDirectoryRefreshCompleted:
        if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFileActionCompleted:
        if (state && state->actionTask && state->actionTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgExternalNavigate:
        if (state && lParam != 0) {
            const auto* path = reinterpret_cast<const std::wstring*>(lParam);
            if (!path->empty()) {
                navigateTo(*state, *path);
                return TRUE;
            }
        }
        return FALSE;
    case WM_NOTIFY:
        if (state && handleNotify(*state, reinterpret_cast<NMHDR*>(lParam))) {
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (state && reinterpret_cast<HWND>(wParam) == state->list) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x == -1 && pt.y == -1) {
                RECT rc{};
                ::GetWindowRect(state->list, &rc);
                pt = { rc.left + 20, rc.top + 20 };
            }
            showContextMenu(*state, pt);
            return 0;
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
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        RECT rc{};
        ::GetClientRect(hwnd, &rc);
        ::FillRect(dc, &rc, ksword::ui::appTheme().windowBrush());
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_NCDESTROY:
        if (state && state->refreshTask) {
            state->refreshTask->cancel();
        }
        if (state && state->filterTask) {
            state->filterTask->cancel();
        }
        if (state && state->actionTask) {
            state->actionTask->cancel();
        }
        if (state && state->imageList) {
            ImageList_Destroy(state->imageList);
            state->imageList = nullptr;
        }
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

} // namespace

HWND createFileViewPage(HWND parent, const RECT& bounds) {
    HINSTANCE instance = ::GetModuleHandleW(nullptr);
    if (!registerFileViewClass(instance)) {
        return nullptr;
    }
    return ::CreateWindowExW(0, kFileViewClass, L"文件", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        instance,
        nullptr);
}

bool requestFileViewNavigate(HWND page, const std::wstring& path) {
    return page && !path.empty() &&
        ::SendMessageW(page, kMsgExternalNavigate, 0, reinterpret_cast<LPARAM>(&path)) != 0;
}

} // namespace Ksword::Features::File

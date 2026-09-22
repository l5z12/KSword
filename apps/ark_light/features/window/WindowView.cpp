#include "WindowView.h"

#include "WindowActions.h"
#include "WindowEnumerator.h"
#include "WindowModel.h"
#include "Win32kTimerEvidenceModel.h"
#include "../file/PathNavigator.h"
#include "../window_tools/WindowToolsHierarchyView.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/Theme.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>

#include <memory>
#include <string>
#include <cstring>
#include <climits>
#include <cstdint>
#include <sstream>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ksword::features::window {
namespace {
constexpr wchar_t kWindowViewClass[] = L"KswordARKLight.Window.FeatureView";
constexpr int kRefreshButtonId = 62001;
constexpr int kFrontButtonId = 62002;
constexpr int kRestoreButtonId = 62003;
constexpr int kMinimizeButtonId = 62004;
constexpr int kMaximizeButtonId = 62005;
constexpr int kCloseButtonId = 62006;
constexpr int kWindowListId = 62007;
constexpr int kDetailListId = 62008;
constexpr int kSortComboId = 62009;
constexpr int kAuditModeComboId = 62010;
constexpr int kFilterBarId = 62011;
constexpr int kLoadingOverlayId = 62012;
constexpr int kExportButtonId = 62013;
constexpr int kHeaderHeight = 96;
constexpr int kGap = 6;
constexpr int kDetailHeight = 210;
constexpr UINT kWindowMenuRefreshDetail = 62601;
constexpr UINT kWindowMenuCopyDetail = 62602;
constexpr UINT kWindowMenuFront = 62603;
constexpr UINT kWindowMenuRestore = 62604;
constexpr UINT kWindowMenuMinimize = 62605;
constexpr UINT kWindowMenuMaximize = 62606;
constexpr UINT kWindowMenuClose = 62607;
constexpr UINT kWindowMenuCopyCell = 62608;
constexpr UINT kWindowMenuCopyRow = 62609;
constexpr UINT kWindowMenuCopyVisible = 62610;
constexpr UINT kWindowMenuCopyDetailCell = 62611;
constexpr UINT kWindowMenuCopyDetailRow = 62612;
constexpr UINT kWindowMenuCopyDetailVisible = 62613;
constexpr UINT kWindowMenuAllowCapture = 62614;
constexpr UINT kWindowMenuBlockCapture = 62615;
constexpr UINT kWindowMenuExcludeFromCapture = 62616;
constexpr UINT kWindowMenuOpenProcess = 62617;
constexpr UINT kWindowMenuOpenImageDirectory = 62618;
constexpr UINT kWindowMenuExportDetail = 62619;
constexpr UINT kMsgWindowRefreshCompleted = WM_APP + 610;
constexpr UINT kMsgWindowFilterCompleted = WM_APP + 611;
constexpr UINT kMsgWindowDetailCompleted = WM_APP + 612;
constexpr UINT kMsgExternalQuery = WM_APP + 613;

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

// WindowViewMode controls whether this retained page shows the existing R3
// window list or a read-only audit entry matrix. Inputs come from the toolbar
// combo box; processing stays inside this UI module and never calls raw IOCTL.
enum class WindowViewMode {
    kWindowList,
    kWin32kGuiAudit,
    kWin32kMessageHookAudit,
    kWin32kTimerAudit,
    kGpuDisplayAudit
};

// AuditEntry is one read-only audit row. Inputs are ArkDriverClient wrapper
// results, static source labels and existing R3 observations; processing only
// displays status and evidence mapping; return behavior is normal ListView text.
struct AuditEntry {
    std::wstring category;
    std::wstring source;
    std::wstring item;
    std::wstring status;
    std::wstring detail;
    DWORD relatedProcessId = 0;
};

struct WindowFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct WindowRefreshSnapshot {
    WindowViewMode mode = WindowViewMode::kWindowList;
    WindowSortMode sortMode = WindowSortMode::kStackingOrder;
    WindowEnumerationResult enumeration;
    std::vector<AuditEntry> auditRows;
    std::vector<ksword::ui::VirtualListRow> displayRows;
};

struct WindowDetailSnapshot {
    std::uint64_t generation = 0;
    int modelIndex = -1;
    WindowSnapshotRow row;
    WindowDetail detail;
    ksword::ark::Win32kWindowRuntimeDetailResult r0Detail;
};

// utf8ToWideLossy promotes ArkDriverClient diagnostic messages to wide strings.
// Input: io.message as a narrow string; Processing: byte-by-byte promotion sufficient for displaying ASCII/UTF-8 diagnostics.
// Returns: wide string; empty input yields empty output.
std::wstring utf8ToWideLossy(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const char kCh : text) {
        wide.push_back(static_cast<unsigned char>(kCh));
    }
    return wide;
}

// HexText formats addresses and flags as hexadecimal.
// Input: 64-bit value; Processing: standardizes to '0x' prefix with uppercase hexadecimal; Returns: display string.
std::wstring hexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// ioStateText converts ArkDriverClient IO status to UI status.
// Input: ok and unsupported; Processing: distinguish between normal operation, legacy driver unsupported, and device unavailable.
// Returns: Table status text.
std::wstring ioStateText(const bool ok, const bool unsupported) {
    if (ok) {
        return L"OK";
    }
    return unsupported ? L"Unsupported" : L"Unavailable";
}

// fixedWideText copies bounded UTF-16 driver arrays into display strings.
// Inputs are a protocol buffer and its element capacity; processing stops at
// the first NUL without reading beyond the fixed packet field; output is empty
// for absent text and otherwise safe for ListView cells.
std::wstring fixedWideText(const wchar_t* text, const std::size_t maxChars) {
    if (text == nullptr || maxChars == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    return std::wstring(text, text + length);
}

// win32kRuntimeStatusText maps KSWORD_ARK_WIN32K_STATUS_* values to the same
// short explanations used by the full WindowDock. Input is one R0 status code;
// output is display-only text and never drives mutation.
const wchar_t* win32kRuntimeStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_WIN32K_STATUS_OK: return L"OK";
    case KSWORD_ARK_WIN32K_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING: return L"ProfileMissing";
    case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND: return L"Win32kNotFound";
    case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED: return L"BufferTruncated";
    case KSWORD_ARK_WIN32K_STATUS_READ_FAILED: return L"ReadFailed";
    case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED: return L"EnumFailed";
    case KSWORD_ARK_WIN32K_STATUS_UNKNOWN:
    default: return L"Unknown";
    }
}

// win32kModuleStateText formats a win32k module state packet. Inputs are the
// shared module state and label; processing exposes loaded/profile/base/name
// fields exactly as read from R0; output is one detail-pane row value.
std::wstring win32kModuleStateText(const wchar_t* label, const KSWORD_ARK_WIN32K_MODULE_STATE& state) {
    std::wostringstream stream;
    stream << label
           << L": loaded=" << state.loaded
           << L"; profile=" << state.profileState
           << L"; base=" << hexText(state.imageBase)
           << L"; size=" << hexText(state.imageSize)
           << L"; name=" << fixedWideText(state.moduleName, KSWORD_ARK_WIN32K_MODULE_NAME_CHARS);
    return stream.str();
}

// Width returns non-negative rectangle width. Input is a RECT; output is pixels
// available for child controls.
int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns non-negative rectangle height. Input is a RECT; output is pixels
// available for child controls.
int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// WindowViewState owns all HWNDs and the current model for one window page.
// Inputs are Win32 messages; processing is isolated to the Window module and no
// desktop-management data is stored here.
struct WindowViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND frontButton = nullptr;
    HWND restoreButton = nullptr;
    HWND minimizeButton = nullptr;
    HWND maximizeButton = nullptr;
    HWND closeButton = nullptr;
    HWND auditModeCombo = nullptr;
    HWND sortCombo = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    HWND windowList = nullptr;
    HWND detailList = nullptr;
    HWND hierarchyReportView = nullptr;
    HIMAGELIST processImageList = nullptr;
    WindowModel model;
    std::vector<AuditEntry> auditRows;
    WindowViewMode viewMode = WindowViewMode::kWindowList;
    std::wstring statusText;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    int contextColumn = 0;
    ksword::ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<WindowRefreshSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<WindowFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<WindowDetailSnapshot>> detailTask;
    std::unordered_map<std::wstring, int> processIconCache;
};

std::vector<std::wstring> windowColumnTitles(const WindowViewState& state) {
    if (state.viewMode == WindowViewMode::kWindowList) {
        return { L"进程 / PID", L"HWND", L"Title", L"Class", L"State" };
    }
    return { L"类别", L"数据源", L"入口 / 对象", L"状态", L"说明" };
}

// appendTsvCell appends one strictly single-line TSV cell. Inputs are the
// current rendered string and an output buffer; tabs/newlines are flattened so
// a copied window title or driver diagnostic cannot add columns or rows.
void appendTsvCell(std::wstring& output, const std::wstring& cell) {
    for (const wchar_t kCharacter : cell) {
        output.push_back(kCharacter == L'\t' || kCharacter == L'\r' || kCharacter == L'\n' ? L' ' : kCharacter);
    }
}

// appendTsvRow writes exactly columnCount cells from one retained display row.
// The Window list keeps additional cells for filtering, but export intentionally
// stops at the currently visible column count so headers and data remain aligned.
void appendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells, const std::size_t columnCount) {
    for (std::size_t column = 0U; column < columnCount; ++column) {
        if (column != 0U) {
            output.push_back(L'\t');
        }
        if (column < cells.size()) {
            appendTsvCell(output, cells[column]);
        }
    }
    output += L"\r\n";
}

// buildVisibleRowsTsv serializes the already-filtered display snapshot. It
// never enumerates HWNDs or queries ArkDriverClient; normal window rows retain
// extra supporting cells for in-page workflows, which are deliberately excluded
// from this five-column visible export.
std::wstring buildVisibleRowsTsv(const WindowViewState& state) {
    const std::vector<std::wstring> kColumns = windowColumnTitles(state);
    const auto& rows = state.virtualList.rows();
    const auto& visibleIndexes = state.virtualList.visibleIndexes();
    if (kColumns.empty() || visibleIndexes.empty()) {
        return {};
    }

    std::wstring text;
    bool wroteHeader = false;
    for (const std::size_t kIndex : visibleIndexes) {
        if (kIndex >= rows.size()) {
            continue;
        }
        if (!wroteHeader) {
            appendTsvRow(text, kColumns, kColumns.size());
            wroteHeader = true;
        }
        appendTsvRow(text, rows[kIndex].cells, kColumns.size());
    }
    return text;
}

void exportVisibleRows(WindowViewState* state) {
    if (!state) {
        return;
    }
    const std::wstring kText = buildVisibleRowsTsv(*state);
    if (kText.empty()) {
        state->statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(state->hwnd, L"window.tsv", L"导出窗口结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        state->statusText = L"窗口可见结果已导出。";
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        state->statusText = L"已取消导出窗口结果。";
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        state->statusText = L"导出窗口结果失败：" + error;
        break;
    }
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// addColumn inserts one report-view column. Inputs are list HWND, column index,
// title and width; processing sends LVM_INSERTCOLUMNW; no value is returned.
void addColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

// setColumn updates a report-view column title and width. Inputs are list HWND,
// column index, title and width; no value is returned.
void setColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    ListView_SetColumn(list, index, &column);
}

// setListText inserts or updates a report-view cell. Inputs are list HWND, row,
// column, text and optional lParam for first-column rows; no value is returned.
void setListText(HWND list, int row, int column, const std::wstring& text, LPARAM data = 0, int imageIndex = -1) {
    if (column == 0) {
        LVITEMW item{};
        item.mask = LVIF_TEXT | LVIF_PARAM;
        if (imageIndex >= 0) {
            item.mask |= LVIF_IMAGE;
            item.iImage = imageIndex;
        }
        item.iItem = row;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(text.c_str());
        item.lParam = data;
        ListView_InsertItem(list, &item);
        return;
    }
    ListView_SetItemText(list, row, column, const_cast<LPWSTR>(text.c_str()));
}

// addDetailRow appends one property/value row. Inputs are detail list HWND, row,
// property name and value; no value is returned.
void addDetailRow(HWND list, int row, const std::wstring& name, const std::wstring& value) {
    setListText(list, row, 0, name);
    setListText(list, row, 1, value);
}

// ListText returns one ListView cell as UTF-16 text. Inputs are control, row and
// column indexes; processing grows its buffer until the common control reports
// a complete value, so detail exports do not silently truncate long diagnostics
// or titles; output is empty on invalid input or a blank cell.
std::wstring listText(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(256, L'\0');
    for (;;) {
        LVITEMW item{};
        item.iSubItem = column;
        item.pszText = buffer.data();
        item.cchTextMax = static_cast<int>(buffer.size());
        const LRESULT kCopiedResult = ::SendMessageW(
            list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
        if (kCopiedResult < 0 || kCopiedResult > INT_MAX) {
            return {};
        }
        const int kCopied = static_cast<int>(kCopiedResult);
        if (kCopied < static_cast<int>(buffer.size()) - 1) {
            return std::wstring(buffer.data(), static_cast<std::size_t>(kCopied));
        }

        // ListView_GetItemText returns cchTextMax - 1 when a buffer might have
        // been filled. Grow and retry even when the cell happened to be exactly
        // that long; only the larger read can prove the value was complete.
        const std::size_t kCurrent = buffer.size();
        if (kCurrent >= static_cast<std::size_t>(INT_MAX / 2)) {
            // A common-control string cannot be read into a larger cchTextMax
            // value. Returning empty is safer than exporting a partial value.
            return {};
        }
        buffer.assign(kCurrent * 2U, L'\0');
    }
}

// buildRenderedDetailTsv serializes only the property/value strings presently
// shown in the detail ListView. It neither revalidates the HWND nor calls the
// driver, so an export remains evidence for the exact R3/R0 snapshot the user
// can see, including an Unsupported or Partial result.
std::wstring buildRenderedDetailTsv(HWND detailList) {
    const int kRows = detailList ? ListView_GetItemCount(detailList) : 0;
    if (kRows <= 0) {
        return {};
    }

    std::wstring text;
    appendTsvCell(text, L"Property");
    text.push_back(L'\t');
    appendTsvCell(text, L"Value");
    text += L"\r\n";
    for (int row = 0; row < kRows; ++row) {
        appendTsvCell(text, listText(detailList, row, 0));
        text.push_back(L'\t');
        appendTsvCell(text, listText(detailList, row, 1));
        text += L"\r\n";
    }
    return text;
}

// exportCurrentDetail persists the already-rendered window/Win32k detail as
// UTF-8 TSV. Inputs are page state and user-selected output path; it performs
// no new R3 inspection, ArkDriverClient request, privilege change, or path
// navigation. saveUtf8TextFileWithDialog also records the exact text in the
// existing evidence session after a successful write.
void exportCurrentDetail(WindowViewState* state) {
    if (!state) {
        return;
    }
    const std::wstring kText = buildRenderedDetailTsv(state->detailList);
    if (kText.empty()) {
        state->statusText = L"没有可导出的当前窗口/Win32k 详情。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }

    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(state->hwnd, L"window_detail.tsv", L"导出窗口/Win32k 详情",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        state->statusText = L"当前窗口/Win32k 详情已导出，并已记录到证据会话。";
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        state->statusText = L"已取消导出当前窗口/Win32k 详情。";
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        state->statusText = L"导出当前窗口/Win32k 详情失败：" + error;
        break;
    }
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// CopyText writes Unicode text to the clipboard. Inputs are owner HWND and text;
// processing transfers CF_UNICODETEXT; output reports success to callers that
// update the status line.
bool copyText(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"窗口模块");
}

// addIconFromShell extracts one small executable icon. Inputs are an image list
// and process image path; processing falls back to the generic .exe icon for
// inaccessible processes; output is the image-list index or -1 on failure.
int addIconFromShell(HIMAGELIST imageList, const std::wstring& path) {
    if (imageList == nullptr) {
        return -1;
    }

    SHFILEINFOW info{};
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    const bool kFallback = path.empty();
    const wchar_t* queryPath = kFallback ? L".exe" : path.c_str();
    if (kFallback) {
        flags |= SHGFI_USEFILEATTRIBUTES;
    }
    if (!::SHGetFileInfoW(queryPath,
            kFallback ? FILE_ATTRIBUTE_NORMAL : 0,
            &info,
            sizeof(info),
            flags) || info.hIcon == nullptr) {
        return -1;
    }

    const int kIndex = ImageList_AddIcon(imageList, info.hIcon);
    ::DestroyIcon(info.hIcon);
    return kIndex;
}

// processIconIndex resolves and caches the icon for a window row's owning
// process. Inputs are page state and a window row; output is the image-list index
// used by the PID/process column.
int processIconIndex(WindowViewState* state, const WindowSnapshotRow& row) {
    if (!state || state->processImageList == nullptr) {
        return -1;
    }

    const std::wstring kKey = row.processImagePath.empty() ? L"<generic-exe>" : row.processImagePath;
    const auto kFound = state->processIconCache.find(kKey);
    if (kFound != state->processIconCache.end()) {
        return kFound->second;
    }

    int index = addIconFromShell(state->processImageList, row.processImagePath);
    if (index < 0 && !row.processImagePath.empty()) {
        index = addIconFromShell(state->processImageList, {});
    }
    state->processIconCache[kKey] = index;
    return index;
}

// selectedModelIndex returns the currently selected model row. Input is module
// state; output is -1 when no visible list row is selected.
int selectedModelIndex(WindowViewState* state) {
    if (!state || !state->windowList) {
        return -1;
    }
    const int kSelected = ListView_GetNextItem(state->windowList, -1, LVNI_SELECTED);
    const auto& visible = state->virtualList.visibleIndexes();
    const auto& rows = state->virtualList.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || rows[kSource].itemData < 0) {
        return -1;
    }
    return static_cast<int>(rows[kSource].itemData);
}

// win32kHookScopeText renders the protocol-level thread/global scope while
// keeping unexpected values explicit for copied audit evidence.
std::wstring win32kHookScopeText(const std::uint32_t scope) {
    switch (scope) {
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_THREAD: return L"Thread";
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_GLOBAL: return L"Global";
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SCOPE_UNKNOWN: return L"Unknown";
    default: return L"Scope(" + std::to_wstring(scope) + L")";
    }
}

// win32kHookTypeText maps the documented WH_* values to their stable names.
std::wstring win32kHookTypeText(const std::uint32_t hookType) {
    switch (hookType) {
    case 0xFFFFFFFFUL: return L"WH_MSGFILTER(-1)";
    case 0UL: return L"WH_JOURNALRECORD";
    case 1UL: return L"WH_JOURNALPLAYBACK";
    case 2UL: return L"WH_KEYBOARD";
    case 3UL: return L"WH_GETMESSAGE";
    case 4UL: return L"WH_CALLWNDPROC";
    case 5UL: return L"WH_CBT";
    case 6UL: return L"WH_SYSMSGFILTER";
    case 7UL: return L"WH_MOUSE";
    case 8UL: return L"WH_HARDWARE";
    case 9UL: return L"WH_DEBUG";
    case 10UL: return L"WH_SHELL";
    case 11UL: return L"WH_FOREGROUNDIDLE";
    case 12UL: return L"WH_CALLWNDPROCRET";
    case 13UL: return L"WH_KEYBOARD_LL";
    case 14UL: return L"WH_MOUSE_LL";
    default: return L"WH_TYPE(" + std::to_wstring(hookType) + L")";
    }
}

std::wstring win32kHookSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_THREAD: return L"ThreadHookChain";
    case KSWORD_ARK_WIN32K_MESSAGE_HOOK_SOURCE_GLOBAL: return L"GlobalHookChain";
    default: return L"Source(" + std::to_wstring(source) + L")";
    }
}

std::wstring win32kHookFlagsText(const std::uint32_t flags) {
    std::vector<const wchar_t*> labels;
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL) != 0U) { labels.push_back(L"Global"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI) != 0U) { labels.push_back(L"Ansi"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP) != 0U) { labels.push_back(L"NeedSkip"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG) != 0U) { labels.push_back(L"Hung"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED) != 0U) { labels.push_back(L"Faulted"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY) != 0U) { labels.push_back(L"NoDelay"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL) != 0U) { labels.push_back(L"Wow64Dll"); }
    if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED) != 0U) { labels.push_back(L"Destroyed"); }
    std::wstring text;
    for (const wchar_t* label : labels) {
        if (!text.empty()) {
            text += L"|";
        }
        text += label;
    }
    return text.empty() ? L"-" : text;
}

// selectedWindow returns the selected HWND after model lookup. Input is module
// state; output is nullptr when no row is selected or the model index is stale.
HWND selectedWindow(WindowViewState* state) {
    const WindowSnapshotRow* row = state ? state->model.rowAt(selectedModelIndex(state)) : nullptr;
    return row ? row->hwnd : nullptr;
}

void showDetail(WindowViewState* state, int modelIndex);

std::wstring captureAffinityText(const DWORD affinity) {
    switch (affinity) {
    case WDA_NONE:
        return L"允许窗口被捕获（WDA_NONE）";
    case WDA_MONITOR:
        return L"阻止屏幕捕获（WDA_MONITOR）";
    case WDA_EXCLUDEFROMCAPTURE:
        return L"从捕获中排除（WDA_EXCLUDEFROMCAPTURE）";
    default:
        return L"未知捕获保护值";
    }
}

bool confirmCaptureProtection(HWND owner, const WindowSnapshotRow& row, const DWORD affinity) {
    const std::wstring kTitle = row.title.empty() ? L"(无标题)" : row.title;
    const std::wstring kProcess = row.processName.empty() ? L"(未知进程)" : row.processName;
    const std::wstring kText =
        L"将修改其他窗口的捕获保护属性：\n\n"
        L"窗口：" + kTitle + L"\n"
        L"句柄：" + hwndToText(row.hwnd) + L"    类名：" + row.className + L"\n"
        L"进程：" + kProcess + L"（PID " + std::to_wstring(row.processId) + L"）\n\n"
        L"新的属性：" + captureAffinityText(affinity) + L"\n\n"
        L"设置为非 WDA_NONE 后，该窗口在屏幕共享、录屏和远程会话中会变成黑块或直接消失，"
        L"而本机屏幕上看不出任何变化。\n\n是否继续？";
    return ::MessageBoxW(owner, kText.c_str(), L"设置窗口捕获保护",
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES;
}

void setCaptureProtection(WindowViewState* state, const DWORD affinity) {
    if (!state || state->viewMode != WindowViewMode::kWindowList) {
        return;
    }
    const WindowSnapshotRow* selected = state->model.rowAt(selectedModelIndex(state));
    if (!selected) {
        state->statusText = L"未选择窗口。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    const WindowSnapshotRow kRow = *selected;
    if (!::IsWindow(kRow.hwnd)) {
        state->statusText = L"目标窗口已关闭，请刷新后重试。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    if (!confirmCaptureProtection(state->hwnd, kRow, affinity)) {
        state->statusText = L"已取消设置窗口捕获保护。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }

    const bool kApplied = ::SetWindowDisplayAffinity(kRow.hwnd, affinity) != FALSE;
    const DWORD kError = kApplied ? ERROR_SUCCESS : ::GetLastError();
    if (kApplied) {
        DWORD current = WDA_NONE;
        state->statusText = ::GetWindowDisplayAffinity(kRow.hwnd, &current)
            ? L"已设置为 " + captureAffinityText(current) + L"。"
            : L"设置调用成功，但回读属性失败。";
    } else {
        state->statusText = L"设置窗口捕获保护失败（错误码 " + std::to_wstring(kError) + L"）。";
        if (kError == ERROR_ACCESS_DENIED) {
            state->statusText += L" 该 API 主要用于进程保护自身窗口，跨进程设置通常被拒绝。";
        }
    }
    showDetail(state, selectedModelIndex(state));
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// buildWin32kGuiAuditRows creates the GUI audit entry matrix. Inputs are the
// current R3 window count; processing calls available ArkDriverClient win32k
// wrappers and keeps the R3 window count as cross-view context; output is a
// vector displayed by the audit mode.
std::vector<AuditEntry> buildWin32kGuiAuditRows(size_t windowCount) {
    std::vector<AuditEntry> rows;
    rows.push_back({ L"Window", L"R3 EnumWindows cross-view", L"Top-level HWND cross-view context", L"Ready",
        L"当前页面已枚举 " + std::to_wstring(windowCount) + L" 个顶层窗口，用于和 ArkDriverClient::queryWin32kWindows 结果对照。" });
    const ksword::ark::DriverClient kClient;
    const auto kProfile = kClient.queryWin32kProfileStatus();
    rows.push_back({ L"Profile", L"ArkDriverClient::queryWin32kProfileStatus", L"win32k/win32kbase/win32kfull", ioStateText(kProfile.io.ok, kProfile.unsupported),
        L"cap=" + hexText(kProfile.capabilityMask) + L"; missing=" + hexText(kProfile.missingCapabilityMask) + L"; sessions=" + std::to_wstring(kProfile.entries.size()) + L"; " + utf8ToWideLossy(kProfile.io.message) });

    const auto kWindows = kClient.queryWin32kWindows();
    rows.push_back({ L"Windows", L"ArkDriverClient::queryWin32kWindows", L"HWND / tagWND cross-view", ioStateText(kWindows.io.ok, kWindows.unsupported),
        L"returned=" + std::to_wstring(kWindows.returnedCount) + L"/" + std::to_wstring(kWindows.totalCount) + L"; cap=" + hexText(kWindows.capabilityMask) + L"; " + utf8ToWideLossy(kWindows.io.message) });

    const auto kGuiThreads = kClient.queryWin32kGuiThreads();
    rows.push_back({ L"GUI Thread", L"ArkDriverClient::queryWin32kGuiThreads", L"tagTHREADINFO / tagQ / focus/capture", ioStateText(kGuiThreads.io.ok, kGuiThreads.unsupported),
        L"returned=" + std::to_wstring(kGuiThreads.returnedCount) + L"/" + std::to_wstring(kGuiThreads.totalCount) + L"; missing=" + hexText(kGuiThreads.missingCapabilityMask) + L"; 不采集消息内容。" });

    const auto kHotkeys = kClient.queryWin32kHotkeysPdb();
    rows.push_back({ L"Hotkeys", L"ArkDriverClient::queryWin32kHotkeysPdb", L"Hotkey object chain", ioStateText(kHotkeys.io.ok, kHotkeys.unsupported),
        L"returned=" + std::to_wstring(kHotkeys.returnedCount) + L"/" + std::to_wstring(kHotkeys.totalCount) + L"; 不删除热键。" });

    const auto kHooks = kClient.queryWin32kHooksPdb();
    rows.push_back({ L"Hooks", L"ArkDriverClient::queryWin32kHooksPdb", L"WH_* hook chain", ioStateText(kHooks.io.ok, kHooks.unsupported),
        L"returned=" + std::to_wstring(kHooks.returnedCount) + L"/" + std::to_wstring(kHooks.totalCount) + L"; chains=" + std::to_wstring(kHooks.discoveredChainCount) + L"; " + kHooks.detail });

    rows.push_back({ L"Message Hook", L"ArkDriverClient::queryWin32kHooksPdb", L"线程 / 全局消息 Hook 链", ioStateText(kHooks.io.ok, kHooks.unsupported),
        L"visited=" + std::to_wstring(kHooks.visitedNodeCount) + L"; readFail=" + std::to_wstring(kHooks.readFailureCount) + L"; corrupt=" + std::to_wstring(kHooks.corruptLinkCount) + L"; capability=" + hexText(kHooks.capabilityMask) + L"; 仅枚举诊断，不捕获消息 payload。" });

    const auto kTimers = kClient.queryWin32kTimers();
    rows.push_back({ L"Timers", L"ArkDriverClient::queryWin32kTimers", L"gTimerHashTable / tagTIMER", ioStateText(kTimers.io.ok, kTimers.unsupported),
        L"returned=" + std::to_wstring(kTimers.returnedCount) + L"/" + std::to_wstring(kTimers.totalCount) + L"; cap=" + hexText(kTimers.capabilityMask) + L"; " + utf8ToWideLossy(kTimers.io.message) });

    const auto kEventHooks = kClient.queryWin32kEventHooks();
    rows.push_back({ L"Event Hooks", L"ArkDriverClient::queryWin32kEventHooks", L"gpWinEventHooks / tagEVENTHOOK", ioStateText(kEventHooks.io.ok, kEventHooks.unsupported),
        L"returned=" + std::to_wstring(kEventHooks.returnedCount) + L"/" + std::to_wstring(kEventHooks.totalCount) + L"; cap=" + hexText(kEventHooks.capabilityMask) + L"; " + utf8ToWideLossy(kEventHooks.io.message) });

    rows.push_back({ L"WM_COPYDATA", L"R3 monitor / ETW / snapshot", L"事件摘要边界", L"ReadOnly",
        L"默认不读取 COPYDATASTRUCT payload，不安装全局消息 hook；当前仅记录只读边界说明。" });
    return rows;
}

// buildWin32kMessageHookAuditRows exposes the structured thread/global hook
// rows added by the current Win32k protocol. It performs one typed, read-only
// client query on the refresh worker and never captures message payloads or
// changes a hook chain.
std::vector<AuditEntry> buildWin32kMessageHookAuditRows() {
    const ksword::ark::Win32kHooksPdbResult kResult = ksword::ark::DriverClient().queryWin32kHooksPdb();
    std::vector<AuditEntry> rows;
    rows.reserve(kResult.entries.size() + 1U);

    const std::wstring kSummary =
        L"returned=" + std::to_wstring(kResult.returnedCount) + L"/" + std::to_wstring(kResult.totalCount) +
        L"; chains=" + std::to_wstring(kResult.discoveredChainCount) +
        L"; visited=" + std::to_wstring(kResult.visitedNodeCount) +
        L"; readFail=" + std::to_wstring(kResult.readFailureCount) +
        L"; corrupt=" + std::to_wstring(kResult.corruptLinkCount) +
        L"; duplicate=" + std::to_wstring(kResult.duplicateCount) +
        L"; cap=" + hexText(kResult.capabilityMask) +
        L"; missing=" + hexText(kResult.missingCapabilityMask) +
        L"; " + utf8ToWideLossy(kResult.io.message) +
        (kResult.detail.empty() ? L"" : L"; " + kResult.detail);

    rows.push_back({
        L"Message Hook snapshot",
        L"ArkDriverClient::queryWin32kHooksPdb",
        L"Thread / global message hook chain",
        ioStateText(kResult.io.ok, kResult.unsupported),
        kSummary
    });

    for (const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry : kResult.entries) {
        const std::wstring kItem = win32kHookTypeText(entry.hookType) + L" / " + win32kHookScopeText(entry.hookScope) +
            L" | PID=" + std::to_wstring(entry.processId) + L" TID=" + std::to_wstring(entry.threadId) +
            L" Session=" + std::to_wstring(entry.sessionId);
        std::wostringstream detail;
        detail << L"source=" << win32kHookSourceText(entry.source)
               << L"; target=" << entry.targetProcessId << L"/" << entry.targetThreadId << L"/" << entry.targetSessionId
               << L"; hookHandle=" << hexText(entry.hookHandle)
               << L"; hookObject=" << hexText(entry.hookObject)
               << L"; chain=" << hexText(entry.chainHead) << L" -> " << hexText(entry.nextHookObject)
               << L"; procedure=" << hexText(entry.procedureAddress) << L" + " << hexText(entry.procedureOffset)
               << L"; moduleBase=" << hexText(entry.moduleBase)
               << L"; moduleId=" << static_cast<std::int32_t>(entry.moduleId)
               << L"; atom=" << hexText(entry.moduleAtom)
               << L"; threadInfo=" << hexText(entry.threadInfo)
               << L"; targetThreadInfo=" << hexText(entry.targetThreadInfo)
               << L"; desktop=" << hexText(entry.desktopObject)
               << L"; flags=" << win32kHookFlagsText(entry.flags) << L" (" << hexText(entry.flags) << L")"
               << L"; fieldFlags=" << hexText(entry.fieldFlags)
               << L"; lastStatus=" << hexText(static_cast<std::uint32_t>(entry.lastStatus));
        const std::wstring kDriverDetail = fixedWideText(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS);
        if (!kDriverDetail.empty()) {
            detail << L"; " << kDriverDetail;
        }
        rows.push_back({
            L"Message Hook",
            win32kHookSourceText(entry.source),
            kItem,
            win32kRuntimeStatusText(entry.status),
            detail.str()
        });
    }
    return rows;
}

// buildWin32kTimerAuditRows exposes the existing typed tagTIMER snapshot as
// immutable display rows. The DriverClient wrapper owns all protocol handling;
// this page only projects the returned snapshot and never alters a timer.
std::vector<AuditEntry> buildWin32kTimerAuditRows() {
    const ksword::ark::Win32kTimersResult kResult = ksword::ark::DriverClient().queryWin32kTimers();
    const std::vector<Win32kTimerEvidenceRow> kEvidenceRows = buildWin32kTimerEvidenceRows(kResult);
    std::vector<AuditEntry> rows;
    rows.reserve(kEvidenceRows.size());
    for (const Win32kTimerEvidenceRow& evidence : kEvidenceRows) {
        rows.push_back({
            evidence.category,
            evidence.source,
            evidence.item,
            evidence.status,
            evidence.detail,
            static_cast<DWORD>(evidence.relatedProcessId)
        });
    }
    return rows;
}

// buildGpuDisplayAuditRows creates the GPU/display/watchdog audit entry matrix.
// Inputs are none; processing calls the ArkDriverClient GPU/display watchdog
// audit wrapper and supplements it with R3 configuration context rows;
// output is displayed as read-only audit rows.
std::vector<AuditEntry> buildGpuDisplayAuditRows() {
    std::vector<AuditEntry> rows;
    const ksword::ark::DriverClient kClient;
    const auto kGpuAudit = kClient.queryGpuDisplayWatchdogAudit();
    rows.push_back({ L"GPU", L"ArkDriverClient::queryGpuDisplayWatchdogAudit", L"dxgkrnl / dxgmms2 / watchdog", ioStateText(kGpuAudit.io.ok, kGpuAudit.unsupported),
        L"drivers=" + std::to_wstring(kGpuAudit.driverCount) + L"; devices=" + std::to_wstring(kGpuAudit.deviceCount) + L"; rows=" + std::to_wstring(kGpuAudit.entries.size()) + L"; " + utf8ToWideLossy(kGpuAudit.io.message) });
    rows.push_back({ L"Display", L"R0 DeviceAudit + R3 display APIs", L"Adapter / monitor / display path", kGpuAudit.io.ok ? L"OK" : L"Partial",
        L"R0 设备栈已接入；R3 display API 可继续作为 cross-view，不修改显示配置。" });
    rows.push_back({ L"Miniport", L"R0 DeviceAudit", L"Display miniport basic state", kGpuAudit.io.ok ? L"OK" : L"Partial",
        L"按 driver/device row 展示 miniport、PCI 设备和显示路径；缺失字段显示 partial。" });
    rows.push_back({ L"TDR", L"Registry/EventLog reader", L"TDR configuration summary", L"ReadOnly",
        L"只读摘要：TdrDelay/TdrDdiDelay/TdrLevel 和事件摘要由用户态安全读取，不修改策略。" });
    rows.push_back({ L"Watchdog", L"ArkDriverClient::queryGpuDisplayWatchdogAudit", L"watchdog.sys integrity / status", ioStateText(kGpuAudit.io.ok, kGpuAudit.unsupported),
        L"展示 watchdog 模块/驱动对象状态；不关闭 watchdog，不改 TDR 策略。" });
    return rows;
}

std::vector<ksword::ui::VirtualListRow> buildWindowDisplayRows(
    const WindowEnumerationResult& enumeration,
    const WindowSortMode sortMode) {
    WindowModel model;
    model.setRows(enumeration.rows);
    model.setSortMode(sortMode);
    const auto& sourceRows = model.rows();
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(sourceRows.size());
    for (std::size_t index = 0; index < sourceRows.size(); ++index) {
        const WindowSnapshotRow& row = sourceRows[index];
        ksword::ui::VirtualListRow display{};
        display.stableKey = hwndToText(row.hwnd);
        display.itemData = static_cast<LPARAM>(index);
        display.cells = {
            model.textForColumn(row, 0),
            model.textForColumn(row, 1),
            model.textForColumn(row, 2),
            model.textForColumn(row, 3),
            model.textForColumn(row, 4),
            row.processImagePath,
            std::to_wstring(row.threadId),
            std::to_wstring(row.style),
            std::to_wstring(row.exStyle),
        };
        rows.push_back(std::move(display));
    }
    return rows;
}

std::vector<ksword::ui::VirtualListRow> buildAuditDisplayRows(const std::vector<AuditEntry>& auditRows) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(auditRows.size());
    for (std::size_t index = 0; index < auditRows.size(); ++index) {
        const AuditEntry& entry = auditRows[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(index) + L":" + entry.item;
        row.itemData = static_cast<LPARAM>(index);
        row.cells = { entry.category, entry.source, entry.item, entry.status, entry.detail };
        rows.push_back(std::move(row));
    }
    return rows;
}

// configureWindowColumns restores the existing live-window list headers. Input
// is page state; processing only updates visible ListView columns; no return.
void configureWindowColumns(WindowViewState* state) {
    if (!state || !state->windowList) {
        return;
    }
    setColumn(state->windowList, 0, L"进程 / PID", 190);
    setColumn(state->windowList, 1, L"HWND", 120);
    setColumn(state->windowList, 2, L"Title", 300);
    setColumn(state->windowList, 3, L"Class", 190);
    setColumn(state->windowList, 4, L"State", 220);
}

// configureAuditColumns switches the main list to audit-entry headers. Input is
// page state; output is visible column metadata only.
void configureAuditColumns(WindowViewState* state) {
    if (!state || !state->windowList) {
        return;
    }
    setColumn(state->windowList, 0, L"类别", 150);
    setColumn(state->windowList, 1, L"数据源", 220);
    setColumn(state->windowList, 2, L"入口 / 对象", 280);
    setColumn(state->windowList, 3, L"状态", 120);
    setColumn(state->windowList, 4, L"说明", 430);
}

// showAuditDetail refreshes the detail pane for one audit row. Inputs are state
// and row index; processing is display-only; no value is returned.
void showAuditDetail(WindowViewState* state, int rowIndex) {
    if (!state || !state->detailList) {
        return;
    }
    ListView_DeleteAllItems(state->detailList);
    if (rowIndex < 0 || rowIndex >= static_cast<int>(state->auditRows.size())) {
        addDetailRow(state->detailList, 0, L"Selection", L"No audit entry selected");
        return;
    }
    const AuditEntry& entry = state->auditRows[rowIndex];
    int detailRow = 0;
    addDetailRow(state->detailList, detailRow++, L"类别", entry.category);
    addDetailRow(state->detailList, detailRow++, L"数据源", entry.source);
    addDetailRow(state->detailList, detailRow++, L"入口 / 对象", entry.item);
    addDetailRow(state->detailList, detailRow++, L"状态", entry.status);
    addDetailRow(state->detailList, detailRow++, L"说明", entry.detail);
    addDetailRow(state->detailList, detailRow++, L"安全边界", L"默认只读审计；本页不提供 patch/delete/bypass/remove/unlink 操作。");
}

void renderWindowDetail(WindowViewState* state, const WindowDetailSnapshot& snapshot);

// showDetail schedules live R3 and R0 window inspection outside the UI thread.
// Inputs are a cached model index; stale results are ignored by request epoch.
void showDetail(WindowViewState* state, int modelIndex) {
    if (!state || !state->detailList) {
        return;
    }
    if (state->viewMode != WindowViewMode::kWindowList) {
        window_tools::updateWindowHierarchyReportView(state->hierarchyReportView, nullptr);
        showAuditDetail(state, modelIndex);
        return;
    }
    const WindowSnapshotRow* row = state->model.rowAt(modelIndex);
    if (!row || !state->detailTask) {
        window_tools::updateWindowHierarchyReportView(state->hierarchyReportView, nullptr);
        ListView_DeleteAllItems(state->detailList);
        addDetailRow(state->detailList, 0, L"Selection", L"No window selected");
        return;
    }
    const WindowSnapshotRow kInput = *row;
    window_tools::updateWindowHierarchyReportView(state->hierarchyReportView, kInput.hwnd);
    const std::uint64_t kGeneration = state->snapshotGeneration;
    ListView_DeleteAllItems(state->detailList);
    addDetailRow(state->detailList, 0, L"状态", L"正在后台查询窗口与 Win32k 详情…");
    state->detailTask->request(
        [kInput, kGeneration, modelIndex] {
            WindowDetailSnapshot snapshot{};
            snapshot.generation = kGeneration;
            snapshot.modelIndex = modelIndex;
            snapshot.row = kInput;
            snapshot.detail = queryWindowDetails(kInput.hwnd);
            snapshot.r0Detail = ksword::ark::DriverClient().queryWin32kWindowDetail(
                static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(kInput.hwnd)),
                static_cast<unsigned long>(kInput.processId),
                static_cast<unsigned long>(kInput.threadId));
            return snapshot;
        },
        [state](std::uint64_t, std::optional<WindowDetailSnapshot>&& snapshot, std::exception_ptr error) {
            if (!state || error || !snapshot.has_value()) {
                if (state) {
                    state->statusText = L"窗口详情查询异常结束。";
                    ::InvalidateRect(state->hwnd, nullptr, TRUE);
                }
                return;
            }
            if (snapshot->generation != state->snapshotGeneration) {
                return;
            }
            const WindowSnapshotRow* current = state->model.rowAt(snapshot->modelIndex);
            if (!current || current->hwnd != snapshot->row.hwnd) {
                return;
            }
            renderWindowDetail(state, *snapshot);
        });
}

// renderWindowDetail installs one completed immutable detail snapshot.
void renderWindowDetail(WindowViewState* state, const WindowDetailSnapshot& snapshot) {
    if (!state || !state->detailList) {
        return;
    }
    if (state->viewMode != WindowViewMode::kWindowList) {
        showAuditDetail(state, snapshot.modelIndex);
        return;
    }
    ListView_DeleteAllItems(state->detailList);
    const WindowSnapshotRow* row = &snapshot.row;
    WindowDetail detail = snapshot.detail;
    if (!detail.found) {
        detail = state->model.detailFromRow(*row);
    }
    int detailRow = 0;
    addDetailRow(state->detailList, detailRow++, L"Window", detail.title);
    for (const WindowProperty& property : detail.properties) {
        addDetailRow(state->detailList, detailRow++, property.name, property.value);
    }

    // Mirror the full WindowDock single-HWND R0 detail path through
    // ArkDriverClient. Inputs are the currently selected HWND/PID/TID; the
    // wrapper keeps DeviceIoControl syntax centralized and returns one bounded
    // response packet; this block appends read-only detail rows and returns no
    // value to the caller.
    const ksword::ark::Win32kWindowRuntimeDetailResult& r0Detail = snapshot.r0Detail;
    addDetailRow(state->detailList, detailRow++, L"R0 Win32k Detail",
        ioStateText(r0Detail.io.ok, r0Detail.unsupported) + L" - " + utf8ToWideLossy(r0Detail.io.message));
    if (r0Detail.io.ok) {
        const KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE& response = r0Detail.response;
        addDetailRow(state->detailList, detailRow++, L"R0 Status", win32kRuntimeStatusText(response.status));
        addDetailRow(state->detailList, detailRow++, L"R0 HWND", hexText(response.hwnd));
        addDetailRow(state->detailList, detailRow++, L"R0 PID/TID",
            std::to_wstring(response.processId) + L" / " + std::to_wstring(response.threadId));
        addDetailRow(state->detailList, detailRow++, L"R0 tagWND", hexText(response.tagWnd));
        addDetailRow(state->detailList, detailRow++, L"R0 threadInfo", hexText(response.threadInfo));
        addDetailRow(state->detailList, detailRow++, L"R0 queue", hexText(response.queueObject));
        addDetailRow(state->detailList, detailRow++, L"R0 desktop", hexText(response.desktopObject));
        addDetailRow(state->detailList, detailRow++, L"R0 capability", hexText(response.capabilityMask));
        addDetailRow(state->detailList, detailRow++, L"R0 missing capability", hexText(response.missingCapabilityMask));
        addDetailRow(state->detailList, detailRow++, L"R0 fieldFlags", hexText(response.fieldFlags));
        addDetailRow(state->detailList, detailRow++, L"R0 lastStatus", hexText(static_cast<std::uint32_t>(response.lastStatus)));
        addDetailRow(state->detailList, detailRow++, L"R0 Title",
            fixedWideText(response.title, KSWORD_ARK_WIN32K_TITLE_CHARS));
        addDetailRow(state->detailList, detailRow++, L"R0 Class",
            fixedWideText(response.className, KSWORD_ARK_WIN32K_CLASS_CHARS));
        addDetailRow(state->detailList, detailRow++, L"R0 Detail",
            fixedWideText(response.detail, KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS));
        addDetailRow(state->detailList, detailRow++, L"R0 win32k",
            win32kModuleStateText(L"win32k", response.win32k));
        addDetailRow(state->detailList, detailRow++, L"R0 win32kbase",
            win32kModuleStateText(L"win32kbase", response.win32kbase));
        addDetailRow(state->detailList, detailRow++, L"R0 win32kfull",
            win32kModuleStateText(L"win32kfull", response.win32kfull));
        addDetailRow(state->detailList, detailRow++, L"R0 offsets tagWND",
            L"pti=" + hexText(response.fieldOffsets.tagWndThreadInfo) +
            L"; style=" + hexText(response.fieldOffsets.tagWndStyle) +
            L"; rect=" + hexText(response.fieldOffsets.tagWndRect) +
            L"; title=" + hexText(response.fieldOffsets.tagWndTitle) +
            L"; class=" + hexText(response.fieldOffsets.tagWndClass));
        addDetailRow(state->detailList, detailRow++, L"R0 offsets thread/queue",
            L"queue=" + hexText(response.fieldOffsets.tagThreadInfoQueue) +
            L"; desktop=" + hexText(response.fieldOffsets.tagThreadInfoDesktop) +
            L"; active=" + hexText(response.fieldOffsets.tagQActiveWindow) +
            L"; focus=" + hexText(response.fieldOffsets.tagQFocusWindow) +
            L"; capture=" + hexText(response.fieldOffsets.tagQCaptureWindow));
    }
}

// requestWindowFilter filters the immutable display snapshot in the worker.
// Inputs are the retained rows and the debounced local query. No enumeration,
// IOCTL, or live HWND query occurs on the UI thread.
void requestWindowFilter(WindowViewState* state, std::wstring query) {
    if (!state || !state->filterTask || !state->filterRows) {
        return;
    }
    state->filterQuery = std::move(query);
    state->filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state->filterBar);
    const std::uint64_t kGeneration = state->snapshotGeneration;
    const auto kRows = state->filterRows;
    const bool kUseRegex = state->filterUseRegex;
    state->filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state->filterQuery]() mutable {
            WindowFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [state](std::uint64_t, std::optional<WindowFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                if (state) {
                    state->statusText = L"窗口筛选异常结束，已保留当前可见结果。";
                    ::InvalidateRect(state->hwnd, nullptr, TRUE);
                }
                return;
            }
            if (result->generation != state->snapshotGeneration || result->query != state->filterQuery ||
                result->useRegex != state->filterUseRegex) {
                return;
            }
            state->virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            if (!state->filterQuery.empty()) {
                state->statusText = L"窗口筛选结果：" + std::to_wstring(state->virtualList.rowCount()) + L" 项。";
            }
        });
}

// populateList installs a preformatted owner-data snapshot. Input is module
// state; only ListView metadata and immutable rows change on the UI thread.
void populateList(WindowViewState* state) {
    if (!state || !state->windowList || !state->filterRows) {
        return;
    }
    if (state->viewMode != WindowViewMode::kWindowList) {
        configureAuditColumns(state);
    } else {
        configureWindowColumns(state);
    }
    state->virtualList.setSharedRows(state->filterRows);
    requestWindowFilter(state, state->filterBar ? ksword::ui::getFilterBarText(state->filterBar) : state->filterQuery);
}

// refreshWindows performs the R3 EnumWindows and optional R0 audit snapshot on
// the worker. UI state keeps the prior result interactive until replacement.
void refreshWindows(WindowViewState* state) {
    if (!state || !state->refreshTask) {
        return;
    }
    const WindowViewMode kMode = state->viewMode;
    const WindowSortMode kSortMode = state->model.sortMode();
    const bool kFirstLoad = state->virtualList.rows().empty();
    state->statusText = state->refreshTask->running()
        ? L"窗口刷新已排队，等待当前快照完成…"
        : L"正在后台枚举窗口和审计 Win32k 状态…";
    ::EnableWindow(state->refreshButton, FALSE);
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(state->loadingOverlay, true, L"正在加载窗口与 Win32k 审计…");
    }
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
    state->refreshTask->request(
        [kMode, kSortMode] {
            WindowRefreshSnapshot snapshot{};
            snapshot.mode = kMode;
            snapshot.sortMode = kSortMode;
            if (kMode == WindowViewMode::kWin32kGuiAudit) {
                snapshot.enumeration = enumerateTopLevelWindows();
                snapshot.auditRows = buildWin32kGuiAuditRows(snapshot.enumeration.rows.size());
                snapshot.displayRows = buildAuditDisplayRows(snapshot.auditRows);
            } else if (kMode == WindowViewMode::kWin32kMessageHookAudit) {
                snapshot.auditRows = buildWin32kMessageHookAuditRows();
                snapshot.displayRows = buildAuditDisplayRows(snapshot.auditRows);
            } else if (kMode == WindowViewMode::kWin32kTimerAudit) {
                snapshot.auditRows = buildWin32kTimerAuditRows();
                snapshot.displayRows = buildAuditDisplayRows(snapshot.auditRows);
            } else if (kMode == WindowViewMode::kGpuDisplayAudit) {
                snapshot.auditRows = buildGpuDisplayAuditRows();
                snapshot.displayRows = buildAuditDisplayRows(snapshot.auditRows);
            } else {
                snapshot.enumeration = enumerateTopLevelWindows();
                snapshot.displayRows = buildWindowDisplayRows(snapshot.enumeration, kSortMode);
            }
            return snapshot;
        },
        [state](std::uint64_t, std::optional<WindowRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (!state) {
                return;
            }
            ::EnableWindow(state->refreshButton, TRUE);
            ksword::ui::setLoadingOverlay(state->loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state->statusText = L"窗口后台刷新异常结束，请检查驱动状态与访问权限。";
                ::InvalidateRect(state->hwnd, nullptr, TRUE);
                return;
            }
            state->model.setRows(std::move(snapshot->enumeration.rows));
            state->model.setSortMode(snapshot->sortMode);
            state->auditRows = std::move(snapshot->auditRows);
            state->filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(snapshot->displayRows));
            ++state->snapshotGeneration;
            if (snapshot->mode == WindowViewMode::kWindowList) {
                state->statusText = state->model.rows().empty() ? L"Windows: 0" : L"Windows: " + std::to_wstring(state->model.rows().size());
            } else if (snapshot->mode == WindowViewMode::kWin32kGuiAudit) {
                state->statusText = L"Win32K GUI 审计快照已刷新。";
            } else if (snapshot->mode == WindowViewMode::kWin32kMessageHookAudit) {
                state->statusText = L"Win32K 消息 Hook 审计快照已刷新：" + std::to_wstring(state->auditRows.size()) + L" 行。";
            } else if (snapshot->mode == WindowViewMode::kWin32kTimerAudit) {
                state->statusText = L"Win32K 定时器只读证据快照已刷新：" + std::to_wstring(state->auditRows.size()) +
                    L" 行；首行保留返回计数、完整性和布局来源。";
            } else {
                state->statusText = L"GPU / Display / Watchdog 审计快照已刷新。";
            }
            populateList(state);
            window_tools::updateWindowHierarchyReportView(state->hierarchyReportView,
                snapshot->mode == WindowViewMode::kWindowList ? selectedWindow(state) : nullptr);
            ::InvalidateRect(state->hwnd, nullptr, TRUE);
        });
}

// updateViewModeFromCombo reads the audit-mode combo and switches between the
// existing window list and read-only audit entry pages. Input is page state;
// processing reuses refreshWindows for R3 cross-view context; no value is
// returned.
void updateViewModeFromCombo(WindowViewState* state) {
    if (!state || !state->auditModeCombo) {
        return;
    }
    const LRESULT kSelected = ::SendMessageW(state->auditModeCombo, CB_GETCURSEL, 0, 0);
    if (kSelected == 1) {
        state->viewMode = WindowViewMode::kWin32kGuiAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else if (kSelected == 2) {
        state->viewMode = WindowViewMode::kWin32kMessageHookAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else if (kSelected == 3) {
        state->viewMode = WindowViewMode::kWin32kTimerAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else if (kSelected == 4) {
        state->viewMode = WindowViewMode::kGpuDisplayAudit;
        ::EnableWindow(state->sortCombo, FALSE);
        ::EnableWindow(state->frontButton, FALSE);
        ::EnableWindow(state->restoreButton, FALSE);
        ::EnableWindow(state->minimizeButton, FALSE);
        ::EnableWindow(state->maximizeButton, FALSE);
        ::EnableWindow(state->closeButton, FALSE);
    } else {
        state->viewMode = WindowViewMode::kWindowList;
        ::EnableWindow(state->sortCombo, TRUE);
        ::EnableWindow(state->frontButton, TRUE);
        ::EnableWindow(state->restoreButton, TRUE);
        ::EnableWindow(state->minimizeButton, TRUE);
        ::EnableWindow(state->maximizeButton, TRUE);
        ::EnableWindow(state->closeButton, TRUE);
    }
    if (state->viewMode != WindowViewMode::kWindowList) {
        window_tools::updateWindowHierarchyReportView(state->hierarchyReportView, nullptr);
    }
    refreshWindows(state);
}

// updateSortModeFromCombo reads the toolbar combo-box and rebuilds the list
// without re-enumerating windows. Input is the page state; processing maps combo
// index 0 to stacking order and index 1 to process order; no value is returned.
void updateSortModeFromCombo(WindowViewState* state) {
    if (!state || !state->sortCombo) {
        return;
    }
    if (state->viewMode != WindowViewMode::kWindowList) {
        return;
    }

    const LRESULT kSelected = ::SendMessageW(state->sortCombo, CB_GETCURSEL, 0, 0);
    const WindowSortMode kMode = kSelected == 1 ? WindowSortMode::kProcessOrder : WindowSortMode::kStackingOrder;
    state->model.setSortMode(kMode);
    state->statusText = kMode == WindowSortMode::kProcessOrder ? L"Windows: 按进程顺序排序" : L"Windows: 按堆叠顺序排序";
    refreshWindows(state);
}

// runAction executes one centralized WindowActions operation against the current
// selection. Inputs are state and action command ID; processing delegates to
// WindowActions.* and refreshes status text; no value is returned.
void runAction(WindowViewState* state, int commandId) {
    if (!state) {
        return;
    }
    if (state->viewMode != WindowViewMode::kWindowList) {
        state->statusText = L"Audit entries are read-only.";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    HWND hwnd = selectedWindow(state);
    WindowActionResult result;
    switch (commandId) {
    case kFrontButtonId:
        result = bringWindowToFront(hwnd);
        break;
    case kRestoreButtonId:
        result = restoreWindow(hwnd);
        break;
    case kMinimizeButtonId:
        result = minimizeWindow(hwnd);
        break;
    case kMaximizeButtonId:
        result = maximizeWindow(hwnd);
        break;
    case kCloseButtonId:
        result = closeWindowGracefully(hwnd);
        break;
    default:
        result = { false, L"Unknown action." };
        break;
    }
    state->statusText = result.message;
    showDetail(state, selectedModelIndex(state));
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// copyCurrentDetail serializes the current detail pane as tab-separated text.
// Input is the page state; processing reads the visible detail ListView rows;
// no value is returned because statusText stores the outcome for painting.
void copyCurrentDetail(WindowViewState* state) {
    if (!state || !state->detailList) {
        return;
    }
    std::wstring text;
    const int kRows = ListView_GetItemCount(state->detailList);
    for (int row = 0; row < kRows; ++row) {
        text += listText(state->detailList, row, 0);
        text += L'\t';
        text += listText(state->detailList, row, 1);
        text += L"\r\n";
    }
    state->statusText = copyText(state->hwnd, text) ? L"Window detail copied." : L"Copy window detail failed.";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

void showDetailContextMenu(WindowViewState* state, POINT screenPoint) {
    if (!state || !state->detailList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state->detailList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_SubItemHitTest(state->detailList, &hit);
    if (kHitRow >= 0) {
        ListView_SetItemState(state->detailList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state->detailList, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const int kSelected = ListView_GetNextItem(state->detailList, -1, LVNI_SELECTED);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kSelected >= 0 ? 0U : MF_GRAYED), kWindowMenuCopyDetailCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kSelected >= 0 ? 0U : MF_GRAYED), kWindowMenuCopyDetailRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (ListView_GetItemCount(state->detailList) > 0 ? 0U : MF_GRAYED), kWindowMenuCopyDetailVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (ListView_GetItemCount(state->detailList) > 0 ? 0U : MF_GRAYED),
        kWindowMenuExportDetail, L"导出当前详情为 TSV");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state->hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kWindowMenuExportDetail) {
        exportCurrentDetail(state);
        return;
    }
    std::wstring text;
    if (kCommand == kWindowMenuCopyDetailCell && kSelected >= 0) {
        text = listText(state->detailList, kSelected, std::max(0, hit.iSubItem));
    } else if (kCommand == kWindowMenuCopyDetailRow && kSelected >= 0) {
        text = listText(state->detailList, kSelected, 0) + L"\t" + listText(state->detailList, kSelected, 1);
    } else if (kCommand == kWindowMenuCopyDetailVisible) {
        for (int row = 0; row < ListView_GetItemCount(state->detailList); ++row) {
            text += listText(state->detailList, row, 0) + L"\t" + listText(state->detailList, row, 1) + L"\r\n";
        }
    }
    if (kCommand != 0) {
        state->statusText = copyText(state->hwnd, text) ? L"已复制结果。" : L"复制结果失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
    }
}

std::wstring copyVirtualRows(const WindowViewState* state, const bool allVisible) {
    if (!state) {
        return {};
    }
    const auto& rows = state->virtualList.rows();
    const auto& visible = state->virtualList.visibleIndexes();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (ListView_GetItemState(state->windowList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            continue;
        }
        const std::size_t kSource = visible[item];
        if (kSource >= rows.size()) {
            continue;
        }
        const auto& cells = rows[kSource].cells;
        for (std::size_t column = 0; column < cells.size(); ++column) {
            if (column != 0) {
                text.push_back(L'\t');
            }
            for (const wchar_t kCh : cells[column]) {
                text.push_back(kCh == L'\t' || kCh == L'\r' || kCh == L'\n' ? L' ' : kCh);
            }
        }
        text += L"\r\n";
    }
    return text;
}

std::wstring copyVirtualCell(const WindowViewState* state) {
    if (!state) {
        return {};
    }
    const int kSelected = ListView_GetNextItem(state->windowList, -1, LVNI_SELECTED);
    const auto& visible = state->virtualList.visibleIndexes();
    const auto& rows = state->virtualList.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return {};
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || state->contextColumn < 0 || static_cast<std::size_t>(state->contextColumn) >= rows[kSource].cells.size()) {
        return {};
    }
    return rows[kSource].cells[static_cast<std::size_t>(state->contextColumn)];
}

// selectedWindowSnapshot returns the currently selected retained window row
// only in the normal window-list mode. Audit rows never pretend to carry the
// same process-image provenance as an EnumWindows snapshot.
const WindowSnapshotRow* selectedWindowSnapshot(WindowViewState* state) {
    if (!state || state->viewMode != WindowViewMode::kWindowList) {
        return nullptr;
    }
    return state->model.rowAt(selectedModelIndex(state));
}

// selectedAuditEntry returns the immutable selected audit snapshot. It never
// treats a kernel object pointer as a live HWND or process handle.
const AuditEntry* selectedAuditEntry(WindowViewState* state) {
    if (!state || state->viewMode == WindowViewMode::kWindowList) {
        return nullptr;
    }
    const int kRowIndex = selectedModelIndex(state);
    if (kRowIndex < 0 || kRowIndex >= static_cast<int>(state->auditRows.size())) {
        return nullptr;
    }
    return &state->auditRows[static_cast<std::size_t>(kRowIndex)];
}

void openSelectedWindowProcess(WindowViewState* state) {
    const WindowSnapshotRow* row = selectedWindowSnapshot(state);
    if (!state || !row || row->processId == 0U) {
        if (state) {
            state->statusText = L"窗口快照没有可导航的 PID。";
            ::InvalidateRect(state->hwnd, nullptr, TRUE);
        }
        return;
    }
    const DWORD kProcessId = row->processId;
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    const bool kRouted = ksword::ui::requestEntityNavigation(state->hwnd, request);
    state->statusText = kRouted
        ? L"已请求打开当前 PID " + std::to_wstring(kProcessId) + L" 的进程详细信息；窗口快照归属会重新校验。"
        : L"无法导航到该窗口快照的当前进程实例。";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// openSelectedAuditProcess routes only the captured numeric PID from a
// read-only audit record. The destination revalidates the current process, so
// a historical tagTIMER owner is never assumed to still be the same instance.
void openSelectedAuditProcess(WindowViewState* state) {
    const AuditEntry* entry = selectedAuditEntry(state);
    if (!state || !entry || entry->relatedProcessId == 0U) {
        if (state) {
            state->statusText = L"审计快照没有可导航的 PID。";
            ::InvalidateRect(state->hwnd, nullptr, TRUE);
        }
        return;
    }
    const DWORD kProcessId = entry->relatedProcessId;
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    const bool kRouted = ksword::ui::requestEntityNavigation(state->hwnd, request);
    state->statusText = kRouted
        ? L"已请求打开快照 PID " + std::to_wstring(kProcessId) + L" 的进程详情；历史定时器归属会重新校验。"
        : L"无法导航到该审计快照的当前进程实例。";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

void openSelectedWindowImageDirectory(WindowViewState* state) {
    const WindowSnapshotRow* row = selectedWindowSnapshot(state);
    if (!state || !row) {
        return;
    }
    const std::wstring kDirectory =
        ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(row->processImagePath);
    if (kDirectory.empty()) {
        state->statusText = L"窗口快照中的映像路径不是可精确导航的 DOS/UNC 文件路径。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        return;
    }
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kFileBrowser;
    request.entity.kind = ksword::core::EntityKind::kFile;
    request.entity.text = kDirectory;
    const bool kRouted = ksword::ui::requestEntityNavigation(state->hwnd, request);
    state->statusText = kRouted
        ? L"已在文件模块打开窗口映像所在目录。"
        : L"文件模块当前无法接收窗口映像所在目录。";
    ::InvalidateRect(state->hwnd, nullptr, TRUE);
}

// showWindowContextMenu exposes the retained Window page actions from the row
// itself. Inputs are page state and screen coordinates; processing selects the
// hit row when needed, groups detail/window actions into submenus, then
// dispatches the chosen menu command; no value is returned.
void showWindowContextMenu(WindowViewState* state, POINT screenPoint) {
    if (!state || !state->windowList) {
        return;
    }

    POINT clientPoint = screenPoint;
    ::ScreenToClient(state->windowList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_SubItemHitTest(state->windowList, &hit);
    if (kHitRow >= 0 && (ListView_GetItemState(state->windowList, kHitRow, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
        ListView_SetItemState(state->windowList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state->windowList, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        showDetail(state, selectedModelIndex(state));
    }
    if (kHitRow >= 0) {
        state->contextColumn = hit.iSubItem;
    }

    const bool kHasWindow = state->viewMode == WindowViewMode::kWindowList && selectedWindow(state) != nullptr;
    const bool kHasRow = ListView_GetNextItem(state->windowList, -1, LVNI_SELECTED) >= 0;
    const bool kHasDetailRows = state->detailList && ListView_GetItemCount(state->detailList) > 0;
    const WindowSnapshotRow* investigationRow = selectedWindowSnapshot(state);
    const AuditEntry* auditInvestigationRow = selectedAuditEntry(state);
    const bool kCanOpenProcess = (investigationRow != nullptr && investigationRow->processId != 0U) ||
        (auditInvestigationRow != nullptr && auditInvestigationRow->relatedProcessId != 0U);
    const bool kCanOpenImageDirectory = investigationRow != nullptr &&
        !ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(investigationRow->processImagePath).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU detailMenu = ::CreatePopupMenu();
    if (detailMenu) {
        ::AppendMenuW(detailMenu, MF_STRING | (kHasWindow ? 0U : MF_GRAYED), kWindowMenuRefreshDetail, L"刷新详细信息");
        ::AppendMenuW(detailMenu, MF_STRING | (kHasRow ? 0U : MF_GRAYED), kWindowMenuCopyDetail, L"复制详细信息");
        ::AppendMenuW(detailMenu, MF_STRING | (kHasDetailRows ? 0U : MF_GRAYED), kWindowMenuExportDetail, L"导出当前详情为 TSV");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(detailMenu), L"详细信息");
    }
    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu) {
        ::AppendMenuW(operationMenu, MF_STRING | (kHasWindow ? 0U : MF_GRAYED), kWindowMenuFront, L"置前");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasWindow ? 0U : MF_GRAYED), kWindowMenuRestore, L"恢复");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasWindow ? 0U : MF_GRAYED), kWindowMenuMinimize, L"最小化");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasWindow ? 0U : MF_GRAYED), kWindowMenuMaximize, L"最大化");
        ::AppendMenuW(operationMenu, MF_STRING | (kHasWindow ? 0U : MF_GRAYED), kWindowMenuClose, L"关闭窗口");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"窗口操作");
    }
    HMENU captureMenu = ::CreatePopupMenu();
    if (captureMenu) {
        const UINT kEnabled = kHasWindow ? MF_ENABLED : MF_GRAYED;
        ::AppendMenuW(captureMenu, MF_STRING | kEnabled, kWindowMenuAllowCapture, L"允许窗口捕获");
        ::AppendMenuW(captureMenu, MF_STRING | kEnabled, kWindowMenuBlockCapture, L"阻止屏幕捕获");
        ::AppendMenuW(captureMenu, MF_STRING | kEnabled, kWindowMenuExcludeFromCapture, L"从捕获中排除");
        ::AppendMenuW(menu, MF_POPUP | kEnabled, reinterpret_cast<UINT_PTR>(captureMenu), L"窗口捕获保护");
    }
    HMENU investigationMenu = ::CreatePopupMenu();
    if (investigationMenu) {
        ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenProcess ? 0U : MF_GRAYED),
            kWindowMenuOpenProcess, L"打开当前 PID 的进程详情");
        ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenImageDirectory ? 0U : MF_GRAYED),
            kWindowMenuOpenImageDirectory, L"打开映像所在目录");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasRow ? 0U : MF_GRAYED), kWindowMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasRow ? 0U : MF_GRAYED), kWindowMenuCopyRow, L"复制行");
        ::AppendMenuW(copyMenu, MF_STRING | (!state->virtualList.visibleIndexes().empty() ? 0U : MF_GRAYED), kWindowMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    const UINT kCommand = ::TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        state->hwnd,
        nullptr);
    ::DestroyMenu(menu);

    switch (kCommand) {
    case kWindowMenuRefreshDetail:
        showDetail(state, selectedModelIndex(state));
        state->statusText = L"Window detail refreshed.";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuCopyDetail:
        copyCurrentDetail(state);
        break;
    case kWindowMenuExportDetail:
        exportCurrentDetail(state);
        break;
    case kWindowMenuCopyCell:
        state->statusText = copyText(state->hwnd, copyVirtualCell(state)) ? L"已复制单元格。" : L"复制单元格失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuCopyRow:
        state->statusText = copyText(state->hwnd, copyVirtualRows(state, false)) ? L"已复制行。" : L"复制行失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuCopyVisible:
        state->statusText = copyText(state->hwnd, copyVirtualRows(state, true)) ? L"已复制可见结果。" : L"复制可见结果失败。";
        ::InvalidateRect(state->hwnd, nullptr, TRUE);
        break;
    case kWindowMenuFront:
        runAction(state, kFrontButtonId);
        break;
    case kWindowMenuRestore:
        runAction(state, kRestoreButtonId);
        break;
    case kWindowMenuMinimize:
        runAction(state, kMinimizeButtonId);
        break;
    case kWindowMenuMaximize:
        runAction(state, kMaximizeButtonId);
        break;
    case kWindowMenuClose:
        runAction(state, kCloseButtonId);
        break;
    case kWindowMenuAllowCapture:
        setCaptureProtection(state, WDA_NONE);
        break;
    case kWindowMenuBlockCapture:
        setCaptureProtection(state, WDA_MONITOR);
        break;
    case kWindowMenuExcludeFromCapture:
        setCaptureProtection(state, WDA_EXCLUDEFROMCAPTURE);
        break;
    case kWindowMenuOpenProcess:
        if (state && state->viewMode == WindowViewMode::kWindowList) {
            openSelectedWindowProcess(state);
        } else {
            openSelectedAuditProcess(state);
        }
        break;
    case kWindowMenuOpenImageDirectory:
        openSelectedWindowImageDirectory(state);
        break;
    default:
        break;
    }
}

// layoutView positions toolbar, list, and detail panes. Input is state; no value
// is returned after MoveWindow calls are issued.
void layoutView(WindowViewState* state) {
    if (!state || !state->hwnd) {
        return;
    }
    RECT rc{};
    ::GetClientRect(state->hwnd, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    const int kLeftWidth = (std::max)(1, (kWidth - kGap * 3) * 2 / 3);
    const int kHierarchyLeft = kGap * 2 + kLeftWidth;
    const int kHierarchyWidth = (std::max)(1, kWidth - kHierarchyLeft - kGap);
    int x = kGap;
    ::MoveWindow(state->auditModeCombo, x, kGap, 180, 160, TRUE); x += 186;
    ::MoveWindow(state->sortCombo, x, kGap, 150, 160, TRUE); x += 156;
    ::MoveWindow(state->refreshButton, x, kGap, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->exportButton, x, kGap, 78, 24, TRUE);

    x = kGap;
    const int kActionY = kGap + 28;
    ::MoveWindow(state->frontButton, x, kActionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->restoreButton, x, kActionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->minimizeButton, x, kActionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->maximizeButton, x, kActionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->closeButton, x, kActionY, 78, 24, TRUE); x += 84;
    ::MoveWindow(state->filterBar, kGap, kGap * 3 + 48, kLeftWidth, 24, TRUE);

    const int kDetailHeightValue = kHeight > 480 ? kDetailHeight : kHeight / 3;
    const int kListTop = kHeaderHeight + kGap;
    const int kListHeight = (std::max)(0, kHeight - kListTop - kDetailHeightValue - (kGap * 2));
    ::MoveWindow(state->windowList, kGap, kListTop, kLeftWidth, kListHeight, TRUE);
    ::MoveWindow(state->detailList, kGap, kListTop + kListHeight + kGap, kLeftWidth, kDetailHeightValue, TRUE);
    ::MoveWindow(state->loadingOverlay, kGap, kListTop, kLeftWidth, kListHeight, TRUE);
    if (state->hierarchyReportView) {
        ::MoveWindow(state->hierarchyReportView, kHierarchyLeft, kGap, kHierarchyWidth,
            (std::max)(1, kHeight - kGap * 2), TRUE);
    }
}

// createChildControls creates all native controls for the Window page. Inputs are
// state and parent HWND; output is true when every required HWND was created.
bool createChildControls(WindowViewState* state, HWND hwnd) {
    state->auditModeCombo = ::CreateWindowExW(0,
        L"COMBOBOX",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0,
        0,
        180,
        160,
        hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kAuditModeComboId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    state->sortCombo = ::CreateWindowExW(0,
        L"COMBOBOX",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST,
        0,
        0,
        150,
        160,
        hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kSortComboId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    state->refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"Refresh", 0, 0, 78, 24);
    state->exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 78, 24);
    state->frontButton = ksword::ui::createButton(hwnd, kFrontButtonId, L"Front", 0, 0, 78, 24);
    state->restoreButton = ksword::ui::createButton(hwnd, kRestoreButtonId, L"Restore", 0, 0, 78, 24);
    state->minimizeButton = ksword::ui::createButton(hwnd, kMinimizeButtonId, L"Minimize", 0, 0, 78, 24);
    state->maximizeButton = ksword::ui::createButton(hwnd, kMaximizeButtonId, L"Maximize", 0, 0, 78, 24);
    state->closeButton = ksword::ui::createButton(hwnd, kCloseButtonId, L"Close", 0, 0, 78, 24);
    state->filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId, L"筛选窗口、HWND、标题、类、状态和审计详情", 0, 0, 0, 0);
    if (!state->virtualList.create(hwnd, kWindowListId, 0, 0, 100, 100, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state->windowList = state->virtualList.hwnd();
    state->detailList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL,
        0, 0, 100, 100, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kDetailListId)), ::GetModuleHandleW(nullptr), nullptr);
    state->hierarchyReportView = window_tools::createWindowHierarchyReportView(hwnd, { 0, 0, 1, 1 });
    if (!state->auditModeCombo || !state->sortCombo || !state->refreshButton || !state->exportButton || !state->frontButton || !state->restoreButton || !state->minimizeButton || !state->filterBar ||
        !state->maximizeButton || !state->closeButton || !state->windowList || !state->detailList || !state->hierarchyReportView) {
        return false;
    }

    ::SendMessageW(state->auditModeCombo, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"窗口列表"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Win32K GUI 审计"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Win32K 消息 Hook 审计"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Win32K 定时器审计"));
    ::SendMessageW(state->auditModeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"GPU/Display 审计"));
    ::SendMessageW(state->auditModeCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state->sortCombo, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ::SendMessageW(state->sortCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"按堆叠顺序"));
    ::SendMessageW(state->sortCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"按进程顺序"));
    ::SendMessageW(state->sortCombo, CB_SETCURSEL, 0, 0);
    ::SendMessageW(state->windowList, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ::SendMessageW(state->detailList, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ListView_SetExtendedListViewStyle(state->windowList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    ListView_SetExtendedListViewStyle(state->detailList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    state->processImageList = ImageList_Create(::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        64,
        64);
    if (state->processImageList != nullptr) {
        ListView_SetImageList(state->windowList, state->processImageList, LVSIL_SMALL);
    }
    state->virtualList.addColumns({
        { 0, 190, LVCFMT_LEFT, L"进程 / PID" },
        { 1, 120, LVCFMT_LEFT, L"HWND" },
        { 2, 300, LVCFMT_LEFT, L"Title" },
        { 3, 190, LVCFMT_LEFT, L"Class" },
        { 4, 220, LVCFMT_LEFT, L"State" },
    });
    addColumn(state->detailList, 0, L"Property", 170);
    addColumn(state->detailList, 1, L"Value", 720);
    state->loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<WindowRefreshSnapshot>>(hwnd, kMsgWindowRefreshCompleted);
    state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<WindowFilterResult>>(hwnd, kMsgWindowFilterCompleted);
    state->detailTask = std::make_unique<ksword::ui::AsyncSnapshotTask<WindowDetailSnapshot>>(hwnd, kMsgWindowDetailCompleted);
    return true;
}

// registerWindowViewClass registers the custom Window feature page. There is no
// input beyond process module state; output is true when CreateWindowExW can use
// the class.
bool registerWindowViewClass() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        WindowViewState* state = reinterpret_cast<WindowViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg) {
        case WM_NCCREATE: {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<WindowViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
            return TRUE;
        }
        case WM_CREATE:
            if (state && createChildControls(state, hwnd)) {
                layoutView(state);
                refreshWindows(state);
            }
            return 0;
        case WM_SIZE:
            layoutView(state);
            return 0;
        case WM_COMMAND: {
            const int kId = LOWORD(wParam);
            if (kId == kRefreshButtonId) {
                refreshWindows(state);
                return 0;
            }
            if (kId == kExportButtonId) {
                exportVisibleRows(state);
                return 0;
            }
            if (kId == kAuditModeComboId && HIWORD(wParam) == CBN_SELCHANGE) {
                updateViewModeFromCombo(state);
                return 0;
            }
            if (kId == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                requestWindowFilter(state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            if (kId == kSortComboId && HIWORD(wParam) == CBN_SELCHANGE) {
                updateSortModeFromCombo(state);
                return 0;
            }
            if (kId == kFrontButtonId || kId == kRestoreButtonId || kId == kMinimizeButtonId ||
                kId == kMaximizeButtonId || kId == kCloseButtonId) {
                runAction(state, kId);
                return 0;
            }
            break;
        }
        case kMsgWindowRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgWindowFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgWindowDetailCompleted:
            if (state && state->detailTask && state->detailTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgExternalQuery:
            if (state && state->filterBar && lParam != 0) {
                const auto* query = reinterpret_cast<const std::wstring*>(lParam);
                ksword::ui::setFilterBarText(state->filterBar, *query, false);
                requestWindowFilter(state, *query);
                ksword::ui::focusFilterBar(state->filterBar);
                return 1;
            }
            return 0;
        case WM_NOTIFY: {
            auto* notify = reinterpret_cast<NMHDR*>(lParam);
            if (state && notify && notify->idFrom == kWindowListId) {
                LRESULT result = 0;
                if (state->virtualList.handleNotify(*notify, result)) {
                    return result;
                }
            }
            if (state && notify && notify->idFrom == kWindowListId && notify->code == LVN_ITEMCHANGED) {
                auto* changed = reinterpret_cast<NMLISTVIEW*>(lParam);
                if ((changed->uNewState & LVIS_SELECTED) != 0) {
                    if (state->viewMode == WindowViewMode::kWindowList) {
                        showDetail(state, selectedModelIndex(state));
                    } else {
                        showAuditDetail(state, selectedModelIndex(state));
                    }
                }
                return 0;
            }
            if (state && notify && notify->idFrom == kWindowListId && notify->code == NM_RCLICK) {
                POINT point{};
                ::GetCursorPos(&point);
                showWindowContextMenu(state, point);
                return 0;
            }
            break;
        }
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->windowList) {
                POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (point.x == -1 && point.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->windowList, &rc);
                    point = { rc.left + 20, rc.top + 20 };
                }
                showWindowContextMenu(state, point);
                return 0;
            }
            if (state && reinterpret_cast<HWND>(wParam) == state->detailList) {
                POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (point.x == -1 && point.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->detailList, &rc);
                    point = { rc.left + 20, rc.top + 20 };
                }
                showDetailContextMenu(state, point);
                return 0;
            }
            break;
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, ksword::ui::appTheme().panelBrush());
            const int kLeftWidth = (std::max)(1, (width(rc) - kGap * 3) * 2 / 3);
            RECT textRc{ 510, 7, kGap + kLeftWidth, kHeaderHeight };
            const std::wstring kTitle = state ? state->statusText : L"Windows";
            ksword::ui::drawTextLine(dc, kTitle, textRc, ksword::ui::appTheme().mutedTextColor,
                ksword::ui::systemUiFont(), DT_SINGLELINE | DT_LEFT | DT_VCENTER);
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_DESTROY:
            if (state) {
                if (state->refreshTask) {
                    state->refreshTask->cancel();
                }
                if (state->filterTask) {
                    state->filterTask->cancel();
                }
                if (state->detailTask) {
                    state->detailTask->cancel();
                }
            }
            if (state && state->processImageList != nullptr) {
                ImageList_Destroy(state->processImageList);
                state->processImageList = nullptr;
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().panelBrush();
    wc.lpszClassName = kWindowViewClass;
    if (::RegisterClassW(&wc)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

} // namespace

HWND createWindowFeatureView(HWND parent, const RECT& bounds) {
    if (!parent || !registerWindowViewClass()) {
        return nullptr;
    }
    auto* state = new WindowViewState();
    HWND hwnd = ::CreateWindowExW(0, kWindowViewClass, L"Windows",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left, bounds.top, width(bounds), height(bounds), parent, nullptr, ::GetModuleHandleW(nullptr), state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

bool requestWindowFeatureViewQuery(HWND page, const std::wstring& query) {
    return page && !query.empty() &&
        ::SendMessageW(page, kMsgExternalQuery, 0, reinterpret_cast<LPARAM>(&query)) != 0;
}

} // namespace Ksword::Features::Window

#include "WindowToolsClipboardView.h"

#include "WindowToolsCommon.h"
#include "../../core/EntityRef.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/TextFindSupport.h"
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

constexpr wchar_t kClipboardViewClass[] = L"KswordARKLight.WindowTools.ClipboardView";

constexpr int kRefreshButtonId = 67001;
constexpr int kEmptyButtonId = 67002;
constexpr int kFilterBarId = 67003;
constexpr int kFormatListId = 67004;
constexpr int kDetailListId = 67005;
constexpr int kPreviewEditId = 67006;
constexpr int kExportButtonId = 67007;

constexpr UINT kMenuCopyRow = 67601;
constexpr UINT kMenuCopyVisible = 67602;
constexpr UINT kMenuCopyPreview = 67603;
constexpr UINT kMenuRefresh = 67604;
constexpr UINT kMenuOpenOwnerProcess = 67605;
constexpr UINT kMenuOpenClipboardProcess = 67606;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kBottomHeight = 210;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 5;

// kPreviewCharLimit caps how much text the preview pane holds. A clipboard can
// carry an entire document, and a single-line EDIT control degrades badly past a
// few hundred kilobytes; the truncation is reported in the pane so a short
// preview is never mistaken for short clipboard content.
constexpr std::size_t kPreviewCharLimit = 64 * 1024;

int width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

// PredefinedFormat maps a CF_* constant to its SDK spelling. Registered formats
// are resolved at runtime with GetClipboardFormatNameW instead, which is why
// this table only needs the predefined range.
struct PredefinedFormat final {
    UINT format;
    const wchar_t* name;
};

constexpr PredefinedFormat kPredefinedFormats[] = {
    { CF_TEXT,            L"CF_TEXT" },
    { CF_BITMAP,          L"CF_BITMAP" },
    { CF_METAFILEPICT,    L"CF_METAFILEPICT" },
    { CF_SYLK,            L"CF_SYLK" },
    { CF_DIF,             L"CF_DIF" },
    { CF_TIFF,            L"CF_TIFF" },
    { CF_OEMTEXT,         L"CF_OEMTEXT" },
    { CF_DIB,             L"CF_DIB" },
    { CF_PALETTE,         L"CF_PALETTE" },
    { CF_PENDATA,         L"CF_PENDATA" },
    { CF_RIFF,            L"CF_RIFF" },
    { CF_WAVE,            L"CF_WAVE" },
    { CF_UNICODETEXT,     L"CF_UNICODETEXT" },
    { CF_ENHMETAFILE,     L"CF_ENHMETAFILE" },
    { CF_HDROP,           L"CF_HDROP" },
    { CF_LOCALE,          L"CF_LOCALE" },
    { CF_DIBV5,           L"CF_DIBV5" },
    { CF_OWNERDISPLAY,    L"CF_OWNERDISPLAY" },
    { CF_DSPTEXT,         L"CF_DSPTEXT" },
    { CF_DSPBITMAP,       L"CF_DSPBITMAP" },
    { CF_DSPMETAFILEPICT, L"CF_DSPMETAFILEPICT" },
    { CF_DSPENHMETAFILE,  L"CF_DSPENHMETAFILE" },
};

struct ClipboardFormatInfo final {
    UINT format = 0;
    std::wstring name;
    std::wstring category;
    std::wstring sizeText;
    std::wstring note;
    std::wstring preview;
};

struct ClipboardSnapshot final {
    bool opened = false;
    DWORD openError = 0;
    DWORD sequenceNumber = 0;
    int formatCount = 0;
    HWND owner = nullptr;
    HWND openerWindow = nullptr;
    HWND viewerWindow = nullptr;
    DWORD ownerProcessId = 0;
    std::wstring ownerTitle;
    std::wstring ownerClass;
    std::wstring ownerProcess;
    std::vector<ClipboardFormatInfo> formats;
};

struct ClipboardViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND emptyButton = nullptr;
    HWND filterBar = nullptr;
    HWND detailList = nullptr;
    HWND previewEdit = nullptr;
    ksword::ui::VirtualListView formatList;
    ClipboardSnapshot snapshot;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"点击刷新读取当前剪贴板内容。";
};

// ScopedClipboard holds the clipboard open for exactly one operation.
//
// OpenClipboard fails outright while another process holds the clipboard, and in
// practice that hold is the last few milliseconds of someone else's copy. A
// short bounded retry converts the common transient failure into a successful
// read; a longer wait would trade a rare real conflict -- which is worth
// reporting -- for a visible UI stall.
class ScopedClipboard final {
public:
    explicit ScopedClipboard(HWND owner) {
        constexpr int kAttempts = 4;
        for (int attempt = 0; attempt < kAttempts; ++attempt) {
            if (::OpenClipboard(owner)) {
                opened_ = true;
                return;
            }
            lastError_ = ::GetLastError();
            if (attempt + 1 < kAttempts) {
                ::Sleep(12);
            }
        }
    }

    ~ScopedClipboard() {
        if (opened_) {
            ::CloseClipboard();
        }
    }

    ScopedClipboard(const ScopedClipboard&) = delete;
    ScopedClipboard& operator=(const ScopedClipboard&) = delete;

    bool opened() const noexcept { return opened_; }
    DWORD lastError() const noexcept { return lastError_; }

private:
    bool opened_ = false;
    DWORD lastError_ = 0;
};

std::wstring predefinedFormatName(const UINT format) {
    for (const PredefinedFormat& entry : kPredefinedFormats) {
        if (entry.format == format) {
            return entry.name;
        }
    }
    return {};
}

std::wstring formatCategory(const UINT format) {
    if (format >= CF_PRIVATEFIRST && format <= CF_PRIVATELAST) {
        return L"私有格式";
    }
    if (format >= CF_GDIOBJFIRST && format <= CF_GDIOBJLAST) {
        return L"GDI 对象";
    }
    if (format >= 0xC000) {
        return L"注册格式";
    }
    return L"预定义";
}

// isHandleBackedFormat reports whether the clipboard handle is a GDI or display
// handle rather than movable memory. GlobalSize on such a handle returns a
// meaningless value, so those rows report the kind of object instead of a size.
bool isHandleBackedFormat(const UINT format) {
    switch (format) {
    case CF_BITMAP:
    case CF_DSPBITMAP:
    case CF_PALETTE:
    case CF_ENHMETAFILE:
    case CF_DSPENHMETAFILE:
    case CF_OWNERDISPLAY:
        return true;
    default:
        return format >= CF_GDIOBJFIRST && format <= CF_GDIOBJLAST;
    }
}

std::wstring resolveFormatName(const UINT format) {
    const std::wstring kPredefined = predefinedFormatName(format);
    if (!kPredefined.empty()) {
        return kPredefined;
    }
    wchar_t buffer[256]{};
    const int kCopied = ::GetClipboardFormatNameW(format, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])));
    if (kCopied > 0) {
        return std::wstring(buffer, buffer + kCopied);
    }
    return L"(无名称)";
}

std::wstring byteSizeText(const SIZE_T bytes) {
    std::wstring text = std::to_wstring(static_cast<std::uint64_t>(bytes)) + L" 字节";
    if (bytes >= 1024) {
        text += L"（约 " + std::to_wstring(static_cast<std::uint64_t>(bytes / 1024)) + L" KB）";
    }
    return text;
}

// readUnicodePreview copies CF_UNICODETEXT out of the clipboard. The clipboard
// must already be open and stays owned by the system: the returned handle is
// never freed here, and the text is copied before CloseClipboard because the
// handle is invalid the moment the clipboard closes.
std::wstring readUnicodePreview(bool& truncated) {
    truncated = false;
    HANDLE handle = ::GetClipboardData(CF_UNICODETEXT);
    if (!handle) {
        return {};
    }
    const auto* source = static_cast<const wchar_t*>(::GlobalLock(handle));
    if (!source) {
        return {};
    }
    const SIZE_T kBytes = ::GlobalSize(handle);
    const std::size_t kMaxChars = kBytes / sizeof(wchar_t);
    std::size_t length = 0;
    while (length < kMaxChars && source[length] != L'\0') {
        ++length;
    }
    if (length > kPreviewCharLimit) {
        length = kPreviewCharLimit;
        truncated = true;
    }
    std::wstring text(source, source + length);
    ::GlobalUnlock(handle);
    return text;
}

// readAnsiPreview copies CF_TEXT and widens it with the process ANSI code page.
// CF_TEXT carries no encoding of its own; CF_LOCALE can name one but almost
// nothing sets it, so CP_ACP is the code page the writer effectively used.
std::wstring readAnsiPreview(bool& truncated) {
    truncated = false;
    HANDLE handle = ::GetClipboardData(CF_TEXT);
    if (!handle) {
        return {};
    }
    const auto* source = static_cast<const char*>(::GlobalLock(handle));
    if (!source) {
        return {};
    }
    const SIZE_T kBytes = ::GlobalSize(handle);
    std::size_t length = 0;
    while (length < kBytes && source[length] != '\0') {
        ++length;
    }
    if (length > kPreviewCharLimit) {
        length = kPreviewCharLimit;
        truncated = true;
    }
    std::wstring text;
    if (length > 0) {
        const int kRequired = ::MultiByteToWideChar(CP_ACP, 0, source, static_cast<int>(length), nullptr, 0);
        if (kRequired > 0) {
            text.resize(static_cast<std::size_t>(kRequired));
            ::MultiByteToWideChar(CP_ACP, 0, source, static_cast<int>(length), text.data(), kRequired);
        }
    }
    ::GlobalUnlock(handle);
    return text;
}

// captureClipboardSnapshot reads the whole clipboard in one open/close pair.
//
// GetClipboardOwner, GetOpenClipboardWindow and GetClipboardSequenceNumber do
// not need the clipboard open, so they are read first and stay meaningful even
// when the open below fails -- that is exactly the case where the user wants to
// know who is holding it.
ClipboardSnapshot captureClipboardSnapshot(HWND owner) {
    ClipboardSnapshot snapshot;
    snapshot.sequenceNumber = ::GetClipboardSequenceNumber();
    snapshot.owner = ::GetClipboardOwner();
    snapshot.openerWindow = ::GetOpenClipboardWindow();
    snapshot.viewerWindow = ::GetClipboardViewer();
    snapshot.formatCount = ::CountClipboardFormats();
    if (snapshot.owner) {
        snapshot.ownerTitle = windowTitleText(snapshot.owner);
        snapshot.ownerClass = windowClassText(snapshot.owner);
        ::GetWindowThreadProcessId(snapshot.owner, &snapshot.ownerProcessId);
        snapshot.ownerProcess = processNameFromId(snapshot.ownerProcessId);
    }

    ScopedClipboard clipboard(owner);
    if (!clipboard.opened()) {
        snapshot.openError = clipboard.lastError();
        return snapshot;
    }
    snapshot.opened = true;

    for (UINT format = ::EnumClipboardFormats(0); format != 0; format = ::EnumClipboardFormats(format)) {
        ClipboardFormatInfo info;
        info.format = format;
        info.name = resolveFormatName(format);
        info.category = formatCategory(format);

        if (isHandleBackedFormat(format)) {
            info.sizeText = L"—";
            info.note = L"GDI / 显示句柄，非内存对象，无法用 GlobalSize 度量";
        } else {
            // GetClipboardData is what forces a delayed-rendered format to be
            // produced: the owner receives WM_RENDERFORMAT and renders it
            // synchronously. That is the price of reporting a real size, and it
            // means a hung clipboard owner can stall this read.
            HANDLE handle = ::GetClipboardData(format);
            if (handle) {
                info.sizeText = byteSizeText(::GlobalSize(handle));
            } else {
                info.sizeText = L"—";
                info.note = L"GetClipboardData 返回空，通常是延迟渲染失败或所有者已退出";
            }
        }

        if (format == CF_UNICODETEXT || format == CF_TEXT) {
            bool truncated = false;
            info.preview = format == CF_UNICODETEXT ? readUnicodePreview(truncated) : readAnsiPreview(truncated);
            if (truncated) {
                info.preview += L"\r\n\r\n[预览已截断，仅显示前 " + std::to_wstring(kPreviewCharLimit) + L" 个字符]";
            }
            if (info.note.empty()) {
                info.note = L"可在下方预览文本内容";
            }
        }
        if (info.note.empty()) {
            info.note = L"二进制内容，本页不做解码";
        }
        snapshot.formats.push_back(std::move(info));
    }
    return snapshot;
}

// currentClipboardOwnerProcessId intentionally reads the owner HWND again at
// click time. The snapshot is useful evidence, but its HWND and PID can both be
// stale by the time the user opens process details.
DWORD currentClipboardOwnerProcessId() {
    const HWND kOwner = ::GetClipboardOwner();
    if (!kOwner || !::IsWindow(kOwner)) {
        return 0;
    }
    DWORD processId = 0;
    if (::GetWindowThreadProcessId(kOwner, &processId) == 0U || processId == 0U) {
        return 0;
    }
    return ::GetClipboardOwner() == kOwner ? processId : 0U;
}

// currentClipboardOpenProcessId follows the same live-read rule for the window
// currently holding OpenClipboard. That window is often the direct explanation
// for an unavailable snapshot, so it must not be confused with the data owner.
DWORD currentClipboardOpenProcessId() {
    const HWND kOpener = ::GetOpenClipboardWindow();
    if (!kOpener || !::IsWindow(kOpener)) {
        return 0;
    }
    DWORD processId = 0;
    if (::GetWindowThreadProcessId(kOpener, &processId) == 0U || processId == 0U) {
        return 0;
    }
    return ::GetOpenClipboardWindow() == kOpener ? processId : 0U;
}

void setDetailText(HWND list, const int row, const int column, const std::wstring& text) {
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

void showOwnerDetail(ClipboardViewState& state) {
    if (!state.detailList) {
        return;
    }
    ListView_DeleteAllItems(state.detailList);
    const ClipboardSnapshot& snapshot = state.snapshot;

    std::vector<std::pair<std::wstring, std::wstring>> properties;
    properties.emplace_back(L"剪贴板序列号", std::to_wstring(snapshot.sequenceNumber));
    properties.emplace_back(L"格式数量", std::to_wstring(snapshot.formatCount));
    properties.emplace_back(L"占有者窗口", snapshot.owner ? hwndText(snapshot.owner) : L"(无，数据来源进程可能已退出)");
    if (snapshot.owner) {
        properties.emplace_back(L"占有者标题", snapshot.ownerTitle.empty() ? L"(无标题)" : snapshot.ownerTitle);
        properties.emplace_back(L"占有者类名", snapshot.ownerClass);
        properties.emplace_back(L"占有者进程", snapshot.ownerProcess + L"（PID " + std::to_wstring(snapshot.ownerProcessId) + L"）");
    }
    properties.emplace_back(L"当前打开剪贴板的窗口",
        snapshot.openerWindow ? describeWindowBrief(snapshot.openerWindow) : L"(无)");
    properties.emplace_back(L"剪贴板查看器链首",
        snapshot.viewerWindow ? describeWindowBrief(snapshot.viewerWindow) : L"(无)");
    properties.emplace_back(L"本次读取", snapshot.opened
        ? std::wstring(L"成功")
        : L"失败（OpenClipboard 错误码 " + std::to_wstring(snapshot.openError) + L"）");

    for (int row = 0; row < static_cast<int>(properties.size()); ++row) {
        setDetailText(state.detailList, row, 0, properties[static_cast<std::size_t>(row)].first);
        setDetailText(state.detailList, row, 1, properties[static_cast<std::size_t>(row)].second);
    }
}

int selectedModelIndex(const ClipboardViewState& state) {
    const HWND kList = state.formatList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.formatList.visibleIndexes();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kModelIndex = visible[static_cast<std::size_t>(kSelected)];
    return kModelIndex < state.snapshot.formats.size() ? static_cast<int>(kModelIndex) : -1;
}

void showPreviewForSelection(ClipboardViewState& state) {
    if (!state.previewEdit) {
        return;
    }
    const int kIndex = selectedModelIndex(state);
    if (kIndex < 0) {
        ::SetWindowTextW(state.previewEdit, L"在上方选择一个剪贴板格式。\r\n仅 CF_UNICODETEXT 与 CF_TEXT 可以显示文本预览。");
        return;
    }
    const ClipboardFormatInfo& info = state.snapshot.formats[static_cast<std::size_t>(kIndex)];
    if (!info.preview.empty()) {
        ::SetWindowTextW(state.previewEdit, info.preview.c_str());
        return;
    }
    const std::wstring kText = info.name + L"（" + hexText(info.format, 4) + L"）\r\n" +
        L"类别：" + info.category + L"\r\n" +
        L"数据大小：" + info.sizeText + L"\r\n" +
        L"说明：" + info.note;
    ::SetWindowTextW(state.previewEdit, kText.c_str());
}

// selectRowAtPoint makes row-scoped context commands operate on the row the
// user actually right-clicked, never on a stale selection left by filtering or
// keyboard navigation. A click on empty space deliberately leaves no row
// selected while keeping page-scoped actions available.
void selectRowAtPoint(ClipboardViewState& state, const POINT screenPoint) {
    const HWND kList = state.formatList.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kClickedItem = ListView_SubItemHitTest(kList, &hit);
    ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    const auto& visible = state.formatList.visibleIndexes();
    if (kClickedItem >= 0 && static_cast<std::size_t>(kClickedItem) < visible.size()) {
        ListView_SetItemState(kList, kClickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    showPreviewForSelection(state);
}

// applyFilter runs on the UI thread on purpose. The row count here is the number
// of formats on the clipboard -- a few dozen at the very most -- so posting the
// work to a background task would cost more than the scan it replaces.
void applyFilter(ClipboardViewState& state) {
    if (!state.filterRows || !state.formatList.hwnd()) {
        return;
    }
    const std::wstring kQuery = state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : std::wstring{};
    const bool kUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    state.formatList.setVisibleIndexes(
        ksword::ui::VirtualListView::filterRowIndexes(*state.filterRows, kQuery, kUseRegex));

    HWND list = state.formatList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (!state.formatList.visibleIndexes().empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    showPreviewForSelection(state);
}

void buildRows(ClipboardViewState& state) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(state.snapshot.formats.size());
    for (std::size_t index = 0; index < state.snapshot.formats.size(); ++index) {
        const ClipboardFormatInfo& info = state.snapshot.formats[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(info.format);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(hexText(info.format, 4) + L" (" + std::to_wstring(info.format) + L")");
        row.cells.push_back(info.name);
        row.cells.push_back(info.category);
        row.cells.push_back(info.sizeText);
        row.cells.push_back(info.note);
        rows.push_back(std::move(row));
    }
    auto shared = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(rows));
    state.formatList.setRows(*shared);
    state.filterRows = std::move(shared);
}

void refreshClipboard(ClipboardViewState& state) {
    state.snapshot = captureClipboardSnapshot(state.hwnd);
    buildRows(state);
    showOwnerDetail(state);
    applyFilter(state);
    if (!state.snapshot.opened) {
        state.statusText = L"无法打开剪贴板（错误码 " + std::to_wstring(state.snapshot.openError) +
            L"）。通常是其他程序正持有剪贴板，请稍后重试。";
    } else {
        state.statusText = L"共 " + std::to_wstring(state.snapshot.formats.size()) + L" 种格式，序列号 " +
            std::to_wstring(state.snapshot.sequenceNumber) + L"。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void exportVisibleRows(ClipboardViewState& state) {
    const std::wstring kText = ksword::ui::buildVisibleVirtualListTsv(
        { L"格式 ID", L"名称", L"类别", L"数据大小", L"说明" }, state.formatList);
    if (kText.empty()) {
        state.statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(state.hwnd, L"clipboard_formats.tsv", L"导出剪贴板格式",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
    case ksword::ui::SaveTextFileResult::kSaved: state.statusText = L"剪贴板可见结果已导出。"; break;
    case ksword::ui::SaveTextFileResult::kCancelled: state.statusText = L"已取消导出剪贴板结果。"; break;
    case ksword::ui::SaveTextFileResult::kFailed: state.statusText = L"导出剪贴板结果失败：" + error; break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// openCurrentClipboardOwnerProcess routes only the live owner PID. The process
// page resolves that PID again, preserving the page's current-instance contract
// without requiring an additional source-side process handle or privilege.
void openCurrentClipboardOwnerProcess(ClipboardViewState& state) {
    const DWORD kProcessId = currentClipboardOwnerProcessId();
    if (kProcessId == 0U) {
        state.statusText = L"当前剪贴板没有可读取的占有者进程。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已请求打开刚读取到的剪贴板占有者 PID " + std::to_wstring(kProcessId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前剪贴板占有者的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// openCurrentClipboardProcess identifies only the window that has the clipboard
// open right now. It does not infer ownership from the last captured snapshot.
void openCurrentClipboardProcess(ClipboardViewState& state) {
    const DWORD kProcessId = currentClipboardOpenProcessId();
    if (kProcessId == 0U) {
        state.statusText = L"当前没有可读取的剪贴板打开者进程。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = kProcessId;
    state.statusText = ksword::ui::requestEntityNavigation(state.hwnd, request)
        ? L"已请求打开刚读取到的剪贴板打开者 PID " + std::to_wstring(kProcessId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前剪贴板打开者的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// emptyClipboardWithConfirm is the only destructive action on this page. The
// default button is No so a stray Enter cannot wipe the clipboard, and the
// prompt names the two consequences that are not obvious: the data cannot be
// recovered, and this window becomes the new clipboard owner afterwards.
void emptyClipboardWithConfirm(ClipboardViewState& state) {
    const wchar_t* text =
        L"将清空系统剪贴板中的全部内容。\n\n"
        L"清空后原有数据无法恢复，正在依赖剪贴板的程序会立即失去可粘贴的数据。\n"
        L"操作完成后本窗口会成为剪贴板的新占有者。\n\n"
        L"是否继续？";
    if (::MessageBoxW(state.hwnd, text, L"清空剪贴板", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) {
        state.statusText = L"已取消清空剪贴板。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    bool emptied = false;
    DWORD error = 0;
    {
        ScopedClipboard clipboard(state.hwnd);
        if (clipboard.opened()) {
            emptied = ::EmptyClipboard() != FALSE;
            error = emptied ? 0 : ::GetLastError();
        } else {
            error = clipboard.lastError();
        }
    }

    refreshClipboard(state);
    state.statusText = emptied
        ? std::wstring(L"剪贴板已清空。")
        : L"清空剪贴板失败（错误码 " + std::to_wstring(error) + L"）。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

std::wstring previewText(const ClipboardViewState& state) {
    const int kLength = state.previewEdit ? ::GetWindowTextLengthW(state.previewEdit) : 0;
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength), L'\0');
    ::GetWindowTextW(state.previewEdit, text.data(), kLength + 1);
    return text;
}

void showContextMenu(ClipboardViewState& state, const POINT screenPoint) {
    selectRowAtPoint(state, screenPoint);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool kHasSelection = selectedModelIndex(state) >= 0;
    const bool kHasCurrentOwnerProcess = currentClipboardOwnerProcessId() != 0U;
    const bool kHasCurrentClipboardProcess = currentClipboardOpenProcessId() != 0U;
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyPreview, L"复制预览内容");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasCurrentOwnerProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenOwnerProcess, L"查看当前剪贴板占有者进程的详细信息");
    ::AppendMenuW(menu, MF_STRING | (kHasCurrentClipboardProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenClipboardProcess, L"查看当前打开剪贴板的进程详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    std::wstring message;
    switch (static_cast<UINT>(kCommand)) {
    case kMenuCopyRow:
        message = copyTextToClipboard(state.hwnd, rowsAsTsv(state.formatList, false, kColumnCount))
            ? L"已复制选中行。" : L"复制失败。";
        break;
    case kMenuCopyVisible:
        message = copyTextToClipboard(state.hwnd, rowsAsTsv(state.formatList, true, kColumnCount))
            ? L"已复制可见行。" : L"复制失败。";
        break;
    case kMenuCopyPreview:
        message = copyTextToClipboard(state.hwnd, previewText(state))
            ? L"已复制预览内容。" : L"复制失败。";
        break;
    case kMenuOpenOwnerProcess:
        openCurrentClipboardOwnerProcess(state);
        return;
    case kMenuOpenClipboardProcess:
        openCurrentClipboardProcess(state);
        return;
    case kMenuRefresh:
        refreshClipboard(state);
        return;
    default:
        return;
    }

    // Copying writes to the clipboard this page inspects, so the table on screen
    // is stale the instant the copy succeeds. The refresh runs first and the
    // copy result is written afterwards, otherwise the refresh status would
    // overwrite the message the user actually asked for.
    refreshClipboard(state);
    state.statusText = std::move(message);
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void layoutView(ClipboardViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kWidth = width(client);
    const int kHeight = height(client);

    int cursorX = kGap;
    const auto kPlace = [&cursorX](HWND control, const int controlWidth) {
        if (control) {
            ::MoveWindow(control, cursorX, kGap, controlWidth, kRowHeight, TRUE);
        }
        cursorX += controlWidth + kGap;
    };
    kPlace(state.refreshButton, 64);
    kPlace(state.exportButton, 78);
    kPlace(state.emptyButton, 110);

    const int kSecondRowY = kGap * 2 + kRowHeight;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, kSecondRowY, (std::max)(120, kWidth - kGap * 2), kRowHeight, TRUE);
    }

    const int kListTop = kHeaderHeight;
    const int kBottomTop = (std::max)(kListTop, kHeight - kStatusHeight - kBottomHeight);
    const int kListHeight = (std::max)(0, kBottomTop - kListTop - kGap);
    if (HWND list = state.formatList.hwnd()) {
        ::MoveWindow(list, kGap, kListTop, (std::max)(0, kWidth - kGap * 2), kListHeight, TRUE);
    }

    const int kBottomHeightValue = (std::max)(0, kHeight - kStatusHeight - kBottomTop - kGap);
    const int kDetailWidth = (std::max)(120, (kWidth - kGap * 3) / 2);
    if (state.detailList) {
        ::MoveWindow(state.detailList, kGap, kBottomTop, kDetailWidth, kBottomHeightValue, TRUE);
    }
    if (state.previewEdit) {
        const int kPreviewLeft = kGap * 2 + kDetailWidth;
        ::MoveWindow(state.previewEdit, kPreviewLeft, kBottomTop,
            (std::max)(0, kWidth - kPreviewLeft - kGap), kBottomHeightValue, TRUE);
    }
}

bool createChildControls(ClipboardViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = ksword::ui::createButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.emptyButton = ksword::ui::createButton(hwnd, kEmptyButtonId, L"清空剪贴板", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId, L"筛选格式 ID、名称、类别与说明", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.emptyButton || !state.filterBar) {
        return false;
    }

    if (!state.formatList.create(hwnd, kFormatListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.formatList.addColumns({
        { 0, 130, LVCFMT_LEFT, L"格式 ID" },
        { 1, 220, LVCFMT_LEFT, L"名称" },
        { 2, 90,  LVCFMT_LEFT, L"类别" },
        { 3, 150, LVCFMT_LEFT, L"数据大小" },
        { 4, 380, LVCFMT_LEFT, L"说明" },
    });
    if (HWND list = state.formatList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.detailList = ksword::ui::createReportListView(hwnd, kDetailListId, 0, 0, 1, 1, LVS_SINGLESEL);
    if (!state.detailList) {
        return false;
    }
    ksword::ui::addListViewColumns(state.detailList, {
        { 0, 170, LVCFMT_LEFT, L"属性" },
        { 1, 420, LVCFMT_LEFT, L"值" },
    });
    ListView_SetExtendedListViewStyle(state.detailList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    state.previewEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 1, 1, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPreviewEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.previewEdit) {
        return false;
    }
    ksword::ui::attachTextFindSupport(state.previewEdit);

    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK clipboardViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<ClipboardViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<ClipboardViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!createChildControls(*state)) {
                return -1;
            }
            layoutView(*state);
            refreshClipboard(*state);
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
                applyFilter(*state);
                return 0;
            }
            if (kNotification == BN_CLICKED) {
                if (kId == kRefreshButtonId) {
                    refreshClipboard(*state);
                    return 0;
                }
                if (kId == kExportButtonId) {
                    exportVisibleRows(*state);
                    return 0;
                }
                if (kId == kEmptyButtonId) {
                    emptyClipboardWithConfirm(*state);
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
                if (state->formatList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->formatList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        showPreviewForSelection(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->formatList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    showContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_CTLCOLORSTATIC: {
        // A read-only EDIT reports itself through WM_CTLCOLORSTATIC. It gets the
        // panel color rather than the window color so a long preview reads as a
        // content pane instead of dissolving into the page background.
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        if (state && reinterpret_cast<HWND>(lParam) == state->previewEdit) {
            ::SetBkColor(dc, ksword::ui::appTheme().panelColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().panelBrush());
        }
        ::SetBkMode(dc, TRANSPARENT);
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
    case WM_NCDESTROY:
        if (state) {
            state->formatList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool ensureClipboardViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = clipboardViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
    windowClass.lpszClassName = kClipboardViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createClipboardInspectorView(HWND parent, const RECT& bounds) {
    if (!parent || !ensureClipboardViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kClipboardViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::window_tools

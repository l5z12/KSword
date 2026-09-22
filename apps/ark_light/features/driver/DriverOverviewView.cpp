#include "DriverOverviewView.h"

#include "DriverActions.h"
#include "../../core/EntityRef.h"
#include "../file/PathNavigator.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <cwchar>
#include <memory>
#include <string>
#include <vector>

namespace ksword::features::driver {
namespace {

constexpr wchar_t kDriverOverviewClass[] = L"KswordARKLight.DriverOverviewView";
constexpr int kOverviewListId = 64001;
constexpr int kOverviewFilterId = 64002;
constexpr int kOverviewLoadingOverlayId = 64003;
constexpr UINT kOverviewMenuDetail = 64101;
constexpr UINT kOverviewMenuCopyCell = 64102;
constexpr UINT kOverviewMenuCopyRow = 64103;
constexpr UINT kOverviewMenuCopyName = 64104;
constexpr UINT kOverviewMenuCopyPath = 64105;
constexpr UINT kOverviewMenuCopyVisible = 64106;
constexpr UINT kOverviewMenuOpenDirectory = 64107;
constexpr UINT kMsgOverviewFilterCompleted = WM_APP + 596;
constexpr UINT kMsgOverviewDetailCompleted = WM_APP + 597;
constexpr wchar_t kOverviewDetailClass[] = L"KswordARKLight.DriverOverviewDetailDialog";
constexpr int kOverviewDetailEditId = 64121;
constexpr int kOverviewDetailCopyId = 64122;
constexpr int kOverviewDetailCloseId = 64123;

// DriverOverviewViewState owns the list control and the attached model pointer.
// Inputs arrive through Win32 messages; processing only reads the model and
// renders it into the child list; no ownership of the model is transferred.
struct DriverOverviewViewState {
    HWND hwnd = nullptr;
    HWND filterBar = nullptr;
    HWND listView = nullptr;
    HWND loadingOverlay = nullptr;
    DriverModel* model = nullptr;
    std::vector<DriverOverviewRow> snapshotRows;
    std::vector<DriverOverviewRow> visibleRows;
    ksword::ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    std::uint64_t detailRequestId = 0;
    int contextColumn = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<struct OverviewFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<struct OverviewDetailResult>> detailTask;
};

struct OverviewFilterResult {
    std::uint64_t snapshotGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct OverviewDetailResult {
    std::uint64_t requestId = 0;
    std::wstring text;
};

// DetailDialogState owns one modeless detail window. Input is the generated
// detail text; processing creates an EDIT plus Copy/Close buttons; no driver
// state is modified by this helper.
struct DetailDialogState {
    HWND hwnd = nullptr;
    HWND edit = nullptr;
    HWND copyButton = nullptr;
    HWND closeButton = nullptr;
    HWND owner = nullptr;
    std::wstring title;
    std::wstring text;
};

// stateFromWindow returns the view state previously stored on the HWND. Input
// is the child window; processing reads GWLP_USERDATA; output is null before
// WM_NCCREATE or after WM_NCDESTROY clears the pointer.
DriverOverviewViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverOverviewViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// setChildFont applies the system UI font to one child window. Input is a child
// HWND; processing sends WM_SETFONT; no return value is needed.
void setChildFont(HWND hwnd) {
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
}

// guessDriverObjectName builds the conventional \Driver\Name fallback from an
// overview row. Input is a kernel module row; processing strips common .sys/.exe
// suffixes and keeps existing object-manager names; output may be empty.
std::wstring guessDriverObjectName(const DriverOverviewRow& row) {
    std::wstring name = row.driverName;
    if (name.empty()) {
        name = row.pathText;
        const std::size_t kSlash = name.find_last_of(L"\\/");
        if (kSlash != std::wstring::npos && kSlash + 1 < name.size()) {
            name = name.substr(kSlash + 1);
        }
    }
    if (name.empty()) {
        return {};
    }
    if (name.rfind(L"\\Driver\\", 0) == 0) {
        return name;
    }
    const std::size_t kDot = name.find_last_of(L'.');
    if (kDot != std::wstring::npos) {
        name.resize(kDot);
    }
    return name.empty() ? std::wstring{} : (L"\\Driver\\" + name);
}

// selectedOverviewRow copies the selected overview model row. Input is the view
// state and output pointer; processing maps the selected list index to the
// current model snapshot; output is true when a row is available.
bool selectedOverviewRow(const DriverOverviewViewState& state, DriverOverviewRow* rowOut) {
    if (!state.listView || !state.model) {
        return false;
    }
    const int kSelected = ListView_GetNextItem(state.listView, -1, LVNI_SELECTED);
    if (kSelected < 0 || kSelected >= static_cast<int>(state.visibleRows.size())) {
        return false;
    }
    if (rowOut) {
        *rowOut = state.visibleRows[static_cast<std::size_t>(kSelected)];
    }
    return true;
}

// copyOverviewText writes selected driver text to the clipboard. Inputs are view
// state and payload; processing delegates clipboard ownership to DriverActions;
// no value is returned because callers retain the non-blocking page state.
void copyOverviewText(const DriverOverviewViewState& state, const std::wstring& text, const wchar_t* title) {
    (void)title;
    DriverActions::copyTextToClipboard(state.hwnd, text);
}

// buildOverviewRowText serializes one overview row. Input is the selected model
// row; output is a TSV-compatible row used by the right-click copy command.
std::wstring buildOverviewRowText(const DriverOverviewRow& row) {
    return row.driverName + L"\t" +
        row.baseAddressText + L"\t" +
        row.memoryRangeText + L"\t" +
        row.sizeText + L"\t" +
        row.pathText + L"\t" +
        row.signatureText + L"\t" +
        row.statusText + L"\t" +
        row.anomalyText + L"\t" +
        row.capabilityHint;
}

// overviewCells builds the immutable display cells for a snapshot row. It is
// used by both owner-data rendering and clipboard export, so filtering matches
// exactly the text visible to the user.
std::vector<std::wstring> overviewCells(const DriverOverviewRow& row) {
    return {
        row.driverName,
        row.baseAddressText,
        row.memoryRangeText,
        row.sizeText,
        row.pathText,
        row.signatureText,
        row.statusText,
        row.anomalyText,
        row.capabilityHint
    };
}

// overviewStableKey provides selection restoration across a background filter
// or refresh. The path prevents duplicate module display names from colliding.
std::wstring overviewStableKey(const DriverOverviewRow& row) {
    return row.driverName + L"\n" + row.pathText + L"\n" + row.baseAddressText;
}

std::vector<ksword::ui::VirtualListRow> buildOverviewVirtualRows(const std::vector<DriverOverviewRow>& rows) {
    std::vector<ksword::ui::VirtualListRow> displayRows;
    displayRows.reserve(rows.size());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        ksword::ui::VirtualListRow display{};
        display.stableKey = overviewStableKey(rows[index]);
        display.cells = overviewCells(rows[index]);
        display.itemData = static_cast<LPARAM>(index);
        displayRows.push_back(std::move(display));
    }
    return displayRows;
}

std::wstring stableKeyAt(const DriverOverviewViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return overviewStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void restoreListPosition(DriverOverviewViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring kKey = overviewStableKey(state.visibleRows[index]);
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

// registerDetailDialogClass installs the modeless detail window class. There
// is no input; processing is idempotent; output is true when CreateWindowExW
// can use the class name.
bool registerDetailDialogClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DetailDialogState* state = reinterpret_cast<DetailDialogState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DetailDialogState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                state->edit = ::CreateWindowExW(
                    WS_EX_CLIENTEDGE,
                    L"EDIT",
                    state->text.c_str(),
                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
                    0,
                    0,
                    0,
                    0,
                    hwnd,
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kOverviewDetailEditId)),
                    ::GetModuleHandleW(nullptr),
                    nullptr);
                ksword::ui::attachTextFindSupport(state->edit);
                state->copyButton = ksword::ui::createButton(hwnd, kOverviewDetailCopyId, L"复制详情", 0, 0, 0, 0);
                state->closeButton = ksword::ui::createButton(hwnd, kOverviewDetailCloseId, L"关闭", 0, 0, 0, 0);
                ksword::ui::setWindowFontRecursive(hwnd);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                RECT rc{};
                ::GetClientRect(hwnd, &rc);
                const int kWidth = rc.right - rc.left;
                const int kHeight = rc.bottom - rc.top;
                const int kMargin = 8;
                const int kButtonHeight = 26;
                ::MoveWindow(state->edit, kMargin, kMargin, std::max(80, kWidth - kMargin * 2), std::max(80, kHeight - kButtonHeight - kMargin * 3), TRUE);
                ::MoveWindow(state->copyButton, kMargin, std::max(kMargin, kHeight - kButtonHeight - kMargin), 96, kButtonHeight, TRUE);
                ::MoveWindow(state->closeButton, kWidth - 88 - kMargin, std::max(kMargin, kHeight - kButtonHeight - kMargin), 88, kButtonHeight, TRUE);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kOverviewDetailCopyId) {
                DriverActions::copyTextToClipboard(hwnd, state->text);
                return 0;
            }
            if (state && LOWORD(wParam) == kOverviewDetailCloseId) {
                ::DestroyWindow(hwnd);
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
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kOverviewDetailClass;
    registered = (::RegisterClassW(&wc) != 0) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

// showDetailWindow opens a scrollable, copyable detail popup. Inputs are owner,
// title and body text; processing creates a modeless top-level window; no value
// is returned.
void showDetailWindow(HWND owner, const std::wstring& title, const std::wstring& text) {
    if (!registerDetailDialogClass()) {
        ::MessageBoxW(owner, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto* state = new DetailDialogState();
    state->owner = owner;
    state->title = title;
    state->text = text;
    HWND hwnd = ::CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        kOverviewDetailClass,
        title.c_str(),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        860,
        620,
        owner,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
        ::MessageBoxW(owner, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
    }
}

// buildOverviewDetailText formats row-local details and, when possible, R0
// DriverObject details. Input is the selected row; output is a rich text body
// for the detail popup.
std::wstring buildOverviewDetailText(const DriverOverviewRow& row) {
    std::wstring detail =
        L"DriverName: " + row.driverName + L"\r\n" +
        L"Base: " + row.baseAddressText + L"\r\n" +
        L"MemoryRange: " + row.memoryRangeText + L"\r\n" +
        L"Size: " + row.sizeText + L"\r\n" +
        L"Path: " + row.pathText + L"\r\n" +
        L"Signature: " + row.signatureText + L"\r\n" +
        L"Status: " + row.statusText + L"\r\n" +
        L"Anomaly: " + row.anomalyText + L"\r\n" +
        L"Hint: " + row.capabilityHint + L"\r\n";

    const std::wstring kDriverObjectName = guessDriverObjectName(row);
    if (!kDriverObjectName.empty()) {
        const DriverActionResult kR0Detail = DriverActions::buildDriverObjectDetailText(kDriverObjectName);
        detail += L"\r\nR0 DriverObject query (" + kDriverObjectName + L"):\r\n";
        detail += kR0Detail.statusText;
    }
    return detail;
}

// showOverviewDetail starts the potentially slow R0 DriverObject query away
// from the UI thread. The overlay makes the wait explicit while the list stays
// usable after the result arrives.
void showOverviewDetail(DriverOverviewViewState& state) {
    DriverOverviewRow row;
    if (!selectedOverviewRow(state, &row) || !state.detailTask) {
        return;
    }
    const std::uint64_t kRequestId = ++state.detailRequestId;
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在后台查询 DriverObject 详情…");
    state.detailTask->request(
        [row, kRequestId] {
            OverviewDetailResult result{};
            result.requestId = kRequestId;
            result.text = buildOverviewDetailText(row);
            return result;
        },
        [&state](std::uint64_t, std::optional<OverviewDetailResult>&& result, std::exception_ptr error) {
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value() || result->requestId != state.detailRequestId) {
                return;
            }
            showDetailWindow(state.hwnd, L"驱动详细信息", result->text);
        });
}

std::wstring driverDirectoryForOverviewRow(const DriverOverviewRow& row) {
    const std::wstring kDirectory =
        ksword::features::file::PathNavigator::parentDirectoryForKnownFilePath(row.pathText);
    // The File browser's ordinary text box expands environment expressions;
    // preserve the snapshot-only boundary by refusing directory names that
    // could be interpreted as an environment-style expression downstream.
    return kDirectory.find(L'%') == std::wstring::npos ? kDirectory : std::wstring{};
}

// openOverviewDriverDirectory routes only a strict DOS/UNC parent directory.
// Kernel, device and prefix aliases remain visible in the row but are never
// guessed into a FileBrowser path.
void openOverviewDriverDirectory(DriverOverviewViewState& state) {
    DriverOverviewRow row;
    if (!selectedOverviewRow(state, &row)) {
        return;
    }
    const std::wstring kDirectory = driverDirectoryForOverviewRow(row);
    if (kDirectory.empty()) {
        return;
    }
    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kFileBrowser;
    request.entity.kind = ksword::core::EntityKind::kFile;
    request.entity.text = kDirectory;
    ksword::ui::requestEntityNavigation(state.hwnd, request);
}

std::wstring buildOverviewTsv(const DriverOverviewViewState& state);

// showOverviewContextMenu displays the overview right-click menu. Inputs are
// the view state and screen coordinate; processing selects the clicked row,
// groups read-only copy/detail actions, and returns no value.
void showOverviewContextMenu(DriverOverviewViewState& state, POINT screenPoint) {
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.listView, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kItem = ListView_HitTest(state.listView, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (kItem >= 0 && static_cast<std::size_t>(kItem) < state.visibleRows.size()) {
        ListView_SetItemState(state.listView, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    DriverOverviewRow selectedRow;
    const bool kHasSelection = selectedOverviewRow(state, &selectedRow);
    const bool kHasNavigableDirectory = kHasSelection && !driverDirectoryForOverviewRow(selectedRow).empty();
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyName, L"复制驱动名称");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kOverviewMenuCopyPath, L"复制驱动路径");
        ::AppendMenuW(copyMenu, MF_STRING | (!state.visibleRows.empty() ? 0U : MF_GRAYED), kOverviewMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    HMENU detailMenu = ::CreatePopupMenu();
    if (detailMenu) {
        ::AppendMenuW(detailMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kOverviewMenuDetail, L"详细信息/R0 DriverObject");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(detailMenu), L"详细信息");
    }
    ::AppendMenuW(menu, MF_STRING | (kHasNavigableDirectory ? 0U : MF_GRAYED),
        kOverviewMenuOpenDirectory, L"打开驱动所在目录");

    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kOverviewMenuDetail) {
        showOverviewDetail(state);
    } else if (kCommand == kOverviewMenuOpenDirectory) {
        openOverviewDriverDirectory(state);
    } else if (kCommand == kOverviewMenuCopyCell ||
        kCommand == kOverviewMenuCopyRow ||
        kCommand == kOverviewMenuCopyName ||
        kCommand == kOverviewMenuCopyPath ||
        kCommand == kOverviewMenuCopyVisible) {
        if (kCommand == kOverviewMenuCopyVisible) {
            copyOverviewText(state, buildOverviewTsv(state), L"复制可见驱动结果");
            return;
        }
        DriverOverviewRow row;
        if (!selectedOverviewRow(state, &row)) {
            return;
        }
        if (kCommand == kOverviewMenuCopyCell) {
            const std::vector<std::wstring> kCells = overviewCells(row);
            const std::size_t kColumn = static_cast<std::size_t>(std::max(0, state.contextColumn));
            copyOverviewText(state, kColumn < kCells.size() ? kCells[kColumn] : std::wstring{}, L"复制单元格");
        } else if (kCommand == kOverviewMenuCopyRow) {
            copyOverviewText(state, buildOverviewRowText(row), L"复制驱动行");
        } else if (kCommand == kOverviewMenuCopyName) {
            copyOverviewText(state, row.driverName, L"复制驱动名称");
        } else {
            copyOverviewText(state, row.pathText, L"复制驱动路径");
        }
    }
}

// overviewColumns returns the report columns shown by the overview page.
// There is no input; processing returns static descriptors; output is consumed
// by the ListView helper.
std::vector<ksword::ui::ListViewColumn> overviewColumns() {
    return {
        { 0, 190, LVCFMT_LEFT, L"驱动名称" },
        { 1, 145, LVCFMT_LEFT, L"基址" },
        { 2, 260, LVCFMT_LEFT, L"内存区间" },
        { 3, 110, LVCFMT_RIGHT, L"大小" },
        { 4, 420, LVCFMT_LEFT, L"路径" },
        { 5, 160, LVCFMT_LEFT, L"签名/来源" },
        { 6, 180, LVCFMT_LEFT, L"状态" },
        { 7, 320, LVCFMT_LEFT, L"异常标记" },
        { 8, 320, LVCFMT_LEFT, L"能力提示" },
    };
}

std::wstring buildOverviewTsv(const DriverOverviewViewState& state);

// requestOverviewFilter filters the immutable preformatted snapshot away from
// the UI thread. A generation check prevents older input or refresh results
// from replacing a newer visible result.
void requestOverviewFilter(DriverOverviewViewState& state, std::wstring query) {
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
            OverviewFilterResult result{};
            result.snapshotGeneration = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<OverviewFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() ||
                result->snapshotGeneration != state.snapshotGeneration ||
                result->query != state.filterQuery ||
                result->useRegex != state.filterUseRegex) {
                return;
            }
            const int kSelected = ListView_GetNextItem(state.listView, -1, LVNI_SELECTED);
            const std::wstring kSelectedKey = stableKeyAt(state, kSelected);
            const std::wstring kTopKey = stableKeyAt(state, ListView_GetTopIndex(state.listView));
            state.visibleRows.clear();
            state.visibleRows.reserve(result->visibleIndexes.size());
            for (const std::size_t kIndex : result->visibleIndexes) {
                if (kIndex < state.snapshotRows.size()) {
                    state.visibleRows.push_back(state.snapshotRows[kIndex]);
                }
            }
            state.virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            restoreListPosition(state, kSelectedKey, kTopKey);
        });
}

// populateOverviewList installs an immutable virtual-list snapshot. It does
// not enumerate or filter synchronously, so a driver refresh never causes a
// per-row ListView insertion storm on the UI thread.
void populateOverviewList(DriverOverviewViewState& state) {
    if (!state.listView || !state.model) {
        return;
    }
    state.snapshotRows = state.model->overviewRows();
    state.filterRows = std::make_shared<const std::vector<ksword::ui::VirtualListRow>>(
        buildOverviewVirtualRows(state.snapshotRows));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    requestOverviewFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery);
}

// buildOverviewTsv converts the rows currently rendered by the virtual list
// into TSV text. Input is the view state; processing serializes its active
// visible indexes so an in-flight filter cannot yield stale export data.
std::wstring buildOverviewTsv(const DriverOverviewViewState& state) {
    return ksword::ui::buildVisibleVirtualListTsv(
        { L"驱动名称", L"基址", L"内存区间", L"大小", L"路径", L"签名/来源", L"状态", L"异常标记", L"能力提示" },
        state.virtualList);
}

// registerDriverOverviewClass installs the child window class once. There is no
// input; processing is idempotent; output is true when CreateWindowExW can use
// the class name.
bool registerDriverOverviewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DriverOverviewViewState* state = stateFromWindow(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DriverOverviewViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                state->filterBar = ksword::ui::createFilterBar(hwnd, kOverviewFilterId,
                    L"筛选驱动、路径、签名、状态和异常详情", 0, 0, 0, 0);
                if (state->virtualList.create(hwnd, kOverviewListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
                    state->listView = state->virtualList.hwnd();
                }
                setChildFont(state->listView);
                state->virtualList.addColumns(overviewColumns());
                state->loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kOverviewLoadingOverlayId, { 0, 0, 1, 1 });
                state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<OverviewFilterResult>>(hwnd, kMsgOverviewFilterCompleted);
                state->detailTask = std::make_unique<ksword::ui::AsyncSnapshotTask<OverviewDetailResult>>(hwnd, kMsgOverviewDetailCompleted);
                populateOverviewList(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kOverviewFilterId && HIWORD(wParam) == EN_CHANGE) {
                requestOverviewFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            break;
        case kMsgOverviewFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgOverviewDetailCompleted:
            if (state && state->detailTask && state->detailTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                LRESULT virtualResult = 0;
                if (header && state->virtualList.handleNotify(*header, virtualResult)) {
                    return virtualResult;
                }
                if (header && header->hwndFrom == state->listView && header->code == NM_RCLICK) {
                    POINT pt{};
                    ::GetCursorPos(&pt);
                    showOverviewContextMenu(*state, pt);
                    return 0;
                }
            }
            break;
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->listView) {
                POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (pt.x == -1 && pt.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->listView, &rc);
                    pt = { rc.left + 24, rc.top + 24 };
                }
                showOverviewContextMenu(*state, pt);
                return 0;
            }
            break;
        case WM_SIZE:
            if (state && state->listView) {
                RECT rc{};
                ::GetClientRect(hwnd, &rc);
                const int kWidth = rc.right - rc.left;
                const int kHeight = rc.bottom - rc.top;
                const int kMargin = 6;
                const int kFilterHeight = 28;
                ::MoveWindow(state->filterBar, kMargin, kMargin, std::max(80, kWidth - kMargin * 2), kFilterHeight, TRUE);
                ::MoveWindow(state->listView, 0, kFilterHeight + kMargin * 2, kWidth, std::max(40, kHeight - kFilterHeight - kMargin * 2), TRUE);
                ::MoveWindow(state->loadingOverlay, 0, kFilterHeight + kMargin * 2, kWidth, std::max(40, kHeight - kFilterHeight - kMargin * 2), TRUE);
            }
            return 0;
        case WM_NCDESTROY:
            if (state && state->filterTask) {
                state->filterTask->cancel();
            }
            if (state && state->detailTask) {
                state->detailTask->cancel();
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
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kDriverOverviewClass;
    if (::RegisterClassW(&wc)) {
        registered = true;
    } else if (::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createDriverOverviewView(HWND parent, const RECT& bounds, DriverModel* model) {
    if (!parent || !registerDriverOverviewClass()) {
        return nullptr;
    }

    auto* state = new DriverOverviewViewState();
    state->model = model;
    HWND hwnd = ::CreateWindowExW(
        0,
        kDriverOverviewClass,
        L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_VISIBLE,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

void resizeDriverOverviewView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

void refreshDriverOverviewView(HWND view) {
    DriverOverviewViewState* state = stateFromWindow(view);
    if (state) {
        populateOverviewList(*state);
    }
}

std::wstring exportDriverOverviewViewTsv(HWND view) {
    const DriverOverviewViewState* state = stateFromWindow(view);
    return state ? buildOverviewTsv(*state) : std::wstring();
}

} // namespace Ksword::Features::Driver

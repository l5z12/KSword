#include "DriverObjectView.h"

#include "DriverActions.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace ksword::features::driver {
namespace {

constexpr wchar_t kDriverObjectClass[] = L"KswordARKLight.DriverObjectView";
constexpr int kObjectListId = 64011;
constexpr int kObjectFilterId = 64012;
constexpr int kObjectLoadingOverlayId = 64013;
constexpr UINT kObjectMenuDetail = 64201;
constexpr UINT kObjectMenuCopyCell = 64202;
constexpr UINT kObjectMenuCopyRow = 64203;
constexpr UINT kObjectMenuCopyName = 64204;
constexpr UINT kObjectMenuCopyPath = 64205;
constexpr UINT kObjectMenuCopyTarget = 64206;
constexpr UINT kObjectMenuCopyVisible = 64207;
constexpr UINT kMsgObjectFilterCompleted = WM_APP + 598;
constexpr UINT kMsgObjectDetailCompleted = WM_APP + 599;
constexpr wchar_t kObjectDetailClass[] = L"KswordARKLight.DriverObjectDetailDialog";
constexpr int kObjectDetailEditId = 64221;
constexpr int kObjectDetailCopyId = 64222;
constexpr int kObjectDetailCloseId = 64223;

// DriverObjectViewState owns the object report list and model pointer. Inputs
// arrive through Win32 messages; processing renders the current snapshot into
// the child list; no model ownership is transferred here.
struct DriverObjectViewState {
    HWND hwnd = nullptr;
    HWND filterBar = nullptr;
    HWND listView = nullptr;
    HWND loadingOverlay = nullptr;
    DriverModel* model = nullptr;
    std::vector<DriverObjectRow> snapshotRows;
    std::vector<DriverObjectRow> visibleRows;
    ksword::ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    std::uint64_t detailRequestId = 0;
    int contextColumn = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<struct ObjectFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<struct ObjectDetailResult>> detailTask;
};

struct ObjectFilterResult {
    std::uint64_t snapshotGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct ObjectDetailResult {
    std::uint64_t requestId = 0;
    std::wstring text;
};

// DetailDialogState owns the read-only detail popup. Input is generated text;
// processing creates a scrollable EDIT and copy/close controls; no return value
// is needed because the window is modeless.
struct DetailDialogState {
    HWND hwnd = nullptr;
    HWND edit = nullptr;
    HWND copyButton = nullptr;
    HWND closeButton = nullptr;
    std::wstring title;
    std::wstring text;
};

// stateFromWindow returns the view state from the HWND. Input is the child
// window; processing reads GWLP_USERDATA; output is null before creation or
// after WM_NCDESTROY clears the pointer.
DriverObjectViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverObjectViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// setChildFont applies the project UI font to one child window. Input is a
// child HWND; processing sends WM_SETFONT; no value is returned.
void setChildFont(HWND hwnd) {
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
}

// selectedObjectRow copies the currently selected object row from the attached
// model. Input is view state and optional output pointer; processing maps the
// selected report row to model storage; output is true when a row exists.
bool selectedObjectRow(const DriverObjectViewState& state, DriverObjectRow* rowOut) {
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

// driverObjectNameForRow resolves the best DriverObject name for an object-grid
// row. Input may be a native \Driver row, an R0 summary row, or an R0 child
// MajorFunction/DeviceObject row; output is the \Driver\Name string required by
// ArkDriverClient DriverObject IOCTLs.
std::wstring driverObjectNameForRow(const DriverObjectRow& row) {
    if (!row.fullPathText.empty() &&
        (row.fullPathText.rfind(L"\\Driver\\", 0) == 0 ||
            row.directoryPathText == L"R0 DriverObject" ||
            row.directoryPathText == L"R0 MajorFunction" ||
            row.directoryPathText == L"R0 DeviceObject")) {
        return row.fullPathText;
    }
    if (row.directoryPathText == L"\\Driver" && row.objectTypeText == L"Driver" && !row.objectNameText.empty()) {
        return L"\\Driver\\" + row.objectNameText;
    }
    return {};
}

// copyObjectText writes selected object text to the clipboard. Inputs are view
// state and payload; processing routes through DriverActions; no value returns.
void copyObjectText(const DriverObjectViewState& state, const std::wstring& text, const wchar_t* title) {
    (void)title;
    DriverActions::copyTextToClipboard(state.hwnd, text);
}

// buildObjectRowText serializes one driver object row. Input is the selected
// model row; output is a TSV-compatible string for the copy-row menu command.
std::wstring buildObjectRowText(const DriverObjectRow& row) {
    return row.directoryPathText + L"\t" +
        row.objectNameText + L"\t" +
        row.objectTypeText + L"\t" +
        row.fullPathText + L"\t" +
        row.targetPathText + L"\t" +
        row.referenceCountText + L"\t" +
        row.handleCountText + L"\t" +
        row.statusText + L"\t" +
        row.capabilityHint;
}

std::vector<std::wstring> objectCells(const DriverObjectRow& row) {
    return {
        row.directoryPathText,
        row.objectNameText,
        row.objectTypeText,
        row.fullPathText,
        row.targetPathText,
        row.referenceCountText,
        row.handleCountText,
        row.statusText,
        row.capabilityHint
    };
}

std::wstring objectStableKey(const DriverObjectRow& row) {
    return row.directoryPathText + L"\n" + row.fullPathText + L"\n" + row.objectTypeText;
}

std::vector<ksword::ui::VirtualListRow> buildObjectVirtualRows(const std::vector<DriverObjectRow>& rows) {
    std::vector<ksword::ui::VirtualListRow> displayRows;
    displayRows.reserve(rows.size());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        ksword::ui::VirtualListRow display{};
        display.stableKey = objectStableKey(rows[index]);
        display.cells = objectCells(rows[index]);
        display.itemData = static_cast<LPARAM>(index);
        displayRows.push_back(std::move(display));
    }
    return displayRows;
}

std::wstring stableKeyAt(const DriverObjectViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return objectStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void restoreListPosition(DriverObjectViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring kKey = objectStableKey(state.visibleRows[index]);
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

// registerDetailDialogClass installs the reusable object detail window class.
// There is no input; output is true when the class is available.
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
                    reinterpret_cast<HMENU>(static_cast<INT_PTR>(kObjectDetailEditId)),
                    ::GetModuleHandleW(nullptr),
                    nullptr);
                ksword::ui::attachTextFindSupport(state->edit);
                state->copyButton = ksword::ui::createButton(hwnd, kObjectDetailCopyId, L"复制详情", 0, 0, 0, 0);
                state->closeButton = ksword::ui::createButton(hwnd, kObjectDetailCloseId, L"关闭", 0, 0, 0, 0);
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
            if (state && LOWORD(wParam) == kObjectDetailCopyId) {
                DriverActions::copyTextToClipboard(hwnd, state->text);
                return 0;
            }
            if (state && LOWORD(wParam) == kObjectDetailCloseId) {
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
    wc.lpszClassName = kObjectDetailClass;
    registered = (::RegisterClassW(&wc) != 0) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

// showDetailWindow creates a scrollable detail popup with copy support. Inputs
// are owner, title, and text body; processing falls back to MessageBox only when
// window creation fails.
void showDetailWindow(HWND owner, const std::wstring& title, const std::wstring& text) {
    if (!registerDetailDialogClass()) {
        ::MessageBoxW(owner, text.c_str(), title.c_str(), MB_OK | MB_ICONINFORMATION);
        return;
    }

    auto* state = new DetailDialogState();
    state->title = title;
    state->text = text;
    HWND hwnd = ::CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        kObjectDetailClass,
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

// buildObjectDetailText formats row-local columns and, for DriverObject rows,
// appends R0 DriverObject query output. Input is a selected row; output is a
// detail body suitable for the popup edit control.
std::wstring buildObjectDetailText(const DriverObjectRow& row) {
    std::wstring detail =
        L"Directory: " + row.directoryPathText + L"\r\n" +
        L"ObjectName: " + row.objectNameText + L"\r\n" +
        L"Type: " + row.objectTypeText + L"\r\n" +
        L"FullPath: " + row.fullPathText + L"\r\n" +
        L"TargetPath: " + row.targetPathText + L"\r\n" +
        L"ReferenceCount: " + row.referenceCountText + L"\r\n" +
        L"HandleCount: " + row.handleCountText + L"\r\n" +
        L"Status: " + row.statusText + L"\r\n" +
        L"Hint: " + row.capabilityHint + L"\r\n";

    const std::wstring kDriverObjectName = driverObjectNameForRow(row);
    if (!kDriverObjectName.empty()) {
        const DriverActionResult kR0Detail = DriverActions::buildDriverObjectDetailText(kDriverObjectName);
        detail += L"\r\nR0 DriverObject query (" + kDriverObjectName + L"):\r\n";
        detail += kR0Detail.statusText;
    }
    return detail;
}

// showObjectDetail runs the optional R0 DriverObject lookup in a worker. This
// keeps object-directory browsing responsive while a large device or dispatch
// list is formatted.
void showObjectDetail(DriverObjectViewState& state) {
    DriverObjectRow row;
    if (!selectedObjectRow(state, &row) || !state.detailTask) {
        return;
    }
    const std::uint64_t kRequestId = ++state.detailRequestId;
    ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在后台查询对象详情…");
    state.detailTask->request(
        [row, kRequestId] {
            ObjectDetailResult result{};
            result.requestId = kRequestId;
            result.text = buildObjectDetailText(row);
            return result;
        },
        [&state](std::uint64_t, std::optional<ObjectDetailResult>&& result, std::exception_ptr error) {
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value() || result->requestId != state.detailRequestId) {
                return;
            }
            showDetailWindow(state.hwnd, L"对象详细信息", result->text);
        });
}

std::wstring buildObjectTsv(const DriverObjectViewState& state);

// showObjectContextMenu displays the object-info right-click menu and dispatches
// retained commands. Inputs are view state and screen point; processing selects
// the clicked row before executing grouped copy/detail read-only actions; no value is
// returned.
void showObjectContextMenu(DriverObjectViewState& state, POINT screenPoint) {
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.listView, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kItem = ListView_HitTest(state.listView, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    if (kItem >= 0) {
        ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state.listView, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    DriverObjectRow row;
    const bool kHasSelection = selectedObjectRow(state, &row);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kObjectMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kObjectMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kObjectMenuCopyName, L"复制对象名");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kObjectMenuCopyPath, L"复制完整路径");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kObjectMenuCopyTarget, L"复制目标路径");
        ::AppendMenuW(copyMenu, MF_STRING | (!state.visibleRows.empty() ? 0U : MF_GRAYED), kObjectMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    HMENU detailMenu = ::CreatePopupMenu();
    if (detailMenu) {
        ::AppendMenuW(detailMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kObjectMenuDetail, L"详细信息/R0 DriverObject");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(detailMenu), L"详细信息");
    }

    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kObjectMenuDetail) {
        showObjectDetail(state);
    } else if (kCommand == kObjectMenuCopyCell ||
        kCommand == kObjectMenuCopyRow ||
        kCommand == kObjectMenuCopyName ||
        kCommand == kObjectMenuCopyPath ||
        kCommand == kObjectMenuCopyTarget ||
        kCommand == kObjectMenuCopyVisible) {
        if (kCommand == kObjectMenuCopyVisible) {
            copyObjectText(state, buildObjectTsv(state), L"复制可见对象结果");
            return;
        }
        if (!selectedObjectRow(state, &row)) {
            return;
        }
        if (kCommand == kObjectMenuCopyCell) {
            const std::vector<std::wstring> kCells = objectCells(row);
            const std::size_t kColumn = static_cast<std::size_t>(std::max(0, state.contextColumn));
            copyObjectText(state, kColumn < kCells.size() ? kCells[kColumn] : std::wstring{}, L"复制单元格");
        } else if (kCommand == kObjectMenuCopyRow) {
            copyObjectText(state, buildObjectRowText(row), L"复制对象行");
        } else if (kCommand == kObjectMenuCopyName) {
            copyObjectText(state, row.objectNameText, L"复制对象名");
        } else if (kCommand == kObjectMenuCopyPath) {
            copyObjectText(state, row.fullPathText, L"复制完整路径");
        } else {
            copyObjectText(state, row.targetPathText, L"复制目标路径");
        }
    }
}

// objectColumns returns the report columns shown by the object page. There is
// no input; processing returns static descriptors; output is consumed by the
// ListView helper.
std::vector<ksword::ui::ListViewColumn> objectColumns() {
    return {
        { 0, 140, LVCFMT_LEFT, L"目录" },
        { 1, 180, LVCFMT_LEFT, L"对象名" },
        { 2, 140, LVCFMT_LEFT, L"类型" },
        { 3, 340, LVCFMT_LEFT, L"完整路径" },
        { 4, 320, LVCFMT_LEFT, L"目标路径" },
        { 5, 120, LVCFMT_RIGHT, L"引用计数" },
        { 6, 120, LVCFMT_RIGHT, L"句柄计数" },
        { 7, 220, LVCFMT_LEFT, L"状态" },
        { 8, 300, LVCFMT_LEFT, L"能力提示" },
    };
}

// requestObjectFilter filters a retained immutable object snapshot in the
// worker. It never calls the object manager or R0 driver while the user types.
void requestObjectFilter(DriverObjectViewState& state, std::wstring query) {
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
            ObjectFilterResult result{};
            result.snapshotGeneration = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ObjectFilterResult>&& result, std::exception_ptr error) {
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

// populateObjectList installs a virtual-list snapshot and delegates local
// filtering to requestObjectFilter. Old rows remain displayed until the next
// complete filter result is installed.
void populateObjectList(DriverObjectViewState& state) {
    if (!state.listView || !state.model) {
        return;
    }
    state.snapshotRows = state.model->objectRows();
    state.filterRows = std::make_shared<const std::vector<ksword::ui::VirtualListRow>>(
        buildObjectVirtualRows(state.snapshotRows));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    requestObjectFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery);
}

// buildObjectTsv converts the rows currently rendered by the virtual list into
// TSV text. Input is the view state; processing serializes its active visible
// indexes so an in-flight filter cannot yield stale export data.
std::wstring buildObjectTsv(const DriverObjectViewState& state) {
    return ksword::ui::buildVisibleVirtualListTsv(
        { L"目录", L"对象名", L"类型", L"完整路径", L"目标路径", L"引用计数", L"句柄计数", L"状态", L"能力提示" },
        state.virtualList);
}

// registerDriverObjectClass installs the child window class once. There is no
// input; processing is idempotent; output is true when CreateWindowExW can use
// the class name.
bool registerDriverObjectClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        DriverObjectViewState* state = stateFromWindow(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<DriverObjectViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                state->filterBar = ksword::ui::createFilterBar(hwnd, kObjectFilterId,
                    L"筛选目录、对象、类型、路径、状态和能力详情", 0, 0, 0, 0);
                if (state->virtualList.create(hwnd, kObjectListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
                    state->listView = state->virtualList.hwnd();
                }
                setChildFont(state->listView);
                state->virtualList.addColumns(objectColumns());
                state->loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kObjectLoadingOverlayId, { 0, 0, 1, 1 });
                state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ObjectFilterResult>>(hwnd, kMsgObjectFilterCompleted);
                state->detailTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ObjectDetailResult>>(hwnd, kMsgObjectDetailCompleted);
                populateObjectList(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kObjectFilterId && HIWORD(wParam) == EN_CHANGE) {
                requestObjectFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            break;
        case kMsgObjectFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgObjectDetailCompleted:
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
                    showObjectContextMenu(*state, pt);
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
                showObjectContextMenu(*state, pt);
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
    wc.lpszClassName = kDriverObjectClass;
    if (::RegisterClassW(&wc)) {
        registered = true;
    } else if (::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createDriverObjectView(HWND parent, const RECT& bounds, DriverModel* model) {
    if (!parent || !registerDriverObjectClass()) {
        return nullptr;
    }

    auto* state = new DriverObjectViewState();
    state->model = model;
    HWND hwnd = ::CreateWindowExW(
        0,
        kDriverObjectClass,
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

void resizeDriverObjectView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

void refreshDriverObjectView(HWND view) {
    DriverObjectViewState* state = stateFromWindow(view);
    if (state) {
        populateObjectList(*state);
    }
}

std::wstring exportDriverObjectViewTsv(HWND view) {
    const DriverObjectViewState* state = stateFromWindow(view);
    return state ? buildObjectTsv(*state) : std::wstring();
}

} // namespace Ksword::Features::Driver

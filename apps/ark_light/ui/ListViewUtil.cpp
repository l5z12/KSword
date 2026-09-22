#include "ListViewUtil.h"

#include "Controls.h"

namespace ksword::ui {

ScopedWindowRedrawLock::ScopedWindowRedrawLock(HWND hwnd, bool invalidateOnExit) noexcept
    : hwnd_(hwnd), invalidateOnExit_(invalidateOnExit) {
    // Constructor input is any HWND that may repaint heavily during a batch
    // operation. Processing only toggles redraw when the handle is valid.
    if (hwnd_ && ::IsWindow(hwnd_)) {
        ::SendMessageW(hwnd_, WM_SETREDRAW, FALSE, 0);
    }
}

ScopedWindowRedrawLock::~ScopedWindowRedrawLock() {
    // Destructor restores redraw and optionally requests one final repaint so
    // callers do not need to remember the balancing WM_SETREDRAW sequence.
    if (!hwnd_ || !::IsWindow(hwnd_)) {
        return;
    }
    ::SendMessageW(hwnd_, WM_SETREDRAW, TRUE, 0);
    if (invalidateOnExit_) {
        ::RedrawWindow(hwnd_, nullptr, nullptr, RDW_ERASE | RDW_FRAME | RDW_INVALIDATE | RDW_ALLCHILDREN);
    }
}

ScopedListViewRedrawLock::ScopedListViewRedrawLock(HWND listView) noexcept
    : listViewLock_(listView, true),
      headerLock_(listView ? ListView_GetHeader(listView) : nullptr, false) {
    // The list-view helper intentionally delays invalidation until both the
    // header and body redraw state have been restored.
}

HWND createReportListView(HWND parent, int id, int x, int y, int width, int height, DWORD extraStyle) {
    // Inputs are direct child-window creation parameters. The helper keeps the
    // standard common-control visual style by using WC_LISTVIEWW and does not
    // owner-draw, subclass, or add page-specific padding.
    const DWORD kStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS |
        LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | extraStyle;
    HWND hwnd = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        kStyle,
        x,
        y,
        width,
        height,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (!hwnd) {
        return nullptr;
    }

    ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    ListView_SetExtendedListViewStyleEx(
        hwnd,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    return hwnd;
}

bool addListViewColumn(HWND listView, const ListViewColumn& column) {
    // The caller owns column ordering. This function only maps the lightweight
    // descriptor to LVCOLUMNW and submits it to the common control.
    if (!listView) {
        return false;
    }

    LVCOLUMNW nativeColumn{};
    nativeColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    nativeColumn.fmt = column.format;
    nativeColumn.cx = column.width;
    nativeColumn.pszText = const_cast<LPWSTR>(column.title.c_str());
    return ListView_InsertColumn(listView, column.index, &nativeColumn) >= 0;
}

bool addListViewColumns(HWND listView, const std::vector<ListViewColumn>& columns) {
    // Every descriptor is attempted so a caller can inspect the resulting
    // control state during debugging. The combined return reports whether all
    // insertions succeeded.
    bool allOk = true;
    for (const ListViewColumn& column : columns) {
        allOk = addListViewColumn(listView, column) && allOk;
    }
    return allOk;
}

bool setListViewColumnWidth(HWND listView, int columnIndex, int width) {
    // Width is passed through unchanged. Callers may use LVSCW_AUTOSIZE or
    // LVSCW_AUTOSIZE_USEHEADER because ListView_SetColumnWidth accepts them.
    if (!listView || columnIndex < 0) {
        return false;
    }
    return ListView_SetColumnWidth(listView, columnIndex, width) != FALSE;
}

void clearListViewColumns(HWND listView) {
    // Header item count is queried first, then columns are deleted right-to-left
    // so indexes remain stable during removal. No row padding or layout change
    // is applied.
    if (!listView) {
        return;
    }

    HWND header = ListView_GetHeader(listView);
    ScopedListViewRedrawLock redrawLock(listView);
    const int kCount = header ? Header_GetItemCount(header) : 0;
    for (int index = kCount - 1; index >= 0; --index) {
        ListView_DeleteColumn(listView, index);
    }
}

int insertListViewTextRow(HWND listView, const std::vector<std::wstring>& cells, LPARAM itemData) {
    // The first cell becomes the item text; remaining cells become subitems.
    // Empty input is valid and creates an empty first column row.
    if (!listView) {
        return -1;
    }

    const std::wstring kEmptyText;
    const std::wstring& firstText = cells.empty() ? kEmptyText : cells.front();
    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = ListView_GetItemCount(listView);
    item.iSubItem = 0;
    item.pszText = const_cast<LPWSTR>(firstText.c_str());
    item.lParam = itemData;

    const int kRow = ListView_InsertItem(listView, &item);
    if (kRow < 0) {
        return -1;
    }

    for (std::size_t column = 1; column < cells.size(); ++column) {
        ListView_SetItemText(
            listView,
            kRow,
            static_cast<int>(column),
            const_cast<LPWSTR>(cells[column].c_str()));
    }
    return kRow;
}

void clearListViewRows(HWND listView) {
    // Rows are cleared through the common control API; columns are intentionally
    // left intact for feature pages that refresh data frequently.
    if (listView) {
        ScopedListViewRedrawLock redrawLock(listView);
        ListView_DeleteAllItems(listView);
    }
}

} // namespace Ksword::Ui

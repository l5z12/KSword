#include "AuditTable.h"

#include "AuditFormatting.h"
#include "../../ui/Controls.h"

#include <commctrl.h>
#include <utility>

namespace ksword::features::audit_common {
namespace {

constexpr UINT kCopyCellCommand = 72001;
constexpr UINT kCopyRowCommand = 72002;
constexpr UINT kCopyAllCommand = 72003;

// Width returns a non-negative rectangle width. Input is a RECT; output is the
// width used for CreateWindow/MoveWindow calls.
int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns a non-negative rectangle height. Input is a RECT; output is the
// height used for CreateWindow/MoveWindow calls.
int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// columnCount returns the current ListView report column count. Input is a
// ListView HWND; processing reads the header control; output is zero when the
// table is invalid or has no header.
int columnCount(HWND listView) {
    HWND header = listView ? ListView_GetHeader(listView) : nullptr;
    return header ? Header_GetItemCount(header) : 0;
}

// headerText returns one report column title. Inputs are a ListView and column
// index; processing reads HDITEMW text; output is empty if the column is invalid.
std::wstring headerText(HWND listView, int column) {
    HWND header = listView ? ListView_GetHeader(listView) : nullptr;
    if (!header || column < 0) {
        return {};
    }

    wchar_t buffer[256]{};
    HDITEMW item{};
    item.mask = HDI_TEXT;
    item.pszText = buffer;
    item.cchTextMax = static_cast<int>(sizeof(buffer) / sizeof(buffer[0]));
    if (!Header_GetItem(header, column, &item)) {
        return {};
    }
    return buffer;
}

// hitTestCell selects the row under a context-menu point and returns row/column.
// Inputs are a ListView and screen point; processing maps to client coordinates
// and performs LVM_SUBITEMHITTEST; output is true when a row was hit.
bool hitTestCell(HWND listView, POINT screenPoint, int* rowOut, int* columnOut) {
    if (!listView) {
        return false;
    }

    POINT clientPoint = screenPoint;
    ::ScreenToClient(listView, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kRow = ListView_SubItemHitTest(listView, &hit);
    if (kRow >= 0) {
        ListView_SetItemState(listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(listView, kRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (rowOut) {
        *rowOut = kRow;
    }
    if (columnOut) {
        *columnOut = hit.iSubItem;
    }
    return kRow >= 0;
}

} // namespace

HWND createReadOnlyAuditTable(
    HWND parent,
    const int id,
    const RECT& bounds,
    const std::vector<AuditTableColumn>& columns) {
    HWND listView = ksword::ui::createReportListView(
        parent,
        id,
        bounds.left,
        bounds.top,
        width(bounds),
        height(bounds));
    if (!listView) {
        return nullptr;
    }
    configureReadOnlyAuditTable(listView);
    setAuditTableColumns(listView, columns);
    return listView;
}

bool configureReadOnlyAuditTable(HWND listView) {
    if (!listView) {
        return false;
    }

    ::SendMessageW(listView, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ListView_SetExtendedListViewStyleEx(
        listView,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_LABELTIP | LVS_EX_DOUBLEBUFFER);
    return true;
}

bool setAuditTableColumns(HWND listView, const std::vector<AuditTableColumn>& columns) {
    if (!listView) {
        return false;
    }

    ksword::ui::clearListViewColumns(listView);
    std::vector<ksword::ui::ListViewColumn> uiColumns;
    uiColumns.reserve(columns.size());
    for (std::size_t index = 0; index < columns.size(); ++index) {
        uiColumns.push_back({
            static_cast<int>(index),
            columns[index].width,
            columns[index].format,
            columns[index].title
        });
    }
    return ksword::ui::addListViewColumns(listView, uiColumns);
}

void replaceAuditTableRows(HWND listView, const std::vector<std::vector<std::wstring>>& rows) {
    if (!listView) {
        return;
    }

    ksword::ui::ScopedListViewRedrawLock redrawLock(listView);
    ListView_DeleteAllItems(listView);
    for (const std::vector<std::wstring>& row : rows) {
        ksword::ui::insertListViewTextRow(listView, row);
    }
}

std::wstring getAuditTableCellText(HWND listView, const int row, const int column) {
    if (!listView || row < 0 || column < 0) {
        return {};
    }

    std::wstring buffer(256, L'\0');
    for (;;) {
        LVITEMW item{};
        item.iSubItem = column;
        item.cchTextMax = static_cast<int>(buffer.size());
        item.pszText = buffer.data();
        const int kCopied = static_cast<int>(::SendMessageW(
            listView,
            LVM_GETITEMTEXTW,
            static_cast<WPARAM>(row),
            reinterpret_cast<LPARAM>(&item)));
        if (kCopied < static_cast<int>(buffer.size()) - 1) {
            buffer.resize(static_cast<std::size_t>(kCopied));
            return buffer;
        }
        buffer.resize(buffer.size() * 2);
        if (buffer.size() > 32768) {
            buffer.resize(static_cast<std::size_t>(kCopied));
            return buffer;
        }
    }
}

std::wstring getSelectedAuditTableRowText(HWND listView) {
    if (!listView) {
        return {};
    }

    const int kSelected = ListView_GetNextItem(listView, -1, LVNI_SELECTED);
    if (kSelected < 0) {
        return {};
    }

    std::vector<std::wstring> cells;
    const int kColumns = columnCount(listView);
    cells.reserve(static_cast<std::size_t>(kColumns));
    for (int column = 0; column < kColumns; ++column) {
        cells.push_back(getAuditTableCellText(listView, kSelected, column));
    }
    return buildTsv({}, { cells });
}

std::wstring buildAuditTableTsv(HWND listView) {
    if (!listView) {
        return {};
    }

    const int kColumns = columnCount(listView);
    const int kRows = ListView_GetItemCount(listView);
    std::vector<std::wstring> headers;
    headers.reserve(static_cast<std::size_t>(kColumns));
    for (int column = 0; column < kColumns; ++column) {
        headers.push_back(headerText(listView, column));
    }

    std::vector<std::vector<std::wstring>> tableRows;
    tableRows.reserve(static_cast<std::size_t>(kRows));
    for (int row = 0; row < kRows; ++row) {
        std::vector<std::wstring> cells;
        cells.reserve(static_cast<std::size_t>(kColumns));
        for (int column = 0; column < kColumns; ++column) {
            cells.push_back(getAuditTableCellText(listView, row, column));
        }
        tableRows.push_back(std::move(cells));
    }
    return buildTsv(headers, tableRows);
}

void showAuditTableContextMenu(HWND owner, HWND listView, POINT screenPoint) {
    if (!owner || !listView) {
        return;
    }

    int row = -1;
    int column = 0;
    const bool kHasHit = hitTestCell(listView, screenPoint, &row, &column);
    const bool kHasSelection = kHasHit || ListView_GetNextItem(listView, -1, LVNI_SELECTED) >= 0;

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kCopyCellCommand, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kCopyRowCommand, L"复制整行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kCopyAllCommand, L"复制全部 TSV");

    const UINT kCommand = ::TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        owner,
        nullptr);
    ::DestroyMenu(menu);

    if (kCommand == kCopyCellCommand) {
        copyTextToClipboard(owner, getAuditTableCellText(listView, row, column));
    } else if (kCommand == kCopyRowCommand) {
        copyTextToClipboard(owner, getSelectedAuditTableRowText(listView));
    } else if (kCommand == kCopyAllCommand) {
        copyTextToClipboard(owner, buildAuditTableTsv(listView));
    }
}

} // namespace Ksword::Features::audit_common

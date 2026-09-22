#include "KWidgets.h"

#include "KPaintDebug.h"

#include "fl_draw.H"

#include <algorithm>
#include <cstdint>
#include <cstdio>

namespace {
constexpr int kTableFontSize = 12;

// drawTableText renders non-empty table text inside a clipped cell rectangle.
void drawTableText(const char* text, int x, int y, int w, int h, Fl_Color color, Fl_Align align) {
    if (!text || text[0] == '\0') {
        return;
    }
    fl_color(color);
    fl_font(FL_HELVETICA, kTableFontSize);
    fl_draw(text, x, y, w, h, align);
}

// drawCellGrid paints the right and bottom dividers for one table rectangle.
void drawCellGrid(int x, int y, int w, int h, Fl_Color color) {
    fl_color(color);
    fl_line(x + w - 1, y, x + w - 1, y + h);
    fl_line(x, y + h - 1, x + w, y + h - 1);
}

// sumColumnPixels returns the logical width occupied by all model columns.
// The input is the live table because FLTK may hold user-resized column widths;
// the output is clamped to non-negative pixels and has no side effects.
int sumColumnPixels(KTable* table) {
    if (!table) {
        return 0;
    }

    int total = 0;
    for (int col = 0; col < table->cols(); ++col) {
        total += std::max(0, table->col_width(col));
    }
    return total;
}

// sumRowPixels returns the logical height occupied by all model rows.
// It mirrors sumColumnPixels for row resize safety and returns zero for a null table.
int sumRowPixels(KTable* table) {
    if (!table) {
        return 0;
    }

    int total = 0;
    for (int row = 0; row < table->rows(); ++row) {
        total += std::max(0, table->row_height(row));
    }
    return total;
}

// fillRectIfVisible paints a rectangular fragment only when dimensions are valid.
// Input coordinates are already table-local screen coordinates; there is no return value.
void fillRectIfVisible(int x, int y, int w, int h, Fl_Color color) {
    if (w <= 0 || h <= 0) {
        return;
    }
    fl_color(color);
    fl_rectf(x, y, w, h);
}

// drawTableDeadZone fills only the area not covered by real cells.
// CONTEXT_TABLE may be delivered during selection/focus updates before FLTK
// repaints just the changed cells. Clearing the whole context rectangle here
// erases other cells, so this helper restricts painting to bottom/right blank
// space or the whole body only when there is no cell model to draw.
void drawTableDeadZone(KTable* table, int x, int y, int w, int h, Fl_Color color) {
    if (!table || w <= 0 || h <= 0) {
        return;
    }

    fl_push_clip(x, y, w, h);
    if (table->rows() <= 0 || table->cols() <= 0) {
        fillRectIfVisible(x, y, w, h, color);
        fl_pop_clip();
        return;
    }

    const int kUsedW = std::min(w, sumColumnPixels(table));
    const int kUsedH = std::min(h, sumRowPixels(table));

    // Right-side and bottom-side fills keep empty table space stable without
    // painting over any existing cell, header, or grid line.
    fillRectIfVisible(x + kUsedW, y, w - kUsedW, h, color);
    fillRectIfVisible(x, y + kUsedH, w, h - kUsedH, color);
    fl_pop_clip();
}
}

KTable::ContextMenuBinding::ContextMenuBinding()
    : callback(nullptr), userData(nullptr) {
}

KTable::KTable(int x, int y, int w, int h, const char* label)
    : Fl_Table(x, y, w, h, label),
      colLabels_(),
      cells_(),
      rowContextMenuCallbacks_(),
      cellContextMenuCallbacks_(),
      rowHeight_(24),
      colWidth_(120),
      contextMenuX_(0),
      contextMenuY_(0) {
    cols(0);
    rows(0);
    col_header(1);
    row_header(0);
    col_resize(1);
    row_resize(0);
    col_header_height(26);
    row_height_all(rowHeight_);
    col_width_all(colWidth_);
    const KTheme& theme = KThemeManager::instance().theme();
    // Match the original FlatTable wrapper: the table owns all background and
    // grid painting, so FLTK should not draw an extra box that can leave stale
    // pixels during partial selection redraws.
    box(FL_NO_BOX);
    color(COLOR_WINDOW_BG);
    selection_color(theme.selection);
    labelfont(FL_HELVETICA);
    labelsize(kTableFontSize);
    labelcolor(COLOR_TEXT);
}

void KTable::draw() {
    kPaintDebugTraceDraw("KTable", this);
    ensureSize(rows(), cols());
    Fl_Table::draw();
}

void KTable::draw_cell(TableContext context, int r, int c, int x, int y, int w, int h) {
    const KTheme& theme = KThemeManager::instance().theme();
    switch (context) {
    case CONTEXT_STARTPAGE:
        fl_font(FL_HELVETICA, kTableFontSize);
        return;
    case CONTEXT_TABLE:
        // Never clear the whole table body from CONTEXT_TABLE. On focus or
        // selection damage, FLTK may call this context for a large rectangle
        // and then redraw only the changed cells; broad clearing is the direct
        // cause of "selected cell erases other cells".
        drawTableDeadZone(this, x, y, w, h, theme.windowBg);
        return;
    case CONTEXT_COL_HEADER:
        fl_push_clip(x, y, w, h);
        fl_color(theme.primary);
        fl_rectf(x, y, w, h);
        drawTableText(colHeaderLabel(c), x + 6, y, w - 12, h, FL_WHITE, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
        drawCellGrid(x, y, w, h, theme.border);
        fl_pop_clip();
        return;
    case CONTEXT_ROW_HEADER: {
        char rowLabel[32] = {};
        std::snprintf(rowLabel, sizeof(rowLabel), "%d", r + 1);
        fl_push_clip(x, y, w, h);
        fl_color(theme.controlAltBg);
        fl_rectf(x, y, w, h);
        drawTableText(rowLabel, x + 4, y, w - 8, h, theme.mutedText, FL_ALIGN_RIGHT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
        drawCellGrid(x, y, w, h, theme.border);
        fl_pop_clip();
        return;
    }
    case CONTEXT_CELL:
        fl_push_clip(x, y, w, h);
        // Use the widget's current selection_color() like the historical
        // FlatTable implementation, so runtime theme refreshes and callers that
        // customize selection color both remain respected.
        fl_color(is_selected(r, c) ? selection_color() : (r % 2 == 0 ? theme.controlBg : theme.controlAltBg));
        fl_rectf(x, y, w, h);
        drawTableText(cell(r, c), x + 6, y, w - 12, h, theme.text, FL_ALIGN_LEFT | FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
        drawCellGrid(x, y, w, h, theme.border);
        fl_pop_clip();
        return;
    default:
        break;
    }
    Fl_Table::draw_cell(context, r, c, x, y, w, h);
}

int KTable::handle(int event) {
    if (event == FL_PUSH && Fl::event_button() == FL_RIGHT_MOUSE) {
        contextMenuX_ = Fl::event_x_root();
        contextMenuY_ = Fl::event_y_root();
        int row = -1;
        int col = -1;
        ResizeFlag resizeFlag = RESIZE_NONE;
        TableContext context = cursor2rowcol(row, col, resizeFlag);
        if (context == CONTEXT_CELL && triggerContextMenuCallback(row, col)) {
            redraw();
            return 1;
        }
        if (context == CONTEXT_ROW_HEADER && triggerContextMenuCallback(row, -1)) {
            redraw();
            return 1;
        }
    }
    return Fl_Table::handle(event);
}

void KTable::setSize(int rowsValue, int colsValue) {
    ensureSize(rowsValue, colsValue);
    row_height_all(rowHeight_);
    col_width_all(colWidth_);
    redraw();
}

void KTable::setColHeaderLabel(int col, const char* label) {
    if (col < 0) {
        return;
    }
    ensureSize(rows(), std::max(cols(), col + 1));
    colLabels_[static_cast<std::size_t>(col)] = label ? label : "";
    redraw();
}

const char* KTable::colHeaderLabel(int col) const {
    if (col >= 0 && col < static_cast<int>(colLabels_.size())) {
        return colLabels_[static_cast<std::size_t>(col)].c_str();
    }
    return "";
}

void KTable::setCell(int row, int col, const char* text) {
    if (row < 0 || col < 0) {
        return;
    }
    ensureSize(std::max(rows(), row + 1), std::max(cols(), col + 1));
    cells_[static_cast<std::size_t>(row)][static_cast<std::size_t>(col)] = text ? text : "";
    redraw();
}

const char* KTable::cell(int row, int col) const {
    if (row >= 0 && row < static_cast<int>(cells_.size()) && col >= 0 && col < static_cast<int>(cells_[static_cast<std::size_t>(row)].size())) {
        return cells_[static_cast<std::size_t>(row)][static_cast<std::size_t>(col)].c_str();
    }
    return "";
}

void KTable::setRowHeight(int h) {
    if (h <= 0) {
        return;
    }
    rowHeight_ = h;
    row_height_all(rowHeight_);
    redraw();
}

void KTable::setColWidth(int width) {
    if (width <= 0) {
        return;
    }
    colWidth_ = width;
    col_width_all(colWidth_);
    redraw();
}

void KTable::setRowContextMenuCallback(int row, ContextMenuCallback callback, void* userData) {
    if (row < 0) {
        return;
    }
    ensureSize(std::max(rows(), row + 1), cols());
    rowContextMenuCallbacks_[static_cast<std::size_t>(row)].callback = callback;
    rowContextMenuCallbacks_[static_cast<std::size_t>(row)].userData = userData;
}

void KTable::setCellContextMenuCallback(int row, int col, ContextMenuCallback callback, void* userData) {
    if (row < 0 || col < 0) {
        return;
    }
    ensureSize(std::max(rows(), row + 1), std::max(cols(), col + 1));
    cellContextMenuCallbacks_[static_cast<std::size_t>(row)][static_cast<std::size_t>(col)].callback = callback;
    cellContextMenuCallbacks_[static_cast<std::size_t>(row)][static_cast<std::size_t>(col)].userData = userData;
}

void KTable::contextMenuPosition(int& xOut, int& yOut) const {
    xOut = contextMenuX_;
    yOut = contextMenuY_;
}

void KTable::ensureSize(int rowsValue, int colsValue) {
    if (rowsValue < 0 || colsValue < 0) {
        return;
    }
    if (rows() != rowsValue) {
        rows(rowsValue);
    }
    if (cols() != colsValue) {
        cols(colsValue);
    }
    colLabels_.resize(static_cast<std::size_t>(colsValue));
    cells_.resize(static_cast<std::size_t>(rowsValue));
    for (auto& row : cells_) {
        row.resize(static_cast<std::size_t>(colsValue));
    }
    rowContextMenuCallbacks_.resize(static_cast<std::size_t>(rowsValue));
    cellContextMenuCallbacks_.resize(static_cast<std::size_t>(rowsValue));
    for (auto& callbacks : cellContextMenuCallbacks_) {
        callbacks.resize(static_cast<std::size_t>(colsValue));
    }
}

bool KTable::triggerContextMenuCallback(int row, int col) {
    if (row < 0 || row >= rows()) {
        return false;
    }
    ensureSize(rows(), cols());
    if (col >= 0 && col < cols()) {
        ContextMenuBinding& cellBinding = cellContextMenuCallbacks_[static_cast<std::size_t>(row)][static_cast<std::size_t>(col)];
        if (cellBinding.callback) {
            cellBinding.callback(this, row, col, cellBinding.userData);
            return true;
        }
    }
    ContextMenuBinding& rowBinding = rowContextMenuCallbacks_[static_cast<std::size_t>(row)];
    if (rowBinding.callback) {
        rowBinding.callback(this, row, col, rowBinding.userData);
        return true;
    }
    return false;
}

#pragma once

class QApplication;
class QAbstractItemView;

namespace ks::ui
{
    // installGlobalTableColumnAutoFit:
    // - Install a global table column width auto-fit filter on QApplication once.
    // - The filter only handles views with horizontal headers, such as QTableView, QTableWidget, QTreeView, and QTreeWidget.
    // - On initial display, layout changes, or viewport size changes, first estimate the preferred width based on headers or sampled content, then compress the total width into the current viewport.
    // - Also listen to the table viewport's actual Resize events to prevent the table from displaying with a temporary width after the initial layout of Dock/Tab/Splitter components.
    // - Widgets set via setCellWidget/indexWidget participate in minimum column width calculations; checkboxes, combo boxes, and buttons will not be compressed or misaligned by default.
    // - Short text columns remain compact; long text columns receive more remaining space.
    // - Compression has a 'readable lower bound': columns will not be compressed to the point where headers become unreadable. When the number of columns exceeds the capacity of this lower
    //   bound, the total column width remains larger than the viewport, causing a horizontal scrollbar to appear naturally rather than compressing all columns into a single row of ellipses.
    // - Do not modify horizontal/vertical scrollbar policies; after the user manually widens a column, the horizontal scrollbar will still appear naturally.
    // Parameter appInstance: the current QApplication instance; ignored if null.
    // Return value: None. Repeated calls are deduplicated by QApplication properties.
    void installGlobalTableColumnAutoFit(QApplication* appInstance);

    // requestTableColumnAutoFit:
    // - Request column width auto-fit once for a single QTableView/QTableWidget/QTreeView/QTreeWidget.
    // - Internally reuses global content-aware auto-fit logic; by default, pushes visible columns into the current viewport.
    // - Requests are merged into the queue tail and executed only once; multi-round periodic correction is not used.
    // - If the table columns have already been manually resized by the user, retain the user-defined widths and skip this request.
    // Parameter view: The target table/tree view; ignored if null or unsupported.
    // Return value: None. Does not modify horizontal or vertical scroll bar policies.
    void requestTableColumnAutoFit(QAbstractItemView* view);

    // setTableColumnAutoFitEnabled:
    // - Enables or disables global column width auto-fit for a single QTableView/QTreeView control.
    // - Inputs: view (target table/tree view); enabled=true allows global fit, enabled=false skips entirely;
    // - Processing: Clear pending requests on close to prevent views that manage column widths themselves (e.g., file managers) from having their layout expanded by global logic.
    // - Return value: None. Invalid or unsupported views are ignored.
    void setTableColumnAutoFitEnabled(QAbstractItemView* view, bool enabled);
}

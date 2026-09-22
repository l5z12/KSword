#pragma once

class QTableWidget;

namespace ks::ui
{
    // installTableHeaderClickSorting:
    // - Install header click sorting for QTableWidget instances where Qt continuous sorting is not enabled.
    // - Perform a full table sort only once per click without changing sortingEnabled to prevent rows from being moved prematurely during subsequent cell-by-cell population;
    // Tables with native sorting enabled continue to be handled by Qt; repeated calls do not duplicate signal connections.
    // Called by: pass the table pointer after general table configuration is complete and the internal model exists.
    // Accepts tableWidget: the table requiring header sorting support; returns nothing.
    void installTableHeaderClickSorting(QTableWidget* tableWidget);

    // setTableHeaderClickSortingEnabled:
    // - Controls whether generic one-time header sorting is enabled;
    // - Pass false for tables with fixed row semantics, such as those relying on call stack or collection order;
    // - This switch does not modify the sortingEnabled state explicitly set by business logic.
    // Note: Pass tableWidget: the target table; enabled: true allows click-to-sort, false preserves fixed row order.
    // Output: None.
    void setTableHeaderClickSortingEnabled(
        QTableWidget* tableWidget,
        bool enabled);
}

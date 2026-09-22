#pragma once

#include "TableSnapshotCompare.h"

#include <QAbstractTableModel>
#include <QList>
#include <QObject>
#include <QPersistentModelIndex>
#include <QPointer>

class QEvent;
class QTableView;

namespace ks::ui
{
    // TablePausedSnapshotModel:
    // - Expose the TableSnapshot captured when refreshing stops as a read-only table model;
    // - The model is completely independent of the real-time business model; background refreshes do not alter the currently displayed content.
    class TablePausedSnapshotModel final : public QAbstractTableModel
    {
    public:
        explicit TablePausedSnapshotModel(
            TableSnapshot snapshot,
            QObject* parent = nullptr);

        const TableSnapshot& snapshot() const;

        int rowCount(const QModelIndex& parent = QModelIndex()) const override;
        int columnCount(const QModelIndex& parent = QModelIndex()) const override;
        QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
        QVariant headerData(
            int section,
            Qt::Orientation orientation,
            int role = Qt::DisplayRole) const override;
        Qt::ItemFlags flags(const QModelIndex& index) const override;

    private:
        TableSnapshot snapshot_;
    };

    // TableFrozenPaneController:
    // - "Freeze rows/columns": Pin selected rows directly below the list header and fix selected columns to the right of the row header;
    // - Only freeze the selected rows/columns themselves, without freezing content above or to the left.
    // - Frozen rows and columns are removed from the scrollable area and occupy space separately (by shrinking the viewport via TableActionBarHost);
    //   all other content—including rows and columns before the freeze point—remains fully scrollable without ghosting or unreachable areas.
    // - Frozen items are tracked using persistent model indices, so they remain pinned to the same row data after row/column insertions, deletions, or sorting; they are automatically unpinned when the entire model is replaced;
    // - The frozen area total must not exceed half of the available size; rows and columns exceeding the budget are not accepted for freezing.
    // The target table must implement TableActionBarHost (such as VisibleTableWidget or TableActionTableView).
    //   A standard QTableView cannot reserve the viewport, so canFreeze() will return false.
    class TableFrozenPaneController final : public QObject
    {
    public:
        explicit TableFrozenPaneController(QObject* parent = nullptr);
        ~TableFrozenPaneController() override;

        void setTargetTable(QTableView* tableView);
        QTableView* targetTable() const;

        // canFreeze purpose: Determines if the target table has viewport reservation capability, deciding whether the freeze menu is available.
        bool canFreeze() const;

        // freezeRows: Freezes the given logical rows (typically selected rows). Returns the count of newly frozen
        // rows. 0 indicates invalid rows, already frozen rows, or insufficient freeze budget, with no changes made.
        int freezeRows(const QList<int>& logicalRows);
        int freezeColumns(const QList<int>& logicalColumns);

        void clearFrozenRows();
        void clearFrozenColumns();
        void clearFrozenPanes();

        int frozenRowCount() const;
        int frozenColumnCount() const;

        void refreshGeometry();

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // FrozenLine purpose: A frozen row or column.
        struct FrozenLine
        {
            QPersistentModelIndex index; // Row freeze stores (row, 0); column freeze stores (0, column); automatically shifts on model insert/delete or sort.
            int extent = 0;              // Row height/column width captured during freezing; the source table hides these rows/columns, making original dimensions unreadable.
            // section is the last known logical row/column. The persistent index is anchored to cells; after the table
            // calls setRowCount(0) to refill, it becomes invalid, while the column's hidden bit is not cleared accordingly.
            // Without it, hidden states cannot be restored, and frozen states cannot be re-anchored.
            int section = -1;
        };

        void disconnectTarget();
        void connectTarget();
        void scheduleRefresh();
        void releaseTarget();
        // Publish the current frozen row/column indices to the target table properties so the data retrieval side can distinguish between frozen and filtered states.
        void publishFrozenSections();
        void destroyPanes();
        void ensurePanes();
        QTableView* createPane(QPointer<QTableView>& guardedPane);
        void configurePane(QTableView* pane, bool showHorizontalHeader, bool showVerticalHeader);
        void bridgeFrozenHeader(QTableView* pane);
        void mirrorColumnLayout(QTableView* pane);
        void mirrorRowLayout(QTableView* pane, int firstLogicalRow, int lastLogicalRow);
        void mirrorVisibleRowLayout(QTableView* pane);
        void applyFrozenRowFilter(QTableView* pane);
        void applyFrozenColumnFilter(QTableView* pane);
        void enforceFrozenState();
        void unfreezeAllRows();
        void unfreezeAllColumns();
        void layoutPanes();
        void syncPanes();
        void setPaneVerticalToSource(QTableView* pane);
        void setPaneHorizontalToSource(QTableView* pane);

        int totalFrozenRowsHeight() const;
        int totalFrozenColumnsWidth() const;
        int frozenRowsBudget() const;
        int frozenColumnsBudget() const;

        QPointer<QTableView> targetTable_;
        QPointer<QAbstractItemModel> targetModel_;
        QPointer<QTableView> topPane_;
        QPointer<QTableView> leftPane_;
        QPointer<QTableView> cornerPane_;
        QList<FrozenLine> frozenRowLines_;
        QList<FrozenLine> frozenColumnLines_;
        int appliedFrozenWidth_ = 0;
        int appliedFrozenHeight_ = 0;
        bool refreshing_ = false;
        bool refreshScheduled_ = false;
        bool mirroringSections_ = false;
    };

    /*
     * Freezing moves rows/columns from the main table to the frozen pane via setRowHidden/setColumnHidden,
     * sharing the same state bit as "filtered out" rows/columns in QTableView. Any code fetching data
     * based on "visible rows/columns" (copy, export, snapshot diff) must first call these functions;
     * otherwise, rows/columns explicitly pinned by the user will be missing from the export results.
     */
    bool isRowHiddenByFreeze(const QTableView* tableView, int row);
    bool isColumnHiddenByFreeze(const QTableView* tableView, int column);
}

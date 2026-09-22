#include "TableHeaderSortingSupport.h"

#include <QAbstractItemModel>
#include <QHeaderView>
#include <QList>
#include <QModelIndex>
#include <QPointer>
#include <QTableWidget>
#include <QVariant>

namespace
{
    // The following dynamic properties only store the installation status of generic table header sorting and the state of the most recent manual sort.
    // Attach the property to the table object to avoid lifecycle desynchronization with an extra controller.
    constexpr char kHeaderSortingInstalledProperty[] =
        "KSWORD_TABLE_HEADER_SORTING_INSTALLED";
    constexpr char kHeaderSortingDisabledProperty[] =
        "KSWORD_TABLE_HEADER_SORTING_DISABLED";
    constexpr char kManualSortActiveProperty[] =
        "KSWORD_TABLE_HEADER_MANUAL_SORT_ACTIVE";
    constexpr char kManualSortColumnProperty[] =
        "KSWORD_TABLE_HEADER_MANUAL_SORT_COLUMN";
    constexpr char kManualSortOrderProperty[] =
        "KSWORD_TABLE_HEADER_MANUAL_SORT_ORDER";

    // clearManualSortState:
    // - Clear general sort records and hide header arrows specific to general sorting as needed.
    // - When native sortingEnabled is true, the caller skips this function to avoid hiding Qt's own arrows.
    // Passes tableWidget (target table) and hideIndicator (whether to hide the sort indicator); returns nothing.
    void clearManualSortState(
        QTableWidget* tableWidget,
        const bool hideIndicator)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setProperty(kManualSortActiveProperty, false);
        tableWidget->setProperty(kManualSortColumnProperty, -1);
        tableWidget->setProperty(
            kManualSortOrderProperty,
            static_cast<int>(Qt::AscendingOrder));

        QHeaderView* const kHeaderView = tableWidget->horizontalHeader();
        if (hideIndicator && kHeaderView != nullptr)
        {
            kHeaderView->setSortIndicatorShown(false);
        }
    }

    // invalidateManualSortAfterDataChange:
    // - Revert manual sort flag after data source changes (add/delete/reset/cell modification);
    // - Do not automatically re-sort new data to avoid moving rows that are not yet fully populated during asynchronous batch filling.
    // - Users can click the header again to sort by the new snapshot.
    void invalidateManualSortAfterDataChange(
        const QPointer<QTableWidget>& guardedTable)
    {
        if (guardedTable.isNull() || guardedTable->isSortingEnabled())
        {
            return;
        }
        if (!guardedTable->property(kManualSortActiveProperty).toBool())
        {
            return;
        }

        clearManualSortState(guardedTable.data(), true);
    }

    // nextSortOrder:
    // - First click on a new column uses ascending order; consecutive clicks on the same column toggle between ascending and descending.
    // - The most recent column and sort order are read from the table's dynamic properties, avoiding reliance on default values from QHeaderView when not displayed.
    // Passes tableWidget (target table) and logicalColumn (column clicked this time); returns the sort order for this click.
    Qt::SortOrder nextSortOrder(
        const QTableWidget* tableWidget,
        const int logicalColumn)
    {
        const bool kManualSortActive =
            tableWidget->property(kManualSortActiveProperty).toBool();
        const int kPreviousColumn =
            tableWidget->property(kManualSortColumnProperty).toInt();
        if (!kManualSortActive || kPreviousColumn != logicalColumn)
        {
            return Qt::AscendingOrder;
        }

        const auto kPreviousOrder = static_cast<Qt::SortOrder>(
            tableWidget->property(kManualSortOrderProperty).toInt());
        return kPreviousOrder == Qt::AscendingOrder
            ? Qt::DescendingOrder
            : Qt::AscendingOrder;
    }

    // sortByClickedHeader:
    // - Responds to a single horizontal header click and sorts the complete internal model of the QTableWidget.
    // - Does not intervene when native persistent sorting is enabled or when business logic disables generic sorting.
    // - Return: None. Sorting results are reflected directly in the target table.
    void sortByClickedHeader(
        QTableWidget* tableWidget,
        const int logicalColumn)
    {
        if (tableWidget == nullptr ||
            tableWidget->property(kHeaderSortingDisabledProperty).toBool() ||
            logicalColumn < 0 ||
            logicalColumn >= tableWidget->columnCount())
        {
            return;
        }

        // Qt's native sorting is already connected to header signals; this step only clears the old manual state to avoid executing sorting twice.
        if (tableWidget->isSortingEnabled())
        {
            tableWidget->setProperty(kManualSortActiveProperty, false);
            return;
        }

        const Qt::SortOrder kSortOrder = nextSortOrder(tableWidget, logicalColumn);
        tableWidget->setProperty(kManualSortActiveProperty, true);
        tableWidget->setProperty(kManualSortColumnProperty, logicalColumn);
        tableWidget->setProperty(kManualSortOrderProperty, static_cast<int>(kSortOrder));

        tableWidget->sortItems(logicalColumn, kSortOrder);
        QHeaderView* const kHeaderView = tableWidget->horizontalHeader();
        if (kHeaderView != nullptr)
        {
            kHeaderView->setSortIndicator(logicalColumn, kSortOrder);
            kHeaderView->setSortIndicatorShown(true);
        }
    }
}

namespace ks::ui
{
    void installTableHeaderClickSorting(QTableWidget* tableWidget)
    {
        if (tableWidget == nullptr ||
            tableWidget->model() == nullptr ||
            tableWidget->property(kHeaderSortingInstalledProperty).toBool())
        {
            return;
        }

        QHeaderView* const kHeaderView = tableWidget->horizontalHeader();
        if (kHeaderView == nullptr)
        {
            return;
        }

        tableWidget->setProperty(kHeaderSortingInstalledProperty, true);
        kHeaderView->setSectionsClickable(true);
        const QPointer<QTableWidget> kGuardedTable(tableWidget);

        QObject::connect(
            kHeaderView,
            &QHeaderView::sectionClicked,
            tableWidget,
            [kGuardedTable](const int logicalColumn)
            {
                sortByClickedHeader(kGuardedTable.data(), logicalColumn);
            });

        // The internal QTableWidget model shares the table's lifetime. Any data change only invalidates old arrows; re-sorting is
        // not performed within the fill signal, ensuring compatibility with both synchronous and timer-based batch refresh modes.
        QAbstractItemModel* const kTableModel = tableWidget->model();
        QObject::connect(
            kTableModel,
            &QAbstractItemModel::modelReset,
            tableWidget,
            [kGuardedTable]()
            {
                invalidateManualSortAfterDataChange(kGuardedTable);
            });
        QObject::connect(
            kTableModel,
            &QAbstractItemModel::rowsInserted,
            tableWidget,
            [kGuardedTable](const QModelIndex&, const int, const int)
            {
                invalidateManualSortAfterDataChange(kGuardedTable);
            });
        QObject::connect(
            kTableModel,
            &QAbstractItemModel::rowsRemoved,
            tableWidget,
            [kGuardedTable](const QModelIndex&, const int, const int)
            {
                invalidateManualSortAfterDataChange(kGuardedTable);
            });
        QObject::connect(
            kTableModel,
            &QAbstractItemModel::dataChanged,
            tableWidget,
            [kGuardedTable](const QModelIndex&, const QModelIndex&, const QList<int>&)
            {
                invalidateManualSortAfterDataChange(kGuardedTable);
            });
    }

    void setTableHeaderClickSortingEnabled(
        QTableWidget* tableWidget,
        const bool enabled)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setProperty(kHeaderSortingDisabledProperty, !enabled);
        if (!enabled && !tableWidget->isSortingEnabled())
        {
            clearManualSortState(tableWidget, true);
        }
    }
}

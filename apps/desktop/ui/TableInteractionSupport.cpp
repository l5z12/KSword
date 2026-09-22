#include "TableInteractionSupport.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"
#include "TableFreezeSupport.h"
#include "TableHeaderSortingSupport.h"
#include "TableSnapshotCompare.h"
#include "TableSearchSupport.h"
#include "VisibleTableWidget.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QDateTime>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTreeView>
#include <QIcon>
#include <QItemSelectionModel>
#include <QKeyEvent>
#include <QKeySequence>
#include <QComboBox>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPalette>
#include <QPointer>
#include <QSaveFile>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QStringConverter>
#include <QTableView>
#include <QTextStream>
#include <QTimer>
#include <QToolButton>
#include <QVariant>
#include <QVector>
#include <QWheelEvent>
#include <QWidget>

#include <algorithm>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    using ks::ui::TableComparisonModel;
    using ks::ui::TableComparisonResult;
    using ks::ui::TableFrozenPaneController;
    using ks::ui::TablePausedSnapshotModel;
    using ks::ui::TableSnapshot;
    using ks::ui::TableSnapshotCaptureLimits;
    using ks::ui::TableSnapshotColumn;
    using ks::ui::TableSnapshotCompareEngine;
    using ks::ui::TableSnapshotComparisonLimits;
    using ks::ui::TableSnapshotRetentionLimits;
    using ks::ui::TableSnapshotRetentionResult;
    using ks::ui::TableActionBarMode;

    constexpr char kInstalledProperty[] = "KSWORD_TABLE_INTERACTION_SUPPORT_INSTALLED";
    constexpr char kActionBarProperty[] = "KSWORD_TABLE_INTERACTION_ACTION_BAR";
    constexpr char kStandardContextMenuProperty[] = "KSWORD_TABLE_INTERACTION_STANDARD_CONTEXT_MENU";
    constexpr char kContextActionsInstalledProperty[] = "KSWORD_TABLE_INTERACTION_CONTEXT_ACTIONS_INSTALLED";
    constexpr char kComparisonActiveProperty[] = "KSWORD_TABLE_INTERACTION_COMPARISON_ACTIVE";
    constexpr char kContextMenuDepthProperty[] = "KSWORD_TABLE_CONTEXT_MENU_DEPTH";
    constexpr int kActionBarHeight = 32;
    constexpr quint64 kBytesPerMiB = 1024ULL * 1024ULL;
    constexpr TableSnapshotCaptureLimits kSnapshotCaptureLimits{};
    constexpr TableSnapshotComparisonLimits kSnapshotComparisonLimits{};
    constexpr TableSnapshotRetentionLimits kSnapshotRetentionLimits{};

    const QString& standardTableHeaderStyle()
    {
        static const QString kStyle = QStringLiteral(
            "QHeaderView{"
            "  background-color:transparent;"
            "  border:none;"
            "}"
            "QHeaderView::section{"
            "  background-color:palette(alternate-base);"
            "  color:palette(text);"
            "  border:none;"
            "  border-right:1px solid palette(mid);"
            "  border-bottom:1px solid palette(midlight);"
            "  padding:3px 6px;"
            "  font-weight:400;"
            "}"
            "QHeaderView::section:hover{"
            "  background-color:palette(button);"
            "}");
        return kStyle;
    }

    void applyStandardTableHeaderStyle(QTableView* tableView)
    {
        if (tableView == nullptr || ks::ui::preservesCustomTableHeaderStyle(tableView))
        {
            return;
        }

        const QString& style = standardTableHeaderStyle();
        const auto kApplyToHeader = [&style](QHeaderView* header)
        {
            if (header != nullptr && header->styleSheet() != style)
            {
                header->setStyleSheet(style);
            }
        };
        kApplyToHeader(tableView->horizontalHeader());
        kApplyToHeader(tableView->verticalHeader());
    }

    // DeferredTableUiCommit：
    // - Save UI commits that were merged and overwritten while the right-click menu was open.
    // - owner/key together identify a refresh class; itemViewList determines when it is safe to re-inject.
    struct DeferredTableUiCommit
    {
        QPointer<QObject> owner;                         // owner: Lifecycle object receiving the delayed callback.
        QString commitKey;                              // commitKey: Refresh deduplication key within the same owner.
        QList<QPointer<QAbstractItemView>> itemViewList; // itemViewList: Tables or trees that may be rebuilt in this submission.
        std::function<void()> commitAction;              // commitAction: The latest UI commit action executed after the menu closes.
    };

    // deferredTableUiCommits:
    // - Returns the shared commit queue within the GUI thread;
    // - The queue is accessed only by the global table event filter and refresh entry points; no cross-thread calls are made.
    QVector<DeferredTableUiCommit>& deferredTableUiCommits()
    {
        static QVector<DeferredTableUiCommit> commitList;
        return commitList;
    }

    // isComboBoxPopupOpen:
    // - Returns whether a QComboBox popup is currently expanded.
    // Popups are independent top-level windows that capture mouse and keyboard input. If the background refreshes and repopulates the dropdown while the popup
    //   is active, the popup continues to capture input but the content becomes stale, resulting in the UI appearing unresponsive after clicking the dropdown.
    // - Criterion uses the parent of activePopupWidget: The parent of a QComboBox popup container is the combo box
    //   itself, whereas the parent of a context menu is not, so the two criteria do not interfere with each other.
    bool isComboBoxPopupOpen()
    {
        QWidget* const kActivePopupWidget = QApplication::activePopupWidget();
        if (kActivePopupWidget == nullptr)
        {
            return false;
        }
        return qobject_cast<QComboBox*>(kActivePopupWidget->parentWidget()) != nullptr;
    }

    // isLeftCtrlHeldForMultiSelect:
    // - Returns whether the left Ctrl key is currently in a physically pressed state (Issue #149).
    // - When the user holds Left Ctrl for multi-row selection, any table refresh must trigger cached refresh just like when opening
    //   a context menu; otherwise, periodic refreshes that rebuild the model will clear selections and interrupt the operation.
    // - Only query the left Ctrl key to align with the requirement 'check if the left Ctrl is pressed once', without intercepting the right Ctrl.
    bool isLeftCtrlHeldForMultiSelect()
    {
        return (::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0;
    }

    // isDeferredTableUiCommitBlocked:
    // - Returns whether a deferred commit still requires caching: if any table/tree is within a menu lifecycle or the left Ctrl key is still held.
    // - Re-check before each actual execution to override re-entrant scenarios where a new menu is synchronously opened during the flush process or the user is still in multi-select mode.
    bool isDeferredTableUiCommitBlocked(const DeferredTableUiCommit& pendingCommit)
    {
        if (isLeftCtrlHeldForMultiSelect() || isComboBoxPopupOpen())
        {
            return true;
        }
        return std::any_of(
            pendingCommit.itemViewList.cbegin(),
            pendingCommit.itemViewList.cend(),
            [](const QPointer<QAbstractItemView>& guardedItemView)
            {
                return !guardedItemView.isNull() &&
                    guardedItemView->property(kContextMenuDepthProperty).toInt() > 0;
            });
    }

    // isItemViewContextMenuOpen:
    // - Determine whether the table/tree right-click menu is still within a nested event loop based on the depth attribute maintained by the global event filter.
    // - Return false for null views or zero depth.
    bool isItemViewContextMenuOpen(const QAbstractItemView* itemView)
    {
        return itemView != nullptr &&
            itemView->property(kContextMenuDepthProperty).toInt() > 0;
    }

    // beginItemViewContextMenu:
    // - Increase table/tree menu depth after the business menu enters exec/popup;
    // - Use a counter instead of a simple boolean when dealing with multi-level menus or consecutive popups.
    void beginItemViewContextMenu(QAbstractItemView* itemView)
    {
        if (itemView == nullptr)
        {
            return;
        }

        const int kCurrentDepth = itemView->property(kContextMenuDepthProperty).toInt();
        itemView->setProperty(kContextMenuDepthProperty, kCurrentDepth + 1);
    }

    // flushDeferredTableUiCommits:
    // - Scan the pending commit queue after the menu is closed.
    // - Only executes the latest commit when all related tables have exited menu state.
    // - Reviews menu status item-by-item before execution to prevent the menu from reopening between flush and a second dispatch.
    void flushDeferredTableUiCommits()
    {
        QVector<DeferredTableUiCommit>& commitList = deferredTableUiCommits();
        for (int commitIndex = 0; commitIndex < commitList.size();)
        {
            DeferredTableUiCommit& pendingCommit = commitList[commitIndex];
            if (pendingCommit.owner.isNull())
            {
                commitList.removeAt(commitIndex);
                continue;
            }

            if (isDeferredTableUiCommitBlocked(pendingCommit))
            {
                ++commitIndex;
                continue;
            }

            // Remove the current commit first, then execute the user callback; even if the callback re-enters and modifies the queue, no dangling references will occur.
            const QPointer<QObject> kOwner = pendingCommit.owner;
            std::function<void()> commitAction = std::move(pendingCommit.commitAction);
            commitList.removeAt(commitIndex);
            if (!kOwner.isNull() && commitAction)
            {
                commitAction();
            }

            // commitAction allows entering a nested event loop and modifying the queue; re-scan from the start to avoid skipping moved items.
            commitIndex = 0;
        }
    }

    // scheduleDeferredTableUiCommitFlush:
    // - Schedule a single flush to the outer event loop to re-inject merged table refreshes after the left Ctrl key is released;
    // - The same path may be triggered consecutively, but the queue is cleared after flushing, so repeated scheduling naturally converges to a no-op.
    // - The flush operation re-checks isDeferredTableUiCommitBlocked item by item; it will not submit prematurely while the left Ctrl key is held.
    void scheduleDeferredTableUiCommitFlush()
    {
        if (qApp == nullptr)
        {
            flushDeferredTableUiCommits();
            return;
        }
        QTimer::singleShot(0, qApp, []()
            {
                flushDeferredTableUiCommits();
            });
    }

    // scheduleItemViewContextMenuEnd:
    // - The menu Hide event occurs before QMenu::exec returns;
    // - Schedule depth reduction and retroactive processing together in the outer event loop to ensure business slots complete old row/node actions first;
    // - New refreshes between Hide and re-injection can still see the positive depth, so they also enter the delay queue.
    void scheduleItemViewContextMenuEnd(QAbstractItemView* itemView)
    {
        const QPointer<QAbstractItemView> kGuardedItemView(itemView);
        const auto kFinishContextMenu = [kGuardedItemView]()
            {
                if (!kGuardedItemView.isNull())
                {
                    const int kCurrentDepth =
                        kGuardedItemView->property(kContextMenuDepthProperty).toInt();
                    kGuardedItemView->setProperty(
                        kContextMenuDepthProperty,
                        std::max(0, kCurrentDepth - 1));
                }
                flushDeferredTableUiCommits();
            };
        if (qApp == nullptr)
        {
            kFinishContextMenu();
            return;
        }
        QTimer::singleShot(0, qApp, kFinishContextMenu);
    }

    // endItemViewContextMenu:
    // - Schedule the context menu to hide or destroy after business action handlers complete to reduce depth.
    // - After the bottom-level menu exits, re-inject the merged table/tree refresh.
    void endItemViewContextMenu(QAbstractItemView* itemView)
    {
        scheduleItemViewContextMenuEnd(itemView);
    }

    // deferItemViewUiCommitIfNeeded:
    // - If any target table/tree menu is open, or the user is still holding Ctrl for multi-selection (Issue #149),
    //   overwrite the previous commit by owner/key to prevent high-frequency refresh backlog and clear multi-selection.
    // - Return false if neither condition holds; the caller continues the current UI commit flow.
    bool deferItemViewUiCommitIfNeeded(
        QObject* owner,
        const QString& commitKey,
        const QList<QAbstractItemView*>& itemViewList,
        std::function<void()> commitAction)
    {
        if (owner == nullptr || commitKey.isEmpty() || !commitAction)
        {
            return false;
        }

        bool contextMenuOpen = false;
        QList<QPointer<QAbstractItemView>> guardedItemViewList;
        guardedItemViewList.reserve(itemViewList.size());
        for (QAbstractItemView* itemView : itemViewList)
        {
            if (itemView == nullptr)
            {
                continue;
            }
            guardedItemViewList.push_back(QPointer<QAbstractItemView>(itemView));
            contextMenuOpen =
                contextMenuOpen || isItemViewContextMenuOpen(itemView);
        }
        // Cache refresh is deferred when the right-click menu is open, the user holds Left Ctrl for multi-selection (Issue #149), or a combo box popup is expanded.
        if (!contextMenuOpen && !isLeftCtrlHeldForMultiSelect() && !isComboBoxPopupOpen())
        {
            // No caching: If the queue still has pending commits from the left Ctrl hold (e.g., release events lost due
            // to focus loss), use this refresh to schedule a flush as a fallback, preventing old commits from lingering.
            if (!deferredTableUiCommits().isEmpty())
            {
                scheduleDeferredTableUiCommitFlush();
            }
            return false;
        }

        QVector<DeferredTableUiCommit>& commitList = deferredTableUiCommits();
        for (int commitIndex = 0; commitIndex < commitList.size(); ++commitIndex)
        {
            DeferredTableUiCommit& pendingCommit = commitList[commitIndex];
            if (pendingCommit.owner.data() == owner && pendingCommit.commitKey == commitKey)
            {
                // Updates with the same key are moved to the back of the queue to ensure they are committed in order of arrival after flushing.
                DeferredTableUiCommit updatedCommit;
                updatedCommit.owner = owner;
                updatedCommit.commitKey = commitKey;
                updatedCommit.itemViewList = std::move(guardedItemViewList);
                updatedCommit.commitAction = std::move(commitAction);
                commitList.removeAt(commitIndex);
                commitList.push_back(std::move(updatedCommit));
                return true;
            }
        }

        DeferredTableUiCommit pendingCommit;
        pendingCommit.owner = owner;
        pendingCommit.commitKey = commitKey;
        pendingCommit.itemViewList = std::move(guardedItemViewList);
        pendingCommit.commitAction = std::move(commitAction);
        commitList.push_back(std::move(pendingCommit));
        return true;
    }

    QString localizedSourceText(const char* sourceText)
    {
        return ks::i18n::sourceText(QString::fromUtf8(sourceText));
    }

    QTableView* tableForEventObject(QObject* watchedObject)
    {
        if (QTableView* tableView = qobject_cast<QTableView*>(watchedObject))
        {
            return tableView;
        }

        QTableView* tableView = qobject_cast<QTableView*>(watchedObject != nullptr
            ? watchedObject->parent()
            : nullptr);
        if (tableView != nullptr && watchedObject == tableView->viewport())
        {
            return tableView;
        }
        return nullptr;
    }

    // itemViewForEventObject:
    // - Resolve a QTableView/QTreeView, its viewport, or its QHeaderView to the owning application view;
    // - Used only for menu lifecycle barriers; does not alter the scope of the global table toolbar.
    QAbstractItemView* itemViewForEventObject(QObject* watchedObject)
    {
        QHeaderView* headerView = qobject_cast<QHeaderView*>(watchedObject);
        if (headerView == nullptr)
        {
            QHeaderView* parentHeader = qobject_cast<QHeaderView*>(
                watchedObject != nullptr ? watchedObject->parent() : nullptr);
            if (parentHeader != nullptr && watchedObject == parentHeader->viewport())
            {
                headerView = parentHeader;
            }
        }
        if (headerView != nullptr)
        {
            if (QAbstractItemView* parentItemView =
                    qobject_cast<QAbstractItemView*>(headerView->parent()))
            {
                return parentItemView;
            }
        }

        if (QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(watchedObject))
        {
            return itemView;
        }

        QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(
            watchedObject != nullptr ? watchedObject->parent() : nullptr);
        if (itemView != nullptr && watchedObject == itemView->viewport())
        {
            return itemView;
        }
        return nullptr;
    }

    QString normalizedTsvField(const QVariant& value)
    {
        QString text = value.toString();
        text.replace(QLatin1Char('\t'), QLatin1Char(' '));
        text.replace(QLatin1Char('\r'), QLatin1Char(' '));
        text.replace(QLatin1Char('\n'), QLatin1Char(' '));
        return text;
    }

    /*
     * Copy, export, and snapshot comparison operations only retrieve visible rows and columns. Freezing is implemented via
     * setRowHidden/setColumnHidden and shares the same state bit with filtering. Without distinguishing them, rows/columns explicitly pinned by the
     * user would disappear from the exported forensic data without any warning. Here, only rows/columns truly filtered out are considered invisible.
     */
    bool isRowHiddenByFilter(const QTableView* tableView, const int row)
    {
        if (tableView == nullptr)
        {
            return false;
        }
        return tableView->isRowHidden(row) && !ks::ui::isRowHiddenByFreeze(tableView, row);
    }

    bool isColumnHiddenByFilter(const QTableView* tableView, const int column)
    {
        if (tableView == nullptr)
        {
            return false;
        }
        return tableView->isColumnHidden(column) && !ks::ui::isColumnHiddenByFreeze(tableView, column);
    }

    QVector<int> selectedVisibleRows(QTableView* tableView, const bool includeCurrentFallback)
    {
        QVector<int> rowList;
        if (tableView == nullptr || tableView->model() == nullptr || tableView->selectionModel() == nullptr)
        {
            return rowList;
        }

        const QModelIndexList kSelectedIndexList = tableView->selectionModel()->selectedIndexes();
        rowList.reserve(kSelectedIndexList.size());
        for (const QModelIndex& index : kSelectedIndexList)
        {
            if (index.isValid() && !isRowHiddenByFilter(tableView, index.row()))
            {
                rowList.push_back(index.row());
            }
        }

        std::sort(rowList.begin(), rowList.end());
        rowList.erase(std::unique(rowList.begin(), rowList.end()), rowList.end());

        if (rowList.isEmpty() && includeCurrentFallback)
        {
            const QModelIndex kCurrentIndex = tableView->currentIndex();
            if (kCurrentIndex.isValid() && !isRowHiddenByFilter(tableView, kCurrentIndex.row()))
            {
                rowList.push_back(kCurrentIndex.row());
            }
        }
        return rowList;
    }

    QVector<int> allVisibleRows(QTableView* tableView)
    {
        QVector<int> rowList;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return rowList;
        }

        const int kRowCount = tableView->model()->rowCount();
        rowList.reserve(kRowCount);
        for (int row = 0; row < kRowCount; ++row)
        {
            if (!isRowHiddenByFilter(tableView, row))
            {
                rowList.push_back(row);
            }
        }
        return rowList;
    }

    QVector<int> visibleColumns(const QTableView* tableView)
    {
        QVector<int> columnList;
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return columnList;
        }

        const int kColumnCount = tableView->model()->columnCount();
        columnList.reserve(kColumnCount);
        for (int column = 0; column < kColumnCount; ++column)
        {
            if (!isColumnHiddenByFilter(tableView, column))
            {
                columnList.push_back(column);
            }
        }
        return columnList;
    }

    QString tableRowsToTsv(
        QTableView* tableView,
        const QVector<int>& rowList,
        const bool includeHeader)
    {
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return {};
        }

        QAbstractItemModel* modelObject = tableView->model();
        const QVector<int> kColumnList = visibleColumns(tableView);
        if (rowList.isEmpty() || kColumnList.isEmpty())
        {
            return {};
        }

        QStringList lineList;
        lineList.reserve(rowList.size() + (includeHeader ? 1 : 0));
        if (includeHeader)
        {
            QStringList headerList;
            headerList.reserve(kColumnList.size());
            for (const int kColumn : kColumnList)
            {
                headerList.push_back(normalizedTsvField(
                    modelObject->headerData(kColumn, Qt::Horizontal, Qt::DisplayRole)));
            }
            lineList.push_back(headerList.join(QLatin1Char('\t')));
        }

        for (const int kRow : rowList)
        {
            if (kRow < 0 || kRow >= modelObject->rowCount() || isRowHiddenByFilter(tableView, kRow))
            {
                continue;
            }

            QStringList valueList;
            valueList.reserve(kColumnList.size());
            for (const int kColumn : kColumnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(modelObject->index(kRow, kColumn), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        return lineList.join(QLatin1Char('\n'));
    }

    void copyRowsToClipboard(QTableView* tableView, const QVector<int>& rowList)
    {
        if (QClipboard* clipboardObject = QApplication::clipboard())
        {
            const QString kText = tableRowsToTsv(tableView, rowList, false);
            if (!kText.isEmpty())
            {
                clipboardObject->setText(kText);
            }
        }
    }

    void copySelectedRowsToClipboard(QTableView* tableView)
    {
        copyRowsToClipboard(tableView, selectedVisibleRows(tableView, true));
    }

    void copyVisibleRowsToClipboard(QTableView* tableView)
    {
        copyRowsToClipboard(tableView, allVisibleRows(tableView));
    }

    // copySelectedTreeRowsToClipboard:
    // - Add Ctrl+C support for hierarchical views like QTreeView/QTreeWidget.
    // - The table path above works via 'flat parallel numbering,' which is meaningless for trees (row numbers repeat under different parent
    //   nodes). Therefore, this uses QModelIndex: traverse in visual order using indexBelow(), and when the selected row is hit, retrieve one row.
    //   Collapsed child nodes are naturally skipped by indexBelow, so the copy result matches exactly what the user sees.
    // - When no selection exists, fall back to the current row, maintaining consistency with the includeCurrentFallback semantics of the table path;
    // - Columns are output in header visual order, skipping hidden columns; when users reorder columns, the copied result follows the new order.
    // Input treeView: target tree view; ignored if null or has no model.
    // Returns: None; writes result to system clipboard.
    void copySelectedTreeRowsToClipboard(QTreeView* treeView)
    {
        if (treeView == nullptr || treeView->model() == nullptr)
        {
            return;
        }

        QItemSelectionModel* selectionModel = treeView->selectionModel();
        QAbstractItemModel* modelObject = treeView->model();
        if (selectionModel == nullptr)
        {
            return;
        }

        // Column order: prioritize the current visual header order; fall back to logical order if no header exists.
        QVector<int> columnList;
        const int kColumnCount = modelObject->columnCount(treeView->rootIndex());
        columnList.reserve(kColumnCount);
        QHeaderView* headerView = treeView->header();
        for (int position = 0; position < kColumnCount; ++position)
        {
            const int kLogicalColumn = headerView != nullptr
                ? headerView->logicalIndex(position)
                : position;
            if (kLogicalColumn >= 0 && !treeView->isColumnHidden(kLogicalColumn))
            {
                columnList.push_back(kLogicalColumn);
            }
        }
        if (columnList.isEmpty())
        {
            return;
        }

        QStringList lineList;
        for (QModelIndex walkIndex = modelObject->index(0, 0, treeView->rootIndex());
            walkIndex.isValid();
            walkIndex = treeView->indexBelow(walkIndex))
        {
            // Determine entire row selection using isSelected(column 0): all these trees are SelectRows, so selecting one selects the whole row.
            // We avoid `isRowSelected(row, parent)` because it has been deprecated since Qt 6.4.
            if (!selectionModel->isSelected(walkIndex))
            {
                continue;
            }

            QStringList valueList;
            valueList.reserve(columnList.size());
            for (const int kColumn : columnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(walkIndex.sibling(walkIndex.row(), kColumn), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        if (lineList.isEmpty())
        {
            const QModelIndex kCurrentIndex = selectionModel->currentIndex();
            if (!kCurrentIndex.isValid())
            {
                return;
            }

            QStringList valueList;
            valueList.reserve(columnList.size());
            for (const int kColumn : columnList)
            {
                valueList.push_back(normalizedTsvField(
                    modelObject->data(kCurrentIndex.sibling(kCurrentIndex.row(), kColumn), Qt::DisplayRole)));
            }
            lineList.push_back(valueList.join(QLatin1Char('\t')));
        }

        if (QClipboard* clipboardObject = QApplication::clipboard())
        {
            clipboardObject->setText(lineList.join(QLatin1Char('\n')));
        }
    }

    // exportRowsToTsv:
    // - Save the specified visible table rows along with headers to a UTF-8 TSV file.
    // - Input: table object, row indices to export, and default filename prefix;
    // - Show a prompt if the row collection is empty or the write fails; on success, QSaveFile atomically commits the file.
    void exportRowsToTsv(
        QTableView* tableView,
        const QVector<int>& rowList,
        const QString& defaultFileNamePrefix)
    {
        // tableText: Stores the serialized TSV body based on the current visible column sequence.
        const QString kTableText = tableRowsToTsv(tableView, rowList, true);
        if (kTableText.isEmpty())
        {
            QMessageBox::information(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("没有可导出的行。"));
            return;
        }

        // outputPath: Full path of the target file confirmed by the user.
        QString outputPath = QFileDialog::getSaveFileName(
            tableView,
            localizedSourceText("导出 TSV"),
            defaultFileNamePrefix
                + QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))
                + QStringLiteral(".tsv"),
            localizedSourceText("TSV 文件 (*.tsv)"));
        if (outputPath.trimmed().isEmpty())
        {
            return;
        }
        if (QFileInfo(outputPath).suffix().isEmpty())
        {
            outputPath += QStringLiteral(".tsv");
        }

        // fileObject purpose: write to the user-selected TSV file using an atomic replace operation.
        QSaveFile fileObject(outputPath);
        if (!fileObject.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QMessageBox::warning(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("导出失败：%1").arg(fileObject.errorString()));
            return;
        }

        // outputStream usage: Writes the TSV body to a temporary file using UTF-8 encoding.
        QTextStream outputStream(&fileObject);
        outputStream.setEncoding(QStringConverter::Utf8);
        outputStream << kTableText << Qt::endl;
        if (outputStream.status() != QTextStream::Ok || !fileObject.commit())
        {
            QMessageBox::warning(
                tableView,
                localizedSourceText("导出 TSV"),
                localizedSourceText("导出失败：%1").arg(fileObject.errorString()));
        }
    }

    // exportTableToTsv purpose: Export all currently visible rows of the table for use by the top-level 'export all' button.
    void exportTableToTsv(QTableView* tableView)
    {
        exportRowsToTsv(tableView, allVisibleRows(tableView), QStringLiteral("table_export_"));
    }

    // exportSelectedRowsToTsv purpose: Export currently selected rows; if none are selected, fall back to the current focus row.
    void exportSelectedRowsToTsv(QTableView* tableView)
    {
        exportRowsToTsv(
            tableView,
            selectedVisibleRows(tableView, true),
            QStringLiteral("table_selected_export_"));
    }

    // ComparisonTableView is used for both the comparison view and the frozen view. It inherits from the table
    // chrome host, so the frozen view can reserve viewport space for frozen panes just like the real-time table.
    class ComparisonTableView final
        : public ks::ui::visible_table_detail::TableChromeHostView<QTableView>
    {
    public:
        using TableChromeHostView<QTableView>::TableChromeHostView;

    protected:
        void wheelEvent(QWheelEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return;
            }

            const QPoint kPixelDeltaPoint = eventObject->pixelDelta();
            const QPoint kAngleDeltaPoint = eventObject->angleDelta();
            const bool kHorizontal = eventObject->modifiers().testFlag(Qt::ShiftModifier) ||
                std::abs(kPixelDeltaPoint.x()) > std::abs(kPixelDeltaPoint.y()) ||
                std::abs(kAngleDeltaPoint.x()) > std::abs(kAngleDeltaPoint.y());
            QScrollBar* scrollBar = kHorizontal ? horizontalScrollBar() : verticalScrollBar();
            if (scrollBar == nullptr || scrollBar->minimum() == scrollBar->maximum())
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            const int kPixelDelta = kHorizontal
                ? (kPixelDeltaPoint.x() != 0 ? kPixelDeltaPoint.x() : kPixelDeltaPoint.y())
                : (kPixelDeltaPoint.y() != 0 ? kPixelDeltaPoint.y() : kPixelDeltaPoint.x());
            if (kPixelDelta != 0)
            {
                scrollBar->setValue(std::clamp(
                    scrollBar->value() - kPixelDelta,
                    scrollBar->minimum(),
                    scrollBar->maximum()));
                eventObject->accept();
                return;
            }

            const int kAngleDelta = kHorizontal
                ? (kAngleDeltaPoint.x() != 0 ? kAngleDeltaPoint.x() : kAngleDeltaPoint.y())
                : (kAngleDeltaPoint.y() != 0 ? kAngleDeltaPoint.y() : kAngleDeltaPoint.x());
            if (kAngleDelta == 0)
            {
                QTableView::wheelEvent(eventObject);
                return;
            }

            const int kWheelSteps = kAngleDelta / 120 != 0
                ? kAngleDelta / 120
                : (kAngleDelta > 0 ? 1 : -1);
            const int kDistance = std::max(24, scrollBar->singleStep() * 3);
            scrollBar->setValue(std::clamp(
                scrollBar->value() - kWheelSteps * kDistance,
                scrollBar->minimum(),
                scrollBar->maximum()));
            eventObject->accept();
        }

    };

    class TableActionBar final : public QFrame
    {
    public:
        explicit TableActionBar(QTableView* tableView, const TableActionBarMode mode)
            : QFrame(tableView)
            , table_(tableView)
            , mode_(mode)
        {
            setObjectName(QString::fromLatin1(kActionBarProperty));
            setFrameShape(QFrame::NoFrame);
            setFixedHeight(kActionBarHeight);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

            // The table action bar appears in both Dock and regular QDialog contexts, so it cannot inherit the host
            // QPushButton/QToolButton geometric styles. Standard dialog themes add large padding and bold fonts to buttons, which
            // previously caused the same set of action buttons in the plugin management page to appear significantly larger than those in
            // the process page, even compressing the 32px high action bar. Using a palette role here establishes a self-contained compact
            // baseline, ensuring skinning still works while guaranteeing consistent appearance for all TableActionBarHost instances.
            setStyleSheet(QStringLiteral(
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR{"
                "  background-color:palette(base);"
                "  border:none;"
                "  border-bottom:1px solid palette(mid);"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton{"
                "  min-height:20px;"
                "  padding:2px 7px;"
                "  color:palette(text) !important;"
                "  background-color:transparent !important;"
                "  border:1px solid transparent !important;"
                "  border-radius:3px;"
                "  font-weight:400;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:hover{"
                "  background-color:palette(alternate-base) !important;"
                "  border-color:palette(highlight) !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:pressed,"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:checked{"
                "  background-color:palette(highlight) !important;"
                "  color:palette(highlighted-text) !important;"
                "  border-color:palette(highlight) !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QToolButton:disabled{"
                "  color:palette(placeholder-text) !important;"
                "  background-color:transparent !important;"
                "  border-color:transparent !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QScrollArea,"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QScrollArea::viewport{"
                "  background-color:transparent !important;"
                "  border:none !important;"
                "}"
                "QFrame#KSWORD_TABLE_INTERACTION_ACTION_BAR QCheckBox{"
                "  background-color:transparent !important;"
                "  font-weight:400;"
                "}"));

            auto* layout = new QHBoxLayout(this);
            layout->setContentsMargins(4, 2, 4, 2);
            layout->setSpacing(4);

            copyAllButton_ = createButton("复制全表", QStringLiteral(":/Icon/log_copy.svg"));
            exportButton_ = createButton("导出", QStringLiteral(":/Icon/log_export.svg"));
            freezePaneButton_ = createButton("冻结行列");
            freezePaneButton_->setToolTip(localizedSourceText(
                "冻结选中的行或列：行会钉在列标题正下方，列会固定在行表头右侧；支持一次冻结多选行"));
            pauseRefreshButton_ = createButton("冻结视图");
            pauseRefreshButton_->setCheckable(true);
            layout->addWidget(copyAllButton_);
            layout->addWidget(exportButton_);
            layout->addWidget(freezePaneButton_);
            layout->addWidget(pauseRefreshButton_);

            frozenPaneController_ = new TableFrozenPaneController(this);
            frozenPaneController_->setTargetTable(table_.data());

            freezePaneMenu_ = new QMenu(freezePaneButton_);
            freezePaneMenu_->setStyleSheet(ksword_theme::contextMenuStyle());
            freezeCurrentRowAction_ = freezePaneMenu_->addAction(
                localizedSourceText("冻结选中行"));
            freezeCurrentColumnAction_ = freezePaneMenu_->addAction(
                localizedSourceText("冻结选中列"));
            freezeCurrentCellAction_ = freezePaneMenu_->addAction(
                localizedSourceText("冻结选中行列"));
            freezePaneMenu_->addSeparator();
            unfreezeRowsAction_ = freezePaneMenu_->addAction(
                localizedSourceText("取消冻结行"));
            unfreezeColumnsAction_ = freezePaneMenu_->addAction(
                localizedSourceText("取消冻结列"));
            unfreezeAllAction_ = freezePaneMenu_->addAction(
                localizedSourceText("取消全部冻结"));
            freezePaneButton_->setMenu(freezePaneMenu_);
            freezePaneButton_->setPopupMode(QToolButton::InstantPopup);

            snapshotScrollArea_ = new QScrollArea(this);
            snapshotScrollArea_->setFrameShape(QFrame::NoFrame);
            snapshotScrollArea_->setWidgetResizable(false);
            snapshotScrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            snapshotScrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            snapshotScrollArea_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            snapshotScrollArea_->setMinimumWidth(96);
            snapshotScrollArea_->setFixedHeight(kActionBarHeight - 4);
            snapshotContent_ = new QWidget(snapshotScrollArea_);
            snapshotLayout_ = new QHBoxLayout(snapshotContent_);
            snapshotLayout_->setContentsMargins(0, 0, 0, 0);
            snapshotLayout_->setSpacing(2);
            snapshotScrollArea_->setWidget(snapshotContent_);
            layout->addWidget(snapshotScrollArea_, 1);

            addSnapshotButton_ = createButton("增加快照");
            cleanupButton_ = createButton("清理");
            doneCleanupButton_ = createButton("完成");
            deleteSelectedButton_ = createButton("清理选中");
            clearAllButton_ = createButton("清除全部");
            layout->addWidget(addSnapshotButton_);
            layout->addWidget(cleanupButton_);
            layout->addWidget(doneCleanupButton_);
            layout->addWidget(deleteSelectedButton_);
            layout->addWidget(clearAllButton_);

            differenceOnlyCheckBox_ = new QCheckBox(localizedSourceText("只显示差异项"), this);
            differenceOnlyCheckBox_->setChecked(true);
            ignoreColumnsButton_ = createButton("忽略列");
            layout->addWidget(differenceOnlyCheckBox_);
            layout->addWidget(ignoreColumnsButton_);

            currentViewButton_ = createButton("当前视图");
            currentViewButton_->setCheckable(true);
            compareViewButton_ = createButton("比对视图");
            compareViewButton_->setCheckable(true);
            layout->addWidget(currentViewButton_);
            layout->addWidget(compareViewButton_);

            connect(copyAllButton_, &QToolButton::clicked, this, [this]()
                {
                    copyVisibleRowsToClipboard(activeTableView());
                });
            connect(exportButton_, &QToolButton::clicked, this, [this]()
                {
                    exportTableToTsv(activeTableView());
                });
            connect(freezePaneMenu_, &QMenu::aboutToShow, this, [this]()
                {
                    updateFreezePaneMenu();
                });
            connect(freezeCurrentRowAction_, &QAction::triggered, this, [this]()
                {
                    freezeToCurrentIndex(true, false);
                });
            connect(freezeCurrentColumnAction_, &QAction::triggered, this, [this]()
                {
                    freezeToCurrentIndex(false, true);
                });
            connect(freezeCurrentCellAction_, &QAction::triggered, this, [this]()
                {
                    freezeToCurrentIndex(true, true);
                });
            connect(unfreezeRowsAction_, &QAction::triggered, this, [this]()
                {
                    frozenPaneController_->clearFrozenRows();
                    updatePosition();
                    updateControls();
                });
            connect(unfreezeColumnsAction_, &QAction::triggered, this, [this]()
                {
                    frozenPaneController_->clearFrozenColumns();
                    updatePosition();
                    updateControls();
                });
            connect(unfreezeAllAction_, &QAction::triggered, this, [this]()
                {
                    frozenPaneController_->clearFrozenPanes();
                    updatePosition();
                    updateControls();
                });
            connect(pauseRefreshButton_, &QToolButton::toggled, this, [this](const bool checked)
                {
                    setRefreshPaused(checked);
                });
            connect(addSnapshotButton_, &QToolButton::clicked, this, [this]()
                {
                    addSnapshot();
                });
            connect(cleanupButton_, &QToolButton::clicked, this, [this]()
                {
                    enterCleanupMode();
                });
            connect(doneCleanupButton_, &QToolButton::clicked, this, [this]()
                {
                    leaveCleanupMode();
                });
            connect(deleteSelectedButton_, &QToolButton::clicked, this, [this]()
                {
                    deleteSelectedSnapshots();
                });
            connect(clearAllButton_, &QToolButton::clicked, this, [this]()
                {
                    clearAllSnapshots();
                });
            connect(differenceOnlyCheckBox_, &QCheckBox::toggled, this, [this](const bool checked)
                {
                    if (!comparisonModel_.isNull())
                    {
                        comparisonModel_->setShowDifferencesOnly(checked);
                    }
                });
            connect(ignoreColumnsButton_, &QToolButton::clicked, this, [this]()
                {
                    showIgnoredColumnsMenu();
                });
            connect(currentViewButton_, &QToolButton::clicked, this, [this]()
                {
                    showCurrentView();
                });
            connect(compareViewButton_, &QToolButton::clicked, this, [this]()
                {
                    showComparisonView();
                });

            rebuildSnapshotControls();
            updateControls();
        }

    protected:
        void changeEvent(QEvent* eventObject) override
        {
            QFrame::changeEvent(eventObject);
            if (eventObject == nullptr || eventObject->type() != QEvent::LanguageChange)
            {
                return;
            }

            copyAllButton_->setText(localizedSourceText("复制全表"));
            exportButton_->setText(localizedSourceText("导出"));
            freezePaneButton_->setText(localizedSourceText("冻结行列"));
            freezePaneButton_->setToolTip(localizedSourceText(
                "冻结选中的行或列：行会钉在列标题正下方，列会固定在行表头右侧；支持一次冻结多选行"));
            freezeCurrentRowAction_->setText(localizedSourceText("冻结选中行"));
            freezeCurrentColumnAction_->setText(localizedSourceText("冻结选中列"));
            freezeCurrentCellAction_->setText(localizedSourceText("冻结选中行列"));
            unfreezeRowsAction_->setText(localizedSourceText("取消冻结行"));
            unfreezeColumnsAction_->setText(localizedSourceText("取消冻结列"));
            unfreezeAllAction_->setText(localizedSourceText("取消全部冻结"));
            cleanupButton_->setText(localizedSourceText("清理"));
            doneCleanupButton_->setText(localizedSourceText("完成"));
            deleteSelectedButton_->setText(localizedSourceText("清理选中"));
            clearAllButton_->setText(localizedSourceText("清除全部"));
            differenceOnlyCheckBox_->setText(localizedSourceText("只显示差异项"));
            ignoreColumnsButton_->setText(localizedSourceText("忽略列"));
            currentViewButton_->setText(localizedSourceText("当前视图"));
            compareViewButton_->setText(localizedSourceText("比对视图"));
            updateControls();
        }

    public:
        void setMode(const TableActionBarMode mode)
        {
            if (mode_ == mode)
            {
                applyModeVisibility();
                return;
            }

            mode_ = mode;
            updateControls();
            updatePosition();
        }

        void updatePosition()
        {
            if (table_.isNull())
            {
                return;
            }

            // Freezing the pane changes viewport margins; since the toolbar position depends on that result, the frozen pane must be refreshed first.
            if (frozenPaneController_ != nullptr)
            {
                frozenPaneController_->refreshGeometry();
            }
            if (ks::ui::TableActionBarHost* host = ks::ui::tableActionBarHostFor(table_.data()))
            {
                const bool kActionBarVisible = mode_ != TableActionBarMode::kNone;
                host->setTopActionBarHeight(kActionBarVisible ? kActionBarHeight : 0);
                setVisible(kActionBarVisible);
                if (kActionBarVisible)
                {
                    setGeometry(host->topActionBarGeometry());
                    raise();
                }
            }
            hideSourceViewportWidgets();
            updateComparisonOverlayGeometry();
        }

    private:
        QToolButton* createButton(const char* text, const QString& iconPath = QString())
        {
            auto* button = new QToolButton(this);
            button->setText(localizedSourceText(text));
            button->setAutoRaise(true);
            button->setToolButtonStyle(Qt::ToolButtonTextOnly);
            if (!iconPath.isEmpty())
            {
                button->setIcon(QIcon(iconPath));
            }
            return button;
        }

        QToolButton* createSnapshotButton(const TableSnapshot& snapshot, const bool checked)
        {
            auto* button = new QToolButton(snapshotContent_);
            button->setText(snapshot.label + (snapshot.isTruncated() ? QStringLiteral("*") : QString()));
            button->setCheckable(true);
            button->setChecked(checked);
            button->setAutoRaise(false);
            button->setMinimumWidth(28);
            QString tooltip = localizedSourceText("快照 %1：保留 %2 行，估算 %3 MiB。")
                .arg(snapshot.label)
                .arg(snapshot.rows.size())
                .arg(QString::number(
                    static_cast<double>(snapshot.estimatedBytes) / kBytesPerMiB,
                    'f',
                    2));
            if (snapshot.isTruncated())
            {
                tooltip += QLatin1Char('\n')
                    + localizedSourceText("该快照仅覆盖源表前 %1 个扫描行；保留部分仍可用于比较，未覆盖行不会参与结果。")
                        .arg(snapshot.visitedSourceRows);
            }
            button->setToolTip(tooltip);
            button->setStyleSheet(QStringLiteral(
                "QToolButton {"
                "  padding: 2px 7px;"
                "  border: 1px solid palette(mid);"
                "  border-radius: 3px;"
                "  background-color: transparent;"
                "  color: palette(button-text);"
                "}"
                "QToolButton:hover {"
                "  border-color: palette(highlight);"
                "}"
                "QToolButton:checked {"
                "  background-color: palette(highlight);"
                "  border-color: palette(highlight);"
                "  color: palette(highlighted-text);"
                "}"));
            return button;
        }

        QTableView* activeTableView() const
        {
            if (!comparisonOverlay_.isNull())
            {
                return comparisonOverlay_.data();
            }
            return pauseOverlay_.isNull() ? table_.data() : pauseOverlay_.data();
        }

        void updateFreezePaneMenu()
        {
            QTableView* tableView = activeTableView();
            const QModelIndex kCurrentIndex =
                tableView != nullptr ? tableView->currentIndex() : QModelIndex();
            if (tableView != nullptr && frozenPaneController_->targetTable() != tableView)
            {
                frozenPaneController_->setTargetTable(tableView);
            }
            const bool kCurrentAvailable =
                !inComparison_ &&
                !pauseCaptureInProgress_ &&
                frozenPaneController_->canFreeze() &&
                kCurrentIndex.isValid();

            freezeCurrentRowAction_->setEnabled(kCurrentAvailable);
            freezeCurrentColumnAction_->setEnabled(kCurrentAvailable);
            freezeCurrentCellAction_->setEnabled(kCurrentAvailable);
            unfreezeRowsAction_->setEnabled(frozenPaneController_->frozenRowCount() > 0);
            unfreezeColumnsAction_->setEnabled(frozenPaneController_->frozenColumnCount() > 0);
            unfreezeAllAction_->setEnabled(
                frozenPaneController_->frozenRowCount() > 0 ||
                frozenPaneController_->frozenColumnCount() > 0);
        }

        // freezeToCurrentIndex:
        // - Row direction: Pin the selected rows (all selected rows if multiple, current row if none) directly below the table header;
        // - Column direction: Freeze the column containing the current cell to the right of the row header.
        // - Freezes only the selected rows and columns themselves; all other content, including rows/columns above or to the left, scrolls normally.
        // - freezeRows/freezeColumns control which direction to modify in this operation only.
        void freezeToCurrentIndex(const bool freezeRows, const bool freezeColumns)
        {
            QTableView* tableView = activeTableView();
            if (inComparison_ || tableView == nullptr || tableView->model() == nullptr ||
                !tableView->currentIndex().isValid())
            {
                return;
            }

            if (frozenPaneController_->targetTable() != tableView)
            {
                frozenPaneController_->setTargetTable(tableView);
            }
            if (!frozenPaneController_->canFreeze())
            {
                return;
            }

            const QModelIndex kCurrentIndex = tableView->currentIndex();
            if (freezeRows)
            {
                const QVector<int> kSelectedRows = selectedVisibleRows(tableView, true);
                frozenPaneController_->freezeRows(
                    QList<int>(kSelectedRows.cbegin(), kSelectedRows.cend()));
            }
            if (freezeColumns)
            {
                frozenPaneController_->freezeColumns({ kCurrentIndex.column() });
            }
            updatePosition();
            updateControls();
        }

        void configurePausedOverlay(
            ComparisonTableView* pausedView,
            const TableSnapshot& snapshot)
        {
            if (pausedView == nullptr || table_.isNull() || pauseModel_.isNull())
            {
                return;
            }

            QTableView* sourceTable = table_.data();
            pausedView->setModel(pauseModel_);
            pausedView->setSelectionMode(QAbstractItemView::ExtendedSelection);
            pausedView->setSelectionBehavior(sourceTable->selectionBehavior());
            pausedView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            pausedView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
            pausedView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
            pausedView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
            pausedView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            pausedView->verticalScrollBar()->setSingleStep(
                std::max(20, sourceTable->verticalScrollBar()->singleStep()));
            pausedView->horizontalScrollBar()->setSingleStep(
                std::max(20, sourceTable->horizontalScrollBar()->singleStep()));
            pausedView->setAlternatingRowColors(sourceTable->alternatingRowColors());
            pausedView->setShowGrid(sourceTable->showGrid());
            pausedView->setGridStyle(sourceTable->gridStyle());
            pausedView->setTextElideMode(sourceTable->textElideMode());
            pausedView->setWordWrap(false);
            pausedView->setSortingEnabled(false);
            pausedView->setFrameShape(QFrame::NoFrame);
            pausedView->setFocusPolicy(Qt::StrongFocus);
            pausedView->setFont(sourceTable->font());
            pausedView->setPalette(sourceTable->palette());
            pausedView->setAutoFillBackground(true);
            pausedView->viewport()->setAutoFillBackground(true);
            pausedView->viewport()->setPalette(sourceTable->viewport()->palette());

            pausedView->verticalHeader()->setVisible(
                !sourceTable->verticalHeader()->isHidden());
            pausedView->verticalHeader()->setMinimumSectionSize(
                sourceTable->verticalHeader()->minimumSectionSize());
            pausedView->verticalHeader()->setDefaultSectionSize(
                sourceTable->verticalHeader()->defaultSectionSize());
            pausedView->horizontalHeader()->setSectionsMovable(false);
            pausedView->horizontalHeader()->setSectionsClickable(false);
            pausedView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
            pausedView->horizontalHeader()->setStretchLastSection(
                sourceTable->horizontalHeader()->stretchLastSection());

            for (int columnIndex = 0; columnIndex < snapshot.visibleColumns.size(); ++columnIndex)
            {
                const int kSourceColumn = snapshot.visibleColumns.at(columnIndex).sourceColumn;
                const int kSourceWidth =
                    kSourceColumn >= 0 &&
                    sourceTable->model() != nullptr &&
                    kSourceColumn < sourceTable->model()->columnCount()
                    ? sourceTable->columnWidth(kSourceColumn)
                    : sourceTable->horizontalHeader()->defaultSectionSize();
                pausedView->setColumnWidth(columnIndex, std::max(32, kSourceWidth));
            }

            const QModelIndex kSourceCurrentIndex = sourceTable->currentIndex();
            if (kSourceCurrentIndex.isValid())
            {
                int pausedRow = -1;
                int pausedColumn = -1;
                for (int rowIndex = 0; rowIndex < snapshot.rows.size(); ++rowIndex)
                {
                    if (snapshot.rows.at(rowIndex).sourceRow == kSourceCurrentIndex.row())
                    {
                        pausedRow = rowIndex;
                        break;
                    }
                }
                for (int columnIndex = 0;
                    columnIndex < snapshot.visibleColumns.size();
                    ++columnIndex)
                {
                    if (snapshot.visibleColumns.at(columnIndex).sourceColumn ==
                        kSourceCurrentIndex.column())
                    {
                        pausedColumn = columnIndex;
                        break;
                    }
                }
                if (pausedRow >= 0 && pausedColumn >= 0)
                {
                    pausedView->setCurrentIndex(pauseModel_->index(pausedRow, pausedColumn));
                }
            }
        }

        bool pauseRefresh()
        {
            if (refreshPaused_)
            {
                return true;
            }
            if (table_.isNull() || table_->model() == nullptr ||
                inComparison_ || pauseCaptureInProgress_)
            {
                return false;
            }

            const QPointer<TableActionBar> kActionBarGuard(this);
            const QPointer<QTableView> kTableGuard(table_);
            const QPointer<QAbstractItemModel> kModelGuard(table_->model());
            pauseCaptureInProgress_ = true;
            updateControls();
            const TableSnapshot kSnapshot = TableSnapshotCompareEngine::capture(
                table_.data(),
                localizedSourceText("视图已冻结"),
                0,
                kSnapshotCaptureLimits);
            if (kActionBarGuard.isNull())
            {
                return false;
            }
            pauseCaptureInProgress_ = false;
            if (kTableGuard.isNull() || kModelGuard.isNull() ||
                table_ != kTableGuard || kTableGuard->model() != kModelGuard ||
                kSnapshot.sourceInvalidated)
            {
                QMessageBox::warning(
                    this,
                    localizedSourceText("冻结视图失败"),
                    localizedSourceText("表格在捕获期间已重建，请重试。"));
                updateControls();
                return false;
            }

            if (kSnapshot.isTruncated())
            {
                QMessageBox::warning(
                    this,
                    localizedSourceText("冻结视图已截断"),
                    localizedSourceText(
                        "表格规模超过冻结视图快照的安全上限，当前冻结视图保留 %1/%2 行和 %3/%4 列；恢复实时视图后可回到完整实时表格。")
                        .arg(kSnapshot.rows.size())
                        .arg(kSnapshot.sourceRowCount)
                        .arg(kSnapshot.visibleColumns.size())
                        .arg(kSnapshot.sourceColumnCount));
                if (kActionBarGuard.isNull() || kTableGuard.isNull() ||
                    kModelGuard.isNull() || table_ != kTableGuard ||
                    kTableGuard->model() != kModelGuard)
                {
                    updateControls();
                    return false;
                }
            }

            pauseModel_ = new TablePausedSnapshotModel(kSnapshot, this);
            auto* pausedView = new ComparisonTableView(table_.data());
            pauseOverlay_ = pausedView;
            configurePausedOverlay(pausedView, kSnapshot);

            frozenPaneController_->setTargetTable(nullptr);
            suspendOriginalTablePainting();
            refreshPaused_ = true;
            pausedView->show();
            updatePosition();
            pausedView->raise();
            pausedView->setFocus(Qt::OtherFocusReason);
            frozenPaneController_->setTargetTable(pausedView);
            updateControls();
            return true;
        }

        void resumeRefresh()
        {
            if (!refreshPaused_ && pauseOverlay_.isNull())
            {
                return;
            }

            frozenPaneController_->setTargetTable(nullptr);
            if (!pauseOverlay_.isNull())
            {
                pauseOverlay_->hide();
                pauseOverlay_->deleteLater();
                pauseOverlay_.clear();
            }
            resumeOriginalTablePainting();
            if (!pauseModel_.isNull())
            {
                pauseModel_->deleteLater();
                pauseModel_.clear();
            }

            refreshPaused_ = false;
            frozenPaneController_->setTargetTable(table_.data());
            {
                const QSignalBlocker kBlocker(pauseRefreshButton_);
                pauseRefreshButton_->setChecked(false);
            }
            updatePosition();
            updateControls();
        }

        void setRefreshPaused(const bool paused)
        {
            if (paused)
            {
                if (!pauseRefresh())
                {
                    const QSignalBlocker kBlocker(pauseRefreshButton_);
                    pauseRefreshButton_->setChecked(false);
                    updateControls();
                }
                return;
            }
            resumeRefresh();
        }

        const TableSnapshot* snapshotForSequence(const quint64 sequence) const
        {
            const auto kIterator = std::find_if(
                snapshots_.cbegin(),
                snapshots_.cend(),
                [sequence](const TableSnapshot& snapshot)
                {
                    return snapshot.sequence == sequence;
                });
            return kIterator == snapshots_.cend() ? nullptr : &*kIterator;
        }

        QVector<const TableSnapshot*> selectedSnapshots() const
        {
            QVector<const TableSnapshot*> result;
            result.reserve(selectedSnapshotSequences_.size());
            for (const quint64 kSequence : selectedSnapshotSequences_)
            {
                if (const TableSnapshot* snapshot = snapshotForSequence(kSequence))
                {
                    result.push_back(snapshot);
                }
            }
            return result;
        }

        void addSnapshot()
        {
            if (table_.isNull() ||
                inComparison_ ||
                snapshotCaptureInProgress_ ||
                table_->model() == nullptr)
            {
                return;
            }

            const quint64 kSequence = nextSnapshotOrdinal_++;
            const QString kLabel = TableSnapshotCompareEngine::snapshotLabelForOrdinal(kSequence);
            snapshotCaptureInProgress_ = true;
            updateControls();

            QPointer<TableActionBar> actionBarGuard(this);
            TableSnapshot snapshot = TableSnapshotCompareEngine::capture(
                table_.data(),
                kLabel,
                kSequence,
                kSnapshotCaptureLimits);
            if (actionBarGuard.isNull())
            {
                return;
            }
            snapshotCaptureInProgress_ = false;
            if (snapshot.sourceInvalidated)
            {
                updateControls();
                QMessageBox::warning(
                    this,
                    localizedSourceText("快照采集限制"),
                    localizedSourceText("采集期间源表已关闭，或其数据、布局、表头可见状态发生变化。本次快照已整份丢弃；请在源表稳定后重试。"));
                return;
            }

            snapshots_.push_back(std::move(snapshot));
            const TableSnapshot& retainedSnapshot = snapshots_.back();

            QStringList limitMessages;
            bool retainedPartialSnapshot = false;
            if (retainedSnapshot.truncatedByRowLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("快照 %1 已截断：源表共 %2 行，仅访问 %3 行并保留 %4 行。")
                        .arg(retainedSnapshot.label)
                        .arg(retainedSnapshot.sourceRowCount)
                        .arg(retainedSnapshot.visitedSourceRows)
                        .arg(retainedSnapshot.rows.size()));
                limitMessages.push_back(
                    localizedSourceText("已达到单份快照的 %1 行硬上限。")
                        .arg(kSnapshotCaptureLimits.maximumRows));
            }
            if (retainedSnapshot.truncatedByColumnLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("快照 %1 仅扫描源表前 %2/%3 列，并保留其中 %4 个可见列。")
                        .arg(retainedSnapshot.label)
                        .arg(retainedSnapshot.visitedSourceColumns)
                        .arg(retainedSnapshot.sourceColumnCount)
                        .arg(retainedSnapshot.visibleColumns.size()));
                limitMessages.push_back(
                    localizedSourceText("已达到单份快照的 %1 列硬上限。")
                        .arg(kSnapshotCaptureLimits.maximumColumns));
            }
            if (retainedSnapshot.truncatedByByteLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("已达到单份快照的 %1 MiB 估算内存硬上限。")
                        .arg(kSnapshotCaptureLimits.maximumEstimatedBytes / kBytesPerMiB));
            }
            if (retainedSnapshot.truncatedByValueLimit)
            {
                retainedPartialSnapshot = true;
                limitMessages.push_back(
                    localizedSourceText("快照 %1 中有 %2 个表头值和 %3 个单元格值超过单值上限，另有 %4 个不支持的显示值类型；相关值已截断或留空。")
                        .arg(retainedSnapshot.label)
                        .arg(retainedSnapshot.truncatedHeaderValueCount)
                        .arg(retainedSnapshot.truncatedCellValueCount)
                        .arg(retainedSnapshot.unsupportedDisplayValueCount));
                limitMessages.push_back(
                    localizedSourceText("单个表头最多保留 %1 个字符，单个单元格最多保留 %2 个字符。")
                        .arg(kSnapshotCaptureLimits.maximumHeaderCharacters)
                        .arg(kSnapshotCaptureLimits.maximumCellCharacters));
            }

            const TableSnapshotRetentionResult kRetention =
                TableSnapshotCompareEngine::enforceRetentionLimits(
                    snapshots_,
                    kSnapshotRetentionLimits);
            if (!kRetention.evictedLabels.isEmpty())
            {
                limitMessages.push_back(
                    localizedSourceText("为满足最多 %1 份快照、总估算内存不超过 %2 MiB 的硬上限，已淘汰最旧的 %3 份快照：%4。")
                        .arg(kSnapshotRetentionLimits.maximumSnapshots)
                        .arg(kSnapshotRetentionLimits.maximumEstimatedBytes / kBytesPerMiB)
                        .arg(kRetention.evictedLabels.size())
                        .arg(kRetention.evictedLabels.join(QStringLiteral(", "))));
            }
            if (retainedPartialSnapshot)
            {
                limitMessages.push_back(
                    localizedSourceText("已保留的部分仍可继续参与快照比较。"));
            }

            pruneSnapshotSelections();
            rebuildSnapshotControls();
            updateControls();
            if (!limitMessages.isEmpty())
            {
                QMessageBox::information(
                    this,
                    localizedSourceText("快照采集限制"),
                    limitMessages.join(QStringLiteral("\n\n")));
            }
        }

        void enterCleanupMode()
        {
            showCurrentView();
            cleanupMode_ = true;
            cleanupSelections_.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void leaveCleanupMode()
        {
            cleanupMode_ = false;
            cleanupSelections_.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void deleteSelectedSnapshots()
        {
            if (cleanupSelections_.isEmpty())
            {
                QMessageBox::information(
                    this,
                    localizedSourceText("清理快照"),
                    localizedSourceText("没有选中的快照。"));
                return;
            }

            const int kCount = cleanupSelections_.size();
            if (QMessageBox::question(
                    this,
                    localizedSourceText("清理快照"),
                    localizedSourceText("确定清理选中的 %1 份快照吗？").arg(kCount),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) != QMessageBox::Yes)
            {
                return;
            }

            snapshots_.erase(
                std::remove_if(
                    snapshots_.begin(),
                    snapshots_.end(),
                    [this](const TableSnapshot& snapshot)
                    {
                        return cleanupSelections_.contains(snapshot.sequence);
                    }),
                snapshots_.end());
            pruneSnapshotSelections();
            cleanupSelections_.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void clearAllSnapshots()
        {
            if (snapshots_.isEmpty())
            {
                return;
            }

            const int kCount = snapshots_.size();
            if (QMessageBox::question(
                    this,
                    localizedSourceText("清理快照"),
                    localizedSourceText("确定清除该表的全部 %1 份快照吗？").arg(kCount),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No) != QMessageBox::Yes)
            {
                return;
            }

            showCurrentView();
            snapshots_.clear();
            selectedSnapshotSequences_.clear();
            cleanupSelections_.clear();
            rebuildSnapshotControls();
            updateControls();
        }

        void pruneSnapshotSelections()
        {
            selectedSnapshotSequences_.erase(
                std::remove_if(
                    selectedSnapshotSequences_.begin(),
                    selectedSnapshotSequences_.end(),
                    [this](const quint64 sequence)
                    {
                        return snapshotForSequence(sequence) == nullptr;
                    }),
                selectedSnapshotSequences_.end());
        }

        void rebuildSnapshotControls()
        {
            while (QLayoutItem* item = snapshotLayout_->takeAt(0))
            {
                delete item->widget();
                delete item;
            }
            snapshotButtons_.clear();

            for (const TableSnapshot& snapshot : snapshots_)
            {
                QToolButton* button = createSnapshotButton(
                    snapshot,
                    cleanupMode_
                        ? cleanupSelections_.contains(snapshot.sequence)
                        : selectedSnapshotSequences_.contains(snapshot.sequence));
                if (cleanupMode_)
                {
                    connect(button, &QToolButton::toggled, this, [this, sequence = snapshot.sequence](const bool checked)
                        {
                            if (checked)
                            {
                                cleanupSelections_.insert(sequence);
                            }
                            else
                            {
                                cleanupSelections_.remove(sequence);
                            }
                            updateControls();
                        });
                }
                else
                {
                    connect(button, &QToolButton::toggled, this, [this, sequence = snapshot.sequence](const bool checked)
                        {
                            selectSnapshot(sequence, checked);
                        });
                }
                snapshotLayout_->addWidget(button);
                snapshotButtons_.insert(snapshot.sequence, button);
            }
            snapshotLayout_->addStretch(1);
            updateSnapshotContentSize();
            QTimer::singleShot(0, this, [this]()
                {
                    updateSnapshotContentSize();
                });
        }

        void updateSnapshotContentSize()
        {
            if (snapshotContent_ == nullptr || snapshotLayout_ == nullptr ||
                snapshotScrollArea_ == nullptr)
            {
                return;
            }

            snapshotLayout_->invalidate();
            snapshotLayout_->activate();
            QSize desiredSize = snapshotLayout_->sizeHint().expandedTo(
                snapshotLayout_->minimumSize());
            desiredSize.setWidth(std::max(1, desiredSize.width()));
            desiredSize.setHeight(std::max(
                desiredSize.height(),
                snapshotScrollArea_->viewport()->height()));
            snapshotContent_->setMinimumSize(desiredSize);
            snapshotContent_->resize(desiredSize);
            snapshotContent_->updateGeometry();
        }

        void selectSnapshot(const quint64 sequence, const bool checked)
        {
            if (inComparison_)
            {
                showCurrentView();
            }

            if (checked)
            {
                if (!selectedSnapshotSequences_.contains(sequence))
                {
                    selectedSnapshotSequences_.push_back(sequence);
                }
                if (selectedSnapshotSequences_.size() > 2)
                {
                    selectedSnapshotSequences_ = { sequence };
                }
            }
            else
            {
                selectedSnapshotSequences_.removeAll(sequence);
            }

            for (auto iterator = snapshotButtons_.begin(); iterator != snapshotButtons_.end(); ++iterator)
            {
                if (iterator.value() != nullptr)
                {
                    const QSignalBlocker kBlocker(iterator.value());
                    iterator.value()->setChecked(selectedSnapshotSequences_.contains(iterator.key()));
                }
            }
            updateControls();
        }

        void hideSourceViewportWidgets()
        {
            if (!originalTablePaintingSuspended_ || table_.isNull() ||
                table_->viewport() == nullptr)
            {
                return;
            }

            for (QWidget* childWidget : table_->viewport()->findChildren<QWidget*>(
                    QString(),
                    Qt::FindDirectChildrenOnly))
            {
                if (childWidget != nullptr && !childWidget->isHidden())
                {
                    childWidget->hide();
                    const bool kAlreadyTracked = std::any_of(
                        hiddenSourceViewportWidgets_.cbegin(),
                        hiddenSourceViewportWidgets_.cend(),
                        [childWidget](const QPointer<QWidget>& guardedWidget)
                        {
                            return guardedWidget.data() == childWidget;
                        });
                    if (!kAlreadyTracked)
                    {
                        hiddenSourceViewportWidgets_.push_back(childWidget);
                    }
                }
            }
        }

        void suspendOriginalTablePainting()
        {
            if (table_.isNull() || originalTablePaintingSuspended_)
            {
                return;
            }

            QTableView* tableView = table_.data();
            originalTablePaintingSuspended_ = true;
            originalHorizontalHeaderHidden_ = tableView->horizontalHeader()->isHidden();
            originalVerticalHeaderHidden_ = tableView->verticalHeader()->isHidden();
            originalHorizontalScrollBarPolicy_ = tableView->horizontalScrollBarPolicy();
            originalVerticalScrollBarPolicy_ = tableView->verticalScrollBarPolicy();
            originalViewportOpaquePaint_ = tableView->viewport()->testAttribute(Qt::WA_OpaquePaintEvent);
            hiddenSourceViewportWidgets_.clear();

            tableView->setProperty(
                ks::ui::visible_table_detail::kComparisonSourceActiveProperty,
                true);
            tableView->viewport()->setAttribute(Qt::WA_OpaquePaintEvent, false);
            hideSourceViewportWidgets();
            tableView->horizontalHeader()->hide();
            tableView->verticalHeader()->hide();
            tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            tableView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
            tableView->viewport()->update();
        }

        void resumeOriginalTablePainting()
        {
            if (!originalTablePaintingSuspended_)
            {
                return;
            }

            if (!table_.isNull())
            {
                QTableView* tableView = table_.data();
                tableView->setProperty(
                    ks::ui::visible_table_detail::kComparisonSourceActiveProperty,
                    false);
                tableView->setHorizontalScrollBarPolicy(originalHorizontalScrollBarPolicy_);
                tableView->setVerticalScrollBarPolicy(originalVerticalScrollBarPolicy_);
                tableView->horizontalHeader()->setHidden(originalHorizontalHeaderHidden_);
                tableView->verticalHeader()->setHidden(originalVerticalHeaderHidden_);
                tableView->viewport()->setAttribute(
                    Qt::WA_OpaquePaintEvent,
                    originalViewportOpaquePaint_);
                for (const QPointer<QWidget>& guardedWidget : hiddenSourceViewportWidgets_)
                {
                    if (!guardedWidget.isNull())
                    {
                        guardedWidget->show();
                    }
                }
                tableView->doItemsLayout();
                tableView->viewport()->update();
            }

            hiddenSourceViewportWidgets_.clear();
            originalTablePaintingSuspended_ = false;
        }

        void configureComparisonOverlay(
            ComparisonTableView* comparisonView,
            const TableComparisonResult& comparison)
        {
            if (comparisonView == nullptr || table_.isNull())
            {
                return;
            }

            QTableView* sourceTable = table_.data();
            comparisonView->setModel(comparisonModel_);
            comparisonView->setSelectionMode(QAbstractItemView::ExtendedSelection);
            comparisonView->setSelectionBehavior(QAbstractItemView::SelectRows);
            comparisonView->setEditTriggers(QAbstractItemView::NoEditTriggers);
            comparisonView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
            comparisonView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
            comparisonView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
            comparisonView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
            comparisonView->verticalScrollBar()->setSingleStep(std::max(20, sourceTable->verticalScrollBar()->singleStep()));
            comparisonView->horizontalScrollBar()->setSingleStep(std::max(20, sourceTable->horizontalScrollBar()->singleStep()));
            comparisonView->setAlternatingRowColors(sourceTable->alternatingRowColors());
            comparisonView->setShowGrid(sourceTable->showGrid());
            comparisonView->setGridStyle(sourceTable->gridStyle());
            comparisonView->setTextElideMode(sourceTable->textElideMode());
            comparisonView->setWordWrap(false);
            comparisonView->setSortingEnabled(false);
            comparisonView->setFrameShape(QFrame::NoFrame);
            comparisonView->setFocusPolicy(Qt::StrongFocus);
            comparisonView->setFont(sourceTable->font());
            comparisonView->setAutoFillBackground(false);
            comparisonView->setPalette(sourceTable->palette());
            if (comparisonView->viewport() != nullptr)
            {
                comparisonView->viewport()->setAutoFillBackground(false);
                comparisonView->viewport()->setPalette(sourceTable->viewport()->palette());
            }

            comparisonView->verticalHeader()->hide();
            const int kReadableRowHeight = std::max(
                sourceTable->verticalHeader()->defaultSectionSize(),
                comparisonView->fontMetrics().lineSpacing() + 8);
            comparisonView->verticalHeader()->setMinimumSectionSize(kReadableRowHeight);
            comparisonView->verticalHeader()->setDefaultSectionSize(kReadableRowHeight);
            comparisonView->horizontalHeader()->setSectionsMovable(false);
            comparisonView->horizontalHeader()->setSectionsClickable(false);
            comparisonView->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
            comparisonView->horizontalHeader()->setStretchLastSection(
                sourceTable->horizontalHeader()->stretchLastSection());

            comparisonView->setColumnWidth(0, 56);
            for (int columnIndex = 0; columnIndex < comparison.columns.size(); ++columnIndex)
            {
                const int kSourceColumn = comparison.columns.at(columnIndex).sourceColumn;
                const int kSourceWidth = kSourceColumn >= 0 && kSourceColumn < sourceTable->model()->columnCount()
                    ? sourceTable->columnWidth(kSourceColumn)
                    : sourceTable->horizontalHeader()->defaultSectionSize();
                comparisonView->setColumnWidth(columnIndex + 1, std::max(48, kSourceWidth));
            }
        }

        void showComparisonLimitWarning(const TableComparisonResult& comparison)
        {
            if (!comparison.isTruncated() || comparison.cancelled)
            {
                return;
            }

            QStringList reasons;
            if (comparison.truncatedByResultByteLimit)
            {
                reasons.push_back(
                    localizedSourceText("比较结果达到 %1 MiB 独立估算内存硬上限。")
                        .arg(kSnapshotComparisonLimits.maximumEstimatedBytes / kBytesPerMiB));
            }
            if (comparison.truncatedByTemporaryByteLimit)
            {
                reasons.push_back(
                    localizedSourceText("比较临时索引达到 %1 MiB 估算内存硬上限。")
                        .arg(kSnapshotComparisonLimits.maximumTemporaryEstimatedBytes / kBytesPerMiB));
            }
            if (comparison.truncatedByWorkLimit)
            {
                reasons.push_back(
                    localizedSourceText("比较达到 %1 个单元工作量硬上限。")
                        .arg(kSnapshotComparisonLimits.maximumWorkUnits));
            }

            QMessageBox::warning(
                this,
                localizedSourceText("快照比较限制"),
                localizedSourceText("比较已按硬预算提前停止；当前视图仅包含停止前生成的部分结果。")
                    + QStringLiteral("\n\n")
                    + reasons.join(QLatin1Char('\n')));
        }

        void showComparisonView()
        {
            if (table_.isNull() ||
                cleanupMode_ ||
                comparisonInProgress_ ||
                selectedSnapshotSequences_.size() != 2)
            {
                return;
            }

            const QPointer<TableActionBar> kActionBarGuard(this);
            const QPointer<QTableView> kTableGuard(table_);
            const QPointer<QAbstractItemModel> kModelGuard(table_->model());
            const auto kSourceStillValid = [kActionBarGuard, kTableGuard, kModelGuard]()
            {
                return !kActionBarGuard.isNull() &&
                    !kTableGuard.isNull() &&
                    !kModelGuard.isNull() &&
                    kActionBarGuard->table_ == kTableGuard &&
                    kTableGuard->model() == kModelGuard;
            };

            QVector<const TableSnapshot*> snapshots = selectedSnapshots();
            if (snapshots.size() != 2)
            {
                pruneSnapshotSelections();
                updateControls();
                return;
            }

            const TableSnapshot* earlier = snapshots.at(0);
            const TableSnapshot* later = snapshots.at(1);
            if (earlier->sequence > later->sequence)
            {
                std::swap(earlier, later);
            }

            if (earlier->isTruncated() || later->isTruncated())
            {
                QStringList snapshotCoverage;
                for (const TableSnapshot* snapshot : { earlier, later })
                {
                    if (snapshot != nullptr && snapshot->isTruncated())
                    {
                        snapshotCoverage.push_back(
                            localizedSourceText("快照 %1：扫描源表前 %2/%3 行，保留 %4 行；扫描前 %5/%6 列，保留 %7 个可见列。")
                                .arg(snapshot->label)
                                .arg(snapshot->visitedSourceRows)
                                .arg(snapshot->sourceRowCount)
                                .arg(snapshot->rows.size())
                                .arg(snapshot->visitedSourceColumns)
                                .arg(snapshot->sourceColumnCount)
                                .arg(snapshot->visibleColumns.size()));
                    }
                }
                QMessageBox::warning(
                    this,
                    localizedSourceText("截断快照比较"),
                    localizedSourceText("所选快照包含截断数据。比对仅覆盖各快照已扫描并保留的行与列；未覆盖内容不会出现在结果中。")
                        + QStringLiteral("\n\n")
                        + snapshotCoverage.join(QLatin1Char('\n')));
                if (!kSourceStillValid())
                {
                    return;
                }

                // The nested modal event loop may have changed the snapshot store
                // without destroying the table. Re-resolve both selections before
                // using their addresses again.
                snapshots = selectedSnapshots();
                if (snapshots.size() != 2)
                {
                    pruneSnapshotSelections();
                    updateControls();
                    return;
                }
                earlier = snapshots.at(0);
                later = snapshots.at(1);
                if (earlier->sequence > later->sequence)
                {
                    std::swap(earlier, later);
                }
            }

            if (inComparison_)
            {
                showCurrentView();
            }

            ignoredSourceColumns_ = TableSnapshotCompareEngine::defaultIgnoredColumnIndexes(*earlier);
            ignoredSourceColumns_.unite(TableSnapshotCompareEngine::defaultIgnoredColumnIndexes(*later));
            comparisonInProgress_ = true;
            updateControls();
            const TableComparisonResult kComparison = TableSnapshotCompareEngine::compare(
                *earlier,
                *later,
                ignoredSourceColumns_,
                QVector<int>(),
                kSnapshotComparisonLimits,
                [kSourceStillValid]()
                {
                    return !kSourceStillValid();
                });
            if (kActionBarGuard.isNull())
            {
                return;
            }
            comparisonInProgress_ = false;
            if (!kSourceStillValid() || kComparison.cancelled)
            {
                updateControls();
                return;
            }
            showComparisonLimitWarning(kComparison);
            if (kActionBarGuard.isNull())
            {
                return;
            }
            if (!kSourceStillValid())
            {
                updateControls();
                return;
            }
            comparisonModel_ = new TableComparisonModel(kComparison, this);
            comparisonModel_->setShowDifferencesOnly(differenceOnlyCheckBox_->isChecked());

            auto* comparisonView = new ComparisonTableView(table_.data());
            comparisonOverlay_ = comparisonView;
            configureComparisonOverlay(comparisonView, kComparison);
            comparisonView->setProperty(kComparisonActiveProperty, true);

            frozenPaneController_->setTargetTable(nullptr);
            suspendOriginalTablePainting();
            inComparison_ = true;
            comparisonView->show();
            updatePosition();
            comparisonView->raise();
            comparisonView->setFocus(Qt::OtherFocusReason);
            updateControls();
        }

        void showCurrentView()
        {
            if (!inComparison_)
            {
                return;
            }

            if (!comparisonOverlay_.isNull())
            {
                comparisonOverlay_->setProperty(kComparisonActiveProperty, false);
                comparisonOverlay_->hide();
                comparisonOverlay_->deleteLater();
                comparisonOverlay_.clear();
            }
            resumeOriginalTablePainting();
            if (!comparisonModel_.isNull())
            {
                comparisonModel_->deleteLater();
                comparisonModel_.clear();
            }

            inComparison_ = false;
            frozenPaneController_->setTargetTable(table_.data());
            updatePosition();
            updateControls();
        }

        void refreshComparison()
        {
            if (!inComparison_ ||
                comparisonInProgress_ ||
                comparisonModel_.isNull() ||
                selectedSnapshotSequences_.size() != 2)
            {
                return;
            }
            const QVector<const TableSnapshot*> kSnapshots = selectedSnapshots();
            if (kSnapshots.size() != 2)
            {
                return;
            }
            const TableSnapshot* earlier = kSnapshots.at(0);
            const TableSnapshot* later = kSnapshots.at(1);
            if (earlier->sequence > later->sequence)
            {
                std::swap(earlier, later);
            }
            comparisonInProgress_ = true;
            updateControls();
            const QPointer<TableActionBar> kActionBarGuard(this);
            const TableComparisonResult kComparison = TableSnapshotCompareEngine::compare(
                *earlier,
                *later,
                ignoredSourceColumns_,
                QVector<int>(),
                kSnapshotComparisonLimits,
                [kActionBarGuard]()
                {
                    return kActionBarGuard.isNull() || kActionBarGuard->table_.isNull();
                });
            if (kActionBarGuard.isNull())
            {
                return;
            }
            comparisonInProgress_ = false;
            if (kComparison.cancelled || table_.isNull() || comparisonModel_.isNull())
            {
                updateControls();
                return;
            }
            showComparisonLimitWarning(kComparison);
            if (kActionBarGuard.isNull())
            {
                return;
            }
            if (table_.isNull() || comparisonModel_.isNull())
            {
                updateControls();
                return;
            }
            comparisonModel_->setComparison(kComparison);
            comparisonModel_->setShowDifferencesOnly(differenceOnlyCheckBox_->isChecked());
            updateControls();
        }

        void showIgnoredColumnsMenu()
        {
            if (!inComparison_ || comparisonModel_.isNull())
            {
                return;
            }

            QMenu menu(this);
            menu.addSection(localizedSourceText("当前比对的忽略列"));
            const QStringList kKeywords = TableSnapshotCompareEngine::defaultIgnoredColumnKeywords();
            const TableComparisonResult& comparison = comparisonModel_->comparison();
            QHash<QAction*, int> columnActions;
            for (const TableSnapshotColumn& column : comparison.columns)
            {
                QStringList matchedKeywords;
                for (const QString& keyword : kKeywords)
                {
                    if (column.headerText.contains(keyword, Qt::CaseInsensitive))
                    {
                        matchedKeywords.push_back(keyword);
                    }
                }

                QString title = column.headerText.isEmpty()
                    ? localizedSourceText("列 %1").arg(column.sourceColumn + 1)
                    : column.headerText;
                if (!matchedKeywords.isEmpty())
                {
                    title += QStringLiteral("  ")
                        + localizedSourceText("自动匹配：%1").arg(matchedKeywords.join(QStringLiteral(", ")));
                }
                QAction* action = menu.addAction(title);
                action->setCheckable(true);
                action->setChecked(ignoredSourceColumns_.contains(column.sourceColumn));
                columnActions.insert(action, column.sourceColumn);
            }

            QAction* selectedAction = menu.exec(ignoreColumnsButton_->mapToGlobal(
                QPoint(0, ignoreColumnsButton_->height())));
            if (selectedAction == nullptr || !columnActions.contains(selectedAction))
            {
                return;
            }

            const int kSourceColumn = columnActions.value(selectedAction);
            if (selectedAction->isChecked())
            {
                ignoredSourceColumns_.insert(kSourceColumn);
            }
            else
            {
                ignoredSourceColumns_.remove(kSourceColumn);
            }
            refreshComparison();
        }

        void updateComparisonOverlayGeometry()
        {
            if (table_.isNull() ||
                (comparisonOverlay_.isNull() && pauseOverlay_.isNull()))
            {
                return;
            }

            const int kFrameWidth = table_->frameWidth();
            const int kTop = std::max(kFrameWidth, geometry().bottom() + 1);
            QTableView* overlayView = !comparisonOverlay_.isNull()
                ? comparisonOverlay_.data()
                : pauseOverlay_.data();
            overlayView->setGeometry(
                kFrameWidth,
                kTop,
                std::max(0, table_->width() - kFrameWidth * 2),
                std::max(0, table_->height() - kTop - kFrameWidth));
            overlayView->raise();
            raise();
        }

        void applyModeVisibility()
        {
            const bool kActionBarVisible = mode_ != TableActionBarMode::kNone;
            const bool kFullMode = mode_ == TableActionBarMode::kFull;
            copyAllButton_->setVisible(kActionBarVisible);
            exportButton_->setVisible(kActionBarVisible);
            freezePaneButton_->setVisible(kFullMode);
            pauseRefreshButton_->setVisible(kFullMode);
            snapshotScrollArea_->setVisible(kFullMode);
            addSnapshotButton_->setVisible(kFullMode);
            cleanupButton_->setVisible(kFullMode && !cleanupMode_);
            doneCleanupButton_->setVisible(kFullMode && cleanupMode_);
            deleteSelectedButton_->setVisible(kFullMode && cleanupMode_);
            clearAllButton_->setVisible(kFullMode && cleanupMode_);
            differenceOnlyCheckBox_->setVisible(kFullMode && inComparison_);
            ignoreColumnsButton_->setVisible(kFullMode && inComparison_);
            currentViewButton_->setVisible(kFullMode);
            compareViewButton_->setVisible(kFullMode);
        }

        void updateControls()
        {
            const bool kHasSnapshots = !snapshots_.isEmpty();
            const bool kExactlyTwoSnapshotsSelected = selectedSnapshotSequences_.size() == 2;
            QTableView* activeTable = activeTableView();
            const bool kHasVisibleRows = activeTable != nullptr &&
                activeTable->model() != nullptr &&
                activeTable->model()->rowCount() > 0 &&
                activeTable->model()->columnCount() > 0;
            const bool kControlsAvailable =
                !snapshotCaptureInProgress_ &&
                !comparisonInProgress_ &&
                !pauseCaptureInProgress_;
            copyAllButton_->setEnabled(kControlsAvailable && kHasVisibleRows);
            exportButton_->setEnabled(kControlsAvailable && kHasVisibleRows);
            freezePaneButton_->setEnabled(
                kControlsAvailable &&
                !inComparison_ &&
                activeTable != nullptr &&
                activeTable->model() != nullptr);
            pauseRefreshButton_->setText(localizedSourceText(
                pauseCaptureInProgress_
                    ? "正在冻结…"
                    : (refreshPaused_ ? "恢复实时视图" : "冻结视图")));
            pauseRefreshButton_->setToolTip(localizedSourceText(
                refreshPaused_
                    ? "恢复实时视图并显示后台更新后的最新结果"
                    : "冻结当前表格内容；后台采集继续运行，恢复后显示最新结果"));
            {
                const QSignalBlocker kBlocker(pauseRefreshButton_);
                pauseRefreshButton_->setChecked(
                    refreshPaused_ || pauseCaptureInProgress_);
            }
            pauseRefreshButton_->setEnabled(
                !pauseCaptureInProgress_ &&
                !snapshotCaptureInProgress_ &&
                !comparisonInProgress_ &&
                !cleanupMode_ &&
                !inComparison_ &&
                table_ != nullptr &&
                table_->model() != nullptr);
            addSnapshotButton_->setText(localizedSourceText(
                snapshotCaptureInProgress_ ? "正在采集…" : "增加快照"));
            addSnapshotButton_->setEnabled(
                kControlsAvailable &&
                !cleanupMode_ &&
                !inComparison_ &&
                !refreshPaused_ &&
                table_ != nullptr &&
                table_->model() != nullptr);
            cleanupButton_->setVisible(!cleanupMode_);
            cleanupButton_->setEnabled(kControlsAvailable && kHasSnapshots && !inComparison_);
            doneCleanupButton_->setVisible(cleanupMode_);
            doneCleanupButton_->setEnabled(kControlsAvailable);
            deleteSelectedButton_->setVisible(cleanupMode_);
            deleteSelectedButton_->setEnabled(
                kControlsAvailable &&
                cleanupMode_ &&
                !cleanupSelections_.isEmpty());
            clearAllButton_->setVisible(cleanupMode_);
            clearAllButton_->setEnabled(kControlsAvailable && cleanupMode_ && kHasSnapshots);
            differenceOnlyCheckBox_->setVisible(inComparison_);
            differenceOnlyCheckBox_->setEnabled(kControlsAvailable);
            ignoreColumnsButton_->setVisible(inComparison_);
            ignoreColumnsButton_->setEnabled(kControlsAvailable);
            currentViewButton_->setEnabled(kControlsAvailable && inComparison_);
            currentViewButton_->setChecked(!inComparison_);
            compareViewButton_->setEnabled(
                kControlsAvailable &&
                !cleanupMode_ &&
                !refreshPaused_ &&
                kExactlyTwoSnapshotsSelected);
            compareViewButton_->setChecked(inComparison_);
            for (QToolButton* snapshotButton : std::as_const(snapshotButtons_))
            {
                if (snapshotButton != nullptr)
                {
                    snapshotButton->setEnabled(kControlsAvailable);
                }
            }
            applyModeVisibility();
        }

        QPointer<QTableView> table_;
        QPointer<QTableView> comparisonOverlay_;
        QPointer<TableComparisonModel> comparisonModel_;
        QPointer<QTableView> pauseOverlay_;
        QPointer<TablePausedSnapshotModel> pauseModel_;
        TableFrozenPaneController* frozenPaneController_ = nullptr;
        QVector<TableSnapshot> snapshots_;
        QVector<quint64> selectedSnapshotSequences_;
        QSet<quint64> cleanupSelections_;
        QSet<int> ignoredSourceColumns_;
        QHash<quint64, QToolButton*> snapshotButtons_;
        QVector<QPointer<QWidget>> hiddenSourceViewportWidgets_;
        quint64 nextSnapshotOrdinal_ = 0;
        Qt::ScrollBarPolicy originalHorizontalScrollBarPolicy_ = Qt::ScrollBarAsNeeded;
        Qt::ScrollBarPolicy originalVerticalScrollBarPolicy_ = Qt::ScrollBarAsNeeded;
        bool originalTablePaintingSuspended_ = false;
        bool originalHorizontalHeaderHidden_ = false;
        bool originalVerticalHeaderHidden_ = false;
        bool originalViewportOpaquePaint_ = false;
        bool cleanupMode_ = false;
        bool inComparison_ = false;
        bool refreshPaused_ = false;
        bool snapshotCaptureInProgress_ = false;
        bool comparisonInProgress_ = false;
        bool pauseCaptureInProgress_ = false;
        TableActionBarMode mode_ = TableActionBarMode::kFull;
        QToolButton* copyAllButton_ = nullptr;
        QToolButton* exportButton_ = nullptr;
        QToolButton* freezePaneButton_ = nullptr;
        QToolButton* pauseRefreshButton_ = nullptr;
        QMenu* freezePaneMenu_ = nullptr;
        QAction* freezeCurrentRowAction_ = nullptr;
        QAction* freezeCurrentColumnAction_ = nullptr;
        QAction* freezeCurrentCellAction_ = nullptr;
        QAction* unfreezeRowsAction_ = nullptr;
        QAction* unfreezeColumnsAction_ = nullptr;
        QAction* unfreezeAllAction_ = nullptr;
        QToolButton* addSnapshotButton_ = nullptr;
        QToolButton* cleanupButton_ = nullptr;
        QToolButton* doneCleanupButton_ = nullptr;
        QToolButton* deleteSelectedButton_ = nullptr;
        QToolButton* clearAllButton_ = nullptr;
        QToolButton* ignoreColumnsButton_ = nullptr;
        QToolButton* currentViewButton_ = nullptr;
        QToolButton* compareViewButton_ = nullptr;
        QCheckBox* differenceOnlyCheckBox_ = nullptr;
        QScrollArea* snapshotScrollArea_ = nullptr;
        QWidget* snapshotContent_ = nullptr;
        QHBoxLayout* snapshotLayout_ = nullptr;
    };

    TableActionBar* actionBarForTable(QTableView* tableView)
    {
        if (tableView == nullptr)
        {
            return nullptr;
        }
        return dynamic_cast<TableActionBar*>(tableView->findChild<QObject*>(
            QString::fromLatin1(kActionBarProperty),
            Qt::FindDirectChildrenOnly));
    }

    void installActionBar(QTableView* tableView)
    {
        if (tableView == nullptr || ks::ui::tableActionBarHostFor(tableView) == nullptr)
        {
            return;
        }
        const TableActionBarMode kMode = ks::ui::effectiveTableActionBarMode(tableView);
        TableActionBar* actionBar = actionBarForTable(tableView);
        if (actionBar == nullptr)
        {
            if (kMode == TableActionBarMode::kNone)
            {
                ks::ui::tableActionBarHostFor(tableView)->setTopActionBarHeight(0);
                return;
            }
            actionBar = new TableActionBar(tableView, kMode);
        }
        actionBar->setMode(kMode);
        actionBar->updatePosition();
    }

    // applyContextMenuStyle purpose: complete opaque theme styles for globally created or extended menus.
    void applyContextMenuStyle(QMenu* menu)
    {
        if (menu != nullptr && menu->styleSheet().trimmed().isEmpty())
        {
            menu->setStyleSheet(ksword_theme::contextMenuStyle());
        }
    }

    // showStandardTableContextMenu purpose: display copy and export menus for tables without business logic on right-click.
    void showStandardTableContextMenu(QTableView* tableView, const QPoint& globalPosition)
    {
        if (tableView == nullptr)
        {
            return;
        }

        QMenu menu(tableView);
        menu.setProperty(kStandardContextMenuProperty, true);
        applyContextMenuStyle(&menu);
        QAction* copyAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_copy.svg")),
            localizedSourceText("复制选中行（TSV）"));
        QAction* exportAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            localizedSourceText("导出选中行（TSV）"));

        copyAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        exportAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());

        QAction* selectedAction = menu.exec(globalPosition);
        if (selectedAction == copyAction)
        {
            copySelectedRowsToClipboard(tableView);
        }
        else if (selectedAction == exportAction)
        {
            exportSelectedRowsToTsv(tableView);
        }
    }

    // appendTableContextActions: Adds copy and export actions for selected rows to the business right-click menu.
    void appendTableContextActions(QMenu* menu, QTableView* contextTableView = nullptr)
    {
        if (menu == nullptr ||
            menu->property(kStandardContextMenuProperty).toBool() ||
            menu->property(kContextActionsInstalledProperty).toBool())
        {
            return;
        }

        // tableView usage: The table corresponding to the current menu, prioritizing the right-click event source.
        QTableView* tableView = contextTableView;
        if (tableView == nullptr)
        {
            tableView = qobject_cast<QTableView*>(menu->parent());
        }
        if (tableView == nullptr)
        {
            return;
        }

        // Add a separator after existing business menu items to keep global actions at the end of the menu.
        menu->setProperty(kContextActionsInstalledProperty, true);
        if (!menu->actions().isEmpty())
        {
            menu->addSeparator();
        }
        applyContextMenuStyle(menu);
        QAction* copyAction = menu->addAction(
            QIcon(QStringLiteral(":/Icon/log_copy.svg")),
            localizedSourceText("复制选中行（TSV）"));
        QAction* exportAction = menu->addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            localizedSourceText("导出选中行（TSV）"));

        // guardedTable usage: Safely references the source table while the menu is active.
        const QPointer<QTableView> kGuardedTable(tableView);
        copyAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        exportAction->setEnabled(!selectedVisibleRows(tableView, true).isEmpty());
        QObject::connect(copyAction, &QAction::triggered, menu, [kGuardedTable]()
            {
                if (!kGuardedTable.isNull())
                {
                    copySelectedRowsToClipboard(kGuardedTable.data());
                }
            });
        QObject::connect(exportAction, &QAction::triggered, menu, [kGuardedTable]()
            {
                if (!kGuardedTable.isNull())
                {
                    exportSelectedRowsToTsv(kGuardedTable.data());
                }
            });
    }

    void selectContextRow(QTableView* tableView, const QModelIndex& clickedIndex)
    {
        if (tableView == nullptr || !clickedIndex.isValid() || tableView->selectionModel() == nullptr)
        {
            return;
        }

        const QVector<int> kSelectedRowList = selectedVisibleRows(tableView, false);
        if (std::find(kSelectedRowList.cbegin(), kSelectedRowList.cend(), clickedIndex.row()) != kSelectedRowList.cend())
        {
            tableView->selectionModel()->setCurrentIndex(clickedIndex, QItemSelectionModel::NoUpdate);
            return;
        }

        tableView->selectionModel()->setCurrentIndex(
            clickedIndex,
            QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    void installDefaultContextMenu(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->contextMenuPolicy() != Qt::DefaultContextMenu)
        {
            return;
        }

        tableView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableView,
            &QTableView::customContextMenuRequested,
            tableView,
            [tableView](const QPoint& localPosition)
            {
                const QModelIndex kClickedIndex = tableView->indexAt(localPosition);
                selectContextRow(tableView, kClickedIndex);
                showStandardTableContextMenu(
                    tableView,
                    tableView->viewport()->mapToGlobal(localPosition));
            });
    }

    void configureTable(QTableView* tableView)
    {
        if (tableView == nullptr || tableView->model() == nullptr)
        {
            return;
        }

        applyStandardTableHeaderStyle(tableView);
        ks::ui::installTableHeaderClickSorting(
            qobject_cast<QTableWidget*>(tableView));
        installActionBar(tableView);
        ks::ui::installTableSearchSupport(tableView);
        ks::ui::refreshTableSearchSupport(tableView);
        installDefaultContextMenu(tableView);
    }

    class GlobalTableInteractionSupportFilter final : public QObject
    {
    public:
        explicit GlobalTableInteractionSupportFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() == QEvent::KeyRelease)
            {
                // Multi-selection end flag: schedule re-injection of cached table refresh after Ctrl release (Issue #149).
                // Defer to the outer event loop and re-check the physical state of the left Ctrl key via flush; releasing the right Ctrl key alone will not trigger a false submission.
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                if (keyEvent->key() == Qt::Key_Control && !keyEvent->isAutoRepeat())
                {
                    scheduleDeferredTableUiCommitFlush();
                }
            }

            if (eventObject->type() == QEvent::Show)
            {
                // shownMenu purpose: Identify the right-click menu just displayed by business logic.
                QMenu* shownMenu = qobject_cast<QMenu*>(watchedObject);
                if (shownMenu != nullptr)
                {
                    // contextItemView: Binds the current menu to the source of the most recent right-click on a table or tree.
                    QAbstractItemView* contextItemView = pendingContextItemView_.data();
                    QTableView* contextTableView =
                        qobject_cast<QTableView*>(contextItemView);
                    appendTableContextActions(shownMenu, contextTableView);
                    if (contextItemView != nullptr)
                    {
                        // A menu object is registered only once per display; Hide/destroy operations remove the refresh barrier.
                        if (!openContextMenuItemViews_.contains(shownMenu))
                        {
                            openContextMenuItemViews_.insert(shownMenu, contextItemView);
                            beginItemViewContextMenu(contextItemView);

                            // The menu can be reused by different views; on destruction, read the current mapping to avoid old connections detaching the new view deeply.
                            QObject::connect(
                                shownMenu,
                                &QObject::destroyed,
                                this,
                                [this, shownMenu]()
                                {
                                    const auto kMenuIterator =
                                        openContextMenuItemViews_.find(shownMenu);
                                    if (kMenuIterator != openContextMenuItemViews_.end())
                                    {
                                        const QPointer<QAbstractItemView> kGuardedItemView =
                                            kMenuIterator.value();
                                        openContextMenuItemViews_.erase(kMenuIterator);
                                        endItemViewContextMenu(kGuardedItemView.data());
                                    }
                                });
                        }
                        pendingContextItemView_.clear();
                        ++pendingContextSequence_;
                    }
                }
            }
            else if (eventObject->type() == QEvent::Hide)
            {
                // The only time to release the isComboBoxPopupOpen barrier is when the dropdown popup collapses.
                // The parent of the popup container is the combo box itself; use this to identify and re-inject cached refreshes.
                if (QWidget* const kHiddenWidget = qobject_cast<QWidget*>(watchedObject))
                {
                    if (qobject_cast<QComboBox*>(kHiddenWidget->parentWidget()) != nullptr)
                    {
                        scheduleDeferredTableUiCommitFlush();
                    }
                }

                // hiddenMenu usage: Releases the UI commit barrier for the corresponding table after the business menu exits the nested event loop.
                QMenu* hiddenMenu = qobject_cast<QMenu*>(watchedObject);
                if (hiddenMenu != nullptr)
                {
                    const auto kMenuIterator = openContextMenuItemViews_.find(hiddenMenu);
                    if (kMenuIterator != openContextMenuItemViews_.end())
                    {
                        const QPointer<QAbstractItemView> kGuardedItemView = kMenuIterator.value();
                        openContextMenuItemViews_.erase(kMenuIterator);
                        endItemViewContextMenu(kGuardedItemView.data());
                    }
                }
            }

            const QEvent::Type kEventType = eventObject->type();
            QAbstractItemView* contextItemView = itemViewForEventObject(watchedObject);
            if (contextItemView != nullptr && kEventType == QEvent::ContextMenu)
            {
                // Records the source before the business menu displays; QTableView and QTreeView share the same lifecycle barrier.
                pendingContextItemView_ = contextItemView;
                ++pendingContextSequence_;
                const unsigned long long kPendingContextSequence = pendingContextSequence_;
                QTimer::singleShot(0, this, [this, kPendingContextSequence]()
                    {
                        if (pendingContextSequence_ == kPendingContextSequence)
                        {
                            pendingContextItemView_.clear();
                        }
                    });
            }

            QTableView* tableView = tableForEventObject(watchedObject);
            if (tableView == nullptr)
            {
                // Tree views do not support the flattened parallel path logic below, but Ctrl+C must not become a stuck key.
                // Previously, the global table facility only recognized QTableView, causing a large group of lists including the handle tree, device tree,
                // kernel object tree, and file usage tree to be completely unresponsive to Ctrl+C—users could not copy anything from a multi-selectable list.
                if (kEventType == QEvent::KeyPress)
                {
                    auto* treeKeyEvent = static_cast<QKeyEvent*>(eventObject);
                    if (treeKeyEvent->matches(QKeySequence::Copy))
                    {
                        if (QTreeView* treeView =
                                qobject_cast<QTreeView*>(itemViewForEventObject(watchedObject)))
                        {
                            copySelectedTreeRowsToClipboard(treeView);
                            treeKeyEvent->accept();
                            return true;
                        }
                    }
                }
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const bool kComparisonActive = tableView->property(kComparisonActiveProperty).toBool();
            if (tableView->property(
                    ks::ui::visible_table_detail::kComparisonSourceActiveProperty).toBool() &&
                watchedObject == tableView->viewport() &&
                (kEventType == QEvent::Paint || kEventType == QEvent::UpdateRequest))
            {
                if (TableActionBar* actionBar = actionBarForTable(tableView))
                {
                    actionBar->updatePosition();
                }
            }
            if (kComparisonActive && kEventType == QEvent::ContextMenu)
            {
                auto* contextMenuEvent = static_cast<QContextMenuEvent*>(eventObject);
                const QPoint kViewportPosition = watchedObject == tableView
                    ? tableView->viewport()->mapFrom(tableView, contextMenuEvent->pos())
                    : contextMenuEvent->pos();
                selectContextRow(tableView, tableView->indexAt(kViewportPosition));
                showStandardTableContextMenu(tableView, contextMenuEvent->globalPos());
                contextMenuEvent->accept();
                return true;
            }
            if (kEventType == QEvent::Show ||
                kEventType == QEvent::Polish ||
                kEventType == QEvent::LayoutRequest ||
                kEventType == QEvent::StyleChange ||
                kEventType == QEvent::Resize)
            {
                configureTable(tableView);
            }
            else if (kEventType == QEvent::KeyPress)
            {
                auto* keyEvent = static_cast<QKeyEvent*>(eventObject);
                if (keyEvent->matches(QKeySequence::Copy))
                {
                    copySelectedRowsToClipboard(tableView);
                    keyEvent->accept();
                    return true;
                }
                if (kComparisonActive &&
                    (keyEvent->key() == Qt::Key_Return ||
                        keyEvent->key() == Qt::Key_Enter ||
                        keyEvent->key() == Qt::Key_Space))
                {
                    keyEvent->accept();
                    return true;
                }
            }
            else if (kEventType == QEvent::ContextMenu)
            {
                auto* contextMenuEvent = static_cast<QContextMenuEvent*>(eventObject);
                const QPoint kViewportPosition = watchedObject == tableView
                    ? tableView->viewport()->mapFrom(tableView, contextMenuEvent->pos())
                    : contextMenuEvent->pos();
                const QModelIndex kClickedIndex = tableView->indexAt(kViewportPosition);
                selectContextRow(tableView, kClickedIndex);

                // The menu source has already been recorded by the generic item-view branch; here we only handle table row selection semantics.
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        // m_pendingContextItemView purpose: Stores the table or tree source that the current business right-click menu should bind to.
        QPointer<QAbstractItemView> pendingContextItemView_;
        // m_pendingContextSequence: Distinguishes consecutive right-click events to ensure delayed cleanup affects only the current event.
        unsigned long long pendingContextSequence_ = 0ULL;
        // m_openContextMenuItemViews usage: Binds currently visible business menus to the table or tree that triggered them.
        QHash<QMenu*, QPointer<QAbstractItemView>> openContextMenuItemViews_;
    };
}

namespace ks::ui
{
    void openProcessDetailByPid(const quint32 pid)
    {
        if (pid == 0U)
        {
            return;
        }

        for (QWidget* topLevelWidget : QApplication::topLevelWidgets())
        {
            if (topLevelWidget != nullptr &&
                QMetaObject::invokeMethod(
                    topLevelWidget,
                    "openProcessDetailByPid",
                    Qt::QueuedConnection,
                    Q_ARG(quint32, pid)))
            {
                return;
            }
        }
    }

    void openProcessDetailByIdentity(
        const quint32 pid,
        const quint64 creationTime100ns)
    {
        // History records must not silently degrade to pure PIDs, as PID reuse could otherwise open unrelated processes.
        if (pid == 0U || creationTime100ns == 0U)
        {
            return;
        }

        // topLevelWidget: Iterate to find main window instances with identity-aware slots.
        for (QWidget* topLevelWidget : QApplication::topLevelWidgets())
        {
            if (topLevelWidget != nullptr &&
                QMetaObject::invokeMethod(
                    topLevelWidget,
                    "openProcessDetailByIdentity",
                    Qt::QueuedConnection,
                    Q_ARG(quint32, pid),
                    Q_ARG(quint64, creationTime100ns)))
            {
                return;
            }
        }
    }

    void installGlobalTableInteractionSupport(QApplication* appInstance)
    {
        if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
        {
            return;
        }

        auto* filter = new GlobalTableInteractionSupportFilter(appInstance);
        appInstance->installEventFilter(filter);
        appInstance->setProperty(kInstalledProperty, true);

        for (QWidget* widget : appInstance->allWidgets())
        {
            configureTable(qobject_cast<QTableView*>(widget));
        }
    }

    bool deferTableUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QTableView*>& tableList,
        std::function<void()> commitAction)
    {
        QList<QAbstractItemView*> itemViewList;
        itemViewList.reserve(tableList.size());
        for (QTableView* tableView : tableList)
        {
            itemViewList.push_back(tableView);
        }
        return deferItemViewUiCommitIfNeeded(
            owner,
            commitKey,
            itemViewList,
            std::move(commitAction));
    }

    bool isTableUiCommitBlockedByContextMenu(
        const QList<QTableView*>& tableList)
    {
        QList<QAbstractItemView*> itemViewList;
        itemViewList.reserve(tableList.size());
        for (QTableView* tableView : tableList)
        {
            itemViewList.push_back(tableView);
        }
        return isItemViewUiCommitBlockedByContextMenu(itemViewList);
    }

    bool deferItemViewUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QAbstractItemView*>& itemViewList,
        std::function<void()> commitAction)
    {
        return deferItemViewUiCommitIfNeeded(
            owner,
            commitKey,
            itemViewList,
            std::move(commitAction));
    }

    bool deferUiCommitIfComboBoxPopupOpen(
        QObject* owner,
        const QString& commitKey,
        std::function<void()> commitAction)
    {
        // View collection empty: this entry does not rebuild the table; the barrier is determined solely by the dropdown popup and left Ctrl.
        return deferItemViewUiCommitIfNeeded(
            owner,
            commitKey,
            {},
            std::move(commitAction));
    }

    bool isItemViewUiCommitBlockedByContextMenu(
        const QList<QAbstractItemView*>& itemViewList)
    {
        // Applies to all tables during left Ctrl multi-select or dropdown popup expansion, regardless of the specific view (Issue #149).
        if (isLeftCtrlHeldForMultiSelect() || isComboBoxPopupOpen())
        {
            return true;
        }
        return std::any_of(
            itemViewList.cbegin(),
            itemViewList.cend(),
            [](const QAbstractItemView* itemView)
            {
                return isItemViewContextMenuOpen(itemView);
            });
    }
}

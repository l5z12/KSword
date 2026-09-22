#pragma once

class QApplication;
class QAbstractItemView;
class QObject;
class QTableView;

#include <QList>
#include <QString>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QVariant>
#include <QtGlobal>

#include <functional>

namespace ks::ui
{
    // NumericSortRole:
    // - Store the 'actual numeric value used for sorting' in this cell, completely decoupled from the DisplayRole's readable text;
    // - Tables default to string comparison based on DisplayRole, causing PIDs to sort as 1/10/100/11/2, 512 KB to appear after
    //   2.50 MB, and non-padded hexadecimal addresses to be completely out of order. These issues have been fixed individually in
    //   four separate copy-pasted private NumericItem instances in this repository; this location unifies the fix.
    // - Qt::UserRole cannot be used: the handle page and others already use it to store row indices, which would cause overwrites.
    constexpr int kNumericSortRole = Qt::UserRole + 900;

    // NumericTableItem:
    // - Numeric sort cells for QTableWidget: Display text can be arbitrary
    //   (hexadecimal, KB/MB, with units), but sorting always reads from NumericSortRole.
    // - If this role is missing, fall back to the base class's string comparison; mixing them will not cause crashes.
    class NumericTableItem final : public QTableWidgetItem
    {
    public:
        // Constructor: displayText is the UI text, sortValue is the actual numeric value used for sorting.
        NumericTableItem(const QString& displayText, const qulonglong sortValue)
            : QTableWidgetItem(displayText)
        {
            setData(kNumericSortRole, QVariant::fromValue<qulonglong>(sortValue));
        }

        // Constructor overload: for signed numeric values (e.g., offsets or differences that can be positive or negative).
        NumericTableItem(const QString& displayText, const qlonglong sortValue)
            : QTableWidgetItem(displayText)
        {
            setData(kNumericSortRole, QVariant::fromValue<qlonglong>(sortValue));
        }

        bool operator<(const QTableWidgetItem& otherItem) const override
        {
            const QVariant kLeftValue = data(kNumericSortRole);
            const QVariant kRightValue = otherItem.data(kNumericSortRole);
            if (!kLeftValue.isValid() || !kRightValue.isValid())
            {
                return QTableWidgetItem::operator<(otherItem);
            }
            return kLeftValue.toDouble() < kRightValue.toDouble();
        }
    };

    // NumericTreeItem:
    // - QTreeWidget version: Each column can have its own NumericSortRole; columns without this role are compared using the original string.
    class NumericTreeItem : public QTreeWidgetItem
    {
    public:
        using QTreeWidgetItem::QTreeWidgetItem;

        // setNumericCell purpose: Write the display text and sort value for a specific column in one operation.
        void setNumericCell(const int column, const QString& displayText, const qulonglong sortValue)
        {
            setText(column, displayText);
            setData(column, kNumericSortRole, QVariant::fromValue<qulonglong>(sortValue));
        }

        bool operator<(const QTreeWidgetItem& otherItem) const override
        {
            const QTreeWidget* ownerTree = treeWidget();
            const int kSortedColumn = ownerTree != nullptr ? ownerTree->sortColumn() : 0;
            const QVariant kLeftValue = data(kSortedColumn, kNumericSortRole);
            const QVariant kRightValue = otherItem.data(kSortedColumn, kNumericSortRole);
            if (!kLeftValue.isValid() || !kRightValue.isValid())
            {
                return QTreeWidgetItem::operator<(otherItem);
            }
            return kLeftValue.toDouble() < kRightValue.toDouble();
        }
    };

    // installGlobalTableInteractionSupport:
    // - Provides unified Ctrl-multi-select, Ctrl+C copy, and TSV export for all QTableView/QTableWidget instances within the application.
    // QTableWidget instances without continuous sorting can be sorted once by clicking the header, preventing row misalignment during refresh and table population.
    // - Preserve the original right-click menu of the business table and append 'Copy Selected Row' and 'Export Selected Row' at the end.
    // - Reserve a compact action area at the top of each table and place an export button there; dynamically created tables automatically integrate.
    void installGlobalTableInteractionSupport(QApplication* appInstance);

    // openProcessDetailByPid: Requests the main window to open detailed information for the process with the specified PID.
    // - Explicitly invoked by the right-click menus of respective business tables; does not automatically add menu items to tables.
    // - Do not perform any operation if pid is 0 or the main window has not been created yet.
    void openProcessDetailByPid(quint32 pid);

    // openProcessDetailByIdentity:
    // - Request to open historical process details by PID and creation time at capture time;
    // - Invocation: Right-click menu on a business table holding historical event identities;
    // - Input pid: Process PID from historical events.
    // - Input parameter creationTime100ns: the process creation time when the historical event was captured;
    // - Returns: None; if identity is missing, it does not degrade to a pure PID jump.
    void openProcessDetailByIdentity(
        quint32 pid,
        quint64 creationTime100ns);

    // isTableUiCommitBlockedByContextMenu:
    // - Input: All tables modified by a single UI commit;
    // - Returns: true if any table's context menu is still open or the user is still holding the left Ctrl key for multi-selection (Issue #149);
    // - Used by refresh entry points carrying large movable snapshots to check first, avoiding normal refreshes from copying the entire data via delayed callbacks.
    bool isTableUiCommitBlockedByContextMenu(
        const QList<QTableView*>& tableList);

    // isItemViewUiCommitBlockedByContextMenu:
    // - Consistent with table versions, but also supports QTreeView/QTreeWidget.
    // - Provides an asynchronous rebuild entry point for business right-click menus in device trees, handle trees, etc.
    // - Return true uniformly for all views while left Ctrl multi-selection is in progress (Issue #149).
    bool isItemViewUiCommitBlockedByContextMenu(
        const QList<QAbstractItemView*>& itemViewList);

    // deferTableUiCommitIfContextMenuOpen:
    // - Input: Commit task owner, stable deduplication key, table collection to be rebuilt, and UI commit function;
    // - Handling: When any table context menu is open or left Ctrl multi-selection is in progress, only the latest commit for
    //   the same owner/key is retained; after the menu closes and left Ctrl is released, the commit is re-injected (Issue #149).
    // - Returns: true indicates this commit was deferred; false indicates no caching is needed, and the caller should commit immediately.
    // Call this method: the refresh function is invoked before modifying the model; returns true to immediately terminate the current refresh cycle.
    bool deferTableUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QTableView*>& tableList,
        std::function<void()> commitAction);

    // deferItemViewUiCommitIfContextMenuOpen:
    // - Provide consistent menu/left Ctrl barrier and owner/key latest-wins semantics for QTableView and QTreeView;
    // - The refresh function must be called before clearing the cache, model, or items; return true to exit immediately.
    bool deferItemViewUiCommitIfContextMenuOpen(
        QObject* owner,
        const QString& commitKey,
        const QList<QAbstractItemView*>& itemViewList,
        std::function<void()> commitAction);

    // deferUiCommitIfComboBoxPopupOpen:
    // - Input: submit task owner, stable deduplication key, and UI commit function;
    // - Handling: When any QComboBox popup is expanded, only retain the latest commit for the same owner/key; re-inject after the popup closes.
    // - Returns: true indicates this commit is deferred; false indicates it can be committed immediately.
    // Called by: Async backfill entry that rebuilds only the combo box content without reconstructing the table, invoked before modifying the control.
    // Why: Popups are independent top-level windows that capture mouse and keyboard input. If they are cleared and repopulated during expansion,
    //      they continue capturing input while the content becomes invalid, resulting in the user seeing a frozen interface after opening the dropdown.
    bool deferUiCommitIfComboBoxPopupOpen(
        QObject* owner,
        const QString& commitKey,
        std::function<void()> commitAction);
}

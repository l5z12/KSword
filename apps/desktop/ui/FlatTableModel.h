#pragma once

#include <QAbstractTableModel>
#include <QMetaType>
#include <QString>
#include <QVariant>

#include "../internationalization/LanguageManager.h"

#include <cstddef>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ks::ui
{
    // FlatTableModel:
    // - Provides a lightweight model for read-only QTableView using an array of row objects as the sole data source;
    // - Suitable for tables without hierarchical relationships, such as logs, search results, and snapshot lists.
    // - The goal is to replace the significant object overhead of QTableWidget/QTreeWidget items.
    template<typename RowT>
    class FlatTableModel final : public QAbstractTableModel
    {
    public:
        using RowType = RowT;

        // DataResolver:
        // - External callers uniformly return cell data based on 'row + column + role'.
        // - Allow the caller to handle roles such as Display, ToolTip, and Background within a single function;
        // - This is more lightweight than maintaining independent item objects for each cell.
        using DataResolver = std::function<QVariant(const RowType& row, int column, int role)>;

        // FlagsResolver:
        // - Allows callers to dynamically control Qt item flags by row/column;
        // - Default to read-only and selectable to maintain compatibility with existing tables.
        // - The process-friendly view uses this to prevent selection of category headings and application aggregate rows, avoiding accidental process actions.
        using FlagsResolver = std::function<Qt::ItemFlags(const RowType& row, int column)>;

        // KeyResolver:
        // - Return stable and unique row keys to support incremental updates for long tables;
        // - If not provided, retain the original reset mode to adapt to snapshots without stable identities, such as logs.
        using KeyResolver = std::function<std::string(const RowType& row)>;

        struct UpdateStats
        {
            int insertedRowCount = 0;
            int removedRowCount = 0;
            int updatedRowCount = 0;
            bool orderChanged = false;
            bool modelReset = false;
        };

        // ColumnSpec:
        // - Stores horizontal header text and default alignment;
        // - Actual data is provided by DataResolver.
        struct ColumnSpec
        {
            QString headerText;
            Qt::Alignment alignment = Qt::AlignLeft | Qt::AlignVCenter;
        };

        // Constructor purpose:
        // - Accept fixed column definitions and a data resolver callback;
        // - Return: None. The model object is directly bound to QTableView.
        explicit FlatTableModel(
            std::vector<ColumnSpec> columns,
            DataResolver resolver,
            QObject* parent = nullptr,
            FlagsResolver flagsResolver = FlagsResolver(),
            KeyResolver keyResolver = KeyResolver())
            : QAbstractTableModel(parent)
            , columns_(std::move(columns))
            , dataResolver_(std::move(resolver))
            , flagsResolver_(std::move(flagsResolver))
            , keyResolver_(std::move(keyResolver))
        {
        }

        // setRows:
        // - Replace the current snapshot with a batch of new rows.
        // - With a stable key, publishes incrementally via delete/insert/layout/dataChanged signals.
        // - Falls back to beginResetModel/endResetModel when there is no stable key or keys are duplicated.
        // Parameter rows: The new set of visible rows.
        UpdateStats setRows(std::vector<RowType> rows)
        {
            if (!keyResolver_)
            {
                return resetRows(std::move(rows));
            }
            return setRowsIncrementally(std::move(rows));
        }

        // clearRows:
        // - Clear current snapshot;
        // - Intended for direct invocation in scenarios such as 'clear log' or 'clear results'.
        void clearRows()
        {
            if (rows_.empty())
            {
                return;
            }

            beginResetModel();
            rows_.clear();
            endResetModel();
        }

        // rowAt:
        // - Read a row from the current snapshot by row index.
        // - Returns nullptr on out-of-bounds access to facilitate safe null checks by the caller.
        const RowType* rowAt(const int row) const
        {
            if (row < 0 || row >= static_cast<int>(rows_.size()))
            {
                return nullptr;
            }
            return &rows_[static_cast<std::size_t>(row)];
        }

        // rows: Returns a read-only reference to the current snapshot for reuse by export/copy logic.
        const std::vector<RowType>& rows() const
        {
            return rows_;
        }

        // rowCount purpose: Returns the current snapshot row count; does not expand child nodes when the parent index is valid.
        int rowCount(const QModelIndex& parent = QModelIndex()) const override
        {
            return parent.isValid() ? 0 : static_cast<int>(rows_.size());
        }

        // columnCount purpose: Return a fixed column count; do not expand child nodes when the parent index is valid.
        int columnCount(const QModelIndex& parent = QModelIndex()) const override
        {
            return parent.isValid() ? 0 : static_cast<int>(columns_.size());
        }

        // data:
        // - Return cell data to the view based on role;
        // - Unified control of roles by column definitions; other roles are delegated to DataResolver.
        QVariant data(const QModelIndex& index, const int role) const override
        {
            if (!index.isValid())
            {
                return {};
            }

            const int kRow = index.row();
            const int kColumn = index.column();
            if (kRow < 0 || kColumn < 0 ||
                kRow >= static_cast<int>(rows_.size()) ||
                kColumn >= static_cast<int>(columns_.size()))
            {
                return {};
            }

            if (role == Qt::TextAlignmentRole)
            {
                return static_cast<int>(columns_[static_cast<std::size_t>(kColumn)].alignment);
            }

            if (!dataResolver_)
            {
                return {};
            }

            const QVariant kResolvedData = dataResolver_(
                rows_[static_cast<std::size_t>(kRow)],
                kColumn,
                role);
            if ((role == Qt::DisplayRole || role == Qt::ToolTipRole)
                && kResolvedData.metaType().id() == QMetaType::QString)
            {
                return ks::i18n::sourceText(kResolvedData.toString());
            }
            return kResolvedData;
        }

        // headerData:
        // Provide header text only for horizontal headers.
        // - Return empty value for vertical headers and other roles uniformly.
        QVariant headerData(const int section, const Qt::Orientation orientation, const int role) const override
        {
            if (orientation != Qt::Horizontal || role != Qt::DisplayRole)
            {
                return {};
            }

            if (section < 0 || section >= static_cast<int>(columns_.size()))
            {
                return {};
            }

            return ks::i18n::displayText(
                columns_[static_cast<std::size_t>(section)].headerText);
        }

        // flags:
        // Keeps the table read-only
        // - Allow the view to support selection and context menu positioning.
        Qt::ItemFlags flags(const QModelIndex& index) const override
        {
            if (!index.isValid())
            {
                return Qt::NoItemFlags;
            }

            const int kRow = index.row();
            const int kColumn = index.column();
            if (kRow < 0 || kColumn < 0 ||
                kRow >= static_cast<int>(rows_.size()) ||
                kColumn >= static_cast<int>(columns_.size()))
            {
                return Qt::NoItemFlags;
            }

            if (flagsResolver_)
            {
                return flagsResolver_(rows_[static_cast<std::size_t>(kRow)], kColumn);
            }

            return Qt::ItemIsEnabled | Qt::ItemIsSelectable;
        }

    private:
        std::vector<ColumnSpec> columns_;  // m_columns: Fixed horizontal column definitions.
        DataResolver dataResolver_;        // m_dataResolver: Cell role resolver.
        FlagsResolver flagsResolver_;      // m_flagsResolver: Optional row flags resolver; remains optional by default if not set.
        KeyResolver keyResolver_;          // m_keyResolver: Optional stable row key, enabling incremental key updates.
        std::vector<RowType> rows_;        // m_rows: Snapshot of currently visible rows.

        UpdateStats resetRows(std::vector<RowType> rows)
        {
            UpdateStats stats;
            stats.updatedRowCount = static_cast<int>(rows.size());
            stats.modelReset = true;
            beginResetModel();
            rows_ = std::move(rows);
            endResetModel();
            return stats;
        }

        bool collectUniqueKeys(
            const std::vector<RowType>& rows,
            std::vector<std::string>& keyList,
            std::unordered_set<std::string>& keySet) const
        {
            keyList.clear();
            keySet.clear();
            keyList.reserve(rows.size());
            keySet.reserve(rows.size());
            for (const RowType& row : rows)
            {
                std::string key = keyResolver_(row);
                if (key.empty() || !keySet.insert(key).second)
                {
                    return false;
                }
                keyList.push_back(std::move(key));
            }
            return true;
        }

        UpdateStats setRowsIncrementally(std::vector<RowType> rows)
        {
            std::vector<std::string> newKeys;
            std::unordered_set<std::string> newKeySet;
            std::vector<std::string> oldKeys;
            std::unordered_set<std::string> oldKeySet;
            if (!collectUniqueKeys(rows, newKeys, newKeySet) ||
                !collectUniqueKeys(rows_, oldKeys, oldKeySet))
            {
                return resetRows(std::move(rows));
            }

            UpdateStats stats;

            // First, delete keys that no longer exist in the new snapshot using a continuous interval. Processing in reverse order ensures remaining row indices remain stable.
            for (int lastRow = static_cast<int>(rows_.size()) - 1; lastRow >= 0;)
            {
                const std::string& key = oldKeys[static_cast<std::size_t>(lastRow)];
                if (newKeySet.find(key) != newKeySet.end())
                {
                    --lastRow;
                    continue;
                }

                int firstRow = lastRow;
                while (firstRow > 0 &&
                    newKeySet.find(oldKeys[static_cast<std::size_t>(firstRow - 1)]) == newKeySet.end())
                {
                    --firstRow;
                }
                beginRemoveRows(QModelIndex(), firstRow, lastRow);
                rows_.erase(rows_.begin() + firstRow, rows_.begin() + lastRow + 1);
                oldKeys.erase(oldKeys.begin() + firstRow, oldKeys.begin() + lastRow + 1);
                endRemoveRows();
                stats.removedRowCount += lastRow - firstRow + 1;
                lastRow = firstRow - 1;
            }

            // New keys are first appended to the end, then moved to their final positions via a single layout change.
            oldKeySet.clear();
            oldKeySet.insert(oldKeys.cbegin(), oldKeys.cend());
            std::vector<std::size_t> insertedNewRowIndexes;
            for (std::size_t newRow = 0; newRow < newKeys.size(); ++newRow)
            {
                if (oldKeySet.find(newKeys[newRow]) != oldKeySet.end())
                {
                    continue;
                }
                insertedNewRowIndexes.push_back(newRow);
                oldKeySet.insert(newKeys[newRow]);
            }
            if (!insertedNewRowIndexes.empty())
            {
                const int kFirstInsertRow = static_cast<int>(rows_.size());
                const int kLastInsertRow = kFirstInsertRow + static_cast<int>(insertedNewRowIndexes.size()) - 1;
                beginInsertRows(QModelIndex(), kFirstInsertRow, kLastInsertRow);
                for (const std::size_t kNewRow : insertedNewRowIndexes)
                {
                    rows_.push_back(rows[kNewRow]);
                    oldKeys.push_back(newKeys[kNewRow]);
                }
                endInsertRows();
                stats.insertedRowCount = static_cast<int>(insertedNewRowIndexes.size());
            }

            stats.orderChanged = (oldKeys != newKeys);
            if (stats.orderChanged)
            {
                std::unordered_map<std::string, int> newRowByKey;
                newRowByKey.reserve(newKeys.size());
                for (int row = 0; row < static_cast<int>(newKeys.size()); ++row)
                {
                    newRowByKey.emplace(newKeys[static_cast<std::size_t>(row)], row);
                }

                const QModelIndexList kOldPersistentIndexes = persistentIndexList();
                QModelIndexList newPersistentIndexes;
                newPersistentIndexes.reserve(kOldPersistentIndexes.size());
                for (const QModelIndex& oldIndex : kOldPersistentIndexes)
                {
                    if (!oldIndex.isValid() || oldIndex.row() < 0 ||
                        oldIndex.row() >= static_cast<int>(oldKeys.size()))
                    {
                        newPersistentIndexes.push_back(QModelIndex());
                        continue;
                    }
                    const auto kTargetIt = newRowByKey.find(oldKeys[static_cast<std::size_t>(oldIndex.row())]);
                    newPersistentIndexes.push_back(
                        kTargetIt == newRowByKey.end()
                        ? QModelIndex()
                        : createIndex(kTargetIt->second, oldIndex.column()));
                }

                emit layoutAboutToBeChanged({}, QAbstractItemModel::VerticalSortHint);
                rows_ = std::move(rows);
                changePersistentIndexList(kOldPersistentIndexes, newPersistentIndexes);
                emit layoutChanged({}, QAbstractItemModel::VerticalSortHint);
            }
            else
            {
                rows_ = std::move(rows);
            }

            stats.updatedRowCount = static_cast<int>(rows_.size());
            if (!rows_.empty() && !columns_.empty())
            {
                emit dataChanged(
                    index(0, 0),
                    index(static_cast<int>(rows_.size()) - 1, static_cast<int>(columns_.size()) - 1));
            }
            return stats;
        }
    };
}

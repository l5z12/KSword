#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::showHeaderContextMenu(const QPoint& localPosition)
{
    Q_UNUSED(localPosition);

    if (processTable_ == nullptr)
    {
        return;
    }

    QMenu columnMenu(this);
    columnMenu.setStyleSheet(ksword_theme::contextMenuStyle());

    // The top-level entry points to the full 'Select Columns' dialog: since the number of columns is close to the full
    // set in Task Manager, a right-click menu that adds or removes items one by one is insufficient for batch operations.
    QAction* const kChooserAction = columnMenu.addAction(
        processContextText("process.columns.menu.open_chooser", QStringLiteral("选择列...")));
    QAction* const kResetAction = columnMenu.addAction(
        processContextText("process.columns.menu.reset_default", QStringLiteral("恢复默认列")));
    columnMenu.addSeparator();

    // The rest are per-column quick-select actions, preserving the original 'click to toggle a column' interaction.
    std::vector<QAction*> columnActions;
    columnActions.reserve(static_cast<std::size_t>(TableColumn::kCount));
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
    {
        QAction* toggleAction = columnMenu.addAction(
            translatedProcessHeader(columnIndex, kProcessTableHeaders.at(columnIndex)));
        toggleAction->setCheckable(true);
        toggleAction->setChecked(!processTable_->isColumnHidden(columnIndex));
        toggleAction->setData(columnIndex);
        // The process name column serves as the row identifier and cannot be hidden entirely.
        toggleAction->setEnabled(columnIndex != toColumnIndex(TableColumn::kName));
        columnActions.push_back(toggleAction);
    }

    QAction* selectedAction = columnMenu.exec(QCursor::pos());
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == kChooserAction)
    {
        showColumnChooserDialog();
        return;
    }
    if (selectedAction == kResetAction)
    {
        resetProcessColumnsToViewDefault();
        return;
    }

    const int kColumnIndex = selectedAction->data().toInt();
    const bool kShouldShow = selectedAction->isChecked();
    setProcessColumnVisible(kColumnIndex, kShouldShow);

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 列显示状态变更, column=" << kColumnIndex
        << ", header=" << kProcessTableHeaders.value(kColumnIndex).toStdString()
        << ", visible=" << (kShouldShow ? "true" : "false")
        << eol;
}

void ProcessDock::copyCurrentCell()
{
    if (processTable_ == nullptr)
    {
        return;
    }

    int currentColumn = 0;
    if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
    {
        currentColumn = selectionModel->currentIndex().column();
    }
    currentColumn = std::clamp(currentColumn, 0, static_cast<int>(TableColumn::kCount) - 1);

    const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(true);
    QStringList cellTexts;
    cellTexts.reserve(static_cast<int>(kSelectedRows.size()));
    std::unordered_set<std::string> visitedIdentitySet;
    for (const QModelIndex& rowIndex : kSelectedRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr)
        {
            continue;
        }
        if (!tableRow->identityKey.empty() && visitedIdentitySet.find(tableRow->identityKey) != visitedIdentitySet.end())
        {
            continue;
        }
        if (!tableRow->identityKey.empty())
        {
            visitedIdentitySet.insert(tableRow->identityKey);
        }

        const QModelIndex kCellIndex = rowIndex.sibling(rowIndex.row(), currentColumn);
        cellTexts.push_back(kCellIndex.data(Qt::DisplayRole).toString());
    }

    QApplication::clipboard()->setText(cellTexts.join("\n"));

    KLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] 复制单元格, column=" << currentColumn
        << ", rowCount=" << cellTexts.size()
        << ", text=" << cellTexts.join("\\n").toStdString()
        << eol;
}

void ProcessDock::copyCurrentRow()
{
    if (processTable_ == nullptr)
    {
        return;
    }

    const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(true);
    QStringList rowTexts;
    rowTexts.reserve(static_cast<int>(kSelectedRows.size()));
    std::unordered_set<std::string> visitedIdentitySet;
    for (const QModelIndex& rowIndex : kSelectedRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr)
        {
            continue;
        }
        if (!tableRow->identityKey.empty() && visitedIdentitySet.find(tableRow->identityKey) != visitedIdentitySet.end())
        {
            continue;
        }
        if (!tableRow->identityKey.empty())
        {
            visitedIdentitySet.insert(tableRow->identityKey);
        }

        QStringList rowFields;
        rowFields.reserve(static_cast<int>(TableColumn::kCount));
        for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
        {
            const QModelIndex kCellIndex = rowIndex.sibling(rowIndex.row(), columnIndex);
            rowFields.push_back(kCellIndex.data(Qt::DisplayRole).toString());
        }
        rowTexts.push_back(rowFields.join("\t"));
    }
    QApplication::clipboard()->setText(rowTexts.join("\n"));

    KLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] 复制整行, rowCount=" << rowTexts.size()
        << ", text=" << rowTexts.join("\\n").toStdString()
        << eol;
}

void ProcessDock::bindContextActionToIndex(const QModelIndex& clickedIndex)
{
    clearContextActionBinding();
    if (processTable_ == nullptr)
    {
        return;
    }

    // Right-click action binding:
    // - Prioritize binding all currently selected rows to naturally support Ctrl-click multi-selection for menu actions;
    // - If no row is currently selected, fall back to the single row clicked via right-click.
    const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(true);
    std::vector<QModelIndex> effectiveRows = kSelectedRows;
    if (effectiveRows.empty() && clickedIndex.isValid())
    {
        effectiveRows.push_back(clickedIndex.sibling(clickedIndex.row(), 0));
    }

    std::unordered_set<std::string> visitedIdentitySet;
    for (const QModelIndex& rowIndex : effectiveRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr)
        {
            continue;
        }
        appendProcessActionTargetsFromTableRow(*tableRow, contextActionRecords_, visitedIdentitySet);
    }

    if (contextActionRecords_.empty())
    {
        return;
    }

    contextActionIdentityKey_ = contextActionRecords_.front().identityKey;
    contextActionRecord_ = contextActionRecords_.front().record;
    hasContextActionRecord_ = true;
}

void ProcessDock::clearContextActionBinding()
{
    contextActionIdentityKey_.clear();
    contextActionRecords_.clear();
    hasContextActionRecord_ = false;
    contextMenuVisible_ = false;
}

std::string ProcessDock::selectedIdentityKey() const
{
    if (!contextActionIdentityKey_.empty())
    {
        return contextActionIdentityKey_;
    }

    if (processTable_ == nullptr)
    {
        return std::string();
    }

    if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
    {
        const QModelIndex kCurrentIndex = selectionModel->currentIndex();
        const ProcessTableRow* tableRow = processTableRowForViewIndex(kCurrentIndex);
        if (tableRow != nullptr && tableRow->rowKind == ProcessTableRowKind::kProcess)
        {
            return tableRow->identityKey;
        }
        if (tableRow != nullptr &&
            tableRow->rowKind == ProcessTableRowKind::kApplicationAggregate &&
            tableRow->actionIdentityKeys.size() == 1U)
        {
            return tableRow->actionIdentityKeys.front();
        }
    }
    return std::string();
}

ks::process::ProcessRecord* ProcessDock::selectedRecord()
{
    const std::string kIdentityKey = selectedIdentityKey();
    if (kIdentityKey.empty())
    {
        return nullptr;
    }

    auto cacheIt = cacheByIdentity_.find(kIdentityKey);
    if (cacheIt == cacheByIdentity_.end())
    {
        if (hasContextActionRecord_)
        {
            return &contextActionRecord_;
        }
        return nullptr;
    }
    return &cacheIt->second.record;
}

std::vector<ProcessDock::ProcessActionTarget> ProcessDock::selectedActionTargets() const
{
    // Prioritize frozen action bindings during right-click menu pop-up to prevent refresh or selection changes from affecting the execution target.
    if (!contextActionRecords_.empty())
    {
        return contextActionRecords_;
    }

    std::vector<ProcessActionTarget> actionTargets;
    std::unordered_set<std::string> visitedIdentitySet;

    if (processTable_ != nullptr)
    {
        const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(true);
        for (const QModelIndex& rowIndex : kSelectedRows)
        {
            const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
            if (tableRow == nullptr)
            {
                continue;
            }
            appendProcessActionTargetsFromTableRow(*tableRow, actionTargets, visitedIdentitySet);
        }
    }

    return actionTargets;
}

std::vector<ProcessDock::ProcessActionTarget> ProcessDock::processTreeActionTargets() const
{
    // Process tree identification reads only the R3-refreshed main process cache.
    // - Do not read R0 cross-view or R0-only rows to avoid kernel enumeration results altering parent-child relationships;
    // - Retains only records that are still alive in the latest round to avoid polluting tree targets with terminated processes or PID reuse.
    std::unordered_map<std::uint32_t, std::vector<ProcessActionTarget>> childrenByParentPid;
    childrenByParentPid.reserve(cacheByIdentity_.size());
    for (const auto& cachePair : cacheByIdentity_)
    {
        const CacheEntry& cacheEntry = cachePair.second;
        if (cacheEntry.isExitedInLatestRound || cacheEntry.record.pid == 0U)
        {
            continue;
        }

        ProcessActionTarget snapshotTarget{};
        snapshotTarget.identityKey = cachePair.first;
        snapshotTarget.record = cacheEntry.record;
        childrenByParentPid[snapshotTarget.record.parentPid].push_back(std::move(snapshotTarget));
    }

    // Fix the traversal order for the same parent node to ensure the generated action list from the same R3 snapshot is consistent every time.
    for (auto& childPair : childrenByParentPid)
    {
        std::vector<ProcessActionTarget>& childTargets = childPair.second;
        std::sort(childTargets.begin(), childTargets.end(), [](const ProcessActionTarget& left, const ProcessActionTarget& right)
        {
            if (left.record.pid != right.record.pid)
            {
                return left.record.pid < right.record.pid;
            }
            return left.identityKey < right.identityKey;
        });
    }

    const std::vector<ProcessActionTarget> kSelectedTargets = selectedActionTargets();
    std::vector<ProcessActionTarget> pendingTargets;
    pendingTargets.reserve(cacheByIdentity_.size());
    std::unordered_set<std::uint32_t> scheduledPidSet;
    scheduledPidSet.reserve(cacheByIdentity_.size());

    // The selected root must also exist in the R3 main cache; R0-only rows are not treated as process tree roots.
    for (const ProcessActionTarget& selectedTarget : kSelectedTargets)
    {
        const auto kCacheIt = cacheByIdentity_.find(selectedTarget.identityKey);
        if (kCacheIt == cacheByIdentity_.end() ||
            kCacheIt->second.isExitedInLatestRound ||
            kCacheIt->second.record.pid == 0U)
        {
            continue;
        }

        const std::uint32_t kProcessId = kCacheIt->second.record.pid;
        if (!scheduledPidSet.insert(kProcessId).second)
        {
            continue;
        }

        ProcessActionTarget rootTarget{};
        rootTarget.identityKey = kCacheIt->first;
        rootTarget.record = kCacheIt->second.record;
        pendingTargets.push_back(std::move(rootTarget));
    }

    std::vector<ProcessActionTarget> treeTargets;
    treeTargets.reserve(pendingTargets.size());
    for (std::size_t pendingIndex = 0U; pendingIndex < pendingTargets.size(); ++pendingIndex)
    {
        ProcessActionTarget currentTarget = pendingTargets[pendingIndex];
        treeTargets.push_back(currentTarget);

        const auto kChildIt = childrenByParentPid.find(currentTarget.record.pid);
        if (kChildIt == childrenByParentPid.end())
        {
            continue;
        }

        for (const ProcessActionTarget& childTarget : kChildIt->second)
        {
            if (scheduledPidSet.insert(childTarget.record.pid).second)
            {
                pendingTargets.push_back(childTarget);
            }
        }
    }

    return treeTargets;
}

void ProcessDock::clearProcessTableSelection()
{
    if (processTable_ == nullptr || contextMenuVisible_)
    {
        return;
    }

    // hadSelectionState：
    // - Check both the current Qt selection and the cross-refresh tracked key;
    // - Avoid repeatedly refreshing the chart and viewport when no selection exists.
    const bool kHadSelectionState =
        !selectedProcessTableRowIndexes(true).empty() ||
        !trackedSelectedIdentityKey_.empty() ||
        !trackedSelectedIdentityKeys_.empty();
    if (!kHadSelectionState)
    {
        return;
    }

    // Clear the Qt selection model:
    // - Block intermediate signals to prevent selectionChanged from re-writing the tracking key before currentIndex is cleared.
    // - Subsequently manually refresh the active graph to ensure the UI state updates only once.
    {
        QSignalBlocker tableSignalBlocker(processTable_);
        if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
        {
            QSignalBlocker selectionSignalBlocker(selectionModel);
            selectionModel->clear();
        }
        processTable_->setCurrentIndex(QModelIndex());
    }

    // Clear ProcessDock's own cross-refresh selection cache, set the active graph selectionKeys to empty, and return to the overall curve.
    trackedSelectedIdentityKey_.clear();
    trackedSelectedIdentityKeys_.clear();
    trackedSelectedColumn_ = 0;
    clearContextActionBinding();

    refreshProcessActivityChart();
    if (activityTimelineSlider_ != nullptr && !activitySamples_.empty())
    {
        previewProcessActivitySnapshotForIndex(activityTimelineSlider_->value());
    }
    processTable_->viewport()->update();

    KLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] 已清空进程表选择，活动图切换为整体视图。"
        << eol;
}

void ProcessDock::syncTrackedSelectionFromTable()
{
    if (processTable_ == nullptr || contextMenuVisible_)
    {
        return;
    }

    std::vector<std::string> selectedIdentityKeys;
    std::unordered_set<std::string> visitedIdentitySet;
    const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(false);
    selectedIdentityKeys.reserve(kSelectedRows.size());

    for (const QModelIndex& rowIndex : kSelectedRows)
    {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
        if (tableRow == nullptr ||
            tableRow->rowKind != ProcessTableRowKind::kProcess ||
            tableRow->identityKey.empty())
        {
            continue;
        }
        if (!visitedIdentitySet.insert(tableRow->identityKey).second)
        {
            continue;
        }
        selectedIdentityKeys.push_back(tableRow->identityKey);
    }

    const QModelIndex kCurrentIndex = processTable_->selectionModel() != nullptr
        ? processTable_->selectionModel()->currentIndex()
        : QModelIndex();
    const ProcessTableRow* currentRow = processTableRowForViewIndex(kCurrentIndex);
    if (currentRow != nullptr &&
        currentRow->rowKind == ProcessTableRowKind::kProcess &&
        !currentRow->identityKey.empty())
    {
        trackedSelectedIdentityKey_ = currentRow->identityKey;
        if (visitedIdentitySet.find(currentRow->identityKey) == visitedIdentitySet.end())
        {
            selectedIdentityKeys.push_back(currentRow->identityKey);
        }
    }
    else
    {
        trackedSelectedIdentityKey_.clear();
    }

    trackedSelectedIdentityKeys_ = std::move(selectedIdentityKeys);
}

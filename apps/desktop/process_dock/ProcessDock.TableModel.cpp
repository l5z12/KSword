#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::rebuildTable()
{
    if (processTable_ == nullptr || processTableModel_ == nullptr || processSortProxy_ == nullptr)
    {
        return;
    }

    // The right-click menu saves the current model row. Do not replace the model before the menu
    // closes, otherwise periodic refreshes may cause menu actions to target a different process.
    const QPointer<ProcessDock> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("process-main-table-rebuild"),
        {processTable_},
        [kSafeThis]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->rebuildTable();
            }
        }))
    {
        return;
    }

    const auto kTableRebuildStartTime = std::chrono::steady_clock::now();

    if (isProcessActivityTableSnapshotActive())
    {
        rebuildProcessActivityTableSnapshotRecords();
    }

    // Record the user's current sort column and order to resolve the issue where sorting resets to PID after a refresh.
    QHeaderView* headerView = processTable_->horizontalHeader();
    const int kPreviousSortColumn = headerView != nullptr
        ? headerView->sortIndicatorSection()
        : toColumnIndex(TableColumn::kPid);
    const Qt::SortOrder kPreviousSortOrder = headerView != nullptr
        ? headerView->sortIndicatorOrder()
        : Qt::AscendingOrder;
    // Use PID when the header has not yet generated a sort indicator, ensuring the sort key snapshot matches the actual sort column.
    const int kSafePreviousSortColumn =
        (kPreviousSortColumn >= 0 && kPreviousSortColumn < static_cast<int>(TableColumn::kCount))
        ? kPreviousSortColumn
        : toColumnIndex(TableColumn::kPid);
    const std::string kTrackedIdentityKeyBeforeRebuild =
        !trackedSelectedIdentityKey_.empty()
        ? trackedSelectedIdentityKey_
        : selectedIdentityKey();
    std::unordered_set<std::string> trackedIdentityKeysBeforeRebuild;
    for (const std::string& identityKey : trackedSelectedIdentityKeys_)
    {
        if (!identityKey.empty())
        {
            trackedIdentityKeysBeforeRebuild.insert(identityKey);
        }
    }
    if (!kTrackedIdentityKeyBeforeRebuild.empty())
    {
        trackedIdentityKeysBeforeRebuild.insert(kTrackedIdentityKeyBeforeRebuild);
    }
    const int kTrackedColumnBeforeRebuild = std::clamp(
        trackedSelectedColumn_,
        0,
        static_cast<int>(TableColumn::kCount) - 1);

    // Scroll position snapshot:
    // - Save the user viewport position before refresh.
    // - Restore scroll position after refresh to avoid jumping to the top on each data replacement.
    QScrollBar* verticalScrollBar = processTable_->verticalScrollBar();
    QScrollBar* horizontalScrollBar = processTable_->horizontalScrollBar();
    const int kVerticalScrollValueBeforeRebuild = (verticalScrollBar != nullptr) ? verticalScrollBar->value() : 0;
    const int kHorizontalScrollValueBeforeRebuild = (horizontalScrollBar != nullptr) ? horizontalScrollBar->value() : 0;

    const bool kActivitySnapshotActive = isProcessActivityTableSnapshotActive();
    const bool kSearchResultActive = !currentProcessSearchText().isEmpty();
    // Historical snapshots and search results are flat; the proxy can be used directly for sorting. Tree and friendly grouping modes retain their respective row order semantics.
    const bool kEnableSorting = kActivitySnapshotActive || kSearchResultActive ||
        (!isTreeModeEnabled() && !isFriendlyViewEnabled());
    if (processSortProxy_ != nullptr)
    {
        auto* processSortProxy = static_cast<ProcessTableSortProxy*>(processSortProxy_);
        processSortProxy->setPreserveSourceOrder(!kEnableSorting);
    }

    const std::vector<DisplayRow> kDisplayRows = buildDisplayOrder();

    // Pre-calculate the maximum amplitude for all resource/workload columns in this round for shared cell intensity coloring.
    // CPU/GPU represent absolute percentages from 0 to 100; other metrics are normalized against the maximum value in the same column among currently visible processes.
    processUsageHighlightMaximums_.fill(0.0);
    for (const DisplayRow& displayRow : kDisplayRows)
    {
        if (displayRow.record == nullptr || displayRow.rowKind == ProcessTableRowKind::kGroupHeader)
        {
            continue;
        }

        for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
        {
            const TableColumn kTableColumn = static_cast<TableColumn>(columnIndex);
            double highlightValue = 0.0;
            if (!processUsageHighlightValue(*displayRow.record, kTableColumn, &highlightValue))
            {
                continue;
            }
            double& maximumValue = processUsageHighlightMaximums_[static_cast<std::size_t>(columnIndex)];
            maximumValue = std::max(maximumValue, highlightValue);
        }
    }
    // Aggregated rows sum member percentages, which may exceed 100; single-process CPU/GPU coloring must still maintain an absolute 0~100 scale.
    processUsageHighlightMaximums_[static_cast<std::size_t>(TableColumn::kCpu)] = 100.0;
    processUsageHighlightMaximums_[static_cast<std::size_t>(TableColumn::kGpu)] = 100.0;

    // tableRows:
    // - Convert DisplayRow to a lightweight row snapshot directly held by FlatTableModel;
    // - All colors, sort keys, and icons are lazily resolved by processTableData via role.
    // - This way, each refresh only replaces the vector, avoiding creation/destruction of old items.
    // The 'Type' column requires per-row classification of applications/background/systems. Friendly views include this info in DisplayRow; tree
    // and list views must compute it separately. Only perform this when the column is visible to avoid enumerating windows for hidden columns.
    const bool kProcessTypeColumnVisible = isProcessColumnVisible(TableColumn::kProcessType);
    std::unordered_map<std::uint32_t, FriendlyProcessGroupType> friendlyGroupTypeByPid;
    if (kProcessTypeColumnVisible && !isFriendlyViewEnabled())
    {
        friendlyGroupTypeByPid = buildFriendlyGroupTypeByPid();
    }

    std::vector<ProcessTableRow> tableRows;
    tableRows.reserve(kDisplayRows.size());
    for (const DisplayRow& displayRow : kDisplayRows)
    {
        if (displayRow.record == nullptr)
        {
            continue;
        }

        const ks::process::ProcessRecord& processRecord = *displayRow.record;
        ProcessTableRow tableRow{};
        tableRow.record = processRecord;
        tableRow.rowKind = displayRow.rowKind;
        tableRow.friendlyGroupType = displayRow.friendlyGroupType;
        if (!friendlyGroupTypeByPid.empty())
        {
            const auto kGroupTypeIt = friendlyGroupTypeByPid.find(processRecord.pid);
            if (kGroupTypeIt != friendlyGroupTypeByPid.end())
            {
                tableRow.friendlyGroupType = kGroupTypeIt->second;
            }
        }
        tableRow.syntheticTitle = displayRow.syntheticTitle;
        tableRow.expansionKey = displayRow.expansionKey;
        tableRow.actionIdentityKeys = displayRow.actionIdentityKeys;
        tableRow.identityKey = displayRow.rowKind == ProcessTableRowKind::kProcess
            ? ks::process::buildProcessIdentityKey(processRecord.pid, processRecord.creationTime100ns)
            : std::string();
        if (displayRow.rowKind == ProcessTableRowKind::kProcess && !displayRow.isExited)
        {
            tableRow.cpuCoreProcessIds.push_back(processRecord.pid);
        }
        else if (displayRow.rowKind == ProcessTableRowKind::kApplicationAggregate)
        {
            // Apply the parent row's existing member identity list, resolve it to the current real PIDs, and pass it to the per-core renderer for summation.
            tableRow.cpuCoreProcessIds.reserve(
                static_cast<qsizetype>(displayRow.actionIdentityKeys.size()));
            for (const std::string& memberIdentityKey : displayRow.actionIdentityKeys)
            {
                const auto kMemberIt = cacheByIdentity_.find(memberIdentityKey);
                if (kMemberIt == cacheByIdentity_.end() ||
                    kMemberIt->second.isExitedInLatestRound)
                {
                    continue;
                }
                tableRow.cpuCoreProcessIds.push_back(kMemberIt->second.record.pid);
            }
        }
        tableRow.depth = displayRow.depth;
        tableRow.hasChildren = displayRow.hasChildren;
        tableRow.isNew = displayRow.isNew;
        tableRow.isExited = displayRow.isExited;
        tableRow.isKernelOnly = displayRow.isKernelOnly;
        tableRow.activitySnapshotActive = kActivitySnapshotActive;
        // Per-core ETW snapshots are shared in real-time across all rows by ProcessDock, avoiding shared_ptr increments/decrements at the row level.
        tableRows.push_back(std::move(tableRow));
    }

    // Purpose of sort key snapshot:
    // - Only compare the numeric key and display key for the current user-sorted column;
    // - When the key remains unchanged, retains the existing order of QSortFilterProxyModel and skips a full sort;
    // - Immediately re-sorts according to existing rules upon new entries, exits, or changes in the current sort value.
    struct ProcessSortCellSnapshot
    {
        bool hasNumericValue = false; // hasNumericValue: Whether the current column provides a numeric sort key.
        double numericValue = 0.0;    // numericValue: Original value for ProcessNumericSortRole.
        QString displayText;          // displayText: Stable secondary sort key when values are equal or for text columns.
    };
    const auto kTableRowStableKey = [](const ProcessTableRow& tableRow) -> std::string
    {
        if (tableRow.rowKind == ProcessTableRowKind::kProcess)
        {
            return std::string("process:") + tableRow.identityKey;
        }
        return std::string("synthetic:")
            + std::to_string(static_cast<int>(tableRow.rowKind))
            + ":"
            + tableRow.expansionKey.toUtf8().toStdString();
    };
    const auto kCaptureSortCell = [this, kSafePreviousSortColumn](const ProcessTableRow& tableRow) -> ProcessSortCellSnapshot
    {
        ProcessSortCellSnapshot snapshot{};
        bool numericParseOk = false;
        const QVariant kNumericSortValue = processTableData(
            tableRow,
            kSafePreviousSortColumn,
            kProcessNumericSortRole);
        const double kNumericValue = kNumericSortValue.toDouble(&numericParseOk);
        snapshot.hasNumericValue = numericParseOk;
        snapshot.numericValue = kNumericValue;
        snapshot.displayText = processTableData(
            tableRow,
            kSafePreviousSortColumn,
            Qt::DisplayRole).toString();
        return snapshot;
    };
    const auto kRequiresProcessTableResort = [&]() -> bool
    {
        // Tree and friendly views define structure via source order; still use the original proxy sorting trigger path.
        if (!kEnableSorting)
        {
            return true;
        }

        const std::vector<ProcessTableRow>& previousRows = processTableModel_->rows();
        if (previousRows.size() != tableRows.size())
        {
            return true;
        }

        std::unordered_map<std::string, ProcessSortCellSnapshot> previousSortCells;
        previousSortCells.reserve(previousRows.size());
        for (const ProcessTableRow& previousRow : previousRows)
        {
            const std::string kStableKey = kTableRowStableKey(previousRow);
            if (kStableKey.empty() ||
                !previousSortCells.emplace(kStableKey, kCaptureSortCell(previousRow)).second)
            {
                return true;
            }
        }

        for (const ProcessTableRow& nextRow : tableRows)
        {
            const std::string kStableKey = kTableRowStableKey(nextRow);
            const auto kPreviousSortCellIt = previousSortCells.find(kStableKey);
            if (kStableKey.empty() || kPreviousSortCellIt == previousSortCells.end())
            {
                return true;
            }

            const ProcessSortCellSnapshot kNextSortCell = kCaptureSortCell(nextRow);
            const ProcessSortCellSnapshot& previousSortCell = kPreviousSortCellIt->second;
            if (previousSortCell.hasNumericValue != kNextSortCell.hasNumericValue ||
                previousSortCell.numericValue != kNextSortCell.numericValue ||
                previousSortCell.displayText != kNextSortCell.displayText)
            {
                return true;
            }
        }
        return false;
    };
    const bool kProcessTableResortRequired = kRequiresProcessTableResort();

    // Temporarily freeze the view and selection signals during refresh to merge intermediate states of incremental model changes before repainting.
    QSignalBlocker tableSignalBlocker(processTable_);
    std::unique_ptr<QSignalBlocker> selectionSignalBlocker;
    if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
    {
        selectionSignalBlocker = std::make_unique<QSignalBlocker>(selectionModel);
    }
    processTable_->setUpdatesEnabled(false);

    const auto kModelApplyStartTime = std::chrono::steady_clock::now();
    const ProcessTableModel::UpdateStats kModelUpdateStats =
        processTableModel_->setRows(std::move(tableRows));
    const auto kModelApplyElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - kModelApplyStartTime).count();

    const auto kSortStartTime = std::chrono::steady_clock::now();
    // QTableView::setSortingEnabled(true) triggers sorting immediately; call only when the sorting state changes to prevent redundant sorting during cycles with no data changes.
    const bool kSortingStateChanged = (processTable_->isSortingEnabled() != kEnableSorting);
    if (kSortingStateChanged)
    {
        processTable_->setSortingEnabled(kEnableSorting);
    }
    if (kEnableSorting)
    {
        if (kSortingStateChanged || kProcessTableResortRequired)
        {
            // Restores the user's previous sort selection instead of forcing a PID ascending order.
            processTable_->sortByColumn(kSafePreviousSortColumn, kPreviousSortOrder);
        }
    }
    else
    {
        // Tree/Friendly mode order is determined by build*DisplayOrder; the proxy triggers a single source-order sort on column 0.
        processSortProxy_->sort(toColumnIndex(TableColumn::kName), Qt::AscendingOrder);
        if (headerView != nullptr && isFriendlyViewEnabled())
        {
            headerView->setSortIndicatorShown(true);
            headerView->setSortIndicator(friendlySortColumn_, friendlySortOrder_);
        }
    }
    const auto kSortElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - kSortStartTime).count();

    // Restore the user's previously selected process by identityKey:
    // - Write back Ctrl-multi-selection row-by-row using Select|Rows to prevent loss of batch selection after refresh.
    // Current focus is updated only via NoUpdate; do not allow currentIndex to collapse a multi-selection into a single selection.
    // - If the process no longer exists, clear the tracking state to prevent incorrect highlighting.
    bool restoredAnySelection = false;
    QItemSelectionModel* selectionModel = processTable_->selectionModel();
    bool selectionRestoreRequired = kModelUpdateStats.modelReset;
    if (selectionModel != nullptr && !selectionRestoreRequired)
    {
        // Incremental model updates maintain a persistent index; if the current actual selection still matches the tracked set, do not clear and re-select to avoid flickering during high-frequency refreshes.
        std::unordered_set<std::string> currentSelectedIdentityKeys;
        bool containsSyntheticSelection = false;
        const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(false);
        currentSelectedIdentityKeys.reserve(kSelectedRows.size());
        for (const QModelIndex& rowIndex : kSelectedRows)
        {
            const ProcessTableRow* selectedTableRow = processTableRowForViewIndex(rowIndex);
            if (selectedTableRow == nullptr ||
                selectedTableRow->rowKind != ProcessTableRowKind::kProcess ||
                selectedTableRow->identityKey.empty())
            {
                containsSyntheticSelection = true;
                continue;
            }
            currentSelectedIdentityKeys.insert(selectedTableRow->identityKey);
        }

        selectionRestoreRequired =
            containsSyntheticSelection ||
            currentSelectedIdentityKeys != trackedIdentityKeysBeforeRebuild;
        if (!selectionRestoreRequired && !kTrackedIdentityKeyBeforeRebuild.empty())
        {
            const QModelIndex kCurrentIndex = selectionModel->currentIndex();
            const ProcessTableRow* currentTableRow = processTableRowForViewIndex(kCurrentIndex);
            selectionRestoreRequired =
                currentTableRow == nullptr ||
                currentTableRow->identityKey != kTrackedIdentityKeyBeforeRebuild ||
                kCurrentIndex.column() != kTrackedColumnBeforeRebuild;
        }
    }
    if (selectionModel != nullptr && selectionRestoreRequired)
    {
        selectionModel->clearSelection();
        for (const std::string& identityKey : trackedIdentityKeysBeforeRebuild)
        {
            const QModelIndex kRowIndex = processTableViewIndexForIdentityKey(identityKey, 0);
            if (kRowIndex.isValid())
            {
                selectionModel->select(
                    kRowIndex,
                    QItemSelectionModel::Select | QItemSelectionModel::Rows);
                restoredAnySelection = true;
            }
        }

        QModelIndex currentIndexToRestore = processTableViewIndexForIdentityKey(
            kTrackedIdentityKeyBeforeRebuild,
            kTrackedColumnBeforeRebuild);
        if (!currentIndexToRestore.isValid() && !trackedIdentityKeysBeforeRebuild.empty())
        {
            currentIndexToRestore = processTableViewIndexForIdentityKey(
                *trackedIdentityKeysBeforeRebuild.begin(),
                kTrackedColumnBeforeRebuild);
        }
        if (currentIndexToRestore.isValid())
        {
            selectionModel->setCurrentIndex(currentIndexToRestore, QItemSelectionModel::NoUpdate);
            restoredAnySelection = true;
        }
    }

    if (restoredAnySelection)
    {
        syncTrackedSelectionFromTable();
        trackedSelectedColumn_ = kTrackedColumnBeforeRebuild;
    }
    else if (selectionRestoreRequired &&
        !trackedIdentityKeysBeforeRebuild.empty() &&
        currentProcessSearchText().isEmpty())
    {
        trackedSelectedIdentityKey_.clear();
        trackedSelectedIdentityKeys_.clear();
        trackedSelectedColumn_ = 0;
    }

    // Refresh the header's "Total Usage" based on this round's data.
    updateUsageSummaryInHeader(kDisplayRows);
    applyR0ColumnAvailability(kDisplayRows);

    // Restore scroll position: keep the user's current view position from being interrupted by refresh.
    if (verticalScrollBar != nullptr)
    {
        verticalScrollBar->setValue(std::clamp(
            kVerticalScrollValueBeforeRebuild,
            verticalScrollBar->minimum(),
            verticalScrollBar->maximum()));
    }
    if (horizontalScrollBar != nullptr)
    {
        horizontalScrollBar->setValue(std::clamp(
            kHorizontalScrollValueBeforeRebuild,
            horizontalScrollBar->minimum(),
            horizontalScrollBar->maximum()));
    }

    // Restore refresh and drawing after table reconstruction is complete.
    processTable_->setUpdatesEnabled(true);
    processTable_->viewport()->update();
    const auto kTableRebuildElapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - kTableRebuildStartTime).count();

    // Output a fine-grained log after rebuilding to facilitate analysis of UI refresh overhead and sort state.
    KLogEvent logEvent;
    dbg << logEvent
        << "[ProcessDock] rebuildTable 完成, rows=" << kDisplayRows.size()
        << ", treeMode=" << (isTreeModeEnabled() ? "true" : "false")
        << ", friendlyView=" << (isFriendlyViewEnabled() ? "true" : "false")
        << ", sortingEnabled=" << (kEnableSorting ? "true" : "false")
        << ", sortColumn=" << (kEnableSorting && headerView != nullptr ? headerView->sortIndicatorSection() : -1)
        << ", modelInserted=" << kModelUpdateStats.insertedRowCount
        << ", modelRemoved=" << kModelUpdateStats.removedRowCount
        << ", modelReordered=" << (kModelUpdateStats.orderChanged ? "true" : "false")
        << ", modelReset=" << (kModelUpdateStats.modelReset ? "true" : "false")
        << ", modelApplyUs=" << kModelApplyElapsedUs
        << ", sortUs=" << kSortElapsedUs
        << ", totalUiRebuildUs=" << kTableRebuildElapsedUs
        << eol;
}

void ProcessDock::updateUsageSummaryInHeader(const std::vector<DisplayRow>& displayRows)
{
    // Total sum displayed in the title bar:
    // - QTableView has no headerItem; dynamic headers are provided by ProcessTableSortProxy::headerData.
    // - This function only calculates aggregate values for currently visible rows and updates the proxy header, without touching model row data.
    if (processSortProxy_ == nullptr)
    {
        return;
    }

    double totalCpuPercent = 0.0;
    double totalRamMB = 0.0;
    double totalDiskMBps = 0.0;
    double totalGpuPercent = 0.0;
    double totalNetKBps = 0.0;
    std::uint64_t totalHandleCount = 0;
    for (const DisplayRow& displayRow : displayRows)
    {
        if (displayRow.record == nullptr ||
            displayRow.rowKind != ProcessTableRowKind::kProcess ||
            displayRow.isExited)
        {
            continue;
        }

        // CPU summary excludes the idle percentage of 'System Idle Process' (PID=0) as per user requirements.
        const bool kIsSystemIdleProcess =
            (displayRow.record->pid == 0) ||
            (QString::fromStdString(displayRow.record->processName).compare("System Idle Process", Qt::CaseInsensitive) == 0);
        if (!kIsSystemIdleProcess)
        {
            totalCpuPercent += displayRow.record->cpuPercent;
        }

        totalRamMB += displayRow.record->ramMB;
        totalDiskMBps += displayRow.record->diskMBps;
        totalGpuPercent += displayRow.record->gpuPercent;
        totalNetKBps += displayRow.record->netKBps;
        totalHandleCount += displayRow.record->handleCount;
    }

    QStringList headerTexts = kProcessTableHeaders;
    headerTexts[toColumnIndex(TableColumn::kCpu)] = QString("CPU %1%").arg(totalCpuPercent, 0, 'f', 2);
    headerTexts[toColumnIndex(TableColumn::kRam)] = QString("RAM %1 MB").arg(totalRamMB, 0, 'f', 1);
    headerTexts[toColumnIndex(TableColumn::kDisk)] = QString("DISK %1 MB/s").arg(totalDiskMBps, 0, 'f', 2);
    headerTexts[toColumnIndex(TableColumn::kGpu)] = QString("GPU %1%").arg(totalGpuPercent, 0, 'f', 1);
    headerTexts[toColumnIndex(TableColumn::kNet)] = QString("Net %1 KB/s").arg(totalNetKBps, 0, 'f', 2);
    headerTexts[toColumnIndex(TableColumn::kHandleCount)] = QString("句柄数 %1").arg(static_cast<qulonglong>(totalHandleCount));

    auto* processSortProxy = static_cast<ProcessTableSortProxy*>(processSortProxy_);
    processSortProxy->setHeaderTexts(std::move(headerTexts));
}

void ProcessDock::applyR0ColumnAvailability(const std::vector<DisplayRow>& displayRows)
{
    if (processTable_ == nullptr)
    {
        return;
    }

    bool hasVisibleR0Extension = false;
    for (const DisplayRow& displayRow : displayRows)
    {
        if (displayRow.record == nullptr ||
            displayRow.rowKind != ProcessTableRowKind::kProcess ||
            displayRow.isExited)
        {
            continue;
        }

        if (isProcessR0ExtensionVisible(*displayRow.record))
        {
            hasVisibleR0Extension = true;
            break;
        }
    }

    const bool kShouldAutoHide = !hasVisibleR0Extension;
    const bool kStateChanged = (autoHideUnavailableR0Columns_ != kShouldAutoHide);
    autoHideUnavailableR0Columns_ = kShouldAutoHide;
    if (!kStateChanged)
    {
        return;
    }

    const int kR0OnlyColumns[] = {
        toColumnIndex(TableColumn::kProtection),
        toColumnIndex(TableColumn::kPpl),
        toColumnIndex(TableColumn::kHandleTable),
        toColumnIndex(TableColumn::kSectionObject),
        toColumnIndex(TableColumn::kR0Status)
    };

    if (kShouldAutoHide)
    {
        for (const int kColumnIndex : kR0OnlyColumns)
        {
            processTable_->setColumnHidden(kColumnIndex, true);
        }
        applyAdaptiveColumnWidths();
    }
    else
    {
        // When R0 extension becomes available again, perform a full re-layout based on 'view preset + user column selection':
        // Forcing these columns to display directly overrides the user's decision to hide them in the 'Select Columns' dialog.
        applyViewMode(currentViewMode());
    }

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] R0-only 列自动"
        << (kShouldAutoHide ? "隐藏" : "显示")
        << ", reason="
        << (kShouldAutoHide ? "所有可见行 R0 扩展均为 Unavailable" : "检测到可用 R0 扩展字段")
        << eol;
}

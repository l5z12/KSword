#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

QVariant ProcessDock::processNumericSortValue(
    const ks::process::ProcessRecord& processRecord,
    const TableColumn column)
{
    // Use raw values for the sort key: display text may include units, but sorting must compare based on actual magnitude.
    switch (column)
    {
    case TableColumn::kPid:
        return static_cast<double>(processRecord.pid);
    case TableColumn::kCpu:
        return processRecord.cpuPercent;
    case TableColumn::kCpuCore:
        return processRecord.cpuCorePercent;
    case TableColumn::kInjectionSurface:
        // Unfiltered or access-restricted items are placed last: their 0
        // means "unknown" and must not be grouped with a true count of 0.
        return ksword::evidence::surfaceScreenCountsAreMeaningful(
                   static_cast<ksword::evidence::SurfaceScreenState>(
                       processRecord.injectionSurfaceState))
            ? static_cast<double>(processRecord.injectionDynamicRegions)
            : -1.0;
    case TableColumn::kRam:
        return processRecord.workingSetMB;
    case TableColumn::kDisk:
        return processRecord.diskMBps;
    case TableColumn::kGpu:
        return processRecord.gpuPercent;
    case TableColumn::kNet:
        return processRecord.netKBps;
    case TableColumn::kParentPid:
        return static_cast<double>(processRecord.parentPid);
    case TableColumn::kStartTime:
        return static_cast<double>(processRecord.creationTime100ns);
    case TableColumn::kIsAdmin:
        return processRecord.isAdmin ? 1.0 : 0.0;
    case TableColumn::kPplLevel:
        return processRecord.protectionLevelKnown ? static_cast<double>(processRecord.protectionLevel) : -1.0;
    case TableColumn::kProtection:
    case TableColumn::kPpl:
        return static_cast<double>(processRecord.r0Protection);
    case TableColumn::kHandleCount:
        return static_cast<double>(processRecord.handleCount);
    case TableColumn::kHandleTable:
        return ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U) ? 1.0 : 0.0;
    case TableColumn::kSectionObject:
        return ((processRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U) ? 1.0 : 0.0;
    case TableColumn::kR0Status:
        return static_cast<double>(processRecord.r0Status);

    // ======== Sorting key for Task Manager-aligned column values ======== Display text includes units or thousands
    // separators, so sorting must revert to the original numeric value; otherwise, "9 K" would sort after "10,240 K".
    case TableColumn::kStatus:
        return processRecord.processStateKnown
            ? (processRecord.processSuspended ? 1.0 : 0.0)
            : -1.0;
    case TableColumn::kSessionId:
        return static_cast<double>(processRecord.sessionId);
    case TableColumn::kJobObject:
        return processRecord.jobObjectKnown
            ? (processRecord.inJobObject ? 1.0 : 0.0)
            : -1.0;
    case TableColumn::kCpuTime:
        return static_cast<double>(processRecord.rawCpuTime100ns);
    case TableColumn::kCycleTime:
        return processRecord.cycleTimeKnown ? static_cast<double>(processRecord.cycleTime) : -1.0;
    case TableColumn::kWorkingSet:
        return static_cast<double>(processRecord.rawWorkingSetBytes);
    case TableColumn::kPeakWorkingSet:
        return static_cast<double>(processRecord.peakWorkingSetBytes);
    case TableColumn::kWorkingSetDelta:
        return static_cast<double>(processRecord.workingSetDeltaBytes);
    case TableColumn::kActivePrivateWorkingSet:
        return static_cast<double>(processRecord.activePrivateWorkingSetBytes);
    case TableColumn::kPrivateWorkingSet:
        return static_cast<double>(processRecord.privateWorkingSetBytes);
    case TableColumn::kSharedWorkingSet:
        return static_cast<double>(processRecord.sharedWorkingSetBytes);
    case TableColumn::kCommitSize:
        return static_cast<double>(processRecord.commitSizeBytes);
    case TableColumn::kPagedPool:
        return static_cast<double>(processRecord.pagedPoolBytes);
    case TableColumn::kNonPagedPool:
        return static_cast<double>(processRecord.nonPagedPoolBytes);
    case TableColumn::kPageFaults:
        return static_cast<double>(processRecord.pageFaultCount);
    case TableColumn::kPageFaultDelta:
        return static_cast<double>(processRecord.pageFaultDeltaCount);
    case TableColumn::kBasePriority:
        return static_cast<double>(processRecord.basePriority);
    case TableColumn::kThreadCount:
        return static_cast<double>(processRecord.threadCount);
    case TableColumn::kUserObjects:
        return processRecord.guiResourceKnown ? static_cast<double>(processRecord.userObjectCount) : -1.0;
    case TableColumn::kGdiObjects:
        return processRecord.guiResourceKnown ? static_cast<double>(processRecord.gdiObjectCount) : -1.0;
    case TableColumn::kIoReads:
        return static_cast<double>(processRecord.ioReadOperationCount);
    case TableColumn::kIoWrites:
        return static_cast<double>(processRecord.ioWriteOperationCount);
    case TableColumn::kIoOther:
        return static_cast<double>(processRecord.ioOtherOperationCount);
    case TableColumn::kIoReadBytes:
        return static_cast<double>(processRecord.ioReadTransferBytes);
    case TableColumn::kIoWriteBytes:
        return static_cast<double>(processRecord.ioWriteTransferBytes);
    case TableColumn::kIoOtherBytes:
        return static_cast<double>(processRecord.ioOtherTransferBytes);
    case TableColumn::kUacVirtualization:
        return processFeatureStateSortValue(processRecord.uacVirtualizationState);
    case TableColumn::kDataExecutionPrevention:
        return processFeatureStateSortValue(processRecord.dataExecutionPreventionState);
    case TableColumn::kControlFlowGuard:
        return processFeatureStateSortValue(processRecord.controlFlowGuardState);
    case TableColumn::kHardwareStackProtection:
        return processFeatureStateSortValue(processRecord.hardwareStackProtectionState);
    case TableColumn::kDpiAwareness:
        return (processRecord.dpiAwarenessLevel == ks::process::ProcessDpiAwarenessLevel::kUnknown)
            ? -1.0
            : static_cast<double>(static_cast<std::uint32_t>(processRecord.dpiAwarenessLevel));
    case TableColumn::kPowerThrottling:
        return processRecord.efficiencyModeSupported
            ? (processRecord.efficiencyModeEnabled ? 1.0 : 0.0)
            : -1.0;
    case TableColumn::kGpuDedicatedMemory:
        return processRecord.gpuMemoryKnown
            ? static_cast<double>(processRecord.gpuDedicatedMemoryBytes)
            : -1.0;
    case TableColumn::kGpuSharedMemory:
        return processRecord.gpuMemoryKnown
            ? static_cast<double>(processRecord.gpuSharedMemoryBytes)
            : -1.0;
    default:
        return {};
    }
}

bool ProcessDock::processUsageHighlightValue(
    const ks::process::ProcessRecord& processRecord,
    const TableColumn column,
    double* const valueOut)
{
    if (valueOut == nullptr)
    {
        return false;
    }

    // Apply intensity coloring only to columns representing resource usage, cumulative workload, or object counts.
    // PID, session ID, priority, boolean status, etc. are sortable, but their numeric values do not indicate 'higher usage'.
    switch (column)
    {
    case TableColumn::kCpu:
    case TableColumn::kRam:
    case TableColumn::kDisk:
    case TableColumn::kGpu:
    case TableColumn::kNet:
    case TableColumn::kHandleCount:
    case TableColumn::kCpuTime:
    case TableColumn::kWorkingSet:
    case TableColumn::kWorkingSetDelta:
    case TableColumn::kThreadCount:
        break;
    case TableColumn::kCycleTime:
        if (!processRecord.cycleTimeKnown)
        {
            return false;
        }
        break;
    case TableColumn::kPeakWorkingSet:
    case TableColumn::kCommitSize:
    case TableColumn::kPagedPool:
    case TableColumn::kNonPagedPool:
    case TableColumn::kPageFaults:
    case TableColumn::kPageFaultDelta:
        if (!processRecord.memoryDetailKnown)
        {
            return false;
        }
        break;
    case TableColumn::kActivePrivateWorkingSet:
    case TableColumn::kPrivateWorkingSet:
    case TableColumn::kSharedWorkingSet:
        if (!processRecord.privateWorkingSetKnown)
        {
            return false;
        }
        break;
    case TableColumn::kUserObjects:
    case TableColumn::kGdiObjects:
        if (!processRecord.guiResourceKnown)
        {
            return false;
        }
        break;
    case TableColumn::kIoReads:
    case TableColumn::kIoWrites:
    case TableColumn::kIoOther:
    case TableColumn::kIoReadBytes:
    case TableColumn::kIoWriteBytes:
    case TableColumn::kIoOtherBytes:
        if (!processRecord.ioDetailKnown)
        {
            return false;
        }
        break;
    case TableColumn::kGpuDedicatedMemory:
    case TableColumn::kGpuSharedMemory:
        if (!processRecord.gpuMemoryKnown)
        {
            return false;
        }
        break;
    default:
        return false;
    }

    bool numericValueOk = false;
    const double kNumericValue = processNumericSortValue(processRecord, column)
        .toDouble(&numericValueOk);
    if (!numericValueOk || !std::isfinite(kNumericValue))
    {
        return false;
    }

    // Incremental columns can be negative; coloring expresses the magnitude of change, while the positive/negative direction is preserved in the cell text.
    *valueOut = std::fabs(kNumericValue);
    return true;
}

bool ProcessDock::processUsageHighlightRatio(
    const ks::process::ProcessRecord& processRecord,
    const TableColumn column,
    double* const ratioOut) const
{
    if (ratioOut == nullptr)
    {
        return false;
    }

    double value = 0.0;
    if (!processUsageHighlightValue(processRecord, column, &value))
    {
        return false;
    }

    const std::size_t kColumnIndex = static_cast<std::size_t>(column);
    if (kColumnIndex >= processUsageHighlightMaximums_.size())
    {
        return false;
    }
    const double kMaximumValue = processUsageHighlightMaximums_[kColumnIndex];
    *ratioOut = kMaximumValue > 0.0
        ? std::clamp(value / kMaximumValue, 0.0, 1.0)
        : 0.0;
    return true;
}

QVariant ProcessDock::processTableData(const ProcessTableRow& tableRow, const int column, const int role)
{
    // Parameter and record validation: the model may request stale index data during reset; return an empty record immediately.
    if (column < 0 || column >= static_cast<int>(TableColumn::kCount))
    {
        return {};
    }

    const ks::process::ProcessRecord& processRecord = tableRow.record;
    const TableColumn kTableColumn = static_cast<TableColumn>(column);
    if (role == Qt::UserRole)
    {
        // UserRole:
        // - Preserve the data contract where the old table's 0th column stores the identityKey;
        // - Facilitates stable row identifier retrieval from the model index for subsequent copy, right-click actions, or external debugging.
        // - Returns the identityKey text composed of the row's PID and creation time.
        return QString::fromStdString(tableRow.identityKey);
    }
    if (kTableColumn == TableColumn::kName)
    {
        if (role == kProcessTreeDepthRole)
        {
            return tableRow.depth;
        }
        if (role == kProcessRowKindRole)
        {
            return static_cast<int>(tableRow.rowKind);
        }
        if (role == kProcessExpandableRole)
        {
            return tableRow.rowKind == ProcessTableRowKind::kGroupHeader ||
                tableRow.rowKind == ProcessTableRowKind::kApplicationAggregate ||
                tableRow.hasChildren;
        }
        if (role == kProcessExpandedRole)
        {
            if (tableRow.rowKind == ProcessTableRowKind::kApplicationAggregate)
            {
                return friendlyExpandedStateByKey_.value(tableRow.expansionKey, false);
            }
            if (tableRow.rowKind == ProcessTableRowKind::kGroupHeader)
            {
                return friendlyExpandedStateByKey_.value(tableRow.expansionKey, true);
            }
            return tableRow.hasChildren;
        }
    }
    if (kTableColumn == TableColumn::kCpuCore && role == Qt::SizeHintRole)
    {
        // The preferred width of the CPU column accommodates both the current percentage and all logical processor capacity slots.
        // After returning SizeHintRole, the global column width adapter will not squash the box into an unreadable row of ellipses.
        const QFontMetrics kTableFontMetrics = processTable_ != nullptr
            ? processTable_->fontMetrics()
            : QFontMetrics(QApplication::font());
        return ks::ui::processCpuCapacityCellSizeHint(
            kTableFontMetrics,
            logicalCpuCount_);
    }
    if (kTableColumn == TableColumn::kCpuCore &&
        (tableRow.rowKind == ProcessTableRowKind::kProcess ||
            tableRow.rowKind == ProcessTableRowKind::kApplicationAggregate) &&
        !tableRow.activitySnapshotActive)
    {
        if (role == ks::ui::kProcessCpuUsageSnapshotRole &&
            latestCpuCoreUsageSnapshot_ != nullptr &&
            !tableRow.isExited &&
            !tableRow.cpuCoreProcessIds.isEmpty())
        {
            // QVariant only copies the shared_ptr control block; the application parent row and the actual process row share the same ETW snapshot.
            return QVariant::fromValue(latestCpuCoreUsageSnapshot_);
        }
        if (role == ks::ui::kProcessCpuProcessIdsRole)
        {
            return QVariant::fromValue(tableRow.cpuCoreProcessIds);
        }
        if (role == Qt::ToolTipRole)
        {
            return processContextText(
                "process.table.cell.cpu_core_summary_tooltip",
                QStringLiteral(
                    "CPU：%1%\n单核等效：%2%\n"
                    "每个扇形对应一个真实逻辑 CPU；悬停扇形查看处理器组、编号和本轮占用。"))
                .arg(processRecord.cpuPercent, 0, 'f', 2)
                .arg(processRecord.cpuCorePercent, 0, 'f', 2);
        }
    }
    if (tableRow.rowKind == ProcessTableRowKind::kGroupHeader)
    {
        // GroupHeader is a synthetic non-process row:
        // - inputs are the stored title and expansion key;
        // - processing keeps only the Name column populated;
        // - return values are display/tooltip/paint roles, never process action data.
        if (role == Qt::DisplayRole)
        {
            if (kTableColumn != TableColumn::kName)
            {
                return QString();
            }
            return tableRow.syntheticTitle;
        }
        if (role == Qt::ToolTipRole && kTableColumn == TableColumn::kName)
        {
            return QStringLiteral("分类标题：双击可折叠/展开；不会作为进程操作目标。");
        }
        if (role == Qt::FontRole)
        {
            QFont font;
            font.setBold(true);
            return font;
        }
        if (role == Qt::ForegroundRole)
        {
            return QBrush(ksword_theme::primaryBlueColor);
        }
        if (role == Qt::BackgroundRole)
        {
            const QColor kBackgroundColor = ksword_theme::withAlpha(
                ksword_theme::primaryBlueSubtleColor(),
                ksword_theme::isDarkModeEnabled() ? 180 : 255);
            return QBrush(kBackgroundColor);
        }
        if (role == kProcessNumericSortRole)
        {
            return -1.0;
        }
        return {};
    }
    if (kTableColumn == TableColumn::kProcessType)
    {
        // The value for the 'Type' column comes from the row's friendly grouping result, not the ProcessRecord field;
        // rebuildTable: Populates friendlyGroupType for real process rows in any view mode.
        if (role == Qt::DisplayRole)
        {
            return friendlyGroupTypeName(tableRow.friendlyGroupType);
        }
        if (role == kProcessNumericSortRole)
        {
            return static_cast<double>(static_cast<int>(tableRow.friendlyGroupType));
        }
    }
    if (tableRow.rowKind == ProcessTableRowKind::kApplicationAggregate)
    {
        // ApplicationAggregate is a synthetic application parent row:
        // - name comes from syntheticTitle and metrics come from the aggregate record;
        // - the row is selectable and expands actions to every real process in this application;
        // - double-click still controls expand/collapse and children remain normal process rows.
        if (role == Qt::DisplayRole)
        {
            if (kTableColumn == TableColumn::kName)
            {
                return tableRow.syntheticTitle;
            }
            return formatColumnText(processRecord, kTableColumn, tableRow.depth);
        }
        if (role == Qt::DecorationRole && kTableColumn == TableColumn::kName)
        {
            return resolveProcessIcon(processRecord);
        }
        if (role == Qt::ToolTipRole && kTableColumn == TableColumn::kName)
        {
            return processContextText(
                "process.friendly.aggregate.tooltip",
                QStringLiteral("应用聚合行：汇总该应用进程树；选中或右键后，进程动作会应用到全部成员；双击可折叠/展开。"));
        }
        if (role == Qt::FontRole)
        {
            QFont font;
            font.setBold(true);
            return font;
        }
    }
    if (role == Qt::DisplayRole)
    {
        // DisplayRole is responsible only for text; the Name column's hierarchy lines and icons are drawn uniformly by the delegate to prevent icons from appearing before the indentation.
        return formatColumnText(
            processRecord,
            kTableColumn,
            kTableColumn == TableColumn::kName ? 0 : tableRow.depth);
    }
    if (role == Qt::DecorationRole && kTableColumn == TableColumn::kName)
    {
        // The Name column is fixed to display the target EXE icon (overhead is controllable after cache hit).
        return resolveProcessIcon(processRecord);
    }
    if (role == Qt::ToolTipRole && kTableColumn == TableColumn::kName)
    {
        if (tableRow.activitySnapshotActive)
        {
            return QStringLiteral("历史快照行：该行来自时间轴样本，不代表当前实时进程状态。");
        }
        // Weak-evidence 'kernel-only' row: explains the source of false positives to prevent users from mistaking short-lived process remnants for hidden processes.
        if (tableRow.isKernelOnly &&
            (processRecord.r0Flags & KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED) != 0U)
        {
            return QStringLiteral("%1\n可能为误报：该 EPROCESS 已退出（ExitStatus 非 STATUS_PENDING），被摘出活动链表后仍留在 PspCidTable 中，多为短命进程残骸。")
                .arg(QString::fromStdString(processRecord.processName));
        }
        if (tableRow.isKernelOnly &&
            (processRecord.r0Flags & KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED) != 0U)
        {
            return QStringLiteral("%1\n可能为误报：CID Table 槽位解出进程对象，但 R0 取引用失败，无法确认该 PID 对应存活进程。")
                .arg(QString::fromStdString(processRecord.processName));
        }
        if (processRecord.efficiencyModeEnabled)
        {
            return QStringLiteral("%1\n效率模式已启用")
                .arg(QString::fromStdString(processRecord.processName));
        }
        return QString::fromStdString(processRecord.processName);
    }
    if (role == kProcessEfficiencyModeKnownRole && kTableColumn == TableColumn::kName)
    {
        return processRecord.efficiencyModeSupported;
    }
    if (role == kProcessEfficiencyModeRole && kTableColumn == TableColumn::kName)
    {
        return processRecord.efficiencyModeEnabled;
    }
    if (role == kProcessNumericSortRole)
    {
        return processNumericSortValue(processRecord, kTableColumn);
    }
    if (role != Qt::BackgroundRole && role != Qt::ForegroundRole)
    {
        return {};
    }

    const QColor kAdminYesColor = ksword_theme::successColor();
    const QColor kAdminNoColor = ksword_theme::errorColor();

    // Exited processes are highlighted in gray; CID table weak references and terminating rows are also highlighted in gray.
    // Only kernel-visible processes are highlighted in red; newly added normal processes are highlighted in green.
    if (tableRow.isExited)
    {
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(ksword_theme::exitedRowBackgroundColor()))
            : QVariant(QBrush(ksword_theme::exitedRowForegroundColor()));
    }
    if ((processRecord.r0Flags &
        (KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED |
            KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED)) != 0U)
    {
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(ksword_theme::exitedRowBackgroundColor()))
            : QVariant(QBrush(ksword_theme::exitedRowForegroundColor()));
    }
    if (tableRow.isKernelOnly)
    {
        const QColor kKernelOnlyForeground = ksword_theme::errorColor();
        const QColor kKernelOnlyBackground = ksword_theme::withAlpha(
            ksword_theme::errorBackgroundColor(),
            ksword_theme::isDarkModeEnabled() ? 140 : 255);
        return role == Qt::BackgroundRole
            ? QVariant(QBrush(kKernelOnlyBackground))
            : QVariant(QBrush(kKernelOnlyForeground));
    }
    if (tableRow.isNew && role == Qt::BackgroundRole)
    {
        return QBrush(ksword_theme::newRowBackgroundColor());
    }

    double usageHighlightRatio = 0.0;
    const bool kHasUsageHighlight = processUsageHighlightRatio(
        processRecord,
        kTableColumn,
        &usageHighlightRatio);

    if (role == Qt::ForegroundRole)
    {
        // Admin column: display status intuitively using 'green/red squares' as required.
        if (kTableColumn == TableColumn::kIsAdmin)
        {
            return QBrush(processRecord.isAdmin ? kAdminYesColor : kAdminNoColor);
        }
        // Digital signature column: highlight in red when untrusted to facilitate rapid identification of risky processes.
        if (kTableColumn == TableColumn::kSignature)
        {
            if (!processRecord.signatureTrusted && processRecord.signatureState != "Pending")
            {
                return QBrush(kAdminNoColor);
            }
            if (processRecord.signatureTrusted)
            {
                return QBrush(kAdminYesColor);
            }
        }

        if (kHasUsageHighlight && usageHighlightRatio >= 0.70)
        {
            return QBrush(ksword_theme::onAccentColor());
        }
        return {};
    }

    if (kHasUsageHighlight)
    {
        return QBrush(usageRatioToHighlightColor(usageHighlightRatio));
    }
    return {};
}

const ProcessDock::ProcessTableRow* ProcessDock::processTableRowForViewIndex(const QModelIndex& viewIndex) const
{
    // Input: QTableView/proxy model index; Processing: maps back to FlatTableModel source row; Returns: row pointer or nullptr.
    if (!viewIndex.isValid() || processSortProxy_ == nullptr || processTableModel_ == nullptr)
    {
        return nullptr;
    }

    const QModelIndex kSourceIndex = processSortProxy_->mapToSource(viewIndex);
    if (!kSourceIndex.isValid())
    {
        return nullptr;
    }
    return processTableModel_->rowAt(kSourceIndex.row());
}

QModelIndex ProcessDock::processTableViewIndexForIdentityKey(const std::string& identityKey, const int column) const
{
    // Input: stable identityKey and target column; Processing: scan model rows and map to current proxy view; Return: valid view index or null index.
    if (identityKey.empty() || processSortProxy_ == nullptr || processTableModel_ == nullptr)
    {
        return QModelIndex();
    }

    const int kSafeColumn = std::clamp(column, 0, static_cast<int>(TableColumn::kCount) - 1);
    const std::vector<ProcessTableRow>& rows = processTableModel_->rows();
    for (int rowIndex = 0; rowIndex < static_cast<int>(rows.size()); ++rowIndex)
    {
        if (rows[static_cast<std::size_t>(rowIndex)].identityKey != identityKey)
        {
            continue;
        }

        const QModelIndex kSourceIndex = processTableModel_->index(rowIndex, kSafeColumn);
        return processSortProxy_->mapFromSource(kSourceIndex);
    }
    return QModelIndex();
}

std::vector<QModelIndex> ProcessDock::selectedProcessTableRowIndexes(const bool includeCurrentFallback) const
{
    // Input: whether to allow currentIndex fallback; Processing: deduplicate selected items by row; Output: set of view indices for column 0 of each row.
    std::vector<QModelIndex> rowIndexes;
    if (processTable_ == nullptr)
    {
        return rowIndexes;
    }

    std::set<int> visitedRows;
    if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
    {
        const QModelIndexList kSelectedRows = selectionModel->selectedRows(0);
        rowIndexes.reserve(static_cast<std::size_t>(kSelectedRows.size()));
        for (const QModelIndex& selectedIndex : kSelectedRows)
        {
            if (!selectedIndex.isValid() || !visitedRows.insert(selectedIndex.row()).second)
            {
                continue;
            }
            rowIndexes.push_back(selectedIndex);
        }

        const QModelIndex kCurrentIndex = selectionModel->currentIndex();
        if (includeCurrentFallback && rowIndexes.empty() && kCurrentIndex.isValid())
        {
            const QModelIndex kRowIndex = kCurrentIndex.sibling(kCurrentIndex.row(), 0);
            if (kRowIndex.isValid() && visitedRows.insert(kRowIndex.row()).second)
            {
                rowIndexes.push_back(kRowIndex);
            }
        }
    }
    return rowIndexes;
}

ProcessDock::ProcessActionTarget ProcessDock::processActionTargetFromTableRow(const ProcessTableRow& tableRow) const
{
    // Input: Model row; Processing: Prefer fetching the complete record from the real-time cache; if the cache is missing, fall back to the model row's record; Return: A copy of the action target.
    ProcessActionTarget actionTarget{};
    if (tableRow.rowKind != ProcessTableRowKind::kProcess)
    {
        return actionTarget;
    }
    actionTarget.identityKey = tableRow.identityKey;
    actionTarget.isKernelOnly = tableRow.isKernelOnly;
    if (actionTarget.identityKey.empty())
    {
        return actionTarget;
    }

    const auto kCacheIt = cacheByIdentity_.find(actionTarget.identityKey);
    if (kCacheIt != cacheByIdentity_.end())
    {
        actionTarget.record = kCacheIt->second.record;
        actionTarget.isKernelOnly = kCacheIt->second.isKernelOnlyInLatestRound;
        return actionTarget;
    }
    actionTarget.record = tableRow.record;
    return actionTarget;
}

void ProcessDock::appendProcessActionTargetsFromTableRow(
    const ProcessTableRow& tableRow,
    std::vector<ProcessActionTarget>& actionTargets,
    std::unordered_set<std::string>& visitedIdentitySet) const
{
    // Append a target to a real process row; expand all members for an aggregated row, maintaining identical action semantics as Ctrl-multi-selection.
    const auto kAppendIdentityTarget = [this, &tableRow, &actionTargets, &visitedIdentitySet](const std::string& identityKey)
    {
        if (identityKey.empty() || !visitedIdentitySet.insert(identityKey).second)
        {
            return;
        }

        ProcessActionTarget actionTarget{};
        actionTarget.identityKey = identityKey;
        const auto kCacheIt = cacheByIdentity_.find(identityKey);
        if (kCacheIt != cacheByIdentity_.end())
        {
            actionTarget.record = kCacheIt->second.record;
            actionTarget.isKernelOnly = kCacheIt->second.isKernelOnlyInLatestRound;
        }
        else if (tableRow.rowKind == ProcessTableRowKind::kProcess && identityKey == tableRow.identityKey)
        {
            actionTarget.record = tableRow.record;
            actionTarget.isKernelOnly = tableRow.isKernelOnly;
        }
        else
        {
            visitedIdentitySet.erase(identityKey);
            return;
        }
        actionTargets.push_back(std::move(actionTarget));
    };

    if (tableRow.rowKind == ProcessTableRowKind::kProcess)
    {
        kAppendIdentityTarget(tableRow.identityKey);
        return;
    }
    if (tableRow.rowKind == ProcessTableRowKind::kApplicationAggregate)
    {
        for (const std::string& identityKey : tableRow.actionIdentityKeys)
        {
            kAppendIdentityTarget(identityKey);
        }
    }
}

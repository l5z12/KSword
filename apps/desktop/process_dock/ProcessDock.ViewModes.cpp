#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

std::vector<int> ProcessDock::defaultVisibleColumnsForViewMode(const ViewMode viewMode)
{
    // Input: Built-in view presets.
    // Processing: Provide the set of columns to display by default for this preset; each preset forcibly includes the process name and PID.
    // Returns: a set of logical column indices, serving as the single source of truth shared by applyViewMode and 'restore defaults'.
    std::vector<int> visibleColumns{
        toColumnIndex(TableColumn::kName),
        toColumnIndex(TableColumn::kPid)
    };

    const auto kAppendColumns = [&visibleColumns](const std::initializer_list<TableColumn> columns) -> void
        {
            for (const TableColumn kColumn : columns)
            {
                visibleColumns.push_back(toColumnIndex(kColumn));
            }
        };

    switch (viewMode)
    {
    case ViewMode::kDetail:
        // Details: Static and management info, without performance counter columns.
        kAppendColumns({
            TableColumn::kStatus,
            TableColumn::kSignature,
            TableColumn::kPath,
            TableColumn::kParentPid,
            TableColumn::kCommandLine,
            TableColumn::kUser,
            TableColumn::kStartTime,
            TableColumn::kIsAdmin,
            TableColumn::kPplLevel,
            TableColumn::kDescription,
            TableColumn::kPlatform,
            TableColumn::kProtection,
            TableColumn::kPpl,
            TableColumn::kHandleTable,
            TableColumn::kSectionObject,
            TableColumn::kR0Status });
        break;

    case ViewMode::kMemory:
        kAppendColumns({
            TableColumn::kWorkingSet,
            TableColumn::kPeakWorkingSet,
            TableColumn::kWorkingSetDelta,
            TableColumn::kActivePrivateWorkingSet,
            TableColumn::kPrivateWorkingSet,
            TableColumn::kSharedWorkingSet,
            TableColumn::kCommitSize,
            TableColumn::kPagedPool,
            TableColumn::kNonPagedPool,
            TableColumn::kPageFaults,
            TableColumn::kPageFaultDelta });
        break;

    case ViewMode::kDiskIo:
        kAppendColumns({
            TableColumn::kDisk,
            TableColumn::kIoReads,
            TableColumn::kIoWrites,
            TableColumn::kIoOther,
            TableColumn::kIoReadBytes,
            TableColumn::kIoWriteBytes,
            TableColumn::kIoOtherBytes });
        break;

    case ViewMode::kGpu:
        kAppendColumns({
            TableColumn::kGpu,
            TableColumn::kGpuEngine,
            TableColumn::kGpuDedicatedMemory,
            TableColumn::kGpuSharedMemory,
            TableColumn::kCpuTime,
            TableColumn::kCycleTime });
        break;

    case ViewMode::kSecurity:
        kAppendColumns({
            TableColumn::kSignature,
            TableColumn::kUser,
            TableColumn::kIsAdmin,
            TableColumn::kPplLevel,
            TableColumn::kUacVirtualization,
            TableColumn::kDataExecutionPrevention,
            TableColumn::kControlFlowGuard,
            TableColumn::kHardwareStackProtection,
            TableColumn::kEnterpriseContext,
            TableColumn::kJobObject,
            TableColumn::kPackageName });
        break;

    case ViewMode::kKernel:
        kAppendColumns({
            TableColumn::kProtection,
            TableColumn::kPpl,
            TableColumn::kHandleTable,
            TableColumn::kSectionObject,
            TableColumn::kR0Status,
            TableColumn::kSessionId,
            TableColumn::kBasePriority,
            TableColumn::kThreadCount,
            TableColumn::kHandleCount });
        break;

    case ViewMode::kMonitor:
    default:
        kAppendColumns({
            TableColumn::kCpu,
            TableColumn::kRam,
            TableColumn::kDisk,
            TableColumn::kGpu,
            TableColumn::kNet,
            TableColumn::kHandleCount,
            TableColumn::kProtection,
            TableColumn::kPpl,
            TableColumn::kHandleTable,
            TableColumn::kSectionObject,
            TableColumn::kR0Status,
            TableColumn::kCpuCore });
        break;
    }

    return visibleColumns;
}

QString ProcessDock::viewModeDisplayName(const ViewMode viewMode)
{
    switch (viewMode)
    {
    case ViewMode::kDetail:
        return processContextText("process.view.detail", QStringLiteral("详细信息视图"));
    case ViewMode::kMemory:
        return processContextText("process.view.memory", QStringLiteral("内存视图"));
    case ViewMode::kDiskIo:
        return processContextText("process.view.disk_io", QStringLiteral("磁盘 I/O 视图"));
    case ViewMode::kGpu:
        return processContextText("process.view.gpu", QStringLiteral("GPU 视图"));
    case ViewMode::kSecurity:
        return processContextText("process.view.security", QStringLiteral("安全策略视图"));
    case ViewMode::kKernel:
        return processContextText("process.view.kernel", QStringLiteral("内核证据视图"));
    case ViewMode::kMonitor:
    default:
        return processContextText("process.view.monitor", QStringLiteral("监视视图"));
    }
}

void ProcessDock::applyViewMode(const ViewMode viewMode)
{
    if (processTable_ == nullptr)
    {
        return;
    }

    const bool kHideR0OnlyColumns = autoHideUnavailableR0Columns_;

    // Hide all columns first, then enable target columns based on presets to ensure predictable state.
    for (int column = 0; column < static_cast<int>(TableColumn::kCount); ++column)
    {
        processTable_->setColumnHidden(column, true);
    }

    for (const int kColumnIndex : defaultVisibleColumnsForViewMode(viewMode))
    {
        if (kColumnIndex < 0 || kColumnIndex >= static_cast<int>(TableColumn::kCount))
        {
            continue;
        }

        // Do not display kernel-only columns when R0 extended round-trip is unavailable: the entire column would be Unavailable, providing no information.
        if (kHideR0OnlyColumns &&
            processColumnGroupOf(static_cast<TableColumn>(kColumnIndex)) == ProcessColumnGroup::kKernel)
        {
            continue;
        }
        processTable_->setColumnHidden(kColumnIndex, false);
    }

    // Columns added/removed by the user in 'Select Columns' must override view
    // presets; otherwise, switching views will overwrite user-configured columns.
    applyUserColumnVisibilityOverrides();
    applyAdaptiveColumnWidths();
}

void ProcessDock::applyCustomView(const int customIndex)
{
    if (processTable_ == nullptr ||
        customIndex < 0 ||
        customIndex >= static_cast<int>(customViews_.size()))
    {
        return;
    }

    // Custom views define the complete column set directly, so per-column overrides are no longer applied.
    // Subsequent adjustments by the user in 'Select Columns' will overwrite the override table and can be saved as a new view.
    userColumnVisibilityOverride_.clear();

    const ProcessCustomView& customView = customViews_[static_cast<std::size_t>(customIndex)];
    std::unordered_set<int> visibleColumnSet(
        customView.visibleColumns.begin(),
        customView.visibleColumns.end());
    // Process name and PID are row identifiers; they must be retained in any view.
    visibleColumnSet.insert(toColumnIndex(TableColumn::kName));
    visibleColumnSet.insert(toColumnIndex(TableColumn::kPid));

    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
    {
        bool shouldShow = (visibleColumnSet.find(columnIndex) != visibleColumnSet.end());
        if (shouldShow &&
            autoHideUnavailableR0Columns_ &&
            processColumnGroupOf(static_cast<TableColumn>(columnIndex)) == ProcessColumnGroup::kKernel)
        {
            shouldShow = false;
        }
        processTable_->setColumnHidden(columnIndex, !shouldShow);
    }

    saveProcessColumnLayoutToSettings();
    applyAdaptiveColumnWidths();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 已应用自定义视图, name=" << customView.name.toStdString()
        << ", columnCount=" << visibleColumnSet.size()
        << eol;
}

void ProcessDock::applyAdaptiveColumnWidths()
{
    // Function purpose:
    // - Only switch the process table columns to interactive mode and request the global column width adapter to compress default widths based on the viewport;
    // - Stretch is no longer forced, and the scroll bar policy is not modified; after the user drags a column wider, the horizontal scroll bar appears naturally.
    // - If the user has manually adjusted column widths, the global auto-resizer skips this request to preserve user-defined widths.
    if (processTable_ == nullptr)
    {
        return;
    }

    QHeaderView* headerView = processTable_->horizontalHeader();
    if (headerView == nullptr)
    {
        return;
    }

    headerView->setStretchLastSection(false);
    for (int column = 0; column < static_cast<int>(TableColumn::kCount); ++column)
    {
        headerView->setSectionResizeMode(column, QHeaderView::Interactive);
    }

    ks::ui::requestTableColumnAutoFit(processTable_);
}

bool ProcessDock::isTreeModeEnabled() const
{
    // Unchecking the friendly view typically indicates tree view; after clicking the header, the internal view can temporarily switch to a standard flat enumeration.
    return friendlyViewCheck_ != nullptr &&
        !friendlyViewCheck_->isChecked() &&
        !flatListForcedByHeaderSort_;
}

bool ProcessDock::isFriendlyViewEnabled() const
{
    // Inputs: current checkbox pointer/state.
    // Processing: guard nullptr during construction and return the user-facing switch state.
    // Return: true when friendly grouping should override the legacy tree/list order.
    return friendlyViewCheck_ != nullptr && friendlyViewCheck_->isChecked();
}

ProcessDock::ViewMode ProcessDock::currentViewMode() const
{
    // Data convention for dropdown items: >=0 indicates a built-in preset ViewMode value; <0 indicates a custom view.
    if (viewModeCombo_ == nullptr)
    {
        return ViewMode::kMonitor;
    }

    bool parseOk = false;
    const int kDataValue = viewModeCombo_->currentData().toInt(&parseOk);
    if (!parseOk || kDataValue < 0 || kDataValue >= static_cast<int>(ViewMode::kCount))
    {
        // Custom views have no corresponding built-in presets: treat as Monitor view. It is used only for 'Restore
        // Default Columns' and refreshing budget judgments, without affecting the current column set of the custom view.
        return ViewMode::kMonitor;
    }
    return static_cast<ViewMode>(kDataValue);
}

int ProcessDock::currentCustomViewIndex() const
{
    if (viewModeCombo_ == nullptr)
    {
        return -1;
    }

    bool parseOk = false;
    const int kDataValue = viewModeCombo_->currentData().toInt(&parseOk);
    if (!parseOk || kDataValue >= 0)
    {
        return -1;
    }

    const int kCustomIndex = -kDataValue - 1;
    return (kCustomIndex < static_cast<int>(customViews_.size())) ? kCustomIndex : -1;
}

bool ProcessDock::isStaticDetailIntensiveViewActive() const
{
    // Input: The current column visibility state of the process table.
    // Processing: Check if static fields requiring per-process handle opening are displayed.
    // Returns: true indicates that background refresh should use a higher static detail budget and perform signature verification.
    // This is more accurate than hard-coding the budget in the 'Details View': when users manually add the
    // Command Line or Description columns in the Monitor View, these fields also need to be fully populated.
    return isProcessColumnVisible(TableColumn::kSignature) ||
        isProcessColumnVisible(TableColumn::kPath) ||
        isProcessColumnVisible(TableColumn::kCommandLine) ||
        isProcessColumnVisible(TableColumn::kUser) ||
        isProcessColumnVisible(TableColumn::kDescription) ||
        isProcessColumnVisible(TableColumn::kPlatform);
}

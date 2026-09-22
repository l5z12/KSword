// ============================================================
// ProcessDock.ColumnChooser.cpp
// Purpose:
// - Implements the ability to add/remove columns in the process list (column selection dialog + per-column show/hide entry);
// - Maintain persistent user column selection, preserving it across sessions and view switches;
// - Calculates the background collection requirement bitmap based on currently visible columns to avoid query costs for hidden columns.
// Notes:
// - Column values and formatting remain in ProcessDock.cpp; this file is responsible only for 'which columns to display'.
// ============================================================

#include "ProcessDock.h"

#include "../Theme.h"
#include "../internationalization/LanguageManager.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QSignalBlocker>
#include <QStringList>
#include <QTableView>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <cstddef>
#include <vector>

namespace
{
    // ProcessColumnLayoutSettingsGroup：
    // - Group name in QSettings for saving process table column layout;
    // - Only store items that differ from the view defaults; the default column set will not be locked by old configurations after adjustment.
    constexpr const char* kProcessColumnLayoutSettingsGroup = "ProcessDock/ColumnLayout";

    // ProcessCustomViewSettingsGroup：
    // - Group name for saving user-defined views in QSettings;
    // - One entry per view: key is the view name, value is a comma-separated list of column logical indices.
    constexpr const char* kProcessCustomViewSettingsGroup = "ProcessDock/CustomViews";

    // View dropdown icons: Monitor presets use the list icon, other built-in presets use the process icon, and custom views have no icon for distinction.
    constexpr const char* kProcessViewMonitorIconPath = ":/Icon/process_list.svg";
    constexpr const char* kProcessViewPresetIconPath = ":/Icon/process_main.svg";

    // processColumnChooserText purpose: Retrieves the UI text for the 'Choose Columns' dialog.
    QString processColumnChooserText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }
}

ProcessDock::ProcessColumnGroup ProcessDock::processColumnGroupOf(const TableColumn column)
{
    // Input: column enumeration value.
    // Note: Group by semantics into the 'Choose Columns' dialog.
    // Returns: Grouping enumeration; used only for dialog display and retrieval, not for any data read/write.
    switch (column)
    {
    case TableColumn::kCpu:
    case TableColumn::kCpuCore:
    case TableColumn::kDisk:
    case TableColumn::kGpu:
    case TableColumn::kNet:
    case TableColumn::kCpuTime:
    case TableColumn::kCycleTime:
    case TableColumn::kBasePriority:
    case TableColumn::kThreadCount:
    case TableColumn::kPowerThrottling:
    case TableColumn::kGpuEngine:
    case TableColumn::kGpuDedicatedMemory:
    case TableColumn::kGpuSharedMemory:
        return ProcessColumnGroup::kPerformance;

    case TableColumn::kRam:
    case TableColumn::kWorkingSet:
    case TableColumn::kPeakWorkingSet:
    case TableColumn::kWorkingSetDelta:
    case TableColumn::kActivePrivateWorkingSet:
    case TableColumn::kPrivateWorkingSet:
    case TableColumn::kSharedWorkingSet:
    case TableColumn::kCommitSize:
    case TableColumn::kPagedPool:
    case TableColumn::kNonPagedPool:
    case TableColumn::kPageFaults:
    case TableColumn::kPageFaultDelta:
        return ProcessColumnGroup::kMemory;

    case TableColumn::kIoReads:
    case TableColumn::kIoWrites:
    case TableColumn::kIoOther:
    case TableColumn::kIoReadBytes:
    case TableColumn::kIoWriteBytes:
    case TableColumn::kIoOtherBytes:
        return ProcessColumnGroup::kIo;

    case TableColumn::kSignature:
    case TableColumn::kIsAdmin:
    case TableColumn::kPplLevel:
    case TableColumn::kUacVirtualization:
    case TableColumn::kDataExecutionPrevention:
    case TableColumn::kControlFlowGuard:
    case TableColumn::kHardwareStackProtection:
    case TableColumn::kEnterpriseContext:
    case TableColumn::kJobObject:
    case TableColumn::kInjectionSurface:
        return ProcessColumnGroup::kSecurity;

    case TableColumn::kProtection:
    case TableColumn::kPpl:
    case TableColumn::kHandleTable:
    case TableColumn::kSectionObject:
    case TableColumn::kR0Status:
        return ProcessColumnGroup::kKernel;

    default:
        return ProcessColumnGroup::kGeneral;
    }
}

QString ProcessDock::processColumnGroupTitle(const ProcessColumnGroup group)
{
    // Input: column group enumeration.
    // Processing: Return the group header in the 'Select Columns' dialog.
    // Returns: Localized title text.
    switch (group)
    {
    case ProcessColumnGroup::kPerformance:
        return processColumnChooserText("process.columns.group.performance", QStringLiteral("性能"));
    case ProcessColumnGroup::kMemory:
        return processColumnChooserText("process.columns.group.memory", QStringLiteral("内存"));
    case ProcessColumnGroup::kIo:
        return processColumnChooserText("process.columns.group.io", QStringLiteral("磁盘 I/O"));
    case ProcessColumnGroup::kSecurity:
        return processColumnChooserText("process.columns.group.security", QStringLiteral("安全与策略"));
    case ProcessColumnGroup::kKernel:
        return processColumnChooserText("process.columns.group.kernel", QStringLiteral("内核扩展"));
    case ProcessColumnGroup::kGeneral:
    default:
        return processColumnChooserText("process.columns.group.general", QStringLiteral("常规"));
    }
}

bool ProcessDock::isProcessColumnVisible(const TableColumn column) const
{
    if (processTable_ == nullptr)
    {
        return false;
    }

    const int kColumnIndex = toColumnIndex(column);
    if (kColumnIndex < 0 || kColumnIndex >= static_cast<int>(TableColumn::kCount))
    {
        return false;
    }
    return !processTable_->isColumnHidden(kColumnIndex);
}

void ProcessDock::applyUserColumnVisibilityOverrides()
{
    // Input: Per-column selections recorded in m_userColumnVisibilityOverride.
    // Note: After laying out base visibility presets in the view, re-apply user selections.
    // Returns: Nothing.
    if (processTable_ == nullptr || userColumnVisibilityOverride_.isEmpty())
    {
        return;
    }

    for (auto overrideIt = userColumnVisibilityOverride_.constBegin();
        overrideIt != userColumnVisibilityOverride_.constEnd();
        ++overrideIt)
    {
        const int kColumnIndex = overrideIt.key();
        if (kColumnIndex < 0 || kColumnIndex >= static_cast<int>(TableColumn::kCount))
        {
            continue;
        }

        // R0-only columns are uniformly hidden by applyR0ColumnAvailability when the entire round of extensions is unavailable;
        // Do not override this check to avoid displaying a full column of 'Unavailable' placeholder text.
        if (overrideIt.value() && autoHideUnavailableR0Columns_)
        {
            const TableColumn kColumn = static_cast<TableColumn>(kColumnIndex);
            if (processColumnGroupOf(kColumn) == ProcessColumnGroup::kKernel)
            {
                continue;
            }
        }

        processTable_->setColumnHidden(kColumnIndex, !overrideIt.value());
    }
}

void ProcessDock::setProcessColumnVisible(
    const int columnIndex,
    const bool visible,
    const bool persistImmediately)
{
    if (processTable_ == nullptr ||
        columnIndex < 0 ||
        columnIndex >= static_cast<int>(TableColumn::kCount))
    {
        return;
    }

    // R0-only columns cannot be manually displayed when the extended round is unavailable: the entire column would be Unavailable, providing no information.
    const TableColumn kColumn = static_cast<TableColumn>(columnIndex);
    if (visible &&
        autoHideUnavailableR0Columns_ &&
        processColumnGroupOf(kColumn) == ProcessColumnGroup::kKernel)
    {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 忽略 R0-only 列手动显示请求：当前所有可见行 R0 扩展均为 Unavailable, column="
            << columnIndex
            << eol;
        return;
    }

    userColumnVisibilityOverride_.insert(columnIndex, visible);
    processTable_->setColumnHidden(columnIndex, !visible);

    if (persistImmediately)
    {
        saveProcessColumnLayoutToSettings();
        applyAdaptiveColumnWidths();

        // Newly displayed columns may require additional collection (GDI objects, jobs, mitigation policies, video memory, etc.):
        // Force an immediate refresh of the next round so users do not have to wait for the next cycle to see real data.
        const std::uint32_t kNextDemandFlags = currentProcessDetailDemandFlags();
        const bool kDetailDemandChanged =
            kNextDemandFlags != lastProcessDetailDemandFlags_;
        if (kDetailDemandChanged)
        {
            lastProcessDetailDemandFlags_ = kNextDemandFlags;
        }
        if (kDetailDemandChanged || kColumn == TableColumn::kCpuCore)
        {
            // The visibility of the CPU Core column determines the single-system ETW session lifecycle, requiring an immediate refresh instead of waiting for the periodic timer.
            requestAsyncRefresh(true);
        }
    }
}

void ProcessDock::resetProcessColumnsToViewDefault()
{
    userColumnVisibilityOverride_.clear();
    saveProcessColumnLayoutToSettings();

    // When in a custom view, 'Default' refers to the column set saved for that custom view.
    // Otherwise, revert to the built-in default column preset.
    const int kCustomIndex = currentCustomViewIndex();
    if (kCustomIndex >= 0)
    {
        applyCustomView(kCustomIndex);
    }
    else
    {
        applyViewMode(currentViewMode());
    }

    lastProcessDetailDemandFlags_ = currentProcessDetailDemandFlags();
    // Restoring built-in presets may show/hide the CPU core column; immediately synchronize the unique ETW session lifecycle.
    requestAsyncRefresh(true);

    KLogEvent logEvent;
    info << logEvent << "[ProcessDock] 进程表列布局已恢复为当前视图默认值。" << eol;
}

void ProcessDock::loadProcessColumnLayoutFromSettings()
{
    // Input: Per-column selection saved in QSettings.
    // Processing: Read only valid column indices, ignoring out-of-bounds items left over from historical versions.
    // Returns: void; result written to m_userColumnVisibilityOverride, applied at caller's discretion.
    userColumnVisibilityOverride_.clear();

    QSettings settings;
    settings.beginGroup(QString::fromLatin1(kProcessColumnLayoutSettingsGroup));
    const QStringList kSavedKeys = settings.childKeys();
    for (const QString& savedKey : kSavedKeys)
    {
        bool parseOk = false;
        const int kColumnIndex = savedKey.toInt(&parseOk);
        if (!parseOk || kColumnIndex < 0 || kColumnIndex >= static_cast<int>(TableColumn::kCount))
        {
            continue;
        }
        userColumnVisibilityOverride_.insert(kColumnIndex, settings.value(savedKey).toBool());
    }
    settings.endGroup();

    if (!userColumnVisibilityOverride_.isEmpty())
    {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 已从配置恢复进程表列布局, overrideCount="
            << userColumnVisibilityOverride_.size()
            << eol;
    }
}

void ProcessDock::saveProcessColumnLayoutToSettings() const
{
    QSettings settings;
    settings.beginGroup(QString::fromLatin1(kProcessColumnLayoutSettingsGroup));
    settings.remove(QString());
    for (auto overrideIt = userColumnVisibilityOverride_.constBegin();
        overrideIt != userColumnVisibilityOverride_.constEnd();
        ++overrideIt)
    {
        settings.setValue(QString::number(overrideIt.key()), overrideIt.value());
    }
    settings.endGroup();
}

void ProcessDock::loadCustomViewsFromSettings()
{
    // Input: custom view saved in QSettings.
    // Processing: Parse comma-separated column indices, discarding out-of-bounds items and empty views.
    // Return: None. Results are written to m_customViews.
    customViews_.clear();

    QSettings settings;
    settings.beginGroup(QString::fromLatin1(kProcessCustomViewSettingsGroup));
    const QStringList kSavedNames = settings.childKeys();
    for (const QString& savedName : kSavedNames)
    {
        const QString kTrimmedName = savedName.trimmed();
        if (kTrimmedName.isEmpty())
        {
            continue;
        }

        ProcessCustomView customView;
        customView.name = kTrimmedName;
        const QStringList kColumnTexts =
            settings.value(savedName).toString().split(QChar(','), Qt::SkipEmptyParts);
        for (const QString& columnText : kColumnTexts)
        {
            bool parseOk = false;
            const int kColumnIndex = columnText.trimmed().toInt(&parseOk);
            if (!parseOk || kColumnIndex < 0 || kColumnIndex >= static_cast<int>(TableColumn::kCount))
            {
                continue;
            }
            customView.visibleColumns.push_back(kColumnIndex);
        }

        if (!customView.visibleColumns.empty())
        {
            customViews_.push_back(std::move(customView));
        }
    }
    settings.endGroup();
}

void ProcessDock::saveCustomViewsToSettings() const
{
    QSettings settings;
    settings.beginGroup(QString::fromLatin1(kProcessCustomViewSettingsGroup));
    settings.remove(QString());
    for (const ProcessCustomView& customView : customViews_)
    {
        QStringList columnTexts;
        columnTexts.reserve(static_cast<int>(customView.visibleColumns.size()));
        for (const int kColumnIndex : customView.visibleColumns)
        {
            columnTexts.push_back(QString::number(kColumnIndex));
        }
        settings.setValue(customView.name, columnTexts.join(QChar(',')));
    }
    settings.endGroup();
}

void ProcessDock::rebuildViewModeComboItems()
{
    if (viewModeCombo_ == nullptr)
    {
        return;
    }

    // Remember the currently selected item and restore to the same view after reconstruction if possible.
    const int kPreviousDataValue = viewModeCombo_->count() > 0
        ? viewModeCombo_->currentData().toInt()
        : 0;

    // Suppress currentIndexChanged during reconstruction: otherwise, adding each item would trigger a view switch and forced refresh.
    viewModeComboUpdating_ = true;
    viewModeCombo_->clear();

    for (int modeIndex = 0; modeIndex < static_cast<int>(ViewMode::kCount); ++modeIndex)
    {
        const ViewMode kViewMode = static_cast<ViewMode>(modeIndex);
        const QIcon kItemIcon(QString::fromLatin1(
            kViewMode == ViewMode::kMonitor ? kProcessViewMonitorIconPath : kProcessViewPresetIconPath));
        viewModeCombo_->addItem(kItemIcon, viewModeDisplayName(kViewMode));
        viewModeCombo_->setItemData(viewModeCombo_->count() - 1, modeIndex);
    }

    for (std::size_t customIndex = 0; customIndex < customViews_.size(); ++customIndex)
    {
        // Custom views use a unified prefix to avoid ambiguity when names conflict with built-in presets.
        viewModeCombo_->addItem(
            ks::i18n::contextText(
                QStringLiteral("process.view.custom_prefix"),
                QStringLiteral("自定义：%1"))
                .arg(customViews_[customIndex].name));
        viewModeCombo_->setItemData(
            viewModeCombo_->count() - 1,
            -static_cast<int>(customIndex) - 1);
    }

    int restoredIndex = viewModeCombo_->findData(kPreviousDataValue);
    if (restoredIndex < 0)
    {
        restoredIndex = 0;
    }
    viewModeCombo_->setCurrentIndex(restoredIndex);
    viewModeComboUpdating_ = false;
}

int ProcessDock::saveCurrentColumnsAsCustomView(const QString& viewName)
{
    const QString kTrimmedName = viewName.trimmed();
    if (processTable_ == nullptr || kTrimmedName.isEmpty())
    {
        return -1;
    }

    ProcessCustomView customView;
    customView.name = kTrimmedName;
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
    {
        if (!processTable_->isColumnHidden(columnIndex))
        {
            customView.visibleColumns.push_back(columnIndex);
        }
    }
    if (customView.visibleColumns.empty())
    {
        return -1;
    }

    // Overwrite views with the same name directly, aligning with the intuition that 'save as same name' updates the view.
    int targetIndex = -1;
    for (std::size_t existingIndex = 0; existingIndex < customViews_.size(); ++existingIndex)
    {
        if (customViews_[existingIndex].name.compare(kTrimmedName, Qt::CaseInsensitive) == 0)
        {
            targetIndex = static_cast<int>(existingIndex);
            break;
        }
    }
    if (targetIndex >= 0)
    {
        customViews_[static_cast<std::size_t>(targetIndex)] = std::move(customView);
    }
    else
    {
        customViews_.push_back(std::move(customView));
        targetIndex = static_cast<int>(customViews_.size()) - 1;
    }

    saveCustomViewsToSettings();
    rebuildViewModeComboItems();

    // Select the just-saved view so the user sees it take effect immediately.
    if (viewModeCombo_ != nullptr)
    {
        const int kItemIndex = viewModeCombo_->findData(-targetIndex - 1);
        if (kItemIndex >= 0)
        {
            viewModeComboUpdating_ = true;
            viewModeCombo_->setCurrentIndex(kItemIndex);
            viewModeComboUpdating_ = false;
        }
    }

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 已保存自定义视图, name=" << kTrimmedName.toStdString()
        << ", columnCount=" << customViews_[static_cast<std::size_t>(targetIndex)].visibleColumns.size()
        << eol;
    return targetIndex;
}

void ProcessDock::removeCustomView(const int customIndex)
{
    if (customIndex < 0 || customIndex >= static_cast<int>(customViews_.size()))
    {
        return;
    }

    const QString kRemovedName = customViews_[static_cast<std::size_t>(customIndex)].name;
    customViews_.erase(customViews_.begin() + customIndex);
    saveCustomViewsToSettings();
    rebuildViewModeComboItems();

    // Fall back to Monitor view after deletion to prevent the dropdown from remaining on a non-existent item.
    if (viewModeCombo_ != nullptr)
    {
        const int kMonitorItemIndex = viewModeCombo_->findData(static_cast<int>(ViewMode::kMonitor));
        if (kMonitorItemIndex >= 0)
        {
            viewModeCombo_->setCurrentIndex(kMonitorItemIndex);
        }
    }

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 已删除自定义视图, name=" << kRemovedName.toStdString()
        << eol;
}

std::uint32_t ProcessDock::currentProcessDetailDemandFlags() const
{
    // Input: The current column visibility state of the process table.
    // Processing: Map 'columns requiring additional queries for population' to collection demand bits.
    // Returns: ks::process::process_detail_demand bitmap; None under default column layout.
    if (processTable_ == nullptr)
    {
        return ks::process::process_detail_demand::kNone;
    }

    std::uint32_t demandFlags = ks::process::process_detail_demand::kNone;

    if (isProcessColumnVisible(TableColumn::kGdiObjects) ||
        isProcessColumnVisible(TableColumn::kUserObjects))
    {
        demandFlags |= ks::process::process_detail_demand::kGuiResources;
    }
    if (isProcessColumnVisible(TableColumn::kJobObject))
    {
        demandFlags |= ks::process::process_detail_demand::kJobObject;
    }
    if (isProcessColumnVisible(TableColumn::kDataExecutionPrevention) ||
        isProcessColumnVisible(TableColumn::kControlFlowGuard) ||
        isProcessColumnVisible(TableColumn::kHardwareStackProtection))
    {
        demandFlags |= ks::process::process_detail_demand::kMitigationPolicy;
    }
    if (isProcessColumnVisible(TableColumn::kPackageName))
    {
        demandFlags |= ks::process::process_detail_demand::kPackageName;
    }
    if (isProcessColumnVisible(TableColumn::kDpiAwareness))
    {
        demandFlags |= ks::process::process_detail_demand::kDpiAwareness;
    }
    if (isProcessColumnVisible(TableColumn::kUacVirtualization))
    {
        demandFlags |= ks::process::process_detail_demand::kUacVirtualization;
    }
    if (isProcessColumnVisible(TableColumn::kDescription))
    {
        demandFlags |= ks::process::process_detail_demand::kFileDescription;
    }
    if (isProcessColumnVisible(TableColumn::kOsContext))
    {
        demandFlags |= ks::process::process_detail_demand::kOsContext;
    }
    if (isProcessColumnVisible(TableColumn::kEnterpriseContext))
    {
        demandFlags |= ks::process::process_detail_demand::kEnterpriseContext;
    }
    if (isProcessColumnVisible(TableColumn::kGpuDedicatedMemory) ||
        isProcessColumnVisible(TableColumn::kGpuSharedMemory))
    {
        demandFlags |= ks::process::process_detail_demand::kGpuMemory;
    }
    if (isProcessColumnVisible(TableColumn::kGpuEngine))
    {
        demandFlags |= ks::process::process_detail_demand::kGpuEngine;
    }

    return demandFlags;
}

void ProcessDock::showColumnChooserDialog()
{
    if (processTable_ == nullptr)
    {
        return;
    }

    QDialog columnDialog(this);
    columnDialog.setObjectName(QStringLiteral("ProcessColumnChooserDialog"));
    columnDialog.setWindowTitle(
        processColumnChooserText("process.columns.dialog.title", QStringLiteral("选择列")));
    columnDialog.setMinimumSize(460, 560);
    // Use an opaque dialog style: the Process page may enable a frosted glass background, and a transparent panel would make long lists hard to distinguish.
    columnDialog.setStyleSheet(ksword_theme::opaqueDialogStyle(columnDialog.objectName()));

    auto* const kDialogLayout = new QVBoxLayout(&columnDialog);
    kDialogLayout->setContentsMargins(12, 12, 12, 12);
    kDialogLayout->setSpacing(8);

    auto* const kHintLabel = new QLabel(
        processColumnChooserText(
            "process.columns.dialog.hint",
            QStringLiteral("勾选需要在进程列表中显示的列。部分列需要额外查询，只有勾选后才会采集。")),
        &columnDialog);
    kHintLabel->setWordWrap(true);
    kDialogLayout->addWidget(kHintLabel);

    auto* const kSearchEdit = new QLineEdit(&columnDialog);
    kSearchEdit->setClearButtonEnabled(true);
    kSearchEdit->setPlaceholderText(
        processColumnChooserText("process.columns.dialog.search", QStringLiteral("搜索列名...")));
    kDialogLayout->addWidget(kSearchEdit);

    auto* const kScrollArea = new QScrollArea(&columnDialog);
    kScrollArea->setWidgetResizable(true);
    auto* const kScrollContent = new QWidget(kScrollArea);
    auto* const kScrollLayout = new QVBoxLayout(kScrollContent);
    kScrollLayout->setContentsMargins(4, 4, 4, 4);
    kScrollLayout->setSpacing(4);

    // columnCheckBoxes: Store checkboxes by column index to facilitate search filtering and batch selection.
    std::vector<QCheckBox*> columnCheckBoxes(static_cast<std::size_t>(TableColumn::kCount), nullptr);
    // groupLabels: Group header controls, used to hide entire groups with no matches during search.
    std::vector<QLabel*> groupLabels(static_cast<std::size_t>(ProcessColumnGroup::kCount), nullptr);

    for (int groupIndex = 0; groupIndex < static_cast<int>(ProcessColumnGroup::kCount); ++groupIndex)
    {
        const ProcessColumnGroup kGroup = static_cast<ProcessColumnGroup>(groupIndex);

        auto* const kGroupLabel = new QLabel(processColumnGroupTitle(kGroup), kScrollContent);
        kGroupLabel->setStyleSheet(QStringLiteral("font-weight:700;color:%1;padding-top:6px;")
            .arg(ksword_theme::kPrimaryBlueHex));
        kScrollLayout->addWidget(kGroupLabel);
        groupLabels[static_cast<std::size_t>(groupIndex)] = kGroupLabel;

        for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
        {
            const TableColumn kColumn = static_cast<TableColumn>(columnIndex);
            if (processColumnGroupOf(kColumn) != kGroup)
            {
                continue;
            }

            const QString kColumnName = processColumnDisplayName(columnIndex);
            if (kColumnName.isEmpty())
            {
                continue;
            }

            auto* const kColumnCheck = new QCheckBox(kColumnName, kScrollContent);
            kColumnCheck->setChecked(!processTable_->isColumnHidden(columnIndex));
            kColumnCheck->setProperty("kswordColumnIndex", columnIndex);

            // The Name column is the row identifier; hiding the entire column is not allowed, or the process list becomes unrecognizable.
            if (kColumn == TableColumn::kName)
            {
                kColumnCheck->setChecked(true);
                kColumnCheck->setEnabled(false);
                kColumnCheck->setToolTip(processColumnChooserText(
                    "process.columns.dialog.name_locked",
                    QStringLiteral("进程名列是行标识，不能隐藏。")));
            }

            kScrollLayout->addWidget(kColumnCheck);
            columnCheckBoxes[static_cast<std::size_t>(columnIndex)] = kColumnCheck;
        }
    }

    kScrollLayout->addStretch(1);
    kScrollArea->setWidget(kScrollContent);
    kDialogLayout->addWidget(kScrollArea, 1);

    auto* const kQuickActionLayout = new QHBoxLayout();
    kQuickActionLayout->setSpacing(6);
    auto* const kSelectAllButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.select_all", QStringLiteral("全选")),
        &columnDialog);
    auto* const kClearAllButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.clear_all", QStringLiteral("全不选")),
        &columnDialog);
    auto* const kRestoreDefaultButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.restore_default", QStringLiteral("恢复默认")),
        &columnDialog);
    auto* const kSaveViewButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.save_view", QStringLiteral("保存为视图...")),
        &columnDialog);
    auto* const kDeleteViewButton = new QPushButton(
        processColumnChooserText("process.columns.dialog.delete_view", QStringLiteral("删除当前视图")),
        &columnDialog);
    // Allow deletion only when the currently selected view is a custom view; built-in presets are not deletable.
    kDeleteViewButton->setEnabled(currentCustomViewIndex() >= 0);
    kQuickActionLayout->addWidget(kSelectAllButton);
    kQuickActionLayout->addWidget(kClearAllButton);
    kQuickActionLayout->addWidget(kRestoreDefaultButton);
    kQuickActionLayout->addWidget(kSaveViewButton);
    kQuickActionLayout->addWidget(kDeleteViewButton);
    kQuickActionLayout->addStretch(1);
    kDialogLayout->addLayout(kQuickActionLayout);

    auto* const kButtonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &columnDialog);
    kDialogLayout->addWidget(kButtonBox);

    // Search filtering: Items matching column names are retained; if a group has no matches, the entire group including the header is hidden.
    QObject::connect(kSearchEdit, &QLineEdit::textChanged, &columnDialog,
        [&columnCheckBoxes, &groupLabels](const QString& filterText)
        {
            const QString kNormalizedFilter = filterText.trimmed();
            std::vector<bool> groupHasVisibleItem(
                static_cast<std::size_t>(ProcessColumnGroup::kCount),
                false);

            for (std::size_t columnIndex = 0; columnIndex < columnCheckBoxes.size(); ++columnIndex)
            {
                QCheckBox* const kColumnCheck = columnCheckBoxes[columnIndex];
                if (kColumnCheck == nullptr)
                {
                    continue;
                }

                const bool kMatched = kNormalizedFilter.isEmpty() ||
                    kColumnCheck->text().contains(kNormalizedFilter, Qt::CaseInsensitive);
                kColumnCheck->setVisible(kMatched);
                if (kMatched)
                {
                    const ProcessColumnGroup kGroup =
                        processColumnGroupOf(static_cast<TableColumn>(columnIndex));
                    groupHasVisibleItem[static_cast<std::size_t>(kGroup)] = true;
                }
            }

            for (std::size_t groupIndex = 0; groupIndex < groupLabels.size(); ++groupIndex)
            {
                if (groupLabels[groupIndex] != nullptr)
                {
                    groupLabels[groupIndex]->setVisible(groupHasVisibleItem[groupIndex]);
                }
            }
        });

    // Select all / Deselect all applies only to visible items in the current search results, aligning with user intuition for filtered results.
    const auto kApplyBulkCheckState =
        [&columnCheckBoxes](const bool checkedState) -> void
        {
            for (QCheckBox* const kColumnCheck : columnCheckBoxes)
            {
                if (kColumnCheck == nullptr || !kColumnCheck->isVisibleTo(kColumnCheck->parentWidget()))
                {
                    continue;
                }
                if (!kColumnCheck->isEnabled())
                {
                    continue;
                }
                kColumnCheck->setChecked(checkedState);
            }
        };
    QObject::connect(kSelectAllButton, &QPushButton::clicked, &columnDialog,
        [kApplyBulkCheckState]() { kApplyBulkCheckState(true); });
    QObject::connect(kClearAllButton, &QPushButton::clicked, &columnDialog,
        [kApplyBulkCheckState]() { kApplyBulkCheckState(false); });

    // Restore defaults: first clear user overrides and reapply view presets, then repopulate the dialog checkboxes based on the result.
    QObject::connect(kRestoreDefaultButton, &QPushButton::clicked, &columnDialog,
        [this, &columnCheckBoxes]()
        {
            resetProcessColumnsToViewDefault();
            for (std::size_t columnIndex = 0; columnIndex < columnCheckBoxes.size(); ++columnIndex)
            {
                QCheckBox* const kColumnCheck = columnCheckBoxes[columnIndex];
                if (kColumnCheck == nullptr)
                {
                    continue;
                }
                const QSignalBlocker kCheckBlocker(kColumnCheck);
                kColumnCheck->setChecked(!processTable_->isColumnHidden(static_cast<int>(columnIndex)));
            }
        });

    // applyCheckedColumnsToTable: Write the check states from the dialog to the table and return the number of columns actually changed.
    // When writing column by column, do not persist immediately; let the caller save uniformly after the batch and perform only one refresh check.
    const auto kApplyCheckedColumnsToTable =
        [this, &columnCheckBoxes]() -> int
        {
            int changedCount = 0;
            for (std::size_t columnIndex = 0; columnIndex < columnCheckBoxes.size(); ++columnIndex)
            {
                QCheckBox* const kColumnCheck = columnCheckBoxes[columnIndex];
                if (kColumnCheck == nullptr)
                {
                    continue;
                }

                const int kTargetColumn = static_cast<int>(columnIndex);
                const bool kShouldShow = kColumnCheck->isChecked();
                if (kShouldShow == !processTable_->isColumnHidden(kTargetColumn))
                {
                    continue;
                }
                setProcessColumnVisible(kTargetColumn, kShouldShow, false);
                ++changedCount;
            }
            return changedCount;
        };

    // commitColumnLayoutChanges: save column layout and immediately force a new collection cycle when collection requirements change.
    const auto kCommitColumnLayoutChanges =
        [this]() -> void
        {
            saveProcessColumnLayoutToSettings();
            applyAdaptiveColumnWidths();

            const std::uint32_t kNextDemandFlags = currentProcessDetailDemandFlags();
            if (kNextDemandFlags != lastProcessDetailDemandFlags_)
            {
                lastProcessDetailDemandFlags_ = kNextDemandFlags;
            }
            // Batch column changes may also include CPU cores, whose ETW lifecycle is not covered by the process_detail_demand bitmap.
            // The dialog calls this commit function only after actual column changes, so forcing a single refresh does not create a cyclic overhead.
            requestAsyncRefresh(true);
        };

    // Save as view: first apply current selections to the table, then create or overwrite a custom view with the same name based on this combination.
    QObject::connect(kSaveViewButton, &QPushButton::clicked, &columnDialog,
        [this, &columnDialog, kApplyCheckedColumnsToTable, kCommitColumnLayoutChanges]()
        {
            bool inputOk = false;
            const QString kViewName = QInputDialog::getText(
                &columnDialog,
                processColumnChooserText("process.columns.dialog.save_view_title", QStringLiteral("保存为视图")),
                processColumnChooserText("process.columns.dialog.save_view_prompt", QStringLiteral("视图名称：")),
                QLineEdit::Normal,
                QString(),
                &inputOk);
            if (!inputOk || kViewName.trimmed().isEmpty())
            {
                return;
            }

            kApplyCheckedColumnsToTable();
            kCommitColumnLayoutChanges();
            saveCurrentColumnsAsCustomView(kViewName);
            columnDialog.accept();
        });

    // Delete the current custom view: after deletion, the view dropdown falls back to the monitoring view.
    QObject::connect(kDeleteViewButton, &QPushButton::clicked, &columnDialog,
        [this, &columnDialog]()
        {
            const int kCustomIndex = currentCustomViewIndex();
            if (kCustomIndex < 0)
            {
                return;
            }
            removeCustomView(kCustomIndex);
            columnDialog.reject();
        });

    QObject::connect(kButtonBox, &QDialogButtonBox::accepted, &columnDialog, &QDialog::accept);
    QObject::connect(kButtonBox, &QDialogButtonBox::rejected, &columnDialog, &QDialog::reject);

    if (columnDialog.exec() != QDialog::Accepted)
    {
        return;
    }

    // Batch apply: write and overwrite columns one by one without immediate persistence; finally, save all at once and perform only a single refresh check.
    // The 'Save as View' branch has already been committed once; here, changedColumnCount will be 0 and the function returns directly.
    const int kChangedColumnCount = kApplyCheckedColumnsToTable();
    if (kChangedColumnCount == 0)
    {
        return;
    }

    kCommitColumnLayoutChanges();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 选择列已应用, changedColumnCount=" << kChangedColumnCount
        << ", demandFlags=" << lastProcessDetailDemandFlags_
        << eol;
}

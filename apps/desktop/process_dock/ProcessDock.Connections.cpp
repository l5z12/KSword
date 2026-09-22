#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::showProcessSettingsDialog()
{
    if (processSettingsDialog_ == nullptr)
    {
        return;
    }

    // Reuse the same controls for the non-modal window; repeated clicks on the gear icon simply bring the existing window to the foreground.
    processSettingsDialog_->adjustSize();
    processSettingsDialog_->show();
    processSettingsDialog_->raise();
    processSettingsDialog_->activateWindow();
}

void ProcessDock::initializeConnections()
{
    // Force an immediate refresh right after strategy switching.
    connect(strategyCombo_, &QComboBox::currentIndexChanged, this, [this]() {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 进程枚举策略切换为: "
            << strategyToText(toStrategy(strategyCombo_->currentIndex()))
            << eol;
        requestAsyncRefresh(true);
    });

    // Refresh immediately upon kernel comparison toggle change to ensure list highlight state matches the switch.
    connect(kernelCompareCheck_, &QCheckBox::toggled, this, [this](const bool checked) {
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 内核进程对比开关变更, enabled="
            << (checked ? "true" : "false")
            << eol;
        requestAsyncRefresh(true);
    });

    // The 'Show Hidden Items' toggle affects only local filtering; if R0 markers need to be re-fetched, the user can manually refresh.
    connect(showKswordHiddenProcessCheck_, &QCheckBox::toggled, this, [this](const bool checked) {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] Ksword隐藏项显示开关变更, visible="
            << (checked ? "true" : "false")
            << eol;
        rebuildTable();
    });

    // Process friendly view:
    // - When checked, buildDisplayOrder uses App/Background/System categories.
    // - When unchecked, switch directly to tree view; the two states are mutually exclusive and require no second button.
    connect(friendlyViewCheck_, &QCheckBox::toggled, this, [this](const bool checked) {
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
        // After the user manually toggles the checkbox, exit the header-triggered flat mode and reset the friendly view sort session.
        flatListForcedByHeaderSort_ = false;
        friendlySortActive_ = false;
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 进程友好视图开关变更, friendlyView="
            << (checked ? "true" : "false")
            << eol;
        rebuildTable();
    });

    // View mode switch: reset default visible columns.
    connect(viewModeCombo_, &QComboBox::currentIndexChanged, this, [this](const int modeIndex) {
        // Do not respond during the rebuild of dropdown items to prevent rebuildViewModeComboItems from triggering unnecessary refreshes.
        if (viewModeComboUpdating_)
        {
            return;
        }

        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();

        const int kCustomIndex = currentCustomViewIndex();
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 视图模式切换, itemIndex=" << modeIndex
            << ", customViewIndex=" << kCustomIndex
            << eol;

        if (kCustomIndex >= 0)
        {
            applyCustomView(kCustomIndex);
        }
        else
        {
            // Clear per-column overrides when switching built-in presets: otherwise, manually added columns from the previous view would carry over to the new view.
            userColumnVisibilityOverride_.clear();
            saveProcessColumnLayoutToSettings();
            applyViewMode(currentViewMode());
        }

        lastProcessDetailDemandFlags_ = currentProcessDetailDemandFlags();
        rebuildTable();
        requestAsyncRefresh(true);
    });

    // Start/Pause monitoring: only toggle the flag and timer, without blocking the UI.
    connect(startButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent logEvent;
        info << logEvent << "[ProcessDock] 用户点击开始刷新，恢复周期刷新并同步记录进程活动。" << eol;
        monitoringEnabled_ = true;
        activityRecordingEnabled_ = true;
        if (activitySamples_.empty())
        {
            activityRecordingStartTick100ns_ = steadyNow100ns();
            activityNextSequence_ = 0;
        }
        activityTimelinePinnedToLatest_ = true;
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
        if (refreshTimer_ != nullptr)
        {
            if (isProcessActivityRefreshAllowedNow())
            {
                refreshTimer_->start(refreshIntervalMillisecondsFromInput());
            }
            else
            {
                refreshTimer_->stop();
            }
        }
        requestAsyncRefresh(true);
    });
    connect(pauseButton_, &QPushButton::clicked, this, [this]() {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 用户点击暂停刷新，周期刷新与进程活动记录一起暂停。" << eol;
        monitoringEnabled_ = false;
        activityRecordingEnabled_ = false;
        if (refreshTimer_ != nullptr)
        {
            refreshTimer_->stop();
        }
        // Uncached icons are for display enhancement only. On suspend, cancel unstarted tasks and discard in-flight task callbacks.
        ++processIconExtractionGeneration_;
        processIconExtractionPool_.clear();
        processIconPathsInFlight_.clear();
        stopProcessNetworkTrafficCapture();
        stopCpuCoreUsageCapture();
        threadCounterSampleByIdentity_.clear();
        updateProcessActivityStatusLabel();
    });

    // Select columns: open the add/remove columns dialog, using the same implementation as the matching item in the header's right-click menu.
    if (columnChooserButton_ != nullptr)
    {
        connect(columnChooserButton_, &QPushButton::clicked, this, [this]() {
            showColumnChooserDialog();
        });
    }

    if (processSettingsButton_ != nullptr)
    {
        connect(processSettingsButton_, &QPushButton::clicked, this, [this]() {
            showProcessSettingsDialog();
        });
    }

    // Two interval spin boxes:
    // - Keyboard tracking is disabled; valueChanged is emitted only once on Enter, loss of focus, clicking the arrow, or scrolling.
    // - Use valueChanged instead of editingFinished; otherwise, adjustments made via up/down arrows will not take effect immediately.
    connect(refreshIntervalSpin_, &QDoubleSpinBox::valueChanged, this, [this](double) {
        applyRefreshIntervalInput();
    });
    connect(tableRefreshIntervalSpin_, &QDoubleSpinBox::valueChanged, this, [this](double) {
        applyTableRefreshIntervalInput();
    });

    // Clear record cache: reset index, timeline, and snap state.
    connect(activityClearButton_, &QPushButton::clicked, this, [this]() {
        activitySamples_.clear();
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
        activityNextSequence_ = 0;
        activityRecordingStartTick100ns_ = steadyNow100ns();
        activityTimelinePinnedToLatest_ = true;
        refreshProcessActivityTimeline();
        refreshProcessActivityChart();
        rebuildTable();
        updateProcessActivityStatusLabel();
        if (activitySnapshotLabel_ != nullptr)
        {
            activitySnapshotLabel_->setText(processContextText(
                "process.activity.snapshot.empty",
                QStringLiteral("时间轴快照：暂无样本")));
        }
    });

    // Metric button: after switching, only repaint the chart without changing the sample cache.
    const auto kConnectMetricButton = [this](QPushButton* button) {
        if (button == nullptr)
        {
            return;
        }
        connect(button, &QPushButton::toggled, this, [this]() {
            refreshProcessActivityChart();
            const int kSampleIndex = (activityTimelineSlider_ != nullptr) ? activityTimelineSlider_->value() : -1;
            if (kSampleIndex >= 0)
            {
                previewProcessActivitySnapshotForIndex(kSampleIndex);
            }
        });
    };
    kConnectMetricButton(activityCpuButton_);
    kConnectMetricButton(activityMemoryButton_);
    kConnectMetricButton(activityDiskButton_);
    kConnectMetricButton(activityNetworkButton_);
    kConnectMetricButton(activityGpuButton_);

    // Timeline slider: dragging to the far right enters 'snap to latest' mode; otherwise, it stays on historical samples.
    connect(activityTimelineSlider_, &QSlider::valueChanged, this, [this](const int sampleIndex) {
        if (activityTimelineSlider_ == nullptr)
        {
            return;
        }
        if (!activityTimelineSliderUpdating_)
        {
            // User requirement: Only switch the table timestamp when the timeline is clicked.
            // Normal valueChanged events may originate from programmatic synchronization or keyboard input; here, only the snapshot hint is updated.
            previewProcessActivitySnapshotForIndex(sampleIndex);
            return;
        }
        previewProcessActivitySnapshotForIndex(sampleIndex);
    });

    // Background refresh/record kept active:
    // - When unchecked, periodic refresh and recording automatically pause after the process page is hidden.
    // - When checked, allow background refresh to continue unless 'Do not record history' explicitly disables writing records.
    connect(activityBackgroundRecordCheck_, &QCheckBox::toggled, this, [this]() {
        updateProcessActivityStatusLabel();
        if (refreshTimer_ != nullptr && monitoringEnabled_)
        {
            if (isProcessActivityRefreshAllowedNow())
            {
                refreshTimer_->start(refreshIntervalMillisecondsFromInput());
            }
            else
            {
                refreshTimer_->stop();
                stopCpuCoreUsageCapture();
            }
        }
        if (monitoringEnabled_ && isProcessActivityRefreshAllowedNow())
        {
            requestAsyncRefresh(true);
        }
    });

    // Do not record history:
    // - When checked, do not clear historical samples; only pause subsequent appends.
    // - After cancellation, continue using the same record timeline for easy comparison of changes before and after.
    connect(activityListOnlyRefreshCheck_, &QCheckBox::toggled, this, [this](const bool checked) {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 不记录历史开关变更, listOnly="
            << (checked ? "true" : "false")
            << eol;
        updateProcessActivityStatusLabel();
        refreshProcessActivityChart();
    });

    // Table right-click context menu.
    connect(processTable_, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showTableContextMenu(localPosition);
    });

    // Header right-click menu (column show/hide).
    connect(processTable_->horizontalHeader(), &QHeaderView::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showHeaderContextMenu(localPosition);
    });

    // The friendly view must preserve the 'App/Background/System' grouping structure; QSortFilterProxyModel must not directly scatter the source order.
    // After clicking a tree view header, maintain a friendly unselected view: unbind parent-child relationships and switch to a flat enumeration sort.
    connect(processTable_->horizontalHeader(), &QHeaderView::sectionClicked, this, [this](const int logicalIndex) {
        if (isProcessActivityTableSnapshotActive() ||
            !currentProcessSearchText().isEmpty())
        {
            return;
        }
        if (logicalIndex < 0 || logicalIndex >= static_cast<int>(TableColumn::kCount))
        {
            return;
        }

        // Parent-child ordering in tree rows cannot be delegated to standard column sorting. On the first click, enforce ascending order,
        // keep checkboxes unchecked, and switch the internal projection to a simple process enumeration without parent-child relationships.
        const bool kTreeModeWasEnabled = isTreeModeEnabled();
        if (kTreeModeWasEnabled)
        {
            flatListForcedByHeaderSort_ = true;
            if (QHeaderView* const kHeaderView = processTable_->horizontalHeader())
            {
                kHeaderView->setSortIndicator(logicalIndex, Qt::AscendingOrder);
                kHeaderView->setSortIndicatorShown(true);
            }
            rebuildTable();
            return;
        }

        // When switched to a plain flat enumeration by the header, the sorting proxy toggles between ascending and descending order per Qt's default behavior.
        // Do not write the sort state specific to the friendly view here.
        if (flatListForcedByHeaderSort_)
        {
            return;
        }

        if (friendlySortActive_ && friendlySortColumn_ == logicalIndex)
        {
            friendlySortOrder_ = (friendlySortOrder_ == Qt::AscendingOrder)
                ? Qt::DescendingOrder
                : Qt::AscendingOrder;
        }
        else
        {
            friendlySortColumn_ = logicalIndex;
            friendlySortOrder_ = Qt::AscendingOrder;
        }
        friendlySortActive_ = true;

        if (!isFriendlyViewEnabled())
        {
            return;
        }

        if (processSortProxy_ != nullptr)
        {
            processSortProxy_->sort(toColumnIndex(TableColumn::kName), Qt::AscendingOrder);
        }
        rebuildTable();
    });

    // Rebuild the table immediately upon search box input change:
    // - Filters only the current cache, without waiting for the next refresh cycle;
    // - This ensures results converge immediately when typing keywords like 'notepad'.
    connect(processSearchLineEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        rebuildTable();
    });

    // Automatically focus the search box when switching back to the 'Process List' tab.
    // - The user does not need to click the input box first.
    // - Can immediately start typing search terms like 'notepad'.
    connect(sideTabWidget_, &QTabWidget::currentChanged, this, [this](const int currentIndex) {
        if (sideTabWidget_ == nullptr || currentIndex < 0)
        {
            return;
        }
        refreshSideTabIconContrast();

        QWidget* currentPage = sideTabWidget_->widget(currentIndex);
        if (currentPage == processListPage_)
        {
            if (monitoringEnabled_ && refreshTimer_ != nullptr && !refreshTimer_->isActive())
            {
                refreshTimer_->start(refreshIntervalMillisecondsFromInput());
            }
            focusProcessSearchBox(true);
            updateProcessActivityStatusLabel();
            if (monitoringEnabled_)
            {
                requestAsyncRefresh(true);
            }
            return;
        }
        if (monitoringEnabled_ &&
            activityBackgroundRecordCheck_ != nullptr &&
            !activityBackgroundRecordCheck_->isChecked())
        {
            if (refreshTimer_ != nullptr)
            {
                refreshTimer_->stop();
            }
            // When the page automatically pauses refreshing, synchronously stop the only CSwitch session in the background to prevent high-frequency events from lingering without consumers.
            stopCpuCoreUsageCapture();
        }
        if (currentPage == threadPage_)
        {
            updateProcessActivityStatusLabel();
            requestAsyncThreadRefresh(true);
            return;
        }
        updateProcessActivityStatusLabel();
    });

    // currentChanged:
    // - Record the identityKey of the process currently selected by the user.
    // - After a periodic refresh, rebuildTable will restore highlighting using this key.
    if (QItemSelectionModel* selectionModel = processTable_->selectionModel())
    {
        connect(selectionModel, &QItemSelectionModel::currentChanged, this, [this](const QModelIndex& currentIndex, const QModelIndex&) {
            if (!currentIndex.isValid())
            {
                if (!contextMenuVisible_)
                {
                    trackedSelectedIdentityKey_.clear();
                    trackedSelectedIdentityKeys_.clear();
                    trackedSelectedColumn_ = 0;
                }
                return;
            }

            const int kCurrentColumn = currentIndex.column();
            if (kCurrentColumn >= 0 && kCurrentColumn < static_cast<int>(TableColumn::kCount))
            {
                trackedSelectedColumn_ = kCurrentColumn;
            }
            syncTrackedSelectionFromTable();
        });

        // selectionChanged:
        // - Records the complete set of rows after Ctrl selection.
        // - After a periodic rebuildTable refresh, restore the multiple selection using identityKey.
        connect(selectionModel, &QItemSelectionModel::selectionChanged, this, [this](const QItemSelection&, const QItemSelection&) {
            syncTrackedSelectionFromTable();
            refreshProcessActivityChart();
            if (activityTimelineSlider_ != nullptr && !activitySamples_.empty())
            {
                previewProcessActivitySnapshotForIndex(activityTimelineSlider_->value());
            }
        });
    }

    // pressed:
    // - Synchronize the clicked column when a row is left-clicked;
    // - When restoring refresh, try to return to the user's original focused column.
    connect(processTable_, &QAbstractItemView::pressed, this, [this](const QModelIndex& index) {
        if (!index.isValid())
        {
            return;
        }

        const ProcessTableRow* tableRow = processTableRowForViewIndex(index);
        if (tableRow != nullptr && tableRow->rowKind == ProcessTableRowKind::kProcess)
        {
            trackedSelectedIdentityKey_ = tableRow->identityKey;
        }
        else if (tableRow != nullptr)
        {
            trackedSelectedIdentityKey_.clear();
        }
        if (index.column() >= 0 && index.column() < static_cast<int>(TableColumn::kCount))
        {
            trackedSelectedColumn_ = index.column();
        }
        QTimer::singleShot(0, this, [this]()
        {
            syncTrackedSelectionFromTable();
        });
    });

    // Collapse/expand when double-clicking a friendly view composite row; real process rows retain the Task Manager-style 'open details' behavior.
    connect(processTable_, &QAbstractItemView::doubleClicked, this, [this](const QModelIndex& index) {
        const ProcessTableRow* tableRow = processTableRowForViewIndex(index);
        if (tableRow == nullptr)
        {
            return;
        }

        if (tableRow->rowKind == ProcessTableRowKind::kGroupHeader ||
            tableRow->rowKind == ProcessTableRowKind::kApplicationAggregate)
        {
            if (!tableRow->expansionKey.isEmpty())
            {
                const bool kDefaultExpanded = tableRow->rowKind == ProcessTableRowKind::kGroupHeader;
                const bool kCurrentExpanded = friendlyExpandedStateByKey_.value(
                    tableRow->expansionKey,
                    kDefaultExpanded);
                friendlyExpandedStateByKey_.insert(tableRow->expansionKey, !kCurrentExpanded);
                rebuildTable();
            }
            return;
        }

        if (tableRow->rowKind == ProcessTableRowKind::kProcess)
        {
            openProcessDetailWindowByPid(tableRow->record.pid);
        }
    });

    // Alt+E action:
    // - Provides a shortcut to terminate processes similar to Task Manager.
    // - Execute the 'Terminate Process' shortcut action only on the 'Process List' page when a row is selected.
    QShortcut* terminateShortcut = new QShortcut(QKeySequence(Qt::ALT | Qt::Key_E), this);
    terminateShortcut->setContext(Qt::WidgetWithChildrenShortcut);
    connect(terminateShortcut, &QShortcut::activated, this, [this]() {
        if (sideTabWidget_ == nullptr || sideTabWidget_->currentWidget() != processListPage_)
        {
            return;
        }

        if (selectedActionTargets().empty())
        {
            KLogEvent logEvent;
            warn << logEvent
                << "[ProcessDock] Alt+E 被忽略：当前没有选中可结束的进程。"
                << eol;
            return;
        }

        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 触发快捷键 Alt+E，执行结束进程组合动作。"
            << eol;
        executeTerminateProcessAction();
    });

    // Thread-page-specific connections: centralized in a separate function to prevent the main connection function from growing further.
    initializeThreadPageConnections();
    initializeCrossViewConnections();
}

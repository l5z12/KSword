#include "ServiceDock.Internal.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

using namespace service_dock_detail;

namespace
{
    // createServiceTable: Creates the main service list control and configures the column structure.
    QTableWidget* createServiceTable(QWidget* parentWidget)
    {
        QTableWidget* tableWidget = new ks::ui::VisibleTableWidget(parentWidget);
        tableWidget->setColumnCount(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kCount));
        tableWidget->setHorizontalHeaderLabels({
            QStringLiteral("服务名"),
            QStringLiteral("显示名"),
            QStringLiteral("状态"),
            QStringLiteral("启动类型"),
            QStringLiteral("PID"),
            QStringLiteral("账户"),
            QStringLiteral("风险")
            });
        tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableWidget->setAlternatingRowColors(true);
        tableWidget->setWordWrap(false);
        tableWidget->verticalHeader()->setVisible(false);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableWidget->horizontalHeader()->setSectionResizeMode(
            ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kRisk),
            QHeaderView::Stretch);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kName), 180);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kDisplayName), 220);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kState), 100);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kStartType), 120);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kPid), 80);
        tableWidget->setColumnWidth(ServiceDock::toServiceColumn(ServiceDock::ServiceColumn::kAccount), 190);
        return tableWidget;
    }

    // createReadOnlyEditorPage purpose: Creates a 'read-only text editor tab'.
    QWidget* createReadOnlyEditorPage(CodeEditorWidget** editorOut, QWidget* parentWidget)
    {
        QWidget* pageWidget = new QWidget(parentWidget);
        QVBoxLayout* pageLayout = new QVBoxLayout(pageWidget);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(4);

        CodeEditorWidget* editorWidget = new CodeEditorWidget(pageWidget);
        editorWidget->setReadOnly(true);
        pageLayout->addWidget(editorWidget, 1);

        if (editorOut != nullptr)
        {
            *editorOut = editorWidget;
        }
        return pageWidget;
    }

    // makeVerticalSeparator: Generates a vertical toolbar separator to enhance visual hierarchy.
    QWidget* makeVerticalSeparator(QWidget* parentWidget)
    {
        QWidget* separatorWidget = new QWidget(parentWidget);
        separatorWidget->setFixedSize(1, 20);
        // Use dynamic tokens for the separator line color so style updates aren't needed when switching themes.
        separatorWidget->setStyleSheet(
            QStringLiteral("background-color:%1;").arg(ksword_theme::borderHex()));
        return separatorWidget;
    }

    // buildDetailSectionText purpose: wrap a detail text block with a unified title to facilitate merging multiple topic sections.
    QString buildDetailSectionText(const QString& titleText, const QString& bodyText)
    {
        return QStringLiteral("[%1]\n%2").arg(titleText).arg(bodyText.trimmed());
    }
}

int ServiceDock::toServiceColumn(const ServiceColumn column)
{
    return static_cast<int>(column);
}

void ServiceDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    initializeToolbar();
    initializeContent();

    rootLayout_->addWidget(toolbarWidget_, 0);
    rootLayout_->addWidget(contentSplitter_, 1);
}

void ServiceDock::initializeToolbar()
{
    toolbarWidget_ = new QWidget(this);
    toolbarLayout_ = new QHBoxLayout(toolbarWidget_);
    toolbarLayout_->setContentsMargins(0, 0, 0, 0);
    toolbarLayout_->setSpacing(6);

    // Basic refresh button group:
    // - Separate full refresh from per-service refresh to avoid accidental global rescans.
    refreshAllButton_ = new QToolButton(toolbarWidget_);
    refreshAllButton_->setIcon(createBlueIcon(":/Icon/process_refresh.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(refreshAllButton_);
    refreshAllButton_->setToolTip(QStringLiteral("刷新全部服务列表"));

    refreshCurrentButton_ = new QToolButton(toolbarWidget_);
    refreshCurrentButton_->setIcon(createBlueIcon(":/Icon/process_details.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(refreshCurrentButton_);
    refreshCurrentButton_->setToolTip(QStringLiteral("刷新当前选中服务详情"));

    // Service control button group:
    // - Use icon buttons for all.
    // - Detailed meaning is shown via tooltip.
    startButton_ = new QToolButton(toolbarWidget_);
    startButton_->setIcon(createBlueIcon(":/Icon/process_start.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(startButton_);
    startButton_->setToolTip(QStringLiteral("启动当前服务"));

    stopButton_ = new QToolButton(toolbarWidget_);
    stopButton_->setIcon(createBlueIcon(":/Icon/process_terminate.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(stopButton_);
    stopButton_->setToolTip(QStringLiteral("停止当前服务（高风险动作）"));

    pauseButton_ = new QToolButton(toolbarWidget_);
    pauseButton_->setIcon(createBlueIcon(":/Icon/process_pause.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(pauseButton_);
    pauseButton_->setToolTip(QStringLiteral("暂停当前服务"));

    continueButton_ = new QToolButton(toolbarWidget_);
    continueButton_->setIcon(createBlueIcon(":/Icon/process_resume.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(continueButton_);
    continueButton_->setToolTip(QStringLiteral("继续当前服务"));

    // Quick filter button group:
    // - Use short text filters to avoid reusing the 'Start/Stop Service' action icon for filtering semantics.
    // - Checkable form allows intuitive visibility of the filter state.
    runningOnlyButton_ = new QToolButton(toolbarWidget_);
    runningOnlyButton_->setCheckable(true);
    runningOnlyButton_->setText(QStringLiteral("运行中"));
    runningOnlyButton_->setToolButtonStyle(Qt::ToolButtonTextOnly);
    runningOnlyButton_->setFixedHeight(28);
    runningOnlyButton_->setToolTip(QStringLiteral("仅显示运行中服务"));

    autoStartOnlyButton_ = new QToolButton(toolbarWidget_);
    autoStartOnlyButton_->setCheckable(true);
    autoStartOnlyButton_->setText(QStringLiteral("自动启动"));
    autoStartOnlyButton_->setToolButtonStyle(Qt::ToolButtonTextOnly);
    autoStartOnlyButton_->setFixedHeight(28);
    autoStartOnlyButton_->setToolTip(QStringLiteral("仅显示自动启动服务"));

    riskOnlyButton_ = new QToolButton(toolbarWidget_);
    riskOnlyButton_->setCheckable(true);
    riskOnlyButton_->setText(QStringLiteral("风险"));
    riskOnlyButton_->setToolButtonStyle(Qt::ToolButtonTextOnly);
    riskOnlyButton_->setFixedHeight(28);
    riskOnlyButton_->setToolTip(QStringLiteral("仅显示带风险标签的服务"));

    // Text filtering and sorting:
    // - Keywords cover service name, display name, description, path, and account.
    // - Sorting mode is used to quickly adjust the focus perspective.
    filterEdit_ = new QLineEdit(toolbarWidget_);
    filterEdit_->setPlaceholderText(QStringLiteral("过滤：服务名/显示名/描述/路径/账户"));
    filterEdit_->setToolTip(QStringLiteral("支持关键字模糊匹配"));

    sortCombo_ = new QComboBox(toolbarWidget_);
    sortCombo_->addItem(QStringLiteral("名称升序"), static_cast<int>(SortMode::kNameAsc));
    sortCombo_->addItem(QStringLiteral("运行中优先"), static_cast<int>(SortMode::kStatePriority));
    sortCombo_->addItem(QStringLiteral("自动启动优先"), static_cast<int>(SortMode::kStartTypePriority));
    sortCombo_->setToolTip(QStringLiteral("切换服务列表排序方式"));

    // Startup type modification control:
    // - Select the target type via dropdown;
    // - Right-side icon button performs the change.
    startTypeCombo_ = new QComboBox(toolbarWidget_);
    startTypeCombo_->setToolTip(QStringLiteral("选择要应用到当前服务的启动类型"));
    startTypeCombo_->addItem(QStringLiteral("自动"));
    startTypeCombo_->setItemData(0, static_cast<qulonglong>(SERVICE_AUTO_START), Qt::UserRole);
    startTypeCombo_->setItemData(0, false, Qt::UserRole + 1);
    startTypeCombo_->addItem(QStringLiteral("自动(延迟)"));
    startTypeCombo_->setItemData(1, static_cast<qulonglong>(SERVICE_AUTO_START), Qt::UserRole);
    startTypeCombo_->setItemData(1, true, Qt::UserRole + 1);
    startTypeCombo_->addItem(QStringLiteral("手动"));
    startTypeCombo_->setItemData(2, static_cast<qulonglong>(SERVICE_DEMAND_START), Qt::UserRole);
    startTypeCombo_->setItemData(2, false, Qt::UserRole + 1);
    startTypeCombo_->addItem(QStringLiteral("禁用"));
    startTypeCombo_->setItemData(3, static_cast<qulonglong>(SERVICE_DISABLED), Qt::UserRole);
    startTypeCombo_->setItemData(3, false, Qt::UserRole + 1);

    applyStartTypeButton_ = new QToolButton(toolbarWidget_);
    applyStartTypeButton_->setIcon(createBlueIcon(":/Icon/service_apply.svg", ksword_theme::compactIconSize()));
    ksword_theme::applyCompactIconButtonMetrics(applyStartTypeButton_);
    applyStartTypeButton_->setToolTip(QStringLiteral("应用当前启动类型修改"));

    summaryLabel_ = new QLabel(QStringLiteral("状态：等待首次刷新"), toolbarWidget_);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    toolbarLayout_->addWidget(refreshAllButton_);
    toolbarLayout_->addWidget(refreshCurrentButton_);
    toolbarLayout_->addWidget(makeVerticalSeparator(toolbarWidget_));
    toolbarLayout_->addWidget(startButton_);
    toolbarLayout_->addWidget(stopButton_);
    toolbarLayout_->addWidget(pauseButton_);
    toolbarLayout_->addWidget(continueButton_);
    toolbarLayout_->addWidget(makeVerticalSeparator(toolbarWidget_));
    toolbarLayout_->addWidget(runningOnlyButton_);
    toolbarLayout_->addWidget(autoStartOnlyButton_);
    toolbarLayout_->addWidget(riskOnlyButton_);
    toolbarLayout_->addWidget(filterEdit_, 1);
    toolbarLayout_->addWidget(sortCombo_);
    toolbarLayout_->addWidget(startTypeCombo_);
    toolbarLayout_->addWidget(applyStartTypeButton_);
    toolbarLayout_->addWidget(summaryLabel_, 1);
}

void ServiceDock::initializeContent()
{
    contentSplitter_ = new QSplitter(Qt::Horizontal, this);
    contentSplitter_->setChildrenCollapsible(false);

    QWidget* leftPanelWidget = new QWidget(contentSplitter_);
    QVBoxLayout* leftPanelLayout = new QVBoxLayout(leftPanelWidget);
    leftPanelLayout->setContentsMargins(0, 0, 0, 0);
    leftPanelLayout->setSpacing(4);

    serviceTable_ = createServiceTable(leftPanelWidget);
    leftPanelLayout->addWidget(serviceTable_, 1);

    QWidget* rightPanelWidget = new QWidget(contentSplitter_);
    QVBoxLayout* rightPanelLayout = new QVBoxLayout(rightPanelWidget);
    rightPanelLayout->setContentsMargins(0, 0, 0, 0);
    rightPanelLayout->setSpacing(4);

    detailTabWidget_ = new QTabWidget(rightPanelWidget);
    initializeDetailTabs();
    rightPanelLayout->addWidget(detailTabWidget_, 1);

    contentSplitter_->addWidget(leftPanelWidget);
    contentSplitter_->addWidget(rightPanelWidget);
    contentSplitter_->setStretchFactor(0, 3);
    contentSplitter_->setStretchFactor(1, 2);
}

void ServiceDock::initializeConnections()
{
    connect(refreshAllButton_, &QToolButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });
    connect(refreshCurrentButton_, &QToolButton::clicked, this, [this]()
        {
            refreshSelectedService();
        });

    connect(startButton_, &QToolButton::clicked, this, [this]()
        {
            startSelectedService();
        });
    connect(stopButton_, &QToolButton::clicked, this, [this]()
        {
            stopSelectedService();
        });
    connect(pauseButton_, &QToolButton::clicked, this, [this]()
        {
            pauseSelectedService();
        });
    connect(continueButton_, &QToolButton::clicked, this, [this]()
        {
            continueSelectedService();
        });
    connect(applyStartTypeButton_, &QToolButton::clicked, this, [this]()
        {
            applySelectedStartType();
        });

    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&)
        {
            rebuildServiceTable();
        });
    connect(sortCombo_, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](const int)
        {
            rebuildServiceTable();
        });
    connect(runningOnlyButton_, &QToolButton::toggled, this, [this](const bool)
        {
            rebuildServiceTable();
        });
    connect(autoStartOnlyButton_, &QToolButton::toggled, this, [this](const bool)
        {
            rebuildServiceTable();
        });
    connect(riskOnlyButton_, &QToolButton::toggled, this, [this](const bool)
        {
            rebuildServiceTable();
        });

    connect(serviceTable_, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPos)
        {
            showServiceContextMenu(localPos);
        });
    connect(serviceTable_, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            onServiceSelectionChanged();
        });
    connect(serviceTable_, &QTableWidget::cellDoubleClicked, this, [this](const int row, const int)
        {
            if (row >= 0)
            {
                refreshSelectedService();
            }
        });

}

void ServiceDock::rebuildServiceTable()
{
    if (serviceTable_ == nullptr)
    {
        return;
    }

    // First, record the previous selection, then restore the selection by service short name after reconstruction to prevent user focus loss during refresh.
    const QString kPreviousSelectedServiceName = selectedServiceName();

    std::vector<int> visibleIndexList;
    visibleIndexList.reserve(serviceList_.size());
    for (int index = 0; index < static_cast<int>(serviceList_.size()); ++index)
    {
        const ServiceEntry& entry = serviceList_[static_cast<std::size_t>(index)];
        if (!entryMatchesCurrentFilter(entry))
        {
            continue;
        }
        visibleIndexList.push_back(index);
    }

    std::sort(
        visibleIndexList.begin(),
        visibleIndexList.end(),
        [this](const int leftIndex, const int rightIndex)
        {
            const ServiceEntry& leftEntry = serviceList_[static_cast<std::size_t>(leftIndex)];
            const ServiceEntry& rightEntry = serviceList_[static_cast<std::size_t>(rightIndex)];
            return serviceLessThan(leftEntry, rightEntry);
        });

    serviceTable_->setRowCount(static_cast<int>(visibleIndexList.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(visibleIndexList.size()); ++rowIndex)
    {
        const ServiceEntry& entry = serviceList_[static_cast<std::size_t>(visibleIndexList[static_cast<std::size_t>(rowIndex)])];

        QTableWidgetItem* nameItem = createReadOnlyItem(entry.serviceNameText);
        nameItem->setData(kServiceNameRole, entry.serviceNameText);
        nameItem->setIcon(entry.currentState == SERVICE_RUNNING
            ? createBlueIcon(":/Icon/process_start.svg")
            : createBlueIcon(":/Icon/process_pause.svg"));

        QTableWidgetItem* displayNameItem = createReadOnlyItem(entry.displayNameText);
        QTableWidgetItem* stateItem = createReadOnlyItem(entry.stateText);
        QTableWidgetItem* startTypeItem = createReadOnlyItem(entry.startTypeText);
        QTableWidgetItem* pidItem = createReadOnlyItem(entry.processId == 0
            ? QStringLiteral("-")
            : QString::number(entry.processId));
        QTableWidgetItem* accountItem = createReadOnlyItem(entry.accountText);
        QTableWidgetItem* riskItem = createReadOnlyItem(entry.riskSummaryText);

        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kName), nameItem);
        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kDisplayName), displayNameItem);
        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kState), stateItem);
        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kStartType), startTypeItem);
        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kPid), pidItem);
        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kAccount), accountItem);
        serviceTable_->setItem(rowIndex, toServiceColumn(ServiceColumn::kRisk), riskItem);

        // Basic highlight strategy:
        // - Running: light green highlight;
        // - Auto-start: light blue highlight;
        // - Pending: Orange weak highlight.
        QColor rowColor;
        if (entry.currentState == SERVICE_RUNNING)
        {
            rowColor = ksword_theme::withAlpha(ksword_theme::successColor(), 70);
        }
        else if (isServiceStatePending(entry.currentState))
        {
            rowColor = ksword_theme::withAlpha(ksword_theme::warningColor(), 70);
        }
        else if (entry.startTypeValue == SERVICE_AUTO_START)
        {
            rowColor = ksword_theme::withAlpha(
                ksword_theme::accentColor(ksword_theme::AccentRole::kBlue), 45);
        }
        if (entry.hasRisk)
        {
            rowColor = ksword_theme::withAlpha(ksword_theme::errorColor(), 68);
        }

        if (rowColor.isValid())
        {
            for (int columnIndex = 0; columnIndex < toServiceColumn(ServiceColumn::kCount); ++columnIndex)
            {
                QTableWidgetItem* rowItem = serviceTable_->item(rowIndex, columnIndex);
                if (rowItem != nullptr)
                {
                    rowItem->setBackground(rowColor);
                }
            }
        }
    }

    // Restore selection after reconstruction:
    // - Prioritize restoring the previous service;
    // - If the previous service does not exist, select the first row.
    bool restoredSelection = false;
    if (!kPreviousSelectedServiceName.isEmpty())
    {
        for (int rowIndex = 0; rowIndex < serviceTable_->rowCount(); ++rowIndex)
        {
            QTableWidgetItem* nameItem = serviceTable_->item(rowIndex, toServiceColumn(ServiceColumn::kName));
            if (nameItem == nullptr)
            {
                continue;
            }

            const QString kRowServiceName = nameItem->data(kServiceNameRole).toString();
            if (QString::compare(kRowServiceName, kPreviousSelectedServiceName, Qt::CaseInsensitive) == 0)
            {
                serviceTable_->selectRow(rowIndex);
                restoredSelection = true;
                break;
            }
        }
    }
    if (!restoredSelection && serviceTable_->rowCount() > 0)
    {
        serviceTable_->selectRow(0);
    }

    updateSummaryText();
    syncToolbarStateWithSelection();
    updateDetailViewsFromSelection();
}

bool ServiceDock::entryMatchesCurrentFilter(const ServiceEntry& entry) const
{
    if ((runningOnlyButton_ != nullptr)
        && runningOnlyButton_->isChecked()
        && entry.currentState != SERVICE_RUNNING)
    {
        return false;
    }

    if ((autoStartOnlyButton_ != nullptr)
        && autoStartOnlyButton_->isChecked()
        && entry.startTypeValue != SERVICE_AUTO_START)
    {
        return false;
    }

    if ((riskOnlyButton_ != nullptr)
        && riskOnlyButton_->isChecked()
        && !entry.hasRisk)
    {
        return false;
    }

    const QString kKeywordText = (filterEdit_ != nullptr) ? filterEdit_->text().trimmed() : QString();
    if (kKeywordText.isEmpty())
    {
        return true;
    }

    const QString kHaystackText =
        entry.serviceNameText + QLatin1Char('\n')
        + entry.displayNameText + QLatin1Char('\n')
        + entry.descriptionText + QLatin1Char('\n')
        + entry.imagePathText + QLatin1Char('\n')
        + entry.commandLineText + QLatin1Char('\n')
        + entry.accountText + QLatin1Char('\n')
        + entry.sourceStatusText + QLatin1Char('\n')
        + entry.riskSummaryText;
    return kHaystackText.contains(kKeywordText, Qt::CaseInsensitive);
}

bool ServiceDock::serviceLessThan(const ServiceEntry& left, const ServiceEntry& right) const
{
    const SortMode kSortMode = (sortCombo_ == nullptr)
        ? SortMode::kNameAsc
        : static_cast<SortMode>(sortCombo_->currentData().toInt());

    if (kSortMode == SortMode::kStatePriority)
    {
        const bool kLeftRunning = left.currentState == SERVICE_RUNNING;
        const bool kRightRunning = right.currentState == SERVICE_RUNNING;
        if (kLeftRunning != kRightRunning)
        {
            return kLeftRunning;
        }

        const bool kLeftPending = isServiceStatePending(left.currentState);
        const bool kRightPending = isServiceStatePending(right.currentState);
        if (kLeftPending != kRightPending)
        {
            return kLeftPending;
        }
    }
    else if (kSortMode == SortMode::kStartTypePriority)
    {
        const bool kLeftAuto = left.startTypeValue == SERVICE_AUTO_START;
        const bool kRightAuto = right.startTypeValue == SERVICE_AUTO_START;
        if (kLeftAuto != kRightAuto)
        {
            return kLeftAuto;
        }

        if (left.startTypeValue != right.startTypeValue)
        {
            return left.startTypeValue < right.startTypeValue;
        }
    }

    const int kDisplayCompareResult = QString::compare(left.displayNameText, right.displayNameText, Qt::CaseInsensitive);
    if (kDisplayCompareResult != 0)
    {
        return kDisplayCompareResult < 0;
    }

    return QString::compare(left.serviceNameText, right.serviceNameText, Qt::CaseInsensitive) < 0;
}

void ServiceDock::updateSummaryText()
{
    if (summaryLabel_ == nullptr)
    {
        return;
    }

    int runningCount = 0;
    int autoStartCount = 0;
    int riskCount = 0;
    int registryOnlyCount = 0;
    int scmOnlyCount = 0;
    for (const ServiceEntry& entry : serviceList_)
    {
        if (entry.currentState == SERVICE_RUNNING)
        {
            ++runningCount;
        }
        if (entry.startTypeValue == SERVICE_AUTO_START)
        {
            ++autoStartCount;
        }
        if (entry.hasRisk)
        {
            ++riskCount;
        }
        if (entry.registryScanCompleted
            && !entry.scmRecordPresent
            && entry.registryKeyPresent)
        {
            ++registryOnlyCount;
        }
        if (entry.registryScanCompleted
            && entry.scmRecordPresent
            && !entry.registryKeyPresent)
        {
            ++scmOnlyCount;
        }
    }

    const int kVisibleCount = (serviceTable_ == nullptr) ? 0 : serviceTable_->rowCount();
    summaryLabel_->setText(
        QStringLiteral("状态：总计 %1，运行中 %2，自动启动 %3，风险 %4，幽灵 %5，SCM 异常 %6，当前可见 %7")
        .arg(serviceList_.size())
        .arg(runningCount)
        .arg(autoStartCount)
        .arg(riskCount)
        .arg(registryOnlyCount)
        .arg(scmOnlyCount)
        .arg(kVisibleCount));
}

QString ServiceDock::selectedServiceName() const
{
    if (serviceTable_ == nullptr)
    {
        return QString();
    }

    const int kCurrentRow = serviceTable_->currentRow();
    if (kCurrentRow < 0)
    {
        return QString();
    }

    QTableWidgetItem* nameItem = serviceTable_->item(kCurrentRow, toServiceColumn(ServiceColumn::kName));
    if (nameItem == nullptr)
    {
        return QString();
    }

    return nameItem->data(kServiceNameRole).toString().trimmed();
}

void ServiceDock::syncToolbarStateWithSelection()
{
    const int kSelectedIndex = findServiceIndexByName(selectedServiceName());
    const bool kHasSelection = kSelectedIndex >= 0 && kSelectedIndex < static_cast<int>(serviceList_.size());

    if (!kHasSelection)
    {
        refreshCurrentButton_->setEnabled(false);
        startButton_->setEnabled(false);
        stopButton_->setEnabled(false);
        pauseButton_->setEnabled(false);
        continueButton_->setEnabled(false);
        applyStartTypeButton_->setEnabled(false);
        startTypeCombo_->setEnabled(false);
        if (generalStartButton_ != nullptr) { generalStartButton_->setEnabled(false); }
        if (generalStopButton_ != nullptr) { generalStopButton_->setEnabled(false); }
        if (generalPauseButton_ != nullptr) { generalPauseButton_->setEnabled(false); }
        if (generalContinueButton_ != nullptr) { generalContinueButton_->setEnabled(false); }
        // Also explain the reason when no service is selected to avoid users guessing why a row of gray buttons is unresponsive.
        const QString kNoSelectionText = QStringLiteral("请先在列表中选择一个服务");
        startButton_->setToolTip(kNoSelectionText);
        stopButton_->setToolTip(kNoSelectionText);
        pauseButton_->setToolTip(kNoSelectionText);
        continueButton_->setToolTip(kNoSelectionText);
        applyStartTypeButton_->setToolTip(kNoSelectionText);
        return;
    }

    const ServiceEntry& selectedEntry = serviceList_[static_cast<std::size_t>(kSelectedIndex)];
    const bool kScmRecordPresent = selectedEntry.scmRecordPresent;
    const bool kPendingState = kScmRecordPresent
        && isServiceStatePending(selectedEntry.currentState);
    const bool kCanPauseContinue = (selectedEntry.controlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) != 0;

    refreshCurrentButton_->setEnabled(true);
    startButton_->setEnabled(kScmRecordPresent
        && !kPendingState
        && (selectedEntry.currentState == SERVICE_STOPPED || selectedEntry.currentState == SERVICE_PAUSED));
    stopButton_->setEnabled(kScmRecordPresent
        && !kPendingState
        && (selectedEntry.currentState == SERVICE_RUNNING || selectedEntry.currentState == SERVICE_PAUSED));

    // Restore the standard tooltip after selecting a service; during the transition state, indicate that a switch is in progress;
    // otherwise, the "Please select a service first" message written to the unselected branch would persist indefinitely.
    if (!kScmRecordPresent)
    {
        const QString kUnavailableText = QStringLiteral("该条目未出现在 SCM 枚举中，仅提供注册表取证与删除操作");
        startButton_->setToolTip(kUnavailableText);
        stopButton_->setToolTip(kUnavailableText);
        applyStartTypeButton_->setToolTip(kUnavailableText);
    }
    else if (kPendingState)
    {
        const QString kPendingText = QStringLiteral("服务正在切换状态，请等待完成");
        startButton_->setToolTip(kPendingText);
        stopButton_->setToolTip(kPendingText);
        applyStartTypeButton_->setToolTip(kPendingText);
    }
    else
    {
        startButton_->setToolTip(startButton_->isEnabled()
            ? QStringLiteral("启动当前服务")
            : QStringLiteral("仅在服务已停止或已暂停时可启动"));
        stopButton_->setToolTip(stopButton_->isEnabled()
            ? QStringLiteral("停止当前服务（高风险动作）")
            : QStringLiteral("仅在服务正在运行或已暂停时可停止"));
        applyStartTypeButton_->setToolTip(QStringLiteral("应用当前启动类型修改"));
    }
    pauseButton_->setEnabled(kScmRecordPresent
        && !kPendingState
        && selectedEntry.currentState == SERVICE_RUNNING
        && kCanPauseContinue);
    continueButton_->setEnabled(kScmRecordPresent
        && !kPendingState
        && selectedEntry.currentState == SERVICE_PAUSED
        && kCanPauseContinue);

    // Grayed-out buttons must explain the reason: these two buttons have three independent sources for
    //being disabled (service does not support pause/resume, currently in a transition state, or current
    // state does not match). Previously, the tooltip was always 'Pause current service'. Users only see
    // grayed-out buttons, repeatedly switching services and waiting, but never see them become available.
    if (!kScmRecordPresent)
    {
        const QString kUnavailableText = QStringLiteral("该条目未出现在 SCM 枚举中，无法执行服务控制");
        pauseButton_->setToolTip(kUnavailableText);
        continueButton_->setToolTip(kUnavailableText);
    }
    else if (!kCanPauseContinue)
    {
        const QString kUnsupportedText = QStringLiteral("该服务不支持暂停/继续");
        pauseButton_->setToolTip(kUnsupportedText);
        continueButton_->setToolTip(kUnsupportedText);
    }
    else if (kPendingState)
    {
        const QString kPendingText = QStringLiteral("服务正在切换状态，请等待完成");
        pauseButton_->setToolTip(kPendingText);
        continueButton_->setToolTip(kPendingText);
    }
    else
    {
        pauseButton_->setToolTip(pauseButton_->isEnabled()
            ? QStringLiteral("暂停当前服务")
            : QStringLiteral("仅在服务正在运行时可暂停"));
        continueButton_->setToolTip(continueButton_->isEnabled()
            ? QStringLiteral("继续当前服务")
            : QStringLiteral("仅在服务已暂停时可继续"));
    }
    applyStartTypeButton_->setEnabled(kScmRecordPresent && !kPendingState);
    startTypeCombo_->setEnabled(kScmRecordPresent && !kPendingState);
    if (generalStartButton_ != nullptr) { generalStartButton_->setEnabled(startButton_->isEnabled()); }
    if (generalStopButton_ != nullptr) { generalStopButton_->setEnabled(stopButton_->isEnabled()); }
    if (generalPauseButton_ != nullptr) { generalPauseButton_->setEnabled(pauseButton_->isEnabled()); }
    if (generalContinueButton_ != nullptr) { generalContinueButton_->setEnabled(continueButton_->isEnabled()); }

    if (!detailUiSyncInProgress_ && generalStartTypeCombo_ != nullptr)
    {
        const QSignalBlocker kBlocker(generalStartTypeCombo_);
        const int kGeneralStartTypeIndex = generalStartTypeCombo_->findData(static_cast<qulonglong>(selectedEntry.startTypeValue));
        if (kGeneralStartTypeIndex >= 0)
        {
            generalStartTypeCombo_->setCurrentIndex(kGeneralStartTypeIndex);
        }
    }

    const QSignalBlocker kStartTypeBlocker(startTypeCombo_);
    const int kToolbarStartTypeIndex = startTypeCombo_->findData(static_cast<qulonglong>(selectedEntry.startTypeValue), Qt::UserRole);
    if (kToolbarStartTypeIndex >= 0)
    {
        startTypeCombo_->setCurrentIndex(kToolbarStartTypeIndex);
    }
}

int ServiceDock::findServiceIndexByName(const QString& serviceNameText) const
{
    if (serviceNameText.trimmed().isEmpty())
    {
        return -1;
    }

    for (int index = 0; index < static_cast<int>(serviceList_.size()); ++index)
    {
        const ServiceEntry& entry = serviceList_[static_cast<std::size_t>(index)];
        if (QString::compare(entry.serviceNameText, serviceNameText, Qt::CaseInsensitive) == 0)
        {
            return index;
        }
    }
    return -1;
}

void ServiceDock::onServiceSelectionChanged()
{
    updateDetailViewsFromSelection();
    syncToolbarStateWithSelection();
}

QString ServiceDock::buildAuditTabText(const ServiceEntry& entry) const
{
    const QString kSourceDetailText = QStringLiteral("交叉比对：%1\nSCM 枚举：%2\n注册表键：%3")
        .arg(entry.sourceStatusText)
        .arg(entry.scmRecordPresent ? QStringLiteral("存在") : QStringLiteral("未发现"))
        .arg(entry.registryKeyPresent ? QStringLiteral("存在") : QStringLiteral("未发现"));
    return buildDetailSectionText(QStringLiteral("独立来源"), kSourceDetailText)
        + QStringLiteral("\n\n")
        + buildDetailSectionText(QStringLiteral("触发器"), buildTriggerDetailText(entry))
        + QStringLiteral("\n\n")
        + buildDetailSectionText(QStringLiteral("安全"), buildSecurityDetailText(entry))
        + QStringLiteral("\n\n")
        + buildDetailSectionText(QStringLiteral("风险"), buildRiskDetailText(entry))
        + QStringLiteral("\n\n")
        + buildDetailSectionText(QStringLiteral("导出"), buildExportDetailText(entry));
}

QString ServiceDock::buildBasicInfoText(const ServiceEntry& entry) const
{
    QString detailText;
    detailText += QStringLiteral("服务名：%1\n").arg(entry.serviceNameText);
    detailText += QStringLiteral("来源交叉验证：%1\n").arg(entry.sourceStatusText);
    detailText += QStringLiteral("显示名：%1\n").arg(entry.displayNameText);
    detailText += QStringLiteral("状态：%1\n").arg(entry.stateText);
    detailText += QStringLiteral("PID：%1\n").arg(entry.processId == 0 ? QStringLiteral("-") : QString::number(entry.processId));
    detailText += QStringLiteral("启动类型：%1\n").arg(entry.startTypeText);
    detailText += QStringLiteral("延迟自动启动：%1\n").arg(entry.delayedAutoStart ? QStringLiteral("是") : QStringLiteral("否"));
    detailText += QStringLiteral("服务类型：%1\n").arg(entry.serviceTypeText);
    detailText += QStringLiteral("错误控制：%1\n").arg(entry.errorControlText);
    detailText += QStringLiteral("启动账户：%1\n").arg(entry.accountText);
    detailText += QStringLiteral("镜像路径：%1\n").arg(entry.imagePathText);
    detailText += QStringLiteral("ServiceDll：%1\n").arg(entry.serviceDllPathText.isEmpty() ? QStringLiteral("未配置") : entry.serviceDllPathText);
    detailText += QStringLiteral("BinaryPath：%1\n").arg(entry.commandLineText);
    detailText += QStringLiteral("描述：%1\n").arg(entry.descriptionText);
    detailText += QStringLiteral("风险摘要：%1\n").arg(entry.riskSummaryText);
    return detailText;
}

QString ServiceDock::buildConfigInfoText(const ServiceEntry& entry) const
{
    QString detailText;
    detailText += QStringLiteral("dwStartType：%1\n").arg(entry.startTypeValue);
    detailText += QStringLiteral("dwServiceType：%1\n").arg(entry.serviceTypeValue);
    detailText += QStringLiteral("dwErrorControl：%1\n").arg(entry.errorControlValue);
    detailText += QStringLiteral("当前状态值：%1\n").arg(entry.currentState);
    detailText += QStringLiteral("可接受控制位：%1\n").arg(entry.controlsAccepted);
    detailText += QStringLiteral("启动类型文本：%1\n").arg(entry.startTypeText);
    detailText += QStringLiteral("服务类型文本：%1\n").arg(entry.serviceTypeText);
    detailText += QStringLiteral("错误控制文本：%1\n").arg(entry.errorControlText);
    detailText += QStringLiteral("账户：%1\n").arg(entry.accountText);
    detailText += QStringLiteral("描述：%1\n").arg(entry.descriptionText);
    return detailText;
}

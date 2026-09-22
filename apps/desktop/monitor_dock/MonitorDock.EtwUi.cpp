#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::updateEtwCollapseHeight()
{
    if (etwCollapseHostWidget_ == nullptr)
    {
        return;
    }

    if (etwCollapseHostLayout_ != nullptr)
    {
        etwCollapseHostLayout_->activate();
    }

    // The custom collapsible area allows full collapse, so only notify layout recalculation without constraining height based on the 'current page'.
    etwCollapseHostWidget_->setMinimumHeight(0);
    etwCollapseHostWidget_->setMaximumHeight(QWIDGETSIZE_MAX);
    etwCollapseHostWidget_->updateGeometry();
    if (etwPage_ != nullptr)
    {
        etwPage_->updateGeometry();
    }
}

void MonitorDock::initializeEtwTab()
{
    etwPage_ = new QWidget(sideTabWidget_);
    etwLayout_ = new QVBoxLayout(etwPage_);
    etwLayout_->setContentsMargins(4, 4, 4, 4);
    etwLayout_->setSpacing(6);

    // ETW top configuration area uses a custom independent collapsible section:
    // - Replace QToolBox to remove the restriction that requires at least one expanded page to be retained.
    // - Each section controls only its own content; users can collapse all configuration sections.
    etwCollapseHostWidget_ = new QWidget(etwPage_);
    etwCollapseHostWidget_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    etwCollapseHostLayout_ = new QVBoxLayout(etwCollapseHostWidget_);
    etwCollapseHostLayout_->setContentsMargins(0, 0, 0, 0);
    etwCollapseHostLayout_->setSpacing(4);
    etwLayout_->addWidget(etwCollapseHostWidget_, 0);

    // Providers and sessions share a single collapsible page, laid out side-by-side within the page.
    QWidget* etwProviderSessionPanel = new QWidget(etwCollapseHostWidget_);
    QHBoxLayout* etwProviderSessionLayout = new QHBoxLayout(etwProviderSessionPanel);
    etwProviderSessionLayout->setContentsMargins(4, 4, 4, 4);
    etwProviderSessionLayout->setSpacing(6);

    etwProviderPanel_ = new QWidget(etwProviderSessionPanel);
    etwProviderPanelLayout_ = new QVBoxLayout(etwProviderPanel_);
    etwProviderPanelLayout_->setContentsMargins(4, 4, 4, 4);
    etwProviderPanelLayout_->setSpacing(6);

    etwProviderControlLayout_ = new QHBoxLayout();
    etwProviderControlLayout_->setContentsMargins(0, 0, 0, 0);
    etwProviderControlLayout_->setSpacing(6);

    etwProviderRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), etwProviderPanel_);
    etwProviderRefreshButton_->setToolTip(QStringLiteral("刷新ETW Provider"));
    etwProviderRefreshButton_->setStyleSheet(blueButtonStyle());
    etwProviderRefreshButton_->setFixedWidth(34);

    etwProviderStatusLabel_ = new QLabel(QStringLiteral("● 待刷新"), etwProviderPanel_);
    ks::ui::applyStatusRole(etwProviderStatusLabel_, ks::ui::StatusRole::kIdle);

    etwProviderControlLayout_->addWidget(new QLabel(QStringLiteral("ETW Providers"), etwProviderPanel_));
    etwProviderControlLayout_->addStretch(1);
    etwProviderControlLayout_->addWidget(etwProviderRefreshButton_);
    etwProviderControlLayout_->addWidget(etwProviderStatusLabel_);

    // Change the Provider area to a left-right split layout:
    // - Left side: Pre-set common Provider templates (including category filtering).
    // - Right side: A checkbox list of all Providers enumerated by the system.
    QHBoxLayout* etwProviderSplitLayout = new QHBoxLayout();
    etwProviderSplitLayout->setContentsMargins(0, 0, 0, 0);
    etwProviderSplitLayout->setSpacing(6);

    QWidget* etwPresetWidget = new QWidget(etwProviderPanel_);
    QVBoxLayout* etwPresetLayout = new QVBoxLayout(etwPresetWidget);
    etwPresetLayout->setContentsMargins(0, 0, 0, 0);
    etwPresetLayout->setSpacing(4);

    QHBoxLayout* etwPresetHeaderLayout = new QHBoxLayout();
    etwPresetHeaderLayout->setContentsMargins(0, 0, 0, 0);
    etwPresetHeaderLayout->setSpacing(6);
    etwPresetHeaderLayout->addWidget(new QLabel(QStringLiteral("常用模板"), etwPresetWidget));

    etwPresetCategoryCombo_ = new QComboBox(etwPresetWidget);
    etwPresetCategoryCombo_->setStyleSheet(blueInputStyle());
    etwPresetCategoryCombo_->addItems(QStringList{
        QStringLiteral("全部分类"),
        QStringLiteral("进程线程"),
        QStringLiteral("文件注册表"),
        QStringLiteral("网络通信"),
        QStringLiteral("安全审计"),
        QStringLiteral("脚本管理")
    });
    etwPresetHeaderLayout->addWidget(etwPresetCategoryCombo_, 1);
    etwPresetLayout->addLayout(etwPresetHeaderLayout);

    etwPresetProviderList_ = new QListWidget(etwPresetWidget);
    etwPresetProviderList_->setAlternatingRowColors(true);
    etwPresetProviderList_->setMinimumHeight(180);
    etwPresetLayout->addWidget(etwPresetProviderList_, 1);

    // Capture selection and simple filtering reuse the same common Provider descriptors to avoid divergence between the two lists.
    for (const EtwPresetProviderDescriptor& preset : etwPresetProviderDescriptorList())
    {
        QListWidgetItem* item = new QListWidgetItem(
            QStringLiteral("[%1] %2").arg(preset.categoryText, preset.providerNameText),
            etwPresetProviderList_);
        item->setData(Qt::UserRole, preset.providerNameText);
        item->setData(Qt::UserRole + 1, preset.categoryText);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(Qt::Checked);
    }

    QWidget* etwAllProviderWidget = new QWidget(etwProviderPanel_);
    QVBoxLayout* etwAllProviderLayout = new QVBoxLayout(etwAllProviderWidget);
    etwAllProviderLayout->setContentsMargins(0, 0, 0, 0);
    etwAllProviderLayout->setSpacing(4);
    etwAllProviderLayout->addWidget(new QLabel(QStringLiteral("系统Providers"), etwAllProviderWidget));

    etwProviderList_ = new QListWidget(etwAllProviderWidget);
    etwProviderList_->setAlternatingRowColors(true);
    etwProviderList_->setMinimumHeight(180);
    etwAllProviderLayout->addWidget(etwProviderList_, 1);

    etwProviderSplitLayout->addWidget(etwPresetWidget, 1);
    etwProviderSplitLayout->addWidget(etwAllProviderWidget, 2);

    etwProviderPanelLayout_->addLayout(etwProviderControlLayout_);
    etwProviderPanelLayout_->addLayout(etwProviderSplitLayout, 1);

    etwSessionPanel_ = new QWidget(etwProviderSessionPanel);
    etwSessionPanelLayout_ = new QVBoxLayout(etwSessionPanel_);
    etwSessionPanelLayout_->setContentsMargins(4, 4, 4, 4);
    etwSessionPanelLayout_->setSpacing(6);

    etwSessionControlLayout_ = new QHBoxLayout();
    etwSessionControlLayout_->setContentsMargins(0, 0, 0, 0);
    etwSessionControlLayout_->setSpacing(6);

    etwSessionRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), etwSessionPanel_);
    etwSessionRefreshButton_->setToolTip(QStringLiteral("枚举系统活动 ETW 会话"));
    etwSessionRefreshButton_->setStyleSheet(blueButtonStyle());
    etwSessionRefreshButton_->setFixedWidth(34);

    etwSessionStopButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), etwSessionPanel_);
    etwSessionStopButton_->setToolTip(QStringLiteral("结束选中的 ETW 会话"));
    etwSessionStopButton_->setStyleSheet(blueButtonStyle());
    etwSessionStopButton_->setFixedWidth(34);
    etwSessionStopButton_->setEnabled(false);

    etwSessionStatusLabel_ = new QLabel(QStringLiteral("● 待刷新"), etwSessionPanel_);
    ks::ui::applyStatusRole(etwSessionStatusLabel_, ks::ui::StatusRole::kIdle);

    etwSessionControlLayout_->addWidget(new QLabel(QStringLiteral("ETW会话"), etwSessionPanel_));
    etwSessionControlLayout_->addStretch(1);
    etwSessionControlLayout_->addWidget(etwSessionRefreshButton_);
    etwSessionControlLayout_->addWidget(etwSessionStopButton_);
    etwSessionControlLayout_->addWidget(etwSessionStatusLabel_);
    etwSessionPanelLayout_->addLayout(etwSessionControlLayout_);

    etwSessionTable_ = new ks::ui::VisibleTableWidget(etwSessionPanel_);
    etwSessionTable_->setColumnCount(5);
    etwSessionTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("会话名"),
        QStringLiteral("模式"),
        QStringLiteral("缓冲区"),
        QStringLiteral("丢失事件"),
        QStringLiteral("日志文件")
    });
    etwSessionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    etwSessionTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    etwSessionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    etwSessionTable_->setAlternatingRowColors(true);
    etwSessionTable_->verticalHeader()->setVisible(false);
    etwSessionTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    etwSessionTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    etwSessionTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    etwSessionTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    etwSessionTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    etwSessionTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    etwSessionTable_->setMinimumHeight(180);
    installMonitorTableCopyMenu(etwSessionTable_);
    etwSessionPanelLayout_->addWidget(etwSessionTable_, 1);

    etwProviderSessionLayout->addWidget(etwProviderPanel_, 3);
    etwProviderSessionLayout->addWidget(etwSessionPanel_, 2);
    etwCollapseHostLayout_->addWidget(createIndependentCollapseSection(
        etwCollapseHostWidget_,
        QStringLiteral("ETW Providers / 会话"),
        etwProviderSessionPanel,
        true), 0);

    // Parameter collapse page.
    QWidget* capturePanel = new QWidget(etwCollapseHostWidget_);
    QVBoxLayout* captureLayout = new QVBoxLayout(capturePanel);
    captureLayout->setContentsMargins(4, 4, 4, 4);
    captureLayout->setSpacing(6);

    QFormLayout* formLayout = new QFormLayout();
    formLayout->setContentsMargins(0, 0, 0, 0);
    formLayout->setSpacing(6);

    etwManualProviderEdit_ = new QLineEdit(capturePanel);
    etwManualProviderEdit_->setPlaceholderText(QStringLiteral("可选：手动输入Provider"));
    etwManualProviderEdit_->setStyleSheet(blueInputStyle());

    etwLevelCombo_ = new QComboBox(capturePanel);
    etwLevelCombo_->setStyleSheet(blueInputStyle());
    etwLevelCombo_->addItems(QStringList{
        QStringLiteral("Critical"),
        QStringLiteral("Error"),
        QStringLiteral("Warning"),
        QStringLiteral("Information"),
        QStringLiteral("Verbose")
    });
    etwLevelCombo_->setCurrentIndex(3);

    etwKeywordMaskEdit_ = new QLineEdit(capturePanel);
    etwKeywordMaskEdit_->setStyleSheet(blueInputStyle());
    etwKeywordMaskEdit_->setText(QStringLiteral("0xFFFFFFFFFFFFFFFF"));

    etwBufferSizeSpin_ = new QSpinBox(capturePanel);
    etwBufferSizeSpin_->setRange(64, 4096);
    etwBufferSizeSpin_->setValue(256);
    etwBufferSizeSpin_->setStyleSheet(blueInputStyle());

    etwMinBufferSpin_ = new QSpinBox(capturePanel);
    etwMinBufferSpin_->setRange(2, 128);
    etwMinBufferSpin_->setValue(16);
    etwMinBufferSpin_->setStyleSheet(blueInputStyle());

    etwMaxBufferSpin_ = new QSpinBox(capturePanel);
    etwMaxBufferSpin_->setRange(4, 256);
    etwMaxBufferSpin_->setValue(64);
    etwMaxBufferSpin_->setStyleSheet(blueInputStyle());

    formLayout->addRow(QStringLiteral("手动Provider"), etwManualProviderEdit_);
    formLayout->addRow(QStringLiteral("级别"), etwLevelCombo_);
    formLayout->addRow(QStringLiteral("关键字掩码"), etwKeywordMaskEdit_);
    formLayout->addRow(QStringLiteral("缓冲区大小(KB)"), etwBufferSizeSpin_);
    formLayout->addRow(QStringLiteral("最小缓冲区"), etwMinBufferSpin_);
    formLayout->addRow(QStringLiteral("最大缓冲区"), etwMaxBufferSpin_);

    etwCaptureControlLayout_ = new QHBoxLayout();
    etwCaptureControlLayout_->setContentsMargins(0, 0, 0, 0);
    etwCaptureControlLayout_->setSpacing(6);

    // Move the ETW control button outside the collapsible section (parent changed to m_etwPage) to prevent the collapsible page from becoming too tall.
    etwStartButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), etwPage_);
    etwStartButton_->setToolTip(QStringLiteral("开始监听"));
    etwStartButton_->setStyleSheet(blueButtonStyle());
    etwStartButton_->setFixedWidth(34);

    etwStopButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), etwPage_);
    etwStopButton_->setToolTip(QStringLiteral("停止监听"));
    etwStopButton_->setStyleSheet(blueButtonStyle());
    etwStopButton_->setFixedWidth(34);

    etwPauseButton_ = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), etwPage_);
    etwPauseButton_->setToolTip(QStringLiteral("暂停/继续"));
    etwPauseButton_->setStyleSheet(blueButtonStyle());
    etwPauseButton_->setFixedWidth(34);

    etwExportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), etwPage_);
    etwExportButton_->setToolTip(QStringLiteral("导出TSV"));
    etwExportButton_->setStyleSheet(blueButtonStyle());
    etwExportButton_->setFixedWidth(34);

    etwCaptureStatusLabel_ = new QLabel(QStringLiteral("● 未监听"), etwPage_);
    ks::ui::applyStatusRole(etwCaptureStatusLabel_, ks::ui::StatusRole::kIdle);

    etwCaptureControlLayout_->addWidget(new QLabel(QStringLiteral("ETW控制"), etwPage_));
    etwCaptureControlLayout_->addStretch(1);
    etwCaptureControlLayout_->addWidget(etwStartButton_);
    etwCaptureControlLayout_->addWidget(etwStopButton_);
    etwCaptureControlLayout_->addWidget(etwPauseButton_);
    etwCaptureControlLayout_->addWidget(etwExportButton_);
    etwCaptureControlLayout_->addWidget(etwCaptureStatusLabel_);

    captureLayout->addLayout(formLayout);
    etwCollapseHostLayout_->addWidget(createIndependentCollapseSection(
        etwCollapseHostWidget_,
        QStringLiteral("ETW捕获"),
        capturePanel,
        false), 0);

    initializeEtwFilterPanels();

    // Place the ETW control bar outside the collapsible bar to unify the layout with the WMI operation area.
    etwLayout_->addLayout(etwCaptureControlLayout_, 0);

    // ETW timeline:
    // - Reuse the compact waterfall control from the 'Process-Oriented' page to ensure consistent interaction semantics across both monitoring pages.
    // - The timeline only stores lightweight time points; actual display/hiding is still uniformly executed by the ETW post-filter.
    // - The default full-range selection produces no filtering; a time window is overlaid only after the user drags or scrolls to zoom.
    etwTimelineWidget_ = new ProcessTraceTimelineWidget(etwPage_);
    etwTimelineWidget_->setToolTip(QStringLiteral(
        "ETW 事件瀑布流时间轴：拖动矩形移动时间窗口；拖动左右边调整边界；滚轮向上放大窗口、向下缩小窗口。"));
    etwLayout_->addWidget(etwTimelineWidget_, 0);

    // Result table
    etwEventTable_ = new ks::ui::VisibleTableWidget(etwPage_);
    etwEventTable_->setColumnCount(7);
    etwEventTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间戳(100ns)"),
        QStringLiteral("Provider"),
        QStringLiteral("事件ID"),
        QStringLiteral("事件名称"),
        QStringLiteral("PID/TID"),
        QStringLiteral("事件摘要"),
        QStringLiteral("ActivityId")
    });
    etwEventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    etwEventTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    etwEventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    etwEventTable_->setAlternatingRowColors(true);
    etwEventTable_->setWordWrap(false);
    etwEventTable_->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    etwEventTable_->verticalHeader()->setDefaultSectionSize(22);
    etwEventTable_->verticalHeader()->setMinimumWidth(78);
    etwEventTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    etwEventTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    // Disable ResizeToContents during high-frequency appends: this mode repeatedly scans existing rows to calculate
    // column widths, amplifying layout costs for each insert/setItem when large volumes of ETW events arrive.
    etwEventTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    etwEventTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    etwEventTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    etwEventTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
    etwEventTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Interactive);
    etwEventTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::Stretch);
    etwEventTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::Interactive);
    etwEventTable_->setColumnWidth(0, 190);
    etwEventTable_->setColumnWidth(1, 240);
    etwEventTable_->setColumnWidth(2, 80);
    etwEventTable_->setColumnWidth(3, 190);
    etwEventTable_->setColumnWidth(4, 110);
    etwEventTable_->setColumnWidth(6, 300);

    etwLayout_->addWidget(etwEventTable_, 1);

    etwUiUpdateTimer_ = new QTimer(this);
    etwUiUpdateTimer_->setInterval(50);

    // Rule editing and timeline dragging may trigger dozens of consecutive changes. Only start a single disk scan after the input stabilizes.
    etwArchiveFilterDebounceTimer_ = new QTimer(this);
    etwArchiveFilterDebounceTimer_->setSingleShot(true);
    etwArchiveFilterDebounceTimer_->setInterval(250);
    connect(etwArchiveFilterDebounceTimer_, &QTimer::timeout, this, [this]() {
        rebuildEtwArchiveFilterAsync();
    });
    updateEtwCaptureActionState();
    updateEtwCollapseHeight();

    sideTabWidget_->addTab(etwPage_, QStringLiteral("ETW监控"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, etwPage_, QStringLiteral("monitor.tab.etw"), QStringLiteral("ETW监控"));
}

MonitorDock::EtwSimpleFilterUiState& MonitorDock::etwSimpleFilterUi(const EtwFilterStage stage)
{
    return stage == EtwFilterStage::kPre ? etwPreSimpleFilterUi_ : etwPostSimpleFilterUi_;
}

const MonitorDock::EtwSimpleFilterUiState& MonitorDock::etwSimpleFilterUi(const EtwFilterStage stage) const
{
    return stage == EtwFilterStage::kPre ? etwPreSimpleFilterUi_ : etwPostSimpleFilterUi_;
}

QWidget* MonitorDock::createEtwSimpleFilterPanel(const EtwFilterStage stage, QWidget* parentWidget)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    uiState.panelWidget = new QWidget(parentWidget);
    QVBoxLayout* rootLayout = new QVBoxLayout(uiState.panelWidget);
    rootLayout->setContentsMargins(4, 4, 4, 4);
    rootLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);
    QLabel* titleLabel = new QLabel(
        stage == EtwFilterStage::kPre ? QStringLiteral("简易前置筛选") : QStringLiteral("简易后置筛选"),
        uiState.panelWidget);
    titleLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex));
    uiState.enabledCheck = new QCheckBox(QStringLiteral("启用"), uiState.panelWidget);
    uiState.enabledCheck->setChecked(true);
    uiState.clearButton = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")),
        QStringLiteral("清空"),
        uiState.panelWidget);
    uiState.clearButton->setStyleSheet(blueButtonStyle());
    headerLayout->addWidget(titleLabel);
    headerLayout->addWidget(uiState.enabledCheck);
    headerLayout->addStretch(1);
    headerLayout->addWidget(uiState.clearButton);
    rootLayout->addLayout(headerLayout);

    QLabel* semanticHintLabel = new QLabel(uiState.panelWidget);
    semanticHintLabel->setWordWrap(true);
    semanticHintLabel->setText(stage == EtwFilterStage::kPre
        ? QStringLiteral("前置筛选会主动排除未命中事件；这些事件不会进入全量归档或表格。")
        : QStringLiteral("后置筛选只改变显示结果；完整事件仍保留在磁盘归档中。"));
    semanticHintLabel->setStyleSheet(
        QStringLiteral("color:%1;font-size:12px;").arg(ksword_theme::textSecondaryHex()));
    rootLayout->addWidget(semanticHintLabel);

    QGridLayout* fieldGrid = new QGridLayout();
    fieldGrid->setContentsMargins(0, 0, 0, 0);
    fieldGrid->setHorizontalSpacing(8);
    fieldGrid->setVerticalSpacing(4);
    int fieldIndex = 0;
    const auto kAddTextField = [this, &fieldGrid, &fieldIndex, &uiState](
        const QString& labelText,
        const QString& placeholderText,
        QLineEdit*& editOut) {
        QWidget* cellWidget = new QWidget(uiState.panelWidget);
        QVBoxLayout* cellLayout = new QVBoxLayout(cellWidget);
        cellLayout->setContentsMargins(0, 0, 0, 0);
        cellLayout->setSpacing(2);
        QLabel* label = new QLabel(labelText, cellWidget);
        editOut = new QLineEdit(cellWidget);
        editOut->setPlaceholderText(placeholderText);
        editOut->setStyleSheet(blueInputStyle());
        cellLayout->addWidget(label);
        cellLayout->addWidget(editOut);
        fieldGrid->addWidget(cellWidget, fieldIndex / 2, fieldIndex % 2);
        ++fieldIndex;
    };

    kAddTextField(QStringLiteral("PID"), QStringLiteral("多个PID用逗号或分号分隔"), uiState.pidEdit);
    kAddTextField(QStringLiteral("进程名"), QStringLiteral("不区分大小写，包含匹配"), uiState.processNameEdit);
    kAddTextField(QStringLiteral("文件路径"), QStringLiteral("当前/旧/新路径，允许空格"), uiState.filePathEdit);
    kAddTextField(QStringLiteral("事件ID"), QStringLiteral("多个ID用逗号或分号分隔"), uiState.eventIdEdit);
    kAddTextField(QStringLiteral("事件名"), QStringLiteral("不区分大小写，包含匹配"), uiState.eventNameEdit);
    kAddTextField(QStringLiteral("注册表路径"), QStringLiteral("键路径或值名"), uiState.registryPathEdit);
    kAddTextField(QStringLiteral("网络地址"), QStringLiteral("IPv4、CIDR或地址范围"), uiState.networkAddressEdit);
    kAddTextField(QStringLiteral("网络端口"), QStringLiteral("端口或端口范围"), uiState.networkPortEdit);
    kAddTextField(QStringLiteral("状态"), QStringLiteral("状态码或结果文本"), uiState.statusEdit);
    fieldGrid->setColumnStretch(0, 1);
    fieldGrid->setColumnStretch(1, 1);
    rootLayout->addLayout(fieldGrid);

    QLabel* providerLabel = new QLabel(QStringLiteral("Provider来源"), uiState.panelWidget);
    providerLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(providerLabel);
    QGridLayout* providerGrid = new QGridLayout();
    providerGrid->setContentsMargins(0, 0, 0, 0);
    providerGrid->setHorizontalSpacing(8);
    providerGrid->setVerticalSpacing(2);
    int providerIndex = 0;
    for (const EtwPresetProviderDescriptor& descriptor : etwPresetProviderDescriptorList())
    {
        QCheckBox* checkBox = new QCheckBox(descriptor.providerNameText, uiState.panelWidget);
        checkBox->setToolTip(QStringLiteral("[%1] %2").arg(
            descriptor.categoryText,
            descriptor.providerNameText));
        uiState.providerCheckList.push_back({ descriptor.providerNameText, checkBox });
        providerGrid->addWidget(checkBox, providerIndex / 2, providerIndex % 2);
        ++providerIndex;
    }
    providerGrid->setColumnStretch(0, 1);
    providerGrid->setColumnStretch(1, 1);
    rootLayout->addLayout(providerGrid);
    uiState.customProviderEdit = new QLineEdit(uiState.panelWidget);
    uiState.customProviderEdit->setPlaceholderText(
        QStringLiteral("自定义Provider：名称或GUID，多值用逗号/分号分隔"));
    uiState.customProviderEdit->setStyleSheet(blueInputStyle());
    rootLayout->addWidget(uiState.customProviderEdit);

    QLabel* actionLabel = new QLabel(QStringLiteral("行为"), uiState.panelWidget);
    actionLabel->setStyleSheet(QStringLiteral("font-weight:600;"));
    rootLayout->addWidget(actionLabel);
    QGridLayout* actionGrid = new QGridLayout();
    actionGrid->setContentsMargins(0, 0, 0, 0);
    actionGrid->setHorizontalSpacing(8);
    actionGrid->setVerticalSpacing(2);
    int actionIndex = 0;
    for (const QString& actionText : etwSimpleActionList())
    {
        QCheckBox* checkBox = new QCheckBox(actionText, uiState.panelWidget);
        uiState.actionCheckList.push_back({ actionText, checkBox });
        actionGrid->addWidget(checkBox, actionIndex / 5, actionIndex % 5);
        ++actionIndex;
    }
    for (int column = 0; column < 5; ++column)
    {
        actionGrid->setColumnStretch(column, 1);
    }
    rootLayout->addLayout(actionGrid);
    uiState.customActionEdit = new QLineEdit(uiState.panelWidget);
    uiState.customActionEdit->setPlaceholderText(
        QStringLiteral("自定义行为，多值用逗号/分号分隔"));
    uiState.customActionEdit->setStyleSheet(blueInputStyle());
    rootLayout->addWidget(uiState.customActionEdit);

    uiState.stateLabel = new QLabel(QStringLiteral("简易筛选：无条件"), uiState.panelWidget);
    uiState.stateLabel->setWordWrap(true);
    ks::ui::applyStatusRole(uiState.stateLabel, ks::ui::StatusRole::kIdle);
    rootLayout->addWidget(uiState.stateLabel);

    uiState.applyDebounceTimer = new QTimer(this);
    uiState.applyDebounceTimer->setSingleShot(true);
    uiState.applyDebounceTimer->setInterval(250);
    connect(uiState.applyDebounceTimer, &QTimer::timeout, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(uiState.enabledCheck, &QCheckBox::toggled, this, [this, stage]() {
        applyEtwFilterRules(stage);
    });
    connect(uiState.clearButton, &QPushButton::clicked, this, [this, stage]() {
        clearEtwSimpleFilter(stage);
    });

    const std::initializer_list<QLineEdit*> kEditList{
        uiState.pidEdit,
        uiState.processNameEdit,
        uiState.filePathEdit,
        uiState.eventIdEdit,
        uiState.eventNameEdit,
        uiState.registryPathEdit,
        uiState.networkAddressEdit,
        uiState.networkPortEdit,
        uiState.statusEdit,
        uiState.customProviderEdit,
        uiState.customActionEdit
    };
    for (QLineEdit* edit : kEditList)
    {
        connect(edit, &QLineEdit::textChanged, this, [this, stage](const QString&) {
            scheduleEtwSimpleFilterApply(stage);
        });
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
    {
        connect(checkState.checkBox, &QCheckBox::toggled, this, [this, stage]() {
            applyEtwFilterRules(stage);
        });
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
    {
        connect(checkState.checkBox, &QCheckBox::toggled, this, [this, stage]() {
            applyEtwFilterRules(stage);
        });
    }
    return uiState.panelWidget;
}

void MonitorDock::scheduleEtwSimpleFilterApply(const EtwFilterStage stage)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    if (uiState.applyDebounceTimer != nullptr)
    {
        uiState.applyDebounceTimer->start();
    }
}

void MonitorDock::clearEtwSimpleFilter(const EtwFilterStage stage, const bool applyRules)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    if (uiState.applyDebounceTimer != nullptr)
    {
        uiState.applyDebounceTimer->stop();
    }
    const std::initializer_list<QLineEdit*> kEditList{
        uiState.pidEdit,
        uiState.processNameEdit,
        uiState.filePathEdit,
        uiState.eventIdEdit,
        uiState.eventNameEdit,
        uiState.registryPathEdit,
        uiState.networkAddressEdit,
        uiState.networkPortEdit,
        uiState.statusEdit,
        uiState.customProviderEdit,
        uiState.customActionEdit
    };
    for (QLineEdit* edit : kEditList)
    {
        if (edit != nullptr)
        {
            const QSignalBlocker kBlocker(edit);
            edit->clear();
        }
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.providerCheckList)
    {
        if (checkState.checkBox != nullptr)
        {
            const QSignalBlocker kBlocker(checkState.checkBox);
            checkState.checkBox->setChecked(false);
        }
    }
    for (const EtwSimpleFilterCheckUiState& checkState : uiState.actionCheckList)
    {
        if (checkState.checkBox != nullptr)
        {
            const QSignalBlocker kBlocker(checkState.checkBox);
            checkState.checkBox->setChecked(false);
        }
    }
    if (applyRules)
    {
        applyEtwFilterRules(stage);
    }
}

void MonitorDock::updateEtwSimpleFilterStateLabel(const EtwFilterStage stage)
{
    EtwSimpleFilterUiState& uiState = etwSimpleFilterUi(stage);
    if (uiState.stateLabel == nullptr)
    {
        return;
    }
    const EtwSimpleFilterCompiled& compiledFilter = stage == EtwFilterStage::kPre
        ? etwPreSimpleFilterCompiled_
        : etwPostSimpleFilterCompiled_;
    if (!compiledFilter.enabled)
    {
        uiState.stateLabel->setText(QStringLiteral("简易筛选：已停用"));
        ks::ui::applyStatusRole(uiState.stateLabel, ks::ui::StatusRole::kIdle);
        return;
    }
    int conditionCount = 0;
    conditionCount += !compiledFilter.pidRangeList.empty();
    conditionCount += !compiledFilter.eventIdRangeList.empty();
    conditionCount += !compiledFilter.networkAddressRangeList.empty();
    conditionCount += !compiledFilter.networkPortRangeList.empty();
    conditionCount += !compiledFilter.providerPresetNameList.isEmpty()
        || !compiledFilter.providerCustomTokenList.isEmpty();
    conditionCount += !compiledFilter.actionPresetList.isEmpty()
        || !compiledFilter.actionCustomTokenList.isEmpty();
    conditionCount += !compiledFilter.processNameTokenList.isEmpty();
    conditionCount += !compiledFilter.filePathTokenList.isEmpty();
    conditionCount += !compiledFilter.eventNameTokenList.isEmpty();
    conditionCount += !compiledFilter.registryPathTokenList.isEmpty();
    conditionCount += !compiledFilter.statusTokenList.isEmpty();
    if (conditionCount == 0)
    {
        uiState.stateLabel->setText(stage == EtwFilterStage::kPre
            ? QStringLiteral("简易筛选：无条件（全部捕获）")
            : QStringLiteral("简易筛选：无条件（全部显示）"));
        ks::ui::applyStatusRole(uiState.stateLabel, ks::ui::StatusRole::kIdle);
        return;
    }
    uiState.stateLabel->setText(QStringLiteral("简易筛选：已应用 %1 项条件").arg(conditionCount));
    ks::ui::applyStatusRole(uiState.stateLabel, ks::ui::StatusRole::kInfo);
}

void MonitorDock::initializeEtwFilterPanels()
{
    QWidget* outerFilterPanel = new QWidget(etwCollapseHostWidget_);
    QVBoxLayout* outerFilterLayout = new QVBoxLayout(outerFilterPanel);
    outerFilterLayout->setContentsMargins(4, 4, 4, 4);
    outerFilterLayout->setSpacing(6);

    QWidget* simpleFilterPanel = new QWidget(outerFilterPanel);
    QHBoxLayout* simpleFilterLayout = new QHBoxLayout(simpleFilterPanel);
    simpleFilterLayout->setContentsMargins(0, 0, 0, 0);
    simpleFilterLayout->setSpacing(6);
    simpleFilterLayout->addWidget(createEtwSimpleFilterPanel(EtwFilterStage::kPre, simpleFilterPanel), 1);
    simpleFilterLayout->addWidget(createEtwSimpleFilterPanel(EtwFilterStage::kPost, simpleFilterPanel), 1);
    outerFilterLayout->addWidget(simpleFilterPanel);

    QWidget* etwFilterPanel = new QWidget(outerFilterPanel);
    QHBoxLayout* etwFilterPanelLayout = new QHBoxLayout(etwFilterPanel);
    etwFilterPanelLayout->setContentsMargins(4, 4, 4, 4);
    etwFilterPanelLayout->setSpacing(6);

    const auto kInitStagePanel = [this](
        const EtwFilterStage stage,
        QWidget*& panelOut,
        QVBoxLayout*& panelLayoutOut,
        QPushButton*& addGroupButtonOut,
        QPushButton*& applyButtonOut,
        QPushButton*& clearButtonOut,
        QPushButton*& loadDefaultButtonOut,
        QPushButton*& saveDefaultButtonOut,
        QPushButton*& importButtonOut,
        QPushButton*& exportButtonOut,
        QLabel*& stateLabelOut,
        QScrollArea*& scrollAreaOut,
        QWidget*& hostWidgetOut,
        QVBoxLayout*& hostLayoutOut)
        {
            panelOut = new QWidget();
            panelLayoutOut = new QVBoxLayout(panelOut);
            panelLayoutOut->setContentsMargins(4, 4, 4, 4);
            panelLayoutOut->setSpacing(6);

            QLabel* stageTitleLabel = new QLabel(
                stage == EtwFilterStage::kPre ? QStringLiteral("ETW前置筛选") : QStringLiteral("ETW后置筛选"),
                panelOut);
            stageTitleLabel->setStyleSheet(
                QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::kPrimaryBlueHex));
            panelLayoutOut->addWidget(stageTitleLabel, 0);

            QLabel* semanticHintLabel = new QLabel(panelOut);
            semanticHintLabel->setWordWrap(true);
            semanticHintLabel->setText(stage == EtwFilterStage::kPre
                ? QStringLiteral("前置筛选 = 不捕获：未命中事件不会入队、不会进入表格、不会参与导出。")
                : QStringLiteral("后置筛选 = 仅改变显示：完整事件仍保留在磁盘归档中，可随时恢复显示。"));
            semanticHintLabel->setStyleSheet(
                QStringLiteral("color:%1;font-size:12px;").arg(ksword_theme::textSecondaryHex()));
            panelLayoutOut->addWidget(semanticHintLabel, 0);

            QHBoxLayout* actionLayout = new QHBoxLayout();
            actionLayout->setContentsMargins(0, 0, 0, 0);
            actionLayout->setSpacing(6);

            addGroupButtonOut = new QPushButton(QIcon(":/Icon/plus.svg"), QStringLiteral("新增规则组"), panelOut);
            addGroupButtonOut->setStyleSheet(blueButtonStyle());
            applyButtonOut = new QPushButton(QIcon(":/Icon/log_track.svg"), QStringLiteral("应用"), panelOut);
            applyButtonOut->setStyleSheet(blueButtonStyle());
            clearButtonOut = new QPushButton(QIcon(":/Icon/log_clear.svg"), QStringLiteral("清空"), panelOut);
            clearButtonOut->setStyleSheet(blueButtonStyle());
            loadDefaultButtonOut = new QPushButton(QIcon(":/Icon/codeeditor_open.svg"), QStringLiteral("加载默认"), panelOut);
            loadDefaultButtonOut->setStyleSheet(blueButtonStyle());
            saveDefaultButtonOut = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("保存默认"), panelOut);
            saveDefaultButtonOut->setStyleSheet(blueButtonStyle());
            importButtonOut = new QPushButton(QIcon(":/Icon/codeeditor_open.svg"), QStringLiteral("导入"), panelOut);
            importButtonOut->setStyleSheet(blueButtonStyle());
            exportButtonOut = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("导出"), panelOut);
            exportButtonOut->setStyleSheet(blueButtonStyle());

            actionLayout->addWidget(addGroupButtonOut);
            actionLayout->addWidget(applyButtonOut);
            actionLayout->addWidget(clearButtonOut);
            actionLayout->addWidget(loadDefaultButtonOut);
            actionLayout->addWidget(saveDefaultButtonOut);
            actionLayout->addWidget(importButtonOut);
            actionLayout->addWidget(exportButtonOut);
            actionLayout->addStretch(1);
            panelLayoutOut->addLayout(actionLayout, 0);

            stateLabelOut = new QLabel(QStringLiteral("当前规则：无"), panelOut);
            ks::ui::applyStatusRole(stateLabelOut, ks::ui::StatusRole::kIdle);
            stateLabelOut->setWordWrap(true);
            panelLayoutOut->addWidget(stateLabelOut, 0);

            // The filter area no longer uses internal scrolling to prevent folded page content from being compressed twice.
            scrollAreaOut = nullptr;
            hostWidgetOut = new QWidget(panelOut);
            hostLayoutOut = new QVBoxLayout(hostWidgetOut);
            hostLayoutOut->setContentsMargins(0, 0, 0, 0);
            hostLayoutOut->setSpacing(6);
            panelLayoutOut->addWidget(hostWidgetOut, 0);
        };

    kInitStagePanel(
        EtwFilterStage::kPre,
        etwPreFilterPanel_,
        etwPreFilterPanelLayout_,
        etwPreFilterAddGroupButton_,
        etwPreFilterApplyButton_,
        etwPreFilterClearButton_,
        etwPreFilterLoadDefaultButton_,
        etwPreFilterSaveDefaultButton_,
        etwPreFilterImportButton_,
        etwPreFilterExportButton_,
        etwPreFilterStateLabel_,
        etwPreFilterScrollArea_,
        etwPreFilterGroupHostWidget_,
        etwPreFilterGroupHostLayout_);

    kInitStagePanel(
        EtwFilterStage::kPost,
        etwPostFilterPanel_,
        etwPostFilterPanelLayout_,
        etwPostFilterAddGroupButton_,
        etwPostFilterApplyButton_,
        etwPostFilterClearButton_,
        etwPostFilterLoadDefaultButton_,
        etwPostFilterSaveDefaultButton_,
        etwPostFilterImportButton_,
        etwPostFilterExportButton_,
        etwPostFilterStateLabel_,
        etwPostFilterScrollArea_,
        etwPostFilterGroupHostWidget_,
        etwPostFilterGroupHostLayout_);

    etwFilterPanelLayout->addWidget(etwPreFilterPanel_, 1);
    etwFilterPanelLayout->addWidget(etwPostFilterPanel_, 1);
    outerFilterLayout->addWidget(createIndependentCollapseSection(
        outerFilterPanel,
        QStringLiteral("ETW筛选器详细配置"),
        etwFilterPanel,
        false));
    if (etwCollapseHostLayout_ != nullptr)
    {
        etwCollapseHostLayout_->addWidget(createIndependentCollapseSection(
            etwCollapseHostWidget_,
            QStringLiteral("ETW筛选器"),
            outerFilterPanel,
            false), 0);
    }

    addEtwFilterRuleGroup(EtwFilterStage::kPre);
    addEtwFilterRuleGroup(EtwFilterStage::kPost);
    // Configuration must be loaded before applying it. The old flow would save empty rules at startup, overwriting the user's default configuration.
    loadEtwFilterConfigFromDefaultPath(false);
    updateEtwCollapseHeight();
}

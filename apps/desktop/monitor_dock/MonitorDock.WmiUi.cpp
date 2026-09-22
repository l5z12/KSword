#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::initializeWmiTab()
{
    wmiPage_ = new QWidget(sideTabWidget_);
    wmiLayout_ = new QVBoxLayout(wmiPage_);
    wmiLayout_->setContentsMargins(3, 3, 3, 3);
    wmiLayout_->setSpacing(4);

    // WMI top configuration area changed to an independent collapsible section:
    // - Left side: Provider enumeration and filtering;
    // - Right side: subscription class selection, WHERE template, and subscription control.
    // - Collapse sections are not mutually exclusive; allow users to collapse all configuration areas simultaneously.
    wmiTopConfigPanel_ = new QWidget(wmiPage_);
    wmiTopConfigLayout_ = new QHBoxLayout(wmiTopConfigPanel_);
    wmiTopConfigLayout_->setContentsMargins(0, 0, 0, 0);
    wmiTopConfigLayout_->setSpacing(4);
    wmiTopConfigPanel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

    // Provider left panel.
    wmiProviderPanel_ = new QWidget(wmiTopConfigPanel_);
    wmiProviderPanelLayout_ = new QVBoxLayout(wmiProviderPanel_);
    wmiProviderPanelLayout_->setContentsMargins(3, 3, 3, 3);
    wmiProviderPanelLayout_->setSpacing(4);

    wmiProviderControlLayout_ = new QHBoxLayout();
    wmiProviderControlLayout_->setContentsMargins(0, 0, 0, 0);
    wmiProviderControlLayout_->setSpacing(4);

    wmiProviderFilterEdit_ = new QLineEdit(wmiProviderPanel_);
    wmiProviderFilterEdit_->setPlaceholderText(QStringLiteral("按Provider或命名空间过滤"));
    wmiProviderFilterEdit_->setStyleSheet(blueInputStyle());

    wmiProviderRefreshButton_ = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), wmiProviderPanel_);
    wmiProviderRefreshButton_->setToolTip(QStringLiteral("刷新WMI Provider"));
    wmiProviderRefreshButton_->setStyleSheet(blueButtonStyle());
    wmiProviderRefreshButton_->setFixedWidth(32);

    wmiProviderStatusLabel_ = new QLabel(QStringLiteral("● 待刷新"), wmiProviderPanel_);
    ks::ui::applyStatusRole(wmiProviderStatusLabel_, ks::ui::StatusRole::kIdle);

    wmiProviderControlLayout_->addWidget(wmiProviderFilterEdit_, 1);
    wmiProviderControlLayout_->addWidget(wmiProviderRefreshButton_);
    wmiProviderControlLayout_->addWidget(wmiProviderStatusLabel_);

    wmiProviderModel_ = new QStandardItemModel(0, 5, wmiProviderPanel_);
    wmiProviderModel_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("Provider名称"),
        QStringLiteral("Namespace"),
        QStringLiteral("CLSID"),
        QStringLiteral("EventClass数量"),
        QStringLiteral("状态")
    });

    wmiProviderProxyModel_ = new QSortFilterProxyModel(wmiProviderPanel_);
    wmiProviderProxyModel_->setSourceModel(wmiProviderModel_);
    wmiProviderProxyModel_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    wmiProviderProxyModel_->setFilterKeyColumn(-1);

    wmiProviderTableView_ = new ks::ui::TableActionTableView(wmiProviderPanel_);
    wmiProviderTableView_->setModel(wmiProviderProxyModel_);
    wmiProviderTableView_->setSortingEnabled(true);
    wmiProviderTableView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    wmiProviderTableView_->setSelectionMode(QAbstractItemView::SingleSelection);
    wmiProviderTableView_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    wmiProviderTableView_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    wmiProviderTableView_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    wmiProviderTableView_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    wmiProviderTableView_->verticalHeader()->setDefaultSectionSize(20);
    installMonitorTableViewCopyMenu(wmiProviderTableView_);
    // Constrain the Provider list height to be narrow, freeing up more visible space for listening results.
    wmiProviderTableView_->setMinimumHeight(120);
    wmiProviderTableView_->setMaximumHeight(160);

    wmiProviderPanelLayout_->addLayout(wmiProviderControlLayout_);
    wmiProviderPanelLayout_->addWidget(wmiProviderTableView_, 1);
    wmiTopConfigLayout_->addWidget(createIndependentCollapseSection(
        wmiTopConfigPanel_,
        QStringLiteral("WMI Providers"),
        wmiProviderPanel_,
        true), 1);

    // Subscribe right panel.
    wmiSubscribePanel_ = new QWidget(wmiTopConfigPanel_);
    wmiSubscribeLayout_ = new QVBoxLayout(wmiSubscribePanel_);
    wmiSubscribeLayout_->setContentsMargins(3, 3, 3, 3);
    wmiSubscribeLayout_->setSpacing(4);

    wmiEventClassControlLayout_ = new QHBoxLayout();
    wmiEventClassControlLayout_->setContentsMargins(0, 0, 0, 0);
    wmiEventClassControlLayout_->setSpacing(4);

    // These three are 'selection aids' rather than flow controls: Previously, ▶/⏸ would look identical to the 'Start Subscription/Pause
    // Subscription' buttons on the same panel, causing users to accidentally start a subscription when intending to select all.
    // Keep class icons reserved for actual flow control; use short text here for unambiguous semantics.
    wmiSelectAllClassesButton_ = new QPushButton(QStringLiteral("全选"), wmiSubscribePanel_);
    wmiSelectAllClassesButton_->setToolTip(QStringLiteral("全选事件类"));
    wmiSelectAllClassesButton_->setStyleSheet(blueButtonStyle());

    wmiSelectNoneClassesButton_ = new QPushButton(QStringLiteral("全不选"), wmiSubscribePanel_);
    wmiSelectNoneClassesButton_->setToolTip(QStringLiteral("全不选事件类"));
    wmiSelectNoneClassesButton_->setStyleSheet(blueButtonStyle());

    wmiSelectWin32ClassesButton_ = new QPushButton(
        QIcon(":/Icon/filter_funnel.svg"),
        QStringLiteral("仅 Win32"),
        wmiSubscribePanel_);
    wmiSelectWin32ClassesButton_->setToolTip(QStringLiteral("仅选择Win32_*"));
    wmiSelectWin32ClassesButton_->setStyleSheet(blueButtonStyle());

    wmiEventClassControlLayout_->addWidget(new QLabel(QStringLiteral("事件类"), wmiSubscribePanel_));
    wmiEventClassControlLayout_->addStretch(1);
    wmiEventClassControlLayout_->addWidget(wmiSelectAllClassesButton_);
    wmiEventClassControlLayout_->addWidget(wmiSelectNoneClassesButton_);
    wmiEventClassControlLayout_->addWidget(wmiSelectWin32ClassesButton_);

    wmiEventClassTable_ = new ks::ui::VisibleTableWidget(wmiSubscribePanel_);
    wmiEventClassTable_->setColumnCount(3);
    wmiEventClassTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("启用"),
        QStringLiteral("事件类"),
        QStringLiteral("匹配")
    });
    wmiEventClassTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    wmiEventClassTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    wmiEventClassTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // Disable the corner button to prevent the default white block in the upper-left corner.
    wmiEventClassTable_->setCornerButtonEnabled(false);
    // Switch the right-side event class table to a headerless compact mode to reduce height usage and increase visible rows.
    wmiEventClassTable_->horizontalHeader()->setVisible(false);
    wmiEventClassTable_->verticalHeader()->setVisible(false);
    wmiEventClassTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    wmiEventClassTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    wmiEventClassTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    wmiEventClassTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    wmiEventClassTable_->verticalHeader()->setDefaultSectionSize(20);
    installMonitorTableCopyMenu(wmiEventClassTable_);
    // Note: The event class table is initially set to a collapsible size policy; the specific height is dynamically calculated by updateWmiSubscribePanelCompactLayout.
    wmiEventClassTable_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    QHBoxLayout* whereLayout = new QHBoxLayout();
    whereLayout->setContentsMargins(0, 0, 0, 0);
    whereLayout->setSpacing(4);
    whereLayout->addWidget(new QLabel(QStringLiteral("WHERE模板"), wmiSubscribePanel_));

    wmiWhereTemplateCombo_ = new QComboBox(wmiSubscribePanel_);
    wmiWhereTemplateCombo_->setStyleSheet(blueInputStyle());
    wmiWhereTemplateCombo_->addItem(QStringLiteral("空模板"), QString());
    wmiWhereTemplateCombo_->addItem(QStringLiteral("powershell"), QStringLiteral("TargetInstance.Name LIKE '%powershell%'"));
    wmiWhereTemplateCombo_->addItem(QStringLiteral("PID>1000"), QStringLiteral("TargetInstance.ProcessId > 1000"));
    wmiWhereTemplateCombo_->addItem(QStringLiteral("Session=0"), QStringLiteral("TargetInstance.SessionId = 0"));
    whereLayout->addWidget(wmiWhereTemplateCombo_, 1);

    wmiWhereEditor_ = new QPlainTextEdit(wmiSubscribePanel_);
    wmiWhereEditor_->setPlaceholderText(QStringLiteral("可选：输入WQL WHERE子句"));
    // Changed WHERE clause to single-line input for better UX, reducing the height of the right-side subscription area and avoiding multi-line placeholders.
    wmiWhereEditor_->setMaximumBlockCount(1);
    wmiWhereEditor_->setLineWrapMode(QPlainTextEdit::NoWrap);
    wmiWhereEditor_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    wmiWhereEditor_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    wmiWhereEditor_->setStyleSheet(blueInputStyle());
    // Keep single-line input and compress height to leave more visible rows for the class list and result table.
    wmiWhereEditor_->setFixedHeight(24);

    wmiSubscribeControlLayout_ = new QHBoxLayout();
    wmiSubscribeControlLayout_->setContentsMargins(0, 0, 0, 0);
    wmiSubscribeControlLayout_->setSpacing(4);

    // Subscription controls remain within the right panel, forming an integrated 'configuration + control' zone to reduce vertical redundancy.
    wmiStartSubscribeButton_ = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), wmiSubscribePanel_);
    wmiStartSubscribeButton_->setToolTip(QStringLiteral("开始订阅"));
    wmiStartSubscribeButton_->setStyleSheet(blueButtonStyle());
    wmiStartSubscribeButton_->setFixedWidth(32);

    wmiStopSubscribeButton_ = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), wmiSubscribePanel_);
    wmiStopSubscribeButton_->setToolTip(QStringLiteral("停止订阅"));
    wmiStopSubscribeButton_->setStyleSheet(blueButtonStyle());
    wmiStopSubscribeButton_->setFixedWidth(32);

    wmiPauseSubscribeButton_ = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), wmiSubscribePanel_);
    wmiPauseSubscribeButton_->setToolTip(QStringLiteral("暂停/继续订阅"));
    wmiPauseSubscribeButton_->setStyleSheet(blueButtonStyle());
    wmiPauseSubscribeButton_->setFixedWidth(32);

    wmiExportButton_ = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), wmiSubscribePanel_);
    wmiExportButton_->setToolTip(QStringLiteral("导出当前WMI结果到文件"));
    wmiExportButton_->setStyleSheet(blueButtonStyle());
    wmiExportButton_->setFixedWidth(32);

    wmiSubscribeStatusLabel_ = new QLabel(QStringLiteral("● 未订阅"), wmiSubscribePanel_);
    ks::ui::applyStatusRole(wmiSubscribeStatusLabel_, ks::ui::StatusRole::kIdle);

    wmiSubscribeControlLayout_->addWidget(new QLabel(QStringLiteral("WMI订阅控制"), wmiSubscribePanel_));
    wmiSubscribeControlLayout_->addStretch(1);
    wmiSubscribeControlLayout_->addWidget(wmiStartSubscribeButton_);
    wmiSubscribeControlLayout_->addWidget(wmiStopSubscribeButton_);
    wmiSubscribeControlLayout_->addWidget(wmiPauseSubscribeButton_);
    wmiSubscribeControlLayout_->addWidget(wmiExportButton_);
    wmiSubscribeControlLayout_->addWidget(wmiSubscribeStatusLabel_);

    wmiSubscribeLayout_->addLayout(wmiEventClassControlLayout_);
    wmiSubscribeLayout_->addWidget(wmiEventClassTable_, 1);
    wmiSubscribeLayout_->addLayout(whereLayout);
    wmiSubscribeLayout_->addWidget(wmiWhereEditor_, 0);
    wmiSubscribeLayout_->addLayout(wmiSubscribeControlLayout_, 0);
    // On initialization, collapse the event class list to 'compact height' first to prevent unnecessary scrollbars in the first frame.
    updateWmiSubscribePanelCompactLayout();

    wmiTopConfigLayout_->addWidget(createIndependentCollapseSection(
        wmiTopConfigPanel_,
        QStringLiteral("WMI订阅配置"),
        wmiSubscribePanel_,
        true), 1);

    // The two top configuration blocks each have their own collapsible headers and do not exclude each other; both can be collapsed simultaneously.
    wmiLayout_->addWidget(wmiTopConfigPanel_, 0);

    // Result table
    wmiEventTable_ = new ks::ui::VisibleTableWidget(wmiPage_);
    wmiEventTable_->setColumnCount(5);
    wmiEventTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间戳(ms)"),
        QStringLiteral("事件来源"),
        QStringLiteral("事件类"),
        QStringLiteral("PID/进程"),
        QStringLiteral("事件详情")
    });
    wmiEventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    wmiEventTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    wmiEventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    wmiEventTable_->setAlternatingRowColors(true);
    wmiEventTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    wmiEventTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    wmiEventTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    wmiEventTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    wmiEventTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    wmiEventTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    wmiEventTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);

    // Result filter bar: Provides full-field/field-specific/regex/case-sensitive/reverse matching and bottom-scroll control.
    QWidget* wmiFilterWidget = new QWidget(wmiPage_);
    QVBoxLayout* wmiFilterLayout = new QVBoxLayout(wmiFilterWidget);
    wmiFilterLayout->setContentsMargins(0, 0, 0, 0);
    wmiFilterLayout->setSpacing(4);

    QHBoxLayout* wmiFilterTopRow = new QHBoxLayout();
    wmiFilterTopRow->setContentsMargins(0, 0, 0, 0);
    wmiFilterTopRow->setSpacing(6);
    wmiEventGlobalFilterEdit_ = new QLineEdit(wmiFilterWidget);
    wmiEventGlobalFilterEdit_->setPlaceholderText(QStringLiteral("全字段筛选（时间/来源/类/PID/详情）"));
    wmiEventGlobalFilterEdit_->setStyleSheet(blueInputStyle());
    wmiEventProviderFilterEdit_ = new QLineEdit(wmiFilterWidget);
    wmiEventProviderFilterEdit_->setPlaceholderText(QStringLiteral("来源筛选"));
    wmiEventProviderFilterEdit_->setStyleSheet(blueInputStyle());
    wmiEventClassFilterEdit_ = new QLineEdit(wmiFilterWidget);
    wmiEventClassFilterEdit_->setPlaceholderText(QStringLiteral("事件类筛选"));
    wmiEventClassFilterEdit_->setStyleSheet(blueInputStyle());
    wmiFilterTopRow->addWidget(new QLabel(QStringLiteral("筛选"), wmiFilterWidget));
    wmiFilterTopRow->addWidget(wmiEventGlobalFilterEdit_, 2);
    wmiFilterTopRow->addWidget(wmiEventProviderFilterEdit_, 1);
    wmiFilterTopRow->addWidget(wmiEventClassFilterEdit_, 1);

    QHBoxLayout* wmiFilterBottomRow = new QHBoxLayout();
    wmiFilterBottomRow->setContentsMargins(0, 0, 0, 0);
    wmiFilterBottomRow->setSpacing(6);
    wmiEventPidFilterEdit_ = new QLineEdit(wmiFilterWidget);
    wmiEventPidFilterEdit_->setPlaceholderText(QStringLiteral("PID/进程筛选"));
    wmiEventPidFilterEdit_->setStyleSheet(blueInputStyle());
    wmiEventDetailFilterEdit_ = new QLineEdit(wmiFilterWidget);
    wmiEventDetailFilterEdit_->setPlaceholderText(QStringLiteral("详情筛选"));
    wmiEventDetailFilterEdit_->setStyleSheet(blueInputStyle());
    wmiEventRegexCheck_ = new QCheckBox(QStringLiteral("正则"), wmiFilterWidget);
    wmiEventCaseCheck_ = new QCheckBox(QStringLiteral("区分大小写"), wmiFilterWidget);
    wmiEventInvertCheck_ = new QCheckBox(QStringLiteral("反向筛选"), wmiFilterWidget);
    wmiEventKeepBottomCheck_ = new QCheckBox(QStringLiteral("保持表格在底部"), wmiFilterWidget);
    wmiEventKeepBottomCheck_->setChecked(true);
    wmiEventFilterClearButton_ = new QPushButton(QIcon(":/Icon/log_clear.svg"), QString(), wmiFilterWidget);
    wmiEventFilterClearButton_->setStyleSheet(blueButtonStyle());
    wmiEventFilterClearButton_->setToolTip(QStringLiteral("清空所有WMI筛选条件"));
    wmiEventFilterClearButton_->setFixedWidth(34);
    wmiEventFilterStatusLabel_ = new QLabel(QStringLiteral("可见: 0 / 0"), wmiFilterWidget);
    wmiEventFilterStatusLabel_->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));

    wmiFilterBottomRow->addWidget(wmiEventPidFilterEdit_, 1);
    wmiFilterBottomRow->addWidget(wmiEventDetailFilterEdit_, 2);
    wmiFilterBottomRow->addWidget(wmiEventRegexCheck_, 0);
    wmiFilterBottomRow->addWidget(wmiEventCaseCheck_, 0);
    wmiFilterBottomRow->addWidget(wmiEventInvertCheck_, 0);
    wmiFilterBottomRow->addWidget(wmiEventKeepBottomCheck_, 0);
    wmiFilterBottomRow->addWidget(wmiEventFilterClearButton_, 0);
    wmiFilterBottomRow->addWidget(wmiEventFilterStatusLabel_, 0);

    wmiFilterLayout->addLayout(wmiFilterTopRow);
    wmiFilterLayout->addLayout(wmiFilterBottomRow);

    wmiLayout_->addWidget(wmiFilterWidget, 0);
    wmiLayout_->addWidget(wmiEventTable_, 1);
    // Adjusts the vertical proportion of the WMI page:
    // - Keep top left and right configuration areas compact.
    // - The event results table takes priority for remaining space.
    wmiLayout_->setStretch(0, 0);
    wmiLayout_->setStretch(1, 0);
    wmiLayout_->setStretch(2, 1);
    sideTabWidget_->addTab(wmiPage_, QStringLiteral("WMI"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, wmiPage_, QStringLiteral("monitor.tab.wmi"), QStringLiteral("WMI"));
}

void MonitorDock::updateWmiSubscribePanelCompactLayout()
{
    if (wmiEventClassTable_ == nullptr)
    {
        return;
    }

    // fallbackVisibleRowCount usage: Pre-allocates a few rows before event classes are loaded to keep the right area compact.
    const int kFallbackVisibleRowCount = 2;
    // maxVisibleRowCount purpose: Limit the event class table height to ensure the WHERE template area remains visible below the table.
    const int kMaxVisibleRowCount = 4;
    // currentRowCount: Records the total number of rows in the current event class table, serving as input for visible height calculation.
    const int kCurrentRowCount = wmiEventClassTable_->rowCount();
    // Purpose of visibleRowCount: Clamps the visible row count within the [fallbackVisibleRowCount, maxVisibleRowCount] range.
    const int kVisibleRowCount = std::clamp(
        kCurrentRowCount > 0 ? kCurrentRowCount : kFallbackVisibleRowCount,
        kFallbackVisibleRowCount,
        kMaxVisibleRowCount);

    // headerHeight usage: record the event class header height; if the header is empty, use the default value to avoid a height of 0.
    int headerHeight = 0;
    QHeaderView* headerView = wmiEventClassTable_->horizontalHeader();
    if (headerView != nullptr && !headerView->isHidden())
    {
        headerHeight = std::max(16, headerView->height());
    }

    // rowHeight usage: Records the default single-row height, used in estimating total table height.
    int rowHeight = 20;
    QHeaderView* verticalHeader = wmiEventClassTable_->verticalHeader();
    if (verticalHeader != nullptr)
    {
        rowHeight = std::max(16, verticalHeader->defaultSectionSize());
    }

    // framePixels usage: Compensates for pixel space occupied by table borders to prevent the bottom row from being clipped.
    const int kFramePixels = wmiEventClassTable_->frameWidth() * 2;
    // safetyPadding purpose: Extra whitespace to absorb height fluctuations under different system styles.
    const int kSafetyPadding = 4;
    // tableTargetHeight usage: The compact height written back to the event class table.
    const int kTableTargetHeight =
        headerHeight + (kVisibleRowCount * rowHeight) + kFramePixels + kSafetyPadding;
    wmiEventClassTable_->setMinimumHeight(kTableTargetHeight);
    wmiEventClassTable_->setMaximumHeight(kTableTargetHeight);
}

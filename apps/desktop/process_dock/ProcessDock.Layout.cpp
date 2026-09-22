#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::refreshThemeVisuals()
{
    // Rebuild only the current table's visible layer without triggering new background enumeration tasks.
    // Purpose: Immediately refresh the theme highlight color for the 'Add/Exit' row after switching between light and dark themes.
    applyBlueComboBoxRuntimeStyle(strategyCombo_);
    applyBlueComboBoxRuntimeStyle(viewModeCombo_);
    updateThreadColumnPresetButtons();
    rebuildTable();
    rebuildThreadTable();
}

void ProcessDock::initializeUi()
{
    // The root layout contains only the top tab control.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(0, 0, 0, 0);
    rootLayout_->setSpacing(0);

    sideTabWidget_ = new QTabWidget(this);
    sideTabWidget_->setTabPosition(QTabWidget::North);
    sideTabWidget_->setDocumentMode(true);
    sideTabWidget_->setIconSize(kSideTabIconSize);

    // The top tabs use content-adaptive width to avoid truncation caused by fixed width under different font sizes or languages.
    // The tab font size is not set in the local QSS; it uniformly inherits the default Qt application font size.
    if (sideTabWidget_->tabBar() != nullptr)
    {
        sideTabWidget_->tabBar()->setExpanding(false);
        sideTabWidget_->tabBar()->setUsesScrollButtons(true);
        sideTabWidget_->tabBar()->setStyleSheet(QStringLiteral(
            "QTabBar{background:transparent;border:none;}"
            "QTabBar::tab{min-height:%1px;padding:3px 12px;margin:0px;border:none;border-radius:0px;}"
            "QTabBar::tab:selected{background-color:%2;color:%5;font-weight:700;}"
            "QTabBar::tab:hover:!selected{background-color:%3;color:%4;}" )
            .arg(kProcessTabMinHeightPx)
            .arg(ksword_theme::kPrimaryBlueHex)
            // No blue-series dynamic roles are available for the hover background color, so fall back to the neutral
            // alternate-base to ensure no residual light blue squares from the old theme remain during light/dark mode switching.
            .arg(ksword_theme::surfaceAltHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(QStringLiteral("palette(highlighted-text)")));
    }

    // The "Process List" page is the core page of this module.
    processListPage_ = new QWidget(this);
    processPageLayout_ = new QVBoxLayout(processListPage_);
    processPageLayout_->setContentsMargins(6, 6, 6, 6);
    processPageLayout_->setSpacing(6);

    // initialize the top control bar and bottom table.
    initializeTopControls();
    initializeProcessActivityPanel();
    initializeProcessTable();
    initializeThreadPage();
    initializeCrossViewPage();
    initializeCreateProcessPage();

    rootLayout_->addWidget(sideTabWidget_);
}

void ProcessDock::initializeTopControls()
{
    // Change the control area to a 'two-row layout': the first row holds operation buttons, and the second row displays monitoring status separately.
    QVBoxLayout* controlContainerLayout = new QVBoxLayout();
    controlContainerLayout->setContentsMargins(0, 0, 0, 0);
    controlContainerLayout->setSpacing(4);

    controlLayout_ = new QHBoxLayout();
    controlLayout_->setContentsMargins(0, 0, 0, 0);
    controlLayout_->setSpacing(8);
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    // Consolidate low-frequency process list settings into a single non-modal, re-openable dialog to prevent the top control row from becoming too long.
    processSettingsDialog_ = new QDialog(this, Qt::Dialog);
    processSettingsDialog_->setModal(false);
    processSettingsDialog_->setAttribute(Qt::WA_DeleteOnClose, false);
    languageManager.bindWindowTitle(
        processSettingsDialog_,
        QStringLiteral("process.dialog.settings.title"),
        QStringLiteral("进程列表设置"));
    processSettingsLayout_ = new QVBoxLayout(processSettingsDialog_);
    processSettingsLayout_->setContentsMargins(12, 12, 12, 12);
    processSettingsLayout_->setSpacing(8);

    // Iterate through the strategy combo box:
    // 1) Toolhelp（CreateToolhelp32Snapshot + Process32First/Next）
    // 2) NtQuerySystemInformation
    // Note: No longer defaults to Auto; explicitly display the currently used method.
    strategyCombo_ = new QComboBox(processSettingsDialog_);
    strategyCombo_->setObjectName(QStringLiteral("ProcessDockStrategyCombo"));
    strategyCombo_->addItem(QIcon(kIconRefresh), "Toolhelp Snapshot / Process32First / Process32Next");
    strategyCombo_->addItem(QIcon(kIconRefresh), "NtQuerySystemInformation");
    languageManager.bindComboBoxItem(
        strategyCombo_,
        0,
        QStringLiteral("process.strategy.toolhelp"),
        QStringLiteral("Toolhelp Snapshot / Process32First / Process32Next"));
    languageManager.bindComboBoxItem(
        strategyCombo_,
        1,
        QStringLiteral("process.strategy.ntquery"),
        QStringLiteral("NtQuerySystemInformation"));
    strategyCombo_->setCurrentIndex(1);
    strategyCombo_->setToolTip("指定进程遍历方案");
    languageManager.bindToolTip(
        strategyCombo_,
        QStringLiteral("process.tooltip.strategy"),
        QStringLiteral("指定进程遍历方案"));
    // Adaptive width strategy: prevents long text from pushing the Dock out of the horizontal scroll bar.
    strategyCombo_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    strategyCombo_->setMinimumContentsLength(18);
    strategyCombo_->setMinimumWidth(320);

    // Process friendly view:
    // - A single checkbox toggles between two mutually exclusive views.
    // - Check to enable Friendly View; uncheck to enable Tree View based on KswordARKLight parent-child relationships.
    friendlyViewCheck_ = new QCheckBox(QStringLiteral("进程友好视图"), this);
    friendlyViewCheck_->setChecked(true);
    friendlyViewCheck_->setToolTip(QStringLiteral("勾选：友好视图（默认）；取消勾选：树状视图。搜索或查看历史活动快照时自动使用扁平结果。"));
    languageManager.bindText(
        friendlyViewCheck_,
        QStringLiteral("process.toolbar.friendly"),
        QStringLiteral("进程友好视图"));
    languageManager.bindToolTip(
        friendlyViewCheck_,
        QStringLiteral("process.tooltip.friendly"),
        QStringLiteral("勾选：友好视图（默认）；取消勾选：树状视图。搜索或查看历史活动快照时自动使用扁平结果。"));

    // View mode combo box: default to monitor view.
    // Items are uniformly generated by rebuildViewModeComboItems: built-in presets come first, followed by user-defined views appended.
    viewModeCombo_ = new QComboBox(this);
    viewModeCombo_->setObjectName(QStringLiteral("ProcessDockViewModeCombo"));
    loadCustomViewsFromSettings();
    rebuildViewModeComboItems();
    viewModeCombo_->setToolTip("切换列视图预设；可在“选择列”里把当前列保存为自定义视图。");
    languageManager.bindToolTip(
        viewModeCombo_,
        QStringLiteral("process.tooltip.view_mode"),
        QStringLiteral("切换列视图预设；可在“选择列”里把当前列保存为自定义视图。"));
    viewModeCombo_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    viewModeCombo_->setMinimumContentsLength(8);
    viewModeCombo_->setMaximumWidth(180);

    applyBlueComboBoxRuntimeStyle(strategyCombo_);
    applyBlueComboBoxRuntimeStyle(viewModeCombo_);

    // Start/Pause buttons: show icons only as needed.
    startButton_ = new QPushButton(QIcon(kIconStart), "", this);
    pauseButton_ = new QPushButton(QIcon(kIconPause), "", this);
    ksword_theme::applyCompactIconButtonMetrics(startButton_);
    ksword_theme::applyCompactIconButtonMetrics(pauseButton_);
    startButton_->setToolTip("开始周期性刷新进程列表，并同步记录进程活动");
    pauseButton_->setToolTip("暂停周期性刷新进程列表，并同步停止记录");
    languageManager.bindToolTip(
        startButton_,
        QStringLiteral("process.tooltip.start"),
        QStringLiteral("开始周期性刷新进程列表，并同步记录进程活动"));
    languageManager.bindToolTip(
        pauseButton_,
        QStringLiteral("process.tooltip.pause"),
        QStringLiteral("暂停周期性刷新进程列表，并同步停止记录"));

    // Process table refresh interval:
    // - This interval controls only the redraw frequency of the process table below; the default is 2 seconds.
    // - Background monitoring and active sampling default to 1-second intervals to avoid affecting recording precision with table rendering costs.
    //
    // Both intervals are continuous values with upper and lower bounds, so QDoubleSpinBox
    // is used instead of QLineEdit + QDoubleValidator: validators silently discard invalid
    // keystrokes, leaving users unaware of the valid range or why their input is rejected.
    // The spin control displays the range, step size, and unit on the UI at once, and supports adjustment via arrows or the scroll wheel.
    refreshLabel_ = new QLabel("列表刷新:", processSettingsDialog_);
    languageManager.bindText(refreshLabel_, QStringLiteral("process.label.refresh_interval"), QStringLiteral("列表刷新:"));
    tableRefreshIntervalSpin_ = new QDoubleSpinBox(processSettingsDialog_);
    tableRefreshIntervalSpin_->setDecimals(1);
    // The range is taken directly from the actual upper and lower limit constants used by the timer, avoiding discrepancies between the control and the clamp logic.
    tableRefreshIntervalSpin_->setRange(
        static_cast<double>(kProcessTableMinimumIntervalMilliseconds) / 1000.0,
        static_cast<double>(kProcessTableMaximumIntervalMilliseconds) / 1000.0);
    tableRefreshIntervalSpin_->setSingleStep(0.5);
    tableRefreshIntervalSpin_->setSuffix(QStringLiteral(" s"));
    tableRefreshIntervalSpin_->setValue(2.0);
    tableRefreshIntervalSpin_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    // Disable keyboard tracking: partial values typed do not trigger timer restart; only Enter, loss of focus, or step changes take effect.
    tableRefreshIntervalSpin_->setKeyboardTracking(false);
    tableRefreshIntervalSpin_->setToolTip("只控制下方进程表格的刷新频率，可调 0.5~60 秒，默认 2 秒。");
    languageManager.bindToolTip(
        tableRefreshIntervalSpin_,
        QStringLiteral("process.tooltip.table_interval"),
        QStringLiteral("只控制下方进程表格的刷新频率，可调 0.5~60 秒，默认 2 秒。"));

    // Active sampling interval:
    // - Allow decimal seconds; default is 1s.
    // - This interval drives background monitoring, refresh, and activity log sampling.
    sampleIntervalLabel_ = new QLabel("采样间隔:", processSettingsDialog_);
    languageManager.bindText(sampleIntervalLabel_, QStringLiteral("process.label.sample_interval"), QStringLiteral("采样间隔:"));
    refreshIntervalSpin_ = new QDoubleSpinBox(processSettingsDialog_);
    refreshIntervalSpin_->setDecimals(2);
    refreshIntervalSpin_->setRange(
        static_cast<double>(kActivityMinimumIntervalMilliseconds) / 1000.0,
        static_cast<double>(kActivityMaximumIntervalMilliseconds) / 1000.0);
    refreshIntervalSpin_->setSingleStep(0.05);
    refreshIntervalSpin_->setSuffix(QStringLiteral(" s"));
    refreshIntervalSpin_->setValue(1.0);
    refreshIntervalSpin_->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    refreshIntervalSpin_->setKeyboardTracking(false);
    refreshIntervalSpin_->setToolTip("进程活动记录的采样间隔，可调 0.05~60 秒，默认 1 秒；间隔越小系统枚举开销越大。");
    languageManager.bindToolTip(
        refreshIntervalSpin_,
        QStringLiteral("process.tooltip.sample_interval"),
        QStringLiteral("进程活动记录的采样间隔，可调 0.05~60 秒，默认 1 秒；间隔越小系统枚举开销越大。"));

    // Process search box:
    // - Performs local filtering directly based on the current cache without triggering additional system queries.
    // - Automatically focuses after switching to the 'Process List' page, supporting direct typing of search terms.
    processSearchLineEdit_ = new QLineEdit(this);
    processSearchLineEdit_->setClearButtonEnabled(true);
    processSearchLineEdit_->setPlaceholderText("搜索 PID / 名称 / 路径 / 命令行 / 用户");
    processSearchLineEdit_->setToolTip("切到进程列表页后可直接输入搜索词");
    languageManager.bindPlaceholder(
        processSearchLineEdit_,
        QStringLiteral("process.placeholder.search"),
        QStringLiteral("搜索 PID / 名称 / 路径 / 命令行 / 用户"));
    languageManager.bindToolTip(
        processSearchLineEdit_,
        QStringLiteral("process.tooltip.search"),
        QStringLiteral("切到进程列表页后可直接输入搜索词"));
    processSearchLineEdit_->setStyleSheet(buildBlueLineEditStyle());
    processSearchLineEdit_->setMaximumWidth(320);

    // Kernel comparison switch:
    // - When checked, request the R0 process list in addition during each refresh cycle.
    // - The UI highlights processes visible in R0 but not R3 in red;
    // - Enabled by default: detecting hidden processes is the primary use case of ARK; users should not need to locate this switch first.
    //   When the driver is not loaded, enumerateProcessesByR0Driver silently skips via openSilently, avoiding R0
    //   permission prompts on every iteration. Residual CIDs of exited processes are also filtered on the driver side.
    //   The toggle is retained so users can disable it to save the enumeration IOCTL per refresh cycle.
    kernelCompareCheck_ = new QCheckBox("刷新时对比内核进程（查隐藏）", processSettingsDialog_);
    kernelCompareCheck_->setChecked(true);
    kernelCompareCheck_->setToolTip("勾选后刷新会额外请求驱动进程列表，并显示仅内核可见的进程。");
    languageManager.bindText(
        kernelCompareCheck_,
        QStringLiteral("process.toolbar.kernel_compare"),
        QStringLiteral("刷新时对比内核进程（查隐藏）"));
    languageManager.bindToolTip(
        kernelCompareCheck_,
        QStringLiteral("process.tooltip.kernel_compare"),
        QStringLiteral("勾选后刷新会额外请求驱动进程列表，并显示仅内核可见的进程。"));

    // Ksword recoverable hidden process display switch:
    // - Do not display processes hidden by R0 by default.
    // - When checked, these rows are still displayed to facilitate right-clicking 'Unhide'.
    showKswordHiddenProcessCheck_ = new QCheckBox(QStringLiteral("显示Ksword隐藏项"), processSettingsDialog_);
    showKswordHiddenProcessCheck_->setChecked(false);
    showKswordHiddenProcessCheck_->setToolTip(QStringLiteral("显示由 R0 摘链后仍可通过内核扫描读取的 Ksword 隐藏项。"));
    languageManager.bindText(
        showKswordHiddenProcessCheck_,
        QStringLiteral("process.toolbar.hidden"),
        QStringLiteral("显示Ksword隐藏项"));
    languageManager.bindToolTip(
        showKswordHiddenProcessCheck_,
        QStringLiteral("process.tooltip.hidden"),
        QStringLiteral("显示由 R0 摘链后仍可通过内核扫描读取的 Ksword 隐藏项。"));

    activityBackgroundRecordCheck_ = new QCheckBox(QStringLiteral("后台保持刷新/记录"), processSettingsDialog_);
    activityBackgroundRecordCheck_->setToolTip(QStringLiteral("默认仅进程列表 Tab 显示时刷新和记录；勾选后切到其它 Tab 仍继续刷新并记录。"));
    languageManager.bindText(
        activityBackgroundRecordCheck_,
        QStringLiteral("process.activity.background"),
        QStringLiteral("后台保持刷新/记录"));
    languageManager.bindToolTip(
        activityBackgroundRecordCheck_,
        QStringLiteral("process.activity.tooltip.background"),
        QStringLiteral("默认仅进程列表 Tab 显示时刷新和记录；勾选后切到其它 Tab 仍继续刷新并记录。"));

    activityListOnlyRefreshCheck_ = new QCheckBox(QStringLiteral("不记录历史"), processSettingsDialog_);
    activityListOnlyRefreshCheck_->setToolTip(QStringLiteral("勾选后周期刷新仍会更新进程列表，但不会向上方时间轴写入新的活动记录。"));
    languageManager.bindText(
        activityListOnlyRefreshCheck_,
        QStringLiteral("process.activity.list_only"),
        QStringLiteral("不记录历史"));
    languageManager.bindToolTip(
        activityListOnlyRefreshCheck_,
        QStringLiteral("process.activity.tooltip.list_only"),
        QStringLiteral("勾选后周期刷新仍会更新进程列表，但不会向上方时间轴写入新的活动记录。"));

    processSettingsLayout_->addWidget(strategyCombo_);
    processSettingsLayout_->addWidget(refreshLabel_);
    processSettingsLayout_->addWidget(tableRefreshIntervalSpin_);
    processSettingsLayout_->addWidget(sampleIntervalLabel_);
    processSettingsLayout_->addWidget(refreshIntervalSpin_);
    processSettingsLayout_->addWidget(kernelCompareCheck_);
    processSettingsLayout_->addWidget(showKswordHiddenProcessCheck_);
    processSettingsLayout_->addWidget(activityBackgroundRecordCheck_);
    processSettingsLayout_->addWidget(activityListOnlyRefreshCheck_);
    processSettingsLayout_->addStretch(1);

    // "Select Columns" entry:
    // - The column set aligns with Task Manager's 'Details' page; right-clicking headers to select/deselect columns individually is inefficient for batch additions or removals.
    // - Provides an explicit entry consistent with Task Manager; the header right-click menu also retains the same item.
    columnChooserButton_ = new QPushButton(QStringLiteral("选择列"), this);
    columnChooserButton_->setToolTip(QStringLiteral("添加或移除进程列表中显示的列。"));
    languageManager.bindText(
        columnChooserButton_,
        QStringLiteral("process.toolbar.column_chooser"),
        QStringLiteral("选择列"));
    languageManager.bindToolTip(
        columnChooserButton_,
        QStringLiteral("process.tooltip.column_chooser"),
        QStringLiteral("添加或移除进程列表中显示的列。"));
    columnChooserButton_->setStyleSheet(buildBlueButtonStyle(false));

    // Process list settings entry: displays only the gear icon; specific options take effect immediately in a separate window.
    processSettingsButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_settings.svg")), QString(), this);
    ksword_theme::applyCompactIconButtonMetrics(processSettingsButton_);
    processSettingsButton_->setToolTip(QStringLiteral("打开进程列表设置"));
    languageManager.bindToolTip(
        processSettingsButton_,
        QStringLiteral("process.tooltip.settings"),
        QStringLiteral("打开进程列表设置"));

    // Unified blue button style (icon button version).
    const QString kButtonStyle = buildBlueButtonStyle(true);
    startButton_->setStyleSheet(kButtonStyle);
    pauseButton_->setStyleSheet(kButtonStyle);
    processSettingsButton_->setStyleSheet(kButtonStyle);

    // Group controls by function in the first row, leave spacing between groups to prevent controls of the same type from being separated by other groups:
    // ① Enumeration and view: Determines 'which processes to list and how to organize them';
    // ② Runtime controls: Start/Pause/Select Columns/Callback Protection;
    // ③ Search;
    // ④ Activity log: inserted by initializeProcessActivityPanel after the search box;
    // ⑤ Right-side refresh interval group and gear settings entry, pushed to the far right via addStretch.
    controlLayout_->addWidget(friendlyViewCheck_);
    controlLayout_->addWidget(viewModeCombo_);
    controlLayout_->addSpacing(12);
    controlLayout_->addWidget(startButton_);
    controlLayout_->addWidget(pauseButton_);
    controlLayout_->addWidget(columnChooserButton_);
    controlLayout_->addSpacing(12);
    controlLayout_->addWidget(processSearchLineEdit_);
    controlLayout_->addStretch(1);
    controlLayout_->addWidget(processSettingsButton_);
    controlContainerLayout->addLayout(controlLayout_);
    processPageLayout_->addLayout(controlContainerLayout);
}

void ProcessDock::initializeProcessActivityPanel()
{
    // Activity panel placed above the process table:
    // - Do not enumerate processes additionally; only consume m_cacheByIdentity after each refresh cycle.
    // - The chart, timeline, and snapshot share the same bounded sample cache.
    activityPanelWidget_ = new QWidget(processListPage_);
    activityPanelWidget_->setObjectName(QStringLiteral("processActivityPanelWidget"));
    activityPanelWidget_->setAutoFillBackground(false);
    activityPanelWidget_->setAttribute(Qt::WA_StyledBackground, true);
    activityPanelWidget_->setStyleSheet(QStringLiteral(
        "QWidget#processActivityPanelWidget {"
        "  background:transparent;"
        "  background-color:transparent;"
        "  border:1px solid %1;"
        "  border-radius:4px;"
        "}")
        .arg(ksword_theme::borderHex()));
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    QVBoxLayout* panelLayout = new QVBoxLayout(activityPanelWidget_);
    panelLayout->setContentsMargins(6, 6, 6, 6);
    panelLayout->setSpacing(5);

    activityClearButton_ = new QPushButton(QStringLiteral("清空"), activityPanelWidget_);
    activityClearButton_->setToolTip(QStringLiteral("清空当前刷新同步记录的进程活动样本。"));
    languageManager.bindText(activityClearButton_, QStringLiteral("process.activity.clear"), QStringLiteral("清空"));
    languageManager.bindToolTip(
        activityClearButton_,
        QStringLiteral("process.activity.tooltip.clear"),
        QStringLiteral("清空当前刷新同步记录的进程活动样本。"));
    activityClearButton_->setStyleSheet(buildBlueButtonStyle(false));

    const QString kMetricButtonStyle = QStringLiteral(
        "QPushButton {"
        "  color:%1;"
        "  background:%2;"
        "  border:1px solid %3;"
        "  border-radius:3px;"
        "  padding:3px 8px;"
        "}"
        "QPushButton:checked {"
        "  color:%5;"
        "  background:%4;"
        "  border:1px solid %4;"
        "}"
        "QPushButton:hover {"
        "  border:1px solid %4;"
        "}")
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(QStringLiteral("palette(highlighted-text)"));

    // Metric button must be independently toggleable:
    // - By default, all metrics are enabled so users can immediately see CPU, memory, disk, network, and GPU curves upon opening the page.
    // - Individual metrics can be disabled on demand later to avoid overly dense curves.
    auto createMetricButton =
        [this, &kMetricButtonStyle](const QString& text, const bool checkedByDefault)
        {
            QPushButton* button = new QPushButton(text, activityPanelWidget_);
            button->setCheckable(true);
            button->setChecked(checkedByDefault);
            button->setStyleSheet(kMetricButtonStyle);
            button->setToolTip(QStringLiteral("切换该指标是否绘制在上方百分比折线图中。"));
            return button;
        };
    activityCpuButton_ = createMetricButton(QStringLiteral("CPU"), true);
    activityMemoryButton_ = createMetricButton(QStringLiteral("内存"), true);
    activityDiskButton_ = createMetricButton(QStringLiteral("磁盘"), true);
    activityNetworkButton_ = createMetricButton(QStringLiteral("网络"), true);
    activityGpuButton_ = createMetricButton(QStringLiteral("GPU"), true);
    languageManager.bindText(activityCpuButton_, QStringLiteral("process.activity.metric.cpu"), QStringLiteral("CPU"));
    languageManager.bindText(activityMemoryButton_, QStringLiteral("process.activity.metric.memory"), QStringLiteral("内存"));
    languageManager.bindText(activityDiskButton_, QStringLiteral("process.activity.metric.disk"), QStringLiteral("磁盘"));
    languageManager.bindText(activityNetworkButton_, QStringLiteral("process.activity.metric.network"), QStringLiteral("网络"));
    languageManager.bindText(activityGpuButton_, QStringLiteral("process.activity.metric.gpu"), QStringLiteral("GPU"));
    for (QPushButton* metricButton : {
             activityCpuButton_,
             activityMemoryButton_,
             activityDiskButton_,
             activityNetworkButton_,
             activityGpuButton_ })
    {
        languageManager.bindToolTip(
            metricButton,
            QStringLiteral("process.activity.tooltip.metric"),
            QStringLiteral("切换该指标是否绘制在上方百分比折线图中。"));
    }

    // Place the crosshair button to the right of time-axis metric buttons such as 'Network/GPU':
    // - Interaction matches the window page picker button: must hold and drag to the target window before releasing;
    // - Do not open the window details after release; instead, filter the process list by the target window's PID and open the process details.
    ProcessWindowPickerDragButton* processPickerButton = new ProcessWindowPickerDragButton(activityPanelWidget_);
    processPickerButton->setIcon(QIcon(kIconWindowPickerTarget));
    ksword_theme::applyCompactIconButtonMetrics(processPickerButton);
    processPickerButton->setStyleSheet(buildBlueButtonStyle(true));
    processPickerButton->setToolTip(QStringLiteral("按住并拖拽准星到目标窗口，松开后按该窗口 PID 筛选进程并打开进程详细信息"));
    languageManager.bindToolTip(
        processPickerButton,
        QStringLiteral("process.activity.tooltip.picker"),
        QStringLiteral("按住并拖拽准星到目标窗口，松开后按该窗口 PID 筛选进程并打开进程详细信息"));
    processPickerButton->setReleaseCallback([this](const QPoint& globalPos) {
        handleProcessWindowPickerRelease(globalPos);
    });
    activityProcessPickerButton_ = processPickerButton;

    QLabel* activityDisplayLabel = new QLabel(QStringLiteral("显示:"), activityPanelWidget_);
    languageManager.bindText(
        activityDisplayLabel,
        QStringLiteral("process.activity.display"),
        QStringLiteral("显示:"));

    // Merge activity controls into the top control row; the chart panel retains only the chart itself, saving an entire vertical row of space.
    // Class controls have been consolidated into the gear window; here, only the clear, metric selection, and window picker entries are retained.
    int topControlInsertIndex = controlLayout_->indexOf(processSearchLineEdit_) + 1;
    controlLayout_->insertSpacing(topControlInsertIndex++, 12);
    for (QWidget* const kActivityControlWidget : {
             static_cast<QWidget*>(activityClearButton_),
             static_cast<QWidget*>(activityDisplayLabel),
             static_cast<QWidget*>(activityCpuButton_),
             static_cast<QWidget*>(activityMemoryButton_),
             static_cast<QWidget*>(activityDiskButton_),
             static_cast<QWidget*>(activityNetworkButton_),
             static_cast<QWidget*>(activityGpuButton_),
             static_cast<QWidget*>(activityProcessPickerButton_) })
    {
        controlLayout_->insertWidget(topControlInsertIndex++, kActivityControlWidget);
    }

    activityChartWidget_ = new ProcessActivityChartWidget(this, activityPanelWidget_);
    activityChartWidget_->setToolTip(QString());

    activityTimelineSlider_ = new ProcessActivityTimelineSlider(this, activityPanelWidget_);
    activityTimelineSlider_->setRange(0, 0);
    activityTimelineSlider_->setValue(0);
    activityTimelineSlider_->setVisible(false);

    // The snapshot description was previously used to display long text for the current sampling point of the line chart, but it would crowd the process list space.
    // Keep the object pointer for null checks in legacy logic, while excluding it from the layout and hiding its text.
    activitySnapshotLabel_ = new QLabel(activityPanelWidget_);
    activitySnapshotLabel_->setVisible(false);
    activitySnapshotLabel_->setWordWrap(false);
    activitySnapshotLabel_->setMinimumHeight(0);
    activitySnapshotLabel_->setMaximumHeight(0);
    activitySnapshotLabel_->setTextInteractionFlags(Qt::NoTextInteraction);
    activitySnapshotLabel_->setStyleSheet(QStringLiteral(
        "QLabel {"
        "  color:%1;"
        "  background:transparent;"
        "  background-color:transparent;"
        "  border:1px solid %2;"
        "  border-radius:3px;"
        "  padding:4px;"
        "}")
        .arg(ksword_theme::textSecondaryHex())
        .arg(ksword_theme::borderHex()));

    panelLayout->addWidget(activityChartWidget_);
    processPageLayout_->addWidget(activityPanelWidget_, 0);
}

void ProcessDock::handleProcessWindowPickerRelease(const QPoint& globalPos)
{
    // This function is the business entry point for process page crosshair picking.
    // - Hit logic remains consistent with the window page: first retrieve the window under the mouse, then backtrack to the root window.
    // Result does not enter window details; instead, convert to PID for filtering and process details.
    KLogEvent pickEvent;
    info << pickEvent
        << "[ProcessDock] 进程准星拾取释放, x="
        << globalPos.x()
        << ", y="
        << globalPos.y()
        << eol;

    POINT nativePoint{};
    nativePoint.x = globalPos.x();
    nativePoint.y = globalPos.y();

    // rawWindowHandle is the finest-grained window under the mouse; rootWindowHandle is used for top-level window fallback.
    HWND rawWindowHandle = ::WindowFromPoint(nativePoint);
    HWND rootWindowHandle = rawWindowHandle != nullptr ? ::GetAncestor(rawWindowHandle, GA_ROOT) : nullptr;
    HWND targetWindowHandle = rawWindowHandle != nullptr ? rawWindowHandle : rootWindowHandle;
    if (targetWindowHandle == nullptr || ::IsWindow(targetWindowHandle) == FALSE)
    {
        warn << pickEvent
            << "[ProcessDock] 进程准星拾取失败：WindowFromPoint 未命中有效窗口。"
            << eol;
        QMessageBox::information(
            this,
            QStringLiteral("进程拾取"),
            QStringLiteral("未命中可用窗口，请重试。"));
        return;
    }

    // Prefer resolving the original window PID; on exception, fall back to the root window PID to align with the window page picking experience.
    DWORD targetPid = 0;
    DWORD targetTid = ::GetWindowThreadProcessId(targetWindowHandle, &targetPid);
    if ((targetPid == 0 || targetTid == 0) && rootWindowHandle != nullptr && rootWindowHandle != targetWindowHandle)
    {
        targetWindowHandle = rootWindowHandle;
        targetPid = 0;
        targetTid = ::GetWindowThreadProcessId(targetWindowHandle, &targetPid);
    }

    const quint64 kTargetHwndValue = static_cast<quint64>(reinterpret_cast<quintptr>(targetWindowHandle));
    if (targetPid == 0)
    {
        warn << pickEvent
            << "[ProcessDock] 进程准星拾取失败：无法解析目标窗口 PID, hwnd=0x"
            << std::hex
            << kTargetHwndValue
            << std::dec
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("进程拾取"),
            QStringLiteral("无法读取目标窗口所属进程 PID。"));
        return;
    }

    // Switching back to the real-time table: the user dragging the window targets current system processes, so the historical snapshot table should not continue to overwrite the real-time list.
    activityTimelinePinnedToLatest_ = true;
    activityTableSnapshotIndex_ = -1;
    activityTableSnapshotRecords_.clear();
    if (activityTimelineSlider_ != nullptr && !activitySamples_.empty())
    {
        const bool kOldUpdating = activityTimelineSliderUpdating_;
        activityTimelineSliderUpdating_ = true;
        activityTimelineSlider_->setValue(static_cast<int>(activitySamples_.size()) - 1);
        activityTimelineSliderUpdating_ = kOldUpdating;
    }

    // Set the process list filter to PID:
    // - Directly write to the top search box to reuse existing filtering logic and UI visibility state.
    // - Manually rebuild after blockSignals to avoid redundant reconstruction during historical state transitions.
    if (processSearchLineEdit_ != nullptr)
    {
        QSignalBlocker blocker(processSearchLineEdit_);
        processSearchLineEdit_->setText(QStringLiteral("pid:%1").arg(static_cast<qulonglong>(targetPid)));
    }
    // Prioritize setting the row corresponding to the target PID as the current row after reconstruction so users can directly see the result after filtering.
    trackedSelectedIdentityKey_.clear();
    trackedSelectedIdentityKeys_.clear();
    for (const auto& cachePair : cacheByIdentity_)
    {
        if (cachePair.second.record.pid == targetPid)
        {
            trackedSelectedIdentityKey_ = cachePair.first;
            trackedSelectedIdentityKeys_.push_back(cachePair.first);
            break;
        }
    }
    rebuildTable();
    updateProcessActivityStatusLabel();

    info << pickEvent
        << "[ProcessDock] 进程准星拾取成功, hwnd=0x"
        << std::hex
        << kTargetHwndValue
        << std::dec
        << ", pid="
        << targetPid
        << ", tid="
        << targetTid
        << "，已设置进程列表筛选器并打开进程详情。"
        << eol;
    openProcessDetailWindowByPid(static_cast<std::uint32_t>(targetPid));
}

void ProcessDock::initializeProcessTable()
{
    // Migrating the process list to QTableView + FlatTableModel:
    // - Row data is stored only in the lightweight ProcessTableRow of the model;
    // - On each refresh, incrementally publish deletions, insertions, reordering, and data changes via stable row keys to avoid resetting the entire table.
    // - The tree view still simulates indentation via the Name column to preserve legacy appearance and interaction semantics.
    // List header text, i18n keys, and the TableColumn enum must strictly correspond one-to-one; otherwise, the table columns will be misaligned.
    // TableColumn is a private nested enum, so compile-time assertions cannot be made at the table definition site; this performs a fallback self-check on the startup path.
    if (kProcessTableHeaders.size() != static_cast<int>(TableColumn::kCount) ||
        kProcessTableHeaderKeyCount != static_cast<std::size_t>(TableColumn::kCount))
    {
        KLogEvent logEvent;
        err << logEvent
            << "[ProcessDock] 列定义不一致：headerTextCount=" << kProcessTableHeaders.size()
            << ", headerKeyCount=" << kProcessTableHeaderKeyCount
            << ", columnCount=" << static_cast<int>(TableColumn::kCount)
            << eol;
    }

    processTable_ = new ks::ui::TableActionTableView(this);
    // Process table refresh rate and row count are high:
    // - Disable mainWindow's global smooth-scroll takeover to prevent wheel events from being overridden by QPropertyAnimation.
    // - Preserves default QTableView/scrollbar scrolling feel without adding inertia or delay.
    // - Return behavior: Sets only the Qt dynamic property; no other side effects.
    processTable_->setProperty("ksword_disable_smooth_scroll", true);
    if (processTable_->viewport() != nullptr)
    {
        processTable_->viewport()->setProperty("ksword_disable_smooth_scroll", true);
    }

    std::vector<ProcessTableModel::ColumnSpec> columnSpecs;
    columnSpecs.reserve(static_cast<std::size_t>(TableColumn::kCount));
    for (int columnIndex = 0; columnIndex < static_cast<int>(TableColumn::kCount); ++columnIndex)
    {
        ProcessTableModel::ColumnSpec columnSpec{};
        columnSpec.headerText = kProcessTableHeaders.at(columnIndex);
        columnSpec.alignment = (columnIndex == toColumnIndex(TableColumn::kIsAdmin))
            ? (Qt::AlignCenter | Qt::AlignVCenter)
            : (Qt::AlignLeft | Qt::AlignVCenter);
        columnSpecs.push_back(std::move(columnSpec));
    }
    processTableModel_ = new ProcessTableModel(
        std::move(columnSpecs),
        [this](const ProcessTableRow& tableRow, const int column, const int role) -> QVariant
        {
            return processTableData(tableRow, column, role);
        },
        this,
        [](const ProcessTableRow& tableRow, const int) -> Qt::ItemFlags
        {
            // Inputs: one ProcessTableRow and the requested column.
            // Processing: group headers are display-only; application aggregates are selectable batch targets.
            // Return: item flags used by Qt selection and context menu targeting.
            return tableRow.rowKind == ProcessDock::ProcessTableRowKind::kGroupHeader
                ? Qt::ItemIsEnabled
                : (Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        },
        [](const ProcessTableRow& tableRow) -> std::string
        {
            if (tableRow.rowKind == ProcessDock::ProcessTableRowKind::kProcess)
            {
                return std::string("process:") + tableRow.identityKey;
            }
            return std::string("synthetic:")
                + std::to_string(static_cast<int>(tableRow.rowKind))
                + ":"
                + tableRow.expansionKey.toUtf8().toStdString();
        });
    processSortProxy_ = new ProcessTableSortProxy(this);
    processSortProxy_->setSourceModel(processTableModel_);
    static_cast<ProcessTableSortProxy*>(processSortProxy_)->setHeaderTexts(kProcessTableHeaders);
    processTable_->setModel(processSortProxy_);

    processTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    // Selection mode:
    // - Standard left-click retains single-row focus;
    // - Qt enters checkable multi-select/deselect mode when clicking with Ctrl held.
    // - The right-click menu reads all selected rows and executes actions in batch.
    processTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    processTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // The "CPU Core" column retains full content width based on the actual number of logical processors:
    // - The table ignores content sizeHint in the horizontal direction to prevent column widths from expanding ProcessDock via page layout.
    // - Columns exceeding the viewport are handled by the table's bottom horizontal scrollbar without compressing the per-core fan layout.
    processTable_->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
    processTable_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    processTable_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    processTable_->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    // Pixel-based scrolling ensures scroll wheel and touchpad events immediately advance the viewport
    // upon arrival, preventing fixed-row-height tables from aggregating input into large per-item jumps.
    processTable_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    processTable_->setSortingEnabled(true);
    processTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    processTable_->setAlternatingRowColors(true);
    processTable_->setItemDelegate(new ProcessRowHighlightDelegate(
        processTable_,
        toColumnIndex(TableColumn::kCpuCore)));
    processTable_->setProperty("ksword_preserve_custom_table_delegate", true);
    processTable_->setShowGrid(false);
    processTable_->setWordWrap(false);
    processTable_->setCornerButtonEnabled(false);
    // Global TableColumnAutoFit attempts to fit regular columns into the viewport during the first display or when dimensions change.
    // Overflow width from per-core columns or user-manually widened columns is handled by the on-demand horizontal scrolling above.
    if (QScrollBar* verticalScrollBar = processTable_->verticalScrollBar())
    {
        verticalScrollBar->setProperty("ksword_disable_smooth_scroll", true);
        verticalScrollBar->setSingleStep(12);
    }
    if (QScrollBar* horizontalScrollBar = processTable_->horizontalScrollBar())
    {
        horizontalScrollBar->setProperty("ksword_disable_smooth_scroll", true);
    }

    // Header supports dragging and right-click to show/hide columns.
    if (QHeaderView* verticalHeader = processTable_->verticalHeader())
    {
        verticalHeader->setVisible(false);
        verticalHeader->setSectionResizeMode(QHeaderView::Fixed);
        verticalHeader->setDefaultSectionSize(24);
    }
    QHeaderView* headerView = processTable_->horizontalHeader();
    headerView->setSectionsMovable(true);
    headerView->setStretchLastSection(false);
    headerView->setContextMenuPolicy(Qt::CustomContextMenu);
    headerView->setStyleSheet(QStringLiteral(
        "QHeaderView::section {"
        "  color: %1;"
        "  background: transparent; /* %2 */"
        "  border: 1px solid %3;"
        "  padding: 4px;"
        "  font-weight: 600;"
        "}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::borderHex()));

    // Column layout configuration must be loaded before applying the default view preset.
    // applyViewMode overlays user overrides after preset layout; reversing the order causes custom columns to be overwritten at startup.
    loadProcessColumnLayoutFromSettings();

    applyDefaultColumnWidths();
    applyViewMode(ViewMode::kMonitor);
    lastProcessDetailDemandFlags_ = currentProcessDetailDemandFlags();
    applyAdaptiveColumnWidths();
    processPageLayout_->addWidget(processTable_, 1);

    // Satisfies requirement 3.1: the sidebar Tab includes the "Process List" tab.
    sideTabWidget_->addTab(processListPage_, blueTintedIcon(kIconProcessMain), "进程列表");
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_,
        processListPage_,
        QStringLiteral("process.tab.list"),
        QStringLiteral("进程列表"));
    sideTabWidget_->setCurrentIndex(0);
    refreshSideTabIconContrast();
}

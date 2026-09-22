#include "NetworkDock.InternalCommon.h"
#include "../ui/VisibleTableWidget.h"
#include "NetworkFirewallPage.h"
#include "NetworkAuditPage.h"
#include "../internationalization/LanguageManager.h"

#include <QFrame>
#include <QScrollArea>

using namespace network_dock_detail;
void NetworkDock::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(4, 4, 4, 4);
    rootLayout_->setSpacing(4);

    // Top horizontal Tab:
    // - The network function tab count is already high; switching to a top horizontal layout prevents vertical scrollbars from being pushed out by left-side vertical tabs.
    // - Retain the unified QTabWidget structure without altering the internal implementation of each functional page.
    sideTabWidget_ = new QTabWidget(this);
    sideTabWidget_->setTabPosition(QTabWidget::North);
    sideTabWidget_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    rootLayout_->addWidget(sideTabWidget_, 1);

    initializeTrafficMonitorTab();
    initializeNidsTab();
    // The process rate-limit page is intentionally not exposed in the UI.
    // Its current implementation throttles by suspending/resuming the whole
    // target process, which is too coarse for a user-facing network dock tab.
    // Keep initializeRateLimitTab() compiled for now so the backend/UI code can
    // be restored later if a cleaner enforcement model replaces it.
    initializeFirewallTab();
    initializeNetworkAuditTab();
    initializeManualRequestTab();
    initializeMultiThreadDownloadTab();
    initializeHttpsAnalyzeTab();
    initializeRouteTableTab();
    initializeArpCacheTab();
    initializeDnsCacheTab();
    initializeAliveHostScanTab();
    initializeHostsFileEditorTab();
}

void NetworkDock::initializeTrafficMonitorTab()
{
    trafficMonitorPage_ = new QWidget(this);
    trafficMonitorLayout_ = new QVBoxLayout(trafficMonitorPage_);
    trafficMonitorLayout_->setContentsMargins(6, 6, 6, 6);
    trafficMonitorLayout_->setSpacing(6);

    // Control bar: Start/Stop/Clear + status indicator.
    monitorControlLayout_ = new QHBoxLayout();
    monitorControlLayout_->setSpacing(6);

    startMonitorButton_ = new QPushButton(trafficMonitorPage_);
    startMonitorButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    startMonitorButton_->setToolTip(QStringLiteral("启动网络流量监控"));

    stopMonitorButton_ = new QPushButton(trafficMonitorPage_);
    stopMonitorButton_->setIcon(QIcon(":/Icon/process_pause.svg"));
    stopMonitorButton_->setToolTip(QStringLiteral("停止网络流量监控"));

    clearPacketButton_ = new QPushButton(trafficMonitorPage_);
    clearPacketButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    clearPacketButton_->setToolTip(QStringLiteral("清空当前流量列表"));

    networkPluginButton_ = new QPushButton(QStringLiteral("插件"), trafficMonitorPage_);
    networkPluginButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    networkPluginButton_->setToolTip(QStringLiteral("运行声明支持网络目标的独立插件"));
    networkPluginMenu_ = new QMenu(networkPluginButton_);
    networkPluginButton_->setMenu(networkPluginMenu_);

    monitorStatusLabel_ = new QLabel(QStringLiteral("状态：未启动"), trafficMonitorPage_);
    // Do not set a large minimum width for the status label to avoid triggering horizontal scrollbars when the window narrows.
    monitorStatusLabel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    monitorControlLayout_->addWidget(startMonitorButton_);
    monitorControlLayout_->addWidget(stopMonitorButton_);
    monitorControlLayout_->addWidget(clearPacketButton_);
    monitorControlLayout_->addWidget(networkPluginButton_);
    monitorControlLayout_->addWidget(monitorStatusLabel_);
    monitorControlLayout_->addStretch(1);

    trafficMonitorLayout_->addLayout(monitorControlLayout_);

    // New filter header bar: funnel button + rule group management + import/export save.
    monitorFilterHeaderLayout_ = new QHBoxLayout();
    monitorFilterHeaderLayout_->setSpacing(6);

    monitorFilterToggleButton_ = new QPushButton(trafficMonitorPage_);
    monitorFilterToggleButton_->setCheckable(true);
    monitorFilterToggleButton_->setChecked(false);
    monitorFilterToggleButton_->setIcon(QIcon(":/Icon/filter_funnel.svg"));
    monitorFilterToggleButton_->setToolTip(QStringLiteral("展开/收起网络筛选器配置"));

    QLabel* filterTitleLabel = new QLabel(QStringLiteral("网络筛选器"), trafficMonitorPage_);
    filterTitleLabel->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Preferred);

    addMonitorFilterGroupButton_ = new QPushButton(QStringLiteral("新增规则组"), trafficMonitorPage_);
    addMonitorFilterGroupButton_->setIcon(QIcon(":/Icon/plus.svg"));
    addMonitorFilterGroupButton_->setToolTip(QStringLiteral("新增一个 OR 规则组"));

    applyMonitorFilterButton_ = new QPushButton(QStringLiteral("应用"), trafficMonitorPage_);
    applyMonitorFilterButton_->setIcon(QIcon(":/Icon/log_track.svg"));
    applyMonitorFilterButton_->setToolTip(QStringLiteral("应用当前全部规则组过滤条件"));

    saveMonitorFilterButton_ = new QPushButton(QStringLiteral("保存"), trafficMonitorPage_);
    saveMonitorFilterButton_->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    saveMonitorFilterButton_->setToolTip(QStringLiteral("保存到 exe 目录下 config/wireshark.cfg"));

    importMonitorFilterButton_ = new QPushButton(QStringLiteral("导入"), trafficMonitorPage_);
    importMonitorFilterButton_->setIcon(QIcon(":/Icon/codeeditor_open.svg"));
    importMonitorFilterButton_->setToolTip(QStringLiteral("从配置文件导入规则组"));

    exportMonitorFilterButton_ = new QPushButton(QStringLiteral("导出"), trafficMonitorPage_);
    exportMonitorFilterButton_->setIcon(QIcon(":/Icon/log_export.svg"));
    exportMonitorFilterButton_->setToolTip(QStringLiteral("导出当前规则组到配置文件"));

    clearMonitorFilterButton_ = new QPushButton(QStringLiteral("一键清空"), trafficMonitorPage_);
    clearMonitorFilterButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    clearMonitorFilterButton_->setToolTip(QStringLiteral("清空全部规则组配置"));

    monitorFilterHeaderLayout_->addWidget(monitorFilterToggleButton_);
    monitorFilterHeaderLayout_->addWidget(filterTitleLabel);
    monitorFilterHeaderLayout_->addSpacing(4);
    monitorFilterHeaderLayout_->addWidget(addMonitorFilterGroupButton_);
    monitorFilterHeaderLayout_->addWidget(applyMonitorFilterButton_);
    monitorFilterHeaderLayout_->addWidget(saveMonitorFilterButton_);
    monitorFilterHeaderLayout_->addWidget(importMonitorFilterButton_);
    monitorFilterHeaderLayout_->addWidget(exportMonitorFilterButton_);
    monitorFilterHeaderLayout_->addWidget(clearMonitorFilterButton_);
    monitorFilterHeaderLayout_->addStretch(1);
    trafficMonitorLayout_->addLayout(monitorFilterHeaderLayout_);

    // Filter collapsible panel: title separator line + rule group scroll area + status label.
    monitorFilterPanel_ = new QWidget(trafficMonitorPage_);
    monitorFilterPanel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    // The filter panel uses a "restricted height + internal scrolling" strategy to prevent expanding the entire Dock and triggering outer scrollbars.
    monitorFilterPanel_->setMaximumHeight(240);
    monitorFilterPanelLayout_ = new QVBoxLayout(monitorFilterPanel_);
    monitorFilterPanelLayout_->setContentsMargins(2, 0, 2, 0);
    monitorFilterPanelLayout_->setSpacing(6);

    QFrame* filterSeparatorLine = new QFrame(monitorFilterPanel_);
    filterSeparatorLine->setFrameShape(QFrame::HLine);
    filterSeparatorLine->setFrameShadow(QFrame::Sunken);
    monitorFilterPanelLayout_->addWidget(filterSeparatorLine);

    monitorFilterScrollArea_ = new QScrollArea(monitorFilterPanel_);
    monitorFilterScrollArea_->setWidgetResizable(true);
    monitorFilterScrollArea_->setFrameShape(QFrame::NoFrame);
    monitorFilterScrollArea_->setMinimumHeight(0);
    monitorFilterScrollArea_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    monitorFilterScrollArea_->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    monitorFilterScrollArea_->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    monitorFilterGroupHostWidget_ = new QWidget(monitorFilterScrollArea_);
    monitorFilterGroupHostLayout_ = new QVBoxLayout(monitorFilterGroupHostWidget_);
    monitorFilterGroupHostLayout_->setContentsMargins(0, 0, 0, 0);
    monitorFilterGroupHostLayout_->setSpacing(8);
    monitorFilterScrollArea_->setWidget(monitorFilterGroupHostWidget_);
    monitorFilterPanelLayout_->addWidget(monitorFilterScrollArea_, 1);

    monitorFilterStateLabel_ = new QLabel(QStringLiteral("当前过滤：无"), monitorFilterPanel_);
    monitorFilterStateLabel_->setWordWrap(true);
    monitorFilterStateLabel_->setMinimumWidth(0);
    monitorFilterStateLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    monitorFilterPanelLayout_->addWidget(monitorFilterStateLabel_);

    trafficMonitorLayout_->addWidget(monitorFilterPanel_);
    monitorFilterPanel_->setVisible(false);

    addMonitorFilterRuleGroup();
    updateMonitorFilterStateLabel();

    // Traffic timeline:
    // - Reuse the box-selection time axis control below the ETW monitoring tab instead of the 'point-in-time slider' from the process tab.
    // - Users can drag the rectangle to move the time window as a whole, or drag the left/right edges to adjust the boundaries.
    // - The control is responsible only for time selection; actual packet display is rebuilt uniformly by NetworkDock's filter chain.
    packetTimelineWidget_ = new ProcessTraceTimelineWidget(trafficMonitorPage_);
    packetTimelineWidget_->setToolTip(QStringLiteral(
        "流量时间轴：横轴只统计监控开启时长，停机间隔不计入；绿色折线为上传速率，蓝色折线为下载速率；拖动矩形移动时间窗口，拖动左右边调整边界，滚轮向上放大窗口、向下缩小窗口。清空报文会重置时间轴。"));
    trafficMonitorLayout_->addWidget(packetTimelineWidget_, 0);

    // Main packet table: displays 'all sent UDP/TCP packets'.
    packetTable_ = new ks::ui::VisibleTableWidget(trafficMonitorPage_);
    packetTable_->setColumnCount(toPacketColumn(PacketTableColumn::kCount));
    packetTable_->setHorizontalHeaderLabels({
        QStringLiteral("时间"),
        QStringLiteral("协议"),
        QStringLiteral("方向"),
        QStringLiteral("来源"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点"),
        QStringLiteral("域名"),
        QStringLiteral("总长度"),
        QStringLiteral("负载"),
        QStringLiteral("内容预览")
        });
    packetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    // Enable multi-selection for the packet capture list to facilitate batch copying of packet ASCII/hex content.
    packetTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    packetTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    packetTable_->verticalHeader()->setVisible(false);
    // Performance and adaptive explanation:
    // 1) Switch to Stretch to avoid performance lag caused by repeated full-table measurements during high-frequency insertions when using ResizeToContents;
    // 2) Do not force-hide the horizontal scrollbar; the global column width adapter will compress default column widths later.
    packetTable_->horizontalHeader()->setStretchLastSection(true);
    packetTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    trafficMonitorLayout_->addWidget(packetTable_, 1);
    sideTabWidget_->addTab(trafficMonitorPage_, QIcon(":/Icon/process_main.svg"), QStringLiteral("流量监控"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, trafficMonitorPage_, QStringLiteral("network.tab.traffic"), QStringLiteral("流量监控"));
}

void NetworkDock::initializeRateLimitTab()
{
    rateLimitPage_ = new QWidget(this);
    rateLimitLayout_ = new QVBoxLayout(rateLimitPage_);
    rateLimitLayout_->setContentsMargins(6, 6, 6, 6);
    rateLimitLayout_->setSpacing(6);

    // Control bar: Input rule parameters and manage rules.
    rateLimitControlLayout_ = new QHBoxLayout();
    rateLimitControlLayout_->setSpacing(6);

    QLabel* pidLabel = new QLabel(QStringLiteral("PID:"), rateLimitPage_);
    rateLimitPidEdit_ = new QLineEdit(rateLimitPage_);
    rateLimitPidEdit_->setPlaceholderText(QStringLiteral("进程 PID"));
    rateLimitPidEdit_->setMaximumWidth(110);
    rateLimitPidEdit_->setMinimumWidth(66);

    QLabel* kbpsLabel = new QLabel(QStringLiteral("限速KB/s:"), rateLimitPage_);
    rateLimitKBpsSpin_ = new QSpinBox(rateLimitPage_);
    rateLimitKBpsSpin_->setRange(1, 1024 * 1024);
    rateLimitKBpsSpin_->setValue(256);
    rateLimitKBpsSpin_->setToolTip(QStringLiteral("每秒允许发送流量上限"));

    QLabel* suspendMsLabel = new QLabel(QStringLiteral("挂起时长ms:"), rateLimitPage_);
    rateLimitSuspendMsSpin_ = new QSpinBox(rateLimitPage_);
    rateLimitSuspendMsSpin_->setRange(50, 2000);
    rateLimitSuspendMsSpin_->setValue(250);
    rateLimitSuspendMsSpin_->setToolTip(QStringLiteral("超限后挂起时长"));

    applyRateLimitButton_ = new QPushButton(rateLimitPage_);
    applyRateLimitButton_->setIcon(QIcon(":/Icon/process_priority.svg"));
    applyRateLimitButton_->setToolTip(QStringLiteral("新增或更新限速规则"));

    removeRateLimitButton_ = new QPushButton(rateLimitPage_);
    removeRateLimitButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    removeRateLimitButton_->setToolTip(QStringLiteral("删除选中的限速规则"));

    clearRateLimitButton_ = new QPushButton(rateLimitPage_);
    clearRateLimitButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    clearRateLimitButton_->setToolTip(QStringLiteral("清空全部限速规则"));

    rateLimitControlLayout_->addWidget(pidLabel);
    rateLimitControlLayout_->addWidget(rateLimitPidEdit_);
    rateLimitControlLayout_->addWidget(kbpsLabel);
    rateLimitControlLayout_->addWidget(rateLimitKBpsSpin_);
    rateLimitControlLayout_->addWidget(suspendMsLabel);
    rateLimitControlLayout_->addWidget(rateLimitSuspendMsSpin_);
    rateLimitControlLayout_->addWidget(applyRateLimitButton_);
    rateLimitControlLayout_->addWidget(removeRateLimitButton_);
    rateLimitControlLayout_->addWidget(clearRateLimitButton_);
    rateLimitControlLayout_->addStretch(1);

    rateLimitLayout_->addLayout(rateLimitControlLayout_);

    // Rule table: displays PID, threshold, trigger count, and current status.
    rateLimitTable_ = new ks::ui::VisibleTableWidget(rateLimitPage_);
    rateLimitTable_->setColumnCount(toRateLimitColumn(RateLimitTableColumn::kCount));
    rateLimitTable_->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("限速KB/s"),
        QStringLiteral("挂起ms"),
        QStringLiteral("触发次数"),
        QStringLiteral("窗口字节"),
        QStringLiteral("状态")
        });
    rateLimitTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    rateLimitTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    rateLimitTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rateLimitTable_->verticalHeader()->setVisible(false);
    // Use Stretch for the rate limit table to reduce UI reflow overhead during periodic refreshes.
    rateLimitTable_->horizontalHeader()->setStretchLastSection(true);
    rateLimitTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    installCopyCurrentRowMenu(
        rateLimitTable_,
        QStringLiteral("复制当前行"),
        toRateLimitColumn(RateLimitTableColumn::kPid));
    rateLimitLayout_->addWidget(rateLimitTable_, 1);

    // Rate-limited action log: facilitates viewing the results of suspension/resumption.
    rateLimitLogOutput_ = new QPlainTextEdit(rateLimitPage_);
    rateLimitLogOutput_->setReadOnly(true);
    rateLimitLogOutput_->setMaximumBlockCount(400);
    // The log box uses automatic line wrapping based on control width to avoid horizontal scrollbars in narrow windows.
    rateLimitLogOutput_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    rateLimitLogOutput_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    rateLimitLogOutput_->setPlaceholderText(QStringLiteral("限速动作日志将显示在这里..."));
    rateLimitLayout_->addWidget(rateLimitLogOutput_, 1);

    sideTabWidget_->addTab(rateLimitPage_, QIcon(":/Icon/process_priority.svg"), QStringLiteral("进程限速"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, rateLimitPage_, QStringLiteral("network.tab.rate_limit"), QStringLiteral("进程限速"));
}

void NetworkDock::initializeConnectionManageTab()
{
    // Connection management page responsibilities:
    // 1) Display the TCP connection table.
    // 2) Display the UDP endpoint table;
    // 3) Provides the ability to terminate TCP connections and refresh controls.
    connectionManagePage_ = new QWidget(this);
    connectionManageLayout_ = new QVBoxLayout(connectionManagePage_);
    connectionManageLayout_->setContentsMargins(6, 6, 6, 6);
    connectionManageLayout_->setSpacing(6);

    // Top control bar: manual refresh / auto-refresh toggle / disconnect button / status label.
    connectionControlLayout_ = new QHBoxLayout();
    connectionControlLayout_->setSpacing(6);

    refreshConnectionButton_ = new QPushButton(connectionManagePage_);
    refreshConnectionButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    refreshConnectionButton_->setToolTip(QStringLiteral("立即刷新 TCP/UDP 连接快照"));

    autoRefreshConnectionButton_ = new QPushButton(connectionManagePage_);
    autoRefreshConnectionButton_->setCheckable(true);
    autoRefreshConnectionButton_->setChecked(true);
    autoRefreshConnectionButton_->setIcon(QIcon(":/Icon/process_pause.svg"));
    autoRefreshConnectionButton_->setToolTip(QStringLiteral("自动刷新已开启，点击暂停"));

    terminateTcpButton_ = new QPushButton(connectionManagePage_);
    terminateTcpButton_->setIcon(QIcon(":/Icon/process_terminate.svg"));
    terminateTcpButton_->setToolTip(QStringLiteral("终止当前选中的 TCP 连接（DELETE_TCB）"));

    clearConnectionPidFilterButton_ = new QPushButton(connectionManagePage_);
    clearConnectionPidFilterButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    clearConnectionPidFilterButton_->setToolTip(QStringLiteral("清除进程页跳转带入的 PID 筛选"));
    clearConnectionPidFilterButton_->setEnabled(false);

    connectionStatusLabel_ = new QLabel(QStringLiteral("状态：等待刷新"), connectionManagePage_);
    connectionStatusLabel_->setWordWrap(true);
    connectionStatusLabel_->setMinimumWidth(0);
    connectionStatusLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);

    connectionControlLayout_->addWidget(refreshConnectionButton_);
    connectionControlLayout_->addWidget(autoRefreshConnectionButton_);
    connectionControlLayout_->addWidget(terminateTcpButton_);
    connectionControlLayout_->addWidget(clearConnectionPidFilterButton_);
    connectionControlLayout_->addWidget(connectionStatusLabel_, 1);
    connectionManageLayout_->addLayout(connectionControlLayout_);

    // Sub-tabs: display TCP and UDP separately.
    connectionSubTabWidget_ = new QTabWidget(connectionManagePage_);
    connectionSubTabWidget_->setTabPosition(QTabWidget::North);
    connectionSubTabWidget_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    connectionManageLayout_->addWidget(connectionSubTabWidget_, 1);

    // TCP table: Status, PID, Process, Local Endpoint, Remote Endpoint.
    tcpConnectionTable_ = new ks::ui::VisibleTableWidget(connectionManagePage_);
    tcpConnectionTable_->setColumnCount(toTcpConnectionColumn(TcpConnectionTableColumn::kCount));
    tcpConnectionTable_->setHorizontalHeaderLabels({
        QStringLiteral("状态"),
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点"),
        QStringLiteral("远端端点")
        });
    tcpConnectionTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tcpConnectionTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    tcpConnectionTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    tcpConnectionTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    tcpConnectionTable_->verticalHeader()->setVisible(false);
    tcpConnectionTable_->horizontalHeader()->setStretchLastSection(true);
    tcpConnectionTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    connectionSubTabWidget_->addTab(tcpConnectionTable_, QIcon(":/Icon/process_main.svg"), QStringLiteral("TCP"));
    ks::i18n::LanguageManager::instance().bindTab(
        connectionSubTabWidget_,
        tcpConnectionTable_,
        QStringLiteral("network.tab.tcp"),
        QStringLiteral("TCP"));

    // UDP table: PID, process, local endpoint.
    udpEndpointTable_ = new ks::ui::VisibleTableWidget(connectionManagePage_);
    udpEndpointTable_->setColumnCount(toUdpEndpointColumn(UdpEndpointTableColumn::kCount));
    udpEndpointTable_->setHorizontalHeaderLabels({
        QStringLiteral("PID"),
        QStringLiteral("进程"),
        QStringLiteral("本地端点")
        });
    udpEndpointTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    udpEndpointTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    udpEndpointTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    udpEndpointTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    udpEndpointTable_->verticalHeader()->setVisible(false);
    udpEndpointTable_->horizontalHeader()->setStretchLastSection(true);
    udpEndpointTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    connectionSubTabWidget_->addTab(udpEndpointTable_, QIcon(":/Icon/process_main.svg"), QStringLiteral("UDP"));
    ks::i18n::LanguageManager::instance().bindTab(
        connectionSubTabWidget_,
        udpEndpointTable_,
        QStringLiteral("network.tab.udp"),
        QStringLiteral("UDP"));

    sideTabWidget_->addTab(connectionManagePage_, QIcon(":/Icon/process_details.svg"), QStringLiteral("连接管理"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, connectionManagePage_, QStringLiteral("network.tab.connections"), QStringLiteral("连接管理"));

    KLogEvent initConnectionTabEvent;
    info << initConnectionTabEvent << "[NetworkDock] 连接管理页初始化完成（TCP/UDP）。" << eol;
}

void NetworkDock::initializeFirewallTab()
{
    // Firewall page:
    // - Input: None; the page dynamically loads fwpuclnt.dll internally and manages the WFP engine;
    // - Processing: Independently display historical/real-time firewall events without reusing traffic capture pipelines.
    // - Return: None; presented as the top-level tab of NetworkDock.
    firewallPage_ = new NetworkFirewallPage(this);
    sideTabWidget_->addTab(
        firewallPage_,
        QIcon(QStringLiteral(":/Icon/process_critical.svg")),
        QStringLiteral("防火墙"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, firewallPage_, QStringLiteral("network.tab.firewall"), QStringLiteral("防火墙"));
}

void NetworkDock::initializeNetworkAuditTab()
{
    // Network audit page:
    // - Take over the original connection management page's operational capabilities for TCP/UDP Cross-View.
    // - AFD, WFP, NDIS, and NSI partitions remain read-only;
    // - Do not create a separate top-level entry for 'Connection Management' to avoid functional duplication.
    networkAuditPage_ = new NetworkAuditPage(this);
    networkAuditPage_->setTrackProcessHandler([this](const std::uint32_t processId)
    {
        addOrTrackProcessPid(processId);

        KLogEvent trackEvent;
        info << trackEvent
            << "[NetworkDock] 跟踪此进程触发, pid=" << processId
            << eol;
    });
    networkAuditPage_->setOpenProcessDetailHandler([this](const std::uint32_t processId)
    {
        ks::process::ProcessRecord processRecord;
        processRecord.pid = processId;
        processRecord.processName = ks::process::getProcessNameByPid(processId);
        if (processRecord.processName.empty())
        {
            processRecord.processName = "PID_" + std::to_string(processId);
        }

        ProcessDetailWindow* detailWindow = new ProcessDetailWindow(processRecord, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindow->setWindowFlag(Qt::Window, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();

        KLogEvent detailEvent;
        info << detailEvent
            << "[NetworkDock] 打开进程详情窗口, pid=" << processId
            << eol;
    });
    networkAuditPage_->setUdpEndpointBlockRuleHandler(
        [this](const std::uint32_t processId, const QString& localEndpointText)
    {
        if (firewallPage_ != nullptr)
        {
            firewallPage_->addUdpEndpointBlockRuleFromEvidence(localEndpointText, processId);
        }
    });
    sideTabWidget_->addTab(
        networkAuditPage_,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("网络审计"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, networkAuditPage_, QStringLiteral("network.tab.audit"), QStringLiteral("网络审计"));
}

void NetworkDock::initializeManualRequestTab()
{
    // The request construction page uses a "grouped parameters + execution result" layout, aligning with the style of the CreateProcess page.
    manualRequestPage_ = new QWidget(this);
    manualRequestLayout_ = new QVBoxLayout(manualRequestPage_);
    manualRequestLayout_->setContentsMargins(6, 6, 6, 6);
    manualRequestLayout_->setSpacing(6);

    // Key change (to prevent scrollbars from appearing in narrow windows):
    // 1) Removes the outer QScrollArea to prevent extra scrollbars from appearing when the page width changes;
    // 2) Change to directly attach each function group to the page's main layout, letting the layout system handle adaptive compression.
    QWidget* contentWidget = manualRequestPage_;
    QVBoxLayout* contentLayout = manualRequestLayout_;
    contentLayout->setContentsMargins(2, 2, 2, 2);
    contentLayout->setSpacing(8);

    // 1) Group API and socket parameters: supports mode switching and manual override of underlying parameters.
    QGroupBox* apiGroup = new QGroupBox(QStringLiteral("API 与 Socket 参数"), contentWidget);
    QGridLayout* apiLayout = new QGridLayout(apiGroup);
    apiLayout->setHorizontalSpacing(8);
    apiLayout->setVerticalSpacing(6);
    apiLayout->setColumnStretch(1, 1);
    apiLayout->setColumnStretch(3, 1);

    manualApiCombo_ = new QComboBox(apiGroup);
    manualApiCombo_->addItem(QStringLiteral("WinSock TCP 请求"), static_cast<int>(ks::network::ManualNetworkApiKind::kWinSockTcp));
    manualApiCombo_->addItem(QStringLiteral("WinSock UDP 请求"), static_cast<int>(ks::network::ManualNetworkApiKind::kWinSockUdp));
    manualApiCombo_->setToolTip(QStringLiteral("切换请求模式：TCP（connect/send/recv）或 UDP。"));

    manualOverrideSocketParameterCheck_ = new QCheckBox(QStringLiteral("手动覆盖 socket 参数"), apiGroup);
    manualOverrideSocketParameterCheck_->setToolTip(
        QStringLiteral("关闭时按模式自动填充 socketType/protocol；开启后使用你填写的底层参数。"));

    manualAddressFamilyEdit_ = new QLineEdit(QStringLiteral("2"), apiGroup);     // AF_INET
    manualSocketTypeEdit_ = new QLineEdit(QStringLiteral("1"), apiGroup);        // SOCK_STREAM
    manualProtocolEdit_ = new QLineEdit(QStringLiteral("6"), apiGroup);          // IPPROTO_TCP
    manualSocketFlagsEdit_ = new QLineEdit(QStringLiteral("0x1"), apiGroup);     // WSA_FLAG_OVERLAPPED
    manualAddressFamilyEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    manualSocketTypeEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    manualProtocolEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    manualSocketFlagsEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    apiLayout->addWidget(new QLabel(QStringLiteral("请求模式:"), apiGroup), 0, 0);
    apiLayout->addWidget(manualApiCombo_, 0, 1, 1, 3);
    apiLayout->addWidget(manualOverrideSocketParameterCheck_, 1, 0, 1, 4);
    apiLayout->addWidget(new QLabel(QStringLiteral("addressFamily:"), apiGroup), 2, 0);
    apiLayout->addWidget(manualAddressFamilyEdit_, 2, 1);
    apiLayout->addWidget(new QLabel(QStringLiteral("socketType:"), apiGroup), 2, 2);
    apiLayout->addWidget(manualSocketTypeEdit_, 2, 3);
    apiLayout->addWidget(new QLabel(QStringLiteral("protocol:"), apiGroup), 3, 0);
    apiLayout->addWidget(manualProtocolEdit_, 3, 1);
    apiLayout->addWidget(new QLabel(QStringLiteral("socketFlags:"), apiGroup), 3, 2);
    apiLayout->addWidget(manualSocketFlagsEdit_, 3, 3);
    contentLayout->addWidget(apiGroup);

    // 2) Endpoint and behavior parameters group: covers details like bind/connect/timeout/options.
    QGroupBox* endpointGroup = new QGroupBox(QStringLiteral("端点与行为参数"), contentWidget);
    QGridLayout* endpointLayout = new QGridLayout(endpointGroup);
    endpointLayout->setHorizontalSpacing(8);
    endpointLayout->setVerticalSpacing(6);
    endpointLayout->setColumnStretch(1, 1);
    endpointLayout->setColumnStretch(3, 1);

    manualEnableBindCheck_ = new QCheckBox(QStringLiteral("启用本地 bind"), endpointGroup);
    manualEnableBindCheck_->setToolTip(QStringLiteral("勾选后先 bind(localAddress:localPort) 再执行连接/发送。"));
    manualLocalAddressEdit_ = new QLineEdit(QStringLiteral("0.0.0.0"), endpointGroup);
    manualLocalAddressEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    manualLocalPortSpin_ = new QSpinBox(endpointGroup);
    manualLocalPortSpin_->setRange(0, 65535);
    manualLocalPortSpin_->setValue(0);

    manualRemoteAddressEdit_ = new QLineEdit(QStringLiteral("127.0.0.1"), endpointGroup);
    manualRemoteAddressEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    manualRemotePortSpin_ = new QSpinBox(endpointGroup);
    manualRemotePortSpin_->setRange(0, 65535);
    manualRemotePortSpin_->setValue(80);

    manualConnectBeforeSendCheck_ = new QCheckBox(QStringLiteral("发送前 connect"), endpointGroup);
    manualConnectBeforeSendCheck_->setChecked(true);
    manualConnectBeforeSendCheck_->setToolTip(QStringLiteral("UDP 关闭该项时会改用 sendto/recvfrom。"));

    manualReuseAddressCheck_ = new QCheckBox(QStringLiteral("SO_REUSEADDR"), endpointGroup);
    manualNoDelayCheck_ = new QCheckBox(QStringLiteral("TCP_NODELAY"), endpointGroup);

    manualSendTimeoutSpin_ = new QSpinBox(endpointGroup);
    manualSendTimeoutSpin_->setRange(0, 60 * 60 * 1000);
    manualSendTimeoutSpin_->setValue(3000);
    manualRecvTimeoutSpin_ = new QSpinBox(endpointGroup);
    manualRecvTimeoutSpin_->setRange(0, 60 * 60 * 1000);
    manualRecvTimeoutSpin_->setValue(3000);

    manualSendFlagsEdit_ = new QLineEdit(QStringLiteral("0"), endpointGroup);
    manualReceiveFlagsEdit_ = new QLineEdit(QStringLiteral("0"), endpointGroup);
    manualSendFlagsEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    manualReceiveFlagsEdit_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    endpointLayout->addWidget(manualEnableBindCheck_, 0, 0, 1, 2);
    endpointLayout->addWidget(new QLabel(QStringLiteral("本地地址:"), endpointGroup), 1, 0);
    endpointLayout->addWidget(manualLocalAddressEdit_, 1, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("本地端口:"), endpointGroup), 1, 2);
    endpointLayout->addWidget(manualLocalPortSpin_, 1, 3);
    endpointLayout->addWidget(new QLabel(QStringLiteral("远端地址:"), endpointGroup), 2, 0);
    endpointLayout->addWidget(manualRemoteAddressEdit_, 2, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("远端端口:"), endpointGroup), 2, 2);
    endpointLayout->addWidget(manualRemotePortSpin_, 2, 3);
    endpointLayout->addWidget(manualConnectBeforeSendCheck_, 3, 0, 1, 2);
    endpointLayout->addWidget(manualReuseAddressCheck_, 3, 2);
    endpointLayout->addWidget(manualNoDelayCheck_, 3, 3);
    endpointLayout->addWidget(new QLabel(QStringLiteral("发送超时(ms):"), endpointGroup), 4, 0);
    endpointLayout->addWidget(manualSendTimeoutSpin_, 4, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("接收超时(ms):"), endpointGroup), 4, 2);
    endpointLayout->addWidget(manualRecvTimeoutSpin_, 4, 3);
    endpointLayout->addWidget(new QLabel(QStringLiteral("sendFlags:"), endpointGroup), 5, 0);
    endpointLayout->addWidget(manualSendFlagsEdit_, 5, 1);
    endpointLayout->addWidget(new QLabel(QStringLiteral("recvFlags:"), endpointGroup), 5, 2);
    endpointLayout->addWidget(manualReceiveFlagsEdit_, 5, 3);
    contentLayout->addWidget(endpointGroup);

    // 3) Group payload and received parameters: support text/HEX input and response read toggle.
    QGroupBox* payloadGroup = new QGroupBox(QStringLiteral("载荷与响应读取"), contentWidget);
    QGridLayout* payloadLayout = new QGridLayout(payloadGroup);
    payloadLayout->setHorizontalSpacing(8);
    payloadLayout->setVerticalSpacing(6);
    payloadLayout->setColumnStretch(1, 1);
    payloadLayout->setColumnStretch(4, 1);

    manualPayloadFormatCombo_ = new QComboBox(payloadGroup);
    manualPayloadFormatCombo_->addItem(QStringLiteral("ASCII 文本"), static_cast<int>(ks::network::ManualPayloadFormat::kAsciiText));
    manualPayloadFormatCombo_->addItem(QStringLiteral("十六进制字节"), static_cast<int>(ks::network::ManualPayloadFormat::kHexBytes));
    manualPayloadFormatCombo_->setToolTip(QStringLiteral("十六进制模式示例：48 65 6C 6C 6F"));

    manualPayloadEditor_ = new QPlainTextEdit(payloadGroup);
    manualPayloadEditor_->setPlaceholderText(QStringLiteral("在此输入请求载荷。"));
    manualPayloadEditor_->setFixedHeight(96);
    manualPayloadEditor_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    manualPayloadEditor_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    manualReceiveAfterSendCheck_ = new QCheckBox(QStringLiteral("发送后读取响应"), payloadGroup);
    manualReceiveAfterSendCheck_->setChecked(true);
    manualReceiveMaxBytesSpin_ = new QSpinBox(payloadGroup);
    manualReceiveMaxBytesSpin_->setRange(1, 1024 * 1024);
    manualReceiveMaxBytesSpin_->setValue(4096);
    manualShutdownSendCheck_ = new QCheckBox(QStringLiteral("发送后 shutdown(SD_SEND)"), payloadGroup);
    manualShutdownSendCheck_->setChecked(false);

    payloadLayout->addWidget(new QLabel(QStringLiteral("载荷格式:"), payloadGroup), 0, 0);
    payloadLayout->addWidget(manualPayloadFormatCombo_, 0, 1);
    payloadLayout->addWidget(manualReceiveAfterSendCheck_, 0, 2);
    payloadLayout->addWidget(new QLabel(QStringLiteral("最大读取字节:"), payloadGroup), 0, 3);
    payloadLayout->addWidget(manualReceiveMaxBytesSpin_, 0, 4);
    payloadLayout->addWidget(manualShutdownSendCheck_, 1, 0, 1, 2);
    payloadLayout->addWidget(manualPayloadEditor_, 2, 0, 1, 5);
    contentLayout->addWidget(payloadGroup);

    // 4) Group Execution and Results: execution requests, reset parameters, and output result logs.
    QGroupBox* actionGroup = new QGroupBox(QStringLiteral("执行与结果"), contentWidget);
    QVBoxLayout* actionLayout = new QVBoxLayout(actionGroup);
    QHBoxLayout* actionButtonLayout = new QHBoxLayout();

    manualExecuteButton_ = new QPushButton(QStringLiteral("执行请求"), actionGroup);
    manualExecuteButton_->setIcon(QIcon(":/Icon/process_start.svg"));
    manualExecuteButton_->setToolTip(QStringLiteral("按上方参数立即执行一次网络请求。"));

    manualResetButton_ = new QPushButton(QStringLiteral("恢复默认参数"), actionGroup);
    manualResetButton_->setIcon(QIcon(":/Icon/log_clear.svg"));
    manualResetButton_->setToolTip(QStringLiteral("重置请求构造页全部参数。"));

    actionButtonLayout->addWidget(manualExecuteButton_);
    actionButtonLayout->addWidget(manualResetButton_);
    actionButtonLayout->addStretch(1);

    manualResultOutput_ = new QPlainTextEdit(actionGroup);
    manualResultOutput_->setReadOnly(true);
    manualResultOutput_->setMaximumBlockCount(800);
    manualResultOutput_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    manualResultOutput_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    manualResultOutput_->setPlaceholderText(QStringLiteral("执行结果、响应摘要和错误码会显示在这里。"));

    actionLayout->addLayout(actionButtonLayout);
    actionLayout->addWidget(manualResultOutput_, 1);
    contentLayout->addWidget(actionGroup, 1);

    // After building, pre-fill a set of 'executable' parameters in default mode.
    resetManualRequestForm();

    sideTabWidget_->addTab(manualRequestPage_, QIcon(":/Icon/process_main.svg"), QStringLiteral("请求构造"));
    ks::i18n::LanguageManager::instance().bindTab(
        sideTabWidget_, manualRequestPage_, QStringLiteral("network.tab.manual_request"), QStringLiteral("请求构造"));

    KLogEvent initManualTabEvent;
    info << initManualTabEvent << "[NetworkDock] 请求构造页初始化完成。" << eol;
}

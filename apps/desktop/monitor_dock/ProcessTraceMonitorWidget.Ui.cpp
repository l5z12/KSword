#include "ProcessTraceMonitorWidget.h"
#include "../ui/VisibleTableWidget.h"
#include "../ui/ThemeStatusRole.h"

// ============================================================
// ProcessTraceMonitorWidget.Ui.cpp
// Purpose:
// 1) Build all visible controls for the process-oriented monitoring page.
// 2) Unify button icons, tooltip text, and table layout;
// 3) Keep the single file size manageable to avoid further growth of MonitorDock.cpp.
// ============================================================

#include "../Theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QFrame>
#include <QGridLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QSizePolicy>
#include <QSplitter>
#include <QSvgRenderer>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace
{
    // createBlueIcon：
    // - Purpose: Uniformly tints SVG icons to the theme blue.
    // - Usage: All simple semantic buttons on this page use icons instead of text.
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize = QSize(16, 16))
    {
        const QString kIconPath = QString::fromUtf8(resourcePath);
        QSvgRenderer renderer(kIconPath);
        if (!renderer.isValid())
        {
            return QIcon(kIconPath);
        }

        QPixmap pixmap(iconSize);
        pixmap.fill(Qt::transparent);

        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(pixmap.rect(), ksword_theme::primaryBlueColor);
        painter.end();

        return QIcon(pixmap);
    }

    // createIconButton：
    // - Purpose: Uniformly create pure icon buttons and force writing the tooltip.
    // - Call: All simple semantic buttons (refresh/add/start/stop/export) are reused here.
    QPushButton* createIconButton(
        QWidget* parentWidget,
        const char* resourcePath,
        const QString& tooltipText)
    {
        QPushButton* buttonPointer = new QPushButton(parentWidget);
        buttonPointer->setIcon(createBlueIcon(resourcePath, QSize(16, 16)));
        buttonPointer->setText(QString());
        buttonPointer->setToolTip(tooltipText);
        buttonPointer->setFixedSize(QSize(28, 28));
        return buttonPointer;
    }

}

QWidget* ProcessTraceMonitorWidget::createConfigurationCollapseSection(
    QWidget* parentWidget,
    const QString& titleText,
    QWidget* contentWidget,
    const bool expanded) const
{
    // Outer collapsible section:
    // - Use the same dynamic property as the existing Collapse in MonitorDock;
    // - Maximum vertical strategy ensures configuration sections participate in layout based on content height, without encroaching on the event table's elastic area.
    QWidget* sectionWidget = new QWidget(parentWidget);
    sectionWidget->setProperty("kswordCollapsePanel", QStringLiteral("true"));
    sectionWidget->setStyleSheet(collapsePanelStyle());
    sectionWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

    QVBoxLayout* sectionLayout = new QVBoxLayout(sectionWidget);
    sectionLayout->setContentsMargins(0, 0, 0, 0);
    sectionLayout->setSpacing(0);

    // Collapsed header:
    // - Expanded by default; arrow direction and checked state remain synchronized.
    // - After user collapses, only hide configuration content; do not affect the timeline or the table below.
    QToolButton* headerButton = new QToolButton(sectionWidget);
    headerButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    headerButton->setText(titleText);
    headerButton->setCheckable(true);
    headerButton->setChecked(expanded);
    headerButton->setArrowType(expanded ? Qt::DownArrow : Qt::RightArrow);
    headerButton->setStyleSheet(collapseHeaderButtonStyle());
    headerButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Content Host:
    // - Wraps in a separate layer to reuse the kswordCollapseContent style.
    // - The content page is built by initializeUi and handed over to the host layout for hosting.
    QWidget* contentHostWidget = new QWidget(sectionWidget);
    contentHostWidget->setProperty("kswordCollapseContent", QStringLiteral("true"));
    contentHostWidget->setStyleSheet(collapsePanelStyle());
    contentHostWidget->setVisible(expanded);
    contentHostWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);

    QVBoxLayout* contentHostLayout = new QVBoxLayout(contentHostWidget);
    contentHostLayout->setContentsMargins(4, 4, 4, 4);
    contentHostLayout->setSpacing(4);
    contentHostLayout->addWidget(contentWidget);

    sectionLayout->addWidget(headerButton, 0);
    sectionLayout->addWidget(contentHostWidget, 0);

    QObject::connect(headerButton, &QToolButton::toggled, sectionWidget,
        [headerButton, contentHostWidget, sectionWidget](const bool checked) {
            // Only collapse the configuration content area; the timeline and event table remain unaffected.
            // After collapsing, the root layout passes all released height to the event table below.
            headerButton->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
            contentHostWidget->setVisible(checked);
            sectionWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
            sectionWidget->updateGeometry();
            if (QWidget* parentPointer = sectionWidget->parentWidget())
            {
                parentPointer->updateGeometry();
            }
        });

    return sectionWidget;
}

void ProcessTraceMonitorWidget::initializeUi()
{
    // Root layout:
    // - Top: Optional dual-column layout for processes and monitoring targets;
    // - Middle: Fixed provider description and start/stop controls;
    // - Below: filter + event table.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    // Top configuration content is unified into a default expanded Collapse:
    // - Includes optional processes, monitoring targets, control bar, and event filter area.
    // Do not place the timeline in the collapsible section to maintain a continuously visible time window for interaction.
    // - The vertical policy for the collapsed section is Maximum to avoid encroaching on the remaining space of the event table below.
    configurationPanel_ = new QWidget(this);
    configurationPanel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Maximum);
    QVBoxLayout* configurationLayout = new QVBoxLayout(configurationPanel_);
    configurationLayout->setContentsMargins(0, 0, 0, 0);
    configurationLayout->setSpacing(6);

    topSplitter_ = new QSplitter(Qt::Horizontal, configurationPanel_);
    configurationLayout->addWidget(topSplitter_, 0);

    // Optional process panel:
    // - Provides current process snapshots, keyword filtering, and an 'Add to Monitoring Target' entry point;
    // - Place manual PID addition and filter bar on the same line to reduce vertical space usage at the top.
    availablePanel_ = new QWidget(topSplitter_);
    QVBoxLayout* availableLayout = new QVBoxLayout(availablePanel_);
    availableLayout->setContentsMargins(6, 6, 6, 6);
    availableLayout->setSpacing(6);

    QHBoxLayout* availableHeaderLayout = new QHBoxLayout();
    availableHeaderLayout->setSpacing(6);
    availableHeaderLayout->addWidget(new QLabel(QStringLiteral("可选进程"), availablePanel_), 0);

    availableFilterEdit_ = new QLineEdit(availablePanel_);
    availableFilterEdit_->setPlaceholderText(QStringLiteral("按 PID / 进程名 / 路径 / 用户过滤"));
    availableFilterEdit_->setStyleSheet(blueInputStyle());
    availableFilterEdit_->setMaximumWidth(320);
    availableHeaderLayout->addWidget(availableFilterEdit_, 1);

    availableRefreshButton_ = createIconButton(
        availablePanel_,
        ":/Icon/process_refresh.svg",
        QStringLiteral("刷新当前系统进程快照"));
    availableRefreshButton_->setStyleSheet(blueButtonStyle());
    availableHeaderLayout->addWidget(availableRefreshButton_, 0);

    createTargetButton_ = createIconButton(
        availablePanel_,
        ":/Icon/plus.svg",
        QStringLiteral("创建并挂起监控目标"));
    createTargetButton_->setStyleSheet(blueButtonStyle());
    availableHeaderLayout->addWidget(createTargetButton_, 0);

    addSelectedButton_ = createIconButton(
        availablePanel_,
        ":/Icon/process_start.svg",
        QStringLiteral("把选中的进程加入监控目标"));
    addSelectedButton_->setStyleSheet(blueButtonStyle());
    availableHeaderLayout->addWidget(addSelectedButton_, 0);
    availableHeaderLayout->addWidget(new QLabel(QStringLiteral("手动 PID"), availablePanel_), 0);

    manualPidEdit_ = new QLineEdit(availablePanel_);
    manualPidEdit_->setPlaceholderText(QStringLiteral("输入十进制或 0x 十六进制 PID"));
    manualPidEdit_->setStyleSheet(blueInputStyle());
    manualPidEdit_->setMinimumWidth(120);
    manualPidEdit_->setMaximumWidth(160);
    availableHeaderLayout->addWidget(manualPidEdit_, 0);

    addManualPidButton_ = createIconButton(
        availablePanel_,
        ":/Icon/process_details.svg",
        QStringLiteral("按输入 PID 加入监控目标"));
    addManualPidButton_->setStyleSheet(blueButtonStyle());
    availableHeaderLayout->addWidget(addManualPidButton_, 0);

    availableLayout->addLayout(availableHeaderLayout);

    availableStatusLabel_ = new QLabel(QStringLiteral("● 等待首次刷新进程快照"), availablePanel_);
    ks::ui::applyStatusRole(availableStatusLabel_, ks::ui::StatusRole::kIdle);
    availableLayout->addWidget(availableStatusLabel_, 0);

    availableTable_ = new ks::ui::VisibleTableWidget(availablePanel_);
    availableTable_->setColumnCount(kAvailableProcessColumnCount);
    availableTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("路径"),
        QStringLiteral("用户")
        });
    availableTable_->setAlternatingRowColors(true);
    availableTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    availableTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    availableTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // The optional process table also allows right-clicking to copy the current/selected row:
    // - Copy action does not change monitoring state.
    // - The target's running state is uniformly checked in Actions.cpp to avoid modifying the root target during collection.
    availableTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    availableTable_->setSortingEnabled(false);
    availableTable_->verticalHeader()->setVisible(false);
    availableTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    availableTable_->setStyleSheet(blueInputStyle());
    availableTable_->setAutoFillBackground(false);
    availableTable_->setAttribute(Qt::WA_StyledBackground, true);
    if (availableTable_->viewport() != nullptr)
    {
        availableTable_->viewport()->setAutoFillBackground(false);
        availableTable_->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    availableTable_->horizontalHeader()->setSectionResizeMode(kAvailableProcessColumnPid, QHeaderView::ResizeToContents);
    availableTable_->horizontalHeader()->setSectionResizeMode(kAvailableProcessColumnName, QHeaderView::ResizeToContents);
    availableTable_->horizontalHeader()->setSectionResizeMode(kAvailableProcessColumnPath, QHeaderView::Stretch);
    availableTable_->horizontalHeader()->setSectionResizeMode(kAvailableProcessColumnUser, QHeaderView::ResizeToContents);
    availableLayout->addWidget(availableTable_, 1);

    // Monitor target panel:
    // - By default, display the target process manually selected by the user.
    // - At runtime, if ETW detects the target process spawning a child process, it is also automatically added to this list.
    // - When a process in the list receives an ETW exit event, it is automatically removed from this list.
    targetPanel_ = new QWidget(topSplitter_);
    QVBoxLayout* targetLayout = new QVBoxLayout(targetPanel_);
    targetLayout->setContentsMargins(6, 6, 6, 6);
    targetLayout->setSpacing(6);

    QHBoxLayout* targetHeaderLayout = new QHBoxLayout();
    targetHeaderLayout->setSpacing(6);
    targetHeaderLayout->addWidget(new QLabel(QStringLiteral("监控目标"), targetPanel_), 0);
    targetHeaderLayout->addStretch(1);

    removeTargetButton_ = createIconButton(
        targetPanel_,
        ":/Icon/process_pause.svg",
        QStringLiteral("移除选中的监控目标"));
    removeTargetButton_->setStyleSheet(blueButtonStyle());
    targetHeaderLayout->addWidget(removeTargetButton_, 0);

    clearTargetButton_ = createIconButton(
        targetPanel_,
        ":/Icon/process_terminate.svg",
        QStringLiteral("清空全部监控目标"));
    clearTargetButton_->setStyleSheet(blueButtonStyle());
    targetHeaderLayout->addWidget(clearTargetButton_, 0);

    targetLayout->addLayout(targetHeaderLayout);

    targetStatusLabel_ = new QLabel(QStringLiteral("● 当前没有监控目标"), targetPanel_);
    ks::ui::applyStatusRole(targetStatusLabel_, ks::ui::StatusRole::kIdle);
    targetLayout->addWidget(targetStatusLabel_, 0);

    targetTable_ = new ks::ui::VisibleTableWidget(targetPanel_);
    targetTable_->setColumnCount(kTargetProcessColumnCount);
    targetTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("状态"),
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("路径"),
        QStringLiteral("用户"),
        QStringLiteral("备注")
        });
    targetTable_->setAlternatingRowColors(true);
    targetTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    targetTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    targetTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    targetTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    targetTable_->verticalHeader()->setVisible(false);
    targetTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    targetTable_->setStyleSheet(blueInputStyle());
    targetTable_->setAutoFillBackground(false);
    targetTable_->setAttribute(Qt::WA_StyledBackground, true);
    if (targetTable_->viewport() != nullptr)
    {
        targetTable_->viewport()->setAutoFillBackground(false);
        targetTable_->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    targetTable_->horizontalHeader()->setSectionResizeMode(kTargetProcessColumnState, QHeaderView::ResizeToContents);
    targetTable_->horizontalHeader()->setSectionResizeMode(kTargetProcessColumnPid, QHeaderView::ResizeToContents);
    targetTable_->horizontalHeader()->setSectionResizeMode(kTargetProcessColumnName, QHeaderView::ResizeToContents);
    targetTable_->horizontalHeader()->setSectionResizeMode(kTargetProcessColumnPath, QHeaderView::Stretch);
    targetTable_->horizontalHeader()->setSectionResizeMode(kTargetProcessColumnUser, QHeaderView::ResizeToContents);
    targetTable_->horizontalHeader()->setSectionResizeMode(kTargetProcessColumnRemark, QHeaderView::ResizeToContents);
    targetLayout->addWidget(targetTable_, 1);

    topSplitter_->addWidget(availablePanel_);
    topSplitter_->addWidget(targetPanel_);
    topSplitter_->setStretchFactor(0, 2);
    topSplitter_->setStretchFactor(1, 3);

    // Control bar:
    // - The middle section strictly adopts 'full pre-configured Provider + process tree auxiliary snapshot'.
    // - Users no longer manually select event types; the program covers them as broadly as possible.
    controlPanel_ = new QWidget(configurationPanel_);
    QHBoxLayout* controlLayout = new QHBoxLayout(controlPanel_);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    controlLayout->setSpacing(6);

    // Move the collection-policy explanation into the start button's tooltip so a permanent line of text no longer occupies the control bar.
    startButton_ = createIconButton(
        controlPanel_,
        ":/Icon/process_start.svg",
        QStringLiteral("开始监控已选择的目标进程。固定启用宽覆盖 ETW Provider，结合进程快照维护目标进程树，只保留与目标有关的事件。"));
    startButton_->setStyleSheet(blueButtonStyle());
    controlLayout->addWidget(startButton_, 0);

    stopButton_ = createIconButton(
        controlPanel_,
        ":/Icon/process_terminate.svg",
        QStringLiteral("停止当前进程定向监控"));
    stopButton_->setStyleSheet(blueButtonStyle());
    controlLayout->addWidget(stopButton_, 0);

    pauseButton_ = createIconButton(
        controlPanel_,
        ":/Icon/process_pause.svg",
        QStringLiteral("暂停处理与目标进程相关的事件"));
    pauseButton_->setStyleSheet(blueButtonStyle());
    controlLayout->addWidget(pauseButton_, 0);

    exportButton_ = createIconButton(
        controlPanel_,
        ":/Icon/log_export.svg",
        QStringLiteral("导出当前事件表中可见的结果"));
    exportButton_->setStyleSheet(blueButtonStyle());
    controlLayout->addWidget(exportButton_, 0);

    statusLabel_ = new QLabel(QStringLiteral("● 空闲"), controlPanel_);
    ks::ui::applyStatusRole(statusLabel_, ks::ui::StatusRole::kIdle);
    controlLayout->addWidget(statusLabel_, 0);

    configurationLayout->addWidget(controlPanel_, 0);

    // Event filter area:
    // - Use a dropdown for the type field, and text filters for other fields.
    // - After the results table refreshes, applyEventFilter is invoked uniformly to maintain interaction consistency.
    filterPanel_ = new QWidget(configurationPanel_);
    QGridLayout* filterLayout = new QGridLayout(filterPanel_);
    filterLayout->setContentsMargins(6, 6, 6, 6);
    filterLayout->setHorizontalSpacing(6);
    filterLayout->setVerticalSpacing(6);

    filterLayout->addWidget(new QLabel(QStringLiteral("类型"), filterPanel_), 0, 0);
    eventTypeCombo_ = new QComboBox(filterPanel_);
    eventTypeCombo_->setStyleSheet(blueInputStyle());
    eventTypeCombo_->addItems(QStringList{
        QStringLiteral("全部类型"),
        QStringLiteral("进程"),
        QStringLiteral("线程"),
        QStringLiteral("镜像"),
        QStringLiteral("文件"),
        QStringLiteral("注册表"),
        QStringLiteral("网络"),
        QStringLiteral("DNS"),
        QStringLiteral("PowerShell"),
        QStringLiteral("WMI"),
        QStringLiteral("计划任务"),
        QStringLiteral("安全审计"),
        QStringLiteral("Defender"),
        QStringLiteral("其他")
        });
    filterLayout->addWidget(eventTypeCombo_, 0, 1);

    filterLayout->addWidget(new QLabel(QStringLiteral("Provider"), filterPanel_), 0, 2);
    eventProviderFilterEdit_ = new QLineEdit(filterPanel_);
    eventProviderFilterEdit_->setPlaceholderText(QStringLiteral("Provider 名称"));
    eventProviderFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(eventProviderFilterEdit_, 0, 3);

    filterLayout->addWidget(new QLabel(QStringLiteral("进程"), filterPanel_), 0, 4);
    eventProcessFilterEdit_ = new QLineEdit(filterPanel_);
    eventProcessFilterEdit_->setPlaceholderText(QStringLiteral("PID / 根 PID / 进程名 / 关系"));
    eventProcessFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(eventProcessFilterEdit_, 0, 5);

    filterLayout->addWidget(new QLabel(QStringLiteral("事件"), filterPanel_), 0, 6);
    eventNameFilterEdit_ = new QLineEdit(filterPanel_);
    eventNameFilterEdit_->setPlaceholderText(QStringLiteral("事件名或事件 ID"));
    eventNameFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(eventNameFilterEdit_, 0, 7);

    filterLayout->addWidget(new QLabel(QStringLiteral("详情"), filterPanel_), 1, 0);
    eventDetailFilterEdit_ = new QLineEdit(filterPanel_);
    eventDetailFilterEdit_->setPlaceholderText(QStringLiteral("属性详情关键字"));
    eventDetailFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(eventDetailFilterEdit_, 1, 1, 1, 3);

    filterLayout->addWidget(new QLabel(QStringLiteral("全字段"), filterPanel_), 1, 4);
    eventGlobalFilterEdit_ = new QLineEdit(filterPanel_);
    eventGlobalFilterEdit_->setPlaceholderText(QStringLiteral("对整行文本做统一过滤"));
    eventGlobalFilterEdit_->setStyleSheet(blueInputStyle());
    filterLayout->addWidget(eventGlobalFilterEdit_, 1, 5, 1, 3);

    eventRegexCheck_ = new QCheckBox(QStringLiteral("正则"), filterPanel_);
    eventCaseCheck_ = new QCheckBox(QStringLiteral("区分大小写"), filterPanel_);
    eventInvertCheck_ = new QCheckBox(QStringLiteral("反向"), filterPanel_);
    eventKeepBottomCheck_ = new QCheckBox(QStringLiteral("保持贴底"), filterPanel_);
    eventRegexCheck_->setToolTip(QStringLiteral("把筛选内容当作正则表达式匹配，而不是普通文字"));
    eventCaseCheck_->setToolTip(QStringLiteral("筛选时区分英文字母大小写"));
    eventInvertCheck_->setToolTip(QStringLiteral("反向筛选：只显示不符合条件的记录"));
    eventKeepBottomCheck_->setToolTip(QStringLiteral("有新记录时自动滚动到底部，便于持续观察最新事件"));
    eventKeepBottomCheck_->setChecked(true);
    filterLayout->addWidget(eventRegexCheck_, 2, 0);
    filterLayout->addWidget(eventCaseCheck_, 2, 1);
    filterLayout->addWidget(eventInvertCheck_, 2, 2);
    filterLayout->addWidget(eventKeepBottomCheck_, 2, 3);

    eventClearFilterButton_ = createIconButton(
        filterPanel_,
        ":/Icon/log_clear.svg",
        QStringLiteral("清空所有事件筛选条件"));
    eventClearFilterButton_->setStyleSheet(blueButtonStyle());
    filterLayout->addWidget(eventClearFilterButton_, 2, 4);

    eventFilterStatusLabel_ = new QLabel(QStringLiteral("筛选结果：0 / 0"), filterPanel_);
    ks::ui::applyStatusRole(eventFilterStatusLabel_, ks::ui::StatusRole::kIdle);
    filterLayout->addWidget(eventFilterStatusLabel_, 2, 5, 1, 3);

    configurationLayout->addWidget(filterPanel_, 0);

    configurationCollapseWidget_ = createConfigurationCollapseSection(
        this,
        QStringLiteral("进程定向配置 / 筛选"),
        configurationPanel_,
        true);
    rootLayout_->addWidget(configurationCollapseWidget_, 0);

    // ETW timeline:
    // - Fixed height of 40px; width automatically fills the root layout.
    // - This control maintains only the internal time selection range and does not derive the event set from graphical points in reverse;
    // - The selected results are combined with the existing post-filter in the event table below.
    eventTimelineWidget_ = new ProcessTraceTimelineWidget(this);
    eventTimelineWidget_->setToolTip(QStringLiteral(
        "ETW 事件瀑布流时间轴：拖动矩形移动时间窗口；拖动左右边调整边界；滚轮向上放大窗口、向下缩小窗口。"));
    rootLayout_->addWidget(eventTimelineWidget_, 0);

    // Event table:
    // - Retain columns for Type, Provider, Root PID, Relationship, etc., separately to facilitate subsequent filtering.
    // - Detail columns should preserve attribute summaries to facilitate subsequent text-based filtering by users.
    eventTable_ = new ks::ui::VisibleTableWidget(this);
    eventTable_->setColumnCount(kEventColumnCount);
    eventTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("时间(100ns)"),
        QStringLiteral("类型"),
        QStringLiteral("Provider"),
        QStringLiteral("事件ID"),
        QStringLiteral("事件名"),
        QStringLiteral("PID / TID"),
        QStringLiteral("进程"),
        QStringLiteral("根PID"),
        QStringLiteral("关系"),
        QStringLiteral("详情"),
        QStringLiteral("ActivityId")
        });
    eventTable_->setAlternatingRowColors(true);
    eventTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    eventTable_->setContextMenuPolicy(Qt::CustomContextMenu);
    eventTable_->verticalHeader()->setVisible(false);
    eventTable_->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    eventTable_->setStyleSheet(blueInputStyle());
    eventTable_->setAutoFillBackground(false);
    eventTable_->setAttribute(Qt::WA_StyledBackground, true);
    if (eventTable_->viewport() != nullptr)
    {
        eventTable_->viewport()->setAutoFillBackground(false);
        eventTable_->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    eventTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    eventTable_->setColumnWidth(kEventColumnTime100ns, 160);
    eventTable_->setColumnWidth(kEventColumnType, 82);
    eventTable_->setColumnWidth(kEventColumnProvider, 190);
    eventTable_->setColumnWidth(kEventColumnEventId, 80);
    eventTable_->setColumnWidth(kEventColumnEventName, 180);
    eventTable_->setColumnWidth(kEventColumnPidTid, 110);
    eventTable_->setColumnWidth(kEventColumnProcess, 180);
    eventTable_->setColumnWidth(kEventColumnRootPid, 86);
    eventTable_->setColumnWidth(kEventColumnRelation, 130);
    eventTable_->setColumnWidth(kEventColumnDetail, 440);
    eventTable_->setColumnWidth(kEventColumnActivityId, 260);
    eventTable_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    rootLayout_->addWidget(eventTable_, 1);

    // Timer:
    // - m_uiUpdateTimer: After the background thread batches enqueueing, the main thread refreshes the table at a fixed interval.
    // - m_runtimeRefreshTimer: Periodically refresh process snapshots during runtime to assist in maintaining the process tree.
    uiUpdateTimer_ = new QTimer(this);
    uiUpdateTimer_->setInterval(120);

    eventFilterDebounceTimer_ = new QTimer(this);
    eventFilterDebounceTimer_->setInterval(180);
    eventFilterDebounceTimer_->setSingleShot(true);

    runtimeRefreshTimer_ = new QTimer(this);
    runtimeRefreshTimer_->setInterval(2000);

    updateActionState();
    updateStatusLabel();
}

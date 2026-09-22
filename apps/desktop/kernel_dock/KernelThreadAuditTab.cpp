#include "KernelThreadAuditTab.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/DetailLayoutRegistry.h"
#include "../ui/TableInteractionSupport.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QCoreApplication>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

namespace
{
    // threadAuditText：
    // - Input key: Stable key in the language pack; fallbackText: Chinese fallback text;
    // - Processing: Uniformly route through LanguageManager context translation.
    // - Returns: Page text in the current language.
    QString threadAuditText(const char* key, const QString& fallbackText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), fallbackText);
    }

    constexpr std::uint32_t kWaitReasonQueue = 15U; // KWAIT_REASON::WrQueue。

    // menuStyle：
    // - Returns an opaque QMenu theme;
    // - Fixes the black background and black text issue caused by transparent menus in light mode.
    QString menuStyle()
    {
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;padding:4px;}"
            "QMenu::item{padding:5px 24px 5px 8px;}"
            "QMenu::item:selected{background:%4;color:%5;}"
            "QMenu::item:disabled{color:%6;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::borderHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::onAccentHex())
            .arg(ksword_theme::textSecondaryHex());
    }

    // messageBoxStyle：
    // - Explicitly set an opaque background for the danger operation confirmation dialog on this page.
    // - Ensure risk text is readable in both light and dark themes.
    QString messageBoxStyle()
    {
        return QStringLiteral(
            "QMessageBox{background:%1;color:%2;}"
            "QMessageBox QLabel{background:transparent;color:%2;min-width:440px;}"
            "QMessageBox QPushButton{min-width:90px;padding:6px 12px;}")
            .arg(ksword_theme::surfaceHex())
            .arg(ksword_theme::textPrimaryHex());
    }

    // showConfirmation：
    // - Input parent/title/body: Confirmation dialog parent and text content;
    // - Processing: explicit theme, Yes/No buttons, default No;
    // - Return: true if the user explicitly selects Yes.
    bool showConfirmation(QWidget* parent, const QString& titleText, const QString& bodyText)
    {
        QMessageBox confirmationBox(QMessageBox::Warning, titleText, bodyText, QMessageBox::NoButton, parent);
        confirmationBox.setStyleSheet(messageBoxStyle());
        confirmationBox.setTextFormat(Qt::PlainText);
        QPushButton* yesButton = confirmationBox.addButton(QMessageBox::Yes);
        QPushButton* noButton = confirmationBox.addButton(QMessageBox::No);
        confirmationBox.setDefaultButton(noButton);
        confirmationBox.setEscapeButton(noButton);
        confirmationBox.exec();
        return confirmationBox.clickedButton() == yesButton;
    }

    // showResultMessage：
    // - Input success: Determines whether to show an info or warning icon;
    // - Processing: Display a result popup with an opaque theme;
    // - Returns: Nothing.
    void showResultMessage(
        QWidget* parent,
        const bool success,
        const QString& titleText,
        const QString& bodyText)
    {
        QMessageBox resultBox(
            success ? QMessageBox::Information : QMessageBox::Warning,
            titleText,
            bodyText,
            QMessageBox::Ok,
            parent);
        resultBox.setStyleSheet(messageBoxStyle());
        resultBox.setTextFormat(Qt::PlainText);
        resultBox.exec();
    }

}

KernelThreadAuditTab::KernelThreadAuditTab(const Mode mode, QWidget* parent)
    : QWidget(parent),
      mode_(mode)
{
    initializeUi();
    applyTranslatedText();

    // Defer the first refresh to the event loop to avoid synchronous system information queries during Dock construction.
    QTimer::singleShot(0, this, [this]() {
        requestRefresh();
    });
}

void KernelThreadAuditTab::initializeUi()
{
    // Root layout: toolbar, table, and details arranged vertically.
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // Toolbar buttons use icons and tooltips; the worker queue thread page displays full evidence columns directly.
    auto* toolLayout = new QHBoxLayout();
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(4);

    refreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), this);
    suspendButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_pause.svg")), QString(), this);
    resumeButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QString(), this);
    terminateButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QString(), this);
    for (QPushButton* actionButton : { refreshButton_, suspendButton_, resumeButton_, terminateButton_ })
    {
        ksword_theme::applyCompactIconButtonMetrics(actionButton);
    }
    const bool kManagementVisible = mode_ == Mode::kSystemThreads;
    suspendButton_->setVisible(kManagementVisible);
    resumeButton_->setVisible(kManagementVisible);
    terminateButton_->setVisible(kManagementVisible);

    overviewButton_ = new QPushButton(QStringLiteral("A"), this);
    evidenceButton_ = new QPushButton(QStringLiteral("B"), this);
    overviewButton_->setFixedSize(28, 28);
    evidenceButton_->setFixedSize(28, 28);
    overviewButton_->setVisible(mode_ != Mode::kWorkQueueThreads);
    evidenceButton_->setVisible(mode_ != Mode::kWorkQueueThreads);

    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    statusLabel_ = new QLabel(this);
    statusLabel_->setStyleSheet(QStringLiteral("QLabel{color:%1;}").arg(ksword_theme::textSecondaryHex()));

    toolLayout->addWidget(refreshButton_);
    toolLayout->addSpacing(3);
    toolLayout->addWidget(suspendButton_);
    toolLayout->addWidget(resumeButton_);
    toolLayout->addWidget(terminateButton_);
    toolLayout->addSpacing(7);
    toolLayout->addWidget(overviewButton_);
    toolLayout->addWidget(evidenceButton_);
    toolLayout->addWidget(filterEdit_, 1);
    toolLayout->addWidget(statusLabel_);
    rootLayout->addLayout(toolLayout);

    // The table and CodeEditorWidget are organized by a vertical splitter; the details window maintains a unified editor for the project.
    auto* splitter = new QSplitter(Qt::Vertical, this);
    table_ = new QTableWidget(splitter);
    table_->setColumnCount(static_cast<int>(Column::kCount));
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setSortingEnabled(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);

    detailEditor_ = new CodeEditorWidget(splitter);
    detailEditor_->setReadOnly(true);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    ks::ui::DetailLayoutRegistry::registerHost(table_, detailEditor_, this);

    // Connect: refresh, filter, selection, view presets, header menu, and row action menu.
    connect(refreshButton_, &QPushButton::clicked, this, [this]() { requestRefresh(); });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this]() { rebuildTable(); });
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() { updateDetail(); });
    connect(overviewButton_, &QPushButton::clicked, this, [this]() {
        applyColumnPreset(ViewPreset::kOverview);
    });
    connect(evidenceButton_, &QPushButton::clicked, this, [this]() {
        applyColumnPreset(ViewPreset::kEvidence);
    });
    connect(table_->horizontalHeader(), &QHeaderView::customContextMenuRequested, this,
        [this](const QPoint& localPosition) { showHeaderMenu(localPosition); });
    connect(table_, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition) { showRowMenu(localPosition); });
    connect(suspendButton_, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
    });
    connect(resumeButton_, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    });
    connect(terminateButton_, &QPushButton::clicked, this, [this]() {
        runControlAction(KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE);
    });

    applyColumnPreset(mode_ == Mode::kWorkQueueThreads
        ? ViewPreset::kEvidence
        : ViewPreset::kOverview);
}

void KernelThreadAuditTab::applyTranslatedText()
{
    // Icon buttons convey action semantics solely via tooltips.
    refreshButton_->setToolTip(threadAuditText("thread_audit.tooltip.refresh", QStringLiteral("刷新线程审计快照")));
    suspendButton_->setToolTip(threadAuditText("thread_audit.tooltip.suspend", QStringLiteral("挂起选中的系统线程")));
    resumeButton_->setToolTip(threadAuditText("thread_audit.tooltip.resume", QStringLiteral("恢复选中的系统线程")));
    terminateButton_->setToolTip(threadAuditText("thread_audit.tooltip.terminate", QStringLiteral("终止选中的系统线程（高风险）")));
    overviewButton_->setToolTip(threadAuditText("thread_audit.tooltip.view_a", QStringLiteral("A：调度与队列概览")));
    evidenceButton_->setToolTip(threadAuditText("thread_audit.tooltip.view_b", QStringLiteral("B：入口地址与模块归属证据")));
    filterEdit_->setPlaceholderText(threadAuditText("thread_audit.filter.placeholder", QStringLiteral("按 TID、状态、队列或模块筛选")));
    filterEdit_->setToolTip(threadAuditText("thread_audit.filter.tooltip", QStringLiteral("输入关键字后实时过滤当前线程快照")));

    // Translate header labels in a fixed column order; presets control visibility only, not the data columns.
    table_->setHorizontalHeaderLabels(QStringList{
        threadAuditText("thread_audit.header.tid", QStringLiteral("线程ID")),
        threadAuditText("thread_audit.header.ethread", QStringLiteral("EThread")),
        threadAuditText("thread_audit.header.category", QStringLiteral("类别")),
        threadAuditText("thread_audit.header.queue_type", QStringLiteral("队列类型")),
        threadAuditText("thread_audit.header.node_priority", QStringLiteral("Node/Priority")),
        threadAuditText("thread_audit.header.work_queue", QStringLiteral("EX_WORK_QUEUE")),
        threadAuditText("thread_audit.header.state", QStringLiteral("线程状态")),
        threadAuditText("thread_audit.header.wait_reason", QStringLiteral("等待原因")),
        threadAuditText("thread_audit.header.routine", QStringLiteral("例程入口")),
        threadAuditText("thread_audit.header.parameter", QStringLiteral("参数")),
        threadAuditText("thread_audit.header.module", QStringLiteral("入口模块")),
        threadAuditText("thread_audit.header.module_base", QStringLiteral("模块基址")),
        threadAuditText("thread_audit.header.module_path", QStringLiteral("模块路径")),
        threadAuditText("thread_audit.header.r0_status", QStringLiteral("R0状态")),
        threadAuditText("thread_audit.header.protection", QStringLiteral("管理保护"))
    });

    if (rows_.empty() && !refreshRunning_)
    {
        statusLabel_->setText(threadAuditText("thread_audit.status.waiting", QStringLiteral("状态：等待刷新")));
        detailEditor_->setText(threadAuditText("thread_audit.detail.initial", QStringLiteral("请选择一条线程记录查看证据与安全边界。")));
    }
    updatePresetButtons();
}

void KernelThreadAuditTab::requestRefresh()
{
    if (refreshRunning_)
    {
        return;
    }

    refreshRunning_ = true;
    const std::uint64_t kRefreshTicket = ++refreshTicket_;
    refreshButton_->setEnabled(false);
    statusLabel_->setText(threadAuditText("thread_audit.status.refreshing", QStringLiteral("状态：正在采集线程与模块证据...")));

    // The background thread constructs only value-type Snapshots; UI controls are accessed only in the main thread callback.
    QPointer<KernelThreadAuditTab> guardThis(this);
    const Mode kRequestedMode = mode_;
    QThreadPool::globalInstance()->start([guardThis, kRefreshTicket, kRequestedMode]() {
        auto snapshot = std::make_shared<Snapshot>(collectSnapshot(kRequestedMode));
        QMetaObject::invokeMethod(
            QCoreApplication::instance(),
            [guardThis, kRefreshTicket, snapshot]() {
                if (guardThis == nullptr || kRefreshTicket != guardThis->refreshTicket_)
                {
                    return;
                }
                guardThis->applySnapshot(*snapshot);
            },
            Qt::QueuedConnection);
    });
}

void KernelThreadAuditTab::applySnapshot(const Snapshot& snapshot)
{
    const QPointer<KernelThreadAuditTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-thread-audit-snapshot"),
        { table_ },
        [kSafeThis, snapshot]()
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applySnapshot(snapshot);
            }
        }))
    {
        return;
    }

    rows_ = snapshot.rows;
    refreshRunning_ = false;
    refreshButton_->setEnabled(true);
    rebuildTable();

    const QString kDiagnosticText = snapshotDiagnosticText(snapshot, mode_);
    if (mode_ == Mode::kWorkQueueThreads)
    {
        statusLabel_->setText(
            threadAuditText(
                "thread_audit.status.work_queue_completed",
                QStringLiteral("状态：%1 条；队列=%2；节点=%3；查询=%4；%5"))
                .arg(static_cast<qulonglong>(rows_.size()))
                .arg(snapshot.workQueueQueuesVisited)
                .arg(snapshot.workQueueNodeCount)
                .arg(snapshot.workQueueQueryStatus)
                .arg(kDiagnosticText));
    }
    else
    {
        statusLabel_->setText(
            threadAuditText(
                "thread_audit.status.completed",
                QStringLiteral("状态：%1 条；R3=%2；R0=%3；%4"))
                .arg(static_cast<qulonglong>(rows_.size()))
                .arg(snapshot.usedNtQuery ? QStringLiteral("NtQuery") : QStringLiteral("Toolhelp"))
                .arg(snapshot.r0Available ? QStringLiteral("OK") : QStringLiteral("Unavailable"))
                .arg(kDiagnosticText));
    }
}

void KernelThreadAuditTab::rebuildTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(detailEditor_);
    const QString kFilterText = filterEdit_->text().trimmed();
    table_->setSortingEnabled(false);
    table_->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < rows_.size(); ++sourceIndex)
    {
        const ThreadRow& row = rows_[sourceIndex];
        const bool kWorkItem =
            row.workQueueRowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM;
        const bool kWorkerThread =
            row.workQueueRowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD;
        const QString kCategoryText = kWorkItem
            ? threadAuditText("thread_audit.category.work_item", QStringLiteral("工作项"))
            : (kWorkerThread
                ? threadAuditText("thread_audit.category.worker", QStringLiteral("关联工作线程"))
                : threadAuditText("thread_audit.category.system", QStringLiteral("系统线程")));
        const QString kQueueText = mode_ == Mode::kWorkQueueThreads
            ? queueTypeText(row.queueType)
            : threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"));
        const QString kParameterText = kWorkItem
            ? pointerText(row.parameterAddress)
            : threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"));
        const QString kModuleText = row.moduleResolved
            ? row.module.name
            : threadAuditText("thread_audit.module.unknown", QStringLiteral("<未知归属>"));
        const QString kProtectionText = row.protectedTarget
            ? threadAuditText("thread_audit.protection.blocked", QStringLiteral("已保护：%1"))
                .arg(protectionReasonText(row.protectionKind))
            : threadAuditText("thread_audit.protection.allowed", QStringLiteral("可操作（需确认）"));
        const QString kStateValue = mode_ == Mode::kWorkQueueThreads
            ? threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"))
            : stateText(row.state);
        const QString kWaitValue = mode_ == Mode::kWorkQueueThreads
            ? threadAuditText("thread_audit.value.not_applicable", QStringLiteral("不适用"))
            : waitReasonText(row.waitReason);
        const QString kR0Value = mode_ == Mode::kWorkQueueThreads
            ? workQueueEntryStatusText(row.workQueueStatus)
            : r0StatusText(row.r0Status);
        const QString kNodePriorityText = QStringLiteral("%1/%2")
            .arg(row.nodeIndex)
            .arg(row.queuePriorityIndex);

        const QStringList kCellTexts{
            QString::number(row.threadId),
            addressText(row.threadObject),
            kCategoryText,
            kQueueText,
            kNodePriorityText,
            addressText(row.queueAddress),
            kStateValue,
            kWaitValue,
            addressText(row.startAddress),
            kParameterText,
            kModuleText,
            addressText(row.module.baseAddress),
            row.module.path,
            kR0Value,
            kProtectionText
        };
        if (!kFilterText.isEmpty() &&
            !kCellTexts.join(QLatin1Char(' ')).contains(kFilterText, Qt::CaseInsensitive))
        {
            continue;
        }

        const int kTargetRow = table_->rowCount();
        table_->insertRow(kTargetRow);
        for (int columnIndex = 0; columnIndex < static_cast<int>(Column::kCount); ++columnIndex)
        {
            auto* item = new QTableWidgetItem(kCellTexts.value(columnIndex));
            item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            if (columnIndex == static_cast<int>(Column::kThreadId))
            {
                item->setData(Qt::DisplayRole, static_cast<qulonglong>(row.threadId));
            }
            table_->setItem(kTargetRow, columnIndex, item);
        }
    }

    table_->setSortingEnabled(true);
    table_->resizeColumnsToContents();
    updateDetail();
}

void KernelThreadAuditTab::updateDetail()
{
    const ThreadRow* selected = selectedRow();
    if (selected == nullptr)
    {
        detailEditor_->setText(threadAuditText("thread_audit.detail.initial", QStringLiteral("请选择一条线程记录查看证据与安全边界。")));
        suspendButton_->setEnabled(false);
        resumeButton_->setEnabled(false);
        terminateButton_->setEnabled(false);
        return;
    }
    const ThreadRow kRow = *selected;

    const bool kActionAllowed =
        mode_ == Mode::kSystemThreads &&
        kRow.threadId != 0U;
    suspendButton_->setEnabled(kActionAllowed);
    resumeButton_->setEnabled(kActionAllowed);
    terminateButton_->setEnabled(kActionAllowed);

    QStringList detailLines;
    detailLines << threadAuditText("thread_audit.detail.identity", QStringLiteral("[线程身份]"));
    if (mode_ == Mode::kWorkQueueThreads)
    {
        detailLines
            << QStringLiteral("RowKind: %1").arg(
                kRow.workQueueRowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM
                    ? threadAuditText("thread_audit.category.work_item", QStringLiteral("工作项"))
                    : threadAuditText("thread_audit.category.worker", QStringLiteral("关联工作线程")))
            << QStringLiteral("TID: %1").arg(kRow.threadId)
            << QStringLiteral("ETHREAD: %1").arg(addressText(kRow.threadObject))
            << QStringLiteral("CreateTime100ns: %1").arg(
                static_cast<qulonglong>(kRow.createTime100ns))
            << QString()
            << threadAuditText("thread_audit.detail.queue", QStringLiteral("[工作队列证据]"))
            << QStringLiteral("QueueType: %1 (%2)")
                .arg(queueTypeText(kRow.queueType))
                .arg(kRow.queueType)
            << QStringLiteral("Node/Priority: %1/%2")
                .arg(kRow.nodeIndex)
                .arg(kRow.queuePriorityIndex)
            << QStringLiteral("EX_WORK_QUEUE: %1").arg(addressText(kRow.queueAddress))
            << QStringLiteral("WORK_QUEUE_ITEM: %1").arg(addressText(kRow.workItemAddress))
            << QStringLiteral("WorkerRoutine: %1").arg(addressText(kRow.startAddress))
            << QStringLiteral("Parameter: %1").arg(pointerText(kRow.parameterAddress))
            << QStringLiteral("EvidenceFlags: 0x%1")
                .arg(kRow.workQueueFlags, 0, 16)
            << QStringLiteral("EntryStatus: %1 (%2)")
                .arg(workQueueEntryStatusText(kRow.workQueueStatus))
                .arg(kRow.workQueueStatus)
            << threadAuditText(
                "thread_audit.detail.queue_boundary",
                QStringLiteral("证据来自当前构建精确匹配的 PDB/DynData 结构描述；未知字段、身份不匹配、链表损坏或读取失败均显式降级。"));
    }
    else
    {
        detailLines
            << QStringLiteral("TID: %1").arg(kRow.threadId)
            << QStringLiteral("CreateTime100ns: %1").arg(
                static_cast<qulonglong>(kRow.createTime100ns))
            << QStringLiteral("Priority/BasePriority: %1/%2").arg(kRow.priority).arg(kRow.basePriority)
            << QStringLiteral("State: %1 (%2)").arg(stateText(kRow.state)).arg(kRow.state)
            << QStringLiteral("WaitReason: %1 (%2)").arg(waitReasonText(kRow.waitReason)).arg(kRow.waitReason)
            << QString()
            << threadAuditText("thread_audit.detail.scheduling", QStringLiteral("[调度证据]"))
            << QStringLiteral("ActiveExWorkerKnown: %1").arg(kRow.workerKnown ? QStringLiteral("true") : QStringLiteral("false"))
            << QStringLiteral("ActiveExWorker: %1").arg(kRow.activeWorker ? QStringLiteral("true") : QStringLiteral("false"))
            << threadAuditText(
                "thread_audit.detail.system_queue_boundary",
                QStringLiteral("队列归属不适用于系统线程管理视图；请在只读工作队列页查看精确队列与工作项证据。"));
    }

    detailLines
        << QString()
        << threadAuditText("thread_audit.detail.module", QStringLiteral("[入口与模块归属]"))
        << QStringLiteral("StartRoutine: %1").arg(addressText(kRow.startAddress))
        << QStringLiteral("Module: %1").arg(kRow.moduleResolved ? kRow.module.name : QStringLiteral("<unresolved>"))
        << QStringLiteral("ModuleBase/Size: %1 / 0x%2")
            .arg(addressText(kRow.module.baseAddress))
            .arg(kRow.module.imageSize, 0, 16)
        << QStringLiteral("ModulePath: %1").arg(kRow.module.path)
        << QString()
        << threadAuditText("thread_audit.detail.safety", QStringLiteral("[管理确认]"))
        << threadAuditText(
            "thread_audit.detail.safety_boundary",
            QStringLiteral("危险操作仅限系统线程页；R0 始终复核 TID，并在启动地址或创建时间可用时同步复核对应字段。"));
    detailEditor_->setText(detailLines.join(QLatin1Char('\n')));
}

void KernelThreadAuditTab::applyColumnPreset(const ViewPreset preset)
{
    viewPreset_ = preset;

    // A: Scheduling/queue overview; B: Address/module/R0 evidence. Both groups remain concise.
    std::vector<Column> visibleColumns;
    if (mode_ == Mode::kWorkQueueThreads)
    {
        visibleColumns = {
            Column::kThreadId,
            Column::kEThread,
            Column::kStartRoutine,
            Column::kParameter,
            Column::kNodePriority,
            Column::kWorkQueueAddress,
            Column::kModule,
            Column::kModuleBase,
            Column::kModulePath,
            Column::kR0Status };
    }
    else if (preset == ViewPreset::kEvidence)
    {
        visibleColumns = {
            Column::kThreadId,
            Column::kStartRoutine,
            Column::kParameter,
            Column::kModule,
            Column::kModuleBase,
            Column::kModulePath,
            Column::kR0Status,
            Column::kProtection };
    }
    else
    {
        visibleColumns = {
            Column::kThreadId,
            Column::kCategory,
            Column::kQueueType,
            Column::kState,
            Column::kWaitReason,
            Column::kModule,
            Column::kProtection };
    }

    for (int columnIndex = 0; columnIndex < static_cast<int>(Column::kCount); ++columnIndex)
    {
        const Column kColumn = static_cast<Column>(columnIndex);
        const bool kVisible = std::find(visibleColumns.begin(), visibleColumns.end(), kColumn) != visibleColumns.end();
        table_->setColumnHidden(columnIndex, !kVisible);
    }
    updatePresetButtons();
}

void KernelThreadAuditTab::updatePresetButtons()
{
    // The foreground of the selected state uses palette(highlighted-text), paired with the palette(highlight) background color.
    // Prevents white text on a white background when the user changes the system accent color to a light theme.
    const QString kActiveStyle = QStringLiteral(
        "QPushButton{background:%1;color:%2;border:1px solid %1;border-radius:3px;font-weight:600;}")
        .arg(ksword_theme::kPrimaryBlueHex)
        .arg(QStringLiteral("palette(highlighted-text)"));
    const QString kInactiveStyle = QStringLiteral(
        "QPushButton{background:%1;color:%2;border:1px solid %3;border-radius:3px;}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex());

    overviewButton_->setStyleSheet(viewPreset_ == ViewPreset::kOverview ? kActiveStyle : kInactiveStyle);
    evidenceButton_->setStyleSheet(viewPreset_ == ViewPreset::kEvidence ? kActiveStyle : kInactiveStyle);
}

void KernelThreadAuditTab::showHeaderMenu(const QPoint& localPosition)
{
    QMenu columnMenu(this);
    columnMenu.setStyleSheet(menuStyle());

    // The header menu allows column-by-column selection; after manual changes, the preset button clears its highlight to indicate Custom.
    for (int columnIndex = 0; columnIndex < static_cast<int>(Column::kCount); ++columnIndex)
    {
        const Column kColumn = static_cast<Column>(columnIndex);
        const bool kWorkQueueOnlyColumn =
            kColumn == Column::kEThread ||
            kColumn == Column::kNodePriority ||
            kColumn == Column::kWorkQueueAddress;
        if ((mode_ == Mode::kWorkQueueThreads && kColumn == Column::kProtection) ||
            (mode_ != Mode::kWorkQueueThreads && kWorkQueueOnlyColumn))
        {
            continue;
        }

        const QString kHeaderText = table_->horizontalHeaderItem(columnIndex) != nullptr
            ? table_->horizontalHeaderItem(columnIndex)->text()
            : QString::number(columnIndex);
        QAction* columnAction = columnMenu.addAction(kHeaderText);
        columnAction->setCheckable(true);
        columnAction->setChecked(!table_->isColumnHidden(columnIndex));
        connect(columnAction, &QAction::toggled, this, [this, columnIndex](const bool visible) {
            table_->setColumnHidden(columnIndex, !visible);
            viewPreset_ = ViewPreset::kCustom;
            updatePresetButtons();
        });
    }
    columnMenu.exec(table_->horizontalHeader()->mapToGlobal(localPosition));
}

void KernelThreadAuditTab::showRowMenu(const QPoint& localPosition)
{
    if (table_->itemAt(localPosition) != nullptr)
    {
        table_->selectRow(table_->itemAt(localPosition)->row());
    }
    if (mode_ != Mode::kSystemThreads)
    {
        return;
    }

    std::optional<ThreadRow> rowCopy;
    if (const ThreadRow* const kSelected = selectedRow(); kSelected != nullptr)
    {
        rowCopy = *kSelected;
    }
    QMenu actionMenu(this);
    actionMenu.setStyleSheet(menuStyle());
    QAction* suspendAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_pause.svg")),
        threadAuditText("thread_audit.menu.suspend", QStringLiteral("挂起系统线程")));
    QAction* resumeAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_resume.svg")),
        threadAuditText("thread_audit.menu.resume", QStringLiteral("恢复系统线程")));
    QAction* terminateAction = actionMenu.addAction(
        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
        threadAuditText("thread_audit.menu.terminate", QStringLiteral("终止系统线程（高风险）")));

    const bool kActionAllowed =
        mode_ == Mode::kSystemThreads &&
        rowCopy.has_value() &&
        rowCopy->threadId != 0U;
    suspendAction->setEnabled(kActionAllowed);
    resumeAction->setEnabled(kActionAllowed);
    terminateAction->setEnabled(kActionAllowed);
    QAction* selectedAction = actionMenu.exec(table_->viewport()->mapToGlobal(localPosition));
    if (!rowCopy.has_value())
    {
        return;
    }
    if (selectedAction == suspendAction)
    {
        runControlAction(*rowCopy, KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
    }
    else if (selectedAction == resumeAction)
    {
        runControlAction(*rowCopy, KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
    }
    else if (selectedAction == terminateAction)
    {
        runControlAction(*rowCopy, KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE);
    }
}

void KernelThreadAuditTab::runControlAction(const unsigned long action)
{
    const ThreadRow* const kSelected = selectedRow();
    if (kSelected == nullptr)
    {
        return;
    }
    const ThreadRow kRow = *kSelected;
    runControlAction(kRow, action);
}

void KernelThreadAuditTab::runControlAction(
    const ThreadRow& row,
    const unsigned long action)
{
    if (mode_ != Mode::kSystemThreads ||
        row.threadId == 0U)
    {
        showResultMessage(
            this,
            false,
            threadAuditText("thread_audit.dialog.blocked.title", QStringLiteral("系统线程操作已阻止")),
            threadAuditText("thread_audit.dialog.blocked.body", QStringLiteral("当前记录没有可用于执行操作的线程 ID。")));
        return;
    }

    const QString kTargetText = QStringLiteral(
        "TID=%1\nStart=%2\nCreateTime100ns=%3\nModule=%4")
        .arg(row.threadId)
        .arg(addressText(row.startAddress))
        .arg(static_cast<qulonglong>(row.createTime100ns))
        .arg(row.module.name);
    const bool kTerminating = action == KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE;
    const QString kActionTitle = kTerminating
        ? threadAuditText("thread_audit.dialog.terminate.title", QStringLiteral("终止系统线程"))
        : (action == KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND
            ? threadAuditText("thread_audit.dialog.suspend.title", QStringLiteral("挂起系统线程"))
            : threadAuditText("thread_audit.dialog.resume.title", QStringLiteral("恢复系统线程")));
    const QString kFirstWarning = kTerminating
        ? threadAuditText(
            "thread_audit.dialog.terminate.warning",
            QStringLiteral("高风险：终止驱动系统线程可能造成设备失效、数据丢失或系统崩溃。\n\n%1\n\n确认继续？")).arg(kTargetText)
        : threadAuditText(
            "thread_audit.dialog.control.warning",
            QStringLiteral("改变驱动系统线程调度状态可能造成设备失效或系统卡死。\n\n%1\n\n确认继续？")).arg(kTargetText);
    if (!showConfirmation(this, kActionTitle, kFirstWarning))
    {
        return;
    }

    // Termination requires a second independent confirmation; resume/suspend requires only one.
    if (kTerminating &&
        !showConfirmation(
            this,
            threadAuditText("thread_audit.dialog.terminate.second.title", QStringLiteral("最终终止确认")),
            threadAuditText(
                "thread_audit.dialog.terminate.second.body",
                QStringLiteral("这是不可逆操作。R0 会再次校验当前可用的线程身份字段，但无法保证目标驱动可以安全恢复。\n\n再次确认终止 TID %1？"))
                .arg(row.threadId)))
    {
        return;
    }

    const unsigned long kTerminateMethod = kTerminating
        ? KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC
        : KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE;
    const bool kUiConfirmed = action != KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME;
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::IoResult kResult = kDriverClient.controlDriverThread(
        row.threadId,
        row.startAddress,
        row.createTime100ns,
        action,
        kTerminateMethod,
        kUiConfirmed);

    KLogEvent controlEvent;
    if (kResult.ok)
    {
        info << controlEvent
            << "[KernelThreadAuditTab] 系统线程控制完成, tid="
            << row.threadId
            << ", action="
            << action
            << eol;
    }
    else
    {
        err << controlEvent
            << "[KernelThreadAuditTab] 系统线程控制失败, tid="
            << row.threadId
            << ", action="
            << action
            << ", detail="
            << kResult.message
            << eol;
    }

    const QString kResultDetail = QString::fromStdString(kResult.message);
    showResultMessage(
        this,
        kResult.ok,
        kActionTitle,
        kResult.ok
            ? threadAuditText("thread_audit.dialog.result.success", QStringLiteral("操作已由 R0 完成。\n%1")).arg(kResultDetail)
            : threadAuditText("thread_audit.dialog.result.failure", QStringLiteral("R0 拒绝或执行失败。\n%1")).arg(kResultDetail));
    requestRefresh();
}

const KernelThreadAuditTab::ThreadRow* KernelThreadAuditTab::selectedRow() const
{
    const int kSourceIndex = selectedSourceIndex();
    if (kSourceIndex < 0 || static_cast<std::size_t>(kSourceIndex) >= rows_.size())
    {
        return nullptr;
    }
    return &rows_[static_cast<std::size_t>(kSourceIndex)];
}

int KernelThreadAuditTab::selectedSourceIndex() const
{
    const QList<QTableWidgetItem*> kSelectedItems = table_->selectedItems();
    if (kSelectedItems.isEmpty())
    {
        return -1;
    }
    const qulonglong kSourceIndex = kSelectedItems.first()->data(Qt::UserRole).toULongLong();
    if (kSourceIndex > static_cast<qulonglong>((std::numeric_limits<int>::max)()))
    {
        return -1;
    }
    return static_cast<int>(kSourceIndex);
}

// collectSnapshot implementation is located in KernelThreadAuditTab.Snapshot.cpp.

// The implementation of queryKernelModules is located in KernelThreadAuditTab.Snapshot.cpp.

// findOwnerModule implementation is located in KernelThreadAuditTab.Snapshot.cpp.

QString KernelThreadAuditTab::stateText(const std::uint32_t stateValue)
{
    switch (stateValue)
    {
    case 0U: return threadAuditText("thread_audit.state.initialized", QStringLiteral("已初始化"));
    case 1U: return threadAuditText("thread_audit.state.ready", QStringLiteral("就绪"));
    case 2U: return threadAuditText("thread_audit.state.running", QStringLiteral("运行中"));
    case 3U: return threadAuditText("thread_audit.state.standby", QStringLiteral("待运行"));
    case 4U: return threadAuditText("thread_audit.state.terminated", QStringLiteral("已终止"));
    case 5U: return threadAuditText("thread_audit.state.waiting", QStringLiteral("等待中"));
    case 6U: return threadAuditText("thread_audit.state.transition", QStringLiteral("转换中"));
    case 7U: return threadAuditText("thread_audit.state.deferred_ready", QStringLiteral("延迟就绪"));
    default: return QStringLiteral("Unknown(%1)").arg(stateValue);
    }
}

QString KernelThreadAuditTab::waitReasonText(const std::uint32_t waitReasonValue)
{
    switch (waitReasonValue)
    {
    case 0U: return QStringLiteral("Executive");
    case 4U: return QStringLiteral("DelayExecution");
    case 5U: return QStringLiteral("Suspended");
    case 6U: return QStringLiteral("UserRequest");
    case 7U: return QStringLiteral("WrExecutive");
    case 11U: return QStringLiteral("WrDelayExecution");
    case 12U: return QStringLiteral("WrSuspended");
    case 13U: return QStringLiteral("WrUserRequest");
    case kWaitReasonQueue: return QStringLiteral("WrQueue");
    case 16U: return QStringLiteral("WrLpcReceive");
    case 17U: return QStringLiteral("WrLpcReply");
    case 25U: return QStringLiteral("WrCalloutStack");
    case 26U: return QStringLiteral("WrKernel");
    case 27U: return QStringLiteral("WrResource");
    case 28U: return QStringLiteral("WrPushLock");
    case 29U: return QStringLiteral("WrMutex");
    default: return QStringLiteral("Reason(%1)").arg(waitReasonValue);
    }
}

QString KernelThreadAuditTab::r0StatusText(const std::uint32_t statusValue)
{
    switch (statusValue)
    {
    case KSWORD_ARK_THREAD_R0_STATUS_OK: return QStringLiteral("OK");
    case KSWORD_ARK_THREAD_R0_STATUS_PARTIAL: return QStringLiteral("Partial");
    case KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING: return QStringLiteral("DynData missing");
    case KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED: return QStringLiteral("Read failed");
    default: return QStringLiteral("Unavailable");
    }
}

QString KernelThreadAuditTab::addressText(const std::uint64_t addressValue)
{
    if (addressValue == 0U)
    {
        return QStringLiteral("Unavailable");
    }
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(addressValue), 0, 16)
        .toUpper();
}

QString KernelThreadAuditTab::pointerText(const std::uint64_t addressValue)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(addressValue), 0, 16)
        .toUpper();
}

QString KernelThreadAuditTab::protectionReasonText(
    const ProtectionKind protectionKind)
{
    switch (protectionKind)
    {
    case ProtectionKind::kUnknownModule:
        return threadAuditText(
            "thread_audit.protection.unknown",
            QStringLiteral("启动入口归属未知"));
    case ProtectionKind::kKernelImage:
        return threadAuditText(
            "thread_audit.protection.kernel",
            QStringLiteral("Windows 内核线程"));
    case ProtectionKind::kMissingThreadIdentity:
        return threadAuditText(
            "thread_audit.protection.identity_missing",
            QStringLiteral("启动地址或创建时间缺失，危险操作已关闭"));
    case ProtectionKind::kBestEffortR0Recheck:
        return threadAuditText(
            "thread_audit.protection.r0_recheck",
            QStringLiteral("操作时由 R0 复核当前可用身份"));
    case ProtectionKind::kReadOnlyWorkQueueEvidence:
        return threadAuditText(
            "thread_audit.protection.read_only",
            QStringLiteral("只读工作队列证据，不提供管理动作"));
    default:
        return threadAuditText(
            "thread_audit.protection.unknown",
            QStringLiteral("启动入口归属未知"));
    }
}

QString KernelThreadAuditTab::queueTypeText(const std::uint32_t queueType)
{
    switch (queueType)
    {
    case KSWORD_ARK_WORK_QUEUE_TYPE_CRITICAL:
        return threadAuditText(
            "thread_audit.queue.critical",
            QStringLiteral("Critical"));
    case KSWORD_ARK_WORK_QUEUE_TYPE_DELAYED:
        return threadAuditText(
            "thread_audit.queue.delayed",
            QStringLiteral("Delayed"));
    case KSWORD_ARK_WORK_QUEUE_TYPE_HYPERCRITICAL:
        return threadAuditText(
            "thread_audit.queue.hypercritical",
            QStringLiteral("HyperCritical"));
    case KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER:
        return threadAuditText(
            "thread_audit.queue.shared_worker",
            QStringLiteral("关联工作线程"));
    default:
        return QStringLiteral("Unknown(%1)").arg(queueType);
    }
}

QString KernelThreadAuditTab::workQueueEntryStatusText(
    const std::uint32_t status)
{
    switch (status)
    {
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK:
        return QStringLiteral("OK");
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_READ_FAILED:
        return threadAuditText(
            "thread_audit.work_queue.entry.read_failed",
            QStringLiteral("读取失败"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_UNRESOLVED:
        return threadAuditText(
            "thread_audit.work_queue.entry.module_unresolved",
            QStringLiteral("例程模块未解析"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_ROUTINE_NOT_EXECUTABLE:
        return threadAuditText(
            "thread_audit.work_queue.entry.not_executable",
            QStringLiteral("例程不在可执行节"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_REFERENCE_FAILED:
        return threadAuditText(
            "thread_audit.work_queue.entry.reference_failed",
            QStringLiteral("线程对象引用失败"));
    case KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED:
        return threadAuditText(
            "thread_audit.work_queue.entry.identity_failed",
            QStringLiteral("线程身份验证失败"));
    default:
        return QStringLiteral("Unknown(%1)").arg(status);
    }
}

QString KernelThreadAuditTab::snapshotDiagnosticText(
    const Snapshot& snapshot,
    const Mode mode)
{
    QStringList diagnostics;
    if (mode == Mode::kWorkQueueThreads)
    {
        // When the IOCTL fails to reach the driver, workQueueQueryStatus remains at its R3 default value (UNSUPPORTED).
        // Treating this as an R0 layout conclusion would misreport 'no driver' as 'layout resolution failure'.
        if ((snapshot.diagnosticFlags & kDiagnosticWorkQueueTransportFailed) != 0U)
        {
            diagnostics <<
                ((snapshot.diagnosticFlags & kDiagnosticWorkQueueUnsupported) != 0U
                ? threadAuditText(
                    "thread_audit.work_queue.transport.unsupported",
                    QStringLiteral("驱动不识别工作队列 IOCTL，驱动版本过旧"))
                : threadAuditText(
                    "thread_audit.work_queue.transport.unavailable",
                    QStringLiteral("驱动未加载或未连接，本次查询 R0 未参与")));
            diagnostics << QStringLiteral("Win32=%1").arg(snapshot.r0Win32Error);
            return diagnostics.join(QStringLiteral(" | "));
        }
        switch (snapshot.workQueueQueryStatus)
        {
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.ok",
                QStringLiteral("精确身份与布局已验证"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.unsupported",
                QStringLiteral("PDB Profile 与运行期签名回退都未能定位工作队列布局；枚举已关闭"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.partial",
                QStringLiteral("快照部分完成，异常已计数"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.invalid_layout",
                QStringLiteral("结构描述边界无效，已关闭枚举"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_IDENTITY_MISMATCH:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.identity_mismatch",
                QStringLiteral("PE/PDB 身份不匹配，已关闭枚举"));
            break;
        case KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED:
            diagnostics << threadAuditText(
                "thread_audit.work_queue.query.read_failed",
                QStringLiteral("内核证据读取失败"));
            break;
        default:
            diagnostics << QStringLiteral("QueryStatus=%1")
                .arg(snapshot.workQueueQueryStatus);
            break;
        }
        // Any non-OK conclusion includes the NTSTATUS. Otherwise, UNSUPPORTED would only have a single conclusion,
        // making it impossible to distinguish between layout search failure, unavailable image, or read failure.
        if ((snapshot.diagnosticFlags & kDiagnosticWorkQueuePartial) != 0U ||
            snapshot.workQueueQueryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK)
        {
            diagnostics << QStringLiteral(
                "corrupt=%1, read=%2, reference=%3, NTSTATUS=0x%4")
                .arg(snapshot.workQueueCorruptCount)
                .arg(snapshot.workQueueReadFailureCount)
                .arg(snapshot.workQueueReferenceFailureCount)
                .arg(static_cast<unsigned long>(snapshot.workQueueLastStatus), 8, 16, QLatin1Char('0'));
        }
    }
    else
    {
        if ((snapshot.diagnosticFlags & kDiagnosticR3EnumerationEmpty) != 0U)
        {
            diagnostics << threadAuditText(
                "thread_audit.diagnostic.r3_empty",
                QStringLiteral("R3 未返回 System 线程"));
        }
        if ((snapshot.diagnosticFlags & kDiagnosticR0ThreadUnavailable) != 0U)
        {
            diagnostics << QStringLiteral("R0 Win32=%1").arg(snapshot.r0Win32Error);
        }
        if ((snapshot.diagnosticFlags & kDiagnosticModuleUnavailable) != 0U)
        {
            diagnostics << QStringLiteral("ModuleStatus=%1, NTSTATUS=0x%2, bytes=%3")
                .arg(static_cast<std::uint32_t>(snapshot.moduleQueryStatus))
                .arg(static_cast<unsigned long>(snapshot.moduleNativeStatus), 8, 16, QLatin1Char('0'))
                .arg(snapshot.moduleRequiredBytes);
        }
        if (diagnostics.isEmpty())
        {
            diagnostics << threadAuditText(
                "thread_audit.diagnostic.complete",
                QStringLiteral("身份与模块证据完整"));
        }
    }
    return diagnostics.join(QStringLiteral(" | "));
}

void KernelThreadAuditTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        applyTranslatedText();
        rebuildTable();
    }
}

#include "KvmWatchPanel.h"

#include "KernelDisassemblyDialog.h"
#include "KvmControl.h"
// The installation form and the four ARK pages share the same source: the two forms will gradually drift apart in the 'page-granularity'
// and 'request access vs. actual access' descriptions, which are precisely the areas most prone to misunderstanding for this feature.
#include "KvmWatchDialog.h"
#include "../framework/DestructiveActionConfirmation.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QProcess>
#include <QTextStream>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>

#include <thread>

namespace
{
    enum WatchColumn
    {
        kWatchColumnId = 0,
        kWatchColumnTarget,
        kWatchColumnRequestedRange,
        kWatchColumnPage,
        kWatchColumnRequestedAccess,
        kWatchColumnEffectiveAccess,
        kWatchColumnMode,
        kWatchColumnState,
        kWatchColumnHits,
        kWatchColumnLastRip,
        kWatchColumnModule,
        kWatchColumnCount
    };

    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }

    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }


}

KvmWatchPanel::KvmWatchPanel(QWidget* const parent)
    : QWidget(parent)
{
    buildUi();
    updateEnabledState();
}

void KvmWatchPanel::buildUi()
{
    auto* const kRootLayout = new QVBoxLayout(this);
    kRootLayout->setContentsMargins(6, 6, 6, 6);
    kRootLayout->setSpacing(6);

    hintLabel_ = new QLabel(
        text(QStringLiteral("监视一个目标页的下一次访问，命中时记下访问者的现场，然后自动解除并让原访问正常继续 —— 常驻不会因此退出。这是观察与归因，不是保护：命中不阻止访问，监视单位是 4 KiB 页而不是你选的字节数，DMA 改写不经过 CPU 的 EPT，目标把自己那一页换个物理页就不在被监视的页上了。")),
        this);
    hintLabel_->setWordWrap(true);
    kRootLayout->addWidget(hintLabel_);

    table_ = new QTableWidget(0, kWatchColumnCount, this);
    table_->setObjectName(QStringLiteral("KvmWatchTable"));
    table_->setHorizontalHeaderLabels(QStringList()
        << text(QStringLiteral("编号"))
        << text(QStringLiteral("目标"))
        << text(QStringLiteral("请求范围"))
        << text(QStringLiteral("监视页"))
        << text(QStringLiteral("请求访问"))
        << text(QStringLiteral("实际访问"))
        << text(QStringLiteral("模式"))
        << text(QStringLiteral("状态"))
        << text(QStringLiteral("命中"))
        << text(QStringLiteral("最近 RIP"))
        << text(QStringLiteral("模块")));
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->verticalHeader()->setVisible(false);
    kRootLayout->addWidget(table_, 3);

    auto* const kButtons = new QGridLayout();
    addButton_ = new QPushButton(
        text(QStringLiteral("添加监视...")), this);
    rearmButton_ = new QPushButton(
        text(QStringLiteral("重新武装")), this);
    rearmButton_->setToolTip(text(QStringLiteral("保留编号与累计命中次数，让这条监视再等下一次访问。已命中和已失效的都可以重新武装。")));
    removeButton_ = new QPushButton(
        text(QStringLiteral("移除")), this);
    refreshButton_ = new QPushButton(
        text(QStringLiteral("刷新")), this);
    disassembleButton_ = new QPushButton(
        text(QStringLiteral("查看写入者反汇编")), this);
    memoryButton_ = new QPushButton(
        text(QStringLiteral("查看目标内存")), this);
    memoryButton_->setToolTip(text(QStringLiteral("按被监视的那一页读一段内存。这是**命中之后**的采样，不是命中那一刻的值——EPT violation 发生在写指令退休之前，所以这里读到的可能已经包含那次写入，也可能还包含之后的更多次修改。")));
    moduleButton_ = new QPushButton(
        text(QStringLiteral("查看模块")), this);
    moduleButton_->setToolTip(text(QStringLiteral("在资源管理器里定位命中 RIP 所属的内核模块文件。RIP 不落在任何已加载模块里时这个按钮不可用。")));
    processButton_ = new QPushButton(
        text(QStringLiteral("解析命中进程")), this);
    processButton_->setToolTip(text(QStringLiteral("把命中现场记下的 CR3 归到一个进程上。它要逐个进程读回页目录基址，所以是一次显式操作而不是随选中行自动跑。结果是后处理推断：进程可能已经退出、PID 可能已经被回收。")));
    copyButton_ = new QPushButton(
        text(QStringLiteral("复制证据")), this);
    exportButton_ = new QPushButton(
        text(QStringLiteral("导出全部证据...")), this);
    exportButton_->setToolTip(text(QStringLiteral("把当前监视表里每一条的目标、命中现场与归因写成一个文本文件。已命中但事件环没接住证据的那几条同样会写进去，并标注出来。")));
    kButtons->addWidget(addButton_, 0, 0);
    kButtons->addWidget(rearmButton_, 0, 1);
    kButtons->addWidget(removeButton_, 0, 2);
    kButtons->addWidget(refreshButton_, 0, 3);
    kButtons->addWidget(disassembleButton_, 1, 0);
    kButtons->addWidget(memoryButton_, 1, 1);
    kButtons->addWidget(moduleButton_, 1, 2);
    kButtons->addWidget(processButton_, 1, 3);
    kButtons->addWidget(copyButton_, 0, 4);
    kButtons->addWidget(exportButton_, 1, 4);
    kRootLayout->addLayout(kButtons);

    detail_ = new QTextEdit(this);
    detail_->setReadOnly(true);
    detail_->setLineWrapMode(QTextEdit::NoWrap);
    detail_->setPlaceholderText(
        text(QStringLiteral("选中一条监视查看它的完整现场与归因。")));
    kRootLayout->addWidget(detail_, 2);

    statusLabel_ = new QLabel(QString(), this);
    statusLabel_->setWordWrap(true);
    kRootLayout->addWidget(statusLabel_);

    connect(addButton_, &QPushButton::clicked, this, [this]() { startAdd(); });
    connect(rearmButton_, &QPushButton::clicked, this, [this]() { startRearm(); });
    connect(removeButton_, &QPushButton::clicked, this, [this]() { startRemove(); });
    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(disassembleButton_, &QPushButton::clicked, this, [this]() {
        openWriterDisassembly();
    });
    connect(memoryButton_, &QPushButton::clicked, this, [this]() {
        openTargetMemory();
    });
    connect(moduleButton_, &QPushButton::clicked, this, [this]() {
        openWriterModule();
    });
    connect(processButton_, &QPushButton::clicked, this, [this]() {
        resolveHitProcess();
    });
    connect(copyButton_, &QPushButton::clicked, this, [this]() { copyEvidence(); });
    connect(exportButton_, &QPushButton::clicked, this, [this]() { exportEvidence(); });
    connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() {
        ksword::kvm::KvmWatchEntry entry;
        if (selectedWatch(&entry))
        {
            showDetail(entry);
        }
        updateEnabledState();
    });
}

void KvmWatchPanel::showEvent(QShowEvent* const event)
{
    QWidget::showEvent(event);
    refreshAsync();
}

void KvmWatchPanel::setBusy(const bool busy)
{
    busy_ = busy;
    updateEnabledState();
    if (onBusyChanged)
    {
        onBusyChanged(busy);
    }
}

void KvmWatchPanel::updateEnabledState()
{
    const bool kWriteAllowed = ksword::kvm::isWriteAccessEnabled();
    const QString kWriteHint = kWriteAllowed
        ? QString()
        : text(QStringLiteral("R-1 写权限未开启：在 KVM 按钮右键菜单中开启后才能安装或撤销监视"));
    ksword::kvm::KvmWatchEntry entry;
    const bool kHasSelection = selectedWatch(&entry);

    if (addButton_ != nullptr)
    {
        addButton_->setEnabled(kWriteAllowed && !busy_);
        addButton_->setToolTip(kWriteHint);
    }
    if (rearmButton_ != nullptr)
    {
        rearmButton_->setEnabled(kWriteAllowed && !busy_ && kHasSelection);
        rearmButton_->setToolTip(kWriteHint);
    }
    if (removeButton_ != nullptr)
    {
        removeButton_->setEnabled(kWriteAllowed && !busy_ && kHasSelection);
        removeButton_->setToolTip(kWriteHint);
    }
    if (refreshButton_ != nullptr)
    {
        refreshButton_->setEnabled(!busy_);
    }
    // Disassembly and copying evidence are only available after at least one hit.
    const bool kHasHit = kHasSelection && entry.hitCount != 0UL;
    if (disassembleButton_ != nullptr)
    {
        disassembleButton_->setEnabled(!busy_ && kHasHit && entry.lastHitRip != 0ULL);
    }
    if (memoryButton_ != nullptr)
    {
        // Target memory does not require a hit: targets that haven't hit yet are still worth inspecting.
        memoryButton_->setEnabled(!busy_ && kHasSelection &&
            entry.physicalPage != 0ULL);
    }
    if (moduleButton_ != nullptr)
    {
        // The button should be disabled when no module is resolved, rather than showing an 'Unknown' popup on click.
        moduleButton_->setEnabled(!busy_ && kHasHit &&
            entry.lastHitRip != 0ULL &&
            ksword::kvm::attributeKernelAddress(entry.lastHitRip).resolved);
    }
    if (processButton_ != nullptr)
    {
        processButton_->setEnabled(!busy_ && kHasHit && entry.lastHitCr3 != 0ULL);
    }
    if (copyButton_ != nullptr)
    {
        copyButton_->setEnabled(kHasSelection);
    }
    if (exportButton_ != nullptr)
    {
        // Export does not require selecting any row: it writes the entire table.
        exportButton_->setEnabled(table_ != nullptr && table_->rowCount() > 0);
    }
}

bool KvmWatchPanel::selectedWatch(
    ksword::kvm::KvmWatchEntry* const entryOut) const
{
    if (table_ == nullptr)
    {
        return false;
    }
    const int kRow = table_->currentRow();
    if (kRow < 0 || table_->item(kRow, kWatchColumnId) == nullptr)
    {
        return false;
    }
    const QVariant kStored =
        table_->item(kRow, kWatchColumnId)->data(Qt::UserRole);
    if (!kStored.isValid())
    {
        return false;
    }
    // The entire snapshot is stored row-wise rather than parsed column-by-column: each column in the table contains
    // human-readable text; attempting to reverse-engineer values from text will fail at the first localized term.
    *entryOut = kStored.value<ksword::kvm::KvmWatchEntry>();
    return true;
}

void KvmWatchPanel::refreshAsync()
{
    if (queryInFlight_ || busy_)
    {
        return;
    }
    queryInFlight_ = true;
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmWatchResult kResult = ksword::kvm::listWatches();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->queryInFlight_ = false;
                if (!kResult.ok)
                {
                    safeThis->statusLabel_->setText(kResult.message);
                    return;
                }
                safeThis->applyWatches(kResult.watches);
                safeThis->statusLabel_->setText(
                    text(QStringLiteral("当前有 %1 条内存监视。"))
                        .arg(kResult.watchCount));
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::applyWatches(
    const QVector<ksword::kvm::KvmWatchEntry>& watches)
{
    table_->setRowCount(watches.size());
    for (int row = 0; row < watches.size(); ++row)
    {
        const ksword::kvm::KvmWatchEntry& entry = watches.at(row);
        const auto kSetCell = [this, row](const int column, const QString& value) {
            auto* const kItem = new QTableWidgetItem(value);
            kItem->setToolTip(value);
            table_->setItem(row, column, kItem);
            return kItem;
        };
        auto* const kIdItem = kSetCell(
            kWatchColumnId, QString::number(entry.watchId));
        kIdItem->setData(Qt::UserRole, QVariant::fromValue(entry));
        kSetCell(kWatchColumnTarget,
            entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                ? text(QStringLiteral("虚拟 %1")).arg(hex64(entry.requestedAddress))
                : text(QStringLiteral("物理 %1")).arg(hex64(entry.requestedAddress)));
        kSetCell(kWatchColumnRequestedRange,
            text(QStringLiteral("%1 字节")).arg(entry.requestedLength));
        // The Watch Page column explicitly states 4096: displaying both columns side-by-side clarifies the granularity difference.
        kSetCell(kWatchColumnPage,
            text(QStringLiteral("%1（4096 字节）")).arg(hex64(entry.physicalPage)));
        kSetCell(kWatchColumnRequestedAccess,
            ksword::kvm::describeWatchAccess(entry.requestedAccess));
        kSetCell(kWatchColumnEffectiveAccess,
            ksword::kvm::describeWatchAccess(entry.effectiveAccess));
        kSetCell(kWatchColumnMode, text(QStringLiteral("首次访问")));
        kSetCell(kWatchColumnState,
            ksword::kvm::describeWatchState(entry.state));
        // The Hits column conveys both "evidence present or not": a hit with a lost event and
        // a never-hit event appear identical in the event list but have opposite conclusions.
        kSetCell(kWatchColumnHits,
            entry.lastHitStatus == KSWORD_ARK_HVM_EPT_WATCH_HIT_EVENT_LOST
                ? text(QStringLiteral("%1（事件已丢失）")).arg(entry.hitCount)
                : QString::number(entry.hitCount));
        kSetCell(kWatchColumnLastRip,
            entry.lastHitRip != 0ULL ? hex64(entry.lastHitRip) : QStringLiteral("-"));
        QString moduleText = QStringLiteral("-");
        if (entry.lastHitRip != 0ULL)
        {
            const ksword::kvm::KvmWatchAttribution kAttribution =
                ksword::kvm::attributeKernelAddress(entry.lastHitRip);
            // Use `module!Symbol+0x..` if an exported symbol exists; otherwise fall back to `module.sys+0xRVA`.
            // Both are true; the difference is only in precision. Fabricating the nearest name is wrong.
            moduleText = !kAttribution.resolved
                ? text(QStringLiteral("未知可执行区域"))
                : kAttribution.symbolName.isEmpty()
                    ? QStringLiteral("%1+0x%2")
                        .arg(kAttribution.moduleName)
                        .arg(kAttribution.relativeAddress, 0, 16)
                    : QStringLiteral("%1!%2+0x%3")
                        .arg(kAttribution.moduleName)
                        .arg(kAttribution.symbolName)
                        .arg(kAttribution.symbolOffset, 0, 16);
        }
        kSetCell(kWatchColumnModule, moduleText);
    }
    table_->resizeColumnsToContents();
    updateEnabledState();
}

void KvmWatchPanel::showDetail(const ksword::kvm::KvmWatchEntry& entry)
{
    QStringList lines;
    lines << text(QStringLiteral("目标"));
    lines << text(QStringLiteral("  请求地址        %1"))
        .arg(hex64(entry.requestedAddress));
    lines << text(QStringLiteral("  请求长度        %1 字节"))
        .arg(entry.requestedLength);
    lines << text(QStringLiteral("  实际监视页      %1，4096 字节"))
        .arg(hex64(entry.physicalPage));
    lines << text(QStringLiteral("  请求访问        %1"))
        .arg(ksword::kvm::describeWatchAccess(entry.requestedAccess));
    lines << text(QStringLiteral("  实际访问        %1"))
        .arg(ksword::kvm::describeWatchAccess(entry.effectiveAccess));
    lines << text(QStringLiteral("  模式            首次访问"));
    lines << QString();

    // Virtual address remapping detection.
    //
    // This watch is bound to the physical page resolved at the moment of armament and will not follow new VA mappings.
    // If detection fails, **do not** continue displaying "Monitoring this
    // virtual address"—that statement appears correct but may be entirely false.
    if (entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL &&
        entry.requestedAddress != 0ULL)
    {
        const ksword::kvm::KvmMemoryResult kCurrent =
            ksword::kvm::translate(0, entry.requestedAddress);
        if (kCurrent.ok && kCurrent.physicalAddress != 0ULL)
        {
            const unsigned long long kCurrentPage =
                kCurrent.physicalAddress & ~0xFFFULL;
            lines << (kCurrentPage == entry.physicalPage
                ? text(QStringLiteral("映射核对        当前虚拟地址仍然落在被监视的那一页上。"))
                : text(QStringLiteral("映射核对        **当前虚拟地址已经指向 %1，与武装时的 %2 不是同一页。这条监视仍然盯着武装时那一页，不再对应该虚拟地址。**"))
                    .arg(hex64(kCurrentPage))
                    .arg(hex64(entry.physicalPage)));
        }
        else
        {
            lines << text(QStringLiteral("映射核对        当前翻译不出物理页，无法核对该虚拟地址是否还指向被监视的那一页。"));
        }
        lines << QString();
    }

    lines << text(QStringLiteral("命中"));
    if (entry.hitCount == 0UL)
    {
        lines << text(QStringLiteral("  尚未命中。"));
    }
    else
    {
        lines << text(QStringLiteral("  累计命中        %1 次"))
            .arg(entry.hitCount);
        lines << text(QStringLiteral("  事件序号        %1"))
            .arg(entry.lastHitSequence);
        lines << text(QStringLiteral("  证据状态        %1"))
            .arg(entry.lastHitStatus ==
                    KSWORD_ARK_HVM_EPT_WATCH_HIT_PUBLISHED
                ? text(QStringLiteral("事件已发布"))
                : text(QStringLiteral("已命中，但事件环没接住这条证据")));
        lines << text(QStringLiteral("  处理器          %1:%2"))
            .arg(entry.lastHitProcessorGroup)
            .arg(entry.lastHitProcessorNumber);
        lines << text(QStringLiteral("  客户物理地址    %1"))
            .arg(hex64(entry.lastHitGuestPhysicalAddress));
        lines << text(QStringLiteral("  客户线性地址    %1"))
            .arg(entry.lastHitGuestLinearValid
                ? hex64(entry.lastHitGuestLinearAddress)
                : text(QStringLiteral("处理器未报告")));
        // Range hit is only meaningful when the CPU provides a valid linear address; if none
        // is provided, report "Unable to determine" rather than defaulting to "Not in range."
        lines << text(QStringLiteral("  落在请求范围内  %1"))
            .arg(!entry.lastHitGuestLinearValid
                ? text(QStringLiteral("无法判断（没有有效的客户线性地址）"))
                : entry.lastHitRangeMatch
                    ? text(QStringLiteral("是"))
                    : text(QStringLiteral("否，落在同一页的其它偏移上")));
        lines << text(QStringLiteral("  RIP             %1"))
            .arg(hex64(entry.lastHitRip));
        lines << text(QStringLiteral("  RSP             %1"))
            .arg(hex64(entry.lastHitRsp));
        lines << text(QStringLiteral("  CR3             %1"))
            .arg(entry.lastHitCr3 != 0ULL
                ? hex64(entry.lastHitCr3)
                : text(QStringLiteral("未采集")));
        lines << QString();
        lines << text(QStringLiteral("归因"));
        const ksword::kvm::KvmWatchAttribution kAttribution =
            ksword::kvm::attributeKernelAddress(entry.lastHitRip);
        if (kAttribution.resolved)
        {
            lines << text(QStringLiteral("  模块            %1"))
                .arg(kAttribution.moduleName);
            lines << text(QStringLiteral("  模块路径        %1"))
                .arg(kAttribution.modulePath);
            lines << text(QStringLiteral("  模块内偏移      +0x%1"))
                .arg(kAttribution.relativeAddress, 0, 16);
            // Symbols come only from the export table: it cannot answer about static functions, so "no symbol" does
            // not mean "this address is not in a function"; it only means "no exported symbol precedes it". This
            // distinction must be stated, otherwise a missing symbol could be misinterpreted as an exception signal.
            lines << (kAttribution.symbolName.isEmpty()
                ? text(QStringLiteral("  符号            该地址之前没有导出符号（只解析导出表，不解析 PDB；静态函数本就不在其中）。"))
                : text(QStringLiteral("  符号            %1!%2+0x%3"))
                    .arg(kAttribution.moduleName)
                    .arg(kAttribution.symbolName)
                    .arg(kAttribution.symbolOffset, 0, 16));
        }
        else
        {
            // Unresolved module is a conclusion, not a failure: it is itself a suspicious reading.
            lines << text(QStringLiteral("  模块            未知可执行区域 —— 这个 RIP 不落在任何已加载内核模块的映像范围内。"));
            lines << text(QStringLiteral("                  用“查看写入者反汇编”直接看那一段代码。"));
        }
        /*
         * Process attribution is a post-processing step and is an explicit operation.
         *
         * Display "Not parsed yet" instead of "Unknown" when parsing hasn't occurred; the latter
         * conflates "not asked" with "asked but no result," where only the latter is a conclusion.
         */
        if (entry.lastHitCr3 == 0ULL)
        {
            lines << text(QStringLiteral("  进程            命中现场没有记下地址空间，无从归因。"));
        }
        else
        {
            const auto kCached = processAttribution_.constFind(entry.lastHitCr3);
            lines << (kCached != processAttribution_.constEnd()
                ? text(QStringLiteral("  进程            %1"))
                    .arg(ksword::kvm::describeProcessAttribution(*kCached))
                : text(QStringLiteral("  进程            尚未解析。点“解析命中进程”按 CR3 反查——这一步要逐个进程读页目录基址，所以不随选中行自动跑。")));
        }
    }
    lines << QString();
    lines << text(QStringLiteral("HVM"));
    lines << text(QStringLiteral("  监视状态        %1"))
        .arg(ksword::kvm::describeWatchState(entry.state));
    lines << text(QStringLiteral("  武装代次        %1"))
        .arg(entry.armedGeneration);
    detail_->setPlainText(lines.join(QLatin1Char('\n')));
}

void KvmWatchPanel::startAdd()
{
    KvmWatchAddDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    if (!dialog.addressValid())
    {
        statusLabel_->setText(
            text(QStringLiteral("地址不是合法的非零十六进制数。")));
        return;
    }
    const ksword::kvm::KvmWatchTarget kTarget = dialog.target();
    if (kTarget.access == 0UL)
    {
        statusLabel_->setText(
            text(QStringLiteral("请至少选择一种要监视的访问类型。")));
        return;
    }
    setBusy(true);
    statusLabel_->setText(text(QStringLiteral("正在安装监视...")));
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, kTarget]() {
        const ksword::kvm::KvmWatchResult kResult =
            ksword::kvm::addWatch(kTarget);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::startRearm()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        statusLabel_->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    statusLabel_->setText(text(QStringLiteral("正在重新武装...")));
    const unsigned long kWatchId = entry.watchId;
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, kWatchId]() {
        const ksword::kvm::KvmWatchResult kResult =
            ksword::kvm::rearmWatch(kWatchId);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::startRemove()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        statusLabel_->setText(
            text(QStringLiteral("请先在表中选择一条监视。")));
        return;
    }
    setBusy(true);
    statusLabel_->setText(text(QStringLiteral("正在移除监视...")));
    const unsigned long kWatchId = entry.watchId;
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, kWatchId]() {
        const ksword::kvm::KvmWatchResult kResult =
            ksword::kvm::removeWatch(kWatchId);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kResult]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(kResult.message);
                safeThis->refreshAsync();
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::openWriterDisassembly()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) ||
        entry.lastHitRip == 0ULL)
    {
        return;
    }
    /*
     * Start disassembly slightly before the hit RIP.
     *
     * RIP points to the instruction that has not yet retired: an EPT violation occurs before the instruction causing
     * the access retires. Looking only from RIP, the user sees the instruction itself, not the preceding instructions
     * that calculated the address—which is often the key to finding the root cause of how this write was computed.
     */
    const unsigned long long kStart = entry.lastHitRip >= 0x40ULL
        ? entry.lastHitRip - 0x40ULL
        : entry.lastHitRip;
    ks::ui::KernelDisassemblyDialog::openKernelAddress(
        this,
        kStart,
        text(QStringLiteral("内存监视 #%1 命中的 RIP %2"))
            .arg(entry.watchId)
            .arg(hex64(entry.lastHitRip)),
        0x200U);
}

void KvmWatchPanel::openTargetMemory()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.physicalPage == 0ULL)
    {
        return;
    }
    /*
     * Prioritize reading by virtual address; fall back to physical pages if not found.
     *
     * They are not equivalent: reading a virtual address gets 'what this VA currently points to', while reading a physical page
     * gets 'the page being monitored'. After remapping, these are different pages, and the user almost always wants the latter.
     * Thus, the physical page read method is a fallback, not a downgrade; the report must clearly state which one was read.
     */
    const bool kByVirtual =
        entry.addressKind == KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL &&
        entry.requestedAddress != 0ULL;
    const unsigned long long kAddress = kByVirtual
        ? entry.requestedAddress
        : entry.physicalPage;
    const ksword::kvm::KvmMemoryResult kResult = kByVirtual
        ? ksword::kvm::readVirtual(0, kAddress, 256U)
        : ksword::kvm::readPhysical(kAddress, 256U);
    if (!kResult.ok)
    {
        statusLabel_->setText(
            text(QStringLiteral("读不到目标内存：%1")).arg(kResult.message));
        return;
    }
    QStringList lines;
    lines << text(QStringLiteral("目标内存（命中之后的采样，不是命中那一刻的值）"));
    lines << (kByVirtual
        ? text(QStringLiteral("  按虚拟地址 %1 读 %2 字节"))
            .arg(hex64(kAddress)).arg(kResult.data.size())
        : text(QStringLiteral("  按被监视的物理页 %1 读 %2 字节"))
            .arg(hex64(kAddress)).arg(kResult.data.size()));
    lines << QString();
    for (int offset = 0; offset < kResult.data.size(); offset += 16)
    {
        const QByteArray kChunk = kResult.data.mid(offset, 16);
        lines << QStringLiteral("  %1  %2")
            .arg(hex64(kAddress + static_cast<unsigned long long>(offset)))
            .arg(QString::fromLatin1(kChunk.toHex(' ')));
    }
    detail_->setPlainText(lines.join(QLatin1Char('\n')));
    statusLabel_->setText(text(QStringLiteral(
        "已读出目标内存。这是命中之后的采样：EPT violation 发生在写指令退休之前，所以这里看到的可能已经包含那次写入，也可能还包含之后的更多次修改。")));
}

void KvmWatchPanel::openWriterModule()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitRip == 0ULL)
    {
        return;
    }
    const ksword::kvm::KvmWatchAttribution kAttribution =
        ksword::kvm::attributeKernelAddress(entry.lastHitRip);
    if (!kAttribution.resolved || kAttribution.modulePath.isEmpty())
    {
        statusLabel_->setText(text(QStringLiteral(
            "这个 RIP 不落在任何已加载内核模块里，没有模块文件可打开。")));
        return;
    }
    /*
     * The kernel returns NT-style paths like \SystemRoot\, which the file explorer does not recognize.
     *
     * On conversion failure, do not fall back to 'try the original string': the file explorer may open a default directory using a
     * non-existent path, appearing successful while misleading the user into thinking they are viewing the module's actual directory.
     */
    const QString kWin32Path = ksword::kvm::toWin32ModulePath(kAttribution.modulePath);
    if (kWin32Path.isEmpty() || !QFileInfo::exists(kWin32Path))
    {
        statusLabel_->setText(
            text(QStringLiteral("模块文件 %1 在磁盘上找不到。"))
                .arg(kAttribution.modulePath));
        return;
    }
    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        QStringList() << QStringLiteral("/select,")
                      << QDir::toNativeSeparators(kWin32Path));
    statusLabel_->setText(
        text(QStringLiteral("已在资源管理器里定位 %1。")).arg(kWin32Path));
}

void KvmWatchPanel::resolveHitProcess()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry) || entry.lastHitCr3 == 0ULL)
    {
        return;
    }
    const quint64 kCr3 = entry.lastHitCr3;
    setBusy(true);
    statusLabel_->setText(text(QStringLiteral(
        "正在按 CR3 逐个进程反查地址空间...")));
    QPointer<KvmWatchPanel> safeThis(this);
    std::thread([safeThis, kCr3]() {
        const ksword::kvm::KvmProcessAttribution kAttribution =
            ksword::kvm::attributeProcessByCr3(kCr3);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kCr3, kAttribution]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->processAttribution_.insert(kCr3, kAttribution);
                safeThis->setBusy(false);
                safeThis->statusLabel_->setText(
                    ksword::kvm::describeProcessAttribution(kAttribution));
                ksword::kvm::KvmWatchEntry selected;
                if (safeThis->selectedWatch(&selected))
                {
                    safeThis->showDetail(selected);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmWatchPanel::exportEvidence()
{
    if (table_ == nullptr || table_->rowCount() == 0)
    {
        return;
    }
    const QString kPath = QFileDialog::getSaveFileName(
        this,
        text(QStringLiteral("导出内存监视证据")),
        QStringLiteral("hvm-memory-watch-%1.txt")
            .arg(QDateTime::currentDateTime().toString(
                QStringLiteral("yyyyMMdd-HHmmss"))),
        text(QStringLiteral("文本文件 (*.txt)")));
    if (kPath.isEmpty())
    {
        return;
    }
    QStringList blocks;
    blocks << text(QStringLiteral("KSword R-1 内存监视证据"));
    blocks << text(QStringLiteral("导出时间：%1"))
        .arg(QDateTime::currentDateTime().toString(Qt::ISODate));
    // Boundary statement at the front: this file will be circulated separately, and the
    // phrase 'this is not protection' must not remain on the UI without being extracted.
    blocks << text(QStringLiteral("这是观察与归因记录，不是保护：命中不阻止访问；硬件监视单位是 4 KiB 页而不是请求范围；DMA 改写不经过 CPU 的 EPT；虚拟地址的绑定在武装那一刻定死，之后的重映射不跟踪。"));
    blocks << QString();
    for (int row = 0; row < table_->rowCount(); ++row)
    {
        QTableWidgetItem* const kItem = table_->item(row, kWatchColumnId);
        if (kItem == nullptr)
        {
            continue;
        }
        const QVariant kStored = kItem->data(Qt::UserRole);
        if (!kStored.isValid())
        {
            continue;
        }
        // Reuses the format from the details dialog: what is displayed on screen and what is exported
        // must be identical; generating a separate copy would cause them to drift over time.
        showDetail(kStored.value<ksword::kvm::KvmWatchEntry>());
        blocks << QStringLiteral("================================");
        blocks << detail_->toPlainText();
        blocks << QString();
    }
    QFile file(kPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        statusLabel_->setText(
            text(QStringLiteral("导出失败：无法写入 %1。")).arg(kPath));
        return;
    }
    // Explicit UTF-8: this file contains only Chinese labels; following the system locale would cause garbled text on other machines.
    QTextStream stream(&file);
    stream.setEncoding(QStringConverter::Utf8);
    stream << blocks.join(QLatin1Char('\n'));
    file.close();
    statusLabel_->setText(
        text(QStringLiteral("已导出 %1 条监视的完整证据到 %2。"))
            .arg(table_->rowCount())
            .arg(kPath));
    // Exporting leaves the details pane on the last item; redrawing the
    // selected item ensures the displayed content matches the selected row.
    ksword::kvm::KvmWatchEntry selected;
    if (selectedWatch(&selected))
    {
        showDetail(selected);
    }
}

void KvmWatchPanel::copyEvidence()
{
    ksword::kvm::KvmWatchEntry entry;
    if (!selectedWatch(&entry))
    {
        return;
    }
    // Directly copy the detail box's raw text: what is seen on screen and what is pasted must
    // be identical; generating a separate formatted version causes them to drift over time.
    showDetail(entry);
    QApplication::clipboard()->setText(detail_->toPlainText());
    statusLabel_->setText(
        text(QStringLiteral("已把这条监视的完整证据复制到剪贴板。")));
}

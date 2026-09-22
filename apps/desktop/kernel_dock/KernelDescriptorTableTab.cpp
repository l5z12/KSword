#include "KernelDescriptorTableTab.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/KernelDisassemblyDialog.h"
#include "../ui/TableInteractionSupport.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum DescriptorColumn : int
    {
        kColumnTable = 0,
        kColumnCpu,
        kColumnVectorSelector,
        kColumnTableBase,
        kColumnTableLimit,
        kColumnEntryAddress,
        kColumnSize,
        kColumnTargetBase,
        kColumnSelector,
        kColumnType,
        kColumnDpl,
        kColumnPresent,
        kColumnIst,
        kColumnGranularity,
        kColumnOwner,
        kColumnRisk,
        kColumnBaseline,
        kColumnTrustedImageBaseline,
        kColumnRaw,
        kColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString tableStyle()
    {
        return QStringLiteral("QTableWidget{background:transparent;color:%1;} QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
            .arg(ksword_theme::textPrimaryHex())
            .arg(ksword_theme::kPrimaryBlueHex)
            .arg(ksword_theme::borderHex());
    }
}

KernelDescriptorTableTab::KernelDescriptorTableTab(
    const KernelDescriptorTableKind tableKind,
    QWidget* parent)
    : QWidget(parent),
      tableKind_(tableKind)
{
    initializeUi();
}

void KernelDescriptorTableTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void KernelDescriptorTableTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    // idtOnly selects precise text for two independent sub-pages without changing the page type at runtime.
    const bool kIdtOnly = tableKind_ == KernelDescriptorTableKind::kIdt;
    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        kernelText(
            kIdtOnly ? "kernel.descriptor.refresh.idt" : "kernel.descriptor.refresh.gdt",
            kIdtOnly ? QStringLiteral("刷新 IDT") : QStringLiteral("刷新 GDT")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    if (kIdtOnly)
    {
        restoreIdtButton_ = new QPushButton(
            kernelText("kernel.descriptor.restore_idt", QStringLiteral("恢复选中 IDT 基线")),
            this);
        restoreIdtButton_->setStyleSheet(ksword_theme::themedButtonStyle());
        restoreIdtButton_->setEnabled(false);
    }
    filterEdit_ = new QLineEdit(this);
    filterEdit_->setClearButtonEnabled(true);
    filterEdit_->setPlaceholderText(kernelText(
        kIdtOnly
            ? "kernel.descriptor.filter.idt.placeholder"
            : "kernel.descriptor.filter.gdt.placeholder",
        kIdtOnly
            ? QStringLiteral("按 CPU、向量、地址、模块和风险筛选 IDT")
            : QStringLiteral("按 CPU、选择子、地址、类型和风险筛选 GDT")));
    statusLabel_ = new QLabel(kernelText("kernel.descriptor.status.waiting", QStringLiteral("状态：等待刷新")), this);
    statusLabel_->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(ksword_theme::textSecondaryHex()));
    toolbar->addWidget(refreshButton_);
    if (restoreIdtButton_ != nullptr)
    {
        toolbar->addWidget(restoreIdtButton_);
    }
    toolbar->addWidget(filterEdit_, 1);
    toolbar->addWidget(statusLabel_);
    rootLayout->addLayout(toolbar);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    table_ = new ks::ui::VisibleTableWidget(splitter);
    table_->setColumnCount(kColumnCount);
    table_->setHorizontalHeaderLabels({
        kernelText("kernel.descriptor.header.table", QStringLiteral("表")),
        kernelText("kernel.descriptor.header.cpu", QStringLiteral("CPU")),
        kernelText("kernel.descriptor.header.vector_selector", QStringLiteral("向量/选择子")),
        kernelText("kernel.descriptor.header.table_base", QStringLiteral("表基址")),
        kernelText("kernel.descriptor.header.table_limit", QStringLiteral("表 Limit")),
        kernelText("kernel.descriptor.header.entry", QStringLiteral("表项地址")),
        kernelText("kernel.descriptor.header.size", QStringLiteral("大小")),
        kernelText("kernel.descriptor.header.target_base", QStringLiteral("Handler/段基址")),
        kernelText("kernel.descriptor.header.selector", QStringLiteral("SEL")),
        kernelText("kernel.descriptor.header.type", QStringLiteral("类型")),
        kernelText("kernel.descriptor.header.dpl", QStringLiteral("DPL")),
        kernelText("kernel.descriptor.header.present", QStringLiteral("Present")),
        kernelText("kernel.descriptor.header.ist", QStringLiteral("IST")),
        kernelText("kernel.descriptor.header.granularity", QStringLiteral("Granularity")),
        kernelText("kernel.descriptor.header.owner", QStringLiteral("归属模块")),
        kernelText("kernel.descriptor.header.risk", QStringLiteral("完整性")),
        kernelText("kernel.descriptor.header.baseline", QStringLiteral("启动期基线")),
        kernelText("kernel.descriptor.header.trusted_image_baseline", QStringLiteral("可信映像基线")),
        kernelText("kernel.descriptor.header.raw", QStringLiteral("原始值"))});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setAlternatingRowColors(true);
    table_->setContextMenuPolicy(Qt::CustomContextMenu);
    table_->setStyleSheet(tableStyle());
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->verticalHeader()->setVisible(false);

    detailEdit_ = new QTextEdit(splitter);
    detailEdit_->setReadOnly(true);
    detailEdit_->setPlaceholderText(kernelText(
        kIdtOnly
            ? "kernel.descriptor.detail.idt.placeholder"
            : "kernel.descriptor.detail.gdt.placeholder",
        kIdtOnly
            ? QStringLiteral("选择 IDT 表项查看 Handler、位域和 R0 诊断详情")
            : QStringLiteral("选择 GDT 表项查看段描述符、位域和 R0 诊断详情")));
    splitter->addWidget(table_);
    splitter->addWidget(detailEdit_);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 1);
    rootLayout->addWidget(splitter, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    if (restoreIdtButton_ != nullptr)
    {
        connect(restoreIdtButton_, &QPushButton::clicked, this, [this]() { restoreSelectedIdtBaseline(); });
    }
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(table_, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCurrentDetail();
        if (restoreIdtButton_ == nullptr)
        {
            return;
        }
        bool canRestore = false;
        if (table_->currentRow() >= 0)
        {
            const QTableWidgetItem* item = table_->item(table_->currentRow(), kColumnTable);
            if (item != nullptr)
            {
                const std::size_t kSourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
                if (kSourceIndex < rows_.size())
                {
                    const auto& row = rows_[kSourceIndex];
                    canRestore =
                        row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER &&
                        (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) != 0U &&
                        (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS) != 0U;
                }
            }
        }
        restoreIdtButton_->setEnabled(canRestore && !refreshRunning_);
    });
    connect(table_, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void KernelDescriptorTableTab::refreshAsync()
{
    if (refreshRunning_)
    {
        return;
    }
    refreshRunning_ = true;
    firstRefreshStarted_ = true;
    refreshButton_->setEnabled(false);
    if (restoreIdtButton_ != nullptr)
    {
        restoreIdtButton_->setEnabled(false);
    }

    // queryFlags requests evidence only for the current sub-page, avoiding redundant transmission of the other table when switching IDT/GDT.
    const bool kIdtOnly = tableKind_ == KernelDescriptorTableKind::kIdt;
    const std::uint32_t kQueryFlags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU |
        (kIdtOnly
            ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES
            : KSWORD_ARK_DRIVER_INTEGRITY_FLAG_GDT_ENTRIES);
    statusLabel_->setText(kernelText(
        kIdtOnly
            ? "kernel.descriptor.status.refreshing.idt"
            : "kernel.descriptor.status.refreshing.gdt",
        kIdtOnly
            ? QStringLiteral("正在按 CPU 读取 IDTR 与 IDT 表项...")
            : QStringLiteral("正在按 CPU 读取 GDTR 与 GDT 描述符...")));
    QPointer<KernelDescriptorTableTab> safeThis(this);
    std::thread([safeThis, kQueryFlags]() {
        ksword::ark::DriverClient client;
        ksword::ark::DriverIntegrityResult result = client.queryKernelCpuIntegrity(
            kQueryFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
        std::vector<ks::kernel::IdtHandlerObservation> observations;
        if (result.io.ok
            && (kQueryFlags
                & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES) != 0U)
        {
            for (const ksword::ark::DriverIntegrityEvidenceEntry& row
                 : result.entries)
            {
                if (row.evidenceClass
                    == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
                {
                    observations.push_back({
                        row.vector,
                        row.descriptorBase
                    });
                }
            }
        }
        std::vector<ks::kernel::TrustedIdtBaselineResult>
            trustedIdtBaselines =
                ks::kernel::KernelCleanImageBaseline::compareIdtHandlers(
                    observations);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [
            safeThis,
            result = std::move(result),
            trustedIdtBaselines = std::move(trustedIdtBaselines)
        ]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applyResult(
                    std::move(result),
                    std::move(trustedIdtBaselines));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDescriptorTableTab::applyResult(
    ksword::ark::DriverIntegrityResult result,
    std::vector<ks::kernel::TrustedIdtBaselineResult>
        trustedIdtBaselines)
{
    const QPointer<KernelDescriptorTableTab> kSafeThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-descriptor-table-snapshot"),
        { table_ },
        [kSafeThis, result, trustedIdtBaselines]() mutable
        {
            if (!kSafeThis.isNull())
            {
                kSafeThis->applyResult(
                    std::move(result),
                    std::move(trustedIdtBaselines));
            }
        }))
    {
        return;
    }

    refreshRunning_ = false;
    refreshButton_->setEnabled(true);
    if (restoreIdtButton_ != nullptr)
    {
        restoreIdtButton_->setEnabled(false);
    }
    rows_.clear();
    trustedIdtBaselines_.clear();
    if (!result.io.ok)
    {
        // failureKey and fallbackText are determined by the fixed sub-page type to avoid mixing IDT/GDT query error messages.
        const bool kIdtOnly = tableKind_ == KernelDescriptorTableKind::kIdt;
        const QString kErrorText = result.io.message.empty()
            ? kernelText(
                kIdtOnly
                    ? "kernel.descriptor.status.failed.idt"
                    : "kernel.descriptor.status.failed.gdt",
                kIdtOnly ? QStringLiteral("IDT 查询失败") : QStringLiteral("GDT 查询失败"))
            : QString::fromStdString(result.io.message);
        statusLabel_->setText(kErrorText);
        rebuildTable();
        return;
    }

    std::size_t idtCount = 0U;
    std::size_t gdtCount = 0U;
    std::size_t trustedIdtIndex = 0U;
    for (ksword::ark::DriverIntegrityEvidenceEntry& row : result.entries)
    {
        if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
        {
            ++idtCount;
            rows_.push_back(std::move(row));
            if (trustedIdtIndex < trustedIdtBaselines.size())
            {
                trustedIdtBaselines_.push_back(
                    std::move(
                        trustedIdtBaselines[trustedIdtIndex]));
            }
            else
            {
                trustedIdtBaselines_.emplace_back();
            }
            ++trustedIdtIndex;
        }
        else if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR)
        {
            ++gdtCount;
            rows_.push_back(std::move(row));
            trustedIdtBaselines_.emplace_back();
        }
    }
    // summary reports only the number of entries in the current sub-page; CPU and protocol version are retained to locate the collection environment.
    const bool kIdtOnly = tableKind_ == KernelDescriptorTableKind::kIdt;
    QString summary = kIdtOnly
        ? kernelText(
            "kernel.descriptor.status.completed.idt",
            QStringLiteral("已读取 %1 个 IDT 表项，CPU %2，协议 v%3"))
            .arg(static_cast<qulonglong>(idtCount))
            .arg(result.cpuCount)
            .arg(result.version)
        : kernelText(
            "kernel.descriptor.status.completed.gdt",
            QStringLiteral("已读取 %1 个 GDT 表项，CPU %2，协议 v%3"))
            .arg(static_cast<qulonglong>(gdtCount))
            .arg(result.cpuCount)
            .arg(result.version);
    if ((result.flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED) != 0U ||
        (result.statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED) != 0U)
    {
        summary += kernelText("kernel.descriptor.status.truncated", QStringLiteral("；响应已截断，部分 CPU 表项未返回"));
    }
    if (kIdtOnly)
    {
        const std::size_t kTrustedAvailable = static_cast<std::size_t>(
            std::count_if(
                trustedIdtBaselines_.cbegin(),
                trustedIdtBaselines_.cend(),
                [](const ks::kernel::TrustedIdtBaselineResult& baseline)
                {
                    return baseline.available;
                }));
        const std::size_t kTrustedMismatch = static_cast<std::size_t>(
            std::count_if(
                trustedIdtBaselines_.cbegin(),
                trustedIdtBaselines_.cend(),
                [](const ks::kernel::TrustedIdtBaselineResult& baseline)
                {
                    return baseline.available
                        && !baseline.handlerMatches;
                }));
        summary += kernelText(
            "kernel.descriptor.status.trusted_baseline_summary",
            QStringLiteral(
                "；可信映像/PDB 基线可用 %1，偏离 %2，unsupported %3"))
            .arg(static_cast<qulonglong>(kTrustedAvailable))
            .arg(static_cast<qulonglong>(kTrustedMismatch))
            .arg(static_cast<qulonglong>(
                trustedIdtBaselines_.size() - kTrustedAvailable));
    }
    statusLabel_->setText(summary);
    rebuildTable();
}

bool KernelDescriptorTableTab::rowMatchesFilter(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const std::size_t sourceIndex) const
{
    // expectedClass fixes the instance to a single table type, preventing page corruption even if old drivers unexpectedly return mixed evidence.
    const std::uint32_t kExpectedClass = tableKind_ == KernelDescriptorTableKind::kIdt
        ? KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        : KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR;
    if (row.evidenceClass != kExpectedClass)
    {
        return false;
    }
    const QString kKeyword = filterEdit_->text().trimmed();
    if (kKeyword.isEmpty())
    {
        return true;
    }
    QStringList values;
    for (int column = 0; column < kColumnCount; ++column)
    {
        values.push_back(columnText(row, column, sourceIndex));
    }
    values.push_back(QString::fromStdWString(row.detail));
    return values.join(QLatin1Char(' ')).contains(kKeyword, Qt::CaseInsensitive);
}

void KernelDescriptorTableTab::rebuildTable()
{
    table_->setRowCount(0);
    for (std::size_t sourceIndex = 0U; sourceIndex < rows_.size(); ++sourceIndex)
    {
        const ksword::ark::DriverIntegrityEvidenceEntry& row = rows_[sourceIndex];
        if (!rowMatchesFilter(row, sourceIndex))
        {
            continue;
        }
        const int kTableRow = table_->rowCount();
        table_->insertRow(kTableRow);
        for (int column = 0; column < kColumnCount; ++column)
        {
            QTableWidgetItem* item = readOnlyItem(
                columnText(row, column, sourceIndex));
            if (column == kColumnTable)
            {
                item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            }
            if (column == kColumnRisk)
            {
                item->setForeground(row.riskFlags == 0U
                    ? ksword_theme::successColor()
                    : ksword_theme::errorColor());
            }
            if (column == kColumnTrustedImageBaseline
                && sourceIndex < trustedIdtBaselines_.size()
                && trustedIdtBaselines_[sourceIndex].available)
            {
                item->setForeground(
                    trustedIdtBaselines_[sourceIndex].handlerMatches
                        ? ksword_theme::successColor()
                        : ksword_theme::errorColor());
            }
            table_->setItem(kTableRow, column, item);
        }
    }
    table_->resizeColumnsToContents();
    showCurrentDetail();
}

QString KernelDescriptorTableTab::tableName(const ksword::ark::DriverIntegrityEvidenceEntry& row)
{
    return row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        ? QStringLiteral("IDT")
        : QStringLiteral("GDT");
}

QString KernelDescriptorTableTab::descriptorTypeText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
{
    if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
    {
        if (row.descriptorType == 0xEU)
        {
            return kernelText("kernel.descriptor.type.interrupt_gate", QStringLiteral("Interrupt Gate"));
        }
        if (row.descriptorType == 0xFU)
        {
            return kernelText("kernel.descriptor.type.trap_gate", QStringLiteral("Trap Gate"));
        }
        return kernelText("kernel.descriptor.type.gate", QStringLiteral("Gate 0x%1")).arg(row.descriptorType, 0, 16);
    }
    if ((row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_USER_SEGMENT) != 0U)
    {
        const bool kCode = (row.descriptorType & 0x8U) != 0U;
        const bool kAccessed = (row.descriptorType & 0x1U) != 0U;
        const bool kReadableWritable = (row.descriptorType & 0x2U) != 0U;
        if (kCode)
        {
            return kernelText("kernel.descriptor.type.code", QStringLiteral("Code%1%2"))
                .arg(kReadableWritable ? QStringLiteral(" R") : QString())
                .arg(kAccessed ? QStringLiteral(" A") : QString());
        }
        return kernelText("kernel.descriptor.type.data", QStringLiteral("Data%1%2"))
            .arg(kReadableWritable ? QStringLiteral(" W") : QString())
            .arg(kAccessed ? QStringLiteral(" A") : QString());
    }
    switch (row.descriptorType)
    {
    case 0x0U: return kernelText("kernel.descriptor.type.reserved", QStringLiteral("Reserved"));
    case 0x2U: return QStringLiteral("LDT");
    case 0x9U: return kernelText("kernel.descriptor.type.tss_available", QStringLiteral("TSS Available"));
    case 0xBU: return kernelText("kernel.descriptor.type.tss_busy", QStringLiteral("TSS Busy"));
    case 0xCU: return kernelText("kernel.descriptor.type.call_gate", QStringLiteral("Call Gate"));
    case 0xEU: return kernelText("kernel.descriptor.type.interrupt_gate", QStringLiteral("Interrupt Gate"));
    case 0xFU: return kernelText("kernel.descriptor.type.trap_gate", QStringLiteral("Trap Gate"));
    default: return kernelText("kernel.descriptor.type.system", QStringLiteral("System 0x%1")).arg(row.descriptorType, 0, 16);
    }
}

QString KernelDescriptorTableTab::riskText(const std::uint32_t riskFlags)
{
    if (riskFlags == 0U)
    {
        return kernelText("kernel.descriptor.risk.clean", QStringLiteral("正常"));
    }
    QStringList risks;
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.invalid", QStringLiteral("描述符异常")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.non_core", QStringLiteral("非核心模块")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.unresolved", QStringLiteral("模块未解析")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.read_failed", QStringLiteral("读取失败")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.baseline_changed", QStringLiteral("偏离启动期基线")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_DIVERGED) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.table_diverged", QStringLiteral("IDT 表与多数 CPU 不一致")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_RELOCATED) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.table_relocated", QStringLiteral("IDT 表被重定位")));
    }
    if ((riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC) != 0U)
    {
        risks.push_back(kernelText("kernel.descriptor.risk.target_non_exec", QStringLiteral("目标不在可执行节")));
    }
    if (risks.isEmpty())
    {
        risks.push_back(hex32(riskFlags));
    }
    return risks.join(QStringLiteral(" / "));
}

QString KernelDescriptorTableTab::columnText(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const int column,
    const std::size_t sourceIndex) const
{
    const bool kIsIdt = row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER;
    switch (column)
    {
    case kColumnTable: return tableName(row);
    case kColumnCpu: return QStringLiteral("%1:%2").arg(row.processorGroup).arg(row.processorNumber);
    case kColumnVectorSelector:
        return kIsIdt ? QString::number(row.vector) : hex32(row.descriptorSelector);
    case kColumnTableBase: return hex64(row.descriptorTableBase);
    case kColumnTableLimit: return hex32(row.descriptorTableLimit);
    case kColumnEntryAddress: return hex64(row.objectAddress);
    case kColumnSize: return QString::number(row.descriptorSize);
    case kColumnTargetBase: return hex64(row.descriptorBase);
    case kColumnSelector: return hex32(row.descriptorSelector);
    case kColumnType: return descriptorTypeText(row);
    case kColumnDpl: return QString::number(row.descriptorDpl);
    case kColumnPresent:
        return (row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT) != 0U ? QStringLiteral("P") : QStringLiteral("-");
    case kColumnIst:
        return kIsIdt ? QString::number(static_cast<unsigned int>((row.descriptorRawLow >> 32) & 0x7ULL)) : QStringLiteral("-");
    case kColumnGranularity:
        return kIsIdt
            ? QStringLiteral("-")
            : ((row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_GRANULARITY_PAGE) != 0U ? QStringLiteral("PAGE") : QStringLiteral("BYTE"));
    case kColumnOwner: return QString::fromStdWString(row.ownerModule);
    case kColumnRisk: return riskText(row.riskFlags);
    case kColumnBaseline:
        if ((row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) == 0U)
        {
            return kernelText("kernel.descriptor.baseline.unavailable", QStringLiteral("不可用"));
        }
        return (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS) != 0U
            ? hex64(row.descriptorBaselineRawLow) + QStringLiteral(" / ") + hex64(row.descriptorBaselineRawHigh)
            : kernelText("kernel.descriptor.baseline.matches", QStringLiteral("一致"));
    case kColumnTrustedImageBaseline:
        if (!kIsIdt || sourceIndex >= trustedIdtBaselines_.size())
        {
            return QStringLiteral("-");
        }
        if (!trustedIdtBaselines_[sourceIndex].available)
        {
            return kernelText(
                "kernel.descriptor.trusted_baseline.unsupported",
                QStringLiteral("Unsupported"));
        }
        return trustedIdtBaselines_[sourceIndex].handlerMatches
            ? kernelText(
                "kernel.descriptor.trusted_baseline.matches",
                QStringLiteral("一致"))
            : kernelText(
                "kernel.descriptor.trusted_baseline.differs",
                QStringLiteral("偏离"));
    case kColumnRaw:
        return row.descriptorSize > 8U
            ? hex64(row.descriptorRawLow) + QStringLiteral(" / ") + hex64(row.descriptorRawHigh)
            : hex64(row.descriptorRawLow);
    default: return {};
    }
}

QString KernelDescriptorTableTab::detailText(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const std::size_t sourceIndex) const
{
    QStringList lines;
    lines << kernelText("kernel.descriptor.detail.table", QStringLiteral("表: %1")).arg(tableName(row));
    lines << kernelText("kernel.descriptor.detail.cpu", QStringLiteral("CPU: %1:%2")).arg(row.processorGroup).arg(row.processorNumber);
    lines << kernelText("kernel.descriptor.detail.table_range", QStringLiteral("表基址: %1  Limit: %2")).arg(hex64(row.descriptorTableBase), hex32(row.descriptorTableLimit));
    lines << kernelText("kernel.descriptor.detail.entry", QStringLiteral("表项: %1  大小: %2")).arg(hex64(row.objectAddress)).arg(row.descriptorSize);
    lines << kernelText("kernel.descriptor.detail.decoded", QStringLiteral("选择子: %1  类型: %2  DPL: %3  基址/Handler: %4  Limit: %5"))
        .arg(hex32(row.descriptorSelector), descriptorTypeText(row))
        .arg(row.descriptorDpl)
        .arg(hex64(row.descriptorBase), hex64(row.descriptorLimit));
    lines << kernelText("kernel.descriptor.detail.flags", QStringLiteral("Flags: %1  风险: %2")).arg(hex32(row.descriptorFlags), riskText(row.riskFlags));
    lines << kernelText("kernel.descriptor.detail.raw", QStringLiteral("Raw: %1 / %2")).arg(hex64(row.descriptorRawLow), hex64(row.descriptorRawHigh));
    if ((row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) != 0U)
    {
        lines << kernelText(
            "kernel.descriptor.detail.baseline",
            QStringLiteral("启动期基线 #%1: Handler %2  Raw %3 / %4"))
            .arg(row.descriptorBaselineGeneration)
            .arg(hex64(row.descriptorBaselineHandler))
            .arg(hex64(row.descriptorBaselineRawLow))
            .arg(hex64(row.descriptorBaselineRawHigh));
    }
    if (row.evidenceClass
            == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        && sourceIndex < trustedIdtBaselines_.size())
    {
        const ks::kernel::TrustedIdtBaselineResult& trusted =
            trustedIdtBaselines_[sourceIndex];
        lines << kernelText(
            "kernel.descriptor.detail.trusted_baseline",
            QStringLiteral(
                "可信映像基线: %1\n主预期 Handler: %2\nPDB 候选数: %3\n观察 Handler: %4\n"
                "映像: %5\nSHA256: %6\nProfile: %7\n来源符号: %8\n状态: %9"))
            .arg(trusted.available
                ? QStringLiteral("AVAILABLE")
                : QStringLiteral("UNSUPPORTED"))
            .arg(hex64(trusted.expectedHandler))
            .arg(trusted.expectedCandidateCount)
            .arg(hex64(trusted.observedHandler))
            .arg(trusted.imagePath.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.imagePath)
            .arg(trusted.imageSha256.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.imageSha256)
            .arg(trusted.profilePath.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.profilePath)
            .arg(trusted.sourceSymbol.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.sourceSymbol)
            .arg(trusted.statusText);
    }
    if (!row.ownerModule.empty())
    {
        lines << kernelText("kernel.descriptor.detail.owner", QStringLiteral("归属模块: %1 [%2 +%3]"))
            .arg(QString::fromStdWString(row.ownerModule), hex64(row.ownerModuleBase), hex32(row.ownerModuleSize));
    }
    if (!row.detail.empty())
    {
        lines << QString() << QString::fromStdWString(row.detail);
    }
    return lines.join(QLatin1Char('\n'));
}

void KernelDescriptorTableTab::showCurrentDetail()
{
    if (table_->currentRow() < 0)
    {
        detailEdit_->clear();
        return;
    }
    const QTableWidgetItem* item = table_->item(table_->currentRow(), kColumnTable);
    if (item == nullptr)
    {
        detailEdit_->clear();
        return;
    }
    const std::size_t kSourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    detailEdit_->setPlainText(
        kSourceIndex < rows_.size()
            ? detailText(rows_[kSourceIndex], kSourceIndex)
            : QString());
}

void KernelDescriptorTableTab::restoreSelectedIdtBaseline()
{
    const int kSelectedRow = table_->currentRow();
    const QTableWidgetItem* item = kSelectedRow >= 0 ? table_->item(kSelectedRow, kColumnTable) : nullptr;
    if (item == nullptr)
    {
        return;
    }
    const std::size_t kSourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    if (kSourceIndex >= rows_.size())
    {
        return;
    }
    const auto kRow = rows_[kSourceIndex];
    if (kRow.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER ||
        kRow.processorGroup > 0xFFFFU ||
        kRow.processorNumber > 0xFFU ||
        kRow.vector > 0xFFU ||
        (kRow.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) == 0U ||
        (kRow.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS) == 0U)
    {
        QMessageBox::information(
            this,
            kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
            kernelText("kernel.descriptor.restore.not_needed", QStringLiteral("该行没有可恢复的 IDT 基线差异。")));
        return;
    }

    ksword::ark::DriverClient client;
    const auto kPreflight = client.restoreIdtBaseline(
        static_cast<std::uint16_t>(kRow.processorGroup),
        static_cast<std::uint8_t>(kRow.processorNumber),
        static_cast<std::uint8_t>(kRow.vector),
        kRow.descriptorRawLow,
        kRow.descriptorRawHigh,
        false,
        false);
    if (!kPreflight.io.ok ||
        kPreflight.status != KSWORD_ARK_IDT_RESTORE_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
            kernelText(
                "kernel.descriptor.restore.preflight_failed",
                QStringLiteral("R0 预检未通过。状态 %1，NTSTATUS %2。\n%3"))
                .arg(kPreflight.status)
                .arg(hex32(static_cast<std::uint32_t>(kPreflight.lastStatus)))
                .arg(QString::fromStdString(kPreflight.io.message)));
        return;
    }

    QMessageBox::warning(
        this,
        kernelText("kernel.descriptor.restore.warning_title", QStringLiteral("高风险：修改 IDT")),
        kernelText(
            "kernel.descriptor.restore.warning",
            QStringLiteral("将原子替换 CPU %1:%2 的 IDT 向量 %3。错误的中断门会立即造成系统崩溃；仅在已确认当前值异常且启动期基线可信时继续。"))
            .arg(kRow.processorGroup)
            .arg(kRow.processorNumber)
            .arg(kRow.vector));
    bool accepted = false;
    const QString kConfirmation = QInputDialog::getText(
        this,
        kernelText("kernel.descriptor.restore.confirm_title", QStringLiteral("确认恢复 IDT")),
        kernelText("kernel.descriptor.restore.confirm_prompt", QStringLiteral("输入 RESTORE IDT 继续：")),
        QLineEdit::Normal,
        QString(),
        &accepted);
    if (!accepted || kConfirmation != QStringLiteral("RESTORE IDT"))
    {
        return;
    }

    const auto kRestored = client.restoreIdtBaseline(
        static_cast<std::uint16_t>(kRow.processorGroup),
        static_cast<std::uint8_t>(kRow.processorNumber),
        static_cast<std::uint8_t>(kRow.vector),
        kRow.descriptorRawLow,
        kRow.descriptorRawHigh,
        true,
        true);
    if (!kRestored.io.ok || kRestored.status != KSWORD_ARK_IDT_RESTORE_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
            kernelText(
                "kernel.descriptor.restore.failed",
                QStringLiteral("IDT 恢复失败。状态 %1，NTSTATUS %2。\n%3"))
                .arg(kRestored.status)
                .arg(hex32(static_cast<std::uint32_t>(kRestored.lastStatus)))
                .arg(QString::fromStdString(kRestored.io.message)));
        return;
    }
    QMessageBox::information(
        this,
        kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
        kernelText(
            "kernel.descriptor.restore.completed",
            QStringLiteral("IDT 表项已按启动期基线恢复，并完成原子写入后的逐位校验。")));
    refreshAsync();
}

QString KernelDescriptorTableTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
}

QString KernelDescriptorTableTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
}

QString KernelDescriptorTableTab::rowClipboardText(QTableWidget* table, const int row, const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }
    QStringList lines;
    if (includeHeader)
    {
        QStringList headers;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            headers << (table->horizontalHeaderItem(column) == nullptr ? QString() : table->horizontalHeaderItem(column)->text());
        }
        lines << headers.join(QLatin1Char('\t'));
    }
    QStringList values;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        values << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    lines << values.join(QLatin1Char('\t'));
    return lines.join(QLatin1Char('\n'));
}

void KernelDescriptorTableTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex kIndex = table_->indexAt(position);
    const int kRow = kIndex.isValid() ? kIndex.row() : table_->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(kernelText("kernel.descriptor.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(kernelText("kernel.descriptor.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(kernelText("kernel.descriptor.copy.all", QStringLiteral("复制全部行")));
    menu.addSeparator();
    QMenu* advancedAnalysis = menu.addMenu(
        QStringLiteral("高级分析"));
    QAction* instructionView = advancedAnalysis->addAction(
        QStringLiteral("指令视图…"));
    copyCell->setEnabled(kIndex.isValid());
    copyRow->setEnabled(kRow >= 0);
    copyAll->setEnabled(table_->rowCount() > 0);
    std::size_t sourceIndex = rows_.size();
    if (kRow >= 0)
    {
        const QTableWidgetItem* sourceItem =
            table_->item(kRow, kColumnTable);
        if (sourceItem != nullptr)
        {
            sourceIndex = static_cast<std::size_t>(
                sourceItem->data(Qt::UserRole).toULongLong());
        }
    }
    const bool kCanOpenInstructionView =
        sourceIndex < rows_.size()
        && rows_[sourceIndex].evidenceClass
            == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        && rows_[sourceIndex].descriptorBase != 0U;
    instructionView->setEnabled(kCanOpenInstructionView);
    QAction* selected = menu.exec(table_->viewport()->mapToGlobal(position));
    if (selected == copyCell && kIndex.isValid())
    {
        const QTableWidgetItem* item = table_->item(kIndex.row(), kIndex.column());
        QApplication::clipboard()->setText(item == nullptr ? QString() : item->text());
    }
    else if (selected == copyRow)
    {
        QApplication::clipboard()->setText(rowClipboardText(table_, kRow, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int tableRow = 0; tableRow < table_->rowCount(); ++tableRow)
        {
            lines << rowClipboardText(table_, tableRow, tableRow == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
    else if (selected == instructionView
        && kCanOpenInstructionView)
    {
        const auto& descriptor = rows_[sourceIndex];
        ks::ui::KernelDisassemblyDialog::openKernelAddress(
            this,
            descriptor.descriptorBase,
            QStringLiteral(
                "IDT 向量 %1（CPU %2:%3）Handler")
                .arg(descriptor.vector)
                .arg(descriptor.processorGroup)
                .arg(descriptor.processorNumber));
    }
}

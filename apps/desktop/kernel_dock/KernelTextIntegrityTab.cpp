#include "KernelTextIntegrityTab.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;
using ks::kernel::KernelCleanImageBaseline;
using ks::kernel::KernelTextDiffRange;
using ks::kernel::KernelTextIntegrityResult;
using ks::kernel::KernelTextScanOptions;

namespace
{
    enum ModuleColumn : int
    {
        kModuleColumnName = 0,
        kModuleColumnBase,
        kModuleColumnSections,
        kModuleColumnScanned,
        kModuleColumnUnreadable,
        kModuleColumnDiffering,
        kModuleColumnKnown,
        kModuleColumnUnexplained,
        kModuleColumnTrust,
        kModuleColumnStatus,
        kModuleColumnCount
    };

    enum RangeColumn : int
    {
        kRangeColumnModule = 0,
        kRangeColumnSection,
        kRangeColumnRva,
        kRangeColumnAddress,
        kRangeColumnLength,
        kRangeColumnOrigin,
        kRangeColumnClean,
        kRangeColumnObserved,
        kRangeColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // setHeaderTip:
    // - Input table/column/tipText: target table, column index, and hover tooltip;
    // - Processing: Attach the evaluation criteria to the corresponding table header it explains.
    // - Return: None; silently skip if the header item is missing.
    void setHeaderTip(QTableWidget* table, const int column, const QString& tipText)
    {
        QTableWidgetItem* headerItem = table->horizontalHeaderItem(column);
        if (headerItem != nullptr)
        {
            headerItem->setToolTip(tipText);
        }
    }
}

KernelTextIntegrityTab::KernelTextIntegrityTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

KernelTextIntegrityTab::~KernelTextIntegrityTab()
{
    // The worker thread holds shared ownership of cancelFlag; this code is only responsible for ensuring it exits as soon as possible.
    if (cancelFlag_ != nullptr)
    {
        cancelFlag_->store(true);
    }
}

void KernelTextIntegrityTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstScanStarted_)
    {
        // A full scan is costly; the interface is only prepared on first entry and triggered by the user.
        firstScanStarted_ = true;
        statusLabel_->setText(
            kernelText(
                "kernel.text_integrity.status.idle",
                QStringLiteral("状态：点击“开始扫描”后逐模块比对可执行节")));
    }
}

void KernelTextIntegrityTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    scanButton_ = new QPushButton(
        kernelText("kernel.text_integrity.scan", QStringLiteral("开始扫描")),
        this);
    // Assessment criteria do not occupy layout space: attached to the trigger scan button; hover to view.
    scanButton_->setToolTip(
        kernelText(
            "kernel.text_integrity.scan.tooltip",
            QStringLiteral("比对基准是磁盘净映像按当前加载基址重定位后的结果。")));
    scanButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    cancelButton_ = new QPushButton(
        kernelText("kernel.text_integrity.cancel", QStringLiteral("取消")),
        this);
    cancelButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    cancelButton_->setEnabled(false);
    moduleFilterEdit_ = new QLineEdit(this);
    moduleFilterEdit_->setClearButtonEnabled(true);
    moduleFilterEdit_->setPlaceholderText(
        kernelText(
            "kernel.text_integrity.filter.placeholder",
            QStringLiteral("按模块名过滤，留空扫描全部已加载模块")));
    unexplainedOnlyCheck_ = new QCheckBox(
        kernelText(
            "kernel.text_integrity.unexplained_only",
            QStringLiteral("只看无法解释的差异")),
        this);
    unexplainedOnlyCheck_->setToolTip(
        kernelText(
            "kernel.text_integrity.unexplained_only.tooltip",
            QStringLiteral("勾选后隐藏归类为动态重定位的差异，只留下无法用已知机制解释的区间。")));
    unexplainedOnlyCheck_->setChecked(true);
    statusLabel_ = new QLabel(
        kernelText(
            "kernel.text_integrity.status.idle",
            QStringLiteral("状态：点击“开始扫描”后逐模块比对可执行节")),
        this);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::textSecondaryHex()));

    toolbar->addWidget(scanButton_);
    toolbar->addWidget(cancelButton_);
    toolbar->addWidget(moduleFilterEdit_, 1);
    toolbar->addWidget(unexplainedOnlyCheck_);
    toolbar->addWidget(statusLabel_);
    rootLayout->addLayout(toolbar);

    verdictLabel_ = new QLabel(this);
    verdictLabel_->setWordWrap(true);
    verdictLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verdictLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(ksword_theme::textPrimaryHex()));
    rootLayout->addWidget(verdictLabel_);

    auto* splitter = new QSplitter(Qt::Vertical, this);

    moduleTable_ = new ks::ui::VisibleTableWidget(splitter);
    moduleTable_->setColumnCount(kModuleColumnCount);
    moduleTable_->setHorizontalHeaderLabels({
        kernelText("kernel.text_integrity.module.name", QStringLiteral("模块")),
        kernelText("kernel.text_integrity.module.base", QStringLiteral("基址")),
        kernelText("kernel.text_integrity.module.sections", QStringLiteral("可执行节")),
        kernelText("kernel.text_integrity.module.scanned", QStringLiteral("已比对字节")),
        kernelText("kernel.text_integrity.module.unreadable", QStringLiteral("不可读字节")),
        kernelText("kernel.text_integrity.module.differing", QStringLiteral("差异字节")),
        kernelText("kernel.text_integrity.module.known", QStringLiteral("动态重定位位点")),
        kernelText("kernel.text_integrity.module.unexplained", QStringLiteral("无法解释")),
        kernelText("kernel.text_integrity.module.trust", QStringLiteral("磁盘信任")),
        kernelText("kernel.text_integrity.module.status", QStringLiteral("结论"))
    });
    // The classification rules follow the column they explain, which is easier to align with than a block of general explanation at the page header.
    setHeaderTip(
        moduleTable_,
        kModuleColumnUnreadable,
        kernelText(
            "kernel.text_integrity.module.unreadable.tooltip",
            QStringLiteral("分页换出导致的读取失败只计入这里，不会被算成篡改。")));
    setHeaderTip(
        moduleTable_,
        kModuleColumnKnown,
        kernelText(
            "kernel.text_integrity.module.known.tooltip",
            QStringLiteral("落在 PE 动态重定位位点上的差异（import optimization / retpoline）由加载器在启动期写入，属于正常现象。")));
    setHeaderTip(
        moduleTable_,
        kModuleColumnUnexplained,
        kernelText(
            "kernel.text_integrity.module.unexplained.tooltip",
            QStringLiteral("无法用任何已知机制解释的差异字节数；HVCI 正在强制执行时这里非零尤其严重。")));
    moduleTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    moduleTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    moduleTable_->setAlternatingRowColors(true);
    moduleTable_->verticalHeader()->setVisible(false);
    moduleTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    moduleTable_->horizontalHeader()->setStretchLastSection(true);

    rangeTable_ = new ks::ui::VisibleTableWidget(splitter);
    rangeTable_->setColumnCount(kRangeColumnCount);
    rangeTable_->setHorizontalHeaderLabels({
        kernelText("kernel.text_integrity.range.module", QStringLiteral("模块")),
        kernelText("kernel.text_integrity.range.section", QStringLiteral("节")),
        QStringLiteral("RVA"),
        kernelText("kernel.text_integrity.range.address", QStringLiteral("内核地址")),
        kernelText("kernel.text_integrity.range.length", QStringLiteral("长度")),
        kernelText("kernel.text_integrity.range.origin", QStringLiteral("归类")),
        kernelText("kernel.text_integrity.range.clean", QStringLiteral("净映像字节")),
        kernelText("kernel.text_integrity.range.observed", QStringLiteral("内存字节"))
    });
    rangeTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    rangeTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    rangeTable_->setAlternatingRowColors(true);
    rangeTable_->verticalHeader()->setVisible(false);
    rangeTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    rangeTable_->horizontalHeader()->setStretchLastSection(true);

    splitter->addWidget(moduleTable_);
    splitter->addWidget(rangeTable_);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    rootLayout->addWidget(splitter, 1);

    connect(scanButton_, &QPushButton::clicked, this, [this]() { startScan(); });
    connect(cancelButton_, &QPushButton::clicked, this, [this]() { cancelScan(); });
    connect(unexplainedOnlyCheck_, &QCheckBox::toggled, this, [this](bool) {
        rebuildRangeTable();
    });
}

void KernelTextIntegrityTab::startScan()
{
    if (scanRunning_)
    {
        return;
    }
    scanRunning_ = true;
    results_.clear();
    moduleTable_->setRowCount(0);
    rangeTable_->setRowCount(0);
    scanButton_->setEnabled(false);
    cancelButton_->setEnabled(true);
    moduleFilterEdit_->setEnabled(false);
    statusLabel_->setText(
        kernelText(
            "kernel.text_integrity.status.scanning",
            QStringLiteral("状态：正在比对...")));

    cancelFlag_ = std::make_shared<std::atomic_bool>(false);
    const QString kFilter = moduleFilterEdit_->text().trimmed();
    QPointer<KernelTextIntegrityTab> safeThis(this);
    auto cancelFlag = cancelFlag_;

    std::thread([safeThis, kFilter, cancelFlag]() {
        // The enforcement status of HVCI determines the severity level of 'unexplained
        // discrepancies', so the security posture is queried once in the scanning thread.
        ksword::ark::DriverClient client;
        const auto kSecurity = client.querySecurityStatus();
        const auto kHyperV = client.queryHyperVSummary();
        const bool kEvidenceUsable =
            kSecurity.io.ok && kSecurity.response.moduleQueryStatus >= 0;
        const bool kEnforcing =
            kEvidenceUsable
            && kSecurity.response.hvciKmciEnabled != 0U
            && kSecurity.response.hvciAuditMode == 0U
            && kHyperV.io.ok
            && kHyperV.response.hypervisorPresent
                == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT
            && (kSecurity.response.secureKernelModuleLoaded
                    == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT
                || kSecurity.response.skciModuleLoaded
                    == KSWORD_ARK_SECURITY_AUDIT_STATE_PRESENT);
        if (safeThis != nullptr)
        {
            QMetaObject::invokeMethod(
                safeThis,
                [safeThis, kEvidenceUsable, kEnforcing]() {
                    if (safeThis != nullptr)
                    {
                        safeThis->hvciEvidenceUsable_ = kEvidenceUsable;
                        safeThis->hvciEnforcing_ = kEnforcing;
                    }
                },
                Qt::QueuedConnection);
        }

        KernelTextScanOptions options;
        options.moduleFilter = kFilter;
        options.cancelFlag = cancelFlag.get();
        options.onModuleComplete =
            [safeThis](const KernelTextIntegrityResult& result) {
                if (safeThis == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    safeThis,
                    [safeThis, result]() {
                        if (safeThis != nullptr)
                        {
                            safeThis->appendModuleResult(result);
                        }
                    },
                    Qt::QueuedConnection);
            };
        KernelCleanImageBaseline::scanExecutableSections(options);

        const bool kCancelled = cancelFlag->load();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, kCancelled]() {
                if (safeThis != nullptr)
                {
                    safeThis->finishScan(kCancelled);
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelTextIntegrityTab::cancelScan()
{
    if (cancelFlag_ != nullptr)
    {
        cancelFlag_->store(true);
    }
    cancelButton_->setEnabled(false);
    statusLabel_->setText(
        kernelText(
            "kernel.text_integrity.status.cancelling",
            QStringLiteral("状态：正在取消...")));
}

void KernelTextIntegrityTab::appendModuleResult(
    const KernelTextIntegrityResult& result)
{
    results_.push_back(result);

    const int kRow = moduleTable_->rowCount();
    moduleTable_->insertRow(kRow);
    moduleTable_->setItem(kRow, kModuleColumnName, readOnlyItem(result.moduleName));
    moduleTable_->setItem(kRow, kModuleColumnBase, readOnlyItem(hex64(result.moduleBase)));
    moduleTable_->setItem(
        kRow,
        kModuleColumnSections,
        readOnlyItem(QString::number(result.executableSectionCount)));
    moduleTable_->setItem(
        kRow,
        kModuleColumnScanned,
        readOnlyItem(QString::number(result.scannedBytes)));
    moduleTable_->setItem(
        kRow,
        kModuleColumnUnreadable,
        readOnlyItem(QString::number(result.unreadableBytes)));
    moduleTable_->setItem(
        kRow,
        kModuleColumnDiffering,
        readOnlyItem(QString::number(result.differingBytes)));
    moduleTable_->setItem(
        kRow,
        kModuleColumnKnown,
        readOnlyItem(QString::number(result.knownRangeCount)));

    auto* unexplainedItem =
        readOnlyItem(QString::number(result.unexplainedRangeCount));
    unexplainedItem->setForeground(
        result.unexplainedRangeCount == 0U
            ? ksword_theme::successColor()
            : ksword_theme::errorColor());
    moduleTable_->setItem(kRow, kModuleColumnUnexplained, unexplainedItem);

    moduleTable_->setItem(
        kRow,
        kModuleColumnTrust,
        readOnlyItem(
            result.diskTrustVerified
                ? kernelText("kernel.text_integrity.trust.verified", QStringLiteral("已验证"))
                : kernelText("kernel.text_integrity.trust.unverified", QStringLiteral("未验证"))));
    moduleTable_->setItem(kRow, kModuleColumnStatus, readOnlyItem(result.statusText));

    // Continuously refresh the difference table and overall verdict during scanning to avoid long periods without feedback.
    rebuildRangeTable();
    updateVerdict();
    statusLabel_->setText(
        kernelText(
            "kernel.text_integrity.status.progress",
            QStringLiteral("状态：已比对 %1 个模块"))
            .arg(results_.size()));
}

void KernelTextIntegrityTab::finishScan(const bool cancelled)
{
    scanRunning_ = false;
    scanButton_->setEnabled(true);
    cancelButton_->setEnabled(false);
    moduleFilterEdit_->setEnabled(true);
    cancelFlag_.reset();
    statusLabel_->setText(
        cancelled
            ? kernelText(
                "kernel.text_integrity.status.cancelled",
                QStringLiteral("状态：已取消，共比对 %1 个模块"))
                .arg(results_.size())
            : kernelText(
                "kernel.text_integrity.status.done",
                QStringLiteral("状态：完成，共比对 %1 个模块"))
                .arg(results_.size()));
    rebuildRangeTable();
    updateVerdict();
}

void KernelTextIntegrityTab::rebuildRangeTable()
{
    const bool kUnexplainedOnly = unexplainedOnlyCheck_->isChecked();
    rangeTable_->setRowCount(0);
    for (const KernelTextIntegrityResult& result : results_)
    {
        for (const KernelTextDiffRange& range : result.ranges)
        {
            if (kUnexplainedOnly
                && range.origin != KernelTextDiffRange::Origin::kUnexplained)
            {
                continue;
            }
            const int kRow = rangeTable_->rowCount();
            rangeTable_->insertRow(kRow);
            rangeTable_->setItem(
                kRow, kRangeColumnModule, readOnlyItem(result.moduleName));
            rangeTable_->setItem(
                kRow, kRangeColumnSection, readOnlyItem(range.sectionName));
            rangeTable_->setItem(
                kRow, kRangeColumnRva, readOnlyItem(hex32(range.rva)));
            rangeTable_->setItem(
                kRow, kRangeColumnAddress, readOnlyItem(hex64(range.kernelAddress)));
            rangeTable_->setItem(
                kRow, kRangeColumnLength, readOnlyItem(QString::number(range.length)));

            auto* originItem = readOnlyItem(originText(range.origin));
            originItem->setForeground(
                range.origin == KernelTextDiffRange::Origin::kUnexplained
                    ? ksword_theme::errorColor()
                    : ksword_theme::warningColor());
            rangeTable_->setItem(kRow, kRangeColumnOrigin, originItem);

            rangeTable_->setItem(
                kRow, kRangeColumnClean, readOnlyItem(byteText(range.cleanBytes)));
            rangeTable_->setItem(
                kRow, kRangeColumnObserved, readOnlyItem(byteText(range.observedBytes)));
        }
    }
    rangeTable_->resizeColumnsToContents();
}

void KernelTextIntegrityTab::updateVerdict()
{
    std::uint32_t unexplained = 0U;
    std::uint32_t known = 0U;
    std::uint32_t unparsedModules = 0U;
    std::uint32_t untrustedModules = 0U;
    for (const KernelTextIntegrityResult& result : results_)
    {
        unexplained += result.unexplainedRangeCount;
        known += result.knownRangeCount;
        if (result.unparsedDynamicRelocations)
        {
            unparsedModules += 1U;
        }
        if (result.available && !result.diskTrustVerified)
        {
            untrustedModules += 1U;
        }
    }

    QString verdict;
    QString color;
    if (unexplained == 0U)
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.clean",
            QStringLiteral("未发现无法解释的代码改写（动态重定位位点差异 %1 处）"))
            .arg(known);
        color = ksword_theme::successHex();
    }
    else if (hvciEvidenceUsable_ && hvciEnforcing_)
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.hvci_violation",
            QStringLiteral("高危：HVCI 正在强制执行，内核代码页本不应可写，却发现 %1 处无法解释的改写"))
            .arg(unexplained);
        color = ksword_theme::errorHex();
    }
    else
    {
        verdict = kernelText(
            "kernel.text_integrity.verdict.unexplained",
            QStringLiteral("发现 %1 处无法解释的代码改写；当前未确认 HVCI 处于强制执行状态"))
            .arg(unexplained);
        color = ksword_theme::errorHex();
    }

    QStringList notes;
    if (unparsedModules != 0U)
    {
        notes.push_back(
            kernelText(
                "kernel.text_integrity.note.unparsed",
                QStringLiteral("%1 个模块含本工具未解析的动态重定位符号，其「无法解释」计数偏保守"))
                .arg(unparsedModules));
    }
    if (untrustedModules != 0U)
    {
        notes.push_back(
            kernelText(
                "kernel.text_integrity.note.untrusted",
                QStringLiteral("%1 个模块的磁盘映像未通过信任校验，比对基准本身可疑"))
                .arg(untrustedModules));
    }
    if (!notes.isEmpty())
    {
        verdict += QStringLiteral("；") + notes.join(QStringLiteral("；"));
    }

    verdictLabel_->setText(verdict);
    verdictLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:8px;border-radius:4px;font-weight:700;color:%1;}")
            .arg(color));
}

QString KernelTextIntegrityTab::originText(const KernelTextDiffRange::Origin origin)
{
    return origin == KernelTextDiffRange::Origin::kKnownDynamicRelocation
        ? kernelText(
            "kernel.text_integrity.origin.dynamic",
            QStringLiteral("动态重定位位点"))
        : kernelText(
            "kernel.text_integrity.origin.unexplained",
            QStringLiteral("无法解释"));
}

QString KernelTextIntegrityTab::byteText(const std::vector<std::uint8_t>& bytes)
{
    QStringList parts;
    parts.reserve(static_cast<qsizetype>(bytes.size()));
    for (const std::uint8_t kValue : bytes)
    {
        parts.push_back(
            QStringLiteral("%1").arg(kValue, 2, 16, QLatin1Char('0')).toUpper());
    }
    return parts.join(QLatin1Char(' '));
}

QString KernelTextIntegrityTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1")
        .arg(value, 16, 16, QLatin1Char('0'));
}

QString KernelTextIntegrityTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1")
        .arg(value, 8, 16, QLatin1Char('0'));
}

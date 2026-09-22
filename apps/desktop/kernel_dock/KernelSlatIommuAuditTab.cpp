#include "KernelSlatIommuAuditTab.h"

#include "KernelDock.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../ui/VisibleTableWidget.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum ProbeColumn : int
    {
        kProbeColumnName = 0,
        kProbeColumnVirtualAddress,
        kProbeColumnPhysicalAddress,
        kProbeColumnBytes,
        kProbeColumnVirtualHash,
        kProbeColumnPhysicalHash,
        kProbeColumnVerdict,
        kProbeColumnStatus,
        kProbeColumnCount
    };

    enum IommuColumn : int
    {
        kIommuColumnType = 0,
        kIommuColumnSegmentDevice,
        kIommuColumnBase,
        kIommuColumnLimit,
        kIommuColumnFlags,
        kIommuColumnCapabilities,
        kIommuColumnRuntime,
        kIommuColumnStatus,
        kIommuColumnCount
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

KernelSlatIommuAuditTab::KernelSlatIommuAuditTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelSlatIommuAuditTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!firstRefreshStarted_)
    {
        firstRefreshStarted_ = true;
        QMetaObject::invokeMethod(
            this,
            [this]() { refreshAsync(); },
            Qt::QueuedConnection);
    }
}

void KernelSlatIommuAuditTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    refreshButton_ = new QPushButton(
        kernelText("kernel.slat_iommu.refresh", QStringLiteral("刷新取证")),
        this);
    refreshButton_->setStyleSheet(ksword_theme::themedButtonStyle());
    // The forensic boundary follows the triggering button; no longer place a persistent explanation at the top of the page.
    refreshButton_->setToolTip(
        kernelText(
            "kernel.slat_iommu.refresh.tooltip",
            QStringLiteral("只读取证：比较来宾可见的内核虚拟视图与物理别名，并解析 CPUID、DMAR/IVRS 和公开 IOMMU 接口。")));
    includeMmioCheck_ = new QCheckBox(
        kernelText(
            "kernel.slat_iommu.include_mmio",
            QStringLiteral("读取 IOMMU MMIO 状态（只读，可能被固件/平台拒绝）")),
        this);
    includeMmioCheck_->setToolTip(
        kernelText(
            "kernel.slat_iommu.include_mmio.tooltip",
            QStringLiteral("只读寄存器、不写入，但错误的固件地址仍可能被平台拒绝或触发硬件异常。")));
    statusLabel_ = new QLabel(
        kernelText(
            "kernel.slat_iommu.status.waiting",
            QStringLiteral("状态：等待刷新")),
        this);
    statusLabel_->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(ksword_theme::textSecondaryHex()));
    toolbar->addWidget(refreshButton_);
    toolbar->addWidget(includeMmioCheck_);
    toolbar->addStretch(1);
    toolbar->addWidget(statusLabel_);
    rootLayout->addLayout(toolbar);

    summaryLabel_ = new QLabel(this);
    summaryLabel_->setWordWrap(true);
    summaryLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    summaryLabel_->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}")
            .arg(ksword_theme::textPrimaryHex()));
    rootLayout->addWidget(summaryLabel_);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    auto* evidenceTabs = new QTabWidget(splitter);

    probeTable_ = new ks::ui::VisibleTableWidget(evidenceTabs);
    probeTable_->setColumnCount(kProbeColumnCount);
    probeTable_->setHorizontalHeaderLabels({
        kernelText("kernel.slat_iommu.probe.name", QStringLiteral("探针")),
        kernelText("kernel.slat_iommu.probe.virtual", QStringLiteral("虚拟地址")),
        kernelText("kernel.slat_iommu.probe.physical", QStringLiteral("物理地址")),
        kernelText("kernel.slat_iommu.probe.bytes", QStringLiteral("字节")),
        kernelText("kernel.slat_iommu.probe.virtual_hash", QStringLiteral("虚拟哈希")),
        kernelText("kernel.slat_iommu.probe.physical_hash", QStringLiteral("物理哈希")),
        kernelText("kernel.slat_iommu.probe.verdict", QStringLiteral("交叉视图")),
        QStringLiteral("NTSTATUS")
    });
    // Attach the verdict criteria to the specific column header it explains, rather than placing a general summary at the top of the page, to ensure easier alignment.
    setHeaderTip(
        probeTable_,
        kProbeColumnVerdict,
        kernelText(
            "kernel.slat_iommu.probe.verdict.tooltip",
            QStringLiteral("外层 Hypervisor 可用 EPT/NPT 对执行和读取提供不同视图，因此“未发现异常”不等于已证明不存在 Hook。")));
    probeTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    probeTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    probeTable_->setAlternatingRowColors(true);
    probeTable_->verticalHeader()->setVisible(false);
    probeTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    probeTable_->horizontalHeader()->setStretchLastSection(true);
    evidenceTabs->addTab(
        probeTable_,
        kernelText(
            "kernel.slat_iommu.probe.tab",
            QStringLiteral("EPT/NPT 交叉视图")));

    iommuTable_ = new ks::ui::VisibleTableWidget(evidenceTabs);
    iommuTable_->setColumnCount(kIommuColumnCount);
    iommuTable_->setHorizontalHeaderLabels({
        kernelText("kernel.slat_iommu.iommu.type", QStringLiteral("类型")),
        kernelText("kernel.slat_iommu.iommu.segment_device", QStringLiteral("段 / 设备")),
        kernelText("kernel.slat_iommu.iommu.base", QStringLiteral("基址")),
        kernelText("kernel.slat_iommu.iommu.limit", QStringLiteral("上界")),
        kernelText("kernel.slat_iommu.iommu.flags", QStringLiteral("证据标志")),
        kernelText("kernel.slat_iommu.iommu.capability", QStringLiteral("能力 / 扩展能力")),
        kernelText("kernel.slat_iommu.iommu.runtime", QStringLiteral("状态 / 根表")),
        QStringLiteral("NTSTATUS")
    });
    iommuTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    iommuTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    iommuTable_->setAlternatingRowColors(true);
    iommuTable_->verticalHeader()->setVisible(false);
    iommuTable_->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    iommuTable_->horizontalHeader()->setStretchLastSection(true);
    evidenceTabs->addTab(
        iommuTable_,
        kernelText(
            "kernel.slat_iommu.iommu.tab",
            QStringLiteral("IOMMU / DMAR / IVRS")));

    detailEdit_ = new QTextEdit(splitter);
    detailEdit_->setReadOnly(true);
    detailEdit_->setPlaceholderText(
        kernelText(
            "kernel.slat_iommu.detail.placeholder",
            QStringLiteral("刷新后显示 CPU、Hypervisor、SLAT 与 IOMMU 原始证据")));
    splitter->addWidget(evidenceTabs);
    splitter->addWidget(detailEdit_);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    connect(refreshButton_, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
}

void KernelSlatIommuAuditTab::refreshAsync()
{
    if (queryRunning_)
    {
        return;
    }
    queryRunning_ = true;
    refreshButton_->setEnabled(false);
    includeMmioCheck_->setEnabled(false);
    statusLabel_->setText(
        kernelText(
            "kernel.slat_iommu.status.refreshing",
            QStringLiteral("状态：正在采集只读证据...")));
    const bool kIncludeMmio = includeMmioCheck_->isChecked();
    QPointer<KernelSlatIommuAuditTab> safeThis(this);
    std::thread([safeThis, kIncludeMmio]() {
        ksword::ark::DriverClient client;
        auto result = client.querySlatIommuAudit(kIncludeMmio);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result = std::move(result)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyResult(std::move(result));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelSlatIommuAuditTab::applyResult(
    ksword::ark::SlatIommuAuditResult result)
{
    queryRunning_ = false;
    refreshButton_->setEnabled(true);
    includeMmioCheck_->setEnabled(true);
    if (!result.io.ok)
    {
        probeTable_->setRowCount(0);
        iommuTable_->setRowCount(0);
        detailEdit_->clear();
        if (result.unsupported)
        {
            statusLabel_->setText(
                kernelText(
                    "kernel.slat_iommu.status.unsupported",
                    QStringLiteral("状态：当前驱动不支持此取证协议")));
        }
        else
        {
            statusLabel_->setText(
                kernelText(
                    "kernel.slat_iommu.status.failed",
                    QStringLiteral("状态：读取失败（%1）"))
                    .arg(QString::fromStdString(result.io.message)));
        }
        summaryLabel_->setText(statusLabel_->text());
        return;
    }

    const auto& response = result.response;
    populateProbeTable(response);
    populateIommuTable(response);
    detailEdit_->setPlainText(buildDetail(response));
    summaryLabel_->setText(
        kernelText(
            "kernel.slat_iommu.summary",
            QStringLiteral("CPU：%1；Hypervisor：%2；特性：%3；来宾可见风险：%4；别名探针 %5 个（不一致 %6，不稳定 %7）；IOMMU 记录 %8 个（保留内存 %9，畸形 %10）。"))
            .arg(fixedAscii(response.cpuVendor, sizeof(response.cpuVendor)))
            .arg(fixedAscii(
                response.hypervisorVendor,
                sizeof(response.hypervisorVendor)).isEmpty()
                    ? QStringLiteral("-")
                    : fixedAscii(
                        response.hypervisorVendor,
                        sizeof(response.hypervisorVendor)))
            .arg(featureText(response.featureFlags))
            .arg(riskText(response.riskFlags))
            .arg(response.probeCount)
            .arg(response.mismatchCount)
            .arg(response.unstableCount)
            .arg(response.iommuRowCount)
            .arg(response.reservedMemoryCount)
            .arg(response.malformedRowCount));
    statusLabel_->setText(
        response.queryStatus < 0
            ? kernelText(
                "kernel.slat_iommu.status.partial",
                QStringLiteral("状态：部分证据不可用（%1）"))
                .arg(ntStatusText(response.queryStatus))
            : kernelText(
                "kernel.slat_iommu.status.ready",
                QStringLiteral("状态：只读取证已刷新")));
}

void KernelSlatIommuAuditTab::populateProbeTable(
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response)
{
    const auto kCount = std::min<unsigned long>(
        response.probeCount,
        KSWORD_ARK_SLAT_IOMMU_MAX_PROBES);
    probeTable_->setRowCount(static_cast<int>(kCount));
    for (unsigned long index = 0; index < kCount; ++index)
    {
        const auto& row = response.probes[index];
        const int kTableRow = static_cast<int>(index);
        probeTable_->setItem(
            kTableRow,
            kProbeColumnName,
            readOnlyItem(fixedAscii(row.name, sizeof(row.name))));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnVirtualAddress,
            readOnlyItem(hex64(row.virtualAddress)));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnPhysicalAddress,
            readOnlyItem(hex64(row.physicalAddress)));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnBytes,
            readOnlyItem(QString::number(row.bytesCompared)));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnVirtualHash,
            readOnlyItem(hex64(row.virtualHash)));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnPhysicalHash,
            readOnlyItem(hex64(row.physicalHash)));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnVerdict,
            readOnlyItem(probeVerdictText(row)));
        probeTable_->setItem(
            kTableRow,
            kProbeColumnStatus,
            readOnlyItem(ntStatusText(row.status)));
    }
}

void KernelSlatIommuAuditTab::populateIommuTable(
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response)
{
    const auto kCount = std::min<unsigned long>(
        response.iommuRowCount,
        KSWORD_ARK_SLAT_IOMMU_MAX_ROWS);
    iommuTable_->setRowCount(static_cast<int>(kCount));
    for (unsigned long index = 0; index < kCount; ++index)
    {
        const auto& row = response.iommuRows[index];
        const int kTableRow = static_cast<int>(index);
        QString segmentDevice = QStringLiteral("%1 / 0x%2")
            .arg(row.segment)
            .arg(row.deviceId, 4, 16, QLatin1Char('0'))
            .toUpper();
        if (row.endDeviceId != 0)
        {
            segmentDevice = QStringLiteral("%1 / 0x%2-0x%3")
                .arg(row.segment)
                .arg(row.deviceId, 4, 16, QLatin1Char('0'))
                .arg(row.endDeviceId, 4, 16, QLatin1Char('0'))
                .toUpper();
        }
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnType,
            readOnlyItem(iommuTypeText(row.type)));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnSegmentDevice,
            readOnlyItem(segmentDevice));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnBase,
            readOnlyItem(hex64(row.baseAddress)));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnLimit,
            readOnlyItem(hex64(row.limitAddress)));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnFlags,
            readOnlyItem(QStringLiteral("%1 | FW=0x%2 | scopes=%3")
                .arg(iommuFlagsText(row.flags))
                .arg(row.firmwareFlags, 8, 16, QLatin1Char('0'))
                .arg(row.scopeCount)
                .toUpper()));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnCapabilities,
            readOnlyItem(QStringLiteral("%1 / %2")
                .arg(hex64(row.capability), hex64(row.extendedCapability))));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnRuntime,
            readOnlyItem(QStringLiteral("%1 / %2")
                .arg(hex64(row.statusRegister), hex64(row.rootTableAddress))));
        iommuTable_->setItem(
            kTableRow,
            kIommuColumnStatus,
            readOnlyItem(ntStatusText(row.status)));
    }
}

QString KernelSlatIommuAuditTab::buildDetail(
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response) const
{
    return kernelText(
        "kernel.slat_iommu.detail.template",
        QStringLiteral("CPU 厂商：%1\nHypervisor 厂商：%2\n特性：%3\n来宾可见风险：%4\n原始字段/风险/特性：0x%5 / 0x%6 / 0x%7\nCPUID 最大叶：basic=0x%8 extended=0x%9 hypervisor=0x%10\nCPUID 周期 min/median/max：%11 / %12 / %13\nIA32_FEATURE_CONTROL：%14\nIA32_VMX_EPT_VPID_CAP：%15\nAMD VM_CR：%16\nAMD EFER：%17\nDMAR/IVRS：%18 / %19\nIOMMU Interface/Ex：%20(v%21) / %22(v%23)\n查询标志：0x%24\n证据边界：虚拟/物理视图一致只能排除当前来宾可观察到的分离；不能读取外层 EPT/NPT 表，也不能证明不存在 execute-only 或按访问类型切换的 Hook。"))
        .arg(fixedAscii(response.cpuVendor, sizeof(response.cpuVendor)))
        .arg(fixedAscii(response.hypervisorVendor, sizeof(response.hypervisorVendor)))
        .arg(featureText(response.featureFlags))
        .arg(riskText(response.riskFlags))
        .arg(response.fieldFlags, 8, 16, QLatin1Char('0'))
        .arg(response.riskFlags, 8, 16, QLatin1Char('0'))
        .arg(response.featureFlags, 16, 16, QLatin1Char('0'))
        .arg(response.cpuidMaxBasic, 0, 16)
        .arg(response.cpuidMaxExtended, 0, 16)
        .arg(response.cpuidMaxHypervisor, 0, 16)
        .arg(response.cpuidCyclesMinimum)
        .arg(response.cpuidCyclesMedian)
        .arg(response.cpuidCyclesMaximum)
        .arg(hex64(response.vmxFeatureControl))
        .arg(hex64(response.vmxEptVpidCapabilities))
        .arg(hex64(response.amdVmCr))
        .arg(hex64(response.amdEfer))
        .arg(ntStatusText(response.dmarStatus))
        .arg(ntStatusText(response.ivrsStatus))
        .arg(ntStatusText(response.iommuInterfaceStatus))
        .arg(response.iommuInterfaceVersion)
        .arg(ntStatusText(response.iommuInterfaceExStatus))
        .arg(response.iommuInterfaceExVersion)
        .arg(response.queryFlags, 8, 16, QLatin1Char('0'));
}

QString KernelSlatIommuAuditTab::featureText(const std::uint64_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_INTEL) != 0) values << QStringLiteral("Intel");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_AMD) != 0) values << QStringLiteral("AMD");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_VMX) != 0) values << QStringLiteral("VMX");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_EPT) != 0) values << QStringLiteral("EPT");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM) != 0) values << QStringLiteral("SVM");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_NPT) != 0) values << QStringLiteral("NPT");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_HYPERVISOR) != 0) values << QStringLiteral("Hypervisor");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_DMAR) != 0) values << QStringLiteral("DMAR");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IVRS) != 0) values << QStringLiteral("IVRS");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE) != 0) values << QStringLiteral("IOMMU Interface");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE_EX) != 0) values << QStringLiteral("IOMMU InterfaceEx");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_TRANSLATION) != 0) values << QStringLiteral("VT-d Translation");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_INTERRUPT_REMAP) != 0) values << QStringLiteral("Interrupt Remap");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN) != 0) values << QStringLiteral("DMA Guard Opt-In");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_PHYSICAL_ALIAS) != 0) values << QStringLiteral("Physical Alias");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EXPORT) != 0) values << QStringLiteral("IOMMU Export");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EX_EXPORT) != 0) values << QStringLiteral("IOMMU Ex Export");
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(", "));
}

QString KernelSlatIommuAuditTab::riskText(const std::uint32_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_HYPERVISOR_OPAQUE) != 0)
        values << kernelText("kernel.slat_iommu.risk.hypervisor_opaque", QStringLiteral("外层 SLAT 不可见"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT) != 0)
        values << kernelText("kernel.slat_iommu.risk.cpuid", QStringLiteral("CPUID 不一致"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_MISMATCH) != 0)
        values << kernelText("kernel.slat_iommu.risk.alias_mismatch", QStringLiteral("虚拟/物理别名不一致"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE) != 0)
        values << kernelText("kernel.slat_iommu.risk.alias_unstable", QStringLiteral("别名读取不稳定"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM) != 0)
        values << kernelText("kernel.slat_iommu.risk.acpi_checksum", QStringLiteral("ACPI 校验和异常"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED) != 0)
        values << kernelText("kernel.slat_iommu.risk.acpi_malformed", QStringLiteral("ACPI 结构畸形"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE) != 0)
        values << kernelText("kernel.slat_iommu.risk.mmio", QStringLiteral("MMIO 不可读"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED) != 0)
        values << kernelText("kernel.slat_iommu.risk.translation", QStringLiteral("IOMMU 转换未启用"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE) != 0)
        values << kernelText("kernel.slat_iommu.risk.root", QStringLiteral("根表不可用"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT) != 0)
        values << kernelText("kernel.slat_iommu.risk.reserved", QStringLiteral("存在保留内存窗口"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_TIMING_VARIANCE) != 0)
        values << kernelText("kernel.slat_iommu.risk.timing", QStringLiteral("CPUID 时延离散"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_TRUNCATED) != 0)
        values << kernelText("kernel.slat_iommu.risk.truncated", QStringLiteral("结果被截断"));
    return values.isEmpty()
        ? kernelText("kernel.slat_iommu.risk.none", QStringLiteral("未发现来宾可见异常"))
        : values.join(QStringLiteral("; "));
}

QString KernelSlatIommuAuditTab::iommuTypeText(const std::uint32_t type)
{
    switch (type)
    {
    case KSWORD_ARK_IOMMU_ROW_INTEL_DRHD: return QStringLiteral("Intel DRHD");
    case KSWORD_ARK_IOMMU_ROW_INTEL_RMRR: return QStringLiteral("Intel RMRR");
    case KSWORD_ARK_IOMMU_ROW_INTEL_ATSR: return QStringLiteral("Intel ATSR");
    case KSWORD_ARK_IOMMU_ROW_INTEL_RHSA: return QStringLiteral("Intel RHSA");
    case KSWORD_ARK_IOMMU_ROW_AMD_IVHD: return QStringLiteral("AMD IVHD");
    case KSWORD_ARK_IOMMU_ROW_AMD_IVMD: return QStringLiteral("AMD IVMD");
    case KSWORD_ARK_IOMMU_ROW_INTEL_ANDD: return QStringLiteral("Intel ANDD");
    case KSWORD_ARK_IOMMU_ROW_INTEL_SATC: return QStringLiteral("Intel SATC");
    default: return kernelText("kernel.slat_iommu.iommu.unknown", QStringLiteral("未知"));
    }
}

QString KernelSlatIommuAuditTab::iommuFlagsText(const std::uint32_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_INCLUDE_ALL) != 0) values << QStringLiteral("IncludeAll");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY) != 0) values << QStringLiteral("ReservedMemory");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ) != 0) values << QStringLiteral("MMIO");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION) != 0) values << QStringLiteral("Translation");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_INTERRUPT_REMAP) != 0) values << QStringLiteral("InterruptRemap");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID) != 0) values << QStringLiteral("RootValid");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED) != 0) values << QStringLiteral("Malformed");
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(", "));
}

QString KernelSlatIommuAuditTab::probeVerdictText(
    const KSWORD_ARK_SLAT_PROBE_ROW& row)
{
    if (row.status < 0)
        return kernelText("kernel.slat_iommu.probe.failed", QStringLiteral("读取失败"));
    if ((row.flags & (KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_UNSTABLE |
                     KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_UNSTABLE)) != 0)
        return kernelText("kernel.slat_iommu.probe.unstable", QStringLiteral("读取不稳定"));
    if ((row.flags & KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MISMATCH) != 0)
        return kernelText("kernel.slat_iommu.probe.mismatch", QStringLiteral("视图不一致"));
    if ((row.flags & KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MATCH) != 0)
        return kernelText("kernel.slat_iommu.probe.match", QStringLiteral("来宾可见视图一致"));
    return kernelText("kernel.slat_iommu.probe.insufficient", QStringLiteral("证据不足"));
}

QString KernelSlatIommuAuditTab::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<quint32>(status), 8, 16, QLatin1Char('0'))
        .toUpper();
}

QString KernelSlatIommuAuditTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(value), 16, 16, QLatin1Char('0'))
        .toUpper();
}

QString KernelSlatIommuAuditTab::fixedAscii(
    const char* text,
    const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return {};
    }
    int length = 0;
    while (length < capacity && text[length] != '\0')
    {
        ++length;
    }
    return QString::fromLatin1(text, length);
}

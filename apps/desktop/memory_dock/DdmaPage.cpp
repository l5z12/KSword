#include "DdmaPage.h"

#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"
#include "../ui/HexEditorWidget.h"
#include "../ui/VisibleTableWidget.h"

#include <QCheckBox>
#include <QEvent>
#include <QFile>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

// ============================================================
// DdmaPage.cpp
// Purpose:
// - Implements DDMA channel configuration, self read/write, and same-address verification between 'standard channel vs DDMA'.
// ============================================================

namespace
{
    // kDiskTableColumns: Disk table column definitions.
    enum class DiskColumn : int
    {
        kIndex = 0,
        kDeviceName,
        kState,
        kProbeStatus,
        kSectorSize,
        kCount
    };

    // kCompareSampleRows: Maximum number of rows to display for the difference review to prevent the table from
    // overflowing with all 4096 page differences. Excess differences are summarized as a total count in the conclusion.
    constexpr int kCompareSampleRows = 256;

    // formatNtStatus: Render NTSTATUS as an 8-digit uppercase hexadecimal string.
    QString formatNtStatus(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(status)), 8, 16, QChar('0'))
            .toUpper()
            .replace(QStringLiteral("0X"), QStringLiteral("0x"));
    }
}

DdmaPage::DdmaPage(QWidget* const parent)
    : QWidget(parent)
{
    initializeUi();
    refreshSessionState();
}

void DdmaPage::setSessionChangedCallback(std::function<void()> callback)
{
    sessionChangedCallback_ = std::move(callback);
}

void DdmaPage::changeEvent(QEvent* const event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }
    // Semantic colors are a snapshot taken at the time of the call; reapply them after a light/dark theme switch so colors do not remain on the old theme.
    if (event->type() == QEvent::ApplicationPaletteChange
        || event->type() == QEvent::PaletteChange)
    {
        applySemanticStyles();
    }
}

void DdmaPage::initializeUi()
{
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    rootLayout->addWidget(buildIntroGroup());
    rootLayout->addWidget(buildChannelGroup());
    rootLayout->addWidget(buildAccessGroup(), 1);
    rootLayout->addWidget(buildCompareGroup());

    applySemanticStyles();
}

QGroupBox* DdmaPage::buildIntroGroup()
{
    QGroupBox* group = new QGroupBox("DDMA 是什么", this);
    QVBoxLayout* layout = new QVBoxLayout(group);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(4);

    QLabel* introLabel = new QLabel(group);
    introLabel->setWordWrap(true);
    introLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    introLabel->setText(
        "DDMA 让磁盘控制器用总线主控 DMA 直接读写物理地址。数据通路走 HBA 而不经过 CPU 页表，"
        "因此不受 SLAT / EPT 约束，能读到被上层虚拟化重定向或隐藏的物理页——"
        "标准通道在这些页上只会读到全 FF 或被替换过的内容。\n"
        "代价有三条，都无法绕开：\n"
        "一、必须借用一块磁盘扇区当中转站。本工具不提供默认扇区，必须由你显式指定 LBA 并确认；"
        "每次读写都在同一次请求内完成“备份→使用→还原”，但还原失败时磁盘上会留下脏扇区。\n"
        "二、开启内核调试的机器上会命中 MiShowBadMapper 直接蓝屏，此时整条通道被禁用。\n"
        "三、需要磁盘驱动栈接受直通命令。优先试 ATA 直通，不通再试 SCSI 直通"
        "（Windows 的 stornvme 会把它翻译成 NVMe 命令，所以 NVMe、SAS/SATA 与合成 SCSI 都走这条）；"
        "两条都被拒绝的盘用不了。另外部分 HBA 不支持 64 位寻址，高物理内存可能访问不到。");
    layout->addWidget(introLabel);

    return group;
}

QGroupBox* DdmaPage::buildChannelGroup()
{
    QGroupBox* group = new QGroupBox("通道配置", this);
    QVBoxLayout* outerLayout = new QVBoxLayout(group);
    outerLayout->setContentsMargins(8, 8, 8, 8);
    outerLayout->setSpacing(6);

    QGridLayout* formLayout = new QGridLayout();
    formLayout->setHorizontalSpacing(8);
    formLayout->setVerticalSpacing(6);

    scratchLbaEdit_ = new QLineEdit(group);
    scratchLbaEdit_->setPlaceholderText("必填，例如 0x100000 或 1048576");
    scratchLbaEdit_->setClearButtonEnabled(true);
    scratchLbaEdit_->setToolTip(
        "暂存扇区起始 LBA。DDMA 必须借磁盘扇区中转，本工具不提供默认值，"
        "留空则整条通道不可用。注意 LBA 0 起的前几个扇区是 MBR / GPT 保护扇区。");

    scratchImpactLabel_ = new QLabel(group);
    scratchImpactLabel_->setWordWrap(true);
    scratchImpactLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    scratchAckCheck_ = new QCheckBox("我确认上述扇区上的数据可以被临时覆盖", group);
    scratchAckCheck_->setToolTip(
        "每次 DDMA 读写都会先备份这几个扇区、用完立刻还原。"
        "但操作期间发生蓝屏或断电时，这几个扇区的原始数据会丢失。");

    probeButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/disk_analyze.svg")), "探测可用磁盘", group);
    probeButton_->setToolTip(
        "枚举 \\Driver\\Disk 上的磁盘设备。已填写暂存 LBA 时，"
        "会对每块盘真的发一次 ATA DMA 读命令来判定通道是否可用（只读，不写盘）。");

    detectScratchButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/file_find.svg")), "侦测候选扇区", group);
    detectScratchButton_->setEnabled(false);
    // Keep the string on a single line: line breaks cause i18n audits to treat it as multiple independent source strings, requiring a translation entry for each segment.
    detectScratchButton_->setToolTip("读取选中磁盘的分区表，找出未分配间隙并把建议的 LBA 填进左侧输入框。只读不写。磁盘头部的间隙正是引导器寄居处，永远不会被选为建议值。填好之后仍然需要你自己勾选确认。");

    scratchDetectLabel_ = new QLabel(group);
    scratchDetectLabel_->setWordWrap(true);
    scratchDetectLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    // Sector context: Once the candidate is finalized, unfold 'what this sector currently is' for one final confirmation.
    // Write using setRawText; bytes on disk are not subject to localization in language packs.
    scratchContextView_ = new CodeEditorWidget(group);
    scratchContextView_->setReadOnly(true);
    // Disable the built-in 'structured view' toggle: This content is a fixed-width aligned hexadecimal dump. After being parsed into
    // an attribute/value table, the byte columns within each row get scattered, making it impossible to discern what is in the sector.
    scratchContextView_->setStructuredReportViewEnabled(false);
    scratchContextView_->setMinimumHeight(150);
    scratchContextView_->setRawText(
        QStringLiteral("尚未侦测。选中一块磁盘后点击“侦测候选扇区”。"));

    activateButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/disk_save.svg")), "启用选中磁盘为 DDMA 通道", group);
    activateButton_->setEnabled(false);
    activateButton_->setToolTip(
        "把选中磁盘写入 DDMA 会话。启用后，内存搜索、内存查看器、"
        "驱动内存读写与系统内存审计四个页面都能选择 DDMA 后端。");

    clearButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")), "清除通道配置", group);
    clearButton_->setToolTip("清空 DDMA 会话，所有页面立刻退回标准驱动通道。本页创建过专属暂存文件时会问你是否一并删除。");

    formLayout->addWidget(new QLabel("暂存扇区 LBA", group), 0, 0);
    formLayout->addWidget(scratchLbaEdit_, 0, 1);
    formLayout->addWidget(detectScratchButton_, 0, 2);
    formLayout->addWidget(probeButton_, 0, 3);
    formLayout->addWidget(scratchDetectLabel_, 1, 0, 1, 4);
    formLayout->addWidget(scratchContextView_, 2, 0, 1, 4);
    formLayout->addWidget(scratchImpactLabel_, 3, 0, 1, 4);
    formLayout->addWidget(scratchAckCheck_, 4, 0, 1, 4);
    formLayout->setColumnStretch(1, 1);
    outerLayout->addLayout(formLayout);

    diskTable_ = new ks::ui::VisibleTableWidget(group);
    diskTable_->setColumnCount(static_cast<int>(DiskColumn::kCount));
    diskTable_->setHorizontalHeaderLabels(
        QStringList{ "序号", "设备名", "通道状态", "探测 NTSTATUS", "扇区大小" });
    diskTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    diskTable_->setSelectionMode(QAbstractItemView::SingleSelection);
    diskTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    diskTable_->setAlternatingRowColors(true);
    diskTable_->verticalHeader()->setVisible(false);
    diskTable_->verticalHeader()->setDefaultSectionSize(22);
    diskTable_->setMinimumHeight(120);
    outerLayout->addWidget(diskTable_);

    QHBoxLayout* actionLayout = new QHBoxLayout();
    actionLayout->setContentsMargins(0, 0, 0, 0);
    actionLayout->setSpacing(6);
    actionLayout->addWidget(activateButton_);
    actionLayout->addWidget(clearButton_);
    actionLayout->addStretch(1);
    outerLayout->addLayout(actionLayout);

    capabilityLabel_ = new QLabel("尚未探测。", group);
    capabilityLabel_->setWordWrap(true);
    capabilityLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outerLayout->addWidget(capabilityLabel_);

    sessionStateLabel_ = new QLabel(group);
    sessionStateLabel_->setWordWrap(true);
    sessionStateLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outerLayout->addWidget(sessionStateLabel_);

    connect(probeButton_, &QPushButton::clicked, this, [this]() { probeChannels(); });
    connect(activateButton_, &QPushButton::clicked, this, [this]() { activateSelectedDisk(); });
    connect(clearButton_, &QPushButton::clicked, this, [this]() { clearSession(); });
    connect(scratchLbaEdit_, &QLineEdit::textChanged, this, [this](const QString&) {
        // LBA changed requires re-confirmation: the user likely switched the target to a different sector range.
        if (scratchAckCheck_ != nullptr && scratchAckCheck_->isChecked())
        {
            scratchAckCheck_->setChecked(false);
        }
        refreshSessionState();
        });
    connect(scratchAckCheck_, &QCheckBox::toggled, this, [this](bool) { refreshSessionState(); });
    connect(detectScratchButton_, &QPushButton::clicked, this, [this]() { detectScratchFromUi(); });
    connect(diskTable_, &QTableWidget::itemSelectionChanged, this, [this]() {
        const bool kHasRow = (diskTable_->currentRow() >= 0);
        if (activateButton_ != nullptr)
        {
            activateButton_->setEnabled(kHasRow);
        }
        // Detection reads the partition table of a specific disk, so it requires a selected row as a prerequisite.
        if (detectScratchButton_ != nullptr)
        {
            detectScratchButton_->setEnabled(kHasRow);
        }
        });

    return group;
}

QGroupBox* DdmaPage::buildAccessGroup()
{
    QGroupBox* group = new QGroupBox("DDMA 物理读写", this);
    QVBoxLayout* outerLayout = new QVBoxLayout(group);
    outerLayout->setContentsMargins(8, 8, 8, 8);
    outerLayout->setSpacing(6);

    QHBoxLayout* barLayout = new QHBoxLayout();
    barLayout->setContentsMargins(0, 0, 0, 0);
    barLayout->setSpacing(6);

    accessAddressEdit_ = new QLineEdit(group);
    accessAddressEdit_->setPlaceholderText("物理地址，例如 0x1000");
    accessAddressEdit_->setClearButtonEnabled(true);

    accessLengthSpin_ = new QSpinBox(group);
    accessLengthSpin_->setRange(1, 64 * 1024);
    accessLengthSpin_->setValue(4096);
    accessLengthSpin_->setSuffix(" B");
    accessLengthSpin_->setToolTip(
        "读取长度。DDMA 的一次 DMA 传输就是一页，超过一页会按页边界自动切片，"
        "每一页都是一次完整的“备份→传输→还原”，所以长度越大越慢。");

    accessReadButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/process_details.svg")), "DDMA 读取", group);
    accessWriteButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/disk_save.svg")), "DDMA 写回差异", group);
    accessWriteButton_->setEnabled(false);
    accessWriteButton_->setToolTip(
        "把下方编辑器中改动过的字节用 DDMA 写回物理内存。"
        "非整页写入时驱动会做读-改-写，同页其它字节存在覆盖窗口。");

    barLayout->addWidget(new QLabel("物理地址", group));
    barLayout->addWidget(accessAddressEdit_, 1);
    barLayout->addWidget(new QLabel("长度", group));
    barLayout->addWidget(accessLengthSpin_);
    barLayout->addWidget(accessReadButton_);
    barLayout->addWidget(accessWriteButton_);
    outerLayout->addLayout(barLayout);

    accessHexEditor_ = new HexEditorWidget(group);
    accessHexEditor_->setBytesPerRow(16);
    accessHexEditor_->setEditable(true);
    outerLayout->addWidget(accessHexEditor_, 1);

    accessStatusLabel_ = new QLabel("等待读取。", group);
    accessStatusLabel_->setWordWrap(true);
    accessStatusLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outerLayout->addWidget(accessStatusLabel_);

    connect(accessReadButton_, &QPushButton::clicked, this, [this]() { readPhysicalFromUi(); });
    connect(accessWriteButton_, &QPushButton::clicked, this, [this]() { writePhysicalFromUi(); });
    connect(accessHexEditor_, &HexEditorWidget::byteEdited, this,
        [this](const std::uint64_t absoluteAddress,
               const std::uint8_t oldValue,
               const std::uint8_t newValue) {
            Q_UNUSED(oldValue);
            // Editing only modifies the local cache; actual write-back requires explicitly triggering 'DDMA write-back differences'.
            if (!hasSnapshot_ || absoluteAddress < snapshotAddress_)
            {
                return;
            }
            const std::uint64_t kOffset = absoluteAddress - snapshotAddress_;
            if (kOffset >= static_cast<std::uint64_t>(editedBytes_.size()))
            {
                return;
            }
            editedBytes_[static_cast<qsizetype>(kOffset)] = static_cast<char>(newValue);
            if (accessWriteButton_ != nullptr)
            {
                accessWriteButton_->setEnabled(editedBytes_ != originalBytes_);
            }
        });

    return group;
}

QGroupBox* DdmaPage::buildCompareGroup()
{
    QGroupBox* group = new QGroupBox("标准通道 vs DDMA 同址复核", this);
    QVBoxLayout* outerLayout = new QVBoxLayout(group);
    outerLayout->setContentsMargins(8, 8, 8, 8);
    outerLayout->setSpacing(6);

    QLabel* hintLabel = new QLabel(group);
    hintLabel->setWordWrap(true);
    hintLabel->setText(
        "对同一物理地址各读一页：标准通道走 MmCopyMemory，受 SLAT 约束；"
        "DDMA 走设备 DMA，不受约束。两者不一致就是这一页被重定向或隐藏的直接证据。");
    outerLayout->addWidget(hintLabel);

    QHBoxLayout* barLayout = new QHBoxLayout();
    barLayout->setContentsMargins(0, 0, 0, 0);
    barLayout->setSpacing(6);

    compareAddressEdit_ = new QLineEdit(group);
    compareAddressEdit_->setPlaceholderText("物理页地址，例如 0x1000");
    compareAddressEdit_->setClearButtonEnabled(true);

    compareButton_ = new QPushButton(
        QIcon(QStringLiteral(":/Icon/file_find.svg")), "复核这一页", group);

    barLayout->addWidget(new QLabel("物理地址", group));
    barLayout->addWidget(compareAddressEdit_, 1);
    barLayout->addWidget(compareButton_);
    outerLayout->addLayout(barLayout);

    compareResultLabel_ = new QLabel("尚未复核。", group);
    compareResultLabel_->setWordWrap(true);
    compareResultLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outerLayout->addWidget(compareResultLabel_);

    compareTable_ = new QTableWidget(group);
    compareTable_->setColumnCount(3);
    compareTable_->setHorizontalHeaderLabels(QStringList{ "偏移", "标准通道", "DDMA" });
    compareTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    compareTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    compareTable_->setAlternatingRowColors(true);
    compareTable_->verticalHeader()->setVisible(false);
    compareTable_->verticalHeader()->setDefaultSectionSize(20);
    compareTable_->setMaximumHeight(160);
    outerLayout->addWidget(compareTable_);

    connect(compareButton_, &QPushButton::clicked, this, [this]() { compareBackendsFromUi(); });

    return group;
}

void DdmaPage::applySemanticStyles()
{
    // The session status label color is determined by refreshSessionState based on availability; here,
    // we only ensure high-risk buttons have consistent error-colored borders across both themes.
    if (accessWriteButton_ != nullptr)
    {
        accessWriteButton_->setStyleSheet(
            QStringLiteral(
                "QPushButton{border:1px solid %1;border-radius:3px;color:%1;padding:4px 10px;}"
                "QPushButton:disabled{border:1px solid %2;color:%2;}")
                .arg(ksword_theme::errorHex())
                .arg(ksword_theme::textSecondaryHex()));
    }
    refreshSessionState();
}

bool DdmaPage::parseScratchLbaFromUi(std::uint64_t& lbaOut, QString& errorTextOut) const
{
    lbaOut = 0ULL;
    errorTextOut.clear();

    if (scratchLbaEdit_ == nullptr)
    {
        errorTextOut = QStringLiteral("界面尚未初始化。");
        return false;
    }

    const QString kText = scratchLbaEdit_->text().trimmed();
    if (kText.isEmpty())
    {
        // Empty input is always treated as "not filled". It must never degrade to 0—LBA 0 is the sector
        // containing the MBR, and selecting it via a default value is precisely what this feature must avoid.
        errorTextOut = QStringLiteral("尚未填写暂存扇区 LBA。");
        return false;
    }

    std::uint64_t value = 0ULL;
    if (!parseSectorNumberText(kText, value))
    {
        errorTextOut = QStringLiteral("暂存扇区 LBA 解析失败，请填写十进制或 0x 十六进制数值。");
        return false;
    }
    // The protocol handles 48-bit LBA; values exceeding the range are rejected by R0, so we block them locally first.
    constexpr std::uint64_t kLbaMax = 0x0001000000000000ULL;
    if (value >= kLbaMax)
    {
        errorTextOut = QStringLiteral("暂存扇区 LBA 超出 48 位上限。");
        return false;
    }

    lbaOut = value;
    return true;
}

void DdmaPage::probeChannels()
{
    std::uint64_t scratchLba = 0ULL;
    QString lbaError;
    const bool kLbaValid = parseScratchLbaFromUi(scratchLba, lbaError);

    if (capabilityLabel_ != nullptr)
    {
        capabilityLabel_->setText(QStringLiteral("正在探测 DDMA 通道..."));
    }

    // The selected disk must be restored after the table is rebuilt. Once 'detect candidate sectors' is filled with LBAs, it automatically
    // re-probes. If the selection is not remembered here, the disk the user just selected will be deselected, and clicking 'Enable' immediately
    // afterward will only yield the message 'Please select a disk first'. This must be done before m_diskCache is overwritten by the new result.
    // **Before** reading, otherwise the read data will be another disk in the same row number of the new table.
    std::uint32_t previousDeviceIndex = 0U;
    bool hadSelection = false;
    if (diskTable_ != nullptr)
    {
        const int kPreviousRow = diskTable_->currentRow();
        if (kPreviousRow >= 0 && kPreviousRow < static_cast<int>(diskCache_.size()))
        {
            previousDeviceIndex = diskCache_[static_cast<std::size_t>(kPreviousRow)].deviceIndex;
            hadSelection = true;
        }
    }

    const ksword::ark::DriverClient kClient;
    const ksword::ark::DdmaCapabilityResult kResult =
        kClient.queryDdmaCapability(kLbaValid, scratchLba, kLbaValid);

    if (!kResult.io.ok)
    {
        probeCompleted_ = false;
        diskCache_.clear();
        if (diskTable_ != nullptr)
        {
            diskTable_->setRowCount(0);
        }
        if (capabilityLabel_ != nullptr)
        {
            capabilityLabel_->setText(
                QStringLiteral("探测失败：%1").arg(QString::fromStdString(kResult.io.message)));
        }
        refreshSessionState();
        return;
    }

    probeCompleted_ = true;
    diskCache_ = kResult.disks;
    kernelDebuggerEnabled_ = kResult.kernelDebuggerEnabled();
    transferBytes_ = kResult.transferBytes;
    scratchSectorCount_ = kResult.scratchSectorCount;

    // If the probe result changes, previously enabled channels may no longer be valid; first retract the probe surface from the session.
    session_.kernelDebuggerEnabled = kernelDebuggerEnabled_;
    session_.transferBytes = transferBytes_;
    session_.scratchSectorCount = scratchSectorCount_;

    if (diskTable_ != nullptr)
    {
        diskTable_->setRowCount(static_cast<int>(diskCache_.size()));
        for (int row = 0; row < static_cast<int>(diskCache_.size()); ++row)
        {
            const ksword::ark::DdmaDiskEntry& entry = diskCache_[static_cast<std::size_t>(row)];

            // Clearly specify the passthrough path in the status: ATA and SCSI are two completely different
            // paths; simply stating "available" makes it impossible to determine how the disk is connected.
            QString stateText;
            if (entry.ataReady() && entry.scsiReady())
            {
                stateText = QStringLiteral("可用（ATA 与 SCSI 均可）");
            }
            else if (entry.ataReady())
            {
                stateText = QStringLiteral("可用（ATA 直通）");
            }
            else if (entry.scsiReady())
            {
                stateText = QStringLiteral("可用（SCSI 直通，覆盖 NVMe）");
            }
            else if ((entry.diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_PROBE_SKIPPED) != 0UL)
            {
                stateText = QStringLiteral("未探测（需先填写暂存 LBA）");
            }
            else
            {
                stateText = QStringLiteral("不可用（两条直通都被拒绝）");
            }

            diskTable_->setItem(row, static_cast<int>(DiskColumn::kIndex),
                new QTableWidgetItem(QString::number(entry.deviceIndex)));
            diskTable_->setItem(row, static_cast<int>(DiskColumn::kDeviceName),
                new QTableWidgetItem(entry.deviceName.empty()
                    ? QStringLiteral("(名称不可用)")
                    : QString::fromStdWString(entry.deviceName)));
            diskTable_->setItem(row, static_cast<int>(DiskColumn::kState),
                new QTableWidgetItem(stateText));
            // Both probe statuses must be visible: showing only one makes it impossible to determine which one failed.
            diskTable_->setItem(row, static_cast<int>(DiskColumn::kProbeStatus),
                new QTableWidgetItem(QStringLiteral("ATA %1 / SCSI %2")
                    .arg(formatNtStatus(entry.probeStatus))
                    .arg(formatNtStatus(entry.scsiProbeStatus))));
            diskTable_->setItem(row, static_cast<int>(DiskColumn::kSectorSize),
                new QTableWidgetItem(QString::number(entry.sectorSize)));
        }
        diskTable_->resizeColumnsToContents();

        // Restore selection by deviceIndex, not by row number: enumeration order is not guaranteed to remain stable between two probes.
        if (hadSelection)
        {
            for (int row = 0; row < static_cast<int>(diskCache_.size()); ++row)
            {
                if (diskCache_[static_cast<std::size_t>(row)].deviceIndex == previousDeviceIndex)
                {
                    diskTable_->selectRow(row);
                    break;
                }
            }
        }
    }

    QString capabilityText = QStringLiteral(
        "枚举到 %1 块磁盘，其中 %2 块通过 DMA 探测。一次传输 %3 字节，占用 %4 个扇区。")
        .arg(kResult.totalDisks)
        .arg(kResult.readyDisks)
        .arg(kResult.transferBytes)
        .arg(kResult.scratchSectorCount);
    if (!kLbaValid)
    {
        capabilityText += QStringLiteral(" 本次未做传输探测：%1").arg(lbaError);
    }
    if (kernelDebuggerEnabled_)
    {
        capabilityText += QStringLiteral(
            " 本机启用了内核调试，DDMA 会命中 MiShowBadMapper 蓝屏，通道已被禁用。");
    }
    if (capabilityLabel_ != nullptr)
    {
        capabilityLabel_->setText(capabilityText);
    }

    refreshSessionState();
}

bool DdmaPage::physicalDriveIndexFromDeviceName(
    const std::wstring& deviceName,
    std::uint32_t& indexOut)
{
    indexOut = 0U;
    // Device names are in the format \Device\Harddisk0\DR0. The index immediately follows 'Harddisk' and corresponds
    // to the N in \\.\PhysicalDriveN. If the name cannot be retrieved, do not guess—guessing incorrectly leads to
    // reading the partition table of a different disk and potentially suggesting overwriting sectors on that disk.
    const std::wstring kMarker = L"Harddisk";
    const std::size_t kPosition = deviceName.find(kMarker);
    if (kPosition == std::wstring::npos)
    {
        return false;
    }
    std::size_t cursor = kPosition + kMarker.size();
    if (cursor >= deviceName.size() || deviceName[cursor] < L'0' || deviceName[cursor] > L'9')
    {
        return false;
    }
    std::uint64_t value = 0ULL;
    while (cursor < deviceName.size() && deviceName[cursor] >= L'0' && deviceName[cursor] <= L'9')
    {
        value = (value * 10ULL) + static_cast<std::uint64_t>(deviceName[cursor] - L'0');
        if (value > 0xFFFFULL)
        {
            return false;
        }
        ++cursor;
    }
    indexOut = static_cast<std::uint32_t>(value);
    return true;
}

DdmaPage::ScratchDetection DdmaPage::detectScratchByOwnedFile(
    const std::uint32_t driveIndex,
    const std::uint32_t sectorSize)
{
    ScratchDetection detection;
    detection.sourceText = QStringLiteral("专属暂存文件");

    if (sectorSize == 0U)
    {
        detection.summaryText = QStringLiteral("扇区大小未知，无法换算 LBA。");
        return detection;
    }

    // Step 1: Identify volumes residing on this physical disk. Only recognize volumes on fixed disks;
    // Converting LBA requires the "starting offset of the volume on the disk"; only single-extent volumes can reliably provide this.
    wchar_t driveStrings[512] = { 0 };
    const DWORD kDriveStringsLength =
        ::GetLogicalDriveStringsW(static_cast<DWORD>(std::size(driveStrings) - 1U), driveStrings);
    if (kDriveStringsLength == 0UL)
    {
        detection.summaryText = QStringLiteral("枚举卷失败，Win32 错误 %1。").arg(::GetLastError());
        return detection;
    }

    // chosenRoot is like "D:" followed by a backslash. Note: Line comments must not end with a backslash, as
    // that is a line-continuation character that would swallow the entire next declaration into the comment.
    QString chosenRoot;
    std::uint64_t volumeStartOffset = 0ULL;
    for (const wchar_t* cursor = driveStrings; *cursor != L'\0'; cursor += wcslen(cursor) + 1U)
    {
        const QString kRoot = QString::fromWCharArray(cursor);
        if (::GetDriveTypeW(cursor) != DRIVE_FIXED)
        {
            continue;
        }
        // Open the volume device in \\.\X: format to query which physical disk and offset it resides on.
        const QString kVolumePath = QStringLiteral("\\\\.\\%1").arg(kRoot.left(2));
        const HANDLE kVolumeHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(kVolumePath.utf16()),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        if (kVolumeHandle == INVALID_HANDLE_VALUE)
        {
            continue;
        }
        std::vector<std::uint8_t> extentBuffer(4096U, 0U);
        DWORD returned = 0UL;
        const BOOL kExtentOk = ::DeviceIoControl(
            kVolumeHandle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            nullptr,
            0UL,
            extentBuffer.data(),
            static_cast<DWORD>(extentBuffer.size()),
            &returned,
            nullptr);
        ::CloseHandle(kVolumeHandle);
        if (kExtentOk == FALSE || returned < sizeof(VOLUME_DISK_EXTENTS))
        {
            continue;
        }
        const auto* extents =
            reinterpret_cast<const VOLUME_DISK_EXTENTS*>(extentBuffer.data());
        // Volumes spanning multiple disks (spanned/striped) cannot provide a single starting offset; conversion would be incorrect, so skip directly.
        if (extents->NumberOfDiskExtents != 1UL)
        {
            continue;
        }
        if (extents->Extents[0].DiskNumber != driveIndex)
        {
            continue;
        }
        chosenRoot = kRoot;
        volumeStartOffset =
            static_cast<std::uint64_t>(extents->Extents[0].StartingOffset.QuadPart);
        break;
    }

    if (chosenRoot.isEmpty())
    {
        detection.summaryText = QStringLiteral(
            "这块磁盘上没有找到可写入的单区间固定卷，无法建立专属暂存文件。");
        return detection;
    }

    // Step 2: Cluster size. LCNs are counted in clusters; converting to LBA requires knowing the byte size of one cluster.
    DWORD sectorsPerCluster = 0UL;
    DWORD bytesPerSector = 0UL;
    DWORD freeClusters = 0UL;
    DWORD totalClusters = 0UL;
    if (::GetDiskFreeSpaceW(
            reinterpret_cast<LPCWSTR>(chosenRoot.utf16()),
            &sectorsPerCluster,
            &bytesPerSector,
            &freeClusters,
            &totalClusters) == FALSE ||
        sectorsPerCluster == 0UL || bytesPerSector == 0UL)
    {
        detection.summaryText = QStringLiteral(
            "读取 %1 的簇大小失败，Win32 错误 %2。").arg(chosenRoot).arg(::GetLastError());
        return detection;
    }
    const std::uint64_t kClusterBytes =
        static_cast<std::uint64_t>(sectorsPerCluster) * bytesPerSector;

    // Step 3: Create a temporary file and write it to disk. The size is set to 16 times
    // a single transfer to ensure it is definitely non-resident—NTFS stores very small
    // files directly in MFT records, which have no retrieval pointer and thus no LCN.
    const std::uint64_t kScratchBytes =
        static_cast<std::uint64_t>(ksword::memory_backend::ddmaTransferBytes()) * 16ULL;
    const QString kFilePath = chosenRoot + QStringLiteral("KSwordDdmaScratch.bin");
    {
        const HANDLE kFileHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(kFilePath.utf16()),
            GENERIC_READ | GENERIC_WRITE,
            0UL,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_WRITE_THROUGH,
            nullptr);
        if (kFileHandle == INVALID_HANDLE_VALUE)
        {
            detection.summaryText = QStringLiteral(
                "创建暂存文件 %1 失败，Win32 错误 %2。").arg(kFilePath).arg(::GetLastError());
            return detection;
        }
        const std::vector<std::uint8_t> kFiller(static_cast<std::size_t>(kScratchBytes), 0U);
        DWORD written = 0UL;
        const BOOL kWriteOk = ::WriteFile(
            kFileHandle,
            kFiller.data(),
            static_cast<DWORD>(kFiller.size()),
            &written,
            nullptr);
        ::FlushFileBuffers(kFileHandle);
        ::CloseHandle(kFileHandle);
        if (kWriteOk == FALSE || written != kFiller.size())
        {
            detection.summaryText = QStringLiteral(
                "写入暂存文件失败，Win32 错误 %1。").arg(::GetLastError());
            return detection;
        }
    }

    // Step 4: Retrieve pointers to obtain the LCN of the first extent.
    std::uint64_t firstLcn = 0ULL;
    std::uint64_t extentClusters = 0ULL;
    {
        const HANDLE kFileHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(kFilePath.utf16()),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0UL,
            nullptr);
        if (kFileHandle == INVALID_HANDLE_VALUE)
        {
            detection.summaryText = QStringLiteral(
                "重新打开暂存文件失败，Win32 错误 %1。").arg(::GetLastError());
            return detection;
        }
        STARTING_VCN_INPUT_BUFFER input{};
        input.StartingVcn.QuadPart = 0;
        std::vector<std::uint8_t> output(8192U, 0U);
        DWORD returned = 0UL;
        const BOOL kOk = ::DeviceIoControl(
            kFileHandle,
            FSCTL_GET_RETRIEVAL_POINTERS,
            &input,
            static_cast<DWORD>(sizeof(input)),
            output.data(),
            static_cast<DWORD>(output.size()),
            &returned,
            nullptr);
        const DWORD kLastError = ::GetLastError();
        ::CloseHandle(kFileHandle);
        if (kOk == FALSE && kLastError != ERROR_MORE_DATA)
        {
            detection.summaryText = QStringLiteral(
                "读取暂存文件簇映射失败，Win32 错误 %1。文件可能是驻留在 MFT 里的小文件。")
                .arg(kLastError);
            return detection;
        }
        const auto* pointers =
            reinterpret_cast<const RETRIEVAL_POINTERS_BUFFER*>(output.data());
        if (pointers->ExtentCount == 0UL)
        {
            detection.summaryText = QStringLiteral(
                "暂存文件没有任何簇映射（可能是驻留文件或稀疏文件），无法换算 LBA。");
            return detection;
        }
        if (pointers->Extents[0].Lcn.QuadPart < 0)
        {
            detection.summaryText = QStringLiteral("暂存文件第一段没有实际分配的簇。");
            return detection;
        }
        firstLcn = static_cast<std::uint64_t>(pointers->Extents[0].Lcn.QuadPart);
        extentClusters =
            static_cast<std::uint64_t>(pointers->Extents[0].NextVcn.QuadPart) -
            static_cast<std::uint64_t>(pointers->StartingVcn.QuadPart);
    }

    // Step 5: LCN → volume-relative byte offset → disk byte offset → disk LBA.
    const std::uint64_t kDiskByteOffset = volumeStartOffset + (firstLcn * kClusterBytes);
    if ((kDiskByteOffset % sectorSize) != 0ULL)
    {
        detection.summaryText = QStringLiteral(
            "换算出的磁盘偏移没有落在扇区边界上，放弃这条路线。");
        return detection;
    }

    detection.ok = true;
    detection.suggestedLba = kDiskByteOffset / sectorSize;
    detection.scratchFilePath = kFilePath;
    detection.summaryText = QStringLiteral(
        "已在 %1 上建立专属暂存文件并占用它自己的簇：LCN %2，连续 %3 簇（每簇 %4 字节）。这块扇区归这个文件所有，不会有别的文件住在这里，也不会被系统分配给别人。通道使用期间不要删除这个文件——删掉它会把这些簇交还系统，可能立刻被分配给别的文件，而暂存 LBA 还指着原处。")
        .arg(kFilePath)
        .arg(firstLcn)
        .arg(extentClusters)
        .arg(kClusterBytes);
    return detection;
}

DdmaPage::ScratchDetection DdmaPage::detectScratchCandidatesForSelectedDisk()
{
    ScratchDetection detection;

    if (diskTable_ == nullptr)
    {
        detection.summaryText = QStringLiteral("界面尚未初始化。");
        return detection;
    }
    const int kRow = diskTable_->currentRow();
    if (kRow < 0 || kRow >= static_cast<int>(diskCache_.size()))
    {
        detection.summaryText = QStringLiteral("请先在上表里选中一块磁盘。");
        return detection;
    }

    const ksword::ark::DdmaDiskEntry& entry = diskCache_[static_cast<std::size_t>(kRow)];
    std::uint32_t driveIndex = 0U;
    if (entry.deviceName.empty() ||
        !physicalDriveIndexFromDeviceName(entry.deviceName, driveIndex))
    {
        detection.summaryText = QStringLiteral(
            "无法从设备名推出物理磁盘序号，侦测中止。设备名=%1")
            .arg(entry.deviceName.empty()
                ? QStringLiteral("(不可用)")
                : QString::fromStdWString(entry.deviceName));
        return detection;
    }

    // Prioritize the 'dedicated scratch file' route: the sectors belong to us, proving no other file resides there, and
    // eliminating the race condition where the bitmap is read but the space is allocated to the system before the actual DMA.
    // Only if this route fails (e.g., no writable volume on disk, file resides in MFT) do we fall back to unallocated gaps.
    {
        ScratchDetection owned =
            detectScratchByOwnedFile(driveIndex, (entry.sectorSize != 0U) ? entry.sectorSize : 512U);
        if (owned.ok)
        {
            return owned;
        }
        // The failure reason must be carried into the conclusion of the next route; otherwise,
        // the user will only see "used gap" and not know why the safer route failed.
        scratchFilePath_.clear();
        const QString kOwnedFailure = owned.summaryText;
        ScratchDetection fallback = detectScratchCandidatesByGap(driveIndex, entry);
        fallback.summaryText = QStringLiteral("未能使用专属暂存文件（%1）改用未分配间隙：%2")
            .arg(kOwnedFailure)
            .arg(fallback.summaryText);
        return fallback;
    }
}

DdmaPage::ScratchDetection DdmaPage::detectScratchCandidatesByGap(
    const std::uint32_t driveIndex,
    const ksword::ark::DdmaDiskEntry& entry)
{
    ScratchDetection detection;
    detection.sourceText = QStringLiteral("未分配间隙");

    const QString kDrivePath = QStringLiteral("\\\\.\\PhysicalDrive%1").arg(driveIndex);
    const HANDLE kDiskHandle = ::CreateFileW(
        reinterpret_cast<LPCWSTR>(kDrivePath.utf16()),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (kDiskHandle == INVALID_HANDLE_VALUE)
    {
        detection.summaryText = QStringLiteral(
            "打开 %1 失败，Win32 错误 %2。侦测需要管理员权限。")
            .arg(kDrivePath)
            .arg(::GetLastError());
        return detection;
    }

    // Use a simple cleanup outside RAII: every return path below must close the handle, so close it uniformly at the end.
    std::vector<ksword::evidence::DdmaScratchOccupiedRange> occupied;
    std::uint64_t diskSectorCount = 0ULL;
    std::uint32_t sectorSize = (entry.sectorSize != 0U) ? entry.sectorSize : 512U;

    // Disk geometry: retrieve sector size and total sector count.
    {
        DISK_GEOMETRY_EX geometry{};
        DWORD returned = 0UL;
        if (::DeviceIoControl(
                kDiskHandle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                nullptr,
                0UL,
                &geometry,
                static_cast<DWORD>(sizeof(geometry)),
                &returned,
                nullptr) != FALSE)
        {
            if (geometry.Geometry.BytesPerSector != 0UL)
            {
                sectorSize = geometry.Geometry.BytesPerSector;
            }
            if (sectorSize != 0U && geometry.DiskSize.QuadPart > 0)
            {
                diskSectorCount =
                    static_cast<std::uint64_t>(geometry.DiskSize.QuadPart) / sectorSize;
            }
        }
    }
    if (diskSectorCount == 0ULL)
    {
        ::CloseHandle(kDiskHandle);
        detection.summaryText = QStringLiteral("读取磁盘几何失败，无法计算间隙。");
        return detection;
    }

    // Partition table: Extract only start and end addresses; risk classification is handled by the pure arithmetic module.
    {
        std::vector<std::uint8_t> layoutBuffer(16384U, 0U);
        DWORD returned = 0UL;
        if (::DeviceIoControl(
                kDiskHandle,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                nullptr,
                0UL,
                layoutBuffer.data(),
                static_cast<DWORD>(layoutBuffer.size()),
                &returned,
                nullptr) == FALSE ||
            returned < sizeof(DRIVE_LAYOUT_INFORMATION_EX))
        {
            ::CloseHandle(kDiskHandle);
            detection.summaryText = QStringLiteral(
                "读取分区表失败，Win32 错误 %1。").arg(::GetLastError());
            return detection;
        }
        const auto* layout =
            reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(layoutBuffer.data());
        for (DWORD index = 0UL; index < layout->PartitionCount; ++index)
        {
            const PARTITION_INFORMATION_EX& partition = layout->PartitionEntry[index];
            if (partition.PartitionLength.QuadPart <= 0)
            {
                continue;
            }
            // Unused slots in the MBR table have a length of zero or type 0; the line above already filters them out.
            ksword::evidence::DdmaScratchOccupiedRange range;
            range.startSector =
                static_cast<std::uint64_t>(partition.StartingOffset.QuadPart) / sectorSize;
            range.sectorCount =
                static_cast<std::uint64_t>(partition.PartitionLength.QuadPart) / sectorSize;
            occupied.push_back(range);
        }
    }

    const std::uint32_t kRequiredSectors =
        ksword::memory_backend::ddmaTransferBytes() / sectorSize;
    const std::vector<ksword::evidence::DdmaScratchCandidate> kCandidates =
        ksword::evidence::planDdmaScratchCandidates(diskSectorCount, occupied, kRequiredSectors);

    const ksword::evidence::DdmaScratchCandidate* chosen = nullptr;
    for (const ksword::evidence::DdmaScratchCandidate& candidate : kCandidates)
    {
        if (candidate.usable && ksword::evidence::ddmaScratchRiskIsSelectable(candidate.risk))
        {
            chosen = &candidate;
            break;
        }
    }

    if (chosen == nullptr)
    {
        ::CloseHandle(kDiskHandle);
        // Explain why there are none, not just state that there are none. The gap at the disk header is often
        // the only available space, yet it is precisely the region that must never be auto-recommended.
        detection.summaryText = QStringLiteral(
            "这块磁盘上没有可自动推荐的暂存区间（共 %1 段未分配空间）。"
            "磁盘头部的间隙是引导器寄居处，尾部是 GPT 备份分区表，两者都不会被推荐；"
            "分区之间若没有留出至少一次传输的空档，就只能由你手工指定一个 LBA。")
            .arg(kCandidates.size());
        return detection;
    }

    // Second piece of evidence: The partition table stating 'unallocated' merely means no registration exists; only a direct read confirms whether the area is truly empty.
    // All zeros can be safely assumed to indicate no usage; non-zero content must trigger a significant
    // alert, as it likely represents a bootloader or vendor data without a partition table entry.
    bool allZero = false;
    bool contentRead = false;
    {
        std::vector<std::uint8_t> sample(ksword::memory_backend::ddmaTransferBytes(), 0U);
        LARGE_INTEGER offset{};
        offset.QuadPart =
            static_cast<LONGLONG>(chosen->startSector * static_cast<std::uint64_t>(sectorSize));
        if (::SetFilePointerEx(kDiskHandle, offset, nullptr, FILE_BEGIN) != FALSE)
        {
            DWORD readBytes = 0UL;
            if (::ReadFile(
                    kDiskHandle,
                    sample.data(),
                    static_cast<DWORD>(sample.size()),
                    &readBytes,
                    nullptr) != FALSE &&
                readBytes == sample.size())
            {
                contentRead = true;
                allZero = std::all_of(
                    sample.begin(),
                    sample.end(),
                    [](const std::uint8_t value) { return value == 0U; });
            }
        }
    }
    ::CloseHandle(kDiskHandle);

    detection.ok = true;
    detection.suggestedLba = chosen->startSector;
    detection.contentAllZero = allZero;

    const QString kRiskText =
        (chosen->risk == ksword::evidence::DdmaScratchRisk::kInteriorGap)
            ? QStringLiteral("分区之间的未分配间隙")
            : QStringLiteral("最后一个分区之后的未分配空间");
    QString summary = QStringLiteral(
        "建议 LBA %1（%2）。所在间隙 %3 - %4，共 %5 个扇区；一次传输占 %6 个。")
        .arg(chosen->startSector)
        .arg(kRiskText)
        .arg(chosen->gapStartSector)
        .arg(chosen->gapStartSector + chosen->gapSectorCount - 1ULL)
        .arg(chosen->gapSectorCount)
        .arg(kRequiredSectors);
    if (!contentRead)
    {
        summary += QStringLiteral(
            " 未能读回该区间内容做复核，无法确认它当前是否空闲，请自行判断。");
    }
    else if (allZero)
    {
        summary += QStringLiteral(" 已读回复核：该区间当前全为 0，没有观察到使用痕迹。");
    }
    else
    {
        summary += QStringLiteral(
            " 警告：已读回复核发现该区间**不是全零**。分区表说它未分配，但那里确实有数据——"
            "可能是没有分区表项的引导器或厂商保留数据。除非你清楚那是什么，否则不要用它。");
    }
    detection.summaryText = summary;
    return detection;
}

QString DdmaPage::buildScratchContextText(
    const std::uint32_t driveIndex,
    const std::uint64_t startLba,
    const std::uint32_t sectorSize,
    bool& allZeroOut)
{
    allZeroOut = false;
    QStringList lines;

    const std::uint32_t kTransferBytes = ksword::memory_backend::ddmaTransferBytes();
    const std::uint32_t kSectorCount =
        (sectorSize != 0U) ? (kTransferBytes / sectorSize) : 0U;
    const std::uint64_t kByteOffset =
        startLba * static_cast<std::uint64_t>(sectorSize);

    lines << QStringLiteral("目标磁盘      : \\\\.\\PhysicalDrive%1").arg(driveIndex);
    lines << QStringLiteral("扇区大小      : %1 字节").arg(sectorSize);
    lines << QStringLiteral("起始 LBA      : %1  (0x%2)")
                 .arg(startLba)
                 .arg(startLba, 0, 16);
    lines << QStringLiteral("覆盖范围      : LBA %1 - %2，共 %3 个扇区")
                 .arg(startLba)
                 .arg(startLba + kSectorCount - 1ULL)
                 .arg(kSectorCount);
    lines << QStringLiteral("磁盘字节偏移  : %1  (0x%2)")
                 .arg(kByteOffset)
                 .arg(kByteOffset, 0, 16);

    // Ownership: Determine whether this offset falls within a partition or outside it.
    // This is the most direct way to see if I am about to overwrite an active partition.
    const QString kDrivePath = QStringLiteral("\\\\.\\PhysicalDrive%1").arg(driveIndex);
    const HANDLE kDiskHandle = ::CreateFileW(
        reinterpret_cast<LPCWSTR>(kDrivePath.utf16()),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (kDiskHandle == INVALID_HANDLE_VALUE)
    {
        lines << QStringLiteral("归属          : 打不开磁盘，无法核对（Win32 %1）")
                     .arg(::GetLastError());
        return lines.join(QLatin1Char('\n'));
    }

    {
        std::vector<std::uint8_t> layoutBuffer(16384U, 0U);
        DWORD returned = 0UL;
        QString ownerText = QStringLiteral("未落在任何分区内（未分配空间）");
        if (::DeviceIoControl(
                kDiskHandle,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                nullptr,
                0UL,
                layoutBuffer.data(),
                static_cast<DWORD>(layoutBuffer.size()),
                &returned,
                nullptr) != FALSE &&
            returned >= sizeof(DRIVE_LAYOUT_INFORMATION_EX))
        {
            const auto* layout =
                reinterpret_cast<const DRIVE_LAYOUT_INFORMATION_EX*>(layoutBuffer.data());
            for (DWORD index = 0UL; index < layout->PartitionCount; ++index)
            {
                const PARTITION_INFORMATION_EX& partition = layout->PartitionEntry[index];
                if (partition.PartitionLength.QuadPart <= 0)
                {
                    continue;
                }
                const std::uint64_t kStart =
                    static_cast<std::uint64_t>(partition.StartingOffset.QuadPart);
                const std::uint64_t kEnd =
                    kStart + static_cast<std::uint64_t>(partition.PartitionLength.QuadPart);
                if (kByteOffset >= kStart && kByteOffset < kEnd)
                {
                    ownerText = QStringLiteral("分区 %1（起始字节 %2，长度 %3）")
                                    .arg(partition.PartitionNumber)
                                    .arg(kStart)
                                    .arg(kEnd - kStart);
                    break;
                }
            }
        }
        lines << QStringLiteral("归属          : %1").arg(ownerText);
    }

    // Content preview: Perform a real read. The partition table may say 'unallocated' simply because it is unregistered; only reading reveals if it is actually empty.
    std::vector<std::uint8_t> sample(kTransferBytes, 0U);
    bool contentRead = false;
    LARGE_INTEGER offset{};
    offset.QuadPart = static_cast<LONGLONG>(kByteOffset);
    if (::SetFilePointerEx(kDiskHandle, offset, nullptr, FILE_BEGIN) != FALSE)
    {
        DWORD readBytes = 0UL;
        if (::ReadFile(
                kDiskHandle,
                sample.data(),
                static_cast<DWORD>(sample.size()),
                &readBytes,
                nullptr) != FALSE &&
            readBytes == sample.size())
        {
            contentRead = true;
        }
    }
    ::CloseHandle(kDiskHandle);

    if (!contentRead)
    {
        lines << QStringLiteral("当前内容      : 读取失败，无法复核");
        return lines.join(QLatin1Char('\n'));
    }

    allZeroOut = std::all_of(
        sample.begin(), sample.end(), [](const std::uint8_t value) { return value == 0U; });
    lines << QStringLiteral("当前内容      : %1")
                 .arg(allZeroOut
                          ? QStringLiteral("全部为 0，没有观察到使用痕迹")
                          : QStringLiteral("非全零 —— 那里确实有数据，用之前请弄清是什么"));
    lines << QString();
    lines << QStringLiteral("前 128 字节十六进制预览：");

    // Iterate 16 bytes per line with offset and ASCII sidebar.
    const std::size_t kPreviewBytes = std::min<std::size_t>(sample.size(), 128U);
    for (std::size_t base = 0U; base < kPreviewBytes; base += 16U)
    {
        QString hexPart;
        QString asciiPart;
        for (std::size_t column = 0U; column < 16U; ++column)
        {
            if (base + column >= kPreviewBytes)
            {
                hexPart += QStringLiteral("   ");
                continue;
            }
            const std::uint8_t kValue = sample[base + column];
            hexPart += QStringLiteral("%1 ").arg(kValue, 2, 16, QChar('0')).toUpper();
            asciiPart += (kValue >= 0x20U && kValue < 0x7FU)
                ? QChar(static_cast<char16_t>(kValue))
                : QChar(QLatin1Char('.'));
        }
        lines << QStringLiteral("  +%1  %2 |%3|")
                     .arg(base, 4, 16, QChar('0'))
                     .arg(hexPart)
                     .arg(asciiPart);
    }

    return lines.join(QLatin1Char('\n'));
}

void DdmaPage::detectScratchFromUi()
{
    if (scratchDetectLabel_ != nullptr)
    {
        scratchDetectLabel_->setText(QStringLiteral("正在侦测候选扇区..."));
    }

    const ScratchDetection kDetection = detectScratchCandidatesForSelectedDisk();

    if (!kDetection.ok)
    {
        if (scratchDetectLabel_ != nullptr)
        {
            scratchDetectLabel_->setText(kDetection.summaryText);
            scratchDetectLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }
        if (scratchContextView_ != nullptr)
        {
            scratchContextView_->setRawText(QStringLiteral("侦测未得出候选。"));
        }
        return;
    }

    // Context is always read and computed on the fly, without reusing intermediate values from the detection process: this
    // section is for user "re-confirmation" and must reflect the actual disk state at the moment the button was clicked.
    std::uint32_t driveIndex = 0U;
    std::uint32_t sectorSize = 512U;
    if (diskTable_ != nullptr)
    {
        const int kRow = diskTable_->currentRow();
        if (kRow >= 0 && kRow < static_cast<int>(diskCache_.size()))
        {
            const ksword::ark::DdmaDiskEntry& entry = diskCache_[static_cast<std::size_t>(kRow)];
            physicalDriveIndexFromDeviceName(entry.deviceName, driveIndex);
            if (entry.sectorSize != 0U)
            {
                sectorSize = entry.sectorSize;
            }
        }
    }

    bool allZero = false;
    QString contextText =
        buildScratchContextText(driveIndex, kDetection.suggestedLba, sectorSize, allZero);
    if (!kDetection.scratchFilePath.isEmpty())
    {
        contextText = QStringLiteral("来源          : 专属暂存文件 %1\n")
                          .arg(kDetection.scratchFilePath) + contextText;
    }
    else
    {
        contextText = QStringLiteral("来源          : %1\n").arg(kDetection.sourceText) + contextText;
    }

    scratchFilePath_ = kDetection.scratchFilePath;
    if (scratchContextView_ != nullptr)
    {
        scratchContextView_->setRawText(contextText);
    }
    if (scratchDetectLabel_ != nullptr)
    {
        scratchDetectLabel_->setText(kDetection.summaryText);
        scratchDetectLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(allZero ? ksword_theme::successHex() : ksword_theme::warningHex()));
    }

    // Fill in only the LBA. Keep the confirmation dialog static—the automatic calculation of candidates is
    // to save manual calculation, not to assume the user's judgment that "this sector can be overwritten."
    if (scratchLbaEdit_ != nullptr)
    {
        scratchLbaEdit_->setText(QString::number(kDetection.suggestedLba));
    }

    // Re-probe immediately after filling the LBA. Without this step, the disk table retains the stale "unprobed
    // (requires filling temporary LBA first)" result. If the user then clicks "Enable Selected Disk," they will
    // encounter the error "This disk failed DMA probing"—which is confusing since they just filled the LBA.
    // probeChannels internally restores the selected row and refreshes the session state at the end.
    probeChannels();
}

void DdmaPage::activateSelectedDisk()
{
    if (diskTable_ == nullptr)
    {
        return;
    }
    const int kRow = diskTable_->currentRow();
    if (kRow < 0 || kRow >= static_cast<int>(diskCache_.size()))
    {
        QMessageBox::warning(this, QStringLiteral("DDMA"), QStringLiteral("请先选中一块磁盘。"));
        return;
    }

    const ksword::ark::DdmaDiskEntry& entry = diskCache_[static_cast<std::size_t>(kRow)];
    if (!entry.ready())
    {
        // 'Never probed' and 'probed but rejected' are distinct cases, requiring completely different next steps:
        // The former just needs to fill in the LBA and probe again; the latter indicates the disk fundamentally rejects ATA passthrough,
        // so probing any number of times is futile. Merging these into one sentence would force users to repeatedly attempt a dead end.
        const bool kProbeSkipped =
            (entry.diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_PROBE_SKIPPED) != 0UL;
        const QString kMessage = kProbeSkipped
            ? QStringLiteral("这块磁盘还没有做过 DMA 传输探测。请先填写或侦测暂存扇区 LBA，再点“探测可用磁盘”。")
            : QStringLiteral("这块磁盘的两条直通都被拒绝，不能作为 DDMA 通道，重复探测也不会改变结果。ATA 直通 NTSTATUS=%1，SCSI 直通 NTSTATUS=%2。SCSI 直通覆盖 NVMe 与 SAS/SATA；两条都不通通常意味着这块盘的驱动栈不接受任何直通命令。")
                  .arg(formatNtStatus(entry.probeStatus))
                  .arg(formatNtStatus(entry.scsiProbeStatus));
        QMessageBox::warning(this, QStringLiteral("DDMA"), kMessage);
        return;
    }

    std::uint64_t scratchLba = 0ULL;
    QString lbaError;
    if (!parseScratchLbaFromUi(scratchLba, lbaError))
    {
        QMessageBox::warning(this, QStringLiteral("DDMA"), lbaError);
        return;
    }

    session_.configured = true;
    session_.diskIndex = entry.deviceIndex;
    session_.deviceName = entry.deviceName;
    session_.scratchLba = scratchLba;
    session_.scratchLbaValid = true;
    session_.scratchAcknowledged =
        (scratchAckCheck_ != nullptr) && scratchAckCheck_->isChecked();
    session_.kernelDebuggerEnabled = kernelDebuggerEnabled_;
    session_.transferBytes = transferBytes_;
    session_.scratchSectorCount = scratchSectorCount_;

    refreshSessionState();
}

void DdmaPage::clearSession()
{
    // Detects that a dedicated scratch file is left on disk. Since this is a side effect of this page, there must be a rollback path;
    // otherwise, users would have to manually find a hidden file on the D: drive. It is placed in "Clear Channel Configuration"
    // because this is the endpoint of the file's lifecycle: once the channel is no longer needed, the file is no longer necessary.
    if (!scratchFilePath_.isEmpty() && QFile::exists(scratchFilePath_))
    {
        const QMessageBox::StandardButton kAnswer = QMessageBox::question(
            this,
            QStringLiteral("DDMA"),
            QStringLiteral("是否同时删除本页创建的专属暂存文件？\n%1\n\n删除后这些簇会交还系统。如果还有别处正在用这个 LBA，请选择“否”。")
                .arg(scratchFilePath_),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kAnswer == QMessageBox::Yes)
        {
            if (QFile::remove(scratchFilePath_))
            {
                if (scratchDetectLabel_ != nullptr)
                {
                    scratchDetectLabel_->setText(
                        QStringLiteral("已删除专属暂存文件 %1。").arg(scratchFilePath_));
                    scratchDetectLabel_->setStyleSheet(
                        QStringLiteral("color:%1;").arg(ksword_theme::textSecondaryHex()));
                }
            }
            else if (scratchDetectLabel_ != nullptr)
            {
                scratchDetectLabel_->setText(
                    QStringLiteral("删除专属暂存文件失败：%1。").arg(scratchFilePath_));
                scratchDetectLabel_->setStyleSheet(
                    QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
            }
        }
    }
    scratchFilePath_.clear();
    if (scratchContextView_ != nullptr)
    {
        scratchContextView_->setRawText(
            QStringLiteral("尚未侦测。选中一块磁盘后点击“侦测候选扇区”。"));
    }

    session_ = ksword::memory_backend::DdmaSession{};
    // The detected machine attributes are independent of whether the session is enabled; retain them for continued status display.
    session_.kernelDebuggerEnabled = kernelDebuggerEnabled_;
    session_.transferBytes = transferBytes_;
    session_.scratchSectorCount = scratchSectorCount_;
    refreshSessionState();
}

void DdmaPage::refreshSessionState()
{
    // The checked state can change at any time; these two items in the session always follow the control, so there is no need to re-click 'Enable'.
    if (session_.configured)
    {
        session_.scratchAcknowledged =
            (scratchAckCheck_ != nullptr) && scratchAckCheck_->isChecked();

        std::uint64_t scratchLba = 0ULL;
        QString lbaError;
        if (parseScratchLbaFromUi(scratchLba, lbaError))
        {
            session_.scratchLba = scratchLba;
            session_.scratchLbaValid = true;
        }
        else
        {
            session_.scratchLbaValid = false;
        }
    }

    // The impact range description must update in real-time with input; users should immediately see which sectors are affected when modifying the LBA.
    if (scratchImpactLabel_ != nullptr)
    {
        std::uint64_t scratchLba = 0ULL;
        QString lbaError;
        const std::uint32_t kSectorCount = (scratchSectorCount_ != 0U)
            ? scratchSectorCount_
            : static_cast<std::uint32_t>(KSWORD_ARK_DDMA_SCRATCH_SECTOR_COUNT);
        if (parseScratchLbaFromUi(scratchLba, lbaError))
        {
            QString impactText = QStringLiteral(
                "每次 DDMA 操作会临时覆盖 LBA %1 到 %2 共 %3 个扇区（字节偏移 %4 起）。")
                .arg(scratchLba)
                .arg(scratchLba + kSectorCount - 1ULL)
                .arg(kSectorCount)
                .arg(formatAddress(scratchLba * KSWORD_ARK_DDMA_SECTOR_SIZE));
            if (scratchLba < kSectorCount)
            {
                impactText += QStringLiteral(
                    " 警告：这段范围覆盖了 LBA 0，也就是 MBR / GPT 保护扇区。"
                    "操作期间发生蓝屏或断电会导致磁盘无法引导。");
            }
            scratchImpactLabel_->setText(impactText);
        }
        else
        {
            scratchImpactLabel_->setText(lbaError);
        }
    }

    // This page is the sole writer for process-level sessions: once local state changes, it is immediately pushed up; the
    // persistent indicator light in the top-right corner and the backend dropdowns on other pages all read from this single source.
    ksword::memory_backend::setCurrentDdmaSession(session_);

    QString reason;
    const bool kUsable = ksword::memory_backend::isDdmaUsable(session_, &reason);

    if (sessionStateLabel_ != nullptr)
    {
        if (kUsable)
        {
            sessionStateLabel_->setText(QStringLiteral(
                "DDMA 通道已就绪：磁盘 #%1 %2，暂存 LBA %3。"
                "内存搜索、内存查看器、驱动内存读写与系统内存审计四个页面现在都可以选择 DDMA 后端。")
                .arg(session_.diskIndex)
                .arg(session_.deviceName.empty()
                    ? QStringLiteral("(名称不可用)")
                    : QString::fromStdWString(session_.deviceName))
                .arg(session_.scratchLba));
            sessionStateLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
        else
        {
            sessionStateLabel_->setText(QStringLiteral("DDMA 通道不可用：%1").arg(reason));
            // The kernel debugger line indicates 'causes a BSOD if used', which is more severe than 'not configured yet', so use an error color.
            sessionStateLabel_->setStyleSheet(
                QStringLiteral("color:%1;")
                    .arg(session_.kernelDebuggerEnabled
                        ? ksword_theme::errorHex()
                        : ksword_theme::warningHex()));
        }
    }

    if (accessReadButton_ != nullptr)
    {
        accessReadButton_->setEnabled(kUsable);
    }
    if (accessWriteButton_ != nullptr && !kUsable)
    {
        accessWriteButton_->setEnabled(false);
    }
    if (compareButton_ != nullptr)
    {
        compareButton_->setEnabled(kUsable);
    }

    if (sessionChangedCallback_)
    {
        sessionChangedCallback_();
    }
}

void DdmaPage::readPhysicalFromUi()
{
    if (accessAddressEdit_ == nullptr || accessLengthSpin_ == nullptr)
    {
        return;
    }

    std::uint64_t physicalAddress = 0ULL;
    if (!parseAddressText(accessAddressEdit_->text(), physicalAddress))
    {
        QMessageBox::warning(
            this, QStringLiteral("DDMA"), QStringLiteral("物理地址解析失败，请填写 0x 十六进制地址。"));
        return;
    }

    const std::uint64_t kLengthBytes = static_cast<std::uint64_t>(accessLengthSpin_->value());
    if (accessStatusLabel_ != nullptr)
    {
        accessStatusLabel_->setText(QStringLiteral("正在通过 DDMA 读取物理内存..."));
    }

    const ksword::memory_backend::AccessOutcome kOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::kDdma,
            session_,
            physicalAddress,
            kLengthBytes);

    if (!kOutcome.ok)
    {
        hasSnapshot_ = false;
        originalBytes_.clear();
        editedBytes_.clear();
        if (accessWriteButton_ != nullptr)
        {
            accessWriteButton_->setEnabled(false);
        }
        if (accessStatusLabel_ != nullptr)
        {
            accessStatusLabel_->setText(QStringLiteral("DDMA 读取失败：%1").arg(kOutcome.failureText));
        }
        QMessageBox::warning(this, QStringLiteral("DDMA"), kOutcome.failureText);
        return;
    }

    snapshotAddress_ = physicalAddress;
    originalBytes_ = kOutcome.data;
    editedBytes_ = originalBytes_;
    hasSnapshot_ = true;

    if (accessHexEditor_ != nullptr)
    {
        accessHexEditor_->setEditable(true);
        accessHexEditor_->setByteArray(editedBytes_, snapshotAddress_);
    }
    if (accessWriteButton_ != nullptr)
    {
        accessWriteButton_->setEnabled(false);
    }

    QString statusText = QStringLiteral("DDMA 读取成功，共 %1 字节。").arg(originalBytes_.size());
    if (kOutcome.scratchDirty)
    {
        statusText += QStringLiteral(
            " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区，请立即检查 LBA %1 起的内容。")
            .arg(session_.scratchLba);
    }
    if (accessStatusLabel_ != nullptr)
    {
        accessStatusLabel_->setText(statusText);
    }
}

void DdmaPage::writePhysicalFromUi()
{
    if (!hasSnapshot_ || editedBytes_ == originalBytes_)
    {
        return;
    }

    const QMessageBox::StandardButton kConfirm = QMessageBox::warning(
        this,
        QStringLiteral("DDMA 写入确认"),
        QStringLiteral(
            "即将用磁盘 DMA 直接写入物理内存。\n"
            "起始物理地址: %1\n"
            "长度: %2 字节\n\n"
            "这条路径没有事务与回滚，非整页写入还会触发读-改-写，"
            "同页其它字节存在覆盖窗口。确认继续？")
            .arg(formatAddress(snapshotAddress_))
            .arg(editedBytes_.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirm != QMessageBox::Yes)
    {
        return;
    }

    // Only commit the modified segment to avoid counting a full-page write-back of unchanged data as a write.
    qsizetype firstDiff = 0;
    while (firstDiff < editedBytes_.size() && editedBytes_[firstDiff] == originalBytes_[firstDiff])
    {
        ++firstDiff;
    }
    qsizetype lastDiff = editedBytes_.size() - 1;
    while (lastDiff > firstDiff && editedBytes_[lastDiff] == originalBytes_[lastDiff])
    {
        --lastDiff;
    }
    const QByteArray kPayload = editedBytes_.mid(firstDiff, lastDiff - firstDiff + 1);
    const std::uint64_t kTargetAddress =
        snapshotAddress_ + static_cast<std::uint64_t>(firstDiff);

    ksword::memory_backend::AccessOutcome outcome =
        ksword::memory_backend::writePhysical(
            ksword::memory_backend::MemoryAccessBackend::kDdma,
            session_,
            kTargetAddress,
            kPayload,
            false);

    if (outcome.forceRequired)
    {
        const QMessageBox::StandardButton kForceConfirm = QMessageBox::warning(
            this,
            QStringLiteral("DDMA 强制写入"),
            QStringLiteral("驱动要求对本次 DDMA 写入附加强制标志。确认继续？"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kForceConfirm != QMessageBox::Yes)
        {
            if (accessStatusLabel_ != nullptr)
            {
                accessStatusLabel_->setText(QStringLiteral("已取消 DDMA 强制写入。"));
            }
            return;
        }
        outcome = ksword::memory_backend::writePhysical(
            ksword::memory_backend::MemoryAccessBackend::kDdma,
            session_,
            kTargetAddress,
            kPayload,
            true);
    }

    QString statusText;
    if (outcome.ok)
    {
        originalBytes_ = editedBytes_;
        if (accessWriteButton_ != nullptr)
        {
            accessWriteButton_->setEnabled(false);
        }
        statusText = QStringLiteral("DDMA 写入成功，共 %1 字节。").arg(outcome.bytesDone);
        if (outcome.lostUpdateWindow)
        {
            statusText += QStringLiteral(
                " 本次为非整页写入，驱动做了读-改-写，同页其它字节存在覆盖窗口。");
        }
    }
    else
    {
        statusText = QStringLiteral("DDMA 写入失败：%1").arg(outcome.failureText);
        QMessageBox::warning(this, QStringLiteral("DDMA"), outcome.failureText);
    }
    if (outcome.scratchDirty)
    {
        statusText += QStringLiteral(
            " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区，请立即检查 LBA %1 起的内容。")
            .arg(session_.scratchLba);
    }
    if (accessStatusLabel_ != nullptr)
    {
        accessStatusLabel_->setText(statusText);
    }
}

void DdmaPage::compareBackendsFromUi()
{
    if (compareAddressEdit_ == nullptr || compareTable_ == nullptr)
    {
        return;
    }

    std::uint64_t physicalAddress = 0ULL;
    if (!parseAddressText(compareAddressEdit_->text(), physicalAddress))
    {
        QMessageBox::warning(
            this, QStringLiteral("DDMA"), QStringLiteral("物理地址解析失败，请填写 0x 十六进制地址。"));
        return;
    }
    // Verify: Fixed to one full page; only two backends reading the same segment are comparable.
    const std::uint64_t kPageBase =
        physicalAddress & ~static_cast<std::uint64_t>(KSWORD_ARK_DDMA_TRANSFER_BYTES - 1UL);

    compareTable_->setRowCount(0);
    if (compareResultLabel_ != nullptr)
    {
        compareResultLabel_->setText(QStringLiteral("正在复核..."));
    }

    const ksword::memory_backend::AccessOutcome kStandardOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::kStandardDriver,
            session_,
            kPageBase,
            KSWORD_ARK_DDMA_TRANSFER_BYTES);
    const ksword::memory_backend::AccessOutcome kDdmaOutcome =
        ksword::memory_backend::readPhysical(
            ksword::memory_backend::MemoryAccessBackend::kDdma,
            session_,
            kPageBase,
            KSWORD_ARK_DDMA_TRANSFER_BYTES);

    if (!kStandardOutcome.ok || !kDdmaOutcome.ok)
    {
        // If one side fails, we cannot conclude 'both match' or 'both mismatch'; we can only state truthfully which side failed to read.
        const QString kDetail = !kStandardOutcome.ok
            ? QStringLiteral("标准通道读取失败：%1").arg(kStandardOutcome.failureText)
            : QStringLiteral("DDMA 读取失败：%1").arg(kDdmaOutcome.failureText);
        if (compareResultLabel_ != nullptr)
        {
            compareResultLabel_->setText(
                QStringLiteral("无法比对，%1").arg(kDetail));
            compareResultLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }
        return;
    }

    const qsizetype kCompareLength =
        std::min<qsizetype>(kStandardOutcome.data.size(), kDdmaOutcome.data.size());
    qsizetype diffCount = 0;
    int shownRows = 0;
    for (qsizetype index = 0; index < kCompareLength; ++index)
    {
        if (kStandardOutcome.data[index] == kDdmaOutcome.data[index])
        {
            continue;
        }
        ++diffCount;
        if (shownRows >= kCompareSampleRows)
        {
            continue;
        }
        const int kRow = compareTable_->rowCount();
        compareTable_->insertRow(kRow);
        compareTable_->setItem(kRow, 0,
            new QTableWidgetItem(formatAddress(kPageBase + static_cast<std::uint64_t>(index))));
        compareTable_->setItem(kRow, 1, new QTableWidgetItem(
            QStringLiteral("%1").arg(
                static_cast<std::uint8_t>(kStandardOutcome.data[index]), 2, 16, QChar('0')).toUpper()));
        compareTable_->setItem(kRow, 2, new QTableWidgetItem(
            QStringLiteral("%1").arg(
                static_cast<std::uint8_t>(kDdmaOutcome.data[index]), 2, 16, QChar('0')).toUpper()));
        ++shownRows;
    }
    compareTable_->resizeColumnsToContents();

    if (compareResultLabel_ == nullptr)
    {
        return;
    }
    if (diffCount == 0)
    {
        // "Consistency" proves nothing on a degenerate page: if the entire page contains only a single byte, a completely
        // broken DDMA (e.g., moving nothing, leaving the buffer as all zeros) will also match the standard channel
        // byte-by-byte, resulting in a false green status. Since this criterion itself is used to determine DDMA path
        // validity, one must first rule out "no meaningful content read on either side" before using it as evidence.
        bool uniformPage = true;
        for (qsizetype index = 1; index < kCompareLength; ++index)
        {
            if (kStandardOutcome.data[index] != kStandardOutcome.data[0])
            {
                uniformPage = false;
                break;
            }
        }
        if (kCompareLength > 0 && uniformPage)
        {
            compareResultLabel_->setText(QStringLiteral("物理页 %1：整页 %2 字节都是同一个值 0x%3，两个后端一致不构成 DDMA 通路成立的证据——什么都没搬过来的实现也会得到同样的结果。请换一张内容有区分度的页再比对，例如某个已加载模块 PE 头所在的物理页。")
                .arg(formatAddress(kPageBase))
                .arg(kCompareLength)
                .arg(static_cast<std::uint8_t>(kStandardOutcome.data[0]), 2, 16, QChar('0')));
            compareResultLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
        }
        else
        {
            compareResultLabel_->setText(QStringLiteral(
                "物理页 %1：两个后端读到的 %2 字节完全一致，没有观察到重定向迹象。")
                .arg(formatAddress(kPageBase))
                .arg(kCompareLength));
            compareResultLabel_->setStyleSheet(
                QStringLiteral("color:%1;").arg(ksword_theme::successHex()));
        }
    }
    else
    {
        compareResultLabel_->setText(QStringLiteral(
            "物理页 %1：共 %2 字节中有 %3 字节不一致（表中最多展示 %4 条）。"
            "标准通道受 SLAT 约束，DDMA 不受约束，这种差异通常意味着该页被上层虚拟化重定向或隐藏。")
            .arg(formatAddress(kPageBase))
            .arg(kCompareLength)
            .arg(diffCount)
            .arg(kCompareSampleRows));
        compareResultLabel_->setStyleSheet(
            QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
    }
}

bool DdmaPage::parseAddressText(const QString& text, std::uint64_t& valueOut)
{
    // Physical addresses: interpreted as hexadecimal if no prefix is provided. The prompt on this page displays '0x1000' and echoes
    // with '0x'; if input is interpreted as decimal, the user would access a different physical page without receiving any warning.
    valueOut = 0ULL;
    const auto kParsed = ksword::evidence::parseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::kHexadecimal);
    if (!kParsed.ok)
    {
        return false;
    }
    valueOut = kParsed.value;
    return true;
}

bool DdmaPage::parseSectorNumberText(const QString& text, std::uint64_t& valueOut)
{
    // Sector LBA is a **count**, not an address: it is the sector index starting from 0. Partition tables, disk management
    // tools, and the hints on this page (e.g., "0x100000" or "1048576") are all read as decimal numbers. Therefore, the
    // default must remain decimal; switching to hexadecimal alongside addresses would cause an already-entered LBA to
    // point to a different sector upon the next opening. An incorrect LBA results in overwriting data elsewhere.
    valueOut = 0ULL;
    const auto kParsed = ksword::evidence::parseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::kDecimal);
    if (!kParsed.ok)
    {
        return false;
    }
    valueOut = kParsed.value;
    return true;
}

QString DdmaPage::formatAddress(const std::uint64_t address)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
        .toUpper()
        .replace(QStringLiteral("0X"), QStringLiteral("0x"));
}

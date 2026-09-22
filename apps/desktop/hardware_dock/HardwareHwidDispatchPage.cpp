#include "HardwareHwidDispatchPage.h"
#include "../ui/VisibleTableWidget.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../Theme.h"
#include "../ui/CodeEditorWidget.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QGridLayout>
#include <QGroupBox>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPixmap>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVariant>
#include <QVBoxLayout>

#include <algorithm>
#include <cwchar>

namespace
{
    // copyQStringToWide：
    // - Input: Qt string, fixed-width character buffer, and capacity.
    // - Processing: Truncate copy and force NUL termination.
    // - Returns: Nothing.
    void copyQStringToWide(const QString& text, wchar_t* destination, const std::size_t destinationChars)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }

        std::fill(destination, destination + destinationChars, L'\0');
        const std::wstring kWideText = text.trimmed().toStdWString();
        const std::size_t kCopyChars = std::min(destinationChars - 1U, kWideText.size());
        if (kCopyChars > 0U)
        {
            std::wmemcpy(destination, kWideText.c_str(), kCopyChars);
        }
        destination[kCopyChars] = L'\0';
    }

    // fixedWideToQString：
    // - Input: Shared protocol fixed-width character array;
    // - Processing: Convert NUL-terminated string to QString.
    // - Returns: Qt string.
    QString fixedWideToQString(const wchar_t* text)
    {
        return text != nullptr ? QString::fromWCharArray(text) : QString();
    }

    // ntStatusText：
    // - Input: NTSTATUS value;
    // - Processing: Fixed 8-digit hexadecimal display.
    // - Return: e.g., 0xC0000001.
    QString ntStatusText(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    // addressText：
    // - Input: 64-bit address;
    // - Handling: Display a hyphen for 0, otherwise display a 16-bit hexadecimal value;
    // - Returns: Interface address text.
    QString addressText(const unsigned long long address)
    {
        if (address == 0ULL)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(address), 16, 16, QChar('0'))
            .toUpper();
    }

    // createReadOnlyItem：
    // - Input: Cell text;
    // - Processing: Create a read-only table item;
    // - Return: An item managed by QTableWidget for its lifecycle.
    QTableWidgetItem* createReadOnlyItem(const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // targetNameFromFlag：
    // - Input: KSWORD_ARK_HWID_DISPATCH_TARGET_*;
    // - Processing: Convert to page title.
    // - Returns: The target name.
    QString targetNameFromFlag(const unsigned long targetFlag)
    {
        switch (targetFlag)
        {
        case KSWORD_ARK_HWID_DISPATCH_TARGET_DISK:
            return QStringLiteral("磁盘序列号");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR:
            return QStringLiteral("分区/GPT GUID");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR:
            return QStringLiteral("卷唯一标识");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA:
            return QStringLiteral("NVIDIA GPU");
        case KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY:
            return QStringLiteral("NSI/ARP");
        default:
            return QStringLiteral("未知目标");
        }
    }
}

HardwareHwidDispatchPage::HardwareHwidDispatchPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    updatePlanPreview();
}

void HardwareHwidDispatchPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    showBlueScreenWarningOnce();
    refreshStatus();
}

void HardwareHwidDispatchPage::initializeUi()
{
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("HWID Dispatch 派遣函数"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(ksword_theme::textPrimaryHex()));
    rootLayout_->addWidget(titleLabel, 0);

    statusLabel_ = new QLabel(QStringLiteral("状态：尚未查询驱动。"), this);
    statusLabel_->setStyleSheet(QStringLiteral("font-weight:600;color:%1;").arg(ksword_theme::kPrimaryBlueHex));
    rootLayout_->addWidget(statusLabel_, 0);

    // Risk notice changed to permanent text: A confirmation dialog still appears before actual dispatch; no
    // longer requires pre-checking a box (avoids redundant steps and prevents errors from missed checks).
    auto* riskNoticeLabel = new QLabel(
        QStringLiteral("注意：启用/卸载派遣钩子可能导致蓝屏，请先保存工作并准备好恢复方案。"),
        this);
    riskNoticeLabel->setWordWrap(true);
    riskNoticeLabel->setStyleSheet(QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
    rootLayout_->addWidget(riskNoticeLabel, 0);

    QGroupBox* targetGroup = new QGroupBox(QStringLiteral("Dispatch 目标驱动"), this);
    QGridLayout* targetLayout = new QGridLayout(targetGroup);
    diskCheck_ = new QCheckBox(QStringLiteral("\\Driver\\Disk - 磁盘查询派遣"), targetGroup);
    partMgrCheck_ = new QCheckBox(QStringLiteral("\\Driver\\partmgr - 分区信息派遣"), targetGroup);
    mountMgrCheck_ = new QCheckBox(QStringLiteral("\\Driver\\mountmgr - 卷唯一标识派遣"), targetGroup);
    nvidiaCheck_ = new QCheckBox(QStringLiteral("\\Driver\\nvlddmkm - NVIDIA GPU 派遣"), targetGroup);
    nsiProxyCheck_ = new QCheckBox(QStringLiteral("\\Driver\\nsiproxy - NSI/ARP 派遣"), targetGroup);
    diskCheck_->setChecked(true);
    partMgrCheck_->setChecked(true);
    mountMgrCheck_->setChecked(true);
    targetLayout->addWidget(diskCheck_, 0, 0);
    targetLayout->addWidget(partMgrCheck_, 0, 1);
    targetLayout->addWidget(mountMgrCheck_, 1, 0);
    targetLayout->addWidget(nvidiaCheck_, 1, 1);
    targetLayout->addWidget(nsiProxyCheck_, 2, 0);
    rootLayout_->addWidget(targetGroup, 0);

    QGroupBox* profileGroup = new QGroupBox(QStringLiteral("派遣函数方案参数"), this);
    QGridLayout* profileLayout = new QGridLayout(profileGroup);
    diskModeCombo_ = new QComboBox(profileGroup);
    diskModeCombo_->addItem(
        QStringLiteral("自定义序列号/产品/固件"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM)));
    diskModeCombo_->addItem(
        QStringLiteral("随机化序列号"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM)));
    diskModeCombo_->addItem(
        QStringLiteral("清空序列号"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_DISK_MODE_NULL)));
    macModeCombo_ = new QComboBox(profileGroup);
    macModeCombo_->addItem(
        QStringLiteral("随机化物理 MAC"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_MAC_MODE_RANDOM)));
    macModeCombo_->addItem(
        QStringLiteral("自定义物理 MAC"),
        QVariant::fromValue(static_cast<qulonglong>(KSWORD_ARK_HWID_DISPATCH_MAC_MODE_CUSTOM)));
    macModeCombo_->setToolTip(QStringLiteral("当前版本不会修改网卡 MAC 地址。"));
    diskSerialEdit_ = new QLineEdit(profileGroup);
    diskProductEdit_ = new QLineEdit(profileGroup);
    diskRevisionEdit_ = new QLineEdit(profileGroup);
    gpuSerialEdit_ = new QLineEdit(profileGroup);
    permanentMacEdit_ = new QLineEdit(profileGroup);
    currentMacEdit_ = new QLineEdit(profileGroup);
    permanentMacEdit_->setToolTip(QStringLiteral("保留设置；当前版本不会修改此地址。"));
    currentMacEdit_->setToolTip(QStringLiteral("保留设置；当前版本不会修改此地址。"));
    diskGuidCheck_ = new QCheckBox(QStringLiteral("随机化 GPT GUID 查询结果"), profileGroup);
    volumeCleanCheck_ = new QCheckBox(QStringLiteral("清理 MountMgr 卷唯一标识查询结果"), profileGroup);
    arpCleanCheck_ = new QCheckBox(QStringLiteral("清理 ARP Table 查询结果"), profileGroup);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘模式"), profileGroup), 0, 0);
    profileLayout->addWidget(diskModeCombo_, 0, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘序列号"), profileGroup), 1, 0);
    profileLayout->addWidget(diskSerialEdit_, 1, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘产品名"), profileGroup), 2, 0);
    profileLayout->addWidget(diskProductEdit_, 2, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("磁盘固件值"), profileGroup), 3, 0);
    profileLayout->addWidget(diskRevisionEdit_, 3, 1);
    profileLayout->addWidget(new QLabel(QStringLiteral("GPU 序列号"), profileGroup), 0, 2);
    profileLayout->addWidget(gpuSerialEdit_, 0, 3);
    profileLayout->addWidget(new QLabel(QStringLiteral("MAC 模式(预留)"), profileGroup), 1, 2);
    profileLayout->addWidget(macModeCombo_, 1, 3);
    profileLayout->addWidget(new QLabel(QStringLiteral("永久 MAC"), profileGroup), 2, 2);
    profileLayout->addWidget(permanentMacEdit_, 2, 3);
    profileLayout->addWidget(new QLabel(QStringLiteral("当前 MAC"), profileGroup), 3, 2);
    profileLayout->addWidget(currentMacEdit_, 3, 3);
    profileLayout->addWidget(diskGuidCheck_, 4, 0, 1, 2);
    profileLayout->addWidget(volumeCleanCheck_, 4, 2, 1, 2);
    profileLayout->addWidget(arpCleanCheck_, 5, 0, 1, 2);
    rootLayout_->addWidget(profileGroup, 0);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    refreshButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("查询状态"), this);
    refreshButton_->setToolTip(QStringLiteral("查询 KswordARK 驱动当前保存的 HWID Dispatch hook 状态。"));
    dryRunButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_details.svg")), QStringLiteral("干跑验证"), this);
    dryRunButton_->setToolTip(QStringLiteral("只验证目标驱动对象是否可引用，不实际替换派遣函数。"));
    enableButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_resume.svg")), QStringLiteral("启用派遣函数"), this);
    // Scope boundary merged into this button: it is the only action that truly alters system behavior, so placing the explanation here maximizes the chance it will be read.
    enableButton_->setToolTip(QStringLiteral("按所选目标替换 IRP_MJ_DEVICE_CONTROL 派遣函数；高风险，可能蓝屏。只改变所选设备的查询结果，不直接写入物理内存、固件或磁盘；网络选项目前仅影响 NSI/ARP 查询结果。"));
    disableButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("卸载全部派遣函数"), this);
    disableButton_->setToolTip(QStringLiteral("恢复本页安装过的全部 Dispatch hook；高风险，可能蓝屏。"));
    copyPlanButton_ = new QPushButton(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制计划"), this);
    copyPlanButton_->setToolTip(QStringLiteral("复制当前目标、参数和风险说明，便于留档或复核。"));
    buttonLayout->addWidget(refreshButton_);
    buttonLayout->addWidget(dryRunButton_);
    buttonLayout->addWidget(enableButton_);
    buttonLayout->addWidget(disableButton_);
    buttonLayout->addWidget(copyPlanButton_);
    buttonLayout->addStretch(1);
    rootLayout_->addLayout(buttonLayout, 0);

    statusTable_ = new ks::ui::VisibleTableWidget(this);
    statusTable_->setColumnCount(7);
    statusTable_->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("目标"),
        QStringLiteral("驱动对象"),
        QStringLiteral("Active"),
        QStringLiteral("LastStatus"),
        QStringLiteral("DriverObject"),
        QStringLiteral("OriginalDispatch"),
        QStringLiteral("CurrentDispatch")
        });
    statusTable_->verticalHeader()->setVisible(false);
    statusTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    statusTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    statusTable_->setAlternatingRowColors(true);
    statusTable_->horizontalHeader()->setStretchLastSection(true);
    rootLayout_->addWidget(statusTable_, 1);

    QWidget* editorPanel = new QWidget(this);
    QHBoxLayout* editorLayout = new QHBoxLayout(editorPanel);
    editorLayout->setContentsMargins(0, 0, 0, 0);
    editorLayout->setSpacing(8);
    planEditor_ = new CodeEditorWidget(editorPanel);
    planEditor_->setReadOnly(true);
    editorLayout->addWidget(planEditor_, 1);
    rootLayout_->addWidget(editorPanel, 1);
}

void HardwareHwidDispatchPage::initializeConnections()
{
    const QList<QObject*> kPlanSources{
        diskCheck_, partMgrCheck_, mountMgrCheck_, nvidiaCheck_, nsiProxyCheck_,
        diskGuidCheck_, volumeCleanCheck_, arpCleanCheck_,
        diskModeCombo_, macModeCombo_,
        diskSerialEdit_, diskProductEdit_, diskRevisionEdit_,
        gpuSerialEdit_, permanentMacEdit_, currentMacEdit_
    };
    for (QObject* sourceObject : kPlanSources)
    {
        if (auto* checkBox = qobject_cast<QCheckBox*>(sourceObject))
        {
            connect(checkBox, &QCheckBox::toggled, this, [this]() { updatePlanPreview(); });
        }
        else if (auto* comboBox = qobject_cast<QComboBox*>(sourceObject))
        {
            connect(comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { updatePlanPreview(); });
        }
        else if (auto* lineEdit = qobject_cast<QLineEdit*>(sourceObject))
        {
            connect(lineEdit, &QLineEdit::textChanged, this, [this](const QString&) { updatePlanPreview(); });
        }
    }

    connect(refreshButton_, &QPushButton::clicked, this, [this]() { refreshStatus(); });
    connect(dryRunButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE, true);
    });
    connect(enableButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(KSWORD_ARK_HWID_DISPATCH_ACTION_ENABLE, false);
    });
    connect(disableButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(KSWORD_ARK_HWID_DISPATCH_ACTION_DISABLE_ALL, false);
    });
    connect(copyPlanButton_, &QPushButton::clicked, this, [this]() {
        if (QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(buildPlanText());
        }
    });
}

void HardwareHwidDispatchPage::showBlueScreenWarningOnce()
{
    if (warningShown_)
    {
        return;
    }
    warningShown_ = true;
    QMessageBox::warning(
        this,
        QStringLiteral("蓝屏风险提示"),
        QStringLiteral("本页会接触内核驱动派遣函数 MajorFunction。启用或卸载 Dispatch hook 可能立即蓝屏，继续前请确认已保存工作、准备好 WinDbg 或恢复方案。"));
}

void HardwareHwidDispatchPage::refreshStatus()
{
    const ksword::ark::DriverClient kClient;
    applyResponseToUi(kClient.queryHwidDispatchState());
}

void HardwareHwidDispatchPage::sendControlRequest(const unsigned long action, const bool dryRun)
{
    if (!dryRun)
    {
        const QMessageBox::StandardButton kAnswer = QMessageBox::warning(
            this,
            QStringLiteral("二次确认"),
            QStringLiteral("即将修改或恢复目标驱动的 IRP_MJ_DEVICE_CONTROL 派遣函数，存在蓝屏风险。是否继续？"),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kAnswer != QMessageBox::Yes)
        {
            appendLogLine(QStringLiteral("[%1] 用户取消真实 Dispatch 操作。")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
            return;
        }
    }

    const ksword::ark::DriverClient kClient;
    applyResponseToUi(kClient.controlHwidDispatch(buildControlRequest(action, dryRun)));
}

KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST HardwareHwidDispatchPage::buildControlRequest(
    const unsigned long action,
    const bool dryRun) const
{
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    request.action = action;
    request.requestFlags = KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_UI_CONFIRMED;
    if (dryRun)
    {
        request.requestFlags |= KSWORD_ARK_HWID_DISPATCH_REQUEST_FLAG_DRY_RUN;
    }
    request.profile.size = sizeof(request.profile);
    request.profile.version = KSWORD_ARK_HWID_DISPATCH_PROTOCOL_VERSION;
    request.profile.targetFlags = selectedTargetFlags();
    request.profile.diskMode = static_cast<unsigned long>(diskModeCombo_->currentData().toULongLong());
    request.profile.macMode = static_cast<unsigned long>(macModeCombo_->currentData().toULongLong());
    request.profile.behaviorFlags =
        (diskGuidCheck_->isChecked() ? KSWORD_ARK_HWID_DISPATCH_FLAG_DISK_GUID_RANDOM : 0UL) |
        (volumeCleanCheck_->isChecked() ? KSWORD_ARK_HWID_DISPATCH_FLAG_VOLUME_ID_CLEAN : 0UL) |
        (arpCleanCheck_->isChecked() ? KSWORD_ARK_HWID_DISPATCH_FLAG_ARP_TABLE_CLEAN : 0UL);
    copyQStringToWide(diskSerialEdit_->text(), request.profile.diskSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(diskProductEdit_->text(), request.profile.diskProduct, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(diskRevisionEdit_->text(), request.profile.diskRevision, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(gpuSerialEdit_->text(), request.profile.gpuSerial, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(permanentMacEdit_->text(), request.profile.permanentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    copyQStringToWide(currentMacEdit_->text(), request.profile.currentMac, KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS);
    return request;
}

unsigned long HardwareHwidDispatchPage::selectedTargetFlags() const
{
    unsigned long flags = 0UL;
    flags |= (diskCheck_ != nullptr && diskCheck_->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_DISK : 0UL;
    flags |= (partMgrCheck_ != nullptr && partMgrCheck_->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR : 0UL;
    flags |= (mountMgrCheck_ != nullptr && mountMgrCheck_->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR : 0UL;
    flags |= (nvidiaCheck_ != nullptr && nvidiaCheck_->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA : 0UL;
    flags |= (nsiProxyCheck_ != nullptr && nsiProxyCheck_->isChecked()) ? KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY : 0UL;
    return flags;
}

QString HardwareHwidDispatchPage::buildPlanText() const
{
    QStringList lines;
    lines << QStringLiteral("HWID Dispatch 派遣函数接入计划");
    lines << QStringLiteral("来源: https://github.com/FiYHer/EASY-HWID-SPOOFER");
    lines << QStringLiteral("保留原理: 修改驱动程序的派遣函数(兼容性强)");
    lines << QStringLiteral("排除原理: 定位物理内存直接修改硬件数据(兼容性弱)");
    lines << QStringLiteral("网络范围: 仅 NSI/ARP 查询输出清理；NDIS 私有块 MAC 改写不接入。");
    lines << QStringLiteral("");
    lines << QStringLiteral("目标 flags: 0x%1").arg(selectedTargetFlags(), 8, 16, QChar('0')).toUpper();
    lines << QStringLiteral("- \\Driver\\Disk: %1").arg(diskCheck_->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过"));
    lines << QStringLiteral("- \\Driver\\partmgr: %1").arg(partMgrCheck_->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过"));
    lines << QStringLiteral("- \\Driver\\mountmgr: %1").arg(mountMgrCheck_->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过"));
    lines << QStringLiteral("- \\Driver\\nvlddmkm: %1").arg(nvidiaCheck_->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过"));
    lines << QStringLiteral("- \\Driver\\nsiproxy: %1").arg(nsiProxyCheck_->isChecked() ? QStringLiteral("启用") : QStringLiteral("跳过"));
    lines << QStringLiteral("");
    lines << QStringLiteral("磁盘模式: %1").arg(diskModeCombo_->currentText());
    lines << QStringLiteral("磁盘序列号: %1").arg(diskSerialEdit_->text().trimmed());
    lines << QStringLiteral("磁盘产品名: %1").arg(diskProductEdit_->text().trimmed());
    lines << QStringLiteral("磁盘固件值: %1").arg(diskRevisionEdit_->text().trimmed());
    lines << QStringLiteral("GPU 序列号: %1").arg(gpuSerialEdit_->text().trimmed());
    lines << QStringLiteral("MAC 模式: %1").arg(macModeCombo_->currentText());
    lines << QStringLiteral("永久 MAC: %1").arg(permanentMacEdit_->text().trimmed());
    lines << QStringLiteral("当前 MAC: %1").arg(currentMacEdit_->text().trimmed());
    lines << QStringLiteral("MAC 字段说明: 当前仅随协议下发并作为预留，不触发 NDIS 私有链表扫描。");
    lines << QStringLiteral("GPT GUID 随机化: %1").arg(diskGuidCheck_->isChecked() ? QStringLiteral("是") : QStringLiteral("否"));
    lines << QStringLiteral("卷唯一标识清理: %1").arg(volumeCleanCheck_->isChecked() ? QStringLiteral("是") : QStringLiteral("否"));
    lines << QStringLiteral("ARP Table 清理: %1").arg(arpCleanCheck_->isChecked() ? QStringLiteral("是") : QStringLiteral("否"));
    lines << QStringLiteral("");
    lines << QStringLiteral("风险: 启用/卸载 Dispatch hook 可能蓝屏；页面真实操作前仍需二次确认。");
    return lines.join(QStringLiteral("\n"));
}

void HardwareHwidDispatchPage::updatePlanPreview()
{
    if (planEditor_ != nullptr)
    {
        planEditor_->setText(buildPlanText());
    }
}

void HardwareHwidDispatchPage::applyResponseToUi(const ksword::ark::HwidDispatchResult& result)
{
    if (statusLabel_ != nullptr)
    {
        statusLabel_->setText(result.unsupported
            ? QStringLiteral("状态：当前驱动未注册 HWID Dispatch IOCTL。")
            : QStringLiteral("状态：%1，Win32=%2，NT=%3，Active=0x%4")
                .arg(result.io.ok ? QStringLiteral("IOCTL 成功") : QStringLiteral("IOCTL 失败"))
                .arg(result.io.win32Error)
                .arg(ntStatusText(result.response.lastStatus))
                .arg(result.response.activeTargetFlags, 8, 16, QChar('0')).toUpper());
    }

    if (statusTable_ != nullptr)
    {
        statusTable_->setRowCount(KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT);
        for (int rowIndex = 0; rowIndex < static_cast<int>(KSWORD_ARK_HWID_DISPATCH_ENTRY_COUNT); ++rowIndex)
        {
            const KSWORD_ARK_HWID_DISPATCH_ENTRY& entry = result.response.entries[rowIndex];
            statusTable_->setItem(rowIndex, 0, createReadOnlyItem(targetNameFromFlag(entry.targetFlag)));
            statusTable_->setItem(rowIndex, 1, createReadOnlyItem(fixedWideToQString(entry.driverName)));
            statusTable_->setItem(rowIndex, 2, createReadOnlyItem(entry.active != 0UL ? QStringLiteral("是") : QStringLiteral("否")));
            statusTable_->setItem(rowIndex, 3, createReadOnlyItem(ntStatusText(entry.lastStatus)));
            statusTable_->setItem(rowIndex, 4, createReadOnlyItem(addressText(entry.driverObjectAddress)));
            statusTable_->setItem(rowIndex, 5, createReadOnlyItem(addressText(entry.originalDispatchAddress)));
            statusTable_->setItem(rowIndex, 6, createReadOnlyItem(addressText(entry.currentDispatchAddress)));
        }
        statusTable_->resizeColumnsToContents();
    }

    appendLogLine(QStringLiteral("[%1] %2")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
        .arg(QString::fromStdString(result.io.message)));
}

void HardwareHwidDispatchPage::appendLogLine(const QString& lineText)
{
    if (planEditor_ == nullptr)
    {
        return;
    }

    const QString kCurrentText = planEditor_->text();
    const QString kNextText = kCurrentText.contains(QStringLiteral("\n\n--- 日志 ---\n"))
        ? kCurrentText + QStringLiteral("\n") + lineText
        : buildPlanText() + QStringLiteral("\n\n--- 日志 ---\n") + lineText;
    planEditor_->setText(kNextText);
}

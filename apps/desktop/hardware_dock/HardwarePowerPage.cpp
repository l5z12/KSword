#include "HardwarePowerPage.h"

#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"
#include "../ui/VisibleTableWidget.h"

#include <QAbstractItemView>
#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <PowrProf.h>

#pragma comment(lib, "PowrProf.lib")

namespace
{
    // powerText: Read the power page context key and retain the Chinese source text as a fallback.
    QString powerText(const QString& key, const QString& sourceText)
    {
        return ks::i18n::contextText(key, sourceText);
    }

    // ntStatusText: Displays R0 NTSTATUS as a fixed 8-digit hexadecimal value.
    QString ntStatusText(const long status)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<quint32>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    // rawMsrText: Formats a 64-bit MSR as a fixed-width hexadecimal string.
    QString rawMsrText(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    // addSnapshotRow: Add a non-editable summary row to the two-column table.
    void addSnapshotRow(
        QTableWidget* table,
        const QString& name,
        const QString& value)
    {
        if (table == nullptr)
        {
            return;
        }
        const int kRow = table->rowCount();
        table->insertRow(kRow);
        auto* nameItem = new QTableWidgetItem(name);
        auto* valueItem = new QTableWidgetItem(value);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);
        table->setItem(kRow, 0, nameItem);
        table->setItem(kRow, 1, valueItem);
    }

    // powerSchemeFriendlyName: reads the localized name of the Windows power scheme.
    QString powerSchemeFriendlyName(const GUID& schemeGuid)
    {
        DWORD nameBytes = 0UL;
        DWORD error = ::PowerReadFriendlyName(
            nullptr,
            &schemeGuid,
            nullptr,
            nullptr,
            nullptr,
            &nameBytes);
        if (error != ERROR_SUCCESS || nameBytes < sizeof(wchar_t))
        {
            return QString();
        }

        std::vector<UCHAR> nameBuffer(nameBytes, 0U);
        error = ::PowerReadFriendlyName(
            nullptr,
            &schemeGuid,
            nullptr,
            nullptr,
            nameBuffer.data(),
            &nameBytes);
        if (error != ERROR_SUCCESS)
        {
            return QString();
        }
        return QString::fromWCharArray(
            reinterpret_cast<const wchar_t*>(nameBuffer.data())).trimmed();
    }

    // guidBytes: copies the GUID into a QVariant-compatible, owning QByteArray.
    QByteArray guidBytes(const GUID& guid)
    {
        return QByteArray(
            reinterpret_cast<const char*>(&guid),
            static_cast<int>(sizeof(guid)));
    }

    // guidFromBytes: Strictly validates length before reconstructing the GUID.
    bool guidFromBytes(const QByteArray& bytes, GUID* guidOut)
    {
        if (guidOut == nullptr || bytes.size() != static_cast<int>(sizeof(GUID)))
        {
            return false;
        }
        std::memcpy(guidOut, bytes.constData(), sizeof(*guidOut));
        return true;
    }

    // cpuPowerFailureReasonText: Convert R0 failureReason to an actionable diagnostic including request values.
    QString cpuPowerFailureReasonText(
        const unsigned long failureReason,
        const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request,
        const KSWORD_ARK_CPU_POWER_RESPONSE& snapshot)
    {
        switch (failureReason)
        {
        case KSWORD_ARK_CPU_POWER_FAILURE_REQUEST_HEADER:
            return powerText(
                QStringLiteral("hardware.power.error.reason.request_header"),
                QStringLiteral("请求头、操作标志或 UI 确认标志无效。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_SAFETY_POLICY:
            return powerText(
                QStringLiteral("hardware.power.error.reason.safety_policy"),
                QStringLiteral("统一 R0 安全策略拒绝了本次 CPU 电源修改。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_VENDOR:
            return powerText(
                QStringLiteral("hardware.power.error.reason.vendor"),
                QStringLiteral("当前 CPU 厂商不支持此 R0 调节路径。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_POWER_CAPABILITY:
            return powerText(
                QStringLiteral("hardware.power.error.reason.power_capability"),
                QStringLiteral("RAPL 功耗限制不可写、字段不可读，或已被 BIOS/固件锁定。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_POWER_ABSOLUTE_RANGE:
            return powerText(
                QStringLiteral("hardware.power.error.reason.power_absolute"),
                QStringLiteral("PL1=%1 W、PL2=%2 W 必须大于 0 且均不超过 1000 W。"))
                .arg(request.pl1Milliwatts / 1000.0, 0, 'f', 3)
                .arg(request.pl2Milliwatts / 1000.0, 0, 'f', 3);
        case KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MAXIMUM:
            return powerText(
                QStringLiteral("hardware.power.error.reason.power_maximum"),
                QStringLiteral("PL1=%1 W、PL2=%2 W 超过 CPU 报告的平台上限 %3 W。"))
                .arg(request.pl1Milliwatts / 1000.0, 0, 'f', 3)
                .arg(request.pl2Milliwatts / 1000.0, 0, 'f', 3)
                .arg(snapshot.packageMaximumPowerMilliwatts / 1000.0, 0, 'f', 3);
        case KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MINIMUM:
            return powerText(
                QStringLiteral("hardware.power.error.reason.power_minimum"),
                QStringLiteral("PL1=%1 W、PL2=%2 W 低于 CPU 报告的平台下限 %3 W。"))
                .arg(request.pl1Milliwatts / 1000.0, 0, 'f', 3)
                .arg(request.pl2Milliwatts / 1000.0, 0, 'f', 3)
                .arg(snapshot.packageMinimumPowerMilliwatts / 1000.0, 0, 'f', 3);
        case KSWORD_ARK_CPU_POWER_FAILURE_POWER_BOOLEAN:
            return powerText(
                QStringLiteral("hardware.power.error.reason.power_boolean"),
                QStringLiteral("PL1/PL2 enable 或 clamp 字段不是有效布尔值。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_TURBO_CAPABILITY:
            return powerText(
                QStringLiteral("hardware.power.error.reason.turbo"),
                QStringLiteral("CPU 未提供可写的 Intel Turbo 控制字段。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_HWP_CAPABILITY:
            return powerText(
                QStringLiteral("hardware.power.error.reason.hwp_capability"),
                QStringLiteral("HWP 未启用，或 HWP capability/request 字段不可读。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_HWP_ORDER:
            return powerText(
                QStringLiteral("hardware.power.error.reason.hwp_order"),
                QStringLiteral("HWP 最小性能 %1 不能高于最大性能 %2。"))
                .arg(request.hwpMinimumPerformance)
                .arg(request.hwpMaximumPerformance);
        case KSWORD_ARK_CPU_POWER_FAILURE_HWP_DESIRED_RANGE:
            return powerText(
                QStringLiteral("hardware.power.error.reason.hwp_desired"),
                QStringLiteral("HWP 期望性能 %1 必须为 0（自动），或位于最小值 %2 与最大值 %3 之间。"))
                .arg(request.hwpDesiredPerformance)
                .arg(request.hwpMinimumPerformance)
                .arg(request.hwpMaximumPerformance);
        case KSWORD_ARK_CPU_POWER_FAILURE_HWP_PLATFORM_RANGE:
            return powerText(
                QStringLiteral("hardware.power.error.reason.hwp_platform"),
                QStringLiteral("HWP 请求 Min=%1 Max=%2 Desired=%3 超出 CPU 报告的范围 %4 到 %5。"))
                .arg(request.hwpMinimumPerformance)
                .arg(request.hwpMaximumPerformance)
                .arg(request.hwpDesiredPerformance)
                .arg(snapshot.hwpLowestPerformance)
                .arg(snapshot.hwpHighestPerformance);
        case KSWORD_ARK_CPU_POWER_FAILURE_HWP_EPP:
            return powerText(
                QStringLiteral("hardware.power.error.reason.hwp_epp"),
                QStringLiteral("该 CPU 未声明 HWP EPP 能力，EPP 字段不能修改。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_TURBO_RATIO:
            return powerText(
                QStringLiteral("hardware.power.error.reason.turbo_ratio"),
                QStringLiteral("Turbo Ratio 不可编程，寄存器不可读，或倍率不在 1 到 255 之间。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_STALE_SNAPSHOT:
            return powerText(
                QStringLiteral("hardware.power.error.stale"),
                QStringLiteral("设置在提交前已被固件、Windows 或其他工具改变，请刷新后重试。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_PROCESSOR_APPLY:
            return powerText(
                QStringLiteral("hardware.power.error.reason.processor_apply"),
                QStringLiteral("至少一个逻辑处理器的 MSR 写入或回读校验失败。"));
        case KSWORD_ARK_CPU_POWER_FAILURE_PERF_CONTROL:
            return powerText(
                QStringLiteral("hardware.power.error.reason.perf_control"),
                QStringLiteral("请求倍频不可编程、IA32_PERF_CTL 不可读，或倍率不在 1 到 255 之间。"));
        default:
            return powerText(
                QStringLiteral("hardware.power.error.reason.unknown"),
                QStringLiteral("R0 未提供已知失败原因，reason=%1。"))
                .arg(failureReason);
        }
    }

    // validateCpuPowerRequestForUi: Prevent relationship errors that will inevitably be rejected by R0 before showing the confirmation dialog.
    QString validateCpuPowerRequestForUi(
        const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request,
        const KSWORD_ARK_CPU_POWER_RESPONSE& snapshot)
    {
        if ((request.applyFlags &
            KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS) != 0UL)
        {
            if (request.pl1Milliwatts == 0UL ||
                request.pl2Milliwatts == 0UL ||
                request.pl1Milliwatts >
                    KSWORD_ARK_CPU_POWER_ABSOLUTE_MAX_MILLIWATTS ||
                request.pl2Milliwatts >
                    KSWORD_ARK_CPU_POWER_ABSOLUTE_MAX_MILLIWATTS)
            {
                return cpuPowerFailureReasonText(
                    KSWORD_ARK_CPU_POWER_FAILURE_POWER_ABSOLUTE_RANGE,
                    request,
                    snapshot);
            }
            if (snapshot.packageMaximumPowerMilliwatts != 0UL &&
                (request.pl1Milliwatts >
                    snapshot.packageMaximumPowerMilliwatts ||
                 request.pl2Milliwatts >
                    snapshot.packageMaximumPowerMilliwatts))
            {
                return cpuPowerFailureReasonText(
                    KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MAXIMUM,
                    request,
                    snapshot);
            }
            if (snapshot.packageMinimumPowerMilliwatts != 0UL &&
                (request.pl1Milliwatts <
                    snapshot.packageMinimumPowerMilliwatts ||
                 request.pl2Milliwatts <
                    snapshot.packageMinimumPowerMilliwatts))
            {
                return cpuPowerFailureReasonText(
                    KSWORD_ARK_CPU_POWER_FAILURE_POWER_PLATFORM_MINIMUM,
                    request,
                    snapshot);
            }
        }

        if ((request.applyFlags & KSWORD_ARK_CPU_POWER_APPLY_HWP) != 0UL)
        {
            if (request.hwpMinimumPerformance >
                request.hwpMaximumPerformance)
            {
                return cpuPowerFailureReasonText(
                    KSWORD_ARK_CPU_POWER_FAILURE_HWP_ORDER,
                    request,
                    snapshot);
            }
            if (request.hwpDesiredPerformance != 0UL &&
                (request.hwpDesiredPerformance <
                    request.hwpMinimumPerformance ||
                 request.hwpDesiredPerformance >
                    request.hwpMaximumPerformance))
            {
                return cpuPowerFailureReasonText(
                    KSWORD_ARK_CPU_POWER_FAILURE_HWP_DESIRED_RANGE,
                    request,
                    snapshot);
            }
            if ((snapshot.hwpLowestPerformance != 0UL &&
                    request.hwpMinimumPerformance <
                        snapshot.hwpLowestPerformance) ||
                (snapshot.hwpHighestPerformance != 0UL &&
                    (request.hwpMaximumPerformance >
                        snapshot.hwpHighestPerformance ||
                     request.hwpDesiredPerformance >
                        snapshot.hwpHighestPerformance)))
            {
                return cpuPowerFailureReasonText(
                    KSWORD_ARK_CPU_POWER_FAILURE_HWP_PLATFORM_RANGE,
                    request,
                    snapshot);
            }
        }
        return QString();
    }
}

HardwarePowerPage::HardwarePowerPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
}

void HardwarePowerPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!loadedOnce_)
    {
        loadedOnce_ = true;
        refreshAll();
    }
}

void HardwarePowerPage::initializeUi()
{
    auto& language = ks::i18n::LanguageManager::instance();
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(8);

    auto* titleLabel = new QLabel(QStringLiteral("CPU 电源与性能调节"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(ksword_theme::textPrimaryHex()));
    language.bindText(
        titleLabel,
        QStringLiteral("hardware.power.title"),
        QStringLiteral("CPU 电源与性能调节"));
    // Move the adjustment description from the permanent text below the title into the title tooltip, available on hover.
    language.bindToolTip(
        titleLabel,
        QStringLiteral("hardware.power.title.tooltip"),
        QStringLiteral("R0 调节仅写入已探测的 Intel RAPL/HWP/Turbo/请求倍频白名单字段，不绕过 BIOS/微码锁，也不提供任意 MSR 写入。"));
    rootLayout->addWidget(titleLabel, 0);

    statusLabel_ = new QLabel(
        powerText(
            QStringLiteral("hardware.power.status.initial"),
            QStringLiteral("状态：尚未刷新。")),
        this);
    statusLabel_->setWordWrap(true);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-weight:600;color:%1;").arg(ksword_theme::kPrimaryBlueHex));
    rootLayout->addWidget(statusLabel_, 0);

    auto* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    auto* contentWidget = new QWidget(scrollArea);
    auto* contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(8);

    auto* schemeGroup = new QGroupBox(QStringLiteral("Windows 电源方案"), contentWidget);
    language.bindText(
        schemeGroup,
        QStringLiteral("hardware.power.scheme.group"),
        QStringLiteral("Windows 电源方案"));
    auto* schemeLayout = new QGridLayout(schemeGroup);
    auto* schemeLabel = new QLabel(QStringLiteral("当前/目标方案"), schemeGroup);
    language.bindText(
        schemeLabel,
        QStringLiteral("hardware.power.scheme.label"),
        QStringLiteral("当前/目标方案"));
    powerSchemeCombo_ = new QComboBox(schemeGroup);
    applyPowerSchemeButton_ = new QPushButton(QStringLiteral("应用电源方案"), schemeGroup);
    language.bindText(
        applyPowerSchemeButton_,
        QStringLiteral("hardware.power.scheme.apply"),
        QStringLiteral("应用电源方案"));
    refreshAllButton_ = new QPushButton(QStringLiteral("刷新全部"), schemeGroup);
    language.bindText(
        refreshAllButton_,
        QStringLiteral("hardware.power.refresh"),
        QStringLiteral("刷新全部"));
    restoreInitialStateButton_ = new QPushButton(
        QStringLiteral("一键还原首次状态"),
        schemeGroup);
    language.bindText(
        restoreInitialStateButton_,
        QStringLiteral("hardware.power.restore"),
        QStringLiteral("一键还原首次状态"));
    restoreInitialStateButton_->setToolTip(
        QStringLiteral("把功耗墙、倍频、Turbo 等所有设置一键恢复到本页刚打开时的原始状态"));
    schemeLayout->addWidget(schemeLabel, 0, 0);
    schemeLayout->addWidget(powerSchemeCombo_, 0, 1);
    schemeLayout->addWidget(applyPowerSchemeButton_, 0, 2);
    schemeLayout->addWidget(refreshAllButton_, 0, 3);
    schemeLayout->addWidget(restoreInitialStateButton_, 1, 0, 1, 4);
    schemeLayout->setColumnStretch(1, 1);
    contentLayout->addWidget(schemeGroup, 0);

    auto* snapshotGroup = new QGroupBox(QStringLiteral("CPU 能力与当前状态"), contentWidget);
    language.bindText(
        snapshotGroup,
        QStringLiteral("hardware.power.snapshot.group"),
        QStringLiteral("CPU 能力与当前状态"));
    auto* snapshotLayout = new QVBoxLayout(snapshotGroup);
    snapshotTable_ = new ks::ui::VisibleTableWidget(snapshotGroup);
    snapshotTable_->setColumnCount(2);
    snapshotTable_->setHorizontalHeaderLabels({
        powerText(QStringLiteral("hardware.power.table.item"), QStringLiteral("项目")),
        powerText(QStringLiteral("hardware.power.table.value"), QStringLiteral("当前值")) });
    snapshotTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    snapshotTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    snapshotTable_->setAlternatingRowColors(true);
    snapshotTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    snapshotTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    snapshotTable_->verticalHeader()->setVisible(false);
    snapshotTable_->setMinimumHeight(260);
    snapshotLayout->addWidget(snapshotTable_, 1);
    contentLayout->addWidget(snapshotGroup, 1);

    auto* raplGroup = new QGroupBox(QStringLiteral("RAPL 功耗墙（PL1 / PL2）"), contentWidget);
    language.bindText(
        raplGroup,
        QStringLiteral("hardware.power.rapl.group"),
        QStringLiteral("RAPL 功耗墙（PL1 / PL2）"));
    auto* raplLayout = new QGridLayout(raplGroup);
    auto* pl1Label = new QLabel(QStringLiteral("PL1 长时功耗"), raplGroup);
    auto* pl2Label = new QLabel(QStringLiteral("PL2 短时功耗"), raplGroup);
    language.bindText(pl1Label, QStringLiteral("hardware.power.rapl.pl1"), QStringLiteral("PL1 长时功耗"));
    language.bindText(pl2Label, QStringLiteral("hardware.power.rapl.pl2"), QStringLiteral("PL2 短时功耗"));
    pl1Spin_ = new QDoubleSpinBox(raplGroup);
    pl2Spin_ = new QDoubleSpinBox(raplGroup);
    for (QDoubleSpinBox* spin : { pl1Spin_, pl2Spin_ })
    {
        spin->setDecimals(3);
        spin->setRange(0.001, 1000.0);
        spin->setSingleStep(1.0);
        spin->setSuffix(QStringLiteral(" W"));
    }
    pl1EnableCheck_ = new QCheckBox(QStringLiteral("启用 PL1"), raplGroup);
    pl1ClampCheck_ = new QCheckBox(QStringLiteral("允许 PL1 Clamp"), raplGroup);
    pl2EnableCheck_ = new QCheckBox(QStringLiteral("启用 PL2"), raplGroup);
    pl2ClampCheck_ = new QCheckBox(QStringLiteral("允许 PL2 Clamp"), raplGroup);
    language.bindText(pl1EnableCheck_, QStringLiteral("hardware.power.rapl.pl1_enable"), QStringLiteral("启用 PL1"));
    language.bindText(pl1ClampCheck_, QStringLiteral("hardware.power.rapl.pl1_clamp"), QStringLiteral("允许 PL1 Clamp"));
    language.bindText(pl2EnableCheck_, QStringLiteral("hardware.power.rapl.pl2_enable"), QStringLiteral("启用 PL2"));
    language.bindText(pl2ClampCheck_, QStringLiteral("hardware.power.rapl.pl2_clamp"), QStringLiteral("允许 PL2 Clamp"));
    applyPowerLimitsButton_ = new QPushButton(QStringLiteral("应用 PL1 / PL2"), raplGroup);
    raisePowerLimitsButton_ = new QPushButton(QStringLiteral("解除软件功耗墙（平台上限）"), raplGroup);
    language.bindText(applyPowerLimitsButton_, QStringLiteral("hardware.power.rapl.apply"), QStringLiteral("应用 PL1 / PL2"));
    language.bindText(raisePowerLimitsButton_, QStringLiteral("hardware.power.rapl.raise"), QStringLiteral("解除软件功耗墙（平台上限）"));
    // Write boundary and attach to this button: whether values get reset by others is something you should know before clicking.
    applyPowerLimitsButton_->setToolTip(
        QStringLiteral("把上面填写的 PL1（长时）/PL2（短时）功耗上限写入 CPU，单位瓦。MSR lock 置位后本页不会尝试清除；固件、Windows 电源管理或其他调校工具可能随时重写这些值。AMD 型号相关 SMU/PBO 暂不写入。"));
    raisePowerLimitsButton_->setToolTip(
        QStringLiteral("把功耗上限拉到平台允许的最高值，相当于解除软件功耗限制；可能升温降频，请谨慎使用"));
    raplLayout->addWidget(pl1Label, 0, 0);
    raplLayout->addWidget(pl1Spin_, 0, 1);
    raplLayout->addWidget(pl1EnableCheck_, 0, 2);
    raplLayout->addWidget(pl1ClampCheck_, 0, 3);
    raplLayout->addWidget(pl2Label, 1, 0);
    raplLayout->addWidget(pl2Spin_, 1, 1);
    raplLayout->addWidget(pl2EnableCheck_, 1, 2);
    raplLayout->addWidget(pl2ClampCheck_, 1, 3);
    raplLayout->addWidget(applyPowerLimitsButton_, 2, 0, 1, 2);
    raplLayout->addWidget(raisePowerLimitsButton_, 2, 2, 1, 2);
    contentLayout->addWidget(raplGroup, 0);

    auto* turboGroup = new QGroupBox(QStringLiteral("Turbo 与超频倍率"), contentWidget);
    language.bindText(turboGroup, QStringLiteral("hardware.power.turbo.group"), QStringLiteral("Turbo 与超频倍率"));
    auto* turboLayout = new QGridLayout(turboGroup);
    turboEnableCheck_ = new QCheckBox(QStringLiteral("启用 Intel Turbo Boost"), turboGroup);
    language.bindText(turboEnableCheck_, QStringLiteral("hardware.power.turbo.enable"), QStringLiteral("启用 Intel Turbo Boost"));
    applyTurboButton_ = new QPushButton(QStringLiteral("应用 Turbo 开关"), turboGroup);
    language.bindText(applyTurboButton_, QStringLiteral("hardware.power.turbo.apply"), QStringLiteral("应用 Turbo 开关"));
    applyTurboButton_->setToolTip(QStringLiteral("打开或关闭 Intel 睿频加速（Turbo Boost）"));
    auto* ratioLabel = new QLabel(QStringLiteral("全档位 Turbo Ratio"), turboGroup);
    language.bindText(ratioLabel, QStringLiteral("hardware.power.turbo.ratio"), QStringLiteral("全档位 Turbo Ratio"));
    turboRatioSpin_ = new QSpinBox(turboGroup);
    turboRatioSpin_->setRange(1, 255);
    turboRatioSpin_->setSuffix(QStringLiteral(" x"));
    applyTurboRatioButton_ = new QPushButton(QStringLiteral("应用超频倍率"), turboGroup);
    language.bindText(applyTurboRatioButton_, QStringLiteral("hardware.power.turbo.ratio_apply"), QStringLiteral("应用超频倍率"));
    applyTurboRatioButton_->setToolTip(
        QStringLiteral("把设定的全核睿频倍率写入 CPU（超频操作，风险较高，可能导致不稳定或死机）"));
    turboLayout->addWidget(turboEnableCheck_, 0, 0);
    turboLayout->addWidget(applyTurboButton_, 0, 1);
    turboLayout->addWidget(ratioLabel, 1, 0);
    turboLayout->addWidget(turboRatioSpin_, 1, 1);
    turboLayout->addWidget(applyTurboRatioButton_, 1, 2);
    auto* requestedMultiplierLabel = new QLabel(
        QStringLiteral("请求倍频（IA32_PERF_CTL）"),
        turboGroup);
    language.bindText(
        requestedMultiplierLabel,
        QStringLiteral("hardware.power.turbo.requested_multiplier"),
        QStringLiteral("请求倍频（IA32_PERF_CTL）"));
    requestedMultiplierSpin_ = new QSpinBox(turboGroup);
    requestedMultiplierSpin_->setRange(1, 255);
    requestedMultiplierSpin_->setSuffix(QStringLiteral(" x"));
    applyRequestedMultiplierButton_ = new QPushButton(
        QStringLiteral("应用请求倍频"),
        turboGroup);
    language.bindText(
        applyRequestedMultiplierButton_,
        QStringLiteral("hardware.power.turbo.requested_multiplier_apply"),
        QStringLiteral("应用请求倍频"));
    applyRequestedMultiplierButton_->setToolTip(
        QStringLiteral("向 CPU 写入请求的运行倍频（IA32_PERF_CTL 寄存器）"));
    turboLayout->addWidget(requestedMultiplierLabel, 2, 0);
    turboLayout->addWidget(requestedMultiplierSpin_, 2, 1);
    turboLayout->addWidget(applyRequestedMultiplierButton_, 2, 2);
    turboLayout->setColumnStretch(3, 1);
    contentLayout->addWidget(turboGroup, 0);

    auto* hwpGroup = new QGroupBox(QStringLiteral("Intel Speed Shift / HWP"), contentWidget);
    language.bindText(hwpGroup, QStringLiteral("hardware.power.hwp.group"), QStringLiteral("Intel Speed Shift / HWP"));
    auto* hwpLayout = new QGridLayout(hwpGroup);
    auto* hwpMinimumLabel = new QLabel(QStringLiteral("最小性能"), hwpGroup);
    auto* hwpMaximumLabel = new QLabel(QStringLiteral("最大性能"), hwpGroup);
    auto* hwpDesiredLabel = new QLabel(QStringLiteral("期望性能（0=自动）"), hwpGroup);
    auto* hwpEppLabel = new QLabel(QStringLiteral("EPP（0=性能，255=节能）"), hwpGroup);
    language.bindText(hwpMinimumLabel, QStringLiteral("hardware.power.hwp.minimum"), QStringLiteral("最小性能"));
    language.bindText(hwpMaximumLabel, QStringLiteral("hardware.power.hwp.maximum"), QStringLiteral("最大性能"));
    language.bindText(hwpDesiredLabel, QStringLiteral("hardware.power.hwp.desired"), QStringLiteral("期望性能（0=自动）"));
    language.bindText(hwpEppLabel, QStringLiteral("hardware.power.hwp.epp"), QStringLiteral("EPP（0=性能，255=节能）"));
    hwpMinimumSpin_ = new QSpinBox(hwpGroup);
    hwpMaximumSpin_ = new QSpinBox(hwpGroup);
    hwpDesiredSpin_ = new QSpinBox(hwpGroup);
    hwpEppSpin_ = new QSpinBox(hwpGroup);
    for (QSpinBox* spin : { hwpMinimumSpin_, hwpMaximumSpin_, hwpDesiredSpin_, hwpEppSpin_ })
    {
        spin->setRange(0, 255);
    }
    applyHwpButton_ = new QPushButton(QStringLiteral("应用到全部逻辑处理器"), hwpGroup);
    language.bindText(applyHwpButton_, QStringLiteral("hardware.power.hwp.apply"), QStringLiteral("应用到全部逻辑处理器"));
    applyHwpButton_->setToolTip(
        QStringLiteral("把上方 Speed Shift/HWP 的最小、最大、期望性能与能效偏好应用到所有 CPU 逻辑核心"));
    hwpLayout->addWidget(hwpMinimumLabel, 0, 0);
    hwpLayout->addWidget(hwpMinimumSpin_, 0, 1);
    hwpLayout->addWidget(hwpMaximumLabel, 0, 2);
    hwpLayout->addWidget(hwpMaximumSpin_, 0, 3);
    hwpLayout->addWidget(hwpDesiredLabel, 1, 0);
    hwpLayout->addWidget(hwpDesiredSpin_, 1, 1);
    hwpLayout->addWidget(hwpEppLabel, 1, 2);
    hwpLayout->addWidget(hwpEppSpin_, 1, 3);
    hwpLayout->addWidget(applyHwpButton_, 2, 0, 1, 4);
    contentLayout->addWidget(hwpGroup, 0);

    // Risk notice changed to permanent text: clicking 'Apply' still triggers a confirmation dialog; no longer requires pre-checking a
    // confirmation box to unlock the button (removes redundant friction, and forgetting to check only resulted in a generic error message).
    auto* riskNoticeLabel = new QLabel(
        QStringLiteral("注意：提高功耗/倍率可能导致过热、降频、数据错误、死机或硬件寿命下降；请先保存工作并准备好恢复方案。"),
        contentWidget);
    riskNoticeLabel->setWordWrap(true);
    riskNoticeLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(ksword_theme::warningHex()));
    language.bindText(
        riskNoticeLabel,
        QStringLiteral("hardware.power.risk_notice"),
        QStringLiteral("注意：提高功耗/倍率可能导致过热、降频、数据错误、死机或硬件寿命下降；请先保存工作并准备好恢复方案。"));
    contentLayout->addWidget(riskNoticeLabel, 0);

    contentLayout->addStretch(1);

    scrollArea->setWidget(contentWidget);
    rootLayout->addWidget(scrollArea, 1);
    updateControlAvailability();
}

void HardwarePowerPage::initializeConnections()
{
    connect(refreshAllButton_, &QPushButton::clicked, this, [this]() {
        refreshAll();
    });
    connect(applyPowerSchemeButton_, &QPushButton::clicked, this, [this]() {
        applySelectedPowerScheme();
    });
    connect(restoreInitialStateButton_, &QPushButton::clicked, this, [this]() {
        restoreInitialState();
    });
    connect(applyPowerLimitsButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(
            KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS,
            powerText(
                QStringLiteral("hardware.power.confirm.rapl"),
                QStringLiteral("即将修改全部处理器封装的 PL1/PL2。过高值可能超过散热和供电能力，过低值可能导致严重限频。是否继续？")));
    });
    connect(raisePowerLimitsButton_, &QPushButton::clicked, this, [this]() {
        raisePowerLimitsToPlatformMaximum();
    });
    connect(applyTurboButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(
            KSWORD_ARK_CPU_POWER_APPLY_TURBO,
            powerText(
                QStringLiteral("hardware.power.confirm.turbo"),
                QStringLiteral("即将在全部逻辑处理器修改 Intel Turbo Boost 开关。该值可能被固件或 Windows 重写。是否继续？")));
    });
    connect(applyTurboRatioButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(
            KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO,
            powerText(
                QStringLiteral("hardware.power.confirm.ratio"),
                QStringLiteral("即将把 MSR_TURBO_RATIO_LIMIT 中所有已实现档位改为同一倍率。超出 CPU、主板或散热能力可能立即死机或产生计算错误。是否继续？")));
    });
    connect(applyRequestedMultiplierButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(
            KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL,
            powerText(
                QStringLiteral("hardware.power.confirm.requested_multiplier"),
                QStringLiteral("即将在全部逻辑处理器修改 IA32_PERF_CTL 请求倍频。Speed Shift、固件或微码可能限制或忽略该请求；过高倍率可能导致过热、死机或计算错误。是否继续？")));
    });
    connect(applyHwpButton_, &QPushButton::clicked, this, [this]() {
        sendControlRequest(
            KSWORD_ARK_CPU_POWER_APPLY_HWP,
            powerText(
                QStringLiteral("hardware.power.confirm.hwp"),
                QStringLiteral("即将在全部逻辑处理器修改 HWP min/max/desired/EPP。设置可能与 Windows 电源策略竞争。是否继续？")));
    });
}

void HardwarePowerPage::refreshAll()
{
    setStatus(powerText(
        QStringLiteral("hardware.power.status.refreshing"),
        QStringLiteral("状态：正在刷新 Windows 电源方案与 R0 CPU 电源快照...")));
    refreshPowerSchemes();
    refreshCpuPower();
}

void HardwarePowerPage::refreshPowerSchemes()
{
    if (powerSchemeCombo_ == nullptr)
    {
        return;
    }

    powerSchemeCombo_->clear();
    GUID* activeGuid = nullptr;
    const DWORD kActiveError = ::PowerGetActiveScheme(nullptr, &activeGuid);
    int activeIndex = -1;

    for (ULONG schemeIndex = 0UL;; ++schemeIndex)
    {
        GUID schemeGuid{};
        DWORD guidBytesCount = sizeof(schemeGuid);
        const DWORD kEnumerateError = ::PowerEnumerate(
            nullptr,
            nullptr,
            nullptr,
            ACCESS_SCHEME,
            schemeIndex,
            reinterpret_cast<UCHAR*>(&schemeGuid),
            &guidBytesCount);
        if (kEnumerateError == ERROR_NO_MORE_ITEMS)
        {
            break;
        }
        if (kEnumerateError != ERROR_SUCCESS || guidBytesCount != sizeof(schemeGuid))
        {
            continue;
        }

        QString friendlyName = powerSchemeFriendlyName(schemeGuid);
        if (friendlyName.isEmpty())
        {
            friendlyName = powerText(
                QStringLiteral("hardware.power.scheme.unnamed"),
                QStringLiteral("未命名电源方案"));
        }
        const bool kIsActive = kActiveError == ERROR_SUCCESS &&
            activeGuid != nullptr && ::IsEqualGUID(*activeGuid, schemeGuid);
        if (kIsActive)
        {
            friendlyName += powerText(
                QStringLiteral("hardware.power.scheme.active_suffix"),
                QStringLiteral("（当前）"));
        }
        const int kComboIndex = powerSchemeCombo_->count();
        powerSchemeCombo_->addItem(friendlyName, guidBytes(schemeGuid));
        if (kIsActive)
        {
            activeIndex = kComboIndex;
        }
    }

    // The first successfully read active scheme serves as the one-click restore target for this page's lifecycle; subsequent refreshes do not overwrite it.
    if (kActiveError == ERROR_SUCCESS && activeGuid != nullptr &&
        restorePowerSchemeGuid_.isEmpty())
    {
        restorePowerSchemeGuid_ = guidBytes(*activeGuid);
    }
    if (activeGuid != nullptr)
    {
        ::LocalFree(activeGuid);
    }
    if (activeIndex >= 0)
    {
        powerSchemeCombo_->setCurrentIndex(activeIndex);
    }
    const bool kHasSchemes = powerSchemeCombo_->count() > 0;
    powerSchemeCombo_->setEnabled(kHasSchemes);
    applyPowerSchemeButton_->setEnabled(kHasSchemes);
    updateControlAvailability();
}

void HardwarePowerPage::applySelectedPowerScheme()
{
    if (powerSchemeCombo_ == nullptr || powerSchemeCombo_->currentIndex() < 0)
    {
        QMessageBox::critical(
            this,
            powerText(QStringLiteral("hardware.power.error.title"), QStringLiteral("电源调节失败")),
            powerText(QStringLiteral("hardware.power.error.no_scheme"), QStringLiteral("没有可应用的 Windows 电源方案。")));
        return;
    }

    GUID schemeGuid{};
    if (!guidFromBytes(
            powerSchemeCombo_->currentData().toByteArray(),
            &schemeGuid))
    {
        QMessageBox::critical(
            this,
            powerText(QStringLiteral("hardware.power.error.title"), QStringLiteral("电源调节失败")),
            powerText(QStringLiteral("hardware.power.error.scheme_data"), QStringLiteral("所选电源方案 GUID 数据无效。")));
        return;
    }

    const DWORD kError = ::PowerSetActiveScheme(nullptr, &schemeGuid);
    if (kError != ERROR_SUCCESS)
    {
        const QString kMessage = powerText(
            QStringLiteral("hardware.power.error.scheme_apply"),
            QStringLiteral("应用 Windows 电源方案失败，Win32=%1。"))
            .arg(kError);
        setStatus(kMessage, true);
        QMessageBox::critical(
            this,
            powerText(QStringLiteral("hardware.power.error.title"), QStringLiteral("电源调节失败")),
            kMessage);
        return;
    }

    setStatus(powerText(
        QStringLiteral("hardware.power.status.scheme_applied"),
        QStringLiteral("状态：Windows 电源方案已应用。")));
    refreshPowerSchemes();
}

void HardwarePowerPage::restoreInitialState()
{
    const QString kErrorTitle = powerText(
        QStringLiteral("hardware.power.error.title"),
        QStringLiteral("电源调节失败"));
    if (restorePowerSchemeGuid_.isEmpty() && !hasRestoreCpuSnapshot_)
    {
        QMessageBox::critical(
            this,
            kErrorTitle,
            powerText(
                QStringLiteral("hardware.power.error.no_restore"),
                QStringLiteral("尚未捕获可还原的首次状态，请先刷新。")));
        return;
    }

    // Refresh the current CPU state before confirmation to avoid judging the need for risk confirmation based on stale capabilities.
    if (hasRestoreCpuSnapshot_)
    {
        refreshCpuPower();
    }

    const unsigned long kInitialCpuApplyFlags = restorableCpuApplyFlags();
    if (kInitialCpuApplyFlags != 0UL)
    {
        const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST kInitialRequest =
            buildRestoreControlRequest(kInitialCpuApplyFlags);
        const QString kValidationError =
            validateCpuPowerRequestForUi(kInitialRequest, snapshot_);
        if (!kValidationError.isEmpty())
        {
            setStatus(kValidationError, true);
            QMessageBox::critical(this, kErrorTitle, kValidationError);
            return;
        }
    }

    if (QMessageBox::warning(
            this,
            powerText(
                QStringLiteral("hardware.power.confirm.restore_title"),
                QStringLiteral("确认一键还原")),
            powerText(
                QStringLiteral("hardware.power.confirm.restore"),
                QStringLiteral("即将恢复本页首次有效刷新时捕获的 Windows 电源方案，以及当前仍可写的 PL1/PL2、Turbo、HWP、Turbo Ratio 和请求倍频。固件或 Windows 仍可能再次重写这些值。是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    bool restoredPowerScheme = false;
    if (!restorePowerSchemeGuid_.isEmpty())
    {
        GUID schemeGuid{};
        if (!guidFromBytes(restorePowerSchemeGuid_, &schemeGuid))
        {
            QMessageBox::critical(
                this,
                kErrorTitle,
                powerText(
                    QStringLiteral("hardware.power.error.restore_scheme_data"),
                    QStringLiteral("首次捕获的 Windows 电源方案 GUID 数据无效。")));
            return;
        }
        const DWORD kSchemeError = ::PowerSetActiveScheme(nullptr, &schemeGuid);
        if (kSchemeError != ERROR_SUCCESS)
        {
            const QString kMessage = powerText(
                QStringLiteral("hardware.power.error.restore_scheme_apply"),
                QStringLiteral("还原首次 Windows 电源方案失败，Win32=%1。"))
                .arg(kSchemeError);
            setStatus(kMessage, true);
            QMessageBox::critical(this, kErrorTitle, kMessage);
            return;
        }
        restoredPowerScheme = true;
        refreshPowerSchemes();
    }

    bool restoredCpuState = false;
    if (hasRestoreCpuSnapshot_)
    {
        // Windows policies may immediately overwrite CPU requests; resample before constructing the expected field.
        refreshCpuPower();
        const unsigned long kCpuApplyFlags = restorableCpuApplyFlags();
        if (kCpuApplyFlags != 0UL)
        {
            const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST kRequest =
                buildRestoreControlRequest(kCpuApplyFlags);
            if (!executeControlRequest(kRequest))
            {
                return;
            }
            restoredCpuState = true;
        }
    }

    if (restoredPowerScheme && restoredCpuState)
    {
        setStatus(powerText(
            QStringLiteral("hardware.power.status.restored"),
            QStringLiteral("状态：已还原首次捕获的 Windows 电源方案和当前可写 CPU 设置。")));
    }
    else if (restoredPowerScheme)
    {
        setStatus(powerText(
            QStringLiteral("hardware.power.status.restored_scheme_only"),
            QStringLiteral("状态：已还原首次捕获的 Windows 电源方案；当前没有可写的 CPU 还原字段。")));
    }
    else if (restoredCpuState)
    {
        setStatus(powerText(
            QStringLiteral("hardware.power.status.restored_cpu_only"),
            QStringLiteral("状态：已还原首次捕获的当前可写 CPU 设置。")));
    }
    else
    {
        const QString kMessage = powerText(
            QStringLiteral("hardware.power.error.restore_unavailable"),
            QStringLiteral("首次状态已捕获，但当前没有可执行的还原目标。"));
        setStatus(kMessage, true);
        QMessageBox::critical(this, kErrorTitle, kMessage);
    }
}

void HardwarePowerPage::refreshCpuPower()
{
    const ksword::ark::DriverClient kClient;
    applySnapshotToUi(kClient.queryCpuPowerState());
}

void HardwarePowerPage::applySnapshotToUi(const ksword::ark::CpuPowerResult& result)
{
    hasSnapshot_ = false;
    snapshotTable_->clearContents();
    snapshotTable_->setRowCount(0);
    snapshotTable_->setHorizontalHeaderLabels({
        powerText(QStringLiteral("hardware.power.table.item"), QStringLiteral("项目")),
        powerText(QStringLiteral("hardware.power.table.value"), QStringLiteral("当前值")) });
    if (result.unsupported)
    {
        setStatus(
            powerText(
                QStringLiteral("hardware.power.status.old_driver"),
                QStringLiteral("状态：当前 KswordARK 驱动版本尚未集成 CPU 电源 IOCTL。")),
            true);
        updateControlAvailability();
        return;
    }
    if (!result.io.ok ||
        result.io.bytesReturned < sizeof(KSWORD_ARK_CPU_POWER_RESPONSE) ||
        result.response.size < sizeof(KSWORD_ARK_CPU_POWER_RESPONSE) ||
        result.response.version != KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION)
    {
        setStatus(
            powerText(
                QStringLiteral("hardware.power.status.query_failed"),
                QStringLiteral("状态：R0 CPU 电源快照读取失败：%1"))
                .arg(QString::fromStdString(result.io.message)),
            true);
        updateControlAvailability();
        return;
    }

    snapshot_ = result.response;
    hasSnapshot_ = true;
    // The first valid protocol snapshot is the restore baseline; refreshes after successful control cannot overwrite it.
    if (!hasRestoreCpuSnapshot_)
    {
        restoreCpuSnapshot_ = snapshot_;
        hasRestoreCpuSnapshot_ = true;
    }
    const QString kVendorText = QString::fromLatin1(snapshot_.vendorId).trimmed();
    const QString kBrandText = QString::fromLatin1(snapshot_.brandText).simplified();
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.cpu"), QStringLiteral("处理器")),
        QStringLiteral("%1 | %2").arg(kVendorText, kBrandText));
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.identity"), QStringLiteral("身份 / 拓扑")),
        powerText(
            QStringLiteral("hardware.power.value.identity"),
            QStringLiteral("Family %1 Model %2 Stepping %3 | 逻辑处理器 %4 | 组 %5"))
            .arg(snapshot_.family)
            .arg(snapshot_.model)
            .arg(snapshot_.stepping)
            .arg(snapshot_.logicalProcessorCount)
            .arg(snapshot_.processorGroupCount));

    QStringList capabilityParts;
    const auto kAppendCapability = [&capabilityParts](
        const unsigned long long mask,
        const unsigned long long available,
        const QString& text) {
        if ((available & mask) != 0ULL)
        {
            capabilityParts.append(text);
        }
    };
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_RAPL,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.rapl"), QStringLiteral("RAPL")));
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.power_write"), QStringLiteral("PL1/PL2 Write")));
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_TURBO_CONTROL,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.turbo"), QStringLiteral("Turbo")));
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_PROGRAMMABLE,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.turbo_ratio"), QStringLiteral("Turbo Ratio")));
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL_PROGRAMMABLE,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.requested_multiplier"), QStringLiteral("请求倍频")));
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_HWP_ENABLED,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.hwp"), QStringLiteral("HWP")));
    kAppendCapability(
        KSWORD_ARK_CPU_POWER_CAP_HWP_EPP,
        snapshot_.capabilityFlags,
        powerText(QStringLiteral("hardware.power.cap.hwp_epp"), QStringLiteral("HWP EPP")));
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.capabilities"), QStringLiteral("可用能力")),
        capabilityParts.isEmpty()
            ? powerText(QStringLiteral("hardware.power.value.none"), QStringLiteral("无可写 R0 能力"))
            : capabilityParts.join(QStringLiteral(", ")));

    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.rapl_units"), QStringLiteral("RAPL 单位")),
        powerText(
            QStringLiteral("hardware.power.value.rapl_units"),
            QStringLiteral("%1 μW / unit | %2 ns / time unit"))
            .arg(snapshot_.powerUnitMicrowatts)
            .arg(snapshot_.timeUnitNanoseconds));
    addSnapshotRow(
        snapshotTable_,
        QStringLiteral("PL1 / PL2"),
        powerText(
            QStringLiteral("hardware.power.value.limits"),
            QStringLiteral("PL1 %1 W（启用=%2 Clamp=%3） | PL2 %4 W（启用=%5 Clamp=%6）"))
            .arg(snapshot_.pl1Milliwatts / 1000.0, 0, 'f', 3)
            .arg(snapshot_.pl1Enabled)
            .arg(snapshot_.pl1ClampEnabled)
            .arg(snapshot_.pl2Milliwatts / 1000.0, 0, 'f', 3)
            .arg(snapshot_.pl2Enabled)
            .arg(snapshot_.pl2ClampEnabled));
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.sku_range"), QStringLiteral("SKU 功耗范围")),
        powerText(
            QStringLiteral("hardware.power.value.sku_range"),
            QStringLiteral("TDP %1 W | 最小 %2 W | 最大 %3 W | Lock=%4"))
            .arg(snapshot_.packageTdpMilliwatts / 1000.0, 0, 'f', 3)
            .arg(snapshot_.packageMinimumPowerMilliwatts / 1000.0, 0, 'f', 3)
            .arg(snapshot_.packageMaximumPowerMilliwatts / 1000.0, 0, 'f', 3)
            .arg((snapshot_.responseFlags & KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED) != 0UL ? 1 : 0));
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.turbo"), QStringLiteral("Turbo / Ratio")),
        powerText(
            QStringLiteral("hardware.power.value.turbo"),
            QStringLiteral("Turbo=%1 | Non-Turbo=%2x | 请求=%3x | 当前=%4x | Ratio MSR=%5"))
            .arg(snapshot_.turboEnabled)
            .arg(snapshot_.maximumNonTurboRatio)
            .arg(snapshot_.requestedMultiplier)
            .arg(snapshot_.currentMultiplier)
            .arg(rawMsrText(snapshot_.msrTurboRatioLimit)));
    addSnapshotRow(
        snapshotTable_,
        QStringLiteral("HWP"),
        powerText(
            QStringLiteral("hardware.power.value.hwp"),
            QStringLiteral("能力 高=%1 保证=%2 高效=%3 低=%4 | 请求 Min=%5 Max=%6 Desired=%7 EPP=%8"))
            .arg(snapshot_.hwpHighestPerformance)
            .arg(snapshot_.hwpGuaranteedPerformance)
            .arg(snapshot_.hwpMostEfficientPerformance)
            .arg(snapshot_.hwpLowestPerformance)
            .arg(snapshot_.hwpMinimumPerformance)
            .arg(snapshot_.hwpMaximumPerformance)
            .arg(snapshot_.hwpDesiredPerformance)
            .arg(snapshot_.hwpEnergyPerformancePreference));
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.raw"), QStringLiteral("原始 MSR")),
        QStringLiteral("0x610=%1 | 0x1A0=%2 | 0x774=%3 | 0x198=%4 | 0x199=%5")
            .arg(rawMsrText(snapshot_.msrPackagePowerLimit))
            .arg(rawMsrText(snapshot_.msrMiscEnable))
            .arg(rawMsrText(snapshot_.msrHwpRequest))
            .arg(rawMsrText(snapshot_.msrPerfStatus))
            .arg(rawMsrText(snapshot_.msrPerfControl)));
    addSnapshotRow(
        snapshotTable_,
        powerText(QStringLiteral("hardware.power.row.status"), QStringLiteral("R0 状态")),
        powerText(
            QStringLiteral("hardware.power.value.r0_status"),
            QStringLiteral("NTSTATUS=%1 | field=0x%2 | flags=0x%3 | reason=%4"))
            .arg(ntStatusText(snapshot_.lastStatus))
            .arg(snapshot_.fieldFlags, 8, 16, QChar('0'))
            .arg(snapshot_.responseFlags, 8, 16, QChar('0'))
            .arg(snapshot_.failureReason)
            .toUpper());

    const double kPlatformMinimumWatts = snapshot_.packageMinimumPowerMilliwatts > 0UL
        ? snapshot_.packageMinimumPowerMilliwatts / 1000.0
        : 0.001;
    double platformMaximumWatts = snapshot_.packageMaximumPowerMilliwatts > 0UL
        ? snapshot_.packageMaximumPowerMilliwatts / 1000.0
        : 1000.0;
    platformMaximumWatts = std::max({
        platformMaximumWatts,
        snapshot_.pl1Milliwatts / 1000.0,
        snapshot_.pl2Milliwatts / 1000.0,
        kPlatformMinimumWatts });
    pl1Spin_->setRange(kPlatformMinimumWatts, platformMaximumWatts);
    pl2Spin_->setRange(kPlatformMinimumWatts, platformMaximumWatts);
    if (snapshot_.pl1Milliwatts > 0UL)
    {
        pl1Spin_->setValue(snapshot_.pl1Milliwatts / 1000.0);
    }
    if (snapshot_.pl2Milliwatts > 0UL)
    {
        pl2Spin_->setValue(snapshot_.pl2Milliwatts / 1000.0);
    }
    pl1EnableCheck_->setChecked(snapshot_.pl1Enabled != 0UL);
    pl1ClampCheck_->setChecked(snapshot_.pl1ClampEnabled != 0UL);
    pl2EnableCheck_->setChecked(snapshot_.pl2Enabled != 0UL);
    pl2ClampCheck_->setChecked(snapshot_.pl2ClampEnabled != 0UL);
    turboEnableCheck_->setChecked(snapshot_.turboEnabled != 0UL);

    int displayedRatio = 0;
    for (const unsigned long kRatio : snapshot_.turboRatios)
    {
        if (kRatio != 0UL)
        {
            displayedRatio = static_cast<int>(kRatio);
        }
    }
    if (displayedRatio > 0)
    {
        turboRatioSpin_->setValue(displayedRatio);
    }
    if (snapshot_.requestedMultiplier > 0UL)
    {
        requestedMultiplierSpin_->setValue(
            static_cast<int>(snapshot_.requestedMultiplier));
    }
    const int kHwpLowest = snapshot_.hwpLowestPerformance != 0UL
        ? static_cast<int>(snapshot_.hwpLowestPerformance)
        : 0;
    const int kHwpHighest = snapshot_.hwpHighestPerformance != 0UL
        ? std::max(kHwpLowest, static_cast<int>(snapshot_.hwpHighestPerformance))
        : 255;
    hwpMinimumSpin_->setRange(kHwpLowest, kHwpHighest);
    hwpMaximumSpin_->setRange(kHwpLowest, kHwpHighest);
    hwpDesiredSpin_->setRange(0, kHwpHighest);
    hwpMinimumSpin_->setValue(static_cast<int>(snapshot_.hwpMinimumPerformance));
    hwpMaximumSpin_->setValue(static_cast<int>(snapshot_.hwpMaximumPerformance));
    hwpDesiredSpin_->setValue(static_cast<int>(snapshot_.hwpDesiredPerformance));
    hwpEppSpin_->setValue(static_cast<int>(snapshot_.hwpEnergyPerformancePreference));

    if ((snapshot_.responseFlags & KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_UNSUPPORTED_VENDOR) != 0UL)
    {
        setStatus(
            powerText(
                QStringLiteral("hardware.power.status.vendor_unsupported"),
                QStringLiteral("状态：该 CPU 厂商暂不支持 R0 调节；Windows 电源方案仍可使用。AMD SMU/PBO 不会按 Intel MSR 方式写入。")),
            true);
    }
    else if ((snapshot_.responseFlags & KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED) != 0UL)
    {
        setStatus(
            powerText(
                QStringLiteral("hardware.power.status.locked"),
                QStringLiteral("状态：CPU 快照已刷新；RAPL 功耗限制已被 BIOS/固件锁定，本页不会尝试清除 lock 位。")),
            true);
    }
    else if ((snapshot_.responseFlags & KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PARTIAL_MSR) != 0UL)
    {
        setStatus(
            powerText(
                QStringLiteral("hardware.power.status.partial"),
                QStringLiteral("状态：CPU 快照部分可用；不可读 MSR 已禁用对应控件。R0=%1"))
                .arg(ntStatusText(snapshot_.lastStatus)),
            true);
    }
    else
    {
        setStatus(powerText(
            QStringLiteral("hardware.power.status.ready"),
            QStringLiteral("状态：CPU 电源快照已刷新；仅能力探测通过的控件可用。")));
    }
    updateControlAvailability();
}

void HardwarePowerPage::updateControlAvailability()
{
    const bool kHasIntelSnapshot = hasSnapshot_ &&
        snapshot_.vendor == KSWORD_ARK_CPU_POWER_VENDOR_INTEL;
    const bool kPowerLimitLocked = hasSnapshot_ &&
        (snapshot_.responseFlags &
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED) != 0UL;
    const bool kCanProgramPowerLimits = kHasIntelSnapshot &&
        !kPowerLimitLocked &&
        (snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT) != 0UL;
    const bool kCanControlTurbo = kHasIntelSnapshot &&
        (snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_TURBO_CONTROL) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_MISC_ENABLE) != 0UL;
    const bool kCanProgramTurboRatio = kHasIntelSnapshot &&
        (snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_PROGRAMMABLE) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT) != 0UL;
    const bool kCanProgramRequestedMultiplier = kHasIntelSnapshot &&
        (snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL_PROGRAMMABLE) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL) != 0UL;
    const bool kCanControlHwp = kHasIntelSnapshot &&
        (snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_HWP_ENABLED) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST) != 0UL;
    const bool kCanControlHwpEpp = kCanControlHwp &&
        (snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_HWP_EPP) != 0ULL;
    const bool kHasPlatformMaximum = kCanProgramPowerLimits &&
        snapshot_.packageMaximumPowerMilliwatts > 0UL &&
        (snapshot_.responseFlags &
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PLATFORM_MAX_UNKNOWN) == 0UL;

    for (QWidget* widget : {
            static_cast<QWidget*>(pl1Spin_),
            static_cast<QWidget*>(pl2Spin_),
            static_cast<QWidget*>(pl1EnableCheck_),
            static_cast<QWidget*>(pl1ClampCheck_),
            static_cast<QWidget*>(pl2EnableCheck_),
            static_cast<QWidget*>(pl2ClampCheck_) })
    {
        if (widget != nullptr)
        {
            widget->setEnabled(kCanProgramPowerLimits);
        }
    }
    applyPowerLimitsButton_->setEnabled(kCanProgramPowerLimits);
    raisePowerLimitsButton_->setEnabled(kHasPlatformMaximum);

    turboEnableCheck_->setEnabled(kCanControlTurbo);
    applyTurboButton_->setEnabled(kCanControlTurbo);
    turboRatioSpin_->setEnabled(kCanProgramTurboRatio);
    applyTurboRatioButton_->setEnabled(kCanProgramTurboRatio);
    requestedMultiplierSpin_->setEnabled(kCanProgramRequestedMultiplier);
    applyRequestedMultiplierButton_->setEnabled(
        kCanProgramRequestedMultiplier);

    hwpMinimumSpin_->setEnabled(kCanControlHwp);
    hwpMaximumSpin_->setEnabled(kCanControlHwp);
    hwpDesiredSpin_->setEnabled(kCanControlHwp);
    hwpEppSpin_->setEnabled(kCanControlHwpEpp);
    applyHwpButton_->setEnabled(kCanControlHwp);

    const bool kHasRestoreBaseline = !restorePowerSchemeGuid_.isEmpty() ||
        hasRestoreCpuSnapshot_;
    restoreInitialStateButton_->setEnabled(kHasRestoreBaseline);
}

void HardwarePowerPage::setStatus(const QString& text, const bool isError)
{
    if (statusLabel_ == nullptr)
    {
        return;
    }
    statusLabel_->setText(text);
    statusLabel_->setStyleSheet(
        QStringLiteral("font-weight:600;color:%1;")
            .arg(isError
                ? ksword_theme::errorHex()
                : ksword_theme::kPrimaryBlueHex));
}

KSWORD_ARK_CPU_POWER_CONTROL_REQUEST HardwarePowerPage::buildControlRequest(
    const unsigned long applyFlags) const
{
    const auto kWattsToMilliwatts = [](const double watts) {
        const double kBoundedWatts = std::clamp(watts, 0.001, 1000.0);
        return static_cast<unsigned long>(
            std::llround(kBoundedWatts * 1000.0));
    };

    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION;
    request.applyFlags = applyFlags;
    request.requestFlags = KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED |
        KSWORD_ARK_CPU_POWER_REQUEST_FLAG_REQUIRE_CURRENT;
    request.pl1Milliwatts = kWattsToMilliwatts(pl1Spin_->value());
    request.pl2Milliwatts = kWattsToMilliwatts(pl2Spin_->value());
    request.pl1Enabled = pl1EnableCheck_->isChecked() ? 1UL : 0UL;
    request.pl1ClampEnabled = pl1ClampCheck_->isChecked() ? 1UL : 0UL;
    request.pl2Enabled = pl2EnableCheck_->isChecked() ? 1UL : 0UL;
    request.pl2ClampEnabled = pl2ClampCheck_->isChecked() ? 1UL : 0UL;
    request.turboEnabled = turboEnableCheck_->isChecked() ? 1UL : 0UL;
    request.hwpMinimumPerformance =
        static_cast<unsigned long>(hwpMinimumSpin_->value());
    request.hwpMaximumPerformance =
        static_cast<unsigned long>(hwpMaximumSpin_->value());
    request.hwpDesiredPerformance =
        static_cast<unsigned long>(hwpDesiredSpin_->value());
    request.hwpEnergyPerformancePreference =
        static_cast<unsigned long>(hwpEppSpin_->value());
    request.turboRatio =
        static_cast<unsigned long>(turboRatioSpin_->value());
    request.requestedMultiplier =
        static_cast<unsigned long>(requestedMultiplierSpin_->value());
    for (unsigned long ratioIndex = 0UL;
        ratioIndex < KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT;
        ++ratioIndex)
    {
        request.turboRatios[ratioIndex] = request.turboRatio;
    }
    request.expectedPackagePowerLimit = snapshot_.msrPackagePowerLimit;
    request.expectedMiscEnable = snapshot_.msrMiscEnable;
    request.expectedHwpRequest = snapshot_.msrHwpRequest;
    request.expectedTurboRatioLimit = snapshot_.msrTurboRatioLimit;
    request.expectedPerfControl = snapshot_.msrPerfControl;
    return request;
}

unsigned long HardwarePowerPage::restorableCpuApplyFlags() const
{
    if (!hasSnapshot_ || !hasRestoreCpuSnapshot_ ||
        snapshot_.vendor != KSWORD_ARK_CPU_POWER_VENDOR_INTEL ||
        restoreCpuSnapshot_.vendor != KSWORD_ARK_CPU_POWER_VENDOR_INTEL)
    {
        return 0UL;
    }

    unsigned long applyFlags = 0UL;
    if ((snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_PACKAGE_POWER_PROGRAMMABLE) != 0ULL &&
        (snapshot_.responseFlags &
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_POWER_LIMIT_LOCKED) == 0UL &&
        (snapshot_.fieldFlags &
            (KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT |
             KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT)) ==
            (KSWORD_ARK_CPU_POWER_FIELD_RAPL_UNIT |
             KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT) &&
        (restoreCpuSnapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_PACKAGE_POWER_LIMIT) != 0UL)
    {
        applyFlags |= KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS;
    }
    if ((snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_TURBO_CONTROL) != 0ULL &&
        (snapshot_.fieldFlags & KSWORD_ARK_CPU_POWER_FIELD_MISC_ENABLE) != 0UL &&
        (restoreCpuSnapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_MISC_ENABLE) != 0UL)
    {
        applyFlags |= KSWORD_ARK_CPU_POWER_APPLY_TURBO;
    }
    if ((snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_HWP_ENABLED) != 0ULL &&
        (snapshot_.fieldFlags &
            (KSWORD_ARK_CPU_POWER_FIELD_HWP_CAPABILITIES |
             KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST)) ==
            (KSWORD_ARK_CPU_POWER_FIELD_HWP_CAPABILITIES |
             KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST) &&
        (restoreCpuSnapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_HWP_REQUEST) != 0UL)
    {
        applyFlags |= KSWORD_ARK_CPU_POWER_APPLY_HWP;
    }
    if ((snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_TURBO_RATIO_PROGRAMMABLE) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT) != 0UL &&
        (restoreCpuSnapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_TURBO_RATIO_LIMIT) != 0UL)
    {
        applyFlags |= KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO;
    }
    if ((snapshot_.capabilityFlags &
            KSWORD_ARK_CPU_POWER_CAP_PERF_CONTROL_PROGRAMMABLE) != 0ULL &&
        (snapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL) != 0UL &&
        (restoreCpuSnapshot_.fieldFlags &
            KSWORD_ARK_CPU_POWER_FIELD_PERF_CONTROL) != 0UL &&
        restoreCpuSnapshot_.requestedMultiplier > 0UL &&
        restoreCpuSnapshot_.requestedMultiplier <= 0xFFUL)
    {
        applyFlags |= KSWORD_ARK_CPU_POWER_APPLY_PERF_CONTROL;
    }
    return applyFlags;
}

KSWORD_ARK_CPU_POWER_CONTROL_REQUEST HardwarePowerPage::buildRestoreControlRequest(
    const unsigned long applyFlags) const
{
    KSWORD_ARK_CPU_POWER_CONTROL_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION;
    request.applyFlags = applyFlags;
    request.requestFlags = KSWORD_ARK_CPU_POWER_REQUEST_FLAG_UI_CONFIRMED |
        KSWORD_ARK_CPU_POWER_REQUEST_FLAG_REQUIRE_CURRENT;
    if ((applyFlags & KSWORD_ARK_CPU_POWER_APPLY_TURBO_RATIO) != 0UL)
    {
        request.requestFlags |=
            KSWORD_ARK_CPU_POWER_REQUEST_FLAG_TURBO_RATIO_ARRAY;
    }

    request.pl1Milliwatts = restoreCpuSnapshot_.pl1Milliwatts;
    request.pl2Milliwatts = restoreCpuSnapshot_.pl2Milliwatts;
    request.pl1Enabled = restoreCpuSnapshot_.pl1Enabled;
    request.pl1ClampEnabled = restoreCpuSnapshot_.pl1ClampEnabled;
    request.pl2Enabled = restoreCpuSnapshot_.pl2Enabled;
    request.pl2ClampEnabled = restoreCpuSnapshot_.pl2ClampEnabled;
    request.turboEnabled = restoreCpuSnapshot_.turboEnabled;
    request.hwpMinimumPerformance =
        restoreCpuSnapshot_.hwpMinimumPerformance;
    request.hwpMaximumPerformance =
        restoreCpuSnapshot_.hwpMaximumPerformance;
    request.hwpDesiredPerformance =
        restoreCpuSnapshot_.hwpDesiredPerformance;
    request.hwpEnergyPerformancePreference =
        (snapshot_.capabilityFlags & KSWORD_ARK_CPU_POWER_CAP_HWP_EPP) != 0ULL
        ? restoreCpuSnapshot_.hwpEnergyPerformancePreference
        : snapshot_.hwpEnergyPerformancePreference;
    request.requestedMultiplier = restoreCpuSnapshot_.requestedMultiplier;
    for (unsigned long ratioIndex = 0UL;
        ratioIndex < KSWORD_ARK_CPU_POWER_TURBO_RATIO_COUNT;
        ++ratioIndex)
    {
        request.turboRatios[ratioIndex] =
            restoreCpuSnapshot_.turboRatios[ratioIndex];
        if (request.turboRatio == 0UL && request.turboRatios[ratioIndex] != 0UL)
        {
            request.turboRatio = request.turboRatios[ratioIndex];
        }
    }

    request.expectedPackagePowerLimit = snapshot_.msrPackagePowerLimit;
    request.expectedMiscEnable = snapshot_.msrMiscEnable;
    request.expectedHwpRequest = snapshot_.msrHwpRequest;
    request.expectedTurboRatioLimit = snapshot_.msrTurboRatioLimit;
    request.expectedPerfControl = snapshot_.msrPerfControl;
    return request;
}

bool HardwarePowerPage::executeControlRequest(
    const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request)
{
    const QString kErrorTitle = powerText(
        QStringLiteral("hardware.power.error.title"),
        QStringLiteral("电源调节失败"));
    const QString kValidationError =
        validateCpuPowerRequestForUi(request, snapshot_);
    if (!kValidationError.isEmpty())
    {
        setStatus(kValidationError, true);
        QMessageBox::critical(this, kErrorTitle, kValidationError);
        return false;
    }

    setStatus(powerText(
        QStringLiteral("hardware.power.status.applying"),
        QStringLiteral("状态：正在通过 KswordARK 应用并回读校验 CPU 电源设置...")));
    const ksword::ark::DriverClient kClient;
    const ksword::ark::CpuPowerResult kResult =
        kClient.controlCpuPower(request);
    const bool kResponseValid =
        kResult.io.bytesReturned >= sizeof(KSWORD_ARK_CPU_POWER_RESPONSE) &&
        kResult.response.size >= sizeof(KSWORD_ARK_CPU_POWER_RESPONSE) &&
        kResult.response.version == KSWORD_ARK_CPU_POWER_PROTOCOL_VERSION;
    if (!kResult.io.ok || !kResponseValid || kResult.response.lastStatus != 0L)
    {
        QString detail = QString::fromStdString(kResult.io.message);
        if (kResponseValid &&
            (kResult.response.responseFlags &
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_STALE_SNAPSHOT) != 0UL)
        {
            detail = powerText(
                QStringLiteral("hardware.power.error.stale"),
                QStringLiteral("设置在提交前已被固件、Windows 或其他工具改变，请刷新后重试。"));
        }
        else if (kResponseValid &&
            (kResult.response.responseFlags &
                KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_WRITE_PARTIAL) != 0UL)
        {
            detail = powerText(
                QStringLiteral("hardware.power.error.partial_write"),
                QStringLiteral("部分逻辑处理器写入或回读失败；请立即刷新并检查当前值。R0=%1"))
                .arg(ntStatusText(kResult.response.lastStatus));
        }
        else if (kResponseValid &&
            kResult.response.failureReason !=
                KSWORD_ARK_CPU_POWER_FAILURE_NONE)
        {
            detail = cpuPowerFailureReasonText(
                kResult.response.failureReason,
                request,
                kResult.response) + QStringLiteral("\n") + detail;
        }
        const QString kMessage = powerText(
            QStringLiteral("hardware.power.error.control"),
            QStringLiteral("CPU 电源设置未完整应用：%1"))
            .arg(detail);
        setStatus(kMessage, true);
        QMessageBox::critical(this, kErrorTitle, kMessage);
        refreshCpuPower();
        setStatus(kMessage, true);
        return false;
    }

    refreshCpuPower();
    setStatus(powerText(
        QStringLiteral("hardware.power.status.applied"),
        QStringLiteral("状态：CPU 电源设置已写入并回读验证，已更新逻辑处理器 %1 个。"))
        .arg(kResult.response.updatedProcessorCount));
    return true;
}

void HardwarePowerPage::sendControlRequest(
    const unsigned long applyFlags,
    const QString& confirmationText)
{
    const QString kErrorTitle = powerText(
        QStringLiteral("hardware.power.error.title"),
        QStringLiteral("电源调节失败"));
    if (!hasSnapshot_)
    {
        QMessageBox::critical(
            this,
            kErrorTitle,
            powerText(
                QStringLiteral("hardware.power.error.no_snapshot"),
                QStringLiteral("没有可用于并发校验的 CPU 电源快照，请先刷新。")));
        return;
    }
    const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST kRequest =
        buildControlRequest(applyFlags);
    const QString kValidationError =
        validateCpuPowerRequestForUi(kRequest, snapshot_);
    if (!kValidationError.isEmpty())
    {
        setStatus(kValidationError, true);
        QMessageBox::critical(this, kErrorTitle, kValidationError);
        return;
    }
    if (QMessageBox::warning(
            this,
            powerText(
                QStringLiteral("hardware.power.confirm.title"),
                QStringLiteral("确认 CPU 电源修改")),
            confirmationText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    (void)executeControlRequest(kRequest);
}

void HardwarePowerPage::raisePowerLimitsToPlatformMaximum()
{
    if (!hasSnapshot_ ||
        snapshot_.packageMaximumPowerMilliwatts == 0UL ||
        (snapshot_.responseFlags &
            KSWORD_ARK_CPU_POWER_RESPONSE_FLAG_PLATFORM_MAX_UNKNOWN) != 0UL)
    {
        QMessageBox::critical(
            this,
            powerText(
                QStringLiteral("hardware.power.error.title"),
                QStringLiteral("电源调节失败")),
            powerText(
                QStringLiteral("hardware.power.error.no_platform_max"),
                QStringLiteral("CPU 未报告可信的平台功耗上限，无法执行一键提升。仍可在允许范围内手动设置 PL1/PL2。")));
        return;
    }

    const double kMaximumWatts =
        snapshot_.packageMaximumPowerMilliwatts / 1000.0;
    pl1Spin_->setValue(kMaximumWatts);
    pl2Spin_->setValue(kMaximumWatts);
    pl1EnableCheck_->setChecked(true);
    pl2EnableCheck_->setChecked(true);
    pl1ClampCheck_->setChecked(false);
    pl2ClampCheck_->setChecked(false);
    sendControlRequest(
        KSWORD_ARK_CPU_POWER_APPLY_POWER_LIMITS,
        powerText(
            QStringLiteral("hardware.power.confirm.raise"),
            QStringLiteral("即将把 PL1/PL2 提升到 CPU 报告的平台最大值 %1 W，并关闭 Clamp。此操作不清除 BIOS/MSR lock，也不保证主板、散热或固件允许持续运行。是否继续？"))
            .arg(kMaximumWatts, 0, 'f', 3));
}

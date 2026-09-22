#include "SystemTimePage.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../internationalization/LanguageManager.h"
#include "../../Theme.h"

#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHideEvent>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QRadioButton>
#include <QShowEvent>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace
{
    constexpr int kStatusRefreshIntervalMs = 2000;
    constexpr int kClockRefreshIntervalMs = 250;
    constexpr int kTimeSyncTimeoutMs = 15000;

    // addressText: converts an R0 diagnostic address to fixed-width hexadecimal text.
    QString addressText(const unsigned long long address)
    {
        return address == 0ULL
            ? ks::i18n::sourceText(QStringLiteral("不可用"))
            : QStringLiteral("0x%1")
                .arg(address, 16, 16, QLatin1Char('0'))
                .toUpper();
    }

    // hexValueText: Displays Hyper-V lock, multiplier, or offset values that are allowed to be zero.
    QString hexValueText(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0'))
            .toUpper();
    }
    // operationStatusText: Converts stable protocol status codes to scenario-specific error messages.
    QString operationStatusText(
        const unsigned long status,
        const long lastStatus)
    {
        QString reason;
        switch (status)
        {
        case KSWORD_ARK_SYSTEM_TIME_STATUS_OK:
            reason = QStringLiteral("操作成功");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_CONFIRMATION_REQUIRED:
            reason = QStringLiteral("安全策略要求重新确认");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_UNSUPPORTED_BUILD:
        case KSWORD_ARK_SYSTEM_TIME_STATUS_RESOLVE_FAILED:
            reason = QStringLiteral("当前 Windows 构建无法安全解析计时器");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_PATCH_FAILED:
            reason = QStringLiteral("计时器接管失败，已回滚");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_CONFLICT:
            reason = QStringLiteral("检测到其它计时器钩子，已失败关闭");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_STALE_GENERATION:
            reason = QStringLiteral("状态已被其它控制者更新，请刷新后重试");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_NOT_PRESENT:
            reason = QStringLiteral("未检测到 Microsoft Hyper-V，未启用变速");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_PAGE_UNAVAILABLE:
            reason = QStringLiteral("Hyper-V 共享 QPC 页不可用，未启用变速");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_VALIDATION_FAILED:
            reason = QStringLiteral("Hyper-V 共享 QPC 页校验冲突，已失败关闭");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_HYPERV_WRITE_FAILED:
            reason = QStringLiteral("Hyper-V 共享 QPC 页写入失败，已回滚");
            break;
        case KSWORD_ARK_SYSTEM_TIME_STATUS_INVALID_REQUEST:
            reason = QStringLiteral("倍率或控制参数无效");
            break;
        default:
            reason = QStringLiteral("系统变速状态不可用");
            break;
        }
        return ks::i18n::sourceText(QStringLiteral("%1；NTSTATUS=0x%2"))
            .arg(ks::i18n::sourceText(reason))
            .arg(
                static_cast<unsigned long>(lastStatus),
                8,
                16,
                QLatin1Char('0'))
            .toUpper();
    }

    // showOpaqueMessage: Explicitly set an opaque theme background for message boxes on high-risk pages.
    void showOpaqueMessage(
        QWidget* parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& text)
    {
        QMessageBox messageBox(parent);
        messageBox.setObjectName(
            QStringLiteral("ksSystemTimeMessageBox"));
        messageBox.setStyleSheet(
            ksword_theme::opaqueDialogStyle(
                messageBox.objectName()));
        messageBox.setIcon(icon);
        messageBox.setWindowTitle(title);
        messageBox.setText(text);
        messageBox.setStandardButtons(QMessageBox::Ok);
        messageBox.exec();
    }
}

namespace ks::misc
{
    SystemTimePage::SystemTimePage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
        initializeConnections();
    }

    void SystemTimePage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
        refreshTimer_->start();
        updateCalibratedTimeDisplay();
        clockTimer_->start();
    }

    void SystemTimePage::hideEvent(QHideEvent* event)
    {
        refreshTimer_->stop();
        clockTimer_->stop();
        QWidget::hideEvent(event);
    }

    void SystemTimePage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if (event->type() == QEvent::ApplicationPaletteChange
            || event->type() == QEvent::PaletteChange)
        {
            applyWarningBannerStyle();
        }
    }

    // applyWarningBannerStyle:
    // - Input: None. Reads semantic colors of the current theme.
    // - Handling: Apply permanent warning banner style; follows the same path during construction and after theme switching.
    // - Return: None. Silently skip if the banner has not been created.
    void SystemTimePage::applyWarningBannerStyle()
    {
        if (warningLabel_ == nullptr)
        {
            return;
        }
        warningLabel_->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;font-weight:600;}")
                .arg(ksword_theme::warningHex())
                .arg(ksword_theme::themeColorName(
                    ksword_theme::warningBackgroundColor()))
                .arg(ksword_theme::textPrimaryHex()));
    }

    void SystemTimePage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        // Permanent warning that does not disappear upon confirmation, ensuring the risk boundary remains visible while active.
        warningLabel_ = new QLabel(
            QStringLiteral(
                "⚠ 系统全局变速会接管内核性能计数器；Hyper-V 后端还会改写"
                "当前 Windows 分区的共享 QPC 倍率与偏置。它可能导致动画、超时、"
                "音视频、网络协议、游戏和安全软件异常，"
                "严重时会造成冻结或蓝屏。请先保存工作，强烈建议仅在虚拟机中使用。"),
            this);
        warningLabel_->setWordWrap(true);
        applyWarningBannerStyle();
        rootLayout->addWidget(warningLabel_);

        persistenceLabel_ = new QLabel(
            QStringLiteral(
                "关闭页面不会自动恢复速度；请使用“恢复 1x”。"
                "恢复 1x 会保留连续计数接管以避免回跳；驱动卸载时才恢复原始路径。"),
            this);
        persistenceLabel_->setWordWrap(true);
        persistenceLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(ksword_theme::textSecondaryHex()));
        rootLayout->addWidget(persistenceLabel_);

        // The backend group requires the user to explicitly choose between Hyper-V shared pages or the original HAL-compatible path.
        auto* backendGroup = new QGroupBox(
            QStringLiteral("计时后端"),
            this);
        auto* backendLayout = new QVBoxLayout(backendGroup);
        hypervBackendRadio_ = new QRadioButton(
            QStringLiteral("Hyper-V 共享 QPC（推荐）"),
            backendGroup);
        hypervBackendRadio_->setToolTip(
            QStringLiteral(
                "保留用户态 QPC 快速路径，接管 Hyper-V 共享倍率与偏置，并同步内核 HAL 计数器"));
        auto* hypervDescription = new QLabel(
            QStringLiteral(
                "要求 Microsoft Hyper-V 与共享 QPC 页均可用。用户态通过共享页变速，"
                "内核态通过 HAL 计数器钩子同步；任一校验失败都不会静默切到其它后端。"),
            backendGroup);
        hypervDescription->setWordWrap(true);
        hypervDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(ksword_theme::textSecondaryHex()));

        halBackendRadio_ = new QRadioButton(
            QStringLiteral("HAL 兼容后端（显式回退）"),
            backendGroup);
        halBackendRadio_->setToolTip(
            QStringLiteral(
                "关闭用户态 QPC 快速旁路，并使用原有 HAL 计数器接管路径"));
        auto* halDescription = new QLabel(
            QStringLiteral(
                "保留原有实现：关闭用户态快速旁路，使用户态和内核态都进入 HAL 计数器钩子。"
                "仅在你明确选择后启用，不会由 Hyper-V 后端自动降级。"),
            backendGroup);
        halDescription->setWordWrap(true);
        halDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(ksword_theme::textSecondaryHex()));
        hypervBackendRadio_->setChecked(true);
        backendLayout->addWidget(hypervBackendRadio_);
        backendLayout->addWidget(hypervDescription);
        backendLayout->addWidget(halBackendRadio_);
        backendLayout->addWidget(halDescription);
        rootLayout->addWidget(backendGroup);
        // The mode group clearly distinguishes between compatibility positioning and pre-write enhanced validation positioning.
        auto* schemeGroup = new QGroupBox(
            QStringLiteral("实现模式"),
            this);
        auto* schemeLayout = new QVBoxLayout(schemeGroup);
        compatRadio_ = new QRadioButton(
            QStringLiteral("兼容模式（默认）"),
            schemeGroup);
        compatRadio_->setToolTip(
            QStringLiteral(
                "按当前系统版本特征定位并接管 HAL 计数器函数指针"));
        auto* compatDescription = new QLabel(
            QStringLiteral(
                "使用基于系统版本特征的 HAL 计数器函数指针接管路径，"
                "兼容性最高；仍保留 KSword 的恢复与冲突监控。"),
            schemeGroup);
        compatDescription->setWordWrap(true);
        compatDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(ksword_theme::textSecondaryHex()));

        guardedResolutionRadio_ = new QRadioButton(
            QStringLiteral("安全模式（即使安全一些但是仍然可能导致严重后果）"),
            schemeGroup);
        guardedResolutionRadio_->setToolTip(
            QStringLiteral(
                "使用相同接管原理，但在写入前验证描述符、函数槽和处理器表"));
        auto* guardedDescription = new QLabel(
            QStringLiteral(
                "使用相同接管原理，但在写入前额外验证描述符、函数槽和处理器表；"
                "校验不通过时拒绝启用。该模式只能降低部分风险，仍可能冻结或蓝屏。"),
            schemeGroup);
        guardedDescription->setWordWrap(true);
        guardedDescription->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(ksword_theme::textSecondaryHex()));
        compatRadio_->setChecked(true);
        schemeLayout->addWidget(compatRadio_);
        schemeLayout->addWidget(compatDescription);
        schemeLayout->addWidget(guardedResolutionRadio_);
        schemeLayout->addWidget(guardedDescription);
        rootLayout->addWidget(schemeGroup);

        // The rate group only provides N-fold acceleration and 1/N deceleration under the same principle.
        auto* controlGroup = new QGroupBox(
            QStringLiteral("计时倍率"),
            this);
        auto* controlLayout = new QVBoxLayout(controlGroup);
        auto* modeLayout = new QHBoxLayout();
        speedUpRadio_ = new QRadioButton(
            QStringLiteral("加速 N 倍"),
            controlGroup);
        slowDownRadio_ = new QRadioButton(
            QStringLiteral("减速到 1/N"),
            controlGroup);
        speedUpRadio_->setChecked(true);
        factorSpin_ = new QSpinBox(controlGroup);
        factorSpin_->setRange(
            static_cast<int>(KSWORD_ARK_SYSTEM_TIME_MIN_FACTOR),
            static_cast<int>(KSWORD_ARK_SYSTEM_TIME_MAX_FACTOR));
        factorSpin_->setValue(2);
        factorSpin_->setSuffix(QStringLiteral(" ×"));
        factorSpin_->setToolTip(
            QStringLiteral("设置 2 到 64 的整数倍率"));
        modeLayout->addWidget(speedUpRadio_);
        modeLayout->addWidget(slowDownRadio_);
        modeLayout->addSpacing(12);
        modeLayout->addWidget(new QLabel(
            QStringLiteral("倍率："),
            controlGroup));
        modeLayout->addWidget(factorSpin_);
        modeLayout->addStretch(1);
        controlLayout->addLayout(modeLayout);

        acknowledgeCheck_ = new QCheckBox(
            QStringLiteral(
                "我已保存工作，并理解该功能可能使系统不稳定"),
            controlGroup);
        controlLayout->addWidget(acknowledgeCheck_);

        auto* buttonLayout = new QHBoxLayout();
        refreshButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QStringLiteral("刷新状态"),
            controlGroup);
        timeSyncButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QStringLiteral("从时间服务器更新时间"),
            controlGroup);
        applyButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QStringLiteral("应用变速"),
            controlGroup);
        resetButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
            QStringLiteral("恢复 1x"),
            controlGroup);
        refreshButton_->setToolTip(
            QStringLiteral("重新查询 R0 计时器接管状态"));
        timeSyncButton_->setToolTip(
            QStringLiteral("调用 Windows 时间服务，从已配置的时间服务器立即同步系统时间"));
        applyButton_->setToolTip(
            QStringLiteral("经过双重确认后应用当前模式和倍率"));
        resetButton_->setToolTip(
            QStringLiteral("立即停止变速并以连续计数保持 1x"));
        for (QPushButton* button :
             { refreshButton_, timeSyncButton_, applyButton_, resetButton_ })
        {
            button->setStyleSheet(
                ksword_theme::themedButtonStyle());
        }
        buttonLayout->addWidget(refreshButton_);
        buttonLayout->addWidget(timeSyncButton_);
        buttonLayout->addWidget(applyButton_);
        buttonLayout->addWidget(resetButton_);
        buttonLayout->addStretch(1);
        controlLayout->addLayout(buttonLayout);
        rootLayout->addWidget(controlGroup);

        // Status group displays both user conclusions and verifiable parsing evidence.
        auto* statusGroup = new QGroupBox(
            QStringLiteral("当前状态"),
            this);
        auto* statusLayout = new QVBoxLayout(statusGroup);
        calibratedTimeLabel_ = new QLabel(
            QStringLiteral("校准后时间：等待倍率状态"),
            statusGroup);
        calibratedTimeLabel_->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(ksword_theme::kPrimaryBlueHex));
        currentModeLabel_ = new QLabel(
            QStringLiteral("当前：等待查询"),
            statusGroup);
        currentModeLabel_->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
                .arg(ksword_theme::textPrimaryHex()));
        backendLabel_ = new QLabel(statusGroup);
        backendLabel_->setWordWrap(true);
        diagnosticLabel_ = new QLabel(statusGroup);
        diagnosticLabel_->setWordWrap(true);
        diagnosticLabel_->setTextInteractionFlags(
            Qt::TextSelectableByMouse);
        operationLabel_ = new QLabel(
            QStringLiteral("尚未查询 R0 状态"),
            statusGroup);
        operationLabel_->setWordWrap(true);
        statusLayout->addWidget(calibratedTimeLabel_);
        statusLayout->addWidget(currentModeLabel_);
        statusLayout->addWidget(backendLabel_);
        statusLayout->addWidget(diagnosticLabel_);
        statusLayout->addWidget(operationLabel_);
        rootLayout->addWidget(statusGroup);
        rootLayout->addStretch(1);

        refreshTimer_ = new QTimer(this);
        refreshTimer_->setInterval(
            kStatusRefreshIntervalMs);
        clockTimer_ = new QTimer(this);
        clockTimer_->setInterval(kClockRefreshIntervalMs);
        resetCalibratedClock();
        updateButtons();
    }

    void SystemTimePage::initializeConnections()
    {
        connect(
            timeSyncButton_,
            &QPushButton::clicked,
            this,
            [this]() { synchronizeFromTimeServer(); });
        connect(
            refreshButton_,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            applyButton_,
            &QPushButton::clicked,
            this,
            [this]() { applyRequestedMode(); });
        connect(
            resetButton_,
            &QPushButton::clicked,
            this,
            [this]() { resetSystemTime(); });
        connect(
            acknowledgeCheck_,
            &QCheckBox::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            hypervBackendRadio_,
            &QRadioButton::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            refreshTimer_,
            &QTimer::timeout,
            this,
            [this]() { refreshStatus(); });
        connect(
            clockTimer_,
            &QTimer::timeout,
            this,
            [this]() { updateCalibratedTimeDisplay(); });
    }

    void SystemTimePage::refreshStatus()
    {
        if (busy_)
        {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto kResult = client.querySystemTime();
        setBusy(false);

        if (!kResult.io.ok)
        {
            supported_ = false;
            hypervAvailable_ = false;
            operationLabel_->setText(
                kResult.unsupported
                    ? ks::i18n::sourceText(QStringLiteral(
                        "当前 KswordARK 驱动不支持系统全局变速，请更新 R0。"))
                    : ks::i18n::sourceText(QStringLiteral("R0 查询失败：%1"))
                        .arg(QString::fromStdString(
                            kResult.io.message)));
            updateButtons();
            return;
        }

        generation_ = kResult.response.generation;
        supported_ =
            (kResult.response.stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_SUPPORTED) != 0UL;
        updateStatusDisplay(
            kResult.response.status,
            kResult.response.stateFlags,
            kResult.response.generation,
            kResult.response.command,
            kResult.response.factor,
            kResult.response.osBuildNumber,
            kResult.response.lastStatus,
            kResult.response.resolutionMode,
            kResult.response.backend,
            kResult.response.counterSourceAddress,
            kResult.response.primarySlotAddress,
            kResult.response.secondarySlotAddress,
            kResult.response.hypervisorSharedPageAddress,
            kResult.response.hypervisorTimeUpdateLock,
            kResult.response.hypervisorOriginalMultiplier,
            kResult.response.hypervisorOriginalBias,
            kResult.response.hypervisorCurrentMultiplier,
            kResult.response.hypervisorCurrentBias);
        updateButtons();
    }

    void SystemTimePage::applyRequestedMode()
    {
        const unsigned long kFactor =
            static_cast<unsigned long>(factorSpin_->value());
        const unsigned long kCommand =
            speedUpRadio_->isChecked()
            ? KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP
            : KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN;
        const QString kModeText = ks::i18n::sourceText(
            speedUpRadio_->isChecked()
            ? QStringLiteral("加速")
            : QStringLiteral("减速"));
        const unsigned long kBackend =
            hypervBackendRadio_->isChecked()
            ? KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC
            : KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT;
        const QString kBackendText = ks::i18n::sourceText(
            hypervBackendRadio_->isChecked()
            ? QStringLiteral("Hyper-V 共享 QPC")
            : QStringLiteral("HAL 兼容后端"));
        const unsigned long kResolutionMode =
            compatRadio_->isChecked()
            ? KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT
            : KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED;
        const QString kSchemeText = ks::i18n::sourceText(
            compatRadio_->isChecked()
            ? QStringLiteral("兼容模式")
            : QStringLiteral("安全模式"));

        if (!acknowledgeCheck_->isChecked() ||
            !confirmHighRisk(
                kModeText,
                kBackendText,
                kSchemeText,
                kFactor))
        {
            return;
        }

        setBusy(true);
        KLogEvent controlEvent;
        ksword::ark::DriverClient client;
        const auto kFreshStatus = client.querySystemTime();
        if (!kFreshStatus.io.ok)
        {
            setBusy(false);
            warn << controlEvent
                << "[SystemTimePage] 控制前状态查询失败: "
                << kFreshStatus.io.message << eol;
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::sourceText(QStringLiteral("系统全局变速")),
                ks::i18n::sourceText(
                    QStringLiteral("控制前无法读取 R0 状态，未执行任何修改。")));
            return;
        }

        const auto kResult = client.controlSystemTime(
            kCommand,
            kFactor,
            kBackend,
            kResolutionMode,
            kFreshStatus.response.generation,
            true);
        setBusy(false);
        if (!kResult.io.ok ||
            kResult.response.status !=
                KSWORD_ARK_SYSTEM_TIME_STATUS_OK)
        {
            warn << controlEvent
                << "[SystemTimePage] 系统变速失败: "
                << kResult.io.message << eol;
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::sourceText(QStringLiteral("系统全局变速")),
                kResult.io.ok
                    ? operationStatusText(
                        kResult.response.status,
                        kResult.response.lastStatus)
                    : ks::i18n::sourceText(QStringLiteral("R0 控制失败：%1"))
                        .arg(QString::fromStdString(
                            kResult.io.message)));
            refreshStatus();
            return;
        }

        info << controlEvent
            << "[SystemTimePage] 系统变速已应用, mode="
            << kModeText.toStdString()
            << ", backend=" << kBackendText.toStdString()
            << ", scheme=" << kSchemeText.toStdString()
            << ", factor=" << kFactor << eol;
        operationLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("已应用：%1；%2；%3 %4 倍"))
                .arg(kBackendText)
                .arg(kSchemeText)
                .arg(kModeText)
                .arg(kFactor));
        refreshStatus();
    }

    void SystemTimePage::resetSystemTime()
    {
        setBusy(true);
        KLogEvent resetEvent;
        ksword::ark::DriverClient client;
        const auto kResult = client.controlSystemTime(
            KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET,
            1UL,
            currentBackend_,
            compatRadio_->isChecked()
                ? KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT
                : KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED,
            generation_,
            false);
        setBusy(false);

        if (!kResult.io.ok ||
            kResult.response.status !=
                KSWORD_ARK_SYSTEM_TIME_STATUS_OK)
        {
            warn << resetEvent
                << "[SystemTimePage] 恢复 1x 失败: "
                << kResult.io.message << eol;
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::sourceText(QStringLiteral("恢复系统计时")),
                kResult.io.ok
                    ? operationStatusText(
                        kResult.response.status,
                        kResult.response.lastStatus)
                    : ks::i18n::sourceText(QStringLiteral("R0 控制失败：%1"))
                        .arg(QString::fromStdString(
                            kResult.io.message)));
            refreshStatus();
            return;
        }

        info << resetEvent
            << "[SystemTimePage] 已停止变速并切换到连续 1x 计时。" << eol;
        operationLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("已停止变速，当前以连续计数保持 1x")));
        acknowledgeCheck_->setChecked(false);
        refreshStatus();
    }

    void SystemTimePage::synchronizeFromTimeServer()
    {
        if (busy_ || timeSyncProcess_ != nullptr)
        {
            return;
        }

        setBusy(true);
        operationLabel_->setText(ks::i18n::sourceText(
            QStringLiteral("正在请求 Windows 时间服务器同步...")));

        auto* process = new QProcess(this);
        timeSyncProcess_ = process;
        process->setProcessChannelMode(QProcess::MergedChannels);
        process->setProgram(QStringLiteral("w32tm.exe"));
        process->setArguments({
            QStringLiteral("/resync"),
            QStringLiteral("/rediscover") });

        auto* timeoutTimer = new QTimer(process);
        timeoutTimer->setSingleShot(true);
        timeoutTimer->setInterval(kTimeSyncTimeoutMs);
        connect(
            timeoutTimer,
            &QTimer::timeout,
            process,
            [this, process]()
            {
                if (timeSyncProcess_ != process)
                {
                    return;
                }
                process->setProperty("ksTimeSyncTimedOut", true);
                process->kill();
            });
        connect(
            process,
            &QProcess::errorOccurred,
            this,
            [this, process](const QProcess::ProcessError error)
            {
                if (error != QProcess::FailedToStart ||
                    timeSyncProcess_ != process)
                {
                    return;
                }
                completeTimeSynchronization(
                    process,
                    false,
                    ks::i18n::sourceText(
                        QStringLiteral("无法启动 Windows 时间服务命令 w32tm.exe")));
            });
        connect(
            process,
            qOverload<int, QProcess::ExitStatus>(&QProcess::finished),
            this,
            [this, process](
                const int exitCode,
                const QProcess::ExitStatus exitStatus)
            {
                if (timeSyncProcess_ != process)
                {
                    return;
                }
                const bool kTimedOut =
                    process->property("ksTimeSyncTimedOut").toBool();
                const QString kOutput = QString::fromLocal8Bit(
                    process->readAll()).trimmed();
                completeTimeSynchronization(
                    process,
                    !kTimedOut &&
                        exitStatus == QProcess::NormalExit &&
                        exitCode == 0,
                    kTimedOut
                        ? ks::i18n::sourceText(
                            QStringLiteral("等待时间服务器响应超时（15 秒）"))
                        : kOutput);
            });

        timeoutTimer->start();
        process->start();
    }

    void SystemTimePage::completeTimeSynchronization(
        QProcess* process,
        const bool success,
        const QString& detailText)
    {
        if (process == nullptr || timeSyncProcess_ != process)
        {
            return;
        }

        timeSyncProcess_ = nullptr;
        process->deleteLater();
        setBusy(false);

        KLogEvent timeSyncEvent;
        if (success)
        {
            resetCalibratedClock();
            operationLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("已从 Windows 时间服务器同步系统时间")));
            info << timeSyncEvent
                << "[SystemTimePage] Windows 时间服务器同步成功。"
                << eol;
            return;
        }

        const QString kFailureDetail = detailText.trimmed().isEmpty()
            ? ks::i18n::sourceText(
                QStringLiteral("Windows 时间服务未返回详细错误"))
            : detailText.trimmed();
        warn << timeSyncEvent
            << "[SystemTimePage] Windows 时间服务器同步失败: "
            << kFailureDetail.toStdString() << eol;
        operationLabel_->setText(
            ks::i18n::sourceText(QStringLiteral("时间服务器同步失败：%1"))
                .arg(kFailureDetail));
        showOpaqueMessage(
            this,
            QMessageBox::Warning,
            ks::i18n::sourceText(QStringLiteral("更新时间失败")),
            ks::i18n::sourceText(QStringLiteral(
                "未能从 Windows 已配置的时间服务器更新时间。\n\n%1\n\n"
                "请确认 Windows Time 服务正在运行，并以管理员身份重试。"))
                .arg(kFailureDetail));
    }

    void SystemTimePage::resetCalibratedClock()
    {
        calibratedAnchorEpochMs_ =
            QDateTime::currentMSecsSinceEpoch();
        calibratedElapsedTimer_.start();
        updateCalibratedTimeDisplay();
    }

    void SystemTimePage::updateCalibratedTimeDisplay()
    {
        if (calibratedTimeLabel_ == nullptr)
        {
            return;
        }
        if (!calibratedElapsedTimer_.isValid())
        {
            calibratedAnchorEpochMs_ =
                QDateTime::currentMSecsSinceEpoch();
            calibratedElapsedTimer_.start();
        }

        const qint64 kMeasuredElapsedMs =
            std::max<qint64>(0, calibratedElapsedTimer_.elapsed());
        qint64 calibratedElapsedMs = kMeasuredElapsedMs;
        QString calibrationMode = ks::i18n::sourceText(
            QStringLiteral("原始速度 1x"));
        if (active_ &&
            currentCommand_ ==
                KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP &&
            currentFactor_ > 1UL)
        {
            calibratedElapsedMs /=
                static_cast<qint64>(currentFactor_);
            calibrationMode = ks::i18n::sourceText(
                QStringLiteral("加速 %1 倍"))
                .arg(currentFactor_);
        }
        else if (active_ &&
                 currentCommand_ ==
                    KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN &&
                 currentFactor_ > 1UL)
        {
            const qint64 kFactor =
                static_cast<qint64>(currentFactor_);
            calibratedElapsedMs = kMeasuredElapsedMs >
                std::numeric_limits<qint64>::max() / kFactor
                ? std::numeric_limits<qint64>::max()
                : kMeasuredElapsedMs * kFactor;
            calibrationMode = ks::i18n::sourceText(
                QStringLiteral("减速到 1/%1"))
                .arg(currentFactor_);
        }

        const qint64 kMaximumAddition =
            std::numeric_limits<qint64>::max() -
            calibratedAnchorEpochMs_;
        const qint64 kCalibratedEpochMs =
            calibratedAnchorEpochMs_ +
            std::min(calibratedElapsedMs, kMaximumAddition);
        const QString kCalibratedTimeText =
            QDateTime::fromMSecsSinceEpoch(kCalibratedEpochMs)
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        calibratedTimeLabel_->setText(
            ks::i18n::sourceText(
                QStringLiteral("校准后时间：%1（按当前 %2 校准）"))
                .arg(kCalibratedTimeText, calibrationMode));
    }

    bool SystemTimePage::confirmHighRisk(
        const QString& modeText,
        const QString& backendText,
        const QString& schemeText,
        const unsigned long factor)
    {
        QMessageBox warningBox(this);
        warningBox.setObjectName(
            QStringLiteral("ksSystemTimeRiskDialog"));
        warningBox.setStyleSheet(
            ksword_theme::opaqueDialogStyle(
                warningBox.objectName()));
        warningBox.setIcon(QMessageBox::Warning);
        warningBox.setWindowTitle(ks::i18n::sourceText(
            QStringLiteral("系统全局变速风险确认")));
        warningBox.setText(
            ks::i18n::sourceText(QStringLiteral(
                "即将使用“%1”后端与“%2”，对整个系统%3 %4 倍。\n\n"
                "此操作会改变全局性能计数器的时间流速，"
                "可能破坏超时、同步、网络、音视频和安全软件行为。\n"
                "请确认已保存工作，并准备在异常时立即恢复 1x。"))
                .arg(backendText)
                .arg(schemeText)
                .arg(modeText)
                .arg(factor));
        warningBox.setStandardButtons(
            QMessageBox::Ok | QMessageBox::Cancel);
        warningBox.setDefaultButton(QMessageBox::Cancel);
        if (warningBox.exec() != QMessageBox::Ok)
        {
            return false;
        }

        // Final confirmation changed to direct click: no longer requires entering a confirmation phrase; defaults to focusing 'No' to prevent accidental triggers.
        QMessageBox finalBox(this);
        finalBox.setIcon(QMessageBox::Warning);
        finalBox.setWindowTitle(ks::i18n::sourceText(QStringLiteral("最终确认")));
        finalBox.setText(ks::i18n::sourceText(
            QStringLiteral("确认修改系统时间相关设置？该操作会影响全局时间行为。")));
        finalBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
        finalBox.setDefaultButton(QMessageBox::No);
        return finalBox.exec() == QMessageBox::Yes;
    }

    void SystemTimePage::updateStatusDisplay(
        const unsigned long status,
        const unsigned long stateFlags,
        const unsigned long generation,
        const unsigned long command,
        const unsigned long factor,
        const unsigned long osBuildNumber,
        const long lastStatus,
        const unsigned long resolutionMode,
        const unsigned long backend,
        const unsigned long long counterSourceAddress,
        const unsigned long long primarySlotAddress,
        const unsigned long long secondarySlotAddress,
        const unsigned long long hypervisorSharedPageAddress,
        const unsigned long long hypervisorTimeUpdateLock,
        const unsigned long long hypervisorOriginalMultiplier,
        const unsigned long long hypervisorOriginalBias,
        const unsigned long long hypervisorCurrentMultiplier,
        const unsigned long long hypervisorCurrentBias)
    {
        const bool kActive =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_ACTIVE) != 0UL;
        const bool kConflict =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_CONFLICT) != 0UL;
        const bool kHypervPresent =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_PRESENT) != 0UL;
        const bool kHypervSharedPage =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_SHARED_PAGE) != 0UL;
        const bool kHypervActive =
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HYPERV_ACTIVE) != 0UL;
        const bool kCalibrationChanged =
            !calibratedElapsedTimer_.isValid() ||
            calibrationGeneration_ != generation ||
            active_ != kActive ||
            currentCommand_ != command ||
            currentFactor_ != factor ||
            currentBackend_ != backend;
        const QString kSchemeText = ks::i18n::sourceText(
            resolutionMode ==
                KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED
            ? QStringLiteral("安全模式")
            : resolutionMode ==
                KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT
                ? QStringLiteral("兼容模式")
                : QStringLiteral("未知"));
        const QString kBackendText = ks::i18n::sourceText(
            backend ==
                KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC
            ? QStringLiteral("Hyper-V 共享 QPC")
            : backend ==
                KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT
                ? QStringLiteral("HAL 兼容后端")
                : QStringLiteral("未知"));
        const QString kHypervStateText = ks::i18n::sourceText(kHypervActive
            ? QStringLiteral("共享页已接管")
            : kHypervSharedPage
                ? QStringLiteral("共享页可用")
                : kHypervPresent
                    ? QStringLiteral("已检测，但共享页不可用")
                    : QStringLiteral("未检测到 Microsoft Hyper-V"));
        const QString kKernelPathText = ks::i18n::sourceText(
            (stateFlags &
                KSWORD_ARK_SYSTEM_TIME_STATE_HANDLER_TABLE) != 0UL
            ? QStringLiteral("HAL 处理器表")
            : QStringLiteral("HAL 计数器槽"));

        hypervAvailable_ = kHypervPresent && kHypervSharedPage;
        active_ = kActive;
        currentCommand_ = kActive
            ? command
            : KSWORD_ARK_SYSTEM_TIME_COMMAND_RESET;
        currentFactor_ = kActive
            ? std::max(1UL, factor)
            : 1UL;
        currentBackend_ = backend;
        calibrationGeneration_ = generation;
        if (kCalibrationChanged)
        {
            resetCalibratedClock();
        }
        else
        {
            updateCalibratedTimeDisplay();
        }
        if (kActive)
        {
            hypervBackendRadio_->setChecked(
                backend ==
                    KSWORD_ARK_SYSTEM_TIME_BACKEND_HYPERV_SHARED_QPC);
            halBackendRadio_->setChecked(
                backend ==
                    KSWORD_ARK_SYSTEM_TIME_BACKEND_HAL_COMPAT);
            compatRadio_->setChecked(
                resolutionMode ==
                    KSWORD_ARK_SYSTEM_TIME_RESOLUTION_ORIGINAL_COMPAT);
            guardedResolutionRadio_->setChecked(
                resolutionMode ==
                    KSWORD_ARK_SYSTEM_TIME_RESOLUTION_GUARDED);
        }
        else if (!hypervAvailable_ &&
                 hypervBackendRadio_->isChecked())
        {
            halBackendRadio_->setChecked(true);
        }

        if (kActive &&
            command == KSWORD_ARK_SYSTEM_TIME_COMMAND_SPEED_UP)
        {
            currentModeLabel_->setText(
                ks::i18n::sourceText(QStringLiteral("当前：全局加速 %1 倍"))
                    .arg(factor));
        }
        else if (kActive &&
                 command ==
                    KSWORD_ARK_SYSTEM_TIME_COMMAND_SLOW_DOWN)
        {
            currentModeLabel_->setText(
                ks::i18n::sourceText(QStringLiteral("当前：全局减速到 1/%1"))
                    .arg(factor));
        }
        else
        {
            currentModeLabel_->setText(ks::i18n::sourceText(
                QStringLiteral("当前：原始速度 1x")));
        }

        currentModeLabel_->setStyleSheet(
            QStringLiteral("font-size:16px;font-weight:700;color:%1;")
                .arg(kConflict
                    ? ksword_theme::errorHex()
                    : kActive
                        ? ksword_theme::warningHex()
                        : ksword_theme::successHex()));
        backendLabel_->setText(
            ks::i18n::sourceText(QStringLiteral(
                "Windows 构建：%1；后端：%2；实现模式：%3；"
                "内核计时路径：%4；Hyper-V：%5；状态代次：%6"))
                .arg(osBuildNumber)
                .arg(kBackendText)
                .arg(kSchemeText)
                .arg(kKernelPathText)
                .arg(kHypervStateText)
                .arg(generation));
        if (kHypervSharedPage)
        {
            diagnosticLabel_->setText(
                ks::i18n::sourceText(QStringLiteral(
                    "计时描述符：%1；主槽：%2；辅助槽：%3；"
                    "Hyper-V 共享页：%4；更新锁：%5；"
                    "原倍率：%6；当前倍率：%7；原偏置：%8；当前偏置：%9"))
                    .arg(addressText(counterSourceAddress))
                    .arg(addressText(primarySlotAddress))
                    .arg(addressText(secondarySlotAddress))
                    .arg(addressText(hypervisorSharedPageAddress))
                    .arg(hexValueText(hypervisorTimeUpdateLock))
                    .arg(hexValueText(hypervisorOriginalMultiplier))
                    .arg(hexValueText(hypervisorCurrentMultiplier))
                    .arg(hexValueText(hypervisorOriginalBias))
                    .arg(hexValueText(hypervisorCurrentBias)));
        }
        else
        {
            diagnosticLabel_->setText(
                ks::i18n::sourceText(QStringLiteral(
                    "计时描述符：%1；主槽：%2；辅助槽：%3；"
                    "Hyper-V 共享页：不可用"))
                    .arg(addressText(counterSourceAddress))
                    .arg(addressText(primarySlotAddress))
                    .arg(addressText(secondarySlotAddress)));
        }
        operationLabel_->setText(
            operationStatusText(status, lastStatus));
    }

    void SystemTimePage::updateButtons()
    {
        refreshButton_->setEnabled(!busy_);
        timeSyncButton_->setEnabled(
            !busy_ && timeSyncProcess_ == nullptr);
        applyButton_->setEnabled(
            !busy_ &&
            supported_ &&
            acknowledgeCheck_->isChecked() &&
            (!hypervBackendRadio_->isChecked() ||
                hypervAvailable_));
        resetButton_->setEnabled(
            !busy_ &&
            supported_);
        factorSpin_->setEnabled(!busy_);
        speedUpRadio_->setEnabled(!busy_);
        slowDownRadio_->setEnabled(!busy_);
        hypervBackendRadio_->setEnabled(
            !busy_ && !active_ && hypervAvailable_);
        halBackendRadio_->setEnabled(
            !busy_ && !active_);
        compatRadio_->setEnabled(
            !busy_ && !active_);
        guardedResolutionRadio_->setEnabled(
            !busy_ && !active_);
        acknowledgeCheck_->setEnabled(!busy_);
    }

    void SystemTimePage::setBusy(const bool busy)
    {
        busy_ = busy;
        updateButtons();
    }
}

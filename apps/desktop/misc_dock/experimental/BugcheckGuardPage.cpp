#include "BugcheckGuardPage.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../internationalization/LanguageManager.h"
#include "../../Theme.h"

#include <QCheckBox>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QShowEvent>
#include <QSpinBox>
#include <QTimer>
#include <QVBoxLayout>

#include <Windows.h>

#include <limits>

namespace
{
    bool sendWinPrintScreen()
    {
        INPUT inputs[4]{};
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].ki.wVk = VK_LWIN;
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].ki.wVk = VK_SNAPSHOT;
        inputs[2].type = INPUT_KEYBOARD;
        inputs[2].ki.wVk = VK_SNAPSHOT;
        inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;
        inputs[3].type = INPUT_KEYBOARD;
        inputs[3].ki.wVk = VK_LWIN;
        inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;

        const UINT kSent = SendInput(4U, inputs, sizeof(INPUT));
        if (kSent != 4U) {
            INPUT releases[2]{};
            releases[0].type = INPUT_KEYBOARD;
            releases[0].ki.wVk = VK_SNAPSHOT;
            releases[0].ki.dwFlags = KEYEVENTF_KEYUP;
            releases[1].type = INPUT_KEYBOARD;
            releases[1].ki.wVk = VK_LWIN;
            releases[1].ki.dwFlags = KEYEVENTF_KEYUP;
            (void)SendInput(2U, releases, sizeof(INPUT));
        }
        return kSent == 4U;
    }

    QString bugcheckGuardStatusText(
        const unsigned long status,
        const long lastStatus,
        const unsigned long stateFlags)
    {
        QString reason;
        const bool kHvciEnabled =
            (stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED) != 0UL;
        const bool kCallbackRegistered =
            (stateFlags &
                KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED) != 0UL;
        switch (status) {
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE:
            reason = kCallbackRegistered
                ? ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.status.active_callback"),
                    QStringLiteral(
                        "已启用：蓝屏前会暂停几秒，之后仍会蓝屏"))
                : ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.active"),
                    QStringLiteral("拦截已开启，等待蓝屏触发"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE:
            reason = kHvciEnabled
                ? ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.status.inactive_hvci"),
                    QStringLiteral(
                        "内存完整性（HVCI）已开启：可以暂停，但不能忽略蓝屏"))
                : ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.inactive"),
                    QStringLiteral("未启用"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFIRMATION_NEEDED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.confirm"),
                QStringLiteral("请先勾选“我已保存工作”"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_UNSUPPORTED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.unsupported"),
                QStringLiteral("当前系统无法启用这个功能"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_CONFLICT:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.conflict"),
                QStringLiteral("检测到其他内核修改，为避免冲突没有启用"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_PATCH_FAILED:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.patch_failed"),
                QStringLiteral("启用失败"));
            break;
        case KSWORD_ARK_BUGCHECK_GUARD_STATUS_BUSY:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.busy"),
                QStringLiteral("上一次操作还没结束，请先关闭后重试"));
            break;
        default:
            reason = ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.invalid"),
                QStringLiteral("无法读取状态"));
            break;
        }
        if (lastStatus == 0L) {
            return reason;
        }
        const QString kErrorCode = QStringLiteral("%1")
            .arg(
                static_cast<unsigned long>(lastStatus),
                8,
                16,
                QLatin1Char('0'))
            .toUpper();
        return QStringLiteral("%1（错误代码：0x%2）")
            .arg(reason, kErrorCode);
    }

    void showOpaqueMessage(
        QWidget* parent,
        const QMessageBox::Icon icon,
        const QString& title,
        const QString& message)
    {
        QMessageBox dialog(parent);
        dialog.setObjectName(QStringLiteral("ksBugcheckGuardMessageBox"));
        dialog.setStyleSheet(
            ksword_theme::opaqueDialogStyle(dialog.objectName()));
        dialog.setIcon(icon);
        dialog.setWindowTitle(title);
        dialog.setText(message);
        dialog.setStandardButtons(QMessageBox::Ok);
        dialog.exec();
    }
}

namespace ks::misc
{
    BugcheckGuardPage::BugcheckGuardPage(QWidget* parent)
        : QWidget(parent)
    {
        initializeUi();
    }

    void BugcheckGuardPage::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        refreshStatus();
    }

    void BugcheckGuardPage::changeEvent(QEvent* event)
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
    // - Processing: Apply risk banner style; the construction phase and theme switch follow the same path.
    // - Return: None. Silently skip if the banner has not been created.
    void BugcheckGuardPage::applyWarningBannerStyle()
    {
        if (warningLabel_ == nullptr)
        {
            return;
        }
        warningLabel_->setStyleSheet(
            QStringLiteral(
                "QLabel{padding:10px;border:1px solid %1;border-radius:5px;"
                "background:%2;color:%3;font-weight:650;}")
                .arg(ksword_theme::errorHex())
                .arg(ksword_theme::themeColorName(
                    ksword_theme::warningBackgroundColor()))
                .arg(ksword_theme::textPrimaryHex()));
    }

    void BugcheckGuardPage::initializeUi()
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(12, 12, 12, 12);
        rootLayout->setSpacing(10);

        auto& language = ks::i18n::LanguageManager::instance();
        warningLabel_ = new QLabel(this);
        warningLabel_->setWordWrap(true);
        applyWarningBannerStyle();
        language.bindText(
            warningLabel_,
            QStringLiteral("misc.experimental.bugcheck.warning"),
            QStringLiteral(
                "⚠ 这个功能不能修好蓝屏，只能在蓝屏前暂停几秒。"
                "开启“内存完整性（HVCI）”时只能暂停，不能忽略。"
                "要尝试继续运行，必须先关闭“内存完整性”并重启；"
                "即使如此，电脑仍可能马上蓝屏、死机或丢失数据。只在测试机上使用。"));
        rootLayout->addWidget(warningLabel_);

        persistenceLabel_ = new QLabel(this);
        persistenceLabel_->setWordWrap(true);
        persistenceLabel_->setStyleSheet(
            QStringLiteral("color:%1;")
                .arg(ksword_theme::textSecondaryHex()));
        language.bindText(
            persistenceLabel_,
            QStringLiteral("misc.experimental.bugcheck.persistence"),
            QStringLiteral(
                "开启后持续拦截：尝试继续运行时保留 Hook，后续触发仍会拦截，直到手动关闭。仅暂停模式仍会在暂停后进入蓝屏。"));
        rootLayout->addWidget(persistenceLabel_);

        auto* controlGroup = new QGroupBox(this);
        language.bindText(
            controlGroup,
            QStringLiteral("misc.experimental.bugcheck.control.title"),
            QStringLiteral("实验性控制"));
        auto* controlLayout = new QVBoxLayout(controlGroup);
        auto* delayLayout = new QHBoxLayout();
        delayLabel_ = new QLabel(controlGroup);
        language.bindText(
            delayLabel_,
            QStringLiteral("misc.experimental.bugcheck.delay"),
            QStringLiteral("蓝屏前暂停："));
        delaySpin_ = new QSpinBox(controlGroup);
        delaySpin_->setRange(
            static_cast<int>(KSWORD_ARK_BUGCHECK_GUARD_MIN_DELAY_SECONDS),
            std::numeric_limits<int>::max());
        delaySpin_->setValue(10);
        language.bindSuffix(
            delaySpin_,
            QStringLiteral("misc.experimental.bugcheck.delay.suffix"),
            QStringLiteral(" 秒"));
        delaySpin_->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.delay.tooltip"),
                QStringLiteral(
                    "没有 30 秒上限。时间设得很长时，电脑会一直卡在蓝屏流程里。")));
        delayLayout->addWidget(delayLabel_);
        delayLayout->addWidget(delaySpin_);
        delayLayout->addStretch(1);
        controlLayout->addLayout(delayLayout);

        acknowledgeCheck_ = new QCheckBox(controlGroup);
        language.bindText(
            acknowledgeCheck_,
            QStringLiteral("misc.experimental.bugcheck.ack"),
            QStringLiteral(
                "我已保存工作，并知道电脑仍可能立即蓝屏或丢失数据"));
        controlLayout->addWidget(acknowledgeCheck_);

        tryIgnoreErrorCheck_ = new QCheckBox(controlGroup);
        tryIgnoreErrorCheck_->setChecked(true);
        language.bindText(
            tryIgnoreErrorCheck_,
            QStringLiteral("misc.experimental.bugcheck.try_ignore"),
            QStringLiteral(
                "暂停后尝试继续运行（仅关闭 HVCI 时可用，极危险）"));
        tryIgnoreErrorCheck_->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.try_ignore.tooltip"),
                QStringLiteral(
                    "开启“内存完整性（HVCI）”时不可用。关闭后强行继续也可能马上再次蓝屏、"
                    "死机或损坏数据。")));
        controlLayout->addWidget(tryIgnoreErrorCheck_);

        screenshotOnTriggerCheck_ = new QCheckBox(controlGroup);
        language.bindText(
            screenshotOnTriggerCheck_,
            QStringLiteral("misc.experimental.bugcheck.screenshot"),
            QStringLiteral("蓝屏前尝试截图（仅关闭 HVCI 时可用）"));
        screenshotOnTriggerCheck_->setToolTip(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.screenshot.tooltip"),
                QStringLiteral(
                    "这里只是模拟 Win+PrintScreen。系统已经卡住时不会成功，"
                    "也无法确认截图是否保存。")));
        controlLayout->addWidget(screenshotOnTriggerCheck_);

        screenshotPollTimer_ = new QTimer(this);
        screenshotPollTimer_->setInterval(10);
        screenshotPollTimer_->setTimerType(Qt::PreciseTimer);

        auto* actionLayout = new QHBoxLayout();
        refreshButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
            QString(),
            controlGroup);
        enableButton_ = new QPushButton(
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            QString(),
            controlGroup);
        enableButton_->setCheckable(true);
        language.bindText(
            refreshButton_,
            QStringLiteral("misc.experimental.bugcheck.refresh"),
            QStringLiteral("刷新状态"));
        language.bindText(
            enableButton_,
            QStringLiteral("misc.experimental.bugcheck.switch"),
            QStringLiteral("拦截开关"));
        for (QPushButton* button :
             { refreshButton_, enableButton_ }) {
            button->setStyleSheet(ksword_theme::themedButtonStyle());
        }
        actionLayout->addWidget(refreshButton_);
        actionLayout->addWidget(enableButton_);
        actionLayout->addStretch(1);
        controlLayout->addLayout(actionLayout);
        rootLayout->addWidget(controlGroup);

        auto* statusGroup = new QGroupBox(this);
        language.bindText(
            statusGroup,
            QStringLiteral("misc.experimental.bugcheck.status.title"),
            QStringLiteral("当前状态"));
        auto* statusLayout = new QVBoxLayout(statusGroup);
        statusLabel_ = new QLabel(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.status.waiting"),
                QStringLiteral("正在读取状态…")),
            statusGroup);
        statusLabel_->setWordWrap(true);
        statusLabel_->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(ksword_theme::textPrimaryHex()));
        detailLabel_ = new QLabel(statusGroup);
        detailLabel_->setWordWrap(true);
        detailLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        statusLayout->addWidget(statusLabel_);
        statusLayout->addWidget(detailLabel_);
        rootLayout->addWidget(statusGroup);
        rootLayout->addStretch(1);

        connect(
            refreshButton_,
            &QPushButton::clicked,
            this,
            [this]() { refreshStatus(); });
        connect(
            enableButton_,
            &QPushButton::clicked,
            this,
            [this]() {
                if (active_ || triggered_) {
                    disableGuard();
                }
                else {
                    enableGuard();
                }
            });
        connect(
            acknowledgeCheck_,
            &QCheckBox::toggled,
            this,
            [this](const bool) { updateButtons(); });
        connect(
            screenshotPollTimer_,
            &QTimer::timeout,
            this,
            [this]() { pollForScreenshot(); });
        updateButtons();
    }

    void BugcheckGuardPage::refreshStatus()
    {
        if (busy_) {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto kResult = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY);
        setBusy(false);
        if (!kResult.io.ok) {
            supported_ = false;
            active_ = false;
            hvciEnabled_ = false;
            callbackBackend_ = false;
            statusLabel_->setText(
                kResult.unsupported
                    ? ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.driver_old"),
                        QStringLiteral("当前 R0 驱动不支持蓝屏缓冲，请更新驱动"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.query_failed"),
                        QStringLiteral("无法读取 R0 蓝屏缓冲状态")));
            detailLabel_->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.detail.io"),
                    QStringLiteral("Win32=%1；%2"))
                    .arg(kResult.io.win32Error)
                    .arg(QString::fromStdString(kResult.io.message)));
            updateButtons();
            return;
        }
        supported_ = true;
        updateFromResponse(kResult.response);
    }

    void BugcheckGuardPage::enableGuard()
    {
        if (busy_ || !acknowledgeCheck_->isChecked()) {
            showOpaqueMessage(
                this,
                QMessageBox::Warning,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.ack_required"),
                    QStringLiteral("请先保存工作并勾选风险确认。")));
            return;
        }
        screenshotPollTimer_->stop();
        screenshotDriverHandle_.reset();
        screenshotWatcherArmed_ = false;
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto kResult = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_ENABLE,
            static_cast<unsigned long>(delaySpin_->value()),
            true,
            tryIgnoreErrorCheck_->isChecked());
        setBusy(false);
        if (kResult.io.ok &&
            kResult.response.status ==
                KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE) {
            const bool kCallbackBackend =
                (kResult.response.stateFlags &
                    KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED) != 0UL;
            screenshotWatcherArmed_ =
                !kCallbackBackend && screenshotOnTriggerCheck_->isChecked();
            screenshotAttempted_ = false;
            screenshotInputAccepted_ = false;
            if (screenshotWatcherArmed_) {
                screenshotDriverHandle_ = client.open();
                screenshotPollTimer_->start();
            }
        }
        if (!kResult.io.ok ||
            kResult.response.status != KSWORD_ARK_BUGCHECK_GUARD_STATUS_ACTIVE) {
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                kResult.io.ok
                    ? bugcheckGuardStatusText(
                        kResult.response.status,
                        kResult.response.lastStatus,
                        kResult.response.stateFlags)
                    : QString::fromStdString(kResult.io.message));
        }
        refreshStatus();
    }

    void BugcheckGuardPage::disableGuard()
    {
        if (busy_) {
            return;
        }
        setBusy(true);
        ksword::ark::DriverClient client;
        const auto kResult = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_DISABLE);
        setBusy(false);
        if (!kResult.io.ok || kResult.response.status != KSWORD_ARK_BUGCHECK_GUARD_STATUS_INACTIVE) {
            showOpaqueMessage(
                this,
                QMessageBox::Critical,
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.title"),
                    QStringLiteral("蓝屏缓冲（实验性）")),
                kResult.io.ok
                    ? bugcheckGuardStatusText(kResult.response.status, kResult.response.lastStatus, kResult.response.stateFlags)
                    : QString::fromStdString(kResult.io.message));
        }
        refreshStatus();
    }

    void BugcheckGuardPage::pollForScreenshot()
    {
        if (!screenshotWatcherArmed_ || screenshotAttempted_) {
            screenshotPollTimer_->stop();
            screenshotDriverHandle_.reset();
            return;
        }

        ksword::ark::DriverClient client;
        if (!screenshotDriverHandle_.isValid()) {
            screenshotDriverHandle_ = client.open();
        }
        if (!screenshotDriverHandle_.isValid()) {
            return;
        }
        const auto kResult = client.configureBugcheckGuard(
            KSWORD_ARK_BUGCHECK_GUARD_ACTION_QUERY,
            0UL,
            false,
            false,
            &screenshotDriverHandle_);
        if (!kResult.io.ok) {
            screenshotDriverHandle_.reset();
            return;
        }

        const bool kFired =
            (kResult.response.stateFlags &
             KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED) != 0UL;
        if (kFired) {
            attemptScreenshot();
            updateFromResponse(kResult.response);
            return;
        }

        const bool kActive =
            (kResult.response.stateFlags &
             KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE) != 0UL;
        if (!kActive) {
            screenshotPollTimer_->stop();
            screenshotDriverHandle_.reset();
            screenshotWatcherArmed_ = false;
        }
    }

    void BugcheckGuardPage::attemptScreenshot()
    {
        if (!screenshotWatcherArmed_ || screenshotAttempted_) {
            return;
        }
        screenshotAttempted_ = true;
        screenshotInputAccepted_ = sendWinPrintScreen();
        screenshotPollTimer_->stop();
        screenshotDriverHandle_.reset();
    }

    void BugcheckGuardPage::updateFromResponse(
        const KSWORD_ARK_BUGCHECK_GUARD_RESPONSE& response)
    {
        const bool kFired =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_FIRED) != 0UL;
        const bool kIgnored =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_ERROR_IGNORED) != 0UL;
        const bool kExecuting =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_HOOK_EXECUTING) != 0UL;
        const bool kTryIgnore =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_TRY_IGNORE_ERROR) != 0UL;
        hvciEnabled_ =
            (response.stateFlags &
                KSWORD_ARK_BUGCHECK_GUARD_STATE_HVCI_ENABLED) != 0UL;
        callbackBackend_ =
            (response.stateFlags &
                KSWORD_ARK_BUGCHECK_GUARD_STATE_CALLBACK_REGISTERED) != 0UL;
        if (hvciEnabled_) {
            tryIgnoreErrorCheck_->setChecked(false);
            screenshotOnTriggerCheck_->setChecked(false);
        }
        active_ =
            (response.stateFlags & KSWORD_ARK_BUGCHECK_GUARD_STATE_ACTIVE) != 0UL;
        if (active_ || kFired) {
            const unsigned long kMaximumUiDelay =
                static_cast<unsigned long>(std::numeric_limits<int>::max());
            delaySpin_->setValue(
                response.delaySeconds > kMaximumUiDelay
                    ? std::numeric_limits<int>::max()
                    : static_cast<int>(response.delaySeconds));
            tryIgnoreErrorCheck_->setChecked(kTryIgnore || kIgnored);
        }
        triggered_ = kFired || kIgnored || kExecuting;
        if (kFired) {
            attemptScreenshot();
        }
        if (screenshotWatcherArmed_ &&
            !screenshotAttempted_ &&
            active_) {
            screenshotPollTimer_->start();
        }
        else if (screenshotAttempted_ ||
                 (!active_ && !kFired && !kExecuting)) {
            screenshotPollTimer_->stop();
        }
        if (!active_ && !kFired && !kExecuting) {
            screenshotDriverHandle_.reset();
            screenshotWatcherArmed_ = false;
        }

        if (kIgnored) {
            statusLabel_->setText(
                active_
                    ? ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.status.ignored_active"),
                        QStringLiteral("已尝试继续运行，拦截仍保持开启；这不代表故障已恢复。"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.status.ignored"),
                        QStringLiteral("已尝试继续运行。请立即保存文件并重启，系统可能随时再次崩溃。")));
        }
        else if (kExecuting) {
            statusLabel_->setText(
                ks::i18n::text(
                    QStringLiteral("misc.experimental.bugcheck.status.executing"),
                    QStringLiteral("正在处理蓝屏，系统可能随时崩溃。")));
        }
        else if (kFired) {
            statusLabel_->setText(
                callbackBackend_
                    ? ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.status.fired_callback"),
                        QStringLiteral(
                            "暂停已结束，Windows 会继续蓝屏。"))
                    : ks::i18n::text(
                        QStringLiteral("misc.experimental.bugcheck.status.fired"),
                        QStringLiteral("已触发拦截；当前开关状态以驱动回读为准。")));
        }
        else {
            statusLabel_->setText(
                bugcheckGuardStatusText(
                    response.status,
                    response.lastStatus,
                    response.stateFlags));
        }
        if (screenshotWatcherArmed_) {
            const QString kScreenshotStatus = screenshotAttempted_
                ? screenshotInputAccepted_
                    ? ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.screenshot.status.sent"),
                        QStringLiteral(
                            "已发送 Win+PrintScreen；Windows 是否真正保存截图无法确认。"))
                    : ks::i18n::text(
                        QStringLiteral(
                            "misc.experimental.bugcheck.screenshot.status.failed"),
                        QStringLiteral(
                            "发送 Win+PrintScreen 失败；系统可能已无法处理用户态输入。"))
                : ks::i18n::text(
                    QStringLiteral(
                        "misc.experimental.bugcheck.screenshot.status.waiting"),
                    QStringLiteral("截屏监视已就绪，等待 Hook 命中。"));
            statusLabel_->setText(
                QStringLiteral("%1\n%2")
                    .arg(statusLabel_->text(), kScreenshotStatus));
        }
        statusLabel_->setStyleSheet(
            QStringLiteral("font-size:15px;font-weight:650;color:%1;")
                .arg(kIgnored || kExecuting
                    ? ksword_theme::errorHex()
                    : active_
                        ? ksword_theme::warningHex()
                        : ksword_theme::successHex()));
        const QString kBackendText = callbackBackend_ || hvciEnabled_
            ? ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.backend.callback"),
                QStringLiteral("HVCI 安全延时（不能忽略）"))
            : ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.backend.hook"),
                QStringLiteral("实验拦截（可尝试继续）"));
        detailLabel_->setText(
            ks::i18n::text(
                QStringLiteral("misc.experimental.bugcheck.detail.state"),
                QStringLiteral(
                    "工作方式：%1；暂停：%4 秒；结束后：%5\n"
                    "技术信息：KeBugCheckEx=0x%2，状态位=0x%3，NTSTATUS=0x%6"))
                .arg(kBackendText)
                .arg(response.targetAddress, 16, 16, QLatin1Char('0'))
                .arg(response.stateFlags, 8, 16, QLatin1Char('0'))
                .arg(response.delaySeconds)
                .arg(
                    kTryIgnore || kIgnored
                        ? ks::i18n::text(
                            QStringLiteral("misc.experimental.bugcheck.mode.ignore"),
                            QStringLiteral("尝试继续运行"))
                        : ks::i18n::text(
                            QStringLiteral("misc.experimental.bugcheck.mode.normal"),
                            QStringLiteral("继续蓝屏")))
                .arg(
                    static_cast<unsigned long>(response.lastStatus),
                    8,
                    16,
                    QLatin1Char('0')));
        updateButtons();
    }

    void BugcheckGuardPage::updateButtons()
    {
        refreshButton_->setEnabled(!busy_);
        enableButton_->setEnabled(
            !busy_ && supported_ &&
            (active_ || triggered_ || acknowledgeCheck_->isChecked()));
        enableButton_->setChecked(active_ || triggered_);
        delaySpin_->setEnabled(!busy_ && !active_ && !triggered_);
        acknowledgeCheck_->setEnabled(!busy_ && !active_ && !triggered_);
        tryIgnoreErrorCheck_->setEnabled(
            !busy_ && !active_ && !triggered_ && !hvciEnabled_);
        screenshotOnTriggerCheck_->setEnabled(
            !busy_ && !active_ && !triggered_ && !hvciEnabled_);
    }

    void BugcheckGuardPage::setBusy(const bool busy)
    {
        busy_ = busy;
        updateButtons();
    }
}

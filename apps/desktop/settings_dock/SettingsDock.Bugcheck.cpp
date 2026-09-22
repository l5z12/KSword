#include "SettingsDock.h"

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include "../framework/PrivilegeElevationPrompt.h"
#include "../internationalization/LanguageManager.h"

#include <QCoreApplication>
#include <QGroupBox>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QThreadPool>
#include <QVBoxLayout>

namespace
{
    // bugcheckDiagnosticsStatusText: Returns the auto-install status description in the current language, prioritizing the busy state.
    QString bugcheckDiagnosticsStatusText(const bool autoInstallEnabled, const bool busy)
    {
        if (busy)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.installing"),
                QStringLiteral("正在由 R0 工作项准备蓝屏诊断。卸载驱动会安全取消本次准备。"));
        }
        if (autoInstallEnabled)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.auto_enabled"),
                QStringLiteral("已启用自动安装：后续 R0 驱动成功启动后，程序会发送安装 IOCTL。"));
        }
        return ks::i18n::text(
            QStringLiteral("settings.features.bugcheck.status.auto_disabled"),
            QStringLiteral("未配置自动安装。普通 R0 驱动启动不会扫描 BGP 私有函数或注册蓝屏诊断回调。"));
    }

    // bugcheckDiagnosticsInstallResultText: Convert protocol status into user prompts that do not exaggerate the scope of success.
    QString bugcheckDiagnosticsInstallResultText(
        const ksword::ark::BugcheckDiagnosticsResult& result)
    {
        if (!result.io.ok)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.transport_failed"),
                QStringLiteral("安装请求未送达 R0 驱动。Win32 错误：%1。"))
                .arg(result.io.win32Error);
        }
        if (result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.session_installed"),
                QStringLiteral("本次蓝屏诊断已安装。驱动卸载或系统重启后失效。"));
        }
        if (result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_UNSUPPORTED)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.unsupported"),
                QStringLiteral("当前 R0 驱动未包含蓝屏诊断安装能力。"));
        }
        if (result.response.status == KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_BUSY)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.busy"),
                QStringLiteral("蓝屏诊断正在安装或清理，请等待当前操作完成。"));
        }
        if (result.response.status ==
                KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_PREPARATION_FAILED &&
            static_cast<unsigned long>(result.response.lastStatus) == 0xC00000B5UL)
        {
            return ks::i18n::text(
                QStringLiteral("settings.features.bugcheck.status.timeout"),
                QStringLiteral("蓝屏诊断未能在 30 秒安全预算内完成，R0 已停止继续准备并清理临时资源。"));
        }
        return ks::i18n::text(
            QStringLiteral("settings.features.bugcheck.status.preparation_failed"),
            QStringLiteral("蓝屏诊断准备失败，Windows 原生蓝屏和转储不会被修改。NTSTATUS：0x%1。"))
            .arg(static_cast<unsigned long>(result.response.lastStatus), 8, 16, QLatin1Char('0'))
            .toUpper();
    }
}

void SettingsDock::initializeBugcheckDiagnosticsControls(
    QVBoxLayout* const featuresRootLayout)
{
    if (featuresRootLayout == nullptr)
    {
        return;
    }

    // Functionally independent grouping carries only configuration and explicit installation actions, avoiding mixing with one-time Hooks of the dangerous Guard.
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    QGroupBox* const kBugcheckGroupBox = new QGroupBox(
        QStringLiteral("蓝屏诊断"),
        featuresTab_);
    languageManager.bindText(
        kBugcheckGroupBox,
        QStringLiteral("settings.features.bugcheck.group"),
        QStringLiteral("蓝屏诊断"));
    QVBoxLayout* const kBugcheckLayout = new QVBoxLayout(kBugcheckGroupBox);
    kBugcheckLayout->setSpacing(8);

    QLabel* const kHintLabel = new QLabel(
        QStringLiteral("仅在自动安装已配置或明确点击“本次安装”后，R0 才会扫描 BGP 私有函数、准备蓝屏绘制资源并注册转储回调。此操作曾在不兼容系统上造成异常，安装失败时会保留 Windows 原生蓝屏和转储路径。"),
        kBugcheckGroupBox);
    kHintLabel->setWordWrap(true);
    languageManager.bindText(
        kHintLabel,
        QStringLiteral("settings.features.bugcheck.hint"),
        QStringLiteral("仅在自动安装已配置或明确点击“本次安装”后，R0 才会扫描 BGP 私有函数、准备蓝屏绘制资源并注册转储回调。此操作曾在不兼容系统上造成异常，安装失败时会保留 Windows 原生蓝屏和转储路径。"));
    kBugcheckLayout->addWidget(kHintLabel);

    bugcheckDiagnosticsStatusLabel_ = new QLabel(kBugcheckGroupBox);
    bugcheckDiagnosticsStatusLabel_->setWordWrap(true);
    kBugcheckLayout->addWidget(bugcheckDiagnosticsStatusLabel_);

    // The three text buttons express different persistence and lifecycle semantics; icons alone are insufficient to avoid ambiguity.
    enableBugcheckDiagnosticsAutoInstallButton_ = new QPushButton(
        QStringLiteral("驱动安装时自动安装蓝屏诊断"),
        kBugcheckGroupBox);
    languageManager.bindText(
        enableBugcheckDiagnosticsAutoInstallButton_,
        QStringLiteral("settings.features.bugcheck.auto_install"),
        QStringLiteral("驱动安装时自动安装蓝屏诊断"));
    enableBugcheckDiagnosticsAutoInstallButton_->setToolTip(
        QStringLiteral("写入配置文件。之后每次 R0 驱动成功启动，程序都会发送蓝屏诊断安装 IOCTL。"));
    languageManager.bindToolTip(
        enableBugcheckDiagnosticsAutoInstallButton_,
        QStringLiteral("settings.features.bugcheck.auto_install.tooltip"),
        QStringLiteral("写入配置文件。之后每次 R0 驱动成功启动，程序都会发送蓝屏诊断安装 IOCTL。"));
    kBugcheckLayout->addWidget(enableBugcheckDiagnosticsAutoInstallButton_);

    disableBugcheckDiagnosticsAutoInstallButton_ = new QPushButton(
        QStringLiteral("取消自动安装"),
        kBugcheckGroupBox);
    languageManager.bindText(
        disableBugcheckDiagnosticsAutoInstallButton_,
        QStringLiteral("settings.features.bugcheck.cancel_auto_install"),
        QStringLiteral("取消自动安装"));
    disableBugcheckDiagnosticsAutoInstallButton_->setToolTip(
        QStringLiteral("移除配置文件中的自动安装项。不影响当前已经安装的诊断，当前诊断会在驱动卸载或重启后失效。"));
    languageManager.bindToolTip(
        disableBugcheckDiagnosticsAutoInstallButton_,
        QStringLiteral("settings.features.bugcheck.cancel_auto_install.tooltip"),
        QStringLiteral("移除配置文件中的自动安装项。不影响当前已经安装的诊断，当前诊断会在驱动卸载或重启后失效。"));
    kBugcheckLayout->addWidget(disableBugcheckDiagnosticsAutoInstallButton_);

    installBugcheckDiagnosticsForSessionButton_ = new QPushButton(
        QStringLiteral("本次安装"),
        kBugcheckGroupBox);
    languageManager.bindText(
        installBugcheckDiagnosticsForSessionButton_,
        QStringLiteral("settings.features.bugcheck.install_session"),
        QStringLiteral("本次安装"));
    installBugcheckDiagnosticsForSessionButton_->setToolTip(
        QStringLiteral("立即向当前 R0 驱动发送安装 IOCTL。驱动卸载或系统重启后失效，不改写自动安装配置。"));
    languageManager.bindToolTip(
        installBugcheckDiagnosticsForSessionButton_,
        QStringLiteral("settings.features.bugcheck.install_session.tooltip"),
        QStringLiteral("立即向当前 R0 驱动发送安装 IOCTL。驱动卸载或系统重启后失效，不改写自动安装配置。"));
    kBugcheckLayout->addWidget(installBugcheckDiagnosticsForSessionButton_);

    featuresRootLayout->addWidget(kBugcheckGroupBox);
    connect(
        enableBugcheckDiagnosticsAutoInstallButton_,
        &QPushButton::clicked,
        this,
        [this]()
        {
            setBugcheckDiagnosticsAutoInstall(true);
        });
    connect(
        disableBugcheckDiagnosticsAutoInstallButton_,
        &QPushButton::clicked,
        this,
        [this]()
        {
            setBugcheckDiagnosticsAutoInstall(false);
        });
    connect(
        installBugcheckDiagnosticsForSessionButton_,
        &QPushButton::clicked,
        this,
        [this]()
        {
            installBugcheckDiagnosticsForCurrentSession();
        });
    refreshBugcheckDiagnosticsStatusText();
}

void SettingsDock::refreshBugcheckDiagnosticsStatusText()
{
    if (bugcheckDiagnosticsStatusLabel_ == nullptr || bugcheckDiagnosticsInstallBusy_)
    {
        return;
    }

    // The label initially reflects only the persisted option; session-specific results from manual installation are written by async callbacks.
    bugcheckDiagnosticsStatusLabel_->setText(
        bugcheckDiagnosticsStatusText(
            currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled,
            false));
}

void SettingsDock::setBugcheckDiagnosticsAutoInstall(const bool enabled)
{
    if (bugcheckDiagnosticsInstallBusy_)
    {
        return;
    }

    // After reading the latest disk configuration, only one field is modified to avoid accidentally submitting unapplied content from the Appearance page via the action button.
    ks::settings::AppearanceSettings savedSettings = ks::settings::loadAppearanceSettings();
    savedSettings.bugcheckDiagnosticsAutoInstallEnabled = enabled;
    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(savedSettings, &saveErrorText))
    {
        if (bugcheckDiagnosticsStatusLabel_ != nullptr)
        {
            bugcheckDiagnosticsStatusLabel_->setText(
                ks::i18n::text(
                    QStringLiteral("settings.features.bugcheck.status.save_failed"),
                    QStringLiteral("蓝屏诊断自动安装配置保存失败：%1。"))
                .arg(saveErrorText));
        }
        KLogEvent settingsEvent;
        err << settingsEvent
            << "[SettingsDock] 保存蓝屏诊断自动安装配置失败: "
            << saveErrorText.toStdString()
            << eol;
        return;
    }

    // Emit the signal after synchronizing the memory snapshot so that mainWindow immediately updates the diagnostic page entry visibility in the current session.
    currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled = enabled;
    refreshBugcheckDiagnosticsStatusText();
    emit bugcheckDiagnosticsAutoInstallChanged(enabled);

    KLogEvent settingsEvent;
    info << settingsEvent
        << "[SettingsDock] 蓝屏诊断自动安装配置已更新: "
        << (enabled ? "enabled" : "disabled")
        << eol;
}

void SettingsDock::installBugcheckDiagnosticsForCurrentSession()
{
    if (bugcheckDiagnosticsInstallBusy_)
    {
        return;
    }
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("蓝屏诊断本次安装"));
        return;
    }

    // First notify the main window to display the entry point, then start the background call, to avoid the user not seeing the diagnostics page while the R0 request is incomplete.
    emit bugcheckDiagnosticsInstallationStarted();
    setBugcheckDiagnosticsControlsBusy(true);
    const QPointer<SettingsDock> kGuardedSettingsDock(this);
    QThreadPool::globalInstance()->start(
        [kGuardedSettingsDock]()
        {
            const ksword::ark::BugcheckDiagnosticsResult kResult =
                ksword::ark::DriverClient().configureBugcheckDiagnostics(
                    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL);
            QCoreApplication* const kApplication = QCoreApplication::instance();
            if (kApplication == nullptr)
            {
                return;
            }

            if (!kGuardedSettingsDock.isNull())
            {
                QMetaObject::invokeMethod(
                    kGuardedSettingsDock,
                    [kGuardedSettingsDock, kResult]()
                {
                    if (kGuardedSettingsDock == nullptr)
                    {
                        return;
                    }

                    kGuardedSettingsDock->setBugcheckDiagnosticsControlsBusy(false);
                    if (kGuardedSettingsDock->bugcheckDiagnosticsStatusLabel_ != nullptr)
                    {
                        kGuardedSettingsDock->bugcheckDiagnosticsStatusLabel_->setText(
                            bugcheckDiagnosticsInstallResultText(kResult));
                    }
                    if (kResult.io.ok &&
                        kResult.response.status ==
                            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
                    {
                        emit kGuardedSettingsDock->bugcheckDiagnosticsInstalledForSession();
                    }

                    KLogEvent settingsEvent;
                    if (kResult.io.ok &&
                        kResult.response.status ==
                            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
                    {
                        info << settingsEvent
                            << "[SettingsDock] 本次蓝屏诊断安装完成, callbackMask=0x"
                            << std::hex
                            << kResult.response.callbackMask
                            << std::dec
                            << eol;
                    }
                    else
                    {
                        warn << settingsEvent
                            << "[SettingsDock] 本次蓝屏诊断安装未完成, win32="
                            << kResult.io.win32Error
                            << ", protocol="
                            << kResult.response.status
                            << ", ntstatus=0x"
                            << std::hex
                            << static_cast<unsigned long>(kResult.response.lastStatus)
                            << std::dec
                            << eol;
                    }
                },
                Qt::QueuedConnection);
            }
        });
}

void SettingsDock::setBugcheckDiagnosticsControlsBusy(const bool busy)
{
    bugcheckDiagnosticsInstallBusy_ = busy;
    if (enableBugcheckDiagnosticsAutoInstallButton_ != nullptr)
    {
        enableBugcheckDiagnosticsAutoInstallButton_->setEnabled(!busy);
    }
    if (disableBugcheckDiagnosticsAutoInstallButton_ != nullptr)
    {
        disableBugcheckDiagnosticsAutoInstallButton_->setEnabled(!busy);
    }
    if (installBugcheckDiagnosticsForSessionButton_ != nullptr)
    {
        installBugcheckDiagnosticsForSessionButton_->setEnabled(!busy);
    }
    if (bugcheckDiagnosticsStatusLabel_ != nullptr && busy)
    {
        bugcheckDiagnosticsStatusLabel_->setText(
            bugcheckDiagnosticsStatusText(
                currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled,
                true));
    }
}

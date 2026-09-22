#include "MainWindow.h"
#include "ui/DockTabInteraction.h"
#include "PluginHost.h"
#include "settings_dock/SettingsDock.h"
#include <QMenu>
#include <QAction>
#include <QTextEdit>
#include <QTextStream>
#include <QToolButton>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QScreen>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QList>
#include <QPushButton>
#include <QScrollArea>
#include <QDialog>
#include <QIODevice>
#include <QMessageBox>
#include <QStringList>
#include <QUrl>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "framework/LogDockWidget.h"
#include "framework/CustomTitleBar.h"
#include "include/ads/DockWidgetTab.h"
#include "internationalization/LanguageManager.h"
#include "framework/DestructiveActionConfirmation.h"
#include "Theme.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <TlHelp32.h>

#include "MainWindow.BugcheckSupport.h"

using namespace ksword::ui::main_window;

void MainWindow::initMenus()
{
    if (optionsMenuButton_ != nullptr || customTitleBar_ == nullptr)
    {
        return;
    }

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    // Feature entry container: attached after the application identifier on the title bar.
    // Adopt the standard Windows menu bar form: a few top-level items, each expanding into a dropdown menu,
    // rather than laying out every function as a separate button, which would crowd out the title bar.
    QWidget* const kTitleActionContainer = new QWidget(customTitleBar_);
    kTitleActionContainer->setObjectName(QStringLiteral("ksTitleActionRow"));
    kTitleActionContainer->setFixedHeight(22);
    QHBoxLayout* const kTitleActionLayout = new QHBoxLayout(kTitleActionContainer);
    kTitleActionLayout->setContentsMargins(2, 0, 0, 0);
    kTitleActionLayout->setSpacing(2);

    // configureTitleMenuButton purpose: Unify the appearance, focus policy, and popup behavior of top-level menu buttons.
    const auto kConfigureTitleMenuButton = [](QToolButton* const button, QMenu* const menu)
    {
        button->setToolButtonStyle(Qt::ToolButtonTextOnly);
        button->setAutoRaise(true);
        button->setFixedHeight(22);
        button->setFocusPolicy(Qt::NoFocus);
        button->setPopupMode(QToolButton::InstantPopup);
        button->setMenu(menu);
    };

    // ======== Options ======== The top-level item is named 'Options'; the
    // actual menu item that opens the settings panel is named 'Settings'.
    optionsMenuButton_ = new QToolButton(kTitleActionContainer);
    optionsMenuButton_->setObjectName(QStringLiteral("ksOptionsMenuButton"));
    optionsMenuButton_->setText(QStringLiteral("选项"));
    optionsMenuButton_->setToolTip(QStringLiteral("界面、插件与许可证"));
    languageManager.bindText(optionsMenuButton_, QStringLiteral("menu.options"), QStringLiteral("选项"));
    languageManager.bindToolTip(optionsMenuButton_, QStringLiteral("menu.options.tooltip"), QStringLiteral("界面、插件与许可证"));
    optionsMenu_ = new QMenu(optionsMenuButton_);
    optionsMenu_->setObjectName(QStringLiteral("ksOptionsMenu"));
    kConfigureTitleMenuButton(optionsMenuButton_, optionsMenu_);

    QAction* const kSettingsAction = optionsMenu_->addAction(QStringLiteral("设置"));
    languageManager.bindText(kSettingsAction, QStringLiteral("menu.settings"), QStringLiteral("设置"));
    connect(kSettingsAction, &QAction::triggered, this, [this]() { showSettingsPanelFromMenu(); });

    QAction* const kPluginAction = optionsMenu_->addAction(QStringLiteral("插件管理"));
    languageManager.bindText(kPluginAction, QStringLiteral("menu.plugins"), QStringLiteral("插件管理"));
    connect(kPluginAction, &QAction::triggered, this, [this]() { ks::plugin_host::showPluginManager(this); });

    optionsMenu_->addSeparator();

    QAction* const kLicenseAction = optionsMenu_->addAction(QStringLiteral("许可证"));
    languageManager.bindText(kLicenseAction, QStringLiteral("menu.license"), QStringLiteral("许可证"));
    connect(kLicenseAction, &QAction::triggered, this, &MainWindow::showLicenseFromMenu);

    QAction* const kExitAction = optionsMenu_->addAction(QStringLiteral("退出"));
    languageManager.bindText(kExitAction, QStringLiteral("menu.exit"), QStringLiteral("退出"));
    kExitAction->setShortcut(QKeySequence(QStringLiteral("Ctrl+Q")));
    kExitAction->setShortcutContext(Qt::WindowShortcut);
    connect(kExitAction, &QAction::triggered, this, &MainWindow::close);
    addAction(kExitAction);

    // ======== GitHub ========
    githubMenuButton_ = new QToolButton(kTitleActionContainer);
    githubMenuButton_->setObjectName(QStringLiteral("ksGitHubMenuButton"));
    githubMenuButton_->setText(QStringLiteral("GitHub"));
    githubMenuButton_->setToolTip(QStringLiteral("项目主页、发行版与问题反馈"));
    languageManager.bindText(githubMenuButton_, QStringLiteral("menu.github"), QStringLiteral("GitHub"));
    languageManager.bindToolTip(githubMenuButton_, QStringLiteral("menu.github.tooltip"), QStringLiteral("项目主页、发行版与问题反馈"));
    githubMenu_ = new QMenu(githubMenuButton_);
    githubMenu_->setObjectName(QStringLiteral("ksGitHubMenu"));
    kConfigureTitleMenuButton(githubMenuButton_, githubMenu_);

    QAction* const kRepositoryAction = githubMenu_->addAction(QStringLiteral("项目主页"));
    languageManager.bindText(kRepositoryAction, QStringLiteral("menu.github.repository"), QStringLiteral("项目主页"));
    connect(kRepositoryAction, &QAction::triggered, this, [this]() {
        openProjectPageFromMenu(
            QStringLiteral("https://github.com/KSwordDEV/KSword"),
            QStringLiteral("项目主页"));
    });

    QAction* const kReleaseAction = githubMenu_->addAction(QStringLiteral("发行版"));
    languageManager.bindText(kReleaseAction, QStringLiteral("menu.github.releases"), QStringLiteral("发行版"));
    connect(kReleaseAction, &QAction::triggered, this, [this]() {
        openProjectPageFromMenu(
            QStringLiteral("https://github.com/KSwordDEV/KSword/releases"),
            QStringLiteral("发行版"));
    });

    QAction* const kIssueAction = githubMenu_->addAction(QStringLiteral("问题反馈"));
    languageManager.bindText(kIssueAction, QStringLiteral("menu.github.issues"), QStringLiteral("问题反馈"));
    connect(kIssueAction, &QAction::triggered, this, [this]() {
        openProjectPageFromMenu(
            QStringLiteral("https://github.com/KSwordDEV/KSword/issues"),
            QStringLiteral("问题反馈"));
    });

    // ======== Window ========
    windowMenuButton_ = new QToolButton(kTitleActionContainer);
    windowMenuButton_->setObjectName(QStringLiteral("ksWindowMenuButton"));
    windowMenuButton_->setText(QStringLiteral("窗口"));
    windowMenuButton_->setToolTip(QStringLiteral("显示或隐藏 Dock 窗口"));
    languageManager.bindText(windowMenuButton_, QStringLiteral("menu.window"), QStringLiteral("窗口"));
    languageManager.bindToolTip(windowMenuButton_, QStringLiteral("menu.window.tooltip"), QStringLiteral("显示或隐藏 Dock 窗口"));
    windowMenu_ = new QMenu(windowMenuButton_);
    windowMenu_->setObjectName(QStringLiteral("ksWindowMenu"));
    kConfigureTitleMenuButton(windowMenuButton_, windowMenu_);

    kTitleActionLayout->addWidget(optionsMenuButton_);
    kTitleActionLayout->addWidget(windowMenuButton_);
    kTitleActionLayout->addWidget(githubMenuButton_);
    customTitleBar_->setCustomLeftWidget(kTitleActionContainer);
    refreshTitleActionButtonStyles();
}

void MainWindow::initializeWindowDockMenuActions()
{
    if (windowMenu_ == nullptr || dockLog_ == nullptr || dockMonitor_ == nullptr || dockCurrentOp_ == nullptr)
    {
        return;
    }

    // Use ADS's native toggle action directly: menu checkmarks, dock title bar close, floating, and layout restoration
    // are all driven by a single visibility state, avoiding the need to maintain a second set of boolean states.
    windowMenu_->clear();
    dockLog_->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);
    dockMonitor_->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);
    dockCurrentOp_->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);

    QAction* logDockAction = dockLog_->toggleViewAction();
    QAction* monitorPanelAction = dockMonitor_->toggleViewAction();
    QAction* currentTasksAction = dockCurrentOp_->toggleViewAction();
    ks::i18n::LanguageManager::instance().bindText(
        logDockAction,
        QStringLiteral("dock.log_window"),
        QStringLiteral("日志窗口"));
    ks::i18n::LanguageManager::instance().bindText(
        monitorPanelAction,
        QStringLiteral("dock.monitor_panel"),
        QStringLiteral("监视面板"));
    ks::i18n::LanguageManager::instance().bindText(
        currentTasksAction,
        QStringLiteral("dock.current_tasks"),
        QStringLiteral("当前任务"));
    windowMenu_->addAction(logDockAction);
    windowMenu_->addAction(monitorPanelAction);
    windowMenu_->addAction(currentTasksAction);
    windowMenu_->addSeparator();

    // Non-modal log output window is not a Dock; it lacks a toggleViewAction, so a separate action is added.
    QAction* const kLogOutputAction = windowMenu_->addAction(QStringLiteral("日志输出窗口"));
    ks::i18n::LanguageManager::instance().bindText(
        kLogOutputAction,
        QStringLiteral("menu.log"),
        QStringLiteral("日志输出窗口"));
    connect(kLogOutputAction, &QAction::triggered, this, &MainWindow::toggleLogOutputWindow);

    windowMenu_->addSeparator();

    // The 'Reset Dock Layout' action is placed here because, prior to this, users had no way to return to the default arrangement.
    // Top tabs can be dragged around arbitrarily, and the layout is persisted in config/ under the exe directory. The
    // only way to reset it is to manually locate and delete the .bin file—a detail we cannot expect users to know.
    QAction* const kResetLayoutAction = windowMenu_->addAction(
        ks::i18n::sourceText(QStringLiteral("重置停靠布局")));
    kResetLayoutAction->setToolTip(
        ks::i18n::sourceText(QStringLiteral("丢弃自己排的标签顺序与浮动窗口位置，下次启动回到默认布局。")));
    connect(kResetLayoutAction, &QAction::triggered, this, &MainWindow::resetDockLayoutToDefault);
}

void MainWindow::resetDockLayoutToDefault()
{
    const bool kConfirmed = ks::ui::confirmDestructiveAction(
        this,
        QStringLiteral("ResetDockLayout"),
        ks::i18n::sourceText(QStringLiteral("重置停靠布局")),
        ks::i18n::sourceText(QStringLiteral("当前窗口布局")),
        ks::i18n::sourceText(QStringLiteral("你自己排的标签顺序、浮动出去的窗口位置与各面板宽高都会丢掉，回到出厂默认排列。已打开的页面内容不受影响。")));
    if (!kConfirmed)
    {
        return;
    }

    const QString kLayoutConfigPath = resolveDockLayoutConfigPath();
    const bool kDiscarded = ks::ui::discardSavedDockLayout(kLayoutConfigPath);

    // Critical step: clear the "restored from configuration" flag.
    //
    // saveDockLayoutToConfig on exit writes the **current** layout back. Since the current layout is the one
    // the user is about to discard, failing to clear this flag and block that save causes the file to restore
    // itself immediately upon app closure even if deleted, making the user perceive the action as ineffective.
    dockLayoutRestoredFromConfig_ = false;
    suppressDockLayoutSave_ = true;

    QMessageBox::information(
        this,
        ks::i18n::sourceText(QStringLiteral("重置停靠布局")),
        kDiscarded
            // Clarify that a restart is required, rather than letting the user think the action is complete upon clicking.
            // ADS lacks an "in-place restore factory layout" interface: the default arrangement is built via a
            // sequence of addDockWidgetTabToArea calls at startup. Replaying them requires dismantling all current
            // Dock Areas first; any failure along that path leaves a worse intermediate state than the current one.
            ? ks::i18n::sourceText(QStringLiteral("已丢弃保存的布局。请重启 KSword，重启后会回到默认排列。本次退出不会再写回当前布局。"))
            : ks::i18n::sourceText(QStringLiteral("删除保存的布局文件失败，可能是文件被占用或没有写权限。可以手动删除 exe 目录下 config 里的布局文件。")));
}

QString MainWindow::buildTitleActionButtonStyle() const
{
    // Title bar action button styles are generated in real-time based on the current theme to avoid retaining old colors after a theme switch.
    const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
    const QString kHoverColor = ksword_theme::rgbaColorName(
        ksword_theme::primaryBlueColor,
        kDarkModeEnabled ? 56 : 36);
    const QString kPressedColor = ksword_theme::rgbaColorName(
        ksword_theme::primaryBlueColor,
        kDarkModeEnabled ? 87 : 62);
    const QString kTextColor = ksword_theme::textPrimaryColorHex();
    const QString kBorderColor = ksword_theme::rgbaColorName(
        ksword_theme::primaryBlueColor,
        kDarkModeEnabled ? 117 : 82);

    return QStringLiteral(
        "QToolButton{"
        "  background:transparent !important;"
        "  color:%1 !important;"
        "  border:1px solid transparent !important;"
        "  border-radius:4px;"
        "  margin:0;"
        "  padding:1px 5px;"
        "  font-weight:600;"
        "  text-align:left;"
        "}"
        "QToolButton:hover{"
        "  background:%2 !important;"
        "  color:%1 !important;"
        "  border-color:%4 !important;"
        "}"
        "QToolButton:pressed{"
        "  background:%3 !important;"
        "  color:%1 !important;"
        "  border-color:%4 !important;"
        "}"
        "QToolButton::menu-indicator{"
        "  image:none;"
        "  width:0;"
        "  height:0;"
        "}")
        .arg(kTextColor)
        .arg(kHoverColor)
        .arg(kPressedColor)
        .arg(kBorderColor);
}

void MainWindow::refreshTitleActionButtonStyles()
{
    // Refresh title bar action buttons: after a theme switch, all buttons reapply the same QSS.
    const QString kTopActionButtonStyle = buildTitleActionButtonStyle();
    const QList<QToolButton*> kTopActionButtonList{
        optionsMenuButton_,
        githubMenuButton_,
        windowMenuButton_
    };
    for (QToolButton* button : kTopActionButtonList)
    {
        if (button != nullptr)
        {
            button->setStyleSheet(kTopActionButtonStyle);
        }
    }
}

void MainWindow::openProjectPageFromMenu(const QString& urlText, const QString& failureTitle)
{
    // The three GitHub menu items share the same external link path; on failure, display a prompt based on their respective titles.
    const QUrl kTargetUrl(urlText);
    if (!QDesktopServices::openUrl(kTargetUrl))
    {
        QMessageBox::warning(
            this,
            failureTitle,
            QStringLiteral("无法打开页面：%1").arg(kTargetUrl.toString()));
    }
}

void MainWindow::showLicenseFromMenu()
{
    const QDir kApplicationDirectory(QCoreApplication::applicationDirPath());
    const QStringList kLicenseFileNames{
        QStringLiteral("LICENSE"),
        QStringLiteral("LICENSE.txt"),
        QStringLiteral("license")
    };
    QString licensePath = kApplicationDirectory.absoluteFilePath(kLicenseFileNames.constFirst());
    for (const QString& licenseFileName : kLicenseFileNames)
    {
        const QString kCandidatePath = kApplicationDirectory.absoluteFilePath(licenseFileName);
        if (QFileInfo(kCandidatePath).isFile())
        {
            licensePath = kCandidatePath;
            break;
        }
    }
    QString licenseText;
    const auto kAppendLegalDocument = [&licenseText](const QString& filePath)
    {
        QFile legalFile(filePath);
        if (!legalFile.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            return false;
        }

        QTextStream legalStream(&legalFile);
        legalStream.setEncoding(QStringConverter::Utf8);
        const QString kDocumentText = legalStream.readAll();
        if (!licenseText.isEmpty())
        {
            licenseText += QStringLiteral("\n\n===== %1 =====\n\n")
                .arg(QFileInfo(filePath).fileName());
        }
        licenseText += kDocumentText;
        return true;
    };

    if (!kAppendLegalDocument(licensePath))
    {
        if (!licenseText.isEmpty())
        {
            licenseText += QString::fromLatin1("\n\n===== LICENSE =====\n\n");
        }
        licenseText += QStringLiteral("未找到程序同目录的 LICENSE 文件：\n%1").arg(QDir::toNativeSeparators(licensePath));
    }

    const QStringList kSupplementaryLegalFiles{
        QStringLiteral("COMMUNITY_COVENANT.md")
    };
    for (const QString& legalFileName : kSupplementaryLegalFiles)
    {
        const QString kLegalFilePath = kApplicationDirectory.absoluteFilePath(legalFileName);
        if (QFileInfo(kLegalFilePath).isFile())
        {
            kAppendLegalDocument(kLegalFilePath);
        }
    }

    QDialog licenseDialog(this);
    licenseDialog.setWindowTitle(QStringLiteral("许可证"));
    licenseDialog.resize(760, 560);
    licenseDialog.setStyleSheet(QStringLiteral(
        "QDialog{background:%1;color:%2;}"
        "QTextEdit{background:%1;color:%2;border:1px solid %3;}"
        "QPushButton{padding:4px 14px;}" )
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::borderHex()));

    QVBoxLayout dialogLayout(&licenseDialog);
    dialogLayout.setContentsMargins(8, 8, 8, 8);
    dialogLayout.setSpacing(8);

    QTextEdit licenseEditor(&licenseDialog);
    licenseEditor.setReadOnly(true);
    // The license body is the original legal text; only the local missing prompt needs to be displayed in the current interface language.
    const QString kLicenseDisplayText = licenseText.trimmed().isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("LICENSE 文件为空。"))
        : licenseText;
    licenseEditor.setPlainText(kLicenseDisplayText);
    dialogLayout.addWidget(&licenseEditor, 1);

    QPushButton closeButton(QStringLiteral("关闭"), &licenseDialog);
    connect(&closeButton, &QPushButton::clicked, &licenseDialog, &QDialog::accept);
    dialogLayout.addWidget(&closeButton, 0, Qt::AlignRight);

    licenseDialog.exec();
}

void MainWindow::showSettingsPanelFromMenu(bool showLanguageTab)
{
    QDialog settingsDialog(this);
    settingsDialog.setWindowTitle(QStringLiteral("设置"));
    settingsDialog.setModal(false);
    settingsDialog.resize(760, 640);
    settingsDialog.setStyleSheet(QStringLiteral(
        "QDialog{background:%1;color:%2;}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        + ksword_theme::themedComboBoxStyle());

    QVBoxLayout dialogLayout(&settingsDialog);
    dialogLayout.setContentsMargins(8, 8, 8, 8);
    dialogLayout.setSpacing(6);

    // The settings panel is changed to a top-menu instant dialog that reads the current JSON each time it opens, avoiding occupation of the main tab bar space.
    auto* settingsScrollArea = new QScrollArea(&settingsDialog);
    settingsScrollArea->setWidgetResizable(true);
    settingsScrollArea->setFrameShape(QFrame::NoFrame);
    settingsScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    settingsScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    auto* settingsPanel = new SettingsDock();
    settingsScrollArea->setWidget(settingsPanel);
    if (showLanguageTab)
    {
        settingsPanel->showLanguageSettingsTab();
    }
    connect(
        settingsPanel,
        &SettingsDock::appearanceSettingsChanged,
        this,
        [this](const ks::settings::AppearanceSettings& settings) {
            applyAppearanceSettings(settings, QStringLiteral("顶部菜单设置变更"));
        });
    connect(
        settingsPanel,
        &SettingsDock::bugcheckDiagnosticsAutoInstallChanged,
        this,
        [this](const bool enabled)
        {
            currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled = enabled;
            updateBugcheckDiagnosticsEntryVisibility();
        });
    connect(
        settingsPanel,
        &SettingsDock::bugcheckDiagnosticsInstallationStarted,
        this,
        [this]()
        {
            bugcheckDiagnosticsEntryRequestedForSession_ = true;
            updateBugcheckDiagnosticsEntryVisibility();
        });
    connect(
        settingsPanel,
        &SettingsDock::bugcheckDiagnosticsInstalledForSession,
        this,
        [this]()
        {
            bugcheckDiagnosticsInstalledForSession_ = true;
            updateBugcheckDiagnosticsEntryVisibility();
            queueBugcheckVerdictResourceUpload();
        });
    dialogLayout.addWidget(settingsScrollArea, 1);

    // Fix the action bar outside the scroll area to ensure 'Apply/Cancel' remains always visible.
    auto* actionLayout = new QHBoxLayout();
    actionLayout->addStretch(1);
    auto* cancelButton = new QPushButton(QStringLiteral("取消"), &settingsDialog);
    auto* applyButton = new QPushButton(QStringLiteral("应用"), &settingsDialog);
    auto& languageManager = ks::i18n::LanguageManager::instance();
    languageManager.bindText(cancelButton, QStringLiteral("common.cancel"), QStringLiteral("取消"));
    languageManager.bindText(applyButton, QStringLiteral("settings.apply"), QStringLiteral("应用"));
    languageManager.bindToolTip(applyButton, QStringLiteral("settings.apply.tooltip"), QStringLiteral("应用当前设置改动"));
    cancelButton->setMinimumWidth(72);
    applyButton->setMinimumWidth(72);
    cancelButton->setFixedHeight(30);
    applyButton->setFixedHeight(30);
    applyButton->setEnabled(false);
    actionLayout->addWidget(cancelButton);
    actionLayout->addWidget(applyButton);
    dialogLayout.addLayout(actionLayout);

    connect(applyButton, &QPushButton::clicked, settingsPanel, &SettingsDock::applySettings);
    connect(cancelButton, &QPushButton::clicked, &settingsDialog, &QDialog::reject);
    connect(settingsPanel, &SettingsDock::pendingChangesChanged, applyButton, &QPushButton::setEnabled);

    settingsDialog.exec();
}

void MainWindow::toggleLogOutputWindow()
{
    if (logOutputWindow_ == nullptr)
    {
        return;
    }

    if (logOutputWindow_->isVisible())
    {
        persistLogOutputWindowGeometry();
        logOutputWindow_->hide();
        return;
    }

    if (logWidget_ != nullptr)
    {
        logWidget_->refreshNow();
    }
    logOutputWindow_->show();
    logOutputWindow_->raise();
    logOutputWindow_->activateWindow();
}

void MainWindow::persistLogOutputWindowGeometry()
{
    if (logOutputWindow_ == nullptr || !logOutputWindow_->geometry().isValid())
    {
        return;
    }

    const QString kEncodedGeometry = QString::fromLatin1(logOutputWindow_->saveGeometry().toBase64());
    if (kEncodedGeometry == currentAppearanceSettings_.logWindowGeometryBase64)
    {
        return;
    }

    currentAppearanceSettings_.logWindowGeometryBase64 = kEncodedGeometry;
    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(currentAppearanceSettings_, &saveErrorText))
    {
        KLogEvent geometryEvent;
        warn << geometryEvent
            << "[MainWindow] 保存日志窗口几何信息失败: "
            << saveErrorText.toStdString()
            << eol;
    }
}

void MainWindow::restoreLogOutputWindowGeometry()
{
    if (logOutputWindow_ == nullptr)
    {
        return;
    }

    const QByteArray kEncodedGeometry = QByteArray::fromBase64(
        currentAppearanceSettings_.logWindowGeometryBase64.toLatin1());
    bool restored = !kEncodedGeometry.isEmpty() && logOutputWindow_->restoreGeometry(kEncodedGeometry);
    if (restored)
    {
        const QRect kRestoredRect = logOutputWindow_->frameGeometry();
        bool intersectsAvailableScreen = false;
        for (QScreen* screen : QGuiApplication::screens())
        {
            if (screen != nullptr && screen->availableGeometry().intersects(kRestoredRect))
            {
                intersectsAvailableScreen = true;
                break;
            }
        }
        if (intersectsAvailableScreen)
        {
            return;
        }
        restored = false;
    }

    if (!restored)
    {
        logOutputWindow_->resize(900, 620);
        const QRect kHostRect = frameGeometry();
        logOutputWindow_->move(
            kHostRect.center() - QPoint(logOutputWindow_->width() / 2, logOutputWindow_->height() / 2));
    }
}

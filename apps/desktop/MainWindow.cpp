#include "MainWindow.h"
#include "internationalization/LanguageManager.h"

#include <QMenu>
#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QFont>
#include <QWidget>
#include <QVBoxLayout>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "framework/NotificationCardManager.h"
#include "framework/CustomTitleBar.h"
#include "include/ads/DockComponentsFactory.h"
#include "include/ads/DockWidgetTab.h"
#include "include/ads/FloatingDockContainer.h"
#include "../../shared/ark_client/ArkDriverClient.h"
#include "kernel_dock/KernelDock.CallbackPromptManager.h"
#include "ui/DockTabInteraction.h"
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

#include "MainWindow.BackgroundSupport.h"
#include "MainWindow.DockTabsSupport.h"
#include "MainWindow.DriverServiceBackendSupport.h"
#include "MainWindow.NativeFrameSupport.h"
#include "MainWindow.DriverServiceConstants.h"
#include "MainWindow.WidgetBehaviorSupport.h"

using namespace ksword::ui::main_window;

MainWindow::MainWindow(
    QWidget* parent,
    StartupProgressCallback startupProgressCallback,
    const QFont& startupSystemFont)
    : QMainWindow(parent)
    , startupSystemFont_(startupSystemFont)
    , startupProgressCallback_(startupProgressCallback)
{
    // Install global QMenu theme filter:
    // - Unifies the fallback background for all right-click menus;
    // - Prevent missing setStyleSheet calls for newly added menus, which would cause a black background in light mode.
    ensureGlobalContextMenuThemeFilterInstalled();
    ensureGlobalComboPopupThemeFilterInstalled();
    ensureGlobalSliderWheelFilterInstalled();
    ensureGlobalTableSelectionOutlineFilterInstalled();

    // Log main window startup to verify the logging system and UI integration are working.
    // Note: Use KLogEvent to avoid naming conflicts with QObject::event.
    KLogEvent startupEvent;
    info << startupEvent << "MainWindow 构造开始，准备初始化 Dock 系统。" << eol;

    // Startup stage breakdown:
    // - Main window shell;
    // - Menu;
    // - Permission button;
    // - Dock content;
    // - Appearance system.
    // Read appearance configuration in advance to determine the preloading strategy for the default startup tab during initDockWidgets.
    currentAppearanceSettings_ = ks::settings::loadAppearanceSettings();

    // The three theme seeds must be set before any page construction, not deferred to initAppearanceSettings below:
    // Many pages evaluate ksword_theme::*ColorHex() during construction and embed the resulting fixed color strings into their own QSS, which
    // then overrides the globally rebuilt QSS when the control's setStyleSheet is applied. If the seed is set too late, pages preloaded at
    // startup (such as the Dock containing the default startup page) will permanently remain on the light/default accent color.
    // Only write the seed here; the palette and global style block are still issued uniformly by initAppearanceSettings.
    ksword_theme::setDarkModeEnabled(isDarkModeEffective(currentAppearanceSettings_));
    ksword_theme::setPrimaryAccentColor(currentAppearanceSettings_.customThemeColor);
    ksword_theme::setMainBackgroundColor(currentAppearanceSettings_.customMainBackgroundColor);

    reportStartupProgress(
        32,
        QStringLiteral("main.startup.progress.main_window_framework"),
        QStringLiteral("正在准备主界面..."));

    // Per-pixel alpha background transparency must be declared before the native window is created:
    // - Runtime switching requires destroying and recreating the HWND, which loses handle bindings for single-instance properties and DWM styles.
    // - This setting is read only once at startup; runtime modifications require a restart to take effect, as prompted by the appearance settings page.
    if (currentAppearanceSettings_.backgroundTransparencyEnabled)
    {
        setAttribute(Qt::WA_TranslucentBackground, true);
    }

    // Enable borderless mode:
    // - Custom-drawn title bar takes over minimize/maximize/close/always-on-top operations.
    // - Retain the system menu and minimize/maximize capabilities for native behavior compatibility.
    setWindowFlag(Qt::FramelessWindowHint, true);
    setWindowFlag(Qt::WindowSystemMenuHint, true);
    setWindowFlag(Qt::WindowMinMaxButtonsHint, true);

    // Dock global configuration:
    // - Only allow auxiliary docks declared with DockWidgetClosable to show the close button on active tabs.
    // - The main feature Dock continues to disable closing in their respective features; the area menu, floating, and close buttons remain hidden.
    ads::CDockManager::setConfigFlag(ads::CDockManager::ActiveTabHasCloseButton, true);
    ads::CDockManager::setConfigFlag(ads::CDockManager::AllTabsHaveCloseButton, false);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DockAreaHasCloseButton, false);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DockAreaHasUndockButton, false);
    // Overflow tabs are accessed via horizontal scrolling and left/right arrows; the area dropdown menu is no longer displayed.
    ads::CDockManager::setConfigFlag(ads::CDockManager::DockAreaHasTabsMenuButton, false);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DisableTabTextEliding, true);
    // The custom ADS tab factory must be installed before creating CDockManager/DockWidget instances;
    // Otherwise, the default CDockWidgetTab is already instantiated; switching factories later cannot fix the white hover background on existing tabs.
    ensureKswordAdsDockComponentsFactoryInstalled();

    // Create main window root container:
    // - Row 0 contains the custom title bar;
    // - Place the ADS Dock manager in row 1;
    // - Uniformly avoid visibility instability of setMenuWidget in borderless scenarios.
    mainRootContainer_ = new MainWindowBackgroundWidget(this);
    mainRootContainer_->setObjectName(QStringLiteral("ksMainRootContainer"));

    mainRootLayout_ = new QVBoxLayout(mainRootContainer_);
    mainRootLayout_->setContentsMargins(0, 0, 0, 0);
    mainRootLayout_->setSpacing(0);

    pDockManager_ = new ads::CDockManager(mainRootContainer_);
    mainRootLayout_->addWidget(pDockManager_, 1);
    setCentralWidget(mainRootContainer_);
    initResizeBorderOverlays();

    // Attach event filter immediately after floating window creation:
    // - Ensure detached Dock containers also synchronize the background image and solid color background.
    // - Subsequent resize/show operations will uniformly follow the mainWindow appearance synchronization logic.
    connect(
        pDockManager_,
        &ads::CDockManager::floatingWidgetCreated,
        this,
        [this](ads::CFloatingDockContainer* floatingWidget)
        {
            if (floatingWidget == nullptr)
            {
                return;
            }
            floatingWidget->installEventFilter(this);
            applyFloatingDockContainerAppearance(floatingWidget);
        });

    // Explicitly request application exit after the last window is closed.
    // Note: The user requires the process to terminate when the main window closes; set the global Qt exit policy here first.
    QApplication::setQuitOnLastWindowClosed(true);

    // Set the window title and size.
    setWindowTitle("KswordARK-5.1-Release");
    resize(1024, 768);
    configureSingleInstanceMessageReception(reinterpret_cast<HWND>(winId()));

    // initialize custom-drawn title bar:
    // - Replace the system title bar;
    // - Holds the topmost button, command input box, and window control buttons.
    reportStartupProgress(
        38,
        QStringLiteral("main.startup.progress.custom_title_bar"),
        QStringLiteral("正在准备主界面..."));
    initCustomTitleBar();

    // Feature entry point attached to the custom title bar; must be created only after the title bar is ready.
    reportStartupProgress(
        44,
        QStringLiteral("main.startup.progress.menu"),
        QStringLiteral("正在准备主界面..."));
    initMenus();

    // initialize the privilege status button:
    // - UIAccess / Admin / Debug / System / R0；
    // - Attach to the right side of the main function Tab bar after the Dock layout is restored.
    reportStartupProgress(
        46,
        QStringLiteral("main.startup.progress.privilege_status"),
        QStringLiteral("正在准备主界面..."));
    initPrivilegeStatusButtons();
    startR0RuntimeConsumersAfterServiceStart();

    // initialize Dock Widgets
    reportStartupProgress(
        48,
        QStringLiteral("main.startup.progress.page_components"),
        QStringLiteral("正在加载功能模块..."));
    initDockWidgets();

    // Set Dock layout.
    reportStartupProgress(
        74,
        QStringLiteral("main.startup.progress.dock_layout"),
        QStringLiteral("正在恢复界面布局..."));
    setupDockLayout();

    // Add horizontal wheel scrolling to the top dock tabs.
    //
    // Must be placed **after** layout establishment: The existing tab bars at this moment must
    // immediately have filters installed, while tab bars created later by floating, restoreState,
    // or new Dock instances are caught by the dockAreaCreated subscription inside the function.
    // If we only scan once at startup, dragging out a floating window would make it unscrollable.
    ks::ui::installDockTabWheelScrolling(pDockManager_);

    // initialize appearance settings:
    // - Read JSON.
    // - Bind to system light/dark mode changes.
    // - Apply window background color/image and text color.
    reportStartupProgress(
        84,
        QStringLiteral("main.startup.progress.theme_appearance"),
        QStringLiteral("正在应用界面设置..."));
    initAppearanceSettings();

    // Log initialization completion so users can see the result directly in the 'Log Output' panel.
    // Note: Use KLogEvent to avoid naming conflicts with QObject::event.
    KLogEvent readyEvent;
    info << readyEvent << "MainWindow 初始化完成，日志面板已加载。" << eol;
    reportStartupProgress(
        93,
        QStringLiteral("main.startup.progress.main_window_ready"),
        QStringLiteral("即将完成..."));
}

MainWindow::~MainWindow()
{
    // Invalidate notifications already in the Qt queue, then wait for worker threads to return leases for copied handlers.
    // After returning, no thread will use this to dispatch new events, so it is safe to then tear down window members.
    r0NotificationLifetime_->store(false, std::memory_order_release);
    ksword::ark::DriverClient::clearR0NotificationHandlersAndWait();
    clearSingleInstanceMessageReception(reinterpret_cast<HWND>(winId()));
    CallbackPromptManager::shutdownGlobalManager();
    stopR0DriverLogPoller();
    // ADS manages memory automatically; manual deletion is not required.
}

void MainWindow::reportStartupProgress(
    const int progressPercent,
    const QString& textKey,
    const QString& fallbackText) const
{
    // Security callback policy:
    // - Silently skip if no callback is provided;
    // - If a callback exists, first resolve the location key using the current effective language, then forward the result to the main function.
    if (!startupProgressCallback_)
    {
        return;
    }

    startupProgressCallback_(
        progressPercent,
        ks::i18n::contextText(textKey, fallbackText));
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // Close event log: used to troubleshoot issues where the window closes but the process remains resident.
    KLogEvent closeEventLog;
    info << closeEventLog << "[MainWindow] 收到关闭事件，准备退出进程。" << eol;

    // On exit, prioritize saving the ADS layout to ensure user drag/drop/floating/active tab states are restored on next startup.
    saveDockLayoutToConfig();
    persistLogOutputWindowGeometry();
    if (notificationCardManager_ != nullptr)
    {
        notificationCardManager_->clearCards();
    }

    // Stop the privilege status timer to prevent UI updates from triggering during the shutdown phase.
    if (privilegeStatusTimer_ != nullptr)
    {
        privilegeStatusTimer_->stop();
    }
    prepareR0DriverServiceStop();
    CallbackPromptManager::shutdownGlobalManager();

    // Automatically stop the R0 driver when the window is closed.
    // - Silently query the service status first;
    // - If running, offload the entire SCM driver unloading sequence to the thread pool; the UI thread immediately hides
    //   the window to prevent the 'SCM stuck in STOP_PENDING' state from forcing a 30-second hard freeze during shutdown.
    bool r0RunningBeforeExit = false;
    if (queryR0DriverServiceRunning(r0RunningBeforeExit, false) && r0RunningBeforeExit)
    {
        if (event != nullptr)
        {
            // We must ignore here: if we accept, Qt will end the event loop based on quitOnLastWindowClosed
            // before the driver-unload callback executes, causing the callback and logs to be lost.
            event->ignore();
        }
        hide();

        // The async shutdown flow advances only once: if a close request is received after the window is hidden,
        // return immediately to avoid re-dispatching driver unload tasks and re-arming the fallback timer.
        static bool asyncShutdownStarted = false;
        if (asyncShutdownStarted)
        {
            return;
        }
        asyncShutdownStarted = true;

        dispatchR0ServiceStopToWorker(
            [](const R0ServiceOperationOutcome& operationOutcome)
            {
                KLogEvent autoStopEvent;
                if (operationOutcome.succeeded)
                {
                    info << autoStopEvent << "[MainWindow][R0] 关闭窗口时已自动停止并删除驱动服务。" << eol;
                }
                else
                {
                    warn << autoStopEvent << "[MainWindow][R0] 关闭窗口时自动停驱失败（已静默处理）。" << eol;
                }
                QApplication::quit();
                QCoreApplication::exit(0);
            });

        // Fallback timer: Exit even if the background driver-stop operation hangs, so a hidden window does not leave the process running.
        // The timeout upper limit is set to 'driver stop wait upper limit + 2 seconds margin'; the normal path will always trigger exit before this limit.
        QTimer::singleShot(
            static_cast<int>(kR0ServiceStopWaitTimeoutMs) + 2000,
            QCoreApplication::instance(),
            []()
            {
                QApplication::quit();
                QCoreApplication::exit(0);
            });
        return;
    }

    // Accept the close event and actively trigger application exit.
    // Calling quit and exit(0) here ensures the event loop terminates as quickly as possible.
    if (event != nullptr)
    {
        event->accept();
    }
    QApplication::quit();
    QCoreApplication::exit(0);

    KLogEvent closeFinishLog;
    info << closeFinishLog << "[MainWindow] 已提交退出请求 (exit code=0)。" << eol;
}

#include "MainWindow.h"

#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QList>
#include <QMessageBox>
#include <QVariant>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "framework/CustomTitleBar.h"
#include "ui/GlobalUiSearch.h"
#include "ui/CommandExecutionPopup.h"
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

#include "MainWindow.DockTabsSupport.h"
#include "MainWindow.NativeFrameSupport.h"

namespace ksword::ui::main_window
{
    // WDA_* compatible constants:
    // - WDA_EXCLUDEFROMCAPTURE is supported in Windows 10 20H2+; hides the window directly in screenshots/screen recordings.
    // - WDA_MONITOR is a fallback for older systems; window areas appear black in screenshots or screen recordings.
    // - WDA_NONE is used to disable screenshot blocking and restore normal capture.
    constexpr DWORD kWindowDisplayAffinityAllowCapture = 0x00000000;

    constexpr DWORD kWindowDisplayAffinityMonitorOnly = 0x00000001;

    constexpr DWORD kWindowDisplayAffinityExcludeFromCapture = 0x00000011;
}

using namespace ksword::ui::main_window;

void MainWindow::initCustomTitleBar()
{
    if (customTitleBar_ != nullptr)
    {
        return;
    }

    customTitleBar_ = new ks::ui::CustomTitleBar(this);
    customTitleBar_->setPinnedState(windowPinned_);
    customTitleBar_->setCaptureProtectionState(captureProtectionEnabled_);
    syncCustomTitleBarMaximizedState();
    customTitleBar_->setDarkModeEnabled(ksword_theme::isDarkModeEnabled());
    if (mainRootLayout_ != nullptr && mainRootContainer_ != nullptr)
    {
        customTitleBar_->setParent(mainRootContainer_);
        mainRootLayout_->insertWidget(0, customTitleBar_, 0);
    }
    else
    {
        // Fallback: if the root container is not yet ready, revert to mounting the menuWidget via QMainWindow.
        setMenuWidget(customTitleBar_);
    }
    customTitleBar_->show();

    connect(customTitleBar_, &ks::ui::CustomTitleBar::requestTogglePinned, this, [this]() {
        togglePinnedWindowState();
    });
    connect(customTitleBar_, &ks::ui::CustomTitleBar::requestToggleCaptureProtection, this, [this]() {
        toggleCaptureProtectionState();
    });
    connect(customTitleBar_, &ks::ui::CustomTitleBar::requestMinimizeWindow, this, [this]() {
        showMinimized();
    });
    connect(customTitleBar_, &ks::ui::CustomTitleBar::requestToggleMaximizeWindow, this, [this]() {
        // targetMaximizedState purpose: Calculate the next target state (maximized or restored) based on the actual state.
        const bool kTargetMaximizedState = !isWindowActuallyMaximized();
        setWindowMaximizedBySystemCommand(kTargetMaximizedState);
    });
    connect(customTitleBar_, &ks::ui::CustomTitleBar::requestCloseWindow, this, [this]() {
        close();
    });
    connect(customTitleBar_, &ks::ui::CustomTitleBar::commandSubmitted, this, [this](const QString& commandText) {
        executeCommandInNewConsole(commandText);
    });

    initGlobalUiSearchController();

    KLogEvent initTitleBarEvent;
    info << initTitleBarEvent << "[MainWindow] 自绘标题栏初始化完成。" << eol;

    // First-frame self-check:
    // - Checks if the title bar is visible in the next event loop after setMenuWidget;
    // - Synchronously records the mount state and dimensions to facilitate troubleshooting 'title bar not displayed' issues.
    QTimer::singleShot(0, this, [this]()
        {
            if (customTitleBar_ == nullptr)
            {
                return;
            }

            // mountedAsMenuWidget purpose: Confirm if the custom-drawn title bar is mounted to the QMainWindow menu widget.
            const bool kMountedAsMenuWidget = (menuWidget() == customTitleBar_);
            // mountedInRootLayout: Confirms whether the custom title bar is attached to row 0 of the root container's vertical layout.
            const bool kMountedInRootLayout =
                (mainRootLayout_ != nullptr && mainRootLayout_->indexOf(customTitleBar_) >= 0);
            if (!customTitleBar_->isVisible())
            {
                customTitleBar_->show();
            }

            KLogEvent titleBarCheckEvent;
            info << titleBarCheckEvent
                << "[MainWindow] 自绘标题栏挂载检查, mounted="
                << (kMountedAsMenuWidget ? "true" : "false")
                << ", mounted_layout="
                << (kMountedInRootLayout ? "true" : "false")
                << ", visible="
                << (customTitleBar_->isVisible() ? "true" : "false")
                << ", size="
                << customTitleBar_->width()
                << "x"
                << customTitleBar_->height()
                << eol;
        });
}

void MainWindow::initGlobalUiSearchController()
{
    if (customTitleBar_ == nullptr || globalUiSearchController_ != nullptr)
    {
        return;
    }

    // The popup host is the main window itself: using child controls for popups in borderless windows prevents focus from being stolen by independent windows.
    globalUiSearchController_ = new ks::ui::GlobalUiSearchController(
        this,
        customTitleBar_->titleInputLineEdit(),
        customTitleBar_->titleInputAnchorWidget(),
        this);
    commandExecutionPopup_ = new ks::ui::CommandExecutionPopup(
        this,
        customTitleBar_->titleInputAnchorWidget(),
        customTitleBar_->titleInputLineEdit(),
        this);
    connect(
        customTitleBar_,
        &ks::ui::CustomTitleBar::inputModeChanged,
        this,
        [this](const bool searchModeActive) {
            if (commandExecutionPopup_ != nullptr)
            {
                commandExecutionPopup_->setCommandModeActive(!searchModeActive);
            }
        });
    connect(
        commandExecutionPopup_,
        &ks::ui::CommandExecutionPopup::executeRequested,
        this,
        [this](const QString& commandText, const ks::ui::CommandExecutionOptions& options) {
            executeCommandWithOptions(commandText, options);
        });
    globalUiSearchController_->setDockListProvider([this]() {
        return collectSearchableDockWidgets();
    });
    globalUiSearchController_->setDockPreparer([this](ads::CDockWidget* dockWidget) {
        ensureDockContentInitialized(dockWidget);
    });
    globalUiSearchController_->setDockActivator([this](ads::CDockWidget* dockWidget) {
        activateDockForSearchNavigation(dockWidget);
    });
    connect(
        globalUiSearchController_,
        &ks::ui::GlobalUiSearchController::requestSearchInputActivation,
        customTitleBar_,
        &ks::ui::CustomTitleBar::activateSearchInput);
    connect(
        globalUiSearchController_,
        &ks::ui::GlobalUiSearchController::searchScopeDisplayTextChanged,
        customTitleBar_,
        &ks::ui::CustomTitleBar::setSearchScopeDisplayText);
    customTitleBar_->setSearchScopeDisplayText(
        globalUiSearchController_->searchScopeDisplayText());
    globalUiSearchController_->setSearchInputActive(
        customTitleBar_->isSearchInputModeActive());

    connect(
        customTitleBar_,
        &ks::ui::CustomTitleBar::searchTextEdited,
        globalUiSearchController_,
        &ks::ui::GlobalUiSearchController::handleQueryEdited);
    connect(
        customTitleBar_,
        &ks::ui::CustomTitleBar::inputModeChanged,
        globalUiSearchController_,
        &ks::ui::GlobalUiSearchController::setSearchInputActive);
}

QList<ads::CDockWidget*> MainWindow::collectSearchableDockWidgets() const
{
    // Order determines the result arrangement order: main function Docks first, auxiliary Docks later.
    return QList<ads::CDockWidget*>{
        dockWelcome_,
        dockProcess_,
        dockNetwork_,
        dockMemory_,
        dockFile_,
        dockDriver_,
        dockKernel_,
        dockKvm_,
        dockMonitorTab_,
        dockHardware_,
        dockPrivilege_,
        dockWindow_,
        dockRegistry_,
        dockHandle_,
        dockStartup_,
        dockService_,
        dockMisc_,
        dockLog_,
        dockMonitor_,
        dockCurrentOp_
    };
}

void MainWindow::activateDockForSearchNavigation(ads::CDockWidget* dockWidget)
{
    if (dockWidget == nullptr)
    {
        return;
    }

    ensureDockContentInitialized(dockWidget);
    withTemporaryNonTopMostForDockSwitch([dockWidget]()
        {
            if (dockWidget->isClosed())
            {
                // Auxiliary docks (logs/monitoring/tasks) can be closed; restore visibility before activation.
                dockWidget->toggleView(true);
            }
            dockWidget->raise();
        });
}

void MainWindow::setPinnedWindowState(const bool pinnedState, const bool emitLog)
{
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
        const qulonglong kMainWindowHandleValue =
            static_cast<qulonglong>(reinterpret_cast<quintptr>(kMainWindowHandle));
        appInstance->setProperty(
            kKswordMainWindowHwndPropertyName,
            QVariant(kMainWindowHandleValue));
    }

    if (windowPinned_ == pinnedState)
    {
        if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
        {
            appInstance->setProperty(kKswordMainWindowTopMostPropertyName, windowPinned_);
        }
        syncTopMostForAllAuxiliaryTopLevelWidgets(this, windowPinned_);
        if (customTitleBar_ != nullptr)
        {
            customTitleBar_->setPinnedState(windowPinned_);
        }
        return;
    }

    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle == nullptr || ::IsWindow(kMainWindowHandle) == FALSE)
    {
        KLogEvent failedEvent;
        err << failedEvent << "[MainWindow] 置顶切换失败：主窗口句柄无效。" << eol;
        return;
    }

    DWORD errorCode = ERROR_SUCCESS;
    bool uiAccessBandApplied = false;
    const bool kSetTopMostResult = applyHighestPermittedTopMostLevel(
        kMainWindowHandle,
        pinnedState,
        &errorCode,
        &uiAccessBandApplied);
    if (!kSetTopMostResult)
    {
        KLogEvent failedEvent;
        err << failedEvent
            << "[MainWindow] 最高级置顶切换失败, targetPinned="
            << (pinnedState ? "true" : "false")
            << ", errorCode="
            << errorCode
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("窗口置顶"),
            QStringLiteral("置顶状态切换失败，错误码：%1").arg(errorCode));
        return;
    }

    windowPinned_ = pinnedState;
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        appInstance->setProperty(kKswordMainWindowTopMostPropertyName, windowPinned_);
    }
    syncTopMostForAllAuxiliaryTopLevelWidgets(this, windowPinned_);
    if (customTitleBar_ != nullptr)
    {
        customTitleBar_->setPinnedState(windowPinned_);
    }

    if (emitLog)
    {
        KLogEvent pinEvent;
        info << pinEvent
            << "[MainWindow] 置顶状态已切换到当前权限允许的最高层级, pinned="
            << (windowPinned_ ? "true" : "false")
            << ", uiAccessBand="
            << (uiAccessBandApplied ? "true" : "false")
            << eol;
    }
}

void MainWindow::togglePinnedWindowState()
{
    setPinnedWindowState(!windowPinned_, true);
    persistPinnedWindowPreference();
}

void MainWindow::persistPinnedWindowPreference()
{
    // pinnedSettings purpose: Copy current appearance settings and update only the startup top-most preference to avoid overwriting other settings.
    ks::settings::AppearanceSettings pinnedSettings = currentAppearanceSettings_;
    if (pinnedSettings.startupTopMostEnabled == windowPinned_)
    {
        return;
    }

    pinnedSettings.startupTopMostEnabled = windowPinned_;
    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(pinnedSettings, &saveErrorText))
    {
        KLogEvent pinPersistFailedEvent;
        err << pinPersistFailedEvent
            << "[MainWindow] 保存窗口置顶偏好失败，错误="
            << saveErrorText.toStdString()
            << eol;
        return;
    }

    currentAppearanceSettings_ = pinnedSettings;
    KLogEvent pinPersistEvent;
    info << pinPersistEvent
        << "[MainWindow] 已保存窗口置顶启动偏好, startupTopMost="
        << (currentAppearanceSettings_.startupTopMostEnabled ? "true" : "false")
        << eol;
}

void MainWindow::setCaptureProtectionState(const bool protectedState, const bool emitLog)
{
    if (captureProtectionEnabled_ == protectedState)
    {
        if (customTitleBar_ != nullptr)
        {
            customTitleBar_->setCaptureProtectionState(captureProtectionEnabled_);
        }
        return;
    }

    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle == nullptr || ::IsWindow(kMainWindowHandle) == FALSE)
    {
        KLogEvent failedEvent;
        err << failedEvent << "[MainWindow] 截屏屏蔽切换失败：主窗口句柄无效。" << eol;
        return;
    }

    // Target policy:
    // - When enabled, first request WDA_EXCLUDEFROMCAPTURE; on Windows 10 20H2+, this hides the window from screenshots and screen recordings.
    // - If the system or window composition does not support it, fall back to WDA_MONITOR; older systems will display a black screen during screenshots or screen recording.
    // - Write WDA_NONE on close to restore normal capture.
    DWORD appliedAffinity = kWindowDisplayAffinityAllowCapture;
    BOOL setAffinityResult = FALSE;
    if (protectedState)
    {
        appliedAffinity = kWindowDisplayAffinityExcludeFromCapture;
        setAffinityResult = ::SetWindowDisplayAffinity(kMainWindowHandle, appliedAffinity);
        if (setAffinityResult == FALSE)
        {
            appliedAffinity = kWindowDisplayAffinityMonitorOnly;
            setAffinityResult = ::SetWindowDisplayAffinity(kMainWindowHandle, appliedAffinity);
        }
    }
    else
    {
        appliedAffinity = kWindowDisplayAffinityAllowCapture;
        setAffinityResult = ::SetWindowDisplayAffinity(kMainWindowHandle, appliedAffinity);
    }

    if (setAffinityResult == FALSE)
    {
        const DWORD kErrorCode = ::GetLastError();
        KLogEvent failedEvent;
        err << failedEvent
            << "[MainWindow] 截屏屏蔽切换失败, targetProtected="
            << (protectedState ? "true" : "false")
            << ", errorCode="
            << kErrorCode
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("截屏屏蔽"),
            QStringLiteral("截屏屏蔽切换失败，错误码：%1").arg(kErrorCode));
        return;
    }

    captureProtectionEnabled_ = protectedState;
    if (customTitleBar_ != nullptr)
    {
        customTitleBar_->setCaptureProtectionState(captureProtectionEnabled_);
    }

    if (emitLog)
    {
        KLogEvent captureProtectionEvent;
        info << captureProtectionEvent
            << "[MainWindow] 截屏屏蔽状态已切换, protected="
            << (captureProtectionEnabled_ ? "true" : "false")
            << ", affinity=0x"
            << std::hex
            << static_cast<unsigned long>(appliedAffinity)
            << std::dec
            << eol;
    }
}

void MainWindow::toggleCaptureProtectionState()
{
    setCaptureProtectionState(!captureProtectionEnabled_, true);
}

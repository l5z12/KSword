#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QDockWidget>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QDragMoveEvent>
#include <QResizeEvent>
#include <QMoveEvent>
#include <QPushButton>
#include <QShowEvent>
#include <QEvent>
#include <QFont>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QString>
#include <QByteArray>
#include <QPixmap>
#include <QToolButton>

#include <functional>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

// ADS header files
#include "include/ads/DockManager.h"
#include "include/ads/DockWidget.h"
#include "include/ads/DockAreaWidget.h"
#include "kvm_dock/KvmDock.h" // The public API uses KvmDock::Action.
#include "settings_dock/AppearanceSettings.h"
// KvmAvailability: The state of the virtualization button in the top-right corner is derived from this complete value; see m_kvmAvailability.
#include "ui/KvmControl.h"

// Dock implementations are private to the translation units that use them.
class WelcomeDock;
class ProcessDock;
class NetworkDock;
class MemoryDock;
class FileDock;
class DriverDock;
class KernelDock;
class MonitorDock;
class MonitorPanelWidget;
class HardwareDock;
class PrivilegeDock;
class StartupDock;
class ServiceDock;
class WindowDock;
class RegistryDock;
class MiscDock;
class HandleDock;

class LogDockWidget; // Forward declaration: Log Dock widget type.
class ProgressDockWidget; // Forward declaration: Current operation progress panel type.
class CodeEditorWidget; // Forward declaration: the immediate window can reuse the code editor component.
namespace ks::ui
{
    class CustomTitleBar; // Forward declaration: Main window custom-drawn title bar component.
    class GlobalUiSearchController; // Forward declaration: Title bar global page search controller.
    class CommandExecutionPopup; // Forward declaration: title bar CMD command option popup.
    struct CommandExecutionOptions; // Forward declaration: CMD command launch options snapshot.
    class NotificationCardManager;
}

class QDialog;
class QScreen;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // StartupProgressCallback:
    // - Passes sub-phase progress back to the startup screen during main window construction;
    // - The main function can accept a lambda to synchronize text and percentage with the splash screen.
    using StartupProgressCallback = std::function<void(int, const QString&)>;

    // Constructor purpose:
    // - initialize the main window's menu, docks, layout, and appearance.
    // - Optionally continuously report startup progress to the splash screen.
    // Parameter parent: Qt parent object.
    // Parameter startupProgressCallback: the startup progress callback; ignored if null.
    // Parameter startupSystemFont: System font baseline captured before reading persistent appearance configuration.
    explicit MainWindow(
        QWidget* parent,
        StartupProgressCallback startupProgressCallback,
        const QFont& startupSystemFont);
    ~MainWindow();

public slots:
    // focusHandleDockByPid:
    // - Bring the 'Handle' Dock to the front and switch PID filtering;
    // - Called when the process details window initiates 'Jump to Handle View'.
    // Invocation method: QMetaObject::invokeMethod(mainWindow, "focusHandleDockByPid", ...).
    // Input parameter pid: The target process PID.
    void focusHandleDockByPid(quint32 pid);
    void focusHandleDockByPids(const QString& pidListText);

    // focusProcessProtectByCallback：
    // - Brings the 'Kernel' Dock to the front and switches to the process protection page for object handle callbacks;
    // - Provide a shortcut entry for process pages without duplicating callback rule editing logic.
    void focusProcessProtectByCallback();

    // focusMemoryDockByPid:
    // - Brings the 'Memory' Dock to the front and attaches the target process for easier memory region inspection and dumping.
    // Invocation: Called from the Process page's right-click context menu 'Jump to Memory Operations'.
    // Input parameter pid: The target process PID.
    void focusMemoryDockByPid(quint32 pid);
    // focusMemoryDockDdmaPage: Opens the memory Dock and switches to the DDMA sub-page.
    // Clicking the DDMA indicator in the top-right corner routes here—registration and deregistration of resident virtual sectors both occur on that page.
    void focusMemoryDockDdmaPage();
    void focusNetworkDockByPids(const QString& pidListText);
    void focusWindowDockByPids(const QString& pidListText);

    // openProcessDetailByPid:
    // - Open an independent process detail window for the specified PID without changing the current Dock tab.
    // - Used by the FileDock 'Handle Scan Results' window for navigation.
    // Invocation method: QMetaObject::invokeMethod(mainWindow, "openProcessDetailByPid", ...).
    // Input parameter pid: The target process PID.
    void openProcessDetailByPid(quint32 pid);

    // openProcessDetailByIdentity:
    // - Opens an independent process detail window for the historical record corresponding to the PID + creation time, without changing the current Dock tab.
    // - Invocation: Called by the history event jump entry in TableInteractionSupport;
    // - Input parameter pid: historical process PID;
    // - Input creationTime100ns: Process creation time captured at the moment;
    // - Return: None; ProcessDock is responsible for rejecting targets that have exited or whose PIDs have been reused.
    void openProcessDetailByIdentity(
        quint32 pid,
        quint64 creationTime100ns);

    // focusServiceDockByName:
    // - Brings the 'Services' Dock to the front and locates the target row by service name;
    // - Called by the 'Go to Service Management' entry in StartupDock.
    // Input serviceNameText: Target service short name.
    void focusServiceDockByName(const QString& serviceNameText);

    // openFileDetailDockByPath:
    // - Bring the 'Files' Dock to the front and open the detail analysis window for the specified file;
    // - Used by ServiceDock for BinaryPath/ServiceDll linkage calls.
    // Input filePath: Target file path.
    void openFileDetailDockByPath(const QString& filePath);

    // openFileUnlockerDockByPath:
    // - Reuse the FileDock internal "File Unlocker (R3/R0)" flow via the Shell right-click entry.
    // - Avoids initializing or switching the File Dock page to prevent lazy-loading the file page during startup from affecting popup display.
    // - Used for automatic linkage invocation after starting via the system context menu command.
    // Parameter filePath: Path to the target file or directory.
    void openFileUnlockerDockByPath(const QString& filePath);

signals:
    // r0DriverServiceStarted: Notifies waiting features to retry their read-only queries after the R0 driver service confirms startup.
    void r0DriverServiceStarted();

protected:
    // eventFilter:
    // - Listen for display and size changes of the ADS floating Dock window;
    // - After the floating window detaches from the main window, synchronize the solid color/background image fill to match the main interface.
    bool eventFilter(QObject* watchedObject, QEvent* event) override;

    // closeEvent:
    // - Explicitly trigger application exit when the main window closes;
    // - Prevent floating docks or background windows from lingering and causing processes to not terminate.
    // Invocation method: automatically called back when the Qt window is closed.
    // Input parameter event: the close event object; the function accepts it and triggers quit/exit.
    void closeEvent(QCloseEvent* event) override;

    // resizeEvent:
    // - Regenerate the background brush when the window size changes to prevent background image stretching and distortion.
    // - Maintain full-window background coverage after switching between light and dark themes.
    // Invocation: Qt automatically calls this back when the window size changes.
    // Parameter event: Size change event object.
    void resizeEvent(QResizeEvent* event) override;

    // moveEvent: Updates the screen notification to follow the new workspace after the main window moves across displays.
    void moveEvent(QMoveEvent* event) override;

    // showEvent:
    // - Start delayed page loading only after the main window is first displayed.
    // - Ensure the window appears first before completing the remaining Dock content.
    void showEvent(QShowEvent* event) override;

    // changeEvent:
    // - Listen for window maximize/restore state changes.
    // - Synchronize the maximized button icon state in the custom-drawn title bar.
    void changeEvent(QEvent* event) override;

    // nativeEvent:
    // - Handle hit testing for borderless windows (dragging and edge resizing);
    // - Return HTCAPTION for the custom-drawn title bar draggable area.
    // Invocation: Qt automatically callbacks this within the Windows message loop.
    // Parameters eventType/message/result: native message parameters.
    // Returns: true if handled; false to proceed with base class default handling.
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;

private:
    void initMenus();
    // initializeWindowDockMenuActions：
    // - After the auxiliary Dock is created, attach ADS native show/hide actions to the "Window" menu.
    // - The menu check state is automatically synchronized with the Dock toggle via CDockWidget::toggleViewAction.
    void initializeWindowDockMenuActions();
    void initPrivilegeStatusButtons();
    // attachPrivilegeStatusButtonsToPrimaryDockTabBar：
    // - Attach global privilege status button group to the right side of the Tab bar of the main Dock belonging to the Welcome page;
    // - Called after layout restoration; the welcome page button group moves with the Dock Area when the user moves or floats the layout.
    void attachPrivilegeStatusButtonsToPrimaryDockTabBar();
    void refreshPrivilegeStatusButtons();

    // applyPrivilegeButtonVisibility:
    // - Show or hide each button in the top-right privilege button row based on settings; collapse the entire row when all are hidden;
    // - Updates the hardware virtualization button's title and tooltip to the name selected in settings.
    // Call method: Called at the start of refreshPrivilegeStatusButtons and when settings change.
    void applyPrivilegeButtonVisibility();
    void applyPrivilegeButtonStyle(QPushButton* button, bool activeState);
    void handleR0DriverUnavailable(unsigned long win32Error);
    void handleR0PermissionRequired(unsigned long win32Error);
    void enableR0ForUserRequest();

    // handleUiAccessButtonClicked:
    // - Handle the title bar UIAccess button click;
    // - If the current instance already has UIAccess, downgrade to a standard user instance.
    // - Otherwise, trigger elevation on demand and attempt to start via SYSTEM TokenUIAccess fallback.
    void handleUiAccessButtonClicked();
    void handleR0StatusButtonClicked();

    // KVM (KSwordVM, Layer-1) button:
    // - handleKvmStatusButtonClicked: toggles resident mode on left-click; auto-initializes and self-checks if not ready;
    // - showKvmMenu: Right-click/long-press to pop up the R-1 capability menu (write permission switch, keep self-check, fault reset).
    // - refreshKvmStatusAsync: Read the HVM status snapshot on a background thread, then refresh the button on the UI thread.
    //   Status queries are blocking IOCTLs and must never be called directly in the synchronous refresh path of permission buttons.
    void handleKvmStatusButtonClicked();
    // DDMA (Direct Disk Memory Access) resident virtual sector button:
    // - handleDdmaStatusButtonClicked: Navigate to the DDMA sub-page of the memory page to configure or unpin.
    // - applyDdmaButtonState: Refreshes the on/off state and tooltip based on the current process-level session; this is a pure local read with no IOCTL calls.
    void handleDdmaStatusButtonClicked();
    void applyDdmaButtonState();
    void showKvmMenu(const QPoint& globalPosition);
    void refreshKvmStatusAsync();
    void applyKvmButtonState();
    // runKvmSoak: Start the resident hypervisor, hold it for the specified milliseconds, then stop it to demonstrate sustained resident operation.
    void runKvmSoak(unsigned long milliseconds);
    // runKvmFaultReset: Clear recoverable faults and rollback markers; rejected by the driver when running in resident mode.
    void runKvmFaultReset();
    // runKvmPrepare/runKvmRelease: Exposes PREPARE and TEARDOWN to the KVM menu.
    // Without these two entry points, the window for installing views/policies/domains cannot be triggered from this menu.
    void runKvmPrepare();
    void runKvmRelease();
    // handleKvmDockAction: the sole entry point for virtualization (KVM) pages, dispatching each action to the implementations listed above.
    // Both entry points share the same implementation to ensure the confirmation criteria cannot diverge into two sets.
    void handleKvmDockAction(KvmDock::Action action);
    // createKvmDockContent: Shared construction and wiring for two creation points (preloading and lazy fallback).
    KvmDock* createKvmDockContent();

    // hasUiAccessPrivilege:
    // - Query the current process's TokenUIAccess privilege status.
    // - Returns true if the current instance already has UIAccess privileges.
    bool hasUiAccessPrivilege() const;

    // launchSelfWithSystemUiAccessToken:
    // - Obtain the SYSTEM process token; DuplicateTokenEx is used for the primary token.
    // - Calls SetTokenInformation(TokenUIAccess) on the copied token;
    // - Finally launches itself via CreateProcessAsUserW.
    bool launchSelfWithSystemUiAccessToken(QString* detailTextOut);
    bool queryR0DriverServiceRunning(bool& runningOut, bool fatalOnError);
    // suppressPrivilegeElevationPrompt: When true, only shows a startup failure if privileges are insufficient, without prompting for admin restart/UAC.
    bool startR0DriverService(bool suppressPrivilegeElevationPrompt = false);
    bool stopR0DriverService(bool suppressErrorDialog = false);
    // prepareR0DriverServiceStop:
    // - Inputs: None;
    // - Processing: Unify convergence of R3 long connections and R0 runtime state before SCM stops KswordARK.
    // - Returns: None. All cleanup is best-effort; failures only log and do not block the actual driver unload request.
    void prepareR0DriverServiceStop();
    // stopR0RuntimeConsumersBeforeServiceStop:
    // - Inputs: None;
    // - Processing: Close R0 log/callback wait handles held long-term by this process before stopping the KswordARK service.
    // - Returns: No return value; underlying stop call releases resources on a best-effort basis.
    void stopR0RuntimeConsumersBeforeServiceStop();
    // startR0RuntimeConsumersAfterServiceStart:
    // - Inputs: None;
    // - Processing: Restore log polling and callback wait manager after KswordARK service starts or is confirmed running.
    // - Return: None. Repeated calls are idempotently ignored by submodules.
    void startR0RuntimeConsumersAfterServiceStart();
    // refreshR0DynDataAfterServiceStart:
    // - Inputs: None;
    // - Processing: Immediately trigger DynData profile pack matching and distribution after the KswordARK driver is loaded;
    // - Returns: None. On failure, only logs the event; R0 functionality remains backed by driver-side runtime fallback.
    void refreshR0DynDataAfterServiceStart();
    void startR0DriverLogPoller();
    void stopR0DriverLogPoller();
    void runR0DriverLogPollerLoop();
    void dispatchR0DriverLogRecord(const std::string& logRecordText);
    bool showUnsignedDriverFailureDialog(unsigned long errorCode, const QString& operationText);
    bool enableWindowsTestModeAndPromptReboot();
    bool isR0DriverSignatureFailure(unsigned long errorCode) const;
    void showR0FatalError(const QString& stageText, unsigned long errorCode, const QString& detailText = QString());
    void requestAdminElevationRestart(bool enableR0AfterRestart = false);
    bool hasAdminPrivilege() const;
    bool hasDebugPrivilege() const;
    bool hasSystemPrivilege() const;
    bool enableSeDebugPrivilege(std::string& errorTextOut) const;
    void initDockWidgets();
    QWidget* createDockPlaceholderWidget(const QString& titleText) const;
    void ensureDockContentInitialized(ads::CDockWidget* dockWidget);

    // BackdropBlurKind:
    // - Describes the blur implementation method after parsing the 'transparent background effect' configuration.
    // - On Windows 11, the traditional BLURBEHIND(3) has degraded to pure transparency ignoring shading, and
    //   DWM Mica is mutually exclusive with layered transparent windows (causing the entire window to appear
    //   washed out). Therefore, system Acrylic is the only available real-time frosted effect for this project.
    enum class BackdropBlurKind
    {
        kNone = 0,    // None: No frosted effect; transparent areas directly reveal content behind.
        kAcrylic,     // Acrylic: ACCENT_ENABLE_ACRYLICBLURBEHIND, applying blur, saturation, and noise.
    };

    // applyMainWindowBackdropMaterial:
    // - Apply/close the system acrylic material for the main window (SetWindowCompositionAttribute);
    // - In transparent mode, enables the 'transparent background effect' option to render transparent areas with a frosted texture;
    // - The tint layer opacity is taken from m_currentAppearanceSettings.acrylicTintOpacityPercent; the blur radius
    //   cannot be adjusted via this interface (ACCENT_POLICY lacks a radius field, which is fixed internally by DWM).
    // Input parameter blurKind: The parsed material type; only Acrylic enables system materials.
    // Return: true indicates system Acrylic is active (coloring is composed by the system; the root container no longer draws a separate coloring layer).
    bool applyMainWindowBackdropMaterial(BackdropBlurKind blurKind);

    // scheduleWindowBackdropRefresh:
    // - Merge and schedule a single re-dispatch of composition properties after window scaling, state changes, activation changes, or cross-monitor transitions.
    // - Focus loss, minimization restoration, and screen switching may cause the system to
    //   downgrade Acrylic to a static fallback color; a re-push is required to restore it.
    // - Not invoked during same-screen moves: DWM automatically re-samples background content based on the new position (empirical tests
    //   show all three handling methods yield identical results); refreshing further would only incur an unnecessary full tree repaint.
    // - Execute only when Acrylic is active, and merge continuous events via window throttling.
    void scheduleWindowBackdropRefresh();

    // refreshWindowBackdropMaterial:
    // - Determine whether to enable the frosted glass effect based on the current 'Transparent Background Effect' configuration, and synchronize the root container shading strategy.
    // - The initial appearance application occurs before the native window is created, so showEvent must be called
    //   again; otherwise, the frosted glass effect selected at startup will only take effect after the next theme change.
    void refreshWindowBackdropMaterial();

    // refreshBackgroundImageBlurCache:
    // - Rebuild the blurred copy of the background image based on the 'Glass Blur Radius' setting; clear the copy when the radius is 0.
    // Both the main window root container and floating dock brushes retrieve images via cachedBackgroundImage;
    //   generating them here ensures consistent appearance and avoids re-blurring on every repaint.
    // - The system's acrylic blur radius is fixed internally by DWM (ACCENT_POLICY has no
    //   radius field), so adjustable radii only apply to this layer of custom-drawn blur.
    void refreshBackgroundImageBlurCache();

    // configureDockWidgetPersistentIdentity:
    // - Set a stable objectName for each ADS Dock.
    // - ADS saveState/restoreState relies on objectName matching the Dock; it cannot rely on mutable title text.
    // - Input parameters dockWidget: the Dock to be configured; dockKey: a stable English key.
    void configureDockWidgetPersistentIdentity(ads::CDockWidget* dockWidget, const QString& dockKey) const;

    // restoreDockLayoutFromConfig:
    // - Read layout configuration after the default Dock topology is created.
    // - Restores the user's previous drag/dock/tab activation state on success;
    // - Returns true on successful restoration; false if no configuration exists or restoration fails.
    bool restoreDockLayoutFromConfig();

    // saveDockLayoutToConfig:
    // - Save the ADS DockManager layout state before exiting.
    // Configuration file is saved to config/ksword_ads_layout.bin in the directory where the application exe resides;
    // - Returns true if the write was successful.
    bool saveDockLayoutToConfig() const;

    // resetDockLayoutToDefault: discards the saved dock layout and restores the default arrangement on the next startup.
    //
    // Reason for existence: Top tabs can be dragged into disorder, and before this, there was **no UI entry** to return
    // to the default state; users had to manually locate and delete the .bin file in the exe directory's config folder.
    void resetDockLayoutToDefault();

    // m_suppressDockLayoutSave: Blocks layout write-back for the current exit after reset.
    // Without blocking, the deleted file would be written back with the current layout intact the moment the application closes.
    bool suppressDockLayoutSave_ = false;

    // resolveDockLayoutConfigPath:
    // - Unify generating the absolute path for ADS layout configuration files.
    // - The write target is fixed to the config folder in the directory where the application exe resides; it does not fall back to the source tree.
    QString resolveDockLayoutConfigPath() const;

    // showSettingsPanelFromMenu：
    // - Purpose: Open settings content from the top menu bar, replacing the 'Settings' tab in the main Dock Tab.
    // - When showLanguageTab is true, directly navigate to the language settings page.
    void showSettingsPanelFromMenu(bool showLanguageTab = false);
    void toggleLogOutputWindow();
    void persistLogOutputWindowGeometry();
    void restoreLogOutputWindowGeometry();
    // openProjectPageFromMenu purpose: Opens an external link related to a project; displays failureTitle on failure.
    void openProjectPageFromMenu(const QString& urlText, const QString& failureTitle);
    // showLicenseFromMenu: Reads the LICENSE file in the program's directory and displays its content.
    void showLicenseFromMenu();

    // buildTitleActionButtonStyle:
    // - Uniformly generate styles for left-side title bar action buttons.
    // - Reapply after switching between light and dark themes to prevent title bar text color drift.
    // Returns: Style text directly applicable to QToolButton.
    QString buildTitleActionButtonStyle() const;

    // refreshTitleActionButtonStyles:
    // - Refresh the title bar top-level menu buttons for Options/GitHub/Window according to the current theme.
    // Resolves the issue of residual light-style artifacts after switching to dark mode.
    void refreshTitleActionButtonStyles();

    void initializeNextDeferredDock();

    // ensureVisibleLazyDocksInitialized:
    // - Input reasonText: Trigger reason, written to logs for troubleshooting startup black screen;
    // - Processing: Scan current/visible lazy ADS docks; if the placeholder page has entered the display path, immediately mount the real content.
    // - Returns: Nothing.
    void ensureVisibleLazyDocksInitialized(const QString& reasonText);

    // repairKernelDockAfterLayoutRestore:
    // - Input reasonText: trigger source, written to logs to help troubleshoot kernel Dock startup black screen;
    // - Processing: Verify that the ADS kernel Dock mounts a KernelDock instance rather than a placeholder page or empty shell, and trigger a repaint of the current internal page.
    // - Returns: Nothing.
    void repairKernelDockAfterLayoutRestore(const QString& reasonText);

    // reportStartupProgress:
    // - Safely invoke startup progress callback;
    // - Allows each stage within mainWindow to actively update the splash screen text.
    // Input progressPercent: Stage progress percentage.
    // Input textKey: stable location key in the language pack.
    // Parameter fallbackText: fallback product text when the language pack is unavailable.
    void reportStartupProgress(
        int progressPercent,
        const QString& textKey,
        const QString& fallbackText) const;

    // initAppearanceSettings:
    // - Read appearance configuration from SettingsDock/JSON;
    // - Bind callbacks for system light/dark theme changes;
    // - Apply appearance settings immediately at startup.
    // Invocation: called at the end of mainWindow construction.
    void initAppearanceSettings();

    // updateBugcheckDiagnosticsEntryVisibility: Syncs persistent configuration with the current installation status to the Miscellaneous page entry.
    // Usage: Called after the Miscellaneous page is constructed, when the Settings page modifies the auto-install option, or after IOCTL installation succeeds.
    // Returns: Nothing.
    void updateBugcheckDiagnosticsEntryVisibility();

    // installBugcheckDiagnosticsAfterServiceStart function: Automatically sends an installation IOCTL in the background after the R0 service starts, if enabled.
    // Invocation: called internally by startR0RuntimeConsumersAfterServiceStart; Return: none; Failure: logs only.
    void installBugcheckDiagnosticsAfterServiceStart();

    // reattachDetachedFeatureDocks:
    // - Reclaim main feature Docks still floating in floating containers after layout restoration back to the main Dock area;
    // - The user's layout configuration was saved in an older version that did not include the newly added docks;
    //   ADS restoreState does not assign positions for them, resulting in new features defaulting to pop-up windows.
    // - Since every new main feature Dock encounters the same issue, implement a general fix rather than a special case.
    // Call once after restoreDockLayoutFromConfig.
    void reattachDetachedFeatureDocks();

    // checkRecentCrashDumps:
    // - After startup stabilizes, check if any new crash dumps were generated within the last 24 hours.
    // - If present, prompt with a dialog to parse immediately; the dialog includes a 'Do not check again' option.
    // - Ask only once per dump; record the decision in the appearance configuration.
    // Usage: call once within the delayed task of showEvent; return directly when closing.
    void checkRecentCrashDumps();

    // openMinidumpDockWithFile:
    // - Activate the "Dump Analysis" tab (perform lazy loading if necessary) and have it parse the specified file.
    // - This page has been merged into the "Misc" Dock; the function first activates the Misc page before switching to the dump analysis sub-page.
    // Input parameter filePath: full path to the dump file.
    void openMinidumpDockWithFile(const QString& filePath);

    // activateMiscDockForMergedTab:
    // - Activate the "Misc" Dock and ensure its content controls have completed lazy loading.
    // - For reuse of entries merged into the Misc tab, such as "Scanner / Dump Analysis / Plugins".
    // Input tabDisplayName: the target sub-page display name, used only for log localization on failure.
    // Returns: the Miscellaneous page content control; returns nullptr if the Dock is not yet available.
    MiscDock* activateMiscDockForMergedTab(const QString& tabDisplayName);

    void setupDockLayout();

    // initCustomTitleBar:
    // - initialize the main window's custom-drawn title bar to replace the system title bar.
    // - Bind signals for three interaction types: pinning, window control, and command input.
    void initCustomTitleBar();

    // initGlobalUiSearchController:
    // - Create a global page search controller for the title bar "Search" mode.
    // - Inject the Dock list, lazy-load initialization, and callbacks to bring the Dock to the front upon activation.
    // - Connect title bar search text and input mode signals.
    // Usage: call once after initCustomTitleBar completes title bar creation.
    void initGlobalUiSearchController();

    // collectSearchableDockWidgets:
    // - Collect the list of Dock widgets participating in global page search (main feature Dock + auxiliary Dock).
    // - Order determines result sorting; null pointers are ignored by the search side.
    QList<ads::CDockWidget*> collectSearchableDockWidgets() const;

    // activateDockForSearchNavigation:
    // - Bring the target Dock to the front when activating search results: first populate lazy-loaded
    //   content, restore visibility for closed Docks, then raise as the active tab under z-order protection.
    // Parameter dockWidget: the target Dock; ignore if null.
    void activateDockForSearchNavigation(ads::CDockWidget* dockWidget);

    // syncCustomTitleBarMaximizedState:
    // - Unified calculation of whether the main window is in the maximized state and refresh the second button icon on the title bar;
    // - Compatible with Qt state and Win32 Zoomed state to avoid icon inconsistency during transition.
    void syncCustomTitleBarMaximizedState();

    // ensureNativeFramelessWindowStyle:
    // - In borderless mode, restore Win32 scalable and maximizable style bits;
    // - Fix intermittent failures in the Win+↑/Win+↓ to system maximize link.
    void ensureNativeFramelessWindowStyle();

    // applyNativeWindowFrameVisualStyle:
    // - Synchronize the current light/dark theme state with DWM and disable system-visible borders.
    // - Fix the issue where the main window briefly flashes a white border when focus changes.
    // Usage: Called after the window handle is created or after a theme switch.
    void applyNativeWindowFrameVisualStyle();

    // initResizeBorderOverlays:
    // - Create four independent 3px theme-blue border controls;
    // - Does not modify the root container's background or layout to avoid color bleed contaminating the title bar or menu bar.
    void initResizeBorderOverlays();

    // updateResizeBorderOverlays:
    // - Reposition the four 3px borders based on the current window size.
    // - Hide the border when maximized; show and bring to front when restored.
    void updateResizeBorderOverlays();

    // applyResizeBorderOverlayStyle:
    // - Refresh four border control styles based on current theme's primary blue;
    // - Can be called repeatedly after theme switching.
    void applyResizeBorderOverlayStyle();

    // handleResizeBorderOverlayEvent:
    // - Handle mouse movement and clicks on the four border controls;
    // - Bridges left-click events to Win32 native border resize messages.
    bool handleResizeBorderOverlayEvent(QObject* watchedObject, QEvent* event);

    // ensureStartupWindowVisibleOnScreen:
    // - After the main window is shown for the first time, constrain the window size and position to the currently visible screen.
    // - Fixes issues where the window's initial area falls outside the screen or the entire window exceeds the visible area under low resolution/high DPI scaling.
    // - Only corrects the normal window state; maximized state remains under system control.
    void ensureStartupWindowVisibleOnScreen();

    // isWindowActuallyMaximized:
    // - Combine Qt state with Win32 IsZoomed to determine the actual maximized state.
    // - Avoid relying solely on isMaximized() to prevent button state drift.
    bool isWindowActuallyMaximized() const;

    // setWindowMaximizedBySystemCommand:
    // - Execute maximize/restore via native Win32 window state APIs.
    // - Avoid synchronous SendMessage reentrancy in the title bar double-click message handler to prevent flickering and state corruption.
    // Input targetMaximizedState: true = maximize; false = restore.
    void setWindowMaximizedBySystemCommand(bool targetMaximizedState);

    // setPinnedWindowState:
    // - Set the main window's pinned state and synchronize the title bar pin icon.
    // - Internally uses SetWindowPos to toggle between HWND_TOPMOST and HWND_NOTOPMOST.
    // Parameter pinnedState: Target pinned state.
    // Input parameter emitLog: whether to log the state toggle.
    void setPinnedWindowState(bool pinnedState, bool emitLog = true);

    // togglePinnedWindowState:
    // - Toggle the current pinned state by inverting it.
    void togglePinnedWindowState();

    // persistPinnedWindowPreference:
    // - Save the pinned window preference after manually toggling the pin in the top-right corner to the settings JSON.
    // - The same field is reused for the next startup and the settings page.
    void persistPinnedWindowPreference();

    // setCaptureProtectionState:
    // - Set the main window screenshot protection state and synchronize the title bar eye icon;
    // - On Windows 10 20H2 and later, WDA_EXCLUDEFROMCAPTURE is preferred to hide windows.
    // - Falls back to WDA_MONITOR in the legacy system to display a black screen in screenshots/screen recordings.
    // Input protectedState: true enables screenshot blocking, false allows screenshots.
    // Input parameter emitLog: whether to log the state toggle.
    void setCaptureProtectionState(bool protectedState, bool emitLog = true);

    // toggleCaptureProtectionState:
    // - Toggle the state by inverting the current screenshot protection status.
    void toggleCaptureProtectionState();

    // executeCommandInNewConsole:
    // - Open a visible cmd using CREATE_NEW_CONSOLE and execute the /K command.
    // - Fallback to the current user, current privileges, and visible CMD window when no popup layer instance exists.
    // Parameter commandText: the command text to execute (user input).
    void executeCommandInNewConsole(const QString& commandText);

    // executeCommandWithOptions:
    // - Launch the command using the directory, user, privilege level, and window options provided by the title bar CMD popup.
    // - Standard CreateProcess, token-based CreateProcessAsUser, and UAC runas are all unified here.
    // Input parameter commandText: the command text to be executed.
    // Input parameter options: current snapshot of the dialog options.
    void executeCommandWithOptions(
        const QString& commandText,
        const ks::ui::CommandExecutionOptions& options);

    // applyAppearanceSettings:
    // - Applies the theme mode, background image, and transparency to the main window.
    // - Force set the window background color to avoid Win11 automatically taking over the background.
    // Usage: Called during initialization, when settings change, or when system colors change.
    // Input settings: the appearance configuration structure.
    // Parameter triggerReason: Text describing the trigger source (for logging).
    void applyAppearanceSettings(const ks::settings::AppearanceSettings& settings, const QString& triggerReason);

    // refreshThemeDependentVisuals:
    // - Uniformly rebuild styles for all dedicated controls that directly depend on light/dark themes or custom theme colors.
    // - Avoid missing custom color hot updates when new theme color consumers only subscribe to light/dark mode changes.
    // Usage: Called by applyAppearanceSettings after theme visual seeds change and the main window QSS is updated.
    // Input darkModeEnabled: the current effective dark mode state; output: none.
    void refreshThemeDependentVisuals(bool darkModeEnabled);

    // isDarkModeEffective:
    // - Calculates whether dark mode is currently effective based on 'manual light/dark' or 'follow system' settings.
    // Invocation: Call when applying styles or rebuilding the background.
    // Input settings: the appearance configuration structure.
    // Returns: true for dark mode; false for light mode.
    bool isDarkModeEffective(const ks::settings::AppearanceSettings& settings) const;

    // rebuildWindowBackgroundBrush:
    // - Pass the current solid color, background image, and transparency to the main window background host.
    // - Actual scaling and centering are performed in the background host's paintEvent using the real rect.
    // Invocation: Called when appearance settings change.
    void rebuildWindowBackgroundBrush(bool includeBackgroundImage = true);

    // queueBackgroundImageValidation:
    // - Only dispatches path probing and image decoding to the thread pool when the background path changes.
    // - The UI thread immediately switches to the 'not ready' cached state without accessing UNC or offline drives.
    // Parameter rawImagePath: original background path from configuration; Output: none.
    void queueBackgroundImageValidation(const QString& rawImagePath);

    // isCachedBackgroundImageReady:
    // - Only compare in-memory path keys, ready flags, and pixel cache; no file system calls are performed.
    // - Purpose: Safe reuse for themes, scrollbars, Dock lazy initialization, and floating container refresh.
    // Input rawImagePath: configuration path to match; Return: whether the cached image is ready for use.
    bool isCachedBackgroundImageReady(const QString& rawImagePath) const;

    // shouldRenderTransparentDockContent:
    // - Check if the Dock content root control must relinquish custom solid background rendering.
    // - When the background image is ready, reveal the image; when enabling transparent window backgrounds, reveal the mica material or desktop;
    // - If either condition holds, the Dock must not paint an opaque background, which would completely cover the underlying visual layer.
    // Returns: true means content layer should remain transparent.
    bool shouldRenderTransparentDockContent() const;

    // cachedBackgroundImage: Returns a background pixel cache decoded by the thread pool.
    // Input rawImagePath: configuration path to match; Return: valid image pointer, or null.
    const QPixmap* cachedBackgroundImage(const QString& rawImagePath) const;

    // applyFloatingDockContainerAppearance:
    // - Synchronize current theme color, background image, and styles to the specified floating Dock container.
    // - Fixes the issue where the background of a floated window becomes solid black and unrendered after being dragged out.
    void applyFloatingDockContainerAppearance(ads::CFloatingDockContainer* floatingWidget) const;

    // buildAppearanceOverlayStyleSheet:
    // - Generate dark/light mode overlay style strings, applied on top of the base QSS.
    // Call site: invoked internally by applyAppearanceSettings.
    // Parameter darkModeEnabled: whether to use dark mode styling.
    // Input parameter enableDockContentTransparency: whether to force the Dock content layer to be transparent;
    //   Must be true when a background image is available or when the window has a transparent background (Mica/Direct
    //   Transparency); otherwise, the Dock will cover the underlying background image or system material with an opaque surface.
    // Returns: Concatenated QSS fragment.
    QString buildAppearanceOverlayStyleSheet(
        const ks::settings::AppearanceSettings& settings,
        bool darkModeEnabled,
        bool enableDockContentTransparency) const;

    // ADS Dock Manager
    QWidget* mainRootContainer_ = nullptr; // m_mainRootContainer: Main window root container (hosting title bar + Dock manager).
    QVBoxLayout* mainRootLayout_ = nullptr; // m_mainRootLayout: Main window root container vertical layout.
    ads::CDockManager* pDockManager_ = nullptr; // m_pDockManager: ADS Dock manager main object.
    QWidget* resizeBorderTop_ = nullptr; // m_resizeBorderTop: Top 3px theme-blue resize border.
    QWidget* resizeBorderBottom_ = nullptr; // m_resizeBorderBottom: 3px bottom theme blue resize border.
    QWidget* resizeBorderLeft_ = nullptr; // m_resizeBorderLeft: 3px blue theme resize border on the left.
    QWidget* resizeBorderRight_ = nullptr; // m_resizeBorderRight: 3px theme-blue resize border on the right.
    QWidget* resizeCornerBottomLeft_ = nullptr; // m_resizeCornerBottomLeft: 6x6 theme blue triangle resize hint at the bottom-left corner.
    QWidget* resizeCornerBottomRight_ = nullptr; // m_resizeCornerBottomRight: 6x6 theme blue triangle resize hint in the bottom-right corner.

    // Dock Widgets
    ads::CDockWidget* dockWelcome_ = nullptr; // m_dockWelcome: Welcome page Dock.
    ads::CDockWidget* dockProcess_ = nullptr; // m_dockProcess: Process page Dock.
    ads::CDockWidget* dockNetwork_ = nullptr; // m_dockNetwork: Network page Dock.
    ads::CDockWidget* dockMemory_ = nullptr; // m_dockMemory: Memory page Dock.
    ads::CDockWidget* dockFile_ = nullptr; // m_dockFile: File page Dock.
    ads::CDockWidget* dockDriver_ = nullptr; // m_dockDriver: Driver page Dock.
    ads::CDockWidget* dockKernel_ = nullptr; // m_dockKernel: Kernel page Dock.
    ads::CDockWidget* dockKvm_ = nullptr; // m_dockKvm: Virtualization (KVM) page dock.
    ads::CDockWidget* dockMonitorTab_ = nullptr; // m_dockMonitorTab: Monitor page dock.
    ads::CDockWidget* dockPrivilege_ = nullptr; // m_dockPrivilege: Privileges page Dock.
    ads::CDockWidget* dockWindow_ = nullptr; // m_dockWindow: Window page Dock.
    ads::CDockWidget* dockRegistry_ = nullptr; // m_dockRegistry: Registry page Dock.
    ads::CDockWidget* dockHandle_ = nullptr;
    ads::CDockWidget* dockStartup_ = nullptr; // m_dockStartup: Startup items page dock.
    ads::CDockWidget* dockService_ = nullptr;
    ads::CDockWidget* dockMisc_ = nullptr;
    ads::CDockWidget* dockHardware_ = nullptr; // m_dockHardware: Hardware page dock.
    ads::CDockWidget* dockCurrentOp_ = nullptr; // m_dockCurrentOp: Bottom 'Current Task' helper dock.
    ads::CDockWidget* dockLog_ = nullptr; // m_dockLog: Bottom "Log Window" auxiliary dock.
    ads::CDockWidget* dockImmediate_ = nullptr; // Disabled; member retained to allow future restoration of Dock code.
    ads::CDockWidget* dockMonitor_ = nullptr; // m_dockMonitor: Bottom "Monitor Panel" auxiliary Dock.

    // Custom widgets.
    WelcomeDock* welcomeWidget_ = nullptr; // m_welcomeWidget: Welcome page content control.
    ProcessDock* processWidget_ = nullptr; // m_processWidget: Process page content control.
    NetworkDock* networkWidget_ = nullptr; // m_networkWidget: Network page content control.
    MemoryDock* memoryWidget_ = nullptr; // m_memoryWidget: Memory page content control.
    FileDock* fileWidget_ = nullptr; // m_fileWidget: File page content control.
    FileDock* shellUnlockerFileDock_ = nullptr; // m_shellUnlockerFileDock: Shell right-click file unlocker hidden host.
    DriverDock* driverWidget_ = nullptr; // m_driverWidget: Driver page content control.
    KernelDock* kernelWidget_ = nullptr; // m_kernelWidget: Kernel page content control.
    KvmDock* kvmWidget_ = nullptr; // m_kvmWidget: Virtualization (KVM) page content widget.
    MonitorDock* monitorWidget_ = nullptr; // m_monitorWidget: Monitor page content control.
    MonitorPanelWidget* monitorPanelWidget_ = nullptr; // m_monitorPanelWidget: Monitor panel performance chart content control.
    HardwareDock* hardwareWidget_ = nullptr; // m_hardwareWidget: Hardware page content control.
    PrivilegeDock* privilegeWidget_ = nullptr; // m_privilegeWidget: privilege page content control.
    StartupDock* startupWidget_ = nullptr; // m_startupWidget: Content control for the startup items page.
    ServiceDock* serviceWidget_ = nullptr;
    MiscDock* miscWidget_ = nullptr;
    WindowDock* windowWidget_ = nullptr; // m_windowWidget: Content control for the window page.
    RegistryDock* registryWidget_ = nullptr; // m_registryWidget: Registry page content control.
    HandleDock* handleWidget_ = nullptr;
    LogDockWidget* logWidget_ = nullptr; // Log panel for the non-modal 'Log Output' independent window.
    LogDockWidget* dockLogWidget_ = nullptr; // Independent log view in the ADS "Log Dock".
    ProgressDockWidget* progressWidget_ = nullptr; // Task progress panel in ADS 'Current Task'.
    CodeEditorWidget* immediateEditorWidget_ = nullptr; // Disabled; retain immediate window implementation.
    QDialog* logOutputWindow_ = nullptr;
    ks::ui::NotificationCardManager* notificationCardManager_ = nullptr;
    ks::ui::CustomTitleBar* customTitleBar_ = nullptr; // m_customTitleBar: Custom-drawn title bar component for the main window.
    ks::ui::GlobalUiSearchController* globalUiSearchController_ = nullptr; // m_globalUiSearchController: Global page search controller in the title bar.
    ks::ui::CommandExecutionPopup* commandExecutionPopup_ = nullptr; // m_commandExecutionPopup: Title bar CMD option popup.
    bool windowPinned_ = false;                        // m_windowPinned: Whether the main window is currently pinned to top.
    bool captureProtectionEnabled_ = false;            // m_captureProtectionEnabled: Whether screenshot blocking is currently enabled in the main window.

    // Main feature Dock Tab bar right-side permission button (text only):
    // - UIAccess: SYSTEM TokenUIAccess fallback and fallback for standard user instances.
    // - Admin: Administrator privilege status and elevation entry point;
    // - Debug: SeDebugPrivilege status and request entry point;
    // - System: Whether the identity is LocalSystem;
    // - R0: Driver service quick switch.
    QWidget* privilegeButtonContainer_ = nullptr;
    QToolButton* optionsMenuButton_ = nullptr;  // m_optionsMenuButton: Top-level 'Options' menu in the title bar.
    QMenu* optionsMenu_ = nullptr;              // m_optionsMenu: Settings / Plugin Management / License / Exit.
    QToolButton* githubMenuButton_ = nullptr;   // m_githubMenuButton: Top-level "GitHub" menu in the title bar.
    QMenu* githubMenu_ = nullptr;               // m_githubMenu: Project homepage, releases, and issue feedback.
    QToolButton* windowMenuButton_ = nullptr;   // m_windowMenuButton: Title bar "Window" top-level menu.
    QMenu* windowMenu_ = nullptr;               // m_windowMenu: Auxiliary Dock show/hide check menu and log output window.
    QPushButton* uiAccessStatusButton_ = nullptr; // m_uiAccessStatusButton: Entry point to trigger UIAccess fallback or downgrade to a standard instance.
    QPushButton* adminStatusButton_ = nullptr;
    QPushButton* debugStatusButton_ = nullptr;
    QPushButton* systemStatusButton_ = nullptr;
    QPushButton* r0StatusButton_ = nullptr;
    QPushButton* kvmStatusButton_ = nullptr;   // m_kvmStatusButton: KSwordVM (Layer-1) resident toggle and capability entry.
    // m_ddmaStatusButton: DDMA resident virtual sector indicator light, positioned to the right of R-1.
    // Lit up indicates that a sector on the disk is currently registered as a DMA transit station ("resident virtual sector").
    // It is merely an indicator light and a navigation entry: whether it persists is determined by the DDMA sub-page of the memory page, because
    // landing requires selecting a disk, filling in the LBA, and confirming overwrite—these three steps cannot be compressed into a single click.
    QPushButton* ddmaStatusButton_ = nullptr;
    // m_ddmaSessionGeneration: Session generation during the last button paint, used to skip redundant repaints when unchanged.
    // The accompanying m_ddmaButtonPainted cannot be omitted: generations start at 0, and members also start at 0. Comparing only against the
    // generation would cause the first frame to be treated as 'no change' and skipped, leaving the button permanently in the unstyled state.
    std::uint64_t ddmaSessionGeneration_ = 0;
    bool ddmaButtonPainted_ = false;
    bool kvmResidentActive_ = false;           // m_kvmResidentActive: Indicates if any processor was in VMX non-root mode in the most recent snapshot.
    bool kvmAvailable_ = false;                // m_kvmAvailable: Whether hardware and drivers satisfy the resident hardware gate requirements.
    // m_kvmAvailability: The complete availability value. Button styling is derived from this, not the
    // flattened boolean above. Flattening would merge NotPrepared into 'Available' and Faulted into
    // 'Unavailable', causing the button to display the opposite of the actual state in both cases.
    ksword::kvm::KvmAvailability kvmAvailability_ =
        ksword::kvm::KvmAvailability::kDriverNotRunning;
    bool kvmFaulted_ = false;                  // m_kvmFaulted: Fault exists or rollback pending; must reset before clicking.
    bool kvmQueryInFlight_ = false;            // m_kvmQueryInFlight: Merge concurrent background status queries to avoid request backlog.
    bool kvmOperationRunning_ = false;         // m_kvmOperationRunning: Disable buttons during resident toggle or self-check hold.
    unsigned long kvmGeneration_ = 0;          // m_kvmGeneration: Generation counter for compare-before request control.
    // m_kvmBackend: The virtualization backend currently selected by the driver, taking values from KSWORD_ARK_HVM_BACKEND_*.
    // The right-click menu entry is disabled when no AMD implementation exists. It shares the same null-check predicate as the group on KvmDock.
    // Each side checks independently; otherwise, the user would find the entry unclickable in one location and unresponsive in the other.
    unsigned long kvmBackend_ = 0;
    QString kvmTooltip_;                       // m_kvmTooltip: Multi-line status description for the most recently generated snapshot.
    bool r0DriverServiceRunning_ = false;      // m_r0DriverServiceRunning: Whether the KswordARK driver service is currently running.
    bool r0UnavailablePromptArmed_ = false;   // Allow the R0 missing prompt only after the main window is displayed to avoid meaningless pop-ups caused by background detection during startup.
    bool r0UnavailablePromptShowing_ = false; // Merge multiple Dock/Background R0 requests arriving at the same time.
    bool r0PermissionPromptShowing_ = false; // Merge multiple R0 IOCTL permission denied prompts occurring within a short time window.
    bool suppressR0PromptsForSession_ = false; // "Do not remind again" applies only within the current process.
    // m_r0NotificationLifetime: Allows queued R0 notifications to become invalid automatically after window destruction begins.
    std::shared_ptr<std::atomic_bool> r0NotificationLifetime_ =
        std::make_shared<std::atomic_bool>(true);
    std::atomic_bool r0DriverLogPollerRunning_{ false }; // m_r0DriverLogPollerRunning: R0 log poller thread running flag.
    std::unique_ptr<std::thread> r0DriverLogPollerThread_; // m_r0DriverLogPollerThread: R0 log polling thread object.
    QTimer* privilegeStatusTimer_ = nullptr;
    QTimer* logWindowGeometrySaveTimer_ = nullptr;

    // m_startupSystemFont purpose: Saves the system font baseline before any user appearance configuration takes effect.
    QFont startupSystemFont_;
    // m_currentAppearanceSettings: Caches the current appearance settings (theme/background/opacity).
    ks::settings::AppearanceSettings currentAppearanceSettings_;
    QString backgroundImageCacheKey_; // m_backgroundImageCacheKey: original path key corresponding to the current asynchronous verification.
    QString backgroundImageResolvedPath_; // m_backgroundImageResolvedPath: The actual path resolved by the thread pool, for diagnostics only.
    QPixmap backgroundImagePixmap_; // m_backgroundImagePixmap: Decoded background pixels held by the UI thread.
    QPixmap backgroundImageBlurredPixmap_; // m_backgroundImageBlurredPixmap: a copy blurred with the current radius; empty if the radius is 0.
    int backgroundImageBlurRadiusApplied_ = -1; // m_backgroundImageBlurRadiusApplied: blur intensity for the copy (-1 = not yet generated).
    quint64 backgroundImageBlurSourceCacheKey_ = 0; // m_backgroundImageBlurSourceCacheKey: source image cacheKey used when generating the copy.
    quint64 backgroundImageValidationGeneration_ = 0; // m_backgroundImageValidationGeneration: Generation counter to evict stale asynchronous results.
    bool backgroundImageReady_ = false; // m_backgroundImageReady: Whether the current path has been validated and successfully decoded.
    bool backgroundReadinessRefreshPending_ = false; // m_backgroundReadinessRefreshPending: Indicates if the asynchronous result requires rebuilding the visual.
    int backdropMaterialState_ = -1; // m_backdropMaterialState: cached blur type already dispatched (-1 for uninitialized, otherwise a BackdropBlurKind value).
    bool backdropRefreshQueued_ = false; // m_backdropRefreshQueued: Whether an acrylic resampling has been queued.
    QScreen* lastKnownScreen_ = nullptr; // m_lastKnownScreen: Screen at the last moveEvent; reapply composition settings only when the screen changes.
    StartupProgressCallback startupProgressCallback_; // m_startupProgressCallback: Progress callback for the main window startup phase.
    bool startupWindowVisibilityAdjusted_ = false; // m_startupWindowVisibilityAdjusted: Whether the initial display area adjustment has been completed.
    bool deferredDockInitializationStarted_ = false; // m_deferredDockInitializationStarted: Indicates if the deferred dock initialization process has started.
    bool dockLayoutRestoredFromConfig_ = false;     // m_dockLayoutRestoredFromConfig: Whether the ADS layout was restored from configuration at startup.
    bool pendingR0DynDataRefresh_ = false;          // m_pendingR0DynDataRefresh: Whether to trigger a deferred DynData refresh after KernelDock is lazily created.
    bool bugcheckDiagnosticsInstalledForSession_ = false; // m_bugcheckDiagnosticsInstalledForSession: Whether blue screen diagnostics were successfully installed during the current driver lifecycle.
    bool bugcheckDiagnosticsEntryRequestedForSession_ = false; // m_bugcheckDiagnosticsEntryRequestedForSession: Whether a request to display the diagnostic entry has been made in this user session.
    std::size_t nextDeferredDockIndex_ = 0;          // m_nextDeferredDockIndex: Index of the next deferred dock queue to load.
    std::vector<ads::CDockWidget*> deferredDockLoadQueue_; // m_deferredDockLoadQueue: Queue for deferred loading of docks after display.
};

#endif // MAINWINDOW_H

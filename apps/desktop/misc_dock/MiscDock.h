#pragma once

// ============================================================
// MiscDock.h
// Purpose:
// 1) Provide the "Miscellaneous" entry page.
// 2) Host sub-feature modules via internal tabs;
// 3) Currently includes sub-modules: Boot, Audio Source, System Speed, Virtual Location, Driver Signature, Shell Association, Disk Editing, and App Control.
// 4) The "Scanner", "Dump Analysis", and "Plugin" were originally top-level docks; to reduce the number of dock bar entries, they have been merged into this page.
// ============================================================

#include "../Framework.h"

#include <QWidget>

class QTabWidget;
class QVBoxLayout;
class BootEditorTab;
class MinidumpDock;
class ScannerDock;
namespace ks::misc
{
    class DiskEditorTab;
    class ContextMenuCleanerTab;
    class ApplicationControlPage;
    class SoundSourcePage;
    class SystemTimePage;
    class VirtualLocationPage;
    class BugcheckGuardPage;
    class DisableDsePage;
    class RenderBenchmarkPage;
    class DesktopDrawingPage;
}

class MiscDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: Create the 'Misc' root layout and internal tabs.
    // - Parameter parent: Qt parent widget.
    explicit MiscDock(QWidget* parent = nullptr);
    ~MiscDock() override = default;

    // activateMinidumpTab:
    // - Switches to the "Dump Analysis" sub-page and returns its control; this page was originally a top-level Dock and is now merged into this page.
    // - Constructs child pages on demand first to ensure the returned control is real, not a placeholder.
    // - Returns nullptr if the child page failed to construct; the caller should abort further operations.
    // The only caller is the 'auto-parse after discovering new dump' chain in mainWindow.
    MinidumpDock* activateMinidumpTab();

    // setBugcheckDiagnosticsVisible: Shows or hides the blue screen diagnostics entry based on configuration or the current installation session state.
    // Invocation: mainWindow calls this when loading configuration, modifying auto-install options, or after manual installation completes.
    // Input parameter visible: true = display and allow lazy loading of the page; false = hide and do not initialize the page; Return: void.
    void setBugcheckDiagnosticsVisible(bool visible);

private:
    // initializeUi：
    // - Purpose: initialize the control tree for the 'Misc' page, creating only placeholder controls for the tabs.
    // - Invocation: Call once in the constructor.
    void initializeUi();

    // ensureTabInitialized：
    // - Purpose: Lazily construct the real sub-page for the specified tab; return the existing one if already constructed.
    // - Input parameter tabIndex: The tab index of the main tab; out-of-bounds or negative values are ignored.
    // - Returns: Nothing.
    void ensureTabInitialized(int tabIndex);

    // initializeXxx series:
    // - Purpose: Construct the corresponding sub-pages and insert them into their respective tab placeholders.
    // - Parameters: None;
    // - Return: None. Repeated calls are safe no-ops.
    void initializeBootEditorTab();
    void initializeSoundSourcePage();
    void initializeSystemTimePage();
    void initializeVirtualLocationPage();
    void initializeBugcheckGuardPage();
    void initializeDisableDsePage();
    void initializeContextMenuCleanerTab();
    void initializeDiskEditorTab();
    void initializeApplicationControlPage();
    void initializeRenderBenchmarkPage();
    void initializeDesktopDrawingPage();
    void initializeWindowInjectionPage();
    void initializeScannerPage();
    void initializeMinidumpPage();
    void initializePluginPage();

    // activateTabByIndex：
    // - Purpose: First construct the sub-page corresponding to the target tab, then set it as the current page.
    // - Input tabIndex: Target tab index; out-of-bounds or negative values are ignored.
    // - Return: None. Reused by the three cross-module jump entry points above.
    void activateTabByIndex(int tabIndex);

private:
    QVBoxLayout* rootLayout_ = nullptr;      // m_rootLayout: Misc page root layout.
    QTabWidget* mainTabWidget_ = nullptr;    // m_mainTabWidget: Miscellaneous page internal Tab container.

    // ===================== Tab Placeholder Controls ===================== Note: Placeholder
    // controls are added to the Tab during construction to lock the tab order, titles, and icons;
    //       Real child pages are lazily instantiated (newed) and inserted into their placeholder controls only when the tab is first selected.
    QWidget* bootEditorHostWidget_ = nullptr;          // m_bootEditorHostWidget: Boot page placeholder widget.
    QWidget* soundSourceHostWidget_ = nullptr;         // m_soundSourceHostWidget: Placeholder widget for the sound source page.
    QWidget* systemTimeHostWidget_ = nullptr;          // m_systemTimeHostWidget: System speed change page placeholder widget.
    QWidget* virtualLocationHostWidget_ = nullptr;     // m_virtualLocationHostWidget: Placeholder control for the virtual location page.
    QWidget* bugcheckGuardHostWidget_ = nullptr;       // m_bugcheckGuardHostWidget: Placeholder control for the experimental page.
    QWidget* disableDseHostWidget_ = nullptr;          // m_disableDseHostWidget: Driver Signature Enforcement page placeholder control.
    QWidget* contextMenuCleanerHostWidget_ = nullptr;  // m_contextMenuCleanerHostWidget: Placeholder widget for the Shell association management page.
    QWidget* diskEditorHostWidget_ = nullptr;          // m_diskEditorHostWidget: Placeholder widget for the disk editor page.
    QWidget* applicationControlHostWidget_ = nullptr;  // m_applicationControlHostWidget: placeholder widget for the application control page.
    QWidget* renderBenchmarkHostWidget_ = nullptr;     // m_renderBenchmarkHostWidget: Render benchmark page placeholder widget.
    QWidget* desktopDrawingHostWidget_ = nullptr;      // Placeholder widget for the direct screen drawing page.
    QWidget* windowInjectionHostWidget_ = nullptr;
    QWidget* scannerHostWidget_ = nullptr;             // m_scannerHostWidget: Placeholder widget for the scanner page.
    QWidget* minidumpHostWidget_ = nullptr;            // m_minidumpHostWidget: Minidump analysis page placeholder widget.
    QWidget* pluginHostWidget_ = nullptr;              // m_pluginHostWidget: Placeholder widget for the plugin page.

    // ===================== Tab Index =====================
    int bootEditorTabIndex_ = -1;          // m_bootEditorTabIndex: Boot page tab index.
    int soundSourceTabIndex_ = -1;         // m_soundSourceTabIndex: Index of the sound source tab.
    int systemTimeTabIndex_ = -1;          // m_systemTimeTabIndex: Index of the system speed change tab.
    int virtualLocationTabIndex_ = -1;     // m_virtualLocationTabIndex: Index of the virtual location tab.
    int bugcheckGuardTabIndex_ = -1;       // m_bugcheckGuardTabIndex: Experimental page tab index.
    int disableDseTabIndex_ = -1;          // m_disableDseTabIndex: Index of the driver signature enforcement page tab.
    int contextMenuCleanerTabIndex_ = -1;  // m_contextMenuCleanerTabIndex: Shell association management page tab index.
    int diskEditorTabIndex_ = -1;          // m_diskEditorTabIndex: disk editor page tab index.
    int applicationControlTabIndex_ = -1;  // m_applicationControlTabIndex: Index of the Application Control page tab.
    int renderBenchmarkTabIndex_ = -1;     // m_renderBenchmarkTabIndex: Index of the render benchmark tab.
    int desktopDrawingTabIndex_ = -1;      // Tab index for the direct screen drawing page.
    int windowInjectionTabIndex_ = -1;
    int scannerTabIndex_ = -1;             // m_scannerTabIndex: Scanner tab index.
    int minidumpTabIndex_ = -1;            // m_minidumpTabIndex: Dump analysis page tab index.
    int pluginTabIndex_ = -1;              // m_pluginTabIndex: Plugin page tab index.

    // ===================== Sub-page components (lazy-assigned, nullptr when uninitialized) =====================
    BootEditorTab* bootEditorTab_ = nullptr; // m_bootEditorTab: Boot editor page component.
    ks::misc::DiskEditorTab* diskEditorTab_ = nullptr; // m_diskEditorTab: Disk Editor page component.
    ks::misc::ContextMenuCleanerTab* contextMenuCleanerTab_ = nullptr; // m_contextMenuCleanerTab: Right-click menu cleaner tab component.
    ks::misc::ApplicationControlPage* applicationControlPage_ = nullptr; // m_applicationControlPage: Application control page component.
    ks::misc::SoundSourcePage* soundSourcePage_ = nullptr; // m_soundSourcePage: Global output sound source detection page.
    ks::misc::SystemTimePage* systemTimePage_ = nullptr; // m_systemTimePage: System-wide global speed control page.
    ks::misc::VirtualLocationPage* virtualLocationPage_ = nullptr; // m_virtualLocationPage: System default location spoofing page.
    ks::misc::BugcheckGuardPage* bugcheckGuardPage_ = nullptr; // m_bugcheckGuardPage: Experimental page for continuous interception and blue screen buffering control.
    bool bugcheckDiagnosticsVisible_ = false; // m_bugcheckDiagnosticsVisible: Indicates whether the Blue Screen diagnostics entry point is shown based on configuration or current installation authorization.
    ks::misc::DisableDsePage* disableDsePage_ = nullptr; // m_disableDsePage: Driver Signature Enforcement (DSE) switch page.
    ks::misc::RenderBenchmarkPage* renderBenchmarkPage_ = nullptr; // m_renderBenchmarkPage: Window rendering and DWM composition benchmark page.
    ks::misc::DesktopDrawingPage* desktopDrawingPage_ = nullptr; // Desktop pattern control page without a drawing window.
    QWidget* windowInjectionPage_ = nullptr;
    ScannerDock* scannerPage_ = nullptr;   // m_scannerPage: PE/ELF/Mach-O scanning and security editing page.
    MinidumpDock* minidumpPage_ = nullptr; // m_minidumpPage: Crash dump analysis page.
    QWidget* pluginPage_ = nullptr;        // m_pluginPage: Process isolation Tab plugin host container.
};

#include "MiscDock.h"

#include "boot_editor/BootEditorTab.h"
#include "ApplicationControlPage.h"
#include "context_menu_cleaner/ContextMenuCleanerTab.h"
#include "disable_dse/DisableDsePage.h"
#include "experimental/BugcheckGuardPage.h"
#include "disk_editor/DiskEditorTab.h"
#include "render_benchmark/RenderBenchmarkPage.h"
#include "desktop_drawing/DesktopDrawingPage.h"
#include "sound_source/SoundSourcePage.h"
#include "system_time/SystemTimePage.h"
#include "virtual_location/VirtualLocationPage.h"

// The Scanner, Dump Analysis, and Plugin were originally three top-level Docks; to streamline the Dock bar entries, they have been merged into this page.
#include "../minidump_dock/MinidumpDock.h"
#include "../scanner_dock/ScannerDock.h"
#include "../PluginHost.h"
#include "../other_dock/WindowInputControl.h"

#include "../internationalization/LanguageManager.h"
#include <QIcon>
#include <QTabBar>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace
{
    // buildHostLayout：
    // - Purpose: Establish a unified container layout for placeholder tab controls with zero margins and
    //   spacing, allowing the actual child pages to fill the same area as when they were direct tab pages;
    // - Input hostWidget: The tab placeholder widget; must not be null.
    // - Returns: A vertical layout attached to the placeholder widget.
    QVBoxLayout* buildHostLayout(QWidget* hostWidget)
    {
        QVBoxLayout* hostLayout = new QVBoxLayout(hostWidget);
        hostLayout->setContentsMargins(0, 0, 0, 0);
        hostLayout->setSpacing(0);
        return hostLayout;
    }
}

MiscDock::MiscDock(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();

    KLogEvent initEvent;
    info << initEvent << "[MiscDock] 杂项页面初始化完成。" << eol;
}

void MiscDock::initializeUi()
{
    // The root layout holds the entire 'Misc' container.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(0, 0, 0, 0);
    rootLayout_->setSpacing(0);

    // The main Tab hosts all miscellaneous tools, ensuring the Dock's outer layer exposes only a single unified entry point.
    mainTabWidget_ = new QTabWidget(this);
    mainTabWidget_->setObjectName(QStringLiteral("ksMiscDockMainTab"));
    rootLayout_->addWidget(mainTabWidget_, 1);

    // Lazy loading strategy:
    // - Seven tabs are initially reserved with empty placeholder controls; their order, titles, and icons align exactly with the legacy implementation.
    // - Real sub-pages are constructed only when the tab is first selected to avoid creating heavy pages like Disk, Shell
    //   Association, and Application Control immediately upon creation of the 'Misc' tab (each triggers an initial enumeration).
    bootEditorHostWidget_ = new QWidget(mainTabWidget_);
    soundSourceHostWidget_ = new QWidget(mainTabWidget_);
    systemTimeHostWidget_ = new QWidget(mainTabWidget_);
    virtualLocationHostWidget_ = new QWidget(mainTabWidget_);
    bugcheckGuardHostWidget_ = new QWidget(mainTabWidget_);
    disableDseHostWidget_ = new QWidget(mainTabWidget_);
    contextMenuCleanerHostWidget_ = new QWidget(mainTabWidget_);
    diskEditorHostWidget_ = new QWidget(mainTabWidget_);
    applicationControlHostWidget_ = new QWidget(mainTabWidget_);
    renderBenchmarkHostWidget_ = new QWidget(mainTabWidget_);
    desktopDrawingHostWidget_ = new QWidget(mainTabWidget_);
    windowInjectionHostWidget_ = new QWidget(mainTabWidget_);
    scannerHostWidget_ = new QWidget(mainTabWidget_);
    minidumpHostWidget_ = new QWidget(mainTabWidget_);
    pluginHostWidget_ = new QWidget(mainTabWidget_);
    // The plugin host must be independently anchored by the theme style: Tab plugins use native child windows;
    // if the parent chain becomes transparent, the plugin rendering turns into black blocks or fails to refresh.
    pluginHostWidget_->setObjectName(QStringLiteral("ksMiscPluginHost"));

    bootEditorTabIndex_ = mainTabWidget_->addTab(
        bootEditorHostWidget_,
        QStringLiteral("引导"));

    // Sound source tab:
    // - R3 continuously samples Core Audio output session peaks and attributes them to the PID.
    // - R0 reuses Cross-View process and Runtime Detail cross-verification to validate candidate PIDs.
    soundSourceTabIndex_ = mainTabWidget_->addTab(
        soundSourceHostWidget_,
        QIcon(QStringLiteral(":/Icon/sound_source.svg")),
        QStringLiteral("声音来源"));

    // System global speed change page:
    // - Controls R0 performance counter continuous rate mapping via ArkDriverClient;
    // - Permanently displays instability risk and requires double confirmation before each enablement.
    systemTimeTabIndex_ = mainTabWidget_->addTab(
        systemTimeHostWidget_,
        QIcon(QStringLiteral(":/Icon/system_time.svg")),
        QStringLiteral("系统变速"));

    // Virtual location tab:
    // - Write arbitrary coordinates as the 'system default location' for Windows Location Service; when R3 is denied by ACL, fall back to R0 registry IOCTL;
    // - This affects only callers of the Windows location API; keep that scope of effect visible on the page.
    virtualLocationTabIndex_ = mainTabWidget_->addTab(
        virtualLocationHostWidget_,
        QIcon(QStringLiteral(":/Icon/virtual_location.svg")),
        QStringLiteral("虚拟定位"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        virtualLocationHostWidget_,
        QStringLiteral("misc.virtual_location.tab"),
        QStringLiteral("虚拟定位"));

    // The Blue Screen diagnostic entry is hidden by default. The mainWindow explicitly displays it only after R3 configuration triggers an automatic installation or a successful installation in the current session.
    bugcheckGuardTabIndex_ = mainTabWidget_->addTab(
        bugcheckGuardHostWidget_,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("蓝屏诊断"));
    // i18n binding is attached to the placeholder control: LanguageManager reads the property via QTabWidget::widget(index).
    // The placeholder control is the permanent tab page, while the real child pages are merely its children.
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        bugcheckGuardHostWidget_,
        QStringLiteral("misc.bugcheck_diagnostics.tab"),
        QStringLiteral("蓝屏诊断"));
    setBugcheckDiagnosticsVisible(false);

    // Driver signature enforcement page:
    // - Runtime: Disassembles to locate CI.dll!g_CiOptions and uses an R0 transactional kernel write to temporarily disable DSE;
    // Before writing, verify that the forced signature bits of the read-back value are consistent with the system-reported status. When HVCI
    //   is enabled, the operation is directly disabled; page destruction will also ensure the original value is written back as a fallback.
    disableDseTabIndex_ = mainTabWidget_->addTab(
        disableDseHostWidget_,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("禁用签名验证"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        disableDseHostWidget_,
        QStringLiteral("misc.disable_dse.tab"),
        QStringLiteral("禁用签名验证"));

    // Shell association management page:
    // - Override right-click menu, URL binding, Open With, and Explorer third-party homepage items;
    // - Deletes only the exact registry subkeys or values bound to the table upon user confirmation.
    contextMenuCleanerTabIndex_ = mainTabWidget_->addTab(
        contextMenuCleanerHostWidget_,
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("Shell 关联管理"));

    // Disk editing page:
    // - Refer to DiskGenius-like tool layout to provide a horizontal bar chart for partitions;
    // - Default is read-only; write-back to the physical disk is allowed only after explicit user unlock.
    diskEditorTabIndex_ = mainTabWidget_->addTab(
        diskEditorHostWidget_,
        QIcon(QStringLiteral(":/Icon/disk_storage.svg")),
        QStringLiteral("磁盘编辑"));

    // Application control page:
    // - The first version performs read-only diagnostics for AppLocker, WDAC, Defender, and event logs only.
    // - Does not modify, delete, or disable any policies.
    applicationControlTabIndex_ = mainTabWidget_->addTab(
        applicationControlHostWidget_,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("应用控制"));

    // Render benchmark tab:
    // - Quantify full-window tree repaints, frame drops during dragging, DWM composition, and target window responsiveness.
    // - All measurements execute on the UI thread and run only upon explicit user click.
    renderBenchmarkTabIndex_ = mainTabWidget_->addTab(
        renderBenchmarkHostWidget_,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("渲染基准"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        renderBenchmarkHostWidget_,
        QStringLiteral("misc.render_benchmark.tab"),
        QStringLiteral("渲染基准"));

    // Page lazy-loading with default non-rendering; user can run across pages after start, stopped via global hotkey.
    desktopDrawingTabIndex_ = mainTabWidget_->addTab(
        desktopDrawingHostWidget_,
        QIcon(QStringLiteral(":/Icon/codeeditor_replace.svg")),
        QStringLiteral("桌面绘制"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        desktopDrawingHostWidget_,
        QStringLiteral("misc.desktop_drawing.tab"),
        QStringLiteral("桌面绘制"));

    windowInjectionTabIndex_ = mainTabWidget_->addTab(
        windowInjectionHostWidget_, QStringLiteral("DWM / Win32k 注入"));
    ks::i18n::LanguageManager::instance().bindTab(mainTabWidget_,
        windowInjectionHostWidget_, QStringLiteral("misc.window_injection.tab"), QStringLiteral("DWM / Win32k 注入"));

    // The following three pages were originally top-level docks; they are merged into the Miscellaneous dock to streamline the dock bar entry.
    // - Tab order follows their relative sequence in the original dock bar (Scanner -> Dump Analysis -> Plugins);
    // - All three pages use lazy loading; opening 'Misc' does not instantiate the scanner, dump parser, or plugin host.
    scannerTabIndex_ = mainTabWidget_->addTab(
        scannerHostWidget_,
        QIcon(QStringLiteral(":/Icon/disk_analyze.svg")),
        QStringLiteral("扫描器"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        scannerHostWidget_,
        QStringLiteral("misc.scanner.tab"),
        QStringLiteral("扫描器"));

    minidumpTabIndex_ = mainTabWidget_->addTab(
        minidumpHostWidget_,
        QIcon(QStringLiteral(":/Icon/log_track.svg")),
        QStringLiteral("转储分析"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        minidumpHostWidget_,
        QStringLiteral("misc.minidump.tab"),
        QStringLiteral("转储分析"));

    pluginTabIndex_ = mainTabWidget_->addTab(
        pluginHostWidget_,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("插件"));
    ks::i18n::LanguageManager::instance().bindTab(
        mainTabWidget_,
        pluginHostWidget_,
        QStringLiteral("misc.plugin.tab"),
        QStringLiteral("插件"));

    // Tab switch: initialize corresponding sub-page on demand.
    connect(
        mainTabWidget_,
        &QTabWidget::currentChanged,
        this,
        [this](const int tabIndex)
        {
            ensureTabInitialized(tabIndex);
        });

    // Initial screen tab must be initialized synchronously:
    // - ADS may directly restore 'Misc' as the current Dock, in which case currentChanged will not be triggered again;
    // - Only initialize the current page; other pages remain lazy-loaded.
    ensureTabInitialized(mainTabWidget_->currentIndex());

    // Add another 0ms fallback to cover cases where currentIndex changes later due to theme/ADS delayed restoration.
    QTimer::singleShot(0, this, [this]()
        {
            ensureTabInitialized(mainTabWidget_ != nullptr ? mainTabWidget_->currentIndex() : -1);
        });
}

void MiscDock::ensureTabInitialized(const int tabIndex)
{
    if (tabIndex < 0)
    {
        return;
    }

    if (tabIndex == bootEditorTabIndex_)
    {
        initializeBootEditorTab();
        return;
    }
    if (tabIndex == soundSourceTabIndex_)
    {
        initializeSoundSourcePage();
        return;
    }
    if (tabIndex == systemTimeTabIndex_)
    {
        initializeSystemTimePage();
        return;
    }
    if (tabIndex == virtualLocationTabIndex_)
    {
        initializeVirtualLocationPage();
        return;
    }
    if (tabIndex == bugcheckGuardTabIndex_)
    {
        if (bugcheckDiagnosticsVisible_)
        {
            initializeBugcheckGuardPage();
        }
        return;
    }
    if (tabIndex == disableDseTabIndex_)
    {
        initializeDisableDsePage();
        return;
    }
    if (tabIndex == contextMenuCleanerTabIndex_)
    {
        initializeContextMenuCleanerTab();
        return;
    }
    if (tabIndex == diskEditorTabIndex_)
    {
        initializeDiskEditorTab();
        return;
    }
    if (tabIndex == applicationControlTabIndex_)
    {
        initializeApplicationControlPage();
        return;
    }
    if (tabIndex == renderBenchmarkTabIndex_)
    {
        initializeRenderBenchmarkPage();
        return;
    }
    if (tabIndex == desktopDrawingTabIndex_)
    {
        initializeDesktopDrawingPage();
        return;
    }
    if (tabIndex == windowInjectionTabIndex_)
    {
        initializeWindowInjectionPage();
        return;
    }
    if (tabIndex == scannerTabIndex_)
    {
        initializeScannerPage();
        return;
    }
    if (tabIndex == minidumpTabIndex_)
    {
        initializeMinidumpPage();
        return;
    }
    if (tabIndex == pluginTabIndex_)
    {
        initializePluginPage();
        return;
    }
}

void MiscDock::activateTabByIndex(const int tabIndex)
{
    if (mainTabWidget_ == nullptr || tabIndex < 0 || tabIndex >= mainTabWidget_->count())
    {
        return;
    }

    // Construct first, then switch: currentChanged does not trigger when the target is already the current page;
    // directly calling setCurrentIndex may cause the caller to receive uninitialized placeholder controls.
    ensureTabInitialized(tabIndex);
    mainTabWidget_->setCurrentIndex(tabIndex);
}

MinidumpDock* MiscDock::activateMinidumpTab()
{
    activateTabByIndex(minidumpTabIndex_);
    return minidumpPage_;
}

void MiscDock::setBugcheckDiagnosticsVisible(const bool visible)
{
    bugcheckDiagnosticsVisible_ = visible;
    if (mainTabWidget_ == nullptr || bugcheckGuardTabIndex_ < 0)
    {
        return;
    }

    // Hide tabs without removing placeholder controls to maintain stable indices, allowing reused page states after re-display.
    QTabBar* const kTabBar = mainTabWidget_->tabBar();
    if (kTabBar != nullptr)
    {
        kTabBar->setTabVisible(bugcheckGuardTabIndex_, visible);
    }
    if (!visible && mainTabWidget_->currentIndex() == bugcheckGuardTabIndex_)
    {
        mainTabWidget_->setCurrentIndex(bootEditorTabIndex_);
    }
    if (visible && mainTabWidget_->currentIndex() == bugcheckGuardTabIndex_)
    {
        ensureTabInitialized(bugcheckGuardTabIndex_);
    }
}

void MiscDock::initializeBootEditorTab()
{
    if (bootEditorHostWidget_ == nullptr || bootEditorTab_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(bootEditorHostWidget_);
    bootEditorTab_ = new BootEditorTab(bootEditorHostWidget_);
    kHostLayout->addWidget(bootEditorTab_, 1);
}

void MiscDock::initializeSoundSourcePage()
{
    if (soundSourceHostWidget_ == nullptr || soundSourcePage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(soundSourceHostWidget_);
    soundSourcePage_ = new ks::misc::SoundSourcePage(0U, 0U, soundSourceHostWidget_);
    kHostLayout->addWidget(soundSourcePage_, 1);
}

void MiscDock::initializeSystemTimePage()
{
    if (systemTimeHostWidget_ == nullptr || systemTimePage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(systemTimeHostWidget_);
    systemTimePage_ = new ks::misc::SystemTimePage(systemTimeHostWidget_);
    kHostLayout->addWidget(systemTimePage_, 1);
}

void MiscDock::initializeVirtualLocationPage()
{
    if (virtualLocationHostWidget_ == nullptr || virtualLocationPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(virtualLocationHostWidget_);
    virtualLocationPage_ = new ks::misc::VirtualLocationPage(virtualLocationHostWidget_);
    kHostLayout->addWidget(virtualLocationPage_, 1);
}

void MiscDock::initializeBugcheckGuardPage()
{
    if (bugcheckGuardHostWidget_ == nullptr || bugcheckGuardPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(bugcheckGuardHostWidget_);
    bugcheckGuardPage_ = new ks::misc::BugcheckGuardPage(bugcheckGuardHostWidget_);
    kHostLayout->addWidget(bugcheckGuardPage_, 1);
}

void MiscDock::initializeDisableDsePage()
{
    if (disableDseHostWidget_ == nullptr || disableDsePage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(disableDseHostWidget_);
    disableDsePage_ = new ks::misc::DisableDsePage(disableDseHostWidget_);
    kHostLayout->addWidget(disableDsePage_, 1);
}

void MiscDock::initializeContextMenuCleanerTab()
{
    if (contextMenuCleanerHostWidget_ == nullptr || contextMenuCleanerTab_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(contextMenuCleanerHostWidget_);
    contextMenuCleanerTab_ = new ks::misc::ContextMenuCleanerTab(contextMenuCleanerHostWidget_);
    kHostLayout->addWidget(contextMenuCleanerTab_, 1);
}

void MiscDock::initializeDiskEditorTab()
{
    if (diskEditorHostWidget_ == nullptr || diskEditorTab_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(diskEditorHostWidget_);
    diskEditorTab_ = new ks::misc::DiskEditorTab(diskEditorHostWidget_);
    kHostLayout->addWidget(diskEditorTab_, 1);
}

void MiscDock::initializeApplicationControlPage()
{
    if (applicationControlHostWidget_ == nullptr || applicationControlPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(applicationControlHostWidget_);
    applicationControlPage_ = new ks::misc::ApplicationControlPage(applicationControlHostWidget_);
    kHostLayout->addWidget(applicationControlPage_, 1);
}

void MiscDock::initializeRenderBenchmarkPage()
{
    if (renderBenchmarkHostWidget_ == nullptr || renderBenchmarkPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(renderBenchmarkHostWidget_);
    renderBenchmarkPage_ = new ks::misc::RenderBenchmarkPage(renderBenchmarkHostWidget_);
    kHostLayout->addWidget(renderBenchmarkPage_, 1);
}

void MiscDock::initializeDesktopDrawingPage()
{
    if (desktopDrawingHostWidget_ == nullptr || desktopDrawingPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(desktopDrawingHostWidget_);
    desktopDrawingPage_ = new ks::misc::DesktopDrawingPage(desktopDrawingHostWidget_);
    kHostLayout->addWidget(desktopDrawingPage_, 1);
}

void MiscDock::initializeScannerPage()
{
    if (scannerHostWidget_ == nullptr || scannerPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(scannerHostWidget_);
    scannerPage_ = new ScannerDock(scannerHostWidget_);
    kHostLayout->addWidget(scannerPage_, 1);
}

void MiscDock::initializeWindowInjectionPage()
{
    if (!windowInjectionHostWidget_ || windowInjectionPage_) return;
    auto* layout = buildHostLayout(windowInjectionHostWidget_);
    windowInjectionPage_ = ks::window_input::createInjectionPage(windowInjectionHostWidget_);
    layout->addWidget(windowInjectionPage_);
}

void MiscDock::initializeMinidumpPage()
{
    if (minidumpHostWidget_ == nullptr || minidumpPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(minidumpHostWidget_);
    minidumpPage_ = new MinidumpDock(minidumpHostWidget_);
    kHostLayout->addWidget(minidumpPage_, 1);
}

void MiscDock::initializePluginPage()
{
    if (pluginHostWidget_ == nullptr || pluginPage_ != nullptr)
    {
        return;
    }

    QVBoxLayout* const kHostLayout = buildHostLayout(pluginHostWidget_);
    pluginPage_ = ks::plugin_host::createTabPluginContainer(pluginHostWidget_);
    kHostLayout->addWidget(pluginPage_, 1);
}

#include "MainWindow.h"
#include "welcome_dock/WelcomeDock.h"
#include "process_dock/ProcessDock.h"
#include "network_dock/NetworkDock.h"
#include "memory_dock/MemoryDock.h"
#include "file_dock/FileDock.h"
#include "driver_dock/DriverDock.h"
#include "kernel_dock/KernelDock.h"
#include "kvm_dock/KvmDock.h"
#include "monitor_dock/MonitorDock.h"
#include "monitor_dock/MonitorPanelWidget.h"
#include "hardware_dock/HardwareDock.h"
#include "privilege_dock/PrivilegeDock.h"
#include "startup_dock/StartupDock.h"
#include "service_dock/ServiceDock.h"
#include "window_dock/WindowDock.h"
#include "registry_dock/RegistryDock.h"
#include "misc_dock/MiscDock.h"
#include "handle_dock/HandleDock.h"
#include <QAbstractScrollArea>
#include <QTimer>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QList>
#include <QPointer>
#include <QProgressBar>
#include <QSizePolicy>
#include <QScrollArea>
#include <QDialog>
#include <QIODevice>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "framework/LogDockWidget.h"
#include "framework/NotificationCardManager.h"
#include "framework/ProgressDockWidget.h"
#include "include/ads/DockWidgetTab.h"
#include "include/ads/FloatingDockContainer.h"
#include "internationalization/LanguageManager.h"
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

#include "MainWindow.DockTabsSupport.h"
#include "MainWindow.DockingSupport.h"

using namespace ksword::ui::main_window;

QWidget* MainWindow::createDockPlaceholderWidget(const QString& titleText) const
{
    QWidget* placeholderWidget = new QWidget();
    placeholderWidget->setObjectName(QStringLiteral("ksLazyDockPlaceholder_%1").arg(titleText));
    placeholderWidget->setAutoFillBackground(false);
    placeholderWidget->setAttribute(Qt::WA_StyledBackground, false);
    // The progress bar's slot and block must be explicitly declared here:
    // - The above QWidget{background:transparent !important} also targets QProgressBar. Without !important, the
    //   global baseline style for progress bars would be overridden, causing the groove to become fully transparent.
    // - Therefore, explicitly re-specify the slot color and block color with equally strong !important here, independent of stacking order.
    placeholderWidget->setStyleSheet(
        QStringLiteral(
            "QWidget{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "QLabel{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "QProgressBar{"
            "  background-color:%1 !important;"
            "  border:none !important;"
            "  border-radius:3px;"
            "}"
            "QProgressBar::chunk{"
            "  background-color:%2 !important;"
            "  border-radius:3px;"
            "}")
        .arg(ksword_theme::surfaceMutedColorHex(), ksword_theme::controlAccentHex()));

    auto* placeholderLayout = new QVBoxLayout(placeholderWidget);
    placeholderLayout->setContentsMargins(24, 24, 24, 24);
    placeholderLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("%1 页面正在初始化...").arg(titleText), placeholderWidget);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;"));
    titleLabel->setAlignment(Qt::AlignCenter);
    placeholderLayout->addStretch(1);
    placeholderLayout->addWidget(titleLabel);

    // Stage labels and progress bar: initialize stages and sync refresh via updateLazyDockPlaceholderProgress.
    // initialize to empty/zero on first creation; the page has not started loading, so no progress should be displayed.
    QLabel* stageLabel = new QLabel(placeholderWidget);
    stageLabel->setObjectName(QString::fromLatin1(kLazyDockPlaceholderStageLabelObjectName));
    stageLabel->setAlignment(Qt::AlignCenter);
    stageLabel->setStyleSheet(QStringLiteral("font-size:12px;color:%1;").arg(ksword_theme::textSecondaryHex()));
    placeholderLayout->addSpacing(12);
    placeholderLayout->addWidget(stageLabel);

    // The progress bar is horizontally centered and does not span the entire page: a progress bar that stretches across the whole row looks poor on wide docks.
    auto* progressRowLayout = new QHBoxLayout();
    progressRowLayout->setContentsMargins(0, 0, 0, 0);
    QProgressBar* loadProgressBar = new QProgressBar(placeholderWidget);
    loadProgressBar->setObjectName(QString::fromLatin1(kLazyDockPlaceholderProgressBarObjectName));
    loadProgressBar->setRange(0, 100);
    loadProgressBar->setValue(0);
    loadProgressBar->setTextVisible(false);
    loadProgressBar->setFixedHeight(6);
    loadProgressBar->setFixedWidth(260);
    progressRowLayout->addStretch(1);
    progressRowLayout->addWidget(loadProgressBar);
    progressRowLayout->addStretch(1);
    placeholderLayout->addLayout(progressRowLayout);

    placeholderLayout->addStretch(1);
    return placeholderWidget;
}

void MainWindow::ensureDockContentInitialized(ads::CDockWidget* dockWidget)
{
    if (dockWidget == nullptr)
    {
        return;
    }
    if (dockWidget->property("ks_lazy_initialized").toBool())
    {
        return;
    }
    if (dockWidget->property("ks_lazy_initializing").toBool())
    {
        KLogEvent lazyDockReentryEvent;
        dbg << lazyDockReentryEvent
            << "[MainWindow][LazyDock] 跳过重入初始化, dock="
            << dockWidget->property("ks_lazy_key").toString().toStdString()
            << eol;
        return;
    }

    const QString kDockKey = dockWidget->property("ks_lazy_key").toString().trimmed().toLower();
    const QString kDockTitleText = dockWidget->windowTitle().trimmed().isEmpty()
        ? kDockKey
        : dockWidget->windowTitle().trimmed();
    dockWidget->setProperty("ks_lazy_initializing", true);
    const int kProgressPid = kPro.add(this, "页面", QStringLiteral("打开%1页").arg(kDockTitleText).toStdString());
    kPro.set(kProgressPid, QStringLiteral("准备加载%1页").arg(kDockTitleText).toStdString(), 0, 8.0f);

    // The page's constructor monopolizes the UI thread for tens to hundreds of milliseconds, during which no
    // repaint occurs; therefore, the progress must be drawn synchronously before entering the constructor so
    // that users see 'loading in progress' rather than a residual image of the previous page while waiting.
    updateLazyDockPlaceholderProgress(
        dockWidget,
        QStringLiteral("准备加载%1页").arg(kDockTitleText),
        8);

    const bool kIsNetworkDock = (kDockKey == QStringLiteral("network"));
    const bool kIsKernelDock = (kDockKey == QStringLiteral("kernel"));
    QWidget* realWidget = nullptr;

    // This frame is the one the user is actually watching: The subsequent page construction will block the UI thread.
    // The progress bar remains stationary here to reflect reality, avoiding fake animations to mask the delay.
    updateLazyDockPlaceholderProgress(
        dockWidget,
        QStringLiteral("正在创建%1页内容").arg(kDockTitleText),
        30);

    if (kDockKey == QStringLiteral("process"))
    {
        if (processWidget_ == nullptr)
        {
            processWidget_ = new ProcessDock(this);
            connect(
                processWidget_,
                &ProcessDock::requestFocusProcessProtectByCallback,
                this,
                &MainWindow::focusProcessProtectByCallback);
        }
        realWidget = processWidget_;
    }
    else if (kDockKey == QStringLiteral("network"))
    {
        if (networkWidget_ == nullptr) { networkWidget_ = new NetworkDock(this); }
        realWidget = networkWidget_;
    }
    else if (kDockKey == QStringLiteral("memory"))
    {
        if (memoryWidget_ == nullptr) { memoryWidget_ = new MemoryDock(this); }
        realWidget = memoryWidget_;
    }
    else if (kDockKey == QStringLiteral("file"))
    {
        if (fileWidget_ == nullptr) { fileWidget_ = new FileDock(this); }
        realWidget = fileWidget_;
    }
    else if (kDockKey == QStringLiteral("driver"))
    {
        if (driverWidget_ == nullptr)
        {
            driverWidget_ = new DriverDock(this);
            if (kernelWidget_ != nullptr)
            {
                driverWidget_->attachKswordSelfDriverPage(
                    kernelWidget_->kswordSelfDriverPage(),
                    kernelWidget_);
            }
        }
        realWidget = driverWidget_;
    }
    else if (kDockKey == QStringLiteral("kernel"))
    {
        if (kernelWidget_ == nullptr)
        {
            kernelWidget_ = new KernelDock(this);
            if (driverWidget_ != nullptr)
            {
                driverWidget_->attachKswordSelfDriverPage(
                    kernelWidget_->kswordSelfDriverPage(),
                    kernelWidget_);
            }
        }
        realWidget = kernelWidget_;
    }
    else if (kDockKey == QStringLiteral("kvm"))
    {
        if (kvmWidget_ == nullptr) { kvmWidget_ = createKvmDockContent(); }
        realWidget = kvmWidget_;
    }
    else if (kDockKey == QStringLiteral("monitor"))
    {
        if (monitorWidget_ == nullptr) { monitorWidget_ = new MonitorDock(this); }
        realWidget = monitorWidget_;
    }
    else if (kDockKey == QStringLiteral("hardware"))
    {
        if (hardwareWidget_ == nullptr) { hardwareWidget_ = new HardwareDock(this); }
        realWidget = hardwareWidget_;
    }
    else if (kDockKey == QStringLiteral("privilege"))
    {
        if (privilegeWidget_ == nullptr) { privilegeWidget_ = new PrivilegeDock(this); }
        realWidget = privilegeWidget_;
    }
    else if (kDockKey == QStringLiteral("window"))
    {
        if (windowWidget_ == nullptr) { windowWidget_ = new WindowDock(this); }
        realWidget = windowWidget_;
    }
    else if (kDockKey == QStringLiteral("registry"))
    {
        if (registryWidget_ == nullptr) { registryWidget_ = new RegistryDock(this); }
        realWidget = registryWidget_;
    }
    else if (kDockKey == QStringLiteral("handle"))
    {
        if (handleWidget_ == nullptr) { handleWidget_ = new HandleDock(this); }
        realWidget = handleWidget_;
    }
    else if (kDockKey == QStringLiteral("startup"))
    {
        if (startupWidget_ == nullptr) { startupWidget_ = new StartupDock(this); }
        realWidget = startupWidget_;
    }
    else if (kDockKey == QStringLiteral("service"))
    {
        if (serviceWidget_ == nullptr) { serviceWidget_ = new ServiceDock(this); }
        realWidget = serviceWidget_;
    }
    else if (kDockKey == QStringLiteral("misc"))
    {
        // The scanner, dump analysis, and plugins have been merged into the Misc page and no longer occupy separate top-level
        // docks. They are lazily loaded as tabs within the Misc page; here, only the Misc container itself needs to be constructed.
        if (miscWidget_ == nullptr) { miscWidget_ = new MiscDock(this); }
        miscWidget_->setBugcheckDiagnosticsVisible(
            currentAppearanceSettings_.bugcheckDiagnosticsAutoInstallEnabled ||
            bugcheckDiagnosticsInstalledForSession_ ||
            bugcheckDiagnosticsEntryRequestedForSession_);
        realWidget = miscWidget_;
    }
    if (realWidget == nullptr)
    {
        kPro.set(kProgressPid, QStringLiteral("%1页无需加载").arg(kDockTitleText).toStdString(), 0, 100.0f);
        // This Dock has no real content to load, so the placeholder will remain on the UI indefinitely:
        // The progress bar must be reset to zero and the stage text cleared; otherwise, it will permanently stick at 30%, appearing frozen.
        updateLazyDockPlaceholderProgress(dockWidget, QString(), 0);
        dockWidget->setProperty("ks_lazy_initializing", false);
        return;
    }

    kPro.set(kProgressPid, QStringLiteral("正在创建%1页内容").arg(kDockTitleText).toStdString(), 0, 45.0f);

    // KernelDock mount strategy:
    // - When no background image is present, keep the root widget self-drawn to prevent the black parent container from showing after ADS restores the layout.
    // - When a background image is present, allow the root widget to be transparent to reveal the background image, while global QSS ensures readability for tables, trees, and lists.
    realWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    if (kIsKernelDock)
    {
        const bool kAllowWallpaperThroughKernelDock = shouldRenderTransparentDockContent();
        realWidget->setAutoFillBackground(!kAllowWallpaperThroughKernelDock);
        realWidget->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThroughKernelDock);
    }
    else
    {
        realWidget->setAutoFillBackground(false);
        realWidget->setAttribute(Qt::WA_StyledBackground, false);
        realWidget->setStyleSheet(
            realWidget->styleSheet()
            + QStringLiteral(
                "QWidget{"
                "  background:transparent;"
                "  background-color:transparent;"
                "}"));
    }

    // Similar to KVM and kernel pages: the internal layout is splitter + table + details;
    // wrapping it in an outer QScrollArea collapses the splitter to minimum height.
    const bool kShouldSuppressOuterScrollArea =
        kIsNetworkDock || (kDockKey == QStringLiteral("hardware")) || kIsKernelDock ||
        (kDockKey == QStringLiteral("kvm"));
    if (kIsNetworkDock)
    {
        // Network page additional requirements:
        // 1) Stop ADS from automatically wrapping an external QScrollArea;
        // 2) Raise the minimum height of the entire network Dock to 300 to facilitate verification of whether the issue lies within the outermost Dock container.
        realWidget->setMinimumHeight(300);
        dockWidget->setMinimumSizeHintMode(ads::CDockWidget::MinimumSizeHintFromDockWidgetMinimumSize);
        dockWidget->setMinimumHeight(300);
        dockWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }

    kPro.set(kProgressPid, QStringLiteral("正在挂载%1页").arg(kDockTitleText).toStdString(), 0, 72.0f);
    // Final refresh of the placeholder: after mounting real content, it is detached via takeWidget and scheduled
    // for deletion with deleteLater, so the 100% frame is meaningless and no further updates are performed.
    updateLazyDockPlaceholderProgress(
        dockWidget,
        QStringLiteral("正在挂载%1页").arg(kDockTitleText),
        80);
    QWidget* oldWidget = dockWidget->takeWidget();
    dockWidget->setWidget(
        realWidget,
        kShouldSuppressOuterScrollArea ? ads::CDockWidget::ForceNoScrollArea : ads::CDockWidget::AutoScrollArea);
    dockWidget->setProperty("ks_lazy_initialized", true);
    dockWidget->setProperty("ks_lazy_initializing", false);
    configureAdsDockTabVisualIdentity(dockWidget);
    if (oldWidget != nullptr)
    {
        oldWidget->deleteLater();
    }

    if (realWidget == processWidget_)
    {
        processWidget_->refreshThemeVisuals();
    }

    // After real content is mounted, continue inheriting the Dock control tree's palette:
    // - After the main window background is drawn by the root container's paintEvent, the mainWindow's Window/Base brush contains only the theme's solid color;
    // - If the palette is explicitly copied to the new content here, child controls like QAbstractScrollArea will render solid black/white backgrounds upon first mount;
    // - When switching the Dock again, the style is re-applied, so the old behavior was: black background after initial initialization, then restoring transparency when switching away and back.
    // During deferred partial loading, perform only local refresh without global appearance recalculation.
    realWidget->update();
    dockWidget->update();
    kPro.set(kProgressPid, QStringLiteral("%1页加载完成").arg(kDockTitleText).toStdString(), 0, 100.0f);

    if (realWidget == kernelWidget_ && pendingR0DynDataRefresh_)
    {
        pendingR0DynDataRefresh_ = false;
        QPointer<KernelDock> kernelDockGuard(kernelWidget_);
        QTimer::singleShot(0, this, [kernelDockGuard]()
            {
                if (kernelDockGuard != nullptr)
                {
                    kernelDockGuard->requestDynDataRefresh();
                }
            });
    }
}

void MainWindow::configureDockWidgetPersistentIdentity(
    ads::CDockWidget* dockWidget,
    const QString& dockKey) const
{
    if (dockWidget == nullptr)
    {
        return;
    }

    // normalizedKey purpose: Generate a stable, language-agnostic ADS objectName.
    const QString kNormalizedKey = dockKey.trimmed().toLower();
    if (kNormalizedKey.isEmpty())
    {
        return;
    }

    dockWidget->setObjectName(QStringLiteral("ksDock_%1").arg(kNormalizedKey));
    dockWidget->setProperty("ks_dock_layout_key", kNormalizedKey);
}

QString MainWindow::resolveDockLayoutConfigPath() const
{
    // applicationDirectoryPath usage: Fixedly points to the directory containing the current executable, without falling back to the source directory.
    const QString kApplicationDirectoryPath = QDir::cleanPath(QCoreApplication::applicationDirPath());
    const QDir kRootDirectory(kApplicationDirectoryPath);
    return QDir::cleanPath(
        kRootDirectory.absoluteFilePath(
            QStringLiteral("config/%1").arg(QString::fromLatin1(kDockLayoutConfigFileName))));
}

bool MainWindow::restoreDockLayoutFromConfig()
{
    if (pDockManager_ == nullptr)
    {
        return false;
    }

    const QString kLayoutConfigPath = resolveDockLayoutConfigPath();
    QFile layoutFile(kLayoutConfigPath);
    if (!layoutFile.exists())
    {
        KLogEvent layoutEvent;
        info << layoutEvent
            << "[MainWindow][ADS] 未发现布局配置，使用默认 Dock 布局。 path="
            << kLayoutConfigPath.toStdString()
            << eol;
        return false;
    }

    if (!layoutFile.open(QIODevice::ReadOnly))
    {
        KLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 打开布局配置失败，使用默认 Dock 布局。 path="
            << kLayoutConfigPath.toStdString()
            << eol;
        return false;
    }

    const QByteArray kSavedStateBytes = layoutFile.readAll();
    layoutFile.close();
    if (kSavedStateBytes.isEmpty())
    {
        KLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 布局配置为空，使用默认 Dock 布局。 path="
            << kLayoutConfigPath.toStdString()
            << eol;
        return false;
    }

    QElapsedTimer restoreTimer;
    restoreTimer.start();
    const bool kRestoreOk = pDockManager_->restoreState(
        kSavedStateBytes,
        kDockLayoutConfigFileVersion);
    const qint64 kRestoreElapsedMs = restoreTimer.elapsed();
    dockLayoutRestoredFromConfig_ = kRestoreOk;

    KLogEvent layoutEvent;
    (kRestoreOk ? info : warn) << layoutEvent
        << "[MainWindow][ADS] 布局配置恢复"
        << (kRestoreOk ? "成功" : "失败")
        << "。 path="
        << kLayoutConfigPath.toStdString()
        << ", bytes="
        << kSavedStateBytes.size()
        << ", elapsedMs="
        << kRestoreElapsedMs
        << eol;
    if (kRestoreOk)
    {
        // ADS does not re-trigger user click events when restoring the currently active Dock:
        // If restoring to a lazy placeholder page (typically the 'Kernel' Dock where the user was last), schedule loading for the
        // first iteration of the event loop to avoid synchronously creating heavy pages during the 'organize dock layout' phase.
        QTimer::singleShot(0, this, [this]()
            {
                ensureVisibleLazyDocksInitialized(QStringLiteral("restoreDockLayout-deferred-0"));
                repairKernelDockAfterLayoutRestore(QStringLiteral("restoreDockLayout-deferred-0"));
            });
        QTimer::singleShot(250, this, [this]()
            {
                repairKernelDockAfterLayoutRestore(QStringLiteral("restoreDockLayout-deferred-250"));
            });
    }
    return kRestoreOk;
}

bool MainWindow::saveDockLayoutToConfig() const
{
    if (pDockManager_ == nullptr)
    {
        return false;
    }
    // The user just clicked "Reset Docking Layout": This exit **must not** write the current layout back.
    //
    // Without this gate, deleted files would instantly reappear upon application closure, while the user sees "the click did
    // nothing"—this is precisely the failure mode this project forbids: an action reports success, but the effect is absent.
    if (suppressDockLayoutSave_)
    {
        return true;
    }

    const QString kLayoutConfigPath = resolveDockLayoutConfigPath();
    const QFileInfo kLayoutFileInfo(kLayoutConfigPath);
    QDir layoutDirectory(kLayoutFileInfo.absolutePath());
    if (!layoutDirectory.exists() && !layoutDirectory.mkpath(QStringLiteral(".")))
    {
        KLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 创建布局配置目录失败。 dir="
            << layoutDirectory.absolutePath().toStdString()
            << eol;
        return false;
    }

    const QByteArray kStateBytes = pDockManager_->saveState(kDockLayoutConfigFileVersion);
    if (kStateBytes.isEmpty())
    {
        KLogEvent layoutEvent;
        warn << layoutEvent << "[MainWindow][ADS] 当前布局状态为空，跳过保存。" << eol;
        return false;
    }

    QFile layoutFile(kLayoutConfigPath);
    if (!layoutFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        KLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 打开布局配置写入失败。 path="
            << kLayoutConfigPath.toStdString()
            << eol;
        return false;
    }

    const qint64 kWrittenBytes = layoutFile.write(kStateBytes);
    layoutFile.close();
    const bool kSaveOk = (kWrittenBytes == kStateBytes.size());
    KLogEvent layoutEvent;
    (kSaveOk ? info : warn) << layoutEvent
        << "[MainWindow][ADS] 布局配置保存"
        << (kSaveOk ? "成功" : "失败")
        << "。 path="
        << kLayoutConfigPath.toStdString()
        << ", bytes="
        << kWrittenBytes
        << eol;
    return kSaveOk;
}

void MainWindow::initializeNextDeferredDock()
{
    while (nextDeferredDockIndex_ < deferredDockLoadQueue_.size())
    {
        ads::CDockWidget* dockWidget = deferredDockLoadQueue_[nextDeferredDockIndex_++];
        if (dockWidget == nullptr || dockWidget->property("ks_lazy_initialized").toBool())
        {
            continue;
        }

        ensureDockContentInitialized(dockWidget);
        QTimer::singleShot(kDeferredDockLoadIntervalMs, this, [this]()
            {
                initializeNextDeferredDock();
            });
        return;
    }

    reportStartupProgress(
        98,
        QStringLiteral("main.startup.progress.remaining_pages_complete"),
        QStringLiteral("启动完成。"));
}

void MainWindow::ensureVisibleLazyDocksInitialized(const QString& reasonText)
{
    if (pDockManager_ == nullptr)
    {
        return;
    }

    const QList<ads::CDockWidget*> kCandidateDockList{
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
        dockMisc_
    };

    ads::CDockWidget* focusedDockWidget = pDockManager_->focusedDockWidget();
    for (ads::CDockWidget* dockWidget : kCandidateDockList)
    {
        if (dockWidget == nullptr || dockWidget->property("ks_lazy_initialized").toBool())
        {
            continue;
        }

        // Dock widgets without ks_lazy_key (e.g., the pre-built welcome page) have no lazy content by default.
        // Adding them to the load-backflow process would only waste time running the progress bar entry once.
        if (!dockWidget->property("ks_lazy_key").isValid())
        {
            continue;
        }

        if (!isDockWidgetActiveForLazyInitialization(dockWidget, focusedDockWidget))
        {
            continue;
        }

        KLogEvent lazyDockEvent;
        info << lazyDockEvent
            << "[MainWindow][LazyDock] 可见惰性 Dock 触发即时加载, reason="
            << reasonText.toStdString()
            << ", dock="
            << dockWidget->property("ks_lazy_key").toString().toStdString()
            << ", current="
            << (dockWidget->isCurrentTab() ? "true" : "false")
            << ", visible="
            << (dockWidget->isVisible() ? "true" : "false")
            << eol;
        ensureDockContentInitialized(dockWidget);

        if (!dockWidget->property("ks_lazy_initialized").toBool())
        {
            // Nothing was created in this round (e.g., dockKey has no implementation), so it does not consume
            // this round's quota. Retrying here must be avoided, or it will cause infinite self-scheduling.
            continue;
        }

        // Shard re-load: only one heavy page may be constructed per event loop.
        // If multiple visible lazy docks (split-screen or multiple tabs visible simultaneously) are constructed consecutively in the same
        // call, the construction cost of tens to hundreds of milliseconds per page will accumulate into a single long blocking operation.
        // Deferring the remaining docks to the next event loop ensures that at least two pages can still repaint and respond to input.
        // guardedSelf usage: Deferred scheduling may outlive the main window; verify lifecycle before callback.
        const QPointer<MainWindow> kGuardedSelf(this);
        QTimer::singleShot(0, this, [kGuardedSelf, reasonText]()
            {
                if (kGuardedSelf == nullptr)
                {
                    return;
                }
                kGuardedSelf->ensureVisibleLazyDocksInitialized(reasonText);
            });
        return;
    }
}

void MainWindow::repairKernelDockAfterLayoutRestore(const QString& reasonText)
{
    if (dockKernel_ == nullptr)
    {
        return;
    }

    ads::CDockWidget* focusedDockWidget = (pDockManager_ != nullptr)
        ? pDockManager_->focusedDockWidget()
        : nullptr;
    if (!isDockWidgetActiveForLazyInitialization(dockKernel_, focusedDockWidget))
    {
        KLogEvent repairSkipEvent;
        info << repairSkipEvent
            << "[MainWindow][KernelDockRepair] skip inactive kernel dock, reason="
            << reasonText.toStdString()
            << ", initialized="
            << (dockKernel_->property("ks_lazy_initialized").toBool() ? "true" : "false")
            << ", current="
            << (dockKernel_->isCurrentTab() ? "true" : "false")
            << ", visible="
            << (dockKernel_->isVisible() ? "true" : "false")
            << eol;
        return;
    }

    if (kernelWidget_ == nullptr)
    {
        ensureDockContentInitialized(dockKernel_);
        if (kernelWidget_ == nullptr)
        {
            return;
        }
    }

    QWidget* mountedWidget = dockKernel_->widget();
    const bool kNeedsRemount = (mountedWidget != kernelWidget_);
    if (kNeedsRemount)
    {
        // The Kernel Dock is the only observed dock that goes black after ADS recovery. This does not rely on visible/current checks; it
        // directly ensures the dock content is the KernelDock instance itself, avoiding restoration to an old placeholder or empty container.
        // In background image mode, the root widget can no longer be forced to self-draw with a solid background, otherwise it will block the main window's background image.
        QWidget* oldWidget = dockKernel_->takeWidget();
        const bool kAllowWallpaperThroughKernelDock = shouldRenderTransparentDockContent();
        kernelWidget_->setAutoFillBackground(!kAllowWallpaperThroughKernelDock);
        kernelWidget_->setAttribute(Qt::WA_StyledBackground, !kAllowWallpaperThroughKernelDock);
        kernelWidget_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        dockKernel_->setWidget(kernelWidget_, ads::CDockWidget::ForceNoScrollArea);
        dockKernel_->setProperty("ks_lazy_initialized", true);
        if (oldWidget != nullptr && oldWidget != kernelWidget_)
        {
            oldWidget->deleteLater();
        }
        mountedWidget = dockKernel_->widget();
    }

    if (kernelWidget_ != nullptr)
    {
        kernelWidget_->ensureCurrentTabReadyForDisplay();
        kernelWidget_->show();
        kernelWidget_->raise();
        kernelWidget_->updateGeometry();
        kernelWidget_->update();
    }

    dockKernel_->setMinimumSizeHintMode(ads::CDockWidget::MinimumSizeHintFromDockWidget);
    dockKernel_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    dockKernel_->updateGeometry();
    dockKernel_->update();

    KLogEvent repairEvent;
    info << repairEvent
        << "[MainWindow][KernelDockRepair] reason="
        << reasonText.toStdString()
        << ", remount="
        << (kNeedsRemount ? "true" : "false")
        << ", dockVisible="
        << (dockKernel_->isVisible() ? "true" : "false")
        << ", dockCurrent="
        << (dockKernel_->isCurrentTab() ? "true" : "false")
        << ", dockSize="
        << dockKernel_->size().width()
        << "x"
        << dockKernel_->size().height()
        << ", widgetMatches="
        << ((mountedWidget == kernelWidget_) ? "true" : "false")
        << ", kernelVisible="
        << ((kernelWidget_ != nullptr && kernelWidget_->isVisible()) ? "true" : "false")
        << ", kernelSize="
        << (kernelWidget_ != nullptr ? kernelWidget_->size().width() : 0)
        << "x"
        << (kernelWidget_ != nullptr ? kernelWidget_->size().height() : 0)
        << ", kernelState="
        << (kernelWidget_ != nullptr ? kernelWidget_->displayStateSummary().toStdString() : std::string("null"))
        << eol;
}

void MainWindow::initDockWidgets()
{
    const QString kStartupDockKey = currentAppearanceSettings_.startupDefaultTabKey.trimmed().toLower();
    const auto kShouldEagerLoad = [&kStartupDockKey](const QString& dockKey) -> bool
        {
            return dockKey == QStringLiteral("welcome") ||
                (kStartupDockKey == QStringLiteral("winapi") && dockKey == QStringLiteral("monitor")) ||
                dockKey == kStartupDockKey;
        };

    // Prioritize the first screen: welcome page and default startup tab; settings are now opened immediately via the top menu.
    reportStartupProgress(
        50,
        QStringLiteral("main.startup.progress.first_page"),
        QStringLiteral("正在加载功能模块..."));
    welcomeWidget_ = new WelcomeDock(this);
    connect(
        welcomeWidget_,
        &WelcomeDock::languageSettingsRequested,
        this,
        [this]() {
            showSettingsPanelFromMenu(true);
        });
    if (kShouldEagerLoad(QStringLiteral("process")))
    {
        processWidget_ = new ProcessDock(this);
        connect(
            processWidget_,
            &ProcessDock::requestFocusProcessProtectByCallback,
            this,
            &MainWindow::focusProcessProtectByCallback);
    }
    if (kShouldEagerLoad(QStringLiteral("network"))) { networkWidget_ = new NetworkDock(this); }
    if (kShouldEagerLoad(QStringLiteral("memory"))) { memoryWidget_ = new MemoryDock(this); }
    if (kShouldEagerLoad(QStringLiteral("file"))) { fileWidget_ = new FileDock(this); }
    if (kShouldEagerLoad(QStringLiteral("driver"))) { driverWidget_ = new DriverDock(this); }
    // KernelDock no longer participates in the main Dock's lazy placeholder:
    // - It is the only scenario that can reproduce the startup recovery black screen.
    // - The actual creation cost is controllable and avoids ADS restoreState restoring placeholder pages/empty containers to the current page.
    kernelWidget_ = new KernelDock(this);
    if (driverWidget_ != nullptr)
    {
        driverWidget_->attachKswordSelfDriverPage(
            kernelWidget_->kswordSelfDriverPage(),
            kernelWidget_);
    }
    if (kShouldEagerLoad(QStringLiteral("kvm"))) { kvmWidget_ = createKvmDockContent(); }
    if (kShouldEagerLoad(QStringLiteral("monitor"))) { monitorWidget_ = new MonitorDock(this); }
    // The welcome page's performance card reuses the sole sampling source from HardwareDock, so the hardware sampler is created along with the main window.
    // The hardware Dock itself remains on-demand to avoid duplicating PDH/DXGI sampling implementations.
    hardwareWidget_ = new HardwareDock(this);
    welcomeWidget_->setHardwareDock(hardwareWidget_);
    if (kShouldEagerLoad(QStringLiteral("privilege"))) { privilegeWidget_ = new PrivilegeDock(this); }
    if (kShouldEagerLoad(QStringLiteral("window"))) { windowWidget_ = new WindowDock(this); }
    if (kShouldEagerLoad(QStringLiteral("registry"))) { registryWidget_ = new RegistryDock(this); }
    if (kShouldEagerLoad(QStringLiteral("handle"))) { handleWidget_ = new HandleDock(this); }
    if (kShouldEagerLoad(QStringLiteral("startup"))) { startupWidget_ = new StartupDock(this); }
    if (kShouldEagerLoad(QStringLiteral("service"))) { serviceWidget_ = new ServiceDock(this); }
    if (kShouldEagerLoad(QStringLiteral("misc")))
    {
        miscWidget_ = new MiscDock(this);
        updateBugcheckDiagnosticsEntryVisibility();
    }

    reportStartupProgress(
        60,
        QStringLiteral("main.startup.progress.auxiliary_components"),
        QStringLiteral("正在加载功能模块..."));
    // The 'Immediate Window' retains its implementation code but is not registered with the ADS.
    // The log output independent window remains persistent; the three auxiliary docks each hold independent content controls.
    logOutputWindow_ = new QDialog(this);
    logOutputWindow_->setObjectName(QStringLiteral("ksLogOutputWindow"));
    logOutputWindow_->setWindowTitle(ks::i18n::text(QStringLiteral("dock.log"), QStringLiteral("日志输出")));
    logOutputWindow_->setWindowModality(Qt::NonModal);
    logOutputWindow_->setModal(false);
    logOutputWindow_->setAttribute(Qt::WA_DeleteOnClose, false);
    logOutputWindow_->resize(900, 620);
    ks::i18n::LanguageManager::instance().bindWindowTitle(
        logOutputWindow_,
        QStringLiteral("dock.log"),
        QStringLiteral("日志输出"));
    QVBoxLayout* logWindowLayout = new QVBoxLayout(logOutputWindow_);
    logWindowLayout->setContentsMargins(8, 8, 8, 8);
    logWindowLayout->setSpacing(0);
    logWidget_ = new LogDockWidget(logOutputWindow_);
    logWindowLayout->addWidget(logWidget_, 1);
    logOutputWindow_->installEventFilter(this);
    logWindowGeometrySaveTimer_ = new QTimer(this);
    logWindowGeometrySaveTimer_->setSingleShot(true);
    logWindowGeometrySaveTimer_->setInterval(300);
    connect(logWindowGeometrySaveTimer_, &QTimer::timeout, this, &MainWindow::persistLogOutputWindowGeometry);
    restoreLogOutputWindowGeometry();
    logOutputWindow_->hide();

    notificationCardManager_ = new ks::ui::NotificationCardManager(this, pDockManager_, this);
    notificationCardManager_->applySettings(currentAppearanceSettings_);

    // Advance the startup progress once more before creating Dock containers to avoid lingering on a single status message for too long.
    reportStartupProgress(
        68,
        QStringLiteral("main.startup.progress.dock_containers"),
        QStringLiteral("正在加载功能模块..."));

    // Use a helper function to create Dock Widgets.
    auto createDockWidget = [this](
        QWidget* widget,
        const QString& title,
        const QString& dockKey,
        const ads::CDockWidget::eInsertMode insertMode = ads::CDockWidget::AutoScrollArea) -> ads::CDockWidget* {
        const bool kIsKernelDock = (dockKey == QStringLiteral("kernel"));
        ads::CDockWidget* dock = new ads::CDockWidget(title);
        configureDockWidgetPersistentIdentity(dock, dockKey);
        ks::i18n::LanguageManager::instance().bindWindowTitle(
            dock,
            QStringLiteral("dock.%1").arg(dockKey),
            title);
        dock->setWidget(widget, insertMode);
        // Disable DockWidgetClosable: Uniformly remove the close 'X' next to each Dock tab.
        dock->setFeature(ads::CDockWidget::DockWidgetClosable, false);
        dock->setFeature(ads::CDockWidget::DockWidgetMovable, true);
        dock->setFeature(ads::CDockWidget::DockWidgetFloatable, true);

        // Dock background property initialization:
        // - Disable automatic background filling for docks and their content root widgets by default;
        // - Prevent the background from being covered by solid black/white in background image mode.
        dock->setAutoFillBackground(false);
        dock->setAttribute(Qt::WA_StyledBackground, false);
        if (widget != nullptr)
        {
            // In transparent background mode, even KernelDock must not self-draw solid content, otherwise it will obscure the mica material.
            const bool kIsRealKernelContent = kIsKernelDock
                && widget == kernelWidget_
                && !shouldRenderTransparentDockContent();
            // KernelDock paints its own tab surface.  Do not convert it to a transparent root here,
            // otherwise a restored startup kernel dock can inherit the dark ADS background before
            // its internal pages get a chance to repaint.
            widget->setAutoFillBackground(kIsRealKernelContent);
            widget->setAttribute(Qt::WA_StyledBackground, kIsRealKernelContent);
        }
        configureAdsDockTabVisualIdentity(dock);
        return dock;
        };

    auto createLazyDockWidget = [this, &createDockWidget](
        ads::CDockWidget*& dockOut,
        QWidget* eagerWidget,
        const QString& title,
        const QString& dockKey)
        {
            const bool kIsNetworkDock = (dockKey == QStringLiteral("network"));
            const bool kIsKernelDock = (dockKey == QStringLiteral("kernel"));
            const bool kShouldSuppressOuterScrollArea =
                kIsNetworkDock || (dockKey == QStringLiteral("hardware")) || kIsKernelDock ||
                (dockKey == QStringLiteral("kvm"));
            QWidget* dockContentWidget = eagerWidget;
            if (dockContentWidget == nullptr)
            {
                dockContentWidget = createDockPlaceholderWidget(title);
            }

            dockContentWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            dockOut = createDockWidget(
                dockContentWidget,
                title,
                dockKey,
                kShouldSuppressOuterScrollArea ? ads::CDockWidget::ForceNoScrollArea : ads::CDockWidget::AutoScrollArea);
            dockOut->setProperty("ks_lazy_key", dockKey);
            dockOut->setProperty("ks_lazy_initialized", eagerWidget != nullptr);
            if (kIsNetworkDock)
            {
                dockContentWidget->setMinimumHeight(300);
                dockOut->setMinimumSizeHintMode(ads::CDockWidget::MinimumSizeHintFromDockWidgetMinimumSize);
                dockOut->setMinimumHeight(300);
                dockOut->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            }
            connect(dockOut, &ads::CDockWidget::visibilityChanged, this, [this, dockOut](const bool visible)
                {
                    if (visible)
                    {
                        QTimer::singleShot(0, this, [this, dockOut]() {
                            ensureDockContentInitialized(dockOut);
                            });
                    }
                });

            if (eagerWidget == nullptr)
            {
                deferredDockLoadQueue_.push_back(dockOut);
            }
        };

    // setupDockTabText purpose: unifies the text truncation strategy for the main Dock Tab and allows width to adapt to content.
    const auto kSetupDockTabText = [](ads::CDockWidget* dockWidget) {
        if (dockWidget == nullptr || dockWidget->tabWidget() == nullptr)
        {
            return;
        }

        ads::CDockWidgetTab* tabWidget = dockWidget->tabWidget();
        tabWidget->setElideMode(Qt::ElideNone);
        tabWidget->setMinimumWidth(0);
        tabWidget->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    };

    // Create all dock shells; if a reloaded page is not preloaded, first reserve a placeholder page, add it to the display queue, and then load it asynchronously.
    dockWelcome_ = createDockWidget(
        welcomeWidget_,
        ks::i18n::text(QStringLiteral("dock.welcome"), QStringLiteral("欢迎")),
        QStringLiteral("welcome"),
        ads::CDockWidget::ForceNoScrollArea);
    createLazyDockWidget(dockProcess_, processWidget_, ks::i18n::text(QStringLiteral("dock.process"), QStringLiteral("进程")), QStringLiteral("process"));
    createLazyDockWidget(dockNetwork_, networkWidget_, ks::i18n::text(QStringLiteral("dock.network"), QStringLiteral("网络")), QStringLiteral("network"));
    createLazyDockWidget(dockMemory_, memoryWidget_, ks::i18n::text(QStringLiteral("dock.memory"), QStringLiteral("内存")), QStringLiteral("memory"));
    createLazyDockWidget(dockFile_, fileWidget_, ks::i18n::text(QStringLiteral("dock.file"), QStringLiteral("文件")), QStringLiteral("file"));
    createLazyDockWidget(dockDriver_, driverWidget_, ks::i18n::text(QStringLiteral("dock.driver"), QStringLiteral("驱动")), QStringLiteral("driver"));
    createLazyDockWidget(dockKernel_, kernelWidget_, ks::i18n::text(QStringLiteral("dock.kernel"), QStringLiteral("内核")), QStringLiteral("kernel"));
    createLazyDockWidget(dockKvm_, kvmWidget_, ks::i18n::text(QStringLiteral("dock.kvm"), QStringLiteral("虚拟化 (KVM)")), QStringLiteral("kvm"));
    createLazyDockWidget(dockMonitorTab_, monitorWidget_, ks::i18n::text(QStringLiteral("dock.monitor"), QStringLiteral("监控")), QStringLiteral("monitor"));
    createLazyDockWidget(dockHardware_, hardwareWidget_, ks::i18n::text(QStringLiteral("dock.hardware"), QStringLiteral("硬件")), QStringLiteral("hardware"));
    createLazyDockWidget(dockPrivilege_, privilegeWidget_, ks::i18n::text(QStringLiteral("dock.privilege"), QStringLiteral("权限")), QStringLiteral("privilege"));
    createLazyDockWidget(dockWindow_, windowWidget_, ks::i18n::text(QStringLiteral("dock.window"), QStringLiteral("窗口")), QStringLiteral("window"));
    createLazyDockWidget(dockRegistry_, registryWidget_, ks::i18n::text(QStringLiteral("dock.registry"), QStringLiteral("注册表")), QStringLiteral("registry"));
    createLazyDockWidget(dockHandle_, handleWidget_, ks::i18n::text(QStringLiteral("dock.handle"), QStringLiteral("句柄")), QStringLiteral("handle"));
    createLazyDockWidget(dockStartup_, startupWidget_, ks::i18n::text(QStringLiteral("dock.startup"), QStringLiteral("启动项")), QStringLiteral("startup"));
    createLazyDockWidget(dockService_, serviceWidget_, ks::i18n::text(QStringLiteral("dock.service"), QStringLiteral("服务")), QStringLiteral("service"));
    createLazyDockWidget(dockMisc_, miscWidget_, ks::i18n::text(QStringLiteral("dock.misc"), QStringLiteral("杂项")), QStringLiteral("misc"));

    // The three auxiliary docks are always created and registered; on close, only the content instances are hidden to ensure menu state and ADS layout remain recoverable.
    dockLogWidget_ = new LogDockWidget(this);
    monitorPanelWidget_ = new MonitorPanelWidget(this);
    progressWidget_ = new ProgressDockWidget(this);
    dockLog_ = createDockWidget(
        dockLogWidget_,
        ks::i18n::text(QStringLiteral("dock.log_window"), QStringLiteral("日志窗口")),
        QStringLiteral("log_window"),
        ads::CDockWidget::ForceNoScrollArea);
    dockMonitor_ = createDockWidget(
        monitorPanelWidget_,
        ks::i18n::text(QStringLiteral("dock.monitor_panel"), QStringLiteral("监视面板")),
        QStringLiteral("monitor_panel"),
        ads::CDockWidget::ForceNoScrollArea);
    dockCurrentOp_ = createDockWidget(
        progressWidget_,
        ks::i18n::text(QStringLiteral("dock.current_tasks"), QStringLiteral("当前任务")),
        QStringLiteral("current_tasks"),
        ads::CDockWidget::ForceNoScrollArea);
    for (ads::CDockWidget* auxiliaryDock : { dockLog_, dockMonitor_, dockCurrentOp_ })
    {
        auxiliaryDock->setFeature(ads::CDockWidget::DockWidgetClosable, true);
        auxiliaryDock->setFeature(ads::CDockWidget::DockWidgetDeleteOnClose, false);
        auxiliaryDock->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);
        kSetupDockTabText(auxiliaryDock);
        configureAdsDockTabVisualIdentity(auxiliaryDock);
    }
    initializeWindowDockMenuActions();

    QList<ads::CDockWidget*> mainDockTabList{
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
        dockMisc_
    };
    for (ads::CDockWidget* dockWidget : mainDockTabList)
    {
        kSetupDockTabText(dockWidget);
        configureAdsDockTabVisualIdentity(dockWidget);
    }

    // The main function tab does not enter the window menu; the menu only hosts three closable auxiliary docks.
    reportStartupProgress(
        72,
        QStringLiteral("main.startup.progress.skip_view_menu"),
        QStringLiteral("正在加载功能模块..."));
}

void MainWindow::setupDockLayout()
{
    QElapsedTimer layoutTimer;
    layoutTimer.start();

    // 1. initialize DockManager (if not initialized in constructor)
    if (!pDockManager_) {
        QWidget* dockParentWidget = (mainRootContainer_ != nullptr)
            ? mainRootContainer_
            : this;
        pDockManager_ = new ads::CDockManager(dockParentWidget);
        if (mainRootLayout_ != nullptr && mainRootContainer_ != nullptr)
        {
            mainRootLayout_->addWidget(pDockManager_, 1);
            if (centralWidget() != mainRootContainer_)
            {
                setCentralWidget(mainRootContainer_);
            }
        }
        else
        {
            setCentralWidget(pDockManager_);
        }
    }

    const bool kMainWindowUpdatesWereEnabled = updatesEnabled();
    const bool kDockManagerUpdatesWereEnabled = pDockManager_->updatesEnabled();
    setUpdatesEnabled(false);
    pDockManager_->setUpdatesEnabled(false);

    reportStartupProgress(
        76,
        QStringLiteral("main.startup.progress.register_main_docks"),
        QStringLiteral("正在加载功能模块..."));

    // 2. Left area: Add the first DockWidget first to retrieve its associated DockArea.
    auto leftDockArea = pDockManager_->addDockWidget(ads::LeftDockWidgetArea, dockWelcome_);

    // 3. Add other DockWidget instances to the same DockArea as
    // tabs. Method 1: Use addDockWidgetTabToArea (recommended).
    pDockManager_->addDockWidgetTabToArea(dockProcess_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockNetwork_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockMemory_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockFile_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockDriver_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockKernel_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockKvm_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockMonitorTab_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockHardware_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockPrivilege_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockWindow_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockRegistry_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockHandle_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockStartup_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockService_, leftDockArea);
    pDockManager_->addDockWidgetTabToArea(dockMisc_, leftDockArea);

    // Method 2: Alternatively, use addDockWidget and specify CenterDockWidgetArea.
    // m_pDockManager->addDockWidget(ads::CenterDockWidgetArea, m_dockProcess, leftDockArea);

    reportStartupProgress(
        78,
        QStringLiteral("main.startup.progress.register_auxiliary_docks"),
        QStringLiteral("正在加载功能模块..."));

    // 4. Auxiliary docks are located at the bottom by default, arranged horizontally in a 2:2:1 ratio as "Log Window | Monitor Panel | Current Task".
    // On first launch, close all three but preserve their dock positions; version 6 layout restoration will override this default visibility state.
    auto bottomLogArea = pDockManager_->addDockWidget(
        ads::BottomDockWidgetArea,
        dockLog_);
    auto bottomMonitorArea = pDockManager_->addDockWidget(
        ads::RightDockWidgetArea,
        dockMonitor_,
        bottomLogArea);
    pDockManager_->addDockWidget(
        ads::RightDockWidgetArea,
        dockCurrentOp_,
        bottomMonitorArea);
    pDockManager_->setSplitterSizes(leftDockArea, { 3, 1 });
    pDockManager_->setSplitterSizes(bottomLogArea, { 2, 2, 1 });
    dockLog_->toggleView(false);
    dockMonitor_->toggleView(false);
    dockCurrentOp_->toggleView(false);

    // 5. Set the default displayed tab.
    withTemporaryNonTopMostForDockSwitch([this]()
        {
            dockWelcome_->raise();
        });

    // Immediately restore updates after the default dock topology is finalized, then allow ADS to create floating top-level windows from the saved state:
    // - restoreState() detaches some docks from m_pDockManager and creates independent top-level windows;
    // - If they were created within a control tree where updatesEnabled=false, they will retain the disabled drawing state after restoration.
    // - At this point, mouse hits and the right-click menu still work normally, but the window client area remains black.
    setUpdatesEnabled(kMainWindowUpdatesWereEnabled);
    pDockManager_->setUpdatesEnabled(kDockManagerUpdatesWereEnabled);

    // 6. Restore user layout after the default layout is built:
    // - ADS restoreState requires every DockWidget to be registered;
    // - objectName is already fixed to an English key in initDockWidgets to prevent title changes from breaking restoration;
    reportStartupProgress(
        80,
        QStringLiteral("main.startup.progress.restore_dock_layout"),
        QStringLiteral("正在恢复界面布局..."));
    restoreDockLayoutFromConfig();
    // Old layout configurations do not include newly added Docks; ADS will not place them, so they must be reattached to the primary tab bar here.
    reattachDetachedFeatureDocks();
    attachPrivilegeStatusButtonsToPrimaryDockTabBar();
    reportStartupProgress(
        82,
        QStringLiteral("main.startup.progress.refresh_dock_tabs"),
        QStringLiteral("正在恢复界面布局..."));
    refreshAdsDockTabVisualIdentities(pDockManager_);

    // Perform an explicit correction on the restored independent top-level windows:
    // ADS version differences may cause dockContainer to retain the update-disabled flag from the restore phase.
    // Process only floating containers generated by this layout restore; do not traverse or modify Dock content controls.
    if (kDockManagerUpdatesWereEnabled)
    {
        const QList<ads::CFloatingDockContainer*> kFloatingWidgets = pDockManager_->floatingWidgets();
        for (ads::CFloatingDockContainer* floatingWidget : kFloatingWidgets)
        {
            if (floatingWidget == nullptr)
            {
                continue;
            }
            floatingWidget->installEventFilter(this);
            floatingWidget->setUpdatesEnabled(true);
            if (ads::CDockContainerWidget* dockContainer = floatingWidget->dockContainer(); dockContainer != nullptr)
            {
                dockContainer->setUpdatesEnabled(true);
                dockContainer->updateGeometry();
                dockContainer->update();
            }
            floatingWidget->updateGeometry();
            floatingWidget->update();
        }
    }
    pDockManager_->updateGeometry();
    pDockManager_->update();

    KLogEvent layoutTimingEvent;
    info << layoutTimingEvent
        << "[MainWindow][StartupTiming] setupDockLayout elapsedMs="
        << layoutTimer.elapsed()
        << eol;
}

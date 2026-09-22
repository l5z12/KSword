#include "MainWindow.h"
#include "minidump_dock/DumpAutoCheck.h"
#include "internationalization/LanguageManager.h"
#include "process_dock/ProcessDock.h"
#include "network_dock/NetworkDock.h"
#include "memory_dock/MemoryDock.h"
#include "file_dock/FileDock.h"
#include "kernel_dock/KernelDock.h"
#include "service_dock/ServiceDock.h"
#include "window_dock/WindowDock.h"
#include "misc_dock/MiscDock.h"
#include "minidump_dock/MinidumpDock.h"
#include "handle_dock/HandleDock.h"
#include <QCheckBox>
#include <QDir>
#include <QFileInfo>
#include <QSet>
#include <QList>
#include <QPushButton>
#include <QMessageBox>
#include <QStringList>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "include/ads/DockAreaWidget.h"
#include "include/ads/DockWidgetTab.h"
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

namespace ksword::ui::main_window
{
    QVector<quint32> parseProcessPidListText(const QString& pidListText)
    {
        QString normalizedText = pidListText;
        normalizedText.replace(',', ' ');
        normalizedText.replace(';', ' ');
        normalizedText.replace('\n', ' ');
        normalizedText.replace('\t', ' ');

        QVector<quint32> processIds;
        QSet<quint32> seenPidSet;
        for (const QString& token : normalizedText.split(' ', Qt::SkipEmptyParts))
        {
            bool parseOk = false;
            const quint32 kProcessId = token.toUInt(&parseOk, 10);
            if (parseOk && kProcessId != 0U && !seenPidSet.contains(kProcessId))
            {
                seenPidSet.insert(kProcessId);
                processIds.push_back(kProcessId);
            }
        }
        return processIds;
    }
}

using namespace ksword::ui::main_window;

void MainWindow::focusHandleDockByPid(const quint32 pid)
{
    // Jump entry log: record the source request PID to facilitate call chain audit tracing.
    KLogEvent focusHandleEvent;
    info << focusHandleEvent
        << "[MainWindow] focusHandleDockByPid: pid="
        << pid
        << eol;

    if (dockHandle_ != nullptr)
    {
        ensureDockContentInitialized(dockHandle_);
    }
    if (handleWidget_ != nullptr)
    {
        handleWidget_->focusProcessId(static_cast<std::uint32_t>(pid), true);
    }
    if (dockHandle_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                dockHandle_->raise();
            });
        dockHandle_->setVisible(true);
    }
}

void MainWindow::focusHandleDockByPids(const QString& pidListText)
{
    const QVector<quint32> kProcessIds = parseProcessPidListText(pidListText);
    if (kProcessIds.isEmpty())
    {
        return;
    }
    if (dockHandle_ != nullptr)
    {
        ensureDockContentInitialized(dockHandle_);
    }
    if (handleWidget_ != nullptr)
    {
        handleWidget_->focusProcessIds(kProcessIds, true);
    }
    if (dockHandle_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]() { dockHandle_->raise(); });
        dockHandle_->setVisible(true);
    }
}

void MainWindow::focusProcessProtectByCallback()
{
    if (dockKernel_ != nullptr)
    {
        ensureDockContentInitialized(dockKernel_);
    }
    if (kernelWidget_ == nullptr || dockKernel_ == nullptr)
    {
        return;
    }

    kernelWidget_->focusProcessProtectTab();
    withTemporaryNonTopMostForDockSwitch([this]()
        {
            dockKernel_->raise();
        });
    dockKernel_->setVisible(true);
}

void MainWindow::focusMemoryDockByPid(const quint32 pid)
{
    // Log entry for jump target: record the target PID and ensure the memory dock is fully loaded lazily.
    KLogEvent focusMemoryEvent;
    info << focusMemoryEvent
        << "[MainWindow] focusMemoryDockByPid: pid="
        << pid
        << eol;

    if (dockMemory_ != nullptr)
    {
        ensureDockContentInitialized(dockMemory_);
    }
    if (memoryWidget_ != nullptr)
    {
        memoryWidget_->focusProcessForOperations(static_cast<std::uint32_t>(pid), false);
    }
    if (dockMemory_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                dockMemory_->raise();
            });
        dockMemory_->setVisible(true);
    }
}

void MainWindow::focusMemoryDockDdmaPage()
{
    KLogEvent focusDdmaEvent;
    info << focusDdmaEvent
        << "[MainWindow] focusMemoryDockDdmaPage: 打开内存页的 DDMA 子页。"
        << eol;

    // The Memory Dock is lazily loaded: if content initialization is not ensured first,
    // m_memoryWidget may still be null, causing button clicks to have no effect.
    if (dockMemory_ != nullptr)
    {
        ensureDockContentInitialized(dockMemory_);
    }
    if (memoryWidget_ != nullptr)
    {
        memoryWidget_->focusDdmaPage();
    }
    if (dockMemory_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                dockMemory_->raise();
            });
        dockMemory_->setVisible(true);
    }
}

void MainWindow::focusNetworkDockByPids(const QString& pidListText)
{
    const QVector<quint32> kProcessIds = parseProcessPidListText(pidListText);
    if (kProcessIds.isEmpty())
    {
        return;
    }
    if (dockNetwork_ != nullptr)
    {
        ensureDockContentInitialized(dockNetwork_);
    }
    if (networkWidget_ != nullptr)
    {
        networkWidget_->focusConnectionsByPids(kProcessIds);
    }
    if (dockNetwork_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]() { dockNetwork_->raise(); });
        dockNetwork_->setVisible(true);
    }
}

void MainWindow::focusWindowDockByPids(const QString& pidListText)
{
    const QVector<quint32> kProcessIds = parseProcessPidListText(pidListText);
    if (kProcessIds.isEmpty())
    {
        return;
    }
    if (dockWindow_ != nullptr)
    {
        ensureDockContentInitialized(dockWindow_);
    }
    if (windowWidget_ != nullptr)
    {
        windowWidget_->focusWindowsByPids(kProcessIds);
    }
    if (dockWindow_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]() { dockWindow_->raise(); });
        dockWindow_->setVisible(true);
    }
}

void MainWindow::openProcessDetailByPid(const quint32 pid)
{
    // Jump entry log: records PID jump requests originating from external modules.
    KLogEvent openProcessDetailEvent;
    info << openProcessDetailEvent
        << "[MainWindow] openProcessDetailByPid: pid="
        << pid
        << eol;

    // The Process page still handles detail window reuse and process identity validation, but here we only initialize its content without
    // activating the Process Dock to avoid switching away from the current tab when opening an independent detail window from another Dock.
    if (dockProcess_ != nullptr)
    {
        ensureDockContentInitialized(dockProcess_);
    }
    if (processWidget_ != nullptr)
    {
        processWidget_->requestOpenProcessDetailByPid(static_cast<std::uint32_t>(pid));
    }
}

void MainWindow::openProcessDetailByIdentity(
    const quint32 pid,
    const quint64 creationTime100ns)
{
    // openProcessDetailEvent: Record the complete process identity carried by the historical event.
    KLogEvent openProcessDetailEvent;
    info << openProcessDetailEvent
        << "[MainWindow] openProcessDetailByIdentity: pid="
        << pid
        << ", creationTime100ns="
        << creationTime100ns
        << eol;

    // The Process page still handles detail window reuse and historical identity validation, but here we only initialize its content without
    // activating the Process Dock to avoid switching away from the current tab when opening an independent detail window from another Dock.
    if (dockProcess_ != nullptr)
    {
        ensureDockContentInitialized(dockProcess_);
    }
    if (processWidget_ != nullptr)
    {
        processWidget_->requestOpenProcessDetailByIdentity(
            static_cast<std::uint32_t>(pid),
            static_cast<std::uint64_t>(creationTime100ns));
    }
    // When a historical target becomes invalid, ProcessDock displays an explicit prompt; detail requests do not change the current Dock tab.
}

void MainWindow::focusServiceDockByName(const QString& serviceNameText)
{
    const QString kNormalizedServiceName = serviceNameText.trimmed();
    KLogEvent focusServiceEvent;
    info << focusServiceEvent
        << "[MainWindow] focusServiceDockByName: service="
        << kNormalizedServiceName.toStdString()
        << eol;

    if (dockService_ != nullptr)
    {
        ensureDockContentInitialized(dockService_);
    }
    if (serviceWidget_ != nullptr && !kNormalizedServiceName.isEmpty())
    {
        serviceWidget_->focusServiceByName(kNormalizedServiceName);
    }
    if (dockService_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                dockService_->raise();
            });
        dockService_->setVisible(true);
    }
}

void MainWindow::openFileDetailDockByPath(const QString& filePath)
{
    const QString kNormalizedFilePath = QDir::toNativeSeparators(filePath.trimmed());
    if (kNormalizedFilePath.isEmpty())
    {
        return;
    }

    KLogEvent openFileDetailEvent;
    info << openFileDetailEvent
        << "[MainWindow] openFileDetailDockByPath: file="
        << kNormalizedFilePath.toStdString()
        << eol;

    if (dockFile_ != nullptr)
    {
        ensureDockContentInitialized(dockFile_);
    }
    if (fileWidget_ != nullptr)
    {
        fileWidget_->openFileDetailByPath(kNormalizedFilePath);
    }
    if (dockFile_ != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                dockFile_->raise();
            });
        dockFile_->setVisible(true);
    }
}

void MainWindow::openFileUnlockerDockByPath(const QString& filePath)
{
    const QString kNormalizedFilePath = QDir::toNativeSeparators(filePath.trimmed());
    if (kNormalizedFilePath.isEmpty())
    {
        return;
    }

    KLogEvent unlockFileEvent;
    info << unlockFileEvent
        << "[MainWindow] openFileUnlockerDockByPath: path="
        << kNormalizedFilePath.toStdString()
        << eol;

    const QFileInfo kTargetFileInfo(kNormalizedFilePath);
    if (!kTargetFileInfo.exists() || (!kTargetFileInfo.isFile() && !kTargetFileInfo.isDir()))
    {
        warn << unlockFileEvent
            << "[MainWindow] openFileUnlockerDockByPath canceled: invalid path="
            << kNormalizedFilePath.toStdString()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("Ksword 文件解锁器"),
            QStringLiteral("目标路径不存在或不是文件/目录：\n%1").arg(kNormalizedFilePath));
        return;
    }

    // The Shell right-click entry must reuse the same flow as the internal 'File Unlocker (R3/R0)' in FileDock.
    // Reuse the real FileDock directly when the file tab is open; otherwise use the hidden host to avoid black screen during file tab switching at startup.
    FileDock* unlockerHost = fileWidget_;
    if (unlockerHost == nullptr)
    {
        if (shellUnlockerFileDock_ == nullptr)
        {
            shellUnlockerFileDock_ = new FileDock(this);
            shellUnlockerFileDock_->setObjectName(QStringLiteral("ShellUnlockerFileDockHost"));
            shellUnlockerFileDock_->setAttribute(Qt::WA_DontShowOnScreen, true);
            shellUnlockerFileDock_->hide();
        }
        unlockerHost = shellUnlockerFileDock_;
    }

    this->raise();
    this->activateWindow();
    unlockerHost->unlockFileByPath(kTargetFileInfo.absoluteFilePath());

    info << unlockFileEvent
        << "[MainWindow] openFileUnlockerDockByPath delegated to FileDock unlocker."
        << eol;
}

void MainWindow::reattachDetachedFeatureDocks()
{
    if (pDockManager_ == nullptr || dockWelcome_ == nullptr)
    {
        return;
    }

    // The main Dock area is anchored to the welcome page: it must exist in the saved layout and serves as the only stable reference.
    ads::CDockAreaWidget* const kMainArea = dockWelcome_->dockAreaWidget();
    if (kMainArea == nullptr)
    {
        return;
    }

    // Only process main feature docks in the left tab bar. Logs, monitoring, and current operations belong to the
    // bottom area; users dragging them into floating windows is normal usage and they should not be retracted together.
    const QList<ads::CDockWidget*> kFeatureDocks = {
        dockProcess_, dockNetwork_, dockMemory_, dockFile_,
        dockDriver_, dockKernel_, dockMonitorTab_,
        dockHardware_, dockPrivilege_, dockWindow_, dockRegistry_,
        dockHandle_, dockStartup_, dockService_, dockMisc_
    };

    QStringList reattachedKeys;
    for (ads::CDockWidget* const kDockWidget : kFeatureDocks)
    {
        if (kDockWidget == nullptr || kDockWidget == dockWelcome_)
        {
            continue;
        }
        // The condition is 'the containing widget is not the main container', not `isFloating()`:
        // The restored Dock may be placed within a tab group of a floating container. In this case, it is not
        // technically floating, but from the user's perspective, it appears as an "independent window popping up."
        ads::CDockContainerWidget* const kContainer = kDockWidget->dockContainer();
        if (kContainer != nullptr && kContainer == pDockManager_)
        {
            continue;
        }

        pDockManager_->addDockWidgetTabToArea(kDockWidget, kMainArea);
        reattachedKeys.append(kDockWidget->property("ks_lazy_key").toString());
    }

    if (reattachedKeys.isEmpty())
    {
        return;
    }

    KLogEvent layoutEvent;
    info << layoutEvent
        << "[MainWindow][ADS] 已把游离的功能页收回主标签区（旧布局配置中不含这些页）: "
        << reattachedKeys.join(QStringLiteral(",")).toStdString()
        << eol;
}

void MainWindow::openMinidumpDockWithFile(const QString& filePath)
{
    const QString kNormalizedPath = QDir::toNativeSeparators(filePath.trimmed());
    if (kNormalizedPath.isEmpty())
    {
        return;
    }

    // Dump analysis has been merged into the Miscellaneous page: first activate the Miscellaneous Dock and add
    // its content, then have the Miscellaneous page construct the "Dump Analysis" sub-page and switch to it.
    MiscDock* const kMiscDock = activateMiscDockForMergedTab(QStringLiteral("转储分析"));
    if (kMiscDock == nullptr)
    {
        KLogEvent dumpEvent;
        warn << dumpEvent
            << "[MainWindow] 杂项页未能初始化，无法自动解析转储: "
            << kNormalizedPath.toStdString()
            << eol;
        return;
    }

    MinidumpDock* const kMinidumpPage = kMiscDock->activateMinidumpTab();
    if (kMinidumpPage == nullptr)
    {
        KLogEvent dumpEvent;
        warn << dumpEvent
            << "[MainWindow] 转储分析子页未能初始化，无法自动解析: "
            << kNormalizedPath.toStdString()
            << eol;
        return;
    }
    kMinidumpPage->openDumpFile(kNormalizedPath);
}

MiscDock* MainWindow::activateMiscDockForMergedTab(const QString& tabDisplayName)
{
    // Input: display name of the sub-page merged into the Miscellaneous page, used for log tracing only.
    // Handling: activate the miscellaneous Dock and ensure its content control is constructed.
    // Returns: the content control for the Miscellaneous page. Returns nullptr if the Dock is unavailable; the caller should abort the navigation.
    if (dockMisc_ == nullptr)
    {
        return nullptr;
    }

    // The Miscellaneous page is also lazily loaded; populate content first, then activate to avoid obtaining a placeholder control.
    ensureDockContentInitialized(dockMisc_);
    dockMisc_->toggleView(true);
    dockMisc_->raise();
    dockMisc_->setAsCurrentTab();

    if (miscWidget_ == nullptr)
    {
        KLogEvent jumpEvent;
        warn << jumpEvent
            << "[MainWindow] 杂项页内容未初始化，跳转失败: "
            << tabDisplayName.toStdString()
            << eol;
    }
    return miscWidget_;
}

void MainWindow::checkRecentCrashDumps()
{
    if (!currentAppearanceSettings_.dumpAutoCheckEnabled)
    {
        return;
    }

    const ks::minidump::RecentDumpInfo kRecent = ks::minidump::findRecentDump(24);
    if (!kRecent.found)
    {
        return;
    }

    // Ask about the same dump only once. Compare both path and time: MEMORY.DMP has a fixed path but its
    // content gets overwritten by the next crash; comparing only the path would miss truly new dumps.
    const qint64 kRecentTimeMsec = kRecent.modifiedTime.toMSecsSinceEpoch();
    if (currentAppearanceSettings_.dumpAutoCheckPromptedPath.compare(
            kRecent.filePath, Qt::CaseInsensitive) == 0 &&
        currentAppearanceSettings_.dumpAutoCheckPromptedTimeMsec == kRecentTimeMsec)
    {
        return;
    }

    {
        KLogEvent dumpEvent;
        info << dumpEvent
            << "[MainWindow] 发现近期崩溃转储: "
            << kRecent.filePath.toStdString()
            << " 时间 " << kRecent.modifiedTime.toString(Qt::ISODate).toStdString()
            << " 窗口内共 " << kRecent.totalRecentCount << " 个"
            << eol;
    }

    // sizeText: Display in MB; if less than 1 MB, retain one decimal place to avoid showing 0 MB.
    const double kSizeMegabytes = static_cast<double>(kRecent.fileSizeBytes) / (1024.0 * 1024.0);
    const QString kSizeText = kSizeMegabytes >= 1.0
        ? QStringLiteral("%1 MB").arg(kSizeMegabytes, 0, 'f', 1)
        : QStringLiteral("%1 KB").arg(kRecent.fileSizeBytes / 1024.0, 0, 'f', 1);

    QString bodyText = ks::i18n::text(
        QStringLiteral("mainwindow.dump.found.body"),
        QStringLiteral(
            "检测到系统在最近 24 小时内产生了新的崩溃转储：\n\n"
            "文件：%1\n时间：%2\n大小：%3\n\n"
            "是否现在解析它？"))
        .arg(kRecent.filePath)
        .arg(kRecent.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")))
        .arg(kSizeText);
    if (kRecent.totalRecentCount > 1)
    {
        bodyText += ks::i18n::text(
            QStringLiteral("mainwindow.dump.found.multiple"),
            QStringLiteral("\n\n（窗口内共有 %1 个转储，这里列出的是最新的一个。）"))
            .arg(kRecent.totalRecentCount);
    }

    QMessageBox messageBox(this);
    messageBox.setIcon(QMessageBox::Question);
    messageBox.setWindowTitle(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.title"),
            QStringLiteral("发现新的崩溃转储")));
    messageBox.setText(bodyText);

    QCheckBox* const kDisableCheckBox = new QCheckBox(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.disable"),
            QStringLiteral("不再检查新的崩溃转储（可在设置-功能中重新开启）")),
        &messageBox);
    messageBox.setCheckBox(kDisableCheckBox);

    QPushButton* const kParseButton = messageBox.addButton(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.parse"), QStringLiteral("立即解析")),
        QMessageBox::AcceptRole);
    messageBox.addButton(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.later"), QStringLiteral("以后再说")),
        QMessageBox::RejectRole);
    messageBox.exec();

    // Regardless of the selection, record that 'this one has already been asked'; otherwise, the next startup will repeat the disturbance.
    ks::settings::AppearanceSettings updatedSettings = currentAppearanceSettings_;
    updatedSettings.dumpAutoCheckPromptedPath = kRecent.filePath;
    updatedSettings.dumpAutoCheckPromptedTimeMsec = kRecentTimeMsec;
    if (kDisableCheckBox->isChecked())
    {
        updatedSettings.dumpAutoCheckEnabled = false;
    }

    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(updatedSettings, &saveErrorText))
    {
        KLogEvent dumpEvent;
        warn << dumpEvent
            << "[MainWindow] 保存转储检查状态失败: "
            << saveErrorText.toStdString()
            << eol;
    }
    // The settings page is a local object constructed only when the settings dialog is opened, and it re-reads the JSON during
    // construction. Therefore, writing the file here is sufficient; no additional synchronization with a persistent instance is needed.
    currentAppearanceSettings_ = updatedSettings;

    if (messageBox.clickedButton() == kParseButton)
    {
        openMinidumpDockWithFile(kRecent.filePath);
    }
}

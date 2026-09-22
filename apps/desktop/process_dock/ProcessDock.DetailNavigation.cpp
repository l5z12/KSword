#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::executeOpenFolderAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeOpenFolderAction 被忽略：当前没有选中进程。" << eol;
        return;
    }

    dispatchProcessActionTargetsInParallel(
        QStringLiteral("打开所在目录"),
        kActionTargets,
        [](const ProcessActionTarget& actionTarget, std::string* detailTextOut)
        {
            return ks::process::openProcessFolder(actionTarget.record.pid, detailTextOut);
        },
        false);
}

void ProcessDock::executeOpenMemoryOperationAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] executeOpenMemoryOperationAction 被忽略：当前没有选中进程。" << eol;
        return;
    }
    if (kActionTargets.size() != 1U)
    {
        QMessageBox::information(this, QStringLiteral("跳转到内存"), QStringLiteral("内存操作一次只能附加一个进程，请仅选择一个进程。"));
        return;
    }

    const bool kInvokeOk = invokeMainWindowPidSlot("focusMemoryDockByPid", kActionTargets.front().record.pid);
    if (!kInvokeOk)
    {
        KLogEvent actionEvent;
        showActionResultMessage(
            QStringLiteral("跳转到内存操作"),
            false,
            std::string("focusMemoryDockByPid invoke failed"),
            actionEvent);
    }
}

void ProcessDock::executeFocusHandleAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    QSet<quint32> seenPidSet;
    QStringList pidTextList;
    for (const ProcessActionTarget& target : kActionTargets)
    {
        const quint32 kProcessId = static_cast<quint32>(target.record.pid);
        if (kProcessId != 0U && !seenPidSet.contains(kProcessId))
        {
            seenPidSet.insert(kProcessId);
            pidTextList.push_back(QString::number(kProcessId));
        }
    }
    (void)invokeMainWindowPidListSlot("focusHandleDockByPids", pidTextList.join(','));
}

void ProcessDock::executeFocusNetworkAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    QSet<quint32> seenPidSet;
    QStringList pidTextList;
    for (const ProcessActionTarget& target : kActionTargets)
    {
        const quint32 kProcessId = static_cast<quint32>(target.record.pid);
        if (kProcessId != 0U && !seenPidSet.contains(kProcessId))
        {
            seenPidSet.insert(kProcessId);
            pidTextList.push_back(QString::number(kProcessId));
        }
    }
    (void)invokeMainWindowPidListSlot("focusNetworkDockByPids", pidTextList.join(','));
}

void ProcessDock::executeFocusWindowAction()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    QSet<quint32> seenPidSet;
    QStringList pidTextList;
    for (const ProcessActionTarget& target : kActionTargets)
    {
        const quint32 kProcessId = static_cast<quint32>(target.record.pid);
        if (kProcessId != 0U && !seenPidSet.contains(kProcessId))
        {
            seenPidSet.insert(kProcessId);
            pidTextList.push_back(QString::number(kProcessId));
        }
    }
    (void)invokeMainWindowPidListSlot("focusWindowDockByPids", pidTextList.join(','));
}

void ProcessDock::executeOpenMessageHooksAction(
    const ks::process::ProcessRecord& targetRecord)
{
    if (targetRecord.pid == 0U)
    {
        return;
    }

    // Freeze the process snapshot when opening via the right-click menu to prevent selecting the wrong process after the menu closes.
    ProcessMessageHookTarget target;
    target.processId = targetRecord.pid;
    target.sessionId = targetRecord.sessionId;
    target.creationTime100ns = targetRecord.creationTime100ns;
    target.processName = QString::fromStdString(targetRecord.processName);

    auto* hookWindow = new ProcessMessageHookWindow(target, nullptr);
    hookWindow->show();
    hookWindow->raise();
    hookWindow->activateWindow();

    KLogEvent actionEvent;
    info << actionEvent
        << "[ProcessDock] open process message hooks window, pid="
        << target.processId
        << ", sessionId="
        << target.sessionId
        << eol;
}

void ProcessDock::requestOpenProcessDetailByPid(const std::uint32_t pid)
{
    // Unified external entry point: facilitates opening process details by PID from FileDock or the main window.
    KLogEvent requestDetailEvent;
    info << requestDetailEvent
        << "[ProcessDock] requestOpenProcessDetailByPid: pid="
        << pid
        << eol;
    openProcessDetailWindowByPid(pid);
}

void ProcessDock::requestOpenProcessDetailByIdentity(
    const std::uint32_t pid,
    const std::uint64_t creationTime100ns)
{
    // requestDetailEvent: Records the complete historical identity passed across modules.
    KLogEvent requestDetailEvent;
    info << requestDetailEvent
        << "[ProcessDock] requestOpenProcessDetailByIdentity: pid="
        << pid
        << ", creationTime100ns="
        << creationTime100ns
        << eol;

    // rejectHistoricalTarget: Unifies recording and prompting of rejection reasons; silent fallback to pure PID jump is not allowed.
    const auto kRejectHistoricalTarget = [this, pid](
        const QString& messageText,
        const std::string& diagnosticText)
    {
        // rejectEvent: Chains the PID of the rejected historical navigation with the underlying diagnostic.
        KLogEvent rejectEvent;
        warn << rejectEvent
            << "[ProcessDock] historical process identity rejected, pid="
            << pid
            << ", detail="
            << diagnosticText
            << eol;
        QMessageBox::information(
            this,
            QStringLiteral("历史进程已退出"),
            messageText);
    };

    // Missing identity is inherently unverifiable; reject the request rather than opening the process currently occupying this PID.
    if (pid == 0U || creationTime100ns == 0U)
    {
        kRejectHistoricalTarget(
            QStringLiteral(
                "该历史记录缺少可验证的进程身份。为避免 PID 复用后打开无关进程，本次跳转已取消。"),
            "historical process identity is incomplete");
        return;
    }

    // currentCreationTime100ns: Re-read the creation time of the current PID at the moment of navigation.
    std::uint64_t currentCreationTime100ns = 0U;

    // identityDetailText: receives the failure reason from OpenProcess/GetProcessTimes.
    std::string identityDetailText;

    // identityQueryOk: only proceed to open the historical target if the real-time identity query succeeds.
    const bool kIdentityQueryOk = ks::process::queryProcessCreationTimeByPid(
        pid,
        &currentCreationTime100ns,
        &identityDetailText);
    if (!kIdentityQueryOk)
    {
        kRejectHistoricalTarget(
            QStringLiteral(
                "该历史记录对应的原进程已退出，或当前无法验证其进程身份。"
                "为避免 PID 复用后打开无关进程，本次跳转已取消。"),
            identityDetailText.empty()
                ? std::string("current process identity is unavailable")
                : identityDetailText);
        return;
    }
    if (currentCreationTime100ns != creationTime100ns)
    {
        kRejectHistoricalTarget(
            QStringLiteral(
                "该历史记录对应的原进程已退出，PID %1 已被其他进程复用。"
                "为避免打开无关进程，本次跳转已取消。").arg(pid),
            "process creation time mismatch");
        return;
    }

    // identityKey: Strictly locates the same process instance in the cache, not just any first item by PID.
    const std::string kIdentityKey = ks::process::buildProcessIdentityKey(
        pid,
        creationTime100ns);

    // cachedEntryIt: If the current cache still marks the target as exited, follow the historical state to reject opening.
    const auto kCachedEntryIt = cacheByIdentity_.find(kIdentityKey);
    if (kCachedEntryIt != cacheByIdentity_.end())
    {
        if (kCachedEntryIt->second.isExitedInLatestRound)
        {
            kRejectHistoricalTarget(
                QStringLiteral(
                    "该历史记录对应的原进程已退出。为避免 PID 复用后打开无关进程，本次跳转已取消。"),
                "cached process record is marked exited");
            return;
        }
        if (!kCachedEntryIt->second.isKernelOnlyInLatestRound)
        {
            showProcessDetailWindowForRecord(
                kIdentityKey,
                kCachedEntryIt->second.record);
            return;
        }
    }

    // queriedRecord: Construct a lightweight record when the cache is not overwritten but the real-time identity matches; fill in fields in the background for the detail page.
    ks::process::ProcessRecord queriedRecord{};
    queriedRecord.pid = pid;
    queriedRecord.creationTime100ns = creationTime100ns;
    queriedRecord.processName = ks::process::getProcessNameByPid(pid);
    if (queriedRecord.processName.empty())
    {
        queriedRecord.processName = "PID_" + std::to_string(pid);
    }
    showProcessDetailWindowForRecord(kIdentityKey, queriedRecord);
}

void ProcessDock::openProcessDetailsPlaceholder()
{
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 打开进程详细信息失败：当前没有选中进程。" << eol;
        QMessageBox::warning(this, "进程详细信息", "请先在表格中选中一个进程。");
        return;
    }
    if (kActionTargets.size() > 1U)
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 打开进程详细信息失败：详情窗口仅支持单进程, selectedCount="
            << kActionTargets.size()
            << eol;
        QMessageBox::information(this, "进程详细信息", "请只选中一个进程再打开详情窗口。");
        return;
    }

    // Do not synchronize and fill static fields before the details window is displayed:
    // - Legacy logic reads command line, tokens, and digital signatures on the UI thread;
    // - Signature verification and permission-restricted processes cause significant lag when opening process details.
    // - Use a list cache to open the window first, and fill in missing fields in the background within ProcessDetailWindow.
    ks::process::ProcessRecord detailRecord = kActionTargets.front().record;

    // identityKey: Used for the 'one process, one window' reuse logic.
    const std::string kIdentityKey = ks::process::buildProcessIdentityKey(
        detailRecord.pid,
        detailRecord.creationTime100ns);

    auto existingWindowIt = detailWindowByIdentity_.find(kIdentityKey);
    if (existingWindowIt != detailWindowByIdentity_.end() && existingWindowIt->second != nullptr)
    {
        existingWindowIt->second->updateBaseRecord(detailRecord);
        detailWindowLastSyncTimeByIdentity_[kIdentityKey] = std::chrono::steady_clock::now();
        existingWindowIt->second->show();
        existingWindowIt->second->raise();
        existingWindowIt->second->activateWindow();

        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 复用已存在进程详情窗口, pid=" << detailRecord.pid
            << ", identity=" << kIdentityKey
            << eol;
        return;
    }

    // Create a new independent window (not part of the Docking System; multiple instances can be opened in parallel).
    ProcessDetailWindow* detailWindow = new ProcessDetailWindow(detailRecord, nullptr);
    detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    detailWindowByIdentity_[kIdentityKey] = detailWindow;
    detailWindowLastSyncTimeByIdentity_[kIdentityKey] = std::chrono::steady_clock::now();

    // Remove from cache after the detail window is destroyed to prevent dangling pointers.
    connect(detailWindow, &QObject::destroyed, this, [this, kIdentityKey]() {
        detailWindowByIdentity_.erase(kIdentityKey);
        detailWindowLastSyncTimeByIdentity_.erase(kIdentityKey);
    });

    // "Go to parent process" signal from the detail window is handled here uniformly.
    connect(detailWindow, &ProcessDetailWindow::requestOpenProcessByPid, this, [this](const std::uint32_t parentPid) {
        openProcessDetailWindowByPid(parentPid);
    });
    connect(detailWindow, &ProcessDetailWindow::requestOpenHandleDockByPid, this, [this](const std::uint32_t targetPid) {
        const bool kInvokeOk = invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
        if (!kInvokeOk)
        {
            KLogEvent logEvent;
            warn << logEvent
                << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                << targetPid
                << eol;
        }
    });

    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 创建新的进程详情窗口, pid=" << detailRecord.pid
        << ", identity=" << kIdentityKey
        << eol;
}

void ProcessDock::openSelectedProcessHotkeyScanner()
{
    // Right-click context menu entry for 'Scan Process Hotkey' in the process list:
    // - Input: A single process action target frozen in the current right-click menu;
    // - Processing: Reuse the existing detail window cache if available; otherwise, create a new one, switch to the hotkey page, and trigger a scan.
    // - Returns: none. When batch selecting, show a prompt directly to avoid creating multiple detail windows and causing UI noise.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 扫描进程热键失败：当前没有选中进程。" << eol;
        QMessageBox::warning(this, QStringLiteral("扫描进程热键"), QStringLiteral("请先在表格中选中一个进程。"));
        return;
    }
    if (kActionTargets.size() > 1U)
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 扫描进程热键失败：仅支持单进程, selectedCount="
            << kActionTargets.size()
            << eol;
        QMessageBox::information(this, QStringLiteral("扫描进程热键"), QStringLiteral("请只选中一个进程再扫描热键。"));
        return;
    }

    ks::process::ProcessRecord detailRecord = kActionTargets.front().record;
    const std::string kIdentityKey = ks::process::buildProcessIdentityKey(
        detailRecord.pid,
        detailRecord.creationTime100ns);

    ProcessDetailWindow* detailWindow = nullptr;
    auto existingWindowIt = detailWindowByIdentity_.find(kIdentityKey);
    if (existingWindowIt != detailWindowByIdentity_.end() && existingWindowIt->second != nullptr)
    {
        detailWindow = existingWindowIt->second.data();
        detailWindow->updateBaseRecord(detailRecord);
        detailWindowLastSyncTimeByIdentity_[kIdentityKey] = std::chrono::steady_clock::now();
    }
    else
    {
        detailWindow = new ProcessDetailWindow(detailRecord, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindowByIdentity_[kIdentityKey] = detailWindow;
        detailWindowLastSyncTimeByIdentity_[kIdentityKey] = std::chrono::steady_clock::now();

        connect(detailWindow, &QObject::destroyed, this, [this, kIdentityKey]() {
            detailWindowByIdentity_.erase(kIdentityKey);
            detailWindowLastSyncTimeByIdentity_.erase(kIdentityKey);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenProcessByPid, this, [this](const std::uint32_t parentPid) {
            openProcessDetailWindowByPid(parentPid);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenHandleDockByPid, this, [this](const std::uint32_t targetPid) {
            const bool kInvokeOk = invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
            if (!kInvokeOk)
            {
                KLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                    << targetPid
                    << eol;
            }
        });
    }

    if (detailWindow == nullptr)
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 扫描进程热键失败：详情窗口创建失败。" << eol;
        QMessageBox::warning(this, QStringLiteral("扫描进程热键"), QStringLiteral("无法创建进程详细信息窗口。"));
        return;
    }

    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
    detailWindow->showHotkeyTabAndRefresh();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 打开进程热键扫描入口, pid="
        << detailRecord.pid
        << ", identity="
        << kIdentityKey
        << eol;
}

void ProcessDock::openSelectedProcessInjectionPage()
{
    // Right-click entry in the process list for 'DLL/Shellcode Injection':
    // - Input: A single process action target frozen in the current right-click menu;
    // - Processing: Reuse existing detail window cache; create a detail window if necessary, then switch to the 'Actions' page.
    // - Returns: none. When batch selecting, show a prompt directly to avoid creating multiple detail windows and causing UI noise.
    const std::vector<ProcessActionTarget> kActionTargets = selectedActionTargets();
    if (kActionTargets.empty())
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 打开 DLL/Shellcode 注入页失败：当前没有选中进程。" << eol;
        QMessageBox::warning(this, QStringLiteral("DLL/Shellcode 注入"), QStringLiteral("请先在表格中选中一个进程。"));
        return;
    }
    if (kActionTargets.size() > 1U)
    {
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDock] 打开 DLL/Shellcode 注入页失败：仅支持单进程, selectedCount="
            << kActionTargets.size()
            << eol;
        QMessageBox::information(this, QStringLiteral("DLL/Shellcode 注入"), QStringLiteral("请只选中一个进程再打开注入页。"));
        return;
    }

    ks::process::ProcessRecord detailRecord = kActionTargets.front().record;
    const std::string kIdentityKey = ks::process::buildProcessIdentityKey(
        detailRecord.pid,
        detailRecord.creationTime100ns);

    ProcessDetailWindow* detailWindow = nullptr;
    auto existingWindowIt = detailWindowByIdentity_.find(kIdentityKey);
    if (existingWindowIt != detailWindowByIdentity_.end() && existingWindowIt->second != nullptr)
    {
        detailWindow = existingWindowIt->second.data();
        detailWindow->updateBaseRecord(detailRecord);
        detailWindowLastSyncTimeByIdentity_[kIdentityKey] = std::chrono::steady_clock::now();
    }
    else
    {
        detailWindow = new ProcessDetailWindow(detailRecord, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindowByIdentity_[kIdentityKey] = detailWindow;
        detailWindowLastSyncTimeByIdentity_[kIdentityKey] = std::chrono::steady_clock::now();

        connect(detailWindow, &QObject::destroyed, this, [this, kIdentityKey]() {
            detailWindowByIdentity_.erase(kIdentityKey);
            detailWindowLastSyncTimeByIdentity_.erase(kIdentityKey);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenProcessByPid, this, [this](const std::uint32_t parentPid) {
            openProcessDetailWindowByPid(parentPid);
        });
        connect(detailWindow, &ProcessDetailWindow::requestOpenHandleDockByPid, this, [this](const std::uint32_t targetPid) {
            const bool kInvokeOk = invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
            if (!kInvokeOk)
            {
                KLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                    << targetPid
                    << eol;
            }
        });
    }

    if (detailWindow == nullptr)
    {
        KLogEvent logEvent;
        warn << logEvent << "[ProcessDock] 打开 DLL/Shellcode 注入页失败：详情窗口创建失败。" << eol;
        QMessageBox::warning(this, QStringLiteral("DLL/Shellcode 注入"), QStringLiteral("无法创建进程详细信息窗口。"));
        return;
    }

    connectDetailWindowNavigation(detailWindow);
    detailWindow->show();
    detailWindow->raise();
    detailWindow->activateWindow();
    detailWindow->showActionTab();

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDock] 打开 DLL/Shellcode 注入页入口, pid="
        << detailRecord.pid
        << ", identity="
        << kIdentityKey
        << eol;
}

void ProcessDock::showProcessDetailWindowForRecord(
    const std::string& identityKey,
    const ks::process::ProcessRecord& detailRecord)
{
    // existingWindowIt: Reuse only one detail window for the same PID + creation time.
    const auto kExistingWindowIt = detailWindowByIdentity_.find(identityKey);
    if (kExistingWindowIt != detailWindowByIdentity_.end() &&
        kExistingWindowIt->second != nullptr)
    {
        kExistingWindowIt->second->updateBaseRecord(detailRecord);
        detailWindowLastSyncTimeByIdentity_[identityKey] =
            std::chrono::steady_clock::now();
        kExistingWindowIt->second->show();
        kExistingWindowIt->second->raise();
        kExistingWindowIt->second->activateWindow();
        return;
    }

    // detailWindow: Missing static fields are filled by the window background to avoid blocking the UI navigation path.
    ProcessDetailWindow* const kDetailWindow =
        new ProcessDetailWindow(detailRecord, nullptr);
    kDetailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
    detailWindowByIdentity_[identityKey] = kDetailWindow;
    detailWindowLastSyncTimeByIdentity_[identityKey] =
        std::chrono::steady_clock::now();
    connect(
        kDetailWindow,
        &QObject::destroyed,
        this,
        [this, identityKey]()
        {
            detailWindowByIdentity_.erase(identityKey);
            detailWindowLastSyncTimeByIdentity_.erase(identityKey);
        });
    connect(
        kDetailWindow,
        &ProcessDetailWindow::requestOpenProcessByPid,
        this,
        [this](const std::uint32_t parentPid)
        {
            openProcessDetailWindowByPid(parentPid);
        });
    connect(
        kDetailWindow,
        &ProcessDetailWindow::requestOpenHandleDockByPid,
        this,
        [this](const std::uint32_t targetPid)
        {
            // invokeOk: delegates the request to jump the detail window's handle page to the main window.
            const bool kInvokeOk =
                invokeMainWindowPidSlot("focusHandleDockByPid", targetPid);
            if (!kInvokeOk)
            {
                KLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenHandleDockByPid 转发失败, pid="
                    << targetPid
                    << eol;
            }
        });
    connectDetailWindowNavigation(kDetailWindow);
    kDetailWindow->show();
    kDetailWindow->raise();
    kDetailWindow->activateWindow();
}

void ProcessDock::openProcessDetailWindowByPid(const std::uint32_t pid)
{
    // currentCreationTime100ns: Select the cached entry for the current PID precisely when the real-time identity query succeeds.
    std::uint64_t currentCreationTime100ns = 0U;

    // identityDetailText: Normal real-time table navigation does not pop up identity errors; used only to decide whether to fall back to cache.
    std::string identityDetailText;

    // identityQueryOk: Avoid exiting during the overlap period between old and new identities when successful.
    const bool kIdentityQueryOk = ks::process::queryProcessCreationTimeByPid(
        pid,
        &currentCreationTime100ns,
        &identityDetailText);
    if (kIdentityQueryOk)
    {
        // currentIdentityKey: Unique cache key corresponding to the real-time PID.
        const std::string kCurrentIdentityKey = ks::process::buildProcessIdentityKey(
            pid,
            currentCreationTime100ns);

        // currentCacheIt: Accepts only current process records that have not exited and are not kernel-reserved.
        const auto kCurrentCacheIt = cacheByIdentity_.find(kCurrentIdentityKey);
        if (kCurrentCacheIt != cacheByIdentity_.end() &&
            !kCurrentCacheIt->second.isExitedInLatestRound &&
            !kCurrentCacheIt->second.isKernelOnlyInLatestRound)
        {
            showProcessDetailWindowForRecord(
                kCurrentIdentityKey,
                kCurrentCacheIt->second.record);
            return;
        }

        // queriedRecord: Constructs a lightweight record using real-time identity when the cache has not yet been refreshed.
        ks::process::ProcessRecord queriedRecord{};
        queriedRecord.pid = pid;
        queriedRecord.creationTime100ns = currentCreationTime100ns;
        queriedRecord.processName = ks::process::getProcessNameByPid(pid);
        if (queriedRecord.processName.empty())
        {
            queriedRecord.processName = "PID_" + std::to_string(pid);
        }
        showProcessDetailWindowForRecord(kCurrentIdentityKey, queriedRecord);
        return;
    }

    // fallbackCacheEntry: When real-time querying is unavailable for protected processes, select the latest identity only from the non-expired cache.
    const CacheEntry* fallbackCacheEntry = nullptr;

    // fallbackIdentityKey: Synchronously saved with fallbackCacheEntry as its stable key.
    std::string fallbackIdentityKey;
    for (const auto& cachePair : cacheByIdentity_)
    {
        const CacheEntry& cacheEntry = cachePair.second;
        if (cacheEntry.record.pid != pid ||
            cacheEntry.isExitedInLatestRound ||
            cacheEntry.isKernelOnlyInLatestRound)
        {
            continue;
        }
        if (fallbackCacheEntry == nullptr ||
            cacheEntry.record.creationTime100ns >
                fallbackCacheEntry->record.creationTime100ns)
        {
            fallbackCacheEntry = &cacheEntry;
            fallbackIdentityKey = cachePair.first;
        }
    }
    if (fallbackCacheEntry != nullptr)
    {
        showProcessDetailWindowForRecord(
            fallbackIdentityKey,
            fallbackCacheEntry->record);
        return;
    }

    // queriedRecord: Retains compatibility for pure PID real-time entry; historical entries do not reach this fallback path.
    ks::process::ProcessRecord queriedRecord{};
    queriedRecord.pid = pid;
    queriedRecord.processName = ks::process::getProcessNameByPid(pid);
    if (queriedRecord.processName.empty())
    {
        queriedRecord.processName = "PID_" + std::to_string(pid);
    }
    const std::string kIdentityKey = ks::process::buildProcessIdentityKey(
        queriedRecord.pid,
        queriedRecord.creationTime100ns);
    showProcessDetailWindowForRecord(kIdentityKey, queriedRecord);
}

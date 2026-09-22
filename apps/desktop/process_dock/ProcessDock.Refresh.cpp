#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

void ProcessDock::requestAsyncRefresh(const bool forceRefresh)
{
    // Requirement: check Ctrl before each refresh; if pressed, skip this round (regardless of whether a forced refresh is requested).
    if ((::GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0)
    {
        KLogEvent logEvent;
        dbg << logEvent << "[ProcessDock] 检测到 Ctrl 按下，本轮刷新跳过。" << eol;
        return;
    }

    // If not a forced refresh, skip immediately if monitoring is paused or a refresh is in progress.
    if (!forceRefresh)
    {
        // Freeze periodic refresh while the context menu is visible to prevent bound items from becoming invalid after reconstruction.
        if (contextMenuVisible_)
        {
            KLogEvent logEvent;
            dbg << logEvent << "[ProcessDock] 右键菜单处于打开状态，本轮刷新跳过。" << eol;
            return;
        }

        if (!monitoringEnabled_ || refreshInProgress_)
        {
            KLogEvent logEvent;
            dbg << logEvent
                << "[ProcessDock] 跳过非强制刷新, monitoringEnabled=" << (monitoringEnabled_ ? "true" : "false")
                << ", refreshInProgress=" << (refreshInProgress_ ? "true" : "false")
                << eol;
            return;
        }

        // Background refresh/record constraint: 'Whether to continue refreshing'.
        // - Default behavior: stop refreshing when leaving the process list page.
        // - When checked, allow background enumeration to continue.
        // - 'Do not record history' only affects whether records are written, and should not block list refresh.
        if (!isProcessActivityRefreshAllowedNow())
        {
            KLogEvent logEvent;
            dbg << logEvent << "[ProcessDock] 跳过非强制刷新：进程页不可见且未启用后台保持刷新/记录。" << eol;
            updateProcessActivityStatusLabel();
            return;
        }
    }

    // Prevent concurrent task stacking even during forced refresh.
    if (refreshInProgress_)
    {
        KLogEvent logEvent;
        dbg << logEvent << "[ProcessDock] 跳过刷新：当前已有后台刷新任务在执行。" << eol;
        return;
    }
    refreshInProgress_ = true;

    // Copy the current cached snapshot to the background thread to avoid cross-thread read/write conflicts.
    const int kStrategyIndex = strategyCombo_->currentIndex();
    // Static detail budgeting is determined by whether columns requiring process opening are actually displayed, rather than being bound
    // to a specific view. Users must also complete these columns when manually adding command-line or description columns in any view.
    const bool kDetailModeEnabled = isStaticDetailIntensiveViewActive();
    const bool kQueryKernelProcessList =
        (kernelCompareCheck_ != nullptr && kernelCompareCheck_->isChecked()) ||
        (showKswordHiddenProcessCheck_ != nullptr && showKswordHiddenProcessCheck_->isChecked()) ||
        !hiddenProcessPidSet_.empty();
    const bool kIsFirstRefresh = cacheByIdentity_.empty();
    const int kStaticDetailFillBudget =
        kDetailModeEnabled
        ? (kIsFirstRefresh ? 96 : 48)   // Detailed view also enforces budget control to avoid UI jitter caused by a full static query in the first refresh.
        : (kIsFirstRefresh ? 8 : 4);    // Monitor view prioritizes speed with a smaller budget.
    // Collect bitmap on demand:
    // - Only incur extra handle/PDH costs for background processing of GDI objects, jobs, mitigation policies, and video memory columns when the user actually displays them;
    // - Under the default column layout, this value is 0, and the refresh overhead remains identical to before filling these columns.
    const std::uint32_t kDetailDemandFlags = currentProcessDetailDemandFlags();
    const std::uint32_t kCpuCount = logicalCpuCount_;
    auto previousCache = cacheByIdentity_;
    auto previousCounters = counterSampleByIdentity_;
    ensureProcessNetworkTrafficCaptureStarted();
    auto networkTrafficSnapshot = snapshotProcessNetworkTrafficCounters();
    // Resident in the same system-level CSwitch session only when the CPU core column is visible or the details window requires data.
    // Forced refresh: if triggered from a hidden page or when per-core data is not needed, do not secretly retain high-frequency sessions.
    const bool kCpuCoreUsageDemanded =
        isProcessColumnVisible(TableColumn::kCpuCore) ||
        std::any_of(
            detailWindowByIdentity_.cbegin(),
            detailWindowByIdentity_.cend(),
            [](const auto& detailWindowPair)
            {
                return detailWindowPair.second != nullptr;
            });
    const bool kCpuCoreCaptureAllowed =
        isProcessActivityRefreshAllowedNow() && kCpuCoreUsageDemanded;
    if (kCpuCoreCaptureAllowed)
    {
        ensureCpuCoreUsageCaptureStarted();
    }
    else if (cpuCoreUsageCaptureStarted_)
    {
        stopCpuCoreUsageCapture();
    }
    const std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> kCpuCoreUsageService =
        kCpuCoreCaptureAllowed ? cpuCoreUsageService_ : nullptr;
    const std::chrono::steady_clock::time_point kCpuCoreSnapshotNow =
        std::chrono::steady_clock::now();
    const bool kCpuCoreSnapshotDue =
        kCpuCoreUsageService != nullptr &&
        (lastCpuCoreUsageSnapshotTime_.time_since_epoch().count() == 0 ||
            std::chrono::duration_cast<std::chrono::milliseconds>(
                kCpuCoreSnapshotNow - lastCpuCoreUsageSnapshotTime_).count() >=
                kCpuCoreSnapshotMinimumIntervalMilliseconds);
    if (kCpuCoreSnapshotDue)
    {
        // Update the timestamp upon dispatch; since the refresh task is mutually exclusive, this prevents concurrent generation of duplicate per-core matrices.
        lastCpuCoreUsageSnapshotTime_ = kCpuCoreSnapshotNow;
    }
    const std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> kPreviousCpuCoreUsageSnapshot =
        latestCpuCoreUsageSnapshot_;

    // ticket is used to discard expired results (to prevent out-of-order overwrites).
    const std::uint64_t kLocalTicket = ++refreshTicket_;
    lastRefreshStartTime_ = std::chrono::steady_clock::now();
    QPointer<ProcessDock> guard(this);

    {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 进程监视刷新开始, ticket=" << kLocalTicket
            << ", force=" << (forceRefresh ? "true" : "false")
            << ", strategy=" << strategyToText(toStrategy(kStrategyIndex))
            << ", detailMode=" << (kDetailModeEnabled ? "true" : "false")
            << ", kernelCompare=" << (kQueryKernelProcessList ? "true" : "false")
            << ", staticBudget=" << kStaticDetailFillBudget
            << ", cacheSize=" << previousCache.size()
            << ", uiTableIntervalMs=" << tableRefreshIntervalMillisecondsFromInput()
            << ", sampleIntervalMs=" << refreshIntervalMillisecondsFromInput()
            << eol;
    }

    // QRunnable + thread pool: satisfies 'asynchronous refresh without blocking the GUI'.
    // Note: forceUiRefresh must be saved as a local value before entering the background lambda;
    // Otherwise, the inner QueuedConnection lambda cannot reference the parameters of requestAsyncRefresh within the worker thread.
    const bool kForceUiRefresh = forceRefresh;
    QRunnable* backgroundTask = QRunnable::create([
        guard,
        kLocalTicket,
        kStrategyIndex,
        kDetailModeEnabled,
        kQueryKernelProcessList,
        kStaticDetailFillBudget,
        kDetailDemandFlags,
        kCpuCount,
        kForceUiRefresh,
        previousCache = std::move(previousCache),
        previousCounters = std::move(previousCounters),
        networkTrafficSnapshot = std::move(networkTrafficSnapshot),
        kCpuCoreUsageService,
        kCpuCoreSnapshotDue,
        kPreviousCpuCoreUsageSnapshot]() mutable {
        // Constructs a complete PID/TID×core snapshot in the worker thread first, ensuring ETW callback lock contention does not block the GUI event loop.
        std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> cpuCoreUsageSnapshot =
            kPreviousCpuCoreUsageSnapshot;
        if (kCpuCoreUsageService != nullptr && kCpuCoreSnapshotDue)
        {
            // Even if the asynchronous Start has not completed, obtain a stale snapshot with processor topology to render gray slots in the UI instead of fake 0%.
            cpuCoreUsageSnapshot = std::make_shared<ks::process::CpuCoreUsageSnapshot>(
                kCpuCoreUsageService->snapshotAndReset());
        }

        ProcessDock::RefreshResult refreshResult = ProcessDock::buildRefreshResult(
            kStrategyIndex,
            kDetailModeEnabled,
            kQueryKernelProcessList,
            kStaticDetailFillBudget,
            kDetailDemandFlags,
            kLocalTicket,
            previousCache,
            previousCounters,
            networkTrafficSnapshot,
            kCpuCount);
        refreshResult.cpuCoreUsageSnapshot = std::move(cpuCoreUsageSnapshot);

        if (guard == nullptr)
        {
            return;
        }

        // Results are returned to the main thread via a queued connection to update the UI.
        QMetaObject::invokeMethod(guard, [
            guard,
            kLocalTicket,
            refreshResult = std::move(refreshResult),
            kForceUiRefresh]() mutable {
            if (guard == nullptr)
            {
                return;
            }

            // Accept only results from the latest ticket; discard older results immediately.
            if (kLocalTicket < guard->refreshTicket_)
            {
                guard->refreshInProgress_ = false;
                return;
            }

            guard->applyRefreshResult(std::move(refreshResult), kForceUiRefresh);
            guard->refreshInProgress_ = false;
        }, Qt::QueuedConnection);
    });

    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

void ProcessDock::applyRefreshResult(RefreshResult refreshResult, const bool forceUiRefresh)
{
    // Background snapshots not only rebuild the model but also replace the process cache used for menu action queries first.
    // Defer the entire commit when the menu is open to avoid brief mismatches between old rows and new cache.
    if (ks::ui::isTableUiCommitBlockedByContextMenu({processTable_}))
    {
        auto deferredResult = std::make_shared<RefreshResult>(std::move(refreshResult));
        const QPointer<ProcessDock> kSafeThis(this);
        if (ks::ui::deferTableUiCommitIfContextMenuOpen(
                this,
                QStringLiteral("process-main-refresh-result"),
                {processTable_},
                [kSafeThis, deferredResult, forceUiRefresh]() mutable
                {
                    if (!kSafeThis.isNull())
                    {
                        kSafeThis->applyRefreshResult(std::move(*deferredResult), forceUiRefresh);
                    }
                }))
        {
            return;
        }
        refreshResult = std::move(*deferredResult);
    }

    // Calculate main thread observation duration for the 'Refresh Status' tag and log output.
    const auto kNowTime = std::chrono::steady_clock::now();
    const auto kElapsedMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kNowTime - lastRefreshStartTime_).count());

    restorePersistedAffinityForNewProcesses(refreshResult);

    // Per-core snapshots and the current process cache come from the same ticket; stale results arriving after a pause must not resurrect the last frame.
    const std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> kPreviousCpuCoreSnapshot =
        latestCpuCoreUsageSnapshot_;
    if (monitoringEnabled_ &&
        cpuCoreUsageCaptureDesired_->load(std::memory_order_acquire))
    {
        latestCpuCoreUsageSnapshot_ = std::move(refreshResult.cpuCoreUsageSnapshot);
    }
    else
    {
        latestCpuCoreUsageSnapshot_.reset();
    }
    const bool kCpuCoreSnapshotChanged =
        kPreviousCpuCoreSnapshot != latestCpuCoreUsageSnapshot_;

    // Sync the latest process data to open detail windows (if the corresponding process still exists).
    // Performance policy:
    // 1) Synchronize only 'visible and non-minimized' detail windows.
    // 2) Minor changes are absorbed by the throttler to avoid triggering the heavy parsing chain on every refresh cycle.
    const std::chrono::milliseconds kDetailWindowSyncInterval(1500);
    for (auto windowIt = detailWindowByIdentity_.begin(); windowIt != detailWindowByIdentity_.end();)
    {
        if (windowIt->second == nullptr)
        {
            detailWindowLastSyncTimeByIdentity_.erase(windowIt->first);
            windowIt = detailWindowByIdentity_.erase(windowIt);
            continue;
        }

        const QPointer<ProcessDetailWindow>& detailWindow = windowIt->second;
        if (!detailWindow->isVisible() || detailWindow->isMinimized())
        {
            ++windowIt;
            continue;
        }

        const auto kNextCacheIt = refreshResult.nextCache.find(windowIt->first);
        if (kNextCacheIt == refreshResult.nextCache.end())
        {
            ++windowIt;
            continue;
        }

        const auto kPreviousCacheIt = cacheByIdentity_.find(windowIt->first);
        const bool kHasSignificantChange =
            (kPreviousCacheIt == cacheByIdentity_.end()) ||
            hasDetailWindowSignificantChange(kPreviousCacheIt->second.record, kNextCacheIt->second.record);

        const auto kLastSyncIt = detailWindowLastSyncTimeByIdentity_.find(windowIt->first);
        const bool kReachPeriodicSyncTime =
            (kLastSyncIt == detailWindowLastSyncTimeByIdentity_.end()) ||
            (std::chrono::duration_cast<std::chrono::milliseconds>(kNowTime - kLastSyncIt->second) >= kDetailWindowSyncInterval);

        if (kHasSignificantChange || kReachPeriodicSyncTime)
        {
            detailWindow->updateBaseRecord(kNextCacheIt->second.record);
            syncCpuCoreUsageToDetailWindow(detailWindow, kNextCacheIt->second.record);
            detailWindowLastSyncTimeByIdentity_[windowIt->first] = kNowTime;
        }
        ++windowIt;
    }

    // Replace the cache with the new result; table repainting is throttled by an independent 'list refresh (s)' to avoid overwhelming the UI with high-frequency sampling.
    cacheByIdentity_ = std::move(refreshResult.nextCache);
    counterSampleByIdentity_ = std::move(refreshResult.nextCounters);
    pruneProcessNetworkTrafficCounters();

    // Immediately dispatch background icon queries for all process images on every refresh cycle; the table no longer waits for an idle scroll period.
    queueProcessIconExtractionsForCurrentProcesses();

    appendProcessActivitySample();
    if (isProcessActivityTableSnapshotActive())
    {
        rebuildProcessActivityTableSnapshotRecords();
    }
    const bool kProcessTableRebuilt = shouldRebuildProcessTableForRefresh(forceUiRefresh);
    if (kProcessTableRebuilt)
    {
        rebuildTable();
        lastProcessTableRebuildTime_ = kNowTime;
    }
    else if (kCpuCoreSnapshotChanged &&
        processTable_ != nullptr &&
        processTable_->viewport() != nullptr)
    {
        // Per-core snapshots are independent of the full-table 2-second throttling: only the visible rectangle of the CPU column is repainted, without touching other columns or model rows.
        const int kCpuColumn = toColumnIndex(TableColumn::kCpuCore);
        const int kCpuColumnLeft = processTable_->columnViewportPosition(kCpuColumn);
        const int kCpuColumnWidth = processTable_->columnWidth(kCpuColumn);
        const QRect kCpuViewportRect(
            kCpuColumnLeft,
            0,
            kCpuColumnWidth,
            processTable_->viewport()->height());
        processTable_->viewport()->update(
            kCpuViewportRect.intersected(processTable_->viewport()->rect()));
    }
    if (sideTabWidget_ != nullptr && sideTabWidget_->currentWidget() == threadPage_)
    {
        requestAsyncThreadRefresh(false);
    }

    // Output detailed refresh log for subsequent performance and correctness troubleshooting.
    {
        KLogEvent logEvent;
        info << logEvent
            << "[ProcessDock] 刷新完成, elapsedMs(main)=" << kElapsedMs
            << ", elapsedMs(worker)=" << refreshResult.workerElapsedMs
            << ", strategySelected=" << strategyToText(refreshResult.selectedStrategy)
            << ", strategyActual=" << strategyToText(refreshResult.actualStrategy)
            << ", enumerated=" << refreshResult.enumeratedCount
            << ", reused=" << refreshResult.reusedProcessCount
            << ", new=" << refreshResult.newProcessCount
            << ", exitedHold=" << refreshResult.exitedProcessCount
            << ", staticFilled=" << refreshResult.staticFilledCount
            << ", staticDeferred=" << refreshResult.staticDeferredCount
            << ", imagePathFilled=" << refreshResult.imagePathFilledCount
            << ", kernelCompareEnabled=" << (refreshResult.kernelCompareEnabled ? "true" : "false")
            << ", kernelQuerySucceeded=" << (refreshResult.kernelQuerySucceeded ? "true" : "false")
            << ", kernelEnumerated=" << refreshResult.kernelEnumeratedCount
            << ", kernelOnly=" << refreshResult.kernelOnlyCount
            << ", kernelDetail=" << refreshResult.kernelQueryDetailText
            << ", cacheNow=" << cacheByIdentity_.size()
            << ", uiRebuildForced=" << (forceUiRefresh ? "true" : "false")
            << eol;
    }
}

void ProcessDock::restorePersistedAffinityForNewProcesses(RefreshResult& refreshResult)
{
    // currentIdentityKeys: Used to clean up completion and backoff records for processes that have exited.
    std::unordered_set<std::string> currentIdentityKeys;
    currentIdentityKeys.reserve(refreshResult.nextCache.size());

    // nowTime: Monotonic time shared across the entire restoration round to ensure consistent backoff judgment within the same refresh cycle.
    const std::chrono::steady_clock::time_point kNowTime = std::chrono::steady_clock::now();

    // restoredRuleCount: Counts the number of persistent rules successfully applied in this round.
    std::size_t restoredRuleCount = 0U;

    // failedRuleCount: Count of rules that failed after the actual attempt in this round.
    std::size_t failedRuleCount = 0U;

    for (const auto& cachePair : refreshResult.nextCache)
    {
        // identityKey: A stable process instance identifier composed of PID and creation time.
        const std::string& identityKey = cachePair.first;

        // cacheEntry: Process cache entry obtained in the current refresh round.
        const CacheEntry& cacheEntry = cachePair.second;
        currentIdentityKeys.insert(identityKey);
        if (cacheEntry.isExitedInLatestRound || cacheEntry.isKernelOnlyInLatestRound ||
            cacheEntry.record.pid == 0U || cacheEntry.record.imagePath.empty() ||
            affinityRestoreCompletedIdentityKeys_.find(identityKey) !=
                affinityRestoreCompletedIdentityKeys_.end())
        {
            continue;
        }

        // retryIt: If the previous restoration failed, used to determine if the retry time has arrived for this round.
        const auto kRetryIt = affinityRestoreRetryByIdentity_.find(identityKey);
        if (kRetryIt != affinityRestoreRetryByIdentity_.end() &&
            kNowTime < kRetryIt->second.nextAttemptTime)
        {
            continue;
        }

        // ruleFound: Distinguishes between 'no rule found' and read/apply failure to avoid misrecording failure as success.
        bool ruleFound = false;

        // detailText: Diagnostic information for registry reads, handle opens, or affinity settings.
        std::string detailText;

        // restoreOk: true only if both rule reading and application were successful.
        const bool kRestoreOk = ks::process::restorePersistedProcessAffinityRule(
            static_cast<DWORD>(cacheEntry.record.pid),
            cacheEntry.record.imagePath,
            &ruleFound,
            &detailText);

        // Complete accounting when successful and no rule is found; do not re-query the same process instance.
        if (kRestoreOk && !ruleFound)
        {
            affinityRestoreCompletedIdentityKeys_.insert(identityKey);
            affinityRestoreRetryByIdentity_.erase(identityKey);
            continue;
        }

        // restoreEvent: Ensures that each actual restoration and its diagnostic information share a single traceable log event.
        KLogEvent restoreEvent;
        (kRestoreOk ? info : warn) << restoreEvent
            << "[ProcessDock] persisted CPU affinity restore, pid=" << cacheEntry.record.pid
            << ", imagePath=" << cacheEntry.record.imagePath
            << ", ok=" << (kRestoreOk ? "true" : "false")
            << ", detail=" << (detailText.empty() ? "none" : detailText) << eol;
        if (kRestoreOk)
        {
            affinityRestoreCompletedIdentityKeys_.insert(identityKey);
            affinityRestoreRetryByIdentity_.erase(identityKey);
            ++restoredRuleCount;
        }
        else
        {
            // retryState: Stores the consecutive failure count and next retry time for this process instance.
            AffinityRestoreRetryState& retryState =
                affinityRestoreRetryByIdentity_[identityKey];
            if (retryState.consecutiveFailureCount < std::numeric_limits<std::uint32_t>::max())
            {
                ++retryState.consecutiveFailureCount;
            }

            // retryDelay: Exponential backoff duration with an upper limit corresponding to the failure count.
            const std::chrono::milliseconds kRetryDelay =
                affinityRestoreRetryDelay(retryState.consecutiveFailureCount);
            retryState.nextAttemptTime = kNowTime + kRetryDelay;

            // retryEvent: Log that automatic recovery will continue and the wait time until the next allowed attempt.
            KLogEvent retryEvent;
            warn << retryEvent
                << "[ProcessDock] persisted CPU affinity restore will retry, pid="
                << cacheEntry.record.pid
                << ", failureCount=" << retryState.consecutiveFailureCount
                << ", retryAfterMs=" << kRetryDelay.count()
                << eol;
            ++failedRuleCount;
        }
    }

    // Clear completion records after process exit to ensure independent evaluation for future instances that reuse the PID but have a different creation time.
    for (auto it = affinityRestoreCompletedIdentityKeys_.begin();
         it != affinityRestoreCompletedIdentityKeys_.end();)
    {
        if (currentIdentityKeys.find(*it) == currentIdentityKeys.end())
        {
            it = affinityRestoreCompletedIdentityKeys_.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // Synchronously clean up failed backoff states for exited processes to prevent accumulation of invalid identities over long runtimes.
    for (auto it = affinityRestoreRetryByIdentity_.begin();
         it != affinityRestoreRetryByIdentity_.end();)
    {
        if (currentIdentityKeys.find(it->first) == currentIdentityKeys.end())
        {
            it = affinityRestoreRetryByIdentity_.erase(it);
        }
        else
        {
            ++it;
        }
    }

    if (restoredRuleCount != 0U || failedRuleCount != 0U)
    {
        KLogEvent restoreSummaryEvent;
        (failedRuleCount == 0U ? info : warn) << restoreSummaryEvent
            << "[ProcessDock] persisted CPU affinity restore summary, restored=" << restoredRuleCount
            << ", failed=" << failedRuleCount << eol;
    }
}

bool ProcessDock::shouldRebuildProcessTableForRefresh(const bool forceUiRefresh) const
{
    // Force refresh, historical snapshot table, and initial display must trigger immediate redraw.
    if (forceUiRefresh || isProcessActivityTableSnapshotActive() || lastProcessTableRebuildTime_.time_since_epoch().count() == 0)
    {
        return true;
    }

    // Non-forced background monitoring is throttled by independent UI intervals to avoid rebuilding the entire process table during high-frequency sampling.
    const int kIntervalMs = tableRefreshIntervalMillisecondsFromInput();
    const auto kElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - lastProcessTableRebuildTime_).count();
    return kElapsedMs >= kIntervalMs;
}

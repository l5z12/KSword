#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

QObject* ProcessDock::mainWindowActionReceiver() const
{
    if (mainWindowActionReceiver_ != nullptr)
    {
        return mainWindowActionReceiver_.data();
    }
    return parent();
}

bool ProcessDock::invokeMainWindowPidSlot(const char* methodName, const std::uint32_t pid) const
{
    QObject* receiver = mainWindowActionReceiver();
    if (receiver == nullptr)
    {
        return false;
    }

    return QMetaObject::invokeMethod(
        receiver,
        methodName,
        Qt::QueuedConnection,
        Q_ARG(quint32, static_cast<quint32>(pid)));
}

void ProcessDock::ensureProcessNetworkTrafficCaptureStarted()
{
    // ensureProcessNetworkTrafficCaptureStarted：
    // - Inputs: None;
    // - Processing: Lazily create the internal ETW accumulator; in the background, record TCP/UDP bytes sent/received by PID only.
    // - Returns: None. On failure, does not fall back to the Raw Socket scheme; the process table retains existing differential results.
    if (processNetworkTrafficCaptureStarted_)
    {
        return;
    }
    processNetworkTrafficCaptureStarted_ = true;

    if (processNetworkTrafficService_ == nullptr)
    {
        processNetworkTrafficService_ = std::make_unique<ks::network::ProcessNetworkEtwMonitor>();
    }

    const bool kStarted = processNetworkTrafficService_->start();

    // Same as above: a single source text line per entry; the failure branch uses %1 to carry the detail.
    KLogEvent logEvent;
    if (kStarted)
    {
        info << logEvent << "[ProcessDock] 进程网络吞吐 ETW 采集器启动成功" << eol;
    }
    else
    {
        warn << logEvent
            << QStringLiteral("[ProcessDock] 进程网络吞吐 ETW 采集器启动失败, detail=%1")
                .arg(QString::fromStdString(processNetworkTrafficService_->lastErrorText()))
                .toStdString()
            << eol;
    }
}

void ProcessDock::stopProcessNetworkTrafficCapture()
{
    // stopProcessNetworkTrafficCapture：
    // - Inputs: None;
    // - Processing: Stop the internal ETW session to prevent accumulation after pause or destruction.
    // - Returns: Nothing.
    if (processNetworkTrafficService_ != nullptr)
    {
        processNetworkTrafficService_->stop();
    }
    processNetworkTrafficCaptureStarted_ = false;
}

void ProcessDock::ensureCpuCoreUsageCaptureStarted()
{
    // First record the desired state: even if a new capture cannot start immediately while Stop is in progress, the completion callback can still restore the same instance based on this.
    cpuCoreUsageCaptureDesired_->store(true, std::memory_order_release);
    // Prevent creating a new instance while an old session is still asynchronously stopping/joining, ensuring the process page always has at most one CSwitch session.
    if (cpuCoreUsageCaptureStarted_ || cpuCoreUsageStopInProgress_)
    {
        return;
    }
    cpuCoreUsageCaptureStarted_ = true;
    if (cpuCoreUsageService_ == nullptr)
    {
        cpuCoreUsageService_ =
            std::make_shared<ks::process::ProcessCpuCoreEtwMonitor>();
    }

    // StartTrace/OpenTrace are executed only once, but are moved to the global worker thread to avoid blocking the GUI when the ETW service responds slowly.
    const std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> kCpuCoreService =
        cpuCoreUsageService_;
    const std::shared_ptr<std::atomic_bool> kCaptureDesired =
        cpuCoreUsageCaptureDesired_;
    QRunnable* startTask = QRunnable::create([kCpuCoreService, kCaptureDesired]()
    {
        const bool kStarted = kCpuCoreService->start();
        if (kStarted && !kCaptureDesired->load(std::memory_order_acquire))
        {
            // Immediately perform background cleanup if the user pauses before startup completes, avoiding brief orphaned high-frequency sessions.
            kCpuCoreService->stop();
        }
        // Write the entire sentence as a single source text (failure branch includes %1):
        // - The notification card and log panel look up source_translations by full line; fragmented content can never match the entries correctly.
        // - %1 is captured via template matching; detail is passed through as-is and not translated.
        KLogEvent logEvent;
        if (kStarted)
        {
            info << logEvent
                << "[ProcessDock] 单系统会话 CSwitch 逐核心 CPU 采集器启动成功"
                << eol;
        }
        else
        {
            warn << logEvent
                << QStringLiteral("[ProcessDock] 单系统会话 CSwitch 逐核心 CPU 采集器启动失败, detail=%1")
                    .arg(QString::fromStdString(kCpuCoreService->lastErrorText()))
                    .toStdString()
                << eol;
        }
    });
    startTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(startTask);
}

void ProcessDock::stopCpuCoreUsageCapture()
{
    // UI immediately releases the latest matrix; StopTrace + consumer join are handled by the background thread so the pause button does not block the UI.
    latestCpuCoreUsageSnapshot_.reset();
    lastCpuCoreUsageSnapshotTime_ = {};
    cpuCoreUsageCaptureDesired_->store(false, std::memory_order_release);
    if (processTable_ != nullptr && processTable_->viewport() != nullptr)
    {
        // Immediately clear the previous frame's fan chart in the CPU column after pausing, without waiting for scrolling, exposure, or the next full table refresh.
        const int kCpuColumn = toColumnIndex(TableColumn::kCpuCore);
        const QRect kCpuViewportRect(
            processTable_->columnViewportPosition(kCpuColumn),
            0,
            processTable_->columnWidth(kCpuColumn),
            processTable_->viewport()->height());
        processTable_->viewport()->update(
            kCpuViewportRect.intersected(processTable_->viewport()->rect()));
    }
    cpuCoreUsageCaptureStarted_ = false;
    if (cpuCoreUsageService_ == nullptr || cpuCoreUsageStopInProgress_)
    {
        return;
    }

    cpuCoreUsageStopInProgress_ = true;
    // Always retain and reuse the same service object; even after recovery following Stop, invoke the same instance. Never create a second session.
    const std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> kCpuCoreService =
        cpuCoreUsageService_;
    const QPointer<ProcessDock> kSafeThis(this);
    QRunnable* stopTask = QRunnable::create([kSafeThis, kCpuCoreService]()
    {
        kCpuCoreService->stop();
        if (kSafeThis.isNull())
        {
            return;
        }

        QMetaObject::invokeMethod(
            kSafeThis,
            [kSafeThis]()
            {
                if (kSafeThis.isNull())
                {
                    return;
                }
                kSafeThis->cpuCoreUsageStopInProgress_ = false;
                if (kSafeThis->cpuCoreUsageCaptureDesired_->load(std::memory_order_acquire))
                {
                    // Restore the unique system-level session if the user re-enters the refresh-allowed state before Stop completes.
                    kSafeThis->ensureCpuCoreUsageCaptureStarted();
                }
            },
            Qt::QueuedConnection);
    });
    stopTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(stopTask);
}

void ProcessDock::syncCpuCoreUsageToDetailWindow(
    ProcessDetailWindow* const detailWindow,
    const ks::process::ProcessRecord& processRecord) const
{
    if (detailWindow == nullptr)
    {
        return;
    }

    ProcessDetailWindow::CpuCoreViewSample viewSample;
    viewSample.processSystemPercent = processRecord.cpuPercent;
    viewSample.processCoreEquivalentPercent = processRecord.cpuCorePercent;
    const std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> kCpuCoreSnapshot =
        latestCpuCoreUsageSnapshot_;
    if (kCpuCoreSnapshot == nullptr)
    {
        viewSample.diagnosticText = ks::i18n::sourceText(
            QStringLiteral("CSwitch monitor has not started"));
        detailWindow->setCpuCoreViewSample(std::move(viewSample));
        return;
    }

    viewSample.monitorRunning = kCpuCoreSnapshot->monitorRunning;
    viewSample.sampleReady = kCpuCoreSnapshot->sampleReady;
    viewSample.dataLossDetected = kCpuCoreSnapshot->dataLossDetected;
    viewSample.eventsLost = kCpuCoreSnapshot->eventsLost;
    viewSample.contextSwitchEvents = kCpuCoreSnapshot->contextSwitchEvents;
    viewSample.diagnosticText = ks::i18n::sourceText(
        QString::fromStdString(kCpuCoreSnapshot->diagnosticText));

    const auto kProcessUsageIt =
        kCpuCoreSnapshot->processUsageByPid.find(processRecord.pid);
    const ks::process::CpuCoreUsageSeries* const kProcessUsage =
        kProcessUsageIt != kCpuCoreSnapshot->processUsageByPid.end()
        ? &kProcessUsageIt->second
        : nullptr;
    viewSample.processCores.reserve(kCpuCoreSnapshot->processors.size());
    for (std::size_t processorIndex = 0;
         processorIndex < kCpuCoreSnapshot->processors.size();
         ++processorIndex)
    {
        const ks::process::EtwLogicalProcessorCoordinate& coordinate =
            kCpuCoreSnapshot->processors[processorIndex];
        ProcessDetailWindow::CpuCoreValue coreValue;
        coreValue.processorIndex = coordinate.processorIndex;
        coreValue.group = coordinate.group;
        coreValue.number = coordinate.number;
        coreValue.sampleReady =
            processorIndex < kCpuCoreSnapshot->sampleReadyByProcessor.size() &&
            kCpuCoreSnapshot->sampleReadyByProcessor[processorIndex];
        if (kProcessUsage != nullptr &&
            processorIndex < kProcessUsage->percentByProcessor.size())
        {
            coreValue.percent = kProcessUsage->percentByProcessor[processorIndex];
        }
        viewSample.processCores.push_back(coreValue);
    }

    std::unordered_set<std::uint32_t> populatedThreadIds;
    populatedThreadIds.reserve(kCpuCoreSnapshot->threadUsageByIdentity.size());
    for (const auto& threadUsagePair : kCpuCoreSnapshot->threadUsageByIdentity)
    {
        const ks::process::CpuCoreUsageSeries& threadUsage = threadUsagePair.second;
        if (threadUsage.processId != processRecord.pid || threadUsage.threadId == 0)
        {
            continue;
        }

        ProcessDetailWindow::ThreadCpuCoreValue threadValue;
        threadValue.threadId = threadUsage.threadId;
        threadValue.cpuPercent = threadUsage.coreEquivalentPercent;
        threadValue.cores.reserve(viewSample.processCores.size());
        for (std::size_t processorIndex = 0;
             processorIndex < viewSample.processCores.size();
             ++processorIndex)
        {
            ProcessDetailWindow::CpuCoreValue coreValue = viewSample.processCores[processorIndex];
            coreValue.percent = processorIndex < threadUsage.percentByProcessor.size()
                ? threadUsage.percentByProcessor[processorIndex]
                : 0.0;
            threadValue.cores.push_back(coreValue);
        }
        viewSample.threads.push_back(std::move(threadValue));
        populatedThreadIds.insert(threadUsage.threadId);
    }

    // During lifecycle rundown, live threads known to exist but not scheduled in this interval are retained as 0% to prevent
    // the thread matrix from listing only "just-run" threads, which could mislead users into thinking threads have exited.
    for (const std::uint64_t kIdentity : kCpuCoreSnapshot->liveThreadIdentities)
    {
        const std::uint32_t kProcessId = static_cast<std::uint32_t>(kIdentity >> 32U);
        const std::uint32_t kThreadId = static_cast<std::uint32_t>(kIdentity & 0xffffffffULL);
        if (kProcessId != processRecord.pid ||
            kThreadId == 0 ||
            populatedThreadIds.find(kThreadId) != populatedThreadIds.end())
        {
            continue;
        }

        ProcessDetailWindow::ThreadCpuCoreValue threadValue;
        threadValue.threadId = kThreadId;
        threadValue.cores = viewSample.processCores;
        for (ProcessDetailWindow::CpuCoreValue& coreValue : threadValue.cores)
        {
            coreValue.percent = 0.0;
        }
        viewSample.threads.push_back(std::move(threadValue));
    }
    std::sort(
        viewSample.threads.begin(),
        viewSample.threads.end(),
        [](const ProcessDetailWindow::ThreadCpuCoreValue& left,
           const ProcessDetailWindow::ThreadCpuCoreValue& right)
        {
            if (left.cpuPercent != right.cpuPercent)
            {
                return left.cpuPercent > right.cpuPercent;
            }
            return left.threadId < right.threadId;
        });
    detailWindow->setCpuCoreViewSample(std::move(viewSample));
}

void ProcessDock::pruneProcessNetworkTrafficCounters()
{
    // Retain only currently live PIDs to prevent the packet capture accumulation table from growing indefinitely with process creation/exit counts.
    std::unordered_set<std::uint32_t> livePidSet;
    livePidSet.reserve(cacheByIdentity_.size());
    for (const auto& cachePair : cacheByIdentity_)
    {
        if (!cachePair.second.isExitedInLatestRound)
        {
            livePidSet.insert(cachePair.second.record.pid);
        }
    }

    if (processNetworkTrafficService_ != nullptr)
    {
        processNetworkTrafficService_->pruneCounters(livePidSet);
    }
}

std::unordered_map<std::uint32_t, ProcessDock::NetworkTrafficCounters>
ProcessDock::snapshotProcessNetworkTrafficCounters() const
{
    // snapshotProcessNetworkTrafficCounters：
    // - Inputs: None;
    // - Processing: Request a snapshot of current PID network cumulative bytes from the ETW accumulator.
    // - Returns: An independent snapshot safe for the refresh thread to read.
    std::unordered_map<std::uint32_t, NetworkTrafficCounters> snapshot;
    if (processNetworkTrafficService_ == nullptr)
    {
        return snapshot;
    }

    const auto kEtwSnapshot = processNetworkTrafficService_->snapshotCounters();
    snapshot.reserve(kEtwSnapshot.size());
    for (const auto& [processId, counters] : kEtwSnapshot)
    {
        snapshot.emplace(processId, NetworkTrafficCounters{ counters.rxBytes, counters.txBytes });
    }
    return snapshot;
}

bool ProcessDock::invokeMainWindowPidListSlot(const char* methodName, const QString& pidListText) const
{
    QObject* receiver = mainWindowActionReceiver();
    if (receiver == nullptr || pidListText.trimmed().isEmpty())
    {
        return false;
    }
    return QMetaObject::invokeMethod(
        receiver,
        methodName,
        Qt::QueuedConnection,
        Q_ARG(QString, pidListText));
}

void ProcessDock::connectDetailWindowNavigation(ProcessDetailWindow* detailWindow)
{
    if (detailWindow == nullptr)
    {
        return;
    }
    if (monitoringEnabled_)
    {
        // Start the first sampling interval as soon as the detail window appears to avoid an extra wait after the user navigates to the CPU core page.
        ensureCpuCoreUsageCaptureStarted();
    }
    synchronizeDetailWindowPerformanceHistory(detailWindow, detailWindow->identityKey());
    const auto kCoreRecordIt = cacheByIdentity_.find(detailWindow->identityKey());
    if (kCoreRecordIt != cacheByIdentity_.end())
    {
        syncCpuCoreUsageToDetailWindow(detailWindow, kCoreRecordIt->second.record);
    }
    else
    {
        ks::process::ProcessRecord fallbackRecord{};
        fallbackRecord.pid = detailWindow->pid();
        syncCpuCoreUsageToDetailWindow(detailWindow, fallbackRecord);
    }
    connect(detailWindow, &ProcessDetailWindow::requestOpenMemoryDockByPid, this,
        [this](const std::uint32_t targetPid) {
            (void)invokeMainWindowPidSlot("focusMemoryDockByPid", targetPid);
        });
    connect(detailWindow, &ProcessDetailWindow::requestOpenNetworkDockByPid, this,
        [this](const std::uint32_t targetPid) {
            (void)invokeMainWindowPidListSlot("focusNetworkDockByPids", QString::number(targetPid));
        });
    connect(detailWindow, &ProcessDetailWindow::requestOpenWindowDockByPid, this,
        [this](const std::uint32_t targetPid) {
            (void)invokeMainWindowPidListSlot("focusWindowDockByPids", QString::number(targetPid));
        });
    connect(detailWindow, &ProcessDetailWindow::requestOpenFileDetailByPath, this,
        [this](const QString& filePath) {
            QObject* const kReceiver = mainWindowActionReceiver();
            const bool kInvokeOk = kReceiver != nullptr &&
                QMetaObject::invokeMethod(
                    kReceiver,
                    "openFileDetailDockByPath",
                    Qt::QueuedConnection,
                    Q_ARG(QString, filePath));
            if (!kInvokeOk)
            {
                KLogEvent logEvent;
                warn << logEvent
                    << "[ProcessDock] requestOpenFileDetailByPath 转发失败, path="
                    << filePath.toStdString()
                    << eol;
            }
        });
}

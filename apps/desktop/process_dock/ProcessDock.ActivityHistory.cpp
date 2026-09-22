#include "ProcessDock.Support.h"
#include "ProcessActivityChartWidget.h"
#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

bool ProcessDock::isProcessActivityMetricEnabled(const ProcessActivityMetric metric) const
{
    // When the button is empty, use the default full display:
    // - Keep consistent with the button state after initialization.
    // - This ensures that the first frame rendering does not miss disk, network, or GPU data due to the control not being bound yet.
    // This ensures that calling before panel initialization does not produce a null pointer.
    switch (metric)
    {
    case ProcessActivityMetric::kCpu:
        return activityCpuButton_ == nullptr || activityCpuButton_->isChecked();
    case ProcessActivityMetric::kMemory:
        return activityMemoryButton_ == nullptr || activityMemoryButton_->isChecked();
    case ProcessActivityMetric::kDisk:
        return activityDiskButton_ == nullptr || activityDiskButton_->isChecked();
    case ProcessActivityMetric::kNetwork:
        return activityNetworkButton_ == nullptr || activityNetworkButton_->isChecked();
    case ProcessActivityMetric::kGpu:
        return activityGpuButton_ == nullptr || activityGpuButton_->isChecked();
    default:
        return false;
    }
}

bool ProcessDock::isProcessListPageVisibleForRecording() const
{
    // By default, refresh/record only when the process list page is the current page.
    // Allow switching to other sub-pages for continued refresh/recording only after the user has checked 'Keep refreshing/recording in background'.
    return sideTabWidget_ != nullptr &&
        processListPage_ != nullptr &&
        sideTabWidget_->currentWidget() == processListPage_ &&
        processListPage_->isVisible();
}

bool ProcessDock::isProcessActivityRefreshAllowedNow() const
{
    // Refresh allow logic only cares about whether enumeration should continue:
    // - No longer refresh after the pause button is closed;
    // - Refresh is allowed only when on the process list page.
    // - The background keep-alive switch allows continued refreshing after leaving the process list page.
    if (!monitoringEnabled_)
    {
        return false;
    }

    if (activityBackgroundRecordCheck_ != nullptr && activityBackgroundRecordCheck_->isChecked())
    {
        return true;
    }

    return isProcessListPageVisibleForRecording();
}

bool ProcessDock::isProcessActivityRecordingAllowedNow() const
{
    // The recording-allowed logic is layered on top of the refresh-allowed logic with an additional 'do not record history' condition:
    // - This allows the list below to continue updating.
    // - Also avoid polluting the time axis samples above.
    if (!isProcessActivityRefreshAllowedNow())
    {
        return false;
    }

    if (activityListOnlyRefreshCheck_ != nullptr && activityListOnlyRefreshCheck_->isChecked())
    {
        return false;
    }

    return true;
}

void ProcessDock::appendProcessActivitySample()
{
    if (!isProcessActivityRecordingAllowedNow())
    {
        updateProcessActivityStatusLabel();
        refreshProcessActivityChart();
        return;
    }

    if (activityRecordingStartTick100ns_ == 0 || activitySamples_.empty())
    {
        activityRecordingStartTick100ns_ = steadyNow100ns();
    }

    ProcessActivitySample sample{};
    const std::uint64_t kNowTick100ns = steadyNow100ns();
    sample.sequence = activityNextSequence_++;
    sample.elapsedMs = (kNowTick100ns >= activityRecordingStartTick100ns_)
        ? ((kNowTick100ns - activityRecordingStartTick100ns_) / 10000ULL)
        : 0ULL;
    sample.unixMilliseconds = QDateTime::currentMSecsSinceEpoch();
    sample.processes.reserve(cacheByIdentity_.size());

    for (const auto& cachePair : cacheByIdentity_)
    {
        const CacheEntry& cacheEntry = cachePair.second;
        if (cacheEntry.isExitedInLatestRound)
        {
            continue;
        }

        const ks::process::ProcessRecord& processRecord = cacheEntry.record;
        ProcessActivityProcessPoint processPoint{};
        processPoint.identityKey = cachePair.first;
        processPoint.processName = processRecord.processName;
        processPoint.imagePath = processRecord.imagePath;
        processPoint.iconCacheKey = processRecord.processName + "|" + processRecord.imagePath;
        processPoint.creationTime100ns = processRecord.creationTime100ns;
        processPoint.pid = processRecord.pid;
        copyProcessActivityDynamicFields(processPoint, processRecord);

        const bool kIsSystemIdleProcess =
            (processRecord.pid == 0) ||
            (QString::fromStdString(processRecord.processName).compare("System Idle Process", Qt::CaseInsensitive) == 0);
        if (!kIsSystemIdleProcess)
        {
            sample.totalCpuPercent += processRecord.cpuPercent;
        }
        sample.totalMemoryMB += processRecord.workingSetMB;
        sample.totalDiskMBps += processRecord.diskMBps;
        sample.totalNetKBps += processRecord.netKBps;
        sample.totalGpuPercent += processRecord.gpuPercent;

        // Historical snapshots store only lightweight data; do not repeatedly dispatch icon queries within the sampling loop.
        // - The current process list submits a full batch of background shell icon tasks during each refresh cycle.
        // - Reuses the ready path cache; when the history row misses, it displays the path and submits a background task.
        // - Icons remain fully based on the process name and path in the snapshot, without additional queries by PID.
        if (!processPoint.iconCacheKey.empty())
        {
            const QString kIconKey = QString::fromStdString(processPoint.iconCacheKey);
            const QString kImagePath = QString::fromStdString(processPoint.imagePath).trimmed();
            const auto kLiveIconIt = iconCacheByPath_.find(kImagePath);
            if (!activityIconCacheByProcessKey_.contains(kIconKey) &&
                kLiveIconIt != iconCacheByPath_.end())
            {
                if (activityIconCacheByProcessKey_.size() >= kActivityIconCacheMaximumCount)
                {
                    activityIconCacheByProcessKey_.erase(activityIconCacheByProcessKey_.begin());
                }
                activityIconCacheByProcessKey_.insert(kIconKey, kLiveIconIt.value());
            }
        }
        sample.processes.push_back(std::move(processPoint));
    }

    activitySamples_.push_back(std::move(sample));
    const bool kSampleIndexShiftedLeft = trimProcessActivitySamples();
    if (activityChartWidget_ != nullptr)
    {
        activityChartWidget_->animateLatestSample(kSampleIndexShiftedLeft);
    }
    if (!activitySamples_.empty())
    {
        appendProcessActivitySampleToDetailWindows(activitySamples_.back());
    }
    if (activityTableSnapshotIndex_ >= static_cast<int>(activitySamples_.size()))
    {
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
    }
    refreshProcessActivityTimeline(kSampleIndexShiftedLeft);
    refreshProcessActivityChart();
    updateProcessActivityStatusLabel();
}

void ProcessDock::synchronizeDetailWindowPerformanceHistory(
    ProcessDetailWindow* const detailWindow,
    const std::string& identityKey) const
{
    if (detailWindow == nullptr || identityKey.empty())
    {
        return;
    }

    std::vector<ProcessDetailWindow::PerformanceHistorySample> history;
    history.reserve(activitySamples_.size());
    for (const ProcessActivitySample& activitySample : activitySamples_)
    {
        const auto kProcessPointIt = std::find_if(
            activitySample.processes.cbegin(),
            activitySample.processes.cend(),
            [&identityKey](const ProcessActivityProcessPoint& processPoint) {
                return processPoint.identityKey == identityKey;
            });
        if (kProcessPointIt == activitySample.processes.cend())
        {
            continue;
        }

        ProcessDetailWindow::PerformanceHistorySample detailSample;
        detailSample.unixMilliseconds = activitySample.unixMilliseconds;
        detailSample.cpuPercent = kProcessPointIt->cpuPercent;
        detailSample.cpuCorePercent = kProcessPointIt->cpuCorePercent;
        detailSample.memoryMB = kProcessPointIt->workingSetMB;
        detailSample.diskMBps = kProcessPointIt->diskMBps;
        detailSample.networkRxKBps = kProcessPointIt->netRxKBps;
        detailSample.networkTxKBps = kProcessPointIt->netTxKBps;
        detailSample.gpuPercent = kProcessPointIt->gpuPercent;
        history.push_back(detailSample);
    }
    detailWindow->setPerformanceHistory(std::move(history));
}

void ProcessDock::appendProcessActivitySampleToDetailWindows(const ProcessActivitySample& sample)
{
    for (const auto& detailWindowPair : detailWindowByIdentity_)
    {
        ProcessDetailWindow* const kDetailWindow = detailWindowPair.second.data();
        if (kDetailWindow == nullptr)
        {
            continue;
        }

        const auto kProcessPointIt = std::find_if(
            sample.processes.cbegin(),
            sample.processes.cend(),
            [&detailWindowPair](const ProcessActivityProcessPoint& processPoint) {
                return processPoint.identityKey == detailWindowPair.first;
            });
        if (kProcessPointIt == sample.processes.cend())
        {
            continue;
        }

        ProcessDetailWindow::PerformanceHistorySample detailSample;
        detailSample.unixMilliseconds = sample.unixMilliseconds;
        detailSample.cpuPercent = kProcessPointIt->cpuPercent;
        detailSample.cpuCorePercent = kProcessPointIt->cpuCorePercent;
        detailSample.memoryMB = kProcessPointIt->workingSetMB;
        detailSample.diskMBps = kProcessPointIt->diskMBps;
        detailSample.networkRxKBps = kProcessPointIt->netRxKBps;
        detailSample.networkTxKBps = kProcessPointIt->netTxKBps;
        detailSample.gpuPercent = kProcessPointIt->gpuPercent;
        kDetailWindow->appendPerformanceHistorySample(detailSample);
    }
}

bool ProcessDock::trimProcessActivitySamples()
{
    // The sample cache has a fixed upper limit to prevent unbounded memory growth from long-term recording.
    if (activitySamples_.size() <= kActivityMaximumSampleCount)
    {
        return false;
    }

    const std::size_t kRemoveCount = activitySamples_.size() - kActivityMaximumSampleCount;
    for (std::size_t removeIndex = 0; removeIndex < kRemoveCount; ++removeIndex)
    {
        activitySamples_.pop_front();
    }
    if (activityTableSnapshotIndex_ >= 0)
    {
        activityTableSnapshotIndex_ -= static_cast<int>(kRemoveCount);
        if (activityTableSnapshotIndex_ < 0)
        {
            activityTableSnapshotIndex_ = -1;
            activityTableSnapshotRecords_.clear();
        }
    }
    return kRemoveCount > 0;
}

void ProcessDock::refreshProcessActivityTimeline(const bool indexShiftedLeft)
{
    if (activityTimelineSlider_ == nullptr)
    {
        return;
    }

    const bool kOldUpdating = activityTimelineSliderUpdating_;
    const int kSampleCount = static_cast<int>(activitySamples_.size());
    const int kPreviousValue = (indexShiftedLeft && !activityTimelinePinnedToLatest_)
        ? std::max(0, activityTimelineSlider_->value())
        : activityTimelineSlider_->value();
    const int kPreviousMaximum = activityTimelineSlider_->maximum();
    const bool kShouldPinToLatest = activityTimelinePinnedToLatest_ || kPreviousValue >= kPreviousMaximum;

    activityTimelineSliderUpdating_ = true;
    activityTimelineSlider_->setRange(0, std::max(0, kSampleCount - 1));
    if (kSampleCount == 0)
    {
        activityTimelineSlider_->setValue(0);
    }
    else if (kShouldPinToLatest)
    {
        activityTimelineSlider_->setValue(kSampleCount - 1);
        activityTimelinePinnedToLatest_ = true;
    }
    else
    {
        const int kRestoredValue = std::clamp(kPreviousValue, 0, kSampleCount - 1);
        activityTimelineSlider_->setValue(kRestoredValue);
        activityTimelinePinnedToLatest_ = (kRestoredValue >= kSampleCount - 1);
    }
    activityTimelineSliderUpdating_ = kOldUpdating;

    if (kSampleCount > 0)
    {
        if (activityTimelinePinnedToLatest_)
        {
            activityTableSnapshotIndex_ = -1;
            activityTableSnapshotRecords_.clear();
        }
        else if (isProcessActivityTableSnapshotActive())
        {
            rebuildProcessActivityTableSnapshotRecords();
        }
        previewProcessActivitySnapshotForIndex(activityTimelineSlider_->value());
    }
    else if (activityChartWidget_ != nullptr)
    {
        activityChartWidget_->setFocusedSampleIndex(-1);
    }
}

void ProcessDock::refreshProcessActivityChart()
{
    if (activityChartWidget_ != nullptr)
    {
        const int kSampleIndex = (activityTimelineSlider_ != nullptr) ? activityTimelineSlider_->value() : -1;
        activityChartWidget_->setFocusedSampleIndex(kSampleIndex);
        activityChartWidget_->update();
    }
}

void ProcessDock::updateProcessActivityStatusLabel()
{
    const bool kRecordingAllowed = isProcessActivityRecordingAllowedNow();
    activityRecordingEnabled_ = kRecordingAllowed;
}

void ProcessDock::previewProcessActivitySnapshotForIndex(const int sampleIndex)
{
    if (activitySamples_.empty())
    {
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
        if (activitySnapshotLabel_ != nullptr && activitySnapshotLabel_->isVisible())
        {
            activitySnapshotLabel_->setText(processContextText(
                "process.activity.snapshot.empty",
                QStringLiteral("时间轴快照：暂无样本")));
        }
        if (activityChartWidget_ != nullptr)
        {
            activityChartWidget_->setFocusedSampleIndex(-1);
        }
        return;
    }

    const int kSafeIndex = std::clamp(sampleIndex, 0, static_cast<int>(activitySamples_.size()) - 1);
    if (activityChartWidget_ != nullptr)
    {
        activityChartWidget_->setFocusedSampleIndex(kSafeIndex);
    }
    if (activitySnapshotLabel_ != nullptr && activitySnapshotLabel_->isVisible())
    {
        activitySnapshotLabel_->setText(buildProcessActivitySnapshotText(kSafeIndex));
    }
}

void ProcessDock::showProcessActivitySnapshotForIndex(const int sampleIndex)
{
    previewProcessActivitySnapshotForIndex(sampleIndex);
}

void ProcessDock::commitProcessActivityTimelineIndex(const int sampleIndex)
{
    if (activitySamples_.empty())
    {
        activityTableSnapshotIndex_ = -1;
        activityTableSnapshotRecords_.clear();
        previewProcessActivitySnapshotForIndex(-1);
        rebuildTable();
        updateProcessActivityStatusLabel();
        return;
    }

    const int kSafeIndex = std::clamp(sampleIndex, 0, static_cast<int>(activitySamples_.size()) - 1);
    const bool kLatestSelected =
        (activityTimelineSlider_ != nullptr && kSafeIndex >= activityTimelineSlider_->maximum()) ||
        (kSafeIndex >= static_cast<int>(activitySamples_.size()) - 1);

    activityTimelinePinnedToLatest_ = kLatestSelected;
    activityTableSnapshotIndex_ = kLatestSelected ? -1 : kSafeIndex;
    if (activityTimelineSlider_ != nullptr && activityTimelineSlider_->value() != kSafeIndex)
    {
        const bool kOldUpdating = activityTimelineSliderUpdating_;
        activityTimelineSliderUpdating_ = true;
        activityTimelineSlider_->setValue(kSafeIndex);
        activityTimelineSliderUpdating_ = kOldUpdating;
    }

    previewProcessActivitySnapshotForIndex(kSafeIndex);
    rebuildProcessActivityTableSnapshotRecords();
    rebuildTable();
    updateProcessActivityStatusLabel();
}

bool ProcessDock::isProcessActivityTableSnapshotActive() const
{
    return activityTableSnapshotIndex_ >= 0 &&
        activityTableSnapshotIndex_ < static_cast<int>(activitySamples_.size());
}

void ProcessDock::rebuildProcessActivityTableSnapshotRecords()
{
    activityTableSnapshotRecords_.clear();
    if (!isProcessActivityTableSnapshotActive())
    {
        return;
    }

    const ProcessActivitySample& sample =
        activitySamples_[static_cast<std::size_t>(activityTableSnapshotIndex_)];
    activityTableSnapshotRecords_.reserve(sample.processes.size());
    for (const ProcessActivityProcessPoint& processPoint : sample.processes)
    {
        ks::process::ProcessRecord record{};
        record.pid = processPoint.pid;
        record.parentPid = 0;
        record.creationTime100ns = processPoint.creationTime100ns;
        if (record.creationTime100ns == 0)
        {
            record.creationTime100ns = (sample.sequence + 1U) * 100000ULL + processPoint.pid;
        }
        record.processName = processPoint.processName.empty() ? std::string("PID ") + std::to_string(processPoint.pid) : processPoint.processName;
        record.imagePath = processPoint.imagePath.empty() ? std::string("历史快照") : processPoint.imagePath;
        record.commandLine = "时间轴历史样本";
        record.userName = "-";
        record.signatureState = "历史快照";
        record.startTimeText = QDateTime::fromMSecsSinceEpoch(sample.unixMilliseconds)
            .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"))
            .toStdString();
        copyProcessActivityDynamicFields(record, processPoint);
        record.activePrivateWorkingSetBytes = processPoint.processSuspended
            ? 0U
            : processPoint.privateWorkingSetBytes;
        record.staticDetailsReady = true;
        record.dynamicCountersReady = true;
        activityTableSnapshotRecords_.push_back(std::move(record));
    }
}

QString ProcessDock::buildProcessActivitySnapshotText(const int sampleIndex) const
{
    if (activitySamples_.empty())
    {
        return QStringLiteral("时间轴快照：暂无样本");
    }

    const int kSafeIndex = std::clamp(sampleIndex, 0, static_cast<int>(activitySamples_.size()) - 1);
    const ProcessActivitySample& sample = activitySamples_[static_cast<std::size_t>(kSafeIndex)];
    const std::vector<std::string> kSelectionKeys = currentProcessActivitySelectionKeys();

    const double kCpuValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::kCpu, kSelectionKeys);
    const double kMemoryValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::kMemory, kSelectionKeys);
    const double kDiskValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::kDisk, kSelectionKeys);
    const double kNetValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::kNetwork, kSelectionKeys);
    const double kGpuValue = processActivitySampleMetricValue(sample, ProcessActivityMetric::kGpu, kSelectionKeys);
    double maxDiskValue = 0.0;
    double maxNetValue = 0.0;
    for (const ProcessActivitySample& historySample : activitySamples_)
    {
        maxDiskValue = std::max(maxDiskValue, processActivitySampleMetricValue(historySample, ProcessActivityMetric::kDisk, kSelectionKeys));
        maxNetValue = std::max(maxNetValue, processActivitySampleMetricValue(historySample, ProcessActivityMetric::kNetwork, kSelectionKeys));
    }
    const double kMemoryPercent = clampPercentValue(
        (kMemoryValue / std::max(1.0, activityTotalPhysicalMemoryMB_)) * 100.0);
    const double kDiskPercent = clampPercentValue((kDiskValue / std::max(1.0, maxDiskValue)) * 100.0);
    const double kNetPercent = clampPercentValue((kNetValue / std::max(1.0, maxNetValue)) * 100.0);
    std::vector<ProcessActivityProcessPoint> matchedProcesses;
    if (!kSelectionKeys.empty())
    {
        for (const ProcessActivityProcessPoint& processPoint : sample.processes)
        {
            if (std::find(kSelectionKeys.begin(), kSelectionKeys.end(), processPoint.identityKey) == kSelectionKeys.end())
            {
                continue;
            }
            matchedProcesses.push_back(processPoint);
        }
    }

    const QDateTime kSampleDateTime = QDateTime::fromMSecsSinceEpoch(sample.unixMilliseconds);
    QString text = processContextText(
        "process.activity.snapshot.template",
        QStringLiteral("时间轴快照：%1 / +%2 | 范围:%3 | CPU %4% | 内存 %5% (%6 MB) | 磁盘 %7% (%8 MB/s) | 网络 %9% (%10 KB/s) | GPU %11%"))
        .arg(kSampleDateTime.toString(QStringLiteral("HH:mm:ss.zzz")))
        .arg(formatActivityElapsedText(sample.elapsedMs))
        .arg(kSelectionKeys.empty()
            ? processContextText("process.activity.snapshot.scope.total", QStringLiteral("总体"))
            : processContextText("process.activity.snapshot.scope.selected", QStringLiteral("选中%1个进程"))
                .arg(static_cast<qulonglong>(kSelectionKeys.size())))
        .arg(clampPercentValue(kCpuValue), 0, 'f', 2)
        .arg(kMemoryPercent, 0, 'f', 2)
        .arg(kMemoryValue, 0, 'f', 1)
        .arg(kDiskPercent, 0, 'f', 2)
        .arg(kDiskValue, 0, 'f', 2)
        .arg(kNetPercent, 0, 'f', 2)
        .arg(kNetValue, 0, 'f', 2)
        .arg(kGpuValue, 0, 'f', 1);

    QStringList enabledMetricTextList;
    const ProcessActivityMetric kAllMetrics[] = {
        ProcessActivityMetric::kCpu,
        ProcessActivityMetric::kMemory,
        ProcessActivityMetric::kDisk,
        ProcessActivityMetric::kNetwork,
        ProcessActivityMetric::kGpu
    };
    for (const ProcessActivityMetric kMetric : kAllMetrics)
    {
        if (isProcessActivityMetricEnabled(kMetric))
        {
            const double kMetricValue = processActivitySampleMetricValue(sample, kMetric, kSelectionKeys);
            double percentValue = 0.0;
            switch (kMetric)
            {
            case ProcessActivityMetric::kCpu:
            case ProcessActivityMetric::kGpu:
                percentValue = clampPercentValue(kMetricValue);
                break;
            case ProcessActivityMetric::kMemory:
                percentValue = kMemoryPercent;
                break;
            case ProcessActivityMetric::kDisk:
                percentValue = kDiskPercent;
                break;
            case ProcessActivityMetric::kNetwork:
                percentValue = kNetPercent;
                break;
            default:
                percentValue = 0.0;
                break;
            }
            enabledMetricTextList << QStringLiteral("%1 %2%3")
                .arg(processActivityMetricText(kMetric))
                .arg(percentValue, 0, 'f', percentValue >= 100.0 ? 1 : 2)
                .arg(processActivityMetricUnit(kMetric));
        }
    }
    if (!enabledMetricTextList.isEmpty())
    {
        text += QStringLiteral(" | 当前显示: %1").arg(enabledMetricTextList.join(QStringLiteral(", ")));
    }

    if (!kSelectionKeys.empty())
    {
        QStringList processTextList;
        const int kMaxProcessPreviewCount = 4;
        for (int i = 0; i < static_cast<int>(matchedProcesses.size()) && i < kMaxProcessPreviewCount; ++i)
        {
            const ProcessActivityProcessPoint& processPoint = matchedProcesses[static_cast<std::size_t>(i)];
            processTextList << QStringLiteral("%1(%2)")
                .arg(QString::fromStdString(processPoint.processName.empty() ? std::string("PID") : processPoint.processName))
                .arg(processPoint.pid);
        }
        if (matchedProcesses.size() > static_cast<std::size_t>(kMaxProcessPreviewCount))
        {
            processTextList << QStringLiteral("...");
        }
        text += QStringLiteral(" | 进程: %1").arg(processTextList.isEmpty() ? QStringLiteral("该时刻未出现") : processTextList.join(QStringLiteral(", ")));
    }
    else
    {
        text += QStringLiteral(" | 进程数: %1").arg(static_cast<qulonglong>(sample.processes.size()));
    }

    return text;
}

std::vector<std::string> ProcessDock::currentProcessActivitySelectionKeys() const
{
    // Use the tracked multi-selection set to avoid freezing the right-click menu copy during read.
    // The chart only cares about the user's current table selection and should not be affected by context menu actions.
    std::vector<std::string> selectionKeys;
    std::unordered_set<std::string> visitedSet;
    if (processTable_ != nullptr)
    {
        const std::vector<QModelIndex> kSelectedRows = selectedProcessTableRowIndexes(false);
        selectionKeys.reserve(kSelectedRows.size());
        for (const QModelIndex& rowIndex : kSelectedRows)
        {
            const ProcessTableRow* tableRow = processTableRowForViewIndex(rowIndex);
            if (tableRow == nullptr)
            {
                continue;
            }
            if (!tableRow->identityKey.empty() && visitedSet.insert(tableRow->identityKey).second)
            {
                selectionKeys.push_back(tableRow->identityKey);
            }
            for (const std::string& aggregateIdentityKey : tableRow->actionIdentityKeys)
            {
                if (!aggregateIdentityKey.empty() && visitedSet.insert(aggregateIdentityKey).second)
                {
                    selectionKeys.push_back(aggregateIdentityKey);
                }
            }
        }
    }
    if (isProcessActivityTableSnapshotActive() && selectionKeys.empty())
    {
        return selectionKeys;
    }
    if (selectionKeys.empty())
    {
        for (const std::string& identityKey : trackedSelectedIdentityKeys_)
        {
            if (!identityKey.empty() &&
                cacheByIdentity_.find(identityKey) != cacheByIdentity_.end() &&
                visitedSet.insert(identityKey).second)
            {
                selectionKeys.push_back(identityKey);
            }
        }
    }
    return selectionKeys;
}

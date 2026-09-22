#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::flushEtwPendingRows(const bool captureFinished)
{
    if (etwEventTable_ == nullptr)
    {
        return;
    }
    if (!captureFinished && etwCapturePaused_.load())
    {
        // Prevent the last timeout dispatched to the event loop before suspension from continuing to drain the queue.
        return;
    }

    // The menu barrier must be placed before any pending drain and before any timeline or table changes. The
    // periodic timeout retains only the latest retry; captureFinished is also passed with the final retry.
    const QPointer<MonitorDock> kGuardThis(this);
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        captureFinished
            ? QStringLiteral("monitor-etw-event-flush-final")
            : QStringLiteral("monitor-etw-event-flush-periodic"),
        { etwEventTable_ },
        [kGuardThis, captureFinished]()
        {
            if (!kGuardThis.isNull())
            {
                kGuardThis->flushEtwPendingRows(captureFinished);
            }
        }))
    {
        return;
    }

    // Create at most 32 rows (224 QTableWidgetItem items) every 50ms, keeping the main thread table construction rate around 640 rows/second.
    // The UI queue handles only real-time mirroring; events not displayed remain fully preserved in disk archives.
    constexpr std::size_t kMaxRowsPerFlush = 32;
    constexpr int kMaxCapturedRows = 6000;
    constexpr int kTrimThresholdRows = 6200;
    constexpr qint64 kTimelineRefreshIntervalMs = 250;

    std::vector<EtwCapturedEventRow> rows;
    {
        std::lock_guard<std::mutex> lock(etwPendingMutex_);
        const std::size_t kFlushCount = std::min(kMaxRowsPerFlush, etwPendingRows_.size());
        rows.reserve(kFlushCount);
        for (std::size_t rowIndex = 0; rowIndex < kFlushCount; ++rowIndex)
        {
            rows.push_back(std::move(etwPendingRows_.front()));
            etwPendingRows_.pop_front();
        }
    }

    // Current rules may change after events enter the UI queue. Only a small subset of rows for this frame is filtered; full
    // results are handled by background archival scanning to avoid repeatedly traversing the history table on the main thread.
    const bool kHasPostRules = etwPostSimpleFilterCompiled_.hasAnyCondition()
        || !etwPostFilterCompiledGroupList_.empty();
    const bool kTimelineFilterActive = isEtwTimelineFilterActive();
    if (kHasPostRules || kTimelineFilterActive)
    {
        rows.erase(
            std::remove_if(
                rows.begin(),
                rows.end(),
                [this, kTimelineFilterActive](const EtwCapturedEventRow& rowData) {
                    bool matches = etwFilterStageMatches(
                        etwPostSimpleFilterCompiled_,
                        etwPostFilterCompiledGroupList_,
                        rowData);
                    if (matches && kTimelineFilterActive)
                    {
                        const std::uint64_t kTimestamp100ns = etwRawTimestampToTimelineTimestamp(
                            rowData.timestampValue);
                        matches = kTimestamp100ns >= etwTimelineSelectionStart100ns_
                            && kTimestamp100ns <= etwTimelineSelectionEnd100ns_;
                    }
                    return !matches;
                }),
            rows.end());
    }

    const bool kRefreshTimeline = captureFinished
        || !etwTimelineRefreshTimer_.isValid()
        || etwTimelineRefreshTimer_.hasExpired(kTimelineRefreshIntervalMs);

    if (rows.empty())
    {
        // Skip refresh when paused to avoid advancing ranges or re-pushing point sets, preventing the waterfall right boundary from continuously compressing existing events.
        const bool kPaused = etwCapturePaused_.load();
        if (kRefreshTimeline && (captureFinished || !kPaused))
        {
            refreshEtwTimelineRange(captureFinished);
            refreshEtwTimelinePoints();
            etwTimelineRefreshTimer_.restart();
        }
        if (captureFinished || (!kPaused && isEtwTimelineFilterActive()))
        {
            applyEtwPostFilterToTable();
        }

        if (captureFinished && etwUiUpdateTimer_ != nullptr && etwUiUpdateTimer_->isActive())
        {
            etwUiUpdateTimer_->stop();
        }
        return;
    }

    // Append in limited batches at a time. `setUpdatesEnabled` only suppresses repainting; actual throttling is handled by `kMaxRowsPerFlush`.
    etwEventTable_->setUpdatesEnabled(false);

    // Pre-allocate fixed result window space, then batch-expand rows to avoid triggering numerous model and layout updates via insertRow/removeRow loops.
    const int kProjectedRowCount = etwEventTable_->rowCount() + static_cast<int>(rows.size());
    const int kOverflowCount = kProjectedRowCount > kTrimThresholdRows
        ? kProjectedRowCount - kMaxCapturedRows
        : 0;
    if (kOverflowCount > 0)
    {
        if (!etwEventTable_->model()->removeRows(0, kOverflowCount))
        {
            for (int rowIndex = 0; rowIndex < kOverflowCount; ++rowIndex)
            {
                etwEventTable_->removeRow(0);
            }
        }
        for (int rowIndex = 0; rowIndex < kOverflowCount && !etwCapturedRows_.empty(); ++rowIndex)
        {
            etwCapturedRows_.pop_front();
        }
        for (int rowIndex = 0; rowIndex < kOverflowCount && !etwTimelineEventPoints_.empty(); ++rowIndex)
        {
            etwTimelineEventPoints_.pop_front();
        }
    }

    const int kFirstInsertedRow = etwEventTable_->rowCount();
    etwEventTable_->setRowCount(kFirstInsertedRow + static_cast<int>(rows.size()));
    for (std::size_t rowIndex = 0; rowIndex < rows.size(); ++rowIndex)
    {
        EtwCapturedEventRow& rowData = rows[rowIndex];
        etwCapturedRows_.push_back(std::move(rowData));
        EtwCapturedEventRow& captured = etwCapturedRows_.back();

        const int kRow = kFirstInsertedRow + static_cast<int>(rowIndex);
        QTableWidgetItem* sequenceItem = new QTableWidgetItem(QString::number(
            static_cast<qulonglong>(captured.archiveSequence != 0
                ? captured.archiveSequence
                : static_cast<std::uint64_t>(kRow + 1))));
        sequenceItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        etwEventTable_->setVerticalHeaderItem(kRow, sequenceItem);

        const QStringList kRowTextList{
            captured.timestampText,
            captured.providerName,
            QString::number(captured.eventId),
            captured.eventName,
            captured.pidTidText,
            captured.detailSummary,
            captured.activityId
        };

        for (int col = 0; col < kRowTextList.size(); ++col)
        {
            const QString kCellText = kRowTextList.at(col);
            QTableWidgetItem* item = new QTableWidgetItem(kCellText);
            item->setToolTip(kCellText);
            if (col == 5)
            {
                // UserRole column stores full JSON; table text displays only the summary.
                item->setData(Qt::UserRole, captured.detailJson);
            }
            etwEventTable_->setItem(kRow, col, item);
        }

        ProcessTraceTimelineEventPoint pointValue;
        // The timeline uses 'active runtime' coordinates; paused intervals do not consume horizontal width.
        pointValue.time100ns = etwRawTimestampToTimelineTimestamp(captured.timestampValue);
        pointValue.typeText = etwTimelineTypeFromCapturedRow(captured);
        etwTimelineEventPoints_.push_back(std::move(pointValue));
    }

    // m_etwCapturedRows and m_etwTimelineEventPoints were already synchronized and batch-trimmed before
    // appending; row numbers remain one-to-one, so there is no need to erase(begin()) line by line.
    if (kRefreshTimeline)
    {
        refreshEtwTimelineRange(captureFinished);
        refreshEtwTimelinePoints();
        etwTimelineRefreshTimer_.restart();
    }
    etwEventTable_->setUpdatesEnabled(true);
    etwEventTable_->scrollToBottom();
    etwEventTable_->viewport()->update();

    if (captureFinished)
    {
        bool hasPendingRows = false;
        {
            std::lock_guard<std::mutex> lock(etwPendingMutex_);
            hasPendingRows = !etwPendingRows_.empty();
        }

        // A batch may still remain in the queue after stopping listening. Drain frame-by-frame to prevent the "Stop" operation from blocking the UI again.
        if (hasPendingRows && !etwCaptureRunning_.load())
        {
            QTimer::singleShot(16, this, [this]() {
                if (!etwCaptureRunning_.load())
                {
                    flushEtwPendingRows(true);
                }
            });
        }
        else if (!hasPendingRows && etwUiUpdateTimer_ != nullptr && etwUiUpdateTimer_->isActive())
        {
            etwUiUpdateTimer_->stop();
        }
    }
}

void MonitorDock::applyEtwTimelineSelection(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // The timeline control only interprets mouse/scroll actions; table visibility remains handled by ETW post-filtering.
    // Stores the effective timestamp after excluding pause segments; during table filtering, original event timestamps are mapped and compared.
    etwTimelineSelectionStart100ns_ = std::min(start100ns, end100ns);
    etwTimelineSelectionEnd100ns_ = std::max(start100ns, end100ns);
    etwTimelineUserSelectionActive_ = true;
    scheduleEtwArchiveFilterRebuild();
}

std::uint64_t MonitorDock::etwRawTimestampToTimelineTimestamp(const std::uint64_t rawTimestamp100ns) const
{
    if (etwCaptureStartTime100ns_ == 0 || rawTimestamp100ns <= etwCaptureStartTime100ns_)
    {
        return etwCaptureStartTime100ns_;
    }

    // pausedDuration100ns: Statistics on the duration already spent in the paused state before rawTimestamp100ns.
    std::uint64_t pausedDuration100ns = 0;
    for (const auto& pauseInterval : etwTimelinePauseIntervals_)
    {
        const std::uint64_t kPauseStart100ns = pauseInterval.first;
        const std::uint64_t kPauseEnd100ns = pauseInterval.second;
        if (kPauseEnd100ns <= kPauseStart100ns || rawTimestamp100ns <= kPauseStart100ns)
        {
            continue;
        }

        const std::uint64_t kEffectivePauseEnd100ns = std::min(rawTimestamp100ns, kPauseEnd100ns);
        pausedDuration100ns += kEffectivePauseEnd100ns - kPauseStart100ns;
    }

    // If still paused, subtract the duration from the pause start to the current boundary from the right-boundary display time.
    if (etwCapturePaused_.load() && etwTimelinePauseTime100ns_ != 0 && rawTimestamp100ns > etwTimelinePauseTime100ns_)
    {
        pausedDuration100ns += rawTimestamp100ns - etwTimelinePauseTime100ns_;
    }

    const std::uint64_t kRawElapsed100ns = rawTimestamp100ns - etwCaptureStartTime100ns_;
    const std::uint64_t kEffectiveElapsed100ns = kRawElapsed100ns > pausedDuration100ns
        ? kRawElapsed100ns - pausedDuration100ns
        : 0;
    return etwCaptureStartTime100ns_ + kEffectiveElapsed100ns;
}

void MonitorDock::closeEtwTimelinePauseInterval(const std::uint64_t resumeTime100ns)
{
    if (etwTimelinePauseTime100ns_ == 0 || resumeTime100ns <= etwTimelinePauseTime100ns_)
    {
        return;
    }

    // Intervals store original ETW absolute time; the mapping function uniformly converts them to valid running time.
    etwTimelinePauseIntervals_.emplace_back(etwTimelinePauseTime100ns_, resumeTime100ns);
}

void MonitorDock::refreshEtwTimelineRange(const bool captureFinished)
{
    if (etwTimelineWidget_ == nullptr || etwCaptureStartTime100ns_ == 0)
    {
        return;
    }

    // captureEndRaw100ns：
    // - Fix the value to the moment of stopping after cessation to prevent selection drift during user review.
    // - Fixes the timestamp to the pause moment to prevent waterfall stream compression when no new events occur.
    // - Use the current system time to advance the right boundary only during normal listening.
    std::uint64_t captureEndRaw100ns = currentSystemTime100ns();
    if (captureFinished && etwCaptureStopTime100ns_ != 0)
    {
        captureEndRaw100ns = etwCaptureStopTime100ns_;
    }
    else if (etwCapturePaused_.load() && etwTimelinePauseTime100ns_ != 0)
    {
        captureEndRaw100ns = etwTimelinePauseTime100ns_;
    }
    if (captureEndRaw100ns <= etwCaptureStartTime100ns_)
    {
        captureEndRaw100ns = etwCaptureStartTime100ns_ + 1;
    }

    std::uint64_t captureEnd100ns = etwRawTimestampToTimelineTimestamp(captureEndRaw100ns);
    if (captureEnd100ns <= etwCaptureStartTime100ns_)
    {
        captureEnd100ns = etwCaptureStartTime100ns_ + 1;
    }

    etwTimelineWidget_->setCaptureRange(etwCaptureStartTime100ns_, captureEnd100ns);
    etwTimelineSelectionStart100ns_ = etwTimelineWidget_->selectionStart100ns();
    etwTimelineSelectionEnd100ns_ = etwTimelineWidget_->selectionEnd100ns();
}

void MonitorDock::refreshEtwTimelinePoints()
{
    if (etwTimelineWidget_ == nullptr)
    {
        return;
    }

    // Control retains the vector API; the ETW side uses a deque for O(1) eviction of the oldest events.
    // The timeline refreshes at the throttling interval to avoid copying and redrawing the full point set for every UI batch.
    std::vector<ProcessTraceTimelineEventPoint> pointSnapshot;
    pointSnapshot.reserve(etwTimelineEventPoints_.size());
    pointSnapshot.insert(
        pointSnapshot.end(),
        etwTimelineEventPoints_.begin(),
        etwTimelineEventPoints_.end());
    etwTimelineWidget_->setEventPoints(pointSnapshot);
}

bool MonitorDock::isEtwTimelineFilterActive() const
{
    if (etwCaptureStartTime100ns_ == 0
        || !etwTimelineUserSelectionActive_
        || etwTimelineSelectionStart100ns_ == 0
        || etwTimelineSelectionEnd100ns_ == 0
        || etwTimelineSelectionEnd100ns_ <= etwTimelineSelectionStart100ns_)
    {
        return false;
    }

    std::uint64_t effectiveEndRaw100ns = currentSystemTime100ns();
    if (etwCaptureStopTime100ns_ != 0)
    {
        effectiveEndRaw100ns = etwCaptureStopTime100ns_;
    }
    else if (etwCapturePaused_.load() && etwTimelinePauseTime100ns_ != 0)
    {
        effectiveEndRaw100ns = etwTimelinePauseTime100ns_;
    }
    std::uint64_t effectiveEnd100ns = etwRawTimestampToTimelineTimestamp(effectiveEndRaw100ns);
    if (effectiveEnd100ns <= etwCaptureStartTime100ns_)
    {
        return false;
    }

    // A full-range selection is not a filter condition; events outside the time window are hidden only after the user actively narrows or pans the window.
    return etwTimelineSelectionStart100ns_ > etwCaptureStartTime100ns_
        || etwTimelineSelectionEnd100ns_ < effectiveEnd100ns;
}

void MonitorDock::appendEtwEventRow(
    const QString& providerName,
    int eventId,
    const QString& eventName,
    std::uint32_t pidValue,
    std::uint32_t tidValue,
    const QString& detailJson,
    const QString& activityIdText)
{
    const int kRow = etwEventTable_->rowCount();
    etwEventTable_->insertRow(kRow);

    const QString kDetailSummaryText = buildEtwSummaryFromDetailJson(
        detailJson,
        providerName,
        eventName,
        pidValue,
        tidValue);

    const QStringList kValues{
        now100nsText(),
        providerName,
        QString::number(eventId),
        eventName,
        QStringLiteral("%1 / %2").arg(pidValue).arg(tidValue),
        kDetailSummaryText,
        activityIdText
    };

    for (int i = 0; i < kValues.size(); ++i)
    {
        QTableWidgetItem* item = new QTableWidgetItem(kValues.at(i));
        item->setToolTip(kValues.at(i));
        if (i == 5)
        {
            item->setData(Qt::UserRole, detailJson);
        }
        etwEventTable_->setItem(kRow, i, item);
    }
}

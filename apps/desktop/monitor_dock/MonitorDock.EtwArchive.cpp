#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

bool MonitorDock::beginEtwArchiveBackgroundTask()
{
    std::lock_guard<std::mutex> lock(etwArchiveTaskMutex_);
    if (etwArchiveTaskShutdown_)
    {
        return false;
    }
    ++etwArchiveBackgroundTaskCount_;
    return true;
}

void MonitorDock::endEtwArchiveBackgroundTask()
{
    std::lock_guard<std::mutex> lock(etwArchiveTaskMutex_);
    if (etwArchiveBackgroundTaskCount_ > 0)
    {
        --etwArchiveBackgroundTaskCount_;
    }
    if (etwArchiveBackgroundTaskCount_ == 0)
    {
        etwArchiveTaskCondition_.notify_all();
    }
}

void MonitorDock::cancelAndWaitEtwArchiveBackgroundTasks()
{
    etwArchiveFilterTicket_.fetch_add(1, std::memory_order_relaxed);
    etwArchiveSessionGeneration_.fetch_add(1, std::memory_order_relaxed);
    if (etwArchiveFilterDebounceTimer_ != nullptr)
    {
        etwArchiveFilterDebounceTimer_->stop();
    }

    std::unique_lock<std::mutex> lock(etwArchiveTaskMutex_);
    etwArchiveTaskShutdown_ = true;
    etwArchiveTaskCondition_.wait(lock, [this]() {
        return etwArchiveBackgroundTaskCount_ == 0;
    });
}

void MonitorDock::scheduleEtwArchiveFilterRebuild()
{
    QString archiveDirectory;
    {
        std::lock_guard<std::mutex> lock(etwArchiveMutex_);
        archiveDirectory = etwArchiveDirectory_;
    }
    if (archiveDirectory.trimmed().isEmpty())
    {
        applyEtwPostFilterToTable();
        return;
    }

    // Immediately cancel the old scan, then debounce to start a new one. Continuous timeline dragging will not stack disk I/O.
    etwArchiveFilterTicket_.fetch_add(1, std::memory_order_relaxed);
    if (etwArchiveFilterDebounceTimer_ != nullptr)
    {
        etwArchiveFilterDebounceTimer_->start();
    }
}

bool MonitorDock::prepareEtwArchiveSession(QString* errorTextOut)
{
    etwArchiveFilterTicket_.fetch_add(1, std::memory_order_relaxed);
    etwArchiveSessionGeneration_.fetch_add(1, std::memory_order_relaxed);
    if (etwArchiveFilterDebounceTimer_ != nullptr)
    {
        etwArchiveFilterDebounceTimer_->stop();
    }
    finishEtwArchiveSession();

    QString baseDirectory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (baseDirectory.trimmed().isEmpty())
    {
        baseDirectory = QCoreApplication::applicationDirPath();
    }

    const QString kSessionDirectory = QDir(baseDirectory).filePath(
        QString::fromLatin1("etw_archive/KswordEtw_%1_%2")
            .arg(QDateTime::currentDateTime().toString(QString::fromLatin1("yyyyMMdd_HHmmss_zzz")))
            .arg(QCoreApplication::applicationPid()));
    if (!QDir().mkpath(kSessionDirectory))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法创建 ETW 全量归档目录：%1").arg(kSessionDirectory);
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(etwArchiveMutex_);
    etwArchiveDirectory_ = QDir::cleanPath(kSessionDirectory);
    etwArchiveActiveSegmentPath_.clear();
    etwArchiveClosedSegmentPaths_.clear();
    etwArchiveWriteBuffer_.clear();
    etwArchiveWriteBuffer_.reserve(kEtwArchiveWriteBufferBytes);
    etwArchiveFileHandle_ = 0;
    etwArchiveSegmentStart100ns_ = 0;
    etwArchiveNextSequence_ = 0;
    etwArchiveSegmentIndex_ = 0;
    etwArchiveWriteFailed_ = false;
    return true;
}

bool MonitorDock::archiveEtwCapturedRow(EtwCapturedEventRow* rowData)
{
    if (rowData == nullptr)
    {
        return false;
    }

    std::lock_guard<std::mutex> lock(etwArchiveMutex_);
    if (etwArchiveWriteFailed_ || etwArchiveDirectory_.trimmed().isEmpty())
    {
        return false;
    }

    rowData->archiveSequence = ++etwArchiveNextSequence_;
    const QByteArray kPayload = serializeEtwArchiveRow(*rowData);
    if (kPayload.isEmpty()
        || kPayload.size() > static_cast<qsizetype>(kEtwArchiveMaximumRecordBytes))
    {
        etwArchiveWriteFailed_ = true;
        return false;
    }

    const auto kCloseActiveSegment = [this]() -> bool {
        if (etwArchiveFileHandle_ == 0)
        {
            return true;
        }

        HANDLE fileHandle = reinterpret_cast<HANDLE>(etwArchiveFileHandle_);
        bool success = writeEtwArchiveBlockToHandle(fileHandle, etwArchiveWriteBuffer_);
        etwArchiveWriteBuffer_.clear();
        if (success)
        {
            success = ::FlushFileBuffers(fileHandle) != FALSE;
        }
        ::CloseHandle(fileHandle);
        etwArchiveFileHandle_ = 0;
        etwArchiveSegmentStart100ns_ = 0;
        if (!etwArchiveActiveSegmentPath_.isEmpty())
        {
            etwArchiveClosedSegmentPaths_.push_back(etwArchiveActiveSegmentPath_);
            etwArchiveActiveSegmentPath_.clear();
        }
        return success;
    };

    constexpr std::uint64_t kSegmentDuration100ns = 10ULL * 1000ULL * 1000ULL * 10ULL;
    const bool kNeedsRotation = etwArchiveFileHandle_ != 0
        && etwArchiveSegmentStart100ns_ != 0
        && rowData->timestampValue >= etwArchiveSegmentStart100ns_ + kSegmentDuration100ns;
    if (kNeedsRotation && !kCloseActiveSegment())
    {
        etwArchiveWriteFailed_ = true;
        return false;
    }

    if (etwArchiveFileHandle_ == 0)
    {
        const QString kSegmentPath = QDir(etwArchiveDirectory_).filePath(
            QString::fromLatin1("segment_%1.ketw")
                .arg(etwArchiveSegmentIndex_++, 6, 10, QChar(u'0')));
        HANDLE fileHandle = ::CreateFileW(
            reinterpret_cast<LPCWSTR>(kSegmentPath.utf16()),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            etwArchiveWriteFailed_ = true;
            return false;
        }

        const QByteArray kFileHeader = buildEtwArchiveFileHeader();
        if (!writeAllToHandle(fileHandle, kFileHeader))
        {
            ::CloseHandle(fileHandle);
            etwArchiveWriteFailed_ = true;
            return false;
        }

        etwArchiveFileHandle_ = reinterpret_cast<std::uintptr_t>(fileHandle);
        etwArchiveActiveSegmentPath_ = QDir::cleanPath(kSegmentPath);
        etwArchiveSegmentStart100ns_ = rowData->timestampValue;
    }

    const quint32 kPayloadSizeLittleEndian = qToLittleEndian(static_cast<quint32>(kPayload.size()));
    etwArchiveWriteBuffer_.append(
        reinterpret_cast<const char*>(&kPayloadSizeLittleEndian),
        static_cast<qsizetype>(sizeof(kPayloadSizeLittleEndian)));
    etwArchiveWriteBuffer_.append(kPayload);
    if (etwArchiveWriteBuffer_.size() >= kEtwArchiveWriteBufferBytes)
    {
        HANDLE fileHandle = reinterpret_cast<HANDLE>(etwArchiveFileHandle_);
        if (!writeEtwArchiveBlockToHandle(fileHandle, etwArchiveWriteBuffer_))
        {
            etwArchiveWriteFailed_ = true;
            return false;
        }
        etwArchiveWriteBuffer_.clear();
    }
    return true;
}

void MonitorDock::finishEtwArchiveSession(const bool flushToPhysicalDisk)
{
    HANDLE fileHandle = nullptr;
    bool success = true;
    {
        std::lock_guard<std::mutex> lock(etwArchiveMutex_);
        if (etwArchiveFileHandle_ == 0)
        {
            return;
        }

        fileHandle = reinterpret_cast<HANDLE>(etwArchiveFileHandle_);
        const bool kAlreadyFailed = etwArchiveWriteFailed_.load(std::memory_order_relaxed);
        success = !kAlreadyFailed
            && writeEtwArchiveBlockToHandle(fileHandle, etwArchiveWriteBuffer_);
        etwArchiveWriteBuffer_.clear();
        etwArchiveFileHandle_ = 0;
        etwArchiveSegmentStart100ns_ = 0;
        if (!etwArchiveActiveSegmentPath_.isEmpty())
        {
            etwArchiveClosedSegmentPaths_.push_back(etwArchiveActiveSegmentPath_);
            etwArchiveActiveSegmentPath_.clear();
        }
    }

    if (success && flushToPhysicalDisk)
    {
        success = ::FlushFileBuffers(fileHandle) != FALSE;
    }
    ::CloseHandle(fileHandle);
    if (!success)
    {
        etwArchiveWriteFailed_.store(true, std::memory_order_relaxed);
    }
}

void MonitorDock::rebuildEtwArchiveFilterAsync()
{
    QString archiveDirectory;
    {
        std::lock_guard<std::mutex> lock(etwArchiveMutex_);
        archiveDirectory = etwArchiveDirectory_;
    }
    if (archiveDirectory.trimmed().isEmpty() || !beginEtwArchiveBackgroundTask())
    {
        return;
    }

    const std::uint64_t kTicket = etwArchiveFilterTicket_.fetch_add(
        1,
        std::memory_order_relaxed) + 1;
    const std::uint64_t kSessionGeneration = etwArchiveSessionGeneration_.load(
        std::memory_order_relaxed);
    const EtwSimpleFilterCompiled kPostSimpleFilter = etwPostSimpleFilterCompiled_;
    const std::vector<EtwFilterRuleGroupCompiled> kPostFilterGroups = etwPostFilterCompiledGroupList_;
    const bool kTimelineFilterActive = isEtwTimelineFilterActive();
    const std::uint64_t kCaptureStart100ns = etwCaptureStartTime100ns_;
    const std::uint64_t kSelectionStart100ns = etwTimelineSelectionStart100ns_;
    const std::uint64_t kSelectionEnd100ns = etwTimelineSelectionEnd100ns_;
    const std::vector<std::pair<std::uint64_t, std::uint64_t>> kPauseIntervals =
        etwTimelinePauseIntervals_;
    const bool kCapturePaused = etwCapturePaused_.load();
    const std::uint64_t kActivePauseStart100ns = etwTimelinePauseTime100ns_;

    MonitorDock* taskOwner = this;
    const auto kTaskCompletion = std::shared_ptr<void>(
        reinterpret_cast<void*>(1),
        [taskOwner](void*) {
            taskOwner->endEtwArchiveBackgroundTask();
        });
    QPointer<MonitorDock> guardThis(this);
    std::thread([
        taskOwner,
        kTaskCompletion,
        guardThis,
        kTicket,
        kSessionGeneration,
        kPostSimpleFilter,
        kPostFilterGroups,
        kTimelineFilterActive,
        kCaptureStart100ns,
        kSelectionStart100ns,
        kSelectionEnd100ns,
        kPauseIntervals,
        kCapturePaused,
        kActivePauseStart100ns]() mutable {
        const auto kShouldCancel = [taskOwner, kTicket, kSessionGeneration]() {
            return taskOwner->etwArchiveFilterTicket_.load(std::memory_order_relaxed) != kTicket
                || taskOwner->etwArchiveSessionGeneration_.load(std::memory_order_relaxed) != kSessionGeneration;
        };
        if (kShouldCancel())
        {
            return;
        }

        // Archive the current active segment (less than 10 seconds) to ensure this filter has a clear and complete disk snapshot.
        taskOwner->finishEtwArchiveSession();
        if (kShouldCancel())
        {
            return;
        }

        QStringList segmentPaths;
        {
            std::lock_guard<std::mutex> lock(taskOwner->etwArchiveMutex_);
            segmentPaths = taskOwner->etwArchiveClosedSegmentPaths_;
        }
        const auto kRawToTimelineTimestamp = [
            kCaptureStart100ns,
            kPauseIntervals,
            kCapturePaused,
            kActivePauseStart100ns](const std::uint64_t rawTimestamp100ns) {
            if (kCaptureStart100ns == 0 || rawTimestamp100ns <= kCaptureStart100ns)
            {
                return kCaptureStart100ns;
            }

            std::uint64_t pausedDuration100ns = 0;
            for (const auto& pauseInterval : kPauseIntervals)
            {
                if (pauseInterval.second <= pauseInterval.first
                    || rawTimestamp100ns <= pauseInterval.first)
                {
                    continue;
                }
                pausedDuration100ns += std::min(rawTimestamp100ns, pauseInterval.second)
                    - pauseInterval.first;
            }
            if (kCapturePaused
                && kActivePauseStart100ns != 0
                && rawTimestamp100ns > kActivePauseStart100ns)
            {
                pausedDuration100ns += rawTimestamp100ns - kActivePauseStart100ns;
            }

            const std::uint64_t kElapsed100ns = rawTimestamp100ns - kCaptureStart100ns;
            return kCaptureStart100ns
                + (kElapsed100ns > pausedDuration100ns
                    ? kElapsed100ns - pausedDuration100ns
                    : 0);
        };

        std::deque<EtwCapturedEventRow> matchingRows;
        std::uint64_t totalMatchCount = 0;
        std::uint64_t scannedRowCount = 0;
        std::uint64_t scannedMaxSequence = 0;
        QString scanErrorText;
        constexpr std::size_t kMaximumVisibleRows = 6000;

        const auto kRowVisitor = [&](const EtwCapturedEventRow& row) {
            bool matches = etwFilterStageMatches(kPostSimpleFilter, kPostFilterGroups, row);
            if (matches && kTimelineFilterActive)
            {
                const std::uint64_t kTimelineTimestamp100ns = kRawToTimelineTimestamp(row.timestampValue);
                matches = kTimelineTimestamp100ns >= kSelectionStart100ns
                    && kTimelineTimestamp100ns <= kSelectionEnd100ns;
            }
            if (!matches)
            {
                return true;
            }

            ++totalMatchCount;
            matchingRows.push_back(row);
            if (matchingRows.size() > kMaximumVisibleRows)
            {
                matchingRows.pop_front();
            }
            return true;
        };

        std::size_t scannedSegmentCount = 0;
        const auto kScanNewSegments = [&]() -> bool {
            while (scannedSegmentCount < static_cast<std::size_t>(segmentPaths.size()))
            {
                if (kShouldCancel())
                {
                    return false;
                }
                const QString kSegmentPath = segmentPaths.at(static_cast<qsizetype>(scannedSegmentCount));
                ++scannedSegmentCount;
                if (!scanEtwArchiveFile(
                    kSegmentPath,
                    kRowVisitor,
                    kShouldCancel,
                    &scannedRowCount,
                    &scannedMaxSequence,
                    &scanErrorText))
                {
                    return false;
                }
            }
            return true;
        };

        if (!kScanNewSegments() && scanErrorText.isEmpty())
        {
            return;
        }

        // The initial full scan may take a long time. Perform up to three additional passes capturing only new events to keep the final UI window
        // as close as possible to the scan completion time, while avoiding continuous listening that would prevent the scan from ever ending.
        for (int catchUpPass = 0;
             catchUpPass < 3 && scanErrorText.isEmpty() && taskOwner->etwCaptureRunning_.load();
             ++catchUpPass)
        {
            taskOwner->finishEtwArchiveSession();
            if (kShouldCancel())
            {
                return;
            }

            QStringList latestSegmentPaths;
            {
                std::lock_guard<std::mutex> lock(taskOwner->etwArchiveMutex_);
                latestSegmentPaths = taskOwner->etwArchiveClosedSegmentPaths_;
            }
            if (latestSegmentPaths.size() <= static_cast<qsizetype>(scannedSegmentCount))
            {
                break;
            }
            segmentPaths = std::move(latestSegmentPaths);
            if (!kScanNewSegments() && scanErrorText.isEmpty())
            {
                return;
            }
        }

        if (kShouldCancel())
        {
            return;
        }

        QMetaObject::invokeMethod(qApp, [
            guardThis,
            kTicket,
            kSessionGeneration,
            rows = std::move(matchingRows),
            totalMatchCount,
            scannedRowCount,
            scannedMaxSequence,
            scanErrorText]() mutable {
            if (guardThis == nullptr
                || guardThis->etwArchiveFilterTicket_.load(std::memory_order_relaxed) != kTicket
                || guardThis->etwArchiveSessionGeneration_.load(std::memory_order_relaxed) != kSessionGeneration)
            {
                return;
            }
            if (!scanErrorText.isEmpty())
            {
                if (guardThis->etwPostSimpleFilterUi_.stateLabel != nullptr)
                {
                    guardThis->etwPostSimpleFilterUi_.stateLabel->setText(scanErrorText);
                    ks::ui::applyStatusRole(guardThis->etwPostSimpleFilterUi_.stateLabel, ks::ui::StatusRole::kError);
                }
                return;
            }
            guardThis->replaceEtwRowsWithSnapshot(
                std::move(rows),
                totalMatchCount,
                scannedRowCount,
                scannedMaxSequence);
        }, Qt::QueuedConnection);
    }).detach();
}

void MonitorDock::replaceEtwRowsWithSnapshot(
    std::deque<EtwCapturedEventRow> rows,
    const std::uint64_t totalMatchCount,
    const std::uint64_t scannedRowCount,
    const std::uint64_t scannedMaxSequence)
{
    if (etwEventTable_ == nullptr)
    {
        return;
    }

    // Background archival scanning replaces the entire table. Use a shared snapshot to avoid extra copying of thousands of
    // rows in the "non-lazy" path, and ensure that pending queue trimming does not occur prematurely when the menu is opened.
    const QPointer<MonitorDock> kGuardThis(this);
    const std::uint64_t kFilterTicketSnapshot =
        etwArchiveFilterTicket_.load(std::memory_order_relaxed);
    const std::uint64_t kSessionGenerationSnapshot =
        etwArchiveSessionGeneration_.load(std::memory_order_relaxed);
    const auto kDeferredRows =
        std::make_shared<std::deque<EtwCapturedEventRow>>(std::move(rows));
    if (ks::ui::deferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("monitor-etw-snapshot-replace"),
        { etwEventTable_ },
        [
            kGuardThis,
            kDeferredRows,
            totalMatchCount,
            scannedRowCount,
            scannedMaxSequence,
            kFilterTicketSnapshot,
            kSessionGenerationSnapshot]() mutable
        {
            if (!kGuardThis.isNull()
                && kGuardThis->etwArchiveFilterTicket_.load(std::memory_order_relaxed)
                    == kFilterTicketSnapshot
                && kGuardThis->etwArchiveSessionGeneration_.load(std::memory_order_relaxed)
                    == kSessionGenerationSnapshot)
            {
                kGuardThis->replaceEtwRowsWithSnapshot(
                    std::move(*kDeferredRows),
                    totalMatchCount,
                    scannedRowCount,
                    scannedMaxSequence);
            }
        }))
    {
        return;
    }
    rows = std::move(*kDeferredRows);

    constexpr std::size_t kMaximumVisibleRows = 6000;
    for (const EtwCapturedEventRow& liveRow : etwCapturedRows_)
    {
        if (liveRow.archiveSequence <= scannedMaxSequence)
        {
            continue;
        }

        bool matches = etwFilterStageMatches(
            etwPostSimpleFilterCompiled_,
            etwPostFilterCompiledGroupList_,
            liveRow);
        if (matches && isEtwTimelineFilterActive())
        {
            const std::uint64_t kTimestamp100ns = etwRawTimestampToTimelineTimestamp(liveRow.timestampValue);
            matches = kTimestamp100ns >= etwTimelineSelectionStart100ns_
                && kTimestamp100ns <= etwTimelineSelectionEnd100ns_;
        }
        if (matches)
        {
            rows.push_back(liveRow);
            if (rows.size() > kMaximumVisibleRows)
            {
                rows.pop_front();
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(etwPendingMutex_);
        while (!etwPendingRows_.empty()
            && etwPendingRows_.front().archiveSequence <= scannedMaxSequence)
        {
            etwPendingRows_.pop_front();
        }
    }

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

    etwEventTable_->setUpdatesEnabled(false);
    etwEventTable_->clearContents();
    etwEventTable_->setRowCount(static_cast<int>(rows.size()));
    etwCapturedRows_.clear();
    etwTimelineEventPoints_.clear();

    int tableRow = 0;
    for (EtwCapturedEventRow& rowData : rows)
    {
        etwCapturedRows_.push_back(std::move(rowData));
        const EtwCapturedEventRow& captured = etwCapturedRows_.back();
        QTableWidgetItem* sequenceItem = new QTableWidgetItem(QString::number(
            static_cast<qulonglong>(captured.archiveSequence != 0
                ? captured.archiveSequence
                : static_cast<std::uint64_t>(tableRow + 1))));
        sequenceItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        etwEventTable_->setVerticalHeaderItem(tableRow, sequenceItem);
        const QStringList kRowTextList{
            captured.timestampText,
            captured.providerName,
            QString::number(captured.eventId),
            captured.eventName,
            captured.pidTidText,
            captured.detailSummary,
            captured.activityId
        };
        for (int column = 0; column < kRowTextList.size(); ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(kRowTextList.at(column));
            item->setToolTip(kRowTextList.at(column));
            if (column == 5)
            {
                item->setData(Qt::UserRole, captured.detailJson);
            }
            etwEventTable_->setItem(tableRow, column, item);
        }

        ProcessTraceTimelineEventPoint timelinePoint;
        timelinePoint.time100ns = etwRawTimestampToTimelineTimestamp(captured.timestampValue);
        timelinePoint.typeText = etwTimelineTypeFromCapturedRow(captured);
        etwTimelineEventPoints_.push_back(std::move(timelinePoint));
        ++tableRow;
    }

    refreshEtwTimelineRange(!etwCaptureRunning_.load());
    refreshEtwTimelinePoints();
    etwEventTable_->setUpdatesEnabled(true);
    etwEventTable_->scrollToBottom();
    etwEventTable_->viewport()->update();

    if (etwPostSimpleFilterUi_.stateLabel != nullptr)
    {
        etwPostSimpleFilterUi_.stateLabel->setText(
            QStringLiteral("全量匹配: %1 | 当前显示最近: %2 | 已扫描: %3 | UI镜像跳过: %4（已归档）")
                .arg(static_cast<qulonglong>(totalMatchCount))
                .arg(etwEventTable_->rowCount())
                .arg(static_cast<qulonglong>(scannedRowCount))
                .arg(static_cast<qulonglong>(etwUiSkippedRows_.load(std::memory_order_relaxed))));
        ks::ui::applyStatusRole(etwPostSimpleFilterUi_.stateLabel, ks::ui::StatusRole::kInfo);
    }
}

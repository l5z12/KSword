#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::stopEtwCapture()
{
    stopEtwCaptureInternal(false);
}

void MonitorDock::stopEtwCaptureInternal(bool waitForThread)
{
    {
        KLogEvent event;
        info << event
            << "[MonitorDock] 停止ETW请求, waitForThread="
            << (waitForThread ? "true" : "false")
            << eol;
    }

    etwCaptureStopFlag_.store(true);
    if (etwCaptureRunning_.load() && etwCaptureStopTime100ns_ == 0)
    {
        // Freeze the right boundary of the timeline immediately when the stop button is pressed to avoid expanding the window while waiting for background threads to exit.
        etwCaptureStopTime100ns_ = etwCapturePaused_.load() && etwTimelinePauseTime100ns_ != 0
            ? etwTimelinePauseTime100ns_
            : currentSystemTime100ns();
        refreshEtwTimelineRange(true);
    }

    // Close the consumer handle first to break the ProcessTrace blocking call.
    const std::uint64_t kOwnedTraceHandle = etwTraceHandle_.exchange(0);
    if (kOwnedTraceHandle != 0)
    {
        ::CloseTrace(static_cast<TRACEHANDLE>(kOwnedTraceHandle));
    }

    // Stop the session again to ensure ETW kernel resources are released.
    const std::uint64_t kOwnedSessionHandle = etwSessionHandle_.exchange(0);
    if (kOwnedSessionHandle != 0)
    {
        const std::wstring kSessionNameWide = etwSessionName_.toStdWString();
        const ULONG kPropertyBufferSize = static_cast<ULONG>(
            sizeof(EVENT_TRACE_PROPERTIES) + (kSessionNameWide.size() + 1) * sizeof(wchar_t));
        std::vector<unsigned char> propertyBuffer(kPropertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = kPropertyBufferSize;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        wchar_t* loggerNamePtr = reinterpret_cast<wchar_t*>(propertyBuffer.data() + properties->LoggerNameOffset);
        if (!kSessionNameWide.empty())
        {
            ::wcscpy_s(loggerNamePtr, kSessionNameWide.size() + 1, kSessionNameWide.c_str());
        }

        ::ControlTraceW(
            static_cast<TRACEHANDLE>(kOwnedSessionHandle),
            loggerNamePtr,
            properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    if (etwCaptureThread_ == nullptr || !etwCaptureThread_->joinable())
    {
        // A paused state is possible even without a background thread; the stop boundary should follow the pause freeze point.
        const bool kWasPaused = etwCapturePaused_.load();
        const std::uint64_t kPauseEnd100ns = etwTimelinePauseTime100ns_;
        if (etwCaptureStopTime100ns_ == 0 && kWasPaused && kPauseEnd100ns != 0)
        {
            etwCaptureStopTime100ns_ = kPauseEnd100ns;
        }
        if (kWasPaused && kPauseEnd100ns != 0)
        {
            closeEtwTimelinePauseInterval(kPauseEnd100ns);
        }
        etwCaptureThread_.reset();
        etwCaptureRunning_.store(false);
        etwCapturePaused_.store(false);
        etwTimelinePauseTime100ns_ = 0;
        if (etwCaptureStatusLabel_ != nullptr)
        {
            const std::uint64_t kEventsLost = etwSourceEventsLost_.load(std::memory_order_relaxed);
            const bool kArchiveFailed = etwArchiveWriteFailed_.load(std::memory_order_relaxed);
            etwCaptureStatusLabel_->setText(kArchiveFailed
                ? QStringLiteral("● ETW归档写入失败")
                : (kEventsLost == 0
                    ? QStringLiteral("● 已停止")
                    : QStringLiteral("● ETW源事件丢失:%1").arg(static_cast<qulonglong>(kEventsLost))));
            ks::ui::applyStatusRole(etwCaptureStatusLabel_,
                !kArchiveFailed && kEventsLost == 0 ? ks::ui::StatusRole::kIdle : ks::ui::StatusRole::kError);
        }
        if (etwUiUpdateTimer_ != nullptr && etwUiUpdateTimer_->isActive())
        {
            etwUiUpdateTimer_->stop();
        }
        flushEtwPendingRows(true);
        scheduleEtwArchiveFilterRebuild();
        updateEtwCaptureActionState();
        KLogEvent event;
        dbg << event
            << "[MonitorDock] 停止ETW：当前无活动线程。"
            << eol;
        return;
    }

    if (waitForThread)
    {
        // Synchronous stop may originate from the destructor path; save the pause boundary before clearing the pause state.
        const bool kWasPaused = etwCapturePaused_.load();
        const std::uint64_t kPauseEnd100ns = etwTimelinePauseTime100ns_;
        if (etwCaptureStopTime100ns_ == 0 && kWasPaused && kPauseEnd100ns != 0)
        {
            etwCaptureStopTime100ns_ = kPauseEnd100ns;
        }
        if (kWasPaused && kPauseEnd100ns != 0)
        {
            closeEtwTimelinePauseInterval(kPauseEnd100ns);
        }
        // Destruct path: synchronously wait for the thread to exit, ensuring the ETW thread is fully cleaned up before object destruction.
        etwCaptureThread_->join();
        etwCaptureThread_.reset();
        etwCaptureRunning_.store(false);
        etwCapturePaused_.store(false);
        etwTimelinePauseTime100ns_ = 0;
        if (etwCaptureStatusLabel_ != nullptr)
        {
            const std::uint64_t kEventsLost = etwSourceEventsLost_.load(std::memory_order_relaxed);
            const bool kArchiveFailed = etwArchiveWriteFailed_.load(std::memory_order_relaxed);
            etwCaptureStatusLabel_->setText(kArchiveFailed
                ? QStringLiteral("● ETW归档写入失败")
                : (kEventsLost == 0
                    ? QStringLiteral("● 已停止")
                    : QStringLiteral("● ETW源事件丢失:%1").arg(static_cast<qulonglong>(kEventsLost))));
            ks::ui::applyStatusRole(etwCaptureStatusLabel_,
                !kArchiveFailed && kEventsLost == 0 ? ks::ui::StatusRole::kIdle : ks::ui::StatusRole::kError);
        }
        if (etwUiUpdateTimer_ != nullptr && etwUiUpdateTimer_->isActive())
        {
            etwUiUpdateTimer_->stop();
        }
        flushEtwPendingRows(true);
        scheduleEtwArchiveFilterRebuild();
        updateEtwCaptureActionState();
        KLogEvent event;
        info << event
            << "[MonitorDock] 停止ETW：同步等待线程结束完成。"
            << eol;
        return;
    }

    // Note: The interaction path only requests a stop; thread ownership must be retained for the destructor path.
    if (etwCaptureStatusLabel_ != nullptr)
    {
        etwCaptureStatusLabel_->setText(QStringLiteral("● 停止中..."));
        ks::ui::applyStatusRole(etwCaptureStatusLabel_, ks::ui::StatusRole::kWarning);
    }
    if (etwUiUpdateTimer_ != nullptr && etwUiUpdateTimer_->isActive())
    {
        etwUiUpdateTimer_->stop();
    }
    updateEtwCaptureActionState();
}

void MonitorDock::setEtwCapturePaused(bool paused)
{
    if (!etwCaptureRunning_.load())
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] 忽略ETW暂停操作：监听未运行。"
            << eol;
        return;
    }

    if (paused)
    {
        if (etwCapturePaused_.load() && etwTimelinePauseTime100ns_ != 0)
        {
            return;
        }
        // Record the original timestamp when paused; the timeline coordinates will deduct this wait duration during mapping.
        etwTimelinePauseTime100ns_ = currentSystemTime100ns();
        if (etwTimelinePauseTime100ns_ <= etwCaptureStartTime100ns_)
        {
            etwTimelinePauseTime100ns_ = etwCaptureStartTime100ns_ + 1;
        }
        etwCapturePaused_.store(true);
        // Immediately freeze the UI mirror. Keep the refresh queue intact, then resume batched display after continuing to listen.
        if (etwUiUpdateTimer_ != nullptr && etwUiUpdateTimer_->isActive())
        {
            etwUiUpdateTimer_->stop();
        }
        etwArchiveFilterTicket_.fetch_add(1, std::memory_order_relaxed);
        if (etwArchiveFilterDebounceTimer_ != nullptr)
        {
            etwArchiveFilterDebounceTimer_->stop();
        }
        refreshEtwTimelineRange(false);
        etwCaptureStatusLabel_->setText(QStringLiteral("● 已暂停"));
        ks::ui::applyStatusRole(etwCaptureStatusLabel_, ks::ui::StatusRole::kWarning);
    }
    else
    {
        // Lock the pause interval when resuming listening; subsequently, deduct this interval from the visible duration in the timeline.
        const std::uint64_t kResumeTime100ns = currentSystemTime100ns();
        closeEtwTimelinePauseInterval(kResumeTime100ns);
        etwCapturePaused_.store(false);
        etwTimelinePauseTime100ns_ = 0;
        if (etwUiUpdateTimer_ != nullptr && !etwUiUpdateTimer_->isActive())
        {
            etwUiUpdateTimer_->start();
        }
        refreshEtwTimelineRange(false);
        refreshEtwTimelinePoints();
        if (etwPostSimpleFilterCompiled_.hasAnyCondition()
            || !etwPostFilterCompiledGroupList_.empty()
            || isEtwTimelineFilterActive())
        {
            scheduleEtwArchiveFilterRebuild();
        }
        etwCaptureStatusLabel_->setText(QStringLiteral("● 监听中"));
        ks::ui::applyStatusRole(etwCaptureStatusLabel_, ks::ui::StatusRole::kInfo);
    }
    updateEtwCaptureActionState();

    KLogEvent event;
    info << event
        << "[MonitorDock] ETW暂停状态变更, paused="
        << (paused ? "true" : "false")
        << eol;
}

void MonitorDock::updateEtwCaptureActionState()
{
    const bool kRunning = etwCaptureRunning_.load();
    const bool kPaused = etwCapturePaused_.load();

    if (etwStartButton_ != nullptr)
    {
        etwStartButton_->setEnabled(!kRunning || kPaused);
        etwStartButton_->setIcon(QIcon(kPaused
            ? QStringLiteral(":/Icon/process_resume.svg")
            : QStringLiteral(":/Icon/process_start.svg")));
        etwStartButton_->setToolTip(kPaused
            ? QStringLiteral("继续监听")
            : QStringLiteral("开始监听"));
    }

    if (etwStopButton_ != nullptr)
    {
        etwStopButton_->setEnabled(kRunning);
    }

    if (etwPauseButton_ != nullptr)
    {
        etwPauseButton_->setEnabled(kRunning && !kPaused);
        etwPauseButton_->setIcon(QIcon(QStringLiteral(":/Icon/process_pause.svg")));
        etwPauseButton_->setToolTip(QStringLiteral("暂停监听"));
    }
}

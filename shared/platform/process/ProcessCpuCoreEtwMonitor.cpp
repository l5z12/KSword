#include "ProcessCpuCoreEtwMonitor.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

#pragma comment(lib, "Advapi32.lib")

namespace
{
    // Microsoft-Windows-Kernel-Thread classic provider (Thread_V2)。
    constexpr GUID kKernelThreadProviderGuid{
        0x3d6fa8d1,
        0xfe05,
        0x11d0,
        { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c }
    };

    // Independent System Logger session GUID base value; must not reuse SystemTraceControlGuid.
    constexpr GUID kKswordCpuCoreSessionGuidBase{
        0xd4392f18,
        0xb98b,
        0x4cc7,
        { 0xa4, 0x93, 0x3f, 0x14, 0x5c, 0xd1, 0xd9, 0x72 }
    };

    constexpr std::uint8_t kThreadStartOpcode = 1;
    constexpr std::uint8_t kThreadEndOpcode = 2;
    constexpr std::uint8_t kThreadDataCollectionStartOpcode = 3;
    constexpr std::uint8_t kThreadDataCollectionEndOpcode = 4;
    constexpr std::uint8_t kContextSwitchOpcode = 36;
    constexpr std::size_t kEtwSessionNameCapacity = 128;

    struct TracePropertiesBlock
    {
        EVENT_TRACE_PROPERTIES properties{};
        wchar_t loggerName[kEtwSessionNameCapacity]{};
    };

    GUID buildSessionGuid()
    {
        GUID sessionGuid = kKswordCpuCoreSessionGuidBase;
        sessionGuid.Data1 ^= static_cast<unsigned long>(::GetCurrentProcessId());
        return sessionGuid;
    }

    std::vector<ks::process::EtwLogicalProcessorCoordinate> enumerateActiveProcessors()
    {
        std::vector<ks::process::EtwLogicalProcessorCoordinate> processors;
        const WORD kGroupCount = ::GetActiveProcessorGroupCount();
        for (WORD group = 0; group < kGroupCount; ++group)
        {
            const DWORD kProcessorCount = ::GetActiveProcessorCount(group);
            for (DWORD number = 0; number < kProcessorCount; ++number)
            {
                ks::process::EtwLogicalProcessorCoordinate coordinate;
                coordinate.processorIndex = static_cast<std::uint32_t>(processors.size());
                coordinate.group = static_cast<std::uint16_t>(group);
                coordinate.number = static_cast<std::uint16_t>(number);
                processors.push_back(coordinate);
            }
        }

        // Fallback for old systems/restricted environments: retain at least one slot to prevent subsequent out-of-bounds access on an empty vector.
        if (processors.empty())
        {
            SYSTEM_INFO systemInfo{};
            ::GetSystemInfo(&systemInfo);
            const DWORD kProcessorCount = std::max<DWORD>(1, systemInfo.dwNumberOfProcessors);
            for (DWORD number = 0; number < kProcessorCount; ++number)
            {
                processors.push_back(ks::process::EtwLogicalProcessorCoordinate{
                    static_cast<std::uint32_t>(processors.size()),
                    0,
                    static_cast<std::uint16_t>(number) });
            }
        }
        return processors;
    }

    void initializeTraceProperties(
        TracePropertiesBlock* const block,
        const std::wstring& sessionName,
        const std::size_t processorCount)
    {
        if (block == nullptr)
        {
            return;
        }

        *block = TracePropertiesBlock{};
        block->properties.Wnode.BufferSize = sizeof(TracePropertiesBlock);
        block->properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        block->properties.Wnode.ClientContext = 1; // QPC timestamp, used for subtraction within the same core.
        block->properties.Wnode.Guid = buildSessionGuid();
        block->properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        block->properties.EnableFlags = EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_CSWITCH;
        block->properties.BufferSize = 64; // KiB; CSwitch is a high-frequency, small event, so avoid using excessively large buffers.
        block->properties.MinimumBuffers = 0; // Let ETW adjust based on the number of logical processors.
        block->properties.MaximumBuffers = static_cast<ULONG>(std::clamp<std::size_t>(
            processorCount * 4,
            64,
            1024));
        block->properties.FlushTimer = 1;
        block->properties.LoggerNameOffset = static_cast<ULONG>(offsetof(TracePropertiesBlock, loggerName));
        wcsncpy_s(block->loggerName, kEtwSessionNameCapacity, sessionName.c_str(), _TRUNCATE);
    }

    std::wstring buildSessionName()
    {
        // PID is part of session ownership: ensures a stable, diagnosable name and avoids conflicts with other live processes.
        return L"KSword.ProcessCpuCore." + std::to_wstring(::GetCurrentProcessId());
    }

    void stopOwnedTraceSession(
        const TRACEHANDLE sessionHandle,
        const std::wstring& sessionName,
        const std::size_t processorCount,
        std::uint64_t* const eventsLostOut)
    {
        if (sessionName.empty())
        {
            return;
        }

        TracePropertiesBlock propertiesBlock;
        initializeTraceProperties(&propertiesBlock, sessionName, processorCount);
        const ULONG kStopStatus = ::ControlTraceW(
            sessionHandle,
            sessionName.c_str(),
            &propertiesBlock.properties,
            EVENT_TRACE_CONTROL_STOP);
        if (kStopStatus == ERROR_SUCCESS && eventsLostOut != nullptr)
        {
            *eventsLostOut = static_cast<std::uint64_t>(propertiesBlock.properties.EventsLost);
        }
    }

    std::string makeEtwErrorText(const char* const operation, const ULONG errorCode)
    {
        std::ostringstream stream;
        stream << operation << " failed (Win32 error " << errorCode << ")";
        if (errorCode == ERROR_ACCESS_DENIED)
        {
            stream << "; administrator or Performance Log Users permission is required";
        }
        return stream.str();
    }

    double calculateUsagePercent(
        const std::uint64_t runtimeTicks,
        const std::uint64_t observedTicks)
    {
        if (observedTicks == 0)
        {
            return 0.0;
        }
        return std::clamp(
            (static_cast<double>(runtimeTicks) / static_cast<double>(observedTicks)) * 100.0,
            0.0,
            100.0);
    }
} // namespace

namespace ks::process
{
    std::uint64_t buildCpuThreadIdentity(
        const std::uint32_t processId,
        const std::uint32_t threadId)
    {
        return (static_cast<std::uint64_t>(processId) << 32U) |
            static_cast<std::uint64_t>(threadId);
    }

    ProcessCpuCoreEtwMonitor::ProcessCpuCoreEtwMonitor()
        : processors_(enumerateActiveProcessors()),
          lastTimestampByProcessor_(processors_.size(), 0),
          currentThreadIdByProcessor_(processors_.size(), 0),
          currentThreadKnownByProcessor_(processors_.size(), false),
          observedTicksByProcessor_(processors_.size(), 0)
    {
    }

    ProcessCpuCoreEtwMonitor::~ProcessCpuCoreEtwMonitor()
    {
        stop();
    }

    bool ProcessCpuCoreEtwMonitor::start()
    {
        std::lock_guard<std::mutex> lifecycleGuard(lifecycleMutex_);
        if (running_.load(std::memory_order_acquire))
        {
            return true;
        }

        if (consumerThread_.joinable())
        {
            consumerThread_.join();
        }
        std::uint64_t ignoredEventsLost = 0;
        stopOwnedTraceSession(sessionHandle_, sessionName_, processors_.size(), &ignoredEventsLost);
        sessionHandle_ = 0;
        consumerHandle_ = INVALID_PROCESSTRACE_HANDLE;
        sessionName_.clear();
        setLastErrorText(std::string());
        bufferEventsLost_.store(0, std::memory_order_relaxed);
        sessionEventsLost_.store(0, std::memory_order_relaxed);
        stopRequested_.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> counterGuard(counterMutex_);
            processRuntimeByPid_.clear();
            threadRuntimeByIdentity_.clear();
            processIdByThreadId_.clear();
            unresolvedThreadIds_.clear();
            std::fill(observedTicksByProcessor_.begin(), observedTicksByProcessor_.end(), 0);
            resetProcessorBaselinesLocked();
            contextSwitchEvents_ = 0;
            lastObservedBufferLoss_ = 0;
            lastSnapshotEventsLost_ = 0;
        }

        const std::wstring kSessionName = buildSessionName();
        // Clear sessions with the same name left over from a previous abnormal termination of the same PID. If the current instance is
        // still running, it would have returned at the function entry, so this will not stop a session owned by another live process.
        std::uint64_t ignoredOrphanLoss = 0;
        stopOwnedTraceSession(0, kSessionName, processors_.size(), &ignoredOrphanLoss);
        TracePropertiesBlock propertiesBlock;
        initializeTraceProperties(&propertiesBlock, kSessionName, processors_.size());

        TRACEHANDLE sessionHandle = 0;
        const ULONG kStartStatus = ::StartTraceW(
            &sessionHandle,
            kSessionName.c_str(),
            &propertiesBlock.properties);
        if (kStartStatus != ERROR_SUCCESS)
        {
            setLastErrorText(makeEtwErrorText("StartTraceW(CSwitch)", kStartStatus));
            return false;
        }

        sessionName_ = kSessionName;
        EVENT_TRACE_LOGFILEW traceLog{};
        traceLog.LoggerName = const_cast<wchar_t*>(sessionName_.c_str());
        traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLog.EventRecordCallback = &ProcessCpuCoreEtwMonitor::eventRecordCallback;
        traceLog.BufferCallback = &ProcessCpuCoreEtwMonitor::bufferCallback;
        traceLog.Context = this;

        const PROCESSTRACE_HANDLE kConsumerHandle = ::OpenTraceW(&traceLog);
        if (kConsumerHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG kOpenTraceError = ::GetLastError();
            std::uint64_t ignoredLoss = 0;
            stopOwnedTraceSession(sessionHandle, kSessionName, processors_.size(), &ignoredLoss);
            sessionName_.clear();
            setLastErrorText(makeEtwErrorText("OpenTraceW(CSwitch)", kOpenTraceError));
            return false;
        }

        sessionHandle_ = sessionHandle;
        consumerHandle_ = kConsumerHandle;
        running_.store(true, std::memory_order_release);
        try
        {
            consumerThread_ = std::thread(
                &ProcessCpuCoreEtwMonitor::consumeTrace,
                this,
                kConsumerHandle,
                sessionName_);
        }
        catch (...)
        {
            running_.store(false, std::memory_order_release);
            (void)::CloseTrace(kConsumerHandle);
            std::uint64_t ignoredLoss = 0;
            stopOwnedTraceSession(sessionHandle, kSessionName, processors_.size(), &ignoredLoss);
            sessionHandle_ = 0;
            consumerHandle_ = INVALID_PROCESSTRACE_HANDLE;
            sessionName_.clear();
            setLastErrorText("failed to create CSwitch ETW consumer thread");
            return false;
        }
        return true;
    }

    void ProcessCpuCoreEtwMonitor::stop()
    {
        std::lock_guard<std::mutex> lifecycleGuard(lifecycleMutex_);
        stopRequested_.store(true, std::memory_order_release);

        if (sessionHandle_ != 0 && !sessionName_.empty())
        {
            std::uint64_t sessionEventsLost = 0;
            stopOwnedTraceSession(
                sessionHandle_,
                sessionName_,
                processors_.size(),
                &sessionEventsLost);
            sessionEventsLost_.store(sessionEventsLost, std::memory_order_relaxed);
        }

        if (consumerThread_.joinable())
        {
            consumerThread_.join();
        }

        sessionHandle_ = 0;
        consumerHandle_ = INVALID_PROCESSTRACE_HANDLE;
        sessionName_.clear();
        running_.store(false, std::memory_order_release);
    }

    bool ProcessCpuCoreEtwMonitor::isRunning() const
    {
        return running_.load(std::memory_order_acquire);
    }

    std::string ProcessCpuCoreEtwMonitor::lastErrorText() const
    {
        std::lock_guard<std::mutex> errorGuard(errorMutex_);
        return lastErrorText_;
    }

    CpuCoreUsageSnapshot ProcessCpuCoreEtwMonitor::snapshotAndReset()
    {
        CpuCoreUsageSnapshot snapshot;
        snapshot.monitorRunning = isRunning();
        const std::uint64_t kTotalEventsLost = std::max(
            bufferEventsLost_.load(std::memory_order_relaxed),
            sessionEventsLost_.load(std::memory_order_relaxed));
        snapshot.diagnosticText = lastErrorText();

        std::lock_guard<std::mutex> counterGuard(counterMutex_);
        snapshot.eventsLost = kTotalEventsLost >= lastSnapshotEventsLost_
            ? kTotalEventsLost - lastSnapshotEventsLost_
            : kTotalEventsLost;
        snapshot.dataLossDetected = snapshot.eventsLost != 0;
        lastSnapshotEventsLost_ = kTotalEventsLost;
        LARGE_INTEGER snapshotTimestamp{};
        if (::QueryPerformanceCounter(&snapshotTimestamp) != FALSE)
        {
            const std::uint64_t kNowTicks = static_cast<std::uint64_t>(snapshotTimestamp.QuadPart);
            for (std::size_t processorIndex = 0;
                 processorIndex < processors_.size();
                 ++processorIndex)
            {
                const std::uint64_t kPreviousTimestamp =
                    lastTimestampByProcessor_[processorIndex];
                if (!currentThreadKnownByProcessor_[processorIndex] ||
                    kPreviousTimestamp == 0 ||
                    kNowTicks <= kPreviousTimestamp)
                {
                    continue;
                }

                // CSwitch only occurs at scheduling switch points; during snapshotting, the continuous runtime interval from the last switch to
                // now must be settled to the current thread, otherwise fully loaded threads that do not switch for a long time will be missed.
                const std::uint64_t kDeltaTicks = kNowTicks - kPreviousTimestamp;
                observedTicksByProcessor_[processorIndex] += kDeltaTicks;
                recordThreadRuntimeLocked(
                    processorIndex,
                    currentThreadIdByProcessor_[processorIndex],
                    kDeltaTicks);
                lastTimestampByProcessor_[processorIndex] = kNowTicks;
            }
        }
        snapshot.processors = processors_;
        snapshot.sampleReadyByProcessor.resize(processors_.size(), false);
        for (std::size_t processorIndex = 0; processorIndex < processors_.size(); ++processorIndex)
        {
            snapshot.sampleReadyByProcessor[processorIndex] =
                observedTicksByProcessor_[processorIndex] != 0;
        }
        snapshot.contextSwitchEvents = contextSwitchEvents_;
        snapshot.sampleReady = std::any_of(
            observedTicksByProcessor_.cbegin(),
            observedTicksByProcessor_.cend(),
            [](const std::uint64_t observedTicks) { return observedTicks != 0; });

        snapshot.liveThreadIdentities.reserve(processIdByThreadId_.size());
        for (const auto& ownerPair : processIdByThreadId_)
        {
            if (ownerPair.first != 0 && ownerPair.second != 0)
            {
                snapshot.liveThreadIdentities.push_back(
                    buildCpuThreadIdentity(ownerPair.second, ownerPair.first));
            }
        }
        std::sort(snapshot.liveThreadIdentities.begin(), snapshot.liveThreadIdentities.end());

        const auto kBuildSeries = [this](
            const std::uint32_t processId,
            const std::uint32_t threadId,
            const RuntimeCounter& runtimeCounter) -> CpuCoreUsageSeries
        {
            CpuCoreUsageSeries series;
            series.processId = processId;
            series.threadId = threadId;
            series.percentByProcessor.resize(processors_.size(), 0.0);
            series.sampleReadyByProcessor.resize(processors_.size(), false);
            for (std::size_t processorIndex = 0;
                 processorIndex < processors_.size();
                 ++processorIndex)
            {
                const std::uint64_t kObservedTicks = observedTicksByProcessor_[processorIndex];
                series.sampleReadyByProcessor[processorIndex] = kObservedTicks != 0;
                const std::uint64_t kRuntimeTicks =
                    processorIndex < runtimeCounter.ticksByProcessor.size()
                    ? runtimeCounter.ticksByProcessor[processorIndex]
                    : 0;
                const double kPercent = calculateUsagePercent(kRuntimeTicks, kObservedTicks);
                series.percentByProcessor[processorIndex] = kPercent;
                series.coreEquivalentPercent += kPercent;
            }
            if (threadId != 0)
            {
                series.coreEquivalentPercent = std::clamp(series.coreEquivalentPercent, 0.0, 100.0);
            }
            return series;
        };

        snapshot.processUsageByPid.reserve(processRuntimeByPid_.size());
        for (const auto& runtimePair : processRuntimeByPid_)
        {
            snapshot.processUsageByPid.emplace(
                runtimePair.first,
                kBuildSeries(runtimePair.first, 0, runtimePair.second));
        }

        snapshot.threadUsageByIdentity.reserve(threadRuntimeByIdentity_.size());
        for (const auto& runtimePair : threadRuntimeByIdentity_)
        {
            const std::uint32_t kProcessId = static_cast<std::uint32_t>(runtimePair.first >> 32U);
            const std::uint32_t kThreadId = static_cast<std::uint32_t>(runtimePair.first & 0xffffffffULL);
            snapshot.threadUsageByIdentity.emplace(
                runtimePair.first,
                kBuildSeries(kProcessId, kThreadId, runtimePair.second));
        }

        processRuntimeByPid_.clear();
        threadRuntimeByIdentity_.clear();
        std::fill(observedTicksByProcessor_.begin(), observedTicksByProcessor_.end(), 0);
        contextSwitchEvents_ = 0;
        return snapshot;
    }

    void WINAPI ProcessCpuCoreEtwMonitor::eventRecordCallback(PEVENT_RECORD const eventRecord)
    {
        if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
        {
            return;
        }
        static_cast<ProcessCpuCoreEtwMonitor*>(eventRecord->UserContext)->recordEvent(*eventRecord);
    }

    ULONG WINAPI ProcessCpuCoreEtwMonitor::bufferCallback(PEVENT_TRACE_LOGFILEW const logFile)
    {
        if (logFile == nullptr || logFile->Context == nullptr)
        {
            return TRUE;
        }

        auto* const kMonitor = static_cast<ProcessCpuCoreEtwMonitor*>(logFile->Context);
        if (logFile->EventsLost != 0)
        {
            kMonitor->bufferEventsLost_.store(logFile->EventsLost, std::memory_order_relaxed);
            std::lock_guard<std::mutex> counterGuard(kMonitor->counterMutex_);
            if (kMonitor->lastObservedBufferLoss_ != logFile->EventsLost)
            {
                // After losing events, do not attribute the duration across the gap to the current OldThreadId; rebuild all core baselines.
                kMonitor->resetProcessorBaselinesLocked();
                kMonitor->lastObservedBufferLoss_ = logFile->EventsLost;
            }
        }
        return kMonitor->stopRequested_.load(std::memory_order_acquire) ? FALSE : TRUE;
    }

    void ProcessCpuCoreEtwMonitor::consumeTrace(
        const PROCESSTRACE_HANDLE consumerHandle,
        std::wstring sessionName)
    {
        PROCESSTRACE_HANDLE activeConsumerHandle = consumerHandle;
        const ULONG kProcessStatus = ::ProcessTrace(&activeConsumerHandle, 1, nullptr, nullptr);
        (void)::CloseTrace(consumerHandle);

        if (!stopRequested_.load(std::memory_order_acquire) &&
            kProcessStatus != ERROR_SUCCESS &&
            kProcessStatus != ERROR_CANCELLED)
        {
            setLastErrorText(makeEtwErrorText("ProcessTrace(CSwitch)", kProcessStatus));
            std::uint64_t eventsLost = 0;
            stopOwnedTraceSession(sessionHandle_, sessionName, processors_.size(), &eventsLost);
            sessionEventsLost_.store(eventsLost, std::memory_order_relaxed);
        }
        running_.store(false, std::memory_order_release);
    }

    void ProcessCpuCoreEtwMonitor::recordEvent(const EVENT_RECORD& eventRecord)
    {
        if (!::IsEqualGUID(eventRecord.EventHeader.ProviderId, kKernelThreadProviderGuid))
        {
            return;
        }

        const std::uint8_t kOpcode = eventRecord.EventHeader.EventDescriptor.Opcode;
        if (kOpcode == kContextSwitchOpcode)
        {
            recordContextSwitchEvent(eventRecord);
            return;
        }
        if (kOpcode == kThreadStartOpcode ||
            kOpcode == kThreadEndOpcode ||
            kOpcode == kThreadDataCollectionStartOpcode ||
            kOpcode == kThreadDataCollectionEndOpcode)
        {
            recordThreadLifecycleEvent(eventRecord, kOpcode);
        }
    }

    void ProcessCpuCoreEtwMonitor::recordThreadLifecycleEvent(
        const EVENT_RECORD& eventRecord,
        const std::uint8_t opcode)
    {
        // The first two MOF fields of Thread_V2 TypeGroup1 are fixed as ProcessId and TThreadId;
        // Use memcpy to avoid dereferencing UserData directly when it is misaligned.
        if (eventRecord.UserData == nullptr || eventRecord.UserDataLength < sizeof(std::uint32_t) * 2)
        {
            return;
        }
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::memcpy(&processId, eventRecord.UserData, sizeof(processId));
        std::memcpy(
            &threadId,
            static_cast<const std::uint8_t*>(eventRecord.UserData) + sizeof(processId),
            sizeof(threadId));
        if (threadId == 0)
        {
            return;
        }

        std::lock_guard<std::mutex> counterGuard(counterMutex_);
        if (opcode == kThreadStartOpcode || opcode == kThreadDataCollectionStartOpcode)
        {
            processIdByThreadId_[threadId] = processId;
            unresolvedThreadIds_.erase(threadId);
        }
        else
        {
            processIdByThreadId_.erase(threadId);
            unresolvedThreadIds_.erase(threadId);
        }
    }

    void ProcessCpuCoreEtwMonitor::recordContextSwitchEvent(const EVENT_RECORD& eventRecord)
    {
        // The first two fields before CSwitch are fixed as NewThreadId and OldThreadId.
        if (eventRecord.UserData == nullptr || eventRecord.UserDataLength < sizeof(std::uint32_t) * 2)
        {
            return;
        }
        std::uint32_t newThreadId = 0;
        std::uint32_t oldThreadId = 0;
        std::memcpy(&newThreadId, eventRecord.UserData, sizeof(newThreadId));
        std::memcpy(
            &oldThreadId,
            static_cast<const std::uint8_t*>(eventRecord.UserData) + sizeof(newThreadId),
            sizeof(oldThreadId));

        const std::uint32_t kProcessorIndex = ::GetEventProcessorIndex(&eventRecord);
        if (kProcessorIndex >= processors_.size())
        {
            return;
        }
        const std::uint64_t kTimestamp = static_cast<std::uint64_t>(eventRecord.EventHeader.TimeStamp.QuadPart);

        std::lock_guard<std::mutex> counterGuard(counterMutex_);
        ++contextSwitchEvents_;
        if (newThreadId != 0 &&
            processIdByThreadId_.find(newThreadId) == processIdByThreadId_.end())
        {
            (void)resolveThreadOwnerLocked(newThreadId);
        }

        const std::uint64_t kPreviousTimestamp = lastTimestampByProcessor_[kProcessorIndex];
        if (kPreviousTimestamp != 0 && kTimestamp <= kPreviousTimestamp)
        {
            return;
        }
        if (kPreviousTimestamp != 0)
        {
            const std::uint64_t kDeltaTicks = kTimestamp - kPreviousTimestamp;
            observedTicksByProcessor_[kProcessorIndex] += kDeltaTicks;
            recordThreadRuntimeLocked(kProcessorIndex, oldThreadId, kDeltaTicks);
        }
        lastTimestampByProcessor_[kProcessorIndex] = kTimestamp;
        currentThreadIdByProcessor_[kProcessorIndex] = newThreadId;
        currentThreadKnownByProcessor_[kProcessorIndex] = true;
    }

    void ProcessCpuCoreEtwMonitor::recordThreadRuntimeLocked(
        const std::size_t processorIndex,
        const std::uint32_t threadId,
        const std::uint64_t deltaTicks)
    {
        if (threadId == 0 || deltaTicks == 0 || processorIndex >= processors_.size())
        {
            return; // Idle threads are only included in the denominator, not attributed to any user process.
        }

        const std::uint32_t kProcessId = resolveThreadOwnerLocked(threadId);
        if (kProcessId == 0)
        {
            return;
        }

        RuntimeCounter& processCounter = processRuntimeByPid_[kProcessId];
        if (processCounter.ticksByProcessor.size() != processors_.size())
        {
            processCounter.ticksByProcessor.assign(processors_.size(), 0);
        }
        processCounter.ticksByProcessor[processorIndex] += deltaTicks;

        RuntimeCounter& threadCounter =
            threadRuntimeByIdentity_[buildCpuThreadIdentity(kProcessId, threadId)];
        if (threadCounter.ticksByProcessor.size() != processors_.size())
        {
            threadCounter.ticksByProcessor.assign(processors_.size(), 0);
        }
        threadCounter.ticksByProcessor[processorIndex] += deltaTicks;
    }

    std::uint32_t ProcessCpuCoreEtwMonitor::resolveThreadOwnerLocked(const std::uint32_t threadId)
    {
        const auto kOwnerIt = processIdByThreadId_.find(threadId);
        if (kOwnerIt != processIdByThreadId_.end())
        {
            return kOwnerIt->second;
        }
        if (unresolvedThreadIds_.find(threadId) != unresolvedThreadIds_.end())
        {
            return 0;
        }

        // Query the handle only once before thread rundown completes; subsequent Start/DCStart events will overwrite the cache.
        std::uint32_t processId = 0;
        HANDLE threadHandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
        if (threadHandle != nullptr)
        {
            processId = static_cast<std::uint32_t>(::GetProcessIdOfThread(threadHandle));
            ::CloseHandle(threadHandle);
        }
        if (processId != 0)
        {
            processIdByThreadId_[threadId] = processId;
        }
        else
        {
            unresolvedThreadIds_.insert(threadId);
        }
        return processId;
    }

    void ProcessCpuCoreEtwMonitor::resetProcessorBaselinesLocked()
    {
        std::fill(lastTimestampByProcessor_.begin(), lastTimestampByProcessor_.end(), 0);
        std::fill(currentThreadIdByProcessor_.begin(), currentThreadIdByProcessor_.end(), 0);
        std::fill(currentThreadKnownByProcessor_.begin(), currentThreadKnownByProcessor_.end(), false);
    }

    void ProcessCpuCoreEtwMonitor::setLastErrorText(std::string errorText)
    {
        std::lock_guard<std::mutex> errorGuard(errorMutex_);
        lastErrorText_ = std::move(errorText);
    }
} // namespace ks::process

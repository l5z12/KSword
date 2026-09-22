#include "NetworkProcessEtwMonitor.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>

namespace
{
    // Microsoft-Windows-Kernel-Network。
    // The send/receive events for this Manifest Provider follow the TCPIP/UDPIP v2 layout:
    // UserData[0..3] contains the PID; UserData[4..7] contains the actual transmitted byte count.
    constexpr GUID kKernelNetworkProviderGuid{
        0x7dd42a49,
        0x5329,
        0x4832,
        { 0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x88 }
    };

    constexpr ULONGLONG kKernelNetworkIpv4Keyword = 0x10ULL;
    constexpr ULONGLONG kKernelNetworkIpv6Keyword = 0x20ULL;

    constexpr USHORT kTcpIpv4SendEventId = 10;
    constexpr USHORT kTcpIpv4ReceiveEventId = 11;
    constexpr USHORT kTcpIpv6SendEventId = 26;
    constexpr USHORT kTcpIpv6ReceiveEventId = 27;
    constexpr USHORT kUdpIpv4SendEventId = 42;
    constexpr USHORT kUdpIpv4ReceiveEventId = 43;
    constexpr USHORT kUdpIpv6SendEventId = 58;
    constexpr USHORT kUdpIpv6ReceiveEventId = 59;

    constexpr std::size_t kEtwSessionNameCapacity = 128;

    struct TracePropertiesBlock
    {
        EVENT_TRACE_PROPERTIES properties{};
        wchar_t loggerName[kEtwSessionNameCapacity]{};
    };

    std::atomic<std::uint32_t> gSessionSequence{ 0 };

    void initializeTraceProperties(TracePropertiesBlock* const block, const std::wstring& sessionName)
    {
        if (block == nullptr)
        {
            return;
        }

        *block = TracePropertiesBlock{};
        block->properties.Wnode.BufferSize = sizeof(TracePropertiesBlock);
        block->properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        block->properties.Wnode.ClientContext = 1; // QPC timestamp.
        block->properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        block->properties.BufferSize = 64;         // KiB。
        block->properties.MinimumBuffers = 4;
        block->properties.MaximumBuffers = 64;
        block->properties.FlushTimer = 1;
        block->properties.LoggerNameOffset = static_cast<ULONG>(offsetof(TracePropertiesBlock, loggerName));
        wcsncpy_s(block->loggerName, kEtwSessionNameCapacity, sessionName.c_str(), _TRUNCATE);
    }

    std::wstring buildSessionName()
    {
        const std::uint32_t kSequence = gSessionSequence.fetch_add(1, std::memory_order_relaxed);
        return L"Ksword.ProcessNet." +
            std::to_wstring(::GetCurrentProcessId()) + L"." +
            std::to_wstring(::GetTickCount64()) + L"." +
            std::to_wstring(kSequence);
    }

    void stopOwnedTraceSession(const TRACEHANDLE sessionHandle, const std::wstring& sessionName)
    {
        if (sessionHandle == 0 || sessionName.empty())
        {
            return;
        }

        TracePropertiesBlock traceProperties;
        initializeTraceProperties(&traceProperties, sessionName);
        (void)::ControlTraceW(
            sessionHandle,
            sessionName.c_str(),
            &traceProperties.properties,
            EVENT_TRACE_CONTROL_STOP);
    }

    std::string makeEtwErrorText(const char* const operation, const ULONG errorCode)
    {
        std::ostringstream stream;
        stream << operation << " failed (Win32 error " << errorCode << ")";
        return stream.str();
    }

    bool resolveNetworkDirection(const USHORT eventId, bool* const isInbound)
    {
        if (isInbound == nullptr)
        {
            return false;
        }

        switch (eventId)
        {
        case kTcpIpv4SendEventId:
        case kTcpIpv6SendEventId:
        case kUdpIpv4SendEventId:
        case kUdpIpv6SendEventId:
            *isInbound = false;
            return true;

        case kTcpIpv4ReceiveEventId:
        case kTcpIpv6ReceiveEventId:
        case kUdpIpv4ReceiveEventId:
        case kUdpIpv6ReceiveEventId:
            *isInbound = true;
            return true;

        default:
            return false;
        }
    }
} // namespace

namespace ks::network
{
    ProcessNetworkEtwMonitor::~ProcessNetworkEtwMonitor()
    {
        stop();
    }

    bool ProcessNetworkEtwMonitor::start()
    {
        std::lock_guard<std::mutex> lifecycleGuard(lifecycleMutex_);
        if (running_.load(std::memory_order_acquire))
        {
            return true;
        }

        // If the previous consumer thread has naturally exited, wait for it to complete resource release first.
        if (consumerThread_.joinable())
        {
            consumerThread_.join();
        }
        stopOwnedTraceSession(sessionHandle_, sessionName_);
        sessionHandle_ = 0;
        consumerHandle_ = INVALID_PROCESSTRACE_HANDLE;
        sessionName_.clear();
        setLastErrorText(std::string());
        bufferEventsLost_.store(0, std::memory_order_relaxed);
        sessionEventsLost_.store(0, std::memory_order_relaxed);
        stopRequested_.store(false, std::memory_order_release);

        const std::wstring kSessionName = buildSessionName();
        TracePropertiesBlock traceProperties;
        initializeTraceProperties(&traceProperties, kSessionName);

        TRACEHANDLE sessionHandle = 0;
        const ULONG kStartResult = ::StartTraceW(
            &sessionHandle,
            kSessionName.c_str(),
            &traceProperties.properties);
        if (kStartResult != ERROR_SUCCESS)
        {
            setLastErrorText(makeEtwErrorText("StartTraceW", kStartResult));
            return false;
        }

        const ULONG kEnableResult = ::EnableTraceEx2(
            sessionHandle,
            &kKernelNetworkProviderGuid,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_INFORMATION,
            kKernelNetworkIpv4Keyword | kKernelNetworkIpv6Keyword,
            0,
            0,
            nullptr);
        if (kEnableResult != ERROR_SUCCESS)
        {
            stopOwnedTraceSession(sessionHandle, kSessionName);
            setLastErrorText(makeEtwErrorText("EnableTraceEx2(Microsoft-Windows-Kernel-Network)", kEnableResult));
            return false;
        }

        sessionName_ = kSessionName;
        EVENT_TRACE_LOGFILEW traceLog{};
        traceLog.LoggerName = const_cast<wchar_t*>(sessionName_.c_str());
        traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        traceLog.EventRecordCallback = &ProcessNetworkEtwMonitor::eventRecordCallback;
        traceLog.BufferCallback = &ProcessNetworkEtwMonitor::bufferCallback;
        traceLog.Context = this;

        const PROCESSTRACE_HANDLE kConsumerHandle = ::OpenTraceW(&traceLog);
        if (kConsumerHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG kOpenTraceError = ::GetLastError();
            stopOwnedTraceSession(sessionHandle, kSessionName);
            sessionName_.clear();
            setLastErrorText(makeEtwErrorText("OpenTraceW", kOpenTraceError));
            return false;
        }

        sessionHandle_ = sessionHandle;
        consumerHandle_ = kConsumerHandle;
        running_.store(true, std::memory_order_release);
        try
        {
            consumerThread_ = std::thread(&ProcessNetworkEtwMonitor::consumeTrace, this, kConsumerHandle, sessionName_);
        }
        catch (...)
        {
            running_.store(false, std::memory_order_release);
            (void)::CloseTrace(kConsumerHandle);
            stopOwnedTraceSession(sessionHandle, kSessionName);
            sessionHandle_ = 0;
            consumerHandle_ = INVALID_PROCESSTRACE_HANDLE;
            sessionName_.clear();
            setLastErrorText("failed to create ETW consumer thread");
            return false;
        }

        return true;
    }

    void ProcessNetworkEtwMonitor::stop()
    {
        std::lock_guard<std::mutex> lifecycleGuard(lifecycleMutex_);
        stopRequested_.store(true, std::memory_order_release);

        if (sessionHandle_ != 0 && !sessionName_.empty())
        {
            TracePropertiesBlock traceProperties;
            initializeTraceProperties(&traceProperties, sessionName_);
            const ULONG kStopResult = ::ControlTraceW(
                sessionHandle_,
                sessionName_.c_str(),
                &traceProperties.properties,
                EVENT_TRACE_CONTROL_STOP);
            if (kStopResult == ERROR_SUCCESS)
            {
                sessionEventsLost_.store(
                    static_cast<std::uint64_t>(traceProperties.properties.EventsLost),
                    std::memory_order_relaxed);
            }
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

    bool ProcessNetworkEtwMonitor::isRunning() const
    {
        return running_.load(std::memory_order_acquire);
    }

    std::string ProcessNetworkEtwMonitor::lastErrorText() const
    {
        std::lock_guard<std::mutex> errorGuard(errorMutex_);
        return lastErrorText_;
    }

    ProcessNetworkEtwHealth ProcessNetworkEtwMonitor::snapshotHealth() const
    {
        const std::uint64_t kBufferEventsLost = bufferEventsLost_.load(std::memory_order_relaxed);
        const std::uint64_t kSessionEventsLost = sessionEventsLost_.load(std::memory_order_relaxed);

        ProcessNetworkEtwHealth health;
        health.isRunning = isRunning();
        health.eventsLost = std::max(kBufferEventsLost, kSessionEventsLost);
        health.dataLossDetected = (health.eventsLost != 0);
        return health;
    }

    std::unordered_map<std::uint32_t, ProcessNetworkTrafficCounters>
    ProcessNetworkEtwMonitor::snapshotCounters() const
    {
        std::lock_guard<std::mutex> counterGuard(counterMutex_);
        return countersByPid_;
    }

    void ProcessNetworkEtwMonitor::pruneCounters(const std::unordered_set<std::uint32_t>& liveProcessIds)
    {
        std::lock_guard<std::mutex> counterGuard(counterMutex_);
        for (auto counterIt = countersByPid_.begin(); counterIt != countersByPid_.end();)
        {
            if (liveProcessIds.find(counterIt->first) == liveProcessIds.end())
            {
                counterIt = countersByPid_.erase(counterIt);
            }
            else
            {
                ++counterIt;
            }
        }
    }

    void WINAPI ProcessNetworkEtwMonitor::eventRecordCallback(PEVENT_RECORD const eventRecord)
    {
        if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
        {
            return;
        }

        auto* const kMonitor = static_cast<ProcessNetworkEtwMonitor*>(eventRecord->UserContext);
        kMonitor->recordNetworkEvent(*eventRecord);
    }

    ULONG WINAPI ProcessNetworkEtwMonitor::bufferCallback(PEVENT_TRACE_LOGFILEW const logFile)
    {
        if (logFile == nullptr || logFile->Context == nullptr)
        {
            return TRUE;
        }

        auto* const kMonitor = static_cast<ProcessNetworkEtwMonitor*>(logFile->Context);
        if (logFile->EventsLost != 0)
        {
            kMonitor->bufferEventsLost_.fetch_add(logFile->EventsLost, std::memory_order_relaxed);
        }
        return kMonitor->stopRequested_.load(std::memory_order_acquire) ? FALSE : TRUE;
    }

    void ProcessNetworkEtwMonitor::consumeTrace(
        const PROCESSTRACE_HANDLE consumerHandle,
        std::wstring sessionName)
    {
        PROCESSTRACE_HANDLE activeConsumerHandle = consumerHandle;
        const ULONG kProcessResult = ::ProcessTrace(
            &activeConsumerHandle,
            1,
            nullptr,
            nullptr);
        (void)::CloseTrace(consumerHandle);

        if (!stopRequested_.load(std::memory_order_acquire) &&
            kProcessResult != ERROR_SUCCESS &&
            kProcessResult != ERROR_CANCELLED)
        {
            setLastErrorText(makeEtwErrorText("ProcessTrace", kProcessResult));
            stopOwnedTraceSession(sessionHandle_, sessionName);
        }

        running_.store(false, std::memory_order_release);
    }

    void ProcessNetworkEtwMonitor::recordNetworkEvent(const EVENT_RECORD& eventRecord)
    {
        if (!::IsEqualGUID(eventRecord.EventHeader.ProviderId, kKernelNetworkProviderGuid) ||
            eventRecord.UserData == nullptr ||
            eventRecord.UserDataLength < (sizeof(std::uint32_t) * 2))
        {
            return;
        }

        bool isInbound = false;
        if (!resolveNetworkDirection(eventRecord.EventHeader.EventDescriptor.Id, &isInbound))
        {
            return;
        }

        std::uint32_t processId = 0;
        std::uint32_t transferBytes = 0;
        std::memcpy(&processId, eventRecord.UserData, sizeof(processId));
        std::memcpy(
            &transferBytes,
            static_cast<const std::uint8_t*>(eventRecord.UserData) + sizeof(processId),
            sizeof(transferBytes));
        if (processId == 0 || transferBytes == 0)
        {
            return;
        }

        std::lock_guard<std::mutex> counterGuard(counterMutex_);
        ProcessNetworkTrafficCounters& counters = countersByPid_[processId];
        if (isInbound)
        {
            counters.rxBytes += static_cast<std::uint64_t>(transferBytes);
        }
        else
        {
            counters.txBytes += static_cast<std::uint64_t>(transferBytes);
        }
    }

    void ProcessNetworkEtwMonitor::setLastErrorText(std::string errorText)
    {
        std::lock_guard<std::mutex> errorGuard(errorMutex_);
        lastErrorText_ = std::move(errorText);
    }
} // namespace ks::network

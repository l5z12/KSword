#pragma once

// ============================================================
// process_cpu_core_etw_monitor.h
// Purpose:
// - Consume Windows kernel thread CSwitch ETW events.
// - Calculate cumulative real running time by PID/TID and logical processor;
// - For displaying per-core CPU usage of processes and threads on the "CPU Core" page of process details.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ks::process
{
    // EtwLogicalProcessorCoordinate: Global ETW logical processor coordinates spanning Processor Groups.
    struct EtwLogicalProcessorCoordinate
    {
        std::uint32_t processorIndex = 0; // ETW global processor index.
        std::uint16_t group = 0;          // Processor Group number.
        std::uint16_t number = 0;         // Logical processor number within the group.
    };

    // CpuCoreUsageSeries: Interval usage of a process or thread across all logical processors.
    struct CpuCoreUsageSeries
    {
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;       // Process ID is fixed at 0; thread ID is the actual TID.
        double coreEquivalentPercent = 0.0; // Sum of per-core utilization; a thread theoretically cannot exceed 100%.
        std::vector<double> percentByProcessor;
        std::vector<bool> sampleReadyByProcessor;
    };

    // CpuCoreUsageSnapshot: Per-core snapshot for a single UI refresh interval.
    struct CpuCoreUsageSnapshot
    {
        bool monitorRunning = false;
        bool sampleReady = false;
        bool dataLossDetected = false;
        std::uint64_t eventsLost = 0;
        std::uint64_t contextSwitchEvents = 0;
        std::string diagnosticText;
        std::vector<EtwLogicalProcessorCoordinate> processors;
        std::vector<bool> sampleReadyByProcessor;
        std::vector<std::uint64_t> liveThreadIdentities;
        std::unordered_map<std::uint32_t, CpuCoreUsageSeries> processUsageByPid;
        std::unordered_map<std::uint64_t, CpuCoreUsageSeries> threadUsageByIdentity;
    };

    // buildCpuThreadIdentity: PID/TID composite key to avoid confusion between thread IDs of different processes.
    std::uint64_t buildCpuThreadIdentity(std::uint32_t processId, std::uint32_t threadId);

    // ProcessCpuCoreEtwMonitor：
    // - Start/Stop manages the System Logger real-time sessions owned by this instance.
    // - The callback only parses fixed-length fields and counts; it does not dispatch individual event objects to the UI;
    // - snapshotAndReset: Creates a flush interval and clears the interval's accumulated values.
    class ProcessCpuCoreEtwMonitor final
    {
    public:
        ProcessCpuCoreEtwMonitor();
        ~ProcessCpuCoreEtwMonitor();

        ProcessCpuCoreEtwMonitor(const ProcessCpuCoreEtwMonitor&) = delete;
        ProcessCpuCoreEtwMonitor& operator=(const ProcessCpuCoreEtwMonitor&) = delete;

        bool start();
        void stop();
        bool isRunning() const;
        std::string lastErrorText() const;
        CpuCoreUsageSnapshot snapshotAndReset();

    private:
        struct RuntimeCounter
        {
            std::vector<std::uint64_t> ticksByProcessor;
        };

        static void WINAPI eventRecordCallback(PEVENT_RECORD eventRecord);
        static ULONG WINAPI bufferCallback(PEVENT_TRACE_LOGFILEW logFile);

        void consumeTrace(PROCESSTRACE_HANDLE consumerHandle, std::wstring sessionName);
        void recordEvent(const EVENT_RECORD& eventRecord);
        void recordThreadLifecycleEvent(const EVENT_RECORD& eventRecord, std::uint8_t opcode);
        void recordContextSwitchEvent(const EVENT_RECORD& eventRecord);
        void recordThreadRuntimeLocked(
            std::size_t processorIndex,
            std::uint32_t threadId,
            std::uint64_t deltaTicks);
        std::uint32_t resolveThreadOwnerLocked(std::uint32_t threadId);
        void resetProcessorBaselinesLocked();
        void setLastErrorText(std::string errorText);

    private:
        mutable std::mutex lifecycleMutex_;
        std::thread consumerThread_;
        TRACEHANDLE sessionHandle_ = 0;
        PROCESSTRACE_HANDLE consumerHandle_ = INVALID_PROCESSTRACE_HANDLE;
        std::wstring sessionName_;

        std::atomic_bool running_{ false };
        std::atomic_bool stopRequested_{ false };
        std::atomic<std::uint64_t> bufferEventsLost_{ 0 };
        std::atomic<std::uint64_t> sessionEventsLost_{ 0 };

        mutable std::mutex counterMutex_;
        std::vector<EtwLogicalProcessorCoordinate> processors_;
        std::vector<std::uint64_t> lastTimestampByProcessor_;
        std::vector<std::uint32_t> currentThreadIdByProcessor_;
        std::vector<bool> currentThreadKnownByProcessor_;
        std::vector<std::uint64_t> observedTicksByProcessor_;
        std::unordered_map<std::uint32_t, RuntimeCounter> processRuntimeByPid_;
        std::unordered_map<std::uint64_t, RuntimeCounter> threadRuntimeByIdentity_;
        std::unordered_map<std::uint32_t, std::uint32_t> processIdByThreadId_;
        std::unordered_set<std::uint32_t> unresolvedThreadIds_;
        std::uint64_t contextSwitchEvents_ = 0;
        std::uint64_t lastObservedBufferLoss_ = 0;
        std::uint64_t lastSnapshotEventsLost_ = 0;

        mutable std::mutex errorMutex_;
        std::string lastErrorText_;
    };
} // namespace ks::process

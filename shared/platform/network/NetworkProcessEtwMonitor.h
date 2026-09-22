#pragma once

// ============================================================
// ksword/network/network_process_etw_monitor.h
// Purpose:
// - Aggregate per-process network bytes via the Microsoft-Windows-Kernel-Network ETW Provider;
// - Process only PID, direction, and transfer size; do not copy packets or enumerate the connection table.
// - Use an independent real-time ETW session; never take over the NT Kernel Logger.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ks::network
{
    // ProcessNetworkTrafficCounters: Cumulative received and transmitted byte counts for a single PID.
    struct ProcessNetworkTrafficCounters
    {
        std::uint64_t rxBytes = 0;
        std::uint64_t txBytes = 0;
    };

    // ProcessNetworkEtwHealth: ETW session running status and detected data loss amount.
    struct ProcessNetworkEtwHealth
    {
        bool isRunning = false;
        bool dataLossDetected = false;
        std::uint64_t eventsLost = 0;
    };

    // ProcessNetworkEtwMonitor：
    // - Start/Stop manage an exclusive private real-time ETW Session;
    // - The callback thread accumulates bytes directly by PID; the UI only takes a snapshot during refresh.
    // - does not dispatch per-packet events to the UI to avoid overwhelming the GUI thread during network activity.
    class ProcessNetworkEtwMonitor final
    {
    public:
        ProcessNetworkEtwMonitor() = default;
        ~ProcessNetworkEtwMonitor();

        ProcessNetworkEtwMonitor(const ProcessNetworkEtwMonitor&) = delete;
        ProcessNetworkEtwMonitor& operator=(const ProcessNetworkEtwMonitor&) = delete;

        // Start: Create a private ETW session and enable the Kernel-Network Provider.
        // If false is returned, the failure reason can be retrieved via lastErrorText.
        bool start();

        // Stop: Stops the session created by this instance and waits for the ETW consumer thread to exit.
        void stop();

        bool isRunning() const;
        std::string lastErrorText() const;
        ProcessNetworkEtwHealth snapshotHealth() const;

        // snapshotCounters: Copies the current PID -> cumulative byte table.
        std::unordered_map<std::uint32_t, ProcessNetworkTrafficCounters> snapshotCounters() const;

        // pruneCounters: Removes accumulated entries not in liveProcessIds to limit long-term memory usage.
        void pruneCounters(const std::unordered_set<std::uint32_t>& liveProcessIds);

    private:
        static void WINAPI eventRecordCallback(PEVENT_RECORD eventRecord);
        static ULONG WINAPI bufferCallback(PEVENT_TRACE_LOGFILEW logFile);

        void consumeTrace(PROCESSTRACE_HANDLE consumerHandle, std::wstring sessionName);
        void recordNetworkEvent(const EVENT_RECORD& eventRecord);
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
        std::unordered_map<std::uint32_t, ProcessNetworkTrafficCounters> countersByPid_;

        mutable std::mutex errorMutex_;
        std::string lastErrorText_;
    };
} // namespace ks::network

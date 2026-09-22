// hGet.h
#pragma once
#include <Windows.h>
#include <pdh.h>
#include <atomic>
#include <mutex>
#include <array>
#pragma comment(lib, "Pdh.lib")

// Lightweight snapshot of metrics to store in history (POD - safe to default construct)
struct HardwareSnapshot {
    double cpuUsage = 0.0;
    double memoryAvailable = 0.0;  // MB
    double memoryCommitted = 0.0;  // MB
    double memoryUsagePercent = 0.0;
    double diskUsagePercent = 0.0;
    double diskReadBytesPerSec = 0.0;
    double diskWriteBytesPerSec = 0.0;
};

class HardwareUsage {
private:
    HQUERY hQuery_;
    PDH_HCOUNTER hCounterCPU_;
    PDH_HCOUNTER hCounterMemAvailable_;
    PDH_HCOUNTER hCounterMemCommitted_;
    PDH_HCOUNTER hCounterMemUsage_;
    PDH_HCOUNTER hCounterDiskTime_;
    PDH_HCOUNTER hCounterDiskRead_;
    PDH_HCOUNTER hCounterDiskWrite_;

    // initialize PDH queries and counters.
    bool initializeCounters();

public:
    // Performance data members
    double cpuUsage;
    double memoryAvailable;  // MB
    double memoryCommitted;  // MB
    double memoryUsagePercent;
    double diskUsagePercent;
    double diskReadBytesPerSec;
    double diskWriteBytesPerSec;

    // Constructor: initializes and immediately fetches data.
    HardwareUsage();
    // Destructor: Clean up resources.
    ~HardwareUsage();

    // Refresh to get the latest performance data.
    bool updateData();

    // Returns a lightweight snapshot for history tracking.
    HardwareSnapshot getSnapshot() const;
};

class HardwareMonitor {
public:
    static const int kHistorySize = 10;  // 10 samples history
private:

    std::array<HardwareSnapshot, kHistorySize> history_;  // Circular queue storing snapshots.
    int currentIndex_;  // Current index
    HANDLE hThread_;    // Monitored thread handle
    std::atomic_bool isRunning_;  // Thread running flag.
    std::mutex lifecycleMutex_;   // Lifecycle and thread handle ownership.
    std::mutex mtx_;    // Mutex

    static DWORD WINAPI monitorThread(LPVOID lpParam);  // Thread function
    void updateHistory(const HardwareSnapshot& snap);  // Update history.
    HardwareUsage* singleUsage_;
public:

    HardwareMonitor();
    ~HardwareMonitor();
    bool startMonitoring();  // Start monitoring
    void stopMonitoring();   // Stop monitoring
    std::array<HardwareSnapshot, kHistorySize> getHistory();  // Get history data
};

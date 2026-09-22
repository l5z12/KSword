// Get.cpp
//#include "stdafx.h"

#include <iostream>
#include <mutex>
#include "HardwareQueries.h"

bool HardwareUsage::initializeCounters() {
    PDH_STATUS status;

    // initialize handles.
    hQuery_ = nullptr;
    hCounterCPU_ = nullptr;
    hCounterMemAvailable_ = nullptr;
    hCounterMemCommitted_ = nullptr;
    hCounterMemUsage_ = nullptr;
    hCounterDiskTime_ = nullptr;
    hCounterDiskRead_ = nullptr;
    hCounterDiskWrite_ = nullptr;

    // Open query for the local machine
    status = PdhOpenQuery(NULL, 0, &hQuery_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // Add CPU counter
    status = PdhAddCounterA(hQuery_, "\\Processor(_Total)\\% Processor Time", 0, &hCounterCPU_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // Add memory counter.
    status = PdhAddCounterA(hQuery_, "\\Memory\\Available Bytes", 0, &hCounterMemAvailable_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    status = PdhAddCounterA(hQuery_, "\\Memory\\Committed Bytes", 0, &hCounterMemCommitted_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    status = PdhAddCounterA(hQuery_, "\\Memory\\% Committed Bytes In Use", 0, &hCounterMemUsage_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // Add disk counter.
    status = PdhAddCounterA(hQuery_, "\\PhysicalDisk(_Total)\\% Disk Time", 0, &hCounterDiskTime_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    status = PdhAddCounterA(hQuery_, "\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", 0, &hCounterDiskRead_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    status = PdhAddCounterA(hQuery_, "\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", 0, &hCounterDiskWrite_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // Collect initial data.
    status = PdhCollectQueryData(hQuery_);
    return status == ERROR_SUCCESS;
}

HardwareUsage::HardwareUsage()
    : hQuery_(nullptr), hCounterCPU_(nullptr), hCounterMemAvailable_(nullptr),
    hCounterMemCommitted_(nullptr), hCounterMemUsage_(nullptr),
    hCounterDiskTime_(nullptr), hCounterDiskRead_(nullptr), hCounterDiskWrite_(nullptr),
    cpuUsage(0.0), memoryAvailable(0.0), memoryCommitted(0.0),
    memoryUsagePercent(0.0), diskUsagePercent(0.0),
    diskReadBytesPerSec(0.0), diskWriteBytesPerSec(0.0) {

    // initialize counters.
    if (initializeCounters()) {
        // Wait for PDH to collect meaningful samples (two samples are required to calculate rate counters).
        Sleep(1000);
        // Fetch data immediately upon initialization.
        updateData();
    }
}

HardwareUsage::~HardwareUsage() {
    // Clean up counters.
    if (hCounterCPU_) PdhRemoveCounter(hCounterCPU_);
    if (hCounterMemAvailable_) PdhRemoveCounter(hCounterMemAvailable_);
    if (hCounterMemCommitted_) PdhRemoveCounter(hCounterMemCommitted_);
    if (hCounterMemUsage_) PdhRemoveCounter(hCounterMemUsage_);
    if (hCounterDiskTime_) PdhRemoveCounter(hCounterDiskTime_);
    if (hCounterDiskRead_) PdhRemoveCounter(hCounterDiskRead_);
    if (hCounterDiskWrite_) PdhRemoveCounter(hCounterDiskWrite_);

    // Close query
    if (hQuery_) PdhCloseQuery(hQuery_);
}

bool HardwareUsage::updateData() {
    PDH_STATUS status;
    PDH_FMT_COUNTERVALUE counterValue;

    // Collect latest data.
    status = PdhCollectQueryData(hQuery_);
    if (status != ERROR_SUCCESS) {
        return false;
    }

    // Get CPU usage
    if (PdhGetFormattedCounterValue(hCounterCPU_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        cpuUsage = counterValue.doubleValue;
    }

    // Get available memory (converted to MB)
    if (PdhGetFormattedCounterValue(hCounterMemAvailable_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        memoryAvailable = counterValue.doubleValue / (1024.0 * 1024.0);
    }

    // Get committed memory (converted to MB).
    if (PdhGetFormattedCounterValue(hCounterMemCommitted_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        memoryCommitted = counterValue.doubleValue / (1024.0 * 1024.0);
    }

    // Get memory usage percentage.
    if (PdhGetFormattedCounterValue(hCounterMemUsage_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        memoryUsagePercent = counterValue.doubleValue;
    }

    // Get disk usage percentage.
    if (PdhGetFormattedCounterValue(hCounterDiskTime_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        diskUsagePercent = counterValue.doubleValue;
    }

    // Get disk read speed
    if (PdhGetFormattedCounterValue(hCounterDiskRead_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        diskReadBytesPerSec = counterValue.doubleValue;
    }

    // Get disk write speed
    if (PdhGetFormattedCounterValue(hCounterDiskWrite_, PDH_FMT_DOUBLE, NULL, &counterValue) == ERROR_SUCCESS) {
        diskWriteBytesPerSec = counterValue.doubleValue;
    }

    return true;
}

// Return lightweight snapshot.
HardwareSnapshot HardwareUsage::getSnapshot() const {
    HardwareSnapshot snap;
    snap.cpuUsage = cpuUsage;
    snap.memoryAvailable = memoryAvailable;
    snap.memoryCommitted = memoryCommitted;
    snap.memoryUsagePercent = memoryUsagePercent;
    snap.diskUsagePercent = diskUsagePercent;
    snap.diskReadBytesPerSec = diskReadBytesPerSec;
    snap.diskWriteBytesPerSec = diskWriteBytesPerSec;
    return snap;
}

// Constructor: initialize HardwareUsage exactly 1 time.
HardwareMonitor::HardwareMonitor()
    : currentIndex_(0), hThread_(nullptr), isRunning_(false), singleUsage_(nullptr) {
    // initialize the history array to zero snapshots.
    history_.fill(HardwareSnapshot());
    // Initializes PDH counters only once (this is the only time it takes time).
    singleUsage_ = new HardwareUsage();
}

// Destructor: release the singleton instance.
HardwareMonitor::~HardwareMonitor() {
    stopMonitoring();
    if (singleUsage_) {
        delete singleUsage_;
        singleUsage_ = nullptr;
    }
}

// Start monitoring: return immediately after thread startup without blocking.
bool HardwareMonitor::startMonitoring() {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (isRunning_.load(std::memory_order_acquire)) return false;
    isRunning_.store(true, std::memory_order_release);
    // Start thread (the thread only reuses m_singleUsage, with no repeated initialization).
    hThread_ = CreateThread(nullptr, 0, monitorThread, this, 0, nullptr);
    if (hThread_ == nullptr) {
        isRunning_.store(false, std::memory_order_release);
        return false;
    }
    return true;
}

// Stop monitoring
void HardwareMonitor::stopMonitoring() {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (!isRunning_.exchange(false, std::memory_order_acq_rel)) return;
    if (hThread_) {
        WaitForSingleObject(hThread_, INFINITE);
        CloseHandle(hThread_);
        hThread_ = nullptr;
    }
}

// Update history (thread-safe).
void HardwareMonitor::updateHistory(const HardwareSnapshot& snap) {
    std::lock_guard<std::mutex> lock(mtx_);
    history_[currentIndex_] = snap;
    currentIndex_ = (currentIndex_ + 1) % kHistorySize;
}

// Thread function: core optimization—only reuse m_singleUsage to update data.
DWORD WINAPI HardwareMonitor::monitorThread(LPVOID lpParam) {
    HardwareMonitor* monitor = static_cast<HardwareMonitor*>(lpParam);
    if (monitor == nullptr || !monitor->singleUsage_) return 1;  // Guard against null pointers

    while (monitor->isRunning_.load(std::memory_order_acquire)) {
        // Update data only (lightweight operation, no initialization)
        if (monitor->singleUsage_->updateData()) {
            // Copy data to the history array (using a lightweight snapshot).
            HardwareSnapshot snap = monitor->singleUsage_->getSnapshot();
            monitor->updateHistory(snap);
        }
        // Update historical data once per second to ensure PDH has time to sample; the interval between two samples is used for rate counters.
        Sleep(1000);
    }
    return 0;
}

// Get history data
std::array<HardwareSnapshot, HardwareMonitor::kHistorySize> HardwareMonitor::getHistory() {
    std::lock_guard<std::mutex> lock(mtx_);
    return history_;
}

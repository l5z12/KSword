#include "Function.h"
#include <windows.h>
#include <qthread.h>
#include <iphlpapi.h>
#include <mutex>
#include <cstdio>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Iphlpapi.lib")

// Global CPU core usage cache: for periodic UI reading.
std::vector<int> cpuUsage;

namespace {
// State lock for network rate calculation to prevent data races from concurrent access by asynchronous threads.
std::mutex gNetworkRateMutex;

// Cumulative byte count from the previous sample, used to calculate the per-second increment.
bool gNetworkRateInitialized = false;
std::uint64_t gPrevUploadBytes = 0;
std::uint64_t gPrevDownloadBytes = 0;
ULONGLONG gPrevNetworkTickMs = 0;

// Read the total cumulative bytes sent and received across all available network interfaces (not an instantaneous rate).
bool queryNetworkTotalBytes(std::uint64_t& totalUploadBytes,
                            std::uint64_t& totalDownloadBytes) {
    totalUploadBytes = 0;
    totalDownloadBytes = 0;

    // Request buffer size first, then read the network interface table to ensure compatibility with older SDK configurations.
    ULONG tableSize = 0;
    DWORD result = GetIfTable(nullptr, &tableSize, FALSE);
    if (result != ERROR_INSUFFICIENT_BUFFER || tableSize == 0) {
        return false;
    }

    std::vector<unsigned char> tableBuffer(tableSize);
    PMIB_IFTABLE interfaceTable = reinterpret_cast<PMIB_IFTABLE>(tableBuffer.data());
    result = GetIfTable(interfaceTable, &tableSize, FALSE);
    if (result != NO_ERROR || interfaceTable == nullptr) {
        return false;
    }

    for (DWORD i = 0; i < interfaceTable->dwNumEntries; ++i) {
        const MIB_IFROW& row = interfaceTable->table[i];

        // Count only online interfaces and filter out loopback interfaces to avoid counting local loopback traffic in network speed.
        if (row.dwOperStatus != IF_OPER_STATUS_OPERATIONAL) {
            continue;
        }
        if (row.dwType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }

        totalDownloadBytes += static_cast<std::uint64_t>(row.dwInOctets);
        totalUploadBytes += static_cast<std::uint64_t>(row.dwOutOctets);
    }

    return true;
}
}

void lockWorkstation() {
    // Directly call the system API to lock the current session.
    ::LockWorkStation();
}

// Open CMD console.
void openCmd() {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    char cmd[] = "cmd.exe";
    if (::CreateProcessA(
        nullptr,
        cmd,
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE,
        nullptr,
        nullptr,
        &si,
        &pi
    )) {
        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);
    }
}

// User-defined extension point.
void userCustomFunction() {
    // Currently reserved as a stub implementation.
}

// Get per-logical-core usage (returns 0-100 integer) and synchronously update the global cpuUsage cache.
std::vector<int> getCPUCoreUsage() {
    std::vector<int> coreUsage;
    PDH_HQUERY hQuery = NULL;
    std::vector<PDH_HCOUNTER> coreCounters;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numCores = sysInfo.dwNumberOfProcessors;
    if (numCores == 0) {
        return coreUsage;
    }

    if (PdhOpenQueryA(NULL, 0, &hQuery) != ERROR_SUCCESS) {
        return coreUsage;
    }

    coreCounters.resize(numCores);
    bool countersCreated = true;
    for (DWORD i = 0; i < numCores; ++i) {
        char counterPath[256] = { 0 };
        if (sprintf_s(counterPath, "\\Processor(%d)\\%% Processor Time", i) < 0) {
            countersCreated = false;
            break;
        }
        if (PdhAddCounterA(hQuery, counterPath, 0, &coreCounters[i]) != ERROR_SUCCESS) {
            countersCreated = false;
            break;
        }
    }

    if (!countersCreated) {
        PdhCloseQuery(hQuery);
        return coreUsage;
    }

    if (PdhCollectQueryData(hQuery) != ERROR_SUCCESS) {
        PdhCloseQuery(hQuery);
        return coreUsage;
    }

    // PDH requires two sampling intervals to obtain valid utilization.
    QThread::msleep(500);
    if (PdhCollectQueryData(hQuery) != ERROR_SUCCESS) {
        PdhCloseQuery(hQuery);
        return coreUsage;
    }

    coreUsage.reserve(numCores);
    for (DWORD i = 0; i < numCores; ++i) {
        PDH_FMT_COUNTERVALUE counterValue;
        if (PdhGetFormattedCounterValue(
            coreCounters[i],
            PDH_FMT_DOUBLE,
            NULL,
            &counterValue
        ) != ERROR_SUCCESS) {
            coreUsage.push_back(0);
            continue;
        }

        int usage = static_cast<int>(std::round(counterValue.doubleValue));
        if (usage < 0) {
            usage = 0;
        }
        if (usage > 100) {
            usage = 100;
        }
        coreUsage.push_back(usage);
    }

    for (auto counter : coreCounters) {
        PdhRemoveCounter(counter);
    }
    PdhCloseQuery(hQuery);

    cpuUsage = coreUsage;
    return coreUsage;
}

// Get current network speed (bytes/sec); the function involves no UI and provides raw data only.
NetworkSpeedRate getNetworkSpeedRate() {
    NetworkSpeedRate rate = { 0, 0 };

    std::uint64_t currentUploadBytes = 0;
    std::uint64_t currentDownloadBytes = 0;
    if (!queryNetworkTotalBytes(currentUploadBytes, currentDownloadBytes)) {
        return rate;
    }

    const ULONGLONG kNowTickMs = GetTickCount64();

    std::lock_guard<std::mutex> lock(gNetworkRateMutex);

    if (!gNetworkRateInitialized) {
        gPrevUploadBytes = currentUploadBytes;
        gPrevDownloadBytes = currentDownloadBytes;
        gPrevNetworkTickMs = kNowTickMs;
        gNetworkRateInitialized = true;
        return rate;
    }

    const ULONGLONG kElapsedMs = kNowTickMs - gPrevNetworkTickMs;
    if (kElapsedMs > 0) {
        if (currentUploadBytes >= gPrevUploadBytes) {
            rate.uploadBytesPerSecond =
                ((currentUploadBytes - gPrevUploadBytes) * 1000ULL) / kElapsedMs;
        }
        if (currentDownloadBytes >= gPrevDownloadBytes) {
            rate.downloadBytesPerSecond =
                ((currentDownloadBytes - gPrevDownloadBytes) * 1000ULL) / kElapsedMs;
        }
    }

    gPrevUploadBytes = currentUploadBytes;
    gPrevDownloadBytes = currentDownloadBytes;
    gPrevNetworkTickMs = kNowTickMs;

    return rate;
}

#pragma once

#include <pdh.h>
#include <vector>
#include <cstdint>
#include <cmath>  // Used for round rounding.

// Network speed data: units unified to bytes/second for asynchronous UI reading.
struct NetworkSpeedRate {
    std::uint64_t uploadBytesPerSecond;   // Upload speed, unit: B/s
    std::uint64_t downloadBytesPerSecond; // Download speed, unit: B/s
};

void lockWorkstation();
void openCmd();
void userCustomFunction();
std::vector<int> getCPUCoreUsage();
NetworkSpeedRate getNetworkSpeedRate();

#pragma once

// ============================================================
// ProcessCpuUsageModel.h
// Purpose:
// - Calculates CPU usage using the difference between two consecutive cumulative CPU times and monotonic clock samples.
// - Provide both "system-wide normalized percentage" and "single-core equivalent percentage";
// - Keep the algorithm independent of Win32/Qt to facilitate pure calculation verification on non-Windows hosts.
// ============================================================

#include <algorithm>
#include <cstdint>

namespace ks::process
{
    struct CpuUsageWindowResult
    {
        double systemPercent = 0.0;         // Normalized relative to all logical processors, range 0~100.
        double coreEquivalentPercent = 0.0; // 100% equals filling one logical processor; can exceed 100% based on concurrency.
        bool valid = false;                 // false indicates the first round, clock rollback, or cumulative counter rollback.
    };

    inline CpuUsageWindowResult calculateCpuUsageWindow(
        const std::uint64_t currentCpuTime100ns,
        const std::uint64_t previousCpuTime100ns,
        const std::uint64_t currentTick100ns,
        const std::uint64_t previousTick100ns,
        const std::uint32_t logicalCpuCount,
        const std::uint32_t maximumConcurrentLogicalProcessors)
    {
        CpuUsageWindowResult result{};
        if (currentTick100ns <= previousTick100ns ||
            currentCpuTime100ns < previousCpuTime100ns)
        {
            return result;
        }

        const std::uint64_t kDeltaTick100ns = currentTick100ns - previousTick100ns;
        const std::uint64_t kDeltaCpu100ns = currentCpuTime100ns - previousCpuTime100ns;
        const double kLogicalCpuCountSafe = static_cast<double>(std::max(1U, logicalCpuCount));
        const double kConcurrentCpuCountSafe = static_cast<double>(
            std::max(1U, maximumConcurrentLogicalProcessors));
        const double kCoreEquivalentPercent =
            (static_cast<double>(kDeltaCpu100ns) / static_cast<double>(kDeltaTick100ns)) * 100.0;

        result.coreEquivalentPercent = std::clamp(
            kCoreEquivalentPercent,
            0.0,
            kConcurrentCpuCountSafe * 100.0);
        result.systemPercent = std::clamp(
            result.coreEquivalentPercent / kLogicalCpuCountSafe,
            0.0,
            100.0);
        result.valid = true;
        return result;
    }
}

#include "ProcessDock.Support.h"

namespace ksword::ui::process_dock
{
    // clampPercentValue:
    // - Clamp all chart input values to the 0~100 range.
    // - The line chart only draws percentages to avoid misinterpretation from directly stacking different units.
    double clampPercentValue(const double percentValue)
    {
        if (!std::isfinite(percentValue))
        {
            return 0.0;
        }
        return std::clamp(percentValue, 0.0, 100.0);
    }

    // totalPhysicalMemoryMB:
    // - Read the total system physical memory;
    // - Used to convert process working set MB to a percentage.
    double totalPhysicalMemoryMB()
    {
        MEMORYSTATUSEX memoryStatus{};
        memoryStatus.dwLength = sizeof(memoryStatus);
        if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE || memoryStatus.ullTotalPhys == 0ULL)
        {
            return 0.0;
        }
        return static_cast<double>(memoryStatus.ullTotalPhys) / (1024.0 * 1024.0);
    }

    // processActivityMetricText:
    // - Map internal activity metric enums to UI display names.
    // - Return value used for buttons, legends, and hover snapshots.
    QString processActivityMetricText(const ProcessDock::ProcessActivityMetric metric)
    {
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::kCpu:
            return QStringLiteral("CPU");
        case ProcessDock::ProcessActivityMetric::kMemory:
            return processContextText("process.activity.metric.memory", QStringLiteral("内存"));
        case ProcessDock::ProcessActivityMetric::kDisk:
            return processContextText("process.activity.metric.disk", QStringLiteral("磁盘"));
        case ProcessDock::ProcessActivityMetric::kNetwork:
            return processContextText("process.activity.metric.network", QStringLiteral("网络"));
        case ProcessDock::ProcessActivityMetric::kGpu:
            return QStringLiteral("GPU");
        default:
            return processContextText("process.activity.metric.unknown", QStringLiteral("未知"));
        }
    }

    // processActivityMetricColor:
    // - Fix the theme color for each metric to prevent color drift after the user switches buttons.
    // - Alpha is adjusted by the caller based on the bar chart or legend scenario.
    QColor processActivityMetricColor(const ProcessDock::ProcessActivityMetric metric)
    {
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::kCpu:
            return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kCpu);
        case ProcessDock::ProcessActivityMetric::kMemory:
            return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kMemory);
        case ProcessDock::ProcessActivityMetric::kDisk:
            return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kDisk);
        case ProcessDock::ProcessActivityMetric::kNetwork:
            return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kNetwork);
        case ProcessDock::ProcessActivityMetric::kGpu:
            return ksword_theme::performanceColor(ksword_theme::PerformanceRole::kGpu);
        default:
            return ksword_theme::textSecondaryColor();
        }
    }

    // processActivityMetricUnit:
    // - Returns the metric unit text.
    // - Hover snapshots and chart titles share the same unit set.
    QString processActivityMetricUnit(const ProcessDock::ProcessActivityMetric metric)
    {
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::kCpu:
        case ProcessDock::ProcessActivityMetric::kMemory:
        case ProcessDock::ProcessActivityMetric::kDisk:
        case ProcessDock::ProcessActivityMetric::kNetwork:
        case ProcessDock::ProcessActivityMetric::kGpu:
            return QStringLiteral("%");
        default:
            return QString();
        }
    }

    // formatActivityElapsedText:
    // - Convert recorded relative milliseconds to a compact timeline label.
    // - Retain 0.1s precision for durations under 1 second to facilitate manual sub-second timestamping.
    QString formatActivityElapsedText(const std::uint64_t elapsedMs)
    {
        if (elapsedMs < 1000U)
        {
            return QStringLiteral("%1s").arg(static_cast<double>(elapsedMs) / 1000.0, 0, 'f', 1);
        }

        const std::uint64_t kTotalSeconds = elapsedMs / 1000U;
        const std::uint64_t kHours = kTotalSeconds / 3600U;
        const std::uint64_t kMinutes = (kTotalSeconds / 60U) % 60U;
        const std::uint64_t kSeconds = kTotalSeconds % 60U;
        if (kHours > 0U)
        {
            return QStringLiteral("%1:%2:%3")
                .arg(kHours)
                .arg(kMinutes, 2, 10, QChar('0'))
                .arg(kSeconds, 2, 10, QChar('0'));
        }
        return QStringLiteral("%1:%2")
            .arg(kMinutes, 2, 10, QChar('0'))
            .arg(kSeconds, 2, 10, QChar('0'));
    }

    // activityMousePosition:
    // - Compatible mouse coordinate API for Qt5/Qt6;
    // - Returns the control-local coordinate.
    QPoint activityMousePosition(const QMouseEvent* eventPointer)
    {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return eventPointer != nullptr ? eventPointer->position().toPoint() : QPoint();
#else
        return eventPointer != nullptr ? eventPointer->pos() : QPoint();
#endif
    }

    // themeColorFromText:
    // - Some colors of ksword_theme may come from the palette(...) expression;
    // - Drawing is restricted to QColor; return the fallback color provided by the caller if parsing fails.
    QColor themeColorFromText(const QString& colorText, const QColor& fallbackColor)
    {
        const QColor kParsedColor(colorText);
        return kParsedColor.isValid() ? kParsedColor : fallbackColor;
    }

    // processActivitySampleMetricValue:
    // - Extract a single metric value for a sample based on the current selection range.
    // - When selectionKeys is empty, take the overall value; otherwise, sum the corresponding processes.
    double processActivitySampleMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::vector<std::string>& selectionKeys)
    {
        if (selectionKeys.empty())
        {
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::kCpu:
                return sample.totalCpuPercent;
            case ProcessDock::ProcessActivityMetric::kMemory:
                return sample.totalMemoryMB;
            case ProcessDock::ProcessActivityMetric::kDisk:
                return sample.totalDiskMBps;
            case ProcessDock::ProcessActivityMetric::kNetwork:
                return sample.totalNetKBps;
            case ProcessDock::ProcessActivityMetric::kGpu:
                return sample.totalGpuPercent;
            default:
                return 0.0;
            }
        }

        double value = 0.0;
        for (const ProcessDock::ProcessActivityProcessPoint& processPoint : sample.processes)
        {
            if (std::find(selectionKeys.begin(), selectionKeys.end(), processPoint.identityKey) == selectionKeys.end())
            {
                continue;
            }
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::kCpu:
                value += processPoint.cpuPercent;
                break;
            case ProcessDock::ProcessActivityMetric::kMemory:
                value += processPoint.workingSetMB;
                break;
            case ProcessDock::ProcessActivityMetric::kDisk:
                value += processPoint.diskMBps;
                break;
            case ProcessDock::ProcessActivityMetric::kNetwork:
                value += processPoint.netKBps;
                break;
            case ProcessDock::ProcessActivityMetric::kGpu:
                value += processPoint.gpuPercent;
                break;
            default:
                break;
            }
        }
        return value;
    }
}

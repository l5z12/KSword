#pragma once

// ============================================================
// MonitorPanelWidget.h
// Purpose:
// 1) Provides a four-quadrant performance dashboard (CPU/Memory/Disk/Network) for the 'Monitor Panel' Dock;
// 2) Displays CPU charts with bar charts for each logical core.
// 3) Decouples sampling logic from MonitorDock to avoid coupling with the WMI/ETW page.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <cstdint> // std::uint64_t: timestamp storage and cumulative byte count.
#include <vector>  // std::vector: Stores per-core counter handles and sampling results.

class QBarSet;
class QChartView;
class QGridLayout;
class QLabel;
class QLineSeries;
class QResizeEvent;
class QShowEvent;
class QEvent;
class QTimer;
class QValueAxis;
class QVBoxLayout;

class MonitorPanelWidget final : public QWidget
{
public:
    // Constructor purpose:
    // - initialize the four-panel chart.
    // - Start a 1-second refresh timer.
    // Parameter parent: Qt parent widget.
    explicit MonitorPanelWidget(QWidget* parent = nullptr);

    // Destructor purpose:
    // - Stop refresh timer;
    // - Release the PDH query handle to prevent resource leaks.
    ~MonitorPanelWidget() override;

protected:
    // resizeEvent:
    // - Recalculate the four-panel chart height when the Dock height changes;
    // - Avoid showing scrollbars on the monitor panel.
    void resizeEvent(QResizeEvent* resizeEventPointer) override;

    // showEvent:
    // - Trigger a single delayed re-layout after the first display.
    // - Resolve height estimation bias when the initial geometry is not yet stable.
    void showEvent(QShowEvent* showEventPointer) override;

    // changeEvent: Immediately refreshes chart text colors upon theme, style, or application palette changes.
    void changeEvent(QEvent* eventPointer) override;

private:
    // initializeUi:
    // - Create CPU/memory/disk/network chart controls and layouts.
    void initializeUi();

    // initializeCounters:
    // - initialize per-core CPU and disk read/write PDH counters.
    void initializeCounters();

    // refreshMetrics:
    // - Perform a single system sample.
    // - Refresh the visible data for the four charts.
    void refreshMetrics();

    // samplePerCoreCpuUsage:
    // - Reads the real-time utilization for each logical core;
    // - Output: Total average CPU utilization.
    // Parameter coreUsagesOut: array for per-core usage output.
    // Parameter totalUsageOut: total average utilization output value.
    // Returns: true on success; false on failure.
    bool samplePerCoreCpuUsage(
        std::vector<double>* coreUsagesOut,
        double* totalUsageOut);

    struct MemoryCompositionSample
    {
        double usedPercent = 0.0;       // usedPercent: Physical memory usage percentage.
        double standbyPercent = 0.0;    // standbyPercent: Approximate cache/standby percentage.
        double availablePercent = 0.0;  // availablePercent: Percentage of available physical memory.
        double commitPercent = 0.0;     // commitPercent: percentage of committed memory relative to the commit limit.
    };

    // sampleMemoryUsage:
    // - Retrieve the system memory composition percentage.
    // Parameter memorySampleOut: memory composition output value.
    // Returns: true on success; false on failure.
    bool sampleMemoryUsage(MemoryCompositionSample* memorySampleOut) const;

    // sampleDiskRate:
    // - Retrieve the system's total disk read and write rates (bytes per second).
    // Parameter readBytesPerSecOut: read rate output value.
    // Parameter writeBytesPerSecOut: output value for write rate.
    // Returns: true on success; false on failure.
    bool sampleDiskRate(
        double* readBytesPerSecOut,
        double* writeBytesPerSecOut);

    // sampleNetworkRate:
    // - Get system network uplink and downlink rates (bytes/second).
    // Parameter rxBytesPerSecOut: The output value for the download rate.
    // Parameter txBytesPerSecOut: The output value for the upload rate.
    // Returns: true on success; false on failure.
    bool sampleNetworkRate(
        double* rxBytesPerSecOut,
        double* txBytesPerSecOut);

    // appendLineSample:
    // - Append a sample point to the line chart;
    // - Automatically maintain historical length and axis range.
    // Parameter series: target line series.
    // Parameter axisX: X-axis object.
    // Parameter axisY: Y-axis object.
    // Parameter value: The current sample value.
    void appendLineSample(
        QLineSeries* series,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double value);

    // adjustChartCellHeights:
    // - Compress four charts based on current Dock available height;
    // - Uniformly set minimum/maximum heights to prevent the outer layout from triggering scrollbars due to minimum height constraints.
    void adjustChartCellHeights();

    // applyChartTextTheme:
    // - Unify refreshing chart title, legend, and axis text colors.
    // - Fix low text contrast for the monitor in the bottom-left corner in dark mode.
    void applyChartTextTheme();

    // updateCompactVisibility:
    // - When the Dock height is too low, hide the four images and display only the text summary.
    // - Prevent flickering caused by repeated layout of self-drawn charts at extremely small heights;
    // - Return: None. Directly updates control visibility.
    void updateCompactVisibility();

private:
    // Layout control.
    QVBoxLayout* rootLayout_ = nullptr;   // m_rootLayout: Root layout.
    QGridLayout* chartGridLayout_ = nullptr; // m_chartGridLayout: Four-panel grid layout.
    QLabel* compactSummaryLabel_ = nullptr; // m_compactSummaryLabel: Text summary displayed at low height.
    QTimer* refreshTimer_ = nullptr;      // m_refreshTimer: Performance sampling timer.

    // CPU/memory chart control.
    QChartView* cpuChartView_ = nullptr;     // m_cpuChartView: Per-core CPU bar chart.
    QChartView* memoryTrendChartView_ = nullptr; // m_memoryTrendChartView: Combined trend chart for memory usage and composition.
    QBarSet* cpuCoreBarSet_ = nullptr;       // m_cpuCoreBarSet: Current bar set for CPU per-core data.
    QBarSet* cpuCoreHistoryBarSet_ = nullptr; // m_cpuCoreHistoryBarSet: CPU per-core historical semi-transparent bar set.
    QLineSeries* memoryUsedSeries_ = nullptr; // m_memoryUsedSeries: Upper boundary of the used memory area.
    QLineSeries* memoryStandbyTopSeries_ = nullptr; // m_memoryStandbyTopSeries: Upper boundary of committed/cached memory area.
    QLineSeries* memoryStandbyBaseSeries_ = nullptr; // m_memoryStandbyBaseSeries: Lower boundary of committed/cached memory area.
    QLineSeries* memoryAvailableTopSeries_ = nullptr; // m_memoryAvailableTopSeries: Upper boundary of available memory area.
    QLineSeries* memoryAvailableBaseSeries_ = nullptr; // m_memoryAvailableBaseSeries: Lower boundary of available memory area.
    QLineSeries* memoryUsageSeries_ = nullptr; // m_memoryUsageSeries: Memory usage history line chart.
    QValueAxis* memoryTrendAxisX_ = nullptr; // m_memoryTrendAxisX: X-axis for memory consolidation trends.
    QValueAxis* memoryTrendAxisY_ = nullptr; // m_memoryTrendAxisY: Y-axis for memory consolidation trends.
    std::vector<double> cpuCoreHistoryPercentList_; // m_cpuCoreHistoryPercentList: Historical average utilization per core.

    // Disk/Network chart control.
    QChartView* diskChartView_ = nullptr;    // m_diskChartView: Disk read/write line chart.
    QChartView* networkChartView_ = nullptr; // m_networkChartView: Network uplink/downlink line chart.
    QLineSeries* diskReadSeries_ = nullptr;  // m_diskReadSeries: Disk read rate series.
    QLineSeries* diskWriteSeries_ = nullptr; // m_diskWriteSeries: Disk write rate series.
    QLineSeries* networkRxSeries_ = nullptr; // m_networkRxSeries: Network download rate series.
    QLineSeries* networkTxSeries_ = nullptr; // m_networkTxSeries: Network upload rate series.
    QValueAxis* diskAxisX_ = nullptr;        // m_diskAxisX: Disk chart X-axis.
    QValueAxis* diskAxisY_ = nullptr;        // m_diskAxisY: Disk chart Y-axis.
    QValueAxis* networkAxisX_ = nullptr;     // m_networkAxisX: Network graph X-axis.
    QValueAxis* networkAxisY_ = nullptr;     // m_networkAxisY: Network graph Y-axis.

    // Historical sampling status.
    int historyLength_ = 60;        // m_historyLength: Number of points retained in the line chart.
    int sampleCounter_ = 0;         // m_sampleCounter: Current sampling sequence number.
    QString lastCompactSummaryText_; // m_lastCompactSummaryText: Summary text from the most recent sampling.
    std::uint64_t lastNetworkRxBytes_ = 0; // m_lastNetworkRxBytes: Cumulative bytes received in the last network operation.
    std::uint64_t lastNetworkTxBytes_ = 0; // m_lastNetworkTxBytes: Cumulative bytes sent in the last network operation.
    qint64 lastNetworkSampleMs_ = 0;       // m_lastNetworkSampleMs: timestamp of the last network sample (ms).

    // PDH handle cache.
    void* cpuPerfQueryHandle_ = nullptr;       // m_cpuPerfQueryHandle: CPU query handle.
    std::vector<void*> coreCounterHandles_;    // m_coreCounterHandles: Per-core CPU counter handles.
    void* diskPerfQueryHandle_ = nullptr;      // m_diskPerfQueryHandle: Disk query handle.
    void* diskReadCounterHandle_ = nullptr;    // m_diskReadCounterHandle: Handle for the disk read counter.
    void* diskWriteCounterHandle_ = nullptr;   // m_diskWriteCounterHandle: Disk write counter handle.
};

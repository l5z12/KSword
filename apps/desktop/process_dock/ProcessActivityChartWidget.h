#pragma once
#include "ProcessDock.Support.h"

class ProcessActivityChartWidget final : public QWidget
{
public:
    // Constructor:
    // - ownerDock: Provides samples, selection, and metric toggles.
    // - parent: Qt parent control;
    // - No return value; initializes mouse tracking to support hover snapshots.
    explicit ProcessActivityChartWidget(ProcessDock* ownerDock, QWidget* parent = nullptr);

    // setFocusedSampleIndex：
    // - sampleIndex: The sample index currently focused on the timeline; -1 indicates no focus.
    // - The function only updates the drawing cursor without modifying the host slider.
    void setFocusedSampleIndex(const int sampleIndex);

    void animateLatestSample(const bool historyWindowShifted);

protected:
    // event：
    // - Input: Qt generic event; focus on handling ToolTip events.
    // - Processing: recalculate the nearest sample based on current mouse position just before the tooltip is displayed;
    // - Returns: true indicates the tooltip is handled by the control, false indicates it is passed to the default QWidget handling.
    bool event(QEvent* eventPointer) override;

    // paintEvent：
    // - Draw a multi-metric percentage line chart with time on the horizontal axis.
    // - No return value; all data is read from the host's bounded sample cache.
    void paintEvent(QPaintEvent* eventPointer) override;

    // mouseMoveEvent：
    // - Map mouse X coordinate to the nearest sample;
    // - Notify host to update timeline slider and snapshot labels.
    void mouseMoveEvent(QMouseEvent* eventPointer) override;

    // mousePressEvent：
    // - Fixes the timeline to the corresponding historical sample on chart click.
    // - If the rightmost sample is clicked, restore the 'stick to latest' mode.
    void mousePressEvent(QMouseEvent* eventPointer) override;

    // leaveEvent：
    // - Preserve the current timeline position after the mouse leaves the chart.
    // - Hide only the tooltip to avoid clearing it while the user reads the snapshot below.
    void leaveEvent(QEvent* eventPointer) override;

private:
    // showSnapshotToolTipAtPosition：
    // - localPosition: Chart local coordinates, used to map to the nearest sample.
    // - globalPosition: screen coordinates used to position the tooltip;
    // - Return: None; hides the tooltip proactively when no samples exist to avoid displaying a static tooltip.
    void showSnapshotToolTipAtPosition(const QPoint& localPosition, const QPoint& globalPosition);

    // chartRect：
    // - Calculate the actual drawing area of the chart;
    // - Reserve fixed space for left-side scale and bottom time labels.
    QRectF chartRect() const;

    // enabledMetricList：
    // - Read currently visible metrics from the host button state;
    // - Returns the order, which corresponds to the line chart drawing order.
    std::vector<ProcessDock::ProcessActivityMetric> enabledMetricList() const;

    // MetricScale:
    // - Saves the denominator for line chart percentage normalization.
    // - Use the current historical window maximum for disk/network usage as 100%.
    struct MetricScale
    {
        double memoryDenominatorMB = 1.0;     // memoryDenominatorMB: Total physical memory or historical peak memory.
        double diskDenominatorMBps = 1.0;     // diskDenominatorMBps: Historical maximum disk throughput.
        double networkDenominatorKBps = 1.0;  // networkDenominatorKBps: Historical maximum network throughput.
    };

    // sampleRawMetricValue：
    // - Reads the raw single metric value at a specific sample point;
    // - Returns the overall aggregate if selectionKeySet is empty; otherwise returns the sum of selected processes via the hash set.
    double sampleRawMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::unordered_set<std::string>& selectionKeySet) const;

    // calculateMetricScale：
    // - Rescan the historical maximum value on every draw.
    // - When new peaks appear in disk or network usage, recalculate percentages and redraw immediately in this round.
    MetricScale calculateMetricScale(
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const std::unordered_set<std::string>& selectionKeySet) const;

    // samplePercentMetricValue：
    // - Convert raw metrics to percentages.
    // - Disk and network metrics are normalized against historical maximums; CPU and GPU are naturally percentages.
    double samplePercentMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::unordered_set<std::string>& selectionKeySet,
        const MetricScale& scale) const;

    // sampleIndexAtX：
    // - Map mouse X coordinate to the nearest sample index;
    // - Out-of-bounds coordinates are clamped to the first or last sample.
    int sampleIndexAtX(const int xValue) const;

    // sampleIndexToX：
    // - Map sample index to the X coordinate of a polyline point.
    // - The focus line and time labels reuse this function for rendering.
    double sampleIndexToX(const int sampleIndex, const QRectF& plotRect) const;

    // animatedSampleIndexToX：
    // Smoothly move old samples from the previous X-coordinate to the target X-coordinate when new points are added.
    // - When history is fully loaded, shift the entire window left; when not full, smoothly compress old points to leave space for the newest point on the far right.
    double animatedSampleIndexToX(const int sampleIndex, const QRectF& plotRect) const;

    // drawGrid：
    // - Draws weak grid lines, maximum value labels, and start/end timestamps.
    // - No additional axis controls are created to reduce UI overhead.
    void drawGrid(
        QPainter& painter,
        const QRectF& plotRect,
        const QColor& borderColor,
        const QColor& textColor) const;

    // drawLines：
    // - Draw multi-indicator line charts ordered by time;
    // - All metrics are normalized to 0~100%, allowing different units to share the same Y-axis.
    void drawLines(
        QPainter& painter,
        const QRectF& plotRect,
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const std::unordered_set<std::string>& selectionKeySet,
        const MetricScale& metricScale) const;

    // drawLegend：
    // - Draw the legend for currently enabled metrics along the top of the chart;
    // - Users can verify the line colors filtered by the button based on this.
    void drawLegend(
        QPainter& painter,
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const QColor& textColor) const;

    // drawFocusLine：
    // - Draw the vertical line indicating the current sample position on the timeline.
    // - This line is driven by both the slider and chart hover.
    void drawFocusLine(QPainter& painter, const QRectF& plotRect) const;

private:
    ProcessDock* ownerDock_ = nullptr; // m_ownerDock: Host ProcessDock, does not own.
    int focusedSampleIndex_ = -1;      // m_focusedSampleIndex: Currently focused sample on the timeline.
    QVariantAnimation* seriesAnimation_ = nullptr; // m_seriesAnimation: Interpolation animation for the latest sample point.
    double animationProgress_ = 1.0; // m_animationProgress: Animation progress for the latest sample point.
    bool historyWindowShifted_ = false; // m_historyWindowShifted: Whether the oldest sample was evicted in this round.
};

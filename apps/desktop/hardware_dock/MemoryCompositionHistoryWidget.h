#pragma once

#include <QWidget>

#include <vector>
class QVariantAnimation;

// MemoryCompositionHistoryWidget:
// - Draw memory usage history line chart;
// - Layer-fill below the line chart according to memory composition ratios at each sample time.
class MemoryCompositionHistoryWidget final : public QWidget
{
public:
    // CompositionSample purpose: Saves the percentage composition of a single memory sample.
    // Usage: appendSample receives this structure and triggers a redraw.
    struct CompositionSample
    {
        double usedPercent = 0.0;          // usedPercent: Percentage of total physical memory used.
        double activePercent = 0.0;        // activePercent: Approximate active usage percentage after deducting cache/pool.
        double cachedPercent = 0.0;        // cachedPercent: percentage of physical memory occupied by system cache.
        double pagedPoolPercent = 0.0;     // pagedPoolPercent: Percentage of paged pool relative to physical memory.
        double nonPagedPoolPercent = 0.0;  // nonPagedPoolPercent: Percentage of non-paged pool relative to physical memory.
    };

    // Constructor purpose: initialize the custom-drawn control's minimum height and drawing properties.
    explicit MemoryCompositionHistoryWidget(QWidget* parent = nullptr);

    // setHistoryLength: Sets the number of history points to retain; samples older than this limit are automatically discarded.
    void setHistoryLength(int historyLength);

    // appendSample purpose: append a memory composition sample at a specific moment and refresh the chart.
    void appendSample(const CompositionSample& sample);

    // clearSamples purpose: Clear historical samples for future reset of the sampling window.
    void clearSamples();

protected:
    // paintEvent: Draws the grid, composition fill, usage line chart, and legend.
    void paintEvent(QPaintEvent* paintEventPointer) override;

private:
    // boundedPercent purpose: Clamp the percentage to 0~100 to prevent abnormal API data from breaking the chart.
    static double boundedPercent(double percentValue);

    // animatedSampleAt: returns the interpolated value of the latest sample point at the current animation frame.
    CompositionSample animatedSampleAt(std::size_t sampleIndex) const;

    // sampleX function: Maps historical sample index to plot area X coordinate.
    double sampleX(int sampleIndex, const QRectF& plotRect) const;

    // percentY: Maps percentage to the Y coordinate of the plot area.
    static double percentY(double percentValue, const QRectF& plotRect);

    // drawStackedComposition: Draws the stacked memory composition fill below the line chart.
    void drawStackedComposition(QPainter& painter, const QRectF& plotRect) const;

    // drawUsageLine: Draws the total usage line above the filled area.
    void drawUsageLine(QPainter& painter, const QRectF& plotRect) const;

    // drawLegend purpose: draw the color legend explaining the memory composition represented by filled areas.
    void drawLegend(QPainter& painter, const QRectF& plotRect) const;

    int historyLength_ = 60; // m_historyLength: Maximum number of historical sample points to retain.
    std::vector<CompositionSample> sampleList_; // m_sampleList: Memory composition history saved in chronological order.
    int previousSampleCount_ = 0; // m_previousSampleCount: Sample count before the animation started.
    bool historyWindowShifted_ = false; // m_historyWindowShifted: Whether the oldest sample was evicted in this round.
    QVariantAnimation* sampleAnimation_ = nullptr; // m_sampleAnimation: Animation for the latest sample point.
    CompositionSample previousSample_; // m_previousSample: Animation start point for the latest sample.
    double animationProgress_ = 1.0; // m_animationProgress: Animation progress for the latest sample point.
    bool hasPreviousSample_ = false; // m_hasPreviousSample: Whether there is a previous sample available for interpolation.
};

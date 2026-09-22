#pragma once

// ============================================================
// PerformanceNavCard.h
// Purpose:
// 1) Provide a 'Task Manager-style' left-side performance navigation card;
// 2) Display card title, subtitle, and thumbnail line chart;
// 3) Support single-line and dual-line thumbnail modes for reuse by the HardwareDock utilization page.
// ============================================================

#include "../Framework.h"

#include <QColor>
#include <QVector>
#include <QWidget>

class QPaintEvent;
class QVariantAnimation;

class PerformanceNavCard final : public QWidget
{
public:
    // Constructor purpose: initialize default colors, sampling capacity, and control properties.
    // Parameter parent: Qt parent control pointer.
    explicit PerformanceNavCard(QWidget* parent = nullptr);

    // setTitleText: Sets the card's main title text (e.g., CPU/Memory/Disk).
    // Parameter titleText: title string.
    void setTitleText(const QString& titleText);

    // setSubtitleText: Sets the card's subtitle text (e.g., "51% 2.88 GHz").
    // Parameter subtitleText: Subtitle string.
    void setSubtitleText(const QString& subtitleText);

    // setAccentColor function: Sets card border and primary line color.
    // Parameter accentColor: Primary color value.
    void setAccentColor(const QColor& accentColor);

    // setSeriesColors purpose: Set the colors for the primary and secondary curves in the thumbnail.
    // Parameter primarySeriesColor: primary series color; falls back to accentColor if invalid.
    // Parameter secondarySeriesColor: Secondary series color; if invalid, hide the second curve.
    void setSeriesColors(
        const QColor& primarySeriesColor,
        const QColor& secondarySeriesColor = QColor());

    // setSelectedState purpose: Set the selection state, affecting background highlight rendering.
    // Parameter selected: true = selected, false = not selected.
    void setSelectedState(bool selected);

    // appendSample purpose: Append a percentage sample point to the thumbnail line chart.
    // Parameter usagePercent: utilization value in the range 0~100.
    void appendSample(double usagePercent);

    // appendDualSample: Simultaneously appends sample points for two thumbnail lines.
    // Parameter primaryUsagePercent: Primary sequence percentage sample value.
    // Parameter secondaryUsagePercent: The percentage sample value for the secondary series.
    void appendDualSample(double primaryUsagePercent, double secondaryUsagePercent);

    // setSampleSeries: Directly replaces the entire thumbnail sampling history of the current card.
    // Parameter primarySampleList: Complete primary sample list, with values in the range 0~100.
    // Parameter secondarySampleList: the complete secondary sample list, with values in the range 0~100.
    void setSampleSeries(
        const QVector<double>& primarySampleList,
        const QVector<double>& secondarySampleList = {});

    // clearSamples: Clears the thumbnail line chart history data.
    void clearSamples();

    // sizeHint: Provides the recommended size for QListWidgetItem.
    [[nodiscard]] QSize sizeHint() const override;

    // sampleCapacity purpose: Return the maximum number of sample points retained for the thumbnail.
    // Returns: The maximum number of samples allowed for the current card.
    [[nodiscard]] int sampleCapacity() const;

protected:
    // paintEvent: Draws the card background, border, text, and thumbnail line chart.
    // Parameter paintEventPointer: Qt paint event object.
    void paintEvent(QPaintEvent* paintEventPointer) override;

private:
    // startLatestSampleAnimation purpose: smoothly transition the latest sample point from the previous value to the target value.
    void startLatestSampleAnimation(double previousPrimarySample, double previousSecondarySample);
    // animatedXRatio: Smoothly interpolates the horizontal coordinates from the old sample window to the new window.
    double animatedXRatio(int sampleIndex, int sampleCount) const;


    QString titleText_;      // m_titleText: Card main title text.
    QString subtitleText_;   // m_subtitleText: Card subtitle text.
    QColor accentColor_;     // m_accentColor: Primary color for lines and borders.
    QColor primarySeriesColor_; // m_primarySeriesColor: Main thumbnail line color.
    QColor secondarySeriesColor_; // m_secondarySeriesColor: Color for the secondary thumbnail line.
    bool selected_ = false;  // m_selected: Whether the current card is selected.
    bool primarySeriesFollowsAccentColor_ = true; // m_primarySeriesFollowsAccentColor: Whether the main thumbnail line follows the border's primary color.
    bool secondarySeriesVisible_ = false; // m_secondarySeriesVisible: Whether to draw the second thumbnail line.
    QVector<double> primarySamples_; // m_primarySamples: Main thumbnail line historical sample list.
    QVector<double> secondarySamples_; // m_secondarySamples: List of historical samples for the secondary thumbnail line.
    int maxSampleCount_ = 36; // m_maxSampleCount: Maximum number of points retained in the line chart.
    int previousSampleCount_ = 0; // m_previousSampleCount: Sample count before the animation started.
    bool historyWindowShifted_ = false; // m_historyWindowShifted: Whether the oldest sample was evicted in this round.
    QVariantAnimation* sampleAnimation_ = nullptr; // m_sampleAnimation: Interpolation animation for the latest sample point.
    double previousPrimarySample_ = 0.0; // m_previousPrimarySample: Mainline animation start point.
    double previousSecondarySample_ = 0.0; // m_previousSecondarySample: Starting point for the secondary line animation.
    double animationProgress_ = 1.0; // m_animationProgress: Animation progress at the latest point.
};

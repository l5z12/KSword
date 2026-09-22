#pragma once

// ============================================================
// ProcessTraceTimelineWidget.h
// Purpose:
// 1) Provides a compact waterfall time axis above the ETW event table;
// 2) Maintains time-selection state using real 100ns timestamps to avoid inferring events from graphical points.
// 3) Expose a lightweight QWidget API so that ProcessTraceMonitorWidget can overlay time filtering with existing text/type filtering.
// ============================================================

#include <QWidget>
#include <QColor>
#include <QPoint>
#include <QRectF>
#include <QString>

#include <cstdint>     // std::uint64_t: 100ns timestamp compatible with ETW FILETIME.
#include <functional>  // std::function: lightweight callback not dependent on Qt moc signals.
#include <vector>      // std::vector: Lightweight point list copied from the event table cache.

class QEvent;
class QMouseEvent;
class QPaintEvent;
class QWheelEvent;
class QVariantAnimation;

// ProcessTraceTimelineEventPoint：
// - time100ns: ETW absolute timestamp in units of 100ns;
// - typeText: categorized event type, used to determine color and row;
// - The control only reads this lightweight structure and does not depend on table row indices or screen coordinates.
struct ProcessTraceTimelineEventPoint
{
    std::uint64_t time100ns = 0;
    QString typeText;
};

// ProcessTraceTimelineRatePoint：
// - time100ns: Timeline position of the polyline point; unit remains 100ns.
// - uploadBytesPerSecond: outbound/upload rate for this second, in B/s.
// - downloadBytesPerSecond: inbound/download rate for that second, in B/s.
// - This structure is an optional overlay; no rate lines are drawn when the ETW page is not set.
struct ProcessTraceTimelineRatePoint
{
    std::uint64_t time100ns = 0;
    double uploadBytesPerSecond = 0.0;
    double downloadBytesPerSecond = 0.0;
};

class ProcessTraceTimelineWidget final : public QWidget
{
public:
    // Constructor:
    // - parent: Qt parent control;
    // - The control has a fixed height of 40 logical pixels, and its width stretches horizontally according to the layout.
    explicit ProcessTraceTimelineWidget(QWidget* parent = nullptr);

    // setCaptureRange：
    // - start100ns: Absolute 100ns timestamp corresponding to the leftmost point of the timeline.
    // - end100ns: The current or final 100ns timestamp corresponding to the rightmost end of the timeline.
    // - Before manual adjustment by the user, the selection automatically covers the full range.
    void setCaptureRange(std::uint64_t start100ns, std::uint64_t end100ns);

    // resetTimeline：
    // - Clear all event points and establish a new full-range selection starting from start100ns.
    // - No return value; call selectionStart100ns/selectionEnd100ns to read the state when needed.
    void resetTimeline(std::uint64_t start100ns);

    // resetSelectionToFullRange：
    // - Reset current selection to full capture range;
    // - No return value; the caller is responsible for re-executing the event table filter.
    void resetSelectionToFullRange();

    // setEventPoints：
    // - Replaces the lightweight event point cache used for rendering;
    // - The caller is responsible for event lifecycle and table filtering; this control is responsible only for rendering.
    void setEventPoints(const std::vector<ProcessTraceTimelineEventPoint>& eventPointList);

    // setRateOverlayPoints：
    // - Replace the upload/download rate line chart cache used for rendering.
    // - Caller is responsible for second-level aggregation; this control only handles scaling mapping and overlay rendering;
    // - Passing an empty list disables the rate polyline overlay.
    void setRateOverlayPoints(const std::vector<ProcessTraceTimelineRatePoint>& ratePointList);

    // setSelectionChangedCallback：
    // - Register callback for selection changes triggered by user interaction;
    // - Callback parameters are absolute start and end timestamps in units of 100ns.
    void setSelectionChangedCallback(
        std::function<void(std::uint64_t, std::uint64_t)> callbackValue);

    // selectionStart100ns：
    // - Returns the absolute 100ns timestamp of the current selection start;
    // - Return 0 if the capture range is not initialized.
    std::uint64_t selectionStart100ns() const;

    // selectionEnd100ns：
    // - Returns the absolute 100ns timestamp of the current selection end;
    // - Return 0 if the capture range is not initialized.
    std::uint64_t selectionEnd100ns() const;

protected:
    // paintEvent：
    // - Draws the timeline background, event points, duration labels, and selection rectangle.
    // - No return value; Qt dispatches and consumes paint events via virtual functions.
    void paintEvent(QPaintEvent* eventPointer) override;

    // mousePressEvent：
    // - Start dragging the selection box or its left/right edges.
    // - Returns no value; takes over events when the draggable area is hit.
    void mousePressEvent(QMouseEvent* eventPointer) override;

    // mouseMoveEvent：
    // - Updates the hover cursor or executes the current drag operation.
    // - No return value; notifies the host callback when the selection changes.
    void mouseMoveEvent(QMouseEvent* eventPointer) override;

    // mouseReleaseEvent：
    // - End the current drag operation and restore standard hit testing.
    // - No return value.
    void mouseReleaseEvent(QMouseEvent* eventPointer) override;

    // leaveEvent：
    // - Restore the default cursor when the mouse leaves without dragging.
    // - No return value.
    void leaveEvent(QEvent* eventPointer) override;

    // wheelEvent：
    // - Scroll up to expand the selection, scroll down to shrink it;
    // - Operations modify internal timestamps; do not infer from table rows or graph points.
    void wheelEvent(QWheelEvent* eventPointer) override;

private:
    // DragMode：
    // - None: Normal hover;
    // - Move: Translate the entire selection;
    // - ResizeLeft/ResizeRight: Adjust the left or right boundary independently.
    enum class DragMode
    {
        kNone,
        kMove,
        kResizeLeft,
        kResizeRight
    };
    ProcessTraceTimelineRatePoint animatedRatePointAt(std::size_t pointIndex) const;
    double animatedRateTimeToX(std::uint64_t time100ns) const;


    // timelineRect：
    // - Returns the actual drawable rectangle within the 40px timeline;
    // - The rectangle should fill the available width as much as possible, keeping only minimal internal padding.
    QRectF timelineRect() const;

    // selectionRect：
    // - Convert internal selection timestamps to rectangles for drawing and hit testing;
    // - Return an empty rectangle if the capture range is invalid.
    QRectF selectionRect() const;

    // hitTestSelection：
    // - Returns which part of the selection box the mouse hit;
    // - The edge hit area is wider than the visible border to facilitate dragging.
    DragMode hitTestSelection(const QPoint& position) const;

    // updateHoverCursor：
    // - Select the appropriate cursor based on the current hover position.
    // - No return value.
    void updateHoverCursor(const QPoint& position);

    // timeToX：
    // - Map absolute 100ns timestamps to X coordinates;
    // - Values exceeding the capture range are clamped within the timeline rectangle.
    double timeToX(std::uint64_t time100ns) const;

    // xToTime：
    // - Map the X coordinate back to an absolute 100ns timestamp;
    // - Used solely to convert mouse input to internal selection time.
    std::uint64_t xToTime(double xValue) const;

    // laneForType：
    // - Map event types to stable vertical lanes;
    // - If 40px height is insufficient to accommodate all subtypes, similar event families share a row.
    int laneForType(const QString& typeText) const;

    // colorForType：
    // - Returns the color with 20% transparency corresponding to a given event type;
    // - Use intentionally distinct colors for different categories.
    QColor colorForType(const QString& typeText) const;

    // formatDurationText：
    // - Format 100ns duration as mm:ss or hh:mm:ss;
    // - Used for the right label; the left label is fixed at 00:00.
    QString formatDurationText(std::uint64_t duration100ns) const;

    // clampSelectionToRange：
    // - Ensure the selection is within the captured range and enforce a minimum width;
    // - No return value; directly corrects member timestamps.
    void clampSelectionToRange();

    // notifySelectionChanged：
    // - If the host registers a callback, notify selection change.
    // - No return value.
    void notifySelectionChanged();

private:
    std::vector<ProcessTraceTimelineEventPoint> eventPointList_; // m_eventPointList: Lightweight event cache for rendering only.
    std::vector<ProcessTraceTimelineRatePoint> ratePointList_; // m_ratePointList: Cache for upload/download rate line chart points; do not draw when empty.
    QVariantAnimation* rateAnimation_ = nullptr; // m_rateAnimation: Interpolation animation for the latest rate point.
    ProcessTraceTimelineRatePoint previousRatePoint_; // m_previousRatePoint: Starting value for the latest point animation.
    double rateAnimationProgress_ = 1.0; // m_rateAnimationProgress: Animation progress for the latest rate point.
    std::uint64_t previousRateRangeStart100ns_ = 0; // m_previousRateRangeStart100ns: Left end of the range before the horizontal animation.
    std::uint64_t previousRateRangeEnd100ns_ = 0; // m_previousRateRangeEnd100ns: Right end of the range before the horizontal animation.
    bool hasPreviousRateRange_ = false; // m_hasPreviousRateRange: Whether a previous time range exists for interpolation.
    bool hasPreviousRatePoint_ = false; // m_hasPreviousRatePoint: Whether there is an old rate point available for interpolation.
    std::function<void(std::uint64_t, std::uint64_t)> selectionChangedCallback_; // m_selectionChangedCallback: Host-side filter callback.
    std::uint64_t rangeStart100ns_ = 0;             // m_rangeStart100ns: Absolute time at the left edge of the timeline.
    std::uint64_t rangeEnd100ns_ = 0;               // m_rangeEnd100ns: Absolute time at the right edge of the timeline.
    std::uint64_t selectionStart100ns_ = 0;         // m_selectionStart100ns: Absolute start time of the selection.
    std::uint64_t selectionEnd100ns_ = 0;           // m_selectionEnd100ns: Absolute end time of the selection area.
    std::uint64_t dragPressTime100ns_ = 0;          // m_dragPressTime100ns: Time corresponding to the drag start point.
    std::uint64_t dragOriginalStart100ns_ = 0;      // m_dragOriginalStart100ns: Start of the selection before dragging.
    std::uint64_t dragOriginalEnd100ns_ = 0;        // m_dragOriginalEnd100ns: Selection end point before dragging.
    DragMode dragMode_ = DragMode::kNone;            // m_dragMode: Current mouse operation mode.
    bool userAdjustedSelection_ = false;            // m_userAdjustedSelection: Whether the user has manually adjusted the selection.
};

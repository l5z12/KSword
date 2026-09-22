#include "ProcessTraceTimelineWidget.h"

// ============================================================
// ProcessTraceTimelineWidget.cpp
// Purpose:
// 1) Render a compact ETW waterfall timeline with category rows.
// 2) Maintain an internal absolute time selection as the time filter condition for the event table;
// 3) Convert mouse operations into timestamp updates instead of deriving event sets from graphical event points.
// ============================================================

#include "../Theme.h"
#include "../internationalization/LanguageManager.h"

#include <QColor>
#include <QEvent>
#include <QFont>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QPolygonF>
#include <QSizePolicy>
#include <QtGlobal>
#include <QWheelEvent>
#include <QEasingCurve>
#include <QVariantAnimation>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>

namespace
{
    // kTimelineHeight：
    // Fixed visible height for the ETW waterfall timeline;
    // - The constructor synchronously locks the control height to this value.
    constexpr int kTimelineHeight = 40;

    // kHorizontalPadding：
    // - Reserves minimal horizontal margins for the border and left/right labels;
    // - The remaining width is used as the time axis available space.
    constexpr int kHorizontalPadding = 4;

    // kVerticalPadding：
    // - The selection rectangle must span the full height of the timeline, so no extra vertical padding is reserved.
    // - Sub-pixel clipping caused by anti-aliasing is acceptable; prioritize interaction semantics.
    constexpr int kVerticalPadding = 0;

    // kEdgeHitWidth：
    // - The logical pixel width of the selection's left and right edges that can trigger stretching.
    // - The hit area is intentionally wider than the visible line to facilitate mouse interaction.
    constexpr int kEdgeHitWidth = 6;

    // kMinimumSelection100ns：
    // - Prevent selection from collapsing to a zero-width time point;
    // - 10ms is fine-grained enough while still being draggable.
    constexpr std::uint64_t kMinimumSelection100ns = 10ULL * 1000ULL * 10ULL;

    // kDefaultRange100ns：
    // - Provide a non-zero draw range before the first ETW event arrives.
    // - A default 1-second span ensures stable initial coordinate calculation.
    constexpr std::uint64_t kDefaultRange100ns = 1ULL * 1000ULL * 1000ULL * 10ULL;

    // kLaneCount：
    // - Reserve independent rows for major categories in the current ETW type dropdown.
    // - 40px height is narrow, so the point radius is reduced accordingly.
    constexpr int kLaneCount = 13;

    // themeColorFromText：
    // - Safely convert the theme's returned palette string to a QColor.
    // - Use fallbackColor when the theme text is not a specific #RRGGBB to maintain drawing stability.
    QColor themeColorFromText(const QString& colorText, const QColor& fallbackColor)
    {
        QColor colorValue(colorText);
        return colorValue.isValid() ? colorValue : fallbackColor;
    }

    // effectiveWheelDelta：
    // - Reads the most reliable scroll direction from the Qt wheel event.
    // - Positive values indicate upward scrolling, negative values indicate downward scrolling.
    int effectiveWheelDelta(const QWheelEvent* eventPointer)
    {
        if (eventPointer == nullptr)
        {
            return 0;
        }

        const QPoint kAngleDelta = eventPointer->angleDelta();
        if (kAngleDelta.y() != 0)
        {
            return kAngleDelta.y();
        }

        const QPoint kPixelDelta = eventPointer->pixelDelta();
        return kPixelDelta.y();
    }

    // currentMousePosition：
    // - Returns local mouse coordinates compatible with different Qt versions;
    // - Qt 6 uses position(), while the old interface uses pos().
    QPoint currentMousePosition(const QMouseEvent* eventPointer)
    {
        if (eventPointer == nullptr)
        {
            return QPoint();
        }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return eventPointer->position().toPoint();
#else
        return eventPointer->pos();
#endif
    }

    // currentWheelPosition：
    // - Returns local wheel coordinates compatible with different Qt versions;
    // - The returned point is used solely as a zoom anchor.
    QPoint currentWheelPosition(const QWheelEvent* eventPointer)
    {
        if (eventPointer == nullptr)
        {
            return QPoint();
        }

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return eventPointer->position().toPoint();
#else
        return eventPointer->pos();
#endif
    }
}

ProcessTraceTimelineWidget::ProcessTraceTimelineWidget(QWidget* parent)
    : QWidget(parent)
{
    // This control is a narrow timeline bar and should occupy all available horizontal space provided by the parent layout.
    setFixedHeight(kTimelineHeight);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMouseTracking(true);
    setFocusPolicy(Qt::NoFocus);
    rateAnimation_ = new QVariantAnimation(this);
    rateAnimation_->setDuration(260);
    rateAnimation_->setEasingCurve(QEasingCurve::OutCubic);
    rateAnimation_->setStartValue(0.0);
    rateAnimation_->setEndValue(1.0);
    connect(rateAnimation_, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        rateAnimationProgress_ = value.toDouble();
        update();
    });
}

void ProcessTraceTimelineWidget::setCaptureRange(
    const std::uint64_t start100ns,
    const std::uint64_t end100ns)
{
    // normalizedEnd100ns: Ensures the timeline range is non-zero even if collection just started or the caller passes identical start/end values.
    const std::uint64_t kNormalizedEnd100ns = end100ns > start100ns
        ? end100ns
        : start100ns + kDefaultRange100ns;

    const bool kHadRange = rangeEnd100ns_ > rangeStart100ns_;
    if (kHadRange)
    {
        previousRateRangeStart100ns_ = rangeStart100ns_;
        previousRateRangeEnd100ns_ = rangeEnd100ns_;
        hasPreviousRateRange_ =
            previousRateRangeStart100ns_ != start100ns
            || previousRateRangeEnd100ns_ != kNormalizedEnd100ns;
    }
    else
    {
        hasPreviousRateRange_ = false;
    }
    rangeStart100ns_ = start100ns;
    rangeEnd100ns_ = kNormalizedEnd100ns;

    // Before the user manually adjusts the selection, the selection continuously covers the full capture range to avoid implicit time filtering by default.
    if (!kHadRange || !userAdjustedSelection_)
    {
        selectionStart100ns_ = rangeStart100ns_;
        selectionEnd100ns_ = rangeEnd100ns_;
    }
    else
    {
        clampSelectionToRange();
    }

    update();
}

void ProcessTraceTimelineWidget::resetTimeline(const std::uint64_t start100ns)
{
    eventPointList_.clear();
    rateAnimation_->stop();
    rateAnimationProgress_ = 1.0;
    hasPreviousRatePoint_ = false;
    ratePointList_.clear();
    rangeStart100ns_ = start100ns;
    rangeEnd100ns_ = start100ns + kDefaultRange100ns;
    previousRateRangeStart100ns_ = rangeStart100ns_;
    previousRateRangeEnd100ns_ = rangeEnd100ns_;
    hasPreviousRateRange_ = false;
    selectionStart100ns_ = rangeStart100ns_;
    selectionEnd100ns_ = rangeEnd100ns_;
    dragPressTime100ns_ = 0;
    dragOriginalStart100ns_ = 0;
    dragOriginalEnd100ns_ = 0;
    dragMode_ = DragMode::kNone;
    userAdjustedSelection_ = false;
    unsetCursor();
    update();
}

void ProcessTraceTimelineWidget::resetSelectionToFullRange()
{
    // When clearing filters, use the full range selection and re-enable automatic following of the collection time's right end.
    selectionStart100ns_ = rangeStart100ns_;
    selectionEnd100ns_ = rangeEnd100ns_;
    userAdjustedSelection_ = false;
    dragMode_ = DragMode::kNone;
    unsetCursor();
    update();
}

void ProcessTraceTimelineWidget::setEventPoints(
    const std::vector<ProcessTraceTimelineEventPoint>& eventPointList)
{
    // Timeline height is fixed and horizontal resolution is limited; thousands of event points per pixel provide no additional visual information
    // but cause thousands of drawEllipse calls per repaint. The table retains all events; here we only bucket for rendering projection.
    constexpr int kMaxBucketsPerLane = 96;
    constexpr int kMaximumDrawablePoints = kLaneCount * kMaxBucketsPerLane;

    if (eventPointList.size() <= static_cast<std::size_t>(kMaximumDrawablePoints)
        || rangeEnd100ns_ <= rangeStart100ns_)
    {
        eventPointList_ = eventPointList;
        update();
        return;
    }

    std::vector<int> bucketIndexList(static_cast<std::size_t>(kMaximumDrawablePoints), -1);
    std::vector<ProcessTraceTimelineEventPoint> compactPointList;
    compactPointList.reserve(static_cast<std::size_t>(kMaximumDrawablePoints));
    const std::uint64_t kRangeDuration100ns = rangeEnd100ns_ - rangeStart100ns_;

    for (const ProcessTraceTimelineEventPoint& pointValue : eventPointList)
    {
        if (pointValue.time100ns < rangeStart100ns_ || pointValue.time100ns > rangeEnd100ns_)
        {
            continue;
        }

        const int kLaneIndex = laneForType(pointValue.typeText);
        const std::uint64_t kElapsed100ns = pointValue.time100ns - rangeStart100ns_;
        const double kBucketPosition = static_cast<double>(kElapsed100ns)
            * static_cast<double>(kMaxBucketsPerLane)
            / static_cast<double>(kRangeDuration100ns);
        const int kBucketIndex = std::min(
            kMaxBucketsPerLane - 1,
            static_cast<int>(kBucketPosition));
        const int kCombinedIndex = kLaneIndex * kMaxBucketsPerLane + kBucketIndex;
        int& compactIndex = bucketIndexList[static_cast<std::size_t>(kCombinedIndex)];
        if (compactIndex < 0)
        {
            compactIndex = static_cast<int>(compactPointList.size());
            compactPointList.push_back(pointValue);
        }
        else
        {
            // Keep the latest event in the same cell to make ongoing activities easier to observe on the timeline.
            compactPointList[static_cast<std::size_t>(compactIndex)] = pointValue;
        }
    }

    eventPointList_ = std::move(compactPointList);
    update();
}

void ProcessTraceTimelineWidget::setRateOverlayPoints(
    const std::vector<ProcessTraceTimelineRatePoint>& ratePointList)
{
    // Rate polyline is an optional overlay:
    // - The ETW page does not set this list, so the original event waterfall rendering remains unaffected;
    // - Network page provides upload/download rates aggregated by second; the control only maps them to the current time range.
    const ProcessTraceTimelineRatePoint kPreviousRatePoint = ratePointList_.empty()
        ? (ratePointList.empty() ? ProcessTraceTimelineRatePoint{} : ratePointList.back())
        : ratePointList_.back();
    ratePointList_ = ratePointList;
    if (ratePointList_.empty())
    {
        rateAnimation_->stop();
        rateAnimationProgress_ = 1.0;
        hasPreviousRatePoint_ = false;
        update();
        return;
    }
    previousRatePoint_ = kPreviousRatePoint;
    hasPreviousRatePoint_ = true;
    rateAnimationProgress_ = 0.0;
    rateAnimation_->stop();
    rateAnimation_->start();
}

ProcessTraceTimelineRatePoint ProcessTraceTimelineWidget::animatedRatePointAt(
    const std::size_t pointIndex) const
{
    const ProcessTraceTimelineRatePoint kTargetPoint = ratePointList_[pointIndex];
    if (!hasPreviousRatePoint_ || pointIndex + 1U != ratePointList_.size() || rateAnimationProgress_ >= 1.0)
    {
        return kTargetPoint;
    }
    ProcessTraceTimelineRatePoint result = kTargetPoint;
    if (kTargetPoint.time100ns >= previousRatePoint_.time100ns)
    {
        result.time100ns = previousRatePoint_.time100ns + static_cast<std::uint64_t>(
            static_cast<long double>(kTargetPoint.time100ns - previousRatePoint_.time100ns)
            * rateAnimationProgress_);
    }
    else
    {
        result.time100ns = kTargetPoint.time100ns;
    }
    result.uploadBytesPerSecond = previousRatePoint_.uploadBytesPerSecond
        + (kTargetPoint.uploadBytesPerSecond - previousRatePoint_.uploadBytesPerSecond) * rateAnimationProgress_;
    result.downloadBytesPerSecond = previousRatePoint_.downloadBytesPerSecond
        + (kTargetPoint.downloadBytesPerSecond - previousRatePoint_.downloadBytesPerSecond) * rateAnimationProgress_;
    return result;
}

double ProcessTraceTimelineWidget::animatedRateTimeToX(const std::uint64_t time100ns) const
{
    long double rangeStart = static_cast<long double>(rangeStart100ns_);
    long double rangeEnd = static_cast<long double>(rangeEnd100ns_);
    if (hasPreviousRateRange_ && rateAnimationProgress_ < 1.0)
    {
        const long double kProgress = rateAnimationProgress_;
        rangeStart = static_cast<long double>(previousRateRangeStart100ns_)
            + (rangeStart - static_cast<long double>(previousRateRangeStart100ns_)) * kProgress;
        rangeEnd = static_cast<long double>(previousRateRangeEnd100ns_)
            + (rangeEnd - static_cast<long double>(previousRateRangeEnd100ns_)) * kProgress;
    }

    const QRectF kAxisRect = timelineRect();
    if (rangeEnd <= rangeStart)
    {
        return kAxisRect.left();
    }
    const long double kRatio = std::clamp(
        (static_cast<long double>(time100ns) - rangeStart) / (rangeEnd - rangeStart),
        0.0L,
        1.0L);
    return kAxisRect.left() + kAxisRect.width() * static_cast<double>(kRatio);
}

void ProcessTraceTimelineWidget::setSelectionChangedCallback(
    std::function<void(std::uint64_t, std::uint64_t)> callbackValue)
{
    selectionChangedCallback_ = std::move(callbackValue);
}

std::uint64_t ProcessTraceTimelineWidget::selectionStart100ns() const
{
    return selectionStart100ns_;
}

std::uint64_t ProcessTraceTimelineWidget::selectionEnd100ns() const
{
    return selectionEnd100ns_;
}

void ProcessTraceTimelineWidget::paintEvent(QPaintEvent* eventPointer)
{
    (void)eventPointer;

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF kAxisRect = timelineRect();
    // themeColorFromText purpose: ksword_theme may return stylesheet text like palette(mid); since the
    // drawing API requires a real QColor, this provides a unified fallback for light and dark colors.
    const QColor kBorderColor = themeColorFromText(
        ksword_theme::borderColorHex(),
        ksword_theme::borderColor());
    const QColor kSurfaceColor = themeColorFromText(
        ksword_theme::surfaceColorHex(),
        ksword_theme::surfaceColor());
    const QColor kTextColor = themeColorFromText(
        ksword_theme::textSecondaryColorHex(),
        ksword_theme::textSecondaryColor());

    // Background and border:
    // - This rectangle represents the complete time range.
    // - Retain clear boundaries even when no events exist.
    painter.setPen(QPen(kBorderColor, 1.0));
    painter.setBrush(kSurfaceColor);
    painter.drawRect(kAxisRect);

    // Row separator lines serve only as weak hints; primary category information is conveyed via event point colors.
    painter.setPen(QPen(kBorderColor, 0.5));
    for (int laneIndex = 1; laneIndex < kLaneCount; ++laneIndex)
    {
        const double kYValue = kAxisRect.top()
            + kAxisRect.height() * static_cast<double>(laneIndex)
            / static_cast<double>(kLaneCount);
        painter.drawLine(QPointF(kAxisRect.left(), kYValue), QPointF(kAxisRect.right(), kYValue));
    }

    // Categorized event point drawing:
    // - Each event type falls into a stable vertical row;
    // - Point opacity is 20%; high-density events naturally stack intensity.
    for (const ProcessTraceTimelineEventPoint& pointValue : eventPointList_)
    {
        if (pointValue.time100ns < rangeStart100ns_ || pointValue.time100ns > rangeEnd100ns_)
        {
            continue;
        }

        const int kLaneIndex = laneForType(pointValue.typeText);
        const double kLaneHeight = kAxisRect.height() / static_cast<double>(kLaneCount);
        const double kYValue = kAxisRect.top() + kLaneHeight * (static_cast<double>(kLaneIndex) + 0.5);
        const double kXValue = timeToX(pointValue.time100ns);

        painter.setPen(Qt::NoPen);
        painter.setBrush(colorForType(pointValue.typeText));
        painter.drawEllipse(QPointF(kXValue, kYValue), 1.7, 1.7);
    }

    // Rate line overlay:
    // - Use a shared X-axis for the line chart; adapt the Y-axis to the peak value within the current visible range;
    // - Green indicates upload/egress, blue indicates download/ingress;
    // - Draw the line chart before the selection box to ensure the selected area remains on top.
    if (!ratePointList_.empty() && rangeEnd100ns_ > rangeStart100ns_)
    {
        double maxVisibleRate = 0.0;
        for (const ProcessTraceTimelineRatePoint& ratePoint : ratePointList_)
        {
            if (ratePoint.time100ns < rangeStart100ns_ || ratePoint.time100ns > rangeEnd100ns_)
            {
                continue;
            }
            maxVisibleRate = std::max(maxVisibleRate, ratePoint.uploadBytesPerSecond);
            maxVisibleRate = std::max(maxVisibleRate, ratePoint.downloadBytesPerSecond);
        }

        if (maxVisibleRate > 0.0)
        {
            QPolygonF uploadPolygon;
            QPolygonF downloadPolygon;
            const QRectF kRateRect = kAxisRect.adjusted(0.0, 3.0, 0.0, -4.0);

            // appendRatePoint: Maps 'B/s per second' to polyline coordinates.
            const auto kAppendRatePoint = [this, &kRateRect, maxVisibleRate](
                QPolygonF& polygon,
                const std::uint64_t time100ns,
                const double bytesPerSecond)
                {
                    const double kClampedRate = std::clamp(bytesPerSecond, 0.0, maxVisibleRate);
                    const double kRatio = maxVisibleRate <= 0.0 ? 0.0 : kClampedRate / maxVisibleRate;
                    const double kXValue = animatedRateTimeToX(time100ns);
                    const double kYValue = kRateRect.bottom() - kRateRect.height() * kRatio;
                    polygon << QPointF(kXValue, kYValue);
                };

            for (std::size_t rateIndex = 0; rateIndex < ratePointList_.size(); ++rateIndex)
            {
                const ProcessTraceTimelineRatePoint kRatePoint = animatedRatePointAt(rateIndex);
                if (kRatePoint.time100ns < rangeStart100ns_ || kRatePoint.time100ns > rangeEnd100ns_)
                {
                    continue;
                }
                kAppendRatePoint(uploadPolygon, kRatePoint.time100ns, kRatePoint.uploadBytesPerSecond);
                kAppendRatePoint(downloadPolygon, kRatePoint.time100ns, kRatePoint.downloadBytesPerSecond);
            }

            // Upload and download lines retain the green/blue semantic colors but now derive values from ksword_theme to ensure they follow the theme and custom accent colors.
            const QColor kUploadLineColor = ksword_theme::withAlpha(ksword_theme::successColor(), 220);
            const QColor kDownloadLineColor = ksword_theme::withAlpha(ksword_theme::infoColor(), 220);
            painter.setBrush(Qt::NoBrush);

            // drawPolyline requires at least two points; a single sample per second degenerates into a dot to avoid the polyline being invisible.
            painter.setPen(QPen(kDownloadLineColor, 1.5));
            if (downloadPolygon.size() > 1)
            {
                painter.drawPolyline(downloadPolygon);
            }
            else if (downloadPolygon.size() == 1)
            {
                painter.setBrush(kDownloadLineColor);
                painter.drawEllipse(downloadPolygon.first(), 2.0, 2.0);
                painter.setBrush(Qt::NoBrush);
            }

            painter.setPen(QPen(kUploadLineColor, 1.5));
            if (uploadPolygon.size() > 1)
            {
                painter.drawPolyline(uploadPolygon);
            }
            else if (uploadPolygon.size() == 1)
            {
                painter.setBrush(kUploadLineColor);
                painter.drawEllipse(uploadPolygon.first(), 2.0, 2.0);
                painter.setBrush(Qt::NoBrush);
            }

            // Draw the concise legend directly within the axis to avoid consuming vertical space in the Network Dock with a new control.
            const QFont kOriginalFont = painter.font();
            QFont legendFont = kOriginalFont;
            legendFont.setPointSizeF(std::max(7.0, kOriginalFont.pointSizeF() - 1.0));
            painter.setFont(legendFont);
            painter.setPen(kUploadLineColor);
            painter.drawText(
                kAxisRect.adjusted(54.0, 1.0, -54.0, 0.0),
                Qt::AlignTop | Qt::AlignHCenter,
                ks::i18n::contextText(QStringLiteral("network.timeline.upload"), QStringLiteral("上行")));
            painter.setPen(kDownloadLineColor);
            painter.drawText(
                kAxisRect.adjusted(96.0, 1.0, -12.0, 0.0),
                Qt::AlignTop | Qt::AlignLeft,
                ks::i18n::contextText(QStringLiteral("network.timeline.download"), QStringLiteral("下行")));
            painter.setFont(kOriginalFont);
        }
    }

    // Draw the selection box after event points to ensure the drag box remains visible.
    const QRectF kSelectedRect = selectionRect();
    if (!kSelectedRect.isEmpty())
    {
        QColor fillColor(ksword_theme::primaryBlueColor);
        fillColor.setAlpha(36);
        QColor edgeColor(ksword_theme::primaryBlueColor);
        edgeColor.setAlpha(220);

        painter.setBrush(fillColor);
        painter.setPen(QPen(edgeColor, 1.5));
        painter.drawRect(kSelectedRect);

        // The left and right handles are two vertical lines; do not create additional child controls.
        painter.setPen(QPen(edgeColor, 2.0));
        painter.drawLine(kSelectedRect.topLeft(), kSelectedRect.bottomLeft());
        painter.drawLine(kSelectedRect.topRight(), kSelectedRect.bottomRight());
    }

    // Draw label last.
    // - Left side fixed relative time 00:00;
    // - The right side displays the total elapsed time, either current or after stopping.
    painter.setPen(kTextColor);
    const QString kLeftText = QStringLiteral("00:00");
    const QString kRightText = formatDurationText(rangeEnd100ns_ > rangeStart100ns_
        ? (rangeEnd100ns_ - rangeStart100ns_)
        : 0);
    painter.drawText(kAxisRect.adjusted(5, 0, -5, 0), Qt::AlignLeft | Qt::AlignVCenter, kLeftText);
    painter.drawText(kAxisRect.adjusted(5, 0, -5, 0), Qt::AlignRight | Qt::AlignVCenter, kRightText);
}

void ProcessTraceTimelineWidget::mousePressEvent(QMouseEvent* eventPointer)
{
    // Respond only to left-button drag events to prevent accidental time window changes triggered by right or middle buttons.
    if (eventPointer == nullptr || eventPointer->button() != Qt::LeftButton)
    {
        QWidget::mousePressEvent(eventPointer);
        return;
    }

    // hitMode determines whether subsequent mouse movement performs a global pan or a single-side stretch.
    const QPoint kPosition = currentMousePosition(eventPointer);
    const DragMode kHitMode = hitTestSelection(kPosition);
    if (kHitMode == DragMode::kNone)
    {
        QWidget::mousePressEvent(eventPointer);
        return;
    }

    // Record the drag start time and original selection; subsequent movements are calculated based on this stable baseline.
    dragMode_ = kHitMode;
    dragPressTime100ns_ = xToTime(kPosition.x());
    dragOriginalStart100ns_ = selectionStart100ns_;
    dragOriginalEnd100ns_ = selectionEnd100ns_;
    eventPointer->accept();
}

void ProcessTraceTimelineWidget::mouseMoveEvent(QMouseEvent* eventPointer)
{
    // Pass null events directly to Qt's default handler to maintain consistent QWidget behavior.
    if (eventPointer == nullptr)
    {
        QWidget::mouseMoveEvent(eventPointer);
        return;
    }

    const QPoint kPosition = currentMousePosition(eventPointer);
    if (dragMode_ == DragMode::kNone)
    {
        // Only update the cursor when not dragging; do not change the internal time selection.
        updateHoverCursor(kPosition);
        QWidget::mouseMoveEvent(eventPointer);
        return;
    }

    // currentTime100ns: The actual time corresponding to the mouse cursor position, independent of event point rendering results.
    const std::uint64_t kCurrentTime100ns = xToTime(kPosition.x());
    const std::uint64_t kOriginalWidth100ns =
        dragOriginalEnd100ns_ > dragOriginalStart100ns_
        ? (dragOriginalEnd100ns_ - dragOriginalStart100ns_)
        : kMinimumSelection100ns;

    if (dragMode_ == DragMode::kMove)
    {
        // Maintain the original selection width during a global move, changing only the absolute time of the left and right boundaries.
        const qint64 kDelta100ns = static_cast<qint64>(kCurrentTime100ns)
            - static_cast<qint64>(dragPressTime100ns_);
        qint64 newStart100ns = static_cast<qint64>(dragOriginalStart100ns_) + kDelta100ns;
        qint64 newEnd100ns = static_cast<qint64>(dragOriginalEnd100ns_) + kDelta100ns;

        if (newStart100ns < static_cast<qint64>(rangeStart100ns_))
        {
            // When the left side is out of bounds, snap to the timeline start while preserving the original width.
            newStart100ns = static_cast<qint64>(rangeStart100ns_);
            newEnd100ns = newStart100ns + static_cast<qint64>(kOriginalWidth100ns);
        }
        if (newEnd100ns > static_cast<qint64>(rangeEnd100ns_))
        {
            // On right-side overflow, snap to the timeline end while preserving the original width.
            newEnd100ns = static_cast<qint64>(rangeEnd100ns_);
            newStart100ns = newEnd100ns - static_cast<qint64>(kOriginalWidth100ns);
        }

        selectionStart100ns_ = static_cast<std::uint64_t>(std::max<qint64>(newStart100ns, 0));
        selectionEnd100ns_ = static_cast<std::uint64_t>(std::max<qint64>(newEnd100ns, 0));
    }
    else if (dragMode_ == DragMode::kResizeLeft)
    {
        // Left-edge stretching modifies only the start point; the end point remains at its original value when pressed.
        selectionStart100ns_ = kCurrentTime100ns;
        selectionEnd100ns_ = dragOriginalEnd100ns_;
    }
    else if (dragMode_ == DragMode::kResizeRight)
    {
        // Stretching the right edge modifies only the end point; the start point remains at its original value when pressed.
        selectionStart100ns_ = dragOriginalStart100ns_;
        selectionEnd100ns_ = kCurrentTime100ns;
    }

    // Any drag switches the timeline to user-selection mode and immediately notifies the event table filter.
    userAdjustedSelection_ = true;
    clampSelectionToRange();
    update();
    notifySelectionChanged();
    eventPointer->accept();
}

void ProcessTraceTimelineWidget::mouseReleaseEvent(QMouseEvent* eventPointer)
{
    // Left button release ends dragging; other buttons continue with default QWidget logic.
    if (eventPointer != nullptr && eventPointer->button() == Qt::LeftButton)
    {
        dragMode_ = DragMode::kNone;
        updateHoverCursor(currentMousePosition(eventPointer));
        eventPointer->accept();
        return;
    }

    QWidget::mouseReleaseEvent(eventPointer);
}

void ProcessTraceTimelineWidget::leaveEvent(QEvent* eventPointer)
{
    // When not dragging, leaving the control should restore the default cursor to prevent the parent interface from continuing to display the resize cursor.
    if (dragMode_ == DragMode::kNone)
    {
        unsetCursor();
    }

    QWidget::leaveEvent(eventPointer);
}

void ProcessTraceTimelineWidget::wheelEvent(QWheelEvent* eventPointer)
{
    // Do not consume the wheel event when the range is invalid; pass it to the parent scroll area for handling.
    if (eventPointer == nullptr || rangeEnd100ns_ <= rangeStart100ns_)
    {
        QWidget::wheelEvent(eventPointer);
        return;
    }

    const int kWheelDelta = effectiveWheelDelta(eventPointer);
    if (kWheelDelta == 0)
    {
        // Some trackpad events may lack direction information; in this case, do not change the time selection range.
        QWidget::wheelEvent(eventPointer);
        return;
    }

    // selectionWidth100ns is the selection width before the current zoom, used to calculate the zoom anchor ratio.
    const std::uint64_t kRangeWidth100ns = rangeEnd100ns_ - rangeStart100ns_;
    const std::uint64_t kSelectionWidth100ns =
        selectionEnd100ns_ > selectionStart100ns_
        ? (selectionEnd100ns_ - selectionStart100ns_)
        : kRangeWidth100ns;

    // Scroll wheel direction rule:
    // Expand the selection upward
    // - Shrink selection downward.
    const double kScaleFactor = kWheelDelta > 0 ? 1.20 : 0.80;
    std::uint64_t newWidth100ns = static_cast<std::uint64_t>(
        std::max<double>(
            static_cast<double>(kMinimumSelection100ns),
            static_cast<double>(kSelectionWidth100ns) * kScaleFactor));
    newWidth100ns = std::min(newWidth100ns, kRangeWidth100ns);

    // Zoom with the mouse's time point as the anchor; if the mouse is outside the selection, the ratio is clamped to the boundary.
    const std::uint64_t kAnchorTime100ns = xToTime(currentWheelPosition(eventPointer).x());
    const double kAnchorRatio = kSelectionWidth100ns == 0
        ? 0.5
        : std::clamp(
            static_cast<double>(kAnchorTime100ns > selectionStart100ns_
                ? kAnchorTime100ns - selectionStart100ns_
                : 0)
            / static_cast<double>(kSelectionWidth100ns),
            0.0,
            1.0);

    const std::uint64_t kLeftPart100ns = static_cast<std::uint64_t>(
        static_cast<double>(newWidth100ns) * kAnchorRatio);
    selectionStart100ns_ = kAnchorTime100ns > kLeftPart100ns
        ? kAnchorTime100ns - kLeftPart100ns
        : rangeStart100ns_;
    selectionEnd100ns_ = selectionStart100ns_ + newWidth100ns;

    // Wheel zooming is also a user-initiated selection of the time window and must be immediately overlaid onto the event table.
    userAdjustedSelection_ = true;
    clampSelectionToRange();
    update();
    notifySelectionChanged();
    eventPointer->accept();
}

QRectF ProcessTraceTimelineWidget::timelineRect() const
{
    // Clamp height and width to a minimum of 1 to prevent division by zero or an empty QRectF during extreme layout phases.
    return QRectF(
        static_cast<double>(kHorizontalPadding),
        static_cast<double>(kVerticalPadding),
        static_cast<double>(std::max(1, width() - kHorizontalPadding * 2)),
        static_cast<double>(std::max(1, height() - kVerticalPadding * 2 - 1)));
}

QRectF ProcessTraceTimelineWidget::selectionRect() const
{
    // If the capture range is invalid or the selection is empty, both the draw layer and hit testing should be treated as having no selection.
    if (rangeEnd100ns_ <= rangeStart100ns_ || selectionEnd100ns_ <= selectionStart100ns_)
    {
        return QRectF();
    }

    const QRectF kAxisRect = timelineRect();
    const double kLeftX = timeToX(selectionStart100ns_);
    const double kRightX = timeToX(selectionEnd100ns_);
    return QRectF(
        QPointF(std::min(kLeftX, kRightX), kAxisRect.top()),
        QPointF(std::max(kLeftX, kRightX), kAxisRect.bottom()));
}

ProcessTraceTimelineWidget::DragMode ProcessTraceTimelineWidget::hitTestSelection(const QPoint& position) const
{
    // The hit test focuses solely on the current selection rectangle, does not read event points, and therefore cannot infer events from the graphics.
    const QRectF kSelectedRect = selectionRect();
    if (kSelectedRect.isEmpty())
    {
        return DragMode::kNone;
    }

    const QRectF kExpandedRect = kSelectedRect.adjusted(
        -static_cast<double>(kEdgeHitWidth),
        0.0,
        static_cast<double>(kEdgeHitWidth),
        0.0);
    // expandedRect expands the clickable area, but the actual move mode still requires the point to be within the selection.
    if (!kExpandedRect.contains(position))
    {
        return DragMode::kNone;
    }

    if (std::abs(position.x() - kSelectedRect.left()) <= kEdgeHitWidth)
    {
        return DragMode::kResizeLeft;
    }
    if (std::abs(position.x() - kSelectedRect.right()) <= kEdgeHitWidth)
    {
        return DragMode::kResizeRight;
    }
    return kSelectedRect.contains(position) ? DragMode::kMove : DragMode::kNone;
}

void ProcessTraceTimelineWidget::updateHoverCursor(const QPoint& position)
{
    // The cursor only reflects the currently executable action and does not change any internal state.
    const DragMode kHitMode = hitTestSelection(position);
    if (kHitMode == DragMode::kResizeLeft || kHitMode == DragMode::kResizeRight)
    {
        setCursor(Qt::SizeHorCursor);
        return;
    }
    if (kHitMode == DragMode::kMove)
    {
        setCursor(Qt::OpenHandCursor);
        return;
    }
    unsetCursor();
}

double ProcessTraceTimelineWidget::timeToX(const std::uint64_t time100ns) const
{
    // Return the left boundary when no valid time range exists, ensuring the caller can still complete the rendering.
    const QRectF kAxisRect = timelineRect();
    if (rangeEnd100ns_ <= rangeStart100ns_)
    {
        return kAxisRect.left();
    }

    const std::uint64_t kClampedTime100ns = std::clamp(
        time100ns,
        rangeStart100ns_,
        rangeEnd100ns_);
    // ratio is the relative position of time within the full capture range.
    const double kRatio = static_cast<double>(kClampedTime100ns - rangeStart100ns_)
        / static_cast<double>(rangeEnd100ns_ - rangeStart100ns_);
    return kAxisRect.left() + kAxisRect.width() * kRatio;
}

std::uint64_t ProcessTraceTimelineWidget::xToTime(const double xValue) const
{
    // Coordinate-to-time conversion serves only selection interaction; the return value is clamped within the captured range.
    const QRectF kAxisRect = timelineRect();
    if (rangeEnd100ns_ <= rangeStart100ns_ || kAxisRect.width() <= 0.0)
    {
        return rangeStart100ns_;
    }

    const double kRatio = std::clamp(
        (xValue - kAxisRect.left()) / kAxisRect.width(),
        0.0,
        1.0);
    // offset100ns: The time offset relative to the start point.
    const double kOffset100ns = static_cast<double>(rangeEnd100ns_ - rangeStart100ns_) * kRatio;
    return rangeStart100ns_ + static_cast<std::uint64_t>(kOffset100ns);
}

int ProcessTraceTimelineWidget::laneForType(const QString& typeText) const
{
    // Line numbers are fixed to event types to ensure events of the same type do not jump rows across different refresh cycles.
    const QString kNormalizedText = typeText.trimmed();
    if (kNormalizedText == QStringLiteral("进程"))
    {
        return 0;
    }
    if (kNormalizedText == QStringLiteral("线程") || kNormalizedText == QStringLiteral("镜像"))
    {
        return kNormalizedText == QStringLiteral("线程") ? 1 : 2;
    }
    if (kNormalizedText == QStringLiteral("文件"))
    {
        return 3;
    }
    if (kNormalizedText == QStringLiteral("注册表"))
    {
        return 4;
    }
    if (kNormalizedText == QStringLiteral("网络") || kNormalizedText == QStringLiteral("DNS"))
    {
        return kNormalizedText == QStringLiteral("网络") ? 5 : 6;
    }
    if (kNormalizedText == QStringLiteral("PowerShell") || kNormalizedText == QStringLiteral("WMI"))
    {
        return kNormalizedText == QStringLiteral("PowerShell") ? 7 : 8;
    }
    if (kNormalizedText == QStringLiteral("计划任务") || kNormalizedText == QStringLiteral("安全审计"))
    {
        return kNormalizedText == QStringLiteral("计划任务") ? 9 : 10;
    }
    if (kNormalizedText == QStringLiteral("Defender"))
    {
        return 11;
    }
    return 12;
}

QColor ProcessTraceTimelineWidget::colorForType(const QString& typeText) const
{
    // Colors encode only event categories; transparency is uniformly set to 20% at the end of the function.
    QColor colorValue;
    const QString kNormalizedText = typeText.trimmed();
    if (kNormalizedText == QStringLiteral("进程"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kProcess);
    }
    else if (kNormalizedText == QStringLiteral("线程"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kThread);
    }
    else if (kNormalizedText == QStringLiteral("镜像"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kImage);
    }
    else if (kNormalizedText == QStringLiteral("文件"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kFile);
    }
    else if (kNormalizedText == QStringLiteral("注册表"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kRegistry);
    }
    else if (kNormalizedText == QStringLiteral("网络"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kNetwork);
    }
    else if (kNormalizedText == QStringLiteral("DNS"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kDns);
    }
    else if (kNormalizedText == QStringLiteral("PowerShell"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kPowerShell);
    }
    else if (kNormalizedText == QStringLiteral("WMI"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kWmi);
    }
    else if (kNormalizedText == QStringLiteral("安全审计"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kSecurity);
    }
    else if (kNormalizedText == QStringLiteral("Defender"))
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kStorage);
    }
    else
    {
        colorValue = ksword_theme::timelineColor(ksword_theme::TimelineRole::kKernel);
    }

    return ksword_theme::withAlpha(colorValue, 51);
}

QString ProcessTraceTimelineWidget::formatDurationText(const std::uint64_t duration100ns) const
{
    // ETW timestamp unit is 100ns; convert to seconds first before formatting.
    const std::uint64_t kTotalSeconds = duration100ns / (1000ULL * 1000ULL * 10ULL);
    const std::uint64_t kHours = kTotalSeconds / 3600ULL;
    const std::uint64_t kMinutes = (kTotalSeconds % 3600ULL) / 60ULL;
    const std::uint64_t kSeconds = kTotalSeconds % 60ULL;

    if (kHours > 0)
    {
        // Display hh:mm:ss when exceeding one hour to prevent the right-side label from losing hour information.
        return QStringLiteral("%1:%2:%3")
            .arg(static_cast<qulonglong>(kHours), 2, 10, QChar(u'0'))
            .arg(static_cast<qulonglong>(kMinutes), 2, 10, QChar(u'0'))
            .arg(static_cast<qulonglong>(kSeconds), 2, 10, QChar(u'0'));
    }

    // Display mm:ss within one hour to align with the short-time reading habit of the fixed 00:00 format on the left.
    return QStringLiteral("%1:%2")
        .arg(static_cast<qulonglong>(kMinutes), 2, 10, QChar(u'0'))
        .arg(static_cast<qulonglong>(kSeconds), 2, 10, QChar(u'0'));
}

void ProcessTraceTimelineWidget::clampSelectionToRange()
{
    // When the capture range is invalid, sync directly to the range endpoints to avoid retaining stale selections.
    if (rangeEnd100ns_ <= rangeStart100ns_)
    {
        selectionStart100ns_ = rangeStart100ns_;
        selectionEnd100ns_ = rangeEnd100ns_;
        return;
    }

    if (selectionStart100ns_ > selectionEnd100ns_)
    {
        // Allow swapping when dragging past the left/right edges, then correct to the minimum width.
        std::swap(selectionStart100ns_, selectionEnd100ns_);
    }

    // The minimum width cannot exceed the entire capture range.
    const std::uint64_t kRangeWidth100ns = rangeEnd100ns_ - rangeStart100ns_;
    const std::uint64_t kMinimumWidth100ns = std::min(kMinimumSelection100ns, kRangeWidth100ns);

    selectionStart100ns_ = std::clamp(
        selectionStart100ns_,
        rangeStart100ns_,
        rangeEnd100ns_);
    selectionEnd100ns_ = std::clamp(
        selectionEnd100ns_,
        rangeStart100ns_,
        rangeEnd100ns_);

    if (selectionEnd100ns_ >= selectionStart100ns_
        && (selectionEnd100ns_ - selectionStart100ns_) >= kMinimumWidth100ns)
    {
        // No need to move boundaries if the selection is already valid.
        return;
    }

    if (dragMode_ == DragMode::kResizeLeft)
    {
        // When the left edge stretch is too narrow, prioritize keeping the right edge fixed.
        selectionStart100ns_ = selectionEnd100ns_ > kMinimumWidth100ns
            ? selectionEnd100ns_ - kMinimumWidth100ns
            : rangeStart100ns_;
    }
    else
    {
        // In other scenarios, prioritize keeping the left edge fixed while expanding the right edge.
        selectionEnd100ns_ = selectionStart100ns_ + kMinimumWidth100ns;
    }

    if (selectionEnd100ns_ > rangeEnd100ns_)
    {
        // After correcting the right-side overflow, move the left side backward to maintain the minimum width.
        selectionEnd100ns_ = rangeEnd100ns_;
        selectionStart100ns_ = selectionEnd100ns_ > kMinimumWidth100ns
            ? selectionEnd100ns_ - kMinimumWidth100ns
            : rangeStart100ns_;
    }
}

void ProcessTraceTimelineWidget::notifySelectionChanged()
{
    // If the callback is null, only update the local draw state; the host may choose not to bind filtering logic.
    if (selectionChangedCallback_)
    {
        selectionChangedCallback_(selectionStart100ns_, selectionEnd100ns_);
    }
}

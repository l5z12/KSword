#include "ProcessActivityTimelineSlider.h"

using namespace ksword::ui::process_dock;

    // Constructor:
    // - ownerDock: Used to read historical snapshots on hover.
    // - parent: Qt parent control;
    // - No return value; enables mouse tracking to implement 'show snapshot on hover'.
    ProcessActivityTimelineSlider::ProcessActivityTimelineSlider(ProcessDock* ownerDock, QWidget* parent )
        : QSlider(Qt::Horizontal, parent)
        , ownerDock_(ownerDock)
    {
        setMouseTracking(true);
        setFocusPolicy(Qt::StrongFocus);
    }

    // mouseMoveEvent：
    // - Map to the corresponding sample when the mouse hovers over any position on the timeline.
    // - Snapshots can be displayed without requiring a drag action.
    void ProcessActivityTimelineSlider::mouseMoveEvent(QMouseEvent* eventPointer) {
        if (eventPointer != nullptr && ownerDock_ != nullptr && !ownerDock_->activitySamples_.empty())
        {
            const int kSampleIndex = valueAtPosition(activityMousePosition(eventPointer).x());
            // Hover only updates the snapshot tooltip, without changing the slider value or repainting the process table below.
            const bool kOldPinnedToLatest = ownerDock_->activityTimelinePinnedToLatest_;
            ownerDock_->previewProcessActivitySnapshotForIndex(kSampleIndex);
            ownerDock_->activityTimelinePinnedToLatest_ = kOldPinnedToLatest;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            const QPoint kGlobalPosition = eventPointer->globalPosition().toPoint();
#else
            const QPoint globalPosition = eventPointer->globalPos();
#endif
            QToolTip::showText(kGlobalPosition, ownerDock_->buildProcessActivitySnapshotText(kSampleIndex), this);
        }
        QSlider::mouseMoveEvent(eventPointer);
    }

    // mousePressEvent：
    // - Clicking the timeline jumps to the corresponding sample.
    // - After dragging to the far right, the host re-enters the 'snap to latest' mode.
    void ProcessActivityTimelineSlider::mousePressEvent(QMouseEvent* eventPointer) {
        if (eventPointer != nullptr && eventPointer->button() == Qt::LeftButton && maximum() >= minimum())
        {
            const int kSampleIndex = valueAtPosition(activityMousePosition(eventPointer).x());
            setValue(kSampleIndex);
            if (ownerDock_ != nullptr)
            {
                ownerDock_->commitProcessActivityTimelineIndex(kSampleIndex);
            }
            eventPointer->accept();
            return;
        }
        QSlider::mousePressEvent(eventPointer);
    }

    // leaveEvent：
    // - Hide tooltip after mouse leaves;
    // - The currently selected historical sample remains in the snapshot tab below.
    void ProcessActivityTimelineSlider::leaveEvent(QEvent* eventPointer) {
        QToolTip::hideText();
        QSlider::leaveEvent(eventPointer);
    }

    // valueAtPosition：
    // - Map local X coordinates to the slider range.
    // - Return value is automatically clamped between minimum and maximum.
    int ProcessActivityTimelineSlider::valueAtPosition(const int xValue) const
    {
        const int kRangeValue = maximum() - minimum();
        if (kRangeValue <= 0 || width() <= 1)
        {
            return minimum();
        }
        const QStyleOptionSlider kOption = sliderOption();
        const QRect kGrooveRect = style()->subControlRect(QStyle::CC_Slider, &kOption, QStyle::SC_SliderGroove, this);
        const QRect kHandleRect = style()->subControlRect(QStyle::CC_Slider, &kOption, QStyle::SC_SliderHandle, this);
        const int kSliderMin = kGrooveRect.left();
        const int kSliderMax = kGrooveRect.right() - kHandleRect.width() + 1;
        if (kSliderMax <= kSliderMin)
        {
            const double kFallbackRatio = std::clamp(
                static_cast<double>(xValue) / static_cast<double>(std::max(1, width() - 1)),
                0.0,
                1.0);
            return minimum() + static_cast<int>(std::llround(kFallbackRatio * static_cast<double>(kRangeValue)));
        }
        const double kDenominator = static_cast<double>(std::max(1, kSliderMax - kSliderMin));
        const double kRatio = std::clamp(
            (static_cast<double>(xValue) - static_cast<double>(kSliderMin)) / kDenominator,
            0.0,
            1.0);
        return minimum() + static_cast<int>(std::llround(kRatio * static_cast<double>(kRangeValue)));
    }

    // sliderOption：
    // - Construct the current QSlider style option.
    // - Used to accurately obtain the groove/handle geometric range.
    QStyleOptionSlider ProcessActivityTimelineSlider::sliderOption() const
    {
        QStyleOptionSlider option;
        initStyleOption(&option);
        return option;
    }

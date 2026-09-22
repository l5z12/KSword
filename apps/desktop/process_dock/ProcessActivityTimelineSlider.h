#pragma once
#include "ProcessDock.Support.h"

class ProcessActivityTimelineSlider final : public QSlider
{
public:
    // Constructor:
    // - ownerDock: Used to read historical snapshots on hover.
    // - parent: Qt parent control;
    // - No return value; enables mouse tracking to implement 'show snapshot on hover'.
    explicit ProcessActivityTimelineSlider(ProcessDock* ownerDock, QWidget* parent = nullptr);

protected:
    // mouseMoveEvent：
    // - Map to the corresponding sample when the mouse hovers over any position on the timeline.
    // - Snapshots can be displayed without requiring a drag action.
    void mouseMoveEvent(QMouseEvent* eventPointer) override;

    // mousePressEvent：
    // - Clicking the timeline jumps to the corresponding sample.
    // - After dragging to the far right, the host re-enters the 'snap to latest' mode.
    void mousePressEvent(QMouseEvent* eventPointer) override;

    // leaveEvent：
    // - Hide tooltip after mouse leaves;
    // - The currently selected historical sample remains in the snapshot tab below.
    void leaveEvent(QEvent* eventPointer) override;

private:
    // valueAtPosition：
    // - Map local X coordinates to the slider range.
    // - Return value is automatically clamped between minimum and maximum.
    int valueAtPosition(const int xValue) const;

    // sliderOption：
    // - Construct the current QSlider style option.
    // - Used to accurately obtain the groove/handle geometric range.
    QStyleOptionSlider sliderOption() const;

private:
    ProcessDock* ownerDock_ = nullptr; // m_ownerDock: Host ProcessDock, does not own.
};

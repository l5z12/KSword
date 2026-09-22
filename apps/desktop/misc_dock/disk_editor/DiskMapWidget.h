#pragma once

// ============================================================
// DiskMapWidget.h
// Purpose:
// 1) Provide a horizontal bar disk view similar to DiskGenius.
// 2) Draw partitions, unallocated regions, and tick marks according to the ratio of actual offset and capacity;
// 3) Returns the user-clicked partition to the upper-level disk editor page via signals.
// ============================================================

#include "DiskEditorModels.h"

#include <QPoint>
#include <QRect>
#include <QWidget>

#include <cstdint>
#include <vector>

class QEvent;
class QMouseEvent;
class QPaintEvent;

namespace ks::misc
{
    // DiskMapWidget:
    // - Input: DiskDeviceInfo snapshot;
    // - Logic: Build horizontal partition rectangles proportional to capacity and draw labels.
    // - Return behavior: No direct return value; clicking a partition emits partitionActivated.
    class DiskMapWidget final : public QWidget
    {
        Q_OBJECT

    public:
        // Constructor:
        // - parent is the Qt parent widget;
        // - initialize mouse tracking and minimum height.
        explicit DiskMapWidget(QWidget* parent = nullptr);

        // setDisk：
        // - Sets the currently displayed disk snapshot;
        // - diskInfo contains disk and partition information;
        // - No return value; triggers internal repaint.
        void setDisk(const DiskDeviceInfo& diskInfo);

        // clearDisk：
        // - Clear current display;
        // - No input parameters or return value.
        void clearDisk();

        // setSelectedPartitionIndex：
        // - Synchronize the current partition in the external table.
        // - partitionIndex corresponds to DiskPartitionInfo::tableIndex.
        // - No return value; triggers internal repaint.
        void setSelectedPartitionIndex(int partitionIndex);

    signals:
        // partitionActivated：
        // - Triggered when the user clicks a partition or unallocated block in the bar chart;
        // - partitionIndex corresponds to DiskPartitionInfo::tableIndex;
        // - Not emitted when missing a valid region.
        void partitionActivated(int partitionIndex);

    protected:
        // paintEvent：
        // - Qt paint entry;
        // - event is the paint event object;
        // - No return value.
        void paintEvent(QPaintEvent* event) override;

        // mousePressEvent：
        // - Handle left-click hit testing.
        // - event is the mouse event object;
        // - No return value.
        void mousePressEvent(QMouseEvent* event) override;

        // mouseMoveEvent：
        // - Update the hovered partition index and tooltip.
        // - event is the mouse event object;
        // - No return value.
        void mouseMoveEvent(QMouseEvent* event) override;

        // leaveEvent：
        // - Clear hover state when the mouse leaves.
        // - event is the leave event object;
        // - No return value.
        void leaveEvent(QEvent* event) override;

    private:
        // PaintSegment:
        // - Stores clickable drawing blocks obtained from a single layout;
        // - rect uses the widget coordinate system
        struct PaintSegment
        {
            QRect rect;                  // rect: Rectangle for drawing and hit testing.
            DiskPartitionInfo partition; // partition: Partition information corresponding to this drawing block.
        };

    private:
        // rebuildPaintSegments：
        // - Rebuild the rectangular layout based on the current widget size and disk information;
        // - No input parameters;
        // - Returns the array of paint segments.
        std::vector<PaintSegment> rebuildPaintSegments() const;

        // hitTest：
        // - Find partition based on mouse position;
        // - point is the widget coordinate.
        // - Returns the tableIndex; returns -1 if no match is found.
        int hitTest(const QPoint& point) const;

        // segmentTooltipText：
        // - Construct a tooltip for a specific segment.
        // - segment is the drawn block;
        // - Returns displayable text.
        static QString segmentTooltipText(const PaintSegment& segment);

    private:
        DiskDeviceInfo diskInfo_;       // m_diskInfo: Current disk snapshot.
        bool hasDisk_ = false;          // m_hasDisk: Whether a valid disk is bound.
        int selectedPartitionIndex_ = -1; // m_selectedPartitionIndex: Currently selected partition.
        int hoverPartitionIndex_ = -1;    // m_hoverPartitionIndex: Currently hovered partition.
    };
}

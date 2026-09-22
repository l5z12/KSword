#pragma once

#include "../../../shared/platform/process/ProcessCpuCoreEtwMonitor.h"

#include <QFontMetrics>
#include <QList>
#include <QMetaType>
#include <QModelIndex>
#include <QPoint>
#include <QSize>
#include <QString>
#include <QStyleOptionViewItem>

#include <cstdint>
#include <memory>

class QPainter;

namespace ks::ui
{
    // ProcessCpuUsageSnapshotPtr: All process rows share the same read-only ETW snapshot per round, avoiding duplication of the PID×core matrix.
    using ProcessCpuUsageSnapshotPtr =
        std::shared_ptr<const ks::process::CpuCoreUsageSnapshot>;

    // Both roles pass the shared snapshot and target PID set to the custom paint delegate.
    // The caller returns only lightweight shared_ptr/PID lists; no QWidget is created for any process or core.
    inline constexpr int kProcessCpuUsageSnapshotRole = Qt::UserRole + 207;
    inline constexpr int kProcessCpuProcessIdsRole = Qt::UserRole + 208;

    // processCpuCapacityCellSizeHint: Calculates the preferred size for the full sector of all real logical cores in the independent 'CPU Core' column.
    // Call pattern: Invoked when the process table model handles Qt::SizeHintRole; arguments are the table font and logical processor count.
    // Return value: A QSize suitable for the column width adapter; does not access the sampler, thread handle, or process handle.
    QSize processCpuCapacityCellSizeHint(
        const QFontMetrics& fontMetrics,
        std::uint32_t logicalProcessorCount);

    // hasProcessCpuCapacityCellData: Determines if the model index carries valid shared snapshots and the target PID.
    // Call method: Called by QStyledItemDelegate::paint before default drawing; input is the current model index.
    // Return value: true indicates per-core cells can be drawn; false indicates falling back to standard Qt cell drawing.
    bool hasProcessCpuCapacityCellData(const QModelIndex& index);

    // paintProcessCpuCapacityCell purpose: Draw a pie chart for the usage of each real logical CPU in the independent column.
    // Call method: The proxy first calls initStyleOption, then passes the painter, complete style options, and model index.
    // Return behavior: Draw only the currently visible cell; when ETW data is incomplete, render a gray invalid state instead of faking 0%.
    void paintProcessCpuCapacityCell(
        QPainter* painter,
        const QStyleOptionViewItem& option,
        const QModelIndex& index);

    // processCpuCapacityToolTipText purpose: generates the actual CPU utilization tooltip for the target logical CPU based on mouse position.
    // Call method: The proxy passes style options, model index, and viewport coordinates via helpEvent; performs only read-only index calculations.
    // Return value: Returns the description text if a core sector is hit; otherwise returns an empty string to defer to the default tooltip path.
    QString processCpuCapacityToolTipText(
        const QStyleOptionViewItem& option,
        const QModelIndex& index,
        const QPoint& viewportPosition);
}

Q_DECLARE_METATYPE(ks::ui::ProcessCpuUsageSnapshotPtr)

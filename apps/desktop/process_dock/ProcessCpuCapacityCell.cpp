#include "ProcessCpuCapacityCell.h"

#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QColor>
#include <QIcon>
#include <QPainter>
#include <QStyle>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <vector>

namespace
{
    // Fixed cell geometry: value refreshes do not change column width; each real logical CPU retains a compact fan-shaped slot.
    constexpr int kCpuCellHorizontalMargin = 6;
    constexpr int kCpuSlotMaximumSide = 14;
    constexpr int kCpuSlotMinimumSide = 10;
    constexpr int kCpuSlotGap = 2;

    // CpuSlotPaintValue: Bind the sampled value and trust status for a single core sample to prevent missing samples from being incorrectly rendered as 0%.
    struct CpuSlotPaintValue
    {
        double percent = 0.0; // percent: Current process interval utilization on this real logical CPU.
        bool sampleReady = false; // sampleReady: Must render gray invalid state when false.
    };

    // blendCpuColor purpose: Blends two theme semantic colors by ratio in linear RGB space.
    // Usage: cpuLoadColor generates blue, green, yellow, and red utilization colors in segments; the ratio is automatically clamped.
    // Return value: Opaque QColor; does not modify QApplication palette or global theme state.
    QColor blendCpuColor(const QColor& startColor, const QColor& endColor, const double ratio)
    {
        // safeRatio: Protects against floating-point errors to ensure each RGB channel remains within 0–255.
        const double kSafeRatio = std::clamp(ratio, 0.0, 1.0);
        const auto kBlendChannel = [kSafeRatio](const int startValue, const int endValue) -> int
        {
            return static_cast<int>(std::lround(
                static_cast<double>(startValue) +
                static_cast<double>(endValue - startValue) * kSafeRatio));
        };

        return QColor(
            kBlendChannel(startColor.red(), endColor.red()),
            kBlendChannel(startColor.green(), endColor.green()),
            kBlendChannel(startColor.blue(), endColor.blue()),
            255);
    }

    // cpuLoadColor purpose: Map a real logical CPU's 0~100% utilization to the theme foreground color.
    // Usage: called before drawing a sector for each valid core slot; input is the ratio already clamped to 0~1.
    // Return value: low usage blue, medium usage green/yellow, high usage red.
    QColor cpuLoadColor(const double loadRatio)
    {
        const double kSafeLoadRatio = std::clamp(loadRatio, 0.0, 1.0);
        if (kSafeLoadRatio <= 0.30)
        {
            return blendCpuColor(
                ksword_theme::primaryBlueColor,
                ksword_theme::successColor(),
                kSafeLoadRatio / 0.30);
        }
        if (kSafeLoadRatio <= 0.70)
        {
            return blendCpuColor(
                ksword_theme::successColor(),
                ksword_theme::warningColor(),
                (kSafeLoadRatio - 0.30) / 0.40);
        }
        return blendCpuColor(
            ksword_theme::warningColor(),
            ksword_theme::errorColor(),
            (kSafeLoadRatio - 0.70) / 0.30);
    }

    // cpuSnapshotFromIndex: Recovers the current shared ETW snapshot from the model role.
    // Usage: Shared by painting, hit testing, and tooltips; input is the CPU column model index.
    // Return value: Valid read-only shared_ptr; returns null if the role is missing.
    ks::ui::ProcessCpuUsageSnapshotPtr cpuSnapshotFromIndex(const QModelIndex& index)
    {
        if (!index.isValid())
        {
            return {};
        }
        return index.data(ks::ui::kProcessCpuUsageSnapshotRole)
            .value<ks::ui::ProcessCpuUsageSnapshotPtr>();
    }

    // cpuProcessIdsFromIndex purpose: Read one or more real PIDs bound to the CPU core cell.
    // Invocation: For real process rows, returns a single-element list; for application aggregation rows, returns all their currently alive member PIDs.
    // Return: true if at least one PID is included; PID 0 is retained as a valid member for full core layout.
    bool cpuProcessIdsFromIndex(
        const QModelIndex& index,
        QList<std::uint32_t>* const processIdsOut)
    {
        if (!index.isValid() || processIdsOut == nullptr)
        {
            return false;
        }

        const QVariant kProcessIdsValue =
            index.data(ks::ui::kProcessCpuProcessIdsRole);
        if (!kProcessIdsValue.canConvert<QList<std::uint32_t>>())
        {
            return false;
        }

        *processIdsOut = kProcessIdsValue.value<QList<std::uint32_t>>();
        return !processIdsOut->isEmpty();
    }

    // cpuSlotSide: Calculates the sector slot side length (10~14px) based on the current row height.
    // Usage: drawing and mouse hit testing must use the same result to prevent the tooltip from pointing to an adjacent core.
    // Return value: Integer pixel side length adapted to the current DPI and row height.
    int cpuSlotSide(const QRect& contentRect)
    {
        return std::clamp(
            contentRect.height() - 6,
            kCpuSlotMinimumSide,
            kCpuSlotMaximumSide);
    }

    // cpuSlotRect: Calculates the position of the small sector slot corresponding to a specific global logical processor index.
    // Invocation: The caller first obtains contentRect/slotSide, then iterates through slots by processorIndex.
    // Returns: a viewport coordinate rectangle identical to the one used for painting and tooltips.
    QRect cpuSlotRect(
        const QRect& contentRect,
        const int slotSide,
        const std::size_t processorIndex)
    {
        const int kSlotsLeft = contentRect.left();
        const int kSlotTop = contentRect.center().y() - slotSide / 2;
        const int kSlotLeft = kSlotsLeft +
            static_cast<int>(processorIndex) * (slotSide + kCpuSlotGap);
        return QRect(kSlotLeft, kSlotTop, slotSide, slotSide);
    }

    // processUsageSeriesList purpose: Locate the per-core series for the target PID set in a single operation.
    // Call method: Called when a cell starts rendering or before a tooltip hit; subsequent cores do not re-query the hash table.
    // Return value: Only save sequences that actually ran in this round; sequences with no members are treated as 0% trusted.
    std::vector<const ks::process::CpuCoreUsageSeries*> processUsageSeriesList(
        const ks::process::CpuCoreUsageSnapshot& snapshot,
        const QList<std::uint32_t>& processIds)
    {
        std::vector<const ks::process::CpuCoreUsageSeries*> usageSeriesList;
        usageSeriesList.reserve(static_cast<std::size_t>(processIds.size()));
        for (const std::uint32_t kProcessId : processIds)
        {
            const auto kProcessUsageIt = snapshot.processUsageByPid.find(kProcessId);
            if (kProcessUsageIt != snapshot.processUsageByPid.end())
            {
                usageSeriesList.push_back(&kProcessUsageIt->second);
            }
        }
        return usageSeriesList;
    }

    // cpuSlotPaintValue purpose: Read and summarize the trusted interval utilization on a specific physical logical CPU.
    // Usage: Pass the PID sequence retrieved in one query and the processor index; the parent row sums over each member.
    // Return value: returns a credible 0% if no members ran in this round; unavailable if samples are invalid; total value is capped at 100%.
    CpuSlotPaintValue cpuSlotPaintValue(
        const ks::process::CpuCoreUsageSnapshot& snapshot,
        const std::vector<const ks::process::CpuCoreUsageSeries*>& usageSeriesList,
        const std::size_t processorIndex)
    {
        CpuSlotPaintValue value;
        value.sampleReady =
            snapshot.monitorRunning &&
            snapshot.sampleReady &&
            !snapshot.dataLossDetected &&
            processorIndex < snapshot.sampleReadyByProcessor.size() &&
            snapshot.sampleReadyByProcessor[processorIndex];
        if (!value.sampleReady)
        {
            return value;
        }

        double aggregatePercent = 0.0;
        for (const ks::process::CpuCoreUsageSeries* const kUsageSeries : usageSeriesList)
        {
            if (kUsageSeries == nullptr ||
                processorIndex >= kUsageSeries->percentByProcessor.size() ||
                (processorIndex < kUsageSeries->sampleReadyByProcessor.size() &&
                    !kUsageSeries->sampleReadyByProcessor[processorIndex]))
            {
                value.sampleReady = false;
                return value;
            }
            aggregatePercent += kUsageSeries->percentByProcessor[processorIndex];
        }

        value.percent = std::clamp(aggregatePercent, 0.0, 100.0);
        return value;
    }

    // drawCpuCoreSlot: Draws an independent core-by-core sector chart without a box or ring border.
    // Call method: The caller has already uniformly enabled anti-aliasing and saved the painter state; this function does not repeat save/restore.
    // Return behavior: A neutral rounded circle indicates free space, colored sectors indicate usage; invalid samples are overlaid with thin gray diagonal lines.
    void drawCpuCoreSlot(
        QPainter* const painter,
        const QRect& slotRect,
        const CpuSlotPaintValue& value)
    {
        if (painter == nullptr || !slotRect.isValid())
        {
            return;
        }

        // pieRect: Use the slot body directly as the pie slice; no longer draw the outer rounded rectangle or blue ring.
        const QRectF kPieRect = QRectF(slotRect).adjusted(1.0, 1.0, -1.0, -1.0);
        const QColor kIdleColor = ksword_theme::withAlpha(
            ksword_theme::surfaceMutedColor(),
            ksword_theme::isDarkModeEnabled() ? 65 : 85);
        painter->setPen(Qt::NoPen);
        painter->setBrush(kIdleColor);
        painter->drawEllipse(kPieRect);

        if (!value.sampleReady)
        {
            // Invalid samples use no colored outline; draw only a restrained diagonal line on a neutral circular background.
            const QColor kUnavailableColor = ksword_theme::withAlpha(
                ksword_theme::textDisabledColor(),
                185);
            painter->setPen(QPen(kUnavailableColor, 1.0, Qt::SolidLine, Qt::RoundCap));
            painter->drawLine(
                kPieRect.topLeft() + QPointF(1.5, 1.5),
                kPieRect.bottomRight() - QPointF(1.5, 1.5));
            return;
        }

        const double kLoadRatio = std::clamp(value.percent / 100.0, 0.0, 1.0);
        if (kLoadRatio <= 0.0)
        {
            return;
        }

        painter->setPen(Qt::NoPen);
        painter->setBrush(cpuLoadColor(kLoadRatio));
        if (kLoadRatio >= 0.9995)
        {
            painter->drawEllipse(kPieRect);
            return;
        }
        painter->drawPie(
            kPieRect,
            90 * 16,
            -static_cast<int>(std::lround(kLoadRatio * 360.0 * 16.0)));
    }
}

QSize ks::ui::processCpuCapacityCellSizeHint(
    const QFontMetrics& fontMetrics,
    const std::uint32_t logicalProcessorCount)
{
    // Set a defensive upper limit on the logical processor count to prevent integer overflow caused by anomalous system return values.
    const int kSafeProcessorCount = static_cast<int>(std::min<std::uint32_t>(
        logicalProcessorCount,
        4096U));
    const int kSlotWidth = kSafeProcessorCount > 0
        ? kSafeProcessorCount * kCpuSlotMaximumSide +
            (kSafeProcessorCount - 1) * kCpuSlotGap
        : 0;
    const int kWidthValue = kCpuCellHorizontalMargin * 2 + kSlotWidth;
    const int kHeightValue = std::max(fontMetrics.height() + 6, kCpuSlotMaximumSide + 6);
    return QSize(kWidthValue, kHeightValue);
}

bool ks::ui::hasProcessCpuCapacityCellData(const QModelIndex& index)
{
    QList<std::uint32_t> processIds;
    const ProcessCpuUsageSnapshotPtr kSnapshot = cpuSnapshotFromIndex(index);
    return kSnapshot != nullptr && cpuProcessIdsFromIndex(index, &processIds);
}

void ks::ui::paintProcessCpuCapacityCell(
    QPainter* const painter,
    const QStyleOptionViewItem& option,
    const QModelIndex& index)
{
    QList<std::uint32_t> processIds;
    const ProcessCpuUsageSnapshotPtr kSnapshot = cpuSnapshotFromIndex(index);
    if (painter == nullptr || !option.rect.isValid() || kSnapshot == nullptr ||
        !cpuProcessIdsFromIndex(index, &processIds))
    {
        return;
    }

    // First, let the current Qt style render the model background to preserve the background color and interaction state of added/removed/high-usage rows.
    QStyleOptionViewItem backgroundOption(option);
    backgroundOption.text.clear();
    backgroundOption.icon = QIcon();
    const QWidget* viewWidget = option.widget;
    QStyle* viewStyle = viewWidget != nullptr ? viewWidget->style() : QApplication::style();
    if (viewStyle != nullptr)
    {
        viewStyle->drawControl(
            QStyle::CE_ItemViewItem,
            &backgroundOption,
            painter,
            viewWidget);
    }

    const QRect kContentRect = option.rect.adjusted(
        kCpuCellHorizontalMargin,
        1,
        -kCpuCellHorizontalMargin,
        -1);
    painter->save();

    // Only iterate over core slots actually visible within the current painter's clipping region; high-core-count machines avoid rendering costs for sectors outside the screen.
    painter->setRenderHint(QPainter::Antialiasing, true);
    const int kSlotSide = cpuSlotSide(kContentRect);
    const QRectF kVisiblePaintRect = painter->hasClipping()
        ? painter->clipBoundingRect()
        : QRectF(option.rect);
    const std::size_t kProcessorCount = kSnapshot->processors.size();
    const std::vector<const ks::process::CpuCoreUsageSeries*> kUsageSeriesList =
        processUsageSeriesList(*kSnapshot, processIds);
    const int kSlotStride = kSlotSide + kCpuSlotGap;
    const int kSlotsLeft = kContentRect.left();
    const int kFirstVisibleOffset = std::max(
        0,
        static_cast<int>(std::floor(
            (kVisiblePaintRect.left() - kSlotsLeft - kSlotSide) /
            static_cast<double>(kSlotStride))));
    const std::size_t kFirstVisibleProcessor = std::min<std::size_t>(
        kProcessorCount,
        static_cast<std::size_t>(kFirstVisibleOffset));
    for (std::size_t processorIndex = kFirstVisibleProcessor;
        processorIndex < kProcessorCount;
        ++processorIndex)
    {
        const QRect kSlotRect = cpuSlotRect(
            kContentRect,
            kSlotSide,
            processorIndex);
        if (kSlotRect.right() < kVisiblePaintRect.left())
        {
            continue;
        }
        if (kSlotRect.left() > kVisiblePaintRect.right())
        {
            break;
        }

        drawCpuCoreSlot(
            painter,
            kSlotRect,
            cpuSlotPaintValue(*kSnapshot, kUsageSeriesList, processorIndex));
    }
    painter->restore();
}

QString ks::ui::processCpuCapacityToolTipText(
    const QStyleOptionViewItem& option,
    const QModelIndex& index,
    const QPoint& viewportPosition)
{
    QList<std::uint32_t> processIds;
    const ProcessCpuUsageSnapshotPtr kSnapshot = cpuSnapshotFromIndex(index);
    if (kSnapshot == nullptr || !cpuProcessIdsFromIndex(index, &processIds))
    {
        return {};
    }

    const QRect kContentRect = option.rect.adjusted(
        kCpuCellHorizontalMargin,
        1,
        -kCpuCellHorizontalMargin,
        -1);
    const int kSlotSide = cpuSlotSide(kContentRect);
    const int kSlotStride = kSlotSide + kCpuSlotGap;
    const int kSlotsLeft = kContentRect.left();
    const int kRelativeX = viewportPosition.x() - kSlotsLeft;
    if (kRelativeX < 0 || kSlotStride <= 0)
    {
        return {};
    }

    const std::size_t kProcessorIndex = static_cast<std::size_t>(kRelativeX / kSlotStride);
    if (kProcessorIndex >= kSnapshot->processors.size())
    {
        return {};
    }
    const QRect kSlotRect = cpuSlotRect(
        kContentRect,
        kSlotSide,
        kProcessorIndex);
    if (!kSlotRect.contains(viewportPosition))
    {
        return {}; // Do not show misleading tooltips when the mouse is in the gap between two sectors.
    }

    const std::vector<const ks::process::CpuCoreUsageSeries*> kUsageSeriesList =
        processUsageSeriesList(*kSnapshot, processIds);
    const ks::process::EtwLogicalProcessorCoordinate& coordinate =
        kSnapshot->processors[kProcessorIndex];
    const CpuSlotPaintValue kValue = cpuSlotPaintValue(
        *kSnapshot,
        kUsageSeriesList,
        kProcessorIndex);
    if (!kValue.sampleReady)
    {
        return ks::i18n::contextText(
            QStringLiteral("process.table.cell.cpu_core_unavailable"),
            QStringLiteral("逻辑 CPU %1（组 %2 / 编号 %3）：本轮采样不可用"))
            .arg(coordinate.processorIndex)
            .arg(coordinate.group)
            .arg(coordinate.number);
    }

    return ks::i18n::contextText(
        QStringLiteral("process.table.cell.cpu_core_tooltip"),
        QStringLiteral("逻辑 CPU %1（组 %2 / 编号 %3）：%4%"))
        .arg(coordinate.processorIndex)
        .arg(coordinate.group)
        .arg(coordinate.number)
        .arg(kValue.percent, 0, 'f', 2);
}

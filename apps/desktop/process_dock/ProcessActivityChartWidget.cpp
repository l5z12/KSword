#include "ProcessActivityChartWidget.h"

using namespace ksword::ui::process_dock;

    // Constructor:
    // - ownerDock: Provides samples, selection, and metric toggles.
    // - parent: Qt parent control;
    // - No return value; initializes mouse tracking to support hover snapshots.
    ProcessActivityChartWidget::ProcessActivityChartWidget(ProcessDock* ownerDock, QWidget* parent )
        : QWidget(parent)
        , ownerDock_(ownerDock)
    {
        setMinimumHeight(120);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        setMouseTracking(true);
        setFocusPolicy(Qt::NoFocus);
        // The line chart no longer fills its own background; the parent Dock background must be visible through the chart's empty areas.
        setAutoFillBackground(false);
        setAttribute(Qt::WA_StyledBackground, false);
        setAttribute(Qt::WA_OpaquePaintEvent, false);
        seriesAnimation_ = new QVariantAnimation(this);
        seriesAnimation_->setDuration(260);
        seriesAnimation_->setEasingCurve(QEasingCurve::OutCubic);
        seriesAnimation_->setStartValue(0.0);
        seriesAnimation_->setEndValue(1.0);
        connect(seriesAnimation_, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
            animationProgress_ = value.toDouble();
            update();
        });
    }

    // setFocusedSampleIndex：
    // - sampleIndex: The sample index currently focused on the timeline; -1 indicates no focus.
    // - The function only updates the drawing cursor without modifying the host slider.
    void ProcessActivityChartWidget::setFocusedSampleIndex(const int sampleIndex)
    {
        if (focusedSampleIndex_ == sampleIndex)
        {
            return;
        }
        focusedSampleIndex_ = sampleIndex;
        update();
    }

    void ProcessActivityChartWidget::animateLatestSample(const bool historyWindowShifted)
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.size() < 2U)
        {
            historyWindowShifted_ = false;
            animationProgress_ = 1.0;
            update();
            return;
        }
        historyWindowShifted_ = historyWindowShifted;
        animationProgress_ = 0.0;
        seriesAnimation_->stop();
        seriesAnimation_->start();
    }

    // event：
    // - Input: Qt generic event; focus on handling ToolTip events.
    // - Processing: recalculate the nearest sample based on current mouse position just before the tooltip is displayed;
    // - Returns: true indicates the tooltip is handled by the control, false indicates it is passed to the default QWidget handling.
    bool ProcessActivityChartWidget::event(QEvent* eventPointer) {
        if (eventPointer != nullptr && eventPointer->type() == QEvent::ToolTip)
        {
            QHelpEvent* helpEvent = static_cast<QHelpEvent*>(eventPointer);
            showSnapshotToolTipAtPosition(helpEvent->pos(), helpEvent->globalPos());
            eventPointer->accept();
            return true;
        }
        return QWidget::event(eventPointer);
    }

    // paintEvent：
    // - Draw a multi-metric percentage line chart with time on the horizontal axis.
    // - No return value; all data is read from the host's bounded sample cache.
    void ProcessActivityChartWidget::paintEvent(QPaintEvent* eventPointer) {
        (void)eventPointer;

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        // Keep background transparent: only draw grid lines, borders, and curves; do not cover the Dock background image with Surface color blocks.

        const QRectF kPlotRect = chartRect();
        const QColor kBorderColor = themeColorFromText(
            ksword_theme::borderHex(),
            ksword_theme::borderColor());
        const QColor kTextColor = themeColorFromText(
            ksword_theme::textSecondaryHex(),
            ksword_theme::textSecondaryColor());

        painter.setPen(QPen(kBorderColor, 1.0));
        painter.setBrush(Qt::NoBrush);
        painter.drawRect(kPlotRect);

        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.empty())
        {
            painter.setPen(kTextColor);
            painter.drawText(
                kPlotRect,
                Qt::AlignCenter,
                processContextText("process.activity.empty", QStringLiteral("未开始刷新进程列表活动")));
            return;
        }

        std::vector<ProcessDock::ProcessActivityMetric> enabledMetrics = enabledMetricList();
        if (enabledMetrics.empty())
        {
            painter.setPen(kTextColor);
            painter.drawText(
                kPlotRect,
                Qt::AlignCenter,
                processContextText(
                    "process.activity.no_metric",
                    QStringLiteral("未选择任何指标，请勾选 CPU / 内存 / 磁盘 / 网络 / GPU")));
            return;
        }

        std::vector<std::string> selectionKeys = ownerDock_->currentProcessActivitySelectionKeys();
        const std::unordered_set<std::string> kSelectionKeySet(
            selectionKeys.cbegin(),
            selectionKeys.cend());
        const MetricScale kMetricScale = calculateMetricScale(enabledMetrics, kSelectionKeySet);

        drawGrid(painter, kPlotRect, kBorderColor, kTextColor);
        drawLines(painter, kPlotRect, enabledMetrics, kSelectionKeySet, kMetricScale);
        drawLegend(painter, enabledMetrics, kTextColor);
        drawFocusLine(painter, kPlotRect);
    }

    // mouseMoveEvent：
    // - Map mouse X coordinate to the nearest sample;
    // - Notify host to update timeline slider and snapshot labels.
    void ProcessActivityChartWidget::mouseMoveEvent(QMouseEvent* eventPointer) {
        if (eventPointer == nullptr || ownerDock_ == nullptr || ownerDock_->activitySamples_.empty())
        {
            QWidget::mouseMoveEvent(eventPointer);
            return;
        }

        const int kSampleIndex = sampleIndexAtX(activityMousePosition(eventPointer).x());
        if (kSampleIndex >= 0)
        {
            const bool kOldPinnedToLatest = ownerDock_->activityTimelinePinnedToLatest_;
            ownerDock_->previewProcessActivitySnapshotForIndex(kSampleIndex);
            ownerDock_->activityTimelinePinnedToLatest_ = kOldPinnedToLatest;
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
            const QPoint kGlobalPosition = eventPointer->globalPosition().toPoint();
#else
            const QPoint globalPosition = eventPointer->globalPos();
#endif
            showSnapshotToolTipAtPosition(activityMousePosition(eventPointer), kGlobalPosition);
        }
        eventPointer->accept();
    }

    // mousePressEvent：
    // - Fixes the timeline to the corresponding historical sample on chart click.
    // - If the rightmost sample is clicked, restore the 'stick to latest' mode.
    void ProcessActivityChartWidget::mousePressEvent(QMouseEvent* eventPointer) {
        if (eventPointer == nullptr ||
            eventPointer->button() != Qt::LeftButton ||
            ownerDock_ == nullptr ||
            ownerDock_->activitySamples_.empty())
        {
            QWidget::mousePressEvent(eventPointer);
            return;
        }

        const int kSampleIndex = sampleIndexAtX(activityMousePosition(eventPointer).x());
        if (kSampleIndex >= 0)
        {
            // The chart itself is now the sole timeline:
            // - Left-click submits the historical timestamp;
            // - Commit to synchronously update the process table below to the corresponding snapshot.
            ownerDock_->commitProcessActivityTimelineIndex(kSampleIndex);
            eventPointer->accept();
            return;
        }
        QWidget::mousePressEvent(eventPointer);
    }

    // leaveEvent：
    // - Preserve the current timeline position after the mouse leaves the chart.
    // - Hide only the tooltip to avoid clearing it while the user reads the snapshot below.
    void ProcessActivityChartWidget::leaveEvent(QEvent* eventPointer) {
        QToolTip::hideText();
        QWidget::leaveEvent(eventPointer);
    }

    // showSnapshotToolTipAtPosition：
    // - localPosition: Chart local coordinates, used to map to the nearest sample.
    // - globalPosition: screen coordinates used to position the tooltip;
    // - Return: None; hides the tooltip proactively when no samples exist to avoid displaying a static tooltip.
    void ProcessActivityChartWidget::showSnapshotToolTipAtPosition(const QPoint& localPosition, const QPoint& globalPosition)
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.empty())
        {
            QToolTip::hideText();
            return;
        }

        const int kSampleIndex = sampleIndexAtX(localPosition.x());
        if (kSampleIndex < 0)
        {
            QToolTip::hideText();
            return;
        }

        const QRect kToolTipRect(localPosition - QPoint(6, 6), QSize(12, 12));
        QToolTip::showText(
            globalPosition,
            ownerDock_->buildProcessActivitySnapshotText(kSampleIndex),
            this,
            kToolTipRect);
    }

    // chartRect：
    // - Calculate the actual drawing area of the chart;
    // - Reserve fixed space for left-side scale and bottom time labels.
    QRectF ProcessActivityChartWidget::chartRect() const
    {
        return QRectF(rect()).adjusted(42.0, 8.0, -10.0, -24.0);
    }

    // enabledMetricList：
    // - Read currently visible metrics from the host button state;
    // - Returns the order, which corresponds to the line chart drawing order.
    std::vector<ProcessDock::ProcessActivityMetric> ProcessActivityChartWidget::enabledMetricList() const
    {
        std::vector<ProcessDock::ProcessActivityMetric> metricList;
        if (ownerDock_ == nullptr)
        {
            return metricList;
        }
        const ProcessDock::ProcessActivityMetric kAllMetrics[] = {
            ProcessDock::ProcessActivityMetric::kCpu,
            ProcessDock::ProcessActivityMetric::kMemory,
            ProcessDock::ProcessActivityMetric::kDisk,
            ProcessDock::ProcessActivityMetric::kNetwork,
            ProcessDock::ProcessActivityMetric::kGpu
        };
        for (const ProcessDock::ProcessActivityMetric kMetric : kAllMetrics)
        {
            if (ownerDock_->isProcessActivityMetricEnabled(kMetric))
            {
                metricList.push_back(kMetric);
            }
        }
        return metricList;
    }

    // sampleRawMetricValue：
    // - Reads the raw single metric value at a specific sample point;
    // - Returns the overall aggregate if selectionKeySet is empty; otherwise returns the sum of selected processes via the hash set.
    double ProcessActivityChartWidget::sampleRawMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::unordered_set<std::string>& selectionKeySet) const
    {
        if (selectionKeySet.empty())
        {
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::kCpu:
                return sample.totalCpuPercent;
            case ProcessDock::ProcessActivityMetric::kMemory:
                return sample.totalMemoryMB;
            case ProcessDock::ProcessActivityMetric::kDisk:
                return sample.totalDiskMBps;
            case ProcessDock::ProcessActivityMetric::kNetwork:
                return sample.totalNetKBps;
            case ProcessDock::ProcessActivityMetric::kGpu:
                return sample.totalGpuPercent;
            default:
                return 0.0;
            }
        }

        double value = 0.0;
        for (const ProcessDock::ProcessActivityProcessPoint& processPoint : sample.processes)
        {
            if (selectionKeySet.find(processPoint.identityKey) == selectionKeySet.end())
            {
                continue;
            }
            switch (metric)
            {
            case ProcessDock::ProcessActivityMetric::kCpu:
                value += processPoint.cpuPercent;
                break;
            case ProcessDock::ProcessActivityMetric::kMemory:
                value += processPoint.workingSetMB;
                break;
            case ProcessDock::ProcessActivityMetric::kDisk:
                value += processPoint.diskMBps;
                break;
            case ProcessDock::ProcessActivityMetric::kNetwork:
                value += processPoint.netKBps;
                break;
            case ProcessDock::ProcessActivityMetric::kGpu:
                value += processPoint.gpuPercent;
                break;
            default:
                break;
            }
        }
        return value;
    }

    // calculateMetricScale：
    // - Rescan the historical maximum value on every draw.
    // - When new peaks appear in disk or network usage, recalculate percentages and redraw immediately in this round.
    ProcessActivityChartWidget::MetricScale ProcessActivityChartWidget::calculateMetricScale(
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const std::unordered_set<std::string>& selectionKeySet) const
    {
        MetricScale scale{};
        if (ownerDock_ == nullptr)
        {
            return scale;
        }

        scale.memoryDenominatorMB = std::max(1.0, ownerDock_->activityTotalPhysicalMemoryMB_);
        double maxMemoryMB = 0.0;
        double maxDiskMBps = 0.0;
        double maxNetworkKBps = 0.0;
        for (const ProcessDock::ProcessActivitySample& sample : ownerDock_->activitySamples_)
        {
            maxMemoryMB = std::max(maxMemoryMB, sampleRawMetricValue(sample, ProcessDock::ProcessActivityMetric::kMemory, selectionKeySet));
            maxDiskMBps = std::max(maxDiskMBps, sampleRawMetricValue(sample, ProcessDock::ProcessActivityMetric::kDisk, selectionKeySet));
            maxNetworkKBps = std::max(maxNetworkKBps, sampleRawMetricValue(sample, ProcessDock::ProcessActivityMetric::kNetwork, selectionKeySet));
        }
        if (scale.memoryDenominatorMB <= 1.0 && maxMemoryMB > 0.0)
        {
            scale.memoryDenominatorMB = maxMemoryMB;
        }
        scale.diskDenominatorMBps = std::max(1.0, maxDiskMBps);
        scale.networkDenominatorKBps = std::max(1.0, maxNetworkKBps);
        (void)metricList;
        return scale;
    }

    // samplePercentMetricValue：
    // - Convert raw metrics to percentages.
    // - Disk and network metrics are normalized against historical maximums; CPU and GPU are naturally percentages.
    double ProcessActivityChartWidget::samplePercentMetricValue(
        const ProcessDock::ProcessActivitySample& sample,
        const ProcessDock::ProcessActivityMetric metric,
        const std::unordered_set<std::string>& selectionKeySet,
        const MetricScale& scale) const
    {
        const double kRawValue = sampleRawMetricValue(sample, metric, selectionKeySet);
        switch (metric)
        {
        case ProcessDock::ProcessActivityMetric::kCpu:
        case ProcessDock::ProcessActivityMetric::kGpu:
            return clampPercentValue(kRawValue);
        case ProcessDock::ProcessActivityMetric::kMemory:
            return clampPercentValue((kRawValue / std::max(1.0, scale.memoryDenominatorMB)) * 100.0);
        case ProcessDock::ProcessActivityMetric::kDisk:
            return clampPercentValue((kRawValue / std::max(1.0, scale.diskDenominatorMBps)) * 100.0);
        case ProcessDock::ProcessActivityMetric::kNetwork:
            return clampPercentValue((kRawValue / std::max(1.0, scale.networkDenominatorKBps)) * 100.0);
        default:
            return 0.0;
        }
    }

    // sampleIndexAtX：
    // - Map mouse X coordinate to the nearest sample index;
    // - Out-of-bounds coordinates are clamped to the first or last sample.
    int ProcessActivityChartWidget::sampleIndexAtX(const int xValue) const
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.empty())
        {
            return -1;
        }
        const QRectF kPlotRect = chartRect();
        if (kPlotRect.width() <= 1.0)
        {
            return -1;
        }
        const double kRatio = std::clamp(
            (static_cast<double>(xValue) - kPlotRect.left()) / kPlotRect.width(),
            0.0,
            1.0);
        const std::size_t kSampleCount = ownerDock_->activitySamples_.size();
        const int kSampleIndex = static_cast<int>(std::llround(kRatio * static_cast<double>(kSampleCount - 1U)));
        return std::clamp(kSampleIndex, 0, static_cast<int>(kSampleCount) - 1);
    }

    // sampleIndexToX：
    // - Map sample index to the X coordinate of a polyline point.
    // - The focus line and time labels reuse this function for rendering.
    double ProcessActivityChartWidget::sampleIndexToX(const int sampleIndex, const QRectF& plotRect) const
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.size() <= 1U)
        {
            return plotRect.left() + plotRect.width() * 0.5;
        }
        const double kRatio = static_cast<double>(sampleIndex)
            / static_cast<double>(ownerDock_->activitySamples_.size() - 1U);
        return plotRect.left() + kRatio * plotRect.width();
    }

    // animatedSampleIndexToX：
    // Smoothly move old samples from the previous X-coordinate to the target X-coordinate when new points are added.
    // - When history is fully loaded, shift the entire window left; when not full, smoothly compress old points to leave space for the newest point on the far right.
    double ProcessActivityChartWidget::animatedSampleIndexToX(const int sampleIndex, const QRectF& plotRect) const
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.size() <= 1U)
        {
            return plotRect.left() + plotRect.width() * 0.5;
        }
        const int kSampleCount = static_cast<int>(ownerDock_->activitySamples_.size());
        const double kTargetRatio =
            static_cast<double>(sampleIndex) / static_cast<double>(kSampleCount - 1);
        double startRatio = kTargetRatio;
        if (animationProgress_ < 1.0)
        {
            if (historyWindowShifted_)
            {
                startRatio = sampleIndex + 1 < kSampleCount
                    ? static_cast<double>(sampleIndex + 1) / static_cast<double>(kSampleCount - 1)
                    : 1.0;
            }
            else if (kSampleCount > 2)
            {
                startRatio = sampleIndex + 1 < kSampleCount
                    ? static_cast<double>(sampleIndex) / static_cast<double>(kSampleCount - 2)
                    : 1.0;
            }
        }
        const double kRatio = startRatio + (kTargetRatio - startRatio) * animationProgress_;
        return plotRect.left() + kRatio * plotRect.width();
    }

    // drawGrid：
    // - Draws weak grid lines, maximum value labels, and start/end timestamps.
    // - No additional axis controls are created to reduce UI overhead.
    void ProcessActivityChartWidget::drawGrid(
        QPainter& painter,
        const QRectF& plotRect,
        const QColor& borderColor,
        const QColor& textColor) const
    {
        painter.setPen(QPen(borderColor, 0.5));
        for (int i = 1; i <= 3; ++i)
        {
            const double kYValue = plotRect.bottom() - plotRect.height() * static_cast<double>(i) / 4.0;
            painter.drawLine(QPointF(plotRect.left(), kYValue), QPointF(plotRect.right(), kYValue));
        }

        painter.setPen(textColor);
        painter.drawText(QRectF(2.0, plotRect.top() - 2.0, 38.0, 18.0), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("100%"));
        painter.drawText(QRectF(2.0, plotRect.center().y() - 9.0, 38.0, 18.0), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("50%"));
        painter.drawText(QRectF(2.0, plotRect.bottom() - 16.0, 38.0, 18.0), Qt::AlignRight | Qt::AlignVCenter,
            QStringLiteral("0%"));

        if (ownerDock_ != nullptr && !ownerDock_->activitySamples_.empty())
        {
            const ProcessDock::ProcessActivitySample& firstSample = ownerDock_->activitySamples_.front();
            const ProcessDock::ProcessActivitySample& lastSample = ownerDock_->activitySamples_.back();
            painter.drawText(QRectF(plotRect.left(), plotRect.bottom() + 3.0, 80.0, 18.0),
                Qt::AlignLeft | Qt::AlignVCenter,
                formatActivityElapsedText(firstSample.elapsedMs));
            painter.drawText(QRectF(plotRect.right() - 90.0, plotRect.bottom() + 3.0, 90.0, 18.0),
                Qt::AlignRight | Qt::AlignVCenter,
                formatActivityElapsedText(lastSample.elapsedMs));
        }
    }

    // drawLines：
    // - Draw multi-indicator line charts ordered by time;
    // - All metrics are normalized to 0~100%, allowing different units to share the same Y-axis.
    void ProcessActivityChartWidget::drawLines(
        QPainter& painter,
        const QRectF& plotRect,
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const std::unordered_set<std::string>& selectionKeySet,
        const MetricScale& metricScale) const
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.empty())
        {
            return;
        }

        const std::size_t kSampleCount = ownerDock_->activitySamples_.size();
        const std::size_t kMaximumRenderedPointCount = static_cast<std::size_t>(
            std::max(2.0, std::floor(plotRect.width())));
        const std::size_t kSampleStride = kSampleCount > kMaximumRenderedPointCount
            ? std::max<std::size_t>(
                1U,
                ((kSampleCount - 1U) + (kMaximumRenderedPointCount - 2U)) /
                    (kMaximumRenderedPointCount - 1U))
            : 1U;
        for (const ProcessDock::ProcessActivityMetric kMetric : metricList)
        {
            QPainterPath metricPath;
            bool hasPoint = false;
            std::vector<QPointF> pointList;
            pointList.reserve(std::min(kSampleCount, kMaximumRenderedPointCount + 1U));
            const auto kAppendSamplePoint = [&](const std::size_t sampleIndex)
            {
                const ProcessDock::ProcessActivitySample& sample = ownerDock_->activitySamples_[sampleIndex];
                double percentValue = samplePercentMetricValue(sample, kMetric, selectionKeySet, metricScale);
                if (sampleIndex + 1U == kSampleCount && sampleIndex > 0U && animationProgress_ < 1.0)
                {
                    const ProcessDock::ProcessActivitySample& previousSample = ownerDock_->activitySamples_[sampleIndex - 1U];
                    const double kPreviousPercentValue = samplePercentMetricValue(previousSample, kMetric, selectionKeySet, metricScale);
                    percentValue = kPreviousPercentValue + (percentValue - kPreviousPercentValue) * animationProgress_;
                }
                const double kXValue = animatedSampleIndexToX(static_cast<int>(sampleIndex), plotRect);
                const double kYValue = plotRect.bottom() - (percentValue / 100.0) * plotRect.height();
                const QPointF kPoint(kXValue, kYValue);
                pointList.push_back(kPoint);
                if (!hasPoint)
                {
                    metricPath.moveTo(kPoint);
                    hasPoint = true;
                }
                else
                {
                    metricPath.lineTo(kPoint);
                }
            };
            std::size_t lastRenderedSampleIndex = 0U;
            for (std::size_t sampleIndex = 0; sampleIndex < kSampleCount; sampleIndex += kSampleStride)
            {
                kAppendSamplePoint(sampleIndex);
                lastRenderedSampleIndex = sampleIndex;
            }
            if (lastRenderedSampleIndex != kSampleCount - 1U)
            {
                kAppendSamplePoint(kSampleCount - 1U);
            }

            QColor lineColor = processActivityMetricColor(kMetric);
            lineColor.setAlpha(230);
            // The polyline allows only stroking; it must not inherit the brush left by the previous metric sample point.
            // Qt's drawPath performs both stroke and fill; if the brush is not cleared, an open polyline path will be implicitly closed and filled.
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(lineColor, 2.0));
            painter.drawPath(metricPath);

            QColor pointColor = lineColor;
            pointColor.setAlpha(245);
            painter.setBrush(pointColor);
            painter.setPen(Qt::NoPen);
            const int kPointStride = static_cast<int>(std::max<std::size_t>(1U, pointList.size() / 80U));
            for (std::size_t pointIndex = 0; pointIndex < pointList.size(); pointIndex += static_cast<std::size_t>(kPointStride))
            {
                painter.drawEllipse(pointList[pointIndex], 2.2, 2.2);
            }
            // Sampling points set a solid brush; before looping to the next line, the brush must be restored to empty.
            painter.setBrush(Qt::NoBrush);
        }
    }

    // drawLegend：
    // - Draw the legend for currently enabled metrics along the top of the chart;
    // - Users can verify the line colors filtered by the button based on this.
    void ProcessActivityChartWidget::drawLegend(
        QPainter& painter,
        const std::vector<ProcessDock::ProcessActivityMetric>& metricList,
        const QColor& textColor) const
    {
        int xOffset = 48;
        const int kYOffset = 4;
        painter.setPen(textColor);
        for (const ProcessDock::ProcessActivityMetric kMetric : metricList)
        {
            QColor color = processActivityMetricColor(kMetric);
            color.setAlpha(220);
            painter.fillRect(QRect(xOffset, kYOffset + 4, 9, 9), color);
            painter.drawText(QRect(xOffset + 13, kYOffset, 54, 18),
                Qt::AlignLeft | Qt::AlignVCenter,
                processActivityMetricText(kMetric));
            xOffset += 62;
        }
    }

    // drawFocusLine：
    // - Draw the vertical line indicating the current sample position on the timeline.
    // - This line is driven by both the slider and chart hover.
    void ProcessActivityChartWidget::drawFocusLine(QPainter& painter, const QRectF& plotRect) const
    {
        if (ownerDock_ == nullptr || ownerDock_->activitySamples_.empty())
        {
            return;
        }
        const int kSafeIndex = std::clamp(
            focusedSampleIndex_,
            0,
            static_cast<int>(ownerDock_->activitySamples_.size()) - 1);
        const double kXValue = sampleIndexToX(kSafeIndex, plotRect);
        QColor lineColor = ksword_theme::primaryBlueColor;
        lineColor.setAlpha(230);
        painter.setPen(QPen(lineColor, 1.4));
        painter.drawLine(QPointF(kXValue, plotRect.top()), QPointF(kXValue, plotRect.bottom()));
    }

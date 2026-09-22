#include "MemoryCompositionHistoryWidget.h"
#include "../internationalization/LanguageManager.h"

#include "../Theme.h"

#include <QFont>
#include <QPainter>
#include <QPainterPath>
#include <QEasingCurve>
#include <QVariantAnimation>
#include <QPaintEvent>
#include <QPen>
#include <QSizePolicy>

#include <algorithm>
#include <array>
#include <cmath>

namespace
{
    // CompositionColor purpose: Stores legend names and their corresponding fill colors.
    struct CompositionColor
    {
        const char* labelText = ""; // labelText: Legend display text.
        QColor color;               // color: fill color for this memory composition layer.
    };

    // buildCompositionColorList: Returns memory composition colors in draw order.
    std::array<CompositionColor, 4> buildCompositionColorList()
    {
        return {
            CompositionColor{ "活跃", ksword_theme::withAlpha(ksword_theme::accentColor(ksword_theme::AccentRole::kPurple), 145) },
            CompositionColor{ "缓存", ksword_theme::withAlpha(ksword_theme::accentColor(ksword_theme::AccentRole::kCyan, 24, -2), 120) },
            CompositionColor{ "分页池", ksword_theme::withAlpha(ksword_theme::accentColor(ksword_theme::AccentRole::kYellow), 120) },
            CompositionColor{ "非分页池", ksword_theme::withAlpha(ksword_theme::accentColor(ksword_theme::AccentRole::kOrange, 36, 10), 130) },
        };
    }
}

MemoryCompositionHistoryWidget::MemoryCompositionHistoryWidget(QWidget* parent)
    : QWidget(parent)
{
    // Utilization page requirements dictate that charts compress automatically when dimensions are insufficient; fixed minimum heights must not be used to force outer scrollbars.
    setMinimumSize(0, 0);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMouseTracking(true);
    setAttribute(Qt::WA_StyledBackground, false);
    setAutoFillBackground(false);
    sampleAnimation_ = new QVariantAnimation(this);
    sampleAnimation_->setDuration(260);
    sampleAnimation_->setEasingCurve(QEasingCurve::OutCubic);
    sampleAnimation_->setStartValue(0.0);
    sampleAnimation_->setEndValue(1.0);
    connect(sampleAnimation_, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        animationProgress_ = value.toDouble();
        update();
    });
}

void MemoryCompositionHistoryWidget::setHistoryLength(const int historyLength)
{
    historyLength_ = std::max(2, historyLength);
    while (static_cast<int>(sampleList_.size()) > historyLength_)
    {
        sampleList_.erase(sampleList_.begin());
    }
    update();
}

void MemoryCompositionHistoryWidget::appendSample(const CompositionSample& sample)
{
    CompositionSample safeSample;
    safeSample.usedPercent = boundedPercent(sample.usedPercent);
    safeSample.cachedPercent = boundedPercent(sample.cachedPercent);
    safeSample.pagedPoolPercent = boundedPercent(sample.pagedPoolPercent);
    safeSample.nonPagedPoolPercent = boundedPercent(sample.nonPagedPoolPercent);

    const double kPoolPercentSum = safeSample.pagedPoolPercent + safeSample.nonPagedPoolPercent;
    safeSample.cachedPercent = std::min(safeSample.cachedPercent, safeSample.usedPercent);
    if (safeSample.cachedPercent + kPoolPercentSum > safeSample.usedPercent)
    {
        const double kScaleValue = safeSample.usedPercent / std::max(1.0, safeSample.cachedPercent + kPoolPercentSum);
        safeSample.cachedPercent *= kScaleValue;
        safeSample.pagedPoolPercent *= kScaleValue;
        safeSample.nonPagedPoolPercent *= kScaleValue;
    }
    safeSample.activePercent = std::max(
        0.0,
        safeSample.usedPercent
            - safeSample.cachedPercent
            - safeSample.pagedPoolPercent
            - safeSample.nonPagedPoolPercent);

    const CompositionSample kPreviousSample = sampleList_.empty()
        ? safeSample
        : sampleList_.back();
    previousSampleCount_ = static_cast<int>(sampleList_.size());
    historyWindowShifted_ = previousSampleCount_ >= historyLength_;
    sampleList_.push_back(safeSample);
    while (static_cast<int>(sampleList_.size()) > historyLength_)
    {
        sampleList_.erase(sampleList_.begin());
    }
    previousSample_ = kPreviousSample;
    hasPreviousSample_ = true;
    animationProgress_ = 0.0;
    sampleAnimation_->stop();
    sampleAnimation_->start();
}

void MemoryCompositionHistoryWidget::clearSamples()
{
    sampleAnimation_->stop();
    animationProgress_ = 1.0;
    hasPreviousSample_ = false;
    previousSampleCount_ = 0;
    historyWindowShifted_ = false;
    sampleList_.clear();
    update();
}

void MemoryCompositionHistoryWidget::paintEvent(QPaintEvent* paintEventPointer)
{
    Q_UNUSED(paintEventPointer);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QColor kTextColor = ksword_theme::textPrimaryColor();
    const QColor kBorderColor = ksword_theme::withAlpha(ksword_theme::borderColor(), 138);
    const QColor kGridColor = ksword_theme::withAlpha(
        ksword_theme::accentColor(ksword_theme::AccentRole::kPurple),
        42);

    painter.fillRect(rect(), Qt::transparent);
    // Legend space scales with height; at low heights, discard the bottom legend to prioritize the line and fill.
    const bool kCompactHeight = height() < 70;
    const QRectF kPlotRect = kCompactHeight
        ? rect().adjusted(4.0, 4.0, -4.0, -4.0)
        : rect().adjusted(8.0, 10.0, -8.0, -24.0);
    if (kPlotRect.width() <= 4.0 || kPlotRect.height() <= 4.0)
    {
        return;
    }

    painter.setPen(QPen(kBorderColor, 1.0));
    painter.drawRect(kPlotRect);
    painter.setPen(QPen(kGridColor, 1.0));
    for (int gridIndex = 1; gridIndex < 4; ++gridIndex)
    {
        const double kYValue = kPlotRect.top() + kPlotRect.height() * static_cast<double>(gridIndex) / 4.0;
        painter.drawLine(QPointF(kPlotRect.left(), kYValue), QPointF(kPlotRect.right(), kYValue));
    }

    drawStackedComposition(painter, kPlotRect);
    drawUsageLine(painter, kPlotRect);

    if (!kCompactHeight)
    {
        painter.setPen(kTextColor);
        painter.setFont(QFont(painter.font().family(), 9));
        painter.drawText(
            kPlotRect.adjusted(6.0, 4.0, -6.0, -4.0),
            Qt::AlignTop | Qt::AlignLeft,
            ks::i18n::contextText(
                QStringLiteral("hardware.memory.history.title"),
                QStringLiteral("内存占用历史 / 构成填充")));
        drawLegend(painter, kPlotRect);
    }
}

double MemoryCompositionHistoryWidget::boundedPercent(const double percentValue)
{
    if (!std::isfinite(percentValue))
    {
        return 0.0;
    }
    return std::clamp(percentValue, 0.0, 100.0);
}

MemoryCompositionHistoryWidget::CompositionSample MemoryCompositionHistoryWidget::animatedSampleAt(
    const std::size_t sampleIndex) const
{
    const CompositionSample kTargetSample = sampleList_[sampleIndex];
    if (!hasPreviousSample_ || sampleIndex + 1U != sampleList_.size() || animationProgress_ >= 1.0)
    {
        return kTargetSample;
    }
    const auto kInterpolate = [this](const double startValue, const double targetValue) {
        return startValue + (targetValue - startValue) * animationProgress_;
    };
    CompositionSample result = kTargetSample;
    result.usedPercent = kInterpolate(previousSample_.usedPercent, kTargetSample.usedPercent);
    result.activePercent = kInterpolate(previousSample_.activePercent, kTargetSample.activePercent);
    result.cachedPercent = kInterpolate(previousSample_.cachedPercent, kTargetSample.cachedPercent);
    result.pagedPoolPercent = kInterpolate(previousSample_.pagedPoolPercent, kTargetSample.pagedPoolPercent);
    result.nonPagedPoolPercent = kInterpolate(previousSample_.nonPagedPoolPercent, kTargetSample.nonPagedPoolPercent);
    return result;
}

double MemoryCompositionHistoryWidget::sampleX(const int sampleIndex, const QRectF& plotRect) const
{
    if (sampleList_.size() <= 1)
    {
        return plotRect.left();
    }
    const int kSampleCount = static_cast<int>(sampleList_.size());
    const double kTargetRatio =
        static_cast<double>(sampleIndex) / static_cast<double>(kSampleCount - 1);
    double startRatio = kTargetRatio;
    if (animationProgress_ < 1.0)
    {
        if (historyWindowShifted_ && previousSampleCount_ == kSampleCount)
        {
            startRatio = sampleIndex + 1 < kSampleCount
                ? static_cast<double>(sampleIndex + 1) / static_cast<double>(kSampleCount - 1)
                : 1.0;
        }
        else if (previousSampleCount_ + 1 == kSampleCount && previousSampleCount_ > 1)
        {
            startRatio = sampleIndex < previousSampleCount_
                ? static_cast<double>(sampleIndex) / static_cast<double>(previousSampleCount_ - 1)
                : 1.0;
        }
    }
    const double kAnimatedRatio =
        startRatio + (kTargetRatio - startRatio) * animationProgress_;
    return plotRect.left() + plotRect.width() * kAnimatedRatio;
}

double MemoryCompositionHistoryWidget::percentY(const double percentValue, const QRectF& plotRect)
{
    return plotRect.bottom() - plotRect.height() * boundedPercent(percentValue) / 100.0;
}

void MemoryCompositionHistoryWidget::drawStackedComposition(QPainter& painter, const QRectF& plotRect) const
{
    if (sampleList_.empty())
    {
        return;
    }

    const std::array<CompositionColor, 4> kColorList = buildCompositionColorList();
    for (int componentIndex = 0; componentIndex < static_cast<int>(kColorList.size()); ++componentIndex)
    {
        QPainterPath componentPath;
        componentPath.moveTo(sampleX(0, plotRect), plotRect.bottom());

        for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList_.size()); ++sampleIndex)
        {
            const CompositionSample kSample = animatedSampleAt(static_cast<std::size_t>(sampleIndex));
            const double kComponentValues[4] = {
                kSample.activePercent,
                kSample.cachedPercent,
                kSample.pagedPoolPercent,
                kSample.nonPagedPoolPercent,
            };

            double stackedPercent = 0.0;
            for (int stackedIndex = 0; stackedIndex <= componentIndex; ++stackedIndex)
            {
                stackedPercent += kComponentValues[stackedIndex];
            }
            componentPath.lineTo(sampleX(sampleIndex, plotRect), percentY(stackedPercent, plotRect));
        }

        for (int sampleIndex = static_cast<int>(sampleList_.size()) - 1; sampleIndex >= 0; --sampleIndex)
        {
            const CompositionSample kSample = animatedSampleAt(static_cast<std::size_t>(sampleIndex));
            const double kComponentValues[4] = {
                kSample.activePercent,
                kSample.cachedPercent,
                kSample.pagedPoolPercent,
                kSample.nonPagedPoolPercent,
            };

            double lowerStackedPercent = 0.0;
            for (int stackedIndex = 0; stackedIndex < componentIndex; ++stackedIndex)
            {
                lowerStackedPercent += kComponentValues[stackedIndex];
            }
            componentPath.lineTo(sampleX(sampleIndex, plotRect), percentY(lowerStackedPercent, plotRect));
        }
        componentPath.closeSubpath();

        painter.fillPath(componentPath, kColorList[static_cast<std::size_t>(componentIndex)].color);
    }
}

void MemoryCompositionHistoryWidget::drawUsageLine(QPainter& painter, const QRectF& plotRect) const
{
    if (sampleList_.empty())
    {
        return;
    }

    QPainterPath linePath;
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(sampleList_.size()); ++sampleIndex)
    {
        const QPointF kPointValue(
            sampleX(sampleIndex, plotRect),
            percentY(animatedSampleAt(static_cast<std::size_t>(sampleIndex)).usedPercent, plotRect));
        if (sampleIndex == 0)
        {
            linePath.moveTo(kPointValue);
        }
        else
        {
            linePath.lineTo(kPointValue);
        }
    }

    painter.setPen(QPen(ksword_theme::accentColor(ksword_theme::AccentRole::kPurple), 2.0));
    painter.drawPath(linePath);
}

void MemoryCompositionHistoryWidget::drawLegend(QPainter& painter, const QRectF& plotRect) const
{
    const std::array<CompositionColor, 4> kColorList = buildCompositionColorList();
    const QColor kTextColor = ksword_theme::textPrimaryColor();

    painter.setFont(QFont(painter.font().family(), 8));
    painter.setPen(kTextColor);

    double xValue = plotRect.left();
    const double kYValue = plotRect.bottom() + 9.0;
    for (const CompositionColor& colorEntry : kColorList)
    {
        const QRectF kColorRect(xValue, kYValue, 10.0, 7.0);
        painter.fillRect(kColorRect, colorEntry.color);
        const QString kSourceLabel = QString::fromUtf8(colorEntry.labelText);
        const QString kLabelKey = kSourceLabel == QStringLiteral("活跃")
            ? QStringLiteral("hardware.memory.legend.active")
            : kSourceLabel == QStringLiteral("缓存")
                ? QStringLiteral("hardware.memory.legend.cached")
                : kSourceLabel == QStringLiteral("分页池")
                    ? QStringLiteral("hardware.memory.legend.paged_pool")
                    : QStringLiteral("hardware.memory.legend.non_paged_pool");
        painter.drawText(
            QRectF(xValue + 13.0, kYValue - 4.0, 58.0, 16.0),
            Qt::AlignLeft | Qt::AlignVCenter,
            ks::i18n::contextText(kLabelKey, kSourceLabel));
        xValue += 68.0;
    }
}

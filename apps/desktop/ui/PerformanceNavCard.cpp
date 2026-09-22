#include "PerformanceNavCard.h"
#include "../internationalization/LanguageManager.h"

// ============================================================
// PerformanceNavCard.cpp
// Purpose:
// 1) Draw the left-side performance navigation card in the Task Manager style.
// 2) Unified handling of background and text readability under light and dark themes;
// 3) Maintains a history of thumbnail polylines and redraws after each sample.
// ============================================================

#include "../Theme.h"

#include <QEasingCurve>
#include <QFontMetrics>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>
#include <QSizePolicy>
#include <QVariantAnimation>

#include <algorithm>

PerformanceNavCard::PerformanceNavCard(QWidget* parent)
    : QWidget(parent)
    , accentColor_(ksword_theme::primaryBlueColor)
    , primarySeriesColor_(ksword_theme::primaryBlueColor)
{
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(false);
    // The left device list dynamically compresses the card based on available Dock height, so a fixed minimum height cannot be set here.
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    setMinimumSize(0, 0);

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

void PerformanceNavCard::setTitleText(const QString& titleText)
{
    titleText_ = titleText;
    update();
}

void PerformanceNavCard::setSubtitleText(const QString& subtitleText)
{
    subtitleText_ = subtitleText;
    update();
}

void PerformanceNavCard::setAccentColor(const QColor& accentColor)
{
    accentColor_ = accentColor;
    if (primarySeriesFollowsAccentColor_)
    {
        primarySeriesColor_ = accentColor;
    }
    if (!secondarySeriesVisible_)
    {
        secondarySeriesColor_ = QColor();
    }
    update();
}

void PerformanceNavCard::setSeriesColors(
    const QColor& primarySeriesColor,
    const QColor& secondarySeriesColor)
{
    primarySeriesFollowsAccentColor_ = !primarySeriesColor.isValid();
    primarySeriesColor_ = primarySeriesColor.isValid() ? primarySeriesColor : accentColor_;
    secondarySeriesColor_ = secondarySeriesColor;
    secondarySeriesVisible_ = secondarySeriesColor.isValid();
    if (!secondarySeriesVisible_)
    {
        secondarySamples_.clear();
    }
    update();
}

void PerformanceNavCard::setSelectedState(const bool selected)
{
    selected_ = selected;
    update();
}

void PerformanceNavCard::appendSample(const double usagePercent)
{
    // clampedPercent usage: Clamps the externally passed sample to the 0~100 range to prevent out-of-bounds drawing.
    const double kClampedPercent = std::clamp(usagePercent, 0.0, 100.0);
    const double kPreviousPrimarySample = primarySamples_.isEmpty()
        ? kClampedPercent
        : primarySamples_.back();
    previousSampleCount_ = static_cast<int>(primarySamples_.size());
    historyWindowShifted_ = previousSampleCount_ >= maxSampleCount_;
    primarySamples_.push_back(kClampedPercent);
    while (primarySamples_.size() > maxSampleCount_)
    {
        primarySamples_.pop_front();
    }
    startLatestSampleAnimation(kPreviousPrimarySample, previousSecondarySample_);
}

void PerformanceNavCard::appendDualSample(
    const double primaryUsagePercent,
    const double secondaryUsagePercent)
{
    // primaryClampedPercent usage: Primary sample value, clamped to 0~100.
    const double kPrimaryClampedPercent = std::clamp(primaryUsagePercent, 0.0, 100.0);
    // secondaryClampedPercent usage: Secondary sample value, clamped to 0~100.
    const double kSecondaryClampedPercent = std::clamp(secondaryUsagePercent, 0.0, 100.0);
    const double kPreviousPrimarySample = primarySamples_.isEmpty()
        ? kPrimaryClampedPercent
        : primarySamples_.back();
    const double kPreviousSecondarySample = secondarySamples_.isEmpty()
        ? kSecondaryClampedPercent
        : secondarySamples_.back();
    previousSampleCount_ = static_cast<int>(primarySamples_.size());
    historyWindowShifted_ = previousSampleCount_ >= maxSampleCount_;
    primarySamples_.push_back(kPrimaryClampedPercent);
    secondarySamples_.push_back(kSecondaryClampedPercent);
    while (primarySamples_.size() > maxSampleCount_)
    {
        primarySamples_.pop_front();
    }
    while (secondarySamples_.size() > maxSampleCount_)
    {
        secondarySamples_.pop_front();
    }
    startLatestSampleAnimation(kPreviousPrimarySample, kPreviousSecondarySample);
}

void PerformanceNavCard::setSampleSeries(
    const QVector<double>& primarySampleList,
    const QVector<double>& secondarySampleList)
{
    const double kPreviousPrimarySample = primarySamples_.isEmpty()
        ? (primarySampleList.isEmpty() ? 0.0 : primarySampleList.back())
        : primarySamples_.back();
    const double kPreviousSecondarySample = secondarySamples_.isEmpty()
        ? (secondarySampleList.isEmpty() ? 0.0 : secondarySampleList.back())
        : secondarySamples_.back();
    previousSampleCount_ = static_cast<int>(primarySamples_.size());
    const int kNextSampleCount = std::min(static_cast<int>(primarySampleList.size()), maxSampleCount_);
    historyWindowShifted_ =
        previousSampleCount_ >= maxSampleCount_ && kNextSampleCount == previousSampleCount_;
    primarySamples_ = primarySampleList;
    while (primarySamples_.size() > maxSampleCount_)
    {
        primarySamples_.pop_front();
    }

    if (secondarySeriesVisible_)
    {
        secondarySamples_ = secondarySampleList;
        while (secondarySamples_.size() > maxSampleCount_)
        {
            secondarySamples_.pop_front();
        }
    }
    else
    {
        secondarySamples_.clear();
    }
    startLatestSampleAnimation(kPreviousPrimarySample, kPreviousSecondarySample);
}

void PerformanceNavCard::clearSamples()
{
    sampleAnimation_->stop();
    animationProgress_ = 1.0;
    primarySamples_.clear();
    previousSampleCount_ = 0;
    historyWindowShifted_ = false;
    secondarySamples_.clear();
    update();
}

void PerformanceNavCard::startLatestSampleAnimation(
    const double previousPrimarySample,
    const double previousSecondarySample)
{
    previousPrimarySample_ = previousPrimarySample;
    previousSecondarySample_ = previousSecondarySample;
    animationProgress_ = 0.0;
    sampleAnimation_->stop();
    sampleAnimation_->start();
}

double PerformanceNavCard::animatedXRatio(const int sampleIndex, const int sampleCount) const
{
    if (sampleCount <= 1)
    {
        return 0.0;
    }

    const double kTargetRatio =
        static_cast<double>(sampleIndex) / static_cast<double>(sampleCount - 1);
    double startRatio = kTargetRatio;
    if (historyWindowShifted_ && previousSampleCount_ == sampleCount)
    {
        startRatio = sampleIndex + 1 < sampleCount
            ? static_cast<double>(sampleIndex + 1) / static_cast<double>(sampleCount - 1)
            : 1.0;
    }
    else if (previousSampleCount_ + 1 == sampleCount && previousSampleCount_ > 1)
    {
        startRatio = sampleIndex < previousSampleCount_
            ? static_cast<double>(sampleIndex) / static_cast<double>(previousSampleCount_ - 1)
            : 1.0;
    }

    return startRatio + (kTargetRatio - startRatio) * animationProgress_;
}

QSize PerformanceNavCard::sizeHint() const
{
    // The default height is reduced to 52px; the actual height is further dynamically lowered by HardwareDock based on the list's visible height.
    return QSize(208, 52);
}


int PerformanceNavCard::sampleCapacity() const
{
    return maxSampleCount_;
}

void PerformanceNavCard::paintEvent(QPaintEvent* paintEventPointer)
{
    Q_UNUSED(paintEventPointer);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    // Card area: change to a transparent background with only the border highlighted to prevent the left-side card on the counter page from obscuring the background.
    const QRect kCardRect = rect().adjusted(1, 1, -1, -1);
    // cardBorderColor purpose: Current card border color; brighter when selected, retaining only a faint outline when not selected.
    const QColor kCardBorderColor = ksword_theme::withAlpha(
        accentColor_,
        selected_ ? 210 : 86);
    QPen cardBorderPen(kCardBorderColor);
    cardBorderPen.setWidthF(selected_ ? 1.2 : 0.8);
    painter.setPen(cardBorderPen);
    painter.setBrush(Qt::NoBrush);
    painter.drawRoundedRect(kCardRect, 4.0, 4.0);

    // Thumbnail area: retain borders and curves, keep internal background transparent.
    // showSparkChart: Determines whether to display the sparkline chart based solely on the card's available width.
    // Do not depend on the top-level window width to avoid interference between hardware page QSplitter dragging and the welcome page host window conditions.
    const bool kShowSparkChart = kCardRect.width() >= 140;
    // compactMode purpose: Shrinks text font size in narrow width/low height scenarios to prevent the left list from triggering scrollbars.
    const bool kCompactMode = kCardRect.width() < 176 || kCardRect.height() < 48;
    const int kSparkInset = kCompactMode ? 4 : 5;
    // When width exceeds 800px, the line chart and text each occupy half of the card content width, no longer using a fixed narrow chart ratio.
    const int kSparkWidth = kShowSparkChart
        ? std::max(1, kCardRect.width() / 2 - kSparkInset)
        : 0;
    const QRect kSparkRect(
        kCardRect.left() + kSparkInset,
        kCardRect.top() + kSparkInset,
        kSparkWidth,
        std::max(1, kCardRect.height() - kSparkInset * 2));
    // sparkBorderColor usage: thumbnail border color; use solid color when selected, reduce transparency when not selected.
    const QColor kSparkBorderColor = ksword_theme::withAlpha(
        accentColor_,
        selected_ ? 220 : 150);
    if (kShowSparkChart)
    {
        painter.setBrush(Qt::NoBrush);
        QPen sparkBorderPen(kSparkBorderColor);
        sparkBorderPen.setWidthF(1.2);
        painter.setPen(sparkBorderPen);
        painter.drawRect(kSparkRect);

        // Grid lines: light auxiliary lines to improve trend readability without overshadowing the main content.
        QPen gridPen(accentColor_);
        gridPen.setWidthF(0.8);
        gridPen.setColor(ksword_theme::withAlpha(accentColor_, 45));
        painter.setPen(gridPen);
        for (int rowIndex = 1; rowIndex < 4; ++rowIndex)
        {
            const int kYValue = kSparkRect.top() + (kSparkRect.height() * rowIndex / 4);
            painter.drawLine(kSparkRect.left(), kYValue, kSparkRect.right(), kYValue);
        }
    }

    // drawSeriesPath:
    // - Map sample list to thumbnail curve.
    // - First draws the transparent fill enclosed by the line chart and the X-axis, then draws the trend line itself.
    const auto kDrawSeriesPath =
        [this, &painter, &kSparkRect](
            const QVector<double>& sampleList,
            const QColor& seriesColor,
            const double previousLastValue)
        {
            if (sampleList.isEmpty())
            {
                return;
            }
            const auto kAnimatedValueAt = [this, &sampleList, previousLastValue](const int indexValue) {
                const double kTargetValue = sampleList.at(indexValue);
                if (indexValue != sampleList.size() - 1 || animationProgress_ >= 1.0)
                {
                    return kTargetValue;
                }
                return previousLastValue
                    + (kTargetValue - previousLastValue) * animationProgress_;
            };


            QPen trendPen(seriesColor);
            trendPen.setWidthF(1.6);

            if (sampleList.size() == 1)
            {
                const double kYRatio = kAnimatedValueAt(0) / 100.0;
                const double kYValue = kSparkRect.bottom() - kYRatio * static_cast<double>(kSparkRect.height());
                const QColor kFillColor = ksword_theme::withAlpha(seriesColor, 34);
                painter.fillRect(
                    QRectF(
                        QPointF(kSparkRect.left(), kYValue),
                        QPointF(kSparkRect.right(), kSparkRect.bottom())),
                    kFillColor);
                painter.setPen(trendPen);
                painter.setBrush(Qt::NoBrush);
                painter.drawLine(
                    QPointF(kSparkRect.left(), kYValue),
                    QPointF(kSparkRect.right(), kYValue));
                return;
            }

            QPainterPath path;
            QPainterPath fillPath;
            const int kPointCount = sampleList.size();
            for (int indexValue = 0; indexValue < kPointCount; ++indexValue)
            {
                const double kXRatio = animatedXRatio(indexValue, kPointCount);
                const double kYRatio = kAnimatedValueAt(indexValue) / 100.0;
                const double kXValue = kSparkRect.left() + kXRatio * static_cast<double>(kSparkRect.width());
                const double kYValue = kSparkRect.bottom() - kYRatio * static_cast<double>(kSparkRect.height());
                if (indexValue == 0)
                {
                    path.moveTo(kXValue, kYValue);
                    fillPath.moveTo(kXValue, kSparkRect.bottom());
                    fillPath.lineTo(kXValue, kYValue);
                }
                else
                {
                    path.lineTo(kXValue, kYValue);
                    fillPath.lineTo(kXValue, kYValue);
                }
            }

            fillPath.lineTo(kSparkRect.right(), kSparkRect.bottom());
            fillPath.closeSubpath();
            painter.fillPath(
                fillPath,
                ksword_theme::withAlpha(seriesColor, 34));
            painter.setPen(trendPen);
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(path);
        };

    // Draw the secondary series before the primary series in the dual-line card to ensure the primary line is not obscured.
    if (kShowSparkChart && secondarySeriesVisible_)
    {
        kDrawSeriesPath(secondarySamples_, secondarySeriesColor_, previousSecondarySample_);
    }
    if (kShowSparkChart)
    {
        kDrawSeriesPath(primarySamples_, primarySeriesColor_, previousPrimarySample_);
    }

    // Text area: main title bold, subtitle in secondary color.
    const int kTextLeft = kShowSparkChart
        ? kSparkRect.right() + (kCompactMode ? 5 : 7)
        : kCardRect.left() + (kCompactMode ? 5 : 8);
    const int kTextWidth = std::max(0, kCardRect.right() - kTextLeft - 4);
    const int kTitleHeight = std::max(1, kCardRect.height() / 2);
    const QRect kTitleRect(kTextLeft, kCardRect.top() + 2, kTextWidth, kTitleHeight);
    const QRect kSubtitleRect(
        kTextLeft,
        kTitleRect.bottom() - 1,
        kTextWidth,
        std::max(1, kCardRect.bottom() - kTitleRect.bottom()));

    QFont titleFont = painter.font();
    // Adjust the device name main title to a smaller size as needed, and further compress it in compact mode.
    titleFont.setPointSizeF(kCompactMode ? 11.0 : 12.5);
    titleFont.setBold(true);
    painter.setFont(titleFont);
    painter.setPen(ksword_theme::textPrimaryColor());
    const QString kElidedTitleText = QFontMetrics(titleFont).elidedText(
        ks::i18n::displayText(titleText_),
        Qt::ElideRight,
        kTitleRect.width());
    painter.drawText(kTitleRect, Qt::AlignLeft | Qt::AlignVCenter, kElidedTitleText);

    QFont subtitleFont = painter.font();
    subtitleFont.setPointSizeF(kCompactMode ? 8.5 : 9.5);
    subtitleFont.setBold(false);
    painter.setFont(subtitleFont);
    painter.setPen(ksword_theme::textSecondaryColor());
    const QString kElidedSubtitleText = QFontMetrics(subtitleFont).elidedText(
        ks::i18n::displayText(subtitleText_),
        Qt::ElideRight,
        kSubtitleRect.width());
    painter.drawText(kSubtitleRect, Qt::AlignLeft | Qt::AlignVCenter, kElidedSubtitleText);
}

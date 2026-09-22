#include "PerformanceNavCard.h"

#include <QEasingCurve>
#include <QVariantAnimation>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>

namespace
{
    QColor textPrimaryColor()
    {
        return QColor(242, 246, 252);
    }

    QColor textSecondaryColor()
    {
        return QColor(190, 206, 226);
    }
}

PerformanceNavCard::PerformanceNavCard(QWidget* parent)
    : QWidget(parent)
    , accentColor_(67, 160, 255)
{
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(false);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMinimumHeight(78);
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
    update();
}

void PerformanceNavCard::setSelectedState(const bool selected)
{
    selected_ = selected;
    update();
}

void PerformanceNavCard::appendSample(const double usagePercent)
{
    const double kClampedPercent = qBound(0.0, usagePercent, 100.0);
    const double kPreviousSample = samples_.isEmpty()
        ? kClampedPercent
        : samples_.back();
    previousSampleCount_ = static_cast<int>(samples_.size());
    historyWindowShifted_ = previousSampleCount_ >= maxSampleCount_;
    samples_.push_back(kClampedPercent);
    while (samples_.size() > maxSampleCount_)
    {
        samples_.pop_front();
    }
    startLatestSampleAnimation(kPreviousSample);
}

void PerformanceNavCard::clearSamples()
{
    sampleAnimation_->stop();
    animationProgress_ = 1.0;
    previousSampleCount_ = 0;
    historyWindowShifted_ = false;
    samples_.clear();
    update();
}

void PerformanceNavCard::startLatestSampleAnimation(const double previousSample)
{
    previousSample_ = previousSample;
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
    return QSize(264, 78);
}

void PerformanceNavCard::paintEvent(QPaintEvent* paintEventPointer)
{
    Q_UNUSED(paintEventPointer);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);
    const auto kAnimatedValueAt = [this](const int indexValue) {
        const double kTargetValue = samples_.at(indexValue);
        if (indexValue != samples_.size() - 1 || animationProgress_ >= 1.0)
        {
            return kTargetValue;
        }
        return previousSample_ + (kTargetValue - previousSample_) * animationProgress_;
    };

    const QRect kCardRect = rect().adjusted(2, 2, -2, -2);
    const QColor kCardBorderColor(
        accentColor_.red(),
        accentColor_.green(),
        accentColor_.blue(),
        selected_ ? 210 : 92);
    QPen cardBorderPen(kCardBorderColor);
    cardBorderPen.setWidthF(selected_ ? 1.6 : 1.0);
    painter.setPen(cardBorderPen);
    painter.setBrush(Qt::NoBrush);
    painter.drawRoundedRect(kCardRect, 4.0, 4.0);

    const QRect kSparkRect(kCardRect.left() + 10, kCardRect.top() + 10, 62, kCardRect.height() - 20);
    const QColor kSparkBorderColor(
        accentColor_.red(),
        accentColor_.green(),
        accentColor_.blue(),
        selected_ ? 220 : 150);
    QPen sparkBorderPen(kSparkBorderColor);
    sparkBorderPen.setWidthF(1.2);
    painter.setPen(sparkBorderPen);
    painter.drawRect(kSparkRect);

    QPen gridPen(QColor(
        accentColor_.red(),
        accentColor_.green(),
        accentColor_.blue(),
        45));
    gridPen.setWidthF(0.8);
    painter.setPen(gridPen);
    for (int rowIndex = 1; rowIndex < 4; ++rowIndex)
    {
        const int kYValue = kSparkRect.top() + (kSparkRect.height() * rowIndex / 4);
        painter.drawLine(kSparkRect.left(), kYValue, kSparkRect.right(), kYValue);
    }

    if (samples_.size() == 1)
    {
        const double kYRatio = kAnimatedValueAt(0) / 100.0;
        const double kYValue = kSparkRect.bottom() - kYRatio * static_cast<double>(kSparkRect.height());
        QPen trendPen(accentColor_);
        trendPen.setWidthF(1.6);
        painter.setPen(trendPen);
        painter.drawLine(
            QPointF(kSparkRect.left(), kYValue),
            QPointF(kSparkRect.right(), kYValue));
    }
    else if (samples_.size() >= 2)
    {
        QPainterPath path;
        const int kPointCount = samples_.size();
        for (int indexValue = 0; indexValue < kPointCount; ++indexValue)
        {
            const double kXRatio = animatedXRatio(indexValue, kPointCount);
            const double kYRatio = kAnimatedValueAt(indexValue) / 100.0;
            const double kXValue = kSparkRect.left() + kXRatio * static_cast<double>(kSparkRect.width());
            const double kYValue = kSparkRect.bottom() - kYRatio * static_cast<double>(kSparkRect.height());
            if (indexValue == 0)
            {
                path.moveTo(kXValue, kYValue);
            }
            else
            {
                path.lineTo(kXValue, kYValue);
            }
        }

        QPen trendPen(accentColor_);
        trendPen.setWidthF(1.6);
        painter.setPen(trendPen);
        painter.setBrush(Qt::NoBrush);
        painter.drawPath(path);
    }

    const QRect kTitleRect(
        kSparkRect.right() + 10,
        kCardRect.top() + 8,
        kCardRect.width() - kSparkRect.width() - 24,
        28);
    const QRect kSubtitleRect(
        kSparkRect.right() + 10,
        kCardRect.top() + 34,
        kCardRect.width() - kSparkRect.width() - 24,
        30);

    QFont titleFont = painter.font();
    titleFont.setPointSizeF(16.0);
    titleFont.setBold(true);
    painter.setFont(titleFont);
    painter.setPen(textPrimaryColor());
    painter.drawText(kTitleRect, Qt::AlignLeft | Qt::AlignVCenter, titleText_);

    QFont subtitleFont = painter.font();
    subtitleFont.setPointSizeF(11.0);
    subtitleFont.setBold(false);
    painter.setFont(subtitleFont);
    painter.setPen(textSecondaryColor());
    painter.drawText(kSubtitleRect, Qt::AlignLeft | Qt::AlignVCenter, subtitleText_);
}

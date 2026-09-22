#include "SpectrumWidget.h"
#include <QPainter>
#include <QDebug>
#include <cmath>

SpectrumWidget::SpectrumWidget(Direction direction, QWidget* parent)
    : QWidget(parent)
    , direction_(direction)
    , spectrumData_(kNumBars, 0.0f)
{
    setupUI();
    paintTimer_.start();
}

SpectrumWidget::~SpectrumWidget()
{
}

void SpectrumWidget::setupUI()
{
    // Set background transparency
    setAttribute(Qt::WA_TranslucentBackground);
    setStyleSheet("background: transparent;");

    // Set size policy
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMinimumHeight(150);
}

void SpectrumWidget::setSpectrumData(const QVector<float>& data)
{
    if (data.size() >= kNumBars) {
        // Clamp data range to 0-1.
        for (int i = 0; i < kNumBars; ++i) {
            spectrumData_[i] = qBound(0.0f, data[i], 1.0f);
        }

        // Limit redraw frequency to avoid excessive painting.
        if (paintTimer_.hasExpired(minPaintInterval_)) {
            update();
            paintTimer_.restart();
        }
    }
}

void SpectrumWidget::setBarColor(const QColor& color)
{
    // Takes theme color; saves immediately and requests redraw to synchronize the foreground color of the earthquake alert state to the spectrum bar.
    if (barColor_ == color) {
        return;
    }

    barColor_ = color;
    update();
}

void SpectrumWidget::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    // Complex drawing region calculation is no longer needed.
}
void SpectrumWidget::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, false);

    // Actual maximum available height.
    int maxAvailableHeight = static_cast<int>(height() * maxHeightRatio_);

    // Set uniform color.
    painter.setPen(Qt::NoPen);
    painter.setBrush(barColor_);

    // Draw spectrum bars based on direction
    switch (direction_) {
    case kLeftToRight:
        // Normal draw from left to right
        for (int i = 0; i < kNumBars; ++i) {
            float spectrumValue = spectrumData_[i];
            if (spectrumValue <= 0.001f) continue;

            float normalizedValue = std::sqrt(spectrumValue);
            int barHeight = static_cast<int>(normalizedValue * maxAvailableHeight);
            barHeight = qMax(4, barHeight);

            int x = i * (barWidth_ + barSpacing_);
            int y = height() - barHeight;

            QRect barRect(x, y, barWidth_, barHeight);
            painter.drawRect(barRect);
        }
        break;

    case kRightToLeft:
        // Mirror draw from right to left
        for (int i = 0; i < kNumBars; ++i) {
            float spectrumValue = spectrumData_[i];
            if (spectrumValue <= 0.001f) continue;

            float normalizedValue = std::sqrt(spectrumValue);
            int barHeight = static_cast<int>(normalizedValue * maxAvailableHeight);
            barHeight = qMax(4, barHeight);

            int x = width() - (i + 1) * (barWidth_ + barSpacing_);
            int y = height() - barHeight;

            QRect barRect(x, y, barWidth_, barHeight);
            painter.drawRect(barRect);
        }
        break;

    case kCenterToLeft:
        // Draw from the right edge to the left (for the left spectrum).
        for (int i = 0; i < kNumBars; ++i) {
            float spectrumValue = spectrumData_[i];
            if (spectrumValue <= 0.001f) continue;

            float normalizedValue = std::sqrt(spectrumValue);
            int barHeight = static_cast<int>(normalizedValue * maxAvailableHeight);
            barHeight = qMax(4, barHeight);

            // Draw from the right edge towards the left.
            int x = width() - (i + 1) * (barWidth_ + barSpacing_);
            int y = height() - barHeight;

            QRect barRect(x, y, barWidth_, barHeight);
            painter.drawRect(barRect);
        }
        break;

    case kCenterToRight:
        // Draw from the left edge to the right (for the right spectrum).
        for (int i = 0; i < kNumBars; ++i) {
            float spectrumValue = spectrumData_[i];
            if (spectrumValue <= 0.001f) continue;

            float normalizedValue = std::sqrt(spectrumValue);
            int barHeight = static_cast<int>(normalizedValue * maxAvailableHeight);
            barHeight = qMax(4, barHeight);

            // Draw from the left edge towards the right.
            int x = i * (barWidth_ + barSpacing_);
            int y = height() - barHeight;

            QRect barRect(x, y, barWidth_, barHeight);
            painter.drawRect(barRect);
        }
        break;
    }
}

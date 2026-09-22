#include "SpectrumWidget.h"
#include <QPainter>
#include <QLinearGradient>
#include <QDebug>

SpectrumWidget::SpectrumWidget(QWidget* parent)
    : QWidget(parent)
    , currentSpectrum_(kNumBars, 0.0f)
    , targetSpectrum_(kNumBars, 0.0f)
{
    setupUI();
    createBars();

    animationTimer_ = new QTimer(this);
    animationTimer_->setTimerType(Qt::PreciseTimer); // High-precision timer
    connect(animationTimer_, &QTimer::timeout, this, &SpectrumWidget::updateSpectrumDisplay);

    startAnimation(30);
}

SpectrumWidget::~SpectrumWidget()
{
    stopAnimation();
}

void SpectrumWidget::setupUI()
{
    layout_ = new QHBoxLayout(this);
    layout_->setContentsMargins(2,2,2,2);
    layout_->setSpacing(barSpacing_);
    layout_->setAlignment(Qt::AlignBottom);

    // Set component style
    setStyleSheet("background-color: #1a1a1a;"); // Dark background

}

void SpectrumWidget::createBars()
{
    for (int i = 0; i < kNumBars; ++i) {
        QLabel* bar = new QLabel(this);

        // Set initial style
        bar->setFixedWidth(barWidth_);
        bar->setMinimumHeight(1);
        bar->setStyleSheet(QString(
            "background: qlineargradient("
            "spread: pad, x1:0.5, y1:0, x1:0.5, y2:1,"
            "stop:0 #00ffff, stop:0.3 #00ccff, stop:0.7 #0099ff, stop:1 #0066ff);"
        ));

        bar->setAlignment(Qt::AlignBottom);
        bars_.append(bar);
        layout_->addWidget(bar);

        // Force layout item to align vertically to the bottom.
        QLayoutItem* barItem = layout_->itemAt(i);
        if (barItem) {
            barItem->setAlignment(Qt::AlignBottom);
        }
    }
}

void SpectrumWidget::setSpectrumData(const QVector<float>& data) {
    if (data.size() >= kNumBars) {
        targetSpectrum_ = data;

        // Debug output
        qDebug() << "Spectrum data received - Max value:" << *std::max_element(data.begin(), data.end());

        for (int i = 0; i < kNumBars; ++i) {
            targetSpectrum_[i] = qBound(0.0f, targetSpectrum_[i], 1.0f);
            if (i < 3) { // Print only the first 3 values for debugging.
                qDebug() << "Band" << i << ":" << targetSpectrum_[i];
            }
        }
    }
    else {
        qWarning() << "Invalid spectrum data size:" << data.size() << ", expected:" << kNumBars;
    }
}

void SpectrumWidget::updateSpectrumDisplay()
{
    // Apply smooth transition
    for (int i = 0; i < kNumBars; ++i) {
        float current = currentSpectrum_[i];
        float target = targetSpectrum_[i];

        // Exponential smoothing: current + factor * (target - current)
        currentSpectrum_[i] = current + smoothingFactor_ * (target - current);

        // Avoid flickering caused by values that are too small.
        if (currentSpectrum_[i] < 0.01f) {
            currentSpectrum_[i] = 0.0f;
        }
    }

    updateBarHeights();
}

void SpectrumWidget::updateBarHeights()
{
    for (int i = 0; i < kNumBars; ++i) {
        QLabel* bar = bars_[i];
        float spectrumValue = currentSpectrum_[i];

        // Apply non-linear mapping (square root) to make small values more visible.
        float normalizedValue = std::sqrt(spectrumValue);

        int barHeight = static_cast<int>(normalizedValue * maxBarHeight_);
        barHeight = qMax(2, barHeight); // Minimum height is 2 pixels.

        bar->setFixedHeight(barHeight);

        // Dynamic color effect: adjust color intensity based on height.
        if (barHeight > 0) {
            int intensity = qMin(255, 100 + static_cast<int>(normalizedValue * 155));
            QString style = QString(
                "background: qlineargradient("
                "spread: pad, x1:0.5, y1:0, x1:0.5, y2:1,"
                "stop:0 rgba(%1, 255, 255, 255), "
                "stop:0.3 rgba(%1, 204, 255, 255), "
                "stop:0.7 rgba(%1, 153, 255, 255), "
                "stop:1 rgba(%1, 102, 255, 255));"
            ).arg(intensity);

            bar->setStyleSheet(style);
        }
    }

    // Force repaint
    update();
}

void SpectrumWidget::startAnimation(int fps)
{
    if (fps < 24) fps = 24; // Ensure not below 24Hz.
    if (fps > 120) fps = 120; // Limit maximum refresh rate.

    updateInterval_ = 1000 / fps;
    stopAnimation(); // Stop existing timer first.

    animationTimer_->start(updateInterval_);
    qDebug() << "Spectrum animation started at" << fps << "Hz";
}

void SpectrumWidget::stopAnimation()
{
    if (animationTimer_->isActive()) {
        animationTimer_->stop();
    }
}

// Optional: Add paint events to enhance visual effects.
//void SpectrumWidget::paintEvent(QPaintEvent* event)
//{
//    QWidget::paintEvent(event);
//
//    Add some decorative drawing
//    QPainter painter(this);
//    painter.setRenderHint(QPainter::Antialiasing);
//
//    Draw bottom gradient mask
//    QLinearGradient gradient(0, height() - 30, 0, height());
//    gradient.setColorAt(0, QColor(0, 0, 0, 100));
//    gradient.setColorAt(1, QColor(0, 0, 0, 200));
//
//    painter.fillRect(0, height() - 30, width(), 30, gradient);
//}

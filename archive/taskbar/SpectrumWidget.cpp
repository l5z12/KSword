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
    connect(animationTimer_, &QTimer::timeout, this, &SpectrumWidget::updateSpectrumDisplay);

    // Default 60Hz refresh rate.
    startAnimation(60);
}

SpectrumWidget::~SpectrumWidget()
{
    stopAnimation();
}

void SpectrumWidget::setupUI()
{
    layout_ = new QHBoxLayout(this);
    layout_->setContentsMargins(10, 10, 10, 10);
    layout_->setSpacing(barSpacing_);
    layout_->setAlignment(Qt::AlignBottom);

    // Set component style
    setStyleSheet("background-color: #1a1a1a;"); // Dark background
    setMinimumHeight(250);
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

void SpectrumWidget::setSpectrumData(const QVector<float>& data)
{
    qDebug() << "SpectrumWidget::setSpectrumData called on" << this << "size=" << data.size();
    if (data.size() >= kNumBars) {
        targetSpectrum_ = data;

        // Clamp data range to 0-1.
        for (int i = 0; i < kNumBars; ++i) {
            targetSpectrum_[i] = qBound(0.0f, targetSpectrum_[i], 1.0f);
        }
    }
}

void SpectrumWidget::updateSpectrumDisplay()
{
    qDebug() << "updateSpectrumDisplay on" << this;
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

    update();
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

    qDebug() << "SpectrumWidget::startAnimation on" << this << "fps=" << fps;
    animationTimer_->start(updateInterval_);
    qDebug() << "Animation timer active:" << animationTimer_->isActive();
}

void SpectrumWidget::stopAnimation()
{
    if (animationTimer_->isActive()) {
        animationTimer_->stop();
    }
}
// Override paintEvent to render all spectrum bars in a single pass.
void SpectrumWidget::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing); // Enable anti-aliasing on demand.

    // Calculate draw area (subtract margins)
    const int kMargin = 10;
    const int kTotalWidth = width() - 2 * kMargin;
    const int kTotalHeight = height() - 2 * kMargin;
    maxBarHeight_ = kTotalHeight; // Cache maximum height

    // Calculate the width and spacing of each bar (to avoid layout manager overhead).
    const int kAvailableWidth = kTotalWidth - (kNumBars - 1) * barSpacing_;
    const int kBarWidth = qMax(1, kAvailableWidth / kNumBars); // Ensure at least 1px

    // Pre-cache gradient (avoid creating on every draw).
    if (gradient_.stops().isEmpty()) {
        gradient_ = QLinearGradient(0, 0, 0, kTotalHeight);
        gradient_.setColorAt(0, QColor(0, 255, 255));
        gradient_.setColorAt(0.3, QColor(0, 204, 255));
        gradient_.setColorAt(0.7, QColor(0, 153, 255));
        gradient_.setColorAt(1, QColor(0, 102, 255));
    }

    // Draw all spectrum bars
    painter.translate(kMargin, kMargin + kTotalHeight); // Move origin to bottom
    for (int i = 0; i < kNumBars; ++i) {
        const float kValue = currentSpectrum_[i];
        if (kValue <= 0.01f) continue; // Skip very small values

        // Calculate height (non-linear mapping).
        const float kNormalized = std::sqrt(kValue);
        const int kBarHeight = static_cast<int>(kNormalized * kTotalHeight);

        // Draw position (x offset: cumulative sum of bar width + spacing)
        const int kX = i * (kBarWidth + barSpacing_);
        // Draw rectangle (y-axis increases downward, so height is negative)
        painter.fillRect(kX, -kBarHeight, kBarWidth, kBarHeight, gradient_);
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

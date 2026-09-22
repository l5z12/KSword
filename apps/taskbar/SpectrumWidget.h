#pragma once
#ifndef SPECTRUMWIDGET_H
#define SPECTRUMWIDGET_H

#include <QWidget>
#include <QColor>
#include <QVector>
#include <QElapsedTimer>

class SpectrumWidget : public QWidget
{
    Q_OBJECT

public:
    enum Direction {
        kLeftToRight,    // Left to right (normal)
        kRightToLeft,    // Right to left (mirror)
        kCenterToLeft,   // From center to left
        kCenterToRight   // From center to right
    };

    explicit SpectrumWidget(Direction direction = kLeftToRight, QWidget* parent = nullptr);
    ~SpectrumWidget();

    void setSpectrumData(const QVector<float>& data);

    // setBarColor: input is the target color for the spectrum bar; updates the draw color and requests repaint; no return value.
    void setBarColor(const QColor& color);

    // Set the maximum height ratio for bars (0.0-1.0)
    void setMaxHeightRatio(float ratio) { maxHeightRatio_ = qBound(0.1f, ratio, 1.0f); }

    // Set drawing direction
    void setDirection(Direction direction) {
        direction_ = direction;
        update();
    }

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    void setupUI();

    // Spectrum bar related.
    static constexpr int kNumBars = 16;
    QVector<float> spectrumData_;

    // Draw direction
    Direction direction_;

    // Style configuration
    int barWidth_ = 12;
    int barSpacing_ = 3;
    float maxHeightRatio_ = 0.8f; // Maximum height is 80% of the available area.

    // Drawing area calculation
    int drawAreaWidth_ = 0;
    int drawAreaHeight_ = 0;
    int drawAreaX_ = 0;
    int drawAreaY_ = 0;

    // Color configuration
    QColor barColor_ = QColor(0, 255, 255); // #00FFFF

    // Performance optimization
    QElapsedTimer paintTimer_;
    int minPaintInterval_ = 16; // Approximately 60fps, avoid excessive redraws.
};

#endif // SPECTRUMWIDGET_H

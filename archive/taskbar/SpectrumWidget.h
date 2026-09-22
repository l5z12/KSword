#pragma once
#ifndef SPECTRUMWIDGET_H
#define SPECTRUMWIDGET_H

#include <QWidget>
#include <QVector>
#include <QLabel>
#include <QHBoxLayout>
#include <QTimer>

class SpectrumWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SpectrumWidget(QWidget* parent = nullptr);
    ~SpectrumWidget();

    void setSpectrumData(const QVector<float>& data);
    void startAnimation(int fps = 60);
    void stopAnimation();

    void testPaint();

public slots:
    void updateSpectrumDisplay();

    void paintEvent(QPaintEvent* event)override;
private:

    void setupUI();
    void createBars();
    void updateBarHeights();

    // Spectrum bar related.
    static constexpr int kNumBars = 16;
    QVector<QLabel*> bars_;
    QVector<float> currentSpectrum_;
    QVector<float> targetSpectrum_;

    // Layout and container
    QHBoxLayout* layout_;
    QWidget* barsContainer_;

    // Animation timer
    QTimer* animationTimer_;
    int updateInterval_; // Milliseconds

    // Style configuration
    QColor barColor_ = QColor(0, 255, 255); // #00FFFF
    int maxBarHeight_ = 36;
    int barWidth_ = 8;
    int barSpacing_ = 2;

    // Smooth animation parameters
    float smoothingFactor_ = 0.7f;

    QLinearGradient gradient_;
};

#endif // SPECTRUMWIDGET_H

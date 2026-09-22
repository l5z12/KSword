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

    //void paintEvent(QPaintEvent* event)override;
private:

    void setupUI();
    void createBars();
    void updateBarHeights();

    // Spectrum bar related.
    static constexpr int NUM_BARS = 16;
    QVector<QLabel*> m_bars;
    QVector<float> m_currentSpectrum;
    QVector<float> m_targetSpectrum;

    // Layout and container
    QHBoxLayout* m_layout;
    QWidget* m_barsContainer;

    // Animation timer
    QTimer* m_animationTimer;
    int m_updateInterval; // Milliseconds

    // Style configuration
    QColor m_barColor = QColor(0, 255, 255); // #00FFFF
    int m_maxBarHeight = 36;
    int m_barWidth = 8;
    int m_barSpacing = 2;

    // Smooth animation parameters
    float m_smoothingFactor = 0.7f;

    QLinearGradient m_gradient;
};

#endif // SPECTRUMWIDGET_H

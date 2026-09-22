#pragma once

#include <QColor>
#include <QVector>
#include <QWidget>

class QPaintEvent;
class QVariantAnimation;

class PerformanceNavCard final : public QWidget
{
public:
    explicit PerformanceNavCard(QWidget* parent = nullptr);

    void setTitleText(const QString& titleText);
    void setSubtitleText(const QString& subtitleText);
    void setAccentColor(const QColor& accentColor);
    void setSelectedState(bool selected);
    void appendSample(double usagePercent);
    void clearSamples();

    [[nodiscard]] QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* paintEventPointer) override;

private:
    void startLatestSampleAnimation(double previousSample);
    double animatedXRatio(int sampleIndex, int sampleCount) const;
    QString titleText_;
    QString subtitleText_;
    QColor accentColor_;
    bool selected_ = false;
    QVector<double> samples_;
    int maxSampleCount_ = 36;
    int previousSampleCount_ = 0;
    bool historyWindowShifted_ = false;
    QVariantAnimation* sampleAnimation_ = nullptr;
    double previousSample_ = 0.0;
    double animationProgress_ = 1.0;
};

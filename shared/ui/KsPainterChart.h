#pragma once

// KsPainterChart is a small, source-compatible subset of the chart API used by
// KSword. It is implemented entirely with QWidget + QPainter.

#include <QAbstractScrollArea>
#include <QBrush>
#include <QEasingCurve>
#include <QFont>
#include <QFrame>
#include <QHash>
#include <QList>
#include <QMargins>
#include <QObject>
#include <QPainter>
#include <QPair>
#include <QPen>
#include <QPointF>
#include <QString>
#include <QStringList>
#include <QVector>

#include <functional>

class QPaintEvent;
class QShowEvent;
class QVariantAnimation;

class KsPainterChartObject : public QObject
{
public:
    explicit KsPainterChartObject(QObject* parent = nullptr);

    void setChangeHandler(std::function<void()> changeHandler);

protected:
    void notifyChanged();

private:
    std::function<void()> changeHandler_;
};

class QAbstractAxis : public KsPainterChartObject
{
public:
    explicit QAbstractAxis(QObject* parent = nullptr);

    void setLabelsVisible(bool visible);
    bool labelsVisible() const;
    void setGridLineVisible(bool visible);
    bool isGridLineVisible() const;
    void setMinorGridLineVisible(bool visible);
    bool isMinorGridLineVisible() const;
    void setLineVisible(bool visible);
    bool isLineVisible() const;

    void setLabelsBrush(const QBrush& brush);
    QBrush labelsBrush() const;
    void setTitleBrush(const QBrush& brush);
    QBrush titleBrush() const;
    void setLinePenColor(const QColor& color);
    void setGridLineColor(const QColor& color);
    void setLinePen(const QPen& pen);
    QPen linePen() const;
    void setGridLinePen(const QPen& pen);
    QPen gridLinePen() const;

    void setTitleText(const QString& titleText);
    QString titleText() const;
    void setLabelFormat(const QString& labelFormat);
    QString labelFormat() const;

    Qt::Alignment alignment() const;

private:
    friend class QChart;
    void setAlignment(Qt::Alignment alignment);

    bool labelsVisible_ = true;
    bool gridLineVisible_ = true;
    bool minorGridLineVisible_ = false;
    bool lineVisible_ = true;
    QBrush labelsBrush_;
    QBrush titleBrush_;
    QPen linePen_ = QPen(QColor(128, 128, 128, 150), 1.0);
    QPen gridLinePen_ = QPen(QColor(128, 128, 128, 55), 1.0);
    QString titleText_;
    QString labelFormat_;
    Qt::Alignment alignment_ = Qt::AlignBottom;
};

class QValueAxis : public QAbstractAxis
{
public:
    explicit QValueAxis(QObject* parent = nullptr);

    void setRange(qreal minimum, qreal maximum);
    qreal min() const;
    qreal max() const;

private:
    qreal minimum_ = 0.0;
    qreal maximum_ = 1.0;
};

class QBarCategoryAxis : public QAbstractAxis
{
public:
    explicit QBarCategoryAxis(QObject* parent = nullptr);

    void append(const QString& category);
    void append(const QStringList& categories);
    QStringList categories() const;

private:
    QStringList categories_;
};

class QAbstractSeries : public KsPainterChartObject
{
public:
    explicit QAbstractSeries(QObject* parent = nullptr);

    void setName(const QString& name);
    QString name() const;
    bool attachAxis(QAbstractAxis* axis);
    QList<QAbstractAxis*> attachedAxes() const;

private:
    QString name_;
    QList<QAbstractAxis*> attachedAxes_;
};

class QLineSeries : public QAbstractSeries
{
public:
    explicit QLineSeries(QObject* parent = nullptr);

    void append(qreal x, qreal y);
    void append(const QPointF& point);
    bool remove(int index);
    void replace(const QList<QPointF>& points);
    int count() const;
    QList<QPointF> points() const;

    void setColor(const QColor& color);
    QColor color() const;
    void setPen(const QPen& pen);
    QPen pen() const;

private:
    QList<QPointF> points_;
    QPen pen_ = QPen(QColor(52, 152, 219), 1.6);
};

class QAreaSeries : public QAbstractSeries
{
public:
    explicit QAreaSeries(
        QLineSeries* upperSeries,
        QLineSeries* lowerSeries = nullptr,
        QObject* parent = nullptr);

    QLineSeries* upperSeries() const;
    QLineSeries* lowerSeries() const;

    void setColor(const QColor& color);
    QColor color() const;
    void setBorderColor(const QColor& color);
    QColor borderColor() const;
    void setPen(const QPen& pen);
    QPen pen() const;
    void setBrush(const QBrush& brush);
    QBrush brush() const;

private:
    QLineSeries* upperSeries_ = nullptr;
    QLineSeries* lowerSeries_ = nullptr;
    QBrush brush_ = QBrush(QColor(52, 152, 219, 48));
    QPen pen_ = QPen(QColor(52, 152, 219), 1.6);
};

class QBarSet : public KsPainterChartObject
{
public:
    explicit QBarSet(const QString& label, QObject* parent = nullptr);

    QBarSet& operator<<(qreal value);
    void append(qreal value);
    void replace(int index, qreal value);
    int count() const;
    QVector<qreal> values() const;
    QString label() const;

    void setColor(const QColor& color);
    QColor color() const;
    void setBorderColor(const QColor& color);
    QColor borderColor() const;
    void setBrush(const QBrush& brush);
    QBrush brush() const;
    void setLabelBrush(const QBrush& brush);
    QBrush labelBrush() const;

private:
    QString label_;
    QVector<qreal> values_;
    QBrush brush_ = QBrush(QColor(52, 152, 219));
    QColor borderColor_ = Qt::transparent;
    QBrush labelBrush_;
};

class QBarSeries : public QAbstractSeries
{
public:
    explicit QBarSeries(QObject* parent = nullptr);

    bool append(QBarSet* set);
    bool append(const QList<QBarSet*>& sets);
    QList<QBarSet*> barSets() const;

private:
    void attachSetHandler(QBarSet* set);

    QList<QBarSet*> sets_;
};

class QLegend : public KsPainterChartObject
{
public:
    explicit QLegend(QObject* parent = nullptr);

    void hide();
    void setVisible(bool visible);
    bool isVisible() const;
    void setAlignment(Qt::Alignment alignment);
    Qt::Alignment alignment() const;
    void setLabelColor(const QColor& color);
    QColor labelColor() const;
    void setLabelBrush(const QBrush& brush);
    QBrush labelBrush() const;
    void setFont(const QFont& font);
    QFont font() const;

private:
    bool visible_ = true;
    Qt::Alignment alignment_ = Qt::AlignTop;
    QBrush labelBrush_;
    QFont font_;
};

class QChart : public KsPainterChartObject
{
public:
    enum AnimationOption
    {
        kNoAnimation = 0x0,
        kGridAxisAnimations = 0x1,
        kSeriesAnimations = 0x2,
        kAllAnimations = kGridAxisAnimations | kSeriesAnimations
    };

    explicit QChart(QObject* parent = nullptr);

    void addSeries(QAbstractSeries* series);
    QList<QAbstractSeries*> series() const;
    void addAxis(QAbstractAxis* axis, Qt::Alignment alignment);
    QList<QAbstractAxis*> axes() const;
    QLegend* legend() const;

    void setTitle(const QString& title);
    QString title() const;
    void setTitleBrush(const QBrush& brush);
    QBrush titleBrush() const;
    void setTitleFont(const QFont& font);
    QFont titleFont() const;

    void setBackgroundVisible(bool visible);
    bool isBackgroundVisible() const;
    void setBackgroundRoundness(qreal roundness);
    qreal backgroundRoundness() const;
    void setBackgroundBrush(const QBrush& brush);
    QBrush backgroundBrush() const;
    void setMargins(const QMargins& margins);
    QMargins margins() const;

    void setPlotAreaBackgroundVisible(bool visible);
    bool isPlotAreaBackgroundVisible() const;
    void setPlotAreaBackgroundBrush(const QBrush& brush);
    QBrush plotAreaBackgroundBrush() const;
    void setPlotAreaBackgroundPen(const QPen& pen);
    QPen plotAreaBackgroundPen() const;

    void setAnimationOptions(AnimationOption options);
    AnimationOption animationOptions() const;
    void setAnimationDuration(int durationMs);
    int animationDuration() const;
    void setAnimationEasingCurve(const QEasingCurve& easingCurve);
    QEasingCurve animationEasingCurve() const;

    void update();

private:
    void attachSeriesHandlers(QAbstractSeries* series);

    QList<QAbstractSeries*> series_;
    QList<QAbstractAxis*> axes_;
    QLegend* legend_ = nullptr;
    QString title_;
    QBrush titleBrush_;
    QFont titleFont_;
    bool backgroundVisible_ = true;
    qreal backgroundRoundness_ = 0.0;
    QBrush backgroundBrush_;
    QMargins margins_;
    bool plotAreaBackgroundVisible_ = false;
    QBrush plotAreaBackgroundBrush_;
    QPen plotAreaBackgroundPen_ = QPen(Qt::NoPen);
    AnimationOption animationOptions_ = kNoAnimation;
    int animationDurationMs_ = 250;
    QEasingCurve animationEasingCurve_ = QEasingCurve(QEasingCurve::OutCubic);
};

class QChartView : public QFrame
{
public:
    explicit QChartView(QChart* chart, QWidget* parent = nullptr);
    ~QChartView() override;

    QChart* chart() const;
    QWidget* viewport();
    const QWidget* viewport() const;

    void setRenderHint(QPainter::RenderHint hint, bool enabled = true);
    void setHorizontalScrollBarPolicy(Qt::ScrollBarPolicy policy);
    void setVerticalScrollBarPolicy(Qt::ScrollBarPolicy policy);
    void setSizeAdjustPolicy(QAbstractScrollArea::SizeAdjustPolicy policy);
    void setBackgroundBrush(const QBrush& brush);

    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent* event) override;
    void showEvent(QShowEvent* event) override;

private:
    using LinePointMap = QHash<const QLineSeries*, QList<QPointF>>;
    using BarValueMap = QHash<const QBarSet*, QVector<qreal>>;
    using AxisRangeMap = QHash<const QValueAxis*, QPair<qreal, qreal>>;

    void scheduleModelUpdate();
    void applyPendingModelUpdate();
    void startModelAnimation();
    void syncSnapshotsToCurrent();
    void captureCurrentFrameAsDisplayed();
    LinePointMap currentLinePoints() const;
    BarValueMap currentBarValues() const;
    AxisRangeMap currentAxisRanges() const;
    QList<QPointF> renderedPoints(const QLineSeries* series) const;
    QVector<qreal> renderedBarValues(const QBarSet* set) const;
    QPair<qreal, qreal> renderedAxisRange(const QValueAxis* axis) const;

    QChart* chart_ = nullptr;
    QVariantAnimation* animation_ = nullptr;
    bool updateScheduled_ = false;
    bool antialiasingEnabled_ = true;
    qreal animationProgress_ = 1.0;
    QBrush viewBackgroundBrush_ = QBrush(Qt::NoBrush);

    LinePointMap displayedLinePoints_;
    LinePointMap fromLinePoints_;
    LinePointMap toLinePoints_;
    BarValueMap displayedBarValues_;
    BarValueMap fromBarValues_;
    BarValueMap toBarValues_;
    AxisRangeMap displayedAxisRanges_;
    AxisRangeMap fromAxisRanges_;
    AxisRangeMap toAxisRanges_;
};

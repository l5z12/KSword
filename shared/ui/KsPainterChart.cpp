#include "KsPainterChart.h"

#include <QAbstractAnimation>
#include <QFontMetricsF>
#include <QPaintEvent>
#include <QPainterPath>
#include <QSet>
#include <QShowEvent>
#include <QTimer>
#include <QVariantAnimation>

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    constexpr qreal kRangeEpsilon = 0.000001;

    qreal interpolateValue(const qreal fromValue, const qreal toValue, const qreal progress)
    {
        return fromValue + (toValue - fromValue) * progress;
    }

    bool nearlyEqual(const qreal firstValue, const qreal secondValue)
    {
        const qreal kScale = std::max<qreal>({ 1.0, std::abs(firstValue), std::abs(secondValue) });
        return std::abs(firstValue - secondValue) <= kRangeEpsilon * kScale;
    }

    bool pointNearlyEqual(const QPointF& firstPoint, const QPointF& secondPoint)
    {
        return nearlyEqual(firstPoint.x(), secondPoint.x())
            && nearlyEqual(firstPoint.y(), secondPoint.y());
    }

    // Keep the existing live-chart motion contract:
    // - when a full history window shifts, retained samples move one slot left;
    // - only the newest sample interpolates vertically;
    // - while a history window is still growing, existing samples keep their
    //   old position and the new sample enters from the right.
    QList<QPointF> interpolatePointLists(
        const QList<QPointF>& fromPoints,
        const QList<QPointF>& toPoints,
        const qreal progress)
    {
        if (toPoints.isEmpty() || progress >= 1.0)
        {
            return toPoints;
        }
        if (fromPoints.isEmpty())
        {
            return toPoints;
        }

        const int kFromCount = fromPoints.size();
        const int kToCount = toPoints.size();
        QList<QPointF> result = toPoints;

        if (kFromCount == kToCount && kToCount >= 2)
        {
            bool resetCoordinateShift = true;
            bool absoluteCoordinateShift = true;
            for (int pointIndex = 0; pointIndex + 1 < kToCount; ++pointIndex)
            {
                resetCoordinateShift = resetCoordinateShift
                    && nearlyEqual(toPoints.at(pointIndex).x(), fromPoints.at(pointIndex).x())
                    && nearlyEqual(toPoints.at(pointIndex).y(), fromPoints.at(pointIndex + 1).y());
                absoluteCoordinateShift = absoluteCoordinateShift
                    && pointNearlyEqual(toPoints.at(pointIndex), fromPoints.at(pointIndex + 1));
            }

            if (resetCoordinateShift || absoluteCoordinateShift)
            {
                qreal sampleSpacing = toPoints.at(1).x() - toPoints.at(0).x();
                if (nearlyEqual(sampleSpacing, 0.0))
                {
                    sampleSpacing = 1.0;
                }
                for (int pointIndex = 0; pointIndex < kToCount; ++pointIndex)
                {
                    const QPointF kTargetPoint = toPoints.at(pointIndex);
                    const qreal kStartX = resetCoordinateShift
                        ? kTargetPoint.x() + sampleSpacing
                        : kTargetPoint.x();
                    const qreal kStartY = pointIndex + 1 == kToCount
                        ? fromPoints.constLast().y()
                        : kTargetPoint.y();
                    result[pointIndex] = QPointF(
                        interpolateValue(kStartX, kTargetPoint.x(), progress),
                        interpolateValue(kStartY, kTargetPoint.y(), progress));
                }
                return result;
            }

            for (int pointIndex = 0; pointIndex < kToCount; ++pointIndex)
            {
                result[pointIndex] = QPointF(
                    interpolateValue(fromPoints.at(pointIndex).x(), toPoints.at(pointIndex).x(), progress),
                    interpolateValue(fromPoints.at(pointIndex).y(), toPoints.at(pointIndex).y(), progress));
            }
            return result;
        }

        if (kToCount == kFromCount + 1)
        {
            for (int pointIndex = 0; pointIndex < kFromCount; ++pointIndex)
            {
                result[pointIndex] = QPointF(
                    interpolateValue(fromPoints.at(pointIndex).x(), toPoints.at(pointIndex).x(), progress),
                    interpolateValue(fromPoints.at(pointIndex).y(), toPoints.at(pointIndex).y(), progress));
            }
            const QPointF kTargetPoint = toPoints.constLast();
            result[kToCount - 1] = QPointF(
                kTargetPoint.x(),
                interpolateValue(fromPoints.constLast().y(), kTargetPoint.y(), progress));
            return result;
        }

        const int kSharedCount = std::min(kFromCount, kToCount);
        for (int pointIndex = 0; pointIndex < kSharedCount; ++pointIndex)
        {
            result[pointIndex] = QPointF(
                interpolateValue(fromPoints.at(pointIndex).x(), toPoints.at(pointIndex).x(), progress),
                interpolateValue(fromPoints.at(pointIndex).y(), toPoints.at(pointIndex).y(), progress));
        }
        return result;
    }

    QVector<qreal> interpolateBarValues(
        const QVector<qreal>& fromValues,
        const QVector<qreal>& toValues,
        const qreal progress)
    {
        QVector<qreal> result = toValues;
        const int kSharedCount = std::min(
            static_cast<int>(fromValues.size()),
            static_cast<int>(toValues.size()));
        for (int valueIndex = 0; valueIndex < kSharedCount; ++valueIndex)
        {
            result[valueIndex] = interpolateValue(fromValues.at(valueIndex), toValues.at(valueIndex), progress);
        }
        return result;
    }

    QColor brushColorOr(const QBrush& brush, const QColor& fallbackColor)
    {
        return brush.style() == Qt::NoBrush ? fallbackColor : brush.color();
    }

    QString formatAxisValue(const QValueAxis* axis, const qreal value)
    {
        if (axis == nullptr)
        {
            return QString::number(value, 'g', 3);
        }

        const QString kFormat = axis->labelFormat();
        if (kFormat.contains(QStringLiteral("%d")))
        {
            return QString::number(qRound64(value));
        }
        if (kFormat.contains(QStringLiteral("%.0f")))
        {
            QString text = QString::number(value, 'f', 0);
            if (kFormat.contains(QStringLiteral("%%")))
            {
                text += QLatin1Char('%');
            }
            return text;
        }

        const qreal kSpan = std::abs(axis->max() - axis->min());
        if (kSpan >= 1000.0)
        {
            return QString::number(value, 'g', 3);
        }
        return QString::number(value, 'f', kSpan <= 10.0 ? 1 : 0);
    }

    bool isHorizontalAlignment(const Qt::Alignment alignment)
    {
        return alignment.testFlag(Qt::AlignBottom) || alignment.testFlag(Qt::AlignTop);
    }

    QPointF mapChartPoint(
        const QPointF& point,
        const QRectF& plotRect,
        const QPair<qreal, qreal>& xRange,
        const QPair<qreal, qreal>& yRange)
    {
        const qreal kXSpan = std::max<qreal>(kRangeEpsilon, xRange.second - xRange.first);
        const qreal kYSpan = std::max<qreal>(kRangeEpsilon, yRange.second - yRange.first);
        const qreal kXRatio = (point.x() - xRange.first) / kXSpan;
        const qreal kYRatio = (point.y() - yRange.first) / kYSpan;
        return QPointF(
            plotRect.left() + kXRatio * plotRect.width(),
            plotRect.bottom() - kYRatio * plotRect.height());
    }
}

KsPainterChartObject::KsPainterChartObject(QObject* parent)
    : QObject(parent)
{
}

void KsPainterChartObject::setChangeHandler(std::function<void()> changeHandler)
{
    changeHandler_ = std::move(changeHandler);
}

void KsPainterChartObject::notifyChanged()
{
    if (changeHandler_)
    {
        changeHandler_();
    }
}

QAbstractAxis::QAbstractAxis(QObject* parent)
    : KsPainterChartObject(parent)
{
}

void QAbstractAxis::setLabelsVisible(const bool visible)
{
    labelsVisible_ = visible;
    notifyChanged();
}

bool QAbstractAxis::labelsVisible() const
{
    return labelsVisible_;
}

void QAbstractAxis::setGridLineVisible(const bool visible)
{
    gridLineVisible_ = visible;
    notifyChanged();
}

bool QAbstractAxis::isGridLineVisible() const
{
    return gridLineVisible_;
}

void QAbstractAxis::setMinorGridLineVisible(const bool visible)
{
    minorGridLineVisible_ = visible;
    notifyChanged();
}

bool QAbstractAxis::isMinorGridLineVisible() const
{
    return minorGridLineVisible_;
}

void QAbstractAxis::setLineVisible(const bool visible)
{
    lineVisible_ = visible;
    notifyChanged();
}

bool QAbstractAxis::isLineVisible() const
{
    return lineVisible_;
}

void QAbstractAxis::setLabelsBrush(const QBrush& brush)
{
    labelsBrush_ = brush;
    notifyChanged();
}

QBrush QAbstractAxis::labelsBrush() const
{
    return labelsBrush_;
}

void QAbstractAxis::setTitleBrush(const QBrush& brush)
{
    titleBrush_ = brush;
    notifyChanged();
}

QBrush QAbstractAxis::titleBrush() const
{
    return titleBrush_;
}

void QAbstractAxis::setLinePenColor(const QColor& color)
{
    linePen_.setColor(color);
    notifyChanged();
}

void QAbstractAxis::setGridLineColor(const QColor& color)
{
    gridLinePen_.setColor(color);
    notifyChanged();
}

void QAbstractAxis::setLinePen(const QPen& pen)
{
    linePen_ = pen;
    notifyChanged();
}

QPen QAbstractAxis::linePen() const
{
    return linePen_;
}

void QAbstractAxis::setGridLinePen(const QPen& pen)
{
    gridLinePen_ = pen;
    notifyChanged();
}

QPen QAbstractAxis::gridLinePen() const
{
    return gridLinePen_;
}

void QAbstractAxis::setTitleText(const QString& titleText)
{
    titleText_ = titleText;
    notifyChanged();
}

QString QAbstractAxis::titleText() const
{
    return titleText_;
}

void QAbstractAxis::setLabelFormat(const QString& labelFormat)
{
    labelFormat_ = labelFormat;
    notifyChanged();
}

QString QAbstractAxis::labelFormat() const
{
    return labelFormat_;
}

Qt::Alignment QAbstractAxis::alignment() const
{
    return alignment_;
}

void QAbstractAxis::setAlignment(const Qt::Alignment alignment)
{
    alignment_ = alignment;
    notifyChanged();
}

QValueAxis::QValueAxis(QObject* parent)
    : QAbstractAxis(parent)
{
}

void QValueAxis::setRange(qreal minimum, qreal maximum)
{
    if (maximum < minimum)
    {
        std::swap(minimum, maximum);
    }
    if (nearlyEqual(minimum, maximum))
    {
        maximum = minimum + 1.0;
    }
    if (nearlyEqual(minimum_, minimum) && nearlyEqual(maximum_, maximum))
    {
        return;
    }
    minimum_ = minimum;
    maximum_ = maximum;
    notifyChanged();
}

qreal QValueAxis::min() const
{
    return minimum_;
}

qreal QValueAxis::max() const
{
    return maximum_;
}

QBarCategoryAxis::QBarCategoryAxis(QObject* parent)
    : QAbstractAxis(parent)
{
}

void QBarCategoryAxis::append(const QString& category)
{
    categories_.append(category);
    notifyChanged();
}

void QBarCategoryAxis::append(const QStringList& categories)
{
    categories_.append(categories);
    notifyChanged();
}

QStringList QBarCategoryAxis::categories() const
{
    return categories_;
}

QAbstractSeries::QAbstractSeries(QObject* parent)
    : KsPainterChartObject(parent)
{
}

void QAbstractSeries::setName(const QString& name)
{
    name_ = name;
    notifyChanged();
}

QString QAbstractSeries::name() const
{
    return name_;
}

bool QAbstractSeries::attachAxis(QAbstractAxis* axis)
{
    if (axis == nullptr)
    {
        return false;
    }
    if (!attachedAxes_.contains(axis))
    {
        attachedAxes_.append(axis);
        notifyChanged();
    }
    return true;
}

QList<QAbstractAxis*> QAbstractSeries::attachedAxes() const
{
    return attachedAxes_;
}

QLineSeries::QLineSeries(QObject* parent)
    : QAbstractSeries(parent)
{
}

void QLineSeries::append(const qreal x, const qreal y)
{
    append(QPointF(x, y));
}

void QLineSeries::append(const QPointF& point)
{
    points_.append(point);
    notifyChanged();
}

bool QLineSeries::remove(const int index)
{
    if (index < 0 || index >= points_.size())
    {
        return false;
    }
    points_.removeAt(index);
    notifyChanged();
    return true;
}

void QLineSeries::replace(const QList<QPointF>& points)
{
    points_ = points;
    notifyChanged();
}

int QLineSeries::count() const
{
    return static_cast<int>(points_.size());
}

QList<QPointF> QLineSeries::points() const
{
    return points_;
}

void QLineSeries::setColor(const QColor& color)
{
    pen_.setColor(color);
    notifyChanged();
}

QColor QLineSeries::color() const
{
    return pen_.color();
}

void QLineSeries::setPen(const QPen& pen)
{
    pen_ = pen;
    notifyChanged();
}

QPen QLineSeries::pen() const
{
    return pen_;
}

QAreaSeries::QAreaSeries(QLineSeries* upperSeries, QLineSeries* lowerSeries, QObject* parent)
    : QAbstractSeries(parent)
    , upperSeries_(upperSeries)
    , lowerSeries_(lowerSeries)
{
    if (upperSeries_ != nullptr)
    {
        upperSeries_->setChangeHandler([this]() { notifyChanged(); });
    }
    if (lowerSeries_ != nullptr)
    {
        lowerSeries_->setChangeHandler([this]() { notifyChanged(); });
    }
}

QLineSeries* QAreaSeries::upperSeries() const
{
    return upperSeries_;
}

QLineSeries* QAreaSeries::lowerSeries() const
{
    return lowerSeries_;
}

void QAreaSeries::setColor(const QColor& color)
{
    brush_ = QBrush(color);
    notifyChanged();
}

QColor QAreaSeries::color() const
{
    return brush_.color();
}

void QAreaSeries::setBorderColor(const QColor& color)
{
    pen_.setColor(color);
    notifyChanged();
}

QColor QAreaSeries::borderColor() const
{
    return pen_.color();
}

void QAreaSeries::setPen(const QPen& pen)
{
    pen_ = pen;
    notifyChanged();
}

QPen QAreaSeries::pen() const
{
    return pen_;
}

void QAreaSeries::setBrush(const QBrush& brush)
{
    brush_ = brush;
    notifyChanged();
}

QBrush QAreaSeries::brush() const
{
    return brush_;
}

QBarSet::QBarSet(const QString& label, QObject* parent)
    : KsPainterChartObject(parent)
    , label_(label)
{
}

QBarSet& QBarSet::operator<<(const qreal value)
{
    append(value);
    return *this;
}

void QBarSet::append(const qreal value)
{
    values_.append(value);
    notifyChanged();
}

void QBarSet::replace(const int index, const qreal value)
{
    if (index < 0 || index >= values_.size())
    {
        return;
    }
    if (nearlyEqual(values_.at(index), value))
    {
        return;
    }
    values_[index] = value;
    notifyChanged();
}

int QBarSet::count() const
{
    return static_cast<int>(values_.size());
}

QVector<qreal> QBarSet::values() const
{
    return values_;
}

QString QBarSet::label() const
{
    return label_;
}

void QBarSet::setColor(const QColor& color)
{
    brush_ = QBrush(color);
    notifyChanged();
}

QColor QBarSet::color() const
{
    return brush_.color();
}

void QBarSet::setBorderColor(const QColor& color)
{
    borderColor_ = color;
    notifyChanged();
}

QColor QBarSet::borderColor() const
{
    return borderColor_;
}

void QBarSet::setBrush(const QBrush& brush)
{
    brush_ = brush;
    notifyChanged();
}

QBrush QBarSet::brush() const
{
    return brush_;
}

void QBarSet::setLabelBrush(const QBrush& brush)
{
    labelBrush_ = brush;
    notifyChanged();
}

QBrush QBarSet::labelBrush() const
{
    return labelBrush_;
}

QBarSeries::QBarSeries(QObject* parent)
    : QAbstractSeries(parent)
{
}

bool QBarSeries::append(QBarSet* set)
{
    if (set == nullptr || sets_.contains(set))
    {
        return false;
    }
    sets_.append(set);
    if (set->parent() == nullptr)
    {
        set->setParent(this);
    }
    attachSetHandler(set);
    notifyChanged();
    return true;
}

bool QBarSeries::append(const QList<QBarSet*>& sets)
{
    bool appendedAny = false;
    for (QBarSet* set : sets)
    {
        appendedAny = append(set) || appendedAny;
    }
    return appendedAny;
}

QList<QBarSet*> QBarSeries::barSets() const
{
    return sets_;
}

void QBarSeries::attachSetHandler(QBarSet* set)
{
    if (set != nullptr)
    {
        set->setChangeHandler([this]() { notifyChanged(); });
    }
}

QLegend::QLegend(QObject* parent)
    : KsPainterChartObject(parent)
{
}

void QLegend::hide()
{
    setVisible(false);
}

void QLegend::setVisible(const bool visible)
{
    visible_ = visible;
    notifyChanged();
}

bool QLegend::isVisible() const
{
    return visible_;
}

void QLegend::setAlignment(const Qt::Alignment alignment)
{
    alignment_ = alignment;
    notifyChanged();
}

Qt::Alignment QLegend::alignment() const
{
    return alignment_;
}

void QLegend::setLabelColor(const QColor& color)
{
    labelBrush_ = QBrush(color);
    notifyChanged();
}

QColor QLegend::labelColor() const
{
    return labelBrush_.color();
}

void QLegend::setLabelBrush(const QBrush& brush)
{
    labelBrush_ = brush;
    notifyChanged();
}

QBrush QLegend::labelBrush() const
{
    return labelBrush_;
}

void QLegend::setFont(const QFont& font)
{
    font_ = font;
    notifyChanged();
}

QFont QLegend::font() const
{
    return font_;
}

QChart::QChart(QObject* parent)
    : KsPainterChartObject(parent)
    , legend_(new QLegend(this))
{
    legend_->setChangeHandler([this]() { notifyChanged(); });
}

void QChart::addSeries(QAbstractSeries* series)
{
    if (series == nullptr || series_.contains(series))
    {
        return;
    }
    series_.append(series);
    if (series->parent() == nullptr)
    {
        series->setParent(this);
    }
    attachSeriesHandlers(series);
    QObject::connect(series, &QObject::destroyed, this, [this, series]() {
        series_.removeAll(series);
        notifyChanged();
    });
    notifyChanged();
}

QList<QAbstractSeries*> QChart::series() const
{
    return series_;
}

void QChart::addAxis(QAbstractAxis* axis, const Qt::Alignment alignment)
{
    if (axis == nullptr)
    {
        return;
    }
    if (!axes_.contains(axis))
    {
        axes_.append(axis);
        if (axis->parent() == nullptr)
        {
            axis->setParent(this);
        }
        axis->setChangeHandler([this]() { notifyChanged(); });
        QObject::connect(axis, &QObject::destroyed, this, [this, axis]() {
            axes_.removeAll(axis);
            notifyChanged();
        });
    }
    axis->setAlignment(alignment);
    notifyChanged();
}

QList<QAbstractAxis*> QChart::axes() const
{
    return axes_;
}

QLegend* QChart::legend() const
{
    return legend_;
}

void QChart::setTitle(const QString& title)
{
    title_ = title;
    notifyChanged();
}

QString QChart::title() const
{
    return title_;
}

void QChart::setTitleBrush(const QBrush& brush)
{
    titleBrush_ = brush;
    notifyChanged();
}

QBrush QChart::titleBrush() const
{
    return titleBrush_;
}

void QChart::setTitleFont(const QFont& font)
{
    titleFont_ = font;
    notifyChanged();
}

QFont QChart::titleFont() const
{
    return titleFont_;
}

void QChart::setBackgroundVisible(const bool visible)
{
    backgroundVisible_ = visible;
    notifyChanged();
}

bool QChart::isBackgroundVisible() const
{
    return backgroundVisible_;
}

void QChart::setBackgroundRoundness(const qreal roundness)
{
    backgroundRoundness_ = std::max<qreal>(0.0, roundness);
    notifyChanged();
}

qreal QChart::backgroundRoundness() const
{
    return backgroundRoundness_;
}

void QChart::setBackgroundBrush(const QBrush& brush)
{
    backgroundBrush_ = brush;
    notifyChanged();
}

QBrush QChart::backgroundBrush() const
{
    return backgroundBrush_;
}

void QChart::setMargins(const QMargins& margins)
{
    margins_ = margins;
    notifyChanged();
}

QMargins QChart::margins() const
{
    return margins_;
}

void QChart::setPlotAreaBackgroundVisible(const bool visible)
{
    plotAreaBackgroundVisible_ = visible;
    notifyChanged();
}

bool QChart::isPlotAreaBackgroundVisible() const
{
    return plotAreaBackgroundVisible_;
}

void QChart::setPlotAreaBackgroundBrush(const QBrush& brush)
{
    plotAreaBackgroundBrush_ = brush;
    notifyChanged();
}

QBrush QChart::plotAreaBackgroundBrush() const
{
    return plotAreaBackgroundBrush_;
}

void QChart::setPlotAreaBackgroundPen(const QPen& pen)
{
    plotAreaBackgroundPen_ = pen;
    notifyChanged();
}

QPen QChart::plotAreaBackgroundPen() const
{
    return plotAreaBackgroundPen_;
}

void QChart::setAnimationOptions(const AnimationOption options)
{
    animationOptions_ = options;
    notifyChanged();
}

QChart::AnimationOption QChart::animationOptions() const
{
    return animationOptions_;
}

void QChart::setAnimationDuration(const int durationMs)
{
    animationDurationMs_ = std::max(0, durationMs);
    notifyChanged();
}

int QChart::animationDuration() const
{
    return animationDurationMs_;
}

void QChart::setAnimationEasingCurve(const QEasingCurve& easingCurve)
{
    animationEasingCurve_ = easingCurve;
    notifyChanged();
}

QEasingCurve QChart::animationEasingCurve() const
{
    return animationEasingCurve_;
}

void QChart::update()
{
    notifyChanged();
}

void QChart::attachSeriesHandlers(QAbstractSeries* series)
{
    if (series == nullptr)
    {
        return;
    }
    series->setChangeHandler([this]() { notifyChanged(); });

    if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(series))
    {
        if (areaSeries->upperSeries() != nullptr)
        {
            areaSeries->upperSeries()->setChangeHandler([this]() { notifyChanged(); });
        }
        if (areaSeries->lowerSeries() != nullptr)
        {
            areaSeries->lowerSeries()->setChangeHandler([this]() { notifyChanged(); });
        }
    }
    else if (QBarSeries* barSeries = dynamic_cast<QBarSeries*>(series))
    {
        for (QBarSet* set : barSeries->barSets())
        {
            if (set != nullptr)
            {
                set->setChangeHandler([this]() { notifyChanged(); });
            }
        }
    }
}

QChartView::QChartView(QChart* chart, QWidget* parent)
    : QFrame(parent)
    , chart_(chart)
    , animation_(new QVariantAnimation(this))
{
    setAutoFillBackground(false);
    setAttribute(Qt::WA_OpaquePaintEvent, false);
    if (chart_ != nullptr)
    {
        if (chart_->parent() == nullptr)
        {
            chart_->setParent(this);
        }
        chart_->setChangeHandler([this]() { scheduleModelUpdate(); });
    }

    animation_->setStartValue(0.0);
    animation_->setEndValue(1.0);
    QObject::connect(
        animation_,
        &QVariantAnimation::valueChanged,
        this,
        [this](const QVariant& progressValue) {
            animationProgress_ = progressValue.toReal();
            QFrame::update();
        });
    QObject::connect(
        animation_,
        &QVariantAnimation::finished,
        this,
        [this]() {
            animationProgress_ = 1.0;
            displayedLinePoints_ = toLinePoints_;
            displayedBarValues_ = toBarValues_;
            displayedAxisRanges_ = toAxisRanges_;
            QFrame::update();
        });

    syncSnapshotsToCurrent();
}

QChartView::~QChartView()
{
    if (chart_ != nullptr)
    {
        chart_->setChangeHandler({});
    }
}

QChart* QChartView::chart() const
{
    return chart_;
}

QWidget* QChartView::viewport()
{
    return this;
}

const QWidget* QChartView::viewport() const
{
    return this;
}

void QChartView::setRenderHint(const QPainter::RenderHint hint, const bool enabled)
{
    if (hint == QPainter::Antialiasing)
    {
        antialiasingEnabled_ = enabled;
        QFrame::update();
    }
}

void QChartView::setHorizontalScrollBarPolicy(const Qt::ScrollBarPolicy policy)
{
    Q_UNUSED(policy);
}

void QChartView::setVerticalScrollBarPolicy(const Qt::ScrollBarPolicy policy)
{
    Q_UNUSED(policy);
}

void QChartView::setSizeAdjustPolicy(const QAbstractScrollArea::SizeAdjustPolicy policy)
{
    Q_UNUSED(policy);
}

void QChartView::setBackgroundBrush(const QBrush& brush)
{
    viewBackgroundBrush_ = brush;
    QFrame::update();
}

QSize QChartView::sizeHint() const
{
    return QSize(240, 150);
}

void QChartView::showEvent(QShowEvent* event)
{
    QFrame::showEvent(event);
    if (animation_ == nullptr || animation_->state() != QAbstractAnimation::Running)
    {
        syncSnapshotsToCurrent();
    }
}

void QChartView::scheduleModelUpdate()
{
    if (updateScheduled_)
    {
        return;
    }
    updateScheduled_ = true;
    QTimer::singleShot(0, this, [this]() { applyPendingModelUpdate(); });
}

void QChartView::applyPendingModelUpdate()
{
    updateScheduled_ = false;
    if (chart_ == nullptr)
    {
        QFrame::update();
        return;
    }
    if (chart_->animationOptions() == QChart::kNoAnimation || chart_->animationDuration() <= 0)
    {
        if (animation_->state() == QAbstractAnimation::Running)
        {
            animation_->stop();
        }
        syncSnapshotsToCurrent();
        QFrame::update();
        return;
    }
    startModelAnimation();
}

void QChartView::startModelAnimation()
{
    if (chart_ == nullptr)
    {
        return;
    }

    if (animation_->state() == QAbstractAnimation::Running)
    {
        captureCurrentFrameAsDisplayed();
    }

    const LinePointMap kTargetLinePoints = currentLinePoints();
    const BarValueMap kTargetBarValues = currentBarValues();
    const AxisRangeMap kTargetAxisRanges = currentAxisRanges();
    if (displayedLinePoints_.isEmpty()
        && displayedBarValues_.isEmpty()
        && displayedAxisRanges_.isEmpty())
    {
        syncSnapshotsToCurrent();
        QFrame::update();
        return;
    }

    const int kOptionBits = static_cast<int>(chart_->animationOptions());
    const bool kAnimateSeries = (kOptionBits & static_cast<int>(QChart::kSeriesAnimations)) != 0;
    const bool kAnimateAxes = (kOptionBits & static_cast<int>(QChart::kGridAxisAnimations)) != 0;

    if (!kAnimateSeries)
    {
        displayedLinePoints_ = kTargetLinePoints;
        displayedBarValues_ = kTargetBarValues;
    }
    if (!kAnimateAxes)
    {
        displayedAxisRanges_ = kTargetAxisRanges;
    }

    fromLinePoints_.clear();
    toLinePoints_ = kTargetLinePoints;
    for (auto iterator = kTargetLinePoints.constBegin(); iterator != kTargetLinePoints.constEnd(); ++iterator)
    {
        fromLinePoints_.insert(
            iterator.key(),
            displayedLinePoints_.value(iterator.key(), iterator.value()));
    }

    fromBarValues_.clear();
    toBarValues_ = kTargetBarValues;
    for (auto iterator = kTargetBarValues.constBegin(); iterator != kTargetBarValues.constEnd(); ++iterator)
    {
        fromBarValues_.insert(
            iterator.key(),
            displayedBarValues_.value(iterator.key(), iterator.value()));
    }

    fromAxisRanges_.clear();
    toAxisRanges_ = kTargetAxisRanges;
    for (auto iterator = kTargetAxisRanges.constBegin(); iterator != kTargetAxisRanges.constEnd(); ++iterator)
    {
        fromAxisRanges_.insert(
            iterator.key(),
            displayedAxisRanges_.value(iterator.key(), iterator.value()));
    }

    const bool kSeriesChanged = kAnimateSeries
        && (fromLinePoints_ != toLinePoints_ || fromBarValues_ != toBarValues_);
    const bool kAxesChanged = kAnimateAxes && fromAxisRanges_ != toAxisRanges_;
    if (!kSeriesChanged && !kAxesChanged)
    {
        syncSnapshotsToCurrent();
        QFrame::update();
        return;
    }

    animationProgress_ = 0.0;
    animation_->setDuration(chart_->animationDuration());
    animation_->setEasingCurve(chart_->animationEasingCurve());
    animation_->setStartValue(0.0);
    animation_->setEndValue(1.0);
    animation_->start();
}

void QChartView::syncSnapshotsToCurrent()
{
    displayedLinePoints_ = currentLinePoints();
    displayedBarValues_ = currentBarValues();
    displayedAxisRanges_ = currentAxisRanges();
    fromLinePoints_ = displayedLinePoints_;
    toLinePoints_ = displayedLinePoints_;
    fromBarValues_ = displayedBarValues_;
    toBarValues_ = displayedBarValues_;
    fromAxisRanges_ = displayedAxisRanges_;
    toAxisRanges_ = displayedAxisRanges_;
    animationProgress_ = 1.0;
}

void QChartView::captureCurrentFrameAsDisplayed()
{
    LinePointMap frameLinePoints;
    for (auto iterator = toLinePoints_.constBegin(); iterator != toLinePoints_.constEnd(); ++iterator)
    {
        frameLinePoints.insert(iterator.key(), renderedPoints(iterator.key()));
    }
    BarValueMap frameBarValues;
    for (auto iterator = toBarValues_.constBegin(); iterator != toBarValues_.constEnd(); ++iterator)
    {
        frameBarValues.insert(iterator.key(), renderedBarValues(iterator.key()));
    }
    AxisRangeMap frameAxisRanges;
    for (auto iterator = toAxisRanges_.constBegin(); iterator != toAxisRanges_.constEnd(); ++iterator)
    {
        frameAxisRanges.insert(iterator.key(), renderedAxisRange(iterator.key()));
    }
    animation_->stop();
    displayedLinePoints_ = frameLinePoints;
    displayedBarValues_ = frameBarValues;
    displayedAxisRanges_ = frameAxisRanges;
    animationProgress_ = 1.0;
}

QChartView::LinePointMap QChartView::currentLinePoints() const
{
    LinePointMap result;
    if (chart_ == nullptr)
    {
        return result;
    }
    QSet<const QLineSeries*> visitedSeries;
    const auto kAddLineSeries = [&result, &visitedSeries](const QLineSeries* lineSeries) {
        if (lineSeries != nullptr && !visitedSeries.contains(lineSeries))
        {
            visitedSeries.insert(lineSeries);
            result.insert(lineSeries, lineSeries->points());
        }
    };
    for (QAbstractSeries* abstractSeries : chart_->series())
    {
        if (QLineSeries* lineSeries = dynamic_cast<QLineSeries*>(abstractSeries))
        {
            kAddLineSeries(lineSeries);
        }
        else if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(abstractSeries))
        {
            kAddLineSeries(areaSeries->upperSeries());
            kAddLineSeries(areaSeries->lowerSeries());
        }
    }
    return result;
}

QChartView::BarValueMap QChartView::currentBarValues() const
{
    BarValueMap result;
    if (chart_ == nullptr)
    {
        return result;
    }
    for (QAbstractSeries* abstractSeries : chart_->series())
    {
        QBarSeries* barSeries = dynamic_cast<QBarSeries*>(abstractSeries);
        if (barSeries == nullptr)
        {
            continue;
        }
        for (QBarSet* set : barSeries->barSets())
        {
            if (set != nullptr)
            {
                result.insert(set, set->values());
            }
        }
    }
    return result;
}

QChartView::AxisRangeMap QChartView::currentAxisRanges() const
{
    AxisRangeMap result;
    if (chart_ == nullptr)
    {
        return result;
    }
    for (QAbstractAxis* abstractAxis : chart_->axes())
    {
        if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(abstractAxis))
        {
            result.insert(valueAxis, qMakePair(valueAxis->min(), valueAxis->max()));
        }
    }
    return result;
}

QList<QPointF> QChartView::renderedPoints(const QLineSeries* series) const
{
    if (series == nullptr)
    {
        return {};
    }
    const int kOptionBits = chart_ != nullptr
        ? static_cast<int>(chart_->animationOptions())
        : 0;
    const bool kAnimateSeries = (kOptionBits & static_cast<int>(QChart::kSeriesAnimations)) != 0;
    if (kAnimateSeries && animation_->state() == QAbstractAnimation::Running)
    {
        return interpolatePointLists(
            fromLinePoints_.value(series, series->points()),
            toLinePoints_.value(series, series->points()),
            animationProgress_);
    }
    return displayedLinePoints_.value(series, series->points());
}

QVector<qreal> QChartView::renderedBarValues(const QBarSet* set) const
{
    if (set == nullptr)
    {
        return {};
    }
    const int kOptionBits = chart_ != nullptr
        ? static_cast<int>(chart_->animationOptions())
        : 0;
    const bool kAnimateSeries = (kOptionBits & static_cast<int>(QChart::kSeriesAnimations)) != 0;
    if (kAnimateSeries && animation_->state() == QAbstractAnimation::Running)
    {
        return interpolateBarValues(
            fromBarValues_.value(set, set->values()),
            toBarValues_.value(set, set->values()),
            animationProgress_);
    }
    return displayedBarValues_.value(set, set->values());
}

QPair<qreal, qreal> QChartView::renderedAxisRange(const QValueAxis* axis) const
{
    if (axis == nullptr)
    {
        return qMakePair(0.0, 1.0);
    }
    const QPair<qreal, qreal> kCurrentRange(axis->min(), axis->max());
    const int kOptionBits = chart_ != nullptr
        ? static_cast<int>(chart_->animationOptions())
        : 0;
    const bool kAnimateAxes = (kOptionBits & static_cast<int>(QChart::kGridAxisAnimations)) != 0;
    if (kAnimateAxes && animation_->state() == QAbstractAnimation::Running)
    {
        const QPair<qreal, qreal> kFromRange = fromAxisRanges_.value(axis, kCurrentRange);
        const QPair<qreal, qreal> kToRange = toAxisRanges_.value(axis, kCurrentRange);
        return qMakePair(
            interpolateValue(kFromRange.first, kToRange.first, animationProgress_),
            interpolateValue(kFromRange.second, kToRange.second, animationProgress_));
    }
    return displayedAxisRanges_.value(axis, kCurrentRange);
}

void QChartView::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, antialiasingEnabled_);
    painter.setRenderHint(QPainter::TextAntialiasing, true);

    if (viewBackgroundBrush_.style() != Qt::NoBrush)
    {
        painter.fillRect(rect(), viewBackgroundBrush_);
    }
    if (chart_ == nullptr)
    {
        return;
    }

    const QMargins kMargins = chart_->margins();
    QRectF contentRect = QRectF(rect()).adjusted(
        1.0 + kMargins.left(),
        1.0 + kMargins.top(),
        -1.0 - kMargins.right(),
        -1.0 - kMargins.bottom());
    if (contentRect.width() <= 2.0 || contentRect.height() <= 2.0)
    {
        return;
    }

    if (chart_->isBackgroundVisible())
    {
        const QBrush kBackgroundBrush = chart_->backgroundBrush().style() == Qt::NoBrush
            ? palette().brush(QPalette::Base)
            : chart_->backgroundBrush();
        painter.setPen(Qt::NoPen);
        painter.setBrush(kBackgroundBrush);
        painter.drawRoundedRect(
            contentRect,
            chart_->backgroundRoundness(),
            chart_->backgroundRoundness());
    }

    QFont titleFont = chart_->titleFont();
    if (titleFont.family().isEmpty())
    {
        titleFont = font();
    }
    if (!chart_->title().isEmpty())
    {
        painter.setFont(titleFont);
        const QFontMetricsF kTitleMetrics(titleFont);
        const qreal kTitleHeight = std::min<qreal>(
            std::max<qreal>(16.0, kTitleMetrics.height() + 2.0),
            std::max<qreal>(16.0, contentRect.height() * 0.28));
        const QRectF kTitleRect(contentRect.left(), contentRect.top(), contentRect.width(), kTitleHeight);
        painter.setPen(brushColorOr(chart_->titleBrush(), palette().color(QPalette::WindowText)));
        painter.drawText(
            kTitleRect,
            Qt::AlignHCenter | Qt::AlignVCenter,
            kTitleMetrics.elidedText(chart_->title(), Qt::ElideRight, kTitleRect.width()));
        contentRect.setTop(kTitleRect.bottom());
    }

    struct LegendEntry
    {
        QString name;
        QColor color;
    };
    QList<LegendEntry> legendEntries;
    QSet<QString> legendNames;
    for (QAbstractSeries* abstractSeries : chart_->series())
    {
        QString entryName = abstractSeries != nullptr ? abstractSeries->name() : QString();
        QColor entryColor = palette().color(QPalette::Highlight);
        if (QLineSeries* lineSeries = dynamic_cast<QLineSeries*>(abstractSeries))
        {
            entryColor = lineSeries->pen().color();
        }
        else if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(abstractSeries))
        {
            entryColor = areaSeries->pen().color();
        }
        else if (QBarSeries* barSeries = dynamic_cast<QBarSeries*>(abstractSeries))
        {
            if (!barSeries->barSets().isEmpty() && barSeries->barSets().first() != nullptr)
            {
                entryColor = barSeries->barSets().first()->color();
            }
        }
        if (!entryName.isEmpty() && !legendNames.contains(entryName))
        {
            legendNames.insert(entryName);
            legendEntries.append({ entryName, entryColor });
        }
    }

    QRectF legendRect;
    if (chart_->legend()->isVisible() && !legendEntries.isEmpty())
    {
        QFont legendFont = chart_->legend()->font();
        if (legendFont.family().isEmpty())
        {
            legendFont = font();
        }
        const qreal kLegendHeight = std::min<qreal>(20.0, std::max<qreal>(14.0, QFontMetricsF(legendFont).height() + 2.0));
        if (chart_->legend()->alignment().testFlag(Qt::AlignBottom))
        {
            legendRect = QRectF(contentRect.left(), contentRect.bottom() - kLegendHeight, contentRect.width(), kLegendHeight);
            contentRect.setBottom(legendRect.top());
        }
        else
        {
            legendRect = QRectF(contentRect.left(), contentRect.top(), contentRect.width(), kLegendHeight);
            contentRect.setTop(legendRect.bottom());
        }
    }

    QAbstractAxis* horizontalAxis = nullptr;
    QAbstractAxis* verticalAxis = nullptr;
    for (QAbstractAxis* axis : chart_->axes())
    {
        if (axis == nullptr)
        {
            continue;
        }
        if (isHorizontalAlignment(axis->alignment()) && horizontalAxis == nullptr)
        {
            horizontalAxis = axis;
        }
        else if (!isHorizontalAlignment(axis->alignment()) && verticalAxis == nullptr)
        {
            verticalAxis = axis;
        }
    }

    const qreal kLeftReserve = verticalAxis != nullptr && verticalAxis->labelsVisible() ? 42.0 : 3.0;
    const qreal kBottomReserve = horizontalAxis != nullptr && horizontalAxis->labelsVisible() ? 18.0 : 3.0;
    const qreal kLeftTitleReserve = verticalAxis != nullptr && !verticalAxis->titleText().isEmpty() ? 13.0 : 0.0;
    const qreal kBottomTitleReserve = horizontalAxis != nullptr && !horizontalAxis->titleText().isEmpty() ? 14.0 : 0.0;
    QRectF plotRect = contentRect.adjusted(
        kLeftReserve + kLeftTitleReserve,
        2.0,
        -3.0,
        -kBottomReserve - kBottomTitleReserve);
    if (plotRect.width() <= 3.0 || plotRect.height() <= 3.0)
    {
        return;
    }

    if (chart_->isPlotAreaBackgroundVisible())
    {
        painter.setPen(chart_->plotAreaBackgroundPen());
        painter.setBrush(chart_->plotAreaBackgroundBrush());
        painter.drawRect(plotRect);
    }

    QPair<qreal, qreal> defaultXRange(0.0, 1.0);
    QPair<qreal, qreal> defaultYRange(0.0, 1.0);
    if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(horizontalAxis))
    {
        defaultXRange = renderedAxisRange(valueAxis);
    }
    else if (QBarCategoryAxis* categoryAxis = dynamic_cast<QBarCategoryAxis*>(horizontalAxis))
    {
        const int kCategoryCount = std::max(
            1, static_cast<int>(categoryAxis->categories().size()));
        defaultXRange = qMakePair(-0.5, static_cast<qreal>(kCategoryCount) - 0.5);
    }
    if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(verticalAxis))
    {
        defaultYRange = renderedAxisRange(valueAxis);
    }

    if (verticalAxis != nullptr && verticalAxis->isGridLineVisible())
    {
        painter.setPen(verticalAxis->gridLinePen());
        for (int gridIndex = 0; gridIndex <= 4; ++gridIndex)
        {
            const qreal kY = plotRect.bottom() - plotRect.height() * static_cast<qreal>(gridIndex) / 4.0;
            painter.drawLine(QPointF(plotRect.left(), kY), QPointF(plotRect.right(), kY));
        }
    }
    if (horizontalAxis != nullptr && horizontalAxis->isGridLineVisible())
    {
        painter.setPen(horizontalAxis->gridLinePen());
        for (int gridIndex = 0; gridIndex <= 4; ++gridIndex)
        {
            const qreal kX = plotRect.left() + plotRect.width() * static_cast<qreal>(gridIndex) / 4.0;
            painter.drawLine(QPointF(kX, plotRect.top()), QPointF(kX, plotRect.bottom()));
        }
    }

    if (verticalAxis != nullptr && verticalAxis->isLineVisible())
    {
        painter.setPen(verticalAxis->linePen());
        painter.drawLine(plotRect.topLeft(), plotRect.bottomLeft());
    }
    if (horizontalAxis != nullptr && horizontalAxis->isLineVisible())
    {
        painter.setPen(horizontalAxis->linePen());
        painter.drawLine(plotRect.bottomLeft(), plotRect.bottomRight());
    }

    QFont axisFont = font();
    axisFont.setPointSizeF(std::max<qreal>(7.0, axisFont.pointSizeF() - 1.0));
    painter.setFont(axisFont);
    if (verticalAxis != nullptr && verticalAxis->labelsVisible())
    {
        painter.setPen(brushColorOr(verticalAxis->labelsBrush(), palette().color(QPalette::Text)));
        QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(verticalAxis);
        for (int labelIndex = 0; labelIndex <= 4; ++labelIndex)
        {
            const qreal kRatio = static_cast<qreal>(labelIndex) / 4.0;
            const qreal kValue = defaultYRange.first + (defaultYRange.second - defaultYRange.first) * kRatio;
            const qreal kY = plotRect.bottom() - plotRect.height() * kRatio;
            painter.drawText(
                QRectF(contentRect.left() + kLeftTitleReserve, kY - 8.0, kLeftReserve - 4.0, 16.0),
                Qt::AlignRight | Qt::AlignVCenter,
                formatAxisValue(valueAxis, kValue));
        }
    }
    if (horizontalAxis != nullptr && horizontalAxis->labelsVisible())
    {
        painter.setPen(brushColorOr(horizontalAxis->labelsBrush(), palette().color(QPalette::Text)));
        if (QBarCategoryAxis* categoryAxis = dynamic_cast<QBarCategoryAxis*>(horizontalAxis))
        {
            const QStringList kCategories = categoryAxis->categories();
            const int kCategoryCount = kCategories.size();
            const int kLabelStep = std::max(1, (kCategoryCount + 11) / 12);
            for (int categoryIndex = 0; categoryIndex < kCategoryCount; categoryIndex += kLabelStep)
            {
                const qreal kSlotWidth = plotRect.width() / std::max(1, kCategoryCount);
                const QRectF kLabelRect(
                    plotRect.left() + kSlotWidth * categoryIndex,
                    plotRect.bottom(),
                    kSlotWidth * kLabelStep,
                    kBottomReserve);
                painter.drawText(kLabelRect, Qt::AlignHCenter | Qt::AlignTop, kCategories.at(categoryIndex));
            }
        }
        else if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(horizontalAxis))
        {
            for (int labelIndex = 0; labelIndex <= 4; ++labelIndex)
            {
                const qreal kRatio = static_cast<qreal>(labelIndex) / 4.0;
                const qreal kValue = defaultXRange.first + (defaultXRange.second - defaultXRange.first) * kRatio;
                const qreal kX = plotRect.left() + plotRect.width() * kRatio;
                painter.drawText(
                    QRectF(kX - 28.0, plotRect.bottom(), 56.0, kBottomReserve),
                    Qt::AlignHCenter | Qt::AlignTop,
                    formatAxisValue(valueAxis, kValue));
            }
        }
    }

    if (verticalAxis != nullptr && !verticalAxis->titleText().isEmpty())
    {
        painter.save();
        painter.setPen(brushColorOr(verticalAxis->titleBrush(), palette().color(QPalette::Text)));
        painter.translate(contentRect.left() + 7.0, plotRect.center().y());
        painter.rotate(-90.0);
        painter.drawText(
            QRectF(-plotRect.height() / 2.0, -7.0, plotRect.height(), 14.0),
            Qt::AlignCenter,
            verticalAxis->titleText());
        painter.restore();
    }
    if (horizontalAxis != nullptr && !horizontalAxis->titleText().isEmpty())
    {
        painter.setPen(brushColorOr(horizontalAxis->titleBrush(), palette().color(QPalette::Text)));
        painter.drawText(
            QRectF(plotRect.left(), contentRect.bottom() - kBottomTitleReserve, plotRect.width(), kBottomTitleReserve),
            Qt::AlignCenter,
            horizontalAxis->titleText());
    }

    const auto kSeriesAxis = [this](QAbstractSeries* series, const bool horizontal) -> QAbstractAxis* {
        if (series != nullptr)
        {
            for (QAbstractAxis* axis : series->attachedAxes())
            {
                if (axis != nullptr && isHorizontalAlignment(axis->alignment()) == horizontal)
                {
                    return axis;
                }
            }
        }
        for (QAbstractAxis* axis : chart_->axes())
        {
            if (axis != nullptr && isHorizontalAlignment(axis->alignment()) == horizontal)
            {
                return axis;
            }
        }
        return nullptr;
    };
    const auto kAxisRange = [this](QAbstractAxis* axis, const bool horizontal) {
        if (QValueAxis* valueAxis = dynamic_cast<QValueAxis*>(axis))
        {
            return renderedAxisRange(valueAxis);
        }
        if (QBarCategoryAxis* categoryAxis = dynamic_cast<QBarCategoryAxis*>(axis))
        {
            const int kCount = std::max(
                1, static_cast<int>(categoryAxis->categories().size()));
            return qMakePair(-0.5, static_cast<qreal>(kCount) - 0.5);
        }
        return horizontal ? qMakePair(0.0, 1.0) : qMakePair(0.0, 1.0);
    };

    painter.save();
    painter.setClipRect(plotRect.adjusted(-1.0, -1.0, 1.0, 1.0));
    for (QAbstractSeries* abstractSeries : chart_->series())
    {
        if (abstractSeries == nullptr)
        {
            continue;
        }

        QAbstractAxis* xAxis = kSeriesAxis(abstractSeries, true);
        QAbstractAxis* yAxis = kSeriesAxis(abstractSeries, false);
        const QPair<qreal, qreal> kXRange = kAxisRange(xAxis, true);
        const QPair<qreal, qreal> kYRange = kAxisRange(yAxis, false);

        if (QAreaSeries* areaSeries = dynamic_cast<QAreaSeries*>(abstractSeries))
        {
            const QList<QPointF> kUpperPoints = renderedPoints(areaSeries->upperSeries());
            QList<QPointF> lowerPoints = renderedPoints(areaSeries->lowerSeries());
            if (lowerPoints.isEmpty())
            {
                lowerPoints.reserve(kUpperPoints.size());
                for (const QPointF& upperPoint : kUpperPoints)
                {
                    lowerPoints.append(QPointF(upperPoint.x(), 0.0));
                }
            }
            const int kPointCount = std::min(
                static_cast<int>(kUpperPoints.size()),
                static_cast<int>(lowerPoints.size()));
            if (kPointCount > 0)
            {
                QPainterPath fillPath;
                QPainterPath borderPath;
                for (int pointIndex = 0; pointIndex < kPointCount; ++pointIndex)
                {
                    const QPointF kMappedPoint = mapChartPoint(kUpperPoints.at(pointIndex), plotRect, kXRange, kYRange);
                    if (pointIndex == 0)
                    {
                        fillPath.moveTo(kMappedPoint);
                        borderPath.moveTo(kMappedPoint);
                    }
                    else
                    {
                        fillPath.lineTo(kMappedPoint);
                        borderPath.lineTo(kMappedPoint);
                    }
                }
                for (int pointIndex = kPointCount - 1; pointIndex >= 0; --pointIndex)
                {
                    fillPath.lineTo(mapChartPoint(lowerPoints.at(pointIndex), plotRect, kXRange, kYRange));
                }
                fillPath.closeSubpath();
                painter.fillPath(fillPath, areaSeries->brush());
                if (areaSeries->pen().style() != Qt::NoPen
                    && areaSeries->pen().color().alpha() > 0)
                {
                    painter.setPen(areaSeries->pen());
                    painter.setBrush(Qt::NoBrush);
                    painter.drawPath(borderPath);
                }
            }
            continue;
        }

        if (QLineSeries* lineSeries = dynamic_cast<QLineSeries*>(abstractSeries))
        {
            const QList<QPointF> kPoints = renderedPoints(lineSeries);
            if (!kPoints.isEmpty() && lineSeries->pen().style() != Qt::NoPen
                && lineSeries->pen().color().alpha() > 0)
            {
                QPainterPath linePath;
                for (int pointIndex = 0; pointIndex < kPoints.size(); ++pointIndex)
                {
                    const QPointF kMappedPoint = mapChartPoint(kPoints.at(pointIndex), plotRect, kXRange, kYRange);
                    if (pointIndex == 0)
                    {
                        linePath.moveTo(kMappedPoint);
                    }
                    else
                    {
                        linePath.lineTo(kMappedPoint);
                    }
                }
                painter.setPen(lineSeries->pen());
                painter.setBrush(Qt::NoBrush);
                painter.drawPath(linePath);
            }
            continue;
        }

        if (QBarSeries* barSeries = dynamic_cast<QBarSeries*>(abstractSeries))
        {
            const QList<QBarSet*> kSets = barSeries->barSets();
            int maximumValueCount = 0;
            for (QBarSet* set : kSets)
            {
                maximumValueCount = std::max(
                    maximumValueCount,
                    static_cast<int>(renderedBarValues(set).size()));
            }
            const bool kSetsAreCategories = maximumValueCount <= 1 && kSets.size() > 1;
            const int kCategoryCount = kSetsAreCategories
                ? static_cast<int>(kSets.size())
                : std::max(1, maximumValueCount);
            const int kBarsPerCategory = kSetsAreCategories
                ? 1
                : std::max(1, static_cast<int>(kSets.size()));
            const qreal kSlotWidth = plotRect.width() / std::max(1, kCategoryCount);
            const qreal kGroupWidth = kSlotWidth * 0.78;
            const qreal kBarWidth = kGroupWidth / kBarsPerCategory;
            const qreal kBaselineY = mapChartPoint(QPointF(0.0, 0.0), plotRect, kXRange, kYRange).y();

            for (int setIndex = 0; setIndex < kSets.size(); ++setIndex)
            {
                QBarSet* set = kSets.at(setIndex);
                if (set == nullptr)
                {
                    continue;
                }
                const QVector<qreal> kValues = renderedBarValues(set);
                const int kValueCount = kSetsAreCategories
                    ? std::min(1, static_cast<int>(kValues.size()))
                    : static_cast<int>(kValues.size());
                for (int valueIndex = 0; valueIndex < kValueCount; ++valueIndex)
                {
                    const int kCategoryIndex = kSetsAreCategories ? setIndex : valueIndex;
                    const int kGroupBarIndex = kSetsAreCategories ? 0 : setIndex;
                    const qreal kGroupLeft = plotRect.left()
                        + kSlotWidth * kCategoryIndex
                        + (kSlotWidth - kGroupWidth) / 2.0;
                    const qreal kBarLeft = kGroupLeft + kBarWidth * kGroupBarIndex;
                    const qreal kValueY = mapChartPoint(
                        QPointF(kCategoryIndex, kValues.at(valueIndex)),
                        plotRect,
                        kXRange,
                        kYRange).y();
                    const QRectF kBarRect(
                        kBarLeft + 0.5,
                        std::min(kValueY, kBaselineY),
                        std::max<qreal>(1.0, kBarWidth - 1.0),
                        std::max<qreal>(0.5, std::abs(kBaselineY - kValueY)));
                    painter.setBrush(set->brush());
                    painter.setPen(set->borderColor().alpha() > 0
                        ? QPen(set->borderColor(), 0.8)
                        : QPen(Qt::NoPen));
                    painter.drawRect(kBarRect);
                }
            }
        }
    }
    painter.restore();

    if (!legendRect.isEmpty())
    {
        QFont legendFont = chart_->legend()->font();
        if (legendFont.family().isEmpty())
        {
            legendFont = font();
        }
        painter.setFont(legendFont);
        painter.setPen(brushColorOr(chart_->legend()->labelBrush(), palette().color(QPalette::Text)));
        const QFontMetricsF kLegendMetrics(legendFont);
        qreal totalWidth = 0.0;
        for (const LegendEntry& entry : legendEntries)
        {
            totalWidth += 13.0 + kLegendMetrics.horizontalAdvance(entry.name) + 12.0;
        }
        qreal currentX = legendRect.left() + std::max<qreal>(0.0, (legendRect.width() - totalWidth) / 2.0);
        for (const LegendEntry& entry : legendEntries)
        {
            const qreal kTextWidth = kLegendMetrics.horizontalAdvance(entry.name);
            painter.fillRect(
                QRectF(currentX, legendRect.center().y() - 3.0, 8.0, 6.0),
                entry.color);
            painter.drawText(
                QRectF(currentX + 11.0, legendRect.top(), kTextWidth, legendRect.height()),
                Qt::AlignLeft | Qt::AlignVCenter,
                entry.name);
            currentX += 13.0 + kTextWidth + 12.0;
            if (currentX > legendRect.right())
            {
                break;
            }
        }
    }
}

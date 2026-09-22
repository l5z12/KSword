#include "SmoothScrollSupport.h"

#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QApplication>
#include <QEasingCurve>
#include <QEvent>
#include <QHash>
#include <QPointer>
#include <QPropertyAnimation>
#include <QScrollBar>
#include <QVariant>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>
#include <utility>

namespace
{
    constexpr char kInstalledProperty[] = "KSWORD_SMOOTH_SCROLL_SUPPORT_INSTALLED";
    constexpr char kEnabledProperty[] = "ksword_smooth_scrolling_enabled";
    constexpr char kOriginalVerticalModeProperty[] =
        "KSWORD_SMOOTH_SCROLL_ORIGINAL_VERTICAL_MODE";
    constexpr char kOriginalHorizontalModeProperty[] =
        "KSWORD_SMOOTH_SCROLL_ORIGINAL_HORIZONTAL_MODE";
    constexpr char kFrozenPaneAuxiliaryProperty[] =
        "KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY";
    constexpr int kWheelAnimationDurationMs = 180;
    constexpr int kPixelAnimationDurationMs = 100;

    class GlobalSmoothScrollFilter;
    QPointer<GlobalSmoothScrollFilter> gInstalledFilter;

    class GlobalSmoothScrollFilter final : public QObject
    {
    public:
        explicit GlobalSmoothScrollFilter(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        void applyEnabledStateToAllWidgets(const bool enabled)
        {
            const QWidgetList kWidgetList = QApplication::allWidgets();
            for (QWidget* widget : kWidgetList)
            {
                QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(widget);
                if (scrollArea != nullptr &&
                    !scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
                {
                    configureScrollArea(scrollArea, enabled);
                }
            }
            // The frozen overlay view must synchronize after the main table switches scroll modes to prevent unit inconsistency when smooth scrolling is disabled.
            for (QWidget* widget : kWidgetList)
            {
                QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(widget);
                if (scrollArea != nullptr &&
                    scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
                {
                    configureScrollArea(scrollArea, enabled);
                }
            }
            if (!enabled)
            {
                stopAllAnimations();
            }
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() == QEvent::Show ||
                eventObject->type() == QEvent::Polish)
            {
                if (QAbstractScrollArea* scrollArea =
                    qobject_cast<QAbstractScrollArea*>(watchedObject))
                {
                    configureScrollArea(scrollArea, enabled());
                }
            }

            if (eventObject->type() != QEvent::Wheel || !enabled())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QAbstractScrollArea* scrollArea = scrollAreaForEventObject(watchedObject);
            if (scrollArea == nullptr ||
                scrollArea->property(kFrozenPaneAuxiliaryProperty).toBool())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            auto* wheelEvent = static_cast<QWheelEvent*>(eventObject);
            if (wheelEvent->modifiers().testFlag(Qt::ControlModifier) ||
                wheelEvent->modifiers().testFlag(Qt::AltModifier))
            {
                // Preserve Ctrl+scroll zooming and business-customized Alt+scroll behavior.
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QPoint kPixelDelta = wheelEvent->pixelDelta();
            const QPoint kAngleDelta = wheelEvent->angleDelta();
            const bool kHorizontal =
                wheelEvent->modifiers().testFlag(Qt::ShiftModifier) ||
                std::abs(kPixelDelta.x()) > std::abs(kPixelDelta.y()) ||
                std::abs(kAngleDelta.x()) > std::abs(kAngleDelta.y());
            QScrollBar* scrollBar = kHorizontal
                ? scrollArea->horizontalScrollBar()
                : scrollArea->verticalScrollBar();
            if (scrollBar == nullptr || scrollBar->minimum() == scrollBar->maximum())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const int kRawPixelDelta = kHorizontal
                ? (kPixelDelta.x() != 0 ? kPixelDelta.x() : kPixelDelta.y())
                : (kPixelDelta.y() != 0 ? kPixelDelta.y() : kPixelDelta.x());
            const int kRawAngleDelta = kHorizontal
                ? (kAngleDelta.x() != 0 ? kAngleDelta.x() : kAngleDelta.y())
                : (kAngleDelta.y() != 0 ? kAngleDelta.y() : kAngleDelta.x());
            if (kRawPixelDelta == 0 && kRawAngleDelta == 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const int kDirectionMultiplier = wheelEvent->inverted() ? -1 : 1;
            int distance = 0;
            int durationMs = kWheelAnimationDurationMs;
            if (kRawPixelDelta != 0)
            {
                distance = -kRawPixelDelta * kDirectionMultiplier;
                durationMs = kPixelAnimationDurationMs;
            }
            else
            {
                const double kWheelSteps =
                    static_cast<double>(kRawAngleDelta * kDirectionMultiplier) / 120.0;
                const int kPixelsPerStep = std::clamp(
                    scrollBar->singleStep() * 3,
                    48,
                    120);
                distance = static_cast<int>(std::lround(-kWheelSteps * kPixelsPerStep));
            }
            if (distance == 0)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QPropertyAnimation* animation = animationForScrollBar(scrollBar);
            const int kAccumulatedStart =
                animation->state() == QAbstractAnimation::Running
                ? animation->endValue().toInt()
                : scrollBar->value();
            const int kTargetValue = std::clamp(
                kAccumulatedStart + distance,
                scrollBar->minimum(),
                scrollBar->maximum());
            if (kTargetValue == scrollBar->value() &&
                animation->state() != QAbstractAnimation::Running)
            {
                // Propagate unconsumed wheel events to the parent scroll area when reaching the boundary.
                return QObject::eventFilter(watchedObject, eventObject);
            }

            animation->stop();
            animation->setDuration(durationMs);
            animation->setStartValue(scrollBar->value());
            animation->setEndValue(kTargetValue);
            animation->setEasingCurve(QEasingCurve::OutCubic);
            animation->start();
            wheelEvent->accept();
            return true;
        }

    private:
        bool enabled() const
        {
            QApplication* appInstance =
                qobject_cast<QApplication*>(QCoreApplication::instance());
            return appInstance != nullptr &&
                appInstance->property(kEnabledProperty).toBool();
        }

        QAbstractScrollArea* scrollAreaForEventObject(QObject* watchedObject) const
        {
            if (QAbstractScrollArea* directArea =
                qobject_cast<QAbstractScrollArea*>(watchedObject))
            {
                return directArea;
            }
            QAbstractScrollArea* parentArea = qobject_cast<QAbstractScrollArea*>(
                watchedObject != nullptr ? watchedObject->parent() : nullptr);
            return parentArea != nullptr && parentArea->viewport() == watchedObject
                ? parentArea
                : nullptr;
        }

        void configureScrollArea(QAbstractScrollArea* scrollArea, const bool enabledState)
        {
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(scrollArea);
            if (itemView == nullptr)
            {
                return;
            }
            if (itemView->property(kFrozenPaneAuxiliaryProperty).toBool())
            {
                // The offset for frozen panes is written directly to the scrollbar in pixels by TableFrozenPaneController. Switching the main table
                // to row-based scrolling would cause the frozen area to misalign with the main table, so pixel-based scrolling is fixed here.
                itemView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                itemView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                return;
            }

            if (enabledState)
            {
                if (!itemView->property(kOriginalVerticalModeProperty).isValid())
                {
                    itemView->setProperty(
                        kOriginalVerticalModeProperty,
                        static_cast<int>(itemView->verticalScrollMode()));
                    itemView->setProperty(
                        kOriginalHorizontalModeProperty,
                        static_cast<int>(itemView->horizontalScrollMode()));
                }
                itemView->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                itemView->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                return;
            }

            const QVariant kOriginalVerticalMode =
                itemView->property(kOriginalVerticalModeProperty);
            const QVariant kOriginalHorizontalMode =
                itemView->property(kOriginalHorizontalModeProperty);
            if (kOriginalVerticalMode.isValid())
            {
                itemView->setVerticalScrollMode(
                    static_cast<QAbstractItemView::ScrollMode>(
                        kOriginalVerticalMode.toInt()));
                itemView->setProperty(kOriginalVerticalModeProperty, QVariant());
            }
            if (kOriginalHorizontalMode.isValid())
            {
                itemView->setHorizontalScrollMode(
                    static_cast<QAbstractItemView::ScrollMode>(
                        kOriginalHorizontalMode.toInt()));
                itemView->setProperty(kOriginalHorizontalModeProperty, QVariant());
            }
        }

        QPropertyAnimation* animationForScrollBar(QScrollBar* scrollBar)
        {
            QPropertyAnimation* animation = animations_.value(scrollBar, nullptr);
            if (animation != nullptr)
            {
                return animation;
            }

            animation = new QPropertyAnimation(scrollBar, "value", this);
            animations_.insert(scrollBar, animation);
            connect(scrollBar, &QScrollBar::sliderPressed, animation, [animation]()
                {
                    animation->stop();
                });
            connect(scrollBar, &QObject::destroyed, this, [this, scrollBar]()
                {
                    if (QPropertyAnimation* removedAnimation =
                        animations_.take(scrollBar))
                    {
                        removedAnimation->stop();
                        removedAnimation->deleteLater();
                    }
                });
            return animation;
        }

        void stopAllAnimations()
        {
            for (QPropertyAnimation* animation : std::as_const(animations_))
            {
                if (animation != nullptr)
                {
                    animation->stop();
                }
            }
        }

        QHash<QScrollBar*, QPropertyAnimation*> animations_;
    };

    GlobalSmoothScrollFilter* installedFilter()
    {
        return gInstalledFilter.data();
    }
}

void ks::ui::installGlobalSmoothScrollSupport(QApplication* appInstance)
{
    if (appInstance == nullptr || appInstance->property(kInstalledProperty).toBool())
    {
        return;
    }

    auto* filter = new GlobalSmoothScrollFilter(appInstance);
    filter->setObjectName(QStringLiteral("KSWORD_GLOBAL_SMOOTH_SCROLL_FILTER"));
    gInstalledFilter = filter;
    appInstance->installEventFilter(filter);
    appInstance->setProperty(kInstalledProperty, true);
    filter->applyEnabledStateToAllWidgets(
        appInstance->property(kEnabledProperty).toBool());
}

void ks::ui::setGlobalSmoothScrollingEnabled(const bool enabled)
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    if (appInstance == nullptr)
    {
        return;
    }
    appInstance->setProperty(kEnabledProperty, enabled);
    if (GlobalSmoothScrollFilter* filter = installedFilter())
    {
        filter->applyEnabledStateToAllWidgets(enabled);
    }
}

bool ks::ui::isGlobalSmoothScrollingEnabled()
{
    QApplication* appInstance =
        qobject_cast<QApplication*>(QCoreApplication::instance());
    return appInstance != nullptr &&
        appInstance->property(kEnabledProperty).toBool();
}

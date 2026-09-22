#include "DockTabInteraction.h"

#include "../include/ads/DockAreaTabBar.h"
#include "../include/ads/DockAreaTitleBar.h"
#include "../include/ads/DockAreaWidget.h"
#include "../include/ads/DockContainerWidget.h"
#include "../include/ads/DockManager.h"
#include "../include/ads/DockWidgetTab.h"
#include "../internationalization/LanguageManager.h"
#include "../Theme.h"

#include <QApplication>
#include <QLayout>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QPointer>
#include <QScrollBar>
#include <QTimer>
#include <QToolButton>
#include <QWheelEvent>
#include <cmath>

namespace ks::ui
{
    namespace
    {
        constexpr int kWheelStepPixels = 48;
        constexpr const char* kInstalledProperty = "ksword_dock_tab_scrolling_installed";

        class DockTabScroller final : public QObject
        {
        public:
            explicit DockTabScroller(ads::CDockAreaTitleBar* titleBar)
                : QObject(titleBar->tabBar()), tabBar_(titleBar->tabBar()),
                  titleBar_(titleBar), viewport_(tabBar_->viewport()),
                  tabsContainer_(tabBar_->widget())
            {
                // Ignored retains a minimum width of zero (allowing contraction), but a stretch weight must also be set.
                // Otherwise, the expanding placeholder control in the ADS title bar will consume all remaining space, compressing the tab bar to zero width.
                tabBar_->setMinimumWidth(0);
                QSizePolicy tabBarPolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
                tabBarPolicy.setHorizontalStretch(1);
                tabBar_->setSizePolicy(tabBarPolicy);
                tabBar_->setProperty("ksword_disable_smooth_scroll", true);
                tabBar_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
                tabBar_->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

                left_ = new QToolButton(titleBar);
                right_ = new QToolButton(titleBar);
                left_->setObjectName(QStringLiteral("ks_dock_scroll_left"));
                right_->setObjectName(QStringLiteral("ks_dock_scroll_right"));
                left_->setArrowType(Qt::LeftArrow);
                right_->setArrowType(Qt::RightArrow);
                for (QToolButton* button : { left_.data(), right_.data() })
                {
                    ksword_theme::applyCompactIconButtonMetrics(button);
                    button->setAutoRepeat(true);
                    button->setAutoRaise(true);
                    button->hide();
                }
                auto& language = ks::i18n::LanguageManager::instance();
                language.bindToolTip(left_, QStringLiteral("dock.tabs.scroll_left"), QStringLiteral("向左滚动标签"));
                language.bindToolTip(right_, QStringLiteral("dock.tabs.scroll_right"), QStringLiteral("向右滚动标签"));
                titleBar->insertWidget(titleBar->indexOf(tabBar_), left_);
                titleBar->insertWidget(titleBar->indexOf(tabBar_) + 1, right_);

                QScrollBar* const kBar = tabBar_->horizontalScrollBar();
                connect(left_.data(), &QToolButton::clicked, this, [this]() { scrollByPage(-1); });
                connect(right_.data(), &QToolButton::clicked, this, [this]() { scrollByPage(1); });
                connect(kBar, &QScrollBar::rangeChanged, this, [this]() { scheduleButtons(); });
                connect(kBar, &QScrollBar::valueChanged, this, [this]() { scheduleButtons(); });
                connect(tabBar_.data(), &ads::CDockAreaTabBar::tabInserted, this, [this]() { scheduleButtons(); });
                connect(tabBar_.data(), &ads::CDockAreaTabBar::removingTab, this, [this]() { scheduleButtons(); });
                connect(tabBar_.data(), &ads::CDockAreaTabBar::tabOpened, this, [this]() { scheduleButtons(); });
                connect(tabBar_.data(), &ads::CDockAreaTabBar::tabClosed, this, [this]() { scheduleButtons(); });
                connect(tabBar_.data(), &ads::CDockAreaTabBar::tabMoved, this, [this]() { scheduleButtons(); });
                connect(tabBar_.data(), &ads::CDockAreaTabBar::currentChanged, this, [this]()
                    {
                        revealCurrent_ = true;
                        scheduleButtons();
                    });

                // Capture the wheel event before forwarding viewportEvent to override text, icons, and dynamic child controls.
                // QApplication filter only takes over descendants of this tab bar.
                qApp->installEventFilter(this);
                scheduleButtons();
            }

            ~DockTabScroller() override
            {
                if (qApp != nullptr)
                {
                    qApp->removeEventFilter(this);
                }
                // Arrows belong to the title bar; remove their associated buttons when destroying or replacing the tab bar separately.
                for (QToolButton* button : { left_.data(), right_.data() })
                {
                    if (button != nullptr)
                    {
                        button->deleteLater();
                    }
                }
            }

        protected:
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (event == nullptr || !tabBar_ || !titleBar_ || !viewport_)
                {
                    return false;
                }
                if (watched == viewport_ || watched == tabBar_ ||
                    watched == titleBar_ || watched == tabsContainer_)
                {
                    switch (event->type())
                    {
                    case QEvent::Resize:
                        revealCurrent_ = revealCurrent_ || watched == viewport_;
                        scheduleButtons();
                        break;
                    case QEvent::Show:
                    case QEvent::Hide:
                    case QEvent::LayoutRequest:
                    case QEvent::FontChange:
                    case QEvent::StyleChange:
                    case QEvent::LanguageChange:
                        scheduleButtons();
                        break;
                    default:
                        break;
                    }
                }
                if (event->type() != QEvent::Wheel)
                {
                    return false;
                }
                auto* const kWidget = qobject_cast<QWidget*>(watched);
                if (kWidget == nullptr || !tabBar_->isVisible() || !tabBar_->isEnabled() ||
                    (kWidget != tabBar_ && !tabBar_->isAncestorOf(kWidget) &&
                        kWidget != left_ && kWidget != right_))
                {
                    return false;
                }

                auto* const kWheel = static_cast<QWheelEvent*>(event);
                if (kWheel->phase() == Qt::ScrollBegin || kWheel->phase() == Qt::ScrollEnd)
                {
                    remainder_ = 0;
                }
                const QPoint kPixelDelta = kWheel->pixelDelta();
                const QPoint kAngleDelta = kWheel->angleDelta();
                const bool kPixels = !kPixelDelta.isNull();
                const QPoint kDelta = kPixels ? kPixelDelta : kAngleDelta;
                const int kAxisDelta = kDelta.x() != 0 ? kDelta.x() : kDelta.y();
                if (kAxisDelta == 0)
                {
                    // Touchpad start/end events may have no displacement; do not forward to ADS for secondary handling.
                    kWheel->accept();
                    return true;
                }
                const qreal kDistance = kPixels ? qreal(kAxisDelta)
                    : qreal(kAxisDelta) * kWheelStepPixels / 120.0;
                // Accumulate sub-pixel remainder from high-resolution scroll wheels; clear the remainder from the previous direction when reversing.
                if (kDistance * remainder_ < 0)
                {
                    remainder_ = 0;
                }
                remainder_ += kDistance;
                const int kWholePixels = static_cast<int>(std::trunc(remainder_));
                remainder_ -= kWholePixels;
                QScrollBar* const kBar = tabBar_->horizontalScrollBar();
                kBar->setValue(kBar->value() - kWholePixels);
                if ((kDistance > 0 && kBar->value() == kBar->minimum())
                    || (kDistance < 0 && kBar->value() == kBar->maximum()))
                {
                    remainder_ = 0;
                }
                // At the boundary, the tab bar still handles the event to prevent ADS from switching pages or scrolling the content below.
                kWheel->accept();
                return true;
            }

        private:
            void scrollByPage(int direction)
            {
                if (!tabBar_ || !viewport_)
                {
                    return;
                }
                QScrollBar* const kBar = tabBar_->horizontalScrollBar();
                remainder_ = 0;
                kBar->setValue(kBar->value() + direction * qMax(kWheelStepPixels, viewport_->width() / 2));
            }

            void updateButtons()
            {
                if (!tabBar_ || !titleBar_ || !viewport_ || !tabsContainer_ || !left_ || !right_)
                {
                    return;
                }
                QLayout* const kTabsLayout = tabsContainer_->layout();
                QLayout* const kTitleLayout = titleBar_->layout();
                if (kTabsLayout == nullptr || kTitleLayout == nullptr)
                {
                    return;
                }

                // Use the natural width of the full tab instead of inferring content width from potentially stale scrollbar ranges.
                // Add back the displayed arrows and their layout spacing, using 'whether all tags can fit without arrows' as the criterion.
                const int kSpacing = qMax(0, kTitleLayout->spacing());
                int availableWidth = viewport_->width();
                for (QToolButton* button : { left_.data(), right_.data() })
                {
                    if (!button->isHidden())
                    {
                        availableWidth += button->width() + kSpacing;
                    }
                }
                const bool kOverflowing = tabBar_->isVisible() && availableWidth > 0 &&
                    kTabsLayout->sizeHint().width() > availableWidth;
                const bool kVisibilityChanged = left_->isHidden() == kOverflowing ||
                    right_->isHidden() == kOverflowing;
                if (kVisibilityChanged)
                {
                    left_->setVisible(kOverflowing);
                    right_->setVisible(kOverflowing);
                    // After the arrow changes its visible width, wait for layout completion before reading the scroll range and positioning the current tab.
                    scheduleButtons();
                    return;
                }

                QScrollBar* const kBar = tabBar_->horizontalScrollBar();
                if (!kOverflowing)
                {
                    remainder_ = 0;
                    kBar->setValue(kBar->minimum());
                }
                if (revealCurrent_ && tabBar_->isVisible())
                {
                    revealCurrent_ = false;
                    if (ads::CDockWidgetTab* current = tabBar_->currentTab())
                    {
                        tabBar_->ensureWidgetVisible(current, 0, 0);
                    }
                }
                left_->setEnabled(kOverflowing && kBar->value() > kBar->minimum());
                right_->setEnabled(kOverflowing && kBar->value() < kBar->maximum());
            }

            void scheduleButtons()
            {
                if (updatePending_)
                {
                    return;
                }
                updatePending_ = true;
                QTimer::singleShot(0, this, [this]()
                    {
                        updatePending_ = false;
                        updateButtons();
                    });
            }

            QPointer<ads::CDockAreaTabBar> tabBar_;
            QPointer<ads::CDockAreaTitleBar> titleBar_;
            QPointer<QWidget> viewport_;
            QPointer<QWidget> tabsContainer_;
            QPointer<QToolButton> left_;
            QPointer<QToolButton> right_;
            qreal remainder_ = 0;
            bool updatePending_ = false;
            bool revealCurrent_ = false;
        };

        void installOnTabBar(ads::CDockAreaWidget* dockArea)
        {
            if (dockArea == nullptr || dockArea->titleBar() == nullptr)
            {
                return;
            }
            ads::CDockAreaTabBar* const kTabBar = dockArea->titleBar()->tabBar();
            if (kTabBar == nullptr || dockArea->titleBar()->indexOf(kTabBar) < 0 ||
                kTabBar->property(kInstalledProperty).toBool())
            {
                return;
            }
            kTabBar->setProperty(kInstalledProperty, true);
            new DockTabScroller(dockArea->titleBar());
        }
    }

    void installDockTabWheelScrolling(ads::CDockManager* dockManager)
    {
        if (dockManager == nullptr || dockManager->property(kInstalledProperty).toBool())
        {
            return;
        }
        dockManager->setProperty(kInstalledProperty, true);
        for (ads::CDockContainerWidget* container : dockManager->dockContainers())
        {
            if (container != nullptr)
            {
                for (ads::CDockAreaWidget* area : container->openedDockAreas())
                {
                    installOnTabBar(area);
                }
            }
        }
        QObject::connect(dockManager, &ads::CDockManager::dockAreaCreated,
            dockManager, [](ads::CDockAreaWidget* area) { installOnTabBar(area); });
    }

    bool discardSavedDockLayout(const QString& layoutConfigPath)
    {
        if (layoutConfigPath.isEmpty())
        {
            return false;
        }
        const QFileInfo kInfo(layoutConfigPath);
        if (!kInfo.exists())
        {
            return true;
        }
        return QFile::remove(layoutConfigPath);
    }
}

#include "MainWindow.h"

#include <QMenu>
#include <QEasingCurve>
#include <QAbstractScrollArea>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QAbstractSlider>
#include <QComboBox>
#include <QTabBar>
#include <QToolButton>
#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QFont>
#include <QHeaderView>
#include <QWidget>
#include <QList>
#include <QPainter>
#include <QPalette>
#include <QPen>
#include <QPixmap>
#include <QPointer>
#include <QPropertyAnimation>
#include <QScrollBar>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QProxyStyle>
#include <QTableView>
#include <QEvent>
#include <QWheelEvent>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "ui/SmoothScrollSupport.h"
#include "Theme.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <unordered_map>
#include <TlHelp32.h>

#include "MainWindow.NativeFrameSupport.h"
#include "MainWindow.WidgetBehaviorSupport.h"

namespace ksword::ui::main_window
{
    constexpr const char* kKswordCustomTableDelegatePropertyName = "ksword_preserve_custom_table_delegate";

    constexpr const char* kKswordTableSelectionOutlineDelegatePropertyName = "ksword_table_selection_outline_delegate";

    constexpr const char* kKswordTableSelectionOutlineStylePropertyName = "ksword_table_selection_outline_style";

    constexpr const char* kKswordComboPopupAutoThemedPropertyName = "ksword_combo_popup_auto_themed";

    constexpr const char* kKswordComboPopupThemeUpdatePendingPropertyName = "ksword_combo_popup_theme_update_pending";

    // comboBoxForPopupView:
    // - Input: QAbstractItemView used by the QComboBox popup list;
    // - Processing: First locate the combo box via the QObject parent chain, then fall back to the QApplication control collection.
    // - Returns: the associated combo box; nullptr if unable to confirm.
    QComboBox* comboBoxForPopupView(QAbstractItemView* const itemView)
    {
        if (itemView == nullptr)
        {
            return nullptr;
        }

        for (QObject* currentObject = itemView; currentObject != nullptr; currentObject = currentObject->parent())
        {
            if (QComboBox* const kComboBox = qobject_cast<QComboBox*>(currentObject))
            {
                return kComboBox;
            }
        }

        QWidget* const kPopupWindow = itemView->window();
        if (kPopupWindow == nullptr || !kPopupWindow->windowFlags().testFlag(Qt::Popup))
        {
            return nullptr;
        }

        const QWidgetList kAllWidgetList = QApplication::allWidgets();
        for (QWidget* const kWidget : kAllWidgetList)
        {
            QComboBox* const kComboBox = qobject_cast<QComboBox*>(kWidget);
            if (kComboBox != nullptr && kComboBox->view() == itemView)
            {
                return kComboBox;
            }
        }
        return nullptr;
    }

    // applyOpaqueComboPopupPalette:
    // - Input: combo box popup container, list view, or viewport;
    // - Processing: Apply opaque background with complete foreground/selected-state palette, and enable background filling.
    // - Returns: none. Even if QSS fails or the platform style falls back, the palette prevents a black background.
    void applyOpaqueComboPopupPalette(QWidget* const targetWidget)
    {
        if (targetWidget == nullptr)
        {
            return;
        }

        const QColor kBackgroundColor = ksword_theme::surfaceColor();
        QPalette popupPalette = targetWidget->palette();
        popupPalette.setColor(QPalette::Window, kBackgroundColor);
        popupPalette.setColor(QPalette::Base, kBackgroundColor);
        popupPalette.setColor(QPalette::AlternateBase, kBackgroundColor);
        popupPalette.setColor(QPalette::Text, ksword_theme::textPrimaryColor());
        popupPalette.setColor(QPalette::WindowText, ksword_theme::textPrimaryColor());
        popupPalette.setColor(QPalette::ButtonText, ksword_theme::textPrimaryColor());
        popupPalette.setColor(QPalette::Highlight, ksword_theme::controlAccentColor());
        popupPalette.setColor(
            QPalette::HighlightedText,
            ksword_theme::maximumContrastMonochromeColor(ksword_theme::controlAccentColor()));
        popupPalette.setColor(QPalette::Mid, ksword_theme::borderColor());
        if (targetWidget->palette() != popupPalette)
        {
            targetWidget->setPalette(popupPalette);
        }
        if (!targetWidget->autoFillBackground())
        {
            targetWidget->setAutoFillBackground(true);
        }
        if (!targetWidget->testAttribute(Qt::WA_StyledBackground))
        {
            targetWidget->setAttribute(Qt::WA_StyledBackground, true);
        }
    }

    // comboPopupViewStyle:
    // - Generates local styles written directly to the QComboBox Popup view.
    // - Popup is a standalone top-level window and cannot rely on mainWindow descendant selectors for background inheritance;
    // - All combo boxes use the current theme's opaque list background; existing controls with direct Popup styles retain their dedicated view rules.
    QString comboPopupViewStyle()
    {
        return ksword_theme::themedComboBoxPopupViewStyle();
    }

    // applyOpaqueComboPopupTheme:
    // - Input: Any QComboBox;
    // - Processing: Directly theme its Popup QFrame, list view, and viewport.
    // - Returns: none. Bypasses the limitation where Qt Popup top-level windows do not inherit the main window's QSS.
    void applyOpaqueComboPopupTheme(QComboBox* const comboBox)
    {
        if (comboBox == nullptr)
        {
            return;
        }

        QAbstractItemView* const kItemView = comboBox->view();
        if (kItemView == nullptr)
        {
            return;
        }

        QWidget* const kPopupContainer = kItemView->window();
        const bool kHasDedicatedPopupContainer =
            kPopupContainer != nullptr &&
            kPopupContainer != comboBox &&
            kPopupContainer->windowFlags().testFlag(Qt::Popup);

        const bool kAutoThemed = kItemView->property(kKswordComboPopupAutoThemedPropertyName).toBool();
        if (!kAutoThemed && !kItemView->styleSheet().trimmed().isEmpty())
        {
            return;
        }

        if (kHasDedicatedPopupContainer)
        {
            applyOpaqueComboPopupPalette(kPopupContainer);
            const QString kPopupContainerStyle = QStringLiteral(
                "QFrame{"
                "  background-color:%1 !important;"
                "  color:%2 !important;"
                "  border:1px solid %3 !important;"
                "}")
                .arg(ksword_theme::surfaceColorHex())
                .arg(ksword_theme::textPrimaryColorHex())
                .arg(ksword_theme::borderColorHex());
            if (kPopupContainer->styleSheet() != kPopupContainerStyle)
            {
                kPopupContainer->setStyleSheet(kPopupContainerStyle);
            }
        }

        applyOpaqueComboPopupPalette(kItemView);
        const QString kItemViewStyle = comboPopupViewStyle();
        if (kItemView->styleSheet() != kItemViewStyle)
        {
            kItemView->setStyleSheet(kItemViewStyle);
        }
        applyOpaqueComboPopupPalette(kItemView->viewport());
        kItemView->setProperty(kKswordComboPopupAutoThemedPropertyName, true);
    }

    // scheduleOpaqueComboPopupTheme:
    // - The QComboBox Popup's Show event occurs during the traversal of internal child objects in QWidgetPrivate::showChildren.
    // - palette/QSS may trigger repolish and rebuild child controls like scrollbars, so updates must wait until the current Show dispatch completes;
    // - Merge duplicate Show events generated by the same Popup container, view, and viewport in a single round via dynamic properties of the combo box.
    void scheduleOpaqueComboPopupTheme(QComboBox* const comboBox)
    {
        if (comboBox == nullptr ||
            comboBox->property(kKswordComboPopupThemeUpdatePendingPropertyName).toBool())
        {
            return;
        }

        comboBox->setProperty(kKswordComboPopupThemeUpdatePendingPropertyName, true);
        const QPointer<QComboBox> kGuardedComboBox(comboBox);
        QTimer::singleShot(0, comboBox, [kGuardedComboBox]()
        {
            if (kGuardedComboBox.isNull())
            {
                return;
            }
            kGuardedComboBox->setProperty(kKswordComboPopupThemeUpdatePendingPropertyName, false);
            applyOpaqueComboPopupTheme(kGuardedComboBox.data());
        });
    }

    // GlobalComboPopupThemeFilter:
    // - Listen for application-wide control display events.
    // - For newly created, lazily loaded, and theme-switched regular combo boxes, update the Popup theme after the current Show dispatch completes.
    // - The combo box body can retain business-specific local styles, but if the Popup lacks direct styles, a uniform opaque list surface is applied.
    class GlobalComboPopupThemeFilter final : public QObject
    {
    public:
        explicit GlobalComboPopupThemeFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() != QEvent::Show)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* const kWatchedWidget = qobject_cast<QWidget*>(watchedObject);
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(watchedObject);
            if (itemView == nullptr)
            {
                if (kWatchedWidget != nullptr)
                {
                    itemView = kWatchedWidget->findChild<QAbstractItemView*>();
                }
            }

            scheduleOpaqueComboPopupTheme(comboBoxForPopupView(itemView));
            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // GlobalContextMenuThemeFilter:
    // - Intercept all QMenu display and style change events at the application layer.
    // Automatically apply a unified theme style to menus that do not have an explicitly set style, avoiding missed single-point setStyleSheet calls.
    class GlobalContextMenuThemeFilter final : public QObject
    {
    public:
        explicit GlobalContextMenuThemeFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type kEventType = eventObject->type();
            if (kEventType != QEvent::Show)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QMenu* menuWidget = qobject_cast<QMenu*>(watchedObject);
            if (menuWidget == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // Note: Only automatically handle menus with no explicitly set style; manually customized menus remain unchanged.
            // For menus handled automatically, refresh on every display to ensure immediate effect of light/dark theme switching.
            const bool kAutoThemedByKsword =
                menuWidget->property("ksword_auto_context_menu_themed").toBool();
            const bool kNoExplicitMenuStyle = menuWidget->styleSheet().trimmed().isEmpty();
            if (kNoExplicitMenuStyle || kAutoThemedByKsword)
            {
                menuWidget->setStyleSheet(ksword_theme::contextMenuStyle());
                menuWidget->setProperty("ksword_auto_context_menu_themed", true);
            }
            if (isKswordPopupTopMostTrackingEnabled())
            {
                applyTopMostToTopLevelWidget(menuWidget, true);
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // GlobalTopLevelTopMostFilter:
    // - Input: QApplication global event stream.
    // - Handling: When the main window is set to topmost, synchronize HWND_TOPMOST for all subsequently displayed top-level windows.
    // - Returns: always passes to Qt's default handler without consuming the event.
    class GlobalTopLevelTopMostFilter final : public QObject
    {
    public:
        explicit GlobalTopLevelTopMostFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type kEventType = eventObject->type();
            if (kEventType != QEvent::Show && kEventType != QEvent::WindowActivate)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* widget = qobject_cast<QWidget*>(watchedObject);
            if (widget == nullptr || widget->isWindow() == false)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (isKswordPopupTopMostTrackingEnabled())
            {
                applyTopMostToTopLevelWidget(widget, true);
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    QIcon contrastIconForSelectedTab(const QIcon& sourceIcon)
    {
        if (sourceIcon.isNull())
        {
            return sourceIcon;
        }

        // Native QTabBar lacks QSS icon tinting capability; generate a white version here using the current icon mask.
        const QSize kIconSize(16, 16);
        QPixmap sourcePixmap = sourceIcon.pixmap(kIconSize);
        if (sourcePixmap.isNull())
        {
            return sourceIcon;
        }

        QPixmap contrastPixmap(kIconSize);
        contrastPixmap.fill(Qt::transparent);
        QPainter painter(&contrastPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.drawPixmap(0, 0, sourcePixmap);
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(contrastPixmap.rect(), ksword_theme::onAccentColor());
        painter.end();
        return QIcon(contrastPixmap);
    }

    class GlobalTabIconContrastFilter final : public QObject
    {
    public:
        explicit GlobalTabIconContrastFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QTabBar* tabBar = qobject_cast<QTabBar*>(watchedObject);
            if (tabBar == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type kEventType = eventObject->type();
            if (kEventType == QEvent::Destroy)
            {
                originalIconsByTabBar_.erase(tabBar);
                displayIconsByTabBar_.erase(tabBar);
                contrastIconsByTabBar_.erase(tabBar);
                return QObject::eventFilter(watchedObject, eventObject);
            }
            if (kEventType == QEvent::Show
                || kEventType == QEvent::Polish
                || kEventType == QEvent::StyleChange)
            {
                configureAdaptiveTabBar(tabBar);
            }
            if (kEventType != QEvent::Show
                && kEventType != QEvent::Polish
                && kEventType != QEvent::StyleChange
                && kEventType != QEvent::PaletteChange
                && kEventType != QEvent::LayoutRequest
                && kEventType != QEvent::ChildAdded
                && kEventType != QEvent::ChildRemoved)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            refreshTabBarIcons(tabBar);
            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        void configureAdaptiveTabBar(QTabBar* tabBar)
        {
            if (tabBar == nullptr || tabBar->property("ksword_adaptive_tabbar_configured").toBool())
            {
                return;
            }

            tabBar->setProperty("ksword_adaptive_tabbar_configured", true);
            tabBar->setExpanding(false);
            tabBar->setUsesScrollButtons(true);
            tabBar->setElideMode(Qt::ElideNone);
            QObject::connect(tabBar, &QTabBar::currentChanged, tabBar, [this, tabBar](int)
            {
                refreshTabBarIcons(tabBar);
            });

            // Execute the "return to the leftmost" initialization only once after the initial configuration to ensure the leftmost Tab is displayed first even if space is insufficient at startup.
            // Subsequent window scaling will no longer re-execute this to avoid affecting the user's manual scroll position.
            if (!tabBar->property("ksword_initial_left_edge_synced").toBool())
            {
                tabBar->setProperty("ksword_initial_left_edge_synced", true);
                QTimer::singleShot(0, tabBar, [tabBar]() {
                    const QList<QToolButton*> kScrollButtons = tabBar->findChildren<QToolButton*>();
                    for (QToolButton* button : kScrollButtons)
                    {
                        if (button == nullptr || !button->isVisible() || !button->isEnabled())
                        {
                            continue;
                        }
                        if (button->arrowType() == Qt::LeftArrow)
                        {
                            while (button->isEnabled())
                            {
                                button->click();
                            }
                            break;
                        }
                    }
                });
            }
        }

        void refreshTabBarIcons(QTabBar* tabBar)
        {
            if (tabBar == nullptr || tabBar->count() <= 0)
            {
                return;
            }

            QList<QIcon>& originalIconList = originalIconsByTabBar_[tabBar];
            QList<QIcon>& displayIconList = displayIconsByTabBar_[tabBar];
            QList<QIcon>& contrastIconList = contrastIconsByTabBar_[tabBar];
            while (originalIconList.size() < tabBar->count())
            {
                originalIconList.push_back(QIcon());
                displayIconList.push_back(QIcon());
                contrastIconList.push_back(QIcon());
            }
            while (originalIconList.size() > tabBar->count())
            {
                originalIconList.removeLast();
                displayIconList.removeLast();
                contrastIconList.removeLast();
            }

            const int kSelectedIndex = tabBar->currentIndex();
            for (int tabIndex = 0; tabIndex < tabBar->count(); ++tabIndex)
            {
                const QIcon kCurrentIcon = tabBar->tabIcon(tabIndex);
                const bool kCurrentIconWasAppliedByFilter = !displayIconList[tabIndex].isNull()
                    && kCurrentIcon.cacheKey() == displayIconList[tabIndex].cacheKey();
                if (originalIconList[tabIndex].isNull())
                {
                    originalIconList[tabIndex] = kCurrentIcon;
                    contrastIconList[tabIndex] = QIcon();
                }
                else if (tabIndex != kSelectedIndex
                    && !kCurrentIconWasAppliedByFilter
                    && !kCurrentIcon.isNull()
                    && kCurrentIcon.cacheKey() != originalIconList[tabIndex].cacheKey())
                {
                    originalIconList[tabIndex] = kCurrentIcon;
                    contrastIconList[tabIndex] = QIcon();
                }

                const QIcon kOriginalIcon = originalIconList[tabIndex];
                if (kOriginalIcon.isNull())
                {
                    continue;
                }
                if (contrastIconList[tabIndex].isNull())
                {
                    contrastIconList[tabIndex] = contrastIconForSelectedTab(kOriginalIcon);
                }

                const QIcon kDisplayIcon = tabIndex == kSelectedIndex
                    ? contrastIconList[tabIndex]
                    : kOriginalIcon;
                if (kCurrentIcon.cacheKey() != kDisplayIcon.cacheKey())
                {
                    tabBar->setTabIcon(tabIndex, kDisplayIcon);
                }
                displayIconList[tabIndex] = kDisplayIcon;
            }
        }

        std::unordered_map<QTabBar*, QList<QIcon>> originalIconsByTabBar_;
        std::unordered_map<QTabBar*, QList<QIcon>> displayIconsByTabBar_;
        std::unordered_map<QTabBar*, QList<QIcon>> contrastIconsByTabBar_;
    };

    class GlobalSliderWheelFilter final : public QObject
    {
    public:
        explicit GlobalSliderWheelFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr || eventObject->type() != QEvent::Wheel)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWheelEvent* wheelEvent = static_cast<QWheelEvent*>(eventObject);
            if (trySmoothScroll(watchedObject, wheelEvent))
            {
                return true;
            }

            QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
            const bool kSliderWheelAdjustEnabled = appInstance != nullptr
                && appInstance->property("ksword_slider_wheel_adjust_enabled").toBool();
            if (kSliderWheelAdjustEnabled)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // Only disable scroll-wheel value adjustment for 'numeric sliders' like QSlider. Do not intercept QScrollBar, or page scrolling will fail.
            if (qobject_cast<QScrollBar*>(watchedObject) != nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (qobject_cast<QAbstractSlider*>(watchedObject) == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            eventObject->ignore();
            return true;
        }

    private:
        bool trySmoothScroll(QObject* watchedObject, QWheelEvent* wheelEvent)
        {
            if (wheelEvent == nullptr || wheelEvent->modifiers().testFlag(Qt::ControlModifier))
            {
                return false;
            }

            if (isItemViewWheelEvent(watchedObject))
            {
                return false;
            }

            if (isSmoothScrollDisabled(watchedObject))
            {
                return false;
            }

            QScrollBar* targetScrollBar = findTargetScrollBar(watchedObject, wheelEvent);
            if (targetScrollBar == nullptr || targetScrollBar->minimum() == targetScrollBar->maximum())
            {
                return false;
            }

            const int kWheelDelta = !wheelEvent->pixelDelta().isNull()
                ? wheelEvent->pixelDelta().y()
                : wheelEvent->angleDelta().y() / 8;
            if (kWheelDelta == 0)
            {
                return false;
            }

            // Keep animation steps restrained: ensure smooth scroll wheel transitions without slowing down rapid browsing of large tables.
            const int kLineStep = std::max(18, targetScrollBar->singleStep() * 3);
            const int kTargetValue = std::clamp(
                targetScrollBar->value() - kWheelDelta * kLineStep / 15,
                targetScrollBar->minimum(),
                targetScrollBar->maximum());
            animateScrollBar(targetScrollBar, kTargetValue);
            wheelEvent->accept();
            return true;
        }

        bool isItemViewWheelEvent(QObject* watchedObject) const
        {
            // isItemViewWheelEvent:
            // - Check if the wheel event originates from an item view (QTableView/QTableWidget/QTreeView/QListView) or its viewport/scrollbar sub-controls;
            // - The scroll bar value of an item view is typically the row/item index, not pixels; global pixel smoothing algorithms cannot be used for scaling.
            // - Return true to pass the Qt default wheelEvent, allowing tables/trees/lists to scroll normally according to their singleStep/pageStep.
            // Parameter watchedObject: Event source received by the QApplication global event filter.
            // Return: true means skip global smooth-scroll; false means continue attempting global smooth-scroll.
            QObject* currentObject = watchedObject;
            while (currentObject != nullptr)
            {
                if (qobject_cast<QAbstractItemView*>(currentObject) != nullptr)
                {
                    return true;
                }

                QWidget* currentWidget = qobject_cast<QWidget*>(currentObject);
                currentObject = currentWidget != nullptr
                    ? currentWidget->parentWidget()
                    : currentObject->parent();
            }
            return false;
        }

        bool isSmoothScrollDisabled(QObject* watchedObject) const
        {
            // isSmoothScrollDisabled:
            // - Allows high-frequency table updates to locally disable global scroll animations and restore Qt default scrolling;
            // - Input is the watchedObject received by the QApplication event filter;
            // - Traverse the QWidget parent chain to locate properties, supporting viewport, table body, and scrollbar hit points;
            // - Returns true to indicate that wheel events are not intercepted and no QPropertyAnimation is created.
            QObject* currentObject = watchedObject;
            while (currentObject != nullptr)
            {
                if (currentObject->property("ksword_disable_smooth_scroll").toBool())
                {
                    return true;
                }

                QWidget* currentWidget = qobject_cast<QWidget*>(currentObject);
                currentObject = currentWidget != nullptr
                    ? currentWidget->parentWidget()
                    : currentObject->parent();
            }
            return false;
        }

        QScrollBar* findTargetScrollBar(QObject* watchedObject, QWheelEvent* wheelEvent) const
        {
            if (qobject_cast<QAbstractSlider*>(watchedObject) != nullptr
                && qobject_cast<QScrollBar*>(watchedObject) == nullptr)
            {
                return nullptr;
            }

            QScrollBar* directScrollBar = qobject_cast<QScrollBar*>(watchedObject);
            if (directScrollBar != nullptr)
            {
                return directScrollBar;
            }

            QWidget* sourceWidget = qobject_cast<QWidget*>(watchedObject);
            QWidget* currentWidget = sourceWidget;
            while (currentWidget != nullptr)
            {
                QAbstractScrollArea* scrollArea = qobject_cast<QAbstractScrollArea*>(currentWidget);
                if (scrollArea != nullptr)
                {
                    return chooseScrollBar(scrollArea, wheelEvent);
                }
                currentWidget = currentWidget->parentWidget();
            }
            return nullptr;
        }

        QScrollBar* chooseScrollBar(QAbstractScrollArea* scrollArea, QWheelEvent* wheelEvent) const
        {
            if (scrollArea == nullptr || wheelEvent == nullptr)
            {
                return nullptr;
            }

            if (std::abs(wheelEvent->angleDelta().x()) > std::abs(wheelEvent->angleDelta().y()))
            {
                QScrollBar* horizontalScrollBar = scrollArea->horizontalScrollBar();
                if (horizontalScrollBar != nullptr && horizontalScrollBar->minimum() != horizontalScrollBar->maximum())
                {
                    return horizontalScrollBar;
                }
            }
            return scrollArea->verticalScrollBar();
        }

        void animateScrollBar(QScrollBar* targetScrollBar, const int targetValue)
        {
            if (targetScrollBar == nullptr)
            {
                return;
            }

            QPointer<QPropertyAnimation>& animationRef = scrollAnimationByBar_[targetScrollBar];
            if (animationRef == nullptr)
            {
                animationRef = new QPropertyAnimation(targetScrollBar, "value", targetScrollBar);
                animationRef->setDuration(110);
                animationRef->setEasingCurve(QEasingCurve::OutCubic);
            }

            animationRef->stop();
            animationRef->setStartValue(targetScrollBar->value());
            animationRef->setEndValue(targetValue);
            animationRef->start();
        }

        std::unordered_map<QScrollBar*, QPointer<QPropertyAnimation>> scrollAnimationByBar_;
    };

    // TableSelectionOutlineDelegate:
    // - Take over selection painting for uncustomized QTableView/QTableWidget delegates;
    // - Clear Qt's default highlight fill, preserving the model's own background color.
    // - Draw a 3px theme-colored full-row border when selected.
    class TableSelectionOutlineDelegate final : public QStyledItemDelegate
    {
    public:
        explicit TableSelectionOutlineDelegate(QTableView* tableView)
            : QStyledItemDelegate(tableView)
            , tableView_(tableView)
        {
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem itemOption(option);
            const bool kRowSelected = (itemOption.state & QStyle::State_Selected) != 0;

            // The transparent background in QSS does not prevent the native style from using Highlight filling.
            // Clear the selected state before calling the base class to preserve alternating row colors and the model's BackgroundRole.
            itemOption.state &= ~QStyle::State_Selected;
            itemOption.state &= ~QStyle::State_HasFocus;
            QStyledItemDelegate::paint(painter, itemOption, index);

            if (kRowSelected)
            {
                drawRowSelectionOutline(painter, option, index);
            }
        }

    private:
        void drawRowSelectionOutline(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const
        {
            if (painter == nullptr || tableView_ == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = tableView_->horizontalHeader();
            const QAbstractItemModel* model = index.model();
            if (headerView == nullptr || model == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int kColumnCount = model->columnCount(index.parent());
            for (int columnIndex = 0; columnIndex < kColumnCount; ++columnIndex)
            {
                if (tableView_->isColumnHidden(columnIndex))
                {
                    continue;
                }

                const int kVisualIndex = headerView->visualIndex(columnIndex);
                if (kVisualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, kVisualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, kVisualIndex);
            }

            const int kCurrentVisualIndex = headerView->visualIndex(index.column());
            if (kCurrentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            const QRect kBorderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!kBorderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(ksword_theme::primaryBlueColor, 3.0));
            painter->drawLine(kBorderRect.topLeft(), kBorderRect.topRight());
            painter->drawLine(kBorderRect.bottomLeft(), kBorderRect.bottomRight());
            if (kCurrentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(kBorderRect.topLeft(), kBorderRect.bottomLeft());
            }
            if (kCurrentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(kBorderRect.topRight(), kBorderRect.bottomRight());
            }
            painter->restore();
        }

        QPointer<QTableView> tableView_;
    };

    // TableSelectionOutlineProxyStyle:
    // - Uniformly remove default selection fill for QTableView/QTableWidget at the native style layer;
    // - Acts as a fallback delegate to cover Highlight issues that reappear after third-party or runtime replacement of the delegate.
    // - Handles CE_ItemViewItem and PE_PanelItemViewRow, without interfering with QHeaderView's CE_Header* drawing or palette.
    class TableSelectionOutlineProxyStyle final : public QProxyStyle
    {
    public:
        TableSelectionOutlineProxyStyle()
            : QProxyStyle(QStringLiteral("windowsvista"))
        {
        }

        void drawControl(
            const ControlElement element,
            const QStyleOption* option,
            QPainter* painter,
            const QWidget* widget = nullptr) const override
        {
            if (element == CE_ItemViewItem &&
                option != nullptr &&
                qobject_cast<const QTableView*>(widget) != nullptr)
            {
                if (const auto* itemOption = qstyleoption_cast<const QStyleOptionViewItem*>(option))
                {
                    QStyleOptionViewItem unselectedOption(*itemOption);
                    unselectedOption.state &= ~QStyle::State_Selected;
                    unselectedOption.state &= ~QStyle::State_HasFocus;
                    QProxyStyle::drawControl(element, &unselectedOption, painter, widget);
                    return;
                }
            }

            QProxyStyle::drawControl(element, option, painter, widget);
        }

        void drawPrimitive(
            const PrimitiveElement element,
            const QStyleOption* option,
            QPainter* painter,
            const QWidget* widget = nullptr) const override
        {
            // QTableView draws PE_PanelItemViewRow before the delegate draws.
            // QStyleSheetStyle falls back to this base style when encountering transparent item backgrounds,
            // causing CE_ItemViewItem to clear State_Selected but leaving the entire row highlighted.
            if (element == PE_PanelItemViewRow &&
                option != nullptr &&
                qobject_cast<const QTableView*>(widget) != nullptr)
            {
                if (const auto* itemOption = qstyleoption_cast<const QStyleOptionViewItem*>(option))
                {
                    QStyleOptionViewItem unselectedOption(*itemOption);
                    unselectedOption.state &= ~QStyle::State_Selected;
                    unselectedOption.state &= ~QStyle::State_HasFocus;
                    QProxyStyle::drawPrimitive(element, &unselectedOption, painter, widget);
                    return;
                }
            }

            QProxyStyle::drawPrimitive(element, option, painter, widget);
        }
    };

    // GlobalTableSelectionOutlineFilter:
    // - Install a unified delegate before the first display of QTableView/QTableWidget.
    // - Subsequently, tables created via lazy loading for Dock and popup windows will automatically share the same selection state.
    // - Tables with a dedicated delegate are explicitly skipped via dynamic properties to avoid breaking editing or custom painting.
    class GlobalTableSelectionOutlineFilter final : public QObject
    {
    public:
        explicit GlobalTableSelectionOutlineFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

        static void installDelegateForTable(QTableView* tableView)
        {
            if (tableView == nullptr)
            {
                return;
            }

            if (!tableView->property(kKswordTableSelectionOutlineStylePropertyName).toBool())
            {
                auto* selectionOutlineStyle = new TableSelectionOutlineProxyStyle();
                selectionOutlineStyle->setParent(tableView);
                tableView->setStyle(selectionOutlineStyle);
                tableView->setProperty(kKswordTableSelectionOutlineStylePropertyName, true);
            }

            if (tableView->property(kKswordCustomTableDelegatePropertyName).toBool() ||
                tableView->property(kKswordTableSelectionOutlineDelegatePropertyName).toBool())
            {
                return;
            }

            tableView->setItemDelegate(new TableSelectionOutlineDelegate(tableView));
            tableView->setProperty(kKswordTableSelectionOutlineDelegatePropertyName, true);
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr || eventObject->type() != QEvent::Show)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            installDelegateForTable(qobject_cast<QTableView*>(watchedObject));
            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // ensureGlobalContextMenuThemeFilterInstalled:
    // - Install the application-level QMenu theme filter once;
    // - Ensure all subsequently created context menus automatically inherit a fallback for both light and dark theme backgrounds.
    void ensureGlobalContextMenuThemeFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalContextMenuThemeFilter* contextMenuThemeFilter = nullptr;
        if (contextMenuThemeFilter == nullptr)
        {
            contextMenuThemeFilter = new GlobalContextMenuThemeFilter(appInstance);
            appInstance->installEventFilter(contextMenuThemeFilter);
        }

        static GlobalTopLevelTopMostFilter* topLevelTopMostFilter = nullptr;
        if (topLevelTopMostFilter == nullptr)
        {
            topLevelTopMostFilter = new GlobalTopLevelTopMostFilter(appInstance);
            appInstance->installEventFilter(topLevelTopMostFilter);
        }
    }

    // ensureGlobalComboPopupThemeFilterInstalled:
    // - Install the application-level combo box popup theme filter once.
    // - Also refresh created combo boxes to ensure the opaque background is used immediately upon the next expansion after a theme switch.
    void ensureGlobalComboPopupThemeFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalComboPopupThemeFilter* comboPopupThemeFilter = nullptr;
        if (comboPopupThemeFilter == nullptr)
        {
            comboPopupThemeFilter = new GlobalComboPopupThemeFilter(appInstance);
            appInstance->installEventFilter(comboPopupThemeFilter);
        }

        const QWidgetList kAllWidgetList = appInstance->allWidgets();
        for (QWidget* const kWidget : kAllWidgetList)
        {
            applyOpaqueComboPopupTheme(qobject_cast<QComboBox*>(kWidget));
        }
    }

    void ensureGlobalSliderWheelFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalTabIconContrastFilter* tabIconContrastFilter = nullptr;
        if (tabIconContrastFilter == nullptr)
        {
            tabIconContrastFilter = new GlobalTabIconContrastFilter(appInstance);
            appInstance->installEventFilter(tabIconContrastFilter);
        }

        static GlobalSliderWheelFilter* sliderWheelFilter = nullptr;
        if (sliderWheelFilter == nullptr)
        {
            sliderWheelFilter = new GlobalSliderWheelFilter(appInstance);
            appInstance->installEventFilter(sliderWheelFilter);
        }
    }

    void ensureGlobalTableSelectionOutlineFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalTableSelectionOutlineFilter* tableSelectionOutlineFilter = nullptr;
        if (tableSelectionOutlineFilter == nullptr)
        {
            tableSelectionOutlineFilter = new GlobalTableSelectionOutlineFilter(appInstance);
            appInstance->installEventFilter(tableSelectionOutlineFilter);
        }

        for (QWidget* widget : appInstance->allWidgets())
        {
            GlobalTableSelectionOutlineFilter::installDelegateForTable(
                qobject_cast<QTableView*>(widget));
        }
    }

    // applyApplicationFontToItemViews:
    // - Explicitly refresh the current application font for tables, trees, and lists to resolve issues where font inheritance remains at the startup default due to local QSS.
    // - Marks controls with ksword_preserve_custom_font to retain dedicated fonts, such as the monospace font in the hex editor.
    // - Usage: Called after each applyAppearanceSettings updates the QApplication font.
    // Input applicationFont: current application font family and anti-aliasing strategy; no return value.
    void applyApplicationFontToItemViews(const QFont& applicationFont)
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        constexpr const char* kPreserveCustomFontProperty = "ksword_preserve_custom_font";
        for (QWidget* widget : appInstance->allWidgets())
        {
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(widget);
            if (itemView == nullptr)
            {
                continue;
            }

            if (itemView->property(kPreserveCustomFontProperty).toBool())
            {
                continue;
            }

            itemView->setFont(applicationFont);
        }
    }
}

using namespace ksword::ui::main_window;

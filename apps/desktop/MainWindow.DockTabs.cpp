#include "MainWindow.h"

#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QWidget>
#include <QLabel>
#include <QList>
#include <QPainter>
#include <QPaintEvent>
#include <QPalette>
#include <QProgressBar>
#include <QMouseEvent>
#include <QEvent>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "include/ads/AutoHideTab.h"
#include "include/ads/DockComponentsFactory.h"
#include "include/ads/DockAreaWidget.h"
#include "include/ads/DockWidgetTab.h"
#include "ui/DockTabInteraction.h"
#include "Theme.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <functional>
#include <TlHelp32.h>

#include "MainWindow.DockTabsSupport.h"
#include "MainWindow.NativeFrameSupport.h"

namespace ksword::ui::main_window
{
    // kKswordDockTabPropertyName:
    // - Assign dynamic properties to ADS main dock tabs for final fallback QSS precise selection;
    // - Prevent QWidget:hover from affecting other controls in the Dock content area.
    constexpr const char* kKswordDockTabPropertyName = "kswordDockTab";

    // kKswordAutoHideTabPropertyName:
    // - Apply dynamic properties to ADS auto-hide side tabs;
    // - Use the same hover color as the main Dock tab, but keep the selector independent.
    constexpr const char* kKswordAutoHideTabPropertyName = "kswordAutoHideTab";

    // dockTabHoverFillColor:
    // - Returns the forced background fill color when the Dock tab is hovered;
    // - Use a weak emphasis background for hover on normal tabs; continue using the active emphasis background for hover on the currently selected tab.
    // - Avoid the selected Dock tab being painted over with light blue on hover in light mode.
    // Parameter activeTab: true indicates the current tab is the ADS selected tab.
    // Returns: The hover background QColor corresponding to the current theme and tab state.
    QColor dockTabHoverFillColor(const bool activeTab)
    {
        if (activeTab)
        {
            return ksword_theme::activeTabBackgroundColor();
        }
        return ksword_theme::primaryBlueSubtleColor();
    }

    // dockTabTextColor:
    // - Returns the final color for ADS Dock tab text;
    // - Select tab automatically chooses readable text color based on actual active background.
    // - Use the current theme's primary text color for unselected tabs.
    // Parameter activeTab: true indicates the currently selected tab; false indicates a regular tab.
    // Returns: A QColor directly writable to QWidget/QLabel palette and local stylesheets.
    QColor dockTabTextColor(const bool activeTab)
    {
        if (!activeTab)
        {
            return ksword_theme::textPrimaryColor();
        }

        // Active tabs use a dedicated foreground color; recalculate contrast based on the blended actual background.
        return ksword_theme::activeTabTextColor();
    }

    // shouldTemporarilyDropTopMostForDockSwitch：
    // - Input: No explicit input; reads QApplication global properties;
    // - Processing: Temporarily disable TOPMOST only if the current process has UIAccess and the main window is globally TOPMOST.
    // - Return: true indicates that NOTOPMOST/TOPMOST protection should be applied before and after the dock switch; false indicates no intervention.
    bool shouldTemporarilyDropTopMostForDockSwitch()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        return appInstance != nullptr
            && appInstance->property(kKswordProcessUiAccessPropertyName).toBool()
            && appInstance->property(kKswordMainWindowTopMostPropertyName).toBool();
    }

    // mainWindowHandleFromGlobalProperty：
    // - Input: No explicit input; reads the cached main window HWND from QApplication.
    // - Processing: Restore the qulonglong property to an HWND and validate it using IsWindow.
    // - Returns: a valid main window handle; returns nullptr if missing or invalid.
    HWND mainWindowHandleFromGlobalProperty()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return nullptr;
        }

        const HWND kWindowHandle = reinterpret_cast<HWND>(
            static_cast<quintptr>(appInstance->property(kKswordMainWindowHwndPropertyName).toULongLong()));
        return (kWindowHandle != nullptr && ::IsWindow(kWindowHandle) != FALSE) ? kWindowHandle : nullptr;
    }

    // setMainWindowTemporaryTopMost：
    // - Input: restores TOPMOST when topMostState is true; temporarily lowers to NOTOPMOST when false.
    // - Handling: Adjust only the main window's Win32 z-order; do not modify m_windowPinned, settings, or sync the title bar pin icon.
    // - Returns: true if SetWindowPos succeeds, otherwise false.
    bool setMainWindowTemporaryTopMost(const bool topMostState)
    {
        const HWND kWindowHandle = mainWindowHandleFromGlobalProperty();
        if (kWindowHandle == nullptr)
        {
            return false;
        }

        return ::SetWindowPos(
            kWindowHandle,
            topMostState ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER) != FALSE;
    }

    // withTemporaryNonTopMostForDockSwitch：
    // - Input: switchOperation is the actual Dock switch action
    // - Handling: Temporarily set NOTOPMOST before switching only when UIAccess+TOPMOST combination is active, then restore TOPMOST.
    // - Returns: None. If switchOperation is null, only performs the protection check without executing any action.
    void withTemporaryNonTopMostForDockSwitch(const std::function<void()>& switchOperation)
    {
        const bool kShouldDropTopMost = shouldTemporarilyDropTopMostForDockSwitch();
        if (kShouldDropTopMost)
        {
            setMainWindowTemporaryTopMost(false);
        }

        if (switchOperation)
        {
            switchOperation();
        }

        if (kShouldDropTopMost)
        {
            QTimer::singleShot(0, []()
                {
                    if (shouldTemporarilyDropTopMostForDockSwitch())
                    {
                        setMainWindowTemporaryTopMost(true);
                    }
                });
        }
    }

    // applyDockTabTextColor:
    // - Directly writes the text color for the ADS tab body and its internal QLabel/CElidingLabel.
    // - Bypasses the issue where parent QSS selectors do not apply to ADS internal tab controls or are overridden by hover rules.
    // Input tabWidget: ADS main tab or auto-hidden side tab.
    // Parameter activeTab: true = selected tab; false = normal tab.
    // Return: void; updates palette/styleSheet only when colors change to avoid StyleChange storms.
    void applyDockTabTextColor(QWidget* tabWidget, const bool activeTab)
    {
        if (tabWidget == nullptr)
        {
            return;
        }

        const QColor kFinalTextColor = dockTabTextColor(activeTab);
        const QString kFinalTextColorName = kFinalTextColor.name(QColor::HexRgb).toUpper();

        if (tabWidget->property("kswordDockTabTextColor").toString() != kFinalTextColorName)
        {
            QPalette tabPalette = tabWidget->palette();
            tabPalette.setColor(QPalette::WindowText, kFinalTextColor);
            tabPalette.setColor(QPalette::Text, kFinalTextColor);
            tabPalette.setColor(QPalette::ButtonText, kFinalTextColor);
            tabWidget->setPalette(tabPalette);
            tabWidget->setProperty("kswordDockTabTextColor", kFinalTextColorName);
        }

        const QString kLabelStyle = QStringLiteral(
            "color:%1 !important;"
            "background-color:transparent !important;"
            "background:transparent !important;"
            "font-weight:%2;")
            .arg(kFinalTextColorName)
            .arg(activeTab ? QStringLiteral("700") : QStringLiteral("600"));

        const QList<QLabel*> kLabelChildren = tabWidget->findChildren<QLabel*>();
        for (QLabel* labelWidget : kLabelChildren)
        {
            if (labelWidget == nullptr)
            {
                continue;
            }

            QPalette labelPalette = labelWidget->palette();
            labelPalette.setColor(QPalette::WindowText, kFinalTextColor);
            labelPalette.setColor(QPalette::Text, kFinalTextColor);
            labelPalette.setColor(QPalette::ButtonText, kFinalTextColor);
            labelWidget->setPalette(labelPalette);

            if (labelWidget->styleSheet() != kLabelStyle)
            {
                labelWidget->setStyleSheet(kLabelStyle);
            }
        }
    }

    // configureDockTabStyleSurface:
    // - Enables QSS/hover background drawing properties for ADS tabs and their direct child controls.
    // - This is a one-time initialization; do not modify the stylesheet in the event filter to avoid StyleChange recursion.
    // Input parameters: tabWidget is the ADS tab QWidget; propertyName is the dynamic property name to write.
    // Returns: Nothing.
    void configureDockTabStyleSurface(QWidget* tabWidget, const char* propertyName)
    {
        if (tabWidget == nullptr || propertyName == nullptr)
        {
            return;
        }

        tabWidget->setProperty(propertyName, true);
        tabWidget->setAttribute(Qt::WA_Hover, true);
        tabWidget->setAttribute(Qt::WA_StyledBackground, true);
        tabWidget->setAutoFillBackground(false);
        tabWidget->setMouseTracking(true);

        // Sub QLabel/QWidget instances are the actual containers for ADS tab text and icons.
        // Process only direct children to avoid inadvertently modifying business controls within Dock content pages.
        const QList<QWidget*> kDirectChildren =
            tabWidget->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
        for (QWidget* childWidget : kDirectChildren)
        {
            if (childWidget == nullptr)
            {
                continue;
            }
            childWidget->setAttribute(Qt::WA_Hover, true);
            childWidget->setAttribute(Qt::WA_StyledBackground, true);
            childWidget->setAutoFillBackground(false);
        }
    }

    // configureAdsDockTabVisualIdentity:
    // - Also mark the main tab and auto-hide side tab of a CDockWidget;
    // - Safety fallback used after creation, after layout restoration, and when synchronizing the appearance of floating windows.
    // Parameter dockWidget: the ADS Dock to process; returns immediately if null.
    // Returns: Nothing.
    void configureAdsDockTabVisualIdentity(ads::CDockWidget* dockWidget)
    {
        if (dockWidget == nullptr)
        {
            return;
        }

        configureDockTabStyleSurface(dockWidget->tabWidget(), kKswordDockTabPropertyName);
        configureDockTabStyleSurface(dockWidget->sideTabWidget(), kKswordAutoHideTabPropertyName);
    }

    // refreshAdsDockTabVisualIdentities:
    // - Scan for existing ADS tabs under a given root widget and complete their dynamic properties;
    // - Applies to tabs generated or migrated after restoreState or floating window creation.
    // Parameter rootWidget: scan root node; return immediately if null.
    // Returns: Nothing.
    void refreshAdsDockTabVisualIdentities(QWidget* rootWidget)
    {
        if (rootWidget == nullptr)
        {
            return;
        }

        const QList<ads::CDockWidgetTab*> kDockTabs =
            rootWidget->findChildren<ads::CDockWidgetTab*>();
        for (ads::CDockWidgetTab* dockTab : kDockTabs)
        {
            configureDockTabStyleSurface(dockTab, kKswordDockTabPropertyName);
            applyDockTabTextColor(dockTab, dockTab->property("activeTab").toBool());
        }

        const QList<ads::CAutoHideTab*> kAutoHideTabs =
            rootWidget->findChildren<ads::CAutoHideTab*>();
        for (ads::CAutoHideTab* autoHideTab : kAutoHideTabs)
        {
            configureDockTabStyleSurface(autoHideTab, kKswordAutoHideTabPropertyName);
            applyDockTabTextColor(autoHideTab, autoHideTab->property("activeTab").toBool());
        }
    }

    // updateLazyDockPlaceholderProgress:
    // - Update the progress bar on the placeholder page with the progress and text for each lazy-loading stage.
    // During page construction, the UI thread's event loop does not process events, so standard update() calls for
    //   repaints are deferred until construction ends (by which time the placeholder has been replaced, meaning it
    //   never rendered). Therefore, repaint() must be called here to force immediate rendering; repaint is synchronous
    //   and does not dispatch events, eliminating the risk of re-entering delayed initialization via processEvents.
    // Input dockWidget: the dock being initialized. Silently return if null or if the placeholder page is not visible.
    // Parameter stageText: current stage text displayed directly to the user.
    // Input progressPercent: progress value from 0 to 100; out-of-range values are clamped.
    // Returns: Nothing.
    void updateLazyDockPlaceholderProgress(
        ads::CDockWidget* dockWidget,
        const QString& stageText,
        const int progressPercent)
    {
        if (dockWidget == nullptr)
        {
            return;
        }

        // placeholderWidget usage: The placeholder page currently attached to the dock.
        // After real content is mounted, this no longer refers to the placeholder page, so findChild naturally fails to locate the progress bar.
        QWidget* const kPlaceholderWidget = dockWidget->widget();
        if (kPlaceholderWidget == nullptr || !kPlaceholderWidget->isVisible())
        {
            return;
        }

        QProgressBar* const kLoadProgressBar = kPlaceholderWidget->findChild<QProgressBar*>(
            QString::fromLatin1(kLazyDockPlaceholderProgressBarObjectName));
        QLabel* const kStageLabel = kPlaceholderWidget->findChild<QLabel*>(
            QString::fromLatin1(kLazyDockPlaceholderStageLabelObjectName));
        if (kLoadProgressBar == nullptr && kStageLabel == nullptr)
        {
            return;
        }

        if (kLoadProgressBar != nullptr)
        {
            kLoadProgressBar->setValue(qBound(0, progressPercent, 100));
        }
        if (kStageLabel != nullptr)
        {
            kStageLabel->setText(stageText);
        }
        kPlaceholderWidget->repaint();
    }

    bool isDockWidgetActiveForLazyInitialization(
        ads::CDockWidget* dockWidget,
        ads::CDockWidget* focusedDockWidget)
    {
        if (dockWidget == nullptr)
        {
            return false;
        }

        if (dockWidget == focusedDockWidget || dockWidget->isCurrentTab())
        {
            return true;
        }

        ads::CDockAreaWidget* dockAreaWidget = dockWidget->dockAreaWidget();
        if (dockAreaWidget != nullptr)
        {
            return dockAreaWidget->isVisible() && dockAreaWidget->currentDockWidget() == dockWidget;
        }

        return dockWidget->isVisible();
    }

    // KswordAdsDockWidgetTab:
    // - Replace the default ADS CDockWidgetTab;
    // - On hover, the tab itself draws a dark background to bypass occasional white backgrounds caused by ADS or system default styles.
    // Input: receives the owning CDockWidget and an optional parent QWidget during construction.
    // Note: initialize QSS recognition attributes; on hover/leave, trigger only repaint without modifying the stylesheet.
    // Return: Constructor has no return; event returns base class event handling result; paintEvent has no return.
    class KswordAdsDockWidgetTab final : public ads::CDockWidgetTab
    {
    public:
        explicit KswordAdsDockWidgetTab(ads::CDockWidget* dockWidget, QWidget* parent = nullptr)
            : ads::CDockWidgetTab(dockWidget, parent)
        {
            configureDockTabStyleSurface(this, kKswordDockTabPropertyName);
            syncDockTabTextColor();
            QObject::connect(
                this,
                &ads::CDockWidgetTab::activeTabChanged,
                this,
                [this]()
                {
                    syncDockTabTextColor();
                    update();
                });
        }

    protected:
        bool event(QEvent* eventObject) override
        {
            const bool kShouldGuardDockSwitch =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::MouseButtonPress ||
                    eventObject->type() == QEvent::MouseButtonRelease) &&
                static_cast<QMouseEvent*>(eventObject)->button() == Qt::LeftButton &&
                !property("activeTab").toBool();
            const bool kShouldRepaintAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::Enter ||
                    eventObject->type() == QEvent::Leave ||
                    eventObject->type() == QEvent::HoverEnter ||
                    eventObject->type() == QEvent::HoverLeave ||
                    eventObject->type() == QEvent::HoverMove);
            const bool kShouldSyncTextAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::DynamicPropertyChange ||
                    eventObject->type() == QEvent::PaletteChange ||
                    eventObject->type() == QEvent::ApplicationPaletteChange ||
                    eventObject->type() == QEvent::StyleChange ||
                    eventObject->type() == QEvent::Polish ||
                    eventObject->type() == QEvent::Show);

            bool handled = false;
            if (kShouldGuardDockSwitch)
            {
                withTemporaryNonTopMostForDockSwitch([this, eventObject, &handled]()
                    {
                        handled = ads::CDockWidgetTab::event(eventObject);
                    });
            }
            else
            {
                handled = ads::CDockWidgetTab::event(eventObject);
            }
            if (kShouldSyncTextAfterEvent)
            {
                syncDockTabTextColor();
            }
            if (kShouldRepaintAfterEvent)
            {
                update();
            }
            return handled;
        }

        void paintEvent(QPaintEvent* paintEventObject) override
        {
            ads::CDockWidgetTab::paintEvent(paintEventObject);
            if (!isEnabled() || !underMouse())
            {
                return;
            }

            // Draw a solid background layer on top of the base class QFrame/QSS rendering to cover the ADS/system default white background.
            // The selected tab must retain the main blue background to prevent it from turning light blue during hover in light mode.
            // Child QLabel widgets are drawn after the parent control's paintEvent returns, ensuring the text is not obscured.
            const bool kActiveTab = property("activeTab").toBool();
            QPainter painter(this);
            painter.setPen(Qt::NoPen);
            painter.setBrush(dockTabHoverFillColor(kActiveTab));
            painter.drawRect(paintEventObject != nullptr ? paintEventObject->rect() : rect());
        }

    private:
        // syncDockTabTextColor:
        // - Read the ADS activeTab property;
        // - Synchronize the text color to be used under the current theme to the tab body and its internal QLabel.
        // Input: No explicit parameters; Depends on the current object's 'activeTab' dynamic property and global theme state.
        // Returns: Nothing.
        void syncDockTabTextColor()
        {
            applyDockTabTextColor(this, property("activeTab").toBool());
        }
    };

    // KswordAdsAutoHideTab:
    // - Replace ADS default auto-hide tabs.
    // - Preserve the original ADS drawing logic, only supplement hover/QSS properties and trigger repaint on hover changes.
    // Input: receives the owning CDockWidget and an optional parent QWidget during construction.
    // Processing: Set Dock association and style properties; do not modify the stylesheet.
    // Return: Constructor has no return; event returns base class event handling result.
    class KswordAdsAutoHideTab final : public ads::CAutoHideTab
    {
    public:
        explicit KswordAdsAutoHideTab(ads::CDockWidget* dockWidget, QWidget* parent = nullptr)
            : ads::CAutoHideTab(parent)
        {
            setDockWidget(dockWidget);
            configureDockTabStyleSurface(this, kKswordAutoHideTabPropertyName);
            syncDockTabTextColor();
        }

    protected:
        bool event(QEvent* eventObject) override
        {
            const bool kShouldRepaintAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::Enter ||
                    eventObject->type() == QEvent::Leave ||
                    eventObject->type() == QEvent::HoverEnter ||
                    eventObject->type() == QEvent::HoverLeave ||
                    eventObject->type() == QEvent::HoverMove);
            const bool kShouldSyncTextAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::DynamicPropertyChange ||
                    eventObject->type() == QEvent::PaletteChange ||
                    eventObject->type() == QEvent::ApplicationPaletteChange ||
                    eventObject->type() == QEvent::StyleChange ||
                    eventObject->type() == QEvent::Polish ||
                    eventObject->type() == QEvent::Show);

            const bool kHandled = ads::CAutoHideTab::event(eventObject);
            if (kShouldSyncTextAfterEvent)
            {
                syncDockTabTextColor();
            }
            if (kShouldRepaintAfterEvent)
            {
                update();
            }
            return kHandled;
        }

    private:
        // syncDockTabTextColor:
        // - Read the ADS activeTab property;
        // - Synchronizes the text color to be used under the current theme to the auto-hide tab body and internal QLabel.
        // Input: No explicit parameters; Depends on the current object's 'activeTab' dynamic property and global theme state.
        // Returns: Nothing.
        void syncDockTabTextColor()
        {
            applyDockTabTextColor(this, property("activeTab").toBool());
        }
    };

    // KswordAdsDockComponentsFactory:
    // - Instructs ADS to use the Ksword custom tab class when creating Dock tabs.
    // - Preserve the default factory behavior for other ADS components to minimize the scope of changes.
    // Input: CDockWidget passed by ADS when creating a tab.
    // Note: Return instances of custom main tabs and auto-hide tabs.
    // Returns: A newly created CDockWidgetTab or CAutoHideTab; ownership is transferred to ADS.
    class KswordAdsDockComponentsFactory final : public ads::CDockComponentsFactory
    {
    public:
        ads::CDockWidgetTab* createDockWidgetTab(ads::CDockWidget* dockWidget) const override
        {
            return new KswordAdsDockWidgetTab(dockWidget);
        }

        ads::CAutoHideTab* createDockWidgetSideTab(ads::CDockWidget* dockWidget) const override
        {
            return new KswordAdsAutoHideTab(dockWidget);
        }
    };

    // ensureKswordAdsDockComponentsFactoryInstalled:
    // - Installs a custom ADS component factory once before CDockManager creation.
    // - Prevent the default CDockWidgetTab from exposing a system white background during dark hover.
    // Return: None; repeated calls are ignored by the static flag.
    void ensureKswordAdsDockComponentsFactoryInstalled()
    {
        static bool installed = false;
        if (installed)
        {
            return;
        }

        ads::CDockComponentsFactory::setFactory(new KswordAdsDockComponentsFactory());
        installed = true;
    }
}

using namespace ksword::ui::main_window;

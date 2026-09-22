#include "WindowChrome.h"

#include "../Theme.h"

#include <QApplication>
#include <QColor>
#include <QEvent>
#include <QPointer>
#include <QVariant>
#include <QWidget>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dwmapi.h>
#pragma comment(lib, "Dwmapi.lib")
#endif

namespace
{
#ifdef Q_OS_WIN
    // kDwmUseImmersiveDarkModeAttribute:
    // - DWMWA_USE_IMMERSIVE_DARK_MODE（Win10 20H1+）；
    // - Enable native title bar to use system dark rendering strategy in dark mode.
    constexpr DWORD kDwmUseImmersiveDarkModeAttribute = 20;
    // kDwmBorderColorAttribute:
    // - DWMWA_BORDER_COLOR (Win11+), controls the thin window border color.
    constexpr DWORD kDwmBorderColorAttribute = 34;
    // kDwmCaptionColorAttribute:
    // - DWMWA_CAPTION_COLOR (Win11+): directly tint the title bar to the specified color.
    // - This is the key attribute that integrates the child window title bar with the theme background.
    constexpr DWORD kDwmCaptionColorAttribute = 35;
    // kDwmTextColorAttribute:
    // - DWMWA_CAPTION_TEXT_COLOR (Win11+), controls the title bar text color.
    constexpr DWORD kDwmTextColorAttribute = 36;

    // kChromeAppliedKeyPropertyName:
    // - Cache the theme fingerprint (light/dark mode, title bar color, text color) last applied to the window.
    // - Skip redundant DWM calls when the theme has not changed.
    constexpr const char* kChromeAppliedKeyPropertyName = "ksword_window_chrome_applied_key";

    // toColorRef purpose: convert QColor to 0x00BBGGRR COLORREF required by DWM.
    COLORREF toColorRef(const QColor& colorValue)
    {
        return RGB(colorValue.red(), colorValue.green(), colorValue.blue());
    }
#endif

    // shouldApplyChromeToWidget:
    // - Determine if a window should have its title bar styled by this module.
    // - Skip borderless windows (main window, startup page, notification cards, ThemedMessageBox) as they lack native title bars.
    // - Skip transient surfaces such as Popup/ToolTip, which also have no title bar.
    bool shouldApplyChromeToWidget(const QWidget* widgetPointer)
    {
        if (widgetPointer == nullptr || !widgetPointer->isWindow())
        {
            return false;
        }
        const Qt::WindowFlags kWindowFlags = widgetPointer->windowFlags();
        if ((kWindowFlags & Qt::FramelessWindowHint) != 0)
        {
            return false;
        }
        const Qt::WindowType kWindowType =
            static_cast<Qt::WindowType>(static_cast<int>(kWindowFlags & Qt::WindowType_Mask));
        switch (kWindowType)
        {
        case Qt::Popup:
        case Qt::ToolTip:
        case Qt::SplashScreen:
        case Qt::Desktop:
            return false;
        default:
            break;
        }
        return true;
    }

    // WindowChromeStyler:
    // - QApplication-level event filter;
    // - Write the theme title bar color to DWM when the top-level window is first displayed.
    class WindowChromeStyler final : public QObject
    {
    public:
        explicit WindowChromeStyler(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        // eventFilter:
        // - Listen for the top-level window Show event (at this point, the native handle is guaranteed to be created).
        // - WinIdChange handles fallback scenarios for handle reconstruction (e.g., after switching window flags).
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr
                || (eventObject->type() != QEvent::Show
                    && eventObject->type() != QEvent::WinIdChange))
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* widgetPointer = qobject_cast<QWidget*>(watchedObject);
            if (widgetPointer != nullptr && shouldApplyChromeToWidget(widgetPointer))
            {
                ks::ui::applyWindowChrome(widgetPointer);
            }
            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // windowChromeStylerInstance:
    // - Returns the title bar styler singleton;
    // - Singleton parent object binds to QApplication to avoid manual release.
    WindowChromeStyler* windowChromeStylerInstance()
    {
        static QPointer<WindowChromeStyler> stylerInstance;
        if (stylerInstance == nullptr && qApp != nullptr)
        {
            stylerInstance = new WindowChromeStyler(qApp);
        }
        return stylerInstance.data();
    }
}

namespace ks::ui
{
    void applyWindowChrome(QWidget* topLevelWidget)
    {
#ifdef Q_OS_WIN
        if (!shouldApplyChromeToWidget(topLevelWidget))
        {
            return;
        }
        // Do not actively trigger winId when a native handle is not created, to avoid introducing reentrancy during early window construction.
        if (!topLevelWidget->testAttribute(Qt::WA_WState_Created))
        {
            return;
        }
        const HWND kWindowHandle = reinterpret_cast<HWND>(topLevelWidget->winId());
        if (kWindowHandle == nullptr || ::IsWindow(kWindowHandle) == FALSE)
        {
            return;
        }

        const bool kDarkModeEnabled = ksword_theme::isDarkModeEnabled();
        // captionColor usage: The title bar and window background use the same role, visually blending together.
        const QColor kCaptionColor = ksword_theme::windowColor();
        const QColor kCaptionTextColor = ksword_theme::mainBackgroundTextColor();
        const QColor kBorderColor = ksword_theme::borderColor();

        // appliedKey purpose: theme fingerprint; skip redundant DWM writes if unchanged.
        const QString kAppliedKey = QStringLiteral("%1|%2|%3|%4")
            .arg(kDarkModeEnabled ? 1 : 0)
            .arg(kCaptionColor.rgb())
            .arg(kCaptionTextColor.rgb())
            .arg(kBorderColor.rgb());
        if (topLevelWidget->property(kChromeAppliedKeyPropertyName).toString() == kAppliedKey)
        {
            return;
        }
        topLevelWidget->setProperty(kChromeAppliedKeyPropertyName, kAppliedKey);

        // Windows 10 20H1+: dark mode rendering strategy (minimum guarantee when Windows 11 tinting attributes are unavailable).
        const BOOL kImmersiveDarkModeValue = kDarkModeEnabled ? TRUE : FALSE;
        (void)::DwmSetWindowAttribute(
            kWindowHandle,
            kDwmUseImmersiveDarkModeAttribute,
            &kImmersiveDarkModeValue,
            sizeof(kImmersiveDarkModeValue));

        // Windows 11+: Directly colors the title bar, text, and border; older systems return E_INVALIDARG, which is silently ignored.
        const COLORREF kCaptionColorValue = toColorRef(kCaptionColor);
        (void)::DwmSetWindowAttribute(
            kWindowHandle,
            kDwmCaptionColorAttribute,
            &kCaptionColorValue,
            sizeof(kCaptionColorValue));

        const COLORREF kCaptionTextColorValue = toColorRef(kCaptionTextColor);
        (void)::DwmSetWindowAttribute(
            kWindowHandle,
            kDwmTextColorAttribute,
            &kCaptionTextColorValue,
            sizeof(kCaptionTextColorValue));

        const COLORREF kBorderColorValue = toColorRef(kBorderColor);
        (void)::DwmSetWindowAttribute(
            kWindowHandle,
            kDwmBorderColorAttribute,
            &kBorderColorValue,
            sizeof(kBorderColorValue));
#else
        Q_UNUSED(topLevelWidget);
#endif
    }

    void installWindowChrome(QApplication* appInstance)
    {
        if (appInstance == nullptr)
        {
            return;
        }

        WindowChromeStyler* stylerInstance = windowChromeStylerInstance();
        if (stylerInstance == nullptr)
        {
            return;
        }

        appInstance->installEventFilter(stylerInstance);
        refreshAllWindowChrome();
    }

    void refreshAllWindowChrome()
    {
        if (qApp == nullptr)
        {
            return;
        }

        const QWidgetList kTopLevelWidgetList = qApp->topLevelWidgets();
        for (QWidget* topLevelWidget : kTopLevelWidgetList)
        {
            applyWindowChrome(topLevelWidget);
        }
    }
}

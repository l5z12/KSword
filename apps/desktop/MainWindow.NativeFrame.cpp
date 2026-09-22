#include "MainWindow.h"
#include <QWindow>

#include <QMenu>
#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QGuiApplication>
#include <QScreen>
#include <QWidget>
#include <QMargins>
#include <QPainter>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QDialog>
#include <QMetaObject>
#include <QMouseEvent>
#include <QEvent>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "framework/NotificationCardManager.h"
#include "framework/CustomTitleBar.h"
#include "include/ads/FloatingDockContainer.h"
#include "../../shared/ark_client/ArkDriverClient.h"
#include "Theme.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <TlHelp32.h>

#pragma comment(lib, "Dwmapi.lib")

#include "MainWindow.DockingSupport.h"
#include "MainWindow.NativeFrameSupport.h"
#include "MainWindow.Win32PrivilegesSupport.h"

namespace ksword::ui::main_window
{
    constexpr wchar_t kKswordMainWindowPropertyName[] = L"KswordARK.MainWindow.Singleton.Release";

    constexpr ULONG_PTR kUnlockerCopyDataMessageId = 0x4B535755; // "KSWU"：Ksword shell unlocker IPC。

    constexpr int kResizeBorderOverlayWidth = 3;

    constexpr int kResizeCornerTriangleLeg = 6;

    // makeNativeMouseLParam：
    // - Input globalPoint: Global coordinates provided by the Qt mouse event;
    // - Processing: Pack signed x/y into Win32 mouse message format.
    // - Returns: A LPARAM directly usable with WM_NCLBUTTONDOWN.
    LPARAM makeNativeMouseLParam(const QPoint& globalPoint)
    {
        return MAKELPARAM(
            static_cast<SHORT>(globalPoint.x()),
            static_cast<SHORT>(globalPoint.y()));
    }

    // isNativeResizeHitTestCode：
    // - Input: Windows non-client area hit test return value;
    // - Processing: Determine if the hit test belongs to one of the eight borders/corners for resizing;
    // - Returns: true indicates that subsequent WM_NCLBUTTONDOWN events must be passed to DefWindowProc to initiate system scaling.
    bool isNativeResizeHitTestCode(const WPARAM hitTestCode)
    {
        return hitTestCode == HTLEFT
            || hitTestCode == HTRIGHT
            || hitTestCode == HTTOP
            || hitTestCode == HTBOTTOM
            || hitTestCode == HTTOPLEFT
            || hitTestCode == HTTOPRIGHT
            || hitTestCode == HTBOTTOMLEFT
            || hitTestCode == HTBOTTOMRIGHT;
    }

    // cursorForResizeHitTestCode：
    // - Input hitTestCode: Win32 border resize hit test value.
    // - Processing: Convert to Qt cursor shape.
    // - Returns: The corresponding resize cursor; an arrow cursor for non-resize hit tests.
    Qt::CursorShape cursorForResizeHitTestCode(const WPARAM hitTestCode)
    {
        switch (hitTestCode)
        {
        case HTLEFT:
        case HTRIGHT:
            return Qt::SizeHorCursor;
        case HTTOP:
        case HTBOTTOM:
            return Qt::SizeVerCursor;
        case HTTOPLEFT:
        case HTBOTTOMRIGHT:
            return Qt::SizeFDiagCursor;
        case HTTOPRIGHT:
        case HTBOTTOMLEFT:
            return Qt::SizeBDiagCursor;
        default:
            return Qt::ArrowCursor;
        }
    }

    // ResizeCornerTriangleWidget:
    // - Input: Specifies the bottom-left or bottom-right corner during construction.
    // - Processing: Draw a right-triangle hint area within an independent 6x6 overlay control.
    // - Return: Constructor has no return value; paintEvent has no return value and is responsible solely for visual rendering.
    class ResizeCornerTriangleWidget final : public QWidget
    {
    public:
        enum class Corner
        {
            kBottomLeft,
            kBottomRight
        };

        explicit ResizeCornerTriangleWidget(const Corner corner, QWidget* parent = nullptr)
            : QWidget(parent)
            , corner_(corner)
        {
            setAttribute(Qt::WA_NoSystemBackground, true);
            setAttribute(Qt::WA_TranslucentBackground, true);
            setAutoFillBackground(false);
            setMouseTracking(true);
        }

    protected:
        void paintEvent(QPaintEvent* event) override
        {
            Q_UNUSED(event);

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, false);
            painter.setPen(Qt::NoPen);
            painter.setBrush(ksword_theme::accentColor(ksword_theme::AccentRole::kBlue));

            const int kRight = std::max(0, width() - 1);
            const int kBottom = std::max(0, height() - 1);
            QPoint trianglePoints[3];
            if (corner_ == Corner::kBottomLeft)
            {
                trianglePoints[0] = QPoint(0, kBottom);
                trianglePoints[1] = QPoint(0, 0);
                trianglePoints[2] = QPoint(kRight, kBottom);
            }
            else
            {
                trianglePoints[0] = QPoint(kRight, kBottom);
                trianglePoints[1] = QPoint(kRight, 0);
                trianglePoints[2] = QPoint(0, kBottom);
            }

            painter.drawPolygon(trianglePoints, 3);
        }

    private:
        Corner corner_; // m_corner: Marks whether the current control draws a triangle at the bottom-left or bottom-right corner.
    };

    // Windows ZBID constants:
    // - ZBID_DEFAULT: standard desktop window band.
    // - ZBID_UIACCESS: the accessibility band that a UIAccess token may attempt to use.
    // - Dynamically call SetWindowBand here to avoid direct link failures on older or restricted systems where the export is missing.
    constexpr DWORD kWindowBandDefault = 0;

    constexpr DWORD kWindowBandUiAccess = 2;

    using SetWindowBandFunction = BOOL(WINAPI*)(HWND, HWND, DWORD);

    // resolveSetWindowBandFunction:
    // - Dynamically resolve SetWindowBand from user32.dll;
    // - This API is not statically linked; on failure, it falls back at most to HWND_TOPMOST.
    // Returns: a function pointer; returns nullptr if unavailable.
    SetWindowBandFunction resolveSetWindowBandFunction()
    {
        // cachedFunction purpose: Cache dynamic resolution results to avoid repeatedly querying the user32 export table on each pin toggle.
        static const SetWindowBandFunction kCachedFunction = []() -> SetWindowBandFunction {
            HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
            if (user32ModuleHandle == nullptr)
            {
                user32ModuleHandle = ::LoadLibraryW(L"user32.dll");
            }
            if (user32ModuleHandle == nullptr)
            {
                return nullptr;
            }

            return reinterpret_cast<SetWindowBandFunction>(
                ::GetProcAddress(user32ModuleHandle, "SetWindowBand"));
        }();
        return kCachedFunction;
    }

    // isCurrentProcessUiAccessTokenEnabled:
    // - Query whether the current process token has TokenUIAccess enabled;
    // - Only attempt UIAccess band when UIAccess is enabled to avoid meaningless calls with standard permissions.
    // Returns: true if the current instance has UIAccess; false if using a standard token or if the query failed.
    bool isCurrentProcessUiAccessTokenEnabled()
    {
        // enabled purpose: TokenUIAccess is fixed for the process lifetime; cache the result after the first query.
        static const bool kEnabled = []() -> bool {
            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
            {
                return false;
            }

            DWORD uiAccessValue = 0;
            DWORD returnedLength = 0;
            const BOOL kQueryOk = ::GetTokenInformation(
                tokenHandle,
                TokenUIAccess,
                &uiAccessValue,
                sizeof(uiAccessValue),
                &returnedLength);
            ::CloseHandle(tokenHandle);
            return kQueryOk != FALSE && uiAccessValue != 0;
        }();
        return kEnabled;
    }

    // tryApplyUiAccessWindowBand:
    // - When the current process already has the UIAccess flag, attempt to place the window in the UIAccess band.
    // - Attempt to restore the DEFAULT band when unpinning;
    // - This is best-effort: retains the HWND_TOPMOST/NOTOPMOST main path even when system policies reject the request.
    // Input windowHandle: main window HWND;
    // Input parameter pinnedState: true = attempt UIAccess + TopMost, false = attempt to restore the default band.
    // Returns: true if the band toggle succeeded; false if UIAccess is not enabled, the API is unavailable, or the system denied the request.
    bool tryApplyUiAccessWindowBand(const HWND windowHandle, const bool pinnedState)
    {
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return false;
        }

        if (!isCurrentProcessUiAccessTokenEnabled())
        {
            return false;
        }

        const SetWindowBandFunction kSetWindowBand = resolveSetWindowBandFunction();
        if (kSetWindowBand == nullptr)
        {
            return false;
        }

        // targetBand usage: Attempt UIAccess band when pinning; fall back to DEFAULT band when unpinned.
        const DWORD kTargetBand = pinnedState ? kWindowBandUiAccess : kWindowBandDefault;
        // insertAfterHandle purpose: Ensure the window remains at the front within the UIAccess band; remove topmost status when restoring defaults.
        const HWND kInsertAfterHandle = pinnedState ? HWND_TOPMOST : HWND_NOTOPMOST;
        return kSetWindowBand(windowHandle, kInsertAfterHandle, kTargetBand) != FALSE;
    }

    // applyHighestPermittedTopMostLevel:
    // - Promote the main window to the highest permitted topmost level within the current process's permission scope;
    // - UIAccess token prioritizes UIAccess band + HWND_TOPMOST; standard token falls back to HWND_TOPMOST.
    // - Additionally attempt BringWindowToTop/SetForegroundWindow to push the same-level sorting as far forward as possible;
    // - Foreground permissions may be denied by system policies; denial does not affect the HWND_TOPMOST result.
    // Call method: invoked internally by mainWindow::setPinnedWindowState.
    // Input windowHandle: main window HWND;
    // Input pinnedState: true = pin to topmost and attempt to raise to topmost level; false = unpin.
    // Input parameter errorCodeOut: outputs GetLastError if SetWindowPos fails.
    // Input parameter: uiAccessBandAppliedOut is an optional output indicating whether the UIAccess band was successfully applied.
    // Returns: true if core top-most or unpinning succeeded; false if SetWindowPos failed.
    bool applyHighestPermittedTopMostLevel(
        const HWND windowHandle,
        const bool pinnedState,
        DWORD* errorCodeOut,
        bool* uiAccessBandAppliedOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (uiAccessBandAppliedOut != nullptr)
        {
            *uiAccessBandAppliedOut = false;
        }

        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_WINDOW_HANDLE;
            }
            return false;
        }

        // UIAccess band purpose: If the current instance already has UIAccess, attempt to apply a higher accessibility window band first.
        // Failure is not treated as a core error, since standard HWND_TOPMOST remains a public, stable fallback path.
        const bool kUiAccessBandApplied = tryApplyUiAccessWindowBand(windowHandle, pinnedState);
        if (uiAccessBandAppliedOut != nullptr)
        {
            *uiAccessBandAppliedOut = kUiAccessBandApplied;
        }

        // insertAfterHandle usage: Selects the highest z-order level in the Win32 public scope that the current privilege can operate on.
        const HWND kInsertAfterHandle = pinnedState ? HWND_TOPMOST : HWND_NOTOPMOST;
        // setWindowPositionFlags usage: may call set-top-most during construction; prohibits SWP_SHOWWINDOW from prematurely displaying a half-initialized window.
        const UINT kSetWindowPositionFlags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;

        const BOOL kSetTopMostResult = ::SetWindowPos(
            windowHandle,
            kInsertAfterHandle,
            0,
            0,
            0,
            0,
            kSetWindowPositionFlags);
        if (kSetTopMostResult == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        if (pinnedState)
        {
            // If foreground switching is permitted by current permissions, move the window to the front at the same level; do not roll back the z-order on failure.
            ::BringWindowToTop(windowHandle);
            ::SetForegroundWindow(windowHandle);
        }
        return true;
    }

    // isKswordPopupTopMostTrackingEnabled:
    // - Inputs: None;
    // - Processing: Read from QApplication attributes whether the main window is currently topmost.
    // - Return: true indicates that subsequently popped-up QDialog/QMenu should also remain TOPMOST to avoid being obscured by the main window.
    bool isKswordPopupTopMostTrackingEnabled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        return appInstance != nullptr
            && appInstance->property(kKswordMainWindowTopMostPropertyName).toBool();
    }

    // applyTopMostToTopLevelWidget:
    // - Input widget: Qt top-level window; topMostState: target topmost state;
    // - Processing: Synchronize top-level windows such as pop-ups, new tool windows, and detail windows to TOPMOST/NOTOPMOST.
    // - Returns: No return value; failures are silent because topmost synchronization must not block the original window lifecycle.
    void applyTopMostToTopLevelWidget(QWidget* widget, const bool topMostState)
    {
        if (widget == nullptr || !widget->isWindow())
        {
            return;
        }

        const HWND kWindowHandle = reinterpret_cast<HWND>(widget->winId());
        if (kWindowHandle == nullptr || ::IsWindow(kWindowHandle) == FALSE)
        {
            return;
        }

        (void)::SetWindowPos(
            kWindowHandle,
            topMostState ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
    }

    // syncTopMostForAllAuxiliaryTopLevelWidgets:
    // - Input mainWindow: main window pointer; topMostState: target topmost state;
    // - Processing: Iterate through current Qt top-level windows and uniformly inherit or remove the top-most state for all auxiliary windows except the main window.
    // - Returns: Nothing.
    void syncTopMostForAllAuxiliaryTopLevelWidgets(QWidget* mainWindow, const bool topMostState)
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        const QWidgetList kTopLevelWidgetList = appInstance->topLevelWidgets();
        for (QWidget* widget : kTopLevelWidgetList)
        {
            if (widget == nullptr || widget == mainWindow)
            {
                continue;
            }
            applyTopMostToTopLevelWidget(widget, topMostState);
        }
    }

    // applyAppBarAwareMaximizedBounds:
    // - Input windowHandle: Top-level window handle receiving WM_GETMINMAXINFO;
    // - Input minMaxInfo: System-provided structure for maximized size/position;
    // - Processing: Read the rcMonitor and rcWork of the display containing the window, and constrain the maximized rectangle to rcWork.
    // - Returns: true indicates AppBar/taskbar-aware maximized bounds have been written; false indicates parameter or system query failure.
    bool applyAppBarAwareMaximizedBounds(
        const HWND windowHandle,
        MINMAXINFO* const minMaxInfo)
    {
        if (windowHandle == nullptr ||
            ::IsWindow(windowHandle) == FALSE ||
            minMaxInfo == nullptr)
        {
            return false;
        }

        // monitorHandle purpose: Select the monitor nearest to the current window, supporting multi-monitor and cross-screen window scenarios.
        const HMONITOR kMonitorHandle = ::MonitorFromWindow(
            windowHandle,
            MONITOR_DEFAULTTONEAREST);
        if (kMonitorHandle == nullptr)
        {
            return false;
        }

        // monitorInfo usage:
        // - rcMonitor is the complete physical display rectangle;
        // - rcWork is the available work area excluding the taskbar/AppBar.
        MONITORINFO monitorInfo = {};
        monitorInfo.cbSize = sizeof(monitorInfo);
        if (::GetMonitorInfoW(kMonitorHandle, &monitorInfo) == FALSE)
        {
            return false;
        }

        const RECT& monitorRect = monitorInfo.rcMonitor;
        const RECT& workRect = monitorInfo.rcWork;
        const LONG kWorkWidth = workRect.right - workRect.left;
        const LONG kWorkHeight = workRect.bottom - workRect.top;
        if (kWorkWidth <= 0 || kWorkHeight <= 0)
        {
            return false;
        }

        // ptMaxPosition is the maximization offset relative to the top-left corner of the current monitor:
        // - When the top AppBar is active, rcWork.top > rcMonitor.top; here, Y is corrected to the taskbar height;
        // - When the taskbar is at the bottom, 'top' is typically 0; only shrink the height without changing Y.
        minMaxInfo->ptMaxPosition.x = workRect.left - monitorRect.left;
        minMaxInfo->ptMaxPosition.y = workRect.top - monitorRect.top;

        // ptMaxSize is the outer frame size of the client area after maximization and must match the work area size.
        // If only the height is modified without updating ptMaxPosition, the top will be obscured and a gap will appear at the bottom.
        minMaxInfo->ptMaxSize.x = kWorkWidth;
        minMaxInfo->ptMaxSize.y = kWorkHeight;

        // ptMaxTrackSize limits the maximum tracking size during user drag or system maximize, keeping it consistent with the work area.
        minMaxInfo->ptMaxTrackSize.x = kWorkWidth;
        minMaxInfo->ptMaxTrackSize.y = kWorkHeight;
        return true;
    }

    // kDwmUseImmersiveDarkModeAttribute:
    // - Compatible with SDK headers that may or may not declare this enum value;
    // - Used to instruct DWM on whether the current window should be processed using a dark or light border strategy.
    constexpr DWORD kDwmUseImmersiveDarkModeAttribute = 20;

    // kDwmBorderColorAttribute:
    // - Points to the Win11 border color attribute ID;
    // - Used to disable the system's default white visible border.
    constexpr DWORD kDwmBorderColorAttribute = 34;

    // kDwmColorNone:
    // After passing to DWMWA_BORDER_COLOR, it indicates 'do not draw a visible border';
    // - Retain shadow and scaling capabilities, only remove the flashing white border.
    constexpr DWORD kDwmColorNone = 0xFFFFFFFE;

    // Declarations related to window composition attributes (SetWindowCompositionAttribute):
    // - DWM Acrylic requires opaque windows and is mutually exclusive with Qt's WA_TranslucentBackground layered windows;
    //   forcing it causes DWM to fall back to the system light theme background, resulting in a washed-out window appearance.
    // - Acrylic applies to layered windows via composition attributes; it is the only system-composed blur used in this project.
    // kWindowCompositionAttributeAccentPolicy function: WCA_ACCENT_POLICY feature identifier.
    constexpr DWORD kWindowCompositionAttributeAccentPolicy = 19;

    // kAccentDisabled / kAccentEnableAcrylicBlurBehind: Values for ACCENT_STATE.
    // - ACRYLIC (4): blur + saturation + noise, composited by DWM;
    // - Traditional BLURBEHIND(3) has degraded to pure transparency and ignores coloring on Windows 11, making it unavailable.
    constexpr DWORD kAccentDisabled = 0;

    constexpr DWORD kAccentEnableAcrylicBlurBehind = 4;

    // AccentPolicyData description: Corresponds to the layout of the undocumented ACCENT_POLICY structure.
    // Note: This structure lacks a blur radius field; the blur intensity for acrylic is fixed internally by DWM.
    // Therefore, the 'Glass Blur Radius' setting only affects the blur layer of custom-drawn background images.
    struct AccentPolicyData
    {
        DWORD accentState = 0;   // accentState: ACCENT_STATE enumeration value.
        DWORD accentFlags = 0;   // accentFlags: Border drawing flags; not needed in this project.
        DWORD gradientColor = 0; // gradientColor: Gradient color value, arranged as 0xAABBGGRR.
        DWORD animationId = 0;   // animationId: Animation identifier; keep as 0.
    };

    // WindowCompositionAttributeData description: Corresponds to the undocumented WINDOWCOMPOSITIONATTRIBDATA.
    struct WindowCompositionAttributeData
    {
        DWORD attribute = 0;          // attribute: WCA_* feature identifier.
        void* dataPointer = nullptr;  // dataPointer: Pointer to feature data.
        SIZE_T dataSizeBytes = 0;     // dataSizeBytes: Size of feature data in bytes.
    };

    // configureSingleInstanceMessageReception:
    // - Input: mainWindowHandle is the native HWND corresponding to the Qt main window.
    // - Processing: Set a stable identification attribute on the window and allow low-integrity/standard-permission instances to dispatch WM_COPYDATA.
    // - Returns: No return value. Failure only affects single-instance Shell unlock forwarding compatibility and does not block main program startup.
    void configureSingleInstanceMessageReception(HWND mainWindowHandle)
    {
        if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
        {
            return;
        }

        (void)::SetPropW(
            mainWindowHandle,
            kKswordMainWindowPropertyName,
            reinterpret_cast<HANDLE>(static_cast<UINT_PTR>(1)));

        // ChangeWindowMessageFilterEx:
        // - When the main process runs as administrator, but the Explorer right-click menu launches a second instance with standard permissions.
        // - Windows UIPI by default intercepts cross-integrity-level messages, preventing WM_COPYDATA from reaching an existing main window;
        // - Only allows WM_COPYDATA required for this feature here, not arbitrary custom messages.
        CHANGEFILTERSTRUCT filterStatus{};
        filterStatus.cbSize = sizeof(filterStatus);
        (void)::ChangeWindowMessageFilterEx(
            mainWindowHandle,
            WM_COPYDATA,
            MSGFLT_ALLOW,
            &filterStatus);
    }

    // clearSingleInstanceMessageReception:
    // - Input: mainWindowHandle is the native HWND corresponding to the Qt main window.
    // - Processing: Remove the property used for single-instance identification before the window is destroyed.
    // - Returns: Nothing.
    void clearSingleInstanceMessageReception(HWND mainWindowHandle)
    {
        if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
        {
            return;
        }

        (void)::RemovePropW(mainWindowHandle, kKswordMainWindowPropertyName);
    }
}

using namespace ksword::ui::main_window;

void MainWindow::initResizeBorderOverlays()
{
    if (resizeBorderTop_ != nullptr)
    {
        return;
    }

    // createBorderOverlay：
    // - Input parentWidget: The parent window for the four borders, fixed here to the mainWindow instance.
    // Processing: Create an independent overlay widget without adding it to the main layout or altering the root container's background.
    // - Returns: A 3px blue border widget initialized.
    auto createBorderOverlay = [this](const QString& objectNameText) -> QWidget*
        {
            QWidget* borderWidget = new QWidget(this);
            borderWidget->setObjectName(objectNameText);
            borderWidget->setAttribute(Qt::WA_StyledBackground, true);
            borderWidget->setMouseTracking(true);
            borderWidget->installEventFilter(this);
            borderWidget->raise();
            return borderWidget;
        };

    resizeBorderTop_ = createBorderOverlay(QStringLiteral("ksResizeBorderTop"));
    resizeBorderBottom_ = createBorderOverlay(QStringLiteral("ksResizeBorderBottom"));
    resizeBorderLeft_ = createBorderOverlay(QStringLiteral("ksResizeBorderLeft"));
    resizeBorderRight_ = createBorderOverlay(QStringLiteral("ksResizeBorderRight"));
    resizeCornerBottomLeft_ = new ResizeCornerTriangleWidget(
        ResizeCornerTriangleWidget::Corner::kBottomLeft,
        this);
    resizeCornerBottomLeft_->setObjectName(QStringLiteral("ksResizeCornerBottomLeft"));
    resizeCornerBottomLeft_->installEventFilter(this);
    resizeCornerBottomLeft_->setCursor(Qt::SizeBDiagCursor);
    resizeCornerBottomLeft_->raise();
    resizeCornerBottomRight_ = new ResizeCornerTriangleWidget(
        ResizeCornerTriangleWidget::Corner::kBottomRight,
        this);
    resizeCornerBottomRight_->setObjectName(QStringLiteral("ksResizeCornerBottomRight"));
    resizeCornerBottomRight_->installEventFilter(this);
    resizeCornerBottomRight_->setCursor(Qt::SizeFDiagCursor);
    resizeCornerBottomRight_->raise();

    applyResizeBorderOverlayStyle();
    updateResizeBorderOverlays();
}

void MainWindow::updateResizeBorderOverlays()
{
    const std::array<QWidget*, 6> kOverlayWidgets = {
        resizeBorderTop_,
        resizeBorderBottom_,
        resizeBorderLeft_,
        resizeBorderRight_,
        resizeCornerBottomLeft_,
        resizeCornerBottomRight_
    };

    // updateResizeBorderOverlays may be triggered by early resize/show state synchronization;
    // Return immediately before initResizeBorderOverlays completes to avoid null pointer access.
    for (QWidget* overlayWidget : kOverlayWidgets)
    {
        if (overlayWidget == nullptr)
        {
            return;
        }
    }

    // Maximized layout compensation:
    // - For maximized windows with WS_THICKFRAME, Windows extends the invisible resize frame beyond the work area;
    // - Keep HWND and Qt backing store in their native system state; only retract the title bar and Dock content inward.
    // - Margins use Qt logical pixels to avoid double-scaling original physical pixels under high DPI.
    QMargins maximizedLayoutMargins;
#ifdef Q_OS_WIN
    if (mainRootLayout_ != nullptr
        && isWindowActuallyMaximized()
        && testAttribute(Qt::WA_WState_Created))
    {
        const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
        if (kMainWindowHandle != nullptr && ::IsWindow(kMainWindowHandle) != FALSE)
        {
            UINT windowDpi = ::GetDpiForWindow(kMainWindowHandle);
            if (windowDpi == 0)
            {
                windowDpi = USER_DEFAULT_SCREEN_DPI;
            }
            const int kNativePaddedBorder =
                ::GetSystemMetricsForDpi(SM_CXPADDEDBORDER, windowDpi);
            const int kNativeFrameX =
                ::GetSystemMetricsForDpi(SM_CXSIZEFRAME, windowDpi) + kNativePaddedBorder;
            const int kNativeFrameY =
                ::GetSystemMetricsForDpi(SM_CYSIZEFRAME, windowDpi) + kNativePaddedBorder;
            const qreal kDeviceScale = std::max<qreal>(1.0, devicePixelRatioF());
            const int kLayoutInsetX = std::max(
                0,
                static_cast<int>(std::lround(static_cast<qreal>(kNativeFrameX) / kDeviceScale)));
            const int kLayoutInsetY = std::max(
                0,
                static_cast<int>(std::lround(static_cast<qreal>(kNativeFrameY) / kDeviceScale)));
            maximizedLayoutMargins = QMargins(
                kLayoutInsetX,
                kLayoutInsetY,
                kLayoutInsetX,
                kLayoutInsetY);
        }
    }
#endif
    if (mainRootLayout_ != nullptr
        && mainRootLayout_->contentsMargins() != maximizedLayoutMargins)
    {
        mainRootLayout_->setContentsMargins(maximizedLayoutMargins);
    }

    const bool kShouldShowBorders =
        !isWindowActuallyMaximized()
        && width() > (kResizeBorderOverlayWidth * 2)
        && height() > (kResizeBorderOverlayWidth * 2);

    for (QWidget* overlayWidget : kOverlayWidgets)
    {
        overlayWidget->setVisible(kShouldShowBorders);
        if (kShouldShowBorders)
        {
            overlayWidget->raise();
        }
    }

    if (!kShouldShowBorders)
    {
        return;
    }

    const int kBorder = kResizeBorderOverlayWidth;
    resizeBorderTop_->setGeometry(0, 0, width(), kBorder);
    resizeBorderBottom_->setGeometry(0, height() - kBorder, width(), kBorder);
    resizeBorderLeft_->setGeometry(0, kBorder, kBorder, std::max(0, height() - kBorder * 2));
    resizeBorderRight_->setGeometry(width() - kBorder, kBorder, kBorder, std::max(0, height() - kBorder * 2));
    resizeCornerBottomLeft_->setGeometry(
        0,
        height() - kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg);
    resizeCornerBottomRight_->setGeometry(
        width() - kResizeCornerTriangleLeg,
        height() - kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg);
}

void MainWindow::applyResizeBorderOverlayStyle()
{
    const QString kBorderStyleText = QStringLiteral(
        "background:%1;"
        "border:none;").arg(ksword_theme::kPrimaryBlueBorderHex);

    const std::array<QWidget*, 4> kBorderWidgets = {
        resizeBorderTop_,
        resizeBorderBottom_,
        resizeBorderLeft_,
        resizeBorderRight_
    };
    for (QWidget* borderWidget : kBorderWidgets)
    {
        if (borderWidget != nullptr)
        {
            borderWidget->setStyleSheet(kBorderStyleText);
        }
    }
    if (resizeCornerBottomLeft_ != nullptr)
    {
        resizeCornerBottomLeft_->update();
    }
    if (resizeCornerBottomRight_ != nullptr)
    {
        resizeCornerBottomRight_->update();
    }
}

bool MainWindow::handleResizeBorderOverlayEvent(QObject* watchedObject, QEvent* event)
{
    if (event == nullptr || watchedObject == nullptr)
    {
        return false;
    }

    QWidget* const kBorderWidget = qobject_cast<QWidget*>(watchedObject);
    if (kBorderWidget == nullptr)
    {
        return false;
    }

    auto resolveOverlayHitTest = [this, watchedObject, kBorderWidget](const QPoint& localPoint) -> WPARAM
        {
            if (watchedObject == resizeBorderTop_)
            {
                if (localPoint.x() < kResizeBorderOverlayWidth)
                {
                    return HTTOPLEFT;
                }
                if (localPoint.x() >= kBorderWidget->width() - kResizeBorderOverlayWidth)
                {
                    return HTTOPRIGHT;
                }
                return HTTOP;
            }
            if (watchedObject == resizeBorderBottom_)
            {
                if (localPoint.x() < kResizeBorderOverlayWidth)
                {
                    return HTBOTTOMLEFT;
                }
                if (localPoint.x() >= kBorderWidget->width() - kResizeBorderOverlayWidth)
                {
                    return HTBOTTOMRIGHT;
                }
                return HTBOTTOM;
            }
            if (watchedObject == resizeBorderLeft_)
            {
                return HTLEFT;
            }
            if (watchedObject == resizeBorderRight_)
            {
                return HTRIGHT;
            }
            if (watchedObject == resizeCornerBottomLeft_)
            {
                return HTBOTTOMLEFT;
            }
            if (watchedObject == resizeCornerBottomRight_)
            {
                return HTBOTTOMRIGHT;
            }
            return HTNOWHERE;
        };

    WPARAM defaultHitTestCode = HTNOWHERE;
    if (watchedObject == resizeBorderTop_)
    {
        defaultHitTestCode = HTTOP;
    }
    else if (watchedObject == resizeBorderBottom_)
    {
        defaultHitTestCode = HTBOTTOM;
    }
    else if (watchedObject == resizeBorderLeft_)
    {
        defaultHitTestCode = HTLEFT;
    }
    else if (watchedObject == resizeBorderRight_)
    {
        defaultHitTestCode = HTRIGHT;
    }
    else if (watchedObject == resizeCornerBottomLeft_)
    {
        defaultHitTestCode = HTBOTTOMLEFT;
    }
    else if (watchedObject == resizeCornerBottomRight_)
    {
        defaultHitTestCode = HTBOTTOMRIGHT;
    }
    else
    {
        return false;
    }

    if (event->type() == QEvent::MouseMove)
    {
        QMouseEvent* const kMouseEvent = static_cast<QMouseEvent*>(event);
        const WPARAM kHitTestCode = kMouseEvent != nullptr
            ? resolveOverlayHitTest(kMouseEvent->position().toPoint())
            : defaultHitTestCode;
        kBorderWidget->setCursor(cursorForResizeHitTestCode(kHitTestCode));
        return false;
    }

    if (event->type() == QEvent::Leave)
    {
        kBorderWidget->unsetCursor();
        return false;
    }

    if (event->type() != QEvent::MouseButtonPress)
    {
        return false;
    }

    QMouseEvent* const kMouseEvent = static_cast<QMouseEvent*>(event);
    if (kMouseEvent == nullptr || kMouseEvent->button() != Qt::LeftButton)
    {
        return false;
    }

    const WPARAM kHitTestCode = resolveOverlayHitTest(kMouseEvent->position().toPoint());
    if (!isNativeResizeHitTestCode(kHitTestCode))
    {
        return false;
    }

    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle == nullptr
        || ::IsWindow(kMainWindowHandle) == FALSE
        || ::IsZoomed(kMainWindowHandle) != FALSE)
    {
        return false;
    }

    // Four overlay border scaling entry points:
    // - Input: Mouse left button pressed on the independent 3px blue border control.
    // - Processing: Bridge to native WM_NCLBUTTONDOWN + HT*.
    // - Return: true indicates the system has taken over drag-and-drop scaling, and Qt will no longer dispatch the event.
    const QPoint kGlobalPoint = kMouseEvent->globalPosition().toPoint();
    ::ReleaseCapture();
    ::SendMessageW(
        kMainWindowHandle,
        WM_NCLBUTTONDOWN,
        kHitTestCode,
        makeNativeMouseLParam(kGlobalPoint));
    kMouseEvent->accept();
    return true;
}

bool MainWindow::eventFilter(QObject* watchedObject, QEvent* event)
{
    if (handleResizeBorderOverlayEvent(watchedObject, event))
    {
        return true;
    }

    ads::CFloatingDockContainer* floatingWidget =
        qobject_cast<ads::CFloatingDockContainer*>(watchedObject);
    if (floatingWidget != nullptr && event != nullptr)
    {
        if (event->type() == QEvent::Show || event->type() == QEvent::Resize)
        {
            applyFloatingDockContainerAppearance(floatingWidget);
        }
    }

    if (watchedObject == logOutputWindow_ && event != nullptr)
    {
        if ((event->type() == QEvent::Move || event->type() == QEvent::Resize || event->type() == QEvent::Hide)
            && logWindowGeometrySaveTimer_ != nullptr)
        {
            logWindowGeometrySaveTimer_->start();
        }
    }

    return QMainWindow::eventFilter(watchedObject, event);
}

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QMainWindow::resizeEvent(event);
    updateResizeBorderOverlays();
    scheduleWindowBackdropRefresh();
    if (mainRootContainer_ != nullptr)
    {
        // The background host calculates scaling and centering positions based on the current real rect in paintEvent.
        mainRootContainer_->update();
    }
    if (notificationCardManager_ != nullptr)
    {
        notificationCardManager_->onHostGeometryChanged();
    }
}

void MainWindow::moveEvent(QMoveEvent* event)
{
    QMainWindow::moveEvent(event);
    // Do not re-dispatch combined features when moving within the same screen:
    // - DWM's Acrylic blurs content "behind" the window in the compositor, independent of pixels drawn by the application. When
    //   the window moves, it automatically resamples based on the new position; the application side does not need to invalidate it.
    // - Each refresh triggers a redraw of the root container. In transparent mode, all Dock content is transparent; a
    //   parent control redraw causes the entire Dock tree to be redrawn. Empirical testing shows a single operation takes
    //   ~41ms. Under a 40ms throttle, this effectively saturates the UI thread, directly causing frame drops during dragging.
    // Refresh once across displays: switching screens rebuilds the window surface with new DPI, which may invalidate composition features.
    QScreen* const kCurrentScreen = screen();
    if (kCurrentScreen != lastKnownScreen_)
    {
        lastKnownScreen_ = kCurrentScreen;
        scheduleWindowBackdropRefresh();
    }
    if (notificationCardManager_ != nullptr)
    {
        notificationCardManager_->onHostGeometryChanged();
    }
}

void MainWindow::showEvent(QShowEvent* event)
{
    QMainWindow::showEvent(event);

    // Take over R0 missing notifications only after the main window is truly interactive. During startup, best-effort probes like
    // log polling exist; they should not trigger an "Enable R0" dialog before the user has interacted with any kernel functionality.
    if (!r0UnavailablePromptArmed_)
    {
        r0UnavailablePromptArmed_ = true;
        // weakLifetime allows safe checks after window member destruction without relying on the lifetime of raw QObject pointers.
        const std::weak_ptr<std::atomic_bool> kWeakLifetime = r0NotificationLifetime_;
        ksword::ark::DriverClient::setR0UnavailableHandler([this, kWeakLifetime](const unsigned long win32Error)
            {
                const std::shared_ptr<std::atomic_bool> kLifetime = kWeakLifetime.lock();
                if (!kLifetime || !kLifetime->load(std::memory_order_acquire))
                {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, kWeakLifetime, win32Error]()
                    {
                        const std::shared_ptr<std::atomic_bool> kQueuedLifetime = kWeakLifetime.lock();
                        if (!kQueuedLifetime || !kQueuedLifetime->load(std::memory_order_acquire))
                        {
                            return;
                        }
                        handleR0DriverUnavailable(win32Error);
                    }, Qt::QueuedConnection);
            });
        ksword::ark::DriverClient::setR0PermissionRequiredHandler([this, kWeakLifetime](const unsigned long win32Error)
            {
                const std::shared_ptr<std::atomic_bool> kLifetime = kWeakLifetime.lock();
                if (!kLifetime || !kLifetime->load(std::memory_order_acquire))
                {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, kWeakLifetime, win32Error]()
                    {
                        const std::shared_ptr<std::atomic_bool> kQueuedLifetime = kWeakLifetime.lock();
                        if (!kQueuedLifetime || !kQueuedLifetime->load(std::memory_order_acquire))
                        {
                            return;
                        }
                        handleR0PermissionRequired(win32Error);
                    }, Qt::QueuedConnection);
            });

        const QString kEnableAfterElevationArgument =
            QString::fromWCharArray(kKswordEnableR0AfterElevationArgument);
        const bool kEnableAfterElevation =
            QCoreApplication::arguments().contains(kEnableAfterElevationArgument, Qt::CaseInsensitive);
        if (kEnableAfterElevation)
        {
            QTimer::singleShot(0, this, [this]()
                {
                    enableR0ForUserRequest();
                });
        }
        else if (currentAppearanceSettings_.startupAutoInstallR0Driver)
        {
            // Automatic installation reuses the same asynchronous SCM link; failure with normal permissions only reports an error without converting the startup settings into an additional UAC request.
            QTimer::singleShot(0, this, [this]()
                {
                    if (!startR0DriverService(true))
                    {
                        refreshPrivilegeStatusButtons();
                    }
                });
        }
    }

    ensureNativeFramelessWindowStyle();
    applyNativeWindowFrameVisualStyle();
    // UI application during initialization occurs before native window creation; composition feature calls are skipped.
    // Apply once more after the window handle becomes available so blur enabled at startup takes effect immediately.
    refreshWindowBackdropMaterial();
    syncCustomTitleBarMaximizedState();
    updateResizeBorderOverlays();
    if (notificationCardManager_ != nullptr)
    {
        notificationCardManager_->onHostGeometryChanged();
    }

    {
        KLogEvent showEventLog;
        const QRect kCurrentFrameRect = frameGeometry();
        info << showEventLog
            << "[MainWindow] showEvent 触发。 spontaneous="
            << ((event != nullptr && event->spontaneous()) ? "true" : "false")
            << ", visible="
            << (isVisible() ? "true" : "false")
            << ", minimized="
            << (isMinimized() ? "true" : "false")
            << ", frame="
            << kCurrentFrameRect.x()
            << ","
            << kCurrentFrameRect.y()
            << " "
            << kCurrentFrameRect.width()
            << "x"
            << kCurrentFrameRect.height()
            << eol;
    }

    // First-time visibility adjustment:
    // - Under low resolution or high scaling, the initial geometry resulting from the Qt/Win32 combination may fall outside the screen.
    // - Here, perform an asynchronous correction once after show to ensure the main window falls within the current visible area at least once.
    if (!startupWindowVisibilityAdjusted_)
    {
        startupWindowVisibilityAdjusted_ = true;
        QTimer::singleShot(0, this, [this]()
            {
                ensureStartupWindowVisibleOnScreen();
            });
    }

    if (deferredDockInitializationStarted_)
    {
        QTimer::singleShot(0, this, [this]()
            {
                ensureVisibleLazyDocksInitialized(QStringLiteral("showEvent-repeat"));
                repairKernelDockAfterLayoutRestore(QStringLiteral("showEvent-repeat"));
            });
        return;
    }

    deferredDockInitializationStarted_ = true;
    QTimer::singleShot(0, this, [this]()
        {
            ensureVisibleLazyDocksInitialized(QStringLiteral("showEvent-deferred-0"));
            repairKernelDockAfterLayoutRestore(QStringLiteral("showEvent-deferred-0"));
        });
    QTimer::singleShot(250, this, [this]()
        {
            ensureVisibleLazyDocksInitialized(QStringLiteral("showEvent-deferred-250"));
            repairKernelDockAfterLayoutRestore(QStringLiteral("showEvent-deferred-250"));
        });
    // Crash dump checks are deferred to the end: they trigger a modal dialog, so they must wait until the first screen and lazy-loaded
    // components are stable; otherwise, users would be blocked by a dialog covering the blank interface immediately upon launching the app.
    QTimer::singleShot(1500, this, [this]()
        {
            checkRecentCrashDumps();
        });

    // Lazy loading strategy correction:
    // - The old logic would continue to load all uninitialized docks one by one after the main window is shown.
    // - This causes 'lazy loading' to degrade into 'delayed but full loading', resulting in persistent UI lag on the first screen after startup.
    // - Now, content is initialized only when the user actually switches to the corresponding Dock or the code explicitly jumps to that Dock.
    // Note: visibilityChanged, focusXXXDock, and raiseStartupDockByKey already cover the on-demand initialization entry points.
    Q_UNUSED(kDeferredDockLoadIntervalMs);
}

void MainWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);

    if (event != nullptr
        && event->type() == QEvent::WindowStateChange)
    {
        syncCustomTitleBarMaximizedState();
        updateResizeBorderOverlays();
        scheduleWindowBackdropRefresh();
        if (notificationCardManager_ != nullptr)
        {
            notificationCardManager_->onHostGeometryChanged();
        }
    }

    // Re-sample on activation state changes: when the window regains focus, the system may have
    // downgraded the frosted glass effect to a static fallback color, requiring a refresh to restore it.
    if (event != nullptr && event->type() == QEvent::ActivationChange)
    {
        scheduleWindowBackdropRefresh();
    }
}

void MainWindow::ensureStartupWindowVisibleOnScreen()
{
    // Maximized window management is handled by the system:
    // - Avoid incorrectly reverting maximized state to normal window state.
    // - This handles only the case where the window is shown but is in a normal state, invisible, or out of bounds.
    if (isWindowActuallyMaximized())
    {
        return;
    }

    // targetFrameRect usage: Based on the top-level frame geometry to ensure the title bar and borders remain within the visible area.
    QRect targetFrameRect = frameGeometry();
    if (!targetFrameRect.isValid() || targetFrameRect.width() <= 0 || targetFrameRect.height() <= 0)
    {
        targetFrameRect = geometry();
    }
    if (!targetFrameRect.isValid() || targetFrameRect.width() <= 0 || targetFrameRect.height() <= 0)
    {
        return;
    }

    // targetScreen purpose: Prefer the screen currently containing the window; if the center point is not within any screen, fall back to the primary screen.
    QScreen* targetScreen = nullptr;
    if (windowHandle() != nullptr)
    {
        targetScreen = windowHandle()->screen();
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::screenAt(targetFrameRect.center());
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::primaryScreen();
    }
    if (targetScreen == nullptr)
    {
        return;
    }

    // availableRect purpose: available working area of the current screen, excluding the taskbar.
    const QRect kAvailableRect = targetScreen->availableGeometry();
    if (!kAvailableRect.isValid() || kAvailableRect.width() <= 0 || kAvailableRect.height() <= 0)
    {
        return;
    }

    // First, crop the window size:
    // - Prevent the default 1024x768 from exceeding the work area on low-resolution displays;
    // - Maintain a minimum size of 320x240 to prevent the window from becoming unmanageable.
    const int kAdjustedWidth = std::clamp(targetFrameRect.width(), 320, kAvailableRect.width());
    const int kAdjustedHeight = std::clamp(targetFrameRect.height(), 240, kAvailableRect.height());

    // Re-clipping window position:
    // - If any part is off-screen, pull the top-left corner back into the visible area.
    // - Ensure the entire frameRect fits within availableRect.
    const int kAdjustedLeft = std::clamp(
        targetFrameRect.left(),
        kAvailableRect.left(),
        kAvailableRect.right() - kAdjustedWidth + 1);
    const int kAdjustedTop = std::clamp(
        targetFrameRect.top(),
        kAvailableRect.top(),
        kAvailableRect.bottom() - kAdjustedHeight + 1);

    const QRect kAdjustedFrameRect(kAdjustedLeft, kAdjustedTop, kAdjustedWidth, kAdjustedHeight);
    if (kAdjustedFrameRect == targetFrameRect)
    {
        KLogEvent noAdjustEvent;
        info << noAdjustEvent
            << "[MainWindow] 首次显示区域检查完成，无需修正。 frame="
            << targetFrameRect.x()
            << ","
            << targetFrameRect.y()
            << " "
            << targetFrameRect.width()
            << "x"
            << targetFrameRect.height()
            << eol;
        return;
    }

    // Derive client geometry using the difference in frameGeometry:
    // - move/resize operations apply directly to the QWidget client area;
    // - This ensures the frame target position is mapped back to Qt geometry as precisely as possible.
    const QRect kCurrentClientRect = geometry();
    const int kFrameOffsetX = targetFrameRect.left() - kCurrentClientRect.left();
    const int kFrameOffsetY = targetFrameRect.top() - kCurrentClientRect.top();
    const int kClientWidthDelta = targetFrameRect.width() - kCurrentClientRect.width();
    const int kClientHeightDelta = targetFrameRect.height() - kCurrentClientRect.height();

    const QRect kAdjustedClientRect(
        kAdjustedFrameRect.left() - kFrameOffsetX,
        kAdjustedFrameRect.top() - kFrameOffsetY,
        std::max(1, kAdjustedFrameRect.width() - kClientWidthDelta),
        std::max(1, kAdjustedFrameRect.height() - kClientHeightDelta));

    {
        KLogEvent adjustEvent;
        warn << adjustEvent
            << "[MainWindow] 首次显示区域已修正。 old_frame="
            << targetFrameRect.x()
            << ","
            << targetFrameRect.y()
            << " "
            << targetFrameRect.width()
            << "x"
            << targetFrameRect.height()
            << ", new_frame="
            << kAdjustedFrameRect.x()
            << ","
            << kAdjustedFrameRect.y()
            << " "
            << kAdjustedFrameRect.width()
            << "x"
            << kAdjustedFrameRect.height()
            << eol;
    }

    setGeometry(kAdjustedClientRect);
}

void MainWindow::syncCustomTitleBarMaximizedState()
{
    if (customTitleBar_ == nullptr)
    {
        return;
    }

    // maximizedState usage: Uniformly records whether the current window is maximized for title bar icon refresh.
    const bool kMaximizedState = isWindowActuallyMaximized();
    customTitleBar_->setMaximizedState(kMaximizedState);
}

void MainWindow::ensureNativeFramelessWindowStyle()
{
#ifdef Q_OS_WIN
    // mainWindowHandle usage: Retrieve the main window's native handle to apply Win32 style bits.
    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle == nullptr || ::IsWindow(kMainWindowHandle) == FALSE)
    {
        return;
    }

    // currentStyleValue usage: stores the current window style for incremental merging of required style bits.
    const LONG_PTR kCurrentStyleValue = ::GetWindowLongPtrW(kMainWindowHandle, GWL_STYLE);
    // requiredStyleMask usage: system interaction capability mask required even for borderless windows.
    //
    // Even if the client area is fully managed by a custom-drawn title bar, WS_CAPTION must be retained: Windows
    // uses it to determine if the window has standard minimize/maximize semantics, ensuring DWM's restore, maximize,
    // minimize transition animations, and Aero Snap follow the standard window path. The standard non-client area is
    // still removed by returning 0 from WM_NCCALCSIZE, so the system title bar will not reappear.
    const LONG_PTR kRequiredStyleMask =
        WS_CAPTION | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX | WS_SYSMENU;
    // updatedStyleValue: Preserves other Qt/Win32 styles, only supplementing system window semantics.
    const LONG_PTR kUpdatedStyleValue = kCurrentStyleValue | kRequiredStyleMask;

    if (kUpdatedStyleValue != kCurrentStyleValue)
    {
        ::SetWindowLongPtrW(kMainWindowHandle, GWL_STYLE, kUpdatedStyleValue);
        ::SetWindowPos(
            kMainWindowHandle,
            nullptr,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    }
#endif
}

void MainWindow::applyNativeWindowFrameVisualStyle()
{
#ifdef Q_OS_WIN
    // Do not actively trigger winId when the native window handle is not created, to avoid introducing extra reentrancy during early construction.
    if (!testAttribute(Qt::WA_WState_Created))
    {
        return;
    }

    // mainWindowHandle: Used to write DWM's main window borderless visual properties.
    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle == nullptr || ::IsWindow(kMainWindowHandle) == FALSE)
    {
        return;
    }

    // darkModeEnabled usage: Determine whether DWM should enable the immersive dark border strategy based on the current appearance configuration.
    const bool kDarkModeEnabled = isDarkModeEffective(currentAppearanceSettings_);
    // immersiveDarkModeValue usage: The BOOL parameter required by DwmSetWindowAttribute.
    const BOOL kImmersiveDarkModeValue = kDarkModeEnabled ? TRUE : FALSE;
    // borderColorValue: Instructs DWM to stop drawing the system default white border.
    const DWORD kBorderColorValue = kDwmColorNone;

    const HRESULT kDarkModeResult = ::DwmSetWindowAttribute(
        kMainWindowHandle,
        kDwmUseImmersiveDarkModeAttribute,
        &kImmersiveDarkModeValue,
        sizeof(kImmersiveDarkModeValue));
    const HRESULT kBorderColorResult = ::DwmSetWindowAttribute(
        kMainWindowHandle,
        kDwmBorderColorAttribute,
        &kBorderColorValue,
        sizeof(kBorderColorValue));

    // darkModeUnsupported / borderColorUnsupported usage:
    // - Mark that the current system simply does not support the new properties, rather than an exception occurred.
    // - Avoid outputting meaningless warnings on every startup for older systems.
    const bool kDarkModeUnsupported = (kDarkModeResult == E_INVALIDARG);
    const bool kBorderColorUnsupported = (kBorderColorResult == E_INVALIDARG);
    if ((!SUCCEEDED(kDarkModeResult) && !kDarkModeUnsupported)
        || (!SUCCEEDED(kBorderColorResult) && !kBorderColorUnsupported))
    {
        KLogEvent frameVisualEvent;
        warn << frameVisualEvent
            << "[MainWindow] DWM 边框样式同步失败, dark_hr=0x"
            << std::hex
            << static_cast<unsigned long>(kDarkModeResult)
            << ", border_hr=0x"
            << static_cast<unsigned long>(kBorderColorResult)
            << std::dec
            << eol;
    }
#endif
}

bool MainWindow::applyMainWindowBackdropMaterial(const BackdropBlurKind blurKind)
{
    const bool kEnableSystemAccent = (blurKind == BackdropBlurKind::kAcrylic);
#ifdef Q_OS_WIN
    if (!testAttribute(Qt::WA_WState_Created))
    {
        return false;
    }
    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle == nullptr || ::IsWindow(kMainWindowHandle) == FALSE)
    {
        return false;
    }

    // setWindowCompositionAttribute purpose:
    // - Unexported entry point in user32 for composition attributes; the only available interface to add blur to 'layered transparent windows'.
    // - DWM's mica (DWMWA_SYSTEMBACKDROP_TYPE) requires the window itself to be opaque, which conflicts with Qt's
    //   WA_TranslucentBackground layered surface, causing a fallback to the system light background (appearing washed out). Therefore,
    //   we use the blur provided by the composition feature instead, which is available on Windows 10 1803+ and Windows 11.
    using SetWindowCompositionAttributeFunction = BOOL(WINAPI*)(HWND, void*);
    static SetWindowCompositionAttributeFunction setWindowCompositionAttribute =
        []() -> SetWindowCompositionAttributeFunction {
            HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
            if (user32ModuleHandle == nullptr)
            {
                return nullptr;
            }
            return reinterpret_cast<SetWindowCompositionAttributeFunction>(
                ::GetProcAddress(user32ModuleHandle, "SetWindowCompositionAttribute"));
        }();
    if (setWindowCompositionAttribute == nullptr)
    {
        return false;
    }

    // requestedState usage: Maps material kinds to comparable cached values.
    const int kRequestedState = static_cast<int>(blurKind);
    // No need to disable if Acrylic was never enabled: avoid touching undocumented interfaces on every startup for users who do not use system materials.
    if (!kEnableSystemAccent && backdropMaterialState_ < 0)
    {
        backdropMaterialState_ = kRequestedState;
        return false;
    }
    // m_backdropMaterialState: Caches the applied kind; -1 indicates uninitialized, other values correspond to BackdropBlurKind.
    // Acrylic requires re-issuing (resampling) when the theme color changes or the window moves.
    // No need to re-issue if already disabled and still needs to be disabled.
    if (!kEnableSystemAccent
        && backdropMaterialState_ != static_cast<int>(BackdropBlurKind::kAcrylic))
    {
        backdropMaterialState_ = kRequestedState;
        return false;
    }
    backdropMaterialState_ = kRequestedState;

    // tintColor purpose: The acrylic's built-in tint layer is directly blended into the blur result; therefore, when
    // enabled, the root container does not draw a separate tint to avoid turbidity caused by double-layer stacking.
    const QColor kTintColor = ksword_theme::mainBackgroundColor();
    // acrylicTintAlpha usage: Opacity of the tint layer, determined by the 'Frosted Tint Opacity' setting.
    // Lower values mean more transparency (closer to pure blur); higher values improve foreground text readability.
    const int kAcrylicTintAlpha = ks::settings::tintAlphaFromOpacityPercent(
        currentAppearanceSettings_.acrylicTintOpacityPercent);
    // gradientColorValue uses 0xAABBGGRR layout, which is the reverse of the common ARGB order.
    const DWORD kGradientColorValue =
        (static_cast<DWORD>(kAcrylicTintAlpha) << 24)
        | (static_cast<DWORD>(kTintColor.blue()) << 16)
        | (static_cast<DWORD>(kTintColor.green()) << 8)
        | static_cast<DWORD>(kTintColor.red());

    AccentPolicyData accentPolicy{};
    accentPolicy.accentState =
        kEnableSystemAccent ? kAccentEnableAcrylicBlurBehind : kAccentDisabled;
    accentPolicy.accentFlags = 0;
    accentPolicy.gradientColor = kEnableSystemAccent ? kGradientColorValue : 0;
    accentPolicy.animationId = 0;

    WindowCompositionAttributeData compositionData{};
    compositionData.attribute = kWindowCompositionAttributeAccentPolicy;
    compositionData.dataPointer = &accentPolicy;
    compositionData.dataSizeBytes = sizeof(accentPolicy);

    const BOOL kApplyOk = setWindowCompositionAttribute(kMainWindowHandle, &compositionData);

    KLogEvent backdropEvent;
    info << backdropEvent
        << "[MainWindow] 窗口模糊材质切换, kind="
        << (blurKind == BackdropBlurKind::kAcrylic ? "acrylic" : "none")
        << ", ok="
        << (kApplyOk != FALSE ? "true" : "false")
        << eol;
    return kEnableSystemAccent && kApplyOk != FALSE;
#else
    Q_UNUSED(blurKind);
    return false;
#endif
}

bool MainWindow::isWindowActuallyMaximized() const
{
#ifdef Q_OS_WIN
    // On Windows, the HWND Zoomed state is the sole authoritative source:
    // - Custom-drawn title bars and borderless windows previously mixed Qt::WindowMaximized with IsZoomed.
    // - After restoring from maximization via title bar drag, the Qt state may retain WindowMaximized;
    // - Continuing with OR Qt state will cause button icons, hit testing, and the maximized button target state to freeze.
    if (!testAttribute(Qt::WA_WState_Created))
    {
        return (windowState() & Qt::WindowMaximized) != 0 || isMaximized();
    }

    const HWND kMainWindowHandle = reinterpret_cast<HWND>(const_cast<MainWindow*>(this)->winId());
    if (kMainWindowHandle != nullptr && ::IsWindow(kMainWindowHandle) != FALSE)
    {
        return ::IsZoomed(kMainWindowHandle) != FALSE;
    }
#endif

    // Fallback to Qt state if not Windows or HWND is not yet available.
    return (windowState() & Qt::WindowMaximized) != 0 || isMaximized();
}

void MainWindow::setWindowMaximizedBySystemCommand(const bool targetMaximizedState)
{
#ifdef Q_OS_WIN
    // mainWindowHandle: The window handle used when performing native maximize/restore.
    const HWND kMainWindowHandle = reinterpret_cast<HWND>(winId());
    if (kMainWindowHandle != nullptr && ::IsWindow(kMainWindowHandle) != FALSE)
    {
        // currentMaximizedState: Records the current actual maximized state to avoid sending duplicate commands.
        const bool kCurrentMaximizedState = (::IsZoomed(kMainWindowHandle) != FALSE);
        if (targetMaximizedState != kCurrentMaximizedState)
        {
            // Use ShowWindow to toggle window state:
            // - Avoid reentrancy caused by synchronous SendMessage(WM_SYSCOMMAND) during title bar mouse message handling.
            // - Fix the 'jump to top-left then flash back' issue and the title bar drag link failure after double-clicking.
            ::ShowWindow(
                kMainWindowHandle,
                targetMaximizedState ? SW_MAXIMIZE : SW_RESTORE);
        }
    }
    else
    {
        if (targetMaximizedState)
        {
            showMaximized();
        }
        else
        {
            showNormal();
        }
    }
#else
    if (targetMaximizedState)
    {
        showMaximized();
    }
    else
    {
        showNormal();
    }
#endif

    syncCustomTitleBarMaximizedState();
    // Keep only the 0ms sync for the second sync.
    // - Overrides the next event loop cycle for 'asynchronous window state switching via system commands';
    // - Avoid perceived lag or icon jitter caused by multiple delayed synchronizations.
    QTimer::singleShot(0, this, [this]()
        {
            syncCustomTitleBarMaximizedState();
        });
}

bool MainWindow::nativeEvent(const QByteArray& eventType, void* message, qintptr* result)
{
    Q_UNUSED(eventType);

#ifdef Q_OS_WIN
    if (message == nullptr || result == nullptr)
    {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    MSG* nativeMessage = reinterpret_cast<MSG*>(message);
    if (nativeMessage == nullptr)
    {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    if (nativeMessage->message == WM_COPYDATA)
    {
        const COPYDATASTRUCT* const kCopyData =
            reinterpret_cast<const COPYDATASTRUCT*>(nativeMessage->lParam);
        if (kCopyData != nullptr
            && kCopyData->dwData == kUnlockerCopyDataMessageId
            && kCopyData->lpData != nullptr
            && kCopyData->cbData >= sizeof(wchar_t))
        {
            const std::size_t kWcharCount =
                static_cast<std::size_t>(kCopyData->cbData / sizeof(wchar_t));
            const wchar_t* const kPathBuffer = reinterpret_cast<const wchar_t*>(kCopyData->lpData);
            QString unlockPath = QString::fromWCharArray(kPathBuffer, static_cast<int>(kWcharCount));
            const int kNullIndex = unlockPath.indexOf(QChar::Null);
            if (kNullIndex >= 0)
            {
                unlockPath.truncate(kNullIndex);
            }
            unlockPath = QDir::toNativeSeparators(unlockPath.trimmed());

            if (!unlockPath.isEmpty())
            {
                KLogEvent event;
                info << event
                    << "[MainWindow] 收到单实例文件解锁请求: path="
                    << unlockPath.toStdString()
                    << eol;
                QTimer::singleShot(0, this, [this, unlockPath]()
                    {
                        this->raise();
                        this->activateWindow();
                        openFileUnlockerDockByPath(unlockPath);
                    });
            }

            *result = TRUE;
            return true;
        }
    }

    if (nativeMessage->message == WM_GETMINMAXINFO)
    {
        // WM_GETMINMAXINFO:
        // - The system queries the window's maximum size and position before maximizing or dragging to the screen edge.
        // - If a custom borderless window does not explicitly apply rcWork, a neighboring AppBar may reduce its height while leaving its origin at (0,0).
        MINMAXINFO* const kMinMaxInfo = reinterpret_cast<MINMAXINFO*>(nativeMessage->lParam);
        if (applyAppBarAwareMaximizedBounds(nativeMessage->hwnd, kMinMaxInfo))
        {
            *result = 0;
            return true;
        }
    }

    if (nativeMessage->message == WM_NCCALCSIZE)
    {
        // WM_NCCALCSIZE: Unified return of 0 for both branches:
        // - wParam=TRUE: Make the entire window area the client area when window size or state changes.
        // - wParam=FALSE: Remove default non-client area during initial window creation to fix residual transparent strips on the left/top in Win11.
        // Note: No additional rectangle modification is performed here to preserve existing scalable and maximized behavior.
        *result = 0;
        return true;
    }

    if (nativeMessage->message == WM_NCLBUTTONDOWN)
    {
        // Explicitly forward HTCAPTION and border resize hit tests to DefWindowProc:
        // - Qt borderless windows do not always complete native non-client area semantics for us;
        // - HTCAPTION is used to initiate system move/maximize drag-down restore;
        // - HTLEFT/HTRIGHT/... are used to initiate system border resizing.
        // - If only HTCAPTION is forwarded, the hit test returns the border, but dragging the edge still won't resize;
        if (nativeMessage->wParam == HTCAPTION
            || isNativeResizeHitTestCode(nativeMessage->wParam))
        {
            *result = ::DefWindowProcW(
                nativeMessage->hwnd,
                nativeMessage->message,
                nativeMessage->wParam,
                nativeMessage->lParam);
            return true;
        }
    }

    if (nativeMessage->message == WM_NCLBUTTONDBLCLK)
    {
        // HTCAPTION double-click to manually toggle maximize/restore:
        // - Preserve system title bar semantics;
        // - Simultaneously prevent Qt/borderless windows from swallowing double-clicks and causing unresponsiveness.
        if (nativeMessage->wParam == HTCAPTION)
        {
            const bool kTargetMaximizedState =
                (nativeMessage->hwnd != nullptr && ::IsWindow(nativeMessage->hwnd) != FALSE)
                ? (::IsZoomed(nativeMessage->hwnd) == FALSE)
                : !isWindowActuallyMaximized();
            setWindowMaximizedBySystemCommand(kTargetMaximizedState);
            *result = 0;
            return true;
        }
    }

    if (nativeMessage->message == WM_NCACTIVATE)
    {
        // On focus switch, require the system to skip default non-client area repaints to avoid a momentary white border flash.
        *result = ::DefWindowProcW(
            nativeMessage->hwnd,
            nativeMessage->message,
            nativeMessage->wParam,
            static_cast<LPARAM>(-1));
        return true;
    }

    if (nativeMessage->message == WM_SIZE)
    {
        // WM_SIZE:
        // - Native HTCAPTION dragging, Win+arrow keys, Aero Snap, and ShowWindow all land via this message;
        // - Do not change the window state; only synchronize the title bar button icons in the next event loop iteration.
        // - Specifically address the unstable triggering of Qt WindowStateChange when dragging a maximized window down from the title bar.
        if (nativeMessage->wParam == SIZE_MAXIMIZED || nativeMessage->wParam == SIZE_RESTORED)
        {
            QTimer::singleShot(0, this, [this]()
                {
                    syncCustomTitleBarMaximizedState();
                    updateResizeBorderOverlays();
                });
        }
    }

    if (nativeMessage->message == WM_NCHITTEST)
    {
        // maximizedInNativeMessage purpose: Determine the maximized state directly using the current message window handle to avoid reentrancy.
        const bool kMaximizedInNativeMessage =
            (nativeMessage->hwnd != nullptr && ::IsWindow(nativeMessage->hwnd) != FALSE)
            ? (::IsZoomed(nativeMessage->hwnd) != FALSE)
            : isWindowActuallyMaximized();

        const LPARAM kPointData = nativeMessage->lParam;
        const POINT kScreenPoint = {
            static_cast<LONG>(static_cast<short>(LOWORD(kPointData))),
            static_cast<LONG>(static_cast<short>(HIWORD(kPointData)))
        };
        const QPoint kScreenQPoint(kScreenPoint.x, kScreenPoint.y);
        const QPoint kLocalPoint = mapFromGlobal(kScreenQPoint);
        // windowRectValue usage: Read the screen coordinate rectangle of the top-level window for border resize hit testing.
        RECT windowRectValue = {};
        if (nativeMessage->hwnd == nullptr
            || ::GetWindowRect(nativeMessage->hwnd, &windowRectValue) == FALSE)
        {
            return QMainWindow::nativeEvent(eventType, message, result);
        }
        // frameLocalPoint: Converts screen coordinates to coordinates relative to the top-left corner of the entire top-level window.
        const QPoint kFrameLocalPoint(
            kScreenPoint.x - windowRectValue.left,
            kScreenPoint.y - windowRectValue.top);
        // frameWidthValue/frameHeightValue purpose: store the current dimensions of the top-level window for hit testing on the right/bottom resize areas.
        const int kFrameWidthValue = windowRectValue.right - windowRectValue.left;
        const int kFrameHeightValue = windowRectValue.bottom - windowRectValue.top;
        const int kBorderWidth = std::max(
            8,
            static_cast<int>(
                ::GetSystemMetrics(SM_CXSIZEFRAME)
                + ::GetSystemMetrics(SM_CXPADDEDBORDER)));

        // Edge resize hit priority:
        // - Must be processed before title bar drag hit detection; otherwise, the title bar will consume the top/left/right resize areas.
        // - This is the direct cause of the window being unresizable.
        if (!kMaximizedInNativeMessage)
        {
            const bool kHitLeft = kFrameLocalPoint.x() >= 0 && kFrameLocalPoint.x() < kBorderWidth;
            const bool kHitRight =
                kFrameLocalPoint.x() <= kFrameWidthValue
                && kFrameLocalPoint.x() > (kFrameWidthValue - kBorderWidth);
            const bool kHitTop = kFrameLocalPoint.y() >= 0 && kFrameLocalPoint.y() < kBorderWidth;
            const bool kHitBottom =
                kFrameLocalPoint.y() <= kFrameHeightValue
                && kFrameLocalPoint.y() > (kFrameHeightValue - kBorderWidth);

            if (kHitTop && kHitLeft)
            {
                *result = HTTOPLEFT;
                return true;
            }
            if (kHitTop && kHitRight)
            {
                *result = HTTOPRIGHT;
                return true;
            }
            if (kHitBottom && kHitLeft)
            {
                *result = HTBOTTOMLEFT;
                return true;
            }
            if (kHitBottom && kHitRight)
            {
                *result = HTBOTTOMRIGHT;
                return true;
            }
            if (kHitLeft)
            {
                *result = HTLEFT;
                return true;
            }
            if (kHitRight)
            {
                *result = HTRIGHT;
                return true;
            }
            if (kHitTop)
            {
                *result = HTTOP;
                return true;
            }
            if (kHitBottom)
            {
                *result = HTBOTTOM;
                return true;
            }
        }

        // Compatibility handling: if a negative coordinate strip exists at the top (residual non-client area), treat it as a draggable title bar and return true.
        if (kLocalPoint.y() < 0 && kLocalPoint.y() >= -kBorderWidth)
        {
            *result = HTCAPTION;
            return true;
        }

        // Custom-drawn title bar hit:
        // - Border scaling is handled above with priority; this only processes the actual draggable area of the title bar.
        // - After returning HTCAPTION, Windows DefWindowProc takes over move, double-click, and Aero Snap operations.
        // - Maximizing the window and dragging it from the title bar also triggers the system-native 'restore and continue moving' semantics.
        // - Right-side window buttons, command input box, and user avatar are excluded by isPointInDraggableRegion, preserving Qt click handling.
        if (customTitleBar_ != nullptr
            && customTitleBar_->isVisible()
            && customTitleBar_->isEnabled())
        {
            const QPoint kTitleBarLocalPoint = customTitleBar_->mapFromGlobal(kScreenQPoint);
            if (customTitleBar_->isPointInDraggableRegion(kTitleBarLocalPoint))
            {
                *result = HTCAPTION;
                return true;
            }
        }

    }
#endif

    return QMainWindow::nativeEvent(eventType, message, result);
}

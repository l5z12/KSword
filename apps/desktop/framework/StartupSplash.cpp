#include "StartupSplash.h"

#include "../internationalization/LanguageManager.h"

#include <QtCore/QFile>
#include <QtCore/QString>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <objidl.h>
#include <propidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <memory>
#include <string>

#pragma comment(lib, "Gdiplus.lib")
#pragma comment(lib, "Ole32.lib")

namespace
{
    // kFrameworkSplashClassName:
    // - Native window class name for the Framework startup splash screen;
    // - Used to register and create a Win32 Layered Window.
    constexpr wchar_t kFrameworkSplashClassName[] = L"KswordFrameworkStartupSplashWindow";

    // kFrameworkSplashLogoResourcePath*: Purpose:
    // - Store the qrc resource paths for the Chinese and English startup images separately;
    // - The splash image is loaded directly from program resources without relying on disk directories.
    constexpr auto kFrameworkSplashLogoResourcePathEnglish =
        ":/Image/Resource/Logo/KswordHome-En.png";
    constexpr auto kFrameworkSplashLogoResourcePathChinese =
        ":/Image/Resource/Logo/KswordHome-ZH.png";

    // frameworkSplashLogoResourcePath:
    // - Select the startup image based on the final interface language resolved by LanguageManager.
    // - Use Chinese images for Simplified Chinese; use English images for other languages.
    QString frameworkSplashLogoResourcePath()
    {
        const QString kCurrentLanguageId =
            ks::i18n::LanguageManager::instance().currentLanguageId();
        return QString::fromLatin1(
            kCurrentLanguageId.startsWith(QStringLiteral("zh"), Qt::CaseInsensitive)
                ? kFrameworkSplashLogoResourcePathChinese
                : kFrameworkSplashLogoResourcePathEnglish);
    }

    // clampProgressPercent:
    // - Clamp progress value to 0~100.
    // - Prevents negative values or overflow in progress bar width.
    int clampProgressPercent(const int rawPercentValue)
    {
        return std::clamp(rawPercentValue, 0, 100);
    }

    // utf8ToWideText:
    // Converts UTF-8 text to a UTF-16 wide string;
    // - Used by GDI+ DrawString to render Chinese status text.
    // Invocation: convert business text when progress is called.
    // Input utf8Text: UTF-8 encoded text.
    // Return: UTF-16 wide string; returns empty string on failure.
    std::wstring utf8ToWideText(const std::string& utf8Text)
    {
        if (utf8Text.empty())
        {
            return std::wstring();
        }

        const int kRequiredLength = ::MultiByteToWideChar(
            CP_UTF8,
            0,
            utf8Text.c_str(),
            -1,
            nullptr,
            0);
        if (kRequiredLength <= 1)
        {
            return std::wstring();
        }

        std::wstring wideTextBuffer(static_cast<std::size_t>(kRequiredLength - 1), L'\0');
        const int kConvertResult = ::MultiByteToWideChar(
            CP_UTF8,
            0,
            utf8Text.c_str(),
            -1,
            wideTextBuffer.data(),
            kRequiredLength);
        if (kConvertResult <= 1)
        {
            return std::wstring();
        }
        return wideTextBuffer;
    }

    // querySystemDpiValue:
    // - Retrieve the current system DPI value.
    // - On new systems, call GetDpiForSystem first; on old systems, fall back to 96 DPI.
    // Returns: System DPI (>=96).
    UINT querySystemDpiValue()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using GetDpiForSystemFunction = UINT(WINAPI*)();
            const GetDpiForSystemFunction kGetDpiForSystemFunction =
                reinterpret_cast<GetDpiForSystemFunction>(
                    ::GetProcAddress(user32ModuleHandle, "GetDpiForSystem"));
            if (kGetDpiForSystemFunction != nullptr)
            {
                const UINT kQueriedDpi = kGetDpiForSystemFunction();
                if (kQueriedDpi >= 96U)
                {
                    return kQueriedDpi;
                }
            }
        }
        return 96U;
    }

    // pumpNativeSplashMessages:
    // - Manually pump the startup window's Win32 message loop once;
    // - Avoid dispatching Qt main window messages too early, which would disrupt the first frame and event timing.
    // Parameter splashWindowHandle: splash window handle.
    void pumpNativeSplashMessages(const HWND splashWindowHandle)
    {
        if (splashWindowHandle == nullptr)
        {
            return;
        }

        MSG pendingMessage = {};
        while (::PeekMessageW(&pendingMessage, splashWindowHandle, 0, 0, PM_REMOVE) != FALSE)
        {
            ::TranslateMessage(&pendingMessage);
            ::DispatchMessageW(&pendingMessage);
        }
    }
}

// KStartupSplash::Impl:
// - Host all Win32/GDI+ resources and drawing logic for the startup window;
// - Unified scheduling by the outer KStartupSplash via PImpl.
class KStartupSplash::Impl final
{
public:
    // Constructor purpose:
    // - initialize default status text and drawing parameters;
    // - Avoids creating heavyweight resources.
    Impl() = default;

    // Destructor purpose:
    // - Uniformly release window handles and GDI+ resources.
    // - Avoid leaving objects behind when the process exits.
    ~Impl()
    {
        shutdown();
    }

    // showWindow:
    // - Ensure the startup window is displayed only after successful initialization.
    // - Synchronously render the first frame on initial display.
    // Returns: true if the window was displayed successfully; false if initialization failed.
    bool showWindow(const std::string& initialStatusTextUtf8)
    {
        const std::wstring kInitialStatusText = utf8ToWideText(initialStatusTextUtf8);
        if (!kInitialStatusText.empty())
        {
            statusText_ = kInitialStatusText;
        }
        progressPercent_ = 0;

        if (!initialize())
        {
            return false;
        }
        if (windowHandle_ == nullptr)
        {
            return false;
        }

        recalculateLayoutMetrics();
        renderFrame();
        ::ShowWindow(windowHandle_, SW_SHOWNOACTIVATE);
        ::UpdateWindow(windowHandle_);
        pumpNativeSplashMessages(windowHandle_);
        return true;
    }

    // hideWindow:
    // - Hide the startup window but keep the handle to support re-displaying it later.
    // - Does not destroy GDI+ and image resources.
    void hideWindow()
    {
        if (windowHandle_ != nullptr)
        {
            ::ShowWindow(windowHandle_, SW_HIDE);
            pumpNativeSplashMessages(windowHandle_);
        }
    }

    // setProgressState:
    // - Update status text and progress percentage.
    // - Immediately repaint and pump messages to ensure real-time visual feedback.
    // Parameter operationNameUtf8: current operation name (UTF-8).
    // Input parameter progressPercent: progress percentage (0~100).
    void setProgressState(const std::string& operationNameUtf8, const int progressPercent)
    {
        if (windowHandle_ == nullptr || !initialized_)
        {
            return;
        }

        const std::wstring kNextStatusText = utf8ToWideText(operationNameUtf8);
        if (!kNextStatusText.empty())
        {
            statusText_ = kNextStatusText;
        }
        progressPercent_ = clampProgressPercent(progressPercent);
        renderFrame();
        pumpNativeSplashMessages(windowHandle_);
    }

    // isReady:
    // - Check if the current implementation object is ready to display.
    // Returns: true if initialization is complete and the window handle is valid.
    bool isReady() const
    {
        return initialized_ && windowHandle_ != nullptr;
    }

private:
    // StreamReleaser:
    // - IStream smart pointer deleter;
    // - Used to safely release COM memory stream objects.
    struct StreamReleaser
    {
        void operator()(IStream* streamPointer) const
        {
            if (streamPointer != nullptr)
            {
                streamPointer->Release();
            }
        }
    };

    // initialize:
    // - initialize GDI+, load the logo, register the window class, and create the window.
    // - After successful initialization, show/progress can be executed.
    bool initialize()
    {
        if (initialized_)
        {
            return true;
        }

        // startupInput: GDI+ startup configuration input structure.
        Gdiplus::GdiplusStartupInput startupInput;
        const Gdiplus::Status kStartupResult = Gdiplus::GdiplusStartup(
            &gdiplusToken_,
            &startupInput,
            nullptr);
        if (kStartupResult != Gdiplus::Ok)
        {
            return false;
        }

        // logoFile purpose: Reads the binary data of the embedded qrc Logo.
        QFile logoFile(frameworkSplashLogoResourcePath());
        if (!logoFile.open(QIODevice::ReadOnly))
        {
            shutdown();
            return false;
        }

        // logoBytes purpose: Holds the raw byte stream of the Logo PNG.
        const QByteArray kLogoBytes = logoFile.readAll();
        if (kLogoBytes.isEmpty())
        {
            shutdown();
            return false;
        }

        // memoryHandle purpose: Allocate a movable global memory block for COM IStream.
        HGLOBAL memoryHandle = ::GlobalAlloc(GMEM_MOVEABLE, static_cast<SIZE_T>(kLogoBytes.size()));
        if (memoryHandle == nullptr)
        {
            shutdown();
            return false;
        }

        void* memoryPointer = ::GlobalLock(memoryHandle);
        if (memoryPointer == nullptr)
        {
            ::GlobalFree(memoryHandle);
            shutdown();
            return false;
        }
        std::memcpy(memoryPointer, kLogoBytes.constData(), static_cast<std::size_t>(kLogoBytes.size()));
        ::GlobalUnlock(memoryHandle);

        IStream* streamRawPointer = nullptr;
        const HRESULT kCreateStreamResult = ::CreateStreamOnHGlobal(memoryHandle, TRUE, &streamRawPointer);
        if (FAILED(kCreateStreamResult) || streamRawPointer == nullptr)
        {
            ::GlobalFree(memoryHandle);
            shutdown();
            return false;
        }
        logoStream_.reset(streamRawPointer);

        // imageRawPointer: Raw pointer to a GDI+ image object, later managed by a unique_ptr.
        Gdiplus::Image* imageRawPointer = Gdiplus::Image::FromStream(logoStream_.get(), FALSE);
        logoImage_.reset(imageRawPointer);
        if (!logoImage_ || logoImage_->GetLastStatus() != Gdiplus::Ok)
        {
            shutdown();
            return false;
        }

        if (!registerWindowClassIfNeeded())
        {
            shutdown();
            return false;
        }

        recalculateLayoutMetrics();

        // windowStyleEx purpose: Combine layered transparency, topmost, and no-activate startup window styles.
        const DWORD kWindowStyleEx = WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE;
        windowHandle_ = ::CreateWindowExW(
            kWindowStyleEx,
            kFrameworkSplashClassName,
            L"",
            WS_POPUP,
            windowPosX_,
            windowPosY_,
            windowWidth_,
            windowHeight_,
            nullptr,
            nullptr,
            ::GetModuleHandleW(nullptr),
            this);
        if (windowHandle_ == nullptr)
        {
            shutdown();
            return false;
        }

        initialized_ = true;
        return true;
    }

    // shutdown:
    // - Recycle native windows, image streams, and GDI+;
    // - Reuse in destructor and initialization failure rollback scenarios.
    void shutdown()
    {
        if (windowHandle_ != nullptr)
        {
            ::DestroyWindow(windowHandle_);
            windowHandle_ = nullptr;
        }
        logoImage_.reset();
        logoStream_.reset();
        if (gdiplusToken_ != 0)
        {
            Gdiplus::GdiplusShutdown(gdiplusToken_);
            gdiplusToken_ = 0;
        }
        initialized_ = false;
    }

    // registerWindowClassIfNeeded:
    // - Registers the startup window class only on the first call;
    // - Safe for repeated calls.
    bool registerWindowClassIfNeeded()
    {
        static bool classRegistered = false;
        if (classRegistered)
        {
            return true;
        }

        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = &Impl::windowProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.lpszClassName = kFrameworkSplashClassName;
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = nullptr;

        const ATOM kRegisterResult = ::RegisterClassExW(&windowClass);
        if (kRegisterResult == 0)
        {
            const DWORD kErrorCode = ::GetLastError();
            if (kErrorCode != ERROR_CLASS_ALREADY_EXISTS)
            {
                return false;
            }
        }

        classRegistered = true;
        return true;
    }

    // recalculateLayoutMetrics:
    // - Recalculates logo drawing dimensions and window size based on system DPI and screen dimensions.
    // - Ensure the startup image maintains a consistent visual aspect ratio at different scales.
    void recalculateLayoutMetrics()
    {
        if (!logoImage_)
        {
            return;
        }

        currentDpi_ = std::max(96U, querySystemDpiValue());
        dpiScaleFactor_ = static_cast<double>(currentDpi_) / 96.0;

        // Fix pixel parameters based on DPI scaling to address controls appearing too small at high scaling factors.
        padding_ = std::max(8, static_cast<int>(std::lround(basePadding_ * dpiScaleFactor_)));
        bottomAreaHeight_ = std::max(28, static_cast<int>(std::lround(baseBottomAreaHeight_ * dpiScaleFactor_)));
        logoInfoSpacing_ = std::max(6, static_cast<int>(std::lround(baseLogoInfoSpacing_ * dpiScaleFactor_)));
        statusFontPixelSize_ = std::max(9.0f, static_cast<float>(baseStatusFontPixelSize_ * dpiScaleFactor_));
        trackHeight_ = std::max(4, static_cast<int>(std::lround(baseTrackHeight_ * dpiScaleFactor_)));

        // sourceLogoWidth/sourceLogoHeight: Original pixel dimensions of the logo.
        const int kSourceLogoWidth = std::max(1, static_cast<int>(logoImage_->GetWidth()));
        const int kSourceLogoHeight = std::max(1, static_cast<int>(logoImage_->GetHeight()));

        // screenWidth/screenHeight: The current primary screen's pixel width and height.
        const int kScreenWidth = std::max(1, ::GetSystemMetrics(SM_CXSCREEN));
        const int kScreenHeight = std::max(1, ::GetSystemMetrics(SM_CYSCREEN));

        // Scale minimum display size by DPI to ensure the logo remains clear and proportionally reasonable at high scaling factors.
        const int kMinLogoWidth = std::max(1, static_cast<int>(std::lround(320.0 * dpiScaleFactor_)));
        const int kMinLogoHeight = std::max(1, static_cast<int>(std::lround(220.0 * dpiScaleFactor_)));
        const int kMaxLogoWidth = std::max(kMinLogoWidth, (kScreenWidth * 40) / 100);
        const int kMaxLogoHeight = std::max(kMinLogoHeight, (kScreenHeight * 38) / 100);

        const double kScaleByWidth = static_cast<double>(kMaxLogoWidth) / static_cast<double>(kSourceLogoWidth);
        const double kScaleByHeight = static_cast<double>(kMaxLogoHeight) / static_cast<double>(kSourceLogoHeight);
        const double kFinalScale = std::min(1.0, std::min(kScaleByWidth, kScaleByHeight));

        logoDrawWidth_ = std::max(1, static_cast<int>(std::lround(kSourceLogoWidth * kFinalScale)));
        logoDrawHeight_ = std::max(1, static_cast<int>(std::lround(kSourceLogoHeight * kFinalScale)));

        windowWidth_ = logoDrawWidth_ + (padding_ * 2);
        windowHeight_ = logoDrawHeight_ + (padding_ * 2) + logoInfoSpacing_ + bottomAreaHeight_;
        windowPosX_ = (kScreenWidth - windowWidth_) / 2;
        windowPosY_ = (kScreenHeight - windowHeight_) / 2;

        if (windowHandle_ != nullptr)
        {
            ::SetWindowPos(
                windowHandle_,
                HWND_TOPMOST,
                windowPosX_,
                windowPosY_,
                windowWidth_,
                windowHeight_,
                SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }
    }

    // renderFrame:
    // - Use a 32-bit ARGB DIB to draw the transparent startup window.
    // - Submits to the system desktop via UpdateLayeredWindow.
    void renderFrame()
    {
        if (windowHandle_ == nullptr || !logoImage_)
        {
            return;
        }

        HDC screenDeviceContext = ::GetDC(nullptr);
        if (screenDeviceContext == nullptr)
        {
            return;
        }

        HDC memoryDeviceContext = ::CreateCompatibleDC(screenDeviceContext);
        if (memoryDeviceContext == nullptr)
        {
            ::ReleaseDC(nullptr, screenDeviceContext);
            return;
        }

        BITMAPINFO bitmapInfo = {};
        bitmapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bitmapInfo.bmiHeader.biWidth = windowWidth_;
        bitmapInfo.bmiHeader.biHeight = -windowHeight_;
        bitmapInfo.bmiHeader.biPlanes = 1;
        bitmapInfo.bmiHeader.biBitCount = 32;
        bitmapInfo.bmiHeader.biCompression = BI_RGB;

        void* dibBitsPointer = nullptr;
        HBITMAP dibBitmapHandle = ::CreateDIBSection(
            memoryDeviceContext,
            &bitmapInfo,
            DIB_RGB_COLORS,
            &dibBitsPointer,
            nullptr,
            0);
        if (dibBitmapHandle == nullptr)
        {
            ::DeleteDC(memoryDeviceContext);
            ::ReleaseDC(nullptr, screenDeviceContext);
            return;
        }

        HGDIOBJ oldBitmapHandle = ::SelectObject(memoryDeviceContext, dibBitmapHandle);

        {
            Gdiplus::Graphics graphics(memoryDeviceContext);
            graphics.SetCompositingMode(Gdiplus::CompositingModeSourceOver);
            graphics.SetCompositingQuality(Gdiplus::CompositingQualityHighQuality);
            graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
            graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
            graphics.Clear(Gdiplus::Color(0, 0, 0, 0));

            // Center-draw the main logo layer.
            const int kLogoPosX = (windowWidth_ - logoDrawWidth_) / 2;
            const int kLogoPosY = padding_;
            graphics.DrawImage(
                logoImage_.get(),
                Gdiplus::Rect(kLogoPosX, kLogoPosY, logoDrawWidth_, logoDrawHeight_));

            // Bottom overlay info layer: status text + progress bar (located entirely below the logo, not obscuring the main image).
            const int kOverlayTop = kLogoPosY + logoDrawHeight_ + logoInfoSpacing_;
            const Gdiplus::RectF kOverlayRect(
                0.0f,
                static_cast<Gdiplus::REAL>(kOverlayTop),
                static_cast<Gdiplus::REAL>(windowWidth_),
                static_cast<Gdiplus::REAL>(bottomAreaHeight_));
            Gdiplus::SolidBrush overlayBrush(Gdiplus::Color(138, 0, 0, 0));
            graphics.FillRectangle(&overlayBrush, kOverlayRect);

            const int kTextPosY = kOverlayTop + std::max(6, static_cast<int>(std::lround(8.0 * dpiScaleFactor_)));
            const Gdiplus::RectF kTextRect(
                static_cast<Gdiplus::REAL>(padding_),
                static_cast<Gdiplus::REAL>(kTextPosY),
                static_cast<Gdiplus::REAL>(windowWidth_ - padding_ * 2),
                static_cast<Gdiplus::REAL>(std::max(16, static_cast<int>(std::lround(22.0 * dpiScaleFactor_)))));
            Gdiplus::Font textFont(
                L"Microsoft YaHei UI",
                statusFontPixelSize_,
                Gdiplus::FontStyleRegular,
                Gdiplus::UnitPixel);
            Gdiplus::SolidBrush textBrush(Gdiplus::Color(235, 248, 248, 248));
            graphics.DrawString(statusText_.c_str(), -1, &textFont, kTextRect, nullptr, &textBrush);

            const int kTrackMarginBottom = std::max(4, static_cast<int>(std::lround(6.0 * dpiScaleFactor_)));
            const int kTrackTop = kOverlayTop + bottomAreaHeight_ - trackHeight_ - kTrackMarginBottom;
            const int kTrackWidth = std::max(1, windowWidth_ - padding_ * 2);
            const Gdiplus::RectF kTrackRect(
                static_cast<Gdiplus::REAL>(padding_),
                static_cast<Gdiplus::REAL>(kTrackTop),
                static_cast<Gdiplus::REAL>(kTrackWidth),
                static_cast<Gdiplus::REAL>(trackHeight_));
            Gdiplus::SolidBrush trackBrush(Gdiplus::Color(130, 25, 25, 25));
            graphics.FillRectangle(&trackBrush, kTrackRect);

            const int kFilledWidth = static_cast<int>(
                std::lround(static_cast<double>(kTrackWidth) * (static_cast<double>(progressPercent_) / 100.0)));
            const Gdiplus::RectF kValueRect(
                static_cast<Gdiplus::REAL>(padding_),
                static_cast<Gdiplus::REAL>(kTrackTop),
                static_cast<Gdiplus::REAL>(std::max(0, kFilledWidth)),
                static_cast<Gdiplus::REAL>(trackHeight_));
            Gdiplus::SolidBrush valueBrush(Gdiplus::Color(240, 67, 160, 255));
            graphics.FillRectangle(&valueBrush, kValueRect);
        }

        POINT sourcePoint = { 0, 0 };
        SIZE layerSize = { windowWidth_, windowHeight_ };
        POINT targetPoint = { windowPosX_, windowPosY_ };
        BLENDFUNCTION blendFunction = {};
        blendFunction.BlendOp = AC_SRC_OVER;
        blendFunction.SourceConstantAlpha = 255;
        blendFunction.AlphaFormat = AC_SRC_ALPHA;

        ::UpdateLayeredWindow(
            windowHandle_,
            screenDeviceContext,
            &targetPoint,
            &layerSize,
            memoryDeviceContext,
            &sourcePoint,
            0,
            &blendFunction,
            ULW_ALPHA);

        ::SelectObject(memoryDeviceContext, oldBitmapHandle);
        ::DeleteObject(dibBitmapHandle);
        ::DeleteDC(memoryDeviceContext);
        ::ReleaseDC(nullptr, screenDeviceContext);
    }

    // windowProc:
    // - Handle basic startup window messages.
    // - Disable background erasure to prevent the transparent layer from flashing white.
    // Parameters hwnd/message/wParam/lParam: Standard Win32 message parameters.
    // Returns: The message processing result.
    static LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (message == WM_NCCREATE)
        {
            const CREATESTRUCTW* createStructPointer = reinterpret_cast<const CREATESTRUCTW*>(lParam);
            if (createStructPointer != nullptr)
            {
                Impl* selfPointer = reinterpret_cast<Impl*>(createStructPointer->lpCreateParams);
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(selfPointer));
            }
        }

        switch (message)
        {
        case WM_ERASEBKGND:
            return 1;
        default:
            return ::DefWindowProcW(hwnd, message, wParam, lParam);
        }
    }

private:
    HWND windowHandle_ = nullptr;                              // m_windowHandle: Startup window handle.
    ULONG_PTR gdiplusToken_ = 0;                              // m_gdiplusToken: GDI+ runtime token.
    std::unique_ptr<Gdiplus::Image> logoImage_;               // m_logoImage: Logo image object.
    std::unique_ptr<IStream, StreamReleaser> logoStream_;     // m_logoStream: Logo memory stream object.
    std::wstring statusText_ = L"KSword";                      // m_statusText: Current status text; the first startup frame is overridden by the caller based on language policy.
    int progressPercent_ = 0;                                 // m_progressPercent: Progress percentage.
    int windowWidth_ = 480;                                   // m_windowWidth: Window width in pixels.
    int windowHeight_ = 320;                                  // m_windowHeight: Window height in pixels.
    int logoDrawWidth_ = 360;                                 // m_logoDrawWidth: Logo drawing width in pixels.
    int logoDrawHeight_ = 220;                                // m_logoDrawHeight: Logo drawing height in pixels.
    int windowPosX_ = 0;                                      // m_windowPosX: X coordinate of the top-left corner of the window.
    int windowPosY_ = 0;                                      // m_windowPosY: Y coordinate of the top-left corner of the window.
    int padding_ = 24;                                        // m_padding: Window padding (value after DPI scaling).
    int bottomAreaHeight_ = 56;                               // m_bottomAreaHeight: Bottom info area height (value after DPI scaling).
    int logoInfoSpacing_ = 12;                                // m_logoInfoSpacing: Vertical spacing between the logo and the info area.
    float statusFontPixelSize_ = 12.0f;                       // m_statusFontPixelSize: Pixel size for status text font.
    int trackHeight_ = 8;                                     // m_trackHeight: Progress bar track height.
    bool initialized_ = false;                                // m_initialized: Whether initialization is complete.
    UINT currentDpi_ = 96U;                                   // m_currentDpi: Current system DPI.
    double dpiScaleFactor_ = 1.0;                             // m_dpiScaleFactor: DPI scaling factor.
    int basePadding_ = 24;                                    // m_basePadding: 96DPI baseline padding.
    int baseBottomAreaHeight_ = 56;                           // m_baseBottomAreaHeight: Base bottom area height at 96 DPI.
    int baseLogoInfoSpacing_ = 12;                            // m_baseLogoInfoSpacing: Spacing between the baseline logo and information at 96 DPI.
    float baseStatusFontPixelSize_ = 12.0f;                   // m_baseStatusFontPixelSize: Base font size in pixels at 96 DPI.
    int baseTrackHeight_ = 8;                                 // m_baseTrackHeight: 96 DPI baseline progress bar height.
};

KStartupSplash::KStartupSplash()
    : impl_(std::make_unique<Impl>())
{
}

KStartupSplash::~KStartupSplash() = default;

bool KStartupSplash::show(const std::string& initialStatusText)
{
    if (!impl_)
    {
        return false;
    }
    return impl_->showWindow(initialStatusText);
}

void KStartupSplash::hide()
{
    if (impl_)
    {
        impl_->hideWindow();
    }
}

void KStartupSplash::progress(const std::string& operationName, const int progressPercent)
{
    if (impl_)
    {
        impl_->setProgressState(operationName, progressPercent);
    }
}

bool KStartupSplash::ready() const
{
    if (!impl_)
    {
        return false;
    }
    return impl_->isReady();
}

// kSplash:
// - Definition of the Framework global startup splash control object.
// - Corresponds to the extern declaration in Framework.h.
KStartupSplash kSplash;

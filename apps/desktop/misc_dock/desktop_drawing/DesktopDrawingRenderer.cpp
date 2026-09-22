#include "DesktopDrawingRenderer.h"

#include <algorithm>
#include <cmath>
#include <cwchar>

#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "User32.lib")

namespace
{
    // Only change the thread context for this call; must restore before returning to the Qt event loop.
    class PhysicalPixels final
    {
    public:
        PhysicalPixels()
        {
            const HMODULE kUser32 = ::GetModuleHandleW(L"user32.dll");
            setContext_ = kUser32 ? reinterpret_cast<SetContext>(
                ::GetProcAddress(kUser32, "SetThreadDpiAwarenessContext")) : nullptr;
            if (setContext_)
            {
                previous_ = setContext_(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            }
        }
        ~PhysicalPixels()
        {
            if (setContext_ && previous_)
            {
                setContext_(previous_);
            }
        }

    private:
        using SetContext = DPI_AWARENESS_CONTEXT(WINAPI*)(DPI_AWARENESS_CONTEXT);
        SetContext setContext_ = nullptr;
        DPI_AWARENESS_CONTEXT previous_ = nullptr;
    };

    // Stop after lock screen, UAC secure desktop, or input desktop switch; do not continue writing across desktops.
    bool isCurrentInputDesktop()
    {
        const HDESK kInput = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
        if (!kInput)
        {
            return false;
        }
        wchar_t inputName[256]{};
        wchar_t threadName[256]{};
        DWORD required = 0;
        const bool kSame = ::GetUserObjectInformationW(kInput, UOI_NAME,
            inputName, sizeof(inputName), &required)
            && ::GetUserObjectInformationW(::GetThreadDesktop(::GetCurrentThreadId()),
                UOI_NAME, threadName, sizeof(threadName), &required)
            && std::wcscmp(inputName, threadName) == 0;
        ::CloseDesktop(kInput);
        return kSame;
    }

    BOOL CALLBACK collectDisplay(HMONITOR monitor, HDC, LPRECT, LPARAM context)
    {
        MONITORINFOEXW info{};
        info.cbSize = sizeof(info);
        if (::GetMonitorInfoW(monitor, &info))
        {
            auto& displays = *reinterpret_cast<std::vector<ks::misc::desktop_drawing::Display>*>(context);
            displays.push_back({ monitor, info.rcMonitor, info.szDevice,
                (info.dwFlags & MONITORINFOF_PRIMARY) != 0 });
        }
        return TRUE;
    }

    // Only request repainting of affected areas; do not re-paste the screen capture from startup to avoid overwriting content that appeared later.
    BOOL CALLBACK repaintWindow(HWND window, LPARAM context)
    {
        if (!::IsWindowVisible(window) || ::IsIconic(window))
        {
            return TRUE;
        }
        const auto& dirty = *reinterpret_cast<const RECT*>(context);
        RECT bounds{}, overlap{};
        if (::GetWindowRect(window, &bounds) && ::IntersectRect(&overlap, &bounds, &dirty))
        {
            POINT origin{};
            if (::ClientToScreen(window, &origin))
            {
                ::OffsetRect(&overlap, -origin.x, -origin.y);
                // Avoid UPDATENOW / ERASENOW to prevent blocking by external window message processing.
                ::RedrawWindow(window, &overlap, nullptr,
                    RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
            }
        }
        return TRUE;
    }

    bool paintPattern(HDC dc, const ks::misc::desktop_drawing::Options& options)
    {
        using ks::misc::desktop_drawing::Pattern;
        const int kX = options.display.bounds.left + options.x;
        const int kY = options.display.bounds.top + options.y;
        const int kRadius = options.size / 2;
        switch (options.pattern)
        {
        case Pattern::kCross:
        {
            const POINT kHorizontal[] = { { kX - kRadius, kY }, { kX + kRadius, kY } };
            const POINT kVertical[] = { { kX, kY - kRadius }, { kX, kY + kRadius } };
            return ::Polyline(dc, kHorizontal, 2) && ::Polyline(dc, kVertical, 2);
        }
        case Pattern::kCircle:
            return ::Ellipse(dc, kX - kRadius, kY - kRadius, kX + kRadius, kY + kRadius) != FALSE;
        case Pattern::kRectangle:
            return ::Rectangle(dc, kX - kRadius, kY - kRadius, kX + kRadius, kY + kRadius) != FALSE;
        case Pattern::kDiamond:
        {
            const POINT kPoints[] = { { kX, kY - kRadius }, { kX + kRadius, kY },
                { kX, kY + kRadius }, { kX - kRadius, kY }, { kX, kY - kRadius } };
            return ::Polyline(dc, kPoints, 5) != FALSE;
        }
        case Pattern::kStar:
        {
            POINT points[11]{};
            constexpr double kPi = 3.14159265358979323846;
            for (int index = 0; index < 10; ++index)
            {
                const double kAngle = -kPi / 2.0 + index * kPi / 5.0;
                const double kDistance = kRadius * (index % 2 == 0 ? 1.0 : 0.382);
                points[index] = { kX + static_cast<LONG>(std::lround(std::cos(kAngle) * kDistance)),
                    kY + static_cast<LONG>(std::lround(std::sin(kAngle) * kDistance)) };
            }
            points[10] = points[0];
            return ::Polyline(dc, points, 11) != FALSE;
        }
        }
        return false;
    }
}

namespace ks::misc::desktop_drawing
{
    std::vector<Display> enumerateDisplays()
    {
        const PhysicalPixels kPhysicalPixels;
        std::vector<Display> displays;
        if (!::EnumDisplayMonitors(nullptr, nullptr, collectDisplay, reinterpret_cast<LPARAM>(&displays)))
        {
            displays.clear();
        }
        std::stable_sort(displays.begin(), displays.end(), [](const Display& left, const Display& right)
            { return left.primary && !right.primary; });
        return displays;
    }

    Renderer::~Renderer()
    {
        stop();
    }

    DrawResult Renderer::start(const Options& options)
    {
        stop();
        options_ = options;
        options_.size = std::clamp(options.size, 16, 1024);
        options_.lineWidth = std::clamp(options.lineWidth, 1, 32);
        pen_ = ::CreatePen(PS_SOLID, options_.lineWidth, options_.color);
        if (!pen_)
        {
            return DrawResult::kResourceFailure;
        }
        const DrawResult kResult = drawFrame();
        if (kResult != DrawResult::kSuccess)
        {
            stop();
        }
        return kResult;
    }

    DrawResult Renderer::drawFrame()
    {
        if (!pen_)
        {
            return DrawResult::kResourceFailure;
        }
        if (!isCurrentInputDesktop())
        {
            return DrawResult::kDesktopUnavailable;
        }
        const PhysicalPixels kPhysicalPixels;
        MONITORINFOEXW display{};
        display.cbSize = sizeof(display);
        if (!::GetMonitorInfoW(options_.display.handle, &display)
            || !::EqualRect(&display.rcMonitor, &options_.display.bounds)
            || options_.display.name != display.szDevice)
        {
            return DrawResult::kDisplayChanged;
        }
        const int kX = display.rcMonitor.left + options_.x;
        const int kY = display.rcMonitor.top + options_.y;
        const int kMargin = options_.size / 2 + options_.lineWidth + 2;
        const RECT kPatternBounds{ kX - kMargin, kY - kMargin, kX + kMargin + 1, kY + kMargin + 1 };
        if (!::IntersectRect(&dirtyBounds_, &kPatternBounds, &display.rcMonitor))
        {
            return DrawResult::kDisplayChanged;
        }

        const HDC kDc = ::GetDC(nullptr);
        if (!kDc)
        {
            return DrawResult::kResourceFailure;
        }
        const int kSaved = ::SaveDC(kDc);
        bool painted = false;
        if (kSaved != 0)
        {
            const HGDIOBJ kOldPen = ::SelectObject(kDc, pen_);
            const HGDIOBJ kOldBrush = ::SelectObject(kDc, ::GetStockObject(HOLLOW_BRUSH));
            const int kClipped = ::IntersectClipRect(kDc, dirtyBounds_.left,
                dirtyBounds_.top, dirtyBounds_.right, dirtyBounds_.bottom);
            if (kOldPen && kOldPen != HGDI_ERROR && kOldBrush && kOldBrush != HGDI_ERROR
                && kClipped != ERROR && kClipped != NULLREGION && ::SetROP2(kDc, R2_COPYPEN))
            {
                hasDrawn_ = true; // Even if drawing fails mid-process, clean up any partially written data upon stopping.
                painted = paintPattern(kDc, options_);
                const BOOL kFlushed = ::GdiFlush();
                painted = painted && kFlushed;
            }
            ::RestoreDC(kDc, kSaved);
        }
        ::ReleaseDC(nullptr, kDc); // Released within the same thread and frame without holding the display DC.
        return painted ? DrawResult::kSuccess : DrawResult::kDrawFailure;
    }

    void Renderer::stop()
    {
        if (pen_)
        {
            ::DeleteObject(pen_);
            pen_ = nullptr;
        }
        if (hasDrawn_)
        {
            hasDrawn_ = false;
            const PhysicalPixels kPhysicalPixels;
            ::RedrawWindow(nullptr, &dirtyBounds_, nullptr,
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
            ::EnumWindows(repaintWindow, reinterpret_cast<LPARAM>(&dirtyBounds_));
        }
    }
}

#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace ks::misc::desktop_drawing
{
    enum class Pattern { kCross, kCircle, kRectangle, kDiamond, kStar };
    enum class DrawResult { kSuccess, kDesktopUnavailable, kDisplayChanged, kResourceFailure, kDrawFailure };

    struct Display
    {
        HMONITOR handle = nullptr;
        RECT bounds{}; // Win32 physical pixels; secondary screens allow negative origins.
        std::wstring name;
        bool primary = false;
    };

    struct Options
    {
        Display display;
        Pattern pattern = Pattern::kStar;
        int x = 0; // Physical pixels relative to the top-left corner of the selected display.
        int y = 0;
        int size = 160;
        int lineWidth = 3;
        COLORREF color = RGB(255, 80, 80);
    };

    // Decoupled from Qt's logical screen coordinates; enumeration and rendering use the same DPI context.
    std::vector<Display> enumerateDisplays();

    // All methods must be called only from the creator's UI thread. Each frame acquires and releases the screen DC; no
    // HWND is created, no handle to the target process is obtained, and the target window's Z-order is not modified.
    class Renderer final
    {
    public:
        Renderer() = default;
        ~Renderer();
        Renderer(const Renderer&) = delete;
        Renderer& operator=(const Renderer&) = delete;

        DrawResult start(const Options& options);
        DrawResult drawFrame();
        void stop();

    private:
        Options options_;
        HPEN pen_ = nullptr;
        RECT dirtyBounds_{};
        bool hasDrawn_ = false;
    };
}

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <windowsx.h>

#include "KTitleBar.h"

#include "KTheme.h"
#include "../resource.h"
#include "../platform/Ksword.h"

#include "Fl.H"
#include "Fl_ICO_Image.H"
#include "Fl_PNG_Image.H"
#include "fl_draw.H"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <vector>

// The bundled FLTK headers in this repository are included without an FL/
// prefix, while platform.H expects that layout. Declare only the Win32 handle
// bridge we need and keep the implementation linked from the existing FLTK lib.
extern HWND fl_win32_xid(const Fl_Window* window);

namespace {
constexpr int kTitleBarHeight = 42;
constexpr int kCaptionButtonWidth = 46;
constexpr int kCaptionIconSize = 24;
constexpr int kLogoTargetHeight = 26;
constexpr int kSnapEdgeMargin = 8;
constexpr int kMinimumRestoreWidth = 360;
constexpr int kMinimumRestoreHeight = 240;
constexpr int kMinimumResizeBorder = 6;
const wchar_t kChromeWndProcProp[] = L"KswordFrame3.CustomChrome.PreviousWndProc";
const wchar_t kChromeWindowProp[] = L"KswordFrame3.CustomChrome.FlWindow";

// EdgeSnap describes the basic Aero Snap target selected by a drag release.
// Input comes from root-screen cursor coordinates; None means keep normal bounds.
enum class EdgeSnap {
    kNone,
    kTop,
    kLeft,
    kRight
};

// clampByte keeps manual color blending inside the displayable 8-bit range.
// Input is an integer channel candidate; output is a valid byte channel.
unsigned char clampByte(int value) {
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 255;
    }
    return static_cast<unsigned char>(value);
}

// ClampInt constrains integer geometry values to a safe range. Inputs are the
// candidate and inclusive bounds; output is the clamped value.
int clampInt(int value, int minValue, int maxValue) {
    if (maxValue < minValue) {
        return minValue;
    }
    return std::max(minValue, std::min(value, maxValue));
}

// blendColor approximates alpha composition for FLTK colors, which are drawn as
// opaque values. Inputs are foreground/background colors and foreground opacity;
// output is a new RGB FLTK color.
Fl_Color blendColor(Fl_Color foreground, Fl_Color background, double opacity) {
    opacity = std::max(0.0, std::min(1.0, opacity));
    uchar fr = 0;
    uchar fg = 0;
    uchar fb = 0;
    uchar br = 0;
    uchar bg = 0;
    uchar bb = 0;
    Fl::get_color(foreground, fr, fg, fb);
    Fl::get_color(background, br, bg, bb);
    const double kInv = 1.0 - opacity;
    return fl_rgb_color(
        clampByte(static_cast<int>(fr * opacity + br * kInv + 0.5)),
        clampByte(static_cast<int>(fg * opacity + bg * kInv + 0.5)),
        clampByte(static_cast<int>(fb * opacity + bb * kInv + 0.5)));
}

// fileExists checks whether a path points to a readable filesystem object.
// Input is a UTF-8/narrow path used by this Win32 project; output is true when present.
bool fileExists(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    const DWORD kAttrs = ::GetFileAttributesA(path.c_str());
    return kAttrs != INVALID_FILE_ATTRIBUTES && (kAttrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

// directoryOf extracts the parent directory from a Windows path. Input is a path
// string; output is an empty string when no separator exists.
std::string directoryOf(const std::string& path) {
    const std::size_t kPos = path.find_last_of("\\/");
    if (kPos == std::string::npos) {
        return "";
    }
    return path.substr(0, kPos);
}

// JoinPath appends a relative path to a base directory. Inputs are narrow paths;
// output uses a backslash separator because this project targets Windows.
std::string joinPath(const std::string& base, const std::string& child) {
    if (base.empty()) {
        return child;
    }
    const char kLast = base[base.size() - 1];
    if (kLast == '\\' || kLast == '/') {
        return base + child;
    }
    return base + "\\" + child;
}

// executableDirectory returns the directory containing the running module. It is
// used only as a fallback when embedded RCDATA extraction is unavailable.
std::string executableDirectory() {
    char modulePath[MAX_PATH] = {};
    const DWORD kWritten = ::GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
    if (kWritten == 0 || kWritten >= MAX_PATH) {
        return "";
    }
    return directoryOf(modulePath);
}

// readResourceBytes reads one RT_RCDATA resource from the current executable.
// Input is a numeric resource id; output is an empty vector when not found.
std::vector<unsigned char> readResourceBytes(int resourceId) {
    HMODULE module = ::GetModuleHandleW(nullptr);
    if (!module) {
        return {};
    }
    HRSRC resource = ::FindResourceW(module, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!resource) {
        return {};
    }
    const DWORD kSize = ::SizeofResource(module, resource);
    HGLOBAL loaded = ::LoadResource(module, resource);
    if (!loaded || kSize == 0) {
        return {};
    }
    const void* data = ::LockResource(loaded);
    if (!data) {
        return {};
    }
    const unsigned char* begin = static_cast<const unsigned char*>(data);
    return std::vector<unsigned char>(begin, begin + kSize);
}

// extractResourceToTemp writes an embedded resource to a stable temp file for
// FLTK image loaders that accept paths rather than memory buffers. Inputs are a
// resource id and file suffix; output is the temp path or empty on failure.
std::string extractResourceToTemp(int resourceId, const char* fileName) {
    const std::vector<unsigned char> kBytes = readResourceBytes(resourceId);
    if (kBytes.empty() || !fileName || !*fileName) {
        return "";
    }

    char tempDir[MAX_PATH] = {};
    const DWORD kCount = ::GetTempPathA(MAX_PATH, tempDir);
    if (kCount == 0 || kCount >= MAX_PATH) {
        return "";
    }

    const std::string kPath = joinPath(tempDir, std::string("KswordFrame3_0_") + fileName);
    // Always rewrite the temp copy so replacing the project asset and rebuilding
    // cannot accidentally display an older resource left by a previous run.
    std::ofstream out(kPath.c_str(), std::ios::binary);
    if (!out) {
        return "";
    }
    out.write(reinterpret_cast<const char*>(kBytes.data()), static_cast<std::streamsize>(kBytes.size()));
    return out ? kPath : "";
}

// resolveProjectAsset finds a resource file when running from the source tree or
// from x64/Debug|Release. Input is the resource.h relative path; output may be empty.
std::string resolveProjectAsset(const char* relativePath) {
    if (!relativePath || !*relativePath) {
        return "";
    }

    const std::string kRelative(relativePath);
    const std::string kExeDir = executableDirectory();
    std::vector<std::string> candidates;
    candidates.push_back(kRelative);
    candidates.push_back(joinPath(kExeDir, kRelative));
    candidates.push_back(joinPath(joinPath(kExeDir, "..\\..\\KswordFrame3.0"), kRelative));
    candidates.push_back(joinPath(joinPath(kExeDir, "..\\.."), kRelative));

    for (const std::string& candidate : candidates) {
        if (fileExists(candidate)) {
            return candidate;
        }
    }
    return "";
}

// windowHandle maps an FLTK window to HWND only after the window has been shown.
// Input may be null; output is null when no platform handle exists yet.
HWND windowHandle(Fl_Window* window) {
    if (!window) {
        return nullptr;
    }
    return fl_win32_xid(window);
}

// pointInRect tests absolute FLTK event coordinates against a simple rectangle.
// Inputs are point and rect; output is true only inside the rect bounds.
bool pointInRect(int px, int py, const KTitleBar::Rect& rect) {
    return rect.w > 0 && rect.h > 0 && px >= rect.x && px < rect.x + rect.w && py >= rect.y && py < rect.y + rect.h;
}

// DrawLineIcon resets the FLTK line style after custom caption button drawing.
// Input is the desired color and line width; there is no return value.
void setCaptionLineStyle(Fl_Color color, int width) {
    fl_color(color);
    fl_line_style(FL_SOLID, width);
}

// chromeSetWindowBounds applies outer window bounds in FLTK screen units. The
// optional frame refresh is size-neutral: FLTK may run with a logical-to-physical
// scale, so Win32 is asked only to recalc styles, never to resize with pixels.
void chromeSetWindowBounds(Fl_Window* window, const KTitleBar::Rect& bounds, bool refreshFrame) {
    if (!window) {
        return;
    }

    const int kSafeWidth = std::max(1, bounds.w);
    const int kSafeHeight = std::max(1, bounds.h);
    window->resize(bounds.x, bounds.y, kSafeWidth, kSafeHeight);

    HWND hwnd = windowHandle(window);
    if (!hwnd) {
        return;
    }

    ::SetWindowPos(
        hwnd,
        nullptr,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}

// chromeShowWindow is the only ShowWindow wrapper used by the custom chrome.
// Input is an FLTK window and Win32 show command; output is true if Win32 handled it.
bool chromeShowWindow(Fl_Window* window, int command) {
    HWND hwnd = windowHandle(window);
    if (!hwnd) {
        return false;
    }
    ::ShowWindow(hwnd, command);
    return true;
}

// workAreaForRootPoint returns the current monitor work area in FLTK logical
// screen units. Inputs are root-screen cursor/window-center coordinates; output
// is true only when FLTK reports a positive monitor work rectangle.
bool workAreaForRootPoint(int rootX, int rootY, KTitleBar::Rect& area) {
    int screenX = 0;
    int screenY = 0;
    int screenW = 0;
    int screenH = 0;
    Fl::screen_work_area(screenX, screenY, screenW, screenH, rootX, rootY);
    if (screenW <= 0 || screenH <= 0) {
        Fl::screen_work_area(screenX, screenY, screenW, screenH);
    }
    if (screenW <= 0 || screenH <= 0) {
        return false;
    }

    area.x = screenX;
    area.y = screenY;
    area.w = screenW;
    area.h = screenH;
    return true;
}

// workAreaForWindow returns the current monitor work area in the same FLTK
// coordinate space used by Fl_Window::resize(). This avoids mixing Win32
// physical pixels with FLTK logical units on scaled displays.
bool workAreaForWindow(Fl_Window* window, KTitleBar::Rect& area) {
    if (window) {
        const int kCenterX = window->x() + window->w() / 2;
        const int kCenterY = window->y() + window->h() / 2;
        if (workAreaForRootPoint(kCenterX, kCenterY, area)) {
            return true;
        }
    }
    return workAreaForRootPoint(Fl::event_x_root(), Fl::event_y_root(), area);
}

// snapForCursor converts a root-screen drag point into a basic snap target.
// Inputs are monitor work area and cursor coordinates; output is the edge target.
EdgeSnap snapForCursor(const KTitleBar::Rect& workArea, int rootX, int rootY) {
    if (rootY <= workArea.y + kSnapEdgeMargin) {
        return EdgeSnap::kTop;
    }
    if (rootX <= workArea.x + kSnapEdgeMargin) {
        return EdgeSnap::kLeft;
    }
    if (rootX >= workArea.x + workArea.w - kSnapEdgeMargin - 1) {
        return EdgeSnap::kRight;
    }
    return EdgeSnap::kNone;
}

// findInstalledTitleBar detects a previously installed KTitleBar child. Input is
// a window; output is the child pointer or nullptr when not present.
KTitleBar* findInstalledTitleBar(Fl_Window* window) {
    if (!window) {
        return nullptr;
    }
    for (int i = 0; i < window->children(); ++i) {
        KTitleBar* bar = dynamic_cast<KTitleBar*>(window->child(i));
        if (bar) {
            return bar;
        }
    }
    return nullptr;
}

// previousChromeWndProc returns the FLTK window procedure saved before the
// custom chrome subclass was installed. Input is an HWND; output may be null
// only if subclass installation failed or the window is being destroyed.
WNDPROC previousChromeWndProc(HWND hwnd) {
    return reinterpret_cast<WNDPROC>(::GetPropW(hwnd, kChromeWndProcProp));
}

// callPreviousChromeWndProc forwards messages to FLTK so normal double-buffered
// client painting and control repaint behavior remain owned by FLTK. Inputs are
// the original Win32 message parameters; output is the previous procedure result.
LRESULT callPreviousChromeWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    WNDPROC previous = previousChromeWndProc(hwnd);
    if (previous) {
        return ::CallWindowProcW(previous, hwnd, message, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

// windowFromChromeProp maps a subclassed HWND back to its FLTK owner. Input is
// the native window handle; output is null when no live FLTK window was recorded.
Fl_Window* windowFromChromeProp(HWND hwnd) {
    return reinterpret_cast<Fl_Window*>(::GetPropW(hwnd, kChromeWindowProp));
}

// nativeResizeBorder returns the Win32 hit-test band in physical pixels. Input
// is none; output is never smaller than a practical mouse target for borderless
// resize on displays where Windows reports a very small padded frame.
int nativeResizeBorder() {
    const int kFrame = ::GetSystemMetrics(SM_CXSIZEFRAME);
    const int kPadded = ::GetSystemMetrics(SM_CXPADDEDBORDER);
    return std::max(kMinimumResizeBorder, kFrame + kPadded);
}

// clientPointInCaptionButtonBand protects custom caption buttons from native
// resize hit-tests. Inputs are the FLTK owner, HWND, and screen point; output is
// true when the point falls over the minimize/maximize/close button strip.
bool clientPointInCaptionButtonBand(Fl_Window* window, HWND hwnd, POINT screenPoint) {
    KTitleBar* bar = findInstalledTitleBar(window);
    if (!bar || !window) {
        return false;
    }

    RECT clientRect = {};
    if (!::GetClientRect(hwnd, &clientRect)) {
        return false;
    }

    POINT clientPoint = screenPoint;
    if (!::ScreenToClient(hwnd, &clientPoint)) {
        return false;
    }

    const int kClientWidth = std::max<LONG>(1, clientRect.right - clientRect.left);
    const int kClientHeight = std::max<LONG>(1, clientRect.bottom - clientRect.top);
    const double kScaleX = static_cast<double>(kClientWidth) / std::max(1, window->w());
    const double kScaleY = static_cast<double>(kClientHeight) / std::max(1, window->h());
    const int kButtonSlots = bar->showMaximize() ? 3 : 2;
    const int kButtonBand = static_cast<int>(kCaptionButtonWidth * kButtonSlots * kScaleX + 0.5);
    const int kTitleHeight = static_cast<int>(bar->h() * kScaleY + 0.5);

    return clientPoint.y >= 0 &&
           clientPoint.y < kTitleHeight &&
           clientPoint.x >= kClientWidth - kButtonBand &&
           clientPoint.x < kClientWidth;
}

// nativeResizeHitTest computes border and corner HT* codes for a borderless
// window. Inputs are the HWND, owner, and WM_NCHITTEST lParam; output is an HT
// code or HTNOWHERE when the point should remain normal FLTK client area.
LRESULT nativeResizeHitTest(HWND hwnd, Fl_Window* window, LPARAM lParam) {
    RECT windowRect = {};
    if (!::GetWindowRect(hwnd, &windowRect)) {
        return HTNOWHERE;
    }

    POINT screenPoint = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
    const int kBorder = nativeResizeBorder();
    bool onLeft = screenPoint.x >= windowRect.left && screenPoint.x < windowRect.left + kBorder;
    bool onRight = screenPoint.x < windowRect.right && screenPoint.x >= windowRect.right - kBorder;
    bool onTop = screenPoint.y >= windowRect.top && screenPoint.y < windowRect.top + kBorder;
    bool onBottom = screenPoint.y < windowRect.bottom && screenPoint.y >= windowRect.bottom - kBorder;

    // The top-right caption buttons must keep receiving FLTK mouse events, so
    // suppress native top/right resize hit-tests inside that button band.
    if ((onTop || onRight) && clientPointInCaptionButtonBand(window, hwnd, screenPoint)) {
        onTop = false;
        onRight = false;
    }

    if (onTop && onLeft) {
        return HTTOPLEFT;
    }
    if (onTop && onRight) {
        return HTTOPRIGHT;
    }
    if (onBottom && onLeft) {
        return HTBOTTOMLEFT;
    }
    if (onBottom && onRight) {
        return HTBOTTOMRIGHT;
    }
    if (onLeft) {
        return HTLEFT;
    }
    if (onRight) {
        return HTRIGHT;
    }
    if (onTop) {
        return HTTOP;
    }
    if (onBottom) {
        return HTBOTTOM;
    }
    return HTNOWHERE;
}

// windowMatchesMonitorWorkArea checks whether a manually resized borderless
// window already occupies the monitor work area. Input is HWND; output supports
// restoring the maximize icon correctly after minimize/taskbar restore.
bool windowMatchesMonitorWorkArea(HWND hwnd) {
    RECT windowRect = {};
    if (!::GetWindowRect(hwnd, &windowRect)) {
        return false;
    }

    HMONITOR monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO info = {};
    info.cbSize = sizeof(info);
    if (!monitor || !::GetMonitorInfoW(monitor, &info)) {
        return false;
    }

    constexpr int kWorkAreaTolerance = 2;
    return std::abs(windowRect.left - info.rcWork.left) <= kWorkAreaTolerance &&
           std::abs(windowRect.top - info.rcWork.top) <= kWorkAreaTolerance &&
           std::abs(windowRect.right - info.rcWork.right) <= kWorkAreaTolerance &&
           std::abs(windowRect.bottom - info.rcWork.bottom) <= kWorkAreaTolerance;
}

// applyMonitorMaxInfo constrains native maximize operations to the taskbar-safe
// monitor work area. Inputs are HWND and WM_GETMINMAXINFO lParam; return is none.
void applyMonitorMaxInfo(HWND hwnd, LPARAM lParam) {
    MINMAXINFO* minMax = reinterpret_cast<MINMAXINFO*>(lParam);
    if (!minMax) {
        return;
    }

    HMONITOR monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
    MONITORINFO info = {};
    info.cbSize = sizeof(info);
    if (!monitor || !::GetMonitorInfoW(monitor, &info)) {
        return;
    }

    const RECT& work = info.rcWork;
    const RECT& monitorRect = info.rcMonitor;
    minMax->ptMaxPosition.x = work.left - monitorRect.left;
    minMax->ptMaxPosition.y = work.top - monitorRect.top;
    minMax->ptMaxSize.x = work.right - work.left;
    minMax->ptMaxSize.y = work.bottom - work.top;
}

// syncTitleBarFromNativeSize mirrors native WM_SIZE changes into the FLTK title
// bar only. Inputs are HWND, owner, and size code; output is none.
void syncTitleBarFromNativeSize(HWND hwnd, Fl_Window* window, WPARAM sizeCode) {
    if (!window || sizeCode == SIZE_MINIMIZED) {
        return;
    }

    KTitleBar* bar = findInstalledTitleBar(window);
    if (!bar) {
        return;
    }

    const bool kMaximized = sizeCode == SIZE_MAXIMIZED || ::IsZoomed(hwnd) || windowMatchesMonitorWorkArea(hwnd);
    bar->syncFromNativeWindow(window->w(), kMaximized);
}

// chromeWindowProc adds only native-window polish around FLTK: it blocks full
// background erase, exposes resize hit-tests, and forwards all normal messages
// back to FLTK without injecting redraws during move/window-position messages.
LRESULT CALLBACK chromeWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_ERASEBKGND) {
        // Returning non-zero tells Windows the client background is already
        // handled by FLTK's buffered paint path, preventing erase-then-redraw
        // flicker while the borderless window is moved.
        return 1;
    }

    if (message == WM_NCCALCSIZE && wParam == TRUE) {
        // Keep any resizable native style invisible; the full HWND remains FLTK
        // client area and KTitleBar draws the custom chrome.
        return 0;
    }

    if (message == WM_NCHITTEST) {
        Fl_Window* window = windowFromChromeProp(hwnd);
        const LRESULT kResizeHit = nativeResizeHitTest(hwnd, window, lParam);
        if (kResizeHit != HTNOWHERE) {
            return kResizeHit;
        }
        return callPreviousChromeWndProc(hwnd, message, wParam, lParam);
    }

    if (message == WM_GETMINMAXINFO) {
        const LRESULT kResult = callPreviousChromeWndProc(hwnd, message, wParam, lParam);
        applyMonitorMaxInfo(hwnd, lParam);
        return kResult;
    }

    if (message == WM_SIZE) {
        const LRESULT kResult = callPreviousChromeWndProc(hwnd, message, wParam, lParam);
        syncTitleBarFromNativeSize(hwnd, windowFromChromeProp(hwnd), wParam);
        return kResult;
    }

    if (message == WM_NCDESTROY) {
        WNDPROC previous = previousChromeWndProc(hwnd);
        const LRESULT kResult = callPreviousChromeWndProc(hwnd, message, wParam, lParam);
        if (previous) {
            ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(previous));
        }
        ::RemovePropW(hwnd, kChromeWndProcProp);
        ::RemovePropW(hwnd, kChromeWindowProp);
        return kResult;
    }

    return callPreviousChromeWndProc(hwnd, message, wParam, lParam);
}

// installChromeSubclass attaches chromeWindowProc once per HWND. Inputs are the
// FLTK owner and native handle; output is true when the subclass is present.
bool installChromeSubclass(Fl_Window* window, HWND hwnd) {
    if (!window || !hwnd) {
        return false;
    }

    ::SetPropW(hwnd, kChromeWindowProp, reinterpret_cast<HANDLE>(window));
    if (::GetPropW(hwnd, kChromeWndProcProp)) {
        return true;
    }

    ::SetLastError(ERROR_SUCCESS);
    LONG_PTR previous = ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(chromeWindowProc));
    if (previous == 0 && ::GetLastError() != ERROR_SUCCESS) {
        ::RemovePropW(hwnd, kChromeWindowProp);
        return false;
    }

    if (!::SetPropW(hwnd, kChromeWndProcProp, reinterpret_cast<HANDLE>(previous))) {
        ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, previous);
        ::RemovePropW(hwnd, kChromeWindowProp);
        return false;
    }
    return true;
}

// shouldExposeOnTaskbar identifies the main app window without changing dialog
// ownership. Input is an FLTK window; output is true only for the maximizable
// custom-chrome window used as the primary application surface.
bool shouldExposeOnTaskbar(Fl_Window* window) {
    KTitleBar* bar = findInstalledTitleBar(window);
    return bar && bar->showMaximize() && window && window->parent() == nullptr;
}

// configureNativeAppWindow makes the primary borderless window a normal shell
// app window. Inputs are the FLTK owner and HWND; output is none.
void configureNativeAppWindow(Fl_Window* window, HWND hwnd) {
    if (!shouldExposeOnTaskbar(window) || !hwnd) {
        return;
    }

    kEnsureAppUserModelId();

    LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    LONG_PTR desiredStyle = style | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_THICKFRAME;
    if (desiredStyle != style) {
        ::SetWindowLongPtrW(hwnd, GWL_STYLE, desiredStyle);
    }

    LONG_PTR exStyle = ::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
    LONG_PTR desiredExStyle = (exStyle & ~(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE)) | WS_EX_APPWINDOW;
    if (desiredExStyle != exStyle) {
        ::SetWindowLongPtrW(hwnd, GWL_EXSTYLE, desiredExStyle);
    }

    if (::GetWindow(hwnd, GW_OWNER)) {
        ::SetWindowLongPtrW(hwnd, GWLP_HWNDPARENT, 0);
    }

    ::SetWindowPos(
        hwnd,
        nullptr,
        0,
        0,
        0,
        0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
}
}

KTitleBar::KTitleBar(int x, int y, int w, int h, const char* title, KTitleBarStyle style, bool showMaximize)
    : Fl_Group(x, y, w, h, title),
      style_(style),
      showMaximize_(showMaximize),
      dragging_(false),
      dragStartedFromNormal_(false),
      restoreValid_(false),
      chromeState_(ChromeState::kNormal),
      dragOffsetX_(0),
      dragOffsetY_(0),
      dragStartX_(0),
      dragStartY_(0),
      dragStartW_(0),
      dragStartH_(0),
      restoreX_(0),
      restoreY_(0),
      restoreW_(0),
      restoreH_(0),
      hoverButton_(Button::kNone),
      pressedButton_(Button::kNone),
      title_(title ? title : "KswordFrame3.0"),
      iconImage_(),
      iconScaled_(),
      logoImage_(),
      logoScaled_() {
    box(FL_NO_BOX);
    color(KThemeManager::instance().theme().windowBg);
}

KTitleBar::~KTitleBar() = default;

void KTitleBar::draw() {
    drawBackground();
    drawBrand();

    drawButton(Button::kMinimize);
    if (showMaximize_) {
        drawButton(Button::kMaximize);
    }
    drawButton(Button::kClose);

    const KTheme& theme = KThemeManager::instance().theme();
    fl_color(theme.border);
    fl_line(x(), y() + h() - 1, x() + w(), y() + h() - 1);
}

int KTitleBar::handle(int event) {
    const int kEventX = Fl::event_x();
    const int kEventY = Fl::event_y();

    if (event == FL_ENTER || event == FL_MOVE) {
        Button next = hitButton(kEventX, kEventY);
        if (next != hoverButton_) {
            hoverButton_ = next;
            redraw();
        }
        return 1;
    }

    if (event == FL_LEAVE) {
        const bool kChanged = hoverButton_ != Button::kNone || pressedButton_ != Button::kNone;
        hoverButton_ = Button::kNone;
        pressedButton_ = Button::kNone;
        if (kChanged) {
            redraw();
        }
        return 1;
    }

    if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
        const Button kHit = hitButton(kEventX, kEventY);
        if (kHit != Button::kNone) {
            pressedButton_ = kHit;
            redraw();
            return 1;
        }

        if (inDraggableArea(kEventX, kEventY)) {
            if (showMaximize_ && Fl::event_clicks() > 0) {
                toggleMaximize();
                return 1;
            }
            beginMoveDrag();
            return 1;
        }
    }

    if (event == FL_DRAG && dragging_) {
        moveWindowForDrag();
        return 1;
    }

    if (event == FL_DRAG && pressedButton_ != Button::kNone) {
        Button next = hitButton(kEventX, kEventY);
        if (next != hoverButton_) {
            hoverButton_ = next;
            redraw();
        }
        return 1;
    }

    if (event == FL_RELEASE) {
        const bool kWasDragging = dragging_;
        const Button kReleased = pressedButton_;
        pressedButton_ = Button::kNone;
        if (kWasDragging && kReleased == Button::kNone) {
            // finishMoveDrag() needs dragging_ to remain true long enough to
            // evaluate snap/maximize targets; it clears the flag before return.
            finishMoveDrag();
        }
        else {
            dragging_ = false;
        }
        if (kReleased != Button::kNone && kReleased == hitButton(kEventX, kEventY)) {
            triggerButton(kReleased);
        }
        if (kReleased != Button::kNone || kWasDragging) {
            redraw();
        }
        return 1;
    }

    return Fl_Group::handle(event);
}

void KTitleBar::setStyle(KTitleBarStyle style) {
    if (style_ == style) {
        return;
    }
    style_ = style;
    redraw();
}

KTitleBarStyle KTitleBar::style() const {
    return style_;
}

void KTitleBar::setShowMaximize(bool showMaximize) {
    if (showMaximize_ == showMaximize) {
        return;
    }
    showMaximize_ = showMaximize;
    redraw();
}

bool KTitleBar::showMaximize() const {
    return showMaximize_;
}

void KTitleBar::syncFromNativeWindow(int ownerWidth, bool maximized) {
    bool changed = false;
    const int kSafeWidth = std::max(1, ownerWidth);
    if (kSafeWidth != w() || x() != 0 || y() != 0 || h() != kTitleBarHeight) {
        // WM_SIZE is the only native path that changes title-bar geometry; keep
        // repaint local to this widget so child controls retain FLTK repainting.
        Fl_Group::resize(0, 0, kSafeWidth, kTitleBarHeight);
        changed = true;
    }

    const ChromeState kNextState = maximized ? ChromeState::kMaximized : ChromeState::kNormal;
    if (!dragging_ && chromeState_ != kNextState) {
        chromeState_ = kNextState;
        changed = true;
    }

    if (changed) {
        redraw();
    }
}

void KTitleBar::ensureImages() {
    if (!iconImage_) {
        std::string iconPath = extractResourceToTemp(IDR_KSWORD_APP_ICON_ICO, "app.ico");
        if (iconPath.empty()) {
            iconPath = resolveProjectAsset(KSWORD_APP_ICON_FILE);
        }
        if (!iconPath.empty()) {
            Fl_ICO_Image* rawIcon = new Fl_ICO_Image(iconPath.c_str());
            if (rawIcon->fail()) {
                delete rawIcon;
            }
            else {
                iconImage_.reset(rawIcon);
                iconScaled_.reset(iconImage_->copy(kCaptionIconSize, kCaptionIconSize));
            }
        }
    }

    if (!logoImage_) {
        std::string logoPath = extractResourceToTemp(IDR_KSWORD_APP_LOGO_PNG, "app_logo.png");
        if (logoPath.empty()) {
            logoPath = resolveProjectAsset(KSWORD_APP_LOGO_FILE);
        }
        if (!logoPath.empty()) {
            Fl_PNG_Image* rawLogo = new Fl_PNG_Image(logoPath.c_str());
            if (rawLogo->fail()) {
                delete rawLogo;
            }
            else {
                logoImage_.reset(rawLogo);
                const int kTargetWidth = std::max(120, std::min(260, rawLogo->data_w() * kLogoTargetHeight / std::max(1, rawLogo->data_h())));
                logoScaled_.reset(logoImage_->copy(kTargetWidth, kLogoTargetHeight));
            }
        }
    }
}

void KTitleBar::drawBackground() {
    const KTheme& theme = KThemeManager::instance().theme();
    const Fl_Color kBase = theme.windowBg;
    const Fl_Color kFill = theme.primary;

    fl_color(kBase);
    fl_rectf(x(), y(), w(), h());

    if (style_ == KTitleBarStyle::kSolid) {
        fl_color(kFill);
        fl_rectf(x(), y(), w(), h());
        return;
    }

    if (style_ == KTitleBarStyle::kFade) {
        const int kStep = 4;
        for (int offset = 0; offset < w(); offset += kStep) {
            const double kProgress = static_cast<double>(offset) / std::max(1, w() - 1);
            const double kOpacity = std::max(0.0, 0.92 - kProgress * 0.86);
            fl_color(blendColor(kFill, kBase, kOpacity));
            fl_rectf(x() + offset, y(), std::min(kStep, w() - offset), h());
        }
        return;
    }

    if (style_ == KTitleBarStyle::kTrapezoid) {
        const int kBrandWidth = std::min(360, std::max(240, w() / 3));
        const int kSlant = 34;
        fl_color(blendColor(kFill, kBase, 0.92));
        fl_begin_polygon();
        fl_vertex(x(), y());
        fl_vertex(x() + kBrandWidth, y());
        fl_vertex(x() + kBrandWidth - kSlant, y() + h());
        fl_vertex(x(), y() + h());
        fl_end_polygon();
    }
}

void KTitleBar::drawBrand() {
    ensureImages();

    const int kIconX = x() + 14;
    const int kIconY = y() + (h() - kCaptionIconSize) / 2;
    if (iconScaled_) {
        iconScaled_->draw(kIconX, kIconY);
    }
    else {
        drawFallbackIcon(kIconX, kIconY, kCaptionIconSize);
    }

    const int kLogoX = kIconX + kCaptionIconSize + 12;
    if (logoScaled_) {
        const int kLogoY = y() + (h() - logoScaled_->h()) / 2;
        logoScaled_->draw(kLogoX, kLogoY);
        return;
    }

    const KTheme& theme = KThemeManager::instance().theme();
    const bool kOnAccent = style_ == KTitleBarStyle::kSolid || style_ == KTitleBarStyle::kTrapezoid;
    fl_color(kOnAccent ? FL_WHITE : theme.text);
    fl_font(FL_HELVETICA_BOLD, 14);
    fl_draw(title_.c_str(), kLogoX, y(), std::max(120, w() / 3), h(), FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
}

void KTitleBar::drawButton(Button button) {
    if (button == Button::kNone || (button == Button::kMaximize && !showMaximize_)) {
        return;
    }

    const Rect kRect = buttonRect(button);
    if (kRect.w <= 0 || kRect.h <= 0) {
        return;
    }

    const KTheme& theme = KThemeManager::instance().theme();
    const bool kHovered = hoverButton_ == button;
    const bool kPressed = pressedButton_ == button;
    const bool kAccentText = style_ == KTitleBarStyle::kSolid;

    if (kHovered || kPressed) {
        Fl_Color buttonFill = blendColor(theme.primary, theme.windowBg, kPressed ? 0.24 : 0.14);
        if (button == Button::kClose) {
            buttonFill = kPressed ? blendColor(theme.danger, FL_BLACK, 0.92) : theme.danger;
        }
        fl_color(buttonFill);
        fl_rectf(kRect.x, kRect.y, kRect.w, kRect.h);
        fl_color(blendColor(buttonFill, FL_BLACK, kPressed ? 0.18 : 0.08));
        fl_line(kRect.x, kRect.y + kRect.h - 1, kRect.x + kRect.w - 1, kRect.y + kRect.h - 1);
    }

    Fl_Color iconColor = kAccentText ? FL_WHITE : theme.text;
    if (button == Button::kClose && kHovered) {
        iconColor = FL_WHITE;
    }

    const int kPressedOffset = kPressed ? 1 : 0;
    const int kCx = kRect.x + kRect.w / 2 + kPressedOffset;
    const int kCy = kRect.y + kRect.h / 2 + kPressedOffset;
    setCaptionLineStyle(iconColor, 2);

    if (button == Button::kMinimize) {
        fl_line(kCx - 6, kCy + 5, kCx + 6, kCy + 5);
    }
    else if (button == Button::kMaximize) {
        if (chromeState_ == ChromeState::kMaximized) {
            fl_rect(kCx - 5, kCy - 3, 10, 8);
            fl_line(kCx - 2, kCy - 6, kCx + 7, kCy - 6);
            fl_line(kCx + 7, kCy - 6, kCx + 7, kCy + 1);
        }
        else {
            fl_rect(kCx - 6, kCy - 6, 12, 12);
        }
    }
    else if (button == Button::kClose) {
        fl_line(kCx - 6, kCy - 6, kCx + 6, kCy + 6);
        fl_line(kCx + 6, kCy - 6, kCx - 6, kCy + 6);
    }

    fl_line_style(0);
}

KTitleBar::Rect KTitleBar::buttonRect(Button button) const {
    const int kRight = x() + w();
    const int kTop = y();
    const int kHeight = h();

    if (button == Button::kClose) {
        return { kRight - kCaptionButtonWidth, kTop, kCaptionButtonWidth, kHeight };
    }
    if (button == Button::kMaximize && showMaximize_) {
        return { kRight - kCaptionButtonWidth * 2, kTop, kCaptionButtonWidth, kHeight };
    }
    if (button == Button::kMinimize) {
        const int kSlot = showMaximize_ ? 3 : 2;
        return { kRight - kCaptionButtonWidth * kSlot, kTop, kCaptionButtonWidth, kHeight };
    }
    return { 0, 0, 0, 0 };
}

KTitleBar::Button KTitleBar::hitButton(int px, int py) const {
    if (pointInRect(px, py, buttonRect(Button::kClose))) {
        return Button::kClose;
    }
    if (showMaximize_ && pointInRect(px, py, buttonRect(Button::kMaximize))) {
        return Button::kMaximize;
    }
    if (pointInRect(px, py, buttonRect(Button::kMinimize))) {
        return Button::kMinimize;
    }
    return Button::kNone;
}

void KTitleBar::triggerButton(Button button) {
    if (button == Button::kMinimize) {
        minimizeWindow();
    }
    else if (button == Button::kMaximize) {
        toggleMaximize();
    }
    else if (button == Button::kClose) {
        closeWindow();
    }
}

void KTitleBar::beginMoveDrag() {
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    // Capture the starting bounds before the first move so Snap restore uses
    // the pre-drag normal geometry instead of the edge-aligned final geometry.
    dragging_ = true;
    dragStartedFromNormal_ = chromeState_ == ChromeState::kNormal;
    dragStartX_ = owner->x();
    dragStartY_ = owner->y();
    dragStartW_ = owner->w();
    dragStartH_ = owner->h();
    dragOffsetX_ = Fl::event_x_root() - owner->x();
    dragOffsetY_ = Fl::event_y_root() - owner->y();
}

void KTitleBar::moveWindowForDrag() {
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    // A maximized or snapped borderless window restores on first drag movement,
    // then the normal move path below keeps the restored window under the cursor.
    if (chromeState_ != ChromeState::kNormal) {
        restoreForInteractiveDrag();
    }

    const int kNextX = Fl::event_x_root() - dragOffsetX_;
    const int kNextY = Fl::event_y_root() - dragOffsetY_;
    applyWindowBounds({ kNextX, kNextY, owner->w(), owner->h() });
}

void KTitleBar::finishMoveDrag() {
    if (!dragging_) {
        return;
    }

    Fl_Window* owner = window();
    if (!owner) {
        dragging_ = false;
        return;
    }

    if (!showMaximize_) {
        dragging_ = false;
        return;
    }

    KTitleBar::Rect work = { 0, 0, 0, 0 };
    if (!workAreaForRootPoint(Fl::event_x_root(), Fl::event_y_root(), work)) {
        dragging_ = false;
        return;
    }

    // Match the basic Windows edge gestures on the monitor currently under the
    // cursor: top maximizes, left/right snap to the corresponding half.
    const EdgeSnap kSnap = snapForCursor(work, Fl::event_x_root(), Fl::event_y_root());
    if (kSnap == EdgeSnap::kTop) {
        maximizeWindow();
    }
    else if (kSnap == EdgeSnap::kLeft) {
        snapWindow(ChromeState::kSnappedLeft);
    }
    else if (kSnap == EdgeSnap::kRight) {
        snapWindow(ChromeState::kSnappedRight);
    }

    dragging_ = false;
}

void KTitleBar::minimizeWindow() {
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }
    if (chromeShowWindow(owner, SW_MINIMIZE)) {
        return;
    }
    owner->iconize();
}

void KTitleBar::toggleMaximize() {
    if (!showMaximize_) {
        return;
    }
    if (chromeState_ == ChromeState::kMaximized) {
        restoreWindow();
    }
    else {
        maximizeWindow();
    }
}

void KTitleBar::maximizeWindow() {
    if (!showMaximize_) {
        return;
    }

    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    KTitleBar::Rect work = { 0, 0, 0, 0 };
    if (!workAreaForWindow(owner, work)) {
        return;
    }

    storeRestoreGeometry();
    applyWindowBounds(work);
    chromeState_ = ChromeState::kMaximized;
    redraw();
}

void KTitleBar::restoreWindow() {
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    KTitleBar::Rect bounds = { restoreX_, restoreY_, restoreW_, restoreH_ };
    KTitleBar::Rect work = { 0, 0, 0, 0 };
    if (!restoreValid_ && workAreaForWindow(owner, work)) {
        bounds.w = std::max(1, work.w * 3 / 4);
        bounds.h = std::max(1, work.h * 3 / 4);
        bounds.x = work.x + (work.w - bounds.w) / 2;
        bounds.y = work.y + (work.h - bounds.h) / 2;
    }
    else if (!restoreValid_) {
        return;
    }

    if (workAreaForWindow(owner, work)) {
        const int kMinWidth = std::min(kMinimumRestoreWidth, std::max(1, work.w));
        const int kMinHeight = std::min(kMinimumRestoreHeight, std::max(1, work.h));
        bounds.w = clampInt(bounds.w, kMinWidth, std::max(1, work.w));
        bounds.h = clampInt(bounds.h, kMinHeight, std::max(1, work.h));
        bounds.x = clampInt(bounds.x, work.x, work.x + std::max(0, work.w - bounds.w));
        bounds.y = clampInt(bounds.y, work.y, work.y + std::max(0, work.h - bounds.h));
    }

    applyWindowBounds(bounds);
    chromeState_ = ChromeState::kNormal;
    redraw();
}

void KTitleBar::snapWindow(ChromeState snapState) {
    if (!showMaximize_) {
        return;
    }
    if (snapState != ChromeState::kSnappedLeft && snapState != ChromeState::kSnappedRight) {
        return;
    }
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    KTitleBar::Rect work = { 0, 0, 0, 0 };
    if (!workAreaForWindow(owner, work)) {
        return;
    }

    storeRestoreGeometry();
    const int kLeftWidth = std::max(1, work.w / 2);
    if (snapState == ChromeState::kSnappedLeft) {
        applyWindowBounds({ work.x, work.y, kLeftWidth, work.h });
    }
    else {
        applyWindowBounds({ work.x + kLeftWidth, work.y, std::max(1, work.w - kLeftWidth), work.h });
    }
    chromeState_ = snapState;
    redraw();
}

void KTitleBar::restoreForInteractiveDrag() {
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    if (!restoreValid_) {
        KTitleBar::Rect work = { 0, 0, 0, 0 };
        if (workAreaForWindow(owner, work)) {
            restoreW_ = std::max(1, work.w * 3 / 4);
            restoreH_ = std::max(1, work.h * 3 / 4);
            restoreX_ = work.x + (work.w - restoreW_) / 2;
            restoreY_ = work.y + (work.h - restoreH_) / 2;
        }
        else {
            restoreX_ = owner->x();
            restoreY_ = owner->y();
            restoreW_ = std::max(kMinimumRestoreWidth, owner->w() * 2 / 3);
            restoreH_ = std::max(kMinimumRestoreHeight, owner->h() * 2 / 3);
        }
        restoreValid_ = true;
    }

    const int kRootX = Fl::event_x_root();
    const int kRootY = Fl::event_y_root();
    const double kRawRatio = static_cast<double>(kRootX - owner->x()) / std::max(1, owner->w());
    const double kRatio = std::max(0.15, std::min(0.85, kRawRatio));
    const int kLocalTitleY = clampInt(Fl::event_y() - y(), 8, std::max(8, kTitleBarHeight - 8));
    const int kNextX = kRootX - static_cast<int>(restoreW_ * kRatio);
    const int kNextY = kRootY - kLocalTitleY;

    // Update drag offsets after restore so the same FL_DRAG event can continue
    // through the normal movement path without a visible jump.
    applyWindowBounds({ kNextX, kNextY, restoreW_, restoreH_ });
    chromeState_ = ChromeState::kNormal;
    dragOffsetX_ = kRootX - kNextX;
    dragOffsetY_ = kRootY - kNextY;
    redraw();
}

void KTitleBar::storeRestoreGeometry() {
    Fl_Window* owner = window();
    if (!owner) {
        return;
    }

    if (chromeState_ == ChromeState::kNormal && dragging_ && dragStartedFromNormal_ && dragStartW_ > 0 && dragStartH_ > 0) {
        restoreX_ = dragStartX_;
        restoreY_ = dragStartY_;
        restoreW_ = dragStartW_;
        restoreH_ = dragStartH_;
    }
    else if (chromeState_ == ChromeState::kNormal || !restoreValid_) {
        restoreX_ = owner->x();
        restoreY_ = owner->y();
        restoreW_ = owner->w();
        restoreH_ = owner->h();
    }

    restoreValid_ = restoreW_ > 0 && restoreH_ > 0;
}

void KTitleBar::applyWindowBounds(const Rect& bounds) {
    Fl_Window* owner = window();
    if (!owner || bounds.w <= 0 || bounds.h <= 0) {
        return;
    }

    const bool kSizeChanged = owner->w() != bounds.w || owner->h() != bounds.h;
    chromeSetWindowBounds(owner, bounds, kSizeChanged);
    if (kSizeChanged) {
        // Movement-only drags must not invalidate the whole window. FLTK keeps
        // client controls painted; only actual size changes adjust this bar and
        // refresh the layout baseline.
        Fl_Group::resize(0, 0, bounds.w, kTitleBarHeight);
        owner->init_sizes();
        redraw();
    }
}

void KTitleBar::closeWindow() {
    Fl_Window* owner = window();
    if (owner) {
        owner->hide();
    }
}

void KTitleBar::drawFallbackIcon(int px, int py, int size) {
    const KTheme& theme = KThemeManager::instance().theme();
    fl_color(theme.primary);
    fl_rectf(px, py, size, size);
    fl_color(FL_WHITE);
    fl_font(FL_HELVETICA_BOLD, std::max(12, size - 8));
    fl_draw("K", px, py, size, size, FL_ALIGN_CENTER);
}

bool KTitleBar::inDraggableArea(int px, int py) const {
    if (py < y() || py >= y() + h()) {
        return false;
    }
    const Rect kFirstButton = buttonRect(Button::kMinimize);
    const int kDragRight = kFirstButton.w > 0 ? kFirstButton.x : x() + w();
    return px >= x() && px < kDragRight;
}

int titleBarHeight() {
    return kTitleBarHeight;
}

bool kInstallTitleBar(Fl_Window* window, KTitleBarStyle style, bool showMaximize) {
    if (!window) {
        return false;
    }

    if (showMaximize) {
        // Set the shell identity before the main HWND is shown so taskbar
        // grouping is stable even though the icon/style is applied after show().
        kEnsureAppUserModelId();
    }

    KTitleBar* existing = findInstalledTitleBar(window);
    if (existing) {
        existing->setStyle(style);
        existing->setShowMaximize(showMaximize);
        return true;
    }

    std::vector<Fl_Widget*> children;
    children.reserve(window->children());
    for (int i = 0; i < window->children(); ++i) {
        children.push_back(window->child(i));
    }

    window->border(0);
    const int kOldWidth = window->w();
    const int kOldHeight = window->h();
    window->size(kOldWidth, kOldHeight + kTitleBarHeight);

    for (Fl_Widget* child : children) {
        if (!child) {
            continue;
        }
        child->resize(child->x(), child->y() + kTitleBarHeight, child->w(), child->h());
    }

    Fl_Group* previous = Fl_Group::current();
    Fl_Group::current(nullptr);
    KTitleBar* bar = new KTitleBar(0, 0, kOldWidth, kTitleBarHeight, window->label(), style, showMaximize);
    Fl_Group::current(previous);
    window->add(bar);
    window->init_sizes();
    KThemeManager::instance().applyTo(bar);
    window->redraw();
    return true;
}

void kApplyWindowIcon(Fl_Window* window) {
    HWND hwnd = windowHandle(window);
    if (!hwnd) {
        return;
    }

    installChromeSubclass(window, hwnd);
    configureNativeAppWindow(window, hwnd);

    HINSTANCE instance = ::GetModuleHandleW(nullptr);
    HICON bigIcon = static_cast<HICON>(::LoadImageW(instance, MAKEINTRESOURCEW(IDI_KSWORD_APP_ICON), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR | LR_SHARED));
    HICON smallIcon = static_cast<HICON>(::LoadImageW(instance, MAKEINTRESOURCEW(IDI_KSWORD_APP_ICON), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR | LR_SHARED));
    if (bigIcon) {
        ::SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(bigIcon));
    }
    if (smallIcon) {
        ::SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));
    }
}

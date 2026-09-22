#include "WindowActions.h"

#include "../../core/Common.h"
#include "WindowModel.h"

namespace ksword::features::window {
namespace {

// validateWindowForAction checks that an HWND still maps to a live window. Input
// is the transient HWND selected in the view; output is an error result when the
// window disappeared, otherwise a successful no-op result used by callers.
WindowActionResult validateWindowForAction(HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd)) {
        return { false, L"Window no longer exists." };
    }
    return { true, L"OK" };
}

} // namespace

WindowActionResult bringWindowToFront(HWND hwnd) {
    WindowActionResult valid = validateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    if (::IsIconic(hwnd)) {
        ::ShowWindow(hwnd, SW_RESTORE);
    }
    if (!::SetForegroundWindow(hwnd)) {
        return { false, L"SetForegroundWindow failed for " + hwndToText(hwnd) + L": " + ksword::core::lastErrorMessage() };
    }
    return { true, L"Brought window to front: " + hwndToText(hwnd) };
}

WindowActionResult minimizeWindow(HWND hwnd) {
    WindowActionResult valid = validateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::ShowWindow(hwnd, SW_MINIMIZE);
    return { true, L"Minimize requested: " + hwndToText(hwnd) };
}

WindowActionResult maximizeWindow(HWND hwnd) {
    WindowActionResult valid = validateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::ShowWindow(hwnd, SW_MAXIMIZE);
    return { true, L"Maximize requested: " + hwndToText(hwnd) };
}

WindowActionResult restoreWindow(HWND hwnd) {
    WindowActionResult valid = validateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    ::ShowWindow(hwnd, SW_RESTORE);
    return { true, L"Restore requested: " + hwndToText(hwnd) };
}

WindowActionResult closeWindowGracefully(HWND hwnd) {
    WindowActionResult valid = validateWindowForAction(hwnd);
    if (!valid.success) {
        return valid;
    }
    if (!::PostMessageW(hwnd, WM_CLOSE, 0, 0)) {
        return { false, L"WM_CLOSE post failed for " + hwndToText(hwnd) + L": " + ksword::core::lastErrorMessage() };
    }
    return { true, L"Close requested: " + hwndToText(hwnd) };
}

} // namespace Ksword::Features::Window

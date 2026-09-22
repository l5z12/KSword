#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::window {

// WindowActionResult reports the outcome of a user-triggered window operation.
// Inputs are produced by WindowActions functions; consumers show message text in
// status panes without throwing exceptions across the Win32 callback boundary.
struct WindowActionResult {
    bool success = false;
    std::wstring message;
};

// bringWindowToFront validates and foregrounds a top-level HWND. Input is a
// transient HWND from EnumWindows; processing restores minimized windows and uses
// SetForegroundWindow; output describes success or the Win32 failure.
WindowActionResult bringWindowToFront(HWND hwnd);

// minimizeWindow validates and minimizes a top-level HWND. Input is a transient
// HWND; processing calls ShowWindow(SW_MINIMIZE); output reports whether the HWND
// still exists and the command was issued.
WindowActionResult minimizeWindow(HWND hwnd);

// maximizeWindow validates and maximizes a top-level HWND. Input is a transient
// HWND; processing calls ShowWindow(SW_MAXIMIZE); output reports command status.
WindowActionResult maximizeWindow(HWND hwnd);

// restoreWindow validates and restores a top-level HWND. Input is a transient
// HWND; processing calls ShowWindow(SW_RESTORE); output reports command status.
WindowActionResult restoreWindow(HWND hwnd);

// closeWindowGracefully posts WM_CLOSE to a top-level HWND. Input is a transient
// HWND; processing does not terminate processes or duplicate handles; output
// reports whether the close request was posted.
WindowActionResult closeWindowGracefully(HWND hwnd);

} // namespace Ksword::Features::Window

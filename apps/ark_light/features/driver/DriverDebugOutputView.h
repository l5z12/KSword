#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::driver {

// createDriverDebugOutputView creates the bounded R0 DbgPrint capture page.
// Capture control and draining are always performed in workers; the returned
// child window owns its timer and cancels pending work on destruction.
HWND createDriverDebugOutputView(HWND parent, const RECT& bounds);

// resizeDriverDebugOutputView moves the retained child view with its tab page.
void resizeDriverDebugOutputView(HWND view, const RECT& bounds);

} // namespace Ksword::Features::Driver

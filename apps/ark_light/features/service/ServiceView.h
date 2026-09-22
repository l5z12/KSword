#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::service {

// createServiceView creates the service management page. Inputs are the dock
// parent HWND and initial bounds; processing registers the window class once and
// creates the child page; output is the page HWND or nullptr on failure.
HWND createServiceView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Service

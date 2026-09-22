#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::hardware {

// createHardwareDeviceManagerView creates the read-only hardware audit page.
// Inputs are parent HWND and parent-relative bounds; processing registers the
// module window class, creates tree/detail controls, and performs an initial
// SetupAPI/Configuration Manager enumeration; output is the child page HWND or
// nullptr on failure.
HWND createHardwareDeviceManagerView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Hardware

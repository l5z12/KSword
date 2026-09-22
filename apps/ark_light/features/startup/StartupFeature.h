#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::startup {

// createStartupFeaturePage is the module facade for startup-entry management.
// Inputs are the dock parent HWND and bounds; processing delegates to StartupView
// and routes all mutations through StartupActions; output is the child HWND or
// nullptr on failure.
HWND createStartupFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Startup

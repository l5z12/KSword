#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::service {

// createServiceFeaturePage is the module facade for SCM service management.
// Inputs are the dock parent HWND and bounds; processing delegates to
// ServiceView and routes every mutation through ServiceActions; output is the
// child HWND or nullptr on failure.
HWND createServiceFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Service

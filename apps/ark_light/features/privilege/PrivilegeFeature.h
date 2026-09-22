#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::privilege {

// createPrivilegeFeaturePage is the module facade for process token privileges.
// Inputs are the dock parent HWND and bounds; processing delegates to
// PrivilegeView and routes changes through PrivilegeActions; output is the child
// HWND or nullptr on failure.
HWND createPrivilegeFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::privilege

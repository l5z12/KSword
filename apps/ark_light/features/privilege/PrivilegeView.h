#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::privilege {

// createPrivilegeView creates the token privilege page. Inputs are the dock
// parent HWND and initial bounds; output is the page HWND or nullptr.
HWND createPrivilegeView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::privilege

#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::sys_tools {

// createSystemTimeView creates the "System Time" tab. Inputs are the tab parent and
// initial bounds; processing renders collectSystemTimeInfo into a read-only
// pane and keeps a live clock line ticking; output is the page HWND or nullptr.
HWND createSystemTimeView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools

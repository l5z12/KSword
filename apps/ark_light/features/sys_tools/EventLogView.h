#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::sys_tools {

// createEventLogView creates the "Event Log" tab. Inputs are the tab parent and
// initial bounds; processing reads System/Application through queryEventLog on a
// worker thread; output is the page HWND or nullptr.
HWND createEventLogView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools

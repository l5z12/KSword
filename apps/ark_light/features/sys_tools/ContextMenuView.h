#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::sys_tools {

// createContextMenuView creates the "Right-click Menu" tab. Inputs are the tab parent and
// initial bounds; processing enumerates the shell registration points and routes
// every mutation through ContextMenuScanner's backup-then-delete actions; output
// is the page HWND or nullptr.
HWND createContextMenuView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools

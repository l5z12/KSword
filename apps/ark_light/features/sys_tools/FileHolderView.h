#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::sys_tools {

// createFileHolderView creates the "file in-use" tab. Inputs are the tab parent and
// the initial bounds; processing drives scanFileHolders on a worker thread and
// renders the matches; output is the page HWND or nullptr.
HWND createFileHolderView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::SysTools

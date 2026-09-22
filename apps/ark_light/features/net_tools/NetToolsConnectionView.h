#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::net_tools {

// createNetToolsConnectionView creates the TCP/UDP connection management tab.
// Inputs are the tab-host parent HWND and initial bounds; processing registers
// the window class once and creates the child page; output is the page HWND or
// nullptr on failure.
HWND createNetToolsConnectionView(HWND parent, const RECT& bounds);

bool requestNetToolsConnectionProcessFilter(HWND page, DWORD processId);

} // namespace Ksword::Features::NetTools

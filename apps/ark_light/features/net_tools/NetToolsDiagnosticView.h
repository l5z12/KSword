#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::net_tools {

// createNetToolsDiagnosticView creates the ping / traceroute / DNS tab. Inputs
// are the tab-host parent HWND and initial bounds; processing registers the
// window class once and creates the child page; output is the page HWND or
// nullptr on failure.
HWND createNetToolsDiagnosticView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::NetTools

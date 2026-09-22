#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::registry {

// createRegistrySearchView creates the separate read-only WinAPI registry
// search page.  Inputs are parent and bounds; output is the child HWND.  It
// deliberately has no R0 selector or mutation controls, so it cannot alter the
// existing registry browser's transport or write semantics.
HWND createRegistrySearchView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Registry

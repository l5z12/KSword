#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::misc {

// createMiscFeaturePage is the module facade for the lightweight Security / CI /
// VBS / Hyper-V audit page. Inputs are the dock parent HWND and initial
// parent-relative bounds; processing creates a read-only Win32 tab page that
// gathers R3/PowerShell/WMI/service/registry evidence and reports R0 query
// availability through ArkDriverClient diagnostics. The return value is the
// created child HWND, or nullptr when the page cannot be created.
HWND createMiscFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Misc

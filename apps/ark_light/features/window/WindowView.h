#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::window {

// createWindowFeatureView creates the retained non-desktop window-management
// page. Inputs are parent HWND and parent-relative bounds; processing registers
// a Win32 page class, creates list/detail controls, and performs an initial
// EnumWindows snapshot; output is the child page HWND or nullptr on failure.
HWND createWindowFeatureView(HWND parent, const RECT& bounds);

bool requestWindowFeatureViewQuery(HWND page, const std::wstring& query);

} // namespace Ksword::Features::Window

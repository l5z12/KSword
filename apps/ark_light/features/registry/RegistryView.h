#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::registry {

// createRegistryView creates the Win32 registry dock surface. Inputs are parent
// HWND and initial bounds; processing creates a persistent toolbar/list/editor
// page; output is the child HWND or nullptr on failure.
HWND createRegistryView(HWND parent, const RECT& bounds);

bool requestRegistryViewNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::Registry

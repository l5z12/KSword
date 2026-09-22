#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::registry {

// createRegistryFeaturePage is the module-local facade for the registry dock.
// Inputs are parent HWND and initial bounds; output is the root page HWND.
HWND createRegistryFeaturePage(HWND parent, const RECT& bounds);

bool requestRegistryFeatureNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::Registry

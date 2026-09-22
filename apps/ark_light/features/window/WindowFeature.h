#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::window {

// createWindowFeaturePage creates the unified Window workspace. It owns tabs
// for window management, clipboard inspection, global-hotkey probing and the
// full read-only hierarchy diagnostics workspace. Window management retains its
// selected-window hierarchy pane and exposes capture protection from each
// window row's context menu.
HWND createWindowFeaturePage(HWND parent, const RECT& bounds);

bool requestWindowFeatureQuery(HWND page, const std::wstring& query);

} // namespace Ksword::Features::Window

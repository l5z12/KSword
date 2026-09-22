#pragma once

#include "../core/EntityRef.h"
#include "../core/Win32Lean.h"

namespace ksword::ui {

constexpr UINT kEntityNavigationMessage = WM_APP + 104;

// requestEntityNavigation synchronously sends an immutable request to the root
// Lite shell. Synchronous delivery keeps the stack-owned request valid and
// returns whether a route accepted it.
bool requestEntityNavigation(HWND source, const ksword::core::NavigationRequest& request);

} // namespace Ksword::Ui

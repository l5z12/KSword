#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::startup {

// createStartupFeatureView creates the startup-management page. Inputs are parent
// HWND and parent-relative bounds; processing registers the module page class,
// creates list/detail controls, enumerates startup entries, and routes all user
// mutations through StartupActions.*; output is the child HWND or nullptr.
HWND createStartupFeatureView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Startup

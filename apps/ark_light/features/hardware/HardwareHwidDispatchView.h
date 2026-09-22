#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::hardware {

// createHardwareHwidDispatchView creates the Light HWID Dispatch page. Inputs
// are the parent HWND and bounds; processing mirrors Ksword5.1's
// HardwareHwidDispatchPage ArkDriverClient query/control calls; output is the
// child HWND or nullptr on creation failure.
HWND createHardwareHwidDispatchView(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Hardware

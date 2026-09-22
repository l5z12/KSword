#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::hardware {

// createHardwareFeaturePage creates the unified Hardware workspace. It owns
// device/CPU/HWID audit pages plus performance monitoring, disk activity, USB
// topology and system-bus pages; every tab retains its own controls and state.
HWND createHardwareFeaturePage(HWND parent, const RECT& bounds);

} // namespace Ksword::Features::Hardware

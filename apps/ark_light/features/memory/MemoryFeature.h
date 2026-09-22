#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::memory {

// createMemoryFeaturePage is the module-local facade for the memory feature UI.
// Inputs are the dock parent and initial bounds; processing creates the
// driver-only memory read/write view; output is the page HWND or null on failure.
HWND createMemoryFeaturePage(HWND parent, const RECT& bounds);

// requestMemoryFeatureProcess forwards an existing process identity to the
// driver-memory page. It only fills local controls; it never auto-reads or
// auto-writes and remains usable when the driver is unavailable.
bool requestMemoryFeatureProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Memory

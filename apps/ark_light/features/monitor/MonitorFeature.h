#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::monitor {

// createMonitorFeaturePage creates the ETW-only monitor page. Inputs are parent
// HWND and bounds; processing delegates to EtwMonitorView; output is the page
// HWND or nullptr. Integration session should wire this facade into docks.
HWND createMonitorFeaturePage(HWND parent, const RECT& bounds);

bool requestMonitorFeatureProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Monitor

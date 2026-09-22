#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::network {

// createNetworkFeaturePage is the ARKLight Network module facade. Inputs are the
// parent HWND and initial host-client bounds; processing delegates all tab and
// table ownership to NetworkView; return value is the created child HWND or
// nullptr when the view class/window cannot be created.
HWND createNetworkFeaturePage(HWND parent, const RECT& bounds);

// resizeNetworkFeaturePage is the host-driven resize facade. Inputs are an
// existing Network page HWND and new bounds; processing moves the page window
// only; there is no return value.
void resizeNetworkFeaturePage(HWND page, const RECT& bounds);

bool requestNetworkFeatureProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Network

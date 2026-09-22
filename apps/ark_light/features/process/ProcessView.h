#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::process {

// createProcessView creates the Win32 child page for the process list feature.
// Inputs are the parent HWND and initial bounds. Processing registers a private
// window class, creates toolbar/status/list controls, and starts a first process
// snapshot refresh. Return value is the page HWND, or null when registration or
// child-window creation fails.
HWND createProcessView(HWND parent, const RECT& bounds);

// resizeProcessView moves the already-created process page. Inputs are the page
// HWND and new bounds in parent-client coordinates. Processing calls MoveWindow;
// there is no return value because invalid HWNDs are ignored by Win32.
void resizeProcessView(HWND view, const RECT& bounds);

// requestProcessViewRefresh purpose: Submit a lightweight refresh request to the existing process view.
// Parameter view is the process page HWND; the handler reuses the standard refresh path and performs R0 hidden process lookup by default.
void requestProcessViewRefresh(HWND view);

// requestProcessViewOpenDetails resolves the current process instance before
// opening details. A zero creation time is replaced from the latest snapshot or
// a verified Win32 process handle; a mismatched nonzero identity is rejected.
bool requestProcessViewOpenDetails(HWND view, DWORD processId, ULONGLONG expectedCreationTime100ns = 0);

} // namespace Ksword::Features::Process

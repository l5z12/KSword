#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::handle {

// createHandleFeaturePage creates the lightweight read-only Handle audit page.
// Inputs are the dock parent HWND and initial client bounds. Processing creates
// one retained child page for HandleTable/ObjectHeader/ObjectType evidence; the
// return value is the root page HWND or nullptr on initialization failure.
HWND createHandleFeaturePage(HWND parent, const RECT& bounds);

// resizeHandleFeaturePage moves the existing Handle page inside its host dock.
// Inputs are the page HWND and new host bounds. Processing calls MoveWindow and
// returns no value; invalid HWND values are ignored by Win32.
void resizeHandleFeaturePage(HWND page, const RECT& bounds);

bool requestHandleFeatureProcess(HWND page, DWORD processId);

} // namespace Ksword::Features::Handle

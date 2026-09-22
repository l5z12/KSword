#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::process {

// createProcessFeaturePage is the module facade for the lightweight Win32
// process list page. Inputs are the parent HWND and initial parent-client
// bounds. Processing delegates to ProcessView so this module only
// needs this stable module-level entry point. Return value is the created child
// HWND or null on failure.
HWND createProcessFeaturePage(HWND parent, const RECT& bounds);

// resizeProcessFeaturePage is the module facade for host-driven layout changes.
// Inputs are an existing process page HWND and new bounds. Processing delegates
// to ProcessView and returns no value.
void resizeProcessFeaturePage(HWND page, const RECT& bounds);

// requestProcessFeatureRefresh: Sends a refresh request to an instantiated process feature page.
// Call scenario: Once the R0 driver becomes available, immediately trigger the hidden process detection logic.
void requestProcessFeatureRefresh(HWND page);

bool requestProcessFeatureOpenDetails(HWND page, DWORD processId, ULONGLONG expectedCreationTime100ns = 0);

} // namespace Ksword::Features::Process

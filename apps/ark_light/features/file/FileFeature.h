#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::file {

// createFileFeaturePage creates the File feature host. Inputs are the dock
// parent HWND and initial bounds; processing hosts the retained browser page
// plus read-only audit tabs for FileObject/Section/filter/storage visibility;
// output is the created child HWND or nullptr on failure.
HWND createFileFeaturePage(HWND parent, const RECT& bounds);

// requestFileFeatureNavigate selects the browser tab and forwards a typed file
// entity path through the browser interface.
bool requestFileFeatureNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::File

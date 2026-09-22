#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::file {

// createFileViewPage creates the native Win32 file page used by KswordARKLight.
// Inputs are the parent HWND and initial bounds; processing creates a toolbar,
// path box, report list, status line and right-click action surface; output is
// the page HWND, or null if class/window creation fails.
HWND createFileViewPage(HWND parent, const RECT& bounds);

// requestFileViewNavigate synchronously navigates an existing browser page to
// an absolute Win32/UNC/NT path supplied by the shell entity router.
bool requestFileViewNavigate(HWND page, const std::wstring& path);

} // namespace Ksword::Features::File

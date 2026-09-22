#pragma once

#include "../core/Win32Lean.h"

#include <string>

namespace ksword::ui {

// createLoadingOverlay creates a hidden child overlay. Call setLoadingOverlay
// when a page starts or finishes background work, and keep it positioned over
// the page's result area from the parent WM_SIZE handler.
HWND createLoadingOverlay(HWND parent, int id, const RECT& bounds);

// setLoadingOverlay toggles the overlay and updates its message. Showing the
// overlay starts a lightweight spinner timer; hiding it stops the timer.
void setLoadingOverlay(HWND overlay, bool visible, const std::wstring& message = L"");

} // namespace Ksword::Ui

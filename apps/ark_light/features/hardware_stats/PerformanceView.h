#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::hardware_stats {

// createPerformanceView creates the live performance-counter table. Inputs are
// the tab parent HWND and bounds; processing owns its own PDH sampler and a one
// second timer; output is the child HWND or nullptr on failure.
HWND createPerformanceView(HWND parent, const RECT& bounds);

// refreshPerformanceView takes one sample immediately without disturbing the
// automatic cadence. Input is the view HWND; nothing is returned because the
// result arrives asynchronously.
void refreshPerformanceView(HWND view);

// exportPerformanceViewTsv renders the currently visible rows as TSV. Input is
// the view HWND; output is empty when the view is not a performance view.
std::wstring exportPerformanceViewTsv(HWND view);

} // namespace Ksword::Features::hardware_stats

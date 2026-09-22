#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::hardware_stats {

// createDiskActivityView creates the per-physical-disk activity table. Inputs
// are the tab parent HWND and bounds; processing owns its own PDH sampler over
// the PhysicalDisk object and a one second timer; output is the child HWND or
// nullptr on failure.
HWND createDiskActivityView(HWND parent, const RECT& bounds);

// refreshDiskActivityView takes one sample immediately without disturbing the
// automatic cadence. Input is the view HWND; nothing is returned because the
// result arrives asynchronously.
void refreshDiskActivityView(HWND view);

// exportDiskActivityViewTsv renders the currently visible rows as TSV. Input is
// the view HWND; output is empty when the view is not a disk activity view.
std::wstring exportDiskActivityViewTsv(HWND view);

} // namespace Ksword::Features::hardware_stats

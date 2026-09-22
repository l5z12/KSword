#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::hardware_stats {

// createBusDeviceView creates the system bus table. Inputs are the tab parent
// HWND and bounds; processing enumerates devnodes and their arbitrated
// resources on a worker thread; output is the child HWND or nullptr on failure.
HWND createBusDeviceView(HWND parent, const RECT& bounds);

// refreshBusDeviceView starts a new background enumeration. Input is the view
// HWND; nothing is returned because the result arrives asynchronously.
void refreshBusDeviceView(HWND view);

// exportBusDeviceViewTsv renders the currently visible rows as TSV. Input is the
// view HWND; output is empty when the view is not a bus device view.
std::wstring exportBusDeviceViewTsv(HWND view);

} // namespace Ksword::Features::hardware_stats

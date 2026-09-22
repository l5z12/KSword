#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::hardware_stats {

// createUsbTopologyView creates the USB device tree table. Inputs are the tab
// parent HWND and bounds; processing enumerates on a worker thread; output is
// the child HWND or nullptr on failure.
HWND createUsbTopologyView(HWND parent, const RECT& bounds);

// refreshUsbTopologyView starts a new background enumeration. Input is the view
// HWND; nothing is returned because the result arrives asynchronously.
void refreshUsbTopologyView(HWND view);

// exportUsbTopologyViewTsv renders the currently visible rows as TSV. Input is
// the view HWND; output is empty when the view is not a USB topology view.
std::wstring exportUsbTopologyViewTsv(HWND view);

} // namespace Ksword::Features::hardware_stats

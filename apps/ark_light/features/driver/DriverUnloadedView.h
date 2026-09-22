#pragma once

#include "../../core/Win32Lean.h"

#include <string>

namespace ksword::features::driver {

// createDriverUnloadedView creates the unloaded-driver evidence page. Inputs are
// the parent HWND and initial bounds; output is the page HWND or nullptr.
//
// This reads the three kernel caches that outlive a driver's unload --
// MmUnloadedDrivers, PiDDBCacheTable and g_KernelHashBucketList -- through the
// existing read-only IOCTL. They are the residue a driver leaves behind after it
// is gone from the loaded-module list, which is exactly where a driver that
// loaded once and unloaded to hide still shows up.
HWND createDriverUnloadedView(HWND parent, const RECT& bounds);

// exportDriverUnloadedViewTsv renders the current visible rows as TSV. Input is
// the page HWND; output is empty when the page is not a view of this class.
std::wstring exportDriverUnloadedViewTsv(HWND page);

} // namespace Ksword::Features::Driver

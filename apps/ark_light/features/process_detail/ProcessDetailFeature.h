#pragma once

#include "../../core/Win32Lean.h"

namespace ksword::features::process_detail {

// createProcessDetailPage is the integration facade for the process module.
// Inputs are a parent HWND, target PID and initial bounds; processing creates
// the independent ProcessDetailPage; output is the child HWND or nullptr on
// registration/window creation failure.
HWND createProcessDetailPage(
    HWND parent,
    DWORD processId,
    ULONGLONG expectedCreationTime100ns,
    const RECT& bounds);

} // namespace Ksword::Features::process_detail

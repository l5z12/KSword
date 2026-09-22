#pragma once

#include "../core/Win32Lean.h"

namespace ksword::ui {

// showEvidenceSessionInspector opens the modeless native inspector for the
// process-wide evidence session. The view reads immutable snapshots only; it
// never triggers a driver query, filesystem scan, or export operation.
bool showEvidenceSessionInspector(HWND owner);

} // namespace Ksword::Ui

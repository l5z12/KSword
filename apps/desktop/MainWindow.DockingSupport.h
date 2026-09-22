#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.

namespace ksword::ui::main_window
{
    // kDeferredDockLoadIntervalMs:
    // - Control the throttling interval for deferred loading after display.
    // - Avoid filling the UI thread again with continuous deferred reloads at 0ms.
    inline constexpr int kDeferredDockLoadIntervalMs = 60;
}

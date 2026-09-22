#pragma once

class QApplication;

namespace ks::ui
{
    // installGlobalSmoothScrollSupport:
    // - Install a single global wheel event filter to cover tables, lists, text areas, and scrollable pages;
    // - Actual enablement is toggled at runtime by setGlobalSmoothScrollingEnabled.
    void installGlobalSmoothScrollSupport(QApplication* appInstance);

    // setGlobalSmoothScrollingEnabled:
    // - Instantly enable or disable global smooth scrolling.
    // When enabled, the item view switches to pixel-based scrolling; when disabled, it restores each control's original scrolling mode.
    void setGlobalSmoothScrollingEnabled(bool enabled);

    bool isGlobalSmoothScrollingEnabled();
}

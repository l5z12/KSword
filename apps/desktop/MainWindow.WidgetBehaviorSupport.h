#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.

class QFont;

namespace ksword::ui::main_window
{
    void ensureGlobalContextMenuThemeFilterInstalled();

    void ensureGlobalComboPopupThemeFilterInstalled();

    void ensureGlobalSliderWheelFilterInstalled();

    void ensureGlobalTableSelectionOutlineFilterInstalled();

    void applyApplicationFontToItemViews(const QFont& applicationFont);
}

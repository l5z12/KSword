#pragma once

// ============================================================
// WindowChrome.h
// Purpose:
// 1) Synchronize the theme color to all 'native title bar' top-level windows (child windows, dialogs, floating docks);
// 2) Use DWM attributes to color the title bar and border, resolving the visual disconnect between the system's default white title bar and dark themes.
// 3) Coordinate with mainWindow's custom title bar: the main window bypasses this module, while all other top-level windows are uniformly managed.
// ============================================================

class QApplication;
class QWidget;

namespace ks::ui
{
    // installWindowChrome:
    // - Install a title bar theme handler for top-level windows in QApplication.
    // - Capture all subsequent native title bar windows and apply the current theme's title bar color;
    // Parameter appInstance: the current QApplication instance; ignored if null.
    // Return value: None.
    void installWindowChrome(QApplication* appInstance);

    // refreshAllWindowChrome:
    // - Re-apply the theme color to all currently displayed top-level window title bars after a theme switch.
    // - Ensure immediate reflection of light/dark theme and primary background color changes to all open windows.
    // Parameters: None.
    // Return value: None.
    void refreshAllWindowChrome();

    // applyWindowChrome:
    // - Apply the current theme's title bar color to a single top-level window;
    // - Silently ignore if the window is null, not top-level, borderless, or the native handle has not been created.
    // Parameter topLevelWidget: Target top-level window.
    // Return value: None.
    void applyWindowChrome(QWidget* topLevelWidget);
}

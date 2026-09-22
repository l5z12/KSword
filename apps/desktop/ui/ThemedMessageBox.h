#pragma once

#include <QApplication>

namespace ks::ui
{
    // installGlobalMessageBoxTheme:
    // - Install a global QMessageBox theme handler for QApplication;
    // - Ensures all subsequent QMessageBox instances automatically apply a unified light/dark theme and button styles upon display.
    // Usage: Call once after QApplication construction in main.cpp.
    // Parameter appInstance: current application object; ignored if null.
    // Return value: None.
    void installGlobalMessageBoxTheme(QApplication* appInstance);

    // refreshGlobalMessageBoxTheme:
    // - Refresh currently open QMessageBox instances after a theme switch;
    // - Resolves the issue of old message boxes retaining old color schemes when switching between dark and light modes.
    // Invocation: Call after mainWindow::applyAppearanceSettings completes the global palette update.
    // Parameters: None.
    // Return value: None.
    void refreshGlobalMessageBoxTheme();
}

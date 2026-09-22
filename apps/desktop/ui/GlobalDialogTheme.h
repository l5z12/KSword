#pragma once

// ============================================================
// GlobalDialogTheme.h
// Purpose:
// 1) Centralize theme background handling for standard QDialog / QInputDialog at the UI layer;
// 2) Avoid repeated manual setStyleSheet calls for temporary dialogs in each feature module;
// 3) Divide responsibilities with UI/ThemedMessageBox; message boxes are still handled by a dedicated themer.
// ============================================================

#include <QApplication>

namespace ks::ui
{
    // installGlobalDialogTheme:
    // Install a global theme for standard dialogs on QApplication.
    // - Captures subsequent QInputDialog and QDialog-derived popups and ensures they have an opaque background.
    // Parameter appInstance: the current QApplication instance; ignored if null.
    // Return value: None.
    void installGlobalDialogTheme(QApplication* appInstance);

    // refreshGlobalDialogTheme:
    // - Re-refresh currently open standard dialogs after a theme switch;
    // - Immediately reflect dark/light mode changes to existing windows.
    // Parameters: None.
    // Return value: None.
    void refreshGlobalDialogTheme();
}

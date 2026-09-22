#pragma once

// ============================================================
// TextSearchReplaceSupport.h
// Purpose:
// 1) - 1) Uniformly provide find-and-replace capabilities for multi-line text boxes across the entire
//    application (QPlainTextEdit / QTextEdit / QTextBrowser), supporting regex and case-sensitivity toggles.
// 2) Implemented via QApplication-level event filters; no need to modify individual control
//    creation points, and newly added text boxes automatically gain the same capability.
// 3) Editors with built-in find panels (code editors /
//    hex editors) are skipped to avoid having two find bars.
// Interaction:
// - Ctrl+F opens the search bar; Ctrl+H opens the search-and-replace dialog and activates the replace input.
// - Enter / Shift+Enter to find next / previous, Esc to close;
// - The read-only text box displays only the search portion, not the replace portion.
// ============================================================

class QApplication;
class QWidget;

namespace ks::ui
{
    // installGlobalTextSearchReplaceSupport:
    // - Install a global event filter once so that any multi-line text box responds to Ctrl+F / Ctrl+H.
    // - The search panel is created on-demand upon first invocation and attached to the corresponding text box for destruction with it.
    // Call method:
    // - Called once in main.cpp after creating the QApplication.
    // Input parameter appInstance:
    // - Application instance; return immediately if null.
    void installGlobalTextSearchReplaceSupport(QApplication* appInstance);

    // openTextSearchPanelFor:
    // - Proactively pop up the search panel for a specified text box for reuse by right-click menus and other entry points.
    // Input parameter editorWidget:
    // - Target: QPlainTextEdit / QTextEdit. Returns false for non-text editors or editors that are skipped.
    // Input parameter focusReplaceField:
    // - When true, expands and focuses the replace input field (read-only text boxes ignore this request).
    // Return value:
    // - Returns true if the panel is successfully displayed.
    bool openTextSearchPanelFor(QWidget* editorWidget, bool focusReplaceField);
}

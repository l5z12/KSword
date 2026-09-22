#pragma once

// ============================================================
// GlobalRefreshShortcut.h
// Purpose:
// 1) Provide Windows convention F5 = refresh for the entire application;
// 2) The refresh button member names across pages are inconsistent (m_refreshButton / m_refreshServiceButton /
//    m_refreshCallbackEnumButton ...). Binding them page-by-page would require modifying dozens of files. Here, we change the behavior
//    so that pressing F5 finds and triggers the refresh button for the current page by searching upward from the focused control.
// 3) If the refresh button is not found, do nothing and do not affect existing key behavior.
// ============================================================

class QApplication;

namespace ks::ui
{
    // installGlobalRefreshShortcut:
    // - Install an F5 shortcut filter for QApplication.
    // - On a hit, click the visible and available refresh button on the current page.
    // Parameter appInstance: the current QApplication instance; ignored if null.
    // Return value: None.
    void installGlobalRefreshShortcut(QApplication* appInstance);
}

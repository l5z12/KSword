#pragma once

// ============================================================
// WindowDock.h
// Purpose:
// 1) Serves as the sole 'Window' page, unifying window management and window auditing.
// 2) The "Window Management" page embeds OtherDock, restoring detailed views for the window list and desktop;
// 3) All other audit pages are read-only, covering win32k GUI/session, hotkeys/hooks, clipboard, and GPU/display.
// 4) Audit details are displayed in a sortable table showing all rows, rather than only truncated text summaries.
// ============================================================

#include "../Framework.h"
#include "../ui/CodeEditorWidget.h"

#include <QWidget>
#include <QStringList>
#include <QVector>

#include <atomic> // std::atomic_bool: Controls mutual exclusion for background refresh tasks.

class QLabel;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;
class QShowEvent;
class OtherDock; // Reuse existing window management (window list / desktop) implementation to avoid reinventing the wheel.

// ============================================================
// WindowDock
// Notes:
// - The 'Window Management' page embeds OtherDock, preserving its complete window list and desktop capabilities;
// - The audit page is read-only by default; structured entries are displayed uniformly in a table with sorting and full-row viewing support;
// - Do not destroy page objects when switching tabs to avoid state flickering and duplicate sampling.
// ============================================================
class WindowDock final : public QWidget
{
public:
    // Constructor:
    // - Purpose: Create the window management page and several read-only audit pages.
    // - Parameter parent: Qt parent widget.
    explicit WindowDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Release the page object; the audit page has no automatic refresh timer.
    // - Returns: Nothing.
    ~WindowDock() override;

    void focusWindowsByPids(const QVector<quint32>& processIds);

    // refreshThemeVisuals:
    // - Regenerate audit table, existing cells, and column preset button visual states dependent on theme colors;
    // - Retains transparent table strategy, row model, sorting, and column visibility toggling without triggering any R0/R3 queries.
    // Usage: The unified theme refresh entry point in mainWindow is called after a change to light/dark theme or custom colors.
    // Input/Output: None
    void refreshThemeVisuals();

protected:
    // showEvent:
    // - Preserve the Qt show event chain;
    // - Do not automatically trigger audit refresh to avoid repeated sampling when switching window pages.
    void showEvent(QShowEvent* showEventPointer) override;

private:
    // initializeUi:
    // - Create the top toolbar, window management page, and all read-only audit pages;
    // - Returns: Nothing.
    void initializeUi();

    // initializeConnections:
    // - Connects refresh button events;
    // - Returns: Nothing.
    void initializeConnections();

    // requestAsyncRefresh:
    // - Collect snapshots of all audit pages and table row models on a background thread;
    // - Results are returned to the UI via a queued connection.
    void requestAsyncRefresh();

    // setRefreshingPlaceholderRows:
    // - Write the 'Collecting...' diagnostic row before background collection starts;
    // - This prevents the audit table from appearing completely blank when the R0 wrapper is slow or temporarily unavailable.
    // - Returns: void; updates only this object's cache and immediately refreshes the UI.
    void setRefreshingPlaceholderRows();

    // applyAuditViews:
    // - Write cached summary text and table rows to controls on the UI thread.
    // - Does not perform any additional collection.
    void applyAuditViews();

    // updateSelectedWindowSnapshotDetail:
    // - Input currentRow: Currently selected row in the window table;
    // - Processing: Read HWND/PID/TID/status only from visible columns in the window table and write to the detail box.
    // - Return: None, does not trigger driver calls.
    void updateSelectedWindowSnapshotDetail(int currentRow);

    // requestSelectedWindowRuntimeDetail:
    // - Input: Selected row in the current window table;
    // - Handling: On-demand background call to ArkDriverClient::queryWin32kWindowDetail;
    // - Returns: None; results are fed back to m_windowDetailEditor.
    void requestSelectedWindowRuntimeDetail();

private:
    // Top-level layout and toolbar.
    QVBoxLayout* rootLayout_ = nullptr;    // m_rootLayout: Root layout.
    QWidget* toolBarWidget_ = nullptr;     // m_toolBarWidget: Top toolbar.
    QVBoxLayout* toolBarLayout_ = nullptr; // m_toolBarLayout: The top toolbar layout.
    QLabel* statusLabel_ = nullptr;        // m_statusLabel: Refresh status prompt.
    QPushButton* refreshButton_ = nullptr; // m_refreshButton: Manual audit refresh button.

    // Tabs and pages.
    QTabWidget* tabWidget_ = nullptr;      // m_tabWidget: Tab container.
    OtherDock* windowManagementDock_ = nullptr; // m_windowManagementDock: Embedded window management (window list / desktop).
    QWidget* sessionPage_ = nullptr;       // m_sessionPage: win32k GUI/session page.
    QWidget* hotkeyHookPage_ = nullptr;    // m_hotkeyHookPage: Hotkey/hook page.
    QWidget* clipboardPage_ = nullptr;     // m_clipboardPage: Clipboard/message-only page.
    QWidget* displayPage_ = nullptr;       // m_displayPage: GPU/Display/Watchdog page.

    // Summary text editor (read-only, used solely to hold non-table context notes).
    CodeEditorWidget* sessionSummaryEditor_ = nullptr;    // m_sessionSummaryEditor: session/window station context summary.
    CodeEditorWidget* hotkeyHookSummaryEditor_ = nullptr; // m_hotkeyHookSummaryEditor: Hotkey/hook context summary.
    CodeEditorWidget* displaySummaryEditor_ = nullptr;    // m_displaySummaryEditor: GPU/display context summary.
    CodeEditorWidget* windowDetailEditor_ = nullptr;      // m_windowDetailEditor: Snapshot or on-demand details for the currently selected HWND.

    // Structured audit table (sortable, displays all rows).
    QTableWidget* windowsTable_ = nullptr;     // m_windowsTable: Win32K window table.
    QTableWidget* guiThreadsTable_ = nullptr;  // m_guiThreadsTable: GUI threads table.
    QTableWidget* sessionTable_ = nullptr;     // m_sessionTable: Win32K session table.
    QTableWidget* hotkeysTable_ = nullptr;     // m_hotkeysTable: Hotkeys table.
    QTableWidget* hooksTable_ = nullptr;       // m_hooksTable: Hook table.
    QTableWidget* clipboardTable_ = nullptr;   // m_clipboardTable: clipboard property/value table.
    QTableWidget* deviceTable_ = nullptr;      // m_deviceTable: GPU/display/watchdog device audit table.

    // Refresh control.
    std::atomic_bool refreshing_{ false };     // m_refreshing: Background refresh mutex.
    std::atomic_bool windowDetailRefreshing_{ false }; // m_windowDetailRefreshing: Mutex for single HWND detail query.
    QPushButton* queryWindowDetailButton_ = nullptr; // m_queryWindowDetailButton: On-demand query for selected HWND detail.

    // Cache: summary text.
    QString cachedSessionSummary_;             // m_cachedSessionSummary: Session summary cache.
    QString cachedHotkeyHookSummary_;          // m_cachedHotkeyHookSummary: Cached summary of hotkeys and hooks.
    QString cachedDisplaySummary_;             // m_cachedDisplaySummary: Display summary cache.

    // Cache: table row model (each row contains a group of column texts, facilitating direct population in the UI thread).
    QVector<QStringList> cachedWindowsRows_;    // m_cachedWindowsRows: Window table rows.
    QVector<QStringList> cachedGuiThreadRows_;  // m_cachedGuiThreadRows: GUI thread table rows.
    QVector<QStringList> cachedSessionRows_;    // m_cachedSessionRows: session table rows.
    QVector<QStringList> cachedHotkeyRows_;     // m_cachedHotkeyRows: Hotkey table rows.
    QVector<QStringList> cachedHookRows_;       // m_cachedHookRows: Hook table rows.
    QVector<QStringList> cachedClipboardRows_;  // m_cachedClipboardRows: Clipboard table rows.
    QVector<QStringList> cachedDeviceRows_;     // m_cachedDeviceRows: device audit table rows.
};

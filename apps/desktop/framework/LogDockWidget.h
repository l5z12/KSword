#pragma once

// LogDockWidget is the visual log panel in the 'Log Output' dock.
// Control responsibility:
// 1) Display the log table (level/time/content/file/function);
// 2) Provide level filtering, event tracing, copy, and export capabilities;
// 3) Periodically refresh data from the global log manager KswordARKEventEntry.

#include "../Framework.h"

#include <QColor>
#include <QIcon>
#include <QPoint>
#include <QString>
#include <QVariant>
#include <QWidget>

#include <vector>

// Forward declarations: reduce header file dependency size and improve compilation speed.
class QCheckBox;
class QHBoxLayout;
class QPushButton;
class QSpinBox;
class QTableView;
class QTimer;
class QVBoxLayout;

namespace ks::ui
{
    template<typename RowT>
    class FlatTableModel;
}

class LogDockWidget final : public QWidget
{
public:
    // Constructor purpose:
    // - initialize all UI controls.
    // - Establish signal connections;
    // - Start periodic refresh.
    // Parameter parent: Qt parent object pointer.
    explicit LogDockWidget(QWidget* parent = nullptr);

    // refreshNow: Forces synchronization of the latest log snapshot when the independent log window is refreshed.
    void refreshNow();

private:
    // initializeUi:
    // - Create layout, filter area, button area, and log table.
    // - Sets the non-editable state and column width policy.
    void initializeUi();

    // initializeConnections:
    // - Connect interaction logic for checkboxes, buttons, right-click menus, timers, etc.
    void initializeConnections();

    // initializeRefreshTimer:
    // - Create and start the refresh timer;
    // - Use Revision() for lightweight change detection.
    void initializeRefreshTimer();

    // refreshTableFromManager:
    // - Read snapshot from the log manager;
    // - App level filter / trace filter.
    // - Only the most recent N filtered log entries are passed to the table model; internal logs remain fully retained by KswordARKEventEntry;
    // - Rebuilds the table and scrolls to the bottom if needed.
    // Parameter forceRefresh:
    // - true: force refresh (for user-initiated actions);
    // - false: refresh only when revision changes (used by timer).
    void refreshTableFromManager(bool forceRefresh);

    // rebuildTable:
    // - Replace the lightweight table model's data snapshot with filteredEvents in a single operation.
    // - No longer creates QTableWidgetItem instances for each cell, reducing heap allocation and destructor pressure during refreshes.
    // Parameter filteredEvents: filtered set of visible logs.
    void rebuildTable(std::vector<KEvent> filteredEvents);

    // visibleLogLimit:
    // - Read the current value from the 'Recent Log Count' numeric input box.
    // - Fall back to the default display count when the UI is not yet initialized or controls are abnormal.
    // Parameters: None.
    // Returns: The maximum number of log lines allowed for display in the current UI, without affecting the internal full log storage.
    int visibleLogLimit() const;

    // applyDetailColumnVisibility:
    // - Toggles the Details column and Function column based on the 'Details' checkbox state.
    // - Toggle the log table between compact and detailed modes.
    void applyDetailColumnVisibility();

    // resolveLogTableData:
    // - Unified parsing of Display/Decoration/ToolTip/Foreground/Background roles for FlatTableModel;
    // - Consolidate text, icons, and row coloring logic previously scattered across QTableWidgetItem into the model layer.
    // Parameters: logItem is the target row log object; column is the target column; role is the Qt data role.
    // Return value: QVariant corresponding to the role; returns an empty QVariant if unsupported or out of bounds.
    QVariant resolveLogTableData(const KEvent& logItem, int column, int role) const;

    // getRowHighlightBrush:
    // - Return the row background/foreground highlight color based on the log level;
    // - Returns a valid color only for Error/Fatal levels; other levels retain the current theme's default table coloring.
    // Parameters: logItem is the target log object; role is Qt::BackgroundRole or Qt::ForegroundRole.
    // Return value: Valid QBrush wrapped in QVariant; returns empty QVariant when no special styling is present.
    QVariant getRowHighlightBrush(const KEvent& logItem, int role) const;

    // makeLevelSquareIcon:
    // - Generates a solid-color small square icon for the 'Level' column.
    // Parameter color: The square's color.
    // Return value: The generated QIcon.
    QIcon makeLevelSquareIcon(const QColor& color) const;

    // getLevelColor purpose: Returns the color corresponding to the level.
    QColor getLevelColor(KLogLevel level) const;

    // getLevelText function: Return the level string (DEBUG/INFO/...).
    QString getLevelText(KLogLevel level) const;

    // isLevelEnabledByCheckbox:
    // - Determine if a specific level should be displayed based on the checkbox state.
    bool isLevelEnabledByCheckbox(KLogLevel level) const;

    // showTableContextMenu:
    // - Display a context menu when right-clicking a table cell;
    // - Provides copy cell/copy row/track or untrack functionality.
    // Parameter position: The position of the right-click point in the table viewport coordinate system.
    void showTableContextMenu(const QPoint& position);

    // copySingleCell: Copies the text of the specified cell to the clipboard.
    // Parameters row/column: Target row and column indices.
    void copySingleCell(int row, int column);

    // copySingleRow action: Copy the specified full row (tab-separated) to the clipboard.
    // Parameter row: target row index.
    void copySingleRow(int row);

    // copySelectedRows:
    // - Copy all selected log rows in the current table.
    // - The right-click menu for multiple selected rows calls only this entry to ensure all selected rows are copied at once.
    // Parameters: none; the function reads the table selection model internally.
    // Return value: None. Copy text directly to the system clipboard.
    void copySelectedRows();

    // copyVisibleRows:
    // - Copy all currently visible table content to the clipboard.
    // - Adapts to the visible subset after event trace filtering.
    void copyVisibleRows();

    // visibleEvents:
    // - Returns a lightweight snapshot of the currently saved visible logs.
    // - Copy, trace, and right-click menu operations all read from this snapshot to avoid the Dock maintaining a second parallel cache.
    // Parameters: None.
    // Return value: Returns a const reference to the row array within the model; returns an empty array reference if the model is not created.
    const std::vector<KEvent>& visibleEvents() const;

    // visibleEventAt:
    // - Safely read current visible logs by table row index.
    // - Centralize handling for scenarios where the model is not created or the row index is out of bounds.
    // Parameter row: table row index.
    // Return value: Returns a pointer to the log object if valid; returns nullptr if invalid.
    const KEvent* visibleEventAt(int row) const;

    // collectSelectedRowIndexes:
    // - Collect the currently selected row indices from the QTableView selection model.
    // - Automatically sort and deduplicate to avoid counting the same row multiple times across different cells.
    // Parameters: None.
    // Returns: A list of valid row indices, ordered to match the top-to-bottom sequence in the UI.
    std::vector<int> collectSelectedRowIndexes() const;

    // buildVisibleRowText:
    // - Concatenate a log row text based on current visible columns.
    // - Reused for 'Copy Row' / 'Copy Visible' to ensure the copied result matches the UI.
    QString buildVisibleRowText(const KEvent& logItem) const;

    // startTrackingByRow:
    // - Read the GUID of a specific row;
    // - Enters 'Show only logs with the same GUID' mode.
    // Parameter row: The row index triggering the tracking.
    void startTrackingByRow(int row);

    // cancelTracking purpose: Exit event tracking mode and restore standard filtering.
    void cancelTracking();

    // exportAllLogs:
    // - Pop up the save dialog;
    // - Call KswordARKEventEntry.Save to export all logs.
    void exportAllLogs();

    // chooseExportPath:
    // - On Windows, prefer calling the native shell save dialog;
    // - fall back to manual path entry if shell call fails.
    // Return value:
    // - Non-null: target path after user confirmation;
    // - Empty string: user cancelled.
    QString chooseExportPath();

    // clearAllLogsWithDoubleConfirm:
    // Root layout: vertical stack of 'single-line toolbar/table'.
    // - Refresh table.
    void clearAllLogsWithDoubleConfirm();

private:
    // ======== Main Layout and Controls ========
    QVBoxLayout* rootLayout_ = nullptr;      // Root layout: vertical stack of 'single-line toolbar' and 'table'.
    QHBoxLayout* filterLayout_ = nullptr;    // m_filterLayout: Reserved member slot, not currently added to a layout individually.
    QHBoxLayout* actionLayout_ = nullptr;    // Action layout: icon buttons + 'Select All' checkbox.

    QCheckBox* debugCheck_ = nullptr;        // Debug level display switch.
    QCheckBox* infoCheck_ = nullptr;         // Info level display switch.
    QCheckBox* warnCheck_ = nullptr;         // Warn level display toggle.
    QCheckBox* errorCheck_ = nullptr;        // Error level display switch.
    QCheckBox* fatalCheck_ = nullptr;        // Fatal level display switch.
    QCheckBox* detailCheck_ = nullptr;       // "Details" switch: controls display of the File/Function columns.
    QCheckBox* autoScrollCheck_ = nullptr;   // Switch for 'keep scrolling to the bottom'.
    QSpinBox* visibleLimitSpin_ = nullptr;   // "Recent log entries" input: Limits only the number of rows rendered in the UI, without truncating internal logs.

    QPushButton* exportButton_ = nullptr;       // Export log button.
    QPushButton* clearButton_ = nullptr;        // Clear log button.
    QPushButton* copyVisibleButton_ = nullptr;  // Copy visible button.

    QTableView* logTable_ = nullptr;                         // Core log table view.
    ks::ui::FlatTableModel<KEvent>* logModel_ = nullptr;     // Core log table lightweight data model.
    QTimer* refreshTimer_ = nullptr;                         // Refresh timer.

    // ======== Refresh and Filter Status ========
    std::size_t lastRevision_ = 0;           // Log revision at the last render.

    bool isTracking_ = false;                // Whether currently in "Track by GUID" mode.
    GUID trackingGuid_{};                    // Target GUID used in tracking mode.
};

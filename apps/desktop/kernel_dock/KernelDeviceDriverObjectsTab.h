#pragma once

// ============================================================
// KernelDeviceDriverObjectsTab.h
// Purpose:
// 1) Provide an independent QWidget for the "Devices and Drivers" specialized view.
// 2) R3 read-only display, filtering, copying, and TSV export only;
// 3) Currently mounted to the object namespace page by KernelDock.cpp as the "Device/Driver Objects" sub-page.
// 4) This page is responsible solely for read-only display of the object directory and does not directly access drivers or modify kernel objects.
// ============================================================

#include "KernelDeviceDriverObjectsWorker.h"

#include <QWidget>

#include <atomic>  // std::atomic_bool: Control background refresh mutual exclusion.
#include <vector>  // std::vector: Container for cached enumeration results and filtered results.

class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QPoint;
class QTableWidget;
class QTableWidgetItem;
class QVBoxLayout;

// ============================================================
// KernelDeviceDriverObjectsTab
// Purpose:
// - Input: Qt parent control;
// - Processing: Asynchronously enumerate device/driver/file system objects in the
//   object manager and display them in the UI filtered by directory, type, and keyword.
// - Output: Read-only table, status label, and exportable TSV text.
// ============================================================
class KernelDeviceDriverObjectsTab final : public QWidget
{
public:
    // Constructor:
    // - Input parent: Qt parent widget;
    // - Handling: Create the UI and initiate the first background refresh.
    // - Returns: Nothing.
    explicit KernelDeviceDriverObjectsTab(QWidget* parent = nullptr);

    // Destructor:
    // - Processing: Object lifecycle managed by Qt's parent-child tree.
    // - Returns: Nothing.
    ~KernelDeviceDriverObjectsTab() override = default;

private:
    // initializeUi：
    // - Processing: Create top toolbar, filters, and results table;
    // - Returns: Nothing.
    void initializeUi();

    // initializeConnections：
    // - Processing: Connect buttons, filters, and table right-click menus;
    // - Returns: Nothing.
    void initializeConnections();

    // refreshAsync：
    // - Processing: Execute R3 enumeration tasks in a background thread.
    // - Return: No return value; results are dispatched to the UI thread.
    void refreshAsync();

    // applyRefreshResult：
    // - Input rows: background enumeration results; input errorText: fatal error text;
    // - Processing: Rebuild filters and the table after returning to the UI thread.
    // - Returns: Nothing.
    void applyRefreshResult(
        std::vector<KernelDeviceDriverObjectEntry> rows,
        const QString& errorText);

    // rebuildVisibleRows：
    // - Processing: filter visible rows based on current filters and rebuild the table;
    // - Returns: Nothing.
    void rebuildVisibleRows();

    // populateFilterCombos：
    // - Input rows: Current full result set.
    // - Action: Refresh directory/type combo boxes;
    // - Returns: Nothing.
    void populateFilterCombos(const std::vector<KernelDeviceDriverObjectEntry>& rows);

    // matchesCurrentFilters：
    // - Input entry: Row to be evaluated.
    // - Processing: Perform read-only filtering by directory, object type, and keyword.
    // - Returns: true if the row should be displayed.
    bool matchesCurrentFilters(const KernelDeviceDriverObjectEntry& entry) const;

    // rebuildTableWidget：
    // - Processing: Write current visible rows to the table widget.
    // - Returns: Nothing.
    void rebuildTableWidget();

    // updateStatusText：
    // - Input errorText: Optional error text;
    // - Processing: Refresh status label color and text based on current load and filter states.
    // - Returns: Nothing.
    void updateStatusText(const QString& errorText = QString());

    // showTableContextMenu：
    // - Input localPosition: click position within the table viewport;
    // - Processing: Pop up the copy and export menu.
    // - Returns: Nothing.
    void showTableContextMenu(const QPoint& localPosition);

    // copyCellAt：
    // - Input row/column: Target cell position;
    // - Processing: write cell text to the clipboard.
    // - Returns: Nothing.
    void copyCellAt(int row, int column) const;

    // copyRowAt：
    // - Input row: target row.
    // - Processing: Export entire rows as TSV-style text to the clipboard.
    // - Returns: Nothing.
    void copyRowAt(int row) const;

    // copyVisibleRowsAsTsv：
    // - Processing: Write current visible results to clipboard.
    // - Returns: Nothing.
    void copyVisibleRowsAsTsv() const;

    // exportVisibleRowsAsTsv：
    // - Processing: Save current visible results as a TSV file.
    // - Returns: Nothing.
    void exportVisibleRowsAsTsv();

    // rowsToTsv：
    // - Input includeHeader: output the header row if true;
    // - Processing: Serialize currently visible results to TSV.
    // - Returns: TSV text.
    QString rowsToTsv(bool includeHeader) const;

    // sanitizeTsvField：
    // - Input text: Original field text.
    // - Handling: Flattens tabs and newlines to prevent TSV structure misalignment.
    // - Returns: a single field text suitable for writing to a TSV.
    static QString sanitizeTsvField(const QString& text);

    // makeReadOnlyItem：
    // - Input text: cell content;
    // - Processing: Create a non-editable QTableWidgetItem;
    // - Returns: a pointer to an item that can be directly inserted into a table.
    static QTableWidgetItem* makeReadOnlyItem(const QString& text);

private:
    QVBoxLayout* rootLayout_ = nullptr;          // m_rootLayout: Page root layout.
    QWidget* toolbarWidget_ = nullptr;           // m_toolbarWidget: The top toolbar container.
    QWidget* filterWidget_ = nullptr;            // m_filterWidget: Filter row container.
    QPushButton* refreshButton_ = nullptr;       // m_refreshButton: Refresh button.
    QPushButton* exportButton_ = nullptr;        // m_exportButton: Export button.
    QLabel* statusLabel_ = nullptr;              // m_statusLabel: Status label.
    QComboBox* directoryFilterCombo_ = nullptr;   // m_directoryFilterCombo: Directory filter.
    QComboBox* typeFilterCombo_ = nullptr;        // m_typeFilterCombo: Object type filter.
    QLineEdit* keywordEdit_ = nullptr;           // m_keywordEdit: Keyword filter box.
    QTableWidget* tableWidget_ = nullptr;        // m_tableWidget: Result table.

    std::vector<KernelDeviceDriverObjectEntry> allRows_;     // m_allRows: Full results enumerated in the background.
    std::vector<KernelDeviceDriverObjectEntry> visibleRows_;  // m_visibleRows: Visible results after current filtering.
    std::atomic_bool refreshRunning_ = false;                 // m_refreshRunning: Refresh mutex flag.
};

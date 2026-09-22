#pragma once

// ============================================================
// KernelBaseNamedObjectsTab.h
// Purpose:
// 1) Declare the BaseNamedObjects specialized aggregation view;
// 2) Provide filtering by Session, object type, and keywords.
// 3) Relies solely on the R3 worker; does not access the KswordARK driver.
// ============================================================

#include "../Framework.h"
#include "KernelBaseNamedObjectsWorker.h"

#include <QWidget>

#include <atomic>
#include <vector>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QVBoxLayout;

// KernelBaseNamedObjectsTab:
// - Input: Qt parent;
// - Handling logic: initialize the read-only table and filter controls, then execute the BaseNamedObjects snapshot in the background.
// - Return behavior: no business return value; results are displayed in the table.
class KernelBaseNamedObjectsTab final : public QWidget
{
public:
    explicit KernelBaseNamedObjectsTab(QWidget* parent = nullptr);
    ~KernelBaseNamedObjectsTab() override = default;

private:
    // initializeUi：
    // - Inputs: None;
    // - Processing: Create refresh button, filters, and results table;
    // - Returns: Nothing.
    void initializeUi();

    // initializeConnections：
    // - Inputs: None;
    // - Processing: Connect refresh button and filter controls.
    // - Returns: Nothing.
    void initializeConnections();

    // refreshSnapshotAsync：
    // - Input: forceRefresh: true when the user manually refreshes.
    // - Processing: Asynchronously invoke runBaseNamedObjectsSnapshotTask in the background.
    // - Return: None; results are returned to the UI thread via Qt queued invocation.
    void refreshSnapshotAsync(bool forceRefresh);

    // populateTable：
    // - Input rows: Complete snapshot returned by the worker;
    // - Processing: Cache and rebuild the table and filter dropdown items.
    // - Returns: Nothing.
    void populateTable(const std::vector<KernelBaseNamedObjectEntry>& rows);

    // rebuildFilterOptions：
    // - Input: None; reads m_rows;
    // - Processing: Refresh Session/Type dropdowns;
    // - Returns: Nothing.
    void rebuildFilterOptions();

    // applyFilters：
    // - Input: None; reads current filter controls.
    // - Processing: Hide non-matching table rows and refresh status.
    // - Returns: Nothing.
    void applyFilters();

    // rowMatchesFilters：
    // - Input entry: a BaseNamedObjects record;
    // - Processing: Match Session, type, and keywords;
    // - Returns: true if the row should be displayed.
    bool rowMatchesFilters(const KernelBaseNamedObjectEntry& entry) const;

    // setStatusText：
    // - Input: statusText: display text
    // - Processing: Update status label;
    // - Returns: Nothing.
    void setStatusText(const QString& statusText);

private:
    QVBoxLayout* rootLayout_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QComboBox* sessionFilterCombo_ = nullptr;
    QComboBox* typeFilterCombo_ = nullptr;
    QLineEdit* keywordFilterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;

    std::vector<KernelBaseNamedObjectEntry> rows_;
    std::atomic_bool refreshing_{ false };
};

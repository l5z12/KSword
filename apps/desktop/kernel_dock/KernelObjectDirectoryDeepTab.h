#pragma once

// ============================================================
// KernelObjectDirectoryDeepTab.h
// Purpose:
// 1) Provides an independent page for 'Object Namespace / Directory Recursion';
// 2) The page independently starts a background thread to call KernelObjectDirectoryDeepWorker.
// 3) Do not depend on KernelDock private members to facilitate future integration into a secondary tab.
// ============================================================

#include "KernelObjectDirectoryDeepWorker.h"

#include <QWidget>

#include <atomic>
#include <vector>

class CodeEditorWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTreeWidget;
class QTreeWidgetItem;

// KernelObjectDirectoryDeepTab
// - Input: Root path and maximum recursion depth provided by the user in the UI;
// - Processing: Execute NtOpenDirectoryObject + NtQueryDirectoryObject recursive enumeration in a background thread.
// - Returns: No direct return value; results are displayed via a QTreeWidget and a details pane.
class KernelObjectDirectoryDeepTab final : public QWidget
{
public:
    explicit KernelObjectDirectoryDeepTab(QWidget* parent = nullptr);
    ~KernelObjectDirectoryDeepTab() override = default;

private:
    // initializeUi：
    // - Purpose: Create root path input, refresh button, depth input, result tree, and details pane.
    // - Returns: Nothing.
    void initializeUi();

    // startRefresh：
    // - Purpose: Read UI parameters and start the background recursive enumeration.
    // - Return: None; the UI is populated via QueuedConnection after the refresh completes.
    void startRefresh();

    // setRefreshRunning：
    // - Purpose: Synchronize the state of the refresh button, status label, and input controls.
    // - Parameter running: true = refreshing; false = idle.
    // - Returns: Nothing.
    void setRefreshRunning(bool running);

    // rebuildTree：
    // - Purpose: Rebuilds m_rows into a tree display.
    // - Returns: Nothing.
    void rebuildTree();

    // showCurrentItemDetail：
    // - Purpose: Display detailed fields based on the data index of the current tree node.
    // - Returns: Nothing.
    void showCurrentItemDetail();

    // formatEntryDetail：
    // - Purpose: Format a single enumeration record into detailed text.
    // - Parameter entry: An object record returned by the Worker.
    // - Return: Multi-line text directly displayable in CodeEditorWidget.
    static QString formatEntryDetail(const KernelObjectDirectoryDeepEntry& entry);

private:
    QLineEdit* rootPathEdit_ = nullptr;       // m_rootPathEdit: Object Manager root path input field.
    QPushButton* refreshButton_ = nullptr;    // m_refreshButton: Start background recursive refresh.
    QSpinBox* maxDepthSpinBox_ = nullptr;     // m_maxDepthSpinBox: Maximum recursion depth input.
    QLabel* statusLabel_ = nullptr;           // m_statusLabel: Refresh status summary.
    QTreeWidget* resultTree_ = nullptr;       // m_resultTree: Recursive result tree.
    CodeEditorWidget* detailEditor_ = nullptr; // m_detailEditor: Current node details.

    std::atomic_bool refreshRunning_{ false }; // m_refreshRunning: Prevents duplicate refreshes.
    std::vector<KernelObjectDirectoryDeepEntry> rows_; // m_rows: Results from the most recent Worker.
};

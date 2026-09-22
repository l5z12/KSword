#pragma once

// ============================================================
// FileMappedProcessWindow.h
// Purpose:
// - Displays Phase-7 file Section/ControlArea reverse lookup results for mapped processes;
// - Call ArkDriverClient in the background; do not invoke DeviceIoControl directly in UI files.
// - Supports jumping to process details and copying the mapped diagnostic line.
// ============================================================

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QDialog>

#include <cstdint>
#include <functional>
#include <vector>

class QHBoxLayout;
class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;

class FileMappedProcessWindow final : public QDialog
{
public:
    using OpenProcessDetailCallback = std::function<void(std::uint32_t)>;

    // Constructor purpose:
    // - Accept file paths to be scanned;
    // - initialize UI;
    // - Automatically initiate the first R0 mapping reverse lookup.
    // Parameter targetPaths: File path list.
    // Parameter parent: Qt parent object.
    // Returns: Nothing.
    explicit FileMappedProcessWindow(const std::vector<QString>& targetPaths, QWidget* parent = nullptr);

    // setOpenProcessDetailCallback:
    // - Sets the external bridge callback for 'Go to Process Details'.
    // - FileDock is responsible for forwarding the callback to mainWindow.
    // Parameter callback: PID callback.
    // Returns: Nothing.
    void setOpenProcessDetailCallback(OpenProcessDetailCallback callback);

private:
    struct MappedProcessRow
    {
        QString targetPath;                       // targetPath: Matched file path.
        QString processName;                      // processName: Process name padded by R3.
        ksword::ark::FileSectionMappingEntry map; // map: Original R0 mapping row.
    };

    struct RefreshResult
    {
        std::vector<MappedProcessRow> rows; // rows: Display rows.
        QString diagnosticText;             // diagnosticText: Status bar diagnostic message.
        std::uint64_t elapsedMs = 0;        // elapsedMs: Background elapsed time.
    };

    enum class TableColumn
    {
        kTargetPath = 0,
        kSectionKind,
        kProcessId,
        kProcessName,
        kViewMapType,
        kBaseAddress,
        kEndAddress,
        kSize,
        kControlArea,
        kCount
    };

private:
    // initializeUi purpose: Create the toolbar, status bar, and results table.
    void initializeUi();
    // initializeConnections: Binds refresh, navigation, and right-click menu actions.
    void initializeConnections();
    // requestRefresh: Asynchronously invokes R0 file mapping reverse lookup.
    void requestRefresh(bool forceRefresh);
    // applyRefreshResult function: Fills the table and status bar on the main thread.
    void applyRefreshResult(std::uint64_t refreshTicket, const RefreshResult& refreshResult);
    // rebuildTable purpose: Rebuilds the QTreeWidget based on m_rows.
    void rebuildTable();
    // selectedRow: Returns the cache of the currently selected row.
    const MappedProcessRow* selectedRow() const;
    // openCurrentProcessDetail: Navigates to the process details for the PID in the current row.
    void openCurrentProcessDetail();
    // copyCurrentRow: Copies visible columns of the current row.
    void copyCurrentRow();
    // showTableContextMenu action: Display the right-click context menu for the result table.
    void showTableContextMenu(const QPoint& localPosition);
    // applyAdaptiveColumnWidths purpose: Set column widths based on window width.
    void applyAdaptiveColumnWidths();
    // resizeEvent purpose: Refresh column widths after window size change.
    void resizeEvent(QResizeEvent* event) override;

private:
    std::vector<QString> targetPaths_;              // m_targetPaths: Files to be scanned.
    std::vector<MappedProcessRow> rows_;            // m_rows: result cache.
    OpenProcessDetailCallback openProcessDetailCallback_; // m_openProcessDetailCallback: Process detail bridge.

    QVBoxLayout* rootLayout_ = nullptr;             // Root layout.
    QHBoxLayout* toolbarLayout_ = nullptr;          // Toolbar layout.
    QPushButton* refreshButton_ = nullptr;          // Refresh button.
    QPushButton* openProcessButton_ = nullptr;      // Button to jump to process details.
    QLabel* targetLabel_ = nullptr;                 // Target path label.
    QLabel* statusLabel_ = nullptr;                 // Status label.
    QTreeWidget* resultTable_ = nullptr;            // Result table.

    bool refreshInProgress_ = false;                // Whether a refresh is in progress.
    bool refreshPending_ = false;                   // Whether a refresh is queued.
    std::uint64_t refreshTicket_ = 0;               // Refresh sequence number.
    int refreshProgressPid_ = 0;                    // kPro task ID.
};

#pragma once

// ============================================================
// ProcessMessageHookWindow.h
// Purpose:
// - Display message hooks associated with the target side, installer side, or both sides in a standalone non-modal window.
// - Query and reuse the ArkDriverClient Win32k PDB read-only snapshot interface.
// - R0 filters by the selected owner/target scope; R3 re-validates using the same semantics without modifying Hook or driver state.
// ============================================================

#include <QDialog>
#include <QString>
#include <QStringList>

#include <cstdint>
#include <vector>

class QComboBox;
class QLabel;
class QPoint;
class QPushButton;
class QTableWidget;

struct ProcessMessageHookTarget
{
    std::uint32_t processId = 0; // processId: Target process PID.
    std::uint32_t sessionId = 0; // sessionId: logon session of the target process.
    std::uint64_t creationTime100ns = 0; // creationTime100ns: Prevents PID reuse during window refresh.
    QString processName;         // processName: Process display name for window summary.
};

class ProcessMessageHookWindow final : public QDialog
{
public:
    explicit ProcessMessageHookWindow(
        const ProcessMessageHookTarget& target,
        QWidget* parent = nullptr);

public:
    enum class QueryScope
    {
        kTargetThreads = 0,
        kInstalledByProcess,
        kRelatedToProcess
    };

    enum class Column
    {
        kTargetProcessId = 0,
        kTargetThreadId,
        kHookType,
        kOwnerProcessId,
        kOwnerThreadId,
        kCallbackAddress,
        kModule,
        kFlags,
        kStatus,
        kSessionId,
        kHookHandle,
        kHookObject,
        kModuleBase,
        kProcedureOffset,
        kSource,
        kLastStatus,
        kDiagnostic,
        kCount
    };

private:
    struct QueryResult
    {
        bool ioOk = false;
        bool unsupported = false;
        QueryScope queryScope = QueryScope::kTargetThreads;
        std::uint32_t status = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t matchedCount = 0;
        std::uint32_t discoveredChainCount = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptLinkCount = 0;
        std::uint32_t duplicateCount = 0;
        long lastStatus = 0;
        QString ioMessage;
        QString detail;
        std::vector<QStringList> rows;
    };

    // initializeUi: Creates the top target summary, refresh button, A/B column groups, and results table.
    void initializeUi();
    // initializeConnections: Connect refresh, column groups, header menus, and table copy menus.
    void initializeConnections();
    // requestRefresh: Call ArkDriverClient from the thread pool to avoid blocking the main window.
    void requestRefresh();
    // currentQueryScope: Returns the current owner/target query scope; falls back to the target thread for invalid values.
    QueryScope currentQueryScope() const;
    // applyQueryResult: Apply a query result on the UI thread.
    void applyQueryResult(std::uint64_t ticket, const QueryResult& result);
    // rebuildTable: Rebuilds the table using filtered rows and retains copyable diagnostic rows for empty results.
    void rebuildTable(const QueryResult& result);
    // applyColumnPreset: Applies complementary A/B condensed column groups.
    void applyColumnPreset(const QString& presetName);
    // updateColumnPresetButtons: Synchronize the selection style of A/B buttons.
    void updateColumnPresetButtons();
    // showHeaderContextMenu: Toggle column visibility on header right-click.
    void showHeaderContextMenu(const QPoint& localPosition);
    // showTableContextMenu: Handles right-click context menu actions for copying cells, the current row, or all rows in the table.
    void showTableContextMenu(const QPoint& localPosition);
    // copyCurrentCell: Copies the current cell.
    void copyCurrentCell() const;
    // copyCurrentRow: Copies all fields of the current row.
    void copyCurrentRow() const;
    // copyAllRows: Copy the header and all result rows.
    void copyAllRows() const;
    // tableRowText: Serialize the specified row as TSV.
    QString tableRowText(int row) const;
    // tableHeaderText: Serializes the complete header row to TSV format.
    QString tableHeaderText() const;
    // visibleColumnCount: Counts currently visible columns to prevent users from hiding the last column.
    int visibleColumnCount() const;

private:
    ProcessMessageHookTarget target_; // m_target: Stable process snapshot bound to the window.
    QLabel* targetLabel_ = nullptr;   // m_targetLabel: Summary of PID/Session/Process name.
    QLabel* statusLabel_ = nullptr;   // m_statusLabel: Asynchronously query status and diagnostic summary.
    QPushButton* refreshButton_ = nullptr; // m_refreshButton: Manual re-query button.
    QComboBox* scopeCombo_ = nullptr; // m_scopeCombo: Query scope for target side, owner side, or both sides.
    QPushButton* columnAButton_ = nullptr; // m_columnAButton: Common column group for positioning.
    QPushButton* columnBButton_ = nullptr; // m_columnBButton: Underlying evidence column group.
    QTableWidget* table_ = nullptr;   // m_table: Message Hook result table.
    bool refreshInProgress_ = false;  // m_refreshInProgress: Prevents concurrent duplicate queries.
    bool refreshPending_ = false;     // m_refreshPending: Queue one refresh if a new request arrives while a query is in progress.
    std::uint64_t refreshTicket_ = 0; // m_refreshTicket: Discard expired query results.
};

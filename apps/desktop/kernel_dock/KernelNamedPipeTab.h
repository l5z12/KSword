#pragma once

// ============================================================
// KernelNamedPipeTab.h
// Purpose:
// 1) Provide an independent Named Pipe enumeration widget.
// 2) Depends only on the R3 worker; no integration with KernelDock.h is required.
// 3) Reserved for integrating session attachment to the KernelDock secondary tab.
// ============================================================

#include "KernelNamedPipeWorker.h"

#include <QWidget>

#include <cstdint>
#include <vector>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class CodeEditorWidget;
class QResizeEvent;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class QHBoxLayout;

class KernelNamedPipeTab final : public QWidget
{
public:
    // Constructor:
    // - Input parent: Qt parent object;
    // - Logic: Create toolbar, filter box, results table, and details panel.
    // - Returns nothing; initiates the first refresh in the queue after construction.
    explicit KernelNamedPipeTab(QWidget* parent = nullptr);

    enum class TableColumn : int
    {
        kPipeName = 0,
        kNtPath,
        kAttributes,
        kLastWriteTime,
        kStatus,
        kSourceDirectory,
        kCount
    };

private:
    // initializeUi：
    // - Inputs: None;
    // - Processing logic: create buttons, filter input, table, and detail box;
    // - Returns result: none.
    void initializeUi();

    // initializeConnections：
    // - Inputs: None;
    // - Processing logic: Bind refresh, filter, copy, detail panel, and right-click menu actions.
    // - Returns result: none.
    void initializeConnections();

    // requestRefresh：
    // - Input forceRefresh: true indicates queuing another refresh while currently refreshing;
    // - Processing logic: run runKernelNamedPipeSnapshotTask in the background.
    // - Returns no result; results are filled back via `applySnapshot`.
    void requestRefresh(bool forceRefresh);

    // applySnapshot：
    // - Input: refreshTicket: refresh sequence number; snapshot: worker return result.
    // - Processing logic: discard expired results, rebuild the table and detail panel;
    // - Returns result: none.
    void applySnapshot(std::uint64_t refreshTicket, const KernelNamedPipeSnapshot& snapshot);

    // rebuildTable：
    // - Inputs: None;
    // - Processing logic: Map m_rows to QTreeWidget rows.
    // - Returns result: none.
    void rebuildTable();

    // applyFilter：
    // - Input: None; reads m_filterEdit;
    // - Processing logic: Hide rows that do not match the name, path, status, or source directory.
    // - Returns result: none.
    void applyFilter();

    // updateDetailPanel：
    // - Input: None; reads the current selected row and m_lastSnapshot;
    // - Handling logic: display NPFS enumeration details, candidate path status, and current row details.
    // - Returns result: none.
    void updateDetailPanel();

    // copyCurrentRow：
    // - Inputs: None;
    // - Processing logic: Copy visible columns of the current row, with fields separated by tabs.
    // - Returns result: none.
    void copyCurrentRow();

    // showContextMenu：
    // - Input localPosition: coordinates within the table viewport;
    // - Handle logic: pop up copy/details menu;
    // - Returns result: none.
    void showContextMenu(const QPoint& localPosition);

    // selectedRow：
    // - Inputs: None;
    // - Handling logic: Look up m_rows using the row index in UserRole.
    // - Return value: pointer to the current row; returns nullptr if no row is selected or the index is invalid.
    const KernelNamedPipeEntry* selectedRow() const;

    // applyAdaptiveColumnWidths：
    // - Inputs: None;
    // - Handling logic: set common column widths based on the current viewport width.
    // - Returns result: none.
    void applyAdaptiveColumnWidths();

    void resizeEvent(QResizeEvent* event) override;

private:
    QVBoxLayout* rootLayout_ = nullptr;
    QHBoxLayout* toolbarLayout_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QPushButton* copyButton_ = nullptr;
    QPushButton* detailButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTreeWidget* resultTable_ = nullptr;
    CodeEditorWidget* detailEdit_ = nullptr;

    std::vector<KernelNamedPipeEntry> rows_;
    KernelNamedPipeSnapshot lastSnapshot_;
    bool refreshInProgress_ = false;
    bool refreshPending_ = false;
    std::uint64_t refreshTicket_ = 0;
};

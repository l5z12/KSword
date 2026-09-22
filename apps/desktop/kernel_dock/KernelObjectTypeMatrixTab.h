#pragma once

// ============================================================
// KernelObjectTypeMatrixTab.h
// Purpose:
// 1) Provide a matrix for object type statistics and enumeration policies.
// 2) Reuse the ObjectTypesInformation parsing from KernelDockQueryWorker;
// 3) Merge R0 ObTypeIndexTable slots with name/index validation via ArkDriverClient.
// ============================================================

#include "KernelDock.h"

#include <QWidget>

#include <atomic>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QPoint;
class QTableWidget;
class QTableWidgetItem;
class CodeEditorWidget;

class KernelObjectTypeMatrixTab final : public QWidget
{
public:
    explicit KernelObjectTypeMatrixTab(QWidget* parent = nullptr);
    ~KernelObjectTypeMatrixTab() override = default;

    void requestInitialRefresh();
    static QString strategyForType(const QString& typeNameText);
    static QString formatAccessMask(std::uint32_t accessMask);

private:
    struct R0SnapshotState
    {
        bool attempted = false;
        bool transportOk = false;
        bool unsupported = false;
        std::uint32_t status = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t tableAddress = 0;
        std::uint64_t snapshotHash = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t otNameOffset = 0xFFFFFFFFUL;
        std::uint32_t otIndexOffset = 0xFFFFFFFFUL;
        std::uint32_t returnedCount = 0;
        QString diagnosticText;
    };

    void initializeUi();
    void initializeConnections();
    void refreshAsync();
    void applyRefreshResult(std::vector<KernelObjectTypeEntry> rows, R0SnapshotState r0State, const QString& errorText, bool success);
    void rebuildTable();
    void showContextMenu(const QPoint& localPosition);
    void copyCurrentRow() const;
    void updateDetailForRow(int tableRow);
    QString buildDetailText(const KernelObjectTypeEntry& entry) const;

    // buildDiagnosticDetailText：
    // - Input: reason for refresh failure, no data, or no results from filtering;
    // - Processing: Expand current filter, data source, and next troubleshooting direction.
    // - Returns: Read-only text directly writable to the detail editor.
    QString buildDiagnosticDetailText(const QString& reasonText) const;

    // insertDiagnosticRow：
    // - Input: Diagnostic row title and detail text;
    // - Processing: Write a copyable placeholder row to the table.
    // - Return: No return value; detail text is stored in UserRole + 2.
    void insertDiagnosticRow(const QString& titleText, const QString& detailText);

    bool rowMatchesFilter(const KernelObjectTypeEntry& entry) const;
    std::size_t sourceIndexForTableRow(int tableRow) const;
    static QTableWidgetItem* readOnlyItem(const QString& text);

private:
    QPushButton* refreshButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    CodeEditorWidget* detailEditor_ = nullptr;

    std::atomic_bool refreshing_{ false };
    bool initialRefreshRequested_ = false;
    std::vector<KernelObjectTypeEntry> rows_;
    R0SnapshotState r0State_;
};

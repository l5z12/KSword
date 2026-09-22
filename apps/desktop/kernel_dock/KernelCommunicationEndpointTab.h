#pragma once

// ============================================================
// KernelCommunicationEndpointTab.h
// Purpose:
// 1) Provide an aggregated namespace view for communication endpoint objects.
// 2) Reuse the directory recursive worker for read-only enumeration of ALPC/RPC-related named objects.
// 3) Do not use handle enumeration; do not add a new R0 protocol.
// ============================================================

#include "KernelObjectDirectoryDeepWorker.h"

#include <QWidget>

#include <atomic>
#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QPoint;
class QTableWidget;
class QTableWidgetItem;

class KernelCommunicationEndpointTab final : public QWidget
{
public:
    explicit KernelCommunicationEndpointTab(QWidget* parent = nullptr);
    ~KernelCommunicationEndpointTab() override = default;

private:
    void initializeUi();
    void initializeConnections();
    void refreshAsync();
    void applyRefreshResult(std::vector<KernelObjectDirectoryDeepEntry> rows, const QString& errorText, bool success);
    void rebuildTable();
    void showContextMenu(const QPoint& localPosition);
    void copyCurrentRow() const;

    // buildDiagnosticText：
    // - Input: Reason for communication object enumeration failure, no results, or no matches after filtering.
    // - Handling: Supplement the filter keywords and data source description for the communication object page.
    // - Returns: compact diagnostic text suitable for status columns or copyable rows.
    QString buildDiagnosticText(const QString& reasonText) const;

    // insertDiagnosticRow：
    // - Input: diagnostic title and detail text;
    // - Processing: Insert a copyable diagnostic placeholder row into the table.
    // - Returns: No return value; updates UI only.
    void insertDiagnosticRow(const QString& titleText, const QString& detailText);

    bool rowMatchesFilter(const KernelObjectDirectoryDeepEntry& entry) const;
    static bool isCommunicationEndpoint(const KernelObjectDirectoryDeepEntry& entry);
    static QTableWidgetItem* readOnlyItem(const QString& text);

private:
    QPushButton* refreshButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;

    std::atomic_bool refreshing_{ false };
    std::vector<KernelObjectDirectoryDeepEntry> rows_;
};

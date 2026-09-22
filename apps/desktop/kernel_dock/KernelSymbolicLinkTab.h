#pragma once

// ============================================================
// KernelSymbolicLinkTab.h
// Purpose:
// 1) Provide a dedicated QWidget page for symbolic links;
// 2) Support refresh, keyword filtering, target path filtering, and copying target paths;
// 3) The UI only consumes R3 Worker results and does not directly access the driver or add new IOCTLs.
// ============================================================

#include "KernelSymbolicLinkWorker.h"

#include <QWidget>

#include <vector>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTableWidgetItem;
class QPoint;

class KernelSymbolicLinkTab final : public QWidget
{
public:
    // KernelSymbolicLinkTab：
    // - Input parent: Qt parent object, may be null;
    // - Handling logic: create the toolbar, description text, result table, and connect interaction signals.
    // - Returns the constructed page object.
    explicit KernelSymbolicLinkTab(QWidget* parent = nullptr);

private:
    enum class Column : int
    {
        kSourceDirectory = 0,
        kLinkName,
        kFullPath,
        kTargetPath,
        kDosCandidate,
        kStatusText,
        kCount
    };

    void initializeUi();
    void initializeConnections();
    void refreshAsync();
    void applySnapshotResult(
        std::vector<KernelSymbolicLinkEntry> rows,
        const QString& errorText,
        bool ok);
    void applyFilters();
    void rebuildTable();
    void copyCurrentTarget() const;
    void copyCurrentRow() const;
    void showContextMenu(const QPoint& position);

    static QTableWidgetItem* createReadOnlyItem(const QString& text);
    static QString rowToTsv(const KernelSymbolicLinkEntry& row);

private:
    QPushButton* refreshButton_ = nullptr;
    QPushButton* copyTargetButton_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QLineEdit* targetFilterEdit_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;

    std::vector<KernelSymbolicLinkEntry> allRows_;
    std::vector<KernelSymbolicLinkEntry> visibleRows_;
    bool refreshing_ = false;
};

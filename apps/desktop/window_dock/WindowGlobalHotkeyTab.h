#pragma once

#include <QStringList>
#include <QVector>
#include <QWidget>

#include <cstdint>
#include <memory>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QTimer;

// WindowGlobalHotkeyTab: Read-only summary of all hotkeys readable by R3 across all processes.
class WindowGlobalHotkeyTab final : public QWidget
{
public:
    explicit WindowGlobalHotkeyTab(QWidget* parent = nullptr);
    ~WindowGlobalHotkeyTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    struct PendingRefreshState;

    void initializeUi();
    void refreshAsync();
    void flushPendingSnapshot();
    void appendSnapshotRows(
        std::uint64_t ticket,
        QVector<QStringList> rows,
        std::uint32_t completedProcessCount,
        std::uint32_t totalProcessCount,
        const QString& processName,
        std::uint32_t diagnosticProcessCount);
    void finishRefresh(std::uint64_t ticket, qint64 elapsedMs);
    void appendVisibleRows(const QVector<QStringList>& rows);
    void rebuildTable();
    void showCopyMenu(const QPoint& position);
    static QString rowClipboardText(QTableWidget* table, int row, bool includeHeader);

    QLineEdit* filterEdit_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    QTimer* flushTimer_ = nullptr;
    QVector<QStringList> rows_;
    std::shared_ptr<PendingRefreshState> refreshState_;
    bool refreshing_ = false;
    bool firstRefreshStarted_ = false;
    bool sortingEnabledBeforeRefresh_ = true;
    std::uint64_t refreshTicket_ = 0;
    std::uint64_t appliedRefreshRevision_ = 0;
    std::uint32_t scannedProcessCount_ = 0;
    std::uint32_t totalProcessCount_ = 0;
    std::uint32_t diagnosticProcessCount_ = 0;
    int progressTaskId_ = 0;
};

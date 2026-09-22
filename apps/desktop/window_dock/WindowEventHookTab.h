#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;

// WindowEventHookTab: Read-only display of WinEvent/tagEVENTHOOK snapshots via ArkDriverClient.
// The page does not provide UnhookWinEvent or any linked list modification operations.
class WindowEventHookTab final : public QWidget
{
public:
    explicit WindowEventHookTab(QWidget* parent = nullptr);
    ~WindowEventHookTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applySnapshot(QVector<QStringList> rows, const QString& statusText);
    void rebuildTable();
    void showCopyMenu(const QPoint& position);
    static QString rowClipboardText(QTableWidget* table, int row, bool includeHeader);

    QLineEdit* filterEdit_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    QVector<QStringList> rows_;
    bool refreshing_ = false;
    bool firstRefreshStarted_ = false;
};

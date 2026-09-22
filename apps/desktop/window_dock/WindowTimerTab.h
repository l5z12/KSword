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

// WindowTimerTab: Read-only displays win32k tagTIMER snapshots via ArkDriverClient.
// The page provides no operations to delete, modify, or reorder the timer linked list.
class WindowTimerTab final : public QWidget
{
public:
    explicit WindowTimerTab(QWidget* parent = nullptr);
    ~WindowTimerTab() override = default;

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

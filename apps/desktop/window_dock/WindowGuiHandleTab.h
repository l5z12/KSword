#pragma once

#include <QString>
#include <QStringList>
#include <QVector>
#include <QWidget>

class QLabel;
class QComboBox;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QTableWidget;

// WindowGuiHandleTab: Read-only enumeration of the USER Handle shared table for the current Session.
// The page does not modify, close, or release any GUI objects.
class WindowGuiHandleTab final : public QWidget
{
public:
    explicit WindowGuiHandleTab(QWidget* parent = nullptr);
    ~WindowGuiHandleTab() override = default;

protected:
    void showEvent(QShowEvent* event) override;

private:
    void initializeUi();
    void refreshAsync();
    void applySnapshot(QVector<QStringList> rows, const QString& statusText);
    void rebuildTable();
    void showCopyMenu(const QPoint& position);
    static QString rowClipboardText(QTableWidget* table, int row, bool includeHeader);

    QComboBox* typeFilterCombo_ = nullptr;
    QLineEdit* filterEdit_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTableWidget* table_ = nullptr;
    QVector<QStringList> rows_;
    bool refreshing_ = false;
    bool firstRefreshStarted_ = false;
};

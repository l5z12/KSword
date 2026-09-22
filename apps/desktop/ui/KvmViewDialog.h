#pragma once

// KvmViewDialog: EPT separation view panel (covert hooks and memory hiding).
//
// A view that provides two backups for the same physical page.
// - CLOAK: Execution uses real pages, while reads/writes use shadow pages. Code runs normally, but memory scans see the shadow.
// - Hook: Reads/writes go to real pages, execution goes to shadow pages — byte comparison cannot detect invisible breakpoints.
//
// Both rely on flipping shared EPT leaf entries, so they can only be installed on single-processor topologies. Furthermore, the view table
// cannot be modified during their residency. These constraints are enforced by the driver; the panel merely reports the actual failure reasons.

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QTableWidget;

class KvmViewDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmViewDialog(QWidget* parent = nullptr);

private:
    // buildUi: Construct control tree and connect signals.
    void buildUi();
    // refreshViews: Queries installed views in the background and refreshes the table.
    void refreshViews();
    // startAdd/startRemove/startClear: Initiate a background view operation.
    void startAdd();
    void startRemove();
    void startClear();
    // setBusy: Disable all action buttons while busy.
    void setBusy(bool busy);
    // updateEnabledState: refresh control availability based on write permissions and busy state.
    void updateEnabledState();

    QComboBox* kindBox_ = nullptr;
    QComboBox* seedBox_ = nullptr;
    QLineEdit* addressEdit_ = nullptr;
    QPlainTextEdit* shadowEdit_ = nullptr;
    QTableWidget* viewTable_ = nullptr;
    QPushButton* addButton_ = nullptr;
    QPushButton* removeButton_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    bool busy_ = false;
};

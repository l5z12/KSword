#pragma once

// KvmMsrPolicyDialog: MSR policy panel.
//
// The MSR bitmap installed by P0 allows all MSRs to pass through natively; this is a prerequisite for persistent survival.
// One policy is to create a hole in the bitmap: the named MSR triggers a VM-exit again, allowing the
// dispatcher to decide what the guest receives, rather than letting the hardware provide it directly.
//
// Write direction is weaker than read: replaying arbitrary WRMSR in VMX root causes a host IDT exception with no resume point if the
// value is invalid. Therefore, the write policy can only reject or swallow the instruction, without offering a "log then allow" option.

#include <QDialog>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KvmMsrPolicyDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmMsrPolicyDialog(QWidget* parent = nullptr);

private:
    // buildUi: Construct control tree and connect signals.
    void buildUi();
    // refreshPolicies: Query installed policies in the background and refresh the table.
    void refreshPolicies();
    // startAdd/startRemove/startClear: Initiate a background policy operation.
    void startAdd();
    void startRemove();
    void startClear();
    // setBusy: Disable all action buttons while busy.
    void setBusy(bool busy);
    // updateEnabledState: Refresh control availability based on write permissions, selected action, and busy status.
    void updateEnabledState();

    QLineEdit* msrEdit_ = nullptr;
    QComboBox* accessBox_ = nullptr;
    QComboBox* actionBox_ = nullptr;
    QLineEdit* fakeValueEdit_ = nullptr;
    QTableWidget* policyTable_ = nullptr;
    QPushButton* addButton_ = nullptr;
    QPushButton* removeButton_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    bool busy_ = false;
};

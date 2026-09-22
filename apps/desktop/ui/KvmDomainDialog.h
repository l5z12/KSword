#pragma once

// KvmDomainDialog: EPT execution domain panel.
//
// A domain is a fork of the default view, published in the EPTP list. A guest can
// switch to it using a single VMFUNC instruction, which performs no CPL check—any ring
// 3 thread can switch without triggering a VM exit, and the driver remains unaware.
//
// Therefore, this panel only supports the 'revoke permissions' direction: the domain is created identical to the
// default view, and afterwards permissions can only be removed. Threads switching into the domain structurally
// cannot gain access rights they didn't originally have; in the worst case, they trigger an EPT violation.
//
// Creating the domain itself does not alter any runtime behavior. To make VMFUNC truly usable, a resident boot
// with ENABLE_VMFUNC is required; this is a separate independent switch in the KVM menu on the title bar.

#include <QDialog>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;

class KvmDomainDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmDomainDialog(QWidget* parent = nullptr);

private:
    // buildUi: Construct control tree and connect signals.
    void buildUi();
    // refreshDomains: Query the EPTP list in the background and refresh the table.
    void refreshDomains();
    // startCreate/startRestrict/startReset: initiates a background domain operation.
    void startCreate();
    void startRestrict();
    void startReset();
    // setBusy: Disable all action buttons while busy.
    void setBusy(bool busy);
    // updateEnabledState: refresh control availability based on write permissions and busy state.
    void updateEnabledState();

    QLineEdit* domainEdit_ = nullptr;
    QLineEdit* addressEdit_ = nullptr;
    QLineEdit* lengthEdit_ = nullptr;
    QCheckBox* denyReadBox_ = nullptr;
    QCheckBox* denyWriteBox_ = nullptr;
    QCheckBox* denyExecuteBox_ = nullptr;
    QTableWidget* domainTable_ = nullptr;
    QPushButton* createButton_ = nullptr;
    QPushButton* restrictButton_ = nullptr;
    QPushButton* resetButton_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    bool busy_ = false;
};

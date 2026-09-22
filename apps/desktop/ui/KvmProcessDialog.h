#pragma once

// KvmProcessDialog: R-1 process handling and injection panel.
//
// These two capabilities previously had only one entry point in the GUI: the 'Full Command Panel'—a probe path
// that launched the main program as an hvm_ctl subprocess, which has now been completely removed. The capabilities
// themselves remain: handling and injection each have dedicated IOCTLs, and the driver implements the full
// production path. This page serves as their native entry point, sharing the same shape as the View/MSR/CR panels.
//
// These two operations share a page because they have the same prerequisites, which are the most common obstacles for users:
// both require CR3 tracking to identify the target address space, both require the EPTP-switch backend to activate restricted
// hierarchies and execution views by switching pointers, and both require the resident hypervisor to be stopped during
// installation. Separate pages would repeat the explanation and force users to troubleshoot the same prerequisites twice.
//
// **This is not a security boundary.** It shares the same nature as stealthy hooks: failure results in allowing the operation. If the
// target process can remap its code page to a different guest physical page (via relocation, self-modification, or mapping changes),
// it is no longer on the page that was denied; code capable of modifying CR3 is also unconstrained. This is a R0-external handling
// path, used to take action when kernel APIs are blocked, not to defend against an adversary aware of its existence. This sentence is
// explicitly written on the UI because treating it as a boundary is the only usage where "using it correctly" still leads to failure.

#include <QDialog>

class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTabWidget;

class KvmProcessDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmProcessDialog(QWidget* parent = nullptr);

private:
    // buildUi/buildDispositionPage/buildInjectionPage: Constructs the control tree and connects signals.
    void buildUi();
    QWidget* buildDispositionPage();
    QWidget* buildInjectionPage();

    // refreshDispositions/refreshInjections: Read the corresponding table once in the background and refresh.
    void refreshDispositions();
    void refreshInjections();

    // startFreeze/startTerminate/...: Initiates a background write operation.
    // Each must first pass confirmDestructiveAction, then the write permission gate in the facade.
    void startFreeze();
    void startTerminate();
    void startReleaseDisposition();
    void startReleaseAllDispositions();
    void startInject();
    void startReleaseInjection();
    void startReleaseAllInjections();

    // setBusy: Disable all action buttons while busy. Both tables share a single busy flag because the driver-side
    // state lock is inherently shared; using two flags would only display a non-existent concurrency in the UI.
    void setBusy(bool busy);
    void updateEnabledState();

    // readSelectedProcessId: Retrieves the PID from the selected row in the current page's table; returns false if no row is selected.
    bool readSelectedProcessId(QTableWidget* table, unsigned long* processIdOut);

    QTabWidget* tabs_ = nullptr;

    QLineEdit* dispositionPidEdit_ = nullptr;
    QLineEdit* dispositionAddressEdit_ = nullptr;
    QTableWidget* dispositionTable_ = nullptr;
    QPushButton* freezeButton_ = nullptr;
    QPushButton* terminateButton_ = nullptr;
    QPushButton* releaseDispositionButton_ = nullptr;
    QPushButton* releaseAllDispositionsButton_ = nullptr;
    QPushButton* refreshDispositionsButton_ = nullptr;

    QLineEdit* injectPidEdit_ = nullptr;
    QLineEdit* injectAddressEdit_ = nullptr;
    QLineEdit* injectLoadLibraryEdit_ = nullptr;
    QLineEdit* injectPathEdit_ = nullptr;
    QPushButton* injectBrowseButton_ = nullptr;
    QTableWidget* injectionTable_ = nullptr;
    QPushButton* injectButton_ = nullptr;
    QPushButton* releaseInjectionButton_ = nullptr;
    QPushButton* releaseAllInjectionsButton_ = nullptr;
    QPushButton* refreshInjectionsButton_ = nullptr;

    QLabel* statusLabel_ = nullptr;
    bool busy_ = false;
};

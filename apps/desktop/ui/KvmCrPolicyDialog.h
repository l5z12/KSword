#pragma once

// KvmCrPolicyDialog: Control register policy panel.
//
// Pinning follows the VMCS guest/host masks: pinned bits belong to the hypervisor. The guest reads them from the shadow;
// any attempt to modify them triggers a VM-exit and is rejected, yet the shadow still reports 'modification successful'.
// This is the technique of hard-coding CR0.WP or CR4.SMEP, tricking the code that clears them into thinking it succeeded.
//
// Tracking CR3 is the most expensive switch in this protocol: Windows switches address spaces thousands of times
// per second, each causing a VM-exit. It is disabled by default, and the UI must clearly explain the cost.
//
// The mask and switch are consumed when building the VMCS, so they must be configured before the resident startup.

#include <QDialog>

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;

class KvmCrPolicyDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit KvmCrPolicyDialog(QWidget* parent = nullptr);

private:
    // buildUi: Construct control tree and connect signals.
    void buildUi();
    // refreshPolicy: Read current configuration and counts in the background.
    void refreshPolicy();
    // startApply/startClear: Initiates a background configuration operation.
    void startApply();
    void startClear();
    // setBusy: Disable all action buttons while busy.
    void setBusy(bool busy);
    // updateEnabledState: refresh control availability based on write permissions and busy state.
    void updateEnabledState();
    // collectMasks: merges quick-check and manual input into the final mask.
    bool collectMasks(unsigned long long* cr0Out, unsigned long long* cr4Out);

    QCheckBox* pinWpCheck_ = nullptr;
    QCheckBox* pinSmepCheck_ = nullptr;
    QCheckBox* pinSmapCheck_ = nullptr;
    QCheckBox* pinUmipCheck_ = nullptr;
    QLineEdit* cr0MaskEdit_ = nullptr;
    QLineEdit* cr4MaskEdit_ = nullptr;
    QCheckBox* trackCr3Check_ = nullptr;
    QCheckBox* interceptDrCheck_ = nullptr;
    QCheckBox* logCheck_ = nullptr;
    QPushButton* applyButton_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* currentLabel_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    bool busy_ = false;
};

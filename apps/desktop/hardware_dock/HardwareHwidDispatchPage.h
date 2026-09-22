#pragma once

// ============================================================
// HardwareHwidDispatchPage.h
// Purpose:
// 1) Centralizes the dispatch function scheme for EASY-HWID-SPOOFER within the Hardware Dock.
// 2) Provide only the 'Modify Driver Dispatch Function (High Compatibility)' GUI entry and KswordARK IOCTL calls;
// 3) Display a blue screen risk warning upon entering the page; do not present physical memory modification options.
// ============================================================

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"

#include <QWidget>

class CodeEditorWidget;
class QCheckBox;
class QComboBox;
class QGridLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QShowEvent;
class QTableWidget;
class QVBoxLayout;

// HardwareHwidDispatchPage：
// - Input: Qt parent control;
// - Processing: Build the HWID Dispatch console, generate control requests, and issue them via ArkDriverClient;
// - Return behavior: The page class has no business return value; R0 responses are displayed in the table and logs.
class HardwareHwidDispatchPage final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent: Qt parent control;
    // - Processing: initialize UI, connect buttons, and generate initial schedule text.
    explicit HardwareHwidDispatchPage(QWidget* parent = nullptr);

protected:
    // showEvent：
    // - Input: Qt show event.
    // - Processing: Display a BSOD warning and refresh driver status upon first entry to the page.
    // - Returns: Nothing.
    void showEvent(QShowEvent* event) override;

private:
    // initializeUi：
    // - Creates title, scope description, Dispatch target, parameter form, action buttons, and status table.
    // - No input parameters;
    // - No return value.
    void initializeUi();

    // initializeConnections：
    // - Connect refresh, dry-run, enable, unload, and copy schedule buttons;
    // - No input parameters;
    // - No return value.
    void initializeConnections();

    // showBlueScreenWarningOnce：
    // - On first display, warn the user that operations on this page may cause a blue screen.
    // - No input parameters;
    // - No return value.
    void showBlueScreenWarningOnce();

    // refreshStatus：
    // - Calls IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY;
    // - No input parameters;
    // - No return value; results are written to the status table and log.
    void refreshStatus();

    // sendControlRequest：
    // - Input: action is the protocol action, dryRun indicates validation only without modification;
    // - Processing: Construct the request, perform a secondary confirmation if necessary, then invoke ArkDriverClient.
    // - No return value; results are written to the status table and log.
    void sendControlRequest(unsigned long action, bool dryRun);

    // buildControlRequest：
    // - Input: action and dryRun;
    // - Handling: Copy target, mode, and custom text from the UI form.
    // - Returns: Complete shared protocol request structure.
    KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST buildControlRequest(unsigned long action, bool dryRun) const;

    // selectedTargetFlags：
    // - Inputs: None;
    // - Processing: Read target checkboxes.
    // - Return: KSWORD_ARK_HWID_DISPATCH_TARGET_* bitmask.
    unsigned long selectedTargetFlags() const;

    // buildPlanText：
    // - Inputs: None;
    // - Processing: Convert current UI configuration into a copyable execution plan.
    // - Returns: Plan text.
    QString buildPlanText() const;

    // updatePlanPreview：
    // - Inputs: None;
    // - Processing: Refresh the read-only plan preview;
    // - No return value.
    void updatePlanPreview();

    // applyResponseToUi：
    // - Input: HWID Dispatch result from ArkDriverClient
    // - Processing: Refresh status label, target table, and log;
    // - No return value.
    void applyResponseToUi(const ksword::ark::HwidDispatchResult& result);

    // appendLogLine：
    // - Input: log line
    // - Processing: Append to page read-only log.
    // - No return value.
    void appendLogLine(const QString& lineText);

private:
    QVBoxLayout* rootLayout_ = nullptr;      // m_rootLayout: Page root layout.
    QLabel* statusLabel_ = nullptr;          // m_statusLabel: Top status summary.
    QCheckBox* diskCheck_ = nullptr;         // m_diskCheck: Target \\Driver\\Disk.
    QCheckBox* partMgrCheck_ = nullptr;      // m_partMgrCheck: Target \\Driver\\partmgr.
    QCheckBox* mountMgrCheck_ = nullptr;     // m_mountMgrCheck: \\Driver\\mountmgr target.
    QCheckBox* nvidiaCheck_ = nullptr;       // m_nvidiaCheck: Target \\Driver\\nvlddmkm.
    QCheckBox* nsiProxyCheck_ = nullptr;     // m_nsiProxyCheck: \\Driver\\nsiproxy target.
    QCheckBox* diskGuidCheck_ = nullptr;     // m_diskGuidCheck: GPT GUID randomization flag.
    QCheckBox* volumeCleanCheck_ = nullptr;  // m_volumeCleanCheck: MountMgr volume ID cleanup flag.
    QCheckBox* arpCleanCheck_ = nullptr;     // m_arpCleanCheck: ARP table cleanup flag.
    QComboBox* diskModeCombo_ = nullptr;     // m_diskModeCombo: Disk serial number mode.
    QComboBox* macModeCombo_ = nullptr;      // m_macModeCombo: MAC mode.
    QLineEdit* diskSerialEdit_ = nullptr;    // m_diskSerialEdit: Custom disk serial number.
    QLineEdit* diskProductEdit_ = nullptr;   // m_diskProductEdit: Custom disk product name.
    QLineEdit* diskRevisionEdit_ = nullptr;  // m_diskRevisionEdit: Custom disk firmware version.
    QLineEdit* gpuSerialEdit_ = nullptr;     // m_gpuSerialEdit: Custom GPU serial number.
    QLineEdit* permanentMacEdit_ = nullptr;  // m_permanentMacEdit: Permanent MAC address.
    QLineEdit* currentMacEdit_ = nullptr;    // m_currentMacEdit: Current MAC.
    QPushButton* refreshButton_ = nullptr;   // m_refreshButton: Query status button.
    QPushButton* dryRunButton_ = nullptr;    // m_dryRunButton: Dry-run verification button.
    QPushButton* enableButton_ = nullptr;    // m_enableButton: Enable Dispatch button.
    QPushButton* disableButton_ = nullptr;   // m_disableButton: Unload Dispatch button.
    QPushButton* copyPlanButton_ = nullptr;  // m_copyPlanButton: Copy plan button.
    QTableWidget* statusTable_ = nullptr;    // m_statusTable: Target driver status table.
    CodeEditorWidget* planEditor_ = nullptr; // m_planEditor: Read-only plan/log text.
    bool warningShown_ = false;              // m_warningShown: Indicates the first-time popup state.
};

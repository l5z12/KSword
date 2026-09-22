#pragma once

// ============================================================
// ServiceDock.h
// Purpose:
// 1) Provides an independent service management Dock page (located in ServerDock);
// 2) Display the Win32 service list with support for filtering, sorting, and status statistics.
// 3) Provide a structured detail page and common service control actions.
// ============================================================

#include "../Framework.h"

#include <QWidget>
#include <QStringList>

#include <atomic>   // std::atomic_bool: Background refresh status flag.
#include <cstdint>  // std::uint32_t: Numeric fields such as PID.
#include <memory>   // std::unique_ptr: Managed by a background thread.
#include <thread>   // std::thread: Service enumeration background thread.
#include <vector>   // std::vector: Service cache container.

#include <winsvc.h> // DWORD, SERVICE_*, and SC_ACTION_* constants and structures.

class QComboBox;
class QCheckBox;
class QPlainTextEdit;
class QRadioButton;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QToolButton;
class QTabWidget;
class QVBoxLayout;
class CodeEditorWidget;

class ServiceDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor purpose:
    // - initialize the ServiceDock UI.
    // - Bind interaction logic;
    // - Trigger asynchronous enumeration when the page is first displayed.
    // Parameter parent: Qt parent widget.
    explicit ServiceDock(QWidget* parent = nullptr);

    // Destructor purpose:
    // - Stop and reclaim background threads to prevent dangling access after window destruction.
    ~ServiceDock() override;

    // focusServiceByName:
    // - Locate and select the corresponding row by service name.
    // - Intended for cross-page navigation calls by StartupDock/mainWindow.
    // Parameter serviceNameText: Target service short name.
    void focusServiceByName(const QString& serviceNameText);

protected:
    // showEvent:
    // - Initiate the first service refresh when the page is displayed for the first time.
    // - Avoid blocking the main window startup with a full service enumeration.
    void showEvent(QShowEvent* event) override;

public:
    // ServiceColumn：
    // - Purpose: Unified service main table column indices to avoid hard-coded magic numbers.
    enum class ServiceColumn : int
    {
        kName = 0,      // Name: Service name.
        kDisplayName,   // DisplayName: Display name.
        kState,         // State: Running status text.
        kStartType,     // StartType: Start type text.
        kPid,           // PID: Associated PID.
        kAccount,       // Account: startup account.
        kRisk,          // Risk: Risk summary.
        kCount          // Count: Total number of columns.
    };

    // SortMode：
    // - Purpose: Define the main list sort mode.
    enum class SortMode : int
    {
        kNameAsc = 0,       // NameAsc: Sort by display name/service name in ascending order.
        kStatePriority,     // statePriority: Priority when running.
        kStartTypePriority  // startTypePriority: Automatic startup priority.
    };

    // ServiceEntry：
    // - Purpose: Uniformly hold a single service record.
    // - Reused by the main list, detail page, and action judgment.
    struct ServiceEntry
    {
        QString serviceNameText;      // serviceNameText: Service short name (unique key).
        QString displayNameText;      // displayNameText: Service display name.
        QString descriptionText;      // descriptionText: service description text.
        QString imagePathText;        // imagePathText: Extracted image path, if possible.
        QString commandLineText;      // commandLineText: Original BinaryPath.
        QString accountText;          // accountText: Service startup account.
        QString stateText;            // stateText: Running state text.
        QString startTypeText;        // startTypeText: Start type text.
        QString serviceTypeText;      // serviceTypeText: service type text.
        QString errorControlText;     // errorControlText: Error control text.
        QString serviceDllPathText;   // serviceDllPathText: Service DLL path (svchost-type services).
        QString sourceStatusText;     // sourceStatusText: Source status after cross-checking SCM and the registry.
        QString riskSummaryText;      // riskSummaryText: Risk summary text.
        QStringList riskTagList;      // riskTagList: List of risk tags.
        std::uint32_t processId = 0;  // processId: PID associated with the current service.
        DWORD currentState = 0;       // currentState：SERVICE_STATUS_PROCESS::dwCurrentState。
        DWORD controlsAccepted = 0;   // controlsAccepted: Current accepted control bit mask.
        DWORD startTypeValue = 0;     // startTypeValue: Original value of the configured start type.
        DWORD serviceTypeValue = 0;   // serviceTypeValue: Original value of the configured service type.
        DWORD errorControlValue = 0;  // errorControlValue: Raw value of the configured error control.
        bool delayedAutoStart = false; // delayedAutoStart: Whether to delay automatic startup.
        bool scmRecordPresent = false; // scmRecordPresent: Indicates whether this service was returned by the current EnumServicesStatusEx call.
        bool registryKeyPresent = false; // registryKeyPresent: Whether the registry key Services root has an item with the same name.
        bool registryScanCompleted = false; // registryScanCompleted: Whether the independent registry scan has completed.
        bool hasRisk = false;         // hasRisk: Whether at least one risk tag was matched.
    };

    // toServiceColumn:
    // - Convert column enum to int index.
    static int toServiceColumn(ServiceColumn column);

private:
    // ServiceRecoverySettings：
    // - Purpose: Cache editable configuration for the 'Recovery' page.
    // - Shared for reading Win32 configuration, populating the UI, and saving back to service configuration.
    struct ServiceRecoverySettings
    {
        SC_ACTION_TYPE firstActionType = SC_ACTION_NONE;    // firstActionType: The first failure action.
        SC_ACTION_TYPE secondActionType = SC_ACTION_NONE;   // secondActionType: The action type for the second failure.
        SC_ACTION_TYPE subsequentActionType = SC_ACTION_NONE; // subsequentActionType: Subsequent action on failure.
        int resetPeriodDays = 0;                            // resetPeriodDays: Number of days for resetting the failure count.
        int restartDelayMinutes = 1;                        // restartDelayMinutes: Delay in minutes before restarting the service.
        bool failureActionsFlag = false;                    // failureActionsFlag: Execute recovery even for non-crash failures.
        QString rebootMessageText;                          // rebootMessageText: System reboot prompt text.
        QString programPathText;                            // programPathText: Program path for restore operation.
        QString programArgumentsText;                       // programArgumentsText: Command-line arguments for the restore operation.
        bool appendFailureCount = false;                    // appendFailureCount: Whether to append /fail=%1%.
    };

    // ===================== Initialization =====================
    void initializeUi();
    void initializeToolbar();
    void initializeContent();
    void initializeDetailTabs();
    void initializeConnections();

    // ===================== Refresh and Enumeration =====================
    void requestAsyncRefresh(bool forceRefresh);
    void applyRefreshResult(std::vector<ServiceEntry> serviceList, const QString& errorText, bool success);
    void enumerateServiceList(std::vector<ServiceEntry>* serviceListOut, QString* errorTextOut) const;
    bool querySingleServiceByName(const QString& serviceNameText, ServiceEntry* entryOut, QString* errorTextOut) const;

    // ===================== List and Details =====================
    void rebuildServiceTable();
    bool entryMatchesCurrentFilter(const ServiceEntry& entry) const;
    bool serviceLessThan(const ServiceEntry& left, const ServiceEntry& right) const;
    void updateSummaryText();
    void syncToolbarStateWithSelection();
    void onServiceSelectionChanged();
    void updateDetailViewsFromSelection();
    QString buildAuditTabText(const ServiceEntry& entry) const;
    QString buildBasicInfoText(const ServiceEntry& entry) const;
    QString buildConfigInfoText(const ServiceEntry& entry) const;
    QString buildProcessLinkDetailText(const ServiceEntry& entry) const;
    QString buildRegistryFileDetailText(const ServiceEntry& entry) const;
    QString buildDependencyDetailText(const ServiceEntry& entry) const;
    QString buildFailureActionDetailText(const ServiceEntry& entry) const;
    QString buildTriggerDetailText(const ServiceEntry& entry) const;
    QString buildSecurityDetailText(const ServiceEntry& entry) const;
    QString buildRiskDetailText(const ServiceEntry& entry) const;
    QString buildExportDetailText(const ServiceEntry& entry) const;
    void initializeGeneralTab();
    void initializeLogonTab();
    void initializeRecoveryTab();
    void initializeDependencyTab();
    void initializeAuditTab();
    void refreshGeneralTabUiState();
    void refreshLogonTabUiState();
    void refreshRecoveryTabUiState();
    void populateGeneralTab(const ServiceEntry& entry);
    void populateLogonTab(const ServiceEntry& entry);
    void populateRecoveryTab(const ServiceEntry& entry);
    void populateDependencyTab(const ServiceEntry& entry);
    void populateAuditTab(const ServiceEntry& entry);
    void applyGeneralTabChanges();
    void applyLogonTabChanges();
    void applyRecoveryTabChanges();
    void browseLogonAccount();
    void browseRecoveryProgramPath();

    // ===================== Interaction and Actions =====================
    void showServiceContextMenu(const QPoint& localPos);
    void refreshSelectedService();
    void startSelectedService();
    void stopSelectedService();
    void pauseSelectedService();
    void continueSelectedService();
    void deleteSelectedService();
    void deleteSelectedServiceAndFile();
    void deleteSelectedServiceInternal(bool deleteBinaryFile);
    void applySelectedStartType();
    void copySelectedServiceName();
    void openSelectedServiceRegistryPath();
    void openSelectedBinaryLocation();
    void openSelectedServiceDllLocation();
    void openSelectedBinaryProperties();
    void jumpToSelectedProcessDetail();
    void jumpToSelectedHandleFilter();
    void jumpToFileDockBinaryDetail();
    void jumpToFileDockServiceDllDetail();
    void exportCurrentListAsTsv();
    void exportSelectedServiceAsJson();
    bool controlSelectedService(
        DWORD desiredAccess,
        const QString& actionText,
        DWORD controlCode,
        bool useStartService,
        DWORD expectedState,
        bool highRiskAction);

    // ===================== Utilities =====================
    QString selectedServiceName() const;
    int findServiceIndexByName(const QString& serviceNameText) const;
    void applyServiceUpdateToCache(const ServiceEntry& updatedEntry);
    QString queryServiceDllPathByName(const QString& serviceNameText) const;
    bool isServiceFilePresent(const QString& filePathText) const;
    bool queryServiceFailureSettings(
        const QString& serviceNameText,
        ServiceRecoverySettings* settingsOut,
        QString* errorTextOut) const;
    bool applyServiceFailureSettings(
        const QString& serviceNameText,
        const ServiceRecoverySettings& settings,
        QString* errorTextOut) const;

private:
    // ===================== Top-level Layout =====================
    QVBoxLayout* rootLayout_ = nullptr;      // m_rootLayout: Root layout.
    QWidget* toolbarWidget_ = nullptr;       // m_toolbarWidget: The top toolbar container.
    QHBoxLayout* toolbarLayout_ = nullptr;   // m_toolbarLayout: The top toolbar layout.
    QSplitter* contentSplitter_ = nullptr;   // m_contentSplitter: Container for left-right split panes.

    // ===================== Toolbar Controls =====================
    QToolButton* refreshAllButton_ = nullptr;      // m_refreshAllButton: Refresh all services button.
    QToolButton* refreshCurrentButton_ = nullptr;  // m_refreshCurrentButton: Refresh current service details.
    QToolButton* startButton_ = nullptr;           // m_startButton: Start service button.
    QToolButton* stopButton_ = nullptr;            // m_stopButton: Stop service.
    QToolButton* pauseButton_ = nullptr;           // m_pauseButton: Pause service.
    QToolButton* continueButton_ = nullptr;        // m_continueButton: Continue service.
    QToolButton* applyStartTypeButton_ = nullptr;  // m_applyStartTypeButton: Applies the modified start type.
    QToolButton* runningOnlyButton_ = nullptr;     // m_runningOnlyButton: Show only running items.
    QToolButton* autoStartOnlyButton_ = nullptr;   // m_autoStartOnlyButton: Show only auto-start.
    QToolButton* riskOnlyButton_ = nullptr;        // m_riskOnlyButton: Display only high-risk services.
    QLineEdit* filterEdit_ = nullptr;              // m_filterEdit: Keyword filter input box.
    QComboBox* sortCombo_ = nullptr;               // m_sortCombo: Sort mode selection box.
    QComboBox* startTypeCombo_ = nullptr;          // m_startTypeCombo: Startup type modification combo box.
    QLabel* summaryLabel_ = nullptr;               // m_summaryLabel: List statistics status bar.

    // ===================== Main List and Details =====================
    QTableWidget* serviceTable_ = nullptr;   // m_serviceTable: Main service list.
    QTabWidget* detailTabWidget_ = nullptr;  // m_detailTabWidget: Right-side detail page container.

    QWidget* generalTabPage_ = nullptr;              // m_generalTabPage: General properties page.
    QWidget* logonTabPage_ = nullptr;                // m_logonTabPage: Login property page.
    QWidget* recoveryTabPage_ = nullptr;             // m_recoveryTabPage: Recovery property page.
    QWidget* dependencyTabPage_ = nullptr;           // m_dependencyTabPage: Dependency tab page.
    QWidget* auditTabPage_ = nullptr;                // m_auditTabPage: Audit page.

    // General page control:
    // - Simulate the 'General' page layout of services.msc;
    // - Allow modification of display name, description, startup type, and delayed auto-start.
    QLineEdit* generalServiceNameEdit_ = nullptr;    // m_generalServiceNameEdit: Read-only service name field.
    QLineEdit* generalDisplayNameEdit_ = nullptr;    // m_generalDisplayNameEdit: Display name edit field.
    QLineEdit* generalBinaryPathEdit_ = nullptr;     // m_generalBinaryPathEdit: Image path read-only field.
    QPlainTextEdit* generalDescriptionEdit_ = nullptr; // m_generalDescriptionEdit: Description edit box.
    QComboBox* generalStartTypeCombo_ = nullptr;     // m_generalStartTypeCombo: Start type dropdown.
    QCheckBox* generalDelayedAutoCheck_ = nullptr;   // m_generalDelayedAutoCheck: Delayed auto-start checkbox.
    QLabel* generalStateValueLabel_ = nullptr;       // m_generalStateValueLabel: Current status label.
    QLabel* generalPidValueLabel_ = nullptr;         // m_generalPidValueLabel: PID label.
    QLabel* generalAccountValueLabel_ = nullptr;     // m_generalAccountValueLabel: Account label.
    QLabel* generalTypeValueLabel_ = nullptr;        // m_generalTypeValueLabel: Service type label.
    QLabel* generalErrorControlValueLabel_ = nullptr; // m_generalErrorControlValueLabel: Error control label.
    QToolButton* generalStartButton_ = nullptr;      // m_generalStartButton: Start button on the General page.
    QToolButton* generalStopButton_ = nullptr;       // m_generalStopButton: General page stop button.
    QToolButton* generalPauseButton_ = nullptr;      // m_generalPauseButton: Pause button on the General page.
    QToolButton* generalContinueButton_ = nullptr;   // m_generalContinueButton: General page Continue button.
    QToolButton* generalApplyButton_ = nullptr;      // m_generalApplyButton: Apply button on the General page.
    QToolButton* generalReloadButton_ = nullptr;     // m_generalReloadButton: General page reload button.

    // Login page control:
    // - Simulate the 'Log On' page layout of services.msc;
    // - Allow switching between LocalSystem and a specified account, and modify the interactive desktop flag.
    QRadioButton* logonLocalSystemRadio_ = nullptr;  // m_logonLocalSystemRadio: Radio button for the Local System account.
    QCheckBox* logonDesktopInteractCheck_ = nullptr; // m_logonDesktopInteractCheck: Allow interaction with the desktop.
    QRadioButton* logonAccountRadio_ = nullptr;      // m_logonAccountRadio: Radio button for this account.
    QLineEdit* logonAccountEdit_ = nullptr;          // m_logonAccountEdit: Edit box for the logon account.
    QLineEdit* logonPasswordEdit_ = nullptr;         // m_logonPasswordEdit: The password editor.
    QLineEdit* logonConfirmPasswordEdit_ = nullptr;  // m_logonConfirmPasswordEdit: Confirm password input field.
    QToolButton* logonBrowseButton_ = nullptr;       // m_logonBrowseButton: Browse account button.
    QToolButton* logonApplyButton_ = nullptr;        // m_logonApplyButton: Login page apply button.
    QToolButton* logonReloadButton_ = nullptr;       // m_logonReloadButton: Login page reload button.

    // Restore page controls:
    // - Simulate the 'Recovery' page layout of services.msc;
    // - Allows modifying the failure action, reset period, command, and failure action flag.
    QComboBox* recoveryFirstActionCombo_ = nullptr;  // m_recoveryFirstActionCombo: First failure action dropdown.
    QComboBox* recoverySecondActionCombo_ = nullptr; // m_recoverySecondActionCombo: Second failure action dropdown.
    QComboBox* recoverySubsequentActionCombo_ = nullptr; // m_recoverySubsequentActionCombo: Subsequent failure action dropdown.
    QSpinBox* recoveryResetDaysSpin_ = nullptr;      // m_recoveryResetDaysSpin: Number of days to reset the failure count.
    QSpinBox* recoveryRestartMinutesSpin_ = nullptr; // m_recoveryRestartMinutesSpin: Service restart delay in minutes.
    QCheckBox* recoveryFailureActionsFlagCheck_ = nullptr; // m_recoveryFailureActionsFlagCheck: Execute recovery even on error stop.
    QLineEdit* recoveryRebootMessageEdit_ = nullptr; // m_recoveryRebootMessageEdit: Reboot message edit box.
    QLineEdit* recoveryProgramEdit_ = nullptr;       // m_recoveryProgramEdit: Program path edit box.
    QLineEdit* recoveryArgumentsEdit_ = nullptr;     // m_recoveryArgumentsEdit: Arguments editor.
    QCheckBox* recoveryAppendFailCountCheck_ = nullptr; // m_recoveryAppendFailCountCheck: Whether to append /fail=%1%.
    QToolButton* recoveryBrowseProgramButton_ = nullptr; // m_recoveryBrowseProgramButton: Browse program button.
    QToolButton* recoveryApplyButton_ = nullptr;     // m_recoveryApplyButton: Apply button on the recovery page.
    QToolButton* recoveryReloadButton_ = nullptr;    // m_recoveryReloadButton: Recovery page reload button.

    // Dependency / Audit page control:
    // - Non-writable data continues to be displayed via the text editor.
    // - Satisfy the requirement that actionable items are not placed inside the text editor.
    CodeEditorWidget* dependencyEditor_ = nullptr;   // m_dependencyEditor: Dependency text editor (read-only).
    CodeEditorWidget* auditEditor_ = nullptr;        // m_auditEditor: Audit text editor (read-only).

    // ===================== Data and Status =====================
    std::vector<ServiceEntry> serviceList_;          // m_serviceList: Service cache list.
    std::atomic_bool refreshInProgress_{ false };    // m_refreshInProgress: Flag for background refresh in progress.
    std::atomic_bool refreshQueued_{ false };        // m_refreshQueued: Refresh queue flag.
    std::unique_ptr<std::thread> refreshThread_;     // m_refreshThread: Background enumeration of thread handles.
    bool initialRefreshDone_ = false;                // m_initialRefreshDone: Flag indicating whether the first lazy load is complete.
    int progressPid_ = 0;                            // m_progressPid: Current progress task PID.
    QString pendingFocusServiceName_;                // m_pendingFocusServiceName: Service name pending focus during cross-page navigation.
    bool detailUiSyncInProgress_ = false;            // m_detailUiSyncInProgress: Flag to block signals when backfilling the right-side property page.
};

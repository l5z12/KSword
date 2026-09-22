#pragma once

// ============================================================
// DriverDock.h
// Purpose:
// 1) Provides driver service enumeration and status viewing capabilities;
// 2) Provide capabilities for driver service registration, update, mount, unmount, and deletion;
// 3) Provide enumeration capability for loaded kernel modules;
// 4) Capture kernel DbgPrint/DbgPrintEx/KdPrintEx output via KswordARK R0 callback
// 5) Provide read-only diagnostic pages for DriverObject, DeviceObject, MajorFunction, and FastIo;
// 6) Provides Module Cross-View, Driver Integrity, and Unloaded/PiDDB evidence pages.
// ============================================================

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverClient.h"

#include <QPointer>
#include <QWidget>

#include <atomic>   // std::atomic_bool: Marks the debug capture thread's running state.
#include <cstdint>  // std::uint32_t/std::uint64_t: Status values and address values.
#include <memory>   // std::unique_ptr: Thread object management.
#include <string>   // std::string: Bridge for error text and log output.
#include <thread>   // std::thread: Background thread for capturing debug output.
#include <vector>   // std::vector: Container for driver service and module snapshots.

// Qt forward declaration: reduces header file compilation coupling.
class QCheckBox;
class QButtonGroup;
class QComboBox;
class CodeEditorWidget;
class QColor;
class QEvent;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QRadioButton;
class QShowEvent;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;
class KernelThreadAuditTab;

// DriverDock：
// - Main control for the driver page.
// - Contains three tabs: 'Overview', 'Operations', and 'Debug Output';
// - All driver management actions are implemented via SCM API.
class DriverDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize the UI, bind signals and slots, and perform the first refresh.
    // - Parameter parent: Pointer to the Qt parent widget.
    explicit DriverDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stop the debug capture thread and reclaim resources.
    ~DriverDock() override;

    // attachKswordSelfDriverPage：
    // - Input page: Container for 'Ksword self-driver' held by KernelDock;
    // - Input fallbackOwner: The original owner of the page to be reattached when DriverDock is destroyed;
    // Processing: Display dynamic offsets/driver status as the top-level Driver Dock page without duplicating business logic.
    // - Output: none; calling the same page repeatedly remains idempotent.
    void attachKswordSelfDriverPage(QWidget* page, QWidget* fallbackOwner);

protected:
    // showEvent：
    // - Perform driver service/module enumeration only upon first display.
    // - Avoid synchronous scanning of SCM and kernel modules during main window startup.
    void showEvent(QShowEvent* event) override;

    // changeEvent：
    // - Purpose: Redraw the DriverDock header after a language switch.
    // - Processing: Control text is updated via LanguageManager binding; table headers are rebuilt centrally by this class.
    // - Returns: Nothing.
    void changeEvent(QEvent* event) override;

private:
    // DriverServiceRecord：
    // - Purpose: Describes the display fields for a driver service record.
    struct DriverServiceRecord
    {
        QString serviceName;           // Service name (unique key, SCM primary key).
        QString displayName;           // Display name (may be null).
        QString binaryPath;            // Driver image path (ImagePath).
        QString description;           // Service description text (may be empty).
        std::uint32_t currentState = 0;// Current service status (SERVICE_* constant values).
        std::uint32_t startType = 0;   // Start type (BOOT/SYSTEM/AUTO/DEMAND/DISABLED).
        std::uint32_t errorControl = 0;// Error control level (IGNORE/NORMAL/SEVERE/CRITICAL).
        std::uint32_t serviceType = 0; // Service type (target should be SERVICE_KERNEL_DRIVER).
    };

    // LoadedKernelModuleRecord：
    // - Purpose: Describe a record of a loaded kernel module (driver image).
    struct LoadedKernelModuleRecord
    {
        QString moduleName;            // Module file name (e.g., xxx.sys).
        QString imagePath;             // Kernel-visible path (typically \SystemRoot\...).
        std::uint64_t baseAddress = 0; // Base address (displayed in hexadecimal).
    };

    enum class LoadedModuleSignatureState : std::uint32_t
    {
        kPending = 0U,
        kPathUnavailable,
        kInvalidTrust,
        kTrustedEmbedded,
        kTrustedCatalog
    };

    // LoadedModuleSignatureEvidence：
    // - Cache only signature semantics, error codes, and file identifiers that do not depend on the current language.
    // - UI thread generates tables, filter text, hints, and details based on the current language; no rescan needed when switching languages.
    struct LoadedModuleSignatureEvidence
    {
        LoadedModuleSignatureState state = LoadedModuleSignatureState::kPending;
        QString verificationPath;
        QString fileIdentifier;
        QString catalogPath;
        QString signerCertificateName;
        std::int32_t embeddedTrustStatus = 0;
        std::int32_t catalogTrustStatus = 0;
        std::uint32_t catalogLookupError = 0U;
        bool catalogAttempted = false;
        bool catalogTrustStatusAvailable = false;
    };

    // LoadedModuleEvidenceRecord：
    // - Purpose: Save R0 evidence aggregation results for a single loaded module;
    // - Data is used only for DriverDock display; no unload, removal, or repair actions are triggered.
    struct LoadedModuleEvidenceRecord
    {
        QString moduleName;            // moduleName: Name of the aggregated module.
        LoadedModuleSignatureEvidence signatureEvidence; // signatureEvidence: Language-agnostic embedded/catalog trust evidence.
        QString driverObjectName;      // driverObjectName: The DriverObject name successfully resolved.
        QString driverObjectStatusText;// driverObjectStatusText: Status display text for DriverObject query.
        QString driverStartMatchText;  // driverStartMatchText: text for comparing DriverStart with module base address.
        QString majorFunctionStatusText;// majorFunctionStatusText: MajorFunction jump summary.
        QString iatEatStatusText;      // iatEatStatusText: Summary of suspicious IAT/EAT entries.
        QString inlineHookStatusText;  // inlineHookStatusText: Summary of suspicious Inline Hook items.
        QString callbackStatusText;    // callbackStatusText: Callback reference summary.
        QString detailText;            // detailText: copyable evidence details in the details section.
        std::uint64_t driverObjectAddress = 0; // driverObjectAddress: Precise object address returned by read-only evidence query.
        std::uint64_t communicationRejectDispatchAddress = 0; // communicationRejectDispatchAddress: R0 system rejection entry point.
        bool queryAttempted = false;   // queryAttempted: Whether aggregation has been attempted.
        bool driverObjectResolved = false; // driverObjectResolved: Indicates whether the DriverObject was resolved successfully.
        bool driverStartKnown = false; // driverStartKnown: Whether DriverStart has a valid value.
        bool driverStartMatchesBase = false; // driverStartMatchesBase: Whether DriverStart equals the module base address.
        bool communicationStateKnown = false; // communicationStateKnown: Controls whether the QUERY returns a valid business state.
        bool communicationActive = false; // communicationActive: Whether there are still blind slots owned by this feature.
        bool communicationConflict = false; // communicationConflict: Sticky conflict caused by third-party modification.
        bool hasMajorFunctionExternalJump = false; // hasMajorFunctionExternalJump: Indicates whether a MajorFunction external jump exists.
        bool hasIatEatSuspicious = false; // hasIatEatSuspicious: Whether there are suspicious IAT/EAT entries.
        bool hasInlineHookSuspicious = false; // hasInlineHookSuspicious: whether there are suspicious Inline Hook items.
        bool hasCallbackReference = false; // hasCallbackReference: Whether a callback references this module.
        bool hasScanError = false;     // hasScanError: Whether an I/O/protocol/parsing error exists.
        std::uint32_t communicationActiveMask = 0; // communicationActiveMask: Slots currently rejected by the system from being taken over by the entry interface.
        std::uint32_t communicationOwnedMask = 0; // communicationOwnedMask: Slots currently held by this feature with recovery eligibility.
        std::uint32_t communicationConflictMask = 0; // communicationConflictMask: Sticky conflict slots that cannot be automatically recovered.
        std::uint32_t communicationGeneration = 0; // communicationGeneration: R0 generation record.
        std::uint32_t majorFunctionIntentionalBlindCount = 0; // majorFunctionIntentionalBlindCount: Number of intentional blind jumps caused by this feature.
        std::uint32_t majorFunctionExternalCount = 0; // majorFunctionExternalCount: Count of dispatched MajorFunction calls.
        std::uint32_t iatEatSuspiciousCount = 0; // iatEatSuspiciousCount: Count of suspicious IAT/EAT entries.
        std::uint32_t inlineHookSuspiciousCount = 0; // inlineHookSuspiciousCount: Count of suspicious Inline Hooks.
        std::uint32_t callbackReferenceCount = 0; // callbackReferenceCount: Number of callbacks referencing this module.
    };

    // DebugOutputLineRecord: Distinguishes localized prompts generated by the application from raw driver output.
    struct DebugOutputLineRecord
    {
        QString timePrefix;
        QString sourceText;
        QString localizedSuffixSource;
        bool translateSourceText = false;
    };

private:
    // ========================= UI Initialization =========================
    // initializeUi：
    // - Purpose: Constructs the Driver page's top-level layout and its three sub-tabs.
    void initializeUi();

    // initializeServiceTab：
    // - Purpose: Construct the 'Driver Services' page (SCM service list and service filtering).
    void initializeServiceTab();

    // initializeKernelModuleTab：
    // - Purpose: Construct the 'Kernel Modules' page (loaded modules and unified details editor).
    void initializeKernelModuleTab();

    // initializeOperateTab：
    // - Purpose: Builds the "Driver Operations" tab (register/mount/unload/delete).
    void initializeOperateTab();

    // initializeDebugOutputTab：
    // - Purpose: Builds the "Debug Output" tab (R0 callback control and output box).
    void initializeDebugOutputTab();

    // initializeObjectInfoTab：
    // - Build the Phase-9 'Object Information' page;
    // - Query DriverObject, MajorFunction, and DeviceObject chains via ArkDriverClient.
    void initializeObjectInfoTab();

    // initializeModuleCrossViewTab：
    // - Build the read-only Module Cross-View evidence page;
    // - Mainly displays evidence related to DriverObject, DriverSection, DeviceChain, and Service;
    // - Does not provide repair, patch, or arbitrary write buttons.
    void initializeModuleCrossViewTab();

    // initializeIntegrityTab：
    // - Build the 'Driver Integrity' page;
    // - Display DriverObject, MajorFunction, FastIo, LDR, and CPU entry evidence.
    // - Does not provide unloading, repair, or arbitrary write operations.
    void initializeIntegrityTab();

    // initializeUnloadedPiddbTab：
    // - Build 'Unloaded Drivers' tab based on issue screenshot.
    // Supports three sources: MmUnloadedDrivers, PiDDBCacheTable, and g_KernelHashBucketList.
    // - Query/filter/detail operations remain read-only; PiDDB sources provide strong confirmation for precise table entry management actions.
    void initializeUnloadedPiddbTab();

    // initializeSystemThreadTab：
    // - Build the 'System Threads' top-level page;
    // - Reuse the existing thread protocol between KernelThreadAuditTab and ArkDriverClient.
    void initializeSystemThreadTab();

    // initializeConnections：
    // - Purpose: Connects all control signals to business slot functions.
    void initializeConnections();

    // applyTranslatedHeaders: Rebuild column headers for all tables created in DriverDock according to the current language.
    void applyTranslatedHeaders();

    // ========================= Data Refresh =========================
    // refreshDriverServiceRecords：
    // - Purpose: Refresh driver service cache and rebuild the service table.
    void refreshDriverServiceRecords();

    // refreshLoadedKernelModuleRecords：
    // - Purpose: Refresh the loaded kernel module cache and rebuild the module table.
    void refreshLoadedKernelModuleRecords();

    // refreshLoadedModuleEvidenceAsync：
    // - Purpose: Aggregate module evidence using existing ArkDriverClient R0 query capabilities;
    // - Processing logic: Query DriverObject/Hook/Callback in a background thread, then update the UI;
    // - Return: None; results written to m_loadedModuleEvidenceCache.
    void refreshLoadedModuleEvidenceAsync();

    // rebuildLoadedModuleEvidenceViews：
    // - Purpose: Fill the module table and detail view with the current evidence cache.
    // - Logic: Update evidence columns line-by-line by source index and refresh details for the currently selected module;
    // - Returns: Nothing.
    void rebuildLoadedModuleEvidenceViews();

    // updateLoadedModuleEvidenceStatusText：
    // - Regenerate the aggregated summary based on cache semantics.
    // - No need to re-run R0/signature background scans when switching languages.
    void updateLoadedModuleEvidenceStatusText();

    // showSelectedModuleEvidenceDetail：
    // - Purpose: Display evidence details for the currently selected module.
    // - Processing logic: map from the table row to the evidence cache and populate the CodeEditorWidget;
    // - Returns: Nothing.
    void showSelectedModuleEvidenceDetail();

    // querySelectedDriverObjectInfo：
    // - Query the R0 DriverObject based on the \Driver\Name input from the object page.
    // - Execute in the background; upon completion, populate the base fields, MajorFunction table, and DeviceObject table.
    void querySelectedDriverObjectInfo();

    // applyDriverObjectQueryResult：
    // - Fill in Phase-9 DriverObject query results;
    // - Parameter result: Structured response parsed by ArkDriverClient.
    void applyDriverObjectQueryResult(const ksword::ark::DriverObjectQueryResult& result);

    // rebuildDriverObjectEvidenceViews：
    // - Purpose: Refresh the DriverObject / DriverExtension / FastIo sub-pages based on current DriverObject query results and integrity cache.
    // - Processing logic: perform only local table projection, do not re-access drivers;
    // - Returns: Nothing.
    void rebuildDriverObjectEvidenceViews();

    // fillObjectDriverNameFromSelection：
    // - Derives the \Driver\Name from the currently selected service name on the overview page.
    // - Facilitates direct object lookup after the user double-clicks a service.
    void fillObjectDriverNameFromSelection();

    // refreshDriverIntegrityAsync：
    // - Asynchronously call ArkDriverClient::queryDriverIntegrity / queryKernelCpuIntegrity.
    // - When the cpuOnly parameter is true, only CPU/IDT/MSR evidence is requested.
    // - Return: None. Results are written back to m_driverIntegrityCache.
    void refreshDriverIntegrityAsync(bool cpuOnly);

    // rebuildDriverIntegrityTable：
    // - Redraw integrity evidence table based on current cache and risk filtering;
    // - Do not re-access drivers;
    // - Returns: Nothing.
    void rebuildDriverIntegrityTable();

    // rebuildModuleCrossViewTable：
    // - Purpose: Redraw the Module Cross-View evidence table based on the current Driver Integrity cache.
    // - Processing logic: display only evidence from ModuleView, PsLoadedModules, DriverObject, DriverSection, DeviceChain, and Service.
    // - Returns: Nothing.
    void rebuildModuleCrossViewTable();

    // refreshUnloadedDriversAsync：
    // - Purpose: Asynchronously call ArkDriverClient to query the source of the currently selected unloaded driver.
    // - Handling logic: Triggered by source switch or refresh button; old ticket results do not overwrite new source results.
    // - Return: None; results are posted to the UI thread.
    void refreshUnloadedDriversAsync();

    // applyUnloadedDriverQueryResult：
    // - Input: Unified result with ArkDriverClient for the query ticket.
    // - Processing logic: Validate the ticket, update the cache/status, and repaint the filtered view.
    // - Returns: Nothing.
    void applyUnloadedDriverQueryResult(
        std::uint64_t ticket,
        ksword::ark::UnloadedDriverQueryResult result);

    // rebuildUnloadedPiddbTable：
    // - Purpose: Redraw the table using the current source cache, field combo box, keywords, and regex switches;
    // - Handling logic: perform local filtering only, do not re-access the driver;
    // - Returns: Nothing.
    void rebuildUnloadedPiddbTable();

    // selectedPiDdbEntryIdentity：
    // - Purpose: Convert the currently selected PiDDB entry row on the screenshot page into the precise identity required for the deletion protocol.
    // - Processing logic: simultaneously validates the current source, query status, cached index, and required fields;
    // - Returns: true only if the selected row can safely enter R0 pre-check.
    bool selectedPiDdbEntryIdentity(ksword::ark::PiDdbEntry* identity) const;

    // deleteSelectedPiDdbEntry：
    // - Purpose: Perform precise identity pre-check and strong confirmation deletion on the currently selected PiDDB row.
    // - Handling logic: Reuse R0 preflight, fixed-phrase confirmation, and re-lock verification after deletion.
    // - Return: None; upon success, the current PiDDB source is re-queried.
    void deleteSelectedPiDdbEntry();

    // showSelectedDriverIntegrityDetail：
    // - Display the detail text for the currently selected integrity evidence row;
    // - Processing logic: reads m_driverIntegrityCache via the cache index in the table's UserRole;
    // - Returns: Nothing.
    void showSelectedDriverIntegrityDetail();

    // showUnloadedPiddbContextMenu：
    // - Input: Local coordinates within the unloaded driver table;
    // - Processing logic: displays detail/copy/refresh menus; deletion or cleanup actions are not provided;
    // - Return: None; performs local UI operations after user selection.
    void showUnloadedPiddbContextMenu(const QPoint& localPosition);

    // showSelectedUnloadedPiddbDetailDialog：
    // - Input: None; reads the currently selected row in the unloaded driver table;
    // - Handling logic: expand the original source fields using cached indices and display them in a CodeEditorWidget popup.
    // - Return: None. No R0/R3 state is modified after the dialog closes.
    void showSelectedUnloadedPiddbDetailDialog();

    // copySelectedUnloadedPiddbRow：
    // - Input: None; reads the currently selected row in the table;
    // - Handling logic: Serialize visible columns to TSV and write to clipboard;
    // - Returns: Nothing.
    void copySelectedUnloadedPiddbRow();

    // copyVisibleUnloadedPiddbRows：
    // - Input: None; iterate through all visible rows after current filtering.
    // - Processing logic: Serialize the table header and all visible rows to TSV format and write them to the clipboard.
    // - Returns: Nothing.
    void copyVisibleUnloadedPiddbRows();

    // showServiceTableContextMenu：
    // - Show the operation context menu on right-click in the driver service list.
    // - Provides both SCM stop and forced unloading of the R0 DriverObject.
    void showServiceTableContextMenu(const QPoint& localPosition);

    // showModuleTableContextMenu：
    // - Pop up an operation menu on right-click in the loaded module list;
    // - Module evidence can still be refreshed/copied; R0 forced unload defaults to non-destructive cleanup flags.
    void showModuleTableContextMenu(const QPoint& localPosition);

    // querySelectedModuleKernelSignature：
    // - Call R0 signature evidence query using the module table path and base address.
    // - Results are written to the module evidence details section; WinTrust is not invoked.
    void querySelectedModuleKernelSignature();

    // dumpSelectedModuleMemory：
    // - Input: Module name, path, and base address snapshot captured before entering the right-click menu;
    // - R0 verifies the identity and image size of loaded modules.
    // - Asynchronously page-read kernel images; only commit the user-selected file via non-overwriting atomic rename upon full success.
    void dumpSelectedModuleMemory(
        const QString& moduleName,
        const QString& rawPath,
        std::uint64_t moduleBase);

    // stopDriverServiceFromServiceRow：
    // - Reads the SCM service name from the selected row in the service list and stops it via ControlService(SERVICE_CONTROL_STOP).
    // - Avoids forcibly unloading via R0 DriverObject to prevent unsafe removal of active drivers.
    void stopDriverServiceFromServiceRow(int rowIndex);

    // scUnloadAndCleanupDriver：
    // - Input: Immutable SCM service name and normalized driver path captured before opening the context menu;
    // - Strictly wait for SERVICE_STOPPED, then re-verify the configuration path and exclusive references after stopping.
    // - Delete driver files only after DeleteService succeeds; if any prerequisite fails, do not touch the registry or files.
    void scUnloadAndCleanupDriver(
        const QString& serviceName,
        const QString& normalizedBinaryPath);

    // forceUnloadDriverFromServiceRow：
    // - normalize the current service name to \Driver\Name and call ArkDriverClient;
    // - false: call DriverUnload directly; true: perform a fixed-order forced teardown of the DriverObject.
    void forceUnloadDriverFromServiceRow(int rowIndex, bool destructiveCleanup = false);

    // forceUnloadDriverFromModuleRow：
    // - Request R0 reverse lookup of DriverObject using the module base address and perform hierarchical forced unloading;
    // - When removeCallbacksFirst is true, request R0 to remove the verifiable callback after successful processing in DriverObject.
    // - Persistent neutralization or deletion of DeviceObject/ObMakeTemporaryObject is permitted only when destructiveCleanup is true.
    void forceUnloadDriverFromModuleRow(int rowIndex, bool removeCallbacksFirst = false, bool destructiveCleanup = false);

    // controlDriverCommunication：
    // - Use the module base address, canonical DriverObject, and object address copied before confirmation as the immutable target;
    // - When restoreCommunication is true, the rollback is executed according to R0 saved records.
    // - Does not re-read table rows that may be refreshed; operations are asynchronous and refresh module evidence upon completion.
    void controlDriverCommunication(
        std::uint64_t moduleBase,
        const QString& moduleName,
        const QString& driverObjectName,
        std::uint64_t expectedDriverObjectAddress,
        bool restoreCommunication);

    // queryDriverObjectForModuleEvidence：
    // - Purpose: Derive the DriverObject name from the module name and query R0 object diagnostics.
    // - Processing logic: Sequentially attempt \Driver, \FileSystem, and \FileSystem\Filters candidates.
    // - Returns: true indicates a DriverObject was resolved; false indicates no available object.
    static bool queryDriverObjectForModuleEvidence(
        const LoadedKernelModuleRecord& moduleRecord,
        ksword::ark::DriverObjectQueryResult& resultOut,
        QString& attemptedNamesTextOut);

    // collectEvidenceForLoadedModules：
    // - Purpose: Collect evidence for modules in a batch.
    // - Processing logic: reuse existing ArkDriverClient interfaces without adding new R0 protocols.
    // - Returns: one LoadedModuleEvidenceRecord per module.
    static std::vector<LoadedModuleEvidenceRecord> collectEvidenceForLoadedModules(
        const std::vector<LoadedKernelModuleRecord>& moduleRecords);

    // verifyLoadedModuleSignature：
    // - First verify embedded Authenticode, then fall back to catalog-only verification using the system Catalog.
    // - Mark as trusted only when both the full chain and whole-chain revocation succeed; offline/unknown remain invalid.
    static LoadedModuleSignatureEvidence verifyLoadedModuleSignature(
        const QString& rawImagePath);

    // buildPendingModuleEvidenceRecord：
    // - Purpose: Construct a placeholder record before evidence aggregation.
    // - Processing logic: Fill all evidence columns with 'Pending Scan' and explain the background query method in the details area.
    // - Returns: LoadedModuleEvidenceRecord placeholder object.
    static LoadedModuleEvidenceRecord buildPendingModuleEvidenceRecord(
        const LoadedKernelModuleRecord& moduleRecord);

    // moduleEvidenceStatusColor：
    // - Purpose: Select table foreground color based on evidence status.
    // - Processing logic: Suspicious items are red, parsing failures or references are orange, and normal items are green.
    // - Returns: QColor directly settable to a QBrush.
    static QColor moduleEvidenceStatusColor(const LoadedModuleEvidenceRecord& evidence);

    static bool moduleSignatureCheckAttempted(
        const LoadedModuleEvidenceRecord& evidence);
    static bool moduleSignatureTrusted(
        const LoadedModuleEvidenceRecord& evidence);
    static QString moduleSignatureStatusText(
        const LoadedModuleEvidenceRecord& evidence);
    static QString moduleSignatureDetailText(
        const LoadedModuleEvidenceRecord& evidence);
    static QString localizedModuleEvidenceText(const QString& sourceText);

    // rebuildDriverServiceTableByFilter：
    // - Purpose: Rebuild driver service table by filter keyword.
    void rebuildDriverServiceTableByFilter();

    // rebuildLoadedModuleTable：
    // - Purpose: Rebuild loaded module table by current cache.
    void rebuildLoadedModuleTable();

    // syncOperateFormBySelectedService：
    // - Purpose: Synchronize parameters of the selected service row to the operation form.
    void syncOperateFormBySelectedService();

    // refreshSelectedServiceStateToForm：
    // - Purpose: Query the SCM by the form service name and refresh the status log.
    void refreshSelectedServiceStateToForm();

    // ========================= Driver Operations =========================
    // registerOrUpdateDriverService：
    // - Purpose: Register a new driver service or update the configuration of an existing service.
    void registerOrUpdateDriverService();

    // loadSelectedDriverService：
    // - Purpose: Start (mount) the target driver service in the form.
    void loadSelectedDriverService();

    // unloadSelectedDriverService：
    // - Purpose: Stop (unload) the target driver service in the form.
    void unloadSelectedDriverService();

    // deleteSelectedDriverService：
    // - Purpose: Delete the target driver service from the form.
    void deleteSelectedDriverService();

    // ========================= Debug Output =========================
    // startDebugOutputCapture：
    // - Purpose: Start the R0 kernel debug output capture thread.
    void startDebugOutputCapture();

    // stopDebugOutputCapture：
    // - Purpose: Stop the R0 kernel debug output capture thread.
    void stopDebugOutputCapture();

    // runKernelDebugOutputCaptureLoop：
    // - Purpose: Thread function that incrementally reads the R0 ring buffer via ArkDriverClient.
    void runKernelDebugOutputCaptureLoop();

    // updateDebugCaptureButtonState：
    // - Purpose: Refresh the enabled state and tooltip text of the debug capture button.
    void updateDebugCaptureButtonState();

    // ========================= Output Utilities =========================
    // appendOperateLogLine：
    // - Purpose: Append a timestamped line to the 'Driver Operation Log' window.
    // - Parameter logText: The log text to append.
    void appendOperateLogLine(const QString& logText);

    // appendDebugOutputLine：
    // - Purpose: Append raw driver output; only the optional suffix participates in localization switching.
    void appendDebugOutputLine(
        const QString& debugText,
        const QString& localizedSuffixSource = QString());

    // appendLocalizedDebugOutputLine: Append application-generated prompts while preserving the canonical source text for hot switching.
    void appendLocalizedDebugOutputLine(const QString& sourceText);

    // refreshDebugOutputLines: rebuilds application prompts based on the current language; driver raw messages remain unchanged.
    void refreshDebugOutputLines();

    // clearDebugOutputLines: Synchronously clears the UI and the records used for re-translation.
    void clearDebugOutputLines();

    // ========================= Static Utility Functions =========================
    // queryDriverServiceRecords：
    // - Purpose: enumerate all driver services from SCM and populate the output container.
    // - Parameter recordListOut: Output service record list.
    // - Parameter errorTextOut: outputs error text on failure; may be null.
    // - Returns: true = success; false = failure.
    static bool queryDriverServiceRecords(
        std::vector<DriverServiceRecord>& recordListOut,
        std::string* errorTextOut = nullptr);

    // queryLoadedKernelModuleRecords：
    // - Purpose: enumerate currently loaded kernel modules and populate the output container.
    // - Parameter recordListOut: Output module record list.
    // - Parameter errorTextOut: outputs error text on failure; may be null.
    // - Returns: true = success; false = failure.
    static bool queryLoadedKernelModuleRecords(
        std::vector<LoadedKernelModuleRecord>& recordListOut,
        std::string* errorTextOut = nullptr);

    // serviceStateToText：
    // - Purpose: Convert the service state value to Chinese text.
    static QString serviceStateToText(std::uint32_t stateValue);

    // startTypeToText：
    // - Purpose: Convert the start type value to Chinese text.
    static QString startTypeToText(std::uint32_t startTypeValue);

    // errorControlToText：
    // - Purpose: Convert the error control value to Chinese text.
    static QString errorControlToText(std::uint32_t errorControlValue);

    // formatWin32ErrorText：
    // - Purpose: Format Win32 error codes as "decimal + text".
    static QString formatWin32ErrorText(std::uint32_t win32ErrorCode);

    // trimQuotedText：
    // - Purpose: Remove paired double quotes from the start and end of the path text.
    static QString trimQuotedText(const QString& textValue);

    // normalizeDriverBinaryPath：
    // - Purpose: normalize driver image paths (automatically add double quotes if necessary).
    static QString normalizeDriverBinaryPath(const QString& pathText);

private:
    // ========================= Top-level Layout =========================
    QVBoxLayout* rootLayout_ = nullptr; // Root layout.
    QTabWidget* tabWidget_ = nullptr;   // Child tab container.
    KernelThreadAuditTab* systemThreadAuditTab_ = nullptr; // System thread level-1 audit page.
    QWidget* kswordSelfDriverPage_ = nullptr; // Self-driver container migrated from KernelDock.
    QPointer<QWidget> kswordSelfDriverFallbackOwner_; // Reclaims ownership of the self-driver container during destruction.
    int kswordSelfDriverTabIndex_ = -1; // Index of the self-driver tab in DriverDock.

    // ========================= Tab 1: Driver Service =========================
    QWidget* servicePage_ = nullptr;                // Driver service page container.
    QVBoxLayout* serviceLayout_ = nullptr;          // Driver service page main layout.
    QWidget* overviewPage_ = nullptr;               // Alias container for the service page compatible with legacy layout states.
    QVBoxLayout* overviewLayout_ = nullptr;         // Main layout for the service page, compatible with pointers.
    QHBoxLayout* overviewToolLayout_ = nullptr;     // Service page toolbar layout.
    QLineEdit* serviceFilterEdit_ = nullptr;        // Service list filter input box.
    QPushButton* refreshServiceButton_ = nullptr;   // Refresh service button.
    QLabel* overviewStatusLabel_ = nullptr;         // Service page status label.
    QTableWidget* serviceTable_ = nullptr;          // Driver service table.

    // ========================= Tab 2: Kernel Modules =========================
    QWidget* kernelModulePage_ = nullptr;           // Kernel module page container.
    QVBoxLayout* kernelModuleLayout_ = nullptr;     // Kernel module page main layout.
    QHBoxLayout* kernelModuleToolLayout_ = nullptr; // Kernel module toolbar layout.
    QPushButton* refreshModuleButton_ = nullptr;    // Refresh module button.
    QPushButton* refreshModuleEvidenceButton_ = nullptr; // Button to refresh module evidence.
    QLineEdit* moduleFilterEdit_ = nullptr;         // Kernel module list filter input box.
    QTableWidget* moduleTable_ = nullptr;            // Loaded modules table.
    CodeEditorWidget* moduleEvidenceDetailEditor_ = nullptr; // Module evidence detail editor.
    QLabel* moduleEvidenceStatusLabel_ = nullptr;   // Module evidence aggregation status label.
    bool moduleEvidenceQuerying_ = false;           // Flag for background module evidence query.
    std::uint64_t moduleEvidenceQueryTicket_ = 0;   // Module evidence query ticket number.
    bool moduleDumpRunning_ = false;                // Module R0 Dump background task running flag.
    bool scCleanupRunning_ = false;                 // Flag indicating whether the SCM unload and file/service registry cleanup background task is running.

    // ========================= Tab 2: Driver Operations =========================
    QWidget* operatePage_ = nullptr;                 // Operation page container.
    QVBoxLayout* operateLayout_ = nullptr;           // Main layout of the operation page.
    QLineEdit* serviceNameEdit_ = nullptr;           // Service name input field.
    QLineEdit* displayNameEdit_ = nullptr;           // Display name input box.
    QLineEdit* binaryPathEdit_ = nullptr;            // Driver path input field.
    QLineEdit* descriptionEdit_ = nullptr;           // Service description input field.
    QComboBox* startTypeCombo_ = nullptr;            // Start type dropdown.
    QComboBox* errorControlCombo_ = nullptr;         // Error control combo box.
    QPushButton* browsePathButton_ = nullptr;        // Browse path button.
    QPushButton* registerOrUpdateButton_ = nullptr;  // Register/Update button.
    QPushButton* loadDriverButton_ = nullptr;        // Load button.
    QPushButton* unloadDriverButton_ = nullptr;      // Unload button.
    QPushButton* deleteServiceButton_ = nullptr;     // Delete service button.
    QPushButton* refreshStateButton_ = nullptr;      // Refresh status button.
    QPlainTextEdit* operateLogOutput_ = nullptr;     // Operation log output box.

    // ========================= Tab 3: Debug Output =========================
    QWidget* debugOutputPage_ = nullptr;             // Debug output page container.
    QVBoxLayout* debugOutputLayout_ = nullptr;       // Main layout for the debug output page.
    QHBoxLayout* debugToolLayout_ = nullptr;         // Debug output toolbar layout.
    QPushButton* startCaptureButton_ = nullptr;      // Start capture button.
    QPushButton* stopCaptureButton_ = nullptr;       // Stop capture button
    QPushButton* clearDebugOutputButton_ = nullptr;  // Clear output button.
    QPushButton* copyDebugOutputButton_ = nullptr;   // Copy output button.
    QLabel* debugCaptureStatusLabel_ = nullptr;      // Capture status label.
    QPlainTextEdit* debugOutputEdit_ = nullptr;      // Debug output text box.
    std::vector<DebugOutputLineRecord> debugOutputLines_; // Debug output raw records, retaining up to 2000 lines.

    // ========================= Tab 4: Object Information =========================
    QWidget* objectInfoPage_ = nullptr;              // Container for the object information page.
    QVBoxLayout* objectInfoLayout_ = nullptr;        // Main layout for the object info page.
    QHBoxLayout* objectInfoToolLayout_ = nullptr;    // Object information page toolbar layout.
    QLineEdit* objectDriverNameEdit_ = nullptr;      // \Driver\Name input box.
    QPushButton* fillObjectDriverNameButton_ = nullptr; // Button to populate from the selected service.
    QPushButton* queryObjectInfoButton_ = nullptr;   // R0 query button.
    QPushButton* objectEvidenceRefreshButton_ = nullptr; // Refresh the Driver/Integrity evidence button.
    QLabel* objectInfoStatusLabel_ = nullptr;        // Query status label.
    CodeEditorWidget* objectInfoSummaryEdit_ = nullptr;// DriverObject summary.
    QTabWidget* objectDetailTabWidget_ = nullptr;    // DriverObject detail tab container.
    QWidget* driverObjectPage_ = nullptr;            // DriverObject diagnostic page.
    QWidget* deviceObjectPage_ = nullptr;            // DeviceObject diagnostic page.
    QWidget* driverExtensionPage_ = nullptr;         // DriverExtension diagnostic page.
    QWidget* majorFunctionPage_ = nullptr;           // MajorFunction diagnostic page.
    QWidget* fastIoPage_ = nullptr;                  // FastIo diagnostic page.
    CodeEditorWidget* driverObjectPageSummaryEdit_ = nullptr; // DriverObject page summary.
    QTableWidget* driverObjectEvidenceTable_ = nullptr;      // DriverObject / DriverSection evidence table.
    QTableWidget* majorFunctionTable_ = nullptr;     // MajorFunction table.
    QTableWidget* deviceObjectTable_ = nullptr;      // DeviceObject/AttachedDevice table.
    QTableWidget* driverExtensionEvidenceTable_ = nullptr;   // DriverExtension / DeviceChain evidence table.
    QTableWidget* fastIoEvidenceTable_ = nullptr;             // FastIo evidence table.
    QLabel* driverExtensionStatusLabel_ = nullptr;   // DriverExtension page status label.
    QLabel* fastIoStatusLabel_ = nullptr;            // FastIo page status label.
    bool objectInfoQuerying_ = false;                // Query in-progress flag.
    std::uint64_t objectInfoQueryTicket_ = 0;        // Query sequence number.

    // ========================= Tab 5: Module Cross-View =========================
    QWidget* moduleCrossViewPage_ = nullptr;         // Module Cross-View page container.
    QVBoxLayout* moduleCrossViewLayout_ = nullptr;   // Module Cross-View main layout.
    QHBoxLayout* moduleCrossViewToolLayout_ = nullptr; // Module Cross-View toolbar layout.
    QPushButton* moduleCrossViewRefreshButton_ = nullptr; // Refresh button.
    QLabel* moduleCrossViewStatusLabel_ = nullptr;    // Status label.
    QTableWidget* moduleCrossViewTable_ = nullptr;    // Module Cross-View table.

    // ========================= Tab 5: Driver Integrity =========================
    QWidget* integrityPage_ = nullptr;               // Driver integrity page container.
    QVBoxLayout* integrityLayout_ = nullptr;         // Main layout for the integrity page.
    QHBoxLayout* integrityToolLayout_ = nullptr;     // Layout for the integrity tool toolbar.
    QLineEdit* integrityDriverNameEdit_ = nullptr;   // Optional \Driver\Name input field.
    QLineEdit* integrityModuleBaseEdit_ = nullptr;   // Optional module base address input field.
    QPushButton* integrityFillFromSelectionButton_ = nullptr; // Fill DriverObject name from current selection.
    QPushButton* integrityRefreshButton_ = nullptr;  // Query evidence from DriverObject, LDR, FastIo, and CPU.
    QPushButton* integrityCpuOnlyButton_ = nullptr;  // Query CPU entry evidence.
    QCheckBox* integrityRiskOnlyCheck_ = nullptr;    // Show risk items only.
    QSpinBox* integrityMaxRowsSpin_ = nullptr;       // Maximum number of rows to return.
    QLabel* integrityStatusLabel_ = nullptr;         // Query status label.
    QTableWidget* integrityTable_ = nullptr;         // Integrity evidence table.
    CodeEditorWidget* integrityDetailEdit_ = nullptr; // Integrity detail editor: read-only display of the original R0 details.
    bool integrityQuerying_ = false;                 // Flag during integrity query.
    std::uint64_t integrityQueryTicket_ = 0;         // Integrity query sequence number.

    // ========================= Tab 6: Unloaded Drivers =========================
    QWidget* unloadedPiddbPage_ = nullptr;           // Container for the unloaded drivers page.
    QVBoxLayout* unloadedPiddbLayout_ = nullptr;     // Layout for unloaded drivers.
    QHBoxLayout* unloadedPiddbSourceLayout_ = nullptr; // Three-source single-selection layout.
    QHBoxLayout* unloadedPiddbFilterLayout_ = nullptr; // Layout for fields, keywords, regex, and counts.
    QPushButton* unloadedPiddbRefreshButton_ = nullptr; // Refresh button for the current source.
    QPushButton* unloadedPiddbDeleteButton_ = nullptr; // Strong confirmation management button only when the exact PiDDB row is available.
    QButtonGroup* unloadedPiddbSourceGroup_ = nullptr; // Three-source mutual exclusion group.
    QRadioButton* unloadedPiddbMmSourceRadio_ = nullptr; // Source of MmUnloadedDrivers.
    QRadioButton* unloadedPiddbPiDdbSourceRadio_ = nullptr; // PiDDBCacheTable source.
    QRadioButton* unloadedPiddbCiSourceRadio_ = nullptr; // Source of g_KernelHashBucketList.
    QComboBox* unloadedPiddbFieldCombo_ = nullptr;   // Filter field combo box.
    QLineEdit* unloadedPiddbFilterEdit_ = nullptr;   // Keyword or regex input field.
    QCheckBox* unloadedPiddbRegexCheck_ = nullptr;   // Whether to use regular expressions.
    QLabel* unloadedPiddbCountLabel_ = nullptr;      // Current visible row count
    QLabel* unloadedPiddbStatusLabel_ = nullptr;     // Current source query status.
    QTableWidget* unloadedPiddbTable_ = nullptr;     // Six-column table for unloaded drivers.
    ksword::ark::UnloadedDriverQueryResult lastUnloadedDriverResult_; // Last queried metadata.
    std::vector<ksword::ark::UnloadedDriverEntry> unloadedDriverCache_; // Current source raw row
    bool unloadedDriverQuerying_ = false;            // Flag indicating that a background query is running.
    std::uint64_t unloadedDriverQueryTicket_ = 0;    // Source switch/query sequence number.

    // ========================= Data Cache =========================
    std::vector<DriverServiceRecord> driverServiceCache_;      // Driver service cache.
    std::vector<LoadedKernelModuleRecord> loadedModuleCache_;  // Loaded modules cache.
    std::vector<LoadedModuleEvidenceRecord> loadedModuleEvidenceCache_; // Module evidence cache.
    ksword::ark::DriverObjectQueryResult lastDriverObjectQueryResult_; // Cache of the most recent DriverObject query result.
    std::vector<ksword::ark::DriverIntegrityEvidenceEntry> driverIntegrityCache_; // Driver integrity evidence cache.
    ksword::ark::DriverIntegrityResult lastDriverIntegrityResult_; // Metadata from the most recent integrity check.
    bool hasDriverObjectQueryResult_ = false;          // Whether a DriverObject query result is available to fill back.
    bool initialRefreshDone_ = false;                          // Whether the first refresh was completed upon initial display.

    // ========================= Debug Capture Thread Status =========================
    std::atomic_bool kernelDebugCaptureRunning_{ false };   // R0 capture thread running flag.
    std::unique_ptr<std::thread> kernelDebugCaptureThread_; // R0 capture thread object.
};

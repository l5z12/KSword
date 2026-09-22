#pragma once

// ============================================================
// ProcessDetailWindow.h
// Purpose:
// - Provide an independent 'Process Details' window (not a Dock, non-blocking).
// - Each process can open an independent window containing tabs for details, threads, operations, modules, tokens, PEB, kernel callback tables, etc.
// - Support module refresh, right-click operations, DLL injection, and Shellcode injection capabilities.
// ============================================================

#include "../Framework.h"
#include "ProcessAffinityModel.h"

#include <QHash>
#include <QIcon>
#include <QPointer>
#include <QSet>
#include <QStringList>
#include <QWidget>

#include <cstdint>
#include <deque>
#include <string>
#include <vector>
#include "../../../shared/driver/KswordArkKeyboardIoctl.h"

#include "../../../shared/driver/KswordArkThreadIoctl.h"

// Forward declaration: reduce header dependencies and improve compilation speed.
class QCheckBox;
class QButtonGroup;
class QComboBox;
class QEvent;
class QFormLayout;
class QGroupBox;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QToolButton;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class QPoint;
class CodeEditorWidget;
class HandleDock;
class MemoryDock;
class NetworkDock;
class OtherDock;

class ProcessDetailWindow final : public QWidget
{
    Q_OBJECT

public:
    // Constructor purpose:
    // - Accepts a process base snapshot as initial window data;
    // - initialize all UI elements and interaction connections;
    // - Trigger the first asynchronous refresh of the startup module page.
    explicit ProcessDetailWindow(const ks::process::ProcessRecord& baseRecord, QWidget* parent = nullptr);

    // updateBaseRecord:
    // - Updates the window display using the latest external process snapshot;
    // - The window is not destroyed; only the display text and status are refreshed.
    void updateBaseRecord(const ks::process::ProcessRecord& baseRecord);

    // pid purpose: Returns the PID of the process bound to the current window.
    std::uint32_t pid() const;

    // identityKey: Returns a stable process identity composed of PID + creation time for exact matching against the active snapshot of the process list.
    std::string identityKey() const;

    // PerformanceHistorySample: A single-process performance sample delivered from the process list activity snapshot to the detail window.
    struct PerformanceHistorySample
    {
        std::int64_t unixMilliseconds = 0; // Sampling timestamp, for X-axis formatting.
        double cpuPercent = 0.0;           // CPU usage percentage.
        double cpuCorePercent = 0.0;       // CPU single-core equivalent percentage, which can exceed 100%.
        double memoryMB = 0.0;             // Working set memory in MB.
        double diskMBps = 0.0;             // Disk throughput in MB/s.
        double networkRxKBps = 0.0;        // Network download KB/s.
        double networkTxKBps = 0.0;        // Network upload KB/s.
        double gpuPercent = 0.0;           // GPU usage percentage.
    };

    // setPerformanceHistory: replaces the current performance history with the active snapshot from the existing process list, allowing new detail windows to immediately access historical data.
    void setPerformanceHistory(std::vector<PerformanceHistorySample> history);

    // appendPerformanceHistorySample: Appends a newly generated activity snapshot for the process list to avoid rebuilding the entire history sequence on every refresh.
    void appendPerformanceHistorySample(const PerformanceHistorySample& sample);

    // CpuCoreValue: CPU utilization of a logical processor within the current sampling interval.
    struct CpuCoreValue
    {
        std::uint32_t processorIndex = 0;
        std::uint16_t group = 0;
        std::uint16_t number = 0;
        double percent = 0.0;
        bool sampleReady = false;
    };

    // ThreadCpuCoreValue: Aggregated CPU usage for a single thread and per-logical-processor usage.
    struct ThreadCpuCoreValue
    {
        std::uint32_t threadId = 0;
        double cpuPercent = 0.0;
        std::vector<CpuCoreValue> cores;
    };

    // CpuCoreViewSample: Current process data filtered by ProcessDock from CSwitch ETW interval snapshots.
    struct CpuCoreViewSample
    {
        bool monitorRunning = false;
        bool sampleReady = false;
        bool dataLossDetected = false;
        std::uint64_t eventsLost = 0;
        std::uint64_t contextSwitchEvents = 0;
        QString diagnosticText;
        double processSystemPercent = 0.0;
        double processCoreEquivalentPercent = 0.0;
        std::vector<CpuCoreValue> processCores;
        std::vector<ThreadCpuCoreValue> threads;
    };

    // setCpuCoreViewSample: Update the 'CPU Cores' page; cache data only if the page has not been lazily loaded yet.
    void setCpuCoreViewSample(CpuCoreViewSample sample);

    // showHotkeyTabAndRefresh:
    // - Switch the details window to the 'Process Hotkey' tab;
    // - Reuse the existing hotkey scanning process in the detail page and trigger an asynchronous refresh;
    // - The caller typically originates from the right-click menu of the process list, used to expose deeply hidden hotkey functionality as a one-click entry.
    // Parameters: None.
    // Returns: Nothing.
    void showHotkeyTabAndRefresh();

    // showActionTab:
    // - Switch the detail window to the 'Actions' tab.
    // - Allows direct navigation from the process list context menu to the DLL/Shellcode injection area.
    // Parameters: None.
    // Returns: Nothing.
    void showActionTab();

signals:
    // requestOpenProcessByPid:
    // - Emitted when the 'Go to Parent Process' button is clicked;
    // - ProcessDock uniformly receives the request and opens the corresponding process detail window.
    void requestOpenProcessByPid(std::uint32_t pid);

    // requestOpenHandleDockByPid:
    // - Triggered when the 'Jump to Handle' button is clicked;
    // - Forwarded by ProcessDock to mainWindow to open the Handle Dock and filter by PID.
    void requestOpenHandleDockByPid(std::uint32_t pid);
    void requestOpenMemoryDockByPid(std::uint32_t pid);
    void requestOpenNetworkDockByPid(std::uint32_t pid);
    void requestOpenWindowDockByPid(std::uint32_t pid);
    // requestOpenFileDetailByPath: Passes the current image path to the main window's FileDock to reuse the existing file detail window.
    void requestOpenFileDetailByPath(const QString& filePath);

private:
    // ModuleRefreshResult: Data structure for the background refresh result of the module page.
    struct ModuleRefreshResult
    {
        ks::process::ProcessModuleSnapshot moduleSnapshot; // Module + thread snapshot.
        std::uint64_t elapsedMs = 0;                       // Background refresh duration (ms).
        bool includeSignatureCheck = false;                // Whether to perform signature verification in this round.
    };

    // ThreadInspectItem: Single-row data for the thread details page.
    struct ThreadInspectItem
    {
        std::uint32_t threadId = 0;        // Thread ID.
        std::uint32_t processId = 0;       // Associated process PID.
        QString stateText;                 // Status text (Running/Ended/Unknown).
        int priorityValue = 0;             // Thread priority value.
        quint64 switchCount = 0;           // Context switch count (current implementation may be 0).
        QString startAddressText;          // Thread start address (hexadecimal).
        QString tebAddressText;            // Thread TEB address (hexadecimal).
        QString affinityText;              // Thread affinity text.
        QString registerSummaryText;       // Register summary text.
        std::uint64_t startAddress = 0;    // Original value of the start address.
        std::uint64_t win32StartAddress = 0; // Original value of Win32StartAddress.
        std::uint64_t createTime100ns = 0; // Creation time; repeated use of the identity field for dangerous driver thread actions.
        std::uint64_t tebAddress = 0;      // Original TEB address value.
        std::uint64_t userStackBase = 0;   // User stack base address.
        std::uint64_t userStackLimit = 0;  // User stack boundary.
        std::uint64_t r0KernelStack = 0;   // KTHREAD.KernelStack。
        std::uint64_t r0StackBase = 0;     // KTHREAD.StackBase。
        std::uint64_t r0StackLimit = 0;    // KTHREAD.StackLimit。
        std::uint64_t r0InitialStack = 0;  // KTHREAD.InitialStack。
        std::uint32_t r0ThreadStatus = KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE; // R0 thread status.
        std::uint64_t r0CapabilityMask = 0; // R0 capability。
        QString r0RuntimeDetailText;       // R0 runtime details readable summary.
        std::uint32_t r0DetailStatus = KSWORD_ARK_DETAIL_STATUS_UNKNOWN; // detail IOCTL overall status.
        std::uint32_t r0DetailFieldFlags = 0; // Actual field bitmap returned by the detail IOCTL.
        std::uint64_t r0MissingCapabilityMask = 0; // detail IOCTL missing capability bitmap.
        long r0DetailLastStatus = 0;        // detail IOCTL: Most recent NTSTATUS.
        std::uint64_t r0ReadOperationCount = 0; // KTHREAD read operation count.
        std::uint64_t r0WriteOperationCount = 0; // KTHREAD write operation count.
        std::uint64_t r0OtherOperationCount = 0; // KTHREAD other operation counts.
        std::uint64_t r0ReadTransferCount = 0; // KTHREAD read transfer bytes.
        std::uint64_t r0WriteTransferCount = 0; // KTHREAD write transfer bytes.
        std::uint64_t r0OtherTransferCount = 0; // KTHREAD other transfer bytes.
    };

    // ThreadInspectRefreshResult: asynchronous refresh result for thread details.
    struct ThreadInspectRefreshResult
    {
        std::vector<ThreadInspectItem> rows; // Thread row data.
        QString diagnosticText;              // Diagnostic text.
        std::uint64_t elapsedMs = 0;         // Refresh duration (milliseconds).
    };

    // TextRefreshResult: Refresh result for token page/PEB page text.
    struct TextRefreshResult
    {
        QString detailText;               // Display text content.
        QString diagnosticText;           // Diagnostic text.
        std::uint64_t elapsedMs = 0;      // Refresh duration (milliseconds).
    };

    // KernelCallbackInspectItem: A single user-mode callback entry in PEB.KernelCallbackTable.
    struct KernelCallbackInspectItem
    {
        std::uint32_t index = 0;          // Callback table index.
        QString callbackName;             // Expose KERNEL_CALLBACK_TABLE field names.
        QString addressText;              // Current remote callback address.
        QString moduleText;               // Module name to which the address belongs; empty if not found.
        QString modulePath;               // Full path of the module owning the address, for tooltip display.
        QString moduleOffsetText;         // callback - moduleBase。
        QString protectionText;           // Page protection attributes returned by VirtualQueryEx.
        QString statusText;               // Audit status for normal/empty/non-module executable memory, etc.
        bool suspicious = false;          // Use warning color in the table when true.
    };

    // KernelCallbackRefreshResult: asynchronous read result of a page in the kernel callback table.
    struct KernelCallbackRefreshResult
    {
        std::vector<KernelCallbackInspectItem> rows; // Callback entries within the valid table length.
        QString pebKindText;                        // NativePEB / Wow64PEB。
        QString pebAddressText;                     // PEB address read in this iteration.
        QString tableAddressText;                   // Address of the KernelCallbackTable.
        QString diagnosticText;                     // Diagnosis of permissions, boundaries, or module enumeration.
        std::uint64_t elapsedMs = 0;                // Refresh duration (milliseconds).
    };

    // SectionRefreshResult: Asynchronous query result for Process SectionObject / ControlArea.
    struct SectionRefreshResult
    {
        QString detailText;              // Display text content.
        QString diagnosticText;          // Diagnostic text.
        std::uint64_t elapsedMs = 0;     // Refresh duration (milliseconds).
    };

    // HotkeyInspectItem: Single-line data for the process hotkey page.
    struct HotkeyInspectItem
    {
        QString objectText;              // HWND/HMENU/resources/shortcut paths.
        std::uint32_t hotkeyId = 0;      // Menu command ID / Accelerator command ID / 0.
        std::uint32_t modifiers = 0;     // MOD_ALT/MOD_CONTROL/MOD_SHIFT/MOD_WIN bitmap.
        std::uint32_t virtualKey = 0;    // Virtual key code; 0 if unknown.
        QString hotkeyText;              // Readable hotkey text.
        std::uint32_t processId = 0;     // Associated process ID.
        std::uint32_t threadId = 0;      // ID of the owning window thread; 0 if not from a window.
        QString processName;             // Name of the owning process.
        QString sourceText;              // Source: Window hotkeys, menus, Accelerators, .lnk files, etc.
        QString detailText;              // Additional context.
        bool hasR0MutationSnapshot = false; // Whether a complete R0 tagHOTKEY snapshot ready for submission is included.
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0MutationSnapshot{}; // Expected value snapshot for edit/delete operations.
    };

    // HotkeyInspectRefreshResult: Asynchronous refresh result for process hotkeys.
    struct HotkeyInspectRefreshResult
    {
        std::vector<HotkeyInspectItem> rows; // Hotkey row data.
        QString diagnosticText;              // Diagnostic text.
        std::uint64_t elapsedMs = 0;         // Refresh duration (milliseconds).
    };

    // KeyboardHookInspectItem: Data for a row in the keyboard page hook form.
    struct KeyboardHookInspectItem
    {
        QString objectText;       // tagHOOK object address.
        QString typeText;         // WH_KEYBOARD / WH_KEYBOARD_LL。
        QString scopeText;        // Thread chain / global chain.
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString procedureText;    // Callback address or R0-stored callback offset.
        QString moduleText;       // Module base address or module ID.
        QString sourceText;       // Source chain.
        QString flagsText;        // tagHOOK flags。
        QString detailText;       // Diagnostic fields such as head, next, and threadInfo.
    };

    // KeyboardInspectRefreshResult: Asynchronous refresh result for the keyboard page.
    struct KeyboardInspectRefreshResult
    {
        std::vector<HotkeyInspectItem> hotkeyRows;     // Hotkey row data.
        std::vector<KeyboardHookInspectItem> hookRows; // Hook row data.
        QString diagnosticText;                        // Diagnostic text.
        std::uint64_t elapsedMs = 0;                   // Refresh duration (milliseconds).
    };

    // StaticDetailRefreshResult: Result of background completion for process static details.
    struct StaticDetailRefreshResult
    {
        ks::process::ProcessRecord processRecord; // Latest process record read in the background.
        QString diagnosticText;                   // Failure or downgrade reason.
        std::uint64_t elapsedMs = 0;              // Background query duration (ms).
        bool queryOk = false;                     // true indicates successful reading of basic static details.
    };

    // DetailOverviewRefreshResult: Runtime/security/GUI data background snapshot for the details page.
    // values use stable key names to prevent result structure expansion when UI control count increases.
    struct DetailOverviewRefreshResult
    {
        std::string identityKey;             // PID + creation time, used to reject stale results after PID reuse.
        QHash<QString, QString> values;      // Display text for each detailed field.
        QString diagnosticText;              // Diagnostic information such as insufficient permissions or target exit.
        std::uint64_t elapsedMs = 0;         // Background query duration (ms).
        bool queryOk = false;                // At least one runtime field must be successfully read.
    };

    // ActionPrivilegeRefreshResult: Background query result for operation page token privileges.
    struct ActionPrivilegeRefreshResult
    {
        std::string identityKey;                              // PID + creation time; rejects old results after PID reuse.
        std::vector<ks::process::TokenPrivilegeInfo> privileges; // Windows SDK full privilege directory status.
        QString diagnosticText;                              // R3/R0 query failure diagnostic.
        std::uint64_t ticket = 0;                            // Prevents out-of-order asynchronous results from overwriting each other.
        bool queryOk = false;                                // Whether the target token was successfully read.
        bool usedR0 = false;                                 // true indicates completion by R0 after R3 failure.
    };

private:
    // ======== UI Initialization
    // ======== changeEvent purpose:
    // - Listen for palette/style changes;
    // - Rebuild internal styles after switching between light and dark themes to avoid residual white backgrounds in the process detail view.
    // Invocation method: Triggered automatically by Qt.
    // Parameter event: The change event object.
    // Returns: Nothing.
    void changeEvent(QEvent* event) override;

    void initializeUi();
    // applyThemeStyle:
    // - Apply consistent light/dark theme styles to internal controls of the detail window.
    // - Explicitly forces Window/Base colors to avoid Win11 automatic background takeover issues.
    // Call method: Called after initializeUi completes control creation; called again in changeEvent.
    // Parameters: None.
    // Returns: Nothing.
    void applyThemeStyle();
    void initializeDetailTab();
    // initializePerformanceTab: Creates the performance history page with charts drawn horizontally and scrollable content arranged vertically.
    void initializePerformanceTab();
    void initializeCpuCoreTab();
    void initializeThreadTab();
    void initializeActionTab();
    void initializeModuleTab();
    // initializeEmbeddedHandleTab: Creates an on-demand handle audit container for the current process.
    void initializeEmbeddedHandleTab();
    // ensureEmbeddedHandleView: Creates the HandleDock and locks the current PID when entering the Handle page for the first time.
    void ensureEmbeddedHandleView();
    // initializeEmbeddedMemoryTab purpose: Creates a lazy container for streamlined memory analysis.
    void initializeEmbeddedMemoryTab();
    void ensureEmbeddedMemoryView();
    // initializeEmbeddedNetworkTab: Creates a lazy container for network connections filtered by the current PID.
    void initializeEmbeddedNetworkTab();
    void ensureEmbeddedNetworkView();
    // initializeSoundSourceTab：
    // - Purpose: Reuse the sound source tab and lock the current process PID.
    // - Invocation: Called by ensureTabContentInitialized when the user first enters the "Sound Source" tab.
    // - Input/Return: Target PID from m_baseRecord; no return value.
    void initializeSoundSourceTab();
    // initializeEmbeddedWindowTab purpose: Create a lazy container for the window list filtered by the current PID.
    void initializeEmbeddedWindowTab();
    void ensureEmbeddedWindowView();
    void initializeTokenTab();
    // initializeKernelObjectTab:
    // - Build the Process Detail Evidence page;
    // - Display R0 extended fields, DynData capability, field source, and availability.
    // - Only shows ObjectTable/SectionObject availability; does not directly enumerate the handle table or Section on this page.
    // Call method: Call after creating m_kernelObjectTab in initializeUi.
    // Parameters: None.
    // Returns: Nothing.
    void initializeKernelObjectTab();
    // initializeHotkeyTab:
    // - Build the 'Process Hotkey' page;
    // - Overrides window activation hotkeys, menu shortcuts, PE Accelerator resources, and .lnk shortcut hotkeys.
    // Invocation: Called after m_hotkeyTab is created in initializeUi.
    // Parameters: None.
    // Returns: Nothing.
    void initializeHotkeyTab();
    // initializeKeyboardTab:
    // - Build the 'Keyboard' page;
    // - Simultaneously display hotkey detection results and R0 keyboard hook chain enumeration results.
    // Usage: Call after creating m_keyboardTab within initializeUi.
    // Parameters: None.
    // Returns: Nothing.
    void initializeKeyboardTab();
    // initializePluginTab:
    // - Build independent plugin entry points for the current process;
    // - The menu dynamically rebuilds by scanning plugin\<id>\plugin.json; the details window does not load plugin code.
    void initializePluginTab();
    // initializeTokenSwitchTab:
    // - Build the 'Token Switch' page;
    // - Provides checkboxes for batch control of Token switch bits, along with Refresh and Apply buttons.
    // Call method: invoked after creating m_tokenSwitchTab in initializeUi.
    // Parameters: None.
    // Returns: Nothing.
    void initializeTokenSwitchTab();
    void initializePebTab();
    // initializeKernelCallbackTab:
    // - Builds an independent audit page for PEB.KernelCallbackTable;
    // - Table displays callback names, addresses, module offsets, memory protection, and exception states.
    void initializeKernelCallbackTab();
    // ensureTabContentInitialized purpose: Construct page controls only when the user first accesses the page, avoiding synchronous creation of all functional pages during window opening.
    void ensureTabContentInitialized(QWidget* tab);
    void initializeConnections();

    // ======== Detail Page Refresh ========
    void refreshDetailTabTexts();
    void refreshPerformanceHistoryCharts();
    void refreshCpuCoreView();
    // requestAsyncStaticDetailRefresh:
    // - Asynchronously populate slow fields in the background, such as path, command line, user, and signature.
    // - Avoid blocking the UI thread during window construction or periodic synchronization.
    // Invocation: call after construction when external snapshot fields are incomplete.
    // Parameter includeSignatureCheck: true indicates that WinVerifyTrust signature verification is allowed in the background.
    // Returns: Nothing.
    void requestAsyncStaticDetailRefresh(bool includeSignatureCheck);
    // applyStaticDetailRefreshResult:
    // - Merge background static detail results on the main thread;
    // - Only use non-null/valid fields to overwrite the current cache.
    // Invocation: Dispatched after the background task of requestAsyncStaticDetailRefresh completes.
    // Parameter refreshResult: Background query result.
    // Returns: Nothing.
    void applyStaticDetailRefreshResult(const StaticDetailRefreshResult& refreshResult);
    // requestAsyncDetailOverviewRefresh purpose: asynchronously reads resource, security, mitigation policy, and GUI statistics for the detail page in the background.
    void requestAsyncDetailOverviewRefresh();
    // applyDetailOverviewRefreshResult: After verifying identity, populate the runtime fields on the detail page.
    void applyDetailOverviewRefreshResult(const DetailOverviewRefreshResult& refreshResult);
    // requestAsyncActionPrivilegeRefresh purpose: Query all operation page token privileges in the background; allow R0 fallback if R3 fails.
    void requestAsyncActionPrivilegeRefresh();
    // applyActionPrivilegeRefreshResult: Updates checkboxes and buttons based on privilege status on the UI thread.
    void applyActionPrivilegeRefreshResult(const ActionPrivilegeRefreshResult& refreshResult);
    // requestInitialRefreshForCurrentTab:
    // - Lazy-initialize the first heavy refresh for the current tab;
    // - Upon opening the window, only the 'Details' tab is displayed; module/PEB/token scanning is not performed immediately.
    // Invocation: called on currentChanged signal and after construction.
    // Parameters: None.
    // Returns: Nothing.
    void requestInitialRefreshForCurrentTab();
    // refreshKernelObjectTabTexts:
    // - Refresh all tabs on the 'Process Detail Evidence' page based on m_baseRecord;
    // - Display 'Unavailable' when DynData is missed to avoid misleading users into directly accessing subsequent handle/section enumeration.
    // Call method: Indirectly called by refreshDetailTabTexts and updateBaseRecord.
    // Parameters: None.
    // Returns: Nothing.
    void refreshKernelObjectTabTexts();
    void refreshParentProcessSection();
    void updateWindowTitle();
    void requestAsyncThreadInspectRefresh();
    void applyThreadInspectResult(const ThreadInspectRefreshResult& refreshResult);
    void updateThreadInspectStatusLabel(const QString& statusText, bool refreshing);
    // requestAsyncSelectedThreadRuntimeSample:
    // - Perform PDB deep runtime small-field sampling on the currently selected TID in the thread table.
    // - Only pass TID/PID and JSON offset/size; do not pass ETHREAD address as input;
    // - Execute in the background to avoid blocking the UI thread due to old drivers or excessive fields.
    // Call context: triggered by the "Sample PDB Field" button on the Threads tab.
    // Parameters: None.
    // Returns: Nothing.
    void requestAsyncSelectedThreadRuntimeSample();
    // openSelectedThreadStackWindow:
    // - Open the Phase-8 call stack window based on the currently selected row in the thread page;
    // - Purpose: Construct the target using the TID, PID, and stack boundaries from the most recent thread refresh cache.
    // Invocation method: thread page button or table double-click.
    // Parameters: None.
    // Returns: Nothing.
    void openSelectedThreadStackWindow();
    // resolveSelectedThreadModulePathForUpload:
    // - Input is the current row in the thread table;
    // - Processing: read the start/win32Start address from ThreadInspectItem and look up the corresponding module path in the module cache.
    // - Return: On hit, returns the module file path; on miss, returns an empty string and writes the reason to errorTextOut.
    QString resolveSelectedThreadModulePathForUpload(QString* errorTextOut) const;

    // ======== Token page / PEB page refresh ========
    void requestAsyncTokenRefresh();
    void requestAsyncPebRefresh();
    void applyTokenRefreshResult(const TextRefreshResult& refreshResult);
    void applyPebRefreshResult(const TextRefreshResult& refreshResult);
    // requestAsyncKernelCallbackRefresh: Background read of the Native/Wow64 PEB's KernelCallbackTable.
    void requestAsyncKernelCallbackRefresh();
    // Purpose of applyKernelCallbackRefreshResult: populate the kernel callback table audit results on the UI thread.
    void applyKernelCallbackRefreshResult(const KernelCallbackRefreshResult& refreshResult);
    // rebuildKernelCallbackTable purpose: Rebuilds the callback table based on the most recent cache.
    void rebuildKernelCallbackTable();
    // requestAsyncHotkeyRefresh:
    // - Background scan for the source of hotkeys related to the current process;
    // - Does not directly access the driver and does not block the detail window UI thread.
    // Invocation: On initial hotkey page load or when clicking the refresh button.
    // Parameters: None.
    // Returns: Nothing.
    void requestAsyncHotkeyRefresh();
    // applyHotkeyRefreshResult:
    // - Fill back hotkey inspection results on the main thread;
    // - Rebuild the table and update the status label.
    // Usage: requestAsyncHotkeyRefresh posts the result after the background task completes.
    // Parameter refreshResult: background scan result.
    // Returns: Nothing.
    void applyHotkeyRefreshResult(const HotkeyInspectRefreshResult& refreshResult);
    // editSelectedHotkey: Validates the currently selected source and writes the window or .lnk hotkey via a stable public interface.
    // deleteSelectedHotkey: deletes the selected public interface hotkey or the R0 RegisterHotKey item protected by snapshots.
    void deleteSelectedHotkey();
    void editSelectedHotkey();
    void rebuildHotkeyTable();
    void updateHotkeyStatusLabel(const QString& statusText, bool refreshing);
    void requestAsyncKeyboardRefresh();
    void applyKeyboardRefreshResult(const KeyboardInspectRefreshResult& refreshResult);
    void rebuildKeyboardHotkeyTable();
    void rebuildKeyboardHookTable();
    void updateKeyboardStatusLabel(const QString& statusText, bool refreshing);
    // requestAsyncSectionRefresh:
    // - Asynchronously query R0 SectionObject / ControlArea via ArkDriverClient;
    // - Only pass the PID; do not return the kernel address visible in the UI to the driver.
    // Invocation: call on the kernel object page refresh button or after initial initialization.
    // Parameters: None.
    // Returns: Nothing.
    void requestAsyncSectionRefresh();
    // applySectionRefreshResult:
    // - Populate Section/ControlArea detail text on the main thread.
    // - Synchronize the refresh status label.
    // Usage: invokeMethod is called after background task completion.
    // Parameter refreshResult: Background query result.
    // Returns: Nothing.
    void applySectionRefreshResult(const SectionRefreshResult& refreshResult);
    // refreshTokenSwitchStates:
    // - Reads the current target process token switch states;
    // - Synchronize read results to the checkboxes on the 'Token Switch' page.
    // Usage: Called when the refresh button is clicked or after the window is first initialized.
    // Parameters: None.
    // Returns: Nothing.
    void refreshTokenSwitchStates();
    // applyTokenSwitchStates:
    // - Write the 'Token Switch' page checkbox states back to the target process token;
    // - Apply items individually via NtSetInformationToken (NtSetTokenInformation) at the lower layer.
    // Invocation: Called after clicking the Apply button.
    // Parameters: None.
    // Returns: Nothing.
    void applyTokenSwitchStates();
    // applyRawTokenInformation:
    // - Read TokenInformationClass and raw payload from the 'Raw Settings' area;
    // - Directly call NtSetInformationToken to submit and overwrite all attempted information classes.
    // Invocation: Called after clicking the 'Apply Raw Settings' button.
    // Parameters: None.
    // Returns: Nothing.
    void applyRawTokenInformation();

    // ======== Module Page Refresh ========
    void requestAsyncModuleRefresh(bool forceRefresh);
    void applyModuleRefreshResult(const ModuleRefreshResult& refreshResult);
    void rebuildModuleTable();
    void updateModuleStatusLabel(const QString& statusText, bool refreshing);
    // requestAsyncDllHijackScan: Performs a read-only scan of the program directory and actual loaded modules, using
    // signature-trusted architecture-matched system DLLs as a baseline without loading any DLLs under inspection.
    void requestAsyncDllHijackScan();
    // requestAsyncInjectionTraceScan: performs read-only collection of address space, module cross-views, working set, thread start
    // points, and normalized image differences. The conclusion has only four states and does not output 'injected' or 'not injected'.
    // When deepMode=true, the entire executable image range is compared, resulting in significantly longer execution time.
    void requestAsyncInjectionTraceScan(bool deepMode);

    // ======== Module Table Right-Click ========
    void showModuleContextMenu(const QPoint& localPosition);
    void copyCurrentModuleCell();
    void copyCurrentModuleRow();
    // showCurrentModuleDetailDialog:
    // - Open a read-only detail dialog for the currently selected module;
    // - Input from current row of module table and m_moduleRecords cache;
    // - Return: None. Automatically released after the dialog closes.
    void showCurrentModuleDetailDialog();
    void openCurrentModuleFolder();
    void unloadCurrentModule();
    void suspendCurrentModuleThread();
    void resumeCurrentModuleThread();
    void terminateCurrentModuleThread();

    // ======== Operation Page Actions ========
    void executeTerminateProcessAction();
    // executeTerminateProcessComboAction:
    // - Execute a multi-method combination termination action consistent with the right-click 'Terminate Process' in the process list;
    // - Input: Binds PID to the current detail page; Processes are attempted sequentially using a fixed method chain.
    // - Return value: None; action results are logged uniformly.
    void executeTerminateProcessComboAction();
    void executeTerminateThreadsAction();
    void executeR0SuspendSelectedThreadAction();
    void executeR0ResumeSelectedThreadAction();
      void executeDriverThreadAction(unsigned long action, unsigned long terminateMethod = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE);
      void executeExperimentalFirmwareRebootAction();
    void executeR0TerminateSelectedThreadAction();
    void executeSelectedTerminateAction();
    void executeSuspendProcessAction();
    void executeResumeProcessAction();
    void executeSetCriticalAction(bool enableCritical);
    void executeSetPriorityAction();
    // executeApplyActionPrivileges: Submits checkboxes with changes on the operation page via the specified R3/R0 path.
    void executeApplyActionPrivileges(bool useR0);
    // refreshActionAffinityControls: Reads cross-node CPU set affinity and populates the operation page handler matrix.
    void refreshActionAffinityControls();
    // confirmActionAffinityRisk purpose: Display explicit risks and wait for user confirmation before applying or persisting.
    bool confirmActionAffinityRisk(bool persistenceSave);
    // applyActionAffinityRule: Maps stable group/index rules to a CPU Set and writes them to the current process.
    void applyActionAffinityRule(const ks::process::ProcessAffinityRule& affinityRule);
    // toggleActionAffinityCore: Toggles a stable logical processor coordinate, ensuring at least one is always retained.
    void toggleActionAffinityCore(
        const ks::process::LogicalProcessorCoordinate& coordinate,
        bool enabled);
    // rebuildActionAffinityCoreButtons purpose: Rebuild the dynamic processor button matrix according to processor groups.
    void rebuildActionAffinityCoreButtons();
    // updateActionAffinityCoreButtons: Refreshes button theme color states based on the current CPU Set snapshot.
    void updateActionAffinityCoreButtons();
    // refreshActionAffinityPersistenceControl purpose: Reads the registry affinity rules for the current executable and synchronizes the switch state.
    void refreshActionAffinityPersistenceControl();
    // executeSetPriorityActionById:
    // - Set the target process priority based on the priority ID passed from the menu/button.
    // - Input priorityActionId corresponds to Idle/BelowNormal/Normal/AboveNormal/High/Realtime;
    // - Return value: None; underlying call results are logged.
    void executeSetPriorityActionById(int priorityActionId);
    // executeSetEfficiencyModeAction:
    // - Enable or disable Windows Efficiency Mode for the target process;
    // - Input enableEfficiencyMode: true to enable, false to disable;
    // - Return value: None; underlying call results are logged.
    void executeSetEfficiencyModeAction(bool enableEfficiencyMode);
    // executeOpenProcessFolderAction:
    // - Navigate to the location of the current process image file in File Explorer.
    // - Input: Derived from m_baseRecord.pid; No additional parameters required.
    // - Return value: None; underlying call results are logged.
    void executeOpenProcessFolderAction();
    // executeRefreshPplProtectionLevelAction:
    // - Refreshes the current process PPL enumeration via R3 ProcessProtectionLevelInfo;
    // - Input: Derived from m_baseRecord.pid; refreshes and updates the detail page cache and text;
    // - Return value: None; query results are written to the log.
    void executeRefreshPplProtectionLevelAction();
    // executeR0TerminateProcessAction:
    // - Request R0 to terminate the current process via ArkDriverClient;
    // - Input derived from m_baseRecord.pid; does not directly call DeviceIoControl;
    // - Return value: None; driver call summaries are logged.
    void executeR0TerminateProcessAction();
    // executeR0SuspendProcessAction:
    // - Request R0 to suspend the current process via ArkDriverClient;
    // - Input derived from m_baseRecord.pid; does not directly call DeviceIoControl;
    // - Return value: None; driver call summaries are logged.
    void executeR0SuspendProcessAction();
    // executeR0SetPplProtectionAction:
    // - Set the target process's PS_PROTECTION raw bytes via ArkDriverClient.
    // - Input: protectionLevel is Signer<<4 | Type; levelDisplayText is for log display.
    // - Return value: None; driver call summaries are logged.
    void executeR0SetPplProtectionAction(std::uint8_t protectionLevel, const QString& levelDisplayText);
    // executeR0SetProcessHiddenAction:
    // - Executes recoverable hide/unhide actions via ArkDriverClient;
    // - Input hidden=true indicates hiding; visibilityFlags specifies the PID/chain-breaking strategy.
    // - Return value: None; driver call summaries are logged.
    void executeR0SetProcessHiddenAction(bool hidden, unsigned long visibilityFlags = 0UL);
    // executeR0ClearProcessHiddenAction:
    // - Clear all recoverable hidden markers within the driver via ArkDriverClient;
    // - No input; affects all targets recorded by the driver.
    // - Return value: None; driver call summaries are logged.
    void executeR0ClearProcessHiddenAction();
    // executeR0SetBreakOnTerminationAction:
    // - Sets or clears BreakOnTermination via ArkDriverClient;
    // - Input enabled=true means enable, false means disable;
    // - Return value: None; driver call summaries are logged.
    void executeR0SetBreakOnTerminationAction(bool enabled);
    // executeR0DisableApcInsertionAction:
    // - Clears the ApcQueueable bit of existing threads in the current process via ArkDriverClient.
    // - Input from m_baseRecord.pid;
    // - Return value: None; driver call summaries are logged.
    void executeR0DisableApcInsertionAction();
    // executeR0DkomRemoveFromCidTableAction:
    // - Removes the current process CID table entry from PspCidTable via ArkDriverClient;
    // - Input from m_baseRecord.pid;
    // - Return value: None; driver call summaries are logged.
    void executeR0DkomRemoveFromCidTableAction();
    void executeInjectDllAction();
    void executeInjectShellcodeAction();

    // ======== Utility Functions ========
    QIcon resolveProcessIcon(const std::string& processPath, int iconPixelSize);
    QString formatModuleSizeText(std::uint32_t moduleSizeBytes) const;
    QString formatHexText(std::uint64_t value) const;
    // readBinaryFile: Reads a binary file into a buffer and uses the same KLogEvent passed by the caller to output process logs.
    // The injection action function passes actionEvent to keep action and file-read logging in the same chain.
    // Parameters: filePath (file path); bufferOut (output buffer); errorTextOut (error message); actionEvent (same-linkage log event object).
    // Return value: returns true on success, false on failure.
    bool readBinaryFile(
        const QString& filePath,
        std::vector<std::uint8_t>& bufferOut,
        std::string& errorTextOut,
        const KLogEvent& actionEvent) const;
    // showActionResultMessage purpose: uniformly log action results (without pop-ups) and reuse the outer KLogEvent to maintain the call chain.
    // Usage: the action function first creates a KLogEvent, then passes this event object to this function.
    // Parameters: title - action title; actionOk - whether the action succeeded; detailText - action details; actionEvent - the log event object for the same call chain.
    // Return value: None.
    void showActionResultMessage(const QString& title, bool actionOk, const std::string& detailText, const KLogEvent& actionEvent);
    ks::process::ProcessModuleRecord* selectedModuleRecord();

private:
    // ======== Currently bound process base data ========
    ks::process::ProcessRecord baseRecord_;   // Process snapshot bound to current window.
    std::string identityKey_;                 // Identity string composed of PID + CreateTime.

    // ======== Root Layout and Tabs ========
    QHBoxLayout* rootLayout_ = nullptr;       // Root layout for the left navigation and right page.
    QWidget* tabNavigation_ = nullptr;        // Container for the left-side single-column always-visible page navigation buttons.
    QButtonGroup* tabNavigationButtonGroup_ = nullptr; // Mapping between navigation buttons and Tab indices.
    QTabWidget* tabWidget_ = nullptr;         // Container for the page stack and existing tab switching/lazy-loading logic.
    QSet<QWidget*> initializedTabs_;           // Pages with constructed control trees to avoid re-initialization.
    QSet<QObject*> connectedSignalSources_;    // Connected senders, supporting signal reconnection after page construction on demand.
    QWidget* detailTab_ = nullptr;            // "Details" tab.
    QWidget* performanceTab_ = nullptr;       // "Performance" tab.
    QWidget* cpuCoreTab_ = nullptr;           // "CPU Core" page.
    QWidget* threadTab_ = nullptr;            // "Thread" tab.
    QWidget* actionTab_ = nullptr;            // "Action" tab.
    QWidget* moduleTab_ = nullptr;            // "Module" tab.
    QWidget* embeddedHandleTab_ = nullptr;    // Current process 'Handle' embedded audit tab.
    QWidget* embeddedMemoryTab_ = nullptr;    // Current process 'Memory' embedded tab (simplified).
    QWidget* embeddedNetworkTab_ = nullptr;   // Current process 'Network Connection' embedded tab.
    QWidget* soundSourceTab_ = nullptr;       // Current process 'Sound Source' embedded tab.
    QWidget* embeddedWindowTab_ = nullptr;    // Current process 'Window List' embedded tab.
    QWidget* tokenTab_ = nullptr;             // "Token" tab.
    QWidget* tokenSwitchTab_ = nullptr;       // "Token Switch" page.
    QWidget* kernelObjectTab_ = nullptr;      // "Process Detail Evidence" page.
    QWidget* hotkeyTab_ = nullptr;            // "Process Hotkeys" tab.
    QWidget* keyboardTab_ = nullptr;          // "Keyboard" tab.
    QWidget* pluginTab_ = nullptr;            // "Plugin" tab.
    QWidget* pebTab_ = nullptr;               // "PEB" tab.
    QWidget* kernelCallbackTab_ = nullptr;    // "Kernel Callback Table" tab.

    // ======== Plugin Page Controls ========
    QToolButton* pluginTargetMenuButton_ = nullptr; // The "Plugin → <Plugin Name>" entry for the current process.
    QMenu* pluginTargetMenu_ = nullptr;             // Dynamically rebuilt from the local plugin.json.

    // ======== Detail Page Controls ========
    QVBoxLayout* detailLayout_ = nullptr;     // Total layout for the detail page.
    QLabel* processIconLabel_ = nullptr;      // Top process icon (40px).
    QLabel* processTitleLabel_ = nullptr;     // Top title (process name + PID).
    QLineEdit* pathLineEdit_ = nullptr;       // Program path (read-only).
    QPushButton* copyPathButton_ = nullptr;   // Copy path button.
    QPushButton* openPathFolderButton_ = nullptr; // Open path button.
    QPushButton* openFileDetailButton_ = nullptr; // Navigate to File Details window.
    QPushButton* refreshDetailOverviewButton_ = nullptr; // Refresh the runtime fields on the detail page.
    QLabel* detailOverviewStatusLabel_ = nullptr; // Refresh status of runtime fields on the detail page.
    QLineEdit* commandLineEdit_ = nullptr;    // Startup command line (read-only).
    QPushButton* copyCommandButton_ = nullptr; // Copy command line button.
    QLabel* parentIconLabel_ = nullptr;       // Parent process icon (20px).
    QLabel* parentInfoLabel_ = nullptr;       // Parent process name + PID.
    QPushButton* detailOpenHandleDockButton_ = nullptr; // Navigates the detail page to the Handle Dock.
    QPushButton* openHandleDockButton_ = nullptr; // Navigate operation page to handle dock.
    QPushButton* openMemoryDockButton_ = nullptr; // Jump to Memory Dock.
    QPushButton* openNetworkDockButton_ = nullptr; // Jump to Network Dock.
    QPushButton* openWindowDockButton_ = nullptr; // Jump to Window Dock.
    QPushButton* gotoParentButton_ = nullptr; // Button to navigate to parent process.

    QLabel* detailStartTimeValue_ = nullptr;  // Start time value.
    QLabel* detailUserValue_ = nullptr;       // User value.
    QLabel* detailAdminValue_ = nullptr;      // Whether it is an admin value.
    QLabel* detailArchitectureValue_ = nullptr; // Architecture value.
    QLabel* detailPriorityValue_ = nullptr;   // Priority value.
    QLabel* detailSessionValue_ = nullptr;    // Session ID value.
    QLabel* detailThreadCountValue_ = nullptr; // Thread-count value.
    QLabel* detailHandleCountValue_ = nullptr; // Handle count value.
    QLabel* detailCpuValue_ = nullptr;        // Current CPU usage value.
    QLabel* detailCpuCoreValue_ = nullptr;    // CPU single-core equivalent usage value.
    QLabel* detailRamValue_ = nullptr;        // Current RAM usage value.
    QLabel* detailDiskValue_ = nullptr;       // DISK current usage value.
    QLabel* detailSignatureValue_ = nullptr;  // Digital signature status value.
    QHash<QString, QLabel*> detailExtraValues_; // Mapping of value controls for extended fields on the detail page.
    DetailOverviewRefreshResult detailOverviewResult_; // Snapshot of the most recent runtime extension field.
    bool detailOverviewRefreshing_ = false;   // Indicates whether the extended field background query is in progress.
    std::uint64_t detailOverviewRefreshTicket_ = 0; // Prevent out-of-order asynchronous backfill.

    // ======== Performance page controls and history ========
    QLabel* performanceHistoryStatusLabel_ = nullptr; // Status of the performance page history range and sample count.
    QWidget* performanceCpuChart_ = nullptr;          // CPU chart.
    QWidget* performanceCpuCoreChart_ = nullptr;      // Single-core CPU equivalent chart.
    QWidget* performanceMemoryChart_ = nullptr;       // Memory chart.
    QWidget* performanceDiskChart_ = nullptr;         // Disk chart.
    QWidget* performanceNetworkChart_ = nullptr;      // Network send/receive chart.
    QWidget* performanceGpuChart_ = nullptr;          // GPU chart.
    std::deque<PerformanceHistorySample> performanceHistory_; // Fixed-length history sequence for the current detail window.

    // ======== CPU Core Page Control and Interval Snapshot ========
    QLabel* cpuCoreTitleLabel_ = nullptr;             // Page title; refresh foreground color on theme switch.
    QLabel* cpuCoreDescriptionLabel_ = nullptr;       // Page description; refresh secondary text color on theme switch.
    QLabel* cpuCoreStatusLabel_ = nullptr;            // ETW running/sampling/lost event status.
    QLabel* cpuCoreSystemValueLabel_ = nullptr;       // Aggregate normalized system-wide CPU usage for the process.
    QLabel* cpuCoreEquivalentValueLabel_ = nullptr;   // Aggregated single-core equivalent CPU usage for the process.
    QWidget* processCpuCoreGrid_ = nullptr;            // Line matrix of the current process per logical processor.
    QWidget* threadCpuCoreGrid_ = nullptr;             // Thread line matrix sorted by total usage, expandable on click.
    CpuCoreViewSample cpuCoreViewSample_;              // Retain the latest snapshot even when the page is not constructed.

    // ======== Thread Page Controls ========
    QVBoxLayout* threadLayout_ = nullptr;     // Thread page total layout.
    QPushButton* refreshThreadInspectButton_ = nullptr; // Refresh thread details button.
    QPushButton* sampleThreadRuntimeButton_ = nullptr; // Current thread PDB field sampling button.
    QLabel* threadInspectStatusLabel_ = nullptr; // Thread detail refresh status.
    QTableWidget* threadInspectTable_ = nullptr; // Thread details table.
    CodeEditorWidget* threadRuntimeSampleOutput_ = nullptr; // Details of the current thread's PDB deep sampling.

    // ======== Operation Page Controls ========
    QVBoxLayout* actionLayout_ = nullptr;     // Total layout of the operation page.
    QComboBox* terminateActionCombo_ = nullptr; // Termination scheme dropdown.
    QPushButton* executeTerminateActionButton_ = nullptr; // Execute the current termination plan button.
    // Suspend is a toggle, not two separate actions: checked means suspended, unchecked means resumed. The checked
    // state comes from m_baseRecord.processSuspended and is synchronized once per refreshDetailTabTexts call.
    QCheckBox* suspendProcessCheck_ = nullptr; // Suspend/Resume toggle.
    QPushButton* setCriticalButton_ = nullptr; // Set as critical process.
    QPushButton* clearCriticalButton_ = nullptr; // Cancel critical process.

    QGroupBox* affinityActionGroup_ = nullptr; // CPU affinity action group.
    QLabel* affinityDescriptionLabel_ = nullptr; // Display symbol descriptions based on the actual number of processor groups.
    QLabel* affinityStatusLabel_ = nullptr; // CPU affinity current mode and operation result.
    QCheckBox* affinityPersistenceCheckBox_ = nullptr; // Whether to persist CPU affinity rules for the current full executable path.
    QPushButton* affinityRefreshButton_ = nullptr; // Re-read affinity.
    QPushButton* affinityAllCoresButton_ = nullptr; // Clear CPU Set restrictions and enable all available processors.
    QGridLayout* affinityMatrixLayout_ = nullptr; // Dynamically arrange logical processors by processor group.
    std::vector<QToolButton*> affinityCoreButtons_; // Buttons consistent with the order of processors in the affinity snapshot.
    ks::process::ProcessAffinitySnapshot actionAffinitySnapshot_; // Snapshot of the most recent cross-group affinity query.
    bool actionAffinityReadable_ = false; // Whether the current affinity was successfully read.

    QGroupBox* privilegeActionGroup_ = nullptr; // Token privilege checkbox group.
    QLabel* actionPrivilegeStatusLabel_ = nullptr; // privilege query and application status.
    QPushButton* actionPrivilegeRefreshButton_ = nullptr; // Refresh privileges.
    QPushButton* applyActionPrivilegeR3Button_ = nullptr; // Apply changes via R3.
    QPushButton* applyActionPrivilegeR0Button_ = nullptr; // Apply changes via R0.
    std::vector<QCheckBox*> actionPrivilegeCheckBoxes_; // Consistent with the order of knownTokenPrivilegeNames.
    std::vector<ks::process::TokenPrivilegeInfo> actionPrivilegeSnapshot_; // Last query snapshot.
    bool actionPrivilegeReadable_ = false; // Whether the current snapshot is editable.
    bool actionPrivilegeRefreshing_ = false; // Indicates whether a query or application is currently executing in the background.
    bool actionPrivilegeInitialRefreshStarted_ = false; // Whether the initial privilege query for the action page has started.
    std::uint64_t actionPrivilegeRefreshTicket_ = 0; // Prevent out-of-order asynchronous results.

    QComboBox* priorityCombo_ = nullptr;      // Priority selection box.
    QPushButton* applyPriorityButton_ = nullptr; // Apply priority button.
    QPushButton* openProcessFolderButton_ = nullptr; // Open process directory button.
    QPushButton* refreshPplProtectionButton_ = nullptr; // Manual refresh PPL protection level button.
    QCheckBox* efficiencyModeCheck_ = nullptr; // Efficiency mode (green leaf) toggle.
    QPushButton* r0TerminateProcessButton_ = nullptr; // R0 terminate process button.
    QPushButton* r0SuspendProcessButton_ = nullptr; // R0 suspend process button.
    QPushButton* r0SetPplButton_ = nullptr; // R0 set PPL level button.
    QPushButton* r0VisibilityButton_ = nullptr; // R0 recoverable hidden menu button.
    QPushButton* r0DangerFlagsButton_ = nullptr; // R0 danger flags / DKOM menu button.

    QLineEdit* dllPathLineEdit_ = nullptr;    // DLL path input field.
    QComboBox* injectionModeCombo_ = nullptr; // Injection mode: R3 or R0 driver.
    QPushButton* browseDllButton_ = nullptr;  // Browse DLL button.
    QPushButton* injectDllButton_ = nullptr;  // Button to execute DLL injection.

    QLineEdit* shellcodePathLineEdit_ = nullptr; // Shellcode file path input box.
    QPushButton* browseShellcodeButton_ = nullptr; // Browse shellcode file button.
    QPushButton* injectShellcodeButton_ = nullptr; // Shellcode injection button.

    // ======== Module Page Controls ========
    QVBoxLayout* moduleLayout_ = nullptr;     // Module page main layout.
    QHBoxLayout* moduleTopBarLayout_ = nullptr; // Module page top toolbar layout.
    QPushButton* refreshModuleButton_ = nullptr; // Module refresh button.
    QPushButton* dllHijackScanButton_ = nullptr; // Read-only DLL hijack scan button.
    QPushButton* injectionTraceButton_ = nullptr;     // Read-only injection trace check button (fast).
    QPushButton* injectionTraceDeepButton_ = nullptr; // Read-only injection trace check button (deep).
    QCheckBox* signatureCheckBox_ = nullptr;  // Whether to perform signature verification during refresh.
    QLabel* moduleStatusLabel_ = nullptr;     // Module refresh status label.
    QTreeWidget* moduleTable_ = nullptr;      // Module table.

    std::vector<ks::process::ProcessModuleRecord> moduleRecords_; // Current module data cache.

    // ======== Embedded Handle Audit Page ========
    QVBoxLayout* embeddedHandleLayout_ = nullptr; // Handle audit page container layout.
    QLabel* embeddedHandlePlaceholder_ = nullptr; // Lightweight prompt before first entry.
    HandleDock* embeddedHandleDock_ = nullptr;    // Reuse the full HandleDock, filtered by the current PID.

    // ======== Embedded Slim Memory Page ========
    QVBoxLayout* embeddedMemoryLayout_ = nullptr;
    QLabel* embeddedMemoryPlaceholder_ = nullptr;
    MemoryDock* embeddedMemoryDock_ = nullptr;

    // ======== Embedded Network Connection Page ========
    QVBoxLayout* embeddedNetworkLayout_ = nullptr;
    QLabel* embeddedNetworkPlaceholder_ = nullptr;
    NetworkDock* embeddedNetworkDock_ = nullptr;

    // ======== Embedded Window List Page ========
    QVBoxLayout* embeddedWindowLayout_ = nullptr;
    QLabel* embeddedWindowPlaceholder_ = nullptr;
    OtherDock* embeddedWindowDock_ = nullptr;

    bool moduleRefreshing_ = false;           // Flag indicating module refresh is in progress.
    bool moduleInitialRefreshStarted_ = false; // Whether the module page first refresh has been started on demand.
    bool firstModuleRefreshDone_ = false;     // Whether the first module refresh is complete.
    std::uint64_t moduleRefreshTicket_ = 0;   // Module refresh sequence number (prevent out-of-order).
    int moduleRefreshProgressPid_ = 0;        // The PID of the kPro task corresponding to the first module refresh.
    bool dllHijackScanRunning_ = false;       // DLL hijack detection background task running flag.
    std::uint64_t dllHijackScanTicket_ = 0;   // Anti-out-of-order sequence number for DLL hijack detection results.
    bool injectionTraceRunning_ = false;      // Flag indicating whether the injection trace check background task is running.
    std::uint64_t injectionTraceTicket_ = 0;  // Injection trace check result to prevent out-of-order sequence numbers.

    // ======== Thread detail refresh status ========
    bool threadInspectRefreshing_ = false;        // Whether thread details are currently refreshing.
    bool threadInspectInitialRefreshStarted_ = false; // Whether the thread page's first refresh has been started on demand.
    std::uint64_t threadInspectRefreshTicket_ = 0;// Thread detail refresh sequence number.
    bool threadRuntimeSampleRefreshing_ = false;  // Whether the current thread's PDB sampling is in progress.
    std::uint64_t threadRuntimeSampleTicket_ = 0; // Thread PDB sampling anti-out-of-order sequence number.
    int threadInspectRefreshProgressPid_ = 0;     // PID corresponding to the thread detail refresh progress.
    std::vector<ThreadInspectItem> threadInspectRows_; // Cache of the most recent refresh for the thread detail page.

    // ======== Process Detail Evidence Page Controls ========
    QVBoxLayout* kernelObjectLayout_ = nullptr; // Process Detail Evidence page total layout.
    QLabel* kernelObjectR0StatusValue_ = nullptr; // R0 extended read status.
    QLabel* kernelObjectCapabilityValue_ = nullptr; // DynData capability bitmap.
    QLabel* kernelObjectProtectionValue_ = nullptr; // EPROCESS.Protection original value.
    QLabel* kernelObjectSignatureValue_ = nullptr; // SignatureLevel raw value.
    QLabel* kernelObjectSectionSignatureValue_ = nullptr; // SectionSignatureLevel original value.
    QLabel* kernelObjectHandleTableValue_ = nullptr; // ObjectTable availability and current pointer.
    QLabel* kernelObjectSectionObjectValue_ = nullptr; // SectionObject availability and current pointer.
    QLabel* kernelObjectImagePathValue_ = nullptr; // R0 image path.
    QLabel* kernelObjectSessionSourceValue_ = nullptr; // Session source.
    QLabel* kernelObjectImagePathSourceValue_ = nullptr; // Image path source.
    QLabel* kernelObjectProtectionSourceValue_ = nullptr; // Protection source.
    QLabel* kernelObjectSignatureSourceValue_ = nullptr; // SignatureLevel source.
    QLabel* kernelObjectSectionSignatureSourceValue_ = nullptr; // SectionSignatureLevel source.
    QLabel* kernelObjectObjectTableSourceValue_ = nullptr; // ObjectTable source.
    QLabel* kernelObjectSectionObjectSourceValue_ = nullptr; // SectionObject source.
    QLabel* kernelObjectProtectionOffsetValue_ = nullptr; // Protection offset.
    QLabel* kernelObjectSignatureOffsetValue_ = nullptr; // SignatureLevel offset.
    QLabel* kernelObjectSectionSignatureOffsetValue_ = nullptr; // SectionSignatureLevel offset.
    QLabel* kernelObjectObjectTableOffsetValue_ = nullptr; // ObjectTable offset.
    QLabel* kernelObjectSectionObjectOffsetValue_ = nullptr; // SectionObject offset.
    QPushButton* refreshSectionInfoButton_ = nullptr; // Refresh Section/ControlArea button.
    QLabel* sectionInfoStatusLabel_ = nullptr; // Section/ControlArea query status.
    CodeEditorWidget* sectionInfoOutput_ = nullptr; // Section/ControlArea detail text output.
    bool sectionInfoRefreshing_ = false; // Section query in progress.
    bool sectionInfoInitialRefreshStarted_ = false; // Whether the Section page's initial query has been started on demand.
    std::uint64_t sectionInfoRefreshTicket_ = 0; // Section query sequence number.
    int sectionInfoRefreshProgressPid_ = 0; // PID for the kPro section query task.

    // ======== Process Hotkey Page Control and Status ========
    QVBoxLayout* hotkeyLayout_ = nullptr;       // Process hotkey page main layout.
    QPushButton* deleteHotkeyButton_ = nullptr;  // Delete the hotkey for the current supported source.
    QPushButton* refreshHotkeyButton_ = nullptr; // Refresh hotkey button.
    QPushButton* editHotkeyButton_ = nullptr;    // Edit the hotkey for the currently supported source.
    QLabel* hotkeyStatusLabel_ = nullptr;       // Hotkey scan status.
    QTableWidget* hotkeyTable_ = nullptr;       // Hotkey results table.
    bool hotkeyRefreshing_ = false;             // Whether hotkey scanning is in progress.
    bool hotkeyInitialRefreshStarted_ = false;  // Whether the hotkey page's initial scan has been started on demand.
    std::uint64_t hotkeyRefreshTicket_ = 0;     // Hotkey scan sequence number.
    int hotkeyRefreshProgressPid_ = 0;          // Hotkey scan kPro task PID.
    std::vector<HotkeyInspectItem> hotkeyRows_; // Hotkey result cache.

    // ======== Keyboard page controls and status ========
    QVBoxLayout* keyboardLayout_ = nullptr;       // Keyboard page main layout.
    QPushButton* refreshKeyboardButton_ = nullptr; // Refresh keyboard button.
    QLabel* keyboardStatusLabel_ = nullptr;       // Keyboard page scan status.
    QTabWidget* keyboardInnerTabWidget_ = nullptr; // Keyboard tab internal hotkeys/hook sub-tabs.
    QTableWidget* keyboardHotkeyTable_ = nullptr; // Keyboard page hotkey table.
    QTableWidget* keyboardHookTable_ = nullptr;   // Keyboard hook results table.
    bool keyboardRefreshing_ = false;             // Whether the keyboard page scan is in progress.
    bool keyboardInitialRefreshStarted_ = false;  // Whether the keyboard tab's initial scan has started.
    std::uint64_t keyboardRefreshTicket_ = 0;     // Keyboard page scan sequence number.
    int keyboardRefreshProgressPid_ = 0;          // Keyboard page scan kPro task PID.
    std::vector<HotkeyInspectItem> keyboardHotkeyRows_; // Keyboard page hotkey cache.
    std::vector<KeyboardHookInspectItem> keyboardHookRows_; // Keyboard page hook cache.

    // ======== Token page controls and status ========
    QVBoxLayout* tokenLayout_ = nullptr;          // Token page layout.
    QPushButton* refreshTokenButton_ = nullptr;   // Button to refresh token information.
    QLabel* tokenStatusLabel_ = nullptr;          // Token page status text.
    CodeEditorWidget* tokenDetailOutput_ = nullptr; // Token information output box (unified text editor component, read-only).
    bool tokenRefreshing_ = false;                // Token page refresh status.
    bool tokenInitialRefreshStarted_ = false;     // Whether the token page has been started on demand for the first refresh.
    std::uint64_t tokenRefreshTicket_ = 0;        // Token page refresh sequence number.
    int tokenRefreshProgressPid_ = 0;             // Token page refresh progress PID.

    // ======== Token switch page controls and status ========
    QVBoxLayout* tokenSwitchLayout_ = nullptr;    // Token switch page main layout.
    QPushButton* refreshTokenSwitchButton_ = nullptr; // Button to toggle token refresh.
    QPushButton* applyTokenSwitchButton_ = nullptr;   // Token switch button for applying.
    QPushButton* refreshTokenAllInfoButton_ = nullptr; // Refresh all token information button (triggers enumeration of all information classes).
    QLabel* tokenSwitchStatusLabel_ = nullptr;    // Token switch application status text.
    bool tokenSwitchInitialRefreshStarted_ = false; // Whether the token switch page has been started on-demand for the first read-back.
    QCheckBox* tokenSandboxInertCheck_ = nullptr; // SandboxInert switch.
    QCheckBox* tokenVirtualizationAllowedCheck_ = nullptr; // VirtualizationAllowed switch.
    QCheckBox* tokenVirtualizationEnabledCheck_ = nullptr; // VirtualizationEnabled switch.
    QCheckBox* tokenUiAccessCheck_ = nullptr;     // UIAccess toggle.
    QCheckBox* tokenMandatoryNoWriteUpCheck_ = nullptr; // MandatoryPolicy: NoWriteUp bit.
    QCheckBox* tokenMandatoryNewProcessMinCheck_ = nullptr; // MandatoryPolicy: NewProcessMin bit.
    QCheckBox* tokenHasRestrictionsCheck_ = nullptr; // TokenHasRestrictions (class=21) toggle.
    QCheckBox* tokenIsAppContainerCheck_ = nullptr;  // TokenIsAppContainer (class=29) switch.
    QCheckBox* tokenIsRestrictedCheck_ = nullptr; // TokenIsRestricted (class=40) switch.
    QCheckBox* tokenIsLessPrivilegedAppContainerCheck_ = nullptr; // TokenIsLessPrivilegedAppContainer (class=46) switch.
    QCheckBox* tokenIsSandboxedCheck_ = nullptr; // TokenIsSandboxed (class=47) switch.
    QCheckBox* tokenIsAppSiloCheck_ = nullptr; // TokenIsAppSilo (class=51) switch.
    QComboBox* tokenRawInfoClassCombo_ = nullptr; // Original setting: TokenInformationClass combo box.
    QComboBox* tokenRawInputModeCombo_ = nullptr; // Raw settings: load input mode (UInt32/UInt64/HexBytes).
    QLineEdit* tokenRawPayloadEdit_ = nullptr;    // Raw settings: payload input text.
    QPushButton* tokenRawApplyButton_ = nullptr;  // Raw settings: button to execute NtSetInformationToken.

    // ======== PEB Page Controls and Status ========
    QVBoxLayout* pebLayout_ = nullptr;            // PEB page layout.
    QPushButton* refreshPebButton_ = nullptr;     // Refresh PEB information button.
    QPushButton* applyPebEditButton_ = nullptr;   // Button to apply editable PEB fields.
    QLabel* pebStatusLabel_ = nullptr;            // PEB page status text.
    QComboBox* pebTargetCombo_ = nullptr;          // PEB write target: NativePEB / Wow64PEB.
    QLineEdit* pebCommandLineEdit_ = nullptr;      // Editable CommandLine.
    QLineEdit* pebImagePathEdit_ = nullptr;        // Editable ImagePathName.
    QLineEdit* pebCurrentDirectoryEdit_ = nullptr; // Editable CurrentDirectory.DosPath.
    QLineEdit* pebImageBaseEdit_ = nullptr;        // Advanced: PEB.ImageBaseAddress.
    QLineEdit* pebAffinityMaskEdit_ = nullptr;     // Editable process affinity mask.
    QComboBox* pebPriorityClassCombo_ = nullptr;   // Editable priority.
    QLineEdit* pebEnvironmentNameEdit_ = nullptr;  // Environment variable name.
    QLineEdit* pebEnvironmentValueEdit_ = nullptr; // Environment variable value.
    CodeEditorWidget* pebReadonlyReasonOutput_ = nullptr; // Do not modify fields directly; support language switching and repainting.
    CodeEditorWidget* pebDetailOutput_ = nullptr;   // PEB information output box (unified text editor component, read-only).
    bool pebRefreshing_ = false;                  // PEB page refresh status.
    bool pebInitialRefreshStarted_ = false;       // Whether the PEB page has been started on demand for the first refresh.
    std::uint64_t pebRefreshTicket_ = 0;          // PEB page refresh sequence number.
    int pebRefreshProgressPid_ = 0;               // PEB page refresh progress PID.

    // ======== PEB.KernelCallbackTable page control and status ========
    QVBoxLayout* kernelCallbackLayout_ = nullptr; // Kernel callback table page layout.
    QPushButton* refreshKernelCallbackButton_ = nullptr; // Refresh kernel callback table button.
    QLabel* kernelCallbackStatusLabel_ = nullptr; // Kernel callback table refresh status.
    QTableWidget* kernelCallbackTable_ = nullptr; // Kernel callback table result grid.
    bool kernelCallbackRefreshing_ = false;       // Whether the callback table is currently being read.
    bool kernelCallbackInitialRefreshStarted_ = false; // Whether lazy-loading initial refresh has been executed.
    std::uint64_t kernelCallbackRefreshTicket_ = 0; // Prevents old tasks from overwriting new results.
    int kernelCallbackRefreshProgressPid_ = 0;    // Kernel callback table progress task ID.
    std::vector<KernelCallbackInspectItem> kernelCallbackRows_; // Last result cache.

    // applyPebEditableFields：
    // - Reads input from the PEB page edit area;
    // - Attempt to write back to remote PEB/ProcessParameters and process basic runtime attributes.
    // - Feedback success/failure via status bar and message box.
    void applyPebEditableFields();
    // populatePebEditableFieldsFromText：
    // - Extract writable fields of the current target PEB from the PEB refresh text;
    // - Automatically populate the edit box to avoid users manually copying long command lines or paths.
    // - Updates UI controls only; no return value.
    void populatePebEditableFieldsFromText(const QString& detailText);
    bool staticDetailRefreshing_ = false;         // Whether static detail background completion is in progress.
    bool staticDetailRefreshAttempted_ = false;   // Whether static details have already been attempted for background completion, to avoid duplicate queuing in periodic refreshes.
    std::uint64_t staticDetailRefreshTicket_ = 0; // Static detail refresh sequence number.
    bool themeStyleApplying_ = false;             // Theme style rebuild re-entrancy guard to prevent circular triggering of changeEvent.

    // Icon cache: path -> icon, avoiding repeated system icon reads.
    QHash<QString, QIcon> iconCacheByPath_;
};

#pragma once

// ============================================================
// MemoryDock.h
// Purpose:
// 1) Constructs the complete multi-Tab interactive interface for the 'Memory' page;
// 2) Provide process attach, module view, memory region browsing, scanning, and hex viewing.
// 3) Provide basic capabilities for breakpoints, bookmarks, R0 memory read/write, and kernel executable page scanning.
// ============================================================

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"
#include "../ui/KernelDisassemblyDialog.h" // ks::ui::DisassemblyRow: The driver read/write page disassembly view's row cache requires a complete type.
#include "../ui/WindowPickerButton.h" // ks::ui::WindowPickerButton: Crosshair picker button, appearing by value in member pointers.
#include "MemoryAccessBackend.h" // Access backend enumeration and DDMA sessions: appear by value in members and return types.
#include "TamperDetectionPage.h" // ksword::memory_dock::TamperDetectionPage: Appears by value in member pointers and module synchronous calls.

#include <QVector>     // QVector: Stores decompiled decoding result lines.
#include <QWidget>

#include <atomic>      // std::atomic: Scan cancellation flag, concurrent status flag.
#include <condition_variable> // std::condition_variable: Wait for the cancelled scan thread to exit.
#include <cstdint>     // std::uint32_t / std::uint64_t: Fixed-width integers for PID, addresses, etc.
#include <functional>  // std::function: Deferred UI commits during dropdown expansion.
#include <memory>      // std::shared_ptr: Ensures the scan task status remains valid until the background thread exits.
#include <mutex>       // std::mutex: Protect scan task counter.
#include <string>      // std::string: String bridging for logs and Win32 calls.
#include <vector>      // std::vector: Caches process/module/region/scan results.

// Qt forward declaration: minimize header file compilation dependencies.
class QAction;
class QCheckBox;
class QComboBox;
class QEvent;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPoint;
class QProgressBar;
class QPushButton;
class QSplitter;
class QSpinBox;
class QStackedWidget;
class QStatusBar;
class QTableWidget;
class QTabWidget;
class QTextEdit;
class QTimer;
class QToolButton;
class QTreeWidget;
class QVBoxLayout;
class CodeEditorWidget;
class HexEditorWidget;
class SystemMemoryAuditPage;
class DdmaPage;

// Forward declaration of UI components within the project: use pointers only to avoid including the table component header in this header file.
namespace ks::ui
{
    class VisibleTableWidget;
}

// Windows handle type forward declaration.
typedef void* HANDLE;

// ============================================================
// MemoryDock
// Notes:
// - This class is responsible for the UI and business logic of the entire 'Memory Page'.
// All functions are implemented in the .cpp file with detailed comments for easier maintenance.
// ============================================================
class MemoryDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize all UI elements, connect signals and slots, and load the initial process list.
    // - Parameter parent: Qt parent widget pointer, may be null.
    explicit MemoryDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Release process handles, stop timers, and clear background scanning status before control destruction.
    ~MemoryDock() override;

    // focusProcessForOperations：
    // - Purpose: Automatically locate and attach to the target PID after navigating from the Process page to the Memory page.
    // - Invocation: Called by mainWindow::focusMemoryDockByPid.
    void focusProcessForOperations(std::uint32_t pid, bool showMessage = false);

    // focusProcessForSearch：
    // - Purpose: Attach to the specified PID and switch to the 'Memory Search' page.
    // - Enables the independent 'Memory Scan' tab in process details to reuse full search capabilities.
    void focusProcessForSearch(std::uint32_t pid, bool showMessage = false);

    // setProcessDetailMemoryScope：
    // - Used for embedding within the process details window.
    // - Retain only four pages: Process & Module, Memory Region, Memory Search, and Memory Viewer.
    void setProcessDetailMemoryScope();

    // focusDdmaPage：
    // - Purpose: Switch the current tab to the DDMA sub-page.
    // - Invocation: mainWindow::focusMemoryDockDdmaPage (click the DDMA indicator in the top-right corner).
    void focusDdmaPage();

protected:
    // changeEvent：
    // - Purpose: Reapply semantic color styles when the application palette changes.
    // - Parameter eventObject: Qt-provided event object;
    // - Note: Semantic color tokens are a snapshot taken at the moment of invocation and do not update automatically with the theme; they must be re-applied here.
    void changeEvent(QEvent* eventObject) override;

private:
    // applyMemoryDockSemanticStyles：
    // - Purpose: Apply semantic color styles to dangerous operation buttons and status bar labels.
    // - Note: Construction and theme switching share this path to ensure colors do not remain stuck on the old theme after switching between light and dark modes.
    // - Return: None. Skips individually if controls have not been created yet.
    void applyMemoryDockSemanticStyles();

private:
    // ========================================================
    // Internal data structure definition (used for table cache and cross-tab shared state).
    // ========================================================

    // ProcessEntry：
    // - Purpose: Stores data required to display a single process row.
    struct ProcessEntry
    {
        std::uint32_t pid = 0;          // Process PID.
        std::uint32_t sessionId = 0;    // Session ID.
        QString processName;            // Process name.
        // CPU usage. It requires two samples to calculate, so "cannot calculate this round" is a
        // real and common state (first refresh, process just started, insufficient permissions to
        // retrieve CPU time). Use an independent valid flag instead of treating 0.0 as a sentinel—0%
        // is a completely valid usage rate. Conflating the two would display "unknown" as "idle".
        double cpuPercent = 0.0;
        bool cpuPercentValid = false;
        double workingSetMB = 0.0;      // Working set memory (MB).
    };

    // ProcessCpuSample: CPU sample from the previous round, saved by PID, used to calculate increments.
    struct ProcessCpuSample
    {
        std::uint64_t cpuTime100ns = 0;
        std::uint64_t sampleTime100ns = 0;
    };

    // ModuleEntry：
    // - Purpose: Saves data for each row in the module table.
    struct ModuleEntry
    {
        QString moduleName;                     // Module file name (end of path).
        QString fullPath;                       // Module full path.
        std::uint64_t baseAddress = 0;          // Module base address (used for jumps and copying).
        std::uint64_t sizeBytes = 0;            // Module size (bytes).
        QString signatureState;                 // Digital signature status text (Signed/Unknown/...).
        bool signatureTrusted = false;          // Whether the signature is trusted (used for coloring).
        std::uint64_t entryPointOffset = 0;     // Entry point offset (RVA).
        QString runningState;                   // Running state text (Running/Suspended/...).
        QString threadIdText;                   // Represents thread ID text (may contain multiple).
        std::uint32_t representativeThreadId = 0; // Representative thread ID (entry point for numeric actions).
    };

    // RegionEntry：
    // - Purpose: Store memory region information obtained from VirtualQueryEx enumeration.
    struct RegionEntry
    {
        std::uint64_t baseAddress = 0;  // Region start address.
        std::uint64_t regionSize = 0;   // Region size (bytes).
        std::uint32_t protect = 0;      // Protection attribute bits (PAGE_*).
        std::uint32_t state = 0;        // State (MEM_COMMIT / MEM_RESERVE / MEM_FREE).
        std::uint32_t type = 0;         // Type (MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE).
        QString mappedFilePath;         // Mapped file path (if available).
    };

    // SearchValueType：
    // - Purpose: Define the data type for the scan value.
    enum class SearchValueType : int
    {
        kByte = 0,           // 1-byte integer.
        kInt16,              // 2-byte integer.
        kInt32,              // 4-byte integer.
        kInt64,              // 8-byte integer.
        kFloat32,            // Single-precision floating-point.
        kFloat64,            // Double-precision floating-point.
        kByteArray,          // Byte array (supports ?? wildcards).
        kStringAscii,        // ASCII string.
        kStringUnicode       // Unicode string (UTF-16LE).
    };

    // SearchCompareMode：
    // - Purpose: Define the filter condition for a subsequent scan.
    enum class SearchCompareMode : int
    {
        kEqual = 0,          // Equal.
        kGreater,            // Greater.
        kLess,               // Less.
        kBetween,            // Between (current value is in [A, B]).
        kChanged,            // Changed.
        kUnchanged,          // Unchanged.
        kIncreased,          // Increased.
        kDecreased           // Decreased.
    };

    // SearchResultEntry：
    // - Purpose: Save a scan result row.
    struct SearchResultEntry
    {
        std::uint64_t address = 0;      // Hit address.
        QByteArray currentValueBytes;   // Current value bytes.
        QByteArray previousValueBytes;  // Previous value bytes (meaningful during re-scan).
        QString noteText;               // Note text (can be filled by the user later).
    };

    // BreakpointEntry：
    // - Purpose: Stores software breakpoint information (0xCC).
    struct BreakpointEntry
    {
        std::uint64_t address = 0;      // Breakpoint address.
        std::uint8_t originalByte = 0;  // Original byte (for restoration).
        bool enabled = false;           // Currently enabled.
        std::uint64_t hitCount = 0;     // Hit count (reserved for current version).
        QString description;            // Breakpoint description text.
    };

    // BookmarkEntry：
    // - Purpose: Save user bookmark information.
    struct BookmarkEntry
    {
        std::uint64_t address = 0;      // Bookmark address.
        QString noteText;               // Note text.
        QString addTimeText;            // Add time text.
        QByteArray lastValueBytes;      // Last refreshed value (used for change observation).
    };

public:
    // ProcessMemoryEvidenceEntry：
    // - Purpose: Represent PTE / working set / risk evidence for a single virtual address.
    // - Note: Serves read-only display for both Tab9 and Tab10.
    struct ProcessMemoryEvidenceEntry
    {
        std::uint64_t virtualAddress = 0;   // Virtual address.
        std::uint64_t regionBaseAddress = 0; // Region base address.
        std::uint64_t regionSize = 0;       // Region size.
        std::uint32_t protect = 0;          // Protection bits from VirtualQueryEx.
        std::uint32_t state = 0;            // VirtualQueryEx state.
        std::uint32_t type = 0;             // VirtualQueryEx type.
        std::uint32_t win32Protection = 0;  // QueryWorkingSetEx protection bits.
        std::uint32_t shareCount = 0;       // Share count.
        std::uint32_t node = 0;             // NUMA node number.
        bool valid = false;                 // Whether the WorkingSet is valid.
        bool shared = false;                // Whether WorkingSet is shared.
        bool locked = false;                // Whether the WorkingSet is locked.
        bool largePage = false;             // Whether the WorkingSet uses large pages.
        bool bad = false;                   // Whether the WorkingSet contains bad pages.
        QString mappedFilePath;             // Mapped file path.
        QString riskText;                   // Risk summary.
        QString detailText;                 // Detail text.
    };

public:
    // KernelModuleEntry：
    // - Purpose: Cache a loaded kernel module record for use by the driver in populating the target page dropdown and parsing 'module name + offset'.
    // - Note: The data source is an R3 SystemModuleInformation snapshot, independent of the attached process, and thus distinct from ModuleEntry.
    struct KernelModuleEntry
    {
        QString moduleName;             // Module file name, e.g., CI.dll.
        QString ntPath;                 // Module NT path, e.g., \SystemRoot\system32\CI.dll.
        std::uint64_t baseAddress = 0;  // Module image base address.
        std::uint32_t sizeBytes = 0;    // Module image size, used for offset out-of-bounds warnings.
        bool kernelImage = false;       // Whether this is the kernel image (ntoskrnl), used for top-level display.
    };

    // DriverMemorySourceMode：
    // - Purpose: Identify the current target source channel for driver read/write pages.
    // - Note: The enumeration values must match the order of items in the source dropdown; the UI converts directly by index.
    enum class DriverMemorySourceMode : int
    {
        kProcessVirtual = 0, // User-mode virtual memory of the target process.
        kKernelVirtual,      // Kernel virtual address space.
        kPhysical            // Physical memory.
    };

    // DriverMemoryViewMode：
    // - Purpose: Identify the current view displayed for driver read/write pages.
    // - Note: The enumeration value order must match the push order of the view stack, as the UI switches pages directly by index.
    enum class DriverMemoryViewMode : int
    {
        kHex = 0,        // Hex editor view.
        kDisassembly,    // Disassembly instruction view.
        kText            // Printable text view.
    };

private:
    // DriverDiffBlock：
    // - Purpose: Store continuous difference blocks derived from comparing 'modified cache' and 'read backup'.
    // - R3 submits only these difference blocks to R0 to avoid redundant full-page writes.
    struct DriverDiffBlock
    {
        std::uint64_t address = 0;      // Target start address of the difference block.
        QByteArray bytes;               // Byte data after modification of the differential block.
    };

    // ParsedSearchPattern：
    // - Purpose: Stores the result of parsing scan input to avoid redundant string parsing within the thread.
    struct ParsedSearchPattern
    {
        SearchValueType valueType = SearchValueType::kByte; // Data type.
        QByteArray exactBytes;         // Exact match bytes.
        QByteArray wildcardMask;       // Wildcard mask (used in ByteArray mode: 1 = valid, 0 = wildcard).
        double lowerBound = 0.0;       // Numerical lower bound (used for 'Between' or floating-point error comparisons).
        double upperBound = 0.0;       // Numerical upper bound.
        double epsilon = 0.00001;      // Floating-point error threshold.
    };

private:
    // ========================================================
    // UI initialization and connection functions
    // ========================================================

    // initializeUi：
    // - Purpose: initialize root layout, toolbar, tab area, and status bar.
    // - Returns: Nothing.
    void initializeUi();

    // initializeToolbar：
    // - Purpose: initialize the top-level global toolbar.
    // - Returns: Nothing.
    void initializeToolbar();

    // initializeTabs：
    // - Purpose: initialize all MemoryDock Tab pages.
    // - Returns: Nothing.
    void initializeTabs();

    // initializeProcessModuleTab：
    // - Purpose: Build the Tab1 (Processes and Modules) interface.
    // - Returns: Nothing.
    void initializeProcessModuleTab();

    // initializeMemoryRegionTab：
    // - Purpose: Constructs the Tab2 (Memory Region) interface.
    // - Returns: Nothing.
    void initializeMemoryRegionTab();

    // initializeMemorySearchTab：
    // - Purpose: Constructs the Tab3 (Memory Search) interface.
    // - Returns: Nothing.
    void initializeMemorySearchTab();

    // initializeMemoryViewerTab：
    // - Purpose: Build the Tab4 (Memory Viewer) interface.
    // - Returns: Nothing.
    void initializeMemoryViewerTab();

    // initializeBreakpointBookmarkTab：
    // - Purpose: Build the Tab5 (Breakpoints and Bookmarks) interface.
    // - Returns: Nothing.
    void initializeBreakpointBookmarkTab();

    // initializeDriverMemoryRwTab：
    // - Purpose: Build the Tab6 (Driver Memory Read/Write) interface.
    // - Returns: Nothing.
    void initializeDriverMemoryRwTab();

    // initializeKernelExecutableMemoryScanTab：
    // - Purpose: Build Tab7 (Kernel Executable Page Scan) interface.
    // - Returns: Nothing.
    void initializeKernelExecutableMemoryScanTab();

    // initializeKernelMemoryEvidenceTab：
    // - Purpose: Build the Tab8 (Kernel Memory Evidence) interface.
    // - Processing logic: Create only read-only query entry points, result tables, and detail areas; all R0 access is delegated to ArkDriverClient.
    // - Returns: Nothing.
    void initializeKernelMemoryEvidenceTab();

    // initializeProcessPteTranslateTab：
    // - Purpose: Builds the Tab9 (PTE/VA translation) interface.
    // - Handling logic: Read only the working set/virtual memory attributes of the currently attached process; no write operations are performed.
    // - Returns: Nothing.
    void initializeProcessPteTranslateTab();

    // initializeProcessMemoryEvidenceTab：
    // - Purpose: Build the Tab10 (process memory evidence) interface.
    // - Processing logic: Organize read-only evidence based on VirtualQueryEx / QueryWorkingSetEx.
    // - Returns: Nothing.
    void initializeProcessMemoryEvidenceTab();

    // initializeSystemMemoryAuditTab：
    // - Purpose: Build the Tab11 (System Memory Audit) interface.
    // - Logic: Aggregates physical distribution, kernel process snapshots, Pool Tag, and Big Pool evidence.
    void initializeSystemMemoryAuditTab();

    // initializeDdmaTab：
    // - Purpose: Build the Tab12 (DDMA) interface.
    // - Processing logic: the page itself handles channel configuration; this function only handles mounting and registering session change callbacks.
    void initializeDdmaTab();

    // initializeTamperDetectionTab：
    // - Purpose: Mount the 'Tamper Detection' page and synchronize the attached process and module lists to it.
    void initializeTamperDetectionTab();


    // createBackendSelector：
    // - Purpose: Create a unified-style "Access Backend" dropdown.
    // - Parameter parent: Parent widget.
    // - Parameters comboOut/hintOut: output combo box and its associated hint label;
    // - Note: All three pages share this single construction entry point. The item order matches
    //   MemoryAccessBackend to prevent any page from defining a separate, differently ordered dropdown.
    QWidget* createBackendSelector(
        QWidget* parent,
        QComboBox*& comboOut,
        QLabel*& hintOut);

    // refreshBackendSelectors：
    // - Purpose: Refresh availability and tooltip text of the three dropdowns after a DDMA session change;
    // - Note: Do not disable the dropdown when DDMA is unavailable; instead, keep the option and explain the missing step
    //   in the tooltip. Otherwise, users will only see a grayed-out option without knowing where to add the configuration.
    void refreshBackendSelectors();

    // currentSearchBackend / currentViewerBackend / currentDriverMemoryBackend：
    // - Purpose: Read the currently selected access backend for each page.
    // - Return: Falls back to the standard driver channel if the control is missing.
    ksword::memory_backend::MemoryAccessBackend currentSearchBackend() const;
    ksword::memory_backend::MemoryAccessBackend currentViewerBackend() const;
    ksword::memory_backend::MemoryAccessBackend currentDriverMemoryBackend() const;

    // currentDdmaSession：
    // - Purpose: Retrieve session configuration maintained by DDMA pages;
    // - Return: Returns an 'unconfigured' empty session when the DDMA page is not yet created.
    const ksword::memory_backend::DdmaSession& currentDdmaSession() const;

    // initializeConnections：
    // - Purpose: Unify interaction logic for all controls.
    // - Returns: Nothing.
    void initializeConnections();

    // initializeStatusBar：
    // - Purpose: initialize the default status bar text.
    // - Returns: Nothing.
    void initializeStatusBar();

    // initializeBookmarkRefreshTimer：
    // - Purpose: initialize the bookmark refresh timer (default 1 second).
    // - Returns: Nothing.
    void initializeBookmarkRefreshTimer();

private:
    // ========================================================
    // Functions related to Processes and Modules (Tab1)
    // ========================================================

    // refreshProcessList：
    // - Purpose: Re-enumerate system processes and refresh the process table/dropdown.
    // - Parameter keepSelection: whether to attempt to preserve the currently selected PID.
    // - Returns: Nothing.
    void refreshProcessList(bool keepSelection);

    // updateProcessComboFromCache：
    // - Purpose: Rebuilds the top "Process Selection" dropdown based on m_processCache.
    // - Returns: Nothing.
    void updateProcessComboFromCache();

    // isComboPopupVisible：
    // - Purpose: Check if a single combo box is within its popup lifecycle.
    // - Parameter comboBox: Dropdown box to check, may be null.
    // - Returns: true if the popup is visible, animating, or still finishing up.
    bool isComboPopupVisible(QComboBox* comboBox) const;

    // isProcessComboPopupOpen：
    // - Purpose: Check if any 'Rebuild Cache by Process' dropdown popup is currently expanding.
    // - Note: The top process combo box and the R0 read/write page's target process box share
    //   the same process cache. A single backfill rebuilds both, so any unwind must defer commit.
    // - Return: true indicates the popup is visible; rebuilding the dropdown in this state causes the popup to capture the mouse, making the UI unresponsive.
    bool isProcessComboPopupOpen();

    // deferCommitWhileProcessComboPopupOpen：
    // - Purpose: Cache the latest process list commit during the popup expansion, and persist it only after the popup is closed.
    // - Parameter commitAction: The complete process cache/table/dropdown commit action.
    // - Returns: true indicates cached; the caller should return immediately. false indicates the commit can proceed directly.
    bool deferCommitWhileProcessComboPopupOpen(std::function<void()> commitAction);

    // flushProcessComboDeferredCommit：
    // - Purpose: Execute the latest cached commit after the layer collapses;
    // - Returns: none. Keeps cache waiting when the popup is reopened.
    void flushProcessComboDeferredCommit();

    // refreshModuleListForPid：
    // - Purpose: enumerate modules by PID and refresh the module list.
    // - Parameter pid: target process PID.
    // - Returns: true indicates enumeration success; false indicates failure.
    bool refreshModuleListForPid(std::uint32_t pid);

    // rebuildModuleTableFromCache：
    // - Purpose: Redraw m_moduleCache to the module table based on current filter conditions.
    // - Note: This function performs only a 'cache -> UI' projection and does not perform Win32 enumeration.
    // - Returns: Nothing.
    void rebuildModuleTableFromCache();

    // syncTamperDetectionTargets：
    // - Purpose: Synchronize the currently attached process with the module list for the 'Tamper Detection' page.
    // - Note: This must be called both after successful attachment and when persisting the module cache. If either is missing, the target dropdown
    //   on that page will remain stuck on the previous process's modules—which continue running but scan the wrong process's address space.
    void syncTamperDetectionTargets();

    // applyProcessTableFilter：
    // - Purpose: Hide/show rows in the process table based on the keyword in m_processFilterEdit and update the count label;
    // - Note: Only hides rows without rebuilding the table. Rebuilding would lose the currently selected
    //   row and conflict with background incremental refresh (icons are asynchronously filled in).
    void applyProcessTableFilter();

    // attachToProcess：
    // - Purpose: Attaches to the target process and caches the handle.
    // - Parameter pid: Target PID.
    // - Parameter processName: Target process name (for status bar display).
    // - Parameter showMessage: Whether to display a message box to report the result.
    // - Returns: true on successful attachment; false on attachment failure.
    bool attachToProcess(std::uint32_t pid, const QString& processName, bool showMessage);

    // detachProcess：
    // - Purpose: Detach the current process and clean up data dependent on the handle.
    // - Returns: Nothing.
    void detachProcess();

    // openProcessHandleForRead：
    // - Purpose: Open process handle by PID (read/query permissions).
    // - Parameter pid: Target PID.
    // - Parameter errorTextOut: outputs error text on failure (nullable).
    // - Return: Valid HANDLE on success; nullptr on failure.
    HANDLE openProcessHandleForRead(std::uint32_t pid, QString* errorTextOut = nullptr) const;

    // duplicateAttachedProcessHandleForWorker：
    // - Purpose: Duplicate the currently attached process handle for background read-only tasks to prevent the task from continuing to use the original handle, which may be closed or reused by the UI thread.
    // - Parameter errorCodeOut: Outputs the Win32 error code on failure (nullable).
    // - Returns: an independent handle lease that auto-closes on success; returns an empty shared_ptr on failure.
    std::shared_ptr<void> duplicateAttachedProcessHandleForWorker(std::uint32_t* errorCodeOut = nullptr) const;

    // showProcessTableContextMenu：
    // - Purpose: Display the right-click context menu for the process list (Attach / Dump memory).
    // - localPosition parameter: the mouse coordinates within the process table viewport.
    // - Returns: Nothing.
    void showProcessTableContextMenu(const QPoint& localPosition);

    // requestDumpProcessMemoryByPid：
    // - Purpose: Pop up a save file dialog and asynchronously dump the target process memory.
    // - Parameter pid: The target process PID to dump.
    // - Parameter processName: Target process name (used for default filename and prompts).
    // - Returns: Nothing.
    void requestDumpProcessMemoryByPid(std::uint32_t pid, const QString& processName);

    // dumpProcessMemoryToFile：
    // - Purpose: Perform actual memory region traversal and file writing.
    // - Parameter pid: Target PID.
    // - Parameter dumpFilePath: Output file path.
    // - Parameter errorTextOut: Error message output on failure.
    // - Returns: true = success; false = failure.
    bool dumpProcessMemoryToFile(
        std::uint32_t pid,
        const QString& dumpFilePath,
        QString& errorTextOut);

private:
    // ========================================================
    // Functions related to memory regions (Tab2)
    // ========================================================

    // refreshMemoryRegionList：
    // - Purpose: Refresh the memory region cache and apply filtering for display.
    // - Parameter forceRequery: Whether to force a re-call to VirtualQueryEx.
    // - Returns: Nothing.
    void refreshMemoryRegionList(bool forceRequery);

    // enumerateMemoryRegionsByVirtualQuery：
    // - Purpose: Perform VirtualQueryEx traversal on the attached process.
    // - Parameter processHandle: The handle to the target process.
    // - Parameter regionsOut: Output region array (cleared before call).
    // - Parameter errorTextOut: Output for failure messages (nullable).
    // - Returns: true on success; false on failure.
    bool enumerateMemoryRegionsByVirtualQuery(
        HANDLE processHandle,
        std::vector<RegionEntry>& regionsOut,
        QString* errorTextOut = nullptr) const;

    // applyRegionFilterAndRebuildTable：
    // - Purpose: Filter regions based on checkbox conditions and rebuild the Tab2 table.
    // - Returns: Nothing.
    void applyRegionFilterAndRebuildTable();

private:
    // ========================================================
    // Functions related to memory search (Tab3)
    // ========================================================

    // parseSearchPatternFromUi：
    // - Purpose: Parse UI input into an executable scan structure.
    // - Parameter patternOut: Output parsed result.
    // - Parameter errorTextOut: Output the reason for parsing failure.
    // - Returns: true on successful parsing; false on parsing failure.
    bool parseSearchPatternFromUi(
        ParsedSearchPattern& patternOut,
        QString& errorTextOut) const;

    // collectSearchRegionsFromUi：
    // - Purpose: Determine the set of scan regions based on 'Range Options' and 'Filter Options'.
    // - Parameter regionsOut: Output region array.
    // - Parameter errorTextOut: Failure reason text.
    // - Returns: true on success; false on failure.
    bool collectSearchRegionsFromUi(
        std::vector<RegionEntry>& regionsOut,
        QString& errorTextOut);

    // startFirstScan：
    // - Purpose: Execute 'First Scan'.
    // - Returns: Nothing.
    void startFirstScan();

    // startNextScan：
    // - Purpose: Execute 'Rescan'.
    // - Returns: Nothing.
    void startNextScan();

    // resetScanState：
    // - Purpose: Resets the scan state and clears the result table.
    // - Returns: Nothing.
    void resetScanState();

    // cancelCurrentScan：
    // - Purpose: Set the scan cancellation flag; background threads will stop as soon as possible.
    // - Returns: Nothing.
    void cancelCurrentScan();

    // cancelAndWaitForMemoryScanTasks：
    // - Purpose: Request all memory scans to stop and wait for background tasks to exit before closing handles or destruction.
    // - Returns: Nothing.
    void cancelAndWaitForMemoryScanTasks();

    // rebuildSearchResultTable：
    // - Purpose: Rebuild the result table based on m_searchResultCache.
    // - Returns: Nothing.
    void rebuildSearchResultTable();

    // scanMemoryRegionsInBackground：
    // - Purpose: Perform initial scan in background and submit results to main thread upon completion.
    // - Parameter scanRegions: Scan regions for this round.
    // - Parameter pattern: Matching pattern for this round.
    // - Returns: Nothing.
    void scanMemoryRegionsInBackground(
        const std::vector<RegionEntry>& scanRegions,
        const ParsedSearchPattern& pattern);

private:
    // ========================================================
    // Functions related to the Memory Viewer (Tab4).
    // ========================================================

    // jumpToAddressFromUi：
    // - Purpose: Read the address input box and jump to the target address.
    // - Returns: Nothing.
    void jumpToAddressFromUi();

    // jumpToAddress：
    // - Purpose: Jumps to the specified address and refreshes one page of the hex view.
    // - Parameter address: target address.
    // - Returns: Nothing.
    void jumpToAddress(std::uint64_t address);

    // reloadMemoryViewerPage：
    // - Purpose: Re-read from the current address and rebuild the hex table.
    // - Returns: Nothing.
    void reloadMemoryViewerPage();

    // writeSingleByteAtViewer：
    // - Purpose: Modifies a single byte in the current view.
    // - Parameter absoluteAddress: Target address.
    // - Parameter value: byte value to write.
    // - Parameter errorTextOut: Error text output on failure.
    // - Return: true if the write succeeds; false if the write fails.
    bool writeSingleByteAtViewer(
        std::uint64_t absoluteAddress,
        std::uint8_t value,
        QString& errorTextOut);

private:
    // ========================================================
    // Functions related to driver memory read/write (Tab6).
    // ========================================================

    // driverReadMemoryFromUi：
    // - Purpose: Read target process memory from R0 based on UI input and refresh HexEditor cache.
    // - Returns: Nothing.
    void driverReadMemoryFromUi();

    // driverApplyMemoryDiffFromUi：
    // - Purpose: Compare the current edit cache with the original backup and submit only the differing blocks to R0.
    // - Returns: Nothing.
    void driverApplyMemoryDiffFromUi();

    // resetDriverMemoryRwState：
    // - Purpose: Clear the driver read/write page cache and state.
    // - Returns: Nothing.
    void resetDriverMemoryRwState();

    // prepareDriverMemoryReadAtAddress：
    // - Purpose: Fill Tab6 with known valid region/address and optionally trigger immediate R0 read.
    // - Parameter absoluteAddress: Target process virtual address.
    // - Parameter preferredBytes: Expected read length; 0 indicates preserving the current surrounding range.
    // - Parameter triggerRead: true = fill and immediately trigger R0 read; false = only page-in fill.
    // - Returns: Nothing.
    void prepareDriverMemoryReadAtAddress(
        std::uint64_t absoluteAddress,
        std::uint64_t preferredBytes,
        bool triggerRead);

    // refreshKernelExecutableMemoryScanAsync：
    // - Purpose: Asynchronously refresh kernel executable page scan results.
    // - Returns: Nothing.
    void refreshKernelExecutableMemoryScanAsync();

    // rebuildKernelExecutableMemoryScanTable：
    // - Purpose: Rebuild the executable page scan table based on current filter conditions.
    // - Returns: Nothing.
    void rebuildKernelExecutableMemoryScanTable();

    // showKernelExecutableMemoryDetailByCurrentRow：
    // - Purpose: Write details of the currently selected row to the CodeEditorWidget.
    // - Returns: Nothing.
    void showKernelExecutableMemoryDetailByCurrentRow();

    // refreshKernelMemoryEvidenceAsync：
    // - Purpose: Asynchronously query kernel memory evidence, including non-module executable pages, BigPool, PTE permissions, and text hash status.
    // - Processing logic: The background thread calls ArkDriverClient::queryKernelMemoryEvidence, and the main thread fills in the UI.
    // - Returns: Nothing.
    void refreshKernelMemoryEvidenceAsync();

    // rebuildKernelMemoryEvidenceTable：
    // - Purpose: Rebuild the kernel memory evidence table based on current cache and filter options.
    // - Processing logic: Only project cached data to the UI; do not execute new driver IOCTLs.
    // - Returns: Nothing.
    void rebuildKernelMemoryEvidenceTable();

    // showKernelMemoryEvidenceDetailByCurrentRow：
    // - Purpose: Expand the currently selected evidence row to the detail editor.
    // - Processing logic: Reverse-lookup cache via virtual address in the UserRole table.
    // - Returns: Nothing.
    void showKernelMemoryEvidenceDetailByCurrentRow();

    // refreshProcessPteTranslateAsync：
    // - Purpose: Asynchronously collect PTE/VA translation information for the current process.
    // - Returns: Nothing.
    void refreshProcessPteTranslateAsync();

    // rebuildProcessPteTranslateTable：
    // - Purpose: Rebuild the PTE/VA translation table based on current filter conditions.
    // - Returns: Nothing.
    void rebuildProcessPteTranslateTable();

    // showProcessPteTranslateDetailByCurrentRow：
    // - Purpose: Expand the currently selected translation record to the detail editor.
    // - Returns: Nothing.
    void showProcessPteTranslateDetailByCurrentRow();

    // refreshProcessMemoryEvidenceAsync：
    // - Purpose: Asynchronously collect memory evidence for the current process.
    // - Returns: Nothing.
    void refreshProcessMemoryEvidenceAsync();

    // rebuildProcessMemoryEvidenceTable：
    // - Purpose: Rebuild process memory evidence table by filter condition.
    // - Returns: Nothing.
    void rebuildProcessMemoryEvidenceTable();

    // showProcessMemoryEvidenceDetailByCurrentRow：
    // - Purpose: Expand the currently selected evidence record to the detail editor.
    // - Returns: Nothing.
    void showProcessMemoryEvidenceDetailByCurrentRow();

    // updateDriverMemoryBaseComboFromProcessCache：
    // - Purpose: Rebuild the Tab6 'Offset Base / Target Process' dropdown using the current process cache.
    // - Handling logic: retain the user-entered 0x base address or process filter text to avoid losing query conditions when refreshing the process list.
    // - Returns: Nothing.
    void updateDriverMemoryBaseComboFromProcessCache();

    // resolveDriverMemoryRequestFromUi：
    // - Purpose: Parse Tab6's target process, offset base address, and center address to output the final R0 read address.
    // - Parameter targetPidOut: Output PID used for R0 read/write operations.
    // - Parameter targetNameOut: Output the matched process name, which may be empty.
    // - Parameter offsetBaseOut: Optional output offset base, default 0.
    // - Parameter centerAddressOut: The original value parsed from the 'Center Address' input field.
    // - Parameter effectiveCenterAddressOut: outputs the final center address calculated as offsetBase + centerAddress.
    // - Parameter errorTextOut: output error text for failure to display to the user.
    // - Returns: true on successful parsing; false on parsing failure.
    bool resolveDriverMemoryRequestFromUi(
        std::uint32_t& targetPidOut,
        QString& targetNameOut,
        std::uint64_t& offsetBaseOut,
        std::uint64_t& centerAddressOut,
        std::uint64_t& effectiveCenterAddressOut,
        QString& errorTextOut);

    // findDriverMemoryProcessComboMatch：
    // - Purpose: Find a matching item in the Tab6 process combo box based on user input.
    // - Parameter filterText: User-entered process name fragment, PID, or full dropdown text.
    // - Parameter comboIndexOut: Output the matched dropdown index.
    // - Return: true if a match is found; false otherwise.
    bool findDriverMemoryProcessComboMatch(
        const QString& filterText,
        int& comboIndexOut) const;

    // resolveDriverMemoryModuleExpression：
    // - Purpose: Parse 'module name + hexadecimal offset' into an absolute address in the currently attached process.
    // - Parameter expressionText: module offset expression, e.g., client.dll+C125D9.
    // - Parameter resolvedBaseOut: Output absolute address after adding the module base address and offset.
    // - Parameter errorTextOut: output precise reason for failure to display to the user.
    // - Return: true if parsed and matched to a unique module; false if format, process, or module matching failed.
    bool resolveDriverMemoryModuleExpression(
        const QString& expressionText,
        std::uint64_t& resolvedBaseOut,
        QString& errorTextOut) const;

    // collectDriverMemoryDiffBlocks：
    // - Purpose: Generate a list of contiguous difference blocks for one or more R0 write requests.
    // - Parameter diffBlocksOut: Output set of difference blocks.
    // - Returns: Nothing.
    void collectDriverMemoryDiffBlocks(std::vector<DriverDiffBlock>& diffBlocksOut) const;

    // confirmForceDriverMemoryWrite：
    // - Purpose: Prompt the user for confirmation to force write when R0 returns a force-required status for a normal write.
    // - Parameter blockAddress: Starting address of the current differential block.
    // - Parameter requestedBytes: Number of bytes requested for the current difference block.
    // - Parameter failureText: Rejection message returned from R0.
    // - Return: true indicates the user chose to force continue; false indicates stopping the operation.
    bool confirmForceDriverMemoryWrite(
        std::uint64_t blockAddress,
        std::uint32_t requestedBytes,
        const QString& failureText);

private:
    // ========================================================
    // Driver memory read/write (Tab6) target source expansion: kernel modules and physical memory
    // ========================================================

    // driverMemoryKernelModuleBaseRole：
    // - Purpose: Returns the Qt custom data role used to store the kernel module base address in the dropdown item.
    // - Note: Process items store PID in Qt::UserRole; kernel modules use a separate role to avoid semantic confusion.
    // - Return: Role value directly passable to QComboBox::itemData.
    static int driverMemoryKernelModuleBaseRole();

    // currentDriverMemorySourceMode：
    // - Purpose: Read the currently selected target channel from the source dropdown.
    // - Return: One of process virtual memory, kernel virtual memory, or physical memory; returns process virtual memory if the control is not yet created.
    DriverMemorySourceMode currentDriverMemorySourceMode() const;

    // refreshKernelModuleCacheAsync：
    // - Purpose: Asynchronously enumerate loaded system kernel modules and refresh the target dropdown.
    // - Processing: Execute SystemModuleInformation snapshot via thread pool; use ticket mechanism to discard stale results and submit to main thread.
    // - Return: None; ignores the current request if a previous one is already in progress.
    void refreshKernelModuleCacheAsync();

    // resolveDriverMemoryKernelModuleExpression：
    // - Purpose: Parse 'kernel module name + offset' into an absolute kernel virtual address.
    // - Parameter moduleToken: Module name or module identifier including path, e.g., CI.dll.
    // - Parameter moduleOffset: offset already parsed in hexadecimal.
    // - Parameter resolvedBaseOut: Output absolute address after adding the module base address and offset.
    // - Parameter errorTextOut: output precise reason for failure to display to the user.
    // - Returns: true if the unique kernel module is matched; false indicates an empty cache, no match, or multiple matches.
    bool resolveDriverMemoryKernelModuleExpression(
        const QString& moduleToken,
        std::uint64_t moduleOffset,
        std::uint64_t& resolvedBaseOut,
        QString& errorTextOut) const;

    // driverReadPhysicalMemoryFromUi：
    // - Purpose: Read physical memory via R0 using UI parameters and populate this page's snapshot.
    // - Processing: Validate 52-bit physical address limit and 64KB single-transfer limit locally before invoking physical read IOCTL;
    // - Return: None; on failure, clears the snapshot and displays diagnostic information.
    void driverReadPhysicalMemoryFromUi();

    // applyDriverMemoryPhysicalDiff：
    // - Purpose: Slice diff blocks into 4KB chunks and write them back to physical memory.
    // - Parameter diffBlocks: Collection of contiguous differential blocks to be written.
    // - Parameter failureTextOut: On failure, outputs a description containing the address, status code, and amount written.
    // - Returns: true indicates all blocks written successfully; false indicates failure midway with no automatic rollback.
    bool applyDriverMemoryPhysicalDiff(
        const std::vector<DriverDiffBlock>& diffBlocks,
        QString& failureTextOut);

    // ========================================================
    // Driver memory read/write (Tab6): multi-view presentation and convenient operations.
    // ========================================================

    // currentDriverMemoryArchitecture：
    // - Purpose: Determine which instruction set architecture to use for disassembling the current snapshot.
    // - Processing: Kernel and physical snapshots are fixed to x64; user-mode snapshots depend on whether the target process is WOW64.
    // - Return: x86 or x64 architecture enumeration; conservatively returns x64 on query failure.
    ks::ui::DisassemblyArchitecture currentDriverMemoryArchitecture() const;

    // applyDriverMemoryViewMode：
    // - Purpose: Switches between Hex, Disassembly, and Text views and synchronizes the segment button states.
    // - Parameter viewMode: target view.
    // - Returns: void; switching to the derived view also triggers a rebuild.
    void applyDriverMemoryViewMode(DriverMemoryViewMode viewMode);

    // refreshDriverMemoryViewsFromSnapshot：
    // - Purpose: Refresh the currently visible derived views after snapshot or edit cache changes.
    // - Returns: None; when staying in the hex view, only clear the stale content of the other two views.
    void refreshDriverMemoryViewsFromSnapshot();

    // rebuildDriverMemoryDisassemblyView：
    // - Purpose: Decode the current edit buffer using Zydis and rebuild the disassembly table.
    // - Processing: Snapshots exceeding 64KB are truncated based on budget; lines that failed to decode are highlighted in secondary color.
    // - Returns: Nothing.
    void rebuildDriverMemoryDisassemblyView();

    // rebuildDriverMemoryTextView：
    // - Purpose: Render the edit buffer into line-by-line printable text according to the current encoding setting.
    // - Returns: None; uses setRawText to ensure target memory content is not translated by language packs.
    void rebuildDriverMemoryTextView();

    // dumpDriverMemorySnapshotToFile：
    // - Purpose: Dump the current edit buffer to a disk file.
    // - Processing: Decide whether to write raw binary or readable hexadecimal dump based on the user-selected extension.
    // - Returns: Nothing.
    void dumpDriverMemorySnapshotToFile();

    // writeStringIntoDriverMemoryBuffer：
    // - Purpose: Display a dialog to fill a string into the edit buffer using a specified encoding.
    // - Processing: Reject out-of-bounds access; only modify local cache, actual writes still go through 'apply differences'.
    // - Returns: Nothing.
    void writeStringIntoDriverMemoryBuffer();

    // showDriverMemoryDisassemblyContextMenu：
    // - Purpose: Provide a copy and jump right-click menu for the disassembly table.
    // - Parameter localPosition: viewport coordinates of the table where the right-click occurred.
    // - Returns: Nothing.
    void showDriverMemoryDisassemblyContextMenu(const QPoint& localPosition);

private:
    // ========================================================
    // Functions related to breakpoints and bookmarks (Tab5).
    // ========================================================

    // addBreakpointByAddress：
    // - Purpose: Write 0xCC at the specified address and record the original byte.
    // - Parameter address: breakpoint address.
    // - Parameter description: Breakpoint description text.
    // - Parameter errorTextOut: Failure message output.
    // - Returns: true on success; false on failure.
    bool addBreakpointByAddress(
        std::uint64_t address,
        const QString& description,
        QString& errorTextOut);

    // removeBreakpointByRow：
    // - Purpose: Remove the breakpoint and restore the original byte.
    // - Parameter row: row index in the breakpoint table.
    // - Returns: true on success; false on failure.
    bool removeBreakpointByRow(int row);

    // setBreakpointEnabledByRow：
    // - Purpose: Enable or disable breakpoints.
    // - Parameter row: Breakpoint table row index.
    // - Parameter enabled: Target state (true = enabled, false = disabled).
    // - Returns: true on success; false on failure.
    bool setBreakpointEnabledByRow(int row, bool enabled);

    // rebuildBreakpointTable：
    // - Purpose: Rebuild the breakpoint table display.
    // - Returns: Nothing.
    void rebuildBreakpointTable();

    // addBookmarkByAddress：
    // - Purpose: Add bookmark record.
    // - Parameter address: bookmark address.
    // - Parameter noteText: Note text.
    // - Returns: Nothing.
    void addBookmarkByAddress(std::uint64_t address, const QString& noteText);

    // rebuildBookmarkTable：
    // - Purpose: Rebuild the bookmark table display.
    // - Returns: Nothing.
    void rebuildBookmarkTable();

    // refreshBookmarkValues：
    // - Purpose: Refresh the bookmark current value column to facilitate monitoring variable changes.
    // - Returns: Nothing.
    void refreshBookmarkValues();

private:
    // ========================================================
    // Common utility functions
    // ========================================================

    // updateStatusBarText：
    // - Purpose: Update the status bar (process name, PID, read/write status).
    // - Returns: Nothing.
    void updateStatusBarText();

    // parseAddressText：
    // - Purpose: Parse decimal or hexadecimal address strings.
    // - Parameter text: input text.
    // - Parameter valueOut: Output address value.
    // - Returns: true on successful parsing; false on parsing failure.
    static bool parseAddressText(const QString& text, std::uint64_t& valueOut);

    // parseUnsignedNumber：
    // - Purpose: Parse generic unsigned integers (supports 0x and decimal).
    // - Parameter text: input text.
    // - Parameter valueOut: The output value.
    // - Returns: true on success; false on failure.
    static bool parseUnsignedNumber(const QString& text, std::uint64_t& valueOut);

    // formatAddress：
    // - Purpose: Format the address as a 16-bit hexadecimal string.
    // - Parameter address: The address value.
    // - Returns: The formatted QString.
    static QString formatAddress(std::uint64_t address);

    // formatSize：
    // - Purpose: Format byte size (B/KB/MB/GB).
    // - Parameter sizeBytes: size in bytes.
    // - Returns: human-readable text.
    static QString formatSize(std::uint64_t sizeBytes);

    // protectToText：
    // - Purpose: Convert PAGE_* protection values to abbreviations (R--, RW-, RX, etc.).
    // - Parameter protect: Win32 protection value.
    // - Returns: human-readable text.
    static QString protectToText(std::uint32_t protect);

    // stateToText：
    // - Purpose: Converts MEM_* state values to human-readable text.
    // - Parameter state: Win32 state value.
    // - Returns: human-readable text.
    static QString stateToText(std::uint32_t state);

    // typeToText：
    // - Purpose: Converts MEM_* type values to human-readable text.
    // - Parameter type: Win32 type value.
    // - Returns: human-readable text.
    static QString typeToText(std::uint32_t type);

    // bytesToDisplayString：
    // - Purpose: Convert a byte array to a human-readable string based on the data type.
    // - Parameter bytes: Raw bytes.
    // - Parameter valueType: The target data type.
    // - Return: Formatted human-readable text.
    static QString bytesToDisplayString(const QByteArray& bytes, SearchValueType valueType);

private:
    // ========================================================
    // Top-level layout and global controls.
    // ========================================================

    QVBoxLayout* rootLayout_ = nullptr;      // Root layout (vertical: toolbar + Tab + status bar).
    QHBoxLayout* toolbarLayout_ = nullptr;   // Top toolbar layout.
    QTabWidget* tabWidget_ = nullptr;        // Container for the five functional tabs.
    QStatusBar* statusBar_ = nullptr;        // Bottom status bar.

    // Status bar control.
    QLabel* dockTitleLabel_ = nullptr;       // Page title label (first segment of the top three header sections).
    QLabel* dockHeaderStatusLabel_ = nullptr; // Top-attached status summary (second segment of the top three-segment header).
    QComboBox* processCombo_ = nullptr;      // Process selection combo box (supports input filtering).
    ks::ui::WindowPickerButton* processPickerButton_ = nullptr; // Crosshair window picker.
    QLabel* processPickerHintLabel_ = nullptr; // Real-time target hint during the pick process, visible only during picking.
    bool processComboPopupLifecycleActive_ = false; // Complete expansion lifecycle, including Qt popup animations.
    // Submit the latest process list cached during the popup expansion; upon collapse, re-inject it to avoid rebuilding the dropdown while it is expanding.
    std::function<void()> processComboDeferredCommit_;
    QTimer* processComboChangeTimer_ = nullptr;      // Debounce timer for process combo box switching.
    std::uint32_t pendingModuleRefreshPid_ = 0;      // The last selected PID within the debounce window.
    QPushButton* attachButton_ = nullptr;    // Attach button.
    QPushButton* detachButton_ = nullptr;    // Detach button.
    QPushButton* refreshButton_ = nullptr;   // Refresh button.
    QPushButton* settingsButton_ = nullptr;  // Settings button (thread count, cache size).

    // Status bar label.
    QLabel* statusProcessLabel_ = nullptr;   // Displays the current process name.
    QLabel* statusPidLabel_ = nullptr;       // Display the current PID.
    QLabel* statusMemoryIoLabel_ = nullptr;  // Display the current read/write status.

    // ========================================================
    // Tab1: Processes and modules
    // ========================================================

    QWidget* tabProcessModule_ = nullptr;    // Tab1 page container.
    QTableWidget* processTable_ = nullptr;   // Process list table.
    QHash<std::uint32_t, ProcessCpuSample> previousCpuSamples_; // Previous CPU sampling round, keyed by PID.
    QLineEdit* processFilterEdit_ = nullptr; // Process name/PID filter input box.
    QLabel* processCountLabel_ = nullptr;    // Process table displays the count as 'N / Total M'.
    QLineEdit* moduleFilterEdit_ = nullptr;  // Module name filter input box.
    QPushButton* moduleRefreshButton_ = nullptr; // Module refresh button.
    QCheckBox* moduleSignatureCheck_ = nullptr;  // Whether to verify signature during module refresh.
    QLabel* moduleStatusLabel_ = nullptr;        // Module refresh status label.
    QTreeWidget* moduleTable_ = nullptr;         // Module list table (tree header style).

    // ========================================================
    // Tab2: Memory Regions
    // ========================================================

    QWidget* tabRegions_ = nullptr;          // Tab2 page container.
    QPushButton* regionRefreshButton_ = nullptr;    // Manual re-enumerate memory regions button.
    QLineEdit* regionFilterEdit_ = nullptr;         // Filter by base address, protection attributes, or mapped file.
    QLabel* regionStatusLabel_ = nullptr;           // Summary of region count and filter results.
    QCheckBox* regionCommittedOnlyCheck_ = nullptr; // Filter for committed regions only.
    QCheckBox* regionImageOnlyCheck_ = nullptr;     // Filter only IMAGE type.
    QCheckBox* regionReadableOnlyCheck_ = nullptr;  // Read-only region filter.
    QTableWidget* regionTable_ = nullptr;    // Memory region table.

    // ========================================================
    // Tab3: Memory Search
    // ========================================================

    QWidget* tabSearch_ = nullptr;           // Tab3: Page container.
    QComboBox* searchTypeCombo_ = nullptr;   // Data type dropdown.
    QLineEdit* searchValueEdit_ = nullptr;   // Search value input field.
    QComboBox* searchRangeCombo_ = nullptr;  // Range combo box (full memory / custom).
    QLineEdit* searchRangeStartEdit_ = nullptr; // Custom range start address.
    QLineEdit* searchRangeEndEdit_ = nullptr;   // Custom range end address.
    QCheckBox* searchImageOnlyCheck_ = nullptr; // IMAGE region only.
    QCheckBox* searchHeapOnlyCheck_ = nullptr;  // Heap regions only (currently approximated as PRIVATE).
    QCheckBox* searchStackOnlyCheck_ = nullptr; // Filter only stack regions (currently reserved).
    QPushButton* firstScanButton_ = nullptr; // First scan button.
    QPushButton* nextScanButton_ = nullptr;  // Rescan button.
    QPushButton* resetScanButton_ = nullptr; // Reset scan button.
    QPushButton* cancelScanButton_ = nullptr;// Cancel scan button.
    QComboBox* nextScanCompareCombo_ = nullptr; // Next scan comparison combo box.
    QLineEdit* nextScanValueEdit_ = nullptr;    // Rescan value input box.
    QLineEdit* nextScanValueBEdit_ = nullptr;   // Between upper bound input box.
    QTableWidget* searchResultTable_ = nullptr; // Scan result table.
    QProgressBar* scanProgressBar_ = nullptr;   // Scan progress bar.
    QLabel* scanStatusLabel_ = nullptr;         // Scan status text.

    // ========================================================
    // Tab4: Memory viewer
    // ========================================================

    QWidget* tabViewer_ = nullptr;           // Tab4: Page container.
    QLineEdit* viewAddressEdit_ = nullptr;   // Address navigation input box.
    QPushButton* viewJumpButton_ = nullptr;  // Jump button.
    QLabel* viewProtectLabel_ = nullptr;     // Current address protection attribute label.
    HexEditorWidget* hexEditorWidget_ = nullptr; // Unified hex editor component.
    QLabel* viewerStatusLabel_ = nullptr;    // Viewer status text.

    // ========================================================
    // Tab5: Breakpoints and Bookmarks
    // ========================================================

    QWidget* tabBpBookmark_ = nullptr;       // Tab5: Page container.
    QTableWidget* breakpointTable_ = nullptr;// Breakpoint table.
    QPushButton* addBreakpointButton_ = nullptr;    // Add breakpoint button.
    QPushButton* removeBreakpointButton_ = nullptr; // Remove breakpoint button.
    QPushButton* toggleBreakpointButton_ = nullptr; // Enable/disable breakpoint button.
    QTableWidget* bookmarkTable_ = nullptr;  // Bookmark table.
    QPushButton* addBookmarkButton_ = nullptr;      // Add bookmark button.
    QPushButton* removeBookmarkButton_ = nullptr;   // Remove bookmark button.
    QPushButton* refreshBookmarkButton_ = nullptr;  // Refresh bookmark value button.
    QPushButton* jumpBookmarkButton_ = nullptr;     // Jump to bookmark button.

    // ========================================================
    // Tab6: Driver memory read/write.
    // ========================================================

    QWidget* tabDriverMemoryRw_ = nullptr;   // Tab6: Page Container
    QComboBox* driverMemoryBaseCombo_ = nullptr; // Optional offset base or R0 target process selection box.
    bool driverMemoryBaseComboPopupLifecycleActive_ = false; // Target combo box popup/animation lifecycle.
    bool driverMemoryBaseComboRefreshPending_ = false; // Pending model rebuild after the popup is collapsed.
    QLineEdit* driverMemoryAddressEdit_ = nullptr; // Target address for driver read/write operations.
    QSpinBox* driverMemoryBeforeSpin_ = nullptr;   // Number of bytes to read forward.
    QSpinBox* driverMemoryAfterSpin_ = nullptr;    // Number of bytes to read backward.
    QPushButton* driverMemoryReadButton_ = nullptr; // R0 read button.
    QPushButton* driverMemoryApplyButton_ = nullptr; // Apply differences button.
    QPushButton* driverMemoryResetButton_ = nullptr; // Clear button.
    QLabel* driverMemoryRangeLabel_ = nullptr;       // Current cached range label.
    QLabel* driverMemoryStatusLabel_ = nullptr;      // R0 read/write status label.
    HexEditorWidget* driverMemoryHexEditor_ = nullptr; // Editable cache view.

    QComboBox* driverMemorySourceCombo_ = nullptr;   // Target source dropdown: Process / Kernel / Physical Memory.
    QPushButton* driverMemoryKernelModuleRefreshButton_ = nullptr; // Refresh the list of loaded kernel modules.
    QPushButton* driverMemoryDumpButton_ = nullptr;  // Dump the current snapshot to a file.
    QPushButton* driverMemoryWriteStringButton_ = nullptr; // Open string write dialog button.
    QToolButton* driverMemoryHexViewButton_ = nullptr;    // View segment button: Hexadecimal.
    QToolButton* driverMemoryDisasmViewButton_ = nullptr; // View segmentation button: Disassembly.
    QToolButton* driverMemoryTextViewButton_ = nullptr;   // View segment button: Text.
    QComboBox* driverMemoryTextEncodingCombo_ = nullptr;  // Text view encoding selection: single-byte / UTF-16LE.
    QStackedWidget* driverMemoryViewStack_ = nullptr;     // Stack container for three views.
    ks::ui::VisibleTableWidget* driverMemoryDisasmTable_ = nullptr; // Disassembly instruction table.
    QLabel* driverMemoryDisasmBackendLabel_ = nullptr;    // Label for disassembly backend and truncation description.
    CodeEditorWidget* driverMemoryTextView_ = nullptr;    // Read-only text view.

    // ========================================================
    // Tab7: Kernel executable page scan
    // ========================================================

    QWidget* tabKernelExecutableMemory_ = nullptr;    // Tab7: Page Container
    QPushButton* kernelExecutableRefreshButton_ = nullptr; // Refresh button.
    QCheckBox* kernelExecutableRiskOnlyCheck_ = nullptr;   // Filter risk items only.
    QLineEdit* kernelExecutableModuleFilterEdit_ = nullptr; // Module path filter input box.
    QLabel* kernelExecutableStatusLabel_ = nullptr;         // Refresh status label.
    QTableWidget* kernelExecutableTable_ = nullptr;         // Executable page scan table.
    CodeEditorWidget* kernelExecutableDetailEditor_ = nullptr; // Detail editor.

    // ========================================================
    // Tab8: Kernel memory evidence.
    // ========================================================

    QWidget* tabKernelMemoryEvidence_ = nullptr;            // Tab8 page container.
    QPushButton* kernelMemoryEvidenceRefreshButton_ = nullptr; // Kernel memory evidence refresh button.
    QCheckBox* kernelMemoryEvidenceRiskOnlyCheck_ = nullptr; // Display only records where riskFlags is non-zero.
    QCheckBox* kernelMemoryEvidenceIncludeNonModuleCheck_ = nullptr; // Whether to explicitly include non-module execution range scanning.
    QLineEdit* kernelMemoryEvidenceFilterEdit_ = nullptr;   // Owner/detail local filter box.
    QLineEdit* kernelMemoryEvidenceStartEdit_ = nullptr;    // Non-module scan start address.
    QLineEdit* kernelMemoryEvidenceEndEdit_ = nullptr;      // Non-module scan end address.
    QSpinBox* kernelMemoryEvidenceMaxRowsSpin_ = nullptr;   // Maximum number of rows returned per request.
    QLabel* kernelMemoryEvidenceStatusLabel_ = nullptr;     // Query status label.
    QTableWidget* kernelMemoryEvidenceTable_ = nullptr;     // Evidence results table.
    CodeEditorWidget* kernelMemoryEvidenceDetailEditor_ = nullptr; // Evidence detail editor.

    // ========================================================
    // Tab9: PTE / VA translation
    // ========================================================

    QWidget* tabProcessPteTranslate_ = nullptr;              // Tab9 page container.
    QPushButton* processPteTranslateRefreshButton_ = nullptr; // Refresh button.
    QCheckBox* processPteTranslateRiskOnlyCheck_ = nullptr;    // Filter risk items only.
    QLineEdit* processPteTranslateAddressEdit_ = nullptr;      // VA input field.
    QSpinBox* processPteTranslatePageCountSpin_ = nullptr;     // Sample page count.
    QLabel* processPteTranslateStatusLabel_ = nullptr;         // Status label.
    QTableWidget* processPteTranslateTable_ = nullptr;         // Translation result table.
    CodeEditorWidget* processPteTranslateDetailEditor_ = nullptr; // Detail editor.

    // ========================================================
    // Tab10: Process memory evidence
    // ========================================================

    QWidget* tabProcessMemoryEvidence_ = nullptr;              // Tab10: Page container.
    QPushButton* processMemoryEvidenceRefreshButton_ = nullptr; // Refresh button.
    QCheckBox* processMemoryEvidenceRiskOnlyCheck_ = nullptr;    // Filter risk items only.
    QCheckBox* processMemoryEvidenceImageOnlyCheck_ = nullptr;   // Image region only.
    QLineEdit* processMemoryEvidenceStartEdit_ = nullptr;        // Start address.
    QLineEdit* processMemoryEvidenceEndEdit_ = nullptr;          // End address.
    QLineEdit* processMemoryEvidenceFilterEdit_ = nullptr;       // Text filter.
    QSpinBox* processMemoryEvidenceMaxRowsSpin_ = nullptr;       // Maximum rows.
    QLabel* processMemoryEvidenceStatusLabel_ = nullptr;         // Status label.
    QTableWidget* processMemoryEvidenceTable_ = nullptr;         // Evidence results table.
    CodeEditorWidget* processMemoryEvidenceDetailEditor_ = nullptr; // Detail editor.

    // ========================================================
    // Tab11: System memory audit
    // ========================================================

    SystemMemoryAuditPage* systemMemoryAuditPage_ = nullptr; // System-level physical memory attribution page.

    // ========================================================
    // Tab12: DDMA (Direct Disk Memory Access)
    // ========================================================

    DdmaPage* ddmaPage_ = nullptr;           // DDMA channel configuration and self-test page.
    ksword::memory_dock::TamperDetectionPage* tamperDetectionPage_ = nullptr; // Multi-path cross-tampering detection page.

    // Three 'Access Backend' dropdowns are attached to the search, viewer, and driver read/write pages respectively.
    // They share the same session configuration in m_ddmaPage; switching between them does not affect each other.
    QComboBox* searchBackendCombo_ = nullptr;        // Tab3: Access backend.
    QComboBox* viewerBackendCombo_ = nullptr;        // Tab4: Access backend.
    QComboBox* driverMemoryBackendCombo_ = nullptr;  // Tab6: Access Backend
    QLabel* searchBackendHintLabel_ = nullptr;       // Tab3: Backend status hint.
    QLabel* viewerBackendHintLabel_ = nullptr;       // Tab4: Backend status hint.
    QLabel* driverMemoryBackendHintLabel_ = nullptr; // Tab6: Backend status hint.

private:
    // ========================================================
    // Runtime state and cache
    // ========================================================

    // MemoryScanTaskState：
    // - Purpose: Independently save scan task count and wait conditions to avoid detached workers depending on QWidget lifecycle.
    // - Lifetime: shared by MemoryDock and all started scan tasks.
    struct MemoryScanTaskState
    {
        std::mutex mutex;                         // mutex: Protects read/write access to activeTaskCount.
        std::condition_variable completion;       // completion: Wakes the shutdown path when the last task exits.
        std::size_t activeTaskCount = 0;          // activeTaskCount: The number of scan coordination threads that have not yet exited.
    };

    HANDLE attachedProcessHandle_ = nullptr; // Handle of the currently attached target process.
    std::uint32_t attachedPid_ = 0;          // Current attached PID.
    QString attachedProcessName_;            // Name of the currently attached process.
    bool canReadWriteMemory_ = false;        // Whether the current handle can read/write memory.
    std::atomic<std::uint64_t> processAttachmentGeneration_{ 0 }; // Attachment context generation (discard stale handle task results).

    std::vector<ProcessEntry> processCache_; // Process cache (reused by Tab1 and the toolbar).
    std::vector<ModuleEntry> moduleCache_;   // Module cache (used by Tab1).
    std::atomic<bool> moduleRefreshInProgress_{ false }; // Whether module refresh is in progress (asynchronous task status).
    std::atomic<std::uint64_t> moduleRefreshTicket_{ 0 }; // Module refresh ticket (discard expired results).
    int dumpMemoryProgressPid_ = 0;        // The PID of the progress bar for the dump memory task.
    std::vector<RegionEntry> regionCache_;   // Region cache (shared between Tab2 and Tab3).

    std::vector<SearchResultEntry> searchResultCache_; // Scan result cache (Tab3).
    std::size_t searchResultVisibleCount_ = 0;         // Actual number of rows currently displayed in the results table (may be less than the total cached count).
    SearchValueType lastSearchValueType_ = SearchValueType::kByte; // Last scan type.
    std::atomic<bool> scanInProgress_{ false };       // Current scan in-progress status.
    std::atomic<bool> scanCancelRequested_{ false };  // Scan cancellation flag.
    std::shared_ptr<MemoryScanTaskState> scanTaskState_ = std::make_shared<MemoryScanTaskState>();
                                                        // m_scanTaskState: Scan task counter surviving across threads.
    std::uint32_t scanThreadCount_ = 4;               // Number of scanning threads (configurable).
    std::uint32_t scanChunkSizeKB_ = 1024;            // Single read block size (KB, configurable).

    std::uint64_t currentViewerAddress_ = 0;          // Tab4: Current start address.
    QByteArray currentViewerPageBytes_;               // Tab4: Original byte cache for the current page.

    std::uint64_t driverMemoryBaseAddress_ = 0;       // Tab6: Current cache base address.
    std::uint64_t driverMemoryOffsetBase_ = 0;        // Tab6: Optional offset base used for this read.
    std::uint64_t driverMemoryCenterAddress_ = 0;     // Tab6: The final center address parsed from this read operation.
    std::uint32_t driverMemorySnapshotPid_ = 0;       // Target PID corresponding to Tab6 snapshot; fixed for write-back operations.
    QString driverMemorySnapshotProcessName_;         // Process name corresponding to the Tab6 snapshot, used for display and confirmation only.
    QByteArray driverMemoryOriginalBytes_;            // Tab6: Read Backup
    QByteArray driverMemoryEditedBytes_;              // Tab6: Current edit cache.
    bool driverMemoryHasSnapshot_ = false;            // Whether Tab6 has a writable snapshot.
    bool driverMemorySnapshotIsPhysical_ = false;     // Tab6: Whether the current snapshot originates from the physical memory channel.
    DriverMemoryViewMode driverMemoryViewMode_ = DriverMemoryViewMode::kHex; // Tab6: Current View
    QVector<ks::ui::DisassemblyRow> driverMemoryDisasmRows_; // Tab6: Cache for disassembly decoding results.

    std::vector<KernelModuleEntry> kernelModuleCache_;  // Cache of loaded kernel modules (Tab6 target dropdown and expression parsing).
    std::atomic<bool> kernelModuleRefreshInProgress_{ false }; // Whether the kernel module list is currently being refreshed.
    std::atomic<std::uint64_t> kernelModuleRefreshTicket_{ 0 }; // Kernel module refresh ticket.

    std::vector<ksword::ark::KernelExecutableMemoryPageEntry> kernelExecutableCache_; // Tab7: Scan Cache
    std::atomic<bool> kernelExecutableRefreshInProgress_{ false }; // Tab7: Whether refresh is in progress.
    std::atomic<std::uint64_t> kernelExecutableRefreshTicket_{ 0 }; // Tab7: Refresh Ticket
    std::size_t kernelExecutableVisibleCount_ = 0; // Tab7: Current visible row count.

    std::vector<ksword::ark::KernelMemoryEvidenceEntry> kernelMemoryEvidenceCache_; // Tab8 evidence cache.
    std::atomic<bool> kernelMemoryEvidenceRefreshInProgress_{ false }; // Tab8: Whether refresh is in progress.
    std::atomic<std::uint64_t> kernelMemoryEvidenceRefreshTicket_{ 0 }; // Tab8: Refresh Ticket
    std::size_t kernelMemoryEvidenceVisibleCount_ = 0; // Tab8: Current visible row count.

    std::vector<ProcessMemoryEvidenceEntry> processPteTranslateCache_; // Tab9 evidence cache.
    std::atomic<bool> processPteTranslateRefreshInProgress_{ false }; // Tab9: Whether refresh is in progress.
    std::atomic<std::uint64_t> processPteTranslateRefreshTicket_{ 0 }; // Tab9 refresh ticket.
    std::size_t processPteTranslateVisibleCount_ = 0; // Tab9: Current visible row count.

    std::vector<ProcessMemoryEvidenceEntry> processMemoryEvidenceCache_; // Tab10: Evidence cache.
    std::atomic<bool> processMemoryEvidenceRefreshInProgress_{ false }; // Whether Tab10 is currently refreshing.
    std::atomic<std::uint64_t> processMemoryEvidenceRefreshTicket_{ 0 }; // Tab10 refresh ticket.
    std::size_t processMemoryEvidenceVisibleCount_ = 0; // Number of currently visible rows in Tab10.

    std::vector<BreakpointEntry> breakpointCache_;    // Breakpoint cache (Tab5).
    std::vector<BookmarkEntry> bookmarkCache_;        // Bookmark cache (Tab5).
    QTimer* bookmarkRefreshTimer_ = nullptr;          // Bookmark refresh timer.
};
